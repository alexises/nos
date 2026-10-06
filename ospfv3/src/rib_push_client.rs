//! Pushes this instance's current SPF-computed routes to the owning
//! `nos-ribd` instance for kernel installation — mirrors
//! `ospf::rib_push_client` exactly (recompute on every `Lsdb` change
//! plus a 2s fallback poll, `Full` snapshot on connect, diffed
//! `Add`/`Remove` afterward). `RibRequest::PushOspfRoutes`/`OspfRoute{prefix: IpNet, next_hop:
//! IpAddr, ..}` are already address-family-generic, confirmed in the
//! `OSPFv3` Phase 1 plan — this file needs no `nos-ribd`-side changes,
//! just `IpNet::V6`/`IpAddr::V6` on the wire instead of `V4`, plus (unlike
//! v2) always populating `OspfRoute::interface_id` from `spf::RouteEntry`
//! — see that field's own doc comment for why v3's link-local next-hops
//! need it.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::SinkExt;
use ipnet::IpNet;
use nos_proto::{IpcCodec, OspfRoute, OspfRouteUpdate, RibRequest, Role, ServiceRef};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::codec::FramedWrite;
use tracing::{debug, warn};

use crate::link::LinkManager;
use crate::watchdog_client::resolve_once;

// ponytail: the 2s poll is only a safety net for SPF inputs that don't touch
// an LSDB (neighbor state, area reconcile); upgrade by notifying from them.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Pause after a change before recomputing, so an LSU burst runs one SPF.
const HOLD_DOWN: Duration = Duration::from_millis(50);
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// Spawns the background task that owns the route-push connection for this
/// process's lifetime.
pub fn spawn(
    watchdog_socket: PathBuf,
    links: Arc<LinkManager>,
    routing_table_rx: watch::Receiver<Option<String>>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(run(watchdog_socket, links, routing_table_rx, shutdown))
}

async fn run(
    watchdog_socket: PathBuf,
    links: Arc<LinkManager>,
    routing_table_rx: watch::Receiver<Option<String>>,
    mut shutdown: watch::Receiver<bool>,
) {
    while !*shutdown.borrow() {
        let Some(table) = routing_table_rx.borrow().clone() else {
            if wait_or_shutdown(POLL_INTERVAL, &mut shutdown).await {
                break;
            }
            continue;
        };

        let Some(rib_socket) =
            resolve_once(&watchdog_socket, &ServiceRef::RibTable(table.clone())).await
        else {
            debug!(table = %table, "failed to resolve nos-ribd instance via nos-watchdogd, retrying");
            if wait_or_shutdown(RETRY_DELAY, &mut shutdown).await {
                break;
            }
            continue;
        };

        let stream = match nos_pki::connect(&rib_socket, Role::Ribd, &table).await {
            Ok(stream) => stream,
            Err(e) => {
                warn!(
                    table = %table,
                    socket = %rib_socket.display(),
                    error = %e,
                    "failed to connect to nos-ribd, retrying"
                );
                if wait_or_shutdown(RETRY_DELAY, &mut shutdown).await {
                    break;
                }
                continue;
            }
        };

        let mut writer = FramedWrite::new(stream, IpcCodec::<RibRequest>::default());
        let routes = compute_routes(&links).await;
        if writer
            .send(RibRequest::PushOspfRoutes(vec![OspfRouteUpdate::Full(
                to_routes(&routes),
            )]))
            .await
            .is_err()
        {
            warn!(table = %table, "failed to send initial ospfv3 route snapshot to nos-ribd, retrying");
            if wait_or_shutdown(RETRY_DELAY, &mut shutdown).await {
                break;
            }
            continue;
        }
        let mut last_sent = routes;
        debug!(table = %table, routes = last_sent.len(), "sent initial ospfv3 route snapshot to nos-ribd");

        let changed = links.route_changed();
        loop {
            if wait_for_change(&changed, &mut shutdown).await {
                return;
            }
            let new_table = routing_table_rx.borrow().clone();
            if new_table.as_deref() != Some(table.as_str()) {
                let _ = writer
                    .send(RibRequest::PushOspfRoutes(vec![OspfRouteUpdate::Full(
                        Vec::new(),
                    )]))
                    .await;
                break;
            }
            let new_routes = compute_routes(&links).await;
            let updates = diff_routes(&last_sent, &new_routes);
            if !updates.is_empty()
                && writer
                    .send(RibRequest::PushOspfRoutes(updates))
                    .await
                    .is_err()
            {
                warn!(table = %table, "write failure sending ospfv3 route update, reconnecting");
                break;
            }
            last_sent = new_routes;
        }
    }
}

/// What one prefix is pushed as: the next hop (`interface_id` is always `Some`
/// — root's own local ifindex, per `spf::RouteEntry::interface_id`'s doc
/// comment — kept `Option` only to match `OspfRoute`'s wire shape), its LFA
/// backup with the backup's own ifindex, and the metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pushed {
    next_hop: IpAddr,
    interface_id: Option<u32>,
    backup_next_hop: Option<IpAddr>,
    backup_interface_id: Option<u32>,
    metric: u32,
}

impl Pushed {
    fn route(self, prefix: IpNet) -> OspfRoute {
        OspfRoute {
            prefix,
            // ponytail: one next hop — ospfv3's SPF is still single-path;
            // the wire already carries a set for when it isn't.
            next_hops: vec![(self.next_hop, self.interface_id)],
            backup_next_hop: self.backup_next_hop,
            backup_interface_id: self.backup_interface_id,
            metric: self.metric,
            discard: false,
        }
    }
}

/// Waits for the next reason to recompute routes: an LSDB change (then a
/// `HOLD_DOWN` pause, so an LSU burst costs one SPF, not one per LSA), the
/// `POLL_INTERVAL` fallback, or shutdown. Returns `true` to stop entirely.
async fn wait_for_change(
    changed: &tokio::sync::Notify,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        () = changed.notified() => wait_or_shutdown(HOLD_DOWN, shutdown).await,
        () = tokio::time::sleep(POLL_INTERVAL) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

async fn compute_routes(links: &Arc<LinkManager>) -> HashMap<IpNet, Pushed> {
    links
        .compute_routes()
        .await
        .into_iter()
        .map(|e| {
            (
                IpNet::V6(e.prefix),
                Pushed {
                    next_hop: IpAddr::V6(e.next_hop),
                    interface_id: Some(e.interface_id),
                    backup_next_hop: e.backup_next_hop.map(IpAddr::V6),
                    backup_interface_id: e.backup_interface_id,
                    metric: e.metric,
                },
            )
        })
        .collect()
}

async fn wait_or_shutdown(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

fn to_routes(routes: &HashMap<IpNet, Pushed>) -> Vec<OspfRoute> {
    routes.iter().map(|(&p, &r)| r.route(p)).collect()
}

/// Mirrors `ospf::rib_push_client::diff_routes` exactly.
fn diff_routes(
    last_sent: &HashMap<IpNet, Pushed>,
    new_routes: &HashMap<IpNet, Pushed>,
) -> Vec<OspfRouteUpdate> {
    let mut updates = Vec::new();
    for (&prefix, &pushed) in new_routes {
        if last_sent.get(&prefix) != Some(&pushed) {
            updates.push(OspfRouteUpdate::Add(pushed.route(prefix)));
        }
    }
    for prefix in last_sent.keys() {
        if !new_routes.contains_key(prefix) {
            updates.push(OspfRouteUpdate::Remove(*prefix));
        }
    }
    updates
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routes(pairs: &[(&str, &str)]) -> HashMap<IpNet, Pushed> {
        pairs
            .iter()
            .map(|(p, gw)| {
                (
                    p.parse().unwrap(),
                    Pushed {
                        next_hop: gw.parse().unwrap(),
                        interface_id: Some(1),
                        backup_next_hop: None,
                        backup_interface_id: None,
                        metric: 10,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn diff_backup_only_change_is_add() {
        let last_sent = routes(&[("2001:db8::/64", "fe80::1")]);
        let mut new_routes = last_sent.clone();
        let p: IpNet = "2001:db8::/64".parse().unwrap();
        new_routes.get_mut(&p).unwrap().backup_next_hop = Some("fe80::2".parse().unwrap());
        new_routes.get_mut(&p).unwrap().backup_interface_id = Some(2);
        let updates = diff_routes(&last_sent, &new_routes);
        assert_eq!(updates.len(), 1);
        assert!(matches!(
            &updates[0],
            OspfRouteUpdate::Add(r) if r.backup_interface_id == Some(2)
        ));
    }

    #[test]
    fn diff_empty_to_empty_is_empty() {
        assert_eq!(diff_routes(&HashMap::new(), &HashMap::new()), []);
    }

    #[test]
    fn diff_unchanged_prefix_is_noop() {
        let r = routes(&[("2001:db8::/64", "fe80::1")]);
        assert_eq!(diff_routes(&r, &r), []);
    }

    #[test]
    fn diff_changed_next_hop_is_add() {
        let last_sent = routes(&[("2001:db8::/64", "fe80::1")]);
        let new_routes = routes(&[("2001:db8::/64", "fe80::2")]);
        assert_eq!(
            diff_routes(&last_sent, &new_routes),
            vec![OspfRouteUpdate::Add(OspfRoute {
                prefix: "2001:db8::/64".parse().unwrap(),
                next_hops: vec![("fe80::2".parse().unwrap(), Some(1))],
                backup_next_hop: None,
                backup_interface_id: None,
                metric: 10,
                discard: false,
            })]
        );
    }

    #[test]
    fn diff_removed_prefix_is_remove() {
        let last_sent = routes(&[("2001:db8::/64", "fe80::1")]);
        assert_eq!(
            diff_routes(&last_sent, &HashMap::new()),
            vec![OspfRouteUpdate::Remove("2001:db8::/64".parse().unwrap())]
        );
    }

    #[test]
    fn diff_mixed_add_and_remove() {
        let last_sent = routes(&[
            ("2001:db8:1::/64", "fe80::1"),
            ("2001:db8:2::/64", "fe80::1"),
        ]);
        let new_routes = routes(&[
            ("2001:db8:1::/64", "fe80::1"),
            ("2001:db8:3::/64", "fe80::1"),
        ]);
        let mut updates = diff_routes(&last_sent, &new_routes);
        updates.sort_by_key(|u| format!("{u:?}"));
        let mut expected = vec![
            OspfRouteUpdate::Add(OspfRoute {
                prefix: "2001:db8:3::/64".parse().unwrap(),
                next_hops: vec![("fe80::1".parse().unwrap(), Some(1))],
                backup_next_hop: None,
                backup_interface_id: None,
                metric: 10,
                discard: false,
            }),
            OspfRouteUpdate::Remove("2001:db8:2::/64".parse().unwrap()),
        ];
        expected.sort_by_key(|u| format!("{u:?}"));
        assert_eq!(updates, expected);
    }

    /// A change wakes the loop long before the fallback poll; a burst of
    /// changes stores one permit, so it costs exactly one wake-up.
    #[tokio::test(start_paused = true)]
    async fn change_wakes_early_and_bursts_coalesce() {
        let n = tokio::sync::Notify::new();
        let (_tx, mut rx) = watch::channel(false);
        let start = tokio::time::Instant::now();
        for _ in 0..5 {
            n.notify_one();
        }
        assert!(!wait_for_change(&n, &mut rx).await);
        assert_eq!(start.elapsed(), HOLD_DOWN);
        // The burst is spent: the next wait falls back to the poll tick.
        assert!(!wait_for_change(&n, &mut rx).await);
        assert_eq!(start.elapsed(), HOLD_DOWN + POLL_INTERVAL);
    }
}
