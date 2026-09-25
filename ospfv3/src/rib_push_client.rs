//! Pushes this instance's current SPF-computed routes to the owning
//! `nos-ribd` instance for kernel installation — mirrors
//! `ospf::rib_push_client` exactly (fixed 2s poll, `Full` snapshot on
//! connect, diffed `Add`/`Remove` afterward — same rationale: this crate's
//! `Lsdb` mutates from too many call sites for a single edge-triggered
//! hook). `RibRequest::PushOspfRoutes`/`OspfRoute{prefix: IpNet, next_hop:
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

const POLL_INTERVAL: Duration = Duration::from_secs(2);
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

        loop {
            if wait_or_shutdown(POLL_INTERVAL, &mut shutdown).await {
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

/// `(gateway, interface_id)` per prefix — `interface_id` is always `Some`
/// (root's own local ifindex, per `spf::RouteEntry::interface_id`'s doc
/// comment), kept `Option` only to match `OspfRoute::interface_id`'s own
/// shape on the wire.
async fn compute_routes(links: &Arc<LinkManager>) -> HashMap<IpNet, (IpAddr, Option<u32>)> {
    links
        .compute_routes()
        .await
        .into_iter()
        .map(|e| {
            (
                IpNet::V6(e.prefix),
                (IpAddr::V6(e.next_hop), Some(e.interface_id)),
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

fn to_routes(routes: &HashMap<IpNet, (IpAddr, Option<u32>)>) -> Vec<OspfRoute> {
    routes
        .iter()
        .map(|(&prefix, &(next_hop, interface_id))| OspfRoute {
            prefix,
            next_hop,
            interface_id,
            backup_next_hop: None,
        })
        .collect()
}

/// Mirrors `ospf::rib_push_client::diff_routes` exactly.
fn diff_routes(
    last_sent: &HashMap<IpNet, (IpAddr, Option<u32>)>,
    new_routes: &HashMap<IpNet, (IpAddr, Option<u32>)>,
) -> Vec<OspfRouteUpdate> {
    let mut updates = Vec::new();
    for (&prefix, &(next_hop, interface_id)) in new_routes {
        if last_sent.get(&prefix) != Some(&(next_hop, interface_id)) {
            updates.push(OspfRouteUpdate::Add(OspfRoute {
                prefix,
                next_hop,
                interface_id,
                backup_next_hop: None,
            }));
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

    fn routes(pairs: &[(&str, &str)]) -> HashMap<IpNet, (IpAddr, Option<u32>)> {
        pairs
            .iter()
            .map(|(p, gw)| (p.parse().unwrap(), (gw.parse().unwrap(), Some(1))))
            .collect()
    }

    #[test]
    fn diff_empty_to_empty_is_empty() {
        assert!(diff_routes(&HashMap::new(), &HashMap::new()).is_empty());
    }

    #[test]
    fn diff_unchanged_prefix_is_noop() {
        let r = routes(&[("2001:db8::/64", "fe80::1")]);
        assert!(diff_routes(&r, &r).is_empty());
    }

    #[test]
    fn diff_changed_next_hop_is_add() {
        let last_sent = routes(&[("2001:db8::/64", "fe80::1")]);
        let new_routes = routes(&[("2001:db8::/64", "fe80::2")]);
        assert_eq!(
            diff_routes(&last_sent, &new_routes),
            vec![OspfRouteUpdate::Add(OspfRoute {
                prefix: "2001:db8::/64".parse().unwrap(),
                next_hop: "fe80::2".parse().unwrap(),
                interface_id: Some(1),
                backup_next_hop: None,
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
                next_hop: "fe80::1".parse().unwrap(),
                interface_id: Some(1),
                backup_next_hop: None,
            }),
            OspfRouteUpdate::Remove("2001:db8:2::/64".parse().unwrap()),
        ];
        expected.sort_by_key(|u| format!("{u:?}"));
        assert_eq!(updates, expected);
    }
}
