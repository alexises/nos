//! Pushes this instance's current SPF-computed routes to the owning
//! `nos-ribd` instance for kernel installation — the OSPF analogue of
//! `bgp::rib_push_client`, same shape (a persistent connection, `Full`
//! snapshot on connect, diffed `Add`/`Remove` afterward).
//!
//! Also driven by a fixed poll rather than an edge trigger, for the same
//! reason `bgp::rib_push_client` is: this crate's `Lsdb` mutates from many
//! call sites (self-origination, `handle_lsu`, a resync's link changes),
//! with no single hook to push a notification out from. Polling and
//! diffing gets the same converged end state for far less surface area, at
//! the cost of up to one poll interval's propagation latency.

use std::collections::HashMap;
use std::net::IpAddr;

/// A route's next hop, its LFA backup (if any) and its SPF metric.
type Hops = (IpAddr, Option<IpAddr>, u32);
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

// ponytail: fixed poll, not edge-triggered from `Lsdb::install`'s many call
// sites — upgrade to a `Notify` wired through them if sub-poll-interval
// kernel convergence is ever required. Matches `ORIGINATION_INTERVAL`
// (`link.rs`), so a route reflects an LSDB change about as promptly as the
// self-originated LSA that caused it.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Matches every other reconnect/resolve loop in this codebase.
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
            warn!(table = %table, "failed to send initial ospf route snapshot to nos-ribd, retrying");
            if wait_or_shutdown(RETRY_DELAY, &mut shutdown).await {
                break;
            }
            continue;
        }
        let mut last_sent = routes;
        debug!(table = %table, routes = last_sent.len(), "sent initial ospf route snapshot to nos-ribd");

        // Inner loop: same connection, same owning table, until the table
        // changes to something else (including `None`) or a write fails.
        loop {
            if wait_or_shutdown(POLL_INTERVAL, &mut shutdown).await {
                return;
            }
            let new_table = routing_table_rx.borrow().clone();
            if new_table.as_deref() != Some(table.as_str()) {
                // Withdraw everything from this connection before switching
                // away — best-effort, we're tearing this connection down
                // regardless of the outcome.
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
                warn!(table = %table, "write failure sending ospf route update, reconnecting");
                break;
            }
            last_sent = new_routes;
        }
        // Reconnect (or idle, if the table is now None) immediately — the
        // outer loop re-reads the current snapshot from scratch.
    }
}

async fn compute_routes(links: &Arc<LinkManager>) -> HashMap<IpNet, Hops> {
    links
        .compute_routes()
        .await
        .into_iter()
        .map(|e| {
            (
                IpNet::V4(e.prefix),
                (
                    IpAddr::V4(e.next_hop),
                    e.backup_next_hop.map(IpAddr::V4),
                    e.metric,
                ),
            )
        })
        .collect()
}

/// Waits out `delay`, interruptible by `shutdown` firing. Returns `true` if
/// the caller should stop entirely.
async fn wait_or_shutdown(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

fn to_routes(routes: &HashMap<IpNet, Hops>) -> Vec<OspfRoute> {
    routes
        .iter()
        .map(
            |(&prefix, &(next_hop, backup_next_hop, metric))| OspfRoute {
                prefix,
                next_hop,
                interface_id: None,
                backup_next_hop,
                metric,
            },
        )
        .collect()
}

/// Computes the minimal `OspfRouteUpdate`s needed to bring `last_sent` (what
/// the connection was last told) up to `new_routes`: an `Add` for every
/// prefix that's new or whose next-hop changed, a `Remove` for every prefix
/// `last_sent` had that `new_routes` no longer does. Pure and unit-tested
/// directly, mirroring `bgp::rib_push_client::diff_routes` exactly.
fn diff_routes(
    last_sent: &HashMap<IpNet, Hops>,
    new_routes: &HashMap<IpNet, Hops>,
) -> Vec<OspfRouteUpdate> {
    let mut updates = Vec::new();
    for (&prefix, &hops) in new_routes {
        if last_sent.get(&prefix) != Some(&hops) {
            updates.push(OspfRouteUpdate::Add(OspfRoute {
                prefix,
                next_hop: hops.0,
                interface_id: None,
                backup_next_hop: hops.1,
                metric: hops.2,
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

    fn routes(pairs: &[(&str, &str)]) -> HashMap<IpNet, Hops> {
        pairs
            .iter()
            .map(|(p, gw)| (p.parse().unwrap(), (gw.parse().unwrap(), None, 10)))
            .collect()
    }

    #[test]
    fn diff_empty_to_empty_is_empty() {
        assert!(diff_routes(&HashMap::new(), &HashMap::new()).is_empty());
    }

    #[test]
    fn diff_unchanged_prefix_is_noop() {
        let r = routes(&[("10.0.0.0/24", "10.0.0.1")]);
        assert!(diff_routes(&r, &r).is_empty());
    }

    #[test]
    fn diff_changed_next_hop_is_add() {
        let last_sent = routes(&[("10.0.0.0/24", "10.0.0.1")]);
        let new_routes = routes(&[("10.0.0.0/24", "10.0.0.2")]);
        assert_eq!(
            diff_routes(&last_sent, &new_routes),
            vec![OspfRouteUpdate::Add(OspfRoute {
                interface_id: None,
                prefix: "10.0.0.0/24".parse().unwrap(),
                next_hop: "10.0.0.2".parse().unwrap(),
                backup_next_hop: None,
                metric: 10,
            })]
        );
    }

    #[test]
    fn diff_removed_prefix_is_remove() {
        let last_sent = routes(&[("10.0.0.0/24", "10.0.0.1")]);
        assert_eq!(
            diff_routes(&last_sent, &HashMap::new()),
            vec![OspfRouteUpdate::Remove("10.0.0.0/24".parse().unwrap())]
        );
    }

    #[test]
    fn diff_mixed_add_and_remove() {
        let last_sent = routes(&[("10.0.0.0/24", "10.0.0.1"), ("10.0.1.0/24", "10.0.1.1")]);
        let new_routes = routes(&[("10.0.0.0/24", "10.0.0.1"), ("10.0.2.0/24", "10.0.2.1")]);
        let mut updates = diff_routes(&last_sent, &new_routes);
        updates.sort_by_key(|u| format!("{u:?}"));
        let mut expected = vec![
            OspfRouteUpdate::Add(OspfRoute {
                interface_id: None,
                prefix: "10.0.2.0/24".parse().unwrap(),
                next_hop: "10.0.2.1".parse().unwrap(),
                backup_next_hop: None,
                metric: 10,
            }),
            OspfRouteUpdate::Remove("10.0.1.0/24".parse().unwrap()),
        ];
        expected.sort_by_key(|u| format!("{u:?}"));
        assert_eq!(updates, expected);
    }

    #[test]
    fn diff_backup_only_change_is_add() {
        let gw: IpAddr = "10.0.0.1".parse().unwrap();
        let bk: IpAddr = "10.0.9.9".parse().unwrap();
        let p: IpNet = "10.0.0.0/24".parse().unwrap();
        let last_sent = HashMap::from([(p, (gw, None, 10))]);
        let new_routes = HashMap::from([(p, (gw, Some(bk), 10))]);
        assert_eq!(
            diff_routes(&last_sent, &new_routes),
            vec![OspfRouteUpdate::Add(OspfRoute {
                prefix: p,
                next_hop: gw,
                interface_id: None,
                backup_next_hop: Some(bk),
                metric: 10,
            })]
        );
    }
}
