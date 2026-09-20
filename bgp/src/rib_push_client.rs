//! Pushes this instance's current BGP best-path routes to the owning
//! `nos-ribd` instance for kernel installation, mirroring `nos-rib`'s
//! `bgp_client.rs` (a persistent connection, `Full` snapshot on connect,
//! diffed `Add`/`Remove` afterward) but role-reversed: this side connects
//! out and pushes.
//!
//! Unlike `bgp_client.rs`'s `watch`-driven design, this is driven by a fixed
//! poll of [`SessionManager::bgp_push_snapshot`] rather than an edge
//! trigger — `BgpRib`'s loc-rib changes from many internal call paths
//! (`handle_update`, redistribute-update application, peer disconnect),
//! and none of them expose a single hook to push a notification out from.
//! Polling and diffing gets the same converged end state for far less
//! surface area, at the cost of up to one poll interval's propagation
//! latency.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::SinkExt;
use ipnet::IpNet;
use nos_proto::{BgpRoute, BgpRouteUpdate, IpcCodec, RibRequest, Role, ServiceRef};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::codec::FramedWrite;
use tracing::{debug, warn};

use crate::session::SessionManager;
use crate::watchdog_client::resolve_once;

// ponytail: fixed poll, not edge-triggered from `BgpRib::recompute_and_propagate`
// — upgrade to a `Notify` wired through its mutation call sites if
// sub-second kernel convergence is ever required.
const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Matches every other reconnect/resolve loop in this codebase.
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// Spawns the background task that owns the route-push connection for this
/// process's lifetime.
pub fn spawn(
    watchdog_socket: PathBuf,
    sessions: Arc<SessionManager>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(run(watchdog_socket, sessions, shutdown))
}

async fn run(
    watchdog_socket: PathBuf,
    sessions: Arc<SessionManager>,
    mut shutdown: watch::Receiver<bool>,
) {
    while !*shutdown.borrow() {
        let (table, routes) = sessions.bgp_push_snapshot().await;
        let Some(table) = table else {
            // No owning routing table yet — idle until the next poll tick.
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
        if writer
            .send(RibRequest::PushBgpRoutes(vec![BgpRouteUpdate::Full(
                to_routes(&routes),
            )]))
            .await
            .is_err()
        {
            warn!(table = %table, "failed to send initial bgp route snapshot to nos-ribd, retrying");
            if wait_or_shutdown(RETRY_DELAY, &mut shutdown).await {
                break;
            }
            continue;
        }
        let mut last_sent = routes;
        debug!(table = %table, routes = last_sent.len(), "sent initial bgp route snapshot to nos-ribd");

        // Inner loop: same connection, same owning table, until the table
        // changes to something else (including `None`) or a write fails.
        loop {
            if wait_or_shutdown(POLL_INTERVAL, &mut shutdown).await {
                return;
            }
            let (new_table, new_routes) = sessions.bgp_push_snapshot().await;
            if new_table.as_deref() != Some(table.as_str()) {
                // Withdraw everything from this connection before switching
                // away — best-effort, we're tearing this connection down
                // regardless of the outcome.
                let _ = writer
                    .send(RibRequest::PushBgpRoutes(vec![BgpRouteUpdate::Full(
                        Vec::new(),
                    )]))
                    .await;
                break;
            }
            let updates = diff_routes(&last_sent, &new_routes);
            if !updates.is_empty()
                && writer
                    .send(RibRequest::PushBgpRoutes(updates))
                    .await
                    .is_err()
            {
                warn!(table = %table, "write failure sending bgp route update, reconnecting");
                break;
            }
            last_sent = new_routes;
        }
        // Reconnect (or idle, if the table is now None) immediately — the
        // outer loop re-reads the current snapshot from scratch.
    }
}

/// Waits out `delay`, interruptible by `shutdown` firing. Returns `true` if
/// the caller should stop entirely.
async fn wait_or_shutdown(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

fn to_routes(routes: &HashMap<IpNet, IpAddr>) -> Vec<BgpRoute> {
    routes
        .iter()
        .map(|(&prefix, &next_hop)| BgpRoute { prefix, next_hop })
        .collect()
}

/// Computes the minimal `BgpRouteUpdate`s needed to bring `last_sent` (what
/// the connection was last told) up to `new_routes`: an `Add` for every
/// prefix that's new or whose next-hop changed, a `Remove` for every prefix
/// `last_sent` had that `new_routes` no longer does. Pure and unit-tested
/// directly — the surrounding connection/reconnect machinery isn't.
fn diff_routes(
    last_sent: &HashMap<IpNet, IpAddr>,
    new_routes: &HashMap<IpNet, IpAddr>,
) -> Vec<BgpRouteUpdate> {
    let mut updates = Vec::new();
    for (&prefix, &next_hop) in new_routes {
        if last_sent.get(&prefix) != Some(&next_hop) {
            updates.push(BgpRouteUpdate::Add(BgpRoute { prefix, next_hop }));
        }
    }
    for prefix in last_sent.keys() {
        if !new_routes.contains_key(prefix) {
            updates.push(BgpRouteUpdate::Remove(*prefix));
        }
    }
    updates
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routes(pairs: &[(&str, &str)]) -> HashMap<IpNet, IpAddr> {
        pairs
            .iter()
            .map(|(p, gw)| (p.parse().unwrap(), gw.parse().unwrap()))
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
            vec![BgpRouteUpdate::Add(BgpRoute {
                prefix: "10.0.0.0/24".parse().unwrap(),
                next_hop: "10.0.0.2".parse().unwrap(),
            })]
        );
    }

    #[test]
    fn diff_removed_prefix_is_remove() {
        let last_sent = routes(&[("10.0.0.0/24", "10.0.0.1")]);
        assert_eq!(
            diff_routes(&last_sent, &HashMap::new()),
            vec![BgpRouteUpdate::Remove("10.0.0.0/24".parse().unwrap())]
        );
    }

    #[test]
    fn diff_mixed_add_and_remove() {
        let last_sent = routes(&[("10.0.0.0/24", "10.0.0.1"), ("10.0.1.0/24", "10.0.1.1")]);
        let new_routes = routes(&[("10.0.0.0/24", "10.0.0.1"), ("10.0.2.0/24", "10.0.2.1")]);
        let mut updates = diff_routes(&last_sent, &new_routes);
        updates.sort_by_key(|u| format!("{u:?}"));
        let mut expected = vec![
            BgpRouteUpdate::Add(BgpRoute {
                prefix: "10.0.2.0/24".parse().unwrap(),
                next_hop: "10.0.2.1".parse().unwrap(),
            }),
            BgpRouteUpdate::Remove("10.0.1.0/24".parse().unwrap()),
        ];
        expected.sort_by_key(|u| format!("{u:?}"));
        assert_eq!(updates, expected);
    }
}
