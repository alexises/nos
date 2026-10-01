//! Forwards this table's redistributable routes to the owning `nos-ospfd`
//! instance over one long-lived connection — the OSPF-redistribution
//! analogue of `bgp_client.rs`, near line-for-line: same single-connection,
//! fixed-delay-reconnect, fire-and-forget-with-no-reply shape
//! (`OspfRequest::RedistributeRoutes` gets no reply, like
//! `BgpRequest::RedistributeRoutes`).
//!
//! `ponytail:` this is a near line-for-line duplicate of `bgp_client.rs`
//! rather than a generic `redistribute_client<Req>` — two call sites with
//! slightly different `Request`/`ServiceRef` wiring don't justify a generic
//! abstraction; factor if a third protocol target ever redistributes.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use futures::SinkExt;
use ipnet::IpNet;
use nos_proto::{IpcCodec, OspfRequest, RedistributeUpdate, RedistributedRoute, Role, ServiceRef};
use tokio::sync::watch;
use tokio_util::codec::FramedWrite;
use tracing::{debug, warn};

use crate::watchdog_client::resolve_once;

/// Fixed retry delay, matching every other reconnect/resolve loop in this
/// crate (`watchdog_client::RETRY_DELAY`, `reconcile::RECONNECT_DELAY`,
/// `bgp_client::RETRY_DELAY`).
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// The desired redistribution state for this table, published by
/// `crate::reconcile::resync` on every resync (diff-triggered or timer
/// alike) regardless of whether anything actually changed — mirrors
/// `bgp_client::RedistributeTarget` exactly, this module is what makes a
/// redundant publish a no-op.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RedistributeTarget {
    /// Which `nos-ospfd` instance (by `OspfInstance` name) this table's
    /// routes should be pushed into. `None` when the table has no owning
    /// `OspfInstance`, or doesn't exist in the running config at all.
    pub ospf_instance: Option<String>,
    /// The routes to redistribute — already filtered to whatever rule is
    /// active (e.g. `redistribute from static to ospf`), v4 and v6 alike
    /// (`OSPFv2` itself only ever consumes the v4 ones — see `ospf::link::
    /// LinkManager::apply_redistribute_update`).
    pub routes: Vec<RedistributedRoute>,
}

/// Spawns the background task that owns the redistribution-push connection
/// for this table's lifetime and returns the `watch::Sender` `resync` uses
/// to publish the current desired state. Seeded with an empty target
/// (`ospf_instance: None`) — the task starts idle until the first resync.
pub fn spawn(
    watchdog_socket: PathBuf,
    shutdown: watch::Receiver<bool>,
) -> watch::Sender<RedistributeTarget> {
    let (tx, rx) = watch::channel(RedistributeTarget::default());
    tokio::spawn(run(watchdog_socket, rx, shutdown));
    tx
}

/// Owns the connection to this table's `nos-ospfd` instance for the whole
/// process lifetime. See the module doc comment for the overall shape.
async fn run(
    watchdog_socket: PathBuf,
    mut target_rx: watch::Receiver<RedistributeTarget>,
    mut shutdown: watch::Receiver<bool>,
) {
    while !*shutdown.borrow() {
        let target = target_rx.borrow_and_update().clone();
        let Some(name) = target.ospf_instance.clone() else {
            // Nothing to connect to yet — idle until the target changes.
            if wait_idle(&mut target_rx, &mut shutdown).await {
                break;
            }
            continue;
        };

        let Some(ospf_socket) =
            resolve_once(&watchdog_socket, &ServiceRef::OspfInstance(name.clone())).await
        else {
            debug!(ospf_instance = %name, "failed to resolve nos-ospfd instance via nos-watchdogd, retrying");
            if wait_retry(RETRY_DELAY, &mut target_rx, &mut shutdown).await {
                break;
            }
            continue;
        };

        let stream = match nos_pki::connect(&ospf_socket, Role::Ospfd, &name).await {
            Ok(stream) => stream,
            Err(e) => {
                warn!(
                    ospf_instance = %name,
                    socket = %ospf_socket.display(),
                    error = %e,
                    "failed to connect to nos-ospfd, retrying"
                );
                if wait_retry(RETRY_DELAY, &mut target_rx, &mut shutdown).await {
                    break;
                }
                continue;
            }
        };

        let mut writer = FramedWrite::new(stream, IpcCodec::<OspfRequest>::default());

        // Re-read the target once more: it may have changed while we were
        // resolving/connecting. If it no longer names the instance we just
        // connected to, drop this connection unsent and let the outer loop
        // re-evaluate from scratch — nothing was sent on it, so there is
        // nothing to withdraw.
        let current = target_rx.borrow_and_update().clone();
        if current.ospf_instance != target.ospf_instance {
            continue;
        }

        if writer
            .send(OspfRequest::RedistributeRoutes(RedistributeUpdate::Full(
                current.routes.clone(),
            )))
            .await
            .is_err()
        {
            warn!(ospf_instance = %name, "failed to send initial redistribution snapshot to nos-ospfd, retrying");
            if wait_retry(RETRY_DELAY, &mut target_rx, &mut shutdown).await {
                break;
            }
            continue;
        }
        let mut last_sent = build_last_sent(&current.routes);
        debug!(
            ospf_instance = %name,
            routes = last_sent.len(),
            "sent initial redistribution snapshot to nos-ospfd"
        );

        // Inner loop: same connection, same target instance, until the
        // target changes to something else or a write fails.
        loop {
            tokio::select! {
                changed = target_rx.changed() => {
                    if changed.is_err() {
                        // Sender dropped: the process is exiting.
                        return;
                    }
                    let new_target = target_rx.borrow_and_update().clone();
                    if new_target.ospf_instance != Some(name.clone()) {
                        // Withdraw everything from this connection before
                        // switching away — best-effort, we're tearing this
                        // connection down regardless of the outcome.
                        let _ = writer
                            .send(OspfRequest::RedistributeRoutes(RedistributeUpdate::Full(Vec::new())))
                            .await;
                        break;
                    }
                    let updates = diff_routes(&last_sent, &new_target.routes);
                    let mut write_failed = false;
                    for update in updates {
                        if writer.send(OspfRequest::RedistributeRoutes(update)).await.is_err() {
                            write_failed = true;
                            break;
                        }
                    }
                    if write_failed {
                        warn!(ospf_instance = %name, "write failure sending redistribution update, reconnecting");
                        break;
                    }
                    last_sent = build_last_sent(&new_target.routes);
                }
                _ = shutdown.changed() => return,
            }
        }
        // Reconnect (or idle, if the new target is None) immediately — the
        // outer loop re-reads the current target from scratch.
    }
}

/// Waits until `target_rx` changes or `shutdown` fires. Returns `true` if
/// the caller should stop entirely (shutdown requested, or the sender side
/// of `target_rx` was dropped).
async fn wait_idle(
    target_rx: &mut watch::Receiver<RedistributeTarget>,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        changed = target_rx.changed() => changed.is_err(),
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

/// Waits out `delay`, interruptible by either `target_rx` changing (so a
/// resolve/connect retry doesn't sit on a stale target) or `shutdown`
/// firing. Returns `true` if the caller should stop entirely.
async fn wait_retry(
    delay: Duration,
    target_rx: &mut watch::Receiver<RedistributeTarget>,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => false,
        changed = target_rx.changed() => changed.is_err(),
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

/// Builds the `prefix -> gateway` map a set of routes reduces to, for
/// diffing purposes.
fn build_last_sent(routes: &[RedistributedRoute]) -> HashMap<IpNet, IpAddr> {
    routes.iter().map(|r| (r.prefix, r.gateway)).collect()
}

/// Computes the minimal `RedistributeUpdate`s needed to bring `last_sent`
/// (what the peer connection was last told) up to `new_routes`: an `Add`
/// for every prefix that's new or whose gateway changed, a `Remove` for
/// every prefix `last_sent` had that `new_routes` no longer does. Pure and
/// unit-tested directly — the surrounding connection/reconnect machinery
/// isn't.
fn diff_routes(
    last_sent: &HashMap<IpNet, IpAddr>,
    new_routes: &[RedistributedRoute],
) -> Vec<RedistributeUpdate> {
    let mut updates = Vec::new();
    let new_map = build_last_sent(new_routes);

    for route in new_routes {
        match last_sent.get(&route.prefix) {
            Some(gateway) if *gateway == route.gateway => {}
            _ => updates.push(RedistributeUpdate::Add(route.clone())),
        }
    }
    for prefix in last_sent.keys() {
        if !new_map.contains_key(prefix) {
            updates.push(RedistributeUpdate::Remove(*prefix));
        }
    }
    updates
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(prefix: &str, gateway: &str) -> RedistributedRoute {
        RedistributedRoute {
            prefix: prefix.parse().unwrap(),
            gateway: gateway.parse().unwrap(),
        }
    }

    #[test]
    fn diff_empty_to_empty_is_empty() {
        let last_sent = HashMap::new();
        assert_eq!(diff_routes(&last_sent, &[]), [] as [nos_proto::RedistributeUpdate; 0]);
    }

    #[test]
    fn diff_new_prefix_is_add() {
        let last_sent = HashMap::new();
        let new = vec![route("10.0.0.0/24", "10.0.0.1")];
        assert_eq!(
            diff_routes(&last_sent, &new),
            vec![RedistributeUpdate::Add(route("10.0.0.0/24", "10.0.0.1"))]
        );
    }

    #[test]
    fn diff_unchanged_prefix_is_noop() {
        let new = vec![route("10.0.0.0/24", "10.0.0.1")];
        let last_sent = build_last_sent(&new);
        assert_eq!(diff_routes(&last_sent, &new), [] as [nos_proto::RedistributeUpdate; 0]);
    }

    #[test]
    fn diff_changed_gateway_is_add() {
        let old = vec![route("10.0.0.0/24", "10.0.0.1")];
        let last_sent = build_last_sent(&old);
        let new = vec![route("10.0.0.0/24", "10.0.0.2")];
        assert_eq!(
            diff_routes(&last_sent, &new),
            vec![RedistributeUpdate::Add(route("10.0.0.0/24", "10.0.0.2"))]
        );
    }

    #[test]
    fn diff_removed_prefix_is_remove() {
        let old = vec![route("10.0.0.0/24", "10.0.0.1")];
        let last_sent = build_last_sent(&old);
        assert_eq!(
            diff_routes(&last_sent, &[]),
            vec![RedistributeUpdate::Remove("10.0.0.0/24".parse().unwrap())]
        );
    }

    #[test]
    fn diff_mixed_add_and_remove() {
        let old = vec![
            route("10.0.0.0/24", "10.0.0.1"),
            route("10.0.1.0/24", "10.0.1.1"),
        ];
        let last_sent = build_last_sent(&old);
        let new = vec![
            route("10.0.0.0/24", "10.0.0.1"),
            route("10.0.2.0/24", "10.0.2.1"),
        ];
        let mut updates = diff_routes(&last_sent, &new);
        updates.sort_by_key(|u| format!("{u:?}"));
        let mut expected = vec![
            RedistributeUpdate::Add(route("10.0.2.0/24", "10.0.2.1")),
            RedistributeUpdate::Remove("10.0.1.0/24".parse().unwrap()),
        ];
        expected.sort_by_key(|u| format!("{u:?}"));
        assert_eq!(updates, expected);
    }

    #[test]
    fn default_target_is_idle() {
        let target = RedistributeTarget::default();
        assert_eq!(target.ospf_instance, None);
        assert_eq!(target.routes, [] as [nos_proto::RedistributedRoute; 0]);
    }
}
