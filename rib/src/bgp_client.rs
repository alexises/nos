//! Forwards this table's redistributable routes to the owning `nos-bgpd`
//! instance over one long-lived connection, mirroring `log_client.rs`'s
//! `ForwardingLayer` background task exactly: a single connection held for
//! the process's lifetime, fixed-delay reconnect, fire-and-forget sends with
//! no reply expected (`BgpRequest::RedistributeRoutes` gets none, like
//! `LogRequest::Push`).
//!
//! Unlike `log_client.rs`, what gets sent isn't a queue of independent
//! events but a *description of desired state* (`RedistributeTarget`,
//! published by `crate::reconcile::resync` on every resync via the
//! `watch::Sender` returned by [`spawn`]) — so this module also owns the
//! full/incremental diffing: a fresh connection always gets a complete
//! `RedistributeUpdate::Full` snapshot, and every later change against the
//! same target is reduced to the minimal `Add`/`Remove` set before being
//! sent.
//!
//! The connection is also read for EOF: `nos-bgpd` never replies on it, so a
//! read returning means it went away (a restart, #12). Without that, a
//! restarted `nos-bgpd` got nothing until the next route change.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use futures::SinkExt;
use ipnet::IpNet;
use nos_proto::{BgpRequest, IpcCodec, RedistributeUpdate, RedistributedRoute, Role, ServiceRef};
use tokio::io::AsyncReadExt;
use tokio::sync::watch;
use tokio_util::codec::FramedWrite;
use tracing::{debug, warn};

use nos_daemon::watchdog::resolve_once;

/// Fixed retry delay, matching every other reconnect/resolve loop in this
/// crate (`nos_daemon::watchdog`'s retry delay, `reconcile::RECONNECT_DELAY`).
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// The desired redistribution state for this table, published by
/// `crate::reconcile::resync` on every resync (diff-triggered or timer
/// alike) regardless of whether anything actually changed — this module is
/// what makes a redundant publish a no-op, the same division of labor
/// `driver.apply` already has with `resync`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RedistributeTarget {
    /// Which `nos-bgpd` instance (by `BgpInstance` name) this table's
    /// routes should be pushed into. `None` when the table has no owning
    /// `BgpInstance`, or doesn't exist in the running config at all.
    pub bgp_instance: Option<String>,
    /// The routes to redistribute — already filtered to whatever rule is
    /// active (e.g. `redistribute from static to bgp`), v4 and v6 alike.
    /// Empty when no rule is active.
    pub routes: Vec<RedistributedRoute>,
}

/// Spawns the background task that owns the redistribution-push connection
/// for this table's lifetime and returns the `watch::Sender` `resync` uses
/// to publish the current desired state. Seeded with an empty target
/// (`bgp_instance: None`) — the task starts idle until the first resync.
/// `chunk` is the routes per `RedistributeRoutes` frame of the initial
/// `Full` (`RedistributeUpdate::split_with`).
pub fn spawn(
    watchdog_socket: PathBuf,
    shutdown: watch::Receiver<bool>,
    chunk: usize,
) -> watch::Sender<RedistributeTarget> {
    let (tx, rx) = watch::channel(RedistributeTarget::default());
    tokio::spawn(run(watchdog_socket, rx, shutdown, chunk));
    tx
}

/// Owns the connection to this table's `nos-bgpd` instance for the whole
/// process lifetime. See the module doc comment for the overall shape.
async fn run(
    watchdog_socket: PathBuf,
    mut target_rx: watch::Receiver<RedistributeTarget>,
    mut shutdown: watch::Receiver<bool>,
    chunk: usize,
) {
    while !*shutdown.borrow() {
        let target = target_rx.borrow_and_update().clone();
        let Some(name) = target.bgp_instance.clone() else {
            // Nothing to connect to yet — idle until the target changes.
            if wait_idle(&mut target_rx, &mut shutdown).await {
                break;
            }
            continue;
        };

        let Some(bgp_socket) =
            resolve_once(&watchdog_socket, &ServiceRef::BgpInstance(name.clone())).await
        else {
            debug!(bgp_instance = %name, "failed to resolve nos-bgpd instance via nos-watchdogd, retrying");
            if wait_retry(RETRY_DELAY, &mut target_rx, &mut shutdown).await {
                break;
            }
            continue;
        };

        let stream = match nos_pki::connect(&bgp_socket, Role::Bgpd, &name).await {
            Ok(stream) => stream,
            Err(e) => {
                warn!(
                    bgp_instance = %name,
                    socket = %bgp_socket.display(),
                    error = %e,
                    "failed to connect to nos-bgpd, retrying"
                );
                if wait_retry(RETRY_DELAY, &mut target_rx, &mut shutdown).await {
                    break;
                }
                continue;
            }
        };

        let (mut reader, write_half) = tokio::io::split(stream);
        let mut writer = FramedWrite::new(write_half, IpcCodec::<BgpRequest>::default());
        let mut eof_buf = [0u8; 1];

        // Re-read the target once more: it may have changed while we were
        // resolving/connecting. If it no longer names the instance we just
        // connected to, drop this connection unsent and let the outer loop
        // re-evaluate from scratch — nothing was sent on it, so there is
        // nothing to withdraw.
        let current = target_rx.borrow_and_update().clone();
        if current.bgp_instance != target.bgp_instance {
            continue;
        }

        // A `Full` over `chunk` routes goes as `FullPart`s closed by a `Full`
        // (16 MiB frame cap, #729); `last_sent` moves only once all are out.
        let frames = RedistributeUpdate::Full(current.routes.clone()).split_with(chunk);
        if !nos_proto::chunk::send_all(
            &mut writer,
            frames.into_iter().map(BgpRequest::RedistributeRoutes),
        )
        .await
        {
            warn!(bgp_instance = %name, "failed to send initial redistribution snapshot to nos-bgpd, retrying");
            if wait_retry(RETRY_DELAY, &mut target_rx, &mut shutdown).await {
                break;
            }
            continue;
        }
        let mut last_sent = build_last_sent(&current.routes);
        debug!(
            bgp_instance = %name,
            routes = last_sent.len(),
            "sent initial redistribution snapshot to nos-bgpd"
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
                    if new_target.bgp_instance != Some(name.clone()) {
                        // Withdraw everything from this connection before
                        // switching away — best-effort, we're tearing this
                        // connection down regardless of the outcome.
                        let _ = writer
                            .send(BgpRequest::RedistributeRoutes(RedistributeUpdate::Full(Vec::new())))
                            .await;
                        break;
                    }
                    let updates = diff_routes(&last_sent, &new_target.routes);
                    let mut write_failed = false;
                    for update in updates {
                        if writer.send(BgpRequest::RedistributeRoutes(update)).await.is_err() {
                            write_failed = true;
                            break;
                        }
                    }
                    if write_failed {
                        warn!(bgp_instance = %name, "write failure sending redistribution update, reconnecting");
                        break;
                    }
                    last_sent = build_last_sent(&new_target.routes);
                }
                _ = reader.read(&mut eof_buf) => {
                    warn!(bgp_instance = %name, "nos-bgpd closed the redistribution connection, reconnecting");
                    break;
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
        assert_eq!(
            diff_routes(&last_sent, &[]),
            [] as [nos_proto::RedistributeUpdate; 0]
        );
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
        assert_eq!(
            diff_routes(&last_sent, &new),
            [] as [nos_proto::RedistributeUpdate; 0]
        );
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
        assert_eq!(target.bgp_instance, None);
        assert_eq!(target.routes, [] as [nos_proto::RedistributedRoute; 0]);
    }

    /// Frames the client sends for `routes` with a `chunk` budget, on a first
    /// connection and again once the receiver closes it (a restart, which
    /// must get a fresh `Full`).
    async fn sent(chunk: usize, routes: Vec<RedistributedRoute>) -> [Vec<RedistributeUpdate>; 2] {
        use nos_test_support::{serve, FakeWatchdog, Reply};

        let tmp = tempfile::tempdir().unwrap();
        let wd = FakeWatchdog::new(&tmp.path().join("wd.sock"));
        let peer = serve(
            &tmp.path().join("peer.sock"),
            "bgpd",
            "i1",
            |_: &BgpRequest| Reply::<()>::None,
        );
        wd.set(ServiceRef::BgpInstance("i1".into()), peer.path.clone());
        let (_stop, shutdown) = watch::channel(false);
        let tx = spawn(wd.path().to_path_buf(), shutdown, chunk);
        tx.send(RedistributeTarget {
            bgp_instance: Some("i1".into()),
            routes,
        })
        .unwrap();
        let mut out = [Vec::new(), Vec::new()];
        for (i, o) in out.iter_mut().enumerate() {
            for _ in 0..500 {
                o.extend(peer.take_seen().into_iter().map(|r| match r {
                    BgpRequest::RedistributeRoutes(u) => u,
                    other => panic!("unexpected {other:?}"),
                }));
                if matches!(o.last(), Some(RedistributeUpdate::Full(_))) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            if i == 0 {
                peer.close_connections();
            }
        }
        out
    }

    /// #729: a `Full` over the chunk crosses as `FullPart`s closed by a
    /// `Full`, in order; one under it stays a single request.
    #[tokio::test]
    async fn initial_full_is_split_at_the_chunk_and_resent_on_close() {
        let all: Vec<_> = (0..5)
            .map(|i| route(&format!("10.{i}.0.0/24"), "10.0.0.1"))
            .collect();
        let split = vec![
            RedistributeUpdate::FullPart(all[0..2].to_vec()),
            RedistributeUpdate::FullPart(all[2..4].to_vec()),
            RedistributeUpdate::Full(all[4..].to_vec()),
        ];
        assert_eq!(sent(2, all.clone()).await, [split.clone(), split]);
        let whole = vec![RedistributeUpdate::Full(all.clone())];
        assert_eq!(sent(5, all).await, [whole.clone(), whole]);
    }
}
