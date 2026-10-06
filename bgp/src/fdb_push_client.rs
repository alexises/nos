//! Pushes every EVPN route this instance received to its consumers — the
//! reverse direction of their own pushes of local routes to `nos-bgpd`, and
//! the EVPN twin of `rib_push_client` (one persistent connection per
//! consumer, `Full` on connect, diffed `Add`/`Remove` after). Two feeds:
//!
//! - `Feed::Domains`: the `nos-fdbd` of each broadcast domain whose
//!   `redistribute from mac to bgp` names this instance — every route but
//!   Type-5 (`FdbRequest::PushEvpnRoutes`).
//! - `Feed::Tables`: the `nos-ribd` of each routing table whose
//!   `evpn.bgp_instance` names this instance — every Type-5 route
//!   (`RibRequest::PushEvpnRoutes`).
//!
//! Same fixed-poll design and the same ceiling as `rib_push_client`: a
//! `ponytail:` upgrade to a `Notify` from `BgpRib::handle_update` if
//! sub-second propagation is ever needed. Route-Target filtering is the
//! receiver's job, so every consumer of a feed gets every route of it. The
//! write-only connection is also read for EOF each tick, so a restarted
//! consumer (which lost what it was told) gets a fresh `Full` at once.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::{FutureExt, SinkExt};
use nos_proto::{
    EvpnKey, EvpnRoute, EvpnUpdate, FdbRequest, IpcCodec, RibRequest, Role, ServiceRef,
};
use tokio::io::{AsyncReadExt, ReadHalf};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::codec::FramedWrite;
use tracing::{debug, info, warn};

use crate::session::SessionManager;
use crate::watchdog_client::resolve_once;

// ponytail: fixed poll, see the module doc.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

type Routes = HashMap<EvpnKey, EvpnRoute>;

/// Which consumers a feed task serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feed {
    Domains,
    Tables,
}

impl Feed {
    fn service(self, name: &str) -> ServiceRef {
        match self {
            Feed::Domains => ServiceRef::FdbDomain(name.to_string()),
            Feed::Tables => ServiceRef::RibTable(name.to_string()),
        }
    }

    fn role(self) -> Role {
        match self {
            Feed::Domains => Role::Fdbd,
            Feed::Tables => Role::Ribd,
        }
    }

    fn peer(self) -> &'static str {
        match self {
            Feed::Domains => "nos-fdbd",
            Feed::Tables => "nos-ribd",
        }
    }
}

enum Writer {
    Fdb(FramedWrite<tokio::io::WriteHalf<nos_pki::Stream>, IpcCodec<FdbRequest>>),
    Rib(FramedWrite<tokio::io::WriteHalf<nos_pki::Stream>, IpcCodec<RibRequest>>),
}

impl Writer {
    async fn send(&mut self, update: EvpnUpdate) -> bool {
        match self {
            Writer::Fdb(w) => w.send(FdbRequest::PushEvpnRoutes(update)).await.is_ok(),
            Writer::Rib(w) => w.send(RibRequest::PushEvpnRoutes(update)).await.is_ok(),
        }
    }
}

pub fn spawn(
    watchdog_socket: PathBuf,
    sessions: Arc<SessionManager>,
    feed: Feed,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(run(watchdog_socket, sessions, feed, shutdown))
}

struct Conn {
    writer: Writer,
    reader: ReadHalf<nos_pki::Stream>,
    last_sent: Routes,
}

impl Conn {
    /// Whether the consumer closed the connection (it never writes to it).
    fn closed(&mut self) -> bool {
        let mut buf = [0u8; 64];
        matches!(
            self.reader.read(&mut buf).now_or_never(),
            Some(Ok(0) | Err(_))
        )
    }
}

async fn run(
    watchdog_socket: PathBuf,
    sessions: Arc<SessionManager>,
    feed: Feed,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut conns: HashMap<String, Conn> = HashMap::new();
    while !*shutdown.borrow() {
        let (targets, routes) = sessions.evpn_feed_snapshot(feed == Feed::Tables).await;
        // A consumer no longer attached (or whose write failed, or that
        // closed the connection) just loses it; the next tick reconnects
        // with a `Full`.
        conns.retain(|t, c| targets.contains(t) && !c.closed());
        for target in targets {
            if let Some(conn) = conns.get_mut(&target) {
                let mut failed = false;
                for u in diff(&conn.last_sent, &routes) {
                    if !conn.writer.send(u).await {
                        warn!(target = %target, peer = feed.peer(), "write failure pushing evpn routes, reconnecting");
                        failed = true;
                        break;
                    }
                }
                if failed {
                    conns.remove(&target);
                } else {
                    conn.last_sent.clone_from(&routes);
                }
            } else if let Some(conn) = connect(&watchdog_socket, feed, &target, &routes).await {
                conns.insert(target, conn);
            }
        }
        tokio::select! {
            () = tokio::time::sleep(POLL_INTERVAL) => {}
            _ = shutdown.changed() => {}
        }
    }
}

async fn connect(
    watchdog_socket: &Path,
    feed: Feed,
    target: &str,
    routes: &Routes,
) -> Option<Conn> {
    let socket = resolve_once(watchdog_socket, &feed.service(target)).await?;
    let stream = match nos_pki::connect(&socket, feed.role(), target).await {
        Ok(s) => s,
        Err(e) => {
            debug!(target = %target, peer = feed.peer(), error = %e, "evpn consumer not reachable yet, retrying");
            return None;
        }
    };
    let (reader, write_half) = tokio::io::split(stream);
    let mut writer = match feed {
        Feed::Domains => Writer::Fdb(FramedWrite::new(write_half, IpcCodec::default())),
        Feed::Tables => Writer::Rib(FramedWrite::new(write_half, IpcCodec::default())),
    };
    if !writer
        .send(EvpnUpdate::Full(routes.values().cloned().collect()))
        .await
    {
        warn!(target = %target, peer = feed.peer(), "failed to send the initial evpn snapshot, retrying");
        return None;
    }
    match feed {
        Feed::Domains => {
            info!(domain = %target, routes = routes.len(), "sent initial evpn snapshot to nos-fdbd");
        }
        Feed::Tables => {
            info!(table = %target, routes = routes.len(), "sent initial evpn snapshot to nos-ribd");
        }
    }
    Some(Conn {
        writer,
        reader,
        last_sent: routes.clone(),
    })
}

/// The `Add`/`Remove`s that bring `last_sent` up to `new`. Pure, unit-tested.
fn diff(last_sent: &Routes, new: &Routes) -> Vec<EvpnUpdate> {
    let mut updates = Vec::new();
    for (key, route) in new {
        if last_sent.get(key) != Some(route) {
            updates.push(EvpnUpdate::Add(route.clone()));
        }
    }
    for key in last_sent.keys() {
        if !new.contains_key(key) {
            updates.push(EvpnUpdate::Remove(key.clone()));
        }
    }
    updates
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(mac: u8, vni: u32) -> (EvpnKey, EvpnRoute) {
        let key = EvpnKey::Mac {
            rd: [0; 8],
            mac: [0, 0, 0, 0, 0, mac],
        };
        (
            key.clone(),
            EvpnRoute {
                key,
                vni,
                next_hop: "192.0.2.1".parse().unwrap(),
                ext_communities: vec![],
                esi: [0; 10],
                l3_vni: None,
            },
        )
    }

    #[test]
    fn diff_adds_changes_and_removes_only_what_moved() {
        let old: Routes = [route(1, 10), route(2, 10)].into();
        let new: Routes = [route(1, 10), route(2, 20), route(3, 10)].into();
        let mut updates = diff(&old, &new);
        updates.sort_by_key(|u| format!("{u:?}"));
        assert_eq!(updates.len(), 2);
        assert!(matches!(&updates[0], EvpnUpdate::Add(r) if r.vni == 20));
        assert!(matches!(&updates[1], EvpnUpdate::Add(r) if r.vni == 10));
        let mut removals = diff(&new, &[route(1, 10)].into());
        removals.sort_by_key(|u| format!("{u:?}"));
        assert_eq!(
            removals,
            vec![
                EvpnUpdate::Remove(route(2, 0).0),
                EvpnUpdate::Remove(route(3, 0).0)
            ]
        );
    }

    #[test]
    fn feeds_name_their_consumers() {
        assert_eq!(
            Feed::Tables.service("tenant"),
            ServiceRef::RibTable("tenant".to_string())
        );
        assert_eq!(Feed::Tables.role(), Role::Ribd);
        assert_eq!(
            Feed::Domains.service("bd1"),
            ServiceRef::FdbDomain("bd1".to_string())
        );
        assert_eq!(Feed::Domains.role(), Role::Fdbd);
    }
}
