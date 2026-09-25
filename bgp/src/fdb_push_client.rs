//! Pushes every EVPN route this instance received to the `nos-fdbd` of each
//! broadcast domain whose `redistribute from mac to bgp` names it — the
//! reverse direction of `nos-fdb`'s own push of local MACs to `nos-bgpd`, and
//! the EVPN twin of `rib_push_client` (one persistent connection per domain,
//! `Full` on connect, diffed `Add`/`Remove` after).
//!
//! Same fixed-poll design and the same ceiling as `rib_push_client`: a
//! `ponytail:` upgrade to a `Notify` from `BgpRib::handle_update` if
//! sub-second propagation is ever needed. Route-Target filtering is the
//! receiving `nos-fdbd`'s job, so every attached domain gets every route.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::SinkExt;
use nos_proto::{EvpnKey, EvpnRoute, EvpnUpdate, FdbRequest, IpcCodec, Role, ServiceRef};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::codec::FramedWrite;
use tracing::{debug, info, warn};

use crate::session::SessionManager;
use crate::watchdog_client::resolve_once;

// ponytail: fixed poll, see the module doc.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

type Routes = HashMap<EvpnKey, EvpnRoute>;
type Writer = FramedWrite<nos_pki::Stream, IpcCodec<FdbRequest>>;

pub fn spawn(
    watchdog_socket: PathBuf,
    sessions: Arc<SessionManager>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(run(watchdog_socket, sessions, shutdown))
}

struct Conn {
    writer: Writer,
    last_sent: Routes,
}

async fn run(
    watchdog_socket: PathBuf,
    sessions: Arc<SessionManager>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut conns: HashMap<String, Conn> = HashMap::new();
    while !*shutdown.borrow() {
        let (domains, routes) = sessions.fdb_push_snapshot().await;
        // A domain no longer attached (or whose fdbd write failed last tick)
        // just loses its connection; the next tick reconnects with a `Full`.
        conns.retain(|d, _| domains.contains(d));
        for domain in domains {
            if let Some(conn) = conns.get_mut(&domain) {
                let updates = diff(&conn.last_sent, &routes);
                let mut failed = false;
                for u in updates {
                    if conn
                        .writer
                        .send(FdbRequest::PushEvpnRoutes(u))
                        .await
                        .is_err()
                    {
                        warn!(domain = %domain, "write failure pushing evpn routes to nos-fdbd, reconnecting");
                        failed = true;
                        break;
                    }
                }
                if failed {
                    conns.remove(&domain);
                } else {
                    conn.last_sent.clone_from(&routes);
                }
            } else if let Some(conn) = connect(&watchdog_socket, &domain, &routes).await {
                conns.insert(domain, conn);
            }
        }
        tokio::select! {
            () = tokio::time::sleep(POLL_INTERVAL) => {}
            _ = shutdown.changed() => {}
        }
    }
}

async fn connect(watchdog_socket: &Path, domain: &str, routes: &Routes) -> Option<Conn> {
    let socket = resolve_once(watchdog_socket, &ServiceRef::FdbDomain(domain.to_string())).await?;
    let stream = match nos_pki::connect(&socket, Role::Fdbd, domain).await {
        Ok(s) => s,
        Err(e) => {
            debug!(domain = %domain, error = %e, "nos-fdbd not reachable yet, retrying");
            return None;
        }
    };
    let mut writer = FramedWrite::new(stream, IpcCodec::<FdbRequest>::default());
    let full = EvpnUpdate::Full(routes.values().cloned().collect());
    if writer.send(FdbRequest::PushEvpnRoutes(full)).await.is_err() {
        warn!(domain = %domain, "failed to send the initial evpn snapshot to nos-fdbd, retrying");
        return None;
    }
    info!(domain = %domain, routes = routes.len(), "sent initial evpn snapshot to nos-fdbd");
    Some(Conn {
        writer,
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
}
