//! Originates this table's best routes as EVPN Type-5 routes into its
//! `evpn.bgp_instance` (the underlay `nos-bgpd`) over one long-lived
//! `BgpRequest::RedistributeEvpnPrefixes` connection — `bgp_client.rs`'s
//! shape, independent of it (the two may name different instances): a
//! `Full` on every (re)connect, then the `Add`/`Remove`s each new published
//! `EvpnTarget` differs by. The write-only connection is also read for EOF,
//! so a `nos-bgpd` restart gets a fresh `Full` at once.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use futures::SinkExt;
use nos_proto::{BgpRequest, EvpnKey, EvpnRoute, EvpnUpdate, IpcCodec, Role, ServiceRef};
use tokio::io::AsyncReadExt;
use tokio::sync::watch;
use tokio_util::codec::FramedWrite;
use tracing::{debug, info, warn};

use crate::watchdog_client::resolve_once;

const RETRY_DELAY: Duration = Duration::from_secs(1);

/// The Type-5 routes to originate and where, published by
/// `reconcile::resync` (`crate::evpn::originated`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EvpnTarget {
    /// `None`: the table has no `evpn` (or no Router's MAC yet) — idle.
    pub bgp_instance: Option<String>,
    pub routes: Vec<EvpnRoute>,
}

pub fn spawn(
    watchdog_socket: PathBuf,
    table: String,
    shutdown: watch::Receiver<bool>,
) -> watch::Sender<EvpnTarget> {
    let (tx, rx) = watch::channel(EvpnTarget::default());
    tokio::spawn(run(watchdog_socket, table, rx, shutdown));
    tx
}

fn keyed(routes: &[EvpnRoute]) -> HashMap<EvpnKey, EvpnRoute> {
    routes.iter().map(|r| (r.key.clone(), r.clone())).collect()
}

/// The `Add`/`Remove`s that bring `last` up to `new`. Pure, unit-tested.
fn diff(last: &HashMap<EvpnKey, EvpnRoute>, new: &[EvpnRoute]) -> Vec<EvpnUpdate> {
    let new = keyed(new);
    let mut out: Vec<EvpnUpdate> = new
        .values()
        .filter(|r| last.get(&r.key) != Some(*r))
        .map(|r| EvpnUpdate::Add(r.clone()))
        .collect();
    out.extend(
        last.keys()
            .filter(|k| !new.contains_key(*k))
            .map(|k| EvpnUpdate::Remove(k.clone())),
    );
    out
}

async fn run(
    watchdog_socket: PathBuf,
    table: String,
    mut rx: watch::Receiver<EvpnTarget>,
    mut shutdown: watch::Receiver<bool>,
) {
    let retry = |rx: &mut watch::Receiver<EvpnTarget>, shutdown: &mut watch::Receiver<bool>| {
        let (mut rx, mut shutdown) = (rx.clone(), shutdown.clone());
        async move {
            tokio::select! {
                () = tokio::time::sleep(RETRY_DELAY) => false,
                c = rx.changed() => c.is_err(),
                _ = shutdown.changed() => true,
            }
        }
    };
    while !*shutdown.borrow() {
        let target = rx.borrow_and_update().clone();
        let Some(name) = target.bgp_instance.clone() else {
            tokio::select! {
                c = rx.changed() => if c.is_err() { return },
                _ = shutdown.changed() => return,
            }
            continue;
        };
        let socket = resolve_once(&watchdog_socket, &ServiceRef::BgpInstance(name.clone())).await;
        let stream = match socket {
            Some(s) => nos_pki::connect(&s, Role::Bgpd, &name).await.ok(),
            None => None,
        };
        let Some(stream) = stream else {
            debug!(table = %table, bgp_instance = %name, "nos-bgpd not reachable yet, retrying");
            if retry(&mut rx, &mut shutdown).await {
                return;
            }
            continue;
        };
        let (mut reader, w) = tokio::io::split(stream);
        let mut writer = FramedWrite::new(w, IpcCodec::<BgpRequest>::default());
        let send = |update| BgpRequest::RedistributeEvpnPrefixes {
            table: table.clone(),
            update,
        };
        let current = rx.borrow_and_update().clone();
        if current.bgp_instance != target.bgp_instance {
            continue;
        }
        if writer
            .send(send(EvpnUpdate::Full(current.routes.clone())))
            .await
            .is_err()
        {
            warn!(table = %table, bgp_instance = %name, "failed to send the type-5 snapshot to nos-bgpd, retrying");
            continue;
        }
        info!(table = %table, bgp_instance = %name, routes = current.routes.len(), "sent initial evpn type-5 snapshot to nos-bgpd");
        let mut last = keyed(&current.routes);
        let mut buf = [0u8; 64];
        loop {
            tokio::select! {
                c = rx.changed() => {
                    if c.is_err() {
                        return;
                    }
                    let new = rx.borrow_and_update().clone();
                    if new.bgp_instance.as_deref() != Some(name.as_str()) {
                        let _ = writer.send(send(EvpnUpdate::Full(Vec::new()))).await;
                        break;
                    }
                    let mut failed = false;
                    for u in diff(&last, &new.routes) {
                        if writer.send(send(u)).await.is_err() {
                            failed = true;
                            break;
                        }
                    }
                    if failed {
                        warn!(table = %table, bgp_instance = %name, "write failure sending type-5 routes, reconnecting");
                        break;
                    }
                    last = keyed(&new.routes);
                }
                n = reader.read(&mut buf) => {
                    if matches!(n, Ok(0) | Err(_)) {
                        warn!(table = %table, bgp_instance = %name, "nos-bgpd closed the type-5 connection, reconnecting");
                        break;
                    }
                }
                _ = shutdown.changed() => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(prefix: &str, vni: u32) -> EvpnRoute {
        EvpnRoute {
            key: EvpnKey::IpPrefix {
                rd: [0; 8],
                prefix: prefix.parse().unwrap(),
            },
            vni,
            next_hop: "10.50.0.2".parse().unwrap(),
            ext_communities: vec![],
            esi: [0; 10],
            l3_vni: None,
        }
    }

    #[test]
    fn diff_adds_changed_and_new_and_removes_gone() {
        let last = keyed(&[route("10.1.0.0/24", 1), route("10.2.0.0/24", 1)]);
        let mut got = diff(&last, &[route("10.1.0.0/24", 2), route("10.3.0.0/24", 1)]);
        got.sort_by_key(|u| format!("{u:?}"));
        assert_eq!(
            got,
            vec![
                EvpnUpdate::Add(route("10.1.0.0/24", 2)),
                EvpnUpdate::Add(route("10.3.0.0/24", 1)),
                EvpnUpdate::Remove(route("10.2.0.0/24", 0).key),
            ]
        );
        assert_eq!(
            diff(&last, &[route("10.1.0.0/24", 1), route("10.2.0.0/24", 1)]),
            [] as [EvpnUpdate; 0]
        );
    }
}
