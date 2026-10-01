//! Originates this domain's local MACs into the named `nos-bgpd` instance
//! over one long-lived connection, mirroring `nos-rib`'s `bgp_client.rs`: a
//! `Full` snapshot on connect, then the minimal `Add`/`Remove` set for every
//! change, fire-and-forget (`BgpRequest::RedistributeMacs` gets no reply).
//! Unlike `nos-ribd`'s twin, the otherwise write-only connection is also
//! read for EOF, so a `nos-bgpd` restart (which forgets everything pushed) is
//! noticed at once and answered with a fresh `Full`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_proto::{BgpEvent, BgpRequest, EvpnKey, EvpnRoute, EvpnUpdate, IpcCodec, Role, ServiceRef};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, warn};

use crate::fdb::EvpnTarget;
use crate::watchdog_client::resolve_once;

/// Fixed delay, like every other reconnect/resolve loop in this codebase.
const RETRY_DELAY: Duration = Duration::from_secs(1);

pub fn spawn(
    watchdog_socket: PathBuf,
    target: watch::Receiver<EvpnTarget>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(run(watchdog_socket, target, shutdown))
}

async fn run(
    watchdog_socket: PathBuf,
    mut target_rx: watch::Receiver<EvpnTarget>,
    mut shutdown: watch::Receiver<bool>,
) {
    while !*shutdown.borrow() {
        let target = target_rx.borrow_and_update().clone();
        let Some(name) = target.bgp_instance.clone() else {
            tokio::select! {
                changed = target_rx.changed() => if changed.is_err() { return },
                _ = shutdown.changed() => {}
            }
            continue;
        };
        let domain = target.domain.clone();

        let Some(bgp_socket) =
            resolve_once(&watchdog_socket, &ServiceRef::BgpInstance(name.clone())).await
        else {
            debug!(bgp_instance = %name, "failed to resolve nos-bgpd via nos-watchdogd, retrying");
            retry_wait(&mut target_rx, &mut shutdown).await;
            continue;
        };
        let stream = match nos_pki::connect(&bgp_socket, Role::Bgpd, &name).await {
            Ok(s) => s,
            Err(e) => {
                warn!(bgp_instance = %name, error = %e, "failed to connect to nos-bgpd, retrying");
                retry_wait(&mut target_rx, &mut shutdown).await;
                continue;
            }
        };
        let (r, w) = tokio::io::split(stream);
        let mut reader = FramedRead::new(r, IpcCodec::<BgpEvent>::default());
        let mut writer = FramedWrite::new(w, IpcCodec::<BgpRequest>::default());

        // The target may have moved while connecting: start over if so.
        let current = target_rx.borrow_and_update().clone();
        if current.bgp_instance != target.bgp_instance {
            continue;
        }
        let full = EvpnUpdate::Full(current.routes.values().cloned().collect());
        if writer
            .send(BgpRequest::RedistributeMacs {
                domain: domain.clone(),
                update: full,
            })
            .await
            .is_err()
        {
            warn!(bgp_instance = %name, "failed to send the initial evpn snapshot to nos-bgpd, retrying");
            retry_wait(&mut target_rx, &mut shutdown).await;
            continue;
        }
        let mut last_sent = current.routes;
        info!(bgp_instance = %name, routes = last_sent.len(), "sent initial evpn snapshot to nos-bgpd");

        loop {
            tokio::select! {
                changed = target_rx.changed() => {
                    if changed.is_err() { return }
                    let new = target_rx.borrow_and_update().clone();
                    if new.bgp_instance.as_deref() != Some(name.as_str()) {
                        // Withdraw before switching away (best effort).
                        let _ = writer
                            .send(BgpRequest::RedistributeMacs {
                                domain: domain.clone(),
                                update: EvpnUpdate::Full(Vec::new()),
                            })
                            .await;
                        break;
                    }
                    let mut failed = false;
                    for update in diff(&last_sent, &new.routes) {
                        let req = BgpRequest::RedistributeMacs { domain: domain.clone(), update };
                        if writer.send(req).await.is_err() {
                            failed = true;
                            break;
                        }
                    }
                    if failed {
                        warn!(bgp_instance = %name, "write failure sending evpn update, reconnecting");
                        break;
                    }
                    last_sent = new.routes;
                }
                // nos-bgpd never replies on this connection: anything here is EOF/garbage.
                _ = reader.next() => {
                    warn!(bgp_instance = %name, "nos-bgpd closed the connection, reconnecting");
                    break;
                }
                _ = shutdown.changed() => return,
            }
        }
    }
}

async fn retry_wait(
    target_rx: &mut watch::Receiver<EvpnTarget>,
    shutdown: &mut watch::Receiver<bool>,
) {
    tokio::select! {
        () = tokio::time::sleep(RETRY_DELAY) => {}
        _ = target_rx.changed() => {}
        _ = shutdown.changed() => {}
    }
}

/// The `Add`/`Remove`s that bring `last_sent` up to `new`. Pure, tested.
fn diff(
    last_sent: &HashMap<EvpnKey, EvpnRoute>,
    new: &HashMap<EvpnKey, EvpnRoute>,
) -> Vec<EvpnUpdate> {
    let mut out: Vec<EvpnUpdate> = new
        .iter()
        .filter(|(k, r)| last_sent.get(*k) != Some(*r))
        .map(|(_, r)| EvpnUpdate::Add(r.clone()))
        .collect();
    out.extend(
        last_sent
            .keys()
            .filter(|k| !new.contains_key(*k))
            .map(|k| EvpnUpdate::Remove(k.clone())),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(mac: u8) -> (EvpnKey, EvpnRoute) {
        let key = EvpnKey::Mac {
            rd: [0; 8],
            mac: [0, 0, 0, 0, 0, mac],
        };
        (
            key.clone(),
            EvpnRoute {
                key,
                vni: 1,
                next_hop: "192.0.2.1".parse().unwrap(),
                ext_communities: vec![],
                esi: [0; 10],
            },
        )
    }

    #[test]
    fn diff_is_minimal() {
        let old = HashMap::from([route(1), route(2)]);
        let new = HashMap::from([route(2), route(3)]);
        let mut d = diff(&old, &new);
        d.sort_by_key(|u| format!("{u:?}"));
        assert_eq!(d.len(), 2);
        assert!(matches!(&d[0], EvpnUpdate::Add(r) if r.key == route(3).0));
        assert!(matches!(&d[1], EvpnUpdate::Remove(k) if *k == route(1).0));
        assert_eq!(diff(&new, &new), []);
    }
}
