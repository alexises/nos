//! Holds static routes with a `bfd` reference out of the RIB until
//! `nos-bfdd` reports their gateway's session `Up`.
//!
//! `reconcile::resync` publishes the gateways it wants sessions for (with
//! their profiles) on a `watch`; this task registers them with `nos-bfdd` on
//! one persistent connection and publishes the set of gateways that are `Up`
//! on another, which `resync` filters the routes by. Fail closed: with no
//! connection to `nos-bfdd` the up set is empty, so the routes stay out.
//! After a reconnect everything is registered again.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_proto::schema::BfdProfile;
use nos_proto::{BfdEvent, BfdRequest, BfdState, IpcCodec, Role, ServiceRef, SessionKey};
use tokio::sync::watch;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, warn};

use crate::watchdog_client::resolve_once;

const RETRY_DELAY: Duration = Duration::from_secs(1);

/// One wanted session: the profile and whether the gateway is off every
/// connected subnet (RFC 5883 multihop; `nos-bfdd` picks the local address).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Want {
    pub profile: BfdProfile,
    pub multihop: bool,
}

/// The gateways that want a session.
pub type Target = HashMap<IpAddr, Want>;
/// The gateways whose session is `Up`.
pub type UpSet = HashSet<IpAddr>;

/// Pure bookkeeping of what is registered and what is up.
#[derive(Debug)]
pub struct Book {
    table: String,
    registered: Target,
    up: UpSet,
}

impl Book {
    pub fn new(table: impl Into<String>) -> Self {
        Book {
            table: table.into(),
            registered: Target::new(),
            up: UpSet::new(),
        }
    }

    pub fn up(&self) -> &UpSet {
        &self.up
    }

    /// Interface resolved by the peer address alone.
    fn key(&self, peer: IpAddr, multihop: bool) -> SessionKey {
        SessionKey {
            aggregate: None,
            table: self.table.clone(),
            peer,
            local: None,
            interface: None,
            multihop,
        }
    }

    /// The requests that bring `nos-bfdd` in line with `target`: a `Register`
    /// for each new or re-profiled gateway (a re-`Register` is the profile
    /// refresh), a `Deregister` for each one that went. A gateway that went
    /// is no longer up.
    pub fn sync(&mut self, target: &Target) -> Vec<BfdRequest> {
        let mut reqs = Vec::new();
        for (peer, want) in target {
            let old = self.registered.get(peer);
            if old == Some(want) {
                continue;
            }
            // A different path is a different session: the old one goes.
            if let Some(old) = old.filter(|o| o.multihop != want.multihop) {
                reqs.push(BfdRequest::Deregister {
                    key: self.key(*peer, old.multihop),
                });
                self.up.remove(peer);
            }
            reqs.push(BfdRequest::Register {
                table: self.table.clone(),
                peer: *peer,
                local: None,
                interface: None,
                profile: want.profile.clone(),
                multihop: want.multihop,
            });
            self.registered.insert(*peer, want.clone());
        }
        let gone: Vec<IpAddr> = self
            .registered
            .keys()
            .filter(|p| !target.contains_key(p))
            .copied()
            .collect();
        for peer in gone {
            let old = self.registered.remove(&peer).expect("just listed");
            self.up.remove(&peer);
            reqs.push(BfdRequest::Deregister {
                key: self.key(peer, old.multihop),
            });
        }
        reqs
    }

    /// A state event; whether the up set changed. Anything but `Up`
    /// (including `AdminDown`) takes the gateway out.
    pub fn on_state(&mut self, key: &SessionKey, state: BfdState) -> bool {
        if key.table != self.table || !self.registered.contains_key(&key.peer) {
            return false;
        }
        if state == BfdState::Up {
            self.up.insert(key.peer)
        } else {
            self.up.remove(&key.peer)
        }
    }

    /// The connection is gone: forget it all (fail closed), so the next
    /// connection registers everything again. Whether the up set changed.
    pub fn reset(&mut self) -> bool {
        self.registered.clear();
        let changed = !self.up.is_empty();
        self.up.clear();
        changed
    }
}

/// Starts the task. The sender takes `resync`'s wishes, the receiver
/// carries the `Up` gateways back.
pub fn spawn(
    watchdog_socket: PathBuf,
    table: String,
    shutdown: watch::Receiver<bool>,
) -> (watch::Sender<Target>, watch::Receiver<UpSet>) {
    let (target_tx, target_rx) = watch::channel(Target::new());
    let (up_tx, up_rx) = watch::channel(UpSet::new());
    tokio::spawn(run(watchdog_socket, table, target_rx, up_tx, shutdown));
    (target_tx, up_rx)
}

fn publish(up_tx: &watch::Sender<UpSet>, book: &Book) {
    up_tx.send_if_modified(|u| {
        let changed = u != book.up();
        if changed {
            u.clone_from(book.up());
        }
        changed
    });
}

async fn wait_retry(shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(RETRY_DELAY) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

async fn run(
    watchdog_socket: PathBuf,
    table: String,
    mut target_rx: watch::Receiver<Target>,
    up_tx: watch::Sender<UpSet>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut book = Book::new(table.clone());
    while !*shutdown.borrow() {
        // Nothing wants a session: leave nos-bfdd alone until something does.
        if target_rx.borrow().is_empty() {
            tokio::select! {
                r = target_rx.changed() => if r.is_err() { return },
                _ = shutdown.changed() => {}
            }
            continue;
        }
        let Some(socket) = resolve_once(&watchdog_socket, &ServiceRef::Bfd).await else {
            debug!(table = %table, "failed to resolve nos-bfdd via nos-watchdogd, retrying");
            if wait_retry(&mut shutdown).await {
                return;
            }
            continue;
        };
        let stream = match nos_pki::connect(&socket, Role::Bfdd, "").await {
            Ok(s) => s,
            Err(e) => {
                warn!(table = %table, error = %e, "failed to connect to nos-bfdd, retrying");
                if wait_retry(&mut shutdown).await {
                    return;
                }
                continue;
            }
        };
        let (r, w) = tokio::io::split(stream);
        let mut reader = FramedRead::new(r, IpcCodec::<BfdEvent>::default());
        let mut writer = FramedWrite::new(w, IpcCodec::<BfdRequest>::default());
        info!(table = %table, "connected to nos-bfdd");
        let mut pending = true;
        loop {
            if pending {
                pending = false;
                let target = target_rx.borrow_and_update().clone();
                let mut failed = false;
                for req in book.sync(&target) {
                    if writer.send(req).await.is_err() {
                        failed = true;
                        break;
                    }
                }
                publish(&up_tx, &book);
                if failed {
                    break;
                }
            }
            tokio::select! {
                r = target_rx.changed() => {
                    if r.is_err() { return }
                    pending = true;
                }
                ev = reader.next() => match ev {
                    Some(Ok(BfdEvent::State { key, state, diag, .. })) => {
                        if book.on_state(&key, state) {
                            info!(table = %table, gateway = %key.peer, state = %state, diag = %diag, "bfd gateway state changed");
                            publish(&up_tx, &book);
                        }
                    }
                    Some(Ok(BfdEvent::Sessions(_) | BfdEvent::Reflector(_))) => {}
                    Some(Err(_)) | None => break,
                },
                _ = shutdown.changed() => if *shutdown.borrow() { return },
            }
        }
        warn!(table = %table, "lost nos-bfdd, holding bfd static routes out");
        book.reset();
        publish(&up_tx, &book);
        if wait_retry(&mut shutdown).await {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn profile(tx: u32) -> Want {
        Want {
            profile: BfdProfile {
                min_tx_interval: tx,
                ..BfdProfile::default()
            },
            multihop: false,
        }
    }

    fn key(table: &str, peer: &str) -> SessionKey {
        SessionKey {
            aggregate: None,
            table: table.into(),
            peer: ip(peer),
            local: None,
            interface: None,
            multihop: false,
        }
    }

    #[test]
    fn a_multihop_gateway_registers_multihop_and_a_path_change_replaces_it() {
        let mut b = Book::new("rt1");
        let mut want = profile(100);
        want.multihop = true;
        let t = Target::from([(ip("10.9.9.9"), want)]);
        assert!(matches!(
            b.sync(&t).as_slice(),
            [BfdRequest::Register {
                multihop: true,
                local: None,
                ..
            }]
        ));
        let reqs = b.sync(&Target::from([(ip("10.9.9.9"), profile(100))]));
        assert!(matches!(
            reqs.as_slice(),
            [
                BfdRequest::Deregister {
                    key: SessionKey { multihop: true, .. }
                },
                BfdRequest::Register {
                    multihop: false,
                    ..
                },
            ]
        ));
    }

    #[test]
    fn registers_new_refreshes_changed_and_deregisters_gone() {
        let mut b = Book::new("rt1");
        let t1 = Target::from([(ip("192.0.2.1"), profile(100))]);
        assert!(matches!(
            b.sync(&t1).as_slice(),
            [BfdRequest::Register { peer, multihop: false, .. }] if *peer == ip("192.0.2.1")
        ));
        assert!(b.sync(&t1).is_empty(), "unchanged: nothing to send");

        let t2 = Target::from([(ip("192.0.2.1"), profile(50))]);
        assert!(matches!(
            b.sync(&t2).as_slice(),
            [BfdRequest::Register { profile, .. }] if profile.min_tx_interval == 50
        ));

        b.on_state(&key("rt1", "192.0.2.1"), BfdState::Up);
        assert!(b.up().contains(&ip("192.0.2.1")));
        let reqs = b.sync(&Target::new());
        assert_eq!(
            reqs,
            vec![BfdRequest::Deregister {
                key: key("rt1", "192.0.2.1")
            }]
        );
        assert!(b.up().is_empty(), "a withdrawn gateway is no longer up");
    }

    #[test]
    fn only_up_lets_a_route_in() {
        let mut b = Book::new("rt1");
        b.sync(&Target::from([(ip("192.0.2.1"), profile(100))]));
        let k = key("rt1", "192.0.2.1");
        assert!(!b.on_state(&k, BfdState::Down));
        assert!(!b.on_state(&k, BfdState::Init));
        assert!(b.on_state(&k, BfdState::Up));
        assert!(!b.on_state(&k, BfdState::Up), "no change");
        assert!(
            b.on_state(&k, BfdState::AdminDown),
            "AdminDown takes it out"
        );
        assert!(b.up().is_empty());
        // Not ours: another table, or never registered.
        assert!(!b.on_state(&key("rt2", "192.0.2.1"), BfdState::Up));
        assert!(!b.on_state(&key("rt1", "192.0.2.9"), BfdState::Up));
    }

    #[test]
    fn a_lost_connection_fails_closed_and_registers_again() {
        let mut b = Book::new("rt1");
        let t = Target::from([(ip("192.0.2.1"), profile(100))]);
        b.sync(&t);
        b.on_state(&key("rt1", "192.0.2.1"), BfdState::Up);
        assert!(b.reset(), "the up set changed");
        assert!(b.up().is_empty());
        assert!(!b.reset(), "nothing left to clear");
        assert_eq!(b.sync(&t).len(), 1, "everything is registered again");
    }
}
