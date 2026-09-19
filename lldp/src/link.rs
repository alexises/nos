//! One LLDP-enabled interface's transmit/receive task — the LLDP counterpart
//! of `nos-lacp`'s `link.rs` `run()` shape.
//!
//! Timers are the fixed 802.1AB defaults (no CLI knobs, like `nos-lacp`'s
//! priorities): `msgTxInterval` 30s and `msgTxHold` 4, so a neighbor is
//! advertised with a TTL of 120s.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio::time::{interval, sleep_until, MissedTickBehavior};
use tracing::{debug, info, trace, warn};

use crate::neighbor::{NeighborTable, Update};
use crate::packet::{
    self, Capabilities, Id, Lldpdu, CAP_ROUTER, CHASSIS_SUBTYPE_MAC, PORT_SUBTYPE_IF_NAME,
};
use crate::socket::{self, LldpSocket};

/// 802.1AB `msgTxInterval` default.
pub const TX_INTERVAL: Duration = Duration::from_secs(30);
/// `msgTxHold` (4) × `msgTxInterval`.
pub const TTL_SECS: u16 = 120;
/// How soon to retry a periodic transmit that found the link down.
const LINK_DOWN_RETRY: Duration = Duration::from_secs(1);

/// Everything a link task needs; also what `reconcile` compares to decide
/// whether a running link must be restarted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkConfig {
    pub interface: String,
    pub transmit: bool,
    pub receive: bool,
    /// Advertised as the System Name TLV (the configured hostname).
    pub system_name: String,
    /// This machine's chassis identity — see `reconcile::local_system_id`.
    pub chassis_mac: [u8; 6],
}

/// Every receiving interface's neighbor table, keyed by interface name. Shared
/// with `server.rs` so `show lldp neighbors` reads live state. A std mutex,
/// never held across an `.await`.
pub type SharedNeighbors = Arc<Mutex<HashMap<String, NeighborTable>>>;

fn chassis_id(cfg: &LinkConfig) -> Id {
    Id {
        subtype: CHASSIS_SUBTYPE_MAC,
        value: cfg.chassis_mac.to_vec(),
    }
}

/// The LLDPDU this link advertises.
pub fn local_pdu(cfg: &LinkConfig) -> Lldpdu {
    Lldpdu {
        chassis_id: chassis_id(cfg),
        port_id: Id {
            subtype: PORT_SUBTYPE_IF_NAME,
            value: cfg.interface.as_bytes().to_vec(),
        },
        ttl: TTL_SECS,
        port_description: Some(cfg.interface.clone()),
        system_name: Some(cfg.system_name.clone()),
        system_description: Some(format!("nos {}", env!("CARGO_PKG_VERSION"))),
        // ponytail: Router only; a Bridge bit for switching-profile ports is
        // the upgrade path.
        capabilities: Some(Capabilities {
            supported: CAP_ROUTER,
            enabled: CAP_ROUTER,
        }),
    }
}

/// A shutdown LLDPDU (802.1AB): identity only, TTL 0, telling
/// neighbors to forget us immediately instead of waiting out the TTL.
fn shutdown_pdu(cfg: &LinkConfig) -> Lldpdu {
    Lldpdu {
        ttl: 0,
        port_description: None,
        system_name: None,
        system_description: None,
        capabilities: None,
        ..local_pdu(cfg)
    }
}

/// Sends `pdu`, returning `false` only if the link was down. A link that comes
/// up just after its task starts (`nos-interfaced` admin-ups it on its own
/// schedule) would otherwise cost a whole `TX_INTERVAL` before the first
/// advertisement — the caller retries after `LINK_DOWN_RETRY` instead.
fn send(socket: &LldpSocket, interface: &str, pdu: &Lldpdu) -> bool {
    match socket.send(&packet::encode(pdu)) {
        Ok(()) => {
            trace!(interface = %interface, ttl = pdu.ttl, "lldpdu sent");
            true
        }
        Err(e) if socket::is_link_down(&e) => {
            debug!(interface = %interface, error = %e, "link down, lldpdu not sent");
            false
        }
        Err(e) => {
            warn!(interface = %interface, error = %e, "failed to send lldpdu");
            true
        }
    }
}

/// Decodes and records one received LLDPDU. Returns `true` iff it introduced a
/// *new* neighbor — the caller answers that with an immediate transmit (a
/// simplified 802.1AB fast-start) so a peer that came up after us learns us
/// without waiting out our 30s timer. Only new neighbors trigger it, so two
/// systems settle after one exchange rather than ping-ponging.
fn handle_rx(cfg: &LinkConfig, neighbors: &SharedNeighbors, payload: &[u8], now: Instant) -> bool {
    let pdu = match packet::decode(payload) {
        Ok(pdu) => pdu,
        Err(e) => {
            debug!(interface = %cfg.interface, error = %e, "dropping malformed lldpdu");
            return false;
        }
    };
    // Our own frame reflected back (looped cable, port mirror).
    if pdu.chassis_id == chassis_id(cfg) {
        return false;
    }
    let chassis = pdu.chassis_display();
    let port = pdu.port_display();
    let system_name = pdu.system_name.clone().unwrap_or_default();
    let update = neighbors
        .lock()
        .unwrap()
        .entry(cfg.interface.clone())
        .or_default()
        .apply(pdu, now);
    match update {
        Update::New => {
            info!(
                interface = %cfg.interface, chassis_id = %chassis, port_id = %port,
                system_name = %system_name, "lldp neighbor learned"
            );
            true
        }
        Update::Removed => {
            info!(
                interface = %cfg.interface, chassis_id = %chassis, port_id = %port,
                reason = "shutdown", "lldp neighbor removed"
            );
            false
        }
        Update::Refreshed | Update::Ignored => false,
    }
}

fn expire(cfg: &LinkConfig, neighbors: &SharedNeighbors, now: Instant) {
    let gone = neighbors
        .lock()
        .unwrap()
        .get_mut(&cfg.interface)
        .map(|t| t.expire(now))
        .unwrap_or_default();
    for pdu in gone {
        info!(
            interface = %cfg.interface, chassis_id = %pdu.chassis_display(),
            port_id = %pdu.port_display(), reason = "expired", "lldp neighbor removed"
        );
    }
}

fn next_expiry(cfg: &LinkConfig, neighbors: &SharedNeighbors) -> Option<Instant> {
    neighbors
        .lock()
        .unwrap()
        .get(&cfg.interface)
        .and_then(NeighborTable::next_expiry)
}

/// Runs one interface's LLDP until `stop` fires (or its sender is dropped).
/// Returns `Err` only when the socket can't be opened or a read fails hard —
/// `reconcile` respawns a link that ended on its own.
pub async fn run(
    cfg: LinkConfig,
    neighbors: SharedNeighbors,
    mut stop: watch::Receiver<bool>,
) -> io::Result<()> {
    let socket = LldpSocket::open(&cfg.interface)?;
    if cfg.receive {
        neighbors
            .lock()
            .unwrap()
            .insert(cfg.interface.clone(), NeighborTable::default());
    }
    info!(
        interface = %cfg.interface, transmit = cfg.transmit, receive = cfg.receive,
        "lldp link started"
    );

    // The first tick fires immediately, which is the initial transmit.
    let mut tx = interval(TX_INTERVAL);
    tx.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let result = loop {
        // Never leave an elapsed deadline armed: `expire` moves it forward by
        // removing the entry it belonged to, and with no entries the branch is
        // disabled by its guard.
        let deadline = next_expiry(&cfg, &neighbors);
        tokio::select! {
            _ = stop.changed() => break Ok(()),
            _ = tx.tick(), if cfg.transmit => {
                if !send(&socket, &cfg.interface, &local_pdu(&cfg)) {
                    tx.reset_after(LINK_DOWN_RETRY);
                }
            }
            frame = socket.recv(), if cfg.receive => match frame {
                Ok(payload) => {
                    if handle_rx(&cfg, &neighbors, &payload, Instant::now()) && cfg.transmit {
                        send(&socket, &cfg.interface, &local_pdu(&cfg));
                        tx.reset();
                    }
                }
                Err(e) => break Err(e),
            },
            () = sleep_until(tokio::time::Instant::from_std(deadline.unwrap_or_else(Instant::now))),
                if deadline.is_some() =>
            {
                expire(&cfg, &neighbors, Instant::now());
            }
        }
    };

    if cfg.transmit {
        send(&socket, &cfg.interface, &shutdown_pdu(&cfg));
    }
    neighbors.lock().unwrap().remove(&cfg.interface);
    info!(interface = %cfg.interface, "lldp link stopped");
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(mac_last: u8) -> LinkConfig {
        LinkConfig {
            interface: "eth1".to_string(),
            transmit: true,
            receive: true,
            system_name: format!("router-{mac_last}"),
            chassis_mac: [2, 0, 0, 0, 0, mac_last],
        }
    }

    fn shared() -> SharedNeighbors {
        Arc::new(Mutex::new(HashMap::new()))
    }

    fn frame_from(peer: &LinkConfig, ttl: u16) -> Vec<u8> {
        let mut pdu = local_pdu(peer);
        pdu.ttl = ttl;
        packet::encode(&pdu)
    }

    #[test]
    fn local_pdu_round_trips_and_carries_our_identity() {
        let c = cfg(1);
        let pdu = packet::decode(&packet::encode(&local_pdu(&c))).unwrap();
        assert_eq!(pdu.chassis_display(), "02:00:00:00:00:01");
        assert_eq!(pdu.port_display(), "eth1");
        assert_eq!(pdu.system_name.as_deref(), Some("router-1"));
        assert_eq!(pdu.ttl, TTL_SECS);
    }

    #[test]
    fn shutdown_pdu_has_ttl_zero_and_only_mandatory_tlvs() {
        let pdu = packet::decode(&packet::encode(&shutdown_pdu(&cfg(1)))).unwrap();
        assert_eq!(pdu.ttl, 0);
        assert_eq!(pdu.system_name, None);
        assert_eq!(pdu.chassis_display(), "02:00:00:00:00:01");
    }

    #[test]
    fn only_a_new_neighbor_asks_for_an_immediate_reply() {
        let (me, peer) = (cfg(1), cfg(2));
        let n = shared();
        n.lock()
            .unwrap()
            .insert("eth1".to_string(), NeighborTable::default());
        let now = Instant::now();
        assert!(handle_rx(&me, &n, &frame_from(&peer, 120), now));
        // The same neighbor again is a refresh: no reply, so no ping-pong.
        assert!(!handle_rx(&me, &n, &frame_from(&peer, 120), now));
        assert_eq!(n.lock().unwrap()["eth1"].snapshot("eth1", now).len(), 1);
    }

    #[test]
    fn shutdown_frame_removes_the_neighbor_immediately() {
        let (me, peer) = (cfg(1), cfg(2));
        let n = shared();
        n.lock()
            .unwrap()
            .insert("eth1".to_string(), NeighborTable::default());
        let now = Instant::now();
        handle_rx(&me, &n, &frame_from(&peer, 120), now);
        assert!(!handle_rx(&me, &n, &frame_from(&peer, 0), now));
        assert!(n.lock().unwrap()["eth1"].snapshot("eth1", now).is_empty());
    }

    #[test]
    fn own_reflected_frame_and_garbage_are_ignored() {
        let me = cfg(1);
        let n = shared();
        n.lock()
            .unwrap()
            .insert("eth1".to_string(), NeighborTable::default());
        let now = Instant::now();
        assert!(!handle_rx(&me, &n, &frame_from(&me, 120), now));
        assert!(!handle_rx(&me, &n, &[0xff, 0xff, 0x01], now));
        assert!(n.lock().unwrap()["eth1"].snapshot("eth1", now).is_empty());
    }

    #[test]
    fn expire_drops_lapsed_neighbors_only() {
        let (me, peer) = (cfg(1), cfg(2));
        let n = shared();
        n.lock()
            .unwrap()
            .insert("eth1".to_string(), NeighborTable::default());
        let now = Instant::now();
        handle_rx(&me, &n, &frame_from(&peer, 10), now);
        expire(&me, &n, now + Duration::from_secs(5));
        assert_eq!(n.lock().unwrap()["eth1"].snapshot("eth1", now).len(), 1);
        expire(&me, &n, now + Duration::from_secs(10));
        assert!(n.lock().unwrap()["eth1"].snapshot("eth1", now).is_empty());
        assert_eq!(next_expiry(&me, &n), None);
    }
}
