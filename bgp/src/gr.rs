//! RFC 4724 graceful restart with RFC 8538's notification (N) bit: the pure
//! decisions — what a peer's capability says, whether a session that just
//! ended keeps its routes, and which Cease goes out as a Hard Reset. The
//! state lives in `rib.rs` (`BgpRib.gr`, the stale sets and deadlines) and
//! the wire format in `message.rs`.

use nos_proto::AddressFamily;

use crate::message::{CeaseSubcode, GrFamily, GracefulRestartCap};

/// The three families this crate knows, as one bit each (`AddressFamily::ALL`
/// order) — keeps `PeerGr` `Copy`, like `fsm::RemoteInfo`.
fn bit(family: AddressFamily) -> u8 {
    match family {
        AddressFamily::Ipv4Unicast => 1,
        AddressFamily::Ipv6Unicast => 2,
        AddressFamily::L2vpnEvpn => 4,
    }
}

/// The `(afi, safi)` of a family this crate knows.
pub fn afi_safi(family: AddressFamily) -> (u16, u8) {
    match family {
        AddressFamily::Ipv4Unicast => (1, 1),
        AddressFamily::Ipv6Unicast => (2, 1),
        AddressFamily::L2vpnEvpn => (crate::message::AFI_L2VPN, crate::message::SAFI_EVPN),
    }
}

/// The family an `(afi, safi)` names, if this crate knows it.
pub fn family_of(afi: u16, safi: u8) -> Option<AddressFamily> {
    AddressFamily::ALL
        .into_iter()
        .find(|f| afi_safi(*f) == (afi, safi))
}

/// A peer's graceful restart capability, as received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerGr {
    pub restart: bool,
    pub notification: bool,
    pub time: u16,
    /// Families listed in the capability (a family this crate doesn't know
    /// is dropped), and the ones among them whose F bit is set.
    families: u8,
    forwarding: u8,
}

impl PeerGr {
    pub fn from_cap(cap: &GracefulRestartCap) -> Self {
        let mut gr = PeerGr {
            restart: cap.restart,
            notification: cap.notification,
            time: cap.time,
            families: 0,
            forwarding: 0,
        };
        for f in &cap.families {
            if let Some(family) = family_of(f.afi, f.safi) {
                gr.families |= bit(family);
                if f.forwarding {
                    gr.forwarding |= bit(family);
                }
            }
        }
        gr
    }

    pub fn has(&self, family: AddressFamily) -> bool {
        self.families & bit(family) != 0
    }

    /// F bit: the peer kept its forwarding state for `family`.
    pub fn forwarding(&self, family: AddressFamily) -> bool {
        self.forwarding & bit(family) != 0
    }

    /// The listed families, in `AddressFamily::ALL` order.
    pub fn families(&self) -> Vec<AddressFamily> {
        AddressFamily::ALL
            .into_iter()
            .filter(|f| self.has(*f))
            .collect()
    }
}

/// Our own capability: N always set (RFC 8538, no knob), one tuple per
/// configured family, each with F = `forwarding`.
pub fn our_cap(
    time: u16,
    families: &[AddressFamily],
    restart: bool,
    forwarding: bool,
) -> GracefulRestartCap {
    GracefulRestartCap {
        restart,
        notification: true,
        time,
        families: families
            .iter()
            .map(|f| {
                let (afi, safi) = afi_safi(*f);
                GrFamily {
                    afi,
                    safi,
                    forwarding,
                }
            })
            .collect(),
    }
}

/// How a session ended, as far as graceful restart is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disconnect {
    /// The TCP connection went away (EOF, error), or a new connection
    /// replaced it (RFC 4724 §4.2).
    Transport,
    /// A NOTIFICATION other than a Hard Reset, sent or received while N was
    /// exchanged — hold-timer expiry included (RFC 8538 §4).
    Graceful,
    /// Anything else: a Hard Reset, any NOTIFICATION without N, or a peer
    /// being deconfigured/shut.
    Hard,
}

/// Whether a NOTIFICATION `(code, subcode)` ending a session keeps the
/// peer's routes: with N, everything but a Hard Reset (Cease/9).
pub fn notification_disconnect(code: u8, subcode: u8, n_exchanged: bool) -> Disconnect {
    if n_exchanged && !(code == 6 && subcode == CeaseSubcode::HardReset as u8) {
        Disconnect::Graceful
    } else {
        Disconnect::Hard
    }
}

/// Whether a session ending with `kind` keeps the routes of a peer whose
/// last capability is `peer` (RFC 4724 §4.2, RFC 8538 §4): never on a Hard
/// end, never for a peer with no capability or one listing no family, and on
/// a NOTIFICATION only once N was exchanged.
pub fn retains(kind: Disconnect, peer: Option<&PeerGr>) -> bool {
    let Some(gr) = peer else {
        return false;
    };
    match kind {
        Disconnect::Hard => false,
        Disconnect::Graceful => gr.notification && gr.families != 0,
        Disconnect::Transport => gr.families != 0,
    }
}

/// RFC 8538 §5.1: with N exchanged, these Cease subcodes go out as a Hard
/// Reset wrapping the original; the rest (Other Configuration Change, …)
/// stay graceful. Without N, never (§4).
pub fn sends_hard_reset(subcode: CeaseSubcode, n_exchanged: bool) -> bool {
    n_exchanged
        && matches!(
            subcode,
            CeaseSubcode::MaximumPrefixesReached
                | CeaseSubcode::AdministrativeShutdown
                | CeaseSubcode::PeerDeconfigured
                | CeaseSubcode::AdministrativeReset
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(notification: bool, families: &[(AddressFamily, bool)]) -> PeerGr {
        PeerGr::from_cap(&GracefulRestartCap {
            restart: false,
            notification,
            time: 120,
            families: families
                .iter()
                .map(|(f, forwarding)| {
                    let (afi, safi) = afi_safi(*f);
                    GrFamily {
                        afi,
                        safi,
                        forwarding: *forwarding,
                    }
                })
                .collect(),
        })
    }

    #[test]
    fn capability_families_and_f_bits() {
        let gr = cap(
            true,
            &[
                (AddressFamily::Ipv4Unicast, true),
                (AddressFamily::L2vpnEvpn, false),
            ],
        );
        assert!(gr.has(AddressFamily::Ipv4Unicast) && gr.forwarding(AddressFamily::Ipv4Unicast));
        assert!(gr.has(AddressFamily::L2vpnEvpn) && !gr.forwarding(AddressFamily::L2vpnEvpn));
        assert!(!gr.has(AddressFamily::Ipv6Unicast));
        assert_eq!(
            gr.families(),
            [AddressFamily::Ipv4Unicast, AddressFamily::L2vpnEvpn]
        );
    }

    /// The retention table over end × N × tuples.
    #[test]
    fn retention_decision_table() {
        let v4 = [(AddressFamily::Ipv4Unicast, true)];
        let with_n = cap(true, &v4);
        let without_n = cap(false, &v4);
        let no_tuples = cap(true, &[]);
        for (kind, gr, want) in [
            (Disconnect::Transport, Some(&with_n), true),
            (Disconnect::Transport, Some(&without_n), true),
            (Disconnect::Transport, Some(&no_tuples), false),
            (Disconnect::Transport, None, false),
            (Disconnect::Graceful, Some(&with_n), true),
            (Disconnect::Graceful, Some(&without_n), false),
            (Disconnect::Hard, Some(&with_n), false),
        ] {
            assert_eq!(retains(kind, gr), want, "{kind:?} {gr:?}");
        }
        assert_eq!(notification_disconnect(6, 6, true), Disconnect::Graceful);
        assert_eq!(notification_disconnect(4, 0, true), Disconnect::Graceful);
        assert_eq!(notification_disconnect(6, 9, true), Disconnect::Hard);
        assert_eq!(notification_disconnect(6, 6, false), Disconnect::Hard);
    }

    #[test]
    fn hard_reset_per_cease_subcode() {
        use CeaseSubcode::*;
        for s in [
            MaximumPrefixesReached,
            AdministrativeShutdown,
            PeerDeconfigured,
            AdministrativeReset,
        ] {
            assert!(sends_hard_reset(s, true), "{s:?}");
            assert!(!sends_hard_reset(s, false), "{s:?}");
        }
        assert!(!sends_hard_reset(OtherConfigurationChange, true));
        assert!(!sends_hard_reset(ConnectionCollisionResolution, true));
    }
}
