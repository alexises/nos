//! RFC 5880 §6.2/§6.8.6 session state machine, pure.

use nos_proto::{BfdDiag, BfdState};

/// What happened to a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A valid packet arrived carrying this remote state (`Sta`).
    RxState(BfdState),
    /// The detection time elapsed without a packet.
    DetectTimeout,
    /// Administratively disabled (profile `shutdown`).
    AdminDown,
    /// Administratively enabled again.
    AdminUp,
}

/// The next state and, when the transition sets one, the new local
/// diagnostic (`None`: keep the current `bfd.LocalDiag`).
pub fn step(state: BfdState, ev: Event) -> (BfdState, Option<BfdDiag>) {
    use BfdState::{AdminDown, Down, Init, Up};
    use Event::{AdminDown as Disable, AdminUp, DetectTimeout, RxState};
    match (state, ev) {
        (AdminDown, AdminUp) => (Down, Some(BfdDiag::NoDiagnostic)),
        // §6.8.6: a session in AdminDown discards everything.
        (AdminDown, _) => (AdminDown, None),
        (_, Disable) => (AdminDown, Some(BfdDiag::AdministrativelyDown)),
        (_, AdminUp) => (state, None),

        (Init | Up, DetectTimeout) => (Down, Some(BfdDiag::ControlDetectionTimeExpired)),
        (Init, RxState(AdminDown)) | (Up, RxState(AdminDown | Down)) => {
            (Down, Some(BfdDiag::NeighborSignaledSessionDown))
        }
        (Down | Init, RxState(Down)) => (Init, None),
        (Down | Init | Up, RxState(Init)) | (Init | Up, RxState(Up)) => (Up, None),
        (Down, _) => (Down, None),
    }
}

/// §6.8.7: whether the periodic transmission may run. A passive session
/// (§6.1) stays silent until it has learned the remote discriminator, and a
/// remote Required Min RX of zero asks us not to send at all.
pub fn may_transmit(passive: bool, remote_discriminator: u32, remote_required_min_rx: u32) -> bool {
    remote_required_min_rx != 0 && !(passive && remote_discriminator == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use BfdState::{AdminDown, Down, Init, Up};
    use Event::{AdminDown as Disable, AdminUp, DetectTimeout, RxState};

    const NSD: Option<BfdDiag> = Some(BfdDiag::NeighborSignaledSessionDown);
    const EXP: Option<BfdDiag> = Some(BfdDiag::ControlDetectionTimeExpired);

    /// The whole table: 4 states x 7 events.
    #[test]
    fn full_transition_table() {
        let rx = RxState;
        #[rustfmt::skip]
        let table = [
            (AdminDown, rx(AdminDown), AdminDown, None),
            (AdminDown, rx(Down),      AdminDown, None),
            (AdminDown, rx(Init),      AdminDown, None),
            (AdminDown, rx(Up),        AdminDown, None),
            (AdminDown, DetectTimeout, AdminDown, None),
            (AdminDown, Disable,       AdminDown, None),
            (AdminDown, AdminUp,       Down,      Some(BfdDiag::NoDiagnostic)),

            (Down, rx(AdminDown), Down, None),
            (Down, rx(Down),      Init, None),
            (Down, rx(Init),      Up,   None),
            (Down, rx(Up),        Down, None),
            (Down, DetectTimeout, Down, None),
            (Down, Disable,       AdminDown, Some(BfdDiag::AdministrativelyDown)),
            (Down, AdminUp,       Down, None),

            (Init, rx(AdminDown), Down, NSD),
            (Init, rx(Down),      Init, None),
            (Init, rx(Init),      Up,   None),
            (Init, rx(Up),        Up,   None),
            (Init, DetectTimeout, Down, EXP),
            (Init, Disable,       AdminDown, Some(BfdDiag::AdministrativelyDown)),
            (Init, AdminUp,       Init, None),

            (Up, rx(AdminDown), Down, NSD),
            (Up, rx(Down),      Down, NSD),
            (Up, rx(Init),      Up,   None),
            (Up, rx(Up),        Up,   None),
            (Up, DetectTimeout, Down, EXP),
            (Up, Disable,       AdminDown, Some(BfdDiag::AdministrativelyDown)),
            (Up, AdminUp,       Up,   None),
        ];
        for (from, ev, to, diag) in table {
            assert_eq!(step(from, ev), (to, diag), "{from} + {ev:?}");
        }
    }

    #[test]
    fn three_way_handshake() {
        let (a, _) = step(Down, RxState(Down));
        let (a, _) = step(a, RxState(Up));
        assert_eq!(a, Up);
        let (b, _) = step(Down, RxState(Init));
        assert_eq!(b, Up);
    }

    #[test]
    fn passive_waits_for_the_peer() {
        assert!(!may_transmit(true, 0, 300_000));
        assert!(may_transmit(true, 7, 300_000));
        assert!(may_transmit(false, 0, 300_000));
    }

    #[test]
    fn remote_min_rx_zero_silences_us() {
        assert!(!may_transmit(false, 7, 0));
    }
}
