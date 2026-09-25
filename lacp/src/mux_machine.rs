//! IEEE 802.1AX-2014 §6.4.15/Figure 6-11 Mux Machine — pure, no I/O.
//! `Distributing` is the only state in which this port belongs in the
//! aggregate's active-member set pushed to `nos-interfaced` (see
//! `aggregate.rs`).

use std::time::Duration;

/// 802.1AX Table 6-3's `aggregate_wait_time` — how long `Waiting` holds
/// before declaring itself synchronized, giving a just-selected port a
/// moment to settle before this side tells its partner it's ready.
pub const AGGREGATE_WAIT_TIME: Duration = Duration::from_secs(2);

/// Local, internal state — see `receive_machine::ReceiveState`'s doc
/// comment for why this isn't `nos_proto::LacpMuxState` directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxState {
    Detached,
    Waiting,
    Attached,
    Collecting,
    Distributing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Selection Logic's outcome for this port changed (re-run after any
    /// port's `ReceiveState`/partner info changes — see `selection.rs`).
    SelectionChanged {
        selected: bool,
    },
    WaitWhileTimerExpired,
    /// The partner's most recently recorded state changed — fed by
    /// `receive_machine`'s own transitions too: losing `Current` (going to
    /// `Expired`/`Defaulted`) reports `synchronized: false, collecting:
    /// false`, exactly like a real LACPDU that cleared those bits would.
    PartnerStateChanged {
        synchronized: bool,
        collecting: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    StartWaitWhileTimer,
    /// Sets this port's own advertised `Actor_State.Synchronization` bit —
    /// `true` on entering `Attached` (telling the partner "ready"), `false`
    /// on falling back to `Detached`.
    SetActorSynchronized(bool),
    EnableCollecting,
    DisableCollecting,
    EnableDistributing,
    /// `Distributing` requires `Collecting` (802.1AX never distributes
    /// without also collecting), so losing sync from `Distributing` drops
    /// both in one step.
    DisableCollectingAndDistributing,
    None,
}

pub fn step(state: MuxState, event: Event) -> (MuxState, Action) {
    // A just-deselected port always falls back to `Detached` and clears its
    // own advertised sync bit, regardless of which active state it was in —
    // checked first so the per-state arms below never need to repeat it.
    if let Event::SelectionChanged { selected: false } = event {
        if state != MuxState::Detached {
            return (MuxState::Detached, Action::SetActorSynchronized(false));
        }
    }

    match (state, event) {
        (MuxState::Detached, Event::SelectionChanged { selected: true }) => {
            (MuxState::Waiting, Action::StartWaitWhileTimer)
        }
        (MuxState::Detached, _) => (MuxState::Detached, Action::None),

        (MuxState::Waiting, Event::WaitWhileTimerExpired) => {
            (MuxState::Attached, Action::SetActorSynchronized(true))
        }
        (MuxState::Waiting, _) => (MuxState::Waiting, Action::None),

        (
            MuxState::Attached,
            Event::PartnerStateChanged {
                synchronized: true, ..
            },
        ) => (MuxState::Collecting, Action::EnableCollecting),
        (MuxState::Attached, _) => (MuxState::Attached, Action::None),

        (
            MuxState::Collecting,
            Event::PartnerStateChanged {
                synchronized: false,
                ..
            },
        ) => (MuxState::Attached, Action::DisableCollecting),
        (
            MuxState::Collecting,
            Event::PartnerStateChanged {
                synchronized: true,
                collecting: true,
            },
        ) => (MuxState::Distributing, Action::EnableDistributing),
        (MuxState::Collecting, _) => (MuxState::Collecting, Action::None),

        (
            MuxState::Distributing,
            Event::PartnerStateChanged {
                synchronized: false,
                ..
            },
        ) => (MuxState::Attached, Action::DisableCollectingAndDistributing),
        (
            MuxState::Distributing,
            Event::PartnerStateChanged {
                synchronized: true,
                collecting: false,
            },
        ) => (
            MuxState::Collecting,
            Action::DisableCollectingAndDistributing,
        ),
        (MuxState::Distributing, _) => (MuxState::Distributing, Action::None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_walks_detached_to_waiting_to_attached() {
        let (s, a) = step(
            MuxState::Detached,
            Event::SelectionChanged { selected: true },
        );
        assert_eq!(s, MuxState::Waiting);
        assert_eq!(a, Action::StartWaitWhileTimer);

        let (s, a) = step(MuxState::Waiting, Event::WaitWhileTimerExpired);
        assert_eq!(s, MuxState::Attached);
        assert_eq!(a, Action::SetActorSynchronized(true));
    }

    #[test]
    fn partner_sync_walks_attached_to_collecting_to_distributing() {
        let (s, a) = step(
            MuxState::Attached,
            Event::PartnerStateChanged {
                synchronized: true,
                collecting: false,
            },
        );
        assert_eq!(s, MuxState::Collecting);
        assert_eq!(a, Action::EnableCollecting);

        let (s, a) = step(
            MuxState::Collecting,
            Event::PartnerStateChanged {
                synchronized: true,
                collecting: true,
            },
        );
        assert_eq!(s, MuxState::Distributing);
        assert_eq!(a, Action::EnableDistributing);
    }

    #[test]
    fn losing_partner_sync_from_distributing_drops_to_attached() {
        let (s, a) = step(
            MuxState::Distributing,
            Event::PartnerStateChanged {
                synchronized: false,
                collecting: false,
            },
        );
        assert_eq!(s, MuxState::Attached);
        assert_eq!(a, Action::DisableCollectingAndDistributing);
    }

    #[test]
    fn deselection_from_any_active_state_falls_back_to_detached() {
        for state in [
            MuxState::Waiting,
            MuxState::Attached,
            MuxState::Collecting,
            MuxState::Distributing,
        ] {
            let (s, a) = step(state, Event::SelectionChanged { selected: false });
            assert_eq!(s, MuxState::Detached);
            assert_eq!(a, Action::SetActorSynchronized(false));
        }
    }

    #[test]
    fn partner_collecting_without_sync_does_not_advance_from_collecting() {
        let (s, a) = step(
            MuxState::Collecting,
            Event::PartnerStateChanged {
                synchronized: true,
                collecting: false,
            },
        );
        assert_eq!(s, MuxState::Collecting);
        assert_eq!(a, Action::None);
    }
}
