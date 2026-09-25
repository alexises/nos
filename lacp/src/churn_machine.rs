//! IEEE 802.1AX-2014 §6.4.17 Actor/Partner Churn Detection — pure, no I/O.
//! One instance per side (actor, partner) per port: `Churn` means the side
//! has been out of sync for a whole `Churn_Detection_Time` without ever
//! settling. `aggregate.rs` keeps a churned port out of the active-member
//! set, so no traffic flows on it.

use std::time::Duration;

/// 802.1AX Table 6-3's `churn_detection_time`.
pub const CHURN_DETECTION_TIME: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChurnState {
    NoChurn,
    Monitor,
    Churn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The monitored side's Synchronization bit was (re)evaluated.
    Sync {
        in_sync: bool,
    },
    TimerExpired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    StartTimer,
    StopTimer,
    None,
}

pub fn step(state: ChurnState, event: Event) -> (ChurnState, Action) {
    match (state, event) {
        (_, Event::Sync { in_sync: true }) => (
            ChurnState::NoChurn,
            if state == ChurnState::Monitor {
                Action::StopTimer
            } else {
                Action::None
            },
        ),
        (ChurnState::NoChurn, Event::Sync { in_sync: false }) => {
            (ChurnState::Monitor, Action::StartTimer)
        }
        (ChurnState::Monitor, Event::TimerExpired) => (ChurnState::Churn, Action::None),
        (s, _) => (s, Action::None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUT: Event = Event::Sync { in_sync: false };
    const IN: Event = Event::Sync { in_sync: true };

    #[test]
    fn out_of_sync_starts_monitoring_once() {
        assert_eq!(
            step(ChurnState::NoChurn, OUT),
            (ChurnState::Monitor, Action::StartTimer)
        );
        // Still out of sync: the running timer must not restart.
        assert_eq!(
            step(ChurnState::Monitor, OUT),
            (ChurnState::Monitor, Action::None)
        );
    }

    #[test]
    fn timer_expiry_while_monitoring_is_churn() {
        assert_eq!(
            step(ChurnState::Monitor, Event::TimerExpired),
            (ChurnState::Churn, Action::None)
        );
        assert_eq!(
            step(ChurnState::Churn, OUT),
            (ChurnState::Churn, Action::None)
        );
    }

    #[test]
    fn sync_clears_from_any_state() {
        assert_eq!(
            step(ChurnState::Monitor, IN),
            (ChurnState::NoChurn, Action::StopTimer)
        );
        assert_eq!(
            step(ChurnState::Churn, IN),
            (ChurnState::NoChurn, Action::None)
        );
        assert_eq!(
            step(ChurnState::NoChurn, IN),
            (ChurnState::NoChurn, Action::None)
        );
    }

    #[test]
    fn stray_timer_expiry_is_ignored() {
        assert_eq!(
            step(ChurnState::NoChurn, Event::TimerExpired),
            (ChurnState::NoChurn, Action::None)
        );
    }
}
