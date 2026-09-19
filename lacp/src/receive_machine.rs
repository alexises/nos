//! IEEE 802.1AX-2014 §6.4.12/Figure 6-8 Receive Machine — pure, no I/O,
//! mirroring `ospf_common::neighbor`'s `step(state, event) -> state` shape.
//! Simplified for this crate's per-task-lifetime model (a `link.rs` task
//! exists only while its port is a configured, running aggregate member —
//! see `aggregate.rs` — so there is no separate "port administratively
//! disabled but task still alive" state to model): `Initialize`/
//! `PortDisabled`/`LacpDisabled` collapse into the task's own startup,
//! entered once via `Event::Started`, never revisited. `Churn Detection`
//! (802.1AX §6.4.17, diagnostic-only) is out of scope — see `lacp/
//! CLAUDE.md`.

/// Local, internal state — deliberately not `nos_proto::LacpReceiveState`
/// (this crate's own state isn't necessarily wire-serializable forever),
/// same convention as `ospf::link::InterfaceState` vs.
/// `nos_proto::LinkInterfaceState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveState {
    Expired,
    Defaulted,
    Current,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The link task has just started (or restarted after a socket error).
    Started,
    /// A valid LACPDU was received. `partner_wants_short_timeout` is the
    /// sender's own advertised `Actor_State.LACP_Timeout` bit — it governs
    /// how long *we* wait before assuming this partner has gone quiet
    /// (802.1AX's Short/Long `Current_While_Timer`).
    LacpduReceived {
        partner_wants_short_timeout: bool,
    },
    CurrentWhileTimerExpired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerDuration {
    /// 3s — `3 * fast_periodic_time`.
    Short,
    /// 90s — `3 * slow_periodic_time`.
    Long,
}

impl TimerDuration {
    pub fn as_duration(self) -> std::time::Duration {
        match self {
            TimerDuration::Short => std::time::Duration::from_secs(3),
            TimerDuration::Long => std::time::Duration::from_secs(90),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// (Re)start the `Current_While_Timer` for the given duration.
    StartCurrentWhileTimer(TimerDuration),
    /// Reset the recorded partner information to administrative defaults —
    /// 802.1AX's `Record_Default` — and stop treating this port as synced.
    RecordDefault,
    None,
}

pub fn step(state: ReceiveState, event: Event) -> (ReceiveState, Action) {
    match (state, event) {
        (_, Event::Started) | (ReceiveState::Current, Event::CurrentWhileTimerExpired) => (
            ReceiveState::Expired,
            Action::StartCurrentWhileTimer(TimerDuration::Short),
        ),
        (
            ReceiveState::Expired | ReceiveState::Current | ReceiveState::Defaulted,
            Event::LacpduReceived {
                partner_wants_short_timeout,
            },
        ) => {
            let duration = if partner_wants_short_timeout {
                TimerDuration::Short
            } else {
                TimerDuration::Long
            };
            (
                ReceiveState::Current,
                Action::StartCurrentWhileTimer(duration),
            )
        }
        (ReceiveState::Expired, Event::CurrentWhileTimerExpired) => {
            (ReceiveState::Defaulted, Action::RecordDefault)
        }
        (ReceiveState::Defaulted, Event::CurrentWhileTimerExpired) => {
            (ReceiveState::Defaulted, Action::None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn started_always_goes_to_expired_with_short_timer() {
        for state in [
            ReceiveState::Expired,
            ReceiveState::Current,
            ReceiveState::Defaulted,
        ] {
            assert_eq!(
                step(state, Event::Started),
                (
                    ReceiveState::Expired,
                    Action::StartCurrentWhileTimer(TimerDuration::Short)
                )
            );
        }
    }

    #[test]
    fn lacpdu_from_any_state_reaches_current() {
        for state in [
            ReceiveState::Expired,
            ReceiveState::Current,
            ReceiveState::Defaulted,
        ] {
            let (next, _) = step(
                state,
                Event::LacpduReceived {
                    partner_wants_short_timeout: true,
                },
            );
            assert_eq!(next, ReceiveState::Current);
        }
    }

    #[test]
    fn lacpdu_timeout_bit_selects_timer_duration() {
        let (_, action) = step(
            ReceiveState::Expired,
            Event::LacpduReceived {
                partner_wants_short_timeout: true,
            },
        );
        assert_eq!(action, Action::StartCurrentWhileTimer(TimerDuration::Short));

        let (_, action) = step(
            ReceiveState::Expired,
            Event::LacpduReceived {
                partner_wants_short_timeout: false,
            },
        );
        assert_eq!(action, Action::StartCurrentWhileTimer(TimerDuration::Long));
    }

    #[test]
    fn current_times_out_to_expired() {
        assert_eq!(
            step(ReceiveState::Current, Event::CurrentWhileTimerExpired),
            (
                ReceiveState::Expired,
                Action::StartCurrentWhileTimer(TimerDuration::Short)
            )
        );
    }

    #[test]
    fn expired_times_out_to_defaulted() {
        assert_eq!(
            step(ReceiveState::Expired, Event::CurrentWhileTimerExpired),
            (ReceiveState::Defaulted, Action::RecordDefault)
        );
    }

    #[test]
    fn defaulted_timer_expiry_is_a_no_op() {
        assert_eq!(
            step(ReceiveState::Defaulted, Event::CurrentWhileTimerExpired),
            (ReceiveState::Defaulted, Action::None)
        );
    }
}
