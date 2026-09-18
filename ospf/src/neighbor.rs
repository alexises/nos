//! RFC 2328 §10.5 neighbor event processing, restricted to the Hello-only
//! subset this phase models: `Down`/`Init`/`TwoWay` only — no `DBD`/`LSR`/
//! `LSU`/`LSAck`, no `ExStart` onward (see `ospf/CLAUDE.md`).

/// A point-to-point link's neighbor state. Deliberately a plain enum (not
/// `Option<NeighborState>` like `bgp::fsm::step`'s `Option<State>`) — `Down`
/// is an ongoing, valid state here, not a signal to tear down the driver
/// task (a point-to-point link keeps sending Hellos while `Down`, hoping to
/// hear one back).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborState {
    Down,
    Init,
    TwoWay,
}

#[derive(Debug, Clone, Copy)]
pub enum Event {
    /// A valid Hello was received from the neighbor (matching area,
    /// well-formed). `saw_self` is whether the Hello's own neighbor list
    /// included this router's router-id.
    HelloReceived {
        saw_self: bool,
    },
    InactivityTimerExpired,
}

/// Pure state transition — no I/O, no timers. `link.rs` drives real Hello
/// send/receive and the dead-interval timer around this.
pub fn step(state: NeighborState, event: Event) -> NeighborState {
    let Event::HelloReceived { saw_self } = event else {
        return NeighborState::Down;
    };
    match state {
        NeighborState::Down => NeighborState::Init,
        _ if saw_self => NeighborState::TwoWay,
        // RFC 2328's "1-WayReceived": the neighbor stopped listing us, so we
        // drop back to Init rather than staying TwoWay.
        _ => NeighborState::Init,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn down_to_init_on_first_hello() {
        assert_eq!(
            step(
                NeighborState::Down,
                Event::HelloReceived { saw_self: false }
            ),
            NeighborState::Init
        );
    }

    #[test]
    fn init_to_two_way_when_self_seen() {
        assert_eq!(
            step(NeighborState::Init, Event::HelloReceived { saw_self: true }),
            NeighborState::TwoWay
        );
    }

    #[test]
    fn init_stays_init_when_self_not_seen() {
        assert_eq!(
            step(
                NeighborState::Init,
                Event::HelloReceived { saw_self: false }
            ),
            NeighborState::Init
        );
    }

    #[test]
    fn two_way_stays_two_way_when_self_seen() {
        assert_eq!(
            step(
                NeighborState::TwoWay,
                Event::HelloReceived { saw_self: true }
            ),
            NeighborState::TwoWay
        );
    }

    #[test]
    fn two_way_drops_to_init_when_self_no_longer_seen() {
        assert_eq!(
            step(
                NeighborState::TwoWay,
                Event::HelloReceived { saw_self: false }
            ),
            NeighborState::Init
        );
    }

    #[test]
    fn inactivity_timer_forces_down_from_any_state() {
        for state in [
            NeighborState::Down,
            NeighborState::Init,
            NeighborState::TwoWay,
        ] {
            assert_eq!(
                step(state, Event::InactivityTimerExpired),
                NeighborState::Down
            );
        }
    }
}
