//! Client-side BFD decisions shared by `nos-ospf` and `nos-ospfv3`
//! (RFC 5882 §4.1: OSPF is a BFD client, BFD the faster failure detector).

use crate::neighbor::{step, Event, NeighborState};

/// Whether a neighbor at `state` gets a BFD session: from 2-Way on, once the
/// neighbor's address is confirmed bidirectional (not at Down/Init).
#[must_use]
pub fn bfd_wanted(state: NeighborState) -> bool {
    !matches!(state, NeighborState::Down | NeighborState::Init)
}

/// The state after BFD declared the neighbor's path down: RFC 2328 §10.2
/// `KillNbr`, which drives the FSM exactly like `InactivityTimerExpired`.
#[must_use]
pub fn on_bfd_down(state: NeighborState) -> NeighborState {
    step(state, Event::InactivityTimerExpired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use NeighborState::*;

    #[test]
    fn wanted_from_two_way_onward() {
        let all = [Down, Init, TwoWay, ExStart, Exchange, Loading, Full];
        let wanted: Vec<bool> = all.iter().map(|s| bfd_wanted(*s)).collect();
        assert_eq!(wanted, [false, false, true, true, true, true, true]);
    }

    #[test]
    fn bfd_down_kills_from_every_state() {
        for s in [Down, Init, TwoWay, ExStart, Exchange, Loading, Full] {
            assert_eq!(on_bfd_down(s), Down, "{s:?}");
        }
    }
}
