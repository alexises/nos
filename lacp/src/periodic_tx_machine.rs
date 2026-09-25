//! IEEE 802.1AX-2014 §6.4.13 Periodic Transmission Machine — how often this
//! port sends an LACPDU.
//!
//! Each end transmits at the rate the *other* end asks for (its advertised
//! `Actor_State.LACP_Timeout`, i.e. its `LacpRate`): Fast (1s) if the partner
//! asked for Fast, Slow (30s) otherwise. A port with no live partner
//! (`Expired`/`Defaulted`) transmits Fast regardless, as 802.1AX does while
//! the partner's timeout preference is still the (short) administrative
//! default — fast-until-heard matters in practice, since a port whose link
//! comes up after its first send would otherwise sit silent for a whole Slow
//! interval before its partner ever hears it.
//!
//! The mirror image — how long *we* wait for the partner's LACPDUs — follows
//! our own rate and lives in `receive_machine` (`Current_While_Timer`).

use std::time::Duration;

use crate::receive_machine::ReceiveState;

pub const SLOW_PERIODIC_INTERVAL: Duration = Duration::from_secs(30);
pub const FAST_PERIODIC_INTERVAL: Duration = Duration::from_secs(1);

/// `partner_wants_fast` is the partner's most recently advertised
/// `LACP_Timeout` bit (`false` if none has been heard).
pub fn interval_for(receive_state: ReceiveState, partner_wants_fast: bool) -> Duration {
    match receive_state {
        ReceiveState::Expired | ReceiveState::Defaulted => FAST_PERIODIC_INTERVAL,
        ReceiveState::Current if partner_wants_fast => FAST_PERIODIC_INTERVAL,
        ReceiveState::Current => SLOW_PERIODIC_INTERVAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_fast_until_a_partner_is_heard() {
        for partner_wants_fast in [false, true] {
            assert_eq!(
                interval_for(ReceiveState::Expired, partner_wants_fast),
                FAST_PERIODIC_INTERVAL
            );
            assert_eq!(
                interval_for(ReceiveState::Defaulted, partner_wants_fast),
                FAST_PERIODIC_INTERVAL
            );
        }
    }

    #[test]
    fn once_current_follows_the_partners_request() {
        assert_eq!(
            interval_for(ReceiveState::Current, false),
            SLOW_PERIODIC_INTERVAL
        );
        assert_eq!(
            interval_for(ReceiveState::Current, true),
            FAST_PERIODIC_INTERVAL
        );
    }
}
