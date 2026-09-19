//! IEEE 802.1AX-2014 §6.4.13 Periodic Transmission Machine — how often this
//! port sends an LACPDU.
//!
//! A port with no live partner (`Expired`/`Defaulted`) transmits at the Fast
//! rate (1s), as 802.1AX does while the partner's timeout preference is
//! still the (short) administrative default. Once `Current` it drops to Slow
//! (30s). Fast-until-heard matters in practice: a port whose link comes up
//! after its first send would otherwise sit silent for a full Slow interval
//! before its partner ever hears it.
//!
//! `ponytail:` the rate is chosen only from *our* Receive state — never from
//! the partner's advertised `LACP_Timeout` bit — and we always advertise the
//! Long timeout ourselves. A partner that insists on Fast from us is
//! therefore still sent Slow once `Current`; most implementations tolerate
//! that. Upgrade path: honor the bit from `receive_machine::Event::
//! LacpduReceived`.

use std::time::Duration;

use crate::receive_machine::ReceiveState;

pub const SLOW_PERIODIC_INTERVAL: Duration = Duration::from_secs(30);
pub const FAST_PERIODIC_INTERVAL: Duration = Duration::from_secs(1);

pub fn interval_for(receive_state: ReceiveState) -> Duration {
    match receive_state {
        ReceiveState::Current => SLOW_PERIODIC_INTERVAL,
        ReceiveState::Expired | ReceiveState::Defaulted => FAST_PERIODIC_INTERVAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_until_a_partner_is_heard_then_slow() {
        assert_eq!(interval_for(ReceiveState::Expired), FAST_PERIODIC_INTERVAL);
        assert_eq!(
            interval_for(ReceiveState::Defaulted),
            FAST_PERIODIC_INTERVAL
        );
        assert_eq!(interval_for(ReceiveState::Current), SLOW_PERIODIC_INTERVAL);
    }
}
