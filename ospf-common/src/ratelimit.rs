//! Log rate limiting and the per-link neighbor cap shared by `nos-ospf` and
//! `nos-ospfv3`: a peer on the segment must not be able to turn Hellos into
//! unbounded log lines or unbounded neighbor-table growth (#394).

use std::time::{Duration, Instant};

/// Most neighbors one link keeps; a Hello from a further router-id is refused.
/// ponytail: a hard constant, not a profile knob; make it configurable if a
/// real segment ever needs more than 64 routers.
pub const MAX_NEIGHBORS_PER_LINK: usize = 64;

const BURST: u32 = 5;
const REFILL: Duration = Duration::from_secs(1);

/// Token bucket for `warn!` lines: `BURST` at once, one more per second.
/// One per link run loop, shared by every warning a peer can trigger.
#[derive(Debug, Default)]
pub struct WarnLimiter {
    tokens: u32,
    last_refill: Option<Instant>,
    suppressed: u32,
}

impl WarnLimiter {
    /// Whether a warning may be logged at `now`.
    pub fn allow(&mut self, now: Instant) -> bool {
        match self.last_refill {
            None => {
                self.tokens = BURST;
                self.last_refill = Some(now);
            }
            Some(last) => {
                let gained =
                    now.saturating_duration_since(last).as_secs_f64() / REFILL.as_secs_f64();
                if gained >= 1.0 {
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    let gained = gained.min(f64::from(BURST)) as u32;
                    self.tokens = (self.tokens + gained).min(BURST);
                    self.last_refill = Some(now);
                }
            }
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
            false
        }
    }

    /// Warnings dropped since the last call, for the next allowed line.
    pub fn take_suppressed(&mut self) -> u32 {
        std::mem::take(&mut self.suppressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_burst_then_refills_one_per_second() {
        let t0 = Instant::now();
        let mut l = WarnLimiter::default();
        assert!((0..5).all(|_| l.allow(t0)));
        assert!(!l.allow(t0));
        assert!(!l.allow(t0));
        assert!(l.allow(t0 + Duration::from_secs(1)));
        assert!(!l.allow(t0 + Duration::from_secs(1)));
        assert_eq!(l.take_suppressed(), 3);
        assert_eq!(l.take_suppressed(), 0);
        // A long idle refills to the burst, not beyond.
        let later = t0 + Duration::from_secs(100);
        assert!((0..5).all(|_| l.allow(later)));
        assert!(!l.allow(later));
    }
}
