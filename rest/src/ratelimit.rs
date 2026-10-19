//! Per-peer token bucket for log lines a remote peer can trigger at will
//! (failed TLS handshakes, refused connections): burst of `BURST`, one more
//! per `REFILL`; the suppressed ones are counted and reported on the next
//! line that gets through. Pure: the caller passes the clock.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const BURST: u32 = 3;
const REFILL: Duration = Duration::from_secs(10);
/// Peers tracked at once; past this, buckets are dropped (a forgotten peer
/// just gets a fresh burst).
const MAX_PEERS: usize = 1024;

struct Bucket {
    tokens: u32,
    refilled: Instant,
    suppressed: u64,
}

#[derive(Default)]
pub struct LogLimiter {
    peers: HashMap<IpAddr, Bucket>,
}

impl LogLimiter {
    /// `Some(n)`: log this one, `n` earlier ones from `peer` were suppressed.
    /// `None`: suppress it.
    pub fn allow(&mut self, peer: IpAddr, now: Instant) -> Option<u64> {
        if self.peers.len() >= MAX_PEERS && !self.peers.contains_key(&peer) {
            // Full buckets carry no state; if that frees nothing, start over.
            self.peers
                .retain(|_, b| b.tokens < BURST || b.suppressed > 0);
            if self.peers.len() >= MAX_PEERS {
                self.peers.clear();
            }
        }
        let b = self.peers.entry(peer).or_insert(Bucket {
            tokens: BURST,
            refilled: now,
            suppressed: 0,
        });
        let gained = now.saturating_duration_since(b.refilled).as_secs() / REFILL.as_secs();
        if gained > 0 {
            b.tokens = u32::try_from(u64::from(b.tokens) + gained)
                .unwrap_or(BURST)
                .min(BURST);
            b.refilled = now;
        }
        if b.tokens == 0 {
            b.suppressed += 1;
            return None;
        }
        b.tokens -= 1;
        Some(std::mem::take(&mut b.suppressed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    #[test]
    fn burst_then_suppressed_then_refill_reports_count() {
        let mut l = LogLimiter::default();
        let t0 = Instant::now();
        for _ in 0..3 {
            assert_eq!(l.allow(ip(1), t0), Some(0));
        }
        assert_eq!(l.allow(ip(1), t0), None);
        assert_eq!(l.allow(ip(1), t0), None);
        // Another peer is unaffected.
        assert_eq!(l.allow(ip(2), t0), Some(0));
        assert_eq!(l.allow(ip(1), t0 + REFILL), Some(2));
        assert_eq!(l.allow(ip(1), t0 + REFILL), None);
    }

    #[test]
    fn refill_is_capped_at_the_burst() {
        let mut l = LogLimiter::default();
        let t0 = Instant::now();
        l.allow(ip(1), t0);
        let later = t0 + REFILL * 100;
        for _ in 0..3 {
            assert!(l.allow(ip(1), later).is_some());
        }
        assert_eq!(l.allow(ip(1), later), None);
    }

    #[test]
    fn peer_table_is_bounded() {
        let mut l = LogLimiter::default();
        let t0 = Instant::now();
        for i in 0..3072u32 {
            l.allow(IpAddr::from(i.to_be_bytes()), t0);
            assert!(l.peers.len() <= MAX_PEERS);
        }
    }
}
