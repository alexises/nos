//! RFC 2439 route flap damping of received routes: a decaying penalty per
//! (peer, prefix) that suppresses the route while it is high. Pure state — the
//! RIB decides what counts as a flap and skips suppressed candidates.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use ipnet::IpNet;
use nos_proto::BgpDamping;
use tracing::info;

/// RFC 7196 §4.1: a withdrawal costs 1000, an attribute change 500.
pub const WITHDRAW_PENALTY: f64 = 1000.0;
pub const CHANGE_PENALTY: f64 = 500.0;

struct Entry {
    penalty: f64,
    updated: Instant,
    suppressed: bool,
}

impl Entry {
    fn decay(&mut self, p: &BgpDamping, now: Instant) {
        let dt = now.saturating_duration_since(self.updated).as_secs_f64();
        self.penalty *= 0.5_f64.powf(dt / f64::from(p.half_life));
        self.updated = now;
    }
}

#[derive(Default)]
pub struct Damping {
    params: HashMap<IpAddr, BgpDamping>,
    entries: HashMap<(IpAddr, IpNet), Entry>,
}

impl Damping {
    /// Sets (or, with `None`, removes) `peer`'s parameters; any state it
    /// had is discarded either way.
    pub fn set_params(&mut self, peer: IpAddr, params: Option<BgpDamping>) {
        self.clear_peer(peer);
        if let Some(p) = params {
            self.params.insert(peer, p);
        }
    }

    pub fn clear_peer(&mut self, peer: IpAddr) {
        self.params.remove(&peer);
        self.entries.retain(|(p, _), _| *p != peer);
    }

    pub fn enabled(&self, peer: IpAddr) -> bool {
        self.params.contains_key(&peer)
    }

    pub fn is_suppressed(&self, peer: IpAddr, prefix: &IpNet) -> bool {
        self.entries
            .get(&(peer, *prefix))
            .is_some_and(|e| e.suppressed)
    }

    /// Adds `weight` to the prefix's penalty (no-op if `peer` has no damping
    /// configured); returns whether that newly suppressed it.
    pub fn flap(&mut self, peer: IpAddr, prefix: IpNet, weight: f64, now: Instant) -> bool {
        let Some(p) = self.params.get(&peer) else {
            return false;
        };
        let ceiling =
            f64::from(p.reuse) * 2_f64.powf(f64::from(p.max_suppress) / f64::from(p.half_life));
        let e = self.entries.entry((peer, prefix)).or_insert(Entry {
            penalty: 0.0,
            updated: now,
            suppressed: false,
        });
        e.decay(p, now);
        e.penalty = (e.penalty + weight).min(ceiling);
        if !e.suppressed && e.penalty >= f64::from(p.suppress) {
            e.suppressed = true;
            info!(peer = %peer, %prefix, penalty = e.penalty.round(), "bgp: route suppressed by flap damping");
            return true;
        }
        false
    }

    /// Decays every entry; returns the routes whose penalty fell below
    /// `reuse` and are released. Forgets entries that have fully calmed down.
    pub fn tick(&mut self, now: Instant) -> Vec<(IpAddr, IpNet)> {
        let mut released = Vec::new();
        let params = &self.params;
        self.entries.retain(|(peer, prefix), e| {
            let Some(p) = params.get(peer) else {
                return false;
            };
            e.decay(p, now);
            if e.suppressed && e.penalty < f64::from(p.reuse) {
                e.suppressed = false;
                info!(peer = %peer, %prefix, "bgp: route released from flap damping");
                released.push((*peer, *prefix));
            }
            e.suppressed || e.penalty >= f64::from(p.reuse) / 2.0
        });
        released
    }
}

/// How often the RIB's damping state is decayed and reuse checked.
pub const TICK: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> BgpDamping {
        BgpDamping {
            half_life: 10,
            reuse: 750,
            suppress: 2500,
            max_suppress: 40,
        }
    }

    fn setup() -> (Damping, IpAddr, IpNet, Instant) {
        let mut d = Damping::default();
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        d.set_params(peer, Some(params()));
        (d, peer, "192.0.2.0/24".parse().unwrap(), Instant::now())
    }

    #[test]
    fn suppresses_at_threshold_and_releases_after_decay() {
        let (mut d, peer, prefix, t0) = setup();
        assert!(!d.flap(peer, prefix, WITHDRAW_PENALTY, t0));
        assert!(!d.flap(peer, prefix, WITHDRAW_PENALTY, t0));
        assert!(d.flap(peer, prefix, WITHDRAW_PENALTY, t0)); // 3000 >= 2500
        assert!(d.is_suppressed(peer, &prefix));
        // 3000 -> 750 takes two half-lives; just short of it stays suppressed.
        assert_eq!(d.tick(t0 + Duration::from_secs(19)), []);
        assert!(d.is_suppressed(peer, &prefix));
        assert_eq!(d.tick(t0 + Duration::from_secs(21)), vec![(peer, prefix)]);
        assert!(!d.is_suppressed(peer, &prefix));
    }

    #[test]
    fn penalty_is_capped_at_the_max_suppress_ceiling() {
        let (mut d, peer, prefix, t0) = setup();
        for _ in 0..50 {
            d.flap(peer, prefix, WITHDRAW_PENALTY, t0);
        }
        // ceiling = 750 * 2^(40/10) = 12000, so it decays under reuse in 40s.
        assert_eq!(d.tick(t0 + Duration::from_secs(41)).len(), 1);
    }

    #[test]
    fn calm_entries_are_forgotten_and_unconfigured_peers_ignored() {
        let (mut d, peer, prefix, t0) = setup();
        d.flap(peer, prefix, CHANGE_PENALTY, t0);
        d.tick(t0 + Duration::from_secs(60));
        assert!(d.entries.is_empty());
        let other: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(!d.flap(other, prefix, 1e9, t0));
        assert!(!d.is_suppressed(other, &prefix));
    }
}
