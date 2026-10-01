//! RFC 2328's per-area Link State Database — installed-LSA store, keyed by
//! `LsaKey`. Pure data structure, no I/O; `link.rs` drives when LSAs get
//! installed (self-origination, or received via LSU) and read (DBD summary
//! lists, LSR responses), holding it behind an `Arc<tokio::sync::Mutex<_>>`
//! shared by every link in the same area.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::lsa::{self, Lsa, LsaHeader, LsaKey};

/// RFC 2328 §13 step 5a / Appendix B's `MinLSArrival` — a newer instance of
/// an LSA received via flooding within this long of the previous received
/// instance is discarded (`InstallOutcome::TooSoon`), not installed and not
/// acknowledged, so a flapping originator can't drive reflood storms.
pub const MIN_LS_ARRIVAL: Duration = Duration::from_secs(1);

/// How many `age_and_evict` ticks an entry sits at `MAX_AGE` before it's
/// evicted. RFC 2328 §14 removes a `MaxAge` LSA once it's off every neighbor's
/// retransmission list; this crate has no such signal (flooding is a periodic
/// full resend, `link::RXMT_INTERVAL` = 5s), so a bounded hold — long enough
/// for one resend tick plus margin — is what lets a flushed LSA actually
/// reach the neighbors before it disappears locally.
pub const MAX_AGE_HOLD_TICKS: u16 = 7;

#[derive(Debug, Default)]
pub struct Lsdb {
    entries: HashMap<LsaKey, Arc<Lsa>>,
    /// Ticks each entry has already spent at `MAX_AGE` — see
    /// `MAX_AGE_HOLD_TICKS`.
    max_age_ticks: HashMap<LsaKey, u16>,
    /// When each key's current instance was last accepted via flooding
    /// (`install_received`) — see `MIN_LS_ARRIVAL`. Self-originated installs
    /// don't record here: they're paced by `lsa::MIN_LS_INTERVAL` instead.
    last_received: HashMap<LsaKey, Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    /// No prior instance existed.
    Installed,
    /// A newer instance replaced an older one.
    Superseded,
    /// The given instance wasn't newer than what's already held — RFC 2328
    /// §13's "database copy is more recent or the same" case.
    Rejected,
    /// Newer, but received less than `MIN_LS_ARRIVAL` after the held
    /// instance was — RFC 2328 §13 step 5a: discard without acknowledging.
    TooSoon,
}

impl Lsdb {
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs `lsa` if it's newer than (or new relative to) what's held —
    /// see `lsa::is_newer`.
    pub fn install(&mut self, lsa: Lsa) -> InstallOutcome {
        let key = lsa.header.key();
        match self.entries.get(&key) {
            Some(existing) if lsa::is_newer(&lsa.header, &existing.header) != Ordering::Greater => {
                InstallOutcome::Rejected
            }
            Some(_) => {
                // A fresh instance restarts the MaxAge hold; a flushed one
                // (same sequence, age now MaxAge) starts it.
                self.max_age_ticks.remove(&key);
                self.entries.insert(key, Arc::new(lsa));
                InstallOutcome::Superseded
            }
            None => {
                self.entries.insert(key, Arc::new(lsa));
                InstallOutcome::Installed
            }
        }
    }

    /// `install` for an instance received via flooding, paced by
    /// `MIN_LS_ARRIVAL`: a newer instance arriving within it of the last one
    /// accepted for the same key is `TooSoon` and left uninstalled — the
    /// sender's retransmission brings it back after `RxmtInterval`.
    pub fn install_received(&mut self, lsa: Lsa, now: Instant) -> InstallOutcome {
        let key = lsa.header.key();
        let too_soon = self
            .last_received
            .get(&key)
            .is_some_and(|last| now.duration_since(*last) < MIN_LS_ARRIVAL);
        let newer = self.entries.get(&key).is_none_or(|existing| {
            lsa::is_newer(&lsa.header, &existing.header) == Ordering::Greater
        });
        if too_soon && newer {
            return InstallOutcome::TooSoon;
        }
        let outcome = self.install(lsa);
        if outcome != InstallOutcome::Rejected {
            self.last_received.insert(key, now);
        }
        outcome
    }

    /// Drops `key` outright — a received Grace-LSA, acted on and never held
    /// (see `link::handle_lsu`).
    pub fn remove(&mut self, key: &LsaKey) {
        self.entries.remove(key);
        self.max_age_ticks.remove(key);
        self.last_received.remove(key);
    }

    pub fn get(&self, key: &LsaKey) -> Option<Arc<Lsa>> {
        self.entries.get(key).cloned()
    }

    /// Every installed LSA's header — the source of a DBD summary list.
    pub fn headers(&self) -> Vec<LsaHeader> {
        self.entries.values().map(|l| l.header).collect()
    }

    /// Every installed LSA — used by `link.rs`'s periodic full-LSDB resend
    /// to `Full` neighbors (see its own `ponytail:` note).
    pub fn all(&self) -> Vec<Arc<Lsa>> {
        self.entries.values().cloned().collect()
    }

    /// RFC 2328 §14: ages every installed LSA by `delta` (saturating at
    /// `MAX_AGE`) and evicts any entry that has sat at `MAX_AGE` for
    /// `MAX_AGE_HOLD_TICKS` ticks — whether it aged out naturally or was
    /// prematurely aged (§14.1, `link::withdraw_self_originated`) — returning
    /// the evicted keys so `link.rs` can log them. The hold is what gives
    /// `link::flood_full_neighbors`' periodic resend a chance to carry the
    /// `MaxAge` copy to every neighbor first.
    ///
    /// An LSA whose advertising router is in `hold` (a neighbor in its RFC
    /// 3623 grace period) is aged no further than just below `MaxAge`: the
    /// helper keeps the restarting router's LSAs until grace ends. A copy
    /// already at `MaxAge` (one the restarter flushed itself) is evicted as
    /// usual.
    pub fn age_and_evict(&mut self, delta: u16, hold: &HashSet<Ipv4Addr>) -> Vec<LsaKey> {
        let mut evicted = Vec::new();
        let max_age_ticks = &mut self.max_age_ticks;
        let last_received = &mut self.last_received;
        self.entries.retain(|key, lsa| {
            if lsa.header.age >= lsa::MAX_AGE {
                let ticks = max_age_ticks.entry(*key).or_insert(0);
                *ticks += 1;
                if *ticks >= MAX_AGE_HOLD_TICKS {
                    max_age_ticks.remove(key);
                    last_received.remove(key);
                    evicted.push(*key);
                    return false;
                }
                return true;
            }
            let mut aged = lsa.header.age.saturating_add(delta).min(lsa::MAX_AGE);
            if aged >= lsa::MAX_AGE && hold.contains(&key.advertising_router) {
                aged = lsa::MAX_AGE - 1;
            }
            if aged != lsa.header.age {
                let mut updated = (**lsa).clone();
                updated.header.age = aged;
                *lsa = Arc::new(updated);
            }
            true
        });
        evicted
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::lsa::{LsaBody, RouterLsaBody};

    fn lsa(seq: i32) -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: lsa::LSA_TYPE_ROUTER,
                link_state_id: Ipv4Addr::new(9, 9, 9, 9),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: seq,
                checksum: 0,
                length: 24,
            },
            body: LsaBody::Router(RouterLsaBody {
                flags: 0,
                links: Vec::new(),
            }),
        }
    }

    #[test]
    fn first_install_is_installed() {
        let mut db = Lsdb::new();
        assert_eq!(db.install(lsa(1)), InstallOutcome::Installed);
        assert!(db.get(&lsa(1).header.key()).is_some());
    }

    #[test]
    fn newer_instance_supersedes() {
        let mut db = Lsdb::new();
        db.install(lsa(1));
        assert_eq!(db.install(lsa(2)), InstallOutcome::Superseded);
        assert_eq!(
            db.get(&lsa(1).header.key()).unwrap().header.sequence_number,
            2
        );
    }

    #[test]
    fn older_instance_is_rejected() {
        let mut db = Lsdb::new();
        db.install(lsa(2));
        assert_eq!(db.install(lsa(1)), InstallOutcome::Rejected);
        assert_eq!(
            db.get(&lsa(1).header.key()).unwrap().header.sequence_number,
            2
        );
    }

    #[test]
    fn unknown_key_returns_none() {
        let db = Lsdb::new();
        assert!(db.get(&lsa(1).header.key()).is_none());
    }

    #[test]
    fn headers_reflects_installed_entries() {
        let mut db = Lsdb::new();
        db.install(lsa(1));
        assert_eq!(db.headers().len(), 1);
        assert_eq!(db.headers()[0].key(), lsa(1).header.key());
    }

    #[test]
    fn age_and_evict_increments_age_without_eviction() {
        let mut db = Lsdb::new();
        db.install(lsa(1));
        let evicted = db.age_and_evict(100, &HashSet::new());
        assert!(evicted.is_empty());
        assert_eq!(db.get(&lsa(1).header.key()).unwrap().header.age, 100);
    }

    /// Ticks until `age_and_evict` reports an eviction, or `None` if it never does
    /// within `MAX_AGE_HOLD_TICKS + 1` ticks.
    fn ticks_until_evicted(db: &mut Lsdb, delta: u16) -> Option<u16> {
        (1..=MAX_AGE_HOLD_TICKS + 1).find(|_| !db.age_and_evict(delta, &HashSet::new()).is_empty())
    }

    #[test]
    fn age_and_evict_holds_at_max_age_then_evicts() {
        let mut db = Lsdb::new();
        db.install(lsa(1));
        let key = lsa(1).header.key();
        // Saturates at MAX_AGE on the first tick, then is held for the flood window.
        assert!(db.age_and_evict(lsa::MAX_AGE, &HashSet::new()).is_empty());
        assert_eq!(db.get(&key).unwrap().header.age, lsa::MAX_AGE);
        assert_eq!(ticks_until_evicted(&mut db, 1), Some(MAX_AGE_HOLD_TICKS));
        assert!(db.get(&key).is_none());
    }

    #[test]
    fn age_and_evict_only_evicts_crossed_entries() {
        let mut db = Lsdb::new();
        let mut stale = lsa(1);
        stale.header.link_state_id = Ipv4Addr::new(1, 1, 1, 1);
        stale.header.advertising_router = Ipv4Addr::new(1, 1, 1, 1);
        stale.header.age = lsa::MAX_AGE;
        db.install(stale.clone());
        db.install(lsa(1));

        assert_eq!(ticks_until_evicted(&mut db, 10), Some(MAX_AGE_HOLD_TICKS));
        assert!(db.get(&stale.header.key()).is_none());
        assert_eq!(
            db.get(&lsa(1).header.key()).unwrap().header.age,
            10 * MAX_AGE_HOLD_TICKS
        );
    }

    #[test]
    fn superseding_a_max_age_entry_restarts_its_hold() {
        let mut db = Lsdb::new();
        let mut flushed = lsa(1);
        flushed.header.age = lsa::MAX_AGE;
        db.install(flushed);
        for _ in 0..MAX_AGE_HOLD_TICKS - 1 {
            assert!(db.age_and_evict(1, &HashSet::new()).is_empty());
        }
        assert_eq!(db.install(lsa(2)), InstallOutcome::Superseded);
        assert!(db.age_and_evict(1, &HashSet::new()).is_empty());
        assert_eq!(db.get(&lsa(2).header.key()).unwrap().header.age, 1);
    }

    #[test]
    fn age_and_evict_holds_a_router_in_grace() {
        let mut db = Lsdb::new();
        db.install(lsa(1));
        let key = lsa(1).header.key();
        let in_grace = HashSet::from([key.advertising_router]);
        assert!(db.age_and_evict(lsa::MAX_AGE, &in_grace).is_empty());
        assert_eq!(db.get(&key).unwrap().header.age, lsa::MAX_AGE - 1);
        // Grace over: it reaches MaxAge and is evicted after the usual hold.
        assert!(db.age_and_evict(1, &HashSet::new()).is_empty());
        assert_eq!(ticks_until_evicted(&mut db, 1), Some(MAX_AGE_HOLD_TICKS));
    }

    /// A copy the restarter already flushed (at `MaxAge`) is not held.
    #[test]
    fn age_and_evict_does_not_hold_a_flushed_copy() {
        let mut db = Lsdb::new();
        let mut flushed = lsa(1);
        flushed.header.age = lsa::MAX_AGE;
        db.install(flushed);
        let in_grace = HashSet::from([lsa(1).header.advertising_router]);
        let evicted = (0..MAX_AGE_HOLD_TICKS).any(|_| !db.age_and_evict(1, &in_grace).is_empty());
        assert!(evicted);
    }

    /// RFC 2328 §13 step 5a: a newer instance within `MIN_LS_ARRIVAL` of the
    /// last received one is `TooSoon` and leaves the held one untouched; at
    /// or past it, it supersedes as usual.
    #[test]
    fn install_received_paces_newer_instances_by_min_ls_arrival() {
        let mut db = Lsdb::new();
        let t0 = Instant::now();
        let key = lsa(1).header.key();
        assert_eq!(db.install_received(lsa(1), t0), InstallOutcome::Installed);
        assert_eq!(
            db.install_received(lsa(2), t0 + MIN_LS_ARRIVAL / 2),
            InstallOutcome::TooSoon
        );
        assert_eq!(db.get(&key).unwrap().header.sequence_number, 1);
        // A duplicate is still just rejected, never `TooSoon`.
        assert_eq!(
            db.install_received(lsa(1), t0 + MIN_LS_ARRIVAL / 2),
            InstallOutcome::Rejected
        );
        assert_eq!(
            db.install_received(lsa(2), t0 + MIN_LS_ARRIVAL),
            InstallOutcome::Superseded
        );
        assert_eq!(db.get(&key).unwrap().header.sequence_number, 2);
        // The pacing clock restarts from the accepted instance.
        assert_eq!(
            db.install_received(lsa(3), t0 + MIN_LS_ARRIVAL + MIN_LS_ARRIVAL / 2),
            InstallOutcome::TooSoon
        );
    }

    /// A self-originated install never records an arrival, so a received
    /// newer instance right after it isn't paced against it.
    #[test]
    fn install_received_is_not_paced_against_a_local_install() {
        let mut db = Lsdb::new();
        let t0 = Instant::now();
        db.install(lsa(1));
        assert_eq!(db.install_received(lsa(2), t0), InstallOutcome::Superseded);
    }
}
