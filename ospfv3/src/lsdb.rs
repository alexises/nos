//! RFC 5340's per-area Link State Database — installed-LSA store, keyed by
//! `LsaKey`. Pure data structure, no I/O; ported verbatim from
//! `ospf::lsdb::Lsdb` (RFC 5340 keeps RFC 2328 §13/§14's install/age/evict
//! semantics unchanged, only the LSA body types stored here differ).
//! `link.rs` drives when LSAs get installed (self-origination, or received
//! via LSU) and read (DBD summary lists, LSR responses), holding it behind
//! an `Arc<tokio::sync::Mutex<_>>` shared by every link in the same area.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::lsa::{self, Lsa, LsaHeader, LsaKey};

/// How many `age_and_evict` ticks an entry sits at `MAX_AGE` before it's
/// evicted — `ospf::lsdb::MAX_AGE_HOLD_TICKS`: long enough for one periodic
/// resend (`link::RXMT_INTERVAL`, 5s) to carry a flushed copy to every
/// neighbor before it disappears locally.
pub const MAX_AGE_HOLD_TICKS: u16 = 7;

#[derive(Debug, Default)]
pub struct Lsdb {
    entries: HashMap<LsaKey, Arc<Lsa>>,
    /// Ticks each entry has already spent at `MAX_AGE` — see
    /// `MAX_AGE_HOLD_TICKS`.
    max_age_ticks: HashMap<LsaKey, u16>,
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

    pub fn remove(&mut self, key: &LsaKey) {
        self.entries.remove(key);
        self.max_age_ticks.remove(key);
    }

    pub fn get(&self, key: &LsaKey) -> Option<Arc<Lsa>> {
        self.entries.get(key).cloned()
    }

    /// Every installed LSA's header — the source of a DBD summary list.
    pub fn headers(&self) -> Vec<LsaHeader> {
        self.entries.values().map(|l| l.header).collect()
    }

    /// Every installed LSA — used by `link.rs`'s periodic full-LSDB resend
    /// to `Full` neighbors.
    pub fn all(&self) -> Vec<Arc<Lsa>> {
        self.entries.values().cloned().collect()
    }

    /// RFC 2328 §14 (unchanged by RFC 5340): ages every installed LSA by
    /// `delta` (saturating at `MAX_AGE`) and evicts any entry that has sat at
    /// `MAX_AGE` for `MAX_AGE_HOLD_TICKS` ticks — aged out naturally or
    /// prematurely aged (§14.1, `link::withdraw_self_originated`) — returning
    /// the evicted keys so `link.rs` can log them. An LSA whose advertising
    /// router is in `hold` (a neighbor in its RFC 5187 grace period) ages to
    /// just below `MaxAge` instead — the helper keeps the restarting router's
    /// LSAs until the grace period ends — but one already at `MaxAge`
    /// (flushed) is never revived by it.
    pub fn age_and_evict(&mut self, delta: u16, hold: &HashSet<Ipv4Addr>) -> Vec<LsaKey> {
        let mut evicted = Vec::new();
        let max_age_ticks = &mut self.max_age_ticks;
        self.entries.retain(|key, lsa| {
            if lsa.header.age >= lsa::MAX_AGE {
                let ticks = max_age_ticks.entry(*key).or_insert(0);
                *ticks += 1;
                if *ticks >= MAX_AGE_HOLD_TICKS {
                    max_age_ticks.remove(key);
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
    use crate::lsa::{LsaBody, RouterLsaBody, LSA_TYPE_ROUTER};

    fn lsa(seq: i32) -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                lsa_type: LSA_TYPE_ROUTER,
                link_state_id: Ipv4Addr::new(9, 9, 9, 9),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: seq,
                checksum: 0,
                length: 24,
            },
            body: LsaBody::Router(RouterLsaBody {
                flags: 0,
                options: 0,
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
        assert_eq!(evicted, []);
        assert_eq!(db.get(&lsa(1).header.key()).unwrap().header.age, 100);
    }

    /// Ticks until `age_and_evict` reports an eviction, or `None` if it
    /// never does within `MAX_AGE_HOLD_TICKS + 1` ticks.
    fn ticks_until_evicted(db: &mut Lsdb, hold: &HashSet<Ipv4Addr>) -> Option<u16> {
        (1..=MAX_AGE_HOLD_TICKS + 1).find(|_| !db.age_and_evict(1, hold).is_empty())
    }

    #[test]
    fn age_and_evict_holds_at_max_age_then_evicts() {
        let mut db = Lsdb::new();
        db.install(lsa(1));
        let key = lsa(1).header.key();
        // Saturates at MAX_AGE on the first tick, then is held for the flood window.
        assert_eq!(db.age_and_evict(lsa::MAX_AGE, &HashSet::new()), []);
        assert_eq!(db.get(&key).unwrap().header.age, lsa::MAX_AGE);
        assert_eq!(
            ticks_until_evicted(&mut db, &HashSet::new()),
            Some(MAX_AGE_HOLD_TICKS)
        );
        assert!(db.get(&key).is_none());
    }

    #[test]
    fn age_and_evict_holds_a_router_in_grace() {
        let mut db = Lsdb::new();
        db.install(lsa(1));
        let in_grace = HashSet::from([lsa(1).header.advertising_router]);
        assert_eq!(db.age_and_evict(lsa::MAX_AGE, &in_grace), []);
        let held = db.get(&lsa(1).header.key()).unwrap();
        assert_eq!(held.header.age, lsa::MAX_AGE - 1);
        assert_eq!(db.age_and_evict(1, &HashSet::new()), []);
        assert_eq!(
            db.get(&lsa(1).header.key()).unwrap().header.age,
            lsa::MAX_AGE
        );
    }

    /// A flushed LSA from a router in grace isn't turned back into a live
    /// `MaxAge - 1` one: it's held, then evicted, like any other.
    #[test]
    fn grace_hold_does_not_revive_a_max_age_entry() {
        let mut db = Lsdb::new();
        let mut flushed = lsa(1);
        flushed.header.age = lsa::MAX_AGE;
        db.install(flushed);
        let in_grace = HashSet::from([lsa(1).header.advertising_router]);
        assert_eq!(
            ticks_until_evicted(&mut db, &in_grace),
            Some(MAX_AGE_HOLD_TICKS)
        );
    }

    #[test]
    fn superseding_a_max_age_entry_restarts_its_hold() {
        let mut db = Lsdb::new();
        let mut flushed = lsa(1);
        flushed.header.age = lsa::MAX_AGE;
        db.install(flushed);
        for _ in 0..MAX_AGE_HOLD_TICKS - 1 {
            assert_eq!(db.age_and_evict(1, &HashSet::new()), []);
        }
        assert_eq!(db.install(lsa(2)), InstallOutcome::Superseded);
        assert_eq!(db.age_and_evict(1, &HashSet::new()), []);
        assert_eq!(db.get(&lsa(2).header.key()).unwrap().header.age, 1);
    }
}
