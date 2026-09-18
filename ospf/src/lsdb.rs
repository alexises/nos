//! RFC 2328's per-area Link State Database — installed-LSA store, keyed by
//! `LsaKey`. Pure data structure, no I/O; `link.rs` drives when LSAs get
//! installed (self-origination, or received via LSU) and read (DBD summary
//! lists, LSR responses), holding it behind an `Arc<tokio::sync::Mutex<_>>`
//! shared by every link in the same area.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;

use crate::lsa::{self, Lsa, LsaHeader, LsaKey};

#[derive(Debug, Default)]
pub struct Lsdb {
    entries: HashMap<LsaKey, Arc<Lsa>>,
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
                self.entries.insert(key, Arc::new(lsa));
                InstallOutcome::Superseded
            }
            None => {
                self.entries.insert(key, Arc::new(lsa));
                InstallOutcome::Installed
            }
        }
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
}
