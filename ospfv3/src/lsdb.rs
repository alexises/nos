//! RFC 5340's per-area Link State Database — the shared
//! `nos_ospf_common::lsdb::Lsdb` instantiated for `OSPFv3` LSAs, keyed by
//! `LsaKey` (RFC 5340 keeps RFC 2328 §13/§14's install/age/evict semantics
//! unchanged, only the LSA body types stored here differ). `link.rs` drives
//! when LSAs get installed and read, holding it behind an
//! `Arc<tokio::sync::Mutex<_>>` shared by every link in the same area.

pub use nos_ospf_common::lsdb::{InstallOutcome, MAX_AGE_HOLD_TICKS, MIN_LS_ARRIVAL};

pub type Lsdb = nos_ospf_common::lsdb::Lsdb<crate::lsa::Lsa>;

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use nos_ospf_common::lsa::{Lsa as _, LsaHeader as _};

    use super::*;
    use crate::lsa::{Lsa, LsaBody, LsaHeader, RouterLsaBody, LSA_TYPE_ROUTER};

    fn lsa(seq: i32) -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                lsa_type: LSA_TYPE_ROUTER,
                link_state_id: Ipv4Addr::new(9, 9, 9, 9),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: seq,
                checksum: 7,
                length: 24,
            },
            body: LsaBody::Router(RouterLsaBody {
                flags: 0,
                options: 0,
                links: Vec::new(),
            }),
        }
    }

    /// The trait impls map every field the shared store touches.
    #[test]
    fn trait_impls_map_header_fields() {
        let mut l = lsa(5);
        let h = l.header();
        assert_eq!(nos_ospf_common::lsa::LsaHeader::key(h), l.header.key());
        assert_eq!(h.seq(), 5);
        assert_eq!(h.checksum(), 7);
        assert_eq!(h.length(), 24);
        assert_eq!(h.advertising_router(), Ipv4Addr::new(9, 9, 9, 9));
        l.header_mut().set_age(42);
        assert_eq!(l.header.age, 42);
        assert_eq!(l.header().age(), 42);
    }

    /// End to end through the alias.
    #[test]
    fn alias_installs_and_supersedes() {
        let mut db = Lsdb::new();
        assert_eq!(db.install(lsa(1)), InstallOutcome::Installed);
        assert_eq!(db.install(lsa(2)), InstallOutcome::Superseded);
        assert_eq!(db.headers()[0].sequence_number, 2);
    }
}
