//! Designated Forwarder election for an Ethernet Segment (RFC 7432 §8.5).
//!
//! The default "service carving" procedure: order the PEs attached to the
//! segment by ascending IP address; the DF for Ethernet tag `V` is the PE at
//! ordinal `V mod N`. With VXLAN the VNI plays `V` (RFC 8365 §8.3.1), and a
//! domain has exactly one VNI, so each domain elects independently and
//! different domains spread over different PEs.
//!
//! Pure: `Fdb` feeds it the Type-4 origins it received and applies the answer.
//!
//! ponytail: no DF wait timer (§8.5 step 3) — a PE that has just come up
//! elects with whatever Type-4s have arrived so far, so BUM can briefly be
//! delivered twice; and every PE on the segment is assumed to serve every
//! domain (no Type-1 per-EVI routes to say otherwise).

use std::collections::BTreeSet;
use std::net::IpAddr;

/// The PEs on a segment ranked for election: `own` plus `peers`, ascending.
#[must_use]
pub fn candidates(own: IpAddr, peers: &BTreeSet<IpAddr>) -> Vec<IpAddr> {
    let mut all: BTreeSet<IpAddr> = peers.clone();
    all.insert(own);
    all.into_iter().collect()
}

/// The elected DF's address among `own` and `peers` for `vni`.
#[must_use]
pub fn elect(own: IpAddr, peers: &BTreeSet<IpAddr>, vni: u32) -> IpAddr {
    let all = candidates(own, peers);
    all[vni as usize % all.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn alone_on_the_segment_is_always_the_df() {
        assert_eq!(
            elect(ip("192.0.2.1"), &BTreeSet::new(), 10100),
            ip("192.0.2.1")
        );
    }

    #[test]
    fn the_vni_modulo_the_ordered_pes_picks_the_df() {
        let peers = BTreeSet::from([ip("192.0.2.9"), ip("192.0.2.5")]);
        // Ordered: .1 .5 .9 — 10100 % 3 == 2, 10101 % 3 == 0.
        assert_eq!(elect(ip("192.0.2.1"), &peers, 10100), ip("192.0.2.9"));
        assert_eq!(elect(ip("192.0.2.1"), &peers, 10101), ip("192.0.2.1"));
        assert_eq!(elect(ip("192.0.2.1"), &peers, 10102), ip("192.0.2.5"));
    }

    #[test]
    fn every_pe_agrees_whichever_one_asks() {
        let a = ip("192.0.2.1");
        let b = ip("192.0.2.9");
        for vni in [1, 2, 10100, 16_777_215] {
            assert_eq!(
                elect(a, &BTreeSet::from([b]), vni),
                elect(b, &BTreeSet::from([a]), vni)
            );
        }
    }

    #[test]
    fn listing_our_own_address_among_the_peers_changes_nothing() {
        let a = ip("192.0.2.1");
        assert_eq!(
            candidates(a, &BTreeSet::from([a, ip("192.0.2.2")])).len(),
            2
        );
    }
}
