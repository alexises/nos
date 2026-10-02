//! Designated Forwarder election for an Ethernet Segment (RFC 7432 §8.5).
//!
//! The default "service carving" procedure: order the PEs attached to the
//! segment by ascending IP address; the DF for Ethernet tag `V` is the PE at
//! ordinal `V mod N`. With VXLAN the VNI plays `V` (RFC 8365 §8.3.1), and a
//! domain has exactly one VNI, so each domain elects independently and
//! different domains spread over different PEs.
//!
//! Pure: `Fdb` feeds it the Type-4 origins it received (already restricted by
//! `plan_df` to PEs also attached to this domain's own EVI) and applies the
//! answer.
//!
//! RFC 8584 §3 Highest Random Weight (`elect_hrw`) is the alternative every
//! PE must agree on (`effective`, §2.2.3) before it is used.
//!
//! The DF wait timer (§8.5 step 3) is `Fdb::sync_df`'s: this only answers
//! "who would be the DF".

use std::collections::BTreeSet;
use std::net::IpAddr;

use nos_proto::evpn_id::Esi;
use nos_proto::DfAlgorithm;

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

/// The algorithm actually run on a segment (RFC 8584 §2.2.3): `Hrw` only if
/// every PE, us included, asked for it (`None` = no DF Election community, or
/// an algorithm we don't implement) and every PE has an IPv4 address.
/// ponytail: §3.2 only defines `Si` for IPv4, so an IPv6 PE forces modulo
/// rather than guessing at an encoding.
#[must_use]
pub fn effective(
    own: DfAlgorithm,
    own_addr: IpAddr,
    peers: impl IntoIterator<Item = (IpAddr, Option<DfAlgorithm>)>,
) -> DfAlgorithm {
    let all_hrw = own == DfAlgorithm::Hrw
        && own_addr.is_ipv4()
        && peers
            .into_iter()
            .all(|(a, alg)| a.is_ipv4() && alg == Some(DfAlgorithm::Hrw));
    if all_hrw {
        DfAlgorithm::Hrw
    } else {
        DfAlgorithm::Modulo
    }
}

/// RFC 8584 §3.2 weight of the PE at `si` for Ethernet tag `vni` on `esi`:
/// `(1103515245 * ((1103515245 * Si + 12345) XOR D(v, Es)) + 12345) mod 2^31`,
/// `D` being CRC-32 over the 4-octet tag then the 10-octet ESI. Only the low
/// 31 bits survive, so wrapping u64 arithmetic gives the exact result.
#[must_use]
pub fn hrw_weight(vni: u32, esi: &Esi, si: u32) -> u32 {
    const A: u64 = 1_103_515_245;
    let mut h = crc32fast::Hasher::new();
    h.update(&vni.to_be_bytes());
    h.update(esi);
    let d = u64::from(h.finalize());
    let inner = A.wrapping_mul(u64::from(si)).wrapping_add(12345) ^ d;
    u32::try_from(A.wrapping_mul(inner).wrapping_add(12345) & 0x7fff_ffff).unwrap_or(0)
}

/// The HRW DF among `own` and `peers` (all IPv4, see `effective`).
#[must_use]
pub fn elect_hrw(own: IpAddr, peers: &BTreeSet<IpAddr>, vni: u32, esi: &Esi) -> IpAddr {
    highest(&candidates(own, peers), |a| match a {
        IpAddr::V4(v4) => hrw_weight(vni, esi, u32::from(*v4)),
        IpAddr::V6(_) => 0,
    })
}

/// The highest-weight address of `ascending`, a tie going to the lowest
/// address (RFC 8584 §3.2). `max_by_key` keeps the last maximum, hence `rev`.
fn highest(ascending: &[IpAddr], weight: impl Fn(&IpAddr) -> u32) -> IpAddr {
    ascending
        .iter()
        .rev()
        .max_by_key(|a| weight(a))
        .copied()
        .unwrap_or(ascending[0])
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

    const ESI: Esi = [0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];

    fn v4(s: &str) -> u32 {
        u32::from(s.parse::<std::net::Ipv4Addr>().unwrap())
    }

    #[test]
    fn hrw_matches_a_hand_computed_vector() {
        // No public RFC 8584 test vector exists; these pin our reading of
        // §3.2, computed independently with Python's `zlib.crc32` and big
        // integers: D(10100, ESI) = 1003094399, weights .1 = 156340126,
        // .5 = 942677242, .9 = 180950870 — so .5 wins where modulo picks .9.
        assert_eq!(hrw_weight(10100, &ESI, v4("192.0.2.1")), 156_340_126);
        assert_eq!(hrw_weight(10100, &ESI, v4("192.0.2.5")), 942_677_242);
        assert_eq!(hrw_weight(10100, &ESI, v4("192.0.2.9")), 180_950_870);
        let peers = BTreeSet::from([ip("192.0.2.9"), ip("192.0.2.5")]);
        assert_eq!(
            elect_hrw(ip("192.0.2.1"), &peers, 10100, &ESI),
            ip("192.0.2.5")
        );
        assert_eq!(elect(ip("192.0.2.1"), &peers, 10100), ip("192.0.2.9"));
        // 10101: .1 = 268822238, .5 = 545567674, .9 = 1620906902.
        assert_eq!(
            elect_hrw(ip("192.0.2.1"), &peers, 10101, &ESI),
            ip("192.0.2.9")
        );
        // 10102: .1 = 1914169969, .5 = 609086285, .9 = 1184268073.
        assert_eq!(
            elect_hrw(ip("192.0.2.1"), &peers, 10102, &ESI),
            ip("192.0.2.1")
        );
    }

    #[test]
    fn every_pe_agrees_on_the_hrw_df_whichever_one_asks() {
        let pes = [ip("192.0.2.1"), ip("192.0.2.5"), ip("192.0.2.9")];
        for vni in [1, 2, 10100, 16_777_215] {
            let dfs: BTreeSet<IpAddr> = pes
                .iter()
                .map(|own| {
                    let peers = pes.iter().filter(|p| *p != own).copied().collect();
                    elect_hrw(*own, &peers, vni, &ESI)
                })
                .collect();
            assert_eq!(dfs.len(), 1);
        }
    }

    #[test]
    fn an_hrw_tie_goes_to_the_lowest_address() {
        let pes = vec![ip("192.0.2.1"), ip("192.0.2.2"), ip("192.0.2.3")];
        assert_eq!(highest(&pes, |_| 5), ip("192.0.2.1"));
        assert_eq!(
            highest(&pes, |a| if *a == ip("192.0.2.1") { 1 } else { 5 }),
            ip("192.0.2.2")
        );
    }

    #[test]
    fn hrw_is_used_only_when_every_pe_asks_for_it() {
        use DfAlgorithm::{Hrw, Modulo};
        let a = ip("192.0.2.1");
        let b = ip("192.0.2.9");
        assert_eq!(effective(Hrw, a, [(b, Some(Hrw))]), Hrw);
        assert_eq!(effective(Hrw, a, []), Hrw);
        assert_eq!(effective(Hrw, a, [(b, None)]), Modulo);
        assert_eq!(effective(Hrw, a, [(b, Some(Modulo))]), Modulo);
        assert_eq!(effective(Modulo, a, [(b, Some(Hrw))]), Modulo);
        assert_eq!(effective(Hrw, a, [(ip("2001:db8::1"), Some(Hrw))]), Modulo);
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
