//! RFC 8326 on EVPN (#874): `LOCAL_PREF` set on learn, applied at push time.

use super::*;
use crate::message::COMMUNITY_GRACEFUL_SHUTDOWN as GS;
use crate::rib::GsKnobs;

const MAC: [u8; 6] = [0, 0, 0, 0, 0, 1];

fn rd(n: u8) -> [u8; 8] {
    [0, 0, 0xfd, 0xe8, 0, 0, 0, n]
}

/// Copies share one ESI (a multi-homed MAC, so every PE holds it): on
/// different ESIs MAC mobility alone picks the PE (`type2_on`).
fn type2(rd_n: u8) -> EvpnNlri {
    type2_on(rd_n, [7; 10])
}

fn type2_on(rd_n: u8, esi: [u8; 10]) -> EvpnNlri {
    EvpnNlri::MacIp {
        rd: rd(rd_n),
        esi,
        tag: 0,
        mac: MAC,
        ip: None,
        labels: vec![10100],
    }
}

fn type5(rd_n: u8, label: u32) -> EvpnNlri {
    EvpnNlri::IpPrefix {
        rd: rd(rd_n),
        esi: [0; 10],
        tag: 0,
        prefix: prefix("10.9.0.0/24"),
        gateway: addr("0.0.0.0"),
        label,
    }
}

/// Peer `10.0.0.<n>` (eBGP unless `ibgp`) announces `nlri` with next hop
/// `192.0.2.<n>`, tagged `GRACEFUL_SHUTDOWN` or not, with MAC-mobility
/// sequence `seq` when given.
fn feed(rib: &mut BgpRib, n: u8, ibgp: bool, tag: bool, nlri: EvpnNlri, seq: Option<u32>) {
    let peer = format!("10.0.0.{n}");
    let mut u = evpn_reach(vec![nlri], vec![65001]);
    let a = u.attributes.as_mut().unwrap();
    if tag {
        a.communities = vec![GS];
    }
    if let Some(s) = seq {
        a.extended_communities
            .push(nos_proto::evpn_id::mac_mobility_ext(s, false));
    }
    u.mp_reach[0].next_hop = addr(&format!("192.0.2.{n}"));
    rib.handle_update(addr(&peer), ibgp, v4(&peer), &u, &deny_all_policy());
}

fn rib_with(n: u8) -> BgpRib {
    let mut rib = new_rib(65000);
    for i in 1..=n {
        let _rx = register_peer(
            &mut rib,
            addr(&format!("10.0.0.{i}")),
            false,
            addr("10.0.0.254"),
        );
    }
    rib
}

fn winners(rib: &BgpRib) -> Vec<IpAddr> {
    let mut v: Vec<_> = rib
        .evpn_push_snapshot()
        .values()
        .map(|r| r.next_hop)
        .collect();
    v.sort();
    v
}

fn knob(rib: &mut BgpRib, peer: u8, send: bool, receive_off: bool) {
    rib.set_graceful_shutdown(HashMap::from([(
        addr(&format!("10.0.0.{peer}")),
        GsKnobs { send, receive_off },
    )]));
}

fn stored(rib: &BgpRib) -> (u32, Vec<u32>) {
    let r = &rib.evpn_routes()[0].2;
    (r.local_pref, r.communities.clone())
}

#[test]
fn type2_prefers_the_untagged_pe_whatever_the_vtep() {
    let mut rib = rib_with(2);
    feed(&mut rib, 1, false, true, type2(1), None); // lower VTEP, tagged
    assert_eq!(winners(&rib), [addr("192.0.2.1")], "tagged alone stays");
    feed(&mut rib, 2, false, false, type2(2), None);
    assert_eq!(winners(&rib), [addr("192.0.2.2")]);
}

#[test]
fn type2_equal_local_pref_keeps_the_lowest_vtep() {
    for tag in [true, false] {
        let mut rib = rib_with(2);
        for i in [2, 1] {
            feed(&mut rib, i, false, tag, type2(i), None);
        }
        assert_eq!(winners(&rib), [addr("192.0.2.1")], "tag={tag}");
    }
}

#[test]
fn mac_mobility_decides_before_local_pref() {
    let mut rib = rib_with(2);
    feed(&mut rib, 1, false, false, type2_on(1, [1; 10]), Some(1));
    // Higher sequence wins the MAC, though tagged.
    feed(&mut rib, 2, false, true, type2_on(2, [2; 10]), Some(5));
    assert_eq!(winners(&rib), [addr("192.0.2.2")]);
}

#[test]
fn type5_tagged_copy_is_withheld_unless_alone() {
    let mut rib = rib_with(3);
    feed(&mut rib, 1, false, true, type5(1, 5000), None);
    assert_eq!(winners(&rib), [addr("192.0.2.1")], "lone tagged stays");
    feed(&mut rib, 2, false, false, type5(2, 5000), None);
    assert_eq!(winners(&rib), [addr("192.0.2.2")]);
    feed(&mut rib, 3, false, false, type5(3, 5000), None);
    assert_eq!(winners(&rib), [addr("192.0.2.2"), addr("192.0.2.3")]);
}

#[test]
fn type5_groups_by_label_so_two_vrfs_never_demote_each_other() {
    let mut rib = rib_with(2);
    feed(&mut rib, 1, false, true, type5(1, 5000), None);
    feed(&mut rib, 2, false, false, type5(2, 6000), None);
    assert_eq!(winners(&rib), [addr("192.0.2.1"), addr("192.0.2.2")]);
}

#[test]
fn types_1_3_4_are_never_demoted() {
    let mut rib = rib_with(1);
    let nlris = [
        EvpnNlri::EthernetAd {
            rd: rd(1),
            esi: [1; 10],
            tag: 0,
            label: 7,
        },
        EvpnNlri::InclusiveMulticast {
            rd: rd(1),
            tag: 0,
            origin: addr("192.0.2.1"),
        },
        EvpnNlri::EthernetSegment {
            rd: rd(1),
            esi: [1; 10],
            origin: addr("192.0.2.1"),
        },
    ];
    for n in nlris {
        feed(&mut rib, 1, false, true, n, None);
    }
    assert_eq!(rib.evpn_push_snapshot().len(), 3);
}

#[test]
fn stored_local_pref_and_communities_follow_the_knobs() {
    let mut rib = rib_with(1);
    feed(&mut rib, 1, false, true, type2(1), None);
    assert_eq!(stored(&rib), (0, vec![GS]), "tagged, receiver on");
    knob(&mut rib, 1, false, true);
    feed(&mut rib, 1, false, true, type2(1), None);
    assert_eq!(stored(&rib), (100, vec![GS]), "receive off keeps 100");
    knob(&mut rib, 1, true, false);
    feed(&mut rib, 1, false, false, type2(1), None);
    assert_eq!(stored(&rib), (0, vec![GS]), "sender tags inbound");
}

#[test]
fn ibgp_is_untouched_by_the_knobs() {
    let mut rib = rib_with(1);
    knob(&mut rib, 1, true, false);
    feed(&mut rib, 1, true, true, type2(1), None);
    assert_eq!(stored(&rib), (100, vec![GS]));
}

#[test]
fn confed_external_peer_is_untouched() {
    let mut rib = new_rib(65101);
    rib.set_confederation(Some(65100));
    rib.set_peer_confed(addr("10.0.0.1"), true);
    let _rx = register_peer(&mut rib, addr("10.0.0.1"), false, addr("10.0.0.254"));
    knob(&mut rib, 1, true, false);
    feed(&mut rib, 1, false, true, type2(1), None);
    assert_eq!(stored(&rib), (100, vec![GS]));
}

#[test]
fn import_policy_reject_still_wins_over_a_demotion() {
    let mut rib = rib_with(1);
    let reject = Arc::new(nos_rpl::compile("reject\n", &nos_rpl::Symbols::EMPTY).unwrap());
    rib.set_peer_evpn_import_policy(addr("10.0.0.1"), Some(reject), false);
    feed(&mut rib, 1, false, true, type2(1), None);
    assert!(rib.evpn_push_snapshot().is_empty());
}

#[test]
fn gs_constant_matches_the_shared_name_table() {
    assert_eq!(
        nos_proto::bgp::community_name(GS),
        Some("graceful-shutdown")
    );
}
