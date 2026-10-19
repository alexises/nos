use super::*;

/// Receives one EVPN UPDATE (RT 65000:10000) from `10.0.0.1` into a rib whose
/// peer has `script` as its EVPN import policy; returns the rib.
fn evpn_import(script: Option<&str>, nlri: EvpnNlri) -> BgpRib {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    rib.set_peer_evpn_import_policy(
        peer,
        script.map(|s| Arc::new(nos_rpl::compile(s, &nos_rpl::Symbols::EMPTY).unwrap())),
        false,
    );
    rib.handle_update(
        peer,
        false,
        v4("192.0.2.1"),
        &evpn_reach(vec![nlri], vec![65001]),
        &deny_all_policy(),
    );
    rib
}

fn rt_script(accept_rt: bool) -> String {
    let rt = (65000u64 << 32) | 10_000;
    let (hit, miss) = if accept_rt {
        ("accept", "reject")
    } else {
        ("reject", "accept")
    };
    format!("if this.bgp.extended_communities.contains(0:2:{rt}):\n    {hit}\nelse:\n    {miss}\n")
}

#[test]
fn accepts_and_rejects_by_route_target() {
    assert_eq!(
        evpn_import(Some(&rt_script(true)), evpn_nlri(1))
            .evpn_push_snapshot()
            .len(),
        1
    );
    assert!(evpn_import(Some(&rt_script(false)), evpn_nlri(1))
        .evpn_push_snapshot()
        .is_empty());
}

#[test]
fn unset_policy_accepts_everything() {
    assert_eq!(
        evpn_import(None, evpn_nlri(1)).evpn_push_snapshot().len(),
        1
    );
}

#[test]
fn ethernet_segment_routes_bypass_the_policy() {
    let nlri = EvpnNlri::EthernetSegment {
        rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
        esi: [1; 10],
        origin: addr("192.0.2.1"),
    };
    assert_eq!(
        evpn_import(Some("reject\n"), nlri)
            .evpn_push_snapshot()
            .len(),
        1
    );
}

#[test]
fn rejected_type2_creates_no_mobility_candidate() {
    let held = |rib: &BgpRib| {
        rib.mac_mobility
            .holds(10_000, [0xaa, 0, 0, 0, 0, 1], addr("192.0.2.1"), [0; 10])
    };
    assert!(held(&evpn_import(None, evpn_nlri(1))));
    assert!(!held(&evpn_import(Some("reject\n"), evpn_nlri(1))));
}

#[test]
fn changing_the_policy_purges_stored_routes() {
    let mut rib = evpn_import(None, evpn_nlri(1));
    assert_eq!(rib.evpn_push_snapshot().len(), 1);
    let reject = Arc::new(nos_rpl::compile("reject\n", &nos_rpl::Symbols::EMPTY).unwrap());
    rib.set_peer_evpn_import_policy(addr("10.0.0.1"), Some(reject), false);
    assert!(rib.evpn_push_snapshot().is_empty());
}
