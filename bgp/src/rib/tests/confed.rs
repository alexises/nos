use super::*;

/// RFC 5065: member AS 65101 of confederation 65100.
fn confed_rib() -> BgpRib {
    let mut rib = new_rib(65101);
    rib.set_confederation(Some(65100));
    rib
}

fn register_confed_peer(rib: &mut BgpRib, peer: IpAddr) -> mpsc::Receiver<OutboundUpdate> {
    rib.set_peer_confed(peer, true);
    register_peer(rib, peer, false, addr("10.0.0.254"))
}

fn confed_update(nlri: &str, confed: &[u32], seq: &[u32], next_hop: &str) -> UpdateMessage {
    let mut u = ebgp_update(vec![nlri], seq.to_vec(), next_hop);
    let path = &mut u.attributes.as_mut().unwrap().as_path;
    for &asn in confed.iter().rev() {
        path.prepend_confed_seq(asn);
    }
    u
}

#[test]
fn confed_send_rules_per_peer_kind() {
    let mut rib = confed_rib();
    let mut confed = register_confed_peer(&mut rib, addr("10.0.0.2"));
    let mut external = register_peer(&mut rib, addr("10.0.0.3"), false, addr("10.0.0.254"));
    let mut internal = register_peer(&mut rib, addr("10.0.0.4"), true, addr("10.0.0.254"));
    let mut u = ebgp_update(vec!["198.51.100.0/24"], vec![65003], "192.0.2.5");
    u.attributes.as_mut().unwrap().med = Some(50);
    rib.handle_update(
        addr("10.0.0.5"),
        false,
        v4("5.5.5.5"),
        &u,
        &accept_all_policy(),
    );

    let c = announced(&mut confed, "198.51.100.0/24").unwrap();
    assert_eq!(format!("{:?}", c.as_path), "[(65101), 65003]");
    assert_eq!(c.next_hop, addr("192.0.2.5"), "next hop kept");
    assert_eq!((c.med, c.local_pref), (Some(50), Some(DEFAULT_LOCAL_PREF)));

    let e = announced(&mut external, "198.51.100.0/24").unwrap();
    assert_eq!(e.as_path, vec![65100, 65003], "identifier only");
    assert_eq!(
        (e.next_hop, e.med, e.local_pref),
        (addr("10.0.0.254"), None, None)
    );

    let i = announced(&mut internal, "198.51.100.0/24").unwrap();
    assert_eq!(i.as_path, vec![65003]);

    // A route from the confed peer: stripped toward the external peer,
    // and sent to the internal one (it is not an iBGP-learned route).
    let u = confed_update("198.51.101.0/24", &[65102], &[65004], "192.0.2.2");
    rib.handle_update(
        addr("10.0.0.2"),
        false,
        v4("2.2.2.2"),
        &u,
        &accept_all_policy(),
    );
    let e = announced(&mut external, "198.51.101.0/24").unwrap();
    assert_eq!(e.as_path, vec![65100, 65004]);
    let i = announced(&mut internal, "198.51.101.0/24").unwrap();
    assert_eq!(format!("{:?}", i.as_path), "[(65102), 65004]");
}

#[test]
fn confed_segments_from_outside_the_confederation_are_withdrawn() {
    for mut rib in [confed_rib(), new_rib(65101)] {
        let from = addr("10.0.0.3");
        let u = ebgp_update(vec!["198.51.100.0/24"], vec![65003], "192.0.2.3");
        rib.handle_update(from, false, v4("3.3.3.3"), &u, &accept_all_policy());
        assert!(rib.loc_rib.contains_key(&prefix("198.51.100.0/24")));
        let bad = confed_update("198.51.100.0/24", &[65109], &[65003], "192.0.2.3");
        rib.handle_update(from, false, v4("3.3.3.3"), &bad, &accept_all_policy());
        assert!(!rib.loc_rib.contains_key(&prefix("198.51.100.0/24")));
    }
}

#[test]
fn confed_loop_detection() {
    let mut rib = confed_rib();
    // The identifier in a plain segment, from an external peer.
    let u = ebgp_update(vec!["198.51.100.0/24"], vec![65003, 65100], "192.0.2.3");
    rib.handle_update(
        addr("10.0.0.3"),
        false,
        v4("3.3.3.3"),
        &u,
        &accept_all_policy(),
    );
    // Our member AS in a confed segment, from a confed peer.
    rib.set_peer_confed(addr("10.0.0.2"), true);
    let u = confed_update("198.51.101.0/24", &[65102, 65101], &[65003], "192.0.2.2");
    rib.handle_update(
        addr("10.0.0.2"),
        false,
        v4("2.2.2.2"),
        &u,
        &accept_all_policy(),
    );
    assert!(rib.loc_rib.is_empty());
    // Our member AS in a plain segment is someone else's AS, not a loop.
    let u = ebgp_update(vec!["198.51.102.0/24"], vec![65003, 65101], "192.0.2.3");
    rib.handle_update(
        addr("10.0.0.3"),
        false,
        v4("3.3.3.3"),
        &u,
        &accept_all_policy(),
    );
    assert_eq!(rib.loc_rib.len(), 1);
}

/// Vendor `local-as`: `[L, G]` (`[L]` with replace-as) toward the
/// local-as peer, `[G]` toward everyone else.
#[test]
fn local_as_outbound_paths() {
    for (confed, replace_as, want) in [
        (false, false, vec![65009, 65000]),
        (false, true, vec![65009]),
        (true, false, vec![65009, 65100]),
    ] {
        let mut rib = new_rib(65000);
        if confed {
            rib.set_confederation(Some(65100));
        }
        rib.set_peer_local_as(addr("10.0.0.1"), Some(local_as(65009, false, replace_as)));
        let mut l = register_peer(&mut rib, addr("10.0.0.1"), false, addr("10.0.0.254"));
        let mut other = register_peer(&mut rib, addr("10.0.0.2"), false, addr("10.0.0.254"));
        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));
        assert_eq!(announced(&mut l, "192.168.1.0/24").unwrap().as_path, want);
        let g = if confed { 65100 } else { 65000 };
        assert_eq!(
            announced(&mut other, "192.168.1.0/24").unwrap().as_path,
            vec![g]
        );
    }
}

/// Inbound: L is prepended (unless no-prepend), seen by the import
/// policy, and other peers get `[G, L, peer]`.
#[test]
fn local_as_inbound_prepend_and_policy() {
    let p = "198.51.100.0/24";
    let mut rib = new_rib(65000);
    let mut other = register_peer(&mut rib, addr("10.0.0.2"), false, addr("10.0.0.254"));
    rib.set_peer_local_as(addr("10.0.0.1"), Some(local_as(65009, false, false)));
    let only_l = nos_rpl::compile(
        "if this.bgp.as_path.contains(65009):\n    accept\nreject\n",
        &nos_rpl::Symbols::EMPTY,
    )
    .unwrap();
    let u = ebgp_update(vec![p], vec![65001], "192.0.2.1");
    rib.handle_update(addr("10.0.0.1"), false, v4("1.1.1.1"), &u, &only_l);
    assert_eq!(rib.loc_rib[&prefix(p)].as_path.flat(), vec![65009, 65001]);
    assert_eq!(
        announced(&mut other, p).unwrap().as_path,
        vec![65000, 65009, 65001]
    );

    rib.set_peer_local_as(addr("10.0.0.1"), Some(local_as(65009, true, false)));
    rib.handle_update(
        addr("10.0.0.1"),
        false,
        v4("1.1.1.1"),
        &u,
        &accept_all_policy(),
    );
    assert_eq!(rib.loc_rib[&prefix(p)].as_path.flat(), vec![65001]);
}

/// L is a loop on the local-as peer's routes only.
#[test]
fn local_as_loop_detection_is_per_peer() {
    let mut rib = new_rib(65000);
    rib.set_peer_local_as(addr("10.0.0.1"), Some(local_as(65009, false, false)));
    let looped = ebgp_update(vec!["198.51.100.0/24"], vec![65001, 65009], "192.0.2.1");
    rib.handle_update(
        addr("10.0.0.1"),
        false,
        v4("1.1.1.1"),
        &looped,
        &accept_all_policy(),
    );
    assert!(rib.loc_rib.is_empty());
    let other = ebgp_update(vec!["198.51.100.0/24"], vec![65002, 65009], "192.0.2.2");
    rib.handle_update(
        addr("10.0.0.2"),
        false,
        v4("2.2.2.2"),
        &other,
        &accept_all_policy(),
    );
    assert_eq!(rib.loc_rib.len(), 1);
}

#[test]
fn confed_step_six_external_then_confed_then_internal() {
    let mut rib = confed_rib();
    rib.set_peer_confed(addr("10.0.0.2"), true);
    let p = "198.51.100.0/24";
    // Same length once confed segments are ignored, same neighbour AS.
    let internal = ebgp_update(vec![p], vec![65003], "192.0.2.4");
    let confed = confed_update(p, &[65102], &[65003], "192.0.2.2");
    let external = ebgp_update(vec![p], vec![65003], "192.0.2.3");
    rib.handle_update(
        addr("10.0.0.4"),
        true,
        v4("4.4.4.4"),
        &internal,
        &accept_all_policy(),
    );
    rib.handle_update(
        addr("10.0.0.2"),
        false,
        v4("2.2.2.2"),
        &confed,
        &accept_all_policy(),
    );
    rib.handle_update(
        addr("10.0.0.3"),
        false,
        v4("3.3.3.3"),
        &external,
        &accept_all_policy(),
    );
    let best = |rib: &BgpRib| rib.loc_rib[&prefix(p)].origin;
    assert_eq!(best(&rib), RouteOrigin::Peer(addr("10.0.0.3")));
    rib.peer_disconnected(addr("10.0.0.3"), Disconnect::Transport);
    assert_eq!(best(&rib), RouteOrigin::Peer(addr("10.0.0.2")));
}

#[test]
fn as_set_counts_as_one_hop() {
    let mut rib = new_rib(65001);
    let p = "198.51.100.0/24";
    let mut set = ebgp_update(vec![p], vec![65003], "192.0.2.2");
    let path = &mut set.attributes.as_mut().unwrap().as_path;
    let mut with_set = AsPath::from(vec![65003]);
    with_set.push_segment(crate::as_path::SegKind::Set, &[1, 2, 3]);
    *path = with_set;
    let seq = ebgp_update(vec![p], vec![65004, 65005, 65006], "192.0.2.3");
    rib.handle_update(
        addr("10.0.0.2"),
        false,
        v4("2.2.2.2"),
        &set,
        &accept_all_policy(),
    );
    rib.handle_update(
        addr("10.0.0.3"),
        false,
        v4("3.3.3.3"),
        &seq,
        &accept_all_policy(),
    );
    assert_eq!(
        rib.loc_rib[&prefix(p)].origin,
        RouteOrigin::Peer(addr("10.0.0.2"))
    );
}

#[test]
fn rpl_prepend_on_a_confed_path_joins_the_sequence() {
    let mut rib = confed_rib();
    let (tx, mut rx) = test_channel();
    rib.peer_established(
        addr("10.0.0.4"),
        true,
        Some(addr("10.0.0.254")),
        all_afs(),
        false,
        None,
        false,
        false,
        HashSet::new(),
        Arc::new(
            nos_rpl::compile(
                "this.bgp.as_path.prepend(64999, 2)\naccept\n",
                &nos_rpl::Symbols::EMPTY,
            )
            .unwrap(),
        ),
        tx,
    );
    rib.set_peer_confed(addr("10.0.0.2"), true);
    let u = confed_update("198.51.100.0/24", &[65102], &[65003], "192.0.2.2");
    rib.handle_update(
        addr("10.0.0.2"),
        false,
        v4("2.2.2.2"),
        &u,
        &accept_all_policy(),
    );
    let adv = announced(&mut rx, "198.51.100.0/24").unwrap();
    assert_eq!(
        format!("{:?}", adv.as_path),
        "[64999, 64999, (65102), 65003]"
    );
}
