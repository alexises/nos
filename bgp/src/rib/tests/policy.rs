use super::*;

#[test]
fn import_policy_reject_prevents_route_from_being_learned() {
    let mut rib = new_rib(65000);
    let source = addr("10.0.0.1");
    let observer = addr("10.0.0.2");
    let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
    let mut observer_rx = register_peer(&mut rib, observer, false, addr("10.0.0.253"));

    rib.handle_update(
        source,
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
        &deny_all_policy(),
    );

    assert_eq!(recv_all(&mut observer_rx), []);
}

#[test]
fn import_policy_can_set_local_pref() {
    let mut rib = new_rib(65000);
    let source = addr("10.0.0.1");
    let observer = addr("10.0.0.2");
    // Source is eBGP-learned, observer is iBGP — LOCAL_PREF is only ever
    // forwarded toward an iBGP peer, and standard split-horizon only
    // suppresses an iBGP-learned route being reflected to another iBGP
    // peer, so this combination exercises the mutation without either
    // rule getting in the way.
    let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
    let mut observer_rx = register_peer(&mut rib, observer, true, addr("10.0.0.253"));

    let policy = nos_rpl::compile(
        "set this.bgp.local_pref = 500\naccept\n",
        &nos_rpl::Symbols::EMPTY,
    )
    .unwrap();
    rib.handle_update(
        source,
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![], "10.0.0.1"),
        &policy,
    );

    let updates = recv_all(&mut observer_rx);
    let adv = updates
        .into_iter()
        .find_map(|u| match u {
            OutboundUpdate::Announce(a) if a.prefix == prefix("1.2.3.0/24") => Some(a),
            _ => None,
        })
        .expect("expected an announcement for 1.2.3.0/24");
    assert_eq!(adv.local_pref, Some(500));
}

#[test]
fn import_policy_can_add_community() {
    let mut rib = new_rib(65000);
    let source = addr("10.0.0.1");
    let observer = addr("10.0.0.2");
    let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
    let mut observer_rx = register_peer(&mut rib, observer, false, addr("10.0.0.253"));

    let policy = nos_rpl::compile(
        "this.bgp.communities.add(65000:100)\naccept\n",
        &nos_rpl::Symbols::EMPTY,
    )
    .unwrap();
    rib.handle_update(
        source,
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![], "10.0.0.1"),
        &policy,
    );

    let updates = recv_all(&mut observer_rx);
    let adv = updates
        .into_iter()
        .find_map(|u| match u {
            OutboundUpdate::Announce(a) if a.prefix == prefix("1.2.3.0/24") => Some(a),
            _ => None,
        })
        .expect("expected an announcement for 1.2.3.0/24");
    assert_eq!(adv.communities, vec![(65000 << 16) | 100]);
}

#[test]
fn atomic_aggregate_and_aggregator_survive_transit() {
    let mut rib = new_rib(65000);
    let source = addr("10.0.0.1");
    let observer = addr("10.0.0.2");
    let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
    let mut observer_rx = register_peer(&mut rib, observer, false, addr("10.0.0.253"));

    let agg = message::Aggregator {
        asn: 4_200_000_001,
        router_id: v4("192.0.2.9"),
    };
    let mut update = ebgp_update(vec!["1.2.3.0/24"], vec![], "10.0.0.1");
    let attrs = update.attributes.as_mut().unwrap();
    attrs.atomic_aggregate = true;
    attrs.aggregator = Some(agg);
    rib.handle_update(
        source,
        false,
        v4("192.0.2.1"),
        &update,
        &nos_rpl::ACCEPT_ALL,
    );

    let adv = recv_all(&mut observer_rx)
        .into_iter()
        .find_map(|u| match u {
            OutboundUpdate::Announce(a) if a.prefix == prefix("1.2.3.0/24") => Some(a),
            _ => None,
        })
        .expect("expected an announcement for 1.2.3.0/24");
    assert!(adv.atomic_aggregate);
    assert_eq!(adv.aggregator, Some(agg));
}

#[test]
fn export_policy_can_remove_community_for_one_peer() {
    let mut rib = new_rib(65000);
    let source = addr("10.0.0.1");
    let allowed = addr("10.0.0.2");
    let stripped = addr("10.0.0.3");
    let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
    let mut allowed_rx = register_peer(&mut rib, allowed, false, addr("10.0.0.253"));

    let (tx, mut stripped_rx) = test_channel();
    rib.peer_established(
        stripped,
        false,
        Some(addr("10.0.0.252")),
        all_afs(),
        false,
        None,
        false,
        false,
        HashSet::new(),
        Arc::new(
            nos_rpl::compile(
                "this.bgp.communities.clear()\naccept\n",
                &nos_rpl::Symbols::EMPTY,
            )
            .unwrap(),
        ),
        tx,
    );

    let import_policy = nos_rpl::compile(
        "this.bgp.communities.add(65000:100)\naccept\n",
        &nos_rpl::Symbols::EMPTY,
    )
    .unwrap();
    rib.handle_update(
        source,
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
        &import_policy,
    );

    let find_adv = |rx: &mut mpsc::Receiver<OutboundUpdate>| {
        recv_all(rx)
            .into_iter()
            .find_map(|u| match u {
                OutboundUpdate::Announce(a) if a.prefix == prefix("1.2.3.0/24") => Some(a),
                _ => None,
            })
            .expect("expected an announcement for 1.2.3.0/24")
    };
    assert_eq!(
        find_adv(&mut allowed_rx).communities,
        vec![(65000 << 16) | 100]
    );
    assert_eq!(find_adv(&mut stripped_rx).communities, [] as [u32; 0]);
}

/// The `communities` phase of `tools/verify-bgp.sh`, in miniature: a
/// *locally redistributed* route (no wire attributes of its own) tagged
/// by the destination peer-group's own *export* policy. Distinct from
/// `import_policy_can_add_community` (peer-learned, import side) and
/// `export_policy_can_remove_community_for_one_peer` (peer-learned,
/// export side, removal).
#[test]
fn export_policy_can_add_community_to_a_redistributed_route() {
    let mut rib = new_rib(65001);
    let peer = addr("10.0.0.1");
    let (tx, mut rx) = test_channel();
    rib.peer_established(
        peer,
        false,
        Some(addr("10.0.0.254")),
        all_afs(),
        false,
        None,
        false,
        false,
        HashSet::new(),
        Arc::new(
            nos_rpl::compile(
                "this.bgp.communities.add(65001:100)\naccept\n",
                &nos_rpl::Symbols::EMPTY,
            )
            .unwrap(),
        ),
        tx,
    );

    rib.apply_redistribute_update(full_update(vec![("198.51.100.0/24", "10.9.9.9")]));

    let adv = recv_all(&mut rx)
        .into_iter()
        .find_map(|u| match u {
            OutboundUpdate::Announce(a) if a.prefix == prefix("198.51.100.0/24") => Some(a),
            _ => None,
        })
        .expect("expected an announcement for 198.51.100.0/24");
    assert_eq!(adv.communities, vec![(65001 << 16) | 100]);
}

#[test]
fn export_policy_prepend_lands_behind_our_own_asn() {
    let mut rib = new_rib(65001);
    let peer = addr("10.0.0.1");
    let (tx, mut rx) = test_channel();
    rib.peer_established(
        peer,
        false,
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

    rib.apply_redistribute_update(full_update(vec![("198.51.100.0/24", "10.9.9.9")]));

    let adv = recv_all(&mut rx)
        .into_iter()
        .find_map(|u| match u {
            OutboundUpdate::Announce(a) if a.prefix == prefix("198.51.100.0/24") => Some(a),
            _ => None,
        })
        .expect("expected an announcement for 198.51.100.0/24");
    assert_eq!(adv.as_path, vec![65001, 64999, 64999]);
}

#[test]
fn import_policy_matches_peer_as_and_adds_to_local_pref() {
    let mut rib = new_rib(65000);
    let source = addr("10.0.0.1");
    let observer = addr("10.0.0.2");
    let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
    let mut observer_rx = register_peer(&mut rib, observer, true, addr("10.0.0.253"));
    rib.set_peer_asn(source, 65099);

    let policy = nos_rpl::compile(
        "if this.bgp.peer_as == 65099:\n    set this.bgp.local_pref += 400\n    accept\nelse:\n    reject\n",
        &nos_rpl::Symbols::EMPTY,
    )
    .unwrap();
    rib.handle_update(
        source,
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![], "10.0.0.1"),
        &policy,
    );

    let adv = recv_all(&mut observer_rx)
        .into_iter()
        .find_map(|u| match u {
            OutboundUpdate::Announce(a) if a.prefix == prefix("1.2.3.0/24") => Some(a),
            _ => None,
        })
        .expect("expected an announcement for 1.2.3.0/24");
    assert_eq!(adv.local_pref, Some(500));
}

#[test]
fn export_policy_can_set_next_hop_and_origin() {
    let mut rib = new_rib(65001);
    let peer = addr("10.0.0.1");
    let (tx, mut rx) = test_channel();
    rib.peer_established(
        peer,
        false,
        Some(addr("10.0.0.254")),
        all_afs(),
        false,
        None,
        false,
        false,
        HashSet::new(),
        Arc::new(
            nos_rpl::compile(
                "set this.bgp.next_hop = 192.0.2.99\nset this.bgp.origin = origin.incomplete\naccept\n",
                &nos_rpl::Symbols::EMPTY,
            )
            .unwrap(),
        ),
        tx,
    );

    rib.apply_redistribute_update(full_update(vec![("198.51.100.0/24", "10.9.9.9")]));

    let adv = recv_all(&mut rx)
        .into_iter()
        .find_map(|u| match u {
            OutboundUpdate::Announce(a) if a.prefix == prefix("198.51.100.0/24") => Some(a),
            _ => None,
        })
        .expect("expected an announcement for 198.51.100.0/24");
    assert_eq!(adv.next_hop, addr("192.0.2.99"));
    assert_eq!(adv.origin, message::Origin::Incomplete);
}

#[test]
fn export_policy_reject_suppresses_advertisement_to_one_peer() {
    let mut rib = new_rib(65000);
    let source = addr("10.0.0.1");
    let allowed = addr("10.0.0.2");
    let blocked = addr("10.0.0.3");
    let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
    let mut allowed_rx = register_peer(&mut rib, allowed, false, addr("10.0.0.253"));

    let (tx, mut blocked_rx) = test_channel();
    rib.peer_established(
        blocked,
        false,
        Some(addr("10.0.0.252")),
        all_afs(),
        false,
        None,
        false,
        false,
        HashSet::new(),
        deny_all_policy(),
        tx,
    );

    rib.handle_update(
        source,
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
        &accept_all_policy(),
    );

    assert_ne!(recv_all(&mut allowed_rx), []);
    assert_eq!(recv_all(&mut blocked_rx), []);
}

/// Sends one route with MED 999 from eBGP `source` and returns what
/// `dest` (eBGP or iBGP, with `export`) is sent for it.
fn med_toward(dest_is_ibgp: bool, export: &str) -> Option<u32> {
    let mut rib = new_rib(65000);
    let source = addr("10.0.0.1");
    let dest = addr("10.0.0.2");
    let _src_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
    let (tx, mut rx) = test_channel();
    rib.peer_established(
        dest,
        dest_is_ibgp,
        Some(addr("10.0.0.253")),
        all_afs(),
        false,
        None,
        false,
        false,
        HashSet::new(),
        Arc::new(nos_rpl::compile(export, &nos_rpl::Symbols::EMPTY).unwrap()),
        tx,
    );
    rib.handle_update(
        source,
        false,
        v4("192.0.2.1"),
        &update_with(
            "9.9.9.0/24",
            vec![65001],
            "10.0.0.1",
            message::Origin::Igp,
            Some(999),
        ),
        &nos_rpl::ACCEPT_ALL,
    );
    recv_all(&mut rx)
        .into_iter()
        .find_map(|u| match u {
            OutboundUpdate::Announce(a) => Some(a.med),
            _ => None,
        })
        .expect("expected an announcement")
}

#[test]
fn received_med_is_not_sent_to_ebgp_but_kept_toward_ibgp() {
    assert_eq!(med_toward(false, "accept\n"), None);
    assert_eq!(med_toward(true, "accept\n"), Some(999));
}

#[test]
fn received_med_is_passed_through_to_route_server_client() {
    let mut rib = new_rib(65000);
    let source = addr("10.0.0.1");
    let _src_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
    let mut rs_rx = register_peer_full(
        &mut rib,
        addr("10.0.0.2"),
        false,
        addr("10.0.0.253"),
        false,
        true,
        HashSet::new(),
    );
    let mut rs_ap_rx = register_peer_full(
        &mut rib,
        addr("10.0.0.3"),
        false,
        addr("10.0.0.252"),
        false,
        true,
        HashSet::from([AddressFamily::Ipv4Unicast]),
    );
    rib.handle_update(
        source,
        false,
        v4("192.0.2.1"),
        &update_with(
            "9.9.9.0/24",
            vec![65001],
            "10.0.0.1",
            message::Origin::Igp,
            Some(999),
        ),
        &nos_rpl::ACCEPT_ALL,
    );
    let meds = |updates: Vec<OutboundUpdate>, add_path: bool| -> Vec<Option<u32>> {
        updates
            .into_iter()
            .filter_map(|u| match u {
                OutboundUpdate::Announce(a) if a.path_id.is_some() == add_path => Some(a.med),
                _ => None,
            })
            .collect()
    };
    // Single best path.
    assert_eq!(meds(recv_all(&mut rs_rx), false), vec![Some(999)]);
    // ADD-PATH per-source fan-out (propagate_add_path).
    let ap = meds(recv_all(&mut rs_ap_rx), true);
    assert_ne!(ap, []);
    assert!(ap.iter().all(|m| *m == Some(999)));
}

#[test]
fn export_policy_med_is_sent_to_ebgp() {
    assert_eq!(
        med_toward(false, "set this.bgp.med = 42\naccept\n"),
        Some(42)
    );
    // `+=` on an eBGP export starts from 0: the received MED is gone.
    assert_eq!(
        med_toward(false, "set this.bgp.med += 5\naccept\n"),
        Some(5)
    );
}

#[test]
fn redistributed_route_rejected_by_redistribute_policy_is_not_announced() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let mut rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    rib.set_redistribute_policy(deny_all_policy());

    rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

    assert_eq!(recv_all(&mut rx), vec![]);
}

/// Proves a redistribute-policy change takes effect promptly — the
/// current redistributed set is re-filtered when the policy itself
/// changes, not just on the next `RedistributeUpdate` from `nos-ribd`.
#[test]
fn redistribute_policy_change_retroactively_filters_existing_routes() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let mut rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));

    rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));
    let announced = recv_all(&mut rx);
    assert!(matches!(
        announced.as_slice(),
        [OutboundUpdate::Announce(a)] if a.prefix == prefix("192.168.1.0/24")
    ));

    rib.set_redistribute_policy(deny_all_policy());

    let updates = recv_all(&mut rx);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Withdraw(
            prefix("192.168.1.0/24"),
            false,
            None
        )]
    );
}

/// Re-applying an unchanged redistribute policy (the 10s reconcile tick
/// does it on every pass) must not re-announce anything (#134).
#[test]
fn reapplying_unchanged_redistribute_policy_sends_nothing() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let mut rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    rib.set_redistribute_policy(accept_all_policy());
    rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));
    assert_eq!(recv_all(&mut rx).len(), 1);

    rib.set_redistribute_policy(accept_all_policy());
    rib.set_redistribute_policy(accept_all_policy());

    assert_eq!(recv_all(&mut rx), vec![]);
}

/// #17: routes are validated on receipt and re-validated in place by
/// `set_vrps`; an import policy reading the state filters invalid ones,
/// and a state change alone is not a flap.
#[test]
fn rpki_validation_on_receipt_and_on_vrp_change() {
    use crate::rpki::{Vrp, VrpTable};
    use nos_rpl::ValidationState::{Invalid, NotFound, Valid};
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    rib.set_peer_damping(peer, Some(BgpDamping::default()));
    let vrps = |asn| {
        let mut t = VrpTable::default();
        t.announce(Vrp {
            prefix: prefix("1.2.0.0/16"),
            max_len: 24,
            asn,
        });
        Arc::new(t)
    };
    let state = |rib: &BgpRib, p| rib.adj_rib_in[&peer][&prefix(p)][0].1.validation_state;
    rib.set_vrps(vrps(65001));
    let reject_invalid = nos_rpl::compile(
        "if this.bgp.validation_state == rpki.invalid:\n    reject\naccept\n",
        &nos_rpl::Symbols::EMPTY,
    )
    .unwrap();
    let update = ebgp_update(vec!["1.2.3.0/24", "9.9.9.0/24"], vec![65001], "10.0.0.1");
    rib.handle_update(peer, false, v4("192.0.2.1"), &update, &reject_invalid);
    assert_eq!(state(&rib, "1.2.3.0/24"), Valid);
    assert_eq!(state(&rib, "9.9.9.0/24"), NotFound);

    rib.set_vrps(vrps(65002));
    assert_eq!(state(&rib, "1.2.3.0/24"), Invalid, "re-validated in place");
    // The peer re-sends it (a route refresh): now rejected.
    rib.handle_update(peer, false, v4("192.0.2.1"), &update, &reject_invalid);
    assert!(!rib.adj_rib_in[&peer].contains_key(&prefix("1.2.3.0/24")));

    // Accepted again with a changed state only: no change penalty.
    rib.set_vrps(vrps(65001));
    rib.handle_update(peer, false, v4("192.0.2.1"), &update, &nos_rpl::ACCEPT_ALL);
    rib.set_vrps(vrps(65002));
    rib.handle_update(peer, false, v4("192.0.2.1"), &update, &nos_rpl::ACCEPT_ALL);
    assert_eq!(state(&rib, "1.2.3.0/24"), Invalid);
    assert!(!rib.damping.is_suppressed(peer, &prefix("1.2.3.0/24")));

    // A redistributed route is validated against our own AS.
    rib.apply_redistribute_update(full_update(vec![("1.2.4.0/24", "10.0.0.9")]));
    assert_eq!(
        rib.redistributed[&prefix("1.2.4.0/24")].validation_state,
        Invalid
    );
    rib.set_vrps(vrps(65000));
    assert_eq!(
        rib.redistributed[&prefix("1.2.4.0/24")].validation_state,
        Valid
    );
}

fn rpki_vrps(asn: u32) -> Arc<crate::rpki::VrpTable> {
    let mut t = crate::rpki::VrpTable::default();
    t.announce(crate::rpki::Vrp {
        prefix: prefix("1.2.0.0/16"),
        max_len: 24,
        asn,
    });
    Arc::new(t)
}

/// #162 receive side: an opted-in iBGP peer's RFC 8097 community sets
/// the state while we have no VRPs; local data wins once we do; it is
/// always stripped, and ignored from eBGP.
#[test]
fn rpki_state_community_on_receipt() {
    use crate::rpki::community::encode;
    use nos_rpl::ValidationState::{Invalid, NotFound, Valid};
    let mut rib = new_rib(65000);
    let (ibgp, ebgp) = (addr("10.0.0.1"), addr("10.0.0.3"));
    rib.set_peer_rpki_state(ibgp, true);
    let _i = register_peer(&mut rib, ibgp, true, addr("10.0.0.254"));
    let _e = register_peer(&mut rib, ebgp, false, addr("10.0.0.254"));
    let reject_invalid = nos_rpl::compile(
        "if this.bgp.validation_state == rpki.invalid:\n    reject\naccept\n",
        &nos_rpl::Symbols::EMPTY,
    )
    .unwrap();
    let tagged = |nlri, state| {
        let mut u = ebgp_update(vec![nlri], vec![65001], "10.0.0.1");
        u.attributes.as_mut().unwrap().extended_communities = vec![RT, encode(state)];
        u
    };
    let learn = |rib: &mut BgpRib, from, ibgp, u: &UpdateMessage| {
        rib.handle_update(from, ibgp, v4("192.0.2.1"), u, &reject_invalid);
    };
    learn(&mut rib, ibgp, true, &tagged("1.2.3.0/24", Invalid));
    assert!(
        !rib.adj_rib_in[&ibgp].contains_key(&prefix("1.2.3.0/24")),
        "the import policy sees the signalled state"
    );
    learn(&mut rib, ibgp, true, &tagged("1.2.4.0/24", Valid));
    let held = |rib: &BgpRib, peer, p| rib.adj_rib_in[&peer][&prefix(p)][0].1.clone();
    let r = held(&rib, ibgp, "1.2.4.0/24");
    assert_eq!(r.validation_state, Valid);
    assert_eq!(r.extended_communities, vec![RT], "stripped");

    // Local data wins, and the signalled state is back once it's gone.
    rib.set_vrps(rpki_vrps(65002));
    assert_eq!(held(&rib, ibgp, "1.2.4.0/24").validation_state, Invalid);
    rib.set_vrps(Arc::default());
    assert_eq!(held(&rib, ibgp, "1.2.4.0/24").validation_state, Valid);

    // From eBGP: ignored and stripped.
    learn(&mut rib, ebgp, false, &tagged("1.2.5.0/24", Invalid));
    let r = held(&rib, ebgp, "1.2.5.0/24");
    assert_eq!(r.validation_state, NotFound);
    assert_eq!(r.extended_communities, vec![RT]);
}

/// #162 send side: exactly one RFC 8097 community, regenerated from our
/// own state, toward an opted-in iBGP peer only; non-transitive extended
/// communities never reach eBGP.
#[test]
fn rpki_state_community_on_advertisement() {
    use crate::rpki::community::encode;
    use nos_rpl::ValidationState::{Invalid, Valid};
    const OPAQUE_NT: u64 = 0x4003_0000_0000_0001;
    let mut rib = new_rib(65000);
    let (src, on, off, ebgp) = (
        addr("10.0.0.1"),
        addr("10.0.0.2"),
        addr("10.0.0.3"),
        addr("10.0.0.4"),
    );
    rib.set_peer_rpki_state(on, true);
    let _s = register_peer(&mut rib, src, false, addr("10.0.0.254"));
    let mut on_rx = register_peer(&mut rib, on, true, addr("10.0.0.254"));
    let mut off_rx = register_peer(&mut rib, off, true, addr("10.0.0.254"));
    let mut ebgp_rx = register_peer(&mut rib, ebgp, false, addr("10.0.0.254"));
    rib.set_vrps(rpki_vrps(65001));
    let mut u = ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1");
    u.attributes.as_mut().unwrap().extended_communities = vec![RT, OPAQUE_NT];
    // A stale copy added after receipt, by policy, is replaced too.
    let tag_stale = nos_rpl::compile(
        "this.bgp.extended_communities.add(67:0:2)\naccept\n",
        &nos_rpl::Symbols::EMPTY,
    )
    .unwrap();
    rib.handle_update(src, false, v4("192.0.2.1"), &u, &tag_stale);
    let ext = |rx: &mut mpsc::Receiver<OutboundUpdate>| {
        recv_all(rx)
            .into_iter()
            .filter_map(|u| match u {
                OutboundUpdate::Announce(a) => Some(a.extended_communities),
                _ => None,
            })
            .next_back()
            .expect("an announcement")
    };
    assert_eq!(ext(&mut on_rx), vec![RT, OPAQUE_NT, encode(Valid)]);
    assert_eq!(ext(&mut off_rx), vec![RT, OPAQUE_NT]);
    assert_eq!(ext(&mut ebgp_rx), vec![RT]);

    // A VRP change re-advertises the new state to iBGP.
    rib.set_vrps(rpki_vrps(65002));
    assert_eq!(ext(&mut on_rx), vec![RT, OPAQUE_NT, encode(Invalid)]);
}

const ALL_ROLES: [nos_proto::BgpRole; 5] =
    [Provider, RouteServer, RouteServerClient, Customer, Peer];

fn otc_update(otc: Option<u32>) -> UpdateMessage {
    let mut u = ebgp_update(vec!["198.51.100.0/24"], vec![65001], "192.0.2.1");
    u.attributes.as_mut().unwrap().otc = otc;
    u
}

/// RFC 9234 §5 ingress, every remote role x OTC absent/present/equal to
/// the peer's ASN; a session with no role is untouched.
#[test]
fn otc_ingress_per_remote_role() {
    let src = addr("10.0.0.1");
    for remote in ALL_ROLES {
        for otc in [None, Some(65001), Some(64999)] {
            let mut rib = new_rib(65000);
            rib.set_peer_asn(src, 65001);
            rib.set_peer_role(src, Some(remote.counterpart()));
            rib.handle_update(
                src,
                false,
                v4("1.1.1.1"),
                &otc_update(otc),
                &accept_all_policy(),
            );
            let got = rib.loc_rib.get(&prefix("198.51.100.0/24")).map(|r| r.otc);
            let want = match (remote, otc) {
                (Customer | RouteServerClient, Some(_)) => None,
                (Peer, Some(o)) if o != 65001 => None,
                (Provider | Peer | RouteServer, None) => Some(Some(65001)),
                (_, o) => Some(o),
            };
            assert_eq!(got, want, "{remote:?} otc={otc:?}");
        }
    }
    let mut rib = new_rib(65000);
    rib.set_peer_asn(src, 65001);
    rib.handle_update(
        src,
        false,
        v4("1.1.1.1"),
        &otc_update(Some(7)),
        &accept_all_policy(),
    );
    assert_eq!(rib.loc_rib[&prefix("198.51.100.0/24")].otc, Some(7));
}

/// A leaked re-announcement withdraws the earlier path.
#[test]
fn otc_leak_withdraws_earlier_path() {
    let src = addr("10.0.0.1");
    let mut rib = new_rib(65000);
    rib.set_peer_asn(src, 65001);
    rib.set_peer_role(src, Some(Provider)); // the peer is our Customer
    rib.handle_update(
        src,
        false,
        v4("1.1.1.1"),
        &otc_update(None),
        &accept_all_policy(),
    );
    assert!(rib.loc_rib.contains_key(&prefix("198.51.100.0/24")));
    rib.handle_update(
        src,
        false,
        v4("1.1.1.1"),
        &otc_update(Some(1)),
        &accept_all_policy(),
    );
    assert!(rib.loc_rib.is_empty());
}

/// RFC 9234 §5 egress, every destination role x OTC absent/present, with
/// `local-as` honoured; a destination with no role forwards unchanged.
#[test]
fn otc_egress_per_remote_role() {
    let src = addr("10.0.0.1");
    let dst = addr("10.0.0.2");
    for remote in ALL_ROLES.map(Some).into_iter().chain([None]) {
        for otc in [None, Some(65001)] {
            let mut rib = new_rib(65000);
            rib.set_peer_asn(src, 65001);
            register_peer(&mut rib, src, false, addr("10.0.0.9"));
            rib.set_peer_role(dst, remote.map(nos_proto::BgpRole::counterpart));
            rib.set_peer_local_as(dst, Some(local_as(65009, false, false)));
            let mut rx = register_peer(&mut rib, dst, false, addr("10.0.0.9"));
            rib.handle_update(
                src,
                false,
                v4("1.1.1.1"),
                &otc_update(otc),
                &accept_all_policy(),
            );
            let got = announced(&mut rx, "198.51.100.0/24").map(|a| a.otc);
            let want = match (remote, otc) {
                (Some(Customer | Peer | RouteServerClient), None) => Some(Some(65009)),
                (Some(Provider | Peer | RouteServer), Some(_)) => None,
                (_, o) => Some(o),
            };
            assert_eq!(got, want, "{remote:?} otc={otc:?}");
        }
    }
}

/// #500: `routes()` lists every Adj-RIB-In path and the redistributed route
/// with its validation state and the best flag.
#[test]
fn routes_lists_paths_local_routes_and_states() {
    use crate::rpki::{Vrp, VrpTable};
    use nos_proto::RpkiValidationState as S;
    let mut rib = new_rib(65000);
    let (p1, p2) = (addr("10.0.0.1"), addr("10.0.0.2"));
    let _rx1 = register_peer(&mut rib, p1, false, addr("10.0.0.254"));
    let _rx2 = register_peer(&mut rib, p2, false, addr("10.0.0.253"));
    let mut t = VrpTable::default();
    t.announce(Vrp {
        prefix: prefix("1.2.0.0/16"),
        max_len: 24,
        asn: 65001,
    });
    rib.set_vrps(Arc::new(t));
    let accept = &nos_rpl::ACCEPT_ALL;
    let u = |asn| ebgp_update(vec!["1.2.3.0/24"], vec![asn], "10.0.0.1");
    rib.handle_update(p1, false, v4("192.0.2.1"), &u(65001), accept);
    rib.handle_update(p2, false, v4("192.0.2.2"), &u(65099), accept);
    rib.apply_redistribute_update(full_update(vec![("9.9.9.0/24", "10.0.0.9")]));

    let routes = rib.routes();
    assert_eq!(routes.len(), 3);
    assert_eq!(routes[0].prefix, "1.2.3.0/24");
    assert_eq!(routes[0].peer, Some(p1));
    assert_eq!(routes[0].validation_state, S::Valid);
    assert_eq!(routes[0].origin_as, Some(65001));
    assert_eq!(routes[0].as_path, "65001");
    assert_eq!(routes[1].peer, Some(p2));
    assert_eq!(routes[1].validation_state, S::Invalid);
    assert_eq!(
        routes.iter().filter(|r| r.best).count(),
        2,
        "one best per prefix"
    );
    assert!(routes[2].peer.is_none() && routes[2].best);
    assert_eq!(routes[2].validation_state, S::NotFound);
    assert_eq!(routes[2].origin_as, Some(65000), "local route: our own AS");
}
