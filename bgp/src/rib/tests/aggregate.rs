use super::*;

fn agg_rib() -> (BgpRib, mpsc::UnboundedReceiver<OutboundUpdate>) {
    let mut rib = new_rib_with_identity(65000, v4("1.1.1.1"), v4("1.1.1.1"));
    rib.set_peer_asn(addr("10.0.0.1"), 65001);
    let _src = register_peer(&mut rib, addr("10.0.0.1"), false, addr("10.0.0.9"));
    let rx = register_peer(&mut rib, addr("10.0.0.2"), false, addr("10.0.0.9"));
    (rib, rx)
}

#[test]
fn aggregate_follows_its_contributors() {
    let (mut rib, mut rx) = agg_rib();
    rib.set_aggregates(vec![agg("198.51.0.0/16", false, false)]);
    assert!(
        !rib.loc_rib.contains_key(&prefix("198.51.0.0/16")),
        "no contributor"
    );

    learn(
        &mut rib,
        &ebgp_update(vec!["198.51.1.0/24"], vec![65001], "10.0.0.1"),
    );
    let a = rib.loc_rib[&prefix("198.51.0.0/16")].clone();
    assert_eq!(a.origin, RouteOrigin::Local);
    assert!(a.as_path.is_empty());
    assert_eq!(a.bgp_origin, message::Origin::Igp);
    assert!(a.atomic_aggregate, "the contributor's path was dropped");
    assert_eq!(
        a.aggregator,
        Some(message::Aggregator {
            asn: 65000,
            router_id: v4("1.1.1.1")
        })
    );
    assert_eq!(
        sent(&mut rx).0,
        [prefix("198.51.0.0/16"), prefix("198.51.1.0/24")]
    );

    // ORIGIN is the worst among the contributors.
    let mut incomplete = ebgp_update(vec!["198.51.2.0/24"], vec![65001], "10.0.0.1");
    incomplete.attributes.as_mut().unwrap().origin = message::Origin::Incomplete;
    learn(&mut rib, &incomplete);
    assert_eq!(
        rib.loc_rib[&prefix("198.51.0.0/16")].bgp_origin,
        message::Origin::Incomplete
    );

    learn(&mut rib, &withdraw("198.51.1.0/24"));
    assert!(
        rib.loc_rib.contains_key(&prefix("198.51.0.0/16")),
        "one left"
    );
    let _ = sent(&mut rx);
    learn(&mut rib, &withdraw("198.51.2.0/24"));
    assert!(!rib.loc_rib.contains_key(&prefix("198.51.0.0/16")));
    let (_, withdrawn) = sent(&mut rx);
    assert!(withdrawn.contains(&prefix("198.51.0.0/16")));
}

#[test]
fn local_contributor_alone_sets_no_atomic_aggregate() {
    let (mut rib, _rx) = agg_rib();
    rib.set_aggregates(vec![agg("198.51.0.0/16", false, false)]);
    rib.apply_redistribute_update(full_update(vec![("198.51.100.0/24", "10.0.0.254")]));
    assert!(!rib.loc_rib[&prefix("198.51.0.0/16")].atomic_aggregate);
    // Inherited from a contributor that carries it, with as-set too.
    rib.set_aggregates(vec![agg("198.51.0.0/16", true, false)]);
    let mut atomic = ebgp_update(vec!["198.51.1.0/24"], vec![65001], "10.0.0.1");
    atomic.attributes.as_mut().unwrap().atomic_aggregate = true;
    learn(&mut rib, &atomic);
    assert!(rib.loc_rib[&prefix("198.51.0.0/16")].atomic_aggregate);
}

#[test]
fn as_set_aggregate_keeps_the_contributors_asns() {
    let (mut rib, _rx) = agg_rib();
    rib.set_aggregates(vec![agg("198.51.0.0/16", true, false)]);
    rib.apply_redistribute_update(full_update(vec![("198.51.100.0/24", "10.0.0.254")]));
    learn(
        &mut rib,
        &ebgp_update(vec!["198.51.1.0/24"], vec![65001, 65005], "10.0.0.1"),
    );
    let a = &rib.loc_rib[&prefix("198.51.0.0/16")];
    assert_eq!(format!("{:?}", a.as_path), "[{65001, 65005}]");
    assert!(!a.atomic_aggregate);
}

#[test]
fn summary_only_suppresses_the_contributors_toward_peers_only() {
    let (mut rib, mut rx) = agg_rib();
    rib.set_aggregates(vec![agg("198.51.0.0/16", false, true)]);
    learn(
        &mut rib,
        &ebgp_update(vec!["198.51.1.0/24"], vec![65001], "10.0.0.1"),
    );
    assert_eq!(sent(&mut rx), (vec![prefix("198.51.0.0/16")], vec![]));
    assert!(
        rib.push_snapshot().1.contains_key(&prefix("198.51.1.0/24")),
        "still installed"
    );

    // A new peer and a route refresh get the aggregate alone too.
    let mut late = register_peer(&mut rib, addr("10.0.0.3"), false, addr("10.0.0.9"));
    rib.resend_all(addr("10.0.0.3"), AddressFamily::Ipv4Unicast, false);
    let (announced, _) = sent(&mut late);
    assert!(announced.iter().all(|p| *p == prefix("198.51.0.0/16")));

    rib.set_aggregates(vec![agg("198.51.0.0/16", false, false)]);
    assert_eq!(sent(&mut rx).0, [prefix("198.51.1.0/24")]);
    rib.set_aggregates(vec![agg("198.51.0.0/16", false, true)]);
    assert_eq!(sent(&mut rx).1, [prefix("198.51.1.0/24")]);
    rib.set_aggregates(vec![]);
    let (announced, withdrawn) = sent(&mut rx);
    assert_eq!(withdrawn, [prefix("198.51.0.0/16")]);
    assert_eq!(announced, [prefix("198.51.1.0/24")]);
}

#[test]
fn summary_only_withdraws_contributors_already_sent() {
    let (mut rib, mut rx) = agg_rib();
    learn(
        &mut rib,
        &ebgp_update(vec!["198.51.1.0/24"], vec![65001], "10.0.0.1"),
    );
    assert_eq!(sent(&mut rx).0, [prefix("198.51.1.0/24")]);
    rib.set_aggregates(vec![agg("198.51.0.0/16", false, true)]);
    assert_eq!(
        sent(&mut rx),
        (vec![prefix("198.51.0.0/16")], vec![prefix("198.51.1.0/24")])
    );
}

#[test]
fn nested_aggregates_and_the_seed_scan() {
    let (mut rib, _rx) = agg_rib();
    learn(
        &mut rib,
        &ebgp_update(vec!["198.51.1.0/24"], vec![65001], "10.0.0.1"),
    );
    rib.set_aggregates(vec![
        agg("198.0.0.0/8", false, false),
        agg("198.51.0.0/16", false, false),
    ]);
    assert!(rib.loc_rib.contains_key(&prefix("198.51.0.0/16")));
    assert!(rib.loc_rib.contains_key(&prefix("198.0.0.0/8")));
    learn(&mut rib, &withdraw("198.51.1.0/24"));
    assert!(!rib.loc_rib.contains_key(&prefix("198.51.0.0/16")));
    assert!(!rib.loc_rib.contains_key(&prefix("198.0.0.0/8")));
}

#[test]
fn a_looped_route_implicitly_withdraws_the_earlier_one() {
    let (mut rib, _rx) = agg_rib();
    learn(
        &mut rib,
        &ebgp_update(vec!["198.51.1.0/24"], vec![65001], "10.0.0.1"),
    );
    assert!(rib.loc_rib.contains_key(&prefix("198.51.1.0/24")));
    learn(
        &mut rib,
        &ebgp_update(vec!["198.51.1.0/24"], vec![65001, 65000], "10.0.0.1"),
    );
    assert!(!rib.loc_rib.contains_key(&prefix("198.51.1.0/24")));
}
