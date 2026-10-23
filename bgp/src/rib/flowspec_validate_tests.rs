use super::*;
use crate::flowspec::{Afi, Prefix};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn flow(dest: Option<&str>) -> Flow {
    Flow {
        dest: dest.map(|d| Prefix {
            net: net(d),
            offset: 0,
        }),
        originator: ip("10.0.0.1"),
        ebgp: None,
        local_domain: false,
    }
}

fn uni(originator: Option<&str>, neighbour_as: u32) -> Unicast {
    Unicast {
        originator: originator.map(ip),
        neighbour_as,
        leftmost_as: Some(neighbour_as),
    }
}

const STRICT: nos_proto::BgpFlowspecValidation = nos_proto::BgpFlowspecValidation {
    disable_dest_prefix_rule: false,
    rfc8955_strict: true,
};

fn mode(relax: bool, strict: bool) -> nos_proto::BgpFlowspecValidation {
    nos_proto::BgpFlowspecValidation {
        disable_dest_prefix_rule: relax,
        rfc8955_strict: strict,
    }
}

/// A unicast view from `(prefix, route)` pairs and a list of
/// `(more-specific prefix, neighbour AS)`.
fn run(f: &Flow, relax: bool, routes: &[(&str, Unicast)], more: &[(&str, u32)]) -> FlowValidity {
    run_mode(f, mode(relax, true), routes, more)
}

/// `run` in the default RFC 9117 mode.
fn run9117(
    f: &Flow,
    relax: bool,
    routes: &[(&str, Unicast)],
    more: &[(&str, u32)],
) -> FlowValidity {
    run_mode(f, mode(relax, false), routes, more)
}

fn run_mode(
    f: &Flow,
    m: nos_proto::BgpFlowspecValidation,
    routes: &[(&str, Unicast)],
    more: &[(&str, u32)],
) -> FlowValidity {
    validate(
        f,
        m,
        |n| routes.iter().find(|(p, _)| net(p) == n).map(|(_, u)| *u),
        |n| {
            more.iter()
                .filter(|(p, _)| n.contains(&net(p)) && net(p).prefix_len() > n.prefix_len())
                .map(|(_, a)| *a)
                .collect()
        },
    )
}

use FlowValidity::{Invalid, Valid};
use InvalidReason as R;

#[test]
fn rule_a_needs_a_destination_prefix_unless_relaxed_strict() {
    let f = flow(None);
    assert_eq!(run(&f, false, &[], &[]), Invalid(R::NoDestinationPrefix));
    // Relaxed: (b) and (c) have nothing to look up.
    assert_eq!(run(&f, true, &[], &[]), Valid);
    // The knob does not relax anything else.
    let mut bad = flow(None);
    bad.ebgp = Some((65001, Some(65009)));
    assert_eq!(run(&bad, true, &[], &[]), Invalid(R::BadNeighbourAs));
}

#[test]
fn rule_a_ipv6_offset_must_be_zero_strict() {
    let mut f = flow(None);
    f.dest = Some(Prefix {
        net: net("2001:db8::/64"),
        offset: 32,
    });
    assert_eq!(run(&f, false, &[], &[]), Invalid(R::OffsetNotZero));
    assert_eq!(run(&f, true, &[], &[]), Valid);
    f.dest = Some(Prefix {
        net: net("2001:db8::/64"),
        offset: 0,
    });
    let r = [("2001:db8::/32", uni(Some("10.0.0.1"), 65001))];
    assert_eq!(run(&f, false, &r, &[]), Valid);
}

#[test]
fn rule_b_best_match_and_originator_strict() {
    let f = flow(Some("192.0.2.0/24"));
    assert_eq!(run(&f, false, &[], &[]), Invalid(R::NoUnicastRoute));
    // A covering route from the same originator validates it.
    let cover = [("192.0.0.0/16", uni(Some("10.0.0.1"), 65001))];
    assert_eq!(run(&f, false, &cover, &[]), Valid);
    // The longest match is the one compared, not a shorter one that agrees.
    let other = [
        ("192.0.0.0/16", uni(Some("10.0.0.1"), 65001)),
        ("192.0.2.0/24", uni(Some("10.0.0.2"), 65002)),
    ];
    assert_eq!(run(&f, false, &other, &[]), Invalid(R::OriginatorMismatch));
    // A local route never matches.
    let local = [("192.0.2.0/24", uni(None, 65000))];
    assert_eq!(run(&f, false, &local, &[]), Invalid(R::OriginatorMismatch));
    // The default route covers everything.
    let default = [("0.0.0.0/0", uni(Some("10.0.0.1"), 65001))];
    assert_eq!(run(&f, false, &default, &[]), Valid);
    // A route for a different address is no cover.
    let elsewhere = [("198.51.100.0/24", uni(Some("10.0.0.1"), 65001))];
    assert_eq!(run(&f, false, &elsewhere, &[]), Invalid(R::NoUnicastRoute));
}

#[test]
fn rule_c_more_specific_from_another_as_strict() {
    let f = flow(Some("192.0.0.0/16"));
    let r = [("192.0.0.0/16", uni(Some("10.0.0.1"), 65001))];
    // Same neighbouring AS is fine, another one is not.
    assert_eq!(run(&f, false, &r, &[("192.0.2.0/24", 65001)]), Valid);
    assert_eq!(
        run(
            &f,
            false,
            &r,
            &[("192.0.2.0/24", 65001), ("192.0.3.0/24", 65002)]
        ),
        Invalid(R::MoreSpecificFromOtherAs)
    );
    // Outside the flow's destination does not count.
    assert_eq!(run(&f, false, &r, &[("198.51.100.0/24", 65002)]), Valid);
}

#[test]
fn ebgp_leftmost_as_must_be_the_neighbour_strict() {
    let r = [("192.0.0.0/16", uni(Some("10.0.0.1"), 65001))];
    let mut f = flow(Some("192.0.2.0/24"));
    f.ebgp = Some((65001, Some(65001)));
    assert_eq!(run(&f, false, &r, &[]), Valid);
    f.ebgp = Some((65001, Some(65002)));
    assert_eq!(run(&f, false, &r, &[]), Invalid(R::BadNeighbourAs));
    f.ebgp = Some((65001, None));
    assert_eq!(run(&f, false, &r, &[]), Invalid(R::BadNeighbourAs));
    // iBGP: no check at all.
    f.ebgp = None;
    assert_eq!(run(&f, false, &r, &[]), Valid);
}

/// The unicast route is `192.0.0.0/16` from another originator, AS 65001.
fn other_originator() -> [(&'static str, Unicast); 1] {
    [("192.0.0.0/16", uni(Some("10.0.0.9"), 65001))]
}

#[test]
fn rfc9117_empty_or_confed_path_skips_the_originator_match() {
    let r = other_originator();
    let mut f = flow(Some("192.0.2.0/24"));
    assert_eq!(run9117(&f, false, &r, &[]), Invalid(R::OriginatorMismatch));
    f.local_domain = true;
    assert_eq!(run9117(&f, false, &r, &[]), Valid);
    // Strict: b.2 does not exist.
    assert_eq!(run(&f, false, &r, &[]), Invalid(R::OriginatorMismatch));
    // (c) is still enforced after b.2.
    assert_eq!(
        run9117(&f, false, &r, &[("192.0.2.0/25", 65002)]),
        Invalid(R::MoreSpecificFromOtherAs)
    );
}

#[test]
fn rfc9117_no_covering_route_is_valid_only_for_a_local_domain_flow() {
    let mut f = flow(Some("192.0.2.0/24"));
    assert_eq!(run9117(&f, false, &[], &[]), Invalid(R::NoUnicastRoute));
    f.local_domain = true;
    assert_eq!(run9117(&f, false, &[], &[]), Valid);
    assert_eq!(run(&f, false, &[], &[]), Invalid(R::NoUnicastRoute));
}

#[test]
fn rfc9117_ebgp_compares_the_leftmost_as_with_the_best_match() {
    let r = [("192.0.0.0/16", uni(Some("10.0.0.1"), 65001))];
    let mut f = flow(Some("192.0.2.0/24"));
    // A route server: the flow's leftmost AS is not the peer's, but it is
    // the best-match route's.
    f.ebgp = Some((65500, Some(65001)));
    assert_eq!(run9117(&f, false, &r, &[]), Valid);
    assert_eq!(run(&f, false, &r, &[]), Invalid(R::BadNeighbourAs));
    f.ebgp = Some((65001, Some(65002)));
    assert_eq!(run9117(&f, false, &r, &[]), Invalid(R::LeftmostAsMismatch));
    f.ebgp = Some((65001, None));
    assert_eq!(run9117(&f, false, &r, &[]), Invalid(R::LeftmostAsMismatch));
    // A best match without a leftmost AS (a local route) never agrees.
    let local = [(
        "192.0.0.0/16",
        Unicast {
            originator: Some(ip("10.0.0.1")),
            neighbour_as: 65000,
            leftmost_as: None,
        },
    )];
    f.ebgp = Some((65001, Some(65001)));
    assert_eq!(
        run9117(&f, false, &local, &[]),
        Invalid(R::LeftmostAsMismatch)
    );
    assert_eq!(run_mode(&f, STRICT, &local, &[]), Valid);
}

#[test]
fn rfc9117_without_a_destination_falls_back_to_the_neighbour_as() {
    let mut f = flow(None);
    assert_eq!(run9117(&f, true, &[], &[]), Valid);
    f.ebgp = Some((65001, Some(65009)));
    assert_eq!(run9117(&f, true, &[], &[]), Invalid(R::BadNeighbourAs));
}

#[test]
fn displays_are_short_and_stable() {
    assert_eq!(Valid.to_string(), "valid");
    assert_eq!(
        Invalid(R::NoUnicastRoute).to_string(),
        "invalid:no-covering-unicast-route"
    );
    for (r, s) in [
        (R::NoDestinationPrefix, "no-destination-prefix"),
        (R::OffsetNotZero, "ipv6-offset-not-zero"),
        (R::OriginatorMismatch, "originator-mismatch"),
        (R::MoreSpecificFromOtherAs, "more-specific-from-other-as"),
        (R::BadNeighbourAs, "bad-neighbour-as"),
        (R::LeftmostAsMismatch, "leftmost-as-mismatch"),
    ] {
        assert_eq!(r.to_string(), s);
    }
}

#[test]
fn dest_of_finds_the_first_destination_component() {
    let v4 = crate::flowspec::FlowSpec::decode(Afi::V4, &[5, 1, 24, 10, 1, 2])
        .unwrap()
        .0;
    assert_eq!(dest_of(&v4).unwrap().net, net("10.1.2.0/24"));
    let none = crate::flowspec::FlowSpec::decode(Afi::V4, &[3, 3, 0x81, 6])
        .unwrap()
        .0;
    assert!(dest_of(&none).is_none());
}

#[test]
fn index_keys_order_descendants_contiguously() {
    let p = net("10.1.0.0/16");
    let (fam, start, _) = key(p);
    assert!(!fam);
    assert_eq!(last(p), start + 0xffff);
    assert!(key(net("10.1.2.0/24")) > key(p));
    assert!(key(net("10.2.0.0/24")).1 > last(p));
    let (fam6, _, len6) = key(net("2001:db8::/32"));
    assert!(fam6);
    assert_eq!(len6, 32);
    assert_eq!(
        last(net("2001:db8::/32")) - key(net("2001:db8::/32")).1,
        (1u128 << 96) - 1
    );
}
