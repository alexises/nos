//! #868: the policy adapter hands `nos-rpl` the complete segmented path, so
//! `path_length` and the AS accessors see the RFC 4271 section 9.1.2.2 value.

use super::*;
use crate::as_path::SegKind;

fn accepts(src: &str, route: &RibRoute) -> bool {
    let p = nos_rpl::compile(src, &nos_rpl::Symbols::EMPTY).unwrap();
    apply_policy(prefix("10.0.0.0/8"), route.clone(), &p, None, None).is_some()
}

fn route_with(path: &[(SegKind, &[u32])]) -> RibRoute {
    let mut r = redistributed_route();
    let a = Arc::make_mut(&mut r.as_path);
    for (k, asns) in path {
        a.push_segment(*k, asns);
    }
    r
}

fn cond(c: &str) -> String {
    format!("if {c}:\n    accept\nelse:\n    reject\n")
}

#[test]
fn segments_concatenate_to_flat_and_length_is_rfc_4271() {
    for r in [
        route_with(&[
            (SegKind::ConfedSequence, &[65100]),
            (SegKind::Sequence, &[65001, 65002]),
            (SegKind::Set, &[1, 2, 3]),
        ]),
        route_with(&[]),
    ] {
        let segs = policy_segments(&r);
        let cat: Vec<u32> = segs.iter().flat_map(|s| s.asns.iter().copied()).collect();
        assert_eq!(cat, r.as_path.flat());
        let want = r.as_path.selection_len();
        assert!(accepts(
            &cond(&format!("this.bgp.as_path.path_length == {want}")),
            &r
        ));
    }
}

#[test]
fn mixed_path_accessors_and_local_route() {
    let r = route_with(&[
        (SegKind::ConfedSequence, &[65100]),
        (SegKind::Sequence, &[65001, 65002]),
    ]);
    assert!(accepts(
        &cond("this.bgp.neighbor_as == 65001 and this.bgp.origin_as == 65002 and this.bgp.first_as != 65100"),
        &r
    ));
    // A locally originated route has an empty path.
    let local = route_with(&[]);
    assert!(accepts(
        &cond("this.bgp.as_path.path_length == 0 and this.bgp.first_as != 1"),
        &local
    ));
}

#[test]
fn accepted_prepend_adds_to_path_length_on_the_stored_route() {
    let r = route_with(&[(SegKind::Sequence, &[65001])]);
    let p = nos_rpl::compile(
        "this.bgp.as_path.prepend(65000, 3)\naccept\n",
        &nos_rpl::Symbols::EMPTY,
    )
    .unwrap();
    let stored = apply_policy(prefix("10.0.0.0/8"), r, &p, None, None).unwrap();
    assert!(accepts(
        &cond("this.bgp.as_path.path_length == 4 and this.bgp.first_as == 65000"),
        &stored
    ));
}

fn compiled(src: &str) -> Arc<CompiledPolicy> {
    Arc::new(nos_rpl::compile(src, &nos_rpl::Symbols::EMPTY).unwrap())
}

/// Whether a route learned from a peer with role `ours` (negotiated or not)
/// survives `policy` as an import policy.
fn imported(ours: Option<nos_proto::BgpRole>, negotiated: bool, policy: &str) -> bool {
    let src = addr("10.0.0.1");
    let mut rib = new_rib(65000);
    rib.set_peer_asn(src, 65001);
    if let Some(r) = ours {
        rib.set_peer_role(src, Some(r));
    }
    rib.set_peer_role_negotiated(src, negotiated);
    rib.handle_update(
        src,
        false,
        v4("1.1.1.1"),
        &ebgp_update(vec!["198.51.100.0/24"], vec![65001], "192.0.2.1"),
        &compiled(policy),
    );
    rib.loc_rib.contains_key(&prefix("198.51.100.0/24"))
}

/// #872: import policies see our role, and the peer's only once negotiated.
#[test]
fn import_policy_sees_negotiated_roles() {
    use nos_proto::BgpRole::Provider;
    let reject_customer = cond("this.bgp.remote_role != role.customer");
    let both =
        cond("this.bgp.local_role == role.provider and this.bgp.remote_role == role.customer");
    // We are the provider, the peer our customer.
    assert!(!imported(Some(Provider), true, &reject_customer));
    assert!(imported(Some(Provider), true, &both));
    // No Role from the peer: remote unset (`!=` true, `==` false), local kept.
    assert!(imported(Some(Provider), false, &reject_customer));
    assert!(!imported(Some(Provider), false, &both));
    assert!(imported(
        Some(Provider),
        false,
        &cond("this.bgp.local_role == role.provider")
    ));
    // No role configured at all.
    assert!(!imported(
        None,
        false,
        &cond("this.bgp.local_role == role.provider")
    ));
    assert!(imported(
        None,
        false,
        &cond("this.bgp.local_role != role.provider")
    ));
}

/// #872: `otc` is the post-ingress value (a provider-learned route with no
/// wire OTC carries the peer's ASN).
#[test]
fn import_policy_sees_post_ingress_otc() {
    use nos_proto::BgpRole::Customer;
    assert!(imported(
        Some(Customer),
        true,
        &cond("this.bgp.otc == 65001")
    ));
    assert!(!imported(None, false, &cond("this.bgp.otc == 65001")));
    assert!(imported(None, false, &cond("this.bgp.otc != 65001")));
}

/// #872: a redistributed route has no session, so both roles are unset.
#[test]
fn redistributed_route_has_no_roles() {
    let r = redistributed_route();
    assert!(accepts(&cond("this.bgp.remote_role != role.customer"), &r));
    assert!(!accepts(&cond("this.bgp.local_role == role.customer"), &r));
}

/// #872: an export policy sees the roles of the destination session.
#[test]
fn export_policy_sees_destination_roles() {
    let policy = compiled(&cond(
        "this.bgp.local_role == role.customer and this.bgp.remote_role == role.provider",
    ));
    for (negotiated, want) in [(true, true), (false, false)] {
        let (src, dst) = (addr("10.0.0.1"), addr("10.0.0.2"));
        let mut rib = new_rib(65000);
        rib.set_peer_asn(src, 65001);
        register_peer(&mut rib, src, false, addr("10.0.0.9"));
        rib.set_peer_role(dst, Some(nos_proto::BgpRole::Customer));
        rib.set_peer_role_negotiated(dst, negotiated);
        let (tx, mut rx) = test_channel();
        rib.peer_established(
            dst,
            false,
            Some(addr("10.0.0.9")),
            all_afs(),
            false,
            None,
            false,
            false,
            HashSet::new(),
            policy.clone(),
            tx,
        );
        rib.handle_update(
            src,
            false,
            v4("1.1.1.1"),
            &ebgp_update(vec!["198.51.100.0/24"], vec![65001], "192.0.2.1"),
            &accept_all_policy(),
        );
        assert_eq!(
            announced(&mut rx, "198.51.100.0/24").is_some(),
            want,
            "negotiated={negotiated}"
        );
    }
}
