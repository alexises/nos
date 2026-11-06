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
