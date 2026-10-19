use super::*;
use crate::as_path::SegKind;

const P: &str = "198.51.100.0/24";
const PEER: &str = "10.0.0.1";

fn rib_enforcing() -> BgpRib {
    let mut rib = new_rib(65000);
    rib.set_peer_asn(addr(PEER), 65001);
    rib.set_peer_enforce_first_as(addr(PEER), true);
    rib
}

fn feed(rib: &mut BgpRib, ibgp: bool, path: Vec<u32>) {
    let u = ebgp_update(vec![P], path, "192.0.2.1");
    rib.handle_update(addr(PEER), ibgp, v4("1.1.1.1"), &u, &accept_all_policy());
}

fn learned(rib: &BgpRib) -> bool {
    rib.loc_rib.contains_key(&prefix(P))
}

#[test]
fn forged_first_as_is_dropped_and_withdraws_the_earlier_path() {
    let mut rib = rib_enforcing();
    feed(&mut rib, false, vec![65001, 65100]);
    assert!(learned(&rib));
    feed(&mut rib, false, vec![65999, 65100]);
    assert!(!learned(&rib), "treat-as-withdraw");
}

#[test]
fn correct_first_as_is_accepted() {
    let mut rib = rib_enforcing();
    feed(&mut rib, false, vec![65001]);
    assert!(learned(&rib));
}

#[test]
fn exempt_when_off_unset_ibgp_or_confed() {
    let mut rib = rib_enforcing();
    rib.set_peer_enforce_first_as(addr(PEER), false); // knob off / route-server client
    feed(&mut rib, false, vec![65999]);
    assert!(learned(&rib), "knob off");

    let mut rib = new_rib(65000); // peer_as unset
    rib.set_peer_enforce_first_as(addr(PEER), true);
    feed(&mut rib, false, vec![65999]);
    assert!(learned(&rib), "peer_as unset");

    let mut rib = rib_enforcing();
    feed(&mut rib, true, vec![65999]);
    assert!(learned(&rib), "iBGP");

    let mut rib = rib_enforcing();
    rib.set_confederation(Some(65100));
    rib.set_peer_confed(addr(PEER), true);
    feed(&mut rib, false, vec![65999]);
    assert!(learned(&rib), "confederation member");
}

#[test]
fn as_set_first_or_empty_path_is_a_violation() {
    let mut rib = rib_enforcing();
    let mut u = ebgp_update(vec![P], vec![], "192.0.2.1");
    u.attributes
        .as_mut()
        .unwrap()
        .as_path
        .push_segment(SegKind::Set, &[65001]);
    rib.handle_update(addr(PEER), false, v4("1.1.1.1"), &u, &accept_all_policy());
    assert!(!learned(&rib), "AS_SET first");
    feed(&mut rib, false, vec![]);
    assert!(!learned(&rib), "empty path");
}

#[test]
fn local_as_peer_checks_against_the_open_asn() {
    let mut rib = rib_enforcing();
    rib.set_peer_local_as(addr(PEER), Some(local_as(65009, false, false)));
    feed(&mut rib, false, vec![65001]);
    assert!(learned(&rib));
}

#[test]
fn warning_is_rate_limited_per_peer() {
    let mut rib = rib_enforcing();
    assert_eq!(rib.first_as_warn_due(addr(PEER)), Some(0));
    for _ in 0..5 {
        assert_eq!(rib.first_as_warn_due(addr(PEER)), None);
    }
    assert_eq!(rib.first_as_warn_due(addr("10.0.0.9")), Some(0), "per peer");
    // Age the last warning past the window: the suppressed count is reported.
    rib.first_as_warned.get_mut(&addr(PEER)).unwrap().0 -= FIRST_AS_WARN_EVERY;
    assert_eq!(rib.first_as_warn_due(addr(PEER)), Some(5));
}
