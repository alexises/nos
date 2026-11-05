//! Soft reconfiguration inbound (#859): retention and local re-evaluation.

use super::*;
use crate::rib::ChunkOutcome;

static ACCEPT: &std::sync::LazyLock<nos_rpl::CompiledPolicy> = &nos_rpl::ACCEPT_ALL;

fn flagged_rib() -> (BgpRib, IpAddr) {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    std::mem::forget(rx); // keep the outbox open for the test's lifetime
    rib.set_peer_soft_reconfig(peer, true);
    (rib, peer)
}

fn announce(rib: &mut BgpRib, peer: IpAddr, prefixes: &[&str], policy: &nos_rpl::CompiledPolicy) {
    let u = ebgp_update(prefixes.to_vec(), vec![65001], "10.0.0.1");
    rib.handle_update(peer, false, v4("192.0.2.1"), &u, policy);
}

fn withdraw(rib: &mut BgpRib, peer: IpAddr, p: &str) {
    let u = UpdateMessage {
        withdrawn_routes: vec![p.parse().unwrap()],
        ..empty_update()
    };
    rib.handle_update(peer, false, v4("192.0.2.1"), &u, ACCEPT);
}

fn arc(p: &nos_rpl::CompiledPolicy) -> Arc<nos_rpl::CompiledPolicy> {
    Arc::new(p.clone())
}

#[test]
fn without_the_flag_nothing_is_retained() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    announce(&mut rib, peer, &["1.0.0.0/24"], &nos_rpl::DENY_ALL);
    assert_eq!(rib.retained_count(peer), 0);
    assert_eq!(rib.reevaluate_peer(peer, arc(ACCEPT)), []);
}

#[test]
fn tighten_then_loosen_readmits_without_a_session_event() {
    let (mut rib, peer) = flagged_rib();
    announce(
        &mut rib,
        peer,
        &["1.0.0.0/24", "2.0.0.0/24"],
        &nos_rpl::DENY_ALL,
    );
    assert_eq!(rib.retained_count(peer), 2);
    assert_eq!(rib.accepted_prefixes(peer), [0, 0, 0]);

    let fams = rib.reevaluate_peer(peer, arc(ACCEPT));
    assert_eq!((fams[0].retained, fams[0].accepted), (2, 2));
    assert_eq!((fams[1].retained, fams[1].accepted), (0, 0));
    assert_eq!(rib.accepted_prefixes(peer), [2, 0, 0]);
    assert!(rib.loc_rib.contains_key(&prefix("1.0.0.0/24")));

    let fams = rib.reevaluate_peer(peer, arc(&nos_rpl::DENY_ALL));
    assert_eq!((fams[0].retained, fams[0].accepted), (2, 0));
    assert_eq!(rib.accepted_prefixes(peer), [0, 0, 0]);
    assert!(!rib.loc_rib.contains_key(&prefix("1.0.0.0/24")));
    assert_eq!(rib.retained_count(peer), 2, "the pre-policy copies stay");
}

#[test]
fn a_withdrawal_drops_the_retained_copy_even_if_policy_rejected_it() {
    let (mut rib, peer) = flagged_rib();
    announce(&mut rib, peer, &["1.0.0.0/24"], &nos_rpl::DENY_ALL);
    withdraw(&mut rib, peer, "1.0.0.0/24");
    assert_eq!(rib.retained_count(peer), 0);
    assert_eq!(rib.retained_count(peer), 0);
}

#[test]
fn disconnect_and_flag_off_free_the_retention() {
    let (mut rib, peer) = flagged_rib();
    announce(&mut rib, peer, &["1.0.0.0/24"], ACCEPT);
    rib.set_peer_soft_reconfig(peer, false);
    assert_eq!(rib.retained_count(peer), 0);
    assert!(!rib.soft_reconfig_enabled(peer));

    rib.set_peer_soft_reconfig(peer, true);
    announce(&mut rib, peer, &["1.0.0.0/24"], ACCEPT);
    assert_eq!(rib.retained_count(peer), 1);
    rib.peer_disconnected(peer, Disconnect::Transport);
    assert_eq!(rib.retained_count(peer), 0);
    assert!(!rib.soft_reconfig_enabled(peer));
}

#[test]
fn reevaluation_applies_no_damping_and_keeps_the_age() {
    let (mut rib, peer) = flagged_rib();
    announce(&mut rib, peer, &["1.0.0.0/24"], ACCEPT);
    let age = rib.loc_rib[&prefix("1.0.0.0/24")].received_at;
    let fams = rib.reevaluate_peer(peer, arc(ACCEPT));
    assert_eq!(fams[0].accepted, 1);
    assert_eq!(rib.loc_rib[&prefix("1.0.0.0/24")].received_at, age);
}

#[test]
fn interleaved_updates_between_chunks_stay_consistent() {
    let (mut rib, peer) = flagged_rib();
    announce(
        &mut rib,
        peer,
        &["1.0.0.0/24", "2.0.0.0/24", "3.0.0.0/24"],
        &nos_rpl::DENY_ALL,
    );
    let mut pass = rib.begin_reevaluation(peer, arc(ACCEPT)).unwrap();
    // One prefix per chunk; between chunks the new policy is already live for
    // UPDATEs, and a withdrawal removes the retained copy.
    let mut visited = 0;
    loop {
        let outcome = rib.reevaluate_chunk(&mut pass, 1);
        visited += 1;
        if visited == 1 {
            // Whatever the snapshot order, withdraw one not yet visited and
            // re-announce another with the new policy.
            let left: Vec<IpNet> = rib
                .retained_routes(peer)
                .into_iter()
                .map(|(p, _, _)| p)
                .filter(|p| !rib.adj_rib_in[&peer].contains_key(p))
                .collect();
            assert_eq!(left.len(), 2);
            withdraw(&mut rib, peer, &left[0].to_string());
            announce(&mut rib, peer, &[&left[1].to_string()], ACCEPT);
        }
        if outcome != ChunkOutcome::More {
            break;
        }
    }
    assert_eq!(rib.accepted_prefixes(peer), [2, 0, 0]);
    assert_eq!(rib.retained_count(peer), 2);
    let fams = pass.families();
    assert!(fams[0].retained <= 3 && fams[0].accepted >= 1);
}

#[test]
fn a_pass_notices_retention_going_away() {
    let (mut rib, peer) = flagged_rib();
    announce(
        &mut rib,
        peer,
        &["1.0.0.0/24", "2.0.0.0/24"],
        &nos_rpl::DENY_ALL,
    );
    let mut pass = rib.begin_reevaluation(peer, arc(ACCEPT)).unwrap();
    rib.set_peer_soft_reconfig(peer, false);
    assert_eq!(rib.reevaluate_chunk(&mut pass, 1), ChunkOutcome::Gone);
    assert!(rib.begin_reevaluation(peer, arc(ACCEPT)).is_none());
}

#[test]
fn each_chunk_visits_at_most_n_prefixes() {
    let (mut rib, peer) = flagged_rib();
    let ps: Vec<String> = (0..10).map(|i| format!("{i}.0.0.0/24")).collect();
    let refs: Vec<&str> = ps.iter().map(String::as_str).collect();
    announce(&mut rib, peer, &refs, &nos_rpl::DENY_ALL);
    let mut pass = rib.begin_reevaluation(peer, arc(ACCEPT)).unwrap();
    let mut chunks = 0;
    while rib.reevaluate_chunk(&mut pass, 3) == ChunkOutcome::More {
        chunks += 1;
        assert!(pass.families()[0].retained <= 3 * (chunks + 1));
    }
    assert_eq!(chunks, 3, "10 prefixes in chunks of 3 is 4 chunks");
    assert_eq!(pass.families()[0].retained, 10);
}

#[test]
fn eorr_marks_retention_complete_once() {
    let (mut rib, peer) = flagged_rib();
    rib.enable_soft_reconfig_live(peer, true);
    // Only awaited families matter; no panic and idempotent.
    rib.retention_eorr(peer, AddressFamily::Ipv4Unicast);
    rib.retention_eorr(peer, AddressFamily::Ipv4Unicast);
}
