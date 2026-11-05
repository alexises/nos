//! RFC 8326 graceful shutdown (#860): receive demotion, sender tagging.

use super::*;
use crate::message::COMMUNITY_GRACEFUL_SHUTDOWN as GS;
use crate::rib::GsKnobs;

const P: &str = "1.2.3.0/24";

fn knobs(peers: &[(&str, bool, bool)]) -> HashMap<IpAddr, GsKnobs> {
    peers
        .iter()
        .map(|(p, send, receive_off)| {
            (
                addr(p),
                GsKnobs {
                    send: *send,
                    receive_off: *receive_off,
                },
            )
        })
        .collect()
}

fn tagged_update(next_hop: &str, tag: bool) -> UpdateMessage {
    let mut u = ebgp_update(vec![P], vec![65001], next_hop);
    if tag {
        u.attributes.as_mut().unwrap().communities = vec![GS];
    }
    u
}

fn stored_lp(rib: &BgpRib, peer: &str) -> u32 {
    rib.adj_rib_in[&addr(peer)][&prefix(P)]
        .iter()
        .next()
        .unwrap()
        .1
        .local_pref
}

fn learn(rib: &mut BgpRib, peer: &str, ibgp: bool, u: &UpdateMessage) {
    rib.handle_update(addr(peer), ibgp, v4("2.2.2.2"), u, &nos_rpl::ACCEPT_ALL);
}

fn announced(rx: &mut mpsc::Receiver<OutboundUpdate>) -> Vec<AdvertisedRoute> {
    recv_all(rx)
        .into_iter()
        .filter_map(|u| match u {
            OutboundUpdate::Announce(a) => Some(a),
            _ => None,
        })
        .collect()
}

#[test]
fn tagged_ebgp_path_is_demoted_and_the_untagged_one_wins() {
    let mut rib = new_rib(65000);
    let _a = register_peer(&mut rib, addr("10.0.0.1"), false, addr("10.0.0.254"));
    let _b = register_peer(&mut rib, addr("10.0.0.2"), false, addr("10.0.0.253"));
    learn(
        &mut rib,
        "10.0.0.1",
        false,
        &tagged_update("10.0.0.1", true),
    );
    assert_eq!(stored_lp(&rib, "10.0.0.1"), 0);
    learn(
        &mut rib,
        "10.0.0.2",
        false,
        &tagged_update("10.0.0.2", false),
    );
    assert_eq!(stored_lp(&rib, "10.0.0.2"), 100);
    assert_eq!(
        rib.loc_rib[&prefix(P)].origin,
        RouteOrigin::Peer(addr("10.0.0.2"))
    );
}

#[test]
fn receive_off_ibgp_and_confed_paths_keep_their_local_pref() {
    let mut rib = new_rib(65000);
    let _a = register_peer(&mut rib, addr("10.0.0.1"), false, addr("10.0.0.254"));
    let _b = register_peer(&mut rib, addr("10.0.0.2"), true, addr("10.0.0.253"));
    rib.set_peer_confed(addr("10.0.0.3"), true);
    let _c = register_peer(&mut rib, addr("10.0.0.3"), false, addr("10.0.0.252"));
    rib.set_graceful_shutdown(knobs(&[("10.0.0.1", false, true)]));
    learn(
        &mut rib,
        "10.0.0.1",
        false,
        &tagged_update("10.0.0.1", true),
    );
    assert_eq!(stored_lp(&rib, "10.0.0.1"), 100);
    learn(&mut rib, "10.0.0.2", true, &tagged_update("10.0.0.2", true));
    assert_eq!(stored_lp(&rib, "10.0.0.2"), 100);
    learn(
        &mut rib,
        "10.0.0.3",
        false,
        &tagged_update("10.0.0.3", true),
    );
    assert_eq!(stored_lp(&rib, "10.0.0.3"), 100);
}

#[test]
fn sender_tags_and_demotes_what_it_receives_and_policy_can_override() {
    let mut rib = new_rib(65000);
    let _a = register_peer(&mut rib, addr("10.0.0.1"), false, addr("10.0.0.254"));
    rib.set_graceful_shutdown(knobs(&[("10.0.0.1", true, false)]));
    learn(
        &mut rib,
        "10.0.0.1",
        false,
        &tagged_update("10.0.0.1", false),
    );
    assert_eq!(stored_lp(&rib, "10.0.0.1"), 0);
    let r = &rib.adj_rib_in[&addr("10.0.0.1")][&prefix(P)];
    assert_eq!(r.iter().next().unwrap().1.communities, vec![GS]);

    // Import policy runs after the knob: it still wins.
    let policy = nos_rpl::compile(
        "set this.bgp.local_pref = 500\naccept\n",
        &nos_rpl::Symbols::EMPTY,
    )
    .unwrap();
    rib.handle_update(
        addr("10.0.0.1"),
        false,
        v4("2.2.2.2"),
        &tagged_update("10.0.0.1", true),
        &policy,
    );
    assert_eq!(stored_lp(&rib, "10.0.0.1"), 500);
}

fn tag_count(a: &AdvertisedRoute) -> usize {
    a.communities.iter().filter(|c| **c == GS).count()
}

#[test]
fn unicast_export_is_tagged_once_toward_ebgp_only_and_toggles_live() {
    let mut rib = new_rib(65000);
    let _src = register_peer(&mut rib, addr("10.0.0.1"), false, addr("10.0.0.254"));
    let mut ebgp = register_peer(&mut rib, addr("10.0.0.2"), false, addr("10.0.0.253"));
    let mut ibgp = register_peer(&mut rib, addr("10.0.0.3"), true, addr("10.0.0.252"));
    // Already tagged upstream: no duplicate.
    learn(
        &mut rib,
        "10.0.0.1",
        false,
        &tagged_update("10.0.0.1", true),
    );
    assert_eq!(tag_count(&announced(&mut ebgp)[0]), 1);
    recv_all(&mut ibgp);

    let changed = rib.set_graceful_shutdown(knobs(&[
        ("10.0.0.2", true, false),
        ("10.0.0.3", true, false),
    ]));
    assert_eq!(changed.len(), 2);
    recv_all(&mut ebgp);
    recv_all(&mut ibgp);
    // Untag the route first so the tag we see is the knob's.
    let mut u = tagged_update("10.0.0.1", false);
    u.attributes.as_mut().unwrap().as_path = vec![65001].into();
    learn(&mut rib, "10.0.0.1", false, &u);
    let adv = announced(&mut ebgp);
    assert_eq!(adv.last().map(tag_count), Some(1));
    let adv = announced(&mut ibgp);
    assert!(adv.iter().all(|a| tag_count(a) == 0));

    // Turning it off re-sends the route without the tag.
    rib.set_graceful_shutdown(HashMap::new());
    assert_eq!(announced(&mut ebgp).last().map(tag_count), Some(0));
}

#[test]
fn export_policy_can_strip_the_tag() {
    let mut rib = new_rib(65000);
    let _src = register_peer(&mut rib, addr("10.0.0.1"), false, addr("10.0.0.254"));
    let (tx, mut rx) = test_channel();
    let strip = nos_rpl::compile(
        "this.bgp.communities.remove(65535:0)\naccept\n",
        &nos_rpl::Symbols::EMPTY,
    )
    .unwrap();
    rib.set_graceful_shutdown(knobs(&[("10.0.0.2", true, false)]));
    rib.peer_established(
        addr("10.0.0.2"),
        false,
        Some(addr("10.0.0.253")),
        all_afs(),
        false,
        None,
        false,
        false,
        HashSet::new(),
        Arc::new(strip),
        tx,
    );
    learn(
        &mut rib,
        "10.0.0.1",
        false,
        &tagged_update("10.0.0.1", false),
    );
    let adv = announced(&mut rx);
    assert_eq!(adv.len(), 1);
    assert_eq!(tag_count(&adv[0]), 0);
}

#[test]
fn evpn_export_is_tagged_unconditionally_toward_ebgp_only() {
    let mut rib = new_rib(65000);
    let evpn = HashSet::from([AddressFamily::Ipv4Unicast, AddressFamily::L2vpnEvpn]);
    rib.set_graceful_shutdown(knobs(&[
        ("10.0.0.1", true, false),
        ("10.0.0.2", true, false),
    ]));
    let mut ebgp = register_mp_peer(
        &mut rib,
        addr("10.0.0.1"),
        false,
        addr("10.0.0.254"),
        evpn.clone(),
    );
    let mut ibgp = register_mp_peer(&mut rib, addr("10.0.0.2"), true, addr("10.0.0.253"), evpn);
    rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(evpn_route()));
    let get = |rx: &mut mpsc::Receiver<OutboundUpdate>| {
        recv_all(rx)
            .into_iter()
            .find_map(|u| match u {
                OutboundUpdate::AnnounceEvpn(a) => Some(a),
                _ => None,
            })
            .expect("an EVPN announcement")
    };
    assert_eq!(get(&mut ebgp).communities, vec![GS]);
    assert_eq!(get(&mut ibgp).communities, [] as [u32; 0]);

    // Live off: the route is re-announced without the tag.
    rib.set_graceful_shutdown(HashMap::new());
    assert_eq!(get(&mut ebgp).communities, [] as [u32; 0]);
}

fn evpn_route() -> nos_proto::EvpnRoute {
    nos_proto::EvpnRoute {
        key: nos_proto::EvpnKey::Mac {
            rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
            mac: [0, 0, 0, 0, 0, 1],
        },
        vni: 10100,
        next_hop: addr("192.0.2.9"),
        ext_communities: vec![],
        esi: [0; 10],
        l3_vni: None,
    }
}

#[test]
fn vpn_export_is_tagged_toward_ebgp_only_and_toggles_live() {
    use super::vpn::{advs, feed, nlri, reach, setup, EBGP, IBGP, P as VP, RD1, SRC};
    let (mut rib, mut rx) = setup();
    feed(
        &mut rib,
        SRC,
        false,
        &reach(SRC, vec![65001], vec![nlri(RD1, VP, 100)]),
    );
    recv_all(&mut rx[1]);
    recv_all(&mut rx[2]);
    let changed = rib.set_graceful_shutdown(knobs(&[(EBGP, true, false), (IBGP, true, false)]));
    assert_eq!(changed.len(), 2);
    let to_ebgp = advs(&mut rx[1]);
    assert_eq!(to_ebgp.len(), 1);
    assert_eq!(tag_count(&to_ebgp[0].route), 1);
    assert!(advs(&mut rx[2]).iter().all(|a| tag_count(&a.route) == 0));
    rib.set_graceful_shutdown(HashMap::new());
    assert_eq!(tag_count(&advs(&mut rx[1])[0].route), 0);
}
