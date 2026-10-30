//! The bounded per-peer outbox (#395): overflow coalesces into a backlog that
//! `drain_backlog` re-sends from the current state.

use proptest::prelude::*;

use super::*;
use crate::rib::evpn_out::{AdvertisedEvpn, EvpnSource};

const CAP: usize = 4;

/// An eBGP peer whose queue holds only `CAP` updates.
fn tiny_peer(
    rib: &mut BgpRib,
    peer: IpAddr,
    add_path: bool,
) -> (mpsc::Receiver<OutboundUpdate>, OutboxTx) {
    let (tx, rx) = outbox_channel(peer, CAP);
    rib.peer_established(
        peer,
        false,
        Some(addr("10.0.0.254")),
        all_afs()
            .into_iter()
            .chain([AddressFamily::L2vpnEvpn])
            .collect(),
        false,
        None,
        false,
        false,
        if add_path {
            HashSet::from([AddressFamily::Ipv4Unicast])
        } else {
            HashSet::new()
        },
        accept_all_policy(),
        tx.clone(),
    );
    (rx, tx)
}

fn routes(range: std::ops::Range<u8>) -> RedistributeUpdate {
    RedistributeUpdate::Full(
        range
            .map(|i| nos_proto::RedistributedRoute {
                prefix: prefix(&format!("192.168.{i}.0/24")),
                gateway: addr("10.9.9.9"),
            })
            .collect(),
    )
}

/// Applies the receiver's queue to a model of what the peer holds, as
/// `(prefix, path id)`.
fn apply(rx: &mut mpsc::Receiver<OutboundUpdate>, model: &mut HashSet<(IpNet, u32)>) {
    let got = recv_all(rx);
    assert!(got.len() <= CAP, "queue exceeded its capacity");
    for u in &got {
        match u {
            OutboundUpdate::Announce(a) => {
                model.insert((a.prefix, a.path_id.unwrap_or(0)));
            }
            OutboundUpdate::Withdraw(p, _, id) => {
                model.remove(&(*p, id.unwrap_or(0)));
            }
            _ => {}
        }
    }
}

/// Plays the FSM: empty the queue, then drain, until nothing is parked.
fn settle(
    rib: &mut BgpRib,
    peer: IpAddr,
    tx: &OutboxTx,
    rx: &mut mpsc::Receiver<OutboundUpdate>,
    model: &mut HashSet<(IpNet, u32)>,
) {
    for _ in 0..100 {
        apply(rx, model);
        if !tx.pending() {
            return;
        }
        rib.drain_backlog(peer);
    }
    panic!("backlog never drained");
}

fn loc_rib_model(rib: &BgpRib, id: u32) -> HashSet<(IpNet, u32)> {
    rib.loc_rib.keys().map(|p| (*p, id)).collect()
}

#[test]
fn overflowed_updates_coalesce_and_converge_to_loc_rib() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let (mut rx, tx) = tiny_peer(&mut rib, peer, false);
    let mut model = HashSet::new();

    // Far more than fits; the later update withdraws some of the first.
    rib.apply_redistribute_update(routes(0..30));
    assert!(tx.pending());
    rib.apply_redistribute_update(routes(20..40));

    settle(&mut rib, peer, &tx, &mut rx, &mut model);
    assert_eq!(model, loc_rib_model(&rib, 0));
    assert_eq!(model.len(), 20);
}

#[test]
fn a_withdraw_lost_to_overflow_is_still_sent() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let (mut rx, tx) = tiny_peer(&mut rib, peer, false);
    let mut model = HashSet::new();
    rib.apply_redistribute_update(routes(0..3));
    apply(&mut rx, &mut model);
    assert_eq!(model.len(), 3);
    // The queue is full when the peer's routes are withdrawn.
    rib.apply_redistribute_update(routes(10..20));
    settle(&mut rib, peer, &tx, &mut rx, &mut model);
    assert_eq!(model, loc_rib_model(&rib, 0));
    assert!(!model.contains(&(prefix("192.168.0.0/24"), 0)));
}

#[test]
fn end_of_rib_follows_the_overflowed_dump() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let (mut rx, tx) = tiny_peer(&mut rib, peer, false);
    rib.apply_redistribute_update(routes(0..12));
    tx.send(OutboundUpdate::EndOfRib(AddressFamily::Ipv4Unicast));
    tx.send(OutboundUpdate::EndOfRib(AddressFamily::Ipv4Unicast)); // deduplicated
    let mut seen = Vec::new();
    for _ in 0..100 {
        seen.extend(recv_all(&mut rx));
        if !tx.pending() {
            break;
        }
        rib.drain_backlog(peer);
    }
    assert_eq!(
        seen.last(),
        Some(&OutboundUpdate::EndOfRib(AddressFamily::Ipv4Unicast))
    );
    assert_eq!(seen.len(), 13);
}

#[test]
fn add_path_withdraws_lost_to_overflow_are_still_sent() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let (mut rx, tx) = tiny_peer(&mut rib, peer, true);
    let mut model = HashSet::new();
    rib.apply_redistribute_update(routes(0..12));
    settle(&mut rib, peer, &tx, &mut rx, &mut model);
    assert_eq!(model.len(), 12);
    // Every withdraw overflows the queue.
    rib.apply_redistribute_update(routes(0..0));
    assert!(tx.pending());
    settle(&mut rib, peer, &tx, &mut rx, &mut model);
    assert!(model.is_empty(), "peer still holds {model:?}");
}

/// What a peer holds after applying `rx`'s EVPN updates.
type EvpnModel = HashMap<EvpnNlri, AdvertisedEvpn>;

fn apply_evpn(rx: &mut mpsc::Receiver<OutboundUpdate>, model: &mut EvpnModel, cap: usize) {
    let got = recv_all(rx);
    assert!(got.len() <= cap, "queue exceeded its capacity");
    for u in got {
        match u {
            OutboundUpdate::AnnounceEvpn(a) => {
                model.insert(a.nlri.clone(), a);
            }
            OutboundUpdate::WithdrawEvpn(n) => {
                model.remove(&n);
            }
            _ => {}
        }
    }
}

/// `settle` for EVPN: empty the queue, drain, until nothing is parked.
fn settle_evpn(
    rib: &mut BgpRib,
    peer: IpAddr,
    tx: &OutboxTx,
    rx: &mut mpsc::Receiver<OutboundUpdate>,
    model: &mut EvpnModel,
) {
    for _ in 0..1000 {
        apply_evpn(rx, model, CAP);
        if !tx.pending() {
            return;
        }
        rib.drain_backlog(peer);
    }
    panic!("backlog never drained");
}

/// A Type-5 route; `nh` varies an attribute without changing the NLRI.
fn type5(i: u8, nh: u8) -> nos_proto::EvpnRoute {
    nos_proto::EvpnRoute {
        key: nos_proto::EvpnKey::IpPrefix {
            rd: [0, 0, 0xfd, 0xe8, 0, 0, 0x13, 0x88],
            prefix: prefix(&format!("10.{i}.0.0/16")),
        },
        vni: 5000,
        next_hop: addr(&format!("192.0.2.{nh}")),
        ext_communities: vec![],
        esi: [0; 10],
        l3_vni: None,
    }
}

fn table() -> EvpnSource {
    EvpnSource::Table("t".to_string())
}

/// #764: an EVPN burst far above the queue coalesces instead of ceasing,
/// including an announce lost then withdrawn and an attribute change lost
/// then superseded.
#[test]
fn overflowed_evpn_updates_coalesce_and_converge_to_adj_rib_out() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let (mut rx, tx) = tiny_peer(&mut rib, peer, false);
    let mut model = EvpnModel::new();
    let full =
        |r: std::ops::Range<u8>, nh| nos_proto::EvpnUpdate::Full(r.map(|i| type5(i, nh)).collect());
    rib.apply_evpn_source(table(), full(0..30, 1));
    assert!(tx.pending());
    // 0..10 lost then withdrawn, 10..30 lost then re-sent with a new next hop.
    rib.apply_evpn_source(table(), full(10..40, 2));
    settle_evpn(&mut rib, peer, &tx, &mut rx, &mut model);
    assert_eq!(&model, &rib.evpn_adj_rib_out[&peer]);
    assert_eq!(model.len(), 30);
    assert!(model.values().all(|a| a.next_hop == addr("192.0.2.2")));
}

#[derive(Debug, Clone)]
enum EvpnOp {
    Add(u8, u8),
    Remove(u8),
    Full(Vec<u8>, u8),
    /// One FSM turn: empty the queue, drain once.
    Step,
}

fn evpn_op() -> impl Strategy<Value = EvpnOp> {
    prop_oneof![
        (0..12u8, 1..3u8).prop_map(|(i, nh)| EvpnOp::Add(i, nh)),
        (0..12u8).prop_map(EvpnOp::Remove),
        (proptest::collection::vec(0..12u8, 0..12), 1..3u8).prop_map(|(v, nh)| EvpnOp::Full(v, nh)),
        Just(EvpnOp::Step),
    ]
}

proptest! {
    /// Whatever the overflow and drain interleaving, the tiny peer ends up
    /// holding exactly what a roomy peer (never overflowed) holds, and both
    /// match `evpn_adj_rib_out`.
    #[test]
    fn evpn_backlog_converges_to_the_from_scratch_state(
        ops in proptest::collection::vec(evpn_op(), 0..40)
    ) {
        let mut rib = new_rib(65000);
        let (tiny, roomy) = (addr("10.0.0.1"), addr("10.0.0.2"));
        let (mut rx, tx) = tiny_peer(&mut rib, tiny, false);
        let (tx2, mut rx2) = test_channel();
        rib.peer_established(
            roomy,
            false,
            Some(addr("10.0.0.253")),
            HashSet::from([AddressFamily::L2vpnEvpn]),
            false,
            None,
            false,
            false,
            HashSet::new(),
            accept_all_policy(),
            tx2.clone(),
        );
        let (mut model, mut reference) = (EvpnModel::new(), EvpnModel::new());
        for op in ops {
            let update = match op {
                EvpnOp::Add(i, nh) => nos_proto::EvpnUpdate::Add(type5(i, nh)),
                EvpnOp::Remove(i) => nos_proto::EvpnUpdate::Remove(type5(i, 1).key),
                EvpnOp::Full(v, nh) => {
                    nos_proto::EvpnUpdate::Full(v.into_iter().map(|i| type5(i, nh)).collect())
                }
                EvpnOp::Step => {
                    apply_evpn(&mut rx, &mut model, CAP);
                    rib.drain_backlog(tiny);
                    continue;
                }
            };
            rib.apply_evpn_source(table(), update);
        }
        settle_evpn(&mut rib, tiny, &tx, &mut rx, &mut model);
        apply_evpn(&mut rx2, &mut reference, OUTBOX_CAPACITY);
        prop_assert!(!tx2.pending());
        prop_assert_eq!(&model, &rib.evpn_adj_rib_out[&tiny]);
        prop_assert_eq!(&reference, &rib.evpn_adj_rib_out[&roomy]);
        prop_assert_eq!(model, reference);
    }
}

#[test]
fn drain_without_a_backlog_or_peer_is_a_no_op() {
    let mut rib = new_rib(65000);
    rib.drain_backlog(addr("10.0.0.7"));
    let peer = addr("10.0.0.1");
    let (mut rx, tx) = tiny_peer(&mut rib, peer, false);
    rib.drain_backlog(peer);
    assert!(!tx.pending());
    assert_eq!(recv_all(&mut rx).len(), 0);
}
