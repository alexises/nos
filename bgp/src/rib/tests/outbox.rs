//! The bounded per-peer outbox (#395): overflow coalesces into a backlog that
//! `drain_backlog` re-sends from the current state.

use super::*;

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
        all_afs(),
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
        assert!(!rib.drain_backlog(peer));
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

#[test]
fn a_lost_evpn_update_asks_for_a_session_reset() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let (_rx, tx) = tiny_peer(&mut rib, peer, false);
    rib.apply_redistribute_update(routes(0..12));
    tx.send(OutboundUpdate::WithdrawEvpn(EvpnNlri::EthernetSegment {
        rd: Default::default(),
        esi: [0; 10],
        origin: addr("10.0.0.9"),
    }));
    assert!(rib.drain_backlog(peer));
    assert!(tx.pending(), "left for the session reset");
}

#[test]
fn drain_without_a_backlog_or_peer_is_a_no_op() {
    let mut rib = new_rib(65000);
    assert!(!rib.drain_backlog(addr("10.0.0.7")));
    let peer = addr("10.0.0.1");
    let (mut rx, tx) = tiny_peer(&mut rib, peer, false);
    assert!(!rib.drain_backlog(peer));
    assert!(!tx.pending());
    assert_eq!(recv_all(&mut rx).len(), 0);
}
