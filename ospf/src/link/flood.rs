//! Acks, retransmission, reliable flooding and the neighbor liveness timers.
//! Moved verbatim out of `link.rs`.

use super::rx::{execute_actions, next_crypto_seq};
use super::{
    bfd, exchange, info, lsa, neighbor, packet, warn, Duration, Instant, Ipv4Addr, LinkConfig,
    LinkSocket, Lsa, Lsdb, LsrPacket, LsuPacket, Mutex, NeighborState, NetworkType, StatusHandle,
};

/// RFC 2328 §13.5 delayed acknowledgment: sends each neighbor's queued acks
/// (`AdjacencyData::pending_acks`, filled by `on_lsu_received`) as one
/// `LSAck`. Runs on the `RXMT_INTERVAL` sweep — the RFC only requires the
/// delay to stay below `RxmtInterval`, and one more tick per link keeps
/// `run()`'s `select!` no wider.
pub(super) fn flush_pending_acks(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    next_seq: &mut u64,
) {
    let mut flushes = Vec::new();
    status.send_if_modified(|s| {
        for (neighbor_id, info) in &mut s.neighbors {
            let Some(adj) = &mut info.adjacency else {
                continue;
            };
            let held = adj.pending_acks_since;
            if let Some(action) = exchange::take_pending_acks(adj) {
                flushes.push((*neighbor_id, held, action));
            }
        }
        // Nothing here changes what `originate_router_lsas` snapshots.
        false
    });
    for (neighbor_id, held, action) in flushes {
        if let exchange::Action::SendLsAck(headers) = &action {
            info!(
                link = %cfg.attach_point, neighbor = %neighbor_id, acked = headers.len(),
                delayed_ms = held.map_or(0, |t| t.elapsed().as_millis()),
                "ospf lsack sent"
            );
        }
        execute_actions(
            socket,
            cfg,
            local_router_id,
            status,
            neighbor_id,
            vec![action],
            next_seq,
        );
    }
}

/// Resends every neighbor's last-sent DBD (if any — see `AdjacencyData::
/// last_dbd_sent`'s doc comment for why this is necessary, not just a
/// reliability nicety) and outstanding request/retransmission list —
/// ponytail: the whole set every tick, rather than tracking each entry's
/// own last-sent time, since `RXMT_INTERVAL` is already the granularity RFC
/// 2328 uses and this NOS's per-neighbor outstanding set is tiny (a handful
/// of LSAs on a lab topology).
pub(super) fn retransmit_pending(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    next_seq: &mut u64,
) {
    let snapshot = status.borrow().clone();
    for (neighbor_id, info) in &snapshot.neighbors {
        let Some(adj) = &info.adjacency else { continue };
        // Only while negotiating: a slave's kept final reply goes out only
        // in answer to the master's duplicate (`exchange`), never on a timer.
        if let (NeighborState::ExStart | NeighborState::Exchange, Some(dbd)) =
            (info.state, &adj.last_dbd_sent)
        {
            let auth = cfg
                .auth
                .as_outgoing(next_crypto_seq(next_seq, &cfg.auth), cfg.local_addr);
            if let Err(e) = socket.send_unicast(info.address, &packet::encode_dbd(dbd, &auth)) {
                warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospf dbd");
            }
        }
        if !matches!(
            info.state,
            NeighborState::Exchange | NeighborState::Loading | NeighborState::Full
        ) {
            continue;
        }
        if !adj.request_list.is_empty() {
            let lsr = LsrPacket {
                router_id: local_router_id,
                area_id: cfg.area_id,
                requests: adj.request_list.clone(),
            };
            let auth = cfg
                .auth
                .as_outgoing(next_crypto_seq(next_seq, &cfg.auth), cfg.local_addr);
            if let Err(e) = socket.send_unicast(info.address, &packet::encode_lsr(&lsr, &auth)) {
                warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospf lsr");
            }
        }
        if !adj.retransmission_list.is_empty() {
            let lsu = LsuPacket {
                router_id: local_router_id,
                area_id: cfg.area_id,
                lsas: adj
                    .retransmission_list
                    .values()
                    .map(|l| (**l).clone())
                    .collect(),
            };
            let auth = cfg
                .auth
                .as_outgoing(next_crypto_seq(next_seq, &cfg.auth), cfg.local_addr);
            if let Err(e) = socket.send_unicast(info.address, &packet::encode_lsu(&lsu, &auth)) {
                warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospf lsu");
            }
        }
    }
}

/// Resends the entire local LSDB — the area's plus this link's own type-9
/// LSAs — to every `Full` neighbor on this link; opaque LSAs only to a
/// neighbor whose DBD set the O-bit (RFC 5250 §3).
///
/// # ponytail: periodic full resend, not RFC 2328 §13's event-driven flood
/// A neighbor's one-shot DBD/LSR/LSU exchange (see `exchange.rs`'s own
/// `ponytail:` note) only ever sees the LSDB's contents at the moment
/// negotiation completes — a self-originated LSA that appears afterward (or
/// one learned from a different link, since every link in an area shares one
/// `Lsdb`) would otherwise never reach an already-`Full` neighbor. Resending
/// everything on every `RXMT_INTERVAL` tick is safe (`Lsdb::install`/
/// `on_lsu_received` already reject and cheaply ack non-newer duplicates)
/// and simple, at the cost of up to one `RXMT_INTERVAL` of propagation delay
/// and some wasted bandwidth on a lab-scale LSDB. This is the permanent
/// design, not a placeholder: nothing in this NOS consumes the LSDB in a
/// time-sensitive way yet (no SPF/route computation), so real event-driven
/// flooding (`exchange::Action::InstallAndFlood`) would add real complexity
/// (threading a fan-out channel through every link task) for a latency bound
/// nothing needs tightened. Revisit once a SPF phase makes convergence speed
/// actually matter.
pub(super) async fn flood_full_neighbors(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    lsdb: &Mutex<Lsdb>,
    link_local_lsdb: &Mutex<Lsdb>,
    status: &StatusHandle,
    next_seq: &mut u64,
) {
    let full_neighbors: Vec<(Ipv4Addr, Ipv4Addr, bool)> = status
        .borrow()
        .neighbors
        .iter()
        .filter(|(_, info)| info.state == NeighborState::Full)
        .map(|(id, info)| {
            let opaque = info.adjacency.as_ref().is_some_and(|a| a.opaque_capable);
            (*id, info.address, opaque)
        })
        .collect();
    if full_neighbors.is_empty() {
        return;
    }
    let mut lsas = lsdb.lock().await.all();
    lsas.extend(link_local_lsdb.lock().await.all());
    // A stub area carries no AS-scope LSA (RFC 2328 §3.6) — one held from
    // before the area turned stub just ages out here.
    lsas.retain(|l| lsa::in_area_scope(l.header.lsa_type, cfg.stub, cfg.nssa));
    // One signed payload per group (opaque-capable or not), reused for every
    // neighbor in it — safe even under Crypto auth: RFC 2328 D.4.3's
    // anti-replay check is per-neighbor on the receive side
    // (`accept_crypto_sequence` keys on the sender's own `router_id`), so two
    // different neighbors each independently accepting the same sequence
    // number is correct, not a replay.
    for opaque in [true, false] {
        let group: Vec<_> = full_neighbors.iter().filter(|n| n.2 == opaque).collect();
        let lsas: Vec<Lsa> = lsas
            .iter()
            .filter(|l| opaque || !lsa::is_opaque(l.header.lsa_type))
            .map(|l| (**l).clone())
            .collect();
        if group.is_empty() || lsas.is_empty() {
            continue;
        }
        let auth = cfg
            .auth
            .as_outgoing(next_crypto_seq(next_seq, &cfg.auth), cfg.local_addr);
        let payload = packet::encode_lsu(
            &LsuPacket {
                router_id: local_router_id,
                area_id: cfg.area_id,
                lsas,
            },
            &auth,
        );
        for (neighbor_id, neighbor_addr, _) in group {
            if let Err(e) = socket.send_unicast(*neighbor_addr, &payload) {
                warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospf lsu");
            }
        }
    }
}

/// Point-to-point only — `run()` only arms this branch when
/// `cfg.network_type` is `PointToPoint`. At most one neighbor entry.
pub(super) fn apply_dead_timer(cfg: &LinkConfig, status: &StatusHandle) {
    let Some((old_state, grace)) = status
        .borrow()
        .neighbors
        .values()
        .next()
        .map(|n| (n.state, n.grace_deadline))
    else {
        return;
    };
    if grace.is_some() {
        return;
    }
    if old_state != NeighborState::Down {
        warn!(link = %cfg.attach_point, "ospf neighbor state changed to down");
    }
    let new_state = neighbor::step(old_state, neighbor::Event::InactivityTimerExpired);
    status.send_modify(|s| {
        for info in s.neighbors.values_mut() {
            info.state = new_state;
            info.adjacency = None;
        }
    });
}

/// RFC 2328 §10.2 `KillNbr` for the neighbor at `address`, because BFD found
/// its path down. The next Hello brings it back through Init; nothing waits
/// on BFD to form an adjacency.
pub(super) fn kill_bfd_neighbor(cfg: &LinkConfig, status: &StatusHandle, address: Ipv4Addr) {
    status.send_modify(|s| {
        for (id, info) in &mut s.neighbors {
            if info.address == address && info.state != NeighborState::Down {
                warn!(link = %cfg.attach_point, neighbor = %id, "bfd session down, killing ospf neighbor");
                info.state = bfd::on_bfd_down(info.state);
                info.adjacency = None;
            }
        }
    });
}

/// RFC 4222 §2 recommendation 2: an authenticated non-Hello packet from a
/// neighbor we have an adjacency with (`ExStart` or later) proves it alive,
/// so it restarts the inactivity timer like a Hello would. Hellos keep their
/// own refresh in `handle_hello`, which only happens once they pass its
/// checks. ponytail: counts any destination, not only unicast / `AllSPFRouters`
/// on point-to-point as the RFC words it — `recv_packet` doesn't return the
/// destination (that needs `IP_PKTINFO`), and nos sends these unicast anyway.
pub(super) fn note_alive(
    cfg: &LinkConfig,
    status: &StatusHandle,
    router_id: Ipv4Addr,
    p2p_dead_deadline: &mut Instant,
) {
    let adjacent = status.borrow().neighbors.get(&router_id).is_some_and(|n| {
        matches!(
            n.state,
            NeighborState::ExStart
                | NeighborState::Exchange
                | NeighborState::Loading
                | NeighborState::Full
        )
    });
    if !adjacent {
        return;
    }
    let now = Instant::now();
    status.send_modify(|s| {
        if let Some(n) = s.neighbors.get_mut(&router_id) {
            n.last_heard = now;
        }
    });
    if cfg.network_type == NetworkType::PointToPoint {
        *p2p_dead_deadline = now + Duration::from_secs(u64::from(cfg.dead_interval));
    }
}

/// Broadcast and point-to-multipoint. Ages out any neighbor whose `last_heard` is
/// older than `cfg.dead_interval` — see `run()`'s `ponytail:` note on why
/// this is a periodic sweep rather than per-neighbor timers.
pub(super) fn sweep_dead_neighbors(cfg: &LinkConfig, status: &StatusHandle) {
    let now = Instant::now();
    let dead_interval = Duration::from_secs(u64::from(cfg.dead_interval));
    let expired: Vec<Ipv4Addr> = status
        .borrow()
        .neighbors
        .iter()
        .filter(|(_, info)| {
            info.state != NeighborState::Down
                && info.grace_deadline.is_none()
                && now.duration_since(info.last_heard) >= dead_interval
        })
        .map(|(id, _)| *id)
        .collect();
    if expired.is_empty() {
        return;
    }
    for _ in &expired {
        warn!(link = %cfg.attach_point, "ospf neighbor state changed to down");
    }
    status.send_modify(|s| {
        for id in &expired {
            if let Some(info) = s.neighbors.get_mut(id) {
                info.state = neighbor::step(info.state, neighbor::Event::InactivityTimerExpired);
                info.adjacency = None;
            }
        }
    });
}
