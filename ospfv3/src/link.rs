//! One `OSPFv3` link's driver, plus `LinkManager` — the RFC 5340 counterpart
//! of `ospf::link`. Same orchestrator architecture (one raw socket per
//! link, neighbor FSM(s) from `nos_ospf_common::neighbor`, RFC 2328 §9.4
//! DR/BDR election from `nos_ospf_common::election`, then `crate::exchange`'s
//! DBD/LSR/LSU/LSAck adjacency-forming exchange), but every self-origination
//! function is structurally new (RFC 5340 restructures where addresses and
//! prefixes live — see `crate::spf`'s module doc comment), and there is no
//! authentication plumbing at all (RFC 5340 Phase 1 is unauthenticated — see
//! `crate::packet`'s doc comment).

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ipnet::Ipv6Net;
use nos_proto::{
    LinkInterfaceState, NetworkType, OspfNeighborState, Ospfv3LsaSummary, Ospfv3NeighborSummary,
};
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::election;
use crate::exchange::{self, AdjacencyData};
use crate::lsa::{
    self, IntraAreaPrefixEntry, IntraAreaPrefixLsaBody, LinkLsaBody, LinkPrefixEntry, Lsa, LsaBody,
    LsaHeader, LsaKey, NetworkLsaBody, RouterLsaBody, RouterLsaLink, LINK_TYPE_POINT_TO_POINT,
    LINK_TYPE_TRANSIT_NETWORK,
};
use crate::lsdb::Lsdb;
use crate::neighbor::{self, NeighborState};
use crate::packet::{self, DbdPacket, LsAckPacket, LsrPacket, LsuPacket, OspfPacket};
use crate::socket::OspfSocket;
use crate::spf;

/// RFC 2328 Appendix C.3's `RxmtInterval` — same fixed value/ponytail
/// rationale as `ospf::link::RXMT_INTERVAL`.
const RXMT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Same cadence/rationale as `ospf::link::ORIGINATION_INTERVAL`.
const ORIGINATION_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Same cadence/rationale as `ospf::link::AGE_TICK_INTERVAL`.
const AGE_TICK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// One link's fully-resolved desired state — diffed wholesale by
/// `LinkManager::reconcile`, mirroring `ospf::link::LinkConfig`.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkConfig {
    /// Display key, matching `reconcile::attach_points_for`'s
    /// `"<interface>.<tag>"`/`"broadcast-domain:<name>"` convention.
    pub attach_point: String,
    pub area_id: Ipv4Addr,
    pub hello_interval: u16,
    pub dead_interval: u16,
    pub vrf: String,
    /// The real Linux device this link's raw socket binds to — see
    /// `ospf::link::LinkConfig.kernel_interface`'s identical doc comment on
    /// why this is never the VRF device.
    pub kernel_interface: String,
    /// This link's RFC 5340 Interface ID — derived from the kernel
    /// interface's own ifindex (`libc::if_nametoindex`, resolved in
    /// `reconcile.rs`), doubling as the socket's multicast scope id (see
    /// `socket::OspfSocket::open`).
    pub interface_id: u32,
    /// This link's own kernel-assigned IPv6 link-local address — Hello and
    /// every self-originated Link-LSA are sourced from this.
    pub link_local_address: Ipv6Addr,
    /// This link's own configured global/ULA prefix, advertised via a
    /// Link-LSA (as this link's own prefix list) and, once self-originated,
    /// an Intra-Area-Prefix-LSA.
    pub prefix: Ipv6Net,
    pub cost: u16,
    pub network_type: NetworkType,
    pub priority: u8,
    pub mtu: u16,
}

/// RFC 5340 §4.5.1's interface states — mirrors `ospf::link::InterfaceState`
/// one-to-one (unchanged by RFC 5340).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceState {
    PointToPoint,
    Waiting,
    Dr,
    Backup,
    DrOther,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NeighborInfo {
    pub state: NeighborState,
    pub priority: u8,
    pub declared_dr: Ipv4Addr,
    pub declared_bdr: Ipv4Addr,
    /// This neighbor's own RFC 5340 Interface ID on this link, learned from
    /// its Hello — needed both for `crate::spf`'s next-hop derivation (a
    /// Router-LSA link's `Neighbor Interface ID` field) and to look up its
    /// own Link-LSA.
    pub interface_id: u32,
    pub last_hello_received: Instant,
    /// The neighbor's own link-local address, as seen on the last Hello it
    /// sent — DBD/LSR/LSU/LSAck reply unicast to this.
    pub address: Ipv6Addr,
    pub adjacency: Option<AdjacencyData>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LinkStatus {
    pub interface_state: InterfaceState,
    pub neighbors: HashMap<Ipv4Addr, NeighborInfo>,
    pub dr: Option<Ipv4Addr>,
    pub bdr: Option<Ipv4Addr>,
}

impl LinkStatus {
    fn new(network_type: NetworkType) -> Self {
        Self {
            interface_state: match network_type {
                NetworkType::PointToPoint => InterfaceState::PointToPoint,
                NetworkType::Broadcast => InterfaceState::Waiting,
            },
            neighbors: HashMap::new(),
            dr: None,
            bdr: None,
        }
    }
}

pub type StatusHandle = watch::Sender<LinkStatus>;

/// RFC 2328 §7.5/§10.4 (unchanged by RFC 5340) — mirrors
/// `ospf::link::should_form_adjacency` verbatim.
fn should_form_adjacency(
    interface_state: InterfaceState,
    neighbor_id: Ipv4Addr,
    dr: Option<Ipv4Addr>,
    bdr: Option<Ipv4Addr>,
) -> bool {
    matches!(
        interface_state,
        InterfaceState::PointToPoint | InterfaceState::Dr | InterfaceState::Backup
    ) || dr == Some(neighbor_id)
        || bdr == Some(neighbor_id)
}

/// Mirrors `ospf::link::initial_dd_sequence_number` verbatim.
fn initial_dd_sequence_number() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |d| d.subsec_nanos())
}

/// Builds a fresh `AdjacencyData` plus the negotiation DBD to send.
fn start_negotiation(cfg: &LinkConfig, local_router_id: Ipv4Addr) -> (AdjacencyData, DbdPacket) {
    let seed = initial_dd_sequence_number();
    let dbd = DbdPacket {
        router_id: local_router_id,
        area_id: cfg.area_id,
        options: 0,
        interface_mtu: cfg.mtu,
        init: true,
        more: true,
        master: true,
        dd_sequence_number: seed,
        lsa_headers: Vec::new(),
    };
    let adj = AdjacencyData {
        is_master: false,
        dd_sequence_number: seed,
        request_list: Vec::new(),
        retransmission_list: HashMap::new(),
        last_dbd_sent: Some(dbd.clone()),
        summary_remaining: std::collections::VecDeque::new(),
    };
    (adj, dbd)
}

/// Runs until aborted. Owns the raw socket, the Hello send ticker, and
/// every timer this link's network type needs — mirrors `ospf::link::run`'s
/// shape, minus all crypto-sequence/auth bookkeeping.
pub async fn run(
    cfg: LinkConfig,
    local_router_id: Ipv4Addr,
    lsdb: Arc<Mutex<Lsdb>>,
    status: StatusHandle,
    dbd_max_headers: Option<usize>,
) {
    let dbd_max_headers =
        dbd_max_headers.unwrap_or_else(|| exchange::mtu_based_max_headers(cfg.mtu));
    let socket = match OspfSocket::open(&cfg.kernel_interface, cfg.interface_id) {
        Ok(s) => s,
        Err(e) => {
            warn!(link = %cfg.attach_point, error = %e, "failed to open ospfv3 raw socket");
            return;
        }
    };

    let mut hello_ticker = tokio::time::interval(std::time::Duration::from_secs(u64::from(
        cfg.hello_interval,
    )));
    hello_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let is_broadcast = cfg.network_type == NetworkType::Broadcast;
    let mut p2p_dead_deadline =
        Instant::now() + std::time::Duration::from_secs(u64::from(cfg.dead_interval));
    let mut dead_sweep = tokio::time::interval(std::time::Duration::from_secs(1));
    dead_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let wait_deadline =
        Instant::now() + std::time::Duration::from_secs(u64::from(cfg.dead_interval));
    let mut waiting = is_broadcast;

    let mut rxmt_sweep = tokio::time::interval(RXMT_INTERVAL);
    rxmt_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    info!(link = %cfg.attach_point, vrf = %cfg.vrf, "ospfv3 link driver started");
    if is_broadcast {
        info!(link = %cfg.attach_point, "ospfv3 interface reached waiting");
    }

    loop {
        tokio::select! {
            _ = hello_ticker.tick() => {
                send_hello(&socket, &cfg, local_router_id, &status);
            }
            result = socket.recv_packet() => {
                match result {
                    Ok((source, data)) => {
                        match packet::decode(&data) {
                            Ok(OspfPacket::Hello(hello)) => {
                                let left_waiting = handle_hello(
                                    &cfg, local_router_id, &status, source, &hello,
                                    &mut p2p_dead_deadline, waiting,
                                );
                                if left_waiting {
                                    waiting = false;
                                }
                                advance_adjacencies(&socket, &cfg, local_router_id, &status);
                            }
                            Ok(OspfPacket::Dbd(dbd)) => {
                                if let Some(actions) = handle_dbd(
                                    &cfg, local_router_id, &status, &lsdb, &dbd, dbd_max_headers,
                                )
                                .await
                                {
                                    execute_actions(&socket, &cfg, local_router_id, &status, dbd.router_id, actions);
                                }
                            }
                            Ok(OspfPacket::Lsr(lsr)) => {
                                if let Some(actions) =
                                    handle_lsr(&cfg, local_router_id, &status, &lsdb, &lsr).await
                                {
                                    execute_actions(&socket, &cfg, local_router_id, &status, lsr.router_id, actions);
                                }
                            }
                            Ok(OspfPacket::Lsu(lsu)) => {
                                if let Some(actions) =
                                    handle_lsu(&cfg, local_router_id, &status, &lsdb, &lsu).await
                                {
                                    execute_actions(&socket, &cfg, local_router_id, &status, lsu.router_id, actions);
                                }
                            }
                            Ok(OspfPacket::LsAck(ack)) => {
                                handle_lsack(&status, &ack);
                            }
                            Err(e) => {
                                warn!(link = %cfg.attach_point, error = %e, "failed to decode ospfv3 packet");
                            }
                        }
                    }
                    Err(e) => warn!(link = %cfg.attach_point, error = %e, "ospfv3 recv error"),
                }
            }
            () = tokio::time::sleep_until(p2p_dead_deadline), if !is_broadcast => {
                apply_dead_timer(&cfg, &status);
                p2p_dead_deadline = Instant::now() + std::time::Duration::from_secs(u64::from(cfg.dead_interval));
            }
            _ = dead_sweep.tick(), if is_broadcast => {
                sweep_dead_neighbors(&cfg, &status);
                if !waiting {
                    run_election(&cfg, local_router_id, &status);
                    advance_adjacencies(&socket, &cfg, local_router_id, &status);
                }
            }
            () = tokio::time::sleep_until(wait_deadline), if waiting => {
                waiting = false;
                run_election(&cfg, local_router_id, &status);
                advance_adjacencies(&socket, &cfg, local_router_id, &status);
            }
            _ = rxmt_sweep.tick() => {
                retransmit_pending(&socket, &cfg, local_router_id, &status);
                flood_full_neighbors(&socket, &cfg, local_router_id, &lsdb, &status).await;
            }
        }
    }
}

fn send_hello(
    socket: &OspfSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
) {
    let current = status.borrow();
    let neighbors: Vec<Ipv4Addr> = current
        .neighbors
        .iter()
        .filter(|(_, info)| info.state != NeighborState::Down)
        .map(|(id, _)| *id)
        .collect();
    let (designated_router, backup_designated_router) = match cfg.network_type {
        NetworkType::PointToPoint => (Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED),
        NetworkType::Broadcast => (
            current.dr.unwrap_or(Ipv4Addr::UNSPECIFIED),
            current.bdr.unwrap_or(Ipv4Addr::UNSPECIFIED),
        ),
    };
    drop(current);

    let pkt = packet::HelloPacket {
        router_id: local_router_id,
        area_id: cfg.area_id,
        interface_id: cfg.interface_id,
        router_priority: cfg.priority,
        options: lsa::OPTION_V6 | lsa::OPTION_R,
        hello_interval: cfg.hello_interval,
        dead_interval: cfg.dead_interval,
        designated_router,
        backup_designated_router,
        neighbors,
    };
    if let Err(e) = socket.send_multicast(cfg.interface_id, &packet::encode_hello(&pkt)) {
        warn!(link = %cfg.attach_point, error = %e, "failed to send ospfv3 hello");
    }
}

/// Returns whether this Hello caused a broadcast link to leave `Waiting`
/// early — mirrors `ospf::link::handle_hello`'s shape, `source`/`address`
/// now `Ipv6Addr`, and records the neighbor's own `interface_id` from the
/// Hello (needed for SPF next-hop derivation, see `NeighborInfo`).
#[allow(clippy::too_many_arguments)]
fn handle_hello(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    source: Ipv6Addr,
    hello: &packet::HelloPacket,
    p2p_dead_deadline: &mut Instant,
    waiting: bool,
) -> bool {
    if hello.area_id != cfg.area_id {
        warn!(
            link = %cfg.attach_point, area = %hello.area_id, expected = %cfg.area_id,
            "dropping ospfv3 hello with mismatched area"
        );
        return false;
    }

    let saw_self = hello.neighbors.contains(&local_router_id);
    let old_state = status
        .borrow()
        .neighbors
        .get(&hello.router_id)
        .map_or(NeighborState::Down, |n| n.state);
    let new_state = neighbor::step(old_state, neighbor::Event::HelloReceived { saw_self });
    if old_state == NeighborState::Down && new_state == NeighborState::Init {
        info!(link = %cfg.attach_point, neighbor = %hello.router_id, "ospfv3 neighbor state changed to init");
    }
    if old_state != NeighborState::TwoWay && new_state == NeighborState::TwoWay {
        info!(link = %cfg.attach_point, neighbor = %hello.router_id, "ospfv3 neighbor reached two-way");
    }
    if old_state != NeighborState::Init
        && new_state == NeighborState::Init
        && old_state != NeighborState::Down
    {
        warn!(link = %cfg.attach_point, neighbor = %hello.router_id, "ospfv3 neighbor adjacency torn down, back to init");
    }
    status.send_modify(|s| {
        let entry = s
            .neighbors
            .entry(hello.router_id)
            .or_insert_with(|| NeighborInfo {
                state: NeighborState::Down,
                priority: 0,
                declared_dr: Ipv4Addr::UNSPECIFIED,
                declared_bdr: Ipv4Addr::UNSPECIFIED,
                interface_id: hello.interface_id,
                last_hello_received: Instant::now(),
                address: source,
                adjacency: None,
            });
        entry.state = new_state;
        entry.priority = hello.router_priority;
        entry.declared_dr = hello.designated_router;
        entry.declared_bdr = hello.backup_designated_router;
        entry.interface_id = hello.interface_id;
        entry.last_hello_received = Instant::now();
        entry.address = source;
        if matches!(new_state, NeighborState::Down | NeighborState::Init) {
            entry.adjacency = None;
        }
    });

    match cfg.network_type {
        NetworkType::PointToPoint => {
            *p2p_dead_deadline =
                Instant::now() + std::time::Duration::from_secs(u64::from(cfg.dead_interval));
            false
        }
        NetworkType::Broadcast if waiting && hello.designated_router == hello.router_id => {
            run_election(cfg, local_router_id, status);
            true
        }
        NetworkType::Broadcast if !waiting => {
            run_election(cfg, local_router_id, status);
            false
        }
        NetworkType::Broadcast => false,
    }
}

fn advance_adjacencies(
    socket: &OspfSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
) {
    let snapshot = status.borrow().clone();
    let eligible: Vec<Ipv4Addr> = snapshot
        .neighbors
        .iter()
        .filter(|(id, info)| {
            info.state == NeighborState::TwoWay
                && info.adjacency.is_none()
                && should_form_adjacency(snapshot.interface_state, **id, snapshot.dr, snapshot.bdr)
        })
        .map(|(id, _)| *id)
        .collect();
    drop(snapshot);

    for neighbor_id in eligible {
        let Some(neighbor_addr) = status
            .borrow()
            .neighbors
            .get(&neighbor_id)
            .map(|n| n.address)
        else {
            continue;
        };
        let (adj, dbd) = start_negotiation(cfg, local_router_id);
        if let Err(e) =
            socket.send_unicast(neighbor_addr, cfg.interface_id, &packet::encode_dbd(&dbd))
        {
            warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospfv3 dbd");
        }
        let new_state = neighbor::step(NeighborState::TwoWay, neighbor::Event::AdjacencyEligible);
        info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospfv3 neighbor reached exstart");
        status.send_modify(|s| {
            if let Some(info) = s.neighbors.get_mut(&neighbor_id) {
                info.state = new_state;
                info.adjacency = Some(adj);
            }
        });
    }
}

async fn handle_dbd(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    lsdb: &Mutex<Lsdb>,
    dbd: &DbdPacket,
    dbd_max_headers: usize,
) -> Option<Vec<exchange::Action>> {
    let (old_state, mut adj) = {
        let snapshot = status.borrow();
        let neighbor = snapshot.neighbors.get(&dbd.router_id)?;
        (neighbor.state, neighbor.adjacency.clone()?)
    };

    let local_lsdb_headers = lsdb.lock().await.headers();
    let actions = exchange::on_dbd_received(
        &mut adj,
        old_state,
        local_router_id,
        dbd.router_id,
        dbd,
        &local_lsdb_headers,
        dbd_max_headers,
        cfg.mtu,
    );

    Some(finish_neighbor_event(
        cfg,
        local_router_id,
        status,
        dbd.router_id,
        old_state,
        adj,
        actions,
    ))
}

async fn handle_lsr(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    lsdb: &Mutex<Lsdb>,
    lsr: &LsrPacket,
) -> Option<Vec<exchange::Action>> {
    let (old_state, mut adj) = {
        let snapshot = status.borrow();
        let neighbor = snapshot.neighbors.get(&lsr.router_id)?;
        (neighbor.state, neighbor.adjacency.clone()?)
    };

    let actions = {
        let lsdb = lsdb.lock().await;
        exchange::on_lsr_received(&mut adj, &lsdb, lsr)
    };

    Some(finish_neighbor_event(
        cfg,
        local_router_id,
        status,
        lsr.router_id,
        old_state,
        adj,
        actions,
    ))
}

async fn handle_lsu(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    lsdb: &Mutex<Lsdb>,
    lsu: &LsuPacket,
) -> Option<Vec<exchange::Action>> {
    let (old_state, mut adj) = {
        let snapshot = status.borrow();
        let neighbor = snapshot.neighbors.get(&lsu.router_id)?;
        (neighbor.state, neighbor.adjacency.clone()?)
    };

    let (actions, newly_installed) = {
        let mut lsdb = lsdb.lock().await;
        exchange::on_lsu_received(&mut adj, &mut lsdb, lsu)
    };
    for header in &newly_installed {
        info!(
            link = %cfg.attach_point, neighbor = %lsu.router_id,
            lsa_type = header.lsa_type, link_state_id = %header.link_state_id,
            advertising_router = %header.advertising_router,
            "ospfv3 lsa installed"
        );
    }

    Some(finish_neighbor_event(
        cfg,
        local_router_id,
        status,
        lsu.router_id,
        old_state,
        adj,
        actions,
    ))
}

fn handle_lsack(status: &StatusHandle, ack: &LsAckPacket) {
    let Some(mut adj) = status
        .borrow()
        .neighbors
        .get(&ack.router_id)
        .and_then(|n| n.adjacency.clone())
    else {
        return;
    };
    exchange::on_lsack_received(&mut adj, ack);
    status.send_modify(|s| {
        if let Some(info) = s.neighbors.get_mut(&ack.router_id) {
            info.adjacency = Some(adj.clone());
        }
    });
}

fn finish_neighbor_event(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    neighbor_id: Ipv4Addr,
    old_state: NeighborState,
    mut adj: AdjacencyData,
    actions: Vec<exchange::Action>,
) -> Vec<exchange::Action> {
    let mut new_state = old_state;
    for action in &actions {
        if let exchange::Action::NeighborEvent(event) = action {
            new_state = neighbor::step(new_state, *event);
        }
    }

    let actions = if new_state == NeighborState::ExStart && old_state != NeighborState::ExStart {
        let (fresh_adj, negotiation_dbd) = start_negotiation(cfg, local_router_id);
        adj = fresh_adj;
        warn!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospfv3 neighbor sequence mismatch, restarting negotiation");
        vec![exchange::Action::SendDbd(negotiation_dbd)]
    } else {
        for action in &actions {
            if let exchange::Action::SendDbd(pkt) = action {
                adj.last_dbd_sent = Some(pkt.clone());
            }
        }
        if matches!(new_state, NeighborState::Loading | NeighborState::Full) {
            adj.last_dbd_sent = None;
        }
        actions
    };

    match (old_state, new_state) {
        (s, NeighborState::Exchange) if s != NeighborState::Exchange => {
            info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospfv3 neighbor reached exchange");
        }
        (s, NeighborState::Loading) if s != NeighborState::Loading => {
            info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospfv3 neighbor reached loading");
        }
        (s, NeighborState::Full) if s != NeighborState::Full => {
            info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospfv3 neighbor reached full");
        }
        _ => {}
    }

    status.send_modify(|s| {
        if let Some(info) = s.neighbors.get_mut(&neighbor_id) {
            info.state = new_state;
            info.adjacency = Some(adj.clone());
        }
    });

    actions
}

fn execute_actions(
    socket: &OspfSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    neighbor_id: Ipv4Addr,
    actions: Vec<exchange::Action>,
) {
    let Some(neighbor_addr) = status
        .borrow()
        .neighbors
        .get(&neighbor_id)
        .map(|n| n.address)
    else {
        return;
    };
    for action in actions {
        let (kind, payload) = match action {
            exchange::Action::SendDbd(pkt) => {
                if !pkt.init && pkt.more {
                    info!(
                        link = %cfg.attach_point, neighbor = %neighbor_id,
                        dd_sequence_number = pkt.dd_sequence_number,
                        "ospfv3 dbd chunk sent, more remaining"
                    );
                }
                ("dbd", packet::encode_dbd(&pkt))
            }
            exchange::Action::SendLsr(requests) => (
                "lsr",
                packet::encode_lsr(&LsrPacket {
                    router_id: local_router_id,
                    area_id: cfg.area_id,
                    requests,
                }),
            ),
            exchange::Action::SendLsu(lsas) => (
                "lsu",
                packet::encode_lsu(&LsuPacket {
                    router_id: local_router_id,
                    area_id: cfg.area_id,
                    lsas: lsas.iter().map(|l| (**l).clone()).collect(),
                }),
            ),
            exchange::Action::SendLsAck(lsa_headers) => (
                "lsack",
                packet::encode_lsack(&LsAckPacket {
                    router_id: local_router_id,
                    area_id: cfg.area_id,
                    lsa_headers,
                }),
            ),
            exchange::Action::NeighborEvent(_) => continue,
        };
        if let Err(e) = socket.send_unicast(neighbor_addr, cfg.interface_id, &payload) {
            warn!(link = %cfg.attach_point, neighbor = %neighbor_id, kind, error = %e, "failed to send ospfv3 packet");
        }
    }
}

fn retransmit_pending(
    socket: &OspfSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
) {
    let snapshot = status.borrow().clone();
    for (neighbor_id, info) in &snapshot.neighbors {
        let Some(adj) = &info.adjacency else { continue };
        if let Some(dbd) = &adj.last_dbd_sent {
            if let Err(e) =
                socket.send_unicast(info.address, cfg.interface_id, &packet::encode_dbd(dbd))
            {
                warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospfv3 dbd");
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
            if let Err(e) =
                socket.send_unicast(info.address, cfg.interface_id, &packet::encode_lsr(&lsr))
            {
                warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospfv3 lsr");
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
            if let Err(e) =
                socket.send_unicast(info.address, cfg.interface_id, &packet::encode_lsu(&lsu))
            {
                warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospfv3 lsu");
            }
        }
    }
}

/// Mirrors `ospf::link::flood_full_neighbors`'s `ponytail:` periodic-resend
/// design exactly, same rationale.
async fn flood_full_neighbors(
    socket: &OspfSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    lsdb: &Mutex<Lsdb>,
    status: &StatusHandle,
) {
    let full_neighbors: Vec<(Ipv4Addr, Ipv6Addr)> = status
        .borrow()
        .neighbors
        .iter()
        .filter(|(_, info)| info.state == NeighborState::Full)
        .map(|(id, info)| (*id, info.address))
        .collect();
    if full_neighbors.is_empty() {
        return;
    }
    let lsas = lsdb.lock().await.all();
    if lsas.is_empty() {
        return;
    }
    let payload = packet::encode_lsu(&LsuPacket {
        router_id: local_router_id,
        area_id: cfg.area_id,
        lsas: lsas.iter().map(|l| (**l).clone()).collect(),
    });
    for (neighbor_id, neighbor_addr) in full_neighbors {
        if let Err(e) = socket.send_unicast(neighbor_addr, cfg.interface_id, &payload) {
            warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospfv3 lsu");
        }
    }
}

fn apply_dead_timer(cfg: &LinkConfig, status: &StatusHandle) {
    let Some(old_state) = status.borrow().neighbors.values().next().map(|n| n.state) else {
        return;
    };
    if old_state != NeighborState::Down {
        warn!(link = %cfg.attach_point, "ospfv3 neighbor state changed to down");
    }
    let new_state = neighbor::step(old_state, neighbor::Event::InactivityTimerExpired);
    status.send_modify(|s| {
        for info in s.neighbors.values_mut() {
            info.state = new_state;
            info.adjacency = None;
        }
    });
}

fn sweep_dead_neighbors(cfg: &LinkConfig, status: &StatusHandle) {
    let now = Instant::now();
    let dead_interval = std::time::Duration::from_secs(u64::from(cfg.dead_interval));
    let expired: Vec<Ipv4Addr> = status
        .borrow()
        .neighbors
        .iter()
        .filter(|(_, info)| {
            info.state != NeighborState::Down
                && now.duration_since(info.last_hello_received) >= dead_interval
        })
        .map(|(id, _)| *id)
        .collect();
    if expired.is_empty() {
        return;
    }
    for _ in &expired {
        warn!(link = %cfg.attach_point, "ospfv3 neighbor state changed to down");
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

fn run_election(cfg: &LinkConfig, local_router_id: Ipv4Addr, status: &StatusHandle) {
    let snapshot = status.borrow().clone();
    let self_candidate = election::Candidate {
        router_id: local_router_id,
        priority: cfg.priority,
        declared_dr: snapshot.dr.unwrap_or(Ipv4Addr::UNSPECIFIED),
        declared_bdr: snapshot.bdr.unwrap_or(Ipv4Addr::UNSPECIFIED),
    };
    let neighbor_candidates: Vec<election::Candidate> = snapshot
        .neighbors
        .iter()
        .filter(|(_, info)| {
            matches!(
                info.state,
                NeighborState::TwoWay
                    | NeighborState::ExStart
                    | NeighborState::Exchange
                    | NeighborState::Loading
                    | NeighborState::Full
            )
        })
        .map(|(id, info)| election::Candidate {
            router_id: *id,
            priority: info.priority,
            declared_dr: info.declared_dr,
            declared_bdr: info.declared_bdr,
        })
        .collect();
    let result = election::elect(self_candidate, &neighbor_candidates);

    let new_interface_state = if result.dr == Some(local_router_id) {
        InterfaceState::Dr
    } else if result.bdr == Some(local_router_id) {
        InterfaceState::Backup
    } else {
        InterfaceState::DrOther
    };

    // Re-logs whenever the reported role *or* the dr/bdr router-ids behind
    // it change — not just on an `InterfaceState` variant change. Mirrors
    // `ospf::link::run_election`'s identical fix; see its own doc comment
    // for the full rationale (a router can stay `DrOther`/`Backup` across
    // more than one election pass while a neighbor's declared role is
    // still converging, which would otherwise freeze the log on a stale,
    // not-yet-converged dr/bdr pair).
    if (snapshot.interface_state, snapshot.dr, snapshot.bdr)
        != (new_interface_state, result.dr, result.bdr)
    {
        match new_interface_state {
            InterfaceState::Dr => {
                info!(link = %cfg.attach_point, dr = %local_router_id, "ospfv3 interface became dr");
            }
            InterfaceState::Backup => {
                info!(
                    link = %cfg.attach_point,
                    dr = %result.dr.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    bdr = %local_router_id,
                    "ospfv3 interface became backup"
                );
            }
            InterfaceState::DrOther => {
                info!(
                    link = %cfg.attach_point,
                    dr = %result.dr.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    bdr = %result.bdr.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    "ospfv3 interface became dr-other"
                );
            }
            InterfaceState::Waiting | InterfaceState::PointToPoint => {
                unreachable!("election never produces Waiting/PointToPoint")
            }
        }
    }

    status.send_modify(|s| {
        s.dr = result.dr;
        s.bdr = result.bdr;
        s.interface_state = new_interface_state;
    });
}

struct LinkEntry {
    config: LinkConfig,
    task: JoinHandle<()>,
    status: watch::Receiver<LinkStatus>,
}

/// Owns every `OSPFv3` link's driver task for one `nos-ospfv3d` process, plus
/// its per-area LSDBs — mirrors `ospf::link::LinkManager`, minus every
/// ASBR/ABR/redistribute field (out of scope for Phase 1).
pub struct LinkManager {
    links: Mutex<HashMap<String, LinkEntry>>,
    lsdbs: Mutex<HashMap<Ipv4Addr, Arc<Mutex<Lsdb>>>>,
    router_id: Mutex<Option<Ipv4Addr>>,
    /// Loopback (`Interface.ospfv3_profile`) attach points' own prefixes,
    /// per area — no live `LinkConfig`/socket for these (see
    /// `reconcile.rs`'s "log-only" loopback handling), so threaded in
    /// directly, purely so `originate_intra_area_prefix_lsas` can advertise
    /// each one as part of this router's own router-referenced prefix set.
    loopback_prefixes: Mutex<HashMap<Ipv4Addr, Vec<(Ipv6Net, u16)>>>,
    age_multiplier: u16,
    /// `Some` only from `--dbd-max-headers` (test/debug); `None` derives it per link from its MTU.
    dbd_max_headers: Option<usize>,
    /// RFC 8362 Full mode: originate the extended (TLV) LSA set instead of
    /// the legacy one. ponytail: no Sparse mode, and legacy LSAs from before
    /// a toggle are simply left to age out rather than flushed early.
    extended_lsa: AtomicBool,
}

/// The four LS types this router originates, per RFC 8362 mode.
struct LsaTypes {
    router: u16,
    network: u16,
    link: u16,
    intra_area_prefix: u16,
}

impl LsaTypes {
    fn new(extended: bool) -> Self {
        if extended {
            Self {
                router: lsa::LSA_TYPE_E_ROUTER,
                network: lsa::LSA_TYPE_E_NETWORK,
                link: lsa::LSA_TYPE_E_LINK,
                intra_area_prefix: lsa::LSA_TYPE_E_INTRA_AREA_PREFIX,
            }
        } else {
            Self {
                router: lsa::LSA_TYPE_ROUTER,
                network: lsa::LSA_TYPE_NETWORK,
                link: lsa::LSA_TYPE_LINK,
                intra_area_prefix: lsa::LSA_TYPE_INTRA_AREA_PREFIX,
            }
        }
    }
}

impl LinkManager {
    /// Switches between legacy and RFC 8362 extended LSA origination; takes
    /// effect at the next origination tick.
    pub fn set_extended_lsa(&self, extended: bool) {
        self.extended_lsa.store(extended, Ordering::Relaxed);
    }

    fn lsa_types(&self) -> LsaTypes {
        LsaTypes::new(self.extended_lsa.load(Ordering::Relaxed))
    }

    pub fn new(age_multiplier: u16, dbd_max_headers: Option<usize>) -> Arc<Self> {
        let manager = Arc::new(Self {
            links: Mutex::new(HashMap::new()),
            lsdbs: Mutex::new(HashMap::new()),
            router_id: Mutex::new(None),
            loopback_prefixes: Mutex::new(HashMap::new()),
            age_multiplier,
            dbd_max_headers,
            extended_lsa: AtomicBool::new(false),
        });
        let background = Arc::clone(&manager);
        tokio::spawn(async move {
            let mut origination_tick = tokio::time::interval(ORIGINATION_INTERVAL);
            origination_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut age_tick = tokio::time::interval(AGE_TICK_INTERVAL);
            age_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = origination_tick.tick() => {
                        if let Some(router_id) = *background.router_id.lock().await {
                            background.originate_router_lsas(router_id).await;
                            background.originate_link_lsas(router_id).await;
                            background.originate_intra_area_prefix_lsas(router_id).await;
                        }
                    }
                    _ = age_tick.tick() => {
                        background.age_lsdbs().await;
                    }
                }
            }
        });
        manager
    }

    async fn lsdb_for(&self, area_id: Ipv4Addr) -> Arc<Mutex<Lsdb>> {
        Arc::clone(
            self.lsdbs
                .lock()
                .await
                .entry(area_id)
                .or_insert_with(|| Arc::new(Mutex::new(Lsdb::new()))),
        )
    }

    async fn age_lsdbs(&self) {
        let areas: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(area_id, lsdb)| (*area_id, Arc::clone(lsdb)))
            .collect();
        for (area_id, lsdb) in areas {
            let evicted = lsdb.lock().await.age_and_evict(self.age_multiplier);
            for key in evicted {
                info!(
                    area = %area_id, lsa_type = key.lsa_type, link_state_id = %key.link_state_id,
                    advertising_router = %key.advertising_router,
                    "ospfv3 lsa maxage flushed"
                );
            }
        }
    }

    /// Recomputes and (re)installs this router's own Router-LSA per area —
    /// pure topology only, no addresses (see the module doc comment).
    async fn originate_router_lsas(&self, local_router_id: Ipv4Addr) {
        let snapshot: Vec<(LinkConfig, LinkStatus)> = self
            .links
            .lock()
            .await
            .values()
            .map(|e| (e.config.clone(), e.status.borrow().clone()))
            .collect();

        let mut by_area: HashMap<Ipv4Addr, Vec<(LinkConfig, LinkStatus)>> = HashMap::new();
        for (cfg, status) in snapshot {
            by_area.entry(cfg.area_id).or_default().push((cfg, status));
        }
        let loopback_areas: HashSet<Ipv4Addr> = self
            .loopback_prefixes
            .lock()
            .await
            .keys()
            .copied()
            .collect();
        let area_ids: HashSet<Ipv4Addr> = by_area.keys().copied().chain(loopback_areas).collect();

        let types = self.lsa_types();
        for area_id in area_ids {
            let links = by_area.get(&area_id).cloned().unwrap_or_default();
            let lsdb = self.lsdb_for(area_id).await;
            let mut lsdb = lsdb.lock().await;

            let router_links = router_lsa_links(local_router_id, &links);
            install_self_originated(
                &mut lsdb,
                local_router_id,
                types.router,
                local_router_id,
                LsaBody::Router(RouterLsaBody {
                    flags: 0,
                    options: lsa::OPTION_V6 | lsa::OPTION_R,
                    links: router_links,
                }),
            );

            for (cfg, status) in &links {
                if cfg.network_type != NetworkType::Broadcast
                    || status.interface_state != InterfaceState::Dr
                {
                    continue;
                }
                let full_neighbors: Vec<Ipv4Addr> = status
                    .neighbors
                    .iter()
                    .filter(|(_, n)| n.state == NeighborState::Full)
                    .map(|(id, _)| *id)
                    .collect();
                if full_neighbors.is_empty() {
                    continue;
                }
                let attached: Vec<Ipv4Addr> = std::iter::once(local_router_id)
                    .chain(full_neighbors)
                    .collect();
                install_self_originated(
                    &mut lsdb,
                    local_router_id,
                    types.network,
                    lsa::interface_id_key(cfg.interface_id),
                    LsaBody::Network(NetworkLsaBody {
                        options: lsa::OPTION_V6 | lsa::OPTION_R,
                        attached_routers: attached,
                    }),
                );
            }
        }
    }

    /// One Link-LSA per live link, unconditionally (RFC 5340 §7.3) —
    /// advertises this router's own link-local address and configured
    /// prefix on that link. See the module doc comment for why this crate
    /// stores it in the same shared per-area `Lsdb` as area-scoped LSAs
    /// rather than a separate per-link store.
    async fn originate_link_lsas(&self, local_router_id: Ipv4Addr) {
        let snapshot: Vec<LinkConfig> = self
            .links
            .lock()
            .await
            .values()
            .map(|e| e.config.clone())
            .collect();
        let types = self.lsa_types();
        for cfg in snapshot {
            let lsdb = self.lsdb_for(cfg.area_id).await;
            let mut lsdb = lsdb.lock().await;
            install_self_originated(
                &mut lsdb,
                local_router_id,
                types.link,
                lsa::interface_id_key(cfg.interface_id),
                LsaBody::Link(LinkLsaBody {
                    priority: cfg.priority,
                    options: lsa::OPTION_V6 | lsa::OPTION_R,
                    link_local_address: cfg.link_local_address,
                    prefixes: vec![LinkPrefixEntry {
                        options: 0,
                        prefix: cfg.prefix,
                    }],
                }),
            );
        }
    }

    /// This router's own Intra-Area-Prefix-LSA (referencing its own
    /// Router-LSA: every point-to-point link's own prefix, plus every
    /// loopback prefix) and, per broadcast link where a Network-LSA was
    /// actually originated, a second Intra-Area-Prefix-LSA referencing that
    /// Network-LSA with the link's own transit prefix.
    async fn originate_intra_area_prefix_lsas(&self, local_router_id: Ipv4Addr) {
        let snapshot: Vec<(LinkConfig, LinkStatus)> = self
            .links
            .lock()
            .await
            .values()
            .map(|e| (e.config.clone(), e.status.borrow().clone()))
            .collect();
        let mut by_area: HashMap<Ipv4Addr, Vec<(LinkConfig, LinkStatus)>> = HashMap::new();
        for (cfg, status) in snapshot {
            by_area.entry(cfg.area_id).or_default().push((cfg, status));
        }
        let loopback_prefixes = self.loopback_prefixes.lock().await.clone();
        let area_ids: HashSet<Ipv4Addr> = by_area
            .keys()
            .copied()
            .chain(loopback_prefixes.keys().copied())
            .collect();

        let types = self.lsa_types();
        for area_id in area_ids {
            let links = by_area.get(&area_id).cloned().unwrap_or_default();
            let lsdb = self.lsdb_for(area_id).await;
            let mut lsdb = lsdb.lock().await;

            let mut router_prefixes: Vec<IntraAreaPrefixEntry> = links
                .iter()
                .filter(|(cfg, _)| cfg.network_type == NetworkType::PointToPoint)
                .map(|(cfg, _)| IntraAreaPrefixEntry {
                    options: 0,
                    metric: cfg.cost,
                    prefix: cfg.prefix,
                })
                .collect();
            for (prefix, cost) in loopback_prefixes.get(&area_id).into_iter().flatten() {
                router_prefixes.push(IntraAreaPrefixEntry {
                    options: 0,
                    metric: *cost,
                    prefix: *prefix,
                });
            }
            if !router_prefixes.is_empty() {
                install_self_originated(
                    &mut lsdb,
                    local_router_id,
                    types.intra_area_prefix,
                    Ipv4Addr::UNSPECIFIED,
                    LsaBody::IntraAreaPrefix(IntraAreaPrefixLsaBody {
                        referenced_ls_type: types.router,
                        referenced_link_state_id: local_router_id,
                        referenced_advertising_router: local_router_id,
                        prefixes: router_prefixes,
                    }),
                );
            }

            for (cfg, status) in &links {
                if cfg.network_type != NetworkType::Broadcast
                    || status.interface_state != InterfaceState::Dr
                {
                    continue;
                }
                let has_full_neighbor = status
                    .neighbors
                    .values()
                    .any(|n| n.state == NeighborState::Full);
                if !has_full_neighbor {
                    continue;
                }
                let network_key = lsa::interface_id_key(cfg.interface_id);
                install_self_originated(
                    &mut lsdb,
                    local_router_id,
                    types.intra_area_prefix,
                    network_key,
                    LsaBody::IntraAreaPrefix(IntraAreaPrefixLsaBody {
                        referenced_ls_type: types.network,
                        referenced_link_state_id: network_key,
                        referenced_advertising_router: local_router_id,
                        prefixes: vec![IntraAreaPrefixEntry {
                            options: 0,
                            metric: 0,
                            prefix: cfg.prefix,
                        }],
                    }),
                );
            }
        }
    }

    /// Diffs `desired` against currently-running links — mirrors
    /// `ospf::link::LinkManager::reconcile` exactly.
    pub async fn reconcile(
        self: &Arc<Self>,
        desired: Vec<LinkConfig>,
        desired_loopback_prefixes: HashMap<Ipv4Addr, Vec<(Ipv6Net, u16)>>,
        local_router_id: Ipv4Addr,
    ) {
        *self.router_id.lock().await = Some(local_router_id);
        *self.loopback_prefixes.lock().await = desired_loopback_prefixes;

        let mut links = self.links.lock().await;
        links.retain(|_, entry| !entry.task.is_finished());

        let current: HashMap<String, LinkConfig> = links
            .iter()
            .map(|(k, entry)| (k.clone(), entry.config.clone()))
            .collect();
        let desired_map: HashMap<String, LinkConfig> = desired
            .into_iter()
            .map(|c| (c.attach_point.clone(), c))
            .collect();
        let (to_stop, to_spawn) = diff_links(&current, &desired_map);

        for key in &to_stop {
            if let Some(entry) = links.remove(key) {
                entry.task.abort();
            }
        }
        for cfg in to_spawn {
            let key = cfg.attach_point.clone();
            let lsdb = self.lsdb_for(cfg.area_id).await;
            let (status_tx, status_rx) = watch::channel(LinkStatus::new(cfg.network_type));
            let task = tokio::spawn(run(
                cfg.clone(),
                local_router_id,
                lsdb,
                status_tx,
                self.dbd_max_headers,
            ));
            links.insert(
                key,
                LinkEntry {
                    config: cfg,
                    task,
                    status: status_rx,
                },
            );
        }
    }

    pub async fn neighbor_summaries(&self) -> Vec<Ospfv3NeighborSummary> {
        self.links
            .lock()
            .await
            .values()
            .flat_map(to_neighbor_summaries)
            .collect()
    }

    pub async fn database_summaries(&self) -> Vec<Ospfv3LsaSummary> {
        let mut result = Vec::new();
        for (area_id, lsdb) in self.lsdbs.lock().await.iter() {
            for header in lsdb.lock().await.headers() {
                result.push(Ospfv3LsaSummary {
                    area_id: *area_id,
                    lsa_type: header.lsa_type,
                    link_state_id: header.link_state_id,
                    advertising_router: header.advertising_router,
                    sequence_number: header.sequence_number,
                    age: header.age,
                    checksum: header.checksum,
                });
            }
        }
        result
    }

    /// Runs `crate::spf::compute` against every area's current LSDB and
    /// merges the results — mirrors `ospf::link::LinkManager::compute_routes`.
    pub async fn compute_routes(&self) -> Vec<spf::RouteEntry> {
        let Some(router_id) = *self.router_id.lock().await else {
            return Vec::new();
        };
        let areas: Vec<Arc<Mutex<Lsdb>>> = self.lsdbs.lock().await.values().cloned().collect();
        let mut merged: HashMap<Ipv6Net, spf::RouteEntry> = HashMap::new();
        for lsdb in areas {
            let lsas = lsdb.lock().await.all();
            for entry in spf::compute(router_id, &lsas) {
                merged
                    .entry(entry.prefix)
                    .and_modify(|existing| {
                        if entry.metric < existing.metric {
                            *existing = entry.clone();
                        }
                    })
                    .or_insert(entry);
            }
        }
        merged.into_values().collect()
    }

    pub async fn shutdown(&self) {
        for (_, entry) in self.links.lock().await.drain() {
            entry.task.abort();
        }
    }
}

fn to_interface_state(state: InterfaceState) -> LinkInterfaceState {
    match state {
        InterfaceState::PointToPoint => LinkInterfaceState::PointToPoint,
        InterfaceState::Waiting => LinkInterfaceState::Waiting,
        InterfaceState::Dr => LinkInterfaceState::Dr,
        InterfaceState::Backup => LinkInterfaceState::Backup,
        InterfaceState::DrOther => LinkInterfaceState::DrOther,
    }
}

fn to_neighbor_state(state: NeighborState) -> OspfNeighborState {
    match state {
        NeighborState::Down => OspfNeighborState::Down,
        NeighborState::Init => OspfNeighborState::Init,
        NeighborState::TwoWay => OspfNeighborState::TwoWay,
        NeighborState::ExStart => OspfNeighborState::ExStart,
        NeighborState::Exchange => OspfNeighborState::Exchange,
        NeighborState::Loading => OspfNeighborState::Loading,
        NeighborState::Full => OspfNeighborState::Full,
    }
}

fn to_neighbor_summaries(entry: &LinkEntry) -> Vec<Ospfv3NeighborSummary> {
    let status = entry.status.borrow().clone();
    let interface_state = to_interface_state(status.interface_state);

    if status.neighbors.is_empty() {
        if entry.config.network_type == NetworkType::Broadcast {
            return Vec::new();
        }
        return vec![Ospfv3NeighborSummary {
            link: entry.config.attach_point.clone(),
            area_id: entry.config.area_id,
            interface_state,
            neighbor_router_id: None,
            state: OspfNeighborState::Down,
            last_hello_secs: None,
            hello_interval: entry.config.hello_interval,
            dead_interval: entry.config.dead_interval,
            priority: entry.config.priority,
            neighbor_priority: None,
            dr: status.dr,
            bdr: status.bdr,
        }];
    }

    status
        .neighbors
        .iter()
        .map(|(id, info)| Ospfv3NeighborSummary {
            link: entry.config.attach_point.clone(),
            area_id: entry.config.area_id,
            interface_state,
            neighbor_router_id: Some(*id),
            state: to_neighbor_state(info.state),
            last_hello_secs: Some(info.last_hello_received.elapsed().as_secs()),
            hello_interval: entry.config.hello_interval,
            dead_interval: entry.config.dead_interval,
            priority: entry.config.priority,
            neighbor_priority: Some(info.priority),
            dr: status.dr,
            bdr: status.bdr,
        })
        .collect()
}

/// RFC 5340 §4.4.3.2's Router-LSA link entries for every currently-running
/// link in one area — one point-to-point entry per link with at least one
/// neighbor, one transit-network entry per link with a resolved DR. Unlike
/// `ospf::link::router_lsa_links`, never a stub-network entry: v3's
/// Router-LSA has nowhere to carry a prefix at all (see the module doc
/// comment) — every prefix instead comes from
/// `LinkManager::originate_intra_area_prefix_lsas`.
fn router_lsa_links(
    local_router_id: Ipv4Addr,
    links: &[(LinkConfig, LinkStatus)],
) -> Vec<RouterLsaLink> {
    let mut result = Vec::new();
    for (cfg, status) in links {
        match cfg.network_type {
            NetworkType::PointToPoint => {
                if let Some((neighbor_id, info)) = status
                    .neighbors
                    .iter()
                    .find(|(_, n)| n.state != NeighborState::Down)
                {
                    result.push(RouterLsaLink {
                        link_type: LINK_TYPE_POINT_TO_POINT,
                        metric: cfg.cost,
                        interface_id: cfg.interface_id,
                        neighbor_interface_id: info.interface_id,
                        neighbor_router_id: *neighbor_id,
                    });
                }
            }
            NetworkType::Broadcast => {
                let Some(dr) = status.dr else { continue };
                let (dr_router_id, dr_interface_id) = if dr == local_router_id {
                    (local_router_id, cfg.interface_id)
                } else {
                    match status.neighbors.get(&dr) {
                        Some(n) => (dr, n.interface_id),
                        None => continue,
                    }
                };
                result.push(RouterLsaLink {
                    link_type: LINK_TYPE_TRANSIT_NETWORK,
                    metric: cfg.cost,
                    interface_id: cfg.interface_id,
                    neighbor_interface_id: dr_interface_id,
                    neighbor_router_id: dr_router_id,
                });
            }
        }
    }
    result
}

/// Installs a self-originated LSA if `body` actually changed since what's
/// held, bumping the sequence number by one — mirrors
/// `ospf::link::install_self_originated` exactly, minus the `options`
/// header field (v3's header carries none — see `lsa::LsaHeader`).
fn install_self_originated(
    lsdb: &mut Lsdb,
    local_router_id: Ipv4Addr,
    lsa_type: u16,
    link_state_id: Ipv4Addr,
    body: LsaBody,
) {
    let key = LsaKey {
        lsa_type,
        link_state_id,
        advertising_router: local_router_id,
    };
    let existing = lsdb.get(&key);
    let needs_refresh = existing
        .as_ref()
        .is_some_and(|e| e.header.age >= lsa::LS_REFRESH_TIME);
    let sequence_number = match &existing {
        Some(e) if e.body == body && !needs_refresh => return,
        Some(e) => e.header.sequence_number.wrapping_add(1),
        None => lsa::INITIAL_SEQUENCE_NUMBER,
    };
    lsdb.install(Lsa {
        header: LsaHeader {
            age: 0,
            lsa_type,
            link_state_id,
            advertising_router: local_router_id,
            sequence_number,
            checksum: 0,
            length: 0,
        },
        body,
    });
    info!(
        lsa_type, link_state_id = %link_state_id, advertising_router = %local_router_id,
        refreshed = needs_refresh,
        "ospfv3 lsa originated"
    );
}

fn diff_links(
    current: &HashMap<String, LinkConfig>,
    desired: &HashMap<String, LinkConfig>,
) -> (Vec<String>, Vec<LinkConfig>) {
    let mut to_stop = Vec::new();
    let mut to_spawn = Vec::new();

    for (key, running) in current {
        match desired.get(key) {
            None => to_stop.push(key.clone()),
            Some(wanted) if wanted != running => {
                to_stop.push(key.clone());
                to_spawn.push(wanted.clone());
            }
            Some(_) => {}
        }
    }
    for (key, wanted) in desired {
        if !current.contains_key(key) {
            to_spawn.push(wanted.clone());
        }
    }

    (to_stop, to_spawn)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(attach_point: &str, hello_interval: u16) -> LinkConfig {
        LinkConfig {
            attach_point: attach_point.to_string(),
            area_id: Ipv4Addr::UNSPECIFIED,
            hello_interval,
            dead_interval: 40,
            vrf: "vrf100".to_string(),
            kernel_interface: "eth0".to_string(),
            interface_id: 3,
            link_local_address: "fe80::1".parse().unwrap(),
            prefix: "2001:db8::/64".parse().unwrap(),
            cost: 1,
            network_type: NetworkType::PointToPoint,
            priority: 1,
            mtu: 1500,
        }
    }

    #[test]
    fn no_changes_produces_no_diff() {
        let mut current = HashMap::new();
        current.insert("eth0.0".to_string(), link("eth0.0", 10));
        let desired = current.clone();
        let (to_stop, to_spawn) = diff_links(&current, &desired);
        assert!(to_stop.is_empty());
        assert!(to_spawn.is_empty());
    }

    #[test]
    fn new_link_is_spawned() {
        let current = HashMap::new();
        let mut desired = HashMap::new();
        desired.insert("eth0.0".to_string(), link("eth0.0", 10));
        let (to_stop, to_spawn) = diff_links(&current, &desired);
        assert!(to_stop.is_empty());
        assert_eq!(to_spawn, vec![link("eth0.0", 10)]);
    }

    #[test]
    fn removed_link_is_stopped() {
        let mut current = HashMap::new();
        current.insert("eth0.0".to_string(), link("eth0.0", 10));
        let desired = HashMap::new();
        let (to_stop, to_spawn) = diff_links(&current, &desired);
        assert_eq!(to_stop, vec!["eth0.0".to_string()]);
        assert!(to_spawn.is_empty());
    }

    #[test]
    fn changed_link_is_stopped_and_respawned() {
        let mut current = HashMap::new();
        current.insert("eth0.0".to_string(), link("eth0.0", 10));
        let mut desired = HashMap::new();
        desired.insert("eth0.0".to_string(), link("eth0.0", 5));
        let (to_stop, to_spawn) = diff_links(&current, &desired);
        assert_eq!(to_stop, vec!["eth0.0".to_string()]);
        assert_eq!(to_spawn, vec![link("eth0.0", 5)]);
    }

    #[test]
    fn point_to_point_neighbor_is_always_adjacency_eligible() {
        assert!(should_form_adjacency(
            InterfaceState::PointToPoint,
            Ipv4Addr::new(1, 1, 1, 1),
            None,
            None,
        ));
    }

    #[test]
    fn dr_other_pair_is_not_adjacency_eligible() {
        assert!(!should_form_adjacency(
            InterfaceState::DrOther,
            Ipv4Addr::new(1, 1, 1, 1),
            Some(Ipv4Addr::new(2, 2, 2, 2)),
            Some(Ipv4Addr::new(3, 3, 3, 3)),
        ));
    }

    fn neighbor_info(state: NeighborState, address: Ipv6Addr, interface_id: u32) -> NeighborInfo {
        NeighborInfo {
            state,
            priority: 1,
            declared_dr: Ipv4Addr::UNSPECIFIED,
            declared_bdr: Ipv4Addr::UNSPECIFIED,
            interface_id,
            last_hello_received: Instant::now(),
            address,
            adjacency: None,
        }
    }

    #[test]
    fn router_lsa_links_includes_p2p_link_with_a_neighbor() {
        let cfg = link("eth0.0", 10);
        let mut status = LinkStatus::new(NetworkType::PointToPoint);
        let neighbor_id = Ipv4Addr::new(9, 9, 9, 10);
        status.neighbors.insert(
            neighbor_id,
            neighbor_info(NeighborState::Full, "fe80::2".parse().unwrap(), 7),
        );
        let links = router_lsa_links(Ipv4Addr::new(1, 1, 1, 1), &[(cfg.clone(), status)]);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].link_type, LINK_TYPE_POINT_TO_POINT);
        assert_eq!(links[0].neighbor_router_id, neighbor_id);
        assert_eq!(links[0].neighbor_interface_id, 7);
        assert_eq!(links[0].interface_id, cfg.interface_id);
    }

    #[test]
    fn router_lsa_links_skips_broadcast_link_with_no_dr_yet() {
        let mut cfg = link("bd1", 10);
        cfg.network_type = NetworkType::Broadcast;
        let status = LinkStatus::new(NetworkType::Broadcast);
        assert!(router_lsa_links(Ipv4Addr::new(1, 1, 1, 1), &[(cfg, status)]).is_empty());
    }

    #[test]
    fn router_lsa_links_uses_own_interface_id_when_self_is_dr() {
        let mut cfg = link("bd1", 10);
        cfg.network_type = NetworkType::Broadcast;
        let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
        let mut status = LinkStatus::new(NetworkType::Broadcast);
        status.interface_state = InterfaceState::Dr;
        status.dr = Some(local_router_id);
        let links = router_lsa_links(local_router_id, &[(cfg.clone(), status)]);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].neighbor_interface_id, cfg.interface_id);
        assert_eq!(links[0].neighbor_router_id, local_router_id);
    }

    #[test]
    fn install_self_originated_first_install_uses_initial_sequence_number() {
        let mut lsdb = Lsdb::new();
        let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
        let body = LsaBody::Router(RouterLsaBody {
            flags: 0,
            options: 0,
            links: Vec::new(),
        });
        install_self_originated(
            &mut lsdb,
            local_router_id,
            lsa::LSA_TYPE_ROUTER,
            local_router_id,
            body.clone(),
        );
        let key = LsaKey {
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: local_router_id,
            advertising_router: local_router_id,
        };
        let installed = lsdb.get(&key).unwrap();
        assert_eq!(
            installed.header.sequence_number,
            lsa::INITIAL_SEQUENCE_NUMBER
        );
        assert_eq!(installed.body, body);
    }

    #[test]
    fn install_self_originated_unchanged_body_is_a_no_op() {
        let mut lsdb = Lsdb::new();
        let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
        let body = LsaBody::Router(RouterLsaBody {
            flags: 0,
            options: 0,
            links: Vec::new(),
        });
        install_self_originated(
            &mut lsdb,
            local_router_id,
            lsa::LSA_TYPE_ROUTER,
            local_router_id,
            body.clone(),
        );
        install_self_originated(
            &mut lsdb,
            local_router_id,
            lsa::LSA_TYPE_ROUTER,
            local_router_id,
            body,
        );
        let key = LsaKey {
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: local_router_id,
            advertising_router: local_router_id,
        };
        assert_eq!(
            lsdb.get(&key).unwrap().header.sequence_number,
            lsa::INITIAL_SEQUENCE_NUMBER
        );
    }

    #[tokio::test]
    async fn originate_link_lsas_installs_one_per_live_link() {
        let manager = LinkManager::new(1, None);
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let cfg = link("eth0.0", 10);
        manager
            .reconcile(vec![cfg.clone()], HashMap::new(), router_id)
            .await;
        // Link driver tasks are spawned but never reach a real socket in
        // this unit-test environment (no root/raw-socket access) — origin
        // uses `links` (the config map), not socket state, so this still
        // exercises the origination logic directly regardless.
        manager.originate_link_lsas(router_id).await;

        let lsdb = manager.lsdb_for(cfg.area_id).await;
        let key = LsaKey {
            lsa_type: lsa::LSA_TYPE_LINK,
            link_state_id: lsa::interface_id_key(cfg.interface_id),
            advertising_router: router_id,
        };
        let installed = lsdb.lock().await.get(&key).unwrap();
        let LsaBody::Link(body) = &installed.body else {
            panic!("expected link lsa")
        };
        assert_eq!(body.link_local_address, cfg.link_local_address);
        assert_eq!(body.prefixes.len(), 1);
        assert_eq!(body.prefixes[0].prefix, cfg.prefix);
    }

    #[tokio::test]
    async fn extended_mode_originates_only_extended_lsas() {
        let manager = LinkManager::new(1, None);
        manager.set_extended_lsa(true);
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let cfg = link("eth0.0", 10);
        manager
            .reconcile(vec![cfg.clone()], HashMap::new(), router_id)
            .await;
        manager.originate_router_lsas(router_id).await;
        manager.originate_link_lsas(router_id).await;
        manager.originate_intra_area_prefix_lsas(router_id).await;

        let lsdb = manager.lsdb_for(cfg.area_id).await;
        let types: HashSet<u16> = lsdb
            .lock()
            .await
            .headers()
            .iter()
            .map(|h| h.lsa_type)
            .collect();
        assert!(types.contains(&lsa::LSA_TYPE_E_ROUTER));
        assert!(types.contains(&lsa::LSA_TYPE_E_LINK));
        assert!(!types.contains(&lsa::LSA_TYPE_ROUTER));
        assert!(!types.contains(&lsa::LSA_TYPE_LINK));
        assert!(!types.contains(&lsa::LSA_TYPE_INTRA_AREA_PREFIX));
    }

    #[tokio::test]
    async fn originate_intra_area_prefix_lsas_includes_loopback_for_area_with_no_live_link() {
        let manager = LinkManager::new(1, None);
        let area = Ipv4Addr::UNSPECIFIED;
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let stub: Ipv6Net = "2001:db8:9::/128".parse().unwrap();
        manager
            .reconcile(
                Vec::new(),
                HashMap::from([(area, vec![(stub, 5)])]),
                router_id,
            )
            .await;
        manager.originate_intra_area_prefix_lsas(router_id).await;

        let lsdb = manager.lsdb_for(area).await;
        let key = LsaKey {
            lsa_type: lsa::LSA_TYPE_INTRA_AREA_PREFIX,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: router_id,
        };
        let installed = lsdb.lock().await.get(&key).unwrap();
        let LsaBody::IntraAreaPrefix(body) = &installed.body else {
            panic!("expected intra-area-prefix lsa")
        };
        assert_eq!(body.referenced_ls_type, lsa::LSA_TYPE_ROUTER);
        assert_eq!(body.prefixes.len(), 1);
        assert_eq!(body.prefixes[0].prefix, stub);
        assert_eq!(body.prefixes[0].metric, 5);
    }
}
