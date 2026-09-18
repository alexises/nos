//! One OSPF link's driver, plus `LinkManager` — the OSPF analogue of
//! `bgp::session::SessionManager`, much smaller since there's no shared
//! listener, no auth, and no collision resolution: each link just owns its
//! own raw socket, neighbor FSM(s), RFC 2328 §9.4 DR/BDR election on a
//! `Broadcast` link, and — once a neighbor is eligible — RFC 2328
//! §10.6-10.8's DBD/LSR/LSU/LSAck adjacency-forming exchange
//! (`crate::exchange`).

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipnet::Ipv4Net;
use nos_proto::{LinkInterfaceState, LsaSummary, NeighborSummary, NetworkType, OspfNeighborState};
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::election::{self, Candidate};
use crate::exchange::{self, AdjacencyData};
use crate::lsa::{
    self, Lsa, LsaBody, LsaHeader, LsaKey, NetworkLsaBody, RouterLink, RouterLsaBody,
    LINK_TYPE_POINT_TO_POINT, LINK_TYPE_STUB_NETWORK, LINK_TYPE_TRANSIT_NETWORK,
};
use crate::lsdb::Lsdb;
use crate::neighbor::{self, NeighborState};
use crate::packet::{self, DbdPacket, LsAckPacket, LsrPacket, LsuPacket, OspfPacket};
use crate::socket::OspfSocket;
use crate::spf;

/// RFC 2328 Appendix C.3's default `RxmtInterval` — how often an
/// unacknowledged LSR/LSU is resent.
///
/// # ponytail: fixed, not a per-`OspfProfile` config field
/// `hello_interval`/`dead_interval`/`priority` are all operator-tunable per
/// profile, but adding a matching `retransmit_interval` field would touch
/// schema/ops/diff/cli plumbing across ~7 files for a knob nothing in this
/// NOS's verification suite needs tuned. Upgrade to a real
/// `OspfProfile.retransmit_interval: Option<u16>` (mirroring
/// `hello_interval`'s exact pattern) if an operator ever needs to tune it.
const RXMT_INTERVAL: Duration = Duration::from_secs(5);

/// How often `LinkManager` recomputes and reinstalls this router's own
/// self-originated LSAs — independent of, and much more frequent than, the
/// 10s config-reapply tick, so a freshly-`Full` adjacency's Router-LSA
/// shows up quickly rather than waiting on the next config resync.
const ORIGINATION_INTERVAL: Duration = Duration::from_secs(2);

/// One link's fully-resolved desired state — diffed wholesale by
/// `LinkManager::reconcile`, mirroring `bgp::session::ResolvedPeer`: any
/// field change (including a re-resolved `vrf`/`local_addr`, or a changed
/// `network_type`/`priority`) restarts the link.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkConfig {
    /// Display key, matching `reconcile::attach_points_for`'s existing
    /// `"<interface>.<tag>"`/`"broadcast-domain:<name>"` convention.
    pub attach_point: String,
    pub area_id: Ipv4Addr,
    pub hello_interval: u16,
    pub dead_interval: u16,
    pub vrf: String,
    pub local_addr: Ipv4Addr,
    /// This link's own subnet's prefix length — needed (alongside
    /// `local_addr`) to originate a real stub-network Router-LSA link for
    /// a point-to-point subnet, and a real `NetworkLsaBody.network_mask`
    /// for a broadcast one. See `crate::spf`.
    pub local_prefix_len: u8,
    /// This link's RFC 2328 §16 SPF cost — `OspfProfile.cost`, defaulting
    /// to `1` when unset (see `reconcile.rs`).
    pub cost: u16,
    /// The real Linux device this link's raw socket binds to — the
    /// specific L3 interface OSPF actually runs on: the physical/VLAN
    /// subinterface itself for a point-to-point attach point, or the
    /// `BroadcastDomain`'s own bridge (its SVI) for a broadcast one. Never
    /// the VRF device: OSPF's raw protocol-89 socket has no port/connection
    /// concept to demultiplex by, so a VRF-wide bind would also receive
    /// every *other* OSPF link's traffic in the same VRF, corrupting each
    /// link's own DBD/LSR/LSU sequence-number/role state — a real bug this
    /// field's introduction fixed (see `socket.rs`'s doc comment).
    pub kernel_interface: String,
    pub network_type: NetworkType,
    pub priority: u8,
}

/// RFC 2328 §9.1's interface states — see `nos_proto::LinkInterfaceState`,
/// which this mirrors one-to-one (kept as a separate type here, like
/// `bgp::status::PeerState` mirrors `nos_proto::bgp::BgpSessionState`, since
/// this crate's internal state isn't necessarily wire-serializable forever).
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
    pub last_hello_received: Instant,
    /// The neighbor's own IP address, as seen on the last Hello it sent —
    /// DBD/LSR/LSU/LSAck reply unicast to this, unlike Hello's multicast.
    pub address: Ipv4Addr,
    /// `Some` from `ExStart` onward; cleared whenever the neighbor drops
    /// back to `Init`/`Down` (RFC 2328: losing 2-way tears down any
    /// adjacency, forcing a fresh negotiation on reconnect).
    pub adjacency: Option<AdjacencyData>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LinkStatus {
    pub interface_state: InterfaceState,
    /// Keyed by neighbor router-id. At most one entry on a point-to-point
    /// link; potentially many on a broadcast link.
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

/// RFC 2328 §7.5/§10.4: on a broadcast link, a neighbor only proceeds
/// toward a full adjacency if this router or that neighbor is the elected
/// DR/BDR — every other pair (`DrOther`-`DrOther`) stays at `TwoWay`
/// forever. Point-to-point has no such restriction (`interface_state` is
/// always `PointToPoint`, so every neighbor is always eligible).
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

/// A sequence number unlikely to collide with whatever this router last
/// used with this neighbor (RFC 2328 §10.6 has no stronger requirement than
/// that). Kept in `link.rs`, not `exchange.rs`, so the DBD negotiation logic
/// stays free of wall-clock reads and fully unit-testable.
fn initial_dd_sequence_number() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |d| d.subsec_nanos())
}

/// Builds a fresh `AdjacencyData` plus the negotiation DBD to send —
/// used both when a neighbor first becomes adjacency-eligible and when a
/// `SeqNumberMismatch` forces negotiation to restart from scratch.
fn start_negotiation(cfg: &LinkConfig, local_router_id: Ipv4Addr) -> (AdjacencyData, DbdPacket) {
    let seed = initial_dd_sequence_number();
    let dbd = DbdPacket {
        router_id: local_router_id,
        area_id: cfg.area_id,
        interface_mtu: 0, // never enforced by this NOS, on send or receive
        options: 0,
        init: true,
        more: true,
        master: true,
        dd_sequence_number: seed,
        lsa_headers: Vec::new(),
    };
    let adj = AdjacencyData {
        is_master: false, // resolved once the neighbor's own negotiation DBD arrives
        dd_sequence_number: seed,
        request_list: Vec::new(),
        retransmission_list: HashMap::new(),
        last_dbd_sent: Some(dbd.clone()),
    };
    (adj, dbd)
}

/// Runs until aborted (link removed from config, or process shutdown — see
/// `LinkManager`). Owns the raw socket, the Hello send ticker, and every
/// timer this link's network type needs.
pub async fn run(
    cfg: LinkConfig,
    local_router_id: Ipv4Addr,
    lsdb: Arc<Mutex<Lsdb>>,
    status: StatusHandle,
) {
    let socket = match OspfSocket::open(&cfg.kernel_interface, cfg.local_addr) {
        Ok(s) => s,
        Err(e) => {
            warn!(link = %cfg.attach_point, error = %e, "failed to open ospf raw socket");
            return;
        }
    };

    let mut hello_ticker =
        tokio::time::interval(Duration::from_secs(u64::from(cfg.hello_interval)));
    hello_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let is_broadcast = cfg.network_type == NetworkType::Broadcast;
    let mut p2p_dead_deadline = Instant::now() + Duration::from_secs(u64::from(cfg.dead_interval));
    // ponytail: a 1s periodic sweep, not N precise per-neighbor timers — a
    // broadcast link's dead-interval tracking only needs to be accurate to
    // about a second, and this avoids a dynamically-sized set of timers
    // growing/shrinking as neighbors come and go. Upgrade to a
    // `last_hello_received`-keyed min-heap (or per-neighbor spawned
    // timers) if sub-second precision on broadcast links ever matters.
    let mut dead_sweep = tokio::time::interval(Duration::from_secs(1));
    dead_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let wait_deadline = Instant::now() + Duration::from_secs(u64::from(cfg.dead_interval));
    let mut waiting = is_broadcast;

    let mut rxmt_sweep = tokio::time::interval(RXMT_INTERVAL);
    rxmt_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    info!(link = %cfg.attach_point, vrf = %cfg.vrf, "ospf link driver started");
    if is_broadcast {
        info!(link = %cfg.attach_point, "ospf interface reached waiting");
    }

    loop {
        tokio::select! {
            _ = hello_ticker.tick() => {
                send_hello(&socket, &cfg, local_router_id, &status);
            }
            result = socket.recv_packet() => {
                match result {
                    Ok((source, data)) => match packet::decode(&data) {
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
                            if let Some(actions) =
                                handle_dbd(&cfg, local_router_id, &status, &lsdb, &dbd).await
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
                            warn!(link = %cfg.attach_point, error = %e, "failed to decode ospf packet");
                        }
                    },
                    Err(e) => warn!(link = %cfg.attach_point, error = %e, "ospf recv error"),
                }
            }
            () = tokio::time::sleep_until(p2p_dead_deadline), if !is_broadcast => {
                apply_dead_timer(&cfg, &status);
                p2p_dead_deadline = Instant::now() + Duration::from_secs(u64::from(cfg.dead_interval));
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
    // Designated/backup-designated router are only meaningful once an
    // election has run — always unspecified on a point-to-point link, since
    // no election ever runs there (RFC 2328 §10.5).
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
        hello_interval: cfg.hello_interval,
        dead_interval: u32::from(cfg.dead_interval),
        router_priority: cfg.priority,
        designated_router,
        backup_designated_router,
        neighbors,
    };
    if let Err(e) = socket.send_multicast(&packet::encode_hello(&pkt)) {
        warn!(link = %cfg.attach_point, error = %e, "failed to send ospf hello");
    }
}

/// Returns whether this Hello caused a broadcast link to leave `Waiting`
/// early (RFC 2328's "`BackupSeen`" shortcut — a neighbor already declaring
/// itself DR means the election result is already knowable).
fn handle_hello(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    source: Ipv4Addr,
    hello: &packet::HelloPacket,
    p2p_dead_deadline: &mut Instant,
    waiting: bool,
) -> bool {
    // RFC 2328 §10.5's packet-validity check precedes any neighbor event —
    // a mismatched area is logged and dropped, not fed into the FSM.
    if hello.area_id != cfg.area_id {
        warn!(
            link = %cfg.attach_point, area = %hello.area_id, expected = %cfg.area_id,
            "dropping ospf hello with mismatched area"
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
        info!(link = %cfg.attach_point, neighbor = %hello.router_id, "ospf neighbor state changed to init");
    }
    if old_state != NeighborState::TwoWay && new_state == NeighborState::TwoWay {
        info!(link = %cfg.attach_point, neighbor = %hello.router_id, "ospf neighbor reached two-way");
    }
    if old_state != NeighborState::Init
        && new_state == NeighborState::Init
        && old_state != NeighborState::Down
    {
        warn!(link = %cfg.attach_point, neighbor = %hello.router_id, "ospf neighbor adjacency torn down, back to init");
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
                last_hello_received: Instant::now(),
                address: source,
                adjacency: None,
            });
        entry.state = new_state;
        entry.priority = hello.router_priority;
        entry.declared_dr = hello.designated_router;
        entry.declared_bdr = hello.backup_designated_router;
        entry.last_hello_received = Instant::now();
        entry.address = source;
        if matches!(new_state, NeighborState::Down | NeighborState::Init) {
            entry.adjacency = None;
        }
    });

    match cfg.network_type {
        NetworkType::PointToPoint => {
            *p2p_dead_deadline = Instant::now() + Duration::from_secs(u64::from(cfg.dead_interval));
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

/// Scans every `TwoWay` neighbor with no adjacency yet and, for each one
/// now eligible (`should_form_adjacency`), starts RFC 2328 §10.6
/// negotiation: sends the initial negotiation DBD and moves it to
/// `ExStart`. Called after anything that could change eligibility — a
/// fresh `TwoWay`, or a completed election.
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
        if let Err(e) = socket.send_unicast(neighbor_addr, &packet::encode_dbd(&dbd)) {
            warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospf dbd");
        }
        let new_state = neighbor::step(NeighborState::TwoWay, neighbor::Event::AdjacencyEligible);
        info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf neighbor reached exstart");
        status.send_modify(|s| {
            if let Some(info) = s.neighbors.get_mut(&neighbor_id) {
                info.state = new_state;
                info.adjacency = Some(adj);
            }
        });
    }
}

/// Handles one received DBD packet against the sending neighbor's current
/// adjacency data, returning the actions `execute_actions` still needs to
/// carry out (sends). Returns `None` if the neighbor is unknown or has no
/// adjacency in progress.
async fn handle_dbd(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    lsdb: &Mutex<Lsdb>,
    dbd: &DbdPacket,
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

/// Handles one received LSR packet, looking up every requested LSA in
/// `lsdb`. Returns `None` if the neighbor is unknown or has no adjacency in
/// progress.
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

/// Handles one received LSU packet, installing every carried LSA into
/// `lsdb`. Returns `None` if the neighbor is unknown or has no adjacency in
/// progress.
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
            "ospf lsa installed"
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

/// Handles one received `LSAck` packet — no neighbor-state transition
/// possible from an ack alone, just retransmission-list bookkeeping.
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

/// Applies any `NeighborEvent`s in `actions` to `old_state` via
/// `neighbor::step`, logs state-transition milestones, and — if the result
/// is a `SeqNumberMismatch`-triggered restart back to `ExStart` — replaces
/// `actions` with a fresh negotiation DBD instead of replaying whatever the
/// caller computed (mirroring `advance_adjacencies`'s own negotiation
/// start). Shared tail of `handle_dbd`/`handle_lsr`/`handle_lsu`.
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
        warn!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf neighbor sequence mismatch, restarting negotiation");
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
            info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf neighbor reached exchange");
        }
        (s, NeighborState::Loading) if s != NeighborState::Loading => {
            info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf neighbor reached loading");
        }
        (s, NeighborState::Full) if s != NeighborState::Full => {
            info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf neighbor reached full");
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

/// Carries out the I/O side of an `exchange::Action` list — sending
/// packets. `NeighborEvent` is already applied to state by the caller;
/// `InstallAndFlood` lands in a later stage (cross-link flooding).
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
            exchange::Action::SendDbd(pkt) => ("dbd", packet::encode_dbd(&pkt)),
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
            exchange::Action::NeighborEvent(_) | exchange::Action::InstallAndFlood(_) => continue,
        };
        if let Err(e) = socket.send_unicast(neighbor_addr, &payload) {
            warn!(link = %cfg.attach_point, neighbor = %neighbor_id, kind, error = %e, "failed to send ospf packet");
        }
    }
}

/// Resends every neighbor's last-sent DBD (if any — see `AdjacencyData::
/// last_dbd_sent`'s doc comment for why this is necessary, not just a
/// reliability nicety) and outstanding request/retransmission list —
/// ponytail: the whole set every tick, rather than tracking each entry's
/// own last-sent time, since `RXMT_INTERVAL` is already the granularity RFC
/// 2328 uses and this NOS's per-neighbor outstanding set is tiny (a handful
/// of LSAs on a lab topology).
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
            if let Err(e) = socket.send_unicast(info.address, &packet::encode_dbd(dbd)) {
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
            if let Err(e) = socket.send_unicast(info.address, &packet::encode_lsr(&lsr)) {
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
            if let Err(e) = socket.send_unicast(info.address, &packet::encode_lsu(&lsu)) {
                warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospf lsu");
            }
        }
    }
}

/// Resends the entire local LSDB to every `Full` neighbor on this link.
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
async fn flood_full_neighbors(
    socket: &OspfSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    lsdb: &Mutex<Lsdb>,
    status: &StatusHandle,
) {
    let full_neighbors: Vec<(Ipv4Addr, Ipv4Addr)> = status
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
        if let Err(e) = socket.send_unicast(neighbor_addr, &payload) {
            warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospf lsu");
        }
    }
}

/// Point-to-point only — `run()` only arms this branch when
/// `cfg.network_type` is `PointToPoint`. At most one neighbor entry.
fn apply_dead_timer(cfg: &LinkConfig, status: &StatusHandle) {
    let Some(old_state) = status.borrow().neighbors.values().next().map(|n| n.state) else {
        return;
    };
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

/// Broadcast only. Ages out any neighbor whose `last_hello_received` is
/// older than `cfg.dead_interval` — see `run()`'s `ponytail:` note on why
/// this is a periodic sweep rather than per-neighbor timers.
fn sweep_dead_neighbors(cfg: &LinkConfig, status: &StatusHandle) {
    let now = Instant::now();
    let dead_interval = Duration::from_secs(u64::from(cfg.dead_interval));
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

/// Broadcast only. Runs RFC 2328 §9.4 election (`election::elect`) over
/// every 2-Way-or-better neighbor, updates `status.dr`/`bdr`/
/// `interface_state`, and logs exactly once per role transition.
fn run_election(cfg: &LinkConfig, local_router_id: Ipv4Addr, status: &StatusHandle) {
    let snapshot = status.borrow().clone();
    let self_candidate = Candidate {
        router_id: local_router_id,
        priority: cfg.priority,
        declared_dr: snapshot.dr.unwrap_or(Ipv4Addr::UNSPECIFIED),
        declared_bdr: snapshot.bdr.unwrap_or(Ipv4Addr::UNSPECIFIED),
    };
    let neighbor_candidates: Vec<Candidate> = snapshot
        .neighbors
        .iter()
        // RFC 2328 §9.4: every neighbor at 2-Way *or better* is eligible —
        // not just exactly `TwoWay`. A neighbor that has since progressed
        // to `ExStart`/`Exchange`/`Loading`/`Full` is still on the segment
        // and must stay in the DR/BDR candidate pool; excluding it here
        // once adjacency starts forming would make this router think it's
        // alone and incorrectly elect itself.
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
        .map(|(id, info)| Candidate {
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

    if snapshot.interface_state != new_interface_state {
        match new_interface_state {
            InterfaceState::Dr => {
                info!(link = %cfg.attach_point, dr = %local_router_id, "ospf interface became dr");
            }
            InterfaceState::Backup => {
                info!(
                    link = %cfg.attach_point,
                    dr = %result.dr.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    bdr = %local_router_id,
                    "ospf interface became backup"
                );
            }
            InterfaceState::DrOther => {
                info!(
                    link = %cfg.attach_point,
                    dr = %result.dr.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    bdr = %result.bdr.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    "ospf interface became dr-other"
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

/// Owns every OSPF link's driver task for one `nos-ospfd` process, plus its
/// per-area LSDBs. `reconcile` is the sole entry point, called by
/// `crate::reconcile::run` on every resync; it's idempotent and safe to
/// call repeatedly with the same desired state — mirrors
/// `bgp::session::SessionManager`.
pub struct LinkManager {
    links: Mutex<HashMap<String, LinkEntry>>,
    /// Partitioned by area, not a single flat map — `OspfArea` is already
    /// multi-valued in this NOS's config schema, so a flat LSDB would leak
    /// LSAs across areas the moment a second one is configured.
    lsdbs: Mutex<HashMap<Ipv4Addr, Arc<Mutex<Lsdb>>>>,
    /// Set on every `reconcile` call, read by the background origination
    /// task started in `new`.
    router_id: Mutex<Option<Ipv4Addr>>,
    /// Loopback (`Interface.ospf_profile`) attach points' own subnets, per
    /// area — these have no live `LinkConfig`/socket (see `reconcile.rs`'s
    /// "log-only" loopback handling), so they're threaded in here directly
    /// rather than through `links`, purely so `originate_router_lsas` can
    /// advertise a real stub-network link for each one. Replaced wholesale
    /// on every `reconcile` call, like every other desired-state field.
    stub_networks: Mutex<HashMap<Ipv4Addr, Vec<(Ipv4Net, u16)>>>,
}

impl LinkManager {
    pub fn new() -> Arc<Self> {
        let manager = Arc::new(Self {
            links: Mutex::new(HashMap::new()),
            lsdbs: Mutex::new(HashMap::new()),
            router_id: Mutex::new(None),
            stub_networks: Mutex::new(HashMap::new()),
        });
        let background = Arc::clone(&manager);
        // Runs for the process's lifetime — like every link driver task, it
        // ends only when the tokio runtime itself is torn down at process
        // exit, so there's nothing to abort on shutdown.
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(ORIGINATION_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                if let Some(router_id) = *background.router_id.lock().await {
                    background.originate_router_lsas(router_id).await;
                }
            }
        });
        manager
    }

    /// Gets or creates the shared LSDB for `area_id`.
    async fn lsdb_for(&self, area_id: Ipv4Addr) -> Arc<Mutex<Lsdb>> {
        Arc::clone(
            self.lsdbs
                .lock()
                .await
                .entry(area_id)
                .or_insert_with(|| Arc::new(Mutex::new(Lsdb::new()))),
        )
    }

    /// RFC 2328 §12.4's self-origination: recomputes and (re)installs this
    /// router's own Router-LSA per area (from every currently-running
    /// link's config/status in that area) and Network-LSA on any broadcast
    /// link where it's DR with at least one `Full` neighbor. Run
    /// periodically (see `ORIGINATION_INTERVAL`) rather than event-driven
    /// off each link's own state changes, since it's cheap and every
    /// relevant link's status already sits in a `watch` channel this can
    /// just snapshot.
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

        let stub_networks = self.stub_networks.lock().await.clone();

        // An area with only a loopback stub and no live link would
        // otherwise never appear here at all — union both sets of area
        // ids rather than iterating `by_area` alone.
        let area_ids: HashSet<Ipv4Addr> = by_area
            .keys()
            .copied()
            .chain(stub_networks.keys().copied())
            .collect();

        for area_id in area_ids {
            let links = by_area.get(&area_id).cloned().unwrap_or_default();
            let lsdb = self.lsdb_for(area_id).await;
            let mut lsdb = lsdb.lock().await;

            let mut router_links = router_lsa_links(local_router_id, &links);
            for (subnet, cost) in stub_networks.get(&area_id).into_iter().flatten() {
                router_links.push(RouterLink {
                    link_id: subnet.network(),
                    link_data: subnet.netmask(),
                    link_type: LINK_TYPE_STUB_NETWORK,
                    metric: *cost,
                });
            }

            install_self_originated(
                &mut lsdb,
                local_router_id,
                lsa::LSA_TYPE_ROUTER,
                local_router_id,
                LsaBody::Router(RouterLsaBody {
                    flags: 0,
                    links: router_links,
                }),
            );

            for (cfg, status) in &links {
                if status.interface_state != InterfaceState::Dr {
                    continue;
                }
                let attached: Vec<Ipv4Addr> = std::iter::once(local_router_id)
                    .chain(
                        status
                            .neighbors
                            .iter()
                            .filter(|(_, n)| n.state == NeighborState::Full)
                            .map(|(id, _)| *id),
                    )
                    .collect();
                if attached.len() < 2 {
                    // No fully-adjacent neighbor yet — nothing transit
                    // about this network from the LSDB's perspective.
                    continue;
                }
                let network_mask = local_subnet(cfg).map_or(Ipv4Addr::UNSPECIFIED, |n| n.netmask());
                install_self_originated(
                    &mut lsdb,
                    local_router_id,
                    lsa::LSA_TYPE_NETWORK,
                    cfg.local_addr,
                    LsaBody::Network(NetworkLsaBody {
                        network_mask,
                        attached_routers: attached,
                    }),
                );
            }
        }
    }

    /// Diffs `desired` against currently-running links by `attach_point`:
    /// links no longer desired, or whose resolved fields changed, are
    /// stopped (and, if still desired with new fields, respawned); newly
    /// desired links are spawned. A link whose driver task ended on its own
    /// (e.g. the raw socket failed to open) is treated as "not currently
    /// running" so this pass respawns it too — the same periodic re-apply
    /// tick that re-resolves a not-yet-ready VRF/interface also recovers
    /// from a transient socket failure this way.
    pub async fn reconcile(
        self: &Arc<Self>,
        desired: Vec<LinkConfig>,
        desired_stubs: HashMap<Ipv4Addr, Vec<(Ipv4Net, u16)>>,
        local_router_id: Ipv4Addr,
    ) {
        *self.router_id.lock().await = Some(local_router_id);
        *self.stub_networks.lock().await = desired_stubs;

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
            let task = tokio::spawn(run(cfg.clone(), local_router_id, lsdb, status_tx));
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

    /// Every currently-configured link's current neighbor summaries, for
    /// `server.rs`'s `OspfRequest::GetNeighbors` handler — backs `nos-cli`'s
    /// `show ospf neigh`. One row per point-to-point link (even with no
    /// neighbor yet); one row per currently-known neighbor on a broadcast
    /// link (zero if none yet).
    pub async fn neighbor_summaries(&self) -> Vec<NeighborSummary> {
        self.links
            .lock()
            .await
            .values()
            .flat_map(to_neighbor_summaries)
            .collect()
    }

    /// Every installed LSA's header, across every area, for `server.rs`'s
    /// `OspfRequest::GetDatabase` handler — backs `nos-cli`'s
    /// `show ospf database`.
    pub async fn database_summaries(&self) -> Vec<LsaSummary> {
        let mut result = Vec::new();
        for (area_id, lsdb) in self.lsdbs.lock().await.iter() {
            for header in lsdb.lock().await.headers() {
                result.push(LsaSummary {
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
    /// merges the results into one route set, for `crate::rib_push_client`.
    /// Areas are logically disjoint in this NOS's single-area/intra-area
    /// scope (no Summary-LSA/inter-area routing), so a plain overwrite on
    /// key collision is fine. Empty if `router_id` hasn't been set yet
    /// (before this instance's first `reconcile` call).
    pub async fn compute_routes(&self) -> Vec<spf::RouteEntry> {
        let Some(router_id) = *self.router_id.lock().await else {
            return Vec::new();
        };
        let areas: Vec<Arc<Mutex<Lsdb>>> = self.lsdbs.lock().await.values().cloned().collect();
        let mut merged: HashMap<Ipv4Net, spf::RouteEntry> = HashMap::new();
        for lsdb in areas {
            let lsas = lsdb.lock().await.all();
            for entry in spf::compute(router_id, &lsas) {
                merged.insert(entry.prefix, entry);
            }
        }
        merged.into_values().collect()
    }

    /// Aborts every link task. Called once when `crate::reconcile::run`'s
    /// loop exits on shutdown.
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

fn to_neighbor_summaries(entry: &LinkEntry) -> Vec<NeighborSummary> {
    let status = entry.status.borrow().clone();
    let interface_state = to_interface_state(status.interface_state);

    if status.neighbors.is_empty() {
        // A point-to-point link always reports a row, even with no
        // neighbor yet; a broadcast link has no single fixed peer to show
        // a placeholder for.
        if entry.config.network_type == NetworkType::Broadcast {
            return Vec::new();
        }
        return vec![NeighborSummary {
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
        .map(|(id, info)| NeighborSummary {
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

/// This link's own subnet, if `local_prefix_len` is a valid IPv4 prefix
/// length — used to originate a stub-network link for it.
fn local_subnet(cfg: &LinkConfig) -> Option<Ipv4Net> {
    Ipv4Net::new(cfg.local_addr, cfg.local_prefix_len).ok()
}

/// RFC 2328 §12.4.1's Router-LSA link entries for every currently-running
/// link in one area: one type-1 (point-to-point) entry per link with at
/// least one neighbor, one type-2 (transit-network) entry per link with a
/// resolved DR (broadcast), and — per RFC 2328 §12.4.1.1 — a type-3
/// (stub-network) entry for every point-to-point link's own subnet
/// *unconditionally*, independent of neighbor state (a numbered p2p
/// interface always advertises its own subnet). Both ends of a p2p link
/// therefore advertise the identical subnet; `crate::spf`'s
/// directly-connected filter is what keeps that from producing a spurious
/// route back to your own subnet via the neighbor. Pure — takes an
/// already-gathered snapshot so it stays independently unit-testable.
fn router_lsa_links(
    local_router_id: Ipv4Addr,
    links: &[(LinkConfig, LinkStatus)],
) -> Vec<RouterLink> {
    let mut result = Vec::new();
    for (cfg, status) in links {
        match cfg.network_type {
            NetworkType::PointToPoint => {
                if let Some((neighbor_id, _)) = status
                    .neighbors
                    .iter()
                    .find(|(_, n)| n.state != NeighborState::Down)
                {
                    result.push(RouterLink {
                        link_id: *neighbor_id,
                        link_data: cfg.local_addr,
                        link_type: LINK_TYPE_POINT_TO_POINT,
                        metric: cfg.cost,
                    });
                }
                if let Some(subnet) = local_subnet(cfg) {
                    result.push(RouterLink {
                        link_id: subnet.network(),
                        link_data: subnet.netmask(),
                        link_type: LINK_TYPE_STUB_NETWORK,
                        metric: cfg.cost,
                    });
                }
            }
            NetworkType::Broadcast => {
                let Some(dr) = status.dr else { continue };
                let dr_addr = if dr == local_router_id {
                    cfg.local_addr
                } else {
                    match status.neighbors.get(&dr) {
                        Some(n) => n.address,
                        None => continue,
                    }
                };
                result.push(RouterLink {
                    link_id: dr_addr,
                    link_data: cfg.local_addr,
                    link_type: LINK_TYPE_TRANSIT_NETWORK,
                    metric: cfg.cost,
                });
            }
        }
    }
    result
}

/// Installs a self-originated LSA (`link_state_id`/`advertising_router` per
/// RFC 2328 §12.4's convention — always this router for a Router-LSA,
/// always the DR's interface address keyed to `local_router_id` for a
/// Network-LSA) if `body` actually changed since what's held, bumping the
/// sequence number by one rather than reinstalling identical content every
/// `ORIGINATION_INTERVAL` tick.
fn install_self_originated(
    lsdb: &mut Lsdb,
    local_router_id: Ipv4Addr,
    lsa_type: u8,
    link_state_id: Ipv4Addr,
    body: LsaBody,
) {
    let key = LsaKey {
        lsa_type,
        link_state_id,
        advertising_router: local_router_id,
    };
    let sequence_number = match lsdb.get(&key) {
        Some(existing) if existing.body == body => return,
        Some(existing) => existing.header.sequence_number.wrapping_add(1),
        None => lsa::INITIAL_SEQUENCE_NUMBER,
    };
    lsdb.install(Lsa {
        header: LsaHeader {
            age: 0,
            options: 0,
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
        "ospf lsa originated"
    );
}

/// Pure diffing, like `bgp::session::diff_peers`.
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
            local_addr: Ipv4Addr::new(10, 0, 0, 1),
            local_prefix_len: 24,
            cost: 1,
            kernel_interface: "eth0".to_string(),
            network_type: NetworkType::PointToPoint,
            priority: 1,
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
    fn network_type_change_is_stopped_and_respawned() {
        let mut current = HashMap::new();
        current.insert("eth0.0".to_string(), link("eth0.0", 10));
        let mut desired = HashMap::new();
        let mut broadcast = link("eth0.0", 10);
        broadcast.network_type = NetworkType::Broadcast;
        desired.insert("eth0.0".to_string(), broadcast.clone());
        let (to_stop, to_spawn) = diff_links(&current, &desired);
        assert_eq!(to_stop, vec!["eth0.0".to_string()]);
        assert_eq!(to_spawn, vec![broadcast]);
    }

    #[test]
    fn new_point_to_point_link_status_is_point_to_point_with_no_neighbors() {
        let status = LinkStatus::new(NetworkType::PointToPoint);
        assert_eq!(status.interface_state, InterfaceState::PointToPoint);
        assert!(status.neighbors.is_empty());
        assert_eq!(status.dr, None);
        assert_eq!(status.bdr, None);
    }

    #[test]
    fn new_broadcast_link_status_is_waiting_with_no_neighbors() {
        let status = LinkStatus::new(NetworkType::Broadcast);
        assert_eq!(status.interface_state, InterfaceState::Waiting);
        assert!(status.neighbors.is_empty());
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

    #[test]
    fn dr_is_eligible_with_every_neighbor() {
        assert!(should_form_adjacency(
            InterfaceState::Dr,
            Ipv4Addr::new(1, 1, 1, 1),
            Some(Ipv4Addr::new(9, 9, 9, 9)),
            None,
        ));
    }

    #[test]
    fn dr_other_is_eligible_with_the_dr() {
        let dr = Ipv4Addr::new(2, 2, 2, 2);
        assert!(should_form_adjacency(
            InterfaceState::DrOther,
            dr,
            Some(dr),
            None,
        ));
    }

    #[test]
    fn dr_other_is_eligible_with_the_bdr() {
        let bdr = Ipv4Addr::new(3, 3, 3, 3);
        assert!(should_form_adjacency(
            InterfaceState::DrOther,
            bdr,
            None,
            Some(bdr),
        ));
    }

    fn neighbor_info(state: NeighborState, address: Ipv4Addr) -> NeighborInfo {
        NeighborInfo {
            state,
            priority: 1,
            declared_dr: Ipv4Addr::UNSPECIFIED,
            declared_bdr: Ipv4Addr::UNSPECIFIED,
            last_hello_received: Instant::now(),
            address,
            adjacency: None,
        }
    }

    #[test]
    fn to_neighbor_state_maps_every_variant_one_to_one() {
        assert_eq!(
            to_neighbor_state(NeighborState::Down),
            OspfNeighborState::Down
        );
        assert_eq!(
            to_neighbor_state(NeighborState::Init),
            OspfNeighborState::Init
        );
        assert_eq!(
            to_neighbor_state(NeighborState::TwoWay),
            OspfNeighborState::TwoWay
        );
        assert_eq!(
            to_neighbor_state(NeighborState::ExStart),
            OspfNeighborState::ExStart
        );
        assert_eq!(
            to_neighbor_state(NeighborState::Exchange),
            OspfNeighborState::Exchange
        );
        assert_eq!(
            to_neighbor_state(NeighborState::Loading),
            OspfNeighborState::Loading
        );
        assert_eq!(
            to_neighbor_state(NeighborState::Full),
            OspfNeighborState::Full
        );
    }

    #[test]
    fn router_lsa_links_p2p_with_no_neighbor_still_emits_stub_network() {
        // RFC 2328 §12.4.1.1: a numbered p2p interface always advertises
        // its own subnet, independent of neighbor state.
        let cfg = link("eth0.0", 10);
        let status = LinkStatus::new(NetworkType::PointToPoint);
        let links = router_lsa_links(Ipv4Addr::new(1, 1, 1, 1), &[(cfg, status)]);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].link_type, LINK_TYPE_STUB_NETWORK);
        assert_eq!(links[0].link_id, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(links[0].link_data, Ipv4Addr::new(255, 255, 255, 0));
    }

    #[test]
    fn router_lsa_links_includes_p2p_link_with_a_neighbor() {
        let cfg = link("eth0.0", 10);
        let mut status = LinkStatus::new(NetworkType::PointToPoint);
        let neighbor_id = Ipv4Addr::new(9, 9, 9, 10);
        status.neighbors.insert(
            neighbor_id,
            neighbor_info(NeighborState::Full, Ipv4Addr::new(10, 0, 0, 2)),
        );
        let links = router_lsa_links(Ipv4Addr::new(1, 1, 1, 1), &[(cfg.clone(), status)]);
        assert_eq!(links.len(), 2);
        let p2p = links
            .iter()
            .find(|l| l.link_type == LINK_TYPE_POINT_TO_POINT)
            .unwrap();
        assert_eq!(p2p.link_id, neighbor_id);
        assert_eq!(p2p.link_data, cfg.local_addr);
        assert!(links.iter().any(|l| l.link_type == LINK_TYPE_STUB_NETWORK));
    }

    #[test]
    fn router_lsa_links_skips_broadcast_link_with_no_dr_yet() {
        let mut cfg = link("bd1", 10);
        cfg.network_type = NetworkType::Broadcast;
        let status = LinkStatus::new(NetworkType::Broadcast);
        assert!(router_lsa_links(Ipv4Addr::new(1, 1, 1, 1), &[(cfg, status)]).is_empty());
    }

    #[test]
    fn router_lsa_links_uses_own_address_when_self_is_dr() {
        let mut cfg = link("bd1", 10);
        cfg.network_type = NetworkType::Broadcast;
        let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
        let mut status = LinkStatus::new(NetworkType::Broadcast);
        status.interface_state = InterfaceState::Dr;
        status.dr = Some(local_router_id);
        let links = router_lsa_links(local_router_id, &[(cfg.clone(), status)]);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].link_id, cfg.local_addr);
        assert_eq!(links[0].link_type, 2);
    }

    #[test]
    fn router_lsa_links_uses_dr_neighbor_address_when_not_self() {
        let mut cfg = link("bd1", 10);
        cfg.network_type = NetworkType::Broadcast;
        let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
        let dr_id = Ipv4Addr::new(9, 9, 9, 10);
        let dr_addr = Ipv4Addr::new(10, 0, 0, 2);
        let mut status = LinkStatus::new(NetworkType::Broadcast);
        status.interface_state = InterfaceState::Backup;
        status.dr = Some(dr_id);
        status
            .neighbors
            .insert(dr_id, neighbor_info(NeighborState::Full, dr_addr));
        let links = router_lsa_links(local_router_id, &[(cfg, status)]);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].link_id, dr_addr);
    }

    #[test]
    fn install_self_originated_first_install_uses_initial_sequence_number() {
        let mut lsdb = Lsdb::new();
        let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
        let body = LsaBody::Router(RouterLsaBody {
            flags: 0,
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
    async fn originate_router_lsas_includes_loopback_stub_for_area_with_no_live_link() {
        // Regression test for the area-union fix: an area with only a
        // loopback stub network and no live `LinkConfig` must still get a
        // Router-LSA originated for it.
        let manager = LinkManager::new();
        let area = Ipv4Addr::UNSPECIFIED;
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let subnet: Ipv4Net = "192.168.9.0/24".parse().unwrap();
        manager
            .reconcile(
                Vec::new(),
                HashMap::from([(area, vec![(subnet, 5)])]),
                router_id,
            )
            .await;
        manager.originate_router_lsas(router_id).await;

        let lsdb = manager.lsdb_for(area).await;
        let key = LsaKey {
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: router_id,
            advertising_router: router_id,
        };
        let installed = lsdb.lock().await.get(&key).unwrap();
        let LsaBody::Router(body) = &installed.body else {
            panic!("expected router lsa")
        };
        assert_eq!(body.links.len(), 1);
        assert_eq!(body.links[0].link_type, LINK_TYPE_STUB_NETWORK);
        assert_eq!(body.links[0].link_id, Ipv4Addr::new(192, 168, 9, 0));
        assert_eq!(body.links[0].metric, 5);
    }

    #[tokio::test]
    async fn database_summaries_flattens_every_area() {
        let manager = LinkManager::new();
        let area = Ipv4Addr::UNSPECIFIED;
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let lsdb = manager.lsdb_for(area).await;
        lsdb.lock().await.install(Lsa {
            header: LsaHeader {
                age: 5,
                options: 0,
                lsa_type: lsa::LSA_TYPE_ROUTER,
                link_state_id: router_id,
                advertising_router: router_id,
                sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
                checksum: 0xabcd,
                length: 0,
            },
            body: LsaBody::Router(RouterLsaBody {
                flags: 0,
                links: Vec::new(),
            }),
        });

        let summaries = manager.database_summaries().await;
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].area_id, area);
        assert_eq!(summaries[0].lsa_type, lsa::LSA_TYPE_ROUTER);
        assert_eq!(summaries[0].link_state_id, router_id);
        assert_eq!(summaries[0].advertising_router, router_id);
        assert_eq!(summaries[0].sequence_number, lsa::INITIAL_SEQUENCE_NUMBER);
        assert_eq!(summaries[0].age, 5);
        assert_eq!(summaries[0].checksum, 0xabcd);
    }

    #[test]
    fn install_self_originated_changed_body_bumps_sequence_number() {
        let mut lsdb = Lsdb::new();
        let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
        install_self_originated(
            &mut lsdb,
            local_router_id,
            lsa::LSA_TYPE_ROUTER,
            local_router_id,
            LsaBody::Router(RouterLsaBody {
                flags: 0,
                links: Vec::new(),
            }),
        );
        install_self_originated(
            &mut lsdb,
            local_router_id,
            lsa::LSA_TYPE_ROUTER,
            local_router_id,
            LsaBody::Router(RouterLsaBody {
                flags: 1,
                links: Vec::new(),
            }),
        );
        let key = LsaKey {
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: local_router_id,
            advertising_router: local_router_id,
        };
        assert_eq!(
            lsdb.get(&key).unwrap().header.sequence_number,
            lsa::INITIAL_SEQUENCE_NUMBER + 1
        );
    }

    #[test]
    fn run_election_keeps_a_neighbor_past_two_way_in_the_candidate_pool() {
        // Regression test: once a neighbor progresses to `ExStart` (or
        // beyond), it must stay eligible for DR/BDR election — excluding
        // it here would make this router think it's alone on the segment
        // and incorrectly re-elect itself DR on every subsequent
        // recomputation, flapping a segment that already converged.
        let mut cfg = link("bd1", 10);
        cfg.network_type = NetworkType::Broadcast;
        cfg.priority = 1;
        let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
        let neighbor_id = Ipv4Addr::new(9, 9, 9, 9);
        let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::Broadcast));
        status.send_modify(|s| {
            // A previously-converged, stable outcome: the neighbor is DR
            // (and its own Hello already self-declares that), this router
            // is Backup.
            s.dr = Some(neighbor_id);
            s.bdr = Some(local_router_id);
            s.interface_state = InterfaceState::Backup;
            let mut info = neighbor_info(NeighborState::ExStart, Ipv4Addr::new(10, 0, 0, 2));
            info.declared_dr = neighbor_id;
            s.neighbors.insert(neighbor_id, info);
        });

        run_election(&cfg, local_router_id, &status);

        let result = status.borrow();
        assert_eq!(result.dr, Some(neighbor_id));
        assert_eq!(result.bdr, Some(local_router_id));
    }
}
