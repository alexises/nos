//! One `OSPFv3` link's driver, plus `LinkManager` — the RFC 5340 counterpart
//! of `ospf::link`. Same orchestrator architecture (one raw socket per
//! link, neighbor FSM(s) from `nos_ospf_common::neighbor`, RFC 2328 §9.4
//! DR/BDR election from `nos_ospf_common::election`, then `crate::exchange`'s
//! DBD/LSR/LSU/LSAck adjacency-forming exchange), but every self-origination
//! function is structurally new (RFC 5340 restructures where addresses and
//! prefixes live — see `crate::spf`'s module doc comment). Authentication is
//! RFC 7166's trailer: `LinkConfig.auth` sets the AT-bit in Hello/DBD and
//! makes the socket sign every send (`socket.rs`); `run` verifies every
//! receive (`packet::verify_trailer`) and keeps the per-neighbor anti-replay
//! sequence (`accept_crypto_sequence`), like `ospf::link`.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ipnet::{IpNet, Ipv6Net};
use nos_proto::{
    LinkInterfaceState, NetworkType, OspfNeighborState, Ospfv3LsaSummary, Ospfv3NeighborSummary,
    RedistributeUpdate,
};
use nos_rpl::CompiledPolicy;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::election;
use crate::exchange::{self, AdjacencyData};
use crate::lsa::{
    self, AsExternalLsaBody, GraceLsaBody, InterAreaPrefixLsaBody, InterAreaRouterLsaBody,
    IntraAreaPrefixEntry, IntraAreaPrefixLsaBody, LinkLsaBody, LinkPrefixEntry, Lsa, LsaBody,
    LsaHeader, LsaKey, NetworkLsaBody, RouterLsaBody, RouterLsaLink, LINK_TYPE_POINT_TO_POINT,
    LINK_TYPE_TRANSIT_NETWORK,
};
use crate::lsdb::Lsdb;
use crate::neighbor::{self, NeighborState};
use crate::packet::{self, DbdPacket, LsAckPacket, LsrPacket, LsuPacket, OspfPacket};
use crate::socket::OspfSocket;

/// What a link task sends and receives on: the real raw socket, or (in
/// tests) an in-memory wire — lets `run` and `LinkManager` be exercised
/// without `CAP_NET_RAW` (#131). Mirrors `ospf::link::LinkSocket`.
pub enum LinkSocket {
    Os(OspfSocket),
    #[cfg(test)]
    Mem(tests::wire::Port),
}

impl LinkSocket {
    fn send_multicast(&self, ifindex: u32, payload: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Os(s) => s.send_multicast(ifindex, payload),
            #[cfg(test)]
            Self::Mem(p) => {
                p.send(None, payload);
                Ok(())
            }
        }
    }

    fn send_unicast(&self, dest: Ipv6Addr, ifindex: u32, payload: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Os(s) => s.send_unicast(dest, ifindex, payload),
            #[cfg(test)]
            Self::Mem(p) => {
                p.send(Some(dest), payload);
                Ok(())
            }
        }
    }

    async fn recv_packet(&self) -> std::io::Result<(Ipv6Addr, Vec<u8>)> {
        match self {
            Self::Os(s) => s.recv_packet().await,
            #[cfg(test)]
            Self::Mem(p) => p.recv().await,
        }
    }
}

/// Opens one link's socket — the real one in production, see `LinkSocket`.
pub type Opener = Arc<dyn Fn(&LinkConfig) -> std::io::Result<LinkSocket> + Send + Sync>;
use crate::spf;

/// RFC 2328 Appendix C.3's `RxmtInterval` — same fixed value/ponytail
/// rationale as `ospf::link::RXMT_INTERVAL`.
const RXMT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Same cadence/rationale as `ospf::link::ORIGINATION_INTERVAL`.
const ORIGINATION_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Same cadence/rationale as `ospf::link::AGE_TICK_INTERVAL`.
const AGE_TICK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// How long `LinkManager::shutdown` waits after each Grace-LSA send before
/// the next one (two sends) and before exiting — enough for the link tasks
/// to put them on the wire. ponytail: sent twice, not retransmitted until
/// acked; a lossless local link is the norm here.
const GRACE_SEND_WINDOW: std::time::Duration = std::time::Duration::from_millis(500);

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
    /// `mtu-ignore`: skip the RFC 2328 §10.6 DBD Interface MTU check.
    pub mtu_ignore: bool,
    /// RFC 7166 keys resolved from `Ospfv3Profile.auth` (`reconcile.rs`);
    /// `None` runs unauthenticated. Part of the wholesale-diffed struct, so
    /// a key change restarts the link like any other field.
    pub auth: Option<packet::TrailerAuth>,
    /// RFC 5340 §A.3.1 Instance ID (`Ospfv3Profile.instance_id`, 0 if
    /// unset): stamped on every packet sent, and a received packet carrying
    /// another one is dropped.
    pub instance_id: u8,
}

/// The Options every self-originated LSA and packet carries: `V6`/`R`, and
/// `E` since every area is a normal area (RFC 5340 §A.2 — no stub areas or
/// NSSA in `OSPFv3` yet; an FRR neighbor treats a clear E-bit in a normal
/// area as a mismatch).
const OWN_OPTIONS: u32 = lsa::OPTION_V6 | lsa::OPTION_E | lsa::OPTION_R;

/// Hello/DBD Options for this link — `OWN_OPTIONS`, plus RFC 7166 §2.1's
/// AT-bit when the link is authenticated.
fn link_options(cfg: &LinkConfig) -> u32 {
    let at = if cfg.auth.is_some() {
        lsa::OPTION_AT
    } else {
        0
    };
    OWN_OPTIONS | at
}

/// RFC 7166 §4.1's anti-replay check, mirroring
/// `ospf::link::accept_crypto_sequence`: `true` to dispatch, `false` to
/// drop. Always `true` unauthenticated (`seq` is `None`) or for a neighbor
/// not yet known (`handle_hello` creates the entry).
fn accept_crypto_sequence(status: &StatusHandle, seq: Option<u64>, pkt: &OspfPacket) -> bool {
    let Some(seq) = seq else { return true };
    let router_id = packet::router_id(pkt);
    let last = status
        .borrow()
        .neighbors
        .get(&router_id)
        .and_then(|n| n.last_crypto_seq);
    if last.is_some_and(|last| seq <= last) {
        return false;
    }
    status.send_modify(|s| {
        if let Some(n) = s.neighbors.get_mut(&router_id) {
            n.last_crypto_seq = Some(seq);
        }
    });
    true
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
    /// Reported only (`last_hello_secs`): when the last valid Hello arrived.
    pub last_hello_received: Instant,
    /// RFC 4222 §2 recommendation 2 — see `ospf::link::NeighborInfo::last_heard`.
    pub last_heard: Instant,
    /// The neighbor's own link-local address, as seen on the last Hello it
    /// sent — DBD/LSR/LSU/LSAck reply unicast to this.
    pub address: Ipv6Addr,
    pub adjacency: Option<AdjacencyData>,
    /// The last accepted RFC 7166 sequence number from this neighbor
    /// (`None` until one is seen, or on an unauthenticated link).
    pub last_crypto_seq: Option<u64>,
    /// RFC 5187 helper mode: `Some` while this neighbor is restarting under
    /// a Grace-LSA it sent. Until then its adjacency is held `Full` through
    /// missing Hellos and Hellos that don't list us (see `in_grace`).
    pub grace_deadline: Option<Instant>,
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
                NetworkType::PointToPoint | NetworkType::PointToMultipoint => {
                    InterfaceState::PointToPoint
                }
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
        options: link_options(cfg),
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
/// shape, minus all crypto-sequence/auth bookkeeping. `lsdb` is the area's
/// shared store; `link_local_lsdb` is this link's own (RFC 5340 §4.5.1:
/// Link-LSAs never leave the link they belong to, so every summary/flood
/// below draws from both, but only ever *this* link's Link-LSAs).
#[allow(clippy::too_many_arguments)]
pub async fn run(
    socket: std::io::Result<LinkSocket>,
    cfg: LinkConfig,
    local_router_id: Ipv4Addr,
    lsdb: Arc<Mutex<Lsdb>>,
    link_local_lsdb: Arc<Mutex<Lsdb>>,
    as_lsdb: Arc<Mutex<Lsdb>>,
    status: StatusHandle,
    dbd_max_headers: Option<usize>,
    mut grace_rx: mpsc::UnboundedReceiver<u32>,
) {
    let stores = Stores {
        area: &lsdb,
        link: &link_local_lsdb,
        as_scope: &as_lsdb,
    };
    let dbd_max_headers =
        dbd_max_headers.unwrap_or_else(|| exchange::mtu_based_max_headers(cfg.mtu));
    let socket = match socket {
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

    info!(link = %cfg.attach_point, vrf = %cfg.vrf, authenticated = cfg.auth.is_some(), "ospfv3 link driver started");
    if is_broadcast {
        info!(link = %cfg.attach_point, "ospfv3 interface reached waiting");
    }

    loop {
        // RFC 4222 prioritisation — see `ospf::link::run`'s note and ceiling.
        tokio::select! {
            biased;
            _ = hello_ticker.tick() => {
                send_hello(&socket, &cfg, local_router_id, &status);
            }
            result = socket.recv_packet() => {
                match result {
                    Ok((source, data)) => {
                        // Before the trailer check: another instance's packets on a
                        // shared link are routine and may use other keys (RFC 5838).
                        if let Some(received) =
                            packet::instance_id(&data).filter(|i| *i != cfg.instance_id)
                        {
                            debug!(
                                link = %cfg.attach_point, source = %source, received,
                                expected = cfg.instance_id, "ospfv3 packet instance id mismatch, dropping"
                            );
                            continue;
                        }
                        let (data, seq) = match packet::verify_trailer(&data, cfg.auth.as_ref(), source) {
                            Ok(verified) => verified,
                            Err(e) => {
                                warn!(link = %cfg.attach_point, source = %source, error = %e, "ospfv3 packet authentication failed");
                                continue;
                            }
                        };
                        match packet::decode(data) {
                            Ok(pkt) if !accept_crypto_sequence(&status, seq, &pkt) => {
                                warn!(
                                    link = %cfg.attach_point, neighbor = %packet::router_id(&pkt),
                                    "ospfv3 packet crypto sequence number not increasing, dropping"
                                );
                            }
                            Ok(pkt) => {
                                if !matches!(pkt, OspfPacket::Hello(_)) {
                                    note_alive(&cfg, &status, packet::router_id(&pkt), &mut p2p_dead_deadline);
                                }
                                match pkt {
                                    OspfPacket::Hello(hello) => {
                                        let left_waiting = handle_hello(
                                            &cfg, local_router_id, &status, source, &hello,
                                            &mut p2p_dead_deadline, waiting,
                                        );
                                        if left_waiting {
                                            waiting = false;
                                        }
                                        advance_adjacencies(&socket, &cfg, local_router_id, &status);
                                    }
                                    OspfPacket::Dbd(dbd) => {
                                        if let Some(actions) = handle_dbd(
                                            &cfg, local_router_id, &status, &stores, &dbd, dbd_max_headers,
                                        )
                                        .await
                                        {
                                            execute_actions(&socket, &cfg, local_router_id, &status, dbd.router_id, actions);
                                        }
                                    }
                                    OspfPacket::Lsr(lsr) => {
                                        if let Some(actions) =
                                            handle_lsr(&cfg, local_router_id, &status, &stores, &lsr).await
                                        {
                                            execute_actions(&socket, &cfg, local_router_id, &status, lsr.router_id, actions);
                                        }
                                    }
                                    OspfPacket::Lsu(lsu) => {
                                        if let Some(actions) =
                                            handle_lsu(&cfg, local_router_id, &status, &stores, &lsu).await
                                        {
                                            execute_actions(&socket, &cfg, local_router_id, &status, lsu.router_id, actions);
                                        }
                                    }
                                    OspfPacket::LsAck(ack) => {
                                        handle_lsack(&status, &ack);
                                    }
                                }
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
            _ = dead_sweep.tick() => {
                expire_grace(&cfg, &status);
                if !is_broadcast {
                    continue;
                }
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
            Some(grace_period) = grace_rx.recv() => {
                send_grace_lsas(&socket, &cfg, local_router_id, &status, grace_period);
            }
            _ = rxmt_sweep.tick() => {
                retransmit_pending(&socket, &cfg, local_router_id, &status);
                flood_full_neighbors(&socket, &cfg, local_router_id, &stores, &status).await;
            }
        }
    }
}

/// The three stores one link reads and writes (RFC 5340 §4.5.1): its area's,
/// its own link-local one and the AS-wide one.
struct Stores<'a> {
    area: &'a Mutex<Lsdb>,
    link: &'a Mutex<Lsdb>,
    as_scope: &'a Mutex<Lsdb>,
}

impl Stores<'_> {
    /// Every LSA this link may summarize/flood.
    async fn all(&self) -> Vec<Arc<Lsa>> {
        let mut lsas = self.area.lock().await.all();
        lsas.extend(self.link.lock().await.all());
        lsas.extend(self.as_scope.lock().await.all());
        lsas
    }

    async fn headers(&self) -> Vec<LsaHeader> {
        let mut headers = self.area.lock().await.headers();
        headers.extend(self.link.lock().await.headers());
        headers.extend(self.as_scope.lock().await.headers());
        headers
    }
}

fn send_hello(
    socket: &LinkSocket,
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
        NetworkType::PointToPoint | NetworkType::PointToMultipoint => {
            (Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED)
        }
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
        options: link_options(cfg),
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
    // RFC 5187 §3: a restarting neighbor's fresh Hellos don't list us yet —
    // that must not tear the adjacency down while we're helping it.
    let new_state = if !saw_self && in_grace(status, hello.router_id) {
        old_state
    } else {
        neighbor::step(old_state, neighbor::Event::HelloReceived { saw_self })
    };
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
                last_heard: Instant::now(),
                address: source,
                adjacency: None,
                last_crypto_seq: None,
                grace_deadline: None,
            });
        entry.state = new_state;
        entry.priority = hello.router_priority;
        entry.declared_dr = hello.designated_router;
        entry.declared_bdr = hello.backup_designated_router;
        entry.interface_id = hello.interface_id;
        entry.last_hello_received = Instant::now();
        entry.last_heard = Instant::now();
        entry.address = source;
        if matches!(new_state, NeighborState::Down | NeighborState::Init) {
            entry.adjacency = None;
        }
    });

    match cfg.network_type {
        NetworkType::PointToPoint | NetworkType::PointToMultipoint => {
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
    socket: &LinkSocket,
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

#[allow(clippy::too_many_arguments)]
async fn handle_dbd(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    stores: &Stores<'_>,
    dbd: &DbdPacket,
    dbd_max_headers: usize,
) -> Option<Vec<exchange::Action>> {
    let (old_state, mut adj) = {
        let snapshot = status.borrow();
        let neighbor = snapshot.neighbors.get(&dbd.router_id)?;
        (neighbor.state, neighbor.adjacency.clone()?)
    };

    // RFC 2328 §10.6: only in ExStart/Exchange; the neighbor stays in ExStart.
    if matches!(old_state, NeighborState::ExStart | NeighborState::Exchange)
        && !exchange::mtu_acceptable(dbd.interface_mtu, cfg.mtu, cfg.mtu_ignore)
    {
        warn!(
            neighbor = %dbd.router_id, local_mtu = cfg.mtu, neighbor_mtu = dbd.interface_mtu,
            "ospfv3 dbd rejected, neighbor interface mtu exceeds ours"
        );
        return None;
    }

    // A MaxAge entry is only held to be flooded out; summarizing it would
    // invite an LSR that fails (BadLSReq) once it's evicted.
    let mut local_lsdb_headers = stores.headers().await;
    local_lsdb_headers.retain(|h| h.age < lsa::MAX_AGE);
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
    stores: &Stores<'_>,
    lsr: &LsrPacket,
) -> Option<Vec<exchange::Action>> {
    let (old_state, mut adj) = {
        let snapshot = status.borrow();
        let neighbor = snapshot.neighbors.get(&lsr.router_id)?;
        (neighbor.state, neighbor.adjacency.clone()?)
    };

    let actions = {
        let lsdb = stores.area.lock().await;
        let link_local_lsdb = stores.link.lock().await;
        let as_lsdb = stores.as_scope.lock().await;
        exchange::on_lsr_received(&mut adj, &lsdb, &link_local_lsdb, &as_lsdb, lsr)
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
    stores: &Stores<'_>,
    lsu: &LsuPacket,
) -> Option<Vec<exchange::Action>> {
    let (old_state, mut adj) = {
        let snapshot = status.borrow();
        let neighbor = snapshot.neighbors.get(&lsu.router_id)?;
        (neighbor.state, neighbor.adjacency.clone()?)
    };

    let (actions, newly_installed) = {
        let mut lsdb = stores.area.lock().await;
        let mut link_local_lsdb = stores.link.lock().await;
        let mut as_lsdb = stores.as_scope.lock().await;
        exchange::on_lsu_received(&mut adj, &mut lsdb, &mut link_local_lsdb, &mut as_lsdb, lsu)
    };
    for header in &newly_installed {
        info!(
            link = %cfg.attach_point, neighbor = %lsu.router_id,
            lsa_type = header.lsa_type, link_state_id = %header.link_state_id,
            advertising_router = %header.advertising_router,
            "ospfv3 lsa installed"
        );
    }
    for grace in lsu
        .lsas
        .iter()
        .filter(|l| newly_installed.contains(&l.header))
    {
        let LsaBody::Grace(body) = grace.body else {
            continue;
        };
        // Acted on at once, never held: a copy left in the LSDB would be
        // offered back to the restarted router and flooded to us again.
        stores.link.lock().await.remove(&grace.header.key());
        on_grace_lsa(cfg, status, &grace.header, body);
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
        // Past `Exchange`, only the slave's final reply can still be needed:
        // `exchange` resends it for the master's duplicate (RFC 2328 §10.6).
        // ponytail: kept until the next `ExStart`, not the RFC's
        // `RouterDeadInterval`; one packet, no timer.
        if adj.is_master && matches!(new_state, NeighborState::Loading | NeighborState::Full) {
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
            if in_grace(status, neighbor_id) {
                info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospfv3 helper: neighbor reformed, exiting grace early");
            }
        }
        _ => {}
    }

    status.send_modify(|s| {
        if let Some(info) = s.neighbors.get_mut(&neighbor_id) {
            info.state = new_state;
            info.adjacency = Some(adj.clone());
            if new_state == NeighborState::Full && old_state != NeighborState::Full {
                info.grace_deadline = None;
            }
        }
    });

    actions
}

fn execute_actions(
    socket: &LinkSocket,
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
            exchange::Action::SendDbd(mut pkt) => {
                pkt.options = link_options(cfg);
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
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
) {
    let snapshot = status.borrow().clone();
    for (neighbor_id, info) in &snapshot.neighbors {
        let Some(adj) = &info.adjacency else { continue };
        // Only while negotiating: a slave's kept final reply goes out only
        // in answer to the master's duplicate (`exchange`), never on a timer.
        if let (NeighborState::ExStart | NeighborState::Exchange, Some(dbd)) =
            (info.state, &adj.last_dbd_sent)
        {
            let mut dbd = dbd.clone();
            dbd.options = link_options(cfg);
            if let Err(e) =
                socket.send_unicast(info.address, cfg.interface_id, &packet::encode_dbd(&dbd))
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
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    stores: &Stores<'_>,
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
    let lsas = stores.all().await;
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

/// RFC 4222 §2 recommendation 2 — mirrors `ospf::link::note_alive`.
fn note_alive(
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
        *p2p_dead_deadline = now + std::time::Duration::from_secs(u64::from(cfg.dead_interval));
    }
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
                && info.grace_deadline.is_none()
                && now.duration_since(info.last_heard) >= dead_interval
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

fn in_grace(status: &StatusHandle, neighbor_id: Ipv4Addr) -> bool {
    status
        .borrow()
        .neighbors
        .get(&neighbor_id)
        .is_some_and(|n| n.grace_deadline.is_some())
}

/// RFC 5187 helper side: a Grace-LSA from a `Full` neighbor on this link
/// starts (or refreshes) its grace period; a `MaxAge` one — the restarting
/// router flushing it — ends it.
fn on_grace_lsa(cfg: &LinkConfig, status: &StatusHandle, header: &LsaHeader, body: GraceLsaBody) {
    let neighbor_id = header.advertising_router;
    let Some((state, deadline)) = status
        .borrow()
        .neighbors
        .get(&neighbor_id)
        .map(|n| (n.state, n.grace_deadline))
    else {
        return;
    };
    if header.age >= lsa::MAX_AGE {
        if deadline.is_some() {
            info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospfv3 helper: grace-lsa flushed, exiting grace");
            status.send_modify(|s| {
                if let Some(n) = s.neighbors.get_mut(&neighbor_id) {
                    n.grace_deadline = None;
                }
            });
        }
        return;
    }
    if state != NeighborState::Full {
        warn!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospfv3 helper: ignoring grace-lsa from a neighbor that is not full");
        return;
    }
    if deadline.is_none() {
        info!(
            link = %cfg.attach_point, neighbor = %neighbor_id,
            grace_period = body.grace_period, restart_reason = body.restart_reason,
            "ospfv3 helper: grace period entered"
        );
    }
    let deadline = Instant::now() + std::time::Duration::from_secs(u64::from(body.grace_period));
    status.send_modify(|s| {
        if let Some(n) = s.neighbors.get_mut(&neighbor_id) {
            n.grace_deadline = Some(deadline);
        }
    });
}

/// Ends every grace period whose deadline has passed; the neighbor is then
/// subject to the ordinary inactivity timer again, restarted from now.
fn expire_grace(cfg: &LinkConfig, status: &StatusHandle) {
    let now = Instant::now();
    let expired: Vec<Ipv4Addr> = status
        .borrow()
        .neighbors
        .iter()
        .filter(|(_, n)| n.grace_deadline.is_some_and(|d| d <= now))
        .map(|(id, _)| *id)
        .collect();
    for id in &expired {
        warn!(link = %cfg.attach_point, neighbor = %id, "ospfv3 helper: grace period expired");
    }
    if !expired.is_empty() {
        status.send_modify(|s| {
            for id in &expired {
                if let Some(n) = s.neighbors.get_mut(id) {
                    n.grace_deadline = None;
                    n.last_heard = now;
                }
            }
        });
    }
}

/// RFC 5187 restarting side: one Grace-LSA to every `Full` neighbor on
/// this link, just before the process exits.
fn send_grace_lsas(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    grace_period: u32,
) {
    let grace = Lsa {
        header: LsaHeader {
            age: 0,
            lsa_type: lsa::LSA_TYPE_GRACE,
            link_state_id: lsa::interface_id_key(cfg.interface_id),
            advertising_router: local_router_id,
            sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
            checksum: 0,
            length: 0,
        },
        body: LsaBody::Grace(GraceLsaBody {
            grace_period,
            restart_reason: lsa::RESTART_REASON_SOFTWARE,
        }),
    };
    let payload = packet::encode_lsu(&LsuPacket {
        router_id: local_router_id,
        area_id: cfg.area_id,
        lsas: vec![grace],
    });
    let full: Vec<(Ipv4Addr, Ipv6Addr)> = status
        .borrow()
        .neighbors
        .iter()
        .filter(|(_, n)| n.state == NeighborState::Full)
        .map(|(id, n)| (*id, n.address))
        .collect();
    for (neighbor_id, address) in full {
        match socket.send_unicast(address, cfg.interface_id, &payload) {
            Ok(()) => info!(
                link = %cfg.attach_point, neighbor = %neighbor_id, grace_period,
                "ospfv3 graceful restart: grace-lsa sent"
            ),
            Err(e) => {
                warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospfv3 grace-lsa");
            }
        }
    }
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
    /// Asks the link task to send Grace-LSAs (the grace period, seconds).
    grace_tx: mpsc::UnboundedSender<u32>,
}

/// Owns every `OSPFv3` link's driver task for one `nos-ospfv3d` process, plus
/// its per-area LSDBs — mirrors `ospf::link::LinkManager` — and, unlike v2,
/// a store per *link* for RFC 5340 §4.5.1's link-local-scoped LSAs and one
/// AS-wide store for its AS-scoped ones.
pub struct LinkManager {
    links: Mutex<HashMap<String, LinkEntry>>,
    /// Area-scoped LSAs (Router/Network/Intra-Area-Prefix and their RFC
    /// 8362 counterparts), per area id, shared by every link in that area.
    lsdbs: Mutex<HashMap<Ipv4Addr, Arc<Mutex<Lsdb>>>>,
    /// Link-local-scoped LSAs (Link-LSA/E-Link-LSA), per attach point —
    /// exclusively that link's own, so a link's DBD summary/flood can never
    /// offer another link's Link-LSAs (RFC 5340 §4.5.1). SPF still merges
    /// every same-area link's store back in (`compute_routes`).
    link_local_lsdbs: Mutex<HashMap<String, Arc<Mutex<Lsdb>>>>,
    /// AS-scoped LSAs (AS-External-LSA/E-AS-External-LSA, `lsa::is_as_scope`)
    /// — one store for the whole router, read by every link whatever its
    /// area, so an ASBR's LSA learned in one area floods on into the others
    /// with no ABR code (v2 copies each Type-5 into every area instead).
    as_lsdb: Arc<Mutex<Lsdb>>,
    /// Raw (pre-policy) redistributed IPv6 prefixes from
    /// `Ospfv3Request::RedistributeRoutes`, and what passes
    /// `redistribute_policy` (re-derived on every update and resync). A
    /// non-empty filtered set makes this router an ASBR.
    redistribute_raw: Mutex<HashSet<Ipv6Net>>,
    redistribute_filtered: Mutex<HashSet<Ipv6Net>>,
    redistribute_policy: Mutex<Arc<CompiledPolicy>>,
    /// Link State IDs of prefix-keyed LSAs (Inter-Area-Prefix,
    /// AS-External), which are opaque in v3 (RFC 5340 §4.4.3.3/§4.4.3.5):
    /// one per `(legacy LS type, prefix)`, handed out from a counter and
    /// kept for the process's life. A restart may hand out other IDs; the
    /// stateless `withdraw_undesired` then flushes the old incarnation's.
    lsids: Mutex<HashMap<(u16, Ipv6Net), Ipv4Addr>>,
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
    /// the legacy one. ponytail: no Sparse mode. The other flavor's own LSAs
    /// (from before a toggle, or a previous incarnation) are prematurely aged
    /// on every origination tick (`withdraw_undesired`).
    extended_lsa: AtomicBool,
    /// RFC 5187 grace period (seconds) to announce on a planned restart;
    /// `0` = graceful restart off.
    grace_period: AtomicU16,
    opener: Opener,
}

/// Every LS type this router originates in either RFC 8362 mode — the only
/// ones `withdraw_undesired` ever flushes (never a Grace-LSA).
const OWNED_TYPES: [u16; 14] = [
    lsa::LSA_TYPE_ROUTER,
    lsa::LSA_TYPE_NETWORK,
    lsa::LSA_TYPE_LINK,
    lsa::LSA_TYPE_INTRA_AREA_PREFIX,
    lsa::LSA_TYPE_INTER_AREA_PREFIX,
    lsa::LSA_TYPE_INTER_AREA_ROUTER,
    lsa::LSA_TYPE_AS_EXTERNAL,
    lsa::LSA_TYPE_E_ROUTER,
    lsa::LSA_TYPE_E_NETWORK,
    lsa::LSA_TYPE_E_LINK,
    lsa::LSA_TYPE_E_INTRA_AREA_PREFIX,
    lsa::LSA_TYPE_E_INTER_AREA_PREFIX,
    lsa::LSA_TYPE_E_INTER_AREA_ROUTER,
    lsa::LSA_TYPE_E_AS_EXTERNAL,
];

/// The keys one origination tick originated, per store.
#[derive(Default)]
struct Originated {
    areas: HashMap<Ipv4Addr, HashSet<LsaKey>>,
    links: HashMap<String, HashSet<LsaKey>>,
    as_scope: HashSet<LsaKey>,
}

/// The LS types this router originates, per RFC 8362 mode.
struct LsaTypes {
    router: u16,
    network: u16,
    link: u16,
    intra_area_prefix: u16,
    inter_area_prefix: u16,
    inter_area_router: u16,
    as_external: u16,
}

impl LsaTypes {
    fn new(extended: bool) -> Self {
        if extended {
            Self {
                router: lsa::LSA_TYPE_E_ROUTER,
                network: lsa::LSA_TYPE_E_NETWORK,
                link: lsa::LSA_TYPE_E_LINK,
                intra_area_prefix: lsa::LSA_TYPE_E_INTRA_AREA_PREFIX,
                inter_area_prefix: lsa::LSA_TYPE_E_INTER_AREA_PREFIX,
                inter_area_router: lsa::LSA_TYPE_E_INTER_AREA_ROUTER,
                as_external: lsa::LSA_TYPE_E_AS_EXTERNAL,
            }
        } else {
            Self {
                router: lsa::LSA_TYPE_ROUTER,
                network: lsa::LSA_TYPE_NETWORK,
                link: lsa::LSA_TYPE_LINK,
                intra_area_prefix: lsa::LSA_TYPE_INTRA_AREA_PREFIX,
                inter_area_prefix: lsa::LSA_TYPE_INTER_AREA_PREFIX,
                inter_area_router: lsa::LSA_TYPE_INTER_AREA_ROUTER,
                as_external: lsa::LSA_TYPE_AS_EXTERNAL,
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

    pub fn set_graceful_restart(&self, grace_period: Option<u16>) {
        self.grace_period
            .store(grace_period.unwrap_or(0), Ordering::Relaxed);
    }

    fn lsa_types(&self) -> LsaTypes {
        LsaTypes::new(self.extended_lsa.load(Ordering::Relaxed))
    }

    pub fn new(age_multiplier: u16, dbd_max_headers: Option<usize>) -> Arc<Self> {
        Self::with_opener(
            age_multiplier,
            dbd_max_headers,
            Arc::new(|cfg: &LinkConfig| {
                let auth = cfg.auth.clone().map(|a| (a, cfg.link_local_address));
                OspfSocket::open(
                    &cfg.kernel_interface,
                    cfg.interface_id,
                    auth,
                    cfg.instance_id,
                )
                .map(LinkSocket::Os)
            }),
        )
    }

    /// `new` with the link sockets opened by `opener` — the in-memory wire in
    /// tests.
    pub fn with_opener(
        age_multiplier: u16,
        dbd_max_headers: Option<usize>,
        opener: Opener,
    ) -> Arc<Self> {
        let manager = Arc::new(Self {
            links: Mutex::new(HashMap::new()),
            lsdbs: Mutex::new(HashMap::new()),
            link_local_lsdbs: Mutex::new(HashMap::new()),
            as_lsdb: Arc::new(Mutex::new(Lsdb::new())),
            redistribute_raw: Mutex::new(HashSet::new()),
            redistribute_filtered: Mutex::new(HashSet::new()),
            redistribute_policy: Mutex::new(Arc::new(nos_rpl::ACCEPT_ALL.clone())),
            lsids: Mutex::new(HashMap::new()),
            router_id: Mutex::new(None),
            loopback_prefixes: Mutex::new(HashMap::new()),
            age_multiplier,
            dbd_max_headers,
            extended_lsa: AtomicBool::new(false),
            grace_period: AtomicU16::new(0),
            opener,
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
                            background.originate_all(router_id).await;
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

    async fn link_local_lsdb_for(&self, attach_point: &str) -> Arc<Mutex<Lsdb>> {
        Arc::clone(
            self.link_local_lsdbs
                .lock()
                .await
                .entry(attach_point.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(Lsdb::new()))),
        )
    }

    /// Every link-local store in `area_id`, tagged by attach point.
    async fn link_local_lsdbs_in(&self, area_id: Ipv4Addr) -> Vec<(String, Arc<Mutex<Lsdb>>)> {
        let attach_points: Vec<String> = self
            .links
            .lock()
            .await
            .values()
            .filter(|e| e.config.area_id == area_id)
            .map(|e| e.config.attach_point.clone())
            .collect();
        let stores = self.link_local_lsdbs.lock().await;
        attach_points
            .into_iter()
            .filter_map(|ap| stores.get(&ap).map(|s| (ap, Arc::clone(s))))
            .collect()
    }

    /// Ages every store — per-area and per-link alike (RFC 2328 §14 aging
    /// is scope-agnostic).
    async fn age_lsdbs(&self) {
        let hold: HashSet<Ipv4Addr> = self
            .links
            .lock()
            .await
            .values()
            .flat_map(|e| {
                e.status
                    .borrow()
                    .neighbors
                    .iter()
                    .filter(|(_, n)| n.grace_deadline.is_some())
                    .map(|(id, _)| *id)
                    .collect::<Vec<_>>()
            })
            .collect();
        let areas: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(area_id, lsdb)| (*area_id, Arc::clone(lsdb)))
            .collect();
        for (area_id, lsdb) in areas {
            let evicted = lsdb.lock().await.age_and_evict(self.age_multiplier, &hold);
            for key in evicted {
                info!(
                    area = %area_id, lsa_type = key.lsa_type, link_state_id = %key.link_state_id,
                    advertising_router = %key.advertising_router,
                    "ospfv3 lsa maxage flushed"
                );
            }
        }
        let links: Vec<(String, Arc<Mutex<Lsdb>>)> = self
            .link_local_lsdbs
            .lock()
            .await
            .iter()
            .map(|(attach_point, lsdb)| (attach_point.clone(), Arc::clone(lsdb)))
            .collect();
        for (attach_point, lsdb) in links {
            let evicted = lsdb.lock().await.age_and_evict(self.age_multiplier, &hold);
            for key in evicted {
                info!(
                    link = %attach_point, lsa_type = key.lsa_type, link_state_id = %key.link_state_id,
                    advertising_router = %key.advertising_router,
                    "ospfv3 lsa maxage flushed"
                );
            }
        }
        let evicted = self
            .as_lsdb
            .lock()
            .await
            .age_and_evict(self.age_multiplier, &hold);
        for key in evicted {
            info!(
                scope = "as", lsa_type = key.lsa_type, link_state_id = %key.link_state_id,
                advertising_router = %key.advertising_router,
                "ospfv3 lsa maxage flushed"
            );
        }
    }

    /// The areas this router has a live link or loopback in.
    async fn attached_areas(&self) -> HashSet<Ipv4Addr> {
        let mut areas: HashSet<Ipv4Addr> = self
            .links
            .lock()
            .await
            .values()
            .map(|e| e.config.area_id)
            .collect();
        areas.extend(self.loopback_prefixes.lock().await.keys().copied());
        areas
    }

    /// The Link State ID for a prefix-keyed LSA — see `lsids`.
    async fn lsid(&self, lsa_type: u16, prefix: Ipv6Net) -> Ipv4Addr {
        let mut lsids = self.lsids.lock().await;
        let next = u32::try_from(lsids.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        *lsids
            .entry((lsa_type, prefix))
            .or_insert_with(|| lsa::interface_id_key(next))
    }

    /// Recomputes and (re)installs this router's own Router-LSA per area —
    /// pure topology only, no addresses (see the module doc comment).
    async fn originate_router_lsas(&self, local_router_id: Ipv4Addr, done: &mut Originated) {
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

        // RFC 5340 §A.4.3: B while attached to 2+ areas (not `lsdbs.len()`,
        // which never shrinks), E while originating AS-External-LSAs — the
        // same set `originate_as_external_lsas` reads, so the bit and the
        // LSAs come and go in the same tick.
        let mut flags = 0;
        if self.attached_areas().await.len() >= 2 {
            flags |= lsa::ROUTER_FLAG_B;
        }
        if !self.redistribute_filtered.lock().await.is_empty() {
            flags |= lsa::ROUTER_FLAG_E;
        }
        let types = self.lsa_types();
        debug_assert!(!lsa::is_link_local_scope(types.router));
        debug_assert!(!lsa::is_link_local_scope(types.network));
        for area_id in area_ids {
            let links = by_area.get(&area_id).cloned().unwrap_or_default();
            let lsdb = self.lsdb_for(area_id).await;
            let mut lsdb = lsdb.lock().await;
            let done = done.areas.entry(area_id).or_default();

            let router_links = router_lsa_links(local_router_id, &links);
            done.insert(install_self_originated(
                &mut lsdb,
                local_router_id,
                types.router,
                local_router_id,
                LsaBody::Router(RouterLsaBody {
                    flags,
                    options: OWN_OPTIONS,
                    links: router_links,
                }),
            ));

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
                done.insert(install_self_originated(
                    &mut lsdb,
                    local_router_id,
                    types.network,
                    lsa::interface_id_key(cfg.interface_id),
                    LsaBody::Network(NetworkLsaBody {
                        options: OWN_OPTIONS,
                        attached_routers: attached,
                    }),
                ));
            }
        }
    }

    /// One Link-LSA per live link, unconditionally (RFC 5340 §7.3) —
    /// advertises this router's own link-local address and configured
    /// prefix on that link. Link-local scoped, so it goes into that link's
    /// own store, never the area's (`LinkManager.link_local_lsdbs`).
    async fn originate_link_lsas(&self, local_router_id: Ipv4Addr, done: &mut Originated) {
        let snapshot: Vec<LinkConfig> = self
            .links
            .lock()
            .await
            .values()
            .map(|e| e.config.clone())
            .collect();
        let types = self.lsa_types();
        debug_assert!(lsa::is_link_local_scope(types.link));
        for cfg in snapshot {
            let lsdb = self.link_local_lsdb_for(&cfg.attach_point).await;
            let mut lsdb = lsdb.lock().await;
            let key = install_self_originated(
                &mut lsdb,
                local_router_id,
                types.link,
                lsa::interface_id_key(cfg.interface_id),
                LsaBody::Link(LinkLsaBody {
                    priority: cfg.priority,
                    options: OWN_OPTIONS,
                    link_local_address: cfg.link_local_address,
                    prefixes: vec![LinkPrefixEntry {
                        options: 0,
                        prefix: cfg.prefix,
                    }],
                }),
            );
            done.links.entry(cfg.attach_point).or_default().insert(key);
        }
    }

    /// This router's own Intra-Area-Prefix-LSA (referencing its own
    /// Router-LSA: every point-to-point link's own prefix, plus every
    /// loopback prefix) and, per broadcast link where a Network-LSA was
    /// actually originated, a second Intra-Area-Prefix-LSA referencing that
    /// Network-LSA with the link's own transit prefix.
    async fn originate_intra_area_prefix_lsas(
        &self,
        local_router_id: Ipv4Addr,
        done: &mut Originated,
    ) {
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
        debug_assert!(!lsa::is_link_local_scope(types.intra_area_prefix));
        for area_id in area_ids {
            let links = by_area.get(&area_id).cloned().unwrap_or_default();
            let lsdb = self.lsdb_for(area_id).await;
            let mut lsdb = lsdb.lock().await;
            let done = done.areas.entry(area_id).or_default();

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
                    // RFC 5340 §A.4.1.1: a /128 loopback is a host address.
                    options: if prefix.prefix_len() == 128 {
                        lsa::PREFIX_OPT_LA
                    } else {
                        0
                    },
                    metric: *cost,
                    prefix: *prefix,
                });
            }
            if !router_prefixes.is_empty() {
                done.insert(install_self_originated(
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
                ));
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
                done.insert(install_self_originated(
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
                ));
            }
        }
    }

    /// RFC 5340 §4.4.3.3/§4.4.3.4 (port of `ospf::link::
    /// originate_summary_lsas`): as an ABR, into every attached area, one
    /// Inter-Area-Prefix-LSA per prefix intra-area in another attached area
    /// and one Inter-Area-Router-LSA per ASBR reachable in one. Never an
    /// inter-area or external route (`spf::intra_area_routes`). Run after the
    /// intra-area passes, so this tick's own prefixes are summarized.
    /// `ponytail:` no area ranges, no backbone check (ABR = 2+ areas), no
    /// up/down-bit loop prevention — `ospf/CLAUDE.md`'s ABR ceilings.
    async fn originate_inter_area_lsas(&self, local_router_id: Ipv4Addr, done: &mut Originated) {
        let attached = self.attached_areas().await;
        if attached.len() < 2 {
            return;
        }
        let areas: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .filter(|(id, _)| attached.contains(id))
            .map(|(id, lsdb)| (*id, Arc::clone(lsdb)))
            .collect();
        let mut views = Vec::new();
        for (area_id, lsdb) in &areas {
            let lsas = lsdb.lock().await.all();
            views.push((*area_id, spf::intra_area_routes(local_router_id, &lsas)));
        }
        let types = self.lsa_types();
        for (dest, lsdb) in &areas {
            // Cheapest over every other area; 24-bit metrics (LSInfinity
            // excluded).
            let mut prefixes: HashMap<Ipv6Net, u32> = HashMap::new();
            let mut asbrs: HashMap<Ipv4Addr, (u32, u32)> = HashMap::new();
            for (_, view) in views.iter().filter(|(src, _)| src != dest) {
                for &(prefix, cost) in &view.prefixes {
                    let e = prefixes.entry(prefix).or_insert(cost);
                    *e = (*e).min(cost);
                }
                for &(asbr, cost, options) in &view.asbrs {
                    let e = asbrs.entry(asbr).or_insert((cost, options));
                    if cost < e.0 {
                        *e = (cost, options);
                    }
                }
            }
            let mut desired = Vec::new();
            for (prefix, metric) in prefixes.into_iter().filter(|(_, m)| *m < 0x00FF_FFFF) {
                let lsid = self.lsid(lsa::LSA_TYPE_INTER_AREA_PREFIX, prefix).await;
                desired.push((
                    types.inter_area_prefix,
                    lsid,
                    LsaBody::InterAreaPrefix(InterAreaPrefixLsaBody {
                        metric,
                        prefix_options: 0,
                        prefix,
                    }),
                ));
            }
            for (asbr, (metric, options)) in
                asbrs.into_iter().filter(|(_, (m, _))| *m < 0x00FF_FFFF)
            {
                desired.push((
                    types.inter_area_router,
                    asbr,
                    LsaBody::InterAreaRouter(InterAreaRouterLsaBody {
                        options,
                        metric,
                        destination_router_id: asbr,
                    }),
                ));
            }
            let mut lsdb = lsdb.lock().await;
            let done = done.areas.entry(*dest).or_default();
            for (lsa_type, lsid, body) in desired {
                done.insert(install_self_originated(
                    &mut lsdb,
                    local_router_id,
                    lsa_type,
                    lsid,
                    body,
                ));
            }
        }
    }

    /// RFC 5340 §4.4.3.5: one AS-External-LSA per redistributed IPv6 prefix,
    /// into the AS-scope store — Type-1, metric `spf::EXTERNAL_METRIC`, no
    /// forwarding address or tag.
    async fn originate_as_external_lsas(&self, local_router_id: Ipv4Addr, done: &mut Originated) {
        let prefixes: Vec<Ipv6Net> = self
            .redistribute_filtered
            .lock()
            .await
            .iter()
            .copied()
            .collect();
        let types = self.lsa_types();
        for prefix in prefixes {
            let lsid = self.lsid(lsa::LSA_TYPE_AS_EXTERNAL, prefix).await;
            done.as_scope.insert(install_self_originated(
                &mut *self.as_lsdb.lock().await,
                local_router_id,
                types.as_external,
                lsid,
                LsaBody::AsExternal(AsExternalLsaBody {
                    type2: false,
                    metric: spf::EXTERNAL_METRIC,
                    prefix_options: 0,
                    prefix,
                    forwarding_address: None,
                    route_tag: None,
                    referenced_ls_type: 0,
                    referenced_link_state_id: None,
                }),
            ));
        }
    }

    /// Applies one `Ospfv3Request::RedistributeRoutes` update (pushed by the
    /// owning `nos-ribd`) to the raw set and re-filters it. `OSPFv3` routes
    /// IPv6 only: `nos-ribd` sends no IPv4 prefix, and one is ignored.
    pub async fn apply_redistribute_update(&self, update: RedistributeUpdate) {
        {
            let mut raw = self.redistribute_raw.lock().await;
            let v6 = |prefix: IpNet| match prefix {
                IpNet::V6(p) => Some(p.trunc()),
                IpNet::V4(_) => None,
            };
            match update {
                RedistributeUpdate::Full(routes) => {
                    *raw = routes.into_iter().filter_map(|r| v6(r.prefix)).collect();
                }
                RedistributeUpdate::Add(route) => raw.extend(v6(route.prefix)),
                RedistributeUpdate::Remove(prefix) => {
                    if let Some(p) = v6(prefix) {
                        raw.remove(&p);
                    }
                }
            }
        }
        self.refilter_redistributed().await;
    }

    /// Sets the redistribute policy (every `reconcile.rs` resync) and
    /// re-filters, so a policy edit takes effect without waiting for a route
    /// change — `ospf::link::LinkManager::set_redistribute_policy`.
    pub async fn set_redistribute_policy(&self, policy: Arc<CompiledPolicy>) {
        *self.redistribute_policy.lock().await = policy;
        self.refilter_redistributed().await;
    }

    async fn refilter_redistributed(&self) {
        let policy = Arc::clone(&*self.redistribute_policy.lock().await);
        let raw = self.redistribute_raw.lock().await.clone();
        *self.redistribute_filtered.lock().await = raw
            .into_iter()
            .filter(|&p| passes_redistribute_policy(p, &policy))
            .collect();
    }

    /// One origination tick: every pass, then RFC 2328 §13.4/§14.1 — every
    /// live LSA of ours this tick did not originate is prematurely aged
    /// (`withdraw_undesired`), like `ospf::link`'s pass. Stateless, so it
    /// covers a lost DR role or last `Full` neighbor (Network-LSA and its
    /// IAP), an emptied router IAP, a left area, a moved Link-LSA key, the
    /// other RFC 8362 flavor, and a previous incarnation's LSAs learned
    /// over DBD alike. Only the stores of links this tick saw are swept: a
    /// removed link's store has no neighbor to flood to.
    async fn originate_all(&self, local_router_id: Ipv4Addr) {
        let mut done = Originated::default();
        self.originate_router_lsas(local_router_id, &mut done).await;
        self.originate_link_lsas(local_router_id, &mut done).await;
        self.originate_intra_area_prefix_lsas(local_router_id, &mut done)
            .await;
        self.originate_inter_area_lsas(local_router_id, &mut done)
            .await;
        self.originate_as_external_lsas(local_router_id, &mut done)
            .await;
        let areas: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(area_id, lsdb)| (*area_id, Arc::clone(lsdb)))
            .collect();
        let none = HashSet::new();
        for (area_id, lsdb) in areas {
            let desired = done.areas.get(&area_id).unwrap_or(&none);
            withdraw_undesired(&mut *lsdb.lock().await, local_router_id, desired);
        }
        for (attach_point, desired) in &done.links {
            let lsdb = self.link_local_lsdb_for(attach_point).await;
            withdraw_undesired(&mut *lsdb.lock().await, local_router_id, desired);
        }
        withdraw_undesired(
            &mut *self.as_lsdb.lock().await,
            local_router_id,
            &done.as_scope,
        );
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
            let link_local_lsdb = self.link_local_lsdb_for(&cfg.attach_point).await;
            let (status_tx, status_rx) = watch::channel(LinkStatus::new(cfg.network_type));
            let (grace_tx, grace_rx) = mpsc::unbounded_channel();
            let task = tokio::spawn(run(
                (self.opener)(&cfg),
                cfg.clone(),
                local_router_id,
                lsdb,
                link_local_lsdb,
                Arc::clone(&self.as_lsdb),
                status_tx,
                self.dbd_max_headers,
                grace_rx,
            ));
            links.insert(
                key,
                LinkEntry {
                    config: cfg,
                    task,
                    status: status_rx,
                    grace_tx,
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

    /// Every installed LSA's header: the area stores' rows carry
    /// `link: None`, each link's own store's rows carry its attach point, and
    /// the AS-scope store's rows carry area `0.0.0.0` and `link: None`.
    pub async fn database_summaries(&self) -> Vec<Ospfv3LsaSummary> {
        let mut result = Vec::new();
        let areas: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(area_id, lsdb)| (*area_id, Arc::clone(lsdb)))
            .collect();
        for (area_id, lsdb) in areas {
            for header in lsdb.lock().await.headers() {
                result.push(to_lsa_summary(area_id, None, &header));
            }
        }
        let links: Vec<(String, Ipv4Addr)> = self
            .links
            .lock()
            .await
            .values()
            .map(|e| (e.config.attach_point.clone(), e.config.area_id))
            .collect();
        for (attach_point, area_id) in links {
            let lsdb = self.link_local_lsdb_for(&attach_point).await;
            for header in lsdb.lock().await.headers() {
                result.push(to_lsa_summary(area_id, Some(attach_point.clone()), &header));
            }
        }
        for header in self.as_lsdb.lock().await.headers() {
            result.push(to_lsa_summary(Ipv4Addr::UNSPECIFIED, None, &header));
        }
        result
    }

    /// Runs `crate::spf::compute` against every area's current LSDB and
    /// merges the results — mirrors `ospf::link::LinkManager::compute_routes`.
    /// Each area's input is its area store plus every same-area link's own
    /// Link-LSAs: RFC 5340 §4.8.1 derives next hops from them, so SPF is the
    /// one reader that legitimately spans every link's link-local store.
    pub async fn compute_routes(&self) -> Vec<spf::RouteEntry> {
        let Some(router_id) = *self.router_id.lock().await else {
            return Vec::new();
        };
        let areas: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(area_id, lsdb)| (*area_id, Arc::clone(lsdb)))
            .collect();
        let mut merged: HashMap<Ipv6Net, spf::RouteEntry> = HashMap::new();
        for (area_id, lsdb) in areas {
            let mut lsas = lsdb.lock().await.all();
            for (_, link_lsdb) in self.link_local_lsdbs_in(area_id).await {
                lsas.extend(link_lsdb.lock().await.all());
            }
            // AS-External-LSAs are routed from every area (through an
            // intra-area ASBR or an Inter-Area-Router-LSA there); the cheapest
            // wins in the merge below.
            lsas.extend(self.as_lsdb.lock().await.all());
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

    /// RFC 5187: when graceful restart is configured, has every link send
    /// a Grace-LSA to its `Full` neighbors (twice) and waits for them to go
    /// out. Called on a planned restart only, before `shutdown`.
    pub async fn announce_graceful_restart(&self) {
        let grace_period = self.grace_period.load(Ordering::Relaxed);
        if grace_period == 0 {
            return;
        }
        info!(
            grace_period,
            "ospfv3 graceful restart: announcing grace period before shutdown"
        );
        let senders: Vec<mpsc::UnboundedSender<u32>> = self
            .links
            .lock()
            .await
            .values()
            .map(|e| e.grace_tx.clone())
            .collect();
        for _ in 0..2 {
            for tx in &senders {
                let _ = tx.send(u32::from(grace_period));
            }
            tokio::time::sleep(GRACE_SEND_WINDOW).await;
        }
    }

    pub async fn shutdown(&self) {
        for (_, entry) in self.links.lock().await.drain() {
            entry.task.abort();
        }
    }
}

fn to_lsa_summary(area_id: Ipv4Addr, link: Option<String>, header: &LsaHeader) -> Ospfv3LsaSummary {
    Ospfv3LsaSummary {
        area_id,
        lsa_type: header.lsa_type,
        link_state_id: header.link_state_id,
        advertising_router: header.advertising_router,
        sequence_number: header.sequence_number,
        age: header.age,
        checksum: header.checksum,
        link,
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
            NetworkType::PointToPoint | NetworkType::PointToMultipoint => {
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
/// header field (v3's header carries none — see `lsa::LsaHeader`). Returns
/// the key, originated whether or not anything had to be reinstalled.
fn install_self_originated(
    lsdb: &mut Lsdb,
    local_router_id: Ipv4Addr,
    lsa_type: u16,
    link_state_id: Ipv4Addr,
    body: LsaBody,
) -> LsaKey {
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
        Some(e) if e.body == body && !needs_refresh => return key,
        Some(e) => e.header.sequence_number.wrapping_add(1),
        None => lsa::INITIAL_SEQUENCE_NUMBER,
    };
    let mut lsa = Lsa {
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
    };
    lsa::fill_checksum(&mut lsa);
    lsdb.install(lsa);
    info!(
        lsa_type, link_state_id = %link_state_id, advertising_router = %local_router_id,
        refreshed = needs_refresh,
        "ospfv3 lsa originated"
    );
    key
}

/// RFC 2328 §14.1 premature aging — `ospf::link::withdraw_self_originated`:
/// flushes one of this router's own LSAs by reinstalling it at `MAX_AGE`
/// with its sequence number unchanged, so `lsa::is_newer`'s `MaxAge`
/// tie-break makes every neighbor accept it; `Lsdb`'s `MaxAge` hold keeps it
/// long enough for the periodic resend to carry it out. No-op (`false`) if
/// `key` isn't held or is already at `MAX_AGE`.
fn withdraw_self_originated(lsdb: &mut Lsdb, key: &LsaKey) -> bool {
    let Some(existing) = lsdb.get(key) else {
        return false;
    };
    if existing.header.age >= lsa::MAX_AGE {
        return false;
    }
    let mut flushed = (*existing).clone();
    flushed.header.age = lsa::MAX_AGE;
    lsdb.install(flushed);
    info!(
        lsa_type = key.lsa_type, link_state_id = %key.link_state_id,
        advertising_router = %key.advertising_router,
        "ospfv3 lsa prematurely aged"
    );
    true
}

/// Withdraws every live LSA of `local_router_id`'s in `lsdb` of an
/// `OWNED_TYPES` type that is not in `desired`.
fn withdraw_undesired(lsdb: &mut Lsdb, local_router_id: Ipv4Addr, desired: &HashSet<LsaKey>) {
    let stale: Vec<LsaKey> = lsdb
        .headers()
        .into_iter()
        .filter(|h| {
            h.advertising_router == local_router_id
                && h.age < lsa::MAX_AGE
                && OWNED_TYPES.contains(&h.lsa_type)
        })
        .map(|h| h.key())
        .filter(|k| !desired.contains(k))
        .collect();
    for key in stale {
        withdraw_self_originated(lsdb, &key);
    }
}

/// Evaluates `prefix` against a redistribute `policy` —
/// `ospf::link::passes_redistribute_policy` with an IPv6 prefix: a
/// redistribute policy has no `this.bgp.*` to read, so those are empty.
fn passes_redistribute_policy(prefix: Ipv6Net, policy: &CompiledPolicy) -> bool {
    let input = nos_rpl::Input {
        prefix: IpNet::V6(prefix),
        bgp: nos_rpl::BgpInput {
            origin: nos_rpl::Origin::Igp,
            as_path: &[],
            local_pref: 0,
            med: None,
            next_hop: None,
            learned_via_ibgp: false,
            router_id: None,
            originator_id: None,
            cluster_list: &[],
            peer: None,
            peer_as: 0,
            communities: &[],
            extended_communities: &[],
            large_communities: &[],
            validation_state: nos_rpl::ValidationState::default(),
        },
    };
    matches!(
        nos_rpl::vm::run(policy, &input),
        nos_rpl::Verdict::Accept { .. }
    )
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
            mtu_ignore: false,
            auth: None,
            instance_id: 0,
        }
    }

    #[test]
    fn no_changes_produces_no_diff() {
        let mut current = HashMap::new();
        current.insert("eth0.0".to_string(), link("eth0.0", 10));
        let desired = current.clone();
        let (to_stop, to_spawn) = diff_links(&current, &desired);
        assert_eq!(to_stop, [] as [String; 0]);
        assert_eq!(to_spawn, []);
    }

    #[test]
    fn new_link_is_spawned() {
        let current = HashMap::new();
        let mut desired = HashMap::new();
        desired.insert("eth0.0".to_string(), link("eth0.0", 10));
        let (to_stop, to_spawn) = diff_links(&current, &desired);
        assert_eq!(to_stop, [] as [String; 0]);
        assert_eq!(to_spawn, vec![link("eth0.0", 10)]);
    }

    #[test]
    fn removed_link_is_stopped() {
        let mut current = HashMap::new();
        current.insert("eth0.0".to_string(), link("eth0.0", 10));
        let desired = HashMap::new();
        let (to_stop, to_spawn) = diff_links(&current, &desired);
        assert_eq!(to_stop, vec!["eth0.0".to_string()]);
        assert_eq!(to_spawn, []);
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
    fn at_bit_follows_auth_config() {
        let mut cfg = link("eth0.0", 10);
        assert_eq!(link_options(&cfg) & lsa::OPTION_AT, 0);
        cfg.auth = Some(packet::TrailerAuth {
            keys: vec![(1, packet::CryptoAlgorithm::HmacSha256, b"k".to_vec())],
            current_key_id: 1,
        });
        assert_ne!(link_options(&cfg) & lsa::OPTION_AT, 0);
        assert_ne!(link_options(&cfg) & lsa::OPTION_V6, 0);
    }

    #[test]
    fn crypto_sequence_must_strictly_increase_per_neighbor() {
        let neighbor = Ipv4Addr::new(9, 9, 9, 10);
        let mut status = LinkStatus::new(NetworkType::PointToPoint);
        status.neighbors.insert(
            neighbor,
            neighbor_info(NeighborState::Init, "fe80::2".parse().unwrap(), 4),
        );
        let (tx, _rx) = watch::channel(status);
        let mut hello = packet::HelloPacket {
            router_id: neighbor,
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_id: 4,
            router_priority: 1,
            options: 0,
            hello_interval: 10,
            dead_interval: 40,
            designated_router: Ipv4Addr::UNSPECIFIED,
            backup_designated_router: Ipv4Addr::UNSPECIFIED,
            neighbors: Vec::new(),
        };
        let pkt = OspfPacket::Hello(hello.clone());
        assert!(accept_crypto_sequence(&tx, None, &pkt));
        assert!(accept_crypto_sequence(&tx, Some(5), &pkt));
        assert!(!accept_crypto_sequence(&tx, Some(5), &pkt));
        assert!(!accept_crypto_sequence(&tx, Some(4), &pkt));
        assert!(accept_crypto_sequence(&tx, Some(6), &pkt));
        assert_eq!(tx.borrow().neighbors[&neighbor].last_crypto_seq, Some(6));
        // An unknown neighbor is never dropped (no state yet).
        hello.router_id = Ipv4Addr::new(9, 9, 9, 11);
        assert!(accept_crypto_sequence(
            &tx,
            Some(1),
            &OspfPacket::Hello(hello)
        ));
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
            last_heard: Instant::now(),
            address,
            adjacency: None,
            last_crypto_seq: None,
            grace_deadline: None,
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
        assert_eq!(
            router_lsa_links(Ipv4Addr::new(1, 1, 1, 1), &[(cfg, status)]),
            []
        );
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

    /// #157: only our own live LSAs of an owned type outside `desired` are
    /// flushed, with the sequence number unchanged.
    #[test]
    fn withdraw_undesired_flushes_only_undesired_own_lsas() {
        let me = Ipv4Addr::new(1, 1, 1, 1);
        let other = Ipv4Addr::new(2, 2, 2, 2);
        let lsa = |lsa_type, advertising_router, age| Lsa {
            header: LsaHeader {
                age,
                lsa_type,
                link_state_id: Ipv4Addr::new(0, 0, 0, 7),
                advertising_router,
                sequence_number: 5,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Grace(GraceLsaBody {
                grace_period: 1,
                restart_reason: lsa::RESTART_REASON_SOFTWARE,
            }),
        };
        let mut lsdb = Lsdb::new();
        let kept = lsa(lsa::LSA_TYPE_ROUTER, me, 1);
        let mut untouched = vec![
            kept.clone(),
            lsa(lsa::LSA_TYPE_NETWORK, other, 1),
            lsa(lsa::LSA_TYPE_GRACE, me, 1),
            lsa(lsa::LSA_TYPE_E_LINK, me, lsa::MAX_AGE),
        ];
        let flushed: Vec<Lsa> = OWNED_TYPES[1..]
            .iter()
            .filter(|t| **t != lsa::LSA_TYPE_E_LINK)
            .map(|t| lsa(*t, me, 1))
            .collect();
        for l in untouched.iter().chain(&flushed) {
            lsdb.install(l.clone());
        }
        withdraw_undesired(&mut lsdb, me, &HashSet::from([kept.header.key()]));
        for l in untouched.drain(..) {
            assert_eq!(lsdb.get(&l.header.key()).unwrap().header, l.header);
        }
        for l in flushed {
            let h = lsdb.get(&l.header.key()).unwrap().header;
            assert_eq!(
                (h.age, h.sequence_number),
                (lsa::MAX_AGE, 5),
                "{:#x}",
                h.lsa_type
            );
        }
    }

    fn age_of(lsdb: &Lsdb, lsa_type: u16, link_state_id: Ipv4Addr, me: Ipv4Addr) -> Option<u16> {
        lsdb.get(&LsaKey {
            lsa_type,
            link_state_id,
            advertising_router: me,
        })
        .map(|l| l.header.age)
    }

    /// #157: a router IAP with no p2p link or loopback left, and a Link-LSA
    /// whose interface id moved, are both flushed.
    #[tokio::test]
    async fn emptied_router_iap_and_moved_link_lsa_are_flushed() {
        let manager = LinkManager::new(1, None);
        let me = Ipv4Addr::new(1, 1, 1, 1);
        let p2p = link("eth0.0", 10);
        let mut bd = link("broadcast-domain:bd1", 10);
        bd.interface_id = 7;
        bd.network_type = NetworkType::Broadcast;
        manager
            .reconcile(vec![p2p.clone(), bd.clone()], HashMap::new(), me)
            .await;
        manager.originate_all(me).await;
        let area = manager.lsdb_for(p2p.area_id).await;
        let iap = || async {
            age_of(
                &*area.lock().await,
                lsa::LSA_TYPE_INTRA_AREA_PREFIX,
                Ipv4Addr::UNSPECIFIED,
                me,
            )
        };
        assert!(iap().await.unwrap() < lsa::MAX_AGE);

        let mut moved = bd.clone();
        moved.interface_id = 8;
        manager
            .reconcile(vec![moved.clone()], HashMap::new(), me)
            .await;
        manager.originate_all(me).await;
        assert_eq!(iap().await, Some(lsa::MAX_AGE));
        let store = manager.link_local_lsdb_for(&bd.attach_point).await;
        let store = store.lock().await;
        let link_age = |id| age_of(&store, lsa::LSA_TYPE_LINK, lsa::interface_id_key(id), me);
        assert_eq!(link_age(7), Some(lsa::MAX_AGE));
        assert!(link_age(8).unwrap() < lsa::MAX_AGE);
        let router = age_of(&*area.lock().await, lsa::LSA_TYPE_ROUTER, me, me);
        assert!(router.unwrap() < lsa::MAX_AGE);
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
        manager.originate_all(router_id).await;

        let lsdb = manager.link_local_lsdb_for(&cfg.attach_point).await;
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

    /// RFC 5340 §4.5.1 (#46): two links in one area each hold only their
    /// own Link-LSA, and the area store holds neither — so neither link's
    /// DBD summary/flood can ever offer the other's.
    #[tokio::test]
    async fn link_lsas_are_kept_per_link_not_per_area() {
        let manager = LinkManager::new(1, None);
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let eth = link("eth0.0", 10);
        let mut bd = link("broadcast-domain:bd1", 10);
        bd.interface_id = 7;
        bd.network_type = NetworkType::Broadcast;
        manager
            .reconcile(vec![eth.clone(), bd.clone()], HashMap::new(), router_id)
            .await;
        manager.originate_all(router_id).await;

        let key = |cfg: &LinkConfig| LsaKey {
            lsa_type: lsa::LSA_TYPE_LINK,
            link_state_id: lsa::interface_id_key(cfg.interface_id),
            advertising_router: router_id,
        };
        let eth_store = manager.link_local_lsdb_for(&eth.attach_point).await;
        let bd_store = manager.link_local_lsdb_for(&bd.attach_point).await;
        assert!(eth_store.lock().await.get(&key(&eth)).is_some());
        assert!(eth_store.lock().await.get(&key(&bd)).is_none());
        assert!(bd_store.lock().await.get(&key(&bd)).is_some());
        assert!(bd_store.lock().await.get(&key(&eth)).is_none());
        let area = manager.lsdb_for(eth.area_id).await;
        assert!(area.lock().await.get(&key(&eth)).is_none());
        assert!(area.lock().await.get(&key(&bd)).is_none());

        // `show ospfv3 database` still lists both, each tagged with its link.
        let mut rows: Vec<(u16, Option<String>)> = manager
            .database_summaries()
            .await
            .into_iter()
            .filter(|r| r.lsa_type == lsa::LSA_TYPE_LINK)
            .map(|r| (r.lsa_type, r.link))
            .collect();
        rows.sort();
        assert_eq!(
            rows,
            vec![
                (lsa::LSA_TYPE_LINK, Some(bd.attach_point.clone())),
                (lsa::LSA_TYPE_LINK, Some(eth.attach_point.clone())),
            ]
        );
    }

    /// SPF still sees a neighbor's Link-LSA once it lives in the link's own
    /// store: without it the next hop can't be derived and the route is
    /// silently dropped (`spf::no_link_lsa_for_neighbor_is_treated_as_unreachable`).
    #[tokio::test]
    async fn compute_routes_merges_link_local_stores_into_spf_input() {
        let manager = LinkManager::new(1, None);
        let root = Ipv4Addr::new(1, 1, 1, 1);
        let w = Ipv4Addr::new(2, 2, 2, 2);
        let cfg = link("eth0.0", 10);
        manager
            .reconcile(vec![cfg.clone()], HashMap::new(), root)
            .await;
        let header = |lsa_type, link_state_id, advertising_router| LsaHeader {
            age: 0,
            lsa_type,
            link_state_id,
            advertising_router,
            sequence_number: 1,
            checksum: 0,
            length: 0,
        };
        let p2p = |neighbor, own_if, neighbor_if| RouterLsaLink {
            link_type: LINK_TYPE_POINT_TO_POINT,
            metric: 1,
            interface_id: own_if,
            neighbor_interface_id: neighbor_if,
            neighbor_router_id: neighbor,
        };
        let router_lsa = |id, links| Lsa {
            header: header(lsa::LSA_TYPE_ROUTER, id, id),
            body: LsaBody::Router(RouterLsaBody {
                flags: 0,
                options: 0,
                links,
            }),
        };
        let stub: Ipv6Net = "2001:db8:1::/64".parse().unwrap();
        let w_link_local: Ipv6Addr = "fe80::2".parse().unwrap();
        {
            let area = manager.lsdb_for(cfg.area_id).await;
            let mut area = area.lock().await;
            area.install(router_lsa(root, vec![p2p(w, cfg.interface_id, 2)]));
            area.install(router_lsa(w, vec![p2p(root, 2, cfg.interface_id)]));
            area.install(Lsa {
                header: header(lsa::LSA_TYPE_INTRA_AREA_PREFIX, Ipv4Addr::UNSPECIFIED, w),
                body: LsaBody::IntraAreaPrefix(IntraAreaPrefixLsaBody {
                    referenced_ls_type: lsa::LSA_TYPE_ROUTER,
                    referenced_link_state_id: w,
                    referenced_advertising_router: w,
                    prefixes: vec![IntraAreaPrefixEntry {
                        options: 0,
                        metric: 1,
                        prefix: stub,
                    }],
                }),
            });
        }
        assert_eq!(manager.compute_routes().await, []);

        // w's Link-LSA arrives on eth0.0 — into that link's own store.
        manager
            .link_local_lsdb_for(&cfg.attach_point)
            .await
            .lock()
            .await
            .install(Lsa {
                header: header(lsa::LSA_TYPE_LINK, lsa::interface_id_key(2), w),
                body: LsaBody::Link(LinkLsaBody {
                    priority: 1,
                    options: 0,
                    link_local_address: w_link_local,
                    prefixes: Vec::new(),
                }),
            });
        let routes = manager.compute_routes().await;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, stub);
        assert_eq!(routes[0].next_hop, w_link_local);
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
        manager.originate_all(router_id).await;

        let types: HashSet<u16> = manager
            .database_summaries()
            .await
            .iter()
            .map(|h| h.lsa_type)
            .collect();
        assert!(types.contains(&lsa::LSA_TYPE_E_ROUTER));
        assert!(types.contains(&lsa::LSA_TYPE_E_LINK));
        assert!(!types.contains(&lsa::LSA_TYPE_ROUTER));
        assert!(!types.contains(&lsa::LSA_TYPE_LINK));
        assert!(!types.contains(&lsa::LSA_TYPE_INTRA_AREA_PREFIX));
    }

    /// RFC 8362 mode switch (#149): the old flavor is prematurely aged with
    /// its sequence number unchanged while the new one is live, and
    /// switching back re-originates it at seq+1.
    #[tokio::test]
    async fn extended_mode_toggle_flushes_the_other_flavor() {
        const LEGACY: [u16; 3] = [
            lsa::LSA_TYPE_ROUTER,
            lsa::LSA_TYPE_LINK,
            lsa::LSA_TYPE_INTRA_AREA_PREFIX,
        ];
        const EXTENDED: [u16; 3] = [
            lsa::LSA_TYPE_E_ROUTER,
            lsa::LSA_TYPE_E_LINK,
            lsa::LSA_TYPE_E_INTRA_AREA_PREFIX,
        ];
        let manager = LinkManager::new(1, None);
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        manager
            .reconcile(vec![link("eth0.0", 10)], HashMap::new(), router_id)
            .await;
        let tick = || manager.originate_all(router_id);
        let by_type = || async {
            manager
                .database_summaries()
                .await
                .into_iter()
                .map(|s| (s.lsa_type, (s.sequence_number, s.age)))
                .collect::<HashMap<u16, (i32, u16)>>()
        };

        tick().await;
        let legacy = by_type().await;
        for t in LEGACY {
            assert!(legacy[&t].1 < lsa::MAX_AGE, "{t:#x} live");
        }

        manager.set_extended_lsa(true);
        tick().await;
        let db = by_type().await;
        for t in LEGACY {
            assert_eq!(db[&t], (legacy[&t].0, lsa::MAX_AGE), "{t:#x} flushed");
        }
        for t in EXTENDED {
            assert!(db[&t].1 < lsa::MAX_AGE, "{t:#x} live");
        }

        manager.set_extended_lsa(false);
        tick().await;
        let db = by_type().await;
        for t in LEGACY {
            assert_eq!(db[&t].0, legacy[&t].0 + 1, "{t:#x} re-originated");
            assert!(db[&t].1 < lsa::MAX_AGE, "{t:#x} live");
        }
        for t in EXTENDED {
            assert_eq!(db[&t].1, lsa::MAX_AGE, "{t:#x} flushed");
        }
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
        manager.originate_all(router_id).await;

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
        // RFC 5340 A.4.1.1: a /128 loopback is flagged LA, a shorter one is not.
        assert_eq!(body.prefixes[0].options, lsa::PREFIX_OPT_LA);
    }

    #[tokio::test]
    async fn loopback_subnet_prefix_has_no_la_bit() {
        let manager = LinkManager::new(1, None);
        let area = Ipv4Addr::UNSPECIFIED;
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let net: Ipv6Net = "2001:db8:9::/64".parse().unwrap();
        manager
            .reconcile(
                Vec::new(),
                HashMap::from([(area, vec![(net, 5)])]),
                router_id,
            )
            .await;
        manager.originate_all(router_id).await;
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
        assert_eq!(body.prefixes[0].options, 0);
    }

    fn grace_status(grace: Option<Instant>) -> StatusHandle {
        let mut status = LinkStatus::new(NetworkType::PointToPoint);
        let mut info = neighbor_info(NeighborState::Full, "fe80::2".parse().unwrap(), 4);
        info.adjacency = Some(start_negotiation(&link("eth0.0", 10), Ipv4Addr::new(1, 1, 1, 1)).0);
        info.grace_deadline = grace;
        status.neighbors.insert(Ipv4Addr::new(9, 9, 9, 10), info);
        watch::channel(status).0
    }

    fn state_of(status: &StatusHandle) -> NeighborState {
        status.borrow().neighbors[&Ipv4Addr::new(9, 9, 9, 10)].state
    }

    fn restarted_hello() -> packet::HelloPacket {
        packet::HelloPacket {
            router_id: Ipv4Addr::new(9, 9, 9, 10),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_id: 4,
            router_priority: 1,
            options: 0,
            hello_interval: 10,
            dead_interval: 40,
            designated_router: Ipv4Addr::UNSPECIFIED,
            backup_designated_router: Ipv4Addr::UNSPECIFIED,
            neighbors: Vec::new(),
        }
    }

    #[tokio::test]
    async fn grace_holds_full_through_a_hello_that_does_not_list_us() {
        let cfg = link("eth0.0", 10);
        let me = Ipv4Addr::new(1, 1, 1, 1);
        let mut deadline = Instant::now();
        for (grace, expected) in [
            (
                Some(Instant::now() + std::time::Duration::from_secs(60)),
                NeighborState::Full,
            ),
            (None, NeighborState::Init),
        ] {
            let status = grace_status(grace);
            handle_hello(
                &cfg,
                me,
                &status,
                "fe80::2".parse().unwrap(),
                &restarted_hello(),
                &mut deadline,
                false,
            );
            assert_eq!(state_of(&status), expected);
        }
    }

    #[tokio::test]
    async fn grace_suppresses_the_inactivity_timer_until_it_expires() {
        let cfg = link("eth0.0", 10);
        let status = grace_status(Some(Instant::now() + std::time::Duration::from_secs(60)));
        apply_dead_timer(&cfg, &status);
        assert_eq!(state_of(&status), NeighborState::Full);

        status.send_modify(|s| {
            for n in s.neighbors.values_mut() {
                n.grace_deadline = Some(Instant::now());
            }
        });
        expire_grace(&cfg, &status);
        assert!(!in_grace(&status, Ipv4Addr::new(9, 9, 9, 10)));
        apply_dead_timer(&cfg, &status);
        assert_eq!(state_of(&status), NeighborState::Down);
    }

    #[tokio::test]
    async fn grace_lsa_starts_helping_only_a_full_neighbor() {
        let cfg = link("eth0.0", 10);
        let header = LsaHeader {
            age: 1,
            lsa_type: lsa::LSA_TYPE_GRACE,
            link_state_id: lsa::interface_id_key(4),
            advertising_router: Ipv4Addr::new(9, 9, 9, 10),
            sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
            checksum: 0,
            length: 0,
        };
        let body = GraceLsaBody {
            grace_period: 60,
            restart_reason: lsa::RESTART_REASON_SOFTWARE,
        };
        let status = grace_status(None);
        on_grace_lsa(&cfg, &status, &header, body);
        assert!(in_grace(&status, header.advertising_router));

        let flushed = LsaHeader {
            age: lsa::MAX_AGE,
            ..header
        };
        on_grace_lsa(&cfg, &status, &flushed, body);
        assert!(!in_grace(&status, header.advertising_router));

        status.send_modify(|s| {
            for n in s.neighbors.values_mut() {
                n.state = NeighborState::ExStart;
            }
        });
        on_grace_lsa(&cfg, &status, &header, body);
        assert!(!in_grace(&status, header.advertising_router));
    }

    /// An in-memory multi-access wire, mirroring `ospf::link`'s: every port
    /// on the same prefix hears every multicast, a unicast reaches only its
    /// destination, and an authenticated port signs like `OspfSocket` (#131).
    pub mod wire {
        use std::collections::HashSet;
        use std::net::Ipv6Addr;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::{Arc, Mutex};

        use ipnet::Ipv6Net;
        use tokio::sync::mpsc;

        use super::super::{LinkConfig, LinkSocket, Opener};
        use crate::packet::TrailerAuth;

        type Tx = mpsc::UnboundedSender<(Ipv6Addr, Vec<u8>)>;

        #[derive(Default)]
        pub struct Wire {
            ports: Mutex<Vec<(Ipv6Net, Ipv6Addr, Tx)>>,
            /// Addresses whose sends are silently dropped (a dead neighbor).
            pub cut: Mutex<HashSet<Ipv6Addr>>,
            /// Addresses whose Hellos (type byte 1) alone are dropped.
            pub drop_hellos: Mutex<HashSet<Ipv6Addr>>,
        }

        impl Wire {
            pub fn opener(self: &Arc<Self>) -> Opener {
                let wire = Arc::clone(self);
                Arc::new(move |cfg: &LinkConfig| {
                    let net = cfg.prefix.trunc();
                    let (tx, rx) = mpsc::unbounded_channel();
                    let mut ports = wire.ports.lock().unwrap();
                    ports.retain(|(_, a, _)| *a != cfg.link_local_address);
                    ports.push((net, cfg.link_local_address, tx));
                    Ok(LinkSocket::Mem(Port {
                        wire: Arc::clone(&wire),
                        net,
                        addr: cfg.link_local_address,
                        auth: cfg.auth.clone(),
                        instance_id: cfg.instance_id,
                        seq: AtomicU64::new(1),
                        rx: tokio::sync::Mutex::new(rx),
                    }))
                })
            }

            /// Delivers `payload` to `to` as if `from` had sent it (a forged,
            /// unauthenticated packet).
            pub fn inject(&self, from: Ipv6Addr, to: Ipv6Addr, payload: &[u8]) {
                for (_, addr, tx) in self.ports.lock().unwrap().iter() {
                    if *addr == to {
                        let _ = tx.send((from, payload.to_vec()));
                    }
                }
            }
        }

        pub struct Port {
            wire: Arc<Wire>,
            net: Ipv6Net,
            addr: Ipv6Addr,
            auth: Option<TrailerAuth>,
            instance_id: u8,
            seq: AtomicU64,
            rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<(Ipv6Addr, Vec<u8>)>>,
        }

        impl Port {
            pub fn send(&self, dest: Option<Ipv6Addr>, payload: &[u8]) {
                if self.wire.cut.lock().unwrap().contains(&self.addr)
                    || (payload[1] == 1
                        && self.wire.drop_hellos.lock().unwrap().contains(&self.addr))
                {
                    return;
                }
                let mut packet = payload.to_vec();
                crate::packet::set_instance_id(&mut packet, self.instance_id);
                if let Some(auth) = &self.auth {
                    auth.sign(
                        &mut packet,
                        self.seq.fetch_add(1, Ordering::Relaxed),
                        self.addr,
                    );
                }
                for (net, addr, tx) in self.wire.ports.lock().unwrap().iter() {
                    if *net == self.net && *addr != self.addr && dest.is_none_or(|d| d == *addr) {
                        let _ = tx.send((self.addr, packet.clone()));
                    }
                }
            }

            pub async fn recv(&self) -> std::io::Result<(Ipv6Addr, Vec<u8>)> {
                match self.rx.lock().await.recv().await {
                    Some(m) => Ok(m),
                    None => std::future::pending().await,
                }
            }
        }
    }

    fn router(wire: &Arc<wire::Wire>) -> Arc<LinkManager> {
        LinkManager::with_opener(1, None, wire.opener())
    }

    fn wired_link(n: u8, network_type: NetworkType) -> LinkConfig {
        LinkConfig {
            attach_point: format!("link-{n}"),
            link_local_address: format!("fe80::{n}").parse().unwrap(),
            prefix: format!("2001:db8::{n}/64").parse().unwrap(),
            interface_id: u32::from(n),
            network_type,
            ..link("unused", 10)
        }
    }

    fn id(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(n, n, n, n)
    }

    fn loopback(n: u8) -> HashMap<Ipv4Addr, Vec<(Ipv6Net, u16)>> {
        HashMap::from([(
            Ipv4Addr::UNSPECIFIED,
            vec![(format!("2001:db8:ff::{n}/128").parse().unwrap(), 1)],
        )])
    }

    async fn settle(secs: u64) {
        tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
    }

    async fn pair(
        wire: &Arc<wire::Wire>,
        auth_a: Option<packet::TrailerAuth>,
        auth_b: Option<packet::TrailerAuth>,
    ) -> (Arc<LinkManager>, Arc<LinkManager>) {
        let (a, b) = (router(wire), router(wire));
        let mut la = wired_link(1, NetworkType::PointToPoint);
        la.auth = auth_a;
        let mut lb = wired_link(2, NetworkType::PointToPoint);
        lb.auth = auth_b;
        a.reconcile(vec![la], HashMap::new(), id(1)).await;
        b.reconcile(vec![lb], loopback(2), id(2)).await;
        settle(60).await;
        (a, b)
    }

    /// RFC 4222 §2 recommendation 2 — mirrors `ospf::link`'s test.
    async fn adjacency_survives_lost_hellos(network_type: NetworkType) {
        let wire = Arc::new(wire::Wire::default());
        let (a, b) = (router(&wire), router(&wire));
        a.reconcile(vec![wired_link(1, network_type)], loopback(1), id(1))
            .await;
        b.reconcile(vec![wired_link(2, network_type)], loopback(2), id(2))
            .await;
        settle(60).await;
        assert_eq!(
            b.neighbor_summaries().await[0].state,
            OspfNeighborState::Full
        );

        let a_addr: Ipv6Addr = "fe80::1".parse().unwrap();
        wire.drop_hellos.lock().unwrap().insert(a_addr);
        settle(3 * 40).await;
        let n = b.neighbor_summaries().await;
        assert_eq!(n[0].state, OspfNeighborState::Full, "{n:?}");

        wire.cut.lock().unwrap().insert(a_addr);
        settle(40 + 2).await;
        assert_eq!(
            b.neighbor_summaries().await[0].state,
            OspfNeighborState::Down
        );
    }

    #[tokio::test(start_paused = true)]
    async fn point_to_point_adjacency_survives_lost_hellos() {
        adjacency_survives_lost_hellos(NetworkType::PointToPoint).await;
    }

    #[tokio::test(start_paused = true)]
    async fn broadcast_adjacency_survives_lost_hellos() {
        adjacency_survives_lost_hellos(NetworkType::Broadcast).await;
    }

    #[test]
    fn note_alive_only_refreshes_an_adjacency() {
        let cfg = link("eth0.0", 10);
        let peer = Ipv4Addr::new(9, 9, 9, 9);
        for (state, refreshed) in [
            (NeighborState::Down, false),
            (NeighborState::Init, false),
            (NeighborState::TwoWay, false),
            (NeighborState::ExStart, true),
            (NeighborState::Full, true),
        ] {
            let mut info = neighbor_info(state, "fe80::2".parse().unwrap(), 2);
            let past = Instant::now()
                .checked_sub(std::time::Duration::from_secs(30))
                .unwrap();
            info.last_heard = past;
            info.last_hello_received = past;
            let mut s = LinkStatus::new(NetworkType::PointToPoint);
            s.neighbors.insert(peer, info);
            let (status, _rx) = watch::channel(s);
            let mut deadline = past;
            note_alive(&cfg, &status, peer, &mut deadline);
            let n = status.borrow().neighbors[&peer].clone();
            assert_eq!(n.last_heard > past, refreshed, "{state:?}");
            assert_eq!(deadline > past, refreshed, "{state:?}");
            assert_eq!(n.last_hello_received, past, "{state:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn point_to_point_pair_reaches_full_and_routes_to_the_far_loopback() {
        let wire = Arc::new(wire::Wire::default());
        let (a, b) = pair(&wire, None, None).await;
        let n = a.neighbor_summaries().await;
        assert_eq!(n[0].state, OspfNeighborState::Full, "{n:?}");
        let routes = a.compute_routes().await;
        let r = routes
            .iter()
            .find(|r| r.prefix == "2001:db8:ff::2/128".parse::<Ipv6Net>().unwrap())
            .unwrap_or_else(|| panic!("{routes:?}"));
        assert_eq!(r.next_hop, "fe80::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(r.interface_id, 1);
        // Link-LSAs are held per link, tagged with it.
        assert!(a
            .database_summaries()
            .await
            .iter()
            .any(|l| l.link.as_deref() == Some("link-1")));

        // RFC 8362 Full mode: both switch to the extended LSA set.
        a.set_extended_lsa(true);
        b.set_extended_lsa(true);
        settle(30).await;
        assert!(a
            .database_summaries()
            .await
            .iter()
            .any(|l| l.lsa_type == lsa::LSA_TYPE_E_ROUTER && l.advertising_router == id(2)));

        // Graceful restart: B helps A through a restart without dropping it.
        a.set_graceful_restart(Some(120));
        a.announce_graceful_restart().await;
        wire.cut.lock().unwrap().insert("fe80::1".parse().unwrap());
        settle(60).await;
        assert_eq!(
            b.neighbor_summaries().await[0].state,
            OspfNeighborState::Full,
            "helper keeps the restarting neighbor"
        );
        // Past the grace period it is finally declared dead.
        settle(120).await;
        assert_eq!(
            b.neighbor_summaries().await[0].state,
            OspfNeighborState::Down
        );
        a.shutdown().await;
    }

    /// The Router-LSA `of` holds for `router` in `area`, if any.
    async fn router_flags(of: &LinkManager, area: Ipv4Addr, router: Ipv4Addr) -> Option<u8> {
        let lsdb = of.lsdb_for(area).await;
        let lsdb = lsdb.lock().await;
        lsdb.all().iter().find_map(|l| match &l.body {
            LsaBody::Router(r)
                if l.header.advertising_router == router && l.header.age < lsa::MAX_AGE =>
            {
                Some(r.flags)
            }
            _ => None,
        })
    }

    /// a (area 0) — b (areas 0 and 1, an ABR) — c (area 1, an ASBR): c's
    /// loopback reaches a as an inter-area route, its redistributed prefix as
    /// an external one through b's Inter-Area-Router-LSA (the AS-External-LSA
    /// crossing areas from the AS-scope store), B/E follow the roles, and
    /// both routes go once c stops advertising them.
    #[tokio::test(start_paused = true)]
    async fn abr_and_asbr_reach_across_areas() {
        let wire = Arc::new(wire::Wire::default());
        let (a, b, c) = (router(&wire), router(&wire), router(&wire));
        let (area0, area1) = (Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(0, 0, 0, 1));
        let seg = |n: u8, net: u8, area_id: Ipv4Addr| LinkConfig {
            area_id,
            prefix: format!("2001:db8:{net}::{n}/64").parse().unwrap(),
            ..wired_link(n, NetworkType::PointToPoint)
        };
        let loopback: Ipv6Net = "2001:db8:ff::3/128".parse().unwrap();
        let external: Ipv6Net = "2001:db8:e::/48".parse().unwrap();
        a.reconcile(vec![seg(1, 1, area0)], HashMap::new(), id(1))
            .await;
        b.reconcile(
            vec![seg(2, 1, area0), seg(3, 2, area1)],
            HashMap::new(),
            id(2),
        )
        .await;
        let c_link = vec![seg(4, 2, area1)];
        c.reconcile(
            c_link.clone(),
            HashMap::from([(area1, vec![(loopback, 1)])]),
            id(3),
        )
        .await;
        c.apply_redistribute_update(RedistributeUpdate::Full(vec![
            nos_proto::RedistributedRoute {
                prefix: IpNet::V6(external),
                gateway: "2001:db8:2::99".parse().unwrap(),
            },
            // OSPFv3 routes IPv6 only.
            nos_proto::RedistributedRoute {
                prefix: "192.0.2.0/24".parse().unwrap(),
                gateway: "10.0.0.1".parse().unwrap(),
            },
        ]))
        .await;
        settle(60).await;

        let routes = a.compute_routes().await;
        let route = |p: Ipv6Net| routes.iter().find(|r| r.prefix == p);
        let inter = route(loopback).unwrap_or_else(|| panic!("{routes:?}"));
        assert_eq!(inter.next_hop, "fe80::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(inter.metric, 3);
        let ext = route(external).unwrap_or_else(|| panic!("{routes:?}"));
        assert_eq!(ext.metric, 2 + spf::EXTERNAL_METRIC);
        assert_eq!(
            routes.len(),
            3,
            "the b–c link, the loopback, the external: {routes:?}"
        );
        assert_eq!(
            router_flags(&a, area0, id(2)).await,
            Some(lsa::ROUTER_FLAG_B)
        );
        assert_eq!(
            router_flags(&b, area1, id(3)).await,
            Some(lsa::ROUTER_FLAG_E)
        );
        assert_eq!(router_flags(&a, area0, id(1)).await, Some(0));
        let db = a.database_summaries().await;
        assert!(db.iter().any(|l| l.lsa_type == lsa::LSA_TYPE_AS_EXTERNAL
            && l.advertising_router == id(3)
            && l.area_id == area0
            && l.link.is_none()));
        assert!(db
            .iter()
            .any(|l| l.lsa_type == lsa::LSA_TYPE_INTER_AREA_ROUTER
                && l.advertising_router == id(2)
                && l.link_state_id == id(3)));

        c.reconcile(c_link, HashMap::new(), id(3)).await;
        c.apply_redistribute_update(RedistributeUpdate::Full(Vec::new()))
            .await;
        settle(30).await;
        let routes = a.compute_routes().await;
        assert!(
            routes
                .iter()
                .all(|r| r.prefix != loopback && r.prefix != external),
            "{routes:?}"
        );
        assert_eq!(router_flags(&b, area1, id(3)).await, Some(0));
    }

    fn trailer(key: &[u8]) -> packet::TrailerAuth {
        packet::TrailerAuth {
            keys: vec![(300, packet::CryptoAlgorithm::HmacSha256, key.to_vec())],
            current_key_id: 300,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn matching_trailer_auth_reaches_full_and_a_mismatch_never_does() {
        let wire = Arc::new(wire::Wire::default());
        let (a, _b) = pair(&wire, Some(trailer(b"k")), Some(trailer(b"k"))).await;
        assert_eq!(
            a.neighbor_summaries().await[0].state,
            OspfNeighborState::Full
        );
        let wire = Arc::new(wire::Wire::default());
        let (a, _b) = pair(&wire, Some(trailer(b"k")), Some(trailer(b"other"))).await;
        assert_eq!(
            a.neighbor_summaries().await[0].state,
            OspfNeighborState::Down
        );
        let wire = Arc::new(wire::Wire::default());
        let (a, _b) = pair(&wire, Some(trailer(b"k")), None).await;
        assert_eq!(
            a.neighbor_summaries().await[0].state,
            OspfNeighborState::Down
        );
    }

    #[tokio::test(start_paused = true)]
    async fn instance_id_must_match_to_reach_full() {
        for (ia, ib, want) in [
            (5, 5, OspfNeighborState::Full),
            (1, 0, OspfNeighborState::Down),
        ] {
            let wire = Arc::new(wire::Wire::default());
            let (a, b) = (router(&wire), router(&wire));
            let mut la = wired_link(1, NetworkType::PointToPoint);
            la.instance_id = ia;
            let mut lb = wired_link(2, NetworkType::PointToPoint);
            lb.instance_id = ib;
            a.reconcile(vec![la], HashMap::new(), id(1)).await;
            b.reconcile(vec![lb], loopback(2), id(2)).await;
            settle(60).await;
            assert_eq!(a.neighbor_summaries().await[0].state, want, "{ia}/{ib}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn broadcast_segment_elects_dr_and_bdr() {
        let wire = Arc::new(wire::Wire::default());
        let segment: Vec<_> = (1..=4).map(|_| router(&wire)).collect();
        for (i, r) in segment.iter().enumerate() {
            let n = u8::try_from(i + 1).unwrap();
            r.reconcile(
                vec![wired_link(n, NetworkType::Broadcast)],
                loopback(n),
                id(n),
            )
            .await;
        }
        settle(120).await;
        let one = segment[0].neighbor_summaries().await;
        assert_eq!(one.len(), 3, "{one:?}");
        for n in &one {
            assert_eq!((n.dr, n.bdr), (Some(id(4)), Some(id(3))));
            let want = if n.neighbor_router_id == Some(id(2)) {
                OspfNeighborState::TwoWay
            } else {
                OspfNeighborState::Full
            };
            assert_eq!(n.state, want, "{n:?}");
        }
        let routes = segment[0].compute_routes().await;
        assert!(
            routes
                .iter()
                .any(|r| r.prefix == "2001:db8:ff::4/128".parse::<Ipv6Net>().unwrap()),
            "{routes:?}"
        );
        // A DR-other dying is swept off the segment.
        wire.cut.lock().unwrap().insert("fe80::2".parse().unwrap());
        settle(60).await;
        let one = segment[0].neighbor_summaries().await;
        assert!(one
            .iter()
            .any(|n| n.neighbor_router_id == Some(id(2)) && n.state == OspfNeighborState::Down));
    }

    /// #157: a DR that loses its only `Full` neighbor flushes its Network-LSA
    /// and the IAP referencing it, and keeps its Router-LSA.
    #[tokio::test(start_paused = true)]
    async fn dr_losing_its_last_full_neighbor_flushes_its_network_lsa() {
        let wire = Arc::new(wire::Wire::default());
        let (a, b) = (router(&wire), router(&wire));
        a.reconcile(
            vec![wired_link(1, NetworkType::Broadcast)],
            loopback(1),
            id(1),
        )
        .await;
        let lb = wired_link(2, NetworkType::Broadcast);
        b.reconcile(vec![lb.clone()], loopback(2), id(2)).await;
        settle(120).await;
        let network_key = lsa::interface_id_key(lb.interface_id);
        let ages = || async {
            let area = b.lsdb_for(Ipv4Addr::UNSPECIFIED).await;
            let area = area.lock().await;
            [
                age_of(&area, lsa::LSA_TYPE_NETWORK, network_key, id(2)),
                age_of(&area, lsa::LSA_TYPE_INTRA_AREA_PREFIX, network_key, id(2)),
                age_of(&area, lsa::LSA_TYPE_ROUTER, id(2), id(2)),
            ]
        };
        for age in ages().await {
            assert!(age.unwrap() < lsa::MAX_AGE, "live while Full");
        }

        wire.cut.lock().unwrap().insert("fe80::1".parse().unwrap());
        settle(43).await;
        let [network, iap, router] = ages().await;
        // Flushed, and maybe already evicted after its MaxAge hold.
        assert!(network.is_none_or(|a| a == lsa::MAX_AGE), "{network:?}");
        assert!(iap.is_none_or(|a| a == lsa::MAX_AGE), "{iap:?}");
        assert!(router.unwrap() < lsa::MAX_AGE);
    }

    #[tokio::test(start_paused = true)]
    async fn tiny_dbd_budget_still_reaches_full() {
        let wire = Arc::new(wire::Wire::default());
        let mk = || LinkManager::with_opener(1, Some(1), wire.opener());
        let (a, b) = (mk(), mk());
        let many = |n: u8| {
            HashMap::from([(
                Ipv4Addr::UNSPECIFIED,
                (0..3)
                    .map(|p| (format!("2001:db8:{n}:{p}::/64").parse().unwrap(), 1))
                    .collect(),
            )])
        };
        a.reconcile(vec![], many(1), id(1)).await;
        b.reconcile(vec![], many(2), id(2)).await;
        settle(3).await;
        a.reconcile(
            vec![wired_link(1, NetworkType::PointToPoint)],
            many(1),
            id(1),
        )
        .await;
        b.reconcile(
            vec![wired_link(2, NetworkType::PointToPoint)],
            many(2),
            id(2),
        )
        .await;
        settle(90).await;
        assert_eq!(
            a.neighbor_summaries().await[0].state,
            OspfNeighborState::Full
        );
        let routes = a.compute_routes().await;
        assert!(
            routes
                .iter()
                .any(|r| r.prefix == "2001:db8:2:2::/64".parse::<Ipv6Net>().unwrap()),
            "{routes:?}"
        );
    }

    /// #146: A hits `SeqNumberMismatch` on its own side (a `BadLSReq`) while
    /// Hellos keep both sides listed; B, still `Full`, must answer A's Init
    /// DBD with `SeqNumberMismatch` too, or A sits in `ExStart` for good.
    /// Renegotiation on the in-memory wire is near-instant, so only the end
    /// state is checked.
    #[tokio::test(start_paused = true)]
    async fn one_sided_seq_number_mismatch_renegotiates_back_to_full() {
        let wire = Arc::new(wire::Wire::default());
        let (a, b) = pair(&wire, None, None).await;
        assert_eq!(
            a.neighbor_summaries().await[0].state,
            OspfNeighborState::Full
        );

        // A forged LSR "from B" for an LSA A doesn't hold: BadLSReq on A only.
        let lsr = LsrPacket {
            router_id: id(2),
            area_id: Ipv4Addr::UNSPECIFIED,
            requests: vec![LsaKey {
                lsa_type: lsa::LSA_TYPE_ROUTER,
                link_state_id: id(77),
                advertising_router: id(77),
            }],
        };
        wire.inject(
            "fe80::2".parse().unwrap(),
            "fe80::1".parse().unwrap(),
            &packet::encode_lsr(&lsr),
        );
        settle(30).await;
        for (m, side) in [(&a, "a"), (&b, "b")] {
            assert_eq!(
                m.neighbor_summaries().await[0].state,
                OspfNeighborState::Full,
                "{side}"
            );
        }
    }

    #[test]
    fn only_the_slave_keeps_its_final_dbd_once_full() {
        let cfg = link("eth0.0", 10);
        let neighbor_id = Ipv4Addr::new(9, 9, 9, 10);
        for is_master in [false, true] {
            let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
            status.send_modify(|s| {
                let mut info =
                    neighbor_info(NeighborState::Exchange, "fe80::2".parse().unwrap(), 2);
                info.adjacency = Some(AdjacencyData::default());
                s.neighbors.insert(neighbor_id, info);
            });
            let (_, reply) = start_negotiation(&cfg, Ipv4Addr::new(9, 9, 9, 9));
            let adj = AdjacencyData {
                is_master,
                ..Default::default()
            };
            finish_neighbor_event(
                &cfg,
                Ipv4Addr::new(9, 9, 9, 9),
                &status,
                neighbor_id,
                NeighborState::Exchange,
                adj,
                vec![
                    exchange::Action::SendDbd(reply.clone()),
                    exchange::Action::NeighborEvent(neighbor::Event::ExchangeDone {
                        more_to_load: false,
                    }),
                ],
            );
            let s = status.borrow();
            let info = &s.neighbors[&neighbor_id];
            assert_eq!(info.state, NeighborState::Full);
            let kept = info.adjacency.as_ref().unwrap().last_dbd_sent.clone();
            assert_eq!(kept, (!is_master).then_some(reply), "is_master={is_master}");
        }
    }

    #[tokio::test]
    async fn retransmit_pending_resends_a_dbd_only_while_negotiating() {
        let wire = Arc::new(wire::Wire::default());
        let cfg = wired_link(1, NetworkType::PointToPoint);
        let socket = (wire.opener())(&cfg).unwrap();
        let LinkSocket::Mem(peer) =
            (wire.opener())(&wired_link(2, NetworkType::PointToPoint)).unwrap()
        else {
            unreachable!()
        };
        let neighbor_id = Ipv4Addr::new(9, 9, 9, 10);
        let (_, dbd) = start_negotiation(&cfg, Ipv4Addr::new(9, 9, 9, 9));
        for (state, sent) in [
            (NeighborState::Full, false),
            (NeighborState::Loading, false),
            (NeighborState::Exchange, true),
        ] {
            let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
            status.send_modify(|s| {
                let mut info = neighbor_info(state, "fe80::2".parse().unwrap(), 2);
                info.adjacency = Some(AdjacencyData {
                    last_dbd_sent: Some(dbd.clone()),
                    ..Default::default()
                });
                s.neighbors.insert(neighbor_id, info);
            });
            retransmit_pending(&socket, &cfg, Ipv4Addr::new(9, 9, 9, 9), &status);
            let got = tokio::time::timeout(std::time::Duration::from_millis(20), peer.recv()).await;
            assert_eq!(got.is_ok(), sent, "{state:?}");
        }
    }
}
