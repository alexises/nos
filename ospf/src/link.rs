//! One OSPF link's driver, plus `LinkManager` — the OSPF analogue of
//! `bgp::session::SessionManager`, much smaller since there's no shared
//! listener and no collision resolution: each link just owns its
//! own raw socket, neighbor FSM(s), RFC 2328 §9.4 DR/BDR election on a
//! `Broadcast` link, and — once a neighbor is eligible — RFC 2328
//! §10.6-10.8's DBD/LSR/LSU/LSAck adjacency-forming exchange
//! (`crate::exchange`).

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipnet::{IpNet, Ipv4Net};
use nos_proto::{
    LinkInterfaceState, LsaSummary, NeighborSummary, NetworkType, OspfNeighborState,
    RedistributeUpdate,
};
use nos_rpl::CompiledPolicy;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::election::{self, Candidate};
use crate::exchange::{self, AdjacencyData};
use crate::lsa::{
    self, AsExternalLsaBody, GraceLsaBody, Lsa, LsaBody, LsaHeader, LsaKey, NetworkLsaBody,
    RouterLink, RouterLsaBody, SummaryLsaBody, LINK_TYPE_POINT_TO_POINT, LINK_TYPE_STUB_NETWORK,
    LINK_TYPE_TRANSIT_NETWORK,
};
use crate::lsdb::Lsdb;
use crate::neighbor::{self, NeighborState};
use crate::packet::{self, DbdPacket, LsAckPacket, LsrPacket, LsuPacket, OspfPacket, PacketError};
use crate::socket::OspfSocket;
use crate::spf;

/// What a link task sends and receives on: the real raw socket, or (in
/// tests) an in-memory wire — the one seam that lets `run` and
/// `LinkManager` be exercised without `CAP_NET_RAW` (#131).
pub enum LinkSocket {
    Os(OspfSocket),
    #[cfg(test)]
    Mem(tests::wire::Port),
}

impl LinkSocket {
    fn send_multicast(&self, payload: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Os(s) => s.send_multicast(payload),
            #[cfg(test)]
            Self::Mem(p) => {
                p.send(None, payload);
                Ok(())
            }
        }
    }

    fn send_unicast(&self, dest: Ipv4Addr, payload: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Os(s) => s.send_unicast(dest, payload),
            #[cfg(test)]
            Self::Mem(p) => {
                p.send(Some(dest), payload);
                Ok(())
            }
        }
    }

    async fn recv_packet(&self) -> std::io::Result<(Ipv4Addr, Vec<u8>)> {
        match self {
            Self::Os(s) => s.recv_packet().await,
            #[cfg(test)]
            Self::Mem(p) => p.recv().await,
        }
    }
}

/// Opens one link's socket — the real one in production, see `LinkSocket`.
pub type Opener = Arc<dyn Fn(&LinkConfig) -> std::io::Result<LinkSocket> + Send + Sync>;

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

/// RFC 2328 §14: how often `LinkManager` ages every installed LSA by one
/// (simulated) second. Real wall-clock cadence — `age_multiplier` scales how
/// many simulated seconds each tick advances, not this tick's own rate, so
/// `age` stays a wire-correct simulated-seconds value regardless of what a
/// test harness sets the multiplier to.
const AGE_TICK_INTERVAL: Duration = Duration::from_secs(1);

/// How long `LinkManager::shutdown` keeps the link tasks alive after
/// prematurely aging every self-originated LSA (RFC 2328 §14.1), so each
/// link's own `RXMT_INTERVAL` resend actually carries the `MaxAge` copies out
/// before the process exits: one resend period plus a second of margin.
/// With `max-metric router-lsa on-shutdown`'s hold (at most
/// `MAX_METRIC_SHUTDOWN_HOLD_MAX`) it must fit `nos-watchdogd`'s 10s
/// SIGINT-to-SIGKILL budget (root `CLAUDE.md`, "Process supervision") with a
/// second to spare for the exit — see the assertion below. The flush is kicked
/// out at once (`LinkCommand::FloodNow`), so the window buys one `RXMT_INTERVAL`
/// retransmission on top.
const PREMATURE_AGE_FLOOD_WINDOW: Duration = Duration::from_secs(6);

/// The longest RFC 6987 on-shutdown hold `OspfInstance.max_metric_on_shutdown`
/// accepts (its garde range is 1-3).
const MAX_METRIC_SHUTDOWN_HOLD_MAX: Duration = Duration::from_secs(3);
const _: () = assert!(
    MAX_METRIC_SHUTDOWN_HOLD_MAX.as_secs() + PREMATURE_AGE_FLOOD_WINDOW.as_secs() <= 9,
    "on-shutdown hold + flush window must fit nos-watchdogd's 10s kill budget"
);

/// How long `LinkManager::announce_graceful_restart` waits after each
/// Grace-LSA send before the next one (two sends) and before exiting —
/// enough for the link tasks to put them on the wire. ponytail: sent twice,
/// not retransmitted until acked; a lossless local link is the norm here.
const GRACE_SEND_WINDOW: Duration = Duration::from_millis(500);

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
    /// This link's effective MTU (`OspfProfile.mtu` if set, else the real
    /// resolved interface MTU, else 1500 — see `reconcile::
    /// resolve_effective_mtu`) — advertised in the wire's
    /// `DbdPacket.interface_mtu` field and used to size real RFC 2328 §10.8
    /// DBD pagination (`exchange::pop_chunk`'s `max_headers` budget) when
    /// `LinkManager.dbd_max_headers` has no explicit test override. See
    /// `ospf/CLAUDE.md`'s "Exchange" section.
    pub mtu: u16,
    /// `mtu-ignore`: skip the RFC 2328 §10.6 DBD Interface MTU check.
    pub mtu_ignore: bool,
    /// RFC 2328 Appendix D auth, resolved once per reconcile from
    /// `OspfProfile.auth` (see `reconcile.rs`). Fits this struct's existing
    /// "any field change restarts the link" rule with no special-casing —
    /// an auth/key change simply restarts the link task, which re-sends
    /// Hello with the new auth; a peer still on the old auth rejects it
    /// until it's updated too, which is exactly the desired match/mismatch
    /// behavior.
    pub auth: LinkAuthConfig,
    /// The link's area is a stub (RFC 2328 §3.6) or an NSSA: Hellos and DBDs
    /// go without the E-bit and a peer's must match, and AS-scope LSAs stay
    /// out of the exchange. Changing an area's type restarts its links.
    pub stub: bool,
    /// The link's area is an NSSA (RFC 3101, `stub` is set too): Hellos carry
    /// the N-bit and a peer's must match, and only here are Type-7s exchanged.
    pub nssa: bool,
}

/// One link's resolved OSPF authentication — `OspfProfile.auth` translated
/// into `packet.rs`'s own key-material shape.
#[derive(Debug, Clone, PartialEq)]
pub enum LinkAuthConfig {
    None,
    Simple {
        password: Vec<u8>,
    },
    /// `current_key_id` names which of `keys` actively signs outgoing
    /// packets — guaranteed present by `OspfProfile.auth`'s own commit-time
    /// validation (`valid_auth`: exactly one `is_current` key) by the time
    /// this is built in `reconcile.rs`.
    Crypto {
        keys: Vec<(u16, packet::CryptoAlgorithm, Vec<u8>)>,
        current_key_id: u16,
        /// RFC 7474 (`OspfProfile.extended_sequence_numbers`): `AuType` 3
        /// with a persisted-boot-count 64-bit sequence number.
        extended: bool,
    },
}

impl LinkAuthConfig {
    fn is_extended(&self) -> bool {
        matches!(self, LinkAuthConfig::Crypto { extended: true, .. })
    }

    /// `source` is the received packet's IP source address (RFC 7474 binds
    /// the digest to it).
    fn as_policy(&self, source: Ipv4Addr) -> packet::AuthPolicy<'_> {
        match self {
            LinkAuthConfig::None => packet::AuthPolicy::None,
            LinkAuthConfig::Simple { password } => packet::AuthPolicy::Simple { password },
            LinkAuthConfig::Crypto { keys, extended, .. } => packet::AuthPolicy::Crypto {
                keys,
                extended: extended.then_some(source),
            },
        }
    }

    /// Builds what to sign an outgoing packet with, given this send's own
    /// crypto sequence number (only meaningful for `Crypto`).
    fn as_outgoing(&self, sequence: u64, local_addr: Ipv4Addr) -> packet::OutgoingAuth<'_> {
        match self {
            LinkAuthConfig::None => packet::OutgoingAuth::None,
            LinkAuthConfig::Simple { password } => packet::OutgoingAuth::Simple { password },
            LinkAuthConfig::Crypto {
                keys,
                current_key_id,
                extended,
            } => {
                let (key_id, algorithm, key) = keys
                    .iter()
                    .find(|(id, _, _)| id == current_key_id)
                    .expect("valid_auth guarantees current_key_id names a real key");
                packet::OutgoingAuth::Crypto {
                    key_id: *key_id,
                    algorithm: *algorithm,
                    key,
                    sequence,
                    extended: extended.then_some(local_addr),
                }
            }
        }
    }
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
    /// Reported only (`last_hello_secs`): when the last valid Hello arrived.
    pub last_hello_received: Instant,
    /// RFC 4222 §2 recommendation 2: when this neighbor was last heard from —
    /// a valid Hello, or any authenticated packet over its adjacency
    /// (`note_alive`). The inactivity timer runs off this, not the Hello time.
    pub last_heard: Instant,
    /// The neighbor's own IP address, as seen on the last Hello it sent —
    /// DBD/LSR/LSU/LSAck reply unicast to this, unlike Hello's multicast.
    pub address: Ipv4Addr,
    /// `Some` from `ExStart` onward; cleared whenever the neighbor drops
    /// back to `Init`/`Down` (RFC 2328: losing 2-way tears down any
    /// adjacency, forcing a fresh negotiation on reconnect).
    pub adjacency: Option<AdjacencyData>,
    /// RFC 2328 D.4.3's anti-replay crypto sequence number, last accepted
    /// from this neighbor — `None` until its first Crypto-authenticated
    /// packet. Only ever populated/checked when `LinkConfig.auth` is
    /// `Crypto`; see `run()`'s receive loop.
    ///
    /// Keyed by packet type under RFC 7474 (its replay rule is per type), by
    /// a single `0` slot under RFC 2328's classic `AuType` 2.
    pub last_crypto_seq: HashMap<u8, u64>,
    /// RFC 3623 helper mode: `Some` while this neighbor is restarting under
    /// a Grace-LSA it sent. Until then its adjacency is held through missing
    /// Hellos and Hellos that don't list us (see `in_grace`).
    pub grace_deadline: Option<Instant>,
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
        interface_mtu: cfg.mtu,
        options: exchange::dbd_options(cfg.stub),
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
        // Populated once real content starts flowing, in `exchange::
        // on_dbd_in_exstart` (this negotiation attempt itself always
        // carries no summary data, per RFC 2328 §10.6).
        summary_remaining: std::collections::VecDeque::new(),
        pending_acks: Vec::new(),
        pending_acks_since: None,
        opaque_capable: false, // learnt from the neighbor's DBD
        stub: cfg.stub,
        nssa: cfg.nssa,
    };
    (adj, dbd)
}

/// Runs until aborted (link removed from config, or process shutdown — see
/// `LinkManager`). Owns the raw socket, the Hello send ticker, and every
/// timer this link's network type needs.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    socket: std::io::Result<LinkSocket>,
    cfg: LinkConfig,
    local_router_id: Ipv4Addr,
    lsdb: Arc<Mutex<Lsdb>>,
    link_local_lsdb: Arc<Mutex<Lsdb>>,
    status: StatusHandle,
    dbd_max_headers: Option<usize>,
    boot_count: u32,
    mut commands: mpsc::UnboundedReceiver<LinkCommand>,
) {
    let socket = match socket {
        Ok(s) => s,
        Err(e) => {
            warn!(link = %cfg.attach_point, error = %e, "failed to open ospf raw socket");
            return;
        }
    };
    // `Some(n)` (from `--dbd-max-headers`, test/debug only) keeps that exact
    // override; `None` (the real default) derives the pagination budget
    // from this link's own effective MTU — see `exchange`'s module doc.
    let dbd_max_headers =
        dbd_max_headers.unwrap_or_else(|| exchange::mtu_based_max_headers(cfg.mtu));

    let mut hello_ticker =
        tokio::time::interval(Duration::from_secs(u64::from(cfg.hello_interval)));
    hello_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let is_broadcast = cfg.network_type == NetworkType::Broadcast;
    // RFC 2328 §9.5: several neighbors, no election — each one's dead timer is
    // tracked by the 1s sweep below instead of the single p2p deadline.
    let is_p2mp = cfg.network_type == NetworkType::PointToMultipoint;
    let mut p2p_dead_deadline = Instant::now() + Duration::from_secs(u64::from(cfg.dead_interval));
    // ponytail: a 1s periodic sweep, not N precise per-neighbor timers — a
    // broadcast link's dead-interval tracking only needs to be accurate to
    // about a second, and this avoids a dynamically-sized set of timers
    // growing/shrinking as neighbors come and go. Upgrade to a
    // `last_heard`-keyed min-heap (or per-neighbor spawned
    // timers) if sub-second precision on broadcast links ever matters.
    let mut dead_sweep = tokio::time::interval(Duration::from_secs(1));
    dead_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let wait_deadline = Instant::now() + Duration::from_secs(u64::from(cfg.dead_interval));
    let mut waiting = is_broadcast;

    let mut rxmt_sweep = tokio::time::interval(RXMT_INTERVAL);
    rxmt_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // RFC 2328 D.4.3's outgoing crypto sequence number — only meaningful
    // when `cfg.auth` is `Crypto`, but harmless to always seed/advance.
    // Floored at wall-clock seconds so it never regresses across a link
    // restart (a fresh `next_crypto_seq` call always floors back up to
    // "now" if the in-memory counter would otherwise be behind).
    let mut next_seq = initial_crypto_seq(&cfg.auth, boot_count);

    info!(link = %cfg.attach_point, vrf = %cfg.vrf, "ospf link driver started");
    if cfg.auth.is_extended() {
        info!(link = %cfg.attach_point, boot_count, "ospf link using rfc 7474 extended sequence numbers");
    }
    if is_broadcast {
        info!(link = %cfg.attach_point, "ospf interface reached waiting");
    }

    loop {
        // RFC 4222 §2 recommendation 1: Hello sends and receives first, the
        // 5s `rxmt_sweep` (LSDB lock + full-LSDB encode) last, and a queued
        // packet ahead of a dead timer that became ready in the same poll.
        // ponytail: `biased;` only orders arms that are already ready — it
        // doesn't preempt a running arm (a handler waiting on the LSDB lock
        // still delays the next Hello), and a sustained inbound queue runs the
        // timer arms late (harmless for the dead timers, see `note_alive`).
        // Upgrade to a separate Hello task or a high/low receive queue if a
        // large LSDB ever shows Hello starvation.
        tokio::select! {
            biased;
            _ = hello_ticker.tick() => {
                send_hello(&socket, &cfg, local_router_id, &status, &mut next_seq);
            }
            result = socket.recv_packet() => {
                match result {
                    Ok((source, data)) => {
                        let policy = cfg.auth.as_policy(source);
                        match packet::decode(&data, &policy) {
                            Ok(pkt) if !accept_crypto_sequence(&cfg, &status, &data, &pkt) => {
                                warn!(
                                    link = %cfg.attach_point, neighbor = %packet::router_id(&pkt),
                                    "ospf packet crypto sequence number not increasing, dropping"
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
                                        advance_adjacencies(&socket, &cfg, local_router_id, &status, &mut next_seq);
                                    }
                                    OspfPacket::Dbd(dbd) => {
                                        if let Some(actions) = handle_dbd(
                                            &cfg, local_router_id, &status, &lsdb, &link_local_lsdb, &dbd, dbd_max_headers,
                                        )
                                        .await
                                        {
                                            execute_actions(&socket, &cfg, local_router_id, &status, dbd.router_id, actions, &mut next_seq);
                                        }
                                    }
                                    OspfPacket::Lsr(lsr) => {
                                        if let Some(actions) =
                                            handle_lsr(&cfg, local_router_id, &status, &lsdb, &link_local_lsdb, &lsr).await
                                        {
                                            execute_actions(&socket, &cfg, local_router_id, &status, lsr.router_id, actions, &mut next_seq);
                                        }
                                    }
                                    OspfPacket::Lsu(lsu) => {
                                        if let Some(actions) =
                                            handle_lsu(&cfg, local_router_id, &status, &lsdb, &link_local_lsdb, &lsu).await
                                        {
                                            execute_actions(&socket, &cfg, local_router_id, &status, lsu.router_id, actions, &mut next_seq);
                                        }
                                    }
                                    OspfPacket::LsAck(ack) => {
                                        handle_lsack(&status, &ack);
                                    }
                                }
                            }
                            Err(e) => match e {
                                PacketError::AuthTypeMismatch | PacketError::AuthFailed => {
                                    warn!(link = %cfg.attach_point, error = %e, "ospf packet authentication failed");
                                }
                                _ => {
                                    warn!(link = %cfg.attach_point, error = %e, "failed to decode ospf packet");
                                }
                            },
                        }
                    }
                    Err(e) => warn!(link = %cfg.attach_point, error = %e, "ospf recv error"),
                }
            }
            () = tokio::time::sleep_until(p2p_dead_deadline), if !is_broadcast && !is_p2mp => {
                apply_dead_timer(&cfg, &status);
                p2p_dead_deadline = Instant::now() + Duration::from_secs(u64::from(cfg.dead_interval));
            }
            _ = dead_sweep.tick() => {
                expire_grace(&cfg, &status);
                if !is_broadcast && !is_p2mp {
                    continue;
                }
                sweep_dead_neighbors(&cfg, &status);
                if is_broadcast && !waiting {
                    run_election(&cfg, local_router_id, &status);
                    advance_adjacencies(&socket, &cfg, local_router_id, &status, &mut next_seq);
                }
            }
            () = tokio::time::sleep_until(wait_deadline), if waiting => {
                waiting = false;
                run_election(&cfg, local_router_id, &status);
                advance_adjacencies(&socket, &cfg, local_router_id, &status, &mut next_seq);
            }
            Some(command) = commands.recv() => match command {
                LinkCommand::Grace(grace_period) => {
                    send_grace_lsas(&socket, &cfg, local_router_id, &status, grace_period, &mut next_seq);
                }
                LinkCommand::FloodNow => {
                    flood_full_neighbors(&socket, &cfg, local_router_id, &lsdb, &link_local_lsdb, &status, &mut next_seq).await;
                }
            },
            _ = rxmt_sweep.tick() => {
                flush_pending_acks(&socket, &cfg, local_router_id, &status, &mut next_seq);
                retransmit_pending(&socket, &cfg, local_router_id, &status, &mut next_seq);
                flood_full_neighbors(&socket, &cfg, local_router_id, &lsdb, &link_local_lsdb, &status, &mut next_seq).await;
            }
        }
    }
}

/// Wall-clock unix-seconds floor for the outgoing crypto sequence number —
/// mirrors `initial_dd_sequence_number`'s use of `SystemTime`, but must
/// specifically never regress (RFC 2328 D.4.3's anti-replay guarantee),
/// which subsec-nanos-based randomness doesn't provide. Only used for the
/// classic `AuType` 2; RFC 7474 links use the persisted boot count instead.
fn crypto_seq_floor() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().min(u64::from(u32::MAX)))
}

/// The starting outgoing sequence: RFC 7474's `boot_count << 32` (counter
/// 0), or the classic wall-clock floor.
fn initial_crypto_seq(auth: &LinkAuthConfig, boot_count: u32) -> u64 {
    if auth.is_extended() {
        u64::from(boot_count) << 32
    } else {
        crypto_seq_floor()
    }
}

/// Bumps `counter` to the next value to sign an outgoing packet with. RFC
/// 7474: one past the previous value — the low 32 bits carry into the boot
/// count on wrap, keeping the 64-bit value strictly increasing (u64 overflow
/// is unreachable). Classic: whichever is larger of one past the previous
/// value or the wall-clock floor, non-decreasing even across a link restart.
fn next_crypto_seq(counter: &mut u64, auth: &LinkAuthConfig) -> u64 {
    *counter = if auth.is_extended() {
        *counter + 1
    } else {
        counter.saturating_add(1).max(crypto_seq_floor())
    };
    *counter
}

/// RFC 2328 D.4.3's anti-replay check: `true` if this packet should be
/// dispatched, `false` if it must be silently dropped instead. Always `true`
/// when `cfg.auth` isn't `Crypto` (nothing to check) or this is the first
/// packet ever seen from this neighbor (no entry yet — `handle_hello`
/// creates it). Kept in `link.rs`, not `packet.rs`: this is stateful
/// per-neighbor bookkeeping, and `link.rs` already owns all such state (see
/// `packet::crypto_sequence`'s doc comment).
fn accept_crypto_sequence(
    cfg: &LinkConfig,
    status: &StatusHandle,
    data: &[u8],
    pkt: &OspfPacket,
) -> bool {
    if !matches!(cfg.auth, LinkAuthConfig::Crypto { .. }) {
        return true;
    }
    let Some(seq) = packet::crypto_sequence(data) else {
        return true;
    };
    let router_id = packet::router_id(pkt);
    let slot = if cfg.auth.is_extended() { data[1] } else { 0 };
    let last_seq = status
        .borrow()
        .neighbors
        .get(&router_id)
        .and_then(|n| n.last_crypto_seq.get(&slot).copied());
    if last_seq.is_some_and(|last| seq <= last) {
        return false;
    }
    status.send_modify(|s| {
        if let Some(n) = s.neighbors.get_mut(&router_id) {
            n.last_crypto_seq.insert(slot, seq);
        }
    });
    true
}

fn send_hello(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    next_seq: &mut u64,
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
        network_mask: local_netmask(cfg),
        hello_interval: cfg.hello_interval,
        options: hello_options(cfg),
        dead_interval: u32::from(cfg.dead_interval),
        router_priority: cfg.priority,
        designated_router,
        backup_designated_router,
        neighbors,
    };
    let auth = cfg
        .auth
        .as_outgoing(next_crypto_seq(next_seq, &cfg.auth), cfg.local_addr);
    if let Err(e) = socket.send_multicast(&packet::encode_hello(&pkt, &auth)) {
        warn!(link = %cfg.attach_point, error = %e, "failed to send ospf hello");
    }
}

/// The Hello options for a link's area: E outside a stub area/NSSA (RFC 2328
/// §3.6), N in an NSSA (RFC 3101 §2.1).
fn hello_options(cfg: &LinkConfig) -> u8 {
    match (cfg.stub, cfg.nssa) {
        (_, true) => packet::OPTION_N,
        (true, false) => 0,
        (false, false) => packet::OPTION_E,
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
    // a mismatched area/timer/mask/E-bit is logged and dropped, not fed into
    // the FSM (a peer with different timers would otherwise be accepted and
    // the adjacency would flap at whichever dead interval is shorter).
    if hello.area_id != cfg.area_id {
        warn!(
            link = %cfg.attach_point, area = %hello.area_id, expected = %cfg.area_id,
            "dropping ospf hello with mismatched area"
        );
        return false;
    }
    if hello.hello_interval != cfg.hello_interval {
        warn!(
            link = %cfg.attach_point, hello_interval = hello.hello_interval, expected = cfg.hello_interval,
            "dropping ospf hello with mismatched hello-interval"
        );
        return false;
    }
    if hello.dead_interval != u32::from(cfg.dead_interval) {
        warn!(
            link = %cfg.attach_point, dead_interval = hello.dead_interval, expected = cfg.dead_interval,
            "dropping ospf hello with mismatched dead-interval"
        );
        return false;
    }
    // NetworkMask is meaningless on point-to-point, point-to-multipoint and
    // virtual links (RFC 2328 §10.5) — `Broadcast` is the only network type
    // it's checked on.
    if cfg.network_type == NetworkType::Broadcast {
        let expected_mask = local_netmask(cfg);
        if hello.network_mask != expected_mask {
            warn!(
                link = %cfg.attach_point, network_mask = %hello.network_mask, expected = %expected_mask,
                "dropping ospf hello with mismatched network mask"
            );
            return false;
        }
    }
    // RFC 2328 §10.5: the E-bit is clear exactly in a stub area, so both
    // ends must agree on whether the area is one.
    if (hello.options & packet::OPTION_E != 0) == cfg.stub {
        warn!(
            link = %cfg.attach_point, neighbor = %hello.router_id,
            "dropping ospf hello with mismatched e-bit"
        );
        return false;
    }
    // RFC 3101 §2.1: the N-bit is set exactly in an NSSA.
    if (hello.options & packet::OPTION_N != 0) != cfg.nssa {
        warn!(
            link = %cfg.attach_point, neighbor = %hello.router_id,
            "dropping ospf hello with mismatched n-bit"
        );
        return false;
    }

    let saw_self = hello.neighbors.contains(&local_router_id);
    let old_state = status
        .borrow()
        .neighbors
        .get(&hello.router_id)
        .map_or(NeighborState::Down, |n| n.state);
    // RFC 3623 §3.1: a restarting neighbor's fresh Hellos don't list us yet —
    // that must not tear the adjacency down while we're helping it.
    let new_state = if !saw_self && in_grace(status, hello.router_id) {
        old_state
    } else {
        neighbor::step(old_state, neighbor::Event::HelloReceived { saw_self })
    };
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
                last_heard: Instant::now(),
                address: source,
                adjacency: None,
                last_crypto_seq: HashMap::new(),
                grace_deadline: None,
            });
        entry.state = new_state;
        entry.priority = hello.router_priority;
        entry.declared_dr = hello.designated_router;
        entry.declared_bdr = hello.backup_designated_router;
        entry.last_hello_received = Instant::now();
        entry.last_heard = Instant::now();
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
        // `last_heard` was refreshed above; the sweep expires it.
        NetworkType::Broadcast | NetworkType::PointToMultipoint => false,
    }
}

/// Scans every `TwoWay` neighbor with no adjacency yet and, for each one
/// now eligible (`should_form_adjacency`), starts RFC 2328 §10.6
/// negotiation: sends the initial negotiation DBD and moves it to
/// `ExStart`. Called after anything that could change eligibility — a
/// fresh `TwoWay`, or a completed election.
fn advance_adjacencies(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    next_seq: &mut u64,
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
        let auth = cfg
            .auth
            .as_outgoing(next_crypto_seq(next_seq, &cfg.auth), cfg.local_addr);
        if let Err(e) = socket.send_unicast(neighbor_addr, &packet::encode_dbd(&dbd, &auth)) {
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
    link_local_lsdb: &Mutex<Lsdb>,
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
            "ospf dbd rejected, neighbor interface mtu exceeds ours"
        );
        return None;
    }

    // A MaxAge entry is never offered in the summary: it may be evicted
    // (`Lsdb::MAX_AGE_HOLD_TICKS`) before the neighbor's LSR for it lands,
    // which would read as `BadLSReq` and restart the adjacency for nothing.
    // The periodic resend still carries the flush to an already-`Full`
    // neighbor.
    let mut local_lsdb_headers = lsdb.lock().await.headers();
    local_lsdb_headers.extend(link_local_lsdb.lock().await.headers());
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

/// Handles one received LSR packet, looking up every requested LSA in
/// `lsdb`. Returns `None` if the neighbor is unknown or has no adjacency in
/// progress.
async fn handle_lsr(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    lsdb: &Mutex<Lsdb>,
    link_local_lsdb: &Mutex<Lsdb>,
    lsr: &LsrPacket,
) -> Option<Vec<exchange::Action>> {
    let (old_state, mut adj) = {
        let snapshot = status.borrow();
        let neighbor = snapshot.neighbors.get(&lsr.router_id)?;
        (neighbor.state, neighbor.adjacency.clone()?)
    };

    let actions = {
        let lsdb = lsdb.lock().await;
        let link_local_lsdb = link_local_lsdb.lock().await;
        exchange::on_lsr_received(&mut adj, &lsdb, &link_local_lsdb, lsr)
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
    link_local_lsdb: &Mutex<Lsdb>,
    lsu: &LsuPacket,
) -> Option<Vec<exchange::Action>> {
    let (old_state, mut adj) = {
        let snapshot = status.borrow();
        let neighbor = snapshot.neighbors.get(&lsu.router_id)?;
        (neighbor.state, neighbor.adjacency.clone()?)
    };

    let (actions, newly_installed) = {
        let mut lsdb = lsdb.lock().await;
        let mut link_local_lsdb = link_local_lsdb.lock().await;
        let result = exchange::on_lsu_received(
            &mut adj,
            &mut lsdb,
            &mut link_local_lsdb,
            lsu,
            // tokio's clock, so paused-time tests see MinLSArrival pass.
            tokio::time::Instant::now().into_std(),
        );
        // A Grace-LSA is acted on at once and never held, even in the link
        // store (RFC 3623), so it is never offered back to the restarted
        // router. Removed under the same lock the install took.
        for l in &lsu.lsas {
            if matches!(l.body, LsaBody::Grace(_)) && result.1.contains(&l.header) {
                link_local_lsdb.remove(&l.header.key());
            }
        }
        result
    };
    if adj.pending_acks_since.is_none() && !adj.pending_acks.is_empty() {
        adj.pending_acks_since = Some(std::time::Instant::now());
    }
    for header in &newly_installed {
        info!(
            link = %cfg.attach_point, neighbor = %lsu.router_id,
            lsa_type = header.lsa_type, link_state_id = %header.link_state_id,
            advertising_router = %header.advertising_router, age = header.age,
            "ospf lsa installed"
        );
    }
    for grace in lsu
        .lsas
        .iter()
        .filter(|l| newly_installed.contains(&l.header))
    {
        if let LsaBody::Grace(body) = grace.body {
            on_grace_lsa(cfg, status, &grace.header, body);
        }
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
            info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf neighbor reached exchange");
        }
        (s, NeighborState::Loading) if s != NeighborState::Loading => {
            info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf neighbor reached loading");
        }
        (s, NeighborState::Full) if s != NeighborState::Full => {
            info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf neighbor reached full");
            if in_grace(status, neighbor_id) {
                info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf helper: neighbor reformed, exiting grace early");
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

/// Carries out the I/O side of an `exchange::Action` list — sending
/// packets. `NeighborEvent` is already applied to state by the caller;
/// `InstallAndFlood` lands in a later stage (cross-link flooding).
fn execute_actions(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    neighbor_id: Ipv4Addr,
    actions: Vec<exchange::Action>,
    next_seq: &mut u64,
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
        // Each packet sent gets its own crypto sequence number — RFC 2328
        // D.4.3's non-decreasing guarantee is per packet, not per action
        // batch.
        let auth = cfg
            .auth
            .as_outgoing(next_crypto_seq(next_seq, &cfg.auth), cfg.local_addr);
        let (kind, payload) = match action {
            exchange::Action::SendDbd(pkt) => {
                // A genuine mid-pagination continuation chunk (not the
                // initial empty negotiation attempt, which also always has
                // `more: true`) — the anchor `tools/verify-e2e.sh`'s
                // `ospf-dbd-pagination` phase greps for.
                if !pkt.init && pkt.more {
                    info!(
                        link = %cfg.attach_point, neighbor = %neighbor_id,
                        dd_sequence_number = pkt.dd_sequence_number,
                        "ospf dbd chunk sent, more remaining"
                    );
                }
                ("dbd", packet::encode_dbd(&pkt, &auth))
            }
            exchange::Action::SendLsr(requests) => (
                "lsr",
                packet::encode_lsr(
                    &LsrPacket {
                        router_id: local_router_id,
                        area_id: cfg.area_id,
                        requests,
                    },
                    &auth,
                ),
            ),
            exchange::Action::SendLsu(lsas) => (
                "lsu",
                packet::encode_lsu(
                    &LsuPacket {
                        router_id: local_router_id,
                        area_id: cfg.area_id,
                        lsas: lsas.iter().map(|l| (**l).clone()).collect(),
                    },
                    &auth,
                ),
            ),
            exchange::Action::SendLsAck(lsa_headers) => (
                "lsack",
                packet::encode_lsack(
                    &LsAckPacket {
                        router_id: local_router_id,
                        area_id: cfg.area_id,
                        lsa_headers,
                    },
                    &auth,
                ),
            ),
            exchange::Action::NeighborEvent(_) | exchange::Action::InstallAndFlood(_) => continue,
        };
        if let Err(e) = socket.send_unicast(neighbor_addr, &payload) {
            warn!(link = %cfg.attach_point, neighbor = %neighbor_id, kind, error = %e, "failed to send ospf packet");
        }
    }
}

/// RFC 2328 §13.5 delayed acknowledgment: sends each neighbor's queued acks
/// (`AdjacencyData::pending_acks`, filled by `on_lsu_received`) as one
/// `LSAck`. Runs on the `RXMT_INTERVAL` sweep — the RFC only requires the
/// delay to stay below `RxmtInterval`, and one more tick per link keeps
/// `run()`'s `select!` no wider.
fn flush_pending_acks(
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
fn retransmit_pending(
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
async fn flood_full_neighbors(
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

/// RFC 4222 §2 recommendation 2: an authenticated non-Hello packet from a
/// neighbor we have an adjacency with (`ExStart` or later) proves it alive,
/// so it restarts the inactivity timer like a Hello would. Hellos keep their
/// own refresh in `handle_hello`, which only happens once they pass its
/// checks. ponytail: counts any destination, not only unicast / `AllSPFRouters`
/// on point-to-point as the RFC words it — `recv_packet` doesn't return the
/// destination (that needs `IP_PKTINFO`), and nos sends these unicast anyway.
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
        *p2p_dead_deadline = now + Duration::from_secs(u64::from(cfg.dead_interval));
    }
}

/// Broadcast and point-to-multipoint. Ages out any neighbor whose `last_heard` is
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

fn in_grace(status: &StatusHandle, neighbor_id: Ipv4Addr) -> bool {
    status
        .borrow()
        .neighbors
        .get(&neighbor_id)
        .is_some_and(|n| n.grace_deadline.is_some())
}

/// RFC 3623 helper side: a Grace-LSA from a `Full` neighbor on this link
/// starts (or, idempotently, refreshes) its grace period; a `MaxAge` one —
/// the restarting router flushing it — ends it. Matched on the advertising
/// router id, which is how neighbors are keyed here (the IP Interface
/// Address TLV only matters where neighbors are keyed by address).
///
/// ponytail: no RFC 3623 §3.2 (c) strict LSA checking — helping goes on
/// through a topology change. Add it if a real topology change during a
/// restart matters: with periodic full resend, "an LSA flooded to the
/// restarter changed" means any type 1-5 content change in this area from
/// anyone but the restarter.
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
            info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf helper: grace-lsa flushed, exiting grace");
            status.send_modify(|s| {
                if let Some(n) = s.neighbors.get_mut(&neighbor_id) {
                    n.grace_deadline = None;
                }
            });
        }
        return;
    }
    if state != NeighborState::Full {
        warn!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf helper: ignoring grace-lsa from a neighbor that is not full");
        return;
    }
    if deadline.is_none() {
        info!(
            link = %cfg.attach_point, neighbor = %neighbor_id,
            grace_period = body.grace_period, restart_reason = body.restart_reason,
            "ospf helper: grace period entered"
        );
    }
    let deadline = Instant::now() + Duration::from_secs(u64::from(body.grace_period));
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
        warn!(link = %cfg.attach_point, neighbor = %id, "ospf helper: grace period expired");
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

/// RFC 3623's restarting side: one Grace-LSA (type 9, opaque type 3) unicast
/// to every `Full` neighbor on this link, just before the process exits.
/// Never installed locally.
fn send_grace_lsas(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    grace_period: u32,
    next_seq: &mut u64,
) {
    let grace = Lsa {
        header: LsaHeader {
            age: 0,
            options: 0,
            lsa_type: lsa::LSA_TYPE_OPAQUE_LINK,
            link_state_id: lsa::GRACE_LINK_STATE_ID,
            advertising_router: local_router_id,
            sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
            checksum: 0,
            length: 0,
        },
        body: LsaBody::Grace(GraceLsaBody {
            grace_period,
            restart_reason: lsa::RESTART_REASON_SOFTWARE,
            interface_address: Some(cfg.local_addr),
        }),
    };
    let auth = cfg
        .auth
        .as_outgoing(next_crypto_seq(next_seq, &cfg.auth), cfg.local_addr);
    let payload = packet::encode_lsu(
        &LsuPacket {
            router_id: local_router_id,
            area_id: cfg.area_id,
            lsas: vec![grace],
        },
        &auth,
    );
    let full: Vec<(Ipv4Addr, Ipv4Addr)> = status
        .borrow()
        .neighbors
        .iter()
        .filter(|(_, n)| n.state == NeighborState::Full)
        .map(|(id, n)| (*id, n.address))
        .collect();
    for (neighbor_id, address) in full {
        match socket.send_unicast(address, &payload) {
            Ok(()) => info!(
                link = %cfg.attach_point, neighbor = %neighbor_id, grace_period,
                "ospf graceful restart: grace-lsa sent"
            ),
            Err(e) => {
                warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospf grace-lsa");
            }
        }
    }
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

    // Re-logs whenever the reported role *or* the dr/bdr router-ids behind
    // it change — not just on an `InterfaceState` variant change. A router
    // can stay `DrOther` (or `Backup`) across more than one election pass
    // while a neighbor's own declared role is still converging (RFC 2328
    // §9.4's own "recompute twice" refinement, which `election.rs`'s
    // single-pass simplification defers to a later Hello-driven rerun
    // instead) — without this, the log would freeze on that first,
    // not-yet-converged dr/bdr pair even though `status.send_modify` below
    // keeps the real state (and thus real adjacency-eligibility decisions)
    // correct throughout.
    if (snapshot.interface_state, snapshot.dr, snapshot.bdr)
        != (new_interface_state, result.dr, result.bdr)
    {
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

/// A request from `LinkManager` to one link task.
#[derive(Debug, Clone, Copy)]
pub enum LinkCommand {
    /// Send Grace-LSAs (the grace period, seconds).
    Grace(u32),
    /// Resend the LSDB to every `Full` neighbor now, not on the next
    /// `RXMT_INTERVAL` — the shutdown path only (`LinkManager::flood_now`).
    FloodNow,
}

struct LinkEntry {
    config: LinkConfig,
    task: JoinHandle<()>,
    status: watch::Receiver<LinkStatus>,
    commands: mpsc::UnboundedSender<LinkCommand>,
    /// RFC 5250 type-9 (link-local) LSAs heard on this link — dropped with
    /// the entry when the link stops or restarts.
    link_local_lsdb: Arc<Mutex<Lsdb>>,
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
    /// Woken by every LSDB change; see `route_changed`.
    route_changed: Arc<tokio::sync::Notify>,
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
    /// Scales `AGE_TICK_INTERVAL`'s per-tick age-increment — always `1` (one
    /// simulated second per real second) outside of `tools/verify-e2e.sh`'s
    /// `ospf-aging` phase, which needs RFC 2328 §14's 1800s/3600s timers to
    /// resolve in seconds rather than tens of minutes. See `main.rs`'s
    /// `--lsa-age-multiplier`.
    age_multiplier: u16,
    /// RFC 2328 §10.8's per-DBD-packet LSA-header budget override, passed
    /// down into every link's `run()`. `None` (the real production default)
    /// derives the budget per-link from that link's own effective MTU
    /// (`exchange::mtu_based_max_headers`); `Some(n)` — set only by
    /// `tools/verify-e2e.sh`'s `ospf-dbd-pagination` phase, test/debug only —
    /// forces every link to the same fixed value regardless of MTU, to
    /// force multi-packet pagination deterministically over a small lab
    /// LSDB. See `main.rs`'s `--dbd-max-headers`.
    dbd_max_headers: Option<usize>,
    /// Source of RFC 7474 boot counts, one per extended-auth link (re)start.
    boots: crate::boot::BootCounter,
    /// Raw (pre-policy) redistributed prefixes from `OspfRequest::
    /// RedistributeRoutes`. A `HashSet`, not a map — the `RedistributedRoute`
    /// gateway is never used: this router always originates with
    /// `forwarding_address = 0.0.0.0`, so a redistributed route's own next-hop
    /// always comes from SPF's own computed next-hop to the ASBR, never from
    /// the raw route's gateway (see `AsExternalLsaBody`'s doc comment).
    redistribute_raw: Mutex<HashSet<Ipv4Net>>,
    /// Policy-filtered set actually originated as Type-5 LSAs. Recomputed by
    /// `set_redistribute_policy`, called every resync from `reconcile.rs`,
    /// mirroring `bgp::BgpRib::set_redistribute_policy`'s "called
    /// unconditionally, re-filters eagerly" contract.
    redistribute_filtered: Mutex<HashSet<Ipv4Net>>,
    /// Set by `shutdown`: stops the origination tick from reoriginating the
    /// LSAs it just flushed while their `MaxAge` copies are still being
    /// flooded (`PREMATURE_AGE_FLOOD_WINDOW`). Aging keeps running.
    shutting_down: AtomicBool,
    /// RFC 3623 grace period (seconds) to announce on a planned restart;
    /// `0` = graceful restart off.
    grace_period: AtomicU16,
    /// RFC 6860: hide transit-only networks (`OspfInstance.prefix_suppression`).
    /// An instance-wide atomic rather than a `LinkConfig` field, so a toggle
    /// re-originates on the next tick without restarting any link.
    prefix_suppression: AtomicBool,
    /// RFC 8770 host router (`OspfInstance.host_router`): the Router-LSA's
    /// H-bit, with max-metric transit links. An atomic like
    /// `prefix_suppression`.
    host_router: AtomicBool,
    /// Each area's last RFC 8770 state — (H-bit honoured, routers with the
    /// H-bit) — only to log a change.
    host_bit_state: Mutex<HashMap<Ipv4Addr, (bool, usize)>>,
    /// Set by `announce_graceful_restart`: `shutdown` then keeps every
    /// self-originated LSA instead of flushing it (RFC 3623 §2).
    restarting: AtomicBool,
    /// RFC 6987 stub router (`OspfInstance.max_metric_*`), see
    /// `max_metric_active`.
    max_metric: std::sync::Mutex<MaxMetric>,
    /// Each configured area's stub/range settings (`OspfArea`), replaced on
    /// every resync; an area missing here is a normal area with no range.
    area_settings: Mutex<HashMap<Ipv4Addr, AreaSettings>>,
    /// Active advertised area ranges and their metric, rewritten by every
    /// `originate_summary_lsas` pass — `compute_routes` turns them into
    /// discard routes.
    active_ranges: Mutex<HashMap<Ipv4Net, u32>>,
    /// Each NSSA's last translator election result (RFC 3101 §3.1), only to
    /// log a change.
    nssa_translating: Mutex<HashMap<Ipv4Addr, bool>>,
    opener: Opener,
}

/// RFC 6987 stub-router state. `std` mutex: never held across an await.
// Independent flags, each read on its own.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default)]
struct MaxMetric {
    administrative: bool,
    /// On-shutdown hold, seconds (0 = off).
    on_shutdown: u8,
    /// End of the on-startup period, armed once by the first `set_max_metric`.
    until: Option<Instant>,
    /// The first `set_max_metric` call has happened.
    armed: bool,
    /// Respawned after a graceful restart (`boot::take_grace_marker`): the
    /// helpers kept the old topology, so on-startup is skipped.
    after_graceful_restart: bool,
    /// The last state logged by `max_metric_tick`.
    logged: bool,
}

/// One area's RFC 2328 §3.5/§3.6 and RFC 3101 settings, resolved from
/// `OspfArea`.
// Independent config flags, each read on its own.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AreaSettings {
    /// No AS-external LSAs (a stub area or an NSSA); as an ABR of a stub
    /// area, originate a default Type-3 into it.
    pub stub: bool,
    /// An RFC 3101 NSSA (`stub` is set too): Type-7s instead of Type-5s, and
    /// a default Type-3 from an ABR only without `import_summaries`.
    pub nssa: bool,
    /// RFC 2328 Appendix C.2 `ImportSummaries`: `false` (totally stubby,
    /// NSSA no-summary) sends only the default Type-3 into the area.
    pub import_summaries: bool,
    /// RFC 3101 `NSSATranslatorRole` `Always` (else `Candidate`).
    pub nssa_translate_always: bool,
    /// RFC 3101 §2.7: as an ABR, originate a default Type-7 into the NSSA.
    pub nssa_default_originate: bool,
    /// `StubDefaultCost`.
    pub default_cost: u32,
    /// `(range, advertise)`, applied to this area's prefixes when summarized
    /// into the other areas.
    pub ranges: Vec<(Ipv4Net, bool)>,
}

impl LinkManager {
    pub fn new(
        age_multiplier: u16,
        dbd_max_headers: Option<usize>,
        boots: crate::boot::BootCounter,
    ) -> Arc<Self> {
        Self::with_opener(
            age_multiplier,
            dbd_max_headers,
            boots,
            Arc::new(|cfg: &LinkConfig| {
                OspfSocket::open(&cfg.kernel_interface, cfg.local_addr).map(LinkSocket::Os)
            }),
        )
    }

    /// `new` with the link sockets opened by `opener` instead of as real raw
    /// sockets — the in-memory wire in tests.
    pub fn with_opener(
        age_multiplier: u16,
        dbd_max_headers: Option<usize>,
        boots: crate::boot::BootCounter,
        opener: Opener,
    ) -> Arc<Self> {
        let manager = Arc::new(Self {
            links: Mutex::new(HashMap::new()),
            lsdbs: Mutex::new(HashMap::new()),
            route_changed: Arc::new(tokio::sync::Notify::new()),
            router_id: Mutex::new(None),
            stub_networks: Mutex::new(HashMap::new()),
            age_multiplier,
            dbd_max_headers,
            boots,
            redistribute_raw: Mutex::new(HashSet::new()),
            redistribute_filtered: Mutex::new(HashSet::new()),
            shutting_down: AtomicBool::new(false),
            grace_period: AtomicU16::new(0),
            prefix_suppression: AtomicBool::new(false),
            host_router: AtomicBool::new(false),
            host_bit_state: Mutex::new(HashMap::new()),
            restarting: AtomicBool::new(false),
            max_metric: std::sync::Mutex::new(MaxMetric::default()),
            area_settings: Mutex::new(HashMap::new()),
            active_ranges: Mutex::new(HashMap::new()),
            nssa_translating: Mutex::new(HashMap::new()),
            opener,
        });
        let background = Arc::clone(&manager);
        // Runs for the process's lifetime — like every link driver task, it
        // ends only when the tokio runtime itself is torn down at process
        // exit, so there's nothing to abort on shutdown.
        tokio::spawn(async move {
            let mut origination_tick = tokio::time::interval(ORIGINATION_INTERVAL);
            origination_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut age_tick = tokio::time::interval(AGE_TICK_INTERVAL);
            age_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = origination_tick.tick() => {
                        if background.shutting_down.load(Ordering::Relaxed) {
                            continue;
                        }
                        if let Some(router_id) = *background.router_id.lock().await {
                            background.originate_router_lsas(router_id).await;
                            background.originate_as_external_lsas(router_id).await;
                            background.originate_summary_lsas(router_id).await;
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

    pub fn set_graceful_restart(&self, grace_period: Option<u16>) {
        self.grace_period
            .store(grace_period.unwrap_or(0), Ordering::Relaxed);
    }

    pub fn set_prefix_suppression(&self, on: bool) {
        self.prefix_suppression.store(on, Ordering::Relaxed);
    }

    pub fn set_host_router(&self, on: bool) {
        self.host_router.store(on, Ordering::Relaxed);
    }

    fn max_metric_state(&self) -> std::sync::MutexGuard<'_, MaxMetric> {
        self.max_metric
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Set once, before the first `set_max_metric`, when this process is the
    /// respawn of a graceful restart (`boot::take_grace_marker`).
    pub fn set_after_graceful_restart(&self, after: bool) {
        self.max_metric_state().after_graceful_restart = after;
    }

    /// RFC 6987 knobs, every resync. The first call (the first config
    /// resolution after start) arms the on-startup period — skipped after a
    /// graceful restart; later calls never re-arm it (it takes effect on the
    /// next start), and `None` ends a running one.
    pub fn set_max_metric(
        &self,
        on_startup: Option<u32>,
        on_shutdown: Option<u8>,
        administrative: bool,
    ) {
        let mut mm = self.max_metric_state();
        mm.administrative = administrative;
        mm.on_shutdown = on_shutdown.unwrap_or(0);
        if !mm.armed {
            mm.armed = true;
            match on_startup {
                Some(_) if mm.after_graceful_restart => {
                    info!("ospf stub router on-startup skipped after graceful restart");
                }
                Some(secs) => {
                    mm.until = Some(Instant::now() + Duration::from_secs(u64::from(secs)));
                }
                None => {}
            }
        } else if on_startup.is_none() {
            mm.until = None;
        }
    }

    /// RFC 6987: whether this router advertises itself as a stub router
    /// (max-metric transit links) — administratively, or still inside its
    /// on-startup period — or as an RFC 8770 host router, whose transit
    /// links are always at max metric.
    pub fn max_metric_active(&self) -> bool {
        let mm = self.max_metric_state();
        mm.administrative
            || mm.until.is_some_and(|t| Instant::now() < t)
            || self.host_router.load(Ordering::Relaxed)
    }

    /// `max_metric_active`, logging a change (read once per origination tick).
    fn max_metric_tick(&self) -> bool {
        let mut mm = self.max_metric_state();
        let starting = mm.until.is_some_and(|t| Instant::now() < t);
        let active = mm.administrative || starting;
        if active != mm.logged {
            mm.logged = active;
            let reason = if active && mm.administrative {
                "administrative"
            } else if active {
                "on-startup"
            } else if mm.until.take().is_some() {
                "expired"
            } else {
                "cleared"
            };
            info!(active, reason, "ospf stub router max-metric changed");
        }
        active
    }

    pub async fn set_area_settings(&self, settings: HashMap<Ipv4Addr, AreaSettings>) {
        *self.area_settings.lock().await = settings;
    }

    /// `area_id`'s settings — a normal area's when not configured.
    async fn area(&self, area_id: Ipv4Addr) -> AreaSettings {
        self.area_settings
            .lock()
            .await
            .get(&area_id)
            .cloned()
            .unwrap_or_default()
    }

    /// RFC 2328 A.4.2's B-bit test: a link or loopback stub in 2+ areas (not
    /// `lsdbs.len()`, which never shrinks after leaving an area).
    async fn is_area_border_router(&self) -> bool {
        let mut areas: HashSet<Ipv4Addr> = self
            .links
            .lock()
            .await
            .values()
            .map(|e| e.config.area_id)
            .collect();
        areas.extend(self.stub_networks.lock().await.keys().copied());
        areas.len() >= 2
    }

    /// RFC 3101 §2.3: a Type-7's forwarding address — one of this router's
    /// own addresses in the NSSA (the lowest link address, else a loopback
    /// stub's), so a translator can translate it. RFC 6860 §4.1: with prefix
    /// suppression the link addresses are hidden, so only a loopback's.
    async fn nssa_forwarding_address(&self, area_id: Ipv4Addr) -> Ipv4Addr {
        let suppressed = self.prefix_suppression.load(Ordering::Relaxed);
        let link = self
            .links
            .lock()
            .await
            .values()
            .filter(|e| e.config.area_id == area_id && !suppressed)
            .map(|e| e.config.local_addr)
            .min();
        match link {
            Some(addr) => addr,
            None => self
                .stub_networks
                .lock()
                .await
                .get(&area_id)
                .and_then(|stubs| stubs.iter().map(|(net, _)| net.addr()).min())
                .unwrap_or(Ipv4Addr::UNSPECIFIED),
        }
    }

    /// Gets or creates the shared LSDB for `area_id`.
    async fn lsdb_for(&self, area_id: Ipv4Addr) -> Arc<Mutex<Lsdb>> {
        Arc::clone(self.lsdbs.lock().await.entry(area_id).or_insert_with(|| {
            Arc::new(Mutex::new(Lsdb::with_notify(Arc::clone(
                &self.route_changed,
            ))))
        }))
    }

    /// RFC 2328 §14: ages every installed LSA, in every area, by one
    /// (simulated) second times `age_multiplier`, evicting anything that
    /// reaches `MAX_AGE`. Run every `AGE_TICK_INTERVAL`, independent of
    /// `originate_router_lsas` — aging is LSDB-wide, not per-link.
    async fn age_lsdbs(&self) {
        // RFC 3623 §3.1: a restarting neighbor's LSAs are kept until its grace
        // period ends.
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
        let mut stores: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(area_id, lsdb)| (*area_id, Arc::clone(lsdb)))
            .collect();
        stores.extend(self.link_local_lsdbs().await);
        for (area_id, lsdb) in stores {
            let evicted = lsdb.lock().await.age_and_evict(self.age_multiplier, &hold);
            for key in evicted {
                info!(
                    area = %area_id, lsa_type = key.lsa_type, link_state_id = %key.link_state_id,
                    advertising_router = %key.advertising_router,
                    "ospf lsa maxage flushed"
                );
            }
        }
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
        let max_metric = self.max_metric_tick();
        self.originate_router_lsas_with(local_router_id, max_metric)
            .await;
    }

    /// `originate_router_lsas` with an explicit RFC 6987 `max_metric`
    /// (forced on as an RFC 8770 host router). Returns whether a Router-LSA
    /// was (re)installed in some area.
    async fn originate_router_lsas_with(
        &self,
        local_router_id: Ipv4Addr,
        max_metric: bool,
    ) -> bool {
        let host_router = self.host_router.load(Ordering::Relaxed);
        let max_metric = max_metric || host_router;
        let mut router_lsa_installed = false;
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
        let prefix_suppression = self.prefix_suppression.load(Ordering::Relaxed);

        // An area with only a loopback stub and no live link would
        // otherwise never appear here at all — union both sets of area
        // ids rather than iterating `by_area` alone. An area this router
        // holds an LSDB for but has left entirely (no link, no stub) is
        // visited too, so its Router-/Network-LSAs get withdrawn.
        let area_ids: HashSet<Ipv4Addr> = by_area
            .keys()
            .copied()
            .chain(stub_networks.keys().copied())
            .chain(self.lsdbs.lock().await.keys().copied())
            .collect();

        // RFC 2328 A.4.2: B when this router has a link or stub in 2+ areas;
        // E when it originates a Type-5 (the same set
        // `originate_as_external_lsas` reads).
        let mut flags = 0;
        if self.is_area_border_router().await {
            flags |= lsa::ROUTER_FLAG_B;
        }
        if !self.redistribute_filtered.lock().await.is_empty() {
            flags |= lsa::ROUTER_FLAG_E;
        }
        // RFC 8770 §3: in every area, ABR or not.
        if host_router {
            flags |= lsa::ROUTER_FLAG_H;
        }
        // RFC 7770 §2.4: stub-router and host-router support (honouring
        // others' H-bit) are capabilities, always set.
        let mut router_info_caps =
            lsa::RI_CAP_GR_HELPER | lsa::RI_CAP_STUB_ROUTER | lsa::RI_CAP_HOST_ROUTER;
        if self.grace_period.load(Ordering::Relaxed) != 0 {
            router_info_caps |= lsa::RI_CAP_GR_CAPABLE;
        }

        for area_id in area_ids {
            let links = by_area.get(&area_id).cloned().unwrap_or_default();
            let lsdb = self.lsdb_for(area_id).await;
            let mut lsdb = lsdb.lock().await;

            if links.is_empty() && !stub_networks.contains_key(&area_id) {
                withdraw_undesired(
                    &mut lsdb,
                    local_router_id,
                    lsa::LSA_TYPE_ROUTER,
                    &HashSet::new(),
                );
                withdraw_undesired(
                    &mut lsdb,
                    local_router_id,
                    lsa::LSA_TYPE_NETWORK,
                    &HashSet::new(),
                );
                withdraw_undesired(
                    &mut lsdb,
                    local_router_id,
                    lsa::LSA_TYPE_OPAQUE_AREA,
                    &HashSet::new(),
                );
                continue;
            }

            let mut router_links =
                router_lsa_links(local_router_id, &links, prefix_suppression, max_metric);
            // Loopbacks aren't transit, so RFC 6860 never hides them.
            for (subnet, cost) in stub_networks.get(&area_id).into_iter().flatten() {
                router_links.push(RouterLink {
                    link_id: subnet.network(),
                    link_data: subnet.netmask(),
                    link_type: LINK_TYPE_STUB_NETWORK,
                    metric: *cost,
                });
            }

            // No Type-5 goes into a stub area, so we are no ASBR there (in an
            // NSSA we are, through Type-7s). RFC 3101 A.2: Nt on an NSSA
            // border router that always translates.
            let area = self.area(area_id).await;
            let mut area_flags = flags;
            if area.stub && !area.nssa {
                area_flags &= !lsa::ROUTER_FLAG_E;
            }
            if area.nssa_translate_always && flags & lsa::ROUTER_FLAG_B != 0 {
                area_flags |= lsa::ROUTER_FLAG_NT;
            }
            router_lsa_installed |= install_self_originated(
                &mut lsdb,
                local_router_id,
                lsa::LSA_TYPE_ROUTER,
                local_router_id,
                LsaBody::Router(RouterLsaBody {
                    flags: area_flags,
                    links: router_links,
                }),
            );
            // RFC 7770 Router Information, area scope (type 10) so it reaches
            // stub areas and NSSAs too. Helper is always on (RFC 3623).
            install_self_originated(
                &mut lsdb,
                local_router_id,
                lsa::LSA_TYPE_OPAQUE_AREA,
                lsa::ROUTER_INFO_LINK_STATE_ID,
                LsaBody::Opaque(lsa::encode_router_info(router_info_caps)),
            );

            let mut network_ids = HashSet::new();
            for (cfg, status) in &links {
                if status.interface_state != InterfaceState::Dr {
                    continue;
                }
                let attached: Vec<Ipv4Addr> = std::iter::once(local_router_id)
                    .chain(
                        status
                            .neighbors
                            .iter()
                            // RFC 3623 §3.1: a restarting neighbor we help
                            // is still advertised as fully adjacent.
                            .filter(|(_, n)| {
                                n.state == NeighborState::Full || n.grace_deadline.is_some()
                            })
                            .map(|(id, _)| *id),
                    )
                    .collect();
                if attached.len() < 2 {
                    // No fully-adjacent neighbor yet — nothing transit
                    // about this network from the LSDB's perspective.
                    continue;
                }
                let network_mask = network_lsa_mask(cfg, prefix_suppression);
                network_ids.insert(cfg.local_addr);
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
            // No longer DR on a link (or the link is gone): flush its Network-LSA.
            withdraw_undesired(
                &mut lsdb,
                local_router_id,
                lsa::LSA_TYPE_NETWORK,
                &network_ids,
            );
        }
        router_lsa_installed
    }

    /// RFC 2328 §12.4.3-style self-origination of this router's own
    /// redistributed prefixes as AS-external-LSAs (ASBR-only — see
    /// `ospf/CLAUDE.md`'s "ASBR and AS-external-LSA origination"). Run from
    /// the same tick as `originate_router_lsas`.
    ///
    /// This is the one genuinely new cross-area mechanism in this crate:
    /// this router's own redistributed prefixes are installed into *every*
    /// area it is itself attached to (`self.lsdbs`'s full key set), not just
    /// one — real RFC 2328 AS-external-LSAs are domain-wide, not area-scoped,
    /// like Router-/Network-LSAs. This is **not** real ABR translation of
    /// another router's externally-learned LSA across areas (which stays out
    /// of scope, see root `CLAUDE.md`) — it's simply this same router
    /// replicating its own origination into every area it directly
    /// participates in. No new flooding code is needed beyond the install
    /// step: `flood_full_neighbors` already resends each link's own area's
    /// full `Lsdb` periodically, so a freshly-installed Type-5 propagates
    /// automatically.
    async fn originate_as_external_lsas(&self, local_router_id: Ipv4Addr) {
        let redistributed: Vec<Ipv4Net> = self
            .redistribute_filtered
            .lock()
            .await
            .iter()
            .copied()
            .collect();
        let areas: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(id, lsdb)| (*id, Arc::clone(lsdb)))
            .collect();
        let settings = self.area_settings.lock().await.clone();
        let abr = self.is_area_border_router().await;

        // RFC 3101 §3.1/§3.2: as the elected translator of an NSSA, its P-bit
        // Type-7s become this router's own Type-5s in the normal areas.
        let mut translated: Vec<(Ipv4Net, u32)> = Vec::new();
        {
            let mut roles = self.nssa_translating.lock().await;
            for (area_id, lsdb) in &areas {
                let Some(area) = settings.get(area_id).filter(|a| a.nssa) else {
                    roles.remove(area_id);
                    continue;
                };
                let lsas = lsdb.lock().await.all();
                let translating =
                    abr && spf::nssa_translator(local_router_id, &lsas, area.nssa_translate_always);
                if roles.insert(*area_id, translating) != Some(translating) {
                    info!(area = %area_id, translating, "ospf nssa translator role changed");
                }
                if translating {
                    translated.extend(spf::nssa_translations(local_router_id, &lsas));
                }
            }
        }

        for (area_id, lsdb) in &areas {
            let area = settings.get(area_id).cloned().unwrap_or_default();
            // Keyed by prefix, so a redistributed prefix that is also
            // translated is originated once. Type-7: `(options, metric,
            // forwarding address)`.
            let mut type5: HashMap<Ipv4Net, u32> = HashMap::new();
            let mut type7: HashMap<Ipv4Net, (u8, u32, Ipv4Addr)> = HashMap::new();
            if !area.stub {
                type5.extend(translated.iter().copied());
                type5.extend(redistributed.iter().map(|&p| (p, 0)));
            } else if area.nssa {
                // RFC 3101 §2.4: an ABR clears the P-bit, since it originates
                // the Type-5 for the same prefix itself.
                let options = if abr { 0 } else { lsa::OPTION_P };
                let fa = self.nssa_forwarding_address(*area_id).await;
                type7.extend(redistributed.iter().map(|&p| (p, (options, 0, fa))));
                if abr && area.nssa_default_originate {
                    type7.insert(
                        Ipv4Net::default(),
                        (0, area.default_cost, Ipv4Addr::UNSPECIFIED),
                    );
                }
            }
            // RFC 2328 §3.6: no Type-5 in a stub area or NSSA (one that just
            // turned stub gets this router's own flushed), and a Type-7 only
            // in an NSSA.
            let mut lsdb = lsdb.lock().await;
            // Type-5 and Type-7 are separate LS-ID spaces.
            let mut type5_ids = HashSet::new();
            for (prefix, id) in assign_link_state_ids(type5.keys().copied()) {
                type5_ids.insert(id);
                install_self_originated(
                    &mut lsdb,
                    local_router_id,
                    lsa::LSA_TYPE_AS_EXTERNAL,
                    id,
                    LsaBody::AsExternal(AsExternalLsaBody {
                        network_mask: prefix.netmask(),
                        metric: type5[&prefix],
                        // ponytail: a translated Type-5 doesn't carry the
                        // Type-7's forwarding address (§3.2 (3)), so traffic
                        // to it goes through the translator, not straight to
                        // the NSSA ASBR. Copy it once SPF resolves one.
                        forwarding_address: Ipv4Addr::UNSPECIFIED,
                        external_route_tag: 0,
                    }),
                );
            }
            let mut type7_ids = HashSet::new();
            for (prefix, id) in assign_link_state_ids(type7.keys().copied()) {
                type7_ids.insert(id);
                let (options, metric, forwarding_address) = type7[&prefix];
                install_self_originated_with_options(
                    &mut lsdb,
                    local_router_id,
                    lsa::LSA_TYPE_NSSA_EXTERNAL,
                    id,
                    options,
                    LsaBody::AsExternal(AsExternalLsaBody {
                        network_mask: prefix.netmask(),
                        metric,
                        forwarding_address,
                        external_route_tag: 0,
                    }),
                );
            }
            // RFC 2328 §14.1: a prefix no longer redistributed (or
            // translated) is flushed, not left to age out over `MAX_AGE`.
            for (lsa_type, desired) in [
                (lsa::LSA_TYPE_AS_EXTERNAL, type5_ids),
                (lsa::LSA_TYPE_NSSA_EXTERNAL, type7_ids),
            ] {
                withdraw_undesired(&mut lsdb, local_router_id, lsa_type, &desired);
            }
        }
    }

    /// RFC 2328 §12.4.3-style self-origination of this router's own ABR
    /// Summary-LSAs (Type-3 network-summary, Type-4 ASBR-summary) — see
    /// `ospf/CLAUDE.md`'s "ABR and Summary-LSA origination". ABR-ness is
    /// purely derived from live state (`self.lsdbs.keys().len() >= 2`),
    /// mirroring how this crate already derives DR-ness/ASBR-ness from live
    /// state rather than a config flag — no explicit "am I an ABR" field.
    /// Run from the same tick as `originate_router_lsas`/
    /// `originate_as_external_lsas`, after both, so this tick's freshest
    /// Router-/AS-external-LSAs are what gets summarized. No new flooding
    /// code needed — `flood_full_neighbors` already resends each link's own
    /// area's full `Lsdb`, exactly as it already does for Type-5.
    async fn originate_summary_lsas(&self, local_router_id: Ipv4Addr) {
        let areas: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(id, lsdb)| (*id, Arc::clone(lsdb)))
            .collect();
        // A single-area router summarizes nothing (and, `lsdbs` never
        // shrinking, can't hold a stale summary either); the per-area
        // withdrawal below is then a cheap no-op header scan.
        let settings = self.area_settings.lock().await.clone();
        // Per source area: what to summarize from it (its area ranges
        // applied, RFC 2328 §12.4.3) and the ASBRs in it.
        let mut per_area: HashMap<Ipv4Addr, (spf::Summaries, Vec<(Ipv4Addr, u32)>)> =
            HashMap::new();
        let mut active_ranges = HashMap::new();
        if areas.len() >= 2 {
            for (area_id, lsdb) in &areas {
                let lsas = lsdb.lock().await.all();
                let view = spf::intra_area_routes(local_router_id, &lsas);
                let ranges = settings.get(area_id).map_or(&[][..], |s| &s.ranges[..]);
                let (prefixes, active) = spf::apply_ranges(&view.routes, ranges);
                active_ranges.extend(active);
                per_area.insert(*area_id, (prefixes, view.asbrs));
            }
        }
        *self.active_ranges.lock().await = active_ranges;

        for (dest_area, dest_lsdb) in &areas {
            let dest = settings.get(dest_area).cloned().unwrap_or_default();
            let mut dest_lsdb = dest_lsdb.lock().await;
            // Collected first, so a prefix intra-area in two source areas is
            // one Type-3 (the cheaper), and Appendix E sees the whole set.
            let mut type3: HashMap<Ipv4Net, u32> = HashMap::new();
            let mut asbr_ids = HashSet::new();
            // RFC 2328 §12.4.3.1: an ABR sends a default Type-3 into a stub
            // area — and, totally stubby (no `ImportSummaries`), nothing else.
            // ponytail: ABR-ness stays "2+ areas", with no check that one of
            // them is the backbone.
            // RFC 3101 §2.3: into an NSSA, only when it's no-summary.
            if dest.stub && (!dest.nssa || !dest.import_summaries) && !per_area.is_empty() {
                type3.insert(Ipv4Net::default(), dest.default_cost);
            }
            for (src_area, (prefixes, asbrs)) in &per_area {
                if src_area == dest_area || (dest.stub && !dest.import_summaries) {
                    continue;
                }
                for &(prefix, metric) in prefixes {
                    let entry = type3.entry(prefix.trunc()).or_insert(metric);
                    *entry = (*entry).min(metric);
                }
                // No ASBR-summary into a stub area or NSSA: it carries no
                // Type-5.
                if dest.stub {
                    continue;
                }
                for &(asbr, dist) in asbrs {
                    asbr_ids.insert(asbr);
                    install_self_originated(
                        &mut dest_lsdb,
                        local_router_id,
                        lsa::LSA_TYPE_ASBR_SUMMARY,
                        asbr,
                        LsaBody::Summary(SummaryLsaBody {
                            network_mask: Ipv4Addr::UNSPECIFIED,
                            metric: dist,
                        }),
                    );
                }
            }
            let mut network_ids = HashSet::new();
            for (prefix, id) in assign_link_state_ids(type3.keys().copied()) {
                network_ids.insert(id);
                install_self_originated(
                    &mut dest_lsdb,
                    local_router_id,
                    lsa::LSA_TYPE_NETWORK_SUMMARY,
                    id,
                    LsaBody::Summary(SummaryLsaBody {
                        network_mask: prefix.netmask(),
                        metric: type3[&prefix],
                    }),
                );
            }
            // RFC 2328 §14.1: a prefix/ASBR no longer intra-area to some
            // other area is flushed, not left to age out over `MAX_AGE`.
            withdraw_undesired(
                &mut dest_lsdb,
                local_router_id,
                lsa::LSA_TYPE_NETWORK_SUMMARY,
                &network_ids,
            );
            withdraw_undesired(
                &mut dest_lsdb,
                local_router_id,
                lsa::LSA_TYPE_ASBR_SUMMARY,
                &asbr_ids,
            );
        }
    }

    /// Applies one `OspfRequest::RedistributeRoutes` update (`Full`/`Add`/
    /// `Remove`, pushed continuously by the owning `nos-ribd` instance) to
    /// the raw redistributed-prefix set. This is `OSPFv2` (IPv4-only,
    /// `Ipv4Addr` throughout this crate); `RedistributedRoute.prefix` is a
    /// dual-stack `IpNet` shared with BGP's own redistribution wire type, so
    /// an `IpNet::V6` entry is skipped with a `warn!` rather than stored or
    /// panicked on.
    pub async fn apply_redistribute_update(&self, update: RedistributeUpdate) {
        let mut raw = self.redistribute_raw.lock().await;
        match update {
            RedistributeUpdate::Full(routes) => {
                raw.clear();
                for route in routes {
                    insert_redistributed_prefix(&mut raw, route.prefix);
                }
            }
            RedistributeUpdate::Add(route) => {
                insert_redistributed_prefix(&mut raw, route.prefix);
            }
            RedistributeUpdate::Remove(prefix) => match prefix {
                IpNet::V4(v4) => {
                    raw.remove(&v4);
                }
                IpNet::V6(_) => {}
            },
        }
    }

    /// Re-filters every raw redistributed prefix through `policy`, storing
    /// the surviving set into `redistribute_filtered`. Called unconditionally
    /// on every resync from `reconcile.rs` (mirrors `bgp::BgpRib::
    /// set_redistribute_policy`'s "called unconditionally, re-filters
    /// eagerly" contract, so a policy edit takes effect promptly rather than
    /// waiting on the next raw update).
    pub async fn set_redistribute_policy(&self, policy: Arc<CompiledPolicy>) {
        let raw = self.redistribute_raw.lock().await.clone();
        let filtered: HashSet<Ipv4Net> = raw
            .into_iter()
            .filter(|&prefix| passes_redistribute_policy(prefix, &policy))
            .collect();
        *self.redistribute_filtered.lock().await = filtered;
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
            // A fresh boot count per (re)start keeps RFC 7474 sequence numbers
            // increasing across link restarts inside one process too.
            let boot_count = if cfg.auth.is_extended() {
                self.boots.next()
            } else {
                0
            };
            let (commands, commands_rx) = mpsc::unbounded_channel();
            let link_local_lsdb = Arc::new(Mutex::new(Lsdb::with_notify(Arc::clone(
                &self.route_changed,
            ))));
            let task = tokio::spawn(run(
                (self.opener)(&cfg),
                cfg.clone(),
                local_router_id,
                lsdb,
                Arc::clone(&link_local_lsdb),
                status_tx,
                self.dbd_max_headers,
                boot_count,
                commands_rx,
            ));
            links.insert(
                key,
                LinkEntry {
                    config: cfg,
                    task,
                    status: status_rx,
                    commands,
                    link_local_lsdb,
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

    /// Every link's type-9 store, with the link's area.
    async fn link_local_lsdbs(&self) -> Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> {
        self.links
            .lock()
            .await
            .values()
            .map(|e| (e.config.area_id, Arc::clone(&e.link_local_lsdb)))
            .collect()
    }

    /// Every installed LSA's header, across every area and every link's
    /// type-9 store (listed under the link's area), for `server.rs`'s
    /// `OspfRequest::GetDatabase` handler — backs `nos-cli`'s
    /// `show ospf database`.
    pub async fn database_summaries(&self) -> Vec<LsaSummary> {
        let mut result = Vec::new();
        let mut stores: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(area_id, lsdb)| (*area_id, Arc::clone(lsdb)))
            .collect();
        stores.extend(self.link_local_lsdbs().await);
        for (area_id, lsdb) in &stores {
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

    /// Woken (one stored permit) whenever any LSDB changes, so a consumer of
    /// `compute_routes` need not poll.
    pub fn route_changed(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.route_changed)
    }

    /// Runs `crate::spf::compute` against every area's current LSDB and
    /// merges the results into one route set, for `crate::rib_push_client`.
    /// A router attached to 2+ areas (an ABR, see `originate_summary_lsas`)
    /// can now legitimately compute the same destination prefix from more
    /// than one area's own LSDB (e.g. via a summarized inter-area path in
    /// one area and a direct path in another) — keeps whichever is cheaper,
    /// and unions the next hops of an equal-cost pair (`spf::merge_equal`),
    /// the same tie-break `spf::insert_best` already applies within one
    /// area. Empty if `router_id` hasn't been set yet (before this
    /// instance's first `reconcile` call).
    pub async fn compute_routes(&self) -> Vec<spf::RouteEntry> {
        let Some(router_id) = *self.router_id.lock().await else {
            return Vec::new();
        };
        let areas: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(id, lsdb)| (*id, Arc::clone(lsdb)))
            .collect();
        let mut merged: HashMap<Ipv4Net, spf::RouteEntry> = HashMap::new();
        for (area_id, lsdb) in areas {
            let mut lsas = lsdb.lock().await.all();
            // A Type-5 still held from before the area turned stub, or a
            // Type-7 from before it stopped being an NSSA (until it ages
            // out), is not a route there.
            let area = self.area(area_id).await;
            lsas.retain(|l| lsa::in_area_scope(l.header.lsa_type, area.stub, area.nssa));
            let state = (
                spf::host_bit_honoured(&lsas),
                spf::h_bit_routers(&lsas).len(),
            );
            if self.host_bit_state.lock().await.insert(area_id, state) != Some(state) {
                info!(area = %area_id, honoured = state.0, host_routers = state.1, "ospf host-bit state changed");
            }
            for entry in spf::compute(router_id, &lsas) {
                match merged.get_mut(&entry.prefix) {
                    None => {
                        merged.insert(entry.prefix, entry);
                    }
                    Some(existing) if entry.metric < existing.metric => *existing = entry,
                    Some(existing) if entry.metric == existing.metric => {
                        spf::merge_equal(existing, entry);
                    }
                    Some(_) => {}
                }
            }
        }
        // RFC 2328 §3.5: a discard route per active advertised range, so
        // traffic to an unused part of it is dropped here rather than looping
        // on a covering route — unless SPF has a real route for exactly it.
        for (&range, &metric) in self.active_ranges.lock().await.iter() {
            merged
                .entry(range)
                .or_insert_with(|| spf::RouteEntry::discard(range, metric));
        }
        merged.into_values().collect()
    }

    /// RFC 2328 §14.1, in bulk: prematurely ages every LSA this router
    /// originated, in every area. Returns how many were withdrawn.
    async fn withdraw_all_self_originated(&self) -> usize {
        let Some(router_id) = *self.router_id.lock().await else {
            return 0;
        };
        let areas: Vec<Arc<Mutex<Lsdb>>> = self.lsdbs.lock().await.values().cloned().collect();
        let mut withdrawn = 0;
        for lsdb in areas {
            let mut lsdb = lsdb.lock().await;
            for header in lsdb.headers() {
                if header.advertising_router == router_id
                    && withdraw_self_originated(&mut lsdb, &header.key())
                {
                    withdrawn += 1;
                }
            }
        }
        withdrawn
    }

    /// RFC 6987 on-shutdown: re-originates the Router-LSAs with max-metric
    /// transit links, kicks them out and holds `on_shutdown` seconds so
    /// neighbors move traffic away before the flush. Skipped when off, when
    /// max-metric is already active (neighbors already avoid us), and when
    /// `MinLSInterval` holds the Router-LSA back (it changed under 5s ago).
    async fn max_metric_on_shutdown(&self) {
        let hold = self.max_metric_state().on_shutdown;
        if hold == 0 || self.max_metric_active() {
            return;
        }
        let Some(router_id) = *self.router_id.lock().await else {
            return;
        };
        if !self.originate_router_lsas_with(router_id, true).await {
            info!("ospf stub router on-shutdown skipped, router-lsa unchanged or changed too recently");
            return;
        }
        info!(
            active = true,
            reason = "on-shutdown",
            "ospf stub router max-metric changed"
        );
        self.flood_now().await;
        tokio::time::sleep(Duration::from_secs(u64::from(hold)).min(MAX_METRIC_SHUTDOWN_HOLD_MAX))
            .await;
    }

    /// The configured RFC 3623 grace period, seconds (0 = off).
    pub fn grace_period(&self) -> u16 {
        self.grace_period.load(Ordering::Relaxed)
    }

    /// RFC 3623: when graceful restart is configured, has every link send a
    /// Grace-LSA to its `Full` neighbors (twice) and waits for them to go
    /// out, then makes `shutdown` keep this router's LSAs. Called on a
    /// planned restart (SIGTERM) only, before `shutdown`.
    pub async fn announce_graceful_restart(&self) {
        let grace_period = self.grace_period.load(Ordering::Relaxed);
        if grace_period == 0 {
            return;
        }
        info!(
            grace_period,
            "ospf graceful restart: announcing grace period before shutdown"
        );
        self.restarting.store(true, Ordering::Relaxed);
        for _ in 0..2 {
            self.send_to_links(LinkCommand::Grace(u32::from(grace_period)))
                .await;
            tokio::time::sleep(GRACE_SEND_WINDOW).await;
        }
    }

    async fn send_to_links(&self, command: LinkCommand) {
        for entry in self.links.lock().await.values() {
            let _ = entry.commands.send(command);
        }
    }

    /// Has every link resend its LSDB to its `Full` neighbors now.
    async fn flood_now(&self) {
        self.send_to_links(LinkCommand::FloodNow).await;
    }

    /// Graceful shutdown: flushes every self-originated LSA (RFC 2328
    /// §14.1) — unless a graceful restart was announced, which must keep
    /// them (RFC 3623 §2) — and keeps the link tasks alive for `PREMATURE_AGE_FLOOD_WINDOW`
    /// so their periodic resend carries the `MaxAge` copies to every neighbor
    /// — which then drops this router's routes at once instead of only when
    /// its LSAs age out an hour later — then aborts every link task. Called
    /// once when `crate::reconcile::run`'s loop exits on shutdown.
    pub async fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::Relaxed);
        let restarting = self.restarting.load(Ordering::Relaxed);
        if !restarting {
            self.max_metric_on_shutdown().await;
        }
        let withdrawn = if restarting {
            0
        } else {
            self.withdraw_all_self_originated().await
        };
        if withdrawn > 0 {
            info!(
                withdrawn,
                "ospf flushing self-originated lsas before shutdown"
            );
            self.flood_now().await;
            tokio::time::sleep(PREMATURE_AGE_FLOOD_WINDOW).await;
        }
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
        if entry.config.network_type != NetworkType::PointToPoint {
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

/// This link's own subnet mask — RFC 2328 §10.5's `NetworkMask`, both sent
/// (`send_hello`) and checked against on receipt (`handle_hello`, skipped on
/// point-to-point). `UNSPECIFIED` if `local_prefix_len` is somehow invalid,
/// same fallback as `local_subnet`.
fn local_netmask(cfg: &LinkConfig) -> Ipv4Addr {
    local_subnet(cfg).map_or(Ipv4Addr::UNSPECIFIED, |n| n.netmask())
}

/// The DR's Network-LSA mask: the segment's own, or RFC 6860 §2.2.2.1's
/// all-ones mask hiding it (the LS-ID stays the DR's address).
fn network_lsa_mask(cfg: &LinkConfig, prefix_suppression: bool) -> Ipv4Addr {
    if prefix_suppression {
        Ipv4Addr::BROADCAST
    } else {
        local_netmask(cfg)
    }
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
/// route back to your own subnet via the neighbor. RFC 6860 §2.1: with
/// `prefix_suppression` the type-3 stub is omitted, hiding the transit-only
/// subnet. RFC 6987 §2: with `max_metric` (a stub router) the type-1 and
/// type-2 links cost `MAX_LINK_METRIC`; the type-3 stubs keep their cost.
/// Pure — takes an already-gathered snapshot so it stays independently
/// unit-testable.
fn router_lsa_links(
    local_router_id: Ipv4Addr,
    links: &[(LinkConfig, LinkStatus)],
    prefix_suppression: bool,
    max_metric: bool,
) -> Vec<RouterLink> {
    let mut result = Vec::new();
    for (cfg, status) in links {
        let transit_cost = if max_metric {
            lsa::MAX_LINK_METRIC
        } else {
            cfg.cost
        };
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
                        metric: transit_cost,
                    });
                }
                if let Some(subnet) = local_subnet(cfg).filter(|_| !prefix_suppression) {
                    result.push(RouterLink {
                        link_id: subnet.network(),
                        link_data: subnet.netmask(),
                        link_type: LINK_TYPE_STUB_NETWORK,
                        metric: cfg.cost,
                    });
                }
            }
            NetworkType::PointToMultipoint => {
                // RFC 2328 §12.4.1.4: a type-1 link per fully adjacent
                // neighbor, plus one /32 stub for our own address (not the
                // subnet's — the neighbors needn't share one).
                for (neighbor_id, n) in &status.neighbors {
                    if n.state == NeighborState::Full || n.grace_deadline.is_some() {
                        result.push(RouterLink {
                            link_id: *neighbor_id,
                            link_data: cfg.local_addr,
                            link_type: LINK_TYPE_POINT_TO_POINT,
                            metric: transit_cost,
                        });
                    }
                }
                if !prefix_suppression {
                    result.push(RouterLink {
                        link_id: cfg.local_addr,
                        link_data: Ipv4Addr::BROADCAST,
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
                    metric: transit_cost,
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
/// `ORIGINATION_INTERVAL` tick. Also reoriginates — bumping the sequence
/// number even with unchanged content — once the held instance's age has
/// reached RFC 2328 §14's `LS_REFRESH_TIME`, so a live self-originated LSA
/// never reaches `MAX_AGE` and gets locally flushed by `LinkManager::
/// age_lsdbs`.
fn install_self_originated(
    lsdb: &mut Lsdb,
    local_router_id: Ipv4Addr,
    lsa_type: u8,
    link_state_id: Ipv4Addr,
    body: LsaBody,
) -> bool {
    install_self_originated_with_options(lsdb, local_router_id, lsa_type, link_state_id, 0, body)
}

/// `install_self_originated` with header `options` (a Type-7's P-bit), which
/// count as content: a change re-originates. Returns whether a new instance
/// was installed (`false`: unchanged, or held back by `MinLSInterval`).
fn install_self_originated_with_options(
    lsdb: &mut Lsdb,
    local_router_id: Ipv4Addr,
    lsa_type: u8,
    link_state_id: Ipv4Addr,
    options: u8,
    body: LsaBody,
) -> bool {
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
        Some(e) if e.body == body && e.header.options == options && !needs_refresh => return false,
        // RFC 2328 §12.1.6: at `MaxSequenceNumber` the instance is flushed
        // (at that same sequence number — never the reserved 0x8000_0000 a
        // wrapping increment would produce) and re-originated at
        // `INITIAL_SEQUENCE_NUMBER` only once the flush has been flooded:
        // `Lsdb::age_and_evict` evicts it after `MAX_AGE_HOLD_TICKS`, and
        // the `None` arm below then takes over.
        Some(e) if e.header.sequence_number == lsa::MAX_SEQUENCE_NUMBER => {
            withdraw_self_originated(lsdb, &key);
            return false;
        }
        // RFC 2328 §12.4 / Appendix B `MinLSInterval`: changed content is
        // not re-originated until the held instance is that old — the next
        // `ORIGINATION_INTERVAL` tick retries. `age` is the local clock
        // since origination (a neighbor's echo never supersedes it, see
        // `lsa::fill_checksum`), so no extra timestamp is needed.
        Some(e) if e.header.age < lsa::MIN_LS_INTERVAL => return false,
        Some(e) => e.header.sequence_number + 1,
        None => lsa::INITIAL_SEQUENCE_NUMBER,
    };
    let mut fresh = Lsa {
        header: LsaHeader {
            age: 0,
            options,
            lsa_type,
            link_state_id,
            advertising_router: local_router_id,
            sequence_number,
            checksum: 0,
            length: 0,
        },
        body,
    };
    // Held with its wire checksum, so a neighbor's echo of it is a duplicate
    // rather than "newer" — see `lsa::fill_checksum`.
    lsa::fill_checksum(&mut fresh);
    lsdb.install(fresh);
    info!(
        lsa_type, link_state_id = %link_state_id, advertising_router = %local_router_id,
        refreshed = needs_refresh,
        "ospf lsa originated"
    );
    true
}

/// RFC 2328 §14.1 premature aging: flushes this router's own `key` by
/// reinstalling it at `MAX_AGE` with its sequence number *unchanged*.
/// `lsa::is_newer` only reaches its `MaxAge` tie-break when sequence number and
/// checksum already tie — which they do here, the body being untouched and
/// the checksum excluding the age field — so every neighbor accepts the
/// flushed copy as newer and `flood_full_neighbors`' next resend carries it.
/// Not bumping is also what makes this usable at `MAX_SEQUENCE_NUMBER` (see
/// `install_self_originated`). No-op (returns `false`) if `key` isn't held
/// or is already at `MAX_AGE`.
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
        "ospf lsa prematurely aged"
    );
    true
}

/// RFC 2328 Appendix E: the Link State ID of each of one LSA type's
/// self-originated prefixes. Shortest mask first, a prefix takes its network
/// address, or else that address with its host bits set — the end state of
/// the RFC's own procedure, which re-originates the longer prefix when a
/// shorter one turns up. Recomputed every tick, and sorted so it never
/// churns. While a renumbered prefix's old ID is held back by
/// `MinLSInterval`, both IDs carry it; receivers truncate (`spf::net_from`)
/// and merge them.
fn assign_link_state_ids(prefixes: impl IntoIterator<Item = Ipv4Net>) -> Vec<(Ipv4Net, Ipv4Addr)> {
    let mut prefixes: Vec<Ipv4Net> = prefixes.into_iter().map(|p| p.trunc()).collect();
    prefixes.sort_unstable_by_key(|p| (p.prefix_len(), p.network()));
    prefixes.dedup();
    let mut taken = HashSet::new();
    prefixes
        .into_iter()
        .filter_map(|prefix| {
            let id = [prefix.network(), prefix.broadcast()]
                .into_iter()
                .find(|&id| taken.insert(id));
            if id.is_none() {
                // ponytail: both IDs taken (10.0.0.0/16 and /24, then the
                // host route 10.0.0.255/32): skipped, Appendix E doesn't
                // resolve it either. A smarter pick is a matching problem.
                warn!(prefix = %prefix, "ospf lsa link state id collision, not originating");
            }
            id.map(|id| (prefix, id))
        })
        .collect()
}

/// The inverse of an origination pass's `install_self_originated` loop:
/// withdraws every live self-originated LSA of `lsa_type` whose link-state
/// id isn't in `desired` — i.e. something this router advertised earlier
/// and no longer does.
fn withdraw_undesired(
    lsdb: &mut Lsdb,
    local_router_id: Ipv4Addr,
    lsa_type: u8,
    desired: &HashSet<Ipv4Addr>,
) {
    let stale: Vec<LsaKey> = lsdb
        .headers()
        .into_iter()
        .filter(|h| {
            h.advertising_router == local_router_id
                && h.lsa_type == lsa_type
                && h.age < lsa::MAX_AGE
                && !desired.contains(&h.link_state_id)
        })
        .map(|h| h.key())
        .collect();
    for key in stale {
        withdraw_self_originated(lsdb, &key);
    }
}

/// Inserts `prefix` into `raw` if it's IPv4 — see `LinkManager::
/// apply_redistribute_update`'s doc comment for why a v6 entry is skipped
/// rather than stored.
fn insert_redistributed_prefix(raw: &mut HashSet<Ipv4Net>, prefix: IpNet) {
    match prefix {
        IpNet::V4(v4) => {
            raw.insert(v4);
        }
        IpNet::V6(_) => {
            warn!(prefix = %prefix, "ospf redistribute update carried an ipv6 prefix, ignoring (ospfv2 is ipv4-only)");
        }
    }
}

/// Evaluates `prefix` against `policy` — the redistribute-policy adapter.
/// OSPF has no route type of its own to adapt (unlike `bgp::rib::
/// to_policy_input`, which converts a real `RibRoute`), so `nos_rpl::
/// BgpInput` is built inline with empty/default values: a redistribute
/// policy has no legitimate reason to reference `this.bgp.*` fields, so they
/// simply read as empty/zero, harmless for a script that only matches on
/// `this.prefix`.
fn passes_redistribute_policy(prefix: Ipv4Net, policy: &CompiledPolicy) -> bool {
    let input = nos_rpl::Input {
        prefix: IpNet::V4(prefix),
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
            mtu: 1500,
            mtu_ignore: false,
            auth: LinkAuthConfig::None,
            stub: false,
            nssa: false,
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
            last_heard: Instant::now(),
            address,
            adjacency: None,
            last_crypto_seq: HashMap::new(),
            grace_deadline: None,
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
        let links = router_lsa_links(Ipv4Addr::new(1, 1, 1, 1), &[(cfg, status)], false, false);
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
        let links = router_lsa_links(
            Ipv4Addr::new(1, 1, 1, 1),
            &[(cfg.clone(), status)],
            false,
            false,
        );
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
    fn router_lsa_links_max_metric_raises_transit_links_only() {
        // RFC 6987 §2: type-1/type-2 at MaxLinkMetric, type-3 keeps its cost.
        let mut p2p = link("eth0.0", 10);
        p2p.cost = 7;
        let mut p2p_status = LinkStatus::new(NetworkType::PointToPoint);
        p2p_status.neighbors.insert(
            Ipv4Addr::new(9, 9, 9, 10),
            neighbor_info(NeighborState::Full, Ipv4Addr::new(10, 0, 0, 2)),
        );
        let mut bcast = link("broadcast-domain:d", 10);
        bcast.network_type = NetworkType::Broadcast;
        bcast.local_addr = Ipv4Addr::new(10, 1, 0, 1);
        bcast.cost = 7;
        let mut bcast_status = LinkStatus::new(NetworkType::Broadcast);
        bcast_status.dr = Some(Ipv4Addr::new(1, 1, 1, 1));
        let links = router_lsa_links(
            Ipv4Addr::new(1, 1, 1, 1),
            &[(p2p, p2p_status), (bcast, bcast_status)],
            false,
            true,
        );
        let metric = |t| links.iter().find(|l| l.link_type == t).unwrap().metric;
        assert_eq!(links.len(), 3);
        assert_eq!(metric(LINK_TYPE_POINT_TO_POINT), lsa::MAX_LINK_METRIC);
        assert_eq!(metric(LINK_TYPE_TRANSIT_NETWORK), lsa::MAX_LINK_METRIC);
        assert_eq!(metric(LINK_TYPE_STUB_NETWORK), 7);
    }

    #[test]
    fn prefix_suppression_hides_the_p2p_stub_and_the_network_mask() {
        // RFC 6860 §2.1: only the type-1 link is left on a p2p link.
        let cfg = link("eth0.0", 10);
        let mut status = LinkStatus::new(NetworkType::PointToPoint);
        status.neighbors.insert(
            Ipv4Addr::new(9, 9, 9, 10),
            neighbor_info(NeighborState::Full, Ipv4Addr::new(10, 0, 0, 2)),
        );
        let links = router_lsa_links(
            Ipv4Addr::new(1, 1, 1, 1),
            &[(cfg.clone(), status)],
            true,
            false,
        );
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].link_type, LINK_TYPE_POINT_TO_POINT);

        // A broadcast link's transit entry is unaffected.
        let mut bcast = link("bd1", 10);
        bcast.network_type = NetworkType::Broadcast;
        let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
        let mut status = LinkStatus::new(NetworkType::Broadcast);
        status.interface_state = InterfaceState::Dr;
        status.dr = Some(local_router_id);
        let on = router_lsa_links(
            local_router_id,
            &[(bcast.clone(), status.clone())],
            true,
            false,
        );
        let off = router_lsa_links(local_router_id, &[(bcast, status)], false, false);
        assert_eq!(on, off);

        // §2.2.2.1: the DR's Network-LSA mask.
        assert_eq!(
            network_lsa_mask(&cfg, false),
            Ipv4Addr::new(255, 255, 255, 0)
        );
        assert_eq!(network_lsa_mask(&cfg, true), Ipv4Addr::BROADCAST);
    }

    #[test]
    fn router_lsa_links_skips_broadcast_link_with_no_dr_yet() {
        let mut cfg = link("bd1", 10);
        cfg.network_type = NetworkType::Broadcast;
        let status = LinkStatus::new(NetworkType::Broadcast);
        assert_eq!(
            router_lsa_links(Ipv4Addr::new(1, 1, 1, 1), &[(cfg, status)], false, false),
            []
        );
    }

    #[test]
    fn router_lsa_links_uses_own_address_when_self_is_dr() {
        let mut cfg = link("bd1", 10);
        cfg.network_type = NetworkType::Broadcast;
        let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
        let mut status = LinkStatus::new(NetworkType::Broadcast);
        status.interface_state = InterfaceState::Dr;
        status.dr = Some(local_router_id);
        let links = router_lsa_links(local_router_id, &[(cfg.clone(), status)], false, false);
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
        let links = router_lsa_links(local_router_id, &[(cfg, status)], false, false);
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

    #[test]
    fn install_self_originated_age_based_refresh_bumps_sequence_number_even_with_unchanged_body() {
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
        lsdb.age_and_evict(lsa::LS_REFRESH_TIME, &HashSet::new());

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
        let installed = lsdb.get(&key).unwrap();
        assert_eq!(
            installed.header.sequence_number,
            lsa::INITIAL_SEQUENCE_NUMBER + 1
        );
        assert_eq!(installed.header.age, 0);
    }

    #[tokio::test]
    async fn originate_router_lsas_includes_loopback_stub_for_area_with_no_live_link() {
        // Regression test for the area-union fix: an area with only a
        // loopback stub network and no live `LinkConfig` must still get a
        // Router-LSA originated for it.
        let manager = LinkManager::new(
            1,
            Some(exchange::DEFAULT_DBD_MAX_HEADERS),
            crate::boot::BootCounter::in_memory(),
        );
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

    /// RFC 2328 A.4.2 (#34): B while stubs sit in 2+ areas, E while a
    /// Type-5 is originated — each cleared again once that stops, even
    /// though `lsdbs` still holds the area that was left.
    #[tokio::test]
    async fn originate_router_lsas_sets_b_and_e_flags() {
        let manager = LinkManager::new(
            1,
            Some(exchange::DEFAULT_DBD_MAX_HEADERS),
            crate::boot::BootCounter::in_memory(),
        );
        let area0 = Ipv4Addr::UNSPECIFIED;
        let area1 = Ipv4Addr::new(0, 0, 0, 1);
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let stub0 = ("192.168.9.0/24".parse::<Ipv4Net>().unwrap(), 1);
        let stub1 = ("192.168.10.0/24".parse::<Ipv4Net>().unwrap(), 1);
        let key = LsaKey {
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: router_id,
            advertising_router: router_id,
        };
        // Originates, then reads the area's Router-LSA flags; ages every
        // area past MinLSInterval first so changed content isn't paced.
        let flags = |area: Ipv4Addr| {
            let manager = &manager;
            async move {
                for lsdb in manager.lsdbs.lock().await.values() {
                    lsdb.lock()
                        .await
                        .age_and_evict(lsa::MIN_LS_INTERVAL, &HashSet::new());
                }
                manager.originate_router_lsas(router_id).await;
                let lsdb = manager.lsdb_for(area).await;
                let lsa = lsdb.lock().await.get(&key).unwrap();
                let LsaBody::Router(body) = &lsa.body else {
                    panic!("expected router lsa")
                };
                body.flags
            }
        };

        manager
            .reconcile(Vec::new(), HashMap::from([(area0, vec![stub0])]), router_id)
            .await;
        assert_eq!(flags(area0).await, 0);

        manager
            .reconcile(
                Vec::new(),
                HashMap::from([(area0, vec![stub0]), (area1, vec![stub1])]),
                router_id,
            )
            .await;
        assert_eq!(flags(area0).await, lsa::ROUTER_FLAG_B);
        assert_eq!(flags(area1).await, lsa::ROUTER_FLAG_B);

        *manager.redistribute_filtered.lock().await = HashSet::from([stub1.0]);
        assert_eq!(flags(area0).await, lsa::ROUTER_FLAG_B | lsa::ROUTER_FLAG_E);

        *manager.redistribute_filtered.lock().await = HashSet::new();
        manager
            .reconcile(Vec::new(), HashMap::from([(area0, vec![stub0])]), router_id)
            .await;
        assert_eq!(flags(area0).await, 0);
        assert!(manager.lsdbs.lock().await.contains_key(&area1));
    }

    /// RFC 8770 §3: H in the Router-LSA of every area while set, stubs at
    /// their cost, and the router counts as max-metric (transit links at
    /// 0xFFFF — `router_lsa_links_max_metric_raises_transit_links_only`).
    #[tokio::test]
    async fn host_router_sets_the_h_bit_in_every_area() {
        let manager = LinkManager::new(
            1,
            Some(exchange::DEFAULT_DBD_MAX_HEADERS),
            crate::boot::BootCounter::in_memory(),
        );
        let (area0, area1) = (Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(0, 0, 0, 1));
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let stub0 = ("192.168.9.0/24".parse::<Ipv4Net>().unwrap(), 5);
        let stub1 = ("192.168.10.0/24".parse::<Ipv4Net>().unwrap(), 5);
        manager
            .reconcile(
                Vec::new(),
                HashMap::from([(area0, vec![stub0]), (area1, vec![stub1])]),
                router_id,
            )
            .await;
        let key = LsaKey {
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: router_id,
            advertising_router: router_id,
        };
        let held = |area: Ipv4Addr| {
            let manager = &manager;
            async move {
                for lsdb in manager.lsdbs.lock().await.values() {
                    lsdb.lock()
                        .await
                        .age_and_evict(lsa::MIN_LS_INTERVAL, &HashSet::new());
                }
                manager.originate_router_lsas(router_id).await;
                let lsa = manager.lsdb_for(area).await.lock().await.get(&key).unwrap();
                let LsaBody::Router(body) = &lsa.body else {
                    panic!("expected router lsa")
                };
                body.clone()
            }
        };
        assert!(!manager.max_metric_active());
        manager.set_host_router(true);
        assert!(manager.max_metric_active());
        for area in [area0, area1] {
            let body = held(area).await;
            assert_eq!(body.flags & lsa::ROUTER_FLAG_H, lsa::ROUTER_FLAG_H);
            assert_eq!(body.links[0].metric, 5);
        }
        manager.set_host_router(false);
        assert_eq!(held(area0).await.flags & lsa::ROUTER_FLAG_H, 0);
    }

    /// RFC 7770: one type-10 RI per area, GR helper always, GR capable only
    /// with a grace period; flushed from an area that was left.
    #[tokio::test]
    async fn originate_router_lsas_originates_router_info_per_area() {
        let manager = LinkManager::new(
            1,
            Some(exchange::DEFAULT_DBD_MAX_HEADERS),
            crate::boot::BootCounter::in_memory(),
        );
        let area0 = Ipv4Addr::UNSPECIFIED;
        let area1 = Ipv4Addr::new(0, 0, 0, 1);
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let stub0 = ("192.168.9.0/24".parse::<Ipv4Net>().unwrap(), 1);
        let stub1 = ("192.168.10.0/24".parse::<Ipv4Net>().unwrap(), 1);
        let key = LsaKey {
            lsa_type: lsa::LSA_TYPE_OPAQUE_AREA,
            link_state_id: lsa::ROUTER_INFO_LINK_STATE_ID,
            advertising_router: router_id,
        };
        let held = |area: Ipv4Addr| {
            let manager = &manager;
            async move {
                for lsdb in manager.lsdbs.lock().await.values() {
                    lsdb.lock()
                        .await
                        .age_and_evict(lsa::MIN_LS_INTERVAL, &HashSet::new());
                }
                manager.originate_router_lsas(router_id).await;
                let lsdb = manager.lsdb_for(area).await;
                let lsa = lsdb.lock().await.get(&key).unwrap();
                (lsa.header.age < lsa::MAX_AGE, lsa.body.clone())
            }
        };
        let body = |caps| (true, LsaBody::Opaque(lsa::encode_router_info(caps)));

        manager
            .reconcile(
                Vec::new(),
                HashMap::from([(area0, vec![stub0]), (area1, vec![stub1])]),
                router_id,
            )
            .await;
        // Helper and stub-router support are capabilities, always set.
        let always = lsa::RI_CAP_GR_HELPER | lsa::RI_CAP_STUB_ROUTER | lsa::RI_CAP_HOST_ROUTER;
        assert_eq!(held(area0).await, body(always));
        assert_eq!(held(area1).await, body(always));

        manager.set_graceful_restart(Some(120));
        let both = always | lsa::RI_CAP_GR_CAPABLE;
        assert_eq!(held(area0).await, body(both));

        manager
            .reconcile(Vec::new(), HashMap::from([(area0, vec![stub0])]), router_id)
            .await;
        assert_eq!(held(area0).await, body(both));
        assert!(!held(area1).await.0);
    }

    #[tokio::test]
    async fn originate_summary_lsas_installs_type3_into_every_other_area() {
        let manager = LinkManager::new(
            1,
            Some(exchange::DEFAULT_DBD_MAX_HEADERS),
            crate::boot::BootCounter::in_memory(),
        );
        let area0 = Ipv4Addr::UNSPECIFIED;
        let area1 = Ipv4Addr::new(0, 0, 0, 1);
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let net0: Ipv4Net = "192.168.10.0/24".parse().unwrap();
        let net1: Ipv4Net = "192.168.11.0/24".parse().unwrap();
        manager
            .reconcile(
                Vec::new(),
                HashMap::from([(area0, vec![(net0, 5)]), (area1, vec![(net1, 7)])]),
                router_id,
            )
            .await;
        manager.originate_router_lsas(router_id).await;
        manager.originate_summary_lsas(router_id).await;

        let lsdb0 = manager.lsdb_for(area0).await;
        let key0 = LsaKey {
            lsa_type: lsa::LSA_TYPE_NETWORK_SUMMARY,
            link_state_id: net1.network(),
            advertising_router: router_id,
        };
        let installed0 = lsdb0.lock().await.get(&key0).unwrap();
        let LsaBody::Summary(body0) = &installed0.body else {
            panic!("expected summary lsa")
        };
        assert_eq!(body0.metric, 7);

        let lsdb1 = manager.lsdb_for(area1).await;
        let key1 = LsaKey {
            lsa_type: lsa::LSA_TYPE_NETWORK_SUMMARY,
            link_state_id: net0.network(),
            advertising_router: router_id,
        };
        let installed1 = lsdb1.lock().await.get(&key1).unwrap();
        let LsaBody::Summary(body1) = &installed1.body else {
            panic!("expected summary lsa")
        };
        assert_eq!(body1.metric, 5);
    }

    fn router_key(router_id: Ipv4Addr) -> LsaKey {
        LsaKey {
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: router_id,
            advertising_router: router_id,
        }
    }

    fn router_body(flags: u8) -> LsaBody {
        LsaBody::Router(RouterLsaBody {
            flags,
            links: Vec::new(),
        })
    }

    #[test]
    fn withdraw_self_originated_sets_max_age_and_keeps_sequence_number() {
        let mut lsdb = Lsdb::new();
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let key = router_key(router_id);
        assert!(!withdraw_self_originated(&mut lsdb, &key));

        install_self_originated(
            &mut lsdb,
            router_id,
            lsa::LSA_TYPE_ROUTER,
            router_id,
            router_body(0),
        );
        lsdb.age_and_evict(lsa::MIN_LS_INTERVAL, &HashSet::new());
        install_self_originated(
            &mut lsdb,
            router_id,
            lsa::LSA_TYPE_ROUTER,
            router_id,
            router_body(1),
        );
        assert!(withdraw_self_originated(&mut lsdb, &key));
        let flushed = lsdb.get(&key).unwrap();
        assert_eq!(flushed.header.age, lsa::MAX_AGE);
        assert_eq!(
            flushed.header.sequence_number,
            lsa::INITIAL_SEQUENCE_NUMBER + 1
        );
        assert_eq!(flushed.body, router_body(1));
        // Already flushed: a no-op.
        assert!(!withdraw_self_originated(&mut lsdb, &key));
    }

    /// A neighbor's echo of a self-originated LSA (decoded from the wire, so
    /// with the real checksum) must be a duplicate of the held instance, not
    /// newer — otherwise it would supersede a prematurely aged one.
    #[test]
    fn self_originated_lsa_ties_with_its_own_wire_copy() {
        let mut lsdb = Lsdb::new();
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        install_self_originated(
            &mut lsdb,
            router_id,
            lsa::LSA_TYPE_ROUTER,
            router_id,
            router_body(0),
        );
        let held = lsdb.get(&router_key(router_id)).unwrap();
        let echo = lsa::decode_lsa(&lsa::encode_lsa(&held)).unwrap();
        assert_ne!(held.header.checksum, 0);
        assert_eq!(
            lsa::is_newer(&echo.header, &held.header),
            std::cmp::Ordering::Equal
        );
        assert_eq!(lsdb.install(echo), crate::lsdb::InstallOutcome::Rejected);
    }

    /// Issue #32 / RFC 2328 §12.1.6: at `MaxSequenceNumber` the LSA is
    /// flushed at that number (never `0x8000_0000`), held for the flood window,
    /// then re-originated at `InitialSequenceNumber`.
    #[test]
    fn install_self_originated_at_max_sequence_flushes_then_restarts_at_initial() {
        let mut lsdb = Lsdb::new();
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let key = router_key(router_id);
        lsdb.install(Lsa {
            header: LsaHeader {
                age: 100,
                options: 0,
                lsa_type: lsa::LSA_TYPE_ROUTER,
                link_state_id: router_id,
                advertising_router: router_id,
                sequence_number: lsa::MAX_SEQUENCE_NUMBER,
                checksum: 0,
                length: 0,
            },
            body: router_body(0),
        });

        install_self_originated(
            &mut lsdb,
            router_id,
            lsa::LSA_TYPE_ROUTER,
            router_id,
            router_body(1),
        );
        let flushed = lsdb.get(&key).unwrap();
        assert_eq!(flushed.header.sequence_number, lsa::MAX_SEQUENCE_NUMBER);
        assert_eq!(flushed.header.age, lsa::MAX_AGE);
        assert_eq!(flushed.body, router_body(0));

        // Deferred while the flushed copy is still held.
        for _ in 0..crate::lsdb::MAX_AGE_HOLD_TICKS - 1 {
            assert_eq!(lsdb.age_and_evict(1, &HashSet::new()), []);
            install_self_originated(
                &mut lsdb,
                router_id,
                lsa::LSA_TYPE_ROUTER,
                router_id,
                router_body(1),
            );
            assert_eq!(
                lsdb.get(&key).unwrap().header.sequence_number,
                lsa::MAX_SEQUENCE_NUMBER
            );
        }
        assert_eq!(lsdb.age_and_evict(1, &HashSet::new()), vec![key]);

        install_self_originated(
            &mut lsdb,
            router_id,
            lsa::LSA_TYPE_ROUTER,
            router_id,
            router_body(1),
        );
        let fresh = lsdb.get(&key).unwrap();
        assert_eq!(fresh.header.sequence_number, lsa::INITIAL_SEQUENCE_NUMBER);
        assert_eq!(fresh.header.age, 0);
        assert_eq!(fresh.body, router_body(1));
    }

    #[tokio::test]
    async fn originate_as_external_lsas_withdraws_a_prefix_no_longer_redistributed() {
        let manager = LinkManager::new(
            1,
            Some(exchange::DEFAULT_DBD_MAX_HEADERS),
            crate::boot::BootCounter::in_memory(),
        );
        let area = Ipv4Addr::UNSPECIFIED;
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let kept: Ipv4Net = "192.0.2.0/24".parse().unwrap();
        let dropped: Ipv4Net = "198.51.100.0/24".parse().unwrap();
        manager.lsdb_for(area).await;
        *manager.redistribute_filtered.lock().await = HashSet::from([kept, dropped]);
        manager.originate_as_external_lsas(router_id).await;
        *manager.redistribute_filtered.lock().await = HashSet::from([kept]);
        manager.originate_as_external_lsas(router_id).await;

        let lsdb = manager.lsdb_for(area).await;
        let lsdb = lsdb.lock().await;
        let key = |p: Ipv4Net| LsaKey {
            lsa_type: lsa::LSA_TYPE_AS_EXTERNAL,
            link_state_id: p.network(),
            advertising_router: router_id,
        };
        let flushed = lsdb.get(&key(dropped)).unwrap();
        assert_eq!(flushed.header.age, lsa::MAX_AGE);
        assert_eq!(flushed.header.sequence_number, lsa::INITIAL_SEQUENCE_NUMBER);
        let live = lsdb.get(&key(kept)).unwrap();
        assert_eq!(live.header.age, 0);
        assert_eq!(live.header.sequence_number, lsa::INITIAL_SEQUENCE_NUMBER);
    }

    fn ids(prefixes: &[&str]) -> Vec<(String, Ipv4Addr)> {
        assign_link_state_ids(prefixes.iter().map(|p| p.parse::<Ipv4Net>().unwrap()))
            .into_iter()
            .map(|(p, id)| (p.to_string(), id))
            .collect()
    }

    /// RFC 2328 Appendix E: the shortest mask keeps the network address, a
    /// longer one with the same address gets its host bits set.
    #[test]
    fn assign_link_state_ids_follows_appendix_e() {
        let expected = vec![
            ("192.0.2.128/25".to_string(), Ipv4Addr::new(192, 0, 2, 128)),
            ("192.0.2.128/26".to_string(), Ipv4Addr::new(192, 0, 2, 191)),
        ];
        assert_eq!(ids(&["192.0.2.128/25", "192.0.2.128/26"]), expected);
        assert_eq!(ids(&["192.0.2.128/26", "192.0.2.128/25"]), expected);
        assert_eq!(
            ids(&["0.0.0.0/8", "0.0.0.0/0"]),
            vec![
                ("0.0.0.0/0".to_string(), Ipv4Addr::UNSPECIFIED),
                ("0.0.0.0/8".to_string(), Ipv4Addr::new(0, 255, 255, 255)),
            ]
        );
        // Both IDs of the /32 are taken: skipped.
        assert_eq!(
            ids(&["10.0.0.255/32", "10.0.0.0/24", "10.0.0.0/16"]),
            vec![
                ("10.0.0.0/16".to_string(), Ipv4Addr::new(10, 0, 0, 0)),
                ("10.0.0.0/24".to_string(), Ipv4Addr::new(10, 0, 0, 255)),
            ]
        );
        assert_eq!(
            ids(&["198.51.100.0/24", "192.0.2.0/24"]),
            vec![
                ("192.0.2.0/24".to_string(), Ipv4Addr::new(192, 0, 2, 0)),
                (
                    "198.51.100.0/24".to_string(),
                    Ipv4Addr::new(198, 51, 100, 0)
                ),
            ]
        );
    }

    fn mask_at(lsdb: &Lsdb, lsa_type: u8, id: Ipv4Addr, router_id: Ipv4Addr) -> (Ipv4Addr, u16) {
        let lsa = lsdb
            .get(&LsaKey {
                lsa_type,
                link_state_id: id,
                advertising_router: router_id,
            })
            .unwrap_or_else(|| panic!("no type {lsa_type} lsa at {id}"));
        let mask = match &lsa.body {
            LsaBody::AsExternal(e) => e.network_mask,
            LsaBody::Summary(s) => s.network_mask,
            other => panic!("unexpected body {other:?}"),
        };
        (mask, lsa.header.age)
    }

    /// Two overlapping redistributed prefixes are two Type-5s (Appendix E);
    /// once the shorter one goes, the longer one moves back to the network
    /// address and its host-bits ID is flushed.
    #[tokio::test]
    async fn overlapping_redistributed_prefixes_get_distinct_type5s() {
        let manager = LinkManager::new(
            1,
            Some(exchange::DEFAULT_DBD_MAX_HEADERS),
            crate::boot::BootCounter::in_memory(),
        );
        let area = Ipv4Addr::UNSPECIFIED;
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let wide: Ipv4Net = "192.0.2.128/25".parse().unwrap();
        let narrow: Ipv4Net = "192.0.2.128/26".parse().unwrap();
        let (low, high) = (Ipv4Addr::new(192, 0, 2, 128), Ipv4Addr::new(192, 0, 2, 191));
        manager.lsdb_for(area).await;
        *manager.redistribute_filtered.lock().await = HashSet::from([wide, narrow]);
        manager.originate_as_external_lsas(router_id).await;
        {
            let lsdb = manager.lsdb_for(area).await;
            let lsdb = lsdb.lock().await;
            let t5 = lsa::LSA_TYPE_AS_EXTERNAL;
            assert_eq!(mask_at(&lsdb, t5, low, router_id), (wide.netmask(), 0));
            assert_eq!(mask_at(&lsdb, t5, high, router_id), (narrow.netmask(), 0));
        }

        *manager.redistribute_filtered.lock().await = HashSet::from([narrow]);
        // Past `MinLSInterval`, so `.128` may change content.
        manager
            .lsdb_for(area)
            .await
            .lock()
            .await
            .age_and_evict(lsa::MIN_LS_INTERVAL, &HashSet::new());
        manager.originate_as_external_lsas(router_id).await;
        let lsdb = manager.lsdb_for(area).await;
        let lsdb = lsdb.lock().await;
        let t5 = lsa::LSA_TYPE_AS_EXTERNAL;
        assert_eq!(mask_at(&lsdb, t5, low, router_id), (narrow.netmask(), 0));
        assert_eq!(
            mask_at(&lsdb, t5, high, router_id),
            (narrow.netmask(), lsa::MAX_AGE)
        );
    }

    #[tokio::test]
    async fn overlapping_redistributed_prefixes_get_distinct_type7s_in_an_nssa() {
        let manager = LinkManager::new(
            1,
            Some(exchange::DEFAULT_DBD_MAX_HEADERS),
            crate::boot::BootCounter::in_memory(),
        );
        let area = Ipv4Addr::new(0, 0, 0, 1);
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let wide: Ipv4Net = "192.0.2.128/25".parse().unwrap();
        let narrow: Ipv4Net = "192.0.2.128/26".parse().unwrap();
        manager
            .set_area_settings(HashMap::from([(
                area,
                AreaSettings {
                    stub: true,
                    nssa: true,
                    import_summaries: true,
                    ..AreaSettings::default()
                },
            )]))
            .await;
        manager.lsdb_for(area).await;
        *manager.redistribute_filtered.lock().await = HashSet::from([wide, narrow]);
        manager.originate_as_external_lsas(router_id).await;
        let lsdb = manager.lsdb_for(area).await;
        let lsdb = lsdb.lock().await;
        let t7 = lsa::LSA_TYPE_NSSA_EXTERNAL;
        let id = |d| Ipv4Addr::new(192, 0, 2, d);
        assert_eq!(mask_at(&lsdb, t7, id(128), router_id).0, wide.netmask());
        assert_eq!(mask_at(&lsdb, t7, id(191), router_id).0, narrow.netmask());
    }

    /// Overlapping intra-area stubs in area 0 become two Type-3s in area 1.
    #[tokio::test]
    async fn overlapping_intra_area_prefixes_get_distinct_type3s() {
        let manager = LinkManager::new(
            1,
            Some(exchange::DEFAULT_DBD_MAX_HEADERS),
            crate::boot::BootCounter::in_memory(),
        );
        let area0 = Ipv4Addr::UNSPECIFIED;
        let area1 = Ipv4Addr::new(0, 0, 0, 1);
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let wide: Ipv4Net = "10.1.0.0/16".parse().unwrap();
        let narrow: Ipv4Net = "10.1.0.0/24".parse().unwrap();
        let net1: Ipv4Net = "192.168.11.0/24".parse().unwrap();
        manager
            .reconcile(
                Vec::new(),
                HashMap::from([
                    (area0, vec![(wide, 5), (narrow, 6)]),
                    (area1, vec![(net1, 7)]),
                ]),
                router_id,
            )
            .await;
        manager.originate_router_lsas(router_id).await;
        manager.originate_summary_lsas(router_id).await;

        let lsdb1 = manager.lsdb_for(area1).await;
        let lsdb1 = lsdb1.lock().await;
        let t3 = lsa::LSA_TYPE_NETWORK_SUMMARY;
        assert_eq!(
            mask_at(&lsdb1, t3, Ipv4Addr::new(10, 1, 0, 0), router_id).0,
            wide.netmask()
        );
        assert_eq!(
            mask_at(&lsdb1, t3, Ipv4Addr::new(10, 1, 0, 255), router_id).0,
            narrow.netmask()
        );
    }

    #[tokio::test]
    async fn leaving_an_area_withdraws_its_router_lsa_and_the_summaries_of_it() {
        let manager = LinkManager::new(
            1,
            Some(exchange::DEFAULT_DBD_MAX_HEADERS),
            crate::boot::BootCounter::in_memory(),
        );
        let area0 = Ipv4Addr::UNSPECIFIED;
        let area1 = Ipv4Addr::new(0, 0, 0, 1);
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let net0: Ipv4Net = "192.168.10.0/24".parse().unwrap();
        let net1: Ipv4Net = "192.168.11.0/24".parse().unwrap();
        manager
            .reconcile(
                Vec::new(),
                HashMap::from([(area0, vec![(net0, 5)]), (area1, vec![(net1, 7)])]),
                router_id,
            )
            .await;
        manager.originate_router_lsas(router_id).await;
        manager.originate_summary_lsas(router_id).await;

        // The area1 loopback goes away: area1 keeps its (now empty) LSDB.
        manager
            .reconcile(
                Vec::new(),
                HashMap::from([(area0, vec![(net0, 5)])]),
                router_id,
            )
            .await;
        manager.originate_router_lsas(router_id).await;
        manager.originate_summary_lsas(router_id).await;

        let lsdb1 = manager.lsdb_for(area1).await;
        assert_eq!(
            lsdb1
                .lock()
                .await
                .get(&router_key(router_id))
                .unwrap()
                .header
                .age,
            lsa::MAX_AGE
        );
        let lsdb0 = manager.lsdb_for(area0).await;
        let lsdb0 = lsdb0.lock().await;
        let summary = lsdb0
            .get(&LsaKey {
                lsa_type: lsa::LSA_TYPE_NETWORK_SUMMARY,
                link_state_id: net1.network(),
                advertising_router: router_id,
            })
            .unwrap();
        assert_eq!(summary.header.age, lsa::MAX_AGE);
        assert_eq!(summary.header.sequence_number, lsa::INITIAL_SEQUENCE_NUMBER);
        assert_eq!(lsdb0.get(&router_key(router_id)).unwrap().header.age, 0);
    }

    #[tokio::test]
    async fn withdraw_all_self_originated_flushes_every_area() {
        let manager = LinkManager::new(
            1,
            Some(exchange::DEFAULT_DBD_MAX_HEADERS),
            crate::boot::BootCounter::in_memory(),
        );
        let area0 = Ipv4Addr::UNSPECIFIED;
        let area1 = Ipv4Addr::new(0, 0, 0, 1);
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let net0: Ipv4Net = "192.168.10.0/24".parse().unwrap();
        let net1: Ipv4Net = "192.168.11.0/24".parse().unwrap();
        manager
            .reconcile(
                Vec::new(),
                HashMap::from([(area0, vec![(net0, 5)]), (area1, vec![(net1, 7)])]),
                router_id,
            )
            .await;
        manager.originate_router_lsas(router_id).await;
        manager.originate_summary_lsas(router_id).await;

        // A Router-LSA, an RI LSA and a Type-3 per area.
        assert_eq!(manager.withdraw_all_self_originated().await, 6);
        for area in [area0, area1] {
            let lsdb = manager.lsdb_for(area).await;
            for header in lsdb.lock().await.headers() {
                assert_eq!(header.advertising_router, router_id);
                assert_eq!(header.age, lsa::MAX_AGE, "{header:?}");
            }
        }
        assert_eq!(manager.withdraw_all_self_originated().await, 0);
    }

    #[tokio::test]
    async fn originate_summary_lsas_is_a_noop_with_only_one_area() {
        let manager = LinkManager::new(
            1,
            Some(exchange::DEFAULT_DBD_MAX_HEADERS),
            crate::boot::BootCounter::in_memory(),
        );
        let area = Ipv4Addr::UNSPECIFIED;
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let net: Ipv4Net = "192.168.12.0/24".parse().unwrap();
        manager
            .reconcile(
                Vec::new(),
                HashMap::from([(area, vec![(net, 5)])]),
                router_id,
            )
            .await;
        manager.originate_router_lsas(router_id).await;
        manager.originate_summary_lsas(router_id).await;

        let lsdb = manager.lsdb_for(area).await;
        let has_summary = lsdb
            .lock()
            .await
            .all()
            .iter()
            .any(|l| l.header.lsa_type == lsa::LSA_TYPE_NETWORK_SUMMARY);
        assert!(!has_summary);
    }

    #[tokio::test]
    async fn originate_summary_lsas_installs_type4_for_reachable_asbr() {
        let manager = LinkManager::new(
            1,
            Some(exchange::DEFAULT_DBD_MAX_HEADERS),
            crate::boot::BootCounter::in_memory(),
        );
        let area0 = Ipv4Addr::UNSPECIFIED;
        let area1 = Ipv4Addr::new(0, 0, 0, 1);
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let asbr = Ipv4Addr::new(2, 2, 2, 2);

        let lsdb0 = manager.lsdb_for(area0).await;
        lsdb0.lock().await.install(Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: lsa::LSA_TYPE_ROUTER,
                link_state_id: router_id,
                advertising_router: router_id,
                sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsaBody {
                flags: 0,
                links: vec![RouterLink {
                    link_id: asbr,
                    link_data: Ipv4Addr::new(10, 0, 0, 1),
                    link_type: LINK_TYPE_POINT_TO_POINT,
                    metric: 5,
                }],
            }),
        });
        lsdb0.lock().await.install(Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: lsa::LSA_TYPE_ROUTER,
                link_state_id: asbr,
                advertising_router: asbr,
                sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsaBody {
                flags: 0,
                links: vec![RouterLink {
                    link_id: router_id,
                    link_data: Ipv4Addr::new(10, 0, 0, 2),
                    link_type: LINK_TYPE_POINT_TO_POINT,
                    metric: 5,
                }],
            }),
        });
        lsdb0.lock().await.install(Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: lsa::LSA_TYPE_AS_EXTERNAL,
                link_state_id: Ipv4Addr::new(198, 51, 100, 0),
                advertising_router: asbr,
                sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::AsExternal(AsExternalLsaBody {
                network_mask: Ipv4Addr::new(255, 255, 255, 0),
                metric: 0,
                forwarding_address: Ipv4Addr::UNSPECIFIED,
                external_route_tag: 0,
            }),
        });
        // Make area1 exist (empty) so this router is a real 2-area ABR.
        manager.lsdb_for(area1).await;

        manager.originate_summary_lsas(router_id).await;

        let lsdb1 = manager.lsdb_for(area1).await;
        let key = LsaKey {
            lsa_type: lsa::LSA_TYPE_ASBR_SUMMARY,
            link_state_id: asbr,
            advertising_router: router_id,
        };
        let installed = lsdb1.lock().await.get(&key).unwrap();
        let LsaBody::Summary(body) = &installed.body else {
            panic!("expected summary lsa")
        };
        assert_eq!(body.metric, 5);
    }

    #[tokio::test]
    async fn compute_routes_keeps_cheaper_of_two_areas_computed_route_to_same_prefix() {
        fn router_lsa(id: Ipv4Addr, link: RouterLink) -> Lsa {
            Lsa {
                header: LsaHeader {
                    age: 0,
                    options: 0,
                    lsa_type: lsa::LSA_TYPE_ROUTER,
                    link_state_id: id,
                    advertising_router: id,
                    sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
                    checksum: 0,
                    length: 0,
                },
                body: LsaBody::Router(RouterLsaBody {
                    flags: 0,
                    links: vec![link],
                }),
            }
        }

        let manager = LinkManager::new(
            1,
            Some(exchange::DEFAULT_DBD_MAX_HEADERS),
            crate::boot::BootCounter::in_memory(),
        );
        let area0 = Ipv4Addr::UNSPECIFIED;
        let area1 = Ipv4Addr::new(0, 0, 0, 1);
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let w = Ipv4Addr::new(2, 2, 2, 2);
        let v = Ipv4Addr::new(3, 3, 3, 3);
        let prefix_net = Ipv4Addr::new(192, 168, 20, 0);
        let mask = Ipv4Addr::new(255, 255, 255, 0);

        // Area 0: root -> w (cost 3), w advertises the stub at cost 10. Total 13.
        let lsdb0 = manager.lsdb_for(area0).await;
        lsdb0.lock().await.install(router_lsa(
            router_id,
            RouterLink {
                link_id: w,
                link_data: Ipv4Addr::new(10, 0, 0, 1),
                link_type: LINK_TYPE_POINT_TO_POINT,
                metric: 3,
            },
        ));
        lsdb0.lock().await.install(Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: lsa::LSA_TYPE_ROUTER,
                link_state_id: w,
                advertising_router: w,
                sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsaBody {
                flags: 0,
                links: vec![
                    RouterLink {
                        link_id: router_id,
                        link_data: Ipv4Addr::new(10, 0, 0, 2),
                        link_type: LINK_TYPE_POINT_TO_POINT,
                        metric: 3,
                    },
                    RouterLink {
                        link_id: prefix_net,
                        link_data: mask,
                        link_type: LINK_TYPE_STUB_NETWORK,
                        metric: 10,
                    },
                ],
            }),
        });

        // Area 1: root -> v (cost 1), v advertises the same stub at cost 2. Total 3.
        let lsdb1 = manager.lsdb_for(area1).await;
        lsdb1.lock().await.install(router_lsa(
            router_id,
            RouterLink {
                link_id: v,
                link_data: Ipv4Addr::new(10, 0, 1, 1),
                link_type: LINK_TYPE_POINT_TO_POINT,
                metric: 1,
            },
        ));
        lsdb1.lock().await.install(Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: lsa::LSA_TYPE_ROUTER,
                link_state_id: v,
                advertising_router: v,
                sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsaBody {
                flags: 0,
                links: vec![
                    RouterLink {
                        link_id: router_id,
                        link_data: Ipv4Addr::new(10, 0, 1, 2),
                        link_type: LINK_TYPE_POINT_TO_POINT,
                        metric: 1,
                    },
                    RouterLink {
                        link_id: prefix_net,
                        link_data: mask,
                        link_type: LINK_TYPE_STUB_NETWORK,
                        metric: 2,
                    },
                ],
            }),
        });

        // `router_id` must be set for `compute_routes` to run at all.
        manager
            .reconcile(Vec::new(), HashMap::new(), router_id)
            .await;

        let routes = manager.compute_routes().await;
        let route = routes
            .iter()
            .find(|r| r.prefix == Ipv4Net::new(prefix_net, 24).unwrap())
            .unwrap();
        assert_eq!(route.metric, 3);
        assert_eq!(route.next_hops, vec![Ipv4Addr::new(10, 0, 1, 2)]);

        // Area 1's stub re-costed to 12: 1 + 12 = 13, equal to area 0's —
        // both areas' next hops are kept.
        lsdb1.lock().await.install(Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: lsa::LSA_TYPE_ROUTER,
                link_state_id: v,
                advertising_router: v,
                sequence_number: lsa::INITIAL_SEQUENCE_NUMBER + 1,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsaBody {
                flags: 0,
                links: vec![
                    RouterLink {
                        link_id: router_id,
                        link_data: Ipv4Addr::new(10, 0, 1, 2),
                        link_type: LINK_TYPE_POINT_TO_POINT,
                        metric: 1,
                    },
                    RouterLink {
                        link_id: prefix_net,
                        link_data: mask,
                        link_type: LINK_TYPE_STUB_NETWORK,
                        metric: 12,
                    },
                ],
            }),
        });
        let routes = manager.compute_routes().await;
        let route = routes
            .iter()
            .find(|r| r.prefix == Ipv4Net::new(prefix_net, 24).unwrap())
            .unwrap();
        assert_eq!(route.metric, 13);
        assert_eq!(
            route.next_hops,
            vec![Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 1, 2)]
        );
    }

    #[tokio::test]
    async fn database_summaries_flattens_every_area() {
        let manager = LinkManager::new(
            1,
            Some(exchange::DEFAULT_DBD_MAX_HEADERS),
            crate::boot::BootCounter::in_memory(),
        );
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

    /// RFC 2328 §12.4 `MinLSInterval`: changed content is held back until
    /// the held instance is `MIN_LS_INTERVAL` old, then re-originated with a
    /// bumped sequence number.
    #[test]
    fn install_self_originated_changed_body_bumps_sequence_number_after_min_ls_interval() {
        let mut lsdb = Lsdb::new();
        let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
        let key = router_key(local_router_id);
        install_self_originated(
            &mut lsdb,
            local_router_id,
            lsa::LSA_TYPE_ROUTER,
            local_router_id,
            router_body(0),
        );
        lsdb.age_and_evict(lsa::MIN_LS_INTERVAL - 1, &HashSet::new());
        install_self_originated(
            &mut lsdb,
            local_router_id,
            lsa::LSA_TYPE_ROUTER,
            local_router_id,
            router_body(1),
        );
        let held = lsdb.get(&key).unwrap();
        assert_eq!(held.header.sequence_number, lsa::INITIAL_SEQUENCE_NUMBER);
        assert_eq!(held.body, router_body(0));

        lsdb.age_and_evict(1, &HashSet::new());
        install_self_originated(
            &mut lsdb,
            local_router_id,
            lsa::LSA_TYPE_ROUTER,
            local_router_id,
            router_body(1),
        );
        let held = lsdb.get(&key).unwrap();
        assert_eq!(
            held.header.sequence_number,
            lsa::INITIAL_SEQUENCE_NUMBER + 1
        );
        assert_eq!(held.header.age, 0);
        assert_eq!(held.body, router_body(1));
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

    fn ext_auth() -> LinkAuthConfig {
        LinkAuthConfig::Crypto {
            keys: vec![(1, packet::CryptoAlgorithm::HmacSha256, b"k".to_vec())],
            current_key_id: 1,
            extended: true,
        }
    }

    #[test]
    fn extended_sequence_starts_at_boot_count_and_carries_into_it() {
        let auth = ext_auth();
        let mut seq = initial_crypto_seq(&auth, 3);
        assert_eq!(seq, 3 << 32);
        assert_eq!(next_crypto_seq(&mut seq, &auth), (3 << 32) + 1);
        // Low 32 bits wrapping carries into the boot count: still increasing.
        seq = (3 << 32) | u64::from(u32::MAX);
        assert_eq!(next_crypto_seq(&mut seq, &auth), 4 << 32);
        // A later link start (higher boot count) is above everything sent before.
        assert!(initial_crypto_seq(&auth, 4) >= seq);
    }

    #[test]
    fn extended_replay_check_is_per_packet_type() {
        let mut cfg = link("eth0.0", 10);
        cfg.auth = ext_auth();
        let mut n = neighbor_info(NeighborState::Full, Ipv4Addr::new(10, 0, 0, 2));
        n.last_crypto_seq = HashMap::new();
        let peer = Ipv4Addr::new(2, 2, 2, 2);
        let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
        status.send_modify(|s| {
            s.neighbors.insert(peer, n);
        });
        let keys = vec![(1, packet::CryptoAlgorithm::HmacSha256, b"k".to_vec())];
        let src = Ipv4Addr::new(10, 0, 0, 2);
        let hello = |seq: u64| {
            let pkt = packet::HelloPacket {
                router_id: peer,
                area_id: Ipv4Addr::UNSPECIFIED,
                network_mask: Ipv4Addr::UNSPECIFIED,
                hello_interval: 10,
                options: packet::OPTION_E,
                dead_interval: 40,
                router_priority: 1,
                designated_router: Ipv4Addr::UNSPECIFIED,
                backup_designated_router: Ipv4Addr::UNSPECIFIED,
                neighbors: vec![],
            };
            let auth = packet::OutgoingAuth::Crypto {
                key_id: 1,
                algorithm: packet::CryptoAlgorithm::HmacSha256,
                key: b"k",
                sequence: seq,
                extended: Some(src),
            };
            packet::encode_hello(&pkt, &auth)
        };
        let policy = packet::AuthPolicy::Crypto {
            keys: &keys,
            extended: Some(src),
        };
        let check = |data: &[u8]| {
            let pkt = packet::decode(data, &policy).unwrap();
            accept_crypto_sequence(&cfg, &status, data, &pkt)
        };
        assert!(check(&hello(10)));
        assert!(!check(&hello(10)), "equal is a replay");
        assert!(!check(&hello(9)), "lower is a replay");
        assert!(check(&hello(11)));
        // A different packet type keeps its own last-seen value: this DBD's
        // (lower) number would be a replay if the slot were shared.
        let dbd = packet::encode_dbd(
            &packet::DbdPacket {
                router_id: peer,
                area_id: Ipv4Addr::UNSPECIFIED,
                interface_mtu: 1500,
                options: 0,
                init: true,
                more: false,
                master: false,
                dd_sequence_number: 1,
                lsa_headers: vec![],
            },
            &packet::OutgoingAuth::Crypto {
                key_id: 1,
                algorithm: packet::CryptoAlgorithm::HmacSha256,
                key: b"k",
                sequence: 5,
                extended: Some(src),
            },
        );
        assert!(check(&dbd));
    }

    /// A Hello matching `cfg` exactly — the baseline `handle_hello` tests
    /// mutate one field away from.
    fn matching_hello(cfg: &LinkConfig, router_id: Ipv4Addr) -> packet::HelloPacket {
        packet::HelloPacket {
            router_id,
            area_id: cfg.area_id,
            network_mask: local_netmask(cfg),
            hello_interval: cfg.hello_interval,
            options: packet::OPTION_E,
            dead_interval: u32::from(cfg.dead_interval),
            router_priority: 1,
            designated_router: Ipv4Addr::UNSPECIFIED,
            backup_designated_router: Ipv4Addr::UNSPECIFIED,
            neighbors: vec![],
        }
    }

    #[test]
    fn handle_hello_accepts_a_matching_hello() {
        let cfg = link("eth0.0", 10);
        let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
        let peer = Ipv4Addr::new(9, 9, 9, 9);
        let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
        let mut deadline = Instant::now();
        handle_hello(
            &cfg,
            local_router_id,
            &status,
            Ipv4Addr::new(10, 0, 0, 2),
            &matching_hello(&cfg, peer),
            &mut deadline,
            false,
        );
        assert_eq!(
            status.borrow().neighbors.get(&peer).unwrap().state,
            NeighborState::Init
        );
    }

    #[test]
    fn p2mp_link_status_is_point_to_point_state_and_hello_has_no_dr() {
        let status = LinkStatus::new(NetworkType::PointToMultipoint);
        assert_eq!(status.interface_state, InterfaceState::PointToPoint);
    }

    #[test]
    fn p2mp_handle_hello_keeps_several_neighbors_ignoring_mask_and_election() {
        let mut cfg = link("eth0.0", 10);
        cfg.network_type = NetworkType::PointToMultipoint;
        let (status, _rx) = watch::channel(LinkStatus::new(cfg.network_type));
        let mut deadline = Instant::now();
        for (i, mask) in [(9u8, cfg.local_prefix_len), (10, 30)] {
            let peer = Ipv4Addr::new(9, 9, 9, i);
            let mut hello = matching_hello(&cfg, peer);
            hello.network_mask = Ipv4Addr::new(255, 255, 255, mask);
            handle_hello(
                &cfg,
                Ipv4Addr::new(1, 1, 1, 1),
                &status,
                Ipv4Addr::new(10, 0, 0, i),
                &hello,
                &mut deadline,
                false,
            );
        }
        let s = status.borrow();
        assert_eq!(s.neighbors.len(), 2);
        assert_eq!((s.dr, s.bdr), (None, None));
    }

    #[test]
    fn router_lsa_links_p2mp_has_link_per_full_neighbor_and_host_stub() {
        let mut cfg = link("eth0.0", 10);
        cfg.network_type = NetworkType::PointToMultipoint;
        let mut status = LinkStatus::new(cfg.network_type);
        status.neighbors.insert(
            Ipv4Addr::new(9, 9, 9, 1),
            neighbor_info(NeighborState::Full, Ipv4Addr::new(10, 0, 0, 2)),
        );
        status.neighbors.insert(
            Ipv4Addr::new(9, 9, 9, 2),
            neighbor_info(NeighborState::TwoWay, Ipv4Addr::new(10, 0, 0, 3)),
        );
        status.neighbors.insert(
            Ipv4Addr::new(9, 9, 9, 3),
            neighbor_info(NeighborState::Down, Ipv4Addr::new(10, 0, 0, 4)),
        );
        let links = router_lsa_links(Ipv4Addr::new(1, 1, 1, 1), &[(cfg, status)], false, false);
        assert_eq!(links.len(), 2);
        let p2p = links
            .iter()
            .find(|l| l.link_type == LINK_TYPE_POINT_TO_POINT)
            .unwrap();
        assert_eq!(p2p.link_id, Ipv4Addr::new(9, 9, 9, 1));
        assert_eq!(p2p.link_data, Ipv4Addr::new(10, 0, 0, 1));
        let stub = links
            .iter()
            .find(|l| l.link_type == LINK_TYPE_STUB_NETWORK)
            .unwrap();
        assert_eq!(stub.link_id, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(stub.link_data, Ipv4Addr::BROADCAST);
    }

    #[test]
    fn handle_hello_drops_mismatched_hello_interval() {
        let cfg = link("eth0.0", 10);
        let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
        let peer = Ipv4Addr::new(9, 9, 9, 9);
        let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
        let mut deadline = Instant::now();
        let mut hello = matching_hello(&cfg, peer);
        hello.hello_interval = 5;
        handle_hello(
            &cfg,
            local_router_id,
            &status,
            Ipv4Addr::new(10, 0, 0, 2),
            &hello,
            &mut deadline,
            false,
        );
        assert!(!status.borrow().neighbors.contains_key(&peer));
    }

    #[test]
    fn handle_hello_drops_mismatched_dead_interval() {
        let cfg = link("eth0.0", 10);
        let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
        let peer = Ipv4Addr::new(9, 9, 9, 9);
        let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
        let mut deadline = Instant::now();
        let mut hello = matching_hello(&cfg, peer);
        hello.dead_interval = 41;
        handle_hello(
            &cfg,
            local_router_id,
            &status,
            Ipv4Addr::new(10, 0, 0, 2),
            &hello,
            &mut deadline,
            false,
        );
        assert!(!status.borrow().neighbors.contains_key(&peer));
    }

    #[test]
    fn handle_hello_skips_network_mask_check_on_point_to_point() {
        let cfg = link("eth0.0", 10);
        let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
        let peer = Ipv4Addr::new(9, 9, 9, 9);
        let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
        let mut deadline = Instant::now();
        let mut hello = matching_hello(&cfg, peer);
        hello.network_mask = Ipv4Addr::new(255, 255, 0, 0); // wrong, but p2p ignores it
        handle_hello(
            &cfg,
            local_router_id,
            &status,
            Ipv4Addr::new(10, 0, 0, 2),
            &hello,
            &mut deadline,
            false,
        );
        assert!(status.borrow().neighbors.contains_key(&peer));
    }

    #[test]
    fn handle_hello_drops_mismatched_network_mask_on_broadcast() {
        let mut cfg = link("bd1", 10);
        cfg.network_type = NetworkType::Broadcast;
        let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
        let peer = Ipv4Addr::new(9, 9, 9, 9);
        let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::Broadcast));
        let mut deadline = Instant::now();
        let mut hello = matching_hello(&cfg, peer);
        hello.network_mask = Ipv4Addr::new(255, 255, 0, 0);
        handle_hello(
            &cfg,
            local_router_id,
            &status,
            Ipv4Addr::new(10, 0, 0, 2),
            &hello,
            &mut deadline,
            false,
        );
        assert!(!status.borrow().neighbors.contains_key(&peer));
    }

    #[test]
    fn handle_hello_drops_mismatched_e_bit() {
        let cfg = link("eth0.0", 10);
        let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
        let peer = Ipv4Addr::new(9, 9, 9, 9);
        let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
        let mut deadline = Instant::now();
        let mut hello = matching_hello(&cfg, peer);
        hello.options = 0;
        handle_hello(
            &cfg,
            local_router_id,
            &status,
            Ipv4Addr::new(10, 0, 0, 2),
            &hello,
            &mut deadline,
            false,
        );
        assert!(!status.borrow().neighbors.contains_key(&peer));
    }

    /// An in-memory multi-access wire: every port on the same subnet hears
    /// every multicast, a unicast reaches only its destination (#131).
    pub mod wire {
        use std::collections::HashSet;
        use std::net::Ipv4Addr;
        use std::sync::{Arc, Mutex};

        use ipnet::Ipv4Net;
        use tokio::sync::mpsc;

        use super::super::{LinkConfig, LinkSocket, Opener};

        type Tx = mpsc::UnboundedSender<(Ipv4Addr, Vec<u8>)>;

        #[derive(Default)]
        pub struct Wire {
            ports: Mutex<Vec<(Ipv4Net, Ipv4Addr, Tx)>>,
            /// Addresses whose sends are silently dropped (a dead neighbor).
            pub cut: Mutex<HashSet<Ipv4Addr>>,
            /// Addresses whose Hellos (type byte 1) alone are dropped.
            pub drop_hellos: Mutex<HashSet<Ipv4Addr>>,
        }

        impl Wire {
            pub fn opener(self: &Arc<Self>) -> Opener {
                let wire = Arc::clone(self);
                Arc::new(move |cfg: &LinkConfig| {
                    let net = Ipv4Net::new(cfg.local_addr, cfg.local_prefix_len)
                        .unwrap()
                        .trunc();
                    let (tx, rx) = mpsc::unbounded_channel();
                    let mut ports = wire.ports.lock().unwrap();
                    ports.retain(|(_, a, _)| *a != cfg.local_addr);
                    ports.push((net, cfg.local_addr, tx));
                    Ok(LinkSocket::Mem(Port {
                        wire: Arc::clone(&wire),
                        net,
                        addr: cfg.local_addr,
                        rx: tokio::sync::Mutex::new(rx),
                    }))
                })
            }

            /// Delivers `payload` to `to` as if `from` had sent it (a forged
            /// packet).
            pub fn inject(&self, from: Ipv4Addr, to: Ipv4Addr, payload: &[u8]) {
                for (_, addr, tx) in self.ports.lock().unwrap().iter() {
                    if *addr == to {
                        let _ = tx.send((from, payload.to_vec()));
                    }
                }
            }
        }

        pub struct Port {
            wire: Arc<Wire>,
            net: Ipv4Net,
            addr: Ipv4Addr,
            rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<(Ipv4Addr, Vec<u8>)>>,
        }

        impl Port {
            pub fn send(&self, dest: Option<Ipv4Addr>, payload: &[u8]) {
                if self.wire.cut.lock().unwrap().contains(&self.addr)
                    || (payload[1] == 1
                        && self.wire.drop_hellos.lock().unwrap().contains(&self.addr))
                {
                    return;
                }
                for (net, addr, tx) in self.wire.ports.lock().unwrap().iter() {
                    if *net == self.net && *addr != self.addr && dest.is_none_or(|d| d == *addr) {
                        let _ = tx.send((self.addr, payload.to_vec()));
                    }
                }
            }

            pub async fn recv(&self) -> std::io::Result<(Ipv4Addr, Vec<u8>)> {
                match self.rx.lock().await.recv().await {
                    Some(m) => Ok(m),
                    None => std::future::pending().await,
                }
            }
        }
    }

    fn router(wire: &Arc<wire::Wire>) -> Arc<LinkManager> {
        LinkManager::with_opener(
            1,
            None,
            crate::boot::BootCounter::in_memory(),
            wire.opener(),
        )
    }

    fn wired_link(addr: [u8; 4], prefix_len: u8, network_type: NetworkType) -> LinkConfig {
        let local_addr = Ipv4Addr::from(addr);
        LinkConfig {
            attach_point: format!("link-{local_addr}"),
            local_addr,
            local_prefix_len: prefix_len,
            network_type,
            hello_interval: 10,
            dead_interval: 40,
            ..link("unused", 10)
        }
    }

    fn stub(prefix: &str) -> HashMap<Ipv4Addr, Vec<(Ipv4Net, u16)>> {
        HashMap::from([(Ipv4Addr::UNSPECIFIED, vec![(prefix.parse().unwrap(), 1)])])
    }

    fn id(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(n, n, n, n)
    }

    async fn settle(secs: u64) {
        tokio::time::sleep(Duration::from_secs(secs)).await;
    }

    /// RFC 2328 §3.5/§3.6 (#35) over the in-memory wire: A is internal to
    /// stub area 1, B its ABR (loopback in area 0, redistributing a static).
    #[tokio::test(start_paused = true)]
    #[allow(clippy::too_many_lines)]
    async fn stub_area_gets_a_default_and_ranges_summarize() {
        let area1 = Ipv4Addr::new(0, 0, 0, 1);
        let net = |s: &str| s.parse::<Ipv4Net>().unwrap();
        let settings = |area_type: Option<bool>, ranges: Vec<(Ipv4Net, bool)>| {
            let mut m = HashMap::from([(
                Ipv4Addr::UNSPECIFIED,
                AreaSettings {
                    ranges,
                    ..AreaSettings::default()
                },
            )]);
            if let Some(import_summaries) = area_type {
                m.insert(
                    area1,
                    AreaSettings {
                        stub: true,
                        import_summaries,
                        default_cost: 5,
                        ranges: Vec::new(),
                        ..AreaSettings::default()
                    },
                );
            }
            m
        };
        let link_in_area1 = |addr, stub| LinkConfig {
            area_id: area1,
            stub,
            ..wired_link(addr, 30, NetworkType::PointToPoint)
        };
        let wire = Arc::new(wire::Wire::default());
        let (a, b) = (router(&wire), router(&wire));
        a.set_area_settings(settings(Some(true), Vec::new())).await;
        a.reconcile(
            vec![link_in_area1([10, 0, 0, 1], true)],
            HashMap::new(),
            id(1),
        )
        .await;
        let b_stubs = HashMap::from([(Ipv4Addr::UNSPECIFIED, vec![(net("192.0.2.2/32"), 1)])]);
        b.set_redistribute_policy(Arc::new(nos_rpl::ACCEPT_ALL.clone()))
            .await;
        b.apply_redistribute_update(RedistributeUpdate::Full(vec![
            nos_proto::RedistributedRoute {
                prefix: "198.51.100.0/24".parse().unwrap(),
                gateway: "10.9.9.9".parse().unwrap(),
            },
        ]))
        .await;
        b.set_redistribute_policy(Arc::new(nos_rpl::ACCEPT_ALL.clone()))
            .await;

        // Stub on A only: the E-bits disagree, so not even Init.
        b.set_area_settings(settings(None, Vec::new())).await;
        b.reconcile(
            vec![link_in_area1([10, 0, 0, 2], false)],
            b_stubs.clone(),
            id(2),
        )
        .await;
        settle(60).await;
        assert_eq!(
            a.neighbor_summaries().await[0].state,
            OspfNeighborState::Down
        );

        // Stub on both, with a range over B's loopback: Full, a default and
        // the range, never the /32 nor the Type-5.
        b.set_area_settings(settings(Some(true), vec![(net("192.0.2.0/24"), true)]))
            .await;
        b.reconcile(
            vec![link_in_area1([10, 0, 0, 2], true)],
            b_stubs.clone(),
            id(2),
        )
        .await;
        settle(60).await;
        assert_eq!(
            a.neighbor_summaries().await[0].state,
            OspfNeighborState::Full
        );
        let route = |routes: &[spf::RouteEntry], p: &str| {
            routes.iter().find(|r| r.prefix == net(p)).cloned()
        };
        let routes = a.compute_routes().await;
        let default = route(&routes, "0.0.0.0/0").expect("default route");
        assert_eq!(default.next_hops, [Ipv4Addr::new(10, 0, 0, 2)]);
        assert_eq!(default.metric, 1 + 5);
        assert!(route(&routes, "192.0.2.0/24").is_some(), "{routes:?}");
        assert!(route(&routes, "192.0.2.2/32").is_none(), "{routes:?}");
        assert!(route(&routes, "198.51.100.0/24").is_none(), "{routes:?}");
        assert!(!a
            .database_summaries()
            .await
            .iter()
            .any(|l| l.lsa_type == lsa::LSA_TYPE_AS_EXTERNAL));
        // B is no ASBR in the stub area: E clear in its Router-LSA there.
        let b_router = a
            .lsdb_for(area1)
            .await
            .lock()
            .await
            .get(&router_key(id(2)))
            .unwrap();
        let LsaBody::Router(body) = &b_router.body else {
            panic!("expected router lsa")
        };
        assert_eq!(body.flags & lsa::ROUTER_FLAG_E, 0);
        // The ABR holds a discard route for its active range.
        let discard = route(&b.compute_routes().await, "192.0.2.0/24").expect("discard");
        assert_eq!(discard.next_hops, Vec::<Ipv4Addr>::new());

        // Totally stubby: the range summary is flushed, the default stays.
        b.set_area_settings(settings(Some(false), vec![(net("192.0.2.0/24"), true)]))
            .await;
        // (Checked on B: A's `MinLSArrival` runs on the real clock, which a
        // paused-time test never advances past, so the flush can't reach A
        // here — `nos-e2e ospf-stub` covers that.)
        settle(4).await;
        let live_summaries: Vec<Ipv4Addr> = b
            .database_summaries()
            .await
            .into_iter()
            .filter(|l| {
                l.area_id == area1
                    && l.lsa_type == lsa::LSA_TYPE_NETWORK_SUMMARY
                    && l.age < lsa::MAX_AGE
            })
            .map(|l| l.link_state_id)
            .collect();
        assert_eq!(live_summaries, [Ipv4Addr::UNSPECIFIED]);

        // Not-advertise: no discard route on the ABR either.
        b.set_area_settings(settings(Some(true), vec![(net("192.0.2.0/24"), false)]))
            .await;
        settle(4).await;
        assert!(route(&b.compute_routes().await, "192.0.2.0/24").is_none());
    }

    #[test]
    fn handle_hello_matches_the_e_bit_to_the_stub_flag() {
        let cfg = LinkConfig {
            stub: true,
            ..link("eth0.0", 10)
        };
        let peer = Ipv4Addr::new(9, 9, 9, 9);
        for (options, accepted) in [(packet::OPTION_E, false), (0, true)] {
            let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
            let hello = packet::HelloPacket {
                options,
                ..matching_hello(&cfg, peer)
            };
            handle_hello(
                &cfg,
                Ipv4Addr::new(1, 1, 1, 1),
                &status,
                Ipv4Addr::new(10, 0, 0, 2),
                &hello,
                &mut Instant::now(),
                false,
            );
            assert_eq!(status.borrow().neighbors.contains_key(&peer), accepted);
        }
    }

    /// RFC 3101 §2.1: the N-bit must match the link's NSSA-ness (with the
    /// E-bit clear in an NSSA).
    #[test]
    fn handle_hello_matches_the_n_bit_to_the_nssa_flag() {
        let peer = Ipv4Addr::new(9, 9, 9, 9);
        for (nssa, options, accepted) in [
            (true, packet::OPTION_N, true),
            (true, 0, false),
            (false, packet::OPTION_N | packet::OPTION_E, false),
            (false, packet::OPTION_E, true),
        ] {
            let cfg = LinkConfig {
                stub: nssa,
                nssa,
                ..link("eth0.0", 10)
            };
            assert_eq!(hello_options(&cfg) & packet::OPTION_N != 0, nssa);
            let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
            let hello = packet::HelloPacket {
                options,
                ..matching_hello(&cfg, peer)
            };
            handle_hello(
                &cfg,
                Ipv4Addr::new(1, 1, 1, 1),
                &status,
                Ipv4Addr::new(10, 0, 0, 2),
                &hello,
                &mut Instant::now(),
                false,
            );
            assert_eq!(
                status.borrow().neighbors.contains_key(&peer),
                accepted,
                "nssa={nssa} options={options}"
            );
        }
    }

    /// RFC 3101 (#36) over the in-memory wire: C is internal to NSSA area 1
    /// and redistributes a static, B is the area's only ABR (so its
    /// translator), A is in the backbone only.
    #[tokio::test(start_paused = true)]
    #[allow(clippy::too_many_lines)]
    async fn nssa_type7_is_translated_into_the_backbone() {
        let area1 = Ipv4Addr::new(0, 0, 0, 1);
        let settings = HashMap::from([(
            area1,
            AreaSettings {
                stub: true,
                nssa: true,
                import_summaries: true,
                default_cost: 1,
                ..AreaSettings::default()
            },
        )]);
        let in_area1 = |addr| LinkConfig {
            area_id: area1,
            stub: true,
            nssa: true,
            ..wired_link(addr, 30, NetworkType::PointToPoint)
        };
        let wire = Arc::new(wire::Wire::default());
        let (a, b, c) = (router(&wire), router(&wire), router(&wire));
        for r in [&a, &b, &c] {
            r.set_area_settings(settings.clone()).await;
        }
        let prefix: Ipv4Net = "198.51.100.0/24".parse().unwrap();
        let redistribute = |routes: Vec<Ipv4Net>| {
            RedistributeUpdate::Full(
                routes
                    .into_iter()
                    .map(|p| nos_proto::RedistributedRoute {
                        prefix: p.into(),
                        gateway: "10.9.9.9".parse().unwrap(),
                    })
                    .collect(),
            )
        };
        c.apply_redistribute_update(redistribute(vec![prefix]))
            .await;
        c.set_redistribute_policy(Arc::new(nos_rpl::ACCEPT_ALL.clone()))
            .await;
        a.reconcile(
            vec![wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint)],
            HashMap::new(),
            id(1),
        )
        .await;
        b.reconcile(
            vec![
                wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint),
                in_area1([10, 0, 1, 1]),
            ],
            HashMap::new(),
            id(2),
        )
        .await;
        c.reconcile(vec![in_area1([10, 0, 1, 2])], HashMap::new(), id(3))
            .await;
        settle(60).await;

        let held = |lsdbs: Vec<LsaSummary>, lsa_type| -> Vec<(Ipv4Addr, Ipv4Addr)> {
            lsdbs
                .into_iter()
                .filter(|l| l.lsa_type == lsa_type && l.age < lsa::MAX_AGE)
                .map(|l| (l.link_state_id, l.advertising_router))
                .collect()
        };
        let net = prefix.network();
        // The backbone holds B's translated Type-5 and no Type-7.
        assert_eq!(
            held(a.database_summaries().await, lsa::LSA_TYPE_AS_EXTERNAL),
            [(net, id(2))]
        );
        assert_eq!(
            held(a.database_summaries().await, lsa::LSA_TYPE_NSSA_EXTERNAL),
            vec![]
        );
        let route = a
            .compute_routes()
            .await
            .into_iter()
            .find(|r| r.prefix == prefix)
            .expect("translated route on A");
        assert_eq!(route.next_hops, [Ipv4Addr::new(10, 0, 0, 2)]);
        // The NSSA holds C's Type-7 (P-bit, forwarding address C's own
        // link address) and no Type-5.
        assert_eq!(
            held(c.database_summaries().await, lsa::LSA_TYPE_AS_EXTERNAL),
            vec![]
        );
        let type7 = b
            .lsdb_for(area1)
            .await
            .lock()
            .await
            .get(&LsaKey {
                lsa_type: lsa::LSA_TYPE_NSSA_EXTERNAL,
                link_state_id: net,
                advertising_router: id(3),
            })
            .expect("type-7 on B");
        assert_eq!(type7.header.options, lsa::OPTION_P);
        let LsaBody::AsExternal(body) = &type7.body else {
            panic!("expected an external body")
        };
        assert_eq!(body.forwarding_address, Ipv4Addr::new(10, 0, 1, 2));
        // B, the ABR, routes to it from the Type-7.
        assert!(b.compute_routes().await.iter().any(|r| r.prefix == prefix));

        // Redistribution removed: C flushes its Type-7. (B's Type-5 flush
        // can't follow here — `MinLSArrival` runs on the real clock, which a
        // paused-time test never advances; `nos-e2e ospf-nssa` covers it.)
        c.apply_redistribute_update(redistribute(Vec::new())).await;
        c.set_redistribute_policy(Arc::new(nos_rpl::ACCEPT_ALL.clone()))
            .await;
        settle(4).await;
        assert_eq!(
            held(c.database_summaries().await, lsa::LSA_TYPE_NSSA_EXTERNAL),
            vec![]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn point_to_point_pair_reaches_full_and_routes_to_the_far_loopback() {
        let wire = Arc::new(wire::Wire::default());
        let (a, b) = (router(&wire), router(&wire));
        a.reconcile(
            vec![wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint)],
            HashMap::new(),
            id(1),
        )
        .await;
        b.reconcile(
            vec![wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint)],
            stub("192.0.2.2/32"),
            id(2),
        )
        .await;
        // B also redistributes two overlapping static routes: two Type-5s
        // for A to learn, the /25 at the host-bits ID (RFC 2328 Appendix E).
        b.set_redistribute_policy(Arc::new(nos_rpl::ACCEPT_ALL.clone()))
            .await;
        b.apply_redistribute_update(RedistributeUpdate::Full(
            ["198.51.100.0/24", "198.51.100.0/25"]
                .into_iter()
                .map(|prefix| nos_proto::RedistributedRoute {
                    prefix: prefix.parse().unwrap(),
                    gateway: "10.9.9.9".parse().unwrap(),
                })
                .collect(),
        ))
        .await;
        b.set_redistribute_policy(Arc::new(nos_rpl::ACCEPT_ALL.clone()))
            .await;
        settle(60).await;

        let n = a.neighbor_summaries().await;
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].state, OspfNeighborState::Full, "{n:?}");
        assert_eq!(n[0].neighbor_router_id, Some(id(2)));
        let routes = a.compute_routes().await;
        for prefix in ["192.0.2.2/32", "198.51.100.0/24", "198.51.100.0/25"] {
            let r = routes
                .iter()
                .find(|r| r.prefix == prefix.parse::<Ipv4Net>().unwrap())
                .unwrap_or_else(|| panic!("no route to {prefix}: {routes:?}"));
            assert_eq!(r.next_hops, [Ipv4Addr::new(10, 0, 0, 2)]);
        }
        assert!(a
            .database_summaries()
            .await
            .iter()
            .any(|l| l.lsa_type == 5 && l.advertising_router == id(2)));
        // RFC 2328 A.4.2 (#34): B's Router-LSA reached A with E set.
        let b_router = a
            .lsdb_for(Ipv4Addr::UNSPECIFIED)
            .await
            .lock()
            .await
            .get(&LsaKey {
                lsa_type: lsa::LSA_TYPE_ROUTER,
                link_state_id: id(2),
                advertising_router: id(2),
            })
            .unwrap();
        let LsaBody::Router(body) = &b_router.body else {
            panic!("expected router lsa")
        };
        assert_eq!(body.flags, lsa::ROUTER_FLAG_E);

        // B goes silent: A's dead interval drops the neighbor.
        wire.cut.lock().unwrap().insert(Ipv4Addr::new(10, 0, 0, 2));
        settle(60).await;
        assert_eq!(
            a.neighbor_summaries().await[0].state,
            OspfNeighborState::Down
        );

        // Graceful shutdown flushes A's own LSAs.
        a.shutdown().await;
        assert_eq!(a.neighbor_summaries().await, []);
    }

    /// RFC 4222 §2 recommendation 2: A's Hellos stop reaching B, but A's
    /// periodic LSUs/LSAcks over the adjacency keep B from declaring it dead;
    /// once A goes fully silent, B drops it.
    async fn adjacency_survives_lost_hellos(network_type: NetworkType) {
        let wire = Arc::new(wire::Wire::default());
        let (a, b) = (router(&wire), router(&wire));
        a.reconcile(
            vec![wired_link([10, 0, 0, 1], 24, network_type)],
            stub("192.0.2.1/32"),
            id(1),
        )
        .await;
        b.reconcile(
            vec![wired_link([10, 0, 0, 2], 24, network_type)],
            stub("192.0.2.2/32"),
            id(2),
        )
        .await;
        settle(60).await;
        assert_eq!(
            b.neighbor_summaries().await[0].state,
            OspfNeighborState::Full
        );

        wire.drop_hellos
            .lock()
            .unwrap()
            .insert(Ipv4Addr::new(10, 0, 0, 1));
        settle(3 * 40).await;
        let n = b.neighbor_summaries().await;
        assert_eq!(n[0].state, OspfNeighborState::Full, "{n:?}");
        // Reported column stays Hello-only.
        assert!(n[0].last_hello_secs.unwrap() >= 3 * 40, "{n:?}");

        wire.cut.lock().unwrap().insert(Ipv4Addr::new(10, 0, 0, 1));
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
        let addr = Ipv4Addr::new(10, 0, 0, 2);
        for (state, refreshed) in [
            (NeighborState::Down, false),
            (NeighborState::Init, false),
            (NeighborState::TwoWay, false),
            (NeighborState::ExStart, true),
            (NeighborState::Full, true),
        ] {
            let mut info = neighbor_info(state, addr);
            let past = Instant::now().checked_sub(Duration::from_secs(30)).unwrap();
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
        // An unknown router changes nothing.
        let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
        let mut deadline = Instant::now();
        let before = deadline;
        note_alive(&cfg, &status, peer, &mut deadline);
        assert_eq!(deadline, before);
        assert!(status.borrow().neighbors.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn broadcast_segment_elects_dr_and_bdr_and_dr_others_stay_two_way() {
        let wire = Arc::new(wire::Wire::default());
        let segment: Vec<_> = (1..=4).map(|_| router(&wire)).collect();
        for (i, r) in segment.iter().enumerate() {
            let n = u8::try_from(i + 1).unwrap();
            r.reconcile(
                vec![wired_link([10, 1, 0, n], 24, NetworkType::Broadcast)],
                stub(&format!("192.0.2.{n}/32")),
                id(n),
            )
            .await;
        }
        settle(120).await;

        let one = segment[0].neighbor_summaries().await;
        assert_eq!(one.len(), 3, "{one:?}");
        for n in &one {
            assert_eq!(n.dr, Some(id(4)));
            assert_eq!(n.bdr, Some(id(3)));
            assert_eq!(n.interface_state, LinkInterfaceState::DrOther);
            let want = if n.neighbor_router_id == Some(id(2)) {
                OspfNeighborState::TwoWay
            } else {
                OspfNeighborState::Full
            };
            assert_eq!(n.state, want, "{n:?}");
        }
        let routes = segment[0].compute_routes().await;
        let to_four = routes
            .iter()
            .find(|r| r.prefix == "192.0.2.4/32".parse::<Ipv4Net>().unwrap())
            .unwrap_or_else(|| panic!("{routes:?}"));
        assert_eq!(to_four.next_hops, [Ipv4Addr::new(10, 1, 0, 4)]);
        // The DR originated a Network-LSA for the segment.
        assert!(segment[0]
            .database_summaries()
            .await
            .iter()
            .any(|l| l.lsa_type == 2 && l.advertising_router == id(4)));
    }

    fn crypto(key: &[u8], extended: bool) -> LinkAuthConfig {
        LinkAuthConfig::Crypto {
            keys: vec![(1, packet::CryptoAlgorithm::HmacSha256, key.to_vec())],
            current_key_id: 1,
            extended,
        }
    }

    async fn pair_with_auth(a_auth: LinkAuthConfig, b_auth: LinkAuthConfig) -> OspfNeighborState {
        let wire = Arc::new(wire::Wire::default());
        let (a, b) = (router(&wire), router(&wire));
        let mut la = wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint);
        la.auth = a_auth;
        let mut lb = wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint);
        lb.auth = b_auth;
        a.reconcile(vec![la], HashMap::new(), id(1)).await;
        b.reconcile(vec![lb], HashMap::new(), id(2)).await;
        settle(60).await;
        a.neighbor_summaries().await[0].state
    }

    #[tokio::test(start_paused = true)]
    async fn matching_crypto_auth_reaches_full_and_a_mismatch_never_does() {
        assert_eq!(
            pair_with_auth(crypto(b"k", false), crypto(b"k", false)).await,
            OspfNeighborState::Full
        );
        assert_eq!(
            pair_with_auth(crypto(b"k", true), crypto(b"k", true)).await,
            OspfNeighborState::Full
        );
        let simple = || LinkAuthConfig::Simple {
            password: b"pw".to_vec(),
        };
        assert_eq!(
            pair_with_auth(simple(), simple()).await,
            OspfNeighborState::Full
        );
        assert_eq!(
            pair_with_auth(crypto(b"k", false), crypto(b"other", false)).await,
            OspfNeighborState::Down
        );
        assert_eq!(
            pair_with_auth(crypto(b"k", false), LinkAuthConfig::None).await,
            OspfNeighborState::Down
        );
    }

    #[tokio::test(start_paused = true)]
    async fn tiny_dbd_budget_still_reaches_full() {
        let wire = Arc::new(wire::Wire::default());
        let mk = || {
            LinkManager::with_opener(
                1,
                Some(1),
                crate::boot::BootCounter::in_memory(),
                wire.opener(),
            )
        };
        let (a, b) = (mk(), mk());
        for (m, n, prefixes) in [(&a, 1u8, 3u8), (&b, 2, 3)] {
            m.set_redistribute_policy(Arc::new(nos_rpl::ACCEPT_ALL.clone()))
                .await;
            m.apply_redistribute_update(RedistributeUpdate::Full(
                (0..prefixes)
                    .map(|p| nos_proto::RedistributedRoute {
                        prefix: format!("198.51.{n}.{p}/32").parse().unwrap(),
                        gateway: "10.9.9.9".parse().unwrap(),
                    })
                    .collect(),
            ))
            .await;
            m.set_redistribute_policy(Arc::new(nos_rpl::ACCEPT_ALL.clone()))
                .await;
            m.reconcile(
                vec![wired_link([10, 0, 0, n], 30, NetworkType::PointToPoint)],
                HashMap::new(),
                id(n),
            )
            .await;
        }
        // Let both originate before the adjacency forms, then restart A's
        // link so the DBD exchange carries several LSAs one at a time.
        settle(3).await;
        a.reconcile(Vec::new(), HashMap::new(), id(1)).await;
        a.reconcile(
            vec![wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint)],
            HashMap::new(),
            id(1),
        )
        .await;
        settle(90).await;
        assert_eq!(
            a.neighbor_summaries().await[0].state,
            OspfNeighborState::Full
        );
        let externals = a
            .database_summaries()
            .await
            .into_iter()
            .filter(|l| l.lsa_type == 5 && l.advertising_router == id(2))
            .count();
        assert_eq!(externals, 3);
    }

    /// #146: A hits `SeqNumberMismatch` on its own side (a `BadLSReq`) while
    /// Hellos keep both sides listed; B, still `Full`, must answer A's Init
    /// DBD with `SeqNumberMismatch` too, or A sits in `ExStart` for good.
    #[tokio::test(start_paused = true)]
    async fn one_sided_seq_number_mismatch_renegotiates_back_to_full() {
        let wire = Arc::new(wire::Wire::default());
        let (a, b) = (router(&wire), router(&wire));
        let (a_addr, b_addr) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
        a.reconcile(
            vec![wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint)],
            HashMap::new(),
            id(1),
        )
        .await;
        b.reconcile(
            vec![wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint)],
            HashMap::new(),
            id(2),
        )
        .await;
        settle(60).await;
        assert_eq!(
            a.neighbor_summaries().await[0].state,
            OspfNeighborState::Full
        );

        // A forged LSR "from B" for an LSA A doesn't hold: BadLSReq on A only.
        let lsr = LsrPacket {
            router_id: id(2),
            area_id: Ipv4Addr::UNSPECIFIED,
            requests: vec![LsaKey {
                lsa_type: 1,
                link_state_id: id(77),
                advertising_router: id(77),
            }],
        };
        let auth = LinkAuthConfig::None.as_outgoing(0, b_addr);
        wire.inject(b_addr, a_addr, &packet::encode_lsr(&lsr, &auth));
        // Renegotiation on the in-memory wire is near-instant, so there is no
        // reliable non-`Full` window to observe; without the fix A ends here
        // stuck in `ExStart`.
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
                let mut info = neighbor_info(NeighborState::Exchange, Ipv4Addr::new(10, 0, 0, 2));
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
        let cfg = wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint);
        let socket = (wire.opener())(&cfg).unwrap();
        let LinkSocket::Mem(peer) =
            (wire.opener())(&wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint)).unwrap()
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
                let mut info = neighbor_info(state, Ipv4Addr::new(10, 0, 0, 2));
                info.adjacency = Some(AdjacencyData {
                    last_dbd_sent: Some(dbd.clone()),
                    ..Default::default()
                });
                s.neighbors.insert(neighbor_id, info);
            });
            let mut seq = 0;
            retransmit_pending(&socket, &cfg, Ipv4Addr::new(9, 9, 9, 9), &status, &mut seq);
            let got = tokio::time::timeout(Duration::from_millis(20), peer.recv()).await;
            assert_eq!(got.is_ok(), sent, "{state:?}");
        }
    }

    // --- RFC 3623 graceful restart ---

    fn grace_status(grace: Option<Instant>) -> StatusHandle {
        let mut status = LinkStatus::new(NetworkType::PointToPoint);
        let mut info = neighbor_info(NeighborState::Full, Ipv4Addr::new(10, 0, 0, 2));
        info.adjacency = Some(start_negotiation(&link("eth0.0", 10), Ipv4Addr::new(1, 1, 1, 1)).0);
        info.grace_deadline = grace;
        status.neighbors.insert(Ipv4Addr::new(9, 9, 9, 10), info);
        watch::channel(status).0
    }

    fn state_of(status: &StatusHandle) -> NeighborState {
        status.borrow().neighbors[&Ipv4Addr::new(9, 9, 9, 10)].state
    }

    #[tokio::test]
    async fn grace_holds_full_through_a_hello_that_does_not_list_us() {
        let cfg = link("eth0.0", 10);
        let mut deadline = Instant::now();
        for (grace, expected) in [
            (
                Some(Instant::now() + Duration::from_secs(60)),
                NeighborState::Full,
            ),
            (None, NeighborState::Init),
        ] {
            let status = grace_status(grace);
            handle_hello(
                &cfg,
                Ipv4Addr::new(1, 1, 1, 1),
                &status,
                Ipv4Addr::new(10, 0, 0, 2),
                &matching_hello(&cfg, Ipv4Addr::new(9, 9, 9, 10)),
                &mut deadline,
                false,
            );
            assert_eq!(state_of(&status), expected);
        }
    }

    #[tokio::test]
    async fn grace_suppresses_the_inactivity_timer_until_it_expires() {
        let cfg = link("eth0.0", 10);
        let status = grace_status(Some(Instant::now() + Duration::from_secs(60)));
        apply_dead_timer(&cfg, &status);
        sweep_dead_neighbors(&cfg, &status);
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
    async fn grace_lsa_starts_helping_only_a_full_neighbor_and_is_idempotent() {
        let cfg = link("eth0.0", 10);
        let header = LsaHeader {
            age: 1,
            options: 0,
            lsa_type: lsa::LSA_TYPE_OPAQUE_LINK,
            link_state_id: lsa::GRACE_LINK_STATE_ID,
            advertising_router: Ipv4Addr::new(9, 9, 9, 10),
            sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
            checksum: 0,
            length: 0,
        };
        let body = GraceLsaBody {
            grace_period: 60,
            restart_reason: lsa::RESTART_REASON_SOFTWARE,
            interface_address: None,
        };
        let status = grace_status(None);
        on_grace_lsa(&cfg, &status, &header, body);
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

    async fn helping(m: &LinkManager, neighbor: Ipv4Addr) -> bool {
        m.links.lock().await.values().any(|e| {
            e.status
                .borrow()
                .neighbors
                .get(&neighbor)
                .is_some_and(|n| n.grace_deadline.is_some())
        })
    }

    async fn routes_to(m: &LinkManager, prefix: &str) -> bool {
        let prefix: Ipv4Net = prefix.parse().unwrap();
        m.compute_routes().await.iter().any(|r| r.prefix == prefix)
    }

    /// RFC 3623 over the wire: B announces a grace period and stops without
    /// flushing its LSAs; A helps — keeps B `Full` and B's routes through
    /// B's absence, past the dead interval, and through the restarted B's
    /// Hellos and Init DBD — never holds or floods the Grace-LSA, and leaves
    /// grace once the fresh B is `Full` again.
    #[tokio::test(start_paused = true)]
    async fn graceful_restart_is_helped_through_a_real_restart() {
        let wire = Arc::new(wire::Wire::default());
        let (a, b) = (router(&wire), router(&wire));
        let link_b = wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint);
        a.reconcile(
            vec![wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint)],
            HashMap::new(),
            id(1),
        )
        .await;
        b.reconcile(vec![link_b.clone()], stub("192.0.2.2/32"), id(2))
            .await;
        b.set_graceful_restart(Some(120));
        // RFC 3623 §3.2 (c): on-shutdown must not change the Router-LSA.
        b.set_max_metric(None, Some(3), false);
        settle(60).await;
        assert_eq!(
            a.neighbor_summaries().await[0].state,
            OspfNeighborState::Full
        );
        assert!(routes_to(&a, "192.0.2.2/32").await);

        b.announce_graceful_restart().await;
        b.shutdown().await;
        assert!(helping(&a, id(2)).await);
        assert_eq!(router_lsa_at(&a, id(2)).await.1, [1]);
        let lsas = a.database_summaries().await;
        assert!(lsas.iter().all(|l| l.lsa_type != lsa::LSA_TYPE_OPAQUE_LINK));
        // RFC 3623 §2: the restarter keeps its LSAs, never prematurely aged.
        assert!(lsas
            .iter()
            .filter(|l| l.advertising_router == id(2))
            .all(|l| l.age < lsa::MAX_AGE));

        // B is gone for longer than the dead interval: A still holds it.
        settle(60).await;
        assert_eq!(
            a.neighbor_summaries().await[0].state,
            OspfNeighborState::Full
        );
        assert!(routes_to(&a, "192.0.2.2/32").await);

        let b2 = router(&wire);
        b2.reconcile(vec![link_b], stub("192.0.2.2/32"), id(2))
            .await;
        settle(60).await;
        assert_eq!(
            a.neighbor_summaries().await[0].state,
            OspfNeighborState::Full
        );
        assert!(!helping(&a, id(2)).await);
        assert!(routes_to(&a, "192.0.2.2/32").await);
    }

    /// `router`'s Router-LSA as `holder` has it: (age, p2p metrics, stub metrics).
    async fn router_lsa_at(holder: &LinkManager, router: Ipv4Addr) -> (u16, Vec<u16>, Vec<u16>) {
        let lsa = holder
            .lsdb_for(Ipv4Addr::UNSPECIFIED)
            .await
            .lock()
            .await
            .get(&LsaKey {
                lsa_type: lsa::LSA_TYPE_ROUTER,
                link_state_id: router,
                advertising_router: router,
            })
            .unwrap();
        let LsaBody::Router(body) = &lsa.body else {
            panic!("expected router lsa")
        };
        let metrics = |t| {
            body.links
                .iter()
                .filter(|l| l.link_type == t)
                .map(|l| l.metric)
                .collect()
        };
        (
            lsa.header.age,
            metrics(LINK_TYPE_POINT_TO_POINT),
            metrics(LINK_TYPE_STUB_NETWORK),
        )
    }

    /// A p2p pair at `Full`, A with a loopback; `a_max_metric` is set on A
    /// before its first resync, like `reconcile.rs` does.
    async fn stub_router_pair(
        a_max_metric: (Option<u32>, Option<u8>, bool),
    ) -> (Arc<LinkManager>, Arc<LinkManager>) {
        let wire = Arc::new(wire::Wire::default());
        let (a, b) = (router(&wire), router(&wire));
        a.set_max_metric(a_max_metric.0, a_max_metric.1, a_max_metric.2);
        a.reconcile(
            vec![wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint)],
            stub("192.0.2.1/32"),
            id(1),
        )
        .await;
        b.reconcile(
            vec![wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint)],
            HashMap::new(),
            id(2),
        )
        .await;
        (a, b)
    }

    /// RFC 6987 on-startup: max-metric transit links for the configured
    /// period, then normal costs; stub links (and B's route to A's loopback)
    /// never change.
    #[tokio::test(start_paused = true)]
    async fn on_startup_max_metric_lasts_its_period() {
        let (a, b) = stub_router_pair((Some(60), None, false)).await;
        settle(40).await;
        assert!(a.max_metric_active());
        let (_, p2p, stubs) = router_lsa_at(&b, id(1)).await;
        assert_eq!(p2p, [lsa::MAX_LINK_METRIC]);
        assert!(stubs.iter().all(|&m| m == 1), "{stubs:?}");
        assert!(routes_to(&b, "192.0.2.1/32").await);

        settle(40).await;
        assert!(!a.max_metric_active());
        assert_eq!(router_lsa_at(&b, id(1)).await.1, [1]);
        // Later resyncs never re-arm it.
        a.set_max_metric(Some(60), None, false);
        assert!(!a.max_metric_active());
    }

    #[tokio::test(start_paused = true)]
    async fn on_startup_is_armed_once_cleared_by_none_and_skipped_after_graceful_restart() {
        let m = LinkManager::new(1, None, crate::boot::BootCounter::in_memory());
        m.set_max_metric(Some(60), None, false);
        assert!(m.max_metric_active());
        m.set_max_metric(None, None, false);
        assert!(!m.max_metric_active());
        m.set_max_metric(None, None, true);
        assert!(m.max_metric_active());

        let restarted = LinkManager::new(1, None, crate::boot::BootCounter::in_memory());
        restarted.set_after_graceful_restart(true);
        restarted.set_max_metric(Some(60), None, false);
        assert!(!restarted.max_metric_active());
    }

    /// RFC 6987 on-shutdown: B installs A's max-metric Router-LSA at once
    /// (the flood kick, well inside `RXMT_INTERVAL`), then the flushed copy
    /// of that same instance once the hold is over.
    #[tokio::test(start_paused = true)]
    async fn on_shutdown_advertises_max_metric_before_the_flush() {
        let (a, b) = stub_router_pair((None, Some(3), false)).await;
        settle(60).await;
        assert_eq!(router_lsa_at(&b, id(1)).await.1, [1]);

        let stopping = Arc::clone(&a);
        let task = tokio::spawn(async move { stopping.shutdown().await });
        settle(1).await;
        let (age, p2p, _) = router_lsa_at(&b, id(1)).await;
        assert_eq!(p2p, [lsa::MAX_LINK_METRIC]);
        assert!(age < lsa::MAX_AGE);
        settle(3).await;
        let (age, p2p, _) = router_lsa_at(&b, id(1)).await;
        assert_eq!((age, p2p), (lsa::MAX_AGE, vec![lsa::MAX_LINK_METRIC]));
        task.await.unwrap();
    }

    /// A Router-LSA that changed under `MinLSInterval` ago skips on-shutdown;
    /// the flush still happens.
    #[tokio::test(start_paused = true)]
    async fn on_shutdown_is_skipped_when_the_router_lsa_just_changed() {
        let (a, b) = stub_router_pair((None, Some(3), false)).await;
        settle(60).await;
        a.set_prefix_suppression(true);
        settle(2).await;
        let stopping = Arc::clone(&a);
        let task = tokio::spawn(async move { stopping.shutdown().await });
        settle(2).await;
        let (age, p2p, _) = router_lsa_at(&b, id(1)).await;
        assert_eq!((age, p2p), (lsa::MAX_AGE, vec![1]));
        task.await.unwrap();
    }

    /// Without a configured grace period, SIGTERM's announce is a no-op and
    /// shutdown flushes as before.
    #[tokio::test(start_paused = true)]
    async fn announce_without_a_grace_period_still_flushes_on_shutdown() {
        let wire = Arc::new(wire::Wire::default());
        let b = router(&wire);
        b.reconcile(Vec::new(), stub("192.0.2.2/32"), id(2)).await;
        settle(3).await;
        b.announce_graceful_restart().await;
        b.shutdown().await;
        let own: Vec<_> = b
            .database_summaries()
            .await
            .into_iter()
            .filter(|l| l.advertising_router == id(2))
            .collect();
        assert_ne!(own, []);
        assert!(own.iter().all(|l| l.age == lsa::MAX_AGE));
    }

    fn opaque_lsa(lsa_type: u8, advertising_router: Ipv4Addr) -> Lsa {
        let mut l = Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type,
                link_state_id: Ipv4Addr::new(4, 0, 0, 1),
                advertising_router,
                sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Opaque(vec![0, 1, 0, 4, 1, 2, 3, 4]),
        };
        lsa::fill_checksum(&mut l);
        l
    }

    fn types_from(lsas: &[LsaSummary], router: Ipv4Addr) -> Vec<u8> {
        let mut t: Vec<u8> = lsas
            .iter()
            .filter(|l| l.advertising_router == router)
            .map(|l| l.lsa_type)
            .collect();
        t.sort_unstable();
        t
    }

    /// RFC 5250 scoping over the wire: X floods a type 9, 10 and 11 to A on
    /// link 1; A keeps the type 9 in link 1's own store and floods only the
    /// type 10 and 11 on to B over link 2.
    #[tokio::test(start_paused = true)]
    async fn opaque_lsas_are_flooded_by_scope() {
        let wire = Arc::new(wire::Wire::default());
        let (x, a, b) = (router(&wire), router(&wire), router(&wire));
        x.reconcile(
            vec![wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint)],
            HashMap::new(),
            id(3),
        )
        .await;
        a.reconcile(
            vec![
                wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint),
                wired_link([10, 0, 1, 1], 30, NetworkType::PointToPoint),
            ],
            HashMap::new(),
            id(1),
        )
        .await;
        b.reconcile(
            vec![wired_link([10, 0, 1, 2], 30, NetworkType::PointToPoint)],
            HashMap::new(),
            id(2),
        )
        .await;
        settle(60).await;

        let origin = id(9);
        {
            let area = x.lsdb_for(Ipv4Addr::UNSPECIFIED).await;
            let mut area = area.lock().await;
            for t in [lsa::LSA_TYPE_OPAQUE_AREA, lsa::LSA_TYPE_OPAQUE_AS] {
                area.install(opaque_lsa(t, origin));
            }
            let links = x.links.lock().await;
            let link = &links.values().next().unwrap().link_local_lsdb;
            link.lock()
                .await
                .install(opaque_lsa(lsa::LSA_TYPE_OPAQUE_LINK, origin));
        }
        settle(30).await;

        assert_eq!(
            types_from(&a.database_summaries().await, origin),
            [9, 10, 11]
        );
        let a_area = a.lsdb_for(Ipv4Addr::UNSPECIFIED).await;
        assert!(a_area
            .lock()
            .await
            .headers()
            .iter()
            .all(|h| h.lsa_type != lsa::LSA_TYPE_OPAQUE_LINK));
        assert_eq!(types_from(&b.database_summaries().await, origin), [10, 11]);
    }
}
