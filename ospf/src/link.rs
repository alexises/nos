//! One OSPF link's driver, plus `LinkManager` — the OSPF analogue of
//! `bgp::session::SessionManager`, much smaller since there's no shared
//! listener and no collision resolution: each link just owns its
//! own raw socket, neighbor FSM(s), RFC 2328 §9.4 DR/BDR election on a
//! `Broadcast` link, and — once a neighbor is eligible — RFC 2328
//! §10.6-10.8's DBD/LSR/LSU/LSAck adjacency-forming exchange
//! (`crate::exchange`).

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipnet::{IpNet, Ipv4Net};
use nos_proto::{
    LinkInterfaceState, LsaSummary, NeighborSummary, NetworkType, OspfNeighborState,
    RedistributeUpdate,
};
use nos_rpl::CompiledPolicy;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::election::{self, Candidate};
use crate::exchange::{self, AdjacencyData};
use crate::lsa::{
    self, AsExternalLsaBody, Lsa, LsaBody, LsaHeader, LsaKey, NetworkLsaBody, RouterLink,
    RouterLsaBody, SummaryLsaBody, LINK_TYPE_POINT_TO_POINT, LINK_TYPE_STUB_NETWORK,
    LINK_TYPE_TRANSIT_NETWORK,
};
use crate::lsdb::Lsdb;
use crate::neighbor::{self, NeighborState};
use crate::packet::{self, DbdPacket, LsAckPacket, LsrPacket, LsuPacket, OspfPacket, PacketError};
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
/// Well inside `nos-watchdogd`'s 10s SIGINT-to-SIGKILL budget (root
/// `CLAUDE.md`, "Process supervision") — recheck if `RXMT_INTERVAL` grows.
const PREMATURE_AGE_FLOOD_WINDOW: Duration = Duration::from_secs(6);

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
    /// RFC 2328 Appendix D auth, resolved once per reconcile from
    /// `OspfProfile.auth` (see `reconcile.rs`). Fits this struct's existing
    /// "any field change restarts the link" rule with no special-casing —
    /// an auth/key change simply restarts the link task, which re-sends
    /// Hello with the new auth; a peer still on the old auth rejects it
    /// until it's updated too, which is exactly the desired match/mismatch
    /// behavior.
    pub auth: LinkAuthConfig,
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
        keys: Vec<(u8, packet::CryptoAlgorithm, Vec<u8>)>,
        current_key_id: u8,
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
    pub last_hello_received: Instant,
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
        interface_mtu: cfg.mtu,
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
        // Populated once real content starts flowing, in `exchange::
        // on_dbd_in_exstart` (this negotiation attempt itself always
        // carries no summary data, per RFC 2328 §10.6).
        summary_remaining: std::collections::VecDeque::new(),
        pending_acks: Vec::new(),
        pending_acks_since: None,
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
    dbd_max_headers: Option<usize>,
    boot_count: u32,
) {
    let socket = match OspfSocket::open(&cfg.kernel_interface, cfg.local_addr) {
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
        tokio::select! {
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
                            Ok(OspfPacket::Hello(hello)) => {
                                let left_waiting = handle_hello(
                                    &cfg, local_router_id, &status, source, &hello,
                                    &mut p2p_dead_deadline, waiting,
                                );
                                if left_waiting {
                                    waiting = false;
                                }
                                advance_adjacencies(&socket, &cfg, local_router_id, &status, &mut next_seq);
                            }
                            Ok(OspfPacket::Dbd(dbd)) => {
                                if let Some(actions) = handle_dbd(
                                    &cfg, local_router_id, &status, &lsdb, &dbd, dbd_max_headers,
                                )
                                .await
                                {
                                    execute_actions(&socket, &cfg, local_router_id, &status, dbd.router_id, actions, &mut next_seq);
                                }
                            }
                            Ok(OspfPacket::Lsr(lsr)) => {
                                if let Some(actions) =
                                    handle_lsr(&cfg, local_router_id, &status, &lsdb, &lsr).await
                                {
                                    execute_actions(&socket, &cfg, local_router_id, &status, lsr.router_id, actions, &mut next_seq);
                                }
                            }
                            Ok(OspfPacket::Lsu(lsu)) => {
                                if let Some(actions) =
                                    handle_lsu(&cfg, local_router_id, &status, &lsdb, &lsu).await
                                {
                                    execute_actions(&socket, &cfg, local_router_id, &status, lsu.router_id, actions, &mut next_seq);
                                }
                            }
                            Ok(OspfPacket::LsAck(ack)) => {
                                handle_lsack(&status, &ack);
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
            () = tokio::time::sleep_until(p2p_dead_deadline), if !is_broadcast => {
                apply_dead_timer(&cfg, &status);
                p2p_dead_deadline = Instant::now() + Duration::from_secs(u64::from(cfg.dead_interval));
            }
            _ = dead_sweep.tick(), if is_broadcast => {
                sweep_dead_neighbors(&cfg, &status);
                if !waiting {
                    run_election(&cfg, local_router_id, &status);
                    advance_adjacencies(&socket, &cfg, local_router_id, &status, &mut next_seq);
                }
            }
            () = tokio::time::sleep_until(wait_deadline), if waiting => {
                waiting = false;
                run_election(&cfg, local_router_id, &status);
                advance_adjacencies(&socket, &cfg, local_router_id, &status, &mut next_seq);
            }
            _ = rxmt_sweep.tick() => {
                flush_pending_acks(&socket, &cfg, local_router_id, &status, &mut next_seq);
                retransmit_pending(&socket, &cfg, local_router_id, &status, &mut next_seq);
                flood_full_neighbors(&socket, &cfg, local_router_id, &lsdb, &status, &mut next_seq).await;
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
    socket: &OspfSocket,
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
        network_mask: local_netmask(cfg),
        hello_interval: cfg.hello_interval,
        options: packet::OPTION_E,
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
    // NetworkMask is meaningless on point-to-point/virtual links (RFC 2328
    // §10.5) — this NOS has neither NBMA nor point-to-multipoint, so
    // `Broadcast` is the only network type it's ever checked on.
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
    // This NOS has no stub-area concept, so our own E-bit is always set —
    // a peer that ever clears its own can never be a legitimate neighbor
    // today, but the comparison is real (not a no-op) so it starts doing
    // something meaningful the moment stub areas exist on either side.
    if hello.options & packet::OPTION_E == 0 {
        warn!(
            link = %cfg.attach_point, neighbor = %hello.router_id,
            "dropping ospf hello with mismatched e-bit"
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
                last_crypto_seq: HashMap::new(),
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
    dbd: &DbdPacket,
    dbd_max_headers: usize,
) -> Option<Vec<exchange::Action>> {
    let (old_state, mut adj) = {
        let snapshot = status.borrow();
        let neighbor = snapshot.neighbors.get(&dbd.router_id)?;
        (neighbor.state, neighbor.adjacency.clone()?)
    };

    // A MaxAge entry is never offered in the summary: it may be evicted
    // (`Lsdb::MAX_AGE_HOLD_TICKS`) before the neighbor's LSR for it lands,
    // which would read as `BadLSReq` and restart the adjacency for nothing.
    // The periodic resend still carries the flush to an already-`Full`
    // neighbor.
    let local_lsdb_headers: Vec<LsaHeader> = lsdb
        .lock()
        .await
        .headers()
        .into_iter()
        .filter(|h| h.age < lsa::MAX_AGE)
        .collect();
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
    socket: &OspfSocket,
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
    socket: &OspfSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    next_seq: &mut u64,
) {
    let snapshot = status.borrow().clone();
    for (neighbor_id, info) in &snapshot.neighbors {
        let Some(adj) = &info.adjacency else { continue };
        if let Some(dbd) = &adj.last_dbd_sent {
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
    next_seq: &mut u64,
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
    // One signed payload reused for every full neighbor — safe even under
    // Crypto auth: RFC 2328 D.4.3's anti-replay check is per-neighbor on the
    // receive side (`accept_crypto_sequence` keys on the sender's own
    // `router_id`), so two different neighbors each independently accepting
    // the same sequence number is correct, not a replay.
    let auth = cfg
        .auth
        .as_outgoing(next_crypto_seq(next_seq, &cfg.auth), cfg.local_addr);
    let payload = packet::encode_lsu(
        &LsuPacket {
            router_id: local_router_id,
            area_id: cfg.area_id,
            lsas: lsas.iter().map(|l| (**l).clone()).collect(),
        },
        &auth,
    );
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
}

impl LinkManager {
    pub fn new(
        age_multiplier: u16,
        dbd_max_headers: Option<usize>,
        boots: crate::boot::BootCounter,
    ) -> Arc<Self> {
        let manager = Arc::new(Self {
            links: Mutex::new(HashMap::new()),
            lsdbs: Mutex::new(HashMap::new()),
            router_id: Mutex::new(None),
            stub_networks: Mutex::new(HashMap::new()),
            age_multiplier,
            dbd_max_headers,
            boots,
            redistribute_raw: Mutex::new(HashSet::new()),
            redistribute_filtered: Mutex::new(HashSet::new()),
            shutting_down: AtomicBool::new(false),
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

    /// RFC 2328 §14: ages every installed LSA, in every area, by one
    /// (simulated) second times `age_multiplier`, evicting anything that
    /// reaches `MAX_AGE`. Run every `AGE_TICK_INTERVAL`, independent of
    /// `originate_router_lsas` — aging is LSDB-wide, not per-link.
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
        // ids rather than iterating `by_area` alone. An area this router
        // holds an LSDB for but has left entirely (no link, no stub) is
        // visited too, so its Router-/Network-LSAs get withdrawn.
        let area_ids: HashSet<Ipv4Addr> = by_area
            .keys()
            .copied()
            .chain(stub_networks.keys().copied())
            .chain(self.lsdbs.lock().await.keys().copied())
            .collect();

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
                continue;
            }

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
        let prefixes: Vec<Ipv4Net> = self
            .redistribute_filtered
            .lock()
            .await
            .iter()
            .copied()
            .collect();
        let area_ids: Vec<Ipv4Addr> = self.lsdbs.lock().await.keys().copied().collect();
        let desired: HashSet<Ipv4Addr> = prefixes.iter().map(Ipv4Net::network).collect();

        for area_id in area_ids {
            let lsdb = self.lsdb_for(area_id).await;
            let mut lsdb = lsdb.lock().await;
            for prefix in &prefixes {
                install_self_originated(
                    &mut lsdb,
                    local_router_id,
                    lsa::LSA_TYPE_AS_EXTERNAL,
                    prefix.network(),
                    LsaBody::AsExternal(AsExternalLsaBody {
                        network_mask: prefix.netmask(),
                        metric: 0,
                        forwarding_address: Ipv4Addr::UNSPECIFIED,
                        external_route_tag: 0,
                    }),
                );
            }
            // RFC 2328 §14.1: a prefix no longer redistributed is flushed,
            // not left to age out over `MAX_AGE`.
            withdraw_undesired(
                &mut lsdb,
                local_router_id,
                lsa::LSA_TYPE_AS_EXTERNAL,
                &desired,
            );
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
        let mut per_area: HashMap<Ipv4Addr, spf::IntraAreaRoutes> = HashMap::new();
        if areas.len() >= 2 {
            for (area_id, lsdb) in &areas {
                let lsas = lsdb.lock().await.all();
                per_area.insert(*area_id, spf::intra_area_routes(local_router_id, &lsas));
            }
        }

        for (dest_area, dest_lsdb) in &areas {
            let mut dest_lsdb = dest_lsdb.lock().await;
            let mut network_ids = HashSet::new();
            let mut asbr_ids = HashSet::new();
            for (src_area, view) in &per_area {
                if src_area == dest_area {
                    continue;
                }
                for route in &view.routes {
                    // ponytail: if the identical prefix happens to be
                    // intra-area in more than one source area (a subnet
                    // spanning areas — not a real topology), the last
                    // src_area processed here (HashMap iteration order) wins;
                    // not worth cross-area coordination machinery for a case
                    // that shouldn't occur.
                    network_ids.insert(route.prefix.network());
                    install_self_originated(
                        &mut dest_lsdb,
                        local_router_id,
                        lsa::LSA_TYPE_NETWORK_SUMMARY,
                        route.prefix.network(),
                        LsaBody::Summary(SummaryLsaBody {
                            network_mask: route.prefix.netmask(),
                            metric: route.metric,
                        }),
                    );
                }
                for &(asbr, dist) in &view.asbrs {
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
            let task = tokio::spawn(run(
                cfg.clone(),
                local_router_id,
                lsdb,
                status_tx,
                self.dbd_max_headers,
                boot_count,
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
    /// A router attached to 2+ areas (an ABR, see `originate_summary_lsas`)
    /// can now legitimately compute the same destination prefix from more
    /// than one area's own LSDB (e.g. via a summarized inter-area path in
    /// one area and a direct path in another) — keeps whichever is cheaper,
    /// the same min-metric tie-break `spf::insert_best` already applies
    /// within one area. Empty if `router_id` hasn't been set yet (before
    /// this instance's first `reconcile` call).
    pub async fn compute_routes(&self) -> Vec<spf::RouteEntry> {
        let Some(router_id) = *self.router_id.lock().await else {
            return Vec::new();
        };
        let areas: Vec<Arc<Mutex<Lsdb>>> = self.lsdbs.lock().await.values().cloned().collect();
        let mut merged: HashMap<Ipv4Net, spf::RouteEntry> = HashMap::new();
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

    /// Graceful shutdown: flushes every self-originated LSA (RFC 2328
    /// §14.1) and keeps the link tasks alive for `PREMATURE_AGE_FLOOD_WINDOW`
    /// so their periodic resend carries the `MaxAge` copies to every neighbor
    /// — which then drops this router's routes at once instead of only when
    /// its LSAs age out an hour later — then aborts every link task. Called
    /// once when `crate::reconcile::run`'s loop exits on shutdown.
    pub async fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::Relaxed);
        let withdrawn = self.withdraw_all_self_originated().await;
        if withdrawn > 0 {
            info!(
                withdrawn,
                "ospf flushing self-originated lsas before shutdown"
            );
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

/// This link's own subnet mask — RFC 2328 §10.5's `NetworkMask`, both sent
/// (`send_hello`) and checked against on receipt (`handle_hello`, skipped on
/// point-to-point). `UNSPECIFIED` if `local_prefix_len` is somehow invalid,
/// same fallback as `local_subnet`.
fn local_netmask(cfg: &LinkConfig) -> Ipv4Addr {
    local_subnet(cfg).map_or(Ipv4Addr::UNSPECIFIED, |n| n.netmask())
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
        // RFC 2328 §12.1.6: at `MaxSequenceNumber` the instance is flushed
        // (at that same sequence number — never the reserved 0x8000_0000 a
        // wrapping increment would produce) and re-originated at
        // `INITIAL_SEQUENCE_NUMBER` only once the flush has been flooded:
        // `Lsdb::age_and_evict` evicts it after `MAX_AGE_HOLD_TICKS`, and
        // the `None` arm below then takes over.
        Some(e) if e.header.sequence_number == lsa::MAX_SEQUENCE_NUMBER => {
            withdraw_self_originated(lsdb, &key);
            return;
        }
        Some(e) => e.header.sequence_number + 1,
        None => lsa::INITIAL_SEQUENCE_NUMBER,
    };
    let mut fresh = Lsa {
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
            auth: LinkAuthConfig::None,
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
            last_crypto_seq: HashMap::new(),
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
        lsdb.age_and_evict(lsa::LS_REFRESH_TIME);

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
            assert!(lsdb.age_and_evict(1).is_empty());
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
        assert_eq!(lsdb.age_and_evict(1), vec![key]);

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

        // Two Router-LSAs plus one Type-3 per area.
        assert_eq!(manager.withdraw_all_self_originated().await, 4);
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
}
