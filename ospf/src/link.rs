//! One OSPF link's Hello-protocol driver, plus `LinkManager` — the OSPF
//! analogue of `bgp::session::SessionManager`, much smaller since there's no
//! shared listener, no auth, and no collision resolution: each link just
//! owns its own raw socket, neighbor FSM(s), and (on a `Broadcast` link)
//! RFC 2328 §9.4 DR/BDR election.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use nos_proto::{LinkInterfaceState, NeighborSummary, NetworkType, OspfNeighborState};
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::election::{self, Candidate};
use crate::neighbor::{self, NeighborState};
use crate::packet::{self, HelloPacket};
use crate::socket::OspfSocket;

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

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NeighborInfo {
    pub state: NeighborState,
    pub priority: u8,
    pub declared_dr: Ipv4Addr,
    pub declared_bdr: Ipv4Addr,
    pub last_hello_received: Instant,
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

/// Runs until aborted (link removed from config, or process shutdown — see
/// `LinkManager`). Owns the raw socket, the Hello send ticker, and every
/// timer this link's network type needs.
pub async fn run(cfg: LinkConfig, local_router_id: Ipv4Addr, status: StatusHandle) {
    let socket = match OspfSocket::open(&cfg.vrf, cfg.local_addr) {
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

    info!(link = %cfg.attach_point, vrf = %cfg.vrf, "ospf link driver started");
    if is_broadcast {
        info!(link = %cfg.attach_point, "ospf interface reached waiting");
    }

    loop {
        tokio::select! {
            _ = hello_ticker.tick() => {
                send_hello(&socket, &cfg, local_router_id, &status);
            }
            result = socket.recv_hello() => {
                let left_waiting = handle_received(
                    result, &cfg, local_router_id, &status, &mut p2p_dead_deadline, waiting,
                );
                if left_waiting {
                    waiting = false;
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
                }
            }
            () = tokio::time::sleep_until(wait_deadline), if waiting => {
                waiting = false;
                run_election(&cfg, local_router_id, &status);
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

    let pkt = HelloPacket {
        router_id: local_router_id,
        area_id: cfg.area_id,
        hello_interval: cfg.hello_interval,
        dead_interval: u32::from(cfg.dead_interval),
        router_priority: cfg.priority,
        designated_router,
        backup_designated_router,
        neighbors,
    };
    if let Err(e) = socket.send_hello(&packet::encode_hello(&pkt)) {
        warn!(link = %cfg.attach_point, error = %e, "failed to send ospf hello");
    }
}

/// Returns whether this Hello caused a broadcast link to leave `Waiting`
/// early (RFC 2328's "`BackupSeen`" shortcut — a neighbor already declaring
/// itself DR means the election result is already knowable).
fn handle_received(
    result: std::io::Result<Vec<u8>>,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    p2p_dead_deadline: &mut Instant,
    waiting: bool,
) -> bool {
    let data = match result {
        Ok(received) => received,
        Err(e) => {
            warn!(link = %cfg.attach_point, error = %e, "ospf recv error");
            return false;
        }
    };
    let hello = match packet::decode_hello(&data) {
        Ok(hello) => hello,
        Err(e) => {
            warn!(link = %cfg.attach_point, error = %e, "failed to decode ospf hello");
            return false;
        }
    };
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
    status.send_modify(|s| {
        s.neighbors.insert(
            hello.router_id,
            NeighborInfo {
                state: new_state,
                priority: hello.router_priority,
                declared_dr: hello.designated_router,
                declared_bdr: hello.backup_designated_router,
                last_hello_received: Instant::now(),
            },
        );
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
        .filter(|(_, info)| info.state == NeighborState::TwoWay)
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

/// Owns every OSPF link's driver task for one `nos-ospfd` process.
/// `reconcile` is the sole entry point, called by `crate::reconcile::run` on
/// every resync; it's idempotent and safe to call repeatedly with the same
/// desired state — mirrors `bgp::session::SessionManager`.
pub struct LinkManager {
    links: Mutex<HashMap<String, LinkEntry>>,
}

impl LinkManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            links: Mutex::new(HashMap::new()),
        })
    }

    /// Diffs `desired` against currently-running links by `attach_point`:
    /// links no longer desired, or whose resolved fields changed, are
    /// stopped (and, if still desired with new fields, respawned); newly
    /// desired links are spawned. A link whose driver task ended on its own
    /// (e.g. the raw socket failed to open) is treated as "not currently
    /// running" so this pass respawns it too — the same periodic re-apply
    /// tick that re-resolves a not-yet-ready VRF/interface also recovers
    /// from a transient socket failure this way.
    pub async fn reconcile(self: &Arc<Self>, desired: Vec<LinkConfig>, local_router_id: Ipv4Addr) {
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
            let (status_tx, status_rx) = watch::channel(LinkStatus::new(cfg.network_type));
            let task = tokio::spawn(run(cfg.clone(), local_router_id, status_tx));
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
            area_id: Ipv4Addr::new(0, 0, 0, 0),
            hello_interval,
            dead_interval: 40,
            vrf: "vrf100".to_string(),
            local_addr: Ipv4Addr::new(10, 0, 0, 1),
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
}
