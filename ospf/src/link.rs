//! One point-to-point OSPF link's Hello-protocol driver, plus `LinkManager`
//! — the OSPF analogue of `bgp::session::SessionManager`, much smaller since
//! there's no shared listener, no auth, and no collision resolution: each
//! link just owns its own raw socket and neighbor FSM.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use nos_proto::{NeighborSummary, OspfNeighborState};
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::neighbor::{self, NeighborState};
use crate::packet::{self, HelloPacket};
use crate::socket::OspfSocket;

/// One point-to-point link's fully-resolved desired state — diffed
/// wholesale by `LinkManager::reconcile`, mirroring `bgp::session::
/// ResolvedPeer`: any field change (including a re-resolved `vrf`/
/// `local_addr`) restarts the link.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkConfig {
    /// Display key, matching `reconcile::attach_points_for`'s existing
    /// `"<interface>.<tag>"` convention (e.g. `"eth0.100"`).
    pub attach_point: String,
    pub area_id: Ipv4Addr,
    pub hello_interval: u16,
    pub dead_interval: u16,
    pub vrf: String,
    pub local_addr: Ipv4Addr,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LinkStatus {
    pub neighbor_router_id: Option<Ipv4Addr>,
    pub state: NeighborState,
    pub last_hello_received: Option<Instant>,
}

impl Default for LinkStatus {
    fn default() -> Self {
        Self {
            neighbor_router_id: None,
            state: NeighborState::Down,
            last_hello_received: None,
        }
    }
}

pub type StatusHandle = watch::Sender<LinkStatus>;

/// Runs until aborted (link removed from config, or process shutdown — see
/// `LinkManager`). Owns the raw socket, the Hello send ticker, and the
/// dead-interval inactivity timer.
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
    let mut dead_deadline = Instant::now() + Duration::from_secs(u64::from(cfg.dead_interval));

    info!(link = %cfg.attach_point, vrf = %cfg.vrf, "ospf link driver started");

    loop {
        tokio::select! {
            _ = hello_ticker.tick() => {
                send_hello(&socket, &cfg, local_router_id, &status);
            }
            result = socket.recv_hello() => {
                handle_received(result, &cfg, local_router_id, &status, &mut dead_deadline);
            }
            () = tokio::time::sleep_until(dead_deadline) => {
                apply_dead_timer(&cfg, &status);
                dead_deadline = Instant::now() + Duration::from_secs(u64::from(cfg.dead_interval));
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
    let current = *status.borrow();
    let neighbors = match current.state {
        NeighborState::Down => Vec::new(),
        NeighborState::Init | NeighborState::TwoWay => {
            current.neighbor_router_id.into_iter().collect()
        }
    };
    let pkt = HelloPacket {
        router_id: local_router_id,
        area_id: cfg.area_id,
        hello_interval: cfg.hello_interval,
        dead_interval: u32::from(cfg.dead_interval),
        neighbors,
    };
    if let Err(e) = socket.send_hello(&packet::encode_hello(&pkt)) {
        warn!(link = %cfg.attach_point, error = %e, "failed to send ospf hello");
    }
}

fn handle_received(
    result: std::io::Result<Vec<u8>>,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    dead_deadline: &mut Instant,
) {
    let data = match result {
        Ok(received) => received,
        Err(e) => {
            warn!(link = %cfg.attach_point, error = %e, "ospf recv error");
            return;
        }
    };
    let hello = match packet::decode_hello(&data) {
        Ok(hello) => hello,
        Err(e) => {
            warn!(link = %cfg.attach_point, error = %e, "failed to decode ospf hello");
            return;
        }
    };
    // RFC 2328 §10.5's packet-validity check precedes any neighbor event —
    // a mismatched area is logged and dropped, not fed into the FSM.
    if hello.area_id != cfg.area_id {
        warn!(
            link = %cfg.attach_point, area = %hello.area_id, expected = %cfg.area_id,
            "dropping ospf hello with mismatched area"
        );
        return;
    }

    let saw_self = hello.neighbors.contains(&local_router_id);
    let old_state = status.borrow().state;
    let new_state = neighbor::step(old_state, neighbor::Event::HelloReceived { saw_self });
    if old_state == NeighborState::Down && new_state == NeighborState::Init {
        info!(link = %cfg.attach_point, neighbor = %hello.router_id, "ospf neighbor state changed to init");
    }
    if old_state != NeighborState::TwoWay && new_state == NeighborState::TwoWay {
        info!(link = %cfg.attach_point, neighbor = %hello.router_id, "ospf neighbor reached two-way");
    }
    status.send_modify(|s| {
        s.neighbor_router_id = Some(hello.router_id);
        s.state = new_state;
        s.last_hello_received = Some(Instant::now());
    });
    *dead_deadline = Instant::now() + Duration::from_secs(u64::from(cfg.dead_interval));
}

fn apply_dead_timer(cfg: &LinkConfig, status: &StatusHandle) {
    let old_state = status.borrow().state;
    let new_state = neighbor::step(old_state, neighbor::Event::InactivityTimerExpired);
    if old_state != NeighborState::Down {
        warn!(link = %cfg.attach_point, "ospf neighbor state changed to down");
    }
    status.send_modify(|s| s.state = new_state);
}

struct LinkEntry {
    config: LinkConfig,
    task: JoinHandle<()>,
    status: watch::Receiver<LinkStatus>,
}

/// Owns every point-to-point OSPF link's driver task for one `nos-ospfd`
/// process. `reconcile` is the sole entry point, called by
/// `crate::reconcile::run` on every resync; it's idempotent and safe to call
/// repeatedly with the same desired state — mirrors
/// `bgp::session::SessionManager`.
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
            let (status_tx, status_rx) = watch::channel(LinkStatus::default());
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

    /// Every currently-configured link's current neighbor summary, for
    /// `server.rs`'s `OspfRequest::GetNeighbors` handler — backs `nos-cli`'s
    /// `show ospf neigh`.
    pub async fn neighbor_summaries(&self) -> Vec<NeighborSummary> {
        self.links
            .lock()
            .await
            .values()
            .map(to_neighbor_summary)
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

fn to_neighbor_summary(entry: &LinkEntry) -> NeighborSummary {
    let status = *entry.status.borrow();
    NeighborSummary {
        link: entry.config.attach_point.clone(),
        area_id: entry.config.area_id,
        neighbor_router_id: status.neighbor_router_id,
        state: match status.state {
            NeighborState::Down => OspfNeighborState::Down,
            NeighborState::Init => OspfNeighborState::Init,
            NeighborState::TwoWay => OspfNeighborState::TwoWay,
        },
        last_hello_secs: status.last_hello_received.map(|t| t.elapsed().as_secs()),
        hello_interval: entry.config.hello_interval,
        dead_interval: entry.config.dead_interval,
    }
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
    fn default_link_status_is_down_with_nothing_else_known() {
        let status = LinkStatus::default();
        assert_eq!(status.state, NeighborState::Down);
        assert_eq!(status.neighbor_router_id, None);
        assert_eq!(status.last_hello_received, None);
    }
}
