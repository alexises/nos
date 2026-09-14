use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use nos_proto::bgp::{BgpSessionState, PeerSummary};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::collision::{PeerSlot, Role};
use crate::fsm::{self, PeerContext};
use crate::rib::BgpRib;
use crate::status::{PeerState, PeerStatus};
use crate::tcp;

const BGP_PORT: u16 = 179;

/// Whether, and how, this `nos-bgpd` instance is scoped into a VRF.
/// Sessions/the listener only ever come up in `Resolved` — see root
/// `CLAUDE.md`'s BGP section for why `Invalid` is a config error, not a
/// "run unscoped" fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VrfRequirement {
    /// The instance has no owning routing table.
    Invalid,
    /// An owning routing table exists but its VRF isn't known yet.
    Pending,
    /// The owning routing table's real Linux VRF interface name.
    Resolved(String),
}

/// This instance's own identity — used to build every OPEN message it sends
/// and to arbitrate RFC 4271 §6.8 collisions. Read fresh (via
/// `SessionManager`'s watch channel) by each connection attempt rather than
/// baked into a peer's task at spawn time, so a config change takes effect
/// on the next connection attempt without needing to restart already-running
/// peer tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalIdentity {
    pub asn: u32,
    pub router_id: Ipv4Addr,
}

/// A configured peer with the fields needed to open its TCP session and
/// validate its OPEN message — resolved from a `BgpPeer` + its
/// `BgpPeerGroup` (see `reconcile::resync`). `hold_time`/`connect_retry_time`
/// are already defaulted (`nos_proto::HOLD_TIME_DEFAULT`/`fsm::CONNECT_RETRY_TIME`)
/// when the peer-group leaves them unset; `keepalive_interval` stays `None`
/// through to `fsm::run`, which derives `negotiated_hold / 3` itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPeer {
    pub remote_address: IpAddr,
    pub source_address: Option<IpAddr>,
    pub remote_as: u32,
    pub peer_group: String,
    pub hold_time: u16,
    pub keepalive_interval: Option<u16>,
    pub connect_retry_time: Duration,
}

struct PeerTask {
    peer: ResolvedPeer,
    task: JoinHandle<()>,
}

struct Listeners {
    vrf: String,
    v4: JoinHandle<()>,
    v6: JoinHandle<()>,
}

/// Owns every raw-TCP + FSM session for one `nos-bgpd` process. `reconcile`
/// is the sole entry point, called by `crate::reconcile::run` on every
/// resync; it's idempotent and safe to call repeatedly with the same
/// desired state.
pub struct SessionManager {
    instance: String,
    local: watch::Sender<LocalIdentity>,
    peers: Arc<RwLock<HashMap<IpAddr, Arc<PeerSlot>>>>,
    peer_tasks: Mutex<HashMap<IpAddr, PeerTask>>,
    listeners: Mutex<Option<Listeners>>,
    vrf: watch::Sender<VrfRequirement>,
    bgp_rib: Arc<Mutex<BgpRib>>,
}

impl SessionManager {
    pub fn new(instance: String) -> Arc<Self> {
        let (vrf, _) = watch::channel(VrfRequirement::Pending);
        let (local, _) = watch::channel(LocalIdentity {
            asn: 0,
            router_id: Ipv4Addr::UNSPECIFIED,
        });
        Arc::new(Self {
            instance,
            local,
            peers: Arc::new(RwLock::new(HashMap::new())),
            peer_tasks: Mutex::new(HashMap::new()),
            listeners: Mutex::new(None),
            vrf,
            bgp_rib: Arc::new(Mutex::new(BgpRib::new())),
        })
    }

    pub async fn reconcile(
        self: &Arc<Self>,
        vrf: VrfRequirement,
        local: LocalIdentity,
        desired: Vec<ResolvedPeer>,
    ) {
        if *self.local.borrow() != local {
            let _ = self.local.send(local);
        }
        self.bgp_rib.lock().await.set_local_asn(local.asn);
        if *self.vrf.borrow() != vrf {
            let _ = self.vrf.send(vrf.clone());
        }
        self.rebind_listeners(&vrf).await;
        self.reconcile_peers(desired).await;
    }

    /// Applies one redistribution update pushed by `nos-ribd`, for
    /// `server.rs`'s fire-and-forget `BgpRequest::RedistributeRoutes` handler.
    pub async fn apply_redistribute_update(&self, update: nos_proto::RedistributeUpdate) {
        self.bgp_rib.lock().await.apply_redistribute_update(update);
    }

    /// Every currently-configured peer's current session summary, for
    /// `server.rs`'s `BgpRequest::GetSummary` handler — backs `nos-cli`'s
    /// `show bgp brief`.
    pub async fn peer_summaries(&self) -> Vec<PeerSummary> {
        self.peers
            .read()
            .await
            .values()
            .map(|slot| to_peer_summary(slot))
            .collect()
    }

    /// Aborts every peer task and the listener, and clears all state.
    /// Called once when `crate::reconcile::run`'s loop exits on shutdown.
    pub async fn shutdown(&self) {
        let mut tasks = self.peer_tasks.lock().await;
        for (_, task) in tasks.drain() {
            task.task.abort();
        }
        drop(tasks);
        self.peers.write().await.clear();
        if let Some(listeners) = self.listeners.lock().await.take() {
            listeners.v4.abort();
            listeners.v6.abort();
        }
    }

    async fn rebind_listeners(self: &Arc<Self>, vrf: &VrfRequirement) {
        let desired_vrf_name = match vrf {
            VrfRequirement::Resolved(name) => Some(name.clone()),
            VrfRequirement::Invalid | VrfRequirement::Pending => None,
        };

        let mut listeners = self.listeners.lock().await;
        let current_vrf_name = listeners.as_ref().map(|l| l.vrf.clone());
        if current_vrf_name == desired_vrf_name {
            return;
        }
        if let Some(old) = listeners.take() {
            old.v4.abort();
            old.v6.abort();
            info!(instance = %self.instance, vrf = %old.vrf, "bgp listener torn down");
        }
        if let Some(name) = desired_vrf_name {
            match self.spawn_listeners(&name) {
                Ok(new) => {
                    info!(instance = %self.instance, vrf = %name, "bgp listener bound");
                    *listeners = Some(new);
                }
                Err(e) => warn!(
                    instance = %self.instance, vrf = %name, error = %e,
                    "failed to bind bgp listener"
                ),
            }
        }
    }

    fn spawn_listeners(self: &Arc<Self>, vrf: &str) -> io::Result<Listeners> {
        let v4_listener = tcp::bind_listener(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), BGP_PORT),
            Some(vrf),
        )?;
        let v6_listener = tcp::bind_listener(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), BGP_PORT),
            Some(vrf),
        )?;
        let v4 = tokio::spawn(self.clone().accept_loop(v4_listener));
        let v6 = tokio::spawn(self.clone().accept_loop(v6_listener));
        Ok(Listeners {
            vrf: vrf.to_string(),
            v4,
            v6,
        })
    }

    async fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => self.handle_inbound(stream, addr.ip()).await,
                Err(e) => {
                    warn!(instance = %self.instance, error = %e, "bgp listener accept failed");
                }
            }
        }
    }

    async fn handle_inbound(self: &Arc<Self>, stream: TcpStream, remote: IpAddr) {
        let slot = self.peers.read().await.get(&remote).cloned();
        let Some(slot) = slot else {
            debug!(
                instance = %self.instance, peer = %remote,
                "rejecting inbound tcp connection from unconfigured peer"
            );
            return;
        };
        if !slot.begin(Role::Passive).await {
            debug!(
                instance = %self.instance, peer = %remote,
                "rejecting inbound tcp connection: a previous inbound session for this peer is still being torn down"
            );
            return;
        }
        info!(instance = %self.instance, peer = %remote, "accepted inbound bgp tcp session");
        let instance = self.instance.clone();
        let local = *self.local.borrow();
        let remote_as = slot.peer.remote_as;
        let local_hold_time = slot.peer.hold_time;
        let keepalive_override = slot.peer.keepalive_interval;
        let bgp_rib = self.bgp_rib.clone();
        tokio::spawn(async move {
            let outcome = fsm::run(
                stream,
                Role::Passive,
                local,
                PeerContext {
                    remote_address: remote,
                    expected_remote_as: remote_as,
                    local_hold_time,
                    keepalive_override,
                },
                slot.clone(),
                bgp_rib,
            )
            .await;
            slot.clear(Role::Passive).await;
            reset_status_if_not_established(&slot).await;
            info!(instance = %instance, peer = %remote, outcome = ?outcome, "inbound bgp session ended");
        });
    }

    async fn reconcile_peers(self: &Arc<Self>, desired: Vec<ResolvedPeer>) {
        let desired: HashMap<IpAddr, ResolvedPeer> =
            desired.into_iter().map(|p| (p.remote_address, p)).collect();

        let mut tasks = self.peer_tasks.lock().await;
        let current: HashMap<IpAddr, ResolvedPeer> = tasks
            .iter()
            .map(|(addr, t)| (*addr, t.peer.clone()))
            .collect();
        let (to_stop, to_spawn) = diff_peers(&current, &desired);

        for addr in to_stop {
            if let Some(task) = tasks.remove(&addr) {
                task.task.abort();
            }
            self.peers.write().await.remove(&addr);
        }
        for peer in to_spawn {
            let slot = PeerSlot::new(peer.clone());
            self.peers
                .write()
                .await
                .insert(peer.remote_address, slot.clone());
            let task = tokio::spawn(active_connect_loop(
                self.instance.clone(),
                slot,
                self.vrf.subscribe(),
                self.local.subscribe(),
                self.bgp_rib.clone(),
            ));
            tasks.insert(peer.remote_address, PeerTask { peer, task });
        }
    }
}

/// Snapshots one peer's current status into the wire-serializable
/// `PeerSummary` — `PeerStatus.established_since` (a `tokio::time::Instant`)
/// isn't itself meaningful to another process, so it's converted to an
/// uptime measured right now instead.
fn to_peer_summary(slot: &PeerSlot) -> PeerSummary {
    let status = *slot.status_receiver().borrow();
    PeerSummary {
        remote_address: slot.peer.remote_address,
        peer_group: slot.peer.peer_group.clone(),
        remote_as: status.remote_asn,
        remote_bgp_id: status.remote_bgp_id,
        state: match status.state {
            PeerState::Idle => BgpSessionState::Idle,
            PeerState::OpenSent => BgpSessionState::OpenSent,
            PeerState::OpenConfirm => BgpSessionState::OpenConfirm,
            PeerState::Established => BgpSessionState::Established,
        },
        uptime_secs: status
            .established_since
            .map(|since| Instant::now().duration_since(since).as_secs()),
        negotiated_hold_time: status.negotiated_hold_time,
        negotiated_keepalive: status.negotiated_keepalive,
    }
}

/// Resets a peer's reported status to `Idle` once one of its connections has
/// ended — but only if no session remains `Established` via the other role
/// (mirrors the guard in `fsm::run`'s own initial status write): a
/// losing/redundant connection ending must never clobber the winning
/// connection's already-reported `Established` status.
async fn reset_status_if_not_established(slot: &PeerSlot) {
    if !slot.is_established().await {
        slot.status.send_modify(|s| *s = PeerStatus::default());
    }
}

/// Diffs `current` (what's running) against `desired` (what config wants):
/// peers no longer desired, or whose fields changed, are stopped (and, if
/// still desired with new fields, respawned); newly desired peers are
/// spawned. Pure and synchronous, like `interface`'s `diff_addresses`.
fn diff_peers(
    current: &HashMap<IpAddr, ResolvedPeer>,
    desired: &HashMap<IpAddr, ResolvedPeer>,
) -> (Vec<IpAddr>, Vec<ResolvedPeer>) {
    let mut to_stop = Vec::new();
    let mut to_spawn = Vec::new();

    for (addr, running) in current {
        match desired.get(addr) {
            None => to_stop.push(*addr),
            Some(wanted) if wanted != running => {
                to_stop.push(*addr);
                to_spawn.push(wanted.clone());
            }
            Some(_) => {}
        }
    }
    for (addr, wanted) in desired {
        if !current.contains_key(addr) {
            to_spawn.push(wanted.clone());
        }
    }

    (to_stop, to_spawn)
}

/// One peer's outbound side: while the VRF is resolved, attempts a connect
/// on a fixed retry interval; on success, runs the FSM until the session
/// ends, then resumes retrying. Runs until aborted by `SessionManager`
/// (peer removed from config, or process shutdown).
async fn active_connect_loop(
    instance: String,
    slot: Arc<PeerSlot>,
    mut vrf: watch::Receiver<VrfRequirement>,
    local: watch::Receiver<LocalIdentity>,
    bgp_rib: Arc<Mutex<BgpRib>>,
) {
    loop {
        let current_vrf = vrf.borrow().clone();
        if let VrfRequirement::Resolved(vrf_name) = current_vrf {
            if slot.is_established().await {
                // Already up (via either role) — dialing out again would
                // just create a pointless collision the existing session
                // would win anyway. Wait for the retry interval (or a VRF
                // change) and check again, rather than actually connecting.
            } else if slot.begin(Role::Active).await {
                let remote = SocketAddr::new(slot.peer.remote_address, BGP_PORT);
                match tcp::connect(remote, slot.peer.source_address, Some(&vrf_name)).await {
                    Ok(stream) => {
                        info!(
                            instance = %instance, peer = %slot.peer.remote_address,
                            "established outbound bgp tcp connection"
                        );
                        let local_identity = *local.borrow();
                        let outcome = fsm::run(
                            stream,
                            Role::Active,
                            local_identity,
                            PeerContext {
                                remote_address: slot.peer.remote_address,
                                expected_remote_as: slot.peer.remote_as,
                                local_hold_time: slot.peer.hold_time,
                                keepalive_override: slot.peer.keepalive_interval,
                            },
                            slot.clone(),
                            bgp_rib.clone(),
                        )
                        .await;
                        info!(
                            instance = %instance, peer = %slot.peer.remote_address,
                            outcome = ?outcome, "outbound bgp session ended"
                        );
                    }
                    Err(e) => debug!(
                        instance = %instance, peer = %slot.peer.remote_address, error = %e,
                        "outbound bgp connect failed, retrying"
                    ),
                }
                slot.clear(Role::Active).await;
                reset_status_if_not_established(&slot).await;
            }
        }
        tokio::select! {
            () = tokio::time::sleep(slot.peer.connect_retry_time) => {}
            _ = vrf.changed() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(addr: &str) -> ResolvedPeer {
        ResolvedPeer {
            remote_address: addr.parse().unwrap(),
            source_address: None,
            remote_as: 65000,
            peer_group: "pg1".to_string(),
            hold_time: 90,
            keepalive_interval: None,
            connect_retry_time: fsm::CONNECT_RETRY_TIME,
        }
    }

    #[test]
    fn to_peer_summary_of_a_never_connected_peer_is_idle() {
        let slot = PeerSlot::new(peer("10.0.0.1"));
        let summary = to_peer_summary(&slot);
        assert_eq!(
            summary.remote_address,
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(summary.peer_group, "pg1");
        assert_eq!(summary.remote_as, None);
        assert_eq!(summary.remote_bgp_id, None);
        assert_eq!(summary.state, BgpSessionState::Idle);
        assert_eq!(summary.uptime_secs, None);
        assert_eq!(summary.negotiated_hold_time, None);
        assert_eq!(summary.negotiated_keepalive, None);
    }

    #[test]
    fn new_peer_is_spawned() {
        let current = HashMap::new();
        let desired = HashMap::from([("10.0.0.1".parse().unwrap(), peer("10.0.0.1"))]);
        let (to_stop, to_spawn) = diff_peers(&current, &desired);
        assert!(to_stop.is_empty());
        assert_eq!(to_spawn, vec![peer("10.0.0.1")]);
    }

    #[test]
    fn removed_peer_is_stopped() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        let current = HashMap::from([(addr, peer("10.0.0.1"))]);
        let desired = HashMap::new();
        let (to_stop, to_spawn) = diff_peers(&current, &desired);
        assert_eq!(to_stop, vec![addr]);
        assert!(to_spawn.is_empty());
    }

    #[test]
    fn unchanged_peer_is_left_alone() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        let current = HashMap::from([(addr, peer("10.0.0.1"))]);
        let desired = HashMap::from([(addr, peer("10.0.0.1"))]);
        let (to_stop, to_spawn) = diff_peers(&current, &desired);
        assert!(to_stop.is_empty());
        assert!(to_spawn.is_empty());
    }

    #[test]
    fn changed_peer_is_restarted() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        let current = HashMap::from([(addr, peer("10.0.0.1"))]);
        let mut changed = peer("10.0.0.1");
        changed.source_address = Some("10.0.0.9".parse().unwrap());
        let desired = HashMap::from([(addr, changed.clone())]);
        let (to_stop, to_spawn) = diff_peers(&current, &desired);
        assert_eq!(to_stop, vec![addr]);
        assert_eq!(to_spawn, vec![changed]);
    }

    #[test]
    fn remote_as_change_triggers_restart() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        let current = HashMap::from([(addr, peer("10.0.0.1"))]);
        let mut changed = peer("10.0.0.1");
        changed.remote_as = 65001;
        let desired = HashMap::from([(addr, changed.clone())]);
        let (to_stop, to_spawn) = diff_peers(&current, &desired);
        assert_eq!(to_stop, vec![addr]);
        assert_eq!(to_spawn, vec![changed]);
    }
}
