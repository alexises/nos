use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::collision::{PeerSlot, Role};
use crate::fsm::{self, PeerContext};
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
/// `BgpPeerGroup` (see `reconcile::resync`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPeer {
    pub remote_address: IpAddr,
    pub source_address: Option<IpAddr>,
    pub remote_as: u32,
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
        if *self.vrf.borrow() != vrf {
            let _ = self.vrf.send(vrf.clone());
        }
        self.rebind_listeners(&vrf).await;
        self.reconcile_peers(desired).await;
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
        tokio::spawn(async move {
            let outcome = fsm::run(
                stream,
                Role::Passive,
                local,
                PeerContext {
                    remote_address: remote,
                    expected_remote_as: remote_as,
                },
                slot.clone(),
            )
            .await;
            slot.clear(Role::Passive).await;
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
            ));
            tasks.insert(peer.remote_address, PeerTask { peer, task });
        }
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
                            },
                            slot.clone(),
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
            }
        }
        tokio::select! {
            () = tokio::time::sleep(fsm::CONNECT_RETRY_TIME) => {}
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
        }
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
