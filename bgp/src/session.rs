use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::tcp;

const BGP_PORT: u16 = 179;

/// Fixed retry interval for a peer's outbound connect attempts — a
/// placeholder for a real `ConnectRetryTimer` (RFC 4271 default: 120s) once
/// the BGP FSM exists; kept shorter here so this first raw-TCP pass
/// reconnects promptly.
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_secs(30);

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

/// A configured peer with the fields needed to open its TCP session —
/// resolved from a `BgpPeer` + its `BgpPeerGroup` (see `reconcile::resync`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPeer {
    pub remote_address: IpAddr,
    pub source_address: Option<IpAddr>,
}

/// Shared between a peer's active-connect task and the (single, shared)
/// passive listener's accept handler, so at most one TCP session per peer
/// is ever held open at a time. See `handle_inbound`/`active_connect_loop`
/// for the collision rule: whichever side flips this flag first wins.
struct PeerSlot {
    peer: ResolvedPeer,
    occupied: AtomicBool,
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

/// Owns every raw-TCP session (active + passive) for one `nos-bgpd`
/// process. `reconcile` is the sole entry point, called by
/// `crate::reconcile::run` on every resync; it's idempotent and safe to
/// call repeatedly with the same desired state.
pub struct SessionManager {
    instance: String,
    peers: Arc<RwLock<HashMap<IpAddr, Arc<PeerSlot>>>>,
    peer_tasks: Mutex<HashMap<IpAddr, PeerTask>>,
    listeners: Mutex<Option<Listeners>>,
    vrf: watch::Sender<VrfRequirement>,
}

impl SessionManager {
    pub fn new(instance: String) -> Arc<Self> {
        let (vrf, _) = watch::channel(VrfRequirement::Pending);
        Arc::new(Self {
            instance,
            peers: Arc::new(RwLock::new(HashMap::new())),
            peer_tasks: Mutex::new(HashMap::new()),
            listeners: Mutex::new(None),
            vrf,
        })
    }

    pub async fn reconcile(self: &Arc<Self>, vrf: VrfRequirement, desired: Vec<ResolvedPeer>) {
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
        if slot
            .occupied
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            // Real RFC 4271 §6.8 collision resolution needs the peer's
            // router-id from an OPEN message, which doesn't exist yet —
            // first-connected-wins is a documented simplification pending
            // the BGP FSM.
            warn!(
                instance = %self.instance, peer = %remote,
                "collision: peer already has an open session, dropping inbound connection"
            );
            return;
        }
        info!(instance = %self.instance, peer = %remote, "accepted inbound bgp tcp session");
        let instance = self.instance.clone();
        tokio::spawn(async move {
            hold_until_closed(stream).await;
            slot.occupied.store(false, Ordering::SeqCst);
            info!(instance = %instance, peer = %remote, "inbound bgp tcp session closed");
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
            let slot = Arc::new(PeerSlot {
                peer: peer.clone(),
                occupied: AtomicBool::new(false),
            });
            self.peers
                .write()
                .await
                .insert(peer.remote_address, slot.clone());
            let task = tokio::spawn(active_connect_loop(
                self.instance.clone(),
                slot,
                self.vrf.subscribe(),
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

/// Blocks until `stream` closes or errors. No BGP message parsing yet —
/// any bytes received are simply discarded until the FSM exists; this only
/// establishes and holds the raw, VRF-scoped TCP session.
async fn hold_until_closed(mut stream: TcpStream) {
    let mut buf = [0u8; 256];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

/// One peer's outbound side: while the VRF is resolved and the slot is
/// free, attempts a connect on a fixed retry interval; on success, holds
/// the session until it closes, then resumes retrying. Runs until aborted
/// by `SessionManager` (peer removed from config, or process shutdown).
async fn active_connect_loop(
    instance: String,
    slot: Arc<PeerSlot>,
    mut vrf: watch::Receiver<VrfRequirement>,
) {
    loop {
        let current_vrf = vrf.borrow().clone();
        if let VrfRequirement::Resolved(vrf_name) = current_vrf {
            if !slot.occupied.load(Ordering::SeqCst) {
                let remote = SocketAddr::new(slot.peer.remote_address, BGP_PORT);
                match tcp::connect(remote, slot.peer.source_address, Some(&vrf_name)).await {
                    Ok(stream) => {
                        if slot
                            .occupied
                            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                            .is_ok()
                        {
                            info!(
                                instance = %instance, peer = %slot.peer.remote_address,
                                "established outbound bgp tcp session"
                            );
                            hold_until_closed(stream).await;
                            slot.occupied.store(false, Ordering::SeqCst);
                            info!(
                                instance = %instance, peer = %slot.peer.remote_address,
                                "outbound bgp tcp session closed"
                            );
                        }
                        // Otherwise an inbound connection claimed the slot
                        // first between our check and this connect
                        // succeeding — drop our own redundant connection.
                    }
                    Err(e) => debug!(
                        instance = %instance, peer = %slot.peer.remote_address, error = %e,
                        "outbound bgp connect failed, retrying"
                    ),
                }
            }
        }
        tokio::select! {
            () = tokio::time::sleep(CONNECT_RETRY_INTERVAL) => {}
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
}
