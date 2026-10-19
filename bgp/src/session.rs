use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ipnet::IpNet;
use nos_proto::bgp::{BgpSessionState, PeerSummary};
use nos_proto::{AddressFamily, BgpAoAlgorithm, BgpAuth, BgpShutdown, NextHopMode, RpkiCache};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::collision::{FsmCommand, PeerSlot, Role};
use crate::fsm::{self, PeerContext};
use crate::gr::Disconnect;
use crate::message::CeaseSubcode;
use crate::rib::{BgpRib, SharedRib};
use crate::rpki;
use crate::status::{PeerState, PeerStatus};
use crate::tcp;

const BGP_PORT: u16 = 179;

/// How long after a VRP change the policy-reading peers are asked for a
/// route refresh — a burst of serials (or a cache switch) costs one refresh.
const RPKI_REFRESH_DELAY: Duration = Duration::from_secs(5);

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
    /// This instance's effective RFC 4456 cluster-id
    /// (`BgpInstance.cluster_id.unwrap_or(router_id)`, computed by
    /// `reconcile::resync`) — threaded straight through to
    /// `crate::rib::BgpRib::set_local_identity`.
    pub cluster_id: Ipv4Addr,
    /// RFC 5065 confederation identifier, when this instance is a member —
    /// `asn` is then its member AS. Threaded to
    /// `crate::rib::BgpRib::set_confederation`.
    pub confed_id: Option<u32>,
}

/// A configured peer with the fields needed to open its TCP session and
/// validate its OPEN message — resolved from a `BgpPeer` + its
/// `BgpPeerGroup` (see `reconcile::resync`). `hold_time`/`connect_retry_time`
/// are already defaulted (`nos_proto::HOLD_TIME_DEFAULT`/`fsm::CONNECT_RETRY_TIME`)
/// when the peer-group leaves them unset; `keepalive_interval` stays `None`
/// through to `fsm::run`, which derives `negotiated_hold / 3` itself.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // independent per-peer-group flags
pub struct ResolvedPeer {
    pub remote_address: IpAddr,
    pub source_address: Option<IpAddr>,
    pub remote_as: u32,
    pub peer_group: String,
    pub hold_time: u16,
    pub keepalive_interval: Option<u16>,
    pub connect_retry_time: Duration,
    /// RFC 4271 §9.2.1.1; zero disables pacing (see `crate::mrai`).
    pub mrai: Duration,
    /// RFC 7313 §4 stale-route bound after a `BoRR`; zero disables it.
    pub route_refresh_stale_time: Duration,
    /// RFC 2439 flap damping of routes received from this peer.
    pub damping: Option<nos_proto::BgpDamping>,
    /// RFC 5082 GTSM hop count (see `tcp::apply_max_hops`); `None` = off.
    pub max_hops: Option<u8>,
    pub auth: Option<ResolvedAuth>,
    /// The owning peer-group's configured next-hop override, if any —
    /// threaded straight through to `fsm::PeerContext`.
    pub next_hop: Option<NextHopMode>,
    /// The owning peer-group's configured address families — threaded
    /// straight through to `fsm::PeerContext`, independent of
    /// `remote_address`'s own family (RFC 8950).
    pub address_families: Vec<AddressFamily>,
    /// The owning peer-group's `route_reflector_client`/`route_server_client`
    /// — threaded straight through to `fsm::PeerContext`.
    pub route_reflector_client: bool,
    pub route_server_client: bool,
    /// The owning peer-group's resolved import/export policy — always
    /// present, `deny-all` by default (see root `CLAUDE.md`'s "Default-deny
    /// rollout impact"), resolved by `reconcile::resync` from the
    /// peer-group's `import_policy`/`export_policy` names.
    pub import_policy: Arc<nos_rpl::CompiledPolicy>,
    pub export_policy: Arc<nos_rpl::CompiledPolicy>,
    /// Effective administrative shutdown (the peer's own, else its
    /// peer-group's): no session is opened or accepted while set.
    pub shutdown: Option<BgpShutdown>,
    /// The peer-group's RFC 4486 maximum-prefix limits.
    pub maximum_prefix: nos_proto::BgpMaximumPrefix,
    /// The peer-group's RFC 8097 `announce_rpki_state` (see `BgpRib::set_peer_rpki_state`).
    pub announce_rpki_state: bool,
    /// The peer-group's vendor `local-as` (see `BgpRib::set_peer_local_as`).
    pub local_as: Option<nos_proto::BgpLocalAs>,
    /// RFC 7911 ADD-PATH mode with its default applied
    /// (`BgpPeerGroup::effective_add_path`); in the OPEN, so a change
    /// restarts the session (`diff_peers`).
    pub add_path: Option<nos_proto::BgpAddPath>,
    /// How many paths per prefix ADD-PATH send gives this peer
    /// (`BgpPeerGroup::effective_add_path_send_count`, `None`: every path;
    /// `BgpRib::set_peer_add_path_send_count`). Not in the OPEN, but a change
    /// restarts the session like every field (`diff_peers`). ponytail: re-run
    /// the fan-out for the peer instead, if anyone tunes it on a live router.
    pub add_path_send_count: Option<usize>,
    /// RFC 9234 role announced in the OPEN, and strict mode (a peer with no
    /// Role is refused). In the OPEN, so a change restarts the session.
    pub role: Option<nos_proto::BgpRole>,
    pub strict_mode: bool,
    /// RFC 5065: this instance's confederation identifier (what an
    /// external peer's OPEN carries), and whether `remote_as` is another
    /// member AS. Here rather than read from `LocalIdentity` so a change
    /// restarts the session (`diff_peers`).
    pub confed_id: Option<u32>,
    pub confed_member: bool,
    /// RFC 4724 graceful restart: our Restart Time, `None` when the
    /// instance turned it off. Here because it goes into the OPEN, so a
    /// change restarts the session (`diff_peers`).
    pub graceful_restart: Option<u16>,
}

/// RFC 5065 §2: how a peer relates to this instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerKind {
    /// Same AS (the member AS, in a confederation).
    Internal,
    /// Another member AS of our confederation.
    ConfedExternal,
    External,
}

impl ResolvedPeer {
    pub fn kind(&self, local_asn: u32) -> PeerKind {
        if self.remote_as == local_asn {
            PeerKind::Internal
        } else if self.confed_member {
            PeerKind::ConfedExternal
        } else {
            PeerKind::External
        }
    }

    /// The AS this instance presents in its OPEN to this peer (RFC 5065
    /// §4): the confederation identifier to an external peer, else `asn` —
    /// or the peer-group's `local-as`, for an external peer.
    pub fn open_as(&self, local_asn: u32) -> u32 {
        match self.kind(local_asn) {
            PeerKind::External => self
                .local_as
                .map_or(self.confed_id.unwrap_or(local_asn), |l| l.asn),
            PeerKind::Internal | PeerKind::ConfedExternal => local_asn,
        }
    }
}

/// A peer-group's `BgpAuth` translated into `nos-tcp-auth`'s wire-level
/// types — resolved once by `reconcile::resync`, then applied at the socket
/// level (never touched by `fsm.rs`, since authentication is verified by
/// the kernel before a `TcpStream` even exists). Mirrors `BgpAuth`'s own
/// mutual exclusion between MD5 and TCP-AO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedAuth {
    Md5(String),
    Ao(Vec<nos_tcp_auth::AoKey>),
}

impl From<&BgpAuth> for ResolvedAuth {
    fn from(auth: &BgpAuth) -> Self {
        match auth {
            BgpAuth::Md5 { password } => ResolvedAuth::Md5(password.clone()),
            BgpAuth::Ao { keys } => ResolvedAuth::Ao(
                keys.iter()
                    .map(|k| nos_tcp_auth::AoKey {
                        send_id: k.send_id,
                        recv_id: k.recv_id,
                        algorithm: match k.algorithm {
                            BgpAoAlgorithm::HmacSha1_96 => nos_tcp_auth::AoAlgorithm::HmacSha1_96,
                            BgpAoAlgorithm::AesCmac96 => nos_tcp_auth::AoAlgorithm::AesCmac96,
                        },
                        key: k.key.clone().into_bytes(),
                        set_current: k.is_current,
                        set_rnext: k.is_rnext,
                        exclude_options: k.exclude_options,
                    })
                    .collect(),
            ),
        }
    }
}

/// The key a connection advertises as its `RNextKeyID` (RFC 5925 §7.5): the
/// one flagged `is_rnext`, else the `is_current` one — so "no rnext" means
/// "don't ask the peer to switch". `None` for an empty list.
pub fn ao_rnext(keys: &[nos_tcp_auth::AoKey]) -> Option<&nos_tcp_auth::AoKey> {
    keys.iter()
        .find(|k| k.set_rnext)
        .or_else(|| keys.iter().find(|k| k.set_current))
        .or_else(|| keys.first())
}

/// What changed between two TCP-AO key lists for one peer, applicable to a
/// live socket without a reset (see `ao_delta`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AoDelta {
    pub add: Vec<nos_tcp_auth::AoKey>,
    /// `(send_id, recv_id)` of keys to delete.
    pub remove: Vec<(u8, u8)>,
    /// `RecvID` of the key to advertise as `RNextKeyID` afterwards.
    pub rnext_recv_id: u8,
}

/// The in-place delta from `old` to `new`, or `None` when the session has to
/// restart: either side is MD5 (or absent), or a kept key's material changed
/// (an MKT is immutable for a connection), or an added key's `RecvID` is one a
/// removed key still holds (the kernel refuses overlapping IDs, RFC 5925
/// §3.1, and adds run before deletes). Moving `is_current`/`is_rnext` is
/// in-place: the kernel follows the peer's `RNextKeyID` per connection
/// (§7.5.2), so only rnext is ever pushed to a live socket.
pub fn ao_delta(old: &ResolvedAuth, new: &ResolvedAuth) -> Option<AoDelta> {
    let (ResolvedAuth::Ao(old), ResolvedAuth::Ao(new)) = (old, new) else {
        return None;
    };
    let mut add = Vec::new();
    for key in new {
        match old.iter().find(|k| k.send_id == key.send_id) {
            None => add.push(key.clone()),
            Some(kept)
                if kept.recv_id != key.recv_id
                    || kept.algorithm != key.algorithm
                    || kept.key != key.key
                    || kept.exclude_options != key.exclude_options =>
            {
                return None;
            }
            Some(_) => {}
        }
    }
    let remove: Vec<(u8, u8)> = old
        .iter()
        .filter(|k| !new.iter().any(|n| n.send_id == k.send_id))
        .map(|k| (k.send_id, k.recv_id))
        .collect();
    if add
        .iter()
        .any(|a| remove.iter().any(|&(_, recv)| recv == a.recv_id))
    {
        return None;
    }
    Some(AoDelta {
        add,
        remove,
        rnext_recv_id: ao_rnext(new)?.recv_id,
    })
}

struct PeerTask {
    peer: ResolvedPeer,
    /// `None` for an administratively shut peer, which never dials out.
    task: Option<JoinHandle<()>>,
}

struct Listeners {
    vrf: String,
    v4: JoinHandle<()>,
    v6: JoinHandle<()>,
    /// Raw fds of the (still-owned-by-the-accept-loop-task) v4/v6 listening
    /// sockets — kept so incremental auth key changes can be applied to an
    /// already-bound-and-listening socket without needing to hold the
    /// `TcpListener` itself (it was moved into `accept_loop`'s spawned
    /// future). Valid for exactly as long as `v4`/`v6` haven't been aborted.
    v4_fd: RawFd,
    v6_fd: RawFd,
    /// Which peer address currently has which auth key installed on
    /// whichever of `v4_fd`/`v6_fd` matches its IP family — tracked so a
    /// later peer removal/change knows what to uninstall before installing
    /// the new state.
    applied_auth: HashMap<IpAddr, ResolvedAuth>,
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
    bgp_rib: Arc<SharedRib>,
    /// The listener's port and the port peers are dialed on — both 179
    /// except in `with_listen`'s localhost tests.
    listen_port: u16,
    peer_port: u16,
    /// Scope sockets into the resolved VRF (`SO_BINDTODEVICE`). Always true
    /// except in `with_listen`'s tests; nothing in config reaches it.
    bind_vrf: bool,
    /// The RTR client (`rpki::Client`) and the task applying its VRP sets.
    rpki: Mutex<Option<(rpki::Client, JoinHandle<()>)>>,
    /// The BFD sessions `reconcile::resync` wants; `bfd_client` registers them.
    bfd_targets: watch::Sender<crate::bfd_client::Target>,
}

/// `SessionManager::applied`.
#[cfg(test)]
pub(crate) struct Applied {
    pub peers: Vec<ResolvedPeer>,
    pub vrf: VrfRequirement,
    pub local: LocalIdentity,
    /// `None` while deferring (`BgpRib::push_snapshot` hides it).
    pub routing_table: Option<String>,
    pub fdb_domains: Vec<String>,
    pub evpn_tables: Vec<String>,
    pub deferral_waiting: Option<Vec<IpAddr>>,
}

/// What a BFD Down does to `peer` (RFC 5882 §4.3, RFC 9384).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BfdAction {
    /// Cease/10; `flush` wraps it in a Hard Reset so the peer drops our routes.
    Close {
        flush: bool,
    },
    /// Not established, routes held stale: act as if the restart timer expired.
    AbortGr,
    Nothing,
}

/// `cpi`: the C bit is set at both ends, so BFD is a forwarding verdict
/// independent of the control plane. Otherwise BFD fails along with a
/// restart and must not cancel the graceful restart (§4.3.2).
pub fn bfd_action(established: bool, has_stale: bool, cpi: bool) -> BfdAction {
    if established {
        BfdAction::Close { flush: cpi }
    } else if has_stale && cpi {
        BfdAction::AbortGr
    } else {
        BfdAction::Nothing
    }
}

impl SessionManager {
    pub fn new(instance: String) -> Arc<Self> {
        Self::with_listen(instance, BGP_PORT, BGP_PORT, true)
    }

    /// Test seam (#131): listen on `listen_port`, dial peers on `peer_port`,
    /// and, with `bind_vrf = false`, open every socket unscoped so two
    /// instances can peer over localhost without privileges. `pub` (not
    /// `cfg(test)`) only because `bgp/tests/` needs it; `main.rs` and config
    /// never call it, so `VrfRequirement` keeps its meaning in production.
    #[doc(hidden)]
    pub fn with_listen(
        instance: String,
        listen_port: u16,
        peer_port: u16,
        bind_vrf: bool,
    ) -> Arc<Self> {
        let (vrf, _) = watch::channel(VrfRequirement::Pending);
        let (local, _) = watch::channel(LocalIdentity {
            asn: 0,
            router_id: Ipv4Addr::UNSPECIFIED,
            cluster_id: Ipv4Addr::UNSPECIFIED,
            confed_id: None,
        });
        Arc::new(Self {
            instance,
            local,
            peers: Arc::new(RwLock::new(HashMap::new())),
            peer_tasks: Mutex::new(HashMap::new()),
            listeners: Mutex::new(None),
            vrf,
            bgp_rib: Arc::new(SharedRib::new(BgpRib::new())),
            listen_port,
            peer_port,
            bind_vrf,
            rpki: Mutex::new(None),
            bfd_targets: watch::channel(crate::bfd_client::Target::default()).0,
        })
    }

    /// What the last `reconcile` applied, for `reconcile::tests` (#344).
    #[cfg(test)]
    pub(crate) async fn applied(&self) -> Applied {
        let mut peers: Vec<ResolvedPeer> = self
            .peers
            .read()
            .await
            .values()
            .map(|s| s.peer.clone())
            .collect();
        peers.sort_by_key(|p| p.remote_address);
        let rib = self.bgp_rib.lock().await;
        Applied {
            peers,
            vrf: self.vrf.borrow().clone(),
            local: *self.local.borrow(),
            routing_table: rib.push_snapshot().0,
            fdb_domains: rib.fdb_domains().to_vec(),
            evpn_tables: rib.evpn_tables().to_vec(),
            deferral_waiting: rib.deferral_waiting(),
        }
    }

    pub fn bfd_targets(&self) -> watch::Receiver<crate::bfd_client::Target> {
        self.bfd_targets.subscribe()
    }

    pub fn set_bfd_targets(&self, target: crate::bfd_client::Target) {
        self.bfd_targets.send_if_modified(|t| {
            let changed = *t != target;
            if changed {
                *t = target;
            }
            changed
        });
    }

    /// `nos-bfdd` reported `peer`'s session went `Up` -> `Down`.
    pub async fn bfd_down(&self, peer: IpAddr, cpi: bool) {
        let slot = self.peers.read().await.get(&peer).cloned();
        let established = match &slot {
            Some(s) => s.is_established().await,
            None => false,
        };
        let has_stale = !established && self.bgp_rib.lock().await.stale_count(peer) > 0;
        match bfd_action(established, has_stale, cpi) {
            BfdAction::Close { flush } => {
                if let Some(slot) = slot {
                    slot.send_command(FsmCommand::BfdDown { flush });
                }
            }
            BfdAction::AbortGr => {
                self.bgp_rib.lock().await.gr_abort(peer);
            }
            BfdAction::Nothing => {}
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn reconcile(
        self: &Arc<Self>,
        vrf: VrfRequirement,
        routing_table: Option<String>,
        local: LocalIdentity,
        desired: Vec<ResolvedPeer>,
        redistribute_policy: Arc<nos_rpl::CompiledPolicy>,
        fdb_domains: Vec<String>,
        evpn_tables: Vec<String>,
        rpki_caches: &[RpkiCache],
    ) {
        // `send_replace`, not `send`: `send` leaves the value unchanged when
        // no receiver exists yet — true on the very first reconcile, before
        // any peer task subscribed — so peers used to start with the
        // placeholder identity/`Pending` VRF until the 10s re-apply (#131).
        if *self.local.borrow() != local {
            self.local.send_replace(local);
        }
        {
            let mut bgp_rib = self.bgp_rib.lock().await;
            bgp_rib.set_local_identity(local.asn, local.router_id, local.cluster_id);
            bgp_rib.set_confederation(local.confed_id);
            bgp_rib.set_routing_table(routing_table);
            bgp_rib.set_redistribute_policy(redistribute_policy);
            bgp_rib.set_fdb_domains(fdb_domains);
            bgp_rib.set_evpn_tables(evpn_tables);
        }
        if *self.vrf.borrow() != vrf {
            self.vrf.send_replace(vrf.clone());
        }
        self.rebind_listeners(&vrf, &desired).await;
        self.reconcile_peers(desired).await;
        self.reconcile_rpki(rpki_caches, &vrf).await;
    }

    /// (Re)starts the RTR client when the cache list or the VRF changes. It
    /// runs only once the VRF is resolved, like the sessions; without caches
    /// the VRP set is emptied, so every route is `not_found` again.
    async fn reconcile_rpki(self: &Arc<Self>, caches: &[RpkiCache], vrf: &VrfRequirement) {
        let want = match vrf {
            VrfRequirement::Resolved(name) if !caches.is_empty() => Some((
                rpki::sorted(caches.to_vec()),
                self.bind_vrf.then(|| name.clone()),
            )),
            _ => None,
        };
        let mut rpki = self.rpki.lock().await;
        let have = rpki
            .as_ref()
            .map(|(c, _)| (c.caches.clone(), c.vrf.clone()));
        if want == have {
            return;
        }
        if let Some((client, applier)) = rpki.take() {
            client.task.abort();
            applier.abort();
            info!(instance = %self.instance, "rpki client stopped");
        }
        if caches.is_empty() && !self.bgp_rib.lock().await.vrps().is_empty() {
            self.bgp_rib.lock().await.set_vrps(Arc::default());
        }
        if let Some((caches, vrf)) = want {
            let current = self.bgp_rib.lock().await.vrps();
            let (client, rx) = rpki::Client::spawn(&caches, vrf, current);
            let applier = tokio::spawn(self.clone().apply_vrps(rx));
            info!(instance = %self.instance, caches = caches.len(), "rpki client started");
            *rpki = Some((client, applier));
        }
    }

    /// Installs every VRP set the RTR client publishes, then — once per
    /// `RPKI_REFRESH_DELAY` — asks each established peer whose import policy
    /// reads `this.bgp.validation_state` for a route refresh: a route that
    /// policy rejected isn't held, so only the peer can give it back.
    async fn apply_vrps(self: Arc<Self>, mut rx: watch::Receiver<Arc<rpki::VrpTable>>) {
        let mut refresh_at: Option<Instant> = None;
        loop {
            tokio::select! {
                changed = rx.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    let vrps = rx.borrow_and_update().clone();
                    self.bgp_rib.lock().await.set_vrps(vrps);
                    refresh_at.get_or_insert_with(|| Instant::now() + RPKI_REFRESH_DELAY);
                }
                () = tokio::time::sleep_until(refresh_at.unwrap_or_else(Instant::now)), if refresh_at.is_some() => {
                    refresh_at = None;
                    let slots: Vec<Arc<PeerSlot>> = self.peers.read().await.values().cloned().collect();
                    for slot in slots {
                        if slot.peer.import_policy.reads_validation_state()
                            && slot.is_established().await
                            && slot.send_command(FsmCommand::SendRouteRefresh)
                        {
                            info!(
                                instance = %self.instance, peer = %slot.peer.remote_address,
                                "rpki change: requesting route refresh"
                            );
                        }
                    }
                }
            }
        }
    }

    /// Every configured RPKI cache's RTR session, for `show bgp rpki`.
    pub async fn rpki_summaries(&self) -> Vec<nos_proto::RpkiCacheStatus> {
        self.rpki
            .lock()
            .await
            .as_ref()
            .map(|(client, _)| rpki::summaries(&client.status))
            .unwrap_or_default()
    }

    /// Applies one redistribution update pushed by `nos-ribd`, for
    /// `server.rs`'s fire-and-forget `BgpRequest::RedistributeRoutes` handler.
    pub async fn apply_redistribute_update(&self, update: nos_proto::RedistributeUpdate) {
        self.bgp_rib.lock().await.apply_redistribute_update(update);
    }

    /// One `nos-fdbd`'s local MACs (`BgpRequest::RedistributeMacs`).
    pub async fn apply_evpn_local(&self, domain: &str, update: nos_proto::EvpnUpdate) {
        self.bgp_rib.lock().await.apply_evpn_local(domain, update);
    }

    /// One `nos-ribd`'s IP-VRF Type-5 routes (`BgpRequest::RedistributeEvpnPrefixes`).
    pub async fn apply_evpn_prefixes(&self, table: &str, update: nos_proto::EvpnUpdate) {
        self.bgp_rib
            .lock()
            .await
            .apply_evpn_source(crate::rib::EvpnSource::Table(table.to_string()), update);
    }

    /// The consumers `fdb_push_client` feeds and what to feed them: every
    /// received Type-5 route to the IP-VRF routing tables (`to_tables`), every
    /// other received EVPN route to the broadcast domains, and a symmetric IRB
    /// MAC+IP to both (`rib::evpn_feeds`) — so `nos-fdbd` never sees a Type-5.
    pub async fn evpn_feed_snapshot(
        &self,
        to_tables: bool,
    ) -> (
        Vec<String>,
        HashMap<nos_proto::EvpnKey, nos_proto::EvpnRoute>,
    ) {
        let rib = self.bgp_rib.lock().await;
        // Deferring (graceful restart): the consumers keep what they hold.
        if rib.deferring() {
            return (Vec::new(), HashMap::new());
        }
        let targets = if to_tables {
            rib.evpn_tables()
        } else {
            rib.fdb_domains()
        };
        let mut routes = rib.evpn_push_snapshot();
        routes.retain(|_, r| crate::rib::evpn_feeds(r, to_tables));
        (targets.to_vec(), routes)
    }

    /// Decays flap-damping penalties and re-decides any released prefixes,
    /// and purges graceful-restart stale routes whose timer expired.
    pub async fn damping_tick(&self) {
        let mut rib = self.bgp_rib.lock().await;
        rib.damping_tick();
        rib.gr_tick();
    }

    /// RFC 4724 §4.1: `nos-ribd` kept `routes` BGP routes across this
    /// process's restart — see `BgpRib::begin_deferral`.
    pub async fn begin_deferral(
        &self,
        routes: u32,
        restart_time: u16,
        selection_deferral_time: u16,
        peers: impl IntoIterator<Item = IpAddr>,
    ) {
        self.bgp_rib.lock().await.begin_deferral(
            routes,
            restart_time,
            selection_deferral_time,
            peers,
        );
    }

    /// `BgpInstance.graceful_restart`'s stale time, for the RIB.
    pub async fn set_gr_stale_time(&self, secs: u16) {
        self.bgp_rib.lock().await.set_gr_stale_time(secs);
    }

    /// Expires old EVPN MAC-mobility move history and lifts any freeze whose
    /// window has passed quietly.
    pub async fn mac_mobility_tick(&self) {
        self.bgp_rib.lock().await.mac_mobility_tick();
    }

    /// Installs the IGP cost table polled by `igp_client`.
    pub async fn set_igp(&self, igp: std::collections::HashMap<IpNet, u32>) {
        self.bgp_rib.lock().await.set_igp(igp);
    }

    /// `BgpInstance.maximum_paths`, for the RIB's multipath selection.
    pub async fn set_maximum_paths(&self, maximum_paths: Option<u8>) {
        self.bgp_rib.lock().await.set_maximum_paths(maximum_paths);
    }

    /// `BgpInstance.aggregates` (RFC 4271 §9.2.2.2).
    pub async fn set_aggregates(&self, aggregates: Vec<nos_proto::BgpAggregate>) {
        self.bgp_rib.lock().await.set_aggregates(aggregates);
    }

    /// Resolves `changed()` after any RIB mutation; the push clients'
    /// wake-up (#420).
    pub fn push_changed(&self) -> watch::Receiver<u64> {
        self.bgp_rib.subscribe()
    }

    /// This instance's owning routing table name and current best-path
    /// snapshot, for `rib_push_client`.
    pub async fn bgp_push_snapshot(&self) -> (Option<String>, HashMap<IpNet, crate::rib::Hops>) {
        self.bgp_rib.lock().await.push_snapshot()
    }

    /// Delivers an operator-triggered `FsmCommand` to `peer`'s live session,
    /// for `server.rs`'s `BgpRequest::SendRouteRefresh` handler. `false` if
    /// `peer` isn't configured or has no `Established` session right now —
    /// both cases are reported identically to the CLI as "nothing to
    /// refresh".
    pub async fn send_command(&self, peer: IpAddr, cmd: FsmCommand) -> bool {
        let peers = self.peers.read().await;
        let Some(slot) = peers.get(&peer) else {
            return false;
        };
        if !slot.is_established().await {
            return false;
        }
        slot.send_command(cmd)
    }

    /// `clear bgp <instance> <peer>`: releases a maximum-prefix hold, and
    /// resets an `Established` session with Cease/Administrative Reset (RFC
    /// 4486). The peer then reconnects on its next connect-retry tick (or its
    /// own inbound connect). `false` if `peer` isn't configured.
    pub async fn clear_peer(&self, peer: IpAddr) -> bool {
        let Some(slot) = self.peers.read().await.get(&peer).cloned() else {
            return false;
        };
        slot.clear_max_prefix();
        cease_established(&slot, CeaseSubcode::AdministrativeReset, Bytes::new()).await;
        info!(instance = %self.instance, peer = %peer, "bgp peer cleared");
        true
    }

    /// Every currently-configured peer's current session summary, for
    /// `server.rs`'s `BgpRequest::GetSummary` handler — backs `nos-cli`'s
    /// `show bgp brief`.
    pub async fn peer_summaries(&self) -> Vec<PeerSummary> {
        let peers = self.peers.read().await;
        let rib = self.bgp_rib.lock().await;
        peers
            .values()
            .map(|slot| to_peer_summary(slot, &rib))
            .collect()
    }

    /// Every received EVPN route, for `BgpRequest::GetEvpnRoutes` — backs
    /// `nos-cli`'s `show bgp evpn`.
    pub async fn evpn_route_summaries(&self) -> Vec<nos_proto::EvpnRouteSummary> {
        self.bgp_rib
            .lock()
            .await
            .evpn_routes()
            .into_iter()
            .map(|(peer, nlri, route)| nos_proto::EvpnRouteSummary {
                peer,
                route_type: nlri.route_type(),
                route: nlri.to_string(),
                next_hop: route.next_hop,
                extended_communities: route
                    .extended_communities
                    .iter()
                    .map(|&c| crate::evpn::format_ext_community(c))
                    .collect(),
            })
            .collect()
    }

    /// Every unicast route held, for `BgpRequest::GetRoutes` (`show bgp routes`).
    pub async fn route_summaries(&self) -> Vec<nos_proto::BgpRouteSummary> {
        self.bgp_rib.lock().await.routes()
    }

    /// Tells every established peer we're going (Cease/Administrative
    /// Shutdown — a Hard Reset once RFC 8538's N is exchanged, so a
    /// graceful-restart peer doesn't keep forwarding to us: the watchdog
    /// only stops this process when the instance is removed or the router
    /// is stopping, and `nos-ribd` deletes the VRF on the same signal), then
    /// aborts every peer task and the listener, and clears all state.
    /// Called once when `crate::reconcile::run`'s loop exits on shutdown.
    pub async fn shutdown(&self) {
        let slots: Vec<Arc<PeerSlot>> = self.peers.read().await.values().cloned().collect();
        // Quiesce first: nothing may be accepted or redialed during the Cease
        // grace. Already-accepted passive sessions are their own tasks and
        // still get their Cease.
        for slot in &slots {
            slot.stop();
        }
        if let Some(listeners) = self.listeners.lock().await.take() {
            listeners.v4.abort();
            listeners.v6.abort();
        }
        futures::future::join_all(slots.iter().map(|slot| {
            cease_established(slot, CeaseSubcode::AdministrativeShutdown, Bytes::new())
        }))
        .await;
        let mut tasks = self.peer_tasks.lock().await;
        for (_, task) in tasks.drain() {
            if let Some(t) = task.task {
                t.abort();
            }
        }
        drop(tasks);
        let taken = self.rpki.lock().await.take();
        if let Some((client, applier)) = taken {
            client.task.abort();
            applier.abort();
        }
        self.peers.write().await.clear();
    }

    async fn rebind_listeners(self: &Arc<Self>, vrf: &VrfRequirement, desired: &[ResolvedPeer]) {
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
            match self.spawn_listeners(&name, desired) {
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

    /// Binds fresh v4/v6 listening sockets and primes every currently
    /// desired peer's auth key onto whichever socket matches its address
    /// family — needed here (not just via `sync_listener_auth`'s
    /// diff-against-previous-peer-set logic) because a fresh listener has no
    /// prior state to diff against even when the peer set itself is
    /// unchanged (e.g. a VRF flap with the same peers configured all along).
    fn spawn_listeners(
        self: &Arc<Self>,
        vrf: &str,
        desired: &[ResolvedPeer],
    ) -> io::Result<Listeners> {
        let scope = self.bind_vrf.then_some(vrf);
        let v4_listener = tcp::bind_listener(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), self.listen_port),
            scope,
        )?;
        let v6_listener = tcp::bind_listener(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), self.listen_port),
            scope,
        )?;
        let v4_fd = v4_listener.as_raw_fd();
        let v6_fd = v6_listener.as_raw_fd();
        let mut applied_auth = HashMap::new();
        for peer in desired {
            if let Some(auth) = &peer.auth {
                let fd = listener_fd_for(peer.remote_address, v4_fd, v6_fd);
                match tcp::apply_auth(fd, peer.remote_address, auth, true) {
                    Ok(()) => {
                        applied_auth.insert(peer.remote_address, auth.clone());
                    }
                    Err(e) => warn!(
                        instance = %self.instance, peer = %peer.remote_address, error = %e,
                        "failed to install bgp listener auth key"
                    ),
                }
            }
        }
        let v4 = tokio::spawn(self.clone().accept_loop(v4_listener));
        let v6 = tokio::spawn(self.clone().accept_loop(v6_listener));
        Ok(Listeners {
            vrf: vrf.to_string(),
            v4,
            v6,
            v4_fd,
            v6_fd,
            applied_auth,
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

    #[allow(clippy::similar_names)] // is_rr_client (reflector) vs. is_rs_client (server)
    async fn handle_inbound(self: &Arc<Self>, stream: TcpStream, remote: IpAddr) {
        let slot = self.peers.read().await.get(&remote).cloned();
        let Some(slot) = slot else {
            debug!(
                instance = %self.instance, peer = %remote,
                "rejecting inbound tcp connection from unconfigured peer"
            );
            return;
        };
        if slot.peer.shutdown.is_some() {
            debug!(
                instance = %self.instance, peer = %remote,
                "rejecting inbound tcp connection from administratively shut peer"
            );
            return;
        }
        if slot.max_prefix_held() {
            debug!(
                instance = %self.instance, peer = %remote,
                "rejecting inbound tcp connection from peer held by maximum prefix limit"
            );
            return;
        }
        if let Some(hops) = slot.peer.max_hops
            && let Err(error) = tcp::apply_max_hops(stream.as_raw_fd(), remote, hops)
        {
            warn!(
                instance = %self.instance, peer = %remote, %error,
                "cannot apply max-hops to inbound connection, dropping it"
            );
            return;
        }
        if !slot.begin(Role::Passive).await {
            debug!(
                instance = %self.instance, peer = %remote,
                "rejecting inbound tcp connection: a previous inbound session for this peer is still being torn down"
            );
            return;
        }
        // An accepted socket advertises whatever the peer is signing with as
        // its RNextKeyID, not our configured rnext: set it, or a session
        // coming back passive mid-rollover never asks for the new key.
        if let Some(ResolvedAuth::Ao(keys)) = slot.auth()
            && let Some(key) = ao_rnext(&keys)
            && let Err(error) = nos_tcp_auth::set_ao_rnext(stream.as_raw_fd(), key.recv_id)
        {
            warn!(
                instance = %self.instance, peer = %remote, %error,
                "cannot set tcp-ao rnext on inbound connection"
            );
        }
        info!(instance = %self.instance, peer = %remote, "accepted inbound bgp tcp session");
        let instance = self.instance.clone();
        let local = *self.local.borrow();
        let remote_as = slot.peer.remote_as;
        let mrai = slot.peer.mrai;
        let route_refresh_stale_time = slot.peer.route_refresh_stale_time;
        let damping = slot.peer.damping;
        let local_hold_time = slot.peer.hold_time;
        let keepalive_override = slot.peer.keepalive_interval;
        let next_hop = slot.peer.next_hop;
        let address_families = slot.peer.address_families.clone();
        let is_rr_client = slot.peer.route_reflector_client;
        let is_rs_client = slot.peer.route_server_client;
        let import_policy = slot.peer.import_policy.clone();
        let export_policy = slot.peer.export_policy.clone();
        let bgp_rib = self.bgp_rib.clone();
        let task_slot = slot.clone();
        let task = tokio::spawn(async move {
            let outcome = fsm::run(
                stream,
                Role::Passive,
                local,
                PeerContext {
                    remote_address: remote,
                    expected_remote_as: remote_as,
                    local_hold_time,
                    keepalive_override,
                    mrai,
                    route_refresh_stale_time,
                    damping,
                    next_hop,
                    address_families,
                    is_rr_client,
                    is_rs_client,
                    import_policy,
                    export_policy,
                },
                slot.clone(),
                bgp_rib,
            )
            .await;
            slot.clear(Role::Passive).await;
            reset_status_if_not_established(&slot).await;
            info!(instance = %instance, peer = %remote, outcome = ?outcome, "inbound bgp session ended");
        });
        task_slot.set_passive_task(task).await;
    }

    async fn reconcile_peers(self: &Arc<Self>, desired: Vec<ResolvedPeer>) {
        let desired: HashMap<IpAddr, ResolvedPeer> =
            desired.into_iter().map(|p| (p.remote_address, p)).collect();

        let mut tasks = self.peer_tasks.lock().await;
        let current: HashMap<IpAddr, ResolvedPeer> = tasks
            .iter()
            .map(|(addr, t)| (*addr, t.peer.clone()))
            .collect();
        let (to_stop, to_spawn, to_update) = diff_peers(&current, &desired);

        self.sync_listener_auth(&to_stop, &to_spawn, &to_update)
            .await;

        // A key-list-only change: no restart. The live session (if any) gets
        // the delta through its command channel — only when established, or
        // the command would sit in the channel until some later session — and
        // any other connection starts from `slot.auth()`.
        for (peer, delta) in to_update {
            let taken = self.peers.read().await.get(&peer.remote_address).cloned();
            if let Some(slot) = taken {
                slot.set_auth(peer.auth.clone());
                // ponytail: a connection still in its handshake keeps the
                // keys it started with until the next reset; no live update
                // is queued for it. Re-send once Established if it matters.
                if slot.is_established().await {
                    slot.send_command(FsmCommand::UpdateAo(delta));
                }
            }
            if let Some(task) = tasks.get_mut(&peer.remote_address) {
                task.peer = peer;
            }
        }

        // Tell every established session why it is going away (RFC 4486)
        // before the tasks are aborted — an abort sends nothing. Concurrent,
        // since each waits up to `CEASE_GRACE` for its NOTIFICATION to flush.
        let mut stopped = Vec::new();
        for addr in &to_stop {
            let slot = self.peers.write().await.remove(addr);
            if let Some(slot) = &slot {
                slot.stop();
            }
            let (subcode, data) = cease_reason(current.get(addr), desired.get(addr));
            stopped.push((*addr, slot, subcode, data));
        }
        futures::future::join_all(stopped.iter().map(|(_, slot, subcode, data)| async move {
            if let Some(slot) = slot {
                cease_established(slot, *subcode, data.clone()).await;
            }
        }))
        .await;

        for (addr, slot, subcode, _) in stopped {
            // Both roles must stop: the active-connect loop owned here, and
            // any passively-accepted session, which is spawned per accepted
            // connection and tracked on the slot. Missing the passive one
            // left an established session running with the `ResolvedPeer` it
            // was accepted with — stale policies, auth and timers — for as
            // long as the session stayed up.
            if let Some(task) = tasks.remove(&addr).and_then(|t| t.task) {
                task.abort();
            }
            if let Some(slot) = slot {
                slot.stop_passive().await;
            }
            // Aborting cancels each task at whatever await point it was
            // parked on, so `fsm::run`'s own exit path — and with it its
            // `peer_disconnected` — never runs. Deregister here instead, or
            // the peer's `adj_rib_in`/`peer_outbox` would outlive the
            // sessions that owned them: the routes would stay in the Loc-RIB
            // (and keep being advertised) until something else happened to
            // evict them, which is exactly what a changed import policy must
            // not do.
            // RFC 8538: only Other Configuration Change keeps the routes.
            let kind = if subcode == CeaseSubcode::OtherConfigurationChange {
                Disconnect::Graceful
            } else {
                Disconnect::Hard
            };
            self.bgp_rib.lock().await.peer_disconnected(addr, kind);
        }
        for peer in to_spawn {
            let slot = PeerSlot::new(peer.clone());
            self.peers
                .write()
                .await
                .insert(peer.remote_address, slot.clone());
            let task = peer.shutdown.is_none().then(|| {
                tokio::spawn(active_connect_loop(
                    self.instance.clone(),
                    (self.peer_port, self.bind_vrf),
                    slot,
                    self.vrf.subscribe(),
                    self.local.subscribe(),
                    self.bgp_rib.clone(),
                ))
            });
            tasks.insert(peer.remote_address, PeerTask { peer, task });
        }
    }

    /// Keeps the shared listener sockets' installed auth keys in step with
    /// `to_stop`/`to_spawn` — the same diff `reconcile_peers` already
    /// computed for active-connect tasks, since "a peer stopped" and "a
    /// peer's listener key should be removed" (respectively "spawned"/
    /// "installed") are exactly the same event here. A no-op if no listener
    /// is currently bound (`VrfRequirement` not `Resolved`).
    async fn sync_listener_auth(
        &self,
        to_stop: &[IpAddr],
        to_spawn: &[ResolvedPeer],
        to_update: &[(ResolvedPeer, AoDelta)],
    ) {
        let mut listeners = self.listeners.lock().await;
        let Some(listeners) = listeners.as_mut() else {
            return;
        };
        for addr in to_stop {
            if let Some(auth) = listeners.applied_auth.remove(addr) {
                let fd = listener_fd_for(*addr, listeners.v4_fd, listeners.v6_fd);
                if let Err(e) = tcp::remove_auth(fd, *addr, &auth) {
                    warn!(
                        instance = %self.instance, peer = %addr, error = %e,
                        "failed to remove bgp listener auth key"
                    );
                }
            }
        }
        for (peer, delta) in to_update {
            let fd = listener_fd_for(peer.remote_address, listeners.v4_fd, listeners.v6_fd);
            // A listener has no current/rnext key, so nothing here can be busy.
            match tcp::apply_ao_delta(fd, peer.remote_address, delta, false) {
                Ok(()) => {
                    if let Some(auth) = &peer.auth {
                        listeners
                            .applied_auth
                            .insert(peer.remote_address, auth.clone());
                    }
                }
                Err(e) => warn!(
                    instance = %self.instance, peer = %peer.remote_address, error = %e,
                    "failed to update bgp listener auth keys"
                ),
            }
        }
        for peer in to_spawn {
            match &peer.auth {
                Some(auth) => {
                    let fd = listener_fd_for(peer.remote_address, listeners.v4_fd, listeners.v6_fd);
                    match tcp::apply_auth(fd, peer.remote_address, auth, true) {
                        Ok(()) => {
                            listeners
                                .applied_auth
                                .insert(peer.remote_address, auth.clone());
                        }
                        Err(e) => warn!(
                            instance = %self.instance, peer = %peer.remote_address, error = %e,
                            "failed to install bgp listener auth key"
                        ),
                    }
                }
                None => {
                    listeners.applied_auth.remove(&peer.remote_address);
                }
            }
        }
    }
}

/// How long `reconcile_peers` waits for a Cease NOTIFICATION to be written
/// and the session to end before it aborts the task regardless.
const CEASE_GRACE: Duration = Duration::from_secs(1);

/// The RFC 4486 Cease subcode (and NOTIFICATION data: an RFC 9003 message
/// for Administrative Shutdown) for taking a running peer down: `wanted` is
/// `None` when it left the config entirely.
fn cease_reason(
    running: Option<&ResolvedPeer>,
    wanted: Option<&ResolvedPeer>,
) -> (CeaseSubcode, Bytes) {
    match (running, wanted) {
        (_, None) => (CeaseSubcode::PeerDeconfigured, Bytes::new()),
        (Some(old), Some(new)) if new.shutdown.is_some() && new.shutdown != old.shutdown => (
            CeaseSubcode::AdministrativeShutdown,
            new.shutdown
                .as_ref()
                .and_then(|s| s.message.as_deref())
                .map_or_else(Bytes::new, crate::message::encode_shutdown_message),
        ),
        _ => (CeaseSubcode::OtherConfigurationChange, Bytes::new()),
    }
}

/// Asks an `Established` session to send a Cease and close, and waits (up to
/// `CEASE_GRACE`) for it to end. A no-op for a peer that isn't established.
async fn cease_established(slot: &PeerSlot, subcode: CeaseSubcode, data: Bytes) {
    async fn pass(slot: &PeerSlot, subcode: CeaseSubcode, data: Bytes) {
        if !slot.is_established().await || !slot.send_command(FsmCommand::Cease { subcode, data }) {
            return;
        }
        let _ = tokio::time::timeout(CEASE_GRACE, async {
            while slot.is_established().await {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
    }
    pass(slot, subcode, data.clone()).await;
    // A dial already in flight when the slot was stopped may have come up
    // meanwhile: Cease it too. ponytail: a handshake finishing after this
    // second pass is closed bare; waiting for "no connection in handshake"
    // would make shutdown wait on a hung SYN.
    if slot.is_stopping() {
        pass(slot, subcode, data).await;
    }
}

/// Which of a `Listeners`' two raw fds matches `addr`'s IP version —
/// `TCP_MD5SIG`/TCP-AO keys are scoped to one socket family, so a peer's key
/// only ever goes on the listener actually reachable by its address.
fn listener_fd_for(addr: IpAddr, v4_fd: RawFd, v6_fd: RawFd) -> RawFd {
    if addr.is_ipv4() {
        v4_fd
    } else {
        v6_fd
    }
}

/// Snapshots one peer's current status into the wire-serializable
/// `PeerSummary` — `PeerStatus.established_since` (a `tokio::time::Instant`)
/// isn't itself meaningful to another process, so it's converted to an
/// uptime measured right now instead.
fn to_peer_summary(slot: &PeerSlot, rib: &BgpRib) -> PeerSummary {
    let status = *slot.status_receiver().borrow();
    // ponytail: a session that ends between fsm::run returning and the next
    // OpenSent write clearing `status.fd` leaves a brief window where this fd
    // is stale/closed — get_ao_info then just errors (e.g. EBADF), reported
    // as `None` below, same as "no AO auth configured". Upgrade path: none
    // needed unless a closed fd is ever observed reused by an unrelated
    // socket in that same microsecond-scale window.
    let ao_info = match (slot.auth(), status.fd) {
        (Some(ResolvedAuth::Ao(_)), Some(fd)) => nos_tcp_auth::get_ao_info(fd).ok(),
        _ => None,
    };
    PeerSummary {
        remote_address: slot.peer.remote_address,
        peer_group: slot.peer.peer_group.clone(),
        shutdown: slot.peer.shutdown.is_some(),
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
        ao_current_key: ao_info.as_ref().map(|i| i.current_key),
        ao_rnext_key: ao_info.as_ref().map(|i| i.rnext_key),
        ao_packets_good: ao_info.as_ref().map(|i| i.pkt_good),
        ao_packets_bad: ao_info.as_ref().map(|i| i.pkt_bad),
        ao_packets_key_not_found: ao_info.as_ref().map(|i| i.pkt_key_not_found),
        max_prefix_held: slot.max_prefix_held(),
        accepted_prefixes: (status.state == PeerState::Established)
            .then(|| rib.accepted_prefixes(slot.peer.remote_address)),
        graceful_restart: rib
            .peer_gr(slot.peer.remote_address)
            .map(|g| nos_proto::GrSummary {
                restart_time: g.time,
                notification: g.notification,
                restarting: g.restart,
                families: g
                    .families()
                    .into_iter()
                    .map(|f| (f, g.forwarding(f)))
                    .collect(),
            }),
        stale_prefixes: rib.stale_count(slot.peer.remote_address),
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
/// spawned; a peer differing only by an in-place-applicable TCP-AO key
/// change (`ao_delta`) is updated instead. Pure and synchronous, like
/// `interface`'s `diff_addresses`.
fn diff_peers(
    current: &HashMap<IpAddr, ResolvedPeer>,
    desired: &HashMap<IpAddr, ResolvedPeer>,
) -> (Vec<IpAddr>, Vec<ResolvedPeer>, Vec<(ResolvedPeer, AoDelta)>) {
    let mut to_stop = Vec::new();
    let mut to_spawn = Vec::new();
    let mut to_update = Vec::new();

    for (addr, running) in current {
        match desired.get(addr) {
            None => to_stop.push(*addr),
            Some(wanted) if wanted != running => {
                let delta = running
                    .auth
                    .as_ref()
                    .zip(wanted.auth.as_ref())
                    .and_then(|(old, new)| ao_delta(old, new))
                    .filter(|_| {
                        let mut same = running.clone();
                        same.auth.clone_from(&wanted.auth);
                        same == *wanted
                    });
                if let Some(delta) = delta {
                    to_update.push((wanted.clone(), delta));
                } else {
                    to_stop.push(*addr);
                    to_spawn.push(wanted.clone());
                }
            }
            Some(_) => {}
        }
    }
    for (addr, wanted) in desired {
        if !current.contains_key(addr) {
            to_spawn.push(wanted.clone());
        }
    }

    (to_stop, to_spawn, to_update)
}

/// One peer's outbound side: while the VRF is resolved, attempts a connect
/// every jittered retry interval (each attempt bounded by it too); on success, runs the FSM until the session
/// ends, then resumes retrying. Runs until aborted by `SessionManager`
/// (peer removed from config, or process shutdown).
async fn active_connect_loop(
    instance: String,
    (peer_port, bind_vrf): (u16, bool),
    slot: Arc<PeerSlot>,
    mut vrf: watch::Receiver<VrfRequirement>,
    local: watch::Receiver<LocalIdentity>,
    bgp_rib: Arc<SharedRib>,
) {
    loop {
        let current_vrf = vrf.borrow().clone();
        if let VrfRequirement::Resolved(vrf_name) = current_vrf {
            if slot.is_stopping() || slot.is_established().await || slot.max_prefix_held() {
                // Already up (via either role) — dialing out again would
                // just create a pointless collision the existing session
                // would win anyway. Wait for the retry interval (or a VRF
                // change) and check again, rather than actually connecting.
                // Held down by its maximum-prefix limit: not until released.
            } else if slot.begin(Role::Active).await {
                let remote = SocketAddr::new(slot.peer.remote_address, peer_port);
                // RFC 4271 §8.2.2: ConnectRetryTimer expiring in Connect drops
                // the attempt — an unanswered SYN would otherwise hold the
                // Active role for the kernel's whole SYN-retry budget (~2min).
                let connect = tokio::time::timeout(
                    slot.peer.connect_retry_time,
                    tcp::connect(
                        remote,
                        slot.peer.source_address,
                        bind_vrf.then_some(vrf_name.as_str()),
                        slot.auth().as_ref(),
                        slot.peer.max_hops,
                    ),
                )
                .await
                .unwrap_or_else(|_| {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "connect timed out after connect-retry-time",
                    ))
                });
                match connect {
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
                                mrai: slot.peer.mrai,
                                route_refresh_stale_time: slot.peer.route_refresh_stale_time,
                                damping: slot.peer.damping,
                                next_hop: slot.peer.next_hop,
                                address_families: slot.peer.address_families.clone(),
                                is_rr_client: slot.peer.route_reflector_client,
                                is_rs_client: slot.peer.route_server_client,
                                import_policy: slot.peer.import_policy.clone(),
                                export_policy: slot.peer.export_policy.clone(),
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
            () = tokio::time::sleep(jittered(slot.peer.connect_retry_time)) => {}
            _ = vrf.changed() => {}
        }
    }
}

/// `d` scaled by a random factor in `[0.75, 1.0]` — RFC 4271 §10's jitter on
/// `ConnectRetryTimer`, so two routers whose sessions ended together (a §6.8
/// collision closes both connections at once) don't redial in lockstep and
/// collide again every cycle. std-only: `RandomState` is randomly seeded.
fn jittered(d: Duration) -> Duration {
    use std::hash::BuildHasher;
    let r = std::hash::RandomState::new().hash_one(std::time::Instant::now());
    let r = f64::from(u32::try_from(r >> 32).unwrap_or(0)) / f64::from(u32::MAX);
    d.mul_f64(0.75 + 0.25 * r)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5882 §4.3: established -> Cease/10 (flushing only with C at both
    /// ends); down with stale routes -> abort the restart only with C.
    #[test]
    fn bfd_down_decision_table() {
        use BfdAction::*;
        for (established, stale, cpi, want) in [
            (true, false, true, Close { flush: true }),
            (true, true, false, Close { flush: false }),
            (false, true, true, AbortGr),
            (false, true, false, Nothing),
            (false, false, true, Nothing),
            (false, false, false, Nothing),
        ] {
            assert_eq!(bfd_action(established, stale, cpi), want);
        }
    }

    #[test]
    fn jittered_stays_between_three_quarters_and_whole() {
        let d = Duration::from_secs(3);
        let samples: Vec<_> = (0..100).map(|_| jittered(d)).collect();
        assert!(samples.iter().all(|j| *j >= d.mul_f64(0.75) && *j <= d));
        assert!(samples.iter().any(|j| *j != samples[0]));
    }

    fn peer(addr: &str) -> ResolvedPeer {
        ResolvedPeer {
            remote_address: addr.parse().unwrap(),
            source_address: None,
            remote_as: 65000,
            peer_group: "pg1".to_string(),
            hold_time: 90,
            keepalive_interval: None,
            connect_retry_time: fsm::CONNECT_RETRY_TIME,
            mrai: Duration::ZERO,
            route_refresh_stale_time: Duration::ZERO,
            damping: None,
            max_hops: None,
            auth: None,
            next_hop: None,
            address_families: vec![AddressFamily::Ipv4Unicast],
            route_reflector_client: false,
            route_server_client: false,
            import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            shutdown: None,
            maximum_prefix: nos_proto::BgpMaximumPrefix::default(),
            announce_rpki_state: false,
            local_as: None,
            add_path: None,
            add_path_send_count: None,
            role: None,
            strict_mode: false,
            confed_id: None,
            confed_member: false,
            graceful_restart: None,
        }
    }

    /// RFC 5065 §4: the OPEN carries the confederation identifier only to a
    /// peer outside the confederation.
    #[test]
    fn open_as_by_peer_kind() {
        let p = |remote_as, confed_member| ResolvedPeer {
            remote_as,
            confed_id: Some(65100),
            confed_member,
            ..peer("10.0.0.1")
        };
        assert_eq!(p(65101, false).kind(65101), PeerKind::Internal);
        assert_eq!(p(65101, false).open_as(65101), 65101);
        assert_eq!(p(65102, true).kind(65101), PeerKind::ConfedExternal);
        assert_eq!(p(65102, true).open_as(65101), 65101);
        assert_eq!(p(65003, false).kind(65101), PeerKind::External);
        assert_eq!(p(65003, false).open_as(65101), 65100);
        let plain = ResolvedPeer {
            remote_as: 65003,
            ..peer("10.0.0.1")
        };
        assert_eq!(plain.open_as(65101), 65101);
        // local-as wins toward an external peer only.
        let local_as = Some(nos_proto::BgpLocalAs {
            asn: 65009,
            ..Default::default()
        });
        let l = |remote_as, confed_member| ResolvedPeer {
            local_as,
            ..p(remote_as, confed_member)
        };
        assert_eq!(l(65003, false).open_as(65101), 65009);
        assert_eq!(l(65101, false).open_as(65101), 65101);
        assert_eq!(l(65102, true).open_as(65101), 65101);
        let plain = ResolvedPeer {
            remote_as: 65003,
            local_as,
            ..peer("10.0.0.1")
        };
        assert_eq!(plain.open_as(65101), 65009);
    }

    #[test]
    fn to_peer_summary_of_a_never_connected_peer_is_idle() {
        let slot = PeerSlot::new(peer("10.0.0.1"));
        let summary = to_peer_summary(&slot, &BgpRib::new());
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
        assert_eq!(summary.ao_current_key, None);
        assert_eq!(summary.ao_rnext_key, None);
        assert_eq!(summary.ao_packets_good, None);
        assert_eq!(summary.ao_packets_bad, None);
        assert_eq!(summary.ao_packets_key_not_found, None);
        assert!(!summary.max_prefix_held);
        assert_eq!(summary.accepted_prefixes, None);
    }

    /// A TCP-AO peer with no `fd` recorded yet (e.g. `OpenSent`, before
    /// `Established`) reports no AO info either, even though `slot.peer.auth`
    /// is `Some(ResolvedAuth::Ao(_))` — `to_peer_summary` must gate on both.
    #[test]
    fn to_peer_summary_of_ao_peer_with_no_fd_yet_has_no_ao_info() {
        let mut p = peer("10.0.0.1");
        p.auth = Some(ResolvedAuth::Ao(vec![nos_tcp_auth::AoKey {
            send_id: 1,
            recv_id: 1,
            algorithm: nos_tcp_auth::AoAlgorithm::HmacSha1_96,
            key: b"secret".to_vec(),
            set_current: true,
            set_rnext: false,
            exclude_options: false,
        }]));
        let slot = PeerSlot::new(p);
        let summary = to_peer_summary(&slot, &BgpRib::new());
        assert_eq!(summary.ao_current_key, None);
        assert_eq!(summary.ao_rnext_key, None);
    }

    #[test]
    fn new_peer_is_spawned() {
        let current = HashMap::new();
        let desired = HashMap::from([("10.0.0.1".parse().unwrap(), peer("10.0.0.1"))]);
        let (to_stop, to_spawn, _) = diff_peers(&current, &desired);
        assert_eq!(to_stop, [] as [IpAddr; 0]);
        assert_eq!(to_spawn, vec![peer("10.0.0.1")]);
    }

    #[test]
    fn removed_peer_is_stopped() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        let current = HashMap::from([(addr, peer("10.0.0.1"))]);
        let desired = HashMap::new();
        let (to_stop, to_spawn, _) = diff_peers(&current, &desired);
        assert_eq!(to_stop, vec![addr]);
        assert_eq!(to_spawn, []);
    }

    #[test]
    fn unchanged_peer_is_left_alone() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        let current = HashMap::from([(addr, peer("10.0.0.1"))]);
        let desired = HashMap::from([(addr, peer("10.0.0.1"))]);
        let (to_stop, to_spawn, _) = diff_peers(&current, &desired);
        assert_eq!(to_stop, [] as [IpAddr; 0]);
        assert_eq!(to_spawn, []);
    }

    #[test]
    fn changed_peer_is_restarted() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        let current = HashMap::from([(addr, peer("10.0.0.1"))]);
        let mut changed = peer("10.0.0.1");
        changed.source_address = Some("10.0.0.9".parse().unwrap());
        let desired = HashMap::from([(addr, changed.clone())]);
        let (to_stop, to_spawn, _) = diff_peers(&current, &desired);
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
        let (to_stop, to_spawn, _) = diff_peers(&current, &desired);
        assert_eq!(to_stop, vec![addr]);
        assert_eq!(to_spawn, vec![changed]);
    }

    #[test]
    fn auth_change_triggers_restart() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        let current = HashMap::from([(addr, peer("10.0.0.1"))]);
        let mut changed = peer("10.0.0.1");
        changed.auth = Some(ResolvedAuth::Md5("secret".to_string()));
        let desired = HashMap::from([(addr, changed.clone())]);
        let (to_stop, to_spawn, _) = diff_peers(&current, &desired);
        assert_eq!(to_stop, vec![addr]);
        assert_eq!(to_spawn, vec![changed]);
    }

    #[test]
    fn resolved_auth_from_bgp_auth_md5() {
        let auth = BgpAuth::Md5 {
            password: "secret".to_string(),
        };
        assert_eq!(
            ResolvedAuth::from(&auth),
            ResolvedAuth::Md5("secret".to_string())
        );
    }

    #[test]
    fn resolved_auth_from_bgp_auth_ao() {
        let auth = BgpAuth::Ao {
            keys: vec![nos_proto::BgpAoKey {
                send_id: 1,
                recv_id: 2,
                algorithm: BgpAoAlgorithm::AesCmac96,
                key: "secret".to_string(),
                is_current: true,
                is_rnext: false,
                exclude_options: true,
            }],
        };
        assert_eq!(
            ResolvedAuth::from(&auth),
            ResolvedAuth::Ao(vec![nos_tcp_auth::AoKey {
                send_id: 1,
                recv_id: 2,
                algorithm: nos_tcp_auth::AoAlgorithm::AesCmac96,
                key: b"secret".to_vec(),
                set_current: true,
                set_rnext: false,
                exclude_options: true,
            }])
        );
    }

    #[test]
    fn shutting_a_peer_restarts_it_with_an_administrative_shutdown_cease() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        let running = peer("10.0.0.1");
        let mut wanted = peer("10.0.0.1");
        wanted.shutdown = Some(BgpShutdown {
            message: Some("maint".to_string()),
        });
        let current = HashMap::from([(addr, running.clone())]);
        let desired = HashMap::from([(addr, wanted.clone())]);
        let (to_stop, to_spawn, _) = diff_peers(&current, &desired);
        assert_eq!(to_stop, vec![addr]);
        assert_eq!(to_spawn, vec![wanted.clone()]);
        assert_eq!(
            cease_reason(Some(&running), Some(&wanted)),
            (
                CeaseSubcode::AdministrativeShutdown,
                crate::message::encode_shutdown_message("maint")
            )
        );
    }

    #[test]
    fn cease_reason_for_removal_and_other_changes() {
        let a = peer("10.0.0.1");
        let mut b = peer("10.0.0.1");
        b.hold_time = 30;
        assert_eq!(
            cease_reason(Some(&a), None),
            (CeaseSubcode::PeerDeconfigured, Bytes::new())
        );
        assert_eq!(
            cease_reason(Some(&a), Some(&b)),
            (CeaseSubcode::OtherConfigurationChange, Bytes::new())
        );
    }

    fn ao(send_id: u8, secret: &str, current: bool, rnext: bool) -> nos_tcp_auth::AoKey {
        nos_tcp_auth::AoKey {
            send_id,
            recv_id: send_id,
            algorithm: nos_tcp_auth::AoAlgorithm::HmacSha1_96,
            key: secret.as_bytes().to_vec(),
            set_current: current,
            set_rnext: rnext,
            exclude_options: false,
        }
    }

    fn ao_auth(keys: Vec<nos_tcp_auth::AoKey>) -> ResolvedAuth {
        ResolvedAuth::Ao(keys)
    }

    #[test]
    fn ao_delta_add_only_advertises_the_flagged_rnext() {
        let old = ao_auth(vec![ao(1, "a", true, false)]);
        let new = ao_auth(vec![ao(1, "a", true, false), ao(2, "b", false, true)]);
        let d = ao_delta(&old, &new).unwrap();
        assert_eq!(d.add, vec![ao(2, "b", false, true)]);
        assert_eq!(d.remove, Vec::<(u8, u8)>::new());
        assert_eq!(d.rnext_recv_id, 2);
    }

    #[test]
    fn ao_delta_promote_and_remove_fall_back_to_current_as_rnext() {
        let old = ao_auth(vec![ao(1, "a", true, false), ao(2, "b", false, true)]);
        // Step 2: 2 becomes current (rnext flag dropped).
        let promoted = ao_auth(vec![ao(1, "a", false, false), ao(2, "b", true, false)]);
        let d = ao_delta(&old, &promoted).unwrap();
        assert!(d.add.is_empty() && d.remove.is_empty());
        assert_eq!(d.rnext_recv_id, 2);
        // Step 3: 1 removed.
        let d = ao_delta(&promoted, &ao_auth(vec![ao(2, "b", true, false)])).unwrap();
        assert_eq!(d.remove, vec![(1, 1)]);
        assert_eq!(d.rnext_recv_id, 2);
    }

    #[test]
    fn ao_delta_rnext_move_is_in_place() {
        let old = ao_auth(vec![ao(1, "a", true, true), ao(2, "b", false, false)]);
        let new = ao_auth(vec![ao(1, "a", true, false), ao(2, "b", false, true)]);
        assert_eq!(ao_delta(&old, &new).unwrap().rnext_recv_id, 2);
    }

    #[test]
    fn ao_delta_needs_a_restart_when_a_kept_key_changes() {
        let old = ao_auth(vec![ao(1, "a", true, false)]);
        assert_eq!(
            ao_delta(&old, &ao_auth(vec![ao(1, "other", true, false)])),
            None
        );
        let mut excl = ao(1, "a", true, false);
        excl.exclude_options = true;
        assert_eq!(ao_delta(&old, &ao_auth(vec![excl])), None);
        let mut recv = ao(1, "a", true, false);
        recv.recv_id = 9;
        assert_eq!(ao_delta(&old, &ao_auth(vec![recv])), None);
    }

    #[test]
    fn ao_delta_needs_a_restart_when_an_added_recv_id_is_still_held() {
        let old = ao_auth(vec![ao(1, "a", true, false)]);
        let mut reused = ao(2, "b", true, false);
        reused.recv_id = 1;
        assert_eq!(ao_delta(&old, &ao_auth(vec![reused])), None);
    }

    #[test]
    fn ao_delta_needs_a_restart_for_md5() {
        let ao_one = ao_auth(vec![ao(1, "a", true, false)]);
        let md5 = ResolvedAuth::Md5("x".to_string());
        assert_eq!(ao_delta(&md5, &ao_one), None);
        assert_eq!(ao_delta(&ao_one, &md5), None);
        assert_eq!(ao_delta(&md5, &md5.clone()), None);
    }

    #[test]
    fn diff_peers_ao_only_change_is_an_in_place_update() {
        let mut a = peer("10.0.0.1");
        a.auth = Some(ao_auth(vec![ao(1, "a", true, false)]));
        let mut b = a.clone();
        b.auth = Some(ao_auth(vec![
            ao(1, "a", true, false),
            ao(2, "b", false, true),
        ]));
        let (current, desired) = (map_of(&a), map_of(&b));
        let (stop, spawn, update) = diff_peers(&current, &desired);
        assert!(stop.is_empty() && spawn.is_empty());
        assert_eq!(update.len(), 1);
        assert_eq!(update[0].0, b);
        assert_eq!(update[0].1.rnext_recv_id, 2);
    }

    #[test]
    fn diff_peers_ao_change_with_another_field_still_restarts() {
        let mut a = peer("10.0.0.1");
        a.auth = Some(ao_auth(vec![ao(1, "a", true, false)]));
        let mut b = a.clone();
        b.auth = Some(ao_auth(vec![
            ao(1, "a", true, false),
            ao(2, "b", false, true),
        ]));
        b.remote_as += 1;
        let (stop, spawn, update) = diff_peers(&map_of(&a), &map_of(&b));
        assert_eq!(stop.len(), 1);
        assert_eq!(spawn.len(), 1);
        assert_eq!(update.len(), 0);
    }

    fn map_of(p: &ResolvedPeer) -> HashMap<IpAddr, ResolvedPeer> {
        HashMap::from([(p.remote_address, p.clone())])
    }
}
