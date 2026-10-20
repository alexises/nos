//! RPKI origin validation (RFC 6811) fed by an RFC 8210 RTR client running
//! inside this `nos-bgpd`, one session per instance, inside its VRF.

pub mod community;
pub mod rtr;
pub mod vrp;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use nos_proto::{Config, RpkiCache, RpkiCacheStatus, RpkiSessionState};
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub use vrp::{origin_as, Vrp, VrpTable};

use crate::session::ResolvedAuth;

/// Every cache's `auth`, labels looked up in the admin keystore, keyed by the
/// cache's socket address. Part of what the client was started with, so a
/// rotated secret restarts it.
pub fn resolve_auths(caches: &[RpkiCache], cfg: &Config) -> HashMap<SocketAddr, ResolvedAuth> {
    caches
        .iter()
        .filter_map(|c| {
            let auth = ResolvedAuth::resolve(c.auth.as_ref()?, cfg)?;
            Some((SocketAddr::new(c.address, c.port), auth))
        })
        .collect()
}

/// One configured cache's live state, in `rtr::run`'s preference order.
#[derive(Debug, Clone)]
pub struct CacheStatus {
    pub cache: RpkiCache,
    pub state: RpkiSessionState,
    pub active: bool,
    pub version: Option<u8>,
    pub session_id: Option<u16>,
    pub serial: Option<u32>,
    pub vrp_count: usize,
    pub last_update: Option<Instant>,
}

pub type SharedStatus = Arc<Mutex<Vec<CacheStatus>>>;

/// RFC 8210 §10: the lowest preference first, ties in configured order.
pub fn sorted(mut caches: Vec<RpkiCache>) -> Vec<RpkiCache> {
    caches.sort_by_key(|c| c.preference);
    caches
}

pub fn new_status(caches: &[RpkiCache]) -> SharedStatus {
    Arc::new(Mutex::new(
        caches
            .iter()
            .map(|c| CacheStatus {
                cache: c.clone(),
                state: RpkiSessionState::Idle,
                active: false,
                version: None,
                session_id: None,
                serial: None,
                vrp_count: 0,
                last_update: None,
            })
            .collect(),
    ))
}

pub fn summaries(status: &SharedStatus) -> Vec<RpkiCacheStatus> {
    status
        .lock()
        .expect("rpki status lock")
        .iter()
        .map(|s| RpkiCacheStatus {
            address: s.cache.address,
            port: s.cache.port,
            preference: s.cache.preference,
            state: s.state,
            active: s.active,
            version: s.version,
            session_id: s.session_id,
            serial: s.serial,
            vrp_count: s.vrp_count,
            last_update_secs: s.last_update.map(|t| t.elapsed().as_secs()),
            authenticated: s.cache.auth.is_some(),
        })
        .collect()
}

/// A running RTR client: what it was started with, and how to stop it.
pub struct Client {
    pub caches: Vec<RpkiCache>,
    pub auths: HashMap<SocketAddr, ResolvedAuth>,
    pub vrf: Option<String>,
    pub status: SharedStatus,
    pub task: JoinHandle<()>,
}

impl Client {
    /// Starts `rtr::run`, seeded with `current` so a restart (a config or
    /// VRF change) keeps validating with the last VRP set until the new
    /// session's first End of Data.
    #[allow(
        clippy::implicit_hasher,
        reason = "one concrete map, built by resolve_auths"
    )]
    pub fn spawn(
        caches: &[RpkiCache],
        auths: HashMap<SocketAddr, ResolvedAuth>,
        vrf: Option<String>,
        current: Arc<VrpTable>,
    ) -> (Self, watch::Receiver<Arc<VrpTable>>) {
        let caches = sorted(caches.to_vec());
        let status = new_status(&caches);
        let (tx, rx) = watch::channel(current);
        let task = tokio::spawn(rtr::run(
            caches.clone(),
            auths.clone(),
            vrf.clone(),
            status.clone(),
            tx,
        ));
        (
            Self {
                caches,
                auths,
                vrf,
                status,
                task,
            },
            rx,
        )
    }
}
