//! The session table: one task per `SessionKey`, shared by every client
//! that registered it and dropped with the last one. Also the receive-side
//! demultiplexer the sockets feed.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use nos_proto::schema::BfdProfile;
use nos_proto::{BfdSessionView, SessionKey};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info};

use crate::packet::{self, Packet};
use crate::session::{self, Core, Status, Tx};

/// How long a session waits before retrying a failed `Net::open` (the VRF
/// not known to `nos-ribd` yet, no route to the peer, ...).
const OPEN_RETRY: Duration = Duration::from_secs(1);

/// Opens the transmit path of a session and makes sure its receive socket
/// runs. The real one is `socket::UdpNet`.
#[async_trait]
pub trait Net: Send + Sync {
    async fn open(&self, key: &SessionKey) -> io::Result<Arc<dyn Tx>>;
}

/// A session as the receive path sees it.
#[derive(Clone)]
struct Slot {
    tx: mpsc::Sender<Packet>,
    multihop: bool,
    /// RFC 5883 §5 / GTSM floor from the profile (multihop only).
    min_ttl: u8,
}

/// RFC 5881 §5: single-hop packets must arrive with TTL 255; RFC 5883 §5:
/// multihop ones with at least the profile's `minimum-ttl`.
pub fn ttl_ok(multihop: bool, ttl: Option<u8>, min_ttl: u8) -> bool {
    match ttl {
        Some(t) if multihop => t >= min_ttl,
        Some(t) => t == 255,
        None => false,
    }
}

#[derive(Default)]
struct Tables {
    by_disc: HashMap<u32, Slot>,
    /// Packets with Your Discriminator 0 (§6.8.6: found by source address
    /// and table, plus the port the packet came in on). ponytail: no
    /// interface in the single-hop key (RFC 5881 §4 mentions it) and no
    /// local address in the multihop one (RFC 5883 §4 wants the pair), so two
    /// sessions to one peer address in one table collide; add the arrival
    /// interface / destination from `IP_PKTINFO` if that matters.
    by_peer: HashMap<(String, IpAddr, bool), Slot>,
}

/// Maps received datagrams to session tasks. Cloned into every socket task.
#[derive(Clone, Default)]
pub struct Demux(Arc<Mutex<Tables>>);

impl Demux {
    fn add(&self, disc: u32, key: &SessionKey, tx: &mpsc::Sender<Packet>, min_ttl: u8) {
        let mut t = self.0.lock().unwrap();
        let slot = Slot {
            tx: tx.clone(),
            multihop: key.multihop,
            min_ttl,
        };
        t.by_disc.insert(disc, slot.clone());
        t.by_peer
            .insert((key.table.clone(), key.peer, key.multihop), slot);
    }

    fn set_min_ttl(&self, disc: u32, key: &SessionKey, min_ttl: u8) {
        let mut t = self.0.lock().unwrap();
        if let Some(s) = t.by_disc.get_mut(&disc) {
            s.min_ttl = min_ttl;
        }
        if let Some(s) = t
            .by_peer
            .get_mut(&(key.table.clone(), key.peer, key.multihop))
        {
            s.min_ttl = min_ttl;
        }
    }

    fn remove(&self, disc: u32, key: &SessionKey) {
        let mut t = self.0.lock().unwrap();
        t.by_disc.remove(&disc);
        t.by_peer
            .remove(&(key.table.clone(), key.peer, key.multihop));
    }

    /// Decodes `data` (received on `table`'s single-hop or `multihop` socket
    /// from `src` with `ttl`) and hands it to its session. Whether a session
    /// took it.
    pub fn route(
        &self,
        table: &str,
        src: IpAddr,
        multihop: bool,
        ttl: Option<u8>,
        data: &[u8],
    ) -> bool {
        let p = match packet::decode(data) {
            Ok(p) => p,
            Err(e) => {
                debug!(peer = %src, error = %e, "bfd packet discarded");
                return false;
            }
        };
        let t = self.0.lock().unwrap();
        let session = if p.your_discriminator == 0 {
            t.by_peer.get(&(table.to_string(), src, multihop))
        } else {
            t.by_disc
                .get(&p.your_discriminator)
                .filter(|s| s.multihop == multihop)
        };
        let Some(s) = session else { return false };
        if !ttl_ok(multihop, ttl, s.min_ttl) {
            debug!(peer = %src, ttl = ?ttl, multihop, "bfd packet discarded: ttl");
            return false;
        }
        // A full queue drops the packet: BFD tolerates loss by design.
        s.tx.try_send(p).is_ok()
    }
}

struct Entry {
    clients: HashSet<u64>,
    profile: BfdProfile,
    disc: u32,
    cmd: mpsc::Sender<BfdProfile>,
    status: watch::Receiver<Status>,
    task: JoinHandle<()>,
}

pub struct Manager {
    net: Arc<dyn Net>,
    demux: Demux,
    sessions: Mutex<HashMap<SessionKey, Entry>>,
    next_disc: AtomicU32,
    next_client: AtomicU64,
}

impl Manager {
    pub fn new(net: Arc<dyn Net>, demux: Demux) -> Arc<Self> {
        Arc::new(Manager {
            net,
            demux,
            sessions: Mutex::default(),
            // Random start (§6.8.1: not guessable), never 0.
            next_disc: AtomicU32::new(session::rand_u32() | 1),
            next_client: AtomicU64::new(1),
        })
    }

    pub fn new_client(&self) -> u64 {
        self.next_client.fetch_add(1, Ordering::Relaxed)
    }

    /// A discriminator from the daemon-wide counter, skipping 0 and any in
    /// use (4 billion values, so the scan is nearly never a second step).
    fn alloc_disc(&self, taken: &HashMap<SessionKey, Entry>) -> u32 {
        loop {
            let d = self.next_disc.fetch_add(1, Ordering::Relaxed);
            if d != 0 && !taken.values().any(|e| e.disc == d) {
                return d;
            }
        }
    }

    /// Adds `client` to the session `key`, starting it if it is new, and
    /// applies `profile` (a changed one runs Poll/Final). The status receiver
    /// holds the session's current state. ponytail: the last registration's
    /// profile wins when two clients disagree about one key.
    pub fn register(
        &self,
        client: u64,
        key: &SessionKey,
        profile: &BfdProfile,
    ) -> watch::Receiver<Status> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(e) = sessions.get_mut(key) {
            e.clients.insert(client);
            if e.profile != *profile {
                e.profile = profile.clone();
                self.demux.set_min_ttl(e.disc, key, profile.minimum_ttl);
                let _ = e.cmd.try_send(profile.clone());
            }
            return e.status.clone();
        }
        let disc = self.alloc_disc(&sessions);
        let core = Core::new(
            profile.clone(),
            disc,
            tokio::time::Instant::now().into_std(),
        );
        let (status_tx, status_rx) = watch::channel(core.status());
        let (pkt_tx, pkt_rx) = mpsc::channel(64);
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        self.demux.add(disc, key, &pkt_tx, profile.minimum_ttl);
        info!(peer = %key.peer, table = %key.table, multihop = key.multihop, "bfd session registered");
        let net = self.net.clone();
        let k = key.clone();
        let task = tokio::spawn(async move {
            let tx = loop {
                match net.open(&k).await {
                    Ok(tx) => break tx,
                    Err(e) => {
                        debug!(peer = %k.peer, table = %k.table, error = %e, "bfd session not ready, retrying");
                        tokio::time::sleep(OPEN_RETRY).await;
                    }
                }
            };
            session::run(k, core, tx, pkt_rx, cmd_rx, status_tx).await;
        });
        sessions.insert(
            key.clone(),
            Entry {
                clients: HashSet::from([client]),
                profile: profile.clone(),
                disc,
                cmd: cmd_tx,
                status: status_rx.clone(),
                task,
            },
        );
        status_rx
    }

    fn release(&self, sessions: &mut HashMap<SessionKey, Entry>, client: u64, key: &SessionKey) {
        let Some(e) = sessions.get_mut(key) else {
            return;
        };
        e.clients.remove(&client);
        if e.clients.is_empty() {
            let e = sessions.remove(key).expect("just seen");
            e.task.abort();
            self.demux.remove(e.disc, key);
            info!(peer = %key.peer, table = %key.table, "bfd session removed");
        }
    }

    pub fn deregister(&self, client: u64, key: &SessionKey) {
        let mut sessions = self.sessions.lock().unwrap();
        self.release(&mut sessions, client, key);
    }

    /// A client's connection went away: it releases everything it held.
    pub fn drop_client(&self, client: u64) {
        let mut sessions = self.sessions.lock().unwrap();
        let keys: Vec<SessionKey> = sessions
            .iter()
            .filter(|(_, e)| e.clients.contains(&client))
            .map(|(k, _)| k.clone())
            .collect();
        for k in keys {
            self.release(&mut sessions, client, &k);
        }
    }

    /// Every session (or the ones to `peer`), ordered by table then peer.
    pub fn sessions(&self, peer: Option<IpAddr>) -> Vec<BfdSessionView> {
        let sessions = self.sessions.lock().unwrap();
        let mut all: Vec<BfdSessionView> = sessions
            .iter()
            .filter(|(k, _)| peer.is_none_or(|p| k.peer == p))
            .map(|(k, e)| {
                let s = *e.status.borrow();
                BfdSessionView {
                    key: k.clone(),
                    state: s.state,
                    diag: s.diag,
                    local_discriminator: s.local_discriminator,
                    remote_discriminator: s.remote_discriminator,
                    tx_interval_us: s.tx_interval_us,
                    detection_time_us: s.detection_time_us,
                    auth_method: s.auth_method,
                    auth_key_id: s.auth_key_id,
                    auth_failures: s.auth_failures,
                }
            })
            .collect();
        all.sort_by(|a, b| (&a.key.table, a.key.peer).cmp(&(&b.key.table, b.key.peer)));
        all
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use nos_proto::BfdState;

    pub struct Sent(pub Mutex<Vec<Vec<u8>>>);
    impl Tx for Sent {
        fn send(&self, b: &[u8]) -> io::Result<()> {
            self.0.lock().unwrap().push(b.to_vec());
            Ok(())
        }
    }

    pub struct MockNet {
        pub sent: Arc<Sent>,
        pub fail: bool,
    }

    #[async_trait]
    impl Net for MockNet {
        async fn open(&self, _: &SessionKey) -> io::Result<Arc<dyn Tx>> {
            if self.fail {
                return Err(io::Error::other("no vrf yet"));
            }
            Ok(self.sent.clone())
        }
    }

    pub fn key(peer: &str) -> SessionKey {
        SessionKey {
            table: "rt1".into(),
            peer: peer.parse().unwrap(),
            local: None,
            interface: None,
            multihop: false,
        }
    }

    pub fn mgr(fail: bool) -> (Arc<Manager>, Arc<Sent>, Demux) {
        let sent = Arc::new(Sent(Mutex::default()));
        let demux = Demux::default();
        let net = Arc::new(MockNet {
            sent: sent.clone(),
            fail,
        });
        (Manager::new(net, demux.clone()), sent, demux)
    }

    #[tokio::test]
    async fn refcount_shares_one_session() {
        let (m, _, demux) = mgr(false);
        let (c1, c2) = (m.new_client(), m.new_client());
        let k = key("192.0.2.1");
        let p = BfdProfile::default();
        let r1 = m.register(c1, &k, &p);
        let r2 = m.register(c2, &k, &p);
        assert_eq!(m.sessions(None).len(), 1);
        assert_eq!(
            r1.borrow().local_discriminator,
            r2.borrow().local_discriminator
        );
        assert_ne!(r1.borrow().local_discriminator, 0);
        assert_eq!(r1.borrow().state, BfdState::Down);

        m.deregister(c1, &k);
        assert_eq!(m.sessions(None).len(), 1, "b still holds it");
        m.drop_client(c2);
        assert_eq!(m.sessions(None).len(), 0);
        assert!(demux.0.lock().unwrap().by_disc.is_empty());
        assert!(demux.0.lock().unwrap().by_peer.is_empty());
    }

    #[tokio::test]
    async fn discriminators_differ_and_peer_filter_works() {
        let (m, _, _) = mgr(false);
        let c = m.new_client();
        m.register(c, &key("192.0.2.1"), &BfdProfile::default());
        m.register(c, &key("192.0.2.2"), &BfdProfile::default());
        let all = m.sessions(None);
        assert_eq!(all.len(), 2);
        assert_ne!(
            all[0].local_discriminator, all[1].local_discriminator,
            "{all:?}"
        );
        assert_eq!(m.sessions(Some("192.0.2.2".parse().unwrap())).len(), 1);
        assert_eq!(m.sessions(Some("192.0.2.9".parse().unwrap())).len(), 0);
    }

    #[tokio::test]
    async fn session_transmits_once_open_and_demux_routes_replies() {
        let (m, sent, demux) = mgr(false);
        let k = key("192.0.2.1");
        let rx = m.register(m.new_client(), &k, &BfdProfile::default());
        // The first periodic packet goes out at once.
        for _ in 0..50 {
            if !sent.0.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let first = packet::decode(&sent.0.lock().unwrap()[0]).unwrap();
        assert_eq!(first.state, BfdState::Down);
        assert_eq!(first.my_discriminator, rx.borrow().local_discriminator);

        // A reply from the peer: Down with Your Discriminator 0 is found by
        // address, then Init is by discriminator.
        let mut reply = Packet {
            my_discriminator: 77,
            your_discriminator: 0,
            ..first
        };
        assert!(demux.route("rt1", k.peer, false, Some(255), &reply.encode()));
        assert!(
            !demux.route("rt2", k.peer, false, Some(255), &reply.encode()),
            "wrong table"
        );
        reply.state = BfdState::Init;
        reply.your_discriminator = rx.borrow().local_discriminator;
        assert!(demux.route(
            "rt1",
            "192.0.2.77".parse().unwrap(),
            false,
            Some(255),
            &reply.encode()
        ));
        assert!(
            !demux.route("rt1", k.peer, false, Some(255), &[0u8; 3]),
            "garbage"
        );
        assert!(
            !demux.route("rt1", k.peer, false, Some(254), &reply.encode()),
            "single-hop wants 255"
        );
        assert!(
            !demux.route("rt1", k.peer, true, Some(255), &reply.encode()),
            "wrong port"
        );
    }

    #[test]
    fn ttl_rule_single_and_multihop() {
        assert!(ttl_ok(false, Some(255), 254));
        assert!(!ttl_ok(false, Some(254), 254), "single-hop is exactly 255");
        assert!(ttl_ok(true, Some(254), 254));
        assert!(ttl_ok(true, Some(255), 254));
        assert!(!ttl_ok(true, Some(253), 254));
        assert!(!ttl_ok(true, None, 0), "no TTL from the kernel: drop");
    }

    /// RFC 5883: a multihop session shares no state with a single-hop one to
    /// the same address and is demuxed by port and TTL.
    #[tokio::test]
    async fn multihop_sessions_are_separate_and_demuxed_by_port_and_ttl() {
        let (m, _, demux) = mgr(false);
        let c = m.new_client();
        let single = key("192.0.2.1");
        let multi = SessionKey {
            multihop: true,
            local: Some("192.0.2.9".parse().unwrap()),
            ..single.clone()
        };
        m.register(c, &single, &BfdProfile::default());
        m.register(c, &multi, &BfdProfile::default());
        assert_eq!(m.sessions(None).len(), 2);
        let p = Packet {
            diag: 0,
            state: BfdState::Down,
            poll: false,
            final_: false,
            control_plane_independent: false,
            demand: false,
            detect_mult: 3,
            my_discriminator: 5,
            your_discriminator: 0,
            desired_min_tx: 1_000_000,
            required_min_rx: 1_000_000,
            required_min_echo_rx: 0,
            auth: None,
        };
        assert!(demux.route("rt1", multi.peer, true, Some(254), &p.encode()));
        assert!(!demux.route("rt1", multi.peer, true, Some(253), &p.encode()));
        let raised = BfdProfile {
            minimum_ttl: 255,
            ..BfdProfile::default()
        };
        m.register(c, &multi, &raised);
        assert!(!demux.route("rt1", multi.peer, true, Some(254), &p.encode()));
        m.drop_client(c);
        assert!(demux.0.lock().unwrap().by_peer.is_empty());
    }

    #[tokio::test]
    async fn open_failure_retries_without_blocking_register() {
        let (m, sent, _) = mgr(true);
        let rx = m.register(m.new_client(), &key("192.0.2.1"), &BfdProfile::default());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(sent.0.lock().unwrap().is_empty());
        assert_eq!(rx.borrow().state, BfdState::Down);
    }

    #[tokio::test]
    async fn changed_profile_reaches_the_running_session() {
        let (m, _, _) = mgr(false);
        let c = m.new_client();
        let k = key("192.0.2.1");
        m.register(c, &k, &BfdProfile::default());
        let down = BfdProfile {
            shutdown: true,
            ..BfdProfile::default()
        };
        let mut rx = m.register(c, &k, &down);
        tokio::time::timeout(Duration::from_secs(2), async {
            while rx.borrow().state != BfdState::AdminDown {
                rx.changed().await.unwrap();
            }
        })
        .await
        .expect("session went admin-down");
    }
}
