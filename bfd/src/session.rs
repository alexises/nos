//! One BFD session: `Core` is the pure state (packets, timers and clock in,
//! packets out), `run` the tokio task that feeds it.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nos_proto::schema::{BfdAuthMethod, BfdProfile};
use nos_proto::{BfdDiag, BfdState, SessionKey};
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::auth::{AuthError, AuthState};
use crate::fsm::{self, Event};
use crate::packet::Packet;
use crate::timers::{Remote, Timers, SLOW_US};

/// Where a session's packets leave: one connected UDP socket for real, a
/// recorder in tests.
pub trait Tx: Send + Sync {
    fn send(&self, bytes: &[u8]) -> io::Result<()>;
}

/// What the rest of the daemon (and `show bfd sessions`) sees of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    pub state: BfdState,
    pub diag: BfdDiag,
    pub local_discriminator: u32,
    pub remote_discriminator: u32,
    pub tx_interval_us: u32,
    pub detection_time_us: u32,
    /// C bit at both ends (see `BfdEvent::State`).
    pub control_plane_independent: bool,
    /// The configured authentication (never the key).
    pub auth_method: Option<BfdAuthMethod>,
    pub auth_key_id: Option<u8>,
    /// Packets dropped by §6.7 authentication so far.
    pub auth_failures: u64,
}

/// RFC 5880 §4.1 C bit: `nos-bfdd` is its own process, so a `nos-bgpd`
/// restart does not stop its packets.
const LOCAL_CPI: bool = true;

#[derive(Debug)]
pub struct Core {
    profile: BfdProfile,
    state: BfdState,
    diag: BfdDiag,
    local_disc: u32,
    remote_disc: u32,
    /// The remote's Required Min RX; 0 silences us (§6.8.7). Starts at 1:
    /// nothing is known yet.
    remote_rx: u32,
    /// The C bit of the last packet received.
    remote_cpi: bool,
    timers: Timers,
    auth: AuthState,
    auth_failures: u64,
}

const MS: u32 = 1000;

impl Core {
    pub fn new(profile: BfdProfile, local_disc: u32, now: Instant) -> Self {
        let timers = Timers::new(
            profile.min_tx_interval * MS,
            profile.min_rx_interval * MS,
            profile.detect_multiplier,
            now,
        );
        let auth = AuthState::new(profile.auth.clone(), rand_u32(), now);
        let mut core = Core {
            profile,
            state: BfdState::Down,
            diag: BfdDiag::NoDiagnostic,
            local_disc,
            remote_disc: 0,
            remote_rx: 1,
            remote_cpi: false,
            timers,
            auth,
            auth_failures: 0,
        };
        if core.profile.shutdown {
            core.apply(Event::AdminDown);
        }
        core
    }

    pub fn status(&self) -> Status {
        Status {
            state: self.state,
            diag: self.diag,
            local_discriminator: self.local_disc,
            remote_discriminator: self.remote_disc,
            tx_interval_us: self.timers.tx_interval_us(self.state).unwrap_or(SLOW_US),
            detection_time_us: self
                .timers
                .detection_time_us()
                .map_or(0, |us| u32::try_from(us).unwrap_or(u32::MAX)),
            control_plane_independent: LOCAL_CPI && self.remote_cpi,
            auth_method: self.auth.cfg().map(|a| a.method),
            auth_key_id: self.auth.cfg().map(|a| a.key_id),
            auth_failures: self.auth_failures,
        }
    }

    fn detection_time(&self) -> Option<Duration> {
        self.timers.detection_time_us().map(Duration::from_micros)
    }

    /// RFC 5880 §6.7.2 for a decoded packet; call before `on_packet`. An
    /// `Err` packet must be dropped: it neither refreshes the detection timer
    /// nor moves the state.
    pub fn authenticate(&mut self, now: Instant, p: &Packet) -> Result<(), AuthError> {
        let r = self
            .auth
            .check(now, p.detect_mult, p.auth.as_ref(), self.detection_time());
        if r.is_err() {
            self.auth_failures += 1;
        }
        r
    }

    /// The wire bytes of an outgoing packet, signed when auth is configured.
    pub fn sign(&mut self, now: Instant, p: &Packet) -> Vec<u8> {
        let d = self.detection_time();
        self.auth.sign(now, &p.encode(), d)
    }

    /// Applies one FSM event; whether the state changed.
    fn apply(&mut self, ev: Event) -> bool {
        let (next, diag) = fsm::step(self.state, ev);
        if let Some(d) = diag {
            self.diag = d;
        }
        let changed = next != self.state;
        self.state = next;
        // §6.8.4: the remote is forgotten when it stops talking.
        if changed && ev == Event::DetectTimeout {
            self.remote_disc = 0;
        }
        changed
    }

    fn packet(&self, final_: bool) -> Packet {
        let (desired_min_tx, required_min_rx) = self.timers.advertised(self.state);
        Packet {
            diag: self.diag.code(),
            state: self.state,
            // P and F are never both set (§6.5).
            poll: self.timers.poll() && !final_,
            final_,
            control_plane_independent: LOCAL_CPI,
            demand: false,
            detect_mult: self.profile.detect_multiplier,
            my_discriminator: self.local_disc,
            your_discriminator: self.remote_disc,
            desired_min_tx,
            required_min_rx,
            required_min_echo_rx: 0,
            auth: None,
        }
    }

    /// A packet from the remote. The returned packet goes out at once: the
    /// Final answering a Poll, or the first packet of a new state.
    pub fn on_packet(&mut self, now: Instant, p: &Packet, rand_pct: u32) -> Option<Packet> {
        // §6.8.6: AdminDown discards everything; a nonzero Your Discriminator
        // must be ours.
        if self.state == BfdState::AdminDown
            || (p.your_discriminator != 0 && p.your_discriminator != self.local_disc)
        {
            return None;
        }
        self.remote_disc = p.my_discriminator;
        self.remote_rx = p.required_min_rx;
        self.remote_cpi = p.control_plane_independent;
        let out = self.timers.on_rx(
            now,
            Remote {
                desired_min_tx: p.desired_min_tx,
                required_min_rx: p.required_min_rx,
                detect_mult: p.detect_mult,
            },
            p.poll,
            p.final_,
        );
        let changed = self.apply(Event::RxState(p.state));
        if out.reply_final || changed {
            self.timers.schedule_tx(now, self.state, rand_pct);
            return Some(self.packet(out.reply_final));
        }
        None
    }

    /// The clock reached `deadline()`: detection expiry and periodic transmit.
    pub fn on_timer(&mut self, now: Instant, rand_pct: u32) -> Option<Packet> {
        let mut due = false;
        if matches!(self.state, BfdState::Init | BfdState::Up) && self.timers.detect_expired(now) {
            due = self.apply(Event::DetectTimeout);
        }
        if due || self.timers.tx_due(now) {
            self.timers.schedule_tx(now, self.state, rand_pct);
            if fsm::may_transmit(self.profile.passive, self.remote_disc, self.remote_rx) {
                return Some(self.packet(false));
            }
        }
        None
    }

    /// A re-`Register` with a new profile: intervals go through Poll/Final
    /// (§6.5, no flap), `shutdown` through `AdminDown`. A packet goes out at
    /// once when that opened a Poll sequence or moved the state.
    pub fn update_profile(
        &mut self,
        profile: BfdProfile,
        now: Instant,
        rand_pct: u32,
    ) -> Option<Packet> {
        let was_polling = self.timers.poll();
        let was_down = profile.shutdown != self.profile.shutdown;
        self.timers.set_detect_mult(profile.detect_multiplier);
        self.timers
            .change(profile.min_tx_interval * MS, profile.min_rx_interval * MS);
        let hold = self.detection_time().unwrap_or(Duration::from_secs(3));
        self.auth.set(profile.auth.clone(), now, hold);
        let shutdown = profile.shutdown;
        self.profile = profile;
        let moved = was_down
            && self.apply(if shutdown {
                Event::AdminDown
            } else {
                Event::AdminUp
            });
        if moved || (!was_polling && self.timers.poll()) {
            self.timers.schedule_tx(now, self.state, rand_pct);
            return Some(self.packet(false));
        }
        None
    }

    /// When `on_timer` next has work.
    pub fn deadline(&self) -> Instant {
        let tx = self.timers.next_tx();
        match self.timers.detect_deadline() {
            Some(d) if matches!(self.state, BfdState::Init | BfdState::Up) => tx.min(d),
            _ => tx,
        }
    }
}

/// Cheap jitter source for §6.8.7 and the discriminator start: a fresh
/// `RandomState` is seeded from the OS per instance.
pub fn rand_u32() -> u32 {
    use std::hash::{BuildHasher, Hasher};
    // ponytail: SipHash of nothing, not a CSPRNG; it seeds discriminators and
    // the auth XmitAuthSeq start, neither of which is a secret (the key is).
    // Swap for `getrandom` if they must be unguessable.
    #[allow(clippy::cast_possible_truncation, reason = "low half is enough")]
    let v = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish() as u32;
    v
}

/// Minimum gap between two `bfd auth failed` warnings of one session.
const AUTH_WARN_EVERY: Duration = Duration::from_secs(10);

fn jitter_pct() -> u32 {
    75 + rand_u32() % 26
}

fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// The session task. Ends when the manager drops its senders (or aborts it).
pub async fn run(
    key: SessionKey,
    mut core: Core,
    tx: Arc<dyn Tx>,
    mut pkts: mpsc::Receiver<Packet>,
    mut cmds: mpsc::Receiver<BfdProfile>,
    status: watch::Sender<Status>,
) {
    let mut last = core.status();
    let mut last_warn: Option<Instant> = None;
    loop {
        let deadline = tokio::time::Instant::from_std(core.deadline());
        let out = tokio::select! {
            p = pkts.recv() => match p {
                Some(p) => match core.authenticate(now(), &p) {
                    Ok(()) => core.on_packet(now(), &p, jitter_pct()),
                    Err(e) => {
                        // Rate-limited: a wrong key is a packet every interval.
                        if last_warn.is_none_or(|t| now() - t >= AUTH_WARN_EVERY) {
                            last_warn = Some(now());
                            warn!(peer = %key.peer, table = %key.table, reason = %e, "bfd auth failed");
                        }
                        None
                    }
                },
                None => break,
            },
            c = cmds.recv() => match c {
                Some(c) => core.update_profile(c, now(), jitter_pct()),
                None => break,
            },
            () = tokio::time::sleep_until(deadline) => core.on_timer(now(), jitter_pct()),
        };
        if let Some(p) = out {
            if let Err(e) = tx.send(&core.sign(now(), &p)) {
                debug!(peer = %key.peer, error = %e, "bfd send failed");
            }
        }
        let s = core.status();
        if s != last {
            if s.state != last.state {
                log_transition(&key, &s);
            }
            last = s;
            status.send_replace(s);
        }
    }
}

fn log_transition(key: &SessionKey, s: &Status) {
    match s.state {
        BfdState::Up => info!(peer = %key.peer, table = %key.table, "bfd session up"),
        BfdState::Down | BfdState::AdminDown => {
            info!(peer = %key.peer, diag = %s.diag, table = %key.table, "bfd session down");
        }
        BfdState::Init => debug!(peer = %key.peer, "bfd session init"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn profile(tx: u32, rx: u32) -> BfdProfile {
        BfdProfile {
            name: "p".into(),
            min_tx_interval: tx,
            min_rx_interval: rx,
            ..BfdProfile::default()
        }
    }

    /// Two cores wired back to back; time only moves in `step`.
    struct Pair {
        a: Core,
        b: Core,
        now: Instant,
    }

    impl Pair {
        fn new(pa: BfdProfile, pb: BfdProfile) -> Self {
            let now = Instant::now();
            Pair {
                a: Core::new(pa, 1, now),
                b: Core::new(pb, 2, now),
                now,
            }
        }

        /// Delivers `p` to `to` and everything the replies trigger.
        fn deliver(now: Instant, from_a: bool, a: &mut Core, b: &mut Core, p: Packet) {
            let mut next = Some((from_a, p));
            while let Some((from_a, p)) = next.take() {
                let (tx, rx) = if from_a {
                    (&mut *a, &mut *b)
                } else {
                    (&mut *b, &mut *a)
                };
                // Over the wire, auth section included.
                let wire = tx.sign(now, &p);
                let p = crate::packet::decode(&wire).expect("our own packet decodes");
                if rx.authenticate(now, &p).is_err() {
                    continue;
                }
                if let Some(reply) = rx.on_packet(now, &p, 100) {
                    next = Some((!from_a, reply));
                }
            }
        }

        /// Advances to the earlier deadline and runs it.
        fn step(&mut self) {
            let a_first = self.a.deadline() <= self.b.deadline();
            self.now = self.a.deadline().min(self.b.deadline());
            let (core, from_a) = if a_first {
                (&mut self.a, true)
            } else {
                (&mut self.b, false)
            };
            if let Some(p) = core.on_timer(self.now, 100) {
                Self::deliver(self.now, from_a, &mut self.a, &mut self.b, p);
            }
        }

        fn run_until(&mut self, mut done: impl FnMut(&Pair) -> bool) {
            for _ in 0..200 {
                if done(self) {
                    return;
                }
                self.step();
            }
            panic!("not reached: a {:?} b {:?}", self.a.state, self.b.state);
        }
    }

    #[test]
    fn handshake_reaches_up_and_negotiates() {
        let mut p = Pair::new(profile(100, 100), profile(200, 150));
        p.run_until(|p| p.a.state == BfdState::Up && p.b.state == BfdState::Up);
        let s = p.a.status();
        assert_eq!(s.local_discriminator, 1);
        assert_eq!(s.remote_discriminator, 2);
        // max(our 100 ms, their required rx 150 ms)
        assert_eq!(s.tx_interval_us, 150_000);
        // 3 x max(our rx 100 ms, their tx 200 ms)
        assert_eq!(s.detection_time_us, 600_000);
    }

    #[test]
    fn c_bit_is_reported_only_when_both_ends_set_it() {
        let mut p = Pair::new(profile(100, 100), profile(100, 100));
        assert!(!p.a.status().control_plane_independent, "nothing received");
        p.run_until(|p| p.a.state == BfdState::Up && p.b.state == BfdState::Up);
        assert!(p.a.status().control_plane_independent);
        p.a.remote_cpi = false; // a peer whose BFD shares fate with its control plane
        assert!(!p.a.status().control_plane_independent);
    }

    #[test]
    fn silence_takes_the_session_down_with_the_diag() {
        let mut p = Pair::new(profile(100, 100), profile(100, 100));
        p.run_until(|p| p.a.state == BfdState::Up && p.b.state == BfdState::Up);
        // The link drops everything: only `a` keeps running.
        let t0 = p.now;
        for _ in 0..50 {
            p.now = p.a.deadline();
            p.a.on_timer(p.now, 100);
            if p.a.state == BfdState::Down {
                break;
            }
        }
        assert_eq!(p.a.diag, BfdDiag::ControlDetectionTimeExpired);
        assert_eq!(p.a.remote_disc, 0);
        assert!(p.now - t0 <= Duration::from_millis(400), "{:?}", p.now - t0);
    }

    #[test]
    fn profile_edit_polls_without_flapping() {
        let mut p = Pair::new(profile(100, 100), profile(100, 100));
        p.run_until(|p| p.a.state == BfdState::Up && p.b.state == BfdState::Up);
        let pkt =
            p.a.update_profile(profile(50, 50), p.now, 100)
                .expect("poll starts at once");
        assert!(pkt.poll);
        assert_eq!(pkt.desired_min_tx, 50_000);
        // Still using the old interval until Final.
        assert_eq!(p.a.status().tx_interval_us, 100_000);
        Pair::deliver(p.now, true, &mut p.a, &mut p.b, pkt);
        assert!(!p.a.timers.poll(), "Final closed the sequence");
        assert_eq!(p.a.status().tx_interval_us, 100_000);
        assert_eq!(p.a.state, BfdState::Up);
        assert_eq!(p.b.state, BfdState::Up);
    }

    fn authed(key: &str, id: u8) -> BfdProfile {
        use nos_proto::schema::BfdAuth;
        BfdProfile {
            auth: Some(BfdAuth {
                key_id: id,
                method: BfdAuthMethod::MeticulousSha1,
                key: key.into(),
            }),
            ..profile(100, 100)
        }
    }

    #[test]
    fn matching_keys_reach_up_and_a_key_change_does_not_flap() {
        let mut p = Pair::new(authed("a", 1), authed("a", 1));
        p.run_until(|p| p.a.state == BfdState::Up && p.b.state == BfdState::Up);
        assert_eq!(p.a.status().auth_failures, 0);
        assert_eq!(p.a.status().auth_key_id, Some(1));
        // Both ends switch at once (new id and secret); the old key covers
        // whatever crosses on the wire meanwhile.
        let pa = p.a.update_profile(authed("b", 2), p.now, 100);
        let pb = p.b.update_profile(authed("b", 2), p.now, 100);
        for (from_a, pkt) in [(true, pa), (false, pb)] {
            if let Some(pkt) = pkt {
                Pair::deliver(p.now, from_a, &mut p.a, &mut p.b, pkt);
            }
        }
        for _ in 0..30 {
            p.step();
            assert_eq!((p.a.state, p.b.state), (BfdState::Up, BfdState::Up));
        }
        assert_eq!(p.a.status().auth_key_id, Some(2));
    }

    #[test]
    fn mismatched_keys_never_come_up_and_are_counted() {
        let mut p = Pair::new(authed("a", 1), authed("b", 1));
        for _ in 0..50 {
            p.step();
        }
        assert_eq!((p.a.state, p.b.state), (BfdState::Down, BfdState::Down));
        assert!(p.a.status().auth_failures > 0);
        assert_eq!(p.a.remote_disc, 0, "a dropped packet teaches nothing");
    }

    #[test]
    fn auth_on_one_side_only_stays_down() {
        let mut p = Pair::new(authed("a", 1), profile(100, 100));
        for _ in 0..50 {
            p.step();
        }
        assert_eq!((p.a.state, p.b.state), (BfdState::Down, BfdState::Down));
        assert!(p.a.status().auth_failures > 0 && p.b.status().auth_failures > 0);
    }

    #[test]
    fn shutdown_goes_admin_down_and_back() {
        let mut p = Pair::new(profile(100, 100), profile(100, 100));
        p.run_until(|p| p.a.state == BfdState::Up && p.b.state == BfdState::Up);
        let mut down = profile(100, 100);
        down.shutdown = true;
        let pkt = p.a.update_profile(down, p.now, 100).unwrap();
        assert_eq!(pkt.state, BfdState::AdminDown);
        assert_eq!(p.a.diag, BfdDiag::AdministrativelyDown);
        Pair::deliver(p.now, true, &mut p.a, &mut p.b, pkt);
        assert_eq!(p.b.state, BfdState::Down);
        assert_eq!(p.b.diag, BfdDiag::NeighborSignaledSessionDown);
        // AdminDown ignores the peer; removal brings it back to Down.
        assert!(p.a.on_packet(p.now, &p.b.packet(false), 100).is_none());
        p.a.update_profile(profile(100, 100), p.now, 100);
        assert_eq!(p.a.state, BfdState::Down);
        p.run_until(|p| p.a.state == BfdState::Up && p.b.state == BfdState::Up);
    }

    #[test]
    fn started_in_shutdown_and_passive() {
        let mut sd = profile(100, 100);
        sd.shutdown = true;
        let c = Core::new(sd, 7, Instant::now());
        assert_eq!(c.state, BfdState::AdminDown);

        let mut passive = profile(100, 100);
        passive.passive = true;
        let now = Instant::now();
        let mut c = Core::new(passive, 7, now);
        assert!(c.on_timer(now, 100).is_none(), "passive stays silent");
        // Learning the remote discriminator ends the silence.
        let first = Core::new(profile(100, 100), 9, now).packet(false);
        let reply = c.on_packet(now, &first, 100).expect("state moved");
        assert_eq!(reply.your_discriminator, 9);
    }

    #[test]
    fn foreign_discriminator_is_dropped() {
        let now = Instant::now();
        let mut c = Core::new(profile(100, 100), 7, now);
        let mut p = Core::new(profile(100, 100), 9, now).packet(false);
        p.your_discriminator = 8;
        assert!(c.on_packet(now, &p, 100).is_none());
        assert_eq!(c.remote_disc, 0);
    }

    #[test]
    fn remote_min_rx_zero_silences_us() {
        let now = Instant::now();
        let mut c = Core::new(profile(100, 100), 7, now);
        let mut p = Core::new(profile(100, 100), 9, now).packet(false);
        p.required_min_rx = 0;
        c.on_packet(now, &p, 100);
        assert!(c.on_timer(now + Duration::from_secs(5), 100).is_none());
    }
}
