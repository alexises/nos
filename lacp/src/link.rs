//! One member port's own Receive/Periodic-Transmission/Mux machines and I/O
//! — the LACP counterpart of `ospf::link.rs`'s per-link `run()` shape.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nos_proto::LacpRate;
use tokio::sync::{watch, Notify};
use tracing::{debug, info, warn};

use crate::churn_machine::{self, ChurnState};
use crate::mux_machine::{self, MuxState};
use crate::packet::{self, state_bit, Lacpdu, PortInfo};
use crate::periodic_tx_machine::interval_for;
use crate::receive_machine::{self, ReceiveState};
use crate::socket::LacpSocket;

/// Static, aggregate-wide identity handed to every one of its member ports
/// — see `aggregate.rs`'s doc comment for how `system_id`/`key` are
/// derived.
#[derive(Debug, Clone)]
pub struct LinkConfig {
    pub interface: String,
    pub actor_system_id: [u8; 6],
    pub actor_system_priority: u16,
    pub actor_key: u16,
    pub actor_port_priority: u16,
    /// How fast we ask the partner to send (our advertised `LACP_Timeout`),
    /// and so how long we wait for it — see `receive_machine`.
    pub rate: LacpRate,
    /// This aggregate's `selected_rx.borrow()` reflects Selection Logic's
    /// current verdict for this specific port — updated by `aggregate.rs`
    /// whenever it re-runs `selection::select` (on any port's observation
    /// change).
    pub selected_rx: watch::Receiver<bool>,
    /// 802.1AX `Churn_Detection_Time` (60s; shortened only by tests/e2e via
    /// `NOS_LACP_CHURN_SECS`, see `aggregate.rs`).
    pub churn_time: Duration,
}

/// One member port's currently-observed state, as reported up to
/// `aggregate.rs` after every event that could change it — the input to
/// `selection::select`, the active-member-set computation, and `show lacp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortObservation {
    pub receive_state: ReceiveState,
    pub mux_state: MuxState,
    pub actor_port: u16,
    /// The partner's last recorded Actor information — `None` until a
    /// LACPDU has been heard, and again once the Receive Machine gives up.
    pub partner: Option<PortInfo>,
    pub actor_churn: ChurnState,
    pub partner_churn: ChurnState,
}

impl PortObservation {
    /// A churned port (either side stuck out of sync for a whole
    /// `Churn_Detection_Time`) carries no traffic: `aggregate.rs` leaves it
    /// out of the active-member set.
    pub fn is_churned(&self) -> bool {
        self.actor_churn == ChurnState::Churn || self.partner_churn == ChurnState::Churn
    }

    pub fn current(&self) -> bool {
        self.receive_state == ReceiveState::Current
    }
}

/// A deadline far enough in the future to act as "this timer is disabled" —
/// simpler than threading `Option<Instant>` through every `tokio::select!`
/// branch for a state (`Waiting`) this port spends only a couple of seconds
/// in per selection change.
fn far_future() -> Instant {
    Instant::now() + Duration::from_hours(24)
}

/// Runs one member port's LACP engine until its socket dies or the
/// aggregate drops it (the caller aborts this task — see
/// `aggregate.rs::reconcile`, mirroring `ospf::link::LinkManager`'s own
/// abort-based teardown). Reports every observable state change into
/// `observations[interface]`, then signals `changed` so `aggregate.rs` can
/// re-run Selection Logic and recompute the aggregate's active-member set.
#[allow(clippy::implicit_hasher)] // always the default hasher; never needs to be generic here
pub async fn run(
    config: LinkConfig,
    observations: Arc<Mutex<HashMap<String, PortObservation>>>,
    changed: Arc<Notify>,
) {
    let socket = match crate::socket::open(&config.interface) {
        Ok(s) => s,
        Err(e) => {
            warn!(interface = %config.interface, error = %e, "failed to open lacp socket");
            return;
        }
    };
    // `& 0xffff` always yields a value in `0..=0xffff` regardless of the
    // operand's sign, so this always fits.
    let port_number =
        u16::try_from(socket.ifindex() & 0xffff).expect("masked to 16 bits, always fits");

    let mut receive_state = ReceiveState::Current; // overwritten by Started below
    let mut mux_state = MuxState::Detached;
    let mut current_while_deadline = Instant::now();
    let mut wait_while_deadline = far_future();
    let mut partner: Option<PortInfo> = None;
    let mut selected_rx = config.selected_rx.clone();

    let (rs, action) = receive_machine::step(receive_state, receive_machine::Event::Started);
    receive_state = rs;
    apply_receive_action(action, &mut current_while_deadline);

    // First send is immediate; each later one is scheduled from the state at
    // the time of the previous send (see `periodic_tx_machine::interval_for`).
    let mut tx = TxState::new();

    let mut churn = Churn::new(&config.interface, config.churn_time);
    churn.eval(mux_state, partner);
    report(
        &observations,
        &changed,
        &config.interface,
        port_number,
        receive_state,
        mux_state,
        partner,
        &churn,
    );

    loop {
        tokio::select! {
            () = tokio::time::sleep_until(tx.next_periodic_send.into()) => {
                let pdu = build_pdu(&config, port_number, receive_state, mux_state, partner);
                // Must move the deadline forward every time it fires, or the
                // elapsed deadline re-fires immediately: a hot loop. A send
                // denied by the limiter retries at the next refill instead
                // (`transmit` sets that).
                tx.next_periodic_send = Instant::now() + interval_for(
                    receive_state,
                    partner.is_some_and(|p| p.has_state(state_bit::TIMEOUT)),
                );
                tx.transmit(&socket, &config.interface, pdu);
            }
            () = tokio::time::sleep_until(current_while_deadline.into()) => {
                let (rs, action) = receive_machine::step(receive_state, receive_machine::Event::CurrentWhileTimerExpired);
                receive_state = rs;
                apply_receive_action(action, &mut current_while_deadline);
                if receive_state != ReceiveState::Current {
                    partner = None;
                    let (ms, mux_action) = mux_machine::step(
                        mux_state,
                        mux_machine::Event::PartnerStateChanged { synchronized: false, collecting: false },
                    );
                    mux_state = ms;
                    apply_mux_action(mux_action, &mut wait_while_deadline);
                }
                info!(interface = %config.interface, receive_state = ?receive_state, "lacp receive machine transitioned");
                churn.eval(mux_state, partner);
                report(&observations, &changed, &config.interface, port_number, receive_state, mux_state, partner, &churn);
                tx.send_if_changed(&socket, &config.interface, build_pdu(&config, port_number, receive_state, mux_state, partner));
            }
            () = tokio::time::sleep_until(churn.actor_deadline.into()) => {
                churn.expire_actor();
                report(&observations, &changed, &config.interface, port_number, receive_state, mux_state, partner, &churn);
            }
            () = tokio::time::sleep_until(churn.partner_deadline.into()) => {
                churn.expire_partner();
                report(&observations, &changed, &config.interface, port_number, receive_state, mux_state, partner, &churn);
            }
            () = tokio::time::sleep_until(wait_while_deadline.into()) => {
                let (ms, action) = mux_machine::step(mux_state, mux_machine::Event::WaitWhileTimerExpired);
                mux_state = ms;
                apply_mux_action(action, &mut wait_while_deadline);
                info!(interface = %config.interface, mux_state = ?mux_state, "lacp mux machine transitioned");
                churn.eval(mux_state, partner);
                report(&observations, &changed, &config.interface, port_number, receive_state, mux_state, partner, &churn);
                tx.send_if_changed(&socket, &config.interface, build_pdu(&config, port_number, receive_state, mux_state, partner));
            }
            result = selected_rx.changed() => {
                if result.is_err() {
                    debug!(interface = %config.interface, "aggregate manager gone, lacp link task exiting");
                    return;
                }
                let selected = *selected_rx.borrow_and_update();
                let (ms, action) = mux_machine::step(mux_state, mux_machine::Event::SelectionChanged { selected });
                mux_state = ms;
                apply_mux_action(action, &mut wait_while_deadline);
                info!(interface = %config.interface, mux_state = ?mux_state, selected, "lacp mux machine transitioned");
                churn.eval(mux_state, partner);
                report(&observations, &changed, &config.interface, port_number, receive_state, mux_state, partner, &churn);
                tx.send_if_changed(&socket, &config.interface, build_pdu(&config, port_number, receive_state, mux_state, partner));
            }
            recv = socket.recv() => {
                let Ok(bytes) = recv else {
                    warn!(interface = %config.interface, error = ?recv.err(), "lacp socket closed, link task exiting");
                    return;
                };
                let Ok(pdu) = packet::decode(&bytes) else {
                    continue;
                };
                partner = Some(pdu.actor);
                let (rs, action) = receive_machine::step(
                    receive_state,
                    receive_machine::Event::LacpduReceived {
                        we_advertise_short_timeout: config.rate == LacpRate::Fast,
                    },
                );
                receive_state = rs;
                apply_receive_action(action, &mut current_while_deadline);
                let (ms, mux_action) = mux_machine::step(
                    mux_state,
                    mux_machine::Event::PartnerStateChanged {
                        synchronized: pdu.actor.has_state(state_bit::SYNCHRONIZATION),
                        collecting: pdu.actor.has_state(state_bit::COLLECTING),
                    },
                );
                mux_state = ms;
                apply_mux_action(mux_action, &mut wait_while_deadline);
                info!(
                    interface = %config.interface,
                    receive_state = ?receive_state,
                    mux_state = ?mux_state,
                    partner_system = ?pdu.actor.system,
                    "lacp lacpdu received"
                );
                churn.eval(mux_state, partner);
                report(&observations, &changed, &config.interface, port_number, receive_state, mux_state, partner, &churn);
                tx.send_if_changed(&socket, &config.interface, build_pdu(&config, port_number, receive_state, mux_state, partner));
            }
        }
    }
}

fn apply_receive_action(action: receive_machine::Action, current_while_deadline: &mut Instant) {
    match action {
        receive_machine::Action::StartCurrentWhileTimer(duration) => {
            *current_while_deadline = Instant::now() + duration.as_duration();
        }
        // `Defaulted` has no timer of its own — it waits indefinitely for a
        // fresh LACPDU (`Event::LacpduReceived`, handled separately below).
        // Without disabling the deadline here, the just-elapsed short timer
        // that triggered this very transition would immediately re-fire on
        // the next loop iteration.
        // `RecordDefault` (entering `Defaulted`) and `None` (`Defaulted`
        // re-expiring) both leave no live timer: `Defaulted` waits
        // indefinitely for a fresh LACPDU. Without disarming here, the
        // just-elapsed timer would re-fire on the next loop iteration.
        receive_machine::Action::RecordDefault | receive_machine::Action::None => {
            *current_while_deadline = far_future();
        }
    }
}

fn apply_mux_action(action: mux_machine::Action, wait_while_deadline: &mut Instant) {
    match action {
        mux_machine::Action::StartWaitWhileTimer => {
            *wait_while_deadline = Instant::now() + mux_machine::AGGREGATE_WAIT_TIME;
        }
        // `None` means nothing happened (e.g. a LACPDU arrived while still
        // `Waiting`): a pending wait must keep running.
        mux_machine::Action::None => {}
        // Every other action means the wait (if any) is over or moot. Leaving
        // the just-elapsed deadline in place would make the `sleep_until`
        // branch in `run` fire on every loop iteration — a hot loop that
        // floods the log and the wire.
        _ => {
            *wait_while_deadline = far_future();
        }
    }
}

#[allow(clippy::implicit_hasher, clippy::too_many_arguments)] // default hasher only; one call-site shape
fn report(
    observations: &Arc<Mutex<HashMap<String, PortObservation>>>,
    changed: &Arc<Notify>,
    interface: &str,
    actor_port: u16,
    receive_state: ReceiveState,
    mux_state: MuxState,
    partner: Option<PortInfo>,
    churn: &Churn,
) {
    let observation = PortObservation {
        receive_state,
        mux_state,
        actor_port,
        partner,
        actor_churn: churn.actor,
        partner_churn: churn.partner,
    };
    let mut observations = observations.lock().unwrap();
    // Only signal on a real change: `aggregate.rs` reacts to every
    // notification by re-running Selection Logic and feeding verdicts back to
    // the ports, so a redundant signal is one turn of a potential feedback
    // loop.
    if observations.get(interface) == Some(&observation) {
        return;
    }
    observations.insert(interface.to_string(), observation);
    drop(observations);
    changed.notify_one();
}

/// Both Churn Detection machines (§6.4.17) with their timer deadlines.
struct Churn {
    interface: String,
    actor: ChurnState,
    partner: ChurnState,
    actor_deadline: Instant,
    partner_deadline: Instant,
    time: Duration,
}

impl Churn {
    fn new(interface: &str, time: Duration) -> Self {
        Self {
            interface: interface.to_string(),
            actor: ChurnState::NoChurn,
            partner: ChurnState::NoChurn,
            actor_deadline: far_future(),
            partner_deadline: far_future(),
            time,
        }
    }

    /// Re-evaluates both sides' Synchronization bit after any state change.
    fn eval(&mut self, mux_state: MuxState, partner: Option<PortInfo>) {
        let actor_sync = matches!(
            mux_state,
            MuxState::Attached | MuxState::Collecting | MuxState::Distributing
        );
        let partner_sync = partner.is_some_and(|p| p.has_state(state_bit::SYNCHRONIZATION));
        let sync = |in_sync| churn_machine::Event::Sync { in_sync };
        self.feed_actor(sync(actor_sync));
        self.feed_partner(sync(partner_sync));
    }

    fn expire_actor(&mut self) {
        self.feed_actor(churn_machine::Event::TimerExpired);
    }

    fn expire_partner(&mut self) {
        self.feed_partner(churn_machine::Event::TimerExpired);
    }

    fn feed_actor(&mut self, event: churn_machine::Event) {
        let before = self.actor;
        Self::feed(&mut self.actor, &mut self.actor_deadline, event, self.time);
        self.log("actor", before, self.actor);
    }

    fn feed_partner(&mut self, event: churn_machine::Event) {
        let before = self.partner;
        Self::feed(
            &mut self.partner,
            &mut self.partner_deadline,
            event,
            self.time,
        );
        self.log("partner", before, self.partner);
    }

    fn log(&self, side: &str, before: ChurnState, after: ChurnState) {
        if before != after {
            info!(interface = %self.interface, churn = ?after, "lacp {side} churn machine transitioned");
        }
    }

    fn feed(
        state: &mut ChurnState,
        deadline: &mut Instant,
        event: churn_machine::Event,
        time: Duration,
    ) {
        let (next, action) = churn_machine::step(*state, event);
        *state = next;
        match action {
            churn_machine::Action::StartTimer => *deadline = Instant::now() + time,
            // Only `None` after an expiry leaves an elapsed deadline armed
            // (a hot loop) — disarm on anything but a still-running timer.
            churn_machine::Action::StopTimer => *deadline = far_future(),
            churn_machine::Action::None => {
                if next != ChurnState::Monitor {
                    *deadline = far_future();
                }
            }
        }
    }
}

/// This port's own advertised `Actor_State` byte — see 802.1AX Table 6-4.
/// `Activity`/`Aggregation` are always set (v1 has no Passive mode, no
/// `Individual` aggregation — see `lacp/CLAUDE.md`'s deferred list);
/// `Timeout` is the aggregate's `LacpRate` (set = Fast, asking the partner
/// to send every second); the rest reflect the live state machines.
fn actor_state_byte(receive_state: ReceiveState, mux_state: MuxState, rate: LacpRate) -> u8 {
    let mut state = state_bit::ACTIVITY | state_bit::AGGREGATION;
    if rate == LacpRate::Fast {
        state |= state_bit::TIMEOUT;
    }
    if matches!(
        mux_state,
        MuxState::Attached | MuxState::Collecting | MuxState::Distributing
    ) {
        state |= state_bit::SYNCHRONIZATION;
    }
    if matches!(mux_state, MuxState::Collecting | MuxState::Distributing) {
        state |= state_bit::COLLECTING;
    }
    if mux_state == MuxState::Distributing {
        state |= state_bit::DISTRIBUTING;
    }
    match receive_state {
        ReceiveState::Defaulted => state |= state_bit::DEFAULTED,
        ReceiveState::Expired => state |= state_bit::EXPIRED,
        ReceiveState::Current => {}
    }
    state
}

fn build_pdu(
    config: &LinkConfig,
    port_number: u16,
    receive_state: ReceiveState,
    mux_state: MuxState,
    partner: Option<PortInfo>,
) -> Lacpdu {
    let actor = PortInfo {
        system_priority: config.actor_system_priority,
        system: config.actor_system_id,
        key: config.actor_key,
        port_priority: config.actor_port_priority,
        port: port_number,
        state: actor_state_byte(receive_state, mux_state, config.rate),
    };
    // Before any LACPDU has ever been received, our own view of the
    // partner is all-zero/defaulted — 802.1AX's administrative default.
    let partner = partner.unwrap_or(PortInfo {
        system_priority: 0,
        system: [0; 6],
        key: 0,
        port_priority: 0,
        port: 0,
        state: 0,
    });
    Lacpdu {
        actor,
        partner,
        collector_max_delay: 0,
    }
}

fn send_lacpdu(socket: &LacpSocket, interface: &str, pdu: &Lacpdu) {
    match socket.send(&packet::encode(pdu)) {
        Ok(()) => {}
        // Expected while the link is down; the fast periodic send retries.
        Err(e) if crate::socket::is_link_down(&e) => {
            debug!(interface = %interface, "link down, lacpdu not sent");
        }
        Err(e) => warn!(interface = %interface, error = %e, "failed to send lacpdu"),
    }
}

/// 802.1AX §6.4.16: at most 3 LACPDUs per `Fast_Periodic_Time`, whatever the
/// NTT events. A fixed window refilled once per second.
const MAX_TX_PER_WINDOW: u8 = 3;
const TX_WINDOW: Duration = Duration::from_secs(1);

struct TxLimiter {
    tokens: u8,
    window_start: Instant,
}

impl TxLimiter {
    fn new(now: Instant) -> Self {
        Self {
            tokens: MAX_TX_PER_WINDOW,
            window_start: now,
        }
    }

    fn try_take(&mut self, now: Instant) -> bool {
        if now.duration_since(self.window_start) >= TX_WINDOW {
            self.tokens = MAX_TX_PER_WINDOW;
            self.window_start = now;
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    fn next_refill(&self) -> Instant {
        self.window_start + TX_WINDOW
    }
}

/// The Transmit machine's state: what we last sent (NTT), the rate limiter,
/// and when the periodic timer next fires.
struct TxState {
    last_sent: Option<Lacpdu>,
    limiter: TxLimiter,
    next_periodic_send: Instant,
}

fn needs_transmit(last_sent: Option<&Lacpdu>, pdu: &Lacpdu) -> bool {
    last_sent != Some(pdu)
}

impl TxState {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            last_sent: None,
            limiter: TxLimiter::new(now),
            // First send is immediate.
            next_periodic_send: now,
        }
    }

    /// Sends `pdu` if the limiter allows. A denied send leaves `last_sent`
    /// untouched (so the change still counts as unsent) and pulls the
    /// periodic timer forward to the next refill, which rebuilds the PDU from
    /// live state — so a suppressed change is delayed, never lost.
    fn transmit(&mut self, socket: &LacpSocket, interface: &str, pdu: Lacpdu) {
        if self.limiter.try_take(Instant::now()) {
            send_lacpdu(socket, interface, &pdu);
            self.last_sent = Some(pdu);
        } else {
            debug!(interface = %interface, "lacpdu rate limit hit, deferring");
            self.next_periodic_send = self.limiter.next_refill();
        }
    }

    /// 802.1AX's NTT ("need to transmit"): an event-driven send happens only
    /// if what we'd advertise differs from what we last sent. Replying to
    /// every received LACPDU unconditionally made two peers ping-pong at wire
    /// speed; with this they settle as soon as their states agree, and the
    /// periodic timer alone keeps the partner's `Current_While_Timer` alive.
    fn send_if_changed(&mut self, socket: &LacpSocket, interface: &str, pdu: Lacpdu) {
        if needs_transmit(self.last_sent.as_ref(), &pdu) {
            self.transmit(socket, interface, pdu);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_observation_does_not_notify() {
        use futures::FutureExt;

        let observations = Arc::new(Mutex::new(HashMap::new()));
        let changed = Arc::new(Notify::new());
        let report_once = || {
            report(
                &observations,
                &changed,
                "eth1",
                1,
                ReceiveState::Expired,
                MuxState::Detached,
                None,
                &Churn::new("eth1", Duration::from_secs(60)),
            );
        };

        report_once();
        assert!(
            changed.notified().now_or_never().is_some(),
            "first report notifies"
        );

        report_once();
        assert!(
            changed.notified().now_or_never().is_none(),
            "an identical report must not notify"
        );
    }

    #[test]
    fn limiter_allows_three_per_window() {
        let t0 = Instant::now();
        let mut l = TxLimiter::new(t0);
        assert!((0..3).all(|_| l.try_take(t0)));
        assert!(!l.try_take(t0 + Duration::from_millis(999)));
        assert_eq!(l.next_refill(), t0 + TX_WINDOW);
        assert!(l.try_take(t0 + TX_WINDOW));
    }

    /// Regression: a LACPDU arriving while `Waiting` yields `Action::None`;
    /// disarming the wait timer on it meant the port never left `Waiting`.
    #[test]
    fn a_no_op_event_leaves_a_pending_wait_armed() {
        let (state, action) = mux_machine::step(
            MuxState::Waiting,
            mux_machine::Event::PartnerStateChanged {
                synchronized: false,
                collecting: false,
            },
        );
        assert_eq!(state, MuxState::Waiting);
        let pending = Instant::now() + Duration::from_secs(2);
        let mut deadline = pending;
        apply_mux_action(action, &mut deadline);
        assert_eq!(deadline, pending);
    }

    #[test]
    fn fast_rate_sets_the_advertised_timeout_bit_and_slow_clears_it() {
        let state = |rate| actor_state_byte(ReceiveState::Current, MuxState::Detached, rate);
        assert_ne!(state(LacpRate::Fast) & state_bit::TIMEOUT, 0);
        assert_eq!(state(LacpRate::Slow) & state_bit::TIMEOUT, 0);
    }

    #[test]
    fn identical_advertisement_is_not_retransmitted() {
        let config_pdu = |state: u8| Lacpdu {
            actor: PortInfo {
                system_priority: 1,
                system: [1; 6],
                key: 1,
                port_priority: 1,
                port: 1,
                state,
            },
            partner: PortInfo {
                system_priority: 0,
                system: [0; 6],
                key: 0,
                port_priority: 0,
                port: 0,
                state: 0,
            },
            collector_max_delay: 0,
        };
        let sent = config_pdu(1);
        assert!(needs_transmit(None, &sent), "first send goes out");
        assert!(
            !needs_transmit(Some(&sent), &config_pdu(1)),
            "unchanged: no reply"
        );
        assert!(
            needs_transmit(Some(&sent), &config_pdu(9)),
            "changed state goes out"
        );
    }

    fn elapsed() -> Instant {
        Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("monotonic clock is more than 1s past its origin")
    }

    /// The regression guard for a real hot loop: `run`'s `sleep_until` arms
    /// resolve immediately for a deadline in the past, so if handling an
    /// elapsed timer leaves that deadline elapsed, the loop spins — flooding
    /// the log and the wire (it once grew `nos-logd` to ~14 GB). After
    /// handling a timer-expiry event, its deadline must be in the future.
    #[test]
    fn handling_wait_while_expiry_disarms_the_timer() {
        let (state, action) =
            mux_machine::step(MuxState::Waiting, mux_machine::Event::WaitWhileTimerExpired);
        assert_eq!(state, MuxState::Attached);
        let mut deadline = elapsed();
        apply_mux_action(action, &mut deadline);
        assert!(deadline > Instant::now());
    }

    #[test]
    fn handling_current_while_expiry_never_leaves_an_elapsed_deadline() {
        for state in [
            ReceiveState::Expired,
            ReceiveState::Current,
            ReceiveState::Defaulted,
        ] {
            let (_, action) =
                receive_machine::step(state, receive_machine::Event::CurrentWhileTimerExpired);
            let mut deadline = elapsed();
            apply_receive_action(action, &mut deadline);
            assert!(
                deadline > Instant::now(),
                "{state:?} left an elapsed deadline"
            );
        }
    }

    #[test]
    fn every_mux_transition_other_than_starting_the_wait_disarms_it() {
        for state in [
            MuxState::Detached,
            MuxState::Waiting,
            MuxState::Attached,
            MuxState::Collecting,
            MuxState::Distributing,
        ] {
            for event in [
                mux_machine::Event::WaitWhileTimerExpired,
                mux_machine::Event::SelectionChanged { selected: false },
                mux_machine::Event::PartnerStateChanged {
                    synchronized: true,
                    collecting: true,
                },
                mux_machine::Event::PartnerStateChanged {
                    synchronized: false,
                    collecting: false,
                },
            ] {
                let (_, action) = mux_machine::step(state, event);
                if action == mux_machine::Action::None {
                    continue;
                }
                let mut deadline = elapsed();
                apply_mux_action(action, &mut deadline);
                assert!(
                    deadline > Instant::now(),
                    "{state:?} + {event:?} left an elapsed wait-while deadline"
                );
            }
        }
    }
}

#[cfg(test)]
mod churn_tests {
    use super::*;

    #[test]
    fn expiry_never_leaves_an_elapsed_deadline_and_sync_recovers() {
        let mut c = Churn::new("eth1", Duration::from_millis(1));
        c.eval(MuxState::Detached, None);
        assert_eq!(
            (c.actor, c.partner),
            (ChurnState::Monitor, ChurnState::Monitor)
        );
        c.expire_actor();
        c.expire_partner();
        assert_eq!((c.actor, c.partner), (ChurnState::Churn, ChurnState::Churn));
        assert!(c.actor_deadline > Instant::now() && c.partner_deadline > Instant::now());
        c.eval(MuxState::Attached, None);
        assert_eq!(c.actor, ChurnState::NoChurn);
        assert_eq!(c.partner, ChurnState::Churn, "no partner sync yet");
    }
}
