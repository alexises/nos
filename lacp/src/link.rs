//! One member port's own Receive/Periodic-Transmission/Mux machines and I/O
//! — the LACP counterpart of `ospf::link.rs`'s per-link `run()` shape.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{watch, Notify};
use tracing::{debug, info, warn};

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
    /// This aggregate's `selected_rx.borrow()` reflects Selection Logic's
    /// current verdict for this specific port — updated by `aggregate.rs`
    /// whenever it re-runs `selection::select` (on any port's observation
    /// change).
    pub selected_rx: watch::Receiver<bool>,
}

/// One member port's currently-observed state, as reported up to
/// `aggregate.rs` after every event that could change it — the input to
/// both `selection::select` (needs `current`/partner identity) and the
/// active-member-set computation (needs `mux_state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortObservation {
    pub current: bool,
    pub partner_system_id: [u8; 6],
    pub partner_key: u16,
    pub mux_state: MuxState,
}

impl Default for PortObservation {
    fn default() -> Self {
        Self {
            current: false,
            partner_system_id: [0; 6],
            partner_key: 0,
            mux_state: MuxState::Detached,
        }
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
    let socket = match LacpSocket::open(&config.interface) {
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
    let mut next_periodic_send = Instant::now();
    let mut last_sent: Option<Lacpdu> = None;

    report(
        &observations,
        &changed,
        &config.interface,
        receive_state,
        mux_state,
        partner,
    );

    loop {
        tokio::select! {
            () = tokio::time::sleep_until(next_periodic_send.into()) => {
                let pdu = build_pdu(&config, port_number, receive_state, mux_state, partner);
                send_lacpdu(&socket, &config.interface, &pdu);
                last_sent = Some(pdu);
                // Must move the deadline forward every time it fires, or the
                // elapsed deadline re-fires immediately: a hot loop.
                next_periodic_send = Instant::now() + interval_for(receive_state);
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
                report(&observations, &changed, &config.interface, receive_state, mux_state, partner);
                send_if_changed(&socket, &config.interface, &mut last_sent, build_pdu(&config, port_number, receive_state, mux_state, partner));
            }
            () = tokio::time::sleep_until(wait_while_deadline.into()) => {
                let (ms, action) = mux_machine::step(mux_state, mux_machine::Event::WaitWhileTimerExpired);
                mux_state = ms;
                apply_mux_action(action, &mut wait_while_deadline);
                info!(interface = %config.interface, mux_state = ?mux_state, "lacp mux machine transitioned");
                report(&observations, &changed, &config.interface, receive_state, mux_state, partner);
                send_if_changed(&socket, &config.interface, &mut last_sent, build_pdu(&config, port_number, receive_state, mux_state, partner));
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
                report(&observations, &changed, &config.interface, receive_state, mux_state, partner);
                send_if_changed(&socket, &config.interface, &mut last_sent, build_pdu(&config, port_number, receive_state, mux_state, partner));
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
                        partner_wants_short_timeout: pdu.actor.has_state(state_bit::TIMEOUT),
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
                report(&observations, &changed, &config.interface, receive_state, mux_state, partner);
                send_if_changed(&socket, &config.interface, &mut last_sent, build_pdu(&config, port_number, receive_state, mux_state, partner));
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

#[allow(clippy::implicit_hasher)] // always the default hasher; never needs to be generic here
fn report(
    observations: &Arc<Mutex<HashMap<String, PortObservation>>>,
    changed: &Arc<Notify>,
    interface: &str,
    receive_state: ReceiveState,
    mux_state: MuxState,
    partner: Option<PortInfo>,
) {
    let observation = PortObservation {
        current: receive_state == ReceiveState::Current,
        partner_system_id: partner.map(|p| p.system).unwrap_or_default(),
        partner_key: partner.map(|p| p.key).unwrap_or_default(),
        mux_state,
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

/// This port's own advertised `Actor_State` byte — see 802.1AX Table 6-4.
/// `Activity`/`Aggregation` are always set (v1 has no Passive mode, no
/// `Individual` aggregation — see `lacp/CLAUDE.md`'s deferred list);
/// `Timeout` always advertises Long (v1 always transmits Slow, see
/// `periodic_tx_machine`); the rest reflect the live state machines.
fn actor_state_byte(receive_state: ReceiveState, mux_state: MuxState) -> u8 {
    let mut state = state_bit::ACTIVITY | state_bit::AGGREGATION;
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
        state: actor_state_byte(receive_state, mux_state),
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

/// 802.1AX's NTT ("need to transmit"): an event-driven send happens only if
/// what we'd advertise differs from what we last sent. Replying to every
/// received LACPDU unconditionally made two peers ping-pong at wire speed;
/// with this they settle as soon as their states agree, and the periodic
/// timer alone keeps the partner's `Current_While_Timer` alive.
fn needs_transmit(last_sent: &mut Option<Lacpdu>, pdu: &Lacpdu) -> bool {
    if last_sent.as_ref() == Some(pdu) {
        return false;
    }
    *last_sent = Some(*pdu);
    true
}

fn send_if_changed(
    socket: &LacpSocket,
    interface: &str,
    last_sent: &mut Option<Lacpdu>,
    pdu: Lacpdu,
) {
    if needs_transmit(last_sent, &pdu) {
        send_lacpdu(socket, interface, &pdu);
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
                ReceiveState::Expired,
                MuxState::Detached,
                None,
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
        let mut last = None;
        assert!(
            needs_transmit(&mut last, &config_pdu(1)),
            "first send goes out"
        );
        assert!(
            !needs_transmit(&mut last, &config_pdu(1)),
            "unchanged: no reply"
        );
        assert!(
            needs_transmit(&mut last, &config_pdu(9)),
            "changed state goes out"
        );
        assert!(!needs_transmit(&mut last, &config_pdu(9)));
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
