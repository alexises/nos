//! RFC 4271 BGP finite state machine, restricted to the states that need
//! message exchange: `OpenSent`, `OpenConfirm`, `Established`. Idle/Connect/
//! Active remain `session.rs`'s existing retry-loop behavior (no task yet,
//! or a connect attempt in flight/backing off) — `fsm::run` is spawned only
//! once a `TcpStream` already exists, on both the active-connect success
//! path and the passive-accept path, replacing what used to be
//! `session::hold_until_closed`.
//!
//! `step` is the pure transition core (state + event -> next state +
//! actions), kept separate from the async orchestrator (`run`) so it can be
//! unit-tested directly without any I/O.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::time::Instant;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info};

use nos_proto::HOLD_TIME_FLOOR;

use crate::collision::{self, PeerSlot};
use crate::message::{
    self, BgpCodec, BgpMessage, CeaseSubcode, ErrorCode, MessageHeaderSubcode, NotificationMessage,
    OpenMessage, OpenMessageSubcode, UpdateMessageSubcode, WireError,
};
use crate::rib::{BgpRib, OutboundUpdate};
use crate::session::LocalIdentity;
use crate::status::{PeerState, PeerStatus};

/// RFC 4271's own suggested `ConnectRetryTimer` default. Replaces
/// `session.rs`'s previous placeholder (30s), which was explicitly
/// documented as standing in "until the BGP FSM exists." Used by
/// `reconcile::resync` as the fallback when a peer-group leaves
/// `connect_retry_time` unset.
pub const CONNECT_RETRY_TIME: Duration = Duration::from_secs(120);

/// The peer identity this connection is being validated against —
/// `expected_remote_as` is compared against the real ASN extracted from the
/// peer's OPEN (see `message::effective_remote_asn`). `local_hold_time`/
/// `keepalive_override` come from the peer's `BgpPeerGroup` (already
/// defaulted by `reconcile::resync` — see `nos_proto::HOLD_TIME_DEFAULT`).
pub struct PeerContext {
    pub remote_address: IpAddr,
    pub expected_remote_as: u32,
    pub local_hold_time: u16,
    pub keepalive_override: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RemoteInfo {
    asn: u32,
    bgp_id: Ipv4Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    OpenSent,
    OpenConfirm(RemoteInfo),
    Established(RemoteInfo),
}

#[derive(Debug)]
enum Event {
    OpenReceived(OpenMessage),
    KeepaliveReceived,
    NotificationReceived(NotificationMessage),
    MalformedMessage(WireError),
    HoldTimerExpires,
    KeepaliveTimerExpires,
    TcpFailed,
    CollisionLost,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    SendKeepalive,
    SendNotification(u8, u8),
    /// `Duration::ZERO` disarms the timer entirely (RFC 4271 allows a
    /// negotiated hold time of 0, meaning no keepalives and no expiry).
    ArmHoldTimer(Duration),
    ArmKeepaliveTimer(Duration),
    ReportEstablished {
        remote_asn: u32,
        remote_bgp_id: Ipv4Addr,
    },
    Close,
}

struct NegotiationContext {
    expected_remote_as: u32,
    local_hold_time: u16,
    keepalive_override: Option<u16>,
}

/// Pure state transition core — the unit-test surface for this module.
fn step(state: State, event: Event, ctx: &NegotiationContext) -> (Option<State>, Vec<Action>) {
    match (state, event) {
        (State::OpenSent, Event::OpenReceived(open)) => handle_open(&open, ctx),
        (State::OpenConfirm(remote), Event::KeepaliveReceived) => (
            Some(State::Established(remote)),
            vec![Action::ReportEstablished {
                remote_asn: remote.asn,
                remote_bgp_id: remote.bgp_id,
            }],
        ),
        (State::Established(remote), Event::KeepaliveReceived) => {
            (Some(State::Established(remote)), vec![])
        }
        (_, Event::HoldTimerExpires) => (
            None,
            vec![
                Action::SendNotification(ErrorCode::HoldTimerExpired as u8, 0),
                Action::Close,
            ],
        ),
        (_, Event::NotificationReceived(_) | Event::TcpFailed) => (None, vec![Action::Close]),
        (_, Event::CollisionLost) => (
            None,
            vec![
                Action::SendNotification(
                    ErrorCode::Cease as u8,
                    CeaseSubcode::ConnectionCollisionResolution as u8,
                ),
                Action::Close,
            ],
        ),
        (State::Established(remote), Event::KeepaliveTimerExpires) => (
            Some(State::Established(remote)),
            vec![Action::SendKeepalive],
        ),
        (_, Event::MalformedMessage(e)) => {
            let (code, subcode) = notification_for_wire_error(&e);
            (
                None,
                vec![Action::SendNotification(code, subcode), Action::Close],
            )
        }
        // Anything else (an OPEN arriving twice, a KeepaliveTimerExpires
        // while not yet Established, ...) is a protocol sequencing error.
        (_, _) => (
            None,
            vec![
                Action::SendNotification(ErrorCode::FiniteStateMachine as u8, 0),
                Action::Close,
            ],
        ),
    }
}

fn handle_open(open: &OpenMessage, ctx: &NegotiationContext) -> (Option<State>, Vec<Action>) {
    if open.version != message::BGP_VERSION {
        return reject(OpenMessageSubcode::UnsupportedVersionNumber);
    }
    if open.my_as == message::AS_TRANS && open.four_octet_asn.is_none() {
        // AS_TRANS with no capability backing it is meaningless per RFC 6793.
        return reject(OpenMessageSubcode::BadPeerAs);
    }
    let remote_asn = message::effective_remote_asn(open);
    if remote_asn != ctx.expected_remote_as {
        return reject(OpenMessageSubcode::BadPeerAs);
    }
    if !message::is_valid_bgp_identifier(open.bgp_identifier) {
        return reject(OpenMessageSubcode::BadBgpIdentifier);
    }
    if open.hold_time != 0 && open.hold_time < HOLD_TIME_FLOOR {
        return reject(OpenMessageSubcode::UnacceptableHoldTime);
    }

    let negotiated_hold = ctx.local_hold_time.min(open.hold_time);
    // `keepalive_override` is only validated at commit time against the
    // locally-configured hold-time, not the negotiated one (negotiation
    // takes `min()` with a peer-proposed value the validator never sees) —
    // fall back to the RFC-suggested ratio whenever the override wouldn't
    // fit under what was actually negotiated. A negotiated hold time of 0
    // unconditionally disables keepalives, regardless of any override.
    let keepalive = if negotiated_hold == 0 {
        0
    } else {
        match ctx.keepalive_override {
            Some(k) if k < negotiated_hold => k,
            _ => negotiated_hold / 3,
        }
    };
    let remote = RemoteInfo {
        asn: remote_asn,
        bgp_id: open.bgp_identifier,
    };
    (
        Some(State::OpenConfirm(remote)),
        vec![
            Action::SendKeepalive,
            Action::ArmHoldTimer(Duration::from_secs(u64::from(negotiated_hold))),
            Action::ArmKeepaliveTimer(Duration::from_secs(u64::from(keepalive))),
        ],
    )
}

fn reject(subcode: OpenMessageSubcode) -> (Option<State>, Vec<Action>) {
    (
        None,
        vec![
            Action::SendNotification(ErrorCode::OpenMessage as u8, subcode as u8),
            Action::Close,
        ],
    )
}

/// Maps a decode failure to the `(error_code, error_subcode)` pair its
/// NOTIFICATION should carry. Every case but `MalformedUpdate` is a Message
/// Header error (RFC 4271 §6.1); `MalformedUpdate` is the one case that
/// belongs to the UPDATE Message Error table (§6.3) instead.
fn notification_for_wire_error(e: &WireError) -> (u8, u8) {
    match e {
        WireError::BadMarker => (
            ErrorCode::MessageHeader as u8,
            MessageHeaderSubcode::ConnectionNotSynchronized as u8,
        ),
        WireError::BadLength(_)
        | WireError::Truncated
        | WireError::MalformedOpen
        | WireError::MalformedNotification
        | WireError::Io(_) => (
            ErrorCode::MessageHeader as u8,
            MessageHeaderSubcode::BadMessageLength as u8,
        ),
        WireError::MalformedUpdate => (
            ErrorCode::UpdateMessage as u8,
            UpdateMessageSubcode::MalformedAttributeList as u8,
        ),
    }
}

/// How one FSM session ended, for `session.rs` to log.
#[derive(Debug)]
pub enum FsmOutcome {
    TcpError,
    PeerClosed,
    NotificationSent { code: u8, subcode: u8 },
    NotificationReceived { code: u8, subcode: u8 },
    HoldTimerExpired,
    CollisionLost,
}

/// Drives one session's `OpenSent` -> `OpenConfirm` -> `Established` FSM
/// over an already-connected `stream`. The caller is responsible for
/// `PeerSlot::begin`/`clear` around this call — `run` only touches
/// `on_open`/`mark_established`, the transitions intrinsic to FSM progress.
///
/// `bgp_rib` is registered with a fresh outbound channel once the session
/// reaches `Established` (`Action::ReportEstablished`), fed real
/// `BgpMessage::Update`s back onto the wire from a dedicated `select!` arm,
/// and unconditionally deregistered (`peer_disconnected`) at this function's
/// single exit point — whatever the reason this session ended.
pub async fn run(
    stream: TcpStream,
    role: collision::Role,
    local: LocalIdentity,
    peer: PeerContext,
    slot: Arc<PeerSlot>,
    bgp_rib: Arc<Mutex<BgpRib>>,
) -> FsmOutcome {
    // Captured before `into_split()` consumes `stream`: this session's own
    // local address, used for next-hop-self advertisements toward this
    // peer. `None` if this connection turned out to be over IPv6 (UPDATE
    // support is IPv4-unicast-only) — such a peer is never eligible for any
    // advertisement (see `crate::rib::build_advertisement`).
    let local_addr_v4 = stream.local_addr().ok().and_then(|addr| match addr.ip() {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    });
    let remote_is_ibgp = local.asn == peer.expected_remote_as;
    let (outbox_tx, mut outbox_rx) = mpsc::unbounded_channel::<OutboundUpdate>();

    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, BgpCodec);
    let mut writer = FramedWrite::new(write_half, BgpCodec);

    let ctx = NegotiationContext {
        expected_remote_as: peer.expected_remote_as,
        local_hold_time: peer.local_hold_time,
        keepalive_override: peer.keepalive_override,
    };

    let mut state = State::OpenSent;
    // Doubles, before negotiation, as the OpenSent-wait timer. A configured
    // `local_hold_time` of 0 disarms it entirely, same as a negotiated hold
    // time of 0 does later via `Action::ArmHoldTimer`.
    let mut hold_period = if peer.local_hold_time == 0 {
        None
    } else {
        Some(Duration::from_secs(u64::from(peer.local_hold_time)))
    };
    let mut hold_deadline = hold_period.map(|p| Instant::now() + p);
    let mut keepalive_period: Option<Duration> = None;
    let mut keepalive_deadline: Option<Instant> = None;
    let mut negotiated_hold_time: Option<u16> = None;
    let mut negotiated_keepalive: Option<u16> = None;
    let cease = Arc::new(Notify::new());

    // Guarded on `is_established` rather than written unconditionally: an
    // inbound connection can arrive for a peer that's already `Established`
    // via the other role (e.g. a flappy/misbehaving peer opening a second
    // TCP session) — such a connection is always going to lose the
    // collision at its first `on_open` below, and must never be allowed to
    // transiently overwrite the genuinely-established session's reported
    // status in the meantime.
    if !slot.is_established().await {
        slot.status.send_modify(|s| {
            *s = PeerStatus {
                state: PeerState::OpenSent,
                ..PeerStatus::default()
            }
        });
    }

    // Single exit point: every early-return case below (`break 'session
    // ...`) funnels through the same `bgp_rib.peer_disconnected` call after
    // this block, rather than returning directly — a session that never
    // reached `Established` makes that call a safe no-op.
    let outcome = 'session: {
        let open = message::build_open(local.asn, local.router_id, peer.local_hold_time);
        if writer.send(BgpMessage::Open(open)).await.is_err() {
            break 'session FsmOutcome::TcpError;
        }

        loop {
            let event = tokio::select! {
                msg = reader.next() => match msg {
                    Some(Ok(bgp_msg)) => {
                        // Any well-formed inbound message proves liveness —
                        // reset the hold timer regardless of type (RFC 4271 §4.4).
                        if let Some(period) = hold_period {
                            hold_deadline = Some(Instant::now() + period);
                        }
                        match bgp_msg {
                            BgpMessage::Open(open) => Event::OpenReceived(open),
                            BgpMessage::Keepalive => Event::KeepaliveReceived,
                            BgpMessage::Notification(n) => Event::NotificationReceived(n),
                            BgpMessage::Update(update) => {
                                // Route exchange bypasses `step` entirely —
                                // it isn't part of the OpenSent/OpenConfirm/
                                // Established transition table.
                                if matches!(state, State::Established(_)) {
                                    bgp_rib.lock().await.handle_update(
                                        peer.remote_address,
                                        remote_is_ibgp,
                                        update,
                                    );
                                } else {
                                    debug!(
                                        peer = %peer.remote_address,
                                        "ignoring bgp update received before session established"
                                    );
                                }
                                continue;
                            }
                            BgpMessage::Unhandled { message_type, .. } => {
                                debug!(
                                    peer = %peer.remote_address, message_type,
                                    "ignoring unrecognized bgp message type"
                                );
                                continue;
                            }
                        }
                    }
                    Some(Err(WireError::Io(_))) => break 'session FsmOutcome::TcpError,
                    Some(Err(e)) => Event::MalformedMessage(e),
                    None => Event::TcpFailed,
                },
                () = sleep_until_opt(hold_deadline) => Event::HoldTimerExpires,
                () = sleep_until_opt(keepalive_deadline) => {
                    if let Some(period) = keepalive_period {
                        keepalive_deadline = Some(Instant::now() + period);
                    }
                    Event::KeepaliveTimerExpires
                }
                () = cease.notified() => Event::CollisionLost,
                Some(update) = outbox_rx.recv() => {
                    let _ = writer.send(outbound_update_to_message(update)).await;
                    continue;
                }
            };

            let is_open_event = matches!(event, Event::OpenReceived(_));
            let notification_received = match &event {
                Event::NotificationReceived(n) => Some((n.error_code, n.error_subcode)),
                _ => None,
            };
            let (mut next_state, mut actions) = step(state, event, &ctx);

            if is_open_event {
                if let Some(State::OpenConfirm(remote)) = next_state {
                    let decision = slot
                        .on_open(role, local.router_id, remote.bgp_id, cease.clone())
                        .await;
                    match decision {
                        collision::Decision::Lose => {
                            next_state = None;
                            actions = vec![
                                Action::SendNotification(
                                    ErrorCode::Cease as u8,
                                    CeaseSubcode::ConnectionCollisionResolution as u8,
                                ),
                                Action::Close,
                            ];
                        }
                        // `on_open` only returns `Proceed` when no other
                        // connection for this peer is already `Established` (see
                        // `collision::PeerSlot::on_open`), so this is safe to
                        // write without an extra `is_established` race check.
                        collision::Decision::Proceed => {
                            slot.status.send_modify(|s| {
                                s.state = PeerState::OpenConfirm;
                                s.remote_asn = Some(remote.asn);
                                s.remote_bgp_id = Some(remote.bgp_id);
                            });
                        }
                    }
                }
            }

            let mut notification_sent = None;
            for action in &actions {
                match action {
                    Action::SendKeepalive => {
                        let _ = writer.send(BgpMessage::Keepalive).await;
                    }
                    Action::SendNotification(code, subcode) => {
                        let _ = writer
                            .send(BgpMessage::Notification(NotificationMessage {
                                error_code: *code,
                                error_subcode: *subcode,
                                data: Bytes::new(),
                            }))
                            .await;
                        notification_sent = Some((*code, *subcode));
                    }
                    Action::ArmHoldTimer(d) => {
                        hold_period = if d.is_zero() { None } else { Some(*d) };
                        hold_deadline = hold_period.map(|p| Instant::now() + p);
                        // Always derived from a u16 (either the local config or
                        // the peer's OPEN), so this never actually truncates.
                        negotiated_hold_time = Some(u16::try_from(d.as_secs()).unwrap_or(u16::MAX));
                    }
                    Action::ArmKeepaliveTimer(d) => {
                        keepalive_period = if d.is_zero() { None } else { Some(*d) };
                        keepalive_deadline = keepalive_period.map(|p| Instant::now() + p);
                        negotiated_keepalive = Some(u16::try_from(d.as_secs()).unwrap_or(u16::MAX));
                    }
                    Action::ReportEstablished {
                        remote_asn,
                        remote_bgp_id,
                    } => {
                        slot.mark_established(role).await;
                        bgp_rib.lock().await.peer_established(
                            peer.remote_address,
                            remote_is_ibgp,
                            local_addr_v4,
                            outbox_tx.clone(),
                        );
                        slot.status.send_modify(|s| {
                            s.state = PeerState::Established;
                            s.remote_asn = Some(*remote_asn);
                            s.remote_bgp_id = Some(*remote_bgp_id);
                            s.established_since = Some(Instant::now());
                            s.negotiated_hold_time = negotiated_hold_time;
                            s.negotiated_keepalive = negotiated_keepalive;
                        });
                        info!(
                            peer = %peer.remote_address, remote_asn, remote_bgp_id = %remote_bgp_id,
                            role = ?role, "bgp session established"
                        );
                    }
                    Action::Close => {}
                }
            }

            if let Some(s) = next_state {
                state = s;
            } else if let Some((code, subcode)) = notification_received {
                break 'session FsmOutcome::NotificationReceived { code, subcode };
            } else if let Some(outcome) = event_outcome(&actions) {
                break 'session outcome;
            } else if let Some((code, subcode)) = notification_sent {
                break 'session FsmOutcome::NotificationSent { code, subcode };
            } else {
                break 'session FsmOutcome::PeerClosed;
            }
        }
    };

    bgp_rib.lock().await.peer_disconnected(peer.remote_address);
    outcome
}

/// Converts one outbound RIB decision into the real `BgpMessage::Update` to
/// send on the wire — the encode side of `crate::rib::BgpRib`'s per-peer
/// propagation decisions.
fn outbound_update_to_message(update: OutboundUpdate) -> BgpMessage {
    match update {
        OutboundUpdate::Announce(route) => BgpMessage::Update(message::UpdateMessage {
            withdrawn_routes: Vec::new(),
            nlri: vec![route.prefix],
            attributes: Some(message::PathAttributes {
                origin: route.origin,
                as_path: route.as_path,
                next_hop: route.next_hop,
                local_pref: route.local_pref,
            }),
        }),
        OutboundUpdate::Withdraw(prefix) => BgpMessage::Update(message::UpdateMessage {
            withdrawn_routes: vec![prefix],
            nlri: Vec::new(),
            attributes: None,
        }),
    }
}

/// Reads the specific closing cause back out of the actions `step` produced,
/// for outcomes that need to be distinguished from a generic "we sent a
/// notification" (hold-timer expiry, collision loss, or the peer's own
/// NOTIFICATION) — everything else falls through to the caller's generic
/// classification.
fn event_outcome(actions: &[Action]) -> Option<FsmOutcome> {
    for action in actions {
        if let Action::SendNotification(code, subcode) = action {
            if *code == ErrorCode::HoldTimerExpired as u8 {
                return Some(FsmOutcome::HoldTimerExpired);
            }
            if *code == ErrorCode::Cease as u8
                && *subcode == CeaseSubcode::ConnectionCollisionResolution as u8
            {
                return Some(FsmOutcome::CollisionLost);
            }
        }
    }
    None
}

async fn sleep_until_opt(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(expected_remote_as: u32) -> NegotiationContext {
        NegotiationContext {
            expected_remote_as,
            local_hold_time: 90,
            keepalive_override: None,
        }
    }

    fn ctx_with(
        expected_remote_as: u32,
        local_hold_time: u16,
        keepalive_override: Option<u16>,
    ) -> NegotiationContext {
        NegotiationContext {
            expected_remote_as,
            local_hold_time,
            keepalive_override,
        }
    }

    fn valid_open(remote_as: u32, hold_time: u16) -> OpenMessage {
        message::build_open(remote_as, Ipv4Addr::new(2, 2, 2, 2), hold_time)
    }

    #[test]
    fn valid_open_moves_to_open_confirm_and_arms_timers() {
        let (next, actions) = step(
            State::OpenSent,
            Event::OpenReceived(valid_open(65002, 90)),
            &ctx(65002),
        );
        assert!(matches!(next, Some(State::OpenConfirm(_))));
        assert!(actions.contains(&Action::SendKeepalive));
        assert!(actions.contains(&Action::ArmHoldTimer(Duration::from_secs(90))));
        assert!(actions.contains(&Action::ArmKeepaliveTimer(Duration::from_secs(30))));
    }

    #[test]
    fn bad_version_is_rejected() {
        let mut open = valid_open(65002, 90);
        open.version = 3;
        let (next, actions) = step(State::OpenSent, Event::OpenReceived(open), &ctx(65002));
        assert_eq!(next, None);
        assert!(actions.contains(&Action::SendNotification(
            ErrorCode::OpenMessage as u8,
            OpenMessageSubcode::UnsupportedVersionNumber as u8
        )));
    }

    #[test]
    fn asn_mismatch_is_rejected() {
        let (next, actions) = step(
            State::OpenSent,
            Event::OpenReceived(valid_open(65099, 90)),
            &ctx(65002),
        );
        assert_eq!(next, None);
        assert!(actions.contains(&Action::SendNotification(
            ErrorCode::OpenMessage as u8,
            OpenMessageSubcode::BadPeerAs as u8
        )));
    }

    #[test]
    fn bad_bgp_identifier_is_rejected() {
        let mut open = valid_open(65002, 90);
        open.bgp_identifier = Ipv4Addr::UNSPECIFIED;
        let (next, actions) = step(State::OpenSent, Event::OpenReceived(open), &ctx(65002));
        assert_eq!(next, None);
        assert!(actions.contains(&Action::SendNotification(
            ErrorCode::OpenMessage as u8,
            OpenMessageSubcode::BadBgpIdentifier as u8
        )));
    }

    #[test]
    fn hold_time_of_one_or_two_is_rejected() {
        for bad in [1u16, 2u16] {
            let (next, actions) = step(
                State::OpenSent,
                Event::OpenReceived(valid_open(65002, bad)),
                &ctx(65002),
            );
            assert_eq!(next, None);
            assert!(actions.contains(&Action::SendNotification(
                ErrorCode::OpenMessage as u8,
                OpenMessageSubcode::UnacceptableHoldTime as u8
            )));
        }
    }

    #[test]
    fn hold_time_zero_disables_both_timers() {
        let (next, actions) = step(
            State::OpenSent,
            Event::OpenReceived(valid_open(65002, 0)),
            &ctx(65002),
        );
        assert!(matches!(next, Some(State::OpenConfirm(_))));
        assert!(actions.contains(&Action::ArmHoldTimer(Duration::ZERO)));
        assert!(actions.contains(&Action::ArmKeepaliveTimer(Duration::ZERO)));
    }

    #[test]
    fn as_trans_without_capability_is_bad_peer_as() {
        let mut open = valid_open(65002, 90);
        open.my_as = message::AS_TRANS;
        open.four_octet_asn = None;
        let (next, actions) = step(State::OpenSent, Event::OpenReceived(open), &ctx(65002));
        assert_eq!(next, None);
        assert!(actions.contains(&Action::SendNotification(
            ErrorCode::OpenMessage as u8,
            OpenMessageSubcode::BadPeerAs as u8
        )));
    }

    #[test]
    fn keepalive_in_open_confirm_reaches_established() {
        let remote = RemoteInfo {
            asn: 65002,
            bgp_id: Ipv4Addr::new(2, 2, 2, 2),
        };
        let (next, actions) = step(
            State::OpenConfirm(remote),
            Event::KeepaliveReceived,
            &ctx(65002),
        );
        assert_eq!(next, Some(State::Established(remote)));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::ReportEstablished { .. })));
    }

    #[test]
    fn hold_timer_expiry_closes_at_every_state() {
        let remote = RemoteInfo {
            asn: 65002,
            bgp_id: Ipv4Addr::new(2, 2, 2, 2),
        };
        for state in [
            State::OpenSent,
            State::OpenConfirm(remote),
            State::Established(remote),
        ] {
            let (next, actions) = step(state, Event::HoldTimerExpires, &ctx(65002));
            assert_eq!(next, None);
            assert!(actions.contains(&Action::SendNotification(
                ErrorCode::HoldTimerExpired as u8,
                0
            )));
        }
    }

    #[test]
    fn notification_received_never_replies() {
        let (next, actions) = step(
            State::OpenSent,
            Event::NotificationReceived(NotificationMessage {
                error_code: 1,
                error_subcode: 1,
                data: Bytes::new(),
            }),
            &ctx(65002),
        );
        assert_eq!(next, None);
        assert_eq!(actions, vec![Action::Close]);
    }

    #[test]
    fn collision_lost_sends_cease() {
        let (next, actions) = step(State::OpenSent, Event::CollisionLost, &ctx(65002));
        assert_eq!(next, None);
        assert!(actions.contains(&Action::SendNotification(
            ErrorCode::Cease as u8,
            CeaseSubcode::ConnectionCollisionResolution as u8
        )));
    }

    #[test]
    fn established_keepalive_tick_stays_established_and_sends_keepalive() {
        let remote = RemoteInfo {
            asn: 65002,
            bgp_id: Ipv4Addr::new(2, 2, 2, 2),
        };
        let (next, actions) = step(
            State::Established(remote),
            Event::KeepaliveTimerExpires,
            &ctx(65002),
        );
        assert_eq!(next, Some(State::Established(remote)));
        assert_eq!(actions, vec![Action::SendKeepalive]);
    }

    #[test]
    fn established_keepalive_received_resets_nothing_but_stays_up() {
        let remote = RemoteInfo {
            asn: 65002,
            bgp_id: Ipv4Addr::new(2, 2, 2, 2),
        };
        let (next, actions) = step(
            State::Established(remote),
            Event::KeepaliveReceived,
            &ctx(65002),
        );
        assert_eq!(next, Some(State::Established(remote)));
        assert!(actions.is_empty());
    }

    #[test]
    fn non_default_local_hold_time_is_used_in_negotiation() {
        // Peer proposes 90s but we only proposed 30s locally — negotiated
        // hold must be the lower of the two.
        let (_, actions) = step(
            State::OpenSent,
            Event::OpenReceived(valid_open(65002, 90)),
            &ctx_with(65002, 30, None),
        );
        assert!(actions.contains(&Action::ArmHoldTimer(Duration::from_secs(30))));
        assert!(actions.contains(&Action::ArmKeepaliveTimer(Duration::from_secs(10))));
    }

    #[test]
    fn handle_open_respects_keepalive_override() {
        let (_, actions) = step(
            State::OpenSent,
            Event::OpenReceived(valid_open(65002, 90)),
            &ctx_with(65002, 90, Some(5)),
        );
        assert!(actions.contains(&Action::ArmKeepaliveTimer(Duration::from_secs(5))));
    }

    #[test]
    fn handle_open_falls_back_to_third_when_override_exceeds_negotiated_hold() {
        // Override 10 is valid against the locally-configured hold-time of
        // 90, but the peer only proposes 6s — negotiated_hold ends up
        // smaller than the override, which commit-time validation can't see
        // in advance, so the runtime must fall back to negotiated_hold / 3.
        let (_, actions) = step(
            State::OpenSent,
            Event::OpenReceived(valid_open(65002, 6)),
            &ctx_with(65002, 90, Some(10)),
        );
        // negotiated_hold = min(90, 6) = 6; override (10) >= 6, so falls
        // back to negotiated_hold / 3 = 2.
        assert!(actions.contains(&Action::ArmHoldTimer(Duration::from_secs(6))));
        assert!(actions.contains(&Action::ArmKeepaliveTimer(Duration::from_secs(2))));
    }

    #[test]
    fn handle_open_negotiated_hold_zero_forces_keepalive_zero_even_with_override() {
        let (_, actions) = step(
            State::OpenSent,
            Event::OpenReceived(valid_open(65002, 0)),
            &ctx_with(65002, 0, Some(5)),
        );
        assert!(actions.contains(&Action::ArmHoldTimer(Duration::ZERO)));
        assert!(actions.contains(&Action::ArmKeepaliveTimer(Duration::ZERO)));
    }
}
