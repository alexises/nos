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

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::time::Instant;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, warn};

use nos_proto::{AddressFamily, NextHopMode, HOLD_TIME_FLOOR};

use crate::collision::{self, FsmCommand, PeerSlot};
use crate::message::{
    self, BgpCodec, BgpMessage, CeaseSubcode, ErrorCode, FsmSubcode, MessageHeaderSubcode,
    NotificationMessage, OpenMessage, OpenMessageSubcode, RouteRefreshMessage,
    UpdateMessageSubcode, WireError,
};
use crate::rib::{BgpRib, OutboundUpdate};
use crate::session::{LocalIdentity, PeerKind};
use crate::status::{PeerState, PeerStatus};

/// RFC 4760/8950 AFI values this crate understands.
const AFI_IPV4: u16 = 1;
const AFI_IPV6: u16 = 2;

fn afi_of(family: AddressFamily) -> u16 {
    match family {
        AddressFamily::Ipv4Unicast => AFI_IPV4,
        AddressFamily::Ipv6Unicast => AFI_IPV6,
        AddressFamily::L2vpnEvpn => message::AFI_L2VPN,
    }
}

/// The wire SAFI of `family`.
fn safi_of(family: AddressFamily) -> u8 {
    match family {
        AddressFamily::Ipv4Unicast | AddressFamily::Ipv6Unicast => 1,
        AddressFamily::L2vpnEvpn => message::SAFI_EVPN,
    }
}

fn afi_of_addr(addr: IpAddr) -> u16 {
    match addr {
        IpAddr::V4(_) => AFI_IPV4,
        IpAddr::V6(_) => AFI_IPV6,
    }
}

/// The `AddressFamily` a `ROUTE_REFRESH`'s wire AFI names, if it's one this
/// crate understands.
fn family_of_afi(afi: u16) -> Option<AddressFamily> {
    match afi {
        AFI_IPV4 => Some(AddressFamily::Ipv4Unicast),
        AFI_IPV6 => Some(AddressFamily::Ipv6Unicast),
        _ => None,
    }
}

/// Builds the `MultiProtocol`/`ExtendedNextHop` capabilities this session's
/// own OPEN should advertise, from its peer-group's configured
/// `address_families` and this session's own transport AFI. RFC 8950: an AF
/// that doesn't match the transport family needs the Extended Next Hop
/// capability too, since its next-hop will be this session's own
/// (cross-family) local address; a same-family AF never needs it.
fn build_mp_capabilities(
    address_families: &[AddressFamily],
    transport_afi: u16,
) -> Vec<message::Capability> {
    let mut caps = Vec::new();
    for &af in address_families {
        let afi = afi_of(af);
        caps.push(message::Capability::MultiProtocol {
            afi,
            safi: safi_of(af),
        });
        // RFC 8950 is about unicast NLRI carried with a cross-family
        // next-hop; EVPN's next-hop family is independent of its NLRI.
        if af != AddressFamily::L2vpnEvpn && afi != transport_afi {
            caps.push(message::Capability::ExtendedNextHop {
                nlri_afi: afi,
                nlri_safi: 1,
                nh_afi: transport_afi,
            });
        }
    }
    caps
}

/// Negotiates which address families this session actually carries, from the
/// peer's OPEN capabilities and this session's own configured
/// `address_families`/transport AFI. Returns `(mp_bgp_negotiated,
/// negotiated_ipv4_unicast, negotiated_ipv6_unicast, negotiated_evpn)` — bools rather
/// than a generic set, since exactly two `AddressFamily` variants exist
/// today and this keeps `RemoteInfo`/`Action` cheaply `Copy`.
///
/// If the peer never sent any Multiprotocol Extensions capability at all
/// (`mp_bgp_negotiated == false`), only plain IPv4 unicast is possible, and
/// only when this session's own transport is IPv4 too — the legacy wire
/// format has no way to carry anything else. Otherwise, an AF is negotiated
/// only if both sides advertised it, and — when its family doesn't match the
/// transport family — only if the peer also advertised the matching
/// Extended Next Hop tuple.
fn negotiate_address_families(
    open: &OpenMessage,
    ctx: &NegotiationContext,
) -> (bool, bool, bool, bool) {
    let peer_mp: HashSet<(u16, u8)> = open
        .capabilities
        .iter()
        .filter_map(|c| match c {
            message::Capability::MultiProtocol { afi, safi } => Some((*afi, *safi)),
            _ => None,
        })
        .collect();
    let peer_ext_nh: HashSet<(u16, u16, u16)> = open
        .capabilities
        .iter()
        .filter_map(|c| match c {
            message::Capability::ExtendedNextHop {
                nlri_afi,
                nlri_safi,
                nh_afi,
            } => Some((*nlri_afi, *nlri_safi, *nh_afi)),
            _ => None,
        })
        .collect();
    let mp_bgp_negotiated = !peer_mp.is_empty();

    let configured = |afi: u16| ctx.address_families.iter().any(|af| afi_of(*af) == afi);
    let negotiated = |afi: u16| -> bool {
        if !configured(afi) {
            return false;
        }
        if !mp_bgp_negotiated {
            return afi == AFI_IPV4 && ctx.transport_afi == AFI_IPV4;
        }
        peer_mp.contains(&(afi, 1))
            && (afi == ctx.transport_afi || peer_ext_nh.contains(&(afi, 1, ctx.transport_afi)))
    };
    // EVPN needs no Extended Next Hop tuple, and has no legacy (non-MP) form.
    let evpn = ctx.address_families.contains(&AddressFamily::L2vpnEvpn)
        && peer_mp.contains(&(message::AFI_L2VPN, message::SAFI_EVPN));
    (
        mp_bgp_negotiated,
        negotiated(AFI_IPV4),
        negotiated(AFI_IPV6),
        evpn,
    )
}

/// Whether the peer's OPEN granted RFC 7911 ADD-PATH for IPv4/IPv6 unicast —
/// always `(false, false)` unless `ctx.is_rs_client`, since this session
/// only ever advertises the capability itself in that case (see `run`);
/// otherwise `true` for any AFI where the peer's OPEN carried an `AddPath`
/// tuple with a non-zero `send_receive` (this crate always offers `3`/both
/// itself, so it doesn't distinguish partial send-only/receive-only grants —
/// `ponytail: treats ADD-PATH as fully bidirectional once negotiated`).
fn negotiate_add_path(open: &OpenMessage, ctx: &NegotiationContext) -> (bool, bool) {
    if !ctx.is_rs_client {
        return (false, false);
    }
    let peer_add_path: HashSet<u16> = open
        .capabilities
        .iter()
        .filter_map(|c| match c {
            message::Capability::AddPath(tuples) => Some(tuples.iter()),
            _ => None,
        })
        .flatten()
        .filter(|t| t.send_receive != 0)
        .map(|t| t.afi)
        .collect();
    (
        peer_add_path.contains(&AFI_IPV4),
        peer_add_path.contains(&AFI_IPV6),
    )
}

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
    /// The peer-group's MRAI; zero means unpaced (see `crate::mrai`).
    pub mrai: Duration,
    /// The peer-group's RFC 2439 flap damping, if enabled (see `crate::damping`).
    pub damping: Option<nos_proto::BgpDamping>,
    /// The peer-group's configured next-hop override, if any — `None` lets
    /// `crate::rib::build_advertisement` fall back to the eBGP/iBGP-dependent
    /// default.
    pub next_hop: Option<NextHopMode>,
    /// The peer-group's configured address families — independent of
    /// `remote_address`'s own family (RFC 8950), see
    /// `build_mp_capabilities`/`negotiate_address_families`.
    pub address_families: Vec<AddressFamily>,
    /// RFC 4456 route-reflector client — passed straight through to
    /// `crate::rib::BgpRib::peer_established`, no FSM-level effect.
    pub is_rr_client: bool,
    /// RFC 7947 route-server client — gates whether this session's own OPEN
    /// advertises the RFC 7911 ADD-PATH capability at all (see `run`) and is
    /// passed through to `BgpRib::peer_established`.
    pub is_rs_client: bool,
    /// This peer's resolved import policy — passed straight through to
    /// every `BgpRib::handle_update` call on this connection, no FSM-level
    /// effect. `deny-all` by default (see root `CLAUDE.md`'s "Default-deny
    /// rollout impact").
    pub import_policy: Arc<nos_rpl::CompiledPolicy>,
    /// Same default-deny semantics as `import_policy`, passed through to
    /// `BgpRib::peer_established` for advertisement instead of receipt.
    pub export_policy: Arc<nos_rpl::CompiledPolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // each bool is an independently-negotiated capability
struct RemoteInfo {
    asn: u32,
    bgp_id: Ipv4Addr,
    mp_bgp_negotiated: bool,
    negotiated_ipv4_unicast: bool,
    negotiated_ipv6_unicast: bool,
    negotiated_evpn: bool,
    /// RFC 7911 ADD-PATH negotiated for this AFI — always `false` unless
    /// this session is `is_rs_client` (only such sessions ever advertise the
    /// capability, see `run`) and the peer echoed it back.
    add_path_ipv4: bool,
    add_path_ipv6: bool,
    /// The peer sent the four-octet AS capability (RFC 6793); `false` means
    /// 2-byte `AS_PATH` + `AS4_PATH` in both directions.
    four_octet_as: bool,
    /// The peer sent the RFC 8654 Extended Message capability (we always do).
    extended_message: bool,
    /// The peer sent the RFC 7313 Enhanced Route Refresh capability (we always do).
    enhanced_refresh: bool,
    /// The peer sent the RFC 2918 Route Refresh capability: without it we
    /// must never send it a `ROUTE_REFRESH`.
    route_refresh: bool,
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
        mp_bgp_negotiated: bool,
        negotiated_ipv4_unicast: bool,
        negotiated_ipv6_unicast: bool,
        negotiated_evpn: bool,
        add_path_ipv4: bool,
        add_path_ipv6: bool,
        four_octet_as: bool,
        extended_message: bool,
    },
    Close,
}

struct NegotiationContext {
    expected_remote_as: u32,
    local_hold_time: u16,
    keepalive_override: Option<u16>,
    address_families: Vec<AddressFamily>,
    transport_afi: u16,
    /// See `PeerContext::is_rs_client` — gates whether `negotiate_add_path`
    /// ever returns `true` at all (this session only ever offers the
    /// capability itself when this is set, so a peer's own advertisement of
    /// it is irrelevant otherwise).
    is_rs_client: bool,
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
                mp_bgp_negotiated: remote.mp_bgp_negotiated,
                negotiated_ipv4_unicast: remote.negotiated_ipv4_unicast,
                negotiated_ipv6_unicast: remote.negotiated_ipv6_unicast,
                negotiated_evpn: remote.negotiated_evpn,
                add_path_ipv4: remote.add_path_ipv4,
                add_path_ipv6: remote.add_path_ipv6,
                four_octet_as: remote.four_octet_as,
                extended_message: remote.extended_message,
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
        (state, _) => {
            let subcode = match state {
                State::OpenSent => FsmSubcode::UnexpectedInOpenSent,
                State::OpenConfirm(_) => FsmSubcode::UnexpectedInOpenConfirm,
                State::Established(_) => FsmSubcode::UnexpectedInEstablished,
            };
            (
                None,
                vec![
                    Action::SendNotification(ErrorCode::FiniteStateMachine as u8, subcode as u8),
                    Action::Close,
                ],
            )
        }
    }
}

fn handle_open(open: &OpenMessage, ctx: &NegotiationContext) -> (Option<State>, Vec<Action>) {
    if open.version != message::BGP_VERSION {
        return reject(OpenMessageSubcode::UnsupportedVersionNumber);
    }
    if open.my_as == message::AS_TRANS && message::four_octet_asn(open).is_none() {
        // AS_TRANS with no capability backing it is meaningless per RFC 6793.
        return reject(OpenMessageSubcode::BadPeerAs);
    }
    let remote_asn = message::effective_remote_asn(open);
    // RFC 7607: AS 0 is never valid, whatever the peer is expected to be.
    if remote_asn == 0 || remote_asn != ctx.expected_remote_as {
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
    let (mp_bgp_negotiated, negotiated_ipv4_unicast, negotiated_ipv6_unicast, negotiated_evpn) =
        negotiate_address_families(open, ctx);
    let (add_path_ipv4, add_path_ipv6) = negotiate_add_path(open, ctx);
    let remote = RemoteInfo {
        asn: remote_asn,
        bgp_id: open.bgp_identifier,
        mp_bgp_negotiated,
        negotiated_ipv4_unicast,
        negotiated_ipv6_unicast,
        negotiated_evpn,
        add_path_ipv4,
        add_path_ipv6,
        four_octet_as: message::four_octet_asn(open).is_some(),
        extended_message: open
            .capabilities
            .contains(&message::Capability::ExtendedMessage),
        enhanced_refresh: open
            .capabilities
            .contains(&message::Capability::EnhancedRouteRefresh),
        route_refresh: open
            .capabilities
            .contains(&message::Capability::RouteRefresh),
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
        | WireError::MalformedRouteRefresh
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

/// Turns one inbound message into the `Event` to feed `step`, or handles it
/// here and returns `None`.
///
/// UPDATE and `ROUTE_REFRESH` bypass `step`'s transition table entirely — they
/// aren't part of the OpenSent/OpenConfirm/Established table and are
/// meaningful only once `Established` — so they are consumed here rather than
/// inside `run`'s `select!`, which only ever yields a value.
async fn classify_inbound(
    msg: BgpMessage,
    state: &State,
    peer: &PeerContext,
    remote_is_ibgp: bool,
    bgp_rib: &Mutex<BgpRib>,
    slot: &PeerSlot,
) -> Option<Event> {
    match msg {
        BgpMessage::Open(open) => Some(Event::OpenReceived(open)),
        BgpMessage::Keepalive => Some(Event::KeepaliveReceived),
        BgpMessage::Notification(n) => Some(Event::NotificationReceived(n)),
        BgpMessage::Update(update) => {
            if let State::Established(remote) = state {
                let mut rib = bgp_rib.lock().await;
                rib.handle_update(
                    peer.remote_address,
                    remote_is_ibgp,
                    remote.bgp_id,
                    &update,
                    &peer.import_policy,
                );
                // RFC 4486 §4: over a hard limit, hold the peer down and have
                // the command arm send the Cease. Once only: UPDATEs read
                // before that arm runs must not queue a second Cease, which
                // would outlive this session in the slot's channel.
                if let Some((family, limit, _)) = rib.check_max_prefix(peer.remote_address) {
                    if !slot.max_prefix_held() {
                        slot.trip_max_prefix(limit.restart_interval);
                        slot.send_command(FsmCommand::Cease {
                            subcode: CeaseSubcode::MaximumPrefixesReached,
                            data: message::encode_max_prefix_data(
                                afi_of(family),
                                safi_of(family),
                                limit.limit,
                            ),
                        });
                    }
                }
            } else {
                debug!(
                    peer = %peer.remote_address,
                    "ignoring bgp update received before session established"
                );
            }
            None
        }
        BgpMessage::RouteRefresh(rr) => {
            resend_loc_rib(rr, state, peer, bgp_rib).await;
            None
        }
        BgpMessage::Unhandled { message_type, .. } => {
            debug!(
                peer = %peer.remote_address, message_type,
                "ignoring unrecognized bgp message type"
            );
            None
        }
    }
}

/// RFC 2918 inbound: re-send the Loc-RIB for the requested address family.
async fn resend_loc_rib(
    rr: RouteRefreshMessage,
    state: &State,
    peer: &PeerContext,
    bgp_rib: &Mutex<BgpRib>,
) {
    if !matches!(state, State::Established(_)) {
        debug!(
            peer = %peer.remote_address,
            "ignoring route refresh received before session established"
        );
        return;
    }
    let Some(family) = family_of_afi(rr.afi) else {
        debug!(
            peer = %peer.remote_address, afi = rr.afi,
            "ignoring route-refresh for unrecognized afi"
        );
        return;
    };
    // RFC 7313: markers only mean something on a session that negotiated it.
    let State::Established(remote) = state else {
        return;
    };
    let mut rib = bgp_rib.lock().await;
    match rr.subtype {
        message::REFRESH_REQUEST => {
            rib.resend_all(peer.remote_address, family, remote.enhanced_refresh);
            info!(
                peer = %peer.remote_address, afi = rr.afi,
                "bgp: received route refresh, resending loc-rib"
            );
        }
        message::REFRESH_BORR if remote.enhanced_refresh => {
            rib.begin_refresh_in(peer.remote_address, family);
            debug!(peer = %peer.remote_address, afi = rr.afi, "bgp: received BoRR");
        }
        message::REFRESH_EORR if remote.enhanced_refresh => {
            rib.end_refresh_in(peer.remote_address, family);
            debug!(peer = %peer.remote_address, afi = rr.afi, "bgp: received EoRR");
        }
        subtype => debug!(
            peer = %peer.remote_address, subtype,
            "ignoring route-refresh with unusable subtype"
        ),
    }
}

/// RFC 2918 outbound: request a refresh for every address family this
/// session actually negotiated.
async fn send_route_refresh(
    writer: &mut FramedWrite<OwnedWriteHalf, BgpCodec>,
    state: &State,
    peer: &PeerContext,
) {
    let State::Established(remote) = state else {
        return;
    };
    if !remote.route_refresh {
        warn!(
            peer = %peer.remote_address,
            "route refresh not sent: the peer did not advertise the route refresh capability (rfc 2918)"
        );
        return;
    }
    let afis = [
        remote.negotiated_ipv4_unicast.then_some(AFI_IPV4),
        remote.negotiated_ipv6_unicast.then_some(AFI_IPV6),
    ];
    for afi in afis.into_iter().flatten() {
        let _ = writer
            .send(BgpMessage::RouteRefresh(RouteRefreshMessage {
                afi,
                subtype: message::REFRESH_REQUEST,
                safi: 1,
            }))
            .await;
    }
    info!(peer = %peer.remote_address, "bgp: sent route refresh request to peer");
}

/// RFC 4271 §6.8: an OPEN has just moved this connection to `OpenConfirm`,
/// so register its BGP Identifier with the peer's shared `PeerSlot` and apply
/// the verdict.
///
/// Returns `Some` replacement `(next_state, actions)` when this connection
/// *lost* — rewriting the transition into "send Cease, then close" — and
/// `None` when it may proceed, having published its newly-known remote
/// identity to the peer's status.
async fn apply_collision_verdict(
    remote: RemoteInfo,
    role: collision::Role,
    local: &LocalIdentity,
    slot: &PeerSlot,
    cease: Arc<Notify>,
) -> Option<(Option<State>, Vec<Action>)> {
    match slot
        .on_open(role, local.router_id, remote.bgp_id, cease)
        .await
    {
        collision::Decision::Lose => Some((
            None,
            vec![
                Action::SendNotification(
                    ErrorCode::Cease as u8,
                    CeaseSubcode::ConnectionCollisionResolution as u8,
                ),
                Action::Close,
            ],
        )),
        // `on_open` only returns `Proceed` when no other connection for this
        // peer is already `Established` (see `collision::PeerSlot::on_open`),
        // so this is safe to write without an extra `is_established` race
        // check.
        collision::Decision::Proceed => {
            slot.status.send_modify(|s| {
                s.state = PeerState::OpenConfirm;
                s.remote_asn = Some(remote.asn);
                s.remote_bgp_id = Some(remote.bgp_id);
            });
            None
        }
    }
}

/// Drives one session's `OpenSent` -> `OpenConfirm` -> `Established` FSM
/// over an already-connected `stream`. The caller is responsible for
/// `PeerSlot::begin`/`clear` around this call — `run` only touches
/// `on_open`/`mark_established`, the transitions intrinsic to FSM progress.
///
/// `bgp_rib` is registered with a fresh outbound channel once the session
/// reaches `Established` (`Action::ReportEstablished`), fed real
/// `BgpMessage::Update`s back onto the wire from a dedicated `select!` arm,
/// and deregistered (`peer_disconnected`) at this function's single exit
/// point — but only if it actually registered, since `BgpRib` is keyed by
/// peer address and a collision loser shares one with its winner (see
/// `registered` below).
/// Logs a received NOTIFICATION; for a Cease/Administrative Shutdown or Reset
/// (RFC 9003) also the peer's shutdown communication, if it sent a valid one.
fn log_notification(peer: IpAddr, n: &NotificationMessage) {
    let is_shutdown = n.error_code == ErrorCode::Cease as u8 && matches!(n.error_subcode, 2 | 4);
    let message = is_shutdown
        .then(|| message::decode_shutdown_message(&n.data))
        .flatten();
    info!(
        peer = %peer, code = n.error_code, subcode = n.error_subcode,
        shutdown_message = message.as_deref().unwrap_or(""),
        "received notification"
    );
}

#[allow(clippy::similar_names)] // add_path_afis (wire AFI ints) vs. add_path_afs (AddressFamily)
pub async fn run(
    stream: TcpStream,
    role: collision::Role,
    local: LocalIdentity,
    peer: PeerContext,
    slot: Arc<PeerSlot>,
    bgp_rib: Arc<Mutex<BgpRib>>,
) -> FsmOutcome {
    // Captured before `into_split()` consumes `stream`: this session's own
    // local address (of whatever family), used as next-hop-self for every
    // address family this session ends up carrying — including a family
    // that differs from this address's own (RFC 8950 cross-family
    // next-hop), which is exactly why this is no longer restricted to IPv4.
    let local_addr = stream.local_addr().ok().map(|addr| addr.ip());
    // Also captured here, for the same reason: `status.fd`, read on demand
    // for a `TCP_AO_INFO` getsockopt once this session reaches `Established`
    // (see `Action::ReportEstablished` below).
    let fd = stream.as_raw_fd();
    // RFC 5065: `Internal` is the member AS, in a confederation.
    let kind = slot.peer.kind(local.asn);
    let remote_is_ibgp = kind == PeerKind::Internal;
    let (outbox_tx, mut outbox_rx) = mpsc::unbounded_channel::<OutboundUpdate>();
    let mut mrai = crate::mrai::Mrai::new(peer.mrai);

    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, BgpCodec::default());
    let mut writer = FramedWrite::new(write_half, BgpCodec::default());

    let ctx = NegotiationContext {
        expected_remote_as: peer.expected_remote_as,
        local_hold_time: peer.local_hold_time,
        keepalive_override: peer.keepalive_override,
        address_families: peer.address_families.clone(),
        transport_afi: afi_of_addr(peer.remote_address),
        is_rs_client: peer.is_rs_client,
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

    // Whether this connection ever registered itself with `bgp_rib`, i.e.
    // reached `Established` and ran `Action::ReportEstablished`.
    //
    // `BgpRib` is keyed by peer *address*, not by connection, so the exit
    // path below must not deregister a peer this connection never
    // registered: a collision loser (RFC 4271 §6.8) shares its peer address
    // with the connection that beat it, and tearing down the loser would
    // otherwise wipe the *winner's* `adj_rib_in` and — worse — its
    // `peer_outbox`, leaving a session that is still up but can never
    // advertise to that peer again.
    let mut registered = false;

    // Single exit point: every early-return case below (`break 'session
    // ...`) funnels through the same `bgp_rib.peer_disconnected` call after
    // this block, rather than returning directly.
    let outcome = 'session: {
        let mut open = message::build_open(
            slot.peer.open_as(local.asn),
            local.router_id,
            peer.local_hold_time,
        );
        open.capabilities.extend(build_mp_capabilities(
            &peer.address_families,
            ctx.transport_afi,
        ));
        open.capabilities.push(message::Capability::RouteRefresh);
        open.capabilities
            .push(message::Capability::EnhancedRouteRefresh);
        open.capabilities.push(message::Capability::ExtendedMessage);
        if peer.is_rs_client {
            // Only ever advertised for a route-server-client peer-group,
            // unlike this crate's other capabilities — see `bgp/CLAUDE.md`'s
            // "Route reflection and route server" section for why.
            let tuples = peer
                .address_families
                .iter()
                .filter(|&&af| af != AddressFamily::L2vpnEvpn)
                .map(|&af| message::AddPathTuple {
                    afi: afi_of(af),
                    safi: 1,
                    send_receive: 3,
                })
                .collect();
            open.capabilities.push(message::Capability::AddPath(tuples));
        }
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
                        match classify_inbound(bgp_msg, &state, &peer, remote_is_ibgp, &bgp_rib, &slot).await {
                            Some(event) => event,
                            None => continue,
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
                    // RFC 7313: EoRR must follow every route it brackets, so
                    // release anything MRAI is still holding first.
                    if matches!(update, OutboundUpdate::RefreshMarker { subtype: message::REFRESH_EORR, .. }) {
                        for held in mrai.drain() {
                            if let Err(e) = writer.send(outbound_update_to_message(held)).await {
                                warn!(error = %e, "could not send update");
                            }
                        }
                    }
                    if let Some(update) = mrai.push(update, Instant::now()) {
                        if let Err(e) = writer.send(outbound_update_to_message(update)).await {
                            warn!(error = %e, "could not send update");
                        }
                    }
                    continue;
                }
                () = sleep_until_opt(mrai.deadline()) => {
                    for update in mrai.flush(Instant::now()) {
                        if let Err(e) = writer.send(outbound_update_to_message(update)).await {
                            warn!(error = %e, "could not send update");
                        }
                    }
                    continue;
                }
                // Guarded on `Established`: collision resolution always
                // happens before either side reaches it, so only the one
                // task that ever becomes canonical polls (and locks)
                // `slot`'s shared command receiver — the collision loser
                // never contends for it.
                Some(cmd) = slot.recv_command(), if matches!(state, State::Established(_)) => {
                    match cmd {
                        FsmCommand::SendRouteRefresh => {
                            send_route_refresh(&mut writer, &state, &peer).await;
                        }
                        FsmCommand::Cease { subcode, data } => {
                            let _ = writer
                                .send(BgpMessage::Notification(NotificationMessage {
                                    error_code: ErrorCode::Cease as u8,
                                    error_subcode: subcode as u8,
                                    data,
                                }))
                                .await;
                            info!(
                                peer = %peer.remote_address, subcode = subcode as u8,
                                "sent cease notification"
                            );
                            break 'session FsmOutcome::NotificationSent {
                                code: ErrorCode::Cease as u8,
                                subcode: subcode as u8,
                            };
                        }
                    }
                    continue;
                }
            };

            let is_open_event = matches!(event, Event::OpenReceived(_));
            let notification_received = match &event {
                Event::NotificationReceived(n) => {
                    log_notification(peer.remote_address, n);
                    Some((n.error_code, n.error_subcode))
                }
                _ => None,
            };
            let (mut next_state, mut actions) = step(state, event, &ctx);

            // Only an OPEN can produce a collision (RFC 4271 §6.8).
            let reached_open_confirm = match (is_open_event, &next_state) {
                (true, Some(State::OpenConfirm(remote))) => Some(*remote),
                _ => None,
            };
            if let Some(remote) = reached_open_confirm {
                if let Some((state, lost)) =
                    apply_collision_verdict(remote, role, &local, &slot, cease.clone()).await
                {
                    next_state = state;
                    actions = lost;
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
                        mp_bgp_negotiated,
                        negotiated_ipv4_unicast,
                        negotiated_ipv6_unicast,
                        negotiated_evpn,
                        add_path_ipv4,
                        add_path_ipv6,
                        four_octet_as,
                        extended_message,
                    } => {
                        slot.mark_established(role).await;
                        let mut negotiated_afs = HashSet::new();
                        if *negotiated_ipv4_unicast {
                            negotiated_afs.insert(AddressFamily::Ipv4Unicast);
                        }
                        if *negotiated_ipv6_unicast {
                            negotiated_afs.insert(AddressFamily::Ipv6Unicast);
                        }
                        if *negotiated_evpn {
                            negotiated_afs.insert(AddressFamily::L2vpnEvpn);
                        }
                        let mut add_path_afis = HashSet::new();
                        let mut add_path_afs = HashSet::new();
                        if *add_path_ipv4 {
                            add_path_afis.insert(AFI_IPV4);
                            add_path_afs.insert(AddressFamily::Ipv4Unicast);
                        }
                        if *add_path_ipv6 {
                            add_path_afis.insert(AFI_IPV6);
                            add_path_afs.insert(AddressFamily::Ipv6Unicast);
                        }
                        // Must be set before any further UPDATE is
                        // decoded/encoded on this connection — done here,
                        // right after Established, the same point every
                        // other negotiated-capability field is applied.
                        reader
                            .decoder_mut()
                            .add_path_afis
                            .clone_from(&add_path_afis);
                        writer.encoder_mut().add_path_afis = add_path_afis;
                        reader.decoder_mut().two_octet_as = !*four_octet_as;
                        writer.encoder_mut().two_octet_as = !*four_octet_as;
                        reader.decoder_mut().extended = *extended_message;
                        writer.encoder_mut().extended = *extended_message;
                        info!(
                            extended_message = *extended_message,
                            "extended message negotiated"
                        );
                        let mut rib = bgp_rib.lock().await;
                        rib.set_peer_damping(peer.remote_address, peer.damping);
                        rib.set_peer_max_prefix(peer.remote_address, slot.peer.maximum_prefix);
                        rib.set_peer_asn(peer.remote_address, *remote_asn);
                        rib.set_peer_confed(peer.remote_address, kind == PeerKind::ConfedExternal);
                        rib.peer_established(
                            peer.remote_address,
                            remote_is_ibgp,
                            local_addr,
                            negotiated_afs,
                            *mp_bgp_negotiated,
                            peer.next_hop,
                            peer.is_rr_client,
                            peer.is_rs_client,
                            add_path_afs,
                            peer.export_policy.clone(),
                            outbox_tx.clone(),
                        );
                        registered = true;
                        slot.status.send_modify(|s| {
                            s.state = PeerState::Established;
                            s.remote_asn = Some(*remote_asn);
                            s.remote_bgp_id = Some(*remote_bgp_id);
                            s.established_since = Some(Instant::now());
                            s.negotiated_hold_time = negotiated_hold_time;
                            s.negotiated_keepalive = negotiated_keepalive;
                            s.fd = Some(fd);
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

    if registered {
        bgp_rib.lock().await.peer_disconnected(peer.remote_address);
    }
    outcome
}

/// Converts one outbound RIB decision into the real `BgpMessage::Update` to
/// send on the wire — the encode side of `crate::rib::BgpRib`'s per-peer
/// propagation decisions. `route.use_mp`/the withdraw's `bool` (set by
/// `crate::rib::build_advertisement`/`BgpRib` from the destination peer's
/// `mp_bgp_negotiated`) picks the legacy plain-NLRI encoding or
/// `MP_REACH_NLRI`/`MP_UNREACH_NLRI` — never derived from the prefix's own
/// family, since the same IPv4 prefix is encoded differently depending on
/// what the destination peer negotiated.
fn outbound_update_to_message(update: OutboundUpdate) -> BgpMessage {
    match update {
        OutboundUpdate::Announce(route) if route.use_mp => {
            let path_ids = route.path_id.map_or_else(Vec::new, |id| vec![id]);
            BgpMessage::Update(message::UpdateMessage {
                withdrawn_routes: Vec::new(),
                withdrawn_path_ids: Vec::new(),
                nlri: Vec::new(),
                nlri_path_ids: Vec::new(),
                attributes: Some(message::PathAttributes {
                    origin: route.origin,
                    as_path: route.as_path,
                    next_hop: Ipv4Addr::UNSPECIFIED, // unused: the real next-hop lives in mp_reach
                    local_pref: route.local_pref,
                    med: route.med,
                    originator_id: route.originator_id,
                    cluster_list: route.cluster_list,
                    communities: route.communities,
                    extended_communities: route.extended_communities,
                    large_communities: route.large_communities,
                    pmsi: None,
                    atomic_aggregate: route.atomic_aggregate,
                    aggregator: route.aggregator,
                }),
                mp_reach: vec![message::MpReachNlri {
                    afi: afi_of_ipnet(route.prefix),
                    safi: 1,
                    next_hop: route.next_hop,
                    nlri: vec![route.prefix],
                    nlri_path_ids: path_ids,
                    evpn: Vec::new(),
                }],
                mp_unreach: Vec::new(),
            })
        }
        OutboundUpdate::Announce(route) => {
            let path_ids = route.path_id.map_or_else(Vec::new, |id| vec![id]);
            BgpMessage::Update(message::UpdateMessage {
                withdrawn_routes: Vec::new(),
                withdrawn_path_ids: Vec::new(),
                nlri: vec![expect_ipv4_net(route.prefix)],
                nlri_path_ids: path_ids,
                attributes: Some(message::PathAttributes {
                    origin: route.origin,
                    as_path: route.as_path,
                    next_hop: expect_ipv4_addr(route.next_hop),
                    local_pref: route.local_pref,
                    med: route.med,
                    originator_id: route.originator_id,
                    cluster_list: route.cluster_list,
                    communities: route.communities,
                    extended_communities: route.extended_communities,
                    large_communities: route.large_communities,
                    pmsi: None,
                    atomic_aggregate: route.atomic_aggregate,
                    aggregator: route.aggregator,
                }),
                mp_reach: Vec::new(),
                mp_unreach: Vec::new(),
            })
        }
        OutboundUpdate::Withdraw(prefix, use_mp, path_id) if use_mp => {
            let path_ids = path_id.map_or_else(Vec::new, |id| vec![id]);
            BgpMessage::Update(message::UpdateMessage {
                withdrawn_routes: Vec::new(),
                withdrawn_path_ids: Vec::new(),
                nlri: Vec::new(),
                nlri_path_ids: Vec::new(),
                attributes: None,
                mp_reach: Vec::new(),
                mp_unreach: vec![message::MpUnreachNlri {
                    afi: afi_of_ipnet(prefix),
                    safi: 1,
                    withdrawn: vec![prefix],
                    withdrawn_path_ids: path_ids,
                    evpn: Vec::new(),
                }],
            })
        }
        OutboundUpdate::RefreshMarker { family, subtype } => {
            BgpMessage::RouteRefresh(RouteRefreshMessage {
                afi: afi_of(family),
                subtype,
                safi: safi_of(family),
            })
        }
        OutboundUpdate::AnnounceEvpn(route) => BgpMessage::Update(message::UpdateMessage {
            withdrawn_routes: Vec::new(),
            withdrawn_path_ids: Vec::new(),
            nlri: Vec::new(),
            nlri_path_ids: Vec::new(),
            attributes: Some(message::PathAttributes {
                origin: message::Origin::Igp,
                as_path: route.as_path,
                next_hop: Ipv4Addr::UNSPECIFIED, // unused: the real next-hop lives in mp_reach
                local_pref: route.local_pref,
                med: None,
                originator_id: None,
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: Vec::new(),
                communities: Vec::new(),
                extended_communities: route.extended_communities,
                large_communities: Vec::new(),
                pmsi: route.pmsi,
            }),
            mp_reach: vec![message::MpReachNlri {
                afi: message::AFI_L2VPN,
                safi: message::SAFI_EVPN,
                next_hop: route.next_hop,
                nlri: Vec::new(),
                nlri_path_ids: Vec::new(),
                evpn: vec![route.nlri],
            }],
            mp_unreach: Vec::new(),
        }),
        OutboundUpdate::WithdrawEvpn(nlri) => BgpMessage::Update(message::UpdateMessage {
            withdrawn_routes: Vec::new(),
            withdrawn_path_ids: Vec::new(),
            nlri: Vec::new(),
            nlri_path_ids: Vec::new(),
            attributes: None,
            mp_reach: Vec::new(),
            mp_unreach: vec![message::MpUnreachNlri {
                afi: message::AFI_L2VPN,
                safi: message::SAFI_EVPN,
                withdrawn: Vec::new(),
                withdrawn_path_ids: Vec::new(),
                evpn: vec![nlri],
            }],
        }),
        OutboundUpdate::Withdraw(prefix, _, path_id) => {
            let path_ids = path_id.map_or_else(Vec::new, |id| vec![id]);
            BgpMessage::Update(message::UpdateMessage {
                withdrawn_routes: vec![expect_ipv4_net(prefix)],
                withdrawn_path_ids: path_ids,
                nlri: Vec::new(),
                nlri_path_ids: Vec::new(),
                attributes: None,
                mp_reach: Vec::new(),
                mp_unreach: Vec::new(),
            })
        }
    }
}

fn afi_of_ipnet(net: ipnet::IpNet) -> u16 {
    match net {
        ipnet::IpNet::V4(_) => AFI_IPV4,
        ipnet::IpNet::V6(_) => AFI_IPV6,
    }
}

/// Only ever called for a `!use_mp` (legacy) `OutboundUpdate` — `BgpRib`
/// only sets `use_mp: false` for an `Ipv4Unicast` prefix/next-hop (see
/// `crate::rib::build_advertisement`), so the `V6` arm is unreachable.
fn expect_ipv4_net(net: ipnet::IpNet) -> ipnet::Ipv4Net {
    match net {
        ipnet::IpNet::V4(n) => n,
        ipnet::IpNet::V6(_) => {
            unreachable!("legacy OutboundUpdate only ever carries an IPv4 prefix")
        }
    }
}

fn expect_ipv4_addr(addr: IpAddr) -> Ipv4Addr {
    match addr {
        IpAddr::V4(a) => a,
        IpAddr::V6(_) => unreachable!("legacy OutboundUpdate only ever carries an IPv4 next-hop"),
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
            address_families: vec![AddressFamily::Ipv4Unicast],
            transport_afi: AFI_IPV4,
            is_rs_client: false,
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
            address_families: vec![AddressFamily::Ipv4Unicast],
            transport_afi: AFI_IPV4,
            is_rs_client: false,
        }
    }

    fn valid_open(remote_as: u32, hold_time: u16) -> OpenMessage {
        message::build_open(remote_as, Ipv4Addr::new(2, 2, 2, 2), hold_time)
    }

    fn open_with_mp(afis: &[(u16, u8)]) -> OpenMessage {
        let mut open = valid_open(65002, 90);
        for &(afi, safi) in afis {
            open.capabilities
                .push(message::Capability::MultiProtocol { afi, safi });
        }
        open
    }

    fn ctx_with_afs(
        address_families: Vec<AddressFamily>,
        transport_afi: u16,
    ) -> NegotiationContext {
        NegotiationContext {
            address_families,
            transport_afi,
            ..ctx(65002)
        }
    }

    #[test]
    fn evpn_negotiated_only_when_both_sides_advertise_it() {
        let both = ctx_with_afs(
            vec![AddressFamily::Ipv4Unicast, AddressFamily::L2vpnEvpn],
            AFI_IPV4,
        );
        let peer = open_with_mp(&[(AFI_IPV4, 1), (message::AFI_L2VPN, message::SAFI_EVPN)]);
        assert_eq!(
            negotiate_address_families(&peer, &both),
            (true, true, false, true)
        );
        // Peer never offered it.
        let no_evpn = open_with_mp(&[(AFI_IPV4, 1)]);
        assert_eq!(
            negotiate_address_families(&no_evpn, &both),
            (true, true, false, false)
        );
        // We never configured it.
        let ipv4_only = ctx_with_afs(vec![AddressFamily::Ipv4Unicast], AFI_IPV4);
        assert_eq!(
            negotiate_address_families(&peer, &ipv4_only),
            (true, true, false, false)
        );
        // EVPN alone needs no Extended Next Hop, even over an IPv6 transport.
        let v6_transport = ctx_with_afs(vec![AddressFamily::L2vpnEvpn], AFI_IPV6);
        let evpn_only = open_with_mp(&[(message::AFI_L2VPN, message::SAFI_EVPN)]);
        assert_eq!(
            negotiate_address_families(&evpn_only, &v6_transport),
            (true, false, false, true)
        );
    }

    #[test]
    fn evpn_capability_is_sent_as_afi25_safi70_without_extended_next_hop() {
        let caps = build_mp_capabilities(&[AddressFamily::L2vpnEvpn], AFI_IPV6);
        assert_eq!(
            caps,
            vec![message::Capability::MultiProtocol {
                afi: message::AFI_L2VPN,
                safi: message::SAFI_EVPN
            }]
        );
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
        open.capabilities.clear();
        let (next, actions) = step(State::OpenSent, Event::OpenReceived(open), &ctx(65002));
        assert_eq!(next, None);
        assert!(actions.contains(&Action::SendNotification(
            ErrorCode::OpenMessage as u8,
            OpenMessageSubcode::BadPeerAs as u8
        )));
    }

    #[test]
    fn as_zero_is_bad_peer_as_even_when_expected() {
        let (next, actions) = step(
            State::OpenSent,
            Event::OpenReceived(valid_open(0, 90)),
            &ctx(0),
        );
        assert_eq!(next, None);
        assert!(actions.contains(&Action::SendNotification(
            ErrorCode::OpenMessage as u8,
            OpenMessageSubcode::BadPeerAs as u8
        )));
    }

    #[test]
    fn extended_message_follows_the_peers_capability() {
        let mut with_cap = valid_open(65002, 90);
        with_cap
            .capabilities
            .push(message::Capability::ExtendedMessage);
        let (Some(State::OpenConfirm(r)), _) = handle_open(&with_cap, &ctx(65002)) else {
            panic!("expected OpenConfirm");
        };
        assert!(r.extended_message);
        let (Some(State::OpenConfirm(r)), _) = handle_open(&valid_open(65002, 90), &ctx(65002))
        else {
            panic!("expected OpenConfirm");
        };
        assert!(!r.extended_message);
    }

    /// RFC 2918 §4: no `ROUTE_REFRESH` toward a peer that didn't advertise
    /// the capability (#17).
    #[test]
    fn route_refresh_follows_the_peers_capability() {
        let mut with_cap = valid_open(65002, 90);
        with_cap
            .capabilities
            .push(message::Capability::RouteRefresh);
        let (Some(State::OpenConfirm(r)), _) = handle_open(&with_cap, &ctx(65002)) else {
            panic!("expected OpenConfirm");
        };
        assert!(r.route_refresh);
        let (Some(State::OpenConfirm(r)), _) = handle_open(&valid_open(65002, 90), &ctx(65002))
        else {
            panic!("expected OpenConfirm");
        };
        assert!(!r.route_refresh);
    }

    #[test]
    fn four_octet_as_follows_the_peers_capability() {
        let with_cap = valid_open(65002, 90);
        let (Some(State::OpenConfirm(r)), _) = handle_open(&with_cap, &ctx(65002)) else {
            panic!("expected OpenConfirm");
        };
        assert!(r.four_octet_as);
        let mut without = with_cap;
        without.capabilities.clear();
        let (Some(State::OpenConfirm(r)), _) = handle_open(&without, &ctx(65002)) else {
            panic!("expected OpenConfirm");
        };
        assert!(!r.four_octet_as);
    }

    #[test]
    fn keepalive_in_open_confirm_reaches_established() {
        let remote = RemoteInfo {
            asn: 65002,
            bgp_id: Ipv4Addr::new(2, 2, 2, 2),
            mp_bgp_negotiated: false,
            negotiated_ipv4_unicast: true,
            negotiated_ipv6_unicast: false,
            negotiated_evpn: false,
            add_path_ipv4: false,
            add_path_ipv6: false,
            four_octet_as: true,
            extended_message: false,
            enhanced_refresh: false,
            route_refresh: false,
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
            mp_bgp_negotiated: false,
            negotiated_ipv4_unicast: true,
            negotiated_ipv6_unicast: false,
            negotiated_evpn: false,
            add_path_ipv4: false,
            add_path_ipv6: false,
            four_octet_as: true,
            extended_message: false,
            enhanced_refresh: false,
            route_refresh: false,
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
    fn unexpected_message_uses_rfc6608_subcode_of_current_state() {
        let remote = RemoteInfo {
            asn: 65002,
            bgp_id: Ipv4Addr::new(2, 2, 2, 2),
            mp_bgp_negotiated: false,
            negotiated_ipv4_unicast: true,
            negotiated_ipv6_unicast: false,
            negotiated_evpn: false,
            add_path_ipv4: false,
            add_path_ipv6: false,
            four_octet_as: true,
            extended_message: false,
            enhanced_refresh: false,
            route_refresh: false,
        };
        for (state, event, subcode) in [
            (State::OpenSent, Event::KeepaliveReceived, 1),
            (
                State::OpenConfirm(remote),
                Event::OpenReceived(valid_open(65002, 90)),
                2,
            ),
            (
                State::Established(remote),
                Event::OpenReceived(valid_open(65002, 90)),
                3,
            ),
        ] {
            let (next, actions) = step(state, event, &ctx(65002));
            assert_eq!(next, None);
            assert!(actions.contains(&Action::SendNotification(
                ErrorCode::FiniteStateMachine as u8,
                subcode
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
            mp_bgp_negotiated: false,
            negotiated_ipv4_unicast: true,
            negotiated_ipv6_unicast: false,
            negotiated_evpn: false,
            add_path_ipv4: false,
            add_path_ipv6: false,
            four_octet_as: true,
            extended_message: false,
            enhanced_refresh: false,
            route_refresh: false,
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
            mp_bgp_negotiated: false,
            negotiated_ipv4_unicast: true,
            negotiated_ipv6_unicast: false,
            negotiated_evpn: false,
            add_path_ipv4: false,
            add_path_ipv6: false,
            four_octet_as: true,
            extended_message: false,
            enhanced_refresh: false,
            route_refresh: false,
        };
        let (next, actions) = step(
            State::Established(remote),
            Event::KeepaliveReceived,
            &ctx(65002),
        );
        assert_eq!(next, Some(State::Established(remote)));
        assert_eq!(actions, []);
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

    /// RFC 4486 §4: Cease/Maximum Number of Prefixes Reached carries
    /// `AFI(2) SAFI(1) limit(4)` for the family that tripped.
    #[test]
    fn max_prefix_cease_data_per_family() {
        let data = |f| message::encode_max_prefix_data(afi_of(f), safi_of(f), 1000).to_vec();
        assert_eq!(data(AddressFamily::Ipv4Unicast), [0, 1, 1, 0, 0, 3, 0xe8]);
        assert_eq!(data(AddressFamily::Ipv6Unicast), [0, 2, 1, 0, 0, 3, 0xe8]);
        assert_eq!(data(AddressFamily::L2vpnEvpn), [0, 25, 70, 0, 0, 3, 0xe8]);
    }
}
