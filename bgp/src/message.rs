//! RFC 4271 BGP-4 wire message format: header, OPEN, KEEPALIVE, NOTIFICATION,
//! UPDATE, plus the RFC 6793 four-octet AS number capability, RFC 4760
//! Multiprotocol Extensions (`MP_REACH_NLRI`/`MP_UNREACH_NLRI`, IPv6 unicast),
//! and RFC 8950 Extended Next Hop Encoding (a session's transport family is
//! independent of which address family/families it carries). This is BGP's
//! own wire contract with external routers, not an inter-NOS-daemon IPC
//! contract, so it lives here rather than in `nos-proto` (whose `IpcCodec` is
//! postcard-based and structurally incompatible with BGP's raw big-endian
//! format anyway).
//!
//! IPv4 unicast keeps its legacy plain-NLRI wire encoding
//! (`UpdateMessage::{withdrawn_routes,nlri}` + `PathAttributes::next_hop`) as
//! a fallback for peers that never negotiate any Multiprotocol Extensions
//! capability at all; any other family (and, once a peer does negotiate
//! MP-BGP, IPv4 unicast too — see `crate::rib::build_advertisement`) goes
//! through `UpdateMessage::{mp_reach,mp_unreach}` instead. Decodes
//! `ORIGIN`/`AS_PATH`/`NEXT_HOP`/`LOCAL_PREF`/`MULTI_EXIT_DISC`/
//! `MP_REACH_NLRI`/`MP_UNREACH_NLRI` path attributes and skips any other attribute type by
//! its declared length (never an error — the same philosophy
//! `parse_optional_parameters` already applies to unknown OPEN capabilities),
//! and, for a peer that never sent the four-octet AS capability
//! (`BgpCodec::two_octet_as`), speaks RFC 6793's transition encoding: 2-byte
//! `AS_PATH` with `AS_TRANS` plus `AS4_PATH` on send, `AS4_PATH` merged back
//! in on receipt (no `AGGREGATOR` attribute exists here, so no
//! `AS4_AGGREGATOR`). Any other/unknown message type
//! still decodes as `BgpMessage::Unhandled` so the codec never chokes on one
//! arriving.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::warn;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use ipnet::{IpNet, Ipv4Net};
use tokio_util::codec::{Decoder, Encoder};

use crate::evpn::{self, EvpnNlri};

pub const BGP_VERSION: u8 = 4;
const MARKER: [u8; 16] = [0xFF; 16];
const HEADER_LEN: usize = 19;
const MAX_MESSAGE_LEN: usize = 4096;

/// RFC 6793 placeholder used in OPEN's 2-byte "My Autonomous System" field
/// whenever the real ASN doesn't fit in 2 bytes; the real value then travels
/// in the four-octet AS number capability instead.
pub const AS_TRANS: u16 = 23456;

const TYPE_OPEN: u8 = 1;
const TYPE_UPDATE: u8 = 2;
const TYPE_NOTIFICATION: u8 = 3;
const TYPE_KEEPALIVE: u8 = 4;
const TYPE_ROUTE_REFRESH: u8 = 5;

const OPT_PARAM_CAPABILITIES: u8 = 2;
const CAP_FOUR_OCTET_ASN: u8 = 65;
/// RFC 4760 §8 Multiprotocol Extensions capability: `AFI(2) reserved(1)
/// SAFI(1)`.
const CAP_MULTIPROTOCOL: u8 = 1;
/// RFC 2918 §3 Route Refresh capability: no payload.
const CAP_ROUTE_REFRESH: u8 = 2;
/// RFC 8950 §3 Extended Next Hop Encoding capability: one or more `NLRI-AFI(2)
/// NLRI-SAFI(2) NextHop-AFI(2)` tuples — note the NLRI-SAFI field is 2 bytes
/// here, unlike `CAP_MULTIPROTOCOL`'s 1-byte SAFI.
const CAP_EXTENDED_NEXT_HOP: u8 = 5;
/// RFC 7911 §3 ADD-PATH capability: one or more `AFI(2) SAFI(1)
/// SendReceive(1)` tuples.
const CAP_ADD_PATH: u8 = 69;

/// AFI values this crate understands (RFC 4760's registry has many more).
pub(crate) const AFI_IPV4: u16 = 1;
pub(crate) const AFI_IPV6: u16 = 2;
/// RFC 7432 EVPN: AFI L2VPN (25) / SAFI EVPN (70).
pub(crate) const AFI_L2VPN: u16 = 25;
pub(crate) const SAFI_EVPN: u8 = 70;

const ATTR_ORIGIN: u8 = 1;
const ATTR_AS_PATH: u8 = 2;
const ATTR_NEXT_HOP: u8 = 3;
const ATTR_MULTI_EXIT_DISC: u8 = 4;
const ATTR_LOCAL_PREF: u8 = 5;
const ATTR_ATOMIC_AGGREGATE: u8 = 6;
const ATTR_AGGREGATOR: u8 = 7;
const ATTR_ORIGINATOR_ID: u8 = 9;
const ATTR_CLUSTER_LIST: u8 = 10;
const ATTR_MP_REACH_NLRI: u8 = 14;
const ATTR_MP_UNREACH_NLRI: u8 = 15;
/// RFC 1997 §3 standard community — a list of 4-byte values.
const ATTR_COMMUNITY: u8 = 8;
/// RFC 4360 §3 extended community — a list of 8-byte (type/subtype/value)
/// values.
const ATTR_EXTENDED_COMMUNITIES: u8 = 16;
/// RFC 8092 §3 large community — a list of 12-byte (3×u32) values.
const ATTR_LARGE_COMMUNITY: u8 = 32;
const ATTR_PMSI_TUNNEL: u8 = 22;
/// RFC 6793 §3: the real 4-byte path, carried beside a 2-byte `AS_PATH` to/from
/// a peer that never negotiated the four-octet AS capability.
const ATTR_AS4_PATH: u8 = 17;
/// RFC 6793 §3: the real 4-byte `AGGREGATOR`, beside a 2-byte one holding `AS_TRANS`.
const ATTR_AS4_AGGREGATOR: u8 = 18;
/// RFC 4271 §4.3 attribute flag bit indicating a 2-byte (rather than 1-byte)
/// attribute length field follows the type byte.
const ATTR_FLAG_EXTENDED_LENGTH: u8 = 0x10;
/// Well-known transitive, per RFC 4271 §5 — the flag value this
/// implementation always encodes for `ORIGIN`/`AS_PATH`/`NEXT_HOP`/`LOCAL_PREF`.
const ATTR_FLAG_WELL_KNOWN_TRANSITIVE: u8 = 0x40;
/// Optional non-transitive, per RFC 4760 §3 — `MP_REACH_NLRI`/
/// `MP_UNREACH_NLRI`'s own flag value (unlike the four well-known attributes
/// above).
const ATTR_FLAG_OPTIONAL_NON_TRANSITIVE: u8 = 0x80;
/// Optional transitive, per RFC 1997/4360/8092 §3 — all three community
/// attribute types' own flag value.
const ATTR_FLAG_OPTIONAL_TRANSITIVE: u8 = 0xC0;
const AS_PATH_SEGMENT_SEQUENCE: u8 = 2;
/// `AS_PATH` segments are encoded as `count: u8`, so a single segment can carry
/// at most this many ASNs before it must be split into another segment.
const MAX_AS_PATH_SEGMENT_LEN: usize = 255;

/// Structural decode failures — the type byte itself is never rejected here
/// (an unknown type decodes as `BgpMessage::Unhandled`), only malformed
/// headers/bodies for the types this crate actually understands.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("bgp message marker is not all-ones")]
    BadMarker,
    #[error("bgp message length {0} out of the 19..=4096 range")]
    BadLength(u16),
    #[error("bgp message body shorter than its declared field lengths")]
    Truncated,
    #[error("malformed OPEN message body")]
    MalformedOpen,
    #[error("malformed NOTIFICATION message body")]
    MalformedNotification,
    #[error("malformed UPDATE message body")]
    MalformedUpdate,
    #[error("malformed ROUTE-REFRESH message body")]
    MalformedRouteRefresh,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// RFC 4271 §6 error codes, used in NOTIFICATION's `error_code` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    MessageHeader = 1,
    OpenMessage = 2,
    UpdateMessage = 3,
    HoldTimerExpired = 4,
    FiniteStateMachine = 5,
    Cease = 6,
}

/// RFC 4271 §6.1 Message Header Error subcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageHeaderSubcode {
    ConnectionNotSynchronized = 1,
    BadMessageLength = 2,
    #[allow(dead_code)]
    // reserved for a future "reject unrecognized type" policy — see fsm.rs's Unhandled handling
    BadMessageType = 3,
}

/// RFC 4271 §6.2 OPEN Message Error subcodes (subcode 5, Authentication
/// Failure, is deprecated by RFC 4271 itself and omitted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMessageSubcode {
    UnsupportedVersionNumber = 1,
    BadPeerAs = 2,
    BadBgpIdentifier = 3,
    #[allow(dead_code)] // no optional parameters besides Capabilities are rejected yet
    UnsupportedOptionalParameter = 4,
    UnacceptableHoldTime = 6,
}

/// RFC 4271 §6.3 UPDATE Message Error subcodes (only the one this crate's
/// parser can actually produce is modeled; the rest of the RFC 4271 table —
/// missing/invalid individual well-known attributes, invalid `NEXT_HOP`, etc.
/// — isn't distinguished from a generic malformed attribute list).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateMessageSubcode {
    MalformedAttributeList = 1,
}

/// RFC 6608 Finite State Machine Error subcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsmSubcode {
    UnexpectedInOpenSent = 1,
    UnexpectedInOpenConfirm = 2,
    UnexpectedInEstablished = 3,
}

/// RFC 4486 Cease subcodes actually used by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeaseSubcode {
    #[allow(dead_code)] // generic fallback, not yet triggered by any code path
    Other = 0,
    AdministrativeShutdown = 2,
    ConnectionCollisionResolution = 7,
}

/// One OPEN capability this crate understands. An unrecognized capability
/// code (or one with an unexpected length) is silently dropped on decode,
/// same skip-by-length philosophy as an unknown path attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// RFC 6793 code 65.
    FourOctetAsn(u32),
    /// RFC 4760 code 1: this session can carry `afi`/`safi` NLRI.
    MultiProtocol { afi: u16, safi: u8 },
    /// RFC 8950 code 5: `nlri_afi`/`nlri_safi` NLRI may be advertised with a
    /// `nh_afi`-family next-hop (the cross-family case — same-family next-hop
    /// never needs this capability at all).
    ExtendedNextHop {
        nlri_afi: u16,
        nlri_safi: u16,
        nh_afi: u16,
    },
    /// RFC 2918 code 2: this session accepts `ROUTE_REFRESH` messages.
    RouteRefresh,
    /// RFC 7911 code 69: one or more AFI/SAFI ADD-PATH grants.
    AddPath(Vec<AddPathTuple>),
}

/// One RFC 7911 ADD-PATH grant: `afi`/`safi` NLRI may carry a 4-byte Path
/// Identifier, in the direction(s) `send_receive` names (1 = receive, 2 =
/// send, 3 = both — "send"/"receive" from the *advertiser's* perspective).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddPathTuple {
    pub afi: u16,
    pub safi: u8,
    pub send_receive: u8,
}

/// An OPEN message. See [`Capability`] for the capabilities this crate
/// builds/understands; `four_octet_asn`/`effective_remote_asn` read the
/// four-octet-ASN one back out regardless of which form the plain `my_as`
/// field arrived in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenMessage {
    pub version: u8,
    pub my_as: u16,
    pub hold_time: u16,
    pub bgp_identifier: Ipv4Addr,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationMessage {
    pub error_code: u8,
    pub error_subcode: u8,
    pub data: Bytes,
}

/// RFC 2918 `ROUTE_REFRESH`: `AFI(2) reserved(1) SAFI(1)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteRefreshMessage {
    pub afi: u16,
    pub safi: u8,
}

/// RFC 4271 §4.3 `ORIGIN` path attribute values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Igp = 0,
    Egp = 1,
    Incomplete = 2,
}

/// The legacy IPv4-unicast path attributes. `local_pref` is `Some` iff the
/// wire message actually carried a `LOCAL_PREF` attribute — this crate never
/// invents one on decode (`rib.rs` applies the RFC 4271 §5.1.5 default only
/// when propagating, not here). `next_hop` is only meaningful (and only ever
/// encoded) when the legacy `UpdateMessage::nlri` field is non-empty —
/// `ORIGIN`/`AS_PATH`/`LOCAL_PREF` are shared with any `mp_reach`/`mp_unreach`
/// batches in the same UPDATE (RFC 4760: only the next-hop moves into
/// `MP_REACH_NLRI` itself, everything else stays a regular path attribute).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathAttributes {
    pub origin: Origin,
    /// Flattened `AS_SEQUENCE`(s), nearest hop first — `AS_SET` vs.
    /// `AS_SEQUENCE` segmentation is not preserved (documented simplification).
    pub as_path: Vec<u32>,
    pub next_hop: Ipv4Addr,
    pub local_pref: Option<u32>,
    /// `Some` iff the wire message carried `MULTI_EXIT_DISC` (RFC 4271
    /// §5.1.4) — this crate never invents one, same convention as
    /// `local_pref`.
    pub med: Option<u32>,
    /// RFC 4456 §5 `ORIGINATOR_ID` — set by the first route reflector to
    /// reflect this route, never overwritten by a later one. `Some` iff the
    /// wire message actually carried it.
    pub originator_id: Option<Ipv4Addr>,
    /// RFC 4456 §5 `CLUSTER_LIST` — one cluster-id prepended by each route
    /// reflector in the path, nearest first. Empty iff the wire message
    /// carried no `CLUSTER_LIST` at all (never reflected, or a reflector
    /// omitting it purely because a route with no prior list needed one).
    pub cluster_list: Vec<Ipv4Addr>,
    /// RFC 1997 `COMMUNITY` — each value packed `(AA << 16) | NN`. Empty iff
    /// the wire message carried no `COMMUNITY` attribute.
    pub communities: Vec<u32>,
    /// RFC 4360 `EXTENDED_COMMUNITIES` — each value is its 8 raw wire bytes
    /// read as one big-endian `u64` (type octet in the high byte). Empty iff
    /// the wire message carried no `EXTENDED_COMMUNITIES` attribute.
    pub extended_communities: Vec<u64>,
    /// RFC 8092 `LARGE_COMMUNITY` — global administrator, local data 1,
    /// local data 2. Empty iff the wire message carried no `LARGE_COMMUNITY`
    /// attribute.
    pub large_communities: Vec<(u32, u32, u32)>,
    /// RFC 6514 §5 PMSI Tunnel — carried on EVPN Type-3 routes (RFC 8365
    /// §8.2.1), which is where the VNI of an inclusive multicast route lives.
    pub pmsi: Option<Pmsi>,
    /// RFC 4271 §5.1.6 `ATOMIC_AGGREGATE` — only ever preserved in transit.
    pub atomic_aggregate: bool,
    /// RFC 4271 §5.1.7 `AGGREGATOR` (`AS4_AGGREGATOR` merged in, RFC 6793).
    pub aggregator: Option<Aggregator>,
}

/// The AS and router-id of the speaker that formed an aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aggregator {
    pub asn: u32,
    pub router_id: Ipv4Addr,
}

/// An ingress-replication (tunnel type 6) PMSI Tunnel attribute, the only
/// kind EVPN/VXLAN uses: `vni` fills the label field, `tunnel_ip` is the VTEP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pmsi {
    pub vni: u32,
    pub tunnel_ip: IpAddr,
}

/// RFC 4760 `MP_REACH_NLRI`: one AFI/SAFI batch of announced routes sharing
/// one next-hop. `next_hop`'s family need not match `nlri`'s own family (RFC
/// 8950 cross-family next-hop) — that's purely a wire-level fact here; which
/// combinations are actually negotiated/allowed is `fsm.rs`'s job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpReachNlri {
    pub afi: u16,
    pub safi: u8,
    pub next_hop: IpAddr,
    pub nlri: Vec<IpNet>,
    /// RFC 7911 ADD-PATH identifiers, aligned by index with `nlri`. Empty
    /// unless this AFI negotiated ADD-PATH on this session — never
    /// partially filled.
    pub nlri_path_ids: Vec<u32>,
    /// AFI 25 / SAFI 70 routes; `nlri` is empty for such a batch.
    pub evpn: Vec<EvpnNlri>,
}

/// RFC 4760 `MP_UNREACH_NLRI`: one AFI/SAFI batch of withdrawn routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpUnreachNlri {
    pub afi: u16,
    pub safi: u8,
    pub withdrawn: Vec<IpNet>,
    /// RFC 7911 ADD-PATH identifiers, aligned by index with `withdrawn`.
    /// Empty unless this AFI negotiated ADD-PATH on this session.
    pub withdrawn_path_ids: Vec<u32>,
    /// AFI 25 / SAFI 70 routes; `withdrawn` is empty for such a batch.
    pub evpn: Vec<EvpnNlri>,
}

/// An RFC 4271 UPDATE message. `withdrawn_routes`/`nlri`/`attributes.next_hop`
/// are the legacy IPv4-unicast-only fields (RFC 4271's base NLRI);
/// `mp_reach`/`mp_unreach` carry everything else, and — once a peer
/// negotiates MP-BGP at all — IPv4 unicast too (see
/// `crate::rib::build_advertisement`). `attributes` is `Some` iff `nlri` or
/// `mp_reach` is non-empty — a pure withdrawal carries no path attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateMessage {
    pub withdrawn_routes: Vec<Ipv4Net>,
    /// RFC 7911 ADD-PATH identifiers, aligned by index with
    /// `withdrawn_routes`. Empty unless IPv4 unicast negotiated ADD-PATH on
    /// this session.
    pub withdrawn_path_ids: Vec<u32>,
    pub nlri: Vec<Ipv4Net>,
    /// RFC 7911 ADD-PATH identifiers, aligned by index with `nlri`. Empty
    /// unless IPv4 unicast negotiated ADD-PATH on this session.
    pub nlri_path_ids: Vec<u32>,
    pub attributes: Option<PathAttributes>,
    pub mp_reach: Vec<MpReachNlri>,
    pub mp_unreach: Vec<MpUnreachNlri>,
}

/// A decoded BGP message.
// ponytail: `Update`'s `PathAttributes` (now carrying 3 community `Vec`s)
// outsizes the other variants; boxing it would touch every construction
// site for a one-off-per-message decode, not a hot repeated allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum BgpMessage {
    Open(OpenMessage),
    Update(UpdateMessage),
    Keepalive,
    Notification(NotificationMessage),
    RouteRefresh(RouteRefreshMessage),
    /// Any message type this crate doesn't parse a body for (unknown to this
    /// implementation).
    Unhandled {
        message_type: u8,
        body: Bytes,
    },
}

/// Builds this instance's own OPEN, carrying only the four-octet AS number
/// capability — callers (`fsm.rs`) push any `MultiProtocol`/
/// `ExtendedNextHop` capabilities this peer's session needs onto
/// `capabilities` afterward, since that depends on peer-group config this
/// module has no business knowing about. Always populated once
/// 4-octet-capable, regardless of whether `my_as` needed `AS_TRANS` — RFC
/// 6793 §4.1 recommends always advertising the capability, since it also
/// governs how the peer's OPEN is interpreted, not just how this one is
/// represented.
pub fn build_open(local_asn: u32, router_id: Ipv4Addr, hold_time: u16) -> OpenMessage {
    let my_as = u16::try_from(local_asn).unwrap_or(AS_TRANS);
    OpenMessage {
        version: BGP_VERSION,
        my_as,
        hold_time,
        bgp_identifier: router_id,
        capabilities: vec![Capability::FourOctetAsn(local_asn)],
    }
}

/// The four-octet ASN carried in `open`'s capabilities, if any.
pub fn four_octet_asn(open: &OpenMessage) -> Option<u32> {
    open.capabilities.iter().find_map(|c| match c {
        Capability::FourOctetAsn(asn) => Some(*asn),
        _ => None,
    })
}

/// The peer's real ASN, whether carried in the plain 2-byte field or (when
/// present) the four-octet AS number capability — falling back to the plain
/// field is what gives interop with peers that never send capability 65.
pub fn effective_remote_asn(open: &OpenMessage) -> u32 {
    four_octet_asn(open).unwrap_or(u32::from(open.my_as))
}

/// Rejects the well-known non-unicast special cases; anything else is
/// accepted (no check against one specific expected identifier).
pub fn is_valid_bgp_identifier(id: Ipv4Addr) -> bool {
    !id.is_unspecified() && !id.is_broadcast() && !id.is_multicast()
}

/// `add_path_afis` is empty by default (identical wire behavior to before
/// RFC 7911 support existed) and is set once, right after this session
/// reaches `Established` and negotiation is known — see
/// `fsm::run`'s `Action::ReportEstablished` handling. Only ever non-empty
/// for a `route_server_client` peer-group (see `bgp/CLAUDE.md`'s "Route
/// reflection and route server" section for why ADD-PATH isn't advertised
/// unconditionally like this crate's other capabilities).
#[derive(Debug, Clone, Default)]
pub struct BgpCodec {
    pub add_path_afis: HashSet<u16>,
    /// True once the peer's OPEN lacked the four-octet AS capability (RFC 6793
    /// §4.2): `AS_PATH` is then 2-byte in both directions, with `AS4_PATH`
    /// carrying the real path. Set at the same point as `add_path_afis`.
    pub two_octet_as: bool,
}

impl Decoder for BgpCodec {
    type Item = BgpMessage;
    type Error = WireError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BgpMessage>, WireError> {
        if src.len() < HEADER_LEN {
            return Ok(None);
        }
        if src[..16] != MARKER {
            return Err(WireError::BadMarker);
        }
        let length = u16::from_be_bytes([src[16], src[17]]);
        if (length as usize) < HEADER_LEN || (length as usize) > MAX_MESSAGE_LEN {
            return Err(WireError::BadLength(length));
        }
        if src.len() < length as usize {
            src.reserve(length as usize - src.len());
            return Ok(None);
        }
        let message_type = src[18];

        let mut frame = src.split_to(length as usize);
        frame.advance(HEADER_LEN);
        let body = frame;

        let message = match message_type {
            TYPE_OPEN => BgpMessage::Open(parse_open(&body)?),
            TYPE_UPDATE => {
                BgpMessage::Update(parse_update(&body, &self.add_path_afis, self.two_octet_as)?)
            }
            TYPE_KEEPALIVE => {
                if !body.is_empty() {
                    return Err(WireError::BadLength(length));
                }
                BgpMessage::Keepalive
            }
            TYPE_NOTIFICATION => BgpMessage::Notification(parse_notification(&body)?),
            TYPE_ROUTE_REFRESH => BgpMessage::RouteRefresh(parse_route_refresh(&body)?),
            other => BgpMessage::Unhandled {
                message_type: other,
                body: body.freeze(),
            },
        };
        Ok(Some(message))
    }
}

impl Encoder<BgpMessage> for BgpCodec {
    type Error = WireError;

    fn encode(&mut self, item: BgpMessage, dst: &mut BytesMut) -> Result<(), WireError> {
        let (message_type, body) = match item {
            BgpMessage::Open(open) => (TYPE_OPEN, encode_open(&open)),
            BgpMessage::Update(update) => (TYPE_UPDATE, encode_update(&update, self.two_octet_as)),
            BgpMessage::Keepalive => (TYPE_KEEPALIVE, Vec::new()),
            BgpMessage::Notification(n) => (TYPE_NOTIFICATION, encode_notification(&n)),
            BgpMessage::RouteRefresh(rr) => (TYPE_ROUTE_REFRESH, encode_route_refresh(rr)),
            BgpMessage::Unhandled { message_type, body } => (message_type, body.to_vec()),
        };
        let total_len = HEADER_LEN + body.len();
        let total_len = u16::try_from(total_len).map_err(|_| WireError::BadLength(u16::MAX))?;
        dst.reserve(total_len as usize);
        dst.put_slice(&MARKER);
        dst.put_u16(total_len);
        dst.put_u8(message_type);
        dst.put_slice(&body);
        Ok(())
    }
}

fn parse_open(body: &[u8]) -> Result<OpenMessage, WireError> {
    // version(1) + my_as(2) + hold_time(2) + bgp_identifier(4) + opt_param_len(1)
    if body.len() < 10 {
        return Err(WireError::MalformedOpen);
    }
    let version = body[0];
    let my_as = u16::from_be_bytes([body[1], body[2]]);
    let hold_time = u16::from_be_bytes([body[3], body[4]]);
    let bgp_identifier = Ipv4Addr::new(body[5], body[6], body[7], body[8]);
    let opt_param_len = body[9] as usize;
    let opt_params = &body[10..];
    if opt_params.len() < opt_param_len {
        return Err(WireError::Truncated);
    }
    let capabilities = parse_optional_parameters(&opt_params[..opt_param_len])?;

    Ok(OpenMessage {
        version,
        my_as,
        hold_time,
        bgp_identifier,
        capabilities,
    })
}

/// Walks every optional parameter, skipping each by its own declared length
/// (so a capability after an unrecognized parameter is still found),
/// collecting every capability from every Capabilities optional parameter
/// encountered (RFC 5492 allows more than one, though this crate always
/// encodes just one).
fn parse_optional_parameters(mut params: &[u8]) -> Result<Vec<Capability>, WireError> {
    let mut capabilities = Vec::new();
    while !params.is_empty() {
        if params.len() < 2 {
            return Err(WireError::Truncated);
        }
        let param_type = params[0];
        let param_len = params[1] as usize;
        if params.len() < 2 + param_len {
            return Err(WireError::Truncated);
        }
        let param_value = &params[2..2 + param_len];
        if param_type == OPT_PARAM_CAPABILITIES {
            capabilities.extend(parse_capabilities(param_value)?);
        }
        params = &params[2 + param_len..];
    }
    Ok(capabilities)
}

fn parse_capabilities(mut data: &[u8]) -> Result<Vec<Capability>, WireError> {
    let mut capabilities = Vec::new();
    while !data.is_empty() {
        if data.len() < 2 {
            return Err(WireError::Truncated);
        }
        let cap_code = data[0];
        let cap_len = data[1] as usize;
        if data.len() < 2 + cap_len {
            return Err(WireError::Truncated);
        }
        let cap_value = &data[2..2 + cap_len];
        match cap_code {
            CAP_FOUR_OCTET_ASN if cap_len == 4 => {
                capabilities.push(Capability::FourOctetAsn(u32::from_be_bytes(
                    cap_value.try_into().unwrap(),
                )));
            }
            CAP_MULTIPROTOCOL if cap_len == 4 => {
                let afi = u16::from_be_bytes([cap_value[0], cap_value[1]]);
                let safi = cap_value[3];
                capabilities.push(Capability::MultiProtocol { afi, safi });
            }
            CAP_ROUTE_REFRESH if cap_len == 0 => {
                capabilities.push(Capability::RouteRefresh);
            }
            CAP_EXTENDED_NEXT_HOP if cap_len.is_multiple_of(6) => {
                for tuple in cap_value.as_chunks::<6>().0 {
                    capabilities.push(Capability::ExtendedNextHop {
                        nlri_afi: u16::from_be_bytes([tuple[0], tuple[1]]),
                        nlri_safi: u16::from_be_bytes([tuple[2], tuple[3]]),
                        nh_afi: u16::from_be_bytes([tuple[4], tuple[5]]),
                    });
                }
            }
            CAP_ADD_PATH if cap_len.is_multiple_of(4) => {
                let tuples = cap_value
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|tuple| AddPathTuple {
                        afi: u16::from_be_bytes([tuple[0], tuple[1]]),
                        safi: tuple[2],
                        send_receive: tuple[3],
                    })
                    .collect();
                capabilities.push(Capability::AddPath(tuples));
            }
            // Unknown capability code, or a known one with an unexpected
            // length: skip by declared length, never an error.
            _ => {}
        }
        data = &data[2 + cap_len..];
    }
    Ok(capabilities)
}

fn parse_notification(body: &[u8]) -> Result<NotificationMessage, WireError> {
    if body.len() < 2 {
        return Err(WireError::MalformedNotification);
    }
    Ok(NotificationMessage {
        error_code: body[0],
        error_subcode: body[1],
        data: Bytes::copy_from_slice(&body[2..]),
    })
}

fn parse_route_refresh(body: &[u8]) -> Result<RouteRefreshMessage, WireError> {
    if body.len() < 4 {
        return Err(WireError::MalformedRouteRefresh);
    }
    Ok(RouteRefreshMessage {
        afi: u16::from_be_bytes([body[0], body[1]]),
        // body[2] is the reserved octet.
        safi: body[3],
    })
}

fn encode_route_refresh(rr: RouteRefreshMessage) -> Vec<u8> {
    let mut body = Vec::with_capacity(4);
    body.extend_from_slice(&rr.afi.to_be_bytes());
    body.push(0); // reserved
    body.push(rr.safi);
    body
}

fn encode_open(open: &OpenMessage) -> Vec<u8> {
    let mut cap_bytes = Vec::new();
    for cap in &open.capabilities {
        match cap {
            Capability::FourOctetAsn(asn) => {
                cap_bytes.push(CAP_FOUR_OCTET_ASN);
                cap_bytes.push(4);
                cap_bytes.extend_from_slice(&asn.to_be_bytes());
            }
            Capability::MultiProtocol { afi, safi } => {
                cap_bytes.push(CAP_MULTIPROTOCOL);
                cap_bytes.push(4);
                cap_bytes.extend_from_slice(&afi.to_be_bytes());
                cap_bytes.push(0); // reserved
                cap_bytes.push(*safi);
            }
            Capability::ExtendedNextHop {
                nlri_afi,
                nlri_safi,
                nh_afi,
            } => {
                cap_bytes.push(CAP_EXTENDED_NEXT_HOP);
                cap_bytes.push(6);
                cap_bytes.extend_from_slice(&nlri_afi.to_be_bytes());
                cap_bytes.extend_from_slice(&nlri_safi.to_be_bytes());
                cap_bytes.extend_from_slice(&nh_afi.to_be_bytes());
            }
            Capability::RouteRefresh => {
                cap_bytes.push(CAP_ROUTE_REFRESH);
                cap_bytes.push(0);
            }
            Capability::AddPath(tuples) => {
                cap_bytes.push(CAP_ADD_PATH);
                cap_bytes.push(
                    u8::try_from(tuples.len() * 4)
                        .expect("this NOS's small, fixed capability set always fits in a u8"),
                );
                for tuple in tuples {
                    cap_bytes.extend_from_slice(&tuple.afi.to_be_bytes());
                    cap_bytes.push(tuple.safi);
                    cap_bytes.push(tuple.send_receive);
                }
            }
        }
    }

    let mut opt_params = Vec::new();
    if !cap_bytes.is_empty() {
        opt_params.push(OPT_PARAM_CAPABILITIES);
        opt_params.push(
            u8::try_from(cap_bytes.len())
                .expect("this NOS's small, fixed capability set always fits in a u8"),
        );
        opt_params.extend_from_slice(&cap_bytes);
    }

    let mut body = Vec::with_capacity(10 + opt_params.len());
    body.push(open.version);
    body.extend_from_slice(&open.my_as.to_be_bytes());
    body.extend_from_slice(&open.hold_time.to_be_bytes());
    body.extend_from_slice(&open.bgp_identifier.octets());
    body.push(
        u8::try_from(opt_params.len())
            .expect("this NOS's small, fixed capability set always fits in a u8"),
    );
    body.extend_from_slice(&opt_params);
    body
}

fn encode_notification(n: &NotificationMessage) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + n.data.len());
    body.push(n.error_code);
    body.push(n.error_subcode);
    body.extend_from_slice(&n.data);
    body
}

/// RFC 4271 §4.3 prefix bit-packing: `prefix_len` (1 byte) followed by the
/// minimum number of whole octets needed to hold that many bits of the
/// address, zero-padded — optionally preceded by a 4-byte RFC 7911 ADD-PATH
/// Path Identifier when `with_ids` is set. Decodes a list that continues
/// until the byte slice is exhausted (both withdrawn-routes and NLRI use
/// this same encoding, with no count field of their own — the caller
/// already knows where the list ends). `afi` picks the address width (4
/// bytes for `AFI_IPV4`, 16 for `AFI_IPV6`) and the resulting prefix-length
/// cap (32/128); any other AFI is `MalformedUpdate` — this crate only
/// understands unicast IPv4/IPv6. Returns the path ids alongside the
/// prefixes, aligned by index — empty when `with_ids` is false.
fn decode_prefixes(
    afi: u16,
    mut data: &[u8],
    with_ids: bool,
) -> Result<(Vec<IpNet>, Vec<u32>), WireError> {
    let addr_bytes: usize = match afi {
        AFI_IPV4 => 4,
        AFI_IPV6 => 16,
        _ => return Err(WireError::MalformedUpdate),
    };
    let max_prefix_len = u8::try_from(addr_bytes * 8).unwrap();

    let mut prefixes = Vec::new();
    let mut path_ids = Vec::new();
    while !data.is_empty() {
        let path_id = if with_ids {
            if data.len() < 4 {
                return Err(WireError::MalformedUpdate);
            }
            let id = u32::from_be_bytes(data[..4].try_into().unwrap());
            data = &data[4..];
            id
        } else {
            0
        };
        if data.is_empty() {
            return Err(WireError::MalformedUpdate);
        }
        let prefix_len = data[0];
        if prefix_len > max_prefix_len {
            return Err(WireError::MalformedUpdate);
        }
        let byte_len = usize::from(prefix_len).div_ceil(8);
        if data.len() < 1 + byte_len {
            return Err(WireError::MalformedUpdate);
        }
        let mut octets = [0u8; 16];
        octets[..byte_len].copy_from_slice(&data[1..=byte_len]);
        let addr: IpAddr = if addr_bytes == 4 {
            Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]).into()
        } else {
            Ipv6Addr::from(octets).into()
        };
        let net = IpNet::new(addr, prefix_len).map_err(|_| WireError::MalformedUpdate)?;
        prefixes.push(net);
        if with_ids {
            path_ids.push(path_id);
        }
        data = &data[1 + byte_len..];
    }
    Ok((prefixes, path_ids))
}

fn encode_prefix(net: IpNet, path_id: Option<u32>, out: &mut Vec<u8>) {
    if let Some(id) = path_id {
        out.extend_from_slice(&id.to_be_bytes());
    }
    let prefix_len = net.prefix_len();
    let byte_len = usize::from(prefix_len).div_ceil(8);
    out.push(prefix_len);
    match net.addr() {
        IpAddr::V4(a) => out.extend_from_slice(&a.octets()[..byte_len]),
        IpAddr::V6(a) => out.extend_from_slice(&a.octets()[..byte_len]),
    }
}

/// Encodes `nets`, attaching each corresponding entry of `path_ids` (must be
/// either empty — no ADD-PATH — or exactly `nets.len()` long) as a leading
/// Path Identifier per prefix.
fn encode_prefixes(nets: &[IpNet], path_ids: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, net) in nets.iter().enumerate() {
        encode_prefix(*net, path_ids.get(i).copied(), &mut out);
    }
    out
}

/// `decode_prefixes(AFI_IPV4, ...)` narrowed back to `Ipv4Net`, for the
/// legacy withdrawn-routes/NLRI fields — `decode_prefixes` with `afi ==
/// AFI_IPV4` only ever constructs `IpNet::V4`, so the `V6` arm is
/// unreachable.
fn decode_prefixes_v4(data: &[u8], with_ids: bool) -> Result<(Vec<Ipv4Net>, Vec<u32>), WireError> {
    let (nets, path_ids) = decode_prefixes(AFI_IPV4, data, with_ids)?;
    let nets = nets
        .into_iter()
        .map(|net| match net {
            IpNet::V4(n) => Ok(n),
            IpNet::V6(_) => Err(WireError::MalformedUpdate),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((nets, path_ids))
}

fn encode_prefixes_v4(nets: &[Ipv4Net], path_ids: &[u32]) -> Vec<u8> {
    let nets: Vec<IpNet> = nets.iter().copied().map(IpNet::V4).collect();
    encode_prefixes(&nets, path_ids)
}

/// Everything `parse_path_attributes` extracts from one UPDATE's attribute
/// list. The four legacy fields are each `Some`/non-empty only if the
/// message actually carried that attribute — callers decide mandatory-
/// attribute enforcement, since that depends on whether the UPDATE carries
/// any NLRI (legacy or `mp_reach`) at all.
struct ParsedAttributes {
    origin: Option<Origin>,
    as_path: Option<Vec<u32>>,
    next_hop: Option<Ipv4Addr>,
    local_pref: Option<u32>,
    med: Option<u32>,
    originator_id: Option<Ipv4Addr>,
    cluster_list: Vec<Ipv4Addr>,
    communities: Vec<u32>,
    extended_communities: Vec<u64>,
    large_communities: Vec<(u32, u32, u32)>,
    pmsi: Option<Pmsi>,
    atomic_aggregate: bool,
    aggregator: Option<Aggregator>,
    mp_reach: Vec<MpReachNlri>,
    mp_unreach: Vec<MpUnreachNlri>,
    /// RFC 7606 treat-as-withdraw: an attribute's content was malformed.
    withdraw: bool,
}

/// Walks the TLV path-attribute list, decoding `ORIGIN`/`AS_PATH`/`NEXT_HOP`/
/// `LOCAL_PREF`/`MULTI_EXIT_DISC`/`ORIGINATOR_ID`/`CLUSTER_LIST`/
/// `COMMUNITY`/`EXTENDED_COMMUNITIES`/`LARGE_COMMUNITY`/`MP_REACH_NLRI`/
/// `MP_UNREACH_NLRI` and skipping anything else by its own declared length
/// (mirrors `parse_optional_parameters`'s handling of unknown OPEN
/// capabilities). `add_path_afis` is threaded down into
/// `MP_REACH_NLRI`/`MP_UNREACH_NLRI` decoding. With `two_octet_as`, `AS_PATH`
/// is read as 2-byte and merged with `AS4_PATH` per RFC 6793 §4.2.3; without
/// it a stray `AS4_PATH` is ignored.
fn parse_path_attributes(
    mut data: &[u8],
    add_path_afis: &HashSet<u16>,
    two_octet_as: bool,
) -> Result<ParsedAttributes, WireError> {
    let mut origin = None;
    let mut as_path: Option<Vec<u32>> = None;
    let mut as4_path = None;
    let mut next_hop = None;
    let mut local_pref = None;
    let mut med = None;
    let mut originator_id = None;
    let mut cluster_list = Vec::new();
    let mut communities = Vec::new();
    let mut extended_communities = Vec::new();
    let mut large_communities = Vec::new();
    let mut pmsi = None;
    let mut atomic_aggregate = false;
    let mut aggregator: Option<Aggregator> = None;
    let mut as4_aggregator = None;
    let mut mp_reach = Vec::new();
    let mut mp_unreach = Vec::new();
    // RFC 7606 treat-as-withdraw: set by any attribute whose *content* is
    // malformed. Framing errors (below, outside `'attr`) still reset.
    let mut withdraw = false;

    while !data.is_empty() {
        if data.len() < 2 {
            return Err(WireError::MalformedUpdate);
        }
        let flags = data[0];
        let attr_type = data[1];
        let (len, header_len) = if flags & ATTR_FLAG_EXTENDED_LENGTH != 0 {
            if data.len() < 4 {
                return Err(WireError::MalformedUpdate);
            }
            (usize::from(u16::from_be_bytes([data[2], data[3]])), 4)
        } else {
            if data.len() < 3 {
                return Err(WireError::MalformedUpdate);
            }
            (usize::from(data[2]), 3)
        };
        if data.len() < header_len + len {
            return Err(WireError::MalformedUpdate);
        }
        let value = &data[header_len..header_len + len];

        'attr: {
            match attr_type {
                ATTR_ORIGIN => {
                    if value.len() != 1 {
                        withdraw = true;
                        break 'attr;
                    }
                    match value[0] {
                        0 => origin = Some(Origin::Igp),
                        1 => origin = Some(Origin::Egp),
                        2 => origin = Some(Origin::Incomplete),
                        _ => withdraw = true,
                    }
                }
                ATTR_AS_PATH => match parse_as_path(value, if two_octet_as { 2 } else { 4 }) {
                    Ok(p) => as_path = Some(p),
                    Err(_) => withdraw = true,
                },
                ATTR_AS4_PATH if two_octet_as => match parse_as_path(value, 4) {
                    Ok(p) => as4_path = Some(p),
                    Err(_) => withdraw = true,
                },
                ATTR_NEXT_HOP => {
                    if value.len() != 4 {
                        withdraw = true;
                        break 'attr;
                    }
                    next_hop = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
                }
                ATTR_LOCAL_PREF => {
                    if value.len() != 4 {
                        withdraw = true;
                        break 'attr;
                    }
                    local_pref = Some(u32::from_be_bytes(value.try_into().unwrap()));
                }
                ATTR_MULTI_EXIT_DISC => {
                    if value.len() != 4 {
                        withdraw = true;
                        break 'attr;
                    }
                    med = Some(u32::from_be_bytes(value.try_into().unwrap()));
                }
                ATTR_ORIGINATOR_ID => {
                    if value.len() != 4 {
                        withdraw = true;
                        break 'attr;
                    }
                    originator_id = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
                }
                ATTR_CLUSTER_LIST => {
                    if !value.len().is_multiple_of(4) {
                        withdraw = true;
                        break 'attr;
                    }
                    cluster_list = value
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                        .collect();
                }
                ATTR_COMMUNITY => {
                    if !value.len().is_multiple_of(4) {
                        withdraw = true;
                        break 'attr;
                    }
                    communities = value
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|c| u32::from_be_bytes(*c))
                        .collect();
                }
                ATTR_EXTENDED_COMMUNITIES => {
                    if !value.len().is_multiple_of(8) {
                        withdraw = true;
                        break 'attr;
                    }
                    extended_communities = value
                        .as_chunks::<8>()
                        .0
                        .iter()
                        .map(|c| u64::from_be_bytes(*c))
                        .collect();
                }
                ATTR_LARGE_COMMUNITY => {
                    if !value.len().is_multiple_of(12) {
                        withdraw = true;
                        break 'attr;
                    }
                    large_communities = value
                        .as_chunks::<12>()
                        .0
                        .iter()
                        .map(|c| {
                            (
                                u32::from_be_bytes(c[0..4].try_into().unwrap()),
                                u32::from_be_bytes(c[4..8].try_into().unwrap()),
                                u32::from_be_bytes(c[8..12].try_into().unwrap()),
                            )
                        })
                        .collect();
                }
                // RFC 7606 §7.7/§7.8: a malformed one is discarded, not a withdraw.
                ATTR_ATOMIC_AGGREGATE => atomic_aggregate = value.is_empty(),
                ATTR_AGGREGATOR => {
                    aggregator = match (value.len(), two_octet_as) {
                        (6, true) => Some(Aggregator {
                            asn: u32::from(u16::from_be_bytes([value[0], value[1]])),
                            router_id: Ipv4Addr::new(value[2], value[3], value[4], value[5]),
                        }),
                        (8, false) => Some(Aggregator {
                            asn: u32::from_be_bytes(value[0..4].try_into().unwrap()),
                            router_id: Ipv4Addr::new(value[4], value[5], value[6], value[7]),
                        }),
                        _ => None,
                    }
                }
                ATTR_AS4_AGGREGATOR if two_octet_as && value.len() == 8 => {
                    as4_aggregator = Some(Aggregator {
                        asn: u32::from_be_bytes(value[0..4].try_into().unwrap()),
                        router_id: Ipv4Addr::new(value[4], value[5], value[6], value[7]),
                    });
                }
                ATTR_PMSI_TUNNEL => pmsi = decode_pmsi(value),
                ATTR_MP_REACH_NLRI => mp_reach.push(decode_mp_reach(value, add_path_afis)?),
                ATTR_MP_UNREACH_NLRI => mp_unreach.push(decode_mp_unreach(value, add_path_afis)?),
                _ => {
                    // Unknown attribute type: skip by declared length, never an
                    // error — same philosophy as unrecognized OPEN capabilities.
                }
            }
        }

        data = &data[header_len + len..];
    }

    // RFC 6793 §4.2.3: the trailing `as4.len()` entries of the 2-byte path are
    // replaced by AS4_PATH; a longer AS4_PATH is malformed and ignored.
    if let (Some(path), Some(as4)) = (as_path.as_mut(), as4_path) {
        if as4.len() <= path.len() {
            path.truncate(path.len() - as4.len());
            path.extend(as4);
        }
    }

    // RFC 6793 §4.2.3: AS4_AGGREGATOR replaces an AGGREGATOR holding AS_TRANS.
    if let (Some(agg), Some(as4)) = (aggregator.as_mut(), as4_aggregator) {
        if agg.asn == u32::from(AS_TRANS) {
            *agg = as4;
        }
    }

    Ok(ParsedAttributes {
        origin,
        as_path,
        next_hop,
        local_pref,
        med,
        originator_id,
        cluster_list,
        communities,
        extended_communities,
        large_communities,
        pmsi,
        atomic_aggregate,
        aggregator,
        mp_reach,
        mp_unreach,
        withdraw,
    })
}

/// `flags(1) type(1) label(3) tunnel-id`; anything but ingress replication
/// (type 6) with a 4/16-byte tunnel id is ignored, never an error — the
/// attribute is optional and only EVPN Type-3 consumers look at it.
fn decode_pmsi(value: &[u8]) -> Option<Pmsi> {
    if value.len() < 5 || value[1] != 6 {
        return None;
    }
    let vni = u32::from_be_bytes([0, value[2], value[3], value[4]]);
    let tunnel_ip = match value.len() - 5 {
        4 => IpAddr::from(<[u8; 4]>::try_from(&value[5..]).ok()?),
        16 => IpAddr::from(<[u8; 16]>::try_from(&value[5..]).ok()?),
        _ => return None,
    };
    Some(Pmsi { vni, tunnel_ip })
}

fn encode_pmsi(p: &Pmsi) -> Vec<u8> {
    let mut v = vec![0, 6];
    v.extend_from_slice(&p.vni.to_be_bytes()[1..]);
    match p.tunnel_ip {
        IpAddr::V4(a) => v.extend_from_slice(&a.octets()),
        IpAddr::V6(a) => v.extend_from_slice(&a.octets()),
    }
    v
}

/// RFC 4760 `MP_REACH_NLRI` value: `AFI(2) SAFI(1) NextHopLen(1)
/// NextHop(NextHopLen) SNPACount(1) SNPAs... NLRI...`. SNPAs are always
/// skipped by their own declared lengths (this crate never emits any, but
/// stays tolerant of a peer that does). `add_path_afis` decides whether this
/// batch's own `afi` carries a leading Path Identifier per NLRI entry.
fn decode_mp_reach(data: &[u8], add_path_afis: &HashSet<u16>) -> Result<MpReachNlri, WireError> {
    if data.len() < 5 {
        return Err(WireError::MalformedUpdate);
    }
    let afi = u16::from_be_bytes([data[0], data[1]]);
    let safi = data[2];
    let nh_len = data[3] as usize;
    if data.len() < 4 + nh_len + 1 {
        return Err(WireError::MalformedUpdate);
    }
    let next_hop: IpAddr = match nh_len {
        4 => Ipv4Addr::new(data[4], data[5], data[6], data[7]).into(),
        // RFC 2545 §3: 32 = global address followed by link-local.
        // ponytail: the link-local is dropped, `next_hop` is a single address.
        16 | 32 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            Ipv6Addr::from(octets).into()
        }
        _ => return Err(WireError::MalformedUpdate),
    };
    let mut pos = 4 + nh_len;
    let snpa_count = data[pos];
    pos += 1;
    for _ in 0..snpa_count {
        if data.len() <= pos {
            return Err(WireError::MalformedUpdate);
        }
        let snpa_len = data[pos] as usize;
        pos += 1 + snpa_len;
        if data.len() < pos {
            return Err(WireError::MalformedUpdate);
        }
    }
    if (afi, safi) == (AFI_L2VPN, SAFI_EVPN) {
        return Ok(MpReachNlri {
            afi,
            safi,
            next_hop,
            nlri: Vec::new(),
            nlri_path_ids: Vec::new(),
            evpn: evpn::decode_nlris(&data[pos..])?,
        });
    }
    let (nlri, nlri_path_ids) = decode_prefixes(afi, &data[pos..], add_path_afis.contains(&afi))?;
    Ok(MpReachNlri {
        afi,
        safi,
        next_hop,
        nlri,
        nlri_path_ids,
        evpn: Vec::new(),
    })
}

/// RFC 4760 `MP_UNREACH_NLRI` value: `AFI(2) SAFI(1) WithdrawnNLRI...`.
/// `add_path_afis` decides whether this batch's own `afi` carries a leading
/// Path Identifier per withdrawn entry.
fn decode_mp_unreach(
    data: &[u8],
    add_path_afis: &HashSet<u16>,
) -> Result<MpUnreachNlri, WireError> {
    if data.len() < 3 {
        return Err(WireError::MalformedUpdate);
    }
    let afi = u16::from_be_bytes([data[0], data[1]]);
    let safi = data[2];
    if (afi, safi) == (AFI_L2VPN, SAFI_EVPN) {
        return Ok(MpUnreachNlri {
            afi,
            safi,
            withdrawn: Vec::new(),
            withdrawn_path_ids: Vec::new(),
            evpn: evpn::decode_nlris(&data[3..])?,
        });
    }
    let (withdrawn, withdrawn_path_ids) =
        decode_prefixes(afi, &data[3..], add_path_afis.contains(&afi))?;
    Ok(MpUnreachNlri {
        afi,
        safi,
        withdrawn,
        withdrawn_path_ids,
        evpn: Vec::new(),
    })
}

fn encode_mp_reach(mp: &MpReachNlri) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&mp.afi.to_be_bytes());
    out.push(mp.safi);
    match mp.next_hop {
        IpAddr::V4(a) => {
            out.push(4);
            out.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            out.push(16);
            out.extend_from_slice(&a.octets());
        }
    }
    out.push(0); // SNPA count — this crate never advertises any.
    out.extend_from_slice(&encode_prefixes(&mp.nlri, &mp.nlri_path_ids));
    mp.evpn.iter().for_each(|n| evpn::encode_nlri(n, &mut out));
    out
}

fn encode_mp_unreach(mp: &MpUnreachNlri) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&mp.afi.to_be_bytes());
    out.push(mp.safi);
    out.extend_from_slice(&encode_prefixes(&mp.withdrawn, &mp.withdrawn_path_ids));
    mp.evpn.iter().for_each(|n| evpn::encode_nlri(n, &mut out));
    out
}

/// Flattens one or more `AS_PATH` segments (`segment_type(1) count(1)
/// count*width bytes`, `width` 2 or 4) into a single `Vec<u32>`, regardless of
/// `AS_SEQUENCE` vs. `AS_SET` (documented simplification — this crate never
/// distinguishes them).
fn parse_as_path(mut data: &[u8], width: usize) -> Result<Vec<u32>, WireError> {
    let mut asns = Vec::new();
    while !data.is_empty() {
        if data.len() < 2 {
            return Err(WireError::MalformedUpdate);
        }
        let count = usize::from(data[1]);
        let segment_len = 2 + count * width;
        if data.len() < segment_len {
            return Err(WireError::MalformedUpdate);
        }
        asns.extend(
            data[2..segment_len]
                .chunks_exact(width)
                .map(|c| c.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b))),
        );
        // RFC 7607: AS 0 must not appear in AS_PATH / AS4_PATH.
        if asns.contains(&0) {
            return Err(WireError::MalformedUpdate);
        }
        data = &data[segment_len..];
    }
    Ok(asns)
}

/// Parses an UPDATE body: withdrawn-routes (u16 length + packed IPv4
/// prefixes), path attributes (u16 length + TLV list), then legacy NLRI
/// (everything remaining — RFC 4271 has no explicit NLRI length field, since
/// the outer message header's length already delimits it).
///
/// `ORIGIN`/`AS_PATH` must be present whenever any NLRI is being announced
/// (legacy `nlri` or an `MP_REACH_NLRI` batch), else `MalformedUpdate`.
/// `NEXT_HOP` is additionally mandatory only when the legacy `nlri` field
/// itself is non-empty — an MP-only announcement carries its next-hop inside
/// `MP_REACH_NLRI` instead and may omit the legacy attribute entirely. If
/// nothing is being announced (a pure withdrawal), `attributes` is `None`,
/// discarding any attributes present. `add_path_afis` (from the owning
/// `BgpCodec`) decides whether IPv4 unicast (legacy `withdrawn_routes`/
/// `nlri`) — and, per-batch, each `mp_reach`/`mp_unreach` entry's own AFI —
/// carries a leading RFC 7911 Path Identifier.
fn parse_update(
    body: &[u8],
    add_path_afis: &HashSet<u16>,
    two_octet_as: bool,
) -> Result<UpdateMessage, WireError> {
    if body.len() < 2 {
        return Err(WireError::MalformedUpdate);
    }
    let with_ids_v4 = add_path_afis.contains(&AFI_IPV4);
    let withdrawn_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
    let mut pos = 2;
    if body.len() < pos + withdrawn_len {
        return Err(WireError::MalformedUpdate);
    }
    let (withdrawn_routes, withdrawn_path_ids) =
        decode_prefixes_v4(&body[pos..pos + withdrawn_len], with_ids_v4)?;
    pos += withdrawn_len;

    if body.len() < pos + 2 {
        return Err(WireError::MalformedUpdate);
    }
    let attr_len = usize::from(u16::from_be_bytes([body[pos], body[pos + 1]]));
    pos += 2;
    if body.len() < pos + attr_len {
        return Err(WireError::MalformedUpdate);
    }
    let parsed = parse_path_attributes(&body[pos..pos + attr_len], add_path_afis, two_octet_as)?;
    pos += attr_len;

    let (nlri, nlri_path_ids) = decode_prefixes_v4(&body[pos..], with_ids_v4)?;

    let announcing = !nlri.is_empty() || !parsed.mp_reach.is_empty();
    let attributes = if announcing && !parsed.withdraw {
        // A missing mandatory attribute is treat-as-withdraw too (RFC 7606
        // §3(d)). NEXT_HOP is only mandatory with legacy NLRI: an MP-only
        // announcement carries its next-hop inside `MP_REACH_NLRI`.
        match (parsed.origin, parsed.as_path, parsed.next_hop) {
            (Some(origin), Some(as_path), next_hop) if next_hop.is_some() || nlri.is_empty() => {
                Some(PathAttributes {
                    origin,
                    as_path,
                    next_hop: next_hop.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    local_pref: parsed.local_pref,
                    med: parsed.med,
                    originator_id: parsed.originator_id,
                    cluster_list: parsed.cluster_list,
                    communities: parsed.communities,
                    extended_communities: parsed.extended_communities,
                    large_communities: parsed.large_communities,
                    pmsi: parsed.pmsi,
                    atomic_aggregate: parsed.atomic_aggregate,
                    aggregator: parsed.aggregator,
                })
            }
            _ => None,
        }
    } else {
        None
    };

    let mut update = UpdateMessage {
        withdrawn_routes,
        withdrawn_path_ids,
        nlri,
        nlri_path_ids,
        attributes,
        mp_reach: parsed.mp_reach,
        mp_unreach: parsed.mp_unreach,
    };
    // RFC 7606 §2 treat-as-withdraw: the announced routes are handled as if
    // listed as withdrawn (legacy NLRI -> Withdrawn Routes, each MP_REACH
    // batch -> an MP_UNREACH batch), and the attributes are dropped.
    if announcing && update.attributes.is_none() {
        warn!(
            "malformed UPDATE path attributes: treating announced routes as withdrawn (RFC 7606)"
        );
        update.withdrawn_routes.append(&mut update.nlri);
        update.withdrawn_path_ids.append(&mut update.nlri_path_ids);
        let reach = std::mem::take(&mut update.mp_reach);
        update
            .mp_unreach
            .extend(reach.into_iter().map(|m| MpUnreachNlri {
                afi: m.afi,
                safi: m.safi,
                withdrawn: m.nlri,
                withdrawn_path_ids: m.nlri_path_ids,
                evpn: m.evpn,
            }));
    }
    Ok(update)
}

fn encode_attribute(out: &mut Vec<u8>, flags: u8, attr_type: u8, value: &[u8]) {
    if let Ok(len) = u8::try_from(value.len()) {
        out.push(flags);
        out.push(attr_type);
        out.push(len);
    } else {
        out.push(flags | ATTR_FLAG_EXTENDED_LENGTH);
        out.push(attr_type);
        // Only reached for an attribute value over 255 bytes (a very long
        // AS_PATH) — still far under a whole message's 4096-byte cap.
        out.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
    }
    out.extend_from_slice(value);
}

/// Splits `asns` into `AS_PATH_SEGMENT_SEQUENCE` segments of at most
/// `MAX_AS_PATH_SEGMENT_LEN` ASNs each (the segment's own count field is a
/// single byte). An empty path encodes as an empty attribute value (no
/// segments at all) — valid for, e.g., a route redistributed straight to an
/// iBGP peer, which never gets a local ASN prepended. With `two_octet`, each
/// ASN is 2 bytes and one that doesn't fit becomes `AS_TRANS` (RFC 6793 §4.2.2).
fn encode_as_path(asns: &[u32], two_octet: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in asns.chunks(MAX_AS_PATH_SEGMENT_LEN) {
        out.push(AS_PATH_SEGMENT_SEQUENCE);
        // `chunks(MAX_AS_PATH_SEGMENT_LEN)` never yields more than 255
        // elements per chunk, so this always fits in a u8.
        out.push(u8::try_from(chunk.len()).unwrap_or(u8::MAX));
        for asn in chunk {
            if two_octet {
                let asn = u16::try_from(*asn).unwrap_or(AS_TRANS);
                out.extend_from_slice(&asn.to_be_bytes());
            } else {
                out.extend_from_slice(&asn.to_be_bytes());
            }
        }
    }
    out
}

/// Builds the whole path-attribute TLV list for one UPDATE: the legacy
/// `ORIGIN`/`AS_PATH`/(`NEXT_HOP`)/`LOCAL_PREF` attributes (`NEXT_HOP` only
/// when the legacy `nlri` field is non-empty), then one `MP_REACH_NLRI`/
/// `MP_UNREACH_NLRI` attribute per batch.
fn encode_attributes(update: &UpdateMessage, two_octet_as: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(attrs) = &update.attributes {
        encode_attribute(
            &mut out,
            ATTR_FLAG_WELL_KNOWN_TRANSITIVE,
            ATTR_ORIGIN,
            &[attrs.origin as u8],
        );
        encode_attribute(
            &mut out,
            ATTR_FLAG_WELL_KNOWN_TRANSITIVE,
            ATTR_AS_PATH,
            &encode_as_path(&attrs.as_path, two_octet_as),
        );
        // RFC 6793 §4.2.2: the real path rides along only when some ASN was
        // squashed to AS_TRANS.
        if two_octet_as && attrs.as_path.iter().any(|&a| a > u32::from(u16::MAX)) {
            encode_attribute(
                &mut out,
                ATTR_FLAG_OPTIONAL_TRANSITIVE,
                ATTR_AS4_PATH,
                &encode_as_path(&attrs.as_path, false),
            );
        }
        if !update.nlri.is_empty() {
            encode_attribute(
                &mut out,
                ATTR_FLAG_WELL_KNOWN_TRANSITIVE,
                ATTR_NEXT_HOP,
                &attrs.next_hop.octets(),
            );
        }
        if attrs.atomic_aggregate {
            encode_attribute(
                &mut out,
                ATTR_FLAG_WELL_KNOWN_TRANSITIVE,
                ATTR_ATOMIC_AGGREGATE,
                &[],
            );
        }
        if let Some(agg) = attrs.aggregator {
            let mut value = Vec::with_capacity(8);
            if two_octet_as {
                value.extend_from_slice(&u16::try_from(agg.asn).unwrap_or(AS_TRANS).to_be_bytes());
            } else {
                value.extend_from_slice(&agg.asn.to_be_bytes());
            }
            value.extend_from_slice(&agg.router_id.octets());
            encode_attribute(
                &mut out,
                ATTR_FLAG_OPTIONAL_TRANSITIVE,
                ATTR_AGGREGATOR,
                &value,
            );
            // RFC 6793 §4.2.2: the real AS rides along only when it was squashed.
            if two_octet_as && agg.asn > u32::from(u16::MAX) {
                let mut v = agg.asn.to_be_bytes().to_vec();
                v.extend_from_slice(&agg.router_id.octets());
                encode_attribute(
                    &mut out,
                    ATTR_FLAG_OPTIONAL_TRANSITIVE,
                    ATTR_AS4_AGGREGATOR,
                    &v,
                );
            }
        }
        if let Some(local_pref) = attrs.local_pref {
            encode_attribute(
                &mut out,
                ATTR_FLAG_WELL_KNOWN_TRANSITIVE,
                ATTR_LOCAL_PREF,
                &local_pref.to_be_bytes(),
            );
        }
        if let Some(med) = attrs.med {
            encode_attribute(
                &mut out,
                ATTR_FLAG_OPTIONAL_NON_TRANSITIVE,
                ATTR_MULTI_EXIT_DISC,
                &med.to_be_bytes(),
            );
        }
        if let Some(originator_id) = attrs.originator_id {
            encode_attribute(
                &mut out,
                ATTR_FLAG_OPTIONAL_NON_TRANSITIVE,
                ATTR_ORIGINATOR_ID,
                &originator_id.octets(),
            );
        }
        if !attrs.cluster_list.is_empty() {
            let value: Vec<u8> = attrs
                .cluster_list
                .iter()
                .flat_map(Ipv4Addr::octets)
                .collect();
            encode_attribute(
                &mut out,
                ATTR_FLAG_OPTIONAL_NON_TRANSITIVE,
                ATTR_CLUSTER_LIST,
                &value,
            );
        }
        if !attrs.communities.is_empty() {
            let value: Vec<u8> = attrs
                .communities
                .iter()
                .flat_map(|c| c.to_be_bytes())
                .collect();
            encode_attribute(
                &mut out,
                ATTR_FLAG_OPTIONAL_TRANSITIVE,
                ATTR_COMMUNITY,
                &value,
            );
        }
        if !attrs.extended_communities.is_empty() {
            let value: Vec<u8> = attrs
                .extended_communities
                .iter()
                .flat_map(|c| c.to_be_bytes())
                .collect();
            encode_attribute(
                &mut out,
                ATTR_FLAG_OPTIONAL_TRANSITIVE,
                ATTR_EXTENDED_COMMUNITIES,
                &value,
            );
        }
        if !attrs.large_communities.is_empty() {
            let value: Vec<u8> = attrs
                .large_communities
                .iter()
                .flat_map(|(ga, l1, l2)| {
                    ga.to_be_bytes()
                        .into_iter()
                        .chain(l1.to_be_bytes())
                        .chain(l2.to_be_bytes())
                })
                .collect();
            encode_attribute(
                &mut out,
                ATTR_FLAG_OPTIONAL_TRANSITIVE,
                ATTR_LARGE_COMMUNITY,
                &value,
            );
        }
    }
    if let Some(pmsi) = update.attributes.as_ref().and_then(|a| a.pmsi.as_ref()) {
        encode_attribute(
            &mut out,
            ATTR_FLAG_OPTIONAL_TRANSITIVE,
            ATTR_PMSI_TUNNEL,
            &encode_pmsi(pmsi),
        );
    }
    for mp in &update.mp_reach {
        encode_attribute(
            &mut out,
            ATTR_FLAG_OPTIONAL_NON_TRANSITIVE,
            ATTR_MP_REACH_NLRI,
            &encode_mp_reach(mp),
        );
    }
    for mp in &update.mp_unreach {
        encode_attribute(
            &mut out,
            ATTR_FLAG_OPTIONAL_NON_TRANSITIVE,
            ATTR_MP_UNREACH_NLRI,
            &encode_mp_unreach(mp),
        );
    }
    out
}

/// Mirror image of `parse_update`. Byte lengths for the withdrawn-routes and
/// path-attributes sections always fit comfortably in a `u16` in practice —
/// the whole message is capped at `MAX_MESSAGE_LEN` (4096) bytes by
/// `BgpCodec::encode`, which will itself reject the overall frame if
/// something pathological ever made it larger.
fn encode_update(update: &UpdateMessage, two_octet_as: bool) -> Vec<u8> {
    let mut body = Vec::new();

    let withdrawn = encode_prefixes_v4(&update.withdrawn_routes, &update.withdrawn_path_ids);
    body.extend_from_slice(
        &u16::try_from(withdrawn.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    body.extend_from_slice(&withdrawn);

    let attrs = encode_attributes(update, two_octet_as);
    body.extend_from_slice(&u16::try_from(attrs.len()).unwrap_or(u16::MAX).to_be_bytes());
    body.extend_from_slice(&attrs);

    body.extend_from_slice(&encode_prefixes_v4(&update.nlri, &update.nlri_path_ids));
    body
}

#[cfg(test)]
// Community/ASN values are conventionally written and read in decimal
// (`65000:100`) — hex/binary notation would make these test fixtures harder
// to read, not easier.
#[allow(clippy::decimal_bitwise_operands, clippy::identity_op)]
mod tests {
    use super::*;

    fn roundtrip(msg: BgpMessage) -> BgpMessage {
        let mut codec = BgpCodec::default();
        let mut buf = BytesMut::new();
        codec.encode(msg, &mut buf).unwrap();
        codec.decode(&mut buf).unwrap().unwrap()
    }

    fn as_path_update(as_path: Vec<u32>) -> UpdateMessage {
        UpdateMessage {
            withdrawn_routes: vec![],
            withdrawn_path_ids: vec![],
            nlri: vec!["10.0.0.0/8".parse().unwrap()],
            nlri_path_ids: vec![],
            attributes: Some(PathAttributes {
                origin: Origin::Igp,
                as_path,
                next_hop: Ipv4Addr::new(192, 0, 2, 1),
                local_pref: None,
                med: None,
                originator_id: None,
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: vec![],
                extended_communities: vec![],
                large_communities: vec![],
                pmsi: None,
            }),
            mp_reach: vec![],
            mp_unreach: vec![],
        }
    }

    fn two_octet_codec() -> BgpCodec {
        BgpCodec {
            two_octet_as: true,
            ..BgpCodec::default()
        }
    }

    /// Path attribute type codes in `update`'s wire encoding.
    fn attr_types(update: &UpdateMessage, two_octet_as: bool) -> Vec<u8> {
        let mut data = &encode_attributes(update, two_octet_as)[..];
        let mut types = vec![];
        while !data.is_empty() {
            types.push(data[1]);
            let (len, hdr) = if data[0] & ATTR_FLAG_EXTENDED_LENGTH != 0 {
                (usize::from(u16::from_be_bytes([data[2], data[3]])), 4)
            } else {
                (usize::from(data[2]), 3)
            };
            data = &data[hdr + len..];
        }
        types
    }

    #[test]
    fn two_octet_peer_gets_as_trans_and_as4_path_and_roundtrips() {
        let update = as_path_update(vec![65001, 4_200_000_000, 65002]);
        assert_eq!(
            encode_as_path(&update.attributes.as_ref().unwrap().as_path, true),
            [2, 3, 0xFD, 0xE9, 0x5B, 0xA0, 0xFD, 0xEA]
        );
        assert!(attr_types(&update, true).contains(&ATTR_AS4_PATH));

        let mut codec = two_octet_codec();
        let mut buf = BytesMut::new();
        codec
            .encode(BgpMessage::Update(update.clone()), &mut buf)
            .unwrap();
        assert_eq!(
            codec.decode(&mut buf).unwrap().unwrap(),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn as_zero_in_as_path_is_malformed() {
        assert!(parse_as_path(&[2, 2, 0xFD, 0xE9, 0, 0], 2).is_err());
        assert!(parse_as_path(&[2, 1, 0, 0, 0, 0], 4).is_err());
        assert!(parse_as_path(&[2, 1, 0, 0, 0xFD, 0xE9], 4).is_ok());
    }

    #[test]
    fn two_octet_peer_with_only_small_asns_gets_no_as4_path() {
        let update = as_path_update(vec![65001, 65002]);
        assert!(!attr_types(&update, true).contains(&ATTR_AS4_PATH));
        // A 4-octet peer never gets one either.
        let big = as_path_update(vec![65001, 4_200_000_000]);
        assert!(!attr_types(&big, false).contains(&ATTR_AS4_PATH));
    }

    #[test]
    fn atomic_aggregate_and_aggregator_roundtrip_and_use_as4_aggregator_for_two_octet() {
        let mut update = as_path_update(vec![65001]);
        let agg = Aggregator {
            asn: 4_200_000_001,
            router_id: Ipv4Addr::new(192, 0, 2, 9),
        };
        {
            let a = update.attributes.as_mut().unwrap();
            a.atomic_aggregate = true;
            a.aggregator = Some(agg);
        }
        // Four-octet session: 8-byte AGGREGATOR, no AS4_AGGREGATOR.
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update.clone())
        );
        let types = attr_types(&update, false);
        assert!(types.contains(&ATTR_ATOMIC_AGGREGATE) && !types.contains(&ATTR_AS4_AGGREGATOR));
        // Two-octet session: AS_TRANS + AS4_AGGREGATOR, merged back on receipt.
        assert!(attr_types(&update, true).contains(&ATTR_AS4_AGGREGATOR));
        let mut codec = two_octet_codec();
        let mut buf = BytesMut::new();
        codec
            .encode(BgpMessage::Update(update.clone()), &mut buf)
            .unwrap();
        assert_eq!(
            codec.decode(&mut buf).unwrap().unwrap(),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn malformed_aggregate_attributes_are_discarded_not_withdrawn() {
        let mut attrs = Vec::new();
        encode_attribute(&mut attrs, 0x40, ATTR_ORIGIN, &[0]);
        encode_attribute(&mut attrs, 0x40, ATTR_AS_PATH, &[]);
        encode_attribute(&mut attrs, 0x40, ATTR_NEXT_HOP, &[192, 0, 2, 1]);
        encode_attribute(&mut attrs, 0x40, ATTR_ATOMIC_AGGREGATE, &[1]);
        encode_attribute(&mut attrs, 0xC0, ATTR_AGGREGATOR, &[0, 1, 2]);
        let p = parse_path_attributes(&attrs, &HashSet::new(), false).unwrap();
        assert!(!p.withdraw && !p.atomic_aggregate && p.aggregator.is_none());
    }

    #[test]
    fn as4_path_merges_per_rfc6793_only_when_two_octet() {
        // AS_PATH 65001 23456 65003 + AS4_PATH (real) 4200000000 65003:
        // the trailing 2 entries are replaced, the leading one kept.
        let mut attrs = Vec::new();
        encode_attribute(&mut attrs, 0x40, ATTR_ORIGIN, &[0]);
        encode_attribute(
            &mut attrs,
            0x40,
            ATTR_AS_PATH,
            &[2, 3, 0xFD, 0xE9, 0x5B, 0xA0, 0xFD, 0xEB],
        );
        encode_attribute(&mut attrs, 0x40, ATTR_NEXT_HOP, &[192, 0, 2, 1]);
        encode_attribute(
            &mut attrs,
            0xC0,
            ATTR_AS4_PATH,
            &encode_as_path(&[4_200_000_000, 65003], false),
        );
        let merged = parse_path_attributes(&attrs, &HashSet::new(), true).unwrap();
        assert_eq!(merged.as_path, Some(vec![65001, 4_200_000_000, 65003]));

        // A longer AS4_PATH is ignored, leaving the 2-byte path as sent.
        let mut long = Vec::new();
        encode_attribute(&mut long, 0x40, ATTR_AS_PATH, &[2, 1, 0xFD, 0xE9]);
        encode_attribute(
            &mut long,
            0xC0,
            ATTR_AS4_PATH,
            &encode_as_path(&[1, 2], false),
        );
        let ignored = parse_path_attributes(&long, &HashSet::new(), true).unwrap();
        assert_eq!(ignored.as_path, Some(vec![65001]));
    }

    #[test]
    fn keepalive_roundtrips() {
        assert_eq!(roundtrip(BgpMessage::Keepalive), BgpMessage::Keepalive);
    }

    #[test]
    fn open_without_capability_roundtrips() {
        let open = OpenMessage {
            version: BGP_VERSION,
            my_as: 65001,
            hold_time: 90,
            bgp_identifier: Ipv4Addr::new(1, 1, 1, 1),
            capabilities: vec![],
        };
        assert_eq!(
            roundtrip(BgpMessage::Open(open.clone())),
            BgpMessage::Open(open)
        );
    }

    #[test]
    fn open_with_four_octet_capability_roundtrips() {
        let open = build_open(4_200_000_000, Ipv4Addr::new(2, 2, 2, 2), 90);
        assert_eq!(open.my_as, AS_TRANS);
        assert_eq!(four_octet_asn(&open), Some(4_200_000_000));
        assert_eq!(
            roundtrip(BgpMessage::Open(open.clone())),
            BgpMessage::Open(open)
        );
    }

    #[test]
    fn open_with_multiprotocol_and_extended_next_hop_capabilities_roundtrips() {
        let mut open = build_open(65001, Ipv4Addr::new(3, 3, 3, 3), 90);
        open.capabilities.push(Capability::MultiProtocol {
            afi: AFI_IPV6,
            safi: 1,
        });
        open.capabilities.push(Capability::ExtendedNextHop {
            nlri_afi: AFI_IPV4,
            nlri_safi: 1,
            nh_afi: AFI_IPV6,
        });
        assert_eq!(
            roundtrip(BgpMessage::Open(open.clone())),
            BgpMessage::Open(open)
        );
    }

    #[test]
    fn open_with_evpn_capability_roundtrips() {
        let mut open = build_open(65001, Ipv4Addr::new(3, 3, 3, 3), 90);
        open.capabilities.push(Capability::MultiProtocol {
            afi: AFI_L2VPN,
            safi: SAFI_EVPN,
        });
        assert_eq!(
            roundtrip(BgpMessage::Open(open.clone())),
            BgpMessage::Open(open)
        );
    }

    #[test]
    fn build_open_uses_as_trans_boundary_correctly() {
        assert_eq!(build_open(65535, Ipv4Addr::LOCALHOST, 90).my_as, 65535);
        assert_eq!(build_open(65536, Ipv4Addr::LOCALHOST, 90).my_as, AS_TRANS);
        // Always advertised once 4-octet-capable, even when `my_as` didn't need AS_TRANS.
        assert_eq!(
            four_octet_asn(&build_open(65535, Ipv4Addr::LOCALHOST, 90)),
            Some(65535)
        );
    }

    #[test]
    fn effective_remote_asn_prefers_capability_over_plain_field() {
        let with_cap = OpenMessage {
            version: BGP_VERSION,
            my_as: AS_TRANS,
            hold_time: 90,
            bgp_identifier: Ipv4Addr::LOCALHOST,
            capabilities: vec![Capability::FourOctetAsn(4_200_000_000)],
        };
        assert_eq!(effective_remote_asn(&with_cap), 4_200_000_000);

        let without_cap = OpenMessage {
            capabilities: vec![],
            ..with_cap
        };
        assert_eq!(effective_remote_asn(&without_cap), u32::from(AS_TRANS));
    }

    #[test]
    fn notification_roundtrips() {
        let n = NotificationMessage {
            error_code: 6,
            error_subcode: 7,
            data: Bytes::new(),
        };
        assert_eq!(
            roundtrip(BgpMessage::Notification(n.clone())),
            BgpMessage::Notification(n)
        );
    }

    #[test]
    fn route_refresh_roundtrips() {
        let rr = RouteRefreshMessage {
            afi: AFI_IPV6,
            safi: 1,
        };
        assert_eq!(
            roundtrip(BgpMessage::RouteRefresh(rr)),
            BgpMessage::RouteRefresh(rr)
        );
    }

    #[test]
    fn route_refresh_truncated_body_is_malformed() {
        let body = vec![0u8, 1u8, 0u8]; // 3 bytes, needs 4
        assert!(matches!(
            parse_route_refresh(&body),
            Err(WireError::MalformedRouteRefresh)
        ));
    }

    #[test]
    fn open_with_route_refresh_capability_roundtrips() {
        let mut open = build_open(65001, Ipv4Addr::new(4, 4, 4, 4), 90);
        open.capabilities.push(Capability::RouteRefresh);
        assert_eq!(
            roundtrip(BgpMessage::Open(open.clone())),
            BgpMessage::Open(open)
        );
    }

    #[test]
    fn unknown_type_decodes_as_unhandled() {
        match roundtrip(BgpMessage::Unhandled {
            message_type: 200, // not a type this crate understands
            body: Bytes::from_static(b"not parsed"),
        }) {
            BgpMessage::Unhandled { message_type, body } => {
                assert_eq!(message_type, 200);
                assert_eq!(&body[..], b"not parsed");
            }
            other => panic!("expected Unhandled, got {other:?}"),
        }
    }

    fn attrs(as_path: Vec<u32>, local_pref: Option<u32>) -> PathAttributes {
        PathAttributes {
            origin: Origin::Igp,
            as_path,
            next_hop: Ipv4Addr::new(10, 0, 0, 1),
            local_pref,
            med: None,
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            cluster_list: vec![],
            communities: vec![],
            extended_communities: vec![],
            large_communities: vec![],
            pmsi: None,
        }
    }

    fn empty_update() -> UpdateMessage {
        UpdateMessage {
            withdrawn_routes: vec![],
            withdrawn_path_ids: vec![],
            nlri: vec![],
            nlri_path_ids: vec![],
            attributes: None,
            mp_reach: vec![],
            mp_unreach: vec![],
        }
    }

    #[test]
    fn update_announce_roundtrips() {
        let update = UpdateMessage {
            nlri: vec![
                "10.1.0.0/24".parse().unwrap(),
                "10.2.0.0/16".parse().unwrap(),
            ],
            attributes: Some(attrs(vec![65001, 65002], Some(200))),
            ..empty_update()
        };
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn update_with_communities_roundtrips() {
        let update = UpdateMessage {
            nlri: vec!["10.1.0.0/24".parse().unwrap()],
            attributes: Some(PathAttributes {
                communities: vec![(65000 << 16) | 100, 0xFFFF_FF01],
                extended_communities: vec![(0u64 << 56) | (2u64 << 48) | 100],
                large_communities: vec![(65000, 1, 1)],
                pmsi: None,
                ..attrs(vec![65001], Some(200))
            }),
            ..empty_update()
        };
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn update_withdraw_only_roundtrips_with_no_attributes() {
        let update = UpdateMessage {
            withdrawn_routes: vec!["10.1.0.0/24".parse().unwrap(), "0.0.0.0/0".parse().unwrap()],
            ..empty_update()
        };
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn update_mixed_withdraw_and_announce_roundtrips() {
        let update = UpdateMessage {
            withdrawn_routes: vec!["192.168.1.0/24".parse().unwrap()],
            nlri: vec!["172.16.0.0/12".parse().unwrap()],
            attributes: Some(attrs(vec![], None)),
            ..empty_update()
        };
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn update_as_path_longer_than_one_segment_roundtrips() {
        let long_path: Vec<u32> = (1..=300).collect();
        let update = UpdateMessage {
            nlri: vec!["10.0.0.0/8".parse().unwrap()],
            attributes: Some(attrs(long_path, None)),
            ..empty_update()
        };
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn mp_reach_ipv6_announce_roundtrips() {
        // MP-only announcement (no legacy nlri): the legacy NEXT_HOP
        // attribute is never encoded, so it must round-trip as
        // UNSPECIFIED rather than whatever placeholder was passed in.
        let update = UpdateMessage {
            attributes: Some(PathAttributes {
                next_hop: Ipv4Addr::UNSPECIFIED,
                ..attrs(vec![65001], Some(150))
            }),
            mp_reach: vec![MpReachNlri {
                afi: AFI_IPV6,
                safi: 1,
                next_hop: "2001:db8::1".parse().unwrap(),
                nlri: vec!["2001:db8:1::/48".parse().unwrap(), "::/0".parse().unwrap()],
                nlri_path_ids: vec![],
                evpn: vec![],
            }],
            ..empty_update()
        };
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn mp_reach_accepts_global_plus_link_local_next_hop() {
        // RFC 2545 §3: next-hop length 32 = global then link-local.
        let mut v = vec![0, 2, 1, 32];
        v.extend("2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        v.extend("fe80::1".parse::<Ipv6Addr>().unwrap().octets());
        v.extend([0, 48, 0x20, 0x01, 0x0d, 0xb8, 0, 1]); // 0 SNPAs, 2001:db8:1::/48
        let mp = decode_mp_reach(&v, &HashSet::new()).unwrap();
        assert_eq!(mp.next_hop, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(mp.nlri, vec!["2001:db8:1::/48".parse().unwrap()]);
    }

    #[test]
    fn mp_unreach_ipv6_withdraw_roundtrips() {
        let update = UpdateMessage {
            mp_unreach: vec![MpUnreachNlri {
                afi: AFI_IPV6,
                safi: 1,
                withdrawn: vec!["2001:db8:1::/48".parse().unwrap()],
                withdrawn_path_ids: vec![],
                evpn: vec![],
            }],
            ..empty_update()
        };
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update)
        );
    }

    fn evpn_routes() -> Vec<EvpnNlri> {
        let rd = [0, 0, 0xfd, 0xe8, 0, 0, 0, 1];
        vec![
            EvpnNlri::MacIp {
                rd,
                esi: [0; 10],
                tag: 0,
                mac: [0xaa, 0xbb, 0xcc, 0, 0, 1],
                ip: Some("10.0.0.5".parse().unwrap()),
                labels: vec![10_000],
            },
            EvpnNlri::InclusiveMulticast {
                rd,
                tag: 0,
                origin: "192.0.2.1".parse().unwrap(),
            },
        ]
    }

    #[test]
    fn mp_reach_evpn_roundtrips_with_extended_communities() {
        // RT 65000:10000 (0x0002 type/subtype, 2-byte AS, 4-byte value).
        let rt = 0x0002_fde8_0000_2710_u64;
        let update = UpdateMessage {
            attributes: Some(PathAttributes {
                next_hop: Ipv4Addr::UNSPECIFIED,
                extended_communities: vec![rt],
                ..attrs(vec![65001], Some(100))
            }),
            mp_reach: vec![MpReachNlri {
                afi: AFI_L2VPN,
                safi: SAFI_EVPN,
                next_hop: "192.0.2.1".parse().unwrap(),
                nlri: vec![],
                nlri_path_ids: vec![],
                evpn: evpn_routes(),
            }],
            ..empty_update()
        };
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn mp_unreach_evpn_roundtrips() {
        let update = UpdateMessage {
            mp_unreach: vec![MpUnreachNlri {
                afi: AFI_L2VPN,
                safi: SAFI_EVPN,
                withdrawn: vec![],
                withdrawn_path_ids: vec![],
                evpn: evpn_routes(),
            }],
            ..empty_update()
        };
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn mp_reach_l2vpn_with_other_safi_is_malformed() {
        // Only SAFI 70 is understood for AFI 25; anything else must not be
        // misread as a prefix list.
        let mut wire = Vec::new();
        wire.extend_from_slice(&AFI_L2VPN.to_be_bytes());
        wire.extend_from_slice(&[128, 4, 192, 0, 2, 1, 0]);
        assert!(decode_mp_reach(&wire, &HashSet::new()).is_err());
    }

    #[test]
    fn mp_reach_evpn_with_truncated_nlri_is_malformed() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&AFI_L2VPN.to_be_bytes());
        wire.extend_from_slice(&[SAFI_EVPN, 4, 192, 0, 2, 1, 0, 3, 200]);
        assert!(decode_mp_reach(&wire, &HashSet::new()).is_err());
    }

    #[test]
    fn mp_reach_cross_family_next_hop_roundtrips() {
        // RFC 8950: IPv4 unicast NLRI carried over an IPv6 next-hop.
        let update = UpdateMessage {
            attributes: Some(PathAttributes {
                next_hop: Ipv4Addr::UNSPECIFIED,
                ..attrs(vec![], None)
            }),
            mp_reach: vec![MpReachNlri {
                afi: AFI_IPV4,
                safi: 1,
                next_hop: "2001:db8::1".parse().unwrap(),
                nlri: vec!["10.0.0.0/24".parse().unwrap()],
                nlri_path_ids: vec![],
                evpn: vec![],
            }],
            ..empty_update()
        };
        let rt = roundtrip(BgpMessage::Update(update.clone()));
        assert_eq!(rt, BgpMessage::Update(update));
        // MP-only announcement never encodes the legacy NEXT_HOP attribute.
        let BgpMessage::Update(u) = rt else {
            unreachable!()
        };
        assert!(u.nlri.is_empty());
        assert_eq!(
            u.mp_reach[0].next_hop,
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn update_with_unknown_attribute_is_skipped_by_length() {
        // withdrawn_routes length = 0
        let mut body = vec![0u8, 0u8];
        // path attributes: an unknown attribute (type 99) with 3 bytes of
        // junk, followed by the three mandatory attributes.
        let mut path_attrs = Vec::new();
        path_attrs.extend_from_slice(&[0x80, 99, 3, 0xAA, 0xBB, 0xCC]);
        path_attrs.extend_from_slice(&[0x40, ATTR_ORIGIN, 1, Origin::Igp as u8]);
        path_attrs.extend_from_slice(&[0x40, ATTR_AS_PATH, 0]);
        path_attrs.extend_from_slice(&[0x40, ATTR_NEXT_HOP, 4, 10, 0, 0, 1]);
        body.extend_from_slice(&u16::try_from(path_attrs.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&path_attrs);
        // nlri: 10.0.0.0/8
        body.extend_from_slice(&[8, 10]);

        let parsed = parse_update(&body, &HashSet::new(), false).unwrap();
        assert_eq!(parsed.nlri, vec!["10.0.0.0/8".parse().unwrap()]);
        assert_eq!(
            parsed.attributes,
            Some(PathAttributes {
                origin: Origin::Igp,
                as_path: vec![],
                next_hop: Ipv4Addr::new(10, 0, 0, 1),
                local_pref: None,
                med: None,
                originator_id: None,
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: vec![],
                extended_communities: vec![],
                large_communities: vec![],
                pmsi: None,
            })
        );
    }

    #[test]
    fn update_with_nlri_but_missing_mandatory_attribute_is_treated_as_withdraw() {
        // withdrawn_routes length = 0, path attributes length = 0 (no
        // ORIGIN/AS_PATH/NEXT_HOP at all), nlri = 10.0.0.0/8.
        let mut body = vec![0u8, 0u8, 0u8, 0u8];
        body.extend_from_slice(&[8, 10]);
        let u = parse_update(&body, &HashSet::new(), false).unwrap();
        assert!(u.nlri.is_empty() && u.attributes.is_none());
        assert_eq!(u.withdrawn_routes, vec!["10.0.0.0/8".parse().unwrap()]);
    }

    /// Body: no withdrawn routes, `attrs`, then legacy NLRI 10.0.0.0/8.
    fn body_with(attrs: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8, 0u8];
        body.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
        body.extend_from_slice(attrs);
        body.extend_from_slice(&[8, 10]);
        body
    }

    fn valid_attrs() -> Vec<u8> {
        let mut a = vec![0x40, ATTR_ORIGIN, 1, 0, 0x40, ATTR_AS_PATH, 0];
        a.extend_from_slice(&[0x40, ATTR_NEXT_HOP, 4, 10, 0, 0, 1]);
        a
    }

    #[test]
    fn malformed_attribute_content_is_treated_as_withdraw_not_reset() {
        let mp_reach = {
            // AFI 2, SAFI 1, nh len 16 (2001:db8::1), reserved, 2001:db8:1::/48
            let mut v = vec![0, 2, 1, 16];
            v.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
            v.extend_from_slice(&[0, 48, 0x20, 0x01, 0x0d, 0xb8, 0, 1]);
            v
        };
        for bad in [
            &[0x40, ATTR_ORIGIN, 1, 9][..],             // bad ORIGIN value
            &[0x80, ATTR_COMMUNITY, 3, 1, 2, 3][..],    // COMMUNITY length % 4
            &[0x80, ATTR_MULTI_EXIT_DISC, 2, 0, 0][..], // MED length
            &[0x40, ATTR_AS_PATH, 4, 2, 1, 0, 0][..],   // AS_PATH truncated segment
        ] {
            let mut attrs = valid_attrs();
            attrs.extend_from_slice(bad);
            attrs.extend_from_slice(&[
                0x80,
                ATTR_MP_REACH_NLRI,
                u8::try_from(mp_reach.len()).unwrap(),
            ]);
            attrs.extend_from_slice(&mp_reach);
            let u = parse_update(&body_with(&attrs), &HashSet::new(), false).unwrap();
            assert_eq!(u.withdrawn_routes, vec!["10.0.0.0/8".parse().unwrap()]);
            assert!(u.nlri.is_empty() && u.mp_reach.is_empty() && u.attributes.is_none());
            assert_eq!(u.mp_unreach.len(), 1);
            assert_eq!(
                u.mp_unreach[0].withdrawn,
                vec!["2001:db8:1::/48".parse().unwrap()]
            );
        }
    }

    #[test]
    fn malformed_attribute_framing_still_resets() {
        // Attribute claims 5 value bytes but only 1 remains.
        let attrs = [0x40, ATTR_ORIGIN, 5, 0];
        assert!(matches!(
            parse_update(&body_with(&attrs), &HashSet::new(), false),
            Err(WireError::MalformedUpdate)
        ));
    }

    #[test]
    fn as_zero_update_is_treated_as_withdraw() {
        let mut attrs = vec![
            0x40,
            ATTR_ORIGIN,
            1,
            0,
            0x40,
            ATTR_AS_PATH,
            6,
            2,
            1,
            0,
            0,
            0,
            0,
        ];
        attrs.extend_from_slice(&[0x40, ATTR_NEXT_HOP, 4, 10, 0, 0, 1]);
        let u = parse_update(&body_with(&attrs), &HashSet::new(), false).unwrap();
        assert!(u.nlri.is_empty() && u.attributes.is_none());
        assert_eq!(u.withdrawn_routes.len(), 1);
    }

    #[test]
    fn withdraw_carries_add_path_ids() {
        let add_path = HashSet::from([AFI_IPV4]);
        let mut attrs = valid_attrs();
        attrs.extend_from_slice(&[0x80, ATTR_COMMUNITY, 1, 0]);
        // ADD-PATH NLRI: path id 7, 10.0.0.0/8
        let mut body = vec![0u8, 0u8];
        body.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&attrs);
        body.extend_from_slice(&[0, 0, 0, 7, 8, 10]);
        let u = parse_update(&body, &add_path, false).unwrap();
        assert_eq!(u.withdrawn_path_ids, vec![7]);
        assert_eq!(u.withdrawn_routes.len(), 1);
    }

    #[test]
    fn pure_withdrawal_with_bad_attribute_is_unchanged() {
        let mut body = vec![0u8, 2, 8, 10];
        let attrs = [0x80, ATTR_COMMUNITY, 1, 0];
        body.extend_from_slice(&[0, 4]);
        body.extend_from_slice(&attrs);
        let u = parse_update(&body, &HashSet::new(), false).unwrap();
        assert_eq!(u.withdrawn_routes, vec!["10.0.0.0/8".parse().unwrap()]);
        assert!(u.attributes.is_none() && u.mp_unreach.is_empty());
    }

    #[test]
    fn update_with_out_of_range_prefix_length_is_malformed() {
        // withdrawn_routes: one entry with an invalid prefix length (33).
        let body = vec![0u8, 2u8, 33u8, 10u8];
        assert!(matches!(
            parse_update(&body, &HashSet::new(), false),
            Err(WireError::MalformedUpdate)
        ));
    }

    #[test]
    fn update_truncated_prefix_data_is_malformed() {
        // withdrawn_routes: declares a /24 (needs 3 octets) but only 1 byte
        // of address data follows before the section's declared length ends.
        let body = vec![0u8, 2u8, 24u8, 10u8];
        assert!(matches!(
            parse_update(&body, &HashSet::new(), false),
            Err(WireError::MalformedUpdate)
        ));
    }

    #[test]
    fn bad_marker_is_rejected() {
        let mut buf = BytesMut::new();
        buf.put_slice(&[0u8; 16]);
        buf.put_u16(19);
        buf.put_u8(4);
        let mut codec = BgpCodec::default();
        assert!(matches!(codec.decode(&mut buf), Err(WireError::BadMarker)));
    }

    #[test]
    fn length_below_header_is_rejected() {
        let mut buf = BytesMut::new();
        buf.put_slice(&MARKER);
        buf.put_u16(18);
        buf.put_u8(4);
        let mut codec = BgpCodec::default();
        assert!(matches!(
            codec.decode(&mut buf),
            Err(WireError::BadLength(18))
        ));
    }

    #[test]
    fn length_above_max_is_rejected() {
        let mut buf = BytesMut::new();
        buf.put_slice(&MARKER);
        buf.put_u16(4097);
        buf.put_u8(4);
        let mut codec = BgpCodec::default();
        assert!(matches!(
            codec.decode(&mut buf),
            Err(WireError::BadLength(4097))
        ));
    }

    #[test]
    fn partial_message_returns_none() {
        let mut buf = BytesMut::new();
        buf.put_slice(&MARKER);
        buf.put_u16(30);
        buf.put_u8(1);
        // Missing the rest of the OPEN body.
        let mut codec = BgpCodec::default();
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn is_valid_bgp_identifier_rejects_special_cases() {
        assert!(!is_valid_bgp_identifier(Ipv4Addr::UNSPECIFIED));
        assert!(!is_valid_bgp_identifier(Ipv4Addr::BROADCAST));
        assert!(!is_valid_bgp_identifier(Ipv4Addr::new(224, 0, 0, 1)));
        assert!(is_valid_bgp_identifier(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn pmsi_tunnel_round_trips_and_other_tunnel_types_are_ignored() {
        let p = Pmsi {
            vni: 10100,
            tunnel_ip: "192.0.2.1".parse().unwrap(),
        };
        assert_eq!(decode_pmsi(&encode_pmsi(&p)), Some(p));
        assert_eq!(decode_pmsi(&[0, 2, 0, 0, 1, 1, 2, 3, 4]), None);
    }
}
