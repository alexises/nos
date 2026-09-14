//! RFC 4271 BGP-4 wire message format: header, OPEN, KEEPALIVE, NOTIFICATION,
//! UPDATE, plus the RFC 6793 four-octet AS number capability. This is BGP's
//! own wire contract with external routers, not an inter-NOS-daemon IPC
//! contract, so it lives here rather than in `nos-proto` (whose `IpcCodec` is
//! postcard-based and structurally incompatible with BGP's raw big-endian
//! format anyway).
//!
//! UPDATE support is IPv4-unicast-only (RFC 4271's base NLRI; MP-BGP/RFC 4760
//! for IPv6 is out of scope), decodes `ORIGIN`/`AS_PATH`/`NEXT_HOP`/`LOCAL_PREF`
//! path attributes and skips any other attribute type by its declared length
//! (never an error — the same philosophy `parse_optional_parameters` already
//! applies to unknown OPEN capabilities), and never emits RFC 6793's `AS4_PATH`
//! transition attribute (`AS_PATH` is always encoded with 4-byte ASNs, since
//! this NOS always advertises the four-octet AS number capability itself).
//! Any other/unknown message type still decodes as `BgpMessage::Unhandled` so
//! the codec never chokes on one arriving.

use std::net::Ipv4Addr;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use ipnet::Ipv4Net;
use tokio_util::codec::{Decoder, Encoder};

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

const OPT_PARAM_CAPABILITIES: u8 = 2;
const CAP_FOUR_OCTET_ASN: u8 = 65;

const ATTR_ORIGIN: u8 = 1;
const ATTR_AS_PATH: u8 = 2;
const ATTR_NEXT_HOP: u8 = 3;
const ATTR_LOCAL_PREF: u8 = 5;
/// RFC 4271 §4.3 attribute flag bit indicating a 2-byte (rather than 1-byte)
/// attribute length field follows the type byte.
const ATTR_FLAG_EXTENDED_LENGTH: u8 = 0x10;
/// Well-known transitive, per RFC 4271 §5 — the flag value this
/// implementation always encodes for `ORIGIN`/`AS_PATH`/`NEXT_HOP`/`LOCAL_PREF`.
const ATTR_FLAG_WELL_KNOWN_TRANSITIVE: u8 = 0x40;
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

/// RFC 4486 Cease subcodes actually used by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeaseSubcode {
    #[allow(dead_code)] // generic fallback, not yet triggered by any code path
    Other = 0,
    AdministrativeShutdown = 2,
    ConnectionCollisionResolution = 7,
}

/// An OPEN message. `four_octet_asn` is `Some` iff the peer's Capabilities
/// optional parameter carried capability 65 (RFC 6793) — see
/// `effective_remote_asn` for how to read the real ASN regardless of which
/// form it arrived in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenMessage {
    pub version: u8,
    pub my_as: u16,
    pub hold_time: u16,
    pub bgp_identifier: Ipv4Addr,
    pub four_octet_asn: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationMessage {
    pub error_code: u8,
    pub error_subcode: u8,
    pub data: Bytes,
}

/// RFC 4271 §4.3 `ORIGIN` path attribute values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Igp = 0,
    Egp = 1,
    Incomplete = 2,
}

/// The four path attributes this implementation understands. `local_pref` is
/// `Some` iff the wire message actually carried a `LOCAL_PREF` attribute — this
/// crate never invents one on decode (`rib.rs` applies the RFC 4271 §5.1.5
/// default only when propagating, not here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathAttributes {
    pub origin: Origin,
    /// Flattened `AS_SEQUENCE`(s), nearest hop first — `AS_SET` vs.
    /// `AS_SEQUENCE` segmentation is not preserved (documented simplification).
    pub as_path: Vec<u32>,
    pub next_hop: Ipv4Addr,
    pub local_pref: Option<u32>,
}

/// An RFC 4271 UPDATE message, IPv4-unicast-only. `attributes` is `Some` iff
/// `nlri` is non-empty — a pure withdrawal carries no path attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateMessage {
    pub withdrawn_routes: Vec<Ipv4Net>,
    pub nlri: Vec<Ipv4Net>,
    pub attributes: Option<PathAttributes>,
}

/// A decoded BGP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpMessage {
    Open(OpenMessage),
    Update(UpdateMessage),
    Keepalive,
    Notification(NotificationMessage),
    /// Any message type this crate doesn't parse a body for (unknown to this
    /// implementation).
    Unhandled {
        message_type: u8,
        body: Bytes,
    },
}

/// Builds this instance's own OPEN. `four_octet_asn` is always populated
/// once 4-octet-capable, regardless of whether `my_as` needed `AS_TRANS` —
/// RFC 6793 §4.1 recommends always advertising the capability, since it also
/// governs how the peer's OPEN is interpreted, not just how this one is
/// represented.
pub fn build_open(local_asn: u32, router_id: Ipv4Addr, hold_time: u16) -> OpenMessage {
    let my_as = u16::try_from(local_asn).unwrap_or(AS_TRANS);
    OpenMessage {
        version: BGP_VERSION,
        my_as,
        hold_time,
        bgp_identifier: router_id,
        four_octet_asn: Some(local_asn),
    }
}

/// The peer's real ASN, whether carried in the plain 2-byte field or (when
/// present) the four-octet AS number capability — falling back to the plain
/// field is what gives interop with peers that never send capability 65.
pub fn effective_remote_asn(open: &OpenMessage) -> u32 {
    open.four_octet_asn.unwrap_or(u32::from(open.my_as))
}

/// Rejects the well-known non-unicast special cases; anything else is
/// accepted (no check against one specific expected identifier).
pub fn is_valid_bgp_identifier(id: Ipv4Addr) -> bool {
    !id.is_unspecified() && !id.is_broadcast() && !id.is_multicast()
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BgpCodec;

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
            TYPE_UPDATE => BgpMessage::Update(parse_update(&body)?),
            TYPE_KEEPALIVE => {
                if !body.is_empty() {
                    return Err(WireError::BadLength(length));
                }
                BgpMessage::Keepalive
            }
            TYPE_NOTIFICATION => BgpMessage::Notification(parse_notification(&body)?),
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
            BgpMessage::Update(update) => (TYPE_UPDATE, encode_update(&update)),
            BgpMessage::Keepalive => (TYPE_KEEPALIVE, Vec::new()),
            BgpMessage::Notification(n) => (TYPE_NOTIFICATION, encode_notification(&n)),
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
    let four_octet_asn = parse_optional_parameters(&opt_params[..opt_param_len])?;

    Ok(OpenMessage {
        version,
        my_as,
        hold_time,
        bgp_identifier,
        four_octet_asn,
    })
}

/// Walks every optional parameter, skipping each by its own declared length
/// (so a capability after an unrecognized parameter is still found), looking
/// only for the four-octet AS number capability.
fn parse_optional_parameters(mut params: &[u8]) -> Result<Option<u32>, WireError> {
    let mut four_octet_asn = None;
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
            if let Some(asn) = parse_capabilities(param_value)? {
                four_octet_asn = Some(asn);
            }
        }
        params = &params[2 + param_len..];
    }
    Ok(four_octet_asn)
}

fn parse_capabilities(mut data: &[u8]) -> Result<Option<u32>, WireError> {
    let mut four_octet_asn = None;
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
        if cap_code == CAP_FOUR_OCTET_ASN && cap_len == 4 {
            four_octet_asn = Some(u32::from_be_bytes(cap_value.try_into().unwrap()));
        }
        data = &data[2 + cap_len..];
    }
    Ok(four_octet_asn)
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

fn encode_open(open: &OpenMessage) -> Vec<u8> {
    let mut opt_params = Vec::new();
    if let Some(asn) = open.four_octet_asn {
        opt_params.push(OPT_PARAM_CAPABILITIES);
        opt_params.push(6); // capability code(1) + capability length(1) + 4-byte ASN
        opt_params.push(CAP_FOUR_OCTET_ASN);
        opt_params.push(4);
        opt_params.extend_from_slice(&asn.to_be_bytes());
    }

    let mut body = Vec::with_capacity(10 + opt_params.len());
    body.push(open.version);
    body.extend_from_slice(&open.my_as.to_be_bytes());
    body.extend_from_slice(&open.hold_time.to_be_bytes());
    body.extend_from_slice(&open.bgp_identifier.octets());
    body.push(u8::try_from(opt_params.len()).expect("at most one capability, always fits in a u8"));
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
/// address, zero-padded. Decodes a `[prefix_len][octets...]` list that
/// continues until the byte slice is exhausted (both withdrawn-routes and
/// NLRI use this same encoding, with no count field of their own — the
/// caller already knows where the list ends).
fn decode_prefixes(mut data: &[u8]) -> Result<Vec<Ipv4Net>, WireError> {
    let mut prefixes = Vec::new();
    while !data.is_empty() {
        let prefix_len = data[0];
        if prefix_len > 32 {
            return Err(WireError::MalformedUpdate);
        }
        let byte_len = usize::from(prefix_len).div_ceil(8);
        if data.len() < 1 + byte_len {
            return Err(WireError::MalformedUpdate);
        }
        let mut octets = [0u8; 4];
        octets[..byte_len].copy_from_slice(&data[1..=byte_len]);
        let net = Ipv4Net::new(Ipv4Addr::from(octets), prefix_len)
            .map_err(|_| WireError::MalformedUpdate)?;
        prefixes.push(net);
        data = &data[1 + byte_len..];
    }
    Ok(prefixes)
}

fn encode_prefix(net: Ipv4Net, out: &mut Vec<u8>) {
    let prefix_len = net.prefix_len();
    let byte_len = usize::from(prefix_len).div_ceil(8);
    out.push(prefix_len);
    out.extend_from_slice(&net.addr().octets()[..byte_len]);
}

fn encode_prefixes(nets: &[Ipv4Net]) -> Vec<u8> {
    let mut out = Vec::new();
    for net in nets {
        encode_prefix(*net, &mut out);
    }
    out
}

/// The four attributes `parse_path_attributes` looks for, each `Some` only
/// if the message actually carried it.
type ParsedAttributeFields = (
    Option<Origin>,
    Option<Vec<u32>>,
    Option<Ipv4Addr>,
    Option<u32>,
);

/// Walks the TLV path-attribute list, decoding `ORIGIN`/`AS_PATH`/`NEXT_HOP`/
/// `LOCAL_PREF` and skipping anything else by its own declared length
/// (mirrors `parse_optional_parameters`'s handling of unknown OPEN
/// capabilities). Returns each attribute's value only if the message
/// actually carried it — callers decide mandatory-attribute enforcement,
/// since that depends on whether the UPDATE carries any NLRI at all.
fn parse_path_attributes(mut data: &[u8]) -> Result<ParsedAttributeFields, WireError> {
    let mut origin = None;
    let mut as_path = None;
    let mut next_hop = None;
    let mut local_pref = None;

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

        match attr_type {
            ATTR_ORIGIN => {
                if value.len() != 1 {
                    return Err(WireError::MalformedUpdate);
                }
                origin = Some(match value[0] {
                    0 => Origin::Igp,
                    1 => Origin::Egp,
                    2 => Origin::Incomplete,
                    _ => return Err(WireError::MalformedUpdate),
                });
            }
            ATTR_AS_PATH => as_path = Some(parse_as_path(value)?),
            ATTR_NEXT_HOP => {
                if value.len() != 4 {
                    return Err(WireError::MalformedUpdate);
                }
                next_hop = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
            }
            ATTR_LOCAL_PREF => {
                if value.len() != 4 {
                    return Err(WireError::MalformedUpdate);
                }
                local_pref = Some(u32::from_be_bytes(value.try_into().unwrap()));
            }
            _ => {
                // Unknown attribute type: skip by declared length, never an
                // error — same philosophy as unrecognized OPEN capabilities.
            }
        }

        data = &data[header_len + len..];
    }

    Ok((origin, as_path, next_hop, local_pref))
}

/// Flattens one or more `AS_PATH` segments (`segment_type(1) count(1)
/// count*4 bytes`) into a single `Vec<u32>`, regardless of `AS_SEQUENCE` vs.
/// `AS_SET` (documented simplification — this crate never distinguishes them).
fn parse_as_path(mut data: &[u8]) -> Result<Vec<u32>, WireError> {
    let mut asns = Vec::new();
    while !data.is_empty() {
        if data.len() < 2 {
            return Err(WireError::MalformedUpdate);
        }
        let count = usize::from(data[1]);
        let segment_len = 2 + count * 4;
        if data.len() < segment_len {
            return Err(WireError::MalformedUpdate);
        }
        let mut asn_data = &data[2..segment_len];
        for _ in 0..count {
            asns.push(u32::from_be_bytes(asn_data[..4].try_into().unwrap()));
            asn_data = &asn_data[4..];
        }
        data = &data[segment_len..];
    }
    Ok(asns)
}

/// Parses an UPDATE body: withdrawn-routes (u16 length + packed prefixes),
/// path attributes (u16 length + TLV list), then NLRI (everything
/// remaining — RFC 4271 has no explicit NLRI length field, since the outer
/// message header's length already delimits it). If `nlri` is non-empty,
/// `ORIGIN`/`AS_PATH`/`NEXT_HOP` must all have been present or this is
/// `MalformedUpdate`; if `nlri` is empty (a pure withdrawal), `attributes`
/// is `None`, discarding any attributes present.
fn parse_update(body: &[u8]) -> Result<UpdateMessage, WireError> {
    if body.len() < 2 {
        return Err(WireError::MalformedUpdate);
    }
    let withdrawn_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
    let mut pos = 2;
    if body.len() < pos + withdrawn_len {
        return Err(WireError::MalformedUpdate);
    }
    let withdrawn_routes = decode_prefixes(&body[pos..pos + withdrawn_len])?;
    pos += withdrawn_len;

    if body.len() < pos + 2 {
        return Err(WireError::MalformedUpdate);
    }
    let attr_len = usize::from(u16::from_be_bytes([body[pos], body[pos + 1]]));
    pos += 2;
    if body.len() < pos + attr_len {
        return Err(WireError::MalformedUpdate);
    }
    let (origin, as_path, next_hop, local_pref) =
        parse_path_attributes(&body[pos..pos + attr_len])?;
    pos += attr_len;

    let nlri = decode_prefixes(&body[pos..])?;

    let attributes = if nlri.is_empty() {
        None
    } else {
        Some(PathAttributes {
            origin: origin.ok_or(WireError::MalformedUpdate)?,
            as_path: as_path.ok_or(WireError::MalformedUpdate)?,
            next_hop: next_hop.ok_or(WireError::MalformedUpdate)?,
            local_pref,
        })
    };

    Ok(UpdateMessage {
        withdrawn_routes,
        nlri,
        attributes,
    })
}

fn encode_attribute(out: &mut Vec<u8>, attr_type: u8, value: &[u8]) {
    if let Ok(len) = u8::try_from(value.len()) {
        out.push(ATTR_FLAG_WELL_KNOWN_TRANSITIVE);
        out.push(attr_type);
        out.push(len);
    } else {
        out.push(ATTR_FLAG_WELL_KNOWN_TRANSITIVE | ATTR_FLAG_EXTENDED_LENGTH);
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
/// iBGP peer, which never gets a local ASN prepended.
fn encode_as_path(asns: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in asns.chunks(MAX_AS_PATH_SEGMENT_LEN) {
        out.push(AS_PATH_SEGMENT_SEQUENCE);
        // `chunks(MAX_AS_PATH_SEGMENT_LEN)` never yields more than 255
        // elements per chunk, so this always fits in a u8.
        out.push(u8::try_from(chunk.len()).unwrap_or(u8::MAX));
        for asn in chunk {
            out.extend_from_slice(&asn.to_be_bytes());
        }
    }
    out
}

fn encode_path_attributes(attrs: &PathAttributes) -> Vec<u8> {
    let mut out = Vec::new();
    encode_attribute(&mut out, ATTR_ORIGIN, &[attrs.origin as u8]);
    encode_attribute(&mut out, ATTR_AS_PATH, &encode_as_path(&attrs.as_path));
    encode_attribute(&mut out, ATTR_NEXT_HOP, &attrs.next_hop.octets());
    if let Some(local_pref) = attrs.local_pref {
        encode_attribute(&mut out, ATTR_LOCAL_PREF, &local_pref.to_be_bytes());
    }
    out
}

/// Mirror image of `parse_update`. Byte lengths for the withdrawn-routes and
/// path-attributes sections always fit comfortably in a `u16` in practice —
/// the whole message is capped at `MAX_MESSAGE_LEN` (4096) bytes by
/// `BgpCodec::encode`, which will itself reject the overall frame if
/// something pathological ever made it larger.
fn encode_update(update: &UpdateMessage) -> Vec<u8> {
    let mut body = Vec::new();

    let withdrawn = encode_prefixes(&update.withdrawn_routes);
    body.extend_from_slice(
        &u16::try_from(withdrawn.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    body.extend_from_slice(&withdrawn);

    let attrs = update
        .attributes
        .as_ref()
        .map(encode_path_attributes)
        .unwrap_or_default();
    body.extend_from_slice(&u16::try_from(attrs.len()).unwrap_or(u16::MAX).to_be_bytes());
    body.extend_from_slice(&attrs);

    body.extend_from_slice(&encode_prefixes(&update.nlri));
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg: BgpMessage) -> BgpMessage {
        let mut codec = BgpCodec;
        let mut buf = BytesMut::new();
        codec.encode(msg, &mut buf).unwrap();
        codec.decode(&mut buf).unwrap().unwrap()
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
            four_octet_asn: None,
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
        assert_eq!(open.four_octet_asn, Some(4_200_000_000));
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
            build_open(65535, Ipv4Addr::LOCALHOST, 90).four_octet_asn,
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
            four_octet_asn: Some(4_200_000_000),
        };
        assert_eq!(effective_remote_asn(&with_cap), 4_200_000_000);

        let without_cap = OpenMessage {
            four_octet_asn: None,
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
        }
    }

    #[test]
    fn update_announce_roundtrips() {
        let update = UpdateMessage {
            withdrawn_routes: vec![],
            nlri: vec![
                "10.1.0.0/24".parse().unwrap(),
                "10.2.0.0/16".parse().unwrap(),
            ],
            attributes: Some(attrs(vec![65001, 65002], Some(200))),
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
            nlri: vec![],
            attributes: None,
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
            withdrawn_routes: vec![],
            nlri: vec!["10.0.0.0/8".parse().unwrap()],
            attributes: Some(attrs(long_path, None)),
        };
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update)
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

        let parsed = parse_update(&body).unwrap();
        assert_eq!(parsed.nlri, vec!["10.0.0.0/8".parse().unwrap()]);
        assert_eq!(
            parsed.attributes,
            Some(PathAttributes {
                origin: Origin::Igp,
                as_path: vec![],
                next_hop: Ipv4Addr::new(10, 0, 0, 1),
                local_pref: None,
            })
        );
    }

    #[test]
    fn update_with_nlri_but_missing_mandatory_attribute_is_malformed() {
        // withdrawn_routes length = 0, path attributes length = 0 (no
        // ORIGIN/AS_PATH/NEXT_HOP at all), nlri = 10.0.0.0/8.
        let mut body = vec![0u8, 0u8, 0u8, 0u8];
        body.extend_from_slice(&[8, 10]);
        assert!(matches!(
            parse_update(&body),
            Err(WireError::MalformedUpdate)
        ));
    }

    #[test]
    fn update_with_out_of_range_prefix_length_is_malformed() {
        // withdrawn_routes: one entry with an invalid prefix length (33).
        let body = vec![0u8, 2u8, 33u8, 10u8];
        assert!(matches!(
            parse_update(&body),
            Err(WireError::MalformedUpdate)
        ));
    }

    #[test]
    fn update_truncated_prefix_data_is_malformed() {
        // withdrawn_routes: declares a /24 (needs 3 octets) but only 1 byte
        // of address data follows before the section's declared length ends.
        let body = vec![0u8, 2u8, 24u8, 10u8];
        assert!(matches!(
            parse_update(&body),
            Err(WireError::MalformedUpdate)
        ));
    }

    #[test]
    fn bad_marker_is_rejected() {
        let mut buf = BytesMut::new();
        buf.put_slice(&[0u8; 16]);
        buf.put_u16(19);
        buf.put_u8(4);
        let mut codec = BgpCodec;
        assert!(matches!(codec.decode(&mut buf), Err(WireError::BadMarker)));
    }

    #[test]
    fn length_below_header_is_rejected() {
        let mut buf = BytesMut::new();
        buf.put_slice(&MARKER);
        buf.put_u16(18);
        buf.put_u8(4);
        let mut codec = BgpCodec;
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
        let mut codec = BgpCodec;
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
        let mut codec = BgpCodec;
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn is_valid_bgp_identifier_rejects_special_cases() {
        assert!(!is_valid_bgp_identifier(Ipv4Addr::UNSPECIFIED));
        assert!(!is_valid_bgp_identifier(Ipv4Addr::BROADCAST));
        assert!(!is_valid_bgp_identifier(Ipv4Addr::new(224, 0, 0, 1)));
        assert!(is_valid_bgp_identifier(Ipv4Addr::new(10, 0, 0, 1)));
    }
}
