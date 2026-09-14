//! RFC 4271 BGP-4 wire message format: header, OPEN, KEEPALIVE, NOTIFICATION,
//! plus the RFC 6793 four-octet AS number capability. This is BGP's own wire
//! contract with external routers, not an inter-NOS-daemon IPC contract, so
//! it lives here rather than in `nos-proto` (whose `IpcCodec` is postcard-
//! based and structurally incompatible with BGP's raw big-endian format
//! anyway).
//!
//! UPDATE message bodies are deliberately never parsed — route exchange is a
//! future feature. They (and any other/unknown type) decode as
//! `BgpMessage::Unhandled` so the codec never chokes on one arriving.

use std::net::Ipv4Addr;

use bytes::{Buf, BufMut, Bytes, BytesMut};
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
const TYPE_NOTIFICATION: u8 = 3;
const TYPE_KEEPALIVE: u8 = 4;

const OPT_PARAM_CAPABILITIES: u8 = 2;
const CAP_FOUR_OCTET_ASN: u8 = 65;

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
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// RFC 4271 §6 error codes, used in NOTIFICATION's `error_code` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    MessageHeader = 1,
    OpenMessage = 2,
    #[allow(dead_code)]
    // no UPDATE validation exists yet — kept for completeness of the RFC 4271 §6 table
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

/// A decoded BGP message. There is deliberately no `Update` variant — see
/// this module's doc comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpMessage {
    Open(OpenMessage),
    Keepalive,
    Notification(NotificationMessage),
    /// Any message type this crate doesn't parse a body for (UPDATE, or any
    /// type unknown to this implementation).
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
            message_type: 2, // UPDATE
            body: Bytes::from_static(b"not parsed"),
        }) {
            BgpMessage::Unhandled { message_type, body } => {
                assert_eq!(message_type, 2);
                assert_eq!(&body[..], b"not parsed");
            }
            other => panic!("expected Unhandled, got {other:?}"),
        }
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
