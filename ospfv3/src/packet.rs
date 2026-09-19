//! RFC 5340 `OSPFv3` wire format — the common packet header (§A.3.1) shared
//! by every packet type, plus each type's own body: Hello (§A.3.2), Database
//! Description (§A.3.3), Link State Request (§A.3.4), Link State Update
//! (§A.3.5), and Link State Acknowledgment (§A.3.6). Pure encode/decode, no
//! I/O — `socket.rs` sends/receives the bytes this module produces/consumes.
//!
//! Two real, deliberate differences from `ospf::packet` (RFC 2328's
//! counterpart), both scope decisions for Phase 1, not oversights:
//!
//! - **No authentication at all.** RFC 5340's 16-byte header (vs. v2's
//!   24-byte one) has no `AuType`/Authentication field — auth moved
//!   conceptually out-of-band (originally `IPsec`; RFC 6506 later added an
//!   in-packet HMAC trailer). Phase 1 runs unauthenticated; a future phase
//!   can add RFC 6506-shaped auth the same way `ospf`'s auth was a later
//!   phase, but it needs a new design, not a port of `ospf::packet`'s
//!   fixed-byte-offset auth mechanics (which have nowhere to attach here).
//! - **No checksum computed or verified in software.** RFC 5340's checksum
//!   (§A.3.1) is the standard IPv6 upper-layer checksum — ones'-complement
//!   over an IPv6 pseudo-header (source/dest address, upper-layer length,
//!   next-header=89) plus the packet, the same construction UDP/TCP/ICMPv6
//!   use, **not** `ospf::packet::checksum`'s bare RFC 1071 sum (which only
//!   ever covered the OSPF bytes themselves — no pseudo-header, since v2
//!   rides directly on IPv4 with no pseudo-header convention for protocol
//!   89). Reimplementing the pseudo-header sum by hand here would need this
//!   module to know the packet's own source/destination — properly a
//!   transport-layer concern. Instead, `socket.rs` sets `IPV6_CHECKSUM` on
//!   the raw socket (the same kernel facility Linux already uses for
//!   `ICMPv6`), so the kernel fills the checksum in on send and verifies (and
//!   silently drops bad packets before delivery) on receive — this module
//!   never sees a checksum mismatch, and doesn't need to. `header.checksum`
//!   is always written as `0` on encode and left unvalidated on decode.

use std::net::Ipv4Addr;

use thiserror::Error;

use crate::lsa::{self, Lsa, LsaHeader, LsaKey};

pub const VERSION: u8 = 3;
pub const TYPE_HELLO: u8 = 1;
pub const TYPE_DBD: u8 = 2;
pub const TYPE_LSR: u8 = 3;
pub const TYPE_LSU: u8 = 4;
pub const TYPE_LSACK: u8 = 5;

/// RFC 5838 multi-instance is out of scope for Phase 1 — every packet this
/// crate sends/expects carries Instance ID `0`.
const INSTANCE_ID: u8 = 0;

const HEADER_LEN: usize = 16;
/// Hello body length excluding the trailing neighbor list: Interface ID(4) +
/// Rtr Priority(1) + Options(3) + `HelloInterval`(2) + `RouterDeadInterval`(2)
/// + Designated Router(4) + Backup Designated Router(4).
const HELLO_BODY_FIXED_LEN: usize = 20;
/// DBD body length excluding the trailing LSA-header summary list:
/// Reserved(1) + Options(3) + Interface MTU(2) + Reserved(1) + Flags(1) + DD
/// sequence number(4).
const DBD_BODY_FIXED_LEN: usize = 12;

const DBD_FLAG_MASTER: u8 = 0x01;
const DBD_FLAG_MORE: u8 = 0x02;
const DBD_FLAG_INIT: u8 = 0x04;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PacketError {
    #[error("packet shorter than the 16-byte OSPFv3 header")]
    Truncated,
    #[error("not an OSPFv3 packet (version {0})")]
    BadVersion(u8),
    #[error("unrecognized OSPFv3 packet type {0}")]
    UnknownType(u8),
    #[error("unrecognized LSA type {0:#06x}")]
    UnknownLsaType(u16),
    #[error("packet body shorter than expected")]
    TruncatedBody,
    /// An LSA's own Fletcher-16 checksum (`lsa::lsa_checksum`) didn't match
    /// — unlike the OSPF packet header's checksum (kernel-verified via
    /// `IPV6_CHECKSUM`, see this module's doc comment), an LSA's checksum
    /// travels inside the packet body and is still validated in software,
    /// exactly like `ospf::packet::PacketError::BadChecksum`.
    #[error("lsa checksum mismatch")]
    BadChecksum,
}

/// One Hello packet's contents (§A.3.2). `designated_router`/
/// `backup_designated_router`/`neighbors` are Router IDs, not addresses — a
/// real RFC 5340 simplification vs. v2, where they're the DR/BDR's own IPv4
/// address (see `nos_ospf_common::election`'s doc comment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloPacket {
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub interface_id: u32,
    pub router_priority: u8,
    /// Low 24 bits only — see `lsa::OPTION_*`.
    pub options: u32,
    pub hello_interval: u16,
    pub dead_interval: u16,
    pub designated_router: Ipv4Addr,
    pub backup_designated_router: Ipv4Addr,
    pub neighbors: Vec<Ipv4Addr>,
}

/// One Database Description packet's contents (§A.3.3), driving RFC 2328
/// §10.6-10.8's master/slave negotiation and summary-list exchange
/// (unchanged by RFC 5340 beyond the widened LSA-type field inside
/// `lsa_headers`).
#[derive(Debug, Clone, PartialEq)]
pub struct DbdPacket {
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    /// Low 24 bits only.
    pub options: u32,
    pub interface_mtu: u16,
    pub init: bool,
    pub more: bool,
    pub master: bool,
    pub dd_sequence_number: u32,
    pub lsa_headers: Vec<LsaHeader>,
}

/// One Link State Request packet's contents (§A.3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsrPacket {
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub requests: Vec<LsaKey>,
}

/// One Link State Update packet's contents (§A.3.5).
#[derive(Debug, Clone, PartialEq)]
pub struct LsuPacket {
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub lsas: Vec<Lsa>,
}

/// One Link State Acknowledgment packet's contents (§A.3.6).
#[derive(Debug, Clone, PartialEq)]
pub struct LsAckPacket {
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub lsa_headers: Vec<LsaHeader>,
}

/// Any one `OSPFv3` packet, tagged by its common-header type byte.
#[derive(Debug, Clone, PartialEq)]
pub enum OspfPacket {
    Hello(HelloPacket),
    Dbd(DbdPacket),
    Lsr(LsrPacket),
    Lsu(LsuPacket),
    LsAck(LsAckPacket),
}

/// Encodes `pkt` as a Hello packet.
pub fn encode_hello(pkt: &HelloPacket) -> Vec<u8> {
    let mut body = Vec::with_capacity(HELLO_BODY_FIXED_LEN + pkt.neighbors.len() * 4);
    body.extend_from_slice(&pkt.interface_id.to_be_bytes());
    body.push(pkt.router_priority);
    body.extend_from_slice(&(pkt.options & 0x00FF_FFFF).to_be_bytes()[1..]);
    body.extend_from_slice(&pkt.hello_interval.to_be_bytes());
    body.extend_from_slice(&pkt.dead_interval.to_be_bytes());
    body.extend_from_slice(&pkt.designated_router.octets());
    body.extend_from_slice(&pkt.backup_designated_router.octets());
    for n in &pkt.neighbors {
        body.extend_from_slice(&n.octets());
    }
    encode_packet(TYPE_HELLO, pkt.router_id, pkt.area_id, &body)
}

/// Decodes a Hello packet, validating the common header first.
pub fn decode_hello(data: &[u8]) -> Result<HelloPacket, PacketError> {
    let (packet_type, router_id, area_id) = decode_header(data)?;
    if packet_type != TYPE_HELLO {
        return Err(PacketError::UnknownType(packet_type));
    }
    let body = &data[HEADER_LEN..];
    if body.len() < HELLO_BODY_FIXED_LEN {
        return Err(PacketError::TruncatedBody);
    }
    let interface_id = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let router_priority = body[4];
    let options = u32::from(body[5]) << 16 | u32::from(body[6]) << 8 | u32::from(body[7]);
    let hello_interval = u16::from_be_bytes([body[8], body[9]]);
    let dead_interval = u16::from_be_bytes([body[10], body[11]]);
    let designated_router = read_ipv4(body, 12);
    let backup_designated_router = read_ipv4(body, 16);

    let neighbor_bytes = &body[HELLO_BODY_FIXED_LEN..];
    if !neighbor_bytes.len().is_multiple_of(4) {
        return Err(PacketError::TruncatedBody);
    }
    let neighbors = neighbor_bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
        .collect();

    Ok(HelloPacket {
        router_id,
        area_id,
        interface_id,
        router_priority,
        options,
        hello_interval,
        dead_interval,
        designated_router,
        backup_designated_router,
        neighbors,
    })
}

/// Encodes `pkt` as a DBD packet.
pub fn encode_dbd(pkt: &DbdPacket) -> Vec<u8> {
    let mut body =
        Vec::with_capacity(DBD_BODY_FIXED_LEN + pkt.lsa_headers.len() * lsa::LSA_HEADER_LEN);
    body.push(0); // reserved
    body.extend_from_slice(&(pkt.options & 0x00FF_FFFF).to_be_bytes()[1..]);
    body.extend_from_slice(&pkt.interface_mtu.to_be_bytes());
    body.push(0); // reserved
    let mut flags = 0u8;
    if pkt.init {
        flags |= DBD_FLAG_INIT;
    }
    if pkt.more {
        flags |= DBD_FLAG_MORE;
    }
    if pkt.master {
        flags |= DBD_FLAG_MASTER;
    }
    body.push(flags);
    body.extend_from_slice(&pkt.dd_sequence_number.to_be_bytes());
    for header in &pkt.lsa_headers {
        lsa::encode_lsa_header(&mut body, header);
    }
    encode_packet(TYPE_DBD, pkt.router_id, pkt.area_id, &body)
}

/// Decodes a DBD packet, validating the common header first.
pub fn decode_dbd(data: &[u8]) -> Result<DbdPacket, PacketError> {
    let (packet_type, router_id, area_id) = decode_header(data)?;
    if packet_type != TYPE_DBD {
        return Err(PacketError::UnknownType(packet_type));
    }
    let body = &data[HEADER_LEN..];
    if body.len() < DBD_BODY_FIXED_LEN {
        return Err(PacketError::TruncatedBody);
    }
    let options = u32::from(body[1]) << 16 | u32::from(body[2]) << 8 | u32::from(body[3]);
    let interface_mtu = u16::from_be_bytes([body[4], body[5]]);
    let flags = body[7];
    let dd_sequence_number = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);

    let header_bytes = &body[DBD_BODY_FIXED_LEN..];
    if !header_bytes.len().is_multiple_of(lsa::LSA_HEADER_LEN) {
        return Err(PacketError::TruncatedBody);
    }
    let lsa_headers = header_bytes
        .as_chunks::<{ lsa::LSA_HEADER_LEN }>()
        .0
        .iter()
        .map(|c| lsa::decode_lsa_header(c))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(DbdPacket {
        router_id,
        area_id,
        options,
        interface_mtu,
        init: flags & DBD_FLAG_INIT != 0,
        more: flags & DBD_FLAG_MORE != 0,
        master: flags & DBD_FLAG_MASTER != 0,
        dd_sequence_number,
        lsa_headers,
    })
}

/// Encodes `pkt` as an LSR packet.
pub fn encode_lsr(pkt: &LsrPacket) -> Vec<u8> {
    let mut body = Vec::with_capacity(pkt.requests.len() * lsa::KEY_LEN);
    for key in &pkt.requests {
        lsa::encode_key(&mut body, key);
    }
    encode_packet(TYPE_LSR, pkt.router_id, pkt.area_id, &body)
}

/// Decodes an LSR packet, validating the common header first.
pub fn decode_lsr(data: &[u8]) -> Result<LsrPacket, PacketError> {
    let (packet_type, router_id, area_id) = decode_header(data)?;
    if packet_type != TYPE_LSR {
        return Err(PacketError::UnknownType(packet_type));
    }
    let body = &data[HEADER_LEN..];
    if !body.len().is_multiple_of(lsa::KEY_LEN) {
        return Err(PacketError::TruncatedBody);
    }
    let requests = body
        .as_chunks::<{ lsa::KEY_LEN }>()
        .0
        .iter()
        .map(|c| lsa::decode_key(c))
        .collect();
    Ok(LsrPacket {
        router_id,
        area_id,
        requests,
    })
}

/// Encodes `pkt` as an LSU packet.
pub fn encode_lsu(pkt: &LsuPacket) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        &u32::try_from(pkt.lsas.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for l in &pkt.lsas {
        body.extend_from_slice(&lsa::encode_lsa(l));
    }
    encode_packet(TYPE_LSU, pkt.router_id, pkt.area_id, &body)
}

/// Decodes an LSU packet, validating the common header first.
pub fn decode_lsu(data: &[u8]) -> Result<LsuPacket, PacketError> {
    let (packet_type, router_id, area_id) = decode_header(data)?;
    if packet_type != TYPE_LSU {
        return Err(PacketError::UnknownType(packet_type));
    }
    let body = &data[HEADER_LEN..];
    if body.len() < 4 {
        return Err(PacketError::TruncatedBody);
    }
    let count = usize::try_from(u32::from_be_bytes([body[0], body[1], body[2], body[3]]))
        .unwrap_or(usize::MAX);
    let mut rest = &body[4..];
    let mut lsas = Vec::with_capacity(count.min(rest.len() / lsa::LSA_HEADER_LEN + 1));
    while !rest.is_empty() {
        let l = lsa::decode_lsa(rest)?;
        let consumed = usize::from(l.header.length);
        lsas.push(l);
        rest = &rest[consumed..];
    }
    if lsas.len() != count {
        return Err(PacketError::TruncatedBody);
    }
    Ok(LsuPacket {
        router_id,
        area_id,
        lsas,
    })
}

/// Encodes `pkt` as an `LSAck` packet.
pub fn encode_lsack(pkt: &LsAckPacket) -> Vec<u8> {
    let mut body = Vec::with_capacity(pkt.lsa_headers.len() * lsa::LSA_HEADER_LEN);
    for header in &pkt.lsa_headers {
        lsa::encode_lsa_header(&mut body, header);
    }
    encode_packet(TYPE_LSACK, pkt.router_id, pkt.area_id, &body)
}

/// Decodes an `LSAck` packet, validating the common header first.
pub fn decode_lsack(data: &[u8]) -> Result<LsAckPacket, PacketError> {
    let (packet_type, router_id, area_id) = decode_header(data)?;
    if packet_type != TYPE_LSACK {
        return Err(PacketError::UnknownType(packet_type));
    }
    let body = &data[HEADER_LEN..];
    if !body.len().is_multiple_of(lsa::LSA_HEADER_LEN) {
        return Err(PacketError::TruncatedBody);
    }
    let lsa_headers = body
        .as_chunks::<{ lsa::LSA_HEADER_LEN }>()
        .0
        .iter()
        .map(|c| lsa::decode_lsa_header(c))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LsAckPacket {
        router_id,
        area_id,
        lsa_headers,
    })
}

/// Encodes any `OSPFv3` packet by dispatching to its type's own encoder.
pub fn encode(pkt: &OspfPacket) -> Vec<u8> {
    match pkt {
        OspfPacket::Hello(p) => encode_hello(p),
        OspfPacket::Dbd(p) => encode_dbd(p),
        OspfPacket::Lsr(p) => encode_lsr(p),
        OspfPacket::Lsu(p) => encode_lsu(p),
        OspfPacket::LsAck(p) => encode_lsack(p),
    }
}

/// Decodes any `OSPFv3` packet by reading the common header's type byte and
/// dispatching to that type's own decoder.
pub fn decode(data: &[u8]) -> Result<OspfPacket, PacketError> {
    if data.len() < HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    match data[1] {
        TYPE_HELLO => decode_hello(data).map(OspfPacket::Hello),
        TYPE_DBD => decode_dbd(data).map(OspfPacket::Dbd),
        TYPE_LSR => decode_lsr(data).map(OspfPacket::Lsr),
        TYPE_LSU => decode_lsu(data).map(OspfPacket::Lsu),
        TYPE_LSACK => decode_lsack(data).map(OspfPacket::LsAck),
        other => Err(PacketError::UnknownType(other)),
    }
}

/// The `router_id` any `OspfPacket` variant carries.
pub fn router_id(pkt: &OspfPacket) -> Ipv4Addr {
    match pkt {
        OspfPacket::Hello(p) => p.router_id,
        OspfPacket::Dbd(p) => p.router_id,
        OspfPacket::Lsr(p) => p.router_id,
        OspfPacket::Lsu(p) => p.router_id,
        OspfPacket::LsAck(p) => p.router_id,
    }
}

/// Builds the 16-byte common header (§A.3.1) around `body`. The checksum
/// field is always written as `0` — see this module's own doc comment for
/// why (`socket.rs`'s `IPV6_CHECKSUM` sockopt handles it at the kernel
/// level).
fn encode_packet(packet_type: u8, router_id: Ipv4Addr, area_id: Ipv4Addr, body: &[u8]) -> Vec<u8> {
    let total_len = HEADER_LEN + body.len();
    let mut buf = Vec::with_capacity(total_len);
    buf.push(VERSION);
    buf.push(packet_type);
    // Always fits: `total_len` is `HEADER_LEN` plus a handful of entries,
    // nowhere near `u16::MAX`.
    buf.extend_from_slice(&u16::try_from(total_len).unwrap_or(u16::MAX).to_be_bytes());
    buf.extend_from_slice(&router_id.octets());
    buf.extend_from_slice(&area_id.octets());
    buf.extend_from_slice(&0u16.to_be_bytes()); // checksum, kernel-filled
    buf.push(INSTANCE_ID);
    buf.push(0); // reserved
    buf.extend_from_slice(body);
    debug_assert_eq!(buf.len(), total_len);
    buf
}

/// Validates the common header's version and returns `(packet_type,
/// router_id, area_id)`.
fn decode_header(data: &[u8]) -> Result<(u8, Ipv4Addr, Ipv4Addr), PacketError> {
    if data.len() < HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    let version = data[0];
    if version != VERSION {
        return Err(PacketError::BadVersion(version));
    }
    let router_id = read_ipv4(data, 4);
    let area_id = read_ipv4(data, 8);
    Ok((data[1], router_id, area_id))
}

pub(crate) fn read_ipv4(data: &[u8], offset: usize) -> Ipv4Addr {
    Ipv4Addr::new(
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::{LsaBody, RouterLsaBody, LSA_TYPE_ROUTER};

    fn sample() -> HelloPacket {
        HelloPacket {
            router_id: Ipv4Addr::new(9, 9, 9, 9),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_id: 3,
            router_priority: 1,
            options: lsa::OPTION_V6 | lsa::OPTION_R,
            hello_interval: 10,
            dead_interval: 40,
            designated_router: Ipv4Addr::new(9, 9, 9, 9),
            backup_designated_router: Ipv4Addr::new(9, 9, 9, 10),
            neighbors: vec![Ipv4Addr::new(9, 9, 9, 10)],
        }
    }

    fn sample_dbd() -> DbdPacket {
        DbdPacket {
            router_id: Ipv4Addr::new(9, 9, 9, 9),
            area_id: Ipv4Addr::UNSPECIFIED,
            options: lsa::OPTION_V6 | lsa::OPTION_R,
            interface_mtu: 1500,
            init: true,
            more: true,
            master: true,
            dd_sequence_number: 42,
            lsa_headers: vec![LsaHeader {
                age: 1,
                lsa_type: LSA_TYPE_ROUTER,
                link_state_id: Ipv4Addr::new(9, 9, 9, 9),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: 0x8000_0001u32.cast_signed(),
                checksum: 0x1234,
                length: 24,
            }],
        }
    }

    fn sample_lsr() -> LsrPacket {
        LsrPacket {
            router_id: Ipv4Addr::new(9, 9, 9, 9),
            area_id: Ipv4Addr::UNSPECIFIED,
            requests: vec![LsaKey {
                lsa_type: LSA_TYPE_ROUTER,
                link_state_id: Ipv4Addr::new(9, 9, 9, 10),
                advertising_router: Ipv4Addr::new(9, 9, 9, 10),
            }],
        }
    }

    fn sample_lsu() -> LsuPacket {
        LsuPacket {
            router_id: Ipv4Addr::new(9, 9, 9, 9),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![Lsa {
                header: LsaHeader {
                    age: 0,
                    lsa_type: LSA_TYPE_ROUTER,
                    link_state_id: Ipv4Addr::new(9, 9, 9, 9),
                    advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                    sequence_number: 0x8000_0001u32.cast_signed(),
                    checksum: 0,
                    length: 0,
                },
                body: LsaBody::Router(RouterLsaBody {
                    flags: 0,
                    options: lsa::OPTION_V6 | lsa::OPTION_R,
                    links: Vec::new(),
                }),
            }],
        }
    }

    fn sample_lsack() -> LsAckPacket {
        LsAckPacket {
            router_id: Ipv4Addr::new(9, 9, 9, 9),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsa_headers: vec![LsaHeader {
                age: 1,
                lsa_type: LSA_TYPE_ROUTER,
                link_state_id: Ipv4Addr::new(9, 9, 9, 9),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: 0x8000_0001u32.cast_signed(),
                checksum: 0x1234,
                length: 24,
            }],
        }
    }

    #[test]
    fn hello_round_trip_with_one_neighbor() {
        let pkt = sample();
        let decoded = decode_hello(&encode_hello(&pkt)).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn hello_round_trip_with_no_neighbors() {
        let mut pkt = sample();
        pkt.neighbors = Vec::new();
        let decoded = decode_hello(&encode_hello(&pkt)).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn hello_round_trip_preserves_dr_bdr_as_router_ids() {
        let pkt = sample();
        let decoded = decode_hello(&encode_hello(&pkt)).unwrap();
        assert_eq!(decoded.designated_router, pkt.designated_router);
        assert_eq!(
            decoded.backup_designated_router,
            pkt.backup_designated_router
        );
        assert_eq!(decoded.interface_id, pkt.interface_id);
    }

    #[test]
    fn truncated_header_is_rejected() {
        assert_eq!(decode_hello(&[0u8; 10]), Err(PacketError::Truncated));
    }

    #[test]
    fn wrong_version_is_rejected() {
        let mut encoded = encode_hello(&sample());
        encoded[0] = 2;
        assert_eq!(decode_hello(&encoded), Err(PacketError::BadVersion(2)));
    }

    #[test]
    fn wrong_type_is_rejected() {
        let mut encoded = encode_hello(&sample());
        encoded[1] = TYPE_DBD;
        assert_eq!(
            decode_hello(&encoded),
            Err(PacketError::UnknownType(TYPE_DBD))
        );
    }

    #[test]
    fn hello_truncated_body_is_rejected() {
        let mut encoded = encode_hello(&sample());
        encoded.truncate(HEADER_LEN + HELLO_BODY_FIXED_LEN + 2);
        assert_eq!(decode_hello(&encoded), Err(PacketError::TruncatedBody));
    }

    #[test]
    fn dbd_round_trips() {
        let pkt = sample_dbd();
        let decoded = decode_dbd(&encode_dbd(&pkt)).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn dbd_flags_are_independent() {
        let mut pkt = sample_dbd();
        pkt.init = false;
        pkt.more = true;
        pkt.master = false;
        let decoded = decode_dbd(&encode_dbd(&pkt)).unwrap();
        assert!(!decoded.init);
        assert!(decoded.more);
        assert!(!decoded.master);
    }

    #[test]
    fn lsr_round_trips() {
        let pkt = sample_lsr();
        let decoded = decode_lsr(&encode_lsr(&pkt)).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn lsu_round_trips() {
        let pkt = sample_lsu();
        let decoded = decode_lsu(&encode_lsu(&pkt)).unwrap();
        assert_eq!(decoded.router_id, pkt.router_id);
        assert_eq!(decoded.lsas.len(), pkt.lsas.len());
        assert_eq!(decoded.lsas[0].body, pkt.lsas[0].body);
    }

    #[test]
    fn lsu_rejects_count_mismatch() {
        let mut encoded = encode_lsu(&sample_lsu());
        let last_idx = HEADER_LEN + 3;
        encoded[last_idx] = 3;
        assert_eq!(decode_lsu(&encoded), Err(PacketError::TruncatedBody));
    }

    #[test]
    fn lsack_round_trips() {
        let pkt = sample_lsack();
        let decoded = decode_lsack(&encode_lsack(&pkt)).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn dispatch_decodes_each_type_by_header_byte() {
        assert!(matches!(
            decode(&encode_hello(&sample())).unwrap(),
            OspfPacket::Hello(_)
        ));
        assert!(matches!(
            decode(&encode_dbd(&sample_dbd())).unwrap(),
            OspfPacket::Dbd(_)
        ));
        assert!(matches!(
            decode(&encode_lsr(&sample_lsr())).unwrap(),
            OspfPacket::Lsr(_)
        ));
        assert!(matches!(
            decode(&encode_lsu(&sample_lsu())).unwrap(),
            OspfPacket::Lsu(_)
        ));
        assert!(matches!(
            decode(&encode_lsack(&sample_lsack())).unwrap(),
            OspfPacket::LsAck(_)
        ));
    }

    #[test]
    fn dispatch_encode_round_trips_through_top_level_enum() {
        let pkt = OspfPacket::Dbd(sample_dbd());
        let decoded = decode(&encode(&pkt)).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn instance_id_is_always_zero() {
        let encoded = encode_hello(&sample());
        assert_eq!(encoded[12], 0);
    }
}
