//! RFC 2328 `OSPFv2` wire format — the common packet header (Appendix A.3.1)
//! shared by every packet type, plus each type's own body: Hello (A.3.2),
//! Database Description (A.3.3), Link State Request (A.3.4), Link State
//! Update (A.3.5), and Link State Acknowledgment (A.3.6). Pure encode/decode,
//! no I/O — `socket.rs` sends/receives the bytes this module produces/
//! consumes.

use std::net::Ipv4Addr;

use thiserror::Error;

use crate::lsa::{self, Lsa, LsaHeader, LsaKey};

pub const VERSION: u8 = 2;
pub const TYPE_HELLO: u8 = 1;
pub const TYPE_DBD: u8 = 2;
pub const TYPE_LSR: u8 = 3;
pub const TYPE_LSU: u8 = 4;
pub const TYPE_LSACK: u8 = 5;

const HEADER_LEN: usize = 24;
/// Hello body length excluding the trailing neighbor list: network mask,
/// hello-interval, options, router-priority, router-dead-interval,
/// designated-router, and backup-designated-router (4+2+1+1+4+4+4 bytes).
const HELLO_BODY_FIXED_LEN: usize = 20;
/// DBD body length excluding the trailing LSA-header summary list: interface
/// MTU, options, flags, DD sequence number (2+1+1+4 bytes).
const DBD_BODY_FIXED_LEN: usize = 8;

const DBD_FLAG_MASTER: u8 = 0x01;
const DBD_FLAG_MORE: u8 = 0x02;
const DBD_FLAG_INIT: u8 = 0x04;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PacketError {
    #[error("packet shorter than the 24-byte OSPF header")]
    Truncated,
    #[error("not an OSPFv2 packet (version {0})")]
    BadVersion(u8),
    #[error("unrecognized OSPF packet type {0}")]
    UnknownType(u8),
    #[error("unrecognized LSA type {0}")]
    UnknownLsaType(u8),
    #[error("checksum mismatch")]
    BadChecksum,
    #[error("packet body shorter than expected")]
    TruncatedBody,
}

/// One Hello packet's contents. `network_mask` is still omitted — RFC 2328
/// §10.5 says to ignore it on a point-to-point/virtual link, and this NOS
/// never validates it on a broadcast link either (no address-mask-based
/// subnet check is implemented), so there's nothing meaningful to do with
/// it in either direction; it's sent as `0.0.0.0` and ignored on decode.
/// `router_priority`/`designated_router`/`backup_designated_router` are
/// real fields, used by `ospf::election`'s DR/BDR election on a `Broadcast`
/// link (sent, but functionally inert, on a `PointToPoint` one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloPacket {
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub hello_interval: u16,
    pub dead_interval: u32,
    pub router_priority: u8,
    pub designated_router: Ipv4Addr,
    pub backup_designated_router: Ipv4Addr,
    /// Router IDs this Hello lists as neighbors it has heard from. RFC 2328's
    /// full neighbor list — collapsed to 0 or 1 entries on a point-to-point
    /// link (which has at most one neighbor), but honestly a full list for
    /// a broadcast link's potentially many neighbors.
    pub neighbors: Vec<Ipv4Addr>,
}

/// One Database Description packet's contents (RFC 2328 Appendix A.3.3),
/// driving §10.6-10.8's master/slave negotiation and summary-list exchange.
#[derive(Debug, Clone, PartialEq)]
pub struct DbdPacket {
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub interface_mtu: u16,
    pub options: u8,
    /// "I"nit bit: this is the first packet in the exchange.
    pub init: bool,
    /// "M"ore bit: the sender has more summary list entries to send.
    pub more: bool,
    /// "MS" bit: the sender considers itself master for this exchange.
    pub master: bool,
    pub dd_sequence_number: u32,
    pub lsa_headers: Vec<LsaHeader>,
}

/// One Link State Request packet's contents (RFC 2328 Appendix A.3.4) — the
/// LSAs the sender is missing and wants a full copy of via LSU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsrPacket {
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub requests: Vec<LsaKey>,
}

/// One Link State Update packet's contents (RFC 2328 Appendix A.3.5) — real
/// LSAs being flooded or sent in response to an LSR.
#[derive(Debug, Clone, PartialEq)]
pub struct LsuPacket {
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub lsas: Vec<Lsa>,
}

/// One Link State Acknowledgment packet's contents (RFC 2328 Appendix
/// A.3.6) — explicit ack of one or more received LSAs, by header only.
#[derive(Debug, Clone, PartialEq)]
pub struct LsAckPacket {
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub lsa_headers: Vec<LsaHeader>,
}

/// Any one OSPF packet, tagged by its common-header type byte — the
/// dispatch point `socket::recv_packet`'s bytes are decoded through.
#[derive(Debug, Clone, PartialEq)]
pub enum OspfPacket {
    Hello(HelloPacket),
    Dbd(DbdPacket),
    Lsr(LsrPacket),
    Lsu(LsuPacket),
    LsAck(LsAckPacket),
}

/// Encodes `pkt` as a Hello packet, computing and filling in the checksum.
pub fn encode_hello(pkt: &HelloPacket) -> Vec<u8> {
    let mut body = Vec::with_capacity(HELLO_BODY_FIXED_LEN + pkt.neighbors.len() * 4);
    // Network mask stays zero/ignored — see `HelloPacket`'s doc comment.
    body.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets());
    body.extend_from_slice(&pkt.hello_interval.to_be_bytes());
    body.push(0); // options
    body.push(pkt.router_priority);
    body.extend_from_slice(&pkt.dead_interval.to_be_bytes());
    body.extend_from_slice(&pkt.designated_router.octets());
    body.extend_from_slice(&pkt.backup_designated_router.octets());
    for n in &pkt.neighbors {
        body.extend_from_slice(&n.octets());
    }
    encode_packet(TYPE_HELLO, pkt.router_id, pkt.area_id, &body)
}

/// Decodes a Hello packet, validating the common header and checksum first.
pub fn decode_hello(data: &[u8]) -> Result<HelloPacket, PacketError> {
    let (packet_type, router_id, area_id, body) = decode_header(data)?;
    if packet_type != TYPE_HELLO {
        return Err(PacketError::UnknownType(packet_type));
    }
    if checksum(data) != 0 {
        return Err(PacketError::BadChecksum);
    }
    if body.len() < HELLO_BODY_FIXED_LEN {
        return Err(PacketError::TruncatedBody);
    }
    let hello_interval = u16::from_be_bytes([body[4], body[5]]);
    let router_priority = body[7];
    let dead_interval = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
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
        hello_interval,
        dead_interval,
        router_priority,
        designated_router,
        backup_designated_router,
        neighbors,
    })
}

/// Encodes `pkt` as a DBD packet.
pub fn encode_dbd(pkt: &DbdPacket) -> Vec<u8> {
    let mut body =
        Vec::with_capacity(DBD_BODY_FIXED_LEN + pkt.lsa_headers.len() * lsa::LSA_HEADER_LEN);
    body.extend_from_slice(&pkt.interface_mtu.to_be_bytes());
    body.push(pkt.options);
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

/// Decodes a DBD packet, validating the common header and checksum first.
pub fn decode_dbd(data: &[u8]) -> Result<DbdPacket, PacketError> {
    let (packet_type, router_id, area_id, body) = decode_header(data)?;
    if packet_type != TYPE_DBD {
        return Err(PacketError::UnknownType(packet_type));
    }
    if checksum(data) != 0 {
        return Err(PacketError::BadChecksum);
    }
    if body.len() < DBD_BODY_FIXED_LEN {
        return Err(PacketError::TruncatedBody);
    }
    let interface_mtu = u16::from_be_bytes([body[0], body[1]]);
    let options = body[2];
    let flags = body[3];
    let dd_sequence_number = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);

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
        interface_mtu,
        options,
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

/// Decodes an LSR packet, validating the common header and checksum first.
pub fn decode_lsr(data: &[u8]) -> Result<LsrPacket, PacketError> {
    let (packet_type, router_id, area_id, body) = decode_header(data)?;
    if packet_type != TYPE_LSR {
        return Err(PacketError::UnknownType(packet_type));
    }
    if checksum(data) != 0 {
        return Err(PacketError::BadChecksum);
    }
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

/// Decodes an LSU packet, validating the common header and checksum first.
pub fn decode_lsu(data: &[u8]) -> Result<LsuPacket, PacketError> {
    let (packet_type, router_id, area_id, body) = decode_header(data)?;
    if packet_type != TYPE_LSU {
        return Err(PacketError::UnknownType(packet_type));
    }
    if checksum(data) != 0 {
        return Err(PacketError::BadChecksum);
    }
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

/// Decodes an `LSAck` packet, validating the common header and checksum first.
pub fn decode_lsack(data: &[u8]) -> Result<LsAckPacket, PacketError> {
    let (packet_type, router_id, area_id, body) = decode_header(data)?;
    if packet_type != TYPE_LSACK {
        return Err(PacketError::UnknownType(packet_type));
    }
    if checksum(data) != 0 {
        return Err(PacketError::BadChecksum);
    }
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

/// Encodes any OSPF packet by dispatching to its type's own encoder.
pub fn encode(pkt: &OspfPacket) -> Vec<u8> {
    match pkt {
        OspfPacket::Hello(p) => encode_hello(p),
        OspfPacket::Dbd(p) => encode_dbd(p),
        OspfPacket::Lsr(p) => encode_lsr(p),
        OspfPacket::Lsu(p) => encode_lsu(p),
        OspfPacket::LsAck(p) => encode_lsack(p),
    }
}

/// Decodes any OSPF packet by reading the common header's type byte and
/// dispatching to that type's own decoder — the multiplexing point
/// `link.rs` uses on every `socket::recv_packet` payload once it speaks more
/// than Hello.
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

/// Builds the 24-byte common header (Appendix A.3.1) around `body` and fills
/// in the checksum. Shared by every packet type's own `encode_*`.
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
    buf.extend_from_slice(&0u16.to_be_bytes()); // checksum, filled in below
    buf.extend_from_slice(&0u16.to_be_bytes()); // AuType: none
    buf.extend_from_slice(&[0u8; 8]); // authentication: none
    buf.extend_from_slice(body);

    debug_assert_eq!(buf.len(), total_len);
    let sum = checksum(&buf);
    buf[12..14].copy_from_slice(&sum.to_be_bytes());
    buf
}

/// Validates the common header's version and returns `(packet_type,
/// router_id, area_id, body)` — checksum is deliberately not checked here:
/// each packet type's own `decode_*` checks its expected type first, so a
/// packet of a different type never gets misinterpreted as a checksum
/// failure. Shared by every packet type's own `decode_*`.
fn decode_header(data: &[u8]) -> Result<(u8, Ipv4Addr, Ipv4Addr, &[u8]), PacketError> {
    if data.len() < HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    let version = data[0];
    if version != VERSION {
        return Err(PacketError::BadVersion(version));
    }
    let router_id = read_ipv4(data, 4);
    let area_id = read_ipv4(data, 8);
    Ok((data[1], router_id, area_id, &data[HEADER_LEN..]))
}

pub(crate) fn read_ipv4(data: &[u8], offset: usize) -> Ipv4Addr {
    Ipv4Addr::new(
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    )
}

/// RFC 2328 Appendix D.4.3's checksum: the standard RFC 1071 ones-complement-
/// of-ones-complement-sum used by IP/TCP/ICMP (**not** `OSPFv3`'s Fletcher
/// checksum, and not the LSA checksum — see `lsa::lsa_checksum` — which uses
/// Fletcher/RFC 905 Annex B instead).
///
/// # ponytail: checksums the whole packet, auth field included
/// RFC 2328 excludes the 8-byte Authentication field from the sum, but this
/// crate always sends it zeroed — summing zero bytes is a no-op, so
/// checksumming the whole packet (auth field and all) gives the identical
/// result with no special-cased byte range. Breaks the day OSPF
/// authentication is added: that upgrade must exclude bytes 16..24 here.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (chunks, remainder) = data.as_chunks::<2>();
    for chunk in chunks {
        sum += u32::from(u16::from_be_bytes(*chunk));
    }
    if let [last] = remainder {
        sum += u32::from(*last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // Always fits: the loop above reduces `sum` until it's below 1 << 16.
    u16::try_from(sum).map_or(0, |s| !s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::{LsaBody, NetworkLsaBody, RouterLsaBody};

    fn sample() -> HelloPacket {
        HelloPacket {
            router_id: Ipv4Addr::new(9, 9, 9, 9),
            area_id: Ipv4Addr::UNSPECIFIED,
            hello_interval: 10,
            dead_interval: 40,
            router_priority: 1,
            designated_router: Ipv4Addr::new(9, 9, 9, 9),
            backup_designated_router: Ipv4Addr::new(9, 9, 9, 10),
            neighbors: vec![Ipv4Addr::new(9, 9, 9, 10)],
        }
    }

    fn sample_dbd() -> DbdPacket {
        DbdPacket {
            router_id: Ipv4Addr::new(9, 9, 9, 9),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 1500,
            options: 0,
            init: true,
            more: true,
            master: true,
            dd_sequence_number: 42,
            lsa_headers: vec![LsaHeader {
                age: 1,
                options: 0,
                lsa_type: lsa::LSA_TYPE_ROUTER,
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
                lsa_type: lsa::LSA_TYPE_ROUTER,
                link_state_id: Ipv4Addr::new(9, 9, 9, 10),
                advertising_router: Ipv4Addr::new(9, 9, 9, 10),
            }],
        }
    }

    fn sample_lsu() -> LsuPacket {
        LsuPacket {
            router_id: Ipv4Addr::new(9, 9, 9, 9),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![
                Lsa {
                    header: LsaHeader {
                        age: 0,
                        options: 0,
                        lsa_type: lsa::LSA_TYPE_ROUTER,
                        link_state_id: Ipv4Addr::new(9, 9, 9, 9),
                        advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                        sequence_number: 0x8000_0001u32.cast_signed(),
                        checksum: 0,
                        length: 0,
                    },
                    body: LsaBody::Router(RouterLsaBody {
                        flags: 0,
                        links: Vec::new(),
                    }),
                },
                Lsa {
                    header: LsaHeader {
                        age: 0,
                        options: 0,
                        lsa_type: lsa::LSA_TYPE_NETWORK,
                        link_state_id: Ipv4Addr::new(10, 0, 0, 1),
                        advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                        sequence_number: 0x8000_0001u32.cast_signed(),
                        checksum: 0,
                        length: 0,
                    },
                    body: LsaBody::Network(NetworkLsaBody {
                        network_mask: Ipv4Addr::new(255, 255, 255, 0),
                        attached_routers: vec![Ipv4Addr::new(9, 9, 9, 9)],
                    }),
                },
            ],
        }
    }

    fn sample_lsack() -> LsAckPacket {
        LsAckPacket {
            router_id: Ipv4Addr::new(9, 9, 9, 9),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsa_headers: vec![LsaHeader {
                age: 1,
                options: 0,
                lsa_type: lsa::LSA_TYPE_ROUTER,
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
        let encoded = encode_hello(&pkt);
        let decoded = decode_hello(&encoded).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn hello_round_trip_with_no_neighbors() {
        let mut pkt = sample();
        pkt.neighbors = Vec::new();
        let encoded = encode_hello(&pkt);
        let decoded = decode_hello(&encoded).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn hello_round_trip_with_two_neighbors() {
        let mut pkt = sample();
        pkt.neighbors = vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(2, 2, 2, 2)];
        let encoded = encode_hello(&pkt);
        let decoded = decode_hello(&encoded).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn hello_round_trip_preserves_dr_bdr_and_priority() {
        let pkt = sample();
        let decoded = decode_hello(&encode_hello(&pkt)).unwrap();
        assert_eq!(decoded.router_priority, pkt.router_priority);
        assert_eq!(decoded.designated_router, pkt.designated_router);
        assert_eq!(
            decoded.backup_designated_router,
            pkt.backup_designated_router
        );
    }

    #[test]
    fn hello_corrupted_checksum_is_rejected() {
        let mut encoded = encode_hello(&sample());
        let last = encoded.len() - 1;
        encoded[last] ^= 0xff;
        assert_eq!(decode_hello(&encoded), Err(PacketError::BadChecksum));
    }

    #[test]
    fn truncated_header_is_rejected() {
        assert_eq!(decode_hello(&[0u8; 10]), Err(PacketError::Truncated));
    }

    #[test]
    fn wrong_version_is_rejected() {
        let mut encoded = encode_hello(&sample());
        encoded[0] = 3;
        // Corrupting the version also invalidates the checksum, but version
        // is checked first.
        assert_eq!(decode_hello(&encoded), Err(PacketError::BadVersion(3)));
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
        // Recompute the checksum over a body truncated mid-neighbor-list so
        // BadChecksum doesn't mask the body-length check.
        encoded.truncate(HEADER_LEN + HELLO_BODY_FIXED_LEN + 2);
        encoded[12..14].copy_from_slice(&0u16.to_be_bytes());
        let sum = checksum(&encoded);
        encoded[12..14].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(decode_hello(&encoded), Err(PacketError::TruncatedBody));
    }

    #[test]
    fn dbd_round_trips() {
        let pkt = sample_dbd();
        let decoded = decode_dbd(&encode_dbd(&pkt)).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn dbd_round_trips_with_no_summary_entries() {
        let mut pkt = sample_dbd();
        pkt.lsa_headers = Vec::new();
        pkt.init = false;
        pkt.more = false;
        pkt.master = false;
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
    fn lsr_round_trips_with_multiple_requests() {
        let mut pkt = sample_lsr();
        pkt.requests.push(LsaKey {
            lsa_type: lsa::LSA_TYPE_NETWORK,
            link_state_id: Ipv4Addr::new(10, 0, 0, 1),
            advertising_router: Ipv4Addr::new(9, 9, 9, 10),
        });
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
        assert_eq!(decoded.lsas[1].body, pkt.lsas[1].body);
    }

    #[test]
    fn lsu_round_trips_with_no_lsas() {
        let mut pkt = sample_lsu();
        pkt.lsas = Vec::new();
        let decoded = decode_lsu(&encode_lsu(&pkt)).unwrap();
        assert!(decoded.lsas.is_empty());
    }

    #[test]
    fn lsu_rejects_count_mismatch() {
        let mut encoded = encode_lsu(&sample_lsu());
        // Overstate the LSA count in the body without adding another LSA.
        let last_idx = HEADER_LEN + 3;
        encoded[last_idx] = 3;
        encoded[12..14].copy_from_slice(&0u16.to_be_bytes());
        let sum = checksum(&encoded);
        encoded[12..14].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(decode_lsu(&encoded), Err(PacketError::TruncatedBody));
    }

    #[test]
    fn lsack_round_trips() {
        let pkt = sample_lsack();
        let decoded = decode_lsack(&encode_lsack(&pkt)).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn lsack_round_trips_with_multiple_headers() {
        let mut pkt = sample_lsack();
        pkt.lsa_headers.push(LsaHeader {
            age: 2,
            options: 0,
            lsa_type: lsa::LSA_TYPE_NETWORK,
            link_state_id: Ipv4Addr::new(10, 0, 0, 1),
            advertising_router: Ipv4Addr::new(9, 9, 9, 9),
            sequence_number: 0x8000_0002u32.cast_signed(),
            checksum: 0x5678,
            length: 28,
        });
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
    fn dispatch_rejects_unknown_type() {
        let mut encoded = encode_hello(&sample());
        encoded[1] = 9;
        encoded[12..14].copy_from_slice(&0u16.to_be_bytes());
        let sum = checksum(&encoded);
        encoded[12..14].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(decode(&encoded), Err(PacketError::UnknownType(9)));
    }
}
