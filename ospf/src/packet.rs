//! RFC 2328 `OSPFv2` wire format — the common packet header (Appendix A.3.1)
//! plus the Hello packet body (Appendix A.3.2). Pure encode/decode, no I/O —
//! `socket.rs` sends/receives the bytes this module produces/consumes.
//!
//! Only what this crate implements needs (see `ospf/CLAUDE.md`): no
//! `DBD`/`LSR`/`LSU`/`LSAck` packet types, no LSAs.

use std::net::Ipv4Addr;

use thiserror::Error;

pub const VERSION: u8 = 2;
pub const TYPE_HELLO: u8 = 1;

const HEADER_LEN: usize = 24;
/// Hello body length excluding the trailing neighbor list: network mask,
/// hello-interval, options, router-priority, router-dead-interval,
/// designated-router, and backup-designated-router (4+2+1+1+4+4+4 bytes).
const HELLO_BODY_FIXED_LEN: usize = 20;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PacketError {
    #[error("packet shorter than the 24-byte OSPF header")]
    Truncated,
    #[error("not an OSPFv2 packet (version {0})")]
    BadVersion(u8),
    #[error("not a Hello packet (type {0})")]
    NotHello(u8),
    #[error("checksum mismatch")]
    BadChecksum,
    #[error("hello body shorter than expected")]
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

/// Encodes `pkt` as a Hello packet, computing and filling in the checksum.
pub fn encode_hello(pkt: &HelloPacket) -> Vec<u8> {
    let body_len = HELLO_BODY_FIXED_LEN + pkt.neighbors.len() * 4;
    let total_len = HEADER_LEN + body_len;
    let mut buf = Vec::with_capacity(total_len);

    // Common header (Appendix A.3.1).
    buf.push(VERSION);
    buf.push(TYPE_HELLO);
    // Always fits: `total_len` is `HEADER_LEN` + a handful of neighbor
    // entries, nowhere near `u16::MAX`.
    buf.extend_from_slice(&u16::try_from(total_len).unwrap_or(u16::MAX).to_be_bytes());
    buf.extend_from_slice(&pkt.router_id.octets());
    buf.extend_from_slice(&pkt.area_id.octets());
    buf.extend_from_slice(&0u16.to_be_bytes()); // checksum, filled in below
    buf.extend_from_slice(&0u16.to_be_bytes()); // AuType: none
    buf.extend_from_slice(&[0u8; 8]); // authentication: none

    // Hello body (Appendix A.3.2). Network mask stays zero/ignored — see
    // `HelloPacket`'s doc comment.
    buf.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets()); // network mask
    buf.extend_from_slice(&pkt.hello_interval.to_be_bytes());
    buf.push(0); // options
    buf.push(pkt.router_priority);
    buf.extend_from_slice(&pkt.dead_interval.to_be_bytes());
    buf.extend_from_slice(&pkt.designated_router.octets());
    buf.extend_from_slice(&pkt.backup_designated_router.octets());
    for n in &pkt.neighbors {
        buf.extend_from_slice(&n.octets());
    }

    debug_assert_eq!(buf.len(), total_len);
    let sum = checksum(&buf);
    buf[12..14].copy_from_slice(&sum.to_be_bytes());
    buf
}

/// Decodes a Hello packet, validating the common header and checksum first.
pub fn decode_hello(data: &[u8]) -> Result<HelloPacket, PacketError> {
    if data.len() < HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    let version = data[0];
    if version != VERSION {
        return Err(PacketError::BadVersion(version));
    }
    let packet_type = data[1];
    if packet_type != TYPE_HELLO {
        return Err(PacketError::NotHello(packet_type));
    }
    if checksum(data) != 0 {
        return Err(PacketError::BadChecksum);
    }

    let router_id = read_ipv4(data, 4);
    let area_id = read_ipv4(data, 8);

    let body = &data[HEADER_LEN..];
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

fn read_ipv4(data: &[u8], offset: usize) -> Ipv4Addr {
    Ipv4Addr::new(
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    )
}

/// RFC 2328 Appendix D.4.3's checksum: the standard RFC 1071 ones-complement-
/// of-ones-complement-sum used by IP/TCP/ICMP (**not** `OSPFv3`'s Fletcher
/// checksum, and not the LSA checksum, which uses Fletcher/RFC 905 Annex B —
/// neither applies here since this phase has no LSAs).
///
/// # ponytail: checksums the whole packet, auth field included
/// RFC 2328 excludes the 8-byte Authentication field from the sum, but this
/// phase always sends it zeroed — summing zero bytes is a no-op, so
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

    fn sample() -> HelloPacket {
        HelloPacket {
            router_id: Ipv4Addr::new(9, 9, 9, 9),
            area_id: Ipv4Addr::new(0, 0, 0, 0),
            hello_interval: 10,
            dead_interval: 40,
            router_priority: 1,
            designated_router: Ipv4Addr::new(9, 9, 9, 9),
            backup_designated_router: Ipv4Addr::new(9, 9, 9, 10),
            neighbors: vec![Ipv4Addr::new(9, 9, 9, 10)],
        }
    }

    #[test]
    fn round_trip_with_one_neighbor() {
        let pkt = sample();
        let encoded = encode_hello(&pkt);
        let decoded = decode_hello(&encoded).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn round_trip_with_no_neighbors() {
        let mut pkt = sample();
        pkt.neighbors = Vec::new();
        let encoded = encode_hello(&pkt);
        let decoded = decode_hello(&encoded).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn round_trip_with_two_neighbors() {
        let mut pkt = sample();
        pkt.neighbors = vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(2, 2, 2, 2)];
        let encoded = encode_hello(&pkt);
        let decoded = decode_hello(&encoded).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn round_trip_preserves_dr_bdr_and_priority() {
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
    fn corrupted_checksum_is_rejected() {
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
        encoded[1] = 2;
        assert_eq!(decode_hello(&encoded), Err(PacketError::NotHello(2)));
    }

    #[test]
    fn truncated_body_is_rejected() {
        let mut encoded = encode_hello(&sample());
        // Recompute the checksum over a body truncated mid-neighbor-list so
        // BadChecksum doesn't mask the body-length check.
        encoded.truncate(HEADER_LEN + HELLO_BODY_FIXED_LEN + 2);
        encoded[12..14].copy_from_slice(&0u16.to_be_bytes());
        let sum = checksum(&encoded);
        encoded[12..14].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(decode_hello(&encoded), Err(PacketError::TruncatedBody));
    }
}
