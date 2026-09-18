//! RFC 2328 Link State Advertisements: the header shared by every LSA type
//! (Appendix A.4.1) plus the two bodies this NOS implements — Router-LSA
//! (Appendix A.4.2) and Network-LSA (Appendix A.4.3). Pure encode/decode, no
//! I/O, same style as `packet.rs`.
//!
//! Router-LSA link **metric** is round-tripped as read/written here, but
//! nothing in this crate computes or consumes a real metric yet (no SPF) —
//! self-originated LSAs (a later phase) send a fixed `1`.
//!
//! AS-external/Summary LSAs (types 3/4/5) and multi-area ABR behavior are out
//! of scope, matching `ospf/CLAUDE.md`'s single-backbone-area ceiling.

use std::cmp::Ordering;
use std::net::Ipv4Addr;

use crate::packet::{read_ipv4, PacketError};

pub const LSA_TYPE_ROUTER: u8 = 1;
pub const LSA_TYPE_NETWORK: u8 = 2;

pub const LSA_HEADER_LEN: usize = 20;
/// One Router-LSA link entry's wire length (Appendix A.4.2): Link ID (4) +
/// Link Data (4) + Type (1) + # TOS (1, always 0 — no TOS metrics) + metric
/// (2).
const ROUTER_LINK_LEN: usize = 12;

/// RFC 2328 §13.1's `MaxAge` (seconds) — an LSA at this age is being flushed
/// and, per §13.1's tie-break, always treated as the newer instance.
pub const MAX_AGE: u16 = 3600;

/// RFC 2328 §12.1.6's `InitialSequenceNumber` — every self-originated LSA
/// starts here and increments by one on each refresh.
pub const INITIAL_SEQUENCE_NUMBER: i32 = i32::MIN + 1;

/// Identifies one LSA instance's slot in the database, independent of its
/// sequence number/age/checksum — RFC 2328 keys the LSDB by exactly these
/// three fields (§12.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LsaKey {
    pub lsa_type: u8,
    pub link_state_id: Ipv4Addr,
    pub advertising_router: Ipv4Addr,
}

/// RFC 2328 Appendix A.4.1's 20-byte common LSA header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LsaHeader {
    pub age: u16,
    pub options: u8,
    pub lsa_type: u8,
    pub link_state_id: Ipv4Addr,
    pub advertising_router: Ipv4Addr,
    /// RFC 2328 §12.1.6: a signed 32-bit space, `MinSequenceNumber =
    /// 0x8000_0001` through `MaxSequenceNumber = 0x7fff_ffff` — stored as
    /// `i32` so plain integer comparison gives the correct "which is newer"
    /// ordering the RFC intends.
    pub sequence_number: i32,
    /// RFC 905 Annex B Fletcher checksum — *not* `packet::checksum`'s RFC
    /// 1071 sum used by the OSPF common header.
    pub checksum: u16,
    /// Total LSA length in bytes, header included.
    pub length: u16,
}

impl LsaHeader {
    pub fn key(&self) -> LsaKey {
        LsaKey {
            lsa_type: self.lsa_type,
            link_state_id: self.link_state_id,
            advertising_router: self.advertising_router,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterLink {
    pub link_id: Ipv4Addr,
    pub link_data: Ipv4Addr,
    pub link_type: u8,
    pub metric: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLsaBody {
    pub flags: u8,
    pub links: Vec<RouterLink>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkLsaBody {
    pub network_mask: Ipv4Addr,
    pub attached_routers: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LsaBody {
    Router(RouterLsaBody),
    Network(NetworkLsaBody),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Lsa {
    pub header: LsaHeader,
    pub body: LsaBody,
}

pub(crate) fn encode_lsa_header(buf: &mut Vec<u8>, header: &LsaHeader) {
    buf.extend_from_slice(&header.age.to_be_bytes());
    buf.push(header.options);
    buf.push(header.lsa_type);
    buf.extend_from_slice(&header.link_state_id.octets());
    buf.extend_from_slice(&header.advertising_router.octets());
    buf.extend_from_slice(&header.sequence_number.to_be_bytes());
    buf.extend_from_slice(&header.checksum.to_be_bytes());
    buf.extend_from_slice(&header.length.to_be_bytes());
}

pub(crate) fn decode_lsa_header(data: &[u8]) -> Result<LsaHeader, PacketError> {
    if data.len() < LSA_HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    Ok(LsaHeader {
        age: u16::from_be_bytes([data[0], data[1]]),
        options: data[2],
        lsa_type: data[3],
        link_state_id: read_ipv4(data, 4),
        advertising_router: read_ipv4(data, 8),
        sequence_number: i32::from_be_bytes([data[12], data[13], data[14], data[15]]),
        checksum: u16::from_be_bytes([data[16], data[17]]),
        length: u16::from_be_bytes([data[18], data[19]]),
    })
}

pub(crate) fn encode_key(buf: &mut Vec<u8>, key: &LsaKey) {
    // RFC 2328 Appendix A.3.4's LS type field is nominally 32 bits wide but
    // only the low byte is ever non-zero.
    buf.extend_from_slice(&[0, 0, 0, key.lsa_type]);
    buf.extend_from_slice(&key.link_state_id.octets());
    buf.extend_from_slice(&key.advertising_router.octets());
}

pub(crate) const KEY_LEN: usize = 12;

pub(crate) fn decode_key(data: &[u8]) -> LsaKey {
    LsaKey {
        lsa_type: data[3],
        link_state_id: read_ipv4(data, 4),
        advertising_router: read_ipv4(data, 8),
    }
}

fn encode_body(body: &LsaBody) -> Vec<u8> {
    match body {
        LsaBody::Router(r) => {
            let mut buf = Vec::with_capacity(4 + r.links.len() * 12);
            buf.push(r.flags);
            buf.push(0); // reserved
            buf.extend_from_slice(
                &u16::try_from(r.links.len())
                    .unwrap_or(u16::MAX)
                    .to_be_bytes(),
            );
            for link in &r.links {
                buf.extend_from_slice(&link.link_id.octets());
                buf.extend_from_slice(&link.link_data.octets());
                buf.push(link.link_type);
                buf.push(0); // # TOS metrics: none supported
                buf.extend_from_slice(&link.metric.to_be_bytes());
            }
            buf
        }
        LsaBody::Network(n) => {
            let mut buf = Vec::with_capacity(4 + n.attached_routers.len() * 4);
            buf.extend_from_slice(&n.network_mask.octets());
            for router in &n.attached_routers {
                buf.extend_from_slice(&router.octets());
            }
            buf
        }
    }
}

fn decode_body(lsa_type: u8, data: &[u8]) -> Result<LsaBody, PacketError> {
    match lsa_type {
        LSA_TYPE_ROUTER => {
            if data.len() < 4 {
                return Err(PacketError::TruncatedBody);
            }
            let flags = data[0];
            let num_links = usize::from(u16::from_be_bytes([data[2], data[3]]));
            let link_bytes = &data[4..];
            if link_bytes.len() != num_links * ROUTER_LINK_LEN {
                return Err(PacketError::TruncatedBody);
            }
            let links = link_bytes
                .as_chunks::<ROUTER_LINK_LEN>()
                .0
                .iter()
                .map(|c| RouterLink {
                    link_id: read_ipv4(c, 0),
                    link_data: read_ipv4(c, 4),
                    link_type: c[8],
                    metric: u16::from_be_bytes([c[10], c[11]]),
                })
                .collect();
            Ok(LsaBody::Router(RouterLsaBody { flags, links }))
        }
        LSA_TYPE_NETWORK => {
            if data.len() < 4 || !(data.len() - 4).is_multiple_of(4) {
                return Err(PacketError::TruncatedBody);
            }
            let network_mask = read_ipv4(data, 0);
            let attached_routers = data[4..]
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                .collect();
            Ok(LsaBody::Network(NetworkLsaBody {
                network_mask,
                attached_routers,
            }))
        }
        other => Err(PacketError::UnknownLsaType(other)),
    }
}

/// Encodes `lsa`, overwriting `length`/`checksum` with freshly-computed
/// values (the caller's input header's own `length`/`checksum` are ignored,
/// mirroring `packet::encode_hello` filling in the checksum itself).
pub fn encode_lsa(lsa: &Lsa) -> Vec<u8> {
    let body = encode_body(&lsa.body);
    let total_len = LSA_HEADER_LEN + body.len();
    let mut header = lsa.header;
    header.length = u16::try_from(total_len).unwrap_or(u16::MAX);
    header.checksum = 0;

    let mut buf = Vec::with_capacity(total_len);
    encode_lsa_header(&mut buf, &header);
    buf.extend_from_slice(&body);

    let checksum = lsa_checksum(&buf[2..]);
    buf[16..18].copy_from_slice(&checksum.to_be_bytes());
    buf
}

/// Decodes one LSA from the start of `data` (which may contain more bytes
/// after it, e.g. a subsequent LSA in an LSU packet) — trusts the header's
/// own `length` field to find the end.
pub fn decode_lsa(data: &[u8]) -> Result<Lsa, PacketError> {
    let header = decode_lsa_header(data)?;
    let total_len = usize::from(header.length);
    if total_len < LSA_HEADER_LEN || data.len() < total_len {
        return Err(PacketError::TruncatedBody);
    }
    let computed = lsa_checksum(&data[2..total_len]);
    if computed != header.checksum {
        return Err(PacketError::BadChecksum);
    }
    let body = decode_body(header.lsa_type, &data[LSA_HEADER_LEN..total_len])?;
    Ok(Lsa { header, body })
}

/// RFC 2328 §12.1.7 / RFC 905 Annex B's Fletcher checksum, computed over an
/// LSA starting at the `options` field (i.e. `without_age` excludes the
/// 2-byte `age` field that precedes it) through the end of the body. The
/// 2-byte checksum field embedded at offset 14 of `without_age` (offset 16 of
/// the full LSA) is treated as zero regardless of its actual contents, so
/// this same function both computes a fresh checksum (`encode_lsa`) and
/// validates an existing one (`decode_lsa`, by comparing against the wire
/// value) without the caller needing to zero anything first.
fn lsa_checksum(without_age: &[u8]) -> u16 {
    const CHECKSUM_OFFSET: usize = 14;
    let mut c0: i64 = 0;
    let mut c1: i64 = 0;
    for (i, &b) in without_age.iter().enumerate() {
        let b = if i == CHECKSUM_OFFSET || i == CHECKSUM_OFFSET + 1 {
            0
        } else {
            b
        };
        c0 += i64::from(b);
        c1 += c0;
    }
    c0 %= 255;
    c1 %= 255;
    let mut x =
        (i64::try_from(without_age.len() - CHECKSUM_OFFSET - 1).unwrap_or(0) * c0 - c1) % 255;
    if x <= 0 {
        x += 255;
    }
    let mut y = 510 - c0 - x;
    if y > 255 {
        y -= 255;
    }
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let (x, y) = (x as u8, y as u8);
    (u16::from(x) << 8) | u16::from(y)
}

/// RFC 2328 §13.1's "which LSA instance is newer": higher sequence number
/// wins, then higher checksum, then an instance at `MAX_AGE` (being flushed)
/// is always considered newer than one that isn't. Returns `Ordering::Equal`
/// for what §13.1 calls "the same instance" — this deliberately doesn't
/// implement the `MaxAgeDiff` age-difference tie-break, since without a
/// running age-increment timer (see module doc) two genuinely-independent
/// instances converging here would never legitimately differ only by age.
pub fn is_newer(a: &LsaHeader, b: &LsaHeader) -> Ordering {
    if a.sequence_number != b.sequence_number {
        return a.sequence_number.cmp(&b.sequence_number);
    }
    if a.checksum != b.checksum {
        return a.checksum.cmp(&b.checksum);
    }
    match (a.age == MAX_AGE, b.age == MAX_AGE) {
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        _ => Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router_lsa() -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: LSA_TYPE_ROUTER,
                link_state_id: Ipv4Addr::new(9, 9, 9, 9),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: 0x8000_0001u32 as i32,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsaBody {
                flags: 0,
                links: vec![RouterLink {
                    link_id: Ipv4Addr::new(10, 0, 0, 1),
                    link_data: Ipv4Addr::new(255, 255, 255, 0),
                    link_type: 3,
                    metric: 1,
                }],
            }),
        }
    }

    fn network_lsa() -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: LSA_TYPE_NETWORK,
                link_state_id: Ipv4Addr::new(10, 0, 0, 1),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: 0x8000_0001u32 as i32,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Network(NetworkLsaBody {
                network_mask: Ipv4Addr::new(255, 255, 255, 0),
                attached_routers: vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(9, 9, 9, 10)],
            }),
        }
    }

    #[test]
    fn router_lsa_round_trips() {
        let lsa = router_lsa();
        let encoded = encode_lsa(&lsa);
        let decoded = decode_lsa(&encoded).unwrap();
        assert_eq!(decoded.header.lsa_type, lsa.header.lsa_type);
        assert_eq!(decoded.header.link_state_id, lsa.header.link_state_id);
        assert_eq!(decoded.body, lsa.body);
    }

    #[test]
    fn router_lsa_with_no_links_round_trips() {
        let mut lsa = router_lsa();
        lsa.body = LsaBody::Router(RouterLsaBody {
            flags: 0,
            links: Vec::new(),
        });
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.body, lsa.body);
    }

    #[test]
    fn network_lsa_round_trips() {
        let lsa = network_lsa();
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.body, lsa.body);
    }

    #[test]
    fn corrupted_checksum_is_rejected() {
        let mut encoded = encode_lsa(&router_lsa());
        let last = encoded.len() - 1;
        encoded[last] ^= 0xff;
        assert_eq!(decode_lsa(&encoded), Err(PacketError::BadChecksum));
    }

    #[test]
    fn unknown_lsa_type_is_rejected() {
        let mut lsa = router_lsa();
        lsa.header.lsa_type = 5;
        let encoded = encode_lsa(&lsa);
        assert_eq!(decode_lsa(&encoded), Err(PacketError::UnknownLsaType(5)));
    }

    #[test]
    fn higher_sequence_number_is_newer() {
        let a = router_lsa().header;
        let mut b = a;
        b.sequence_number += 1;
        assert_eq!(is_newer(&b, &a), Ordering::Greater);
        assert_eq!(is_newer(&a, &b), Ordering::Less);
    }

    #[test]
    fn equal_sequence_number_falls_back_to_checksum() {
        let a = router_lsa().header;
        let mut b = a;
        b.checksum += 1;
        assert_eq!(is_newer(&b, &a), Ordering::Greater);
    }

    #[test]
    fn max_age_is_always_newer_when_seq_and_checksum_tie() {
        let a = router_lsa().header;
        let mut b = a;
        b.age = MAX_AGE;
        assert_eq!(is_newer(&b, &a), Ordering::Greater);
        assert_eq!(is_newer(&a, &b), Ordering::Less);
    }

    #[test]
    fn identical_headers_are_equal() {
        let a = router_lsa().header;
        assert_eq!(is_newer(&a, &a), Ordering::Equal);
    }
}
