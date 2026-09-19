//! RFC 2328 Link State Advertisements: the header shared by every LSA type
//! (Appendix A.4.1) plus the two bodies this NOS implements — Router-LSA
//! (Appendix A.4.2) and Network-LSA (Appendix A.4.3). Pure encode/decode, no
//! I/O, same style as `packet.rs`.
//!
//! Router-LSA link **metric** and the three link types (point-to-point,
//! transit-network, stub-network) are real inputs to `crate::spf`'s RFC
//! 2328 §16.1/§16.2 Dijkstra — self-originated LSAs (`crate::link`) send a
//! link's configured `OspfProfile.cost` and always advertise a stub-network
//! link for a point-to-point interface's own subnet, real transit-network
//! masks included.
//!
//! AS-external-LSA (type 5, Appendix A.4.5) is implemented for ASBR-only
//! redistribution (see `ospf/CLAUDE.md`'s "ASBR and AS-external-LSA
//! origination"), and Summary-LSA (types 3/4, Appendix A.4.4) is implemented
//! for a real, 2-area-scoped ABR mechanism (see `ospf/CLAUDE.md`'s "ABR and
//! Summary-LSA origination") — stub/NSSA areas, virtual links, and area-range
//! aggregation remain out of scope.

use std::cmp::Ordering;
use std::net::Ipv4Addr;

use crate::packet::{read_ipv4, PacketError};

pub const LSA_TYPE_ROUTER: u8 = 1;
pub const LSA_TYPE_NETWORK: u8 = 2;
pub const LSA_TYPE_NETWORK_SUMMARY: u8 = 3;
pub const LSA_TYPE_ASBR_SUMMARY: u8 = 4;
pub const LSA_TYPE_AS_EXTERNAL: u8 = 5;

/// RFC 2328 §12.4.1's Router-LSA link types.
pub const LINK_TYPE_POINT_TO_POINT: u8 = 1;
pub const LINK_TYPE_TRANSIT_NETWORK: u8 = 2;
pub const LINK_TYPE_STUB_NETWORK: u8 = 3;

pub const LSA_HEADER_LEN: usize = 20;
/// One Router-LSA link entry's wire length (Appendix A.4.2): Link ID (4) +
/// Link Data (4) + Type (1) + # TOS (1, always 0 — no TOS metrics) + metric
/// (2).
const ROUTER_LINK_LEN: usize = 12;

/// RFC 2328 §13.1's `MaxAge` (seconds) — an LSA at this age is being flushed
/// and, per §13.1's tie-break, always treated as the newer instance.
pub const MAX_AGE: u16 = 3600;

/// RFC 2328 §14's `LSRefreshTime` (seconds) — a self-originated LSA is
/// reoriginated once its own age reaches this, even with unchanged content,
/// so it never reaches `MAX_AGE` while its originator is still alive.
pub const LS_REFRESH_TIME: u16 = 1800;

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

/// RFC 2328 Appendix A.4.5's AS-external-LSA body.
///
/// `ponytail:` this crate only ever produces/consumes Type-1 external-route
/// semantics — `metric`'s top bit (RFC 2328's E-type flag, distinguishing
/// Type-1 from Type-2 metrics) is always forced to `0` on encode and always
/// masked off on decode, so a foreign/corrupt encoder's E-bit can never leak
/// into a value `crate::spf` sums. There is no Type-1/Type-2 comparison
/// machinery in `crate::spf` — nothing downstream needs the distinction, and
/// this NOS never produces a Type-2 route (see `spf::EXTERNAL_METRIC_CONSTANT`).
/// `forwarding_address` is decoded faithfully (so a foreign LSA never fails
/// to parse) but `crate::spf` only ever treats an external route as reachable
/// via the advertising ASBR's own next-hop — a non-zero forwarding address is
/// never resolved to an alternate one. Upgrade path for both: thread an
/// `e_type` and a resolved forwarding-address next-hop through
/// `spf::RouteEntry` if real Type-2/forwarding-address interop is ever
/// needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsExternalLsaBody {
    pub network_mask: Ipv4Addr,
    /// Low 24 bits only — the top byte's high bit (E-type) is always `0`.
    pub metric: u32,
    pub forwarding_address: Ipv4Addr,
    pub external_route_tag: u32,
}

/// Masks off the wire's E-type bit (RFC 2328 A.4.5) so it can never leak into
/// a value `crate::spf` treats as a plain additive cost — see
/// `AsExternalLsaBody`'s doc comment.
const EXTERNAL_METRIC_MASK: u32 = 0x00FF_FFFF;

/// RFC 2328 Appendix A.4.4's Summary-LSA body — one wire shape backs both
/// `LSA_TYPE_NETWORK_SUMMARY` (type 3) and `LSA_TYPE_ASBR_SUMMARY` (type 4);
/// only `LsaHeader.lsa_type` plus `link_state_id`'s conventional meaning (a
/// network's address for type 3, the ASBR's own router-id for type 4, with
/// `network_mask` conventionally `0.0.0.0` for type 4) distinguish them —
/// mirrors RFC 2328 itself, which defines an identical wire format for both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SummaryLsaBody {
    pub network_mask: Ipv4Addr,
    /// Low 24 bits only, reusing `EXTERNAL_METRIC_MASK` — RFC 2328 A.4.4's
    /// metric field is also a 24-bit value following a 1-byte TOS field; no
    /// TOS-metric list support, the same "# TOS metrics: none supported"
    /// simplification `RouterLsaBody`'s own links already use.
    pub metric: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LsaBody {
    Router(RouterLsaBody),
    Network(NetworkLsaBody),
    Summary(SummaryLsaBody),
    AsExternal(AsExternalLsaBody),
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
        LsaBody::AsExternal(e) => {
            let mut buf = Vec::with_capacity(16);
            buf.extend_from_slice(&e.network_mask.octets());
            buf.extend_from_slice(&(e.metric & EXTERNAL_METRIC_MASK).to_be_bytes());
            buf.extend_from_slice(&e.forwarding_address.octets());
            buf.extend_from_slice(&e.external_route_tag.to_be_bytes());
            buf
        }
        LsaBody::Summary(s) => {
            let mut buf = Vec::with_capacity(8);
            buf.extend_from_slice(&s.network_mask.octets());
            buf.extend_from_slice(&(s.metric & EXTERNAL_METRIC_MASK).to_be_bytes());
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
        LSA_TYPE_AS_EXTERNAL => {
            if data.len() < 16 {
                return Err(PacketError::TruncatedBody);
            }
            let network_mask = read_ipv4(data, 0);
            let metric =
                u32::from_be_bytes([data[4], data[5], data[6], data[7]]) & EXTERNAL_METRIC_MASK;
            let forwarding_address = read_ipv4(data, 8);
            let external_route_tag = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
            Ok(LsaBody::AsExternal(AsExternalLsaBody {
                network_mask,
                metric,
                forwarding_address,
                external_route_tag,
            }))
        }
        LSA_TYPE_NETWORK_SUMMARY | LSA_TYPE_ASBR_SUMMARY => {
            if data.len() < 8 {
                return Err(PacketError::TruncatedBody);
            }
            let network_mask = read_ipv4(data, 0);
            let metric =
                u32::from_be_bytes([data[4], data[5], data[6], data[7]]) & EXTERNAL_METRIC_MASK;
            Ok(LsaBody::Summary(SummaryLsaBody {
                network_mask,
                metric,
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
/// implement the `MaxAgeDiff` age-difference tie-break: a real age-increment
/// timer now runs (`link::LinkManager`'s age tick, see `lsdb::Lsdb::
/// age_and_evict`), but two instances that already tie on sequence number
/// and checksum are the same content regardless of stored age, so there's no
/// ambiguity left for `MaxAgeDiff` to resolve.
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
                sequence_number: 0x8000_0001u32.cast_signed(),
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
                sequence_number: 0x8000_0001u32.cast_signed(),
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
        lsa.header.lsa_type = 6;
        let encoded = encode_lsa(&lsa);
        assert_eq!(decode_lsa(&encoded), Err(PacketError::UnknownLsaType(6)));
    }

    fn as_external_lsa() -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: LSA_TYPE_AS_EXTERNAL,
                link_state_id: Ipv4Addr::new(192, 0, 2, 0),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: 0x8000_0001u32.cast_signed(),
                checksum: 0,
                length: 0,
            },
            body: LsaBody::AsExternal(AsExternalLsaBody {
                network_mask: Ipv4Addr::new(255, 255, 255, 0),
                metric: 20,
                forwarding_address: Ipv4Addr::UNSPECIFIED,
                external_route_tag: 0,
            }),
        }
    }

    #[test]
    fn as_external_lsa_round_trips() {
        let lsa = as_external_lsa();
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.body, lsa.body);
    }

    /// Hand-crafts raw wire bytes with the E-type bit set in the metric's top
    /// byte (bypassing `encode_body`'s own masking) to prove `decode_body`
    /// masks it off independently, not just as a side effect of what
    /// `encode_body` already stripped — see `AsExternalLsaBody`'s doc comment.
    #[test]
    fn as_external_lsa_metric_e_type_bit_masked_on_decode() {
        let header = LsaHeader {
            age: 0,
            options: 0,
            lsa_type: LSA_TYPE_AS_EXTERNAL,
            link_state_id: Ipv4Addr::new(192, 0, 2, 0),
            advertising_router: Ipv4Addr::new(9, 9, 9, 9),
            sequence_number: 0x8000_0001u32.cast_signed(),
            checksum: 0,
            length: u16::try_from(LSA_HEADER_LEN + 16).unwrap(),
        };
        let mut buf = Vec::new();
        encode_lsa_header(&mut buf, &header);
        buf.extend_from_slice(&Ipv4Addr::new(255, 255, 255, 0).octets());
        buf.extend_from_slice(&(0x0000_0014u32 | 0x8000_0000u32).to_be_bytes()); // metric=20, E-type bit set
        buf.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets());
        buf.extend_from_slice(&0u32.to_be_bytes());
        let checksum = lsa_checksum(&buf[2..]);
        buf[16..18].copy_from_slice(&checksum.to_be_bytes());

        let decoded = decode_lsa(&buf).unwrap();
        let LsaBody::AsExternal(e) = decoded.body else {
            panic!("expected as-external lsa")
        };
        assert_eq!(e.metric, 20);
    }

    fn summary_lsa(lsa_type: u8, link_state_id: Ipv4Addr, network_mask: Ipv4Addr) -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type,
                link_state_id,
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: 0x8000_0001u32.cast_signed(),
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Summary(SummaryLsaBody {
                network_mask,
                metric: 20,
            }),
        }
    }

    #[test]
    fn summary_lsa_type3_round_trips() {
        let lsa = summary_lsa(
            LSA_TYPE_NETWORK_SUMMARY,
            Ipv4Addr::new(192, 0, 2, 0),
            Ipv4Addr::new(255, 255, 255, 0),
        );
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.body, lsa.body);
    }

    #[test]
    fn summary_lsa_type4_round_trips() {
        // Type 4's link_state_id is conventionally the ASBR's own router-id
        // and network_mask is conventionally unspecified — same body shape,
        // proving one decode_body arm correctly serves both type bytes.
        let lsa = summary_lsa(
            LSA_TYPE_ASBR_SUMMARY,
            Ipv4Addr::new(7, 7, 7, 7),
            Ipv4Addr::UNSPECIFIED,
        );
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.body, lsa.body);
        assert_eq!(decoded.header.lsa_type, LSA_TYPE_ASBR_SUMMARY);
    }

    /// Mirrors `as_external_lsa_metric_e_type_bit_masked_on_decode`: hand-crafts
    /// raw wire bytes with a non-zero TOS byte in the metric word (bypassing
    /// `encode_body`'s own masking) to prove `decode_body` masks it off
    /// independently.
    #[test]
    fn summary_lsa_metric_tos_byte_masked_on_decode() {
        let header = LsaHeader {
            age: 0,
            options: 0,
            lsa_type: LSA_TYPE_NETWORK_SUMMARY,
            link_state_id: Ipv4Addr::new(192, 0, 2, 0),
            advertising_router: Ipv4Addr::new(9, 9, 9, 9),
            sequence_number: 0x8000_0001u32.cast_signed(),
            checksum: 0,
            length: u16::try_from(LSA_HEADER_LEN + 8).unwrap(),
        };
        let mut buf = Vec::new();
        encode_lsa_header(&mut buf, &header);
        buf.extend_from_slice(&Ipv4Addr::new(255, 255, 255, 0).octets());
        buf.extend_from_slice(&(0x0000_0014u32 | 0xFF00_0000u32).to_be_bytes()); // metric=20, TOS byte set
        let checksum = lsa_checksum(&buf[2..]);
        buf[16..18].copy_from_slice(&checksum.to_be_bytes());

        let decoded = decode_lsa(&buf).unwrap();
        let LsaBody::Summary(s) = decoded.body else {
            panic!("expected summary lsa")
        };
        assert_eq!(s.metric, 20);
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
