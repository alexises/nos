//! RFC 5340 Link State Advertisements — the header shared by every LSA type
//! (§A.4.2.1) plus the four bodies needed for Phase 1 single-area intra-area
//! routing: Router-LSA (§A.4.3), Network-LSA (§A.4.4), Link-LSA (§A.4.9), and
//! Intra-Area-Prefix-LSA (§A.4.10). Pure encode/decode, no I/O, same style as
//! `ospf::lsa` (RFC 2328's counterpart) — but the two crates' body shapes
//! diverge completely: v3 restructures prefix-carrying entirely out of
//! Router-/Network-LSA (which in v3 carry pure topology, no addresses at
//! all) and into the two new LSA types here. Out of scope for Phase 1:
//! Inter-Area-Prefix-LSA/Inter-Area-Router-LSA (ABR), AS-External-LSA
//! (ASBR), NSSA.
//!
//! The 20-byte common header (§A.4.2.1) is the same total length as v2's,
//! but its shape differs: v3 has no separate `options` byte in the header at
//! all (each body carries its own `Options` field instead) and widens the
//! 8-bit type byte into a 16-bit `LS Type` word carrying the U-bit (flood-
//! if-unknown), the S2/S1 scope bits, and a 13-bit function code — see the
//! `LSA_TYPE_*` constants' doc comments for the bit layout. The header's
//! Fletcher-16 checksum (RFC 905 Annex B, `lsa_checksum`) and freshness
//! tie-break (`is_newer`) are otherwise byte-for-byte identical to v2's,
//! since RFC 5340 keeps RFC 2328 §13.1's LSA-header semantics unchanged —
//! ported verbatim rather than reimplemented.

use std::cmp::Ordering;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::Ipv6Net;

use crate::packet::{read_ipv4, PacketError};

/// RFC 5340 §A.4.2.1's Options bits, shared by Router-/Network-/Link-LSA
/// bodies (Intra-Area-Prefix-LSA has none). `V6` must always be set (this
/// router participates in IPv6 topology); `R` must always be set on
/// self-origination (clearing it silently excludes this router from other
/// routers' SPF — RFC 5340 §4.8.1 — a real correctness trap if forgotten).
/// `E` (ASBR-capable) stays clear: no ASBR support in Phase 1.
pub const OPTION_V6: u32 = 0x01;
pub const OPTION_E: u32 = 0x02;
pub const OPTION_R: u32 = 0x10;

/// S2/S1 scope bits (bits 14-13): `01` = area scope. The U-bit (bit 15,
/// "flood even if unrecognized") is left clear on every `LSA_TYPE_*`
/// constant below — every type this crate ever originates or requests is
/// known, so it never needs setting.
const SCOPE_AREA: u16 = 0x2000;
/// S2/S1 scope bits: `00` = link-local scope.
const SCOPE_LINK_LOCAL: u16 = 0x0000;

/// RFC 5340 §A.4.3 Router-LSA — area-scoped, function code 1.
pub const LSA_TYPE_ROUTER: u16 = SCOPE_AREA | 1;
/// RFC 5340 §A.4.4 Network-LSA — area-scoped, function code 2.
pub const LSA_TYPE_NETWORK: u16 = SCOPE_AREA | 2;
/// RFC 5340 §A.4.9 Link-LSA — link-local scoped (never flooded past the
/// originating link), function code 8.
pub const LSA_TYPE_LINK: u16 = SCOPE_LINK_LOCAL | 8;
/// RFC 5340 §A.4.10 Intra-Area-Prefix-LSA — area-scoped, function code 9.
pub const LSA_TYPE_INTRA_AREA_PREFIX: u16 = SCOPE_AREA | 9;

/// RFC 5340 §4.4.3.2's Router-LSA link types — identical values to
/// `OSPFv2`'s (RFC 5340 §A.4.3: "Values as in [OSPFV2]"). No stub-network
/// type in v3: a Router-LSA link never carries a prefix at all.
pub const LINK_TYPE_POINT_TO_POINT: u8 = 1;
pub const LINK_TYPE_TRANSIT_NETWORK: u8 = 2;

pub const LSA_HEADER_LEN: usize = 20;
/// One Router-LSA link entry's wire length (§A.4.3): Type(1) + Reserved(1) +
/// Metric(2) + Interface ID(4) + Neighbor Interface ID(4) + Neighbor Router
/// ID(4).
const ROUTER_LINK_LEN: usize = 16;

/// RFC 2328 §13.1's `MaxAge` (seconds, unchanged by RFC 5340) — an LSA at
/// this age is being flushed and, per §13.1's tie-break, always treated as
/// the newer instance.
pub const MAX_AGE: u16 = 3600;

/// RFC 2328 §14's `LSRefreshTime` (seconds, unchanged by RFC 5340) — a
/// self-originated LSA is reoriginated once its own age reaches this, even
/// with unchanged content, so it never reaches `MAX_AGE` while its
/// originator is still alive.
pub const LS_REFRESH_TIME: u16 = 1800;

/// RFC 2328 §12.1.6's `InitialSequenceNumber` (unchanged by RFC 5340) —
/// every self-originated LSA starts here and increments by one on each
/// refresh.
pub const INITIAL_SEQUENCE_NUMBER: i32 = i32::MIN + 1;

/// Identifies one LSA instance's slot in the database, independent of its
/// sequence number/age/checksum — RFC 5340 keeps RFC 2328 §12.2's keying.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LsaKey {
    pub lsa_type: u16,
    /// An opaque 32-bit value, never a real address — for Router-/Network-
    /// LSA it's the DR's Interface ID (Network-LSA) or unused (Router-LSA,
    /// conventionally the originating router's own id repeated); for
    /// Link-LSA it's the originating interface's own Interface ID; for
    /// Intra-Area-Prefix-LSA it's an arbitrary disambiguator. Stored as
    /// `Ipv4Addr` purely to reuse the same 4-byte octet codec every other
    /// 32-bit identifier in this codebase already uses (`router_id`,
    /// `area_id`), matching v2's own `LsaKey.link_state_id` convention —
    /// never interpreted as a real address.
    pub link_state_id: Ipv4Addr,
    pub advertising_router: Ipv4Addr,
}

/// RFC 5340 §A.4.2.1's 20-byte common LSA header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LsaHeader {
    pub age: u16,
    /// The full 16-bit `LS Type` word — U-bit, S2/S1 scope, and 13-bit
    /// function code all packed together, matching the wire exactly (unlike
    /// v2, there's no separate `options` header field to split out).
    pub lsa_type: u16,
    pub link_state_id: Ipv4Addr,
    pub advertising_router: Ipv4Addr,
    /// RFC 2328 §12.1.6 (unchanged by RFC 5340): `MinSequenceNumber =
    /// 0x8000_0001` through `MaxSequenceNumber = 0x7fff_ffff`, stored as
    /// `i32` so plain integer comparison gives the correct freshness order.
    pub sequence_number: i32,
    /// RFC 905 Annex B Fletcher checksum — identical algorithm to v2's LSA
    /// checksum, see `lsa_checksum`.
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
pub struct RouterLsaLink {
    pub link_type: u8,
    pub metric: u16,
    pub interface_id: u32,
    pub neighbor_interface_id: u32,
    pub neighbor_router_id: Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLsaBody {
    /// Top byte of the header word (RFC 5340 §A.4.3's Nt/x/V/E/B bits) —
    /// always `0` in Phase 1 (no virtual links, no ABR, no ASBR).
    pub flags: u8,
    /// Low 24 bits only.
    pub options: u32,
    pub links: Vec<RouterLsaLink>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkLsaBody {
    /// Low 24 bits only.
    pub options: u32,
    pub attached_routers: Vec<Ipv4Addr>,
}

/// One prefix entry as carried by a Link-LSA (§A.4.9) — no metric, unlike
/// `IntraAreaPrefixEntry`, since a Link-LSA's prefixes aren't themselves SPF
/// inputs, only material `link::originate_intra_area_prefix_lsas` later
/// republishes with a real cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkPrefixEntry {
    pub options: u8,
    pub prefix: Ipv6Net,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkLsaBody {
    pub priority: u8,
    /// Low 24 bits only.
    pub options: u32,
    pub link_local_address: Ipv6Addr,
    pub prefixes: Vec<LinkPrefixEntry>,
}

/// One prefix entry as carried by an Intra-Area-Prefix-LSA (§A.4.10) — real
/// SPF input, unlike `LinkPrefixEntry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntraAreaPrefixEntry {
    pub options: u8,
    pub metric: u16,
    pub prefix: Ipv6Net,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntraAreaPrefixLsaBody {
    /// §A.4.10: the full 16-bit LS Type of the referenced LSA — always
    /// `LSA_TYPE_ROUTER` (a router's own stub/loopback prefixes) or
    /// `LSA_TYPE_NETWORK` (a transit network's prefix) in this crate, never
    /// a bare function code.
    pub referenced_ls_type: u16,
    pub referenced_link_state_id: Ipv4Addr,
    pub referenced_advertising_router: Ipv4Addr,
    pub prefixes: Vec<IntraAreaPrefixEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LsaBody {
    Router(RouterLsaBody),
    Network(NetworkLsaBody),
    Link(LinkLsaBody),
    IntraAreaPrefix(IntraAreaPrefixLsaBody),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Lsa {
    pub header: LsaHeader,
    pub body: LsaBody,
}

pub(crate) fn encode_lsa_header(buf: &mut Vec<u8>, header: &LsaHeader) {
    buf.extend_from_slice(&header.age.to_be_bytes());
    buf.extend_from_slice(&header.lsa_type.to_be_bytes());
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
        lsa_type: u16::from_be_bytes([data[2], data[3]]),
        link_state_id: read_ipv4(data, 4),
        advertising_router: read_ipv4(data, 8),
        sequence_number: i32::from_be_bytes([data[12], data[13], data[14], data[15]]),
        checksum: u16::from_be_bytes([data[16], data[17]]),
        length: u16::from_be_bytes([data[18], data[19]]),
    })
}

/// RFC 5340 §A.3.4's Link State Request entry: Reserved(16) + LS Type(16) +
/// Link State ID(32) + Advertising Router(32) — 12 bytes, same length as
/// v2's (whose LS Type field is only 1 byte wide but padded to the same
/// 4-byte word).
pub(crate) const KEY_LEN: usize = 12;

pub(crate) fn encode_key(buf: &mut Vec<u8>, key: &LsaKey) {
    buf.extend_from_slice(&0u16.to_be_bytes()); // reserved
    buf.extend_from_slice(&key.lsa_type.to_be_bytes());
    buf.extend_from_slice(&key.link_state_id.octets());
    buf.extend_from_slice(&key.advertising_router.octets());
}

pub(crate) fn decode_key(data: &[u8]) -> LsaKey {
    LsaKey {
        lsa_type: u16::from_be_bytes([data[2], data[3]]),
        link_state_id: read_ipv4(data, 4),
        advertising_router: read_ipv4(data, 8),
    }
}

/// Bytes needed to hold a `/prefix_len` IPv6 prefix on the wire (RFC 5340
/// §A.4.1.1): `ceil(prefix_len / 32)` 32-bit words, zero-padded — never more
/// than 16 (the whole address) for any valid `prefix_len <= 128`.
fn prefix_wire_len(prefix_len: u8) -> usize {
    (usize::from(prefix_len).div_ceil(32)) * 4
}

fn encode_prefix(buf: &mut Vec<u8>, prefix: &Ipv6Net) {
    let truncated = prefix.trunc();
    let octets = truncated.addr().octets();
    buf.extend_from_slice(&octets[..prefix_wire_len(truncated.prefix_len())]);
}

fn decode_prefix(data: &[u8], prefix_len: u8) -> Result<(Ipv6Net, usize), PacketError> {
    if prefix_len > 128 {
        return Err(PacketError::TruncatedBody);
    }
    let wire_len = prefix_wire_len(prefix_len);
    if data.len() < wire_len {
        return Err(PacketError::TruncatedBody);
    }
    let mut octets = [0u8; 16];
    octets[..wire_len].copy_from_slice(&data[..wire_len]);
    let net =
        Ipv6Net::new(Ipv6Addr::from(octets), prefix_len).map_err(|_| PacketError::TruncatedBody)?;
    Ok((net, wire_len))
}

fn encode_body(body: &LsaBody) -> Vec<u8> {
    match body {
        LsaBody::Router(r) => {
            let mut buf = Vec::with_capacity(4 + r.links.len() * ROUTER_LINK_LEN);
            buf.push(r.flags);
            buf.extend_from_slice(&(r.options & 0x00FF_FFFF).to_be_bytes()[1..]);
            for link in &r.links {
                buf.push(link.link_type);
                buf.push(0); // reserved
                buf.extend_from_slice(&link.metric.to_be_bytes());
                buf.extend_from_slice(&link.interface_id.to_be_bytes());
                buf.extend_from_slice(&link.neighbor_interface_id.to_be_bytes());
                buf.extend_from_slice(&link.neighbor_router_id.octets());
            }
            buf
        }
        LsaBody::Network(n) => {
            let mut buf = Vec::with_capacity(4 + n.attached_routers.len() * 4);
            buf.push(0); // reserved
            buf.extend_from_slice(&(n.options & 0x00FF_FFFF).to_be_bytes()[1..]);
            for router in &n.attached_routers {
                buf.extend_from_slice(&router.octets());
            }
            buf
        }
        LsaBody::Link(l) => {
            let mut buf = Vec::with_capacity(20 + l.prefixes.len() * 20);
            buf.push(l.priority);
            buf.extend_from_slice(&(l.options & 0x00FF_FFFF).to_be_bytes()[1..]);
            buf.extend_from_slice(&l.link_local_address.octets());
            buf.extend_from_slice(
                &u32::try_from(l.prefixes.len())
                    .unwrap_or(u32::MAX)
                    .to_be_bytes(),
            );
            for p in &l.prefixes {
                let truncated = p.prefix.trunc();
                buf.push(truncated.prefix_len());
                buf.push(p.options);
                buf.extend_from_slice(&0u16.to_be_bytes()); // reserved
                encode_prefix(&mut buf, &p.prefix);
            }
            buf
        }
        LsaBody::IntraAreaPrefix(i) => {
            let mut buf = Vec::with_capacity(12 + i.prefixes.len() * 20);
            buf.extend_from_slice(
                &u16::try_from(i.prefixes.len())
                    .unwrap_or(u16::MAX)
                    .to_be_bytes(),
            );
            buf.extend_from_slice(&i.referenced_ls_type.to_be_bytes());
            buf.extend_from_slice(&i.referenced_link_state_id.octets());
            buf.extend_from_slice(&i.referenced_advertising_router.octets());
            for p in &i.prefixes {
                let truncated = p.prefix.trunc();
                buf.push(truncated.prefix_len());
                buf.push(p.options);
                buf.extend_from_slice(&p.metric.to_be_bytes());
                encode_prefix(&mut buf, &p.prefix);
            }
            buf
        }
    }
}

fn decode_body(lsa_type: u16, data: &[u8]) -> Result<LsaBody, PacketError> {
    match lsa_type {
        LSA_TYPE_ROUTER => {
            if data.len() < 4 {
                return Err(PacketError::TruncatedBody);
            }
            let flags = data[0];
            let options = u32::from(data[1]) << 16 | u32::from(data[2]) << 8 | u32::from(data[3]);
            let link_bytes = &data[4..];
            if !link_bytes.len().is_multiple_of(ROUTER_LINK_LEN) {
                return Err(PacketError::TruncatedBody);
            }
            let links = link_bytes
                .as_chunks::<ROUTER_LINK_LEN>()
                .0
                .iter()
                .map(|c| RouterLsaLink {
                    link_type: c[0],
                    metric: u16::from_be_bytes([c[2], c[3]]),
                    interface_id: u32::from_be_bytes([c[4], c[5], c[6], c[7]]),
                    neighbor_interface_id: u32::from_be_bytes([c[8], c[9], c[10], c[11]]),
                    neighbor_router_id: read_ipv4(c, 12),
                })
                .collect();
            Ok(LsaBody::Router(RouterLsaBody {
                flags,
                options,
                links,
            }))
        }
        LSA_TYPE_NETWORK => {
            if data.len() < 4 || !(data.len() - 4).is_multiple_of(4) {
                return Err(PacketError::TruncatedBody);
            }
            let options = u32::from(data[1]) << 16 | u32::from(data[2]) << 8 | u32::from(data[3]);
            let attached_routers = data[4..]
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                .collect();
            Ok(LsaBody::Network(NetworkLsaBody {
                options,
                attached_routers,
            }))
        }
        LSA_TYPE_LINK => {
            if data.len() < 20 {
                return Err(PacketError::TruncatedBody);
            }
            let priority = data[0];
            let options = u32::from(data[1]) << 16 | u32::from(data[2]) << 8 | u32::from(data[3]);
            let mut addr_octets = [0u8; 16];
            addr_octets.copy_from_slice(&data[4..20]);
            let link_local_address = Ipv6Addr::from(addr_octets);
            let num_prefixes =
                usize::try_from(u32::from_be_bytes([data[20], data[21], data[22], data[23]]))
                    .unwrap_or(usize::MAX);
            let mut rest = &data[24..];
            let mut prefixes = Vec::with_capacity(num_prefixes.min(rest.len() / 4 + 1));
            for _ in 0..num_prefixes {
                if rest.len() < 4 {
                    return Err(PacketError::TruncatedBody);
                }
                let prefix_len = rest[0];
                let options = rest[1];
                let (prefix, consumed) = decode_prefix(&rest[4..], prefix_len)?;
                prefixes.push(LinkPrefixEntry { options, prefix });
                rest = &rest[4 + consumed..];
            }
            Ok(LsaBody::Link(LinkLsaBody {
                priority,
                options,
                link_local_address,
                prefixes,
            }))
        }
        LSA_TYPE_INTRA_AREA_PREFIX => {
            if data.len() < 12 {
                return Err(PacketError::TruncatedBody);
            }
            let num_prefixes = usize::from(u16::from_be_bytes([data[0], data[1]]));
            let referenced_ls_type = u16::from_be_bytes([data[2], data[3]]);
            let referenced_link_state_id = read_ipv4(data, 4);
            let referenced_advertising_router = read_ipv4(data, 8);
            let mut rest = &data[12..];
            let mut prefixes = Vec::with_capacity(num_prefixes.min(rest.len() / 4 + 1));
            for _ in 0..num_prefixes {
                if rest.len() < 4 {
                    return Err(PacketError::TruncatedBody);
                }
                let prefix_len = rest[0];
                let options = rest[1];
                let metric = u16::from_be_bytes([rest[2], rest[3]]);
                let (prefix, consumed) = decode_prefix(&rest[4..], prefix_len)?;
                prefixes.push(IntraAreaPrefixEntry {
                    options,
                    metric,
                    prefix,
                });
                rest = &rest[4 + consumed..];
            }
            Ok(LsaBody::IntraAreaPrefix(IntraAreaPrefixLsaBody {
                referenced_ls_type,
                referenced_link_state_id,
                referenced_advertising_router,
                prefixes,
            }))
        }
        other => Err(PacketError::UnknownLsaType(other)),
    }
}

/// Encodes `lsa`, overwriting `length`/`checksum` with freshly-computed
/// values.
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

/// RFC 2328 §12.1.7 / RFC 905 Annex B's Fletcher checksum — byte-for-byte
/// identical algorithm to `ospf::lsa::lsa_checksum` (RFC 5340 keeps RFC
/// 2328 §13.1's LSA-header semantics unchanged); ported verbatim rather than
/// reimplemented. Computed over an LSA starting at the `lsa_type` field
/// (i.e. `without_age` excludes the 2-byte `age` field that precedes it)
/// through the end of the body, treating the embedded checksum field
/// (offset 14 of `without_age`) as zero regardless of its actual contents —
/// so this same function both computes a fresh checksum (`encode_lsa`) and
/// validates an existing one (`decode_lsa`).
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

/// Encodes a raw RFC 5340 Interface ID (or any other opaque 32-bit value —
/// a Network-LSA's own disambiguator, etc.) as the `Ipv4Addr`-shaped key
/// convention `LsaKey.link_state_id` uses throughout this crate — see
/// `LsaKey`'s own doc comment for why. Shared by `link.rs` (origination) and
/// `spf.rs` (next-hop derivation), the two places that need to move between
/// a raw `u32` interface id and this key shape.
pub fn interface_id_key(id: u32) -> Ipv4Addr {
    Ipv4Addr::from(id.to_be_bytes())
}

/// The inverse of `interface_id_key`.
pub fn key_to_interface_id(key: Ipv4Addr) -> u32 {
    u32::from_be_bytes(key.octets())
}

/// RFC 2328 §13.1's "which LSA instance is newer" (unchanged by RFC 5340):
/// higher sequence number wins, then higher checksum, then an instance at
/// `MAX_AGE` (being flushed) is always considered newer than one that isn't.
/// Ported verbatim from `ospf::lsa::is_newer`.
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
                lsa_type: LSA_TYPE_ROUTER,
                link_state_id: Ipv4Addr::new(9, 9, 9, 9),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: 0x8000_0001u32.cast_signed(),
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsaBody {
                flags: 0,
                options: OPTION_V6 | OPTION_R,
                links: vec![RouterLsaLink {
                    link_type: LINK_TYPE_POINT_TO_POINT,
                    metric: 1,
                    interface_id: 3,
                    neighbor_interface_id: 4,
                    neighbor_router_id: Ipv4Addr::new(9, 9, 9, 10),
                }],
            }),
        }
    }

    fn network_lsa() -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                lsa_type: LSA_TYPE_NETWORK,
                link_state_id: Ipv4Addr::new(0, 0, 0, 3),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: 0x8000_0001u32.cast_signed(),
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Network(NetworkLsaBody {
                options: OPTION_V6 | OPTION_R,
                attached_routers: vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(9, 9, 9, 10)],
            }),
        }
    }

    fn link_lsa() -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                lsa_type: LSA_TYPE_LINK,
                link_state_id: Ipv4Addr::new(0, 0, 0, 3),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: 0x8000_0001u32.cast_signed(),
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Link(LinkLsaBody {
                priority: 1,
                options: OPTION_V6 | OPTION_R,
                link_local_address: "fe80::1".parse().unwrap(),
                prefixes: vec![LinkPrefixEntry {
                    options: 0,
                    prefix: "2001:db8:1::/64".parse().unwrap(),
                }],
            }),
        }
    }

    fn intra_area_prefix_lsa() -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                lsa_type: LSA_TYPE_INTRA_AREA_PREFIX,
                link_state_id: Ipv4Addr::UNSPECIFIED,
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: 0x8000_0001u32.cast_signed(),
                checksum: 0,
                length: 0,
            },
            body: LsaBody::IntraAreaPrefix(IntraAreaPrefixLsaBody {
                referenced_ls_type: LSA_TYPE_ROUTER,
                referenced_link_state_id: Ipv4Addr::UNSPECIFIED,
                referenced_advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                prefixes: vec![IntraAreaPrefixEntry {
                    options: 0,
                    metric: 1,
                    prefix: "2001:db8:9::/128".parse().unwrap(),
                }],
            }),
        }
    }

    #[test]
    fn router_lsa_round_trips() {
        let lsa = router_lsa();
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.header.lsa_type, lsa.header.lsa_type);
        assert_eq!(decoded.body, lsa.body);
    }

    #[test]
    fn router_lsa_with_no_links_round_trips() {
        let mut lsa = router_lsa();
        lsa.body = LsaBody::Router(RouterLsaBody {
            flags: 0,
            options: OPTION_V6,
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
    fn link_lsa_round_trips_with_one_prefix() {
        let lsa = link_lsa();
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.body, lsa.body);
    }

    #[test]
    fn link_lsa_round_trips_with_no_prefixes() {
        let mut lsa = link_lsa();
        lsa.body = LsaBody::Link(LinkLsaBody {
            priority: 1,
            options: OPTION_V6,
            link_local_address: "fe80::1".parse().unwrap(),
            prefixes: Vec::new(),
        });
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.body, lsa.body);
    }

    #[test]
    fn link_lsa_round_trips_with_non_aligned_prefix_length() {
        let mut lsa = link_lsa();
        lsa.body = LsaBody::Link(LinkLsaBody {
            priority: 1,
            options: OPTION_V6,
            link_local_address: "fe80::1".parse().unwrap(),
            prefixes: vec![LinkPrefixEntry {
                options: 0,
                // /48 needs 2 32-bit words (6 bytes -> padded to 8).
                prefix: "2001:db8:1::/48".parse().unwrap(),
            }],
        });
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.body, lsa.body);
    }

    #[test]
    fn intra_area_prefix_lsa_round_trips() {
        let lsa = intra_area_prefix_lsa();
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.body, lsa.body);
    }

    #[test]
    fn intra_area_prefix_lsa_round_trips_with_multiple_prefixes() {
        let mut lsa = intra_area_prefix_lsa();
        lsa.body = LsaBody::IntraAreaPrefix(IntraAreaPrefixLsaBody {
            referenced_ls_type: LSA_TYPE_NETWORK,
            referenced_link_state_id: Ipv4Addr::new(0, 0, 0, 3),
            referenced_advertising_router: Ipv4Addr::new(9, 9, 9, 9),
            prefixes: vec![
                IntraAreaPrefixEntry {
                    options: 0,
                    metric: 1,
                    prefix: "2001:db8:1::/64".parse().unwrap(),
                },
                IntraAreaPrefixEntry {
                    options: 0,
                    metric: 10,
                    prefix: "2001:db8:2::/64".parse().unwrap(),
                },
            ],
        });
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
        lsa.header.lsa_type = 0x2FFF;
        let encoded = encode_lsa(&lsa);
        assert_eq!(
            decode_lsa(&encoded),
            Err(PacketError::UnknownLsaType(0x2FFF))
        );
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
