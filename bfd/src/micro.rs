//! RFC 7130 micro-BFD framing, pure: the control packet leaves a LAG member
//! in a hand-built IP/UDP frame (`socket::MicroTx`, an `AF_PACKET` socket on
//! the member itself, so the bond never touches it).
//!
//! - UDP destination port 6784, source port in 49152-65535 (§2.2, RFC 5881 §4).
//! - TTL / hop limit 255 sent and required (RFC 5881 §5).
//! - Destination MAC [`GROUP`] (§2.3); the destination IP is the peer's.
//! - Receive accepts untagged frames and 802.1p priority-tagged ones (VLAN 0).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::echo::{fold, sum, udp_checksum};

/// RFC 7130 §7: the micro-BFD UDP destination port.
pub const PORT: u16 = 6784;
/// RFC 7130 §2.3: the dedicated multicast MAC.
pub const GROUP: [u8; 6] = [0x01, 0x00, 0x5e, 0x90, 0x00, 0x01];
const TTL: u8 = 255;
const IP4_LEN: usize = 20;
const IP6_LEN: usize = 40;
const UDP_LEN: usize = 8;

/// The `Demux` table key of a member's sessions (no VRF is involved).
pub fn demux_table(member: &str) -> String {
    format!("micro:{member}")
}

/// The IP packet (no Ethernet header) carrying `pdu` from `src`:`sport` to
/// `dst`:6784. `None` when the families differ.
pub fn build_frame(src: IpAddr, dst: IpAddr, sport: u16, pdu: &[u8]) -> Option<Vec<u8>> {
    let udp_len = UDP_LEN + pdu.len();
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&PORT.to_be_bytes());
    udp.extend_from_slice(&u16::try_from(udp_len).ok()?.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(pdu);

    let mut out = Vec::with_capacity(IP6_LEN + udp_len);
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            out.extend_from_slice(&[0x45, 0xc0]);
            out.extend_from_slice(&u16::try_from(IP4_LEN + udp_len).ok()?.to_be_bytes());
            out.extend_from_slice(&[0, 0, 0x40, 0, TTL, 17, 0, 0]);
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
            let c = fold(sum(&out, 0));
            out[10..12].copy_from_slice(&c.to_be_bytes());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            out.extend_from_slice(&[0x60, 0xc0, 0, 0]);
            out.extend_from_slice(&u16::try_from(udp_len).ok()?.to_be_bytes());
            out.extend_from_slice(&[17, TTL]);
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
        }
        _ => return None,
    }
    let c = udp_checksum(src, dst, &udp);
    udp[6..8].copy_from_slice(&c.to_be_bytes());
    out.extend_from_slice(&udp);
    Some(out)
}

/// What a received IP packet carries for micro-BFD.
#[derive(Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub pdu: &'a [u8],
}

/// Parses an IP packet (IPv4 or IPv6), `None` unless it is an unfragmented
/// UDP datagram to port 6784 with TTL / hop limit exactly 255 and a good
/// checksum (IPv6 has no extension headers: next header must be UDP).
pub fn parse_frame(packet: &[u8]) -> Option<Frame<'_>> {
    let (src, dst, udp) = match packet.first()? >> 4 {
        4 => {
            let ihl = usize::from(packet[0] & 0xf) * 4;
            let hdr = packet.get(..ihl).filter(|_| ihl >= IP4_LEN)?;
            let total = usize::from(u16::from_be_bytes([hdr[2], hdr[3]]));
            // MF set or a fragment offset: not a whole datagram.
            if hdr[9] != 17 || hdr[8] != TTL || (hdr[6] & 0x3f, hdr[7]) != (0, 0) {
                return None;
            }
            if fold(sum(hdr, 0)) != 0 {
                return None;
            }
            let udp = packet.get(ihl..total)?;
            let s = Ipv4Addr::new(hdr[12], hdr[13], hdr[14], hdr[15]);
            let d = Ipv4Addr::new(hdr[16], hdr[17], hdr[18], hdr[19]);
            (IpAddr::V4(s), IpAddr::V4(d), udp)
        }
        6 => {
            let hdr = packet.get(..IP6_LEN)?;
            if hdr[6] != 17 || hdr[7] != TTL {
                return None;
            }
            let plen = usize::from(u16::from_be_bytes([hdr[4], hdr[5]]));
            let udp = packet.get(IP6_LEN..IP6_LEN + plen)?;
            let s = Ipv6Addr::from(<[u8; 16]>::try_from(&hdr[8..24]).ok()?);
            let d = Ipv6Addr::from(<[u8; 16]>::try_from(&hdr[24..40]).ok()?);
            (IpAddr::V6(s), IpAddr::V6(d), udp)
        }
        _ => return None,
    };
    let uhdr = udp.get(..UDP_LEN)?;
    let ulen = usize::from(u16::from_be_bytes([uhdr[4], uhdr[5]]));
    if u16::from_be_bytes([uhdr[2], uhdr[3]]) != PORT || ulen < UDP_LEN || ulen > udp.len() {
        return None;
    }
    let udp = &udp[..ulen];
    let checksum = u16::from_be_bytes([uhdr[6], uhdr[7]]);
    // IPv4 may omit the UDP checksum (RFC 768), IPv6 may not.
    let ok = if checksum == 0 {
        src.is_ipv4()
    } else {
        udp_checksum(src, dst, udp) == 0xffff
    };
    ok.then_some(Frame {
        src,
        dst,
        pdu: &udp[UDP_LEN..],
    })
}

/// RFC 7130 §2.3: the IP packet inside an 802.1p priority-tagged frame
/// (`payload` follows the 0x8100 ethertype: TCI, inner ethertype, packet);
/// `None` for a real VLAN id or a non-IP inner type.
pub fn untag_priority(payload: &[u8]) -> Option<&[u8]> {
    let tci = u16::from_be_bytes([*payload.first()?, *payload.get(1)?]);
    let inner = u16::from_be_bytes([*payload.get(2)?, *payload.get(3)?]);
    (tci.trailing_zeros() >= 12 && matches!(inner, 0x0800 | 0x86dd)).then(|| &payload[4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4() -> (IpAddr, IpAddr) {
        ("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap())
    }

    fn v6() -> (IpAddr, IpAddr) {
        (
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        )
    }

    #[test]
    fn round_trips_both_families() {
        for (s, d) in [v4(), v6()] {
            let f = build_frame(s, d, 50000, b"0123456789ab").unwrap();
            let p = parse_frame(&f).unwrap();
            assert_eq!((p.src, p.dst, p.pdu), (s, d, &b"0123456789ab"[..]));
        }
        assert!(build_frame(v4().0, v6().1, 1, b"x").is_none());
    }

    #[test]
    fn ipv4_header_is_well_formed() {
        let f = build_frame(v4().0, v4().1, 49152, &[0u8; 24]).unwrap();
        assert_eq!(&f[..10], &[0x45, 0xc0, 0, 52, 0, 0, 0x40, 0, 255, 17]);
        // Summing the header with its checksum gives all ones.
        assert_eq!(fold(sum(&f[..20], 0)), 0);
        // source port 49152 = 0xc000, destination port 6784 = 0x1a80
        assert_eq!(&f[20..24], &[0xc0, 0x00, 0x1a, 0x80]);
    }

    #[test]
    fn rejects_every_bad_shape() {
        for (s, d) in [v4(), v6()] {
            let good = build_frame(s, d, 50000, b"0123456789ab").unwrap();
            let ttl_at = if s.is_ipv4() { 8 } else { 7 };
            let udp_at = if s.is_ipv4() { 20 } else { 40 };
            let mut ttl = good.clone();
            ttl[ttl_at] = 254;
            let mut port = good.clone();
            port[udp_at + 3] ^= 1;
            let mut sum_bad = good.clone();
            *sum_bad.last_mut().unwrap() ^= 0xff;
            for bad in [
                ttl,
                port,
                sum_bad,
                good[..good.len() - 1].to_vec(),
                good[..10].to_vec(),
            ] {
                assert_eq!(parse_frame(&bad), None);
            }
        }
        // IPv4 fragment, IPv6 extension header, unknown version.
        let mut frag = build_frame(v4().0, v4().1, 1, b"x").unwrap();
        frag[6] |= 0x20;
        assert_eq!(parse_frame(&frag), None);
        let mut ext = build_frame(v6().0, v6().1, 1, b"x").unwrap();
        ext[6] = 0;
        assert_eq!(parse_frame(&ext), None);
        assert_eq!(parse_frame(&[0x10; 40]), None);
        assert_eq!(parse_frame(&[]), None);
    }

    #[test]
    fn ipv4_may_omit_the_udp_checksum_ipv6_may_not() {
        let mut f = build_frame(v4().0, v4().1, 1, b"x").unwrap();
        f[26] = 0;
        f[27] = 0;
        assert!(parse_frame(&f).is_some());
        let mut f = build_frame(v6().0, v6().1, 1, b"x").unwrap();
        f[46] = 0;
        f[47] = 0;
        assert_eq!(parse_frame(&f), None);
    }

    #[test]
    fn priority_tag_zero_only() {
        let mut p = vec![0x00, 0x00, 0x08, 0x00];
        p.extend_from_slice(b"ip");
        assert_eq!(untag_priority(&p), Some(&b"ip"[..]));
        p[0] = 0xa0; // priority 5, VLAN 0: still accepted
        assert_eq!(untag_priority(&p), Some(&b"ip"[..]));
        p[1] = 7; // VLAN 7
        assert_eq!(untag_priority(&p), None);
        p[1] = 0;
        p[2] = 0x88;
        assert_eq!(untag_priority(&p), None);
        assert_eq!(untag_priority(&[0, 0]), None);
    }
}
