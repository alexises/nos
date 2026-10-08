//! RFC 5880 §6.4 / RFC 5881 §4 Echo packets, pure: the payload is ours
//! (the peer never parses it), the IP/UDP headers are built by hand because
//! they leave through an `AF_PACKET` socket (`l2` in `socket.rs`).
//!
//! The packet is addressed to ourselves (source = destination = our own
//! address, TTL 255, UDP 3785) and sent to the neighbour's MAC; its ordinary
//! forwarding sends it back.

use std::net::IpAddr;

/// RFC 5881 §4: the Echo destination port.
pub const ECHO_PORT: u16 = 3785;
const TTL: u8 = 255;
/// What the forwarding hop leaves of the TTL: 255 minus one, at least.
const MIN_RX_TTL: u8 = 254;
const IP4_LEN: usize = 20;
const IP6_LEN: usize = 40;
const UDP_LEN: usize = 8;

/// The payload: our discriminator and a per-packet sequence number.
pub fn payload(disc: u32, seq: u32) -> [u8; 8] {
    let mut p = [0u8; 8];
    p[..4].copy_from_slice(&disc.to_be_bytes());
    p[4..].copy_from_slice(&seq.to_be_bytes());
    p
}

fn sum(data: &[u8], acc: u32) -> u32 {
    // An odd last byte is the high half of a zero-padded word.
    data.chunks(2).fold(acc, |a, c| {
        a + (u32::from(c[0]) << 8 | c.get(1).map_or(0, |b| u32::from(*b)))
    })
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !u16::try_from(acc).unwrap_or(0xffff)
}

/// UDP checksum over the pseudo header, the UDP header (checksum field as
/// given) and the payload.
fn udp_checksum(src: IpAddr, dst: IpAddr, udp: &[u8]) -> u16 {
    let len = u32::try_from(udp.len()).unwrap_or(0);
    let mut acc = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => sum(&d.octets(), sum(&s.octets(), 0)) + 17 + len,
        (IpAddr::V6(s), IpAddr::V6(d)) => sum(&d.octets(), sum(&s.octets(), 0)) + 17 + len,
        _ => 0,
    };
    acc = sum(udp, acc);
    match fold(acc) {
        0 => 0xffff, // RFC 768: a computed zero goes out as all ones
        c => c,
    }
}

/// The IP packet (no Ethernet header) of one Echo: `local` to `local`, from
/// UDP source port `sport`.
pub fn build(local: IpAddr, sport: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = UDP_LEN + payload.len();
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&ECHO_PORT.to_be_bytes());
    udp.extend_from_slice(&u16::try_from(udp_len).unwrap_or(0).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    let c = udp_checksum(local, local, &udp);
    udp[6..8].copy_from_slice(&c.to_be_bytes());

    let mut out = Vec::new();
    match local {
        IpAddr::V4(a) => {
            out.extend_from_slice(&[0x45, 0xc0]);
            out.extend_from_slice(&u16::try_from(IP4_LEN + udp_len).unwrap_or(0).to_be_bytes());
            out.extend_from_slice(&[0, 0, 0x40, 0, TTL, 17, 0, 0]);
            out.extend_from_slice(&a.octets());
            out.extend_from_slice(&a.octets());
            let c = fold(sum(&out, 0));
            out[10..12].copy_from_slice(&c.to_be_bytes());
        }
        IpAddr::V6(a) => {
            out.extend_from_slice(&[0x60, 0xc0, 0, 0]);
            out.extend_from_slice(&u16::try_from(udp_len).unwrap_or(0).to_be_bytes());
            out.extend_from_slice(&[17, TTL]);
            out.extend_from_slice(&a.octets());
            out.extend_from_slice(&a.octets());
        }
    }
    out.extend_from_slice(&udp);
    out
}

/// The (discriminator, sequence) of a returned Echo for `local`, or `None`
/// for anything else: wrong family, protocol, port, addresses (source must
/// equal destination must equal `local`), a TTL below 254 (it crossed more
/// than the one hop), a bad checksum or a payload that is not ours.
pub fn parse(packet: &[u8], local: IpAddr) -> Option<(u32, u32)> {
    let (p, _) = parse_udp(packet, local)?;
    (p.len() == 8).then_some((
        u32::from_be_bytes(p.get(..4)?.try_into().ok()?),
        u32::from_be_bytes(p.get(4..8)?.try_into().ok()?),
    ))
}

/// The UDP payload and TTL of a packet that passes every `parse` check
/// except the payload's shape (RFC 9747 loops a whole Control packet).
pub fn parse_udp(packet: &[u8], local: IpAddr) -> Option<(&[u8], u8)> {
    let (udp, ttl) = match local {
        IpAddr::V4(a) => {
            let ihl = usize::from(*packet.first()? & 0xf) * 4;
            if packet.first()? >> 4 != 4 || ihl < IP4_LEN || packet.get(9) != Some(&17) {
                return None;
            }
            let total = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
            // Fragments (offset or MF) are never ours.
            if packet.get(6)? & 0x20 != 0 || (packet.get(6)? & 0x1f, packet.get(7)?) != (0, &0) {
                return None;
            }
            let hdr = packet.get(..ihl)?;
            if fold(sum(hdr, 0)) != 0 {
                return None;
            }
            let o = a.octets();
            if hdr[12..16] != o || hdr[16..20] != o {
                return None;
            }
            (packet.get(ihl..total)?, hdr[8])
        }
        IpAddr::V6(a) => {
            if packet.first()? >> 4 != 6 || packet.get(6) != Some(&17) {
                return None;
            }
            let plen = usize::from(u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]));
            let o = a.octets();
            if packet.get(8..24)? != o || packet.get(24..40)? != o {
                return None;
            }
            (packet.get(IP6_LEN..IP6_LEN + plen)?, *packet.get(7)?)
        }
    };
    if ttl < MIN_RX_TTL
        || udp.len() < UDP_LEN
        || u16::from_be_bytes([udp[2], udp[3]]) != ECHO_PORT
        || usize::from(u16::from_be_bytes([udp[4], udp[5]])) != udp.len()
        || fold(sum(udp, pseudo(local, udp.len()))) != 0
    {
        return None;
    }
    Some((&udp[UDP_LEN..], ttl))
}

/// The pseudo-header sum of a `local`-to-`local` UDP datagram.
fn pseudo(local: IpAddr, udp_len: usize) -> u32 {
    let len = u32::try_from(udp_len).unwrap_or(0);
    match local {
        IpAddr::V4(a) => 2 * sum(&a.octets(), 0) + 17 + len,
        IpAddr::V6(a) => 2 * sum(&a.octets(), 0) + 17 + len,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4() -> IpAddr {
        "192.0.2.1".parse().unwrap()
    }
    fn v6() -> IpAddr {
        "2001:db8::1".parse().unwrap()
    }

    #[test]
    fn round_trip_both_families() {
        for local in [v4(), v6()] {
            let p = build(local, 50000, &payload(7, 9));
            assert_eq!(parse(&p, local), Some((7, 9)), "{local}");
        }
    }

    #[test]
    fn header_fields() {
        let p = build(v4(), 50000, &payload(1, 2));
        assert_eq!((p[8], p[9]), (255, 17), "ttl 255, udp");
        assert_eq!(p[12..16], p[16..20], "source == destination");
        assert_eq!(u16::from_be_bytes([p[22], p[23]]), 3785);
        assert_eq!(fold(sum(&p[..20], 0)), 0, "ip checksum");
        let p = build(v6(), 50000, &payload(1, 2));
        assert_eq!((p[6], p[7]), (17, 255));
        assert_eq!(p[8..24], p[24..40]);
    }

    #[test]
    fn forwarded_copy_is_accepted_but_not_a_second_hop() {
        let mut p = build(v6(), 50000, &payload(3, 4));
        p[7] = 254;
        assert_eq!(parse(&p, v6()), Some((3, 4)));
        p[7] = 253;
        assert_eq!(parse(&p, v6()), None);
        // IPv4: the forwarder rewrites TTL and the header checksum.
        let mut p = build(v4(), 50000, &payload(3, 4));
        p[8] = 254;
        p[10] = 0;
        p[11] = 0;
        let c = fold(sum(&p[..20], 0));
        p[10..12].copy_from_slice(&c.to_be_bytes());
        assert_eq!(parse(&p, v4()), Some((3, 4)));
    }

    #[test]
    fn control_sized_payloads_pass_parse_udp_only() {
        let p = build(v4(), 50000, &[7u8; 24]);
        let (pl, ttl) = parse_udp(&p, v4()).unwrap();
        assert_eq!((pl, ttl), (&[7u8; 24][..], 255));
        assert_eq!(parse(&p, v4()), None, "not an 8-byte echo payload");
    }

    #[test]
    fn rejects_foreign_and_damaged_packets() {
        let good = build(v4(), 50000, &payload(3, 4));
        assert_eq!(
            parse(&good, "192.0.2.2".parse().unwrap()),
            None,
            "not our address"
        );
        let mut bad = good.clone();
        bad[28] ^= 1;
        assert_eq!(parse(&bad, v4()), None, "udp checksum");
        let mut bad = good.clone();
        bad[22] = 0xff;
        assert_eq!(parse(&bad, v4()), None, "port");
        assert_eq!(parse(&good[..25], v4()), None, "runt");
        assert_eq!(parse(&[], v4()), None);
        // A v4 packet is no answer for a v6 session.
        assert_eq!(parse(&good, v6()), None);
    }
}
