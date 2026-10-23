//! The 5-tuple of a sampled frame (pure). psample hands the frame from its
//! Ethernet header at both hooks (seen in `nos-tc`'s kernel test, #544); a
//! `log` rule's filters are `ip`/`ipv6`, so the frame is never VLAN-tagged.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// What a truncated or odd frame leaves unknown is `None`, never a panic.
/// ICMP/ICMPv6 put the type in `sport` and the code in `dport`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FiveTuple {
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    pub proto: Option<u8>,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
}

/// An optional field as a log value: `-` when unknown.
pub struct Show<T>(pub Option<T>);

impl<T: fmt::Display> fmt::Display for Show<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(v) => v.fmt(f),
            None => f.write_str("-"),
        }
    }
}

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
/// IPv6 extension headers walked (hop-by-hop, routing, destination options,
/// fragment); a longer chain leaves the ports unknown.
const MAX_EXTENSIONS: usize = 4;
/// IPv4 fragment offset bits of the flags/offset word.
const FRAG_OFFSET: u16 = 0x1FFF;

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

pub fn parse_frame(frame: &[u8]) -> FiveTuple {
    let mut t = FiveTuple::default();
    match frame.get(12..14).map(be16) {
        Some(ETH_P_IP) => v4(&frame[14..], &mut t),
        Some(ETH_P_IPV6) => v6(&frame[14..], &mut t),
        _ => {}
    }
    t
}

fn v4(p: &[u8], t: &mut FiveTuple) {
    let Some(h) = p.get(..20) else { return };
    t.src = Some(Ipv4Addr::new(h[12], h[13], h[14], h[15]).into());
    t.dst = Some(Ipv4Addr::new(h[16], h[17], h[18], h[19]).into());
    t.proto = Some(h[9]);
    // A non-first fragment has no L4 header.
    if be16(&h[6..8]) & FRAG_OFFSET == 0 {
        l4(h[9], p.get(usize::from(h[0] & 0xF) * 4..), t);
    }
}

fn v6(p: &[u8], t: &mut FiveTuple) {
    let Some(h) = p.get(..40) else { return };
    let addr =
        |at: usize| Some(Ipv6Addr::from(<[u8; 16]>::try_from(&h[at..at + 16]).unwrap()).into());
    t.src = addr(8);
    t.dst = addr(24);
    let (mut next, mut at) = (h[6], 40);
    for _ in 0..MAX_EXTENSIONS {
        let Some(e) = p.get(at..at + 8) else { break };
        match next {
            0 | 43 | 60 => at += (usize::from(e[1]) + 1) * 8,
            44 if be16(&e[2..4]) & 0xFFF8 != 0 => {
                t.proto = Some(e[0]);
                return;
            }
            44 => at += 8,
            _ => break,
        }
        next = e[0];
    }
    t.proto = Some(next);
    l4(next, p.get(at..), t);
}

fn l4(proto: u8, p: Option<&[u8]>, t: &mut FiveTuple) {
    let Some(p) = p else { return };
    match proto {
        6 | 17 => {
            if let Some(h) = p.get(..4) {
                (t.sport, t.dport) = (Some(be16(h)), Some(be16(&h[2..])));
            }
        }
        1 | 58 => {
            if let Some(h) = p.get(..2) {
                (t.sport, t.dport) = (Some(h[0].into()), Some(h[1].into()));
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth(ethertype: u16, ip: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(ip);
        f
    }

    fn ipv4(proto: u8, frag: u16, l4: &[u8]) -> Vec<u8> {
        let mut h = vec![0x45, 0, 0, 0, 0, 0];
        h.extend_from_slice(&frag.to_be_bytes());
        h.extend_from_slice(&[64, proto, 0, 0, 192, 0, 2, 1, 198, 51, 100, 9]);
        h.extend_from_slice(l4);
        h
    }

    fn ipv6(next: u8, rest: &[u8]) -> Vec<u8> {
        let mut h = vec![0x60, 0, 0, 0, 0, 0, next, 64];
        h.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        h.extend_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        h.extend_from_slice(rest);
        h
    }

    fn tuple(src: &str, dst: &str, proto: u8, ports: Option<(u16, u16)>) -> FiveTuple {
        FiveTuple {
            src: Some(src.parse().unwrap()),
            dst: Some(dst.parse().unwrap()),
            proto: Some(proto),
            sport: ports.map(|p| p.0),
            dport: ports.map(|p| p.1),
        }
    }

    #[test]
    fn the_kernel_test_frame() {
        // `SAMPLE_MSG`'s data in `nos-tc`'s genl_tests.rs: UDP to 6000.
        let f = "020000000102020000000101080045000023704f400040117609c6336401c6336409c1d01770000f54927073616d706c65";
        let f: Vec<u8> = (0..f.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&f[i..i + 2], 16).unwrap())
            .collect();
        let t = parse_frame(&f);
        assert_eq!(
            t,
            tuple("198.51.100.1", "198.51.100.9", 17, Some((0xc1d0, 6000)))
        );
    }

    #[test]
    fn v4_tcp_icmp_and_fragments() {
        let tcp = eth(ETH_P_IP, &ipv4(6, 0, &[0, 179, 0x30, 0x39]));
        let want = tuple("192.0.2.1", "198.51.100.9", 6, Some((179, 12345)));
        assert_eq!(parse_frame(&tcp), want);
        let icmp = eth(ETH_P_IP, &ipv4(1, 0, &[8, 0]));
        assert_eq!(parse_frame(&icmp).sport, Some(8));
        assert_eq!(parse_frame(&icmp).dport, Some(0));
        // Don't-fragment alone keeps the ports; an offset drops them.
        let df = eth(ETH_P_IP, &ipv4(6, 0x4000, &[0, 179, 0, 1]));
        assert_eq!(parse_frame(&df).sport, Some(179));
        let later = eth(ETH_P_IP, &ipv4(6, 0x0010, &[0, 179, 0, 1]));
        assert_eq!(
            parse_frame(&later),
            tuple("192.0.2.1", "198.51.100.9", 6, None)
        );
    }

    #[test]
    fn v6_udp_icmpv6_and_extension_headers() {
        let udp = eth(ETH_P_IPV6, &ipv6(17, &[0, 53, 0, 54]));
        let want = tuple("2001:db8::1", "2001:db8::2", 17, Some((53, 54)));
        assert_eq!(parse_frame(&udp), want);
        let icmp = eth(ETH_P_IPV6, &ipv6(58, &[135, 0]));
        assert_eq!(
            (parse_frame(&icmp).sport, parse_frame(&icmp).dport),
            (Some(135), Some(0))
        );
        // Hop-by-hop (8 bytes) then a first fragment, then TCP.
        let mut ext = vec![44, 0, 1, 4, 0, 0, 0, 0];
        ext.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 1, 0, 22, 0, 23]);
        let f = eth(ETH_P_IPV6, &ipv6(0, &ext));
        assert_eq!(
            parse_frame(&f),
            tuple("2001:db8::1", "2001:db8::2", 6, Some((22, 23)))
        );
        // A later fragment: the protocol, no ports.
        let f = eth(
            ETH_P_IPV6,
            &ipv6(44, &[6, 0, 0, 8, 0, 0, 0, 1, 0, 22, 0, 23]),
        );
        assert_eq!(
            parse_frame(&f),
            tuple("2001:db8::1", "2001:db8::2", 6, None)
        );
        // Five hop-by-hop headers: past the walk, no ports.
        let f = eth(
            ETH_P_IPV6,
            &ipv6(0, &[[0u8, 0, 0, 0, 0, 0, 0, 0]; 5].concat()),
        );
        assert_eq!(parse_frame(&f).proto, Some(0));
    }

    #[test]
    fn truncated_and_foreign_frames_never_panic() {
        assert_eq!(parse_frame(&[]), FiveTuple::default());
        assert_eq!(parse_frame(&eth(0x0806, &[0; 28])), FiveTuple::default());
        assert_eq!(
            parse_frame(&eth(ETH_P_IP, &[0x45; 19])),
            FiveTuple::default()
        );
        assert_eq!(
            parse_frame(&eth(ETH_P_IPV6, &[0x60; 39])),
            FiveTuple::default()
        );
        let short = eth(ETH_P_IP, &ipv4(6, 0, &[0, 179]));
        assert_eq!(parse_frame(&short).sport, None);
        assert_eq!(parse_frame(&eth(ETH_P_IP, &ipv4(1, 0, &[8]))).sport, None);
        let ospf = eth(ETH_P_IP, &ipv4(89, 0, &[1, 2, 3, 4]));
        assert_eq!(
            parse_frame(&ospf),
            tuple("192.0.2.1", "198.51.100.9", 89, None)
        );
        // An extension header cut short: the walk stops there.
        let f = eth(ETH_P_IPV6, &ipv6(0, &[6, 0]));
        assert_eq!(parse_frame(&f).proto, Some(0));
        // A bad IHL points past the frame.
        let mut bad = ipv4(6, 0, &[0, 1, 0, 2]);
        bad[0] = 0x4F;
        assert_eq!(parse_frame(&eth(ETH_P_IP, &bad)).sport, None);
    }

    #[test]
    fn unknown_fields_show_as_a_dash() {
        assert_eq!(Show(Some(5)).to_string(), "5");
        assert_eq!(Show::<u8>(None).to_string(), "-");
    }
}
