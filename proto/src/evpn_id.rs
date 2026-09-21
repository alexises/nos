//! EVPN Route Distinguisher / Route Target text <-> wire encodings (RFC 4364
//! §4.2, RFC 4360). Lives here, not in `nos-bgp`, because `nos-config`'s
//! commit-time validation and `nos-fdbd` both need it and `nos-proto` can't
//! depend on a daemon.
//!
//! Text forms: `asn:nn` (ASN <= 65535 -> type 0, 4-byte nn), `asn:nn` with a
//! 4-byte ASN (type 2, 2-byte nn), `a.b.c.d:nn` (type 1, 2-byte nn).

use std::net::Ipv4Addr;

/// `(admin, assigned)` split of `text`, parsed as either an IPv4 address or a
/// number, plus what the administrator field turned out to be.
enum Admin {
    Asn(u32),
    Ip(Ipv4Addr),
}

fn split(text: &str) -> Option<(Admin, u32)> {
    let (admin, assigned) = text.split_once(':')?;
    let assigned = assigned.parse().ok()?;
    let admin = match admin.parse::<Ipv4Addr>() {
        Ok(ip) => Admin::Ip(ip),
        Err(_) => Admin::Asn(admin.parse().ok()?),
    };
    Some((admin, assigned))
}

/// Encodes an RD in the 8-byte wire form (`bgp::evpn::Rd`).
#[must_use]
pub fn parse_rd(text: &str) -> Option<[u8; 8]> {
    let (admin, n) = split(text)?;
    let mut out = [0u8; 8];
    match admin {
        Admin::Asn(asn) if u16::try_from(asn).is_ok() => {
            out[2..4].copy_from_slice(&asn.to_be_bytes()[2..]);
            out[4..8].copy_from_slice(&n.to_be_bytes());
        }
        Admin::Asn(asn) => {
            out[1] = 2;
            out[2..6].copy_from_slice(&asn.to_be_bytes());
            out[6..8].copy_from_slice(&u16::try_from(n).ok()?.to_be_bytes());
        }
        Admin::Ip(ip) => {
            out[1] = 1;
            out[2..6].copy_from_slice(&ip.octets());
            out[6..8].copy_from_slice(&u16::try_from(n).ok()?.to_be_bytes());
        }
    }
    Some(out)
}

/// Encodes a Route Target as the `u64` extended community `bgp` stores
/// (8 big-endian wire bytes: type, subtype 0x02, 6-byte value).
#[must_use]
pub fn parse_rt(text: &str) -> Option<u64> {
    let (admin, n) = split(text)?;
    let mut b = [0u8, 0x02, 0, 0, 0, 0, 0, 0];
    match admin {
        Admin::Asn(asn) if u16::try_from(asn).is_ok() => {
            b[2..4].copy_from_slice(&asn.to_be_bytes()[2..]);
            b[4..8].copy_from_slice(&n.to_be_bytes());
        }
        Admin::Asn(asn) => {
            b[0] = 2;
            b[2..6].copy_from_slice(&asn.to_be_bytes());
            b[6..8].copy_from_slice(&u16::try_from(n).ok()?.to_be_bytes());
        }
        Admin::Ip(ip) => {
            b[0] = 1;
            b[2..6].copy_from_slice(&ip.octets());
            b[6..8].copy_from_slice(&u16::try_from(n).ok()?.to_be_bytes());
        }
    }
    Some(u64::from_be_bytes(b))
}

/// RFC 7348 / RFC 8365 VXLAN Encapsulation extended community (type 0x03,
/// subtype 0x0c, tunnel type 8).
pub const ENCAP_VXLAN: u64 = 0x030c_0000_0000_0008;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rd_types() {
        assert_eq!(parse_rd("65000:1"), Some([0, 0, 0xfd, 0xe8, 0, 0, 0, 1]));
        assert_eq!(parse_rd("192.0.2.1:7"), Some([0, 1, 192, 0, 2, 1, 0, 7]));
        assert_eq!(
            parse_rd("4200000000:5"),
            Some([0, 2, 0xfa, 0x56, 0xea, 0, 0, 5])
        );
        assert_eq!(parse_rd("192.0.2.1:70000"), None);
        assert_eq!(parse_rd("nonsense"), None);
    }

    #[test]
    fn rt_matches_the_wire_bytes_bgp_prints() {
        // `RT:65000:10000` is what `bgp::evpn::format_ext_community` renders.
        assert_eq!(
            parse_rt("65000:10000"),
            Some(u64::from_be_bytes([0, 2, 0xfd, 0xe8, 0, 0, 0x27, 0x10]))
        );
        assert_eq!(
            parse_rt("192.0.2.1:7"),
            Some(u64::from_be_bytes([1, 2, 192, 0, 2, 1, 0, 7]))
        );
        assert_eq!(parse_rt("65000"), None);
    }
}
