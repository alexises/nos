//! Route Target (subtype 0x02) and Site of Origin (subtype 0x03) helpers over
//! the `u64` form `PathAttributes.extended_communities` stores (type octet in
//! the high byte). Only the three transitive types RFC 4364 uses: 0x00
//! two-octet AS, 0x01 IPv4 address, 0x02 four-octet AS.

const SUB_RT: u8 = 0x02;
const SUB_SOO: u8 = 0x03;

fn is_vpn_type(c: u64, subtype: u8) -> bool {
    let b = c.to_be_bytes();
    b[0] <= 0x02 && b[1] == subtype
}

/// Whether `c` is a Route Target.
#[must_use]
pub fn is_route_target(c: u64) -> bool {
    is_vpn_type(c, SUB_RT)
}

/// The Route Targets among `communities`, in order.
#[must_use]
pub fn route_targets(communities: &[u64]) -> Vec<u64> {
    communities
        .iter()
        .copied()
        .filter(|c| is_route_target(*c))
        .collect()
}

/// The Sites of Origin among `communities`, in order.
#[must_use]
pub fn sites_of_origin(communities: &[u64]) -> Vec<u64> {
    communities
        .iter()
        .copied()
        .filter(|c| is_vpn_type(*c, SUB_SOO))
        .collect()
}

/// A Route Target of wire type `ty` (0x00: `admin` is a 16-bit AS and
/// `assigned` 32 bits; 0x01: an IPv4 address and 16 bits; 0x02: a 32-bit AS
/// and 16 bits). `None` for another type or a value that does not fit.
#[must_use]
pub fn rt(ty: u8, admin: u32, assigned: u32) -> Option<u64> {
    let mut b = [ty, SUB_RT, 0, 0, 0, 0, 0, 0];
    match ty {
        0x00 => {
            b[2..4].copy_from_slice(&u16::try_from(admin).ok()?.to_be_bytes());
            b[4..8].copy_from_slice(&assigned.to_be_bytes());
        }
        0x01 | 0x02 => {
            b[2..6].copy_from_slice(&admin.to_be_bytes());
            b[6..8].copy_from_slice(&u16::try_from(assigned).ok()?.to_be_bytes());
        }
        _ => return None,
    }
    Some(u64::from_be_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evpn::format_ext_community;
    use nos_proto::evpn_id::parse_rt;

    #[test]
    fn route_targets_of_the_three_types_are_extracted_and_soo_is_not() {
        let a = rt(0, 65000, 100).unwrap();
        let b = rt(1, 0x0a00_0001, 7).unwrap();
        let c = rt(2, 4_200_000_000, 9).unwrap();
        let soo = 0x0003_fde8_0000_0001_u64;
        let encap = 0x030c_0000_0000_0008_u64;
        let all = [a, soo, b, encap, c];
        assert_eq!(route_targets(&all), vec![a, b, c]);
        assert_eq!(sites_of_origin(&all), vec![soo]);
        assert!(is_route_target(a) && !is_route_target(soo) && !is_route_target(encap));
        // Non-transitive twins (type 0x40+) are out.
        assert!(!is_route_target(a | (0x40 << 56)));
    }

    #[test]
    fn rt_constructors_match_parse_rt_and_format() {
        assert_eq!(rt(0, 65000, 100), parse_rt("65000:100"));
        assert_eq!(rt(2, 4_200_000_000, 9), parse_rt("4200000000:9"));
        assert_eq!(rt(1, 0x0a00_0001, 7), parse_rt("10.0.0.1:7"));
        assert_eq!(
            format_ext_community(rt(0, 65000, 100).unwrap()),
            "RT:65000:100"
        );
        assert_eq!(
            format_ext_community(rt(1, 0x0a00_0001, 7).unwrap()),
            "RT:10.0.0.1:7"
        );
        assert_eq!(
            format_ext_community(rt(2, 4_200_000_000, 9).unwrap()),
            "RT:4200000000:9"
        );
    }

    #[test]
    fn rt_rejects_values_that_do_not_fit() {
        assert_eq!(rt(0, 70_000, 1), None);
        assert_eq!(rt(1, 1, 70_000), None);
        assert_eq!(rt(2, 1, 70_000), None);
        assert_eq!(rt(3, 1, 1), None);
    }
}
