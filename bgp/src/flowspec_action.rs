//! RFC 8955 section 7 / RFC 8956 section 6.1 traffic-action decoding: pure,
//! over the 8-octet extended communities (`Vec<u64>` in `PathAttributes`).
//!
//! Unknown community types are ordinary communities and are skipped; a known
//! type that cannot be decoded (a NaN rate) is `MalformedAction`, which the
//! UPDATE parser turns into RFC 7606 treat-as-withdraw (RFC 8955 section 10).
//! The IPv6 redirect (type 0x000d) lives in the 20-octet IPv6-address-
//! specific attribute (RFC 5701), which NOS does not parse yet (#560), so
//! `decode_redirect_ipv6` is wired to nothing for now.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const RATE_BYTES: u16 = 0x8006;
pub const TRAFFIC_ACTION: u16 = 0x8007;
pub const REDIRECT_AS2: u16 = 0x8008;
pub const MARKING: u16 = 0x8009;
pub const RATE_PACKETS: u16 = 0x800c;
pub const REDIRECT_IPV4: u16 = 0x8108;
pub const REDIRECT_AS4: u16 = 0x8208;

/// The global administrator of a Route Target redirect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtGlobal {
    As(u32),
    Ip(Ipv4Addr),
}

/// One decoded traffic action. Rates are in bytes (or packets) per second;
/// 0 is "discard" (a negative rate decodes to 0, RFC 8955 section 7.1).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FlowAction {
    RateBytes(f32),
    RatePackets(f32),
    TrafficAction { sample: bool, terminal: bool },
    RedirectRt { global: RtGlobal, local: u32 },
    RedirectIpv6 { addr: Ipv6Addr, local: u16 },
    Dscp(u8),
}

/// A known action community that cannot be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedAction(pub u64);

impl fmt::Display for MalformedAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed flowspec action community 0x{:016x}", self.0)
    }
}

/// Section 7.1: negative (and -0) means discard; NaN has no meaning.
fn rate(bits: [u8; 4]) -> Option<f32> {
    let r = f32::from_be_bytes(bits);
    if r.is_nan() {
        None
    } else if r.is_sign_negative() {
        Some(0.0)
    } else {
        Some(r)
    }
}

/// Decodes the action communities in `communities`, in attribute order.
pub fn decode_actions(communities: &[u64]) -> Result<Vec<FlowAction>, MalformedAction> {
    let mut out = Vec::new();
    for &c in communities {
        let b = c.to_be_bytes();
        let tail = [b[4], b[5], b[6], b[7]];
        let local32 = u32::from_be_bytes(tail);
        let action = match u16::from_be_bytes([b[0], b[1]]) {
            RATE_BYTES => FlowAction::RateBytes(rate(tail).ok_or(MalformedAction(c))?),
            RATE_PACKETS => FlowAction::RatePackets(rate(tail).ok_or(MalformedAction(c))?),
            TRAFFIC_ACTION => FlowAction::TrafficAction {
                sample: b[7] & 0x02 != 0,
                terminal: b[7] & 0x01 != 0,
            },
            REDIRECT_AS2 => FlowAction::RedirectRt {
                global: RtGlobal::As(u32::from(u16::from_be_bytes([b[2], b[3]]))),
                local: local32,
            },
            REDIRECT_IPV4 => FlowAction::RedirectRt {
                global: RtGlobal::Ip(Ipv4Addr::new(b[2], b[3], b[4], b[5])),
                local: u32::from(u16::from_be_bytes([b[6], b[7]])),
            },
            REDIRECT_AS4 => FlowAction::RedirectRt {
                global: RtGlobal::As(u32::from_be_bytes([b[2], b[3], b[4], b[5]])),
                local: u32::from(u16::from_be_bytes([b[6], b[7]])),
            },
            MARKING => FlowAction::Dscp(b[7] & 0x3f),
            _ => continue,
        };
        out.push(action);
    }
    Ok(out)
}

/// RFC 8956 section 6.1 / RFC 5701: a 20-octet IPv6-address-specific
/// community with type 0x00 and sub-type 0x0d.
#[must_use]
pub fn decode_redirect_ipv6(c: &[u8; 20]) -> Option<FlowAction> {
    if c[0] != 0x00 || c[1] != 0x0d {
        return None;
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(&c[2..18]);
    Some(FlowAction::RedirectIpv6 {
        addr: Ipv6Addr::from(a),
        local: u16::from_be_bytes([c[18], c[19]]),
    })
}

fn is_rate(a: &FlowAction) -> bool {
    matches!(a, FlowAction::RateBytes(_) | FlowAction::RatePackets(_))
}

/// Section 7.7 interference, our choice: the first traffic-rate (bytes or
/// packets) in attribute order wins, later ones are ignored. Returns one
/// flag per action, `true` when it is ignored.
#[must_use]
pub fn ignored(actions: &[FlowAction]) -> Vec<bool> {
    let mut seen = false;
    actions
        .iter()
        .map(|a| {
            let dup = is_rate(a) && seen;
            seen |= is_rate(a);
            dup
        })
        .collect()
}

impl fmt::Display for FlowAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowAction::RateBytes(r) if *r == 0.0 => f.write_str("discard"),
            FlowAction::RatePackets(r) if *r == 0.0 => f.write_str("discard (packets)"),
            FlowAction::RateBytes(r) => write!(f, "rate {r} bytes/s"),
            FlowAction::RatePackets(r) => write!(f, "rate {r} packets/s"),
            FlowAction::TrafficAction { sample, terminal } => {
                write!(f, "sample={sample} terminal={terminal}")
            }
            FlowAction::RedirectRt {
                global: RtGlobal::As(a),
                local,
            } => write!(f, "redirect rt {a}:{local}"),
            FlowAction::RedirectRt {
                global: RtGlobal::Ip(a),
                local,
            } => write!(f, "redirect rt {a}:{local}"),
            FlowAction::RedirectIpv6 { addr, local } => write!(f, "redirect ipv6 [{addr}]:{local}"),
            FlowAction::Dscp(d) => write!(f, "dscp {d}"),
        }
    }
}

/// One human string per action, a shadowed traffic-rate suffixed `(ignored)`.
#[must_use]
pub fn describe(communities: &[u64]) -> Vec<String> {
    let Ok(actions) = decode_actions(communities) else {
        return Vec::new();
    };
    actions
        .iter()
        .zip(ignored(&actions))
        .map(|(a, ign)| {
            if ign {
                format!("{a} (ignored)")
            } else {
                a.to_string()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comm(t: u16, rest: [u8; 6]) -> u64 {
        let mut b = [0u8; 8];
        b[..2].copy_from_slice(&t.to_be_bytes());
        b[2..].copy_from_slice(&rest);
        u64::from_be_bytes(b)
    }

    fn rate_comm(t: u16, r: f32) -> u64 {
        let b = r.to_be_bytes();
        comm(t, [0xfd, 0xe8, b[0], b[1], b[2], b[3]])
    }

    fn one(c: u64) -> FlowAction {
        decode_actions(&[c]).unwrap()[0]
    }

    #[test]
    fn rates_decode_with_the_float_edges() {
        assert_eq!(
            one(rate_comm(RATE_BYTES, 1000.0)),
            FlowAction::RateBytes(1000.0)
        );
        assert_eq!(
            one(rate_comm(RATE_PACKETS, 5.0)),
            FlowAction::RatePackets(5.0)
        );
        // Negative and -0 are discard (0).
        assert_eq!(one(rate_comm(RATE_BYTES, -5.0)), FlowAction::RateBytes(0.0));
        assert_eq!(one(rate_comm(RATE_BYTES, -0.0)), FlowAction::RateBytes(0.0));
        assert_eq!(
            one(rate_comm(RATE_PACKETS, f32::NEG_INFINITY)),
            FlowAction::RatePackets(0.0)
        );
        assert_eq!(
            one(rate_comm(RATE_BYTES, f32::INFINITY)),
            FlowAction::RateBytes(f32::INFINITY)
        );
        let sub = f32::from_bits(1);
        assert_eq!(one(rate_comm(RATE_BYTES, sub)), FlowAction::RateBytes(sub));
        // NaN has no meaning: malformed.
        let nan = rate_comm(RATE_BYTES, f32::NAN);
        assert_eq!(decode_actions(&[nan]), Err(MalformedAction(nan)));
        assert!(MalformedAction(nan).to_string().contains("malformed"));
        let nan = rate_comm(RATE_PACKETS, f32::NAN);
        assert!(decode_actions(&[1, nan]).is_err());
    }

    #[test]
    fn traffic_action_bits() {
        let t = |b: u8| one(comm(TRAFFIC_ACTION, [0, 0, 0, 0, 0, b]));
        let a = |sample, terminal| FlowAction::TrafficAction { sample, terminal };
        assert_eq!(t(0), a(false, false));
        assert_eq!(t(1), a(false, true));
        assert_eq!(t(2), a(true, false));
        assert_eq!(t(3), a(true, true));
        // Reserved bits are ignored.
        assert_eq!(t(0xfc), a(false, false));
    }

    #[test]
    fn redirect_forms_and_dscp() {
        assert_eq!(
            one(comm(REDIRECT_AS2, [0xfd, 0xe8, 0, 0, 0, 10])),
            FlowAction::RedirectRt {
                global: RtGlobal::As(65000),
                local: 10
            }
        );
        assert_eq!(
            one(comm(REDIRECT_IPV4, [192, 0, 2, 1, 0, 7])),
            FlowAction::RedirectRt {
                global: RtGlobal::Ip(Ipv4Addr::new(192, 0, 2, 1)),
                local: 7
            }
        );
        assert_eq!(
            one(comm(REDIRECT_AS4, [0, 1, 0, 0, 0, 9])),
            FlowAction::RedirectRt {
                global: RtGlobal::As(65536),
                local: 9
            }
        );
        assert_eq!(
            one(comm(MARKING, [0, 0, 0, 0, 0, 0xca])),
            FlowAction::Dscp(10)
        );
    }

    #[test]
    fn ipv6_redirect_decoder() {
        let mut c = [0u8; 20];
        c[1] = 0x0d;
        c[2..18].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        c[19] = 5;
        assert_eq!(
            decode_redirect_ipv6(&c),
            Some(FlowAction::RedirectIpv6 {
                addr: "2001:db8::1".parse().unwrap(),
                local: 5
            })
        );
        c[1] = 0x0e;
        assert_eq!(decode_redirect_ipv6(&c), None);
        c[1] = 0x0d;
        c[0] = 0x80;
        assert_eq!(decode_redirect_ipv6(&c), None);
    }

    #[test]
    fn unknown_types_are_skipped_and_order_is_kept() {
        let rt = 0x0002_fde8_0000_2710; // an ordinary Route Target
        let v = decode_actions(&[rt, rate_comm(RATE_BYTES, 1.0), comm(MARKING, [0; 6])]).unwrap();
        assert_eq!(v, vec![FlowAction::RateBytes(1.0), FlowAction::Dscp(0)]);
        assert_eq!(decode_actions(&[]).unwrap(), vec![]);
    }

    #[test]
    fn first_traffic_rate_wins() {
        let v = decode_actions(&[
            rate_comm(RATE_PACKETS, 9.0),
            rate_comm(RATE_BYTES, 1.0),
            comm(MARKING, [0; 6]),
            rate_comm(RATE_BYTES, 2.0),
        ])
        .unwrap();
        assert_eq!(ignored(&v), vec![false, true, false, true]);
    }

    #[test]
    fn describe_renders_each_action() {
        assert_eq!(
            describe(&[
                rate_comm(RATE_BYTES, 0.0),
                rate_comm(RATE_BYTES, 1000.0),
                rate_comm(RATE_PACKETS, 0.0),
                rate_comm(RATE_PACKETS, 7.0),
                comm(TRAFFIC_ACTION, [0, 0, 0, 0, 0, 3]),
                comm(REDIRECT_AS2, [0xfd, 0xe8, 0, 0, 0, 10]),
                comm(REDIRECT_IPV4, [192, 0, 2, 1, 0, 7]),
                comm(MARKING, [0, 0, 0, 0, 0, 10]),
            ]),
            vec![
                "discard",
                "rate 1000 bytes/s (ignored)",
                "discard (packets) (ignored)",
                "rate 7 packets/s (ignored)",
                "sample=true terminal=true",
                "redirect rt 65000:10",
                "redirect rt 192.0.2.1:7",
                "dscp 10",
            ]
        );
        let v6 = FlowAction::RedirectIpv6 {
            addr: "2001:db8::1".parse().unwrap(),
            local: 5,
        };
        assert_eq!(v6.to_string(), "redirect ipv6 [2001:db8::1]:5");
        assert_eq!(
            describe(&[rate_comm(RATE_BYTES, f32::NAN)]),
            [] as [std::string::String; 0]
        );
    }
}
