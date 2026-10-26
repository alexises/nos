use std::net::IpAddr;

use nos_proto::{FlowBitOp, FlowComponent, FlowNumOp, FlowRule, FlowRuleAction};
use nos_tc::{
    ActionKind, FlowerKeys, Pedit, PeditFamily, Protocol, RateUnit, Verdict, FLAG_FRAG_IS_FIRST,
    FLAG_IS_FRAGMENT,
};

use super::*;

/// `(lt, gt, eq)` and a value, OR with what precedes.
fn op(lt: bool, gt: bool, eq: bool, value: u64) -> FlowNumOp {
    FlowNumOp {
        and: false,
        lt,
        gt,
        eq,
        value,
    }
}

fn eq(value: u64) -> FlowNumOp {
    op(false, false, true, value)
}

fn and(mut o: FlowNumOp) -> FlowNumOp {
    o.and = true;
    o
}

fn bit(m: bool, not: bool, value: u64) -> FlowBitOp {
    FlowBitOp {
        and: false,
        not,
        m,
        value,
    }
}

fn rule(components: Vec<FlowComponent>, actions: Vec<FlowRuleAction>) -> FlowRule {
    FlowRule {
        flow: "f".into(),
        ipv6: false,
        components,
        actions,
    }
}

fn drop() -> Vec<FlowRuleAction> {
    vec![FlowRuleAction::RateBytes(0.0)]
}

fn keys_of(r: &FlowRule) -> Result<Vec<FlowerKeys>, String> {
    lower(r).map(|l| l.filters)
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn numeric_operators_follow_rfc_table_1() {
    let s = |ops: &[FlowNumOp]| num_set(ops, 100);
    assert_eq!(s(&[op(false, false, false, 5)]), []);
    assert_eq!(s(&[eq(5)]), [(5, 5)]);
    assert_eq!(s(&[eq(500)]), []);
    assert_eq!(s(&[op(false, true, false, 5)]), [(6, 100)]);
    assert_eq!(s(&[op(false, true, true, 5)]), [(5, 100)]);
    assert_eq!(s(&[op(true, false, false, 5)]), [(0, 4)]);
    assert_eq!(s(&[op(true, false, false, 0)]), []);
    assert_eq!(s(&[op(true, false, true, 5)]), [(0, 5)]);
    assert_eq!(s(&[op(true, true, false, 5)]), [(0, 4), (6, 100)]);
    assert_eq!(s(&[op(true, true, true, 5)]), [(0, 100)]);
    assert_eq!(s(&[op(false, true, false, 100)]), []);
    // >= 10 AND <= 20, OR = 50: AND binds tighter.
    let range = [
        op(false, true, true, 10),
        and(op(true, false, true, 20)),
        eq(50),
    ];
    assert_eq!(s(&range), [(10, 20), (50, 50)]);
    // Adjacent ORed values merge.
    assert_eq!(s(&[eq(1), eq(2), eq(3)]), [(1, 3)]);
}

#[test]
fn a_drop_rule_on_prefixes_and_protocol() {
    let r = rule(
        vec![
            FlowComponent::Dest {
                prefix: "192.0.2.0/24".parse().unwrap(),
                offset: 0,
            },
            FlowComponent::Source {
                prefix: "198.51.100.7/32".parse().unwrap(),
                offset: 0,
            },
            FlowComponent::Protocol(vec![eq(6), eq(17)]),
        ],
        drop(),
    );
    let l = lower(&r).unwrap();
    assert_eq!(l.protocol, Protocol::Ip);
    assert_eq!(l.actions, [ActionKind::Gact(Verdict::Shot)]);
    let base = FlowerKeys {
        dst_ip: Some((ip("192.0.2.0"), 24)),
        src_ip: Some((ip("198.51.100.7"), 32)),
        ..Default::default()
    };
    let with = |p| FlowerKeys {
        ip_proto: Some(p),
        ..base.clone()
    };
    assert_eq!(l.filters, [with(6), with(17)]);
}

#[test]
fn ports_imply_tcp_or_udp_and_type_4_is_either_side() {
    // Port 80 (src or dst) and dst port 80..90: two alternatives per
    // protocol, the src one narrowed by the dst range.
    let r = rule(
        vec![
            FlowComponent::Port(vec![eq(80)]),
            FlowComponent::DstPort(vec![
                op(false, true, true, 80),
                and(op(true, false, true, 90)),
            ]),
        ],
        drop(),
    );
    let k = |p, src, dst| FlowerKeys {
        ip_proto: Some(p),
        src_port: src,
        dst_port: dst,
        ..Default::default()
    };
    assert_eq!(
        keys_of(&r).unwrap(),
        [
            k(6, Some((80, 80)), Some((80, 90))),
            k(17, Some((80, 80)), Some((80, 90))),
            k(6, None, Some((80, 80))),
            k(17, None, Some((80, 80))),
        ]
    );
    // A dst range that misses the type-4 value leaves the src side only.
    let r = rule(
        vec![
            FlowComponent::Protocol(vec![eq(6)]),
            FlowComponent::Port(vec![eq(80)]),
            FlowComponent::DstPort(vec![eq(443)]),
        ],
        drop(),
    );
    assert_eq!(
        keys_of(&r).unwrap(),
        [FlowerKeys {
            ip_proto: Some(6),
            src_port: Some((80, 80)),
            dst_port: Some((443, 443)),
            ..Default::default()
        }]
    );
    // != expands to two ranges.
    let r = rule(
        vec![
            FlowComponent::Protocol(vec![eq(17)]),
            FlowComponent::SrcPort(vec![op(true, true, false, 53)]),
        ],
        drop(),
    );
    let got: Vec<_> = keys_of(&r).unwrap().iter().map(|k| k.src_port).collect();
    assert_eq!(got, [Some((0, 52)), Some((54, 65535))]);
    // Ports with icmp only: no packet.
    let r = rule(
        vec![
            FlowComponent::Protocol(vec![eq(1)]),
            FlowComponent::DstPort(vec![eq(80)]),
        ],
        drop(),
    );
    assert_eq!(keys_of(&r).unwrap_err(), "matches no packet");
}

#[test]
fn icmp_dscp_and_the_filter_cap() {
    let mut r = rule(
        vec![
            FlowComponent::IcmpType(vec![eq(8)]),
            FlowComponent::IcmpCode(vec![eq(0)]),
            FlowComponent::Dscp(vec![eq(46), eq(10)]),
        ],
        drop(),
    );
    let k = |tos| FlowerKeys {
        ip_proto: Some(1),
        icmp_type: Some(8),
        icmp_code: Some(0),
        ip_tos: Some(tos),
        ..Default::default()
    };
    assert_eq!(keys_of(&r).unwrap(), [k(10), k(46)]);
    r.ipv6 = true;
    let l = lower(&r).unwrap();
    assert_eq!(
        (l.protocol, l.filters[0].ip_proto),
        (Protocol::Ipv6, Some(58))
    );
    // DSCP over 63 is clipped to the field.
    let r = rule(
        vec![FlowComponent::Dscp(vec![op(false, true, false, 62)])],
        drop(),
    );
    assert_eq!(keys_of(&r).unwrap()[0].ip_tos, Some(63));
    // Protocol != 6: 255 values.
    let r = rule(
        vec![FlowComponent::Protocol(vec![op(true, true, false, 6)])],
        drop(),
    );
    assert_eq!(keys_of(&r).unwrap_err(), "more than 64 filters");
    // 9 x 9 port alternatives.
    let nine: Vec<_> = (0..9).map(|i| eq(1000 + 2 * i)).collect();
    let r = rule(
        vec![
            FlowComponent::Protocol(vec![eq(6)]),
            FlowComponent::SrcPort(nine.clone()),
            FlowComponent::DstPort(nine),
        ],
        drop(),
    );
    assert_eq!(keys_of(&r).unwrap_err(), "more than 64 filters");
    // 8 x 8 fits exactly.
    let eight: Vec<_> = (0..8).map(|i| eq(1000 + 2 * i)).collect();
    let r = rule(
        vec![
            FlowComponent::Protocol(vec![eq(6)]),
            FlowComponent::SrcPort(eight.clone()),
            FlowComponent::DstPort(eight),
        ],
        drop(),
    );
    assert_eq!(keys_of(&r).unwrap().len(), 64);
}

#[test]
fn tcp_flags_as_flags_and_mask() {
    let t = |ops: Vec<FlowBitOp>| {
        keys_of(&rule(vec![FlowComponent::TcpFlags(ops)], drop())).map(|v| {
            v.iter()
                .map(|k| (k.ip_proto, k.tcp_flags))
                .collect::<Vec<_>>()
        })
    };
    // SYN set (match).
    assert_eq!(
        t(vec![bit(true, false, 0x02)]).unwrap(),
        [(Some(6), Some((2, 2)))]
    );
    // SYN and not ACK.
    let mut not_ack = bit(false, true, 0x10);
    not_ack.and = true;
    assert_eq!(
        t(vec![bit(true, false, 0x02), not_ack]).unwrap(),
        [(Some(6), Some((0x02, 0x12)))]
    );
    // Any of FIN, RST: two filters.
    assert_eq!(
        t(vec![bit(false, false, 0x05)]).unwrap(),
        [(Some(6), Some((1, 1))), (Some(6), Some((4, 4)))]
    );
    // Not all of SYN+ACK has no single mask.
    assert_eq!(
        t(vec![bit(true, true, 0x12)]).unwrap_err(),
        "tcp flags: no flags/mask form"
    );
    // Not all of SYN alone is "SYN clear".
    assert_eq!(
        t(vec![bit(true, true, 0x02)]).unwrap(),
        [(Some(6), Some((0, 2)))]
    );
    // SYN set AND SYN clear: contradiction.
    let mut clear = bit(false, true, 0x02);
    clear.and = true;
    assert_eq!(
        t(vec![bit(true, false, 0x02), clear]).unwrap_err(),
        "matches no packet"
    );
}

#[test]
fn fragments_map_to_flower_flags() {
    let f = |ops: Vec<FlowBitOp>| {
        keys_of(&rule(vec![FlowComponent::Fragment(ops)], drop()))
            .map(|v| v.iter().map(|k| k.flags).collect::<Vec<_>>())
    };
    let frag = FLAG_IS_FRAGMENT;
    let first = FLAG_IS_FRAGMENT | FLAG_FRAG_IS_FIRST;
    assert_eq!(
        f(vec![bit(false, false, 0x02)]).unwrap(),
        [Some((frag, frag))]
    );
    assert_eq!(
        f(vec![bit(false, false, 0x04)]).unwrap(),
        [Some((first, first))]
    );
    assert_eq!(f(vec![bit(false, true, 0x02)]).unwrap(), [Some((0, frag))]);
    // Not a first fragment: unfragmented or a later one.
    assert_eq!(
        f(vec![bit(false, true, 0x04)]).unwrap(),
        [Some((0, frag)), Some((frag, first))]
    );
    // IsF or not IsF: every packet, no key.
    assert_eq!(
        f(vec![bit(false, false, 0x02), bit(false, true, 0x02)]).unwrap(),
        [None]
    );
    assert_eq!(
        f(vec![bit(false, false, 0x01)]).unwrap_err(),
        "fragment DF/LF bits: no flower key"
    );
    let mut never = bit(false, true, 0x02);
    never.and = true;
    assert_eq!(
        f(vec![bit(false, false, 0x02), never]).unwrap_err(),
        "matches no packet"
    );
}

#[test]
fn unsupported_matches_are_refused_not_approximated() {
    let why = |c| lower(&rule(vec![c], drop())).unwrap_err();
    assert_eq!(
        why(FlowComponent::PacketLen(vec![eq(64)])),
        "packet length: no flower key"
    );
    assert_eq!(
        why(FlowComponent::FlowLabel(vec![eq(1)])),
        "flow label: no flower key"
    );
    assert_eq!(
        why(FlowComponent::Dest {
            prefix: "2001:db8::/64".parse().unwrap(),
            offset: 8
        }),
        "ipv6 prefix offset"
    );
    let r = rule(
        vec![],
        vec![FlowRuleAction::Unsupported("redirect 65000:1".into())],
    );
    assert_eq!(lower(&r).unwrap_err(), "redirect 65000:1");
}

#[test]
fn actions_in_order_with_the_verdict_from_the_t_bit() {
    let acts = |a: Vec<FlowRuleAction>, ipv6| {
        let mut r = rule(vec![], a);
        r.ipv6 = ipv6;
        lower(&r).unwrap().actions
    };
    let ta = |sample, terminal| FlowRuleAction::TrafficAction { sample, terminal };
    // No action: accept, flowspec evaluation stops, the ACL still runs.
    assert_eq!(
        acts(vec![], false),
        [ActionKind::Gact(Verdict::GotoChain(EXIT_CHAIN))]
    );
    // Everything: sample, mark, police, then T set = later rules apply.
    assert_eq!(
        acts(
            vec![
                FlowRuleAction::Dscp(46),
                FlowRuleAction::RateBytes(1000.4),
                FlowRuleAction::RatePackets(5.0),
                ta(true, true),
                FlowRuleAction::Dscp(10),
            ],
            true
        ),
        [
            ActionKind::Sample {
                rate: 100,
                trunc: 128,
                group: PSAMPLE_GROUP
            },
            ActionKind::Pedit(Pedit::Dscp {
                value: 46,
                family: PeditFamily::Ipv6
            }),
            ActionKind::Police {
                rate: 1001,
                burst: 16_384,
                unit: RateUnit::Bytes
            },
            ActionKind::Gact(Verdict::Unspec),
        ]
    );
    assert_eq!(
        acts(vec![FlowRuleAction::RatePackets(100.0)], false),
        [
            ActionKind::Police {
                rate: 100,
                burst: 100,
                unit: RateUnit::Packets
            },
            ActionKind::Gact(Verdict::GotoChain(EXIT_CHAIN)),
        ]
    );
    // A drop is final even with the T bit set; the IPv4 mark keeps its family.
    assert_eq!(
        acts(
            vec![
                FlowRuleAction::Dscp(1),
                FlowRuleAction::RatePackets(-0.0),
                ta(false, true)
            ],
            false
        ),
        [
            ActionKind::Pedit(Pedit::Dscp {
                value: 1,
                family: PeditFamily::Ip
            }),
            ActionKind::Gact(Verdict::Shot),
        ]
    );
}
