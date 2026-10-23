//! Against the real kernel: needs `CAP_NET_ADMIN` in the current netns, and
//! `ip`/`tc` (the independent oracle) to set up and read back, so run it in a
//! throwaway one: `unshare -Urn cargo test -p nos-tc --test kernel -- --ignored`.
#![allow(
    clippy::disallowed_types,
    reason = "test code: `ip`/`tc` are the independent oracle for the netlink encoder (#228)"
)]

use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::process::Command;

use nos_tc::{
    dump, send, Action, ActionKind, Filter, FlowerKeys, Hook, Kind, Protocol, Request, Verdict,
    FLAG_IS_FRAGMENT,
};

const EEXIST: i32 = 17;
const ENOENT: i32 = 2;
const EINVAL: i32 = 22;

fn run(args: &[&str]) -> String {
    let o = Command::new(args[0]).args(&args[1..]).output().unwrap();
    assert!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// `3: vx5: <...`
fn idx(name: &str) -> u32 {
    run(&["ip", "-o", "link", "show", name])
        .split(':')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

fn gact(v: Verdict) -> Vec<Action> {
    vec![Action::new(ActionKind::Gact(v))]
}

fn add(
    ifindex: u32,
    chain: u32,
    prio: u16,
    protocol: Protocol,
    keys: FlowerKeys,
    actions: Vec<Action>,
) {
    send(
        &Request::AddFilter(Filter {
            ifindex,
            hook: Hook::Ingress,
            chain,
            prio,
            protocol,
            handle: 1,
            kind: Kind::Flower(keys),
            actions,
            replace: false,
        }),
        &[],
    )
    .unwrap();
}

/// The raw reply to a hand-built dump request of `chain` at ingress, every
/// received buffer concatenated: the source of `decode_tests.rs`'s fixture.
fn raw_dump(ifindex: u32, chain: u32) -> Vec<u8> {
    use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
    let mut req = Vec::new();
    for w in [
        44u32,
        0x2E | (0x301 << 16),
        1,
        0,
        0,
        ifindex,
        0,
        0xFFFF_FFF2,
        0,
    ] {
        req.extend_from_slice(&w.to_ne_bytes());
    }
    req.extend_from_slice(&8u16.to_ne_bytes());
    req.extend_from_slice(&11u16.to_ne_bytes());
    req.extend_from_slice(&chain.to_ne_bytes());
    let mut s = Socket::new(NETLINK_ROUTE).unwrap();
    s.bind_auto().unwrap();
    s.connect(&SocketAddr::new(0, 0)).unwrap();
    s.send(&req, 0).unwrap();
    let mut all = Vec::new();
    loop {
        let mut buf = Vec::with_capacity(1 << 16);
        s.recv(&mut buf, 0).unwrap();
        all.extend_from_slice(&buf);
        // The last message of the buffer is NLMSG_DONE (type 3) at the end.
        if buf.len() >= 20 && buf[buf.len() - 20 + 4] == 3 {
            return all;
        }
    }
}

/// `nos-fdbd`'s local-bias shapes: `flower enc_src_ip` + `skbedit`, `fw` +
/// `gact drop`, per-priority delete.
#[test]
#[ignore = "talks to the kernel; needs CAP_NET_ADMIN"]
fn fdb_local_bias_filters_round_trip() {
    run(&["ip", "link", "set", "lo", "up"]);
    run(&[
        "ip",
        "link",
        "add",
        "vx5",
        "type",
        "vxlan",
        "id",
        "5",
        "dstport",
        "4789",
        "local",
        "10.0.0.1",
        "nolearning",
    ]);
    run(&["ip", "link", "add", "d0", "type", "dummy"]);
    let (vx, d0) = (idx("vx5"), idx("d0"));
    for i in [vx, d0] {
        send(&Request::Clsact { ifindex: i }, &[]).unwrap();
        assert!(
            send(&Request::Clsact { ifindex: i }, &[]).is_err(),
            "exclusive"
        );
        send(&Request::Clsact { ifindex: i }, &[EEXIST]).unwrap();
    }
    let mcast = [1, 0, 0, 0, 0, 0];
    let mark = |handle, src: Option<&str>, bits: u32, prio| {
        Request::AddFilter(Filter {
            ifindex: vx,
            hook: Hook::Ingress,
            chain: 0,
            prio,
            protocol: Protocol::All,
            handle,
            kind: Kind::Flower(FlowerKeys {
                eth_dst: Some((mcast, Some(mcast))),
                enc_src_ip: src.map(|s| s.parse().unwrap()),
                ..FlowerKeys::default()
            }),
            actions: vec![Action::new(ActionKind::Skbedit {
                mark: 0xE500_0000 | bits,
                mask: 0xFF00_FFFF,
                verdict: Verdict::Pipe,
            })],
            replace: false,
        })
    };
    send(&mark(1, Some("10.0.0.2"), 0b11, 1), &[]).unwrap();
    send(&mark(2, Some("fd00::2"), 0b01, 1), &[]).unwrap();
    // The same handle again replaces.
    send(&mark(2, Some("fd00::3"), 0b01, 1), &[]).unwrap();
    send(&mark(1, None, 0, 2), &[]).unwrap();
    let shown = run(&["tc", "filter", "show", "dev", "vx5", "ingress"]);
    for want in [
        "enc_src_ip 10.0.0.2",
        "enc_src_ip fd00::3",
        "mark 3841982467/0xff00ffff",
        "mark 3841982464/0xff00ffff",
    ] {
        assert!(shown.contains(want), "{want} in {shown}");
    }
    assert!(!shown.contains("fd00::2"), "{shown}");
    let drop = |prio, bits: u32| {
        Request::AddFilter(Filter {
            ifindex: d0,
            hook: Hook::Egress,
            chain: 0,
            prio,
            protocol: Protocol::All,
            handle: 0xE500_0000 | bits,
            kind: Kind::Fw {
                mask: 0xFF00_0000 | bits,
            },
            actions: gact(Verdict::Shot),
            replace: false,
        })
    };
    send(&drop(1, 2), &[]).unwrap();
    send(&drop(1, 2), &[]).unwrap();
    send(&drop(2, 0), &[]).unwrap();
    let shown = run(&["tc", "filter", "show", "dev", "d0", "egress"]);
    assert!(
        shown.contains("handle 0xe5000002") && shown.contains("handle 0xe5000000"),
        "{shown}"
    );
    assert!(shown.contains("action drop"), "{shown}");
    let rows = dump(d0, Hook::Egress, 0).unwrap();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows.iter().all(|r| r.action == "gact"), "{rows:?}");
    // Deleting a priority removes all its filters; again is ENOENT.
    let del = |hook, ifindex, prio, handle| Request::DelFilter {
        ifindex,
        hook,
        chain: 0,
        prio,
        protocol: Protocol::All,
        handle,
    };
    send(&del(Hook::Egress, d0, 2, 0), &[]).unwrap();
    assert!(send(&del(Hook::Egress, d0, 2, 0), &[]).is_err());
    send(&del(Hook::Egress, d0, 2, 0), &[ENOENT, EINVAL]).unwrap();
    send(&del(Hook::Ingress, vx, 1, 2), &[]).unwrap();
    let shown = run(&["tc", "filter", "show", "dev", "vx5", "ingress"]);
    assert!(
        !shown.contains("fd00::3") && shown.contains("10.0.0.2"),
        "{shown}"
    );
}

/// ACL shapes (#541): a chain of flower filters behind a keyless `goto
/// chain` entry, swapped in place, counted, flushed; foreign filters on
/// chain 0 survive.
#[test]
#[ignore = "talks to the kernel; needs CAP_NET_ADMIN"]
#[allow(clippy::too_many_lines, reason = "one linear kernel scenario")]
fn acl_chains_swap_count_and_flush() {
    run(&["ip", "link", "set", "lo", "up"]);
    run(&[
        "ip",
        "link",
        "add",
        "v0",
        "address",
        "02:00:00:00:00:01",
        "type",
        "veth",
        "peer",
        "name",
        "v1",
        "address",
        "02:00:00:00:00:02",
    ]);
    run(&["ip", "link", "set", "v0", "up"]);
    run(&["ip", "link", "set", "v1", "up"]);
    run(&["ip", "addr", "add", "192.0.2.1/24", "dev", "v0"]);
    run(&[
        "ip",
        "neigh",
        "add",
        "192.0.2.9",
        "lladdr",
        "02:00:00:00:00:02",
        "dev",
        "v0",
        "nud",
        "permanent",
    ]);
    let v1 = idx("v1");
    send(&Request::Clsact { ifindex: v1 }, &[EEXIST]).unwrap();
    // Foreign owners (nos-fdbd/nos-interfaced) at priorities 1 and 2.
    for prio in [1, 2] {
        let keys = FlowerKeys {
            eth_dst: Some(([1, 0x80, 0xc2, 0, 0, 0], None)),
            ..FlowerKeys::default()
        };
        add(v1, 0, prio, Protocol::Llc802_2, keys, gact(Verdict::Shot));
    }

    let net = |a, b, c, d, len| Some((IpAddr::V4(Ipv4Addr::new(a, b, c, d)), len));
    let cookie = |n: u32| Action {
        kind: ActionKind::Gact(Verdict::Pipe),
        cookie: n.to_be_bytes().to_vec(),
    };
    let tcp = |keys| FlowerKeys {
        ip_proto: Some(6),
        ..keys
    };
    let none = FlowerKeys::default;
    // First alone, so the captured dump below is one filter long.
    let udp = FlowerKeys {
        dst_ip: net(192, 0, 2, 9, 32),
        ip_proto: Some(17),
        dst_port: Some((5000, 5000)),
        ..none()
    };
    add(
        v1,
        1000,
        7,
        Protocol::Ip,
        udp,
        vec![cookie(7), Action::new(ActionKind::Gact(Verdict::Shot))],
    );

    // The entry: a keyless flower (not matchall) on chain 0, replaced in place.
    let entry = |chain, replace| {
        Request::AddFilter(Filter {
            ifindex: v1,
            hook: Hook::Ingress,
            chain: 0,
            prio: 100,
            protocol: Protocol::All,
            handle: 1,
            kind: Kind::Flower(none()),
            actions: gact(Verdict::GotoChain(chain)),
            replace,
        })
    };
    send(&entry(1000, false), &[]).unwrap();
    let shown = run(&["tc", "filter", "show", "dev", "v1", "ingress", "chain", "0"]);
    assert!(shown.contains("goto chain 1000"), "{shown}");

    let to = std::net::SocketAddr::from(([192, 0, 2, 9], 5000));
    let sock = UdpSocket::bind("192.0.2.1:0").unwrap();
    for _ in 0..3 {
        sock.send_to(b"acl", to).unwrap();
    }
    std::thread::sleep(std::time::Duration::from_millis(200));
    if std::env::var_os("NOS_TC_CAPTURE").is_some() {
        let hex = raw_dump(v1, 1000).iter().fold(String::new(), |mut s, b| {
            write!(s, "{b:02x}").unwrap();
            s
        });
        println!("DUMP_REPLY {hex}");
    }

    add(
        v1,
        1000,
        1,
        Protocol::Ip,
        tcp(FlowerKeys {
            src_ip: net(10, 1, 0, 0, 16),
            dst_port: Some((1024, 2048)),
            ..none()
        }),
        vec![cookie(1)],
    );
    add(
        v1,
        1000,
        2,
        Protocol::Ip,
        tcp(FlowerKeys {
            tcp_flags: Some((0x10, 0x10)),
            ..none()
        }),
        vec![cookie(2)],
    );
    add(
        v1,
        1000,
        3,
        Protocol::Ip,
        FlowerKeys {
            ip_proto: Some(1),
            icmp_type: Some(8),
            icmp_code: Some(0),
            ..none()
        },
        vec![cookie(3)],
    );
    add(
        v1,
        1000,
        4,
        Protocol::Ip,
        FlowerKeys {
            flags: Some((FLAG_IS_FRAGMENT, FLAG_IS_FRAGMENT)),
            ..none()
        },
        vec![cookie(4)],
    );
    let v6 = FlowerKeys {
        dst_ip: Some(("2001:db8::".parse().unwrap(), 32)),
        ip_proto: Some(17),
        dst_port: Some((53, 53)),
        ..none()
    };
    add(v1, 1000, 5, Protocol::Ipv6, v6, vec![cookie(5)]);
    add(
        v1,
        1000,
        6,
        Protocol::Ipv6,
        FlowerKeys {
            ip_proto: Some(58),
            icmp_type: Some(128),
            ..none()
        },
        vec![cookie(6)],
    );
    let shown = run(&[
        "tc", "filter", "show", "dev", "v1", "ingress", "chain", "1000",
    ]);
    for want in [
        "src_ip 10.1.0.0/16",
        "dst_port 1024-2048",
        "tcp_flags 0x10/10",
        "icmp_type 8",
        "ip_flags frag",
        "dst_ip 2001:db8::/32",
        "dst_port 53",
        "icmp_type 128",
        "cookie 00000007",
    ] {
        assert!(shown.contains(want), "{want} in {shown}");
    }

    let rows = dump(v1, Hook::Ingress, 1000).unwrap();
    assert_eq!(rows.len(), 8, "one row per action: {rows:?}");
    let hit: Vec<_> = rows.iter().filter(|r| r.prio == 7).collect();
    assert_eq!(hit.len(), 2, "{rows:?}");
    assert_eq!(hit[0].cookie, 7u32.to_be_bytes());
    assert_eq!(
        (hit[0].chain, hit[0].handle, hit[0].packets),
        (1000, 1, 3),
        "{hit:?}"
    );
    assert!(hit[0].bytes >= 3 * 31, "{hit:?}");
    assert!(hit[1].cookie.is_empty() && hit[1].action == "gact");
    assert!(
        rows.iter().filter(|r| r.prio < 7).all(|r| r.packets == 0),
        "{rows:?}"
    );
    let head = dump(v1, Hook::Ingress, 0).unwrap();
    // The entry also sees the veth's own IPv6 autoconf traffic.
    assert_eq!(
        head.iter().map(|r| r.prio).collect::<Vec<_>>(),
        [1, 2, 100],
        "{head:?}"
    );
    assert!(head[2].packets >= 3, "{head:?}");
    assert!(
        dump(v1, Hook::Ingress, 4242).unwrap().is_empty(),
        "no such chain"
    );
    assert!(dump(v1, Hook::Egress, 0).unwrap().is_empty(), "egress");

    add(v1, 1001, 1, Protocol::Ip, none(), vec![cookie(9)]);
    send(&entry(1001, true), &[]).unwrap();
    let shown = run(&["tc", "filter", "show", "dev", "v1", "ingress", "chain", "0"]);
    assert!(
        shown.contains("goto chain 1001") && !shown.contains("goto chain 1000"),
        "{shown}"
    );
    assert_eq!(
        shown.matches("pref 100 ").count(),
        2,
        "head + one filter: {shown}"
    );

    send(
        &Request::FlushChain {
            ifindex: v1,
            hook: Hook::Ingress,
            chain: 1000,
        },
        &[],
    )
    .unwrap();
    let left = run(&[
        "tc", "filter", "show", "dev", "v1", "ingress", "chain", "1000",
    ]);
    assert!(left.trim().is_empty(), "flushed: {left}");
    assert!(dump(v1, Hook::Ingress, 1000).unwrap().is_empty(), "flushed");
    let kept = run(&["tc", "filter", "show", "dev", "v1", "ingress"]);
    for want in [
        "pref 1 flower",
        "pref 2 flower",
        "goto chain 1001",
        "chain 1001",
    ] {
        assert!(kept.contains(want), "{want} in {kept}");
    }
    assert!(send(
        &Request::FlushChain {
            ifindex: v1,
            hook: Hook::Ingress,
            chain: 1000
        },
        &[]
    )
    .is_err());
    send(
        &Request::FlushChain {
            ifindex: v1,
            hook: Hook::Ingress,
            chain: 1000,
        },
        &[ENOENT, EINVAL],
    )
    .unwrap();
}
