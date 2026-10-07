//! Raw `RTM_NEWQDISC` / `RTM_NEWTFILTER` / `RTM_DELTFILTER` for EVPN local bias
//! (RFC 8365 §8.3.1, see `docs/protocols/evpn-vxlan.md` "Implementation notes"): the bridge only sees the inner
//! frame, so the *outer* source of a core-origin BUM frame is classified by
//! `flower` on the VXLAN device's ingress (`enc_src_ip`) into `skb->mark`, and
//! `fw` + `gact drop` on a segment port's egress acts on the mark.
//! `netlink-packet-route` types flower but not `skbedit`, `fw` or `gact`, so —
//! like `nexthop.rs` — the few messages are hand-built and sent on a plain
//! `NETLINK_ROUTE` socket (a unit test pins the layout, an ignored one runs
//! them against the real kernel).

use std::io;
use std::net::IpAddr;

use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

const RTM_NEWQDISC: u16 = 36;
const RTM_NEWTFILTER: u16 = 44;
const RTM_DELTFILTER: u16 = 45;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;

/// `TC_H_CLSACT` and its two hooks.
const CLSACT: u32 = 0xFFFF_FFF1;
const HOOK_INGRESS: u32 = 0xFFFF_FFF2;
const HOOK_EGRESS: u32 = 0xFFFF_FFF3;
/// `htons(ETH_P_ALL)`, in the low half of `tcm_info` (the high half is the priority).
const ETH_P_ALL_BE: u32 = 0x0300;

const TCA_KIND: u16 = 1;
const TCA_OPTIONS: u16 = 2;
const NLA_F_NESTED: u16 = 1 << 15;

const TCA_FLOWER_ACT: u16 = 3;
const TCA_FLOWER_KEY_ETH_DST: u16 = 4;
const TCA_FLOWER_KEY_ETH_DST_MASK: u16 = 5;
const TCA_FLOWER_KEY_ENC_IPV4_SRC: u16 = 27;
const TCA_FLOWER_KEY_ENC_IPV6_SRC: u16 = 31;
const TCA_FW_ACT: u16 = 4;
const TCA_FW_MASK: u16 = 5;

const TCA_ACT_KIND: u16 = 1;
const TCA_ACT_OPTIONS: u16 = 2;
const TCA_SKBEDIT_PARMS: u16 = 2;
const TCA_SKBEDIT_MARK: u16 = 5;
const TCA_SKBEDIT_MASK: u16 = 8;
const TCA_GACT_PARMS: u16 = 2;
const TC_ACT_SHOT: i32 = 2;
const TC_ACT_PIPE: i32 = 3;

/// The top byte of every mark this module sets: any other mark is not ours.
pub const MARK_MAGIC: u32 = 0xE500_0000;
/// What `skbedit` may change: the magic byte and the segment bitmap, never
/// the middle byte (left for anything else using marks).
pub const MARK_MASK: u32 = 0xFF00_FFFF;
/// The filter priorities: peers first, the catch-all after them (the first
/// match wins); on a port the local-bias drop, then the DF drop.
pub const PRIO_FIRST: u16 = 1;
pub const PRIO_SECOND: u16 = 2;

/// The multicast bit of the destination MAC: broadcast, IPv4 and IPv6
/// multicast, i.e. the multi-destination frames local bias is about.
const MCAST_MAC: [u8; 6] = [1, 0, 0, 0, 0, 0];

/// Which side of the device a filter lives on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hook {
    Ingress,
    Egress,
}

impl Hook {
    fn parent(self) -> u32 {
        match self {
            Self::Ingress => HOOK_INGRESS,
            Self::Egress => HOOK_EGRESS,
        }
    }
}

/// What one request creates or removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tc {
    /// The `clsact` qdisc (both hooks); an existing one is left alone.
    Clsact { ifindex: u32 },
    /// `flower dst_mac <mcast> [enc_src_ip <src>] action skbedit mark
    /// <MARK_MAGIC | bits>/MARK_MASK` on the VXLAN device's ingress. No `src`
    /// is the catch-all: every core-origin BUM frame, marked with the magic
    /// byte alone.
    Mark {
        ifindex: u32,
        prio: u16,
        handle: u32,
        src: Option<IpAddr>,
        bits: u16,
    },
    /// `fw handle <MARK_MAGIC | bits>/<MARK_MAGIC-byte | bits> action drop` on a
    /// port's egress: drops a frame whose mark has all of `bits` set (and the
    /// magic byte); `bits == 0` drops every marked frame.
    DropMarked { ifindex: u32, prio: u16, bits: u16 },
    /// Removes `handle` (or, with `handle == 0`, every filter) at `prio`.
    Delete {
        ifindex: u32,
        hook: Hook,
        prio: u16,
        handle: u32,
    },
}

fn nla(out: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let len = u16::try_from(4 + payload.len()).expect("a tc attribute is tiny");
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(out.len().next_multiple_of(4), 0);
}

fn nested(out: &mut Vec<u8>, kind: u16, f: impl FnOnce(&mut Vec<u8>)) {
    let mut inner = Vec::new();
    f(&mut inner);
    nla(out, kind | NLA_F_NESTED, &inner);
}

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

/// `struct tc_gen` (index, capab, action, refcnt, bindcnt): both actions here
/// are just this.
fn tc_gen(action: i32) -> Vec<u8> {
    let mut v = vec![0u8; 8];
    v.extend_from_slice(&action.to_ne_bytes());
    v.extend_from_slice(&[0u8; 8]);
    v
}

/// `TCA_*_ACT`: a table holding one action, numbered 1.
fn action(out: &mut Vec<u8>, kind: u16, name: &str, f: impl FnOnce(&mut Vec<u8>)) {
    nested(out, kind, |tab| {
        nested(tab, 1, |act| {
            nla(act, TCA_ACT_KIND, &cstr(name));
            nested(act, TCA_ACT_OPTIONS, f);
        });
    });
}

/// The whole netlink message, `seq` chosen by the caller.
#[must_use]
pub fn encode(tc: &Tc, seq: u32) -> Vec<u8> {
    // tcmsg: family, pad, ifindex, handle, parent, info.
    let (kind, flags, ifindex, handle, parent, prio) = match tc {
        Tc::Clsact { ifindex } => (
            RTM_NEWQDISC,
            NLM_F_CREATE | NLM_F_EXCL,
            *ifindex,
            0xFFFF_0000,
            CLSACT,
            0,
        ),
        Tc::Mark {
            ifindex,
            prio,
            handle,
            ..
        } => (
            RTM_NEWTFILTER,
            NLM_F_CREATE,
            *ifindex,
            *handle,
            HOOK_INGRESS,
            *prio,
        ),
        Tc::DropMarked {
            ifindex,
            prio,
            bits,
        } => (
            RTM_NEWTFILTER,
            NLM_F_CREATE,
            *ifindex,
            MARK_MAGIC | u32::from(*bits),
            HOOK_EGRESS,
            *prio,
        ),
        Tc::Delete {
            ifindex,
            hook,
            prio,
            handle,
        } => (RTM_DELTFILTER, 0, *ifindex, *handle, hook.parent(), *prio),
    };
    let info = match tc {
        Tc::Clsact { .. } => 0,
        _ => (u32::from(prio) << 16) | ETH_P_ALL_BE,
    };
    let mut body = Vec::new();
    body.extend_from_slice(&[0u8; 4]);
    body.extend_from_slice(&ifindex.to_ne_bytes());
    body.extend_from_slice(&handle.to_ne_bytes());
    body.extend_from_slice(&parent.to_ne_bytes());
    body.extend_from_slice(&info.to_ne_bytes());
    match tc {
        Tc::Clsact { .. } => nla(&mut body, TCA_KIND, &cstr("clsact")),
        Tc::Mark { src, bits, .. } => {
            nla(&mut body, TCA_KIND, &cstr("flower"));
            nested(&mut body, TCA_OPTIONS, |o| {
                nla(o, TCA_FLOWER_KEY_ETH_DST, &MCAST_MAC);
                nla(o, TCA_FLOWER_KEY_ETH_DST_MASK, &MCAST_MAC);
                match src {
                    Some(IpAddr::V4(a)) => nla(o, TCA_FLOWER_KEY_ENC_IPV4_SRC, &a.octets()),
                    Some(IpAddr::V6(a)) => nla(o, TCA_FLOWER_KEY_ENC_IPV6_SRC, &a.octets()),
                    None => {}
                }
                action(o, TCA_FLOWER_ACT, "skbedit", |p| {
                    nla(p, TCA_SKBEDIT_PARMS, &tc_gen(TC_ACT_PIPE));
                    nla(
                        p,
                        TCA_SKBEDIT_MARK,
                        &(MARK_MAGIC | u32::from(*bits)).to_ne_bytes(),
                    );
                    nla(p, TCA_SKBEDIT_MASK, &MARK_MASK.to_ne_bytes());
                });
            });
        }
        Tc::DropMarked { bits, .. } => {
            nla(&mut body, TCA_KIND, &cstr("fw"));
            nested(&mut body, TCA_OPTIONS, |o| {
                // The head's mask is fixed by its first filter, one per
                // priority (hence two priorities on a port).
                nla(
                    o,
                    TCA_FW_MASK,
                    &(0xFF00_0000 | u32::from(*bits)).to_ne_bytes(),
                );
                action(o, TCA_FW_ACT, "gact", |p| {
                    nla(p, TCA_GACT_PARMS, &tc_gen(TC_ACT_SHOT));
                });
            });
        }
        Tc::Delete { .. } => {}
    }
    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(&u32::try_from(16 + body.len()).unwrap().to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK | flags).to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(&body);
    out
}

/// Sends one request and waits for its acknowledgement. Blocking: run it on a
/// blocking thread. `tolerate` are errnos (positive) that count as success.
pub fn send(tc: &Tc, tolerate: &[i32]) -> io::Result<()> {
    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;
    socket.send(&encode(tc, 1), 0)?;
    let mut reply = Vec::with_capacity(4096);
    socket.recv(&mut reply, 0)?;
    if reply.len() < 20 || u16::from_ne_bytes([reply[4], reply[5]]) != NLMSG_ERROR {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a netlink ack",
        ));
    }
    let errno = i32::from_ne_bytes([reply[16], reply[17], reply[18], reply[19]]);
    if errno == 0 || tolerate.contains(&-errno) {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(-errno))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16_at(b: &[u8], at: usize) -> u16 {
        u16::from_ne_bytes([b[at], b[at + 1]])
    }
    fn u32_at(b: &[u8], at: usize) -> u32 {
        u32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
    }

    /// The `(kind, payload)` attributes of a block, one level deep.
    fn attrs(b: &[u8]) -> Vec<(u16, &[u8])> {
        let mut v = Vec::new();
        let mut at = 0;
        while at + 4 <= b.len() {
            let len = usize::from(u16_at(b, at));
            v.push((u16_at(b, at + 2) & !NLA_F_NESTED, &b[at + 4..at + len]));
            at += len.next_multiple_of(4);
        }
        v
    }

    #[test]
    fn clsact_is_created_exclusively_on_the_clsact_parent() {
        let m = encode(&Tc::Clsact { ifindex: 7 }, 3);
        assert_eq!(u32_at(&m, 0) as usize, m.len());
        assert_eq!(u16_at(&m, 4), RTM_NEWQDISC);
        assert_eq!(
            u16_at(&m, 6),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        );
        assert_eq!(u32_at(&m, 8), 3);
        assert_eq!(u32_at(&m, 20), 7, "ifindex");
        assert_eq!(u32_at(&m, 24), 0xFFFF_0000, "handle");
        assert_eq!(u32_at(&m, 28), CLSACT, "parent");
        assert_eq!(attrs(&m[36..]), [(TCA_KIND, &b"clsact\0"[..])]);
    }

    #[test]
    fn a_peer_filter_matches_the_outer_source_and_sets_the_mark_under_a_mask() {
        let m = encode(
            &Tc::Mark {
                ifindex: 9,
                prio: 1,
                handle: 4,
                src: Some("10.0.0.2".parse().unwrap()),
                bits: 0b101,
            },
            1,
        );
        assert_eq!(u16_at(&m, 4), RTM_NEWTFILTER);
        assert_eq!(u16_at(&m, 6), NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE);
        assert_eq!(u32_at(&m, 24), 4, "handle");
        assert_eq!(u32_at(&m, 28), HOOK_INGRESS);
        assert_eq!(u32_at(&m, 32), (1 << 16) | 0x0300, "prio 1, protocol all");
        let top = attrs(&m[36..]);
        assert_eq!(top[0], (TCA_KIND, &b"flower\0"[..]));
        let opts = attrs(top[1].1);
        assert_eq!(opts[0], (TCA_FLOWER_KEY_ETH_DST, &MCAST_MAC[..]));
        assert_eq!(opts[1], (TCA_FLOWER_KEY_ETH_DST_MASK, &MCAST_MAC[..]));
        assert_eq!(opts[2], (TCA_FLOWER_KEY_ENC_IPV4_SRC, &[10, 0, 0, 2][..]));
        assert_eq!(opts[3].0, TCA_FLOWER_ACT);
        // action table -> action 1 -> kind, options
        let act = attrs(attrs(opts[3].1)[0].1);
        assert_eq!(act[0], (TCA_ACT_KIND, &b"skbedit\0"[..]));
        let p = attrs(act[1].1);
        assert_eq!(p[0].0, TCA_SKBEDIT_PARMS);
        assert_eq!(p[0].1.len(), 20);
        assert_eq!(
            i32::from_ne_bytes(p[0].1[8..12].try_into().unwrap()),
            TC_ACT_PIPE
        );
        assert_eq!(p[1], (TCA_SKBEDIT_MARK, &0xE500_0005u32.to_ne_bytes()[..]));
        assert_eq!(p[2], (TCA_SKBEDIT_MASK, &0xFF00_FFFFu32.to_ne_bytes()[..]));
    }

    #[test]
    fn an_ipv6_peer_uses_the_ipv6_key_and_the_catch_all_has_none() {
        let v6: IpAddr = "fd00::2".parse().unwrap();
        let m = encode(
            &Tc::Mark {
                ifindex: 1,
                prio: 1,
                handle: 1,
                src: Some(v6),
                bits: 1,
            },
            1,
        );
        let opts = attrs(attrs(&m[36..])[1].1);
        assert_eq!(
            opts[2],
            (
                TCA_FLOWER_KEY_ENC_IPV6_SRC,
                &[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2][..]
            )
        );

        let m = encode(
            &Tc::Mark {
                ifindex: 1,
                prio: 2,
                handle: 1,
                src: None,
                bits: 0,
            },
            1,
        );
        let opts = attrs(attrs(&m[36..])[1].1);
        assert_eq!(opts.len(), 3, "dst_mac, its mask, the action");
        let act = attrs(attrs(opts[2].1)[0].1);
        let p = attrs(act[1].1);
        assert_eq!(p[1], (TCA_SKBEDIT_MARK, &0xE500_0000u32.to_ne_bytes()[..]));
    }

    #[test]
    fn a_port_filter_drops_a_mark_by_handle_and_mask() {
        let m = encode(
            &Tc::DropMarked {
                ifindex: 3,
                prio: 1,
                bits: 0x0010,
            },
            1,
        );
        assert_eq!(u32_at(&m, 24), 0xE500_0010, "handle");
        assert_eq!(u32_at(&m, 28), HOOK_EGRESS);
        let top = attrs(&m[36..]);
        assert_eq!(top[0], (TCA_KIND, &b"fw\0"[..]));
        let opts = attrs(top[1].1);
        assert_eq!(opts[0], (TCA_FW_MASK, &0xFF00_0010u32.to_ne_bytes()[..]));
        assert_eq!(opts[1].0, TCA_FW_ACT);
        let act = attrs(attrs(opts[1].1)[0].1);
        assert_eq!(act[0], (TCA_ACT_KIND, &b"gact\0"[..]));
        let p = attrs(act[1].1);
        assert_eq!(p[0].0, TCA_GACT_PARMS);
        assert_eq!(
            i32::from_ne_bytes(p[0].1[8..12].try_into().unwrap()),
            TC_ACT_SHOT
        );

        // bits 0: every marked frame.
        let m = encode(
            &Tc::DropMarked {
                ifindex: 3,
                prio: 2,
                bits: 0,
            },
            1,
        );
        assert_eq!(u32_at(&m, 24), 0xE500_0000);
        assert_eq!(
            attrs(attrs(&m[36..])[1].1)[0],
            (TCA_FW_MASK, &0xFF00_0000u32.to_ne_bytes()[..])
        );
    }

    #[test]
    fn a_delete_names_the_priority_and_handle_and_no_options() {
        let m = encode(
            &Tc::Delete {
                ifindex: 4,
                hook: Hook::Egress,
                prio: 2,
                handle: 0,
            },
            1,
        );
        assert_eq!(u16_at(&m, 4), RTM_DELTFILTER);
        assert_eq!(u16_at(&m, 6), NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(u32_at(&m, 28), HOOK_EGRESS);
        assert_eq!(u32_at(&m, 32), (2 << 16) | 0x0300);
        assert_eq!(m.len(), 36);
    }

    /// Against the real kernel: needs `CAP_NET_ADMIN` in the current netns,
    /// and `tc` to read the result back, so run it in a throwaway one:
    /// `unshare -Urn cargo test -p nos-fdb tc:: -- --ignored`.
    #[test]
    #[ignore = "talks to the kernel; needs CAP_NET_ADMIN"]
    #[allow(
        clippy::disallowed_types,
        reason = "test code: `tc` is the independent oracle for the netlink encoder (#228)"
    )]
    fn the_kernel_accepts_every_message_and_reads_them_back_as_intended() {
        let run = |args: &[&str]| {
            let o = std::process::Command::new(args[0])
                .args(&args[1..])
                .output()
                .unwrap();
            assert!(
                o.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            String::from_utf8_lossy(&o.stdout).into_owned()
        };
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
        let idx = |n: &str| -> u32 {
            // `3: vx5: <...`
            run(&["ip", "-o", "link", "show", n])
                .split(':')
                .next()
                .unwrap()
                .parse()
                .unwrap()
        };
        let (vx, d0) = (idx("vx5"), idx("d0"));
        for i in [vx, d0] {
            send(&Tc::Clsact { ifindex: i }, &[]).unwrap();
            assert!(send(&Tc::Clsact { ifindex: i }, &[]).is_err(), "exclusive");
            send(&Tc::Clsact { ifindex: i }, &[17]).unwrap();
        }
        let mark = |handle, src: Option<&str>, bits, prio| Tc::Mark {
            ifindex: vx,
            prio,
            handle,
            src: src.map(|s| s.parse().unwrap()),
            bits,
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
        send(
            &Tc::DropMarked {
                ifindex: d0,
                prio: 1,
                bits: 0x0002,
            },
            &[],
        )
        .unwrap();
        send(
            &Tc::DropMarked {
                ifindex: d0,
                prio: 1,
                bits: 0x0002,
            },
            &[],
        )
        .unwrap();
        send(
            &Tc::DropMarked {
                ifindex: d0,
                prio: 2,
                bits: 0,
            },
            &[],
        )
        .unwrap();
        let shown = run(&["tc", "filter", "show", "dev", "d0", "egress"]);
        assert!(
            shown.contains("handle 0xe5000002") && shown.contains("handle 0xe5000000"),
            "{shown}"
        );
        assert!(shown.contains("action drop"), "{shown}");
        // Deleting a priority removes all its filters; again is ENOENT.
        let del = |hook, ifindex, prio, handle| Tc::Delete {
            ifindex,
            hook,
            prio,
            handle,
        };
        send(&del(Hook::Egress, d0, 2, 0), &[]).unwrap();
        assert!(send(&del(Hook::Egress, d0, 2, 0), &[]).is_err());
        send(&del(Hook::Egress, d0, 2, 0), &[2, 22]).unwrap();
        send(&del(Hook::Ingress, vx, 1, 2), &[]).unwrap();
        let shown = run(&["tc", "filter", "show", "dev", "vx5", "ingress"]);
        assert!(
            !shown.contains("fd00::3") && shown.contains("10.0.0.2"),
            "{shown}"
        );
    }
}
