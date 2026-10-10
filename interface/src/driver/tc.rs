//! Raw `RTM_NEWQDISC` / `RTM_NEWTFILTER` / `RTM_DELTFILTER` for the STP BPDU
//! trap (`docs/internals/stp.md`): a `BR_NO_STP` bridge floods the BPDU group
//! MAC, so every bridge port gets an ingress `flower dst_mac <group> action
//! drop` (protocol 802.2, i.e. untagged LLC frames). The drop happens after the `ETH_P_ALL` packet tap, so `nos-stpd`
//! (#327) still sees every BPDU. `netlink-packet-route` types `flower` but not
//! `gact`, so — like `nos-fdbd`'s `tc.rs`, which this is a trimmed per-crate
//! copy of — the messages are hand-built and sent on a plain `NETLINK_ROUTE`
//! socket (a unit test pins the layout, an ignored one runs them against the
//! real kernel).

use std::io;

use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

const RTM_NEWQDISC: u16 = 36;
const RTM_NEWTFILTER: u16 = 44;
const RTM_DELTFILTER: u16 = 45;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;

/// `TC_H_CLSACT` and its ingress hook.
const CLSACT: u32 = 0xFFFF_FFF1;
const HOOK_INGRESS: u32 = 0xFFFF_FFF2;
/// `htons(ETH_P_802_2)`, in the low half of `tcm_info` (the high half is the
/// priority). Every BPDU (IEEE or SSTP) is an 802.3 frame with an LLC header,
/// and a frame carrying a VLAN tag reads as `ETH_P_8021Q` to the classifier,
/// so the trap never drops the tagged SSTP of a trunk's sub-links on their
/// parent port (#322); the sub-link itself sees the tag already removed.
const ETH_P_802_2_BE: u32 = 0x0400;

const TCA_KIND: u16 = 1;
const TCA_OPTIONS: u16 = 2;
const NLA_F_NESTED: u16 = 1 << 15;

const TCA_FLOWER_ACT: u16 = 3;
const TCA_FLOWER_KEY_ETH_DST: u16 = 4;

const TCA_ACT_KIND: u16 = 1;
const TCA_ACT_OPTIONS: u16 = 2;
const TCA_GACT_PARMS: u16 = 2;
const TC_ACT_SHOT: i32 = 2;

/// The one filter priority this module uses.
pub const PRIO: u16 = 1;

/// The IEEE 802.1D/Q BPDU group address (STP, RSTP, MSTP).
pub const MAC_BPDU: [u8; 6] = [0x01, 0x80, 0xc2, 0, 0, 0];
/// Cisco's SSTP (per-VLAN spanning tree) group address.
pub const MAC_SSTP: [u8; 6] = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcd];
/// Every trapped destination with its filter handle.
pub const TRAPPED: [(u32, [u8; 6]); 2] = [(1, MAC_BPDU), (2, MAC_SSTP)];

/// What one request creates or removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tc {
    /// The `clsact` qdisc (both hooks); an existing one is left alone.
    Clsact { ifindex: u32 },
    /// `flower dst_mac <dst_mac> action drop` on the port's ingress.
    BpduTrap {
        ifindex: u32,
        handle: u32,
        dst_mac: [u8; 6],
    },
    /// Removes `handle` at [`PRIO`] from the port's ingress.
    Delete { ifindex: u32, handle: u32 },
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
        Tc::BpduTrap {
            ifindex, handle, ..
        } => (
            RTM_NEWTFILTER,
            NLM_F_CREATE,
            *ifindex,
            *handle,
            HOOK_INGRESS,
            PRIO,
        ),
        Tc::Delete { ifindex, handle } => {
            (RTM_DELTFILTER, 0, *ifindex, *handle, HOOK_INGRESS, PRIO)
        }
    };
    let info = match tc {
        Tc::Clsact { .. } => 0,
        _ => (u32::from(prio) << 16) | ETH_P_802_2_BE,
    };
    let mut body = Vec::new();
    body.extend_from_slice(&[0u8; 4]);
    body.extend_from_slice(&ifindex.to_ne_bytes());
    body.extend_from_slice(&handle.to_ne_bytes());
    body.extend_from_slice(&parent.to_ne_bytes());
    body.extend_from_slice(&info.to_ne_bytes());
    match tc {
        Tc::Clsact { .. } => nla(&mut body, TCA_KIND, &cstr("clsact")),
        Tc::BpduTrap { dst_mac, .. } => {
            nla(&mut body, TCA_KIND, &cstr("flower"));
            nested(&mut body, TCA_OPTIONS, |o| {
                // No mask attribute: an exact match.
                nla(o, TCA_FLOWER_KEY_ETH_DST, dst_mac);
                action(o, TCA_FLOWER_ACT, "gact", |p| {
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
    fn a_trap_matches_the_destination_and_drops() {
        let m = encode(
            &Tc::BpduTrap {
                ifindex: 9,
                handle: 2,
                dst_mac: MAC_SSTP,
            },
            1,
        );
        assert_eq!(u16_at(&m, 4), RTM_NEWTFILTER);
        assert_eq!(u16_at(&m, 6), NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE);
        assert_eq!(u32_at(&m, 20), 9);
        assert_eq!(u32_at(&m, 24), 2, "handle");
        assert_eq!(u32_at(&m, 28), HOOK_INGRESS);
        assert_eq!(u32_at(&m, 32), (1 << 16) | 0x0400, "prio 1, protocol 802.2");
        let top = attrs(&m[36..]);
        assert_eq!(top[0], (TCA_KIND, &b"flower\0"[..]));
        let opts = attrs(top[1].1);
        assert_eq!(opts[0], (TCA_FLOWER_KEY_ETH_DST, &MAC_SSTP[..]));
        assert_eq!(opts[1].0, TCA_FLOWER_ACT);
        let act = attrs(attrs(opts[1].1)[0].1);
        assert_eq!(act[0], (TCA_ACT_KIND, &b"gact\0"[..]));
        let p = attrs(act[1].1);
        assert_eq!(p[0].0, TCA_GACT_PARMS);
        assert_eq!(
            i32::from_ne_bytes(p[0].1[8..12].try_into().unwrap()),
            TC_ACT_SHOT
        );
    }

    #[test]
    fn a_delete_names_the_priority_and_handle_and_no_options() {
        let m = encode(
            &Tc::Delete {
                ifindex: 4,
                handle: 1,
            },
            1,
        );
        assert_eq!(u16_at(&m, 4), RTM_DELTFILTER);
        assert_eq!(u16_at(&m, 6), NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(u32_at(&m, 24), 1);
        assert_eq!(u32_at(&m, 28), HOOK_INGRESS);
        assert_eq!(u32_at(&m, 32), (1 << 16) | 0x0400);
        assert_eq!(m.len(), 36);
    }
}
