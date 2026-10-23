//! The request side: typed filters and actions, encoded into one netlink
//! message. Pure; `socket.rs` sends what this builds.

use std::io;
use std::net::IpAddr;

#[allow(clippy::wildcard_imports, reason = "the uapi constant table")]
use crate::consts::*;

/// Which side of the device a filter lives on (a `clsact` hook).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hook {
    Ingress,
    Egress,
}

impl Hook {
    pub(crate) fn parent(self) -> u32 {
        match self {
            Self::Ingress => HOOK_INGRESS,
            Self::Egress => HOOK_EGRESS,
        }
    }
}

/// The filter's `protocol`: which frames reach it at all. A frame carrying a
/// VLAN tag reads as `802.1Q`, so `Ip`/`Ipv6`/`Llc802_2` see untagged frames
/// only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    All,
    Llc802_2,
    Ip,
    Ipv6,
}

impl Protocol {
    fn ethertype(self) -> u16 {
        match self {
            Self::All => ETH_P_ALL,
            Self::Llc802_2 => ETH_P_802_2,
            Self::Ip => ETH_P_IP,
            Self::Ipv6 => ETH_P_IPV6,
        }
    }

    /// `htons(ethertype)`, the low half of `tcm_info`.
    fn info(self) -> u32 {
        u32::from(u16::from_ne_bytes(self.ethertype().to_be_bytes()))
    }
}

/// `TCA_FLOWER_KEY_FLAGS` bits (`pkt_cls.h`), for [`FlowerKeys::flags`].
pub const FLAG_IS_FRAGMENT: u32 = 1;
pub const FLAG_FRAG_IS_FIRST: u32 = 2;

/// Flower match keys, all optional; none set is the match-all. The kernel
/// only honours an L4 key when `ip_proto` is set (ports: TCP or UDP), and
/// an ICMP key when `ip_proto` is ICMP for the filter's family.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowerKeys {
    /// Destination MAC and its mask (`None`: exact, no mask attribute).
    pub eth_dst: Option<([u8; 6], Option<[u8; 6]>)>,
    pub ip_proto: Option<u8>,
    /// `(address, prefix length)`; the family picks the attribute.
    pub src_ip: Option<(IpAddr, u8)>,
    pub dst_ip: Option<(IpAddr, u8)>,
    /// Inclusive `(min, max)`; `min == max` uses the exact TCP/UDP key (the
    /// kernel rejects a range whose min is not below its max).
    pub src_port: Option<(u16, u16)>,
    pub dst_port: Option<(u16, u16)>,
    /// `(flags, mask)`, the TCP header's flag bits.
    pub tcp_flags: Option<(u16, u16)>,
    /// ICMP (`Protocol::Ip`) or `ICMPv6` (`Protocol::Ipv6`) type and code.
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    /// `(flags, mask)` of [`FLAG_IS_FRAGMENT`]/[`FLAG_FRAG_IS_FIRST`].
    pub flags: Option<(u32, u32)>,
    /// The tunnel's outer source (needs tunnel metadata on the device).
    pub enc_src_ip: Option<IpAddr>,
}

/// The classifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Flower(FlowerKeys),
    /// `fw`: matches `skb->mark & mask == handle`.
    Fw {
        mask: u32,
    },
}

/// What an action does with the packet next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    Shot,
    Pipe,
    /// Continue at the head of chain `n` (`n < 2^28`).
    GotoChain(u32),
}

impl Verdict {
    fn code(self) -> i32 {
        match self {
            Self::Ok => TC_ACT_OK,
            Self::Shot => TC_ACT_SHOT,
            Self::Pipe => TC_ACT_PIPE,
            // Checked below 2^28 by `check`, so the cast keeps every bit.
            #[allow(clippy::cast_possible_wrap, reason = "kernel int, bit pattern")]
            Self::GotoChain(c) => (TC_ACT_GOTO_CHAIN | c) as i32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionKind {
    Gact(Verdict),
    /// Sets `skb->mark` under `mask`, then `verdict`.
    Skbedit {
        mark: u32,
        mask: u32,
        verdict: Verdict,
    },
}

/// One action; a non-empty `cookie` (at most 16 bytes) is read back by
/// [`crate::dump`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    pub kind: ActionKind,
    pub cookie: Vec<u8>,
}

impl Action {
    /// An action without a cookie.
    pub fn new(kind: ActionKind) -> Self {
        Self {
            kind,
            cookie: Vec::new(),
        }
    }
}

/// One filter. `chain == 0` sends no `TCA_CHAIN`; `replace` swaps an
/// existing `handle` at the same chain/prio in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    pub ifindex: u32,
    pub hook: Hook,
    pub chain: u32,
    pub prio: u16,
    pub protocol: Protocol,
    pub handle: u32,
    pub kind: Kind,
    pub actions: Vec<Action>,
    pub replace: bool,
}

/// What one request creates or removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// The `clsact` qdisc (both hooks), exclusively: tolerate `EEXIST`.
    Clsact {
        ifindex: u32,
    },
    AddFilter(Filter),
    /// Removes `handle` (or, with `handle == 0`, every filter) at `prio`.
    DelFilter {
        ifindex: u32,
        hook: Hook,
        chain: u32,
        prio: u16,
        protocol: Protocol,
        handle: u32,
    },
    /// `RTM_DELCHAIN`: every filter of the chain goes.
    FlushChain {
        ifindex: u32,
        hook: Hook,
        chain: u32,
    },
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

fn check_verdict(v: Verdict) -> io::Result<()> {
    match v {
        Verdict::GotoChain(c) if c > TC_ACT_EXT_VAL_MASK => Err(invalid("goto chain >= 2^28")),
        _ => Ok(()),
    }
}

fn check_port(port: Option<(u16, u16)>, proto: Option<u8>) -> io::Result<()> {
    match port {
        Some((lo, hi)) if lo > hi => Err(invalid("port range min above max")),
        Some((lo, hi)) if lo == hi && !matches!(proto, Some(IPPROTO_TCP | IPPROTO_UDP)) => {
            Err(invalid("an exact port needs ip_proto tcp or udp"))
        }
        _ => Ok(()),
    }
}

fn check_prefix(p: Option<(IpAddr, u8)>) -> io::Result<()> {
    match p {
        Some((IpAddr::V4(_), l)) if l > 32 => Err(invalid("ipv4 prefix over 32")),
        Some((IpAddr::V6(_), l)) if l > 128 => Err(invalid("ipv6 prefix over 128")),
        _ => Ok(()),
    }
}

/// Everything the kernel would reject with a less helpful error, refused
/// before encoding.
fn check(f: &Filter) -> io::Result<()> {
    for a in &f.actions {
        if a.cookie.len() > TC_COOKIE_MAX_SIZE {
            return Err(invalid("cookie over 16 bytes"));
        }
        match a.kind {
            ActionKind::Gact(v) | ActionKind::Skbedit { verdict: v, .. } => check_verdict(v)?,
        }
    }
    if let Kind::Flower(k) = &f.kind {
        check_port(k.src_port, k.ip_proto)?;
        check_port(k.dst_port, k.ip_proto)?;
        check_prefix(k.src_ip)?;
        check_prefix(k.dst_ip)?;
    }
    Ok(())
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

/// `struct tc_gen` (index, capab, action, refcnt, bindcnt).
fn tc_gen(action: i32) -> Vec<u8> {
    let mut v = vec![0u8; 8];
    v.extend_from_slice(&action.to_ne_bytes());
    v.extend_from_slice(&[0u8; 8]);
    v
}

fn action(tab: &mut Vec<u8>, index: u16, a: &Action) {
    nested(tab, index, |act| {
        let name = match a.kind {
            ActionKind::Gact(_) => "gact",
            ActionKind::Skbedit { .. } => "skbedit",
        };
        nla(act, TCA_ACT_KIND, &cstr(name));
        nested(act, TCA_ACT_OPTIONS, |p| match a.kind {
            ActionKind::Gact(v) => nla(p, TCA_GACT_PARMS, &tc_gen(v.code())),
            ActionKind::Skbedit {
                mark,
                mask,
                verdict,
            } => {
                nla(p, TCA_SKBEDIT_PARMS, &tc_gen(verdict.code()));
                nla(p, TCA_SKBEDIT_MARK, &mark.to_ne_bytes());
                nla(p, TCA_SKBEDIT_MASK, &mask.to_ne_bytes());
            }
        });
        if !a.cookie.is_empty() {
            nla(act, TCA_ACT_COOKIE, &a.cookie);
        }
    });
}

/// `TCA_*_ACT`: the action table, numbered from 1.
fn actions(out: &mut Vec<u8>, kind: u16, acts: &[Action]) {
    if acts.is_empty() {
        return;
    }
    nested(out, kind, |tab| {
        for (i, a) in (1u16..).zip(acts) {
            action(tab, i, a);
        }
    });
}

/// Address and mask of a prefix, network order.
fn prefix(addr: IpAddr, len: u8) -> (Vec<u8>, Vec<u8>) {
    match addr {
        IpAddr::V4(a) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            (a.octets().to_vec(), mask.to_be_bytes().to_vec())
        }
        IpAddr::V6(a) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            (a.octets().to_vec(), mask.to_be_bytes().to_vec())
        }
    }
}

/// `attrs`: IPv4 address, its mask, IPv6 address, its mask.
fn ip_key(o: &mut Vec<u8>, key: Option<(IpAddr, u8)>, attrs: [u16; 4]) {
    if let Some((addr, len)) = key {
        let (kind, mask) = if addr.is_ipv4() {
            (attrs[0], attrs[1])
        } else {
            (attrs[2], attrs[3])
        };
        let (a, m) = prefix(addr, len);
        nla(o, kind, &a);
        nla(o, mask, &m);
    }
}

/// `attrs`: exact TCP port, exact UDP port, range min, range max.
fn port_key(o: &mut Vec<u8>, key: Option<(u16, u16)>, proto: Option<u8>, attrs: [u16; 4]) {
    match key {
        Some((lo, hi)) if lo == hi => {
            let kind = if proto == Some(IPPROTO_TCP) {
                attrs[0]
            } else {
                attrs[1]
            };
            nla(o, kind, &lo.to_be_bytes());
        }
        Some((lo, hi)) => {
            nla(o, attrs[2], &lo.to_be_bytes());
            nla(o, attrs[3], &hi.to_be_bytes());
        }
        None => {}
    }
}

fn flower(o: &mut Vec<u8>, k: &FlowerKeys, protocol: Protocol) {
    if let Some((mac, mask)) = k.eth_dst {
        nla(o, TCA_FLOWER_KEY_ETH_DST, &mac);
        if let Some(m) = mask {
            nla(o, TCA_FLOWER_KEY_ETH_DST_MASK, &m);
        }
    }
    // Flower reads its L3 keys only once `n_proto` is set, which comes from
    // this key, not from the filter's protocol (iproute2 sends both too).
    if matches!(protocol, Protocol::Ip | Protocol::Ipv6) {
        let ethertype = protocol.ethertype().to_be_bytes();
        nla(o, TCA_FLOWER_KEY_ETH_TYPE, &ethertype);
    }
    if let Some(p) = k.ip_proto {
        nla(o, TCA_FLOWER_KEY_IP_PROTO, &[p]);
    }
    let src = [
        TCA_FLOWER_KEY_IPV4_SRC,
        TCA_FLOWER_KEY_IPV4_SRC_MASK,
        TCA_FLOWER_KEY_IPV6_SRC,
        TCA_FLOWER_KEY_IPV6_SRC_MASK,
    ];
    let dst = [
        TCA_FLOWER_KEY_IPV4_DST,
        TCA_FLOWER_KEY_IPV4_DST_MASK,
        TCA_FLOWER_KEY_IPV6_DST,
        TCA_FLOWER_KEY_IPV6_DST_MASK,
    ];
    ip_key(o, k.src_ip, src);
    ip_key(o, k.dst_ip, dst);
    let src = [
        TCA_FLOWER_KEY_TCP_SRC,
        TCA_FLOWER_KEY_UDP_SRC,
        TCA_FLOWER_KEY_PORT_SRC_MIN,
        TCA_FLOWER_KEY_PORT_SRC_MAX,
    ];
    let dst = [
        TCA_FLOWER_KEY_TCP_DST,
        TCA_FLOWER_KEY_UDP_DST,
        TCA_FLOWER_KEY_PORT_DST_MIN,
        TCA_FLOWER_KEY_PORT_DST_MAX,
    ];
    port_key(o, k.src_port, k.ip_proto, src);
    port_key(o, k.dst_port, k.ip_proto, dst);
    if let Some((flags, mask)) = k.tcp_flags {
        nla(o, TCA_FLOWER_KEY_TCP_FLAGS, &flags.to_be_bytes());
        nla(o, TCA_FLOWER_KEY_TCP_FLAGS_MASK, &mask.to_be_bytes());
    }
    let (ty, code) = if protocol == Protocol::Ipv6 {
        (TCA_FLOWER_KEY_ICMPV6_TYPE, TCA_FLOWER_KEY_ICMPV6_CODE)
    } else {
        (TCA_FLOWER_KEY_ICMPV4_TYPE, TCA_FLOWER_KEY_ICMPV4_CODE)
    };
    if let Some(t) = k.icmp_type {
        nla(o, ty, &[t]);
    }
    if let Some(c) = k.icmp_code {
        nla(o, code, &[c]);
    }
    if let Some((flags, mask)) = k.flags {
        nla(o, TCA_FLOWER_KEY_FLAGS, &flags.to_be_bytes());
        nla(o, TCA_FLOWER_KEY_FLAGS_MASK, &mask.to_be_bytes());
    }
    match k.enc_src_ip {
        Some(IpAddr::V4(a)) => nla(o, TCA_FLOWER_KEY_ENC_IPV4_SRC, &a.octets()),
        Some(IpAddr::V6(a)) => nla(o, TCA_FLOWER_KEY_ENC_IPV6_SRC, &a.octets()),
        None => {}
    }
}

fn chain(body: &mut Vec<u8>, chain: u32) {
    if chain != 0 {
        nla(body, TCA_CHAIN, &chain.to_ne_bytes());
    }
}

/// `nlmsghdr` (request + ack + `flags`) around a `tcmsg` and its attributes.
fn message(kind: u16, flags: u16, seq: u32, tcm: [u32; 4], attrs: &[u8]) -> Vec<u8> {
    let len = 16 + 20 + attrs.len();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&u32::try_from(len).unwrap().to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&(NLM_F_REQUEST | flags).to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    // tcmsg: family, pad, then ifindex, handle, parent, info.
    out.extend_from_slice(&[0u8; 4]);
    for w in tcm {
        out.extend_from_slice(&w.to_ne_bytes());
    }
    out.extend_from_slice(attrs);
    out
}

fn add_filter(f: &Filter, seq: u32) -> Vec<u8> {
    let mut body = Vec::new();
    let flags = if f.replace {
        NLM_F_CREATE | NLM_F_REPLACE
    } else {
        NLM_F_CREATE
    };
    match &f.kind {
        Kind::Flower(k) => {
            nla(&mut body, TCA_KIND, &cstr("flower"));
            chain(&mut body, f.chain);
            nested(&mut body, TCA_OPTIONS, |o| {
                flower(o, k, f.protocol);
                actions(o, TCA_FLOWER_ACT, &f.actions);
            });
        }
        Kind::Fw { mask } => {
            nla(&mut body, TCA_KIND, &cstr("fw"));
            chain(&mut body, f.chain);
            nested(&mut body, TCA_OPTIONS, |o| {
                // The head's mask is fixed by its first filter, one per
                // priority.
                nla(o, TCA_FW_MASK, &mask.to_ne_bytes());
                actions(o, TCA_FW_ACT, &f.actions);
            });
        }
    }
    let info = (u32::from(f.prio) << 16) | f.protocol.info();
    message(
        RTM_NEWTFILTER,
        NLM_F_ACK | flags,
        seq,
        [f.ifindex, f.handle, f.hook.parent(), info],
        &body,
    )
}

/// The whole netlink message, `seq` chosen by the caller. Refuses (as
/// `InvalidInput`) a cookie over 16 bytes, a `goto chain` at or above 2^28,
/// an inverted port range, an exact port without `ip_proto` tcp/udp and an
/// over-long prefix.
pub fn encode(req: &Request, seq: u32) -> io::Result<Vec<u8>> {
    Ok(match req {
        Request::Clsact { ifindex } => {
            let mut body = Vec::new();
            nla(&mut body, TCA_KIND, &cstr("clsact"));
            message(
                RTM_NEWQDISC,
                NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
                seq,
                [*ifindex, 0xFFFF_0000, CLSACT, 0],
                &body,
            )
        }
        Request::AddFilter(f) => {
            check(f)?;
            add_filter(f, seq)
        }
        Request::DelFilter {
            ifindex,
            hook,
            chain: c,
            prio,
            protocol,
            handle,
        } => {
            let mut body = Vec::new();
            chain(&mut body, *c);
            let info = (u32::from(*prio) << 16) | protocol.info();
            message(
                RTM_DELTFILTER,
                NLM_F_ACK,
                seq,
                [*ifindex, *handle, hook.parent(), info],
                &body,
            )
        }
        Request::FlushChain {
            ifindex,
            hook,
            chain: c,
        } => {
            let mut body = Vec::new();
            nla(&mut body, TCA_CHAIN, &c.to_ne_bytes());
            message(
                RTM_DELCHAIN,
                NLM_F_ACK,
                seq,
                [*ifindex, 0, hook.parent(), 0],
                &body,
            )
        }
    })
}

/// `RTM_GETTFILTER` dump of every filter in `chain` at `hook`.
pub(crate) fn dump_request(ifindex: u32, hook: Hook, chain: u32, seq: u32) -> Vec<u8> {
    let mut body = Vec::new();
    nla(&mut body, TCA_CHAIN, &chain.to_ne_bytes());
    message(
        RTM_GETTFILTER,
        NLM_F_DUMP,
        seq,
        [ifindex, 0, hook.parent(), 0],
        &body,
    )
}

#[cfg(test)]
#[path = "encode_tests.rs"]
mod tests;
