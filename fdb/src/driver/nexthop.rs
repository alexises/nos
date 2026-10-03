//! Raw `RTM_NEWNEXTHOP` / `RTM_DELNEXTHOP` for FDB nexthops and groups
//! (`ip nexthop add id N via <vtep> fdb`, `... group A/B fdb`), which is how
//! one MAC is load-balanced over several VTEPs. `netlink-packet-route` has no
//! nexthop messages and `rtnetlink::Handle` only carries the ones it has, so
//! these few bytes are built by hand and sent on a plain `NETLINK_ROUTE`
//! socket.

use std::io;
use std::net::IpAddr;
#[cfg(test)]
use std::net::Ipv4Addr;

use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

const RTM_NEWNEXTHOP: u16 = 104;
const RTM_DELNEXTHOP: u16 = 105;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_CREATE: u16 = 0x400;

const NHA_ID: u16 = 1;
const NHA_GROUP: u16 = 2;
const NHA_GATEWAY: u16 = 6;
const NHA_FDB: u16 = 11;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const RTPROT_STATIC: u8 = 4;

/// What one request creates or removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Nexthop {
    /// An FDB nexthop: just a remote VTEP.
    Gateway {
        id: u32,
        gateway: IpAddr,
    },
    /// An FDB group over existing gateway nexthops (equal weight).
    Group {
        id: u32,
        members: Vec<u32>,
    },
    Delete {
        id: u32,
    },
}

fn nla(out: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let len = u16::try_from(4 + payload.len()).expect("a nexthop attribute is tiny");
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(out.len().next_multiple_of(4), 0);
}

/// The whole netlink message, `seq` chosen by the caller.
pub(super) fn encode(nh: &Nexthop, seq: u32) -> Vec<u8> {
    let (kind, flags, family) = match nh {
        Nexthop::Gateway { gateway, .. } => (
            RTM_NEWNEXTHOP,
            NLM_F_CREATE | NLM_F_REPLACE,
            if gateway.is_ipv4() { AF_INET } else { AF_INET6 },
        ),
        // A group has no family of its own.
        Nexthop::Group { .. } => (RTM_NEWNEXTHOP, NLM_F_CREATE | NLM_F_REPLACE, 0),
        Nexthop::Delete { .. } => (RTM_DELNEXTHOP, 0, 0),
    };
    // nhmsg: family, scope, protocol, resvd, flags. The scope must be zero —
    // the kernel rejects any other with EINVAL and picks link scope itself
    // (what `ip nexthop show` then prints).
    // A delete has to leave the protocol zero too (`nh_valid_get_del_req`).
    let protocol = if matches!(nh, Nexthop::Delete { .. }) {
        0
    } else {
        RTPROT_STATIC
    };
    let mut body = vec![family, 0, protocol, 0, 0, 0, 0, 0];
    match nh {
        Nexthop::Gateway { id, gateway } => {
            nla(&mut body, NHA_ID, &id.to_ne_bytes());
            match gateway {
                IpAddr::V4(a) => nla(&mut body, NHA_GATEWAY, &a.octets()),
                IpAddr::V6(a) => nla(&mut body, NHA_GATEWAY, &a.octets()),
            }
            nla(&mut body, NHA_FDB, &[]);
        }
        Nexthop::Group { id, members } => {
            nla(&mut body, NHA_ID, &id.to_ne_bytes());
            // struct nexthop_grp: id, weight (stored minus one), two reserved.
            let grp: Vec<u8> = members
                .iter()
                .flat_map(|m| {
                    let mut e = m.to_ne_bytes().to_vec();
                    e.extend_from_slice(&[0, 0, 0, 0]);
                    e
                })
                .collect();
            nla(&mut body, NHA_GROUP, &grp);
            nla(&mut body, NHA_FDB, &[]);
        }
        Nexthop::Delete { id } => nla(&mut body, NHA_ID, &id.to_ne_bytes()),
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

/// The errno an ack (`nlmsgerr`) carries, `0` for a plain acknowledgement.
fn ack_errno(reply: &[u8]) -> io::Result<i32> {
    if reply.len() < 20 || u16::from_ne_bytes([reply[4], reply[5]]) != NLMSG_ERROR {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a netlink ack",
        ));
    }
    Ok(i32::from_ne_bytes([
        reply[16], reply[17], reply[18], reply[19],
    ]))
}

/// Sends one request and waits for its acknowledgement. Blocking: run it on a
/// blocking thread. `tolerate` is an errno (positive) that counts as success.
pub(super) fn send(nh: &Nexthop, tolerate: i32) -> io::Result<()> {
    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;
    socket.send(&encode(nh, 1), 0)?;
    let mut reply = Vec::with_capacity(4096);
    socket.recv(&mut reply, 0)?;
    match ack_errno(&reply)? {
        0 => Ok(()),
        e if -e == tolerate => Ok(()),
        e => Err(io::Error::from_raw_os_error(-e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16_at(b: &[u8], at: usize) -> u16 {
        u16::from_ne_bytes([b[at], b[at + 1]])
    }

    #[test]
    fn a_gateway_is_an_fdb_nexthop_with_an_id_and_a_v4_gateway() {
        let m = encode(
            &Nexthop::Gateway {
                id: 0x0102_0304,
                gateway: Ipv4Addr::new(10, 50, 0, 7).into(),
            },
            9,
        );
        // nlmsghdr
        assert_eq!(
            u32::from_ne_bytes(m[0..4].try_into().unwrap()) as usize,
            m.len()
        );
        assert_eq!(u16_at(&m, 4), RTM_NEWNEXTHOP);
        assert_eq!(
            u16_at(&m, 6),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE
        );
        assert_eq!(u32::from_ne_bytes(m[8..12].try_into().unwrap()), 9);
        // nhmsg: AF_INET, scope 0 (the kernel rejects anything else)
        assert_eq!(&m[16..20], &[AF_INET, 0, RTPROT_STATIC, 0]);
        // NHA_ID, NHA_GATEWAY, NHA_FDB (empty), each 4-aligned
        assert_eq!((u16_at(&m, 24), u16_at(&m, 26)), (8, NHA_ID));
        assert_eq!(&m[28..32], &0x0102_0304u32.to_ne_bytes());
        assert_eq!((u16_at(&m, 32), u16_at(&m, 34)), (8, NHA_GATEWAY));
        assert_eq!(&m[36..40], &[10, 50, 0, 7]);
        assert_eq!((u16_at(&m, 40), u16_at(&m, 42)), (4, NHA_FDB));
        assert_eq!(m.len(), 44);
    }

    #[test]
    fn a_v6_gateway_is_af_inet6_with_16_octets() {
        let gw: std::net::Ipv6Addr = "fd00:10:50::a".parse().unwrap();
        let m = encode(
            &Nexthop::Gateway {
                id: 1,
                gateway: gw.into(),
            },
            1,
        );
        assert_eq!(&m[16..20], &[AF_INET6, 0, RTPROT_STATIC, 0]);
        assert_eq!((u16_at(&m, 32), u16_at(&m, 34)), (4 + 16, NHA_GATEWAY));
        assert_eq!(&m[36..52], &gw.octets());
        assert_eq!((u16_at(&m, 52), u16_at(&m, 54)), (4, NHA_FDB));
        assert_eq!(m.len(), 56);
    }

    #[test]
    fn a_group_lists_its_members_with_the_default_weight() {
        let m = encode(
            &Nexthop::Group {
                id: 7,
                members: vec![1, 2],
            },
            1,
        );
        assert_eq!(m[16], 0, "a group has no address family");
        // NHA_ID, then NHA_GROUP of two 8-byte entries, then NHA_FDB.
        assert_eq!(u16_at(&m, 26), NHA_ID);
        assert_eq!((u16_at(&m, 32), u16_at(&m, 34)), (4 + 16, NHA_GROUP));
        assert_eq!(&m[36..40], &1u32.to_ne_bytes());
        assert_eq!(&m[40..44], &[0, 0, 0, 0], "weight 0 means 1, reserved zero");
        assert_eq!(&m[44..48], &2u32.to_ne_bytes());
        assert_eq!((u16_at(&m, 52), u16_at(&m, 54)), (4, NHA_FDB));
    }

    #[test]
    fn a_delete_names_only_the_id() {
        let m = encode(&Nexthop::Delete { id: 5 }, 1);
        assert_eq!(&m[16..24], &[0; 8], "the whole nhmsg is zero");
        assert_eq!(u16_at(&m, 4), RTM_DELNEXTHOP);
        assert_eq!(u16_at(&m, 6), NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(m.len(), 16 + 8 + 8);
    }

    /// Against the real kernel: needs `CAP_NET_ADMIN` in the current netns, so
    /// run it in a throwaway one:
    /// `unshare -Urn cargo test -p nos-fdb nexthop -- --ignored`.
    #[test]
    #[ignore = "talks to the kernel; needs CAP_NET_ADMIN"]
    fn the_kernel_accepts_gateways_a_group_and_their_removal() {
        let gw = |id, a: [u8; 4]| Nexthop::Gateway {
            id,
            gateway: Ipv4Addr::from(a).into(),
        };
        send(&gw(1, [10, 50, 0, 11]), 0).unwrap();
        send(&gw(2, [10, 50, 0, 12]), 0).unwrap();
        // The same id again is a replace, not an error.
        send(&gw(2, [10, 50, 0, 12]), 0).unwrap();
        send(
            &Nexthop::Group {
                id: 3,
                members: vec![1, 2],
            },
            0,
        )
        .unwrap();
        send(&Nexthop::Delete { id: 3 }, 0).unwrap();
        send(&Nexthop::Delete { id: 1 }, 0).unwrap();
        send(&Nexthop::Delete { id: 2 }, 0).unwrap();
        // Already gone: only fine when tolerated.
        assert!(send(&Nexthop::Delete { id: 2 }, 0).is_err());
        send(&Nexthop::Delete { id: 2 }, 2).unwrap();
        // IPv6 gateways and a group over them (one family per group).
        let gw6 = |id, a: &str| Nexthop::Gateway {
            id,
            gateway: a.parse().unwrap(),
        };
        send(&gw6(4, "fd00:10:50::a"), 0).unwrap();
        send(&gw6(5, "fd00:10:50::b"), 0).unwrap();
        send(
            &Nexthop::Group {
                id: 6,
                members: vec![4, 5],
            },
            0,
        )
        .unwrap();
        for id in [6, 4, 5] {
            send(&Nexthop::Delete { id }, 0).unwrap();
        }
    }

    #[test]
    fn an_ack_carries_the_negated_errno() {
        let mut reply = vec![0u8; 36];
        reply[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        reply[16..20].copy_from_slice(&(-2i32).to_ne_bytes());
        assert_eq!(ack_errno(&reply).unwrap(), -2);
        assert!(ack_errno(&reply[..8]).is_err());
    }
}
