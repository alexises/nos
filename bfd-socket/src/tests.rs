use super::*;
use socket2::{Domain, Protocol, Socket, Type};
use std::os::fd::AsRawFd;

fn pair(v6: bool) -> (Socket, SocketAddr) {
    let (d, ip): (_, IpAddr) = if v6 {
        (Domain::IPV6, Ipv6Addr::LOCALHOST.into())
    } else {
        (Domain::IPV4, Ipv4Addr::LOCALHOST.into())
    };
    let s = Socket::new(d, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    s.bind(&SocketAddr::new(ip, 0).into()).unwrap();
    let addr = s.local_addr().unwrap().as_socket().unwrap();
    (s, addr)
}

#[test]
fn ifindex_lo_and_missing() {
    assert_ne!(ifindex("lo"), 0);
    assert_eq!(ifindex("nos-no-such-if"), 0);
    assert_eq!(ifindex("bad\0name"), 0);
}

#[test]
fn set_int_ok_and_error() {
    let (s, _) = pair(false);
    set_int(s.as_raw_fd(), libc::IPPROTO_IP, libc::IP_RECVTTL, 1).unwrap();
    assert!(set_int(s.as_raw_fd(), libc::IPPROTO_IP, 9999, 1).is_err());
}

fn roundtrip(v6: bool) {
    let (rx, to) = pair(v6);
    let (level, opt, pkt) = if v6 {
        (
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVHOPLIMIT,
            libc::IPV6_RECVPKTINFO,
        )
    } else {
        (libc::IPPROTO_IP, libc::IP_RECVTTL, libc::IP_PKTINFO)
    };
    let fd = rx.as_raw_fd();
    let domain = if v6 { Domain::IPV6 } else { Domain::IPV4 };
    let tx = Socket::new(domain, Type::DGRAM, None).unwrap();
    let dst: SockAddr = to.into();
    let src: IpAddr = to.ip();

    // No source address, no ancillary data requested yet.
    send_from(tx.as_raw_fd(), &dst, None, b"a").unwrap();
    let mut buf = [0u8; 16];
    let d = recv_one(fd, &mut buf).unwrap();
    assert_eq!((d.src, d.len, d.ttl), (src, 1, None));

    // TTL / hop limit once asked for.
    set_int(fd, level, opt, 1).unwrap();
    if v6 {
        tx.set_unicast_hops_v6(77).unwrap();
    } else {
        tx.set_ttl_v4(77).unwrap();
    }
    send_from(tx.as_raw_fd(), &dst, Some(src), b"bc").unwrap();
    let d = recv_one(fd, &mut buf).unwrap();
    assert_eq!((d.len, d.ttl), (2, Some(77)));

    // Probe: the destination comes from pktinfo, the name is the sender.
    set_int(fd, level, pkt, 1).unwrap();
    send_from(tx.as_raw_fd(), &dst, Some(src), b"xyz").unwrap();
    let p = recv_probe(fd, &mut buf).unwrap();
    assert_eq!((p.len, p.dst, p.src.ip()), (3, src, src));
    assert_eq!(p.name.as_socket(), Some(p.src));
}

#[test]
fn roundtrip_v4() {
    roundtrip(false);
}

#[test]
fn roundtrip_v6() {
    // Hosts without an IPv6 loopback cannot bind ::1.
    if Socket::new(Domain::IPV6, Type::DGRAM, None)
        .and_then(|s| s.bind(&SocketAddr::from((Ipv6Addr::LOCALHOST, 0)).into()))
        .is_ok()
    {
        roundtrip(true);
    }
}

#[test]
fn bad_fd_errors() {
    let mut buf = [0u8; 4];
    assert!(recv_one(-1, &mut buf).is_err());
    assert!(recv_probe(-1, &mut buf).is_err());
    let to = SockAddr::from(SocketAddr::from(([127, 0, 0, 1], 9)));
    assert!(send_from(-1, &to, None, b"x").is_err());
}
