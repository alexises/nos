//! The UDP side of RFC 5881 single-hop (3784) and RFC 5883 multihop (4784) BFD (excluded from coverage: it only
//! runs against a real kernel, `nos-e2e`'s `bfd` phase is its test).
//!
//! - One receive socket per (table, address family): UDP 3784 wildcard,
//!   `SO_BINDTODEVICE` to the table's VRF, `IP_RECVTTL`/`IPV6_RECVHOPLIMIT` so
//!   every datagram's TTL is checked (RFC 5881 §5: must be exactly 255).
//! - Echo (RFC 5881 §4): per single-hop session one `AF_PACKET` socket
//!   (`nos_l2_socket::L2Unicast`, filtered to UDP 3785) on the session's
//!   interface, sending to the neighbour's MAC read from the kernel; the
//!   returned packet has our own address as source, which the IP stack would
//!   drop as a martian, so it is received at the packet layer too.
//! - One connected transmit socket per session, a fixed random source port in
//!   49152-65535 (§4), TTL/hop limit 255, bound to the session's interface or
//!   else the VRF.

#![allow(
    unsafe_code,
    reason = "recvmsg/cmsg parsing and setsockopt: std and socket2 expose no TTL ancillary data"
)]

use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use nos_proto::{RibEvent, RibRequest, Role, ServiceRef, SessionKey};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::echo;
use crate::manager::{Demux, Net};
use crate::micro;
use crate::neigh;
use crate::packet;
use crate::reflector::Reflector;
use crate::sbfd::{self, SbfdPath};
use crate::session::{rand_u32, EchoPath, EchoTx, Looped, Tx};
use nos_daemon::{ipc, watchdog};
use nos_l2_socket::{L2Socket, L2Unicast};

/// The Linux VRF device of routing table `table`, `None` while `nos-ribd`
/// is unreachable or has not created it.
pub async fn vrf_name(watchdog_socket: &std::path::Path, table: &str) -> Option<String> {
    let rib =
        watchdog::resolve_once(watchdog_socket, &ServiceRef::RibTable(table.to_string())).await?;
    match ipc::one_shot(&rib, Role::Ribd, RibRequest::GetVrfName).await? {
        RibEvent::VrfName(name) => name,
        _ => None,
    }
}

pub const BFD_PORT: u16 = 3784;
/// RFC 5883 §2: multihop control packets.
pub const BFD_MULTIHOP_PORT: u16 = 4784;

const fn port(multihop: bool) -> u16 {
    if multihop {
        BFD_MULTIHOP_PORT
    } else {
        BFD_PORT
    }
}
const TTL: u32 = 255;
/// Largest micro-BFD frame worth reading (Ethernet + IP + UDP + a 24-byte-plus-auth PDU).
const RX_FRAME: usize = 256;

fn ifindex(name: &str) -> u32 {
    CString::new(name)
        .ok()
        // SAFETY: a valid NUL-terminated string.
        .map_or(0, |c| unsafe { libc::if_nametoindex(c.as_ptr()) })
}

fn set_int(fd: RawFd, level: libc::c_int, opt: libc::c_int, v: libc::c_int) -> io::Result<()> {
    // SAFETY: `v` outlives the call and the length is its size.
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            (&raw const v).cast(),
            libc::socklen_t::try_from(size_of::<libc::c_int>()).unwrap_or(4),
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn domain(v6: bool) -> Domain {
    if v6 {
        Domain::IPV6
    } else {
        Domain::IPV4
    }
}

fn rx_socket(vrf: &str, v6: bool, port: u16) -> io::Result<AsyncFd<Socket>> {
    let s = Socket::new(domain(v6), Type::DGRAM, Some(Protocol::UDP))?;
    s.bind_device(Some(vrf.as_bytes()))?;
    let fd = s.as_raw_fd();
    let bind: SocketAddr = if v6 {
        s.set_only_v6(true)?;
        set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT, 1)?;
        (Ipv6Addr::UNSPECIFIED, port).into()
    } else {
        set_int(fd, libc::IPPROTO_IP, libc::IP_RECVTTL, 1)?;
        (Ipv4Addr::UNSPECIFIED, port).into()
    };
    s.bind(&bind.into())?;
    s.set_nonblocking(true)?;
    AsyncFd::new(s)
}

/// One datagram: its source and TTL/hop limit (when the kernel gave it).
struct Datagram {
    src: IpAddr,
    ttl: Option<u8>,
    len: usize,
}

fn recv_one(fd: RawFd, buf: &mut [u8]) -> io::Result<Datagram> {
    // SAFETY: every pointer handed to recvmsg points into locals that live to
    // the end of the function; the cmsg walk stays inside `msg_controllen`.
    unsafe {
        let mut name: socket2::SockAddrStorage = std::mem::zeroed();
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut ctrl = [0u64; 32];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = (&raw mut name).cast();
        msg.msg_namelen =
            libc::socklen_t::try_from(size_of::<socket2::SockAddrStorage>()).unwrap_or(128);
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl.as_mut_ptr().cast();
        msg.msg_controllen = size_of_val(&ctrl) as _;
        let n = libc::recvmsg(fd, &raw mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let src = SockAddr::new(name, msg.msg_namelen)
            .as_socket()
            .map(|s| s.ip())
            .ok_or_else(|| io::Error::other("datagram without an IP source"))?;
        let mut ttl = None;
        let mut c = libc::CMSG_FIRSTHDR(&raw const msg);
        while !c.is_null() {
            let h = &*c;
            let is_ttl = (h.cmsg_level == libc::IPPROTO_IP && h.cmsg_type == libc::IP_TTL)
                || (h.cmsg_level == libc::IPPROTO_IPV6 && h.cmsg_type == libc::IPV6_HOPLIMIT);
            if is_ttl {
                let v = std::ptr::read_unaligned(libc::CMSG_DATA(c).cast::<libc::c_int>());
                ttl = u8::try_from(v).ok();
            }
            c = libc::CMSG_NXTHDR(&raw const msg, c);
        }
        Ok(Datagram {
            src,
            ttl,
            len: usize::try_from(n).unwrap_or(0),
        })
    }
}

async fn rx_loop(sock: AsyncFd<Socket>, table: String, multihop: bool, demux: Demux) {
    let mut buf = [0u8; 128];
    loop {
        let mut guard = match sock.readable().await {
            Ok(g) => g,
            Err(e) => {
                warn!(table = %table, error = %e, "bfd receive socket failed");
                return;
            }
        };
        match guard.try_io(|s| recv_one(s.get_ref().as_raw_fd(), &mut buf)) {
            Ok(Ok(d)) => {
                // TTL check (RFC 5881 §5 / RFC 5883 §5) is per session, in `route`.
                let ok = demux.route(&table, d.src, multihop, d.ttl, &buf[..d.len.min(buf.len())]);
                debug!(peer = %d.src, ttl = ?d.ttl, delivered = ok, "bfd packet received");
            }
            Ok(Err(e)) if e.kind() != io::ErrorKind::Interrupted => {
                warn!(table = %table, error = %e, "bfd receive failed");
                return;
            }
            Ok(Err(_)) | Err(_) => {}
        }
    }
}

struct UdpTx(Socket);

impl Tx for UdpTx {
    fn send(&self, bytes: &[u8]) -> io::Result<()> {
        self.0.send(bytes).map(|_| ())
    }
}

/// Whether interface `name` is enslaved to the VRF device `vrf`.
fn in_vrf(name: &str, vrf: &str) -> bool {
    std::fs::read_link(format!("/sys/class/net/{name}/master"))
        .is_ok_and(|m| m.file_name().is_some_and(|f| f == vrf))
}

fn as_bits(a: IpAddr) -> u128 {
    match a {
        IpAddr::V4(a) => u128::from(u32::from(a)),
        IpAddr::V6(a) => u128::from(a),
    }
}

/// The local address on the connected network of `peer` and the interface
/// holding it: of `interface`, or else of any interface in `vrf`.
fn local_for(peer: IpAddr, vrf: &str, interface: Option<&str>) -> Option<(IpAddr, String)> {
    let sock_ip = |a: nix::sys::socket::SockaddrStorage| -> Option<IpAddr> {
        a.as_sockaddr_in()
            .map(|s| IpAddr::V4(s.ip()))
            .or_else(|| a.as_sockaddr_in6().map(|s| IpAddr::V6(s.ip())))
    };
    nix::ifaddrs::getifaddrs().ok()?.find_map(|ifa| {
        let ok = match interface {
            Some(i) => ifa.interface_name == i,
            None => in_vrf(&ifa.interface_name, vrf),
        };
        let (addr, mask) = (sock_ip(ifa.address?)?, sock_ip(ifa.netmask?)?);
        (ok && addr.is_ipv4() == peer.is_ipv4()
            && as_bits(addr) & as_bits(mask) == as_bits(peer) & as_bits(mask))
        .then_some((addr, ifa.interface_name))
    })
}

/// The source address the kernel would use towards `peer` in `vrf`: a
/// connected UDP socket's local address is a route lookup, nothing is sent.
/// RFC 5883 §4 wants the multihop local address fixed; a client that does
/// not name one gets this one. ponytail: not refreshed if the route's source
/// changes while the session lives.
fn kernel_source(peer: IpAddr, vrf: &str) -> Option<IpAddr> {
    let s = Socket::new(domain(peer.is_ipv6()), Type::DGRAM, Some(Protocol::UDP)).ok()?;
    s.bind_device(Some(vrf.as_bytes())).ok()?;
    s.connect(&SocketAddr::new(peer, BFD_MULTIHOP_PORT).into())
        .ok()?;
    let ip = s.local_addr().ok()?.as_socket()?.ip();
    (!ip.is_unspecified()).then_some(ip)
}

fn tx_socket(device: &str, vrf: &str, key: &SessionKey, dport: u16) -> io::Result<UdpTx> {
    let v6 = key.peer.is_ipv6();
    let s = Socket::new(domain(v6), Type::DGRAM, Some(Protocol::UDP))?;
    s.bind_device(Some(device.as_bytes()))?;
    // RFC 9764 §3: padded packets must not be fragmented, or they would test
    // nothing (EMSGSIZE on send instead). Harmless for bare packets.
    if v6 {
        s.set_unicast_hops_v6(TTL)?;
        set_int(s.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, 1)?;
        // An S-BFD initiator's reflections arrive here (`open_sbfd`) and are TTL-checked.
        set_int(
            s.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVHOPLIMIT,
            1,
        )?;
    } else {
        set_int(s.as_raw_fd(), libc::IPPROTO_IP, libc::IP_RECVTTL, 1)?;
        s.set_ttl_v4(TTL)?;
        set_int(
            s.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            libc::IP_PMTUDISC_DO,
        )?;
    }
    // A wildcard source left to the kernel goes out as 0.0.0.0 from a socket
    // bound to a VRF, so the source is picked here.
    let local = key
        .local
        .or_else(|| {
            if key.multihop {
                kernel_source(key.peer, vrf)
            } else {
                local_for(key.peer, vrf, key.interface.as_deref()).map(|(a, _)| a)
            }
        })
        .ok_or_else(|| io::Error::other("no local address towards the peer yet"))?;
    let mut bound = false;
    let mut err = io::Error::other("no free source port");
    for _ in 0..32 {
        let port = 49152 + u16::try_from(rand_u32() % 16384).unwrap_or(0);
        match s.bind(&SocketAddr::new(local, port).into()) {
            Ok(()) => {
                bound = true;
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => err = e,
            Err(e) => return Err(e),
        }
    }
    if !bound {
        return Err(err);
    }
    let scope = key.interface.as_deref().map_or(0, ifindex);
    let peer: SockAddr = match key.peer {
        IpAddr::V6(a) => SocketAddrV6::new(a, dport, 0, scope).into(),
        IpAddr::V4(a) => SocketAddr::new(a.into(), dport).into(),
    };
    s.connect(&peer)?;
    s.set_nonblocking(true)?;
    Ok(UdpTx(s))
}

/// Echo packets out through the neighbour: its MAC is kept fresh by a task.
struct L2Echo {
    sock: Arc<L2Unicast>,
    mac: Arc<Mutex<Option<[u8; 6]>>>,
    local: IpAddr,
    sport: u16,
}

impl EchoTx for L2Echo {
    fn send(&self, payload: &[u8]) -> io::Result<()> {
        let mac = (*self.mac.lock().unwrap())
            .ok_or_else(|| io::Error::other("no neighbour entry for the peer yet"))?;
        let ip = echo::build(self.local, self.sport, payload);
        self.sock.send(mac, &ip)
    }
}

/// Keeps `mac` equal to the kernel's entry for `peer` on `ifindex`; asks
/// again fast while there is none.
async fn neigh_loop(
    nl: rtnetlink::Handle,
    peer: IpAddr,
    ifindex: u32,
    mac: Arc<Mutex<Option<[u8; 6]>>>,
    kick: Option<UdpTx>,
) {
    loop {
        let found = neigh::lookup(&nl, peer, ifindex).await;
        let delay = match found {
            Ok(m) => {
                *mac.lock().unwrap() = m;
                if m.is_some() {
                    Duration::from_secs(1)
                } else {
                    // An unaffiliated session has no Control traffic to make
                    // the kernel resolve the peer: an empty datagram does.
                    if let Some(k) = &kick {
                        let _ = k.send(&[]);
                    }
                    Duration::from_millis(200)
                }
            }
            Err(e) => {
                debug!(peer = %peer, error = %e, "bfd neighbour lookup failed");
                Duration::from_secs(1)
            }
        };
        tokio::time::sleep(delay).await;
    }
}

async fn echo_rx_loop(
    sock: Arc<L2Unicast>,
    local: IpAddr,
    disc: u32,
    unaffiliated: bool,
    out: tokio::sync::mpsc::Sender<Looped>,
) {
    loop {
        match sock.recv().await {
            Ok(p) => {
                let looped = if unaffiliated {
                    // RFC 9747 §3: our own Control packet, TTL exactly 254.
                    echo::parse_udp(&p, local)
                        .filter(|(_, ttl)| *ttl == 254)
                        .and_then(|(pl, _)| packet::decode(pl).ok())
                        .filter(|c| c.my_discriminator == disc)
                        .map(|c| Looped::Control(c.state))
                } else {
                    echo::parse(&p, local)
                        .filter(|(d, _)| *d == disc)
                        .map(|(_, seq)| Looped::Seq(seq))
                };
                if let Some(l) = looped {
                    let _ = out.try_send(l);
                }
            }
            Err(e) => {
                warn!(error = %e, "bfd echo receive failed");
                return;
            }
        }
    }
}

/// One RFC 7130 micro-BFD session's transport: control packets leave the LAG
/// member in an IP/UDP frame to the dedicated multicast MAC; two receive
/// tasks (untagged, and 802.1p tag 0) feed the `Demux`. The member's own
/// socket is not affected by the bond enslaving it (it is bound to the
/// member's ifindex and the bond's `rx_handler` re-targets the skb after the
/// packet tap: `nos-e2e`'s `micro-bfd` phase proves it).
struct MicroTx {
    sock: Arc<L2Socket>,
    local: IpAddr,
    peer: IpAddr,
    sport: u16,
    rx: Vec<tokio::task::AbortHandle>,
}

impl Tx for MicroTx {
    fn send(&self, bytes: &[u8]) -> io::Result<()> {
        let ip = micro::build_frame(self.local, self.peer, self.sport, bytes)
            .ok_or_else(|| io::Error::other("local and peer address families differ"))?;
        self.sock.send(&ip)
    }
}

impl Drop for MicroTx {
    fn drop(&mut self) {
        for t in &self.rx {
            t.abort();
        }
    }
}

async fn micro_rx_loop(
    sock: Arc<L2Socket>,
    tagged: bool,
    member: String,
    local: IpAddr,
    demux: Demux,
) {
    loop {
        let payload = match sock.recv().await {
            Ok(p) => p,
            Err(e) => {
                warn!(member = %member, error = %e, "bfd micro receive failed");
                return;
            }
        };
        let ip = if tagged {
            micro::untag_priority(&payload)
        } else {
            Some(&payload[..])
        };
        // Addressed to the bond's address; TTL 255 is `parse_frame`'s.
        if let Some(f) = ip.and_then(micro::parse_frame).filter(|f| f.dst == local) {
            let ok = demux.route_micro(&member, f.src, f.pdu);
            debug!(member = %member, peer = %f.src, delivered = ok, "bfd micro packet received");
        }
    }
}

/// Reads reflections off an initiator's own socket (RFC 7881 §2: they come
/// back to its source port) and hands them to the session with their TTL.
async fn sbfd_rx_loop(
    sock: AsyncFd<Socket>,
    peer: IpAddr,
    out: tokio::sync::mpsc::Sender<sbfd::Reflection>,
) {
    let mut buf = [0u8; 128];
    loop {
        let mut guard = match sock.readable().await {
            Ok(g) => g,
            Err(e) => {
                warn!(peer = %peer, error = %e, "bfd sbfd receive socket failed");
                return;
            }
        };
        match guard.try_io(|s| recv_one(s.get_ref().as_raw_fd(), &mut buf)) {
            Ok(Ok(d)) => {
                if let Ok(p) = packet::decode(&buf[..d.len.min(buf.len())]) {
                    let _ = out.try_send((p, d.ttl));
                }
            }
            // ICMP errors on a connected socket (reflector unreachable) are not fatal.
            Ok(Err(e))
                if e.kind() == io::ErrorKind::Interrupted
                    || matches!(
                        e.raw_os_error(),
                        Some(libc::ECONNREFUSED | libc::EHOSTUNREACH | libc::ENETUNREACH)
                    ) => {}
            Ok(Err(e)) => {
                warn!(peer = %peer, error = %e, "bfd sbfd receive failed");
                return;
            }
            Err(_) => {}
        }
    }
}

/// One datagram for the reflector: who sent it, which of our addresses it
/// was sent to (`IP_PKTINFO`), and the raw sender address to answer to.
struct Probe {
    src: SocketAddr,
    dst: IpAddr,
    name: SockAddr,
    len: usize,
}

fn recv_probe(fd: RawFd, buf: &mut [u8]) -> io::Result<Probe> {
    // SAFETY: as `recv_one`: every pointer is to a local that outlives the
    // call, the cmsg walk stays inside `msg_controllen`.
    unsafe {
        let mut name: socket2::SockAddrStorage = std::mem::zeroed();
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut ctrl = [0u64; 32];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = (&raw mut name).cast();
        msg.msg_namelen =
            libc::socklen_t::try_from(size_of::<socket2::SockAddrStorage>()).unwrap_or(128);
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl.as_mut_ptr().cast();
        msg.msg_controllen = size_of_val(&ctrl) as _;
        let n = libc::recvmsg(fd, &raw mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let name = SockAddr::new(name, msg.msg_namelen);
        let src = name
            .as_socket()
            .ok_or_else(|| io::Error::other("datagram without an IP source"))?;
        let mut dst = if src.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        let mut c = libc::CMSG_FIRSTHDR(&raw const msg);
        while !c.is_null() {
            let h = &*c;
            if h.cmsg_level == libc::IPPROTO_IP && h.cmsg_type == libc::IP_PKTINFO {
                let i = std::ptr::read_unaligned(libc::CMSG_DATA(c).cast::<libc::in_pktinfo>());
                dst = IpAddr::V4(Ipv4Addr::from(u32::from_be(i.ipi_addr.s_addr)));
            } else if h.cmsg_level == libc::IPPROTO_IPV6 && h.cmsg_type == libc::IPV6_PKTINFO {
                let i = std::ptr::read_unaligned(libc::CMSG_DATA(c).cast::<libc::in6_pktinfo>());
                dst = IpAddr::V6(Ipv6Addr::from(i.ipi6_addr.s6_addr));
            }
            c = libc::CMSG_NXTHDR(&raw const msg, c);
        }
        Ok(Probe {
            src,
            dst,
            name,
            len: usize::try_from(n).unwrap_or(0),
        })
    }
}

/// Sends `data` to `to` with `from` as the IP source (`IP_PKTINFO`'s
/// `ipi_spec_dst`): RFC 7881 §6.1 answers from the address that was probed,
/// which a wildcard-bound socket would not otherwise pick.
fn send_from(fd: RawFd, to: &SockAddr, from: Option<IpAddr>, data: &[u8]) -> io::Result<()> {
    // SAFETY: the buffers outlive the call; the control message is built with
    // the `CMSG_*` macros inside a buffer larger than `CMSG_SPACE` of either.
    unsafe {
        let mut ctrl = [0u64; 8];
        let mut iov = libc::iovec {
            iov_base: data.as_ptr().cast_mut().cast(),
            iov_len: data.len(),
        };
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = to.as_ptr().cast_mut().cast();
        msg.msg_namelen = to.len();
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        if let Some(from) = from {
            msg.msg_control = ctrl.as_mut_ptr().cast();
            let (level, kind, size) = match from {
                IpAddr::V4(_) => (
                    libc::IPPROTO_IP,
                    libc::IP_PKTINFO,
                    size_of::<libc::in_pktinfo>(),
                ),
                IpAddr::V6(_) => (
                    libc::IPPROTO_IPV6,
                    libc::IPV6_PKTINFO,
                    size_of::<libc::in6_pktinfo>(),
                ),
            };
            let size = u32::try_from(size).unwrap_or(0);
            msg.msg_controllen = libc::CMSG_SPACE(size) as _;
            let h = libc::CMSG_FIRSTHDR(&raw const msg);
            (*h).cmsg_level = level;
            (*h).cmsg_type = kind;
            (*h).cmsg_len = libc::CMSG_LEN(size) as _;
            match from {
                IpAddr::V4(a) => {
                    let mut i: libc::in_pktinfo = std::mem::zeroed();
                    i.ipi_spec_dst.s_addr = u32::from(a).to_be();
                    std::ptr::write_unaligned(libc::CMSG_DATA(h).cast(), i);
                }
                IpAddr::V6(a) => {
                    let mut i: libc::in6_pktinfo = std::mem::zeroed();
                    i.ipi6_addr.s6_addr = a.octets();
                    std::ptr::write_unaligned(libc::CMSG_DATA(h).cast(), i);
                }
            }
        }
        if libc::sendmsg(fd, &raw const msg, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Whether `a` may be the source of a reply: not loopback (RFC 7881 §6.1 lets
/// the kernel pick then), not a broadcast/multicast/unspecified destination.
fn reply_source(a: IpAddr) -> Option<IpAddr> {
    let ok = !(a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || matches!(a, IpAddr::V4(v) if v.is_broadcast()));
    ok.then_some(a)
}

fn reflector_socket(vrf: &str, v6: bool) -> io::Result<AsyncFd<Socket>> {
    let s = Socket::new(domain(v6), Type::DGRAM, Some(Protocol::UDP))?;
    s.bind_device(Some(vrf.as_bytes()))?;
    let fd = s.as_raw_fd();
    let bind: SocketAddr = if v6 {
        s.set_only_v6(true)?;
        set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1)?;
        s.set_unicast_hops_v6(TTL)?;
        (Ipv6Addr::UNSPECIFIED, sbfd::PORT).into()
    } else {
        set_int(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, 1)?;
        s.set_ttl_v4(TTL)?;
        (Ipv4Addr::UNSPECIFIED, sbfd::PORT).into()
    };
    s.bind(&bind.into())?;
    s.set_nonblocking(true)?;
    AsyncFd::new(s)
}

async fn reflect_loop(sock: AsyncFd<Socket>, vrf: String, reflector: Arc<Reflector>) {
    let mut buf = [0u8; 128];
    loop {
        let mut guard = match sock.readable().await {
            Ok(g) => g,
            Err(e) => {
                warn!(vrf = %vrf, error = %e, "bfd reflector socket failed");
                return;
            }
        };
        match guard.try_io(|s| recv_probe(s.get_ref().as_raw_fd(), &mut buf)) {
            Ok(Ok(p)) => {
                let data = &buf[..p.len.min(buf.len())];
                if let Some(reply) = reflector.handle(std::time::Instant::now(), p.src, p.dst, data)
                {
                    let fd = sock.get_ref().as_raw_fd();
                    if let Err(e) = send_from(fd, &p.name, reply_source(p.dst), &reply) {
                        debug!(peer = %p.src, error = %e, "bfd reflector reply failed");
                    }
                }
            }
            Ok(Err(e)) if e.kind() != io::ErrorKind::Interrupted => {
                warn!(vrf = %vrf, error = %e, "bfd reflector receive failed");
                return;
            }
            Ok(Err(_)) | Err(_) => {}
        }
    }
}

type ReflectorTasks = HashMap<(String, bool), (u32, JoinHandle<()>)>;

/// The reflector's UDP 7784 sockets: one per (VRF, family) while a
/// discriminator is configured, restarted when the VRF device is recreated.
pub struct ReflectorNet {
    watchdog_socket: PathBuf,
    reflector: Arc<Reflector>,
    /// (table, v6) -> (VRF ifindex it was opened for, its task).
    tasks: Mutex<ReflectorTasks>,
}

impl ReflectorNet {
    pub fn new(watchdog_socket: PathBuf, reflector: Arc<Reflector>) -> Self {
        ReflectorNet {
            watchdog_socket,
            reflector,
            tasks: Mutex::default(),
        }
    }

    /// Follows the running config: the policy, then the sockets of every table.
    pub async fn configure(&self, cfg: &nos_proto::Config) {
        self.reflector.set_policy(crate::reflector::policy_of(cfg));
        let tables: Vec<String> = cfg.routing_tables.iter().map(|t| t.name.clone()).collect();
        self.apply(&tables).await;
    }

    /// Makes the sockets match the policy and the routing `tables`; idempotent.
    pub async fn apply(&self, tables: &[String]) {
        if !self.reflector.enabled() {
            for (_, (_, t)) in self.tasks.lock().unwrap().drain() {
                t.abort();
            }
            return;
        }
        self.tasks.lock().unwrap().retain(|(t, _), (_, task)| {
            let keep = tables.contains(t);
            if !keep {
                task.abort();
            }
            keep
        });
        for table in tables {
            let Some(vrf) = vrf_name(&self.watchdog_socket, table).await else {
                continue;
            };
            let idx = ifindex(&vrf);
            for v6 in [false, true] {
                let mut tasks = self.tasks.lock().unwrap();
                let key = (table.clone(), v6);
                if let Some((have, task)) = tasks.get(&key) {
                    if *have == idx && !task.is_finished() {
                        continue;
                    }
                    task.abort();
                }
                match reflector_socket(&vrf, v6) {
                    Ok(sock) => {
                        tasks.insert(
                            key,
                            (
                                idx,
                                tokio::spawn(reflect_loop(
                                    sock,
                                    vrf.clone(),
                                    self.reflector.clone(),
                                )),
                            ),
                        );
                    }
                    Err(e) => debug!(vrf = %vrf, v6, error = %e, "bfd reflector socket not opened"),
                }
            }
        }
    }
}

type RxTasks = HashMap<(String, bool, bool), (u32, JoinHandle<()>)>;

/// The real transport. Owns the receive sockets and feeds the `Demux`.
pub struct UdpNet {
    watchdog_socket: PathBuf,
    demux: Demux,
    /// (table, v6, multihop) -> (VRF ifindex it was opened for, its receive task).
    rx: Mutex<RxTasks>,
    /// The shared rtnetlink handle for neighbour lookups, made on first use.
    nl: Mutex<Option<rtnetlink::Handle>>,
}

impl UdpNet {
    pub fn new(watchdog_socket: PathBuf, demux: Demux) -> Arc<Self> {
        Arc::new(UdpNet {
            watchdog_socket,
            demux,
            rx: Mutex::default(),
            nl: Mutex::default(),
        })
    }

    fn netlink(&self) -> io::Result<rtnetlink::Handle> {
        let mut nl = self.nl.lock().unwrap();
        if let Some(h) = nl.as_ref() {
            return Ok(h.clone());
        }
        let (conn, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(conn);
        *nl = Some(handle.clone());
        Ok(handle)
    }

    async fn try_open_echo(
        &self,
        key: &SessionKey,
        disc: u32,
        unaffiliated: bool,
    ) -> io::Result<EchoPath> {
        let vrf = vrf_name(&self.watchdog_socket, &key.table)
            .await
            .ok_or_else(|| io::Error::other("the table has no VRF yet"))?;
        let (addr, iface) = local_for(key.peer, &vrf, key.interface.as_deref())
            .ok_or_else(|| io::Error::other("no interface towards the peer"))?;
        let local = key.local.unwrap_or(addr);
        let ethertype = if local.is_ipv4() { 0x0800 } else { 0x86dd };
        let sock = Arc::new(L2Unicast::open(&iface, ethertype, echo::ECHO_PORT)?);
        let ifindex = u32::try_from(nos_l2_socket::if_index(&iface)?).unwrap_or(0);
        let mac = Arc::new(Mutex::new(None));
        let (seq_tx, seq_rx) = tokio::sync::mpsc::channel(64);
        let rx = tokio::spawn(echo_rx_loop(
            sock.clone(),
            local,
            disc,
            unaffiliated,
            seq_tx,
        ));
        let kick = if unaffiliated {
            let device = key.interface.as_deref().unwrap_or(&vrf);
            Some(tx_socket(device, &vrf, key, echo::ECHO_PORT)?)
        } else {
            None
        };
        let neigh = tokio::spawn(neigh_loop(
            self.netlink()?,
            key.peer,
            ifindex,
            mac.clone(),
            kick,
        ));
        let sport = 49152 + u16::try_from(rand_u32() % 16384).unwrap_or(0);
        Ok(EchoPath {
            tx: Arc::new(L2Echo {
                sock,
                mac,
                local,
                sport,
            }),
            rx: seq_rx,
            tasks: vec![rx.abort_handle(), neigh.abort_handle()],
        })
    }

    fn open_micro(&self, key: &SessionKey) -> io::Result<Arc<dyn Tx>> {
        let member = key
            .interface
            .clone()
            .ok_or_else(|| io::Error::other("micro-BFD session without a member"))?;
        let local = key
            .local
            .ok_or_else(|| io::Error::other("micro-BFD session without a source address"))?;
        let ethertype = if local.is_ipv4() { 0x0800 } else { 0x86dd };
        let ip = Arc::new(
            L2Socket::open(&member, ethertype, micro::GROUP, RX_FRAME)?
                .accept_own_unicast()
                .udp_dst_port(micro::PORT)?,
        );
        // ponytail: no kernel filter on the tagged socket: it wakes for every
        // VLAN frame of the member (RFC 7130 §2.3 wants tag 0 received).
        let tag =
            Arc::new(L2Socket::open(&member, 0x8100, micro::GROUP, RX_FRAME)?.accept_own_unicast());
        let rx = [(ip.clone(), false), (tag, true)]
            .into_iter()
            .map(|(sock, tagged)| {
                tokio::spawn(micro_rx_loop(
                    sock,
                    tagged,
                    member.clone(),
                    local,
                    self.demux.clone(),
                ))
                .abort_handle()
            })
            .collect();
        Ok(Arc::new(MicroTx {
            sock: ip,
            local,
            peer: key.peer,
            sport: 49152 + u16::try_from(rand_u32() % 16384).unwrap_or(0),
            rx,
        }))
    }

    /// Starts the table's receive socket, or restarts it when the VRF device
    /// behind it was recreated (a `nos-ribd` restart): the old socket is
    /// bound to the deleted device's index.
    fn ensure_rx(&self, table: &str, vrf: &str, v6: bool, multihop: bool) -> io::Result<()> {
        let idx = ifindex(vrf);
        let mut rx = self.rx.lock().unwrap();
        if let Some((have, task)) = rx.get(&(table.to_string(), v6, multihop)) {
            if *have == idx && !task.is_finished() {
                return Ok(());
            }
            task.abort();
        }
        let sock = rx_socket(vrf, v6, port(multihop))?;
        let task = tokio::spawn(rx_loop(
            sock,
            table.to_string(),
            multihop,
            self.demux.clone(),
        ));
        rx.insert((table.to_string(), v6, multihop), (idx, task));
        Ok(())
    }
}

#[async_trait]
impl Net for UdpNet {
    async fn open(&self, key: &SessionKey) -> io::Result<Arc<dyn Tx>> {
        if key.aggregate.is_some() {
            return self.open_micro(key);
        }
        let vrf = vrf_name(&self.watchdog_socket, &key.table)
            .await
            .ok_or_else(|| io::Error::other("the table has no VRF yet"))?;
        self.ensure_rx(&key.table, &vrf, key.peer.is_ipv6(), key.multihop)?;
        let device = key
            .interface
            .as_deref()
            .filter(|_| !key.multihop)
            .unwrap_or(&vrf);
        Ok(Arc::new(tx_socket(device, &vrf, key, port(key.multihop))?))
    }

    async fn listen(&self, table: &str, v6: bool) -> io::Result<()> {
        let vrf = vrf_name(&self.watchdog_socket, table)
            .await
            .ok_or_else(|| io::Error::other("the table has no VRF yet"))?;
        self.ensure_rx(table, &vrf, v6, false)
    }

    async fn open_sbfd(&self, key: &SessionKey) -> io::Result<SbfdPath> {
        let vrf = vrf_name(&self.watchdog_socket, &key.table)
            .await
            .ok_or_else(|| io::Error::other("the table has no VRF yet"))?;
        let device = key
            .interface
            .as_deref()
            .filter(|_| !key.multihop)
            .unwrap_or(&vrf);
        // Its own source port (never 7784, unique per session: `bind` fails
        // on a port in use) so the reflections find their way back.
        let tx = tx_socket(device, &vrf, key, sbfd::PORT)?;
        let rx = AsyncFd::new(tx.0.try_clone()?)?;
        let (out, rx_chan) = tokio::sync::mpsc::channel(64);
        let task = tokio::spawn(sbfd_rx_loop(rx, key.peer, out));
        Ok(SbfdPath {
            tx: Arc::new(tx),
            rx: rx_chan,
            task: task.abort_handle(),
        })
    }

    async fn open_echo(&self, key: &SessionKey, disc: u32, unaffiliated: bool) -> Option<EchoPath> {
        // ponytail: tried once, at session start. A session whose interface
        // has no address yet never runs Echo until it is re-registered.
        match self.try_open_echo(key, disc, unaffiliated).await {
            Ok(p) => Some(p),
            Err(e) => {
                warn!(peer = %key.peer, table = %key.table, error = %e, "bfd echo unavailable");
                None
            }
        }
    }
}
