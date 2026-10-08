//! The UDP side of RFC 5881 single-hop BFD (excluded from coverage: it only
//! runs against a real kernel, `nos-e2e`'s `bfd` phase is its test).
//!
//! - One receive socket per (table, address family): UDP 3784 wildcard,
//!   `SO_BINDTODEVICE` to the table's VRF, `IP_RECVTTL`/`IPV6_RECVHOPLIMIT` so
//!   every datagram's TTL is checked (RFC 5881 §5: must be exactly 255).
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

use async_trait::async_trait;
use nos_proto::SessionKey;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::manager::{Demux, Net};
use crate::session::{rand_u32, Tx};
use crate::watchdog_client;

pub const BFD_PORT: u16 = 3784;
const TTL: u32 = 255;

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

fn rx_socket(vrf: &str, v6: bool) -> io::Result<AsyncFd<Socket>> {
    let s = Socket::new(domain(v6), Type::DGRAM, Some(Protocol::UDP))?;
    s.bind_device(Some(vrf.as_bytes()))?;
    let fd = s.as_raw_fd();
    let bind: SocketAddr = if v6 {
        s.set_only_v6(true)?;
        set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT, 1)?;
        (Ipv6Addr::UNSPECIFIED, BFD_PORT).into()
    } else {
        set_int(fd, libc::IPPROTO_IP, libc::IP_RECVTTL, 1)?;
        (Ipv4Addr::UNSPECIFIED, BFD_PORT).into()
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
        let mut name: libc::sockaddr_storage = std::mem::zeroed();
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut ctrl = [0u64; 32];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = (&raw mut name).cast();
        msg.msg_namelen =
            libc::socklen_t::try_from(size_of::<libc::sockaddr_storage>()).unwrap_or(128);
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

async fn rx_loop(sock: AsyncFd<Socket>, table: String, demux: Demux) {
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
                // RFC 5881 §5: single-hop packets must arrive with TTL 255.
                if d.ttl == Some(255) {
                    let ok = demux.route(&table, d.src, &buf[..d.len.min(buf.len())]);
                    debug!(peer = %d.src, delivered = ok, "bfd packet received");
                } else {
                    debug!(peer = %d.src, ttl = ?d.ttl, "bfd packet discarded: ttl is not 255");
                }
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

/// The local address on the connected network of `peer`: of `interface`, or
/// else of any interface in `vrf`.
fn local_for(peer: IpAddr, vrf: &str, interface: Option<&str>) -> Option<IpAddr> {
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
        .then_some(addr)
    })
}

fn tx_socket(device: &str, vrf: &str, key: &SessionKey) -> io::Result<UdpTx> {
    let v6 = key.peer.is_ipv6();
    let s = Socket::new(domain(v6), Type::DGRAM, Some(Protocol::UDP))?;
    s.bind_device(Some(device.as_bytes()))?;
    if v6 {
        s.set_unicast_hops_v6(TTL)?;
    } else {
        s.set_ttl(TTL)?;
    }
    // A wildcard source left to the kernel goes out as 0.0.0.0 from a socket
    // bound to a VRF, so the source is picked here.
    let local = key
        .local
        .or_else(|| local_for(key.peer, vrf, key.interface.as_deref()))
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
        IpAddr::V6(a) => SocketAddrV6::new(a, BFD_PORT, 0, scope).into(),
        IpAddr::V4(a) => SocketAddr::new(a.into(), BFD_PORT).into(),
    };
    s.connect(&peer)?;
    s.set_nonblocking(true)?;
    Ok(UdpTx(s))
}

type RxTasks = HashMap<(String, bool), (u32, JoinHandle<()>)>;

/// The real transport. Owns the receive sockets and feeds the `Demux`.
pub struct UdpNet {
    watchdog_socket: PathBuf,
    demux: Demux,
    /// (table, v6) -> (VRF ifindex it was opened for, its receive task).
    rx: Mutex<RxTasks>,
}

impl UdpNet {
    pub fn new(watchdog_socket: PathBuf, demux: Demux) -> Arc<Self> {
        Arc::new(UdpNet {
            watchdog_socket,
            demux,
            rx: Mutex::default(),
        })
    }

    /// Starts the table's receive socket, or restarts it when the VRF device
    /// behind it was recreated (a `nos-ribd` restart): the old socket is
    /// bound to the deleted device's index.
    fn ensure_rx(&self, table: &str, vrf: &str, v6: bool) -> io::Result<()> {
        let idx = ifindex(vrf);
        let mut rx = self.rx.lock().unwrap();
        if let Some((have, task)) = rx.get(&(table.to_string(), v6)) {
            if *have == idx && !task.is_finished() {
                return Ok(());
            }
            task.abort();
        }
        let sock = rx_socket(vrf, v6)?;
        let task = tokio::spawn(rx_loop(sock, table.to_string(), self.demux.clone()));
        rx.insert((table.to_string(), v6), (idx, task));
        Ok(())
    }
}

#[async_trait]
impl Net for UdpNet {
    async fn open(&self, key: &SessionKey) -> io::Result<Arc<dyn Tx>> {
        let vrf = watchdog_client::vrf_name(&self.watchdog_socket, &key.table)
            .await
            .ok_or_else(|| io::Error::other("the table has no VRF yet"))?;
        self.ensure_rx(&key.table, &vrf, key.peer.is_ipv6())?;
        let device = key.interface.as_deref().unwrap_or(&vrf);
        Ok(Arc::new(tx_socket(device, &vrf, key)?))
    }
}
