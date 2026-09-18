//! Raw protocol-89 (OSPF) socket, VRF-scoped via `SO_BINDTODEVICE` — the
//! same mechanism `bgp/src/tcp.rs` uses for TCP, applied here to a raw IP
//! socket since OSPF has no transport layer of its own. Joins the
//! `AllSPFRouters` (224.0.0.5) multicast group on the link's own local
//! address, since RFC 2328 Hello is always multicast, point-to-point links
//! included (see `ospf/CLAUDE.md`).

use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;

pub const OSPF_IP_PROTO: i32 = 89;
pub const ALL_SPF_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 5);

/// Largest Hello packet this crate ever sends/receives — well above any
/// realistic point-to-point Hello size (a handful of neighbor entries at
/// most), generous enough that a legitimately larger packet from a peer is
/// still fully captured rather than silently truncated.
const RECV_BUF_LEN: usize = 4096;

/// A raw protocol-89 socket bound into one VRF and joined to 224.0.0.5 on
/// one local interface address — one per point-to-point OSPF link.
pub struct OspfSocket {
    inner: AsyncFd<Socket>,
}

impl OspfSocket {
    /// Opens the socket, scopes it into `vrf`, and joins 224.0.0.5 on the
    /// interface owning `local_addr`.
    pub fn open(vrf: &str, local_addr: Ipv4Addr) -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(OSPF_IP_PROTO)))?;
        socket.bind_device(Some(vrf.as_bytes()))?;
        socket.join_multicast_v4(&ALL_SPF_ROUTERS, &local_addr)?;
        // A multicast destination has no unicast route in the VRF's FIB, so
        // an outbound send would otherwise fail with `ENETUNREACH` despite
        // `bind_device` — `IP_MULTICAST_IF` picks the egress interface for
        // multicast traffic independently of any route lookup.
        socket.set_multicast_if_v4(&local_addr)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: AsyncFd::new(socket)?,
        })
    }

    /// Sends `payload` (an already-encoded OSPF packet, see `crate::packet`)
    /// to 224.0.0.5. The kernel fills in the IP header (no `IP_HDRINCL` set)
    /// — this NOS doesn't need control over IP-layer fields for a lab/real
    /// point-to-point Hello exchange.
    pub fn send_hello(&self, payload: &[u8]) -> io::Result<()> {
        let dest = SockAddr::from(SocketAddrV4::new(ALL_SPF_ROUTERS, 0));
        self.inner.get_ref().send_to(payload, &dest)?;
        Ok(())
    }

    /// Waits for and returns one received OSPF packet's payload, with the
    /// IP header already stripped. The sender's address isn't reported —
    /// neighbor identity comes from the Hello body's own router-id field
    /// (see `crate::packet::HelloPacket`), not the IP source.
    ///
    /// Raw IPv4 sockets on Linux always deliver the IP header on receive,
    /// even without `IP_HDRINCL` — the IHL nibble in the first header byte
    /// gives the header's real length (it may carry options, so it isn't
    /// always the minimum 20 bytes).
    pub async fn recv_hello(&self) -> io::Result<Vec<u8>> {
        loop {
            let mut guard = self.inner.readable().await?;
            let mut buf = [0u8; RECV_BUF_LEN];
            match guard.try_io(|inner| inner.get_ref().read(&mut buf)) {
                Ok(Ok(n)) => {
                    if n == 0 {
                        continue;
                    }
                    let ihl = usize::from(buf[0] & 0x0f) * 4;
                    if ihl == 0 || n < ihl {
                        continue;
                    }
                    return Ok(buf[ihl..n].to_vec());
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {}
            }
        }
    }
}

impl AsRawFd for OspfSocket {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.inner.get_ref().as_raw_fd()
    }
}
