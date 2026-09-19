//! Raw `AF_PACKET`/`SOCK_RAW` socket bound to **one physical interface**,
//! carrying one ethertype to/from one link-local multicast group — the shared
//! transport of `nos-lacp` (slow protocols) and `nos-lldp`. A leaf crate with
//! no NOS dependencies, like `nos-tcp-auth`, so both daemons can use it
//! without depending on each other.
//!
//! # Why the specific interface
//! A raw socket has no port/connection concept to demultiplex by — binding
//! wider than the one link a protocol runs on would receive every other
//! link's frames too.
//!
//! # `unsafe` scope
//! `AF_PACKET` needs a `sockaddr_ll` (interface index, not a name) for both
//! `bind` and multicast-group membership, which `socket2` doesn't wrap — this
//! crate is where that raw `libc` socket work lives.

use std::io::{self, Read};
use std::os::fd::AsRawFd;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;

const ETH_HEADER_LEN: usize = 14;

// Field names deliberately mirror `linux/if_packet.h`'s own `sockaddr_ll`/
// `packet_mreq` exactly, for auditability against the kernel ABI.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(clippy::struct_field_names)]
struct SockaddrLl {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

/// `PACKET_ADD_MEMBERSHIP`'s payload (`linux/if_packet.h`'s `packet_mreq`) —
/// used to join the multicast group, since an ordinary NIC otherwise only
/// passes up unicast-to-self/broadcast frames, not an arbitrary multicast
/// destination.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(clippy::struct_field_names)]
struct PacketMreq {
    mr_ifindex: i32,
    mr_type: u16,
    mr_alen: u16,
    mr_address: [u8; 8],
}

const SOL_PACKET: i32 = 263;
const PACKET_ADD_MEMBERSHIP: i32 = 1;
const PACKET_MR_MULTICAST: u16 = 0;

const LINK_DOWN_RETRY: std::time::Duration = std::time::Duration::from_millis(500);

/// A raw L2 socket for one ethertype and one multicast group on one interface.
pub struct L2Socket {
    inner: AsyncFd<Socket>,
    own_hw_addr: [u8; 6],
    ifindex: i32,
    ethertype: u16,
    group: [u8; 6],
    recv_buf_len: usize,
}

impl L2Socket {
    /// Opens the socket, restricts it to `interface`'s `ethertype` traffic, and
    /// joins `group` on it. `recv_buf_len` is the largest *frame* (header
    /// included) worth receiving; a longer one is truncated by the kernel.
    pub fn open(
        interface: &str,
        ethertype: u16,
        group: [u8; 6],
        recv_buf_len: usize,
    ) -> io::Result<Self> {
        let own_hw_addr = read_hw_addr(interface)?;
        let ifindex = if_index(interface)?;

        let protocol = i32::from(ethertype.to_be());
        let socket = Socket::new(
            Domain::from(libc::AF_PACKET),
            Type::RAW,
            Some(Protocol::from(protocol)),
        )?;

        // SAFETY: `addr` is a plain, fully-initialized `sockaddr_ll`; `bind`
        // is called with its own correct size, matching the kernel's
        // expectation for this socket family.
        #[allow(unsafe_code)]
        {
            let addr = SockaddrLl {
                sll_family: u16::try_from(libc::AF_PACKET).expect("AF_PACKET always fits u16"),
                sll_protocol: ethertype.to_be(),
                sll_ifindex: ifindex,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0; 8],
            };
            let ret = unsafe {
                libc::bind(
                    socket.as_raw_fd(),
                    std::ptr::from_ref(&addr).cast::<libc::sockaddr>(),
                    libc::socklen_t::try_from(std::mem::size_of::<SockaddrLl>())
                        .expect("fixed, small struct size"),
                )
            };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        join_multicast(&socket, ifindex, group)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: AsyncFd::new(socket)?,
            own_hw_addr,
            ifindex,
            ethertype,
            group,
            recv_buf_len,
        })
    }

    /// This port's own real MAC address — this socket's Ethernet source.
    pub fn own_hw_addr(&self) -> [u8; 6] {
        self.own_hw_addr
    }

    /// This port's real kernel interface index.
    pub fn ifindex(&self) -> i32 {
        self.ifindex
    }

    /// Sends an already-encoded PDU, wrapping it in an Ethernet header
    /// addressed to this socket's multicast group.
    pub fn send(&self, pdu: &[u8]) -> io::Result<()> {
        let mut frame = Vec::with_capacity(ETH_HEADER_LEN + pdu.len());
        frame.extend_from_slice(&self.group);
        frame.extend_from_slice(&self.own_hw_addr);
        frame.extend_from_slice(&self.ethertype.to_be_bytes());
        frame.extend_from_slice(pdu);
        self.inner.get_ref().send(&frame)?;
        Ok(())
    }

    /// Waits for and returns one received PDU's payload, Ethernet header
    /// already stripped. Frames that are runts, sent by this port itself, or
    /// not addressed to this socket's group are skipped.
    pub async fn recv(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; self.recv_buf_len];
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| inner.get_ref().read(&mut buf)) {
                Ok(Ok(n)) => {
                    if let Some(payload) =
                        payload_of_foreign_frame(&buf[..n], self.own_hw_addr, self.group)
                    {
                        return Ok(payload.to_vec());
                    }
                }
                // A link that is administratively down (or just coming up)
                // surfaces as `ENETDOWN` on read — a normal, recoverable
                // state, so wait and retry rather than end the caller's task.
                Ok(Err(e)) if is_link_down(&e) => {
                    tokio::time::sleep(LINK_DOWN_RETRY).await;
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {}
            }
        }
    }
}

impl AsRawFd for L2Socket {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.inner.get_ref().as_raw_fd()
    }
}

/// `ENETDOWN` — see `recv`. Also what `send` returns while the link is down.
pub fn is_link_down(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ENETDOWN)
}

/// The payload of a received frame, or `None` for a runt, a frame not
/// addressed to `group`, or one this port sent itself. An `AF_PACKET` socket
/// also sees its own *outgoing* frames; treating those as the peer's makes a
/// port "talk to itself" and, where each receive triggers a reply, loop at
/// line rate.
fn payload_of_foreign_frame(frame: &[u8], own: [u8; 6], group: [u8; 6]) -> Option<&[u8]> {
    if frame.len() < ETH_HEADER_LEN || frame[..6] != group || frame[6..12] == own {
        return None;
    }
    Some(&frame[ETH_HEADER_LEN..])
}

fn if_index(interface: &str) -> io::Result<i32> {
    let name = std::ffi::CString::new(interface)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name has a NUL"))?;
    // SAFETY: `name` is a valid, NUL-terminated C string for this call.
    #[allow(unsafe_code)]
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(i32::try_from(index).expect("kernel ifindex always fits i32"))
}

/// Joins `group` via `PACKET_ADD_MEMBERSHIP` — without this most NIC drivers
/// never pass an arbitrary multicast destination up to userspace.
fn join_multicast(socket: &Socket, ifindex: i32, group: [u8; 6]) -> io::Result<()> {
    let mut addr = [0u8; 8];
    addr[..6].copy_from_slice(&group);
    let mreq = PacketMreq {
        mr_ifindex: ifindex,
        mr_type: PACKET_MR_MULTICAST,
        mr_alen: 6,
        mr_address: addr,
    };
    let len = libc::socklen_t::try_from(std::mem::size_of::<PacketMreq>())
        .expect("fixed, small struct size");
    // SAFETY: `mreq` is a plain, fully-initialized value of the size
    // `setsockopt` is told, matching the kernel's `packet_mreq` layout.
    #[allow(unsafe_code)]
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            SOL_PACKET,
            PACKET_ADD_MEMBERSHIP,
            std::ptr::from_ref(&mreq).cast::<libc::c_void>(),
            len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Reads `interface`'s own MAC address from sysfs — no netlink/ioctl needed.
fn read_hw_addr(interface: &str) -> io::Result<[u8; 6]> {
    let path = format!("/sys/class/net/{interface}/address");
    let text = std::fs::read_to_string(path)?;
    parse_hw_addr(text.trim()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unrecognized MAC address format for {interface}"),
        )
    })
}

fn parse_hw_addr(text: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = text.split(':');
    for byte in &mut out {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUP: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E];

    #[test]
    fn enetdown_is_recognized_as_link_down() {
        assert!(is_link_down(&io::Error::from_raw_os_error(libc::ENETDOWN)));
        assert!(!is_link_down(&io::Error::from_raw_os_error(libc::ENODEV)));
    }

    #[test]
    fn own_frames_runts_and_foreign_groups_are_dropped() {
        let own = [2, 0, 0, 0, 0, 1];
        let other = [2, 0, 0, 0, 0, 2];
        let frame = |dst: [u8; 6], src: [u8; 6]| {
            let mut f = dst.to_vec();
            f.extend_from_slice(&src);
            f.extend_from_slice(&0x88CCu16.to_be_bytes());
            f.extend_from_slice(b"pdu");
            f
        };
        assert_eq!(
            payload_of_foreign_frame(&frame(GROUP, other), own, GROUP),
            Some(&b"pdu"[..])
        );
        assert_eq!(
            payload_of_foreign_frame(&frame(GROUP, own), own, GROUP),
            None
        );
        // Addressed to a different group than this socket joined.
        assert_eq!(
            payload_of_foreign_frame(&frame([0x01, 0x80, 0xC2, 0, 0, 0], other), own, GROUP),
            None
        );
        assert_eq!(payload_of_foreign_frame(&[0; 5], own, GROUP), None);
    }

    #[test]
    fn parses_colon_separated_mac() {
        assert_eq!(
            parse_hw_addr("02:00:00:00:00:01"),
            Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
        );
        assert_eq!(parse_hw_addr("not-a-mac"), None);
        assert_eq!(parse_hw_addr("02:00:00:00:00"), None);
        assert_eq!(parse_hw_addr("02:00:00:00:00:01:02"), None);
    }
}
