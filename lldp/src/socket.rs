//! Raw `AF_PACKET`/`SOCK_RAW` socket bound to **one physical interface**,
//! carrying real LLDPDUs (ethertype `0x88CC`) to/from the "nearest bridge"
//! multicast address `01:80:C2:00:00:0E`.
//!
//! Derived from `nos-lacp`'s `socket.rs` (same shape, different ethertype and
//! multicast group). It is copied rather than shared because the workspace's
//! star dependency graph forbids one daemon crate depending on another; a
//! shared leaf crate is the upgrade path if a third raw-L2 daemon appears.
//!
//! # `unsafe` scope
//! `AF_PACKET` needs a `sockaddr_ll` (interface index, not a name) for both
//! `bind` and multicast-group membership, which `socket2` doesn't wrap — this
//! module is the one place in this crate that touches raw `libc` socket calls.

use std::io::{self, Read};
use std::os::fd::AsRawFd;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;

/// `ETH_P_LLDP` (IEEE 802.1AB).
const ETH_P_LLDP: u16 = 0x88CC;

/// The "nearest bridge" group address every LLDPDU is sent to. It is in the
/// link-local reserved range, so bridges never forward it.
pub const LLDP_MULTICAST: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E];

const ETH_HEADER_LEN: usize = 14;

/// Comfortably above any realistic LLDPDU; a longer frame is truncated by the
/// kernel and simply fails to decode.
const RECV_BUF_LEN: usize = 2048;

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

/// A raw LLDP socket bound to one physical interface.
pub struct LldpSocket {
    inner: AsyncFd<Socket>,
    own_hw_addr: [u8; 6],
}

impl LldpSocket {
    /// Opens the socket, restricts it to `interface`'s LLDP traffic, and joins
    /// the LLDP multicast group on it.
    pub fn open(interface: &str) -> io::Result<Self> {
        let own_hw_addr = read_hw_addr(interface)?;
        let ifindex = if_index(interface)?;

        let protocol = i32::from(ETH_P_LLDP.to_be());
        let socket = Socket::new(
            Domain::from(libc::AF_PACKET),
            Type::RAW,
            Some(Protocol::from(protocol)),
        )?;

        // SAFETY: `addr` is a plain, fully-initialized `sockaddr_ll`; `bind`
        // is called with its own correct size.
        #[allow(unsafe_code)]
        {
            let addr = SockaddrLl {
                sll_family: u16::try_from(libc::AF_PACKET).expect("AF_PACKET always fits u16"),
                sll_protocol: ETH_P_LLDP.to_be(),
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

        join_lldp_multicast(&socket, ifindex)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: AsyncFd::new(socket)?,
            own_hw_addr,
        })
    }

    /// Sends an already-encoded LLDPDU (`packet::encode`'s output), wrapping it
    /// in an Ethernet header addressed to the LLDP multicast group.
    pub fn send(&self, lldpdu: &[u8]) -> io::Result<()> {
        let mut frame = Vec::with_capacity(ETH_HEADER_LEN + lldpdu.len());
        frame.extend_from_slice(&LLDP_MULTICAST);
        frame.extend_from_slice(&self.own_hw_addr);
        frame.extend_from_slice(&ETH_P_LLDP.to_be_bytes());
        frame.extend_from_slice(lldpdu);
        self.inner.get_ref().send(&frame)?;
        Ok(())
    }

    /// Waits for and returns one received LLDPDU's payload, Ethernet header
    /// already stripped.
    pub async fn recv(&self) -> io::Result<Vec<u8>> {
        loop {
            let mut guard = self.inner.readable().await?;
            let mut buf = [0u8; RECV_BUF_LEN];
            match guard.try_io(|inner| inner.get_ref().read(&mut buf)) {
                Ok(Ok(n)) => {
                    if let Some(payload) = payload_of_foreign_frame(&buf[..n], self.own_hw_addr) {
                        return Ok(payload.to_vec());
                    }
                }
                // A link that is administratively down (or just coming up)
                // surfaces as `ENETDOWN` on read — a normal, recoverable
                // state, so wait and retry rather than end the link task.
                Ok(Err(e)) if is_link_down(&e) => {
                    tokio::time::sleep(LINK_DOWN_RETRY).await;
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {}
            }
        }
    }
}

const LINK_DOWN_RETRY: std::time::Duration = std::time::Duration::from_millis(500);

/// `ENETDOWN` — see `recv`. Also what `send` returns while the link is down.
pub fn is_link_down(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ENETDOWN)
}

/// The LLDPDU payload of a received frame, or `None` for a runt, a frame not
/// addressed to the LLDP group, or one this port sent itself. An `AF_PACKET`
/// socket also sees its own *outgoing* frames.
fn payload_of_foreign_frame(frame: &[u8], own: [u8; 6]) -> Option<&[u8]> {
    if frame.len() < ETH_HEADER_LEN || frame[..6] != LLDP_MULTICAST || frame[6..12] == own {
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

/// Joins `LLDP_MULTICAST` via `PACKET_ADD_MEMBERSHIP` — without this most NIC
/// drivers never pass an arbitrary multicast destination up to userspace.
fn join_lldp_multicast(socket: &Socket, ifindex: i32) -> io::Result<()> {
    let mut addr = [0u8; 8];
    addr[..6].copy_from_slice(&LLDP_MULTICAST);
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

    #[test]
    fn enetdown_is_recognized_as_link_down() {
        assert!(is_link_down(&io::Error::from_raw_os_error(libc::ENETDOWN)));
        assert!(!is_link_down(&io::Error::from_raw_os_error(libc::ENODEV)));
    }

    #[test]
    fn own_frames_runts_and_foreign_destinations_are_dropped() {
        let own = [2, 0, 0, 0, 0, 1];
        let other = [2, 0, 0, 0, 0, 2];
        let frame = |dst: [u8; 6], src: [u8; 6]| {
            let mut f = dst.to_vec();
            f.extend_from_slice(&src);
            f.extend_from_slice(&ETH_P_LLDP.to_be_bytes());
            f.extend_from_slice(b"lldpdu");
            f
        };
        assert_eq!(
            payload_of_foreign_frame(&frame(LLDP_MULTICAST, other), own),
            Some(&b"lldpdu"[..])
        );
        assert_eq!(
            payload_of_foreign_frame(&frame(LLDP_MULTICAST, own), own),
            None
        );
        // Not the nearest-bridge group (e.g. the customer-bridge address).
        assert_eq!(
            payload_of_foreign_frame(&frame([0x01, 0x80, 0xC2, 0, 0, 0], other), own),
            None
        );
        assert_eq!(payload_of_foreign_frame(&[0; 5], own), None);
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
