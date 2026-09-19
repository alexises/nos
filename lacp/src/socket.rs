//! LACP's raw socket: `nos-l2-socket`'s `L2Socket` fixed to ethertype
//! `ETH_P_SLOW` and the slow-protocols multicast group. Bound to **one
//! physical member interface** — never the bond device, never a VRF — since
//! LACP negotiates per-physical-link.

use std::io;

pub use nos_l2_socket::is_link_down;
pub type LacpSocket = nos_l2_socket::L2Socket;

/// `ETH_P_SLOW` (IEEE 802.3, Annex 43B) — the ethertype both LACP and the
/// Marker protocol use; `packet::decode` further rejects anything that isn't
/// LACP's own subtype byte.
const ETH_P_SLOW: u16 = 0x8809;

/// The IEEE 802.1AX slow-protocols multicast destination MAC every LACPDU is
/// sent to (and the only one `recv` accepts).
pub const SLOW_PROTOCOLS_MULTICAST: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x02];

/// A full LACPDU (`packet::LACPDU_LEN`) plus its Ethernet header, generously
/// rounded up.
const RECV_BUF_LEN: usize = 256;

pub fn open(interface: &str) -> io::Result<LacpSocket> {
    LacpSocket::open(
        interface,
        ETH_P_SLOW,
        SLOW_PROTOCOLS_MULTICAST,
        RECV_BUF_LEN,
    )
}
