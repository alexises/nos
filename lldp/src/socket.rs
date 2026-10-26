//! LLDP's raw socket: `nos-l2-socket`'s `L2Socket` fixed to ethertype
//! `0x88CC`, bound to **one physical interface**, joined to whichever
//! 802.1AB destination group the interface is configured for.

use std::io;

pub use nos_l2_socket::is_link_down;
pub type LldpSocket = nos_l2_socket::L2Socket;

/// `ETH_P_LLDP` (IEEE 802.1AB).
const ETH_P_LLDP: u16 = 0x88CC;

/// Comfortably above any realistic LLDPDU; a longer frame is truncated by the
/// kernel and simply fails to decode.
const RECV_BUF_LEN: usize = 2048;

pub fn open(interface: &str, group: [u8; 6]) -> io::Result<LldpSocket> {
    LldpSocket::open_untagged(interface, ETH_P_LLDP, group, RECV_BUF_LEN)
}
