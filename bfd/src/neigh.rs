//! The neighbour's MAC address for Echo (RFC 5881 §4: the Ethernet
//! destination is the neighbour's), read from the kernel neighbour table.
//! Read-only: the Control session's ARP/ND creates the entry, we never write.

use std::io;
use std::net::IpAddr;

use futures::TryStreamExt;
use netlink_packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState,
};
use netlink_packet_route::AddressFamily;

/// A state with a MAC worth using: not Incomplete/Failed/None.
pub fn state_usable(s: NeighbourState) -> bool {
    matches!(
        s,
        NeighbourState::Reachable
            | NeighbourState::Stale
            | NeighbourState::Delay
            | NeighbourState::Probe
            | NeighbourState::Permanent
    )
}

/// The MAC `msg` holds for `peer` on `ifindex`, when it is a usable entry.
pub fn mac_of(msg: &NeighbourMessage, peer: IpAddr, ifindex: u32) -> Option<[u8; 6]> {
    if msg.header.ifindex != ifindex || !state_usable(msg.header.state) {
        return None;
    }
    let mut dst = None;
    let mut mac = None;
    for a in &msg.attributes {
        match a {
            NeighbourAttribute::Destination(NeighbourAddress::Inet(v4)) => {
                dst = Some(IpAddr::V4(*v4));
            }
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(v6)) => {
                dst = Some(IpAddr::V6(*v6));
            }
            NeighbourAttribute::LinkLayerAddress(b) => mac = <[u8; 6]>::try_from(b.as_slice()).ok(),
            _ => {}
        }
    }
    (dst == Some(peer)).then_some(mac).flatten()
}

/// Dumps the neighbour table and returns `peer`'s MAC on `ifindex`.
pub async fn lookup(
    handle: &rtnetlink::Handle,
    peer: IpAddr,
    ifindex: u32,
) -> io::Result<Option<[u8; 6]>> {
    let family = if peer.is_ipv4() {
        AddressFamily::Inet
    } else {
        AddressFamily::Inet6
    };
    let mut dump = handle
        .neighbours()
        .get()
        .set_address_family(family)
        .execute();
    while let Some(m) = dump.try_next().await.map_err(io::Error::other)? {
        if let Some(mac) = mac_of(&m, peer, ifindex) {
            return Ok(Some(mac));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(state: NeighbourState, ifindex: u32, dst: &str, mac: &[u8]) -> NeighbourMessage {
        let mut m = NeighbourMessage::default();
        m.header.state = state;
        m.header.ifindex = ifindex;
        m.attributes = vec![
            match dst.parse().unwrap() {
                IpAddr::V4(a) => NeighbourAttribute::Destination(NeighbourAddress::Inet(a)),
                IpAddr::V6(a) => NeighbourAttribute::Destination(NeighbourAddress::Inet6(a)),
            },
            NeighbourAttribute::LinkLayerAddress(mac.to_vec()),
        ];
        m
    }

    #[test]
    fn only_usable_entries_for_the_peer_and_interface_count() {
        let peer: IpAddr = "192.0.2.2".parse().unwrap();
        let mac = [2, 0, 0, 0, 0, 2];
        let ok = |s, i, d| mac_of(&msg(s, i, d, &mac), peer, 3);
        assert_eq!(ok(NeighbourState::Reachable, 3, "192.0.2.2"), Some(mac));
        assert_eq!(ok(NeighbourState::Stale, 3, "192.0.2.2"), Some(mac));
        assert_eq!(ok(NeighbourState::Incomplete, 3, "192.0.2.2"), None);
        assert_eq!(ok(NeighbourState::Failed, 3, "192.0.2.2"), None);
        assert_eq!(ok(NeighbourState::Reachable, 4, "192.0.2.2"), None);
        assert_eq!(ok(NeighbourState::Reachable, 3, "192.0.2.9"), None);
        // A short link-layer address is no MAC.
        assert_eq!(
            mac_of(
                &msg(NeighbourState::Reachable, 3, "192.0.2.2", &[1, 2]),
                peer,
                3
            ),
            None
        );
    }
}
