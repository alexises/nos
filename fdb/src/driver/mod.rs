use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::mpsc;

pub mod linux;
pub mod noop;

pub use linux::LinuxFdbDriver;
pub use noop::NoopFdbDriver;

pub type Mac = [u8; 6];

/// UDP port every VXLAN device here uses (RFC 7348's IANA port).
pub const VXLAN_PORT: u16 = 4789;

/// The kernel VXLAN device for `vni`: a VNI is unique per netns, so the name
/// needs no registry (`vx16777215` is 10 chars, under `IFNAMSIZ`).
#[must_use]
pub fn vxlan_name(vni: u32) -> String {
    format!("vx{vni}")
}

/// Errors from applying state to a real (or simulated) backend — never fatal
/// to the daemon: every call site logs and the next tick retries.
#[derive(Debug, Error)]
pub enum DriverError {
    #[error("netlink error: {0}")]
    Netlink(#[from] rtnetlink::Error),
    #[error("{0}")]
    Other(String),
}

/// Applies one broadcast domain's EVPN state to the OS. Every method is
/// idempotent; callers pass what they want and never diff against the kernel.
#[async_trait]
pub trait FdbDriver: Send + Sync {
    /// Ensures `vx<vni>` exists with this VNI, local VTEP address and
    /// `underlay` device (the one carrying `vtep` — required to bind the UDP
    /// socket when that address lives in a VRF), has learning off, and is
    /// enslaved to (and up under) `bridge`. A device with a different
    /// VNI/address/underlay is recreated. `Err` also when `bridge` or
    /// `underlay` doesn't exist yet — the caller retries next tick.
    async fn ensure_vxlan(
        &self,
        vni: u32,
        vtep: IpAddr,
        underlay: &str,
        bridge: &str,
    ) -> Result<(), DriverError>;

    /// Deletes `vx<vni>` (and with it every FDB entry on it). No-op if absent.
    async fn remove_vxlan(&self, vni: u32) -> Result<(), DriverError>;

    /// A remote MAC reachable via `vtep`, marked `extern_learn` so the kernel
    /// neither ages nor relearns it.
    async fn set_remote_mac(&self, vni: u32, mac: Mac, vtep: IpAddr) -> Result<(), DriverError>;
    async fn del_remote_mac(&self, vni: u32, mac: Mac, vtep: IpAddr) -> Result<(), DriverError>;

    /// One head-end-replication flood destination (the all-zero MAC entry).
    async fn add_flood(&self, vni: u32, vtep: IpAddr) -> Result<(), DriverError>;
    async fn del_flood(&self, vni: u32, vtep: IpAddr) -> Result<(), DriverError>;

    /// MACs the bridge learned (or an operator pinned) on its local ports,
    /// each with the name of the port it sits behind: not `extern_learn`, not
    /// on the VXLAN port, not the ports' own (permanent/local) addresses, no
    /// group addresses.
    async fn local_macs(
        &self,
        bridge: &str,
        vni: u32,
    ) -> Result<BTreeMap<Mac, String>, DriverError>;

    /// Turns flooding of unknown-unicast, multicast and broadcast frames to
    /// the bridge port `port` on or off (`bridge link set ... flood`). How a
    /// non-Designated-Forwarder PE stops delivering BUM traffic to an
    /// Ethernet Segment. `Err` while the port doesn't exist (yet).
    async fn set_port_flood(&self, port: &str, flood: bool) -> Result<(), DriverError>;

    /// IP-to-MAC bindings (ARP / IPv6 ND) on the bridge itself, i.e. the SVI's
    /// neighbour table: not `extern_learn` (our own `set_neigh` writes — the
    /// loop guard), only usable states, and only `is_advertisable_ip`
    /// addresses.
    async fn local_neighbours(&self, bridge: &str) -> Result<BTreeSet<(Mac, IpAddr)>, DriverError>;

    /// The bridge's own MAC — what an SVI address is originated with.
    async fn bridge_mac(&self, bridge: &str) -> Result<Mac, DriverError>;

    /// A remote host's IP-to-MAC binding on the bridge (the SVI's neighbour
    /// table), marked `extern_learn` so the kernel neither ages nor probes it.
    async fn set_neigh(&self, bridge: &str, mac: Mac, ip: IpAddr) -> Result<(), DriverError>;
    async fn del_neigh(&self, bridge: &str, mac: Mac, ip: IpAddr) -> Result<(), DriverError>;

    /// A wake-up on every kernel neighbour/FDB change (the receiver only
    /// signals "look again" — `local_macs` is the source of truth). `None`
    /// when the backend has no such feed; the caller then relies on its tick.
    fn watch_neigh(&self) -> Option<mpsc::UnboundedReceiver<()>>;
}

/// Whether an address belongs in a Type-2 route: link-local, loopback,
/// multicast and unspecified addresses only ever mean something on one link.
#[must_use]
pub fn is_advertisable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            !(a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || a.is_link_local()
                || a.is_broadcast())
        }
        IpAddr::V6(a) => {
            !(a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || (a.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// Whether a neighbour dump entry is a binding this domain should originate.
/// `usable` = the state carries a resolved MAC (reachable/stale/delay/probe/
/// permanent, not incomplete/failed/none/noarp).
#[must_use]
pub fn is_local_neigh(
    mac: Mac,
    ip: IpAddr,
    usable: bool,
    ext_learned: bool,
    ifindex: u32,
    bridge_ifindex: u32,
) -> bool {
    ifindex == bridge_ifindex
        && usable
        && !ext_learned
        && mac != [0; 6]
        && mac[0] & 1 == 0
        && is_advertisable_ip(ip)
}

/// Whether a bridge FDB dump entry is a MAC this domain should originate.
/// Pure so the rules are testable without a kernel.
#[must_use]
pub fn is_local_mac(
    mac: Mac,
    permanent: bool,
    ext_learned: bool,
    port_ifindex: u32,
    master: Option<u32>,
    bridge_ifindex: u32,
    vxlan_ifindex: Option<u32>,
) -> bool {
    master == Some(bridge_ifindex)
        && Some(port_ifindex) != vxlan_ifindex
        && !ext_learned
        && !permanent
        && mac != [0; 6]
        && mac[0] & 1 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: Mac = [0, 0x11, 0x22, 0x33, 0x44, 0x55];

    #[test]
    fn only_dynamic_or_static_entries_on_a_local_port_count() {
        assert!(is_local_mac(M, false, false, 5, Some(2), 2, Some(9)));
        // the port's own (permanent) address
        assert!(!is_local_mac(M, true, false, 5, Some(2), 2, Some(9)));
        // our own extern_learn write, and anything seen on the vxlan port
        assert!(!is_local_mac(M, false, true, 9, Some(2), 2, Some(9)));
        assert!(!is_local_mac(M, false, false, 9, Some(2), 2, Some(9)));
        // another bridge's entry, the flood entry, a group address
        assert!(!is_local_mac(M, false, false, 5, Some(3), 2, Some(9)));
        assert!(!is_local_mac([0; 6], false, false, 5, Some(2), 2, Some(9)));
        assert!(!is_local_mac(
            [1, 0, 0x5e, 0, 0, 1],
            false,
            false,
            5,
            Some(2),
            2,
            None
        ));
    }

    #[test]
    fn only_resolved_global_neighbours_on_the_bridge_count() {
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        assert!(is_local_neigh(M, ip, true, false, 2, 2));
        // our own extern_learn write, an unresolved entry, another device
        assert!(!is_local_neigh(M, ip, true, true, 2, 2));
        assert!(!is_local_neigh(M, ip, false, false, 2, 2));
        assert!(!is_local_neigh(M, ip, true, false, 3, 2));
        assert!(!is_local_neigh([0; 6], ip, true, false, 2, 2));
    }

    #[test]
    fn link_local_and_special_addresses_are_not_advertised() {
        for ip in ["198.51.100.7", "2001:db8::7"] {
            assert!(is_advertisable_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "169.254.1.1",
            "fe80::1",
            "127.0.0.1",
            "::1",
            "224.0.0.1",
            "ff02::1",
            "0.0.0.0",
            "::",
        ] {
            assert!(!is_advertisable_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn vxlan_names_fit_ifnamsiz() {
        assert_eq!(vxlan_name(10100), "vx10100");
        assert!(vxlan_name(0x00ff_ffff).len() <= 15);
    }
}
