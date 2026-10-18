//! One-shot queries of `nos-interfaced` and `nos-ribd` (best-effort:
//! `None` is "not answerable yet", retried next tick), over
//! `nos_daemon::ipc::one_shot`.

use std::net::IpAddr;
use std::path::Path;

use nos_proto::rib::EvpnIrb;
use nos_proto::{
    BroadcastDomainStatus, InterfaceEvent, InterfaceRequest, RibEvent, RibRequest, Role,
    ServiceRef, SourceAddress, LOOPBACK_PREFIX,
};
use tracing::trace;

use nos_daemon::ipc::one_shot;
use nos_daemon::watchdog;

async fn ask(sock: &Path, req: InterfaceRequest) -> Option<InterfaceEvent> {
    one_shot(sock, Role::Interfaced, req).await
}

/// The domain's reconciled bridge device name (`None` until created).
pub async fn bridge_name(watchdog_socket: &Path, domain: &str) -> Option<String> {
    let sock = watchdog::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
    let req = InterfaceRequest::GetBroadcastDomain {
        name: domain.to_string(),
    };
    match ask(&sock, req).await? {
        InterfaceEvent::BroadcastDomain(BroadcastDomainStatus { bridge_name, .. }) => bridge_name,
        other => {
            trace!(?other, "unexpected reply to GetBroadcastDomain");
            None
        }
    }
}

/// The kernel bond device `nos-interfaced` created for port aggregate
/// `aggregate` (`bond<id>`, never its config name; `None` until created).
pub async fn bond_name(watchdog_socket: &Path, aggregate: &str) -> Option<String> {
    let sock = watchdog::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
    let req = InterfaceRequest::GetPortAggregate {
        name: aggregate.to_string(),
    };
    match ask(&sock, req).await? {
        InterfaceEvent::PortAggregate(status) => status.bond_name,
        other => {
            trace!(?other, "unexpected reply to GetPortAggregate");
            None
        }
    }
}

/// The kernel name of routing table `table`'s loopback device: `lo<table id>`,
/// the id being `nos-ribd`'s (see `RibRequest::GetTableId`).
async fn loopback_device(watchdog_socket: &Path, table: &str) -> Option<String> {
    match ask_rib(watchdog_socket, table, RibRequest::GetTableId).await? {
        RibEvent::TableId(Some(id)) => Some(format!("lo{id}")),
        _ => None,
    }
}

/// Routing table `table`'s EVPN IP-VRF, for symmetric IRB (`None` until its
/// `nos-ribd` built it, or while that daemon isn't reachable).
pub async fn evpn_irb(watchdog_socket: &Path, table: &str) -> Option<EvpnIrb> {
    match ask_rib(watchdog_socket, table, RibRequest::GetEvpnIrb).await? {
        RibEvent::EvpnIrb(irb) => irb,
        _ => None,
    }
}

async fn ask_rib(watchdog_socket: &Path, table: &str, req: RibRequest) -> Option<RibEvent> {
    let sock =
        watchdog::resolve_once(watchdog_socket, &ServiceRef::RibTable(table.to_string())).await?;
    one_shot(&sock, Role::Ribd, req).await
}

/// The VTEP address `source` names, preferring IPv4, and the kernel device
/// that carries it (the VXLAN device's underlay: with the address inside a VRF
/// the kernel can only bind the tunnel's UDP socket through that device).
/// `bgp_table` is the routing table owning the BGP instance (for `Loopback`,
/// which derives `loopback-<table>`). Mirrors `nos-bgpd`'s
/// `resolve_source_address`.
pub async fn resolve_vtep(
    watchdog_socket: &Path,
    bgp_table: Option<&str>,
    source: &SourceAddress,
) -> Option<(IpAddr, String)> {
    let (interface, label, is_loopback) = match source {
        SourceAddress::Interface { interface, label } => (interface.clone(), label, false),
        SourceAddress::Loopback { label } => {
            (format!("{LOOPBACK_PREFIX}{}", bgp_table?), label, true)
        }
    };
    let device = if is_loopback {
        loopback_device(watchdog_socket, bgp_table?).await?
    } else {
        interface.clone()
    };
    let sock = watchdog::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
    let InterfaceEvent::Interface(status) =
        ask(&sock, InterfaceRequest::GetInterface { name: interface }).await?
    else {
        return None;
    };
    // A loopback carries its addresses flat; any other interface's live under
    // its untagged (tag 0) subinterface — see `schema::valid_addressing_split`.
    let addresses = if is_loopback {
        status.addresses
    } else {
        status
            .subinterfaces
            .into_iter()
            .find(|s| s.tag == 0)?
            .addresses
    };
    let mut ips: Vec<IpAddr> = addresses
        .into_iter()
        .filter(|a| label.is_none() || a.label == *label)
        .map(|a| a.address.addr())
        .collect();
    ips.sort_by_key(IpAddr::is_ipv6); // IPv4 first
    ips.into_iter().next().map(|ip| (ip, device))
}
