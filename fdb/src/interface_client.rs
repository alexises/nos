//! One-shot queries of `nos-interfaced` (best-effort like `nos-bgpd`'s and
//! `nos-ospfd`'s copies: `None` is "not answerable yet", retried next tick).
//! Reimplemented rather than imported, per the star dependency graph.

use std::net::IpAddr;
use std::path::Path;

use futures::{SinkExt, StreamExt};
use nos_proto::{
    BroadcastDomainStatus, InterfaceEvent, InterfaceRequest, IpcCodec, RibEvent, RibRequest, Role,
    ServiceRef, SourceAddress, LOOPBACK_PREFIX,
};
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::trace;

use crate::watchdog_client;

async fn ask(sock: &Path, req: InterfaceRequest) -> Option<InterfaceEvent> {
    let stream = nos_pki::connect(sock, Role::Interfaced, "").await.ok()?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<InterfaceEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<InterfaceRequest>::default());
    writer.send(req).await.ok()?;
    reader.next().await?.ok()
}

/// The domain's reconciled bridge device name (`None` until created).
pub async fn bridge_name(watchdog_socket: &Path, domain: &str) -> Option<String> {
    let sock = watchdog_client::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
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
    let sock = watchdog_client::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
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
    let sock =
        watchdog_client::resolve_once(watchdog_socket, &ServiceRef::RibTable(table.to_string()))
            .await?;
    let stream = nos_pki::connect_role(&sock, Role::Ribd).await.ok()?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<RibEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<RibRequest>::default());
    writer.send(RibRequest::GetTableId).await.ok()?;
    match reader.next().await? {
        Ok(RibEvent::TableId(Some(id))) => Some(format!("lo{id}")),
        _ => None,
    }
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
    let sock = watchdog_client::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
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
