use std::ffi::CString;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use ipnet::{IpNet, Ipv6Net};
use nos_proto::{DiffScope, Event, NetworkType, ServiceRef};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config_client;
use crate::interface_client;
use crate::link::{LinkConfig, LinkManager};
use crate::watchdog_client;

/// Fixed reconnect delay — same cadence as every other config-subscribing
/// consumer in this codebase, `ospf::reconcile::RECONNECT_DELAY` included.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// How often to re-apply desired state even without a new config diff —
/// same reasoning/cadence as `ospf::reconcile::REAPPLY_INTERVAL`: a link's
/// VRF/local-address/link-local-address readiness is an external condition
/// no config commit signals.
const REAPPLY_INTERVAL: Duration = Duration::from_secs(10);

/// Runs until `shutdown` fires — mirrors `ospf::reconcile::run` exactly,
/// subscribed to `Ospfv3Instances` instead of `OspfInstances`.
pub async fn run(
    config_socket: PathBuf,
    watchdog_socket: PathBuf,
    instance: String,
    links: Arc<LinkManager>,
    routing_table_tx: watch::Sender<Option<String>>,
    mut shutdown: watch::Receiver<bool>,
) {
    while !*shutdown.borrow() {
        match config_client::subscribe_diff(&config_socket, vec![DiffScope::Ospfv3Instances]).await
        {
            Ok(mut reader) => {
                info!(instance = %instance, "connected to nos-configd diff stream");
                let mut reapply = tokio::time::interval(REAPPLY_INTERVAL);
                reapply.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                reapply.tick().await;
                resync(
                    &config_socket,
                    &watchdog_socket,
                    &instance,
                    &links,
                    &routing_table_tx,
                )
                .await;
                loop {
                    tokio::select! {
                        event = reader.next() => match event {
                            Some(Ok(Event::Diff(_))) => {
                                resync(&config_socket, &watchdog_socket, &instance, &links, &routing_table_tx).await;
                            }
                            Some(Ok(_)) => {}
                            Some(Err(e)) => {
                                warn!(error = %e, "error reading diff stream, reconnecting");
                                break;
                            }
                            None => {
                                warn!("diff stream closed, reconnecting");
                                break;
                            }
                        },
                        _ = reapply.tick() => {
                            resync(&config_socket, &watchdog_socket, &instance, &links, &routing_table_tx).await;
                        }
                        _ = shutdown.changed() => break,
                    }
                }
            }
            Err(e) => warn!(
                error = %e,
                socket = %config_socket.display(),
                "failed to connect to nos-configd"
            ),
        }

        if *shutdown.borrow() {
            break;
        }
        if wait_or_shutdown(RECONNECT_DELAY, &mut shutdown).await {
            break;
        }
    }

    links.shutdown().await;
    info!(instance = %instance, "reconciliation loop stopped");
}

async fn resync(
    config_socket: &Path,
    watchdog_socket: &Path,
    instance: &str,
    links: &Arc<LinkManager>,
    routing_table_tx: &watch::Sender<Option<String>>,
) {
    let cfg = match config_client::fetch_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!(error = %e, "failed to fetch running config, keeping previous state");
            return;
        }
    };

    let Some(own) = cfg.ospfv3_instances.iter().find(|i| i.name == instance) else {
        warn!(instance = %instance, "own ospfv3 instance missing from running config");
        let _ = routing_table_tx.send(None);
        return;
    };
    let _ = routing_table_tx.send(own.routing_table.clone());
    info!(
        instance = %instance,
        router_id = %own.router_id,
        routing_table = ?own.routing_table,
        area_count = own.areas.len(),
        extended_lsa = own.extended_lsa,
        "ospfv3 instance config resolved"
    );
    links.set_extended_lsa(own.extended_lsa);

    let mut desired_links = Vec::new();
    let mut desired_loopback_prefixes: std::collections::HashMap<
        std::net::Ipv4Addr,
        Vec<(Ipv6Net, u16)>,
    > = std::collections::HashMap::new();

    for area in &own.areas {
        info!(
            instance = %instance,
            area = %area.area_id,
            profile_count = area.profiles.len(),
            "ospfv3 area resolved"
        );
        for profile in &area.profiles {
            let interfaces = attach_points_for(&cfg, &profile.name);
            info!(
                instance = %instance,
                area = %area.area_id,
                profile = %profile.name,
                interfaces = ?interfaces,
                cost = ?profile.cost,
                "ospfv3 profile resolved"
            );

            let hello_interval = profile
                .hello_interval
                .unwrap_or(nos_proto::HELLO_INTERVAL_DEFAULT);
            let dead_interval = profile
                .dead_interval
                .unwrap_or(nos_proto::DEAD_INTERVAL_DEFAULT);
            let priority = profile.priority.unwrap_or(nos_proto::PRIORITY_DEFAULT);
            let cost = profile.cost.unwrap_or(1);

            for attach in subinterface_attach_points(&cfg, &profile.name) {
                let link_name = attach.display_name();
                let Some(routing_table) = &attach.routing_table else {
                    warn!(
                        instance = %instance, link = %link_name,
                        "ospfv3 profile attached to a subinterface with no routing-table, skipping"
                    );
                    continue;
                };
                let Some(vrf) = resolve_vrf(watchdog_socket, routing_table).await else {
                    warn!(instance = %instance, link = %link_name, "ospfv3 link's vrf not resolvable yet");
                    continue;
                };
                let kernel_interface = subinterface_kernel_interface(&attach.interface, attach.tag);
                let Some(resolved) =
                    resolve_local_address(watchdog_socket, &attach.interface, attach.tag).await
                else {
                    warn!(instance = %instance, link = %link_name, "ospfv3 link's local address not resolvable yet");
                    continue;
                };
                let Some(interface_id) = kernel_ifindex(&kernel_interface) else {
                    warn!(instance = %instance, link = %link_name, kernel_interface = %kernel_interface, "ospfv3 link's kernel interface not present yet");
                    continue;
                };
                desired_links.push(LinkConfig {
                    attach_point: link_name,
                    area_id: area.area_id,
                    hello_interval,
                    dead_interval,
                    vrf,
                    kernel_interface,
                    interface_id,
                    link_local_address: resolved.link_local_address,
                    prefix: resolved.prefix,
                    cost,
                    network_type: profile.network_type.unwrap_or(NetworkType::PointToPoint),
                    priority,
                    mtu: resolve_effective_mtu(profile, Some(resolved.mtu)),
                });
            }

            for attach in loopback_attach_points(&cfg, &profile.name) {
                let Some(prefix) =
                    resolve_loopback_prefix(watchdog_socket, &attach.interface).await
                else {
                    warn!(
                        instance = %instance, interface = %attach.interface,
                        "ospfv3 loopback prefix not resolvable yet"
                    );
                    continue;
                };
                desired_loopback_prefixes
                    .entry(area.area_id)
                    .or_default()
                    .push((prefix, cost));
            }

            for attach in broadcast_domain_attach_points(&cfg, &profile.name) {
                let link_name = attach.display_name();
                let Some(routing_table) = &attach.routing_table else {
                    warn!(
                        instance = %instance, link = %link_name,
                        "ospfv3 profile attached to a broadcast domain with no routing-table, skipping"
                    );
                    continue;
                };
                let Some(vrf) = resolve_vrf(watchdog_socket, routing_table).await else {
                    warn!(instance = %instance, link = %link_name, "ospfv3 link's vrf not resolvable yet");
                    continue;
                };
                let Some((resolved, kernel_interface)) =
                    resolve_broadcast_domain(watchdog_socket, &attach.name).await
                else {
                    warn!(instance = %instance, link = %link_name, "ospfv3 link's local address/bridge not resolvable yet");
                    continue;
                };
                let Some(interface_id) = kernel_ifindex(&kernel_interface) else {
                    warn!(instance = %instance, link = %link_name, kernel_interface = %kernel_interface, "ospfv3 link's kernel bridge not present yet");
                    continue;
                };
                desired_links.push(LinkConfig {
                    attach_point: link_name,
                    area_id: area.area_id,
                    hello_interval,
                    dead_interval,
                    vrf,
                    kernel_interface,
                    interface_id,
                    link_local_address: resolved.link_local_address,
                    prefix: resolved.prefix,
                    cost,
                    network_type: profile.network_type.unwrap_or(NetworkType::Broadcast),
                    priority,
                    mtu: resolve_effective_mtu(profile, None),
                });
            }
        }
    }

    links
        .reconcile(desired_links, desired_loopback_prefixes, own.router_id)
        .await;
}

/// Every L3 attach point referencing `profile` by name — mirrors
/// `ospf::reconcile::attach_points_for` exactly, checking `ospfv3_profile`
/// instead of `ospf_profile`.
fn attach_points_for(cfg: &nos_proto::Config, profile: &str) -> Vec<String> {
    let mut points = Vec::new();
    for iface in &cfg.interfaces {
        if iface.ospfv3_profile.as_deref() == Some(profile) {
            points.push(iface.name.clone());
        }
        for sub in &iface.subinterfaces {
            if sub.ospfv3_profile.as_deref() == Some(profile) {
                points.push(format!("{}.{}", iface.name, sub.tag));
            }
        }
    }
    for domain in &cfg.broadcast_domains {
        if domain.ospfv3_profile.as_deref() == Some(profile) {
            points.push(format!("broadcast-domain:{}", domain.name));
        }
    }
    points
}

struct SubinterfaceAttachPoint {
    interface: String,
    tag: u16,
    routing_table: Option<String>,
}

impl SubinterfaceAttachPoint {
    fn display_name(&self) -> String {
        format!("{}.{}", self.interface, self.tag)
    }
}

fn subinterface_attach_points(
    cfg: &nos_proto::Config,
    profile: &str,
) -> Vec<SubinterfaceAttachPoint> {
    let mut points = Vec::new();
    for iface in &cfg.interfaces {
        for sub in &iface.subinterfaces {
            if sub.ospfv3_profile.as_deref() == Some(profile) {
                points.push(SubinterfaceAttachPoint {
                    interface: iface.name.clone(),
                    tag: sub.tag,
                    routing_table: sub.routing_table.clone(),
                });
            }
        }
    }
    points
}

struct BroadcastDomainAttachPoint {
    name: String,
    routing_table: Option<String>,
}

impl BroadcastDomainAttachPoint {
    fn display_name(&self) -> String {
        format!("broadcast-domain:{}", self.name)
    }
}

fn broadcast_domain_attach_points(
    cfg: &nos_proto::Config,
    profile: &str,
) -> Vec<BroadcastDomainAttachPoint> {
    cfg.broadcast_domains
        .iter()
        .filter(|d| d.ospfv3_profile.as_deref() == Some(profile))
        .map(|d| BroadcastDomainAttachPoint {
            name: d.name.clone(),
            routing_table: d.routing_table.clone(),
        })
        .collect()
}

struct LoopbackAttachPoint {
    interface: String,
}

fn loopback_attach_points(cfg: &nos_proto::Config, profile: &str) -> Vec<LoopbackAttachPoint> {
    cfg.interfaces
        .iter()
        .filter(|i| {
            nos_proto::loopback_table_name(&i.name).is_some()
                && i.ospfv3_profile.as_deref() == Some(profile)
        })
        .map(|i| LoopbackAttachPoint {
            interface: i.name.clone(),
        })
        .collect()
}

async fn resolve_vrf(watchdog_socket: &Path, table: &str) -> Option<String> {
    let socket =
        watchdog_client::resolve_once(watchdog_socket, &ServiceRef::RibTable(table.to_string()))
            .await?;
    crate::rib_client::get_vrf_name(&socket).await
}

/// A link's resolved IPv6 addressing — link-local (Hello/Link-LSA source)
/// and the global/ULA prefix configured on it — plus its real interface
/// MTU.
struct ResolvedLink {
    link_local_address: Ipv6Addr,
    prefix: Ipv6Net,
    mtu: u32,
}

/// Resolves a subinterface's link-local address (populated by
/// `nos-interfaced`'s Linux driver purely by observing the kernel — see
/// `nos_proto::SubinterfaceStatus.link_local_address`'s doc comment) and its
/// configured global/ULA prefix, by asking `nos-interfaced` directly.
/// `None` covers every "not resolvable yet" case uniformly, retried by the
/// caller's periodic re-apply tick.
async fn resolve_local_address(
    watchdog_socket: &Path,
    interface: &str,
    tag: u16,
) -> Option<ResolvedLink> {
    let socket = watchdog_client::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
    let status = interface_client::get_interface(&socket, interface).await?;
    let mtu = status.mtu;
    let sub = status.subinterfaces.into_iter().find(|s| s.tag == tag)?;
    let link_local_address = sub.link_local_address?;
    let prefix = sub.addresses.into_iter().find_map(|a| match a.address {
        IpNet::V6(v6) => Some(v6),
        IpNet::V4(_) => None,
    })?;
    Some(ResolvedLink {
        link_local_address,
        prefix,
        mtu,
    })
}

const DEFAULT_OSPF_MTU: u16 = 1500;

/// Mirrors `ospf::reconcile::resolve_effective_mtu` exactly.
fn resolve_effective_mtu(profile: &nos_proto::Ospfv3Profile, resolved_mtu: Option<u32>) -> u16 {
    profile.mtu.unwrap_or_else(|| {
        resolved_mtu
            .and_then(|m| u16::try_from(m).ok())
            .unwrap_or(DEFAULT_OSPF_MTU)
    })
}

/// Resolves a loopback (`Interface.ospfv3_profile`) attach point's own
/// IPv6 prefix — feeds `LinkManager`'s loopback-prefix map, since a
/// loopback has no live link/socket to carry it through `LinkConfig` (no
/// Hello is ever sent from it — see `link.rs`'s module doc comment).
async fn resolve_loopback_prefix(watchdog_socket: &Path, interface: &str) -> Option<Ipv6Net> {
    let socket = watchdog_client::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
    let status = interface_client::get_interface(&socket, interface).await?;
    status.addresses.into_iter().find_map(|a| match a.address {
        IpNet::V6(v6) => Some(v6),
        IpNet::V4(_) => None,
    })
}

/// Resolves a broadcast domain's own SVI link-local address, its IPv6
/// prefix, and its real kernel bridge device name — mirrors
/// `ospf::reconcile::resolve_broadcast_domain`'s shape.
async fn resolve_broadcast_domain(
    watchdog_socket: &Path,
    domain: &str,
) -> Option<(ResolvedLink, String)> {
    let socket = watchdog_client::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
    let status = interface_client::get_broadcast_domain(&socket, domain).await?;
    let bridge_name = status.bridge_name?;
    let link_local_address = status.link_local_address?;
    let prefix = status.addresses.into_iter().find_map(|a| match a.address {
        IpNet::V6(v6) => Some(v6),
        IpNet::V4(_) => None,
    })?;
    Some((
        ResolvedLink {
            link_local_address,
            prefix,
            // A broadcast domain's own bridge has no separate MTU concept
            // in this schema (see `nos_proto::BroadcastDomainStatus`) —
            // `resolve_effective_mtu` always falls back to
            // `DEFAULT_OSPF_MTU` for this attach-point kind, matching
            // `ospf::reconcile`'s identical `None` here.
            mtu: 0,
        },
        bridge_name,
    ))
}

fn subinterface_kernel_interface(interface: &str, tag: u16) -> String {
    if tag == 0 {
        interface.to_string()
    } else {
        format!("{interface}.{tag}")
    }
}

/// Resolves a kernel interface's ifindex, doubling as this link's RFC 5340
/// Interface ID (see `LinkConfig.interface_id`'s doc comment) — a local
/// `libc` call, not an IPC round trip: every daemon in this NOS shares one
/// network namespace, so `nos-ospfv3d` can read the kernel's own interface
/// table directly, the same way `nos-interfaced`'s Linux driver does.
/// `None` if the interface doesn't exist in the netns yet (an ordinary
/// transient condition, not an error — retried by the caller's periodic
/// re-apply tick).
fn kernel_ifindex(name: &str) -> Option<u32> {
    let cname = CString::new(name).ok()?;
    #[allow(unsafe_code)]
    // SAFETY: `cname` is a valid, NUL-terminated C string owned for the
    // duration of this call, matching `if_nametoindex`'s contract.
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        None
    } else {
        Some(idx)
    }
}

/// Local copy of `nos-watchdog::supervisor::wait_or_shutdown` — not
/// imported, per the star-dependency rule.
async fn wait_or_shutdown(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

#[cfg(test)]
mod tests {
    use nos_proto::{BroadcastDomain, Config, Interface, Subinterface};

    use super::attach_points_for;
    use super::broadcast_domain_attach_points;
    use super::loopback_attach_points;
    use super::subinterface_attach_points;

    fn interface(name: &str, ospfv3_profile: Option<&str>) -> Interface {
        Interface {
            name: name.to_string(),
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
            ospfv3_profile: ospfv3_profile.map(str::to_string),
            switching_profile: None,
            port_aggregate: None,
            mtu: None,
            lldp_transmit: false,
            lldp_receive: false,
            lldp_destination: nos_proto::LldpDestination::default(),
            subinterfaces: Vec::new(),
        }
    }

    #[test]
    fn finds_loopback_interface_attachment() {
        let cfg = Config {
            interfaces: vec![interface("loopback-rt1", Some("p1"))],
            ..Default::default()
        };
        assert_eq!(attach_points_for(&cfg, "p1"), vec!["loopback-rt1"]);
    }

    #[test]
    fn finds_subinterface_attachment() {
        let mut iface = interface("eth0", None);
        iface.subinterfaces = vec![Subinterface {
            tag: 100,
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
            ospfv3_profile: Some("p1".to_string()),
        }];
        let cfg = Config {
            interfaces: vec![iface],
            ..Default::default()
        };
        assert_eq!(attach_points_for(&cfg, "p1"), vec!["eth0.100"]);
    }

    #[test]
    fn finds_broadcast_domain_attachment() {
        let cfg = Config {
            broadcast_domains: vec![BroadcastDomain {
                name: "bd1".to_string(),
                addresses: Vec::new(),
                routing_table: None,
                ospf_profile: None,
                ospfv3_profile: Some("p1".to_string()),
                vni: None,
                rd: None,
                route_targets_import: Vec::new(),
                route_targets_export: Vec::new(),
                vtep_source: None,
                mac_redistribute: None,
                arp_redistribute: None,
                connected_redistribute: None,
            }],
            ..Default::default()
        };
        assert_eq!(attach_points_for(&cfg, "p1"), vec!["broadcast-domain:bd1"]);
    }

    #[test]
    fn ignores_attachments_to_other_profiles() {
        let cfg = Config {
            interfaces: vec![interface("loopback-rt1", Some("other"))],
            ..Default::default()
        };
        assert!(attach_points_for(&cfg, "p1").is_empty());
    }

    #[test]
    fn subinterface_attach_points_finds_routing_table() {
        let mut iface = interface("eth0", None);
        iface.subinterfaces = vec![Subinterface {
            tag: 0,
            addresses: Vec::new(),
            routing_table: Some("rt1".to_string()),
            ospf_profile: None,
            ospfv3_profile: Some("p1".to_string()),
        }];
        let cfg = Config {
            interfaces: vec![iface],
            ..Default::default()
        };
        let points = subinterface_attach_points(&cfg, "p1");
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].display_name(), "eth0.0");
        assert_eq!(points[0].routing_table.as_deref(), Some("rt1"));
    }

    #[test]
    fn broadcast_domain_attach_points_finds_routing_table() {
        let cfg = Config {
            broadcast_domains: vec![BroadcastDomain {
                name: "bd1".to_string(),
                addresses: Vec::new(),
                routing_table: Some("rt1".to_string()),
                ospf_profile: None,
                ospfv3_profile: Some("p1".to_string()),
                vni: None,
                rd: None,
                route_targets_import: Vec::new(),
                route_targets_export: Vec::new(),
                vtep_source: None,
                mac_redistribute: None,
                arp_redistribute: None,
                connected_redistribute: None,
            }],
            ..Default::default()
        };
        let points = broadcast_domain_attach_points(&cfg, "p1");
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].display_name(), "broadcast-domain:bd1");
        assert_eq!(points[0].routing_table.as_deref(), Some("rt1"));
    }

    #[test]
    fn loopback_attach_points_finds_loopback_interface() {
        let cfg = Config {
            interfaces: vec![interface("loopback-rt1", Some("p1"))],
            ..Default::default()
        };
        let points = loopback_attach_points(&cfg, "p1");
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].interface, "loopback-rt1");
    }
}
