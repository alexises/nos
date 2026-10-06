use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use ipnet::Ipv4Net;
use nos_proto::{DiffScope, Event, NetworkType, OspfAuth, OspfCryptoAlgorithm, ServiceRef};
use nos_rpl::CompiledPolicy;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config_client;
use crate::interface_client;
use crate::link::{AreaSettings, LinkAuthConfig, LinkConfig, LinkManager};
use crate::packet;
use crate::rib_client;
use crate::watchdog_client;

/// Fixed reconnect delay for the config subscription, matching every other
/// config-subscribing consumer in this codebase (`nos-bgp`/`nos-rib`/
/// `nos-interface`'s own `reconcile::RECONNECT_DELAY`).
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// How often to re-apply desired state even without a new config diff —
/// needed because a link's VRF/local-address readiness (the owning
/// `nos-ribd`/`nos-interfaced` having resolved it) is an external condition
/// no config commit signals, same as `nos-bgp`'s own `reconcile::
/// REAPPLY_INTERVAL`.
const REAPPLY_INTERVAL: Duration = Duration::from_secs(10);

/// Runs until `shutdown` fires. Subscribes to `OspfInstances` diffs purely as
/// a resync trigger — the actual state always comes from a fresh
/// `fetch_config` call, plus a periodic tick independent of any config
/// change.
pub async fn run(
    config_socket: PathBuf,
    watchdog_socket: PathBuf,
    instance: String,
    links: Arc<LinkManager>,
    routing_table_tx: watch::Sender<Option<String>>,
    mut shutdown: watch::Receiver<bool>,
) {
    while !*shutdown.borrow() {
        match config_client::subscribe_diff(&config_socket, vec![DiffScope::OspfInstances]).await {
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
                                resync(
                                    &config_socket,
                                    &watchdog_socket,
                                    &instance,
                                    &links,
                                    &routing_table_tx,
                                )
                                .await;
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
                            resync(
                                &config_socket,
                                &watchdog_socket,
                                &instance,
                                &links,
                                &routing_table_tx,
                            )
                            .await;
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

    let Some(own) = cfg.ospf_instances.iter().find(|i| i.name == instance) else {
        // The watchdog would be tearing this process down anyway if the
        // instance were genuinely removed from config.
        warn!(instance = %instance, "own ospf instance missing from running config");
        let _ = routing_table_tx.send(None);
        return;
    };
    let _ = routing_table_tx.send(own.routing_table.clone());
    info!(
        instance = %instance,
        router_id = %own.router_id,
        routing_table = ?own.routing_table,
        area_count = own.areas.len(),
        graceful_restart_grace_period = ?own.graceful_restart_grace_period,
        prefix_suppression = own.prefix_suppression,
        max_metric_on_startup = ?own.max_metric_on_startup,
        max_metric_on_shutdown = ?own.max_metric_on_shutdown,
        max_metric_administrative = own.max_metric_administrative,
        host_router = own.host_router,
        "ospf instance config resolved"
    );
    links.set_graceful_restart(own.graceful_restart_grace_period);
    links.set_prefix_suppression(own.prefix_suppression);
    links.set_host_router(own.host_router);
    links.set_max_metric(
        own.max_metric_on_startup,
        own.max_metric_on_shutdown,
        own.max_metric_administrative,
    );
    links.set_area_settings(area_settings(&own.areas)).await;

    let mut desired_links = Vec::new();
    let mut desired_stubs: HashMap<Ipv4Addr, Vec<(Ipv4Net, u16)>> = HashMap::new();
    for area in &own.areas {
        info!(
            instance = %instance,
            area = %area.area_id,
            profile_count = area.profiles.len(),
            "ospf area resolved"
        );
        for profile in &area.profiles {
            let interfaces = attach_points_for(&cfg, &profile.name);
            info!(
                instance = %instance,
                area = %area.area_id,
                profile = %profile.name,
                interfaces = ?interfaces,
                cost = ?profile.cost,
                "ospf profile resolved"
            );

            let hello_interval = profile
                .hello_interval
                .unwrap_or(nos_proto::HELLO_INTERVAL_DEFAULT);
            let dead_interval = profile
                .dead_interval
                .unwrap_or(nos_proto::DEAD_INTERVAL_DEFAULT);
            let priority = profile.priority.unwrap_or(nos_proto::PRIORITY_DEFAULT);
            let auth = resolve_auth(profile);

            for attach in subinterface_attach_points(&cfg, &profile.name) {
                let link_name = attach.display_name();
                let Some(routing_table) = &attach.routing_table else {
                    // Can't happen in practice —
                    // `valid_subinterface_ospf_profile_requires_routing_table`
                    // already enforces this at commit time — but the field
                    // is still `Option` on the wire.
                    warn!(
                        instance = %instance, link = %link_name,
                        "ospf profile attached to a subinterface with no routing-table, skipping"
                    );
                    continue;
                };
                let Some(vrf) = resolve_vrf(watchdog_socket, routing_table).await else {
                    warn!(instance = %instance, link = %link_name, "ospf link's vrf not resolvable yet");
                    continue;
                };
                let Some((local_addr, local_prefix_len, resolved_mtu)) =
                    resolve_local_address(watchdog_socket, &attach.interface, attach.tag).await
                else {
                    warn!(instance = %instance, link = %link_name, "ospf link's local address not resolvable yet");
                    continue;
                };
                desired_links.push(LinkConfig {
                    attach_point: link_name,
                    area_id: area.area_id,
                    hello_interval,
                    dead_interval,
                    vrf,
                    local_addr,
                    local_prefix_len,
                    cost: profile.cost.unwrap_or(1),
                    kernel_interface: subinterface_kernel_interface(&attach.interface, attach.tag),
                    network_type: profile.network_type.unwrap_or(NetworkType::PointToPoint),
                    priority,
                    mtu: resolve_effective_mtu(profile, Some(resolved_mtu)),
                    mtu_ignore: profile.mtu_ignore,
                    auth: auth.clone(),
                    stub: area.area_type.is_stub(),
                    nssa: area.area_type.is_nssa(),
                });
            }

            for attach in loopback_attach_points(&cfg, &profile.name) {
                let Some((addr, prefix_len)) =
                    resolve_loopback_prefix(watchdog_socket, &attach.interface).await
                else {
                    warn!(
                        instance = %instance, interface = %attach.interface,
                        "ospf loopback stub network not resolvable yet"
                    );
                    continue;
                };
                if let Ok(subnet) = Ipv4Net::new(addr, prefix_len) {
                    desired_stubs
                        .entry(area.area_id)
                        .or_default()
                        .push((subnet, profile.cost.unwrap_or(1)));
                }
            }

            for attach in broadcast_domain_attach_points(&cfg, &profile.name) {
                let link_name = attach.display_name();
                let Some(routing_table) = &attach.routing_table else {
                    // Can't happen in practice —
                    // `broadcast_domain::valid_broadcast_domains` already
                    // enforces this at commit time — but the field is
                    // still `Option` on the wire.
                    warn!(
                        instance = %instance, link = %link_name,
                        "ospf profile attached to a broadcast domain with no routing-table, skipping"
                    );
                    continue;
                };
                let Some(vrf) = resolve_vrf(watchdog_socket, routing_table).await else {
                    warn!(instance = %instance, link = %link_name, "ospf link's vrf not resolvable yet");
                    continue;
                };
                let Some((local_addr, local_prefix_len, kernel_interface)) =
                    resolve_broadcast_domain(watchdog_socket, &attach.name).await
                else {
                    warn!(instance = %instance, link = %link_name, "ospf link's local address/bridge not resolvable yet");
                    continue;
                };
                desired_links.push(LinkConfig {
                    attach_point: link_name,
                    area_id: area.area_id,
                    hello_interval,
                    dead_interval,
                    vrf,
                    local_addr,
                    local_prefix_len,
                    cost: profile.cost.unwrap_or(1),
                    kernel_interface,
                    network_type: profile.network_type.unwrap_or(NetworkType::Broadcast),
                    priority,
                    mtu: resolve_effective_mtu(profile, None),
                    mtu_ignore: profile.mtu_ignore,
                    auth: auth.clone(),
                    stub: area.area_type.is_stub(),
                    nssa: area.area_type.is_nssa(),
                });
            }
        }
    }

    let redistribute_policy = resolve_redistribute_policy(&cfg, own.redistribute_policy.as_deref());
    links.set_redistribute_policy(redistribute_policy).await;
    links
        .set_redistribute_metric(own.redistribute_metric, own.redistribute_metric_type)
        .await;

    links
        .reconcile(desired_links, desired_stubs, own.router_id)
        .await;
}

/// Each area's RFC 2328 §3.5/§3.6 and RFC 3101 settings, for `LinkManager`'s
/// summary/external origination and discard routes.
fn area_settings(areas: &[nos_proto::OspfArea]) -> HashMap<Ipv4Addr, AreaSettings> {
    areas
        .iter()
        .map(|a| {
            let settings = AreaSettings {
                stub: a.area_type.is_stub(),
                nssa: a.area_type.is_nssa(),
                import_summaries: a.area_type.import_summaries(),
                nssa_translate_always: a.nssa_translate_always,
                nssa_default_originate: a.nssa_default_originate,
                default_cost: u32::from(a.stub_default_cost.unwrap_or(1)),
                ranges: a
                    .ranges
                    .iter()
                    .map(|r| (r.cidr, !r.not_advertise))
                    .collect(),
            };
            (a.area_id, settings)
        })
        .collect()
}

/// Resolves the mirrored `OspfInstance.redistribute_policy` field to a
/// compiled policy. Unlike `bgp::policy::PolicyCache` (which caches many
/// policies for many peer-groups), `OspfInstance.redistribute_policy` is
/// exactly one policy per instance — compiling fresh every resync tick (the
/// same cadence every other resolution in this function already runs at)
/// needs no cache-invalidation logic; add a cache only if profiling ever
/// shows this compile step matters.
///
/// `None` resolves to `accept-all`, matching `bgp::reconcile::resync`'s own
/// precedent — redistribution is already opt-in via the `Redistribute`
/// rule's existence, unlike peer import/export policy's deny-all default.
///
/// `ponytail:` this duplicates `bgp::policy::PolicyCache::resync`'s
/// `Symbols`-building logic rather than sharing it — expected, not an
/// oversight, per the star-dependency rule (components share only
/// `nos-proto`, never each other's code).
fn resolve_redistribute_policy(
    cfg: &nos_proto::Config,
    redistribute_policy_name: Option<&str>,
) -> Arc<CompiledPolicy> {
    let Some(name) = redistribute_policy_name else {
        return Arc::new(nos_rpl::ACCEPT_ALL.clone());
    };
    if name == nos_rpl::ACCEPT_ALL_NAME {
        return Arc::new(nos_rpl::ACCEPT_ALL.clone());
    }
    if name == nos_rpl::DENY_ALL_NAME {
        return Arc::new(nos_rpl::DENY_ALL.clone());
    }
    let Some(def) = cfg.policy_definitions.iter().find(|p| p.name == name) else {
        // Can't happen in practice — commit-time validation already
        // guarantees this reference exists — but the field is still a plain
        // `Option<String>` on the wire.
        return Arc::new(nos_rpl::DENY_ALL.clone());
    };

    let alias_parts: Vec<(&str, Vec<i64>)> = cfg
        .community_aliases
        .iter()
        .filter_map(|a| {
            nos_rpl::parse_colon_literal(&a.value).map(|parts| (a.name.as_str(), parts))
        })
        .collect();
    let alias_refs: Vec<(&str, &[i64])> = alias_parts
        .iter()
        .map(|(n, p)| (*n, p.as_slice()))
        .collect();

    let resolve_member = |m: &str| -> Option<Vec<i64>> {
        cfg.community_aliases
            .iter()
            .find(|a| a.name == m)
            .and_then(|a| nos_rpl::parse_colon_literal(&a.value))
            .or_else(|| nos_rpl::parse_colon_literal(m))
    };
    let group_parts: Vec<(&str, Vec<Vec<i64>>)> = cfg
        .community_groups
        .iter()
        .map(|g| {
            (
                g.name.as_str(),
                g.members.iter().filter_map(|m| resolve_member(m)).collect(),
            )
        })
        .collect();
    let group_member_slices: Vec<Vec<&[i64]>> = group_parts
        .iter()
        .map(|(_, members)| members.iter().map(Vec::as_slice).collect())
        .collect();
    let group_refs: Vec<(&str, &[&[i64]])> = group_parts
        .iter()
        .zip(&group_member_slices)
        .map(|((name, _), slices)| (*name, slices.as_slice()))
        .collect();

    let prefix_list_entries: Vec<(&str, Vec<nos_rpl::PrefixListEntry>)> = cfg
        .prefix_lists
        .iter()
        .map(|pl| {
            let entries = pl
                .entries
                .iter()
                .map(|e| nos_rpl::PrefixListEntry {
                    cidr: e.cidr,
                    range: e.range,
                })
                .collect();
            (pl.name.as_str(), entries)
        })
        .collect();
    let prefix_list_refs: Vec<(&str, &[nos_rpl::PrefixListEntry])> = prefix_list_entries
        .iter()
        .map(|(n, e)| (*n, e.as_slice()))
        .collect();

    let as_path_lists: Vec<(&str, Vec<&str>)> = cfg
        .as_path_lists
        .iter()
        .map(|l| {
            (
                l.name.as_str(),
                l.patterns.iter().map(String::as_str).collect(),
            )
        })
        .collect();
    let as_path_list_refs: Vec<(&str, &[&str])> = as_path_lists
        .iter()
        .map(|(n, p)| (*n, p.as_slice()))
        .collect();

    let symbols = nos_rpl::Symbols {
        aliases: &alias_refs,
        groups: &group_refs,
        prefix_lists: &prefix_list_refs,
        as_path_lists: &as_path_list_refs,
    };

    match nos_rpl::compile(&def.source, &symbols) {
        Ok(compiled) => Arc::new(compiled),
        Err(_) => Arc::new(nos_rpl::DENY_ALL.clone()), // unreachable post-commit-validation
    }
}

/// Every L3 attach point (loopback interface name, `<interface>.<tag>`
/// subinterface, or `broadcast-domain:<name>`) currently referencing
/// `profile` by name, across the whole running config. Purely a display
/// helper for the log line above — `cfg` already carries every interface
/// and broadcast domain from the same `fetch_config` call, so no extra IPC
/// round trip is needed to resolve it.
fn attach_points_for(cfg: &nos_proto::Config, profile: &str) -> Vec<String> {
    let mut points = Vec::new();
    for iface in &cfg.interfaces {
        if iface.ospf_profile.as_deref() == Some(profile) {
            points.push(iface.name.clone());
        }
        for sub in &iface.subinterfaces {
            if sub.ospf_profile.as_deref() == Some(profile) {
                points.push(format!("{}.{}", iface.name, sub.tag));
            }
        }
    }
    for domain in &cfg.broadcast_domains {
        if domain.ospf_profile.as_deref() == Some(profile) {
            points.push(format!("broadcast-domain:{}", domain.name));
        }
    }
    points
}

/// One `Subinterface.ospf_profile` attach point, with enough structure to
/// resolve and build a `LinkConfig`. Point-to-point only this phase (see
/// `ospf/CLAUDE.md`) — loopback and `BroadcastDomain` attach points stay
/// log-only, handled entirely by `attach_points_for` above.
struct SubinterfaceAttachPoint {
    interface: String,
    tag: u16,
    routing_table: Option<String>,
}

impl SubinterfaceAttachPoint {
    /// Matches `attach_points_for`'s existing `"<interface>.<tag>"`
    /// convention.
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
            if sub.ospf_profile.as_deref() == Some(profile) {
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

/// One `BroadcastDomain.ospf_profile` attach point, with enough structure to
/// resolve and build a `LinkConfig`.
struct BroadcastDomainAttachPoint {
    name: String,
    routing_table: Option<String>,
}

impl BroadcastDomainAttachPoint {
    /// Matches `attach_points_for`'s existing `"broadcast-domain:<name>"`
    /// convention.
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
        .filter(|d| d.ospf_profile.as_deref() == Some(profile))
        .map(|d| BroadcastDomainAttachPoint {
            name: d.name.clone(),
            routing_table: d.routing_table.clone(),
        })
        .collect()
}

/// One loopback (`Interface.ospf_profile`) attach point — unlike a
/// `Subinterface`/`BroadcastDomain` attach point, this carries no
/// `routing_table` of its own to resolve a VRF from (a loopback's `Interface.
/// routing_table` field only matters for the L3 driver, not OSPF, which just
/// needs the interface's own subnet — see `loopback_attach_points`).
struct LoopbackAttachPoint {
    interface: String,
}

/// Every `Interface.ospf_profile` attach point (a loopback, per
/// `nos_proto::loopback_table_name`) referencing `profile` — these have no
/// live link/socket (see `ospf/CLAUDE.md`'s "log-only" note), just a
/// stub-network subnet for `LinkManager::stub_networks`.
fn loopback_attach_points(cfg: &nos_proto::Config, profile: &str) -> Vec<LoopbackAttachPoint> {
    cfg.interfaces
        .iter()
        .filter(|i| {
            nos_proto::loopback_table_name(&i.name).is_some()
                && i.ospf_profile.as_deref() == Some(profile)
        })
        .map(|i| LoopbackAttachPoint {
            interface: i.name.clone(),
        })
        .collect()
}

/// Resolves `table`'s Linux VRF interface name by asking the owning
/// `nos-ribd` instance directly over IPC (see `crate::rib_client`),
/// resolved via the watchdog broker — never derived locally. `None` covers
/// every "not answerable yet" case uniformly (broker doesn't know that
/// table, connect failure, rib hasn't created a VRF yet), retried by the
/// caller's periodic re-apply tick. Mirrors `nos-bgp`'s own
/// `reconcile::resolve_vrf`.
async fn resolve_vrf(watchdog_socket: &Path, table: &str) -> Option<String> {
    let socket =
        watchdog_client::resolve_once(watchdog_socket, &ServiceRef::RibTable(table.to_string()))
            .await?;
    rib_client::get_vrf_name(&socket).await
}

/// Resolves a subinterface's tag-0-or-tagged local IPv4 address, its real
/// subnet prefix length, and its parent interface's real MTU, by asking
/// `nos-interfaced` directly (resolved via the watchdog broker's
/// `ServiceRef::Interfaces`, mirroring `resolve_vrf`'s `ServiceRef::RibTable`
/// and `nos-ribd` query). The prefix length feeds
/// `link::LinkConfig::local_prefix_len`, needed to originate a real
/// stub-network Router-LSA link for this subnet (see `crate::spf`); the MTU
/// feeds `LinkConfig::mtu` (see `resolve_effective_mtu`) — MTU is a
/// physical-interface-level property (`InterfaceStatus.mtu`), not a
/// per-subinterface one, so it's read from the same already-fetched
/// `InterfaceStatus` rather than a separate query. `None` covers every "not
/// resolvable right now" case uniformly, retried by the caller's periodic
/// re-apply tick.
async fn resolve_local_address(
    watchdog_socket: &Path,
    interface: &str,
    tag: u16,
) -> Option<(Ipv4Addr, u8, u32)> {
    let socket = watchdog_client::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
    let status = interface_client::get_interface(&socket, interface).await?;
    let mtu = status.mtu;
    let sub = status.subinterfaces.into_iter().find(|s| s.tag == tag)?;
    let net = sub.addresses.into_iter().next()?.address;
    match net.addr() {
        std::net::IpAddr::V4(v4) => Some((v4, net.prefix_len(), mtu)),
        std::net::IpAddr::V6(_) => None,
    }
}

/// Linux's own default MTU, used as the ultimate fallback when neither an
/// `OspfProfile.mtu` override nor a real resolved interface MTU is
/// available (a broadcast-domain bridge attach point, which has no
/// per-domain MTU of its own — see root `CLAUDE.md`'s scope note on this).
const DEFAULT_OSPF_MTU: u16 = 1500;

/// Resolves the effective MTU OSPF uses for a link — for the wire's
/// `DbdPacket.interface_mtu` field and DBD pagination sizing (see
/// `ospf/CLAUDE.md`'s "Exchange" section) — as `profile.mtu` if set, else
/// `resolved_mtu` (the link's real interface MTU, when one exists), else
/// `DEFAULT_OSPF_MTU`.
fn resolve_effective_mtu(profile: &nos_proto::OspfProfile, resolved_mtu: Option<u32>) -> u16 {
    profile.mtu.unwrap_or_else(|| {
        resolved_mtu
            .and_then(|m| u16::try_from(m).ok())
            .unwrap_or(DEFAULT_OSPF_MTU)
    })
}

/// Resolves a loopback (`Interface.ospf_profile`) attach point's own
/// address *and* prefix length the same way `resolve_local_address` does,
/// but reading `InterfaceStatus.addresses` directly (a loopback's L3 config
/// is flat, no subinterface lookup) — feeds `LinkManager`'s `stub_networks`
/// map, since a loopback has no live link/socket of its own to carry this
/// through `LinkConfig` (see `ospf/CLAUDE.md`'s "log-only" loopback note).
async fn resolve_loopback_prefix(
    watchdog_socket: &Path,
    interface: &str,
) -> Option<(Ipv4Addr, u8)> {
    let socket = watchdog_client::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
    let status = interface_client::get_interface(&socket, interface).await?;
    let net = status.addresses.into_iter().next()?.address;
    match net.addr() {
        std::net::IpAddr::V4(v4) => Some((v4, net.prefix_len())),
        std::net::IpAddr::V6(_) => None,
    }
}

/// Resolves a broadcast domain's own SVI local IPv4 address *and* its real
/// kernel bridge device name (`nos-ospfd`'s socket binds to the bridge
/// itself — the L3 attach point for this domain — never the shared VRF
/// device; see `link::LinkConfig::kernel_interface`'s doc comment) from one
/// `GetBroadcastDomain` query, asking `nos-interfaced` directly the same
/// way `resolve_local_address` does. `None` covers every "not resolvable
/// right now" case uniformly (including the bridge not created yet),
/// retried by the caller's periodic re-apply tick.
async fn resolve_broadcast_domain(
    watchdog_socket: &Path,
    domain: &str,
) -> Option<(Ipv4Addr, u8, String)> {
    let socket = watchdog_client::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
    let status = interface_client::get_broadcast_domain(&socket, domain).await?;
    let bridge_name = status.bridge_name?;
    let net = status.addresses.into_iter().next()?.address;
    match net.addr() {
        std::net::IpAddr::V4(v4) => Some((v4, net.prefix_len(), bridge_name)),
        std::net::IpAddr::V6(_) => None,
    }
}

/// A `Subinterface` attach point's real kernel device name — the untagged
/// case shares the physical link itself; a real VLAN tag gets its own
/// `<interface>.<tag>` sub-interface (see root `CLAUDE.md`'s "L2 switching"
/// section). Pure — no IPC needed, since this is exactly the naming
/// convention `nos-interfaced`'s own driver already uses.
fn subinterface_kernel_interface(interface: &str, tag: u16) -> String {
    if tag == 0 {
        interface.to_string()
    } else {
        format!("{interface}.{tag}")
    }
}

/// Translates `OspfProfile.auth` into `link::LinkAuthConfig` — pure, no I/O,
/// since `auth` is already fully present in the fetched `Config`.
/// `current_key_id` is safe to pull from whichever key has `is_current` set
/// without a fallback: `OspfProfile`'s own commit-time validation
/// (`schema::ospf_profile::valid_auth`) already guarantees exactly one does
/// whenever `auth` is `Crypto`.
fn resolve_auth(profile: &nos_proto::OspfProfile) -> LinkAuthConfig {
    match &profile.auth {
        None => LinkAuthConfig::None,
        Some(OspfAuth::Simple { password }) => LinkAuthConfig::Simple {
            password: password.clone().into_bytes(),
        },
        Some(OspfAuth::Crypto { keys }) => {
            let current_key_id = keys.iter().find(|k| k.is_current).map_or(0, |k| k.key_id);
            LinkAuthConfig::Crypto {
                keys: keys
                    .iter()
                    .map(|k| {
                        (
                            k.key_id,
                            resolve_algorithm(k.algorithm),
                            k.key.clone().into_bytes(),
                        )
                    })
                    .collect(),
                current_key_id,
                extended: profile.extended_sequence_numbers,
            }
        }
    }
}

fn resolve_algorithm(algorithm: OspfCryptoAlgorithm) -> packet::CryptoAlgorithm {
    match algorithm {
        OspfCryptoAlgorithm::Md5 => packet::CryptoAlgorithm::Md5,
        OspfCryptoAlgorithm::HmacSha1 => packet::CryptoAlgorithm::HmacSha1,
        OspfCryptoAlgorithm::HmacSha256 => packet::CryptoAlgorithm::HmacSha256,
        OspfCryptoAlgorithm::HmacSha384 => packet::CryptoAlgorithm::HmacSha384,
        OspfCryptoAlgorithm::HmacSha512 => packet::CryptoAlgorithm::HmacSha512,
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

    fn interface(name: &str, ospf_profile: Option<&str>) -> Interface {
        Interface {
            ospfv3_profile: None,
            name: name.to_string(),
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: ospf_profile.map(str::to_string),
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
            ospfv3_profile: None,
            tag: 100,
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: Some("p1".to_string()),
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
                ospfv3_profile: None,
                vni: None,
                rd: None,
                route_targets_import: Vec::new(),
                route_targets_export: Vec::new(),
                vtep_source: None,
                mac_redistribute: None,
                arp_redistribute: None,
                connected_redistribute: None,
                neigh_suppress: false,
                name: "bd1".to_string(),
                addresses: Vec::new(),
                routing_table: None,
                ospf_profile: Some("p1".to_string()),
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
        assert_eq!(attach_points_for(&cfg, "p1"), [] as [String; 0]);
    }

    #[test]
    fn subinterface_attach_points_finds_routing_table() {
        let mut iface = interface("eth0", None);
        iface.subinterfaces = vec![Subinterface {
            ospfv3_profile: None,
            tag: 0,
            addresses: Vec::new(),
            routing_table: Some("rt1".to_string()),
            ospf_profile: Some("p1".to_string()),
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
    fn subinterface_attach_points_ignores_loopback_and_broadcast_domain() {
        let cfg = Config {
            interfaces: vec![interface("loopback-rt1", Some("p1"))],
            broadcast_domains: vec![BroadcastDomain {
                ospfv3_profile: None,
                vni: None,
                rd: None,
                route_targets_import: Vec::new(),
                route_targets_export: Vec::new(),
                vtep_source: None,
                mac_redistribute: None,
                arp_redistribute: None,
                connected_redistribute: None,
                neigh_suppress: false,
                name: "bd1".to_string(),
                addresses: Vec::new(),
                routing_table: None,
                ospf_profile: Some("p1".to_string()),
            }],
            ..Default::default()
        };
        assert!(subinterface_attach_points(&cfg, "p1").is_empty());
    }

    #[test]
    fn broadcast_domain_attach_points_finds_routing_table() {
        let cfg = Config {
            broadcast_domains: vec![BroadcastDomain {
                ospfv3_profile: None,
                vni: None,
                rd: None,
                route_targets_import: Vec::new(),
                route_targets_export: Vec::new(),
                vtep_source: None,
                mac_redistribute: None,
                arp_redistribute: None,
                connected_redistribute: None,
                neigh_suppress: false,
                name: "bd1".to_string(),
                addresses: Vec::new(),
                routing_table: Some("rt1".to_string()),
                ospf_profile: Some("p1".to_string()),
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

    #[test]
    fn loopback_attach_points_ignores_subinterface_and_broadcast_domain() {
        let mut iface = interface("eth0", None);
        iface.subinterfaces = vec![Subinterface {
            ospfv3_profile: None,
            tag: 0,
            addresses: Vec::new(),
            routing_table: Some("rt1".to_string()),
            ospf_profile: Some("p1".to_string()),
        }];
        let cfg = Config {
            interfaces: vec![iface],
            broadcast_domains: vec![BroadcastDomain {
                ospfv3_profile: None,
                vni: None,
                rd: None,
                route_targets_import: Vec::new(),
                route_targets_export: Vec::new(),
                vtep_source: None,
                mac_redistribute: None,
                arp_redistribute: None,
                connected_redistribute: None,
                neigh_suppress: false,
                name: "bd1".to_string(),
                addresses: Vec::new(),
                routing_table: None,
                ospf_profile: Some("p1".to_string()),
            }],
            ..Default::default()
        };
        assert!(loopback_attach_points(&cfg, "p1").is_empty());
    }

    #[test]
    fn broadcast_domain_attach_points_ignores_loopback_and_subinterface() {
        let mut iface = interface("eth0", None);
        iface.subinterfaces = vec![Subinterface {
            ospfv3_profile: None,
            tag: 0,
            addresses: Vec::new(),
            routing_table: Some("rt1".to_string()),
            ospf_profile: Some("p1".to_string()),
        }];
        let cfg = Config {
            interfaces: vec![interface("loopback-rt1", Some("p1")), iface],
            ..Default::default()
        };
        assert!(broadcast_domain_attach_points(&cfg, "p1").is_empty());
    }
}
