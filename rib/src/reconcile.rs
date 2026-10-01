use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use nos_proto::{
    BroadcastDomainStatus, Config, DiffScope, Event, InterfaceStatus, IpNet, PortAggregateStatus,
    Redistribute, RedistributeSource, RedistributeTarget, RedistributedRoute, ServiceRef,
};
use tokio::sync::{watch, RwLock};
use tokio::time::sleep;
use tracing::{debug, error, info, trace, warn};

use crate::bgp_client;
use crate::config_client;
use crate::driver::RibDriver;
use crate::interface_client;
use crate::ospf_client;
use crate::rib::{build_from_config, Rib, RibEntry, RouteSource};
use crate::watchdog_client;

/// Fixed reconnect delay for the config subscription, matching
/// `nos-watchdog`'s `bgp_instances::RECONNECT_DELAY` for consistency across
/// the codebase's config-subscribing consumers.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// How often to re-apply the current `Rib` to the driver even without a new
/// config diff. Needed for two reasons: a driver's kernel state can drift
/// out of band (an operator or another process editing routes/the VRF
/// directly), and — the motivating case — the VRF device this table's
/// routes are installed into may not exist yet if `nos-interfaced` races
/// this daemon's own VRF creation on startup; nothing about *our* config
/// changes when that happens, so nothing else would ever retry it.
const REAPPLY_INTERVAL: Duration = Duration::from_secs(10);

/// Runs until `shutdown` fires. Subscribes to `RoutingTables` and
/// `StaticRoutingInstances` diffs purely as an edge trigger: every
/// `Event::Diff` received (including the first, synthesized one) causes a
/// full `resync` — a fresh `Request::Get` plus a from-scratch rebuild of
/// this table's `Static` candidates (via `Rib::replace_source`, leaving any
/// `Bgp`-sourced candidates pushed by `crate::server::apply_bgp_route_update`
/// untouched) — rather than incremental diff application, since
/// `SectionDiff`/`FieldDiff` only carry pre-formatted display strings, not
/// structured route data (see `nos_proto::diff::routing_table`/`static_routing_instance`).
/// The `Connected` candidates are rebuilt the same way, from what
/// `nos-interfaced` (resolved through `watchdog_socket`) reports it applied
/// — so a new address is visible to `show route` and to `nos-bgpd`'s
/// next-hop check within one `REAPPLY_INTERVAL` at worst.
///
/// On exit, tears down this table's kernel VRF/routes via `driver` (see
/// `RibDriver::teardown`) — the same SIGINT `nos-watchdog` sends both for
/// "shutting down" and "this table was removed from config" (root
/// `CLAUDE.md`), so this runs on every ordinary restart too, not only a
/// real removal. That's an accepted tradeoff: the driver's persisted
/// table-id registry (see `driver::table_registry`) is untouched by
/// `teardown`, so the next `apply` recreates the exact same VRF name.
#[allow(clippy::too_many_arguments)] // one socket/channel per collaborator, wired once by main.rs
pub async fn run(
    config_socket: PathBuf,
    watchdog_socket: PathBuf,
    table: String,
    rib: Arc<RwLock<Rib>>,
    driver: Arc<dyn RibDriver>,
    redistribute_tx: watch::Sender<bgp_client::RedistributeTarget>,
    ospf_redistribute_tx: watch::Sender<ospf_client::RedistributeTarget>,
    mut shutdown: watch::Receiver<bool>,
) {
    while !*shutdown.borrow() {
        match config_client::subscribe_diff(
            &config_socket,
            vec![DiffScope::RoutingTables, DiffScope::StaticRoutingInstances],
        )
        .await
        {
            Ok(mut reader) => {
                info!(table = %table, "connected to nos-configd diff stream");
                let mut reapply = tokio::time::interval(REAPPLY_INTERVAL);
                reapply.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                reapply.tick().await; // consume the immediate first tick — the
                                      // diff stream's own synthesized first
                                      // Event::Diff already resyncs
                loop {
                    tokio::select! {
                        event = reader.next() => match event {
                            Some(Ok(Event::Diff(_))) => {
                                resync(&config_socket, &watchdog_socket, &table, &rib, driver.as_ref(), &redistribute_tx, &ospf_redistribute_tx).await;
                            }
                            Some(Ok(_)) => {}
                            Some(Err(e)) => {
                                warn!(table = %table, error = %e, "error reading diff stream, reconnecting");
                                break;
                            }
                            None => {
                                warn!(table = %table, "diff stream closed, reconnecting");
                                break;
                            }
                        },
                        _ = reapply.tick() => {
                            resync(&config_socket, &watchdog_socket, &table, &rib, driver.as_ref(), &redistribute_tx, &ospf_redistribute_tx).await;
                        }
                        _ = shutdown.changed() => break,
                    }
                }
            }
            Err(e) => warn!(
                table = %table,
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

    match driver.teardown(&table).await {
        Ok(()) => debug!(table = %table, "tore down VRF/table on shutdown"),
        Err(e) => warn!(table = %table, error = %e, "failed to tear down VRF on shutdown"),
    }
    info!(table = %table, "reconciliation loop stopped");
}

async fn resync(
    config_socket: &Path,
    watchdog_socket: &Path,
    table: &str,
    rib: &Arc<RwLock<Rib>>,
    driver: &dyn RibDriver,
    redistribute_tx: &watch::Sender<bgp_client::RedistributeTarget>,
    ospf_redistribute_tx: &watch::Sender<ospf_client::RedistributeTarget>,
) {
    match config_client::fetch_config(config_socket).await {
        Ok(cfg) => {
            let static_entries = if let Some(new_rib) = build_from_config(&cfg, table) {
                new_rib
                    .all_routes()
                    .into_iter()
                    .flat_map(|(_, candidates)| candidates)
                    .collect::<Vec<_>>()
            } else {
                warn!(
                    table = %table,
                    "routing table not found in running config; static routes cleared until it reappears"
                );
                Vec::new()
            };
            let connected = fetch_connected(watchdog_socket, &cfg, table).await;

            let mut guard = rib.write().await;
            guard.replace_source(RouteSource::Static, static_entries);
            match connected {
                Some(entries) => {
                    debug!(table = %table, connected = entries.len(), "resolved connected prefixes");
                    guard.replace_source(RouteSource::Connected, entries);
                }
                // Same "keep the last good set on a transient failure" rule
                // as nos-bgpd's `igp_client`.
                None => {
                    debug!(table = %table, "nos-interfaced unreachable, keeping previous connected prefixes");
                }
            }
            let routes = guard.best_routes_for_kernel();
            drop(guard);

            debug!(table = %table, prefixes = routes.len(), "recomputed RIB");
            for (prefix, entry) in &routes {
                trace!(
                    table = %table,
                    %prefix,
                    next_hops = ?entry.next_hops,
                    source = ?entry.source,
                    "best route"
                );
            }
            if let Err(e) = driver.apply(table, &routes).await {
                error!(table = %table, error = %e, "failed to apply routes to kernel");
            }
            let _ = redistribute_tx.send(compute_redistribute_target(&cfg, table, &routes));
            let _ =
                ospf_redistribute_tx.send(compute_redistribute_target_ospf(&cfg, table, &routes));
        }
        Err(e) => {
            warn!(table = %table, error = %e, "failed to fetch running config, keeping previous RIB");
        }
    }
}

/// Asks `nos-interfaced` (resolved via the broker, `ServiceRef::Interfaces`)
/// for every interface, plus each `cfg.broadcast_domains` entry in `table`
/// with an SVI address (one `GetBroadcastDomain` each — there is no "list
/// every domain" request, the same per-name lookup `nos-fdbd` does), and
/// derives this table's `Connected` candidates. `None` if any call failed.
async fn fetch_connected(
    watchdog_socket: &Path,
    cfg: &Config,
    table: &str,
) -> Option<Vec<RibEntry>> {
    let socket = watchdog_client::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
    let interfaces = interface_client::get_interfaces(&socket).await?;
    let aggregates = if cfg.port_aggregates.iter().any(|a| {
        a.subinterfaces
            .iter()
            .any(|s| s.routing_table.as_deref() == Some(table))
    }) {
        interface_client::get_port_aggregates(&socket).await?
    } else {
        Vec::new()
    };
    let mut domains = Vec::new();
    for d in &cfg.broadcast_domains {
        if d.routing_table.as_deref() == Some(table) && !d.addresses.is_empty() {
            domains.push(interface_client::get_broadcast_domain(&socket, &d.name).await?);
        }
    }
    Some(connected_entries(table, &interfaces, &aggregates, &domains))
}

/// The `Connected` candidates of `table`: the network of every address on an
/// interface (a loopback's flat `addresses`, or any `Subinterface`'s per
/// tag), port aggregate subinterface or broadcast-domain SVI whose
/// `routing_table` is `table`. The entry's
/// `gateway` is the local address itself — display only, never installed
/// (see `RouteSource::Connected`). A prefix addressed twice keeps the first
/// address seen. Pure, so it's unit-tested without IPC.
fn connected_entries(
    table: &str,
    interfaces: &[InterfaceStatus],
    aggregates: &[PortAggregateStatus],
    domains: &[BroadcastDomainStatus],
) -> Vec<RibEntry> {
    let in_table = |rt: &Option<String>| rt.as_deref() == Some(table);
    let mut entries: Vec<RibEntry> = Vec::new();
    let addressed = interfaces
        .iter()
        .flat_map(|i| {
            std::iter::once((&i.routing_table, &i.addresses)).chain(
                i.subinterfaces
                    .iter()
                    .map(|s| (&s.routing_table, &s.addresses)),
            )
        })
        .chain(
            aggregates
                .iter()
                .flat_map(|a| &a.subinterfaces)
                .map(|s| (&s.routing_table, &s.addresses)),
        )
        .chain(domains.iter().map(|d| (&d.routing_table, &d.addresses)))
        .filter(|(rt, _)| in_table(rt))
        .flat_map(|(_, addresses)| addresses.iter().map(|a| a.address));
    for address in addressed {
        let prefix = address.trunc();
        if entries.iter().any(|e| e.prefix == prefix) {
            continue;
        }
        entries.push(RibEntry {
            prefix,
            next_hops: vec![(address.addr(), None)],
            source: RouteSource::Connected,
            backup: None,
            backup_interface_id: None,
        });
    }
    entries
}

/// Computes the `bgp_client::RedistributeTarget` to publish for `table`,
/// given the just-fetched `cfg` and this resync's freshly recomputed best
/// routes (`new_rib.best_routes()`). Pure and unit-tested directly.
///
/// Redistribution forwards every `RouteSource::Static` entry, v4 and v6
/// alike (nos-bgp negotiates MP-BGP per peer independently), only when
/// `table.redistribute` is exactly `Some(Redistribute{from: Static, to:
/// Bgp})`, the one rule this config schema supports today.
fn compute_redistribute_target(
    cfg: &Config,
    table_name: &str,
    routes: &HashMap<IpNet, RibEntry>,
) -> bgp_client::RedistributeTarget {
    let Some(table) = cfg.routing_tables.iter().find(|t| t.name == table_name) else {
        return bgp_client::RedistributeTarget::default();
    };

    let active_rule = matches!(
        &table.redistribute,
        Some(Redistribute {
            from: RedistributeSource::Static,
            to: RedistributeTarget::Bgp,
            ..
        })
    );

    let redistributed = if active_rule {
        routes
            .values()
            .filter(|entry| entry.source == RouteSource::Static)
            .map(|entry| RedistributedRoute {
                prefix: entry.prefix,
                gateway: entry.next_hops[0].0,
            })
            .collect()
    } else {
        Vec::new()
    };

    bgp_client::RedistributeTarget {
        bgp_instance: table.bgp_instance.clone(),
        routes: redistributed,
    }
}

/// The OSPF-redistribution analogue of `compute_redistribute_target` — same
/// shape, matching `to: Ospf` instead of `to: Bgp` and populating
/// `ospf_client::RedistributeTarget`. Kept as a separate function rather
/// than generalizing over the target/instance-field pair: there are only two
/// call sites, and the field name differs per target struct
/// (`bgp_instance` vs. `ospf_instance`), so a generic parameter isn't worth
/// it yet.
fn compute_redistribute_target_ospf(
    cfg: &Config,
    table_name: &str,
    routes: &HashMap<IpNet, RibEntry>,
) -> ospf_client::RedistributeTarget {
    let Some(table) = cfg.routing_tables.iter().find(|t| t.name == table_name) else {
        return ospf_client::RedistributeTarget::default();
    };

    let active_rule = matches!(
        &table.redistribute,
        Some(Redistribute {
            from: RedistributeSource::Static,
            to: RedistributeTarget::Ospf,
            ..
        })
    );

    let redistributed = if active_rule {
        routes
            .values()
            .filter(|entry| entry.source == RouteSource::Static)
            .map(|entry| RedistributedRoute {
                prefix: entry.prefix,
                gateway: entry.next_hops[0].0,
            })
            .collect()
    } else {
        Vec::new()
    };

    ospf_client::RedistributeTarget {
        ospf_instance: table.ospf_instance.clone(),
        routes: redistributed,
    }
}

/// Local copy of `nos-watchdog::supervisor::wait_or_shutdown` — not
/// imported, per the star-dependency rule.
async fn wait_or_shutdown(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = sleep(delay) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use nos_proto::RoutingTable;

    fn cfg_with_table(table: RoutingTable) -> Config {
        Config {
            routing_tables: vec![table],
            ..Default::default()
        }
    }

    fn static_entry(prefix: &str, gateway: &str) -> RibEntry {
        RibEntry {
            prefix: prefix.parse().unwrap(),
            next_hops: vec![(gateway.parse().unwrap(), None)],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
        }
    }

    fn addrs(list: &[&str]) -> Vec<nos_proto::InterfaceAddress> {
        list.iter()
            .map(|a| nos_proto::InterfaceAddress {
                address: a.parse().unwrap(),
                label: None,
            })
            .collect()
    }

    fn iface(
        name: &str,
        flat: (&[&str], Option<&str>),
        subs: &[(u16, &[&str], Option<&str>)],
    ) -> InterfaceStatus {
        InterfaceStatus {
            name: name.into(),
            addresses: addrs(flat.0),
            routing_table: flat.1.map(String::from),
            switching_profile: None,
            port_aggregate: None,
            mtu: 1500,
            subinterfaces: subs
                .iter()
                .map(|(tag, a, rt)| nos_proto::SubinterfaceStatus {
                    tag: *tag,
                    addresses: addrs(a),
                    routing_table: rt.map(String::from),
                    link_local_address: None,
                })
                .collect(),
            link_local_address: None,
        }
    }

    fn domain(name: &str, a: &[&str], rt: Option<&str>) -> BroadcastDomainStatus {
        BroadcastDomainStatus {
            name: name.into(),
            addresses: addrs(a),
            routing_table: rt.map(String::from),
            link_local_address: None,
            bridge_name: None,
        }
    }

    #[test]
    fn connected_entries_cover_loopback_subinterface_bond_and_svi_addresses_of_this_table() {
        let interfaces = vec![
            iface("loopback-rt1", (&["203.0.113.1/32"], Some("rt1")), &[]),
            iface(
                "eth0",
                (&[], None),
                &[
                    (0, &["10.50.0.2/24"], Some("rt1")),
                    (300, &["192.0.2.1/24", "2001:db8::1/64"], Some("rt1")),
                    (301, &["10.99.0.1/24"], Some("rt2")),
                ],
            ),
            iface("loopback-rt2", (&["203.0.113.2/32"], Some("rt2")), &[]),
        ];
        let domains = vec![
            domain("bd-svi", &["203.0.113.65/28"], Some("rt1")),
            domain("bd-other", &["203.0.113.81/28"], Some("rt2")),
        ];
        let aggregates = vec![nos_proto::PortAggregateStatus {
            name: "bond1".into(),
            mode: nos_proto::PortAggregateMode::Xor,
            switching_profile: None,
            mtu: 1500,
            subinterfaces: iface(
                "bond1",
                (&[], None),
                &[
                    (0, &["198.51.100.1/29"], Some("rt1")),
                    (10, &["198.51.100.9/29"], Some("rt2")),
                ],
            )
            .subinterfaces,
            link_local_address: None,
            bond_name: None,
        }];
        let mut got: Vec<(String, String)> =
            connected_entries("rt1", &interfaces, &aggregates, &domains)
                .into_iter()
                .map(|e| {
                    assert_eq!(e.source, RouteSource::Connected);
                    (e.prefix.to_string(), e.next_hops[0].0.to_string())
                })
                .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("10.50.0.0/24".into(), "10.50.0.2".into()),
                ("192.0.2.0/24".into(), "192.0.2.1".into()),
                ("198.51.100.0/29".into(), "198.51.100.1".into()),
                ("2001:db8::/64".into(), "2001:db8::1".into()),
                ("203.0.113.1/32".into(), "203.0.113.1".into()),
                ("203.0.113.64/28".into(), "203.0.113.65".into()),
            ]
        );
    }

    #[test]
    fn connected_entries_keep_first_address_for_a_prefix_seen_twice() {
        let interfaces = vec![iface(
            "eth0",
            (&[], None),
            &[(0, &["10.0.0.1/24", "10.0.0.2/24"], Some("rt1"))],
        )];
        let got = connected_entries("rt1", &interfaces, &[], &[]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].next_hops[0].0, "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn table_not_found_publishes_idle_target() {
        let cfg = Config::default();
        let target = compute_redistribute_target(&cfg, "rt1", &HashMap::new());
        assert_eq!(target, bgp_client::RedistributeTarget::default());
    }

    #[test]
    fn no_redistribute_rule_publishes_bgp_instance_with_empty_routes() {
        let table = RoutingTable {
            rest_api: None,
            ospfv3_instance: None,
            name: "rt1".into(),
            bgp_instance: Some("bgp1".into()),
            ospf_instance: None,
            static_routing_instance: None,
            redistribute: None,
        };
        let cfg = cfg_with_table(table);
        let mut routes = HashMap::new();
        let entry = static_entry("10.0.0.0/24", "10.0.0.1");
        routes.insert(entry.prefix, entry);

        let target = compute_redistribute_target(&cfg, "rt1", &routes);
        assert_eq!(target.bgp_instance.as_deref(), Some("bgp1"));
        assert_eq!(target.routes, [] as [nos_proto::RedistributedRoute; 0]);
    }

    #[test]
    fn active_rule_redistributes_static_ipv4_routes() {
        let table = RoutingTable {
            rest_api: None,
            ospfv3_instance: None,
            name: "rt1".into(),
            bgp_instance: Some("bgp1".into()),
            ospf_instance: None,
            static_routing_instance: None,
            redistribute: Some(Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Bgp,
                policy: None,
            }),
        };
        let cfg = cfg_with_table(table);
        let mut routes = HashMap::new();
        let entry = static_entry("10.0.0.0/24", "10.0.0.1");
        routes.insert(entry.prefix, entry);

        let target = compute_redistribute_target(&cfg, "rt1", &routes);
        assert_eq!(target.bgp_instance.as_deref(), Some("bgp1"));
        assert_eq!(target.routes.len(), 1);
        assert_eq!(target.routes[0].prefix, "10.0.0.0/24".parse().unwrap());
        assert_eq!(
            target.routes[0].gateway,
            "10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn active_rule_skips_bgp_sourced_routes() {
        let table = RoutingTable {
            rest_api: None,
            ospfv3_instance: None,
            name: "rt1".into(),
            bgp_instance: Some("bgp1".into()),
            ospf_instance: None,
            static_routing_instance: None,
            redistribute: Some(Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Bgp,
                policy: None,
            }),
        };
        let cfg = cfg_with_table(table);
        let mut routes = HashMap::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        routes.insert(
            prefix,
            RibEntry {
                prefix,
                next_hops: vec![("10.0.0.9".parse().unwrap(), None)],
                source: RouteSource::Bgp,
                backup: None,
                backup_interface_id: None,
            },
        );

        let target = compute_redistribute_target(&cfg, "rt1", &routes);
        assert_eq!(target.routes, [] as [nos_proto::RedistributedRoute; 0]);
    }

    #[test]
    fn active_rule_redistributes_static_ipv6_routes_too() {
        let table = RoutingTable {
            rest_api: None,
            ospfv3_instance: None,
            name: "rt1".into(),
            bgp_instance: Some("bgp1".into()),
            ospf_instance: None,
            static_routing_instance: None,
            redistribute: Some(Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Bgp,
                policy: None,
            }),
        };
        let cfg = cfg_with_table(table);
        let mut routes = HashMap::new();
        let entry = RibEntry {
            prefix: "2001:db8::/32".parse().unwrap(),
            next_hops: vec![("2001:db8::1".parse().unwrap(), None)],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
        };
        routes.insert(entry.prefix, entry);

        let target = compute_redistribute_target(&cfg, "rt1", &routes);
        assert_eq!(
            target.routes,
            vec![nos_proto::RedistributedRoute {
                prefix: "2001:db8::/32".parse().unwrap(),
                gateway: "2001:db8::1".parse().unwrap(),
            }]
        );
    }

    #[test]
    fn ospf_table_not_found_publishes_idle_target() {
        let cfg = Config::default();
        let target = compute_redistribute_target_ospf(&cfg, "rt1", &HashMap::new());
        assert_eq!(target, ospf_client::RedistributeTarget::default());
    }

    #[test]
    fn ospf_no_redistribute_rule_publishes_ospf_instance_with_empty_routes() {
        let table = RoutingTable {
            rest_api: None,
            ospfv3_instance: None,
            name: "rt1".into(),
            bgp_instance: None,
            ospf_instance: Some("ospf1".into()),
            static_routing_instance: None,
            redistribute: None,
        };
        let cfg = cfg_with_table(table);
        let mut routes = HashMap::new();
        let entry = static_entry("10.0.0.0/24", "10.0.0.1");
        routes.insert(entry.prefix, entry);

        let target = compute_redistribute_target_ospf(&cfg, "rt1", &routes);
        assert_eq!(target.ospf_instance.as_deref(), Some("ospf1"));
        assert_eq!(target.routes, [] as [nos_proto::RedistributedRoute; 0]);
    }

    #[test]
    fn ospf_active_rule_redistributes_static_ipv4_routes() {
        let table = RoutingTable {
            rest_api: None,
            ospfv3_instance: None,
            name: "rt1".into(),
            bgp_instance: None,
            ospf_instance: Some("ospf1".into()),
            static_routing_instance: None,
            redistribute: Some(Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Ospf,
                policy: None,
            }),
        };
        let cfg = cfg_with_table(table);
        let mut routes = HashMap::new();
        let entry = static_entry("10.0.0.0/24", "10.0.0.1");
        routes.insert(entry.prefix, entry);

        let target = compute_redistribute_target_ospf(&cfg, "rt1", &routes);
        assert_eq!(target.ospf_instance.as_deref(), Some("ospf1"));
        assert_eq!(target.routes.len(), 1);
        assert_eq!(target.routes[0].prefix, "10.0.0.0/24".parse().unwrap());
    }

    #[test]
    fn ospf_active_rule_skips_bgp_sourced_routes() {
        let table = RoutingTable {
            rest_api: None,
            ospfv3_instance: None,
            name: "rt1".into(),
            bgp_instance: None,
            ospf_instance: Some("ospf1".into()),
            static_routing_instance: None,
            redistribute: Some(Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Ospf,
                policy: None,
            }),
        };
        let cfg = cfg_with_table(table);
        let mut routes = HashMap::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        routes.insert(
            prefix,
            RibEntry {
                prefix,
                next_hops: vec![("10.0.0.9".parse().unwrap(), None)],
                source: RouteSource::Bgp,
                backup: None,
                backup_interface_id: None,
            },
        );

        let target = compute_redistribute_target_ospf(&cfg, "rt1", &routes);
        assert_eq!(target.routes, [] as [nos_proto::RedistributedRoute; 0]);
    }

    #[test]
    fn ospf_rule_does_not_redistribute_when_target_is_bgp() {
        let table = RoutingTable {
            rest_api: None,
            ospfv3_instance: None,
            name: "rt1".into(),
            bgp_instance: Some("bgp1".into()),
            ospf_instance: Some("ospf1".into()),
            static_routing_instance: None,
            redistribute: Some(Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Bgp,
                policy: None,
            }),
        };
        let cfg = cfg_with_table(table);
        let mut routes = HashMap::new();
        let entry = static_entry("10.0.0.0/24", "10.0.0.1");
        routes.insert(entry.prefix, entry);

        let target = compute_redistribute_target_ospf(&cfg, "rt1", &routes);
        assert_eq!(target.routes, [] as [nos_proto::RedistributedRoute; 0]);
    }
}
