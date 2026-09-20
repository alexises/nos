use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use nos_proto::{
    Config, DiffScope, Event, IpNet, Redistribute, RedistributeSource, RedistributeTarget,
    RedistributedRoute,
};
use tokio::sync::{watch, RwLock};
use tokio::time::sleep;
use tracing::{debug, error, info, trace, warn};

use crate::bgp_client;
use crate::config_client;
use crate::driver::RibDriver;
use crate::ospf_client;
use crate::rib::{build_from_config, Rib, RibEntry, RouteSource};

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
///
/// On exit, tears down this table's kernel VRF/routes via `driver` (see
/// `RibDriver::teardown`) — the same SIGINT `nos-watchdog` sends both for
/// "shutting down" and "this table was removed from config" (root
/// `CLAUDE.md`), so this runs on every ordinary restart too, not only a
/// real removal. That's an accepted tradeoff: the driver's persisted
/// table-id registry (see `driver::table_registry`) is untouched by
/// `teardown`, so the next `apply` recreates the exact same VRF name.
pub async fn run(
    config_socket: PathBuf,
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
                                resync(&config_socket, &table, &rib, driver.as_ref(), &redistribute_tx, &ospf_redistribute_tx).await;
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
                            resync(&config_socket, &table, &rib, driver.as_ref(), &redistribute_tx, &ospf_redistribute_tx).await;
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

            let mut guard = rib.write().await;
            guard.replace_source(RouteSource::Static, static_entries);
            let routes = guard.best_routes();
            drop(guard);

            debug!(table = %table, prefixes = routes.len(), "recomputed RIB");
            for (prefix, entry) in &routes {
                trace!(
                    table = %table,
                    %prefix,
                    gateway = %entry.gateway,
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
                gateway: entry.gateway,
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
                gateway: entry.gateway,
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
            interface_id: None,
            prefix: prefix.parse().unwrap(),
            gateway: gateway.parse().unwrap(),
            source: RouteSource::Static,
        }
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
        assert!(target.routes.is_empty());
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
                interface_id: None,
                prefix,
                gateway: "10.0.0.9".parse().unwrap(),
                source: RouteSource::Bgp,
            },
        );

        let target = compute_redistribute_target(&cfg, "rt1", &routes);
        assert!(target.routes.is_empty());
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
            interface_id: None,
            prefix: "2001:db8::/32".parse().unwrap(),
            gateway: "2001:db8::1".parse().unwrap(),
            source: RouteSource::Static,
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
        assert!(target.routes.is_empty());
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
                interface_id: None,
                prefix,
                gateway: "10.0.0.9".parse().unwrap(),
                source: RouteSource::Bgp,
            },
        );

        let target = compute_redistribute_target_ospf(&cfg, "rt1", &routes);
        assert!(target.routes.is_empty());
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
        assert!(target.routes.is_empty());
    }
}
