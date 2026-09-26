use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use nos_proto::{DiffScope, Event, ServiceRef, SourceAddress, LOOPBACK_PREFIX};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::config_client;
use crate::fsm;
use crate::interface_client;
use crate::policy::PolicyCache;
use crate::rib_client;
use crate::session::{LocalIdentity, ResolvedAuth, ResolvedPeer, SessionManager, VrfRequirement};
use crate::watchdog_client;

/// Fixed reconnect delay for the config subscription, matching every other
/// config-subscribing consumer in this codebase (`nos-rib`/`nos-interface`'s
/// `reconcile::RECONNECT_DELAY`, `nos-watchdog`'s `bgp_instances::RECONNECT_DELAY`).
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// How often to re-apply desired state even without a new config diff —
/// needed because VRF readiness (the owning `nos-ribd` instance having
/// created its VRF) is an external condition no config commit signals, same
/// as `nos-interface`'s `reconcile::REAPPLY_INTERVAL`.
const REAPPLY_INTERVAL: Duration = Duration::from_secs(10);

/// Runs until `shutdown` fires. Subscribes to `BgpInstances`/`RoutingTables`
/// diffs purely as a resync trigger (mirrors `nos-rib`/`nos-interface`'s
/// reconcile loops) — the actual state always comes from a fresh
/// `fetch_config` call, plus a periodic tick independent of any config
/// change.
pub async fn run(
    config_socket: PathBuf,
    watchdog_socket: PathBuf,
    instance: String,
    sessions: Arc<SessionManager>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut policy_cache = PolicyCache::default();
    while !*shutdown.borrow() {
        match config_client::subscribe_diff(
            &config_socket,
            vec![
                DiffScope::BgpInstances,
                DiffScope::RoutingTables,
                DiffScope::BroadcastDomains,
                DiffScope::PolicyDefinitions,
                DiffScope::CommunityAliases,
                DiffScope::CommunityGroups,
                DiffScope::PrefixLists,
                DiffScope::AsPathLists,
            ],
        )
        .await
        {
            Ok(mut reader) => {
                info!(instance = %instance, "connected to nos-configd diff stream");
                let mut reapply = tokio::time::interval(REAPPLY_INTERVAL);
                reapply.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                // The diff stream's own synthesized first event already
                // triggers a resync below — skip the immediate first tick
                // so it isn't a redundant duplicate.
                reapply.tick().await;
                loop {
                    tokio::select! {
                        event = reader.next() => match event {
                            Some(Ok(Event::Diff(_))) => {
                                resync(&config_socket, &watchdog_socket, &instance, &sessions, &mut policy_cache).await;
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
                            resync(&config_socket, &watchdog_socket, &instance, &sessions, &mut policy_cache).await;
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

    sessions.shutdown().await;
    info!(instance = %instance, "reconciliation loop stopped");
}

async fn resync(
    config_socket: &Path,
    watchdog_socket: &Path,
    instance: &str,
    sessions: &Arc<SessionManager>,
    policy_cache: &mut PolicyCache,
) {
    let cfg = match config_client::fetch_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!(error = %e, "failed to fetch running config, keeping previous state");
            return;
        }
    };

    policy_cache.resync(
        &cfg.policy_definitions,
        &cfg.community_aliases,
        &cfg.community_groups,
        &cfg.prefix_lists,
        &cfg.as_path_lists,
    );

    let Some(own) = cfg.bgp_instances.iter().find(|i| i.name == instance) else {
        // The watchdog would be tearing this process down anyway if the
        // instance were genuinely removed from config.
        error!(instance = %instance, "own bgp instance missing from running config");
        return;
    };

    let resolved = match &own.routing_table {
        Some(table) => resolve_vrf(watchdog_socket, table).await,
        None => None,
    };
    let vrf = classify_vrf(own.routing_table.as_ref(), resolved);
    match &vrf {
        VrfRequirement::Invalid => error!(
            instance = %instance,
            "BGP instance has no owning routing table, refusing to open any session"
        ),
        VrfRequirement::Pending => debug!(
            instance = %instance,
            table = ?own.routing_table,
            "routing table's vrf not resolvable yet"
        ),
        VrfRequirement::Resolved(name) => {
            debug!(instance = %instance, vrf = %name, "resolved bgp instance's vrf");
        }
    }

    // One `nos-interfaced` query per peer-group that configures a
    // source-address (not per peer) — every peer in the group shares the
    // same reference, so this avoids a redundant round trip per peer.
    let mut source_addrs: HashMap<&str, Vec<IpAddr>> = HashMap::new();
    for group in &own.peer_groups {
        if let Some(source) = &group.source_address {
            let addrs =
                resolve_source_address(watchdog_socket, own.routing_table.as_deref(), source).await;
            if addrs.is_empty() {
                debug!(
                    peer_group = %group.name,
                    "peer-group source-address not resolvable yet"
                );
            } else {
                info!(
                    peer_group = %group.name,
                    addresses = ?addrs,
                    "resolved peer-group source-address"
                );
            }
            source_addrs.insert(group.name.as_str(), addrs);
        }
    }

    let mut peers: Vec<ResolvedPeer> = Vec::new();
    for peer in &own.peers {
        let Some(group) = own.peer_groups.iter().find(|g| g.name == peer.peer_group) else {
            continue;
        };
        let source_address = source_addrs.get(group.name.as_str()).and_then(|addrs| {
            addrs
                .iter()
                .find(|a| a.is_ipv4() == peer.remote_address.is_ipv4())
                .copied()
        });
        peers.push(ResolvedPeer {
            remote_address: peer.remote_address,
            source_address,
            remote_as: group.remote_as,
            peer_group: peer.peer_group.clone(),
            hold_time: group.hold_time.unwrap_or(nos_proto::HOLD_TIME_DEFAULT),
            keepalive_interval: group.keepalive_interval,
            connect_retry_time: group
                .connect_retry_time
                .map_or(fsm::CONNECT_RETRY_TIME, |s| {
                    Duration::from_secs(u64::from(s))
                }),
            mrai: Duration::from_secs(u64::from(group.mrai.unwrap_or(0))),
            damping: group.damping,
            max_hops: group.max_hops,
            auth: group.auth.as_ref().map(ResolvedAuth::from),
            next_hop: group.next_hop,
            address_families: group.address_families.clone(),
            route_reflector_client: group.route_reflector_client,
            route_server_client: group.route_server_client,
            import_policy: policy_cache.resolve(group.import_policy.as_deref()),
            export_policy: policy_cache.resolve(group.export_policy.as_deref()),
            shutdown: peer.shutdown.clone().or_else(|| group.shutdown.clone()),
        });
    }

    let local = LocalIdentity {
        asn: own.asn,
        router_id: own.router_id,
        cluster_id: own.cluster_id.unwrap_or(own.router_id),
    };

    // Unlike `import_policy`/`export_policy`, `None` here means accept-all,
    // not deny-all — redistribution has no filtering unless a policy is
    // explicitly configured (see `nos_proto::Redistribute.policy`'s doc
    // comment), so the default is resolved here rather than by
    // `PolicyCache::resolve` (whose `None => deny_all` stays correct for its
    // only other caller, peer import/export).
    let redistribute_policy = match own.redistribute_policy.as_deref() {
        None => Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        Some(name) => policy_cache.resolve(Some(name)),
    };

    // The broadcast domains that `redistribute from mac to bgp` this instance
    // — the ones whose `nos-fdbd` gets every received EVPN route.
    let fdb_domains = cfg
        .broadcast_domains
        .iter()
        .filter(|d| d.vni.is_some() && d.mac_redistribute.as_deref() == Some(instance))
        .map(|d| d.name.clone())
        .collect();

    sessions
        .reconcile(
            vrf,
            own.routing_table.clone(),
            local,
            peers,
            redistribute_policy,
            fdb_domains,
        )
        .await;
}

/// Resolves `table`'s Linux VRF interface name by asking the owning
/// `nos-ribd` instance directly over IPC (see `crate::rib_client`),
/// resolved via the watchdog broker — never derived locally. `None` covers
/// every "not answerable yet" case uniformly (broker doesn't know that
/// table, connect failure, rib hasn't created a VRF yet), all retried by
/// the caller's periodic re-apply tick.
async fn resolve_vrf(watchdog_socket: &Path, table: &str) -> Option<String> {
    let socket =
        watchdog_client::resolve_once(watchdog_socket, &ServiceRef::RibTable(table.to_string()))
            .await?;
    rib_client::get_vrf_name(&socket).await
}

/// Resolves a peer-group's `SourceAddress` reference to every candidate
/// local address (both families — the caller picks the one matching each
/// peer's own remote-address family), querying `nos-interfaced` directly
/// (resolved via the watchdog broker's `ServiceRef::Interfaces`, mirroring
/// `resolve_vrf`'s `ServiceRef::RibTable` + `nos-ribd` query). An empty
/// result covers every "not resolvable right now" case uniformly
/// (`nos-interfaced` unreachable, the referenced interface not configured
/// yet, no address under the requested label, or — for `Loopback` — this
/// instance having no owning routing table to derive the loopback's name
/// from) — retried by the caller's periodic re-apply tick, same as
/// `resolve_vrf`.
async fn resolve_source_address(
    watchdog_socket: &Path,
    own_routing_table: Option<&str>,
    source: &SourceAddress,
) -> Vec<IpAddr> {
    let (interface, label, is_loopback) = match source {
        SourceAddress::Interface { interface, label } => (interface.clone(), label.clone(), false),
        SourceAddress::Loopback { label } => {
            let Some(table) = own_routing_table else {
                warn!(
                    "peer-group's source-address is loopback but this instance has no owning \
                     routing table to derive it from"
                );
                return Vec::new();
            };
            (format!("{LOOPBACK_PREFIX}{table}"), label.clone(), true)
        }
    };
    let Some(socket) =
        watchdog_client::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await
    else {
        return Vec::new();
    };
    let Some(status) = interface_client::get_interface(&socket, &interface).await else {
        return Vec::new();
    };
    // A loopback interface still carries its addresses flat (`status.addresses`,
    // unchanged); every other interface's addresses live under its tag-0
    // (untagged/native) subinterface instead — see
    // `schema::valid_addressing_split`.
    let addresses = if is_loopback {
        status.addresses
    } else {
        status
            .subinterfaces
            .into_iter()
            .find(|s| s.tag == 0)
            .map(|s| s.addresses)
            .unwrap_or_default()
    };
    addresses
        .into_iter()
        .filter(|a| label.is_none() || a.label == label)
        .map(|a| a.address.addr())
        .collect()
}

/// Pure classification of the three-way VRF requirement (see
/// `session::VrfRequirement`) from a `BgpInstance`'s reflexive
/// `routing_table` reference and, if set, that table's resolved VRF name.
fn classify_vrf(routing_table: Option<&String>, resolved: Option<String>) -> VrfRequirement {
    match routing_table {
        None => VrfRequirement::Invalid,
        Some(_) => match resolved {
            Some(name) => VrfRequirement::Resolved(name),
            None => VrfRequirement::Pending,
        },
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
    use super::*;

    #[test]
    fn no_owning_table_is_invalid() {
        assert_eq!(classify_vrf(None, None), VrfRequirement::Invalid);
    }

    #[test]
    fn owning_table_with_no_resolved_vrf_is_pending() {
        let table = "rt1".to_string();
        assert_eq!(classify_vrf(Some(&table), None), VrfRequirement::Pending);
    }

    #[test]
    fn owning_table_with_resolved_vrf_is_resolved() {
        let table = "rt1".to_string();
        assert_eq!(
            classify_vrf(Some(&table), Some("vrf100".to_string())),
            VrfRequirement::Resolved("vrf100".to_string())
        );
    }
}
