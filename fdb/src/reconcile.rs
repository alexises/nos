//! Keeps this domain's `Fdb` in step with the running config: subscribes to
//! the relevant diffs purely as a resync trigger (always re-fetching the whole
//! config, like `nos-ribd`), and also resyncs on a fixed tick, since the
//! bridge and VTEP address becoming available are external conditions no
//! config diff signals.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use nos_proto::evpn_id::{parse_rd, parse_rt};
use nos_proto::{BroadcastDomain, Config, DiffScope, Event};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::config_client;
use crate::fdb::{Fdb, Ready, TICK};
use crate::interface_client;

const RECONNECT_DELAY: Duration = Duration::from_secs(1);

pub async fn run(
    config_socket: PathBuf,
    watchdog_socket: PathBuf,
    domain: String,
    fdb: Arc<Fdb>,
    mut shutdown: watch::Receiver<bool>,
) {
    let scopes = vec![
        DiffScope::BroadcastDomains,
        DiffScope::Interfaces,
        DiffScope::BgpInstances,
        DiffScope::RoutingTables,
    ];
    'outer: while !*shutdown.borrow() {
        let mut events = match config_client::subscribe_diff(&config_socket, scopes.clone()).await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "failed to subscribe to config diffs, retrying");
                tokio::select! {
                    () = tokio::time::sleep(RECONNECT_DELAY) => continue,
                    _ = shutdown.changed() => break,
                }
            }
        };
        resync(&config_socket, &watchdog_socket, &domain, &fdb).await;
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                ev = events.next() => match ev {
                    Some(Ok(Event::Diff(_))) => {}
                    Some(Ok(_)) => continue,
                    Some(Err(_)) | None => {
                        warn!("config subscription dropped, reconnecting");
                        tokio::select! {
                            () = tokio::time::sleep(RECONNECT_DELAY) => continue 'outer,
                            _ = shutdown.changed() => break 'outer,
                        }
                    }
                },
                _ = tick.tick() => {}
                _ = shutdown.changed() => break 'outer,
            }
            resync(&config_socket, &watchdog_socket, &domain, &fdb).await;
        }
    }
    info!(domain = %domain, "reconciliation loop stopped");
}

async fn resync(config_socket: &Path, watchdog_socket: &Path, domain: &str, fdb: &Fdb) {
    let cfg = match config_client::fetch_config(config_socket).await {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "failed to fetch running config, keeping previous state");
            return;
        }
    };
    let ready = match cfg.broadcast_domains.iter().find(|d| d.name == domain) {
        Some(d) => resolve(&cfg, d, watchdog_socket).await,
        // The watchdog stops this process when the domain goes; until it does,
        // hold nothing.
        None => None,
    };
    fdb.set_ready(ready).await;
}

/// `None` while anything needed is missing — logged at `debug`, retried by the
/// tick (a bridge or address that isn't there *yet* is the normal case).
async fn resolve(cfg: &Config, d: &BroadcastDomain, watchdog_socket: &Path) -> Option<Ready> {
    let vni = d.vni?;
    let (Some(rd), Some(source), Some(instance)) = (
        d.rd.as_deref().and_then(parse_rd),
        d.vtep_source.as_ref(),
        d.mac_redistribute.clone(),
    ) else {
        debug!(domain = %d.name, "evpn config incomplete (needs rd, vtep-source and redistribute), idle");
        return None;
    };
    let table = cfg
        .bgp_instances
        .iter()
        .find(|i| i.name == instance)
        .and_then(|i| i.routing_table.as_deref());
    let Some((vtep, underlay)) =
        interface_client::resolve_vtep(watchdog_socket, table, source).await
    else {
        debug!(domain = %d.name, "vtep-source has no address yet");
        return None;
    };
    let Some(bridge) = interface_client::bridge_name(watchdog_socket, &d.name).await else {
        debug!(domain = %d.name, "bridge not created by nos-interfaced yet");
        return None;
    };
    let rts = |v: &[String]| v.iter().filter_map(|r| parse_rt(r)).collect();
    Some(Ready {
        vni,
        bridge,
        vtep,
        underlay,
        rd,
        rt_import: rts(&d.route_targets_import),
        rt_export: rts(&d.route_targets_export),
        bgp_instance: instance,
    })
}
