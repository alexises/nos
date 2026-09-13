use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use nos_proto::{DiffScope, Event};
use tokio::sync::{watch, RwLock};
use tokio::time::sleep;
use tracing::{info, warn};

use crate::config_client;
use crate::rib::{build_from_config, Rib};

/// Fixed reconnect delay for the config subscription, matching
/// `nos-watchdog`'s `bgp_instances::RECONNECT_DELAY` for consistency across
/// the codebase's config-subscribing consumers.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Runs until `shutdown` fires. Subscribes to `RoutingTables` and
/// `StaticRoutingInstances` diffs purely as an edge trigger: every
/// `Event::Diff` received (including the first, synthesized one) causes a
/// full `resync` — a fresh `Request::Get` plus a from-scratch `Rib` rebuild
/// — rather than incremental diff application, since `SectionDiff`/
/// `FieldDiff` only carry pre-formatted display strings, not structured
/// route data (see `nos_proto::diff::routing_table`/`static_routing_instance`).
pub async fn run(
    config_socket: PathBuf,
    table: String,
    rib: Arc<RwLock<Rib>>,
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
                loop {
                    tokio::select! {
                        event = reader.next() => match event {
                            Some(Ok(Event::Diff(_))) => {
                                resync(&config_socket, &table, &rib).await;
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

    info!(table = %table, "reconciliation loop stopped");
}

async fn resync(config_socket: &Path, table: &str, rib: &Arc<RwLock<Rib>>) {
    match config_client::fetch_config(config_socket).await {
        Ok(cfg) => {
            if let Some(new_rib) = build_from_config(&cfg, table) {
                let routes = new_rib.best_routes();
                info!(table = %table, prefixes = routes.len(), "recomputed RIB");
                for (prefix, entry) in &routes {
                    info!(
                        table = %table,
                        %prefix,
                        gateway = %entry.gateway,
                        source = ?entry.source,
                        "best route"
                    );
                }
                *rib.write().await = new_rib;
            } else {
                warn!(
                    table = %table,
                    "routing table not found in running config; RIB left empty until it appears"
                );
                *rib.write().await = Rib::new();
            }
        }
        Err(e) => {
            warn!(table = %table, error = %e, "failed to fetch running config, keeping previous RIB");
        }
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
