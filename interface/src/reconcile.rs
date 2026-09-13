use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use nos_proto::{DiffScope, Event};
use tokio::sync::{watch, RwLock};
use tokio::time::sleep;
use tracing::{info, warn};

use crate::config_client;
use crate::state::{build_from_config, Interfaces};

/// Fixed reconnect delay for the config subscription, matching
/// `nos-rib`'s `reconcile::RECONNECT_DELAY`/`nos-watchdog`'s
/// `bgp_instances::RECONNECT_DELAY` for consistency across the codebase's
/// config-subscribing consumers.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Runs until `shutdown` fires. Subscribes to `Interfaces` diffs purely as
/// an edge trigger: every `Event::Diff` received (including the first,
/// synthesized one) causes a full `resync` — a fresh `Request::Get` plus a
/// from-scratch `Interfaces` rebuild — rather than incremental diff
/// application, since `SectionDiff`/`FieldDiff` only carry pre-formatted
/// display strings, not structured data (mirrors `nos-rib`'s
/// `reconcile::run`).
pub async fn run(
    config_socket: PathBuf,
    interfaces: Arc<RwLock<Interfaces>>,
    mut shutdown: watch::Receiver<bool>,
) {
    while !*shutdown.borrow() {
        match config_client::subscribe_diff(&config_socket, vec![DiffScope::Interfaces]).await {
            Ok(mut reader) => {
                info!("connected to nos-configd diff stream");
                loop {
                    tokio::select! {
                        event = reader.next() => match event {
                            Some(Ok(Event::Diff(_))) => {
                                resync(&config_socket, &interfaces).await;
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

    info!("reconciliation loop stopped");
}

async fn resync(config_socket: &Path, interfaces: &Arc<RwLock<Interfaces>>) {
    match config_client::fetch_config(config_socket).await {
        Ok(cfg) => {
            let new_interfaces = build_from_config(&cfg);
            info!(count = cfg.interfaces.len(), "reconciled interfaces");
            *interfaces.write().await = new_interfaces;
        }
        Err(e) => {
            warn!(error = %e, "failed to fetch running config, keeping previous state");
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
