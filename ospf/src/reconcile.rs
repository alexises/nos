use std::path::PathBuf;
use std::time::Duration;

use futures::StreamExt;
use nos_proto::{DiffScope, Event};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config_client;

/// Fixed reconnect delay for the config subscription, matching every other
/// config-subscribing consumer in this codebase (`nos-bgp`/`nos-rib`/
/// `nos-interface`'s own `reconcile::RECONNECT_DELAY`).
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Runs until `shutdown` fires. Subscribes to `OspfInstances` diffs purely as
/// a resync trigger — the actual state always comes from a fresh
/// `fetch_config` call. This is a config-only skeleton (see `ospf/CLAUDE.md`):
/// there is no OSPF protocol logic yet, so a resync only ever logs what it
/// found.
pub async fn run(config_socket: PathBuf, instance: String, mut shutdown: watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        match config_client::subscribe_diff(&config_socket, vec![DiffScope::OspfInstances]).await {
            Ok(mut reader) => {
                info!(instance = %instance, "connected to nos-configd diff stream");
                resync(&config_socket, &instance).await;
                loop {
                    tokio::select! {
                        event = reader.next() => match event {
                            Some(Ok(Event::Diff(_))) => {
                                resync(&config_socket, &instance).await;
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

    info!(instance = %instance, "reconciliation loop stopped");
}

async fn resync(config_socket: &std::path::Path, instance: &str) {
    let cfg = match config_client::fetch_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!(error = %e, "failed to fetch running config, keeping previous state");
            return;
        }
    };

    match cfg.ospf_instances.iter().find(|i| i.name == instance) {
        Some(own) => info!(
            instance = %instance,
            router_id = %own.router_id,
            routing_table = ?own.routing_table,
            "ospf instance config resolved"
        ),
        None => {
            // The watchdog would be tearing this process down anyway if the
            // instance were genuinely removed from config.
            warn!(instance = %instance, "own ospf instance missing from running config");
        }
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
