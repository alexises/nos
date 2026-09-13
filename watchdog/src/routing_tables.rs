use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::StreamExt;
use nos_proto::{DiffScope, DiffStatus, Event, SectionDiff};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config_client;
use crate::supervisor::{supervise_one, wait_or_shutdown, BackoffPolicy, ProcessSpec};

/// Fixed reconnect delay for the config subscription itself — distinct from
/// `BackoffPolicy`, which governs per-child crash/restart backoff. Mirrors
/// `bgp_instances`'s reconnect policy exactly (fixed 1s, no backoff): a
/// daemon restart shouldn't permanently break the subscriber.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

struct InstanceHandle {
    shutdown_tx: watch::Sender<bool>,
    task: JoinHandle<()>,
}

/// Subscribes to `nos-configd`'s `RoutingTables` diff stream and maintains
/// one supervised `nos-ribd --table <name>` process per routing table
/// currently in the running config, reconciling on every diff event. Runs
/// until `shutdown` fires, then stops every still-running instance (same
/// SIGINT-then-kill path `supervise_one` already uses) before returning.
pub async fn manage(
    config_socket: PathBuf,
    ribd_bin: PathBuf,
    ribd_flags: Vec<String>,
    policy: BackoffPolicy,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut instances: HashMap<String, InstanceHandle> = HashMap::new();

    while !*shutdown.borrow() {
        match config_client::subscribe_diff(&config_socket, vec![DiffScope::RoutingTables]).await {
            Ok(mut reader) => {
                info!("connected to nos-configd diff stream");
                // The first event on a fresh connection is always synthesized
                // against an empty config (all-Added) — treat it as the
                // authoritative full membership list rather than an
                // incremental change, so a table removed while we were
                // disconnected (and thus never seen as `Removed`) still gets
                // reconciled away instead of leaking as an orphan process.
                let mut first_event = true;
                loop {
                    tokio::select! {
                        event = reader.next() => match event {
                            Some(Ok(Event::Diff(diff))) => {
                                if first_event {
                                    sync_from_initial(&mut instances, &diff.routing_tables, &ribd_bin, &ribd_flags, policy);
                                    first_event = false;
                                } else {
                                    apply_diff(&mut instances, &diff.routing_tables, &ribd_bin, &ribd_flags, policy);
                                }
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
            Err(e) => {
                warn!(error = %e, socket = %config_socket.display(), "failed to connect to nos-configd");
            }
        }
        if *shutdown.borrow() {
            break;
        }
        if wait_or_shutdown(RECONNECT_DELAY, &mut shutdown).await {
            break;
        }
    }

    shutdown_all(instances).await;
}

/// Reconciles the full set of currently-wanted table names (all `Added` by
/// construction — see `manage`'s doc comment) against what's already
/// supervised: spawns anything missing, stops anything no longer wanted.
fn sync_from_initial(
    instances: &mut HashMap<String, InstanceHandle>,
    sections: &[SectionDiff],
    ribd_bin: &Path,
    ribd_flags: &[String],
    policy: BackoffPolicy,
) {
    let wanted: HashSet<&str> = sections.iter().map(|s| s.name.as_str()).collect();

    let stale: Vec<String> = instances
        .keys()
        .filter(|name| !wanted.contains(name.as_str()))
        .cloned()
        .collect();
    for name in stale {
        stop_instance(instances, &name);
    }

    for name in wanted {
        if !instances.contains_key(name) {
            spawn_instance(instances, name, ribd_bin, ribd_flags, policy);
        }
    }
}

/// Applies an incremental diff on an unbroken connection: `Added` spawns if
/// missing (idempotent), `Removed` stops if present. `Modified` (e.g. a
/// table's `static_routing_instance`/`bgp_instance` association changing) is
/// a no-op here: the already-running `nos-ribd` instance independently
/// subscribes to config and re-resolves its own associations on every
/// relevant diff, so restarting the process here would be redundant and
/// would needlessly drop its in-memory RIB.
fn apply_diff(
    instances: &mut HashMap<String, InstanceHandle>,
    sections: &[SectionDiff],
    ribd_bin: &Path,
    ribd_flags: &[String],
    policy: BackoffPolicy,
) {
    for section in sections {
        match section.status {
            DiffStatus::Added => {
                if !instances.contains_key(&section.name) {
                    spawn_instance(instances, &section.name, ribd_bin, ribd_flags, policy);
                }
            }
            DiffStatus::Removed => stop_instance(instances, &section.name),
            DiffStatus::Modified => {}
        }
    }
}

fn spawn_instance(
    instances: &mut HashMap<String, InstanceHandle>,
    name: &str,
    ribd_bin: &Path,
    ribd_flags: &[String],
    policy: BackoffPolicy,
) {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let spec = ProcessSpec::new(
        format!("nos-ribd[{name}]"),
        ribd_bin.to_path_buf(),
        std::iter::once("--table".to_string())
            .chain(std::iter::once(name.to_string()))
            .chain(ribd_flags.iter().cloned())
            .collect(),
    );
    info!(table = %name, "spawning nos-ribd for new routing table");
    let task = tokio::spawn(supervise_one(spec, policy, shutdown_rx));
    instances.insert(name.to_string(), InstanceHandle { shutdown_tx, task });
}

fn stop_instance(instances: &mut HashMap<String, InstanceHandle>, name: &str) {
    if let Some(handle) = instances.remove(name) {
        info!(table = %name, "routing table removed from config, stopping nos-ribd");
        let _ = handle.shutdown_tx.send(true);
        // Don't block reconciliation on this shutdown's up-to-10s grace period.
        tokio::spawn(async move {
            let _ = handle.task.await;
        });
    }
}

async fn shutdown_all(instances: HashMap<String, InstanceHandle>) {
    futures::future::join_all(instances.into_values().map(|h| async move {
        let _ = h.shutdown_tx.send(true);
        let _ = h.task.await;
    }))
    .await;
}
