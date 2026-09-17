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
/// `bgp_instances`/`routing_tables`' own reconnect policy exactly (fixed 1s,
/// no backoff).
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

struct InstanceHandle {
    shutdown_tx: watch::Sender<bool>,
    task: JoinHandle<()>,
}

/// Subscribes to `nos-configd`'s `OspfInstances` diff stream and maintains
/// one supervised `nos-ospfd --instance <name>` process per OSPF instance
/// currently in the running config, reconciling on every diff event — the
/// identical dynamic-spawn pattern `bgp_instances::manage` uses. Runs until
/// `shutdown` fires, then stops every still-running instance before
/// returning.
///
/// Unlike `bgp_instances`/`routing_tables`, no `EndpointRegistry` entry is
/// registered here: `nos-ospfd` has no IPC query listener yet (see
/// `ospf/CLAUDE.md`), so there is no socket to resolve `ServiceRef::
/// OspfInstance` to. `EndpointRegistry::set_ospf_instance`/
/// `remove_ospf_instance` already exist for whichever future change gives
/// `nos-ospfd` one.
pub async fn manage(
    config_socket: PathBuf,
    ospfd_bin: PathBuf,
    ospfd_flags: Vec<String>,
    log_socket: PathBuf,
    policy: BackoffPolicy,
    watchdog_listen_socket: PathBuf,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut instances: HashMap<String, InstanceHandle> = HashMap::new();

    while !*shutdown.borrow() {
        match config_client::subscribe_diff(&config_socket, vec![DiffScope::OspfInstances]).await {
            Ok(mut reader) => {
                info!("connected to nos-configd diff stream");
                // The first event on a fresh connection is always synthesized
                // against an empty config (all-Added) — treat it as the
                // authoritative full membership list rather than an
                // incremental change, so an instance removed while we were
                // disconnected (and thus never seen as `Removed`) still gets
                // reconciled away instead of leaking as an orphan process.
                let mut first_event = true;
                loop {
                    tokio::select! {
                        event = reader.next() => match event {
                            Some(Ok(Event::Diff(diff))) => {
                                if first_event {
                                    sync_from_initial(&mut instances, &diff.ospf_instances, &ospfd_bin, &ospfd_flags, &log_socket, policy, &watchdog_listen_socket);
                                    first_event = false;
                                } else {
                                    apply_diff(&mut instances, &diff.ospf_instances, &ospfd_bin, &ospfd_flags, &log_socket, policy, &watchdog_listen_socket);
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

/// Reconciles the full set of currently-wanted instance names (all `Added`
/// by construction — see `manage`'s doc comment) against what's already
/// supervised: spawns anything missing, stops anything no longer wanted.
fn sync_from_initial(
    instances: &mut HashMap<String, InstanceHandle>,
    sections: &[SectionDiff],
    ospfd_bin: &Path,
    ospfd_flags: &[String],
    log_socket: &Path,
    policy: BackoffPolicy,
    watchdog_listen_socket: &Path,
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
            spawn_instance(
                instances,
                name,
                ospfd_bin,
                ospfd_flags,
                log_socket,
                policy,
                watchdog_listen_socket,
            );
        }
    }
}

/// Applies an incremental diff on an unbroken connection: `Added` spawns if
/// missing (idempotent), `Removed` stops if present, `Modified` is a no-op
/// at this level — `nos-ospfd` independently subscribes to config and
/// re-resolves its own instance on every relevant diff, so a parameter
/// change never needs a process restart here.
fn apply_diff(
    instances: &mut HashMap<String, InstanceHandle>,
    sections: &[SectionDiff],
    ospfd_bin: &Path,
    ospfd_flags: &[String],
    log_socket: &Path,
    policy: BackoffPolicy,
    watchdog_listen_socket: &Path,
) {
    for section in sections {
        match section.status {
            DiffStatus::Added => {
                if !instances.contains_key(&section.name) {
                    spawn_instance(
                        instances,
                        &section.name,
                        ospfd_bin,
                        ospfd_flags,
                        log_socket,
                        policy,
                        watchdog_listen_socket,
                    );
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
    ospfd_bin: &Path,
    ospfd_flags: &[String],
    log_socket: &Path,
    policy: BackoffPolicy,
    watchdog_listen_socket: &Path,
) {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let spec = ProcessSpec::new(
        format!("nos-ospfd[{name}]"),
        ospfd_bin.to_path_buf(),
        std::iter::once("--instance".to_string())
            .chain(std::iter::once(name.to_string()))
            .chain(std::iter::once("--watchdog-socket".to_string()))
            .chain(std::iter::once(
                watchdog_listen_socket.display().to_string(),
            ))
            .chain(std::iter::once("--log-socket".to_string()))
            .chain(std::iter::once(log_socket.display().to_string()))
            .chain(ospfd_flags.iter().cloned())
            .collect(),
    );
    info!(instance = %name, "spawning nos-ospfd for new OSPF instance");
    let task = tokio::spawn(supervise_one(spec, policy, shutdown_rx));
    instances.insert(name.to_string(), InstanceHandle { shutdown_tx, task });
}

fn stop_instance(instances: &mut HashMap<String, InstanceHandle>, name: &str) {
    if let Some(handle) = instances.remove(name) {
        info!(instance = %name, "OSPF instance removed from config, stopping nos-ospfd");
        let _ = handle.shutdown_tx.send(true);
        let name = name.to_string();
        // Don't block reconciliation on this shutdown's up-to-10s grace period.
        tokio::spawn(async move {
            if let Err(e) = handle.task.await {
                warn!(instance = %name, error = %e, "supervised ospfd task panicked");
            }
        });
    }
}

async fn shutdown_all(instances: HashMap<String, InstanceHandle>) {
    futures::future::join_all(instances.into_iter().map(|(name, h)| async move {
        let _ = h.shutdown_tx.send(true);
        if let Err(e) = h.task.await {
            warn!(instance = %name, error = %e, "supervised ospfd task panicked");
        }
    }))
    .await;
}
