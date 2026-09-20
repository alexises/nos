//! One supervised process per named config object.
//!
//! `nos-bgpd`, `nos-ribd` and `nos-ospfd` are all supervised the same way:
//! subscribe to one `ConfigDiff` scope, run one process per object in it, and
//! reconcile on every diff. They differ only in the fields of [`Managed`], so
//! they share this one implementation rather than a module each.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use nos_proto::{ConfigDiff, DiffScope, DiffStatus, Event, Role, SectionDiff};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config_client;
use crate::pki::Pki;
use crate::registry::{EndpointKind, EndpointRegistry};
use crate::supervisor::{supervise_one, wait_or_shutdown, BackoffPolicy, ProcessSpec};

/// Fixed reconnect delay for the config subscription itself — distinct from
/// `BackoffPolicy`, which governs per-child crash/restart backoff. Mirrors
/// nos-cli's subscribe-retry policy exactly (fixed 1s, no backoff): a daemon
/// restart shouldn't permanently break the subscriber.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// The per-instance IPC socket a daemon family serves queries on, and the
/// registry slot it is published under for `ServiceRef` resolution.
pub struct Endpoint {
    pub kind: EndpointKind,
    /// Names the socket: `/run/nos/<prefix>-<name>.sock`.
    pub socket_prefix: &'static str,
}

/// Everything that distinguishes one dynamically-spawned daemon family from
/// another.
pub struct Managed {
    /// The diff scope to subscribe to, and the section of a received
    /// `ConfigDiff` that scope fills in.
    pub scope: DiffScope,
    pub section: fn(&ConfigDiff) -> &[SectionDiff],
    pub bin: PathBuf,
    /// Opaque pass-through flags for this family (`--bgpd-arg` and friends).
    pub flags: Vec<String>,
    /// How the binary names its own object: `--instance` or `--table`.
    pub name_flag: &'static str,
    /// Binary name, for `ProcessSpec` and every log line.
    pub daemon: &'static str,
    /// The role each instance's certificate asserts (its name is the object's).
    pub role: Role,
    /// What one object is called, for log lines: `"BGP instance"`.
    pub noun: &'static str,
    /// `None` for a daemon family with no IPC query listener to register —
    /// every family managed here (`nos-bgpd`, `nos-ribd`, `nos-ospfd`)
    /// currently has one, so `main.rs` always passes `Some` today.
    pub endpoint: Option<Endpoint>,
    /// `None` (every family but one): a process per section, always. `Some`:
    /// a process only while the section carries a `FieldDiff` with this label
    /// whose new value is set — for a daemon that is *opt-in per object*
    /// (`nos-restd` on a `RoutingTable`'s `rest-api` field) rather than one
    /// per object. This is what lets a field flip on an existing object
    /// (`Modified`) spawn or stop a process.
    pub claim_label: Option<&'static str>,
    pub config_socket: PathBuf,
    pub log_socket: PathBuf,
    pub watchdog_listen_socket: PathBuf,
    pub policy: BackoffPolicy,
    pub registry: EndpointRegistry,
    pub pki: Arc<Pki>,
}

struct InstanceHandle {
    shutdown_tx: watch::Sender<bool>,
    task: JoinHandle<()>,
}

/// Subscribes to `m.scope`'s diff stream and maintains one supervised
/// `<m.daemon> <m.name_flag> <name>` process per object currently in the
/// running config, reconciling on every diff event. Runs until `shutdown`
/// fires, then stops every still-running instance (same SIGINT-then-kill path
/// `supervise_one` already uses) before returning.
pub async fn manage(m: Managed, mut shutdown: watch::Receiver<bool>) {
    let mut instances: HashMap<String, InstanceHandle> = HashMap::new();

    while !*shutdown.borrow() {
        match config_client::subscribe_diff(&m.pki.identity, &m.config_socket, vec![m.scope]).await
        {
            Ok(reader) => {
                info!("connected to nos-configd diff stream");
                if follow(reader, &mut instances, &m, &mut shutdown).await {
                    break;
                }
            }
            Err(e) => {
                warn!(error = %e, socket = %m.config_socket.display(), "failed to connect to nos-configd");
            }
        }
        if *shutdown.borrow() {
            break;
        }
        if wait_or_shutdown(RECONNECT_DELAY, &mut shutdown).await {
            break;
        }
    }

    shutdown_all(instances, &m).await;
}

/// Reconciles against one connection's diff stream until it breaks or
/// `shutdown` fires. Returns `true` if it was shutdown (stop for good),
/// `false` if the stream ended and the caller should reconnect.
async fn follow<R>(
    mut reader: R,
    instances: &mut HashMap<String, InstanceHandle>,
    m: &Managed,
    shutdown: &mut watch::Receiver<bool>,
) -> bool
where
    R: futures::Stream<Item = std::io::Result<Event>> + Unpin,
{
    // The first event on a fresh connection is always synthesized against an
    // empty config (all-Added) — treat it as the authoritative full
    // membership list rather than an incremental change, so an object removed
    // while we were disconnected (and thus never seen as `Removed`) still
    // gets reconciled away instead of leaking as an orphan process.
    let mut first_event = true;
    loop {
        let event = tokio::select! {
            event = reader.next() => event,
            _ = shutdown.changed() => return true,
        };
        let diff = match event {
            Some(Ok(Event::Diff(diff))) => diff,
            Some(Ok(_)) => continue,
            Some(Err(e)) => {
                warn!(error = %e, "error reading diff stream, reconnecting");
                return false;
            }
            None => {
                warn!("diff stream closed, reconnecting");
                return false;
            }
        };
        let sections = (m.section)(&diff);
        if first_event {
            sync_from_initial(instances, sections, m).await;
            first_event = false;
        } else {
            apply_diff(instances, sections, m).await;
        }
    }
}

/// Whether `section` says its object currently wants a process under
/// `m.claim_label`: `Some(true)` = claimed, `Some(false)` = the label is
/// present but unset/removed, `None` = this section doesn't mention it.
/// Meaningless (and never called) when `m.claim_label` is `None`.
fn claim(m: &Managed, section: &SectionDiff) -> Option<bool> {
    let label = m.claim_label?;
    section
        .fields
        .iter()
        .find(|f| f.label == label)
        .map(|f| f.new.as_deref().is_some_and(|v| v != "unset"))
}

/// A section that is `Added` (or part of a fresh connection's initial
/// snapshot) wants a process unless this family is opt-in and unclaimed.
fn wanted_when_added(m: &Managed, section: &SectionDiff) -> bool {
    m.claim_label.is_none() || claim(m, section) == Some(true)
}

/// Reconciles the full set of currently-wanted names (all `Added` by
/// construction — see `manage`'s doc comment) against what's already
/// supervised: spawns anything missing, stops anything no longer wanted.
async fn sync_from_initial(
    instances: &mut HashMap<String, InstanceHandle>,
    sections: &[SectionDiff],
    m: &Managed,
) {
    let wanted: HashSet<&str> = sections
        .iter()
        .filter(|s| wanted_when_added(m, s))
        .map(|s| s.name.as_str())
        .collect();

    let stale: Vec<String> = instances
        .keys()
        .filter(|name| !wanted.contains(name.as_str()))
        .cloned()
        .collect();
    for name in stale {
        stop_instance(instances, &name, m).await;
    }

    for name in wanted {
        if !instances.contains_key(name) {
            spawn_instance(instances, name, m).await;
        }
    }
}

/// Applies an incremental diff on an unbroken connection: `Added` spawns if
/// missing (idempotent), `Removed` stops if present, `Modified` is a no-op at
/// this level — every one of these daemons independently subscribes to config
/// and re-resolves its own state on each relevant diff, so a parameter change
/// never needs a process restart here. The one exception is an opt-in family
/// (`claim_label`): `Modified` that flips the claim spawns or stops.
async fn apply_diff(
    instances: &mut HashMap<String, InstanceHandle>,
    sections: &[SectionDiff],
    m: &Managed,
) {
    for section in sections {
        match section.status {
            DiffStatus::Added => {
                if wanted_when_added(m, section) && !instances.contains_key(&section.name) {
                    spawn_instance(instances, &section.name, m).await;
                }
            }
            DiffStatus::Removed => stop_instance(instances, &section.name, m).await,
            DiffStatus::Modified => match claim(m, section) {
                Some(true) if !instances.contains_key(&section.name) => {
                    spawn_instance(instances, &section.name, m).await;
                }
                Some(false) => stop_instance(instances, &section.name, m).await,
                _ => {}
            },
        }
    }
}

async fn spawn_instance(instances: &mut HashMap<String, InstanceHandle>, name: &str, m: &Managed) {
    let mut args = vec![
        m.name_flag.to_string(),
        name.to_string(),
        "--watchdog-socket".to_string(),
        m.watchdog_listen_socket.display().to_string(),
        "--log-socket".to_string(),
        m.log_socket.display().to_string(),
    ];
    if let Some(endpoint) = &m.endpoint {
        let socket = PathBuf::from(format!("/run/nos/{}-{name}.sock", endpoint.socket_prefix));
        args.push("--listen-socket".to_string());
        args.push(socket.display().to_string());
        m.registry.set(endpoint.kind, name, socket).await;
    }
    args.extend(m.flags.iter().cloned());

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let spec = ProcessSpec::new(format!("{}[{name}]", m.daemon), m.bin.clone(), args)
        .with_identity(m.pki.clone(), m.role, name);
    info!(name = %name, "spawning {} for new {}", m.daemon, m.noun);
    let task = tokio::spawn(supervise_one(spec, m.policy, shutdown_rx));
    instances.insert(name.to_string(), InstanceHandle { shutdown_tx, task });
}

async fn stop_instance(instances: &mut HashMap<String, InstanceHandle>, name: &str, m: &Managed) {
    let Some(handle) = instances.remove(name) else {
        return;
    };
    info!(name = %name, "{} removed from config, stopping {}", m.noun, m.daemon);
    if let Some(endpoint) = &m.endpoint {
        m.registry.remove(endpoint.kind, name).await;
    }
    let _ = handle.shutdown_tx.send(true);
    let (name, daemon) = (name.to_string(), m.daemon);
    // Don't block reconciliation on this shutdown's up-to-10s grace period.
    tokio::spawn(async move {
        if let Err(e) = handle.task.await {
            warn!(name = %name, error = %e, "supervised {daemon} task panicked");
        }
    });
}

async fn shutdown_all(instances: HashMap<String, InstanceHandle>, m: &Managed) {
    let daemon = m.daemon;
    futures::future::join_all(instances.into_iter().map(|(name, h)| async move {
        let _ = h.shutdown_tx.send(true);
        if let Err(e) = h.task.await {
            warn!(name = %name, error = %e, "supervised {daemon} task panicked");
        }
    }))
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn managed(claim_label: Option<&'static str>) -> Managed {
        Managed {
            scope: DiffScope::RoutingTables,
            section: |d| &d.routing_tables,
            // Exits immediately; only the `instances` bookkeeping is under test.
            bin: PathBuf::from("/bin/true"),
            flags: Vec::new(),
            name_flag: "--table",
            daemon: "test-daemon",
            noun: "thing",
            endpoint: None,
            claim_label,
            config_socket: PathBuf::from("/nonexistent"),
            log_socket: PathBuf::from("/nonexistent"),
            watchdog_listen_socket: PathBuf::from("/nonexistent"),
            policy: BackoffPolicy::default(),
            registry: EndpointRegistry::default(),
            role: Role::Ribd,
            pki: Pki::start(
                tempfile::tempdir().unwrap().path(),
                Duration::from_secs(60),
                Duration::from_secs(30),
                Duration::from_secs(60),
            )
            .unwrap(),
        }
    }

    /// What a section says about the `rest-api` field.
    #[derive(Clone, Copy)]
    enum Claim {
        /// The section doesn't mention the field.
        Silent,
        /// Field present, new value `"unset"` (or any other text).
        Is(&'static str),
        /// Field present with no new value (the table was removed).
        Gone,
    }

    fn section(name: &str, status: DiffStatus, claim: Claim) -> SectionDiff {
        let new = match claim {
            Claim::Silent => None,
            Claim::Is(v) => Some(Some(v.to_string())),
            Claim::Gone => Some(None),
        };
        SectionDiff {
            header: format!("routing-table {name}"),
            name: name.to_string(),
            status,
            fields: new
                .map(|new| nos_proto::FieldDiff {
                    label: "rest-api".to_string(),
                    old: None,
                    new,
                })
                .into_iter()
                .collect(),
            subsections: Vec::new(),
        }
    }

    fn names(instances: &HashMap<String, InstanceHandle>) -> Vec<&str> {
        let mut n: Vec<&str> = instances.keys().map(String::as_str).collect();
        n.sort_unstable();
        n
    }

    #[tokio::test]
    async fn opt_in_family_follows_the_claim_field() {
        let m = managed(Some("rest-api"));
        let mut inst = HashMap::new();

        // Initial snapshot: only the claimed table gets a process.
        sync_from_initial(
            &mut inst,
            &[
                section("rt1", DiffStatus::Added, Claim::Is("10.0.0.1:8080")),
                section("rt2", DiffStatus::Added, Claim::Is("unset")),
            ],
            &m,
        )
        .await;
        assert_eq!(names(&inst), ["rt1"]);

        // Flip on an existing table spawns; flip off stops; unrelated
        // modification changes nothing.
        apply_diff(
            &mut inst,
            &[section(
                "rt2",
                DiffStatus::Modified,
                Claim::Is("10.0.0.2:80"),
            )],
            &m,
        )
        .await;
        assert_eq!(names(&inst), ["rt1", "rt2"]);
        apply_diff(
            &mut inst,
            &[section("rt1", DiffStatus::Modified, Claim::Is("unset"))],
            &m,
        )
        .await;
        assert_eq!(names(&inst), ["rt2"]);
        apply_diff(
            &mut inst,
            &[section("rt2", DiffStatus::Modified, Claim::Silent)],
            &m,
        )
        .await;
        assert_eq!(names(&inst), ["rt2"]);

        // A table added already-claimed spawns; removal stops.
        apply_diff(
            &mut inst,
            &[section("rt3", DiffStatus::Added, Claim::Is("[::1]:80"))],
            &m,
        )
        .await;
        apply_diff(
            &mut inst,
            &[section("rt2", DiffStatus::Removed, Claim::Gone)],
            &m,
        )
        .await;
        assert_eq!(names(&inst), ["rt3"]);

        shutdown_all(inst, &m).await;
    }

    #[tokio::test]
    async fn family_without_claim_label_still_spawns_per_section() {
        let m = managed(None);
        let mut inst = HashMap::new();
        apply_diff(
            &mut inst,
            &[section("rt1", DiffStatus::Added, Claim::Silent)],
            &m,
        )
        .await;
        apply_diff(
            &mut inst,
            &[section("rt1", DiffStatus::Modified, Claim::Is("unset"))],
            &m,
        )
        .await;
        assert_eq!(names(&inst), ["rt1"]);
        shutdown_all(inst, &m).await;
    }
}
