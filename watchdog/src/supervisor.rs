use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use nos_proto::Role;
use tokio::io::AsyncWriteExt;
#[allow(
    clippy::disallowed_types,
    reason = "the supervisor's whole job is spawning the daemons (#228)"
)]
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use nos_pki::Serial;

use crate::pki::Pki;

/// One child process to keep running.
#[derive(Debug, Clone)]
pub struct ProcessSpec {
    pub name: String,
    pub program: PathBuf,
    pub args: Vec<String>,
    /// `Some`: each spawn gets a fresh certificate identity down its stdin
    /// (and rotations after it). `None` only for tests that supervise
    /// `/bin/true`; every real daemon has one.
    pub identity: Option<SpawnIdentity>,
}

/// Which certificate a child is issued: `nos://<role>/<name>`.
#[derive(Clone)]
pub struct SpawnIdentity {
    pub pki: Arc<Pki>,
    pub role: Role,
    pub name: String,
}

impl std::fmt::Debug for SpawnIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.role.as_str(), self.name)
    }
}

impl ProcessSpec {
    pub fn new(name: impl Into<String>, program: impl Into<PathBuf>, args: Vec<String>) -> Self {
        Self {
            name: name.into(),
            program: program.into(),
            args,
            identity: None,
        }
    }

    #[must_use]
    pub fn with_identity(mut self, pki: Arc<Pki>, role: Role, name: impl Into<String>) -> Self {
        self.identity = Some(SpawnIdentity {
            pki,
            role,
            name: name.into(),
        });
        self
    }
}

/// Exponential backoff policy for respawns.
#[derive(Debug, Clone, Copy)]
pub struct BackoffPolicy {
    pub base: Duration,
    pub max: Duration,
    pub multiplier: u32,
    pub stable_after: Duration,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            max: Duration::from_secs(30),
            multiplier: 2,
            stable_after: Duration::from_secs(60),
        }
    }
}

impl BackoffPolicy {
    fn grow(&self, current: Duration) -> Duration {
        current.saturating_mul(self.multiplier).min(self.max)
    }
}

/// Supervises one child process: spawn, wait, restart with exponential
/// backoff, forever, until `shutdown` reports `true`.
#[allow(
    clippy::disallowed_types,
    reason = "the supervisor's whole job is spawning the daemons (#228)"
)]
pub async fn supervise_one(
    spec: ProcessSpec,
    policy: BackoffPolicy,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut delay = policy.base;

    while !*shutdown.borrow() {
        info!(process = %spec.name, program = %spec.program.display(), "starting");
        let start = Instant::now();

        let mut command = Command::new(&spec.program);
        command.args(&spec.args);
        if spec.identity.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                error!(process = %spec.name, error = %e, "failed to spawn");
                if wait_or_shutdown(delay, &mut shutdown).await {
                    return;
                }
                delay = policy.grow(delay);
                continue;
            }
        };
        let issued = Arc::new(Mutex::new(Vec::new()));
        let pusher = spec
            .identity
            .clone()
            .zip(child.stdin.take())
            .map(|(id, stdin)| push_identity(spec.name.clone(), id, stdin, issued.clone()));

        let child_exited = tokio::select! {
            status = child.wait() => {
                match status {
                    Ok(status) => warn!(process = %spec.name, %status, "exited"),
                    Err(e) => error!(process = %spec.name, error = %e, "wait() failed"),
                }
                true
            }
            _ = shutdown.changed() => false,
        };

        if !child_exited {
            // Shutdown requested while the child was still running — the
            // whole watchdog stopping, or this instance removed/unpinned.
            shutdown_child(&spec.name, &mut child).await;
            if let Some(p) = pusher {
                p.abort();
            }
            revoke_spawn(&spec, &issued);
            return;
        }
        if let Some(p) = pusher {
            p.abort(); // closes the dead child's pipe
        }
        // Before the backoff, so the replacement's first frame already
        // carries a CRL naming its predecessor's certificates.
        revoke_spawn(&spec, &issued);
        if *shutdown.borrow() {
            return;
        }

        // Reset backoff if the process ran long enough to be "stable";
        // otherwise this exit is treated as another rapid crash.
        if start.elapsed() >= policy.stable_after {
            delay = policy.base;
        }

        info!(process = %spec.name, delay_secs = delay.as_secs(), "restarting after backoff");
        if wait_or_shutdown(delay, &mut shutdown).await {
            return;
        }
        delay = policy.grow(delay);
    }
}

/// Revokes every certificate minted for one spawn of `spec`, now that its
/// process is gone. A key that outlives its process is only a liability.
fn revoke_spawn(spec: &ProcessSpec, issued: &Mutex<Vec<Serial>>) {
    if let Some(id) = &spec.identity {
        let serials = std::mem::take(&mut *issued.lock().unwrap_or_else(PoisonError::into_inner));
        id.pki.revoke(id.role, &id.name, serials);
    }
}

/// Delivers a child's identity down its stdin: the first frame right away, a
/// fresh leaf every `rotate_every`, and the current leaf again with the new
/// CRL whenever the CRL changes. The key travels only through this pipe:
/// never argv, environment or disk. Every leaf minted is recorded in `issued`
/// for `revoke_spawn`. Ends when the child stops reading (it exited) or the
/// supervisor aborts it.
fn push_identity(
    name: String,
    id: SpawnIdentity,
    mut stdin: ChildStdin,
    issued: Arc<Mutex<Vec<Serial>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut crl = id.pki.crl();
        let mut current = None;
        let mut rotate = true;
        let mut next_rotation = tokio::time::Instant::now();
        loop {
            if rotate {
                next_rotation += id.pki.rotate_every;
                match id.pki.mint(id.role, &id.name) {
                    Ok(bundle) => {
                        if let Ok(serial) = Serial::of(&bundle.cert) {
                            issued
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .push(serial);
                        }
                        current = Some(bundle);
                    }
                    Err(e) => warn!(process = %name, error = %e, "failed to mint an identity"),
                }
            }
            if let Some(bundle) = &mut current {
                bundle.crl.clone_from(&crl.borrow_and_update());
                if let Err(e) = stdin.write_all(&bundle.encode()).await {
                    debug!(process = %name, error = %e, "child no longer reads its identity");
                    return;
                }
            }
            tokio::select! {
                () = tokio::time::sleep_until(next_rotation) => rotate = true,
                changed = crl.changed() => {
                    if changed.is_err() {
                        return; // the Pki is gone: the watchdog is exiting
                    }
                    rotate = false;
                }
            }
        }
    })
}

/// Sleeps for `delay`, or returns early (`true`) if shutdown fires first.
pub(crate) async fn wait_or_shutdown(
    delay: Duration,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

/// Sends SIGINT (not SIGTERM — see main.rs doc comment), then force-kills
/// after a grace period if the child hasn't exited.
async fn shutdown_child(name: &str, child: &mut Child) {
    if let Some(pid) = child.id() {
        info!(process = %name, "sending SIGINT");
        let pid = Pid::from_raw(i32::try_from(pid).unwrap_or(i32::MAX));
        if let Err(e) = signal::kill(pid, Signal::SIGINT) {
            warn!(process = %name, error = %e, "failed to send SIGINT");
        }
    }

    if tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .is_ok()
    {
        info!(process = %name, "exited cleanly");
    } else {
        warn!(process = %name, "did not exit within 10s, killing");
        if let Err(e) = child.kill().await {
            warn!(process = %name, error = %e, "failed to force-kill process");
        }
        let _ = child.wait().await;
    }
}
