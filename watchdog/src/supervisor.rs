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
    /// `Some((uid, gid))`: the child runs as that user (set before exec, so
    /// its file capabilities still apply). `None`: it inherits ours.
    pub uid: Option<(u32, u32)>,
    /// Extra variables for this child only, applied after the scrubbed
    /// `CHILD_ENV` allowlist (which stays untouched for everyone else).
    pub env: Vec<(String, String)>,
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
            uid: None,
            env: Vec::new(),
        }
    }

    /// Adds one environment variable to this child (on top of the allowlist).
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// With `Some(gid)`, runs the child as its role's own uid (`uids::role_uid`)
    /// and group `gid`. Call after `with_identity`: the role is the key, so the
    /// uid cannot disagree with the certificate. `None`: inherit ours.
    #[must_use]
    pub fn with_role_uid(mut self, gid: Option<u32>) -> Self {
        let uid = self
            .identity
            .as_ref()
            .and_then(|i| crate::uids::role_uid(i.role));
        self.uid = uid.zip(gid);
        self
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

    /// The delay to wait after a run of `ran_for`: a run that survived
    /// `stable_after` decays the level one step (never straight to `base`, so
    /// a process crashing every 61 s stays near `max`); a rapid crash keeps it.
    #[must_use]
    pub fn next_delay(&self, current: Duration, ran_for: Duration) -> Duration {
        if ran_for >= self.stable_after {
            (current / self.multiplier.max(1)).max(self.base)
        } else {
            current
        }
    }
}

/// Environment variables a child inherits; everything else (`LD_PRELOAD`,
/// proxies, secrets) is dropped. Identity goes through stdin, not the env.
const CHILD_ENV: [&str; 4] = ["RUST_LOG", "PATH", "TZ", "NOS_LACP_CHURN_SECS"];

/// Keeps only the `CHILD_ENV` entries of `vars`.
fn allowed_env(
    vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    vars.filter(|(k, _)| CHILD_ENV.iter().any(|a| k == a))
        .collect()
}

/// Consecutive rapid crashes at which (and every 10th after) an alarm is logged.
const CRASH_LOOP_ALARM: u32 = 5;

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
    let mut consecutive_crashes: u32 = 0;

    while !*shutdown.borrow() {
        info!(
            process = %spec.name,
            program = %spec.program.display(),
            uid = spec.uid.map(|i| i.0),
            gid = spec.uid.map(|i| i.1),
            env = %spec.env.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(","),
            "starting"
        );
        let start = Instant::now();

        let mut command = Command::new(&spec.program);
        command.args(&spec.args);
        command.env_clear().envs(allowed_env(std::env::vars_os()));
        command.envs(spec.env.iter().cloned());
        if let Some((uid, gid)) = spec.uid {
            command.uid(uid).gid(gid);
        }
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

        // A stable run decays the backoff one step; a rapid one is a crash.
        let ran_for = start.elapsed();
        delay = policy.next_delay(delay, ran_for);
        if ran_for >= policy.stable_after {
            consecutive_crashes = 0;
        } else {
            consecutive_crashes += 1;
            if consecutive_crashes >= CRASH_LOOP_ALARM
                && (consecutive_crashes - CRASH_LOOP_ALARM).is_multiple_of(10)
            {
                error!(process = %spec.name, consecutive_crashes, "crash loop");
            }
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

#[cfg(test)]
mod backoff_tests {
    use super::*;

    const S: Duration = Duration::from_secs(1);

    #[test]
    fn rapid_crash_keeps_level_then_grows_to_max() {
        let p = BackoffPolicy::default();
        assert_eq!(p.next_delay(4 * S, 2 * S), 4 * S);
        let mut d = p.base;
        for _ in 0..10 {
            d = p.grow(d);
        }
        assert_eq!(d, p.max);
    }

    #[test]
    fn stable_run_decays_one_step_never_to_base_from_max() {
        let p = BackoffPolicy::default();
        assert_eq!(p.next_delay(p.max, 61 * S), 15 * S);
        assert_eq!(p.next_delay(p.base, 61 * S), p.base);
        // 61 s crash cycle at the cap: wait, grow, decay stays at 15 s.
        let mut d = p.max;
        for _ in 0..5 {
            d = p.next_delay(d, 61 * S);
            assert!(d > p.base);
            d = p.grow(d);
        }
    }

    #[test]
    fn with_role_uid_maps_the_role_and_defaults_to_none() {
        let pki = Pki::start(
            tempfile::tempdir().unwrap().path(),
            Duration::from_secs(60),
            Duration::from_secs(30),
            Duration::from_secs(60),
        )
        .unwrap();
        let s = ProcessSpec::new("x", "/bin/true", vec![]);
        assert_eq!(s.uid, None);
        let s = s.with_identity(pki, Role::Bgpd, "r1");
        assert_eq!(s.clone().with_role_uid(None).uid, None);
        assert_eq!(s.with_role_uid(Some(992)).uid, Some((10003, 992)));
        // No identity, no role, no uid.
        let bare = ProcessSpec::new("x", "/bin/true", vec![]);
        assert_eq!(bare.with_role_uid(Some(992)).uid, None);
    }

    /// A child spawned with our own uid/gid still runs (an unprivileged
    /// `setuid` to oneself is allowed), and the `starting` path takes it.
    #[tokio::test]
    async fn a_child_spawns_with_an_explicit_uid() {
        use std::os::unix::fs::MetadataExt;
        let me = std::fs::metadata("/proc/self").unwrap();
        let ids = (me.uid(), me.gid());
        let mut spec = ProcessSpec::new("t", "/bin/sleep", vec!["30".into()]);
        spec.uid = Some(ids);
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(supervise_one(spec, BackoffPolicy::default(), rx));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!task.is_finished(), "the child must be running");
        tx.send(true).unwrap();
        task.await.unwrap();
    }

    #[test]
    fn env_allow_list_drops_the_rest() {
        let v = |s: &str| std::ffi::OsString::from(s);
        let out = allowed_env(
            [
                ("LD_PRELOAD", "x"),
                ("HTTP_PROXY", "y"),
                ("RUST_LOG", "info"),
                ("PATH", "/bin"),
            ]
            .into_iter()
            .map(|(k, x)| (v(k), v(x))),
        );
        let keys: Vec<_> = out.iter().map(|(k, _)| k.to_str().unwrap()).collect();
        assert_eq!(keys, ["RUST_LOG", "PATH"]);
    }

    #[tokio::test]
    async fn with_env_reaches_the_child_only_when_asked() {
        async fn seen(spec: ProcessSpec, out: &std::path::Path) -> String {
            let (tx, rx) = watch::channel(false);
            let task = tokio::spawn(supervise_one(spec, BackoffPolicy::default(), rx));
            tokio::time::sleep(Duration::from_millis(500)).await;
            tx.send(true).unwrap();
            task.await.unwrap();
            std::fs::read_to_string(out)
                .unwrap_or_default()
                .trim()
                .to_string()
        }
        let dir = tempfile::tempdir().unwrap();
        let spec = |name: &str| {
            let out = dir.path().join(name);
            let args = vec![
                "-c".into(),
                format!(
                    "echo \"x${{MALLOC_ARENA_MAX}}\" > {}; exec sleep 30",
                    out.display()
                ),
            ];
            (ProcessSpec::new("t", "/bin/sh", args), out)
        };
        let (with, out) = spec("with");
        assert_eq!(
            seen(with.with_env("MALLOC_ARENA_MAX", "1"), &out).await,
            "x1"
        );
        let (without, out) = spec("without");
        assert_eq!(seen(without, &out).await, "x");
    }
}
