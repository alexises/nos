use std::path::PathBuf;
use std::time::{Duration, Instant};

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tokio::process::{Child, Command};
use tokio::sync::watch;
use tracing::{error, info, warn};

/// One child process to keep running.
#[derive(Debug, Clone)]
pub struct ProcessSpec {
    pub name: String,
    pub program: PathBuf,
    pub args: Vec<String>,
}

impl ProcessSpec {
    pub fn new(name: impl Into<String>, program: impl Into<PathBuf>, args: Vec<String>) -> Self {
        Self {
            name: name.into(),
            program: program.into(),
            args,
        }
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
pub async fn supervise_one(
    spec: ProcessSpec,
    policy: BackoffPolicy,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut delay = policy.base;

    while !*shutdown.borrow() {
        info!(process = %spec.name, program = %spec.program.display(), "starting");
        let start = Instant::now();

        let mut child = match Command::new(&spec.program).args(&spec.args).spawn() {
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
            // Shutdown requested while the child was still running.
            shutdown_child(&spec.name, &mut child).await;
            return;
        }
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

/// Sleeps for `delay`, or returns early (`true`) if shutdown fires first.
async fn wait_or_shutdown(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
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
        let _ = signal::kill(pid, Signal::SIGINT);
    }

    if tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .is_ok()
    {
        info!(process = %name, "exited cleanly");
    } else {
        warn!(process = %name, "did not exit within 10s, killing");
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}
