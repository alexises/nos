//! Keeps one sink per configured collector. Resolves `nos-configd` in the
//! background (startup never waits on it: every other daemon's log forwarder
//! needs `nos-logd` up first), reads the running config, then re-reads it on
//! every `Logging`/`Hostname` diff.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::StreamExt;
use nos_proto::{Config, DiffScope, ServiceRef, SyslogServer};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use super::client;
use super::sink::{self, SinkConfig};
use crate::LogStore;

const RETRY: Duration = Duration::from_secs(1);
/// How long a stopping TCP sink gets to send `FIN` before it is aborted.
const STOP_GRACE: Duration = Duration::from_secs(2);

/// What should be running for `cfg`: collector name → its settings and the
/// hostname its messages carry.
pub fn desired(cfg: &Config) -> HashMap<String, (SyslogServer, String)> {
    cfg.logging
        .syslog
        .iter()
        .map(|s| (s.name.clone(), (s.clone(), cfg.hostname.clone())))
        .collect()
}

/// Which sinks to stop and which to (re)start to get from `running` to `want`.
#[allow(clippy::implicit_hasher)] // only ever the std HashMap
pub fn plan<'a>(
    running: impl Iterator<Item = (&'a String, &'a (SyslogServer, String))>,
    want: &HashMap<String, (SyslogServer, String)>,
) -> (Vec<String>, Vec<String>) {
    let mut stop = Vec::new();
    let mut have = Vec::new();
    for (name, cur) in running {
        if want.get(name) == Some(cur) {
            have.push(name.clone());
        } else {
            stop.push(name.clone());
        }
    }
    let start = want.keys().filter(|n| !have.contains(n)).cloned().collect();
    (stop, start)
}

struct Running {
    spec: (SyslogServer, String),
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl Running {
    async fn stop(mut self) {
        let _ = self.stop.send(true);
        if tokio::time::timeout(STOP_GRACE, &mut self.task)
            .await
            .is_err()
        {
            self.task.abort();
        }
    }
}

pub async fn run(watchdog_socket: PathBuf, store: LogStore, mut shutdown: watch::Receiver<bool>) {
    let mut sinks: HashMap<String, Running> = HashMap::new();
    let mut last_error: Option<String> = None;
    'outer: loop {
        let Some(config_socket) = client::resolve(&watchdog_socket, ServiceRef::Config).await
        else {
            if wait(&mut shutdown).await {
                break;
            }
            continue;
        };
        let reader = client::subscribe_diff(
            &config_socket,
            vec![DiffScope::Logging, DiffScope::Hostname],
        )
        .await;
        let mut reader = match reader {
            Ok(r) => r,
            Err(e) => {
                // nos-configd may still be creating its socket: say so once.
                if last_error.as_deref() != Some(&e) {
                    warn!(error = %e, "syslog export: cannot subscribe to nos-configd");
                    last_error = Some(e);
                }
                if wait(&mut shutdown).await {
                    break;
                }
                continue;
            }
        };
        loop {
            match client::fetch_config(&config_socket).await {
                Ok(cfg) => apply(&mut sinks, &desired(&cfg), &watchdog_socket, &store).await,
                Err(e) => warn!(error = %e, "syslog export: cannot read the config"),
            }
            tokio::select! {
                ev = reader.next() => {
                    // Any event is just a reason to re-read the config; the
                    // subscription ending (nos-configd restarted) means
                    // resolving it again.
                    if !matches!(ev, Some(Ok(_))) {
                        if wait(&mut shutdown).await { break 'outer; }
                        continue 'outer;
                    }
                }
                _ = shutdown.changed() => break 'outer,
            }
        }
    }
    for (_, s) in sinks.drain() {
        s.stop().await;
    }
}

async fn apply(
    sinks: &mut HashMap<String, Running>,
    want: &HashMap<String, (SyslogServer, String)>,
    watchdog_socket: &Path,
    store: &LogStore,
) {
    let (stop, start) = plan(sinks.iter().map(|(n, r)| (n, &r.spec)), want);
    for name in stop {
        if let Some(s) = sinks.remove(&name) {
            s.stop().await;
        }
    }
    for name in start {
        let spec = want[&name].clone();
        info!(server = %name, address = %spec.0.address, "syslog export starting");
        let (stop_tx, stop_rx) = watch::channel(false);
        let cfg = SinkConfig {
            server: spec.0.clone(),
            hostname: spec.1.clone(),
            watchdog_socket: watchdog_socket.to_path_buf(),
        };
        let task = tokio::spawn(sink::run(cfg, store.clone(), stop_rx));
        sinks.insert(
            name,
            Running {
                spec,
                stop: stop_tx,
                task,
            },
        );
    }
}

/// Sleeps one retry delay; true if shutdown fired meanwhile.
async fn wait(shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(RETRY) => false,
        _ = shutdown.changed() => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(name: &str, port: Option<u16>) -> SyslogServer {
        SyslogServer {
            name: name.into(),
            port,
            ..SyslogServer::default()
        }
    }

    fn map(v: &[(&str, Option<u16>, &str)]) -> HashMap<String, (SyslogServer, String)> {
        v.iter()
            .map(|(n, p, h)| ((*n).to_string(), (s(n, *p), (*h).to_string())))
            .collect()
    }

    #[test]
    fn plan_starts_stops_and_restarts_on_change() {
        let running = map(&[("a", None, "h"), ("b", None, "h"), ("c", None, "h")]);
        let want = map(&[("a", None, "h"), ("b", Some(1), "h"), ("d", None, "h")]);
        let (mut stop, mut start) = plan(running.iter(), &want);
        stop.sort();
        start.sort();
        assert_eq!(stop, ["b", "c"]);
        assert_eq!(start, ["b", "d"]);
        // A hostname change restarts every sink (it is in every message).
        let want = map(&[("a", None, "new")]);
        let (stop, start) = plan(map(&[("a", None, "h")]).iter(), &want);
        assert_eq!(
            (stop, start),
            (vec!["a".to_string()], vec!["a".to_string()])
        );
    }

    #[test]
    fn desired_carries_the_hostname() {
        let mut cfg = Config {
            hostname: "r9".into(),
            ..Config::default()
        };
        cfg.logging.syslog = vec![s("a", None)];
        assert_eq!(desired(&cfg)["a"].1, "r9");
    }
}
