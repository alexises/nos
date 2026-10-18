//! Steady-state loop: subscribes to the config diff stream purely as a resync
//! trigger and always re-fetches the whole config, as `lacp::reconcile` does;
//! the result is the daemon's [`Plan`] (or none while STP is off).

use std::path::PathBuf;
use std::time::Duration;

use futures::StreamExt;
use nos_proto::{DiffScope, Event};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::ports::{self, Plan};

const RECONNECT_DELAY: Duration = Duration::from_secs(1);
/// Cheap insurance against a missed diff, as in `lacp::reconcile`.
const REAPPLY_INTERVAL: Duration = Duration::from_secs(10);

pub async fn run(
    config_socket: PathBuf,
    plan_tx: watch::Sender<Option<Plan>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let scopes = vec![
        DiffScope::SpanningTree,
        DiffScope::StpPortProfiles,
        DiffScope::Interfaces,
        DiffScope::PortAggregates,
        DiffScope::SwitchingProfiles,
        DiffScope::BroadcastDomains,
    ];
    while !*shutdown.borrow() {
        match nos_daemon::config::subscribe_diff(&config_socket, scopes.clone()).await {
            Ok(mut reader) => {
                info!(socket = %config_socket.display(), "connected to nos-configd diff stream");
                resync(&config_socket, &plan_tx).await;
                let mut reapply = tokio::time::interval(REAPPLY_INTERVAL);
                reapply.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                reapply.tick().await;
                loop {
                    tokio::select! {
                        event = reader.next() => match event {
                            Some(Ok(Event::Diff(_))) => resync(&config_socket, &plan_tx).await,
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
                        _ = reapply.tick() => resync(&config_socket, &plan_tx).await,
                        _ = shutdown.changed() => break,
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, socket = %config_socket.display(), "failed to connect to nos-configd");
            }
        }
        tokio::select! {
            () = tokio::time::sleep(RECONNECT_DELAY) => {}
            _ = shutdown.changed() => {}
        }
    }
    info!("stp reconciliation loop stopped");
}

async fn resync(config_socket: &std::path::Path, plan_tx: &watch::Sender<Option<Plan>>) {
    match nos_daemon::config::fetch_config(config_socket).await {
        Ok(cfg) => {
            let plan = ports::plan(&cfg);
            plan_tx.send_if_modified(|cur| {
                if *cur == plan {
                    return false;
                }
                *cur = plan;
                true
            });
        }
        Err(e) => warn!(error = %e, "failed to fetch running config, keeping previous state"),
    }
}
