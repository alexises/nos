//! Polls the owning `nos-ribd` for IGP costs (`RibRequest::IgpCosts`) and
//! hands them to `BgpRib` for decision step (d) — see `BgpRib::set_igp`.
//! Polled, not subscribed, for the same reason as `rib_push_client`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use nos_proto::ServiceRef;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::rib_client::get_igp_costs;
use crate::session::SessionManager;
use crate::watchdog_client::resolve_once;

const POLL_INTERVAL: Duration = Duration::from_secs(2);

pub fn spawn(
    watchdog_socket: PathBuf,
    sessions: Arc<SessionManager>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while !*shutdown.borrow() {
            poll_once(&watchdog_socket, &sessions).await;
            tokio::select! {
                () = tokio::time::sleep(POLL_INTERVAL) => {}
                _ = shutdown.changed() => {}
            }
        }
    })
}

/// A failed poll (no table yet, ribd not up) keeps the last table: dropping
/// it would flip every decision on a transient error.
async fn poll_once(watchdog_socket: &std::path::Path, sessions: &SessionManager) {
    let (Some(table), _) = sessions.bgp_push_snapshot().await else {
        return;
    };
    let Some(socket) = resolve_once(watchdog_socket, &ServiceRef::RibTable(table)).await else {
        return;
    };
    if let Some(costs) = get_igp_costs(&socket).await {
        sessions
            .set_igp(costs.into_iter().collect::<HashMap<_, _>>())
            .await;
    }
}
