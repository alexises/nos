use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, Role, ServiceRef, WatchdogEvent, WatchdogRequest};
use tokio::sync::watch;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::warn;

/// Fixed retry delay, matching this crate's `reconcile::RECONNECT_DELAY` and
/// `nos-watchdog`'s own reconnect policy for config subscriptions.
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// One-shot resolve of `service` against `nos-watchdogd`'s broker socket —
/// no retry, `None` on any failure (connect error, decode error,
/// `WatchdogEvent::NotAvailable`). Used by the Linux interface driver
/// (`driver::linux`) to resolve a routing table's owning `nos-ribd`
/// instance on every reconcile pass, where "not available yet" is an
/// expected, frequently-recurring condition (e.g. that table's `nos-ribd`
/// hasn't started, or was just removed) rather than something worth
/// retrying in a loop right here — the caller's own periodic re-apply tick
/// is what retries this, so this must return quickly either way.
pub async fn resolve_once(watchdog_socket: &Path, service: &ServiceRef) -> Option<PathBuf> {
    let stream = nos_pki::connect(watchdog_socket, Role::Watchdog, "")
        .await
        .ok()?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<WatchdogEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<WatchdogRequest>::default());
    writer
        .send(WatchdogRequest::ResolveEndpoint {
            service: service.clone(),
        })
        .await
        .ok()?;
    match reader.next().await {
        Some(Ok(WatchdogEvent::Endpoint(path))) => Some(path),
        _ => None,
    }
}

/// Resolves `service` against `nos-watchdogd`, retrying forever (fixed 1s
/// delay, no backoff — matching every other reconnect loop in this
/// codebase) until it succeeds or `shutdown` fires, in which case `None` is
/// returned.
pub async fn resolve_with_retry(
    watchdog_socket: &Path,
    service: ServiceRef,
    shutdown: &mut watch::Receiver<bool>,
) -> Option<PathBuf> {
    loop {
        if let Some(path) = resolve_once(watchdog_socket, &service).await {
            return Some(path);
        }
        warn!(
            socket = %watchdog_socket.display(),
            service = ?service,
            "failed to resolve endpoint via nos-watchdogd, retrying"
        );
        if wait_or_shutdown(RETRY_DELAY, shutdown).await {
            return None;
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
