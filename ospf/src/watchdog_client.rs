use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, ServiceRef, WatchdogEvent, WatchdogRequest};
use tokio::net::UnixStream;
use tokio::sync::watch;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::warn;

/// Fixed retry delay, matching every other reconnect/resolve loop in this
/// codebase (`nos-bgp`/`nos-rib`/`nos-interface`'s `watchdog_client::RETRY_DELAY`).
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// One-shot resolve of `service` against `nos-watchdogd`'s broker socket.
pub async fn resolve_once(watchdog_socket: &Path, service: &ServiceRef) -> Option<PathBuf> {
    let stream = UnixStream::connect(watchdog_socket).await.ok()?;
    let (r, w) = stream.into_split();
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
