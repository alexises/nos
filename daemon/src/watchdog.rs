//! Endpoint resolution through `nos-watchdogd`'s broker socket.

use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, Role, ServiceRef, WatchdogEvent, WatchdogRequest};
use tokio::sync::watch;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::warn;

/// Fixed retry delay, matching every other reconnect/resolve loop.
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// One-shot resolve of `service` against `nos-watchdogd`'s broker socket.
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
/// delay, no backoff) until it succeeds or `shutdown` fires, in which case
/// `None` is returned.
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

async fn wait_or_shutdown(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_endpoint() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("w.sock");
        let listener = nos_pki::testing::shared()
            .identity("watchdog", "")
            .listen(&p)
            .unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
            let (r, w) = tokio::io::split(stream);
            let mut reader = FramedRead::new(r, IpcCodec::<WatchdogRequest>::default());
            let mut writer = FramedWrite::new(w, IpcCodec::<WatchdogEvent>::default());
            let _ = reader.next().await;
            let _ = writer
                .send(WatchdogEvent::Endpoint(PathBuf::from("/x.sock")))
                .await;
        });
        assert_eq!(
            resolve_once(&p, &ServiceRef::Config).await,
            Some(PathBuf::from("/x.sock"))
        );
    }

    #[tokio::test]
    async fn refused_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("nope.sock");
        assert_eq!(resolve_once(&p, &ServiceRef::Config).await, None);
    }

    #[tokio::test]
    async fn retry_stops_on_shutdown() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("nope.sock");
        let (tx, mut rx) = watch::channel(false);
        let t =
            tokio::spawn(async move { resolve_with_retry(&p, ServiceRef::Config, &mut rx).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        tx.send(true).unwrap();
        assert_eq!(t.await.unwrap(), None);
    }
}
