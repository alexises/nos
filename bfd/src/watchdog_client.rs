//! Broker lookups: where `nos-ribd` of a table listens, and its VRF device.

use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, RibEvent, RibRequest, Role, ServiceRef, WatchdogEvent, WatchdogRequest};
use tokio::sync::watch;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::warn;

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

/// Resolves `service`, retrying every second until it works or `shutdown`
/// fires.
pub async fn resolve_with_retry(
    watchdog_socket: &Path,
    service: ServiceRef,
    shutdown: &mut watch::Receiver<bool>,
) -> Option<PathBuf> {
    loop {
        if let Some(path) = resolve_once(watchdog_socket, &service).await {
            return Some(path);
        }
        warn!(service = ?service, "failed to resolve endpoint via nos-watchdogd, retrying");
        tokio::select! {
            () = tokio::time::sleep(RETRY_DELAY) => {}
            _ = shutdown.changed() => if *shutdown.borrow() { return None },
        }
    }
}

/// The Linux VRF device of routing table `table`, `None` while `nos-ribd`
/// is unreachable or has not created it.
pub async fn vrf_name(watchdog_socket: &Path, table: &str) -> Option<String> {
    let rib = resolve_once(watchdog_socket, &ServiceRef::RibTable(table.to_string())).await?;
    let stream = nos_pki::connect_role(&rib, Role::Ribd).await.ok()?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<RibEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<RibRequest>::default());
    writer.send(RibRequest::GetVrfName).await.ok()?;
    match reader.next().await {
        Some(Ok(RibEvent::VrfName(name))) => name,
        _ => None,
    }
}
