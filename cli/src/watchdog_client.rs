use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, ServiceRef, WatchdogEvent, WatchdogRequest};
use thiserror::Error;
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum WatchdogClientError {
    #[error("could not connect to nos-watchdogd at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-watchdogd closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-watchdogd: {0}")]
    Io(#[from] std::io::Error),
}

/// Resolves `service` against `nos-watchdogd`'s broker socket. `Ok(None)`
/// means the broker is reachable but reports the service as not currently
/// available (e.g. the routing table isn't configured, or its `nos-ribd`
/// hasn't finished starting yet) — distinct from `Err`, which means the
/// broker itself couldn't be reached at all.
pub async fn resolve(
    watchdog_socket: &Path,
    service: ServiceRef,
) -> Result<Option<PathBuf>, WatchdogClientError> {
    let stream = UnixStream::connect(watchdog_socket)
        .await
        .map_err(|source| WatchdogClientError::Connect {
            path: watchdog_socket.to_path_buf(),
            source,
        })?;
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, IpcCodec::<WatchdogEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<WatchdogRequest>::default());
    writer
        .send(WatchdogRequest::ResolveEndpoint { service })
        .await?;
    match reader.next().await {
        Some(Ok(WatchdogEvent::Endpoint(path))) => Ok(Some(path)),
        Some(Ok(WatchdogEvent::NotAvailable)) => Ok(None),
        Some(Err(e)) => Err(WatchdogClientError::Io(e)),
        None => Err(WatchdogClientError::ConnectionClosed),
    }
}
