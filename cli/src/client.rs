use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_proto::{Config, Event, IpcCodec, Request};
use thiserror::Error;
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("could not connect to nos-configd at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-configd closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-configd: {0}")]
    Io(#[from] std::io::Error),
    #[error("nos-configd reported an error: {0}")]
    Daemon(String),
}

/// Dials the daemon, sends a one-shot `Request::Get`, and returns the snapshot.
pub async fn fetch_running_config(socket_path: &Path) -> Result<Config, ClientError> {
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|source| ClientError::Connect {
            path: socket_path.to_path_buf(),
            source,
        })?;
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, IpcCodec::<Event>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<Request>::default());

    writer.send(Request::Get).await?;

    match reader.next().await {
        Some(Ok(Event::Config(cfg))) => Ok(cfg),
        Some(Ok(Event::Error(msg))) => Err(ClientError::Daemon(msg)),
        Some(Ok(Event::Saved)) => Err(ClientError::Daemon(
            "unexpected Saved event in reply to Get".to_string(),
        )),
        Some(Err(e)) => Err(ClientError::Io(e)),
        None => Err(ClientError::ConnectionClosed),
    }
}

/// Dials the daemon, sends a one-shot `Request::Save`, and waits for
/// confirmation that the running config was persisted to disk.
pub async fn save_running_config(socket_path: &Path) -> Result<(), ClientError> {
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|source| ClientError::Connect {
            path: socket_path.to_path_buf(),
            source,
        })?;
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, IpcCodec::<Event>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<Request>::default());

    writer.send(Request::Save).await?;

    match reader.next().await {
        Some(Ok(Event::Saved)) => Ok(()),
        Some(Ok(Event::Error(msg))) => Err(ClientError::Daemon(msg)),
        Some(Ok(Event::Config(_))) => Err(ClientError::Daemon(
            "unexpected Config event in reply to Save".to_string(),
        )),
        Some(Err(e)) => Err(ClientError::Io(e)),
        None => Err(ClientError::ConnectionClosed),
    }
}
