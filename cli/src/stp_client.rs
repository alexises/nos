use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, Role, StpEvent, StpRequest, StpSummary};
use thiserror::Error;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum StpClientError {
    #[error("could not connect to nos-stpd at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-stpd closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-stpd: {0}")]
    Io(#[from] std::io::Error),
}

/// Fetches the bridge and every port's spanning-tree state.
pub async fn get_summary(stp_socket: &Path) -> Result<StpSummary, StpClientError> {
    let stream = nos_pki::connect(stp_socket, Role::Stpd, "")
        .await
        .map_err(|source| StpClientError::Connect {
            path: stp_socket.to_path_buf(),
            source,
        })?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<StpEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<StpRequest>::default());
    writer.send(StpRequest::GetSummary).await?;
    match reader.next().await {
        Some(Ok(StpEvent::Summary(s))) => Ok(s),
        Some(Err(e)) => Err(StpClientError::Io(e)),
        None => Err(StpClientError::ConnectionClosed),
    }
}
