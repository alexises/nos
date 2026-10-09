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

/// 802.1Q `mcheck` on one port or all; returns how many ports matched.
pub async fn mcheck(stp_socket: &Path, interface: Option<String>) -> Result<u32, StpClientError> {
    match request(stp_socket, StpRequest::Mcheck { interface }).await? {
        StpEvent::Mcheck { ports } => Ok(ports),
        StpEvent::Summary(_) => Err(StpClientError::ConnectionClosed),
    }
}

/// Fetches the bridge and every port's spanning-tree state.
pub async fn get_summary(stp_socket: &Path) -> Result<StpSummary, StpClientError> {
    match request(stp_socket, StpRequest::GetSummary).await? {
        StpEvent::Summary(s) => Ok(s),
        StpEvent::Mcheck { .. } => Err(StpClientError::ConnectionClosed),
    }
}

async fn request(stp_socket: &Path, req: StpRequest) -> Result<StpEvent, StpClientError> {
    let stream = nos_pki::connect(stp_socket, Role::Stpd, "")
        .await
        .map_err(|source| StpClientError::Connect {
            path: stp_socket.to_path_buf(),
            source,
        })?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<StpEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<StpRequest>::default());
    writer.send(req).await?;
    match reader.next().await {
        Some(Ok(e)) => Ok(e),
        Some(Err(e)) => Err(StpClientError::Io(e)),
        None => Err(StpClientError::ConnectionClosed),
    }
}
