use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, LldpEvent, LldpNeighbor, LldpRequest, Role};
use thiserror::Error;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum LldpClientError {
    #[error("could not connect to nos-lldpd at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-lldpd closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-lldpd: {0}")]
    Io(#[from] std::io::Error),
}

/// Fetches every neighbor `nos-lldpd` currently knows, across every interface.
pub async fn get_neighbors(lldp_socket: &Path) -> Result<Vec<LldpNeighbor>, LldpClientError> {
    let stream = nos_pki::connect(lldp_socket, Role::Lldpd, "")
        .await
        .map_err(|source| LldpClientError::Connect {
            path: lldp_socket.to_path_buf(),
            source,
        })?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<LldpEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<LldpRequest>::default());
    writer.send(LldpRequest::GetNeighbors).await?;
    match reader.next().await {
        Some(Ok(LldpEvent::Neighbors(neighbors))) => Ok(neighbors),
        Some(Err(e)) => Err(LldpClientError::Io(e)),
        None => Err(LldpClientError::ConnectionClosed),
    }
}
