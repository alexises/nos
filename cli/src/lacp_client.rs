use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, LacpEvent, LacpRequest, PortAggregateLacpSummary, Role};
use thiserror::Error;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum LacpClientError {
    #[error("could not connect to nos-lacpd at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-lacpd closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-lacpd: {0}")]
    Io(#[from] std::io::Error),
}

/// Fetches every `Lacp`-mode aggregate's current LACP state.
pub async fn get_summary(
    lacp_socket: &Path,
) -> Result<Vec<PortAggregateLacpSummary>, LacpClientError> {
    let stream = nos_pki::connect(lacp_socket, Role::Lacpd, "")
        .await
        .map_err(|source| LacpClientError::Connect {
            path: lacp_socket.to_path_buf(),
            source,
        })?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<LacpEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<LacpRequest>::default());
    writer.send(LacpRequest::GetSummary).await?;
    match reader.next().await {
        Some(Ok(LacpEvent::Summary(summaries))) => Ok(summaries),
        Some(Err(e)) => Err(LacpClientError::Io(e)),
        None => Err(LacpClientError::ConnectionClosed),
    }
}
