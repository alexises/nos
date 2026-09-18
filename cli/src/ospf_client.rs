use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, NeighborSummary, OspfEvent, OspfRequest};
use thiserror::Error;
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum OspfClientError {
    #[error("could not connect to nos-ospfd at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-ospfd closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-ospfd: {0}")]
    Io(#[from] std::io::Error),
}

/// Fetches every configured link's current neighbor summary.
pub async fn get_neighbors(ospf_socket: &Path) -> Result<Vec<NeighborSummary>, OspfClientError> {
    let stream =
        UnixStream::connect(ospf_socket)
            .await
            .map_err(|source| OspfClientError::Connect {
                path: ospf_socket.to_path_buf(),
                source,
            })?;
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, IpcCodec::<OspfEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<OspfRequest>::default());
    writer.send(OspfRequest::GetNeighbors).await?;
    match reader.next().await {
        Some(Ok(OspfEvent::Neighbors(neighbors))) => Ok(neighbors),
        Some(Err(e)) => Err(OspfClientError::Io(e)),
        None => Err(OspfClientError::ConnectionClosed),
    }
}
