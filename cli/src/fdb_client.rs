use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_proto::{FdbEvent, FdbRequest, FdbTable, IpcCodec, Role};
use thiserror::Error;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum FdbClientError {
    #[error("could not connect to nos-fdbd at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-fdbd closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-fdbd: {0}")]
    Io(#[from] std::io::Error),
}

/// Fetches one broadcast domain's forwarding database from its `nos-fdbd`.
pub async fn get_table(fdb_socket: &Path) -> Result<FdbTable, FdbClientError> {
    let stream = nos_pki::connect_role(fdb_socket, Role::Fdbd)
        .await
        .map_err(|source| FdbClientError::Connect {
            path: fdb_socket.to_path_buf(),
            source,
        })?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<FdbEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<FdbRequest>::default());
    writer.send(FdbRequest::GetMacs).await?;
    match reader.next().await {
        Some(Ok(FdbEvent::Table(t))) => Ok(t),
        Some(Err(e)) => Err(FdbClientError::Io(e)),
        None => Err(FdbClientError::ConnectionClosed),
    }
}
