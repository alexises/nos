use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_proto::{BgpEvent, BgpRequest, IpcCodec, PeerSummary};
use thiserror::Error;
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum BgpClientError {
    #[error("could not connect to nos-bgpd at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-bgpd closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-bgpd: {0}")]
    Io(#[from] std::io::Error),
}

async fn connect(
    bgp_socket: &Path,
) -> Result<
    (
        FramedRead<tokio::net::unix::OwnedReadHalf, IpcCodec<BgpEvent>>,
        FramedWrite<tokio::net::unix::OwnedWriteHalf, IpcCodec<BgpRequest>>,
    ),
    BgpClientError,
> {
    let stream =
        UnixStream::connect(bgp_socket)
            .await
            .map_err(|source| BgpClientError::Connect {
                path: bgp_socket.to_path_buf(),
                source,
            })?;
    let (r, w) = stream.into_split();
    Ok((
        FramedRead::new(r, IpcCodec::<BgpEvent>::default()),
        FramedWrite::new(w, IpcCodec::<BgpRequest>::default()),
    ))
}

/// Fetches every configured peer's current session summary.
pub async fn get_summary(bgp_socket: &Path) -> Result<Vec<PeerSummary>, BgpClientError> {
    let (mut reader, mut writer) = connect(bgp_socket).await?;
    writer.send(BgpRequest::GetSummary).await?;
    match reader.next().await {
        Some(Ok(BgpEvent::Summary(peers))) => Ok(peers),
        Some(Err(e)) => Err(BgpClientError::Io(e)),
        None => Err(BgpClientError::ConnectionClosed),
    }
}
