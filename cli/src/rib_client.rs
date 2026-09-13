use std::net::IpAddr;
use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, PrefixRoutes, RibEvent, RibRequest};
use thiserror::Error;
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum RibClientError {
    #[error("could not connect to nos-ribd at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-ribd closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-ribd: {0}")]
    Io(#[from] std::io::Error),
    #[error("nos-ribd reported an error: {0}")]
    Daemon(String),
}

async fn connect(
    rib_socket: &Path,
) -> Result<
    (
        FramedRead<tokio::net::unix::OwnedReadHalf, IpcCodec<RibEvent>>,
        FramedWrite<tokio::net::unix::OwnedWriteHalf, IpcCodec<RibRequest>>,
    ),
    RibClientError,
> {
    let stream =
        UnixStream::connect(rib_socket)
            .await
            .map_err(|source| RibClientError::Connect {
                path: rib_socket.to_path_buf(),
                source,
            })?;
    let (r, w) = stream.into_split();
    Ok((
        FramedRead::new(r, IpcCodec::<RibEvent>::default()),
        FramedWrite::new(w, IpcCodec::<RibRequest>::default()),
    ))
}

/// Fetches the whole table: every prefix, each with its full candidate list
/// ordered best to worst, prefixes in ascending CIDR order.
pub async fn get_routes(rib_socket: &Path) -> Result<Vec<PrefixRoutes>, RibClientError> {
    let (mut reader, mut writer) = connect(rib_socket).await?;
    writer.send(RibRequest::GetRoutes).await?;
    match reader.next().await {
        Some(Ok(RibEvent::Routes(routes))) => Ok(routes),
        Some(Ok(RibEvent::Error(msg))) => Err(RibClientError::Daemon(msg)),
        Some(Ok(_)) => Err(RibClientError::Daemon(
            "unexpected event in reply to GetRoutes".to_string(),
        )),
        Some(Err(e)) => Err(RibClientError::Io(e)),
        None => Err(RibClientError::ConnectionClosed),
    }
}

/// Longest-prefix-match lookup for one destination address. `Ok(None)` means
/// no configured prefix covers `addr` (no default route).
pub async fn lookup(
    rib_socket: &Path,
    addr: IpAddr,
) -> Result<Option<PrefixRoutes>, RibClientError> {
    let (mut reader, mut writer) = connect(rib_socket).await?;
    writer.send(RibRequest::Lookup { addr }).await?;
    match reader.next().await {
        Some(Ok(RibEvent::Match(routes))) => Ok(Some(routes)),
        Some(Ok(RibEvent::NoMatch)) => Ok(None),
        Some(Ok(RibEvent::Error(msg))) => Err(RibClientError::Daemon(msg)),
        Some(Ok(_)) => Err(RibClientError::Daemon(
            "unexpected event in reply to Lookup".to_string(),
        )),
        Some(Err(e)) => Err(RibClientError::Io(e)),
        None => Err(RibClientError::ConnectionClosed),
    }
}
