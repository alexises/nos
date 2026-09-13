use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_proto::{InterfaceEvent, InterfaceRequest, InterfaceStatus, IpcCodec};
use thiserror::Error;
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum InterfaceClientError {
    #[error("could not connect to nos-interfaced at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-interfaced closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-interfaced: {0}")]
    Io(#[from] std::io::Error),
    #[error("nos-interfaced reported an error: {0}")]
    Daemon(String),
}

async fn connect(
    interface_socket: &Path,
) -> Result<
    (
        FramedRead<tokio::net::unix::OwnedReadHalf, IpcCodec<InterfaceEvent>>,
        FramedWrite<tokio::net::unix::OwnedWriteHalf, IpcCodec<InterfaceRequest>>,
    ),
    InterfaceClientError,
> {
    let stream = UnixStream::connect(interface_socket)
        .await
        .map_err(|source| InterfaceClientError::Connect {
            path: interface_socket.to_path_buf(),
            source,
        })?;
    let (r, w) = stream.into_split();
    Ok((
        FramedRead::new(r, IpcCodec::<InterfaceEvent>::default()),
        FramedWrite::new(w, IpcCodec::<InterfaceRequest>::default()),
    ))
}

/// Fetches every configured interface's reconciled status.
pub async fn get_interfaces(
    interface_socket: &Path,
) -> Result<Vec<InterfaceStatus>, InterfaceClientError> {
    let (mut reader, mut writer) = connect(interface_socket).await?;
    writer.send(InterfaceRequest::GetInterfaces).await?;
    match reader.next().await {
        Some(Ok(InterfaceEvent::Interfaces(statuses))) => Ok(statuses),
        Some(Ok(_)) => Err(InterfaceClientError::Daemon(
            "unexpected event in reply to GetInterfaces".to_string(),
        )),
        Some(Err(e)) => Err(InterfaceClientError::Io(e)),
        None => Err(InterfaceClientError::ConnectionClosed),
    }
}

/// Fetches one named interface's reconciled status. `Ok(None)` means no such
/// interface is configured.
pub async fn get_interface(
    interface_socket: &Path,
    name: &str,
) -> Result<Option<InterfaceStatus>, InterfaceClientError> {
    let (mut reader, mut writer) = connect(interface_socket).await?;
    writer
        .send(InterfaceRequest::GetInterface {
            name: name.to_string(),
        })
        .await?;
    match reader.next().await {
        Some(Ok(InterfaceEvent::Interface(status))) => Ok(Some(status)),
        Some(Ok(InterfaceEvent::NotFound)) => Ok(None),
        Some(Ok(_)) => Err(InterfaceClientError::Daemon(
            "unexpected event in reply to GetInterface".to_string(),
        )),
        Some(Err(e)) => Err(InterfaceClientError::Io(e)),
        None => Err(InterfaceClientError::ConnectionClosed),
    }
}
