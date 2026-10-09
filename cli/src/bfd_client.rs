use std::net::IpAddr;
use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_proto::{BfdEvent, BfdRequest, BfdSessionView, IpcCodec, ReflectorView, Role};
use thiserror::Error;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum BfdClientError {
    #[error("could not connect to nos-bfdd at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-bfdd closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-bfdd: {0}")]
    Io(#[from] std::io::Error),
    #[error("nos-bfdd sent an unexpected reply: {0}")]
    UnexpectedReply(&'static str),
}

/// Sends one request and returns the one reply.
async fn ask(bfd_socket: &Path, request: BfdRequest) -> Result<BfdEvent, BfdClientError> {
    let stream = nos_pki::connect(bfd_socket, Role::Bfdd, "")
        .await
        .map_err(|source| BfdClientError::Connect {
            path: bfd_socket.to_path_buf(),
            source,
        })?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<BfdEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<BfdRequest>::default());
    writer.send(request).await?;
    match reader.next().await {
        Some(Ok(event)) => Ok(event),
        Some(Err(e)) => Err(BfdClientError::Io(e)),
        None => Err(BfdClientError::ConnectionClosed),
    }
}

/// Fetches every session `nos-bfdd` holds, or only those to `peer`.
pub async fn get_sessions(
    bfd_socket: &Path,
    peer: Option<IpAddr>,
) -> Result<Vec<BfdSessionView>, BfdClientError> {
    match ask(bfd_socket, BfdRequest::GetSessions { peer }).await? {
        BfdEvent::Sessions(sessions) => Ok(sessions),
        _ => Err(BfdClientError::UnexpectedReply("reply to GetSessions")),
    }
}

/// Fetches the S-BFD reflector's discriminators and counters.
pub async fn get_reflector(bfd_socket: &Path) -> Result<ReflectorView, BfdClientError> {
    match ask(bfd_socket, BfdRequest::GetReflector).await? {
        BfdEvent::Reflector(v) => Ok(v),
        _ => Err(BfdClientError::UnexpectedReply("reply to GetReflector")),
    }
}
