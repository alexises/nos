use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_proto::{AclEvent, AclRequest, AclStatus, IpcCodec, Role};
use thiserror::Error;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum AclClientError {
    #[error("could not connect to nos-acld at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-acld closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-acld: {0}")]
    Io(#[from] std::io::Error),
}

/// Fetches every ACL (or the named one, empty when unknown) with its counters.
pub async fn show(acl_socket: &Path, name: Option<&str>) -> Result<Vec<AclStatus>, AclClientError> {
    let stream = nos_pki::connect(acl_socket, Role::Acld, "")
        .await
        .map_err(|source| AclClientError::Connect {
            path: acl_socket.to_path_buf(),
            source,
        })?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<AclEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<AclRequest>::default());
    writer
        .send(AclRequest::Show {
            name: name.map(Into::into),
        })
        .await?;
    match reader.next().await {
        Some(Ok(AclEvent::Acls(acls))) => Ok(acls),
        Some(Err(e)) => Err(AclClientError::Io(e)),
        None => Err(AclClientError::ConnectionClosed),
    }
}
