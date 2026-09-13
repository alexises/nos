use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, LogEntry, LogEvent, LogRequest};
use thiserror::Error;
use tokio::net::unix::OwnedReadHalf;
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum LogClientError {
    #[error("could not connect to nos-logd at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-logd closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-logd: {0}")]
    Io(#[from] std::io::Error),
    #[error("nos-logd reported an error: {0}")]
    Daemon(String),
}

type Reader = FramedRead<OwnedReadHalf, IpcCodec<LogEvent>>;

async fn connect(
    log_socket: &Path,
) -> Result<
    (
        Reader,
        FramedWrite<tokio::net::unix::OwnedWriteHalf, IpcCodec<LogRequest>>,
    ),
    LogClientError,
> {
    let stream =
        UnixStream::connect(log_socket)
            .await
            .map_err(|source| LogClientError::Connect {
                path: log_socket.to_path_buf(),
                source,
            })?;
    let (r, w) = stream.into_split();
    Ok((
        FramedRead::new(r, IpcCodec::<LogEvent>::default()),
        FramedWrite::new(w, IpcCodec::<LogRequest>::default()),
    ))
}

/// Fetches a one-shot snapshot of the current buffer, optionally filtered by
/// `source` (exact match) and capped to the most recent `limit` entries.
pub async fn get_logs(
    log_socket: &Path,
    source: Option<String>,
    limit: Option<usize>,
) -> Result<Vec<LogEntry>, LogClientError> {
    let (mut reader, mut writer) = connect(log_socket).await?;
    writer.send(LogRequest::GetLogs { source, limit }).await?;
    match reader.next().await {
        Some(Ok(LogEvent::Logs(logs))) => Ok(logs),
        Some(Ok(LogEvent::Error(msg))) => Err(LogClientError::Daemon(msg)),
        Some(Ok(_)) => Err(LogClientError::Daemon(
            "unexpected event in reply to GetLogs".to_string(),
        )),
        Some(Err(e)) => Err(LogClientError::Io(e)),
        None => Err(LogClientError::ConnectionClosed),
    }
}

/// Opens a long-lived connection: sends `LogRequest::Tail { source }` and
/// returns the reader half for the caller to loop on indefinitely — the
/// current buffer as one `LogEvent::Logs`, then one `LogEvent::Line` per new
/// matching entry. Unlike `get_logs`, this connection is not one-shot — the
/// caller owns its lifetime, same as `client::subscribe`'s doc comment.
pub async fn tail(log_socket: &Path, source: Option<String>) -> Result<Reader, LogClientError> {
    let (reader, mut writer) = connect(log_socket).await?;
    writer.send(LogRequest::Tail { source }).await?;
    Ok(reader)
}
