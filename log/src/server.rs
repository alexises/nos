use std::path::Path;

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, LogEvent, LogRequest};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, error, info, trace, warn};

use crate::store::LogStore;

/// Binds `listen_socket` and spawns the IPC accept loop.
///
/// Returns a `JoinHandle` the caller must keep alive for the server to run.
pub fn start(listen_socket: &Path, store: LogStore) -> std::io::Result<JoinHandle<()>> {
    if listen_socket.exists() {
        std::fs::remove_file(listen_socket)?;
    }
    let listener = UnixListener::bind(listen_socket)?;
    info!(socket = %listen_socket.display(), "log IPC server listening");
    Ok(tokio::spawn(accept_loop(listener, store)))
}

async fn accept_loop(listener: UnixListener, store: LogStore) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_connection(stream, store.clone()));
            }
            Err(e) => {
                error!(error = %e, "log IPC accept loop terminated");
                break;
            }
        }
    }
}

/// Handles one connection for its whole lifetime. `Push` (sent continuously
/// by every other component process) gets no reply, so the loop just keeps
/// reading further requests on the same connection; `GetLogs` sends one
/// reply and the connection typically closes right after (the client's
/// choice, not enforced here); `Tail` sends one reply then switches into
/// streaming new entries from the store's broadcast channel until the
/// client's read side reports an error/EOF or a write to it fails.
async fn handle_connection(stream: tokio::net::UnixStream, store: LogStore) {
    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, IpcCodec::<LogRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<LogEvent>::default());

    while let Some(msg) = reader.next().await {
        let req = match msg {
            Ok(req) => req,
            Err(e) => {
                warn!(error = %e, "log IPC read error");
                break;
            }
        };
        match req {
            LogRequest::Push(entry) => store.record(entry).await,
            LogRequest::GetLogs { source, limit } => {
                let logs = store.snapshot(source.as_deref(), limit).await;
                trace!(source = ?source, limit = ?limit, count = logs.len(), "served GetLogs query");
                if writer.send(LogEvent::Logs(logs)).await.is_err() {
                    break;
                }
            }
            LogRequest::Tail { source } => {
                let logs = store.snapshot(source.as_deref(), None).await;
                if writer.send(LogEvent::Logs(logs)).await.is_err() {
                    break;
                }
                debug!(source = ?source, "log tail subscription started");
                let result = tail(&mut reader, &mut writer, &store, source.as_deref()).await;
                debug!("log tail subscription ended");
                if !result {
                    break;
                }
            }
        }
    }
}

/// Streams new matching entries to `writer` until the client disconnects
/// (a read error/EOF on `reader`, or a failed write). Returns `false` when
/// the connection should be torn down.
async fn tail(
    reader: &mut FramedRead<tokio::net::unix::OwnedReadHalf, IpcCodec<LogRequest>>,
    writer: &mut FramedWrite<tokio::net::unix::OwnedWriteHalf, IpcCodec<LogEvent>>,
    store: &LogStore,
    source: Option<&str>,
) -> bool {
    let mut rx = store.subscribe();
    loop {
        tokio::select! {
            entry = rx.recv() => match entry {
                Ok(entry) => {
                    if source.is_some_and(|s| entry.source != s) {
                        continue;
                    }
                    if writer.send(LogEvent::Line(entry)).await.is_err() {
                        return false;
                    }
                }
                // A slow subscriber that fell behind the broadcast channel's
                // capacity — resubscribing loses only the gap, not the
                // connection; a truly closed channel never happens while
                // `store` (and thus its `tail_tx`) is still alive.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "log tail subscriber lagged, entries dropped");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return false,
            },
            // Per this codebase's connection-lifecycle convention (see root
            // CLAUDE.md's "Endpoint broker"/`SubscribeDiff` notes), a
            // subscriber is only expected to send its request and never
            // write again — so any activity here at all (EOF, a read error,
            // or even an unexpected extra request) means it's time to tear
            // the connection down rather than keep tailing.
            _ = reader.next() => return false,
        }
    }
}
