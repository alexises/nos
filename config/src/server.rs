use std::path::Path;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_proto::{Config, Event, IpcCodec, Request};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{RwLock, broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, warn};

/// Binds a Unix domain socket at `socket_path` and spawns the IPC accept loop.
///
/// Returns a `JoinHandle` the caller must keep alive for the server to run.
/// When the handle is dropped (or aborted), the server stops accepting new connections.
pub fn start(
    socket_path: &Path,
    running: Arc<RwLock<Config>>,
    tx: broadcast::Sender<Arc<Config>>,
) -> std::io::Result<JoinHandle<()>> {
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;

    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(handle_connection(
                        stream,
                        Arc::clone(&running),
                        tx.clone(),
                    ));
                }
                Err(e) => {
                    warn!("IPC accept error: {e}");
                    break;
                }
            }
        }
    });

    Ok(handle)
}

async fn handle_connection(
    stream: UnixStream,
    running: Arc<RwLock<Config>>,
    broadcast_tx: broadcast::Sender<Arc<Config>>,
) {
    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, IpcCodec::<Request>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<Event>::default());

    // mpsc channel that bridges the broadcast channel to this connection.
    // The sender is cloned into a spawned forwarder task on Subscribe; we keep the
    // receiver here so the select! loop can drain it without borrowing anything across arms.
    let (sub_tx, mut sub_rx) = mpsc::channel::<Arc<Config>>(16);
    let mut sub_task: Option<JoinHandle<()>> = None;

    loop {
        tokio::select! {
            msg = reader.next() => {
                match msg {
                    Some(Ok(Request::Get)) => {
                        let cfg = running.read().await.clone();
                        if writer.send(Event::Config(cfg)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Request::Subscribe)) => {
                        // Cancel any existing subscription forwarder.
                        if let Some(h) = sub_task.take() { h.abort(); }

                        // Spawn a task that forwards broadcast updates → mpsc.
                        let mut bcast_rx = broadcast_tx.subscribe();
                        let forward_tx = sub_tx.clone();
                        sub_task = Some(tokio::spawn(async move {
                            loop {
                                match bcast_rx.recv().await {
                                    Ok(cfg) => {
                                        if forward_tx.send(cfg).await.is_err() {
                                            break; // connection writer dropped
                                        }
                                    }
                                    Err(broadcast::error::RecvError::Lagged(n)) => {
                                        warn!("IPC subscriber lagged by {n} messages");
                                        // Continue — the next recv will return the latest value.
                                    }
                                    Err(broadcast::error::RecvError::Closed) => break,
                                }
                            }
                        }));

                        // Send the current snapshot as the initial event.
                        let cfg = running.read().await.clone();
                        if writer.send(Event::Config(cfg)).await.is_err() {
                            break;
                        }
                        debug!("IPC client subscribed");
                    }
                    Some(Ok(Request::Unsubscribe)) => {
                        if let Some(h) = sub_task.take() { h.abort(); }
                        debug!("IPC client unsubscribed");
                    }
                    Some(Err(e)) => {
                        warn!("IPC read error: {e}");
                        break;
                    }
                    None => break, // client closed connection
                }
            }
            Some(update) = sub_rx.recv() => {
                if writer.send(Event::Config((*update).clone())).await.is_err() {
                    break;
                }
            }
        }
    }

    if let Some(h) = sub_task { h.abort(); }
}
