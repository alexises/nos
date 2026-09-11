use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_proto::{Config, Event, IpcCodec, Request};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{RwLock, broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, warn};

/// Where the IPC server binds.
///
/// Parsed from a string: tries `SocketAddr` first (IPv4 or IPv6); if that
/// fails the whole string is used as a Unix socket path (absolute or relative).
///
/// Examples:
///   `127.0.0.1:9000`          → TCP
///   `[::1]:9000`              → TCP (IPv6)
///   `/run/nos/config.sock`    → Unix (absolute)
///   `config.sock`             → Unix (relative to CWD)
#[derive(Debug, Clone)]
pub enum ListenAddr {
    Unix(PathBuf),
    Tcp(SocketAddr),
}

impl FromStr for ListenAddr {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Ok(ListenAddr::Tcp(addr));
        }
        Ok(ListenAddr::Unix(PathBuf::from(s)))
    }
}

impl fmt::Display for ListenAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ListenAddr::Tcp(addr) => write!(f, "{addr}"),
            ListenAddr::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

/// Binds the given address and spawns the IPC accept loop.
///
/// Returns a `JoinHandle` the caller must keep alive for the server to run.
pub fn start(
    addr: &ListenAddr,
    running: Arc<RwLock<Config>>,
    tx: broadcast::Sender<Arc<Config>>,
) -> std::io::Result<JoinHandle<()>> {
    match addr {
        ListenAddr::Unix(path) => {
            if path.exists() {
                std::fs::remove_file(path)?;
            }
            let listener = UnixListener::bind(path)?;
            Ok(tokio::spawn(accept_loop_unix(listener, running, tx)))
        }
        ListenAddr::Tcp(addr) => {
            // TcpListener::bind is async, so we bind inside the spawned task.
            let addr = *addr;
            Ok(tokio::spawn(async move {
                match TcpListener::bind(addr).await {
                    Ok(listener) => accept_loop_tcp(listener, running, tx).await,
                    Err(e) => warn!("IPC TCP bind error: {e}"),
                }
            }))
        }
    }
}

async fn accept_loop_unix(
    listener: UnixListener,
    running: Arc<RwLock<Config>>,
    tx: broadcast::Sender<Arc<Config>>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_connection(stream, Arc::clone(&running), tx.clone()));
            }
            Err(e) => {
                warn!("IPC accept error: {e}");
                break;
            }
        }
    }
}

async fn accept_loop_tcp(
    listener: TcpListener,
    running: Arc<RwLock<Config>>,
    tx: broadcast::Sender<Arc<Config>>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_connection(stream, Arc::clone(&running), tx.clone()));
            }
            Err(e) => {
                warn!("IPC TCP accept error: {e}");
                break;
            }
        }
    }
}

async fn handle_connection<S>(
    stream: S,
    running: Arc<RwLock<Config>>,
    broadcast_tx: broadcast::Sender<Arc<Config>>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<Request>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<Event>::default());

    // mpsc bridges the broadcast channel to this connection so we never hold
    // a &mut borrow across select! arms.
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
                        if let Some(h) = sub_task.take() { h.abort(); }

                        let mut bcast_rx = broadcast_tx.subscribe();
                        let forward_tx = sub_tx.clone();
                        sub_task = Some(tokio::spawn(async move {
                            loop {
                                match bcast_rx.recv().await {
                                    Ok(cfg) => {
                                        if forward_tx.send(cfg).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(broadcast::error::RecvError::Lagged(n)) => {
                                        warn!("IPC subscriber lagged by {n} messages");
                                    }
                                    Err(broadcast::error::RecvError::Closed) => break,
                                }
                            }
                        }));

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
                    None => break,
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
