use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use futures::{SinkExt, StreamExt};
use nos_proto::{Event, IpcCodec, Request};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, warn};

use crate::store::ConfigStore;

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
pub fn start(addr: &ListenAddr, store: ConfigStore) -> std::io::Result<JoinHandle<()>> {
    match addr {
        ListenAddr::Unix(path) => {
            if path.exists() {
                std::fs::remove_file(path)?;
            }
            let listener = UnixListener::bind(path)?;
            Ok(tokio::spawn(accept_loop_unix(listener, store)))
        }
        ListenAddr::Tcp(addr) => {
            // TcpListener::bind is async, so we bind inside the spawned task.
            let addr = *addr;
            Ok(tokio::spawn(async move {
                match TcpListener::bind(addr).await {
                    Ok(listener) => accept_loop_tcp(listener, store).await,
                    Err(e) => warn!("IPC TCP bind error: {e}"),
                }
            }))
        }
    }
}

async fn accept_loop_unix(listener: UnixListener, store: ConfigStore) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_connection(stream, store.clone()));
            }
            Err(e) => {
                warn!("IPC accept error: {e}");
                break;
            }
        }
    }
}

async fn accept_loop_tcp(listener: TcpListener, store: ConfigStore) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_connection(stream, store.clone()));
            }
            Err(e) => {
                warn!("IPC TCP accept error: {e}");
                break;
            }
        }
    }
}

/// Handles every `Request` variant except `Subscribe`/`Unsubscribe`, which
/// the caller manages itself since they control the connection's forwarder
/// task rather than producing a single reply `Event`.
async fn dispatch_request(store: &ConfigStore, req: Request) -> Option<Event> {
    Some(match req {
        Request::Get => Event::Config(store.running_snapshot().await),
        Request::Save => match store.save_to_disk().await {
            Ok(()) => Event::Saved,
            Err(e) => Event::Error(e.to_string()),
        },
        Request::OpenTransaction { name, base } => {
            Event::Transaction(store.open_transaction(&name, base).await)
        }
        Request::ApplyOp { name, op } => match store.apply_op(&name, op).await {
            Ok(snap) => Event::Transaction(snap),
            Err(e) => Event::Error(e.to_string()),
        },
        Request::GetTransaction { name } => match store.get_transaction(&name).await {
            Ok(snap) => Event::Transaction(snap),
            Err(e) => Event::Error(e.to_string()),
        },
        Request::CommitTransaction { name } => match store.commit_transaction(&name).await {
            Ok(()) => Event::Committed,
            Err(e) => Event::Error(e.to_string()),
        },
        Request::DiscardTransaction { name } => match store.discard_transaction(&name).await {
            Ok(()) => Event::Discarded,
            Err(e) => Event::Error(e.to_string()),
        },
        Request::Describe { topic } => Event::Description(crate::docs::command_doc(topic)),
        Request::DiffTransaction { name } => match store.diff_transaction(&name).await {
            Ok(diff) => Event::Diff(diff),
            Err(e) => Event::Error(e.to_string()),
        },
        Request::Subscribe | Request::Unsubscribe | Request::SubscribeDiff { .. } => return None,
    })
}

async fn handle_connection<S>(stream: S, store: ConfigStore)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<Request>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<Event>::default());

    // mpsc bridges the broadcast channel to this connection so we never hold
    // a &mut borrow across select! arms. The forwarder task builds the exact
    // `Event` to send (Config for Subscribe, Diff for SubscribeDiff), so this
    // channel is type-erased at the Event level rather than tied to one kind
    // of subscription.
    let (sub_tx, mut sub_rx) = mpsc::channel::<Event>(16);
    let mut sub_task: Option<JoinHandle<()>> = None;
    // A Subscribe/SubscribeDiff client is expected to send its request then
    // drop (or never touch again) its write half — "the caller owns its
    // lifetime" per `client::subscribe`'s doc comment — so seeing EOF/an
    // error on `reader` must not tear down the connection while a
    // subscription is active; it only means no further *requests* will
    // arrive. Once there is no active subscription, EOF/error does mean the
    // connection is genuinely done.
    let mut reader_open = true;

    loop {
        tokio::select! {
            msg = reader.next(), if reader_open => {
                match msg {
                    Some(Ok(Request::Subscribe)) => {
                        if let Some(h) = sub_task.take() { h.abort(); }

                        let mut bcast_rx = store.subscribe();
                        let forward_tx = sub_tx.clone();
                        sub_task = Some(tokio::spawn(async move {
                            loop {
                                match bcast_rx.recv().await {
                                    Ok(update) => {
                                        let event = Event::Config(update.config.clone());
                                        if forward_tx.send(event).await.is_err() {
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

                        let cfg = store.running_snapshot().await;
                        if writer.send(Event::Config(cfg)).await.is_err() {
                            break;
                        }
                        debug!("IPC client subscribed");
                    }
                    Some(Ok(Request::SubscribeDiff { scopes })) => {
                        if let Some(h) = sub_task.take() { h.abort(); }

                        let mut bcast_rx = store.subscribe();
                        let forward_tx = sub_tx.clone();
                        let task_scopes = scopes.clone();
                        sub_task = Some(tokio::spawn(async move {
                            loop {
                                match bcast_rx.recv().await {
                                    Ok(update) => {
                                        let scoped = update.diff.scoped(&task_scopes);
                                        if !scoped.is_empty()
                                            && forward_tx.send(Event::Diff(scoped)).await.is_err()
                                        {
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

                        let initial = store.initial_diff().await.scoped(&scopes);
                        if writer.send(Event::Diff(initial)).await.is_err() {
                            break;
                        }
                        debug!("IPC client subscribed to diff (scopes: {scopes:?})");
                    }
                    Some(Ok(Request::Unsubscribe)) => {
                        if let Some(h) = sub_task.take() { h.abort(); }
                        debug!("IPC client unsubscribed");
                    }
                    Some(Ok(req)) => {
                        if let Some(event) = dispatch_request(&store, req).await {
                            if writer.send(event).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        warn!("IPC read error: {e}");
                        if sub_task.is_none() {
                            break;
                        }
                        reader_open = false;
                    }
                    None => {
                        if sub_task.is_none() {
                            break;
                        }
                        reader_open = false;
                    }
                }
            }
            Some(event) = sub_rx.recv() => {
                if writer.send(event).await.is_err() {
                    break;
                }
            }
        }
    }

    if let Some(h) = sub_task {
        h.abort();
    }
}
