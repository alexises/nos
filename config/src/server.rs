use std::fmt;
use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::str::FromStr;

use futures::{SinkExt, StreamExt};
use nos_proto::{Event, IpcCodec, Request};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, error, info, warn};

use crate::store::{CommitUpdate, ConfigStore};

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
            info!(listen = %addr, "config IPC server listening");
            Ok(tokio::spawn(accept_loop_unix(listener, store)))
        }
        ListenAddr::Tcp(addr) => {
            // TcpListener::bind is async, so we bind inside the spawned task.
            let addr = *addr;
            Ok(tokio::spawn(async move {
                match TcpListener::bind(addr).await {
                    Ok(listener) => {
                        info!(listen = %addr, "config IPC server listening");
                        accept_loop_tcp(listener, store).await;
                    }
                    Err(e) => error!(error = %e, listen = %addr, "IPC TCP bind failed"),
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
                error!(error = %e, "IPC accept loop terminated");
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
                error!(error = %e, "IPC TCP accept loop terminated");
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
            Err(e) => {
                warn!(error = %e, "save to disk failed");
                Event::Error(e.to_string())
            }
        },
        Request::OpenTransaction { name, base } => {
            Event::Transaction(store.open_transaction(&name, base).await)
        }
        Request::ApplyOp { name, op } => match store.apply_op(&name, op).await {
            Ok(snap) => Event::Transaction(snap),
            Err(e) => {
                debug!(transaction = %name, error = %e, "apply op failed");
                Event::Error(e.to_string())
            }
        },
        Request::GetTransaction { name } => match store.get_transaction(&name).await {
            Ok(snap) => Event::Transaction(snap),
            Err(e) => {
                debug!(transaction = %name, error = %e, "get transaction failed");
                Event::Error(e.to_string())
            }
        },
        Request::CommitTransaction { name } => match store.commit_transaction(&name).await {
            Ok(()) => Event::Committed,
            Err(e) => {
                warn!(transaction = %name, error = %e, "commit failed");
                Event::Error(e.to_string())
            }
        },
        Request::DiscardTransaction { name } => match store.discard_transaction(&name).await {
            Ok(()) => Event::Discarded,
            Err(e) => {
                debug!(transaction = %name, error = %e, "discard transaction failed");
                Event::Error(e.to_string())
            }
        },
        Request::Describe { topic } => Event::Description(crate::docs::command_doc(topic)),
        Request::DiffTransaction { name } => match store.diff_transaction(&name).await {
            Ok(diff) => Event::Diff(diff),
            Err(e) => {
                debug!(transaction = %name, error = %e, "diff transaction failed");
                Event::Error(e.to_string())
            }
        },
        Request::SetTransactionPath { name, path, value } => {
            match store
                .set_transaction_path(&name, &path, value.as_deref())
                .await
            {
                Ok(snap) => Event::Transaction(snap),
                Err(e) => {
                    debug!(transaction = %name, error = %e, "set transaction path failed");
                    Event::Error(e.to_string())
                }
            }
        }
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
        // Each arm only decides *what* happened; the work of acting on it
        // lives in `on_request` below, so this stays a two-line dispatch.
        tokio::select! {
            msg = reader.next(), if reader_open => {
                let req = match msg {
                    Some(Ok(req)) => req,
                    other => {
                        if let Some(Err(e)) = other {
                            warn!(error = %e, "IPC read error");
                        }
                        if sub_task.is_none() {
                            break;
                        }
                        reader_open = false;
                        continue;
                    }
                };
                let flow =
                    on_request(req, &store, &mut writer, &sub_tx, &mut sub_task).await;
                if flow.is_break() {
                    break;
                }
            }
            Some(event) = sub_rx.recv() => {
                if writer.send(event).await.is_err() {
                    break;
                }
            }
        }
    }

    set_forwarder(&mut sub_task, None);
}

/// Handles one request, replying on `writer`. `Break` means the client is
/// gone (a write failed) and the connection should close.
async fn on_request<S>(
    req: Request,
    store: &ConfigStore,
    writer: &mut FramedWrite<tokio::io::WriteHalf<S>, IpcCodec<Event>>,
    sub_tx: &mpsc::Sender<Event>,
    sub_task: &mut Option<JoinHandle<()>>,
) -> ControlFlow<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let reply = match req {
        Request::Subscribe => {
            let forwarder = spawn_forwarder(store, sub_tx.clone(), |u| {
                Some(Event::Config(u.config.clone()))
            });
            set_forwarder(sub_task, Some(forwarder));
            debug!("IPC client subscribed");
            Event::Config(store.running_snapshot().await)
        }
        Request::SubscribeDiff { scopes } => {
            let task_scopes = scopes.clone();
            let forwarder = spawn_forwarder(store, sub_tx.clone(), move |u| {
                let scoped = u.diff.scoped(&task_scopes);
                (!scoped.is_empty()).then_some(Event::Diff(scoped))
            });
            set_forwarder(sub_task, Some(forwarder));
            debug!(?scopes, "IPC client subscribed to diff");
            Event::Diff(store.initial_diff().await.scoped(&scopes))
        }
        Request::Unsubscribe => {
            set_forwarder(sub_task, None);
            debug!("IPC client unsubscribed");
            return ControlFlow::Continue(());
        }
        req => match dispatch_request(store, req).await {
            Some(reply) => reply,
            None => return ControlFlow::Continue(()),
        },
    };
    match writer.send(reply).await {
        Ok(()) => ControlFlow::Continue(()),
        Err(_) => ControlFlow::Break(()),
    }
}

/// Installs this connection's forwarder task, aborting whichever one it
/// replaces — `None` both unsubscribes and tears the connection down.
fn set_forwarder(slot: &mut Option<JoinHandle<()>>, next: Option<JoinHandle<()>>) {
    if let Some(previous) = std::mem::replace(slot, next) {
        previous.abort();
    }
}

/// Bridges the store's commit broadcast to one connection's `mpsc`, so the
/// connection loop never holds a `&mut` borrow across `select!` arms.
/// `to_event` builds the event this subscriber wants from each commit, and
/// returning `None` skips it — which is how a `SubscribeDiff` subscriber is
/// never woken for a commit outside its scopes.
fn spawn_forwarder(
    store: &ConfigStore,
    tx: mpsc::Sender<Event>,
    to_event: impl Fn(&CommitUpdate) -> Option<Event> + Send + 'static,
) -> JoinHandle<()> {
    let mut bcast_rx = store.subscribe();
    tokio::spawn(async move {
        loop {
            match bcast_rx.recv().await {
                Ok(update) => {
                    let Some(event) = to_event(&update) else {
                        continue;
                    };
                    if tx.send(event).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(lagged = n, "IPC subscriber lagged, dropped messages");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}
