use std::path::Path;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_proto::{BgpEvent, BgpRequest, IpcCodec};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{error, info, trace, warn};

use crate::collision::FsmCommand;
use crate::session::SessionManager;

/// Binds `listen_socket` and spawns the IPC accept loop for session
/// summaries.
///
/// Returns a `JoinHandle` the caller must keep alive for the server to run.
pub fn start(
    listen_socket: &Path,
    instance: String,
    sessions: Arc<SessionManager>,
) -> std::io::Result<JoinHandle<()>> {
    if listen_socket.exists() {
        std::fs::remove_file(listen_socket)?;
    }
    let listener = UnixListener::bind(listen_socket)?;
    info!(instance = %instance, socket = %listen_socket.display(), "BGP IPC server listening");
    Ok(tokio::spawn(accept_loop(listener, instance, sessions)))
}

async fn accept_loop(listener: UnixListener, instance: String, sessions: Arc<SessionManager>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_connection(
                    stream,
                    instance.clone(),
                    sessions.clone(),
                ));
            }
            Err(e) => {
                error!(instance = %instance, error = %e, "BGP IPC accept loop terminated");
                break;
            }
        }
    }
}

/// Handles one connection for its whole lifetime. `GetSummary` sends one
/// reply per request; `RedistributeRoutes` (sent continuously by `nos-ribd`
/// over one long-lived connection, mirroring `nos-logd`'s handling of
/// `LogRequest::Push`) gets no reply at all, so the loop just keeps reading
/// further requests on the same connection.
async fn handle_connection(
    stream: tokio::net::UnixStream,
    instance: String,
    sessions: Arc<SessionManager>,
) {
    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, IpcCodec::<BgpRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<BgpEvent>::default());

    while let Some(msg) = reader.next().await {
        let req = match msg {
            Ok(req) => req,
            Err(e) => {
                warn!(instance = %instance, error = %e, "BGP IPC read error");
                break;
            }
        };
        trace!(instance = %instance, request = ?req, "serving BGP query");
        match req {
            BgpRequest::GetSummary => {
                let event = BgpEvent::Summary(sessions.peer_summaries().await);
                if writer.send(event).await.is_err() {
                    break;
                }
            }
            BgpRequest::RedistributeRoutes(update) => {
                sessions.apply_redistribute_update(update).await;
            }
            BgpRequest::SendRouteRefresh { peer } => {
                let event = if sessions
                    .send_command(peer, FsmCommand::SendRouteRefresh)
                    .await
                {
                    BgpEvent::RouteRefreshSent
                } else {
                    BgpEvent::PeerNotFound
                };
                if writer.send(event).await.is_err() {
                    break;
                }
            }
        }
    }
}
