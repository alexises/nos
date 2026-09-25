use std::path::Path;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, Incoming, Listener, Stream};
use nos_proto::{IpcCodec, Ospfv3Event, Ospfv3Request, Role};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, error, info, trace, warn};

use crate::link::LinkManager;

/// Binds `listen_socket` and spawns the IPC accept loop for neighbor/LSDB
/// summaries — mirrors `ospf::server::start`, minus `RedistributeRoutes`
/// (no ASBR in Phase 1).
pub fn start(
    listen_socket: &Path,
    instance: String,
    links: Arc<LinkManager>,
    identity: &Identity,
) -> std::io::Result<JoinHandle<()>> {
    let listener = identity.listen(listen_socket)?;
    info!(instance = %instance, socket = %listen_socket.display(), "OSPFv3 IPC server listening");
    Ok(tokio::spawn(accept_loop(listener, instance, links)))
}

/// Every request here is a read-only query: for people, and `Restd` on their
/// behalf. Nothing else has a reason to ask, so nothing else gets in.
fn may_query(role: Role) -> bool {
    matches!(role, Role::User | Role::Restd)
}

async fn serve(incoming: Incoming, instance: String, links: Arc<LinkManager>) {
    match incoming.handshake_as(Role::parse).await {
        Ok((stream, role, _)) if may_query(role) => {
            handle_connection(stream, instance, links).await;
        }
        Ok((_, role, name)) => warn!(
            instance = %instance, role = role.as_str(), name = %name,
            "OSPFv3 query refused: this role may not send it"
        ),
        Err(e) => debug!(instance = %instance, error = %e, "OSPFv3 IPC handshake refused"),
    }
}

async fn accept_loop(listener: Listener, instance: String, links: Arc<LinkManager>) {
    loop {
        match listener.accept().await {
            Ok(incoming) => {
                tokio::spawn(serve(incoming, instance.clone(), links.clone()));
            }
            Err(e) => {
                error!(instance = %instance, error = %e, "OSPFv3 IPC accept loop terminated");
                break;
            }
        }
    }
}

async fn handle_connection(stream: Stream, instance: String, links: Arc<LinkManager>) {
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<Ospfv3Request>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<Ospfv3Event>::default());

    while let Some(msg) = reader.next().await {
        let req = match msg {
            Ok(req) => req,
            Err(e) => {
                warn!(instance = %instance, error = %e, "OSPFv3 IPC read error");
                break;
            }
        };
        trace!(instance = %instance, request = ?req, "serving OSPFv3 query");
        match req {
            Ospfv3Request::GetNeighbors => {
                let event = Ospfv3Event::Neighbors(links.neighbor_summaries().await);
                if writer.send(event).await.is_err() {
                    break;
                }
            }
            Ospfv3Request::GetDatabase => {
                let event = Ospfv3Event::Database(links.database_summaries().await);
                if writer.send(event).await.is_err() {
                    break;
                }
            }
        }
    }
}
