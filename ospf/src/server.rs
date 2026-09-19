use std::path::Path;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, OspfEvent, OspfRequest};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{error, info, trace, warn};

use crate::link::LinkManager;

/// Binds `listen_socket` and spawns the IPC accept loop for neighbor
/// summaries. Mirrors `bgp::server::start`.
///
/// Returns a `JoinHandle` the caller must keep alive for the server to run.
pub fn start(
    listen_socket: &Path,
    instance: String,
    links: Arc<LinkManager>,
) -> std::io::Result<JoinHandle<()>> {
    if listen_socket.exists() {
        std::fs::remove_file(listen_socket)?;
    }
    let listener = UnixListener::bind(listen_socket)?;
    info!(instance = %instance, socket = %listen_socket.display(), "OSPF IPC server listening");
    Ok(tokio::spawn(accept_loop(listener, instance, links)))
}

async fn accept_loop(listener: UnixListener, instance: String, links: Arc<LinkManager>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_connection(stream, instance.clone(), links.clone()));
            }
            Err(e) => {
                error!(instance = %instance, error = %e, "OSPF IPC accept loop terminated");
                break;
            }
        }
    }
}

async fn handle_connection(
    stream: tokio::net::UnixStream,
    instance: String,
    links: Arc<LinkManager>,
) {
    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, IpcCodec::<OspfRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<OspfEvent>::default());

    while let Some(msg) = reader.next().await {
        let req = match msg {
            Ok(req) => req,
            Err(e) => {
                warn!(instance = %instance, error = %e, "OSPF IPC read error");
                break;
            }
        };
        trace!(instance = %instance, request = ?req, "serving OSPF query");
        match req {
            OspfRequest::GetNeighbors => {
                let event = OspfEvent::Neighbors(links.neighbor_summaries().await);
                if writer.send(event).await.is_err() {
                    break;
                }
            }
            OspfRequest::GetDatabase => {
                let event = OspfEvent::Database(links.database_summaries().await);
                if writer.send(event).await.is_err() {
                    break;
                }
            }
            OspfRequest::RedistributeRoutes(update) => {
                links.apply_redistribute_update(update).await;
            }
        }
    }
}
