use std::path::Path;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, Ospfv3Event, Ospfv3Request};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{error, info, trace, warn};

use crate::link::LinkManager;

/// Binds `listen_socket` and spawns the IPC accept loop for neighbor/LSDB
/// summaries — mirrors `ospf::server::start`, minus `RedistributeRoutes`
/// (no ASBR in Phase 1).
pub fn start(
    listen_socket: &Path,
    instance: String,
    links: Arc<LinkManager>,
) -> std::io::Result<JoinHandle<()>> {
    if listen_socket.exists() {
        std::fs::remove_file(listen_socket)?;
    }
    let listener = UnixListener::bind(listen_socket)?;
    info!(instance = %instance, socket = %listen_socket.display(), "OSPFv3 IPC server listening");
    Ok(tokio::spawn(accept_loop(listener, instance, links)))
}

async fn accept_loop(listener: UnixListener, instance: String, links: Arc<LinkManager>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_connection(stream, instance.clone(), links.clone()));
            }
            Err(e) => {
                error!(instance = %instance, error = %e, "OSPFv3 IPC accept loop terminated");
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
