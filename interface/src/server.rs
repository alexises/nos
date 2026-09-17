use std::path::Path;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_proto::{InterfaceEvent, InterfaceRequest, InterfaceStatus, IpcCodec};
use tokio::net::UnixListener;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{error, info, trace, warn};

use crate::state::{InterfaceState, Interfaces};

/// Binds `listen_socket` and spawns the IPC accept loop for interface
/// queries.
///
/// Returns a `JoinHandle` the caller must keep alive for the server to run.
pub fn start(
    listen_socket: &Path,
    interfaces: Arc<RwLock<Interfaces>>,
) -> std::io::Result<JoinHandle<()>> {
    if listen_socket.exists() {
        std::fs::remove_file(listen_socket)?;
    }
    let listener = UnixListener::bind(listen_socket)?;
    info!(socket = %listen_socket.display(), "interface IPC server listening");
    Ok(tokio::spawn(accept_loop(listener, interfaces)))
}

async fn accept_loop(listener: UnixListener, interfaces: Arc<RwLock<Interfaces>>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_connection(stream, interfaces.clone()));
            }
            Err(e) => {
                error!(error = %e, "interface IPC accept loop terminated");
                break;
            }
        }
    }
}

async fn handle_connection(stream: tokio::net::UnixStream, interfaces: Arc<RwLock<Interfaces>>) {
    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, IpcCodec::<InterfaceRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<InterfaceEvent>::default());

    while let Some(msg) = reader.next().await {
        let event = match msg {
            Ok(req) => dispatch(&interfaces, req).await,
            Err(e) => {
                warn!(error = %e, "interface IPC read error");
                break;
            }
        };
        if writer.send(event).await.is_err() {
            break;
        }
    }
}

async fn dispatch(interfaces: &Arc<RwLock<Interfaces>>, req: InterfaceRequest) -> InterfaceEvent {
    trace!(request = ?req, "serving interface query");
    let guard = interfaces.read().await;
    match req {
        InterfaceRequest::GetInterfaces => {
            InterfaceEvent::Interfaces(guard.all().into_iter().map(to_status).collect())
        }
        InterfaceRequest::GetInterface { name } => match guard.get(&name) {
            Some(iface) => InterfaceEvent::Interface(to_status(iface.clone())),
            None => InterfaceEvent::NotFound,
        },
    }
}

fn to_status(iface: InterfaceState) -> InterfaceStatus {
    InterfaceStatus {
        name: iface.name,
        addresses: iface.addresses,
        routing_table: iface.routing_table,
        switching_profile: iface.switching_profile,
    }
}
