use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, WatchdogEvent, WatchdogRequest};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::warn;

use crate::registry::EndpointRegistry;

/// Binds `listen_socket` and spawns the accept loop for the endpoint-broker
/// IPC: any daemon or client can dial this socket to ask where to reach
/// another service, instead of assuming a hardcoded default.
///
/// Returns a `JoinHandle` the caller must keep alive for the server to run.
pub fn start(
    listen_socket: &Path,
    registry: EndpointRegistry,
    config_socket: PathBuf,
) -> std::io::Result<JoinHandle<()>> {
    if listen_socket.exists() {
        std::fs::remove_file(listen_socket)?;
    }
    let listener = UnixListener::bind(listen_socket)?;
    Ok(tokio::spawn(accept_loop(listener, registry, config_socket)))
}

async fn accept_loop(listener: UnixListener, registry: EndpointRegistry, config_socket: PathBuf) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_connection(
                    stream,
                    registry.clone(),
                    config_socket.clone(),
                ));
            }
            Err(e) => {
                warn!("broker IPC accept error: {e}");
                break;
            }
        }
    }
}

async fn handle_connection(
    stream: tokio::net::UnixStream,
    registry: EndpointRegistry,
    config_socket: PathBuf,
) {
    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, IpcCodec::<WatchdogRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<WatchdogEvent>::default());

    while let Some(msg) = reader.next().await {
        let event = match msg {
            Ok(WatchdogRequest::ResolveEndpoint { service }) => {
                match registry.resolve(&service, &config_socket).await {
                    Some(path) => WatchdogEvent::Endpoint(path),
                    None => WatchdogEvent::NotAvailable,
                }
            }
            Err(e) => {
                warn!("broker IPC read error: {e}");
                break;
            }
        };
        if writer.send(event).await.is_err() {
            break;
        }
    }
}
