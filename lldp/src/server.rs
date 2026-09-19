//! Binds `--listen-socket` and serves `LldpRequest::GetNeighbors` from the live
//! neighbor tables — backs `nos-cli`'s `show lldp neighbors`. Mirrors
//! `nos-lacp`'s `server.rs`.

use std::path::Path;
use std::time::Instant;

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, LldpEvent, LldpNeighbor, LldpRequest};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{error, info, trace, warn};

use crate::link::SharedNeighbors;

pub fn start(listen_socket: &Path, neighbors: SharedNeighbors) -> std::io::Result<JoinHandle<()>> {
    if listen_socket.exists() {
        std::fs::remove_file(listen_socket)?;
    }
    let listener = UnixListener::bind(listen_socket)?;
    info!(socket = %listen_socket.display(), "lldp IPC server listening");
    Ok(tokio::spawn(accept_loop(listener, neighbors)))
}

async fn accept_loop(listener: UnixListener, neighbors: SharedNeighbors) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_connection(stream, neighbors.clone()));
            }
            Err(e) => {
                error!(error = %e, "lldp IPC accept loop terminated");
                break;
            }
        }
    }
}

async fn handle_connection(stream: tokio::net::UnixStream, neighbors: SharedNeighbors) {
    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, IpcCodec::<LldpRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<LldpEvent>::default());

    while let Some(msg) = reader.next().await {
        let event = match msg {
            Ok(LldpRequest::GetNeighbors) => {
                trace!("serving lldp neighbor query");
                LldpEvent::Neighbors(all_neighbors(&neighbors))
            }
            Err(e) => {
                warn!(error = %e, "lldp IPC read error");
                break;
            }
        };
        if writer.send(event).await.is_err() {
            break;
        }
    }
}

/// Every neighbor on every interface, ordered by interface then chassis then
/// port. The std mutex is released before any `.await` in the caller.
fn all_neighbors(neighbors: &SharedNeighbors) -> Vec<LldpNeighbor> {
    let now = Instant::now();
    let mut all: Vec<LldpNeighbor> = neighbors
        .lock()
        .unwrap()
        .iter()
        .flat_map(|(interface, table)| table.snapshot(interface, now))
        .collect();
    all.sort_by(|a, b| {
        (&a.local_interface, &a.chassis_id, &a.port_id).cmp(&(
            &b.local_interface,
            &b.chassis_id,
            &b.port_id,
        ))
    });
    all
}
