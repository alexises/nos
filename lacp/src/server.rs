//! Binds `--listen-socket` and serves `LacpRequest::GetSummary` from the live
//! `AggregateManager`s — backs `nos-cli`'s `show lacp`. Mirrors
//! `interface::server`'s shape.

use std::path::Path;

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, LacpEvent, LacpRequest, PortAggregateLacpSummary};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{error, info, trace, warn};

use crate::reconcile::SharedAggregates;

pub fn start(
    listen_socket: &Path,
    aggregates: SharedAggregates,
) -> std::io::Result<JoinHandle<()>> {
    if listen_socket.exists() {
        std::fs::remove_file(listen_socket)?;
    }
    let listener = UnixListener::bind(listen_socket)?;
    info!(socket = %listen_socket.display(), "lacp IPC server listening");
    Ok(tokio::spawn(accept_loop(listener, aggregates)))
}

async fn accept_loop(listener: UnixListener, aggregates: SharedAggregates) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_connection(stream, aggregates.clone()));
            }
            Err(e) => {
                error!(error = %e, "lacp IPC accept loop terminated");
                break;
            }
        }
    }
}

async fn handle_connection(stream: tokio::net::UnixStream, aggregates: SharedAggregates) {
    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, IpcCodec::<LacpRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<LacpEvent>::default());

    while let Some(msg) = reader.next().await {
        let event = match msg {
            Ok(LacpRequest::GetSummary) => {
                trace!("serving lacp summary query");
                LacpEvent::Summary(summaries(&aggregates))
            }
            Err(e) => {
                warn!(error = %e, "lacp IPC read error");
                break;
            }
        };
        if writer.send(event).await.is_err() {
            break;
        }
    }
}

/// Every aggregate's summary, ordered by name. The std mutex is released
/// before any `.await` in the caller.
fn summaries(aggregates: &SharedAggregates) -> Vec<PortAggregateLacpSummary> {
    let mut all: Vec<PortAggregateLacpSummary> = aggregates
        .lock()
        .unwrap()
        .values()
        .map(|m| m.summary())
        .collect();
    all.sort_by(|a, b| a.aggregate.cmp(&b.aggregate));
    all
}
