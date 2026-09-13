use std::path::Path;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, PrefixRoutes, RibEvent, RibRequest, RouteEntry, RouteSourceKind};
use tokio::net::UnixListener;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::warn;

use crate::rib::{Rib, RibEntry, RouteSource};

/// Binds `listen_socket` and spawns the IPC accept loop for route queries.
///
/// Returns a `JoinHandle` the caller must keep alive for the server to run.
pub fn start(listen_socket: &Path, rib: Arc<RwLock<Rib>>) -> std::io::Result<JoinHandle<()>> {
    if listen_socket.exists() {
        std::fs::remove_file(listen_socket)?;
    }
    let listener = UnixListener::bind(listen_socket)?;
    Ok(tokio::spawn(accept_loop(listener, rib)))
}

async fn accept_loop(listener: UnixListener, rib: Arc<RwLock<Rib>>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_connection(stream, rib.clone()));
            }
            Err(e) => {
                warn!("RIB IPC accept error: {e}");
                break;
            }
        }
    }
}

async fn handle_connection(stream: tokio::net::UnixStream, rib: Arc<RwLock<Rib>>) {
    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, IpcCodec::<RibRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<RibEvent>::default());

    while let Some(msg) = reader.next().await {
        let event = match msg {
            Ok(req) => dispatch(&rib, req).await,
            Err(e) => {
                warn!("RIB IPC read error: {e}");
                break;
            }
        };
        if writer.send(event).await.is_err() {
            break;
        }
    }
}

async fn dispatch(rib: &Arc<RwLock<Rib>>, req: RibRequest) -> RibEvent {
    let guard = rib.read().await;
    match req {
        RibRequest::GetRoutes => RibEvent::Routes(
            guard
                .all_routes()
                .into_iter()
                .map(|(prefix, candidates)| to_prefix_routes(prefix, &candidates))
                .collect(),
        ),
        RibRequest::Lookup { addr } => match guard.lookup(addr) {
            Some((prefix, candidates)) => RibEvent::Match(to_prefix_routes(prefix, &candidates)),
            None => RibEvent::NoMatch,
        },
    }
}

fn to_prefix_routes(prefix: nos_proto::IpNet, candidates: &[RibEntry]) -> PrefixRoutes {
    PrefixRoutes {
        prefix,
        candidates: candidates
            .iter()
            .map(|e| RouteEntry {
                gateway: e.gateway,
                source: to_source_kind(e.source),
            })
            .collect(),
    }
}

fn to_source_kind(source: RouteSource) -> RouteSourceKind {
    match source {
        RouteSource::Static => RouteSourceKind::Static,
        RouteSource::Bgp => RouteSourceKind::Bgp,
    }
}
