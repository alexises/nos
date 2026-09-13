use std::path::Path;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, PrefixRoutes, RibEvent, RibRequest, RouteEntry, RouteSourceKind};
use tokio::net::UnixListener;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::warn;

use crate::driver::RibDriver;
use crate::rib::{Rib, RibEntry, RouteSource};

/// Shared, read-only context every connection dispatches against: the
/// table's in-memory `Rib` (for `GetRoutes`/`Lookup`) and the driver
/// backing this instance (for `GetVrfName`, which asks the driver directly
/// rather than caching the answer — see `RibDriver::vrf_name`).
struct Context {
    table: String,
    rib: Arc<RwLock<Rib>>,
    driver: Arc<dyn RibDriver>,
}

/// Binds `listen_socket` and spawns the IPC accept loop for route queries.
///
/// Returns a `JoinHandle` the caller must keep alive for the server to run.
pub fn start(
    listen_socket: &Path,
    table: String,
    rib: Arc<RwLock<Rib>>,
    driver: Arc<dyn RibDriver>,
) -> std::io::Result<JoinHandle<()>> {
    if listen_socket.exists() {
        std::fs::remove_file(listen_socket)?;
    }
    let listener = UnixListener::bind(listen_socket)?;
    let ctx = Arc::new(Context { table, rib, driver });
    Ok(tokio::spawn(accept_loop(listener, ctx)))
}

async fn accept_loop(listener: UnixListener, ctx: Arc<Context>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_connection(stream, ctx.clone()));
            }
            Err(e) => {
                warn!("RIB IPC accept error: {e}");
                break;
            }
        }
    }
}

async fn handle_connection(stream: tokio::net::UnixStream, ctx: Arc<Context>) {
    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, IpcCodec::<RibRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<RibEvent>::default());

    while let Some(msg) = reader.next().await {
        let event = match msg {
            Ok(req) => dispatch(&ctx, req).await,
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

async fn dispatch(ctx: &Context, req: RibRequest) -> RibEvent {
    match req {
        RibRequest::GetRoutes => {
            let guard = ctx.rib.read().await;
            RibEvent::Routes(
                guard
                    .all_routes()
                    .into_iter()
                    .map(|(prefix, candidates)| to_prefix_routes(prefix, &candidates))
                    .collect(),
            )
        }
        RibRequest::Lookup { addr } => {
            let guard = ctx.rib.read().await;
            match guard.lookup(addr) {
                Some((prefix, candidates)) => {
                    RibEvent::Match(to_prefix_routes(prefix, &candidates))
                }
                None => RibEvent::NoMatch,
            }
        }
        RibRequest::GetVrfName => RibEvent::VrfName(ctx.driver.vrf_name(&ctx.table).await),
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
