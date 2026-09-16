use std::path::Path;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_proto::{
    BgpRouteUpdate, IpcCodec, PrefixRoutes, RibEvent, RibRequest, RouteEntry, RouteSourceKind,
};
use tokio::net::UnixListener;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{error, info, trace, warn};

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
    info!(table = %table, socket = %listen_socket.display(), "RIB IPC server listening");
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
                error!(table = %ctx.table, error = %e, "RIB IPC accept loop terminated");
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
                warn!(table = %ctx.table, error = %e, "RIB IPC read error");
                break;
            }
        };
        if let Some(event) = event {
            if writer.send(event).await.is_err() {
                break;
            }
        }
    }
}

async fn dispatch(ctx: &Context, req: RibRequest) -> Option<RibEvent> {
    trace!(table = %ctx.table, request = ?req, "serving RIB query");
    match req {
        RibRequest::GetRoutes => {
            let guard = ctx.rib.read().await;
            Some(RibEvent::Routes(
                guard
                    .all_routes()
                    .into_iter()
                    .map(|(prefix, candidates)| to_prefix_routes(prefix, &candidates))
                    .collect(),
            ))
        }
        RibRequest::Lookup { addr } => {
            let guard = ctx.rib.read().await;
            Some(match guard.lookup(addr) {
                Some((prefix, candidates)) => {
                    RibEvent::Match(to_prefix_routes(prefix, &candidates))
                }
                None => RibEvent::NoMatch,
            })
        }
        RibRequest::GetVrfName => Some(RibEvent::VrfName(ctx.driver.vrf_name(&ctx.table).await)),
        RibRequest::GetTableId => Some(RibEvent::TableId(ctx.driver.table_id(&ctx.table).await)),
        RibRequest::PushBgpRoutes(update) => {
            apply_bgp_route_update(ctx, update).await;
            None
        }
    }
}

/// Applies one BGP-pushed route update to the shared `Rib` and re-applies
/// the table's recomputed best routes to the kernel driver, independent of
/// `crate::reconcile::resync`'s own periodic apply — safe because `apply`
/// is already an idempotent dump-diff-converge operation, and the two
/// writers only ever touch disjoint `RouteSource` candidates (see
/// `Rib::replace_source`'s doc comment).
async fn apply_bgp_route_update(ctx: &Context, update: BgpRouteUpdate) {
    let mut guard = ctx.rib.write().await;
    match update {
        BgpRouteUpdate::Full(routes) => {
            guard.replace_source(
                RouteSource::Bgp,
                routes.into_iter().map(|r| RibEntry {
                    prefix: r.prefix,
                    gateway: r.next_hop,
                    source: RouteSource::Bgp,
                }),
            );
        }
        BgpRouteUpdate::Add(r) => guard.upsert(RibEntry {
            prefix: r.prefix,
            gateway: r.next_hop,
            source: RouteSource::Bgp,
        }),
        BgpRouteUpdate::Remove(prefix) => guard.remove(&prefix, RouteSource::Bgp),
    }
    let routes = guard.best_routes();
    drop(guard);

    info!(table = %ctx.table, prefixes = routes.len(), "applying bgp-pushed routes to kernel");
    if let Err(e) = ctx.driver.apply(&ctx.table, &routes).await {
        error!(table = %ctx.table, error = %e, "failed to apply bgp-pushed routes to kernel");
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
