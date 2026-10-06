use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, Incoming, Listener};
use nos_proto::{
    BgpRouteUpdate, EvpnRouteInfo, EvpnUpdate, IpNet, IpcCodec, OspfRoute, OspfRouteUpdate,
    PrefixRoutes, RibEvent, RibRequest, Role, RouteEntry, RouteSourceKind,
};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, error, info, trace, warn};

use crate::driver::RibDriver;
use crate::evpn::EvpnState;
use crate::rib::{BestPathChange, Rib, RibEntry, RouteSource};

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
    identity: &Identity,
) -> std::io::Result<JoinHandle<()>> {
    let listener = identity.listen(listen_socket)?;
    info!(table = %table, socket = %listen_socket.display(), "RIB IPC server listening");
    let ctx = Arc::new(Context { table, rib, driver });
    Ok(tokio::spawn(accept_loop(listener, ctx)))
}

/// Who may send what. Route pushes are the sensitive part — they become
/// kernel routes — so each is reserved for the one daemon family that owns
/// that source. No wildcard arm: a new request must be classified.
// ponytail: role-level only. `bgpd/r2` could still push into `rt1`; binding
// an instance to its table needs a config lookup — add it if that matters.
fn allowed(role: Role, req: &RibRequest) -> bool {
    match req {
        RibRequest::GetRoutes | RibRequest::Lookup { .. } => {
            matches!(role, Role::User | Role::Restd)
        }
        // `ribd`/`fdbd` name a loopback VTEP's device (`lo<table id>`) of
        // the underlay table.
        // `logd` scopes a syslog collector's socket into its table's VRF.
        RibRequest::GetVrfName | RibRequest::GetTableId => matches!(
            role,
            Role::User
                | Role::Logd
                | Role::Restd
                | Role::Interfaced
                | Role::Bgpd
                | Role::Ospfd
                | Role::Ospfv3d
                | Role::Ribd
                | Role::Fdbd
        ),
        // `BgpRouteCount`: a restarted `nos-bgpd`'s graceful-restart check.
        RibRequest::PushBgpRoutes(_)
        | RibRequest::PushEvpnRoutes(_)
        | RibRequest::BgpRouteCount => role == Role::Bgpd,
        // `nos-ospfv3d` shares the OSPF route source: its SPF results are
        // pushed with the same request.
        RibRequest::PushOspfRoutes(_) => matches!(role, Role::Ospfd | Role::Ospfv3d),
        RibRequest::IgpCosts => matches!(role, Role::User | Role::Restd | Role::Bgpd),
        // Symmetric IRB: the `nos-fdbd` of a domain whose SVI is in this table.
        RibRequest::GetEvpnIrb => role == Role::Fdbd,
    }
}

async fn accept_loop(listener: Listener, ctx: Arc<Context>) {
    loop {
        match listener.accept().await {
            Ok(incoming) => {
                tokio::spawn(serve(incoming, ctx.clone()));
            }
            Err(e) => {
                error!(table = %ctx.table, error = %e, "RIB IPC accept loop terminated");
                break;
            }
        }
    }
}

async fn serve(incoming: Incoming, ctx: Arc<Context>) {
    match incoming.handshake_as(Role::parse).await {
        Ok((stream, role, name)) => handle_connection(stream, role, name, ctx).await,
        Err(e) => debug!(table = %ctx.table, error = %e, "RIB IPC handshake refused"),
    }
}

async fn handle_connection(stream: nos_pki::Stream, role: Role, name: String, ctx: Arc<Context>) {
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<RibRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<RibEvent>::default());

    while let Some(msg) = reader.next().await {
        let event = match msg {
            Ok(req) if !allowed(role, &req) => {
                warn!(
                    table = %ctx.table, role = role.as_str(), name = %name,
                    "RIB request refused: this role may not send it"
                );
                break;
            }
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
                    .map(|(prefix, candidates)| to_prefix_routes(prefix, &candidates, &guard.evpn))
                    .collect(),
            ))
        }
        RibRequest::Lookup { addr } => {
            let guard = ctx.rib.read().await;
            Some(match guard.lookup(addr) {
                Some((prefix, candidates)) => {
                    RibEvent::Match(to_prefix_routes(prefix, &candidates, &guard.evpn))
                }
                None => RibEvent::NoMatch,
            })
        }
        RibRequest::GetVrfName => Some(RibEvent::VrfName(ctx.driver.vrf_name(&ctx.table).await)),
        RibRequest::GetTableId => Some(RibEvent::TableId(ctx.driver.table_id(&ctx.table).await)),
        RibRequest::PushBgpRoutes(updates) => {
            apply_bgp_route_update(ctx, updates).await;
            None
        }
        RibRequest::PushOspfRoutes(updates) => {
            apply_ospf_route_update(ctx, updates).await;
            None
        }
        RibRequest::IgpCosts => Some(RibEvent::IgpCosts(ctx.rib.read().await.igp_costs())),
        RibRequest::BgpRouteCount => Some(RibEvent::BgpRouteCount(
            ctx.rib.read().await.count_source(RouteSource::Bgp),
        )),
        RibRequest::PushEvpnRoutes(update) => {
            apply_evpn_route_update(ctx, update).await;
            None
        }
        RibRequest::GetEvpnIrb => Some(RibEvent::EvpnIrb(ctx.rib.read().await.evpn.irb())),
    }
}

/// Applies one push of received Type-5 routes: the raw set is kept
/// (`EvpnState.received`), filtered into the `Evpn` candidates
/// (`Rib::refresh_evpn`), then the L3 VNI's remote VTEPs and the routes are
/// brought in line — the same two driver calls `reconcile::resync` ends with.
async fn apply_evpn_route_update(ctx: &Context, update: EvpnUpdate) {
    {
        let mut guard = ctx.rib.write().await;
        let received = &mut guard.evpn.received;
        match update {
            EvpnUpdate::Full(routes) => {
                *received = routes.into_iter().map(|r| (r.key.clone(), r)).collect();
            }
            EvpnUpdate::Add(r) => {
                received.insert(r.key.clone(), r);
            }
            EvpnUpdate::Remove(key) => {
                received.remove(&key);
            }
        }
        guard.refresh_evpn();
    }
    crate::reconcile::apply_to_kernel(&ctx.table, &ctx.rib, ctx.driver.as_ref()).await;
}

/// Applies one batch of BGP-pushed route updates (one poll tick's worth,
/// see `nos_proto::rib::RibRequest::PushBgpRoutes`) to the shared `Rib`,
/// independent of `crate::reconcile::resync`'s own periodic apply — safe
/// because the two writers only ever touch disjoint `RouteSource`
/// candidates (see `Rib::replace_source`'s doc comment). `Full` (rare —
/// only on BGP connect/reconnect/withdraw) goes through the driver's full
/// dump-diff-converge `apply`, since it replaces the whole `Bgp`-sourced
/// set at once. `Add`/`Remove` (the frequent per-route hot path) instead
/// recompute only the touched prefix's winning route (`Rib::upsert_and_diff`/
/// `remove_and_diff`) and, only for a prefix whose winner actually changed,
/// queue a delta applied directly via `apply_delta` — never a whole-table
/// recompute or a fresh kernel dump for an incremental push.
async fn apply_bgp_route_update(ctx: &Context, updates: Vec<BgpRouteUpdate>) {
    let mut guard = ctx.rib.write().await;
    let mut deltas: HashMap<IpNet, Option<RibEntry>> = HashMap::new();
    let mut full_replace = false;

    for update in updates {
        match update {
            BgpRouteUpdate::Full(routes) => {
                guard.replace_source(
                    RouteSource::Bgp,
                    routes.into_iter().map(|r| RibEntry {
                        prefix: r.prefix,
                        next_hops: r.next_hops.into_iter().map(|h| (h, None)).collect(),
                        source: RouteSource::Bgp,
                        backup: r.backup_next_hop,
                        backup_interface_id: None,
                    }),
                );
                full_replace = true;
            }
            BgpRouteUpdate::Add(r) => {
                let entry = RibEntry {
                    prefix: r.prefix,
                    next_hops: r.next_hops.iter().map(|&h| (h, None)).collect(),
                    source: RouteSource::Bgp,
                    backup: r.backup_next_hop,
                    backup_interface_id: None,
                };
                match guard.upsert_and_diff(entry) {
                    BestPathChange::Unchanged => {}
                    BestPathChange::Installed(e) => {
                        deltas.insert(r.prefix, Some(e));
                    }
                    BestPathChange::Removed => {
                        deltas.insert(r.prefix, None);
                    }
                }
            }
            BgpRouteUpdate::Remove(prefix) => {
                match guard.remove_and_diff(&prefix, RouteSource::Bgp) {
                    BestPathChange::Unchanged => {}
                    BestPathChange::Installed(e) => {
                        deltas.insert(prefix, Some(e));
                    }
                    BestPathChange::Removed => {
                        deltas.insert(prefix, None);
                    }
                }
            }
        }
    }

    if full_replace {
        let routes = guard.best_routes_for_kernel();
        drop(guard);
        info!(table = %ctx.table, prefixes = routes.len(), "applying bgp-pushed routes to kernel");
        if let Err(e) = ctx.driver.apply(&ctx.table, &routes).await {
            error!(table = %ctx.table, error = %e, "failed to apply bgp-pushed routes to kernel");
        }
    } else {
        drop(guard);
        if !deltas.is_empty() {
            info!(table = %ctx.table, changed = deltas.len(), "applying bgp route deltas to kernel");
            if let Err(e) = ctx.driver.apply_delta(&ctx.table, &deltas).await {
                error!(table = %ctx.table, error = %e, "failed to apply bgp route deltas to kernel");
            }
        }
    }
}

/// Applies one batch of OSPF-pushed route updates to the shared `Rib` — the
/// OSPF analogue of `apply_bgp_route_update` above, identical shape (`Full`
/// goes through the driver's full `apply`, `Add`/`Remove` recompute only the
/// touched prefix's winner and `apply_delta` just that), since the two
/// writers only ever touch disjoint `RouteSource` candidates.
async fn apply_ospf_route_update(ctx: &Context, updates: Vec<OspfRouteUpdate>) {
    let mut guard = ctx.rib.write().await;
    let mut deltas: HashMap<IpNet, Option<RibEntry>> = HashMap::new();
    let mut full_replace = false;

    for update in updates {
        match update {
            OspfRouteUpdate::Full(routes) => {
                guard.set_ospf_metrics(routes.iter().map(|r| (r.prefix, r.metric)));
                guard.replace_source(RouteSource::Ospf, routes.into_iter().map(ospf_entry));
                full_replace = true;
            }
            OspfRouteUpdate::Add(r) => {
                guard.set_ospf_metric(r.prefix, Some(r.metric));
                let prefix = r.prefix;
                match guard.upsert_and_diff(ospf_entry(r)) {
                    BestPathChange::Unchanged => {}
                    BestPathChange::Installed(e) => {
                        deltas.insert(prefix, Some(e));
                    }
                    BestPathChange::Removed => {
                        deltas.insert(prefix, None);
                    }
                }
            }
            OspfRouteUpdate::Remove(prefix) => {
                guard.set_ospf_metric(prefix, None);
                match guard.remove_and_diff(&prefix, RouteSource::Ospf) {
                    BestPathChange::Unchanged => {}
                    BestPathChange::Installed(e) => {
                        deltas.insert(prefix, Some(e));
                    }
                    BestPathChange::Removed => {
                        deltas.insert(prefix, None);
                    }
                }
            }
        }
    }

    if full_replace {
        let routes = guard.best_routes_for_kernel();
        drop(guard);
        info!(table = %ctx.table, prefixes = routes.len(), "applying ospf-pushed routes to kernel");
        if let Err(e) = ctx.driver.apply(&ctx.table, &routes).await {
            error!(table = %ctx.table, error = %e, "failed to apply ospf-pushed routes to kernel");
        }
    } else {
        drop(guard);
        if !deltas.is_empty() {
            info!(table = %ctx.table, changed = deltas.len(), "applying ospf route deltas to kernel");
            if let Err(e) = ctx.driver.apply_delta(&ctx.table, &deltas).await {
                error!(table = %ctx.table, error = %e, "failed to apply ospf route deltas to kernel");
            }
        }
    }
}

/// A pushed OSPF route as a `Rib` candidate: a discard route is one with no
/// next hop (and so no backup) — see `RibEntry::is_discard`.
fn ospf_entry(r: OspfRoute) -> RibEntry {
    RibEntry {
        prefix: r.prefix,
        next_hops: if r.discard { Vec::new() } else { r.next_hops },
        source: RouteSource::Ospf,
        backup: r.backup_next_hop.filter(|_| !r.discard),
        backup_interface_id: r.backup_interface_id,
    }
}

fn to_prefix_routes(
    prefix: nos_proto::IpNet,
    candidates: &[RibEntry],
    evpn: &EvpnState,
) -> PrefixRoutes {
    PrefixRoutes {
        prefix,
        candidates: candidates
            .iter()
            .map(|e| RouteEntry {
                gateways: e.next_hops.iter().map(|(gw, _)| *gw).collect(),
                source: to_source_kind(e.source),
                backup: e.backup,
                discard: e.is_discard(),
                evpn: evpn_info(e, evpn),
            })
            .collect(),
    }
}

/// `show route`'s view of an `Evpn` candidate: its VTEP, that PE's Router's
/// MAC and the L3 VNI.
fn evpn_info(e: &RibEntry, evpn: &EvpnState) -> Option<EvpnRouteInfo> {
    let vtep = e.next_hops.first()?.0;
    (e.source == RouteSource::Evpn).then(|| EvpnRouteInfo {
        vtep,
        router_mac: evpn
            .remotes
            .get(&vtep)
            .map(nos_proto::evpn_id::format_mac)
            .unwrap_or_default(),
        vni: evpn.local.as_ref().map_or(0, |l| l.vni),
    })
}

fn to_source_kind(source: RouteSource) -> RouteSourceKind {
    match source {
        RouteSource::Static => RouteSourceKind::Static,
        RouteSource::Bgp => RouteSourceKind::Bgp,
        RouteSource::Ospf => RouteSourceKind::Ospf,
        RouteSource::Connected => RouteSourceKind::Connected,
        RouteSource::Evpn => RouteSourceKind::Evpn,
    }
}

#[cfg(test)]
mod authz_tests {
    use super::*;

    #[test]
    fn a_discard_ospf_route_has_no_next_hop() {
        let route = OspfRoute {
            prefix: "10.9.0.0/16".parse().unwrap(),
            next_hops: vec![("10.0.0.1".parse().unwrap(), None)],
            backup_next_hop: Some("10.0.0.2".parse().unwrap()),
            backup_interface_id: None,
            metric: 3,
            discard: true,
        };
        let entry = ospf_entry(route.clone());
        assert!(entry.is_discard());
        assert_eq!(entry.backup, None);
        assert!(
            to_prefix_routes(entry.prefix, &[entry], &EvpnState::default()).candidates[0].discard
        );
        assert!(!ospf_entry(OspfRoute {
            discard: false,
            ..route
        })
        .is_discard());
    }

    #[test]
    fn an_evpn_candidate_shows_its_router_mac_and_vni() {
        let vtep: std::net::IpAddr = "10.50.0.3".parse().unwrap();
        let entry = RibEntry {
            prefix: "10.2.0.0/24".parse().unwrap(),
            next_hops: vec![(vtep, None)],
            source: RouteSource::Evpn,
            backup: None,
            backup_interface_id: None,
        };
        let evpn = EvpnState {
            remotes: [(vtep, [2, 0, 0, 0, 0, 3])].into(),
            ..EvpnState::default()
        };
        let shown = to_prefix_routes(entry.prefix, &[entry], &evpn);
        let info = shown.candidates[0].evpn.as_ref().unwrap();
        assert_eq!(shown.candidates[0].source, RouteSourceKind::Evpn);
        assert_eq!(
            (info.vtep, info.router_mac.as_str()),
            (vtep, "02:00:00:00:00:03")
        );
    }

    #[test]
    fn only_the_owning_daemon_family_may_push_routes() {
        for role in Role::ALL {
            assert_eq!(
                allowed(role, &RibRequest::PushBgpRoutes(vec![])),
                role == Role::Bgpd
            );
            assert_eq!(
                allowed(role, &RibRequest::PushOspfRoutes(vec![])),
                matches!(role, Role::Ospfd | Role::Ospfv3d)
            );
            assert_eq!(
                allowed(role, &RibRequest::PushEvpnRoutes(EvpnUpdate::Full(vec![]))),
                role == Role::Bgpd
            );
        }
    }

    #[test]
    fn route_queries_are_for_people_and_the_rest_api() {
        for role in Role::ALL {
            let expected = matches!(role, Role::User | Role::Restd);
            assert_eq!(allowed(role, &RibRequest::GetRoutes), expected, "{role:?}");
        }
        // The daemons that resolve a VRF (or a loopback VTEP) through this instance.
        for role in [
            Role::Interfaced,
            Role::Bgpd,
            Role::Ospfd,
            Role::Ospfv3d,
            Role::Ribd,
            Role::Fdbd,
            Role::Logd,
        ] {
            assert!(allowed(role, &RibRequest::GetVrfName), "{role:?}");
        }
        assert!(!allowed(Role::Lacpd, &RibRequest::GetVrfName));
    }

    #[test]
    fn igp_costs_are_for_bgpd_and_readers_only() {
        for role in Role::ALL {
            let expected = matches!(role, Role::User | Role::Restd | Role::Bgpd);
            assert_eq!(allowed(role, &RibRequest::IgpCosts), expected, "{role:?}");
        }
    }

    #[test]
    fn evpn_irb_is_for_fdbd_only_and_none_before_the_router_mac() {
        for role in Role::ALL {
            assert_eq!(
                allowed(role, &RibRequest::GetEvpnIrb),
                role == Role::Fdbd,
                "{role:?}"
            );
        }
        assert_eq!(EvpnState::default().irb(), None);
    }

    #[test]
    fn bgp_route_count_is_for_bgpd_only() {
        for role in Role::ALL {
            assert_eq!(
                allowed(role, &RibRequest::BgpRouteCount),
                role == Role::Bgpd,
                "{role:?}"
            );
        }
    }
}
