use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, Incoming, Listener, Stream};
use nos_proto::{BgpEvent, BgpRequest, IpcCodec, Role};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, error, info, trace, warn};

use crate::collision::FsmCommand;
use crate::page::{Snapshot, PAGE_BYTES};
use crate::session::{SessionManager, VpnAsk, VpnSnapshot};

/// Binds `listen_socket` and spawns the IPC accept loop for session
/// summaries.
///
/// Returns a `JoinHandle` the caller must keep alive for the server to run.
/// `watchdog_socket` resolves `nos-acld` for `show bgp flowspec`.
pub fn start(
    listen_socket: &Path,
    instance: String,
    sessions: Arc<SessionManager>,
    identity: &Identity,
    watchdog_socket: PathBuf,
) -> std::io::Result<JoinHandle<()>> {
    let listener = identity.listen(listen_socket)?;
    info!(instance = %instance, socket = %listen_socket.display(), "BGP IPC server listening");
    let ctx = Arc::new((instance, sessions, watchdog_socket));
    Ok(tokio::spawn(accept_loop(listener, ctx)))
}

/// What every connection needs: the instance name, the sessions, the
/// watchdog socket.
type Ctx = Arc<(String, Arc<SessionManager>, PathBuf)>;

/// Session queries and `clear bgp` are for people (and `Restd` on their
/// behalf); the redistribution feed is `nos-ribd`'s alone. No wildcard arm.
fn allowed(role: Role, req: &BgpRequest) -> bool {
    match req {
        BgpRequest::GetSummary
        | BgpRequest::GetEvpnRoutes
        | BgpRequest::GetFlowspecRoutes
        | BgpRequest::GetVpnRoutes { .. }
        | BgpRequest::SendRouteRefresh { .. }
        | BgpRequest::ClearPeer { .. }
        | BgpRequest::GetRoutes
        | BgpRequest::GetRoutesPage { .. }
        | BgpRequest::GetEvpnRoutesPage { .. }
        | BgpRequest::GetFlowspecRoutesPage { .. }
        | BgpRequest::GetVpnRoutesPage { .. }
        | BgpRequest::GetRpkiSummary => {
            matches!(role, Role::User | Role::Restd)
        }
        BgpRequest::RedistributeRoutes(_)
        | BgpRequest::RedistributeEvpnPrefixes { .. }
        | BgpRequest::RedistributeVpnPrefixes { .. } => role == Role::Ribd,
        BgpRequest::RedistributeMacs { .. } => role == Role::Fdbd,
    }
}

async fn accept_loop(listener: Listener, ctx: Ctx) {
    loop {
        match listener.accept().await {
            Ok(incoming) => {
                tokio::spawn(serve(incoming, ctx.clone()));
            }
            Err(e) => {
                error!(instance = %ctx.0, error = %e, "BGP IPC accept loop terminated");
                break;
            }
        }
    }
}

/// Handles one connection for its whole lifetime. `GetSummary` sends one
/// reply per request; `RedistributeRoutes` (sent continuously by `nos-ribd`
/// over one long-lived connection, mirroring `nos-logd`'s handling of
/// `LogRequest::Push`) gets no reply at all, so the loop just keeps reading
/// further requests on the same connection.
async fn serve(incoming: Incoming, ctx: Ctx) {
    match incoming.handshake_as(Role::parse).await {
        Ok((stream, role, name)) => handle_connection(stream, role, name, ctx).await,
        Err(e) => debug!(instance = %ctx.0, error = %e, "BGP IPC handshake refused"),
    }
}

/// One sorted key snapshot per paged query kind, dropped with the connection.
#[derive(Default)]
struct Snapshots {
    routes: Snapshot<nos_proto::BgpRouteCursor>,
    evpn: Snapshot<crate::rib::EvpnKey>,
    flowspec: Snapshot<crate::rib::FlowKey>,
    vpn: VpnSnapshot,
}

impl Snapshots {
    /// The reply to a paged query (#722, #723); `None` for any other request.
    async fn page(
        &mut self,
        req: &BgpRequest,
        sessions: &SessionManager,
        watchdog_socket: &Path,
    ) -> Option<BgpEvent> {
        Some(match req {
            BgpRequest::GetRoutesPage { after, limit } => {
                let (routes, next) = sessions
                    .route_page(&mut self.routes, after.as_ref(), *limit, PAGE_BYTES)
                    .await;
                BgpEvent::RoutesPage { routes, next }
            }
            BgpRequest::GetEvpnRoutesPage { after, limit } => {
                let (routes, next) = sessions
                    .evpn_page(&mut self.evpn, after.as_ref(), *limit, PAGE_BYTES)
                    .await;
                BgpEvent::EvpnRoutesPage { routes, next }
            }
            BgpRequest::GetFlowspecRoutesPage { after, limit } => {
                let acld = crate::acl_push_client::show(watchdog_socket).await;
                let (routes, next) = sessions
                    .flowspec_page(
                        &mut self.flowspec,
                        after.as_ref(),
                        *limit,
                        PAGE_BYTES,
                        acld.as_deref(),
                    )
                    .await;
                BgpEvent::FlowspecRoutesPage { routes, next }
            }
            BgpRequest::GetVpnRoutesPage {
                family,
                rd,
                after,
                limit,
            } => {
                let ask = VpnAsk {
                    family: *family,
                    rd: rd.as_deref(),
                    after: after.as_ref(),
                    limit: *limit,
                };
                let (routes, next) = sessions.vpn_page(&mut self.vpn, &ask, PAGE_BYTES).await;
                BgpEvent::VpnRoutesPage { routes, next }
            }
            _ => return None,
        })
    }
}

async fn handle_connection(stream: Stream, role: Role, name: String, ctx: Ctx) {
    let (instance, sessions, watchdog_socket) = &*ctx;
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<BgpRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<BgpEvent>::default());

    let mut snapshots = Snapshots::default();
    while let Some(msg) = reader.next().await {
        let req = match msg {
            Ok(req) => req,
            Err(e) => {
                warn!(instance = %instance, error = %e, "BGP IPC read error");
                break;
            }
        };
        if !allowed(role, &req) {
            warn!(
                instance = %instance, role = role.as_str(), name = %name,
                "BGP request refused: this role may not send it"
            );
            break;
        }
        trace!(instance = %instance, request = ?req, "serving BGP query");
        if let Some(event) = snapshots.page(&req, sessions, watchdog_socket).await {
            if writer.send(event).await.is_err() {
                break;
            }
            continue;
        }
        match req {
            BgpRequest::GetSummary => {
                let event = BgpEvent::Summary(sessions.peer_summaries().await);
                if writer.send(event).await.is_err() {
                    break;
                }
            }
            BgpRequest::GetRoutes
            | BgpRequest::GetEvpnRoutes
            | BgpRequest::GetFlowspecRoutes
            | BgpRequest::GetVpnRoutes { .. } => {
                let event = BgpEvent::Error("removed (#722, #723): use GetRoutesPage, GetEvpnRoutesPage, GetFlowspecRoutesPage or GetVpnRoutesPage".into());
                if writer.send(event).await.is_err() {
                    break;
                }
            }
            // Answered above, through the connection's snapshots.
            BgpRequest::GetRoutesPage { .. }
            | BgpRequest::GetEvpnRoutesPage { .. }
            | BgpRequest::GetFlowspecRoutesPage { .. }
            | BgpRequest::GetVpnRoutesPage { .. } => {}
            BgpRequest::GetRpkiSummary => {
                let event = BgpEvent::RpkiSummary(sessions.rpki_summaries().await);
                if writer.send(event).await.is_err() {
                    break;
                }
            }
            BgpRequest::RedistributeRoutes(update) => {
                sessions.apply_redistribute_update(update).await;
            }
            BgpRequest::RedistributeMacs { domain, update } => {
                sessions.apply_evpn_local(&domain, update).await;
            }
            BgpRequest::RedistributeEvpnPrefixes { table, update } => {
                sessions.apply_evpn_prefixes(&table, update).await;
            }
            BgpRequest::RedistributeVpnPrefixes { table, update } => {
                sessions.apply_vpn_prefixes(&table, update).await;
            }
            BgpRequest::SendRouteRefresh { peer } => {
                let event = if sessions
                    .send_command(peer, FsmCommand::SendRouteRefresh)
                    .await
                {
                    BgpEvent::RouteRefreshSent
                } else {
                    BgpEvent::PeerNotFound
                };
                if writer.send(event).await.is_err() {
                    break;
                }
            }
            BgpRequest::ClearPeer { peer } => {
                let event = if sessions.clear_peer(peer).await {
                    BgpEvent::PeerCleared
                } else {
                    BgpEvent::PeerNotFound
                };
                if writer.send(event).await.is_err() {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod authz_tests {
    use super::*;

    #[test]
    fn only_ribd_feeds_redistribution_and_only_people_query() {
        for role in Role::ALL {
            assert_eq!(
                allowed(
                    role,
                    &BgpRequest::RedistributeRoutes(nos_proto::RedistributeUpdate::Full(vec![]))
                ),
                role == Role::Ribd,
                "{role:?} redistribute"
            );
            assert_eq!(
                allowed(
                    role,
                    &BgpRequest::RedistributeMacs {
                        domain: "bd1".to_string(),
                        update: nos_proto::EvpnUpdate::Full(vec![])
                    }
                ),
                role == Role::Fdbd,
                "{role:?} redistribute macs"
            );
            assert_eq!(
                allowed(
                    role,
                    &BgpRequest::RedistributeEvpnPrefixes {
                        table: "tenant".to_string(),
                        update: nos_proto::EvpnUpdate::Full(vec![])
                    }
                ),
                role == Role::Ribd,
                "{role:?} redistribute evpn prefixes"
            );
            assert_eq!(
                allowed(
                    role,
                    &BgpRequest::RedistributeVpnPrefixes {
                        table: "red".to_string(),
                        update: nos_proto::VpnPrefixUpdate::Full(vec![])
                    }
                ),
                role == Role::Ribd,
                "{role:?} redistribute vpn prefixes"
            );
            assert_eq!(
                allowed(role, &BgpRequest::GetSummary),
                matches!(role, Role::User | Role::Restd),
                "{role:?} summary"
            );
            assert_eq!(
                allowed(
                    role,
                    &BgpRequest::ClearPeer {
                        peer: "10.0.0.1".parse().unwrap()
                    }
                ),
                matches!(role, Role::User | Role::Restd),
                "{role:?} clear peer"
            );
            assert_eq!(
                allowed(role, &BgpRequest::GetRpkiSummary),
                matches!(role, Role::User | Role::Restd),
                "{role:?} rpki summary"
            );
            assert_eq!(
                allowed(role, &BgpRequest::GetRoutes),
                matches!(role, Role::User | Role::Restd),
                "{role:?} routes"
            );
            assert_eq!(
                allowed(
                    role,
                    &BgpRequest::GetRoutesPage {
                        after: None,
                        limit: 10
                    }
                ),
                matches!(role, Role::User | Role::Restd),
                "{role:?} routes page"
            );
            assert_eq!(
                allowed(role, &BgpRequest::GetEvpnRoutes),
                matches!(role, Role::User | Role::Restd),
                "{role:?} evpn routes"
            );
            assert_eq!(
                allowed(role, &BgpRequest::GetFlowspecRoutes),
                matches!(role, Role::User | Role::Restd),
                "{role:?} flowspec routes"
            );
            for req in [
                BgpRequest::GetEvpnRoutesPage {
                    after: None,
                    limit: 10,
                },
                BgpRequest::GetFlowspecRoutesPage {
                    after: None,
                    limit: 10,
                },
                BgpRequest::GetVpnRoutesPage {
                    family: nos_proto::AddressFamily::Vpnv4Unicast,
                    rd: None,
                    after: None,
                    limit: 10,
                },
            ] {
                assert_eq!(
                    allowed(role, &req),
                    matches!(role, Role::User | Role::Restd),
                    "{role:?} {req:?}"
                );
            }
            assert_eq!(
                allowed(
                    role,
                    &BgpRequest::GetVpnRoutes {
                        family: nos_proto::AddressFamily::Vpnv4Unicast,
                        rd: None
                    }
                ),
                matches!(role, Role::User | Role::Restd),
                "{role:?} vpn routes"
            );
        }
    }
}
