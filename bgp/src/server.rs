use std::path::Path;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, Incoming, Listener, Stream};
use nos_proto::{BgpEvent, BgpRequest, IpcCodec, Role};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, error, info, trace, warn};

use crate::collision::FsmCommand;
use crate::session::SessionManager;

/// Binds `listen_socket` and spawns the IPC accept loop for session
/// summaries.
///
/// Returns a `JoinHandle` the caller must keep alive for the server to run.
pub fn start(
    listen_socket: &Path,
    instance: String,
    sessions: Arc<SessionManager>,
    identity: &Identity,
) -> std::io::Result<JoinHandle<()>> {
    let listener = identity.listen(listen_socket)?;
    info!(instance = %instance, socket = %listen_socket.display(), "BGP IPC server listening");
    Ok(tokio::spawn(accept_loop(listener, instance, sessions)))
}

/// Session queries and `clear bgp` are for people (and `Restd` on their
/// behalf); the redistribution feed is `nos-ribd`'s alone. No wildcard arm.
fn allowed(role: Role, req: &BgpRequest) -> bool {
    match req {
        BgpRequest::GetSummary
        | BgpRequest::GetEvpnRoutes
        | BgpRequest::SendRouteRefresh { .. }
        | BgpRequest::ClearPeer { .. }
        | BgpRequest::GetRpkiSummary => {
            matches!(role, Role::User | Role::Restd)
        }
        BgpRequest::RedistributeRoutes(_) => role == Role::Ribd,
        BgpRequest::RedistributeMacs { .. } => role == Role::Fdbd,
    }
}

async fn accept_loop(listener: Listener, instance: String, sessions: Arc<SessionManager>) {
    loop {
        match listener.accept().await {
            Ok(incoming) => {
                tokio::spawn(serve(incoming, instance.clone(), sessions.clone()));
            }
            Err(e) => {
                error!(instance = %instance, error = %e, "BGP IPC accept loop terminated");
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
async fn serve(incoming: Incoming, instance: String, sessions: Arc<SessionManager>) {
    match incoming.handshake_as(Role::parse).await {
        Ok((stream, role, name)) => handle_connection(stream, role, name, instance, sessions).await,
        Err(e) => debug!(instance = %instance, error = %e, "BGP IPC handshake refused"),
    }
}

async fn handle_connection(
    stream: Stream,
    role: Role,
    name: String,
    instance: String,
    sessions: Arc<SessionManager>,
) {
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<BgpRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<BgpEvent>::default());

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
        match req {
            BgpRequest::GetSummary => {
                let event = BgpEvent::Summary(sessions.peer_summaries().await);
                if writer.send(event).await.is_err() {
                    break;
                }
            }
            BgpRequest::GetEvpnRoutes => {
                let event = BgpEvent::EvpnRoutes(sessions.evpn_route_summaries().await);
                if writer.send(event).await.is_err() {
                    break;
                }
            }
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
                allowed(role, &BgpRequest::GetEvpnRoutes),
                matches!(role, Role::User | Role::Restd),
                "{role:?} evpn routes"
            );
        }
    }
}
