//! Operator actions — the `nos-cli` `clear` commands. Unlike `show` these
//! change live session state (never config), so they are `POST`s.

use std::net::IpAddr;

use axum::extract::{Path, State};
use axum::Json;
use nos_proto::{BgpEvent, BgpRequest, ServiceRef};
use serde::Serialize;
use utoipa::ToSchema;

use crate::error::{ApiError, ApiResult, ErrorBody};
use crate::ipc::{unexpected, Daemons};

#[derive(Serialize, ToSchema)]
pub struct SoftInResult {
    instance: String,
    #[schema(value_type = String)]
    peer: IpAddr,
    /// Always `"sent"`: the ROUTE-REFRESH was delivered to the live session.
    route_refresh: &'static str,
}

/// `clear bgp <instance> <peer> soft-in`: ask the peer's live session to send
/// a ROUTE-REFRESH (RFC 2918), so it re-advertises its routes through the
/// current import policy.
#[utoipa::path(
    post, path = "/v1/bgp/{instance}/peer/{peer}/soft-in", tag = "clear",
    summary = "Soft-reset a BGP peer inbound (ROUTE-REFRESH)",
    params(
        ("instance" = String, Path, description = "BGP instance name"),
        ("peer" = String, Path, description = "peer address")
    ),
    responses(
        (status = 200, body = SoftInResult),
        (status = 404, body = ErrorBody, description = "peer not configured, or no Established session with it"),
        (status = 503, body = ErrorBody, description = "that instance's nos-bgpd is not running")
    )
)]
pub async fn bgp_soft_in(
    State(d): State<Daemons>,
    Path((instance, peer)): Path<(String, IpAddr)>,
) -> ApiResult<Json<SoftInResult>> {
    match d
        .service(
            ServiceRef::BgpInstance(instance.clone()),
            BgpRequest::SendRouteRefresh { peer },
        )
        .await?
    {
        BgpEvent::RouteRefreshSent => Ok(Json(SoftInResult {
            instance,
            peer,
            route_refresh: "sent",
        })),
        BgpEvent::PeerNotFound => Err(ApiError::NotFound(format!(
            "no Established session with {peer} in bgp instance '{instance}'"
        ))),
        other @ (BgpEvent::Summary(_)
        | BgpEvent::EvpnRoutes(_)
        | BgpEvent::PeerCleared
        | BgpEvent::RpkiSummary(_)) => Err(unexpected("nos-bgpd", &other)),
    }
}

#[derive(Serialize, ToSchema)]
pub struct ClearPeerResult {
    instance: String,
    #[schema(value_type = String)]
    peer: IpAddr,
    /// Always `true`: any maximum-prefix hold is released, and an
    /// Established session was reset with Cease/Administrative Reset.
    cleared: bool,
}

/// `clear bgp <instance> <peer>`: release a peer held down by its
/// maximum-prefix limit (RFC 4486), and reset its session if one is up.
#[utoipa::path(
    post, path = "/v1/bgp/{instance}/peer/{peer}/clear", tag = "clear",
    summary = "Reset a BGP peer (and release a maximum-prefix hold)",
    params(
        ("instance" = String, Path, description = "BGP instance name"),
        ("peer" = String, Path, description = "peer address")
    ),
    responses(
        (status = 200, body = ClearPeerResult),
        (status = 404, body = ErrorBody, description = "peer not configured"),
        (status = 503, body = ErrorBody, description = "that instance's nos-bgpd is not running")
    )
)]
pub async fn bgp_clear_peer(
    State(d): State<Daemons>,
    Path((instance, peer)): Path<(String, IpAddr)>,
) -> ApiResult<Json<ClearPeerResult>> {
    match d
        .service(
            ServiceRef::BgpInstance(instance.clone()),
            BgpRequest::ClearPeer { peer },
        )
        .await?
    {
        BgpEvent::PeerCleared => Ok(Json(ClearPeerResult {
            instance,
            peer,
            cleared: true,
        })),
        BgpEvent::PeerNotFound => Err(ApiError::NotFound(format!(
            "no peer {peer} in bgp instance '{instance}'"
        ))),
        other @ (BgpEvent::Summary(_)
        | BgpEvent::EvpnRoutes(_)
        | BgpEvent::RouteRefreshSent
        | BgpEvent::RpkiSummary(_)) => Err(unexpected("nos-bgpd", &other)),
    }
}
