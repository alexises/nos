//! Read-only endpoints: one per `nos-cli` `show` command, returning the
//! daemon's own reply payload as JSON.

use std::net::IpAddr;

use std::convert::Infallible;

use axum::extract::{Path, Query, State};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::Json;
use futures::{Stream, StreamExt};
use nos_proto::{
    BfdEvent, BfdRequest, BfdSessionView, BgpEvent, BgpRequest, Config, EvpnRouteSummary, FdbEvent,
    FdbRequest, FdbTable, InterfaceEvent, InterfaceRequest, InterfaceStatus, LacpEvent,
    LacpRequest, LldpEvent, LldpLinkStats, LldpNeighbor, LldpRequest, LogEntry, LogEvent,
    LogRequest, LsaSummary, NeighborSummary, OspfEvent, OspfRequest, Ospfv3Event, Ospfv3LsaSummary,
    Ospfv3NeighborSummary, Ospfv3Request, PeerSummary, PortAggregateLacpSummary,
    PortAggregateStatus, PrefixRoutes, ReflectorView, RibEvent, RibRequest, ServiceRef, StpEvent,
    StpRequest, StpSummary,
};
use serde::{Deserialize, Serialize};

use utoipa::ToSchema;

use crate::error::{ApiError, ApiResult, ErrorBody};
use crate::ipc::{unexpected, Daemons};

#[utoipa::path(get, path = "/v1/config", tag = "show", summary = "Running config", responses((status = 200, body = Config)))]
pub async fn config(State(d): State<Daemons>) -> ApiResult<Json<Config>> {
    Ok(Json(d.running_config().await?))
}

#[utoipa::path(get, path = "/v1/routes/{table}", tag = "show", summary = "Every route in a table, best to worst per prefix", params(("table" = String, Path, description = "routing table name")), responses((status = 200, body = Vec<PrefixRoutes>), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn routes(
    State(d): State<Daemons>,
    Path(table): Path<String>,
) -> ApiResult<Json<Vec<PrefixRoutes>>> {
    match d
        .service(ServiceRef::RibTable(table), RibRequest::GetRoutes)
        .await?
    {
        RibEvent::Routes(r) => Ok(Json(r)),
        RibEvent::Error(e) => Err(ApiError::BadGateway(e)),
        other => Err(unexpected("nos-ribd", &other)),
    }
}

#[utoipa::path(get, path = "/v1/fdb/{domain}", tag = "show", summary = "A broadcast domain's forwarding database: local and EVPN-learned MACs, flood list", params(("domain" = String, Path, description = "broadcast domain name")), responses((status = 200, body = FdbTable), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn fdb(
    State(d): State<Daemons>,
    Path(domain): Path<String>,
) -> ApiResult<Json<FdbTable>> {
    match d
        .service(ServiceRef::FdbDomain(domain), FdbRequest::GetMacs)
        .await?
    {
        FdbEvent::Table(t) => Ok(Json(t)),
    }
}

/// Longest-prefix-match lookup for one address.
#[utoipa::path(get, path = "/v1/routes/{table}/{addr}", tag = "show", summary = "Longest-prefix-match lookup", params(("table" = String, Path, description = "routing table name"), ("addr" = String, Path, description = "destination address")), responses((status = 200, body = PrefixRoutes), (status = 404, body = ErrorBody, description = "no route covers the address"), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn route_lookup(
    State(d): State<Daemons>,
    Path((table, addr)): Path<(String, IpAddr)>,
) -> ApiResult<Json<PrefixRoutes>> {
    match d
        .service(ServiceRef::RibTable(table), RibRequest::Lookup { addr })
        .await?
    {
        RibEvent::Match(r) => Ok(Json(r)),
        RibEvent::NoMatch => Err(ApiError::NotFound(format!("no route covers {addr}"))),
        RibEvent::Error(e) => Err(ApiError::BadGateway(e)),
        other => Err(unexpected("nos-ribd", &other)),
    }
}

#[utoipa::path(get, path = "/v1/interfaces", tag = "show", summary = "Every interface", responses((status = 200, body = Vec<InterfaceStatus>), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn interfaces(State(d): State<Daemons>) -> ApiResult<Json<Vec<InterfaceStatus>>> {
    match d
        .service(ServiceRef::Interfaces, InterfaceRequest::GetInterfaces)
        .await?
    {
        InterfaceEvent::Interfaces(v) => Ok(Json(v)),
        other => Err(unexpected("nos-interfaced", &other)),
    }
}

#[utoipa::path(get, path = "/v1/interfaces/{name}", tag = "show", summary = "One interface", params(("name" = String, Path, description = "interface name")), responses((status = 200, body = InterfaceStatus), (status = 404, body = ErrorBody), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn interface(
    State(d): State<Daemons>,
    Path(name): Path<String>,
) -> ApiResult<Json<InterfaceStatus>> {
    match d
        .service(
            ServiceRef::Interfaces,
            InterfaceRequest::GetInterface { name: name.clone() },
        )
        .await?
    {
        InterfaceEvent::Interface(v) => Ok(Json(v)),
        InterfaceEvent::NotFound => Err(ApiError::NotFound(format!("no interface '{name}'"))),
        other => Err(unexpected("nos-interfaced", &other)),
    }
}

#[utoipa::path(get, path = "/v1/port-aggregates", tag = "show", summary = "Every port aggregate", responses((status = 200, body = Vec<PortAggregateStatus>), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn port_aggregates(
    State(d): State<Daemons>,
) -> ApiResult<Json<Vec<PortAggregateStatus>>> {
    match d
        .service(ServiceRef::Interfaces, InterfaceRequest::GetPortAggregates)
        .await?
    {
        InterfaceEvent::PortAggregates(v) => Ok(Json(v)),
        other => Err(unexpected("nos-interfaced", &other)),
    }
}

#[utoipa::path(get, path = "/v1/port-aggregates/{name}", tag = "show", summary = "One port aggregate", params(("name" = String, Path, description = "port aggregate name")), responses((status = 200, body = PortAggregateStatus), (status = 404, body = ErrorBody), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn port_aggregate(
    State(d): State<Daemons>,
    Path(name): Path<String>,
) -> ApiResult<Json<PortAggregateStatus>> {
    match d
        .service(
            ServiceRef::Interfaces,
            InterfaceRequest::GetPortAggregate { name: name.clone() },
        )
        .await?
    {
        InterfaceEvent::PortAggregate(v) => Ok(Json(v)),
        InterfaceEvent::NotFound => Err(ApiError::NotFound(format!("no port-aggregate '{name}'"))),
        other => Err(unexpected("nos-interfaced", &other)),
    }
}

async fn lacp_summary(d: &Daemons) -> ApiResult<Vec<PortAggregateLacpSummary>> {
    match d.service(ServiceRef::Lacp, LacpRequest::GetSummary).await? {
        LacpEvent::Summary(v) => Ok(v),
    }
}

#[utoipa::path(get, path = "/v1/lacp", tag = "show", summary = "LACP state of every aggregate", responses((status = 200, body = Vec<PortAggregateLacpSummary>), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn lacp(State(d): State<Daemons>) -> ApiResult<Json<Vec<PortAggregateLacpSummary>>> {
    Ok(Json(lacp_summary(&d).await?))
}

#[utoipa::path(get, path = "/v1/lacp/{name}", tag = "show", summary = "LACP state of one aggregate", params(("name" = String, Path, description = "port aggregate name")), responses((status = 200, body = PortAggregateLacpSummary), (status = 404, body = ErrorBody), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn lacp_one(
    State(d): State<Daemons>,
    Path(name): Path<String>,
) -> ApiResult<Json<PortAggregateLacpSummary>> {
    lacp_summary(&d)
        .await?
        .into_iter()
        .find(|a| a.aggregate == name)
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("no lacp aggregate '{name}'")))
}

#[utoipa::path(get, path = "/v1/lldp/neighbors", tag = "show", summary = "Every LLDP neighbor", responses((status = 200, body = Vec<LldpNeighbor>), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn lldp_neighbors(State(d): State<Daemons>) -> ApiResult<Json<Vec<LldpNeighbor>>> {
    match d
        .service(ServiceRef::Lldp, LldpRequest::GetNeighbors)
        .await?
    {
        LldpEvent::Neighbors(v) => Ok(Json(v)),
        other @ LldpEvent::Statistics(_) => Err(unexpected("nos-lldpd", &other)),
    }
}

#[utoipa::path(get, path = "/v1/spanning-tree", tag = "show", summary = "The spanning-tree bridge and every port's role and state (`enabled: false` when the mode is not rstp)", responses((status = 200, body = StpSummary), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn spanning_tree(State(d): State<Daemons>) -> ApiResult<Json<StpSummary>> {
    match d.service(ServiceRef::Stp, StpRequest::GetSummary).await? {
        StpEvent::Summary(s) => Ok(Json(s)),
        other @ (StpEvent::Mcheck { .. } | StpEvent::ErrDisabledCleared { .. }) => {
            Err(crate::ipc::unexpected("nos-stpd", &other))
        }
    }
}

#[utoipa::path(get, path = "/v1/lldp/statistics", tag = "show", summary = "Every LLDP-enabled interface's IEEE 802.1AB counters", responses((status = 200, body = Vec<LldpLinkStats>), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn lldp_statistics(State(d): State<Daemons>) -> ApiResult<Json<Vec<LldpLinkStats>>> {
    match d
        .service(ServiceRef::Lldp, LldpRequest::GetStatistics)
        .await?
    {
        LldpEvent::Statistics(v) => Ok(Json(v)),
        other @ LldpEvent::Neighbors(_) => Err(unexpected("nos-lldpd", &other)),
    }
}

#[derive(Deserialize)]
pub struct BfdQuery {
    peer: Option<String>,
}

#[utoipa::path(get, path = "/v1/bfd/sessions", tag = "show", summary = "Every BFD session, or those to one peer", params(("peer" = Option<String>, Query, description = "only sessions to this peer address")), responses((status = 200, body = Vec<BfdSessionView>), (status = 400, body = ErrorBody, description = "peer is not an IP address"), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn bfd_sessions(
    State(d): State<Daemons>,
    Query(q): Query<BfdQuery>,
) -> ApiResult<Json<Vec<BfdSessionView>>> {
    let peer = q
        .peer
        .map(|p| {
            p.parse::<IpAddr>()
                .map_err(|_| ApiError::BadRequest(format!("peer '{p}' is not an IP address")))
        })
        .transpose()?;
    match d
        .service(ServiceRef::Bfd, BfdRequest::GetSessions { peer })
        .await?
    {
        BfdEvent::Sessions(v) => Ok(Json(v)),
        other => Err(unexpected("nos-bfdd", &other)),
    }
}

#[utoipa::path(get, path = "/v1/bfd/reflector", tag = "show", summary = "The S-BFD reflector's discriminators and counters", responses((status = 200, body = ReflectorView), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn bfd_reflector(State(d): State<Daemons>) -> ApiResult<Json<ReflectorView>> {
    match d.service(ServiceRef::Bfd, BfdRequest::GetReflector).await? {
        BfdEvent::Reflector(v) => Ok(Json(v)),
        other => Err(unexpected("nos-bfdd", &other)),
    }
}

#[derive(Deserialize)]
pub struct LogQuery {
    source: Option<String>,
    limit: Option<usize>,
}

/// One-shot buffer snapshot (`show log`); there is no `--follow` equivalent yet.
#[utoipa::path(get, path = "/v1/logs", tag = "show", summary = "Log buffer snapshot", params(("source" = Option<String>, Query, description = "only entries from this source"), ("limit" = Option<usize>, Query, description = "most recent N entries")), responses((status = 200, body = Vec<LogEntry>), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn logs(
    State(d): State<Daemons>,
    Query(q): Query<LogQuery>,
) -> ApiResult<Json<Vec<LogEntry>>> {
    match d
        .service(
            ServiceRef::Log,
            LogRequest::GetLogs {
                source: q.source,
                limit: q.limit,
            },
        )
        .await?
    {
        LogEvent::Logs(v) => Ok(Json(v)),
        LogEvent::Error(e) => Err(ApiError::BadGateway(e)),
        other @ LogEvent::Line(_) => Err(unexpected("nos-logd", &other)),
    }
}

/// Named so `#[utoipa::path]` can take them as a `body` (it cannot parse nested generics).
pub type BgpSummaryReport = Vec<InstanceReport<Vec<PeerSummary>>>;
pub type BgpEvpnReport = Vec<InstanceReport<Vec<EvpnRouteSummary>>>;
pub type BgpRpkiReport = Vec<InstanceReport<Vec<nos_proto::RpkiCacheStatus>>>;
pub type OspfNeighborsReport = Vec<InstanceReport<Vec<NeighborSummary>>>;
pub type OspfDatabaseReport = Vec<InstanceReport<Vec<LsaSummary>>>;
pub type Ospfv3NeighborsReport = Vec<InstanceReport<Vec<Ospfv3NeighborSummary>>>;
pub type Ospfv3DatabaseReport = Vec<InstanceReport<Vec<Ospfv3LsaSummary>>>;

#[derive(Deserialize)]
pub struct FollowQuery {
    source: Option<String>,
    limit: Option<usize>,
}

/// `show log --follow`: a Server-Sent Events stream. The buffer as it stands
/// (trimmed to the most recent `limit`, if given) is sent first, then each new
/// entry as it is logged, until the client disconnects. Every entry is a `log`
/// event whose data is the JSON `LogEntry`; a daemon-side failure is an `error`
/// event with the message as data.
#[utoipa::path(
    get, path = "/v1/logs/follow", tag = "show", summary = "Follow the log (Server-Sent Events)",
    params(
        ("source" = Option<String>, Query, description = "only entries from this source"),
        ("limit" = Option<usize>, Query, description = "trim the initial backlog to the most recent N entries")
    ),
    responses(
        (status = 200, content_type = "text/event-stream", body = String,
         description = "`event: log` per entry, data = a JSON LogEntry"),
        (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")
    )
)]
pub async fn logs_follow(
    State(d): State<Daemons>,
    Query(q): Query<FollowQuery>,
) -> ApiResult<Sse<impl Stream<Item = Result<SseEvent, Infallible>>>> {
    let (reader, writer) = d
        .open_stream::<_, LogEvent>(ServiceRef::Log, LogRequest::Tail { source: q.source })
        .await?;
    let mut backlog_limit = q.limit;
    let events = reader.flat_map(move |item| {
        let entries: Vec<SseEvent> = match item {
            Ok(LogEvent::Logs(mut v)) => {
                if let Some(n) = backlog_limit.take() {
                    v.drain(..v.len().saturating_sub(n));
                }
                v.iter().filter_map(log_event).collect()
            }
            Ok(LogEvent::Line(e)) => log_event(&e).into_iter().collect(),
            Ok(LogEvent::Error(m)) => vec![SseEvent::default().event("error").data(m)],
            Err(e) => vec![SseEvent::default().event("error").data(e.to_string())],
        };
        futures::stream::iter(entries.into_iter().map(Ok))
    });
    // Holding the write half until the stream is dropped keeps the daemon's
    // side of the tail subscription open.
    let events = events.map(move |e| {
        let _keep_open = &writer;
        e
    });
    Ok(Sse::new(events).keep_alive(KeepAlive::default()))
}

fn log_event(entry: &LogEntry) -> Option<SseEvent> {
    SseEvent::default().event("log").json_data(entry).ok()
}

/// One instance's answer to a router-wide query: its payload, or why it has none.
#[derive(Serialize, ToSchema)]
pub struct InstanceReport<T> {
    pub instance: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Asks every named instance's daemon the same question, like `nos-cli`'s
/// router-wide `show bgp brief`: an instance whose daemon isn't reachable
/// gets an `error` entry instead of failing the whole query.
async fn per_instance<Req, Ev, T>(
    d: &Daemons,
    names: Vec<String>,
    service: impl Fn(String) -> ServiceRef,
    request: impl Fn() -> Req,
    extract: impl Fn(Ev) -> Option<T>,
) -> Vec<InstanceReport<T>>
where
    Req: Serialize,
    Ev: serde::de::DeserializeOwned,
{
    let mut out = Vec::new();
    for instance in names {
        let reply = d
            .service::<_, Ev>(service(instance.clone()), request())
            .await;
        let (result, error) = match reply {
            Ok(ev) => match extract(ev) {
                Some(t) => (Some(t), None),
                None => (None, Some("unexpected reply".to_string())),
            },
            Err(ApiError::Unavailable(_)) => (None, Some("not running".to_string())),
            Err(e) => (None, Some(format!("{e:?}"))),
        };
        out.push(InstanceReport {
            instance,
            result,
            error,
        });
    }
    out
}

#[utoipa::path(get, path = "/v1/bgp/summary", tag = "show", summary = "BGP session summary, per instance", responses((status = 200, body = BgpSummaryReport), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn bgp_summary(State(d): State<Daemons>) -> ApiResult<Json<BgpSummaryReport>> {
    let names = d
        .running_config()
        .await?
        .bgp_instances
        .into_iter()
        .map(|i| i.name)
        .collect();
    Ok(Json(
        per_instance(
            &d,
            names,
            ServiceRef::BgpInstance,
            || BgpRequest::GetSummary,
            |e| match e {
                BgpEvent::Summary(v) => Some(v),
                _ => None,
            },
        )
        .await,
    ))
}

#[utoipa::path(get, path = "/v1/bgp/evpn", tag = "show", summary = "Received EVPN routes, per instance", responses((status = 200, body = BgpEvpnReport), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn bgp_evpn(State(d): State<Daemons>) -> ApiResult<Json<BgpEvpnReport>> {
    let names = d
        .running_config()
        .await?
        .bgp_instances
        .into_iter()
        .map(|i| i.name)
        .collect();
    Ok(Json(
        per_instance(
            &d,
            names,
            ServiceRef::BgpInstance,
            || BgpRequest::GetEvpnRoutes,
            |e| match e {
                BgpEvent::EvpnRoutes(v) => Some(v),
                _ => None,
            },
        )
        .await,
    ))
}

#[utoipa::path(get, path = "/v1/bgp/rpki", tag = "show", summary = "RPKI cache sessions (RFC 8210), per instance", responses((status = 200, body = BgpRpkiReport), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn bgp_rpki(State(d): State<Daemons>) -> ApiResult<Json<BgpRpkiReport>> {
    let names = d
        .running_config()
        .await?
        .bgp_instances
        .into_iter()
        .map(|i| i.name)
        .collect();
    Ok(Json(
        per_instance(
            &d,
            names,
            ServiceRef::BgpInstance,
            || BgpRequest::GetRpkiSummary,
            |e| match e {
                BgpEvent::RpkiSummary(v) => Some(v),
                _ => None,
            },
        )
        .await,
    ))
}

#[utoipa::path(get, path = "/v1/ospf/neighbors", tag = "show", summary = "OSPF neighbors, per instance", responses((status = 200, body = OspfNeighborsReport), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn ospf_neighbors(State(d): State<Daemons>) -> ApiResult<Json<OspfNeighborsReport>> {
    let names = d
        .running_config()
        .await?
        .ospf_instances
        .into_iter()
        .map(|i| i.name)
        .collect();
    Ok(Json(
        per_instance(
            &d,
            names,
            ServiceRef::OspfInstance,
            || OspfRequest::GetNeighbors,
            |e| match e {
                OspfEvent::Neighbors(v) => Some(v),
                OspfEvent::Database(_) => None,
            },
        )
        .await,
    ))
}

#[utoipa::path(get, path = "/v1/ospf/database", tag = "show", summary = "OSPF LSDB summary, per instance", responses((status = 200, body = OspfDatabaseReport), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn ospf_database(State(d): State<Daemons>) -> ApiResult<Json<OspfDatabaseReport>> {
    let names = d
        .running_config()
        .await?
        .ospf_instances
        .into_iter()
        .map(|i| i.name)
        .collect();
    Ok(Json(
        per_instance(
            &d,
            names,
            ServiceRef::OspfInstance,
            || OspfRequest::GetDatabase,
            |e| match e {
                OspfEvent::Database(v) => Some(v),
                OspfEvent::Neighbors(_) => None,
            },
        )
        .await,
    ))
}

#[utoipa::path(get, path = "/v1/ospfv3/neighbors", tag = "show", summary = "OSPFv3 neighbors, per instance", responses((status = 200, body = Ospfv3NeighborsReport), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn ospfv3_neighbors(State(d): State<Daemons>) -> ApiResult<Json<Ospfv3NeighborsReport>> {
    let names = d
        .running_config()
        .await?
        .ospfv3_instances
        .into_iter()
        .map(|i| i.name)
        .collect();
    Ok(Json(
        per_instance(
            &d,
            names,
            ServiceRef::Ospfv3Instance,
            || Ospfv3Request::GetNeighbors,
            |e| match e {
                Ospfv3Event::Neighbors(v) => Some(v),
                Ospfv3Event::Database(_) => None,
            },
        )
        .await,
    ))
}

#[utoipa::path(get, path = "/v1/ospfv3/database", tag = "show", summary = "OSPFv3 LSDB summary, per instance", responses((status = 200, body = Ospfv3DatabaseReport), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn ospfv3_database(State(d): State<Daemons>) -> ApiResult<Json<Ospfv3DatabaseReport>> {
    let names = d
        .running_config()
        .await?
        .ospfv3_instances
        .into_iter()
        .map(|i| i.name)
        .collect();
    Ok(Json(
        per_instance(
            &d,
            names,
            ServiceRef::Ospfv3Instance,
            || Ospfv3Request::GetDatabase,
            |e| match e {
                Ospfv3Event::Database(v) => Some(v),
                Ospfv3Event::Neighbors(_) => None,
            },
        )
        .await,
    ))
}
