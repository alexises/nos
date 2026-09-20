//! `nos-ospfd`'s IPC query protocol — backs `nos-cli`'s `show ospf neigh`/
//! `show ospf database`. Mirrors `bgp`'s shape: a request/event pair framed
//! by `IpcCodec` over a Unix socket resolved via the watchdog broker
//! (`ServiceRef::OspfInstance`).
//!
//! Neighbor establishment reaches the full RFC 2328 §10.5 ladder (`Down`
//! through `Full`), backed by a real per-area LSDB — see `ospf/CLAUDE.md`.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// One neighbor's state, as reported by `nos-ospfd` — the full RFC 2328
/// §10.5 ladder. `Down` is an ongoing, valid state (no Hello received yet,
/// or the dead-interval expired) — a point-to-point link always reports at
/// least one row, even `Down`; a broadcast link reports one row per
/// currently-known neighbor (zero if none yet — there's no single fixed peer
/// to show a placeholder for on a multi-access segment).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OspfNeighborState {
    Down,
    Init,
    TwoWay,
    ExStart,
    Exchange,
    Loading,
    Full,
}

/// RFC 2328 §9.1's interface states, as they apply to this phase's Hello-only
/// scope: `PointToPoint` is fixed forever on a point-to-point link (no
/// election ever runs); a broadcast link starts `Waiting`, then becomes
/// `Dr`/`Backup`/`DrOther` once RFC 2328 §9.4 election runs (see
/// `ospf::election`).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkInterfaceState {
    PointToPoint,
    Waiting,
    Dr,
    Backup,
    DrOther,
}

/// One neighbor's summary row, for `show ospf neigh` — one row per
/// currently-known neighbor on a link (see `OspfNeighborState`'s doc
/// comment for point-to-point vs. broadcast row-count semantics).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NeighborSummary {
    /// The attach point's display name, matching
    /// `reconcile::attach_points_for`'s existing `"<interface>.<tag>"`/
    /// `"broadcast-domain:<name>"` convention.
    pub link: String,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub area_id: Ipv4Addr,
    pub interface_state: LinkInterfaceState,
    /// Known once at least one Hello has been received on this link.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub neighbor_router_id: Option<Ipv4Addr>,
    pub state: OspfNeighborState,
    /// Seconds since the last Hello was received from this neighbor. `None`
    /// if none has ever been received.
    pub last_hello_secs: Option<u64>,
    pub hello_interval: u16,
    pub dead_interval: u16,
    /// This link's own configured Router Priority — mirrors how
    /// `hello_interval`/`dead_interval` already report the *local* link's
    /// config on every row.
    pub priority: u8,
    /// The remote neighbor's own decoded Router Priority. `None` if no
    /// Hello has been received from it yet.
    pub neighbor_priority: Option<u8>,
    /// This link's currently elected DR/BDR — `None` on a point-to-point
    /// link (no election ever runs) or before a broadcast link's first
    /// election.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub dr: Option<Ipv4Addr>,
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub bdr: Option<Ipv4Addr>,
}

/// One installed LSA's header fields, for `show ospf database` — never the
/// full LSA body, which this NOS has no operator-facing use for yet (no SPF
/// consumer to explain a route's ancestry).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LsaSummary {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub area_id: Ipv4Addr,
    pub lsa_type: u8,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub link_state_id: Ipv4Addr,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub advertising_router: Ipv4Addr,
    pub sequence_number: i32,
    pub age: u16,
    pub checksum: u16,
}

/// Messages sent from a client to one `nos-ospfd` instance's IPC socket.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index, so reordering breaks wire compatibility with
/// already-built binaries.
#[derive(Debug, Serialize, Deserialize)]
pub enum OspfRequest {
    /// One-shot: every configured link's current neighbor summary.
    GetNeighbors,
    /// One-shot: every installed LSA's header, across every area.
    GetDatabase,
    /// Fire-and-forget, no reply — sent continuously by `nos-ribd` over one
    /// long-lived connection, the OSPF-redistribution analogue of
    /// `BgpRequest::RedistributeRoutes`: this instance's ASBR-redistributed
    /// routes (e.g. `redistribute from static to ospf`), to be originated as
    /// real RFC 2328 AS-external-LSAs.
    RedistributeRoutes(crate::bgp::RedistributeUpdate),
}

/// Messages sent from `nos-ospfd` to a query client.
#[derive(Debug, Serialize, Deserialize)]
pub enum OspfEvent {
    Neighbors(Vec<NeighborSummary>),
    Database(Vec<LsaSummary>),
}
