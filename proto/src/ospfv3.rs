//! `nos-ospfv3d`'s IPC query protocol — backs `nos-cli`'s `show ospfv3
//! neigh`/`show ospfv3 database`. Mirrors `ospf`'s shape (`NeighborSummary`/
//! `LsaSummary`/`OspfRequest`/`OspfEvent`) — reuses `OspfNeighborState`/
//! `LinkInterfaceState` directly rather than duplicating them, since both are
//! already address-family-agnostic (RFC 5340 doesn't change the neighbor FSM
//! or interface-state ladder — see `nos_ospf_common::neighbor`/`election`'s
//! doc comments).

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::ospf::{LinkInterfaceState, OspfNeighborState};

/// One neighbor's summary row, for `show ospfv3 neigh` — mirrors
/// `ospf::NeighborSummary` exactly (nothing in it is an address field beyond
/// router-ids, so it needs no IPv6-specific fields either).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ospfv3NeighborSummary {
    /// The attach point's display name, matching `nos-ospfv3d`'s own
    /// `"<interface>.<tag>"`/`"broadcast-domain:<name>"` convention.
    pub link: String,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub area_id: Ipv4Addr,
    pub interface_state: LinkInterfaceState,
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub neighbor_router_id: Option<Ipv4Addr>,
    pub state: OspfNeighborState,
    pub last_hello_secs: Option<u64>,
    pub hello_interval: u16,
    pub dead_interval: u16,
    pub priority: u8,
    pub neighbor_priority: Option<u8>,
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub dr: Option<Ipv4Addr>,
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub bdr: Option<Ipv4Addr>,
}

/// One installed LSA's header fields, for `show ospfv3 database` — mirrors
/// `ospf::LsaSummary`, with `lsa_type` widened to `u16`: RFC 5340's LS Type
/// word carries the U-bit/S2/S1 scope bits alongside the function code.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ospfv3LsaSummary {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub area_id: Ipv4Addr,
    pub lsa_type: u16,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub link_state_id: Ipv4Addr,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub advertising_router: Ipv4Addr,
    pub sequence_number: i32,
    pub age: u16,
    pub checksum: u16,
}

/// Messages sent from a client to one `nos-ospfv3d` instance's IPC socket.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index, so reordering breaks wire compatibility with
/// already-built binaries.
#[derive(Debug, Serialize, Deserialize)]
pub enum Ospfv3Request {
    /// One-shot: every configured link's current neighbor summary.
    GetNeighbors,
    /// One-shot: every installed LSA's header, across every area.
    GetDatabase,
}

/// Messages sent from `nos-ospfv3d` to a query client.
#[derive(Debug, Serialize, Deserialize)]
pub enum Ospfv3Event {
    Neighbors(Vec<Ospfv3NeighborSummary>),
    Database(Vec<Ospfv3LsaSummary>),
}
