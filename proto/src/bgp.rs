//! `nos-bgpd`'s IPC query protocol — backs `nos-cli`'s `show bgp brief`.
//! Mirrors `rib`/`interface`'s shape: a request/event pair framed by
//! `IpcCodec` over a Unix socket resolved via the watchdog broker
//! (`ServiceRef::BgpInstance`).

use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// The FSM state a peer's session is in, as reported by `nos-bgpd`.
/// `Idle` covers everything before a TCP connection has even reached
/// `OpenSent` (no active/passive attempt has an OPEN in flight yet) — it is
/// not a real state in `nos-bgp::fsm`, which only models `OpenSent`/
/// `OpenConfirm`/`Established`, but is the natural "nothing established yet"
/// value to report over this protocol.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BgpSessionState {
    Idle,
    OpenSent,
    OpenConfirm,
    Established,
}

/// One configured peer's one-line summary, for `show bgp brief`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerSummary {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub remote_address: IpAddr,
    pub peer_group: String,
    /// The peer (or its peer-group) is administratively shut.
    pub shutdown: bool,
    /// Known only once negotiated (i.e. at least `OpenConfirm`).
    pub remote_as: Option<u32>,
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub remote_bgp_id: Option<Ipv4Addr>,
    pub state: BgpSessionState,
    /// Seconds since the session reached `Established`. `None` unless
    /// `state == Established` — computed server-side from an `Instant`,
    /// which isn't itself meaningful to serialize across processes.
    pub uptime_secs: Option<u64>,
    pub negotiated_hold_time: Option<u16>,
    pub negotiated_keepalive: Option<u16>,
    /// RFC 5925 TCP-AO live per-connection state, from
    /// `getsockopt(TCP_AO_INFO)` — `Some` only for an `Established` session
    /// whose peer-group uses TCP-AO and whose readback succeeded just now;
    /// `None` for MD5/no-auth peers, a non-`Established` peer, or a readback
    /// that raced session teardown. Counters are since the kernel installed
    /// AO on *this* connection (reset on every reconnect, not cumulative
    /// across the peer's whole configured lifetime).
    pub ao_current_key: Option<u8>,
    pub ao_rnext_key: Option<u8>,
    pub ao_packets_good: Option<u64>,
    pub ao_packets_bad: Option<u64>,
    pub ao_packets_key_not_found: Option<u64>,
    /// Held down by an RFC 4486 maximum-prefix trip: no session is opened or
    /// accepted until `ClearPeer`, a shut/no-shut, or the restart interval.
    pub max_prefix_held: bool,
    /// Accepted (post-import-policy) prefixes from this peer per address
    /// family: ipv4, ipv6, l2vpn-evpn. `Some` only while `Established`.
    pub accepted_prefixes: Option<[u32; 3]>,
}

/// One received EVPN (RFC 7432) route, for `show bgp evpn`. `route` is the
/// NLRI rendered by `nos-bgpd` (`[2]:[65000:1]:[<esi>]:[<tag>]:...`) — nothing
/// downstream interprets it.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvpnRouteSummary {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub peer: IpAddr,
    pub route_type: u8,
    pub route: String,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub next_hop: IpAddr,
    /// Extended communities rendered as `RT:65000:10000`, `encap:8`, ...
    pub extended_communities: Vec<String>,
}

/// A single already-resolved winning route pushed by `nos-ribd` for
/// redistribution into BGP — not `PrefixRoutes`/`RouteEntry`'s
/// multi-candidate shape. `gateway` is carried for completeness only: the
/// BGP RIB engine always applies next-hop-self and never reads it. `prefix`
/// and `gateway` are always the same address family (v4/v6 alike, inferred
/// from `prefix`'s own `IpNet` variant — no separate AFI tag needed).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RedistributedRoute {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub prefix: IpNet,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub gateway: IpAddr,
}

/// Sent by `nos-ribd` to `nos-bgpd` over a persistent, long-lived
/// connection (mirroring `LogRequest::Push`'s pattern): a `Full` snapshot on
/// connect, then incremental `Add`/`Remove` for each subsequent change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RedistributeUpdate {
    Full(Vec<RedistributedRoute>),
    Add(RedistributedRoute),
    Remove(IpNet),
}

/// Messages sent from a client to one `nos-bgpd` instance's IPC socket.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index, so reordering breaks wire compatibility with
/// already-built binaries.
#[derive(Debug, Serialize, Deserialize)]
pub enum BgpRequest {
    /// One-shot: every configured peer's current summary.
    GetSummary,
    /// Fire-and-forget, no reply — like `LogRequest::Push`, sent
    /// continuously over one long-lived connection from `nos-ribd`.
    RedistributeRoutes(RedistributeUpdate),
    /// Operator-triggered `clear bgp <instance> <peer> soft-in` — ask
    /// `peer`'s live session to send it an RFC 2918 `ROUTE_REFRESH`.
    SendRouteRefresh { peer: IpAddr },
    /// One-shot: every EVPN route received from any peer.
    GetEvpnRoutes,
    /// Fire-and-forget, no reply: one `nos-fdbd`'s local MACs, originated as
    /// EVPN Type-2 (and its flood-list Type-3) routes. `domain` scopes a
    /// `Full`, since several domains feed one BGP instance (unlike
    /// `nos-ribd`, where table and instance are 1:1).
    RedistributeMacs {
        domain: String,
        update: crate::fdb::EvpnUpdate,
    },
    /// Operator-triggered `clear bgp <instance> <peer>`: release a peer held
    /// by its maximum-prefix limit, and reset its session if one is up
    /// (Cease/Administrative Reset). Replies `PeerCleared` or `PeerNotFound`.
    ClearPeer { peer: IpAddr },
}

/// Messages sent from `nos-bgpd` to a query client.
#[derive(Debug, Serialize, Deserialize)]
pub enum BgpEvent {
    Summary(Vec<PeerSummary>),
    /// Reply to `SendRouteRefresh`: the command was delivered to a live,
    /// `Established` session for that peer.
    RouteRefreshSent,
    /// Reply to `SendRouteRefresh`: no `Established` session with that peer
    /// exists right now. Reply to `ClearPeer`: that peer isn't configured.
    PeerNotFound,
    /// Reply to `GetEvpnRoutes`.
    EvpnRoutes(Vec<EvpnRouteSummary>),
    /// Reply to `ClearPeer`.
    PeerCleared,
}
