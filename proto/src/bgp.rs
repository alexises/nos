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
    /// `Idle` (RFC 4271 section 8.2.2).
    Idle,
    /// `OpenSent`: our OPEN is sent, waiting for the peer's.
    OpenSent,
    /// `OpenConfirm`: OPENs exchanged, waiting for a KEEPALIVE.
    OpenConfirm,
    /// `Established`: UPDATEs may flow.
    Established,
}

/// One configured peer's one-line summary, for `show bgp brief`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerSummary {
    /// The peer's address.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub remote_address: IpAddr,
    /// Name of the peer group the peer belongs to.
    pub peer_group: String,
    /// The peer (or its peer-group) is administratively shut.
    pub shutdown: bool,
    /// Known only once negotiated (i.e. at least `OpenConfirm`).
    pub remote_as: Option<u32>,
    /// BGP Identifier from the peer's OPEN (RFC 4271 section 4.2), once received.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub remote_bgp_id: Option<Ipv4Addr>,
    /// Session state.
    pub state: BgpSessionState,
    /// Seconds since the session reached `Established`. `None` unless
    /// `state == Established` — computed server-side from an `Instant`,
    /// which isn't itself meaningful to serialize across processes.
    pub uptime_secs: Option<u64>,
    /// Hold time agreed with the peer, in seconds (RFC 4271 section 4.2).
    pub negotiated_hold_time: Option<u16>,
    /// Keepalive interval in effect, in seconds.
    pub negotiated_keepalive: Option<u16>,
    /// RFC 5925 TCP-AO live per-connection state, from
    /// `getsockopt(TCP_AO_INFO)` — `Some` only for an `Established` session
    /// whose peer-group uses TCP-AO and whose readback succeeded just now;
    /// `None` for MD5/no-auth peers, a non-`Established` peer, or a readback
    /// that raced session teardown. Counters are since the kernel installed
    /// AO on *this* connection (reset on every reconnect, not cumulative
    /// across the peer's whole configured lifetime). `ao_current_key` is the
    /// `KeyID` signing outgoing segments right now (it follows the peer's
    /// `RNextKeyID`, RFC 5925 §7.5.2); `ao_rnext_key` is the `RecvID` of the key
    /// *this router* asks the peer to send with, not what the peer asked for.
    pub ao_current_key: Option<u8>,
    /// TCP-AO `RNextKeyID` the peer asks us to send (RFC 5925 section 3.1).
    pub ao_rnext_key: Option<u8>,
    /// Segments that passed TCP-AO verification.
    pub ao_packets_good: Option<u64>,
    /// Segments that failed TCP-AO verification.
    pub ao_packets_bad: Option<u64>,
    /// Segments dropped because no matching TCP-AO key was found.
    pub ao_packets_key_not_found: Option<u64>,
    /// Held down by an RFC 4486 maximum-prefix trip: no session is opened or
    /// accepted until `ClearPeer`, a shut/no-shut, or the restart interval.
    pub max_prefix_held: bool,
    /// Accepted (post-import-policy) prefixes from this peer per address
    /// family: ipv4, ipv6, l2vpn-evpn. `Some` only while `Established`.
    pub accepted_prefixes: Option<[u32; 3]>,
    /// The RFC 4724 graceful restart capability the peer last advertised,
    /// while this instance has graceful restart on. Kept after the session
    /// ends, so it shows while its routes are retained.
    pub graceful_restart: Option<GrSummary>,
    /// Routes from this peer kept as stale after a graceful restart, waiting
    /// for its End-of-RIB (also RFC 7313 enhanced route refresh's).
    pub stale_prefixes: u32,
}

/// A peer's RFC 4724 / RFC 8538 graceful restart capability.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrSummary {
    /// Its Restart Time, in seconds.
    pub restart_time: u16,
    /// RFC 8538 N bit: a NOTIFICATION other than a Hard Reset keeps routes.
    pub notification: bool,
    /// R bit: the peer has just restarted.
    pub restarting: bool,
    /// The families it keeps forwarding state for, and each one's F bit.
    pub families: Vec<(crate::AddressFamily, bool)>,
}

/// One received EVPN (RFC 7432) route, for `show bgp evpn`. `route` is the
/// NLRI rendered by `nos-bgpd` (`[2]:[65000:1]:[<esi>]:[<tag>]:...`) — nothing
/// downstream interprets it.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvpnRouteSummary {
    /// The advertising peer.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub peer: IpAddr,
    /// EVPN route type (RFC 7432 section 7).
    pub route_type: u8,
    /// The NLRI rendered as text.
    pub route: String,
    /// The route's BGP next hop.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub next_hop: IpAddr,
    /// Extended communities rendered as `RT:65000:10000`, `encap:8`, ...
    pub extended_communities: Vec<String>,
}

/// RFC 8210 session state of one configured RPKI cache, as seen by one
/// `nos-bgpd`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RpkiSessionState {
    /// Not connected (or a lower-preference cache is in use).
    Idle,
    /// Connected, waiting for the first End of Data.
    Syncing,
    /// Holding a complete VRP set from this cache.
    Established,
}

/// One configured RPKI cache's status, for `show bgp rpki`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpkiCacheStatus {
    /// The cache's address.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub address: IpAddr,
    /// The cache's RTR TCP port (RFC 8210).
    pub port: u16,
    /// Cache preference; the lowest is used first.
    pub preference: u8,
    /// Session state.
    pub state: RpkiSessionState,
    /// This cache's VRPs are the ones validating routes right now.
    pub active: bool,
    /// RTR protocol version negotiated (0 or 1).
    pub version: Option<u8>,
    /// RTR Session ID (RFC 8210 section 5.1), once received.
    pub session_id: Option<u16>,
    /// Latest RTR serial number applied.
    pub serial: Option<u32>,
    /// Validated ROA Payloads currently held from this cache.
    pub vrp_count: usize,
    /// Seconds since the last End of Data from this cache.
    pub last_update_secs: Option<u64>,
    /// The RTR session is configured with TCP-MD5 or TCP-AO (RFC 8210 §9);
    /// never the secret itself. Appended last: postcard is positional.
    #[serde(default)]
    pub authenticated: bool,
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
    /// The redistributed prefix.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub prefix: IpNet,
    /// Next-hop address of the redistributed route.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub gateway: IpAddr,
}

/// Sent by `nos-ribd` to `nos-bgpd` over a persistent, long-lived
/// connection (mirroring `LogRequest::Push`'s pattern): a `Full` snapshot on
/// connect, then incremental `Add`/`Remove` for each subsequent change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RedistributeUpdate {
    /// The complete set of redistributed routes, replacing any previous one.
    Full(Vec<RedistributedRoute>),
    /// One route added or changed.
    Add(RedistributedRoute),
    /// One route withdrawn.
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
    SendRouteRefresh {
        /// The advertising peer.
        peer: IpAddr,
    },
    /// One-shot: every EVPN route received from any peer.
    GetEvpnRoutes,
    /// Fire-and-forget, no reply: one `nos-fdbd`'s local MACs, originated as
    /// EVPN Type-2 (and its flood-list Type-3) routes. `domain` scopes a
    /// `Full`, since several domains feed one BGP instance (unlike
    /// `nos-ribd`, where table and instance are 1:1).
    RedistributeMacs {
        /// Broadcast domain the update belongs to.
        domain: String,
        /// The EVPN route change.
        update: crate::fdb::EvpnUpdate,
    },
    /// Operator-triggered `clear bgp <instance> <peer>`: release a peer held
    /// by its maximum-prefix limit, and reset its session if one is up
    /// (Cease/Administrative Reset). Replies `PeerCleared` or `PeerNotFound`.
    ClearPeer {
        /// The advertising peer.
        peer: IpAddr,
    },
    /// One-shot: every configured RPKI cache's RTR session (`show bgp rpki`).
    GetRpkiSummary,
    /// Fire-and-forget, no reply, `nos-ribd` only: one IP-VRF's best routes
    /// as EVPN Type-5 routes (`EvpnKey::IpPrefix`), originated into this
    /// (underlay) instance. `table` scopes a `Full`, like `RedistributeMacs`'s
    /// `domain`. A variant of its own, not `RedistributeMacs`, since only
    /// `ribd` may send it.
    RedistributeEvpnPrefixes {
        /// Routing table (IP-VRF) the update belongs to.
        table: String,
        /// The EVPN route change.
        update: crate::fdb::EvpnUpdate,
    },
}

/// Messages sent from `nos-bgpd` to a query client.
#[derive(Debug, Serialize, Deserialize)]
pub enum BgpEvent {
    /// Reply to the summary query: one entry per peer.
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
    /// Reply to `GetRpkiSummary`.
    RpkiSummary(Vec<RpkiCacheStatus>),
}
