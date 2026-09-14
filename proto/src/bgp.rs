//! `nos-bgpd`'s IPC query protocol — backs `nos-cli`'s `show bgp brief`.
//! Mirrors `rib`/`interface`'s shape: a request/event pair framed by
//! `IpcCodec` over a Unix socket resolved via the watchdog broker
//! (`ServiceRef::BgpInstance`).

use std::net::{IpAddr, Ipv4Addr};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

/// The FSM state a peer's session is in, as reported by `nos-bgpd`.
/// `Idle` covers everything before a TCP connection has even reached
/// `OpenSent` (no active/passive attempt has an OPEN in flight yet) — it is
/// not a real state in `nos-bgp::fsm`, which only models `OpenSent`/
/// `OpenConfirm`/`Established`, but is the natural "nothing established yet"
/// value to report over this protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BgpSessionState {
    Idle,
    OpenSent,
    OpenConfirm,
    Established,
}

/// One configured peer's one-line summary, for `show bgp brief`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerSummary {
    pub remote_address: IpAddr,
    pub peer_group: String,
    /// Known only once negotiated (i.e. at least `OpenConfirm`).
    pub remote_as: Option<u32>,
    pub remote_bgp_id: Option<Ipv4Addr>,
    pub state: BgpSessionState,
    /// Seconds since the session reached `Established`. `None` unless
    /// `state == Established` — computed server-side from an `Instant`,
    /// which isn't itself meaningful to serialize across processes.
    pub uptime_secs: Option<u64>,
    pub negotiated_hold_time: Option<u16>,
    pub negotiated_keepalive: Option<u16>,
}

/// A single already-resolved winning route pushed by `nos-ribd` for
/// redistribution into BGP — not `PrefixRoutes`/`RouteEntry`'s
/// multi-candidate shape. `gateway` is carried for completeness only: the
/// BGP RIB engine always applies next-hop-self and never reads it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RedistributedRoute {
    pub prefix: Ipv4Net,
    pub gateway: Ipv4Addr,
}

/// Sent by `nos-ribd` to `nos-bgpd` over a persistent, long-lived
/// connection (mirroring `LogRequest::Push`'s pattern): a `Full` snapshot on
/// connect, then incremental `Add`/`Remove` for each subsequent change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RedistributeUpdate {
    Full(Vec<RedistributedRoute>),
    Add(RedistributedRoute),
    Remove(Ipv4Net),
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
}

/// Messages sent from `nos-bgpd` to a query client.
#[derive(Debug, Serialize, Deserialize)]
pub enum BgpEvent {
    Summary(Vec<PeerSummary>),
}
