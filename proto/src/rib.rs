use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Wire twin of `nos-rib`'s internal `RouteSource` — kept separate so
/// `nos-rib`'s own domain type doesn't need to derive wire traits it has no
/// other use for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteSourceKind {
    Static,
    Bgp,
    Ospf,
}

/// One candidate route for a prefix.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteEntry {
    pub gateway: IpAddr,
    pub source: RouteSourceKind,
}

/// One prefix's full candidate list, ordered best (winner) to worst by
/// source preference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrefixRoutes {
    pub prefix: IpNet,
    pub candidates: Vec<RouteEntry>,
}

/// One BGP-learned best-path route, pushed by the owning `nos-bgpd`
/// instance for kernel installation. Always peer-learned — a `Local`-origin
/// (redistributed-from-static) loc-rib entry has no real next-hop and is
/// never pushed at all, to avoid a pointless static→bgp→rib→kernel round
/// trip on the same table it came from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BgpRoute {
    pub prefix: IpNet,
    pub next_hop: IpAddr,
}

/// Sent by the owning `nos-bgpd` instance to `nos-ribd` over a persistent,
/// long-lived connection (mirroring `RedistributeUpdate`'s pattern for the
/// opposite direction): a `Full` snapshot on connect, then incremental
/// `Add`/`Remove` for each subsequent change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BgpRouteUpdate {
    Full(Vec<BgpRoute>),
    Add(BgpRoute),
    Remove(IpNet),
}

/// One SPF-computed OSPF route, pushed by the owning `nos-ospfd` instance
/// for kernel installation — the OSPF analogue of `BgpRoute`. Never a
/// directly-connected destination (root's own subnet) — see
/// `ospf::spf::compute`'s directly-connected filter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OspfRoute {
    pub prefix: IpNet,
    pub next_hop: IpAddr,
    /// The local kernel interface (ifindex) `next_hop` is reachable over,
    /// when the pushing daemon knows it — always `Some` from `nos-ospfv3d`
    /// (RFC 5340 next-hops are link-local IPv6 addresses, which Linux's
    /// netlink `RTM_NEWROUTE` rejects with EINVAL unless an outgoing
    /// interface is given alongside the gateway; `OSPFv3`'s own SPF already
    /// derives it, since a first-hop link-local address is only meaningful
    /// relative to the specific local link it was learned on — see
    /// `ospfv3::spf`'s module doc comment), always `None` from `nos-ospfd`
    /// (RFC 2328 next-hops are ordinary routable IPv4 addresses, which the
    /// kernel resolves via its own routing table without needing one).
    pub interface_id: Option<u32>,
}

/// Sent by the owning `nos-ospfd` instance to `nos-ribd` over a persistent,
/// long-lived connection — the OSPF analogue of `BgpRouteUpdate`, same
/// `Full`-on-connect-then-incremental shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OspfRouteUpdate {
    Full(Vec<OspfRoute>),
    Add(OspfRoute),
    Remove(IpNet),
}

/// Messages sent from a client to a `nos-ribd` instance's IPC socket.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index, so reordering breaks wire compatibility with
/// already-built binaries.
#[derive(Debug, Serialize, Deserialize)]
pub enum RibRequest {
    /// One-shot: every prefix currently in the table, each with its full
    /// candidate list, prefixes in ascending CIDR order.
    GetRoutes,
    /// One-shot: longest-prefix-match lookup for one destination address.
    Lookup { addr: IpAddr },
    /// One-shot: this table's Linux VRF interface name, if its driver has
    /// allocated/created one. The only cross-daemon consumer today is
    /// `nos-interfaced`'s Linux driver, resolving which device to enslave
    /// an interface into — see root `CLAUDE.md`'s "Endpoint broker"
    /// section for how it finds this instance's socket
    /// (`ServiceRef::RibTable`). No table name is carried on the request:
    /// which table you're asking about is implicit in which per-table
    /// `nos-ribd` socket you connected to, exactly like `GetRoutes`/
    /// `Lookup` above.
    GetVrfName,
    /// One-shot: this table's allocated kernel table id, if any — backs
    /// loopback kernel device naming (`lo<table_id>`) in `nos-interfaced`'s
    /// Linux driver. Symmetric to `GetVrfName`; no table name carried, same
    /// reasoning.
    GetTableId,
    /// Fire-and-forget, no reply — sent continuously by the owning
    /// `nos-bgpd` instance over one long-lived connection, mirroring
    /// `BgpRequest::RedistributeRoutes`'s pattern for the opposite
    /// direction. One or more updates from a single poll tick, batched
    /// into one message rather than one `PushBgpRoutes` per update — the
    /// receiving `nos-ribd` applies the whole batch to its in-memory `Rib`
    /// first, then touches the kernel once for the prefixes whose winning
    /// route actually changed, never once per update.
    PushBgpRoutes(Vec<BgpRouteUpdate>),
    /// Fire-and-forget, no reply — sent continuously by the owning
    /// `nos-ospfd` instance over one long-lived connection, the OSPF
    /// analogue of `PushBgpRoutes` above (its own SPF computation, not BGP
    /// best-path selection, is what changes here).
    PushOspfRoutes(Vec<OspfRouteUpdate>),
}

/// Messages sent from a `nos-ribd` instance to a client.
#[derive(Debug, Serialize, Deserialize)]
pub enum RibEvent {
    /// Reply to `GetRoutes`.
    Routes(Vec<PrefixRoutes>),
    /// Reply to `Lookup` when a covering prefix exists.
    Match(PrefixRoutes),
    /// Reply to `Lookup` when no configured prefix covers the address (no
    /// default route).
    NoMatch,
    /// A human-readable error message from the daemon.
    Error(String),
    /// Reply to `GetVrfName`. `None` if no VRF has been allocated/created
    /// yet (or the running driver never backs a table with a real VRF at
    /// all, e.g. a no-op driver) — a normal, expected transient state, not
    /// an error.
    VrfName(Option<String>),
    /// Reply to `GetTableId`. `None` under the same conditions as
    /// `VrfName(None)` — normal/transient, never an error.
    TableId(Option<u32>),
}
