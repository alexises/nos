use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Wire twin of `nos-rib`'s internal `RouteSource` — kept separate so
/// `nos-rib`'s own domain type doesn't need to derive wire traits it has no
/// other use for.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteSourceKind {
    /// A statically configured route.
    Static,
    /// A route learned via BGP.
    Bgp,
    /// A route learned via OSPF.
    Ospf,
    /// A directly-connected prefix, derived by `nos-ribd` from the
    /// addresses `nos-interfaced` applied in this table.
    Connected,
    /// An EVPN Type-5 (RFC 9136) route received over the table's L3 VNI.
    Evpn,
}

/// What an `Evpn`-sourced candidate is reached through: the remote VTEP (its
/// one gateway), the remote PE's Router's MAC and the L3 VNI.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvpnRouteInfo {
    /// Remote VTEP the route is tunnelled to.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub vtep: IpAddr,
    /// `aa:bb:cc:dd:ee:ff`.
    pub router_mac: String,
    /// VXLAN VNI of the tunnel.
    pub vni: u32,
}

/// One candidate route for a prefix.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteEntry {
    /// Every next hop of this candidate — two or more is an equal-cost
    /// multipath (ECMP) route, installed as one kernel route.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub gateways: Vec<IpAddr>,
    /// Protocol that produced the route.
    pub source: RouteSourceKind,
    /// Pre-computed backup next hop, installed in the kernel at a higher
    /// metric so it takes over the instant the primary is withdrawn.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub backup: Option<IpAddr>,
    /// A discard (blackhole) route — no gateway; e.g. an OSPF ABR's route
    /// for one of its advertised area ranges (RFC 2328 §3.5).
    #[serde(default)]
    pub discard: bool,
    /// Set on an `Evpn` candidate.
    #[serde(default)]
    pub evpn: Option<EvpnRouteInfo>,
    /// `backup` is an RFC 7490 remote LFA: the PQ node the backup tunnels
    /// (IP-in-IP) to, not a neighbor.
    #[serde(default)]
    pub backup_tunnel: bool,
}

/// One prefix's full candidate list, ordered best (winner) to worst by
/// source preference.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrefixRoutes {
    /// The destination prefix.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub prefix: IpNet,
    /// All candidate routes for the prefix.
    pub candidates: Vec<RouteEntry>,
}

/// One BGP-learned best-path route, pushed by the owning `nos-bgpd`
/// instance for kernel installation. Always peer-learned — a `Local`-origin
/// (redistributed-from-static) loc-rib entry has no real next-hop and is
/// never pushed at all, to avoid a pointless static→bgp→rib→kernel round
/// trip on the same table it came from.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BgpRoute {
    /// The destination prefix.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub prefix: IpNet,
    /// The best path's next hop plus every multipath sibling's
    /// (`BgpInstance.maximum_paths`), sorted, never empty. Two or more
    /// become one `RTA_MULTIPATH` kernel route.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub next_hops: Vec<IpAddr>,
    /// Runner-up path's next hop (none of `next_hops`), if any.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub backup_next_hop: Option<IpAddr>,
}

/// Sent by the owning `nos-bgpd` instance to `nos-ribd` over a persistent,
/// long-lived connection (mirroring `RedistributeUpdate`'s pattern for the
/// opposite direction): a `Full` snapshot on connect, then incremental
/// `Add`/`Remove` for each subsequent change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BgpRouteUpdate {
    /// The complete route set, replacing any previous one.
    Full(Vec<BgpRoute>),
    /// One route added or changed.
    Add(BgpRoute),
    /// One route withdrawn.
    Remove(IpNet),
}

/// One SPF-computed OSPF route, pushed by the owning `nos-ospfd` instance
/// for kernel installation — the OSPF analogue of `BgpRoute`. Never a
/// directly-connected destination (root's own subnet) — see
/// `ospf::spf::compute`'s directly-connected filter.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OspfRoute {
    /// The destination prefix.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub prefix: IpNet,
    /// Every equal-cost next hop (RFC 2328 §16.1 2(d)), non-empty unless
    /// `discard` is set, each
    /// with the local kernel interface (ifindex) it is reachable over when
    /// the pushing daemon knows it — always `Some` from `nos-ospfv3d`
    /// (RFC 5340 next-hops are link-local IPv6 addresses, which Linux's
    /// netlink `RTM_NEWROUTE` rejects with EINVAL unless an outgoing
    /// interface is given alongside the gateway; `OSPFv3`'s own SPF already
    /// derives it, since a first-hop link-local address is only meaningful
    /// relative to the specific local link it was learned on — see
    /// `ospfv3::spf`'s module doc comment), always `None` from `nos-ospfd`
    /// (RFC 2328 next-hops are ordinary routable IPv4 addresses, which the
    /// kernel resolves via its own routing table without needing one).
    /// Two or more become one `RTA_MULTIPATH` kernel route.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<Object>))]
    pub next_hops: Vec<(IpAddr, Option<u32>)>,
    /// RFC 5286 loop-free alternate next hop, if one exists.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub backup_next_hop: Option<IpAddr>,
    /// The ifindex of `backup_next_hop` (which may leave over a
    /// different link than the primary).
    pub backup_interface_id: Option<u32>,
    /// SPF cost to `prefix` — what BGP's RFC 4271 §9.1.2.2(d) step compares
    /// (via `RibRequest::IgpCosts`) for paths whose `NEXT_HOP` falls in it.
    pub metric: u32,
    /// A discard route: an ABR's blackhole for one of its active advertised
    /// area ranges (RFC 2328 §3.5), so traffic to an unused part of the
    /// range is dropped rather than looping on a covering route.
    /// `next_hops` is empty and `backup_next_hop` `None` when set.
    #[serde(default)]
    pub discard: bool,
    /// RFC 7490 remote LFA: the PQ node (its loopback) to tunnel to when
    /// the primary fails — set only when `backup_next_hop` is `None`.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[serde(default)]
    pub backup_tunnel: Option<IpAddr>,
}

/// Sent by the owning `nos-ospfd` instance to `nos-ribd` over a persistent,
/// long-lived connection — the OSPF analogue of `BgpRouteUpdate`, same
/// `Full`-on-connect-then-incremental shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OspfRouteUpdate {
    /// The complete route set, replacing any previous one.
    Full(Vec<OspfRoute>),
    /// One route added or changed.
    Add(OspfRoute),
    /// One route withdrawn.
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
    Lookup {
        /// Address to look up.
        addr: IpAddr,
    },
    /// One-shot: this table's Linux VRF interface name, if its driver has
    /// allocated/created one. The only cross-daemon consumer today is
    /// `nos-interfaced`'s Linux driver, resolving which device to enslave
    /// an interface into — see `docs/architecture/endpoint-broker.md`
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
    /// One-shot: the IGP cost of every prefix whose best non-BGP candidate
    /// is known (`Static` = 0, `Ospf` = its SPF metric). BGP resolves each
    /// path's `NEXT_HOP` against this for decision step (d); `Bgp`-sourced
    /// routes are excluded so a next hop never resolves recursively.
    IgpCosts,
    /// Fire-and-forget, no reply, `nos-bgpd` only: every EVPN Type-5 route
    /// the underlay instance named by this table's `evpn.bgp_instance`
    /// received (`Full` on connect, then `Add`/`Remove`). Route-Target and
    /// VNI filtering is `nos-ribd`'s.
    PushEvpnRoutes(crate::fdb::EvpnUpdate),
    /// One-shot, `nos-bgpd` only: how many `Bgp`-sourced candidates this
    /// table still holds. A restarted `nos-bgpd` asks it once at startup:
    /// more than zero means its forwarding state survived (RFC 4724 §4.1),
    /// so it restarts gracefully (F bit, selection deferral).
    BgpRouteCount,
    /// One-shot, `nos-fdbd` only: this table's EVPN IP-VRF, for RFC 9135
    /// symmetric IRB (Label2 + Router's MAC on a domain's MAC+IP routes).
    GetEvpnIrb,
}

/// Reply to `GetEvpnIrb`: what a MAC+IP route needs to be symmetric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvpnIrb {
    /// L3 VNI of the IP-VRF (RFC 9135), if any.
    pub l3_vni: u32,
    /// The IP-VRF's Router's MAC (`brv<l3-vni>`'s address).
    pub router_mac: [u8; 6],
    /// The IP-VRF's export Route Targets, as extended communities.
    pub route_targets_export: Vec<u64>,
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
    /// Reply to `IgpCosts`.
    IgpCosts(Vec<(IpNet, u32)>),
    /// Reply to `BgpRouteCount`.
    BgpRouteCount(u32),
    /// Reply to `GetEvpnIrb`. `None` until the IP-VRF is up (an L3 VNI, its
    /// VTEP and the Router's MAC known; never with `--driver noop`).
    EvpnIrb(Option<EvpnIrb>),
}
