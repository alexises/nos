//! The BGP RIB engine: Adj-RIB-In per peer, a locally-redistributed route
//! set (fed by `nos-ribd` via `nos_proto::RedistributeUpdate`, filtered
//! through the configured redistribute RPL policy — see
//! `apply_redistribute_update`/`set_redistribute_policy`), a cached
//! Loc-RIB best-path per prefix, and per-peer outbound channels used to push
//! `OutboundUpdate`s out to each `fsm::run` task. Prefixes/next-hops are
//! `IpNet`/`IpAddr` throughout — v4 and v6 share the same maps, family
//! discriminated by the value itself, the same pattern `nos-rib`'s own `Rib`
//! already uses.
//!
//! Best path selection (`best_path`) implements the full RFC 4271 §9.1.2.2
//! decision process, in order: (1) higher `LOCAL_PREF`; (2) a
//! locally-redistributed route beats any peer-learned route (not an RFC
//! step — this implementation's equivalent of "prefer locally originated",
//! placed here per common vendor convention, e.g. Cisco's own ordering);
//! (3) shorter `AS_PATH` (`AS_SET` vs. `AS_SEQUENCE` segmentation isn't
//! preserved — see `message.rs`'s documented simplification — so this
//! compares flattened length only); (4) lowest `ORIGIN` type (`Igp` <
//! `Egp` < `Incomplete`); (5) lowest `MULTI_EXIT_DISC`, only compared
//! between routes sharing the same neighboring AS (`AS_PATH`'s first
//! entry), missing MED treated as 0; (6) an eBGP-learned route beats an
//! iBGP-learned one; (7) lowest IGP metric to the next-hop — **not
//! implemented**: this NOS has no IGP protocol yet, so this step is a
//! documented no-op rather than a fabricated metric; (8) oldest route
//! wins (by `received_at`), only between two eBGP-learned candidates,
//! per RFC 4271's anti-flap tie-break; (9) lowest BGP Identifier
//! (router-id) of the advertising peer; (10) lowest advertising peer
//! address, the final deterministic tiebreak.
//! - Next-hop rewriting is peer-group configurable (`nos_proto::NextHopMode`
//!   — `SelfAddress`/`Unchanged`), defaulting to `SelfAddress` for an eBGP
//!   peer and `Unchanged` for an iBGP one. `Unchanged` re-advertises the
//!   route's own stored next-hop (the address it was received with, for a
//!   peer-learned route); a locally-redistributed route has no such stored
//!   value, so it always gets next-hop-self regardless of mode.
//!   `SelfAddress` always uses the destination peer's own session-local
//!   address (`PeerOutbox::local_addr`), regardless of the prefix's own
//!   family — this is what makes RFC 8950 cross-family next-hop work: no
//!   special-casing needed here, since `local_addr` is already whatever
//!   family this session's transport is.
//! - Standard iBGP split-horizon (no route reflection): a route learned via
//!   one iBGP peer is never re-advertised to another iBGP peer.
//! - `AS_PATH` is prepended with our own ASN only toward eBGP peers;
//!   `LOCAL_PREF` is included only toward iBGP peers.
//! - A received route whose `AS_PATH` already contains our own ASN is dropped
//!   (loop prevention), not just deprioritized.
//! - A peer only ever gets a prefix whose address family is in its own
//!   `negotiated_afs` (config ∩ what was actually negotiated in OPEN — see
//!   `fsm::negotiate_address_families`); `mp_bgp_negotiated` then picks
//!   whether that peer's `OutboundUpdate`s get encoded as legacy plain NLRI
//!   or `MP_REACH_NLRI`/`MP_UNREACH_NLRI` (`fsm::outbound_update_to_message`
//!   is the encode side of that decision).
//!
//! Locking: one whole-instance `Arc<tokio::sync::Mutex<BgpRib>>`, owned by
//! `session::SessionManager`. All methods here are synchronous `&mut self`
//! (channel sends are non-blocking) — callers lock once per call. A single
//! lock is deliberate: best-path recomputation must see a consistent
//! cross-peer view, and this NOS's route volume is not internet-table scale.
//!
//! Outbox ownership lives here (`BgpRib::peer_outboxes`), keyed by `IpAddr`,
//! rather than as a field on `collision::PeerSlot` — `BgpRib` already needs a
//! peer-keyed table for `adj_rib_in`, and `PeerSlot`'s job is strictly RFC
//! 4271 §6.8 arbitration, not routing state.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

use ipnet::IpNet;
use nos_proto::{AddressFamily, NextHopMode, RedistributeUpdate};
use nos_rpl::CompiledPolicy;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::evpn::EvpnNlri;
use crate::message::{self, UpdateMessage};

mod evpn_out;
pub use evpn_out::AdvertisedEvpn;

/// Adapts a `RibRoute` into `nos_rpl`'s input shape — see root `CLAUDE.md`'s
/// "Execution model". A plain function, not an adapter trait: there is
/// exactly one producer (`RibRoute`) today, so a trait would add indirection
/// with nothing to abstract over yet.
fn to_policy_input(prefix: IpNet, route: &RibRoute) -> nos_rpl::Input<'_> {
    nos_rpl::Input {
        prefix,
        bgp: nos_rpl::BgpInput {
            origin: match route.bgp_origin {
                message::Origin::Igp => nos_rpl::Origin::Igp,
                message::Origin::Egp => nos_rpl::Origin::Egp,
                message::Origin::Incomplete => nos_rpl::Origin::Incomplete,
            },
            as_path: &route.as_path,
            local_pref: route.local_pref,
            med: route.med,
            next_hop: route.next_hop,
            learned_via_ibgp: route.learned_via_ibgp,
            router_id: route.router_id,
            originator_id: route.originator_id,
            cluster_list: &route.cluster_list,
            communities: &route.communities,
            extended_communities: &route.extended_communities,
            large_communities: &route.large_communities,
        },
    }
}

/// Runs a compiled RPL policy against a candidate route — a peer's import
/// policy against a freshly-received UPDATE, or the redistribute policy
/// against a locally-redistributed route (see `apply_redistribute_update`).
/// `None` means reject: for peer import, the caller treats the prefix like
/// an explicit withdrawal instead of inserting it, since a rejected route
/// must not linger in `adj_rib_in` from an earlier, now-superseded UPDATE;
/// for redistribution, the caller simply omits the prefix from `redistributed`.
fn apply_policy(
    prefix: IpNet,
    mut candidate: RibRoute,
    policy: &CompiledPolicy,
) -> Option<RibRoute> {
    match nos_rpl::vm::run(policy, &to_policy_input(prefix, &candidate)) {
        nos_rpl::Verdict::Reject => None,
        nos_rpl::Verdict::Accept {
            local_pref,
            med,
            communities,
            extended_communities,
            large_communities,
        } => {
            candidate.local_pref = local_pref;
            candidate.med = med;
            candidate.communities = communities;
            candidate.extended_communities = extended_communities;
            candidate.large_communities = large_communities;
            Some(candidate)
        }
    }
}

/// Stores one `MP_REACH_NLRI` batch's EVPN routes in a peer's EVPN Adj-RIB-In,
/// logging only routes that are new or changed.
fn learn_evpn(
    table: &mut HashMap<EvpnNlri, EvpnRoute>,
    from: IpAddr,
    mp: &message::MpReachNlri,
    extended_communities: &[u64],
    pmsi: Option<message::Pmsi>,
) {
    for nlri in &mp.evpn {
        let route = EvpnRoute {
            next_hop: mp.next_hop,
            pmsi_vni: pmsi.map(|p| p.vni),
            extended_communities: extended_communities.to_vec(),
        };
        if table.insert(nlri.clone(), route.clone()) != Some(route) {
            info!(peer = %from, route_type = nlri.route_type(), route = %nlri, next_hop = %mp.next_hop, "evpn route learned");
        }
    }
}

/// Applies one learned NLRI to a peer's Adj-RIB-In, shared by an UPDATE's
/// plain IPv4 NLRI and its RFC 4760 `MP_REACH_NLRI`, which differ only in
/// where the next-hop comes from.
///
/// A rejected prefix is *removed* rather than skipped — a policy that now
/// rejects it must not leave an earlier, now-superseded copy behind — and is
/// `touched` either way so best-path selection re-runs for it.
fn learn_prefix(
    table: &mut HashMap<IpNet, RibRoute>,
    touched: &mut HashSet<IpNet>,
    from: IpAddr,
    prefix: IpNet,
    candidate: RibRoute,
    import_policy: &CompiledPolicy,
) {
    match apply_policy(prefix, candidate, import_policy) {
        Some(route) => {
            info!(peer = %from, "bgp: learned route for {prefix} into adj-rib-in");
            table.insert(prefix, route);
        }
        None => {
            table.remove(&prefix);
        }
    }
    touched.insert(prefix);
}

/// RFC 4271 §5.1.5's default `LOCAL_PREF`, applied whenever a peer's UPDATE
/// omits the attribute (or for every locally-redistributed route, which
/// carries no wire attributes at all).
const DEFAULT_LOCAL_PREF: u32 = 100;

fn family_of(net: IpNet) -> AddressFamily {
    match net {
        IpNet::V4(_) => AddressFamily::Ipv4Unicast,
        IpNet::V6(_) => AddressFamily::Ipv6Unicast,
    }
}

/// Where a `RibRoute` came from — `Local` for a route pushed in by
/// `nos-ribd`'s redistribution feed, `Peer(addr)` for one learned from a
/// specific peer's Adj-RIB-In.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteOrigin {
    Local,
    Peer(IpAddr),
}

/// One received EVPN route's attributes — `Adj-RIB-In` content, nothing derived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnRoute {
    pub next_hop: IpAddr,
    /// The VNI of a Type-3 route's PMSI Tunnel attribute, when it had one.
    pub pmsi_vni: Option<u32>,
    /// Raw 8-byte extended communities (Route Targets, Encapsulation, MAC
    /// Mobility, ...), exactly as received.
    pub extended_communities: Vec<u64>,
}

/// One candidate route for a prefix, either locally redistributed or learned
/// from a peer.
#[derive(Debug, Clone, PartialEq)]
pub struct RibRoute {
    pub origin: RouteOrigin,
    /// Never mutated in place by RPL (`as_path` is a read-only policy input)
    /// — shared via `Arc` so cloning a `RibRoute` (candidate collection,
    /// `loc_rib`/`adj_rib_in` storage) never deep-copies this list.
    pub as_path: Arc<Vec<u32>>,
    pub bgp_origin: message::Origin,
    /// Always the effective value — defaulted to `DEFAULT_LOCAL_PREF` when
    /// the peer's UPDATE omitted `LOCAL_PREF`, or for a `Local` route.
    pub local_pref: u32,
    /// `Some` iff the peer's UPDATE carried `MULTI_EXIT_DISC`. Always
    /// `None` for `origin == Local` — a locally-redistributed route never
    /// carries one.
    pub med: Option<u32>,
    /// Meaningless when `origin == Local`.
    pub learned_via_ibgp: bool,
    /// The advertising peer's BGP Identifier, for `origin == Peer(_)` —
    /// used as the RFC 4271 §9.1.2.2 router-id tiebreak. Always `None` for
    /// `origin == Local`.
    pub router_id: Option<Ipv4Addr>,
    /// The `NEXT_HOP` this route was received with, for `origin ==
    /// Peer(_)` — read back out when a destination peer-group's `next_hop`
    /// resolves to `NextHopMode::Unchanged`. Always `None` for `origin ==
    /// Local`: a locally-redistributed route has no "received" next-hop to
    /// preserve, so it always gets next-hop-self regardless of mode.
    pub next_hop: Option<IpAddr>,
    /// When this candidate was learned — used only by the RFC 4271
    /// §9.1.2.2 "oldest route wins" tiebreak between two eBGP-learned
    /// candidates. Meaningless when `origin == Local`.
    pub received_at: Instant,
    /// RFC 4456 §5 `ORIGINATOR_ID`, for `origin == Peer(_)` — `Some` iff the
    /// peer's UPDATE carried it (meaning this route was already reflected at
    /// least once upstream). Always `None` for `origin == Local`.
    pub originator_id: Option<Ipv4Addr>,
    /// RFC 4456 §5 `CLUSTER_LIST`, for `origin == Peer(_)` — one cluster-id
    /// per route reflector this route has already passed through, nearest
    /// first. Always empty for `origin == Local`. Never mutated in place by
    /// RPL, like `as_path` — shared via `Arc` for the same reason.
    pub cluster_list: Arc<Vec<Ipv4Addr>>,
    /// RFC 1997 `COMMUNITY` values, possibly rewritten by import policy.
    /// Empty for a fresh `Local` route (no wire attributes to start from).
    pub communities: Vec<u32>,
    /// RFC 4360 `EXTENDED_COMMUNITIES` values, possibly rewritten by import
    /// policy. Empty for a fresh `Local` route.
    pub extended_communities: Vec<u64>,
    /// RFC 8092 `LARGE_COMMUNITY` values, possibly rewritten by import
    /// policy. Empty for a fresh `Local` route.
    pub large_communities: Vec<(u32, u32, u32)>,
}

/// One update this instance needs to send out over a specific peer's
/// session. The `bool` picks the destination peer's wire encoding (`true` =
/// `MP_REACH_NLRI`/`MP_UNREACH_NLRI`, `false` = legacy plain NLRI — see
/// `fsm::outbound_update_to_message`), mirroring `AdvertisedRoute::use_mp`.
/// `Withdraw`'s trailing `Option<u32>` is the RFC 7911 ADD-PATH identifier
/// being withdrawn — `Some` only ever comes from
/// `BgpRib::propagate_rs_view`'s per-source fan-out to a
/// `route_server_client` peer; every other withdrawal path always sends
/// `None` (no ADD-PATH in use).
#[derive(Debug, Clone, PartialEq)]
pub enum OutboundUpdate {
    Announce(AdvertisedRoute),
    Withdraw(IpNet, bool, Option<u32>),
    /// An EVPN route originated by `nos-fdbd` (see `evpn_out`).
    AnnounceEvpn(AdvertisedEvpn),
    WithdrawEvpn(EvpnNlri),
}

/// A route rewritten for advertisement toward one specific peer.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvertisedRoute {
    pub prefix: IpNet,
    /// Already rewritten for the destination peer (our ASN prepended iff
    /// eBGP and not a `route_server_client`).
    pub as_path: Vec<u32>,
    /// Rewritten per the destination peer-group's effective `NextHopMode` —
    /// either that peer's own session's local address (`SelfAddress`) or the
    /// route's stored next-hop (`Unchanged`).
    pub next_hop: IpAddr,
    /// `Some` only toward iBGP peers.
    pub local_pref: Option<u32>,
    /// The route's `MULTI_EXIT_DISC`, forwarded only toward iBGP peers —
    /// MED is meant for use between adjacent ASes, so it's never
    /// propagated further to another eBGP peer.
    pub med: Option<u32>,
    pub origin: message::Origin,
    /// Whether the destination peer negotiated any Multiprotocol Extensions
    /// capability at all — `true` means encode via `MP_REACH_NLRI` (even for
    /// an `Ipv4Unicast` prefix), `false` means the legacy plain-NLRI fields
    /// (only ever set for an `Ipv4Unicast` prefix/next-hop).
    pub use_mp: bool,
    /// `Some` only when reflecting (RFC 4456 §5) — the route's original
    /// advertising router, set once by the first reflector and never
    /// rewritten by a later one.
    pub originator_id: Option<Ipv4Addr>,
    /// `Some` only when reflecting — the reflected route's `CLUSTER_LIST`
    /// with this instance's own cluster-id prepended. Empty otherwise.
    pub cluster_list: Vec<Ipv4Addr>,
    /// Optional-transitive by RFC 1997/4360/8092 default, so — unlike
    /// `local_pref`/`med` — these three propagate to every eligible peer
    /// unconditionally, regardless of eBGP/iBGP; an export policy's
    /// `.clear()`/`.remove()` is the only way to strip one toward a
    /// specific peer.
    pub communities: Vec<u32>,
    pub extended_communities: Vec<u64>,
    pub large_communities: Vec<(u32, u32, u32)>,
    /// RFC 7911 ADD-PATH identifier — `Some` only when
    /// `BgpRib::propagate_rs_view` is sending one of several concurrent
    /// paths for the same prefix to a `route_server_client` peer that
    /// negotiated ADD-PATH for this family. `None` for every ordinary
    /// single-best-path advertisement.
    pub path_id: Option<u32>,
}

#[allow(clippy::struct_excessive_bools)] // each bool is an independent, unrelated per-session flag
#[allow(clippy::similar_names)] // is_rr_client (reflector) vs. is_rs_client (server) are deliberately parallel
struct PeerOutbox {
    tx: mpsc::UnboundedSender<OutboundUpdate>,
    is_ibgp: bool,
    /// This session's own transport-local address, of whatever family —
    /// used as next-hop-self for every negotiated address family this peer
    /// carries, cross-family or not (RFC 8950). `None` if it couldn't be
    /// determined, in which case this peer is never eligible for a
    /// `SelfAddress` advertisement.
    local_addr: Option<IpAddr>,
    /// Address families this peer actually negotiated (config ∩ what was
    /// negotiated in OPEN — see `fsm::negotiate_address_families`). A prefix
    /// whose family isn't in this set is never advertised to this peer.
    negotiated_afs: HashSet<AddressFamily>,
    /// Whether this peer negotiated any Multiprotocol Extensions capability
    /// at all — see `AdvertisedRoute::use_mp`.
    mp_bgp_negotiated: bool,
    /// This peer-group's configured next-hop override, if any — `None`
    /// resolves to `SelfAddress` for an eBGP peer, `Unchanged` for an iBGP
    /// one (see `build_advertisement`).
    next_hop_mode: Option<NextHopMode>,
    /// RFC 4456 route-reflector client — see `build_advertisement`'s
    /// reflection eligibility check.
    is_rr_client: bool,
    /// RFC 7947 route-server client — see `build_advertisement`'s `AS_PATH`
    /// exception and `BgpRib::propagate_rs_view`.
    is_rs_client: bool,
    /// Address families this peer negotiated RFC 7911 ADD-PATH for (always
    /// empty unless `is_rs_client`) — gates `propagate_rs_view`'s per-source
    /// multi-path fan-out; a family missing here still gets the ordinary
    /// single-best-path advertisement like any other peer.
    add_path_afs: HashSet<AddressFamily>,
    /// This peer-group's resolved export policy — always present, `deny-all`
    /// by default (see root `CLAUDE.md`'s "Default-deny rollout impact"),
    /// consulted by `build_advertisement`.
    export_policy: Arc<CompiledPolicy>,
}

/// The BGP RIB engine for one `nos-bgpd` instance. See the module doc
/// comment for the locking model.
pub struct BgpRib {
    local_asn: u32,
    /// This instance's own router-id — used for RFC 4456 §5 `ORIGINATOR_ID`
    /// loop-prevention on receipt (`handle_update`).
    local_router_id: Ipv4Addr,
    /// This instance's effective RFC 4456 cluster-id (`BgpInstance.cluster_id`
    /// unwrapped to `router_id` when unset) — prepended to `CLUSTER_LIST` on
    /// reflection and checked for loop-prevention on receipt.
    cluster_id: Ipv4Addr,
    adj_rib_in: HashMap<IpAddr, HashMap<IpNet, RibRoute>>,
    /// Received EVPN (RFC 7432) routes per peer, keyed by NLRI.
    // ponytail: Adj-RIB-In only — no best-path, Route-Target import filtering,
    // import policy (RPL's `Input` is prefix-shaped) or re-advertisement, since
    // nothing consumes EVPN routes yet. Add a Loc-RIB when a MAC-VRF does.
    evpn_adj_rib_in: HashMap<IpAddr, HashMap<EvpnNlri, EvpnRoute>>,
    /// EVPN routes originated by each `nos-fdbd` (keyed by broadcast domain),
    /// and what was last announced to each peer — see `evpn_out`.
    evpn_local: HashMap<String, HashMap<nos_proto::EvpnKey, nos_proto::EvpnRoute>>,
    evpn_adj_rib_out: HashMap<IpAddr, HashMap<EvpnNlri, AdvertisedEvpn>>,
    /// Broadcast domains whose `redistribute from mac to bgp` names this
    /// instance — the ones `fdb_push_client` feeds received EVPN routes to.
    fdb_domains: Vec<String>,
    /// The unfiltered prefix set as told by `nos-ribd`'s
    /// `RedistributeUpdate` — the raw truth `redistributed` below is
    /// filtered from (see `apply_redistribute_update`/`set_redistribute_policy`).
    redistribute_raw: HashSet<IpNet>,
    /// `redistribute_raw` filtered through `redistribute_policy` — this is
    /// what best-path selection (`recompute_and_propagate`) actually reads.
    redistributed: HashMap<IpNet, RibRoute>,
    /// The compiled RPL policy currently filtering redistribution, resolved
    /// from `BgpInstance.redistribute_policy` by `reconcile.rs`'s `resync`
    /// (`None` there means accept-all, unlike peer import/export's
    /// deny-all default — see `proto`'s `Redistribute.policy` doc comment).
    redistribute_policy: Arc<CompiledPolicy>,
    loc_rib: HashMap<IpNet, RibRoute>,
    /// Per prefix, the runner-up path's next hop (a different next hop from
    /// the winner's), pushed to `nos-ribd` as the kernel backup route.
    backups: HashMap<IpNet, IpAddr>,
    /// What we've last told each peer, for correct withdrawals.
    adj_rib_out: HashMap<IpAddr, HashSet<IpNet>>,
    peer_outboxes: HashMap<IpAddr, PeerOutbox>,
    /// Per `route_server_client` peer, per prefix, the path id and last-sent
    /// snapshot of every source currently advertised to it — see
    /// `propagate_rs_view`.
    rs_sent: HashMap<(IpAddr, IpNet), HashMap<RouteOrigin, (u32, RibRoute)>>,
    /// Per `route_server_client` peer, per prefix, the next path id to
    /// allocate — monotonic, never recycled (see `propagate_rs_view`'s doc
    /// comment).
    rs_next_id: HashMap<(IpAddr, IpNet), u32>,
    /// Reusable scratch buffer for `recompute_and_propagate`'s peer list —
    /// swapped out via `mem::take` and refilled each call instead of
    /// collecting a fresh `Vec` on every touched prefix, so its capacity is
    /// retained across calls once it reaches the peer count.
    peer_scratch: Vec<IpAddr>,
    /// This instance's owning `RoutingTable` name (`BgpInstance.routing_table`),
    /// set by `session::SessionManager::reconcile`. Read by `push_snapshot`
    /// to resolve which `nos-ribd` instance, if any, this instance's best
    /// routes should be pushed to.
    owning_routing_table: Option<String>,
}

impl Default for BgpRib {
    fn default() -> Self {
        Self::new()
    }
}

impl BgpRib {
    pub fn new() -> Self {
        Self {
            local_asn: 0,
            local_router_id: Ipv4Addr::UNSPECIFIED,
            cluster_id: Ipv4Addr::UNSPECIFIED,
            adj_rib_in: HashMap::new(),
            evpn_adj_rib_in: HashMap::new(),
            evpn_local: HashMap::new(),
            evpn_adj_rib_out: HashMap::new(),
            fdb_domains: Vec::new(),
            redistribute_raw: HashSet::new(),
            redistributed: HashMap::new(),
            redistribute_policy: Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            loc_rib: HashMap::new(),
            backups: HashMap::new(),
            adj_rib_out: HashMap::new(),
            peer_outboxes: HashMap::new(),
            rs_sent: HashMap::new(),
            rs_next_id: HashMap::new(),
            peer_scratch: Vec::new(),
            owning_routing_table: None,
        }
    }

    /// Sets this instance's own ASN, router-id, and effective RFC 4456
    /// cluster-id (already resolved from `BgpInstance.cluster_id.unwrap_or(
    /// router_id)` by the caller — see `session::LocalIdentity`).
    pub fn set_local_identity(&mut self, asn: u32, router_id: Ipv4Addr, cluster_id: Ipv4Addr) {
        self.local_asn = asn;
        self.local_router_id = router_id;
        self.cluster_id = cluster_id;
    }

    /// Sets the broadcast domains fed by `fdb_push_client`.
    pub fn set_fdb_domains(&mut self, domains: Vec<String>) {
        self.fdb_domains = domains;
    }

    pub fn fdb_domains(&self) -> &[String] {
        &self.fdb_domains
    }

    /// Sets this instance's owning `RoutingTable` name (`BgpInstance.routing_table`).
    pub fn set_routing_table(&mut self, table: Option<String>) {
        self.owning_routing_table = table;
    }

    /// Snapshot for `rib_push_client`: this instance's owning routing table
    /// name, and every loc-rib prefix whose winner has a real next-hop. A
    /// `Local`-origin (redistributed-from-static) loc-rib entry always has
    /// `next_hop: None` (see `redistributed_route`) and is excluded — there's
    /// no real gateway to install, and pushing it would round-trip
    /// static→bgp→rib→kernel pointlessly on the same table it came from.
    pub fn push_snapshot(&self) -> (Option<String>, HashMap<IpNet, Hops>) {
        let routes = self
            .loc_rib
            .iter()
            .filter_map(|(prefix, route)| {
                route
                    .next_hop
                    .map(|next_hop| (*prefix, (next_hop, self.backups.get(prefix).copied())))
            })
            .collect();
        (self.owning_routing_table.clone(), routes)
    }

    /// Registers a newly-`Established` peer's outbound channel and does an
    /// initial full advertisement of the current Loc-RIB to it.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::fn_params_excessive_bools)] // each bool is an independent, unrelated flag
    #[allow(clippy::similar_names)] // is_rr_client (reflector) vs. is_rs_client (server)
    pub fn peer_established(
        &mut self,
        peer: IpAddr,
        is_ibgp: bool,
        local_addr: Option<IpAddr>,
        negotiated_afs: HashSet<AddressFamily>,
        mp_bgp_negotiated: bool,
        next_hop_mode: Option<NextHopMode>,
        is_rr_client: bool,
        is_rs_client: bool,
        add_path_afs: HashSet<AddressFamily>,
        export_policy: Arc<CompiledPolicy>,
        tx: mpsc::UnboundedSender<OutboundUpdate>,
    ) {
        self.peer_outboxes.insert(
            peer,
            PeerOutbox {
                tx,
                is_ibgp,
                local_addr,
                negotiated_afs,
                mp_bgp_negotiated,
                next_hop_mode,
                is_rr_client,
                is_rs_client,
                add_path_afs,
                export_policy,
            },
        );
        let outbox = self.peer_outboxes.get(&peer).expect("just inserted");
        let mut advertised = HashSet::new();
        for (prefix, best) in &self.loc_rib {
            let source_is_rr_client = self.source_is_rr_client(best);
            if let Some(adv) = build_advertisement(
                *prefix,
                best,
                peer,
                outbox,
                self.local_asn,
                source_is_rr_client,
                self.cluster_id,
            ) {
                let _ = outbox.tx.send(OutboundUpdate::Announce(adv));
                advertised.insert(*prefix);
            }
        }
        self.adj_rib_out.insert(peer, advertised);
        self.announce_evpn_to(peer);
        if is_rs_client {
            let prefixes: Vec<IpNet> = self.loc_rib.keys().copied().collect();
            for prefix in prefixes {
                self.propagate_rs_view(prefix);
            }
        }
    }

    /// RFC 2918 `ROUTE_REFRESH` handling: re-sends the current Loc-RIB to
    /// `peer`, for prefixes of `family` only. Reuses `build_advertisement`'s
    /// full eligibility logic (split-horizon, negotiated-AF check,
    /// source-peer echo), so a family the peer never negotiated is silently
    /// a no-op. Does not touch `adj_rib_out`: a resend re-announces exactly
    /// the prefix set already recorded as sent, so the withdrawal-diffing
    /// bookkeeping `recompute_and_propagate` relies on is unaffected.
    pub fn resend_all(&mut self, peer: IpAddr, family: AddressFamily) {
        let Some(outbox) = self.peer_outboxes.get(&peer) else {
            return;
        };
        for (prefix, best) in &self.loc_rib {
            if family_of(*prefix) != family {
                continue;
            }
            let source_is_rr_client = self.source_is_rr_client(best);
            if let Some(adv) = build_advertisement(
                *prefix,
                best,
                peer,
                outbox,
                self.local_asn,
                source_is_rr_client,
                self.cluster_id,
            ) {
                let _ = outbox.tx.send(OutboundUpdate::Announce(adv));
            }
        }
    }

    /// The source peer of `route` is a route-reflector client iff it's still
    /// a registered peer with `is_rr_client` set — `false` for a `Local`
    /// route or a source peer that's since disconnected.
    fn source_is_rr_client(&self, route: &RibRoute) -> bool {
        match route.origin {
            RouteOrigin::Peer(addr) => self
                .peer_outboxes
                .get(&addr)
                .is_some_and(|o| o.is_rr_client),
            RouteOrigin::Local => false,
        }
    }

    /// Deregisters a peer's outbox and Adj-RIB-In, then re-decides every
    /// prefix that peer had contributed — the implicit withdraw-everything
    /// path for a session ending, whatever the reason.
    /// Whether `peer` currently has a registered outbound channel — i.e. an
    /// `Established` session that route propagation can actually reach.
    /// `false` while only a losing/collided connection exists for it.
    pub fn has_peer(&self, peer: IpAddr) -> bool {
        self.peer_outboxes.contains_key(&peer)
    }

    /// Every received EVPN route, ordered by peer then route for stable output.
    pub fn evpn_routes(&self) -> Vec<(IpAddr, &EvpnNlri, &EvpnRoute)> {
        let mut out: Vec<_> = self
            .evpn_adj_rib_in
            .iter()
            .flat_map(|(peer, t)| t.iter().map(move |(n, r)| (*peer, n, r)))
            .collect();
        out.sort_by_cached_key(|(peer, n, _)| (*peer, n.to_string()));
        out
    }

    pub fn peer_disconnected(&mut self, peer: IpAddr) {
        self.peer_outboxes.remove(&peer);
        self.adj_rib_out.remove(&peer);
        self.evpn_adj_rib_out.remove(&peer);
        self.rs_sent.retain(|(p, _), _| *p != peer);
        self.rs_next_id.retain(|(p, _), _| *p != peer);
        if let Some(routes) = self.evpn_adj_rib_in.remove(&peer) {
            for nlri in routes.keys() {
                info!(peer = %peer, route_type = nlri.route_type(), route = %nlri, "evpn route withdrawn");
            }
        }
        let removed = self.adj_rib_in.remove(&peer);
        if let Some(routes) = removed {
            for prefix in routes.into_keys() {
                self.recompute_and_propagate(prefix);
            }
        }
    }

    /// Handles one inbound UPDATE from `from`, whose BGP Identifier is
    /// `remote_bgp_id` (used as the RFC 4271 §9.1.2.2 router-id tiebreak).
    /// Withdrawals (legacy `withdrawn_routes` plus any `mp_unreach` batch)
    /// are always processed first, unconditionally; announcements (legacy
    /// `nlri` plus any `mp_reach` batch) are dropped entirely (with a
    /// `warn!`) if the `AS_PATH` already contains our own ASN (loop
    /// prevention), never partially applied. `ORIGIN`/`AS_PATH`/
    /// `LOCAL_PREF`/`MULTI_EXIT_DISC` are shared across the legacy `nlri`
    /// and every `mp_reach` batch in the same UPDATE (RFC 4760: only the
    /// next-hop is per-batch); each `mp_reach` batch's own `next_hop` is
    /// used instead of the legacy attribute's. `import_policy` is `from`'s
    /// peer-group's resolved import policy (`deny-all` by default — see root
    /// `CLAUDE.md`'s "Default-deny rollout impact"): a rejected prefix is
    /// treated like an explicit withdrawal rather than inserted.
    pub fn handle_update(
        &mut self,
        from: IpAddr,
        remote_is_ibgp: bool,
        remote_bgp_id: Ipv4Addr,
        update: &UpdateMessage,
        import_policy: &CompiledPolicy,
    ) {
        // Sized from the message's own known counts so this doesn't rehash
        // its way up on every insert — bounded by the total NLRI/withdrawn
        // entries this one UPDATE could possibly touch.
        let touched_capacity = update.nlri.len()
            + update.mp_reach.iter().map(|m| m.nlri.len()).sum::<usize>()
            + update.withdrawn_routes.len()
            + update
                .mp_unreach
                .iter()
                .map(|u| u.withdrawn.len())
                .sum::<usize>();
        let mut touched: HashSet<IpNet> = HashSet::with_capacity(touched_capacity);

        let withdrawn: Vec<IpNet> = update
            .withdrawn_routes
            .iter()
            .copied()
            .map(IpNet::V4)
            .chain(
                update
                    .mp_unreach
                    .iter()
                    .flat_map(|u| u.withdrawn.iter().copied()),
            )
            .collect();
        for nlri in update.mp_unreach.iter().flat_map(|u| &u.evpn) {
            if self
                .evpn_adj_rib_in
                .get_mut(&from)
                .is_some_and(|t| t.remove(nlri).is_some())
            {
                info!(peer = %from, route_type = nlri.route_type(), route = %nlri, "evpn route withdrawn");
            }
        }
        if !withdrawn.is_empty() {
            let table = self.adj_rib_in.entry(from).or_default();
            for prefix in &withdrawn {
                if table.remove(prefix).is_some() {
                    touched.insert(*prefix);
                }
            }
        }

        if !update.nlri.is_empty() || !update.mp_reach.is_empty() {
            let Some(attrs) = &update.attributes else {
                // parse_update never actually produces this (attributes is
                // Some whenever nlri or mp_reach is non-empty), but stay
                // defensive.
                for prefix in touched {
                    self.recompute_and_propagate(prefix);
                }
                return;
            };
            if attrs.as_path.contains(&self.local_asn) {
                warn!(
                    peer = %from, as_path = ?attrs.as_path,
                    "dropping bgp update: as_path already contains our own asn (loop prevention)"
                );
            } else if attrs.cluster_list.contains(&self.cluster_id) {
                warn!(
                    peer = %from, cluster_list = ?attrs.cluster_list,
                    "dropping bgp update: cluster_list already contains our own cluster-id (rfc 4456 reflection loop prevention)"
                );
            } else if attrs.originator_id == Some(self.local_router_id) {
                warn!(
                    peer = %from, originator_id = ?attrs.originator_id,
                    "dropping bgp update: originator_id is our own router-id (rfc 4456 reflection loop prevention)"
                );
            } else {
                let table = self.adj_rib_in.entry(from).or_default();
                // This UPDATE adds at most this many entries — reserving
                // once lets the per-peer table grow in fewer, larger steps
                // on the way up to a full table, instead of rehashing on
                // every insert-triggered doubling.
                table.reserve(
                    update.nlri.len() + update.mp_reach.iter().map(|m| m.nlri.len()).sum::<usize>(),
                );
                let base_route = RibRoute {
                    origin: RouteOrigin::Peer(from),
                    as_path: attrs.as_path.clone().into(),
                    bgp_origin: attrs.origin,
                    local_pref: attrs.local_pref.unwrap_or(DEFAULT_LOCAL_PREF),
                    med: attrs.med,
                    learned_via_ibgp: remote_is_ibgp,
                    router_id: Some(remote_bgp_id),
                    next_hop: None,
                    received_at: Instant::now(),
                    originator_id: attrs.originator_id,
                    cluster_list: attrs.cluster_list.clone().into(),
                    communities: attrs.communities.clone(),
                    extended_communities: attrs.extended_communities.clone(),
                    large_communities: attrs.large_communities.clone(),
                };
                for prefix in &update.nlri {
                    let candidate = RibRoute {
                        next_hop: Some(IpAddr::V4(attrs.next_hop)),
                        ..base_route.clone()
                    };
                    learn_prefix(
                        table,
                        &mut touched,
                        from,
                        IpNet::V4(*prefix),
                        candidate,
                        import_policy,
                    );
                }
                for mp in &update.mp_reach {
                    for prefix in &mp.nlri {
                        let candidate = RibRoute {
                            next_hop: Some(mp.next_hop),
                            ..base_route.clone()
                        };
                        learn_prefix(table, &mut touched, from, *prefix, candidate, import_policy);
                    }
                    if !mp.evpn.is_empty() {
                        learn_evpn(
                            self.evpn_adj_rib_in.entry(from).or_default(),
                            from,
                            mp,
                            &attrs.extended_communities,
                            attrs.pmsi,
                        );
                    }
                }
            }
        }

        for prefix in touched {
            self.recompute_and_propagate(prefix);
        }
    }

    /// Applies one `nos_proto::RedistributeUpdate` from `nos-ribd`. `gateway`
    /// on the wire type is never read — a locally-redistributed route always
    /// gets next-hop-self, regardless of the destination peer-group's
    /// configured mode (see `RibRoute::next_hop`'s doc comment). Updates the
    /// raw source-of-truth prefix set (`redistribute_raw`) and re-derives
    /// each touched prefix's policy-filtered entry via `refilter_redistribute`.
    pub fn apply_redistribute_update(&mut self, update: RedistributeUpdate) {
        match update {
            RedistributeUpdate::Full(routes) => {
                let new_raw: HashSet<IpNet> = routes.iter().map(|r| r.prefix).collect();
                let touched: Vec<IpNet> = self
                    .redistribute_raw
                    .symmetric_difference(&new_raw)
                    .copied()
                    .collect();
                self.redistribute_raw = new_raw;
                for prefix in touched {
                    self.refilter_redistribute(prefix);
                    self.recompute_and_propagate(prefix);
                }
            }
            RedistributeUpdate::Add(route) => {
                self.redistribute_raw.insert(route.prefix);
                self.refilter_redistribute(route.prefix);
                self.recompute_and_propagate(route.prefix);
            }
            RedistributeUpdate::Remove(prefix) => {
                self.redistribute_raw.remove(&prefix);
                self.refilter_redistribute(prefix);
                self.recompute_and_propagate(prefix);
            }
        }
    }

    /// Recomputes `prefix`'s policy-filtered entry in `redistributed` from
    /// `redistribute_raw` + `redistribute_policy`, inserting or removing it
    /// as needed. Returns whether the entry actually changed — callers use
    /// this to decide whether `recompute_and_propagate` is warranted.
    fn refilter_redistribute(&mut self, prefix: IpNet) -> bool {
        let new = if self.redistribute_raw.contains(&prefix) {
            apply_policy(prefix, redistributed_route(), &self.redistribute_policy)
        } else {
            None
        };
        let changed = match (&new, self.redistributed.get(&prefix)) {
            (Some(n), Some(o)) => n != o,
            (None, None) => false,
            _ => true,
        };
        match new {
            Some(route) => {
                self.redistributed.insert(prefix, route);
            }
            None => {
                self.redistributed.remove(&prefix);
            }
        }
        changed
    }

    /// Sets the compiled redistribute policy and re-filters every currently
    /// raw-redistributed prefix against it — called unconditionally on every
    /// `reconcile()`, mirroring `set_local_identity`'s existing
    /// unconditional-call pattern. Unlike peer import/export (which take
    /// effect via a full peer restart on any policy-name change), there's no
    /// restart mechanism for redistribution, so a policy edit only takes
    /// effect promptly because this method actively re-derives the filtered
    /// set on every call rather than waiting for the next unrelated
    /// `RedistributeUpdate` from `nos-ribd`.
    pub fn set_redistribute_policy(&mut self, policy: Arc<CompiledPolicy>) {
        self.redistribute_policy = policy;
        let prefixes: Vec<IpNet> = self.redistribute_raw.iter().copied().collect();
        for prefix in prefixes {
            if self.refilter_redistribute(prefix) {
                self.recompute_and_propagate(prefix);
            }
        }
    }

    /// The shared core: re-decides `prefix`'s winner from every current
    /// candidate (redistributed + every peer's Adj-RIB-In), and if the
    /// winner actually changed, pushes `Announce`/`Withdraw` to every
    /// registered peer as appropriate.
    fn recompute_and_propagate(&mut self, prefix: IpNet) {
        // Runs independently of the single-elected-best-path logic below —
        // a route-server-client's view covers every source for a prefix,
        // not just the one instance-wide winner, so a change to a
        // non-winning source must still be reflected here even when
        // `best_path`'s pick doesn't change.
        self.propagate_rs_view(prefix);

        // Bounded by one redistributed candidate plus at most one per peer
        // — sizing this avoids the reallocate-on-every-push churn this
        // always-tiny, rebuilt-per-touched-prefix scratch Vec used to pay.
        let mut candidates: Vec<(RibRoute, Option<IpAddr>)> =
            Vec::with_capacity(1 + self.adj_rib_in.len());
        if let Some(route) = self.redistributed.get(&prefix) {
            candidates.push((route.clone(), None));
        }
        for (peer, table) in &self.adj_rib_in {
            if let Some(route) = table.get(&prefix) {
                candidates.push((route.clone(), Some(*peer)));
            }
        }

        let best = best_path(&candidates);
        match best
            .as_ref()
            .and_then(|b| runner_up_next_hop(&candidates, b))
        {
            Some(nh) => {
                self.backups.insert(prefix, nh);
            }
            None => {
                self.backups.remove(&prefix);
            }
        }

        let unchanged = match (&best, self.loc_rib.get(&prefix)) {
            (Some(new), Some(old)) => new == old,
            (None, None) => true,
            _ => false,
        };
        if unchanged {
            return;
        }
        if let Some(route) = &best {
            info!(origin = ?route.origin, as_path = ?route.as_path, communities = ?route.communities, "bgp: loc-rib best path for {prefix} updated");
            self.loc_rib.insert(prefix, route.clone());
        } else {
            info!("bgp: loc-rib route for {prefix} withdrawn");
            self.loc_rib.remove(&prefix);
        }

        let source_is_rr_client = best.as_ref().is_some_and(|r| self.source_is_rr_client(r));
        // Reused across calls (see `peer_scratch`'s doc comment) instead of
        // collecting a fresh Vec on every touched prefix.
        let mut peers = std::mem::take(&mut self.peer_scratch);
        peers.clear();
        peers.extend(self.peer_outboxes.keys().copied());
        for &peer in &peers {
            let outbox = self.peer_outboxes.get(&peer).expect("just listed");
            let advertisement = best.as_ref().and_then(|route| {
                build_advertisement(
                    prefix,
                    route,
                    peer,
                    outbox,
                    self.local_asn,
                    source_is_rr_client,
                    self.cluster_id,
                )
            });

            match advertisement {
                Some(adv) => {
                    let outbox = self.peer_outboxes.get(&peer).expect("just listed");
                    let _ = outbox.tx.send(OutboundUpdate::Announce(adv));
                    self.adj_rib_out.entry(peer).or_default().insert(prefix);
                }
                None => {
                    if let Some(sent) = self.adj_rib_out.get_mut(&peer) {
                        if sent.remove(&prefix) {
                            let outbox = self.peer_outboxes.get(&peer).expect("just listed");
                            let _ = outbox.tx.send(OutboundUpdate::Withdraw(
                                prefix,
                                outbox.mp_bgp_negotiated,
                                None,
                            ));
                        }
                    }
                }
            }
        }
        self.peer_scratch = peers;
    }

    /// RFC 7947 route-server multi-path fan-out: for every `route_server_client`
    /// peer that negotiated RFC 7911 ADD-PATH for `prefix`'s family, sends
    /// every *other* peer's (and any locally-redistributed) contribution for
    /// `prefix` as a separate path, each with its own stable ADD-PATH
    /// identifier — not just the one instance-wide elected best path every
    /// other peer gets. Reuses `build_advertisement` per source unchanged
    /// (a route-server-client is always eBGP, so the iBGP reflection branch
    /// never triggers) and only overrides the resulting `path_id`.
    ///
    /// `ponytail:` no inbound multi-path support — `adj_rib_in` still stores
    /// at most one path per peer per prefix, so a client that itself submits
    /// more than one path for the same prefix only ever contributes its
    /// latest one here. Add per-path `adj_rib_in` keying if a client needs
    /// to submit multiple paths itself.
    fn propagate_rs_view(&mut self, prefix: IpNet) {
        let rs_peers: Vec<IpAddr> = self
            .peer_outboxes
            .iter()
            .filter(|(_, o)| o.is_rs_client && o.add_path_afs.contains(&family_of(prefix)))
            .map(|(addr, _)| *addr)
            .collect();
        if rs_peers.is_empty() {
            return;
        }

        for peer in rs_peers {
            let mut current: HashMap<RouteOrigin, RibRoute> = HashMap::new();
            if let Some(route) = self.redistributed.get(&prefix) {
                current.insert(RouteOrigin::Local, route.clone());
            }
            for (src, table) in &self.adj_rib_in {
                if *src == peer {
                    continue; // never echo the destination's own contribution
                }
                if let Some(route) = table.get(&prefix) {
                    current.insert(RouteOrigin::Peer(*src), route.clone());
                }
            }

            // Owned working copy — avoids holding a live borrow of
            // `self.rs_sent` across the loop below, which also needs to
            // borrow `self.peer_outboxes`/`self.rs_next_id`.
            let mut sent = self.rs_sent.entry((peer, prefix)).or_default().clone();
            let outbox_tx = self.peer_outboxes[&peer].tx.clone();
            let mp_bgp_negotiated = self.peer_outboxes[&peer].mp_bgp_negotiated;

            let stale: Vec<RouteOrigin> = sent
                .keys()
                .filter(|origin| !current.contains_key(origin))
                .copied()
                .collect();
            for origin in stale {
                let (id, _) = sent.remove(&origin).expect("just found");
                let _ = outbox_tx.send(OutboundUpdate::Withdraw(
                    prefix,
                    mp_bgp_negotiated,
                    Some(id),
                ));
            }

            for (origin, route) in current {
                if sent.get(&origin).is_some_and(|(_, last)| *last == route) {
                    continue; // unchanged since last sent to this peer
                }
                let source_is_rr_client = match origin {
                    RouteOrigin::Peer(addr) => self
                        .peer_outboxes
                        .get(&addr)
                        .is_some_and(|o| o.is_rr_client),
                    RouteOrigin::Local => false,
                };
                let outbox = self.peer_outboxes.get(&peer).expect("just listed");
                let Some(adv) = build_advertisement(
                    prefix,
                    &route,
                    peer,
                    outbox,
                    self.local_asn,
                    source_is_rr_client,
                    self.cluster_id,
                ) else {
                    continue;
                };
                let id = sent.get(&origin).map_or_else(
                    || {
                        let counter = self.rs_next_id.entry((peer, prefix)).or_insert(1);
                        let id = *counter;
                        *counter += 1;
                        id
                    },
                    |(id, _)| *id,
                );
                let adv = AdvertisedRoute {
                    path_id: Some(id),
                    ..adv
                };
                let _ = outbox_tx.send(OutboundUpdate::Announce(adv));
                sent.insert(origin, (id, route));
            }

            self.rs_sent.insert((peer, prefix), sent);
        }
    }
}

fn redistributed_route() -> RibRoute {
    RibRoute {
        origin: RouteOrigin::Local,
        as_path: Vec::new().into(),
        bgp_origin: message::Origin::Igp,
        local_pref: DEFAULT_LOCAL_PREF,
        med: None,
        learned_via_ibgp: false,
        router_id: None,
        next_hop: None,
        received_at: Instant::now(),
        originator_id: None,
        cluster_list: Vec::new().into(),
        communities: Vec::new(),
        extended_communities: Vec::new(),
        large_communities: Vec::new(),
    }
}

/// `ORIGIN` rank for the decision process's step 4 — lower wins (`Igp` <
/// `Egp` < `Incomplete`), using the enum's own discriminant values.
fn origin_rank(origin: message::Origin) -> u8 {
    origin as u8
}

/// The "neighboring AS" a route was received from, per RFC 4271 §9.1.2.2's
/// MED comparison rule — the nearest-hop entry in `AS_PATH`. `None` for an
/// empty `AS_PATH` (e.g. a route relayed by an iBGP peer that never went
/// through an eBGP hop), which makes it ineligible for MED comparison
/// against anything.
fn neighboring_as(route: &RibRoute) -> Option<u32> {
    route.as_path.first().copied()
}

/// Step 5: lower `MULTI_EXIT_DISC` wins, but only between routes sharing
/// the same neighboring AS — otherwise this step is skipped entirely
/// (`Equal`). Missing MED is treated as 0, the common convention.
fn compare_med(a: &RibRoute, b: &RibRoute) -> std::cmp::Ordering {
    match (neighboring_as(a), neighboring_as(b)) {
        (Some(x), Some(y)) if x == y => b.med.unwrap_or(0).cmp(&a.med.unwrap_or(0)),
        _ => std::cmp::Ordering::Equal,
    }
}

/// A route's next hop plus its backup (runner-up path's next hop), as pushed
/// to `nos-ribd`.
pub type Hops = (IpAddr, Option<IpAddr>);

/// The next hop of the best candidate other than `best` that has a real
/// next hop different from `best`'s — the backup path. `None` when there is
/// no such candidate (a single path, or every other path shares the winner's
/// next hop, which a backup route couldn't protect against anyway).
fn runner_up_next_hop(
    candidates: &[(RibRoute, Option<IpAddr>)],
    best: &RibRoute,
) -> Option<IpAddr> {
    if candidates.len() < 2 {
        return None;
    }
    let others: Vec<(RibRoute, Option<IpAddr>)> = candidates
        .iter()
        .filter(|(r, _)| r.next_hop.is_some() && r.next_hop != best.next_hop)
        .cloned()
        .collect();
    best_path(&others)?.next_hop
}

/// The full RFC 4271 §9.1.2.2 decision process — see the module doc
/// comment for the ten-step order. `candidates` is `(route, source_peer)`
/// — `source_peer` is `None` for a locally-redistributed route, used only
/// for the final tiebreak (step 10).
fn best_path(candidates: &[(RibRoute, Option<IpAddr>)]) -> Option<RibRoute> {
    candidates
        .iter()
        .max_by(|(a, a_peer), (b, b_peer)| {
            a.local_pref
                .cmp(&b.local_pref)
                .then_with(|| {
                    // Step 2 (not an RFC step): a Local route beats any
                    // Peer(_) route.
                    let a_is_local = matches!(a.origin, RouteOrigin::Local);
                    let b_is_local = matches!(b.origin, RouteOrigin::Local);
                    a_is_local.cmp(&b_is_local)
                })
                .then_with(|| b.as_path.len().cmp(&a.as_path.len())) // step 3
                .then_with(|| origin_rank(b.bgp_origin).cmp(&origin_rank(a.bgp_origin))) // step 4
                .then_with(|| compare_med(a, b)) // step 5
                .then_with(|| b.learned_via_ibgp.cmp(&a.learned_via_ibgp)) // step 6: eBGP beats iBGP
                // Step 7 (IGP metric to next-hop) is a documented no-op:
                // this NOS has no IGP protocol to source a metric from.
                .then_with(|| {
                    // Step 8: oldest route wins, only between two
                    // eBGP-learned candidates (RFC 4271's anti-flap rule).
                    if !a.learned_via_ibgp && !b.learned_via_ibgp {
                        b.received_at.cmp(&a.received_at)
                    } else {
                        std::cmp::Ordering::Equal
                    }
                })
                .then_with(|| {
                    // Step 9: lowest advertising peer's BGP Identifier.
                    match (a.router_id, b.router_id) {
                        (Some(a_id), Some(b_id)) => b_id.cmp(&a_id),
                        _ => std::cmp::Ordering::Equal,
                    }
                })
                .then_with(|| {
                    // Step 10: lowest peer address, the final deterministic
                    // tiebreak — reverse the comparison since `max_by`
                    // favors the greater element, and `None` (a local
                    // route) never reaches this arm (already decided by
                    // step 2).
                    match (a_peer, b_peer) {
                        (Some(a_addr), Some(b_addr)) => b_addr.cmp(a_addr),
                        _ => std::cmp::Ordering::Equal,
                    }
                })
        })
        .map(|(route, _)| route.clone())
}

/// Decides whether `best` should be advertised to `peer` and, if so, rewrites
/// it for that destination. `None` covers every ineligibility case
/// (split-horizon, source-peer echo, family not negotiated by this peer, no
/// local address for next-hop-self). `source_is_rr_client` is whether the
/// peer `best` was learned from (if any) is a route-reflector client;
/// `cluster_id` is this instance's own effective RFC 4456 cluster-id, used
/// only when actually reflecting.
fn build_advertisement(
    prefix: IpNet,
    best: &RibRoute,
    peer: IpAddr,
    outbox: &PeerOutbox,
    local_asn: u32,
    source_is_rr_client: bool,
    cluster_id: Ipv4Addr,
) -> Option<AdvertisedRoute> {
    if !outbox.negotiated_afs.contains(&family_of(prefix)) {
        return None;
    }
    if best.origin == RouteOrigin::Peer(peer) {
        // Never echo a route back to the peer it came from.
        return None;
    }
    // RFC 4456 §6: a route learned via iBGP is reflected to another iBGP
    // peer only when the source or the destination is a configured
    // route-reflector client — otherwise the standard iBGP split-horizon
    // rule (no reflection, full mesh assumed) still applies unchanged.
    let ibgp_to_ibgp =
        matches!(best.origin, RouteOrigin::Peer(_)) && best.learned_via_ibgp && outbox.is_ibgp;
    let reflecting = ibgp_to_ibgp && (source_is_rr_client || outbox.is_rr_client);
    if ibgp_to_ibgp && !reflecting {
        return None;
    }

    // This destination peer-group's resolved export policy (`deny-all` by
    // default — see root `CLAUDE.md`'s "Default-deny rollout impact").
    // `best` is shadowed with a possibly policy-adjusted owned copy so every
    // rewrite below (`AS_PATH`, `LOCAL_PREF`, `MED`, reflection) sees the
    // policy's `local_pref`/`med`, not the pre-policy values.
    let best = match nos_rpl::vm::run(&outbox.export_policy, &to_policy_input(prefix, best)) {
        nos_rpl::Verdict::Reject => return None,
        nos_rpl::Verdict::Accept {
            local_pref,
            med,
            communities,
            extended_communities,
            large_communities,
        } => {
            let mut adjusted = best.clone();
            adjusted.local_pref = local_pref;
            adjusted.med = med;
            adjusted.communities = communities;
            adjusted.extended_communities = extended_communities;
            adjusted.large_communities = large_communities;
            adjusted
        }
    };
    let best = &best;

    let mode = outbox.next_hop_mode.unwrap_or(if outbox.is_ibgp {
        NextHopMode::Unchanged
    } else {
        NextHopMode::SelfAddress
    });
    let next_hop = match mode {
        NextHopMode::SelfAddress => outbox.local_addr?,
        NextHopMode::Unchanged => best.next_hop.or(outbox.local_addr)?,
    };

    // `as_path` is never mutated by RPL (read-only policy input), so it's
    // still shared with whatever's stored in loc_rib/adj_rib_in at this
    // point — `Arc::clone` is a refcount bump, not a deep copy. The one
    // real content copy this function can't avoid is the eBGP prepend
    // case, where the result genuinely differs per destination peer;
    // `Arc::make_mut` does that copy directly into an owned buffer instead
    // of cloning twice (once wastefully inside `adjusted = best.clone()`
    // above, once again here) like the pre-Arc version of this code did.
    let mut as_path = Arc::clone(&best.as_path);
    // RFC 7947 route-server clients get a fully transparent AS_PATH: no
    // local-ASN prepend, even though they're always eBGP (enforced at
    // config-validation time — see `bgp_instance::valid_route_reflection_and_server`).
    if !outbox.is_ibgp && !outbox.is_rs_client {
        Arc::make_mut(&mut as_path).insert(0, local_asn);
    }
    let as_path: Vec<u32> = Arc::try_unwrap(as_path).unwrap_or_else(|arc| (*arc).clone());
    let local_pref = outbox.is_ibgp.then_some(best.local_pref);
    // MED is meant for use between adjacent ASes, so it's never forwarded
    // on to a further eBGP peer, only preserved toward iBGP peers.
    let med = if outbox.is_ibgp { best.med } else { None };

    let (originator_id, cluster_list) = if reflecting {
        let mut clusters = (*best.cluster_list).clone();
        clusters.insert(0, cluster_id);
        (best.originator_id.or(best.router_id), clusters)
    } else {
        (None, Vec::new())
    };

    Some(AdvertisedRoute {
        prefix,
        as_path,
        next_hop,
        local_pref,
        med,
        origin: best.bgp_origin,
        use_mp: outbox.mp_bgp_negotiated,
        originator_id,
        cluster_list,
        communities: best.communities.clone(),
        extended_communities: best.extended_communities.clone(),
        large_communities: best.large_communities.clone(),
        path_id: None,
    })
}

#[cfg(test)]
// Community/ASN values are conventionally written and read in decimal
// (`65000:100`) — hex/binary notation would make these test fixtures harder
// to read, not easier.
#[allow(clippy::decimal_bitwise_operands)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn prefix(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn new_rib(local_asn: u32) -> BgpRib {
        let mut rib = BgpRib::new();
        rib.set_local_identity(local_asn, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED);
        rib
    }

    fn new_rib_with_identity(local_asn: u32, router_id: Ipv4Addr, cluster_id: Ipv4Addr) -> BgpRib {
        let mut rib = BgpRib::new();
        rib.set_local_identity(local_asn, router_id, cluster_id);
        rib
    }

    fn all_afs() -> HashSet<AddressFamily> {
        [AddressFamily::Ipv4Unicast, AddressFamily::Ipv6Unicast]
            .into_iter()
            .collect()
    }

    fn register_peer(
        rib: &mut BgpRib,
        peer: IpAddr,
        is_ibgp: bool,
        local_addr: IpAddr,
    ) -> mpsc::UnboundedReceiver<OutboundUpdate> {
        register_peer_with_mode(rib, peer, is_ibgp, local_addr, None)
    }

    fn register_peer_with_mode(
        rib: &mut BgpRib,
        peer: IpAddr,
        is_ibgp: bool,
        local_addr: IpAddr,
        next_hop_mode: Option<NextHopMode>,
    ) -> mpsc::UnboundedReceiver<OutboundUpdate> {
        let (tx, rx) = mpsc::unbounded_channel();
        rib.peer_established(
            peer,
            is_ibgp,
            Some(local_addr),
            all_afs(),
            false,
            next_hop_mode,
            false,
            false,
            HashSet::new(),
            accept_all_policy(),
            tx,
        );
        rx
    }

    /// Registers a peer that negotiated MP-BGP (so `Ipv4Unicast` too gets
    /// encoded via `MP_REACH_NLRI`/`MP_UNREACH_NLRI`, per
    /// `AdvertisedRoute::use_mp`), with a given negotiated AF set.
    fn register_mp_peer(
        rib: &mut BgpRib,
        peer: IpAddr,
        is_ibgp: bool,
        local_addr: IpAddr,
        negotiated_afs: HashSet<AddressFamily>,
    ) -> mpsc::UnboundedReceiver<OutboundUpdate> {
        let (tx, rx) = mpsc::unbounded_channel();
        rib.peer_established(
            peer,
            is_ibgp,
            Some(local_addr),
            negotiated_afs,
            true,
            None,
            false,
            false,
            HashSet::new(),
            accept_all_policy(),
            tx,
        );
        rx
    }

    /// Registers a peer with full control over route-reflector-client/
    /// route-server-client/ADD-PATH — for RFC 4456/RFC 7911 tests.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::similar_names)]
    fn register_peer_full(
        rib: &mut BgpRib,
        peer: IpAddr,
        is_ibgp: bool,
        local_addr: IpAddr,
        is_rr_client: bool,
        is_rs_client: bool,
        add_path_afs: HashSet<AddressFamily>,
    ) -> mpsc::UnboundedReceiver<OutboundUpdate> {
        let (tx, rx) = mpsc::unbounded_channel();
        rib.peer_established(
            peer,
            is_ibgp,
            Some(local_addr),
            all_afs(),
            false,
            None,
            is_rr_client,
            is_rs_client,
            add_path_afs,
            accept_all_policy(),
            tx,
        );
        rx
    }

    fn accept_all_policy() -> Arc<CompiledPolicy> {
        Arc::new(nos_rpl::ACCEPT_ALL.clone())
    }

    fn deny_all_policy() -> Arc<CompiledPolicy> {
        Arc::new(nos_rpl::DENY_ALL.clone())
    }

    fn full_update(routes: Vec<(&str, &str)>) -> RedistributeUpdate {
        RedistributeUpdate::Full(
            routes
                .into_iter()
                .map(|(p, gw)| nos_proto::RedistributedRoute {
                    prefix: prefix(p),
                    gateway: addr(gw),
                })
                .collect(),
        )
    }

    fn recv_all(rx: &mut mpsc::UnboundedReceiver<OutboundUpdate>) -> Vec<OutboundUpdate> {
        let mut out = Vec::new();
        while let Ok(update) = rx.try_recv() {
            out.push(update);
        }
        out
    }

    fn ebgp_update(nlri: Vec<&str>, as_path: Vec<u32>, next_hop: &str) -> UpdateMessage {
        UpdateMessage {
            withdrawn_routes: vec![],
            withdrawn_path_ids: vec![],
            nlri: nlri.into_iter().map(|s| s.parse().unwrap()).collect(),
            nlri_path_ids: vec![],
            attributes: Some(message::PathAttributes {
                origin: message::Origin::Igp,
                as_path,
                next_hop: v4(next_hop),
                local_pref: None,
                med: None,
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                pmsi: None,
            }),
            mp_reach: vec![],
            mp_unreach: vec![],
        }
    }

    fn empty_update() -> UpdateMessage {
        UpdateMessage {
            withdrawn_routes: vec![],
            withdrawn_path_ids: vec![],
            nlri: vec![],
            nlri_path_ids: vec![],
            attributes: None,
            mp_reach: vec![],
            mp_unreach: vec![],
        }
    }

    fn evpn_nlri(mac_last: u8) -> EvpnNlri {
        EvpnNlri::MacIp {
            rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
            esi: [0; 10],
            tag: 0,
            mac: [0xaa, 0, 0, 0, 0, mac_last],
            ip: None,
            labels: vec![10_000],
        }
    }

    fn evpn_reach(nlris: Vec<EvpnNlri>, as_path: Vec<u32>) -> UpdateMessage {
        let mut u = ebgp_update(vec![], as_path, "0.0.0.0");
        u.attributes.as_mut().unwrap().extended_communities = vec![0x0002_fde8_0000_2710];
        u.mp_reach = vec![message::MpReachNlri {
            afi: message::AFI_L2VPN,
            safi: message::SAFI_EVPN,
            next_hop: addr("192.0.2.1"),
            nlri: vec![],
            nlri_path_ids: vec![],
            evpn: nlris,
        }];
        u
    }

    fn mac_route(mac: u8) -> nos_proto::EvpnRoute {
        nos_proto::EvpnRoute {
            key: nos_proto::EvpnKey::Mac {
                rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
                mac: [0, 0, 0, 0, 0, mac],
            },
            vni: 10100,
            next_hop: addr("192.0.2.9"),
            ext_communities: vec![0x0002_fde8_0000_2774],
            esi: [0; 10],
        }
    }

    fn evpn_afs() -> HashSet<AddressFamily> {
        HashSet::from([AddressFamily::Ipv4Unicast, AddressFamily::L2vpnEvpn])
    }

    #[test]
    fn local_evpn_routes_are_announced_withdrawn_and_replayed_to_new_peers() {
        let mut rib = new_rib(65000);
        let mut evpn_rx = register_mp_peer(
            &mut rib,
            addr("10.0.0.1"),
            false,
            addr("10.0.0.254"),
            evpn_afs(),
        );
        let mut plain_rx = register_mp_peer(
            &mut rib,
            addr("10.0.0.2"),
            false,
            addr("10.0.0.253"),
            HashSet::from([AddressFamily::Ipv4Unicast]),
        );

        rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(mac_route(1)));
        let updates = recv_all(&mut evpn_rx);
        assert_eq!(updates.len(), 1);
        let OutboundUpdate::AnnounceEvpn(adv) = &updates[0] else {
            panic!("expected an EVPN announcement, got {updates:?}");
        };
        // eBGP: our ASN prepended; the VTEP next-hop is untouched.
        assert_eq!(adv.as_path, vec![65000]);
        assert_eq!(adv.next_hop, addr("192.0.2.9"));
        assert_eq!(adv.extended_communities, vec![0x0002_fde8_0000_2774]);
        assert!(recv_all(&mut plain_rx).is_empty(), "EVPN not negotiated");

        // An identical re-push is not re-announced.
        rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(mac_route(1)));
        assert!(recv_all(&mut evpn_rx).is_empty());

        // A peer that comes up later gets the current set.
        let mut late_rx = register_mp_peer(
            &mut rib,
            addr("10.0.0.3"),
            false,
            addr("10.0.0.252"),
            evpn_afs(),
        );
        assert_eq!(recv_all(&mut late_rx).len(), 1);

        // Full replaces only that domain's routes: mac 1 is withdrawn, 2 announced.
        rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Full(vec![mac_route(2)]));
        let updates = recv_all(&mut evpn_rx);
        assert_eq!(updates.len(), 2);
        assert!(updates
            .iter()
            .any(|u| matches!(u, OutboundUpdate::WithdrawEvpn(_))));

        rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Remove(mac_route(2).key));
        assert!(matches!(
            recv_all(&mut evpn_rx).as_slice(),
            [OutboundUpdate::WithdrawEvpn(_)]
        ));
    }

    #[test]
    fn type2_carries_its_esi_and_moving_onto_a_segment_withdraws_the_old_nlri() {
        let mut rib = new_rib(65000);
        let mut rx = register_mp_peer(
            &mut rib,
            addr("10.0.0.1"),
            false,
            addr("10.0.0.254"),
            evpn_afs(),
        );
        let esi = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(mac_route(1)));
        let _ = recv_all(&mut rx);

        // Same key, now on a segment: the old (ESI 0) NLRI goes, the new one comes.
        let mut on_es = mac_route(1);
        on_es.esi = esi;
        rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(on_es));
        let updates = recv_all(&mut rx);
        assert_eq!(updates.len(), 2, "{updates:?}");
        assert!(matches!(
            &updates[0],
            OutboundUpdate::WithdrawEvpn(EvpnNlri::MacIp { esi, .. }) if *esi == [0; 10]
        ));
        assert!(matches!(
            &updates[1],
            OutboundUpdate::AnnounceEvpn(a) if matches!(a.nlri, EvpnNlri::MacIp { esi: e, .. } if e == esi)
        ));
    }

    #[test]
    fn local_ethernet_segment_route_is_originated_and_received_ones_reach_fdbd() {
        let mut rib = new_rib(65000);
        let mut rx = register_mp_peer(
            &mut rib,
            addr("10.0.0.1"),
            false,
            addr("10.0.0.254"),
            evpn_afs(),
        );
        let esi = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let rd = [0, 0, 0xfd, 0xe8, 0, 0, 0, 1];
        let route = nos_proto::EvpnRoute {
            key: nos_proto::EvpnKey::EthernetSegment {
                rd,
                esi,
                origin: addr("192.0.2.9"),
            },
            vni: 0,
            next_hop: addr("192.0.2.9"),
            ext_communities: vec![nos_proto::evpn_id::es_import_rt(&esi)],
            esi,
        };
        rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(route));
        let updates = recv_all(&mut rx);
        assert!(matches!(
            updates.as_slice(),
            [OutboundUpdate::AnnounceEvpn(a)] if matches!(a.nlri, EvpnNlri::EthernetSegment { .. })
        ));

        // A received Type-4 is handed to fdbd (previously dropped).
        let peer = addr("10.0.0.2");
        let _peer_rx = register_peer(&mut rib, peer, false, addr("10.0.0.253"));
        rib.handle_update(
            peer,
            false,
            v4("192.0.2.2"),
            &evpn_reach(
                vec![EvpnNlri::EthernetSegment {
                    rd,
                    esi,
                    origin: addr("192.0.2.2"),
                }],
                vec![65001],
            ),
            &deny_all_policy(),
        );
        let snap = rib.evpn_push_snapshot();
        assert!(snap.keys().any(|k| matches!(
            k,
            nos_proto::EvpnKey::EthernetSegment { origin, .. } if *origin == addr("192.0.2.2")
        )));
    }

    #[test]
    fn ethernet_ad_routes_are_originated_per_es_and_per_evi_and_received_ones_keep_their_origin() {
        use nos_proto::fdb::AD_TAG_ES;
        let mut rib = new_rib(65000);
        let mut rx = register_mp_peer(
            &mut rib,
            addr("10.0.0.1"),
            false,
            addr("10.0.0.254"),
            evpn_afs(),
        );
        let esi = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let rd = [0, 0, 0xfd, 0xe8, 0, 0, 0, 1];
        let ad = |tag: u32, vni: u32| nos_proto::EvpnRoute {
            key: nos_proto::EvpnKey::EthernetAd {
                rd,
                esi,
                tag,
                origin: addr("192.0.2.9"),
            },
            vni,
            next_hop: addr("192.0.2.9"),
            ext_communities: vec![nos_proto::evpn_id::esi_label_ext(false)],
            esi,
        };
        rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(ad(AD_TAG_ES, 0)));
        rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(ad(0, 10_100)));
        let updates = recv_all(&mut rx);
        // Per-ES: MAX-ET and no label; per-EVI: tag 0, the VNI in the label.
        assert!(matches!(
            &updates[0],
            OutboundUpdate::AnnounceEvpn(a)
                if matches!(a.nlri, EvpnNlri::EthernetAd { tag: AD_TAG_ES, label: 0, .. })
        ));
        assert!(matches!(
            &updates[1],
            OutboundUpdate::AnnounceEvpn(a)
                if matches!(a.nlri, EvpnNlri::EthernetAd { tag: 0, label: 10_100, .. })
        ));

        // Two PEs sending the same NLRI stay two entries, told apart by origin.
        for (peer, nh) in [
            (addr("10.0.0.2"), "192.0.2.2"),
            (addr("10.0.0.3"), "192.0.2.3"),
        ] {
            let _peer_rx = register_peer(&mut rib, peer, false, addr("10.0.0.253"));
            let mut u = evpn_reach(
                vec![EvpnNlri::EthernetAd {
                    rd,
                    esi,
                    tag: AD_TAG_ES,
                    label: 0,
                }],
                vec![65001],
            );
            u.mp_reach[0].next_hop = addr(nh);
            rib.handle_update(peer, false, v4(nh), &u, &deny_all_policy());
        }
        let snap = rib.evpn_push_snapshot();
        let origins: std::collections::BTreeSet<_> = snap
            .keys()
            .filter_map(|k| match k {
                nos_proto::EvpnKey::EthernetAd { origin, tag, .. } if *tag == AD_TAG_ES => {
                    Some(*origin)
                }
                _ => None,
            })
            .collect();
        assert_eq!(origins.len(), 2, "{snap:?}");
    }

    #[test]
    fn received_type2_and_type3_become_wire_routes_for_fdbd() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
        rib.handle_update(
            peer,
            false,
            v4("192.0.2.1"),
            &evpn_reach(vec![evpn_nlri(1)], vec![65001]),
            &deny_all_policy(),
        );
        let snap = rib.evpn_push_snapshot();
        assert_eq!(snap.len(), 1);
        let r = snap.values().next().unwrap();
        assert_eq!(r.next_hop, addr("192.0.2.1"));
        assert_eq!(r.ext_communities, vec![0x0002_fde8_0000_2710]);
    }

    #[test]
    fn evpn_routes_are_stored_per_peer_withdrawn_and_cleared_on_disconnect() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let observer = addr("10.0.0.2");
        let _peer_rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
        let mut observer_rx = register_peer(&mut rib, observer, false, addr("10.0.0.253"));

        rib.handle_update(
            peer,
            false,
            v4("192.0.2.1"),
            &evpn_reach(vec![evpn_nlri(1), evpn_nlri(2)], vec![65001]),
            &deny_all_policy(), // import policy is prefix-shaped: not applied to EVPN
        );
        let routes = rib.evpn_routes();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].0, peer);
        assert_eq!(routes[0].2.next_hop, addr("192.0.2.1"));
        assert_eq!(
            routes[0].2.extended_communities,
            vec![0x0002_fde8_0000_2710]
        );
        // Nothing is re-advertised: no consumer exists yet.
        assert!(recv_all(&mut observer_rx).is_empty());

        // Re-announcing an existing route replaces it rather than duplicating.
        rib.handle_update(
            peer,
            false,
            v4("192.0.2.1"),
            &evpn_reach(vec![evpn_nlri(1)], vec![65001]),
            &deny_all_policy(),
        );
        assert_eq!(rib.evpn_routes().len(), 2);

        let mut withdraw = empty_update();
        withdraw.mp_unreach = vec![message::MpUnreachNlri {
            afi: message::AFI_L2VPN,
            safi: message::SAFI_EVPN,
            withdrawn: vec![],
            withdrawn_path_ids: vec![],
            evpn: vec![evpn_nlri(1)],
        }];
        rib.handle_update(peer, false, v4("192.0.2.1"), &withdraw, &deny_all_policy());
        let routes = rib.evpn_routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].1, &evpn_nlri(2));

        rib.peer_disconnected(peer);
        assert!(rib.evpn_routes().is_empty());
    }

    #[test]
    fn evpn_update_with_own_asn_in_as_path_is_dropped() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
        rib.handle_update(
            peer,
            false,
            v4("192.0.2.1"),
            &evpn_reach(vec![evpn_nlri(1)], vec![65001, 65000]),
            &deny_all_policy(),
        );
        assert!(rib.evpn_routes().is_empty());
    }

    #[test]
    fn import_policy_reject_prevents_route_from_being_learned() {
        let mut rib = new_rib(65000);
        let source = addr("10.0.0.1");
        let observer = addr("10.0.0.2");
        let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
        let mut observer_rx = register_peer(&mut rib, observer, false, addr("10.0.0.253"));

        rib.handle_update(
            source,
            false,
            v4("192.0.2.1"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
            &deny_all_policy(),
        );

        assert!(recv_all(&mut observer_rx).is_empty());
    }

    #[test]
    fn import_policy_can_set_local_pref() {
        let mut rib = new_rib(65000);
        let source = addr("10.0.0.1");
        let observer = addr("10.0.0.2");
        // Source is eBGP-learned, observer is iBGP — LOCAL_PREF is only ever
        // forwarded toward an iBGP peer, and standard split-horizon only
        // suppresses an iBGP-learned route being reflected to another iBGP
        // peer, so this combination exercises the mutation without either
        // rule getting in the way.
        let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
        let mut observer_rx = register_peer(&mut rib, observer, true, addr("10.0.0.253"));

        let policy = nos_rpl::compile(
            "set this.bgp.local_pref = 500\naccept\n",
            &nos_rpl::Symbols::EMPTY,
        )
        .unwrap();
        rib.handle_update(
            source,
            false,
            v4("192.0.2.1"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![], "10.0.0.1"),
            &policy,
        );

        let updates = recv_all(&mut observer_rx);
        let adv = updates
            .into_iter()
            .find_map(|u| match u {
                OutboundUpdate::Announce(a) if a.prefix == prefix("1.2.3.0/24") => Some(a),
                _ => None,
            })
            .expect("expected an announcement for 1.2.3.0/24");
        assert_eq!(adv.local_pref, Some(500));
    }

    #[test]
    fn import_policy_can_add_community() {
        let mut rib = new_rib(65000);
        let source = addr("10.0.0.1");
        let observer = addr("10.0.0.2");
        let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
        let mut observer_rx = register_peer(&mut rib, observer, false, addr("10.0.0.253"));

        let policy = nos_rpl::compile(
            "this.bgp.communities.add(65000:100)\naccept\n",
            &nos_rpl::Symbols::EMPTY,
        )
        .unwrap();
        rib.handle_update(
            source,
            false,
            v4("192.0.2.1"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![], "10.0.0.1"),
            &policy,
        );

        let updates = recv_all(&mut observer_rx);
        let adv = updates
            .into_iter()
            .find_map(|u| match u {
                OutboundUpdate::Announce(a) if a.prefix == prefix("1.2.3.0/24") => Some(a),
                _ => None,
            })
            .expect("expected an announcement for 1.2.3.0/24");
        assert_eq!(adv.communities, vec![(65000 << 16) | 100]);
    }

    #[test]
    fn export_policy_can_remove_community_for_one_peer() {
        let mut rib = new_rib(65000);
        let source = addr("10.0.0.1");
        let allowed = addr("10.0.0.2");
        let stripped = addr("10.0.0.3");
        let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
        let mut allowed_rx = register_peer(&mut rib, allowed, false, addr("10.0.0.253"));

        let (tx, mut stripped_rx) = mpsc::unbounded_channel();
        rib.peer_established(
            stripped,
            false,
            Some(addr("10.0.0.252")),
            all_afs(),
            false,
            None,
            false,
            false,
            HashSet::new(),
            Arc::new(
                nos_rpl::compile(
                    "this.bgp.communities.clear()\naccept\n",
                    &nos_rpl::Symbols::EMPTY,
                )
                .unwrap(),
            ),
            tx,
        );

        let import_policy = nos_rpl::compile(
            "this.bgp.communities.add(65000:100)\naccept\n",
            &nos_rpl::Symbols::EMPTY,
        )
        .unwrap();
        rib.handle_update(
            source,
            false,
            v4("192.0.2.1"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
            &import_policy,
        );

        let find_adv = |rx: &mut mpsc::UnboundedReceiver<OutboundUpdate>| {
            recv_all(rx)
                .into_iter()
                .find_map(|u| match u {
                    OutboundUpdate::Announce(a) if a.prefix == prefix("1.2.3.0/24") => Some(a),
                    _ => None,
                })
                .expect("expected an announcement for 1.2.3.0/24")
        };
        assert_eq!(
            find_adv(&mut allowed_rx).communities,
            vec![(65000 << 16) | 100]
        );
        assert!(find_adv(&mut stripped_rx).communities.is_empty());
    }

    /// The `communities` phase of `tools/verify-bgp.sh`, in miniature: a
    /// *locally redistributed* route (no wire attributes of its own) tagged
    /// by the destination peer-group's own *export* policy. Distinct from
    /// `import_policy_can_add_community` (peer-learned, import side) and
    /// `export_policy_can_remove_community_for_one_peer` (peer-learned,
    /// export side, removal).
    #[test]
    fn export_policy_can_add_community_to_a_redistributed_route() {
        let mut rib = new_rib(65001);
        let peer = addr("10.0.0.1");
        let (tx, mut rx) = mpsc::unbounded_channel();
        rib.peer_established(
            peer,
            false,
            Some(addr("10.0.0.254")),
            all_afs(),
            false,
            None,
            false,
            false,
            HashSet::new(),
            Arc::new(
                nos_rpl::compile(
                    "this.bgp.communities.add(65001:100)\naccept\n",
                    &nos_rpl::Symbols::EMPTY,
                )
                .unwrap(),
            ),
            tx,
        );

        rib.apply_redistribute_update(full_update(vec![("198.51.100.0/24", "10.9.9.9")]));

        let adv = recv_all(&mut rx)
            .into_iter()
            .find_map(|u| match u {
                OutboundUpdate::Announce(a) if a.prefix == prefix("198.51.100.0/24") => Some(a),
                _ => None,
            })
            .expect("expected an announcement for 198.51.100.0/24");
        assert_eq!(adv.communities, vec![(65001 << 16) | 100]);
    }

    #[test]
    fn export_policy_reject_suppresses_advertisement_to_one_peer() {
        let mut rib = new_rib(65000);
        let source = addr("10.0.0.1");
        let allowed = addr("10.0.0.2");
        let blocked = addr("10.0.0.3");
        let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
        let mut allowed_rx = register_peer(&mut rib, allowed, false, addr("10.0.0.253"));

        let (tx, mut blocked_rx) = mpsc::unbounded_channel();
        rib.peer_established(
            blocked,
            false,
            Some(addr("10.0.0.252")),
            all_afs(),
            false,
            None,
            false,
            false,
            HashSet::new(),
            deny_all_policy(),
            tx,
        );

        rib.handle_update(
            source,
            false,
            v4("192.0.2.1"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
            &accept_all_policy(),
        );

        assert!(!recv_all(&mut allowed_rx).is_empty());
        assert!(recv_all(&mut blocked_rx).is_empty());
    }

    #[test]
    fn redistributed_route_is_announced_to_ebgp_peer_with_prepend_and_no_local_pref() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let mut rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));

        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

        let updates = recv_all(&mut rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("192.168.1.0/24"),
                as_path: vec![65000],
                next_hop: addr("10.0.0.254"),
                local_pref: None,
                med: None,
                origin: message::Origin::Igp,
                use_mp: false,
            })]
        );
    }

    #[test]
    fn redistributed_route_is_announced_to_ibgp_peer_with_local_pref_and_no_prepend() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.2");
        let mut rx = register_peer(&mut rib, peer, true, addr("10.0.0.253"));

        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

        let updates = recv_all(&mut rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("192.168.1.0/24"),
                as_path: vec![],
                next_hop: addr("10.0.0.253"),
                local_pref: Some(100),
                med: None,
                origin: message::Origin::Igp,
                use_mp: false,
            })]
        );
    }

    #[test]
    fn redistributed_route_rejected_by_redistribute_policy_is_not_announced() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let mut rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
        rib.set_redistribute_policy(deny_all_policy());

        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

        assert_eq!(recv_all(&mut rx), vec![]);
    }

    /// Proves a redistribute-policy change takes effect promptly — the
    /// current redistributed set is re-filtered when the policy itself
    /// changes, not just on the next `RedistributeUpdate` from `nos-ribd`.
    #[test]
    fn redistribute_policy_change_retroactively_filters_existing_routes() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let mut rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));

        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));
        let announced = recv_all(&mut rx);
        assert!(matches!(
            announced.as_slice(),
            [OutboundUpdate::Announce(a)] if a.prefix == prefix("192.168.1.0/24")
        ));

        rib.set_redistribute_policy(deny_all_policy());

        let updates = recv_all(&mut rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Withdraw(
                prefix("192.168.1.0/24"),
                false,
                None
            )]
        );
    }

    #[test]
    fn resend_all_resends_loc_rib_filtered_to_one_family() {
        let mut rib = new_rib(65000);
        let v4_peer = addr("10.0.0.1");
        let v6_peer = addr("10.0.0.2");
        let mut v4_rx = register_mp_peer(
            &mut rib,
            v4_peer,
            false,
            addr("10.0.0.254"),
            [AddressFamily::Ipv4Unicast].into_iter().collect(),
        );
        let mut v6_rx = register_mp_peer(
            &mut rib,
            v6_peer,
            false,
            addr("10.0.0.254"),
            [AddressFamily::Ipv6Unicast].into_iter().collect(),
        );

        rib.apply_redistribute_update(full_update(vec![
            ("192.168.1.0/24", "10.9.9.9"),
            ("2001:db8::/32", "2001:db8::1"),
        ]));
        // Drain the initial full-advertisement sends from registration/redistribution.
        recv_all(&mut v4_rx);
        recv_all(&mut v6_rx);

        rib.resend_all(v4_peer, AddressFamily::Ipv4Unicast);
        rib.resend_all(v6_peer, AddressFamily::Ipv6Unicast);

        let v4_updates = recv_all(&mut v4_rx);
        assert_eq!(v4_updates.len(), 1);
        assert!(matches!(
            &v4_updates[0],
            OutboundUpdate::Announce(adv) if adv.prefix == prefix("192.168.1.0/24")
        ));

        let v6_updates = recv_all(&mut v6_rx);
        assert_eq!(v6_updates.len(), 1);
        assert!(matches!(
            &v6_updates[0],
            OutboundUpdate::Announce(adv) if adv.prefix == prefix("2001:db8::/32")
        ));

        // Requesting the family a peer didn't negotiate is a silent no-op.
        rib.resend_all(v4_peer, AddressFamily::Ipv6Unicast);
        assert!(recv_all(&mut v4_rx).is_empty());
    }

    #[test]
    fn peer_learned_route_beats_nothing_and_is_never_echoed_back_to_source() {
        let mut rib = new_rib(65000);
        let source = addr("10.0.0.1");
        let mut source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));

        rib.handle_update(
            source,
            false,
            v4("192.0.2.1"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
            &nos_rpl::ACCEPT_ALL,
        );

        // Never echoed back to the source peer.
        assert!(recv_all(&mut source_rx).is_empty());
    }

    #[test]
    fn peer_learned_route_is_propagated_to_a_third_peer() {
        let mut rib = new_rib(65000);
        let source = addr("10.0.0.1");
        let other = addr("10.0.0.2");
        let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
        let mut other_rx = register_peer(&mut rib, other, false, addr("10.0.0.253"));

        rib.handle_update(
            source,
            false,
            v4("192.0.2.1"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
            &nos_rpl::ACCEPT_ALL,
        );

        let updates = recv_all(&mut other_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("1.2.3.0/24"),
                as_path: vec![65000, 65001],
                next_hop: addr("10.0.0.253"),
                local_pref: None,
                med: None,
                origin: message::Origin::Igp,
                use_mp: false,
            })]
        );
    }

    #[test]
    fn ibgp_split_horizon_never_reflects_between_two_ibgp_peers() {
        let mut rib = new_rib(65000);
        let source = addr("10.0.0.1");
        let other = addr("10.0.0.2");
        let _source_rx = register_peer(&mut rib, source, true, addr("10.0.0.254"));
        let mut other_rx = register_peer(&mut rib, other, true, addr("10.0.0.253"));

        rib.handle_update(
            source,
            true,
            v4("192.0.2.1"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![], "10.0.0.1"),
            &nos_rpl::ACCEPT_ALL,
        );

        assert!(recv_all(&mut other_rx).is_empty());
    }

    #[test]
    fn ebgp_learned_route_is_still_propagated_to_an_ibgp_peer_with_next_hop_unchanged() {
        let mut rib = new_rib(65000);
        let source = addr("10.0.0.1"); // eBGP source
        let ibgp_peer = addr("10.0.0.2");
        let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
        let mut ibgp_rx = register_peer(&mut rib, ibgp_peer, true, addr("10.0.0.253"));

        rib.handle_update(
            source,
            false,
            v4("192.0.2.1"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
            &nos_rpl::ACCEPT_ALL,
        );

        let updates = recv_all(&mut ibgp_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("1.2.3.0/24"),
                as_path: vec![65001],
                // iBGP defaults to Unchanged: the eBGP source's own
                // next-hop (10.0.0.1) is preserved, not rewritten to the
                // ibgp_peer's own local address.
                next_hop: addr("10.0.0.1"),
                local_pref: Some(100),
                med: None,
                origin: message::Origin::Igp,
                use_mp: false,
            })]
        );
    }

    #[test]
    fn ibgp_peer_with_next_hop_self_override_rewrites_to_local_address() {
        let mut rib = new_rib(65000);
        let source = addr("10.0.0.1"); // eBGP source
        let ibgp_peer = addr("10.0.0.2");
        let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
        let mut ibgp_rx = register_peer_with_mode(
            &mut rib,
            ibgp_peer,
            true,
            addr("10.0.0.253"),
            Some(NextHopMode::SelfAddress),
        );

        rib.handle_update(
            source,
            false,
            v4("192.0.2.1"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
            &nos_rpl::ACCEPT_ALL,
        );

        let updates = recv_all(&mut ibgp_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("1.2.3.0/24"),
                as_path: vec![65001],
                next_hop: addr("10.0.0.253"),
                local_pref: Some(100),
                med: None,
                origin: message::Origin::Igp,
                use_mp: false,
            })]
        );
    }

    #[test]
    fn ebgp_peer_with_next_hop_unchanged_override_preserves_received_next_hop() {
        let mut rib = new_rib(65000);
        let source = addr("10.0.0.1");
        let other = addr("10.0.0.2");
        let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
        let mut other_rx = register_peer_with_mode(
            &mut rib,
            other,
            false,
            addr("10.0.0.253"),
            Some(NextHopMode::Unchanged),
        );

        rib.handle_update(
            source,
            false,
            v4("192.0.2.1"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
            &nos_rpl::ACCEPT_ALL,
        );

        let updates = recv_all(&mut other_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("1.2.3.0/24"),
                as_path: vec![65000, 65001],
                next_hop: addr("10.0.0.1"),
                local_pref: None,
                med: None,
                origin: message::Origin::Igp,
                use_mp: false,
            })]
        );
    }

    #[test]
    fn redistributed_route_always_gets_next_hop_self_even_with_unchanged_override() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let mut rx = register_peer_with_mode(
            &mut rib,
            peer,
            true,
            addr("10.0.0.253"),
            Some(NextHopMode::Unchanged),
        );

        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

        let updates = recv_all(&mut rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("192.168.1.0/24"),
                as_path: vec![],
                // No stored next-hop on a Local-origin route, so it always
                // falls back to next-hop-self regardless of mode.
                next_hop: addr("10.0.0.253"),
                local_pref: Some(100),
                med: None,
                origin: message::Origin::Igp,
                use_mp: false,
            })]
        );
    }

    #[test]
    fn route_with_own_asn_in_as_path_is_dropped_for_loop_prevention() {
        let mut rib = new_rib(65000);
        let source = addr("10.0.0.1");
        let other = addr("10.0.0.2");
        let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
        let mut other_rx = register_peer(&mut rib, other, false, addr("10.0.0.253"));

        rib.handle_update(
            source,
            false,
            v4("192.0.2.1"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![65002, 65000, 65001], "10.0.0.1"),
            &nos_rpl::ACCEPT_ALL,
        );

        assert!(recv_all(&mut other_rx).is_empty());
    }

    #[test]
    fn higher_local_pref_wins_best_path() {
        // peer_a/peer_b are eBGP sources (so split-horizon doesn't remove
        // them from consideration for the iBGP observer below) proposing the
        // same prefix with different LOCAL_PREF values.
        let mut rib = new_rib(65000);
        let peer_a = addr("10.0.0.1");
        let peer_b = addr("10.0.0.2");
        let observer = addr("10.0.0.3");
        let _rx_a = register_peer(&mut rib, peer_a, false, addr("10.0.0.254"));
        let _rx_b = register_peer(&mut rib, peer_b, false, addr("10.0.0.253"));
        let mut observer_rx = register_peer(&mut rib, observer, true, addr("10.0.0.252"));

        rib.handle_update(
            peer_a,
            false,
            v4("192.0.2.1"),
            &UpdateMessage {
                nlri: vec!["9.9.9.0/24".parse().unwrap()],
                attributes: Some(message::PathAttributes {
                    origin: message::Origin::Igp,
                    as_path: vec![],
                    next_hop: v4("10.0.0.1"),
                    local_pref: Some(50),
                    med: None,
                    originator_id: None,
                    cluster_list: vec![],
                    communities: Vec::new(),
                    extended_communities: Vec::new(),
                    large_communities: Vec::new(),
                    pmsi: None,
                }),
                ..empty_update()
            },
            &nos_rpl::ACCEPT_ALL,
        );
        let _ = recv_all(&mut observer_rx);

        rib.handle_update(
            peer_b,
            false,
            v4("192.0.2.1"),
            &UpdateMessage {
                nlri: vec!["9.9.9.0/24".parse().unwrap()],
                attributes: Some(message::PathAttributes {
                    origin: message::Origin::Igp,
                    as_path: vec![],
                    next_hop: v4("10.0.0.2"),
                    local_pref: Some(200),
                    med: None,
                    originator_id: None,
                    cluster_list: vec![],
                    communities: Vec::new(),
                    extended_communities: Vec::new(),
                    large_communities: Vec::new(),
                    pmsi: None,
                }),
                ..empty_update()
            },
            &nos_rpl::ACCEPT_ALL,
        );

        let updates = recv_all(&mut observer_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("9.9.9.0/24"),
                as_path: vec![],
                // iBGP defaults to Unchanged: peer_b's own advertised
                // next-hop (10.0.0.2) is preserved, not rewritten to the
                // observer's local address.
                next_hop: addr("10.0.0.2"),
                local_pref: Some(200),
                med: None,
                origin: message::Origin::Igp,
                use_mp: false,
            })]
        );
    }

    #[test]
    fn local_redistributed_route_beats_peer_learned_route_for_same_prefix() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let observer = addr("10.0.0.2");
        let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
        let mut observer_rx = register_peer(&mut rib, observer, false, addr("10.0.0.253"));

        rib.handle_update(
            peer,
            false,
            v4("192.0.2.1"),
            &ebgp_update(vec!["5.5.5.0/24"], vec![65099], "10.0.0.1"),
            &nos_rpl::ACCEPT_ALL,
        );
        let _ = recv_all(&mut observer_rx);

        rib.apply_redistribute_update(full_update(vec![("5.5.5.0/24", "10.9.9.9")]));

        let updates = recv_all(&mut observer_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("5.5.5.0/24"),
                as_path: vec![65000],
                next_hop: addr("10.0.0.253"),
                local_pref: None,
                med: None,
                origin: message::Origin::Igp,
                use_mp: false,
            })]
        );
    }

    #[test]
    fn withdrawal_removes_route_and_notifies_downstream_peers() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let observer = addr("10.0.0.2");
        let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
        let mut observer_rx = register_peer(&mut rib, observer, false, addr("10.0.0.253"));

        rib.handle_update(
            peer,
            false,
            v4("192.0.2.1"),
            &ebgp_update(vec!["5.5.5.0/24"], vec![65099], "10.0.0.1"),
            &nos_rpl::ACCEPT_ALL,
        );
        let _ = recv_all(&mut observer_rx);

        rib.handle_update(
            peer,
            false,
            v4("192.0.2.1"),
            &UpdateMessage {
                withdrawn_routes: vec!["5.5.5.0/24".parse().unwrap()],
                ..empty_update()
            },
            &nos_rpl::ACCEPT_ALL,
        );

        let updates = recv_all(&mut observer_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Withdraw(prefix("5.5.5.0/24"), false, None)]
        );
    }

    #[test]
    fn peer_disconnected_withdraws_every_route_it_contributed() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let observer = addr("10.0.0.2");
        let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
        let mut observer_rx = register_peer(&mut rib, observer, false, addr("10.0.0.253"));

        rib.handle_update(
            peer,
            false,
            v4("192.0.2.1"),
            &ebgp_update(vec!["5.5.5.0/24", "6.6.6.0/24"], vec![65099], "10.0.0.1"),
            &nos_rpl::ACCEPT_ALL,
        );
        let _ = recv_all(&mut observer_rx);

        rib.peer_disconnected(peer);

        let mut updates = recv_all(&mut observer_rx);
        updates.sort_by_key(|u| match u {
            OutboundUpdate::Withdraw(p, _, _) => p.to_string(),
            OutboundUpdate::Announce(a) => a.prefix.to_string(),
            OutboundUpdate::AnnounceEvpn(_) | OutboundUpdate::WithdrawEvpn(_) => String::new(),
        });
        assert_eq!(
            updates,
            vec![
                OutboundUpdate::Withdraw(prefix("5.5.5.0/24"), false, None),
                OutboundUpdate::Withdraw(prefix("6.6.6.0/24"), false, None),
            ]
        );
    }

    #[test]
    fn peer_with_no_local_address_is_never_eligible_for_self_address() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let (tx, mut rx) = mpsc::unbounded_channel();
        rib.peer_established(
            peer,
            false,
            None,
            all_afs(),
            false,
            None,
            false,
            false,
            HashSet::new(),
            accept_all_policy(),
            tx,
        );

        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

        assert!(recv_all(&mut rx).is_empty());
    }

    #[test]
    fn redistribute_full_matching_current_state_is_a_no_op() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let mut rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));

        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));
        let _ = recv_all(&mut rx);

        // A reconnect-triggered Full with the exact same prefix set: no
        // touched prefixes, so no new sends.
        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));
        assert!(recv_all(&mut rx).is_empty());
    }

    #[test]
    fn redistribute_remove_of_absent_prefix_is_a_no_op() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let mut rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));

        rib.apply_redistribute_update(RedistributeUpdate::Remove(prefix("10.10.10.0/24")));
        assert!(recv_all(&mut rx).is_empty());
    }

    #[test]
    fn newly_established_peer_gets_full_initial_advertisement_of_loc_rib() {
        let mut rib = new_rib(65000);
        let first = addr("10.0.0.1");
        let _rx_first = register_peer(&mut rib, first, false, addr("10.0.0.254"));

        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

        // A second peer joining afterward should get the existing route
        // immediately, without needing a fresh redistribute push.
        let second = addr("10.0.0.2");
        let mut rx_second = register_peer(&mut rib, second, false, addr("10.0.0.253"));

        let updates = recv_all(&mut rx_second);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("192.168.1.0/24"),
                as_path: vec![65000],
                next_hop: addr("10.0.0.253"),
                local_pref: None,
                med: None,
                origin: message::Origin::Igp,
                use_mp: false,
            })]
        );
    }

    #[test]
    fn ipv6_redistributed_route_is_announced_to_a_dual_stack_peer() {
        let mut rib = new_rib(65000);
        let peer = addr("2001:db8::1");
        let mut rx = register_mp_peer(&mut rib, peer, false, addr("2001:db8::254"), all_afs());

        rib.apply_redistribute_update(full_update(vec![("2001:db8:1::/48", "2001:db8::9")]));

        let updates = recv_all(&mut rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("2001:db8:1::/48"),
                as_path: vec![65000],
                next_hop: addr("2001:db8::254"),
                local_pref: None,
                med: None,
                origin: message::Origin::Igp,
                use_mp: true,
            })]
        );
    }

    #[test]
    fn peer_only_negotiated_ipv4_never_gets_an_ipv6_prefix() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let mut rx = register_mp_peer(
            &mut rib,
            peer,
            false,
            addr("10.0.0.254"),
            [AddressFamily::Ipv4Unicast].into_iter().collect(),
        );

        rib.apply_redistribute_update(full_update(vec![("2001:db8:1::/48", "2001:db8::9")]));

        assert!(recv_all(&mut rx).is_empty());
    }

    #[test]
    fn cross_family_next_hop_self_uses_transport_local_address() {
        // RFC 8950: an IPv6-transport peer carrying IPv4 unicast still gets
        // next-hop-self rewritten to its own (IPv6) session-local address.
        let mut rib = new_rib(65000);
        let peer = addr("2001:db8::1");
        let mut rx = register_mp_peer(
            &mut rib,
            peer,
            false,
            addr("2001:db8::254"),
            [AddressFamily::Ipv4Unicast].into_iter().collect(),
        );

        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

        let updates = recv_all(&mut rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("192.168.1.0/24"),
                as_path: vec![65000],
                next_hop: addr("2001:db8::254"),
                local_pref: None,
                med: None,
                origin: message::Origin::Igp,
                use_mp: true,
            })]
        );
    }

    #[test]
    fn mp_peer_ipv4_withdrawal_is_marked_use_mp() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let mut rx = register_mp_peer(&mut rib, peer, false, addr("10.0.0.254"), all_afs());

        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));
        let _ = recv_all(&mut rx);
        rib.apply_redistribute_update(RedistributeUpdate::Remove(prefix("192.168.1.0/24")));

        let updates = recv_all(&mut rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Withdraw(
                prefix("192.168.1.0/24"),
                true,
                None
            )]
        );
    }

    fn update_with(
        nlri: &str,
        as_path: Vec<u32>,
        next_hop: &str,
        origin: message::Origin,
        med: Option<u32>,
    ) -> UpdateMessage {
        UpdateMessage {
            nlri: vec![nlri.parse().unwrap()],
            attributes: Some(message::PathAttributes {
                origin,
                as_path,
                next_hop: v4(next_hop),
                local_pref: None,
                med,
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                pmsi: None,
            }),
            ..empty_update()
        }
    }

    #[test]
    fn lower_origin_type_wins_when_local_pref_and_as_path_tie() {
        let mut rib = new_rib(65000);
        let peer_a = addr("10.0.0.1");
        let peer_b = addr("10.0.0.2");
        let observer = addr("10.0.0.3");
        let _rx_a = register_peer(&mut rib, peer_a, false, addr("10.0.0.254"));
        let _rx_b = register_peer(&mut rib, peer_b, false, addr("10.0.0.253"));
        let mut observer_rx = register_peer(&mut rib, observer, true, addr("10.0.0.252"));

        rib.handle_update(
            peer_a,
            false,
            v4("192.0.2.1"),
            &update_with(
                "9.9.9.0/24",
                vec![65001],
                "10.0.0.1",
                message::Origin::Incomplete,
                None,
            ),
            &nos_rpl::ACCEPT_ALL,
        );
        let _ = recv_all(&mut observer_rx);

        rib.handle_update(
            peer_b,
            false,
            v4("192.0.2.1"),
            &update_with(
                "9.9.9.0/24",
                vec![65001],
                "10.0.0.2",
                message::Origin::Igp,
                None,
            ),
            &nos_rpl::ACCEPT_ALL,
        );

        let updates = recv_all(&mut observer_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("9.9.9.0/24"),
                as_path: vec![65001],
                next_hop: addr("10.0.0.2"),
                local_pref: Some(100),
                med: None,
                origin: message::Origin::Igp,
                use_mp: false,
            })]
        );
    }

    #[test]
    fn lower_med_wins_when_neighboring_as_matches() {
        let mut rib = new_rib(65000);
        let peer_a = addr("10.0.0.1");
        let peer_b = addr("10.0.0.2");
        let observer = addr("10.0.0.3");
        let _rx_a = register_peer(&mut rib, peer_a, false, addr("10.0.0.254"));
        let _rx_b = register_peer(&mut rib, peer_b, false, addr("10.0.0.253"));
        let mut observer_rx = register_peer(&mut rib, observer, true, addr("10.0.0.252"));

        // Both candidates' AS_PATH starts with 65001 — same neighboring AS —
        // so MED is directly comparable between them.
        rib.handle_update(
            peer_a,
            false,
            v4("192.0.2.1"),
            &update_with(
                "9.9.9.0/24",
                vec![65001],
                "10.0.0.1",
                message::Origin::Igp,
                Some(200),
            ),
            &nos_rpl::ACCEPT_ALL,
        );
        let _ = recv_all(&mut observer_rx);

        rib.handle_update(
            peer_b,
            false,
            v4("192.0.2.1"),
            &update_with(
                "9.9.9.0/24",
                vec![65001],
                "10.0.0.2",
                message::Origin::Igp,
                Some(100),
            ),
            &nos_rpl::ACCEPT_ALL,
        );

        let updates = recv_all(&mut observer_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("9.9.9.0/24"),
                as_path: vec![65001],
                next_hop: addr("10.0.0.2"),
                local_pref: Some(100),
                med: Some(100), // forwarded: the destination is an iBGP peer
                origin: message::Origin::Igp,
                use_mp: false,
            })]
        );
    }

    #[test]
    fn med_is_ignored_between_different_neighboring_as() {
        let mut rib = new_rib(65000);
        let peer_a = addr("10.0.0.1");
        let peer_b = addr("10.0.0.2");
        let observer = addr("10.0.0.3");
        let _rx_a = register_peer(&mut rib, peer_a, false, addr("10.0.0.254"));
        let _rx_b = register_peer(&mut rib, peer_b, false, addr("10.0.0.253"));
        let mut observer_rx = register_peer(&mut rib, observer, true, addr("10.0.0.252"));

        // peer_a's MED (999) is far worse than peer_b's (1), but their
        // AS_PATHs start with different ASes, so MED must not be compared
        // between them — peer_a keeps winning via the earlier "oldest
        // route" step (step 8), since both are eBGP-learned and peer_a
        // arrived first, proving the MED comparison was skipped rather
        // than deciding in peer_b's favor.
        rib.handle_update(
            peer_a,
            false,
            v4("192.0.2.1"),
            &update_with(
                "9.9.9.0/24",
                vec![65001],
                "10.0.0.1",
                message::Origin::Igp,
                Some(999),
            ),
            &nos_rpl::ACCEPT_ALL,
        );
        let initial = recv_all(&mut observer_rx);
        assert_eq!(
            initial,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("9.9.9.0/24"),
                as_path: vec![65001],
                next_hop: addr("10.0.0.1"),
                local_pref: Some(100),
                med: Some(999), // forwarded: the destination is an iBGP peer
                origin: message::Origin::Igp,
                use_mp: false,
            })]
        );

        rib.handle_update(
            peer_b,
            false,
            v4("192.0.2.1"),
            &update_with(
                "9.9.9.0/24",
                vec![65002],
                "10.0.0.2",
                message::Origin::Igp,
                Some(1),
            ),
            &nos_rpl::ACCEPT_ALL,
        );

        // The winner is unchanged (still peer_a), so no new announcement is
        // sent at all — if MED had been compared across the differing
        // neighboring ASes, peer_b's much lower MED would have won instead.
        assert!(recv_all(&mut observer_rx).is_empty());
    }

    #[test]
    fn ebgp_learned_route_beats_ibgp_learned_route_when_otherwise_tied() {
        let mut rib = new_rib(65000);
        // The iBGP source has the numerically lower peer address, so an
        // eBGP win here can only be explained by the eBGP-over-iBGP step,
        // not the final peer-address tiebreak.
        let ibgp_peer = addr("10.0.0.1");
        let ebgp_peer = addr("10.0.0.2");
        let observer = addr("10.0.0.3");
        let _rx_ibgp = register_peer(&mut rib, ibgp_peer, true, addr("10.0.0.254"));
        let _rx_ebgp = register_peer(&mut rib, ebgp_peer, false, addr("10.0.0.253"));
        let mut observer_rx = register_peer(&mut rib, observer, false, addr("10.0.0.252"));

        rib.handle_update(
            ibgp_peer,
            true,
            v4("192.0.2.1"),
            &update_with(
                "9.9.9.0/24",
                vec![65001],
                "10.0.0.1",
                message::Origin::Igp,
                None,
            ),
            &nos_rpl::ACCEPT_ALL,
        );
        let _ = recv_all(&mut observer_rx);

        rib.handle_update(
            ebgp_peer,
            false,
            v4("192.0.2.1"),
            &update_with(
                "9.9.9.0/24",
                vec![65001],
                "10.0.0.2",
                message::Origin::Igp,
                None,
            ),
            &nos_rpl::ACCEPT_ALL,
        );

        let updates = recv_all(&mut observer_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("9.9.9.0/24"),
                as_path: vec![65000, 65001],
                // Destination is eBGP, so next-hop-self rewrites to the
                // observer's own local address, not either source's.
                next_hop: addr("10.0.0.252"),
                local_pref: None,
                med: None,
                origin: message::Origin::Igp,
                use_mp: false,
            })]
        );
    }

    #[test]
    fn lower_router_id_wins_when_otherwise_tied() {
        let mut rib = new_rib(65000);
        // Both sources are iBGP, so the eBGP-over-iBGP step (6) and the
        // eBGP-only "oldest route" step (8) both tie — router-id (9) must
        // decide. peer_b has the higher address but the lower router-id, so
        // its win can only be explained by the router-id step, not the
        // final peer-address tiebreak.
        let peer_a = addr("10.0.0.1");
        let peer_b = addr("10.0.0.2");
        let observer = addr("10.0.0.3");
        let _rx_a = register_peer(&mut rib, peer_a, true, addr("10.0.0.254"));
        let _rx_b = register_peer(&mut rib, peer_b, true, addr("10.0.0.253"));
        let mut observer_rx = register_peer(&mut rib, observer, false, addr("10.0.0.252"));

        rib.handle_update(
            peer_a,
            true,
            v4("5.5.5.5"),
            &update_with(
                "9.9.9.0/24",
                vec![65001],
                "10.0.0.1",
                message::Origin::Igp,
                None,
            ),
            &nos_rpl::ACCEPT_ALL,
        );
        let _ = recv_all(&mut observer_rx);

        rib.handle_update(
            peer_b,
            true,
            v4("1.1.1.1"),
            &update_with(
                "9.9.9.0/24",
                vec![65001],
                "10.0.0.2",
                message::Origin::Igp,
                None,
            ),
            &nos_rpl::ACCEPT_ALL,
        );

        let updates = recv_all(&mut observer_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("9.9.9.0/24"),
                // Destination is eBGP, so our own ASN is prepended and
                // next-hop-self rewrites to the observer's own local
                // address, not either source's.
                as_path: vec![65000, 65001],
                next_hop: addr("10.0.0.252"),
                local_pref: None,
                med: None,
                origin: message::Origin::Igp,
                use_mp: false,
            })]
        );
    }

    #[test]
    fn oldest_route_wins_over_a_later_lower_router_id_and_address() {
        let mut rib = new_rib(65000);
        // peer_a has the higher address and router-id (would lose steps 9
        // and 10) but is received first; peer_b has the lower address and
        // router-id but arrives second. peer_a winning proves the "oldest
        // route" step (8) is applied, and applied before router-id/address.
        let peer_a = addr("10.0.0.9");
        let peer_b = addr("10.0.0.1");
        let observer = addr("10.0.0.3");
        let _rx_a = register_peer(&mut rib, peer_a, false, addr("10.0.0.254"));
        let _rx_b = register_peer(&mut rib, peer_b, false, addr("10.0.0.253"));
        let mut observer_rx = register_peer(&mut rib, observer, true, addr("10.0.0.252"));

        rib.handle_update(
            peer_a,
            false,
            v4("9.9.9.9"),
            &update_with(
                "9.9.9.0/24",
                vec![65001],
                "10.0.0.9",
                message::Origin::Igp,
                None,
            ),
            &nos_rpl::ACCEPT_ALL,
        );
        let initial = recv_all(&mut observer_rx);
        assert_eq!(
            initial,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("9.9.9.0/24"),
                as_path: vec![65001],
                next_hop: addr("10.0.0.9"),
                local_pref: Some(100),
                med: None,
                origin: message::Origin::Igp,
                use_mp: false,
            })]
        );

        rib.handle_update(
            peer_b,
            false,
            v4("1.1.1.1"),
            &update_with(
                "9.9.9.0/24",
                vec![65001],
                "10.0.0.1",
                message::Origin::Igp,
                None,
            ),
            &nos_rpl::ACCEPT_ALL,
        );

        // The winner is unchanged (still peer_a), so no new announcement is
        // sent — if the oldest-route step didn't apply, peer_b's lower
        // router-id and address would have won at steps 9/10 instead.
        assert!(recv_all(&mut observer_rx).is_empty());
    }

    // --- RFC 4456 route reflection ---

    #[test]
    fn route_reflector_reflects_ibgp_route_from_non_client_to_client() {
        let router_id = v4("1.1.1.1");
        let cluster_id = v4("9.9.9.9");
        let mut rib = new_rib_with_identity(65000, router_id, cluster_id);
        let source = addr("10.0.0.1"); // plain iBGP peer, not a client
        let client = addr("10.0.0.2"); // route-reflector client
        let _source_rx = register_peer(&mut rib, source, true, addr("10.0.0.254"));
        let mut client_rx = register_peer_full(
            &mut rib,
            client,
            true,
            addr("10.0.0.253"),
            true,
            false,
            HashSet::new(),
        );

        rib.handle_update(
            source,
            true,
            v4("192.0.2.1"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![], "10.0.0.1"),
            &nos_rpl::ACCEPT_ALL,
        );

        let updates = recv_all(&mut client_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: Some(v4("192.0.2.1")),
                cluster_list: vec![cluster_id],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("1.2.3.0/24"),
                as_path: vec![],
                next_hop: addr("10.0.0.1"),
                local_pref: Some(100),
                med: None,
                origin: message::Origin::Igp,
                use_mp: false,
            })]
        );
    }

    #[test]
    fn route_reflector_reflects_ibgp_route_from_client_to_non_client() {
        let router_id = v4("1.1.1.1");
        let cluster_id = v4("9.9.9.9");
        let mut rib = new_rib_with_identity(65000, router_id, cluster_id);
        let client = addr("10.0.0.1"); // route-reflector client (source)
        let other = addr("10.0.0.2"); // plain iBGP peer, not a client
        let _client_rx = register_peer_full(
            &mut rib,
            client,
            true,
            addr("10.0.0.254"),
            true,
            false,
            HashSet::new(),
        );
        let mut other_rx = register_peer(&mut rib, other, true, addr("10.0.0.253"));

        rib.handle_update(
            client,
            true,
            v4("192.0.2.2"),
            &ebgp_update(vec!["4.5.6.0/24"], vec![], "10.0.0.1"),
            &nos_rpl::ACCEPT_ALL,
        );

        let updates = recv_all(&mut other_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: Some(v4("192.0.2.2")),
                cluster_list: vec![cluster_id],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("4.5.6.0/24"),
                as_path: vec![],
                next_hop: addr("10.0.0.1"),
                local_pref: Some(100),
                med: None,
                origin: message::Origin::Igp,
                use_mp: false,
            })]
        );
    }

    #[test]
    fn inbound_update_with_own_cluster_id_in_cluster_list_is_dropped() {
        let router_id = v4("1.1.1.1");
        let cluster_id = v4("9.9.9.9");
        let mut rib = new_rib_with_identity(65000, router_id, cluster_id);
        let source = addr("10.0.0.1");
        let observer = addr("10.0.0.2");
        let mut observer_rx = register_peer(&mut rib, observer, true, addr("10.0.0.253"));

        let mut update = ebgp_update(vec!["7.8.9.0/24"], vec![], "10.0.0.1");
        update.attributes.as_mut().unwrap().cluster_list = vec![cluster_id];

        rib.handle_update(source, true, v4("192.0.2.1"), &update, &nos_rpl::ACCEPT_ALL);

        assert!(recv_all(&mut observer_rx).is_empty());
    }

    #[test]
    fn inbound_update_with_own_router_id_as_originator_id_is_dropped() {
        let router_id = v4("1.1.1.1");
        let cluster_id = v4("9.9.9.9");
        let mut rib = new_rib_with_identity(65000, router_id, cluster_id);
        let source = addr("10.0.0.1");
        let observer = addr("10.0.0.2");
        let mut observer_rx = register_peer(&mut rib, observer, true, addr("10.0.0.253"));

        let mut update = ebgp_update(vec!["7.8.9.0/24"], vec![], "10.0.0.1");
        update.attributes.as_mut().unwrap().originator_id = Some(router_id);

        rib.handle_update(source, true, v4("192.0.2.1"), &update, &nos_rpl::ACCEPT_ALL);

        assert!(recv_all(&mut observer_rx).is_empty());
    }

    // --- RFC 7947 route server ---

    #[test]
    fn route_server_client_gets_no_as_path_prepend_but_plain_ebgp_peer_does() {
        let mut rib = new_rib(65000);
        let plain_peer = addr("10.0.0.1");
        let rs_client = addr("10.0.0.2");
        let mut plain_rx = register_peer(&mut rib, plain_peer, false, addr("10.0.0.254"));
        let mut rs_rx = register_peer_full(
            &mut rib,
            rs_client,
            false,
            addr("10.0.0.253"),
            false,
            true,
            HashSet::new(),
        );

        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

        let plain_updates = recv_all(&mut plain_rx);
        assert_eq!(
            plain_updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("192.168.1.0/24"),
                as_path: vec![65000],
                next_hop: addr("10.0.0.254"),
                local_pref: None,
                med: None,
                origin: message::Origin::Igp,
                use_mp: false,
            })]
        );

        let rs_updates = recv_all(&mut rs_rx);
        assert_eq!(
            rs_updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                originator_id: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("192.168.1.0/24"),
                as_path: vec![], // route-server-client: transparent, no local-asn prepend
                next_hop: addr("10.0.0.253"),
                local_pref: None,
                med: None,
                origin: message::Origin::Igp,
                use_mp: false,
            })]
        );
    }

    #[test]
    fn propagate_rs_view_sends_distinct_path_ids_and_withdraws_on_source_disconnect() {
        let mut rib = new_rib(65000);
        let peer_a = addr("10.0.0.1");
        let peer_b = addr("10.0.0.2");
        let rs_client = addr("10.0.0.3");

        let _rx_a = register_peer(&mut rib, peer_a, false, addr("10.0.0.254"));
        let _rx_b = register_peer(&mut rib, peer_b, false, addr("10.0.0.253"));
        let mut rs_rx = register_peer_full(
            &mut rib,
            rs_client,
            false,
            addr("10.0.0.252"),
            false,
            true,
            [AddressFamily::Ipv4Unicast].into_iter().collect(),
        );

        rib.handle_update(
            peer_a,
            false,
            v4("192.0.2.1"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
            &nos_rpl::ACCEPT_ALL,
        );
        rib.handle_update(
            peer_b,
            false,
            v4("192.0.2.2"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![65002], "10.0.0.2"),
            &nos_rpl::ACCEPT_ALL,
        );

        let updates = recv_all(&mut rs_rx);
        // Each source's own path reaches the rs-client transparently (no
        // local-asn prepend), each carrying its own distinct, stable path id
        // — alongside whichever single path the ordinary fan-out also sends
        // (with no path id at all).
        let id_for_a = updates
            .iter()
            .find_map(|u| match u {
                OutboundUpdate::Announce(r) if r.as_path == vec![65001] => r.path_id,
                _ => None,
            })
            .expect("peer_a's path reached the rs-client with a path id");
        let id_for_b = updates
            .iter()
            .find_map(|u| match u {
                OutboundUpdate::Announce(r) if r.as_path == vec![65002] => r.path_id,
                _ => None,
            })
            .expect("peer_b's path reached the rs-client with a path id");
        assert_ne!(id_for_a, id_for_b);

        // Disconnecting peer_a withdraws only its path id; peer_b's stays.
        rib.peer_disconnected(peer_a);
        let after = recv_all(&mut rs_rx);
        let withdrawn_ids: Vec<Option<u32>> = after
            .iter()
            .filter_map(|u| match u {
                OutboundUpdate::Withdraw(_, _, id) if id.is_some() => Some(*id),
                _ => None,
            })
            .collect();
        assert_eq!(withdrawn_ids, vec![Some(id_for_a)]);
    }

    #[test]
    fn route_server_client_without_add_path_gets_only_ordinary_single_best() {
        let mut rib = new_rib(65000);
        let peer_a = addr("10.0.0.1");
        let peer_b = addr("10.0.0.2");
        let rs_client_no_add_path = addr("10.0.0.3");

        let _rx_a = register_peer(&mut rib, peer_a, false, addr("10.0.0.254"));
        let _rx_b = register_peer(&mut rib, peer_b, false, addr("10.0.0.253"));
        let mut rs_rx = register_peer_full(
            &mut rib,
            rs_client_no_add_path,
            false,
            addr("10.0.0.252"),
            false,
            true,
            HashSet::new(), // is_rs_client but no negotiated add_path_afs
        );

        rib.handle_update(
            peer_a,
            false,
            v4("192.0.2.1"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
            &nos_rpl::ACCEPT_ALL,
        );
        rib.handle_update(
            peer_b,
            false,
            v4("192.0.2.2"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![65002], "10.0.0.2"),
            &nos_rpl::ACCEPT_ALL,
        );

        let updates = recv_all(&mut rs_rx);
        assert!(!updates.is_empty());
        // No path-id'd traffic at all — propagate_rs_view never runs for a
        // family this peer didn't negotiate ADD-PATH for.
        assert!(updates.iter().all(|u| match u {
            OutboundUpdate::Announce(r) => r.path_id.is_none(),
            OutboundUpdate::Withdraw(_, _, id) => id.is_none(),
            OutboundUpdate::AnnounceEvpn(_) | OutboundUpdate::WithdrawEvpn(_) => true,
        }));
        // Still transparent (no AS_PATH prepend) — that's governed by
        // is_rs_client alone, independent of ADD-PATH negotiation. Only
        // peer_a's route ever wins the ordinary single-best election (lower
        // router-id), so that's the one path this peer ever sees.
        assert!(updates.iter().any(|u| matches!(
            u,
            OutboundUpdate::Announce(r) if r.as_path == vec![65001]
        )));
    }

    #[test]
    fn push_snapshot_includes_peer_learned_route_with_next_hop() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        rib.handle_update(
            peer,
            false,
            v4("192.0.2.1"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.9"),
            &nos_rpl::ACCEPT_ALL,
        );

        let (_, routes) = rib.push_snapshot();
        assert_eq!(
            routes.get(&prefix("1.2.3.0/24")),
            Some(&(addr("10.0.0.9"), None))
        );
    }

    #[test]
    fn push_snapshot_carries_runner_up_as_backup() {
        let mut rib = new_rib(65000);
        rib.handle_update(
            addr("10.0.0.1"),
            false,
            v4("192.0.2.1"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.9"),
            &nos_rpl::ACCEPT_ALL,
        );
        // Longer AS_PATH → loses, but its distinct next hop is the backup.
        rib.handle_update(
            addr("10.0.0.2"),
            false,
            v4("192.0.2.2"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![65002, 65003], "10.0.0.8"),
            &nos_rpl::ACCEPT_ALL,
        );
        // A third path sharing the winner's next hop can't be a backup.
        rib.handle_update(
            addr("10.0.0.3"),
            false,
            v4("192.0.2.3"),
            &ebgp_update(vec!["1.2.3.0/24"], vec![65004, 65005, 65006], "10.0.0.9"),
            &nos_rpl::ACCEPT_ALL,
        );

        let (_, routes) = rib.push_snapshot();
        assert_eq!(
            routes.get(&prefix("1.2.3.0/24")),
            Some(&(addr("10.0.0.9"), Some(addr("10.0.0.8"))))
        );

        // Losing the runner-up drops the backup.
        rib.peer_disconnected(addr("10.0.0.2"));
        let (_, routes) = rib.push_snapshot();
        assert_eq!(
            routes.get(&prefix("1.2.3.0/24")),
            Some(&(addr("10.0.0.9"), None))
        );
    }

    #[test]
    fn push_snapshot_excludes_local_origin_redistributed_route() {
        let mut rib = new_rib(65000);
        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

        let (_, routes) = rib.push_snapshot();
        assert!(!routes.contains_key(&prefix("192.168.1.0/24")));
    }

    #[test]
    fn push_snapshot_reflects_routing_table_after_set() {
        let mut rib = new_rib(65000);
        assert_eq!(rib.push_snapshot().0, None);

        rib.set_routing_table(Some("rt1".to_string()));
        assert_eq!(rib.push_snapshot().0, Some("rt1".to_string()));
    }
}
