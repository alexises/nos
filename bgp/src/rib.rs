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
//! Before any of it runs, RFC 4271 §9.1.2's feasibility check: a peer-learned
//! candidate whose `NEXT_HOP` no route in the IGP table polled from `nos-ribd`
//! covers is unfeasible and is dropped from the candidate set outright
//! (`next_hop_feasible`) — not merely tie-broken — once that table has been
//! fetched at least once (`igp_ready`; before that every candidate is kept,
//! so a fresh start never blackholes what it just learned). Directly connected
//! next hops resolve because `nos-ribd` holds every applied address as a
//! `Connected` route. The runner-up/backup path is picked from the same
//! filtered set, so it needs a resolvable next hop just the same.
//!
//! Best path selection (`best_path`) implements the full RFC 4271 §9.1.2.2
//! decision process, in order: (1) higher `LOCAL_PREF`; (2) a
//! locally-redistributed route beats any peer-learned route (not an RFC
//! step — this implementation's equivalent of "prefer locally originated",
//! placed here per common vendor convention, e.g. Cisco's own ordering);
//! (3) shorter `AS_PATH` (`AsPath::selection_len`: an `AS_SET` counts one,
//! RFC 5065 confederation segments none); (4) lowest `ORIGIN` type (`Igp` <
//! `Egp` < `Incomplete`); (5) lowest `MULTI_EXIT_DISC`, only compared
//! between routes sharing the same neighboring AS (`AsPath::neighbor_as`,
//! confederation segments skipped), missing MED treated as 0; (6) an
//! eBGP-learned route beats an iBGP-learned one; (7) lowest IGP metric to the next-hop, resolved by
//! longest-prefix match against the table `igp_client` polls from
//! `nos-ribd` (`set_igp`) — a directly connected one is a `Connected` route
//! at cost 0, an unresolvable one never gets here (see above); (8) oldest route
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
//! - RFC 5065 confederations (`set_confederation`, `set_peer_confed`): a
//!   confederation-external peer is treated as iBGP for next hop, MED and
//!   `LOCAL_PREF` and gets our member AS in an `AS_CONFED_SEQUENCE`; an
//!   external peer gets the path without confederation segments and the
//!   identifier prepended. Confederation segments from outside the
//!   confederation are treat-as-withdraw; loop detection checks the
//!   identifier in plain segments and the member AS in confed segments.
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
use nos_proto::{AddressFamily, BgpDamping, NextHopMode, RedistributeUpdate};
use nos_rpl::CompiledPolicy;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::as_path::AsPath;
use crate::damping::{Damping, CHANGE_PENALTY, WITHDRAW_PENALTY};
use crate::evpn::EvpnNlri;
use crate::mac_mobility::MacMobility;
use crate::message::{self, UpdateMessage};

mod evpn_out;
pub use evpn_out::AdvertisedEvpn;

/// Adapts a `RibRoute` into `nos_rpl`'s input shape — see root `CLAUDE.md`'s
/// "Execution model". A plain function, not an adapter trait: there is
/// exactly one producer (`RibRoute`) today, so a trait would add indirection
/// with nothing to abstract over yet.
fn to_policy_input(
    prefix: IpNet,
    route: &RibRoute,
    peer: Option<(IpAddr, u32)>,
) -> nos_rpl::Input<'_> {
    nos_rpl::Input {
        prefix,
        bgp: nos_rpl::BgpInput {
            origin: match route.bgp_origin {
                message::Origin::Igp => nos_rpl::Origin::Igp,
                message::Origin::Egp => nos_rpl::Origin::Egp,
                message::Origin::Incomplete => nos_rpl::Origin::Incomplete,
            },
            as_path: route.as_path.flat(),
            local_pref: route.local_pref,
            med: route.med,
            next_hop: route.next_hop,
            learned_via_ibgp: route.learned_via_ibgp,
            router_id: route.router_id,
            originator_id: route.originator_id,
            cluster_list: &route.cluster_list,
            peer: peer.map(|(addr, _)| addr),
            peer_as: peer.map_or(0, |(_, asn)| asn),
            communities: &route.communities,
            extended_communities: &route.extended_communities,
            large_communities: &route.large_communities,
            validation_state: route.validation_state,
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
    peer: Option<(IpAddr, u32)>,
) -> Option<RibRoute> {
    let verdict = nos_rpl::vm::run(policy, &to_policy_input(prefix, &candidate, peer));
    apply_verdict(&mut candidate, verdict).map(|_| candidate)
}

/// Writes an accepting verdict's attribute rewrites back onto `route` and
/// returns the policy's next-hop edit; `None` means the verdict was a reject
/// (and `route` is untouched). An explicit next-hop address is stored on the
/// route; `SelfAddress` only means something when advertising, so it is
/// returned for `build_advertisement` and ignored on import.
fn apply_verdict(route: &mut RibRoute, verdict: nos_rpl::Verdict) -> Option<nos_rpl::NextHopSet> {
    let nos_rpl::Verdict::Accept {
        local_pref,
        med,
        communities,
        extended_communities,
        large_communities,
        edits,
    } = verdict
    else {
        return None;
    };
    route.local_pref = local_pref;
    route.med = med;
    route.communities = communities;
    route.extended_communities = extended_communities;
    route.large_communities = large_communities;
    // RPL only prepends: the new leading ASNs join the leading AS_SEQUENCE.
    if let Some(flat) = edits.as_path {
        let added = flat.len().saturating_sub(route.as_path.flat().len());
        let path = Arc::make_mut(&mut route.as_path);
        for &asn in flat[..added].iter().rev() {
            path.prepend_seq(asn);
        }
    }
    if let Some(origin) = edits.origin {
        route.bgp_origin = match origin {
            nos_rpl::Origin::Igp => message::Origin::Igp,
            nos_rpl::Origin::Egp => message::Origin::Egp,
            nos_rpl::Origin::Incomplete => message::Origin::Incomplete,
        };
    }
    if let nos_rpl::NextHopSet::Addr(a) = edits.next_hop {
        route.next_hop = Some(a);
    }
    Some(edits.next_hop)
}

/// A Type-2 route's `(VNI, MAC)` mobility identity — `None` for every other
/// EVPN route type, which RFC 7432 §15 mobility doesn't apply to.
fn evpn_mac_key(nlri: &EvpnNlri) -> Option<(u32, [u8; 6])> {
    match nlri {
        EvpnNlri::MacIp { mac, labels, .. } => Some((labels.first().copied().unwrap_or(0), *mac)),
        _ => None,
    }
}

/// Stores one `MP_REACH_NLRI` batch's EVPN routes in a peer's EVPN Adj-RIB-In,
/// logging only routes that are new or changed, and registers each Type-2's
/// `(VNI, MAC)` as an RFC 7432 §15 mobility candidate.
fn learn_evpn(
    table: &mut HashMap<EvpnNlri, EvpnRoute>,
    mac_mobility: &mut MacMobility,
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
        if let Some((vni, mac)) = evpn_mac_key(nlri) {
            let (seq, sticky) = extended_communities
                .iter()
                .find_map(|c| nos_proto::evpn_id::parse_mac_mobility(*c))
                .unwrap_or((0, false));
            mac_mobility.candidate(vni, mac, mp.next_hop, seq, sticky, Instant::now());
        }
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
#[allow(clippy::too_many_arguments)]
fn learn_prefix(
    table: &mut HashMap<IpNet, RibRoute>,
    v6_count: &mut u32,
    damping: &mut Damping,
    touched: &mut HashSet<IpNet>,
    peer: (IpAddr, u32),
    prefix: IpNet,
    candidate: RibRoute,
    import_policy: &CompiledPolicy,
) {
    let (from, _) = peer;
    match apply_policy(prefix, candidate, import_policy, Some(peer)) {
        Some(mut route) => {
            if let Some(old) = table.get(&prefix) {
                // An RPKI state change alone is no flap (#17).
                let same = RibRoute {
                    received_at: old.received_at,
                    validation_state: old.validation_state,
                    ..route.clone()
                } == *old;
                if same {
                    // Keep the age: `received_at` is part of `PartialEq`, so a
                    // fresh one would make every identical re-announcement
                    // look changed downstream and be re-propagated (#160).
                    route.received_at = old.received_at;
                } else if damping.enabled(from) {
                    damping.flap(from, prefix, CHANGE_PENALTY, Instant::now());
                }
            }
            info!(
                peer = %from,
                atomic_aggregate = route.atomic_aggregate,
                aggregator = ?route.aggregator.map(|a| (a.asn, a.router_id)),
                validation_state = ?route.validation_state,
                "bgp: learned route for {prefix} into adj-rib-in"
            );
            if table.insert(prefix, route).is_none() && prefix.addr().is_ipv6() {
                *v6_count += 1;
            }
        }
        None => {
            if table.remove(&prefix).is_some() {
                if prefix.addr().is_ipv6() {
                    *v6_count -= 1;
                }
                damping.flap(from, prefix, WITHDRAW_PENALTY, Instant::now());
            }
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
    /// Never mutated in place by RPL (a `prepend` replaces the whole `Arc`)
    /// — shared via `Arc` so cloning a `RibRoute` (candidate collection,
    /// `loc_rib`/`adj_rib_in` storage) never deep-copies this list.
    pub as_path: Arc<AsPath>,
    pub bgp_origin: message::Origin,
    /// Always the effective value — defaulted to `DEFAULT_LOCAL_PREF` when
    /// the peer's UPDATE omitted `LOCAL_PREF`, or for a `Local` route.
    pub local_pref: u32,
    /// `Some` iff the peer's UPDATE carried `MULTI_EXIT_DISC`. Always
    /// `None` for `origin == Local` — a locally-redistributed route never
    /// carries one.
    pub med: Option<u32>,
    /// Learned from an `Internal` peer (the member AS, in an RFC 5065
    /// confederation). Meaningless when `origin == Local`.
    pub learned_via_ibgp: bool,
    /// Learned from a confederation-external peer (RFC 5065) — ranks
    /// between external and internal at decision step 6.
    pub learned_via_confed: bool,
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
    /// When this candidate was first received with these attributes (an
    /// identical re-announcement keeps it, #160) — used only by the RFC 4271
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
    /// RFC 4271 §5.1.6/§5.1.7, preserved in transit (never set locally).
    pub atomic_aggregate: bool,
    pub aggregator: Option<message::Aggregator>,
    /// RFC 6811 origin validation against the instance's current VRP set,
    /// computed before import policy runs (`this.bgp.validation_state`).
    pub validation_state: nos_rpl::ValidationState,
    /// The RFC 8097 state an opted-in iBGP peer sent with this route, used
    /// instead of local validation while the VRP table is empty (`ov_state`).
    pub received_ov: Option<nos_rpl::ValidationState>,
}

/// RFC 8097 §2: a state signalled by the peer applies only "in the absence
/// of validation state set based on local data".
fn ov_state(
    vrps: &crate::rpki::VrpTable,
    prefix: IpNet,
    origin: Option<u32>,
    received: Option<nos_rpl::ValidationState>,
) -> nos_rpl::ValidationState {
    match received {
        Some(s) if vrps.is_empty() => s,
        _ => vrps.validate(prefix, origin),
    }
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
    /// RFC 7313 Begin/End-of-Route-Refresh marker for one family, queued in
    /// order with the resent routes it brackets.
    RefreshMarker {
        family: AddressFamily,
        subtype: u8,
    },
}

/// A route rewritten for advertisement toward one specific peer.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvertisedRoute {
    pub prefix: IpNet,
    /// Already rewritten for the destination peer (our ASN prepended iff
    /// eBGP and not a `route_server_client`).
    pub as_path: AsPath,
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
    /// Transitive: forwarded unchanged to every eligible peer.
    pub atomic_aggregate: bool,
    pub aggregator: Option<message::Aggregator>,
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
    /// `Internal` (the member AS, in a confederation).
    is_ibgp: bool,
    /// RFC 5065 confederation-external: next hop, MED and `LOCAL_PREF`
    /// kept as for iBGP, `AS_CONFED_SEQUENCE` prepended.
    is_confed: bool,
    /// This instance's confederation identifier when the peer was
    /// registered — the AS an external peer sees.
    confed_id: Option<u32>,
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
    /// RFC 8097: attach the route's validation state (`set_peer_rpki_state`).
    announce_rpki_state: bool,
    /// See `BgpRib::peer_asns`.
    remote_asn: u32,
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
    /// Our AS — the member AS in an RFC 5065 confederation.
    local_asn: u32,
    /// RFC 5065 confederation identifier, if this instance is a member.
    confed_id: Option<u32>,
    /// Peers in another member AS of our confederation (`set_peer_confed`).
    confed_peers: HashSet<IpAddr>,
    /// iBGP peers exchanging RFC 8097 states (`set_peer_rpki_state`).
    rpki_state_peers: HashSet<IpAddr>,
    /// This instance's own router-id — used for RFC 4456 §5 `ORIGINATOR_ID`
    /// loop-prevention on receipt (`handle_update`).
    local_router_id: Ipv4Addr,
    /// This instance's effective RFC 4456 cluster-id (`BgpInstance.cluster_id`
    /// unwrapped to `router_id` when unset) — prepended to `CLUSTER_LIST` on
    /// reflection and checked for loop-prevention on receipt.
    cluster_id: Ipv4Addr,
    adj_rib_in: HashMap<IpAddr, HashMap<IpNet, RibRoute>>,
    /// How many of each peer's `adj_rib_in` prefixes are IPv6 (the rest are
    /// IPv4) — kept in step at every `adj_rib_in` mutation so the RFC 4486
    /// maximum-prefix check is O(1) per UPDATE, not a table scan.
    v6_counts: HashMap<IpAddr, u32>,
    /// Each peer's maximum-prefix limits (`set_peer_max_prefix`), and the
    /// `(peer, family)` pairs already warned about for a `warning_only` limit,
    /// so the warning is logged once per crossing.
    max_prefix: HashMap<IpAddr, nos_proto::BgpMaximumPrefix>,
    max_prefix_warned: HashSet<(IpAddr, AddressFamily)>,
    /// Received EVPN (RFC 7432) routes per peer, keyed by NLRI.
    // ponytail: Adj-RIB-In only — no best-path, Route-Target import filtering,
    // import policy (RPL's `Input` is prefix-shaped) or re-advertisement, since
    // nothing consumes EVPN routes yet. Add a Loc-RIB when a MAC-VRF does.
    evpn_adj_rib_in: HashMap<IpAddr, HashMap<EvpnNlri, EvpnRoute>>,
    /// RFC 7313: prefixes in a peer's Adj-RIB-In marked stale by a `BoRR` and
    /// not yet re-announced; purged by the matching `EoRR`.
    stale: HashMap<IpAddr, HashSet<IpNet>>,
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
    /// IGP cost per prefix, as last polled from `nos-ribd` — decision step (d).
    igp: HashMap<IpNet, u32>,
    /// Whether `igp` has been fetched at least once — before that, no
    /// candidate is excluded for an unresolvable next hop (see the module
    /// doc comment).
    igp_ready: bool,
    /// Per prefix, the runner-up path's next hop (a different next hop from
    /// the winner's), pushed to `nos-ribd` as the kernel backup route.
    backups: HashMap<IpNet, IpAddr>,
    /// What we've last told each peer, for correct withdrawals.
    adj_rib_out: HashMap<IpAddr, HashSet<IpNet>>,
    peer_outboxes: HashMap<IpAddr, PeerOutbox>,
    /// Each peer's negotiated remote ASN (see `set_peer_asn`), for RPL's
    /// `this.bgp.peer_as`. Kept across resets like damping params.
    peer_asns: HashMap<IpAddr, u32>,
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
    /// RFC 2439 flap-damping state for received routes; a suppressed
    /// (peer, prefix) stays in `adj_rib_in` but is not a best-path candidate.
    damping: Damping,
    /// RFC 7432 §15 EVPN MAC mobility: which advertisement (local or from a
    /// peer) for a `(VNI, MAC)` is authoritative, and §15.2 duplicate-MAC
    /// freezing — see `evpn_out`.
    mac_mobility: MacMobility,
    /// This instance's owning `RoutingTable` name (`BgpInstance.routing_table`),
    /// set by `session::SessionManager::reconcile`. Read by `push_snapshot`
    /// to resolve which `nos-ribd` instance, if any, this instance's best
    /// routes should be pushed to.
    owning_routing_table: Option<String>,
    /// The RPKI VRP set (RFC 6811) every route is validated against, from
    /// the instance's RTR client (`crate::rpki`).
    vrps: Arc<crate::rpki::VrpTable>,
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
            confed_id: None,
            confed_peers: HashSet::new(),
            rpki_state_peers: HashSet::new(),
            local_router_id: Ipv4Addr::UNSPECIFIED,
            cluster_id: Ipv4Addr::UNSPECIFIED,
            adj_rib_in: HashMap::new(),
            v6_counts: HashMap::new(),
            max_prefix: HashMap::new(),
            max_prefix_warned: HashSet::new(),
            evpn_adj_rib_in: HashMap::new(),
            stale: HashMap::new(),
            evpn_local: HashMap::new(),
            evpn_adj_rib_out: HashMap::new(),
            fdb_domains: Vec::new(),
            redistribute_raw: HashSet::new(),
            redistributed: HashMap::new(),
            redistribute_policy: Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            loc_rib: HashMap::new(),
            igp: HashMap::new(),
            igp_ready: false,
            backups: HashMap::new(),
            adj_rib_out: HashMap::new(),
            peer_outboxes: HashMap::new(),
            peer_asns: HashMap::new(),
            rs_sent: HashMap::new(),
            rs_next_id: HashMap::new(),
            peer_scratch: Vec::new(),
            damping: Damping::default(),
            mac_mobility: MacMobility::default(),
            owning_routing_table: None,
            vrps: Arc::default(),
        }
    }

    /// The origin AS a route with `path` validates as (RFC 6811 §2): our
    /// own AS — the confederation identifier, if any — for a path with no
    /// non-confederation segment.
    fn validate(&self, prefix: IpNet, path: &AsPath) -> nos_rpl::ValidationState {
        self.vrps.validate(
            prefix,
            crate::rpki::origin_as(path, self.confed_id.unwrap_or(self.local_asn)),
        )
    }

    pub fn vrps(&self) -> Arc<crate::rpki::VrpTable> {
        self.vrps.clone()
    }

    /// Installs a new VRP set and re-validates every held route in place,
    /// re-deciding each prefix whose state changed — so best path and export
    /// policies see it at once. An import policy reading the state needs the
    /// routes again (rejected ones aren't held), which is the caller's route
    /// refresh (`SessionManager::apply_vrps`).
    pub fn set_vrps(&mut self, vrps: Arc<crate::rpki::VrpTable>) {
        self.vrps = vrps;
        let local = self.confed_id.unwrap_or(self.local_asn);
        let mut touched = HashSet::new();
        for table in self.adj_rib_in.values_mut() {
            for (prefix, route) in table.iter_mut() {
                let state = ov_state(
                    &self.vrps,
                    *prefix,
                    crate::rpki::origin_as(&route.as_path, local),
                    route.received_ov,
                );
                if state != route.validation_state {
                    route.validation_state = state;
                    touched.insert(*prefix);
                }
            }
        }
        for prefix in self.redistribute_raw.clone() {
            if self.refilter_redistribute(prefix) {
                touched.insert(prefix);
            }
        }
        info!(
            vrps = self.vrps.len(),
            revalidated = touched.len(),
            "rpki vrp set applied"
        );
        for prefix in touched {
            self.recompute_and_propagate(prefix);
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

    /// Sets the RFC 5065 confederation identifier (`None`: not confederated).
    pub fn set_confederation(&mut self, confed_id: Option<u32>) {
        self.confed_id = confed_id;
    }

    /// Records whether `peer` is in another member AS of our confederation.
    /// Call before `peer_established`, like `set_peer_asn`.
    pub fn set_peer_confed(&mut self, peer: IpAddr, confed: bool) {
        if confed {
            self.confed_peers.insert(peer);
        } else {
            self.confed_peers.remove(&peer);
        }
    }

    /// Records whether `peer` exchanges RFC 8097 validation states (an
    /// opted-in iBGP peer). Call before `peer_established`, like `set_peer_asn`.
    pub fn set_peer_rpki_state(&mut self, peer: IpAddr, on: bool) {
        if on {
            self.rpki_state_peers.insert(peer);
        } else {
            self.rpki_state_peers.remove(&peer);
        }
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
        let remote_asn = self.peer_asns.get(&peer).copied().unwrap_or(0);
        self.peer_outboxes.insert(
            peer,
            PeerOutbox {
                tx,
                is_ibgp,
                is_confed: self.confed_peers.contains(&peer),
                announce_rpki_state: self.rpki_state_peers.contains(&peer),
                confed_id: self.confed_id,
                local_addr,
                negotiated_afs,
                mp_bgp_negotiated,
                next_hop_mode,
                is_rr_client,
                is_rs_client,
                remote_asn,
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
    pub fn resend_all(&mut self, peer: IpAddr, family: AddressFamily, enhanced: bool) {
        let Some(outbox) = self.peer_outboxes.get(&peer) else {
            return;
        };
        let marker = |subtype| OutboundUpdate::RefreshMarker { family, subtype };
        if enhanced {
            let _ = outbox.tx.send(marker(message::REFRESH_BORR));
        }
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
        if enhanced {
            let _ = outbox.tx.send(marker(message::REFRESH_EORR));
        }
    }

    /// RFC 7313 `BoRR` received: every `family` route currently held from
    /// `peer` becomes stale until the peer re-announces it.
    pub fn begin_refresh_in(&mut self, peer: IpAddr, family: AddressFamily) {
        let Some(table) = self.adj_rib_in.get(&peer) else {
            return;
        };
        let set = self.stale.entry(peer).or_default();
        set.extend(table.keys().copied().filter(|p| family_of(*p) == family));
    }

    /// RFC 7313 `EoRR` received: withdraw every `family` route from `peer`
    /// that the refresh did not re-announce.
    pub fn end_refresh_in(&mut self, peer: IpAddr, family: AddressFamily) {
        let Some(set) = self.stale.get_mut(&peer) else {
            return;
        };
        let purge: Vec<IpNet> = set
            .iter()
            .copied()
            .filter(|p| family_of(*p) == family)
            .collect();
        set.retain(|p| family_of(*p) != family);
        for prefix in purge {
            if self
                .adj_rib_in
                .get_mut(&peer)
                .is_some_and(|t| t.remove(&prefix).is_some())
            {
                if prefix.addr().is_ipv6() {
                    *self.v6_counts.entry(peer).or_default() -= 1;
                }
                info!(peer = %peer, %prefix, "bgp: purged stale route at end of route refresh");
                self.recompute_and_propagate(prefix);
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

    /// Enables (or with `None` disables) RFC 2439 damping of routes from `peer`.
    /// Records the remote ASN negotiated in a peer's OPEN, so import and
    /// export policies can match `this.bgp.peer_as`. Call before
    /// `peer_established`.
    pub fn set_peer_asn(&mut self, peer: IpAddr, asn: u32) {
        self.peer_asns.insert(peer, asn);
    }

    pub fn set_peer_damping(&mut self, peer: IpAddr, params: Option<BgpDamping>) {
        self.damping.set_params(peer, params);
    }

    /// Sets `peer`'s RFC 4486 maximum-prefix limits (see `check_max_prefix`).
    pub fn set_peer_max_prefix(&mut self, peer: IpAddr, limits: nos_proto::BgpMaximumPrefix) {
        self.max_prefix.insert(peer, limits);
    }

    /// Accepted (post-import-policy) prefixes held from `peer`: ipv4, ipv6,
    /// l2vpn-evpn.
    pub fn accepted_prefixes(&self, peer: IpAddr) -> [u32; 3] {
        let len = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        let total = len(self.adj_rib_in.get(&peer).map_or(0, HashMap::len));
        let v6 = self.v6_counts.get(&peer).copied().unwrap_or(0);
        let evpn = len(self.evpn_adj_rib_in.get(&peer).map_or(0, HashMap::len));
        [total - v6, v6, evpn]
    }

    /// RFC 4486 §4: the first address family whose accepted-prefix count from
    /// `peer` is over a hard (not `warning_only`) limit, with that count —
    /// the caller closes the session. Logs `maximum prefix limit exceeded`
    /// once per crossing for every family over its limit, hard or not.
    pub fn check_max_prefix(
        &mut self,
        peer: IpAddr,
    ) -> Option<(AddressFamily, nos_proto::BgpPrefixLimit, u32)> {
        let limits = *self.max_prefix.get(&peer)?;
        let counts = self.accepted_prefixes(peer);
        let mut tripped = None;
        for (family, count) in AddressFamily::ALL.into_iter().zip(counts) {
            let Some(limit) = limits.get(family) else {
                continue;
            };
            if count <= limit.limit {
                self.max_prefix_warned.remove(&(peer, family));
                continue;
            }
            if self.max_prefix_warned.insert((peer, family)) {
                warn!(
                    peer = %peer, family = %family, count, limit = limit.limit,
                    warning_only = limit.warning_only,
                    "maximum prefix limit exceeded"
                );
            }
            if !limit.warning_only && tripped.is_none() {
                tripped = Some((family, limit, count));
            }
        }
        tripped
    }

    /// Installs a fresh IGP cost table (see `igp_client`) and, if it changed
    /// (or this is the first table ever fetched, which turns the feasibility
    /// check on), re-decides every prefix — an IGP change is not a BGP event,
    /// so nothing else would trigger it. Every Adj-RIB-In prefix is
    /// re-decided, not only the Loc-RIB: a candidate excluded as unfeasible
    /// isn't in the Loc-RIB, and a new IGP route is exactly what admits it.
    pub fn set_igp(&mut self, igp: HashMap<IpNet, u32>) {
        let first = !self.igp_ready;
        self.igp_ready = true;
        if !first && igp == self.igp {
            return;
        }
        self.igp = igp;
        tracing::info!(costs = ?self.igp, "igp costs updated");
        let prefixes: HashSet<IpNet> = self
            .loc_rib
            .keys()
            .chain(self.adj_rib_in.values().flat_map(HashMap::keys))
            .copied()
            .collect();
        for prefix in prefixes {
            self.recompute_and_propagate(prefix);
        }
    }

    /// RFC 4271 §9.1.2: a candidate is feasible if it has no next hop of its
    /// own (a locally-redistributed route), if no IGP table has been fetched
    /// yet (startup), or if some route in that table covers its next hop —
    /// which includes `nos-ribd`'s `Connected` routes, so a directly
    /// connected next hop resolves. No link-local exception is needed:
    /// `RibRoute.next_hop` can never be a link-local address, because
    /// `message::decode_mp_reach` keeps only the global half of an RFC 2545
    /// next-hop field (see `message.rs`'s
    /// `mp_reach_accepts_global_plus_link_local_next_hop` test) and the
    /// legacy `NEXT_HOP` attribute is IPv4 — revisit this if that parsing
    /// ever changes.
    fn next_hop_feasible(&self, next_hop: Option<IpAddr>) -> bool {
        match next_hop {
            None => true,
            Some(addr) => !self.igp_ready || igp_lookup(&self.igp, addr).is_some(),
        }
    }

    /// Decays penalties and re-decides every prefix whose suppression ended.
    pub fn damping_tick(&mut self) {
        for (_, prefix) in self.damping.tick(Instant::now()) {
            self.recompute_and_propagate(prefix);
        }
    }

    /// Expires old EVPN MAC-mobility move history and lifts any freeze whose
    /// window has passed quietly — see `mac_mobility`.
    pub fn mac_mobility_tick(&mut self) {
        self.mac_mobility.tick(Instant::now());
    }

    pub fn peer_disconnected(&mut self, peer: IpAddr) {
        self.peer_outboxes.remove(&peer);
        self.v6_counts.remove(&peer);
        self.max_prefix_warned.retain(|(p, _)| *p != peer);
        // ponytail: a session reset forgets its flap history (RFC 2439 allows
        // keeping it); keep entries across resets to damp session flaps too.
        self.damping.clear_peer(peer);
        self.stale.remove(&peer);
        self.adj_rib_out.remove(&peer);
        self.evpn_adj_rib_out.remove(&peer);
        self.rs_sent.retain(|(p, _), _| *p != peer);
        self.rs_next_id.retain(|(p, _), _| *p != peer);
        if let Some(routes) = self.evpn_adj_rib_in.remove(&peer) {
            // mac_mobility's record of this route's (vni, mac) is
            // deliberately left alone (see its own doc comment): a future
            // re-learn, local or remote, still needs to outrank it.
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
        let peer_as = self.peer_asns.get(&from).copied().unwrap_or(0);
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

        // RFC 7313: any prefix the peer mentions again is no longer stale.
        if let Some(stale) = self.stale.get_mut(&from) {
            for p in &update.nlri {
                stale.remove(&IpNet::V4(*p));
            }
            for p in &update.withdrawn_routes {
                stale.remove(&IpNet::V4(*p));
            }
            for mp in &update.mp_reach {
                for p in &mp.nlri {
                    stale.remove(p);
                }
            }
            for mp in &update.mp_unreach {
                for p in &mp.withdrawn {
                    stale.remove(p);
                }
            }
        }

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
            // mac_mobility's record of this route's (vni, mac) is
            // deliberately left alone here too — see peer_disconnected.
            let removed = self
                .evpn_adj_rib_in
                .get_mut(&from)
                .is_some_and(|t| t.remove(nlri).is_some());
            if removed {
                info!(peer = %from, route_type = nlri.route_type(), route = %nlri, "evpn route withdrawn");
            }
        }
        if !withdrawn.is_empty() {
            let table = self.adj_rib_in.entry(from).or_default();
            let v6_count = self.v6_counts.entry(from).or_default();
            for prefix in &withdrawn {
                if table.remove(prefix).is_some() {
                    if prefix.addr().is_ipv6() {
                        *v6_count -= 1;
                    }
                    touched.insert(*prefix);
                    self.damping
                        .flap(from, *prefix, WITHDRAW_PENALTY, Instant::now());
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
            let from_confed = self.confed_peers.contains(&from);
            // RFC 5065 §5.3 / RFC 7606 §7.2: confederation segments only ever
            // come from inside our own confederation.
            let stray_confed = attrs.as_path.has_confed()
                && (self.confed_id.is_none() || !(remote_is_ibgp || from_confed));
            // RFC 5065 §5.1: our confederation identifier (or AS) in a plain
            // segment, or our member AS in a confederation segment.
            let looped = attrs
                .as_path
                .contains(self.confed_id.unwrap_or(self.local_asn))
                || (self.confed_id.is_some() && attrs.as_path.contains_confed(self.local_asn));
            if stray_confed {
                warn!(
                    peer = %from, as_path = ?attrs.as_path,
                    "treating bgp update as withdraw: as_path has confederation segments from outside the confederation"
                );
                self.withdraw_announced(from, update, &mut touched);
            } else if looped {
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
                let mut evpn_recheck: Vec<(u32, [u8; 6])> = Vec::new();
                let table = self.adj_rib_in.entry(from).or_default();
                let v6_count = self.v6_counts.entry(from).or_default();
                // This UPDATE adds at most this many entries — reserving
                // once lets the per-peer table grow in fewer, larger steps
                // on the way up to a full table, instead of rehashing on
                // every insert-triggered doubling.
                table.reserve(
                    update.nlri.len() + update.mp_reach.iter().map(|m| m.nlri.len()).sum::<usize>(),
                );
                // RFC 8097 §2: always stripped; honoured only from an
                // opted-in iBGP peer (`rpki_state_peers` holds no other).
                let mut extended_communities = attrs.extended_communities.clone();
                let mut received_ov = None;
                extended_communities.retain(|&c| {
                    let ov = crate::rpki::community::is_ov(c);
                    if ov && received_ov.is_none() {
                        received_ov = crate::rpki::community::decode(c);
                    }
                    !ov
                });
                let received_ov = received_ov.filter(|_| self.rpki_state_peers.contains(&from));
                let base_route = RibRoute {
                    origin: RouteOrigin::Peer(from),
                    as_path: Arc::new(attrs.as_path.clone()),
                    bgp_origin: attrs.origin,
                    local_pref: attrs.local_pref.unwrap_or(DEFAULT_LOCAL_PREF),
                    med: attrs.med,
                    learned_via_ibgp: remote_is_ibgp,
                    learned_via_confed: from_confed,
                    router_id: Some(remote_bgp_id),
                    next_hop: None,
                    received_at: Instant::now(),
                    originator_id: attrs.originator_id,
                    cluster_list: attrs.cluster_list.clone().into(),
                    communities: attrs.communities.clone(),
                    extended_communities,
                    large_communities: attrs.large_communities.clone(),
                    atomic_aggregate: attrs.atomic_aggregate,
                    aggregator: attrs.aggregator,
                    validation_state: nos_rpl::ValidationState::NotFound,
                    received_ov,
                };
                let origin_as = crate::rpki::origin_as(
                    &attrs.as_path,
                    self.confed_id.unwrap_or(self.local_asn),
                );
                for prefix in &update.nlri {
                    let candidate = RibRoute {
                        next_hop: Some(IpAddr::V4(attrs.next_hop)),
                        validation_state: ov_state(
                            &self.vrps,
                            IpNet::V4(*prefix),
                            origin_as,
                            received_ov,
                        ),
                        ..base_route.clone()
                    };
                    learn_prefix(
                        table,
                        v6_count,
                        &mut self.damping,
                        &mut touched,
                        (from, peer_as),
                        IpNet::V4(*prefix),
                        candidate,
                        import_policy,
                    );
                }
                for mp in &update.mp_reach {
                    for prefix in &mp.nlri {
                        let candidate = RibRoute {
                            next_hop: Some(mp.next_hop),
                            validation_state: ov_state(&self.vrps, *prefix, origin_as, received_ov),
                            ..base_route.clone()
                        };
                        learn_prefix(
                            table,
                            v6_count,
                            &mut self.damping,
                            &mut touched,
                            (from, peer_as),
                            *prefix,
                            candidate,
                            import_policy,
                        );
                    }
                    if !mp.evpn.is_empty() {
                        learn_evpn(
                            self.evpn_adj_rib_in.entry(from).or_default(),
                            &mut self.mac_mobility,
                            from,
                            mp,
                            &attrs.extended_communities,
                            attrs.pmsi,
                        );
                        evpn_recheck.extend(mp.evpn.iter().filter_map(evpn_mac_key));
                    }
                }
                for (vni, mac) in evpn_recheck {
                    self.mac_mobility_recheck(vni, mac);
                }
            }
        }

        for prefix in touched {
            self.recompute_and_propagate(prefix);
        }
    }

    /// RFC 7606 treat-as-withdraw, decided here rather than in the codec
    /// because it depends on the peer: every route `update` announces is
    /// removed from `from`'s Adj-RIB-In.
    fn withdraw_announced(
        &mut self,
        from: IpAddr,
        update: &UpdateMessage,
        touched: &mut HashSet<IpNet>,
    ) {
        let announced = update
            .nlri
            .iter()
            .copied()
            .map(IpNet::V4)
            .chain(update.mp_reach.iter().flat_map(|m| m.nlri.iter().copied()));
        if let Some(table) = self.adj_rib_in.get_mut(&from) {
            for prefix in announced {
                if table.remove(&prefix).is_some() {
                    if prefix.addr().is_ipv6() {
                        *self.v6_counts.entry(from).or_default() -= 1;
                    }
                    touched.insert(prefix);
                }
            }
        }
        if let Some(table) = self.evpn_adj_rib_in.get_mut(&from) {
            for nlri in update.mp_reach.iter().flat_map(|m| &m.evpn) {
                if table.remove(nlri).is_some() {
                    info!(peer = %from, route_type = nlri.route_type(), route = %nlri, "evpn route withdrawn");
                }
            }
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
            let route = RibRoute {
                validation_state: self.validate(prefix, &AsPath::default()),
                ..redistributed_route()
            };
            apply_policy(prefix, route, &self.redistribute_policy, None)
        } else {
            None
        };
        // Keep the existing `received_at`: it is part of `RibRoute`'s
        // `PartialEq`, and a fresh `Instant::now()` would make every
        // periodic `set_redistribute_policy` look like a change and
        // re-announce the prefix to every peer (#134).
        let new = new.map(|n| match self.redistributed.get(&prefix) {
            Some(o) => RibRoute {
                received_at: o.received_at,
                ..n
            },
            None => n,
        });
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
            if self.damping.is_suppressed(*peer, &prefix) {
                continue;
            }
            if let Some(route) = table.get(&prefix) {
                candidates.push((route.clone(), Some(*peer)));
            }
        }
        // RFC 4271 §9.1.2: an unresolvable next hop is unfeasible — out of
        // the decision process (and the backup pick below) entirely.
        candidates.retain(|(route, peer)| {
            let feasible = self.next_hop_feasible(route.next_hop);
            if !feasible {
                debug!(peer = ?peer, %prefix, next_hop = ?route.next_hop, "bgp: candidate excluded, next hop unresolvable");
            }
            feasible
        });

        let best = best_path(&candidates, &self.igp);
        match best
            .as_ref()
            .and_then(|b| runner_up_next_hop(&candidates, b, &self.igp))
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
            info!(origin = ?route.origin, as_path = ?route.as_path, communities = ?route.communities, med = ?route.med, next_hop = ?route.next_hop, "bgp: loc-rib best path for {prefix} updated");
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
    ///
    /// Deliberately *not* filtered by `next_hop_feasible`: RFC 7947 §2.2.2
    /// transparency means a client sees every other client's path as
    /// submitted, and whether *this* instance can resolve a next hop says
    /// nothing about whether the client can.
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
                if *src == peer || self.damping.is_suppressed(*src, &prefix) {
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
        as_path: Arc::default(),
        bgp_origin: message::Origin::Igp,
        local_pref: DEFAULT_LOCAL_PREF,
        med: None,
        learned_via_ibgp: false,
        learned_via_confed: false,
        router_id: None,
        next_hop: None,
        received_at: Instant::now(),
        originator_id: None,
        atomic_aggregate: false,
        aggregator: None,
        cluster_list: Vec::new().into(),
        communities: Vec::new(),
        extended_communities: Vec::new(),
        large_communities: Vec::new(),
        validation_state: nos_rpl::ValidationState::NotFound,
        received_ov: None,
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
    route.as_path.neighbor_as()
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

/// Decision step 6 rank, higher wins: external 2, confederation-external 1,
/// internal 0.
fn peer_rank(route: &RibRoute) -> u8 {
    if route.learned_via_ibgp {
        0
    } else if route.learned_via_confed {
        1
    } else {
        2
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
    igp: &HashMap<IpNet, u32>,
) -> Option<IpAddr> {
    if candidates.len() < 2 {
        return None;
    }
    let others: Vec<(RibRoute, Option<IpAddr>)> = candidates
        .iter()
        .filter(|(r, _)| r.next_hop.is_some() && r.next_hop != best.next_hop)
        .cloned()
        .collect();
    best_path(&others, igp)?.next_hop
}

/// Cost of the longest `igp` prefix covering `addr`, `None` if nothing does.
fn igp_lookup(igp: &HashMap<IpNet, u32>, addr: IpAddr) -> Option<u32> {
    if igp.is_empty() {
        return None;
    }
    let max = if addr.is_ipv4() { 32 } else { 128 };
    (0..=max)
        .rev()
        .find_map(|len| igp.get(&IpNet::new(addr, len).ok()?.trunc()))
        .copied()
}

/// Cost of the longest `igp` prefix covering `next_hop`; 0 when there is no
/// next hop (a local route) or nothing covers it (only reachable before the
/// first IGP poll — afterwards such a candidate is unfeasible, see
/// `BgpRib::next_hop_feasible`).
fn igp_cost(igp: &HashMap<IpNet, u32>, next_hop: Option<IpAddr>) -> u32 {
    next_hop.and_then(|addr| igp_lookup(igp, addr)).unwrap_or(0)
}

/// The full RFC 4271 §9.1.2.2 decision process — see the module doc
/// comment for the ten-step order. `candidates` is `(route, source_peer)`
/// — `source_peer` is `None` for a locally-redistributed route, used only
/// for the final tiebreak (step 10).
fn best_path(
    candidates: &[(RibRoute, Option<IpAddr>)],
    igp: &HashMap<IpNet, u32>,
) -> Option<RibRoute> {
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
                .then_with(|| b.as_path.selection_len().cmp(&a.as_path.selection_len())) // step 3
                .then_with(|| origin_rank(b.bgp_origin).cmp(&origin_rank(a.bgp_origin))) // step 4
                .then_with(|| compare_med(a, b)) // step 5
                // Step 6: eBGP beats confederation-eBGP beats iBGP (RFC 5065 §5.3).
                .then_with(|| peer_rank(a).cmp(&peer_rank(b)))
                // Step 7: lower IGP cost to the next hop wins (evaluated
                // lazily — only reached when steps 1-6 tie).
                .then_with(|| igp_cost(igp, b.next_hop).cmp(&igp_cost(igp, a.next_hop)))
                .then_with(|| {
                    // Step 8: oldest route wins, only between two
                    // eBGP-learned candidates (RFC 4271's anti-flap rule).
                    if peer_rank(a) == 2 && peer_rank(b) == 2 {
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
    let mut adjusted = best.clone();
    // RFC 4271 §5.1.4: a MED received from a neighbouring AS is never
    // passed on to another AS. It is cleared before the export policy runs,
    // so a MED the policy sets (or a locally originated one) is still sent.
    // RFC 7947 §2.2: a route server passes MED through unchanged to its clients.
    // RFC 5065 §5.3: kept within the confederation too.
    if !outbox.is_ibgp
        && !outbox.is_confed
        && !outbox.is_rs_client
        && matches!(best.origin, RouteOrigin::Peer(_))
    {
        adjusted.med = None;
    }
    let verdict = nos_rpl::vm::run(
        &outbox.export_policy,
        &to_policy_input(prefix, &adjusted, Some((peer, outbox.remote_asn))),
    );
    let nh_edit = apply_verdict(&mut adjusted, verdict)?;
    // RFC 4360 §6: non-transitive extended communities (type bit 0x40)
    // don't leave the AS (kept across a confederation, like MED).
    if !outbox.is_ibgp && !outbox.is_confed {
        adjusted.extended_communities.retain(|c| c >> 62 & 1 == 0);
    }
    // RFC 8097 §2: at most one, regenerated from our own state.
    adjusted
        .extended_communities
        .retain(|&c| !crate::rpki::community::is_ov(c));
    if outbox.is_ibgp && outbox.announce_rpki_state {
        adjusted
            .extended_communities
            .push(crate::rpki::community::encode(adjusted.validation_state));
    }
    let best = adjusted;
    let best = &best;

    // RFC 7947 §2.2.1: a route server passes NEXT_HOP through unchanged, so
    // a route-server client defaults to `Unchanged` like an iBGP peer. An
    // explicit `next-hop self` still wins.
    let mode = outbox.next_hop_mode.unwrap_or(
        if outbox.is_ibgp || outbox.is_confed || outbox.is_rs_client {
            NextHopMode::Unchanged
        } else {
            NextHopMode::SelfAddress
        },
    );
    let next_hop = match (nh_edit, mode) {
        (nos_rpl::NextHopSet::Addr(a), _) => a,
        (nos_rpl::NextHopSet::SelfAddress, _) | (_, NextHopMode::SelfAddress) => {
            outbox.local_addr?
        }
        (nos_rpl::NextHopSet::Unchanged, NextHopMode::Unchanged) => {
            best.next_hop.or(outbox.local_addr)?
        }
    };

    // `as_path` is only replaced (never mutated in place) by an RPL
    // `prepend`, so when the script didn't touch it it's still shared with whatever's stored in loc_rib/adj_rib_in at this
    // point — `Arc::clone` is a refcount bump, not a deep copy. The one
    // real content copy this function can't avoid is the eBGP prepend
    // case, where the result genuinely differs per destination peer;
    // `Arc::make_mut` does that copy directly into an owned buffer instead
    // of cloning twice (once wastefully inside `adjusted = best.clone()`
    // above, once again here) like the pre-Arc version of this code did.
    let mut as_path = Arc::clone(&best.as_path);
    if outbox.is_confed {
        // RFC 5065 §4.1: our member AS, in an AS_CONFED_SEQUENCE.
        Arc::make_mut(&mut as_path).prepend_confed_seq(local_asn);
    } else if !outbox.is_ibgp {
        // RFC 5065 §4.1: outside the confederation, its segments go and
        // only the identifier is prepended.
        if as_path.has_confed() {
            Arc::make_mut(&mut as_path).strip_confed();
        }
        // RFC 7947 route-server clients get a fully transparent AS_PATH: no
        // local-ASN prepend, even though they're always eBGP (enforced at
        // config-validation time — see `bgp_instance::valid_route_reflection_and_server`).
        if !outbox.is_rs_client {
            Arc::make_mut(&mut as_path).prepend_seq(outbox.confed_id.unwrap_or(local_asn));
        }
    }
    let as_path: AsPath = Arc::try_unwrap(as_path).unwrap_or_else(|arc| (*arc).clone());
    let local_pref = (outbox.is_ibgp || outbox.is_confed).then_some(best.local_pref);
    let med = best.med;

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
        atomic_aggregate: best.atomic_aggregate,
        aggregator: best.aggregator,
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
                as_path: as_path.into(),
                next_hop: v4(next_hop),
                local_pref: None,
                med: None,
                originator_id: None,
                atomic_aggregate: false,
                aggregator: None,
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
        // The stored RT plus a freshly attached RFC 7432 §7.7 MAC Mobility
        // community (sequence 0, not sticky — see `with_local_mobility`).
        assert_eq!(
            adv.extended_communities,
            vec![0x0002_fde8_0000_2774, 0x0600_0000_0000_0000]
        );
        assert!(recv_all(&mut plain_rx).is_empty(), "EVPN not negotiated");

        // An identical re-push is not re-announced.
        rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(mac_route(1)));
        assert_eq!(recv_all(&mut evpn_rx), []);

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
        assert_eq!(recv_all(&mut observer_rx), []);

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
        assert_eq!(rib.evpn_routes(), []);
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
        assert_eq!(rib.evpn_routes(), []);
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

        assert_eq!(recv_all(&mut observer_rx), []);
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
    fn atomic_aggregate_and_aggregator_survive_transit() {
        let mut rib = new_rib(65000);
        let source = addr("10.0.0.1");
        let observer = addr("10.0.0.2");
        let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
        let mut observer_rx = register_peer(&mut rib, observer, false, addr("10.0.0.253"));

        let agg = message::Aggregator {
            asn: 4_200_000_001,
            router_id: v4("192.0.2.9"),
        };
        let mut update = ebgp_update(vec!["1.2.3.0/24"], vec![], "10.0.0.1");
        let attrs = update.attributes.as_mut().unwrap();
        attrs.atomic_aggregate = true;
        attrs.aggregator = Some(agg);
        rib.handle_update(
            source,
            false,
            v4("192.0.2.1"),
            &update,
            &nos_rpl::ACCEPT_ALL,
        );

        let adv = recv_all(&mut observer_rx)
            .into_iter()
            .find_map(|u| match u {
                OutboundUpdate::Announce(a) if a.prefix == prefix("1.2.3.0/24") => Some(a),
                _ => None,
            })
            .expect("expected an announcement for 1.2.3.0/24");
        assert!(adv.atomic_aggregate);
        assert_eq!(adv.aggregator, Some(agg));
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
        assert_eq!(find_adv(&mut stripped_rx).communities, [] as [u32; 0]);
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
    fn export_policy_prepend_lands_behind_our_own_asn() {
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
                    "this.bgp.as_path.prepend(64999, 2)\naccept\n",
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
        assert_eq!(adv.as_path, vec![65001, 64999, 64999]);
    }

    /// RFC 5065: member AS 65101 of confederation 65100.
    fn confed_rib() -> BgpRib {
        let mut rib = new_rib(65101);
        rib.set_confederation(Some(65100));
        rib
    }

    fn register_confed_peer(
        rib: &mut BgpRib,
        peer: IpAddr,
    ) -> mpsc::UnboundedReceiver<OutboundUpdate> {
        rib.set_peer_confed(peer, true);
        register_peer(rib, peer, false, addr("10.0.0.254"))
    }

    fn confed_update(nlri: &str, confed: &[u32], seq: &[u32], next_hop: &str) -> UpdateMessage {
        let mut u = ebgp_update(vec![nlri], seq.to_vec(), next_hop);
        let path = &mut u.attributes.as_mut().unwrap().as_path;
        for &asn in confed.iter().rev() {
            path.prepend_confed_seq(asn);
        }
        u
    }

    fn announced(
        rx: &mut mpsc::UnboundedReceiver<OutboundUpdate>,
        p: &str,
    ) -> Option<AdvertisedRoute> {
        recv_all(rx).into_iter().find_map(|u| match u {
            OutboundUpdate::Announce(a) if a.prefix == prefix(p) => Some(a),
            _ => None,
        })
    }

    #[test]
    fn confed_send_rules_per_peer_kind() {
        let mut rib = confed_rib();
        let mut confed = register_confed_peer(&mut rib, addr("10.0.0.2"));
        let mut external = register_peer(&mut rib, addr("10.0.0.3"), false, addr("10.0.0.254"));
        let mut internal = register_peer(&mut rib, addr("10.0.0.4"), true, addr("10.0.0.254"));
        let mut u = ebgp_update(vec!["198.51.100.0/24"], vec![65003], "192.0.2.5");
        u.attributes.as_mut().unwrap().med = Some(50);
        rib.handle_update(
            addr("10.0.0.5"),
            false,
            v4("5.5.5.5"),
            &u,
            &accept_all_policy(),
        );

        let c = announced(&mut confed, "198.51.100.0/24").unwrap();
        assert_eq!(format!("{:?}", c.as_path), "[(65101), 65003]");
        assert_eq!(c.next_hop, addr("192.0.2.5"), "next hop kept");
        assert_eq!((c.med, c.local_pref), (Some(50), Some(DEFAULT_LOCAL_PREF)));

        let e = announced(&mut external, "198.51.100.0/24").unwrap();
        assert_eq!(e.as_path, vec![65100, 65003], "identifier only");
        assert_eq!(
            (e.next_hop, e.med, e.local_pref),
            (addr("10.0.0.254"), None, None)
        );

        let i = announced(&mut internal, "198.51.100.0/24").unwrap();
        assert_eq!(i.as_path, vec![65003]);

        // A route from the confed peer: stripped toward the external peer,
        // and sent to the internal one (it is not an iBGP-learned route).
        let u = confed_update("198.51.101.0/24", &[65102], &[65004], "192.0.2.2");
        rib.handle_update(
            addr("10.0.0.2"),
            false,
            v4("2.2.2.2"),
            &u,
            &accept_all_policy(),
        );
        let e = announced(&mut external, "198.51.101.0/24").unwrap();
        assert_eq!(e.as_path, vec![65100, 65004]);
        let i = announced(&mut internal, "198.51.101.0/24").unwrap();
        assert_eq!(format!("{:?}", i.as_path), "[(65102), 65004]");
    }

    #[test]
    fn confed_segments_from_outside_the_confederation_are_withdrawn() {
        for mut rib in [confed_rib(), new_rib(65101)] {
            let from = addr("10.0.0.3");
            let u = ebgp_update(vec!["198.51.100.0/24"], vec![65003], "192.0.2.3");
            rib.handle_update(from, false, v4("3.3.3.3"), &u, &accept_all_policy());
            assert!(rib.loc_rib.contains_key(&prefix("198.51.100.0/24")));
            let bad = confed_update("198.51.100.0/24", &[65109], &[65003], "192.0.2.3");
            rib.handle_update(from, false, v4("3.3.3.3"), &bad, &accept_all_policy());
            assert!(!rib.loc_rib.contains_key(&prefix("198.51.100.0/24")));
        }
    }

    #[test]
    fn confed_loop_detection() {
        let mut rib = confed_rib();
        // The identifier in a plain segment, from an external peer.
        let u = ebgp_update(vec!["198.51.100.0/24"], vec![65003, 65100], "192.0.2.3");
        rib.handle_update(
            addr("10.0.0.3"),
            false,
            v4("3.3.3.3"),
            &u,
            &accept_all_policy(),
        );
        // Our member AS in a confed segment, from a confed peer.
        rib.set_peer_confed(addr("10.0.0.2"), true);
        let u = confed_update("198.51.101.0/24", &[65102, 65101], &[65003], "192.0.2.2");
        rib.handle_update(
            addr("10.0.0.2"),
            false,
            v4("2.2.2.2"),
            &u,
            &accept_all_policy(),
        );
        assert!(rib.loc_rib.is_empty());
        // Our member AS in a plain segment is someone else's AS, not a loop.
        let u = ebgp_update(vec!["198.51.102.0/24"], vec![65003, 65101], "192.0.2.3");
        rib.handle_update(
            addr("10.0.0.3"),
            false,
            v4("3.3.3.3"),
            &u,
            &accept_all_policy(),
        );
        assert_eq!(rib.loc_rib.len(), 1);
    }

    #[test]
    fn confed_step_six_external_then_confed_then_internal() {
        let mut rib = confed_rib();
        rib.set_peer_confed(addr("10.0.0.2"), true);
        let p = "198.51.100.0/24";
        // Same length once confed segments are ignored, same neighbour AS.
        let internal = ebgp_update(vec![p], vec![65003], "192.0.2.4");
        let confed = confed_update(p, &[65102], &[65003], "192.0.2.2");
        let external = ebgp_update(vec![p], vec![65003], "192.0.2.3");
        rib.handle_update(
            addr("10.0.0.4"),
            true,
            v4("4.4.4.4"),
            &internal,
            &accept_all_policy(),
        );
        rib.handle_update(
            addr("10.0.0.2"),
            false,
            v4("2.2.2.2"),
            &confed,
            &accept_all_policy(),
        );
        rib.handle_update(
            addr("10.0.0.3"),
            false,
            v4("3.3.3.3"),
            &external,
            &accept_all_policy(),
        );
        let best = |rib: &BgpRib| rib.loc_rib[&prefix(p)].origin;
        assert_eq!(best(&rib), RouteOrigin::Peer(addr("10.0.0.3")));
        rib.peer_disconnected(addr("10.0.0.3"));
        assert_eq!(best(&rib), RouteOrigin::Peer(addr("10.0.0.2")));
    }

    #[test]
    fn as_set_counts_as_one_hop() {
        let mut rib = new_rib(65001);
        let p = "198.51.100.0/24";
        let mut set = ebgp_update(vec![p], vec![65003], "192.0.2.2");
        let path = &mut set.attributes.as_mut().unwrap().as_path;
        let mut with_set = AsPath::from(vec![65003]);
        with_set.push_segment(crate::as_path::SegKind::Set, &[1, 2, 3]);
        *path = with_set;
        let seq = ebgp_update(vec![p], vec![65004, 65005, 65006], "192.0.2.3");
        rib.handle_update(
            addr("10.0.0.2"),
            false,
            v4("2.2.2.2"),
            &set,
            &accept_all_policy(),
        );
        rib.handle_update(
            addr("10.0.0.3"),
            false,
            v4("3.3.3.3"),
            &seq,
            &accept_all_policy(),
        );
        assert_eq!(
            rib.loc_rib[&prefix(p)].origin,
            RouteOrigin::Peer(addr("10.0.0.2"))
        );
    }

    #[test]
    fn rpl_prepend_on_a_confed_path_joins_the_sequence() {
        let mut rib = confed_rib();
        let (tx, mut rx) = mpsc::unbounded_channel();
        rib.peer_established(
            addr("10.0.0.4"),
            true,
            Some(addr("10.0.0.254")),
            all_afs(),
            false,
            None,
            false,
            false,
            HashSet::new(),
            Arc::new(
                nos_rpl::compile(
                    "this.bgp.as_path.prepend(64999, 2)\naccept\n",
                    &nos_rpl::Symbols::EMPTY,
                )
                .unwrap(),
            ),
            tx,
        );
        rib.set_peer_confed(addr("10.0.0.2"), true);
        let u = confed_update("198.51.100.0/24", &[65102], &[65003], "192.0.2.2");
        rib.handle_update(
            addr("10.0.0.2"),
            false,
            v4("2.2.2.2"),
            &u,
            &accept_all_policy(),
        );
        let adv = announced(&mut rx, "198.51.100.0/24").unwrap();
        assert_eq!(
            format!("{:?}", adv.as_path),
            "[64999, 64999, (65102), 65003]"
        );
    }

    #[test]
    fn import_policy_matches_peer_as_and_adds_to_local_pref() {
        let mut rib = new_rib(65000);
        let source = addr("10.0.0.1");
        let observer = addr("10.0.0.2");
        let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
        let mut observer_rx = register_peer(&mut rib, observer, true, addr("10.0.0.253"));
        rib.set_peer_asn(source, 65099);

        let policy = nos_rpl::compile(
            "if this.bgp.peer_as == 65099:\n    set this.bgp.local_pref += 400\n    accept\nelse:\n    reject\n",
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

        let adv = recv_all(&mut observer_rx)
            .into_iter()
            .find_map(|u| match u {
                OutboundUpdate::Announce(a) if a.prefix == prefix("1.2.3.0/24") => Some(a),
                _ => None,
            })
            .expect("expected an announcement for 1.2.3.0/24");
        assert_eq!(adv.local_pref, Some(500));
    }

    #[test]
    fn export_policy_can_set_next_hop_and_origin() {
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
                    "set this.bgp.next_hop = 192.0.2.99\nset this.bgp.origin = origin.incomplete\naccept\n",
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
        assert_eq!(adv.next_hop, addr("192.0.2.99"));
        assert_eq!(adv.origin, message::Origin::Incomplete);
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

        assert_ne!(recv_all(&mut allowed_rx), []);
        assert_eq!(recv_all(&mut blocked_rx), []);
    }

    /// Sends one route with MED 999 from eBGP `source` and returns what
    /// `dest` (eBGP or iBGP, with `export`) is sent for it.
    fn med_toward(dest_is_ibgp: bool, export: &str) -> Option<u32> {
        let mut rib = new_rib(65000);
        let source = addr("10.0.0.1");
        let dest = addr("10.0.0.2");
        let _src_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
        let (tx, mut rx) = mpsc::unbounded_channel();
        rib.peer_established(
            dest,
            dest_is_ibgp,
            Some(addr("10.0.0.253")),
            all_afs(),
            false,
            None,
            false,
            false,
            HashSet::new(),
            Arc::new(nos_rpl::compile(export, &nos_rpl::Symbols::EMPTY).unwrap()),
            tx,
        );
        rib.handle_update(
            source,
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
        recv_all(&mut rx)
            .into_iter()
            .find_map(|u| match u {
                OutboundUpdate::Announce(a) => Some(a.med),
                _ => None,
            })
            .expect("expected an announcement")
    }

    #[test]
    fn received_med_is_not_sent_to_ebgp_but_kept_toward_ibgp() {
        assert_eq!(med_toward(false, "accept\n"), None);
        assert_eq!(med_toward(true, "accept\n"), Some(999));
    }

    #[test]
    fn received_med_is_passed_through_to_route_server_client() {
        let mut rib = new_rib(65000);
        let source = addr("10.0.0.1");
        let _src_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
        let mut rs_rx = register_peer_full(
            &mut rib,
            addr("10.0.0.2"),
            false,
            addr("10.0.0.253"),
            false,
            true,
            HashSet::new(),
        );
        let mut rs_ap_rx = register_peer_full(
            &mut rib,
            addr("10.0.0.3"),
            false,
            addr("10.0.0.252"),
            false,
            true,
            HashSet::from([AddressFamily::Ipv4Unicast]),
        );
        rib.handle_update(
            source,
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
        let meds = |updates: Vec<OutboundUpdate>, add_path: bool| -> Vec<Option<u32>> {
            updates
                .into_iter()
                .filter_map(|u| match u {
                    OutboundUpdate::Announce(a) if a.path_id.is_some() == add_path => Some(a.med),
                    _ => None,
                })
                .collect()
        };
        // Single best path.
        assert_eq!(meds(recv_all(&mut rs_rx), false), vec![Some(999)]);
        // ADD-PATH per-source fan-out (propagate_rs_view).
        let ap = meds(recv_all(&mut rs_ap_rx), true);
        assert_ne!(ap, []);
        assert!(ap.iter().all(|m| *m == Some(999)));
    }

    #[test]
    fn export_policy_med_is_sent_to_ebgp() {
        assert_eq!(
            med_toward(false, "set this.bgp.med = 42\naccept\n"),
            Some(42)
        );
        // `+=` on an eBGP export starts from 0: the received MED is gone.
        assert_eq!(
            med_toward(false, "set this.bgp.med += 5\naccept\n"),
            Some(5)
        );
    }

    #[test]
    fn route_server_client_defaults_to_unchanged_next_hop() {
        let mut rib = new_rib(65000);
        let source = addr("10.0.0.1");
        let _src_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
        let mut rs_rx = register_peer_full(
            &mut rib,
            addr("10.0.0.2"),
            false,
            addr("10.0.0.253"),
            false,
            true,
            HashSet::new(),
        );
        rib.handle_update(
            source,
            false,
            v4("192.0.2.1"),
            &ebgp_update(vec!["9.9.9.0/24"], vec![65001], "10.0.0.1"),
            &nos_rpl::ACCEPT_ALL,
        );
        let next_hops: Vec<IpAddr> = recv_all(&mut rs_rx)
            .into_iter()
            .filter_map(|u| match u {
                OutboundUpdate::Announce(a) => Some(a.next_hop),
                _ => None,
            })
            .collect();
        assert_eq!(next_hops, vec![addr("10.0.0.1")]);
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
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("192.168.1.0/24"),
                as_path: vec![65000].into(),
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
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("192.168.1.0/24"),
                as_path: vec![].into(),
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

    /// Re-applying an unchanged redistribute policy (the 10s reconcile tick
    /// does it on every pass) must not re-announce anything (#134).
    #[test]
    fn reapplying_unchanged_redistribute_policy_sends_nothing() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let mut rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
        rib.set_redistribute_policy(accept_all_policy());
        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));
        assert_eq!(recv_all(&mut rx).len(), 1);

        rib.set_redistribute_policy(accept_all_policy());
        rib.set_redistribute_policy(accept_all_policy());

        assert_eq!(recv_all(&mut rx), vec![]);
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

        rib.resend_all(v4_peer, AddressFamily::Ipv4Unicast, false);
        rib.resend_all(v6_peer, AddressFamily::Ipv6Unicast, false);

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
        rib.resend_all(v4_peer, AddressFamily::Ipv6Unicast, false);
        assert_eq!(recv_all(&mut v4_rx), []);
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
        assert_eq!(recv_all(&mut source_rx), []);
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
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("1.2.3.0/24"),
                as_path: vec![65000, 65001].into(),
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

        assert_eq!(recv_all(&mut other_rx), []);
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
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("1.2.3.0/24"),
                as_path: vec![65001].into(),
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
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("1.2.3.0/24"),
                as_path: vec![65001].into(),
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
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("1.2.3.0/24"),
                as_path: vec![65000, 65001].into(),
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
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("192.168.1.0/24"),
                as_path: vec![].into(),
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

        assert_eq!(recv_all(&mut other_rx), []);
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
                    as_path: vec![].into(),
                    next_hop: v4("10.0.0.1"),
                    local_pref: Some(50),
                    med: None,
                    originator_id: None,
                    atomic_aggregate: false,
                    aggregator: None,
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
                    as_path: vec![].into(),
                    next_hop: v4("10.0.0.2"),
                    local_pref: Some(200),
                    med: None,
                    originator_id: None,
                    atomic_aggregate: false,
                    aggregator: None,
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
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("9.9.9.0/24"),
                as_path: vec![].into(),
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
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("5.5.5.0/24"),
                as_path: vec![65000].into(),
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
            OutboundUpdate::AnnounceEvpn(_)
            | OutboundUpdate::WithdrawEvpn(_)
            | OutboundUpdate::RefreshMarker { .. } => String::new(),
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

        assert_eq!(recv_all(&mut rx), []);
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
        assert_eq!(recv_all(&mut rx), []);
    }

    #[test]
    fn redistribute_remove_of_absent_prefix_is_a_no_op() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let mut rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));

        rib.apply_redistribute_update(RedistributeUpdate::Remove(prefix("10.10.10.0/24")));
        assert_eq!(recv_all(&mut rx), []);
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
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("192.168.1.0/24"),
                as_path: vec![65000].into(),
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
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("2001:db8:1::/48"),
                as_path: vec![65000].into(),
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

        assert_eq!(recv_all(&mut rx), []);
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
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("192.168.1.0/24"),
                as_path: vec![65000].into(),
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

    #[test]
    fn enhanced_refresh_purges_unrefreshed_routes_at_eorr() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
        let policy = accept_all_policy();
        for p in ["192.0.2.0/24", "198.51.100.0/24"] {
            let u = update_with(p, vec![65001], "10.0.0.1", message::Origin::Igp, None);
            rib.handle_update(peer, false, v4("1.1.1.1"), &u, &policy);
        }
        let v4f = AddressFamily::Ipv4Unicast;
        rib.begin_refresh_in(peer, v4f);
        // Only one prefix is re-announced during the refresh.
        let u = update_with(
            "192.0.2.0/24",
            vec![65001],
            "10.0.0.1",
            message::Origin::Igp,
            None,
        );
        rib.handle_update(peer, false, v4("1.1.1.1"), &u, &policy);
        rib.end_refresh_in(peer, v4f);
        assert!(rib.adj_rib_in[&peer].contains_key(&prefix("192.0.2.0/24")));
        assert!(!rib.adj_rib_in[&peer].contains_key(&prefix("198.51.100.0/24")));
    }

    #[test]
    fn enhanced_resend_is_bracketed_by_markers() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let mut rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));
        recv_all(&mut rx);
        rib.resend_all(peer, AddressFamily::Ipv4Unicast, true);
        let got = recv_all(&mut rx);
        assert!(matches!(
            got.as_slice(),
            [
                OutboundUpdate::RefreshMarker {
                    subtype: message::REFRESH_BORR,
                    ..
                },
                OutboundUpdate::Announce(_),
                OutboundUpdate::RefreshMarker {
                    subtype: message::REFRESH_EORR,
                    ..
                },
            ]
        ));
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
                as_path: as_path.into(),
                next_hop: v4(next_hop),
                local_pref: None,
                med,
                originator_id: None,
                atomic_aggregate: false,
                aggregator: None,
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
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("9.9.9.0/24"),
                as_path: vec![65001].into(),
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
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("9.9.9.0/24"),
                as_path: vec![65001].into(),
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
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("9.9.9.0/24"),
                as_path: vec![65001].into(),
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
        assert_eq!(recv_all(&mut observer_rx), []);
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
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("9.9.9.0/24"),
                as_path: vec![65000, 65001].into(),
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
    fn lower_igp_cost_to_next_hop_wins_and_follows_igp_changes() {
        let mut rib = new_rib(65000);
        // Both iBGP with equal attributes; peer_a has the lower router-id, so
        // without step (d) it would win at step 9.
        let peer_a = addr("10.0.0.1");
        let peer_b = addr("10.0.0.2");
        let _rx_a = register_peer(&mut rib, peer_a, true, addr("10.0.0.254"));
        let _rx_b = register_peer(&mut rib, peer_b, true, addr("10.0.0.253"));
        rib.set_routing_table(Some("rt1".to_string()));
        for (peer, rid, nh) in [
            (peer_a, "1.1.1.1", "10.1.0.1"),
            (peer_b, "5.5.5.5", "10.2.0.1"),
        ] {
            rib.handle_update(
                peer,
                true,
                v4(rid),
                &update_with("9.9.9.0/24", vec![65001], nh, message::Origin::Igp, None),
                &nos_rpl::ACCEPT_ALL,
            );
        }
        let best = |rib: &BgpRib| rib.push_snapshot().1[&prefix("9.9.9.0/24")].0;
        assert_eq!(best(&rib), addr("10.1.0.1"));

        let igp = |a: u32, b: u32| {
            HashMap::from([(prefix("10.1.0.0/16"), a), (prefix("10.2.0.0/16"), b)])
        };
        rib.set_igp(igp(30, 10));
        assert_eq!(best(&rib), addr("10.2.0.1"));
        rib.set_igp(igp(10, 30));
        assert_eq!(best(&rib), addr("10.1.0.1"));
        // Longest match wins: a /24 for peer_a's next hop overrides its /16.
        let mut more = igp(10, 20);
        more.insert(prefix("10.1.0.0/24"), 99);
        rib.set_igp(more);
        assert_eq!(best(&rib), addr("10.2.0.1"));
    }

    // --- RFC 4271 §9.1.2 next-hop feasibility ---

    /// One peer-learned route for `9.9.9.0/24` with next hop `10.1.0.1`.
    fn learn_one(rib: &mut BgpRib, peer: IpAddr, next_hop: &str) {
        rib.handle_update(
            peer,
            false,
            v4("5.5.5.5"),
            &update_with(
                "9.9.9.0/24",
                vec![65001],
                next_hop,
                message::Origin::Igp,
                None,
            ),
            &nos_rpl::ACCEPT_ALL,
        );
    }

    #[test]
    fn unresolved_next_hop_excluded_once_igp_ready_and_admitted_when_igp_learns_it() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
        rib.set_routing_table(Some("rt1".to_string()));
        // The IGP knows the peer's own subnet, not the advertised next hop.
        rib.set_igp(HashMap::from([(prefix("10.0.0.0/24"), 0)]));

        learn_one(&mut rib, peer, "10.1.0.1");
        assert!(
            rib.push_snapshot().1.is_empty(),
            "unfeasible route reached the loc-rib"
        );
        assert!(rib.loc_rib.is_empty());

        // An IGP route covering the next hop appears: no BGP event, but the
        // candidate must be re-decided and win.
        rib.set_igp(HashMap::from([
            (prefix("10.0.0.0/24"), 0),
            (prefix("10.1.0.0/16"), 20),
        ]));
        assert_eq!(
            rib.push_snapshot().1[&prefix("9.9.9.0/24")].0,
            addr("10.1.0.1")
        );

        // ...and disappears again: withdrawn from the loc-rib.
        rib.set_igp(HashMap::from([(prefix("10.0.0.0/24"), 0)]));
        assert!(rib.loc_rib.is_empty());
    }

    #[test]
    fn unresolved_next_hop_not_excluded_before_first_igp_poll() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
        rib.set_routing_table(Some("rt1".to_string()));

        learn_one(&mut rib, peer, "10.1.0.1");
        assert_eq!(
            rib.push_snapshot().1[&prefix("9.9.9.0/24")].0,
            addr("10.1.0.1")
        );

        // The very first poll — even an empty table — turns the check on.
        rib.set_igp(HashMap::new());
        assert!(rib.loc_rib.is_empty());
    }

    #[test]
    fn local_redistributed_route_never_filtered() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let mut rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
        rib.set_igp(HashMap::new());

        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));
        assert!(rib.loc_rib.contains_key(&prefix("192.168.1.0/24")));
        assert!(matches!(
            recv_all(&mut rx).as_slice(),
            [OutboundUpdate::Announce(_)]
        ));
    }

    #[test]
    fn route_server_client_still_sees_infeasible_path_transparently() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let rs_client = addr("10.0.0.2");
        let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
        let mut rs_rx = register_peer_full(
            &mut rib,
            rs_client,
            false,
            addr("10.0.0.253"),
            false,
            true,
            [AddressFamily::Ipv4Unicast].into_iter().collect(),
        );
        rib.set_igp(HashMap::new());

        learn_one(&mut rib, peer, "10.1.0.1");
        // Not in this instance's own loc-rib...
        assert!(rib.loc_rib.is_empty());
        // ...but the route-server client gets the path as submitted.
        let updates = recv_all(&mut rs_rx);
        assert!(
            matches!(
                updates.as_slice(),
                [OutboundUpdate::Announce(AdvertisedRoute {
                    path_id: Some(_),
                    ..
                })]
            ),
            "{updates:?}"
        );
    }

    #[test]
    fn runner_up_backup_also_requires_resolvable_next_hop() {
        let mut rib = new_rib(65000);
        let peer_a = addr("10.0.0.1");
        let peer_b = addr("10.0.0.2");
        let _rx_a = register_peer(&mut rib, peer_a, true, addr("10.0.0.254"));
        let _rx_b = register_peer(&mut rib, peer_b, true, addr("10.0.0.253"));
        rib.set_routing_table(Some("rt1".to_string()));
        // Only peer_a's next hop resolves.
        rib.set_igp(HashMap::from([(prefix("10.1.0.0/16"), 10)]));
        for (peer, nh) in [(peer_a, "10.1.0.1"), (peer_b, "10.2.0.1")] {
            rib.handle_update(
                peer,
                true,
                v4("5.5.5.5"),
                &update_with("9.9.9.0/24", vec![65001], nh, message::Origin::Igp, None),
                &nos_rpl::ACCEPT_ALL,
            );
        }
        assert_eq!(
            rib.push_snapshot().1[&prefix("9.9.9.0/24")],
            (addr("10.1.0.1"), None)
        );

        // Once peer_b's resolves too, it becomes the backup.
        rib.set_igp(HashMap::from([
            (prefix("10.1.0.0/16"), 10),
            (prefix("10.2.0.0/16"), 10),
        ]));
        assert_eq!(
            rib.push_snapshot().1[&prefix("9.9.9.0/24")],
            (addr("10.1.0.1"), Some(addr("10.2.0.1")))
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
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("9.9.9.0/24"),
                // Destination is eBGP, so our own ASN is prepended and
                // next-hop-self rewrites to the observer's own local
                // address, not either source's.
                as_path: vec![65000, 65001].into(),
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
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("9.9.9.0/24"),
                as_path: vec![65001].into(),
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
        assert_eq!(recv_all(&mut observer_rx), []);
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
                atomic_aggregate: false,
                aggregator: None,
                path_id: None,
                prefix: prefix("1.2.3.0/24"),
                as_path: vec![].into(),
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
                atomic_aggregate: false,
                aggregator: None,
                path_id: None,
                prefix: prefix("4.5.6.0/24"),
                as_path: vec![].into(),
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

        assert_eq!(recv_all(&mut observer_rx), []);
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

        assert_eq!(recv_all(&mut observer_rx), []);
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
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("192.168.1.0/24"),
                as_path: vec![65000].into(),
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
                atomic_aggregate: false,
                aggregator: None,
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                path_id: None,
                prefix: prefix("192.168.1.0/24"),
                as_path: vec![].into(), // route-server-client: transparent, no local-asn prepend
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
        assert_ne!(updates, []);
        // No path-id'd traffic at all — propagate_rs_view never runs for a
        // family this peer didn't negotiate ADD-PATH for.
        assert!(updates.iter().all(|u| match u {
            OutboundUpdate::Announce(r) => r.path_id.is_none(),
            OutboundUpdate::Withdraw(_, _, id) => id.is_none(),
            OutboundUpdate::AnnounceEvpn(_)
            | OutboundUpdate::WithdrawEvpn(_)
            | OutboundUpdate::RefreshMarker { .. } => true,
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

    #[test]
    fn flapping_route_is_suppressed_then_released_after_decay() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
        // Ceiling 1500 = suppress, so two flaps suppress; decays under 750 in ~1s.
        rib.set_peer_damping(
            peer,
            Some(BgpDamping {
                half_life: 1,
                reuse: 750,
                suppress: 1500,
                max_suppress: 1,
            }),
        );
        let p = prefix("1.2.3.0/24");
        let announce = ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1");
        let withdraw = UpdateMessage {
            withdrawn_routes: vec!["1.2.3.0/24".parse().unwrap()],
            ..empty_update()
        };
        for _ in 0..2 {
            rib.handle_update(
                peer,
                false,
                v4("192.0.2.1"),
                &announce,
                &nos_rpl::ACCEPT_ALL,
            );
            rib.handle_update(
                peer,
                false,
                v4("192.0.2.1"),
                &withdraw,
                &nos_rpl::ACCEPT_ALL,
            );
        }
        rib.handle_update(
            peer,
            false,
            v4("192.0.2.1"),
            &announce,
            &nos_rpl::ACCEPT_ALL,
        );
        assert!(rib.damping.is_suppressed(peer, &p));
        assert!(
            !rib.push_snapshot().1.contains_key(&p),
            "suppressed route in loc-rib"
        );

        std::thread::sleep(std::time::Duration::from_millis(1100));
        rib.damping_tick();
        assert!(
            rib.push_snapshot().1.contains_key(&p),
            "released route missing"
        );
    }

    #[test]
    fn identical_readvertisement_is_not_a_flap() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
        rib.set_peer_damping(
            peer,
            Some(BgpDamping {
                half_life: 900,
                reuse: 750,
                suppress: 1000,
                max_suppress: 3600,
            }),
        );
        let announce = ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1");
        for _ in 0..5 {
            rib.handle_update(
                peer,
                false,
                v4("192.0.2.1"),
                &announce,
                &nos_rpl::ACCEPT_ALL,
            );
        }
        assert!(!rib.damping.is_suppressed(peer, &prefix("1.2.3.0/24")));
        assert!(rib.push_snapshot().1.contains_key(&prefix("1.2.3.0/24")));
    }

    #[test]
    fn identical_reannouncement_is_not_repropagated() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
        let mut observer_rx = register_peer(&mut rib, addr("10.0.0.2"), false, addr("10.0.0.253"));
        let announce = ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1");
        let send = |rib: &mut BgpRib| {
            rib.handle_update(
                peer,
                false,
                v4("192.0.2.1"),
                &announce,
                &nos_rpl::ACCEPT_ALL,
            );
        };
        send(&mut rib);
        assert_eq!(recv_all(&mut observer_rx).len(), 1);
        let age = rib.loc_rib[&prefix("1.2.3.0/24")].received_at;
        send(&mut rib);
        assert_eq!(recv_all(&mut observer_rx), vec![]);
        assert_eq!(rib.loc_rib[&prefix("1.2.3.0/24")].received_at, age);
    }

    #[test]
    fn identical_reannouncement_keeps_oldest_route_tiebreak() {
        // Step 8: the older eBGP route wins; re-sending it unchanged must not
        // make it "newer" and hand the best path to the other peer (#160).
        let mut rib = new_rib(65000);
        let (old, new) = (addr("10.0.0.1"), addr("10.0.0.2"));
        let _a = register_peer(&mut rib, old, false, addr("10.0.0.254"));
        let _b = register_peer(&mut rib, new, false, addr("10.0.0.253"));
        let from_old = ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1");
        let from_new = ebgp_update(vec!["1.2.3.0/24"], vec![65002], "10.0.0.2");
        // `old` has the higher router id, so only step 8 can make it win.
        rib.handle_update(old, false, v4("192.0.2.2"), &from_old, &nos_rpl::ACCEPT_ALL);
        rib.handle_update(new, false, v4("192.0.2.1"), &from_new, &nos_rpl::ACCEPT_ALL);
        rib.handle_update(old, false, v4("192.0.2.2"), &from_old, &nos_rpl::ACCEPT_ALL);
        assert_eq!(
            rib.loc_rib[&prefix("1.2.3.0/24")].origin,
            RouteOrigin::Peer(old)
        );
    }

    /// #17: routes are validated on receipt and re-validated in place by
    /// `set_vrps`; an import policy reading the state filters invalid ones,
    /// and a state change alone is not a flap.
    #[test]
    fn rpki_validation_on_receipt_and_on_vrp_change() {
        use crate::rpki::{Vrp, VrpTable};
        use nos_rpl::ValidationState::{Invalid, NotFound, Valid};
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
        rib.set_peer_damping(peer, Some(BgpDamping::default()));
        let vrps = |asn| {
            let mut t = VrpTable::default();
            t.announce(Vrp {
                prefix: prefix("1.2.0.0/16"),
                max_len: 24,
                asn,
            });
            Arc::new(t)
        };
        let state = |rib: &BgpRib, p| rib.adj_rib_in[&peer][&prefix(p)].validation_state;
        rib.set_vrps(vrps(65001));
        let reject_invalid = nos_rpl::compile(
            "if this.bgp.validation_state == rpki.invalid:\n    reject\naccept\n",
            &nos_rpl::Symbols::EMPTY,
        )
        .unwrap();
        let update = ebgp_update(vec!["1.2.3.0/24", "9.9.9.0/24"], vec![65001], "10.0.0.1");
        rib.handle_update(peer, false, v4("192.0.2.1"), &update, &reject_invalid);
        assert_eq!(state(&rib, "1.2.3.0/24"), Valid);
        assert_eq!(state(&rib, "9.9.9.0/24"), NotFound);

        rib.set_vrps(vrps(65002));
        assert_eq!(state(&rib, "1.2.3.0/24"), Invalid, "re-validated in place");
        // The peer re-sends it (a route refresh): now rejected.
        rib.handle_update(peer, false, v4("192.0.2.1"), &update, &reject_invalid);
        assert!(!rib.adj_rib_in[&peer].contains_key(&prefix("1.2.3.0/24")));

        // Accepted again with a changed state only: no change penalty.
        rib.set_vrps(vrps(65001));
        rib.handle_update(peer, false, v4("192.0.2.1"), &update, &nos_rpl::ACCEPT_ALL);
        rib.set_vrps(vrps(65002));
        rib.handle_update(peer, false, v4("192.0.2.1"), &update, &nos_rpl::ACCEPT_ALL);
        assert_eq!(state(&rib, "1.2.3.0/24"), Invalid);
        assert!(!rib.damping.is_suppressed(peer, &prefix("1.2.3.0/24")));

        // A redistributed route is validated against our own AS.
        rib.apply_redistribute_update(full_update(vec![("1.2.4.0/24", "10.0.0.9")]));
        assert_eq!(
            rib.redistributed[&prefix("1.2.4.0/24")].validation_state,
            Invalid
        );
        rib.set_vrps(vrps(65000));
        assert_eq!(
            rib.redistributed[&prefix("1.2.4.0/24")].validation_state,
            Valid
        );
    }

    fn rpki_vrps(asn: u32) -> Arc<crate::rpki::VrpTable> {
        let mut t = crate::rpki::VrpTable::default();
        t.announce(crate::rpki::Vrp {
            prefix: prefix("1.2.0.0/16"),
            max_len: 24,
            asn,
        });
        Arc::new(t)
    }

    const RT: u64 = 0x0002_fde8_0000_0064;

    /// #162 receive side: an opted-in iBGP peer's RFC 8097 community sets
    /// the state while we have no VRPs; local data wins once we do; it is
    /// always stripped, and ignored from eBGP.
    #[test]
    fn rpki_state_community_on_receipt() {
        use crate::rpki::community::encode;
        use nos_rpl::ValidationState::{Invalid, NotFound, Valid};
        let mut rib = new_rib(65000);
        let (ibgp, ebgp) = (addr("10.0.0.1"), addr("10.0.0.3"));
        rib.set_peer_rpki_state(ibgp, true);
        let _i = register_peer(&mut rib, ibgp, true, addr("10.0.0.254"));
        let _e = register_peer(&mut rib, ebgp, false, addr("10.0.0.254"));
        let reject_invalid = nos_rpl::compile(
            "if this.bgp.validation_state == rpki.invalid:\n    reject\naccept\n",
            &nos_rpl::Symbols::EMPTY,
        )
        .unwrap();
        let tagged = |nlri, state| {
            let mut u = ebgp_update(vec![nlri], vec![65001], "10.0.0.1");
            u.attributes.as_mut().unwrap().extended_communities = vec![RT, encode(state)];
            u
        };
        let learn = |rib: &mut BgpRib, from, ibgp, u: &UpdateMessage| {
            rib.handle_update(from, ibgp, v4("192.0.2.1"), u, &reject_invalid);
        };
        learn(&mut rib, ibgp, true, &tagged("1.2.3.0/24", Invalid));
        assert!(
            !rib.adj_rib_in[&ibgp].contains_key(&prefix("1.2.3.0/24")),
            "the import policy sees the signalled state"
        );
        learn(&mut rib, ibgp, true, &tagged("1.2.4.0/24", Valid));
        let held = |rib: &BgpRib, peer, p| rib.adj_rib_in[&peer][&prefix(p)].clone();
        let r = held(&rib, ibgp, "1.2.4.0/24");
        assert_eq!(r.validation_state, Valid);
        assert_eq!(r.extended_communities, vec![RT], "stripped");

        // Local data wins, and the signalled state is back once it's gone.
        rib.set_vrps(rpki_vrps(65002));
        assert_eq!(held(&rib, ibgp, "1.2.4.0/24").validation_state, Invalid);
        rib.set_vrps(Arc::default());
        assert_eq!(held(&rib, ibgp, "1.2.4.0/24").validation_state, Valid);

        // From eBGP: ignored and stripped.
        learn(&mut rib, ebgp, false, &tagged("1.2.5.0/24", Invalid));
        let r = held(&rib, ebgp, "1.2.5.0/24");
        assert_eq!(r.validation_state, NotFound);
        assert_eq!(r.extended_communities, vec![RT]);
    }

    /// #162 send side: exactly one RFC 8097 community, regenerated from our
    /// own state, toward an opted-in iBGP peer only; non-transitive extended
    /// communities never reach eBGP.
    #[test]
    fn rpki_state_community_on_advertisement() {
        use crate::rpki::community::encode;
        use nos_rpl::ValidationState::{Invalid, Valid};
        const OPAQUE_NT: u64 = 0x4003_0000_0000_0001;
        let mut rib = new_rib(65000);
        let (src, on, off, ebgp) = (
            addr("10.0.0.1"),
            addr("10.0.0.2"),
            addr("10.0.0.3"),
            addr("10.0.0.4"),
        );
        rib.set_peer_rpki_state(on, true);
        let _s = register_peer(&mut rib, src, false, addr("10.0.0.254"));
        let mut on_rx = register_peer(&mut rib, on, true, addr("10.0.0.254"));
        let mut off_rx = register_peer(&mut rib, off, true, addr("10.0.0.254"));
        let mut ebgp_rx = register_peer(&mut rib, ebgp, false, addr("10.0.0.254"));
        rib.set_vrps(rpki_vrps(65001));
        let mut u = ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1");
        u.attributes.as_mut().unwrap().extended_communities = vec![RT, OPAQUE_NT];
        // A stale copy added after receipt, by policy, is replaced too.
        let tag_stale = nos_rpl::compile(
            "this.bgp.extended_communities.add(67:0:2)\naccept\n",
            &nos_rpl::Symbols::EMPTY,
        )
        .unwrap();
        rib.handle_update(src, false, v4("192.0.2.1"), &u, &tag_stale);
        let ext = |rx: &mut mpsc::UnboundedReceiver<OutboundUpdate>| {
            recv_all(rx)
                .into_iter()
                .filter_map(|u| match u {
                    OutboundUpdate::Announce(a) => Some(a.extended_communities),
                    _ => None,
                })
                .next_back()
                .expect("an announcement")
        };
        assert_eq!(ext(&mut on_rx), vec![RT, OPAQUE_NT, encode(Valid)]);
        assert_eq!(ext(&mut off_rx), vec![RT, OPAQUE_NT]);
        assert_eq!(ext(&mut ebgp_rx), vec![RT]);

        // A VRP change re-advertises the new state to iBGP.
        rib.set_vrps(rpki_vrps(65002));
        assert_eq!(ext(&mut on_rx), vec![RT, OPAQUE_NT, encode(Invalid)]);
    }

    fn v6_update(nlri: Vec<&str>) -> UpdateMessage {
        let mut u = ebgp_update(vec![], vec![65001], "0.0.0.0");
        u.mp_reach = vec![message::MpReachNlri {
            afi: 2,
            safi: 1,
            next_hop: addr("2001:db8::1"),
            nlri: nlri.into_iter().map(prefix).collect(),
            nlri_path_ids: vec![],
            evpn: vec![],
        }];
        u
    }

    /// What `accepted_prefixes` must always equal: a full scan.
    fn recount(rib: &BgpRib, peer: IpAddr) -> [u32; 3] {
        let table = rib.adj_rib_in.get(&peer);
        let count = |v6: bool| {
            table.map_or(0, |t| {
                u32::try_from(t.keys().filter(|p| p.addr().is_ipv6() == v6).count()).unwrap()
            })
        };
        let evpn = rib.evpn_adj_rib_in.get(&peer).map_or(0, HashMap::len);
        [count(false), count(true), u32::try_from(evpn).unwrap()]
    }

    #[test]
    fn prefix_counters_match_a_recount_through_every_mutation() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
        let accept = &nos_rpl::ACCEPT_ALL;
        let step = |rib: &mut BgpRib, u: &UpdateMessage, policy: &CompiledPolicy, want| {
            rib.handle_update(peer, false, v4("192.0.2.1"), u, policy);
            assert_eq!(rib.accepted_prefixes(peer), recount(rib, peer));
            assert_eq!(rib.accepted_prefixes(peer), want);
        };
        let v4s = ebgp_update(vec!["1.0.0.0/24", "2.0.0.0/24"], vec![65001], "10.0.0.1");
        let v6s = v6_update(vec!["2001:db8:1::/48", "2001:db8:2::/48"]);
        step(&mut rib, &v4s, accept, [2, 0, 0]);
        step(&mut rib, &v6s, accept, [2, 2, 0]);
        // Re-announcing is not a new prefix.
        step(&mut rib, &v4s, accept, [2, 2, 0]);
        step(&mut rib, &v6s, accept, [2, 2, 0]);
        let withdraw = UpdateMessage {
            withdrawn_routes: vec!["1.0.0.0/24".parse().unwrap()],
            mp_unreach: vec![message::MpUnreachNlri {
                afi: 2,
                safi: 1,
                withdrawn: vec![prefix("2001:db8:1::/48")],
                withdrawn_path_ids: vec![],
                evpn: vec![],
            }],
            ..empty_update()
        };
        step(&mut rib, &withdraw, accept, [1, 1, 0]);
        // An import policy now rejecting a held route removes it.
        step(
            &mut rib,
            &v6_update(vec!["2001:db8:2::/48"]),
            &nos_rpl::DENY_ALL,
            [1, 0, 0],
        );
        step(&mut rib, &v6s, accept, [1, 2, 0]);
        // RFC 7313: a refresh that re-announces nothing purges everything.
        rib.begin_refresh_in(peer, AddressFamily::Ipv6Unicast);
        rib.end_refresh_in(peer, AddressFamily::Ipv6Unicast);
        assert_eq!(rib.accepted_prefixes(peer), [1, 0, 0]);
        assert_eq!(rib.accepted_prefixes(peer), recount(&rib, peer));
        rib.peer_disconnected(peer);
        assert_eq!(rib.accepted_prefixes(peer), [0, 0, 0]);
    }

    #[test]
    fn maximum_prefix_families_are_independent_and_warning_only_never_trips() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
        let limit = |limit, warning_only| {
            Some(nos_proto::BgpPrefixLimit {
                limit,
                warning_only,
                restart_interval: 0,
            })
        };
        rib.set_peer_max_prefix(
            peer,
            nos_proto::BgpMaximumPrefix {
                ipv4: limit(5, false),
                ipv6: limit(1, false),
                l2vpn_evpn: None,
            },
        );
        let accept = &nos_rpl::ACCEPT_ALL;
        let three_v4 = ebgp_update(
            vec!["1.0.0.0/24", "2.0.0.0/24", "3.0.0.0/24"],
            vec![65001],
            "10.0.0.1",
        );
        rib.handle_update(peer, false, v4("192.0.2.1"), &three_v4, accept);
        assert_eq!(
            rib.check_max_prefix(peer),
            None,
            "3 v4 under v4's 5, v6's 1 unused"
        );
        rib.handle_update(
            peer,
            false,
            v4("192.0.2.1"),
            &v6_update(vec!["2001:db8:1::/48", "2001:db8:2::/48"]),
            accept,
        );
        let (family, l, count) = rib.check_max_prefix(peer).expect("v6 over its limit");
        assert_eq!((family, l.limit, count), (AddressFamily::Ipv6Unicast, 1, 2));

        rib.set_peer_max_prefix(
            peer,
            nos_proto::BgpMaximumPrefix {
                ipv4: limit(2, true),
                ipv6: limit(1, true),
                l2vpn_evpn: None,
            },
        );
        assert_eq!(rib.check_max_prefix(peer), None, "warning-only never trips");
    }
}
