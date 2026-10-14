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
//! Locking: one whole-instance `Arc<SharedRib>` (`rib/shared.rs`: a mutex plus the push generation), owned by
//! `session::SessionManager`. All methods here are synchronous `&mut self`
//! (channel sends are non-blocking) — callers lock once per call. A single
//! lock is deliberate: best-path recomputation must see a consistent
//! cross-peer view, and this NOS's route volume is not internet-table scale.
//!
//! Outbox ownership lives here (`BgpRib::peer_outboxes`), keyed by `IpAddr`,
//! rather than as a field on `collision::PeerSlot` — `BgpRib` already needs a
//! peer-keyed table for `adj_rib_in`, and `PeerSlot`'s job is strictly RFC
//! 4271 §6.8 arbitration, not routing state.

use nos_proto::BgpRole::{Customer, Peer, Provider, RouteServer, RouteServerClient};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipnet::IpNet;
use nos_proto::{AddressFamily, BgpDamping, NextHopMode, RedistributeUpdate};
use nos_rpl::CompiledPolicy;
use smallvec::SmallVec;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::as_path::AsPath;
use crate::damping::{Damping, CHANGE_PENALTY, WITHDRAW_PENALTY};
use crate::evpn::EvpnNlri;
use crate::gr::{Disconnect, PeerGr};
use crate::mac_mobility::MacMobility;
use crate::message::{self, UpdateMessage};

mod aggregate;
mod evpn_out;
mod shared;
pub use evpn_out::{feeds as evpn_feeds, AdvertisedEvpn, EvpnSource};
pub use shared::{RibGuard, SharedRib};

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

/// A Type-2 route's `(VNI, MAC)` mobility identity, plus its ESI — `None`
/// for every other EVPN route type, which RFC 7432 §15 mobility doesn't
/// apply to.
fn evpn_mac_key(nlri: &EvpnNlri) -> Option<(u32, [u8; 6], [u8; 10])> {
    match nlri {
        EvpnNlri::MacIp {
            mac, labels, esi, ..
        } => Some((labels.first().copied().unwrap_or(0), *mac, *esi)),
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
            nlri: nlri.clone(),
            next_hop: mp.next_hop,
            pmsi_vni: pmsi.map(|p| p.vni),
            extended_communities: extended_communities.to_vec(),
        };
        if let Some((vni, mac, esi)) = evpn_mac_key(nlri) {
            let (seq, sticky) = extended_communities
                .iter()
                .find_map(|c| nos_proto::evpn_id::parse_mac_mobility(*c))
                .unwrap_or((0, false));
            mac_mobility.candidate(vni, mac, mp.next_hop, esi, seq, sticky, Instant::now());
        }
        if table.insert(nlri.route_key(), route.clone()) != Some(route) {
            info!(peer = %from, route_type = nlri.route_type(), route = %nlri, next_hop = %mp.next_hop, "evpn route learned");
        }
    }
}

/// Every path one peer holds for a prefix, by RFC 7911 path id (0 on a
/// session that doesn't receive ADD-PATH). One inline entry, so a table
/// without ADD-PATH pays no extra allocation per prefix.
type Paths = SmallVec<[(u32, RibRoute); 1]>;

/// What `propagate_add_path` last sent one ADD-PATH peer for one prefix:
/// per source path (`PathKey`), the id it was sent under and the route.
type AddPathSent = HashMap<PathKey, (u32, RibRoute)>;

/// A path's identity: its origin and its received RFC 7911 path id (0
/// without ADD-PATH). A `Local` origin is 0 for the redistributed route and
/// 1 for the aggregate, which can coexist on one prefix.
type PathKey = (RouteOrigin, u32);

/// One peer's Adj-RIB-In.
type PeerTable = HashMap<IpNet, Paths>;

/// How many paths a peer holds, `[ipv4, ipv6]` — kept in step at every
/// Adj-RIB-In mutation by `put_path`/`take_path`.
type PathCounts = [u32; 2];

fn family_index(prefix: IpNet) -> usize {
    usize::from(prefix.addr().is_ipv6())
}

fn get_path(table: &PeerTable, prefix: IpNet, id: u32) -> Option<&RibRoute> {
    table
        .get(&prefix)?
        .iter()
        .find(|(i, _)| *i == id)
        .map(|(_, r)| r)
}

/// Stores path `id` of `prefix` (RFC 7911 §5: a new advertisement for the
/// same path id replaces the old one).
fn put_path(
    table: &mut PeerTable,
    counts: &mut PathCounts,
    prefix: IpNet,
    id: u32,
    route: RibRoute,
) {
    let paths = table.entry(prefix).or_default();
    if let Some((_, old)) = paths.iter_mut().find(|(i, _)| *i == id) {
        *old = route;
    } else {
        paths.push((id, route));
        counts[family_index(prefix)] += 1;
    }
}

/// Removes path `id` of `prefix`, if held — an unknown id is a no-op (RFC
/// 7911 §5).
fn take_path(
    table: &mut PeerTable,
    counts: &mut PathCounts,
    prefix: IpNet,
    id: u32,
) -> Option<RibRoute> {
    let paths = table.get_mut(&prefix)?;
    let pos = paths.iter().position(|(i, _)| *i == id)?;
    let (_, route) = paths.remove(pos);
    if paths.is_empty() {
        table.remove(&prefix);
    }
    counts[family_index(prefix)] -= 1;
    Some(route)
}

/// The path id of entry `i` of an NLRI list whose ids are index-aligned in
/// `ids` — empty without ADD-PATH, which is path id 0.
fn path_id_at(ids: &[u32], i: usize) -> u32 {
    ids.get(i).copied().unwrap_or(0)
}

/// Every `(prefix, path id)` an UPDATE withdraws, legacy and MP alike.
fn withdrawn_paths(update: &UpdateMessage) -> Vec<(IpNet, u32)> {
    let legacy = update
        .withdrawn_routes
        .iter()
        .enumerate()
        .map(|(i, p)| (IpNet::V4(*p), path_id_at(&update.withdrawn_path_ids, i)));
    let mp = update.mp_unreach.iter().flat_map(|u| {
        u.withdrawn
            .iter()
            .enumerate()
            .map(|(i, p)| (*p, path_id_at(&u.withdrawn_path_ids, i)))
    });
    legacy.chain(mp).collect()
}

/// Every `(prefix, path id)` an UPDATE announces, legacy and MP alike.
fn announced_paths(update: &UpdateMessage) -> Vec<(IpNet, u32)> {
    let legacy = update
        .nlri
        .iter()
        .enumerate()
        .map(|(i, p)| (IpNet::V4(*p), path_id_at(&update.nlri_path_ids, i)));
    let mp = update.mp_reach.iter().flat_map(|m| {
        m.nlri
            .iter()
            .enumerate()
            .map(|(i, p)| (*p, path_id_at(&m.nlri_path_ids, i)))
    });
    legacy.chain(mp).collect()
}

/// Applies one learned NLRI to a peer's Adj-RIB-In, shared by an UPDATE's
/// plain IPv4 NLRI and its RFC 4760 `MP_REACH_NLRI`, which differ only in
/// where the next-hop comes from.
///
/// A rejected prefix is *removed* rather than skipped — a policy that now
/// rejects it must not leave an earlier, now-superseded copy behind — and is
/// `touched` either way so best-path selection re-runs for it.
// ponytail: damping stays keyed by (peer, prefix), so a flap of any one
// ADD-PATH path penalises the prefix from that peer; key it by path id too
// if per-path damping is ever needed.
#[allow(clippy::too_many_arguments)]
fn learn_prefix(
    table: &mut PeerTable,
    counts: &mut PathCounts,
    damping: &mut Damping,
    touched: &mut HashSet<IpNet>,
    peer: (IpAddr, u32),
    (prefix, id): (IpNet, u32),
    candidate: RibRoute,
    import_policy: &CompiledPolicy,
) {
    let (from, _) = peer;
    match apply_policy(prefix, candidate, import_policy, Some(peer)) {
        Some(mut route) => {
            if let Some(old) = get_path(table, prefix, id) {
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
                path_id = id,
                atomic_aggregate = route.atomic_aggregate,
                aggregator = ?route.aggregator.map(|a| (a.asn, a.router_id)),
                otc = ?route.otc,
                validation_state = ?route.validation_state,
                communities = ?route.communities,
                "bgp: learned route for {prefix} into adj-rib-in"
            );
            put_path(table, counts, prefix, id, route);
        }
        None => {
            if take_path(table, counts, prefix, id).is_some() {
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
    /// The NLRI as last received; the table key is its `route_key`, so the
    /// labels and ESI live here.
    pub nlri: EvpnNlri,
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
    /// RFC 4271 §5.1.6/§5.1.7: preserved in transit, generated for an
    /// aggregate (`aggregate::build_aggregate`).
    pub atomic_aggregate: bool,
    pub aggregator: Option<message::Aggregator>,
    /// RFC 9234 Only to Customer ASN (`message::PathAttributes::otc`).
    pub otc: Option<u32>,
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
/// being withdrawn — `Some` exactly toward a peer we send ADD-PATH to for
/// that family (`PeerOutbox::add_path_tx`), `None` otherwise.
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
    /// RFC 4724 §2 End-of-RIB for one family, after a session's initial dump.
    EndOfRib(AddressFamily),
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
    /// RFC 9234 Only to Customer ASN (`message::PathAttributes::otc`).
    pub otc: Option<u32>,
    /// RFC 7911 ADD-PATH identifier — `Some` exactly toward a peer we send
    /// ADD-PATH to for this family (`BgpRib::propagate_add_path`). `None`
    /// without ADD-PATH.
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
    /// The peer-group's vendor `local-as`, external peers only
    /// (`set_peer_local_as`) — see `prepend_external`.
    local_as: Option<nos_proto::BgpLocalAs>,
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
    /// exception and `BgpRib::propagate_add_path`.
    is_rs_client: bool,
    /// RFC 8097: attach the route's validation state (`set_peer_rpki_state`).
    announce_rpki_state: bool,
    /// See `BgpRib::peer_asns`.
    remote_asn: u32,
    /// RFC 9234: the peer's role (the counterpart of the configured one).
    remote_role: Option<nos_proto::BgpRole>,
    /// Address families we send RFC 7911 ADD-PATH ids to this peer for
    /// (`fsm::negotiate_add_path`). Every NLRI of such a family must carry
    /// one, so the plain fan-out skips them and `propagate_add_path` sends
    /// them their paths.
    add_path_tx: HashSet<AddressFamily>,
    /// How many paths per prefix `propagate_add_path` sends this peer
    /// (`set_peer_add_path_send_count`); `None` is every path.
    add_path_send_count: Option<usize>,
    /// This peer-group's resolved export policy — always present, `deny-all`
    /// by default (see root `CLAUDE.md`'s "Default-deny rollout impact"),
    /// consulted by `build_advertisement`.
    export_policy: Arc<CompiledPolicy>,
}

impl PeerOutbox {
    /// What an external (non-confederation) peer gets prepended (RFC 5065
    /// §4.1): our AS — the confederation identifier, if any — or, with a
    /// vendor `local-as`, `[local-as, ours]` (`[local-as]` with `replace-as`).
    fn prepend_external(&self, path: &mut AsPath, local_asn: u32) {
        match self.local_as {
            Some(l) if l.replace_as => {}
            _ => path.prepend_seq(self.confed_id.unwrap_or(local_asn)),
        }
        if let Some(l) = self.local_as {
            path.prepend_seq(l.asn);
        }
    }
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
    /// External peers whose peer-group sets `local-as` (`set_peer_local_as`).
    local_as_peers: HashMap<IpAddr, nos_proto::BgpLocalAs>,
    /// Peers with a configured RFC 9234 role (`set_peer_role`), ours toward them.
    role_peers: HashMap<IpAddr, nos_proto::BgpRole>,
    /// iBGP peers exchanging RFC 8097 states (`set_peer_rpki_state`).
    rpki_state_peers: HashSet<IpAddr>,
    /// This instance's own router-id — used for RFC 4456 §5 `ORIGINATOR_ID`
    /// loop-prevention on receipt (`handle_update`).
    local_router_id: Ipv4Addr,
    /// This instance's effective RFC 4456 cluster-id (`BgpInstance.cluster_id`
    /// unwrapped to `router_id` when unset) — prepended to `CLUSTER_LIST` on
    /// reflection and checked for loop-prevention on receipt.
    cluster_id: Ipv4Addr,
    /// Every path each peer sent per prefix (several with RFC 7911 ADD-PATH).
    adj_rib_in: HashMap<IpAddr, PeerTable>,
    /// How many paths each peer's `adj_rib_in` holds per family — kept in
    /// step at every mutation (`put_path`/`take_path`) so the RFC 4486
    /// maximum-prefix check is O(1) per UPDATE, not a table scan.
    path_counts: HashMap<IpAddr, PathCounts>,
    /// Each peer's maximum-prefix limits (`set_peer_max_prefix`), and the
    /// `(peer, family)` pairs already warned about for a `warning_only` limit,
    /// so the warning is logged once per crossing.
    max_prefix: HashMap<IpAddr, nos_proto::BgpMaximumPrefix>,
    max_prefix_warned: HashSet<(IpAddr, AddressFamily)>,
    /// Received EVPN (RFC 7432) routes per peer, keyed by NLRI.
    // ponytail: Adj-RIB-In only — no best-path, Route-Target import filtering,
    // import policy (RPL's `Input` is prefix-shaped) or re-advertisement, since
    // nothing consumes EVPN routes yet. Add a Loc-RIB when a MAC-VRF does.
    /// Keyed by `EvpnNlri::route_key` (RFC 7432 §7.2: labels and ESI are
    /// attributes, not identity).
    evpn_adj_rib_in: HashMap<IpAddr, HashMap<EvpnNlri, EvpnRoute>>,
    /// RFC 7313: paths (prefix, path id) in a peer's Adj-RIB-In marked stale
    /// by a `BoRR` and not yet re-announced; purged by the matching `EoRR`.
    stale: HashMap<IpAddr, HashSet<(IpNet, u32)>>,
    /// The EVPN twin of `stale` (route keys), filled only by a graceful restart.
    evpn_stale: HashMap<IpAddr, HashSet<EvpnNlri>>,
    /// RFC 4724: each peer's last graceful restart capability
    /// (`set_peer_gr`), recorded only while this instance has graceful
    /// restart on. Kept across the peer's sessions, so its presence also
    /// means this process already had a session with it — what our F bit
    /// says (`gr_forwarding`).
    gr: HashMap<IpAddr, PeerGr>,
    /// When a peer's retained (stale) routes are purged if no End-of-RIB
    /// came: its restart time after it went down, `gr_stale_time` after it
    /// came back. Present exactly while a graceful restart is in progress.
    gr_deadline: HashMap<IpAddr, Instant>,
    /// `BgpGracefulRestart.stale_time`.
    gr_stale_time: Duration,
    /// RFC 4724 §4.1: set while this restarting process defers what it
    /// sends (`begin_deferral`); every send site returns early meanwhile.
    deferral: Option<crate::gr::Deferral>,
    /// `nos-ribd` still held BGP routes when this process started, so our
    /// F bit is 1 toward every peer (`gr_forwarding`).
    forwarding_preserved: bool,
    /// `nos-ribd`'s redistribution feed has delivered its first snapshot.
    redistribute_seen: bool,
    /// EVPN routes originated by each `nos-fdbd` (keyed by broadcast domain),
    /// and what was last announced to each peer — see `evpn_out`.
    evpn_local: HashMap<evpn_out::EvpnSource, HashMap<nos_proto::EvpnKey, nos_proto::EvpnRoute>>,
    evpn_adj_rib_out: HashMap<IpAddr, HashMap<EvpnNlri, AdvertisedEvpn>>,
    /// Broadcast domains whose `redistribute from mac to bgp` names this
    /// instance — the ones `fdb_push_client` feeds received EVPN routes to.
    fdb_domains: Vec<String>,
    /// Routing tables whose `evpn.bgp_instance` names this instance — the
    /// ones `fdb_push_client` feeds received Type-5 routes to.
    evpn_tables: Vec<String>,
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
    /// `BgpInstance.aggregates` and each one's contributors — see `aggregate`.
    aggregates: Vec<aggregate::AggregateState>,
    /// Active aggregate routes: a local candidate source like `redistributed`.
    aggregated: HashMap<IpNet, RibRoute>,
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
    /// Per prefix, the multipath next-hop set (`multipath_next_hops`) when
    /// it holds two or more — absent means the winner's own next hop alone.
    multipaths: HashMap<IpNet, Vec<IpAddr>>,
    /// `BgpInstance.maximum_paths` (1 when unset): how many next hops a
    /// prefix may install.
    maximum_paths: usize,
    /// What we've last told each peer, for correct withdrawals.
    adj_rib_out: HashMap<IpAddr, HashSet<IpNet>>,
    peer_outboxes: HashMap<IpAddr, PeerOutbox>,
    /// Each peer's negotiated remote ASN (see `set_peer_asn`), for RPL's
    /// `this.bgp.peer_as`. Kept across resets like damping params.
    peer_asns: HashMap<IpAddr, u32>,
    /// Per ADD-PATH send peer, per prefix, the path id and last-sent
    /// snapshot of every path currently advertised to it — see
    /// `propagate_add_path`.
    add_path_sent: HashMap<(IpAddr, IpNet), AddPathSent>,
    /// Per ADD-PATH send peer, per prefix, the next fresh path id —
    /// monotonic, never recycled once withdrawn (see `send_add_paths`).
    add_path_next_id: HashMap<(IpAddr, IpNet), u32>,
    /// Each peer's resolved `add_path_send_count` (`None`: every path), set
    /// before `peer_established` like `set_peer_local_as`.
    add_path_counts: HashMap<IpAddr, Option<usize>>,
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
            local_as_peers: HashMap::new(),
            role_peers: HashMap::new(),
            rpki_state_peers: HashSet::new(),
            local_router_id: Ipv4Addr::UNSPECIFIED,
            cluster_id: Ipv4Addr::UNSPECIFIED,
            adj_rib_in: HashMap::new(),
            path_counts: HashMap::new(),
            max_prefix: HashMap::new(),
            max_prefix_warned: HashSet::new(),
            evpn_adj_rib_in: HashMap::new(),
            stale: HashMap::new(),
            evpn_stale: HashMap::new(),
            gr: HashMap::new(),
            gr_deadline: HashMap::new(),
            gr_stale_time: Duration::from_secs(u64::from(nos_proto::GR_STALE_TIME_DEFAULT)),
            deferral: None,
            forwarding_preserved: false,
            redistribute_seen: false,
            evpn_local: HashMap::new(),
            evpn_adj_rib_out: HashMap::new(),
            fdb_domains: Vec::new(),
            evpn_tables: Vec::new(),
            redistribute_raw: HashSet::new(),
            redistributed: HashMap::new(),
            redistribute_policy: Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            aggregates: Vec::new(),
            aggregated: HashMap::new(),
            loc_rib: HashMap::new(),
            igp: HashMap::new(),
            igp_ready: false,
            backups: HashMap::new(),
            multipaths: HashMap::new(),
            maximum_paths: 1,
            adj_rib_out: HashMap::new(),
            peer_outboxes: HashMap::new(),
            peer_asns: HashMap::new(),
            add_path_sent: HashMap::new(),
            add_path_next_id: HashMap::new(),
            add_path_counts: HashMap::new(),
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
            for (prefix, paths) in table.iter_mut() {
                for (_, route) in paths.iter_mut() {
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

    /// Sets `BgpInstance.maximum_paths` (`None`: 1) and, on a change,
    /// re-decides every received prefix's multipath set.
    pub fn set_maximum_paths(&mut self, maximum_paths: Option<u8>) {
        let max = usize::from(maximum_paths.unwrap_or(1).max(1));
        if max == self.maximum_paths {
            return;
        }
        self.maximum_paths = max;
        let prefixes: HashSet<IpNet> = self
            .adj_rib_in
            .values()
            .flat_map(HashMap::keys)
            .copied()
            .collect();
        for prefix in prefixes {
            self.recompute_and_propagate(prefix);
        }
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

    /// Records `peer`'s vendor `local-as` (`None`: none, or not an external
    /// peer). Call before `peer_established`, like `set_peer_confed`.
    pub fn set_peer_local_as(&mut self, peer: IpAddr, local_as: Option<nos_proto::BgpLocalAs>) {
        match local_as {
            Some(l) => self.local_as_peers.insert(peer, l),
            None => self.local_as_peers.remove(&peer),
        };
    }

    /// Records our configured RFC 9234 role toward `peer` (`None`: none).
    /// RFC 9234 §4.2: the procedures apply even when the peer sent no Role. Call before `peer_established`, like `set_peer_local_as`.
    pub fn set_peer_role(&mut self, peer: IpAddr, role: Option<nos_proto::BgpRole>) {
        match role {
            Some(r) => self.role_peers.insert(peer, r),
            None => self.role_peers.remove(&peer),
        };
    }

    /// Our configured RFC 9234 role toward `peer`, if any.
    pub fn peer_role(&self, peer: IpAddr) -> Option<nos_proto::BgpRole> {
        self.role_peers.get(&peer).copied()
    }

    /// Records how many paths per prefix `peer` is sent over ADD-PATH
    /// (`ResolvedPeer::add_path_send_count`; `None`: every path). Call before
    /// `peer_established`, like `set_peer_local_as`. Never set: the
    /// unconfigured default.
    pub fn set_peer_add_path_send_count(&mut self, peer: IpAddr, count: Option<usize>) {
        self.add_path_counts.insert(peer, count);
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

    /// Sets the IP-VRFs (routing tables) fed received Type-5 routes.
    pub fn set_evpn_tables(&mut self, tables: Vec<String>) {
        self.evpn_tables = tables;
    }

    pub fn evpn_tables(&self) -> &[String] {
        &self.evpn_tables
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
        // Deferring: `nos-ribd` keeps what it holds, rather than getting a
        // `Full` of a Loc-RIB that is still filling.
        if self.deferring() {
            return (None, HashMap::new());
        }
        let routes = self
            .loc_rib
            .iter()
            .filter_map(|(prefix, route)| {
                route.next_hop.map(|next_hop| {
                    let hops = self
                        .multipaths
                        .get(prefix)
                        .cloned()
                        .unwrap_or_else(|| vec![next_hop]);
                    (*prefix, (hops, self.backups.get(prefix).copied()))
                })
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
        add_path_tx: HashSet<AddressFamily>,
        export_policy: Arc<CompiledPolicy>,
        tx: mpsc::UnboundedSender<OutboundUpdate>,
    ) {
        self.gr_peer_returned(peer);
        let remote_asn = self.peer_asns.get(&peer).copied().unwrap_or(0);
        self.peer_outboxes.insert(
            peer,
            PeerOutbox {
                tx,
                is_ibgp,
                is_confed: self.confed_peers.contains(&peer),
                announce_rpki_state: self.rpki_state_peers.contains(&peer),
                confed_id: self.confed_id,
                local_as: self.local_as_peers.get(&peer).copied(),
                local_addr,
                negotiated_afs,
                mp_bgp_negotiated,
                next_hop_mode,
                is_rr_client,
                is_rs_client,
                remote_asn,
                remote_role: self.role_peers.get(&peer).map(|r| r.counterpart()),
                add_path_tx,
                add_path_send_count: self.add_path_counts.get(&peer).copied().unwrap_or(
                    nos_proto::BgpPeerGroup::default_add_path_send_count(is_rs_client),
                ),
                export_policy,
            },
        );
        if let Some(deferral) = self.deferral.as_mut() {
            let families = self.peer_outboxes[&peer].negotiated_afs.clone();
            deferral.established(peer, self.gr.get(&peer).copied(), &families);
            // Ending it sends this peer's initial update too.
            self.maybe_end_deferral(Instant::now());
            return;
        }
        self.initial_update(peer);
    }

    /// The initial full advertisement of the current Loc-RIB (and local
    /// EVPN routes) to a just-established peer, then — toward a graceful
    /// restart peer — one End-of-RIB per negotiated family (RFC 4724 §2),
    /// on the same channel so it follows the dump.
    fn initial_update(&mut self, peer: IpAddr) {
        let Some(outbox) = self.peer_outboxes.get(&peer) else {
            return;
        };
        let add_path = !outbox.add_path_tx.is_empty();
        let mut advertised = HashSet::new();
        for (prefix, best) in &self.loc_rib {
            if outbox.add_path_tx.contains(&family_of(*prefix))
                || self.suppressed_by_aggregate(*prefix)
            {
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
                advertised.insert(*prefix);
            }
        }
        self.adj_rib_out.insert(peer, advertised);
        self.announce_evpn_to(peer);
        if add_path {
            let prefixes: Vec<IpNet> = self.loc_rib.keys().copied().collect();
            for prefix in prefixes {
                self.propagate_add_path(prefix, Some(peer));
            }
        }
        if self.gr.contains_key(&peer) {
            let outbox = &self.peer_outboxes[&peer];
            for family in AddressFamily::ALL {
                if outbox.negotiated_afs.contains(&family) {
                    let _ = outbox.tx.send(OutboundUpdate::EndOfRib(family));
                }
            }
        }
    }

    /// Starts RFC 4724 §4.1 selection deferral: `nos-ribd` still held
    /// `routes` BGP routes when this process started. Call before any
    /// session starts; `peers` are the configured, non-shut ones.
    pub fn begin_deferral(
        &mut self,
        routes: u32,
        restart_time: u16,
        selection_deferral_time: u16,
        peers: impl IntoIterator<Item = IpAddr>,
    ) {
        info!(
            bgp_routes = routes,
            "graceful restart: forwarding state preserved, deferring route selection"
        );
        self.forwarding_preserved = true;
        let now = Instant::now();
        let mut deferral =
            crate::gr::Deferral::new(now, restart_time, selection_deferral_time, peers);
        if self.redistribute_seen {
            deferral.local_routes_in();
        }
        self.deferral = Some(deferral);
        self.maybe_end_deferral(now);
    }

    /// Whether selection deferral is in progress — our R bit.
    pub fn deferring(&self) -> bool {
        self.deferral.is_some()
    }

    /// The peers the deferral still waits for (`reconcile::tests`).
    #[cfg(test)]
    pub(crate) fn deferral_waiting(&self) -> Option<Vec<IpAddr>> {
        self.deferral.as_ref().map(crate::gr::Deferral::waiting)
    }

    /// Ends the deferral if it is over: every established peer gets its
    /// initial update and End-of-RIB, and the next push to `nos-ribd` is a
    /// `Full` that replaces what it kept (§4.1: stale forwarding state goes).
    fn maybe_end_deferral(&mut self, now: Instant) {
        let Some(reason) = self.deferral.as_ref().and_then(|d| d.over(now)) else {
            return;
        };
        self.deferral = None;
        info!(reason = %reason, "route selection deferral ended");
        let peers: Vec<IpAddr> = self.peer_outboxes.keys().copied().collect();
        for peer in peers {
            self.initial_update(peer);
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
        // Deferring: the initial update at its end sends everything anyway.
        let Some(outbox) = self.peer_outboxes.get(&peer).filter(|_| !self.deferring()) else {
            return;
        };
        let marker = |subtype| OutboundUpdate::RefreshMarker { family, subtype };
        if enhanced {
            let _ = outbox.tx.send(marker(message::REFRESH_BORR));
        }
        if outbox.add_path_tx.contains(&family) {
            // The same top N again, under the same ids (a path the export
            // policy now refuses gives its id up), plus every prefix still
            // holding an id toward this peer.
            let mut prefixes: HashSet<IpNet> = self
                .loc_rib
                .keys()
                .copied()
                .filter(|p| family_of(*p) == family)
                .collect();
            prefixes.extend(
                self.add_path_sent
                    .keys()
                    .filter(|(p, n)| *p == peer && family_of(*n) == family)
                    .map(|(_, n)| *n),
            );
            for prefix in prefixes {
                self.propagate_add_path(prefix, Some(peer));
            }
        } else {
            for (prefix, best) in &self.loc_rib {
                if family_of(*prefix) != family || self.suppressed_by_aggregate(*prefix) {
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
        if enhanced {
            let _ = self.peer_outboxes[&peer]
                .tx
                .send(marker(message::REFRESH_EORR));
        }
    }

    /// RFC 7313 `BoRR` received: every `family` route currently held from
    /// `peer` becomes stale until the peer re-announces it.
    pub fn begin_refresh_in(&mut self, peer: IpAddr, family: AddressFamily) {
        let Some(table) = self.adj_rib_in.get(&peer) else {
            return;
        };
        let set = self.stale.entry(peer).or_default();
        for (prefix, paths) in table {
            if family_of(*prefix) == family {
                set.extend(paths.iter().map(|(id, _)| (*prefix, *id)));
            }
        }
    }

    /// RFC 7313 `EoRR` received: withdraw every `family` route from `peer`
    /// that the refresh did not re-announce.
    /// Returns how many routes it purged.
    pub fn end_refresh_in(&mut self, peer: IpAddr, family: AddressFamily) -> usize {
        let Some(set) = self.stale.get_mut(&peer) else {
            return 0;
        };
        let purge: Vec<(IpNet, u32)> = set
            .iter()
            .copied()
            .filter(|(p, _)| family_of(*p) == family)
            .collect();
        set.retain(|(p, _)| family_of(*p) != family);
        let mut count = 0;
        for (prefix, id) in purge {
            if self.remove_path(peer, prefix, id).is_some() {
                count += 1;
                info!(peer = %peer, %prefix, path_id = id, "bgp: purged stale route");
                self.recompute_and_propagate(prefix);
            }
        }
        count
    }

    /// Purges `peer`'s stale EVPN routes (a graceful restart's); returns how
    /// many.
    fn purge_stale_evpn(&mut self, peer: IpAddr) -> usize {
        let Some(set) = self.evpn_stale.remove(&peer) else {
            return 0;
        };
        let Some(table) = self.evpn_adj_rib_in.get_mut(&peer) else {
            return 0;
        };
        let mut count = 0;
        for key in set {
            if let Some(EvpnRoute { nlri, .. }) = table.remove(&key) {
                count += 1;
                info!(peer = %peer, route_type = nlri.route_type(), route = %nlri, "evpn route withdrawn");
            }
        }
        count
    }

    /// Purges `peer`'s stale routes of `family`; returns how many.
    fn purge_stale(&mut self, peer: IpAddr, family: AddressFamily) -> usize {
        match family {
            AddressFamily::L2vpnEvpn => self.purge_stale_evpn(peer),
            _ => self.end_refresh_in(peer, family),
        }
    }

    /// Whether `peer` still has a route marked stale, of `family` or (with
    /// `None`) of any family.
    fn has_stale(&self, peer: IpAddr, family: Option<AddressFamily>) -> bool {
        let ip = self.stale.get(&peer).is_some_and(|s| {
            s.iter()
                .any(|(p, _)| family.is_none_or(|f| family_of(*p) == f))
        });
        let evpn = family.is_none_or(|f| f == AddressFamily::L2vpnEvpn)
            && self.evpn_stale.get(&peer).is_some_and(|s| !s.is_empty());
        ip || evpn
    }

    /// `BgpGracefulRestart.stale_time`.
    pub fn set_gr_stale_time(&mut self, secs: u16) {
        self.gr_stale_time = Duration::from_secs(u64::from(secs));
    }

    /// Records the graceful restart capability `peer` sent (`None`: none, or
    /// graceful restart is off here). Call before `peer_established`.
    pub fn set_peer_gr(&mut self, peer: IpAddr, gr: Option<PeerGr>) {
        match gr {
            Some(gr) => self.gr.insert(peer, gr),
            None => self.gr.remove(&peer),
        };
    }

    pub fn peer_gr(&self, peer: IpAddr) -> Option<&PeerGr> {
        self.gr.get(&peer)
    }

    /// Our F bit toward `peer`: this process already had a session with it,
    /// so the kernel still holds what that session installed, or
    /// `nos-ribd` still held BGP routes when it started (`begin_deferral`).
    /// Otherwise a fresh process says 0 — its first push to `nos-ribd`
    /// replaced everything.
    pub fn gr_forwarding(&self, peer: IpAddr) -> bool {
        self.forwarding_preserved || self.gr.contains_key(&peer)
    }

    /// Routes from `peer` currently marked stale (`PeerSummary.stale_prefixes`).
    pub fn stale_count(&self, peer: IpAddr) -> u32 {
        let n = self.stale.get(&peer).map_or(0, HashSet::len)
            + self.evpn_stale.get(&peer).map_or(0, HashSet::len);
        u32::try_from(n).unwrap_or(u32::MAX)
    }

    /// RFC 4724 §4.2, on a retained peer's new session: a family its new
    /// capability doesn't list, or lists with F = 0, is purged now; the
    /// rest waits for End-of-RIB, bounded by the stale timer.
    fn gr_peer_returned(&mut self, peer: IpAddr) {
        if !self.gr_deadline.contains_key(&peer) {
            return;
        }
        let gr = self.gr.get(&peer).copied();
        for family in AddressFamily::ALL {
            if !self.has_stale(peer, Some(family)) {
                continue;
            }
            let reason = match gr {
                Some(g) if g.has(family) && g.forwarding(family) => continue,
                Some(g) if g.has(family) => "forwarding-not-preserved",
                _ => "no-capability",
            };
            info!(peer = %peer, family = %family, reason = %reason, "bgp: flushing stale routes");
            self.purge_stale(peer, family);
        }
        if self.has_stale(peer, None) {
            self.gr_deadline
                .insert(peer, Instant::now() + self.gr_stale_time);
        } else {
            self.gr_deadline.remove(&peer);
        }
    }

    /// RFC 4724 §2 End-of-RIB from `peer`: whatever of `family` it hasn't
    /// re-announced since its restart is gone.
    pub fn end_of_rib(&mut self, peer: IpAddr, family: AddressFamily) {
        info!(peer = %peer, family = %family, "received end-of-rib");
        if self.gr_deadline.contains_key(&peer) {
            let count = self.purge_stale(peer, family);
            info!(peer = %peer, family = %family, count, "bgp: purged stale routes after end-of-rib");
            if !self.has_stale(peer, None) {
                self.gr_deadline.remove(&peer);
            }
        }
        // After the purge, so the deferral's initial updates don't carry
        // routes about to be withdrawn.
        if let Some(deferral) = self.deferral.as_mut() {
            deferral.end_of_rib(peer, family);
            self.maybe_end_deferral(Instant::now());
        }
    }

    /// Purges the stale routes of every peer whose restart or stale timer
    /// expired. Driven by the 5s damping tick.
    // ponytail: 5s granularity on top of the restart/stale times; a
    // per-peer timer would make it exact.
    pub fn gr_tick(&mut self) {
        self.gr_tick_at(Instant::now());
    }

    fn gr_tick_at(&mut self, now: Instant) {
        let expired: Vec<IpAddr> = self
            .gr_deadline
            .iter()
            .filter(|(_, d)| **d <= now)
            .map(|(p, _)| *p)
            .collect();
        for peer in expired {
            warn!(peer = %peer, "bgp: graceful restart timer expired, purging stale routes");
            self.gr_deadline.remove(&peer);
            for family in AddressFamily::ALL {
                self.purge_stale(peer, family);
            }
        }
        if let Some(deferral) = self.deferral.as_mut() {
            let established = &self.peer_outboxes;
            deferral.drop_dead(now, |p| established.contains_key(&p));
            self.maybe_end_deferral(now);
        }
    }

    /// RFC 5882 §4.3.1: BFD declared `peer` down while its routes are stale
    /// from a graceful restart: act as if the restart timer expired. `false`
    /// if nothing was stale.
    pub fn gr_abort(&mut self, peer: IpAddr) -> bool {
        if !self.has_stale(peer, None) {
            return false;
        }
        warn!(peer = %peer, "bgp: bfd down, aborting graceful restart and purging stale routes");
        self.gr_deadline.remove(&peer);
        for family in AddressFamily::ALL {
            self.purge_stale(peer, family);
        }
        true
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
            .flat_map(|(peer, t)| t.values().map(move |r| (*peer, &r.nlri, r)))
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

    /// Accepted (post-import-policy) paths held from `peer` — prefixes, or
    /// more with RFC 7911 ADD-PATH: ipv4, ipv6, l2vpn-evpn.
    pub fn accepted_prefixes(&self, peer: IpAddr) -> [u32; 3] {
        let len = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        let [v4, v6] = self.path_counts.get(&peer).copied().unwrap_or_default();
        let evpn = len(self.evpn_adj_rib_in.get(&peer).map_or(0, HashMap::len));
        [v4, v6, evpn]
    }

    /// Removes path `id` of `prefix` from `peer`'s Adj-RIB-In, keeping the
    /// path counters in step.
    fn remove_path(&mut self, peer: IpAddr, prefix: IpNet, id: u32) -> Option<RibRoute> {
        take_path(
            self.adj_rib_in.get_mut(&peer)?,
            self.path_counts.entry(peer).or_default(),
            prefix,
            id,
        )
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

    /// A session with `peer` ended (`kind` says how). Graceful restart
    /// (RFC 4724 §4.2, RFC 8538 §4): when the peer's capability allows it,
    /// its routes of every family it listed and negotiated stay in use,
    /// marked stale, for its restart time; everything else is withdrawn as
    /// before. Called again for a peer already down and retaining (by
    /// `reconcile_peers` after an abort), only a `Hard` end changes anything.
    pub fn peer_disconnected(&mut self, peer: IpAddr, kind: Disconnect) {
        // ponytail: a deferral this ends (its last waiting peer gone hard)
        // is noticed by the next `gr_tick`, up to 5s later.
        if let Some(deferral) = self.deferral.as_mut() {
            deferral.disconnected(peer, kind == Disconnect::Hard);
        }
        let outbox = self.peer_outboxes.remove(&peer);
        if outbox.is_none() && kind != Disconnect::Hard && self.gr_deadline.contains_key(&peer) {
            return;
        }
        let gr = self.gr.get(&peer).copied();
        let retained: Vec<AddressFamily> = match (&outbox, gr) {
            (Some(o), Some(g)) if crate::gr::retains(kind, Some(&g)) => g
                .families()
                .into_iter()
                .filter(|f| o.negotiated_afs.contains(f))
                .collect(),
            _ => Vec::new(),
        };
        self.max_prefix_warned.retain(|(p, _)| *p != peer);
        // ponytail: a session reset forgets its flap history (RFC 2439 allows
        // keeping it); keep entries across resets to damp session flaps too.
        self.damping.clear_peer(peer);
        self.adj_rib_out.remove(&peer);
        self.evpn_adj_rib_out.remove(&peer);
        self.add_path_sent.retain(|(p, _), _| *p != peer);
        self.add_path_next_id.retain(|(p, _), _| *p != peer);
        if let (false, Some(gr)) = (retained.is_empty(), gr) {
            self.retain_as_stale(peer, gr, &retained);
            return;
        }
        self.path_counts.remove(&peer);
        self.stale.remove(&peer);
        self.evpn_stale.remove(&peer);
        self.gr_deadline.remove(&peer);
        if let Some(routes) = self.evpn_adj_rib_in.remove(&peer) {
            // mac_mobility's record of this route's (vni, mac) is
            // deliberately left alone (see its own doc comment): a future
            // re-learn, local or remote, still needs to outrank it.
            for EvpnRoute { nlri, .. } in routes.values() {
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

    /// The retaining half of `peer_disconnected`: `families` stay, marked
    /// stale; any other family is withdrawn.
    fn retain_as_stale(&mut self, peer: IpAddr, gr: PeerGr, families: &[AddressFamily]) {
        // RFC 4724 §4.2: consecutive restarts without N drop what is still
        // stale from the previous one; RFC 8538 §4.1 keeps it with N.
        if !gr.notification {
            for family in AddressFamily::ALL {
                self.purge_stale(peer, family);
            }
        }
        let mut dropped = Vec::new();
        if let Some(table) = self.adj_rib_in.get(&peer) {
            let stale = self.stale.entry(peer).or_default();
            for (prefix, paths) in table {
                for (id, _) in paths {
                    if families.contains(&family_of(*prefix)) {
                        stale.insert((*prefix, *id));
                    } else {
                        dropped.push((*prefix, *id));
                    }
                }
            }
        }
        for (prefix, id) in dropped {
            if self.remove_path(peer, prefix, id).is_some() {
                self.recompute_and_propagate(prefix);
            }
        }
        if families.contains(&AddressFamily::L2vpnEvpn) {
            if let Some(table) = self.evpn_adj_rib_in.get(&peer) {
                self.evpn_stale
                    .entry(peer)
                    .or_default()
                    .extend(table.keys().cloned());
            }
        } else if let Some(routes) = self.evpn_adj_rib_in.remove(&peer) {
            for EvpnRoute { nlri, .. } in routes.values() {
                info!(peer = %peer, route_type = nlri.route_type(), route = %nlri, "evpn route withdrawn");
            }
        }
        let now = Instant::now();
        self.gr_deadline
            .insert(peer, now + Duration::from_secs(u64::from(gr.time)));
        info!(
            peer = %peer, families = ?families, restart_time = gr.time,
            "bgp: peer down, retaining routes as stale"
        );
        // A restart time of 0 keeps nothing.
        self.gr_tick_at(now);
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

        // RFC 4724: an EVPN route the peer mentions again is no longer stale.
        if let Some(stale) = self.evpn_stale.get_mut(&from) {
            for n in update.mp_reach.iter().flat_map(|m| &m.evpn) {
                stale.remove(&n.route_key());
            }
            for n in update.mp_unreach.iter().flat_map(|m| &m.evpn) {
                stale.remove(&n.route_key());
            }
        }
        let withdrawn = withdrawn_paths(update);
        let announced = announced_paths(update);
        // RFC 7313 / RFC 4724: any path the peer mentions again is no
        // longer stale.
        if let Some(stale) = self.stale.get_mut(&from) {
            for path in withdrawn.iter().chain(&announced) {
                stale.remove(path);
            }
        }

        for nlri in update.mp_unreach.iter().flat_map(|u| &u.evpn) {
            // mac_mobility's record of this route's (vni, mac) is
            // deliberately left alone here too — see peer_disconnected.
            let removed = self
                .evpn_adj_rib_in
                .get_mut(&from)
                .is_some_and(|t| t.remove(&nlri.route_key()).is_some());
            if removed {
                info!(peer = %from, route_type = nlri.route_type(), route = %nlri, "evpn route withdrawn");
            }
        }
        for &(prefix, id) in &withdrawn {
            if self.remove_path(from, prefix, id).is_some() {
                debug!(peer = %from, path_id = id, "bgp: withdrew path for {prefix} from adj-rib-in");
                touched.insert(prefix);
                self.damping
                    .flap(from, prefix, WITHDRAW_PENALTY, Instant::now());
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
            // RFC 9234 §5 applies to unicast only, never EVPN.
            let unicast =
                !update.nlri.is_empty() || update.mp_reach.iter().any(|m| !m.nlri.is_empty());
            // RFC 9234 §5 ingress 3: a route from a Provider, Peer or Route
            // Server with no OTC gets the neighbor's ASN.
            let otc = match self.role_peers.get(&from).map(|r| r.counterpart()) {
                Some(Provider | Peer | RouteServer) if unicast && attrs.otc.is_none() => {
                    Some(peer_as)
                }
                _ => attrs.otc,
            };
            // RFC 5065 §5.3 / RFC 7606 §7.2: confederation segments only ever
            // come from inside our own confederation.
            let stray_confed = attrs.as_path.has_confed()
                && (self.confed_id.is_none() || !(remote_is_ibgp || from_confed));
            // RFC 5065 §5.1: our confederation identifier (or AS) in a plain
            // segment, or our member AS in a confederation segment.
            // Vendor `local-as`: it counts as ours on this peer's routes only.
            let local_as = self.local_as_peers.get(&from).copied();
            let looped = attrs
                .as_path
                .contains(self.confed_id.unwrap_or(self.local_asn))
                || (self.confed_id.is_some() && attrs.as_path.contains_confed(self.local_asn))
                || local_as.is_some_and(|l| attrs.as_path.contains(l.asn));
            if stray_confed {
                warn!(
                    peer = %from, as_path = ?attrs.as_path,
                    "treating bgp update as withdraw: as_path has confederation segments from outside the confederation"
                );
                self.withdraw_announced(from, update, &announced, &mut touched);
            } else if looped {
                // RFC 4271 §9.1.2: a looped route is unfeasible, so it
                // replaces (implicitly withdraws) an earlier one.
                warn!(
                    peer = %from, as_path = ?attrs.as_path,
                    "dropping bgp update: as_path already contains our own asn (loop prevention)"
                );
                self.withdraw_announced(from, update, &announced, &mut touched);
            } else if let Some(role) = unicast
                .then(|| self.role_peers.get(&from).map(|r| r.counterpart()))
                .flatten()
                .filter(|&r| otc_leak(r, attrs.otc, peer_as))
            {
                warn!(
                    peer = %from, prefix = ?announced.iter().map(|a| a.0).collect::<Vec<_>>(),
                    otc = ?attrs.otc, role = ?role,
                    "route leak detected: dropping bgp update (rfc 9234 only-to-customer)"
                );
                self.withdraw_announced(from, update, &announced, &mut touched);
            } else if attrs.cluster_list.contains(&self.cluster_id) {
                warn!(
                    peer = %from, cluster_list = ?attrs.cluster_list,
                    "dropping bgp update: cluster_list already contains our own cluster-id (rfc 4456 reflection loop prevention)"
                );
                self.withdraw_announced(from, update, &announced, &mut touched);
            } else if attrs.originator_id == Some(self.local_router_id) {
                warn!(
                    peer = %from, originator_id = ?attrs.originator_id,
                    "dropping bgp update: originator_id is our own router-id (rfc 4456 reflection loop prevention)"
                );
                self.withdraw_announced(from, update, &announced, &mut touched);
            } else {
                let mut evpn_recheck: Vec<(u32, [u8; 6])> = Vec::new();
                let table = self.adj_rib_in.entry(from).or_default();
                let counts = self.path_counts.entry(from).or_default();
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
                // Vendor `local-as`: the received path gets it as a real hop,
                // so policy and every other peer see `[local-as, peer…]`.
                let mut as_path = attrs.as_path.clone();
                if let Some(l) = local_as.filter(|l| !l.no_prepend) {
                    as_path.prepend_seq(l.asn);
                }
                let base_route = RibRoute {
                    origin: RouteOrigin::Peer(from),
                    as_path: Arc::new(as_path),
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
                    otc,
                    validation_state: nos_rpl::ValidationState::NotFound,
                    received_ov,
                };
                let origin_as = crate::rpki::origin_as(
                    &base_route.as_path,
                    self.confed_id.unwrap_or(self.local_asn),
                );
                for (i, prefix) in update.nlri.iter().enumerate() {
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
                        counts,
                        &mut self.damping,
                        &mut touched,
                        (from, peer_as),
                        (IpNet::V4(*prefix), path_id_at(&update.nlri_path_ids, i)),
                        candidate,
                        import_policy,
                    );
                }
                for mp in &update.mp_reach {
                    for (i, prefix) in mp.nlri.iter().enumerate() {
                        let candidate = RibRoute {
                            next_hop: Some(mp.next_hop),
                            validation_state: ov_state(&self.vrps, *prefix, origin_as, received_ov),
                            ..base_route.clone()
                        };
                        learn_prefix(
                            table,
                            counts,
                            &mut self.damping,
                            &mut touched,
                            (from, peer_as),
                            (*prefix, path_id_at(&mp.nlri_path_ids, i)),
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
                        evpn_recheck.extend(
                            mp.evpn
                                .iter()
                                .filter_map(evpn_mac_key)
                                .map(|(vni, mac, _)| (vni, mac)),
                        );
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
        announced: &[(IpNet, u32)],
        touched: &mut HashSet<IpNet>,
    ) {
        for &(prefix, id) in announced {
            if self.remove_path(from, prefix, id).is_some() {
                debug!(peer = %from, path_id = id, "bgp: withdrew path for {prefix} from adj-rib-in");
                touched.insert(prefix);
            }
        }
        if let Some(table) = self.evpn_adj_rib_in.get_mut(&from) {
            for nlri in update.mp_reach.iter().flat_map(|m| &m.evpn) {
                if table.remove(&nlri.route_key()).is_some() {
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
        // `nos-ribd` sends a `Full` (maybe empty) as soon as it connects.
        self.redistribute_seen = true;
        if let Some(deferral) = self.deferral.as_mut() {
            deferral.local_routes_in();
            self.maybe_end_deferral(Instant::now());
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

    /// Every best-path candidate for `prefix`: the redistributed route (path
    /// id 0), the aggregate (1) and every peer path not damped, minus the
    /// unfeasible ones (logged when `log`).
    fn candidates(&self, prefix: IpNet, log: bool) -> Vec<Candidate> {
        // Sized for one redistributed candidate plus one path per peer —
        // avoids the reallocate-on-every-push churn this always-tiny,
        // rebuilt-per-touched-prefix scratch Vec used to pay. ADD-PATH
        // peers add every path they sent.
        let mut candidates: Vec<Candidate> = Vec::with_capacity(1 + self.adj_rib_in.len());
        if let Some(route) = self.redistributed.get(&prefix) {
            candidates.push((route.clone(), 0));
        }
        if let Some(route) = self.aggregated.get(&prefix) {
            candidates.push((route.clone(), 1));
        }
        for (peer, table) in &self.adj_rib_in {
            if self.damping.is_suppressed(*peer, &prefix) {
                continue;
            }
            for (id, route) in table.get(&prefix).into_iter().flatten() {
                candidates.push((route.clone(), *id));
            }
        }
        // RFC 4271 §9.1.2: an unresolvable next hop is unfeasible — out of
        // the decision process (and the backup pick) entirely.
        candidates.retain(|(route, _)| {
            let feasible = self.next_hop_feasible(route.next_hop);
            if !feasible && log {
                debug!(origin = ?route.origin, %prefix, next_hop = ?route.next_hop, "bgp: candidate excluded, next hop unresolvable");
            }
            feasible
        });
        candidates
    }

    /// The shared core: re-decides `prefix`'s winner from every current
    /// candidate (redistributed + every peer's Adj-RIB-In), and if the
    /// winner actually changed, pushes `Announce`/`Withdraw` to every
    /// registered peer as appropriate.
    fn recompute_and_propagate(&mut self, prefix: IpNet) {
        // Runs independently of the single-elected-best-path logic below —
        // an ADD-PATH peer's view covers more than the one instance-wide
        // winner, so a change to a non-winning path must still be reflected
        // here even when `best_path`'s pick doesn't change.
        self.propagate_add_path(prefix, None);

        let candidates = self.candidates(prefix, true);
        let best = best_path(&candidates, &self.igp);
        // Install-only: the multipath set never changes what is advertised
        // (still `best` alone), so it's updated before the `unchanged`
        // return below, like the backup — `rib_push_client`'s poll picks
        // up a sibling joining or leaving on its own.
        let multipath = best.as_ref().map_or_else(Vec::new, |b| {
            multipath_next_hops(&candidates, b, &self.igp, self.maximum_paths)
        });
        if multipath.len() > 1 {
            if self.multipaths.get(&prefix) != Some(&multipath) {
                debug!(
                    next_hops = multipath.len(),
                    "bgp: multipath set for {prefix} updated"
                );
                self.multipaths.insert(prefix, multipath.clone());
            }
        } else if self.multipaths.remove(&prefix).is_some() {
            debug!(
                next_hops = multipath.len(),
                "bgp: multipath set for {prefix} updated"
            );
        }
        match best
            .as_ref()
            .and_then(|_| runner_up_next_hop(&candidates, &multipath, &self.igp))
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
        // Before the fan-out, so a `summary-only` aggregate this prefix
        // activates already suppresses it.
        if !self.aggregates.is_empty() {
            self.update_aggregates_for(prefix);
        }
        self.fan_out(prefix);
    }

    /// Sends `prefix`'s current Loc-RIB entry (or its withdrawal) to every
    /// peer, diffed against `adj_rib_out`.
    fn fan_out(&mut self, prefix: IpNet) {
        if self.deferring() {
            return;
        }
        let suppressed = self.suppressed_by_aggregate(prefix);
        let source_is_rr_client = self
            .loc_rib
            .get(&prefix)
            .is_some_and(|r| self.source_is_rr_client(r));
        let best = self.loc_rib.get(&prefix);
        // Reused across calls (see `peer_scratch`'s doc comment) instead of
        // collecting a fresh Vec on every touched prefix.
        let mut peers = std::mem::take(&mut self.peer_scratch);
        peers.clear();
        peers.extend(self.peer_outboxes.keys().copied());
        for &peer in &peers {
            let outbox = self.peer_outboxes.get(&peer).expect("just listed");
            if outbox.add_path_tx.contains(&family_of(prefix)) {
                continue; // `propagate_add_path`'s, every NLRI needs an id
            }
            let advertisement = best.filter(|_| !suppressed).and_then(|route| {
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

    /// RFC 7911 ADD-PATH fan-out of `prefix` to every peer we send ADD-PATH
    /// to for its family (only `only`, re-sending even unchanged paths, for a
    /// new session or a route refresh): the best `add_path_send_count` paths
    /// by the decision process (`decision_cmp`), counted after this peer's
    /// own filtering (`build_advertisement`: split horizon, RR rules, export
    /// policy, never echoing a peer's own path) — a refused path doesn't use
    /// up a slot. The best path is rank 1, so it's sent unless refused (§5).
    ///
    /// An ordinary peer ranks the Loc-RIB's candidates (`candidates`); a
    /// summary-only-suppressed prefix sends none. A route-server client
    /// ranks every source's paths, deliberately *not* filtered by
    /// `next_hop_feasible` nor aggregates (RFC 7947 §2.2.2 transparency:
    /// whether *this* instance can resolve a next hop says nothing about
    /// whether the client can). Ids: see `send_add_paths`.
    fn propagate_add_path(&mut self, prefix: IpNet, only: Option<IpAddr>) {
        if self.deferring() {
            return;
        }
        let family = family_of(prefix);
        let peers: Vec<IpAddr> = self
            .peer_outboxes
            .iter()
            .filter(|(addr, o)| o.add_path_tx.contains(&family) && only.is_none_or(|p| p == **addr))
            .map(|(addr, _)| *addr)
            .collect();
        if peers.is_empty() {
            return;
        }
        let suppressed = self.suppressed_by_aggregate(prefix);
        // Ranked once per prefix, best first, shared by every peer.
        let (mut ranked, mut rs_ranked) = (None, None);
        for peer in peers {
            let list: &[Candidate] = if self.peer_outboxes[&peer].is_rs_client {
                rs_ranked.get_or_insert_with(|| self.ranked(self.rs_candidates(prefix)))
            } else if suppressed {
                &[]
            } else {
                ranked.get_or_insert_with(|| self.ranked(self.candidates(prefix, false)))
            };
            self.send_add_paths(prefix, peer, list, only.is_some());
        }
    }

    /// A route-server client's candidates: the redistributed route and every
    /// peer path not damped (`propagate_add_path`).
    fn rs_candidates(&self, prefix: IpNet) -> Vec<Candidate> {
        let mut candidates: Vec<Candidate> = Vec::new();
        if let Some(route) = self.redistributed.get(&prefix) {
            candidates.push((route.clone(), 0));
        }
        for (src, table) in &self.adj_rib_in {
            if !self.damping.is_suppressed(*src, &prefix) {
                candidates.extend(
                    table
                        .get(&prefix)
                        .into_iter()
                        .flatten()
                        .map(|(id, r)| (r.clone(), *id)),
                );
            }
        }
        candidates
    }

    /// `candidates` sorted best first.
    fn ranked(&self, mut candidates: Vec<Candidate>) -> Vec<Candidate> {
        candidates.sort_by(|a, b| decision_cmp(b, a, &self.igp));
        candidates
    }

    /// Sends `peer` the first `add_path_send_count` paths of `ranked` it may
    /// have, diffed against what it was last sent (`add_path_sent`). A path
    /// still selected keeps its id, re-announced only if it changed (or
    /// `force`). A path that left the set frees its id; an entering path
    /// takes the lowest freed id — an RFC 7911 §3 implicit replace, so the
    /// receiver never drops to N−1 paths in between — else a fresh one from
    /// `add_path_next_id`. Ids still free at the end are withdrawn.
    fn send_add_paths(&mut self, prefix: IpNet, peer: IpAddr, ranked: &[Candidate], force: bool) {
        let outbox = &self.peer_outboxes[&peer];
        let limit = outbox.add_path_send_count.unwrap_or(usize::MAX);
        let mut selected: Vec<(PathKey, &RibRoute, AdvertisedRoute)> = Vec::new();
        for (route, id) in ranked {
            if selected.len() >= limit {
                break;
            }
            if let Some(adv) = build_advertisement(
                prefix,
                route,
                peer,
                outbox,
                self.local_asn,
                self.source_is_rr_client(route),
                self.cluster_id,
            ) {
                selected.push(((route.origin, *id), route, adv));
            }
        }
        let (tx, mp) = (outbox.tx.clone(), outbox.mp_bgp_negotiated);

        let mut sent = self
            .add_path_sent
            .remove(&(peer, prefix))
            .unwrap_or_default();
        let mut freed = Vec::new();
        sent.retain(|key, (id, _)| {
            let keep = selected.iter().any(|(k, ..)| k == key);
            if !keep {
                freed.push(*id);
            }
            keep
        });
        freed.sort_unstable_by(|a, b| b.cmp(a)); // `pop` takes the lowest
        for (key, route, adv) in selected {
            let id = match sent.get(&key) {
                Some((_, last)) if !force && last == route => continue,
                Some((id, _)) => *id,
                None => freed.pop().unwrap_or_else(|| {
                    // ponytail: never recycled once withdrawn, a u32 per
                    // (peer, prefix) is nowhere near exhausted.
                    let next = self.add_path_next_id.entry((peer, prefix)).or_insert(1);
                    *next += 1;
                    *next - 1
                }),
            };
            let _ = tx.send(OutboundUpdate::Announce(AdvertisedRoute {
                path_id: Some(id),
                ..adv
            }));
            sent.insert(key, (id, route.clone()));
        }
        for id in freed.into_iter().rev() {
            let _ = tx.send(OutboundUpdate::Withdraw(prefix, mp, Some(id)));
        }
        if !sent.is_empty() {
            self.add_path_sent.insert((peer, prefix), sent);
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
        otc: None,
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

/// A route's next hops (its multipath set, sorted, at least one) plus its
/// backup (runner-up path's next hop), as pushed to `nos-ribd`.
pub type Hops = (Vec<IpAddr>, Option<IpAddr>);

/// The next hop of the best candidate whose real next hop is none of
/// `primary` (the winner's multipath set) — the backup path. `None` when
/// there is no such candidate (a single path, or every other path shares a
/// primary next hop, which a backup route couldn't protect against anyway).
fn runner_up_next_hop(
    candidates: &[Candidate],
    primary: &[IpAddr],
    igp: &HashMap<IpNet, u32>,
) -> Option<IpAddr> {
    if candidates.len() < 2 {
        return None;
    }
    let others: Vec<Candidate> = candidates
        .iter()
        .filter(|(r, _)| r.next_hop.is_some_and(|nh| !primary.contains(&nh)))
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

/// One best-path candidate: the route and its path id — `(route.origin, id)`
/// is its `PathKey`. The id breaks the final tie (step 10).
type Candidate = (RibRoute, u32);

/// The full RFC 4271 §9.1.2.2 decision process — see the module doc
/// comment for the ten-step order.
fn best_path(candidates: &[Candidate], igp: &HashMap<IpNet, u32>) -> Option<RibRoute> {
    candidates
        .iter()
        .max_by(|a, b| decision_cmp(a, b, igp))
        .map(|(route, _)| route.clone())
}

/// `best_path`'s comparator over two `(route, source_peer)` candidates:
/// `Greater` means `a` is preferred.
fn decision_cmp(
    (a, a_id): &Candidate,
    (b, b_id): &Candidate,
    igp: &HashMap<IpNet, u32>,
) -> std::cmp::Ordering {
    multipath_cmp(a, b, igp)
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
            // Step 10: lowest peer address, then lowest RFC 7911 path
            // id (two paths of one peer tie on steps 9 and 10), so the
            // order is total — reverse the comparison since `max_by`
            // favors the greater element. A local route never reaches
            // this arm against a peer one (already decided by step 2).
            match (a.origin, b.origin) {
                (RouteOrigin::Peer(x), RouteOrigin::Peer(y)) => (y, b_id).cmp(&(x, a_id)),
                _ => std::cmp::Ordering::Equal,
            }
        })
}

/// Decision steps 1–7 — the ones two paths must tie on to be installed
/// together as multipath (`multipath_next_hops`); `Greater` means `a` wins.
fn multipath_cmp(a: &RibRoute, b: &RibRoute, igp: &HashMap<IpNet, u32>) -> std::cmp::Ordering {
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
}

/// The next hops installed for `best`'s prefix: `best`'s own, plus those of
/// every other peer-learned candidate tying with it on decision steps 1–7
/// (`multipath_cmp`) and learned from the same neighbouring AS (the usual
/// non-relaxed vendor rule — no RFC defines multipath selection; RFC 2991/
/// 2992 only cover forwarding). Deduplicated, picked in decision order
/// (steps 8–10 between the ties), capped at `max`, then sorted so the push
/// diff is stable. Empty when `best` has no next hop (a `Local` route).
fn multipath_next_hops(
    candidates: &[Candidate],
    best: &RibRoute,
    igp: &HashMap<IpNet, u32>,
    max: usize,
) -> Vec<IpAddr> {
    let Some(best_hop) = best.next_hop else {
        return Vec::new();
    };
    let mut ties: Vec<&Candidate> = candidates
        .iter()
        .filter(|(r, _)| {
            r.next_hop.is_some()
                && !matches!(r.origin, RouteOrigin::Local)
                && neighboring_as(r) == neighboring_as(best)
                && multipath_cmp(r, best, igp).is_eq()
        })
        .collect();
    ties.sort_by(|a, b| decision_cmp(b, a, igp));
    let mut hops = vec![best_hop];
    for (r, _) in ties {
        if hops.len() >= max {
            break;
        }
        let hop = r.next_hop.expect("filtered");
        if !hops.contains(&hop) {
            hops.push(hop);
        }
    }
    hops.sort_unstable();
    hops
}

/// RFC 9234 §5 ingress rules 1 and 2: is a route with `otc` a leak from a
/// neighbor whose role is `remote`?
fn otc_leak(remote: nos_proto::BgpRole, otc: Option<u32>, peer_as: u32) -> bool {
    match (remote, otc) {
        (Customer | RouteServerClient, Some(_)) => true,
        (Peer, Some(o)) => o != peer_as,
        _ => false,
    }
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
    // RFC 9234 §5 egress, after policy so it cannot defeat it.
    match (outbox.remote_role, adjusted.otc) {
        (Some(Customer | Peer | RouteServerClient), None) => {
            adjusted.otc = Some(outbox.local_as.map_or(local_asn, |l| l.asn));
        }
        (Some(Provider | Peer | RouteServer), Some(_)) => return None,
        _ => {}
    }
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
            outbox.prepend_external(Arc::make_mut(&mut as_path), local_asn);
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
        otc: best.otc,
        path_id: None,
    })
}

#[cfg(test)]
mod tests;
