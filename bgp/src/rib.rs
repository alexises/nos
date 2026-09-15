//! The BGP RIB engine: Adj-RIB-In per peer, a locally-redistributed route
//! set (fed by `nos-ribd` via `nos_proto::RedistributeUpdate`), a cached
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
use std::time::Instant;

use ipnet::IpNet;
use nos_proto::{AddressFamily, NextHopMode, RedistributeUpdate};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::message::{self, UpdateMessage};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteOrigin {
    Local,
    Peer(IpAddr),
}

/// One candidate route for a prefix, either locally redistributed or learned
/// from a peer.
#[derive(Debug, Clone, PartialEq)]
pub struct RibRoute {
    pub origin: RouteOrigin,
    pub as_path: Vec<u32>,
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
}

/// One update this instance needs to send out over a specific peer's
/// session. The `bool` picks the destination peer's wire encoding (`true` =
/// `MP_REACH_NLRI`/`MP_UNREACH_NLRI`, `false` = legacy plain NLRI — see
/// `fsm::outbound_update_to_message`), mirroring `AdvertisedRoute::use_mp`.
#[derive(Debug, Clone, PartialEq)]
pub enum OutboundUpdate {
    Announce(AdvertisedRoute),
    Withdraw(IpNet, bool),
}

/// A route rewritten for advertisement toward one specific peer.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvertisedRoute {
    pub prefix: IpNet,
    /// Already rewritten for the destination peer (our ASN prepended iff
    /// eBGP).
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
}

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
}

/// The BGP RIB engine for one `nos-bgpd` instance. See the module doc
/// comment for the locking model.
pub struct BgpRib {
    local_asn: u32,
    adj_rib_in: HashMap<IpAddr, HashMap<IpNet, RibRoute>>,
    redistributed: HashMap<IpNet, RibRoute>,
    loc_rib: HashMap<IpNet, RibRoute>,
    /// What we've last told each peer, for correct withdrawals.
    adj_rib_out: HashMap<IpAddr, HashSet<IpNet>>,
    peer_outboxes: HashMap<IpAddr, PeerOutbox>,
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
            adj_rib_in: HashMap::new(),
            redistributed: HashMap::new(),
            loc_rib: HashMap::new(),
            adj_rib_out: HashMap::new(),
            peer_outboxes: HashMap::new(),
        }
    }

    pub fn set_local_asn(&mut self, asn: u32) {
        self.local_asn = asn;
    }

    /// Registers a newly-`Established` peer's outbound channel and does an
    /// initial full advertisement of the current Loc-RIB to it.
    #[allow(clippy::too_many_arguments)]
    pub fn peer_established(
        &mut self,
        peer: IpAddr,
        is_ibgp: bool,
        local_addr: Option<IpAddr>,
        negotiated_afs: HashSet<AddressFamily>,
        mp_bgp_negotiated: bool,
        next_hop_mode: Option<NextHopMode>,
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
            },
        );
        let outbox = self.peer_outboxes.get(&peer).expect("just inserted");
        let mut advertised = HashSet::new();
        for (prefix, best) in &self.loc_rib {
            if let Some(adv) = build_advertisement(*prefix, best, peer, outbox, self.local_asn) {
                let _ = outbox.tx.send(OutboundUpdate::Announce(adv));
                advertised.insert(*prefix);
            }
        }
        self.adj_rib_out.insert(peer, advertised);
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
            if let Some(adv) = build_advertisement(*prefix, best, peer, outbox, self.local_asn) {
                let _ = outbox.tx.send(OutboundUpdate::Announce(adv));
            }
        }
    }

    /// Deregisters a peer's outbox and Adj-RIB-In, then re-decides every
    /// prefix that peer had contributed — the implicit withdraw-everything
    /// path for a session ending, whatever the reason.
    pub fn peer_disconnected(&mut self, peer: IpAddr) {
        self.peer_outboxes.remove(&peer);
        self.adj_rib_out.remove(&peer);
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
    /// used instead of the legacy attribute's.
    pub fn handle_update(
        &mut self,
        from: IpAddr,
        remote_is_ibgp: bool,
        remote_bgp_id: Ipv4Addr,
        update: &UpdateMessage,
    ) {
        let mut touched: HashSet<IpNet> = HashSet::new();

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
            } else {
                let table = self.adj_rib_in.entry(from).or_default();
                let base_route = RibRoute {
                    origin: RouteOrigin::Peer(from),
                    as_path: attrs.as_path.clone(),
                    bgp_origin: attrs.origin,
                    local_pref: attrs.local_pref.unwrap_or(DEFAULT_LOCAL_PREF),
                    med: attrs.med,
                    learned_via_ibgp: remote_is_ibgp,
                    router_id: Some(remote_bgp_id),
                    next_hop: None,
                    received_at: Instant::now(),
                };
                for prefix in &update.nlri {
                    let prefix = IpNet::V4(*prefix);
                    info!(peer = %from, "bgp: learned route for {prefix} into adj-rib-in");
                    table.insert(
                        prefix,
                        RibRoute {
                            next_hop: Some(IpAddr::V4(attrs.next_hop)),
                            ..base_route.clone()
                        },
                    );
                    touched.insert(prefix);
                }
                for mp in &update.mp_reach {
                    for prefix in &mp.nlri {
                        info!(peer = %from, "bgp: learned route for {prefix} into adj-rib-in");
                        table.insert(
                            *prefix,
                            RibRoute {
                                next_hop: Some(mp.next_hop),
                                ..base_route.clone()
                            },
                        );
                        touched.insert(*prefix);
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
    /// configured mode (see `RibRoute::next_hop`'s doc comment).
    pub fn apply_redistribute_update(&mut self, update: RedistributeUpdate) {
        match update {
            RedistributeUpdate::Full(routes) => {
                let mut new_redistributed = HashMap::with_capacity(routes.len());
                for route in routes {
                    new_redistributed.insert(route.prefix, redistributed_route());
                }
                let old_keys: HashSet<IpNet> = self.redistributed.keys().copied().collect();
                let new_keys: HashSet<IpNet> = new_redistributed.keys().copied().collect();
                let touched: Vec<IpNet> =
                    old_keys.symmetric_difference(&new_keys).copied().collect();
                self.redistributed = new_redistributed;
                for prefix in touched {
                    self.recompute_and_propagate(prefix);
                }
            }
            RedistributeUpdate::Add(route) => {
                self.redistributed
                    .insert(route.prefix, redistributed_route());
                self.recompute_and_propagate(route.prefix);
            }
            RedistributeUpdate::Remove(prefix) => {
                self.redistributed.remove(&prefix);
                self.recompute_and_propagate(prefix);
            }
        }
    }

    /// The shared core: re-decides `prefix`'s winner from every current
    /// candidate (redistributed + every peer's Adj-RIB-In), and if the
    /// winner actually changed, pushes `Announce`/`Withdraw` to every
    /// registered peer as appropriate.
    fn recompute_and_propagate(&mut self, prefix: IpNet) {
        let mut candidates: Vec<(RibRoute, Option<IpAddr>)> = Vec::new();
        if let Some(route) = self.redistributed.get(&prefix) {
            candidates.push((route.clone(), None));
        }
        for (peer, table) in &self.adj_rib_in {
            if let Some(route) = table.get(&prefix) {
                candidates.push((route.clone(), Some(*peer)));
            }
        }

        let best = best_path(&candidates);

        let unchanged = match (&best, self.loc_rib.get(&prefix)) {
            (Some(new), Some(old)) => new == old,
            (None, None) => true,
            _ => false,
        };
        if unchanged {
            return;
        }
        if let Some(route) = &best {
            info!(origin = ?route.origin, as_path = ?route.as_path, "bgp: loc-rib best path for {prefix} updated");
            self.loc_rib.insert(prefix, route.clone());
        } else {
            info!("bgp: loc-rib route for {prefix} withdrawn");
            self.loc_rib.remove(&prefix);
        }

        let peers: Vec<IpAddr> = self.peer_outboxes.keys().copied().collect();
        for peer in peers {
            let outbox = self.peer_outboxes.get(&peer).expect("just listed");
            let advertisement = best
                .as_ref()
                .and_then(|route| build_advertisement(prefix, route, peer, outbox, self.local_asn));

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
                            let _ = outbox
                                .tx
                                .send(OutboundUpdate::Withdraw(prefix, outbox.mp_bgp_negotiated));
                        }
                    }
                }
            }
        }
    }
}

fn redistributed_route() -> RibRoute {
    RibRoute {
        origin: RouteOrigin::Local,
        as_path: Vec::new(),
        bgp_origin: message::Origin::Igp,
        local_pref: DEFAULT_LOCAL_PREF,
        med: None,
        learned_via_ibgp: false,
        router_id: None,
        next_hop: None,
        received_at: Instant::now(),
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
/// local address for next-hop-self).
fn build_advertisement(
    prefix: IpNet,
    best: &RibRoute,
    peer: IpAddr,
    outbox: &PeerOutbox,
    local_asn: u32,
) -> Option<AdvertisedRoute> {
    if !outbox.negotiated_afs.contains(&family_of(prefix)) {
        return None;
    }
    if best.origin == RouteOrigin::Peer(peer) {
        // Never echo a route back to the peer it came from.
        return None;
    }
    if let RouteOrigin::Peer(_) = best.origin {
        if best.learned_via_ibgp && outbox.is_ibgp {
            // Standard iBGP split-horizon: no route reflection.
            return None;
        }
    }
    let mode = outbox.next_hop_mode.unwrap_or(if outbox.is_ibgp {
        NextHopMode::Unchanged
    } else {
        NextHopMode::SelfAddress
    });
    let next_hop = match mode {
        NextHopMode::SelfAddress => outbox.local_addr?,
        NextHopMode::Unchanged => best.next_hop.or(outbox.local_addr)?,
    };

    let mut as_path = best.as_path.clone();
    if !outbox.is_ibgp {
        as_path.insert(0, local_asn);
    }
    let local_pref = outbox.is_ibgp.then_some(best.local_pref);
    // MED is meant for use between adjacent ASes, so it's never forwarded
    // on to a further eBGP peer, only preserved toward iBGP peers.
    let med = if outbox.is_ibgp { best.med } else { None };

    Some(AdvertisedRoute {
        prefix,
        as_path,
        next_hop,
        local_pref,
        med,
        origin: best.bgp_origin,
        use_mp: outbox.mp_bgp_negotiated,
    })
}

#[cfg(test)]
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
        rib.set_local_asn(local_asn);
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
            tx,
        );
        rx
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
            nlri: nlri.into_iter().map(|s| s.parse().unwrap()).collect(),
            attributes: Some(message::PathAttributes {
                origin: message::Origin::Igp,
                as_path,
                next_hop: v4(next_hop),
                local_pref: None,
                med: None,
            }),
            mp_reach: vec![],
            mp_unreach: vec![],
        }
    }

    fn empty_update() -> UpdateMessage {
        UpdateMessage {
            withdrawn_routes: vec![],
            nlri: vec![],
            attributes: None,
            mp_reach: vec![],
            mp_unreach: vec![],
        }
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
        );

        let updates = recv_all(&mut other_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
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
        );

        let updates = recv_all(&mut ibgp_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
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
        );

        let updates = recv_all(&mut ibgp_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
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
        );

        let updates = recv_all(&mut other_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
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
                }),
                ..empty_update()
            },
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
                }),
                ..empty_update()
            },
        );

        let updates = recv_all(&mut observer_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
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
        );
        let _ = recv_all(&mut observer_rx);

        rib.apply_redistribute_update(full_update(vec![("5.5.5.0/24", "10.9.9.9")]));

        let updates = recv_all(&mut observer_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
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
        );

        let updates = recv_all(&mut observer_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Withdraw(prefix("5.5.5.0/24"), false)]
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
        );
        let _ = recv_all(&mut observer_rx);

        rib.peer_disconnected(peer);

        let mut updates = recv_all(&mut observer_rx);
        updates.sort_by_key(|u| match u {
            OutboundUpdate::Withdraw(p, _) => p.to_string(),
            OutboundUpdate::Announce(a) => a.prefix.to_string(),
        });
        assert_eq!(
            updates,
            vec![
                OutboundUpdate::Withdraw(prefix("5.5.5.0/24"), false),
                OutboundUpdate::Withdraw(prefix("6.6.6.0/24"), false),
            ]
        );
    }

    #[test]
    fn peer_with_no_local_address_is_never_eligible_for_self_address() {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        let (tx, mut rx) = mpsc::unbounded_channel();
        rib.peer_established(peer, false, None, all_afs(), false, None, tx);

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
            vec![OutboundUpdate::Withdraw(prefix("192.168.1.0/24"), true)]
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
        );

        let updates = recv_all(&mut observer_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
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
        );

        let updates = recv_all(&mut observer_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
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
        );
        let initial = recv_all(&mut observer_rx);
        assert_eq!(
            initial,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
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
        );

        let updates = recv_all(&mut observer_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
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
        );

        let updates = recv_all(&mut observer_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
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
        );
        let initial = recv_all(&mut observer_rx);
        assert_eq!(
            initial,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
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
        );

        // The winner is unchanged (still peer_a), so no new announcement is
        // sent — if the oldest-route step didn't apply, peer_b's lower
        // router-id and address would have won at steps 9/10 instead.
        assert!(recv_all(&mut observer_rx).is_empty());
    }
}
