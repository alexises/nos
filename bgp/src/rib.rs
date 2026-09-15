//! The BGP RIB engine: Adj-RIB-In per peer, a locally-redistributed route
//! set (fed by `nos-ribd` via `nos_proto::RedistributeUpdate`), a cached
//! Loc-RIB best-path per prefix, and per-peer outbound channels used to push
//! `OutboundUpdate`s out to each `fsm::run` task.
//!
//! This deliberately implements the **simplified** decision/propagation
//! rules documented in the implementation plan, not full RFC 4271 §9.1.2:
//!
//! - Best path: (1) higher `LOCAL_PREF`, (2) shorter `AS_PATH`, (3) a
//!   locally-redistributed route beats any peer-learned route, (4) lowest
//!   advertising peer address as a final deterministic tiebreak. No MED,
//!   origin-type ordering, IGP metric, or router-id tiebreaks.
//! - Next-hop rewriting is peer-group configurable (`nos_proto::NextHopMode`
//!   — `SelfAddress`/`Unchanged`), defaulting to `SelfAddress` for an eBGP
//!   peer and `Unchanged` for an iBGP one. `Unchanged` re-advertises the
//!   route's own stored next-hop (the address it was received with, for a
//!   peer-learned route); a locally-redistributed route has no such stored
//!   value, so it always gets next-hop-self regardless of mode.
//! - Standard iBGP split-horizon (no route reflection): a route learned via
//!   one iBGP peer is never re-advertised to another iBGP peer.
//! - `AS_PATH` is prepended with our own ASN only toward eBGP peers;
//!   `LOCAL_PREF` is included only toward iBGP peers.
//! - A received route whose `AS_PATH` already contains our own ASN is dropped
//!   (loop prevention), not just deprioritized.
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

use ipnet::Ipv4Net;
use nos_proto::{NextHopMode, RedistributeUpdate};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::message::{self, UpdateMessage};

/// RFC 4271 §5.1.5's default `LOCAL_PREF`, applied whenever a peer's UPDATE
/// omits the attribute (or for every locally-redistributed route, which
/// carries no wire attributes at all).
const DEFAULT_LOCAL_PREF: u32 = 100;

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
    /// Meaningless when `origin == Local`.
    pub learned_via_ibgp: bool,
    /// The `NEXT_HOP` this route was received with, for `origin ==
    /// Peer(_)` — read back out when a destination peer-group's `next_hop`
    /// resolves to `NextHopMode::Unchanged`. Always `None` for `origin ==
    /// Local`: a locally-redistributed route has no "received" next-hop to
    /// preserve, so it always gets next-hop-self regardless of mode.
    pub next_hop: Option<Ipv4Addr>,
}

/// One update this instance needs to send out over a specific peer's
/// session.
#[derive(Debug, Clone, PartialEq)]
pub enum OutboundUpdate {
    Announce(AdvertisedRoute),
    Withdraw(Ipv4Net),
}

/// A route rewritten for advertisement toward one specific peer.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvertisedRoute {
    pub prefix: Ipv4Net,
    /// Already rewritten for the destination peer (our ASN prepended iff
    /// eBGP).
    pub as_path: Vec<u32>,
    /// Rewritten per the destination peer-group's effective `NextHopMode` —
    /// either that peer's own session's local address (`SelfAddress`) or the
    /// route's stored next-hop (`Unchanged`).
    pub next_hop: Ipv4Addr,
    /// `Some` only toward iBGP peers.
    pub local_pref: Option<u32>,
    pub origin: message::Origin,
}

struct PeerOutbox {
    tx: mpsc::UnboundedSender<OutboundUpdate>,
    is_ibgp: bool,
    /// `None` if this peer's own TCP transport turned out not to have an
    /// IPv4 local address (e.g. a v6 transport) — such a peer is never
    /// eligible for any advertisement, since next-hop-self has nothing to
    /// offer it.
    local_addr: Option<Ipv4Addr>,
    /// This peer-group's configured next-hop override, if any — `None`
    /// resolves to `SelfAddress` for an eBGP peer, `Unchanged` for an iBGP
    /// one (see `build_advertisement`).
    next_hop_mode: Option<NextHopMode>,
}

/// The BGP RIB engine for one `nos-bgpd` instance. See the module doc
/// comment for the locking model.
pub struct BgpRib {
    local_asn: u32,
    adj_rib_in: HashMap<IpAddr, HashMap<Ipv4Net, RibRoute>>,
    redistributed: HashMap<Ipv4Net, RibRoute>,
    loc_rib: HashMap<Ipv4Net, RibRoute>,
    /// What we've last told each peer, for correct withdrawals.
    adj_rib_out: HashMap<IpAddr, HashSet<Ipv4Net>>,
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
    pub fn peer_established(
        &mut self,
        peer: IpAddr,
        is_ibgp: bool,
        local_addr: Option<Ipv4Addr>,
        next_hop_mode: Option<NextHopMode>,
        tx: mpsc::UnboundedSender<OutboundUpdate>,
    ) {
        self.peer_outboxes.insert(
            peer,
            PeerOutbox {
                tx,
                is_ibgp,
                local_addr,
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

    /// Handles one inbound UPDATE from `from`. Withdrawals are always
    /// processed first, unconditionally; the announcement side is dropped
    /// entirely (with a `warn!`) if the `AS_PATH` already contains our own
    /// ASN (loop prevention), never partially applied.
    pub fn handle_update(&mut self, from: IpAddr, remote_is_ibgp: bool, update: UpdateMessage) {
        let mut touched: HashSet<Ipv4Net> = HashSet::new();

        if !update.withdrawn_routes.is_empty() {
            let table = self.adj_rib_in.entry(from).or_default();
            for prefix in &update.withdrawn_routes {
                if table.remove(prefix).is_some() {
                    touched.insert(*prefix);
                }
            }
        }

        if !update.nlri.is_empty() {
            let Some(attrs) = update.attributes else {
                // parse_update never actually produces this (attributes is
                // Some iff nlri is non-empty), but stay defensive.
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
                let route = RibRoute {
                    origin: RouteOrigin::Peer(from),
                    as_path: attrs.as_path,
                    bgp_origin: attrs.origin,
                    local_pref: attrs.local_pref.unwrap_or(DEFAULT_LOCAL_PREF),
                    learned_via_ibgp: remote_is_ibgp,
                    next_hop: Some(attrs.next_hop),
                };
                for prefix in &update.nlri {
                    info!(peer = %from, "bgp: learned route for {prefix} into adj-rib-in");
                    table.insert(*prefix, route.clone());
                    touched.insert(*prefix);
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
                let old_keys: HashSet<Ipv4Net> = self.redistributed.keys().copied().collect();
                let new_keys: HashSet<Ipv4Net> = new_redistributed.keys().copied().collect();
                let touched: Vec<Ipv4Net> =
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
    fn recompute_and_propagate(&mut self, prefix: Ipv4Net) {
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
                            let _ = outbox.tx.send(OutboundUpdate::Withdraw(prefix));
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
        learned_via_ibgp: false,
        next_hop: None,
    }
}

/// The simplified four-step best-path decision documented in the module doc
/// comment. `candidates` is `(route, source_peer)` — `source_peer` is `None`
/// for a locally-redistributed route, used only for the final tiebreak.
fn best_path(candidates: &[(RibRoute, Option<IpAddr>)]) -> Option<RibRoute> {
    candidates
        .iter()
        .max_by(|(a, a_peer), (b, b_peer)| {
            a.local_pref
                .cmp(&b.local_pref)
                .then_with(|| b.as_path.len().cmp(&a.as_path.len()))
                .then_with(|| {
                    // A Local route beats any Peer(_) route.
                    let a_is_local = matches!(a.origin, RouteOrigin::Local);
                    let b_is_local = matches!(b.origin, RouteOrigin::Local);
                    a_is_local.cmp(&b_is_local)
                })
                .then_with(|| {
                    // Lowest peer address wins the tiebreak — reverse the
                    // comparison since `max_by` favors the greater element,
                    // and `None` (a local route) never reaches this arm
                    // (already decided by the previous step).
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
/// (split-horizon, source-peer echo, no IPv4 local address).
fn build_advertisement(
    prefix: Ipv4Net,
    best: &RibRoute,
    peer: IpAddr,
    outbox: &PeerOutbox,
    local_asn: u32,
) -> Option<AdvertisedRoute> {
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

    Some(AdvertisedRoute {
        prefix,
        as_path,
        next_hop,
        local_pref,
        origin: best.bgp_origin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(s: &str) -> Ipv4Net {
        s.parse().unwrap()
    }

    fn peer_addr(s: &str) -> IpAddr {
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

    fn register_peer(
        rib: &mut BgpRib,
        peer: IpAddr,
        is_ibgp: bool,
        local_addr: Ipv4Addr,
    ) -> mpsc::UnboundedReceiver<OutboundUpdate> {
        register_peer_with_mode(rib, peer, is_ibgp, local_addr, None)
    }

    fn register_peer_with_mode(
        rib: &mut BgpRib,
        peer: IpAddr,
        is_ibgp: bool,
        local_addr: Ipv4Addr,
        next_hop_mode: Option<NextHopMode>,
    ) -> mpsc::UnboundedReceiver<OutboundUpdate> {
        let (tx, rx) = mpsc::unbounded_channel();
        rib.peer_established(peer, is_ibgp, Some(local_addr), next_hop_mode, tx);
        rx
    }

    fn full_update(routes: Vec<(&str, &str)>) -> RedistributeUpdate {
        RedistributeUpdate::Full(
            routes
                .into_iter()
                .map(|(p, gw)| nos_proto::RedistributedRoute {
                    prefix: prefix(p),
                    gateway: v4(gw),
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
            nlri: nlri.into_iter().map(prefix).collect(),
            attributes: Some(message::PathAttributes {
                origin: message::Origin::Igp,
                as_path,
                next_hop: v4(next_hop),
                local_pref: None,
            }),
        }
    }

    #[test]
    fn redistributed_route_is_announced_to_ebgp_peer_with_prepend_and_no_local_pref() {
        let mut rib = new_rib(65000);
        let peer = peer_addr("10.0.0.1");
        let mut rx = register_peer(&mut rib, peer, false, v4("10.0.0.254"));

        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

        let updates = recv_all(&mut rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                prefix: prefix("192.168.1.0/24"),
                as_path: vec![65000],
                next_hop: v4("10.0.0.254"),
                local_pref: None,
                origin: message::Origin::Igp,
            })]
        );
    }

    #[test]
    fn redistributed_route_is_announced_to_ibgp_peer_with_local_pref_and_no_prepend() {
        let mut rib = new_rib(65000);
        let peer = peer_addr("10.0.0.2");
        let mut rx = register_peer(&mut rib, peer, true, v4("10.0.0.253"));

        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

        let updates = recv_all(&mut rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                prefix: prefix("192.168.1.0/24"),
                as_path: vec![],
                next_hop: v4("10.0.0.253"),
                local_pref: Some(100),
                origin: message::Origin::Igp,
            })]
        );
    }

    #[test]
    fn peer_learned_route_beats_nothing_and_is_never_echoed_back_to_source() {
        let mut rib = new_rib(65000);
        let source = peer_addr("10.0.0.1");
        let mut source_rx = register_peer(&mut rib, source, false, v4("10.0.0.254"));

        rib.handle_update(
            source,
            false,
            ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
        );

        // Never echoed back to the source peer.
        assert!(recv_all(&mut source_rx).is_empty());
    }

    #[test]
    fn peer_learned_route_is_propagated_to_a_third_peer() {
        let mut rib = new_rib(65000);
        let source = peer_addr("10.0.0.1");
        let other = peer_addr("10.0.0.2");
        let _source_rx = register_peer(&mut rib, source, false, v4("10.0.0.254"));
        let mut other_rx = register_peer(&mut rib, other, false, v4("10.0.0.253"));

        rib.handle_update(
            source,
            false,
            ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
        );

        let updates = recv_all(&mut other_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                prefix: prefix("1.2.3.0/24"),
                as_path: vec![65000, 65001],
                next_hop: v4("10.0.0.253"),
                local_pref: None,
                origin: message::Origin::Igp,
            })]
        );
    }

    #[test]
    fn ibgp_split_horizon_never_reflects_between_two_ibgp_peers() {
        let mut rib = new_rib(65000);
        let source = peer_addr("10.0.0.1");
        let other = peer_addr("10.0.0.2");
        let _source_rx = register_peer(&mut rib, source, true, v4("10.0.0.254"));
        let mut other_rx = register_peer(&mut rib, other, true, v4("10.0.0.253"));

        rib.handle_update(
            source,
            true,
            ebgp_update(vec!["1.2.3.0/24"], vec![], "10.0.0.1"),
        );

        assert!(recv_all(&mut other_rx).is_empty());
    }

    #[test]
    fn ebgp_learned_route_is_still_propagated_to_an_ibgp_peer_with_next_hop_unchanged() {
        let mut rib = new_rib(65000);
        let source = peer_addr("10.0.0.1"); // eBGP source
        let ibgp_peer = peer_addr("10.0.0.2");
        let _source_rx = register_peer(&mut rib, source, false, v4("10.0.0.254"));
        let mut ibgp_rx = register_peer(&mut rib, ibgp_peer, true, v4("10.0.0.253"));

        rib.handle_update(
            source,
            false,
            ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
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
                next_hop: v4("10.0.0.1"),
                local_pref: Some(100),
                origin: message::Origin::Igp,
            })]
        );
    }

    #[test]
    fn ibgp_peer_with_next_hop_self_override_rewrites_to_local_address() {
        let mut rib = new_rib(65000);
        let source = peer_addr("10.0.0.1"); // eBGP source
        let ibgp_peer = peer_addr("10.0.0.2");
        let _source_rx = register_peer(&mut rib, source, false, v4("10.0.0.254"));
        let mut ibgp_rx = register_peer_with_mode(
            &mut rib,
            ibgp_peer,
            true,
            v4("10.0.0.253"),
            Some(NextHopMode::SelfAddress),
        );

        rib.handle_update(
            source,
            false,
            ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
        );

        let updates = recv_all(&mut ibgp_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                prefix: prefix("1.2.3.0/24"),
                as_path: vec![65001],
                next_hop: v4("10.0.0.253"),
                local_pref: Some(100),
                origin: message::Origin::Igp,
            })]
        );
    }

    #[test]
    fn ebgp_peer_with_next_hop_unchanged_override_preserves_received_next_hop() {
        let mut rib = new_rib(65000);
        let source = peer_addr("10.0.0.1");
        let other = peer_addr("10.0.0.2");
        let _source_rx = register_peer(&mut rib, source, false, v4("10.0.0.254"));
        let mut other_rx = register_peer_with_mode(
            &mut rib,
            other,
            false,
            v4("10.0.0.253"),
            Some(NextHopMode::Unchanged),
        );

        rib.handle_update(
            source,
            false,
            ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
        );

        let updates = recv_all(&mut other_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                prefix: prefix("1.2.3.0/24"),
                as_path: vec![65000, 65001],
                next_hop: v4("10.0.0.1"),
                local_pref: None,
                origin: message::Origin::Igp,
            })]
        );
    }

    #[test]
    fn redistributed_route_always_gets_next_hop_self_even_with_unchanged_override() {
        let mut rib = new_rib(65000);
        let peer = peer_addr("10.0.0.1");
        let mut rx = register_peer_with_mode(
            &mut rib,
            peer,
            true,
            v4("10.0.0.253"),
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
                next_hop: v4("10.0.0.253"),
                local_pref: Some(100),
                origin: message::Origin::Igp,
            })]
        );
    }

    #[test]
    fn route_with_own_asn_in_as_path_is_dropped_for_loop_prevention() {
        let mut rib = new_rib(65000);
        let source = peer_addr("10.0.0.1");
        let other = peer_addr("10.0.0.2");
        let _source_rx = register_peer(&mut rib, source, false, v4("10.0.0.254"));
        let mut other_rx = register_peer(&mut rib, other, false, v4("10.0.0.253"));

        rib.handle_update(
            source,
            false,
            ebgp_update(vec!["1.2.3.0/24"], vec![65002, 65000, 65001], "10.0.0.1"),
        );

        assert!(recv_all(&mut other_rx).is_empty());
    }

    #[test]
    fn higher_local_pref_wins_best_path() {
        // peer_a/peer_b are eBGP sources (so split-horizon doesn't remove
        // them from consideration for the iBGP observer below) proposing the
        // same prefix with different LOCAL_PREF values.
        let mut rib = new_rib(65000);
        let peer_a = peer_addr("10.0.0.1");
        let peer_b = peer_addr("10.0.0.2");
        let observer = peer_addr("10.0.0.3");
        let _rx_a = register_peer(&mut rib, peer_a, false, v4("10.0.0.254"));
        let _rx_b = register_peer(&mut rib, peer_b, false, v4("10.0.0.253"));
        let mut observer_rx = register_peer(&mut rib, observer, true, v4("10.0.0.252"));

        rib.handle_update(
            peer_a,
            false,
            UpdateMessage {
                withdrawn_routes: vec![],
                nlri: vec![prefix("9.9.9.0/24")],
                attributes: Some(message::PathAttributes {
                    origin: message::Origin::Igp,
                    as_path: vec![],
                    next_hop: v4("10.0.0.1"),
                    local_pref: Some(50),
                }),
            },
        );
        let _ = recv_all(&mut observer_rx);

        rib.handle_update(
            peer_b,
            false,
            UpdateMessage {
                withdrawn_routes: vec![],
                nlri: vec![prefix("9.9.9.0/24")],
                attributes: Some(message::PathAttributes {
                    origin: message::Origin::Igp,
                    as_path: vec![],
                    next_hop: v4("10.0.0.2"),
                    local_pref: Some(200),
                }),
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
                next_hop: v4("10.0.0.2"),
                local_pref: Some(200),
                origin: message::Origin::Igp,
            })]
        );
    }

    #[test]
    fn local_redistributed_route_beats_peer_learned_route_for_same_prefix() {
        let mut rib = new_rib(65000);
        let peer = peer_addr("10.0.0.1");
        let observer = peer_addr("10.0.0.2");
        let _rx = register_peer(&mut rib, peer, false, v4("10.0.0.254"));
        let mut observer_rx = register_peer(&mut rib, observer, false, v4("10.0.0.253"));

        rib.handle_update(
            peer,
            false,
            ebgp_update(vec!["5.5.5.0/24"], vec![65099], "10.0.0.1"),
        );
        let _ = recv_all(&mut observer_rx);

        rib.apply_redistribute_update(full_update(vec![("5.5.5.0/24", "10.9.9.9")]));

        let updates = recv_all(&mut observer_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                prefix: prefix("5.5.5.0/24"),
                as_path: vec![65000],
                next_hop: v4("10.0.0.253"),
                local_pref: None,
                origin: message::Origin::Igp,
            })]
        );
    }

    #[test]
    fn withdrawal_removes_route_and_notifies_downstream_peers() {
        let mut rib = new_rib(65000);
        let peer = peer_addr("10.0.0.1");
        let observer = peer_addr("10.0.0.2");
        let _rx = register_peer(&mut rib, peer, false, v4("10.0.0.254"));
        let mut observer_rx = register_peer(&mut rib, observer, false, v4("10.0.0.253"));

        rib.handle_update(
            peer,
            false,
            ebgp_update(vec!["5.5.5.0/24"], vec![65099], "10.0.0.1"),
        );
        let _ = recv_all(&mut observer_rx);

        rib.handle_update(
            peer,
            false,
            UpdateMessage {
                withdrawn_routes: vec![prefix("5.5.5.0/24")],
                nlri: vec![],
                attributes: None,
            },
        );

        let updates = recv_all(&mut observer_rx);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Withdraw(prefix("5.5.5.0/24"))]
        );
    }

    #[test]
    fn peer_disconnected_withdraws_every_route_it_contributed() {
        let mut rib = new_rib(65000);
        let peer = peer_addr("10.0.0.1");
        let observer = peer_addr("10.0.0.2");
        let _rx = register_peer(&mut rib, peer, false, v4("10.0.0.254"));
        let mut observer_rx = register_peer(&mut rib, observer, false, v4("10.0.0.253"));

        rib.handle_update(
            peer,
            false,
            ebgp_update(vec!["5.5.5.0/24", "6.6.6.0/24"], vec![65099], "10.0.0.1"),
        );
        let _ = recv_all(&mut observer_rx);

        rib.peer_disconnected(peer);

        let mut updates = recv_all(&mut observer_rx);
        updates.sort_by_key(|u| match u {
            OutboundUpdate::Withdraw(p) => p.to_string(),
            OutboundUpdate::Announce(a) => a.prefix.to_string(),
        });
        assert_eq!(
            updates,
            vec![
                OutboundUpdate::Withdraw(prefix("5.5.5.0/24")),
                OutboundUpdate::Withdraw(prefix("6.6.6.0/24")),
            ]
        );
    }

    #[test]
    fn peer_with_no_ipv4_local_address_is_never_eligible() {
        let mut rib = new_rib(65000);
        let peer = peer_addr("10.0.0.1");
        let (tx, mut rx) = mpsc::unbounded_channel();
        rib.peer_established(peer, false, None, None, tx);

        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

        assert!(recv_all(&mut rx).is_empty());
    }

    #[test]
    fn redistribute_full_matching_current_state_is_a_no_op() {
        let mut rib = new_rib(65000);
        let peer = peer_addr("10.0.0.1");
        let mut rx = register_peer(&mut rib, peer, false, v4("10.0.0.254"));

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
        let peer = peer_addr("10.0.0.1");
        let mut rx = register_peer(&mut rib, peer, false, v4("10.0.0.254"));

        rib.apply_redistribute_update(RedistributeUpdate::Remove(prefix("10.10.10.0/24")));
        assert!(recv_all(&mut rx).is_empty());
    }

    #[test]
    fn newly_established_peer_gets_full_initial_advertisement_of_loc_rib() {
        let mut rib = new_rib(65000);
        let first = peer_addr("10.0.0.1");
        let _rx_first = register_peer(&mut rib, first, false, v4("10.0.0.254"));

        rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

        // A second peer joining afterward should get the existing route
        // immediately, without needing a fresh redistribute push.
        let second = peer_addr("10.0.0.2");
        let mut rx_second = register_peer(&mut rib, second, false, v4("10.0.0.253"));

        let updates = recv_all(&mut rx_second);
        assert_eq!(
            updates,
            vec![OutboundUpdate::Announce(AdvertisedRoute {
                prefix: prefix("192.168.1.0/24"),
                as_path: vec![65000],
                next_hop: v4("10.0.0.253"),
                local_pref: None,
                origin: message::Origin::Igp,
            })]
        );
    }
}
