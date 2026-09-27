//! EVPN origination and the fdbd-facing views of `BgpRib`.
//!
//! `nos-fdbd` pushes fully formed routes (RD, Route Targets, VTEP next-hop,
//! VNI) per broadcast domain (`BgpRequest::RedistributeMacs`); this module
//! only carries them to every peer that negotiated AFI 25 / SAFI 70, and
//! hands the *received* EVPN routes back out as `nos_proto::EvpnRoute`s for
//! `fdb_push_client`. Deltas only: one changed MAC touches one NLRI per peer,
//! never the whole table (see `apply_evpn_local`).
//!
//! A Type-2's ESI rides in `WireRoute::esi`; Type-4 (Ethernet Segment) routes
//! are originated and received like any other key.
//!
//! ponytail: EVPN bypasses export policy (RPL's `Input` is prefix-shaped) and
//! the local routes are announced verbatim — no best-path between a local and
//! a received route for the same NLRI, other than RFC 7432 §15 MAC mobility
//! (`with_local_mobility`/`mac_mobility_recheck`, below).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use nos_proto::fdb::AD_TAG_ES;
use nos_proto::{AddressFamily, EvpnKey, EvpnRoute as WireRoute, EvpnUpdate};
use tracing::warn;

use super::{BgpRib, OutboundUpdate, PeerOutbox};
use crate::evpn::EvpnNlri;
use crate::mac_mobility::format_mac;
use crate::message::Pmsi;

/// One EVPN route rewritten for one peer.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvertisedEvpn {
    pub nlri: EvpnNlri,
    /// The VTEP, verbatim — never rewritten to next-hop-self.
    pub next_hop: IpAddr,
    /// Our ASN toward an eBGP peer, empty toward iBGP.
    pub as_path: Vec<u32>,
    /// `Some` only toward iBGP peers.
    pub local_pref: Option<u32>,
    pub extended_communities: Vec<u64>,
    /// Type-3 only.
    pub pmsi: Option<Pmsi>,
}

/// RFC 4271 §5.1.5's default, as `rib.rs`'s `DEFAULT_LOCAL_PREF`.
const LOCAL_PREF: u32 = 100;

fn nlri_of(r: &WireRoute) -> EvpnNlri {
    match &r.key {
        EvpnKey::Mac { rd, mac } => EvpnNlri::MacIp {
            rd: *rd,
            esi: r.esi,
            tag: 0,
            mac: *mac,
            ip: None,
            labels: vec![r.vni],
        },
        EvpnKey::MacIp { rd, mac, ip } => EvpnNlri::MacIp {
            rd: *rd,
            esi: r.esi,
            tag: 0,
            mac: *mac,
            ip: Some(*ip),
            labels: vec![r.vni],
        },
        EvpnKey::Imet { rd, origin } => EvpnNlri::InclusiveMulticast {
            rd: *rd,
            tag: 0,
            origin: *origin,
        },
        EvpnKey::EthernetSegment { rd, esi, origin } => EvpnNlri::EthernetSegment {
            rd: *rd,
            esi: *esi,
            origin: *origin,
        },
        // `origin` is not on the wire: the NLRI has no originator.
        EvpnKey::EthernetAd { rd, esi, tag, .. } => EvpnNlri::EthernetAd {
            rd: *rd,
            esi: *esi,
            tag: *tag,
            // RFC 8365 §5.1.3: a per-EVI route's label field carries the VNI.
            label: if *tag == AD_TAG_ES { 0 } else { r.vni },
        },
    }
}

fn advertise(outbox: &PeerOutbox, local_asn: u32, r: &WireRoute) -> Option<AdvertisedEvpn> {
    if !outbox.negotiated_afs.contains(&AddressFamily::L2vpnEvpn) {
        return None;
    }
    Some(AdvertisedEvpn {
        nlri: nlri_of(r),
        next_hop: r.next_hop,
        as_path: if outbox.is_ibgp {
            Vec::new()
        } else {
            vec![local_asn]
        },
        local_pref: outbox.is_ibgp.then_some(LOCAL_PREF),
        extended_communities: r.ext_communities.clone(),
        pmsi: match &r.key {
            EvpnKey::Imet { origin, .. } => Some(Pmsi {
                vni: r.vni,
                tunnel_ip: *origin,
            }),
            EvpnKey::Mac { .. }
            | EvpnKey::MacIp { .. }
            | EvpnKey::EthernetSegment { .. }
            | EvpnKey::EthernetAd { .. } => None,
        },
    })
}

impl BgpRib {
    /// Applies one `RedistributeMacs` push from `nos-fdbd`'s `domain`.
    pub fn apply_evpn_local(&mut self, domain: &str, update: EvpnUpdate) {
        let now = Instant::now();
        match update {
            EvpnUpdate::Full(routes) => {
                let prepared: Vec<(WireRoute, bool)> = routes
                    .into_iter()
                    .map(|r| self.with_local_mobility(r, now))
                    .collect();
                let new: HashMap<EvpnKey, WireRoute> = prepared
                    .iter()
                    .map(|(r, _)| (r.key.clone(), r.clone()))
                    .collect();
                let old = self
                    .evpn_local
                    .insert(domain.to_string(), new.clone())
                    .unwrap_or_default();
                for (key, r) in &old {
                    // The ESI is part of a Type-2's wire identity, so a route
                    // that moved onto/off a segment withdraws its old NLRI.
                    if new.get(key).map(nlri_of) != Some(nlri_of(r)) {
                        self.withdraw_evpn(&nlri_of(r));
                    }
                }
                for (r, wins) in &prepared {
                    if *wins {
                        self.announce_evpn(r);
                    }
                }
            }
            EvpnUpdate::Add(r) => {
                let (r, wins) = self.with_local_mobility(r, now);
                let old = self
                    .evpn_local
                    .entry(domain.to_string())
                    .or_default()
                    .insert(r.key.clone(), r.clone());
                if let Some(old) = old.filter(|o| nlri_of(o) != nlri_of(&r)) {
                    self.withdraw_evpn(&nlri_of(&old));
                }
                if wins {
                    self.announce_evpn(&r);
                }
            }
            EvpnUpdate::Remove(key) => {
                let old = self.evpn_local.get_mut(domain).and_then(|t| t.remove(&key));
                if let Some(r) = old {
                    self.withdraw_evpn(&nlri_of(&r));
                }
            }
        }
    }

    /// Attaches an RFC 7432 §7.7 MAC Mobility community to a Type-2 route
    /// pushed by `nos-fdbd`, with a sequence one past whatever `(VNI, MAC)`'s
    /// current winner (local or remote) holds if some other owner currently
    /// holds it — so a genuine local re-learn always outranks a stale remote
    /// copy — or `owner`'s own unchanged sequence when it already holds it
    /// (an ordinary re-push isn't a re-learn). Registers it as a mobility
    /// candidate either way. Returns the (possibly rewritten) route and
    /// whether it's the current winner and should actually be announced —
    /// `false` only when `(VNI, MAC)` is frozen as a duplicate (see
    /// `mac_mobility::MacMobility`). A route with no `(VNI, MAC)` identity
    /// (only Type-2 has one) passes through unchanged, always announced.
    fn with_local_mobility(&mut self, mut r: WireRoute, now: Instant) -> (WireRoute, bool) {
        let Some((vni, mac)) = super::evpn_mac_key(&nlri_of(&r)) else {
            return (r, true);
        };
        let seq = self.mac_mobility.local_seq(vni, mac, r.next_hop);
        r.ext_communities
            .retain(|c| nos_proto::evpn_id::parse_mac_mobility(*c).is_none());
        r.ext_communities
            .push(nos_proto::evpn_id::mac_mobility_ext(seq, false));
        let wins = self
            .mac_mobility
            .candidate(vni, mac, r.next_hop, seq, false, now);
        if !wins {
            warn!(vni, mac = %format_mac(mac), "local mac not advertised: mobility frozen");
        }
        (r, wins)
    }

    /// After a remote MAC/IP route is learned (`rib.rs`'s `handle_update`,
    /// right after registering it as a mobility candidate), withdraws any
    /// local advertisement for the same `(VNI, MAC)` that no longer wins —
    /// RFC 7432 §15: a PE that learns a remote route with a properly higher
    /// sequence number for a MAC it also advertises locally must withdraw
    /// its own claim. The MAC stays known to `nos-fdbd`'s own local-MAC
    /// bookkeeping; a later fresh push (a real local re-learn) picks a new,
    /// higher sequence and reclaims it via `apply_evpn_local`.
    pub(super) fn mac_mobility_recheck(&mut self, vni: u32, mac: [u8; 6]) {
        let Some(winner) = self.mac_mobility.winner(vni, mac) else {
            return;
        };
        let stale: Vec<WireRoute> = self
            .evpn_local
            .values()
            .flat_map(HashMap::values)
            .filter(|r| {
                super::evpn_mac_key(&nlri_of(r)) == Some((vni, mac)) && r.next_hop != winner
            })
            .cloned()
            .collect();
        for r in stale {
            self.withdraw_evpn(&nlri_of(&r));
            warn!(vni, mac = %format_mac(mac), "local mac mobility lost: remote advertisement now wins");
        }
    }

    fn announce_evpn(&mut self, r: &WireRoute) {
        for (peer, outbox) in &self.peer_outboxes {
            let Some(adv) = advertise(outbox, self.local_asn, r) else {
                continue;
            };
            let sent = self.evpn_adj_rib_out.entry(*peer).or_default();
            if sent.get(&adv.nlri) != Some(&adv) {
                sent.insert(adv.nlri.clone(), adv.clone());
                let _ = outbox.tx.send(OutboundUpdate::AnnounceEvpn(adv));
            }
        }
    }

    fn withdraw_evpn(&mut self, nlri: &EvpnNlri) {
        for (peer, outbox) in &self.peer_outboxes {
            if self
                .evpn_adj_rib_out
                .get_mut(peer)
                .is_some_and(|sent| sent.remove(nlri).is_some())
            {
                let _ = outbox.tx.send(OutboundUpdate::WithdrawEvpn(nlri.clone()));
            }
        }
    }

    /// Initial advertisement of every local EVPN route to a just-established
    /// peer (called by `peer_established`).
    pub(super) fn announce_evpn_to(&mut self, peer: IpAddr) {
        let Some(outbox) = self.peer_outboxes.get(&peer) else {
            return;
        };
        let sent = self.evpn_adj_rib_out.entry(peer).or_default();
        sent.clear();
        for r in self.evpn_local.values().flat_map(HashMap::values) {
            if let Some(adv) = advertise(outbox, self.local_asn, r) {
                sent.insert(adv.nlri.clone(), adv.clone());
                let _ = outbox.tx.send(OutboundUpdate::AnnounceEvpn(adv));
            }
        }
    }

    /// Every received Type-2/3/4 route, across peers, as the wire shape
    /// `nos-fdbd` consumes. A Type-2 MAC (or MAC+IP) learned from two peers
    /// under two different RDs still collapses to at most one entry — the
    /// RFC 7432 §15 mobility winner for its `(VNI, MAC)`, not an arbitrary
    /// iteration order — since `nos-fdbd`'s own `EvpnKey` keeps different RDs
    /// apart (see `mac_mobility`).
    pub fn evpn_push_snapshot(&self) -> HashMap<EvpnKey, WireRoute> {
        let mut out = HashMap::new();
        for (nlri, route) in self.evpn_adj_rib_in.values().flatten() {
            // RFC 7432 §15: only the MAC-mobility winner for a Type-2's
            // (VNI, MAC) reaches nos-fdbd — a losing PE's copy (a different
            // RD, so it wouldn't otherwise collide with the winner's own key
            // below) is filtered out here instead.
            if let Some((vni, mac)) = super::evpn_mac_key(nlri) {
                if self.mac_mobility.winner(vni, mac) != Some(route.next_hop) {
                    continue;
                }
            }
            let (key, vni, esi) = match nlri {
                EvpnNlri::MacIp {
                    rd,
                    esi,
                    mac,
                    ip,
                    labels,
                    ..
                } => (
                    match ip {
                        Some(ip) => EvpnKey::MacIp {
                            rd: *rd,
                            mac: *mac,
                            ip: *ip,
                        },
                        None => EvpnKey::Mac { rd: *rd, mac: *mac },
                    },
                    labels.first().copied().unwrap_or(0),
                    *esi,
                ),
                EvpnNlri::InclusiveMulticast { rd, origin, .. } => (
                    EvpnKey::Imet {
                        rd: *rd,
                        origin: *origin,
                    },
                    route.pmsi_vni.unwrap_or(0),
                    [0; 10],
                ),
                EvpnNlri::EthernetSegment { rd, esi, origin } => (
                    EvpnKey::EthernetSegment {
                        rd: *rd,
                        esi: *esi,
                        origin: *origin,
                    },
                    0,
                    *esi,
                ),
                EvpnNlri::EthernetAd {
                    rd,
                    esi,
                    tag,
                    label,
                } => (
                    EvpnKey::EthernetAd {
                        rd: *rd,
                        esi: *esi,
                        tag: *tag,
                        origin: route.next_hop,
                    },
                    if *tag == AD_TAG_ES { 0 } else { *label },
                    *esi,
                ),
                _ => continue,
            };
            out.insert(
                key.clone(),
                WireRoute {
                    key,
                    vni,
                    next_hop: route.next_hop,
                    ext_communities: route.extended_communities.clone(),
                    esi,
                },
            );
        }
        out
    }
}
