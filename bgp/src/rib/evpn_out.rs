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

use ipnet::IpNet;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use nos_proto::fdb::AD_TAG_ES;
use nos_proto::{AddressFamily, EvpnKey, EvpnRoute as WireRoute, EvpnUpdate};
use tracing::{debug, warn};

use super::{BgpRib, OutboundUpdate, PeerOutbox};
use crate::as_path::AsPath;
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
    pub as_path: AsPath,
    /// `Some` only toward iBGP peers.
    pub local_pref: Option<u32>,
    /// RFC 8326 `GRACEFUL_SHUTDOWN` toward an eBGP peer with the knob on.
    pub communities: Vec<u32>,
    pub extended_communities: Vec<u64>,
    /// Type-3 only.
    pub pmsi: Option<Pmsi>,
}

/// RFC 4271 §5.1.5's default, as `rib.rs`'s `DEFAULT_LOCAL_PREF`.
const LOCAL_PREF: u32 = 100;

/// Who pushed a set of local EVPN routes: one `nos-fdbd` (a broadcast domain's
/// MAC-VRF) or one `nos-ribd` (a routing table's IP-VRF). A domain and a table
/// may share a name, so they never share a slot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EvpnSource {
    Domain(String),
    Table(String),
}

/// Whether a received route feeds an IP-VRF's `nos-ribd` (`to_tables`) or a
/// MAC-VRF's `nos-fdbd`: a Type-5 goes to tables only, a symmetric IRB
/// MAC+IP (RFC 9135, Label2 set) to both, everything else to domains only.
#[must_use]
pub fn feeds(r: &WireRoute, to_tables: bool) -> bool {
    match r.key {
        EvpnKey::IpPrefix { .. } => to_tables,
        EvpnKey::MacIp { .. } if r.l3_vni.is_some() => true,
        _ => !to_tables,
    }
}

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
            // RFC 9135 §5.1: Label2 is the IP-VRF's L3 VNI (symmetric IRB).
            labels: std::iter::once(r.vni).chain(r.l3_vni).collect(),
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
        // RFC 9136 §4.4.1 "interface-less": no ESI, no gateway IP (zero of
        // the prefix's family), the L3 VNI as the label.
        EvpnKey::IpPrefix { rd, prefix } => EvpnNlri::IpPrefix {
            rd: *rd,
            esi: [0; 10],
            tag: 0,
            prefix: *prefix,
            gateway: if prefix.addr().is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            },
            label: r.vni,
        },
    }
}

fn advertise(outbox: &PeerOutbox, local_asn: u32, r: &WireRoute) -> Option<AdvertisedEvpn> {
    if !outbox.negotiated_afs.contains(&AddressFamily::L2vpnEvpn) {
        return None;
    }
    // RFC 4684 filters VPN NLRI; Type-4 (ES-Import) is never held back
    // (RFC 7432 section 7.6, #875).
    if !matches!(r.key, EvpnKey::EthernetSegment { .. })
        && outbox
            .rtc_interest
            .as_ref()
            .is_some_and(|i| !i.permits(&r.ext_communities))
    {
        return None;
    }
    Some(AdvertisedEvpn {
        nlri: nlri_of(r),
        next_hop: r.next_hop,
        // RFC 5065 §4.1, as `rib::build_advertisement`.
        as_path: if outbox.is_ibgp {
            AsPath::default()
        } else if outbox.is_confed {
            let mut p = AsPath::default();
            p.prepend_confed_seq(local_asn);
            p
        } else {
            let mut p = AsPath::default();
            outbox.prepend_external(&mut p, local_asn);
            p
        },
        local_pref: (outbox.is_ibgp || outbox.is_confed).then_some(LOCAL_PREF),
        // EVPN bypasses export policy, so the tag is unconditional.
        communities: if outbox.gs_send && !outbox.is_ibgp && !outbox.is_confed {
            vec![crate::message::COMMUNITY_GRACEFUL_SHUTDOWN]
        } else {
            Vec::new()
        },
        extended_communities: r.ext_communities.clone(),
        pmsi: match &r.key {
            EvpnKey::Imet { origin, .. } => Some(Pmsi {
                vni: r.vni,
                tunnel_ip: *origin,
            }),
            EvpnKey::Mac { .. }
            | EvpnKey::MacIp { .. }
            | EvpnKey::EthernetSegment { .. }
            | EvpnKey::EthernetAd { .. }
            | EvpnKey::IpPrefix { .. } => None,
        },
    })
}

impl BgpRib {
    /// Applies one `RedistributeMacs` push from `nos-fdbd`'s `domain`.
    pub fn apply_evpn_local(&mut self, domain: &str, update: EvpnUpdate) {
        self.apply_evpn_source(EvpnSource::Domain(domain.to_string()), update);
    }

    /// How many local EVPN routes are held, across every source.
    pub fn evpn_local_len(&self) -> usize {
        self.evpn_local.values().map(HashMap::len).sum()
    }

    /// Applies one push of local EVPN routes — `RedistributeMacs` from a
    /// domain's `nos-fdbd` or `RedistributeEvpnPrefixes` from a table's
    /// `nos-ribd` (MAC mobility is a no-op for its Type-5 routes).
    pub fn apply_evpn_source(&mut self, source: EvpnSource, update: EvpnUpdate) {
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
                    .insert(source, new.clone())
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
                    .entry(source)
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
                let old = self
                    .evpn_local
                    .get_mut(&source)
                    .and_then(|t| t.remove(&key));
                if let Some(r) = old {
                    self.withdraw_evpn(&nlri_of(&r));
                }
            }
            // Staged per source by `server.rs`'s `EvpnStaging` (#724).
            EvpnUpdate::FullPart(_) => {}
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
        let Some((vni, mac, esi)) = super::evpn_mac_key(&nlri_of(&r)) else {
            return (r, true);
        };
        let seq = self.mac_mobility.local_seq(vni, mac, r.next_hop, esi);
        r.ext_communities
            .retain(|c| nos_proto::evpn_id::parse_mac_mobility(*c).is_none());
        r.ext_communities
            .push(nos_proto::evpn_id::mac_mobility_ext(seq, false));
        let wins = self
            .mac_mobility
            .candidate(vni, mac, r.next_hop, esi, seq, false, now);
        if !wins {
            warn!(vni, mac = %format_mac(mac), "local mac not advertised: mobility frozen");
        }
        (r, wins)
    }

    /// After a remote MAC/IP route is learned (`rib.rs`'s `handle_update`,
    /// right after registering it as a mobility candidate), withdraws any
    /// local advertisement for the same `(VNI, MAC)` that no longer holds it —
    /// RFC 7432 §15.1: a PE that learns a remote route with a different ESI
    /// and a higher sequence number for a MAC it also advertises locally must
    /// withdraw its own claim. A local route on the holder's own non-zero ESI
    /// (the same multi-homed segment) is never withdrawn. The MAC stays known to `nos-fdbd`'s own local-MAC
    /// bookkeeping; a later fresh push (a real local re-learn) picks a new,
    /// higher sequence and reclaims it via `apply_evpn_local`.
    pub(super) fn mac_mobility_recheck(&mut self, vni: u32, mac: [u8; 6]) {
        let stale: Vec<WireRoute> = self
            .evpn_local
            .values()
            .flat_map(HashMap::values)
            .filter(|r| {
                super::evpn_mac_key(&nlri_of(r)).is_some_and(|(v, m, esi)| {
                    (v, m) == (vni, mac) && !self.mac_mobility.holds(vni, mac, r.next_hop, esi)
                })
            })
            .cloned()
            .collect();
        for r in stale {
            self.withdraw_evpn(&nlri_of(&r));
            warn!(vni, mac = %format_mac(mac), "local mac mobility lost: remote advertisement now wins");
        }
    }

    fn announce_evpn(&mut self, r: &WireRoute) {
        // Deferring (graceful restart): `announce_evpn_to` sends it after.
        if self.deferring() {
            return;
        }
        for (peer, outbox) in &self.peer_outboxes {
            let Some(adv) = advertise(outbox, self.local_asn, r) else {
                continue;
            };
            let sent = self.evpn_adj_rib_out.entry(*peer).or_default();
            if sent.get(&adv.nlri) != Some(&adv) {
                sent.insert(adv.nlri.clone(), adv.clone());
                outbox.tx.send(OutboundUpdate::AnnounceEvpn(adv));
            }
        }
    }

    fn withdraw_evpn(&mut self, nlri: &EvpnNlri) {
        if self.deferring() {
            return;
        }
        for (peer, outbox) in &self.peer_outboxes {
            if self
                .evpn_adj_rib_out
                .get_mut(peer)
                .is_some_and(|sent| sent.remove(nlri).is_some())
            {
                outbox.tx.send(OutboundUpdate::WithdrawEvpn(nlri.clone()));
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
                outbox.tx.send(OutboundUpdate::AnnounceEvpn(adv));
            }
        }
    }

    /// RT-Constraint membership of `peer` changed at `keys`: announce the
    /// local routes they newly cover, withdraw those no longer wanted.
    pub(super) fn resync_evpn(&mut self, peer: IpAddr, keys: &[super::RtcKey]) {
        let Some(outbox) = self.peer_outboxes.get(&peer) else {
            return;
        };
        let sent = self.evpn_adj_rib_out.entry(peer).or_default();
        for r in self.evpn_local.values().flat_map(HashMap::values) {
            if !keys.iter().any(|k| k.covers_any(&r.ext_communities)) {
                continue;
            }
            let nlri = nlri_of(r);
            match advertise(outbox, self.local_asn, r) {
                Some(adv) if sent.get(&nlri) != Some(&adv) => {
                    sent.insert(nlri, adv.clone());
                    outbox.tx.send(OutboundUpdate::AnnounceEvpn(adv));
                }
                Some(_) => {}
                None => {
                    if sent.remove(&nlri).is_some() {
                        outbox.tx.send(OutboundUpdate::WithdrawEvpn(nlri));
                    }
                }
            }
        }
    }

    /// Route refresh (RFC 2918) of EVPN: re-sends what `peer` was last sent.
    pub(super) fn resend_evpn(&self, peer: IpAddr) {
        let Some(outbox) = self.peer_outboxes.get(&peer) else {
            return;
        };
        for adv in self
            .evpn_adj_rib_out
            .get(&peer)
            .into_iter()
            .flat_map(HashMap::values)
        {
            outbox.tx.send(OutboundUpdate::AnnounceEvpn(adv.clone()));
        }
    }

    /// Every received Type-2/3/4 route, across peers, as the wire shape
    /// `nos-fdbd` consumes. A Type-2 MAC (or MAC+IP) learned from several
    /// peers under different RDs still collapses to one PE's copies — among
    /// the PEs that hold its `(VNI, MAC)` under RFC 7432 §15 mobility (the
    /// winner, or every PE on the winner's multi-homed segment), the lowest
    /// VTEP — since `nos-fdbd`'s own `EvpnKey` keeps different RDs apart and
    /// expects one route per `(VNI, MAC)` (see `mac_mobility`). RFC 8326: among
    /// those, the highest `LOCAL_PREF` wins before the lowest VTEP, and a Type-5
    /// below its `(prefix, label)` group's best `LOCAL_PREF` is withheld.
    ///
    /// Type-5 (`EvpnKey::IpPrefix`) routes are in it too; `fdb_push_snapshot`
    /// and `rib_evpn_push_snapshot` split it per consumer.
    pub fn evpn_push_snapshot(&self) -> HashMap<EvpnKey, WireRoute> {
        let held = |nlri: &EvpnNlri, next_hop: IpAddr| {
            super::evpn_mac_key(nlri).map(|(vni, mac, esi)| {
                ((vni, mac), self.mac_mobility.holds(vni, mac, next_hop, esi))
            })
        };
        // RFC 7432 §15: only a PE holding a Type-2's (VNI, MAC) reaches
        // nos-fdbd — a losing PE's copy (a different RD, so it wouldn't
        // otherwise collide with the winner's own key below) is filtered out
        // here — and of a multi-homed segment's PEs, only the lowest VTEP.
        // RFC 8326: among holders, the highest LOCAL_PREF first (a drained
        // PE's copies carry 0), then the lowest VTEP. Mobility decides first.
        let mut chosen: HashMap<(u32, [u8; 6]), (Reverse<u32>, IpAddr)> = HashMap::new();
        // Type-5 has no mobility: a copy below the best LOCAL_PREF for its
        // (prefix, label) is withheld, a lone copy stays.
        let mut best_t5: HashMap<(IpNet, u32), u32> = HashMap::new();
        for route in self.evpn_adj_rib_in.values().flat_map(HashMap::values) {
            let nlri = &route.nlri;
            if let Some((key, true)) = held(nlri, route.next_hop) {
                let rank = (Reverse(route.local_pref), route.next_hop);
                let best = chosen.entry(key).or_insert(rank);
                *best = (*best).min(rank);
            }
            if let EvpnNlri::IpPrefix { prefix, label, .. } = nlri {
                let best = best_t5.entry((*prefix, *label)).or_insert(route.local_pref);
                *best = (*best).max(route.local_pref);
            }
        }
        let mut out = HashMap::new();
        for route in self.evpn_adj_rib_in.values().flat_map(HashMap::values) {
            let nlri = &route.nlri;
            if let Some((key, _)) = held(nlri, route.next_hop)
                && chosen.get(&key).map(|c| c.1) != Some(route.next_hop)
            {
                continue;
            }
            if let EvpnNlri::IpPrefix { prefix, label, .. } = nlri
                && best_t5.get(&(*prefix, *label)) > Some(&route.local_pref)
            {
                continue;
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
                // ponytail: only the RFC 9136 §4.4.1 interface-less form; the
                // gateway-IP and ESI overlay indexes (§4.3, §4.4.2) need a
                // recursive resolution nos-ribd doesn't do.
                EvpnNlri::IpPrefix {
                    rd,
                    esi,
                    prefix,
                    gateway,
                    label,
                    ..
                } => {
                    if !gateway.is_unspecified() || esi.iter().any(|b| *b != 0) {
                        debug!(route = %nlri, "evpn type-5 with an overlay index skipped");
                        continue;
                    }
                    (
                        EvpnKey::IpPrefix {
                            rd: *rd,
                            prefix: *prefix,
                        },
                        *label,
                        [0; 10],
                    )
                }
                EvpnNlri::Unknown { .. } => continue,
            };
            // RFC 9135 §5.2: a non-zero Label2 means symmetric IRB.
            let l3_vni = match nlri {
                EvpnNlri::MacIp {
                    ip: Some(_),
                    labels,
                    ..
                } => labels.get(1).copied().filter(|l| *l != 0),
                _ => None,
            };
            out.insert(
                key.clone(),
                WireRoute {
                    key,
                    vni,
                    next_hop: route.next_hop,
                    ext_communities: route.extended_communities.clone(),
                    esi,
                    l3_vni,
                },
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac_ip(l3_vni: Option<u32>) -> WireRoute {
        WireRoute {
            key: EvpnKey::MacIp {
                rd: [0; 8],
                mac: [2, 0, 0, 0, 0, 9],
                ip: "10.72.0.20".parse().unwrap(),
            },
            vni: 10_300,
            next_hop: "10.50.0.3".parse().unwrap(),
            ext_communities: vec![],
            esi: [0; 10],
            l3_vni,
        }
    }

    #[test]
    fn a_symmetric_mac_ip_carries_the_l3_vni_as_label2() {
        let labels = |r: &WireRoute| match nlri_of(r) {
            EvpnNlri::MacIp { labels, .. } => labels,
            _ => unreachable!(),
        };
        assert_eq!(labels(&mac_ip(Some(5000))), vec![10_300, 5000]);
        assert_eq!(labels(&mac_ip(None)), vec![10_300]);
    }

    #[test]
    fn a_symmetric_mac_ip_feeds_both_consumers() {
        let type5 = WireRoute {
            key: EvpnKey::IpPrefix {
                rd: [0; 8],
                prefix: "10.2.0.0/24".parse().unwrap(),
            },
            ..mac_ip(None)
        };
        let mac = WireRoute {
            key: EvpnKey::Mac {
                rd: [0; 8],
                mac: [2, 0, 0, 0, 0, 9],
            },
            ..mac_ip(None)
        };
        for (r, tables, domains) in [
            (mac_ip(Some(5000)), true, true),
            (mac_ip(None), false, true),
            (type5, true, false),
            (mac, false, true),
        ] {
            assert_eq!(
                (feeds(&r, true), feeds(&r, false)),
                (tables, domains),
                "{r:?}"
            );
        }
    }
}
