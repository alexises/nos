//! VRF import of received VPN-IPv4/IPv6 paths (RFC 4364 section 4.3.2,
//! #579): every path of the VPN Adj-RIB-In whose Route Targets match a VRF's
//! import set (`VrfSet::import_by_table`) is a candidate in that VRF, the RD
//! stripped, so paths under different RDs for one prefix compete there
//! (section 4.3.5 keeps them apart only in the VPN table itself). The best
//! one per (VRF, prefix) is what `vpn_push_client` resolves and pushes.
//!
//! Snapshot-based like `evpn_push_snapshot`: one derivation covers announce,
//! withdraw, RT change, peer loss, GR purge and a VRF set change.
// ponytail: O(paths x VRFs) per push tick; import incrementally if it ever
// shows in `tools/bench-bgp.sh`. Single best path, no VPN multipath yet.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use ipnet::IpNet;

use super::{decision_cmp, BgpRib, Candidate, VpnRoute};
use crate::vpn::{Rd, VpnKey, VrfSet};

/// One route imported into one VRF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnImport {
    /// The remote PE (the path's BGP next hop), still to resolve in the
    /// underlay.
    pub pe: IpAddr,
    pub labels: Vec<u32>,
    pub rd: Rd,
}

/// A path a VRF refused by Site of Origin: (table, RD, prefix, Site of Origin).
pub type SooSkip = (String, Rd, IpNet, u64);

/// Per VRF table (every one of the set, even empty), per prefix.
pub type VpnImports = HashMap<String, HashMap<IpNet, VpnImport>>;

impl BgpRib {
    /// The VRFs whose `vpn.bgp_instance` is this instance (`reconcile.rs`).
    pub fn set_vpn_vrfs(&mut self, vrfs: VrfSet) {
        self.vpn_vrfs = vrfs;
    }

    pub fn vpn_vrfs(&self) -> &VrfSet {
        &self.vpn_vrfs
    }

    /// This instance's (underlay) routing table, where PE next hops resolve,
    /// and what each VRF imports; `None` while deferring (graceful restart:
    /// the VRFs keep what they hold). A path whose PE is unfeasible
    /// (`next_hop_feasible`) is no candidate.
    pub fn vpn_import_snapshot(&self) -> (Option<String>, Option<VpnImports>) {
        if self.deferring() {
            return (None, None);
        }
        let paths = self
            .vpn_adj_rib_in
            .values()
            .flatten()
            .filter(|(_, r)| r.route.next_hop.is_some() && self.next_hop_feasible(r.route.next_hop))
            .map(|(k, r)| (k, r.route.extended_communities.as_slice(), r));
        let mut out: VpnImports = self
            .vpn_vrfs
            .tables()
            .map(|t| (t.to_string(), HashMap::new()))
            .collect();
        for (table, routes) in self.vpn_vrfs.import_by_table(paths) {
            let mut per_prefix: HashMap<IpNet, Vec<(&VpnKey<IpNet>, &VpnRoute)>> = HashMap::new();
            for (k, r) in routes {
                per_prefix.entry(k.1).or_default().push((k, r));
            }
            let dest = out.entry(table.to_string()).or_default();
            for (prefix, cands) in per_prefix {
                if let Some(best) = self.best_import(cands) {
                    dest.insert(prefix, best);
                }
            }
        }
        (self.owning_routing_table.clone(), Some(out))
    }

    /// The (table, RD, prefix, Site of Origin) of every held path a VRF
    /// refused for carrying its own Site of Origin (RFC 4364 section 7).
    pub fn vpn_soo_skipped(&self) -> HashSet<SooSkip> {
        self.vpn_adj_rib_in
            .values()
            .flatten()
            .flat_map(|(k, r)| {
                self.vpn_vrfs
                    .soo_blocked(&r.route.extended_communities)
                    .into_iter()
                    .map(move |(t, soo)| (t.to_string(), k.0, k.1, soo))
            })
            .collect()
    }

    /// The unicast decision process over one VRF prefix's candidates. They
    /// are ordered by RD and the position is the step-10 path id, so a full
    /// tie (one peer, two RDs) always picks the lowest RD.
    fn best_import(&self, mut cands: Vec<(&VpnKey<IpNet>, &VpnRoute)>) -> Option<VpnImport> {
        cands.sort_by_key(|(k, _)| k.0);
        let scored: Vec<Candidate> = cands
            .iter()
            .zip(0u32..)
            .map(|((_, r), id)| (r.route.clone(), id))
            .collect();
        let (i, _) = scored
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| decision_cmp(a, b, &self.igp))?;
        let (k, r) = cands[i];
        Some(VpnImport {
            pe: r.route.next_hop?,
            labels: r.labels.clone(),
            rd: k.0,
        })
    }
}
