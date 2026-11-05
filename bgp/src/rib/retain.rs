//! Soft reconfiguration inbound (#859): the pre-policy copy of every route a
//! flagged peer sends, kept so an import-policy change is re-evaluated locally
//! (no session reset, no Route Refresh). Unicast only until #866.
//!
//! Re-evaluation is chunked (`BgpRib::reevaluate_chunk`): the caller takes the
//! RIB lock per chunk, so UPDATEs interleave between chunks. See
//! `docs/protocols/bgp-internals.md`, "Soft reconfiguration inbound".

use super::adj_in::{get_path, put_path, take_path, PathCounts, PeerTable};
use super::{
    apply_policy, family_index, info, ov_state, Arc, BgpRib, CompiledPolicy, HashMap, HashSet,
    IpAddr, IpNet, RibRoute,
};
use nos_proto::{AddressFamily, FamilyReeval, ReevalFamily};

/// Prefixes re-evaluated per RIB lock hold: keeps a hold in the low
/// milliseconds on a full table. Not configurable (#859).
pub const REEVAL_CHUNK: usize = 5000;

/// Per flagged peer: the pre-policy tables and counters. Reuses
/// `put_path`/`take_path`, so ADD-PATH ids come for free.
#[derive(Default)]
pub(super) struct Retained {
    tables: HashMap<IpAddr, PeerTable>,
    counts: HashMap<IpAddr, PathCounts>,
    enabled: HashSet<IpAddr>,
    /// Families whose enhanced-refresh `EoRR` is still awaited after an
    /// in-place enable (`BgpRib::enable_soft_reconfig_live`).
    awaiting_eorr: HashSet<(IpAddr, AddressFamily)>,
}

/// The mutable halves of one peer's retention, handed to `learn_prefix`.
pub(super) struct RetainSlot<'a> {
    pub table: &'a mut PeerTable,
    pub counts: &'a mut PathCounts,
}

impl Retained {
    pub(super) fn slot(&mut self, peer: IpAddr) -> Option<RetainSlot<'_>> {
        if !self.enabled.contains(&peer) {
            return None;
        }
        Some(RetainSlot {
            table: self.tables.entry(peer).or_default(),
            counts: self.counts.entry(peer).or_default(),
        })
    }

    pub(super) fn take(&mut self, peer: IpAddr, prefix: IpNet, id: u32) {
        if let (Some(t), Some(c)) = (self.tables.get_mut(&peer), self.counts.get_mut(&peer)) {
            take_path(t, c, prefix, id);
        }
    }

    /// Frees everything held for `peer`, including the enabled mark.
    pub(super) fn drop_peer(&mut self, peer: IpAddr) {
        self.tables.remove(&peer);
        self.counts.remove(&peer);
        self.enabled.remove(&peer);
        self.awaiting_eorr.retain(|(p, _)| *p != peer);
    }

    pub(super) fn count(&self, peer: IpAddr) -> PathCounts {
        self.counts.get(&peer).copied().unwrap_or_default()
    }
}

/// One re-evaluation pass over a peer's retained routes.
pub struct ReevalPass {
    peer: IpAddr,
    policy: Arc<CompiledPolicy>,
    keys: Vec<IpNet>,
    next: usize,
    /// Per unicast family: retained paths visited, of which accepted, of
    /// which changed the Adj-RIB-In.
    stats: [(u32, u32, u32); 2],
}

/// What `reevaluate_chunk` did.
#[derive(Debug, PartialEq, Eq)]
pub enum ChunkOutcome {
    /// More keys remain.
    More,
    /// Every snapshot key was visited.
    Done,
    /// Retention is gone (disconnect or flag off).
    Gone,
}

impl ReevalPass {
    /// Per-family counts so far, in `ReevalFamily` order.
    pub fn families(&self) -> Vec<FamilyReeval> {
        [ReevalFamily::Ipv4Unicast, ReevalFamily::Ipv6Unicast]
            .into_iter()
            .zip(self.stats)
            .map(|(family, (retained, accepted, _))| FamilyReeval {
                family,
                retained,
                accepted,
            })
            .collect()
    }

    /// Logs one line per family; the caller logs the closing line.
    pub fn log(&self) {
        for (f, (_, _, changed)) in self.families().iter().zip(self.stats) {
            info!(
                peer = %self.peer, family = %f.family, retained = f.retained,
                accepted = f.accepted, changed,
                "soft reconfiguration: re-evaluated import policy"
            );
        }
    }
}

impl BgpRib {
    /// Turns retention on or off for `peer`; off frees the memory. Call
    /// before `peer_established`, like `set_peer_damping`.
    pub fn set_peer_soft_reconfig(&mut self, peer: IpAddr, on: bool) {
        if on {
            self.retained.enabled.insert(peer);
        } else {
            self.retained.drop_peer(peer);
        }
    }

    /// Enables retention on an `Established` peer whose routes are about to be
    /// re-sent by a Route Refresh; remembers which unicast families' `EoRR`
    /// marks retention as complete.
    pub fn enable_soft_reconfig_live(&mut self, peer: IpAddr, enhanced: bool) {
        self.retained.enabled.insert(peer);
        if !enhanced {
            info!(peer = %peer, "soft reconfiguration: retention enabled, route refresh requested");
            return;
        }
        let afs = self
            .peer_outboxes
            .get(&peer)
            .map(|o| o.negotiated_afs.clone());
        for f in afs.into_iter().flatten() {
            if matches!(f, AddressFamily::Ipv4Unicast | AddressFamily::Ipv6Unicast) {
                self.retained.awaiting_eorr.insert((peer, f));
            }
        }
        info!(peer = %peer, "soft reconfiguration: retention enabled, route refresh requested");
    }

    /// An RFC 7313 `EoRR` for `family` arrived; logs once every awaited family
    /// is in.
    pub fn retention_eorr(&mut self, peer: IpAddr, family: AddressFamily) {
        if self.retained.awaiting_eorr.remove(&(peer, family))
            && !self.retained.awaiting_eorr.iter().any(|(p, _)| *p == peer)
        {
            let n = self.retained_count(peer);
            info!(peer = %peer, retained = n, "soft reconfiguration: retention complete");
        }
    }

    /// Paths retained for `peer`, all unicast families.
    pub fn retained_count(&self, peer: IpAddr) -> u32 {
        self.retained.count(peer).iter().sum()
    }

    /// Whether retention is on for `peer`.
    pub fn soft_reconfig_enabled(&self, peer: IpAddr) -> bool {
        self.retained.enabled.contains(&peer)
    }

    /// Every retained path of `peer`: `(prefix, path id, route)`.
    pub fn retained_routes(&self, peer: IpAddr) -> Vec<(IpNet, u32, &RibRoute)> {
        self.retained
            .tables
            .get(&peer)
            .into_iter()
            .flatten()
            .flat_map(|(p, paths)| paths.iter().map(move |(id, r)| (*p, *id, r)))
            .collect()
    }

    /// Starts a pass: `policy` is what every later UPDATE of `peer` is judged
    /// by (the caller installs it in the same critical section), the pass
    /// snapshots the retained KEYS only. `None` if retention is off.
    pub fn begin_reevaluation(
        &self,
        peer: IpAddr,
        policy: Arc<CompiledPolicy>,
    ) -> Option<ReevalPass> {
        self.retained.enabled.contains(&peer).then(|| ReevalPass {
            peer,
            policy,
            keys: self
                .retained
                .tables
                .get(&peer)
                .map(|t| t.keys().copied().collect())
                .unwrap_or_default(),
            next: 0,
            stats: [(0, 0, 0); 2],
        })
    }

    /// Re-evaluates the next `n` snapshot keys against the CURRENT retained
    /// table (a path withdrawn since the snapshot is skipped), refreshing the
    /// RPKI state, and applies admit/replace/remove to the Adj-RIB-In.
    /// Only prefixes whose result changed are re-decided and propagated.
    /// Applies no damping.
    pub fn reevaluate_chunk(&mut self, pass: &mut ReevalPass, n: usize) -> ChunkOutcome {
        let peer = pass.peer;
        if !self.retained.enabled.contains(&peer) {
            return ChunkOutcome::Gone;
        }
        let peer_as = self.peer_asns.get(&peer).copied().unwrap_or(0);
        let local = self.confed_id.unwrap_or(self.local_asn);
        let end = (pass.next + n).min(pass.keys.len());
        let mut touched = Vec::new();
        for &prefix in &pass.keys[pass.next..end] {
            let Some(paths) = self.retained.tables.get(&peer).and_then(|t| t.get(&prefix)) else {
                continue;
            };
            let fam = family_index(prefix);
            let adj = self.adj_rib_in.entry(peer).or_default();
            let counts = self.path_counts.entry(peer).or_default();
            let mut changed = false;
            for (id, held) in paths {
                let mut cand = held.clone();
                cand.validation_state = ov_state(
                    &self.vrps,
                    prefix,
                    crate::rpki::origin_as(&cand.as_path, local),
                    cand.received_ov,
                );
                let result = apply_policy(prefix, cand, &pass.policy, Some((peer, peer_as)), None);
                pass.stats[fam].0 += 1;
                pass.stats[fam].1 += u32::from(result.is_some());
                changed |= settle(adj, counts, (peer, prefix, *id), result);
            }
            if changed {
                pass.stats[fam].2 += 1;
                touched.push(prefix);
            }
        }
        pass.next = end;
        for prefix in touched {
            self.recompute_and_propagate(prefix);
        }
        if end >= pass.keys.len() {
            ChunkOutcome::Done
        } else {
            ChunkOutcome::More
        }
    }

    /// Re-evaluates everything in one go (tests and small tables); the daemon
    /// uses the chunked form.
    pub fn reevaluate_peer(
        &mut self,
        peer: IpAddr,
        policy: Arc<CompiledPolicy>,
    ) -> Vec<FamilyReeval> {
        let Some(mut pass) = self.begin_reevaluation(peer, policy) else {
            return Vec::new();
        };
        while self.reevaluate_chunk(&mut pass, usize::MAX) == ChunkOutcome::More {}
        pass.families()
    }
}

/// Applies one re-evaluated path to the Adj-RIB-In; whether it changed.
fn settle(
    adj: &mut PeerTable,
    counts: &mut PathCounts,
    (peer, prefix, id): (IpAddr, IpNet, u32),
    result: Option<RibRoute>,
) -> bool {
    let Some(mut route) = result else {
        return take_path(adj, counts, prefix, id).is_some();
    };
    if let Some(old) = get_path(adj, prefix, id) {
        route.received_at = old.received_at;
        if route == *old {
            return false;
        }
    } else {
        info!(
            peer = %peer, path_id = id,
            "bgp: learned route for {prefix} into adj-rib-in"
        );
    }
    put_path(adj, counts, prefix, id, route);
    true
}
