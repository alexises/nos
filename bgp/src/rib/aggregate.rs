//! RFC 4271 §9.2.2.2 route aggregation (`BgpInstance.aggregates`).
//!
//! An aggregate's contributors are the Loc-RIB prefixes strictly more
//! specific than it. `recompute_and_propagate` calls
//! `update_aggregates_for` after every Loc-RIB change and before fanning the
//! changed prefix out, so a `summary-only` aggregate is active before its
//! first contributor reaches any peer. An active aggregate is a local
//! candidate (`aggregated`) next to `redistributed`; a change to it re-runs
//! `recompute_and_propagate` on the (strictly shorter) aggregate prefix, so
//! the recursion ends and nested aggregates just work.
//!
//! ponytail: the covering-aggregate lookup is a linear scan of the
//! configured aggregates per Loc-RIB change (free with none configured) and
//! `as-set` rebuilds from every contributor on each change; move to a prefix
//! trie / ref-counted ASN multiset if thousands of aggregates or a huge
//! `as-set` aggregate ever show up in the benchmark.

use std::collections::HashSet;
use std::sync::Arc;

use ipnet::IpNet;
use nos_proto::BgpAggregate;
use tracing::info;

use super::{origin_rank, redistributed_route, BgpRib, RibRoute};
use crate::as_path::{AsPath, SegKind};
use crate::message;

pub(super) struct AggregateState {
    cfg: BgpAggregate,
    contributors: HashSet<IpNet>,
}

/// `inner` is strictly more specific than `agg`.
fn covers(agg: IpNet, inner: IpNet) -> bool {
    agg != inner && agg.contains(&inner)
}

/// RFC 4271 Appendix F.6: the contributors' longest common leading
/// `AS_SEQUENCE`, then one `AS_SET` (sorted, deduplicated) of every other
/// ASN. Confederation segments are dropped first.
fn as_set_path<'a>(paths: impl Iterator<Item = &'a AsPath>) -> AsPath {
    let tuples: Vec<Vec<(SegKind, u32)>> = paths
        .map(|p| {
            p.segments()
                .filter(|(k, _)| !k.is_confed())
                .flat_map(|(k, s)| s.iter().map(move |a| (k, *a)))
                .collect()
        })
        .collect();
    let Some(first) = tuples.first() else {
        return AsPath::default();
    };
    let common = first
        .iter()
        .enumerate()
        .take_while(|(i, t)| {
            t.0 == SegKind::Sequence && tuples.iter().all(|o| o.get(*i) == Some(t))
        })
        .count();
    let mut out = AsPath::default();
    let leading: Vec<u32> = first[..common].iter().map(|t| t.1).collect();
    out.push_segment(SegKind::Sequence, &leading);
    let mut rest: Vec<u32> = tuples
        .iter()
        .flat_map(|t| t[common..].iter().map(|x| x.1))
        .collect();
    rest.sort_unstable();
    rest.dedup();
    out.push_segment(SegKind::Set, &rest);
    out
}

impl BgpRib {
    /// Installs `BgpInstance.aggregates`. Unchanged config is a no-op; a
    /// change seeds each aggregate's contributors with one Loc-RIB scan,
    /// withdraws the aggregates that went away, and re-sends every covered
    /// prefix in case `summary-only` changed.
    pub fn set_aggregates(&mut self, cfgs: Vec<BgpAggregate>) {
        if self.aggregates.iter().map(|a| &a.cfg).eq(cfgs.iter()) {
            return;
        }
        let mut refan: HashSet<IpNet> = self.summary_covered();
        self.aggregates = cfgs
            .into_iter()
            .map(|cfg| AggregateState {
                contributors: self
                    .loc_rib
                    .keys()
                    .copied()
                    .filter(|p| covers(cfg.prefix, *p))
                    .collect(),
                cfg,
            })
            .collect();
        let gone: Vec<IpNet> = self
            .aggregated
            .keys()
            .copied()
            .filter(|p| !self.aggregates.iter().any(|a| a.cfg.prefix == *p))
            .collect();
        for prefix in gone {
            self.aggregated.remove(&prefix);
            info!(aggregate = %prefix, "bgp: aggregate withdrawn");
            self.recompute_and_propagate(prefix);
        }
        for i in 0..self.aggregates.len() {
            self.refresh_aggregate(i);
        }
        refan.extend(self.summary_covered());
        for prefix in refan {
            self.propagate_add_path(prefix, None);
            self.fan_out(prefix);
        }
    }

    /// Every Loc-RIB prefix under some `summary-only` aggregate.
    fn summary_covered(&self) -> HashSet<IpNet> {
        self.aggregates
            .iter()
            .filter(|a| a.cfg.summary_only)
            .flat_map(|a| a.contributors.iter().copied())
            .collect()
    }

    /// `prefix` is strictly covered by an active `summary-only` aggregate:
    /// it's withheld from (and withdrawn toward) every peer.
    pub(super) fn suppressed_by_aggregate(&self, prefix: IpNet) -> bool {
        self.aggregates.iter().any(|a| {
            a.cfg.summary_only
                && covers(a.cfg.prefix, prefix)
                && self.aggregated.contains_key(&a.cfg.prefix)
        })
    }

    /// `prefix`'s Loc-RIB entry just changed: updates the contributor set of
    /// every aggregate covering it and rebuilds those aggregates.
    pub(super) fn update_aggregates_for(&mut self, prefix: IpNet) {
        let present = self.loc_rib.contains_key(&prefix);
        for i in 0..self.aggregates.len() {
            let a = &mut self.aggregates[i];
            if !covers(a.cfg.prefix, prefix) {
                continue;
            }
            if present {
                a.contributors.insert(prefix);
            } else {
                a.contributors.remove(&prefix);
            }
            self.refresh_aggregate(i);
        }
    }

    /// Rebuilds aggregate `i`'s route from its contributors and, on a
    /// change, re-decides the aggregate prefix. Activation or withdrawal of
    /// a `summary-only` aggregate re-sends its contributors.
    fn refresh_aggregate(&mut self, i: usize) {
        let a = &self.aggregates[i];
        let prefix = a.cfg.prefix;
        let new = self.build_aggregate(a);
        let old = self.aggregated.get(&prefix);
        if new.as_ref() == old {
            return;
        }
        let flipped = new.is_some() != old.is_some();
        if let Some(route) = new {
            info!(
                aggregate = %prefix,
                contributors = a.contributors.len(),
                as_set = a.cfg.as_set,
                "bgp: aggregate {}",
                if flipped { "activated" } else { "updated" }
            );
            self.aggregated.insert(prefix, route);
        } else {
            info!(aggregate = %prefix, "bgp: aggregate withdrawn");
            self.aggregated.remove(&prefix);
        }
        let refan: Vec<IpNet> = if flipped && a.cfg.summary_only {
            a.contributors.iter().copied().collect()
        } else {
            Vec::new()
        };
        self.recompute_and_propagate(prefix);
        for c in refan {
            self.propagate_add_path(c, None);
            self.fan_out(c);
        }
    }

    /// The aggregate route (RFC 4271 §9.2.2.2), `None` with no contributor.
    fn build_aggregate(&self, a: &AggregateState) -> Option<RibRoute> {
        let routes: Vec<&RibRoute> = a
            .contributors
            .iter()
            .filter_map(|p| self.loc_rib.get(p))
            .collect();
        let bgp_origin = routes
            .iter()
            .map(|r| r.bgp_origin)
            .max_by_key(|o| origin_rank(*o))?;
        let as_path = if a.cfg.as_set {
            as_set_path(routes.iter().map(|r| &*r.as_path))
        } else {
            AsPath::default()
        };
        // §9.2.2.2: inherited from any contributor, and set when the
        // contributors' AS_PATHs are dropped (path information is lost).
        let atomic_aggregate = routes
            .iter()
            .any(|r| r.atomic_aggregate || (!a.cfg.as_set && !r.as_path.is_empty()));
        Some(RibRoute {
            validation_state: self.validate(a.cfg.prefix, &as_path),
            as_path: Arc::new(as_path),
            bgp_origin,
            atomic_aggregate,
            aggregator: Some(message::Aggregator {
                asn: self.local_asn,
                router_id: self.local_router_id,
            }),
            // Kept across rebuilds: part of `RibRoute`'s `PartialEq`.
            received_at: self
                .aggregated
                .get(&a.cfg.prefix)
                .map_or_else(std::time::Instant::now, |r| r.received_at),
            ..redistributed_route()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(segs: &[(SegKind, &[u32])]) -> AsPath {
        let mut p = AsPath::default();
        for (k, s) in segs {
            p.push_segment(*k, s);
        }
        p
    }

    #[test]
    fn as_set_keeps_the_common_leading_sequence_and_sets_the_rest() {
        let a = path(&[(SegKind::Sequence, &[1, 2, 5])]);
        let b = path(&[(SegKind::Sequence, &[1, 2, 4, 3])]);
        assert_eq!(
            as_set_path([&a, &b].into_iter()),
            path(&[(SegKind::Sequence, &[1, 2]), (SegKind::Set, &[3, 4, 5])])
        );
        // One contributor: its path unchanged, no set.
        assert_eq!(as_set_path([&a].into_iter()), a);
        // Confederation segments are dropped; an empty path shares nothing.
        let c = path(&[
            (SegKind::ConfedSequence, &[9]),
            (SegKind::Sequence, &[1, 7]),
        ]);
        assert_eq!(
            as_set_path([&c, &AsPath::default()].into_iter()),
            path(&[(SegKind::Set, &[1, 7])])
        );
    }
}
