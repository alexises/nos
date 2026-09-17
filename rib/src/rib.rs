use std::collections::HashMap;
use std::net::IpAddr;

use nos_proto::{Config, IpNet};
use tracing::warn;

/// Where a route came from. New sources are appended as new variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteSource {
    /// From a `StaticRoutingInstance` in the running config. Populated
    /// wholesale by `build_from_config` on every resync.
    Static,
    /// Pushed by the owning `nos-bgpd` instance over `RibRequest::PushBgpRoutes`
    /// (see `crate::server::apply_bgp_route_update`) — its per-prefix best
    /// path, peer-learned routes only.
    Bgp,
}

impl RouteSource {
    /// Lower wins, like an administrative distance. Static is preferred
    /// over Bgp, matching conventional router defaults (an explicit
    /// operator override beats a dynamically learned route).
    fn preference(self) -> u8 {
        match self {
            RouteSource::Static => 1,
            RouteSource::Bgp => 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RibEntry {
    pub prefix: IpNet,
    pub gateway: IpAddr,
    pub source: RouteSource,
}

/// Whether a mutation actually changed a prefix's *winning* candidate —
/// see `Rib::upsert_and_diff`/`remove_and_diff`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BestPathChange {
    /// The winner is the same as before this mutation (a losing candidate
    /// churned, or the value re-sent was identical) — nothing to do.
    Unchanged,
    /// The prefix now has no winner at all (its last candidate was removed).
    Removed,
    /// The prefix has a new (or first) winner.
    Installed(RibEntry),
}

fn diff_best(before: Option<&RibEntry>, after: Option<RibEntry>) -> BestPathChange {
    if before == after.as_ref() {
        BestPathChange::Unchanged
    } else {
        match after {
            Some(entry) => BestPathChange::Installed(entry),
            None => BestPathChange::Removed,
        }
    }
}

/// One routing table's candidate routes, keyed by prefix, potentially with
/// more than one source contending for a prefix. Two independent writers
/// mutate this: `crate::reconcile::resync` (config-driven, rebuilds the
/// whole `Static` side from scratch on every resync) and
/// `crate::server::apply_bgp_route_update` (BGP-push-driven, incremental).
/// Each writer only ever touches its own `RouteSource`'s candidates via
/// `replace_source`/`upsert`/`remove`, so neither can clobber the other's
/// state.
#[derive(Debug, Clone, Default)]
pub struct Rib {
    entries: HashMap<IpNet, Vec<RibEntry>>,
}

impl Rib {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, entry: RibEntry) {
        self.entries.entry(entry.prefix).or_default().push(entry);
    }

    /// Replaces every `source`-sourced candidate across the whole table with
    /// `entries`, leaving every other source's candidates untouched. Used
    /// for a config resync's wholesale `Static` rebuild and a BGP push's
    /// `Full` snapshot (on connect/reconnect) alike.
    pub fn replace_source(
        &mut self,
        source: RouteSource,
        entries: impl IntoIterator<Item = RibEntry>,
    ) {
        for candidates in self.entries.values_mut() {
            candidates.retain(|e| e.source != source);
        }
        for entry in entries {
            debug_assert_eq!(entry.source, source);
            self.entries.entry(entry.prefix).or_default().push(entry);
        }
        self.entries.retain(|_, c| !c.is_empty());
    }

    /// Upserts one `source`-sourced candidate for `entry.prefix` — used for
    /// a BGP push's incremental `Add`.
    pub fn upsert(&mut self, entry: RibEntry) {
        let candidates = self.entries.entry(entry.prefix).or_default();
        candidates.retain(|e| e.source != entry.source);
        candidates.push(entry);
    }

    /// Removes `source`'s candidate for `prefix`, if any — used for a BGP
    /// push's incremental `Remove`. Prunes the prefix entirely if that was
    /// its last remaining candidate.
    pub fn remove(&mut self, prefix: &IpNet, source: RouteSource) {
        if let Some(candidates) = self.entries.get_mut(prefix) {
            candidates.retain(|e| e.source != source);
            if candidates.is_empty() {
                self.entries.remove(prefix);
            }
        }
    }

    /// Same as `upsert`, but reports whether the prefix's *winning*
    /// candidate changed as a result — a caller that only cares about
    /// kernel-visible state (e.g. `crate::server::apply_bgp_route_update`)
    /// can then skip pushing anything for a losing candidate's churn or a
    /// re-sent identical route, instead of recomputing/reinstalling the
    /// whole table on every single update.
    pub fn upsert_and_diff(&mut self, entry: RibEntry) -> BestPathChange {
        let prefix = entry.prefix;
        let before = self.best_route(&prefix).cloned();
        self.upsert(entry);
        diff_best(before.as_ref(), self.best_route(&prefix).cloned())
    }

    /// Same as `remove`, but reports whether the prefix's winning candidate
    /// changed — see `upsert_and_diff`.
    pub fn remove_and_diff(&mut self, prefix: &IpNet, source: RouteSource) -> BestPathChange {
        let before = self.best_route(prefix).cloned();
        self.remove(prefix, source);
        diff_best(before.as_ref(), self.best_route(prefix).cloned())
    }

    /// The winning candidate for one prefix, if any exist.
    pub fn best_route(&self, prefix: &IpNet) -> Option<&RibEntry> {
        self.entries
            .get(prefix)?
            .iter()
            .min_by_key(|e| e.source.preference())
    }

    /// The winning route for every known prefix.
    pub fn best_routes(&self) -> HashMap<IpNet, RibEntry> {
        self.entries
            .iter()
            .filter_map(|(prefix, candidates)| {
                candidates
                    .iter()
                    .min_by_key(|e| e.source.preference())
                    .cloned()
                    .map(|e| (*prefix, e))
            })
            .collect()
    }

    /// Every prefix's full candidate list, each sorted best (winner) to
    /// worst by source preference, with prefixes themselves in ascending
    /// CIDR order — for serving an unfiltered `show route <table>` query.
    pub fn all_routes(&self) -> Vec<(IpNet, Vec<RibEntry>)> {
        let mut out: Vec<(IpNet, Vec<RibEntry>)> = self
            .entries
            .iter()
            .map(|(prefix, candidates)| (*prefix, sorted_by_preference(candidates)))
            .collect();
        out.sort_by_key(|(prefix, _)| *prefix);
        out
    }

    /// Longest-prefix-match lookup: the most specific configured prefix that
    /// covers `addr`, with its full candidate list sorted best to worst.
    /// `None` if no configured prefix covers `addr` (no default route).
    pub fn lookup(&self, addr: IpAddr) -> Option<(IpNet, Vec<RibEntry>)> {
        let (prefix, candidates) = self
            .entries
            .iter()
            .filter(|(net, _)| net.contains(&addr))
            .max_by_key(|(net, _)| net.prefix_len())?;
        Some((*prefix, sorted_by_preference(candidates)))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Clones and sorts a prefix's candidates best (lowest preference value)
/// first.
fn sorted_by_preference(candidates: &[RibEntry]) -> Vec<RibEntry> {
    let mut sorted = candidates.to_vec();
    sorted.sort_by_key(|e| e.source.preference());
    sorted
}

/// Builds a fresh `Rib` for `table_name` from a freshly fetched `Config`.
/// Returns `None` if no `RoutingTable` named `table_name` exists in `cfg` —
/// the caller (see `crate::reconcile::resync`) treats that as a
/// recoverable, possibly-transient condition, not fatal.
///
/// Only resolves `table.static_routing_instance` — `table.bgp_instance` is
/// intentionally not read here: `RouteSource::Bgp` entries never come from
/// config, only from the owning `nos-bgpd` instance's own IPC push (see
/// `crate::server::apply_bgp_route_update`).
pub fn build_from_config(cfg: &Config, table_name: &str) -> Option<Rib> {
    let table = cfg.routing_tables.iter().find(|t| t.name == table_name)?;
    let mut rib = Rib::new();

    if let Some(sri_name) = &table.static_routing_instance {
        if let Some(sri) = cfg
            .static_routing_instances
            .iter()
            .find(|i| &i.name == sri_name)
        {
            for route in &sri.routes {
                rib.insert(RibEntry {
                    prefix: route.subnet,
                    gateway: route.gateway,
                    source: RouteSource::Static,
                });
            }
        } else {
            warn!(
                table = %table_name,
                static_routing_instance = %sri_name,
                "static_routing_instance referenced by routing table not found in config"
            );
        }
    }

    Some(rib)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nos_proto::{RoutingTable, StaticRoute, StaticRoutingInstance};

    fn cfg(tables: Vec<RoutingTable>, instances: Vec<StaticRoutingInstance>) -> Config {
        Config {
            routing_tables: tables,
            static_routing_instances: instances,
            ..Default::default()
        }
    }

    #[test]
    fn best_route_none_for_unknown_prefix() {
        let rib = Rib::new();
        assert!(rib.best_route(&"10.0.0.0/24".parse().unwrap()).is_none());
    }

    #[test]
    fn single_static_entry_is_its_own_best() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
        });
        assert_eq!(
            rib.best_route(&prefix).unwrap().gateway,
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    /// Proves the tie-break logic actually discriminates by source, using a
    /// synthetic `RouteSource::Bgp` entry even though no real code
    /// constructs one today.
    #[test]
    fn static_beats_bgp_for_same_prefix() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
            source: RouteSource::Bgp,
        });
        rib.insert(RibEntry {
            prefix,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
        });
        assert_eq!(rib.best_route(&prefix).unwrap().source, RouteSource::Static);
    }

    #[test]
    fn best_routes_has_one_entry_per_prefix() {
        let mut rib = Rib::new();
        let p1: IpNet = "10.0.0.0/24".parse().unwrap();
        let p2: IpNet = "10.0.1.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix: p1,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
        });
        rib.insert(RibEntry {
            prefix: p2,
            gateway: "10.0.1.1".parse().unwrap(),
            source: RouteSource::Static,
        });
        assert_eq!(rib.best_routes().len(), 2);
    }

    #[test]
    fn all_routes_sorts_prefixes_and_candidates() {
        let mut rib = Rib::new();
        let p1: IpNet = "10.0.1.0/24".parse().unwrap();
        let p2: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix: p1,
            gateway: "10.0.1.1".parse().unwrap(),
            source: RouteSource::Static,
        });
        rib.insert(RibEntry {
            prefix: p2,
            gateway: "10.0.0.9".parse().unwrap(),
            source: RouteSource::Bgp,
        });
        rib.insert(RibEntry {
            prefix: p2,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
        });

        let all = rib.all_routes();
        assert_eq!(all.len(), 2);
        // p2 (10.0.0.0/24) sorts before p1 (10.0.1.0/24).
        assert_eq!(all[0].0, p2);
        assert_eq!(all[1].0, p1);
        // p2's candidates are ordered best (Static) to worst (Bgp).
        assert_eq!(all[0].1.len(), 2);
        assert_eq!(all[0].1[0].source, RouteSource::Static);
        assert_eq!(all[0].1[1].source, RouteSource::Bgp);
    }

    #[test]
    fn lookup_performs_longest_prefix_match() {
        let mut rib = Rib::new();
        let broad: IpNet = "10.0.0.0/16".parse().unwrap();
        let narrow: IpNet = "10.0.1.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix: broad,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
        });
        rib.insert(RibEntry {
            prefix: narrow,
            gateway: "10.0.1.1".parse().unwrap(),
            source: RouteSource::Static,
        });

        let (matched, candidates) = rib.lookup("10.0.1.5".parse().unwrap()).unwrap();
        assert_eq!(matched, narrow);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].gateway, "10.0.1.1".parse::<IpAddr>().unwrap());

        let (matched, _) = rib.lookup("10.0.2.5".parse().unwrap()).unwrap();
        assert_eq!(matched, broad);

        assert!(rib.lookup("192.168.0.1".parse().unwrap()).is_none());
    }

    #[test]
    fn build_from_config_table_not_found_is_none() {
        assert!(build_from_config(&cfg(vec![], vec![]), "rt1").is_none());
    }

    #[test]
    fn build_from_config_table_without_static_instance_is_empty() {
        let tables = vec![RoutingTable {
            name: "rt1".into(),
            bgp_instance: None,
            ospf_instance: None,
            static_routing_instance: None,
            redistribute: None,
        }];
        let rib = build_from_config(&cfg(tables, vec![]), "rt1").unwrap();
        assert!(rib.is_empty());
    }

    #[test]
    fn replace_source_leaves_other_sources_untouched() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
            source: RouteSource::Bgp,
        });
        rib.replace_source(
            RouteSource::Static,
            vec![RibEntry {
                prefix,
                gateway: "10.0.0.1".parse().unwrap(),
                source: RouteSource::Static,
            }],
        );
        let candidates = rib
            .all_routes()
            .into_iter()
            .find(|(p, _)| *p == prefix)
            .unwrap()
            .1;
        assert_eq!(candidates.len(), 2);
        assert!(candidates.iter().any(|e| e.source == RouteSource::Bgp));
        assert!(candidates.iter().any(|e| e.source == RouteSource::Static));
    }

    #[test]
    fn replace_source_with_empty_clears_only_that_source_and_prunes() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
        });
        rib.replace_source(RouteSource::Static, Vec::new());
        assert!(rib.is_empty());
    }

    #[test]
    fn upsert_replaces_prior_same_source_candidate_only() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
        });
        rib.upsert(RibEntry {
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
            source: RouteSource::Bgp,
        });
        rib.upsert(RibEntry {
            prefix,
            gateway: "10.0.0.99".parse().unwrap(),
            source: RouteSource::Bgp,
        });
        let candidates = rib
            .all_routes()
            .into_iter()
            .find(|(p, _)| *p == prefix)
            .unwrap()
            .1;
        assert_eq!(candidates.len(), 2);
        let bgp = candidates
            .iter()
            .find(|e| e.source == RouteSource::Bgp)
            .unwrap();
        assert_eq!(bgp.gateway, "10.0.0.99".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn upsert_and_diff_reports_unchanged_for_an_identical_resend() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        let entry = RibEntry {
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
            source: RouteSource::Bgp,
        };
        assert_eq!(
            rib.upsert_and_diff(entry.clone()),
            BestPathChange::Installed(entry.clone())
        );
        assert_eq!(rib.upsert_and_diff(entry), BestPathChange::Unchanged);
    }

    #[test]
    fn upsert_and_diff_reports_unchanged_when_a_losing_candidate_churns() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
        });
        // Static already wins this prefix, so a new/changed Bgp candidate
        // never becomes the winner — no kernel-visible change.
        assert_eq!(
            rib.upsert_and_diff(RibEntry {
                prefix,
                gateway: "10.0.0.9".parse().unwrap(),
                source: RouteSource::Bgp,
            }),
            BestPathChange::Unchanged
        );
    }

    #[test]
    fn upsert_and_diff_reports_installed_when_a_better_candidate_arrives() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        let bgp_entry = RibEntry {
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
            source: RouteSource::Bgp,
        };
        assert_eq!(
            rib.upsert_and_diff(bgp_entry),
            BestPathChange::Installed(RibEntry {
                prefix,
                gateway: "10.0.0.9".parse().unwrap(),
                source: RouteSource::Bgp,
            })
        );
        let static_entry = RibEntry {
            prefix,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
        };
        assert_eq!(
            rib.upsert_and_diff(static_entry.clone()),
            BestPathChange::Installed(static_entry)
        );
    }

    #[test]
    fn remove_and_diff_reports_removed_when_the_last_candidate_goes() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
            source: RouteSource::Bgp,
        });
        assert_eq!(
            rib.remove_and_diff(&prefix, RouteSource::Bgp),
            BestPathChange::Removed
        );
    }

    #[test]
    fn remove_and_diff_reports_unchanged_when_a_losing_candidate_is_removed() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
        });
        rib.insert(RibEntry {
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
            source: RouteSource::Bgp,
        });
        // Static still wins after Bgp's candidate is removed.
        assert_eq!(
            rib.remove_and_diff(&prefix, RouteSource::Bgp),
            BestPathChange::Unchanged
        );
    }

    #[test]
    fn remove_and_diff_reports_installed_when_the_winner_falls_back() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
        });
        rib.insert(RibEntry {
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
            source: RouteSource::Bgp,
        });
        assert_eq!(
            rib.remove_and_diff(&prefix, RouteSource::Static),
            BestPathChange::Installed(RibEntry {
                prefix,
                gateway: "10.0.0.9".parse().unwrap(),
                source: RouteSource::Bgp,
            })
        );
    }

    #[test]
    fn remove_drops_only_named_source_and_prunes_if_last() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
        });
        rib.insert(RibEntry {
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
            source: RouteSource::Bgp,
        });
        rib.remove(&prefix, RouteSource::Bgp);
        let candidates = rib
            .all_routes()
            .into_iter()
            .find(|(p, _)| *p == prefix)
            .unwrap()
            .1;
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].source, RouteSource::Static);

        rib.remove(&prefix, RouteSource::Static);
        assert!(rib.is_empty());
    }

    #[test]
    fn build_from_config_resolves_static_routes() {
        let tables = vec![RoutingTable {
            name: "rt1".into(),
            bgp_instance: None,
            ospf_instance: None,
            static_routing_instance: Some("sri1".into()),
            redistribute: None,
        }];
        let instances = vec![StaticRoutingInstance {
            name: "sri1".into(),
            routes: vec![StaticRoute {
                subnet: "10.0.0.0/24".parse().unwrap(),
                gateway: "10.0.0.1".parse().unwrap(),
            }],
        }];
        let rib = build_from_config(&cfg(tables, instances), "rt1").unwrap();
        let best = rib.best_route(&"10.0.0.0/24".parse().unwrap()).unwrap();
        assert_eq!(best.source, RouteSource::Static);
        assert_eq!(best.gateway, "10.0.0.1".parse::<IpAddr>().unwrap());
    }
}
