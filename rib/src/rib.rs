use std::collections::HashMap;
use std::net::IpAddr;

use nos_proto::{Config, IpNet};

/// Where a route came from. New sources are appended as new variants — see
/// the doc comment on `Bgp` for the seam this leaves for later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteSource {
    /// From a `StaticRoutingInstance` in the running config. The only
    /// source any code path constructs today.
    Static,
    /// Reserved for a future BGP→RIB data-plane feed. No process
    /// constructs this variant yet — this is the documented extensibility
    /// seam, not live plumbing: a future BGP feed would populate `Rib`
    /// entries with this source the same way `build_from_config` populates
    /// `Static` ones today, without any change to `Rib`'s public shape.
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

/// One routing table's candidate routes, keyed by prefix, potentially with
/// more than one source contending for a prefix. Rebuilt wholesale on every
/// resync (see `crate::reconcile`) — never mutated incrementally — so
/// there is no cache-invalidation concern and no separate "recompute" step
/// distinct from `best_routes()`.
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
/// intentionally not read here: no BGP→RIB feed exists yet (see
/// `RouteSource::Bgp`'s doc comment for the seam this leaves).
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
            static_routing_instance: None,
        }];
        let rib = build_from_config(&cfg(tables, vec![]), "rt1").unwrap();
        assert!(rib.is_empty());
    }

    #[test]
    fn build_from_config_resolves_static_routes() {
        let tables = vec![RoutingTable {
            name: "rt1".into(),
            bgp_instance: None,
            static_routing_instance: Some("sri1".into()),
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
