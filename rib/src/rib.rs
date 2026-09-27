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
    /// Pushed by the owning `nos-ospfd` instance over `RibRequest::PushOspfRoutes`
    /// (see `crate::server::apply_ospf_route_update`) — its own SPF-computed
    /// routes, never a directly-connected destination (see `ospf::spf`).
    Ospf,
    /// A directly-connected prefix: the network of an address
    /// `nos-interfaced` applied to an interface/subinterface or a broadcast
    /// domain's SVI in this table (`reconcile::connected_entries`, from
    /// `InterfaceRequest::GetInterfaces`/`GetBroadcastDomain`). Rebuilt
    /// wholesale on every resync like `Static`. Its `gateway` is the local
    /// address itself, for display only: the kernel installs a connected
    /// route on its own the moment the address is applied, so this source is
    /// never installed (`Rib::best_routes_for_kernel`). It exists so
    /// `igp_costs` can tell "directly connected" (cost 0) from "unresolvable"
    /// (absent) — RFC 4271 §9.1.2's next-hop feasibility check in `nos-bgpd`.
    Connected,
}

impl RouteSource {
    /// Lower wins, like an administrative distance. Connected beats Static
    /// beats Bgp beats Ospf, matching conventional (Cisco-style) router
    /// defaults: a directly-connected prefix beats an explicit operator
    /// override beats eBGP beats an interior IGP route.
    fn preference(self) -> u8 {
        match self {
            RouteSource::Connected => 0,
            RouteSource::Static => 1,
            RouteSource::Bgp => 20,
            RouteSource::Ospf => 110,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RibEntry {
    pub prefix: IpNet,
    pub gateway: IpAddr,
    pub source: RouteSource,
    /// Mirrors `nos_proto::OspfRoute::interface_id` — the local kernel
    /// interface `gateway` is reachable over, when known (always `Some`
    /// for an `Ospf`-sourced entry pushed by `nos-ospfv3d`, always `None`
    /// otherwise). Threaded down to `RibDriver::add_route`/`remove_route`,
    /// required for Linux's netlink route install when `gateway` is an
    /// IPv6 link-local address.
    pub interface_id: Option<u32>,
    /// Pre-computed backup gateway (OSPF LFA / BGP runner-up), installed by
    /// the driver as a second route at a higher metric. Part of equality, so
    /// a backup-only change counts as a change of the winner.
    pub backup: Option<IpAddr>,
    /// `interface_id` of `backup` — it can leave over a different link than
    /// the primary, and an IPv6 link-local backup needs one just the same.
    pub backup_interface_id: Option<u32>,
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
/// more than one source contending for a prefix. Three independent writers
/// mutate this: `crate::reconcile::resync` (config-driven, rebuilds the
/// whole `Static` side — and, from `nos-interfaced`'s applied addresses,
/// the whole `Connected` side — from scratch on every resync), and
/// `crate::server::apply_bgp_route_update`/`apply_ospf_route_update`
/// (push-driven, incremental). Each writer only ever touches its own
/// `RouteSource`'s candidates via `replace_source`/`upsert`/`remove`, so
/// none can clobber another's state.
#[derive(Debug, Clone, Default)]
pub struct Rib {
    entries: HashMap<IpNet, Vec<RibEntry>>,
    /// SPF cost per `Ospf`-sourced prefix, kept beside `entries` (not in
    /// `RibEntry`) since the kernel diff must not see a metric-only change.
    ospf_metrics: HashMap<IpNet, u32>,
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

    /// `best_routes` for the driver: the winner per prefix among every
    /// candidate *except* `Connected` ones, so a `Connected` prefix is left
    /// to the kernel's own on-link route (which exists the instant
    /// `nos-interfaced` applies the address, and which
    /// `driver::linux::extract_route` already ignores as an unmanaged,
    /// gateway-less route — so it never shows up on either side of the
    /// dump-diff), while a `Static`/`Bgp`/`Ospf` candidate shadowed by a
    /// `Connected` one for the same prefix is still installed as before.
    pub fn best_routes_for_kernel(&self) -> HashMap<IpNet, RibEntry> {
        self.entries
            .iter()
            .filter_map(|(prefix, candidates)| {
                candidates
                    .iter()
                    .filter(|e| e.source != RouteSource::Connected)
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

    /// Replaces every recorded OSPF metric (a `Full` push).
    pub fn set_ospf_metrics(&mut self, metrics: impl IntoIterator<Item = (IpNet, u32)>) {
        self.ospf_metrics = metrics.into_iter().collect();
    }

    /// Records (`Some`) or forgets (`None`) one prefix's OSPF metric.
    pub fn set_ospf_metric(&mut self, prefix: IpNet, metric: Option<u32>) {
        match metric {
            Some(m) => self.ospf_metrics.insert(prefix, m),
            None => self.ospf_metrics.remove(&prefix),
        };
    }

    /// IGP cost per prefix: its best non-BGP candidate's cost (`Connected`/
    /// `Static` 0, `Ospf` its SPF metric). `Bgp` candidates never count.
    pub fn igp_costs(&self) -> Vec<(IpNet, u32)> {
        self.entries
            .iter()
            .filter_map(|(prefix, candidates)| {
                let best = candidates
                    .iter()
                    .filter(|e| e.source != RouteSource::Bgp)
                    .min_by_key(|e| e.source.preference())?;
                let cost = match best.source {
                    RouteSource::Ospf => self.ospf_metrics.get(prefix).copied().unwrap_or(0),
                    _ => 0,
                };
                Some((*prefix, cost))
            })
            .collect()
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
                    interface_id: None,
                    backup: None,
                    backup_interface_id: None,
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
    fn igp_costs_use_best_non_bgp_candidate() {
        let mut rib = Rib::new();
        let entry = |p: &str, source| RibEntry {
            prefix: p.parse().unwrap(),
            gateway: "10.0.0.1".parse().unwrap(),
            source,
            interface_id: None,
            backup: None,
            backup_interface_id: None,
        };
        rib.insert(entry("10.1.0.0/16", RouteSource::Ospf));
        rib.insert(entry("10.2.0.0/16", RouteSource::Static));
        rib.insert(entry("10.3.0.0/16", RouteSource::Bgp));
        rib.set_ospf_metric("10.1.0.0/16".parse().unwrap(), Some(25));
        let mut costs = rib.igp_costs();
        costs.sort();
        assert_eq!(
            costs,
            vec![
                ("10.1.0.0/16".parse().unwrap(), 25),
                ("10.2.0.0/16".parse().unwrap(), 0)
            ]
        );
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
            interface_id: None,
            prefix,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
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
            interface_id: None,
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
        });
        rib.insert(RibEntry {
            interface_id: None,
            prefix,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
        });
        assert_eq!(rib.best_route(&prefix).unwrap().source, RouteSource::Static);
    }

    fn entry(prefix: &str, gateway: &str, source: RouteSource) -> RibEntry {
        RibEntry {
            interface_id: None,
            prefix: prefix.parse().unwrap(),
            gateway: gateway.parse().unwrap(),
            source,
            backup: None,
            backup_interface_id: None,
        }
    }

    #[test]
    fn connected_beats_static_for_same_prefix() {
        let mut rib = Rib::new();
        rib.insert(entry("10.0.0.0/24", "10.0.0.1", RouteSource::Static));
        rib.insert(entry("10.0.0.0/24", "10.0.0.2", RouteSource::Connected));
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        assert_eq!(
            rib.best_route(&prefix).unwrap().source,
            RouteSource::Connected
        );
        // and counts as an IGP destination at cost 0
        assert_eq!(rib.igp_costs(), vec![(prefix, 0)]);
    }

    #[test]
    fn best_routes_for_kernel_excludes_connected_but_falls_back_to_static_for_same_prefix() {
        let mut rib = Rib::new();
        rib.insert(entry("10.0.0.0/24", "10.0.0.2", RouteSource::Connected));
        rib.insert(entry("10.0.0.0/24", "10.0.0.1", RouteSource::Static));
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        let kernel = rib.best_routes_for_kernel();
        assert_eq!(kernel[&prefix].source, RouteSource::Static);
        assert_eq!(rib.best_routes()[&prefix].source, RouteSource::Connected);
    }

    #[test]
    fn best_routes_for_kernel_omits_connected_only_prefix_entirely() {
        let mut rib = Rib::new();
        rib.insert(entry("10.0.0.0/24", "10.0.0.2", RouteSource::Connected));
        rib.insert(entry("10.0.1.0/24", "10.0.0.1", RouteSource::Static));
        let kernel = rib.best_routes_for_kernel();
        assert_eq!(kernel.len(), 1);
        assert!(kernel.contains_key(&"10.0.1.0/24".parse::<IpNet>().unwrap()));
        assert_eq!(rib.best_routes().len(), 2);
    }

    #[test]
    fn best_routes_has_one_entry_per_prefix() {
        let mut rib = Rib::new();
        let p1: IpNet = "10.0.0.0/24".parse().unwrap();
        let p2: IpNet = "10.0.1.0/24".parse().unwrap();
        rib.insert(RibEntry {
            interface_id: None,
            prefix: p1,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
        });
        rib.insert(RibEntry {
            interface_id: None,
            prefix: p2,
            gateway: "10.0.1.1".parse().unwrap(),
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
        });
        assert_eq!(rib.best_routes().len(), 2);
    }

    #[test]
    fn all_routes_sorts_prefixes_and_candidates() {
        let mut rib = Rib::new();
        let p1: IpNet = "10.0.1.0/24".parse().unwrap();
        let p2: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            interface_id: None,
            prefix: p1,
            gateway: "10.0.1.1".parse().unwrap(),
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
        });
        rib.insert(RibEntry {
            interface_id: None,
            prefix: p2,
            gateway: "10.0.0.9".parse().unwrap(),
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
        });
        rib.insert(RibEntry {
            interface_id: None,
            prefix: p2,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
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
            interface_id: None,
            prefix: broad,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
        });
        rib.insert(RibEntry {
            interface_id: None,
            prefix: narrow,
            gateway: "10.0.1.1".parse().unwrap(),
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
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
            rest_api: None,
            ospfv3_instance: None,
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
            interface_id: None,
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
        });
        rib.replace_source(
            RouteSource::Static,
            vec![RibEntry {
                interface_id: None,
                prefix,
                gateway: "10.0.0.1".parse().unwrap(),
                source: RouteSource::Static,
                backup: None,
                backup_interface_id: None,
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
            interface_id: None,
            prefix,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
        });
        rib.replace_source(RouteSource::Static, Vec::new());
        assert!(rib.is_empty());
    }

    #[test]
    fn upsert_replaces_prior_same_source_candidate_only() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            interface_id: None,
            prefix,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
        });
        rib.upsert(RibEntry {
            interface_id: None,
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
        });
        rib.upsert(RibEntry {
            interface_id: None,
            prefix,
            gateway: "10.0.0.99".parse().unwrap(),
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
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
            interface_id: None,
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
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
            interface_id: None,
            prefix,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
        });
        // Static already wins this prefix, so a new/changed Bgp candidate
        // never becomes the winner — no kernel-visible change.
        assert_eq!(
            rib.upsert_and_diff(RibEntry {
                interface_id: None,
                prefix,
                gateway: "10.0.0.9".parse().unwrap(),
                source: RouteSource::Bgp,
                backup: None,
                backup_interface_id: None,
            }),
            BestPathChange::Unchanged
        );
    }

    #[test]
    fn upsert_and_diff_reports_installed_when_a_better_candidate_arrives() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        let bgp_entry = RibEntry {
            interface_id: None,
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
        };
        assert_eq!(
            rib.upsert_and_diff(bgp_entry),
            BestPathChange::Installed(RibEntry {
                interface_id: None,
                prefix,
                gateway: "10.0.0.9".parse().unwrap(),
                source: RouteSource::Bgp,
                backup: None,
                backup_interface_id: None,
            })
        );
        let static_entry = RibEntry {
            interface_id: None,
            prefix,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
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
            interface_id: None,
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
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
            interface_id: None,
            prefix,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
        });
        rib.insert(RibEntry {
            interface_id: None,
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
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
            interface_id: None,
            prefix,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
        });
        rib.insert(RibEntry {
            interface_id: None,
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
        });
        assert_eq!(
            rib.remove_and_diff(&prefix, RouteSource::Static),
            BestPathChange::Installed(RibEntry {
                interface_id: None,
                prefix,
                gateway: "10.0.0.9".parse().unwrap(),
                source: RouteSource::Bgp,
                backup: None,
                backup_interface_id: None,
            })
        );
    }

    #[test]
    fn remove_drops_only_named_source_and_prunes_if_last() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            interface_id: None,
            prefix,
            gateway: "10.0.0.1".parse().unwrap(),
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
        });
        rib.insert(RibEntry {
            interface_id: None,
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
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
            rest_api: None,
            ospfv3_instance: None,
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
