mod generate;

pub use generate::diff_values;

use serde::{Deserialize, Serialize};

use crate::schema::Config;

/// Whether a diffed section is wholly new, wholly gone, or has some fields
/// changed within it.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffStatus {
    Added,
    Removed,
    Modified,
}

/// One changed (or added/removed) field — either a top-level scalar or one
/// field within a `SectionDiff`. Values are pre-formatted strings; the
/// client only needs to display them, never interpret them.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldDiff {
    pub label: String,
    /// `None` only when the field's owning section is newly `Added`.
    pub old: Option<String>,
    /// `None` only when the field's owning section is being `Removed`.
    pub new: Option<String>,
}

/// A single named/keyed section (e.g. one BGP instance) that changed between
/// two configs, and the specific fields within it that did.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionDiff {
    /// Context line identifying the section, e.g. "bgp instance foo" —
    /// always included even when `status` is `Modified` and the header
    /// itself didn't change, so a reader can tell which section a changed
    /// field belongs to without being shown the whole config.
    pub header: String,
    /// The section's identifying key as a plain string (e.g. a BGP
    /// instance's `name`, a peer's `remote_address`, a route's `subnet`) —
    /// structured, unlike `header`, so a machine consumer never has to parse
    /// display text to find out which item changed.
    pub name: String,
    pub status: DiffStatus,
    pub fields: Vec<FieldDiff>,
    /// Nested sections one level deeper (e.g. a BGP instance's peer-groups
    /// and peers). Empty for a section with no nested collections.
    #[cfg_attr(feature = "openapi", schema(no_recursion))]
    pub subsections: Vec<SectionDiff>,
}

/// The structural difference between two `Config` values. Only what changed
/// is included — no unchanged section or field is ever present, so a client
/// can render this directly as a minimal, context-aware diff.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigDiff {
    pub hostname: Option<FieldDiff>,
    pub bgp_instances: Vec<SectionDiff>,
    pub routing_tables: Vec<SectionDiff>,
    pub ospf_instances: Vec<SectionDiff>,
    pub ospfv3_instances: Vec<SectionDiff>,
    pub static_routing_instances: Vec<SectionDiff>,
    pub interfaces: Vec<SectionDiff>,
    pub policy_definitions: Vec<SectionDiff>,
    pub community_aliases: Vec<SectionDiff>,
    pub community_groups: Vec<SectionDiff>,
    pub as_path_lists: Vec<SectionDiff>,
    pub prefix_lists: Vec<SectionDiff>,
    pub broadcast_domains: Vec<SectionDiff>,
    pub switching_profiles: Vec<SectionDiff>,
    pub port_aggregates: Vec<SectionDiff>,
    /// Field-level: `Config.lldp` is one singleton section, not a keyed list.
    pub lldp: Vec<FieldDiff>,
    pub users: Vec<SectionDiff>,
    /// Field-level, like `lldp`: `Config.logging` is one singleton section.
    pub logging: Vec<FieldDiff>,
    pub bfd_profiles: Vec<SectionDiff>,
    /// Field-level, like `lldp`: `Config.sbfd_reflector` is one singleton section.
    pub sbfd_reflector: Vec<FieldDiff>,
}

impl ConfigDiff {
    pub fn is_empty(&self) -> bool {
        self.hostname.is_none()
            && self.bgp_instances.is_empty()
            && self.routing_tables.is_empty()
            && self.ospf_instances.is_empty()
            && self.ospfv3_instances.is_empty()
            && self.static_routing_instances.is_empty()
            && self.interfaces.is_empty()
            && self.policy_definitions.is_empty()
            && self.community_aliases.is_empty()
            && self.community_groups.is_empty()
            && self.as_path_lists.is_empty()
            && self.prefix_lists.is_empty()
            && self.broadcast_domains.is_empty()
            && self.switching_profiles.is_empty()
            && self.port_aggregates.is_empty()
            && self.lldp.is_empty()
            && self.users.is_empty()
            && self.logging.is_empty()
            && self.bfd_profiles.is_empty()
            && self.sbfd_reflector.is_empty()
    }

    /// A copy of this diff keeping only the sections/fields covered by
    /// `scopes` — sections not requested are treated as unchanged (empty),
    /// even if they did change.
    #[must_use]
    pub fn scoped(&self, scopes: &[DiffScope]) -> ConfigDiff {
        ConfigDiff {
            hostname: if scopes.contains(&DiffScope::Hostname) {
                self.hostname.clone()
            } else {
                None
            },
            bgp_instances: if scopes.contains(&DiffScope::BgpInstances) {
                self.bgp_instances.clone()
            } else {
                Vec::new()
            },
            routing_tables: if scopes.contains(&DiffScope::RoutingTables) {
                self.routing_tables.clone()
            } else {
                Vec::new()
            },
            ospf_instances: if scopes.contains(&DiffScope::OspfInstances) {
                self.ospf_instances.clone()
            } else {
                Vec::new()
            },
            ospfv3_instances: if scopes.contains(&DiffScope::Ospfv3Instances) {
                self.ospfv3_instances.clone()
            } else {
                Vec::new()
            },
            static_routing_instances: if scopes.contains(&DiffScope::StaticRoutingInstances) {
                self.static_routing_instances.clone()
            } else {
                Vec::new()
            },
            interfaces: if scopes.contains(&DiffScope::Interfaces) {
                self.interfaces.clone()
            } else {
                Vec::new()
            },
            policy_definitions: if scopes.contains(&DiffScope::PolicyDefinitions) {
                self.policy_definitions.clone()
            } else {
                Vec::new()
            },
            community_aliases: if scopes.contains(&DiffScope::CommunityAliases) {
                self.community_aliases.clone()
            } else {
                Vec::new()
            },
            community_groups: if scopes.contains(&DiffScope::CommunityGroups) {
                self.community_groups.clone()
            } else {
                Vec::new()
            },
            as_path_lists: if scopes.contains(&DiffScope::AsPathLists) {
                self.as_path_lists.clone()
            } else {
                Vec::new()
            },
            prefix_lists: if scopes.contains(&DiffScope::PrefixLists) {
                self.prefix_lists.clone()
            } else {
                Vec::new()
            },
            broadcast_domains: if scopes.contains(&DiffScope::BroadcastDomains) {
                self.broadcast_domains.clone()
            } else {
                Vec::new()
            },
            switching_profiles: if scopes.contains(&DiffScope::SwitchingProfiles) {
                self.switching_profiles.clone()
            } else {
                Vec::new()
            },
            port_aggregates: if scopes.contains(&DiffScope::PortAggregates) {
                self.port_aggregates.clone()
            } else {
                Vec::new()
            },
            lldp: if scopes.contains(&DiffScope::Lldp) {
                self.lldp.clone()
            } else {
                Vec::new()
            },
            users: if scopes.contains(&DiffScope::Users) {
                self.users.clone()
            } else {
                Vec::new()
            },
            logging: if scopes.contains(&DiffScope::Logging) {
                self.logging.clone()
            } else {
                Vec::new()
            },
            bfd_profiles: if scopes.contains(&DiffScope::BfdProfiles) {
                self.bfd_profiles.clone()
            } else {
                Vec::new()
            },
            sbfd_reflector: if scopes.contains(&DiffScope::SbfdReflector) {
                self.sbfd_reflector.clone()
            } else {
                Vec::new()
            },
        }
    }
}

/// Which top-level `ConfigDiff` sections a diff subscriber cares about — see
/// `Request::SubscribeDiff`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffScope {
    Hostname,
    BgpInstances,
    RoutingTables,
    StaticRoutingInstances,
    Interfaces,
    PolicyDefinitions,
    CommunityAliases,
    CommunityGroups,
    AsPathLists,
    PrefixLists,
    BroadcastDomains,
    SwitchingProfiles,
    OspfInstances,
    Ospfv3Instances,
    PortAggregates,
    Lldp,
    Users,
    Logging,
    BfdProfiles,
    SbfdReflector,
}

/// The `FieldDiff` label `nos-watchdogd` keys on to decide whether a routing
/// table currently wants a `nos-restd` — a table's `Added`/`Modified`
/// section carries it with `new` = `"unset"` when the API is not pinned.
pub const REST_API_LABEL: &str = "rest-api";

/// The field label `nos-watchdogd` keys its `nos-fdbd` claim on (see
/// `Managed::claim_label`): a domain runs one while its vni is set.
pub const VNI_LABEL: &str = "vni";

/// Computes what changed between `base` (e.g. the running config) and
/// `candidate` (e.g. a transaction's in-progress config). Pure and
/// synchronous — no store state needed, the same category as `ConfigOp::apply`.
///
/// Generated from the CLI tree (`cli::root()`), like `show config` (#116):
/// every non-hidden field is compared, so a field can't exist without being
/// diffed, and labels/headers are the CLI's own words.
pub fn diff_configs(base: &Config, candidate: &Config) -> ConfigDiff {
    generate::diff_configs(base, candidate)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::schema::BgpInstance;

    use super::*;

    fn instance(name: &str, asn: u32) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn,
            peer_groups: Vec::new(),
            peers: Vec::new(),
            cluster_id: None,
            maximum_paths: None,
            confederation: crate::schema::BgpConfederation::default(),
            rpki_caches: Vec::new(),
            aggregates: Vec::new(),
            graceful_restart: crate::schema::BgpGracefulRestart::default(),
            routing_table: None,
            redistribute_policy: None,
        }
    }

    #[test]
    fn identical_configs_produce_empty_diff() {
        let cfg = Config {
            bgp_instances: vec![instance("r1", 65000)],
            ..Default::default()
        };
        assert!(diff_configs(&cfg, &cfg).is_empty());
    }

    #[test]
    fn hostname_change_is_reported() {
        let base = Config {
            hostname: "router-a".to_string(),
            ..Default::default()
        };
        let candidate = Config {
            hostname: "router-b".to_string(),
            ..Default::default()
        };
        let diff = diff_configs(&base, &candidate);
        let field = diff.hostname.expect("hostname diff expected");
        assert_eq!(field.old.as_deref(), Some("router-a"));
        assert_eq!(field.new.as_deref(), Some("router-b"));
        assert_eq!(diff.bgp_instances, []);
    }

    #[test]
    fn combined_hostname_and_instance_changes() {
        let base = Config {
            hostname: "router-a".to_string(),
            bgp_instances: vec![instance("r1", 65000)],
            ..Default::default()
        };
        let candidate = Config {
            hostname: "router-b".to_string(),
            bgp_instances: vec![instance("r1", 65001), instance("r2", 65002)],
            ..Default::default()
        };
        let diff = diff_configs(&base, &candidate);
        assert!(diff.hostname.is_some());
        assert_eq!(diff.bgp_instances.len(), 2);
    }
}
