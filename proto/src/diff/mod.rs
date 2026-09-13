pub mod bgp_instance;
pub mod bgp_peer;
pub mod bgp_peer_group;

use serde::{Deserialize, Serialize};

use crate::schema::Config;

/// Whether a diffed section is wholly new, wholly gone, or has some fields
/// changed within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffStatus {
    Added,
    Removed,
    Modified,
}

/// One changed (or added/removed) field — either a top-level scalar or one
/// field within a `SectionDiff`. Values are pre-formatted strings; the
/// client only needs to display them, never interpret them.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionDiff {
    /// Context line identifying the section, e.g. "bgp instance foo" —
    /// always included even when `status` is `Modified` and the header
    /// itself didn't change, so a reader can tell which section a changed
    /// field belongs to without being shown the whole config.
    pub header: String,
    pub status: DiffStatus,
    pub fields: Vec<FieldDiff>,
    /// Nested sections one level deeper (e.g. a BGP instance's peer-groups
    /// and peers). Empty for a section with no nested collections.
    pub subsections: Vec<SectionDiff>,
}

/// The structural difference between two `Config` values. Only what changed
/// is included — no unchanged section or field is ever present, so a client
/// can render this directly as a minimal, context-aware diff.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigDiff {
    pub hostname: Option<FieldDiff>,
    pub bgp_instances: Vec<SectionDiff>,
}

impl ConfigDiff {
    pub fn is_empty(&self) -> bool {
        self.hostname.is_none() && self.bgp_instances.is_empty()
    }
}

/// Computes what changed between `base` (e.g. the running config) and
/// `candidate` (e.g. a transaction's in-progress config). Pure and
/// synchronous — no store state needed, the same category as `ConfigOp::apply`.
pub fn diff_configs(base: &Config, candidate: &Config) -> ConfigDiff {
    let hostname = (base.hostname != candidate.hostname).then(|| FieldDiff {
        label: "hostname".to_string(),
        old: Some(base.hostname.clone()),
        new: Some(candidate.hostname.clone()),
    });
    ConfigDiff {
        hostname,
        bgp_instances: bgp_instance::diff_bgp_instances(
            &base.bgp_instances,
            &candidate.bgp_instances,
        ),
    }
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
        assert!(diff.bgp_instances.is_empty());
    }

    #[test]
    fn combined_hostname_and_instance_changes() {
        let base = Config {
            hostname: "router-a".to_string(),
            bgp_instances: vec![instance("r1", 65000)],
        };
        let candidate = Config {
            hostname: "router-b".to_string(),
            bgp_instances: vec![instance("r1", 65001), instance("r2", 65002)],
        };
        let diff = diff_configs(&base, &candidate);
        assert!(diff.hostname.is_some());
        assert_eq!(diff.bgp_instances.len(), 2);
    }
}
