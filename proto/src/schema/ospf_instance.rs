use std::net::Ipv4Addr;

use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_in;

use super::Config;

/// A named OSPF instance. Basic configuration only today — `router_id` and
/// the routing-table (VRF) association, mirroring `BgpInstance`'s own
/// minimal shape. No areas/interfaces/neighbors yet — this is a config-only
/// skeleton, see `ospf/CLAUDE.md`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
#[garde(context(Config as ctx))]
pub struct OspfInstance {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, ctx: &Config| unique_in(n, &ctx.ospf_instances, |i| &i.name))
    )]
    pub name: String,

    // Ipv4Addr is structurally valid by construction; no additional garde rule needed.
    #[garde(skip)]
    pub router_id: Ipv4Addr,

    /// The name of the `RoutingTable` that claims this instance (i.e. the
    /// VRF it belongs to), mirrored from that table's `ospf_instance` field.
    /// Derived and read-only: never set by any `OspfInstanceOp`, recomputed
    /// by `nos-config` (`crate::derive::sync_routing_table_refs`) on every
    /// commit and on load, so an operator only ever edits the one
    /// authoritative reference (`RoutingTable.ospf_instance`). `nos-ospfd`
    /// reads this directly to resolve its own VRF without scanning every
    /// routing table. Deliberately not rendered by `nos-cli`.
    #[garde(skip)]
    pub routing_table: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use garde::Validate as _;

    use crate::schema::Config;

    use super::OspfInstance;

    fn instance(name: &str) -> OspfInstance {
        OspfInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            routing_table: None,
        }
    }

    fn config_with(instances: Vec<OspfInstance>) -> Config {
        Config {
            ospf_instances: instances,
            ..Default::default()
        }
    }

    #[test]
    fn valid_instance_passes() {
        let cfg = config_with(vec![instance("default")]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_name_fails() {
        let cfg = config_with(vec![instance("vrf-a"), instance("vrf-a")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn distinct_names_pass() {
        let cfg = config_with(vec![instance("vrf-a"), instance("vrf-b")]);
        cfg.validate_with(&cfg).unwrap();
    }
}
