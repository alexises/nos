use std::net::Ipv4Addr;

use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_in;

use super::{Config, OspfArea};
use nos_proto_derive::Cli;

/// A named OSPF instance. Basic configuration only today — `router_id`, the
/// routing-table (VRF) association mirroring `BgpInstance`'s own minimal
/// shape, and `areas` (dotted-quad-keyed, see `OspfArea`). No interfaces
/// beyond what a nested area's profiles can be attached to yet, and no wire
/// protocol — this is a config-only skeleton, see `ospf/CLAUDE.md`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct OspfInstance {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, ctx: &Config| unique_in(n, &ctx.ospf_instances, |i| &i.name))
    )]
    #[cli(key)]
    pub name: String,

    // Ipv4Addr is structurally valid by construction; no additional garde rule needed.
    #[garde(skip)]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(topic = OspfInstanceRouterId)]
    pub router_id: Ipv4Addr,

    /// This instance's OSPF areas, keyed by `area_id` — see `OspfArea`.
    #[garde(dive, custom(|areas, _ctx: &Config| unique_area_ids(areas)))]
    #[cli(topic = OspfArea)]
    pub areas: Vec<OspfArea>,

    /// The name of the `RoutingTable` that claims this instance (i.e. the
    /// VRF it belongs to), mirrored from that table's `ospf_instance` field.
    /// Derived and read-only: never set by any `OspfInstanceOp`, recomputed
    /// by `nos-config` (`crate::derive::sync_routing_table_refs`) on every
    /// commit and on load, so an operator only ever edits the one
    /// authoritative reference (`RoutingTable.ospf_instance`). `nos-ospfd`
    /// reads this directly to resolve its own VRF without scanning every
    /// routing table. Deliberately not rendered by `nos-cli`.
    #[garde(skip)]
    #[cli(hidden)]
    pub routing_table: Option<String>,

    /// The name of the RPL policy filtering routes redistributed into this
    /// instance, mirrored from the owning `RoutingTable.redistribute.policy`
    /// (only when `redistribute.to == Ospf`). Derived and read-only, exactly
    /// like `routing_table` above: never set by any `OspfInstanceOp`,
    /// recomputed by `nos-config` (`crate::derive::sync_routing_table_refs`)
    /// on every commit and on load. `nos-ospfd` reads this directly to
    /// resolve its own redistribution policy without scanning every routing
    /// table. Deliberately not rendered by `nos-cli`.
    #[garde(skip)]
    #[cli(hidden)]
    pub redistribute_policy: Option<String>,

    /// RFC 3623 graceful restart: on a planned shutdown, send a Grace-LSA
    /// asking every `Full` neighbor to keep the adjacency (and this router's
    /// routes) for this many seconds while the daemon restarts. `None`
    /// (default) disables it. Helper mode needs no config — every instance
    /// always helps a restarting neighbor.
    // ponytail: capped at 1800s; RFC 3623 sets no ceiling, raise if asked.
    #[serde(default)]
    #[garde(range(min = 1, max = 1800))]
    #[cli(topic = OspfInstanceGracefulRestart, words = "graceful-restart grace-period")]
    pub graceful_restart_grace_period: Option<u16>,
}

/// The placeholder a new `OspfInstance` starts from (`edit` on a missing one).
impl Default for OspfInstance {
    fn default() -> Self {
        OspfInstance {
            name: String::new(),
            router_id: Ipv4Addr::UNSPECIFIED,
            areas: Vec::new(),
            routing_table: None,
            redistribute_policy: None,
            graceful_restart_grace_period: None,
        }
    }
}

/// No two areas within the same instance may share an `area_id` — mirrors
/// `static_routing_instance::unique_subnets`. Scoped to `self.areas` only
/// (per-instance, not global — unlike `OspfProfile.name`).
fn unique_area_ids(areas: &[OspfArea]) -> garde::Result {
    let mut seen: Vec<Ipv4Addr> = Vec::new();
    for a in areas {
        if seen.contains(&a.area_id) {
            return Err(garde::Error::new(
                "must not repeat an area id within the same ospf instance",
            ));
        }
        seen.push(a.area_id);
    }
    Ok(())
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
            areas: Vec::new(),
            routing_table: None,
            redistribute_policy: None,
            graceful_restart_grace_period: None,
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
