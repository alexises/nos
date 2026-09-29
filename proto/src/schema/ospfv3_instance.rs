use std::net::Ipv4Addr;

use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_in;

use super::{Config, Ospfv3Area};
use nos_proto_derive::Cli;

/// A named `OSPFv3` (RFC 5340) instance — the IPv6 counterpart of
/// `OspfInstance`, kept as a fully parallel type rather than widened onto
/// it, since `OSPFv2` and `OSPFv3` are different wire protocols (different
/// packet/LSA formats) run by two independent daemons (`nos-ospfd`/
/// `nos-ospfv3d`) — see the `OSPFv3` Phase 1 plan. `router_id`/`area_id`
/// (on `Ospfv3Area`) stay `Ipv4Addr`: RFC 5340 keeps these as opaque 32-bit
/// identifiers, not real addresses, exactly like RFC 2328.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct Ospfv3Instance {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, ctx: &Config| unique_in(n, &ctx.ospfv3_instances, |i| &i.name))
    )]
    #[cli(key)]
    pub name: String,

    // Ipv4Addr is structurally valid by construction; no additional garde rule needed.
    #[garde(skip)]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(topic = Ospfv3InstanceRouterId)]
    pub router_id: Ipv4Addr,

    /// This instance's `OSPFv3` areas, keyed by `area_id` — see `Ospfv3Area`.
    #[garde(dive, custom(|areas, _ctx: &Config| unique_area_ids(areas)))]
    #[cli(topic = Ospfv3Area)]
    pub areas: Vec<Ospfv3Area>,

    /// The name of the `RoutingTable` that claims this instance (i.e. the
    /// VRF it belongs to), mirrored from that table's `ospfv3_instance`
    /// field — same derived/read-only pattern as `OspfInstance.routing_table`
    /// (`crate::derive::sync_routing_table_refs`). No `redistribute_policy`
    /// counterpart: Phase 1 has no ASBR support, so there's nothing to
    /// redistribute into an `OSPFv3` instance yet.
    #[garde(skip)]
    #[cli(hidden)]
    pub routing_table: Option<String>,

    /// RFC 8362 Full mode: originate/consume the TLV-based extended LSAs
    /// (E-Router, E-Network, E-Link, E-Intra-Area-Prefix) instead of the
    /// RFC 5340 legacy set. Off by default; `#[serde(default)]` so configs
    /// saved before this field existed still load.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = Ospfv3InstanceExtendedLsa)]
    pub extended_lsa: bool,
}

/// The placeholder a new `Ospfv3Instance` starts from (`edit` on a missing one).
impl Default for Ospfv3Instance {
    fn default() -> Self {
        Ospfv3Instance {
            name: String::new(),
            router_id: Ipv4Addr::UNSPECIFIED,
            areas: Vec::new(),
            routing_table: None,
            extended_lsa: false,
        }
    }
}

/// No two areas within the same instance may share an `area_id` — mirrors
/// `ospf_instance::unique_area_ids` exactly.
fn unique_area_ids(areas: &[Ospfv3Area]) -> garde::Result {
    let mut seen: Vec<Ipv4Addr> = Vec::new();
    for a in areas {
        if seen.contains(&a.area_id) {
            return Err(garde::Error::new(
                "must not repeat an area id within the same ospfv3 instance",
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

    use super::Ospfv3Instance;

    fn instance(name: &str) -> Ospfv3Instance {
        Ospfv3Instance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            areas: Vec::new(),
            routing_table: None,
            extended_lsa: false,
        }
    }

    fn config_with(instances: Vec<Ospfv3Instance>) -> Config {
        Config {
            ospfv3_instances: instances,
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
