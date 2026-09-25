use std::net::Ipv4Addr;

use garde::Validate;
use serde::{Deserialize, Serialize};

use super::ospf_profile;
use super::{Config, OspfProfile};

/// One OSPF area within an `OspfInstance`, keyed by its dotted-quad area id
/// (e.g. `0.0.0.0` for the backbone). Unique only within its owning
/// instance — never referenced from outside `OspfInstance`, unlike
/// `OspfProfile.name` — so uniqueness is enforced on the parent's `areas`
/// field (`ospf_instance::unique_area_ids`), not here.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
#[garde(context(Config as ctx))]
pub struct OspfArea {
    // Ipv4Addr is structurally valid by construction; uniqueness lives on
    // the owning OspfInstance.areas field instead.
    #[garde(skip)]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub area_id: Ipv4Addr,

    #[garde(
        dive,
        custom(|profiles, _ctx: &Config| ospf_profile::valid_profile_timers(profiles))
    )]
    pub profiles: Vec<OspfProfile>,
}

#[cfg(test)]
mod tests {
    use garde::Validate as _;

    use crate::schema::{Config, OspfInstance};

    use super::OspfArea;

    fn area(area_id: &str) -> OspfArea {
        OspfArea {
            area_id: area_id.parse().unwrap(),
            profiles: Vec::new(),
        }
    }

    fn instance(name: &str, areas: Vec<OspfArea>) -> OspfInstance {
        OspfInstance {
            name: name.to_string(),
            router_id: "1.1.1.1".parse().unwrap(),
            areas,
            routing_table: None,
            redistribute_policy: None,
        }
    }

    fn config_with(instances: Vec<OspfInstance>) -> Config {
        Config {
            ospf_instances: instances,
            ..Default::default()
        }
    }

    #[test]
    fn valid_area_passes() {
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0")])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_area_id_within_instance_fails() {
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0"), area("0.0.0.0")])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn distinct_area_ids_within_instance_pass() {
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0"), area("0.0.0.1")])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn same_area_id_across_different_instances_passes() {
        let cfg = config_with(vec![
            instance("r1", vec![area("0.0.0.0")]),
            instance("r2", vec![area("0.0.0.0")]),
        ]);
        cfg.validate_with(&cfg).unwrap();
    }
}
