use garde::Validate;
use serde::{Deserialize, Serialize};

use super::Config;

/// A named OSPF profile, declared inside an area (`OspfArea.profiles`) but
/// referenced by bare name from any L3 attach point's `ospf_profile` field
/// (`Interface`/`Subinterface`/`BroadcastDomain`) with no instance/area
/// qualifier — so, like `BgpPeerGroup.name`, its uniqueness is enforced
/// globally across the whole config, not just within its owning area. Minimal
/// today: just a name, since OSPF has no wire protocol yet (see
/// `ospf/CLAUDE.md`) — a future hello/dead-interval-style field lands as an
/// additive field here, not a reshape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
#[garde(context(Config as ctx))]
pub struct OspfProfile {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, ctx: &Config| unique_name(n, ctx))
    )]
    pub name: String,
}

/// Profile names are unique across the whole config, not just within the
/// owning area — mirrors `bgp_peer_group::unique_name`, flattened one level
/// further (`ospf_instances -> areas -> profiles` instead of
/// `bgp_instances -> peer_groups`).
fn unique_name(name: &str, ctx: &Config) -> garde::Result {
    let count = ctx
        .ospf_instances
        .iter()
        .flat_map(|i| &i.areas)
        .flat_map(|a| &a.profiles)
        .filter(|p| p.name == name)
        .count();
    if count > 1 {
        return Err(garde::Error::new("must be unique"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use garde::Validate as _;

    use crate::schema::{Config, OspfArea, OspfInstance};

    use super::OspfProfile;

    fn profile(name: &str) -> OspfProfile {
        OspfProfile {
            name: name.to_string(),
        }
    }

    fn area(area_id: &str, profiles: Vec<OspfProfile>) -> OspfArea {
        OspfArea {
            area_id: area_id.parse().unwrap(),
            profiles,
        }
    }

    fn instance(name: &str, areas: Vec<OspfArea>) -> OspfInstance {
        OspfInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            areas,
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
    fn valid_profile_passes() {
        let cfg = config_with(vec![instance(
            "r1",
            vec![area("0.0.0.0", vec![profile("p1")])],
        )]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_name_within_same_area_fails() {
        let cfg = config_with(vec![instance(
            "r1",
            vec![area("0.0.0.0", vec![profile("p1"), profile("p1")])],
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_name_across_areas_fails() {
        let cfg = config_with(vec![instance(
            "r1",
            vec![
                area("0.0.0.0", vec![profile("p1")]),
                area("0.0.0.1", vec![profile("p1")]),
            ],
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_name_across_instances_fails() {
        let cfg = config_with(vec![
            instance("r1", vec![area("0.0.0.0", vec![profile("p1")])]),
            instance("r2", vec![area("0.0.0.0", vec![profile("p1")])]),
        ]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn distinct_names_pass() {
        let cfg = config_with(vec![instance(
            "r1",
            vec![area("0.0.0.0", vec![profile("p1"), profile("p2")])],
        )]);
        cfg.validate_with(&cfg).unwrap();
    }
}
