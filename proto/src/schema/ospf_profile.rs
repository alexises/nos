use garde::Validate;
use serde::{Deserialize, Serialize};

use super::Config;

/// This profile's own proposed Hello interval when left unset. RFC 2328
/// Appendix C.3's point-to-point/broadcast default — the only network type
/// this NOS models today (see `ospf/CLAUDE.md`).
pub const HELLO_INTERVAL_DEFAULT: u16 = 10;

/// This profile's own proposed router dead interval when left unset. RFC
/// 2328 Appendix C.3's point-to-point/broadcast default.
pub const DEAD_INTERVAL_DEFAULT: u16 = 40;

/// A named OSPF profile, declared inside an area (`OspfArea.profiles`) but
/// referenced by bare name from any L3 attach point's `ospf_profile` field
/// (`Interface`/`Subinterface`/`BroadcastDomain`) with no instance/area
/// qualifier — so, like `BgpPeerGroup.name`, its uniqueness is enforced
/// globally across the whole config, not just within its owning area.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
#[garde(context(Config as ctx))]
pub struct OspfProfile {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, ctx: &Config| unique_name(n, ctx))
    )]
    pub name: String,

    /// `None` defaults to `HELLO_INTERVAL_DEFAULT` (10s).
    #[garde(skip)]
    pub hello_interval: Option<u16>,

    /// `None` defaults to `DEAD_INTERVAL_DEFAULT` (40s). When both this and
    /// `hello_interval` are set, this must be strictly greater than
    /// `hello_interval` — checked one level up, on `OspfArea.profiles`,
    /// since garde's per-field `custom` closures can't see a sibling field
    /// (see `ospf_area.rs`, mirrors `bgp_peer_group`'s identical
    /// hold-time/keepalive-interval pattern).
    #[garde(skip)]
    pub dead_interval: Option<u16>,
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

/// Mirrors `bgp_peer_group::valid_peer_group_timers` exactly, one level
/// shallower (`OspfProfile` has no further-nested collection to skip over).
pub(crate) fn valid_profile_timers(profiles: &[OspfProfile]) -> garde::Result {
    for p in profiles {
        if let (Some(hello), Some(dead)) = (p.hello_interval, p.dead_interval) {
            if dead <= hello {
                return Err(garde::Error::new(
                    "dead-interval must be greater than hello-interval when both are set",
                ));
            }
        }
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
            hello_interval: None,
            dead_interval: None,
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

    fn profile_with_timers(
        name: &str,
        hello_interval: Option<u16>,
        dead_interval: Option<u16>,
    ) -> OspfProfile {
        OspfProfile {
            name: name.to_string(),
            hello_interval,
            dead_interval,
        }
    }

    #[test]
    fn dead_interval_greater_than_hello_interval_passes() {
        let cfg = config_with(vec![instance(
            "r1",
            vec![area(
                "0.0.0.0",
                vec![profile_with_timers("p1", Some(10), Some(40))],
            )],
        )]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn dead_interval_not_greater_than_hello_interval_fails() {
        let cfg = config_with(vec![instance(
            "r1",
            vec![area(
                "0.0.0.0",
                vec![profile_with_timers("p1", Some(10), Some(10))],
            )],
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn either_timer_unset_passes() {
        let cfg = config_with(vec![instance(
            "r1",
            vec![area(
                "0.0.0.0",
                vec![profile_with_timers("p1", Some(10), None)],
            )],
        )]);
        cfg.validate_with(&cfg).unwrap();
    }
}
