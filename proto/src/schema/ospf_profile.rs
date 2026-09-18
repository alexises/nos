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

/// This profile's own Router Priority when left unset. RFC 2328 Appendix
/// C.3's typical default. `0` is a legal, meaningful value too — it means
/// "never eligible to become DR/BDR" (see `ospf::election`) — so this is
/// only a default, never a floor.
pub const PRIORITY_DEFAULT: u8 = 1;

/// Which RFC 2328 network type an attach point using this profile runs.
/// `OspfProfile.network_type` is `Option` — see its doc comment for how an
/// unset value is resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkType {
    PointToPoint,
    Broadcast,
}

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

    /// Interface cost, in the usual OSPF sense (lower is preferred by
    /// SPF). `None` defaults to `1` — a real behavioral consumer:
    /// `ospf::link::router_lsa_links`/`originate_router_lsas` use it as
    /// this link's RFC 2328 §16 metric, and `ospf::spf::compute` sums it
    /// along the Dijkstra path. `0` is rejected (not a valid OSPF cost).
    #[garde(custom(|c: &Option<u16>, _ctx: &Config| valid_cost(*c)))]
    pub cost: Option<u16>,

    /// `None` defaults to `PRIORITY_DEFAULT` (1). Governs RFC 2328 §9.4
    /// DR/BDR election eligibility on a `Broadcast` attach point; sent on
    /// the wire (but functionally inert) on a `PointToPoint` one too.
    #[garde(skip)]
    pub priority: Option<u8>,

    /// `None` resolves per attach point: a `Subinterface`/loopback
    /// `Interface` attach point defaults to `PointToPoint`, a
    /// `BroadcastDomain` one defaults to `Broadcast` — resolved by
    /// `ospf::reconcile`, not here, since one profile may be referenced by
    /// attach points of different kinds at once. Setting this explicitly
    /// overrides that default per attach point (e.g. forcing
    /// point-to-point behavior on a `BroadcastDomain` attach point, or
    /// vice versa) — never validated against the attach point's own kind,
    /// matching real OSPF's own allowance for this.
    #[garde(skip)]
    pub network_type: Option<NetworkType>,
}

fn valid_cost(cost: Option<u16>) -> garde::Result {
    match cost {
        Some(0) => Err(garde::Error::new("cost must be between 1 and 65535")),
        _ => Ok(()),
    }
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

    use super::{NetworkType, OspfProfile};

    fn profile(name: &str) -> OspfProfile {
        OspfProfile {
            name: name.to_string(),
            hello_interval: None,
            dead_interval: None,
            cost: None,
            priority: None,
            network_type: None,
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
            cost: None,
            priority: None,
            network_type: None,
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

    #[test]
    fn nonzero_cost_passes() {
        let mut p = profile("p1");
        p.cost = Some(10);
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn zero_cost_fails() {
        let mut p = profile("p1");
        p.cost = Some(0);
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn unset_cost_passes() {
        let cfg = config_with(vec![instance(
            "r1",
            vec![area("0.0.0.0", vec![profile("p1")])],
        )]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn any_priority_passes() {
        let mut p = profile("p1");
        p.priority = Some(0);
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn either_network_type_passes() {
        for network_type in [NetworkType::PointToPoint, NetworkType::Broadcast] {
            let mut p = profile("p1");
            p.network_type = Some(network_type);
            let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
            cfg.validate_with(&cfg).unwrap();
        }
    }
}
