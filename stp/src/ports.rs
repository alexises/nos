//! Config to the daemon's plan: which kernel links are STP ports and with
//! which parameters (pure).

use nos_proto::schema::{EdgePort, LinkType, SpanningTree};
use nos_proto::{Config, StpMode, StpPortAssignment, StpPortState, LOOPBACK_PREFIX};

use crate::actions::PortState;
use crate::timers::Timers;

/// One STP port: a physical `Interface` or a `PortAggregate` (the bond, never
/// one of its members) with a `switching_profile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortCfg {
    /// Config name, also the kernel device the BPDU socket binds to.
    pub name: String,
    /// Broadcast domains of the port's switching profile (CIST state is
    /// expanded to each).
    pub domains: Vec<String>,
    pub priority: u8,
    /// `None`: automatic from the link speed.
    pub cost: Option<u32>,
    pub edge: EdgePort,
    pub link_type: LinkType,
}

/// Everything the engine is built from; a changed plan rebuilds the bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub priority: u16,
    pub timers: Timers,
    /// Sorted by name: a port's number is its index plus one.
    pub ports: Vec<PortCfg>,
}

/// `None` while spanning tree has nothing to do here: mode `disabled`, or a
/// mode this daemon does not run yet (MSTP, Rapid-PVST: later sub-issues).
pub fn plan(cfg: &Config) -> Option<Plan> {
    let st: &SpanningTree = &cfg.spanning_tree;
    if st.mode != StpMode::Rstp {
        return None;
    }
    let mut ports: Vec<PortCfg> = cfg
        .interfaces
        .iter()
        .filter(|i| i.port_aggregate.is_none() && !i.name.starts_with(LOOPBACK_PREFIX))
        .filter_map(|i| {
            port(
                cfg,
                &i.name,
                i.switching_profile.as_deref(),
                i.stp_port_profile.as_deref(),
            )
        })
        .chain(cfg.port_aggregates.iter().filter_map(|a| {
            port(
                cfg,
                &a.name,
                a.switching_profile.as_deref(),
                a.stp_port_profile.as_deref(),
            )
        }))
        .collect();
    ports.sort_by(|a, b| a.name.cmp(&b.name));
    Some(Plan {
        priority: st.priority,
        timers: Timers {
            hello: st.hello_time,
            max_age: st.max_age,
            forward_delay: st.forward_delay,
            tx_hold_count: st.tx_hold_count,
            ..Timers::default()
        },
        ports,
    })
}

fn port(
    cfg: &Config,
    name: &str,
    switching: Option<&str>,
    profile: Option<&str>,
) -> Option<PortCfg> {
    let switching = switching?;
    let sw = cfg
        .switching_profiles
        .iter()
        .find(|p| p.name == switching)?;
    let prof = profile.and_then(|n| cfg.stp_port_profiles.iter().find(|p| p.name == n));
    Some(PortCfg {
        name: name.to_string(),
        domains: sw
            .members
            .iter()
            .map(|m| m.broadcast_domain.clone())
            .collect(),
        priority: prof.map_or(128, |p| p.priority),
        cost: prof.and_then(|p| p.cost),
        edge: prof.map_or(EdgePort::Auto, |p| p.edge_port),
        link_type: prof.map_or(LinkType::Auto, |p| p.link_type),
    })
}

/// The kernel state `nos-interfaced` writes for a core state.
pub fn kernel_state(s: PortState) -> StpPortState {
    match s {
        PortState::Discarding => StpPortState::Blocking,
        PortState::Learning => StpPortState::Learning,
        PortState::Forwarding => StpPortState::Forwarding,
    }
}

/// The CIST state of `port` as one assignment per domain it is a member of.
pub fn assignments(port: &PortCfg, s: PortState) -> Vec<StpPortAssignment> {
    port.domains
        .iter()
        .map(|d| StpPortAssignment {
            port: port.name.clone(),
            domain: d.clone(),
            state: kernel_state(s),
        })
        .collect()
}

/// `(port, domain)` pairs whose learned MACs to flush.
pub fn flushes(port: &PortCfg) -> Vec<(String, String)> {
    port.domains
        .iter()
        .map(|d| (port.name.clone(), d.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nos_proto::schema::StpPortProfile;
    use nos_proto::{Interface, PortAggregate, SwitchingProfile, SwitchingProfileMember};

    fn cfg() -> Config {
        let member = |d: &str| SwitchingProfileMember {
            broadcast_domain: d.into(),
            ..Default::default()
        };
        let iface = |name: &str, sw: bool| Interface {
            name: name.into(),
            switching_profile: sw.then(|| "sw".to_string()),
            ..Default::default()
        };
        Config {
            switching_profiles: vec![SwitchingProfile {
                name: "sw".into(),
                members: vec![member("d1"), member("d2")],
            }],
            stp_port_profiles: vec![StpPortProfile {
                name: "fast".into(),
                edge_port: EdgePort::Admin,
                cost: Some(77),
                priority: 64,
                ..Default::default()
            }],
            interfaces: vec![
                Interface {
                    stp_port_profile: Some("fast".into()),
                    ..iface("eth2", true)
                },
                iface("eth1", true),
                // a bond member, an L3-only interface and a loopback: no ports
                Interface {
                    port_aggregate: Some("bond0".into()),
                    ..iface("eth3", true)
                },
                iface("eth4", false),
                iface("loopback-lo", true),
            ],
            port_aggregates: vec![PortAggregate {
                name: "bond0".into(),
                switching_profile: Some("sw".into()),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn discovers_physical_and_bond_ports_sorted() {
        let p = plan(&cfg()).unwrap();
        let names: Vec<_> = p.ports.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["bond0", "eth1", "eth2"]);
        assert_eq!(p.ports[1].domains, ["d1", "d2"]);
        assert_eq!(p.ports[1].priority, 128);
        assert_eq!(p.ports[1].cost, None);
        assert_eq!(p.ports[2].priority, 64);
        assert_eq!(p.ports[2].cost, Some(77));
        assert_eq!(p.ports[2].edge, EdgePort::Admin);
        assert_eq!(p.priority, 32768);
    }

    #[test]
    fn only_rstp_mode_has_a_plan() {
        for mode in [StpMode::Disabled, StpMode::Mstp, StpMode::RapidPvst] {
            let mut c = cfg();
            c.spanning_tree.mode = mode;
            assert_eq!(plan(&c), None, "{mode:?}");
        }
    }

    #[test]
    fn dangling_switching_profile_is_not_a_port() {
        let mut c = cfg();
        c.switching_profiles.clear();
        assert_eq!(plan(&c).unwrap().ports.len(), 0);
    }

    #[test]
    fn state_expands_to_every_domain() {
        let p = plan(&cfg()).unwrap();
        let a = assignments(&p.ports[1], PortState::Discarding);
        assert_eq!(a.len(), 2);
        assert_eq!(a[1].port, "eth1");
        assert_eq!(a[1].domain, "d2");
        assert_eq!(a[1].state, StpPortState::Blocking);
        assert_eq!(
            assignments(&p.ports[1], PortState::Forwarding)[0].state,
            StpPortState::Forwarding
        );
        assert_eq!(
            assignments(&p.ports[1], PortState::Learning)[0].state,
            StpPortState::Learning
        );
        assert_eq!(
            flushes(&p.ports[1]),
            [("eth1".into(), "d1".into()), ("eth1".into(), "d2".into())]
        );
    }
}
