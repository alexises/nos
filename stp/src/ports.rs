//! Config to the daemon's plan: which kernel links are STP ports and with
//! which parameters (pure).

use nos_proto::schema::{EdgePort, LinkType, SpanningTree, StpForceVersion};
use nos_proto::{Config, StpMode, StpPortAssignment, StpPortState, VlanTag, LOOPBACK_PREFIX};

use crate::actions::PortState;
use crate::machines::Protections;
use crate::mst::{digest, vidmap, MstPlan, PortMst};
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
    pub prot: Protections,
    /// The port's `mst-instance` settings (MSTP only).
    pub mst: Vec<PortMst>,
    /// The port's switching-profile memberships (Rapid-PVST+ trees).
    pub members: Vec<Member>,
}

/// One broadcast domain on a port: its tag and the per-(port, domain) overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub domain: String,
    pub tag: VlanTag,
    pub cost: Option<u32>,
    pub priority: Option<u8>,
}

/// One Rapid-PVST+ tree: a broadcast domain, run as an ordinary RSTP bridge
/// over the ports that are members of the domain (#322).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreePlan {
    pub domain: String,
    /// The domain's VLAN: its dot1q tag, 1 when it is only untagged.
    pub vid: u16,
    /// `ext` is the VLAN (802.1Q 13.2 system id extension); `ports` are the
    /// members only, with the member's cost and priority.
    pub plan: Box<Plan>,
    /// The tag of each of `plan.ports`: it picks the BPDU link (`ethX.<tag>`
    /// or the link itself).
    pub tags: Vec<VlanTag>,
}

/// Everything the engine is built from; a changed plan rebuilds the bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub priority: u16,
    /// `force-version stp` turns RSTP off; unset and `rstp` allow it.
    pub rstp_version: bool,
    pub timers: Timers,
    /// Sorted by name: a port's number is its index plus one.
    pub ports: Vec<PortCfg>,
    /// `Some` in mode `mstp`.
    pub mst: Option<MstPlan>,
    /// System id extension of the bridge id: the VLAN of a Rapid-PVST+ tree,
    /// 0 otherwise.
    pub ext: u16,
    /// The domain a Rapid-PVST+ tree belongs to (it labels the tree's logs).
    pub domain: Option<String>,
    /// `Some` in mode `rapid-pvst`: the trees, `ports` above being all ports.
    pub pvst: Option<Vec<TreePlan>>,
}

fn mst_plan(cfg: &Config) -> MstPlan {
    let st = &cfg.spanning_tree;
    let domains = vidmap::domains(cfg);
    let mut instances: Vec<(u16, u16)> = st
        .mst_instances
        .iter()
        .map(|m| (m.id, m.priority))
        .collect();
    instances.sort_unstable();
    MstPlan {
        name: st.region.name.clone(),
        revision: st.region.revision,
        digest: digest::digest(&vidmap::table(&domains)),
        max_hops: st.max_hops,
        instances,
        domains,
    }
}

fn pvst_trees(cfg: &Config, ports: &[PortCfg]) -> Vec<TreePlan> {
    let st = &cfg.spanning_tree;
    vidmap::domains(cfg)
        .into_iter()
        .filter_map(|(domain, vid, _)| {
            let (mut sub, mut tags) = (Vec::new(), Vec::new());
            for p in ports {
                let Some(m) = p.members.iter().find(|m| m.domain == domain) else {
                    continue;
                };
                tags.push(m.tag);
                sub.push(PortCfg {
                    domains: vec![domain.clone()],
                    cost: m.cost.or(p.cost),
                    priority: m.priority.unwrap_or(p.priority),
                    mst: Vec::new(),
                    members: vec![m.clone()],
                    ..p.clone()
                });
            }
            if sub.is_empty() {
                return None;
            }
            let bd = cfg.broadcast_domains.iter().find(|d| d.name == domain);
            let own = |f: fn(&nos_proto::BroadcastDomain) -> Option<u8>, global: u8| {
                bd.and_then(f).unwrap_or(global)
            };
            Some(TreePlan {
                vid,
                plan: Box::new(Plan {
                    priority: bd.and_then(|d| d.stp_priority).unwrap_or(st.priority),
                    rstp_version: st.force_version != Some(StpForceVersion::Stp),
                    timers: Timers {
                        hello: own(|d| d.stp_hello_time, st.hello_time),
                        max_age: own(|d| d.stp_max_age, st.max_age),
                        forward_delay: own(|d| d.stp_forward_delay, st.forward_delay),
                        tx_hold_count: st.tx_hold_count,
                        ..Timers::default()
                    },
                    ports: sub,
                    mst: None,
                    ext: vid,
                    domain: Some(domain.clone()),
                    pvst: None,
                }),
                tags,
                domain,
            })
        })
        .collect()
}

/// `None` while spanning tree has nothing to do here: mode `disabled`.
pub fn plan(cfg: &Config) -> Option<Plan> {
    let st: &SpanningTree = &cfg.spanning_tree;
    if st.mode == StpMode::Disabled {
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
    let pvst = (st.mode == StpMode::RapidPvst).then(|| pvst_trees(cfg, &ports));
    Some(Plan {
        priority: st.priority,
        rstp_version: st.force_version != Some(StpForceVersion::Stp),
        timers: Timers {
            hello: st.hello_time,
            max_age: st.max_age,
            forward_delay: st.forward_delay,
            tx_hold_count: st.tx_hold_count,
            ..Timers::default()
        },
        ports,
        mst: (st.mode == StpMode::Mstp).then(|| mst_plan(cfg)),
        ext: 0,
        domain: None,
        pvst,
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
        members: sw
            .members
            .iter()
            .map(|m| Member {
                domain: m.broadcast_domain.clone(),
                tag: m.tag,
                cost: m.stp_cost,
                priority: m.stp_priority,
            })
            .collect(),
        priority: prof.map_or(128, |p| p.priority),
        cost: prof.and_then(|p| p.cost),
        edge: prof.map_or(EdgePort::Auto, |p| p.edge_port),
        link_type: prof.map_or(LinkType::Auto, |p| p.link_type),
        prot: prof.map_or_else(Protections::default, |p| Protections {
            bpdu_guard: p.bpdu_guard,
            recovery: p.bpdu_guard_recovery,
            bpdu_filter: p.bpdu_filter,
            root_guard: p.root_guard,
            loop_guard: p.loop_guard,
            restricted_tcn: p.restricted_tcn,
        }),
        mst: prof.map_or_else(Vec::new, |p| {
            p.mst_instances
                .iter()
                .map(|m| PortMst {
                    id: m.id,
                    cost: m.cost,
                    priority: m.priority,
                })
                .collect()
        }),
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

/// The domains of `port` that run in `tree` (0: the CIST, which also owns
/// every domain when there is no MST plan).
pub fn tree_domains<'a>(
    port: &'a PortCfg,
    mst: Option<&'a MstPlan>,
    tree: u16,
) -> impl Iterator<Item = &'a String> {
    port.domains
        .iter()
        .filter(move |d| mst.map_or(0, |m| m.tree_of(d)) == tree)
}

/// The state of `port` in `tree` as one assignment per domain it is a member of.
pub fn assignments(
    port: &PortCfg,
    mst: Option<&MstPlan>,
    tree: u16,
    s: PortState,
) -> Vec<StpPortAssignment> {
    tree_domains(port, mst, tree)
        .map(|d| StpPortAssignment {
            port: port.name.clone(),
            domain: d.clone(),
            state: kernel_state(s),
        })
        .collect()
}

/// `(port, domain)` pairs of `tree` whose learned MACs to flush.
pub fn flushes(port: &PortCfg, mst: Option<&MstPlan>, tree: u16) -> Vec<(String, String)> {
    tree_domains(port, mst, tree)
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
                bpdu_guard: true,
                bpdu_guard_recovery: Some(30),
                root_guard: true,
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
        let prot = p.ports[2].prot;
        assert!(prot.bpdu_guard && prot.root_guard && !prot.loop_guard);
        assert_eq!(prot.recovery, Some(30));
        assert_eq!(p.ports[1].prot, Protections::default());
        assert_eq!(p.priority, 32768);
    }

    #[test]
    fn only_disabled_has_no_plan() {
        let mut c = cfg();
        c.spanning_tree.mode = StpMode::Disabled;
        assert_eq!(plan(&c), None);
        assert_eq!(plan(&cfg()).unwrap().mst, None);
        assert_eq!(plan(&cfg()).unwrap().pvst, None);
    }

    #[test]
    fn mstp_plan_carries_the_region_and_the_vid_map() {
        use nos_proto::schema::{MstInstance, StpPortMstInstance, StpRegion};
        use nos_proto::{BroadcastDomain, VlanTag};
        let mut c = cfg();
        c.spanning_tree.mode = StpMode::Mstp;
        c.spanning_tree.region = StpRegion {
            name: "lab".into(),
            revision: 3,
        };
        c.spanning_tree.mst_instances = vec![MstInstance {
            id: 1,
            priority: 4096,
        }];
        for sp in &mut c.switching_profiles {
            sp.members[0].tag = VlanTag::Dot1q(10);
            sp.members[1].tag = VlanTag::Dot1q(20);
        }
        c.broadcast_domains = vec![
            BroadcastDomain {
                name: "d1".into(),
                stp_instance: Some(1),
                ..Default::default()
            },
            BroadcastDomain {
                name: "d2".into(),
                ..Default::default()
            },
        ];
        c.stp_port_profiles[0].mst_instances = vec![StpPortMstInstance {
            id: 1,
            cost: Some(500),
            priority: 32,
        }];
        let p = plan(&c).unwrap();
        let m = p.mst.unwrap();
        assert_eq!((m.name.as_str(), m.revision, m.max_hops), ("lab", 3, 20));
        assert_eq!(m.instances, [(1, 4096)]);
        assert_eq!(m.tree_of("d1"), 1);
        assert_eq!(m.tree_of("d2"), 0);
        assert_eq!(m.tree_of("nowhere"), 0);
        assert_ne!(m.digest, digest::digest(&[0; 4096]));
        assert_eq!(
            p.ports[2].mst,
            [PortMst {
                id: 1,
                cost: Some(500),
                priority: 32
            }]
        );
        assert_eq!(p.ports[1].mst, Vec::<PortMst>::new());
    }

    #[test]
    fn rapid_pvst_plans_one_tree_per_domain_with_member_overrides() {
        use nos_proto::BroadcastDomain;
        let mut c = cfg();
        c.spanning_tree.mode = StpMode::RapidPvst;
        for sp in &mut c.switching_profiles {
            sp.members[0].tag = VlanTag::Dot1q(10);
            sp.members[0].stp_cost = Some(500);
            sp.members[1].stp_priority = Some(32);
        }
        c.broadcast_domains = vec![BroadcastDomain {
            name: "d1".into(),
            stp_priority: Some(4096),
            stp_hello_time: Some(1),
            ..Default::default()
        }];
        let trees = plan(&c).unwrap().pvst.unwrap();
        // sorted by VID: the untagged-only d2 is VLAN 1
        let [d2, d1] = &trees[..] else {
            panic!("{trees:?}")
        };
        assert_eq!((d1.domain.as_str(), d1.vid), ("d1", 10));
        assert_eq!((d1.plan.ext, d1.plan.priority), (10, 4096));
        assert_eq!(d1.plan.timers.hello, 1);
        assert_eq!(d1.plan.timers.max_age, 20, "inherited");
        let names: Vec<_> = d1.plan.ports.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["bond0", "eth1", "eth2"]);
        assert!(d1.plan.ports.iter().all(|p| p.cost == Some(500)));
        assert_eq!(d1.tags, [VlanTag::Dot1q(10); 3]);
        assert_eq!(d1.plan.domain.as_deref(), Some("d1"));
        assert_eq!((d2.vid, d2.plan.ext, d2.plan.priority), (1, 1, 32768));
        assert_eq!(d2.tags, [VlanTag::Untagged; 3]);
        assert_eq!(
            d2.plan.ports[2].priority, 32,
            "member beats the profile's 64"
        );
        assert_eq!(
            d2.plan.ports[2].cost,
            Some(77),
            "profile cost when the member has none"
        );
        assert_eq!(d2.plan.timers.hello, 2);
    }

    #[test]
    fn force_version_stp_turns_rstp_off() {
        let mut c = cfg();
        assert!(plan(&c).unwrap().rstp_version);
        c.spanning_tree.force_version = Some(StpForceVersion::Rstp);
        assert!(plan(&c).unwrap().rstp_version);
        c.spanning_tree.force_version = Some(StpForceVersion::Stp);
        assert!(!plan(&c).unwrap().rstp_version);
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
        let a = assignments(&p.ports[1], None, 0, PortState::Discarding);
        assert_eq!(a.len(), 2);
        assert_eq!(a[1].port, "eth1");
        assert_eq!(a[1].domain, "d2");
        assert_eq!(a[1].state, StpPortState::Blocking);
        assert_eq!(
            assignments(&p.ports[1], None, 0, PortState::Forwarding)[0].state,
            StpPortState::Forwarding
        );
        assert_eq!(
            assignments(&p.ports[1], None, 0, PortState::Learning)[0].state,
            StpPortState::Learning
        );
        assert_eq!(
            flushes(&p.ports[1], None, 0),
            [("eth1".into(), "d1".into()), ("eth1".into(), "d2".into())]
        );
    }

    #[test]
    fn a_tree_only_owns_its_domains() {
        let p = plan(&cfg()).unwrap();
        let m = MstPlan {
            name: String::new(),
            revision: 0,
            digest: [0; 16],
            max_hops: 20,
            instances: vec![(1, 32768)],
            domains: vec![("d1".into(), 10, 1), ("d2".into(), 20, 0)],
        };
        let doms = |tree| {
            assignments(&p.ports[1], Some(&m), tree, PortState::Forwarding)
                .into_iter()
                .map(|a| a.domain)
                .collect::<Vec<_>>()
        };
        assert_eq!(doms(0), ["d2"]);
        assert_eq!(doms(1), ["d1"]);
        assert_eq!(
            flushes(&p.ports[1], Some(&m), 1),
            [("eth1".into(), "d1".into())]
        );
    }
}
