//! The core hosted on real ports: turns the core's [`Action`]s into the three
//! things the daemon does (send a BPDU, push kernel states, flush an FDB) and
//! into the log lines the e2e phase anchors on. No I/O, no clock.

use nos_proto::{StpMode, StpPortAssignment, StpPortInfo, StpRole, StpState, StpSummary};
use tracing::{error, info, warn};

use crate::actions::{Action, Event, PortState};
use crate::bpdu::Bpdu;
use crate::bridge::{Bridge, PortParams};
use crate::identity;
use crate::machines::Role;
use crate::ports::{self, Plan, PortCfg};
use crate::vector::{IdError, PortId};
use nos_proto::schema::EdgePort;

/// What the daemon must do after a call into the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    /// Encode and send on port `port` (index into the plan).
    Tx { port: usize, bpdu: Bpdu },
    /// Kernel states to push to `nos-interfaced`.
    States(Vec<StpPortAssignment>),
    /// `(port, domain)` pairs to flush.
    Flush(Vec<(String, String)>),
    /// Take `port`'s link down (`true`) or back up (`false`) in `nos-interfaced`.
    ErrDisabled { port: String, disabled: bool },
}

pub struct Engine {
    bridge: Bridge,
    ports: Vec<PortCfg>,
}

impl Engine {
    /// A bridge with every port disabled; the returned outputs are its
    /// initial (blocking) states.
    pub fn new(plan: &Plan, mac: [u8; 6]) -> Result<(Self, Vec<Out>), IdError> {
        let params = plan
            .ports
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let number = u16::try_from(i + 1).map_err(|_| IdError::PortNumber(u16::MAX))?;
                Ok(PortParams {
                    id: PortId::new(p.priority, number)?,
                    path_cost: crate::link::path_cost(p.cost, crate::link::LinkInfo::default()),
                    admin_edge: p.edge == EdgePort::Admin,
                    auto_edge: p.edge == EdgePort::Auto,
                })
            })
            .collect::<Result<Vec<_>, IdError>>()?;
        let mut bridge = Bridge::new(
            identity::bridge_id(plan.priority, mac)?,
            plan.timers,
            &params,
        );
        bridge.set_rstp_version(plan.rstp_version);
        for (i, p) in plan.ports.iter().enumerate() {
            bridge.set_protections(i, p.prot);
        }
        let mut e = Engine {
            bridge,
            ports: plan.ports.clone(),
        };
        // A fresh bridge is its own root; the core only reports changes.
        info!(root = %identity::show(&e.bridge.root_id), "root bridge changed");
        let out = e.drain();
        Ok((e, out))
    }

    /// `mcheck` on the named port, or on every port (`None`); how many ports
    /// matched.
    pub fn mcheck(&mut self, interface: Option<&str>) -> (u32, Vec<Out>) {
        let mut n = 0;
        for i in 0..self.ports.len() {
            if interface.is_none_or(|name| name == self.ports[i].name) {
                self.bridge.mcheck(i);
                n += 1;
            }
        }
        (n, self.drain())
    }

    /// Err-disabled ports and their seconds to recovery (`None`: manual).
    pub fn err_disabled(&self) -> Vec<(String, Option<u32>)> {
        (0..self.ports.len())
            .filter_map(|i| Some((self.ports[i].name.clone(), self.bridge.err_disabled(i)?)))
            .collect()
    }

    /// Keep a port err-disabled across a bridge rebuild; false when the new
    /// plan no longer has the port or its guard.
    pub fn restore_err_disabled(&mut self, name: &str, remaining: Option<u32>) -> bool {
        let Some(i) = self
            .ports
            .iter()
            .position(|p| p.name == name && p.prot.bpdu_guard)
        else {
            return false;
        };
        // The new `bpdu-guard-recovery` wins: unset makes it manual.
        let remaining = self.ports[i]
            .prot
            .recovery
            .map(|r| remaining.map_or(r, |old| old.min(r)));
        self.bridge.restore_err_disabled(i, remaining);
        true
    }

    /// `clear spanning-tree err-disabled`: whether `name` was err-disabled.
    pub fn clear_err_disabled(&mut self, name: &str) -> (bool, Vec<Out>) {
        let Some(i) = self.ports.iter().position(|p| p.name == name) else {
            return (false, Vec::new());
        };
        let was = self.bridge.err_disabled(i).is_some();
        self.bridge.clear_err_disabled(i);
        (was, self.drain())
    }

    pub fn ports(&self) -> &[PortCfg] {
        &self.ports
    }

    /// The live view `show spanning-tree` serves.
    pub fn summary(&self) -> StpSummary {
        let b = &self.bridge;
        let root_cost = b.root_port.map_or(0, |i| {
            b.ports[i]
                .port_priority
                .root_path_cost
                .saturating_add(b.ports[i].path_cost)
        });
        StpSummary {
            enabled: true,
            mode: StpMode::Rstp,
            bridge_id: identity::show(&b.id),
            root_id: identity::show(&b.root_id),
            root_path_cost: root_cost,
            root_port: b.root_port.map(|i| self.ports[i].name.clone()),
            hello_time_secs: b.root_times.hello,
            max_age_secs: b.root_times.max_age,
            forward_delay_secs: b.root_times.forward_delay,
            ports: self
                .ports
                .iter()
                .enumerate()
                .map(|(i, cfg)| {
                    let p = &b.ports[i];
                    let (designated_bridge, designated_port) = if p.role == Role::Disabled {
                        (String::new(), String::new())
                    } else {
                        let dp = p.port_priority.designated_port;
                        (
                            identity::show(&p.port_priority.designated_bridge),
                            format!("{}.{}", dp.priority(), dp.number()),
                        )
                    };
                    StpPortInfo {
                        name: cfg.name.clone(),
                        role: match p.role {
                            Role::Root => StpRole::Root,
                            Role::Designated => StpRole::Designated,
                            Role::Alternate => StpRole::Alternate,
                            Role::Backup => StpRole::Backup,
                            Role::Disabled => StpRole::Disabled,
                        },
                        state: match b.port_state(i) {
                            PortState::Discarding => StpState::Discarding,
                            PortState::Learning => StpState::Learning,
                            PortState::Forwarding => StpState::Forwarding,
                        },
                        cost: p.path_cost,
                        priority: cfg.priority,
                        designated_bridge,
                        designated_port,
                        edge: p.oper_edge,
                        bpdu_guard: cfg.prot.bpdu_guard,
                        bpdu_filter: cfg.prot.bpdu_filter,
                        root_guard: cfg.prot.root_guard,
                        loop_guard: cfg.prot.loop_guard,
                        restricted_tcn: cfg.prot.restricted_tcn,
                        root_inconsistent: p.root_inconsistent,
                        loop_inconsistent: p.loop_inconsistent,
                        err_disabled: p.err_disabled,
                        err_recovery_secs: p.err_remaining,
                    }
                })
                .collect(),
        }
    }

    pub fn receive(&mut self, port: usize, bpdu: Bpdu) -> Vec<Out> {
        self.bridge.receive(port, bpdu);
        self.drain()
    }

    /// `portEnabled`, `operPointToPoint` and the path cost of one port.
    pub fn set_link(&mut self, port: usize, enabled: bool, p2p: bool, cost: u32) -> Vec<Out> {
        self.bridge.set_path_cost(port, cost);
        self.bridge.set_oper_point_to_point(port, p2p);
        self.bridge.set_port_enabled(port, enabled);
        self.drain()
    }

    /// One second elapsed.
    pub fn tick(&mut self) -> Vec<Out> {
        self.bridge.tick();
        self.drain()
    }

    fn drain(&mut self) -> Vec<Out> {
        let mut out = Vec::new();
        let mut states = Vec::new();
        for action in self.bridge.take_actions() {
            match action {
                Action::Transmit { port, bpdu } => out.push(Out::Tx { port, bpdu }),
                Action::SetPortState { port, state } => {
                    let p = &self.ports[port];
                    info!(port = %p.name, state = ?state, "port state changed");
                    states.extend(ports::assignments(p, state));
                }
                Action::FlushFdb { port } => {
                    out.push(Out::Flush(ports::flushes(&self.ports[port])));
                }
                Action::Log(Event::RoleChanged { port, to, .. }) => {
                    info!(port = %self.ports[port].name, role = ?to, "port role changed");
                }
                Action::Log(Event::ProtocolMigrated { port, rstp }) => {
                    let name = &self.ports[port].name;
                    if rstp {
                        info!(port = %name, "port migrated to RSTP");
                    } else {
                        info!(port = %name, "port migrated to STP");
                    }
                }
                Action::Log(Event::RootChanged { root, .. }) => {
                    info!(root = %identity::show(&root), "root bridge changed");
                }
                Action::ErrDisable { port } => {
                    let name = self.ports[port].name.clone();
                    warn!(port = %name, reason = %"bpdu-guard", "port err-disabled");
                    out.push(Out::ErrDisabled {
                        port: name,
                        disabled: true,
                    });
                }
                Action::ErrRecover { port } => {
                    let name = self.ports[port].name.clone();
                    info!(port = %name, "port err-disabled recovered");
                    out.push(Out::ErrDisabled {
                        port: name,
                        disabled: false,
                    });
                }
                Action::Log(Event::RootInconsistent { port, on }) => {
                    let name = &self.ports[port].name;
                    if on {
                        warn!(port = %name, "port root-inconsistent");
                    } else {
                        info!(port = %name, "port root-consistent");
                    }
                }
                Action::Log(Event::LoopInconsistent { port, on }) => {
                    let name = &self.ports[port].name;
                    if on {
                        warn!(port = %name, "port loop-inconsistent");
                    } else {
                        info!(port = %name, "port loop-consistent");
                    }
                }
                Action::Log(Event::NotQuiescent) => {
                    error!("spanning tree state machines did not reach quiescence");
                }
            }
        }
        if !states.is_empty() {
            out.push(Out::States(states));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timers::Timers;

    fn plan() -> Plan {
        let port = |n: &str| PortCfg {
            name: n.into(),
            domains: vec!["d1".into(), "d2".into()],
            priority: 128,
            cost: None,
            edge: EdgePort::Disabled,
            link_type: nos_proto::schema::LinkType::Auto,
            prot: crate::machines::Protections::default(),
        };
        Plan {
            priority: 32768,
            rstp_version: true,
            timers: Timers::default(),
            ports: vec![port("eth1"), port("eth2")],
        }
    }

    #[test]
    fn starts_blocking_then_a_lone_root_forwards_and_hellos() {
        let (mut e, init) = Engine::new(&plan(), [2, 0, 0, 0, 0, 1]).unwrap();
        let Some(Out::States(s)) = init.iter().find(|o| matches!(o, Out::States(_))) else {
            panic!("no initial states: {init:?}");
        };
        assert_eq!(s.len(), 4, "two ports times two domains");
        assert!(s
            .iter()
            .all(|a| a.state == nos_proto::StpPortState::Blocking));

        let out = e.set_link(0, true, true, 20_000);
        assert!(
            out.iter().any(|o| matches!(o, Out::Tx { port: 0, .. })),
            "an enabled designated port announces itself: {out:?}"
        );
        // Alone on the segment: the port reaches forwarding after the delays.
        let mut forwarding = false;
        for _ in 0..40 {
            for o in e.tick() {
                if let Out::States(s) = o {
                    forwarding |= s
                        .iter()
                        .any(|a| a.state == nos_proto::StpPortState::Forwarding);
                }
            }
        }
        assert!(forwarding);
        assert_eq!(e.bridge.port_state(0), PortState::Forwarding);
        assert_eq!(e.bridge.port_state(1), PortState::Discarding);

        let s = e.summary();
        assert!(s.enabled && s.root_port.is_none() && s.root_path_cost == 0);
        assert_eq!(s.root_id, s.bridge_id, "a lone bridge is its own root");
        assert_eq!(
            (s.ports[0].role, s.ports[0].state),
            (StpRole::Designated, StpState::Forwarding)
        );
        assert_eq!(s.ports[0].designated_bridge, s.bridge_id);
        assert_eq!(s.ports[0].designated_port, "128.1");
        assert_eq!(s.ports[1].role, StpRole::Disabled);
        assert_eq!(s.ports[1].designated_bridge, "");
    }

    #[test]
    fn mcheck_counts_matching_ports() {
        let (mut e, _) = Engine::new(&plan(), [2, 0, 0, 0, 0, 1]).unwrap();
        assert_eq!(e.mcheck(None).0, 2);
        assert_eq!(e.mcheck(Some("eth2")).0, 1);
        assert_eq!(e.mcheck(Some("nope")).0, 0);
    }

    #[test]
    fn forced_stp_never_transmits_rstp() {
        let mut p = plan();
        p.rstp_version = false;
        let (mut e, _) = Engine::new(&p, [2, 0, 0, 0, 0, 1]).unwrap();
        let mut out = e.set_link(0, true, true, 20_000);
        for _ in 0..5 {
            out.extend(e.tick());
        }
        let sent: Vec<_> = out
            .iter()
            .filter_map(|o| match o {
                Out::Tx { bpdu, .. } => Some(bpdu),
                _ => None,
            })
            .collect();
        assert_ne!(sent.len(), 0);
        assert!(
            sent.iter().all(|b| matches!(b, Bpdu::Config(_))),
            "{sent:?}"
        );
    }

    #[test]
    fn bpdu_guard_pushes_err_disable_and_clear_lifts_it() {
        let mut p = plan();
        p.ports[0].edge = EdgePort::Admin;
        p.ports[0].prot.bpdu_guard = true;
        let (mut e, _) = Engine::new(&p, [2, 0, 0, 0, 0, 1]).unwrap();
        e.set_link(0, true, true, 20_000);
        let bpdu = crate::machines::tests::rst(&e.bridge, 0, false);
        let out = e.receive(0, bpdu);
        assert!(out.contains(&Out::ErrDisabled {
            port: "eth1".into(),
            disabled: true
        }));
        assert_eq!(e.err_disabled(), [("eth1".to_string(), None)]);
        let s = e.summary();
        assert!(s.ports[0].err_disabled && s.ports[0].bpdu_guard);
        assert!(!e.clear_err_disabled("eth2").0);
        let (was, out) = e.clear_err_disabled("eth1");
        assert!(was);
        assert!(out.contains(&Out::ErrDisabled {
            port: "eth1".into(),
            disabled: false
        }));
        // A rebuilt bridge keeps the port down while the guard is configured.
        let (mut e2, _) = Engine::new(&p, [2, 0, 0, 0, 0, 1]).unwrap();
        assert!(e2.restore_err_disabled("eth1", Some(5)));
        assert_eq!(
            e2.err_disabled(),
            [("eth1".to_string(), None)],
            "recovery is unset in the new plan, so the port waits for clear"
        );
        assert!(!e2.restore_err_disabled("eth2", None), "no guard on eth2");
        p.ports[0].prot.recovery = Some(60);
        let (mut e3, _) = Engine::new(&p, [2, 0, 0, 0, 0, 1]).unwrap();
        assert!(e3.restore_err_disabled("eth1", Some(5)));
        assert_eq!(e3.err_disabled(), [("eth1".to_string(), Some(5))]);
        assert!(e3.restore_err_disabled("eth1", None));
        assert_eq!(e3.err_disabled(), [("eth1".to_string(), Some(60))]);
    }

    #[test]
    fn rejects_an_out_of_range_priority() {
        let mut p = plan();
        p.priority = 100;
        assert!(Engine::new(&p, [2; 6]).is_err());
    }
}
