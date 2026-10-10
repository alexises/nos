//! The core hosted on real ports: turns the core's [`Action`]s into the three
//! things the daemon does (send a BPDU, push kernel states, flush an FDB) and
//! into the log lines the e2e phase anchors on. No I/O, no clock.
//!
//! In mode `mstp` the CIST bridge is accompanied by one bridge per MSTI
//! ([`crate::mst`]); the kernel state of a domain's port is the state of the
//! tree its `stp-instance` names, pushed whenever it differs from the last push.

use std::collections::HashMap;

use nos_proto::{
    StpInstance, StpInstancePort, StpMode, StpMst, StpPortAssignment, StpPortInfo, StpRole,
    StpState, StpSummary,
};
use tracing::{error, info, warn};

use crate::actions::{Action, Event, PortState};
use crate::bpdu::{Bpdu, MstBpdu, Rx};
use crate::bridge::{Bridge, PortParams};
use crate::identity;
use crate::machines::{build, Role, Tx};
use crate::mst::{self, digest, vidmap, Edge, Mst, PortMst};
use crate::ports::{self, Plan, PortCfg};
use crate::vector::{IdError, PortId};
use nos_proto::schema::EdgePort;

/// What the daemon must do after a call into the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    /// Encode and send on port `port` (index into the plan).
    Tx { port: usize, bpdu: Bpdu },
    /// Like `Tx`, a version 3 BPDU (CIST plus the MSTI messages).
    TxMst { port: usize, bpdu: Box<MstBpdu> },
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
    mst: Option<Mst>,
    /// The last state pushed per `(tree, port)`.
    pushed: HashMap<(u16, usize), PortState>,
}

fn stp_role(r: Role) -> StpRole {
    match r {
        Role::Root => StpRole::Root,
        Role::Designated => StpRole::Designated,
        Role::Alternate => StpRole::Alternate,
        Role::Backup => StpRole::Backup,
        Role::Disabled => StpRole::Disabled,
    }
}

fn stp_state(s: PortState) -> StpState {
    match s {
        PortState::Discarding => StpState::Discarding,
        PortState::Learning => StpState::Learning,
        PortState::Forwarding => StpState::Forwarding,
    }
}

/// The MSTI bridges follow the `Edge` of each port: a boundary port runs none.
fn sync_mst(cist: &Bridge, mst: &mut Mst) {
    for i in 0..cist.ports.len() {
        if !cist.ports[i].port_enabled {
            mst.edge[i] = Edge::Unknown;
        }
        let want = cist.ports[i].port_enabled && !matches!(mst.edge[i], Edge::Boundary(_));
        for m in &mut mst.instances {
            if m.bridge.ports[i].link_up != want {
                m.bridge.set_port_enabled(i, want);
            }
        }
    }
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
        let mst = match &plan.mst {
            Some(m) => {
                let cfgs: Vec<Vec<PortMst>> = plan.ports.iter().map(|p| p.mst.clone()).collect();
                let mst = Mst::new(m, mac, plan.timers, &params, cfgs)?;
                info!(
                    name = %m.name,
                    revision = m.revision,
                    digest = %digest::hex(&m.digest),
                    instances = m.instances.len(),
                    "mst configuration"
                );
                Some(mst)
            }
            None => None,
        };
        let mut e = Engine {
            bridge,
            ports: plan.ports.clone(),
            mst,
            pushed: HashMap::new(),
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

    fn mst_plan(&self) -> Option<&mst::MstPlan> {
        self.mst.as_ref().map(|m| &m.plan)
    }

    /// The state the kernel gets for `tree` on `port`: a boundary port's
    /// MSTIs follow the CIST.
    fn effective(&self, tree: u16, port: usize) -> PortState {
        match self.mst.as_ref().filter(|_| tree != 0) {
            Some(m) if !matches!(m.edge[port], Edge::Boundary(_)) => m
                .instances
                .iter()
                .find(|i| i.id == tree)
                .map_or(PortState::Discarding, |i| i.bridge.port_state(port)),
            _ => self.bridge.port_state(port),
        }
    }

    /// One tree of the summary: the CIST (`tree` 0) or an MSTI.
    fn instance_view(&self, tree: u16, plan: &mst::MstPlan) -> StpInstance {
        let b = match tree {
            0 => &self.bridge,
            t => {
                &self
                    .mst
                    .as_ref()
                    .and_then(|m| m.instances.iter().find(|i| i.id == t))
                    .expect("a planned instance")
                    .bridge
            }
        };
        let root_cost = b.root_port.map_or(0, |i| {
            b.ports[i]
                .port_priority
                .root_path_cost
                .saturating_add(b.ports[i].path_cost)
        });
        let mut domains: Vec<String> = plan
            .domains
            .iter()
            .filter(|d| d.2 == tree)
            .map(|d| d.0.clone())
            .collect();
        domains.sort();
        StpInstance {
            id: tree,
            vlans: vidmap::ranges(&plan.domains, tree),
            domains,
            bridge_id: identity::show(&b.id),
            root_id: identity::show(&b.root_id),
            root_path_cost: root_cost,
            root_port: b.root_port.map(|i| self.ports[i].name.clone()),
            ports: self
                .ports
                .iter()
                .enumerate()
                .map(|(i, cfg)| {
                    let boundary = self
                        .mst
                        .as_ref()
                        .is_some_and(|m| matches!(m.edge[i], Edge::Boundary(_)));
                    // A boundary port has no MSTI information: show the CIST's.
                    let src = if boundary { &self.bridge } else { b };
                    let p = &src.ports[i];
                    let (designated_bridge, designated_port) = if p.role == Role::Disabled {
                        (String::new(), String::new())
                    } else {
                        let dp = p.port_priority.designated_port;
                        (
                            identity::show(&p.port_priority.designated_bridge),
                            format!("{}.{}", dp.priority(), dp.number()),
                        )
                    };
                    StpInstancePort {
                        name: cfg.name.clone(),
                        role: stp_role(p.role),
                        state: stp_state(self.effective(tree, i)),
                        boundary,
                        cost: b.ports[i].path_cost,
                        priority: b.ports[i].port_id.priority(),
                        designated_bridge,
                        designated_port,
                    }
                })
                .collect(),
        }
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
            mode: if self.mst.is_some() {
                StpMode::Mstp
            } else {
                StpMode::Rstp
            },
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
                        role: stp_role(p.role),
                        state: stp_state(b.port_state(i)),
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
            mst: self.mst.as_ref().map(|m| {
                let ids = std::iter::once(0).chain(m.instances.iter().map(|i| i.id));
                StpMst {
                    region_name: m.plan.name.clone(),
                    revision: m.plan.revision,
                    digest: digest::hex(&m.plan.digest),
                    max_hops: m.plan.max_hops,
                    instances: ids.map(|t| self.instance_view(t, &m.plan)).collect(),
                }
            }),
        }
    }

    pub fn receive(&mut self, port: usize, bpdu: Bpdu) -> Vec<Out> {
        self.receive_rx(port, Rx::Plain(bpdu))
    }

    /// A BPDU as decoded from the wire. A version 3 BPDU from a bridge in the
    /// same region also feeds the MSTIs; anything else makes the port a
    /// boundary port.
    pub fn receive_rx(&mut self, port: usize, rx: Rx) -> Vec<Out> {
        let p = &self.bridge.ports[port];
        let ignored = p.prot.bpdu_filter || p.err_disabled;
        let (cist, msti) = match rx {
            Rx::Plain(b) => {
                if !ignored {
                    self.set_edge(port, Edge::Boundary("plain-bpdu"));
                }
                (b, None)
            }
            Rx::Mst(m) => {
                let flat = Bpdu::Rst(mst::flat(&m));
                match self.mst.as_ref().map(|s| mst::mismatch(&s.id, &m.config)) {
                    Some(why) if !ignored => {
                        self.set_edge(port, why.map_or(Edge::Internal, Edge::Boundary));
                        (flat, why.is_none().then_some(m))
                    }
                    _ => (flat, None),
                }
            }
        };
        self.bridge.receive(port, cist);
        if let (Some(m), Some(mst)) = (msti, self.mst.as_mut()) {
            if !self.bridge.ports[port].err_disabled {
                sync_mst(&self.bridge, mst);
                mst.receive(port, &m);
            }
        }
        self.drain()
    }

    fn set_edge(&mut self, port: usize, edge: Edge) {
        let Some(m) = self.mst.as_mut() else { return };
        if m.edge[port] == edge {
            return;
        }
        m.edge[port] = edge;
        let name = &self.ports[port].name;
        match edge {
            Edge::Boundary(reason) => info!(port = %name, reason = %reason, "mst boundary port"),
            Edge::Internal => {
                info!(port = %name, digest = %digest::hex(&m.id.digest), "mst region match");
            }
            Edge::Unknown => {}
        }
    }

    /// `portEnabled`, `operPointToPoint` and the path cost of one port.
    pub fn set_link(&mut self, port: usize, enabled: bool, p2p: bool, cost: u32) -> Vec<Out> {
        self.bridge.set_path_cost(port, cost);
        self.bridge.set_oper_point_to_point(port, p2p);
        self.bridge.set_port_enabled(port, enabled);
        if let Some(m) = self.mst.as_mut() {
            for inst in &mut m.instances {
                let own = m.port_cfg[port].iter().find(|c| c.id == inst.id);
                inst.bridge
                    .set_path_cost(port, own.and_then(|c| c.cost).unwrap_or(cost));
                inst.bridge.set_oper_point_to_point(port, p2p);
            }
        }
        self.drain()
    }

    /// One second elapsed.
    pub fn tick(&mut self) -> Vec<Out> {
        self.bridge.tick();
        if let Some(m) = self.mst.as_mut() {
            m.instances.iter_mut().for_each(|i| i.bridge.tick());
        }
        self.drain()
    }

    fn drain(&mut self) -> Vec<Out> {
        if let Some(m) = self.mst.as_mut() {
            sync_mst(&self.bridge, m);
        }
        let mut out = Vec::new();
        // CIST Transmit of each port, held back while an MST BPDU can carry it.
        let mut cist_tx = HashMap::new();
        for action in self.bridge.take_actions() {
            match action {
                Action::Transmit { port, bpdu } => match bpdu {
                    Bpdu::Rst(p) if self.mst.is_some() => {
                        cist_tx.insert(port, p);
                    }
                    bpdu => out.push(Out::Tx { port, bpdu }),
                },
                Action::SetPortState { port, state } => {
                    info!(port = %self.ports[port].name, state = ?state, "port state changed");
                }
                Action::FlushFdb { port } => {
                    let f = ports::flushes(&self.ports[port], self.mst_plan(), 0);
                    out.push(Out::Flush(f));
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
        self.drain_mst(&mut out, cist_tx);
        let states = self.diff_states();
        if !states.is_empty() {
            out.push(Out::States(states));
        }
        out
    }

    /// The MSTI bridges' actions: flushes, logs, and the triggers for one
    /// MST BPDU per port (ponytail: the MSTIs' own `txHoldCount` limits are
    /// not summed, a burst can exceed the CIST's by the number of MSTIs).
    fn drain_mst(&mut self, out: &mut Vec<Out>, mut cist_tx: HashMap<usize, crate::bpdu::Params>) {
        let Some(m) = self.mst.as_mut() else { return };
        let mut triggers = Vec::new();
        for inst in &mut m.instances {
            for action in inst.bridge.take_actions() {
                match action {
                    Action::Transmit { port, .. } => triggers.push(port),
                    Action::FlushFdb { port } => {
                        let f = ports::flushes(&self.ports[port], Some(&m.plan), inst.id);
                        if !f.is_empty() {
                            out.push(Out::Flush(f));
                        }
                    }
                    Action::Log(Event::RoleChanged { port, to, .. }) => {
                        info!(port = %self.ports[port].name, msti = inst.id, role = ?to, "msti port role changed");
                    }
                    Action::Log(Event::RootChanged { root, .. }) => {
                        info!(msti = inst.id, root = %identity::show(&root), "msti root bridge changed");
                    }
                    Action::Log(Event::NotQuiescent) => {
                        error!(
                            msti = inst.id,
                            "spanning tree state machines did not reach quiescence"
                        );
                    }
                    _ => {}
                }
            }
        }
        for port in triggers {
            let p = &self.bridge.ports[port];
            if p.send_rstp && p.port_enabled && !p.prot.bpdu_filter {
                if let Bpdu::Rst(params) = build(&self.bridge, port, Tx::Rst) {
                    cist_tx.entry(port).or_insert(params);
                }
            }
        }
        let mut sends: Vec<_> = cist_tx.into_iter().collect();
        sends.sort_by_key(|&(port, _)| port);
        for (port, params) in sends {
            let bpdu = Box::new(m.tx(port, &params, self.bridge.id));
            out.push(Out::TxMst { port, bpdu });
        }
    }

    fn trees(&self) -> Vec<u16> {
        std::iter::once(0)
            .chain(
                self.mst
                    .iter()
                    .flat_map(|m| m.instances.iter().map(|i| i.id)),
            )
            .collect()
    }

    /// Every `(port, domain)` state as it is now, for the periodic re-push:
    /// a push that `nos-interfaced` overwrote with a stale resync is healed
    /// by the next one (it only writes states that differ).
    pub fn all_states(&self) -> Vec<Out> {
        let states: Vec<_> = self
            .trees()
            .into_iter()
            .flat_map(|t| {
                (0..self.ports.len()).flat_map(move |i| {
                    ports::assignments(&self.ports[i], self.mst_plan(), t, self.effective(t, i))
                })
            })
            .collect();
        if states.is_empty() {
            Vec::new()
        } else {
            vec![Out::States(states)]
        }
    }

    /// Kernel states that changed since the last push, for every tree.
    fn diff_states(&mut self) -> Vec<StpPortAssignment> {
        let trees = self.trees();
        let mut states = Vec::new();
        for tree in trees {
            for i in 0..self.ports.len() {
                let now = self.effective(tree, i);
                if self.pushed.insert((tree, i), now) == Some(now) {
                    continue;
                }
                let a = ports::assignments(&self.ports[i], self.mst_plan(), tree, now);
                if tree != 0 {
                    let domains: Vec<_> = a.iter().map(|a| a.domain.as_str()).collect();
                    info!(
                        port = %self.ports[i].name,
                        msti = tree,
                        state = ?now,
                        domains = %domains.join(","),
                        "msti port state changed"
                    );
                }
                states.extend(a);
            }
        }
        states
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
            mst: Vec::new(),
        };
        Plan {
            priority: 32768,
            rstp_version: true,
            timers: Timers::default(),
            ports: vec![port("eth1"), port("eth2")],
            mst: None,
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
    fn all_states_repeats_every_domain_state_for_the_periodic_push() {
        let (e, _) = Engine::new(&plan(), [2, 0, 0, 0, 0, 1]).unwrap();
        let [Out::States(s)] = &e.all_states()[..] else {
            panic!("one States output");
        };
        assert_eq!(s.len(), 4, "two ports times two domains");
        assert!(s
            .iter()
            .all(|a| a.state == nos_proto::StpPortState::Blocking));
    }

    #[test]
    fn rejects_an_out_of_range_priority() {
        let mut p = plan();
        p.priority = 100;
        assert!(Engine::new(&p, [2; 6]).is_err());
    }
}
