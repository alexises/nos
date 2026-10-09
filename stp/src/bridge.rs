//! Bridge-wide state and the "run every machine until quiescent" driver.
//!
//! Time only enters through [`Bridge::tick`] (once per second, the granularity
//! of every 13.22 timer); the host feeds `portEnabled`, `operPointToPoint`,
//! `operEdge` (admin) and received BPDUs, then drains [`Bridge::take_actions`].

use crate::actions::{Action, Event};
use crate::bpdu::Bpdu;
use crate::machines::{bdm, pim, ppm, prs, prt, prx, pst, ptx, tcm, Port, Role, Times};
use crate::timers::Timers;
use crate::vector::{BridgeId, PortId, PriorityVector};

/// Hard cap on full machine passes in one `run` (non-convergence = a bug).
const MAX_PASSES: usize = 1000;

#[derive(Debug, Clone, Copy)]
pub struct PortParams {
    pub id: PortId,
    pub path_cost: u32,
    pub admin_edge: bool,
    pub auto_edge: bool,
}

pub struct Bridge {
    pub id: BridgeId,
    pub timers: Timers,
    /// `BridgeTimes`: this bridge's own timers, message age 0.
    pub bridge_times: Times,
    /// `rootTimes`: the root's timers as learnt (== `bridge_times` at the root).
    pub root_times: Times,
    /// `rstpVersion`: false forces STP compatibility (`force-version`, #319).
    pub rstp_version: bool,
    pub ports: Vec<Port>,
    /// Index of the Root Port, `None` when this bridge is the root.
    pub root_port: Option<usize>,
    /// Identifier of the root bridge as currently computed (this bridge when it is the root).
    pub root_id: BridgeId,
    pub prs: prs::State,
    pub(crate) actions: Vec<Action>,
}

impl Bridge {
    /// BEGIN: every machine in its initial state, all ports disabled.
    pub fn new(id: BridgeId, timers: Timers, ports: &[PortParams]) -> Self {
        let times = Times {
            message_age: 0,
            max_age: timers.max_age,
            hello: timers.hello,
            forward_delay: timers.forward_delay,
        };
        let pv = PriorityVector {
            root: id,
            root_path_cost: 0,
            designated_bridge: id,
            designated_port: PortId::from_u16(0),
            bridge_port: PortId::from_u16(0),
        };
        let mut b = Bridge {
            id,
            timers,
            bridge_times: times,
            root_times: times,
            rstp_version: true,
            ports: ports
                .iter()
                .map(|p| Port::new(p.id, p.path_cost, p.admin_edge, p.auto_edge, pv, times))
                .collect(),
            root_port: None,
            root_id: id,
            prs: prs::State::InitBridge,
            actions: Vec::new(),
        };
        for i in 0..b.ports.len() {
            prx::enter(&mut b, i, prx::State::Discard);
            pim::enter(&mut b, i, pim::State::Disabled);
            prt::enter(&mut b, i, prt::State::InitPort);
            pst::enter(&mut b, i, pst::State::Discarding);
            tcm::enter(&mut b, i, tcm::State::Inactive);
            ppm::enter(&mut b, i, ppm::State::CheckingRstp);
            ptx::enter(&mut b, i, ptx::State::TransmitInit);
            let s = if b.ports[i].admin_edge {
                bdm::State::Edge
            } else {
                bdm::State::NotEdge
            };
            bdm::enter(&mut b, i, s);
        }
        b.run();
        b
    }

    pub fn take_actions(&mut self) -> Vec<Action> {
        std::mem::take(&mut self.actions)
    }

    /// One second elapsed.
    pub fn tick(&mut self) {
        self.ports.iter_mut().for_each(Port::tick);
        self.run();
    }

    pub fn receive(&mut self, port: usize, bpdu: Bpdu) {
        let p = &mut self.ports[port];
        p.rcvd = Some(bpdu);
        p.rcvd_bpdu = true;
        self.run();
    }

    pub fn set_port_enabled(&mut self, port: usize, up: bool) {
        self.ports[port].port_enabled = up;
        self.run();
    }

    pub fn set_oper_point_to_point(&mut self, port: usize, p2p: bool) {
        self.ports[port].oper_point_to_point = p2p;
        self.run();
    }

    pub fn set_path_cost(&mut self, port: usize, cost: u32) {
        self.ports[port].path_cost = cost;
        self.ports[port].reselect = true;
        self.run();
    }

    /// Change the bridge identifier (priority) and re-run role selection.
    pub fn set_bridge_id(&mut self, id: BridgeId) {
        self.id = id;
        for p in &mut self.ports {
            p.reselect = true;
            p.selected = false;
        }
        self.run();
    }

    /// `forceVersion` (13.7): `false` is 802.1D, no RSTP BPDU is ever sent.
    /// Restarts the PPM machines, so call it before the ports come up.
    pub fn set_rstp_version(&mut self, rstp: bool) {
        self.rstp_version = rstp;
        for i in 0..self.ports.len() {
            ppm::enter(self, i, ppm::State::CheckingRstp);
        }
        self.run();
    }

    /// Management `mcheck` (13.7): probe `port` for RSTP again. A peer that
    /// still sends STP BPDUs moves it straight back after Migrate Time.
    pub fn mcheck(&mut self, port: usize) {
        self.ports[port].mcheck = true;
        self.run();
    }

    pub fn role(&self, port: usize) -> Role {
        self.ports[port].role
    }

    pub fn port_state(&self, port: usize) -> crate::actions::PortState {
        use crate::actions::PortState;
        let p = &self.ports[port];
        if p.forwarding {
            PortState::Forwarding
        } else if p.learning {
            PortState::Learning
        } else {
            PortState::Discarding
        }
    }

    /// Run every machine until a full pass changes nothing.
    pub fn run(&mut self) {
        for _ in 0..MAX_PASSES {
            let mut changed = prs::step(self);
            for i in 0..self.ports.len() {
                changed |= prx::step(self, i);
                changed |= ppm::step(self, i);
                changed |= bdm::step(self, i);
                changed |= pim::step(self, i);
                changed |= prt::step(self, i);
                changed |= pst::step(self, i);
                changed |= tcm::step(self, i);
                changed |= ptx::step(self, i);
            }
            if !changed {
                return;
            }
        }
        debug_assert!(false, "state machines did not reach quiescence");
        self.actions.push(Action::Log(Event::NotQuiescent));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpdu::{raw_secs, Flags, Params};
    use crate::machines::tests::{bid, bridge};

    #[test]
    fn legacy_config_bpdu_puts_only_that_port_in_stp_mode() {
        let mut b = bridge(5);
        b.set_port_enabled(0, true);
        b.set_port_enabled(1, true);
        for _ in 0..3 {
            b.tick(); // Migrate Time: CHECKING_RSTP -> SENSING
        }
        let config = Bpdu::Config(Params {
            flags: Flags::default(),
            root: bid(1),
            root_path_cost: 0,
            bridge: bid(1),
            port: PortId::new(128, 1).unwrap(),
            message_age: 0,
            max_age: raw_secs(20),
            hello_time: raw_secs(2),
            forward_delay: raw_secs(15),
        });
        b.receive(0, config);
        assert_eq!(b.role(0), Role::Root);
        assert!(!b.ports[0].send_rstp, "port 0 talks STP to a legacy peer");
        assert!(b.ports[1].send_rstp, "port 1 is unaffected");
    }

    #[test]
    fn nothing_is_sent_on_a_down_port() {
        let mut b = bridge(5);
        b.tick();
        assert!(!b
            .take_actions()
            .iter()
            .any(|a| matches!(a, Action::Transmit { .. })));
    }
}
