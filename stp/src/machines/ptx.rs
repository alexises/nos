//! Port Transmit machine, 13.33 (Figure 13-15).

use super::{hello, transmit, Role, Tx};
use crate::bridge::Bridge;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    TransmitInit,
    TransmitPeriodic,
    Idle,
    TransmitConfig,
    TransmitTcn,
    TransmitRstp,
}

pub fn enter(b: &mut Bridge, i: usize, s: State) {
    let h = hello(b);
    b.ports[i].ptx = s;
    match s {
        State::TransmitInit => {
            let p = &mut b.ports[i];
            p.new_info = true;
            p.tx_count = 0;
        }
        State::TransmitPeriodic => {
            let p = &mut b.ports[i];
            p.new_info = p.new_info
                || p.role == Role::Designated
                || (p.role == Role::Root && p.tc_while != 0);
        }
        State::Idle => b.ports[i].hello_when = h,
        State::TransmitConfig | State::TransmitTcn | State::TransmitRstp => {
            let kind = match s {
                State::TransmitConfig => Tx::Config,
                State::TransmitTcn => Tx::Tcn,
                _ => Tx::Rst,
            };
            b.ports[i].new_info = false;
            transmit(b, i, kind);
            let p = &mut b.ports[i];
            p.tx_count += 1;
            p.tc_ack = false;
        }
    }
}

pub fn step(b: &mut Bridge, i: usize) -> bool {
    let hold = b.timers.tx_hold_count;
    let p = &b.ports[i];
    let ok = p.selected && !p.updt_info && p.port_enabled; // ponytail: the host drops frames on a down port anyway; this keeps the action stream clean
    let can_tx = p.new_info && p.tx_count < hold && p.hello_when != 0 && ok;
    let next = match p.ptx {
        State::TransmitInit | State::TransmitPeriodic => State::Idle,
        State::TransmitConfig | State::TransmitTcn | State::TransmitRstp => State::Idle,
        State::Idle if p.hello_when == 0 && ok => State::TransmitPeriodic,
        State::Idle if p.send_rstp && can_tx => State::TransmitRstp,
        State::Idle if !p.send_rstp && can_tx && p.role == Role::Root => State::TransmitTcn,
        State::Idle if !p.send_rstp && can_tx && p.role == Role::Designated => {
            State::TransmitConfig
        }
        State::Idle => return false,
    };
    enter(b, i, next);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::Action;
    use crate::bpdu::Bpdu;
    use crate::machines::tests::bridge;

    fn ready(b: &mut Bridge) {
        let p = &mut b.ports[0];
        p.port_enabled = true;
        p.selected = true;
        p.updt_info = false;
        p.role = Role::Designated;
        p.send_rstp = true;
        p.new_info = false;
        p.hello_when = 2;
        p.ptx = State::Idle;
        b.take_actions();
    }

    #[test]
    fn init_and_periodic_and_tx_return_to_idle() {
        let mut b = bridge(1);
        for s in [
            State::TransmitInit,
            State::TransmitPeriodic,
            State::TransmitRstp,
        ] {
            b.ports[0].ptx = s;
            assert!(step(&mut b, 0));
            assert_eq!(b.ports[0].ptx, State::Idle);
        }
    }

    #[test]
    fn idle_to_transmit_rstp_only_with_new_info() {
        let mut b = bridge(1);
        ready(&mut b);
        assert!(!step(&mut b, 0));
        b.ports[0].new_info = true;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].ptx, State::TransmitRstp);
        assert!(matches!(
            b.take_actions()[..],
            [
                Action::Transmit {
                    bpdu: Bpdu::Rst(_),
                    ..
                },
                ..
            ]
        ));
        assert!(!b.ports[0].new_info);
        assert_eq!(b.ports[0].tx_count, 1);
    }

    #[test]
    fn idle_to_periodic_when_hello_expires() {
        let mut b = bridge(1);
        ready(&mut b);
        b.ports[0].hello_when = 0;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].ptx, State::TransmitPeriodic);
        assert!(step(&mut b, 0));
        assert!(b.ports[0].new_info, "designated ports always refresh");
    }

    #[test]
    fn tx_hold_count_limits_bursts() {
        let mut b = bridge(1);
        ready(&mut b);
        b.ports[0].new_info = true;
        b.ports[0].tx_count = b.timers.tx_hold_count;
        assert!(!step(&mut b, 0));
    }

    #[test]
    fn tick_decrements_tx_count_by_one() {
        let mut b = bridge(1);
        ready(&mut b);
        let hold = b.timers.tx_hold_count;
        b.ports[0].tx_count = hold;
        b.ports[0].tick();
        assert_eq!(b.ports[0].tx_count, hold - 1);
        b.ports[0].tx_count = 0;
        b.ports[0].tick();
        assert_eq!(b.ports[0].tx_count, 0);
    }

    #[test]
    fn stp_peer_gets_config_from_designated_and_tcn_from_root() {
        let mut b = bridge(1);
        ready(&mut b);
        b.ports[0].send_rstp = false;
        b.ports[0].new_info = true;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].ptx, State::TransmitConfig);
        ready(&mut b);
        b.ports[0].send_rstp = false;
        b.ports[0].role = Role::Root;
        b.ports[0].new_info = true;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].ptx, State::TransmitTcn);
        assert!(matches!(
            b.take_actions()[..],
            [Action::Transmit {
                bpdu: Bpdu::Tcn,
                ..
            }]
        ));
    }
}
