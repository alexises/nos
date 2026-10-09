//! Topology Change machine, 13.37 (Figure 13-17).
//!
//! `fdbFlush` is performed synchronously by the host: the machine emits
//! `FlushFdb` and clears the variable at once (`ponytail`: no async flush
//! handshake with PST; a host that flushes slowly must queue it itself).

use super::{new_tc_while, set_tc_prop_tree, Role};
use crate::actions::Action;
use crate::bridge::Bridge;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Inactive,
    Learning,
    Detected,
    Active,
    NotifiedTcn,
    NotifiedTc,
    Propagating,
    Acknowledged,
}

fn flush(b: &mut Bridge, i: usize) {
    b.ports[i].fdb_flush = false;
    b.actions.push(Action::FlushFdb { port: i });
}

pub fn enter(b: &mut Bridge, i: usize, s: State) {
    b.ports[i].tcm = s;
    match s {
        State::Inactive => {
            flush(b, i);
            let p = &mut b.ports[i];
            p.tc_while = 0;
            p.tc_ack = false;
        }
        State::Learning => {
            let p = &mut b.ports[i];
            p.rcvd_tc = false;
            p.rcvd_tcn = false;
            p.rcvd_tc_ack = false;
            p.tc_prop = false;
        }
        State::Detected => {
            new_tc_while(b, i);
            set_tc_prop_tree(b, i);
            b.ports[i].new_info = true;
        }
        State::Active => {}
        State::NotifiedTcn => new_tc_while(b, i),
        State::NotifiedTc => {
            let p = &mut b.ports[i];
            p.rcvd_tcn = false;
            p.rcvd_tc = false;
            if p.role == Role::Designated {
                p.tc_ack = true;
            }
            set_tc_prop_tree(b, i);
        }
        State::Propagating => {
            new_tc_while(b, i);
            flush(b, i);
            b.ports[i].tc_prop = false;
        }
        State::Acknowledged => {
            let p = &mut b.ports[i];
            p.tc_while = 0;
            p.rcvd_tc_ack = false;
        }
    }
}

pub fn step(b: &mut Bridge, i: usize) -> bool {
    let p = &b.ports[i];
    let rd = matches!(p.role, Role::Root | Role::Designated);
    let any = p.rcvd_tc || p.rcvd_tcn || p.rcvd_tc_ack || p.tc_prop;
    let next = match p.tcm {
        State::Inactive if p.learn && !p.fdb_flush => State::Learning,
        State::Learning if !rd && !p.learn && !p.learning && !any => State::Inactive,
        State::Learning if any => State::Learning,
        State::Learning if rd && p.forward && !p.oper_edge => State::Detected,
        State::Detected | State::NotifiedTc | State::Propagating | State::Acknowledged => {
            State::Active
        }
        State::NotifiedTcn => State::NotifiedTc,
        State::Active if !rd || p.oper_edge => State::Learning,
        State::Active if p.rcvd_tcn => State::NotifiedTcn,
        State::Active if p.rcvd_tc => State::NotifiedTc,
        State::Active if p.tc_prop && !p.oper_edge => State::Propagating,
        State::Active if p.rcvd_tc_ack => State::Acknowledged,
        _ => return false,
    };
    enter(b, i, next);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machines::tests::bridge;

    fn at(b: &mut Bridge, s: State) {
        b.ports[0].tcm = s;
    }

    #[test]
    fn inactive_to_learning_when_learn() {
        let mut b = bridge(1);
        assert!(!step(&mut b, 0));
        b.ports[0].learn = true;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].tcm, State::Learning);
    }

    #[test]
    fn learning_to_inactive_and_self_loop_and_detected() {
        let mut b = bridge(1);
        at(&mut b, State::Learning);
        b.ports[0].role = Role::Alternate;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].tcm, State::Inactive);
        at(&mut b, State::Learning);
        b.ports[0].rcvd_tc = true;
        assert!(step(&mut b, 0));
        assert!(!b.ports[0].rcvd_tc, "LEARNING -> LEARNING clears the flags");
        b.ports[0].role = Role::Designated;
        b.ports[0].forward = true;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].tcm, State::Detected);
    }

    #[test]
    fn detected_starts_tc_and_propagates() {
        let mut b = bridge(1);
        let p = &mut b.ports[0];
        p.send_rstp = true;
        p.role = Role::Designated;
        enter(&mut b, 0, State::Detected);
        assert_eq!(b.ports[0].tc_while, b.root_times.hello + 1);
        assert!(b.ports[0].new_info && b.ports[1].tc_prop && !b.ports[0].tc_prop);
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].tcm, State::Active);
    }

    #[test]
    fn active_exits() {
        let cases: [Case; 5] = [
            ("tcn", |p| p.rcvd_tcn = true, State::NotifiedTcn),
            ("tc", |p| p.rcvd_tc = true, State::NotifiedTc),
            ("prop", |p| p.tc_prop = true, State::Propagating),
            ("ack", |p| p.rcvd_tc_ack = true, State::Acknowledged),
            ("role", |p| p.role = Role::Alternate, State::Learning),
        ];
        for (name, set, want) in cases {
            let mut b = bridge(1);
            at(&mut b, State::Active);
            b.ports[0].role = Role::Designated;
            set(&mut b.ports[0]);
            assert!(step(&mut b, 0), "{name}");
            assert_eq!(b.ports[0].tcm, want, "{name}");
        }
    }

    type Port0 = crate::machines::Port;
    type Case = (&'static str, fn(&mut Port0), State);

    #[test]
    fn notified_tcn_chains_to_notified_tc_then_active() {
        let mut b = bridge(1);
        let p = &mut b.ports[0];
        p.role = Role::Designated;
        p.rcvd_tcn = true;
        p.tcm = State::NotifiedTcn;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].tcm, State::NotifiedTc);
        assert!(b.ports[0].tc_ack, "designated ports acknowledge TCNs");
        assert!(b.ports[1].tc_prop);
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].tcm, State::Active);
    }

    #[test]
    fn propagating_flushes_and_acknowledged_stops_tc() {
        let mut b = bridge(1);
        b.take_actions();
        enter(&mut b, 0, State::Propagating);
        assert!(b.take_actions().contains(&Action::FlushFdb { port: 0 }));
        b.ports[0].tc_while = 5;
        enter(&mut b, 0, State::Acknowledged);
        assert_eq!(b.ports[0].tc_while, 0);
    }
}
