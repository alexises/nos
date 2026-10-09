//! Port Receive machine, 13.28 (Figure 13-12).

use crate::bpdu::Bpdu;
use crate::bridge::Bridge;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Discard,
    Receive,
}

pub fn enter(b: &mut Bridge, i: usize, s: State) {
    let migrate = b.timers.migrate_time;
    let p = &mut b.ports[i];
    p.prx = s;
    match s {
        State::Discard => {
            p.rcvd_bpdu = false;
            p.rcvd_rstp = false;
            p.rcvd_stp = false;
            p.rcvd = None;
            p.edge_delay_while = migrate;
        }
        State::Receive => {
            let bpdu = p.rcvd.take();
            // updtBPDUVersion (13.30): TCN and version 0 Config mean STP, RST means RSTP.
            match bpdu {
                Some(Bpdu::Tcn) => {
                    p.rcvd_stp = true;
                    p.rcvd_tcn = true;
                }
                Some(Bpdu::Config(_)) => p.rcvd_stp = true,
                Some(Bpdu::Rst(_)) => p.rcvd_rstp = true,
                None => {}
            }
            // 9.3.4: a BPDU already past its max age is discarded.
            let aged = match bpdu {
                Some(Bpdu::Config(pr) | Bpdu::Rst(pr)) => pr.message_age >= pr.max_age,
                _ => false,
            };
            if bpdu.is_some() {
                p.oper_edge = false;
            }
            p.rcvd_bpdu = false;
            p.rcvd_msg = matches!(bpdu, Some(Bpdu::Config(_) | Bpdu::Rst(_))) && !aged;
            p.msg = if p.rcvd_msg { bpdu } else { None };
            p.edge_delay_while = migrate;
        }
    }
}

pub fn step(b: &mut Bridge, i: usize) -> bool {
    let migrate = b.timers.migrate_time;
    let p = &b.ports[i];
    let next = match p.prx {
        State::Discard if (p.rcvd_bpdu || p.edge_delay_while != migrate) && p.port_enabled => {
            State::Receive
        }
        State::Receive if !p.port_enabled => State::Discard,
        State::Receive if p.rcvd_bpdu && p.port_enabled && !p.rcvd_msg => State::Receive,
        _ => return false,
    };
    enter(b, i, next);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machines::tests::*;

    #[test]
    fn discard_to_receive() {
        let mut b = bridge(1);
        b.ports[0].port_enabled = true;
        b.ports[0].rcvd = Some(rst(&b, 0, false));
        b.ports[0].rcvd_bpdu = true;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].prx, State::Receive);
        assert!(b.ports[0].rcvd_msg && b.ports[0].rcvd_rstp && !b.ports[0].oper_edge);
    }

    #[test]
    fn receive_to_discard_when_disabled() {
        let mut b = bridge(1);
        b.ports[0].port_enabled = true;
        enter(&mut b, 0, State::Receive);
        b.ports[0].port_enabled = false;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].prx, State::Discard);
    }

    #[test]
    fn receive_to_receive_on_new_bpdu() {
        let mut b = bridge(1);
        b.ports[0].port_enabled = true;
        enter(&mut b, 0, State::Receive);
        b.ports[0].rcvd = Some(Bpdu::Tcn);
        b.ports[0].rcvd_bpdu = true;
        assert!(step(&mut b, 0));
        assert!(b.ports[0].rcvd_tcn && b.ports[0].rcvd_stp && !b.ports[0].rcvd_msg);
    }

    #[test]
    fn aged_bpdu_is_dropped() {
        let mut b = bridge(1);
        b.ports[0].port_enabled = true;
        let Bpdu::Rst(mut pr) = rst(&b, 0, false) else {
            unreachable!()
        };
        pr.message_age = pr.max_age;
        b.ports[0].rcvd = Some(Bpdu::Rst(pr));
        b.ports[0].rcvd_bpdu = true;
        step(&mut b, 0);
        assert!(!b.ports[0].rcvd_msg);
    }
}
