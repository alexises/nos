//! Port Protocol Migration machine, 13.31 (Figure 13-13).

use crate::bridge::Bridge;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    CheckingRstp,
    SelectingStp,
    Sensing,
}

pub fn enter(b: &mut Bridge, i: usize, s: State) {
    let (migrate, rstp) = (b.timers.migrate_time, b.rstp_version);
    let p = &mut b.ports[i];
    p.ppm = s;
    match s {
        State::CheckingRstp => {
            p.mcheck = false;
            p.send_rstp = rstp;
            p.mdelay_while = migrate;
        }
        State::SelectingStp => {
            p.send_rstp = false;
            p.mdelay_while = migrate;
        }
        State::Sensing => {
            p.rcvd_rstp = false;
            p.rcvd_stp = false;
        }
    }
}

pub fn step(b: &mut Bridge, i: usize) -> bool {
    let (migrate, rstp) = (b.timers.migrate_time, b.rstp_version);
    let p = &b.ports[i];
    let next = match p.ppm {
        State::CheckingRstp if p.mdelay_while == 0 => State::Sensing,
        State::CheckingRstp if p.mdelay_while != migrate && !p.port_enabled => State::CheckingRstp,
        State::Sensing if p.send_rstp && p.rcvd_stp => State::SelectingStp,
        State::Sensing if !p.port_enabled || p.mcheck || (rstp && !p.send_rstp && p.rcvd_rstp) => {
            State::CheckingRstp
        }
        State::SelectingStp if p.mdelay_while == 0 || !p.port_enabled || p.mcheck => State::Sensing,
        _ => return false,
    };
    enter(b, i, next);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machines::tests::bridge;

    #[test]
    fn checking_to_sensing_after_migrate_time() {
        let mut b = bridge(1);
        assert!(!step(&mut b, 0));
        b.ports[0].mdelay_while = 0;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].ppm, State::Sensing);
    }

    #[test]
    fn checking_restarts_when_disabled_mid_delay() {
        let mut b = bridge(1);
        b.ports[0].mdelay_while = 1;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].mdelay_while, 3);
    }

    #[test]
    fn sensing_to_selecting_stp_on_legacy_bpdu() {
        let mut b = bridge(1);
        enter(&mut b, 0, State::Sensing);
        b.ports[0].port_enabled = true;
        b.ports[0].rcvd_stp = true;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].ppm, State::SelectingStp);
        assert!(!b.ports[0].send_rstp);
    }

    #[test]
    fn selecting_stp_back_to_sensing_after_migrate_time() {
        let mut b = bridge(1);
        b.ports[0].port_enabled = true;
        enter(&mut b, 0, State::SelectingStp);
        assert!(!step(&mut b, 0));
        b.ports[0].mdelay_while = 0;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].ppm, State::Sensing);
    }

    #[test]
    fn sensing_to_checking_on_rstp_after_stp_or_mcheck() {
        let mut b = bridge(1);
        b.ports[0].port_enabled = true;
        enter(&mut b, 0, State::Sensing);
        b.ports[0].send_rstp = false;
        b.ports[0].rcvd_rstp = true;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].ppm, State::CheckingRstp);
        assert!(b.ports[0].send_rstp);
        enter(&mut b, 0, State::Sensing);
        b.ports[0].mcheck = true;
        assert!(step(&mut b, 0));
        assert!(!b.ports[0].mcheck);
    }
}
