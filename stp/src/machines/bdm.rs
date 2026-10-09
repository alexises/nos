//! Bridge Detection machine, 13.32 (Figure 13-14): `operEdge`.

use crate::bridge::Bridge;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Edge,
    NotEdge,
}

pub fn enter(b: &mut Bridge, i: usize, s: State) {
    let p = &mut b.ports[i];
    p.bdm = s;
    p.oper_edge = s == State::Edge;
}

pub fn step(b: &mut Bridge, i: usize) -> bool {
    let p = &b.ports[i];
    let next = match p.bdm {
        State::Edge if (!p.port_enabled && !p.admin_edge) || !p.oper_edge => State::NotEdge,
        State::NotEdge
            if (!p.port_enabled && p.admin_edge)
                || (p.edge_delay_while == 0 && p.auto_edge && p.send_rstp && p.proposing) =>
        {
            State::Edge
        }
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
    fn not_edge_to_edge_when_admin_edge_and_down() {
        let mut b = bridge(1);
        b.ports[0].admin_edge = true;
        assert!(step(&mut b, 0));
        assert!(b.ports[0].oper_edge);
    }

    #[test]
    fn not_edge_to_edge_by_auto_detection() {
        let mut b = bridge(1);
        let p = &mut b.ports[0];
        p.port_enabled = true;
        p.auto_edge = true;
        p.send_rstp = true;
        p.proposing = true;
        p.edge_delay_while = 1;
        assert!(!step(&mut b, 0));
        b.ports[0].edge_delay_while = 0;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].bdm, State::Edge);
    }

    #[test]
    fn edge_to_not_edge_when_bpdu_seen_or_link_down_non_admin() {
        let mut b = bridge(1);
        enter(&mut b, 0, State::Edge);
        b.ports[0].port_enabled = true;
        b.ports[0].oper_edge = false; // PRX clears it on a BPDU
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].bdm, State::NotEdge);
        enter(&mut b, 0, State::Edge);
        b.ports[0].port_enabled = false;
        assert!(step(&mut b, 0), "port down and not adminEdge");
    }
}
