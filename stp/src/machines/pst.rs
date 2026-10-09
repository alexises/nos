//! Port State Transition machine, 13.38 (Figure 13-16): turns `learn`/`forward`
//! into `learning`/`forwarding` and tells the host.

use crate::actions::{Action, PortState};
use crate::bridge::Bridge;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Discarding,
    Learning,
    Forwarding,
}

pub fn enter(b: &mut Bridge, i: usize, s: State) {
    let p = &mut b.ports[i];
    p.pst = s;
    let state = match s {
        State::Discarding => {
            p.learning = false;
            p.forwarding = false;
            PortState::Discarding
        }
        State::Learning => {
            p.learning = true;
            PortState::Learning
        }
        State::Forwarding => {
            p.forwarding = true;
            PortState::Forwarding
        }
    };
    b.actions.push(Action::SetPortState { port: i, state });
}

pub fn step(b: &mut Bridge, i: usize) -> bool {
    let p = &b.ports[i];
    let next = match p.pst {
        State::Discarding if p.learn => State::Learning,
        State::Learning if !p.learn => State::Discarding,
        State::Learning if p.forward => State::Forwarding,
        State::Forwarding if !p.forward => State::Discarding,
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
    fn full_cycle() {
        let mut b = bridge(1);
        b.take_actions();
        b.ports[0].learn = true;
        assert!(step(&mut b, 0));
        assert!(b.ports[0].learning && !b.ports[0].forwarding);
        b.ports[0].forward = true;
        assert!(step(&mut b, 0));
        assert!(b.ports[0].forwarding);
        b.ports[0].forward = false;
        assert!(step(&mut b, 0)); // FORWARDING -> DISCARDING
        assert!(!b.ports[0].forwarding && !b.ports[0].learning);
        assert_eq!(
            b.take_actions().last(),
            Some(&Action::SetPortState {
                port: 0,
                state: PortState::Discarding
            })
        );
    }

    #[test]
    fn learning_to_discarding_when_learn_dropped() {
        let mut b = bridge(1);
        b.ports[0].learn = true;
        step(&mut b, 0);
        b.ports[0].learn = false;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].pst, State::Discarding);
    }
}
