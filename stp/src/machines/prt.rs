//! Port Role Transition machine, 13.35 (Figures 13-20 to 13-22).
//!
//! Variables are the CIST's; clause numbers in comments cite the guards that
//! are easy to get wrong. Transient states (`ROOT_PROPOSED`, ...) are real
//! states: they run their entry, then return to their role's resting state.

use super::{
    all_synced, edge_delay, fwd_delay, hello, max_age, re_rooted, set_re_root_tree, set_sync_tree,
    Role,
};
use crate::actions::{Action, Event};
use crate::bridge::Bridge;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    InitPort,
    DisablePort,
    DisabledPort,
    RootPort,
    RootProposed,
    RootAgreed,
    Reroot,
    RootForward,
    RootLearn,
    Rerooted,
    DesignatedPort,
    DesignatedPropose,
    DesignatedSynced,
    DesignatedRetired,
    DesignatedForward,
    DesignatedLearn,
    DesignatedDiscard,
    BlockPort,
    AlternatePort,
    AlternateProposed,
    AlternateAgreed,
    BackupPort,
}

fn set_role(b: &mut Bridge, i: usize, role: Role) {
    let p = &mut b.ports[i];
    if p.role != role {
        let from = p.role;
        p.role = role;
        b.actions.push(Action::Log(Event::RoleChanged {
            port: i,
            from,
            to: role,
        }));
    }
}

pub fn enter(b: &mut Bridge, i: usize, s: State) {
    let (fwd, age, h) = (fwd_delay(b), max_age(b), hello(b));
    b.ports[i].prt = s;
    match s {
        State::InitPort => {
            set_role(b, i, Role::Disabled);
            let p = &mut b.ports[i];
            p.learn = false;
            p.forward = false;
            p.synced = false;
            p.sync = true;
            p.re_root = true;
            p.rr_while = fwd;
            p.fd_while = age;
            p.rb_while = 0;
        }
        State::DisablePort => {
            let r = b.ports[i].selected_role;
            set_role(b, i, r);
            b.ports[i].learn = false;
            b.ports[i].forward = false;
        }
        State::DisabledPort => {
            let p = &mut b.ports[i];
            p.fd_while = age;
            p.synced = true;
            p.rr_while = 0;
            p.sync = false;
            p.re_root = false;
        }
        State::RootPort => {
            set_role(b, i, Role::Root);
            b.ports[i].rr_while = fwd;
        }
        State::RootProposed => {
            set_sync_tree(b);
            b.ports[i].proposed = false;
        }
        State::RootAgreed | State::AlternateAgreed => {
            let p = &mut b.ports[i];
            p.proposed = false;
            p.sync = false;
            p.agree = true;
            p.new_info = true;
        }
        State::Reroot => set_re_root_tree(b),
        State::RootForward => {
            let p = &mut b.ports[i];
            p.fd_while = 0;
            p.forward = true;
        }
        State::RootLearn => {
            let p = &mut b.ports[i];
            p.fd_while = fwd;
            p.learn = true;
        }
        State::Rerooted => b.ports[i].re_root = false,
        State::DesignatedPort => set_role(b, i, Role::Designated),
        State::DesignatedPropose => {
            let ed = edge_delay(b, i);
            let p = &mut b.ports[i];
            p.proposing = true;
            p.edge_delay_while = ed;
            p.new_info = true;
        }
        State::DesignatedSynced => {
            let p = &mut b.ports[i];
            p.rr_while = 0;
            p.synced = true;
            p.sync = false;
        }
        State::DesignatedRetired => b.ports[i].re_root = false,
        State::DesignatedForward => {
            let p = &mut b.ports[i];
            p.forward = true;
            p.fd_while = 0;
            p.agreed = p.send_rstp;
        }
        State::DesignatedLearn => {
            let p = &mut b.ports[i];
            p.learn = true;
            p.fd_while = fwd;
        }
        State::DesignatedDiscard => {
            let p = &mut b.ports[i];
            p.learn = false;
            p.forward = false;
            p.disputed = false;
            p.fd_while = fwd;
        }
        State::BlockPort => {
            let r = b.ports[i].selected_role;
            set_role(b, i, r);
            b.ports[i].learn = false;
            b.ports[i].forward = false;
        }
        State::AlternatePort => {
            let p = &mut b.ports[i];
            p.fd_while = fwd;
            p.synced = true;
            p.rr_while = 0;
            p.sync = false;
            p.re_root = false;
        }
        State::AlternateProposed => {
            set_sync_tree(b);
            b.ports[i].proposed = false;
        }
        State::BackupPort => b.ports[i].rb_while = h.saturating_mul(2),
    }
}

/// The resting state for a role (what a role change enters).
fn role_state(r: Role) -> State {
    match r {
        Role::Disabled => State::DisablePort,
        Role::Root => State::RootPort,
        Role::Designated => State::DesignatedPort,
        Role::Alternate | Role::Backup => State::BlockPort,
    }
}

pub fn step(b: &mut Bridge, i: usize) -> bool {
    let (fwd, h, rstp) = (fwd_delay(b), hello(b), b.rstp_version);
    let synced_all = all_synced(b);
    let rerooted = re_rooted(b, i);
    let p = &b.ports[i];
    let ready = p.selected && !p.updt_info;
    // A role change is a global transition (not from INIT_PORT, whose only exit is unconditional).
    let resting = match p.prt {
        State::InitPort => {
            enter(b, i, State::DisablePort);
            return true;
        }
        s => s,
    };
    if ready
        && p.role != p.selected_role
        && !matches!(resting, State::DisablePort | State::BlockPort)
    {
        enter(b, i, role_state(p.selected_role));
        return true;
    }
    // Shortcut forwarding (reRooted) is an RSTP-only privilege (13.35 ROOT_PORT).
    let fast = rerooted && p.rb_while == 0 && rstp;
    let next = match resting {
        State::InitPort => unreachable!(),
        State::DisablePort if !p.learning && !p.forwarding && ready => State::DisabledPort,
        State::DisabledPort if p.fd_while != max_age(b) || p.sync || p.re_root || !p.synced => {
            State::DisabledPort
        }
        State::BlockPort if !p.learning && !p.forwarding => State::AlternatePort,
        State::AlternatePort | State::BackupPort if ready && p.role == p.selected_role => {
            if p.proposed && !p.agree {
                State::AlternateProposed
            } else if (synced_all && !p.agree) || (p.proposed && p.agree) {
                State::AlternateAgreed
            } else if p.role == Role::Backup && p.rb_while != h.saturating_mul(2) {
                State::BackupPort
            } else if p.fd_while != fwd || p.sync || p.re_root || !p.synced {
                State::AlternatePort
            } else {
                return false;
            }
        }
        State::RootPort if ready && p.role == p.selected_role => {
            if p.proposed && !p.agree {
                State::RootProposed
            } else if (synced_all && !p.agree) || (p.proposed && p.agree) {
                State::RootAgreed
            } else if !p.forward && !p.re_root {
                State::Reroot
            } else if p.re_root && p.forward {
                State::Rerooted
            } else if p.rr_while != fwd {
                State::RootPort
            } else if (p.fd_while == 0 || fast) && !p.learn {
                State::RootLearn
            } else if (p.fd_while == 0 || fast) && p.learn && !p.forward {
                State::RootForward
            } else {
                return false;
            }
        }
        State::DesignatedPort if ready && p.role == p.selected_role => {
            let moving = (p.fd_while == 0 || p.agreed || p.oper_edge)
                && (p.rr_while == 0 || !p.re_root)
                && !p.sync;
            if !p.forward && !p.agreed && !p.proposing && !p.oper_edge {
                State::DesignatedPropose
            // Checked before SYNCED: a forwarding port must discard first (13.35).
            } else if ((p.sync && !p.synced) || (p.re_root && p.rr_while != 0) || p.disputed)
                && !p.oper_edge
                && (p.learn || p.forward)
            {
                State::DesignatedDiscard
            } else if (!p.learning && !p.forwarding && !p.synced)
                || (p.agreed && !p.synced)
                || (p.oper_edge && !p.synced)
                || (p.sync && !p.synced)
            {
                State::DesignatedSynced
            } else if p.rr_while == 0 && p.re_root {
                State::DesignatedRetired
            } else if moving && !p.learn {
                State::DesignatedLearn
            } else if moving && p.learn && !p.forward {
                State::DesignatedForward
            } else {
                return false;
            }
        }
        // Transient states return to their role's resting state.
        State::RootProposed
        | State::RootAgreed
        | State::Reroot
        | State::RootForward
        | State::RootLearn
        | State::Rerooted => State::RootPort,
        State::DesignatedPropose
        | State::DesignatedSynced
        | State::DesignatedRetired
        | State::DesignatedForward
        | State::DesignatedLearn
        | State::DesignatedDiscard => State::DesignatedPort,
        State::AlternateProposed | State::AlternateAgreed => State::AlternatePort,
        _ => return false,
    };
    enter(b, i, next);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machines::tests::bridge;

    /// Port 0 selected as `role`, resting in that role's state.
    fn at(role: Role) -> Bridge {
        let mut b = bridge(1);
        for p in &mut b.ports {
            p.selected = true;
            p.updt_info = false;
            p.selected_role = Role::Designated;
            p.role = Role::Designated;
            p.synced = true;
            p.sync = false;
            p.re_root = false;
            p.rr_while = 0;
            p.fd_while = 99;
        }
        b.ports[0].selected_role = role;
        b.ports[0].role = role;
        b.ports[0].prt = match role {
            Role::Disabled => State::DisabledPort,
            Role::Root => State::RootPort,
            Role::Designated => State::DesignatedPort,
            Role::Alternate | Role::Backup => State::AlternatePort,
        };
        b.ports[0].rr_while = if role == Role::Root {
            b.root_times.forward_delay
        } else {
            0
        };
        b.ports[0].fd_while = b.root_times.forward_delay;
        b
    }

    fn goes(b: &mut Bridge, to: State) {
        assert!(step(b, 0), "no transition, want {to:?}");
        assert_eq!(b.ports[0].prt, to);
    }

    #[test]
    fn init_to_disable_to_disabled() {
        let mut b = bridge(1);
        b.ports[0].prt = State::InitPort;
        goes(&mut b, State::DisablePort);
        b.ports[0].selected = true;
        b.ports[0].updt_info = false;
        goes(&mut b, State::DisabledPort);
        assert!(b.ports[0].synced && b.ports[0].rr_while == 0);
    }

    #[test]
    fn role_change_enters_role_state() {
        let mut b = at(Role::Designated);
        b.ports[0].selected_role = Role::Root;
        goes(&mut b, State::RootPort);
        b.ports[0].selected_role = Role::Alternate;
        goes(&mut b, State::BlockPort);
        goes(&mut b, State::AlternatePort);
        b.ports[0].selected_role = Role::Disabled;
        goes(&mut b, State::DisablePort);
        b.ports[0].updt_info = true;
        b.ports[0].selected_role = Role::Designated;
        assert!(!step(&mut b, 0), "no role change while updtInfo");
    }

    #[test]
    fn root_proposed_then_agreed() {
        let mut b = at(Role::Root);
        b.ports[0].proposed = true;
        b.ports[0].agree = false;
        b.ports[1].synced = false;
        goes(&mut b, State::RootProposed);
        assert!(b.ports.iter().all(|p| p.sync) && !b.ports[0].proposed);
        goes(&mut b, State::RootPort);
        b.ports[2].rr_while = 1; // no reRooted shortcut
        b.ports[0].re_root = true;
        assert!(!step(&mut b, 0), "port 1 not synced yet");
        b.ports[1].synced = true;
        b.ports[2].synced = true;
        goes(&mut b, State::RootAgreed);
        assert!(b.ports[0].agree && b.ports[0].new_info && !b.ports[0].sync);
    }

    #[test]
    fn root_agreed_again_on_repeated_proposal() {
        let mut b = at(Role::Root);
        b.ports[0].agree = true;
        b.ports[0].proposed = true;
        goes(&mut b, State::RootAgreed);
    }

    #[test]
    fn root_port_reroot_rerooted_and_reload() {
        let mut b = at(Role::Root);
        b.ports[0].agree = true;
        b.ports[0].rr_while = 3; // ticked down
        goes(&mut b, State::Reroot);
        assert!(b.ports.iter().all(|p| p.re_root));
        goes(&mut b, State::RootPort);
        assert_eq!(b.ports[0].rr_while, b.root_times.forward_delay);
        b.ports[0].forward = true;
        goes(&mut b, State::Rerooted);
        assert!(!b.ports[0].re_root);
    }

    #[test]
    fn root_learn_then_forward_on_fd_while_or_rerooted() {
        let mut b = at(Role::Root);
        b.ports[0].agree = true;
        b.ports[0].re_root = true;
        b.ports[0].fd_while = 5;
        // reRooted && rbWhile == 0 shortcut: other ports' rrWhile are 0.
        goes(&mut b, State::RootLearn);
        assert!(b.ports[0].learn);
        goes(&mut b, State::RootPort);
        goes(&mut b, State::RootForward);
        assert!(b.ports[0].forward && b.ports[0].fd_while == 0);
    }

    #[test]
    fn root_waits_while_another_port_was_recently_root() {
        let mut b = at(Role::Root);
        b.ports[0].agree = true;
        b.ports[0].re_root = true;
        b.ports[0].fd_while = 5;
        b.ports[1].rr_while = 4;
        assert!(!step(&mut b, 0));
        b.ports[0].fd_while = 0;
        goes(&mut b, State::RootLearn);
    }

    #[test]
    fn designated_propose_when_not_forwarding() {
        let mut b = at(Role::Designated);
        goes(&mut b, State::DesignatedPropose);
        assert!(b.ports[0].proposing && b.ports[0].new_info);
        assert_eq!(b.ports[0].edge_delay_while, 3);
    }

    #[test]
    fn designated_synced_and_retired() {
        let mut b = at(Role::Designated);
        b.ports[0].proposing = true;
        b.ports[0].synced = false;
        goes(&mut b, State::DesignatedSynced);
        assert!(b.ports[0].synced && b.ports[0].rr_while == 0);
        goes(&mut b, State::DesignatedPort);
        b.ports[0].re_root = true;
        goes(&mut b, State::DesignatedRetired);
        assert!(!b.ports[0].re_root);
    }

    #[test]
    fn designated_learn_forward_after_agreement() {
        let mut b = at(Role::Designated);
        b.ports[0].proposing = true;
        b.ports[0].agreed = true;
        goes(&mut b, State::DesignatedLearn);
        assert!(b.ports[0].learn);
        goes(&mut b, State::DesignatedPort);
        goes(&mut b, State::DesignatedForward);
        assert!(b.ports[0].forward && b.ports[0].agreed == b.ports[0].send_rstp);
    }

    #[test]
    fn designated_waits_for_fd_while_without_agreement() {
        let mut b = at(Role::Designated);
        b.ports[0].proposing = true;
        b.ports[0].fd_while = 2;
        assert!(!step(&mut b, 0));
        b.ports[0].fd_while = 0;
        goes(&mut b, State::DesignatedLearn);
    }

    #[test]
    fn designated_discard_on_sync_dispute_or_reroot() {
        for set in [
            (|p: &mut crate::machines::Port| {
                p.sync = true;
                p.synced = false;
            }) as fn(&mut crate::machines::Port),
            |p| p.disputed = true,
            |p| {
                p.re_root = true;
                p.rr_while = 3;
            },
        ] {
            let mut b = at(Role::Designated);
            b.ports[0].forward = true;
            b.ports[0].learn = true;
            b.ports[0].proposing = true;
            set(&mut b.ports[0]);
            goes(&mut b, State::DesignatedDiscard);
            let p = &b.ports[0];
            assert!(
                !p.learn && !p.forward && !p.disputed && p.fd_while == b.root_times.forward_delay
            );
        }
    }

    #[test]
    fn disabled_reloads_while_unsynced() {
        let mut b = at(Role::Disabled);
        b.ports[0].fd_while = 3; // ticked
        goes(&mut b, State::DisabledPort);
        assert_eq!(b.ports[0].fd_while, b.root_times.max_age);
    }

    #[test]
    fn alternate_proposed_and_agreed() {
        let mut b = at(Role::Alternate);
        b.ports[0].proposed = true;
        goes(&mut b, State::AlternateProposed);
        assert!(b.ports[1].sync);
        goes(&mut b, State::AlternatePort);
        b.ports[1].synced = true;
        b.ports[0].proposed = true;
        b.ports[0].agree = false;
        goes(&mut b, State::AlternateProposed);
        goes(&mut b, State::AlternatePort);
        b.ports[0].sync = false;
        b.ports[1].synced = true;
        b.ports[2].synced = true;
        goes(&mut b, State::AlternateAgreed);
        assert!(b.ports[0].agree && b.ports[0].new_info);
    }

    #[test]
    fn backup_sets_recent_backup_timer() {
        let mut b = at(Role::Backup);
        b.ports[0].agree = true;
        goes(&mut b, State::BackupPort);
        assert_eq!(b.ports[0].rb_while, 2 * b.root_times.hello);
    }
}
