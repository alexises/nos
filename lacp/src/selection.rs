//! Config-scoped Selection Logic (802.1AX §6.4.14, deliberately narrowed —
//! see below). Pure, no I/O.
//!
//! Real 802.1AX Selection Logic *discovers* aggregate membership from
//! scratch, purely from which ports observe a consistent partner system-id
//! and key across an arbitrary pool of candidate ports. This crate doesn't
//! need that: a `PortAggregate`'s member set is already a config-defined,
//! operator-fixed reference (`Interface.port_aggregate`), and the
//! underlying kernel bond device is already fixed by `nos-interfaced`
//! independent of LACP. So this only ever compares ports already belonging
//! to the *same configured* aggregate — its job is to confirm the wire
//! agrees with what was configured (a consistent partner across every
//! currently-`Current` member), not to discover membership from the wire.
//! This is the deliberate, permanent v1 design, not a temporary cut.

use std::collections::HashSet;

/// One member port's current standing within its aggregate, as input to
/// [`select`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortCandidate {
    pub interface: String,
    /// Whether this port's Receive Machine is currently `Current` — a port
    /// that isn't is never selected, regardless of stale partner info it
    /// may still be holding.
    pub current: bool,
    pub partner_system_id: [u8; 6],
    pub partner_key: u16,
    /// This port's own advertised Actor Port Priority and number (lower wins
    /// the tie-break in [`select`]).
    pub actor_port_priority: u16,
    pub actor_port_number: u16,
}

/// Returns the subset of `candidates` that should be `Selected`: every
/// `current` port whose partner (system-id, key) matches the aggregate's
/// most common such pair among its `current` ports — a `current` port
/// disagreeing with that majority is excluded (a basic split-detection). A
/// tie between equally large groups goes to the group holding the port with
/// the lowest (actor port priority, actor port number) — lower priority
/// value wins, as in LACP generally. Because membership is config-fixed and there
/// is no standby/`max-links`, this tie-break is the only place priorities
/// change which ports are selected.
pub fn select(candidates: &[PortCandidate]) -> HashSet<String> {
    let mut counts: Vec<([u8; 6], u16, usize)> = Vec::new();
    for c in candidates.iter().filter(|c| c.current) {
        let key = (c.partner_system_id, c.partner_key);
        match counts.iter_mut().find(|(sys, k, _)| (*sys, *k) == key) {
            Some((_, _, n)) => *n += 1,
            None => counts.push((key.0, key.1, 1)),
        }
    }
    let Some(&(_, _, best)) = counts.iter().max_by_key(|(_, _, n)| *n) else {
        return HashSet::new();
    };
    let rank = |system: [u8; 6], key: u16| {
        candidates
            .iter()
            .filter(|c| c.current && (c.partner_system_id, c.partner_key) == (system, key))
            .map(|c| (c.actor_port_priority, c.actor_port_number))
            .min()
    };
    let &(winning_system, winning_key, _) = counts
        .iter()
        .filter(|(_, _, n)| *n == best)
        .min_by_key(|(s, k, _)| rank(*s, *k))
        .expect("a group of the best size exists");
    candidates
        .iter()
        .filter(|c| {
            c.current && c.partner_system_id == winning_system && c.partner_key == winning_key
        })
        .map(|c| c.interface.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(interface: &str, current: bool, system: u8, key: u16) -> PortCandidate {
        PortCandidate {
            interface: interface.to_string(),
            current,
            partner_system_id: [0, 0, 0, 0, 0, system],
            partner_key: key,
            actor_port_priority: 32768,
            actor_port_number: 1,
        }
    }

    fn with_port(mut c: PortCandidate, priority: u16, number: u16) -> PortCandidate {
        c.actor_port_priority = priority;
        c.actor_port_number = number;
        c
    }

    #[test]
    fn tie_goes_to_lowest_port_priority_then_number() {
        let split = |p1, n1, p2, n2| {
            select(&[
                with_port(candidate("eth1", true, 1, 1), p1, n1),
                with_port(candidate("eth2", true, 2, 2), p2, n2),
            ])
        };
        assert_eq!(split(200, 1, 100, 2), HashSet::from(["eth2".to_string()]));
        assert_eq!(split(100, 1, 200, 2), HashSet::from(["eth1".to_string()]));
        assert_eq!(split(100, 2, 100, 1), HashSet::from(["eth2".to_string()]));
    }

    #[test]
    fn majority_beats_port_priority() {
        let selected = select(&[
            with_port(candidate("eth1", true, 1, 1), 1, 1),
            with_port(candidate("eth2", true, 2, 2), 9, 2),
            with_port(candidate("eth3", true, 2, 2), 9, 3),
        ]);
        assert_eq!(
            selected,
            HashSet::from(["eth2".to_string(), "eth3".to_string()])
        );
    }

    #[test]
    fn no_current_ports_selects_nothing() {
        let candidates = vec![
            candidate("eth1", false, 1, 1),
            candidate("eth2", false, 1, 1),
        ];
        assert!(select(&candidates).is_empty());
    }

    #[test]
    fn agreeing_current_ports_are_all_selected() {
        let candidates = vec![candidate("eth1", true, 1, 1), candidate("eth2", true, 1, 1)];
        let selected = select(&candidates);
        assert_eq!(selected.len(), 2);
        assert!(selected.contains("eth1"));
        assert!(selected.contains("eth2"));
    }

    #[test]
    fn disagreeing_port_is_excluded() {
        let candidates = vec![
            candidate("eth1", true, 1, 1),
            candidate("eth2", true, 1, 1),
            candidate("eth3", true, 9, 9),
        ];
        let selected = select(&candidates);
        assert_eq!(selected.len(), 2);
        assert!(!selected.contains("eth3"));
    }

    #[test]
    fn non_current_port_is_never_selected_even_if_it_agrees() {
        let candidates = vec![
            candidate("eth1", true, 1, 1),
            candidate("eth2", false, 1, 1),
        ];
        let selected = select(&candidates);
        assert_eq!(selected, HashSet::from(["eth1".to_string()]));
    }
}
