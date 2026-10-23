//! The kernel side, per (device, direction) on the device's `clsact` qdisc:
//!
//! - chain 0, priority [`ACL_PRIO`], handle 1: one keyless flower filter,
//!   `goto chain <live>`, whose action cookie is the live chain number;
//! - the ACL itself in chain [`ACL_CHAIN_A`] or [`ACL_CHAIN_B`].
//!
//! An update fills the idle chain, replaces the entry (one RCU swap: no
//! packet sees no ACL or half of one), then flushes the old chain.
//! `nos-fdbd`/`nos-interfaced` own lower priorities on chain 0 (`tc/CLAUDE.md`):
//! nothing here deletes the qdisc or touches their priorities.

mod linux;
mod noop;

use std::fmt;
use std::io;

pub use linux::LinuxDriver;
pub use noop::{Call, NoopDriver};

use nos_proto::schema::AclAction;
use nos_tc::{
    Action, ActionKind, Filter, FilterStats, FlowerKeys, Hook, Kind, Protocol, Request, Verdict,
};

use crate::compile::{prio, Compiled, DEFAULT_COOKIE};

/// Chain 0 priority of the entry filter: above every priority `nos-fdbd` and
/// `nos-interfaced` use (1, 2), so theirs run first.
pub const ACL_PRIO: u16 = 100;
/// The two chains an ACL alternates between.
pub const ACL_CHAIN_A: u32 = 1000;
pub const ACL_CHAIN_B: u32 = 1001;
/// The entry filter's fixed handle.
const ENTRY_HANDLE: u32 = 1;

/// `acl in` is clsact ingress, `acl out` clsact egress (no ifb).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    In,
    Out,
}

impl Direction {
    pub const BOTH: [Direction; 2] = [Direction::In, Direction::Out];

    pub fn hook(self) -> Hook {
        match self {
            Self::In => Hook::Ingress,
            Self::Out => Hook::Egress,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::In => "in",
            Self::Out => "out",
        })
    }
}

/// The chain an update fills: the one not live.
pub fn idle(live: Option<u32>) -> u32 {
    if live == Some(ACL_CHAIN_A) {
        ACL_CHAIN_B
    } else {
        ACL_CHAIN_A
    }
}

/// What the kernel holds for one (device, direction). Blocking: the daemon
/// calls it from `spawn_blocking`.
pub trait Driver: Send + 'static {
    /// The chain the entry filter points at, `None` without one.
    fn live_chain(&mut self, ifindex: u32, dir: Direction) -> io::Result<Option<u32>>;
    /// Ensures `clsact`, empties `chain`, fills it with `acl`.
    fn install(
        &mut self,
        ifindex: u32,
        dir: Direction,
        chain: u32,
        acl: &Compiled,
    ) -> io::Result<()>;
    /// Creates or replaces the entry filter to point at `chain`.
    fn switch(&mut self, ifindex: u32, dir: Direction, chain: u32) -> io::Result<()>;
    /// Removes every filter of `chain` (absent is fine).
    fn flush(&mut self, ifindex: u32, dir: Direction, chain: u32) -> io::Result<()>;
    /// Removes the entry filter, then both chains.
    fn detach(&mut self, ifindex: u32, dir: Direction) -> io::Result<()>;
    /// The counters of `chain`'s filters, one per action cookie (`show acl`).
    fn counters(&mut self, ifindex: u32, dir: Direction, chain: u32) -> io::Result<Vec<Counter>>;
}

/// One filter's `gact` counters: the action cookie (a rule index, or
/// [`DEFAULT_COOKIE`]) and what matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counter {
    pub cookie: u32,
    pub packets: u64,
    pub bytes: u64,
}

/// The `gact` rows of a chain dump. Read by kind, not position: a filter may
/// carry a `sample` action (#544) whose counters are not the verdict's.
pub fn counters_from(rows: &[FilterStats]) -> Vec<Counter> {
    rows.iter()
        .filter(|r| r.action == "gact")
        .filter_map(|r| {
            Some(Counter {
                cookie: u32::from_be_bytes(<[u8; 4]>::try_from(r.cookie.as_slice()).ok()?),
                packets: r.packets,
                bytes: r.bytes,
            })
        })
        .collect()
}

fn verdict(a: AclAction) -> Verdict {
    match a {
        AclAction::Permit => Verdict::Ok,
        AclAction::Deny => Verdict::Shot,
    }
}

/// The filters of `chain` for `acl`, levels then defaults.
pub fn chain_requests(ifindex: u32, dir: Direction, chain: u32, acl: &Compiled) -> Vec<Request> {
    let filter = |level, protocol, keys, action, cookie: u32| {
        Request::AddFilter(Filter {
            ifindex,
            hook: dir.hook(),
            chain,
            prio: prio(level, protocol),
            protocol,
            handle: 0,
            kind: Kind::Flower(keys),
            actions: vec![Action {
                kind: ActionKind::Gact(verdict(action)),
                cookie: cookie.to_be_bytes().to_vec(),
            }],
            replace: false,
        })
    };
    let mut v: Vec<Request> = acl
        .levels
        .iter()
        .enumerate()
        .flat_map(|(i, l)| {
            l.filters
                .iter()
                .map(move |f| filter(i, f.protocol, f.keys.clone(), f.action, f.rule))
        })
        .collect();
    for p in [Protocol::Ip, Protocol::Ipv6] {
        let keys = FlowerKeys::default();
        v.push(filter(
            acl.levels.len(),
            p,
            keys,
            acl.default_action,
            DEFAULT_COOKIE,
        ));
    }
    v
}

/// The chain-0 entry filter (`NLM_F_REPLACE`: creates or swaps in place).
pub fn entry_request(ifindex: u32, dir: Direction, chain: u32) -> Request {
    Request::AddFilter(Filter {
        ifindex,
        hook: dir.hook(),
        chain: 0,
        prio: ACL_PRIO,
        protocol: Protocol::All,
        handle: ENTRY_HANDLE,
        kind: Kind::Flower(FlowerKeys::default()),
        actions: vec![Action {
            kind: ActionKind::Gact(Verdict::GotoChain(chain)),
            cookie: chain.to_be_bytes().to_vec(),
        }],
        replace: true,
    })
}

/// Deletes the entry filter (the whole of our priority on chain 0).
pub fn entry_delete(ifindex: u32, dir: Direction) -> Request {
    Request::DelFilter {
        ifindex,
        hook: dir.hook(),
        chain: 0,
        prio: ACL_PRIO,
        protocol: Protocol::All,
        handle: 0,
    }
}

/// The live chain from a chain-0 dump: our entry's cookie.
pub fn live_from(rows: &[FilterStats]) -> Option<u32> {
    rows.iter()
        .find(|r| r.prio == ACL_PRIO && r.handle == ENTRY_HANDLE)
        .and_then(|r| <[u8; 4]>::try_from(r.cookie.as_slice()).ok())
        .map(u32::from_be_bytes)
        .filter(|c| [ACL_CHAIN_A, ACL_CHAIN_B].contains(c))
}

#[cfg(test)]
mod tests {
    use nos_proto::schema::{Acl, AclRule};

    use super::*;
    use crate::compile::compile;

    #[test]
    fn idle_alternates() {
        assert_eq!(idle(None), ACL_CHAIN_A);
        assert_eq!(idle(Some(ACL_CHAIN_A)), ACL_CHAIN_B);
        assert_eq!(idle(Some(ACL_CHAIN_B)), ACL_CHAIN_A);
    }

    #[test]
    fn directions_are_clsact_hooks() {
        assert_eq!(Direction::In.hook(), Hook::Ingress);
        assert_eq!(Direction::Out.hook(), Hook::Egress);
        assert_eq!(format!("{} {}", Direction::In, Direction::Out), "in out");
    }

    #[test]
    fn chain_holds_levels_then_one_default_per_family() {
        let acl = Acl {
            rules: vec![AclRule {
                name: "p".into(),
                action: AclAction::Permit,
                ..Default::default()
            }],
            ..Default::default()
        };
        let reqs = chain_requests(9, Direction::Out, ACL_CHAIN_B, &compile(&acl).unwrap());
        let got: Vec<_> = reqs
            .iter()
            .map(|r| match r {
                Request::AddFilter(f) => {
                    assert_eq!(
                        (f.ifindex, f.hook, f.chain, f.handle),
                        (9, Hook::Egress, ACL_CHAIN_B, 0)
                    );
                    assert!(!f.replace);
                    (f.prio, f.protocol, f.actions[0].clone())
                }
                other => panic!("{other:?}"),
            })
            .collect();
        let act = |v, c: u32| Action {
            kind: ActionKind::Gact(v),
            cookie: c.to_be_bytes().to_vec(),
        };
        assert_eq!(
            got,
            [
                (1, Protocol::Ip, act(Verdict::Ok, 0)),
                (2, Protocol::Ipv6, act(Verdict::Ok, 0)),
                (3, Protocol::Ip, act(Verdict::Shot, DEFAULT_COOKIE)),
                (4, Protocol::Ipv6, act(Verdict::Shot, DEFAULT_COOKIE)),
            ]
        );
    }

    #[test]
    fn counters_come_from_the_gact_rows_by_kind() {
        let row = |action: &str, cookie: &[u8], packets| FilterStats {
            action: action.into(),
            cookie: cookie.to_vec(),
            packets,
            bytes: packets * 10,
            ..Default::default()
        };
        let c = |cookie, packets| Counter {
            cookie,
            packets,
            bytes: packets * 10,
        };
        let rows = [
            row("sample", &[0, 0, 0, 1], 99),
            row("gact", &[0, 0, 0, 1], 3),
            row("gact", &DEFAULT_COOKIE.to_be_bytes(), 5),
            row("gact", &[1, 2], 7),
            row("gact", &[], 8),
        ];
        assert_eq!(counters_from(&rows), [c(1, 3), c(DEFAULT_COOKIE, 5)]);
    }

    #[test]
    fn entry_points_at_the_chain_and_names_it_in_its_cookie() {
        let Request::AddFilter(f) = entry_request(3, Direction::In, ACL_CHAIN_A) else {
            panic!()
        };
        assert_eq!(
            (f.chain, f.prio, f.handle, f.protocol),
            (0, ACL_PRIO, 1, Protocol::All)
        );
        assert!(f.replace);
        assert_eq!(f.kind, Kind::Flower(FlowerKeys::default()));
        assert_eq!(
            f.actions[0].kind,
            ActionKind::Gact(Verdict::GotoChain(ACL_CHAIN_A))
        );
        let row = |prio, handle, cookie: Vec<u8>| FilterStats {
            prio,
            handle,
            cookie,
            ..Default::default()
        };
        assert_eq!(
            live_from(&[row(ACL_PRIO, 1, f.actions[0].cookie.clone())]),
            Some(ACL_CHAIN_A)
        );
        assert_eq!(
            live_from(&[row(1, 1, ACL_CHAIN_A.to_be_bytes().to_vec())]),
            None
        );
        assert_eq!(live_from(&[row(ACL_PRIO, 1, vec![1, 2])]), None);
        assert_eq!(
            live_from(&[row(ACL_PRIO, 1, 7u32.to_be_bytes().to_vec())]),
            None
        );
        assert_eq!(live_from(&[]), None);
        assert_eq!(
            entry_delete(3, Direction::Out),
            Request::DelFilter {
                ifindex: 3,
                hook: Hook::Egress,
                chain: 0,
                prio: ACL_PRIO,
                protocol: Protocol::All,
                handle: 0,
            }
        );
    }
}
