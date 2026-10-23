//! An `Acl` to tc flower filters (pure). One user rule is one level, and one
//! level is one flower priority per family in the ACL's chain: tc walks the
//! priorities in order, so the first matching rule decides, as written. The
//! optimiser (#542) packs disjoint rules into shared levels.

mod rule;

use nos_proto::schema::{Acl, AclAction};
use nos_tc::{FlowerKeys, Protocol};

/// The action cookie of the default-action filters; a rule's is its index.
pub const DEFAULT_COOKIE: u32 = u32::MAX;

/// One flower filter of a level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    /// `Ip` or `Ipv6`: the filter's family (its tc `protocol`).
    pub protocol: Protocol,
    pub keys: FlowerKeys,
    pub action: AclAction,
    /// The user rule's index in `Acl.rules` (the tc action cookie, read back
    /// by `show acl`'s counters, #543).
    pub rule: u32,
}

/// Filters that may share priorities: at most one of them matches a packet.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Level {
    pub filters: Vec<Filter>,
}

/// What the driver installs in one chain: the levels in order, then a
/// keyless filter per family with `default_action`. Non-IP frames match no
/// filter and pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compiled {
    pub levels: Vec<Level>,
    pub default_action: AclAction,
    /// User rules compiled (`levels.len()` until #542).
    pub rules: usize,
    /// Rules dropped because an earlier rule hides them (0 until #542).
    pub shadowed: usize,
}

impl Compiled {
    /// Every filter, the two defaults included.
    pub fn filters(&self) -> usize {
        self.levels.iter().map(|l| l.filters.len()).sum::<usize>() + 2
    }
}

/// The tc priority of `level`'s `protocol` filters: two per level, because
/// the kernel refuses two protocols at one priority. The defaults sit at
/// `level == levels.len()`.
pub fn prio(level: usize, protocol: Protocol) -> u16 {
    let base = 2 * level + 1;
    let p = if protocol == Protocol::Ipv6 {
        base + 1
    } else {
        base
    };
    u16::try_from(p).expect("compile bounds the level count")
}

/// Most levels a chain holds: their priorities and the defaults' fit `u16`.
pub const MAX_LEVELS: usize = (u16::MAX as usize - 2) / 2;

/// Compiles `acl`. Fails only when it would not fit tc's priority space.
pub fn compile(acl: &Acl) -> Result<Compiled, String> {
    if acl.rules.len() > MAX_LEVELS {
        return Err(format!(
            "{} rules, at most {MAX_LEVELS} fit in tc's priorities",
            acl.rules.len()
        ));
    }
    let levels = (0u32..)
        .zip(&acl.rules)
        .map(|(i, r)| Level {
            filters: rule::filters(r, i),
        })
        .collect::<Vec<_>>();
    Ok(Compiled {
        rules: levels.len(),
        levels,
        default_action: acl.default_action,
        shadowed: 0,
    })
}

#[cfg(test)]
mod tests {
    use nos_proto::schema::{AclProtocol, AclRule};

    use super::*;

    fn rule(name: &str, action: AclAction, protocol: Option<AclProtocol>) -> AclRule {
        AclRule {
            name: name.into(),
            action,
            protocol,
            ..Default::default()
        }
    }

    #[test]
    fn rule_order_is_level_order_then_defaults() {
        let acl = Acl {
            name: "A".into(),
            default_action: AclAction::Permit,
            rules: vec![
                rule("a", AclAction::Deny, Some(AclProtocol::Icmp)),
                rule("b", AclAction::Permit, None),
            ],
        };
        let c = compile(&acl).unwrap();
        assert_eq!((c.rules, c.shadowed, c.levels.len()), (2, 0, 2));
        assert_eq!(c.levels[0].filters.len(), 1);
        assert_eq!(c.levels[0].filters[0].rule, 0);
        assert_eq!(c.levels[1].filters.len(), 2);
        assert!(c.levels[1].filters.iter().all(|f| f.rule == 1));
        assert_eq!(c.default_action, AclAction::Permit);
        assert_eq!(c.filters(), 5);
    }

    #[test]
    fn an_empty_acl_is_just_the_defaults() {
        let c = compile(&Acl::default()).unwrap();
        assert_eq!(c.levels, Vec::<Level>::new());
        assert_eq!((c.filters(), c.default_action), (2, AclAction::Deny));
    }

    #[test]
    fn priorities_split_families_and_stay_ordered() {
        assert_eq!(prio(0, Protocol::Ip), 1);
        assert_eq!(prio(0, Protocol::Ipv6), 2);
        assert_eq!(prio(1, Protocol::Ip), 3);
        assert_eq!(prio(MAX_LEVELS, Protocol::Ipv6), u16::MAX - 1);
    }

    #[test]
    fn too_many_rules_do_not_compile() {
        let acl = Acl {
            rules: vec![AclRule::default(); MAX_LEVELS + 1],
            ..Default::default()
        };
        assert!(compile(&acl).unwrap_err().contains("at most"));
    }
}
