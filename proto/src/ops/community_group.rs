use serde::{Deserialize, Serialize};

use crate::schema::{CommunityGroup, Config};

use super::OpError;

/// An edit to a single named `CommunityGroup` within a transaction's
/// in-progress config. Applied without validation — `garde` validation only
/// runs at commit time, matching every other `Op`. `members` has no
/// `Ensure`/`SetX` split since it's a plain list of scalars (not a keyed
/// collection) — `AddMember`/`RemoveMember` mutate it directly, mirroring
/// `InterfaceOp::AddAddress`/`RemoveAddress`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommunityGroupOp {
    /// Creates the group with no members if it doesn't already exist by
    /// name; no-op if it does. Backs `edit community-group <name>`'s
    /// "create if missing, else navigate to it" semantics.
    Ensure {
        /// Name of the community group this op targets.
        name: String,
    },
    /// Adds member `member` to the community group.
    AddMember {
        /// Name of the community group this op targets.
        name: String,
        /// Member of the group.
        member: String,
    },
    /// Removes member `member` from the community group.
    RemoveMember {
        /// Name of the community group this op targets.
        name: String,
        /// Member of the group.
        member: String,
    },
    /// Deletes the community group and everything nested under it.
    Delete {
        /// Name of the community group this op targets.
        name: String,
    },
}

impl CommunityGroupOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            CommunityGroupOp::Ensure { name } => {
                if !config.community_groups.iter().any(|g| &g.name == name) {
                    config.community_groups.push(CommunityGroup {
                        name: name.clone(),
                        members: Vec::new(),
                    });
                }
                Ok(())
            }
            CommunityGroupOp::AddMember { name, member } => {
                let group = find_group_mut(config, name)?;
                if !group.members.contains(member) {
                    group.members.push(member.clone());
                }
                Ok(())
            }
            CommunityGroupOp::RemoveMember { name, member } => {
                let group = find_group_mut(config, name)?;
                let before = group.members.len();
                group.members.retain(|m| m != member);
                if group.members.len() == before {
                    return Err(OpError::CommunityGroupMemberNotFound {
                        name: name.clone(),
                        member: member.clone(),
                    });
                }
                Ok(())
            }
            CommunityGroupOp::Delete { name } => {
                let before = config.community_groups.len();
                config.community_groups.retain(|g| &g.name != name);
                if config.community_groups.len() == before {
                    return Err(OpError::CommunityGroupNotFound(name.clone()));
                }
                Ok(())
            }
        }
    }
}

fn find_group_mut<'a>(
    config: &'a mut Config,
    name: &str,
) -> Result<&'a mut CommunityGroup, OpError> {
    config
        .community_groups
        .iter_mut()
        .find(|g| g.name == name)
        .ok_or_else(|| OpError::CommunityGroupNotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(name: &str) -> CommunityGroup {
        CommunityGroup {
            name: name.to_string(),
            members: Vec::new(),
        }
    }

    #[test]
    fn ensure_creates_when_missing() {
        let mut cfg = Config::default();
        CommunityGroupOp::Ensure {
            name: "g1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.community_groups.len(), 1);
        assert_eq!(cfg.community_groups[0].members, [] as [String; 0]);
    }

    #[test]
    fn ensure_is_idempotent_and_adds_distinct_names() {
        let mut cfg = Config::default();
        let ensure = |cfg: &mut Config, n: &str| {
            CommunityGroupOp::Ensure {
                name: n.to_string(),
            }
            .apply(cfg)
            .unwrap();
        };
        ensure(&mut cfg, "g1");
        CommunityGroupOp::AddMember {
            name: "g1".to_string(),
            member: "65000:1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        ensure(&mut cfg, "g1");
        assert_eq!(cfg.community_groups.len(), 1);
        assert_eq!(cfg.community_groups[0].members, ["65000:1"]);
        ensure(&mut cfg, "g2");
        let names: Vec<_> = cfg
            .community_groups
            .iter()
            .map(|g| g.name.as_str())
            .collect();
        assert_eq!(names, ["g1", "g2"]);
        // An edit lands on the named group only.
        CommunityGroupOp::AddMember {
            name: "g2".to_string(),
            member: "65000:2".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.community_groups[0].members, ["65000:1"]);
        assert_eq!(cfg.community_groups[1].members, ["65000:2"]);
    }

    #[test]
    fn add_and_remove_member() {
        let mut cfg = Config {
            community_groups: vec![group("g1")],
            ..Default::default()
        };
        CommunityGroupOp::AddMember {
            name: "g1".to_string(),
            member: "65000:100".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.community_groups[0].members, vec!["65000:100"]);

        CommunityGroupOp::RemoveMember {
            name: "g1".to_string(),
            member: "65000:100".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.community_groups[0].members, [] as [String; 0]);
    }

    #[test]
    fn add_member_is_idempotent() {
        let mut cfg = Config {
            community_groups: vec![group("g1")],
            ..Default::default()
        };
        for _ in 0..2 {
            CommunityGroupOp::AddMember {
                name: "g1".to_string(),
                member: "65000:100".to_string(),
            }
            .apply(&mut cfg)
            .unwrap();
        }
        assert_eq!(cfg.community_groups[0].members.len(), 1);
    }

    #[test]
    fn remove_missing_member_errors() {
        let mut cfg = Config {
            community_groups: vec![group("g1")],
            ..Default::default()
        };
        let err = CommunityGroupOp::RemoveMember {
            name: "g1".to_string(),
            member: "65000:100".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::CommunityGroupMemberNotFound { name, member }
            if name == "g1" && member == "65000:100"
        ));
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            community_groups: vec![group("g1"), group("g2")],
            ..Default::default()
        };
        CommunityGroupOp::Delete {
            name: "g1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.community_groups.len(), 1);
        assert_eq!(cfg.community_groups[0].name, "g2");
    }

    #[test]
    fn delete_missing_group_errors() {
        let mut cfg = Config::default();
        let err = CommunityGroupOp::Delete {
            name: "g1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::CommunityGroupNotFound(n) if n == "g1"));
    }
}
