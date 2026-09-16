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
        name: String,
    },
    AddMember {
        name: String,
        member: String,
    },
    RemoveMember {
        name: String,
        member: String,
    },
    Delete {
        name: String,
    },
}

impl CommunityGroupOp {
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
        assert!(cfg.community_groups[0].members.is_empty());
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
        assert!(cfg.community_groups[0].members.is_empty());
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
