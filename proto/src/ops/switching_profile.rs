use serde::{Deserialize, Serialize};

use crate::schema::{Config, SwitchingProfile, SwitchingProfileMember, VlanTag};

use super::OpError;

/// An edit to a single named `SwitchingProfile` within a transaction's
/// in-progress config. Applied without validation, matching every other
/// `Op`. `AddMember`/`RemoveMember` are keyed by `broadcast_domain`, the
/// same nested-upsert shape as `StaticRouteOp` keyed by `subnet` under a
/// `StaticRoutingInstance`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SwitchingProfileOp {
    /// Creates the profile if it doesn't already exist; no-op if it does.
    /// Backs `edit switching-profile <name>`'s "create if missing, else
    /// navigate to it" semantics.
    Ensure {
        name: String,
    },
    /// Upserts by `broadcast_domain` — a repeat `AddMember` for the same
    /// domain replaces its tag, mirroring `InterfaceOp::AddAddress`'s
    /// upsert-by-`address` semantics.
    AddMember {
        name: String,
        broadcast_domain: String,
        tag: VlanTag,
    },
    RemoveMember {
        name: String,
        broadcast_domain: String,
    },
    Delete {
        name: String,
    },
}

impl SwitchingProfileOp {
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            SwitchingProfileOp::Ensure { name } => {
                if !config.switching_profiles.iter().any(|p| &p.name == name) {
                    config.switching_profiles.push(SwitchingProfile {
                        name: name.clone(),
                        members: Vec::new(),
                    });
                }
                Ok(())
            }
            SwitchingProfileOp::AddMember {
                name,
                broadcast_domain,
                tag,
            } => {
                let profile = find_profile_mut(config, name)?;
                match profile
                    .members
                    .iter_mut()
                    .find(|m| &m.broadcast_domain == broadcast_domain)
                {
                    Some(member) => member.tag = *tag,
                    None => profile.members.push(SwitchingProfileMember {
                        broadcast_domain: broadcast_domain.clone(),
                        tag: *tag,
                        stp_cost: None,
                        stp_priority: None,
                    }),
                }
                Ok(())
            }
            SwitchingProfileOp::RemoveMember {
                name,
                broadcast_domain,
            } => {
                let profile = find_profile_mut(config, name)?;
                let before = profile.members.len();
                profile
                    .members
                    .retain(|m| &m.broadcast_domain != broadcast_domain);
                if profile.members.len() == before {
                    return Err(OpError::SwitchingProfileMemberNotFound {
                        name: name.clone(),
                        broadcast_domain: broadcast_domain.clone(),
                    });
                }
                Ok(())
            }
            SwitchingProfileOp::Delete { name } => {
                let before = config.switching_profiles.len();
                config.switching_profiles.retain(|p| &p.name != name);
                if config.switching_profiles.len() == before {
                    return Err(OpError::SwitchingProfileNotFound(name.clone()));
                }
                Ok(())
            }
        }
    }
}

fn find_profile_mut<'a>(
    config: &'a mut Config,
    name: &str,
) -> Result<&'a mut SwitchingProfile, OpError> {
    config
        .switching_profiles
        .iter_mut()
        .find(|p| p.name == name)
        .ok_or_else(|| OpError::SwitchingProfileNotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str, members: Vec<SwitchingProfileMember>) -> SwitchingProfile {
        SwitchingProfile {
            name: name.to_string(),
            members,
        }
    }

    #[test]
    fn ensure_creates_when_missing() {
        let mut cfg = Config::default();
        SwitchingProfileOp::Ensure {
            name: "sp1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.switching_profiles.len(), 1);
        assert_eq!(cfg.switching_profiles[0].name, "sp1");
        assert_eq!(cfg.switching_profiles[0].members, []);
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = Config {
            switching_profiles: vec![profile("sp1", vec![])],
            ..Default::default()
        };
        SwitchingProfileOp::Ensure {
            name: "sp1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.switching_profiles.len(), 1);
    }

    #[test]
    fn add_member_creates_when_missing() {
        let mut cfg = Config {
            switching_profiles: vec![profile("sp1", vec![])],
            ..Default::default()
        };
        SwitchingProfileOp::AddMember {
            name: "sp1".to_string(),
            broadcast_domain: "bd1".to_string(),
            tag: VlanTag::Dot1q(100),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.switching_profiles[0].members.len(), 1);
        assert_eq!(
            cfg.switching_profiles[0].members[0].tag,
            VlanTag::Dot1q(100)
        );
    }

    #[test]
    fn add_member_upserts_existing_domain() {
        let mut cfg = Config {
            switching_profiles: vec![profile(
                "sp1",
                vec![SwitchingProfileMember {
                    broadcast_domain: "bd1".to_string(),
                    tag: VlanTag::Dot1q(100),
                    ..Default::default()
                }],
            )],
            ..Default::default()
        };
        SwitchingProfileOp::AddMember {
            name: "sp1".to_string(),
            broadcast_domain: "bd1".to_string(),
            tag: VlanTag::Untagged,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.switching_profiles[0].members.len(), 1);
        assert_eq!(cfg.switching_profiles[0].members[0].tag, VlanTag::Untagged);
    }

    #[test]
    fn add_member_missing_profile_errors() {
        let mut cfg = Config::default();
        let err = SwitchingProfileOp::AddMember {
            name: "sp1".to_string(),
            broadcast_domain: "bd1".to_string(),
            tag: VlanTag::Untagged,
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::SwitchingProfileNotFound(n) if n == "sp1"));
    }

    #[test]
    fn remove_member_removes_existing() {
        let mut cfg = Config {
            switching_profiles: vec![profile(
                "sp1",
                vec![SwitchingProfileMember {
                    broadcast_domain: "bd1".to_string(),
                    tag: VlanTag::Dot1q(100),
                    ..Default::default()
                }],
            )],
            ..Default::default()
        };
        SwitchingProfileOp::RemoveMember {
            name: "sp1".to_string(),
            broadcast_domain: "bd1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.switching_profiles[0].members, []);
    }

    #[test]
    fn remove_member_missing_errors() {
        let mut cfg = Config {
            switching_profiles: vec![profile("sp1", vec![])],
            ..Default::default()
        };
        let err = SwitchingProfileOp::RemoveMember {
            name: "sp1".to_string(),
            broadcast_domain: "bd1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::SwitchingProfileMemberNotFound { name, broadcast_domain }
            if name == "sp1" && broadcast_domain == "bd1"
        ));
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            switching_profiles: vec![profile("sp1", vec![]), profile("sp2", vec![])],
            ..Default::default()
        };
        SwitchingProfileOp::Delete {
            name: "sp1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.switching_profiles.len(), 1);
        assert_eq!(cfg.switching_profiles[0].name, "sp2");
    }

    #[test]
    fn delete_missing_profile_errors() {
        let mut cfg = Config::default();
        let err = SwitchingProfileOp::Delete {
            name: "sp1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::SwitchingProfileNotFound(n) if n == "sp1"));
    }
}
