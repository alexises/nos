use serde::{Deserialize, Serialize};

use crate::schema::{CommunityAlias, Config};

use super::OpError;

/// An edit to a single named `CommunityAlias` within a transaction's
/// in-progress config. Applied without validation — `garde` validation only
/// runs at commit time, matching every other `Op`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommunityAliasOp {
    /// Creates the alias with an empty value if it doesn't already exist by
    /// name; no-op if it does. Backs `edit community-alias <name>`'s "create
    /// if missing, else navigate to it" semantics.
    Ensure {
        name: String,
    },
    SetValue {
        name: String,
        value: String,
    },
    Delete {
        name: String,
    },
}

impl CommunityAliasOp {
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            CommunityAliasOp::Ensure { name } => {
                if !config.community_aliases.iter().any(|a| &a.name == name) {
                    config.community_aliases.push(CommunityAlias {
                        name: name.clone(),
                        value: String::new(),
                    });
                }
                Ok(())
            }
            CommunityAliasOp::SetValue { name, value } => {
                find_alias_mut(config, name)?.value.clone_from(value);
                Ok(())
            }
            CommunityAliasOp::Delete { name } => {
                let before = config.community_aliases.len();
                config.community_aliases.retain(|a| &a.name != name);
                if config.community_aliases.len() == before {
                    return Err(OpError::CommunityAliasNotFound(name.clone()));
                }
                Ok(())
            }
        }
    }
}

fn find_alias_mut<'a>(
    config: &'a mut Config,
    name: &str,
) -> Result<&'a mut CommunityAlias, OpError> {
    config
        .community_aliases
        .iter_mut()
        .find(|a| a.name == name)
        .ok_or_else(|| OpError::CommunityAliasNotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alias(name: &str, value: &str) -> CommunityAlias {
        CommunityAlias {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn ensure_creates_when_missing() {
        let mut cfg = Config::default();
        CommunityAliasOp::Ensure {
            name: "a1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.community_aliases.len(), 1);
        assert_eq!(cfg.community_aliases[0].name, "a1");
        assert_eq!(cfg.community_aliases[0].value, "");
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = Config {
            community_aliases: vec![alias("a1", "65000:100")],
            ..Default::default()
        };
        CommunityAliasOp::Ensure {
            name: "a1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.community_aliases.len(), 1);
        assert_eq!(cfg.community_aliases[0].value, "65000:100");
    }

    #[test]
    fn set_value_updates_existing() {
        let mut cfg = Config {
            community_aliases: vec![alias("a1", "")],
            ..Default::default()
        };
        CommunityAliasOp::SetValue {
            name: "a1".to_string(),
            value: "65000:100".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.community_aliases[0].value, "65000:100");
    }

    #[test]
    fn set_value_missing_alias_errors() {
        let mut cfg = Config::default();
        let err = CommunityAliasOp::SetValue {
            name: "a1".to_string(),
            value: "65000:100".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::CommunityAliasNotFound(n) if n == "a1"));
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            community_aliases: vec![alias("a1", ""), alias("a2", "")],
            ..Default::default()
        };
        CommunityAliasOp::Delete {
            name: "a1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.community_aliases.len(), 1);
        assert_eq!(cfg.community_aliases[0].name, "a2");
    }

    #[test]
    fn delete_missing_alias_errors() {
        let mut cfg = Config::default();
        let err = CommunityAliasOp::Delete {
            name: "a1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::CommunityAliasNotFound(n) if n == "a1"));
    }
}
