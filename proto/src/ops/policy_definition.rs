use serde::{Deserialize, Serialize};

use crate::schema::{Config, PolicyDefinition};

use super::OpError;

/// An edit to a single named `PolicyDefinition` within a transaction's
/// in-progress config. Applied without validation — `garde` validation
/// (including running the real RPL compiler on `source`) only runs at
/// commit time, matching every other `Op`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDefinitionOp {
    /// Creates the policy with an empty source if it doesn't already exist
    /// by name; no-op if it does. Backs `edit policy-definition <name>`'s
    /// "create if missing, else navigate to it" semantics.
    Ensure {
        name: String,
    },
    SetSource {
        name: String,
        source: String,
    },
    Delete {
        name: String,
    },
}

impl PolicyDefinitionOp {
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            PolicyDefinitionOp::Ensure { name } => {
                if !config.policy_definitions.iter().any(|p| &p.name == name) {
                    config.policy_definitions.push(PolicyDefinition {
                        name: name.clone(),
                        source: String::new(),
                    });
                }
                Ok(())
            }
            PolicyDefinitionOp::SetSource { name, source } => {
                find_policy_mut(config, name)?.source.clone_from(source);
                Ok(())
            }
            PolicyDefinitionOp::Delete { name } => {
                let before = config.policy_definitions.len();
                config.policy_definitions.retain(|p| &p.name != name);
                if config.policy_definitions.len() == before {
                    return Err(OpError::PolicyDefinitionNotFound(name.clone()));
                }
                Ok(())
            }
        }
    }
}

pub(crate) fn find_policy_mut<'a>(
    config: &'a mut Config,
    name: &str,
) -> Result<&'a mut PolicyDefinition, OpError> {
    config
        .policy_definitions
        .iter_mut()
        .find(|p| p.name == name)
        .ok_or_else(|| OpError::PolicyDefinitionNotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(name: &str, source: &str) -> PolicyDefinition {
        PolicyDefinition {
            name: name.to_string(),
            source: source.to_string(),
        }
    }

    #[test]
    fn ensure_creates_when_missing() {
        let mut cfg = Config::default();
        PolicyDefinitionOp::Ensure {
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.policy_definitions.len(), 1);
        assert_eq!(cfg.policy_definitions[0].name, "p1");
        assert_eq!(cfg.policy_definitions[0].source, "");
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = Config {
            policy_definitions: vec![policy("p1", "accept\n")],
            ..Default::default()
        };
        PolicyDefinitionOp::Ensure {
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.policy_definitions.len(), 1);
        assert_eq!(cfg.policy_definitions[0].source, "accept\n");
    }

    #[test]
    fn set_source_updates_existing() {
        let mut cfg = Config {
            policy_definitions: vec![policy("p1", "")],
            ..Default::default()
        };
        PolicyDefinitionOp::SetSource {
            name: "p1".to_string(),
            source: "accept\n".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.policy_definitions[0].source, "accept\n");
    }

    #[test]
    fn set_source_missing_policy_errors() {
        let mut cfg = Config::default();
        let err = PolicyDefinitionOp::SetSource {
            name: "p1".to_string(),
            source: "accept\n".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::PolicyDefinitionNotFound(n) if n == "p1"));
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            policy_definitions: vec![policy("p1", ""), policy("p2", "")],
            ..Default::default()
        };
        PolicyDefinitionOp::Delete {
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.policy_definitions.len(), 1);
        assert_eq!(cfg.policy_definitions[0].name, "p2");
    }

    #[test]
    fn delete_missing_policy_errors() {
        let mut cfg = Config::default();
        let err = PolicyDefinitionOp::Delete {
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::PolicyDefinitionNotFound(n) if n == "p1"));
    }
}
