use serde::{Deserialize, Serialize};

use crate::schema::{BfdProfile, Config};

use super::OpError;

/// An edit to a named `BfdProfile`. Applied without validation — `garde`
/// only runs at commit, where a deleted-but-still-referenced profile is
/// reported once per user by `bfd_reference_valid`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BfdProfileOp {
    /// Creates the profile with defaults if missing; no-op otherwise.
    Ensure {
        name: String,
    },
    Delete {
        name: String,
    },
}

impl BfdProfileOp {
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            BfdProfileOp::Ensure { name } => {
                if !config.bfd_profiles.iter().any(|p| &p.name == name) {
                    config.bfd_profiles.push(BfdProfile {
                        name: name.clone(),
                        ..Default::default()
                    });
                }
                Ok(())
            }
            BfdProfileOp::Delete { name } => {
                let before = config.bfd_profiles.len();
                config.bfd_profiles.retain(|p| &p.name != name);
                if config.bfd_profiles.len() == before {
                    return Err(OpError::BfdProfileNotFound(name.clone()));
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_is_idempotent_and_delete_errors_when_missing() {
        let mut c = Config::default();
        let ensure = BfdProfileOp::Ensure { name: "a".into() };
        ensure.apply(&mut c).unwrap();
        ensure.apply(&mut c).unwrap();
        assert_eq!(c.bfd_profiles.len(), 1);
        let del = BfdProfileOp::Delete { name: "a".into() };
        del.apply(&mut c).unwrap();
        assert!(matches!(
            del.apply(&mut c),
            Err(OpError::BfdProfileNotFound(_))
        ));
    }
}
