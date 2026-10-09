use serde::{Deserialize, Serialize};

use crate::schema::{Config, StpPortProfile};

use super::OpError;

/// An edit to a named `StpPortProfile`. Applied without validation — `garde`
/// only runs at commit, where a deleted-but-still-referenced profile is
/// reported once per user by `stp_port_profile_reference_valid`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StpPortProfileOp {
    /// Creates the profile with defaults if missing; no-op otherwise.
    Ensure {
        name: String,
    },
    Delete {
        name: String,
    },
}

impl StpPortProfileOp {
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            StpPortProfileOp::Ensure { name } => {
                if !config.stp_port_profiles.iter().any(|p| &p.name == name) {
                    config.stp_port_profiles.push(StpPortProfile {
                        name: name.clone(),
                        ..Default::default()
                    });
                }
                Ok(())
            }
            StpPortProfileOp::Delete { name } => {
                let before = config.stp_port_profiles.len();
                config.stp_port_profiles.retain(|p| &p.name != name);
                if config.stp_port_profiles.len() == before {
                    return Err(OpError::StpPortProfileNotFound(name.clone()));
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
        let ensure = StpPortProfileOp::Ensure { name: "a".into() };
        ensure.apply(&mut c).unwrap();
        ensure.apply(&mut c).unwrap();
        assert_eq!(c.stp_port_profiles.len(), 1);
        let del = StpPortProfileOp::Delete { name: "a".into() };
        del.apply(&mut c).unwrap();
        assert!(matches!(
            del.apply(&mut c),
            Err(OpError::StpPortProfileNotFound(_))
        ));
    }
}
