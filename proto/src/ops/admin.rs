use std::fmt;

use serde::{Deserialize, Serialize};

use crate::schema::{AdminKey, Config};

use super::OpError;

/// An edit to one labelled secret in `Config.admin`. Applied without
/// validation, like every other `Op`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminOp {
    /// Creates the key if missing, then sets its secret.
    SetKey {
        /// Label of the key.
        label: String,
        /// The secret, stored as given.
        secret: String,
    },
    /// Deletes the key.
    DeleteKey {
        /// Label of the key.
        label: String,
    },
}

// Manual `Debug`: ops are forwarded to `nos-logd` and printed in errors.
impl fmt::Debug for AdminOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdminOp::SetKey { label, .. } => f
                .debug_struct("SetKey")
                .field("label", label)
                .field("secret", &crate::cli::render::HIDDEN)
                .finish(),
            AdminOp::DeleteKey { label } => {
                f.debug_struct("DeleteKey").field("label", label).finish()
            }
        }
    }
}

impl AdminOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        let keys = &mut config.admin.keys;
        match self {
            AdminOp::SetKey { label, secret } => {
                if let Some(k) = keys.iter_mut().find(|k| &k.label == label) {
                    k.secret.clone_from(secret);
                } else {
                    keys.push(AdminKey {
                        label: label.clone(),
                        secret: secret.clone(),
                    });
                }
                Ok(())
            }
            AdminOp::DeleteKey { label } => {
                let before = keys.len();
                keys.retain(|k| &k.label != label);
                if keys.len() == before {
                    return Err(OpError::AdminKeyNotFound(label.clone()));
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(label: &str, secret: &str) -> AdminOp {
        AdminOp::SetKey {
            label: label.into(),
            secret: secret.into(),
        }
    }

    #[test]
    fn set_creates_then_updates() {
        let mut cfg = Config::default();
        set("a", "x").apply(&mut cfg).unwrap();
        set("a", "y").apply(&mut cfg).unwrap();
        assert_eq!(cfg.admin.keys.len(), 1);
        assert_eq!(cfg.key("a"), Some("y"));
    }

    #[test]
    fn delete_removes_and_missing_errors() {
        let mut cfg = Config::default();
        set("a", "x").apply(&mut cfg).unwrap();
        let del = AdminOp::DeleteKey { label: "a".into() };
        del.apply(&mut cfg).unwrap();
        assert_eq!(cfg.admin.keys, []);
        let err = del.apply(&mut cfg).unwrap_err();
        assert!(matches!(err, OpError::AdminKeyNotFound(l) if l == "a"));
    }

    #[test]
    fn debug_hides_secret() {
        let op = set("a", "hunter2");
        assert!(!format!("{op:?}").contains("hunter2"));
        assert!(!format!("{:?}", crate::ops::ConfigOp::Admin(op)).contains("hunter2"));
        assert!(format!("{:?}", AdminOp::DeleteKey { label: "a".into() }).contains("DeleteKey"));
    }
}
