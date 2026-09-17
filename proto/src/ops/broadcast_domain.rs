use serde::{Deserialize, Serialize};

use crate::schema::{BroadcastDomain, Config};

use super::OpError;

/// An edit to a single named `BroadcastDomain` within a transaction's
/// in-progress config. Applied without validation, matching every other
/// `Op`. No `Set*` variant — a broadcast domain has no field besides its
/// name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BroadcastDomainOp {
    /// Creates the domain if it doesn't already exist; no-op if it does.
    /// Backs `edit broadcast-domain <name>`'s "create if missing, else
    /// navigate to it" semantics.
    Ensure {
        name: String,
    },
    Delete {
        name: String,
    },
}

impl BroadcastDomainOp {
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            BroadcastDomainOp::Ensure { name } => {
                if !config.broadcast_domains.iter().any(|d| &d.name == name) {
                    config
                        .broadcast_domains
                        .push(BroadcastDomain { name: name.clone() });
                }
                Ok(())
            }
            BroadcastDomainOp::Delete { name } => {
                let before = config.broadcast_domains.len();
                config.broadcast_domains.retain(|d| &d.name != name);
                if config.broadcast_domains.len() == before {
                    return Err(OpError::BroadcastDomainNotFound(name.clone()));
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(name: &str) -> BroadcastDomain {
        BroadcastDomain {
            name: name.to_string(),
        }
    }

    #[test]
    fn ensure_creates_when_missing() {
        let mut cfg = Config::default();
        BroadcastDomainOp::Ensure {
            name: "bd1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.broadcast_domains.len(), 1);
        assert_eq!(cfg.broadcast_domains[0].name, "bd1");
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = Config {
            broadcast_domains: vec![domain("bd1")],
            ..Default::default()
        };
        BroadcastDomainOp::Ensure {
            name: "bd1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.broadcast_domains.len(), 1);
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            broadcast_domains: vec![domain("bd1"), domain("bd2")],
            ..Default::default()
        };
        BroadcastDomainOp::Delete {
            name: "bd1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.broadcast_domains.len(), 1);
        assert_eq!(cfg.broadcast_domains[0].name, "bd2");
    }

    #[test]
    fn delete_missing_domain_errors() {
        let mut cfg = Config::default();
        let err = BroadcastDomainOp::Delete {
            name: "bd1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::BroadcastDomainNotFound(n) if n == "bd1"));
    }
}
