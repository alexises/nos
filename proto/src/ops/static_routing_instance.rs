use serde::{Deserialize, Serialize};

use crate::schema::{Config, StaticRoutingInstance};

use super::OpError;

/// An edit to a single named `StaticRoutingInstance` within a transaction's
/// in-progress config. Applied without validation, matching every other
/// `Op`. No `Set*` variant — the section's only editable content besides its
/// name is its `routes` collection, handled entirely by `StaticRouteOp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StaticRoutingInstanceOp {
    /// Creates the instance if it doesn't already exist; no-op if it does.
    /// Backs `edit static-routing-instance <name>`'s "create if missing,
    /// else navigate to it" semantics.
    Ensure {
        name: String,
    },
    Delete {
        name: String,
    },
}

impl StaticRoutingInstanceOp {
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            StaticRoutingInstanceOp::Ensure { name } => {
                if !config
                    .static_routing_instances
                    .iter()
                    .any(|i| &i.name == name)
                {
                    config.static_routing_instances.push(StaticRoutingInstance {
                        name: name.clone(),
                        routes: Vec::new(),
                    });
                }
                Ok(())
            }
            StaticRoutingInstanceOp::Delete { name } => {
                let before = config.static_routing_instances.len();
                config.static_routing_instances.retain(|i| &i.name != name);
                if config.static_routing_instances.len() == before {
                    return Err(OpError::StaticRoutingInstanceNotFound(name.clone()));
                }
                Ok(())
            }
        }
    }
}

pub(crate) fn find_static_routing_instance_mut<'a>(
    config: &'a mut Config,
    name: &str,
) -> Result<&'a mut StaticRoutingInstance, OpError> {
    config
        .static_routing_instances
        .iter_mut()
        .find(|i| i.name == name)
        .ok_or_else(|| OpError::StaticRoutingInstanceNotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance(name: &str) -> StaticRoutingInstance {
        StaticRoutingInstance {
            name: name.to_string(),
            routes: Vec::new(),
        }
    }

    #[test]
    fn ensure_creates_when_missing() {
        let mut cfg = Config::default();
        StaticRoutingInstanceOp::Ensure {
            name: "sri1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.static_routing_instances.len(), 1);
        assert_eq!(cfg.static_routing_instances[0].name, "sri1");
        assert_eq!(cfg.static_routing_instances[0].routes, []);
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = Config {
            static_routing_instances: vec![instance("sri1")],
            ..Default::default()
        };
        StaticRoutingInstanceOp::Ensure {
            name: "sri1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.static_routing_instances.len(), 1);
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            static_routing_instances: vec![instance("sri1"), instance("sri2")],
            ..Default::default()
        };
        StaticRoutingInstanceOp::Delete {
            name: "sri1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.static_routing_instances.len(), 1);
        assert_eq!(cfg.static_routing_instances[0].name, "sri2");
    }

    #[test]
    fn delete_missing_instance_errors() {
        let mut cfg = Config::default();
        let err = StaticRoutingInstanceOp::Delete {
            name: "sri1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::StaticRoutingInstanceNotFound(n) if n == "sri1"));
    }
}
