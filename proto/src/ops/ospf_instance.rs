use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::schema::{Config, OspfInstance};

use super::OpError;

/// An edit to a single named `OspfInstance` within a transaction's
/// in-progress config. Applied without validation — `garde` validation only
/// runs at commit time, matching every other `Op`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OspfInstanceOp {
    /// Creates the instance with placeholder field values if it doesn't
    /// already exist by name; no-op if it does. Backs `edit ospf instance
    /// <name>`'s "create if missing, else navigate to it" semantics.
    Ensure {
        name: String,
    },
    SetRouterId {
        name: String,
        router_id: Ipv4Addr,
    },
    /// Sets (`Some`) or clears (`None`) the RFC 3623 grace period.
    SetGracefulRestartGracePeriod {
        name: String,
        grace_period: Option<u16>,
    },
    /// Turns RFC 6860 prefix suppression on or off.
    SetPrefixSuppression {
        name: String,
        enabled: bool,
    },
    Delete {
        name: String,
    },
}

impl OspfInstanceOp {
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            OspfInstanceOp::Ensure { name } => {
                if !config.ospf_instances.iter().any(|i| &i.name == name) {
                    config.ospf_instances.push(OspfInstance {
                        name: name.clone(),
                        router_id: Ipv4Addr::UNSPECIFIED,
                        areas: Vec::new(),
                        routing_table: None,
                        redistribute_policy: None,
                        graceful_restart_grace_period: None,
                        prefix_suppression: false,
                    });
                }
                Ok(())
            }
            OspfInstanceOp::SetRouterId { name, router_id } => {
                find_instance_mut(config, name)?.router_id = *router_id;
                Ok(())
            }
            OspfInstanceOp::SetGracefulRestartGracePeriod { name, grace_period } => {
                find_instance_mut(config, name)?.graceful_restart_grace_period = *grace_period;
                Ok(())
            }
            OspfInstanceOp::SetPrefixSuppression { name, enabled } => {
                find_instance_mut(config, name)?.prefix_suppression = *enabled;
                Ok(())
            }
            OspfInstanceOp::Delete { name } => {
                let before = config.ospf_instances.len();
                config.ospf_instances.retain(|i| &i.name != name);
                if config.ospf_instances.len() == before {
                    return Err(OpError::OspfInstanceNotFound(name.clone()));
                }
                Ok(())
            }
        }
    }
}

pub(crate) fn find_instance_mut<'a>(
    config: &'a mut Config,
    name: &str,
) -> Result<&'a mut OspfInstance, OpError> {
    config
        .ospf_instances
        .iter_mut()
        .find(|i| i.name == name)
        .ok_or_else(|| OpError::OspfInstanceNotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance(name: &str) -> OspfInstance {
        OspfInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            areas: Vec::new(),
            routing_table: None,
            redistribute_policy: None,
            graceful_restart_grace_period: None,
            prefix_suppression: false,
        }
    }

    #[test]
    fn set_prefix_suppression_toggles() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1")],
            ..Default::default()
        };
        let op = |enabled| OspfInstanceOp::SetPrefixSuppression {
            name: "o1".to_string(),
            enabled,
        };
        op(true).apply(&mut cfg).unwrap();
        assert!(cfg.ospf_instances[0].prefix_suppression);
        op(false).apply(&mut cfg).unwrap();
        assert!(!cfg.ospf_instances[0].prefix_suppression);
        let err = OspfInstanceOp::SetPrefixSuppression {
            name: "nope".to_string(),
            enabled: true,
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::OspfInstanceNotFound(n) if n == "nope"));
    }

    #[test]
    fn ensure_creates_placeholder_when_missing() {
        let mut cfg = Config::default();
        OspfInstanceOp::Ensure {
            name: "o1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances.len(), 1);
        assert_eq!(cfg.ospf_instances[0].name, "o1");
        assert_eq!(cfg.ospf_instances[0].router_id, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1")],
            ..Default::default()
        };
        OspfInstanceOp::Ensure {
            name: "o1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances.len(), 1);
        assert_eq!(cfg.ospf_instances[0].router_id, Ipv4Addr::new(1, 1, 1, 1));
    }

    #[test]
    fn set_router_id_updates_existing() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1")],
            ..Default::default()
        };
        OspfInstanceOp::SetRouterId {
            name: "o1".to_string(),
            router_id: Ipv4Addr::new(10, 0, 0, 1),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances[0].router_id, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn set_router_id_missing_instance_errors() {
        let mut cfg = Config::default();
        let err = OspfInstanceOp::SetRouterId {
            name: "o1".to_string(),
            router_id: Ipv4Addr::new(10, 0, 0, 1),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::OspfInstanceNotFound(n) if n == "o1"));
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1"), instance("o2")],
            ..Default::default()
        };
        OspfInstanceOp::Delete {
            name: "o1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances.len(), 1);
        assert_eq!(cfg.ospf_instances[0].name, "o2");
    }

    #[test]
    fn delete_missing_instance_errors() {
        let mut cfg = Config::default();
        let err = OspfInstanceOp::Delete {
            name: "o1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::OspfInstanceNotFound(n) if n == "o1"));
    }
}
