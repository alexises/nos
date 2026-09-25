use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::schema::{Config, Ospfv3Instance};

use super::OpError;

/// An edit to a single named `Ospfv3Instance` within a transaction's
/// in-progress config — mirrors `OspfInstanceOp` exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ospfv3InstanceOp {
    /// Creates the instance with placeholder field values if it doesn't
    /// already exist by name; no-op if it does. Backs `edit ospfv3 instance
    /// <name>`'s "create if missing, else navigate to it" semantics.
    Ensure {
        name: String,
    },
    SetRouterId {
        name: String,
        router_id: Ipv4Addr,
    },
    /// Turns RFC 8362 extended-LSA (Full mode) origination on or off.
    SetExtendedLsa {
        name: String,
        enabled: bool,
    },
    Delete {
        name: String,
    },
}

impl Ospfv3InstanceOp {
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            Ospfv3InstanceOp::Ensure { name } => {
                if !config.ospfv3_instances.iter().any(|i| &i.name == name) {
                    config.ospfv3_instances.push(Ospfv3Instance {
                        name: name.clone(),
                        router_id: Ipv4Addr::UNSPECIFIED,
                        areas: Vec::new(),
                        routing_table: None,
                        extended_lsa: false,
                    });
                }
                Ok(())
            }
            Ospfv3InstanceOp::SetRouterId { name, router_id } => {
                find_instance_mut(config, name)?.router_id = *router_id;
                Ok(())
            }
            Ospfv3InstanceOp::SetExtendedLsa { name, enabled } => {
                find_instance_mut(config, name)?.extended_lsa = *enabled;
                Ok(())
            }
            Ospfv3InstanceOp::Delete { name } => {
                let before = config.ospfv3_instances.len();
                config.ospfv3_instances.retain(|i| &i.name != name);
                if config.ospfv3_instances.len() == before {
                    return Err(OpError::Ospfv3InstanceNotFound(name.clone()));
                }
                Ok(())
            }
        }
    }
}

pub(crate) fn find_instance_mut<'a>(
    config: &'a mut Config,
    name: &str,
) -> Result<&'a mut Ospfv3Instance, OpError> {
    config
        .ospfv3_instances
        .iter_mut()
        .find(|i| i.name == name)
        .ok_or_else(|| OpError::Ospfv3InstanceNotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance(name: &str) -> Ospfv3Instance {
        Ospfv3Instance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            areas: Vec::new(),
            routing_table: None,
            extended_lsa: false,
        }
    }

    #[test]
    fn ensure_creates_placeholder_when_missing() {
        let mut cfg = Config::default();
        Ospfv3InstanceOp::Ensure {
            name: "o1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospfv3_instances.len(), 1);
        assert_eq!(cfg.ospfv3_instances[0].name, "o1");
        assert_eq!(cfg.ospfv3_instances[0].router_id, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = Config {
            ospfv3_instances: vec![instance("o1")],
            ..Default::default()
        };
        Ospfv3InstanceOp::Ensure {
            name: "o1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospfv3_instances.len(), 1);
        assert_eq!(cfg.ospfv3_instances[0].router_id, Ipv4Addr::new(1, 1, 1, 1));
    }

    #[test]
    fn set_router_id_updates_existing() {
        let mut cfg = Config {
            ospfv3_instances: vec![instance("o1")],
            ..Default::default()
        };
        Ospfv3InstanceOp::SetRouterId {
            name: "o1".to_string(),
            router_id: Ipv4Addr::new(10, 0, 0, 1),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospfv3_instances[0].router_id,
            Ipv4Addr::new(10, 0, 0, 1)
        );
    }

    #[test]
    fn set_extended_lsa_toggles() {
        let mut cfg = Config {
            ospfv3_instances: vec![instance("o1")],
            ..Default::default()
        };
        let op = |enabled| Ospfv3InstanceOp::SetExtendedLsa {
            name: "o1".to_string(),
            enabled,
        };
        op(true).apply(&mut cfg).unwrap();
        assert!(cfg.ospfv3_instances[0].extended_lsa);
        op(false).apply(&mut cfg).unwrap();
        assert!(!cfg.ospfv3_instances[0].extended_lsa);
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            ospfv3_instances: vec![instance("o1"), instance("o2")],
            ..Default::default()
        };
        Ospfv3InstanceOp::Delete {
            name: "o1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospfv3_instances.len(), 1);
        assert_eq!(cfg.ospfv3_instances[0].name, "o2");
    }

    #[test]
    fn delete_missing_instance_errors() {
        let mut cfg = Config::default();
        let err = Ospfv3InstanceOp::Delete {
            name: "o1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::Ospfv3InstanceNotFound(n) if n == "o1"));
    }
}
