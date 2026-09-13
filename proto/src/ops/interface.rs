use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::schema::{Config, Interface};

use super::OpError;

/// An edit to a single named `Interface` within a transaction's in-progress
/// config. Applied without validation — `garde` validation only runs at
/// commit time, matching every other `Op`. `addresses` has no `Ensure`/`SetX`
/// split since it's a plain list of scalars (not a keyed collection like
/// `StaticRoute`) — `AddAddress`/`RemoveAddress` mutate it directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterfaceOp {
    /// Creates the interface if it doesn't already exist; no-op if it does.
    /// Backs `edit interface <name>`'s "create if missing, else navigate to
    /// it" semantics.
    Ensure {
        name: String,
    },
    AddAddress {
        name: String,
        address: IpNet,
    },
    RemoveAddress {
        name: String,
        address: IpNet,
    },
    SetRoutingTable {
        name: String,
        routing_table: String,
    },
    ClearRoutingTable {
        name: String,
    },
    Delete {
        name: String,
    },
}

impl InterfaceOp {
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            InterfaceOp::Ensure { name } => {
                if !config.interfaces.iter().any(|i| &i.name == name) {
                    config.interfaces.push(Interface {
                        name: name.clone(),
                        addresses: Vec::new(),
                        routing_table: None,
                    });
                }
                Ok(())
            }
            InterfaceOp::AddAddress { name, address } => {
                let iface = find_interface_mut(config, name)?;
                if !iface.addresses.contains(address) {
                    iface.addresses.push(*address);
                }
                Ok(())
            }
            InterfaceOp::RemoveAddress { name, address } => {
                let iface = find_interface_mut(config, name)?;
                let before = iface.addresses.len();
                iface.addresses.retain(|a| a != address);
                if iface.addresses.len() == before {
                    return Err(OpError::InterfaceAddressNotFound {
                        name: name.clone(),
                        address: *address,
                    });
                }
                Ok(())
            }
            InterfaceOp::SetRoutingTable {
                name,
                routing_table,
            } => {
                find_interface_mut(config, name)?.routing_table = Some(routing_table.clone());
                Ok(())
            }
            InterfaceOp::ClearRoutingTable { name } => {
                find_interface_mut(config, name)?.routing_table = None;
                Ok(())
            }
            InterfaceOp::Delete { name } => {
                let before = config.interfaces.len();
                config.interfaces.retain(|i| &i.name != name);
                if config.interfaces.len() == before {
                    return Err(OpError::InterfaceNotFound(name.clone()));
                }
                Ok(())
            }
        }
    }
}

pub(crate) fn find_interface_mut<'a>(
    config: &'a mut Config,
    name: &str,
) -> Result<&'a mut Interface, OpError> {
    config
        .interfaces
        .iter_mut()
        .find(|i| i.name == name)
        .ok_or_else(|| OpError::InterfaceNotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interface(name: &str) -> Interface {
        Interface {
            name: name.to_string(),
            addresses: Vec::new(),
            routing_table: None,
        }
    }

    fn addr(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn ensure_creates_when_missing() {
        let mut cfg = Config::default();
        InterfaceOp::Ensure {
            name: "eth0".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces.len(), 1);
        assert_eq!(cfg.interfaces[0].name, "eth0");
        assert!(cfg.interfaces[0].addresses.is_empty());
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = Config {
            interfaces: vec![Interface {
                name: "eth0".to_string(),
                addresses: vec![addr("10.0.0.1/24")],
                routing_table: None,
            }],
            ..Default::default()
        };
        InterfaceOp::Ensure {
            name: "eth0".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces.len(), 1);
        assert_eq!(cfg.interfaces[0].addresses.len(), 1);
    }

    #[test]
    fn add_and_remove_address() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0")],
            ..Default::default()
        };
        InterfaceOp::AddAddress {
            name: "eth0".to_string(),
            address: addr("10.0.0.1/24"),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].addresses, vec![addr("10.0.0.1/24")]);

        InterfaceOp::RemoveAddress {
            name: "eth0".to_string(),
            address: addr("10.0.0.1/24"),
        }
        .apply(&mut cfg)
        .unwrap();
        assert!(cfg.interfaces[0].addresses.is_empty());
    }

    #[test]
    fn add_address_is_idempotent() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0")],
            ..Default::default()
        };
        for _ in 0..2 {
            InterfaceOp::AddAddress {
                name: "eth0".to_string(),
                address: addr("10.0.0.1/24"),
            }
            .apply(&mut cfg)
            .unwrap();
        }
        assert_eq!(cfg.interfaces[0].addresses.len(), 1);
    }

    #[test]
    fn remove_missing_address_errors() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0")],
            ..Default::default()
        };
        let err = InterfaceOp::RemoveAddress {
            name: "eth0".to_string(),
            address: addr("10.0.0.1/24"),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::InterfaceAddressNotFound { name, address }
            if name == "eth0" && address == addr("10.0.0.1/24")
        ));
    }

    #[test]
    fn set_and_clear_routing_table() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0")],
            ..Default::default()
        };
        InterfaceOp::SetRoutingTable {
            name: "eth0".to_string(),
            routing_table: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].routing_table.as_deref(), Some("rt1"));

        InterfaceOp::ClearRoutingTable {
            name: "eth0".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].routing_table, None);
    }

    #[test]
    fn set_routing_table_missing_interface_errors() {
        let mut cfg = Config::default();
        let err = InterfaceOp::SetRoutingTable {
            name: "eth0".to_string(),
            routing_table: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::InterfaceNotFound(n) if n == "eth0"));
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0"), interface("eth1")],
            ..Default::default()
        };
        InterfaceOp::Delete {
            name: "eth0".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces.len(), 1);
        assert_eq!(cfg.interfaces[0].name, "eth1");
    }

    #[test]
    fn delete_missing_interface_errors() {
        let mut cfg = Config::default();
        let err = InterfaceOp::Delete {
            name: "eth0".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::InterfaceNotFound(n) if n == "eth0"));
    }
}
