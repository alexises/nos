use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::schema::{Config, Interface, InterfaceAddress};

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
    /// it" semantics. A loopback interface is created the same way, simply
    /// by using a `loopback-<table>`-prefixed name (see
    /// `schema::LOOPBACK_PREFIX`) — there is no separate op for it.
    Ensure {
        name: String,
    },
    /// Upserts by address: if `address` is already present on the
    /// interface, this replaces its label rather than adding a duplicate —
    /// re-running `set interface <name> address <addr> label <label>` is
    /// how a label is changed or cleared.
    AddAddress {
        name: String,
        address: IpNet,
        label: Option<String>,
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
    SetOspfProfile {
        name: String,
        ospf_profile: String,
    },
    ClearOspfProfile {
        name: String,
    },
    SetSwitchingProfile {
        name: String,
        switching_profile: String,
    },
    ClearSwitchingProfile {
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
                        ospf_profile: None,
                        switching_profile: None,
                        subinterfaces: Vec::new(),
                    });
                }
                Ok(())
            }
            InterfaceOp::AddAddress {
                name,
                address,
                label,
            } => {
                let iface = find_interface_mut(config, name)?;
                match iface.addresses.iter_mut().find(|a| &a.address == address) {
                    Some(existing) => existing.label.clone_from(label),
                    None => iface.addresses.push(InterfaceAddress {
                        address: *address,
                        label: label.clone(),
                    }),
                }
                Ok(())
            }
            InterfaceOp::RemoveAddress { name, address } => {
                let iface = find_interface_mut(config, name)?;
                let before = iface.addresses.len();
                iface.addresses.retain(|a| &a.address != address);
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
            InterfaceOp::SetOspfProfile { name, ospf_profile } => {
                find_interface_mut(config, name)?.ospf_profile = Some(ospf_profile.clone());
                Ok(())
            }
            InterfaceOp::ClearOspfProfile { name } => {
                find_interface_mut(config, name)?.ospf_profile = None;
                Ok(())
            }
            InterfaceOp::SetSwitchingProfile {
                name,
                switching_profile,
            } => {
                find_interface_mut(config, name)?.switching_profile =
                    Some(switching_profile.clone());
                Ok(())
            }
            InterfaceOp::ClearSwitchingProfile { name } => {
                find_interface_mut(config, name)?.switching_profile = None;
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
            ospf_profile: None,
            switching_profile: None,
            subinterfaces: Vec::new(),
        }
    }

    fn addr(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn iface_addr(s: &str) -> InterfaceAddress {
        InterfaceAddress {
            address: addr(s),
            label: None,
        }
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
                addresses: vec![iface_addr("10.0.0.1/24")],
                routing_table: None,
                ospf_profile: None,
                switching_profile: None,
                subinterfaces: Vec::new(),
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
            label: None,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].addresses, vec![iface_addr("10.0.0.1/24")]);

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
                label: None,
            }
            .apply(&mut cfg)
            .unwrap();
        }
        assert_eq!(cfg.interfaces[0].addresses.len(), 1);
    }

    #[test]
    fn add_address_with_label() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0")],
            ..Default::default()
        };
        InterfaceOp::AddAddress {
            name: "eth0".to_string(),
            address: addr("10.0.0.1/24"),
            label: Some("mgmt".to_string()),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.interfaces[0].addresses[0].label.as_deref(),
            Some("mgmt")
        );
    }

    #[test]
    fn add_address_upserts_label_on_existing_address() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0")],
            ..Default::default()
        };
        InterfaceOp::AddAddress {
            name: "eth0".to_string(),
            address: addr("10.0.0.1/24"),
            label: Some("a".to_string()),
        }
        .apply(&mut cfg)
        .unwrap();
        InterfaceOp::AddAddress {
            name: "eth0".to_string(),
            address: addr("10.0.0.1/24"),
            label: Some("b".to_string()),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].addresses.len(), 1);
        assert_eq!(cfg.interfaces[0].addresses[0].label.as_deref(), Some("b"));
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
    fn set_and_clear_ospf_profile() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0")],
            ..Default::default()
        };
        InterfaceOp::SetOspfProfile {
            name: "eth0".to_string(),
            ospf_profile: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].ospf_profile.as_deref(), Some("p1"));

        InterfaceOp::ClearOspfProfile {
            name: "eth0".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].ospf_profile, None);
    }

    #[test]
    fn set_and_clear_switching_profile() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0")],
            ..Default::default()
        };
        InterfaceOp::SetSwitchingProfile {
            name: "eth0".to_string(),
            switching_profile: "sp1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].switching_profile.as_deref(), Some("sp1"));

        InterfaceOp::ClearSwitchingProfile {
            name: "eth0".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].switching_profile, None);
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
