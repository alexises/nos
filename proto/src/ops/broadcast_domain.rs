use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::schema::{BroadcastDomain, Config, InterfaceAddress};

use super::OpError;

/// An edit to a single named `BroadcastDomain` within a transaction's
/// in-progress config. Applied without validation, matching every other
/// `Op`. `addresses`/`routing_table` mirror `InterfaceOp`'s own address and
/// routing-table variants exactly — same upsert-by-address semantics for
/// `AddAddress`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BroadcastDomainOp {
    /// Creates the domain if it doesn't already exist; no-op if it does.
    /// Backs `edit broadcast-domain <name>`'s "create if missing, else
    /// navigate to it" semantics.
    Ensure {
        name: String,
    },
    /// Upserts by address: if `address` is already present on the domain,
    /// this replaces its label rather than adding a duplicate.
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
    Delete {
        name: String,
    },
}

impl BroadcastDomainOp {
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            BroadcastDomainOp::Ensure { name } => {
                if !config.broadcast_domains.iter().any(|d| &d.name == name) {
                    config.broadcast_domains.push(BroadcastDomain {
                        name: name.clone(),
                        addresses: Vec::new(),
                        routing_table: None,
                    });
                }
                Ok(())
            }
            BroadcastDomainOp::AddAddress {
                name,
                address,
                label,
            } => {
                let domain = find_domain_mut(config, name)?;
                match domain.addresses.iter_mut().find(|a| &a.address == address) {
                    Some(existing) => existing.label.clone_from(label),
                    None => domain.addresses.push(InterfaceAddress {
                        address: *address,
                        label: label.clone(),
                    }),
                }
                Ok(())
            }
            BroadcastDomainOp::RemoveAddress { name, address } => {
                let domain = find_domain_mut(config, name)?;
                let before = domain.addresses.len();
                domain.addresses.retain(|a| &a.address != address);
                if domain.addresses.len() == before {
                    return Err(OpError::BroadcastDomainAddressNotFound {
                        name: name.clone(),
                        address: *address,
                    });
                }
                Ok(())
            }
            BroadcastDomainOp::SetRoutingTable {
                name,
                routing_table,
            } => {
                find_domain_mut(config, name)?.routing_table = Some(routing_table.clone());
                Ok(())
            }
            BroadcastDomainOp::ClearRoutingTable { name } => {
                find_domain_mut(config, name)?.routing_table = None;
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

fn find_domain_mut<'a>(
    config: &'a mut Config,
    name: &str,
) -> Result<&'a mut BroadcastDomain, OpError> {
    config
        .broadcast_domains
        .iter_mut()
        .find(|d| d.name == name)
        .ok_or_else(|| OpError::BroadcastDomainNotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(name: &str) -> BroadcastDomain {
        BroadcastDomain {
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
    fn add_and_remove_address() {
        let mut cfg = Config {
            broadcast_domains: vec![domain("bd1")],
            ..Default::default()
        };
        BroadcastDomainOp::AddAddress {
            name: "bd1".to_string(),
            address: addr("10.0.0.1/24"),
            label: None,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.broadcast_domains[0].addresses.len(), 1);

        BroadcastDomainOp::RemoveAddress {
            name: "bd1".to_string(),
            address: addr("10.0.0.1/24"),
        }
        .apply(&mut cfg)
        .unwrap();
        assert!(cfg.broadcast_domains[0].addresses.is_empty());
    }

    #[test]
    fn add_address_upserts_label_on_existing_address() {
        let mut cfg = Config {
            broadcast_domains: vec![domain("bd1")],
            ..Default::default()
        };
        BroadcastDomainOp::AddAddress {
            name: "bd1".to_string(),
            address: addr("10.0.0.1/24"),
            label: Some("a".to_string()),
        }
        .apply(&mut cfg)
        .unwrap();
        BroadcastDomainOp::AddAddress {
            name: "bd1".to_string(),
            address: addr("10.0.0.1/24"),
            label: Some("b".to_string()),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.broadcast_domains[0].addresses.len(), 1);
        assert_eq!(
            cfg.broadcast_domains[0].addresses[0].label.as_deref(),
            Some("b")
        );
    }

    #[test]
    fn remove_missing_address_errors() {
        let mut cfg = Config {
            broadcast_domains: vec![domain("bd1")],
            ..Default::default()
        };
        let err = BroadcastDomainOp::RemoveAddress {
            name: "bd1".to_string(),
            address: addr("10.0.0.1/24"),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::BroadcastDomainAddressNotFound { name, address }
            if name == "bd1" && address == addr("10.0.0.1/24")
        ));
    }

    #[test]
    fn set_and_clear_routing_table() {
        let mut cfg = Config {
            broadcast_domains: vec![domain("bd1")],
            ..Default::default()
        };
        BroadcastDomainOp::SetRoutingTable {
            name: "bd1".to_string(),
            routing_table: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.broadcast_domains[0].routing_table.as_deref(),
            Some("rt1")
        );

        BroadcastDomainOp::ClearRoutingTable {
            name: "bd1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.broadcast_domains[0].routing_table, None);
    }

    #[test]
    fn set_routing_table_missing_domain_errors() {
        let mut cfg = Config::default();
        let err = BroadcastDomainOp::SetRoutingTable {
            name: "bd1".to_string(),
            routing_table: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::BroadcastDomainNotFound(n) if n == "bd1"));
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
