use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::schema::{Config, InterfaceAddress, Subinterface};

use super::OpError;

/// An edit to a single `Subinterface` (keyed by `tag`) nested under a named
/// `PortAggregate`, within a transaction's in-progress config — the
/// `PortAggregate` counterpart of `SubinterfaceOp`, which is hard-wired to
/// `Config.interfaces`. Same cascading-create shape: `AddAddress`/
/// `SetRoutingTable`/etc. upsert the subinterface entry (creating it, but
/// *not* its parent `PortAggregate` — unlike `SubinterfaceOp`, an aggregate
/// is never implicitly created by editing one of its subinterfaces, since
/// `mode` has no sensible implicit default).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortAggregateSubinterfaceOp {
    Ensure {
        port_aggregate: String,
        tag: u16,
    },
    AddAddress {
        port_aggregate: String,
        tag: u16,
        address: IpNet,
        label: Option<String>,
    },
    RemoveAddress {
        port_aggregate: String,
        tag: u16,
        address: IpNet,
    },
    SetRoutingTable {
        port_aggregate: String,
        tag: u16,
        routing_table: String,
    },
    ClearRoutingTable {
        port_aggregate: String,
        tag: u16,
    },
    SetOspfProfile {
        port_aggregate: String,
        tag: u16,
        ospf_profile: String,
    },
    ClearOspfProfile {
        port_aggregate: String,
        tag: u16,
    },
    SetOspfv3Profile {
        port_aggregate: String,
        tag: u16,
        ospfv3_profile: String,
    },
    ClearOspfv3Profile {
        port_aggregate: String,
        tag: u16,
    },
    Delete {
        port_aggregate: String,
        tag: u16,
    },
}

impl PortAggregateSubinterfaceOp {
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            PortAggregateSubinterfaceOp::Ensure {
                port_aggregate,
                tag,
            } => {
                ensure_subinterface_mut(config, port_aggregate, *tag)?;
                Ok(())
            }
            PortAggregateSubinterfaceOp::AddAddress {
                port_aggregate,
                tag,
                address,
                label,
            } => {
                let sub = ensure_subinterface_mut(config, port_aggregate, *tag)?;
                match sub.addresses.iter_mut().find(|a| &a.address == address) {
                    Some(existing) => existing.label.clone_from(label),
                    None => sub.addresses.push(InterfaceAddress {
                        address: *address,
                        label: label.clone(),
                    }),
                }
                Ok(())
            }
            PortAggregateSubinterfaceOp::RemoveAddress {
                port_aggregate,
                tag,
                address,
            } => {
                let sub = find_subinterface_mut(config, port_aggregate, *tag)?;
                let before = sub.addresses.len();
                sub.addresses.retain(|a| &a.address != address);
                if sub.addresses.len() == before {
                    return Err(OpError::PortAggregateSubinterfaceAddressNotFound {
                        port_aggregate: port_aggregate.clone(),
                        tag: *tag,
                        address: *address,
                    });
                }
                Ok(())
            }
            PortAggregateSubinterfaceOp::SetRoutingTable {
                port_aggregate,
                tag,
                routing_table,
            } => {
                ensure_subinterface_mut(config, port_aggregate, *tag)?.routing_table =
                    Some(routing_table.clone());
                Ok(())
            }
            PortAggregateSubinterfaceOp::ClearRoutingTable {
                port_aggregate,
                tag,
            } => {
                find_subinterface_mut(config, port_aggregate, *tag)?.routing_table = None;
                Ok(())
            }
            PortAggregateSubinterfaceOp::SetOspfProfile {
                port_aggregate,
                tag,
                ospf_profile,
            } => {
                ensure_subinterface_mut(config, port_aggregate, *tag)?.ospf_profile =
                    Some(ospf_profile.clone());
                Ok(())
            }
            PortAggregateSubinterfaceOp::ClearOspfProfile {
                port_aggregate,
                tag,
            } => {
                find_subinterface_mut(config, port_aggregate, *tag)?.ospf_profile = None;
                Ok(())
            }
            PortAggregateSubinterfaceOp::SetOspfv3Profile {
                port_aggregate,
                tag,
                ospfv3_profile,
            } => {
                ensure_subinterface_mut(config, port_aggregate, *tag)?.ospfv3_profile =
                    Some(ospfv3_profile.clone());
                Ok(())
            }
            PortAggregateSubinterfaceOp::ClearOspfv3Profile {
                port_aggregate,
                tag,
            } => {
                find_subinterface_mut(config, port_aggregate, *tag)?.ospfv3_profile = None;
                Ok(())
            }
            PortAggregateSubinterfaceOp::Delete {
                port_aggregate,
                tag,
            } => {
                let agg = find_aggregate_mut(config, port_aggregate)?;
                let before = agg.subinterfaces.len();
                agg.subinterfaces.retain(|s| s.tag != *tag);
                if agg.subinterfaces.len() == before {
                    return Err(OpError::PortAggregateSubinterfaceNotFound {
                        port_aggregate: port_aggregate.clone(),
                        tag: *tag,
                    });
                }
                Ok(())
            }
        }
    }
}

fn find_aggregate_mut<'a>(
    config: &'a mut Config,
    name: &str,
) -> Result<&'a mut crate::schema::PortAggregate, OpError> {
    config
        .port_aggregates
        .iter_mut()
        .find(|a| a.name == name)
        .ok_or_else(|| OpError::PortAggregateNotFound(name.to_string()))
}

fn find_subinterface_mut<'a>(
    config: &'a mut Config,
    port_aggregate: &str,
    tag: u16,
) -> Result<&'a mut Subinterface, OpError> {
    find_aggregate_mut(config, port_aggregate)?
        .subinterfaces
        .iter_mut()
        .find(|s| s.tag == tag)
        .ok_or_else(|| OpError::PortAggregateSubinterfaceNotFound {
            port_aggregate: port_aggregate.to_string(),
            tag,
        })
}

/// Finds the subinterface, creating it if missing — but requires the parent
/// `PortAggregate` to already exist (unlike `subinterface::ensure_subinterface_mut`,
/// which also cascade-creates the parent `Interface`).
fn ensure_subinterface_mut<'a>(
    config: &'a mut Config,
    port_aggregate: &str,
    tag: u16,
) -> Result<&'a mut Subinterface, OpError> {
    let agg = find_aggregate_mut(config, port_aggregate)?;
    if !agg.subinterfaces.iter().any(|s| s.tag == tag) {
        agg.subinterfaces.push(Subinterface {
            tag,
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
            ospfv3_profile: None,
        });
    }
    Ok(agg.subinterfaces.iter_mut().find(|s| s.tag == tag).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{PortAggregate, PortAggregateMode};

    fn aggregate(name: &str, subinterfaces: Vec<Subinterface>) -> PortAggregate {
        PortAggregate {
            name: name.to_string(),
            mode: PortAggregateMode::Xor,
            lacp_rate: crate::schema::LacpRate::default(),
            esi: None,
            lacp_system_id: None,
            switching_profile: None,
            mtu: None,
            subinterfaces,
        }
    }

    fn addr(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn ensure_creates_subinterface_on_existing_aggregate() {
        let mut cfg = Config {
            port_aggregates: vec![aggregate("bond1", vec![])],
            ..Default::default()
        };
        PortAggregateSubinterfaceOp::Ensure {
            port_aggregate: "bond1".to_string(),
            tag: 100,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.port_aggregates[0].subinterfaces.len(), 1);
        assert_eq!(cfg.port_aggregates[0].subinterfaces[0].tag, 100);
    }

    #[test]
    fn ensure_missing_aggregate_errors() {
        let mut cfg = Config::default();
        let err = PortAggregateSubinterfaceOp::Ensure {
            port_aggregate: "bond1".to_string(),
            tag: 100,
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::PortAggregateNotFound(n) if n == "bond1"));
    }

    #[test]
    fn add_address_upserts_label_on_existing_address() {
        let mut cfg = Config {
            port_aggregates: vec![aggregate("bond1", vec![])],
            ..Default::default()
        };
        PortAggregateSubinterfaceOp::AddAddress {
            port_aggregate: "bond1".to_string(),
            tag: 0,
            address: addr("10.0.0.1/24"),
            label: Some("a".to_string()),
        }
        .apply(&mut cfg)
        .unwrap();
        PortAggregateSubinterfaceOp::AddAddress {
            port_aggregate: "bond1".to_string(),
            tag: 0,
            address: addr("10.0.0.1/24"),
            label: Some("b".to_string()),
        }
        .apply(&mut cfg)
        .unwrap();
        let sub = &cfg.port_aggregates[0].subinterfaces[0];
        assert_eq!(sub.addresses.len(), 1);
        assert_eq!(sub.addresses[0].label.as_deref(), Some("b"));
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            port_aggregates: vec![aggregate(
                "bond1",
                vec![Subinterface {
                    tag: 100,
                    addresses: Vec::new(),
                    routing_table: None,
                    ospf_profile: None,
                    ospfv3_profile: None,
                }],
            )],
            ..Default::default()
        };
        PortAggregateSubinterfaceOp::Delete {
            port_aggregate: "bond1".to_string(),
            tag: 100,
        }
        .apply(&mut cfg)
        .unwrap();
        assert!(cfg.port_aggregates[0].subinterfaces.is_empty());
    }

    #[test]
    fn delete_missing_subinterface_errors() {
        let mut cfg = Config {
            port_aggregates: vec![aggregate("bond1", vec![])],
            ..Default::default()
        };
        let err = PortAggregateSubinterfaceOp::Delete {
            port_aggregate: "bond1".to_string(),
            tag: 0,
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::PortAggregateSubinterfaceNotFound { port_aggregate, tag }
            if port_aggregate == "bond1" && tag == 0
        ));
    }
}
