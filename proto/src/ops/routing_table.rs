use serde::{Deserialize, Serialize};

use crate::schema::{Config, Redistribute, RoutingTable};

use super::OpError;

/// An edit to a single named `RoutingTable` within a transaction's
/// in-progress config. Applied without validation — `garde` validation only
/// runs at commit time, matching every other `Op`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoutingTableOp {
    /// Creates the table if it doesn't already exist; no-op if it does.
    /// Backs `edit routing-table <name>`'s "create if missing, else
    /// navigate to it" semantics.
    Ensure {
        name: String,
    },
    SetBgpInstance {
        name: String,
        bgp_instance: String,
    },
    ClearBgpInstance {
        name: String,
    },
    SetStaticRoutingInstance {
        name: String,
        static_routing_instance: String,
    },
    ClearStaticRoutingInstance {
        name: String,
    },
    SetRedistribute {
        name: String,
        redistribute: Redistribute,
    },
    ClearRedistribute {
        name: String,
    },
    Delete {
        name: String,
    },
    SetOspfInstance {
        name: String,
        ospf_instance: String,
    },
    ClearOspfInstance {
        name: String,
    },
    SetOspfv3Instance {
        name: String,
        ospfv3_instance: String,
    },
    ClearOspfv3Instance {
        name: String,
    },
}

impl RoutingTableOp {
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            RoutingTableOp::Ensure { name } => {
                if !config.routing_tables.iter().any(|t| &t.name == name) {
                    config.routing_tables.push(RoutingTable {
                        name: name.clone(),
                        bgp_instance: None,
                        ospf_instance: None,
                        ospfv3_instance: None,
                        static_routing_instance: None,
                        redistribute: None,
                    });
                }
                Ok(())
            }
            RoutingTableOp::SetBgpInstance { name, bgp_instance } => {
                find_table_mut(config, name)?.bgp_instance = Some(bgp_instance.clone());
                Ok(())
            }
            RoutingTableOp::ClearBgpInstance { name } => {
                find_table_mut(config, name)?.bgp_instance = None;
                Ok(())
            }
            RoutingTableOp::SetStaticRoutingInstance {
                name,
                static_routing_instance,
            } => {
                find_table_mut(config, name)?.static_routing_instance =
                    Some(static_routing_instance.clone());
                Ok(())
            }
            RoutingTableOp::ClearStaticRoutingInstance { name } => {
                find_table_mut(config, name)?.static_routing_instance = None;
                Ok(())
            }
            RoutingTableOp::SetRedistribute { name, redistribute } => {
                find_table_mut(config, name)?.redistribute = Some(redistribute.clone());
                Ok(())
            }
            RoutingTableOp::ClearRedistribute { name } => {
                find_table_mut(config, name)?.redistribute = None;
                Ok(())
            }
            RoutingTableOp::Delete { name } => {
                let before = config.routing_tables.len();
                config.routing_tables.retain(|t| &t.name != name);
                if config.routing_tables.len() == before {
                    return Err(OpError::RoutingTableNotFound(name.clone()));
                }
                Ok(())
            }
            RoutingTableOp::SetOspfInstance {
                name,
                ospf_instance,
            } => {
                find_table_mut(config, name)?.ospf_instance = Some(ospf_instance.clone());
                Ok(())
            }
            RoutingTableOp::ClearOspfInstance { name } => {
                find_table_mut(config, name)?.ospf_instance = None;
                Ok(())
            }
            RoutingTableOp::SetOspfv3Instance {
                name,
                ospfv3_instance,
            } => {
                find_table_mut(config, name)?.ospfv3_instance = Some(ospfv3_instance.clone());
                Ok(())
            }
            RoutingTableOp::ClearOspfv3Instance { name } => {
                find_table_mut(config, name)?.ospfv3_instance = None;
                Ok(())
            }
        }
    }
}

pub(crate) fn find_table_mut<'a>(
    config: &'a mut Config,
    name: &str,
) -> Result<&'a mut RoutingTable, OpError> {
    config
        .routing_tables
        .iter_mut()
        .find(|t| t.name == name)
        .ok_or_else(|| OpError::RoutingTableNotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(name: &str) -> RoutingTable {
        RoutingTable {
            ospfv3_instance: None,
            name: name.to_string(),
            bgp_instance: None,
            ospf_instance: None,
            static_routing_instance: None,
            redistribute: None,
        }
    }

    #[test]
    fn ensure_creates_when_missing() {
        let mut cfg = Config::default();
        RoutingTableOp::Ensure {
            name: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables.len(), 1);
        assert_eq!(cfg.routing_tables[0].name, "rt1");
        assert_eq!(cfg.routing_tables[0].bgp_instance, None);
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = Config {
            routing_tables: vec![RoutingTable {
                ospfv3_instance: None,
                name: "rt1".to_string(),
                bgp_instance: Some("r1".to_string()),
                ospf_instance: None,
                static_routing_instance: None,
                redistribute: None,
            }],
            ..Default::default()
        };
        RoutingTableOp::Ensure {
            name: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables.len(), 1);
        assert_eq!(cfg.routing_tables[0].bgp_instance.as_deref(), Some("r1"));
    }

    #[test]
    fn set_and_clear_bgp_instance() {
        let mut cfg = Config {
            routing_tables: vec![table("rt1")],
            ..Default::default()
        };
        RoutingTableOp::SetBgpInstance {
            name: "rt1".to_string(),
            bgp_instance: "r1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables[0].bgp_instance.as_deref(), Some("r1"));

        RoutingTableOp::ClearBgpInstance {
            name: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables[0].bgp_instance, None);
    }

    #[test]
    fn set_and_clear_static_routing_instance() {
        let mut cfg = Config {
            routing_tables: vec![table("rt1")],
            ..Default::default()
        };
        RoutingTableOp::SetStaticRoutingInstance {
            name: "rt1".to_string(),
            static_routing_instance: "sri1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.routing_tables[0].static_routing_instance.as_deref(),
            Some("sri1")
        );

        RoutingTableOp::ClearStaticRoutingInstance {
            name: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables[0].static_routing_instance, None);
    }

    #[test]
    fn set_and_clear_ospf_instance() {
        let mut cfg = Config {
            routing_tables: vec![table("rt1")],
            ..Default::default()
        };
        RoutingTableOp::SetOspfInstance {
            name: "rt1".to_string(),
            ospf_instance: "o1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables[0].ospf_instance.as_deref(), Some("o1"));

        RoutingTableOp::ClearOspfInstance {
            name: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables[0].ospf_instance, None);
    }

    #[test]
    fn set_and_clear_redistribute() {
        use crate::schema::{RedistributeSource, RedistributeTarget};

        let mut cfg = Config {
            routing_tables: vec![table("rt1")],
            ..Default::default()
        };
        RoutingTableOp::SetRedistribute {
            name: "rt1".to_string(),
            redistribute: Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Bgp,
                policy: None,
            },
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.routing_tables[0].redistribute,
            Some(Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Bgp,
                policy: None,
            })
        );

        RoutingTableOp::ClearRedistribute {
            name: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables[0].redistribute, None);
    }

    #[test]
    fn set_redistribute_with_policy() {
        use crate::schema::{RedistributeSource, RedistributeTarget};

        let mut cfg = Config {
            routing_tables: vec![table("rt1")],
            ..Default::default()
        };
        RoutingTableOp::SetRedistribute {
            name: "rt1".to_string(),
            redistribute: Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Bgp,
                policy: Some("p1".to_string()),
            },
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.routing_tables[0]
                .redistribute
                .as_ref()
                .and_then(|r| r.policy.as_deref()),
            Some("p1")
        );
    }

    #[test]
    fn set_bgp_instance_missing_table_errors() {
        let mut cfg = Config::default();
        let err = RoutingTableOp::SetBgpInstance {
            name: "rt1".to_string(),
            bgp_instance: "r1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::RoutingTableNotFound(n) if n == "rt1"));
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            routing_tables: vec![table("rt1"), table("rt2")],
            ..Default::default()
        };
        RoutingTableOp::Delete {
            name: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables.len(), 1);
        assert_eq!(cfg.routing_tables[0].name, "rt2");
    }

    #[test]
    fn delete_missing_table_errors() {
        let mut cfg = Config::default();
        let err = RoutingTableOp::Delete {
            name: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::RoutingTableNotFound(n) if n == "rt1"));
    }
}
