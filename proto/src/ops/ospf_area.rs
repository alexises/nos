use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::schema::{Config, OspfArea};

use super::ospf_instance::find_instance_mut;
use super::OpError;

/// An edit to a single `OspfArea` (keyed by `area_id`) nested under a named
/// `OspfInstance`, within a transaction's in-progress config. Applied
/// without validation, matching every other `Op`. No `Set*` variant — an
/// area's only content today is its key plus its `profiles` list, handled
/// entirely by `OspfProfileOp` — mirrors `StaticRoutingInstanceOp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OspfAreaOp {
    /// Creates the area if it doesn't already exist (creating its parent
    /// `OspfInstance` too is *not* implied — the instance must already
    /// exist); no-op if it does. Backs `edit ospf instance <name> area
    /// <area-id>`'s "create if missing, else navigate to it" semantics.
    Ensure {
        instance: String,
        area_id: Ipv4Addr,
    },
    Delete {
        instance: String,
        area_id: Ipv4Addr,
    },
}

impl OspfAreaOp {
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            OspfAreaOp::Ensure { instance, area_id } => {
                let inst = find_instance_mut(config, instance)?;
                if !inst.areas.iter().any(|a| &a.area_id == area_id) {
                    inst.areas.push(OspfArea {
                        area_id: *area_id,
                        profiles: Vec::new(),
                    });
                }
                Ok(())
            }
            OspfAreaOp::Delete { instance, area_id } => {
                let inst = find_instance_mut(config, instance)?;
                let before = inst.areas.len();
                inst.areas.retain(|a| &a.area_id != area_id);
                if inst.areas.len() == before {
                    return Err(OpError::OspfAreaNotFound {
                        instance: instance.clone(),
                        area_id: *area_id,
                    });
                }
                Ok(())
            }
        }
    }
}

pub(crate) fn find_area_mut<'a>(
    config: &'a mut Config,
    instance: &str,
    area_id: Ipv4Addr,
) -> Result<&'a mut OspfArea, OpError> {
    find_instance_mut(config, instance)?
        .areas
        .iter_mut()
        .find(|a| a.area_id == area_id)
        .ok_or_else(|| OpError::OspfAreaNotFound {
            instance: instance.to_string(),
            area_id,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::OspfInstance;

    fn instance(name: &str, areas: Vec<OspfArea>) -> OspfInstance {
        OspfInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            areas,
            routing_table: None,
            redistribute_policy: None,
            graceful_restart_grace_period: None,
        }
    }

    fn area_id(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn ensure_creates_when_missing() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![])],
            ..Default::default()
        };
        OspfAreaOp::Ensure {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances[0].areas.len(), 1);
        assert_eq!(cfg.ospf_instances[0].areas[0].area_id, area_id("0.0.0.0"));
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = Config {
            ospf_instances: vec![instance(
                "o1",
                vec![OspfArea {
                    area_id: area_id("0.0.0.0"),
                    profiles: vec![crate::schema::OspfProfile {
                        name: "p1".to_string(),
                        hello_interval: None,
                        dead_interval: None,
                        cost: None,
                        priority: None,
                        mtu: None,
                        network_type: None,
                        auth: None,
                        extended_sequence_numbers: false,
                    }],
                }],
            )],
            ..Default::default()
        };
        OspfAreaOp::Ensure {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances[0].areas.len(), 1);
        assert_eq!(cfg.ospf_instances[0].areas[0].profiles.len(), 1);
    }

    #[test]
    fn ensure_missing_instance_errors() {
        let mut cfg = Config::default();
        let err = OspfAreaOp::Ensure {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::OspfInstanceNotFound(n) if n == "o1"));
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            ospf_instances: vec![instance(
                "o1",
                vec![
                    OspfArea {
                        area_id: area_id("0.0.0.0"),
                        profiles: Vec::new(),
                    },
                    OspfArea {
                        area_id: area_id("0.0.0.1"),
                        profiles: Vec::new(),
                    },
                ],
            )],
            ..Default::default()
        };
        OspfAreaOp::Delete {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances[0].areas.len(), 1);
        assert_eq!(cfg.ospf_instances[0].areas[0].area_id, area_id("0.0.0.1"));
    }

    #[test]
    fn delete_missing_area_errors() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![])],
            ..Default::default()
        };
        let err = OspfAreaOp::Delete {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::OspfAreaNotFound { instance, area_id }
            if instance == "o1" && area_id == self::area_id("0.0.0.0")
        ));
    }

    #[test]
    fn delete_missing_instance_errors() {
        let mut cfg = Config::default();
        let err = OspfAreaOp::Delete {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::OspfInstanceNotFound(n) if n == "o1"));
    }
}
