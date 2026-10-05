use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::schema::{Config, OspfArea, OspfAreaRange, OspfAreaType};

use super::ospf_instance::find_instance_mut;
use super::OpError;

/// An edit to a single `OspfArea` (keyed by `area_id`) nested under a named
/// `OspfInstance`, within a transaction's in-progress config. Applied
/// without validation, matching every other `Op`. Its `profiles` list is
/// `OspfProfileOp`'s. The CLI/REST reach the stub/range fields through
/// `SetTransactionPath`; these ops exist for `nos-provision`.
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
    SetAreaType {
        instance: String,
        area_id: Ipv4Addr,
        area_type: OspfAreaType,
    },
    SetStubDefaultCost {
        instance: String,
        area_id: Ipv4Addr,
        cost: Option<u16>,
    },
    /// Upserts by `cidr`.
    SetRange {
        instance: String,
        area_id: Ipv4Addr,
        cidr: Ipv4Net,
        not_advertise: bool,
    },
    RemoveRange {
        instance: String,
        area_id: Ipv4Addr,
        cidr: Ipv4Net,
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
                        ..Default::default()
                    });
                }
                Ok(())
            }
            OspfAreaOp::SetAreaType {
                instance,
                area_id,
                area_type,
            } => {
                find_area_mut(config, instance, *area_id)?.area_type = *area_type;
                Ok(())
            }
            OspfAreaOp::SetStubDefaultCost {
                instance,
                area_id,
                cost,
            } => {
                find_area_mut(config, instance, *area_id)?.stub_default_cost = *cost;
                Ok(())
            }
            OspfAreaOp::SetRange {
                instance,
                area_id,
                cidr,
                not_advertise,
            } => {
                let ranges = &mut find_area_mut(config, instance, *area_id)?.ranges;
                let range = OspfAreaRange {
                    cidr: *cidr,
                    not_advertise: *not_advertise,
                };
                match ranges.iter_mut().find(|r| r.cidr == *cidr) {
                    Some(r) => *r = range,
                    None => ranges.push(range),
                }
                Ok(())
            }
            OspfAreaOp::RemoveRange {
                instance,
                area_id,
                cidr,
            } => {
                let ranges = &mut find_area_mut(config, instance, *area_id)?.ranges;
                let before = ranges.len();
                ranges.retain(|r| r.cidr != *cidr);
                if ranges.len() == before {
                    return Err(OpError::OspfAreaRangeNotFound {
                        instance: instance.clone(),
                        area_id: *area_id,
                        cidr: *cidr,
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
            prefix_suppression: false,
            max_metric_on_startup: None,
            max_metric_on_shutdown: None,
            max_metric_administrative: false,
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
                    ..Default::default()
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
                        ..Default::default()
                    },
                    OspfArea {
                        area_id: area_id("0.0.0.1"),
                        ..Default::default()
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
    fn stub_settings_and_ranges_apply() {
        let mut cfg = Config {
            ospf_instances: vec![instance(
                "o1",
                vec![OspfArea {
                    area_id: area_id("0.0.0.1"),
                    ..Default::default()
                }],
            )],
            ..Default::default()
        };
        let (instance, area_id) = ("o1".to_string(), area_id("0.0.0.1"));
        let cidr: Ipv4Net = "10.0.0.0/16".parse().unwrap();
        for op in [
            OspfAreaOp::SetAreaType {
                instance: instance.clone(),
                area_id,
                area_type: OspfAreaType::TotallyStubby,
            },
            OspfAreaOp::SetStubDefaultCost {
                instance: instance.clone(),
                area_id,
                cost: Some(7),
            },
            OspfAreaOp::SetRange {
                instance: instance.clone(),
                area_id,
                cidr,
                not_advertise: false,
            },
            // Upsert: flips the same range, never duplicates it.
            OspfAreaOp::SetRange {
                instance: instance.clone(),
                area_id,
                cidr,
                not_advertise: true,
            },
        ] {
            op.apply(&mut cfg).unwrap();
        }
        let a = &cfg.ospf_instances[0].areas[0];
        assert_eq!(a.area_type, OspfAreaType::TotallyStubby);
        assert_eq!(a.stub_default_cost, Some(7));
        assert_eq!(
            a.ranges,
            vec![OspfAreaRange {
                cidr,
                not_advertise: true
            }]
        );
        let remove = OspfAreaOp::RemoveRange {
            instance,
            area_id,
            cidr,
        };
        remove.apply(&mut cfg).unwrap();
        assert_eq!(cfg.ospf_instances[0].areas[0].ranges, vec![]);
        assert!(matches!(
            remove.apply(&mut cfg),
            Err(OpError::OspfAreaRangeNotFound { .. })
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
