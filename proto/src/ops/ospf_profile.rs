use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::schema::{Config, NetworkType, OspfProfile};

use super::ospf_area::find_area_mut;
use super::OpError;

/// An edit to a single `OspfProfile` (keyed by `name`, globally unique) nested
/// under a named `OspfArea` of a named `OspfInstance`, within a transaction's
/// in-progress config. Applied without validation, matching every other
/// `Op`. Compound-keyed (`instance`, `area_id`, `name`) like `BgpPeerGroupOp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OspfProfileOp {
    /// Creates the profile if it doesn't already exist (the owning area
    /// must already exist); no-op if it does. Backs `edit ospf instance
    /// <name> area <area-id> profile <profile-name>`'s "create if missing,
    /// else navigate to it" semantics.
    Ensure {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
    },
    Delete {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
    },
    SetHelloInterval {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
        hello_interval: u16,
    },
    ClearHelloInterval {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
    },
    SetDeadInterval {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
        dead_interval: u16,
    },
    ClearDeadInterval {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
    },
    SetCost {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
        cost: u16,
    },
    ClearCost {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
    },
    SetPriority {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
        priority: u8,
    },
    ClearPriority {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
    },
    SetNetworkType {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
        network_type: NetworkType,
    },
    ClearNetworkType {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
    },
}

impl OspfProfileOp {
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            OspfProfileOp::Ensure {
                instance,
                area_id,
                name,
            } => {
                let area = find_area_mut(config, instance, *area_id)?;
                if !area.profiles.iter().any(|p| &p.name == name) {
                    area.profiles.push(OspfProfile {
                        name: name.clone(),
                        hello_interval: None,
                        dead_interval: None,
                        cost: None,
                        priority: None,
                        network_type: None,
                    });
                }
                Ok(())
            }
            OspfProfileOp::Delete {
                instance,
                area_id,
                name,
            } => {
                let area = find_area_mut(config, instance, *area_id)?;
                let before = area.profiles.len();
                area.profiles.retain(|p| &p.name != name);
                if area.profiles.len() == before {
                    return Err(OpError::OspfProfileNotFound {
                        instance: instance.clone(),
                        area_id: *area_id,
                        name: name.clone(),
                    });
                }
                Ok(())
            }
            OspfProfileOp::SetHelloInterval {
                instance,
                area_id,
                name,
                hello_interval,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.hello_interval =
                    Some(*hello_interval);
                Ok(())
            }
            OspfProfileOp::ClearHelloInterval {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.hello_interval = None;
                Ok(())
            }
            OspfProfileOp::SetDeadInterval {
                instance,
                area_id,
                name,
                dead_interval,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.dead_interval =
                    Some(*dead_interval);
                Ok(())
            }
            OspfProfileOp::ClearDeadInterval {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.dead_interval = None;
                Ok(())
            }
            OspfProfileOp::SetCost {
                instance,
                area_id,
                name,
                cost,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.cost = Some(*cost);
                Ok(())
            }
            OspfProfileOp::ClearCost {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.cost = None;
                Ok(())
            }
            OspfProfileOp::SetPriority {
                instance,
                area_id,
                name,
                priority,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.priority = Some(*priority);
                Ok(())
            }
            OspfProfileOp::ClearPriority {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.priority = None;
                Ok(())
            }
            OspfProfileOp::SetNetworkType {
                instance,
                area_id,
                name,
                network_type,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.network_type =
                    Some(*network_type);
                Ok(())
            }
            OspfProfileOp::ClearNetworkType {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.network_type = None;
                Ok(())
            }
        }
    }
}

fn find_profile_mut<'a>(
    config: &'a mut Config,
    instance: &str,
    area_id: Ipv4Addr,
    name: &str,
) -> Result<&'a mut OspfProfile, OpError> {
    find_area_mut(config, instance, area_id)?
        .profiles
        .iter_mut()
        .find(|p| p.name == name)
        .ok_or_else(|| OpError::OspfProfileNotFound {
            instance: instance.to_string(),
            area_id,
            name: name.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{OspfArea, OspfInstance};

    fn area_id(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn instance(name: &str, areas: Vec<OspfArea>) -> OspfInstance {
        OspfInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            areas,
            routing_table: None,
        }
    }

    fn area(id: &str, profiles: Vec<OspfProfile>) -> OspfArea {
        OspfArea {
            area_id: area_id(id),
            profiles,
        }
    }

    fn profile(name: &str) -> OspfProfile {
        OspfProfile {
            name: name.to_string(),
            hello_interval: None,
            dead_interval: None,
            cost: None,
            priority: None,
            network_type: None,
        }
    }

    #[test]
    fn ensure_creates_when_missing() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![])])],
            ..Default::default()
        };
        OspfProfileOp::Ensure {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances[0].areas[0].profiles.len(), 1);
        assert_eq!(cfg.ospf_instances[0].areas[0].profiles[0].name, "p1");
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        OspfProfileOp::Ensure {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances[0].areas[0].profiles.len(), 1);
    }

    #[test]
    fn ensure_missing_area_errors() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![])],
            ..Default::default()
        };
        let err = OspfProfileOp::Ensure {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
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
    fn delete_removes_existing() {
        let mut cfg = Config {
            ospf_instances: vec![instance(
                "o1",
                vec![area("0.0.0.0", vec![profile("p1"), profile("p2")])],
            )],
            ..Default::default()
        };
        OspfProfileOp::Delete {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances[0].areas[0].profiles.len(), 1);
        assert_eq!(cfg.ospf_instances[0].areas[0].profiles[0].name, "p2");
    }

    #[test]
    fn delete_missing_profile_errors() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![])])],
            ..Default::default()
        };
        let err = OspfProfileOp::Delete {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::OspfProfileNotFound { instance, area_id, name }
            if instance == "o1" && area_id == self::area_id("0.0.0.0") && name == "p1"
        ));
    }

    #[test]
    fn set_and_clear_hello_interval() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        OspfProfileOp::SetHelloInterval {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            hello_interval: 5,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospf_instances[0].areas[0].profiles[0].hello_interval,
            Some(5)
        );

        OspfProfileOp::ClearHelloInterval {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospf_instances[0].areas[0].profiles[0].hello_interval,
            None
        );
    }

    #[test]
    fn set_and_clear_dead_interval() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        OspfProfileOp::SetDeadInterval {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            dead_interval: 20,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospf_instances[0].areas[0].profiles[0].dead_interval,
            Some(20)
        );

        OspfProfileOp::ClearDeadInterval {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospf_instances[0].areas[0].profiles[0].dead_interval,
            None
        );
    }

    #[test]
    fn set_hello_interval_missing_profile_errors() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![])])],
            ..Default::default()
        };
        let err = OspfProfileOp::SetHelloInterval {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            hello_interval: 5,
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::OspfProfileNotFound { instance, area_id, name }
            if instance == "o1" && area_id == self::area_id("0.0.0.0") && name == "p1"
        ));
    }

    #[test]
    fn set_and_clear_cost() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        OspfProfileOp::SetCost {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            cost: 20,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances[0].areas[0].profiles[0].cost, Some(20));

        OspfProfileOp::ClearCost {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances[0].areas[0].profiles[0].cost, None);
    }

    #[test]
    fn set_and_clear_priority() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        OspfProfileOp::SetPriority {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            priority: 200,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospf_instances[0].areas[0].profiles[0].priority,
            Some(200)
        );

        OspfProfileOp::ClearPriority {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances[0].areas[0].profiles[0].priority, None);
    }

    #[test]
    fn set_and_clear_network_type() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        OspfProfileOp::SetNetworkType {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            network_type: NetworkType::Broadcast,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospf_instances[0].areas[0].profiles[0].network_type,
            Some(NetworkType::Broadcast)
        );

        OspfProfileOp::ClearNetworkType {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospf_instances[0].areas[0].profiles[0].network_type,
            None
        );
    }
}
