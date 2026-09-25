use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::schema::{Config, NetworkType, Ospfv3Profile};

use super::ospfv3_area::find_area_mut;
use super::OpError;

/// An edit to a single `Ospfv3Profile` (keyed by `name`, globally unique)
/// nested under a named `Ospfv3Area` of a named `Ospfv3Instance` — mirrors
/// `OspfProfileOp` exactly, minus its crypto/simple-auth variants (RFC 5340
/// Phase 1 has no authentication — see `Ospfv3Profile`'s doc comment).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ospfv3ProfileOp {
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
    SetMtu {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
        mtu: u16,
    },
    ClearMtu {
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

impl Ospfv3ProfileOp {
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            Ospfv3ProfileOp::Ensure {
                instance,
                area_id,
                name,
            } => {
                let area = find_area_mut(config, instance, *area_id)?;
                if !area.profiles.iter().any(|p| &p.name == name) {
                    area.profiles.push(Ospfv3Profile {
                        name: name.clone(),
                        hello_interval: None,
                        dead_interval: None,
                        cost: None,
                        priority: None,
                        mtu: None,
                        network_type: None,
                    });
                }
                Ok(())
            }
            Ospfv3ProfileOp::Delete {
                instance,
                area_id,
                name,
            } => {
                let area = find_area_mut(config, instance, *area_id)?;
                let before = area.profiles.len();
                area.profiles.retain(|p| &p.name != name);
                if area.profiles.len() == before {
                    return Err(OpError::Ospfv3ProfileNotFound {
                        instance: instance.clone(),
                        area_id: *area_id,
                        name: name.clone(),
                    });
                }
                Ok(())
            }
            Ospfv3ProfileOp::SetHelloInterval {
                instance,
                area_id,
                name,
                hello_interval,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.hello_interval =
                    Some(*hello_interval);
                Ok(())
            }
            Ospfv3ProfileOp::ClearHelloInterval {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.hello_interval = None;
                Ok(())
            }
            Ospfv3ProfileOp::SetDeadInterval {
                instance,
                area_id,
                name,
                dead_interval,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.dead_interval =
                    Some(*dead_interval);
                Ok(())
            }
            Ospfv3ProfileOp::ClearDeadInterval {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.dead_interval = None;
                Ok(())
            }
            Ospfv3ProfileOp::SetCost {
                instance,
                area_id,
                name,
                cost,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.cost = Some(*cost);
                Ok(())
            }
            Ospfv3ProfileOp::ClearCost {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.cost = None;
                Ok(())
            }
            Ospfv3ProfileOp::SetPriority {
                instance,
                area_id,
                name,
                priority,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.priority = Some(*priority);
                Ok(())
            }
            Ospfv3ProfileOp::ClearPriority {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.priority = None;
                Ok(())
            }
            Ospfv3ProfileOp::SetMtu {
                instance,
                area_id,
                name,
                mtu,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.mtu = Some(*mtu);
                Ok(())
            }
            Ospfv3ProfileOp::ClearMtu {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.mtu = None;
                Ok(())
            }
            Ospfv3ProfileOp::SetNetworkType {
                instance,
                area_id,
                name,
                network_type,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.network_type =
                    Some(*network_type);
                Ok(())
            }
            Ospfv3ProfileOp::ClearNetworkType {
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
) -> Result<&'a mut Ospfv3Profile, OpError> {
    find_area_mut(config, instance, area_id)?
        .profiles
        .iter_mut()
        .find(|p| p.name == name)
        .ok_or_else(|| OpError::Ospfv3ProfileNotFound {
            instance: instance.to_string(),
            area_id,
            name: name.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Ospfv3Area, Ospfv3Instance};

    fn area_id(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn instance(name: &str, areas: Vec<Ospfv3Area>) -> Ospfv3Instance {
        Ospfv3Instance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            areas,
            routing_table: None,
            extended_lsa: false,
        }
    }

    fn area(id: &str, profiles: Vec<Ospfv3Profile>) -> Ospfv3Area {
        Ospfv3Area {
            area_id: area_id(id),
            profiles,
        }
    }

    fn profile(name: &str) -> Ospfv3Profile {
        Ospfv3Profile {
            name: name.to_string(),
            hello_interval: None,
            dead_interval: None,
            cost: None,
            priority: None,
            mtu: None,
            network_type: None,
        }
    }

    #[test]
    fn ensure_creates_when_missing() {
        let mut cfg = Config {
            ospfv3_instances: vec![instance("o1", vec![area("0.0.0.0", vec![])])],
            ..Default::default()
        };
        Ospfv3ProfileOp::Ensure {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospfv3_instances[0].areas[0].profiles.len(), 1);
        assert_eq!(cfg.ospfv3_instances[0].areas[0].profiles[0].name, "p1");
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            ospfv3_instances: vec![instance(
                "o1",
                vec![area("0.0.0.0", vec![profile("p1"), profile("p2")])],
            )],
            ..Default::default()
        };
        Ospfv3ProfileOp::Delete {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospfv3_instances[0].areas[0].profiles.len(), 1);
        assert_eq!(cfg.ospfv3_instances[0].areas[0].profiles[0].name, "p2");
    }

    #[test]
    fn set_and_clear_hello_interval() {
        let mut cfg = Config {
            ospfv3_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        Ospfv3ProfileOp::SetHelloInterval {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            hello_interval: 5,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospfv3_instances[0].areas[0].profiles[0].hello_interval,
            Some(5)
        );

        Ospfv3ProfileOp::ClearHelloInterval {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospfv3_instances[0].areas[0].profiles[0].hello_interval,
            None
        );
    }

    #[test]
    fn set_and_clear_cost() {
        let mut cfg = Config {
            ospfv3_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        Ospfv3ProfileOp::SetCost {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            cost: 20,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospfv3_instances[0].areas[0].profiles[0].cost, Some(20));

        Ospfv3ProfileOp::ClearCost {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospfv3_instances[0].areas[0].profiles[0].cost, None);
    }

    #[test]
    fn set_and_clear_network_type() {
        let mut cfg = Config {
            ospfv3_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        Ospfv3ProfileOp::SetNetworkType {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            network_type: NetworkType::Broadcast,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospfv3_instances[0].areas[0].profiles[0].network_type,
            Some(NetworkType::Broadcast)
        );

        Ospfv3ProfileOp::ClearNetworkType {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospfv3_instances[0].areas[0].profiles[0].network_type,
            None
        );
    }
}
