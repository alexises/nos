use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::schema::{BgpInstance, Config};

use super::OpError;

/// An edit to a single named `BgpInstance` within a transaction's in-progress
/// config. Applied without validation — `garde` validation only runs at
/// commit time, matching the daemon's existing edit/commit split.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BgpInstanceOp {
    /// Creates the instance with placeholder field values if it doesn't
    /// already exist by name; no-op if it does. Backs `edit bgp instance
    /// <name>`'s "create if missing, else navigate to it" semantics.
    Ensure {
        name: String,
    },
    SetAsn {
        name: String,
        asn: u32,
    },
    SetRouterId {
        name: String,
        router_id: Ipv4Addr,
    },
    Delete {
        name: String,
    },
}

impl BgpInstanceOp {
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            BgpInstanceOp::Ensure { name } => {
                if !config.bgp_instances.iter().any(|i| &i.name == name) {
                    config.bgp_instances.push(BgpInstance {
                        name: name.clone(),
                        router_id: Ipv4Addr::UNSPECIFIED,
                        asn: 0,
                    });
                }
                Ok(())
            }
            BgpInstanceOp::SetAsn { name, asn } => {
                find_mut(config, name)?.asn = *asn;
                Ok(())
            }
            BgpInstanceOp::SetRouterId { name, router_id } => {
                find_mut(config, name)?.router_id = *router_id;
                Ok(())
            }
            BgpInstanceOp::Delete { name } => {
                let before = config.bgp_instances.len();
                config.bgp_instances.retain(|i| &i.name != name);
                if config.bgp_instances.len() == before {
                    return Err(OpError::BgpInstanceNotFound(name.clone()));
                }
                Ok(())
            }
        }
    }
}

fn find_mut<'a>(config: &'a mut Config, name: &str) -> Result<&'a mut BgpInstance, OpError> {
    config
        .bgp_instances
        .iter_mut()
        .find(|i| i.name == name)
        .ok_or_else(|| OpError::BgpInstanceNotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance(name: &str, asn: u32) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn,
        }
    }

    #[test]
    fn ensure_creates_placeholder_when_missing() {
        let mut cfg = Config::default();
        BgpInstanceOp::Ensure {
            name: "r1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances.len(), 1);
        assert_eq!(cfg.bgp_instances[0].name, "r1");
        assert_eq!(cfg.bgp_instances[0].router_id, Ipv4Addr::UNSPECIFIED);
        assert_eq!(cfg.bgp_instances[0].asn, 0);
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1", 65000)],
        };
        BgpInstanceOp::Ensure {
            name: "r1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances.len(), 1);
        assert_eq!(cfg.bgp_instances[0].asn, 65000);
    }

    #[test]
    fn set_asn_updates_existing() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1", 65000)],
        };
        BgpInstanceOp::SetAsn {
            name: "r1".to_string(),
            asn: 65001,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].asn, 65001);
    }

    #[test]
    fn set_asn_missing_instance_errors() {
        let mut cfg = Config::default();
        let err = BgpInstanceOp::SetAsn {
            name: "r1".to_string(),
            asn: 65001,
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::BgpInstanceNotFound(n) if n == "r1"));
    }

    #[test]
    fn set_router_id_updates_existing() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1", 65000)],
        };
        BgpInstanceOp::SetRouterId {
            name: "r1".to_string(),
            router_id: Ipv4Addr::new(10, 0, 0, 1),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].router_id, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1", 65000), instance("r2", 65001)],
        };
        BgpInstanceOp::Delete {
            name: "r1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances.len(), 1);
        assert_eq!(cfg.bgp_instances[0].name, "r2");
    }

    #[test]
    fn delete_missing_instance_errors() {
        let mut cfg = Config::default();
        let err = BgpInstanceOp::Delete {
            name: "r1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::BgpInstanceNotFound(n) if n == "r1"));
    }
}
