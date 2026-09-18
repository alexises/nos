use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::schema::{Config, OspfProfile};

use super::ospf_area::find_area_mut;
use super::OpError;

/// An edit to a single `OspfProfile` (keyed by `name`, globally unique) nested
/// under a named `OspfArea` of a named `OspfInstance`, within a transaction's
/// in-progress config. Applied without validation, matching every other
/// `Op`. Compound-keyed (`instance`, `area_id`, `name`) like `BgpPeerGroupOp`
/// — `Ensure`-shaped with room for future `Set*` variants once a profile
/// gains real fields (see `schema::OspfProfile`'s doc comment), even though
/// there's nothing to `Set` yet.
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
                    area.profiles.push(OspfProfile { name: name.clone() });
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
        }
    }
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
            ospf_instances: vec![instance(
                "o1",
                vec![area(
                    "0.0.0.0",
                    vec![OspfProfile {
                        name: "p1".to_string(),
                    }],
                )],
            )],
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
                vec![area(
                    "0.0.0.0",
                    vec![
                        OspfProfile {
                            name: "p1".to_string(),
                        },
                        OspfProfile {
                            name: "p2".to_string(),
                        },
                    ],
                )],
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
}
