use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

use crate::schema::{BgpInstance, Config, RpkiCache};

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
    SetClusterId {
        name: String,
        cluster_id: Ipv4Addr,
    },
    ClearClusterId {
        name: String,
    },
    Delete {
        name: String,
    },
    /// RFC 5065: makes the instance a confederation member.
    SetConfederationIdentifier {
        name: String,
        identifier: u32,
    },
    ClearConfederation {
        name: String,
    },
    /// Adds another member AS; no-op if already listed. Refused at commit
    /// until an identifier is set too.
    AddConfederationPeer {
        name: String,
        asn: u32,
    },
    RemoveConfederationPeer {
        name: String,
        asn: u32,
    },
    /// RFC 8210: adds an RPKI cache, or replaces the one with that address.
    SetRpkiCache {
        name: String,
        cache: RpkiCache,
    },
    RemoveRpkiCache {
        name: String,
        address: IpAddr,
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
                        peer_groups: Vec::new(),
                        peers: Vec::new(),
                        cluster_id: None,
                        confederation: crate::schema::BgpConfederation::default(),
                        rpki_caches: Vec::new(),
                        routing_table: None,
                        redistribute_policy: None,
                    });
                }
                Ok(())
            }
            BgpInstanceOp::SetAsn { name, asn } => {
                find_instance_mut(config, name)?.asn = *asn;
                Ok(())
            }
            BgpInstanceOp::SetRouterId { name, router_id } => {
                find_instance_mut(config, name)?.router_id = *router_id;
                Ok(())
            }
            BgpInstanceOp::SetClusterId { name, cluster_id } => {
                find_instance_mut(config, name)?.cluster_id = Some(*cluster_id);
                Ok(())
            }
            BgpInstanceOp::ClearClusterId { name } => {
                find_instance_mut(config, name)?.cluster_id = None;
                Ok(())
            }
            BgpInstanceOp::SetConfederationIdentifier { name, identifier } => {
                find_instance_mut(config, name)?.confederation.identifier = Some(*identifier);
                Ok(())
            }
            BgpInstanceOp::ClearConfederation { name } => {
                find_instance_mut(config, name)?.confederation =
                    crate::schema::BgpConfederation::default();
                Ok(())
            }
            BgpInstanceOp::AddConfederationPeer { name, asn } => {
                let c = &mut find_instance_mut(config, name)?.confederation;
                if !c.peers.contains(asn) {
                    c.peers.push(*asn);
                }
                Ok(())
            }
            BgpInstanceOp::RemoveConfederationPeer { name, asn } => {
                find_instance_mut(config, name)?
                    .confederation
                    .peers
                    .retain(|p| p != asn);
                Ok(())
            }
            BgpInstanceOp::SetRpkiCache { name, cache } => {
                let caches = &mut find_instance_mut(config, name)?.rpki_caches;
                match caches.iter_mut().find(|c| c.address == cache.address) {
                    Some(c) => *c = cache.clone(),
                    None => caches.push(cache.clone()),
                }
                Ok(())
            }
            BgpInstanceOp::RemoveRpkiCache { name, address } => {
                find_instance_mut(config, name)?
                    .rpki_caches
                    .retain(|c| c.address != *address);
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

pub(crate) fn find_instance_mut<'a>(
    config: &'a mut Config,
    name: &str,
) -> Result<&'a mut BgpInstance, OpError> {
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
            peer_groups: Vec::new(),
            peers: Vec::new(),
            cluster_id: None,
            confederation: crate::schema::BgpConfederation::default(),
            rpki_caches: Vec::new(),
            routing_table: None,
            redistribute_policy: None,
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
    fn confederation_ops() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1", 65101)],
            ..Default::default()
        };
        let name = "r1".to_string();
        for op in [
            BgpInstanceOp::AddConfederationPeer {
                name: name.clone(),
                asn: 65102,
            },
            BgpInstanceOp::AddConfederationPeer {
                name: name.clone(),
                asn: 65102,
            },
            BgpInstanceOp::SetConfederationIdentifier {
                name: name.clone(),
                identifier: 65100,
            },
            BgpInstanceOp::AddConfederationPeer {
                name: name.clone(),
                asn: 65103,
            },
            BgpInstanceOp::RemoveConfederationPeer {
                name: name.clone(),
                asn: 65103,
            },
        ] {
            op.apply(&mut cfg).unwrap();
        }
        assert_eq!(
            cfg.bgp_instances[0].confederation,
            crate::schema::BgpConfederation {
                identifier: Some(65100),
                peers: vec![65102],
            }
        );
        BgpInstanceOp::ClearConfederation { name }
            .apply(&mut cfg)
            .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].confederation,
            crate::schema::BgpConfederation::default()
        );
    }

    #[test]
    fn rpki_cache_ops_upsert_by_address() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1", 65000)],
            ..Default::default()
        };
        let cache = |port| RpkiCache {
            address: "192.0.2.9".parse().unwrap(),
            port,
            preference: 1,
        };
        for port in [323, 8282] {
            BgpInstanceOp::SetRpkiCache {
                name: "r1".into(),
                cache: cache(port),
            }
            .apply(&mut cfg)
            .unwrap();
        }
        assert_eq!(cfg.bgp_instances[0].rpki_caches, vec![cache(8282)]);
        BgpInstanceOp::RemoveRpkiCache {
            name: "r1".into(),
            address: "192.0.2.9".parse().unwrap(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert!(cfg.bgp_instances[0].rpki_caches.is_empty());
    }

    #[test]
    fn set_and_clear_cluster_id() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1", 65000)],
            ..Default::default()
        };
        BgpInstanceOp::SetClusterId {
            name: "r1".to_string(),
            cluster_id: Ipv4Addr::new(1, 2, 3, 4),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].cluster_id,
            Some(Ipv4Addr::new(1, 2, 3, 4))
        );

        BgpInstanceOp::ClearClusterId {
            name: "r1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].cluster_id, None);
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1", 65000), instance("r2", 65001)],
            ..Default::default()
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
