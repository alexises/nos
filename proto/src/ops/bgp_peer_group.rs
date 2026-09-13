use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::schema::{AddressFamily, BgpPeerGroup, Config};

use super::bgp_instance::find_instance_mut;
use super::OpError;

/// An edit to a single named `BgpPeerGroup` within a given BGP instance, in
/// a transaction's in-progress config. Applied without validation — `garde`
/// validation only runs at commit time, matching `BgpInstanceOp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BgpPeerGroupOp {
    /// Creates the peer-group with placeholder field values if it doesn't
    /// already exist by name within `instance`; no-op if it does. Backs
    /// `edit peer-group <name>`'s "create if missing, else navigate to it"
    /// semantics.
    Ensure {
        instance: String,
        name: String,
    },
    SetRemoteAs {
        instance: String,
        name: String,
        remote_as: u32,
    },
    SetSourceAddress {
        instance: String,
        name: String,
        address: IpAddr,
    },
    ClearSourceAddress {
        instance: String,
        name: String,
    },
    /// Idempotent — no-op if `af` is already present.
    AddAddressFamily {
        instance: String,
        name: String,
        af: AddressFamily,
    },
    /// Idempotent — no-op if `af` is already absent.
    RemoveAddressFamily {
        instance: String,
        name: String,
        af: AddressFamily,
    },
    Delete {
        instance: String,
        name: String,
    },
}

impl BgpPeerGroupOp {
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            BgpPeerGroupOp::Ensure { instance, name } => {
                let inst = find_instance_mut(config, instance)?;
                if !inst.peer_groups.iter().any(|g| &g.name == name) {
                    inst.peer_groups.push(BgpPeerGroup {
                        name: name.clone(),
                        remote_as: 0,
                        source_address: None,
                        address_families: Vec::new(),
                    });
                }
                Ok(())
            }
            BgpPeerGroupOp::SetRemoteAs {
                instance,
                name,
                remote_as,
            } => {
                find_group_mut(config, instance, name)?.remote_as = *remote_as;
                Ok(())
            }
            BgpPeerGroupOp::SetSourceAddress {
                instance,
                name,
                address,
            } => {
                find_group_mut(config, instance, name)?.source_address = Some(*address);
                Ok(())
            }
            BgpPeerGroupOp::ClearSourceAddress { instance, name } => {
                find_group_mut(config, instance, name)?.source_address = None;
                Ok(())
            }
            BgpPeerGroupOp::AddAddressFamily { instance, name, af } => {
                let group = find_group_mut(config, instance, name)?;
                if !group.address_families.contains(af) {
                    group.address_families.push(*af);
                }
                Ok(())
            }
            BgpPeerGroupOp::RemoveAddressFamily { instance, name, af } => {
                find_group_mut(config, instance, name)?
                    .address_families
                    .retain(|a| a != af);
                Ok(())
            }
            BgpPeerGroupOp::Delete { instance, name } => {
                let inst = find_instance_mut(config, instance)?;
                let before = inst.peer_groups.len();
                inst.peer_groups.retain(|g| &g.name != name);
                if inst.peer_groups.len() == before {
                    return Err(OpError::BgpPeerGroupNotFound {
                        instance: instance.clone(),
                        name: name.clone(),
                    });
                }
                Ok(())
            }
        }
    }
}

fn find_group_mut<'a>(
    config: &'a mut Config,
    instance: &str,
    name: &str,
) -> Result<&'a mut BgpPeerGroup, OpError> {
    let inst = find_instance_mut(config, instance)?;
    inst.peer_groups
        .iter_mut()
        .find(|g| g.name == name)
        .ok_or_else(|| OpError::BgpPeerGroupNotFound {
            instance: instance.to_string(),
            name: name.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::schema::BgpInstance;

    use super::*;

    fn instance(name: &str, groups: Vec<BgpPeerGroup>) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn: 65000,
            peer_groups: groups,
            peers: Vec::new(),
        }
    }

    fn group(name: &str, remote_as: u32) -> BgpPeerGroup {
        BgpPeerGroup {
            name: name.to_string(),
            remote_as,
            source_address: None,
            address_families: vec![],
        }
    }

    fn config_with(instances: Vec<BgpInstance>) -> Config {
        Config {
            bgp_instances: instances,
            ..Default::default()
        }
    }

    #[test]
    fn ensure_creates_placeholder_when_missing() {
        let mut cfg = config_with(vec![instance("r1", vec![])]);
        BgpPeerGroupOp::Ensure {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        let inst = &cfg.bgp_instances[0];
        assert_eq!(inst.peer_groups.len(), 1);
        assert_eq!(inst.peer_groups[0].remote_as, 0);
        assert_eq!(inst.peer_groups[0].source_address, None);
        assert!(inst.peer_groups[0].address_families.is_empty());
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::Ensure {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups.len(), 1);
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].remote_as, 65001);
    }

    #[test]
    fn ensure_missing_instance_errors() {
        let mut cfg = config_with(vec![]);
        let err = BgpPeerGroupOp::Ensure {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::BgpInstanceNotFound(n) if n == "r1"));
    }

    #[test]
    fn set_remote_as_updates_existing() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetRemoteAs {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            remote_as: 65002,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].remote_as, 65002);
    }

    #[test]
    fn set_remote_as_missing_group_errors() {
        let mut cfg = config_with(vec![instance("r1", vec![])]);
        let err = BgpPeerGroupOp::SetRemoteAs {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            remote_as: 65002,
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(
            matches!(err, OpError::BgpPeerGroupNotFound { instance, name } if instance == "r1" && name == "pg1")
        );
    }

    #[test]
    fn set_and_clear_source_address() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        BgpPeerGroupOp::SetSourceAddress {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            address: addr,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].source_address,
            Some(addr)
        );

        BgpPeerGroupOp::ClearSourceAddress {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].source_address, None);
    }

    #[test]
    fn add_and_remove_address_family_are_idempotent() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        for _ in 0..2 {
            BgpPeerGroupOp::AddAddressFamily {
                instance: "r1".to_string(),
                name: "pg1".to_string(),
                af: AddressFamily::Ipv4Unicast,
            }
            .apply(&mut cfg)
            .unwrap();
        }
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].address_families,
            vec![AddressFamily::Ipv4Unicast]
        );

        for _ in 0..2 {
            BgpPeerGroupOp::RemoveAddressFamily {
                instance: "r1".to_string(),
                name: "pg1".to_string(),
                af: AddressFamily::Ipv4Unicast,
            }
            .apply(&mut cfg)
            .unwrap();
        }
        assert!(cfg.bgp_instances[0].peer_groups[0]
            .address_families
            .is_empty());
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = config_with(vec![instance(
            "r1",
            vec![group("pg1", 65001), group("pg2", 65002)],
        )]);
        BgpPeerGroupOp::Delete {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups.len(), 1);
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].name, "pg2");
    }

    #[test]
    fn delete_missing_group_errors() {
        let mut cfg = config_with(vec![instance("r1", vec![])]);
        let err = BgpPeerGroupOp::Delete {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(
            matches!(err, OpError::BgpPeerGroupNotFound { instance, name } if instance == "r1" && name == "pg1")
        );
    }
}
