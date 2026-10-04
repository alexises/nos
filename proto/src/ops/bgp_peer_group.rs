use serde::{Deserialize, Serialize};

use crate::schema::{
    AddressFamily, BgpAoKey, BgpAuth, BgpDamping, BgpPeerGroup, BgpPrefixLimit, BgpShutdown,
    Config, NextHopMode, SourceAddress,
};

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
        source: SourceAddress,
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
    SetHoldTime {
        instance: String,
        name: String,
        hold_time: u16,
    },
    ClearHoldTime {
        instance: String,
        name: String,
    },
    SetKeepaliveInterval {
        instance: String,
        name: String,
        keepalive_interval: u16,
    },
    ClearKeepaliveInterval {
        instance: String,
        name: String,
    },
    SetConnectRetryTime {
        instance: String,
        name: String,
        connect_retry_time: u16,
    },
    ClearConnectRetryTime {
        instance: String,
        name: String,
    },
    SetMrai {
        instance: String,
        name: String,
        mrai: u16,
    },
    ClearMrai {
        instance: String,
        name: String,
    },
    SetDamping {
        instance: String,
        name: String,
        damping: BgpDamping,
    },
    ClearDamping {
        instance: String,
        name: String,
    },
    SetMaxHops {
        instance: String,
        name: String,
        max_hops: u8,
    },
    ClearMaxHops {
        instance: String,
        name: String,
    },
    /// Sets `auth` to a single MD5 password, replacing any TCP-AO keys
    /// (the two mechanisms are mutually exclusive — the kernel accepts only
    /// one per socket).
    SetMd5Auth {
        instance: String,
        name: String,
        password: String,
    },
    /// Upserts one TCP-AO key by `send_id`. If `auth` isn't already `Ao`
    /// (unset, or `Md5`), starts a fresh key list with just this key.
    SetAoKey {
        instance: String,
        name: String,
        key: BgpAoKey,
    },
    /// Removes one TCP-AO key by `send_id`. No-op if `auth` isn't `Ao` or
    /// the id isn't present — does not clear `auth` back to `None` even if
    /// the list becomes empty; commit-time validation rejects an empty
    /// `Ao` list, so an explicit `ClearAuth` is required for that case.
    RemoveAoKey {
        instance: String,
        name: String,
        send_id: u8,
    },
    /// Marks one existing TCP-AO key as the current key, clearing the flag
    /// on every other key in the list.
    SetAoCurrentKey {
        instance: String,
        name: String,
        send_id: u8,
    },
    /// Marks one existing TCP-AO key as the rnext key, clearing the flag on
    /// every other key in the list.
    SetAoRnextKey {
        instance: String,
        name: String,
        send_id: u8,
    },
    /// Unsets `auth` entirely, regardless of which mechanism was set.
    ClearAuth {
        instance: String,
        name: String,
    },
    SetNextHop {
        instance: String,
        name: String,
        mode: NextHopMode,
    },
    ClearNextHop {
        instance: String,
        name: String,
    },
    SetRouteReflectorClient {
        instance: String,
        name: String,
    },
    /// RFC 8097 `announce_rpki_state` on/off.
    SetAnnounceRpkiState {
        instance: String,
        name: String,
        enabled: bool,
    },
    ClearRouteReflectorClient {
        instance: String,
        name: String,
    },
    SetRouteServerClient {
        instance: String,
        name: String,
    },
    ClearRouteServerClient {
        instance: String,
        name: String,
    },
    SetImportPolicy {
        instance: String,
        name: String,
        import_policy: String,
    },
    ClearImportPolicy {
        instance: String,
        name: String,
    },
    SetExportPolicy {
        instance: String,
        name: String,
        export_policy: String,
    },
    ClearExportPolicy {
        instance: String,
        name: String,
    },
    /// Administratively shuts the whole peer-group (see `BgpShutdown`).
    SetShutdown {
        instance: String,
        name: String,
        message: Option<String>,
    },
    ClearShutdown {
        instance: String,
        name: String,
    },
    /// Sets one address family's RFC 4486 maximum-prefix limit.
    SetMaximumPrefix {
        instance: String,
        name: String,
        family: AddressFamily,
        limit: BgpPrefixLimit,
    },
    /// Removes one address family's maximum-prefix limit (no-op if unset).
    ClearMaximumPrefix {
        instance: String,
        name: String,
        family: AddressFamily,
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
                        hold_time: None,
                        keepalive_interval: None,
                        connect_retry_time: None,
                        mrai: None,
                        damping: None,
                        max_hops: None,
                        auth: None,
                        next_hop: None,
                        route_reflector_client: false,
                        route_server_client: false,
                        import_policy: None,
                        export_policy: None,
                        shutdown: None,
                        maximum_prefix: crate::schema::BgpMaximumPrefix::default(),
                        announce_rpki_state: false,
                    });
                }
                Ok(())
            }
            BgpPeerGroupOp::SetMaximumPrefix {
                instance,
                name,
                family,
                limit,
            } => {
                *find_group_mut(config, instance, name)?
                    .maximum_prefix
                    .slot_mut(*family) = Some(*limit);
                Ok(())
            }
            BgpPeerGroupOp::ClearMaximumPrefix {
                instance,
                name,
                family,
            } => {
                *find_group_mut(config, instance, name)?
                    .maximum_prefix
                    .slot_mut(*family) = None;
                Ok(())
            }
            BgpPeerGroupOp::SetShutdown {
                instance,
                name,
                message,
            } => {
                find_group_mut(config, instance, name)?.shutdown = Some(BgpShutdown {
                    message: message.clone(),
                });
                Ok(())
            }
            BgpPeerGroupOp::ClearShutdown { instance, name } => {
                find_group_mut(config, instance, name)?.shutdown = None;
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
                source,
            } => {
                find_group_mut(config, instance, name)?.source_address = Some(source.clone());
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
            BgpPeerGroupOp::SetHoldTime {
                instance,
                name,
                hold_time,
            } => {
                find_group_mut(config, instance, name)?.hold_time = Some(*hold_time);
                Ok(())
            }
            BgpPeerGroupOp::ClearHoldTime { instance, name } => {
                find_group_mut(config, instance, name)?.hold_time = None;
                Ok(())
            }
            BgpPeerGroupOp::SetKeepaliveInterval {
                instance,
                name,
                keepalive_interval,
            } => {
                find_group_mut(config, instance, name)?.keepalive_interval =
                    Some(*keepalive_interval);
                Ok(())
            }
            BgpPeerGroupOp::ClearKeepaliveInterval { instance, name } => {
                find_group_mut(config, instance, name)?.keepalive_interval = None;
                Ok(())
            }
            BgpPeerGroupOp::SetConnectRetryTime {
                instance,
                name,
                connect_retry_time,
            } => {
                find_group_mut(config, instance, name)?.connect_retry_time =
                    Some(*connect_retry_time);
                Ok(())
            }
            BgpPeerGroupOp::ClearConnectRetryTime { instance, name } => {
                find_group_mut(config, instance, name)?.connect_retry_time = None;
                Ok(())
            }
            BgpPeerGroupOp::SetMrai {
                instance,
                name,
                mrai,
            } => {
                find_group_mut(config, instance, name)?.mrai = Some(*mrai);
                Ok(())
            }
            BgpPeerGroupOp::ClearMrai { instance, name } => {
                find_group_mut(config, instance, name)?.mrai = None;
                Ok(())
            }
            BgpPeerGroupOp::SetDamping {
                instance,
                name,
                damping,
            } => {
                find_group_mut(config, instance, name)?.damping = Some(*damping);
                Ok(())
            }
            BgpPeerGroupOp::ClearDamping { instance, name } => {
                find_group_mut(config, instance, name)?.damping = None;
                Ok(())
            }
            BgpPeerGroupOp::SetMaxHops {
                instance,
                name,
                max_hops,
            } => {
                find_group_mut(config, instance, name)?.max_hops = Some(*max_hops);
                Ok(())
            }
            BgpPeerGroupOp::ClearMaxHops { instance, name } => {
                find_group_mut(config, instance, name)?.max_hops = None;
                Ok(())
            }
            BgpPeerGroupOp::SetMd5Auth {
                instance,
                name,
                password,
            } => {
                find_group_mut(config, instance, name)?.auth = Some(BgpAuth::Md5 {
                    password: password.clone(),
                });
                Ok(())
            }
            BgpPeerGroupOp::SetAoKey {
                instance,
                name,
                key,
            } => {
                let group = find_group_mut(config, instance, name)?;
                let keys = match &mut group.auth {
                    Some(BgpAuth::Ao { keys }) => keys,
                    Some(BgpAuth::Md5 { .. }) | None => {
                        group.auth = Some(BgpAuth::Ao { keys: Vec::new() });
                        let Some(BgpAuth::Ao { keys }) = &mut group.auth else {
                            unreachable!("just set to Ao above")
                        };
                        keys
                    }
                };
                match keys.iter_mut().find(|k| k.send_id == key.send_id) {
                    Some(existing) => *existing = key.clone(),
                    None => keys.push(key.clone()),
                }
                Ok(())
            }
            BgpPeerGroupOp::RemoveAoKey {
                instance,
                name,
                send_id,
            } => {
                if let Some(BgpAuth::Ao { keys }) =
                    &mut find_group_mut(config, instance, name)?.auth
                {
                    keys.retain(|k| k.send_id != *send_id);
                }
                Ok(())
            }
            BgpPeerGroupOp::SetAoCurrentKey {
                instance,
                name,
                send_id,
            } => set_ao_key_flag(config, instance, name, *send_id, |k, is_target| {
                k.is_current = is_target;
            }),
            BgpPeerGroupOp::SetAoRnextKey {
                instance,
                name,
                send_id,
            } => set_ao_key_flag(config, instance, name, *send_id, |k, is_target| {
                k.is_rnext = is_target;
            }),
            BgpPeerGroupOp::ClearAuth { instance, name } => {
                find_group_mut(config, instance, name)?.auth = None;
                Ok(())
            }
            BgpPeerGroupOp::SetNextHop {
                instance,
                name,
                mode,
            } => {
                find_group_mut(config, instance, name)?.next_hop = Some(*mode);
                Ok(())
            }
            BgpPeerGroupOp::ClearNextHop { instance, name } => {
                find_group_mut(config, instance, name)?.next_hop = None;
                Ok(())
            }
            BgpPeerGroupOp::SetAnnounceRpkiState {
                instance,
                name,
                enabled,
            } => {
                find_group_mut(config, instance, name)?.announce_rpki_state = *enabled;
                Ok(())
            }
            BgpPeerGroupOp::SetRouteReflectorClient { instance, name } => {
                find_group_mut(config, instance, name)?.route_reflector_client = true;
                Ok(())
            }
            BgpPeerGroupOp::ClearRouteReflectorClient { instance, name } => {
                find_group_mut(config, instance, name)?.route_reflector_client = false;
                Ok(())
            }
            BgpPeerGroupOp::SetRouteServerClient { instance, name } => {
                find_group_mut(config, instance, name)?.route_server_client = true;
                Ok(())
            }
            BgpPeerGroupOp::ClearRouteServerClient { instance, name } => {
                find_group_mut(config, instance, name)?.route_server_client = false;
                Ok(())
            }
            BgpPeerGroupOp::SetImportPolicy {
                instance,
                name,
                import_policy,
            } => {
                find_group_mut(config, instance, name)?.import_policy = Some(import_policy.clone());
                Ok(())
            }
            BgpPeerGroupOp::ClearImportPolicy { instance, name } => {
                find_group_mut(config, instance, name)?.import_policy = None;
                Ok(())
            }
            BgpPeerGroupOp::SetExportPolicy {
                instance,
                name,
                export_policy,
            } => {
                find_group_mut(config, instance, name)?.export_policy = Some(export_policy.clone());
                Ok(())
            }
            BgpPeerGroupOp::ClearExportPolicy { instance, name } => {
                find_group_mut(config, instance, name)?.export_policy = None;
                Ok(())
            }
        }
    }
}

/// Shared body of `SetAoCurrentKey`/`SetAoRnextKey`: sets `set_flag(key,
/// true)` on the key matching `send_id` and `set_flag(key, false)` on every
/// other key in the same `Ao` list, enforcing "at most one key has this
/// flag" eagerly rather than deferring to commit-time validation.
fn set_ao_key_flag(
    config: &mut Config,
    instance: &str,
    name: &str,
    send_id: u8,
    set_flag: impl Fn(&mut BgpAoKey, bool),
) -> Result<(), OpError> {
    let group = find_group_mut(config, instance, name)?;
    let Some(BgpAuth::Ao { keys }) = &mut group.auth else {
        return Err(OpError::BgpAoKeyNotFound {
            instance: instance.to_string(),
            name: name.to_string(),
            send_id,
        });
    };
    if !keys.iter().any(|k| k.send_id == send_id) {
        return Err(OpError::BgpAoKeyNotFound {
            instance: instance.to_string(),
            name: name.to_string(),
            send_id,
        });
    }
    for key in keys.iter_mut() {
        set_flag(key, key.send_id == send_id);
    }
    Ok(())
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
    use std::net::Ipv4Addr;

    use crate::schema::BgpInstance;

    use super::*;

    fn instance(name: &str, groups: Vec<BgpPeerGroup>) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn: 65000,
            peer_groups: groups,
            peers: Vec::new(),
            cluster_id: None,
            maximum_paths: None,
            confederation: crate::schema::BgpConfederation::default(),
            rpki_caches: Vec::new(),
            routing_table: None,
            redistribute_policy: None,
        }
    }

    fn group(name: &str, remote_as: u32) -> BgpPeerGroup {
        BgpPeerGroup {
            name: name.to_string(),
            remote_as,
            source_address: None,
            address_families: vec![],
            hold_time: None,
            keepalive_interval: None,
            connect_retry_time: None,
            mrai: None,
            damping: None,
            max_hops: None,
            auth: None,
            next_hop: None,
            route_reflector_client: false,
            route_server_client: false,
            import_policy: None,
            export_policy: None,
            shutdown: None,
            maximum_prefix: crate::schema::BgpMaximumPrefix::default(),
            announce_rpki_state: false,
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
        assert_eq!(inst.peer_groups[0].address_families, []);
        assert_eq!(inst.peer_groups[0].hold_time, None);
        assert_eq!(inst.peer_groups[0].keepalive_interval, None);
        assert_eq!(inst.peer_groups[0].connect_retry_time, None);
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
        let source = SourceAddress::Interface {
            interface: "eth0".to_string(),
            label: None,
        };
        BgpPeerGroupOp::SetSourceAddress {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            source: source.clone(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].source_address,
            Some(source)
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
    fn set_and_clear_hold_time() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetHoldTime {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            hold_time: 30,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].hold_time, Some(30));

        BgpPeerGroupOp::ClearHoldTime {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].hold_time, None);
    }

    #[test]
    fn set_and_clear_next_hop() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetNextHop {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            mode: NextHopMode::Unchanged,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].next_hop,
            Some(NextHopMode::Unchanged)
        );

        BgpPeerGroupOp::ClearNextHop {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].next_hop, None);
    }

    #[test]
    fn set_and_clear_route_reflector_client() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetRouteReflectorClient {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert!(cfg.bgp_instances[0].peer_groups[0].route_reflector_client);

        BgpPeerGroupOp::ClearRouteReflectorClient {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert!(!cfg.bgp_instances[0].peer_groups[0].route_reflector_client);
    }

    #[test]
    fn set_and_clear_route_server_client() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetRouteServerClient {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert!(cfg.bgp_instances[0].peer_groups[0].route_server_client);

        BgpPeerGroupOp::ClearRouteServerClient {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert!(!cfg.bgp_instances[0].peer_groups[0].route_server_client);
    }

    #[test]
    fn set_and_clear_import_policy() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetImportPolicy {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            import_policy: "accept-all".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].import_policy.as_deref(),
            Some("accept-all")
        );

        BgpPeerGroupOp::ClearImportPolicy {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].import_policy, None);
    }

    #[test]
    fn set_and_clear_export_policy() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetExportPolicy {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            export_policy: "deny-all".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].export_policy.as_deref(),
            Some("deny-all")
        );

        BgpPeerGroupOp::ClearExportPolicy {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].export_policy, None);
    }

    #[test]
    fn set_and_clear_keepalive_interval() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetKeepaliveInterval {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            keepalive_interval: 10,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].keepalive_interval,
            Some(10)
        );

        BgpPeerGroupOp::ClearKeepaliveInterval {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].keepalive_interval, None);
    }

    #[test]
    fn set_and_clear_damping() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetDamping {
            instance: "r1".into(),
            name: "pg1".into(),
            damping: BgpDamping::default(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].damping,
            Some(BgpDamping::default())
        );
        BgpPeerGroupOp::ClearDamping {
            instance: "r1".into(),
            name: "pg1".into(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].damping, None);
    }

    #[test]
    fn set_and_clear_maximum_prefix_per_family() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        let lim = BgpPrefixLimit {
            limit: 2,
            warning_only: false,
            restart_interval: 0,
        };
        BgpPeerGroupOp::SetMaximumPrefix {
            instance: "r1".into(),
            name: "pg1".into(),
            family: AddressFamily::Ipv4Unicast,
            limit: lim,
        }
        .apply(&mut cfg)
        .unwrap();
        let m = cfg.bgp_instances[0].peer_groups[0].maximum_prefix;
        assert_eq!((m.ipv4, m.ipv6, m.l2vpn_evpn), (Some(lim), None, None));
        BgpPeerGroupOp::ClearMaximumPrefix {
            instance: "r1".into(),
            name: "pg1".into(),
            family: AddressFamily::Ipv4Unicast,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].maximum_prefix,
            crate::schema::BgpMaximumPrefix::default()
        );
    }

    #[test]
    fn set_and_clear_max_hops() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetMaxHops {
            instance: "r1".into(),
            name: "pg1".into(),
            max_hops: 1,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].max_hops, Some(1));
        BgpPeerGroupOp::ClearMaxHops {
            instance: "r1".into(),
            name: "pg1".into(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].max_hops, None);
    }

    #[test]
    fn set_and_clear_mrai() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetMrai {
            instance: "r1".into(),
            name: "pg1".into(),
            mrai: 30,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].mrai, Some(30));
        BgpPeerGroupOp::ClearMrai {
            instance: "r1".into(),
            name: "pg1".into(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].mrai, None);
    }

    #[test]
    fn set_and_clear_connect_retry_time() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetConnectRetryTime {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            connect_retry_time: 45,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].connect_retry_time,
            Some(45)
        );

        BgpPeerGroupOp::ClearConnectRetryTime {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].connect_retry_time, None);
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
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].address_families, []);
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

    use crate::schema::BgpAoAlgorithm;

    fn ao_key(send_id: u8) -> BgpAoKey {
        BgpAoKey {
            send_id,
            recv_id: send_id,
            algorithm: BgpAoAlgorithm::HmacSha1_96,
            key: "secret".to_string(),
            is_current: false,
            is_rnext: false,
            exclude_options: false,
        }
    }

    #[test]
    fn set_md5_auth_sets_password() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetMd5Auth {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            password: "secret".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].auth,
            Some(BgpAuth::Md5 {
                password: "secret".to_string()
            })
        );
    }

    #[test]
    fn set_md5_auth_replaces_existing_ao_keys() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetAoKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            key: ao_key(1),
        }
        .apply(&mut cfg)
        .unwrap();
        BgpPeerGroupOp::SetMd5Auth {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            password: "secret".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].auth,
            Some(BgpAuth::Md5 {
                password: "secret".to_string()
            })
        );
    }

    #[test]
    fn set_ao_key_starts_fresh_list_from_none() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetAoKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            key: ao_key(1),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].auth,
            Some(BgpAuth::Ao {
                keys: vec![ao_key(1)]
            })
        );
    }

    #[test]
    fn set_ao_key_upserts_by_send_id() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetAoKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            key: ao_key(1),
        }
        .apply(&mut cfg)
        .unwrap();
        let mut updated = ao_key(1);
        updated.key = "new-secret".to_string();
        BgpPeerGroupOp::SetAoKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            key: updated.clone(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].auth,
            Some(BgpAuth::Ao {
                keys: vec![updated]
            })
        );
    }

    #[test]
    fn remove_ao_key_removes_by_send_id() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetAoKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            key: ao_key(1),
        }
        .apply(&mut cfg)
        .unwrap();
        BgpPeerGroupOp::SetAoKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            key: ao_key(2),
        }
        .apply(&mut cfg)
        .unwrap();
        BgpPeerGroupOp::RemoveAoKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            send_id: 1,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].auth,
            Some(BgpAuth::Ao {
                keys: vec![ao_key(2)]
            })
        );
    }

    #[test]
    fn remove_ao_key_is_noop_when_not_ao() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::RemoveAoKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            send_id: 1,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].auth, None);
    }

    #[test]
    fn set_ao_current_key_sets_only_the_target() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        for id in [1, 2] {
            BgpPeerGroupOp::SetAoKey {
                instance: "r1".to_string(),
                name: "pg1".to_string(),
                key: ao_key(id),
            }
            .apply(&mut cfg)
            .unwrap();
        }
        BgpPeerGroupOp::SetAoCurrentKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            send_id: 1,
        }
        .apply(&mut cfg)
        .unwrap();
        BgpPeerGroupOp::SetAoCurrentKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            send_id: 2,
        }
        .apply(&mut cfg)
        .unwrap();
        let Some(BgpAuth::Ao { keys }) = &cfg.bgp_instances[0].peer_groups[0].auth else {
            panic!("expected Ao auth");
        };
        assert!(!keys.iter().find(|k| k.send_id == 1).unwrap().is_current);
        assert!(keys.iter().find(|k| k.send_id == 2).unwrap().is_current);
    }

    #[test]
    fn set_ao_current_key_missing_id_errors() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetAoKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            key: ao_key(1),
        }
        .apply(&mut cfg)
        .unwrap();
        let err = BgpPeerGroupOp::SetAoCurrentKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            send_id: 9,
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::BgpAoKeyNotFound { send_id, .. } if send_id == 9));
    }

    #[test]
    fn set_ao_current_key_when_no_auth_errors() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        let err = BgpPeerGroupOp::SetAoCurrentKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            send_id: 1,
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::BgpAoKeyNotFound { .. }));
    }

    #[test]
    fn set_ao_rnext_key_sets_only_the_target() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        for id in [1, 2] {
            BgpPeerGroupOp::SetAoKey {
                instance: "r1".to_string(),
                name: "pg1".to_string(),
                key: ao_key(id),
            }
            .apply(&mut cfg)
            .unwrap();
        }
        BgpPeerGroupOp::SetAoRnextKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            send_id: 2,
        }
        .apply(&mut cfg)
        .unwrap();
        let Some(BgpAuth::Ao { keys }) = &cfg.bgp_instances[0].peer_groups[0].auth else {
            panic!("expected Ao auth");
        };
        assert!(!keys.iter().find(|k| k.send_id == 1).unwrap().is_rnext);
        assert!(keys.iter().find(|k| k.send_id == 2).unwrap().is_rnext);
    }

    #[test]
    fn clear_auth_unsets_md5() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetMd5Auth {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            password: "secret".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        BgpPeerGroupOp::ClearAuth {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].auth, None);
    }
}
