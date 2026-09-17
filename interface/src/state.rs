use std::collections::{HashMap, HashSet};

use nos_proto::{Config, InterfaceAddress, VlanTag};
use tracing::{debug, trace, warn};

use crate::driver::InterfaceDriver;

/// One interface's desired state, as reconciled from the running config.
#[derive(Debug, Clone, PartialEq)]
pub struct InterfaceState {
    pub name: String,
    pub addresses: Vec<InterfaceAddress>,
    pub routing_table: Option<String>,
    /// The raw `Interface.switching_profile` name, same shape as
    /// `routing_table` — for status display.
    pub switching_profile: Option<String>,
    /// `switching_profile` resolved to its `SwitchingProfile`'s member
    /// list — pure local config, unlike `routing_table`'s VRF name, so no
    /// cross-daemon IPC is needed to resolve it here; the driver interprets
    /// each `(domain, tag)` pair directly. Empty if `switching_profile` is
    /// unset (or names a profile that doesn't exist, which commit-time
    /// validation already prevents).
    pub switching_profile_members: Vec<(String, VlanTag)>,
}

/// Every configured interface's desired state, rebuilt wholesale on every
/// resync (see `crate::reconcile`) — mirrors `nos-rib`'s `Rib`.
#[derive(Debug, Clone, Default)]
pub struct Interfaces {
    by_name: HashMap<String, InterfaceState>,
    /// Every `BroadcastDomain` name configured as of the last resync —
    /// tracked purely so the next resync can diff for domains removed from
    /// config and call `driver.remove_broadcast_domain`, the same
    /// "previous vs current, call remove for what's gone" shape `by_name`
    /// itself already uses for interfaces. Not exposed over IPC — nothing
    /// queries domains through `nos-interfaced`.
    domains: HashSet<String>,
}

impl Interfaces {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, name: &str) -> Option<&InterfaceState> {
        self.by_name.get(name)
    }

    /// Every interface, ordered by name — for serving an unfiltered
    /// `show interface` query.
    pub fn all(&self) -> Vec<InterfaceState> {
        let mut interfaces: Vec<InterfaceState> = self.by_name.values().cloned().collect();
        interfaces.sort_by(|a, b| a.name.cmp(&b.name));
        interfaces
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

/// Builds a fresh `Interfaces` from a freshly fetched `Config`, applying
/// each interface's desired state via `driver` along the way, and calling
/// `driver.remove` for every interface present in `previous` but absent
/// from `cfg` (removed from config outright). Broadcast domain bridges are
/// reconciled first, in the same pass — an interface's switching-profile
/// enslavement below resolves each bridge by name, so it must already
/// exist (or the driver treats it as the ordinary transient
/// not-ready-yet case and retries on the next resync).
pub async fn build_from_config(
    cfg: &Config,
    driver: &dyn InterfaceDriver,
    previous: &Interfaces,
) -> Interfaces {
    for domain in &cfg.broadcast_domains {
        if let Err(e) = driver.ensure_broadcast_domain(&domain.name).await {
            warn!(domain = %domain.name, error = %e, "failed to ensure broadcast domain bridge");
        }
    }
    let domains: HashSet<String> = cfg
        .broadcast_domains
        .iter()
        .map(|d| d.name.clone())
        .collect();
    for gone in previous
        .domains
        .iter()
        .filter(|name| !domains.contains(name.as_str()))
    {
        debug!(domain = %gone, "broadcast domain removed from config, cleaning up");
        if let Err(e) = driver.remove_broadcast_domain(gone).await {
            warn!(domain = %gone, error = %e, "failed to clean up removed broadcast domain");
        }
    }

    let mut by_name = HashMap::with_capacity(cfg.interfaces.len());
    for iface in &cfg.interfaces {
        let switching_profile_members = iface
            .switching_profile
            .as_deref()
            .and_then(|name| cfg.switching_profiles.iter().find(|p| p.name == name))
            .map(|p| {
                p.members
                    .iter()
                    .map(|m| (m.broadcast_domain.clone(), m.tag))
                    .collect()
            })
            .unwrap_or_default();
        let state = InterfaceState {
            name: iface.name.clone(),
            addresses: iface.addresses.clone(),
            routing_table: iface.routing_table.clone(),
            switching_profile: iface.switching_profile.clone(),
            switching_profile_members,
        };
        trace!(
            interface = %state.name,
            addresses = ?state.addresses,
            routing_table = ?state.routing_table,
            switching_profile_members = ?state.switching_profile_members,
            "applying interface state"
        );
        if let Err(e) = driver.apply(&state).await {
            warn!(interface = %state.name, error = %e, "failed to apply interface configuration");
        }
        by_name.insert(state.name.clone(), state);
    }

    let current: HashSet<&str> = by_name.keys().map(String::as_str).collect();
    for gone in previous
        .all()
        .iter()
        .map(|i| i.name.clone())
        .filter(|name| !current.contains(name.as_str()))
    {
        debug!(interface = %gone, "interface removed from config, cleaning up");
        if let Err(e) = driver.remove(&gone).await {
            warn!(interface = %gone, error = %e, "failed to clean up removed interface");
        }
    }

    Interfaces { by_name, domains }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use nos_proto::Interface;

    use super::*;
    use crate::driver::{DriverError, NoopInterfaceDriver};

    fn cfg(interfaces: Vec<Interface>) -> Config {
        Config {
            interfaces,
            ..Default::default()
        }
    }

    /// Records every `apply`/`remove` call it receives, for asserting on
    /// what `build_from_config` did without needing to observe log output.
    #[derive(Debug, Clone, PartialEq)]
    enum Call {
        Apply(String),
        Remove(String),
        EnsureDomain(String),
        RemoveDomain(String),
    }

    #[derive(Default)]
    struct RecordingDriver {
        calls: Mutex<Vec<Call>>,
    }

    #[async_trait]
    impl InterfaceDriver for RecordingDriver {
        async fn apply(&self, desired: &InterfaceState) -> Result<(), DriverError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::Apply(desired.name.clone()));
            Ok(())
        }

        async fn remove(&self, name: &str) -> Result<(), DriverError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::Remove(name.to_string()));
            Ok(())
        }

        async fn ensure_broadcast_domain(&self, domain: &str) -> Result<(), DriverError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::EnsureDomain(domain.to_string()));
            Ok(())
        }

        async fn remove_broadcast_domain(&self, domain: &str) -> Result<(), DriverError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::RemoveDomain(domain.to_string()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn build_from_config_with_no_interfaces_is_empty() {
        let interfaces =
            build_from_config(&cfg(vec![]), &NoopInterfaceDriver, &Interfaces::new()).await;
        assert!(interfaces.is_empty());
    }

    #[tokio::test]
    async fn build_from_config_maps_each_interface() {
        let iface_addr = InterfaceAddress {
            address: "10.0.0.1/24".parse().unwrap(),
            label: None,
        };
        let interfaces = build_from_config(
            &cfg(vec![Interface {
                name: "eth0".to_string(),
                addresses: vec![iface_addr.clone()],
                routing_table: Some("rt1".to_string()),
                switching_profile: None,
            }]),
            &NoopInterfaceDriver,
            &Interfaces::new(),
        )
        .await;
        let iface = interfaces.get("eth0").unwrap();
        assert_eq!(iface.addresses, vec![iface_addr]);
        assert_eq!(iface.routing_table.as_deref(), Some("rt1"));
    }

    #[tokio::test]
    async fn get_missing_interface_is_none() {
        let interfaces =
            build_from_config(&cfg(vec![]), &NoopInterfaceDriver, &Interfaces::new()).await;
        assert!(interfaces.get("eth0").is_none());
    }

    #[tokio::test]
    async fn all_is_sorted_by_name() {
        let interfaces = build_from_config(
            &cfg(vec![
                Interface {
                    name: "eth1".to_string(),
                    addresses: vec![],
                    routing_table: None,
                    switching_profile: None,
                },
                Interface {
                    name: "eth0".to_string(),
                    addresses: vec![],
                    routing_table: None,
                    switching_profile: None,
                },
            ]),
            &NoopInterfaceDriver,
            &Interfaces::new(),
        )
        .await;
        let all = interfaces.all();
        let names: Vec<&str> = all.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["eth0", "eth1"]);
    }

    #[tokio::test]
    async fn apply_is_called_for_every_configured_interface() {
        let driver = RecordingDriver::default();
        build_from_config(
            &cfg(vec![
                Interface {
                    name: "eth0".to_string(),
                    addresses: vec![],
                    routing_table: None,
                    switching_profile: None,
                },
                Interface {
                    name: "eth1".to_string(),
                    addresses: vec![],
                    routing_table: None,
                    switching_profile: None,
                },
            ]),
            &driver,
            &Interfaces::new(),
        )
        .await;
        let calls = driver.calls.lock().unwrap().clone();
        assert!(calls.contains(&Call::Apply("eth0".to_string())));
        assert!(calls.contains(&Call::Apply("eth1".to_string())));
    }

    #[tokio::test]
    async fn remove_is_called_for_interface_dropped_from_config() {
        let driver = RecordingDriver::default();
        let previous = build_from_config(
            &cfg(vec![
                Interface {
                    name: "eth0".to_string(),
                    addresses: vec![],
                    routing_table: None,
                    switching_profile: None,
                },
                Interface {
                    name: "eth1".to_string(),
                    addresses: vec![],
                    routing_table: None,
                    switching_profile: None,
                },
            ]),
            &NoopInterfaceDriver,
            &Interfaces::new(),
        )
        .await;

        build_from_config(
            &cfg(vec![Interface {
                name: "eth0".to_string(),
                addresses: vec![],
                routing_table: None,
                switching_profile: None,
            }]),
            &driver,
            &previous,
        )
        .await;

        let calls = driver.calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![
                Call::Apply("eth0".to_string()),
                Call::Remove("eth1".to_string())
            ]
        );
    }

    #[tokio::test]
    async fn switching_profile_resolves_to_member_list() {
        let mut config = cfg(vec![Interface {
            name: "eth0".to_string(),
            addresses: vec![],
            routing_table: None,
            switching_profile: Some("sp1".to_string()),
        }]);
        config.switching_profiles = vec![nos_proto::SwitchingProfile {
            name: "sp1".to_string(),
            members: vec![nos_proto::SwitchingProfileMember {
                broadcast_domain: "bd1".to_string(),
                tag: VlanTag::Dot1q(100),
            }],
        }];
        let interfaces = build_from_config(&config, &NoopInterfaceDriver, &Interfaces::new()).await;
        let iface = interfaces.get("eth0").unwrap();
        assert_eq!(
            iface.switching_profile_members,
            vec![("bd1".to_string(), VlanTag::Dot1q(100))]
        );
    }

    #[tokio::test]
    async fn unset_switching_profile_resolves_to_empty_members() {
        let interfaces = build_from_config(
            &cfg(vec![Interface {
                name: "eth0".to_string(),
                addresses: vec![],
                routing_table: None,
                switching_profile: None,
            }]),
            &NoopInterfaceDriver,
            &Interfaces::new(),
        )
        .await;
        assert!(interfaces
            .get("eth0")
            .unwrap()
            .switching_profile_members
            .is_empty());
    }

    #[tokio::test]
    async fn ensure_broadcast_domain_is_called_for_every_configured_domain() {
        let driver = RecordingDriver::default();
        let mut config = cfg(vec![]);
        config.broadcast_domains = vec![
            nos_proto::BroadcastDomain {
                name: "bd1".to_string(),
            },
            nos_proto::BroadcastDomain {
                name: "bd2".to_string(),
            },
        ];
        build_from_config(&config, &driver, &Interfaces::new()).await;
        let calls = driver.calls.lock().unwrap().clone();
        assert!(calls.contains(&Call::EnsureDomain("bd1".to_string())));
        assert!(calls.contains(&Call::EnsureDomain("bd2".to_string())));
    }

    #[tokio::test]
    async fn remove_broadcast_domain_is_called_for_domain_dropped_from_config() {
        let driver = RecordingDriver::default();
        let mut config_with_domain = cfg(vec![]);
        config_with_domain.broadcast_domains = vec![nos_proto::BroadcastDomain {
            name: "bd1".to_string(),
        }];
        let previous = build_from_config(&config_with_domain, &driver, &Interfaces::new()).await;

        build_from_config(&cfg(vec![]), &driver, &previous).await;

        let calls = driver.calls.lock().unwrap().clone();
        assert!(calls.contains(&Call::RemoveDomain("bd1".to_string())));
    }
}
