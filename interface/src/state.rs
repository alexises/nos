use std::collections::{HashMap, HashSet};

use nos_proto::{Config, IpNet};
use tracing::warn;

use crate::driver::InterfaceDriver;

/// One interface's desired state, as reconciled from the running config.
#[derive(Debug, Clone, PartialEq)]
pub struct InterfaceState {
    pub name: String,
    pub addresses: Vec<IpNet>,
    pub routing_table: Option<String>,
}

/// Every configured interface's desired state, rebuilt wholesale on every
/// resync (see `crate::reconcile`) — mirrors `nos-rib`'s `Rib`.
#[derive(Debug, Clone, Default)]
pub struct Interfaces {
    by_name: HashMap<String, InterfaceState>,
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
/// from `cfg` (removed from config outright).
pub async fn build_from_config(
    cfg: &Config,
    driver: &dyn InterfaceDriver,
    previous: &Interfaces,
) -> Interfaces {
    let mut by_name = HashMap::with_capacity(cfg.interfaces.len());
    for iface in &cfg.interfaces {
        let state = InterfaceState {
            name: iface.name.clone(),
            addresses: iface.addresses.clone(),
            routing_table: iface.routing_table.clone(),
        };
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
        if let Err(e) = driver.remove(&gone).await {
            warn!(interface = %gone, error = %e, "failed to clean up removed interface");
        }
    }

    Interfaces { by_name }
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
    }

    #[tokio::test]
    async fn build_from_config_with_no_interfaces_is_empty() {
        let interfaces =
            build_from_config(&cfg(vec![]), &NoopInterfaceDriver, &Interfaces::new()).await;
        assert!(interfaces.is_empty());
    }

    #[tokio::test]
    async fn build_from_config_maps_each_interface() {
        let interfaces = build_from_config(
            &cfg(vec![Interface {
                name: "eth0".to_string(),
                addresses: vec!["10.0.0.1/24".parse().unwrap()],
                routing_table: Some("rt1".to_string()),
            }]),
            &NoopInterfaceDriver,
            &Interfaces::new(),
        )
        .await;
        let iface = interfaces.get("eth0").unwrap();
        assert_eq!(iface.addresses, vec!["10.0.0.1/24".parse().unwrap()]);
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
                },
                Interface {
                    name: "eth0".to_string(),
                    addresses: vec![],
                    routing_table: None,
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
                },
                Interface {
                    name: "eth1".to_string(),
                    addresses: vec![],
                    routing_table: None,
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
                },
                Interface {
                    name: "eth1".to_string(),
                    addresses: vec![],
                    routing_table: None,
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
}
