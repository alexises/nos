use std::collections::HashMap;

use nos_proto::{Config, IpNet};
use tracing::info;

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
/// (today: logging) each interface's desired state along the way.
pub fn build_from_config(cfg: &Config) -> Interfaces {
    let mut by_name = HashMap::with_capacity(cfg.interfaces.len());
    for iface in &cfg.interfaces {
        let state = InterfaceState {
            name: iface.name.clone(),
            addresses: iface.addresses.clone(),
            routing_table: iface.routing_table.clone(),
        };
        apply_interface(&state);
        by_name.insert(state.name.clone(), state);
    }
    Interfaces { by_name }
}

/// Placeholder for real OS application. Logs the state `nos-interfaced`
/// would apply — addresses, routing-table/VRF assignment — but does not
/// touch the OS network stack yet. Real application (e.g. via the
/// `rtnetlink` crate, adding/removing addresses and binding the interface to
/// its routing table's VRF device) is a follow-up; see `CLAUDE.md`.
fn apply_interface(iface: &InterfaceState) {
    info!(
        interface = %iface.name,
        addresses = ?iface.addresses,
        routing_table = ?iface.routing_table,
        "would apply interface configuration (placeholder — no OS effect yet)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use nos_proto::Interface;

    fn cfg(interfaces: Vec<Interface>) -> Config {
        Config {
            interfaces,
            ..Default::default()
        }
    }

    #[test]
    fn build_from_config_with_no_interfaces_is_empty() {
        let interfaces = build_from_config(&cfg(vec![]));
        assert!(interfaces.is_empty());
    }

    #[test]
    fn build_from_config_maps_each_interface() {
        let interfaces = build_from_config(&cfg(vec![Interface {
            name: "eth0".to_string(),
            addresses: vec!["10.0.0.1/24".parse().unwrap()],
            routing_table: Some("rt1".to_string()),
        }]));
        let iface = interfaces.get("eth0").unwrap();
        assert_eq!(iface.addresses, vec!["10.0.0.1/24".parse().unwrap()]);
        assert_eq!(iface.routing_table.as_deref(), Some("rt1"));
    }

    #[test]
    fn get_missing_interface_is_none() {
        let interfaces = build_from_config(&cfg(vec![]));
        assert!(interfaces.get("eth0").is_none());
    }

    #[test]
    fn all_is_sorted_by_name() {
        let interfaces = build_from_config(&cfg(vec![
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
        ]));
        let all = interfaces.all();
        let names: Vec<&str> = all.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["eth0", "eth1"]);
    }
}
