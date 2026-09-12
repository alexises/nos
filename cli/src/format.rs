use nos_proto::{BgpInstance, Config, TransactionSnapshot};

use crate::session::Path;

/// Render one BGP instance as human-readable text.
pub fn render_bgp_instance(instance: &BgpInstance) -> String {
    format!(
        "bgp instance {}: router-id {}, asn {}",
        instance.name, instance.router_id, instance.asn
    )
}

/// Render a full running-config snapshot as human-readable text.
pub fn render_config(config: &Config) -> String {
    let mut lines = vec![format!("hostname: {}", config.hostname)];
    if config.bgp_instances.is_empty() {
        lines.push("no BGP instances configured".to_string());
    } else {
        lines.extend(config.bgp_instances.iter().map(render_bgp_instance));
    }
    lines.join("\n")
}

/// Render a transaction's in-progress config, scoped to the current
/// navigation path: the whole config at `Path::Root`, or a single BGP
/// instance at `Path::BgpInstance(name)`.
pub fn render_transaction(snapshot: &TransactionSnapshot, path: &Path) -> String {
    match path {
        Path::Root => {
            let header = if snapshot.dirty {
                format!("transaction '{}' (uncommitted changes):", snapshot.name)
            } else {
                format!("transaction '{}':", snapshot.name)
            };
            format!("{header}\n{}", render_config(&snapshot.config))
        }
        Path::BgpInstance(name) => snapshot
            .config
            .bgp_instances
            .iter()
            .find(|i| &i.name == name)
            .map_or_else(
                || format!("bgp instance '{name}' not found"),
                render_bgp_instance,
            ),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use nos_proto::BgpInstance;

    use super::*;

    fn instance(name: &str, asn: u32) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn,
        }
    }

    #[test]
    fn empty_config() {
        let cfg = Config::default();
        assert_eq!(
            render_config(&cfg),
            "hostname: nos\nno BGP instances configured"
        );
    }

    #[test]
    fn single_instance() {
        let cfg = Config {
            bgp_instances: vec![instance("default", 65000)],
            ..Default::default()
        };
        assert_eq!(
            render_config(&cfg),
            "hostname: nos\nbgp instance default: router-id 1.1.1.1, asn 65000"
        );
    }

    #[test]
    fn multiple_instances() {
        let cfg = Config {
            bgp_instances: vec![instance("vrf-a", 65001), instance("vrf-b", 65002)],
            ..Default::default()
        };
        assert_eq!(
            render_config(&cfg),
            "hostname: nos\nbgp instance vrf-a: router-id 1.1.1.1, asn 65001\n\
             bgp instance vrf-b: router-id 1.1.1.1, asn 65002"
        );
    }

    fn snapshot(dirty: bool) -> TransactionSnapshot {
        TransactionSnapshot {
            name: "demo".to_string(),
            config: Config {
                bgp_instances: vec![instance("r1", 65001)],
                ..Default::default()
            },
            dirty,
            resumed: false,
        }
    }

    #[test]
    fn render_transaction_at_root_clean() {
        let rendered = render_transaction(&snapshot(false), &Path::Root);
        assert_eq!(
            rendered,
            "transaction 'demo':\nhostname: nos\nbgp instance r1: router-id 1.1.1.1, asn 65001"
        );
    }

    #[test]
    fn render_transaction_at_root_dirty() {
        let rendered = render_transaction(&snapshot(true), &Path::Root);
        assert!(rendered.starts_with("transaction 'demo' (uncommitted changes):"));
    }

    #[test]
    fn render_transaction_at_bgp_instance_found() {
        let rendered = render_transaction(&snapshot(false), &Path::BgpInstance("r1".to_string()));
        assert_eq!(rendered, "bgp instance r1: router-id 1.1.1.1, asn 65001");
    }

    #[test]
    fn render_transaction_at_bgp_instance_not_found() {
        let rendered = render_transaction(&snapshot(false), &Path::BgpInstance("r2".to_string()));
        assert_eq!(rendered, "bgp instance 'r2' not found");
    }
}
