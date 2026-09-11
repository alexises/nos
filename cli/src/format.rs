use nos_proto::Config;

/// Render a full running-config snapshot as human-readable text.
pub fn render_config(config: &Config) -> String {
    if config.bgp_instances.is_empty() {
        return "no BGP instances configured".to_string();
    }
    config
        .bgp_instances
        .iter()
        .map(|i| {
            format!(
                "bgp instance {}: router-id {}, asn {}",
                i.name, i.router_id, i.asn
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
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
        assert_eq!(render_config(&cfg), "no BGP instances configured");
    }

    #[test]
    fn single_instance() {
        let cfg = Config {
            bgp_instances: vec![instance("default", 65000)],
        };
        assert_eq!(
            render_config(&cfg),
            "bgp instance default: router-id 1.1.1.1, asn 65000"
        );
    }

    #[test]
    fn multiple_instances() {
        let cfg = Config {
            bgp_instances: vec![instance("vrf-a", 65001), instance("vrf-b", 65002)],
        };
        assert_eq!(
            render_config(&cfg),
            "bgp instance vrf-a: router-id 1.1.1.1, asn 65001\n\
             bgp instance vrf-b: router-id 1.1.1.1, asn 65002"
        );
    }
}
