use garde::Validate;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::validators::unique_in;

use super::Config;

/// A named network interface, with zero or more IP addresses and an
/// optional routing table (VRF) assignment. Unlike `RoutingTable`'s
/// `bgp_instance`/`static_routing_instance` references, many interfaces may
/// share the same `routing_table` — a routing table already plays the VRF
/// role, and a VRF naturally has more than one interface in it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
#[garde(context(Config as ctx))]
pub struct Interface {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, ctx: &Config| unique_in(n, &ctx.interfaces, |i| &i.name))
    )]
    pub name: String,

    #[garde(custom(|addrs, _ctx: &Config| unique_addresses(addrs)))]
    pub addresses: Vec<IpNet>,

    #[garde(custom(|rt: &Option<String>, ctx: &Config| routing_table_reference_valid(rt.as_ref(), ctx)))]
    pub routing_table: Option<String>,
}

/// No two addresses on the same interface may repeat, mirroring
/// `static_routing_instance::unique_subnets`. Scoped to `self.addresses`
/// only, since this uniqueness is per-interface, not global.
fn unique_addresses(addresses: &[IpNet]) -> garde::Result {
    let mut seen: Vec<IpNet> = Vec::new();
    for addr in addresses {
        if seen.contains(addr) {
            return Err(garde::Error::new(
                "must not repeat an address on the same interface",
            ));
        }
        seen.push(*addr);
    }
    Ok(())
}

/// If set, `routing_table` must name an existing `RoutingTable`. Unlike
/// `RoutingTable.bgp_instance`/`static_routing_instance`, there is no
/// single-owner constraint here — many interfaces may be assigned to the
/// same routing table/VRF.
fn routing_table_reference_valid(routing_table: Option<&String>, ctx: &Config) -> garde::Result {
    let Some(name) = routing_table else {
        return Ok(());
    };
    if !ctx.routing_tables.iter().any(|t| &t.name == name) {
        return Err(garde::Error::new("referenced routing table does not exist"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::schema::{Config, RoutingTable};

    use super::*;

    fn interface(name: &str, addresses: &[&str], routing_table: Option<&str>) -> Interface {
        Interface {
            name: name.to_string(),
            addresses: addresses.iter().map(|a| a.parse().unwrap()).collect(),
            routing_table: routing_table.map(str::to_string),
        }
    }

    fn table(name: &str) -> RoutingTable {
        RoutingTable {
            name: name.to_string(),
            bgp_instance: None,
            static_routing_instance: None,
        }
    }

    fn config_with(interfaces: Vec<Interface>, tables: Vec<RoutingTable>) -> Config {
        Config {
            interfaces,
            routing_tables: tables,
            ..Default::default()
        }
    }

    #[test]
    fn valid_interface_with_no_associations_passes() {
        let cfg = config_with(vec![interface("eth0", &[], None)], vec![]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn valid_interface_with_addresses_and_routing_table_passes() {
        let cfg = config_with(
            vec![interface(
                "eth0",
                &["10.0.0.1/24", "2001:db8::1/64"],
                Some("rt1"),
            )],
            vec![table("rt1")],
        );
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_interface_name_fails() {
        let cfg = config_with(
            vec![interface("eth0", &[], None), interface("eth0", &[], None)],
            vec![],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_address_on_same_interface_fails() {
        let cfg = config_with(
            vec![interface("eth0", &["10.0.0.1/24", "10.0.0.1/24"], None)],
            vec![],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn same_address_on_different_interfaces_passes() {
        let cfg = config_with(
            vec![
                interface("eth0", &["10.0.0.1/24"], None),
                interface("eth1", &["10.0.0.1/24"], None),
            ],
            vec![],
        );
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn dangling_routing_table_reference_fails() {
        let cfg = config_with(vec![interface("eth0", &[], Some("does-not-exist"))], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn multiple_interfaces_may_share_a_routing_table() {
        let cfg = config_with(
            vec![
                interface("eth0", &[], Some("rt1")),
                interface("eth1", &[], Some("rt1")),
            ],
            vec![table("rt1")],
        );
        cfg.validate_with(&cfg).unwrap();
    }
}
