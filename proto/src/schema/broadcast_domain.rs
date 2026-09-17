use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::{routing_table_reference_valid, unique_addresses, unique_in};

use super::{Config, InterfaceAddress};

/// A named L2 broadcast domain. `SwitchingProfile` references it for L2
/// membership; `addresses`/`routing_table` independently make the domain's
/// own bridge device an SVI (switch virtual interface) — a routed L3
/// attachment point for the domain as a whole, the same flat shape as a
/// loopback `Interface`'s L3 config (no VLAN/tag concept applies to a
/// domain's own bridge, so there's nothing for per-tag addressing to buy
/// it). The bridge device and whatever interfaces are enslaved into it as L2
/// members are separate Linux links, so there is no conflict between this
/// and any member's own VRF assignment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
#[garde(context(Config as ctx))]
pub struct BroadcastDomain {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, ctx: &Config| unique_in(n, &ctx.broadcast_domains, |d| &d.name))
    )]
    pub name: String,

    #[garde(custom(|addrs, _ctx: &Config| unique_addresses(addrs)))]
    pub addresses: Vec<InterfaceAddress>,

    #[garde(custom(|rt: &Option<String>, ctx: &Config| routing_table_reference_valid(rt.as_ref(), ctx)))]
    pub routing_table: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::RoutingTable;

    fn domain(name: &str) -> BroadcastDomain {
        BroadcastDomain {
            name: name.to_string(),
            addresses: Vec::new(),
            routing_table: None,
        }
    }

    fn table(name: &str) -> RoutingTable {
        RoutingTable {
            name: name.to_string(),
            bgp_instance: None,
            static_routing_instance: None,
            redistribute: None,
        }
    }

    fn config_with(domains: Vec<BroadcastDomain>, tables: Vec<RoutingTable>) -> Config {
        Config {
            broadcast_domains: domains,
            routing_tables: tables,
            ..Default::default()
        }
    }

    #[test]
    fn valid_domain_passes() {
        let cfg = config_with(vec![domain("bd1")], vec![]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_name_fails() {
        let cfg = config_with(vec![domain("bd1"), domain("bd1")], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn empty_name_fails() {
        let mut d = domain("bd1");
        d.name = String::new();
        let cfg = config_with(vec![d], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn valid_addresses_and_routing_table_pass() {
        let mut d = domain("bd1");
        d.addresses = vec![InterfaceAddress {
            address: "10.0.0.1/24".parse().unwrap(),
            label: None,
        }];
        d.routing_table = Some("rt1".to_string());
        let cfg = config_with(vec![d], vec![table("rt1")]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_address_fails() {
        let mut d = domain("bd1");
        d.addresses = vec![
            InterfaceAddress {
                address: "10.0.0.1/24".parse().unwrap(),
                label: None,
            },
            InterfaceAddress {
                address: "10.0.0.1/24".parse().unwrap(),
                label: None,
            },
        ];
        let cfg = config_with(vec![d], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn dangling_routing_table_reference_fails() {
        let mut d = domain("bd1");
        d.routing_table = Some("does-not-exist".to_string());
        let cfg = config_with(vec![d], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }
}
