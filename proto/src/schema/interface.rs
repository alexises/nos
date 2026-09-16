use garde::Validate;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::validators::unique_in;

use super::Config;

/// Any `Interface.name` starting with this prefix is a loopback interface
/// for the routing table named by the rest of the string (e.g.
/// `loopback-rt1` is a loopback for routing table `rt1`) — see
/// `loopback_table_name`. There is no separate "kind" field: identity is
/// carried entirely by the name, which also means the existing
/// `Interface.name` uniqueness check already guarantees at most one
/// loopback per routing table, for free.
pub const LOOPBACK_PREFIX: &str = "loopback-";

/// Extracts the target routing table name from a loopback interface name,
/// or `None` if `name` isn't a loopback (doesn't start with
/// `LOOPBACK_PREFIX`, or has nothing after it). Shared by `nos-config`'s
/// commit-time validation (below) and `nos-interfaced`'s Linux driver,
/// which both need the identical rule.
pub fn loopback_table_name(name: &str) -> Option<&str> {
    name.strip_prefix(LOOPBACK_PREFIX).filter(|t| !t.is_empty())
}

/// One address on an interface, with an optional label. The label is
/// stored from commit time onward but not yet applied to the kernel by any
/// driver (no `ip addr ... label` call) — schema/plumbing only for now.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InterfaceAddress {
    pub address: IpNet,
    pub label: Option<String>,
}

/// A named network interface, with zero or more IP addresses and an
/// optional routing table (VRF) assignment. Unlike `RoutingTable`'s
/// `bgp_instance`/`static_routing_instance` references, many interfaces may
/// share the same `routing_table` — a routing table already plays the VRF
/// role, and a VRF naturally has more than one interface in it. Not
/// consulted for a loopback interface (see `LOOPBACK_PREFIX`) — its target
/// table comes from its name instead.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
#[garde(context(Config as ctx))]
pub struct Interface {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, ctx: &Config| interface_name_valid(n, ctx))
    )]
    pub name: String,

    #[garde(custom(|addrs, _ctx: &Config| unique_addresses(addrs)))]
    pub addresses: Vec<InterfaceAddress>,

    #[garde(custom(|rt: &Option<String>, ctx: &Config| routing_table_reference_valid(rt.as_ref(), ctx)))]
    pub routing_table: Option<String>,
}

/// Combines interface-name uniqueness (existing) with, for a loopback name,
/// checking its target routing table actually exists — one closure rather
/// than stacking two `custom(...)` attributes, matching the pattern used
/// where a field needs more than one rule (e.g. `BgpPeerGroup.auth`'s
/// `valid_auth`).
fn interface_name_valid(name: &String, ctx: &Config) -> garde::Result {
    unique_in(name, &ctx.interfaces, |i| &i.name)?;
    if let Some(table) = loopback_table_name(name) {
        if !ctx.routing_tables.iter().any(|t| t.name == table) {
            return Err(garde::Error::new(
                "loopback interface's routing table does not exist",
            ));
        }
    }
    Ok(())
}

/// No two addresses on the same interface may repeat, mirroring
/// `static_routing_instance::unique_subnets`. Scoped to `self.addresses`
/// only, since this uniqueness is per-interface, not global. Compares
/// `.address` only — two entries can't have the same address with
/// different labels either, since `AddAddress` upserts by address.
fn unique_addresses(addresses: &[InterfaceAddress]) -> garde::Result {
    let mut seen: Vec<IpNet> = Vec::new();
    for addr in addresses {
        if seen.contains(&addr.address) {
            return Err(garde::Error::new(
                "must not repeat an address on the same interface",
            ));
        }
        seen.push(addr.address);
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
            addresses: addresses
                .iter()
                .map(|a| InterfaceAddress {
                    address: a.parse().unwrap(),
                    label: None,
                })
                .collect(),
            routing_table: routing_table.map(str::to_string),
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

    #[test]
    fn loopback_name_with_existing_table_passes() {
        let cfg = config_with(
            vec![interface("loopback-rt1", &[], None)],
            vec![table("rt1")],
        );
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn loopback_name_with_missing_table_fails() {
        let cfg = config_with(vec![interface("loopback-rt1", &[], None)], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn loopback_prefix_with_empty_suffix_is_not_a_loopback() {
        // "loopback-" alone has nothing after the prefix, so it's treated
        // as an ordinary interface name — no routing table required.
        let cfg = config_with(vec![interface("loopback-", &[], None)], vec![]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn physical_interface_name_unaffected_by_loopback_check() {
        let cfg = config_with(vec![interface("eth0", &[], None)], vec![]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_loopback_name_rejected_by_existing_uniqueness() {
        // Two interfaces targeting the same table via the naming
        // convention would need the identical name, already rejected by
        // ordinary name uniqueness — no separate "one loopback per table"
        // validator needed.
        let cfg = config_with(
            vec![
                interface("loopback-rt1", &[], None),
                interface("loopback-rt1", &[], None),
            ],
            vec![table("rt1")],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn loopback_table_name_parses_prefix() {
        assert_eq!(loopback_table_name("loopback-rt1"), Some("rt1"));
        assert_eq!(loopback_table_name("loopback-"), None);
        assert_eq!(loopback_table_name("eth0"), None);
        assert_eq!(loopback_table_name("loopback"), None);
    }

    #[test]
    fn duplicate_address_different_label_still_conflicts() {
        let cfg = config_with(
            vec![Interface {
                name: "eth0".to_string(),
                addresses: vec![
                    InterfaceAddress {
                        address: "10.0.0.1/24".parse().unwrap(),
                        label: Some("a".to_string()),
                    },
                    InterfaceAddress {
                        address: "10.0.0.1/24".parse().unwrap(),
                        label: Some("b".to_string()),
                    },
                ],
                routing_table: None,
            }],
            vec![],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }
}
