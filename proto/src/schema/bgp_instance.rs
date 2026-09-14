use std::net::Ipv4Addr;

use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_in;

use super::{BgpPeer, BgpPeerGroup, Config};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
#[garde(context(Config as ctx))]
pub struct BgpInstance {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, ctx: &Config| unique_in(n, &ctx.bgp_instances, |i| &i.name))
    )]
    pub name: String,

    // Ipv4Addr is structurally valid by construction; no additional garde rule needed.
    #[garde(skip)]
    pub router_id: Ipv4Addr,

    // RFC 6793: ASN 0 and 4_294_967_295 are reserved.
    #[garde(range(min = 1, max = 4_294_967_294u32))]
    pub asn: u32,

    #[garde(dive)]
    pub peer_groups: Vec<BgpPeerGroup>,

    #[garde(dive)]
    pub peers: Vec<BgpPeer>,

    /// The name of the `RoutingTable` that claims this instance (i.e. the
    /// VRF it belongs to), mirrored from that table's `bgp_instance` field.
    /// Derived and read-only: never set by any `BgpInstanceOp`, recomputed
    /// by `nos-config` (`crate::derive::sync_routing_table_refs`) on every
    /// commit and on load, so an operator only ever edits the one
    /// authoritative reference (`RoutingTable.bgp_instance`). `nos-bgpd`
    /// reads this directly to resolve its own VRF without scanning every
    /// routing table. Deliberately not rendered by `nos-cli`.
    #[garde(skip)]
    pub routing_table: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use garde::Validate as _;

    use crate::schema::Config;

    use super::BgpInstance;

    fn instance(name: &str, asn: u32) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn,
            peer_groups: Vec::new(),
            peers: Vec::new(),
            routing_table: None,
        }
    }

    fn config_with(instances: Vec<BgpInstance>) -> Config {
        Config {
            bgp_instances: instances,
            ..Default::default()
        }
    }

    #[test]
    fn valid_instance_passes() {
        let cfg = config_with(vec![instance("default", 65000)]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn asn_zero_fails() {
        let cfg = config_with(vec![instance("default", 0)]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn asn_max_reserved_fails() {
        let cfg = config_with(vec![instance("default", 4_294_967_295)]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_name_fails() {
        let cfg = config_with(vec![instance("vrf-a", 65001), instance("vrf-a", 65002)]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn distinct_names_pass() {
        let cfg = config_with(vec![instance("vrf-a", 65001), instance("vrf-b", 65002)]);
        cfg.validate_with(&cfg).unwrap();
    }
}
