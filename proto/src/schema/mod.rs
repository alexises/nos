pub mod bgp_instance;
pub mod bgp_peer;
pub mod bgp_peer_group;
pub mod broadcast_domain;
pub mod community_alias;
pub mod community_group;
pub mod interface;
pub mod ospf_area;
pub mod ospf_instance;
pub mod ospf_profile;
pub mod policy_definition;
pub mod prefix_list;
pub mod routing_table;
pub mod static_route;
pub mod static_routing_instance;
pub mod switching_profile;

pub use bgp_instance::BgpInstance;
pub use bgp_peer::BgpPeer;
pub use bgp_peer_group::{
    AddressFamily, BgpAoAlgorithm, BgpAoKey, BgpAuth, BgpPeerGroup, NextHopMode, SourceAddress,
    CONNECT_RETRY_TIME_DEFAULT_SECS, HOLD_TIME_DEFAULT, HOLD_TIME_FLOOR,
};
pub use broadcast_domain::BroadcastDomain;
pub use community_alias::CommunityAlias;
pub use community_group::CommunityGroup;
pub use interface::{
    loopback_table_name, Interface, InterfaceAddress, Subinterface, LOOPBACK_PREFIX,
};
pub use ospf_area::OspfArea;
pub use ospf_instance::OspfInstance;
pub use ospf_profile::{OspfProfile, DEAD_INTERVAL_DEFAULT, HELLO_INTERVAL_DEFAULT};
pub use policy_definition::PolicyDefinition;
pub use prefix_list::{PrefixList, PrefixListEntry};
pub use routing_table::{Redistribute, RedistributeSource, RedistributeTarget, RoutingTable};
pub use static_route::StaticRoute;
pub use static_routing_instance::StaticRoutingInstance;
pub use switching_profile::{SwitchingProfile, SwitchingProfileMember, VlanTag};

use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::hostname_charset;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
#[garde(context(Config as ctx))]
pub struct Config {
    #[garde(
        dive,
        custom(|instances, _ctx: &Config| bgp_instance::valid_route_reflection_and_server(instances))
    )]
    pub bgp_instances: Vec<BgpInstance>,

    #[garde(
        dive,
        custom(|tables, ctx: &Config| routing_table::valid_redistribute_rules(tables, ctx))
    )]
    pub routing_tables: Vec<RoutingTable>,

    #[garde(dive)]
    pub ospf_instances: Vec<OspfInstance>,

    #[garde(dive)]
    pub static_routing_instances: Vec<StaticRoutingInstance>,

    #[garde(
        dive,
        custom(|interfaces, ctx: &Config| interface::valid_interfaces(interfaces, ctx))
    )]
    pub interfaces: Vec<Interface>,

    #[garde(dive)]
    pub policy_definitions: Vec<PolicyDefinition>,

    #[garde(dive)]
    pub community_aliases: Vec<CommunityAlias>,

    #[garde(dive)]
    pub community_groups: Vec<CommunityGroup>,

    #[garde(dive)]
    pub prefix_lists: Vec<PrefixList>,

    #[garde(
        dive,
        custom(|domains, _ctx: &Config| broadcast_domain::valid_broadcast_domains(domains))
    )]
    pub broadcast_domains: Vec<BroadcastDomain>,

    #[garde(dive)]
    pub switching_profiles: Vec<SwitchingProfile>,

    #[serde(default = "default_hostname")]
    #[garde(length(min = 1, max = 253), custom(|h, _ctx: &Config| hostname_charset(h)))]
    pub hostname: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bgp_instances: Vec::new(),
            routing_tables: Vec::new(),
            ospf_instances: Vec::new(),
            static_routing_instances: Vec::new(),
            interfaces: Vec::new(),
            policy_definitions: Vec::new(),
            community_aliases: Vec::new(),
            community_groups: Vec::new(),
            prefix_lists: Vec::new(),
            broadcast_domains: Vec::new(),
            switching_profiles: Vec::new(),
            hostname: default_hostname(),
        }
    }
}

fn default_hostname() -> String {
    "nos".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_hostname_is_nos() {
        assert_eq!(Config::default().hostname, "nos");
    }

    #[test]
    fn valid_hostname_passes() {
        let cfg = Config {
            hostname: "router-1".to_string(),
            ..Default::default()
        };
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn empty_hostname_fails_length() {
        let cfg = Config {
            hostname: String::new(),
            ..Default::default()
        };
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn hyphen_leading_hostname_fails_charset() {
        let cfg = Config {
            hostname: "-router".to_string(),
            ..Default::default()
        };
        assert!(cfg.validate_with(&cfg).is_err());
    }
}
