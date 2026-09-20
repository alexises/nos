pub mod bgp_instance;
pub mod bgp_peer;
pub mod bgp_peer_group;
pub mod broadcast_domain;
pub mod community_alias;
pub mod community_group;
pub mod interface;
pub mod lldp;
pub mod ospf_area;
pub mod ospf_instance;
pub mod ospf_profile;
pub mod ospfv3_area;
pub mod ospfv3_instance;
pub mod ospfv3_profile;
pub mod policy_definition;
pub mod port_aggregate;
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
pub use lldp::{LldpDestination, LldpSettings};
pub use ospf_area::OspfArea;
pub use ospf_instance::OspfInstance;
pub use ospf_profile::{
    NetworkType, OspfAuth, OspfCryptoAlgorithm, OspfCryptoKey, OspfProfile, DEAD_INTERVAL_DEFAULT,
    HELLO_INTERVAL_DEFAULT, PRIORITY_DEFAULT,
};
pub use ospfv3_area::Ospfv3Area;
pub use ospfv3_instance::Ospfv3Instance;
pub use ospfv3_profile::Ospfv3Profile;
pub use policy_definition::PolicyDefinition;
pub use port_aggregate::{LacpRate, PortAggregate, PortAggregateMode};
pub use prefix_list::{PrefixList, PrefixListEntry};
pub use routing_table::{
    Redistribute, RedistributeSource, RedistributeTarget, RestApi, RoutingTable,
    REST_API_PORT_DEFAULT,
};
pub use static_route::StaticRoute;
pub use static_routing_instance::StaticRoutingInstance;
pub use switching_profile::{SwitchingProfile, SwitchingProfileMember, VlanTag};

use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::hostname_charset;

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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
    pub ospfv3_instances: Vec<Ospfv3Instance>,

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

    #[garde(
        dive,
        custom(|aggregates, ctx: &Config| port_aggregate::valid_port_aggregates(aggregates, ctx))
    )]
    pub port_aggregates: Vec<PortAggregate>,

    #[serde(default = "default_hostname")]
    #[garde(length(min = 1, max = 253), custom(|h, _ctx: &Config| hostname_charset(h)))]
    pub hostname: String,

    /// System-wide LLDP timers and management address. `serde(default)` so
    /// on-disk config saved before this field existed still loads.
    #[serde(default)]
    #[garde(custom(|l: &LldpSettings, _ctx: &Config| l.check()))]
    pub lldp: LldpSettings,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bgp_instances: Vec::new(),
            routing_tables: Vec::new(),
            ospf_instances: Vec::new(),
            ospfv3_instances: Vec::new(),
            static_routing_instances: Vec::new(),
            interfaces: Vec::new(),
            policy_definitions: Vec::new(),
            community_aliases: Vec::new(),
            community_groups: Vec::new(),
            prefix_lists: Vec::new(),
            broadcast_domains: Vec::new(),
            switching_profiles: Vec::new(),
            port_aggregates: Vec::new(),
            hostname: default_hostname(),
            lldp: LldpSettings::default(),
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
    fn lldp_settings_are_validated_at_config_level() {
        let mut cfg = Config::default();
        cfg.lldp.tx_interval_secs = Some(5);
        cfg.lldp.tx_hold = Some(3);
        cfg.validate_with(&cfg).unwrap();
        cfg.lldp.tx_interval_secs = Some(0);
        assert!(cfg.validate_with(&cfg).is_err());
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
