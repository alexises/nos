pub mod as_path_list;
pub mod bfd_profile;
pub mod bgp_instance;
pub mod bgp_peer;
pub mod bgp_peer_group;
pub mod broadcast_domain;
pub mod community_alias;
pub mod community_group;
pub mod interface;
pub mod lldp;
pub mod logging;
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
pub mod sbfd;
pub mod spanning_tree;
pub mod static_route;
pub mod static_routing_instance;
pub mod stp_port_profile;
pub mod sugar;
pub mod switching_profile;
pub mod user;

pub use as_path_list::AsPathList;
pub use bfd_profile::{BfdAuth, BfdAuthMethod, BfdMode, BfdProfile, EchoMode};
pub use bgp_instance::{
    BgpAggregate, BgpConfederation, BgpGracefulRestart, BgpInstance, RpkiCache,
    GR_RESTART_TIME_DEFAULT, GR_SELECTION_DEFERRAL_TIME_DEFAULT, GR_STALE_TIME_DEFAULT,
    RPKI_RTR_PORT_DEFAULT,
};
pub use bgp_peer::BgpPeer;
pub use bgp_peer_group::{
    AddressFamily, BgpAddPath, BgpAoAlgorithm, BgpAoKey, BgpAuth, BgpDamping, BgpLocalAs,
    BgpMaximumPrefix, BgpPeerGroup, BgpPrefixLimit, BgpRole, BgpShutdown, NextHopMode,
    SourceAddress, CONNECT_RETRY_TIME_DEFAULT_SECS, HOLD_TIME_DEFAULT, HOLD_TIME_FLOOR,
    ROUTE_REFRESH_STALE_TIME_DEFAULT_SECS,
};
pub use broadcast_domain::BroadcastDomain;
pub use community_alias::CommunityAlias;
pub use community_group::CommunityGroup;
pub use interface::{
    loopback_table_name, Interface, InterfaceAddress, Subinterface, LOOPBACK_PREFIX,
};
pub use lldp::{LldpDestination, LldpSettings};
pub use logging::{
    parse_fingerprint, LoggingSettings, SyslogFacility, SyslogServer, SyslogTls, SyslogTransport,
};
pub use ospf_area::{OspfArea, OspfAreaRange, OspfAreaType, OspfVirtualLink};
pub use ospf_instance::OspfInstance;
pub use ospf_profile::{
    NetworkType, OspfAuth, OspfCryptoAlgorithm, OspfCryptoKey, OspfProfile, DEAD_INTERVAL_DEFAULT,
    HELLO_INTERVAL_DEFAULT, PRIORITY_DEFAULT,
};
pub use ospfv3_area::Ospfv3Area;
pub use ospfv3_instance::Ospfv3Instance;
pub use ospfv3_profile::Ospfv3Profile;
pub use policy_definition::PolicyDefinition;
pub use port_aggregate::{
    DfAlgorithm, EsRedundancy, LacpMode, LacpRate, PortAggregate, PortAggregateMode,
};
pub use prefix_list::{PrefixList, PrefixListEntry};
pub use routing_table::{
    Redistribute, RedistributeSource, RedistributeTarget, RestApi, RoutingTable, RoutingTableEvpn,
    REST_API_PORT_DEFAULT,
};
pub use sbfd::SbfdReflector;
pub use spanning_tree::{MstInstance, SpanningTree, StpForceVersion, StpMode, StpRegion};
pub use static_route::StaticRoute;
pub use static_routing_instance::StaticRoutingInstance;
pub use stp_port_profile::{EdgePort, LinkType, StpPortMstInstance, StpPortProfile};
pub use switching_profile::{SwitchingProfile, SwitchingProfileMember, VlanTag};
pub use user::{User, PASSWORD_HASH_PREFIX};

use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::hostname_charset;
use nos_proto_derive::Cli;

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct Config {
    #[garde(
        dive,
        custom(|instances, _ctx: &Config| bgp_instance::valid_route_reflection_and_server(instances))
    )]
    #[cli(topic = BgpInstance, words = "bgp instance")]
    pub bgp_instances: Vec<BgpInstance>,

    #[garde(
        dive,
        custom(|tables, ctx: &Config| routing_table::valid_redistribute_rules(tables, ctx))
    )]
    #[cli(topic = RoutingTable)]
    pub routing_tables: Vec<RoutingTable>,

    #[garde(dive)]
    #[cli(topic = OspfInstance, words = "ospf instance")]
    pub ospf_instances: Vec<OspfInstance>,

    #[garde(dive)]
    #[cli(topic = Ospfv3Instance, words = "ospfv3 instance")]
    pub ospfv3_instances: Vec<Ospfv3Instance>,

    #[garde(dive)]
    #[cli(topic = StaticRoutingInstance)]
    pub static_routing_instances: Vec<StaticRoutingInstance>,

    #[garde(
        dive,
        custom(|interfaces, ctx: &Config| interface::valid_interfaces(interfaces, ctx))
    )]
    #[cli(topic = Interface, sugar = "{name}.{tag} => {name} subinterface {tag}")]
    pub interfaces: Vec<Interface>,

    #[garde(dive)]
    #[cli(topic = PolicyDefinition)]
    pub policy_definitions: Vec<PolicyDefinition>,

    #[garde(dive)]
    #[cli(topic = CommunityAlias)]
    pub community_aliases: Vec<CommunityAlias>,

    #[garde(dive)]
    #[cli(topic = CommunityGroup)]
    pub community_groups: Vec<CommunityGroup>,

    #[garde(dive)]
    #[cli(topic = PrefixList)]
    pub prefix_lists: Vec<PrefixList>,

    #[garde(dive)]
    #[cli(topic = AsPathList)]
    pub as_path_lists: Vec<AsPathList>,

    #[garde(
        dive,
        custom(|domains, ctx: &Config| broadcast_domain::valid_broadcast_domains(domains, ctx))
    )]
    #[cli(topic = BroadcastDomain, words = "broadcast domain")]
    pub broadcast_domains: Vec<BroadcastDomain>,

    #[garde(dive)]
    #[cli(topic = SwitchingProfile)]
    pub switching_profiles: Vec<SwitchingProfile>,

    #[garde(
        dive,
        custom(|aggregates, ctx: &Config| port_aggregate::valid_port_aggregates(aggregates, ctx))
    )]
    #[cli(topic = PortAggregate)]
    pub port_aggregates: Vec<PortAggregate>,

    #[serde(default = "default_hostname")]
    #[garde(length(min = 1, max = 253), custom(|h, _ctx: &Config| hostname_charset(h)))]
    #[cli(topic = Hostname)]
    pub hostname: String,

    /// System-wide LLDP timers and management address. `serde(default)` so
    /// on-disk config saved before this field existed still loads.
    #[serde(default)]
    #[garde(custom(|l: &LldpSettings, _ctx: &Config| l.check()))]
    #[cli(topic = Lldp)]
    pub lldp: LldpSettings,

    /// Log export (remote syslog). `serde(default)` so on-disk config saved
    /// before this field existed still loads.
    #[serde(default)]
    #[garde(dive)]
    #[cli(topic = Logging)]
    pub logging: LoggingSettings,

    /// Local users allowed to log in. `serde(default)` so on-disk config saved
    /// before this field existed still loads (`nos-configd` then seeds `admin`).
    #[serde(default)]
    #[garde(dive)]
    #[cli(topic = User)]
    pub users: Vec<User>,

    /// Named BFD parameter sets, referenced by `bfd <name>` from BGP
    /// peer-groups, OSPF/OSPFv3 profiles and static routes. `serde(default)`
    /// so on-disk config saved before this field existed still loads.
    #[serde(default)]
    #[garde(dive)]
    #[cli(topic = BfdProfile)]
    pub bfd_profiles: Vec<BfdProfile>,

    /// RFC 7880 S-BFD reflector. `serde(default)` so on-disk config saved
    /// before this field existed still loads.
    #[serde(default)]
    #[garde(custom(|r: &SbfdReflector, _ctx: &Config| r.check()))]
    #[cli(topic = SbfdReflector, words = "sbfd reflector")]
    pub sbfd_reflector: SbfdReflector,

    /// Bridge-wide spanning-tree parameters (inert until `nos-stpd`).
    /// `serde(default)` so on-disk config saved before this field existed
    /// still loads.
    #[serde(default)]
    #[garde(custom(|s: &SpanningTree, ctx: &Config| spanning_tree::valid_spanning_tree(s, ctx)))]
    #[cli(topic = SpanningTree, words = "spanning-tree")]
    pub spanning_tree: SpanningTree,

    /// Named spanning-tree port settings, referenced by `stp-port-profile`
    /// from interfaces and port aggregates.
    #[serde(default)]
    #[garde(dive)]
    #[cli(topic = StpPortProfile, words = "stp-port-profile")]
    pub stp_port_profiles: Vec<StpPortProfile>,
}

impl Config {
    /// Whether `ip` lies on a subnet configured on an interface (or
    /// subinterface, or port-aggregate subinterface) in routing table
    /// `table`: the config-only "directly connected" test BFD clients use to
    /// choose single-hop (RFC 5881) over multihop (RFC 5883) sessions.
    /// ponytail: addresses learned outside the config (DHCP) are not seen.
    pub fn is_connected(&self, table: &str, ip: std::net::IpAddr) -> bool {
        let on = |rt: &Option<String>, addrs: &[interface::InterfaceAddress]| {
            rt.as_deref() == Some(table) && addrs.iter().any(|a| a.address.trunc().contains(&ip))
        };
        let subs = |subs: &[interface::Subinterface]| {
            subs.iter().any(|s| on(&s.routing_table, &s.addresses))
        };
        self.interfaces
            .iter()
            .any(|i| on(&i.routing_table, &i.addresses) || subs(&i.subinterfaces))
            || self.port_aggregates.iter().any(|a| subs(&a.subinterfaces))
    }
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
            as_path_lists: Vec::new(),
            prefix_lists: Vec::new(),
            broadcast_domains: Vec::new(),
            switching_profiles: Vec::new(),
            port_aggregates: Vec::new(),
            hostname: default_hostname(),
            lldp: LldpSettings::default(),
            logging: LoggingSettings::default(),
            users: Vec::new(),
            bfd_profiles: Vec::new(),
            sbfd_reflector: SbfdReflector::default(),
            spanning_tree: SpanningTree::default(),
            stp_port_profiles: Vec::new(),
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
    fn connected_means_inside_a_configured_subnet_of_the_table() {
        use interface::{Interface, InterfaceAddress, Subinterface};
        let addr = |a: &str| InterfaceAddress {
            address: a.parse().unwrap(),
            label: None,
        };
        let cfg = Config {
            interfaces: vec![
                Interface {
                    name: "eth1".into(),
                    subinterfaces: vec![Subinterface {
                        routing_table: Some("rt1".into()),
                        addresses: vec![addr("10.0.0.1/24")],
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                Interface {
                    name: "loopback-rt1".into(),
                    routing_table: Some("rt1".into()),
                    addresses: vec![addr("1.1.1.1/32")],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let ip = |s: &str| s.parse().unwrap();
        assert!(cfg.is_connected("rt1", ip("10.0.0.2")));
        assert!(!cfg.is_connected("rt2", ip("10.0.0.2")), "other table");
        assert!(!cfg.is_connected("rt1", ip("10.0.1.2")));
        assert!(!cfg.is_connected("rt1", ip("1.1.1.2")), "loopback /32");
    }

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
