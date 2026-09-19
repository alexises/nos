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
pub mod subinterface;
pub mod switching_profile;

pub use bgp_instance::BgpInstanceOp;
pub use bgp_peer::BgpPeerOp;
pub use bgp_peer_group::BgpPeerGroupOp;
pub use broadcast_domain::BroadcastDomainOp;
pub use community_alias::CommunityAliasOp;
pub use community_group::CommunityGroupOp;
pub use interface::InterfaceOp;
pub use ospf_area::OspfAreaOp;
pub use ospf_instance::OspfInstanceOp;
pub use ospf_profile::OspfProfileOp;
pub use policy_definition::PolicyDefinitionOp;
pub use prefix_list::PrefixListOp;
pub use routing_table::RoutingTableOp;
pub use static_route::StaticRouteOp;
pub use static_routing_instance::StaticRoutingInstanceOp;
pub use subinterface::SubinterfaceOp;
pub use switching_profile::SwitchingProfileOp;

use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::schema::{Config, PrefixListEntry};

/// A single edit applied to a transaction's in-progress config tree.
///
/// One variant per config section, plus one variant per top-level scalar
/// field. Adding a new named/keyed section follows the convention in
/// `proto/CLAUDE.md`'s "Adding a new config section": add a sibling
/// `<Section>Op` enum in `ops/<section>.rs`, then a new `ConfigOp` variant
/// wrapping it. A scalar field with a single possible edit (like
/// `hostname`) skips that — it gets one `ConfigOp` variant directly here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigOp {
    BgpInstance(BgpInstanceOp),
    SetHostname(String),
    BgpPeerGroup(BgpPeerGroupOp),
    BgpPeer(BgpPeerOp),
    RoutingTable(RoutingTableOp),
    StaticRoutingInstance(StaticRoutingInstanceOp),
    StaticRoute(StaticRouteOp),
    Interface(InterfaceOp),
    PolicyDefinition(PolicyDefinitionOp),
    CommunityAlias(CommunityAliasOp),
    CommunityGroup(CommunityGroupOp),
    PrefixList(PrefixListOp),
    BroadcastDomain(BroadcastDomainOp),
    SwitchingProfile(SwitchingProfileOp),
    Subinterface(SubinterfaceOp),
    OspfInstance(OspfInstanceOp),
    OspfArea(OspfAreaOp),
    OspfProfile(OspfProfileOp),
}

impl ConfigOp {
    /// Applies the op to `config` in place. Never runs `garde` validation —
    /// validation happens only at commit time. Only reports structural
    /// errors (e.g. setting a field on a name that doesn't exist).
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            ConfigOp::BgpInstance(op) => op.apply(config),
            ConfigOp::SetHostname(hostname) => {
                config.hostname.clone_from(hostname);
                Ok(())
            }
            ConfigOp::BgpPeerGroup(op) => op.apply(config),
            ConfigOp::BgpPeer(op) => op.apply(config),
            ConfigOp::RoutingTable(op) => op.apply(config),
            ConfigOp::StaticRoutingInstance(op) => op.apply(config),
            ConfigOp::StaticRoute(op) => op.apply(config),
            ConfigOp::Interface(op) => op.apply(config),
            ConfigOp::PolicyDefinition(op) => op.apply(config),
            ConfigOp::CommunityAlias(op) => op.apply(config),
            ConfigOp::CommunityGroup(op) => op.apply(config),
            ConfigOp::PrefixList(op) => op.apply(config),
            ConfigOp::BroadcastDomain(op) => op.apply(config),
            ConfigOp::SwitchingProfile(op) => op.apply(config),
            ConfigOp::Subinterface(op) => op.apply(config),
            ConfigOp::OspfInstance(op) => op.apply(config),
            ConfigOp::OspfArea(op) => op.apply(config),
            ConfigOp::OspfProfile(op) => op.apply(config),
        }
    }
}

#[derive(Debug, Error)]
pub enum OpError {
    #[error("bgp instance '{0}' not found")]
    BgpInstanceNotFound(String),
    #[error("peer-group '{name}' not found in bgp instance '{instance}'")]
    BgpPeerGroupNotFound { instance: String, name: String },
    #[error("ao key with send-id '{send_id}' not found in peer-group '{name}' of bgp instance '{instance}'")]
    BgpAoKeyNotFound {
        instance: String,
        name: String,
        send_id: u8,
    },
    #[error("peer '{remote_address}' not found in bgp instance '{instance}'")]
    BgpPeerNotFound {
        instance: String,
        remote_address: IpAddr,
    },
    #[error("routing table '{0}' not found")]
    RoutingTableNotFound(String),
    #[error("static routing instance '{0}' not found")]
    StaticRoutingInstanceNotFound(String),
    #[error("route to '{subnet}' not found in static routing instance '{instance}'")]
    StaticRouteNotFound { instance: String, subnet: IpNet },
    #[error("interface '{0}' not found")]
    InterfaceNotFound(String),
    #[error("address '{address}' not found on interface '{name}'")]
    InterfaceAddressNotFound { name: String, address: IpNet },
    #[error("policy definition '{0}' not found")]
    PolicyDefinitionNotFound(String),
    #[error("community alias '{0}' not found")]
    CommunityAliasNotFound(String),
    #[error("community group '{0}' not found")]
    CommunityGroupNotFound(String),
    #[error("member '{member}' not found in community group '{name}'")]
    CommunityGroupMemberNotFound { name: String, member: String },
    #[error("prefix list '{0}' not found")]
    PrefixListNotFound(String),
    #[error("entry '{entry:?}' not found in prefix list '{name}'")]
    PrefixListEntryNotFound {
        name: String,
        entry: PrefixListEntry,
    },
    #[error("broadcast domain '{0}' not found")]
    BroadcastDomainNotFound(String),
    #[error("address '{address}' not found on broadcast domain '{name}'")]
    BroadcastDomainAddressNotFound { name: String, address: IpNet },
    #[error("switching profile '{0}' not found")]
    SwitchingProfileNotFound(String),
    #[error("broadcast domain '{broadcast_domain}' not found in switching profile '{name}'")]
    SwitchingProfileMemberNotFound {
        name: String,
        broadcast_domain: String,
    },
    #[error("subinterface with tag '{tag}' not found on interface '{interface}'")]
    SubinterfaceNotFound { interface: String, tag: u16 },
    #[error("address '{address}' not found on subinterface '{interface}.{tag}'")]
    SubinterfaceAddressNotFound {
        interface: String,
        tag: u16,
        address: IpNet,
    },
    #[error("ospf instance '{0}' not found")]
    OspfInstanceNotFound(String),
    #[error("ospf area '{area_id}' not found in ospf instance '{instance}'")]
    OspfAreaNotFound { instance: String, area_id: Ipv4Addr },
    #[error("ospf profile '{name}' not found in area '{area_id}' of ospf instance '{instance}'")]
    OspfProfileNotFound {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
    },
    #[error("crypto key with key-id '{key_id}' not found in ospf profile '{name}' (area '{area_id}' of ospf instance '{instance}')")]
    OspfCryptoKeyNotFound {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
        key_id: u8,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_hostname_updates_config() {
        let mut cfg = Config::default();
        ConfigOp::SetHostname("router1".to_string())
            .apply(&mut cfg)
            .unwrap();
        assert_eq!(cfg.hostname, "router1");
    }
}
