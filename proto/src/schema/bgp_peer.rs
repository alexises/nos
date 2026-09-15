use std::net::IpAddr;

use garde::Validate;
use serde::{Deserialize, Serialize};

use super::Config;

/// Associates a remote address with a peer-group, by name — the bulk of
/// session config (remote-as, source-address, address-families) lives on
/// the referenced `BgpPeerGroup`, not here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
#[garde(context(Config as ctx))]
pub struct BgpPeer {
    #[garde(custom(|addr, ctx: &Config| unique_remote_address(addr, ctx)))]
    pub remote_address: IpAddr,

    #[garde(custom(|name, ctx: &Config| peer_group_exists(name, ctx)))]
    pub peer_group: String,
}

/// Peer remote-addresses are unique across the whole config — see
/// `bgp_peer_group::unique_name` for why this is scoped globally rather
/// than per-instance.
fn unique_remote_address(addr: &IpAddr, ctx: &Config) -> garde::Result {
    let count = ctx
        .bgp_instances
        .iter()
        .flat_map(|i| &i.peers)
        .filter(|p| &p.remote_address == addr)
        .count();
    if count > 1 {
        return Err(garde::Error::new("must be unique"));
    }
    Ok(())
}

fn peer_group_exists(name: &str, ctx: &Config) -> garde::Result {
    let exists = ctx
        .bgp_instances
        .iter()
        .flat_map(|i| &i.peer_groups)
        .any(|g| g.name == name);
    if exists {
        Ok(())
    } else {
        Err(garde::Error::new("referenced peer-group does not exist"))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::schema::{BgpInstance, BgpPeerGroup, Config};

    use super::*;
    use crate::schema::bgp_peer_group::AddressFamily;

    fn instance(name: &str, groups: Vec<BgpPeerGroup>, peers: Vec<BgpPeer>) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn: 65000,
            peer_groups: groups,
            peers,
            routing_table: None,
        }
    }

    fn group(name: &str) -> BgpPeerGroup {
        BgpPeerGroup {
            name: name.to_string(),
            remote_as: 65001,
            source_address: None,
            address_families: vec![AddressFamily::Ipv4Unicast],
            hold_time: None,
            keepalive_interval: None,
            connect_retry_time: None,
            auth: None,
            next_hop: None,
        }
    }

    fn config_with(instances: Vec<BgpInstance>) -> Config {
        Config {
            bgp_instances: instances,
            ..Default::default()
        }
    }

    #[test]
    fn valid_peer_passes() {
        let peer = BgpPeer {
            remote_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            peer_group: "pg1".to_string(),
        };
        let cfg = config_with(vec![instance("r1", vec![group("pg1")], vec![peer])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn dangling_peer_group_reference_fails() {
        let peer = BgpPeer {
            remote_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            peer_group: "does-not-exist".to_string(),
        };
        let cfg = config_with(vec![instance("r1", vec![group("pg1")], vec![peer])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_remote_address_fails_across_different_instances() {
        let peer_a = BgpPeer {
            remote_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            peer_group: "pg1".to_string(),
        };
        let peer_b = BgpPeer {
            remote_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            peer_group: "pg2".to_string(),
        };
        let cfg = config_with(vec![
            instance("r1", vec![group("pg1")], vec![peer_a]),
            instance("r2", vec![group("pg2")], vec![peer_b]),
        ]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    /// RFC 8950: a peer's own IP version is independent of the address
    /// families exchanged over its peer-group's session.
    #[test]
    fn ipv6_peer_referencing_ipv4_address_family_group_passes() {
        let peer = BgpPeer {
            remote_address: IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2)),
            peer_group: "pg1".to_string(),
        };
        let cfg = config_with(vec![instance("r1", vec![group("pg1")], vec![peer])]);
        cfg.validate_with(&cfg).unwrap();
    }
}
