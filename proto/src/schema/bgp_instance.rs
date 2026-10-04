use std::net::{IpAddr, Ipv4Addr};

use garde::Validate;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::validators::unique_in;

use super::bgp_peer_group;
use super::{BgpPeer, BgpPeerGroup, Config};
use nos_proto_derive::Cli;

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct BgpInstance {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, ctx: &Config| unique_in(n, &ctx.bgp_instances, |i| &i.name))
    )]
    #[cli(key)]
    pub name: String,

    // Ipv4Addr is structurally valid by construction; no additional garde rule needed.
    #[garde(skip)]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(topic = BgpInstanceRouterId)]
    pub router_id: Ipv4Addr,

    // RFC 6793: ASN 0 and 4_294_967_295 are reserved.
    #[garde(range(min = 1, max = 4_294_967_294u32))]
    #[cli(topic = BgpInstanceAsn)]
    pub asn: u32,

    #[garde(
        dive,
        custom(|groups, _ctx: &Config| bgp_peer_group::valid_peer_group_timers(groups))
    )]
    #[cli(topic = BgpPeerGroup)]
    pub peer_groups: Vec<BgpPeerGroup>,

    #[garde(dive)]
    #[cli(topic = BgpPeer)]
    pub peers: Vec<BgpPeer>,

    /// RFC 4456 route reflector cluster id. `None` resolves to this
    /// instance's own `router_id` — the standard single-RR-per-cluster
    /// convention. Only meaningful when at least one peer-group has
    /// `route_reflector_client` set; harmless (unused) otherwise.
    #[garde(skip)]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[cli(topic = BgpInstanceClusterId)]
    pub cluster_id: Option<Ipv4Addr>,

    /// How many equal paths' next hops a prefix installs in the kernel
    /// (BGP multipath): the best path plus every path tying with it up to
    /// the IGP cost to the next hop and learned from the same neighbouring
    /// AS. Only the best path is advertised. Unset or 1 installs the best
    /// path alone.
    #[serde(default)]
    #[garde(range(min = 1, max = 64))]
    #[cli(topic = BgpInstanceMaximumPaths)]
    pub maximum_paths: Option<u8>,

    /// RFC 5065 confederation: once `identifier` is set, `asn` is this
    /// router's member AS and `identifier` the AS the confederation shows
    /// to the outside. A plain struct (not an `Option`) so the CLI can set
    /// its two fields one at a time. Checked by
    /// `valid_route_reflection_and_server`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BgpInstanceConfederation)]
    pub confederation: BgpConfederation,

    /// RFC 8210 RPKI-to-Router caches this instance's `nos-bgpd` takes its
    /// validated ROA payloads from, reached inside the instance's VRF. One
    /// is used at a time: the lowest `preference` that answers (RFC 8210
    /// §10), ties in list order.
    #[serde(default)]
    #[garde(custom(|c: &Vec<RpkiCache>, _ctx: &Config| valid_rpki_caches(c)))]
    #[cli(topic = BgpInstanceRpkiCache, words = "rpki-cache")]
    pub rpki_caches: Vec<RpkiCache>,

    /// RFC 4271 §9.2.2.2 aggregates this instance originates while some
    /// more specific route is in its Loc-RIB.
    #[serde(default)]
    #[garde(custom(|a: &Vec<BgpAggregate>, _ctx: &Config| valid_aggregates(a)))]
    #[cli(topic = BgpInstanceAggregate, words = "aggregate-address")]
    pub aggregates: Vec<BgpAggregate>,

    /// The name of the `RoutingTable` that claims this instance (i.e. the
    /// VRF it belongs to), mirrored from that table's `bgp_instance` field.
    /// Derived and read-only: never set by any `BgpInstanceOp`, recomputed
    /// by `nos-config` (`crate::derive::sync_routing_table_refs`) on every
    /// commit and on load, so an operator only ever edits the one
    /// authoritative reference (`RoutingTable.bgp_instance`). `nos-bgpd`
    /// reads this directly to resolve its own VRF without scanning every
    /// routing table. Deliberately not rendered by `nos-cli`.
    #[garde(skip)]
    #[cli(hidden)]
    pub routing_table: Option<String>,

    /// The name of the RPL policy filtering routes redistributed into this
    /// instance, mirrored from the owning `RoutingTable.redistribute.policy`
    /// (only when `redistribute.to == Bgp`). Derived and read-only, exactly
    /// like `routing_table` above: never set by any `BgpInstanceOp`,
    /// recomputed by `nos-config` (`crate::derive::sync_routing_table_refs`)
    /// on every commit and on load. `nos-bgpd` reads this directly to
    /// resolve its own redistribution policy without scanning every routing
    /// table. Deliberately not rendered by `nos-cli`.
    #[garde(skip)]
    #[cli(hidden)]
    pub redistribute_policy: Option<String>,
}

/// The well-known RPKI-RTR port (RFC 8210 §3 / IANA `rpki-rtr`).
pub const RPKI_RTR_PORT_DEFAULT: u16 = 323;

fn rpki_rtr_port_default() -> u16 {
    RPKI_RTR_PORT_DEFAULT
}

/// One RPKI-to-Router cache (RFC 8210), keyed by its address.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct RpkiCache {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(key)]
    pub address: IpAddr,
    #[serde(default = "rpki_rtr_port_default")]
    #[cli(topic = BgpInstanceRpkiCachePort)]
    pub port: u16,
    /// Lower is preferred (RFC 8210 §10).
    #[serde(default)]
    #[cli(topic = BgpInstanceRpkiCachePreference)]
    pub preference: u8,
}

impl Default for RpkiCache {
    fn default() -> Self {
        RpkiCache {
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: RPKI_RTR_PORT_DEFAULT,
            preference: 0,
        }
    }
}

fn valid_rpki_caches(caches: &[RpkiCache]) -> garde::Result {
    for (i, c) in caches.iter().enumerate() {
        if c.port == 0 || c.address.is_unspecified() {
            return Err(garde::Error::new(
                "an rpki cache needs a specified address and a non-zero port",
            ));
        }
        if caches[..i].iter().any(|o| o.address == c.address) {
            return Err(garde::Error::new("rpki cache addresses must be unique"));
        }
    }
    Ok(())
}

/// One aggregate (RFC 4271 §9.2.2.2), keyed by its prefix.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub struct BgpAggregate {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(key)]
    pub prefix: IpNet,
    /// Carry the contributors' ASNs as an `AS_SET` instead of setting
    /// `ATOMIC_AGGREGATE`.
    #[serde(default)]
    #[cli(topic = BgpInstanceAggregateAsSet)]
    pub as_set: bool,
    /// Withdraw the contributing more-specifics from every peer while the
    /// aggregate is active.
    #[serde(default)]
    #[cli(topic = BgpInstanceAggregateSummaryOnly)]
    pub summary_only: bool,
}

fn valid_aggregates(aggregates: &[BgpAggregate]) -> garde::Result {
    for (i, a) in aggregates.iter().enumerate() {
        if a.prefix != a.prefix.trunc() {
            return Err(garde::Error::new(
                "an aggregate-address must be a network address (no host bits set)",
            ));
        }
        if a.prefix.prefix_len() == a.prefix.max_prefix_len() {
            return Err(garde::Error::new(
                "an aggregate-address can't be a host route: nothing is more specific",
            ));
        }
        if aggregates[..i].iter().any(|o| o.prefix == a.prefix) {
            return Err(garde::Error::new(
                "aggregate-address prefixes must be unique",
            ));
        }
    }
    Ok(())
}

/// RFC 5065 §2: the confederation identifier (`None`: not in a
/// confederation) and the other member ASes (`peers`) — a peer-group whose
/// `remote_as` is one of them is a confederation-external peer, not an
/// external one.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub struct BgpConfederation {
    #[serde(default)]
    #[cli(topic = BgpInstanceConfederationIdentifier)]
    pub identifier: Option<u32>,
    #[serde(default)]
    #[cli(topic = BgpInstanceConfederationPeer)]
    pub peers: Vec<u32>,
}

impl BgpConfederation {
    /// `asn` is another member AS — only meaningful with an identifier set.
    pub fn is_member(&self, asn: u32) -> bool {
        self.identifier.is_some() && self.peers.contains(&asn)
    }
}

fn valid_confederation(instance: &BgpInstance) -> garde::Result {
    let c = &instance.confederation;
    let Some(id) = c.identifier else {
        if c.peers.is_empty() {
            return Ok(());
        }
        return Err(garde::Error::new(
            "confederation peers need a confederation identifier",
        ));
    };
    if id == 0 || id == u32::MAX || id == instance.asn {
        return Err(garde::Error::new(
            "confederation identifier must be a valid asn (1..=4294967294) different from this instance's asn",
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for &p in &c.peers {
        if p == 0 || p == u32::MAX || p == instance.asn || p == id || !seen.insert(p) {
            return Err(garde::Error::new(
                "confederation peers must be distinct valid asns, neither this instance's asn nor the confederation identifier",
            ));
        }
    }
    Ok(())
}

/// The placeholder a new `BgpInstance` starts from (`edit` on a missing one).
impl Default for BgpInstance {
    fn default() -> Self {
        BgpInstance {
            name: String::new(),
            router_id: Ipv4Addr::UNSPECIFIED,
            asn: 0,
            peer_groups: Vec::new(),
            peers: Vec::new(),
            cluster_id: None,
            maximum_paths: None,
            confederation: crate::schema::BgpConfederation::default(),
            rpki_caches: Vec::new(),
            aggregates: Vec::new(),
            routing_table: None,
            redistribute_policy: None,
        }
    }
}

/// Cross-instance check needing both `BgpInstance.asn` and a sibling
/// `BgpPeerGroup`'s fields — a per-field `custom` closure scoped to
/// `peer_groups` can't see `asn` (a different field on the same parent), so
/// this is wired one level up, on `Config.bgp_instances` itself (mirrors
/// `routing_table::valid_redistribute_rules`'s wiring on
/// `Config.routing_tables`).
///
/// - `route_reflector_client` and `route_server_client` are mutually
///   exclusive on the same peer-group.
/// - `route_reflector_client` requires an iBGP peer-group (`remote_as ==
///   asn`) — reflection is an iBGP-only concept (RFC 4456).
/// - `announce_rpki_state` requires an iBGP peer-group: RFC 8097's
///   community is non-transitive, and ignored when received over eBGP.
/// - `route_server_client` requires an eBGP peer-group (`remote_as != asn`)
///   — a route server's transparency (no `AS_PATH` prepend) is an eBGP concept
///   (RFC 7947) — outside the confederation, if there is one.
/// - `confederation`: identifier in 1..=4294967294 and not `asn`; peers
///   distinct, neither `asn` nor the identifier (RFC 5065).
pub(crate) fn valid_route_reflection_and_server(instances: &[BgpInstance]) -> garde::Result {
    for instance in instances {
        valid_confederation(instance)?;
        for group in &instance.peer_groups {
            if group.route_reflector_client && group.route_server_client {
                return Err(garde::Error::new(
                    "route-reflector-client and route-server-client are mutually exclusive",
                ));
            }
            if group.route_reflector_client && group.remote_as != instance.asn {
                return Err(garde::Error::new(
                    "route-reflector-client requires an iBGP peer-group (remote-as must equal this instance's asn)",
                ));
            }
            if group.announce_rpki_state && group.remote_as != instance.asn {
                return Err(garde::Error::new(
                    "announce-rpki-state requires an iBGP peer-group (remote-as must equal this instance's asn)",
                ));
            }
            if group.damping.is_some() && group.remote_as == instance.asn {
                return Err(garde::Error::new(
                    "damping requires an eBGP peer-group (remote-as must differ from this instance's asn)",
                ));
            }
            if group.route_server_client && group.remote_as == instance.asn {
                return Err(garde::Error::new(
                    "route-server-client requires an eBGP peer-group (remote-as must differ from this instance's asn)",
                ));
            }
            if group.route_server_client && instance.confederation.is_member(group.remote_as) {
                return Err(garde::Error::new(
                    "route-server-client requires a peer-group outside the confederation (remote-as must not be a confederation peer)",
                ));
            }
        }
    }
    Ok(())
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
            cluster_id: None,
            maximum_paths: None,
            confederation: crate::schema::BgpConfederation::default(),
            rpki_caches: Vec::new(),
            aggregates: Vec::new(),
            routing_table: None,
            redistribute_policy: None,
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
    fn maximum_paths_range() {
        for (n, ok) in [(0, false), (1, true), (64, true), (65, false)] {
            let mut i = instance("default", 65000);
            i.maximum_paths = Some(n);
            let cfg = config_with(vec![i]);
            assert_eq!(cfg.validate_with(&cfg).is_ok(), ok, "maximum-paths {n}");
        }
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

    /// The cross-field `keepalive_interval < hold_time` check is wired on
    /// `peer_groups` (not on `BgpPeerGroup` itself, which can't see sibling
    /// fields) — this proves it fires per-group, not globally across the
    /// whole list.
    #[test]
    fn invalid_timer_combo_on_one_group_fails_even_with_another_valid_group() {
        use crate::schema::{AddressFamily, BgpPeerGroup};

        let mut inst = instance("r1", 65000);
        inst.peer_groups = vec![
            BgpPeerGroup {
                name: "valid".to_string(),
                remote_as: 65001,
                source_address: None,
                address_families: vec![AddressFamily::Ipv4Unicast],
                hold_time: Some(30),
                keepalive_interval: Some(10),
                connect_retry_time: None,
                mrai: None,
                route_refresh_stale_time: None,
                damping: None,
                max_hops: None,
                auth: None,
                next_hop: None,
                route_reflector_client: false,
                route_server_client: false,
                import_policy: None,
                export_policy: None,
                shutdown: None,
                maximum_prefix: crate::schema::BgpMaximumPrefix::default(),
                announce_rpki_state: false,
            },
            BgpPeerGroup {
                name: "invalid".to_string(),
                remote_as: 65002,
                source_address: None,
                address_families: vec![AddressFamily::Ipv4Unicast],
                hold_time: Some(30),
                keepalive_interval: Some(30),
                connect_retry_time: None,
                mrai: None,
                route_refresh_stale_time: None,
                damping: None,
                max_hops: None,
                auth: None,
                next_hop: None,
                route_reflector_client: false,
                route_server_client: false,
                import_policy: None,
                export_policy: None,
                shutdown: None,
                maximum_prefix: crate::schema::BgpMaximumPrefix::default(),
                announce_rpki_state: false,
            },
        ];
        let cfg = config_with(vec![inst]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    fn group_with_flags(
        name: &str,
        remote_as: u32,
        route_reflector_client: bool,
        route_server_client: bool,
    ) -> crate::schema::BgpPeerGroup {
        use crate::schema::AddressFamily;
        crate::schema::BgpPeerGroup {
            name: name.to_string(),
            remote_as,
            source_address: None,
            address_families: vec![AddressFamily::Ipv4Unicast],
            hold_time: None,
            keepalive_interval: None,
            connect_retry_time: None,
            mrai: None,
            route_refresh_stale_time: None,
            damping: None,
            max_hops: None,
            auth: None,
            next_hop: None,
            route_reflector_client,
            route_server_client,
            import_policy: None,
            export_policy: None,
            shutdown: None,
            maximum_prefix: crate::schema::BgpMaximumPrefix::default(),
            announce_rpki_state: false,
        }
    }

    #[test]
    fn route_reflector_and_route_server_client_together_fails() {
        let mut inst = instance("r1", 65000);
        inst.peer_groups = vec![group_with_flags("pg1", 65000, true, true)];
        let cfg = config_with(vec![inst]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn route_reflector_client_on_ebgp_group_fails() {
        let mut inst = instance("r1", 65000);
        inst.peer_groups = vec![group_with_flags("pg1", 65001, true, false)];
        let cfg = config_with(vec![inst]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn announce_rpki_state_needs_an_ibgp_group() {
        for (remote_as, ok) in [(65001, false), (65000, true)] {
            let mut inst = instance("r1", 65000);
            let mut g = group_with_flags("pg1", remote_as, false, false);
            g.announce_rpki_state = true;
            inst.peer_groups = vec![g];
            let cfg = config_with(vec![inst]);
            assert_eq!(cfg.validate_with(&cfg).is_ok(), ok, "remote-as {remote_as}");
        }
    }

    #[test]
    fn route_reflector_client_on_ibgp_group_passes() {
        let mut inst = instance("r1", 65000);
        inst.peer_groups = vec![group_with_flags("pg1", 65000, true, false)];
        let cfg = config_with(vec![inst]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn route_server_client_on_ibgp_group_fails() {
        let mut inst = instance("r1", 65000);
        inst.peer_groups = vec![group_with_flags("pg1", 65000, false, true)];
        let cfg = config_with(vec![inst]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn route_server_client_on_ebgp_group_passes() {
        let mut inst = instance("r1", 65000);
        inst.peer_groups = vec![group_with_flags("pg1", 65001, false, true)];
        let cfg = config_with(vec![inst]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn confederation_is_checked() {
        use super::BgpConfederation;
        let check = |identifier: u32, peers: Vec<u32>, rs_remote: Option<u32>| {
            let mut inst = instance("r1", 65101);
            inst.confederation = BgpConfederation {
                identifier: Some(identifier),
                peers,
            };
            if let Some(r) = rs_remote {
                inst.peer_groups = vec![group_with_flags("pg1", r, false, true)];
            }
            let cfg = config_with(vec![inst]);
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(check(65100, vec![65102, 65103], None));
        assert!(!check(0, vec![], None), "identifier 0");
        assert!(!check(65101, vec![], None), "identifier == asn");
        assert!(!check(65100, vec![65101], None), "peer == asn");
        assert!(!check(65100, vec![65100], None), "peer == identifier");
        assert!(!check(65100, vec![65102, 65102], None), "duplicate peer");
        assert!(check(65100, vec![65102], Some(65003)), "external rs client");
        assert!(!check(65100, vec![65102], Some(65102)), "confed rs client");
        let mut inst = instance("r1", 65101);
        inst.confederation.peers = vec![65102];
        let cfg = config_with(vec![inst]);
        assert!(cfg.validate_with(&cfg).is_err(), "peers without identifier");
    }

    #[test]
    fn aggregates_are_checked() {
        use super::BgpAggregate;
        let check = |prefixes: &[&str]| {
            let mut inst = instance("r1", 65000);
            inst.aggregates = prefixes
                .iter()
                .map(|p| BgpAggregate {
                    prefix: p.parse().unwrap(),
                    ..Default::default()
                })
                .collect();
            let cfg = config_with(vec![inst]);
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(check(&["198.51.0.0/16", "2001:db8::/32"]));
        assert!(!check(&["198.51.1.0/16"]), "host bits set");
        assert!(!check(&["198.51.0.1/32"]), "host route");
        assert!(!check(&["2001:db8::1/128"]), "v6 host route");
        assert!(!check(&["198.51.0.0/16", "198.51.0.0/16"]), "duplicate");
    }

    #[test]
    fn rpki_caches_are_checked() {
        use super::RpkiCache;
        let check = |caches: Vec<RpkiCache>| {
            let mut inst = instance("r1", 65000);
            inst.rpki_caches = caches;
            let cfg = config_with(vec![inst]);
            cfg.validate_with(&cfg).is_ok()
        };
        let cache = |a: &str, port: u16| RpkiCache {
            address: a.parse().unwrap(),
            port,
            preference: 0,
        };
        assert!(check(vec![
            cache("192.0.2.1", 323),
            cache("2001:db8::1", 8282)
        ]));
        assert!(!check(vec![cache("192.0.2.1", 0)]), "port 0");
        assert!(!check(vec![RpkiCache::default()]), "unspecified address");
        assert!(
            !check(vec![cache("192.0.2.1", 323), cache("192.0.2.1", 8282)]),
            "duplicate address"
        );
        let old: super::BgpInstance = serde_json::from_str(
            r#"{"name":"r1","router_id":"1.1.1.1","asn":1,"peer_groups":[],"peers":[],"cluster_id":null,"routing_table":null,"redistribute_policy":null}"#,
        )
        .unwrap();
        assert!(
            old.rpki_caches.is_empty(),
            "a saved config without caches loads"
        );
        let c: RpkiCache = serde_json::from_str(r#"{"address":"192.0.2.1"}"#).unwrap();
        assert_eq!((c.port, c.preference), (323, 0));
    }

    #[test]
    fn damping_needs_an_ebgp_group_and_sane_values() {
        let d = crate::schema::BgpDamping::default();
        let check = |remote_as: u32, damping: crate::schema::BgpDamping| {
            let mut inst = instance("r1", 65000);
            let mut g = group_with_flags("pg1", remote_as, false, false);
            g.damping = Some(damping);
            inst.peer_groups = vec![g];
            let cfg = config_with(vec![inst]);
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(check(65001, d));
        assert!(!check(65000, d), "iBGP group");
        assert!(
            !check(65001, crate::schema::BgpDamping { suppress: 750, ..d }),
            "suppress <= reuse"
        );
        assert!(!check(
            65001,
            crate::schema::BgpDamping { half_life: 0, ..d }
        ));
    }
}
