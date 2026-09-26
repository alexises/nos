use std::net::Ipv4Addr;

use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_in;

use super::bgp_peer_group;
use super::{BgpPeer, BgpPeerGroup, Config};

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub router_id: Ipv4Addr,

    // RFC 6793: ASN 0 and 4_294_967_295 are reserved.
    #[garde(range(min = 1, max = 4_294_967_294u32))]
    pub asn: u32,

    #[garde(
        dive,
        custom(|groups, _ctx: &Config| bgp_peer_group::valid_peer_group_timers(groups))
    )]
    pub peer_groups: Vec<BgpPeerGroup>,

    #[garde(dive)]
    pub peers: Vec<BgpPeer>,

    /// RFC 4456 route reflector cluster id. `None` resolves to this
    /// instance's own `router_id` — the standard single-RR-per-cluster
    /// convention. Only meaningful when at least one peer-group has
    /// `route_reflector_client` set; harmless (unused) otherwise.
    #[garde(skip)]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub cluster_id: Option<Ipv4Addr>,

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

    /// The name of the RPL policy filtering routes redistributed into this
    /// instance, mirrored from the owning `RoutingTable.redistribute.policy`
    /// (only when `redistribute.to == Bgp`). Derived and read-only, exactly
    /// like `routing_table` above: never set by any `BgpInstanceOp`,
    /// recomputed by `nos-config` (`crate::derive::sync_routing_table_refs`)
    /// on every commit and on load. `nos-bgpd` reads this directly to
    /// resolve its own redistribution policy without scanning every routing
    /// table. Deliberately not rendered by `nos-cli`.
    #[garde(skip)]
    pub redistribute_policy: Option<String>,
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
/// - `route_server_client` requires an eBGP peer-group (`remote_as != asn`)
///   — a route server's transparency (no `AS_PATH` prepend) is an eBGP concept
///   (RFC 7947).
pub(crate) fn valid_route_reflection_and_server(instances: &[BgpInstance]) -> garde::Result {
    for instance in instances {
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
                damping: None,
                max_hops: None,
                auth: None,
                next_hop: None,
                route_reflector_client: false,
                route_server_client: false,
                import_policy: None,
                export_policy: None,
                shutdown: None,
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
                damping: None,
                max_hops: None,
                auth: None,
                next_hop: None,
                route_reflector_client: false,
                route_server_client: false,
                import_policy: None,
                export_policy: None,
                shutdown: None,
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
            damping: None,
            max_hops: None,
            auth: None,
            next_hop: None,
            route_reflector_client,
            route_server_client,
            import_policy: None,
            export_policy: None,
            shutdown: None,
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
