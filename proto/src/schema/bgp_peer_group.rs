use std::net::IpAddr;

use garde::Validate;
use serde::{Deserialize, Serialize};

use super::Config;

/// Which NLRI (AFI/SAFI) is exchanged over a peer-group's session —
/// independent of the IP version of `source_address` or a peer's
/// `remote_address`. RFC 8950's extended next-hop encoding allows an
/// IPv6-transport session to carry IPv4 unicast NLRI, so this must never be
/// derived from, or cross-validated against, either address's IP version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressFamily {
    Ipv4Unicast,
    Ipv6Unicast,
}

impl AddressFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            AddressFamily::Ipv4Unicast => "ipv4",
            AddressFamily::Ipv6Unicast => "ipv6",
        }
    }
}

impl std::fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// RFC 4271 §6.2: a proposed hold time of 1 or 2 seconds is invalid — it
/// must be exactly 0 (disables the hold timer and keepalives entirely) or
/// at least 3. Shared with `nos-bgp::fsm`, which applies the identical rule
/// to the *remote* peer's proposed hold time in its OPEN message.
pub const HOLD_TIME_FLOOR: u16 = 3;

/// This instance's own proposed hold time when a peer-group leaves
/// `hold_time` unset. Sits at the fast end of common router defaults (many
/// ship 90-180s).
pub const HOLD_TIME_DEFAULT: u16 = 90;

/// RFC 4271's own suggested `ConnectRetryTimer` default, used when a
/// peer-group leaves `connect_retry_time` unset.
pub const CONNECT_RETRY_TIME_DEFAULT_SECS: u16 = 120;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
#[garde(context(Config as ctx))]
pub struct BgpPeerGroup {
    #[garde(length(min = 1, max = 64), custom(|n, ctx: &Config| unique_name(n, ctx)))]
    pub name: String,

    // RFC 6793: ASN 0 and 4_294_967_295 are reserved.
    #[garde(range(min = 1, max = 4_294_967_294u32))]
    pub remote_as: u32,

    // Transport source address. Deliberately `#[garde(skip)]` and never
    // cross-validated against `address_families` or a peer's
    // `remote_address` — see `AddressFamily`'s doc comment.
    #[garde(skip)]
    pub source_address: Option<IpAddr>,

    #[garde(custom(|afs, _ctx: &Config| non_empty_no_duplicate_afs(afs)))]
    pub address_families: Vec<AddressFamily>,

    /// `None` defaults to `HOLD_TIME_DEFAULT` (90s). `Some(0)` disables both
    /// the hold timer and keepalives entirely; otherwise must be `>=
    /// HOLD_TIME_FLOOR` (RFC 4271 §6.2). The value actually used by a
    /// session is `min(this, the peer's own proposed hold time)`.
    #[garde(custom(|h: &Option<u16>, _ctx: &Config| valid_hold_time(*h)))]
    pub hold_time: Option<u16>,

    /// `None` defaults to `negotiated_hold / 3`, computed after negotiation
    /// (RFC 4271's suggested ratio). When both this and `hold_time` are set,
    /// this must be strictly less than `hold_time` — checked one level up,
    /// on `BgpInstance.peer_groups`, since garde's per-field `custom`
    /// closures can't see a sibling field (see `bgp_instance.rs`).
    #[garde(skip)]
    pub keepalive_interval: Option<u16>,

    /// `None` defaults to `CONNECT_RETRY_TIME_DEFAULT_SECS` (120s).
    #[garde(custom(|c: &Option<u16>, _ctx: &Config| valid_connect_retry_time(*c)))]
    pub connect_retry_time: Option<u16>,
}

/// Peer-group names are unique across the whole config, not just within the
/// owning instance — garde's validation context is fixed as `&Config` for
/// the whole dive chain, so this is the simplest correct scoping, and a
/// name collision is a real conflict regardless of which instance either
/// group belongs to.
fn unique_name(name: &str, ctx: &Config) -> garde::Result {
    let count = ctx
        .bgp_instances
        .iter()
        .flat_map(|i| &i.peer_groups)
        .filter(|g| g.name == name)
        .count();
    if count > 1 {
        return Err(garde::Error::new("must be unique"));
    }
    Ok(())
}

fn non_empty_no_duplicate_afs(afs: &[AddressFamily]) -> garde::Result {
    if afs.is_empty() {
        return Err(garde::Error::new(
            "must include at least one address family",
        ));
    }
    let mut seen: Vec<AddressFamily> = Vec::new();
    for af in afs {
        if seen.contains(af) {
            return Err(garde::Error::new("address families must not repeat"));
        }
        seen.push(*af);
    }
    Ok(())
}

fn valid_hold_time(hold_time: Option<u16>) -> garde::Result {
    match hold_time {
        None | Some(0) => Ok(()),
        Some(h) if h >= HOLD_TIME_FLOOR => Ok(()),
        Some(_) => Err(garde::Error::new("hold-time must be 0 or >= 3")),
    }
}

fn valid_connect_retry_time(connect_retry_time: Option<u16>) -> garde::Result {
    match connect_retry_time {
        None | Some(1..=u16::MAX) => Ok(()),
        Some(0) => Err(garde::Error::new(
            "connect-retry-time must be at least 1 second",
        )),
    }
}

/// Cross-field check for a `BgpInstance`'s whole `peer_groups` list — garde's
/// per-field `custom` closures only ever see `(field_value, &Config)`, never
/// a sibling field on the same struct, so this must be wired on
/// `BgpInstance.peer_groups` rather than on either field here (mirrors
/// `static_routing_instance::unique_subnets`'s technique of validating a
/// whole `Vec<Item>` to reach a sibling field).
///
/// `keepalive_interval` must be strictly less than `hold_time` whenever both
/// are explicitly set. This is applied uniformly even when `hold_time` is
/// explicitly `Some(0)` — since `keepalive_interval: u16` can never be less
/// than 0, the only combination that satisfies the inequality with
/// `hold_time: Some(0)` is `keepalive_interval: None`, so hold-time-disables
/// keepalives falls out of the one rule with no special case needed.
pub(crate) fn valid_peer_group_timers(groups: &[BgpPeerGroup]) -> garde::Result {
    for group in groups {
        if let (Some(hold), Some(keepalive)) = (group.hold_time, group.keepalive_interval) {
            if keepalive >= hold {
                return Err(garde::Error::new(
                    "keepalive-interval must be less than hold-time when both are set \
                     (hold-time 0 requires keepalive-interval to be left unset)",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::schema::{BgpInstance, Config};

    use super::*;

    fn instance_with_groups(name: &str, groups: Vec<BgpPeerGroup>) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn: 65000,
            peer_groups: groups,
            peers: Vec::new(),
            routing_table: None,
        }
    }

    fn group(name: &str, remote_as: u32, afs: Vec<AddressFamily>) -> BgpPeerGroup {
        BgpPeerGroup {
            name: name.to_string(),
            remote_as,
            source_address: None,
            address_families: afs,
            hold_time: None,
            keepalive_interval: None,
            connect_retry_time: None,
        }
    }

    fn config_with(instances: Vec<BgpInstance>) -> Config {
        Config {
            bgp_instances: instances,
            ..Default::default()
        }
    }

    #[test]
    fn valid_group_passes() {
        let cfg = config_with(vec![instance_with_groups(
            "r1",
            vec![group("pg1", 65001, vec![AddressFamily::Ipv4Unicast])],
        )]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn remote_as_zero_fails() {
        let cfg = config_with(vec![instance_with_groups(
            "r1",
            vec![group("pg1", 0, vec![AddressFamily::Ipv4Unicast])],
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn remote_as_max_reserved_fails() {
        let cfg = config_with(vec![instance_with_groups(
            "r1",
            vec![group(
                "pg1",
                4_294_967_295,
                vec![AddressFamily::Ipv4Unicast],
            )],
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn empty_address_families_fails() {
        let cfg = config_with(vec![instance_with_groups(
            "r1",
            vec![group("pg1", 65001, vec![])],
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_address_family_fails() {
        let cfg = config_with(vec![instance_with_groups(
            "r1",
            vec![group(
                "pg1",
                65001,
                vec![AddressFamily::Ipv4Unicast, AddressFamily::Ipv4Unicast],
            )],
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_name_fails_across_different_instances() {
        let cfg = config_with(vec![
            instance_with_groups(
                "r1",
                vec![group("pg1", 65001, vec![AddressFamily::Ipv4Unicast])],
            ),
            instance_with_groups(
                "r2",
                vec![group("pg1", 65002, vec![AddressFamily::Ipv4Unicast])],
            ),
        ]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn distinct_names_across_instances_pass() {
        let cfg = config_with(vec![
            instance_with_groups(
                "r1",
                vec![group("pg1", 65001, vec![AddressFamily::Ipv4Unicast])],
            ),
            instance_with_groups(
                "r2",
                vec![group("pg2", 65002, vec![AddressFamily::Ipv4Unicast])],
            ),
        ]);
        cfg.validate_with(&cfg).unwrap();
    }

    /// RFC 8950: an IPv6-transport session may carry IPv4 unicast NLRI.
    /// `source_address`'s IP version must never constrain `address_families`.
    #[test]
    fn ipv6_source_address_with_ipv4_address_family_passes() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.source_address = Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)));
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn hold_time_one_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.hold_time = Some(1);
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn hold_time_two_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.hold_time = Some(2);
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn hold_time_zero_passes() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.hold_time = Some(0);
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn hold_time_three_passes() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.hold_time = Some(3);
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn connect_retry_time_zero_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.connect_retry_time = Some(0);
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn connect_retry_time_one_passes() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.connect_retry_time = Some(1);
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn keepalive_equal_to_hold_time_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.hold_time = Some(30);
        pg.keepalive_interval = Some(30);
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn keepalive_less_than_hold_time_passes() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.hold_time = Some(30);
        pg.keepalive_interval = Some(10);
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn keepalive_with_hold_time_zero_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.hold_time = Some(0);
        pg.keepalive_interval = Some(0);
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn keepalive_unset_with_hold_time_zero_passes() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.hold_time = Some(0);
        pg.keepalive_interval = None;
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        cfg.validate_with(&cfg).unwrap();
    }
}
