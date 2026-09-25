use garde::Validate;
use serde::{Deserialize, Serialize};

use super::Config;

/// Which NLRI (AFI/SAFI) is exchanged over a peer-group's session —
/// independent of whatever address family `source_address` resolves to at
/// runtime, or a peer's `remote_address`. RFC 8950's extended next-hop
/// encoding allows an IPv6-transport session to carry IPv4 unicast NLRI, so
/// this must never be derived from, or cross-validated against, either
/// address's IP version.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AddressFamily {
    Ipv4Unicast,
    Ipv6Unicast,
    /// RFC 7432 EVPN (AFI 25 / SAFI 70). Appended last: postcard indexes
    /// enum variants by position.
    L2vpnEvpn,
}

impl AddressFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            AddressFamily::Ipv4Unicast => "ipv4",
            AddressFamily::Ipv6Unicast => "ipv6",
            AddressFamily::L2vpnEvpn => "l2vpn-evpn",
        }
    }
}

impl std::fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A peer-group's transport source address, referenced by interface + label
/// rather than a literal `IpAddr` — resolved to an actual address by
/// `nos-bgpd` at runtime (querying `nos-interfaced`, the same way a
/// `BgpInstance.routing_table` reference resolves to a VRF name via
/// `nos-ribd`), never here. `label` disambiguates which of an interface's
/// addresses to use when it carries more than one; `None` requires the
/// interface to carry exactly one address.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceAddress {
    /// An explicitly named interface.
    Interface {
        interface: String,
        label: Option<String>,
    },
    /// This peer-group's owning `BgpInstance`'s own loopback interface
    /// (`loopback-<table>`, where `<table>` is that instance's
    /// `routing_table`) — so no interface name needs to be spelled out.
    /// Invalid (an error, not a fallback) for an instance with no owning
    /// routing table, exactly like `BgpInstance.routing_table` itself.
    Loopback { label: Option<String> },
}

impl std::fmt::Display for SourceAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceAddress::Interface { interface, label } => {
                write!(f, "interface {interface}")?;
                if let Some(label) = label {
                    write!(f, " label {label}")?;
                }
                Ok(())
            }
            SourceAddress::Loopback { label } => {
                write!(f, "loopback")?;
                if let Some(label) = label {
                    write!(f, " label {label}")?;
                }
                Ok(())
            }
        }
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

/// Controls the `NEXT_HOP` path attribute this instance writes into every
/// UPDATE it advertises to a peer-group's sessions. `SelfAddress` rewrites it
/// to the session's own local address ("next-hop-self"); `Unchanged`
/// preserves the next-hop the route already carries (the address it was
/// received with, for a peer-learned route). `BgpPeerGroup.next_hop: None`
/// resolves to `SelfAddress` for an eBGP peer-group and `Unchanged` for an
/// iBGP one — standard BGP practice, since an iBGP speaker must not silently
/// mask a route's real eBGP-learned next-hop unless explicitly told to.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NextHopMode {
    SelfAddress,
    Unchanged,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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
    // `remote_address` — see `AddressFamily`'s doc comment. Also never
    // cross-validated against `Config.interfaces` — like
    // `BgpInstance.routing_table`'s VRF, the referenced interface is
    // resolved by `nos-bgpd` itself and may not exist yet in this
    // transaction.
    #[garde(skip)]
    pub source_address: Option<SourceAddress>,

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

    /// RFC 4271 §9.2.1.1 `MinRouteAdvertisementInterval`, in seconds: at most
    /// one batch of advertisements per this interval to each peer (withdrawals
    /// are exempt). `None` (or 0) disables pacing — every change is sent at once.
    #[garde(skip)]
    pub mrai: Option<u16>,

    /// `None` opens sessions with no transport authentication at all.
    /// Secrets are stored clear-text, like every other field in this config
    /// — see `BgpAuth`.
    #[garde(custom(|a: &Option<BgpAuth>, _ctx: &Config| valid_auth(a.as_ref())))]
    pub auth: Option<BgpAuth>,

    /// `None` defaults to `SelfAddress` for an eBGP peer-group and
    /// `Unchanged` for an iBGP one — see `NextHopMode`.
    #[garde(skip)]
    pub next_hop: Option<NextHopMode>,

    /// RFC 4456 route-reflector client: routes learned from other iBGP
    /// peers are reflected to this peer (and vice versa) instead of being
    /// withheld by the usual iBGP split-horizon rule. Requires this
    /// peer-group's `remote_as` to equal the owning instance's `asn` (an
    /// iBGP peer-group) — checked cross-instance, see
    /// `bgp_instance::valid_route_reflection_and_server`. Mutually exclusive
    /// with `route_server_client`.
    #[garde(skip)]
    pub route_reflector_client: bool,

    /// RFC 7947 route-server client: this peer-group's own ASN is never
    /// prepended to `AS_PATH` when advertising to it, and (via RFC 7911
    /// ADD-PATH) it receives every other route-server-client's path for a
    /// prefix, not just the one instance-wide elected best path. Requires
    /// this peer-group's `remote_as` to differ from the owning instance's
    /// `asn` (an eBGP peer-group). Mutually exclusive with
    /// `route_reflector_client`.
    #[garde(skip)]
    pub route_server_client: bool,

    /// `None` defaults to `deny-all` — this NOS never leaves a direction
    /// unfiltered, unlike every other `Option` field on this struct, which
    /// defaults to some permissive/derived behavior. See root `CLAUDE.md`'s
    /// "Default-deny rollout impact".
    #[garde(custom(|p: &Option<String>, ctx: &Config| policy_reference_valid(p.as_ref(), ctx)))]
    pub import_policy: Option<String>,

    /// Same default-deny semantics as `import_policy`, applied on
    /// advertisement instead of receipt.
    #[garde(custom(|p: &Option<String>, ctx: &Config| policy_reference_valid(p.as_ref(), ctx)))]
    pub export_policy: Option<String>,
}

/// `"accept-all"`/`"deny-all"` are always valid regardless of what's
/// configured — see `nos_rpl::ACCEPT_ALL_NAME`/`DENY_ALL_NAME`. Any other
/// name must match a real `PolicyDefinition`.
fn policy_reference_valid(name: Option<&String>, ctx: &Config) -> garde::Result {
    let Some(name) = name else {
        return Ok(());
    };
    if name == nos_rpl::ACCEPT_ALL_NAME || name == nos_rpl::DENY_ALL_NAME {
        return Ok(());
    }
    if ctx.policy_definitions.iter().any(|p| &p.name == name) {
        Ok(())
    } else {
        Err(garde::Error::new("referenced policy does not exist"))
    }
}

/// Transport authentication for a peer-group's sessions — mutually
/// exclusive mechanisms, matching the kernel (a socket can carry
/// `TCP_MD5SIG` or TCP-AO keys, never both at once). Stored clear-text, like
/// every field in this config.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BgpAuth {
    /// RFC 2385 TCP MD5 signature — a single shared password.
    Md5 { password: String },
    /// RFC 5925 TCP Authentication Option — one or more keys, supporting
    /// rotation via `send_id`/`recv_id` and the `is_current`/`is_rnext`
    /// flags.
    Ao { keys: Vec<BgpAoKey> },
}

/// One TCP-AO key. `send_id`/`recv_id` identify it on the wire (RFC 5925's
/// KeyID/RNextKeyID); `is_current` marks the key actively signing outgoing
/// segments (exactly one key must have this set); `is_rnext` optionally
/// requests the peer switch to this key next, for rotation without a
/// dropped session.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BgpAoKey {
    pub send_id: u8,
    pub recv_id: u8,
    pub algorithm: BgpAoAlgorithm,
    pub key: String,
    pub is_current: bool,
    pub is_rnext: bool,
}

/// RFC 5925's two mandatory-to-implement algorithms.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BgpAoAlgorithm {
    HmacSha1_96,
    AesCmac96,
}

/// Maximum key/password length accepted by Linux's `TCP_MD5SIG`/TCP-AO
/// socket options (`TCP_MD5SIG_MAXKEYLEN`/`TCP_AO_MAXKEYLEN`, both 80).
const MAX_AUTH_KEY_LEN: usize = 80;

fn valid_auth(auth: Option<&BgpAuth>) -> garde::Result {
    match auth {
        None => Ok(()),
        Some(BgpAuth::Md5 { password }) => {
            if password.is_empty() || password.len() > MAX_AUTH_KEY_LEN {
                return Err(garde::Error::new("md5 password must be 1 to 80 bytes long"));
            }
            Ok(())
        }
        Some(BgpAuth::Ao { keys }) => {
            if keys.is_empty() {
                return Err(garde::Error::new(
                    "ao auth must have at least one key (or be cleared)",
                ));
            }
            let mut seen_send_ids: Vec<u8> = Vec::new();
            let mut current_count = 0;
            let mut rnext_count = 0;
            for key in keys {
                if key.key.is_empty() || key.key.len() > MAX_AUTH_KEY_LEN {
                    return Err(garde::Error::new("ao key must be 1 to 80 bytes long"));
                }
                if seen_send_ids.contains(&key.send_id) {
                    return Err(garde::Error::new(
                        "ao key send-id must be unique within a peer-group",
                    ));
                }
                seen_send_ids.push(key.send_id);
                if key.is_current {
                    current_count += 1;
                }
                if key.is_rnext {
                    rnext_count += 1;
                }
            }
            if current_count != 1 {
                return Err(garde::Error::new(
                    "ao auth must have exactly one current key",
                ));
            }
            if rnext_count > 1 {
                return Err(garde::Error::new("ao auth must have at most one rnext key"));
            }
            Ok(())
        }
    }
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
    use std::net::Ipv4Addr;

    use crate::schema::{BgpInstance, Config};

    use super::*;

    fn instance_with_groups(name: &str, groups: Vec<BgpPeerGroup>) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn: 65000,
            peer_groups: groups,
            peers: Vec::new(),
            cluster_id: None,
            routing_table: None,
            redistribute_policy: None,
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
            mrai: None,
            auth: None,
            next_hop: None,
            route_reflector_client: false,
            route_server_client: false,
            import_policy: None,
            export_policy: None,
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
    /// `source_address`'s resolved IP version must never constrain
    /// `address_families`.
    #[test]
    fn source_address_never_constrains_address_family() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.source_address = Some(SourceAddress::Interface {
            interface: "eth0".to_string(),
            label: None,
        });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn loopback_source_address_passes() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.source_address = Some(SourceAddress::Loopback {
            label: Some("mgmt".to_string()),
        });
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

    fn ao_key(send_id: u8, is_current: bool) -> BgpAoKey {
        BgpAoKey {
            send_id,
            recv_id: send_id,
            algorithm: BgpAoAlgorithm::HmacSha1_96,
            key: "secret".to_string(),
            is_current,
            is_rnext: false,
        }
    }

    #[test]
    fn md5_password_passes() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.auth = Some(BgpAuth::Md5 {
            password: "secret".to_string(),
        });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn empty_md5_password_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.auth = Some(BgpAuth::Md5 {
            password: String::new(),
        });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn oversized_md5_password_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.auth = Some(BgpAuth::Md5 {
            password: "x".repeat(81),
        });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn ao_with_one_current_key_passes() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.auth = Some(BgpAuth::Ao {
            keys: vec![ao_key(1, true)],
        });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn ao_with_no_keys_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.auth = Some(BgpAuth::Ao { keys: vec![] });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn ao_with_no_current_key_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.auth = Some(BgpAuth::Ao {
            keys: vec![ao_key(1, false)],
        });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn ao_with_two_current_keys_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.auth = Some(BgpAuth::Ao {
            keys: vec![ao_key(1, true), ao_key(2, true)],
        });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn ao_with_duplicate_send_id_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.auth = Some(BgpAuth::Ao {
            keys: vec![ao_key(1, true), ao_key(1, false)],
        });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn ao_with_oversized_key_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        let mut key = ao_key(1, true);
        key.key = "x".repeat(81);
        pg.auth = Some(BgpAuth::Ao { keys: vec![key] });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }
}
