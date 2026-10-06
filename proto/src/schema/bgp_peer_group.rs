use garde::Validate;
use serde::{Deserialize, Serialize};

use super::Config;
use nos_proto_derive::Cli;

use super::sugar;

/// Which NLRI (AFI/SAFI) is exchanged over a peer-group's session —
/// independent of whatever address family `source_address` resolves to at
/// runtime, or a peer's `remote_address`. RFC 8950's extended next-hop
/// encoding allows an IPv6-transport session to carry IPv4 unicast NLRI, so
/// this must never be derived from, or cross-validated against, either
/// address's IP version.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Cli)]
pub enum AddressFamily {
    #[cli(words = "ipv4")]
    Ipv4Unicast,
    #[cli(words = "ipv6")]
    Ipv6Unicast,
    /// RFC 7432 EVPN (AFI 25 / SAFI 70). Appended last: postcard indexes
    /// enum variants by position.
    L2vpnEvpn,
}

impl AddressFamily {
    /// Every variant, in declaration order.
    pub const ALL: [AddressFamily; 3] = [
        AddressFamily::Ipv4Unicast,
        AddressFamily::Ipv6Unicast,
        AddressFamily::L2vpnEvpn,
    ];

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli)]
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

/// RFC 7313 §4 default upper bound on how long routes stay stale after a
/// `BoRR` with no `EoRR` (`BgpPeerGroup.route_refresh_stale_time`): the
/// stale-path default FRR and Cisco use for graceful restart.
pub const ROUTE_REFRESH_STALE_TIME_DEFAULT_SECS: u16 = 360;

/// Controls the `NEXT_HOP` path attribute this instance writes into every
/// UPDATE it advertises to a peer-group's sessions. `SelfAddress` rewrites it
/// to the session's own local address ("next-hop-self"); `Unchanged`
/// preserves the next-hop the route already carries (the address it was
/// received with, for a peer-learned route). `BgpPeerGroup.next_hop: None`
/// resolves to `SelfAddress` for an eBGP peer-group and `Unchanged` for an
/// iBGP or route-server-client one — standard BGP practice, since an iBGP speaker must not silently
/// mask a route's real eBGP-learned next-hop unless explicitly told to.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub enum NextHopMode {
    #[cli(words = "self")]
    SelfAddress,
    Unchanged,
}

/// RFC 9234 §4.1 BGP Role: what this speaker is to the peer. Carried in the
/// OPEN's Role capability (code 9); the pair must be legal (Provider/Customer,
/// RS/RS-Client, Peer/Peer) or the session is refused with Role Mismatch.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub enum BgpRole {
    Provider,
    RouteServer,
    RouteServerClient,
    Customer,
    Peer,
}

impl BgpRole {
    /// RFC 9234 §4.1 capability value.
    pub fn wire(self) -> u8 {
        match self {
            BgpRole::Provider => 0,
            BgpRole::RouteServer => 1,
            BgpRole::RouteServerClient => 2,
            BgpRole::Customer => 3,
            BgpRole::Peer => 4,
        }
    }

    pub fn from_wire(v: u8) -> Option<Self> {
        Some(match v {
            0 => BgpRole::Provider,
            1 => BgpRole::RouteServer,
            2 => BgpRole::RouteServerClient,
            3 => BgpRole::Customer,
            4 => BgpRole::Peer,
            _ => return None,
        })
    }

    /// RFC 9234 §4.2 Table 2: the role the *peer* must announce for this
    /// one to be a legal pair.
    #[must_use]
    pub fn counterpart(self) -> Self {
        match self {
            BgpRole::Provider => BgpRole::Customer,
            BgpRole::Customer => BgpRole::Provider,
            BgpRole::RouteServer => BgpRole::RouteServerClient,
            BgpRole::RouteServerClient => BgpRole::RouteServer,
            BgpRole::Peer => BgpRole::Peer,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            BgpRole::Provider => "provider",
            BgpRole::RouteServer => "route-server",
            BgpRole::RouteServerClient => "route-server-client",
            BgpRole::Customer => "customer",
            BgpRole::Peer => "peer",
        }
    }
}

/// RFC 7911 ADD-PATH direction for a peer-group's unicast families: whether
/// this side offers to receive several paths per prefix, send them, or both.
/// What is actually used per family is negotiated against the peer's own
/// capability (RFC 7911 §5).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub enum BgpAddPath {
    Receive,
    Send,
    Both,
}

impl BgpAddPath {
    /// The capability's Send/Receive value (RFC 7911 §4): 1 receive, 2
    /// send, 3 both.
    pub fn send_receive(self) -> u8 {
        match self {
            BgpAddPath::Receive => 1,
            BgpAddPath::Send => 2,
            BgpAddPath::Both => 3,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            BgpAddPath::Receive => "receive",
            BgpAddPath::Send => "send",
            BgpAddPath::Both => "both",
        }
    }
}

/// Administrative shutdown (RFC 4486 Cease/Administrative Shutdown). While set
/// on a peer-group, or on an individual `BgpPeer` (which overrides the group),
/// no session is opened or accepted; an established one is closed with a
/// NOTIFICATION carrying `message` as an RFC 9003 shutdown communication.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub struct BgpShutdown {
    #[cli(topic = BgpPeerGroupShutdown)]
    pub message: Option<String>,
}

/// RFC 2439 route flap damping of routes received from a peer-group, all times
/// in seconds. A route's penalty rises on each flap, halves every `half_life`,
/// suppresses the route at `>= suppress` and releases it below `reuse`; it
/// never exceeds the ceiling implied by `max_suppress`. `Default` is RFC 7196's
/// conservative recommendation. eBGP peer-groups only (`bgp_instance`).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct BgpDamping {
    #[cli(topic = BgpPeerGroupDamping)]
    pub half_life: u32,
    #[cli(topic = BgpPeerGroupDamping)]
    pub reuse: u32,
    #[cli(topic = BgpPeerGroupDamping)]
    pub suppress: u32,
    #[cli(topic = BgpPeerGroupDamping)]
    pub max_suppress: u32,
}

impl Default for BgpDamping {
    fn default() -> Self {
        Self {
            half_life: 900,
            reuse: 750,
            suppress: 6000,
            max_suppress: 3600,
        }
    }
}

pub(super) fn valid_damping(d: Option<&BgpDamping>) -> garde::Result {
    let Some(d) = d else { return Ok(()) };
    if d.half_life == 0 || d.reuse == 0 || d.suppress <= d.reuse || d.max_suppress < d.half_life {
        return Err(garde::Error::new(
            "damping needs half-life > 0, reuse > 0, suppress > reuse and max-suppress >= half-life",
        ));
    }
    Ok(())
}

/// Vendor `local-as` (IOS/Junos; no RFC): the AS this group's peers see
/// instead of the instance's own (its `asn`, or the confederation
/// identifier). The OPEN carries `asn`; outbound `AS_PATH` gets `[asn, own]`
/// (`[asn]` with `replace_as`); a received path gets `asn` prepended unless
/// `no_prepend`, and holding `asn` counts as a loop for this group's routes.
/// External (non-confederation eBGP) peer-groups only
/// (`bgp_instance::valid_route_reflection_and_server`).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub struct BgpLocalAs {
    #[cli(topic = BgpPeerGroupLocalAs)]
    pub asn: u32,
    #[serde(default)]
    #[cli(topic = BgpPeerGroupLocalAs)]
    pub no_prepend: bool,
    #[serde(default)]
    #[cli(topic = BgpPeerGroupLocalAs)]
    pub replace_as: bool,
}

/// One address family's RFC 4486 §4 maximum-prefix limit: more than `limit`
/// accepted (post-import-policy) prefixes from one peer closes the session
/// with Cease/Maximum Number of Prefixes Reached, unless `warning_only`.
/// `restart_interval` (seconds) re-allows the session after that long; `0`
/// keeps the peer down until `clear bgp <instance> <peer>` or a shut/no-shut.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub struct BgpPrefixLimit {
    #[cli(topic = BgpPeerGroupMaximumPrefixLimit)]
    pub limit: u32,
    #[serde(default)]
    #[cli(topic = BgpPeerGroupMaximumPrefixWarningOnly)]
    pub warning_only: bool,
    #[serde(default)]
    #[cli(topic = BgpPeerGroupMaximumPrefixRestartInterval)]
    pub restart_interval: u16,
}

/// Per-address-family maximum-prefix limits; `None` means unlimited. A fixed
/// struct rather than a list keyed by `AddressFamily`: the family set is
/// closed, and three fields give the same CLI/REST shape with no enum-keyed
/// list support in the config path grammar.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub struct BgpMaximumPrefix {
    #[cli(topic = BgpPeerGroupMaximumPrefix)]
    pub ipv4: Option<BgpPrefixLimit>,
    #[cli(topic = BgpPeerGroupMaximumPrefix)]
    pub ipv6: Option<BgpPrefixLimit>,
    #[cli(topic = BgpPeerGroupMaximumPrefix)]
    pub l2vpn_evpn: Option<BgpPrefixLimit>,
}

impl BgpMaximumPrefix {
    pub fn get(&self, family: AddressFamily) -> Option<BgpPrefixLimit> {
        match family {
            AddressFamily::Ipv4Unicast => self.ipv4,
            AddressFamily::Ipv6Unicast => self.ipv6,
            AddressFamily::L2vpnEvpn => self.l2vpn_evpn,
        }
    }

    pub fn slot_mut(&mut self, family: AddressFamily) -> &mut Option<BgpPrefixLimit> {
        match family {
            AddressFamily::Ipv4Unicast => &mut self.ipv4,
            AddressFamily::Ipv6Unicast => &mut self.ipv6,
            AddressFamily::L2vpnEvpn => &mut self.l2vpn_evpn,
        }
    }
}

fn valid_maximum_prefix(m: &BgpMaximumPrefix) -> garde::Result {
    if AddressFamily::ALL
        .iter()
        .any(|af| m.get(*af).is_some_and(|l| l.limit == 0))
    {
        return Err(garde::Error::new("maximum-prefix limit must be at least 1"));
    }
    Ok(())
}

/// RFC 9003 §2: the shutdown communication is at most 255 octets of UTF-8.
pub const SHUTDOWN_MESSAGE_MAX: usize = 255;

pub(super) fn valid_shutdown(s: Option<&BgpShutdown>) -> garde::Result {
    match s.and_then(|s| s.message.as_ref()) {
        Some(m) if m.len() > SHUTDOWN_MESSAGE_MAX => Err(garde::Error::new(
            "shutdown message must be at most 255 bytes",
        )),
        _ => Ok(()),
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli, Default)]
#[garde(context(Config as ctx))]
#[allow(clippy::struct_excessive_bools)] // each bool is an independent schema field
pub struct BgpPeerGroup {
    #[garde(length(min = 1, max = 64), custom(|n, ctx: &Config| unique_name(n, ctx)))]
    #[cli(key)]
    pub name: String,

    // RFC 6793: ASN 0 and 4_294_967_295 are reserved.
    #[garde(range(min = 1, max = 4_294_967_294u32))]
    #[cli(topic = BgpPeerGroupRemoteAs)]
    pub remote_as: u32,

    // Transport source address. Deliberately `#[garde(skip)]` and never
    // cross-validated against `address_families` or a peer's
    // `remote_address` — see `AddressFamily`'s doc comment. Also never
    // cross-validated against `Config.interfaces` — like
    // `BgpInstance.routing_table`'s VRF, the referenced interface is
    // resolved by `nos-bgpd` itself and may not exist yet in this
    // transaction.
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupSourceAddress)]
    pub source_address: Option<SourceAddress>,

    #[garde(custom(|afs, _ctx: &Config| non_empty_no_duplicate_afs(afs)))]
    #[cli(topic = BgpPeerGroupAddressFamily)]
    pub address_families: Vec<AddressFamily>,

    /// `None` defaults to `HOLD_TIME_DEFAULT` (90s). `Some(0)` disables both
    /// the hold timer and keepalives entirely; otherwise must be `>=
    /// HOLD_TIME_FLOOR` (RFC 4271 §6.2). The value actually used by a
    /// session is `min(this, the peer's own proposed hold time)`.
    #[garde(custom(|h: &Option<u16>, _ctx: &Config| valid_hold_time(*h)))]
    #[cli(topic = BgpPeerGroupHoldTime)]
    pub hold_time: Option<u16>,

    /// `None` defaults to `negotiated_hold / 3`, computed after negotiation
    /// (RFC 4271's suggested ratio). When both this and `hold_time` are set,
    /// this must be strictly less than `hold_time` — checked one level up,
    /// on `BgpInstance.peer_groups`, since garde's per-field `custom`
    /// closures can't see a sibling field (see `bgp_instance.rs`).
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupKeepaliveInterval)]
    pub keepalive_interval: Option<u16>,

    /// `None` defaults to `CONNECT_RETRY_TIME_DEFAULT_SECS` (120s).
    #[garde(custom(|c: &Option<u16>, _ctx: &Config| valid_connect_retry_time(*c)))]
    #[cli(topic = BgpPeerGroupConnectRetryTime)]
    pub connect_retry_time: Option<u16>,

    /// RFC 4271 §9.2.1.1 `MinRouteAdvertisementInterval`, in seconds: at most
    /// one batch of advertisements per this interval to each peer (withdrawals
    /// are exempt). `None` (or 0) disables pacing — every change is sent at once.
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupMrai)]
    pub mrai: Option<u16>,

    /// RFC 7313 §4: seconds routes from a peer stay stale after its `BoRR`
    /// before they're purged as if its `EoRR` had arrived. `None` defaults to
    /// `ROUTE_REFRESH_STALE_TIME_DEFAULT_SECS` (360s); 0 disables the timer.
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupRouteRefreshStaleTime)]
    pub route_refresh_stale_time: Option<u16>,

    /// RFC 2439 flap damping of routes received from this group; `None`
    /// disables it. See `BgpDamping`.
    #[garde(custom(|d: &Option<BgpDamping>, _ctx: &Config| valid_damping(d.as_ref())))]
    #[cli(topic = BgpPeerGroupDamping)]
    pub damping: Option<BgpDamping>,

    /// RFC 5082 GTSM: the most router hops away the peer may be (1 =
    /// directly connected, 1..=254). Sends with TTL/hop-limit 255 and drops
    /// received packets below `256 - max_hops`. `None` disables it.
    #[garde(custom(|h: &Option<u8>, _ctx: &Config| valid_max_hops(*h)))]
    #[cli(topic = BgpPeerGroupMaxHops)]
    pub max_hops: Option<u8>,

    /// `None` opens sessions with no transport authentication at all.
    /// Secrets are stored clear-text, like every other field in this config
    /// — see `BgpAuth`.
    #[garde(custom(|a: &Option<BgpAuth>, _ctx: &Config| valid_auth(a.as_ref())))]
    #[cli(topic = BgpPeerGroupAuth, render = sugar::render_bgp_auth, sugar(word = "md5-password", with = sugar::md5_password, topic = BgpPeerGroupMd5Password), sugar(word = "ao-key", with = sugar::ao_key, topic = BgpPeerGroupAoKey))]
    pub auth: Option<BgpAuth>,

    /// `None` defaults to `SelfAddress` for an eBGP peer-group and
    /// `Unchanged` for an iBGP or `route_server_client` one (RFC 7947
    /// §2.2.1) — see `NextHopMode`.
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupNextHop)]
    pub next_hop: Option<NextHopMode>,

    /// RFC 4456 route-reflector client: routes learned from other iBGP
    /// peers are reflected to this peer (and vice versa) instead of being
    /// withheld by the usual iBGP split-horizon rule. Requires this
    /// peer-group's `remote_as` to equal the owning instance's `asn` (an
    /// iBGP peer-group) — checked cross-instance, see
    /// `bgp_instance::valid_route_reflection_and_server`. Mutually exclusive
    /// with `route_server_client`.
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupRouteReflectorClient)]
    pub route_reflector_client: bool,

    /// RFC 7947 route-server client: this peer-group's own ASN is never
    /// prepended to `AS_PATH` when advertising to it, and (via RFC 7911
    /// ADD-PATH) it receives every other route-server-client's path for a
    /// prefix, not just the one instance-wide elected best path. Requires
    /// this peer-group's `remote_as` to differ from the owning instance's
    /// `asn` (an eBGP peer-group). Mutually exclusive with
    /// `route_reflector_client`.
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupRouteServerClient)]
    pub route_server_client: bool,

    /// `None` defaults to `deny-all` — this NOS never leaves a direction
    /// unfiltered, unlike every other `Option` field on this struct, which
    /// defaults to some permissive/derived behavior. See root `CLAUDE.md`'s
    /// "Default-deny rollout impact".
    #[garde(custom(|p: &Option<String>, ctx: &Config| policy_reference_valid(p.as_ref(), ctx)))]
    #[cli(topic = BgpPeerGroupImportPolicy)]
    pub import_policy: Option<String>,

    /// Same default-deny semantics as `import_policy`, applied on
    /// advertisement instead of receipt.
    #[garde(custom(|p: &Option<String>, ctx: &Config| policy_reference_valid(p.as_ref(), ctx)))]
    #[cli(topic = BgpPeerGroupExportPolicy)]
    pub export_policy: Option<String>,

    /// See `BgpShutdown`. Appended last, like every later-added field.
    #[garde(custom(|s: &Option<BgpShutdown>, _ctx: &Config| valid_shutdown(s.as_ref())))]
    #[cli(topic = BgpPeerGroupShutdown, render = sugar::render_shutdown, sugar(word = "shutdown", with = sugar::shutdown, topic = BgpPeerGroupShutdown))]
    pub shutdown: Option<BgpShutdown>,

    /// RFC 4486 §4 per-address-family maximum-prefix limits — see
    /// `BgpPrefixLimit`. A limit for a family not in `address_families` is
    /// rejected (`valid_peer_group_timers`).
    #[serde(default)]
    #[garde(custom(|m: &BgpMaximumPrefix, _ctx: &Config| valid_maximum_prefix(m)))]
    #[cli(topic = BgpPeerGroupMaximumPrefix)]
    pub maximum_prefix: BgpMaximumPrefix,

    /// RFC 8097: send each route's RPKI origin validation state to these
    /// peers as a non-transitive extended community, and take the state
    /// from theirs while this instance has no VRP data of its own. iBGP
    /// peer-groups only (`bgp_instance::valid_route_reflection_and_server`).
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupAnnounceRpkiState)]
    pub announce_rpki_state: bool,

    /// See `BgpLocalAs`; `None` presents the instance's own AS.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupLocalAs)]
    pub local_as: Option<BgpLocalAs>,

    /// RFC 7911 ADD-PATH for this group's unicast families (`ipv4`/`ipv6`;
    /// never EVPN). `None` is `Both` for a `route_server_client` group and off
    /// otherwise. Carried in the OPEN, so a change restarts the sessions.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupAddPath)]
    pub add_path: Option<BgpAddPath>,

    /// RFC 7911: how many paths per prefix this group is sent when ADD-PATH
    /// send is negotiated: the best N by the decision process, after this
    /// group's own filtering (split horizon, export policy). Unset: 2, or
    /// every path for a route-server client. Needs `add_path` send or both.
    #[serde(default)]
    #[garde(range(min = 2, max = 64))]
    #[cli(topic = BgpPeerGroupAddPathSendCount)]
    pub add_path_send_count: Option<u8>,

    /// RFC 9234 BGP Role this group's peers are to us — see `BgpRole`. eBGP
    /// only; a change restarts the sessions (it is in the OPEN).
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupRole)]
    pub role: Option<BgpRole>,

    /// RFC 9234 §4.2 strict mode: refuse (Role Mismatch) a peer whose OPEN
    /// carries no Role capability. Needs `role`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupStrictMode)]
    pub strict_mode: bool,
}

impl BgpPeerGroup {
    /// `add_path` with its default applied: `Both` for a route-server client.
    pub fn effective_add_path(&self) -> Option<BgpAddPath> {
        self.add_path
            .or(self.route_server_client.then_some(BgpAddPath::Both))
    }

    /// How many paths per prefix an ADD-PATH send peer of this group gets:
    /// `add_path_send_count`, else `default_add_path_send_count`. `None` is
    /// every path.
    pub fn effective_add_path_send_count(&self) -> Option<usize> {
        self.add_path_send_count.map_or_else(
            || Self::default_add_path_send_count(self.route_server_client),
            |n| Some(usize::from(n)),
        )
    }

    /// The unset `add_path_send_count`: every path for a route-server client
    /// (RFC 7947 transparency), 2 (best plus one backup) otherwise.
    pub fn default_add_path_send_count(route_server_client: bool) -> Option<usize> {
        (!route_server_client).then_some(2)
    }
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub enum BgpAuth {
    /// RFC 2385 TCP MD5 signature — a single shared password.
    Md5 { password: String },
    /// RFC 5925 TCP Authentication Option — one or more keys, supporting
    /// rotation via `send_id`/`recv_id` and the `is_current`/`is_rnext`
    /// flags.
    Ao { keys: Vec<BgpAoKey> },
}

/// One TCP-AO key. `send_id`/`recv_id` identify it on the wire (RFC 5925's
/// `KeyID`/`RNextKeyID`); `is_current` marks the key a new connection starts
/// signing with (exactly one key must have this set; on a live session the
/// peer's `RNextKeyID` decides, RFC 5925 §7.5.2); `is_rnext` optionally asks
/// the peer to switch to this key next, for rotation without a dropped
/// session (applied to the live session in place); `exclude_options` (RFC 5925 §5.2, `#[serde(default)]`
/// so pre-existing on-disk config still loads as today's always-include
/// behavior) excludes TCP options from this key's MAC coverage — both peers
/// must agree, or authentication fails.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli)]
#[cli(no_default)]
pub struct BgpAoKey {
    #[cli(key)]
    pub send_id: u8,
    #[cli(topic = BgpPeerGroupAoKey)]
    pub recv_id: u8,
    #[cli(topic = BgpPeerGroupAoKey)]
    pub algorithm: BgpAoAlgorithm,
    #[cli(topic = BgpPeerGroupAoKey)]
    pub key: String,
    #[cli(topic = BgpPeerGroupAoKey)]
    pub is_current: bool,
    #[cli(topic = BgpPeerGroupAoKey)]
    pub is_rnext: bool,
    #[serde(default)]
    #[cli(topic = BgpPeerGroupAoKey)]
    pub exclude_options: bool,
}

/// RFC 5925's two mandatory-to-implement algorithms.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub enum BgpAoAlgorithm {
    #[cli(words = "hmac-sha1")]
    HmacSha1_96,
    #[cli(words = "aes-cmac")]
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
            let mut seen_recv_ids: Vec<u8> = Vec::new();
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
                // RFC 5925 §3.1: the kernel refuses (EEXIST) overlapping
                // RecvIDs just like SendIDs, at socket time otherwise.
                if seen_recv_ids.contains(&key.recv_id) {
                    return Err(garde::Error::new(
                        "ao key recv-id must be unique within a peer-group",
                    ));
                }
                seen_recv_ids.push(key.recv_id);
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

fn valid_max_hops(max_hops: Option<u8>) -> garde::Result {
    match max_hops {
        None | Some(1..=254) => Ok(()),
        Some(_) => Err(garde::Error::new("max-hops must be between 1 and 254")),
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
        if AddressFamily::ALL.iter().any(|af| {
            group.maximum_prefix.get(*af).is_some() && !group.address_families.contains(af)
        }) {
            return Err(garde::Error::new(
                "maximum-prefix is set for an address family the peer-group does not negotiate",
            ));
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
            maximum_paths: None,
            confederation: crate::schema::BgpConfederation::default(),
            rpki_caches: Vec::new(),
            aggregates: Vec::new(),
            graceful_restart: crate::schema::BgpGracefulRestart::default(),
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
            local_as: None,
            add_path: None,
            add_path_send_count: None,
            role: None,
            strict_mode: false,
        }
    }

    fn config_with(instances: Vec<BgpInstance>) -> Config {
        Config {
            bgp_instances: instances,
            ..Default::default()
        }
    }

    #[test]
    fn maximum_prefix_needs_a_negotiated_family_and_a_nonzero_limit() {
        let check = |family: AddressFamily, limit: u32| {
            let mut g = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
            *g.maximum_prefix.slot_mut(family) = Some(BgpPrefixLimit {
                limit,
                ..Default::default()
            });
            let cfg = config_with(vec![instance_with_groups("r1", vec![g])]);
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(check(AddressFamily::Ipv4Unicast, 1));
        assert!(!check(AddressFamily::Ipv4Unicast, 0), "limit 0");
        assert!(!check(AddressFamily::Ipv6Unicast, 5), "ipv6 not negotiated");
        assert!(!check(AddressFamily::L2vpnEvpn, 5), "evpn not negotiated");
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
            exclude_options: false,
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
    fn ao_with_duplicate_recv_id_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        let mut second = ao_key(2, false);
        second.recv_id = 1;
        pg.auth = Some(BgpAuth::Ao {
            keys: vec![ao_key(1, true), second],
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

    #[test]
    fn add_path_defaults_to_both_for_a_route_server_client_only() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        assert_eq!(pg.effective_add_path(), None);
        pg.route_server_client = true;
        assert_eq!(pg.effective_add_path(), Some(BgpAddPath::Both));
        pg.add_path = Some(BgpAddPath::Receive);
        assert_eq!(pg.effective_add_path(), Some(BgpAddPath::Receive));
    }

    #[test]
    fn role_wire_and_counterpart() {
        for v in 0..=4 {
            let r = BgpRole::from_wire(v).unwrap();
            assert_eq!(r.wire(), v);
            assert_eq!(r.counterpart().counterpart(), r);
        }
        assert_eq!(BgpRole::from_wire(5), None);
        assert_eq!(BgpRole::Provider.counterpart(), BgpRole::Customer);
        assert_eq!(BgpRole::Peer.counterpart(), BgpRole::Peer);
    }
}
