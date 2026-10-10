//! One-shot config provisioning tool for manually verifying the nos-bgpd
//! FSM feature end to end across two real containers. Not part of the nos
//! workspace — nos-cli's interactive shell (reedline) can't be driven over
//! a plain pipe, so this speaks nos-configd's IPC protocol directly,
//! reusing nos-proto's own types for wire compatibility.
//!
//! Sets up exactly one "router": one interface (one address) enslaved to
//! one routing table, one BGP instance (asn/router-id) owning that routing
//! table, one peer-group (remote-as + ipv4-unicast), one peer using that
//! peer-group. Opens a transaction, applies every op, commits, and (if
//! `--save` is passed) persists it.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use anyhow::{bail, Context};
use clap::Parser;

use ipnet::{IpNet, Ipv4Net};
use nos_proto::{
    AddressFamily, BfdProfileOp, BgpAoAlgorithm, BgpAoKey, BgpInstanceOp, BgpPeerGroupOp,
    BgpPeerOp, BroadcastDomainOp, ConfigOp, EsRedundancy, InterfaceOp, LacpRate, LldpDestination,
    LldpOp, LogLevel, LoggingOp, NetworkType, OspfAreaOp, OspfAreaType, OspfCryptoAlgorithm,
    OspfCryptoKey, OspfInstanceOp, OspfProfileOp, Ospfv3AreaOp, Ospfv3InstanceOp, Ospfv3ProfileOp,
    PolicyDefinitionOp, PortAggregateMode, PortAggregateOp, PortAggregateSubinterfaceOp,
    Redistribute, RedistributeSource, RedistributeTarget, RoutingTableEvpn, RoutingTableOp,
    SourceAddress, StaticRouteOp, StaticRoutingInstanceOp, StpPortProfileOp, SubinterfaceOp,
    SwitchingProfileOp, SyslogFacility, SyslogTransport, UserOp, VlanTag,
};

/// Clap-facing mirror of the `spanning-tree mode` values the e2e lab uses.
#[derive(Clone, Copy, clap::ValueEnum)]
pub enum StpModeArg {
    Rstp,
    Mstp,
    RapidPvst,
    Disabled,
}

impl From<StpModeArg> for nos_proto::StpMode {
    fn from(mode: StpModeArg) -> Self {
        match mode {
            StpModeArg::Rstp => nos_proto::StpMode::Rstp,
            StpModeArg::Mstp => nos_proto::StpMode::Mstp,
            StpModeArg::RapidPvst => nos_proto::StpMode::RapidPvst,
            StpModeArg::Disabled => nos_proto::StpMode::Disabled,
        }
    }
}

/// Clap-facing mirror of `spanning-tree force-version`.
#[derive(Clone, Copy, clap::ValueEnum)]
pub enum StpForceVersionArg {
    Stp,
    Rstp,
}

impl From<StpForceVersionArg> for nos_proto::schema::StpForceVersion {
    fn from(v: StpForceVersionArg) -> Self {
        match v {
            StpForceVersionArg::Stp => nos_proto::schema::StpForceVersion::Stp,
            StpForceVersionArg::Rstp => nos_proto::schema::StpForceVersion::Rstp,
        }
    }
}

/// Clap-facing mirror of `nos_proto::PortAggregateMode` — `clap::ValueEnum`
/// can't be derived on a `nos-proto` type directly (that crate stays
/// dependency-free of `clap`, per the star-dependency rule).
#[derive(Clone, Copy, clap::ValueEnum)]
pub enum PortAggregateModeArg {
    Xor,
    Lacp,
}

impl From<PortAggregateModeArg> for PortAggregateMode {
    fn from(mode: PortAggregateModeArg) -> Self {
        match mode {
            PortAggregateModeArg::Xor => PortAggregateMode::Xor,
            PortAggregateModeArg::Lacp => PortAggregateMode::Lacp,
        }
    }
}

/// Clap-facing mirror of `nos_proto::EsRedundancy` (`all-active` /
/// `single-active`), for the same reason as `PortAggregateModeArg`.
#[derive(Clone, Copy, clap::ValueEnum)]
pub enum EsRedundancyArg {
    AllActive,
    SingleActive,
}

impl From<EsRedundancyArg> for EsRedundancy {
    fn from(mode: EsRedundancyArg) -> Self {
        match mode {
            EsRedundancyArg::AllActive => EsRedundancy::AllActive,
            EsRedundancyArg::SingleActive => EsRedundancy::SingleActive,
        }
    }
}

/// Clap-facing mirror of `nos_proto::DfAlgorithm` (`modulo` / `hrw`).
#[derive(Clone, Copy, clap::ValueEnum)]
pub enum DfAlgorithmArg {
    Modulo,
    Hrw,
}

impl From<DfAlgorithmArg> for nos_proto::DfAlgorithm {
    fn from(a: DfAlgorithmArg) -> Self {
        match a {
            DfAlgorithmArg::Modulo => nos_proto::DfAlgorithm::Modulo,
            DfAlgorithmArg::Hrw => nos_proto::DfAlgorithm::Hrw,
        }
    }
}

/// Clap-facing mirror of `nos_proto::LacpMode`.
#[derive(Clone, Copy, clap::ValueEnum)]
pub enum LacpModeArg {
    Active,
    Passive,
}

impl From<LacpModeArg> for nos_proto::LacpMode {
    fn from(mode: LacpModeArg) -> Self {
        match mode {
            LacpModeArg::Active => nos_proto::LacpMode::Active,
            LacpModeArg::Passive => nos_proto::LacpMode::Passive,
        }
    }
}

/// Clap-facing mirror of `nos_proto::LacpRate`, for the same reason as
/// `PortAggregateModeArg`.
#[derive(Clone, Copy, clap::ValueEnum)]
pub enum LacpRateArg {
    Slow,
    Fast,
}

impl From<LacpRateArg> for LacpRate {
    fn from(rate: LacpRateArg) -> Self {
        match rate {
            LacpRateArg::Slow => LacpRate::Slow,
            LacpRateArg::Fast => LacpRate::Fast,
        }
    }
}

/// Clap-facing mirror of `nos_proto::BgpAoAlgorithm`, for the same reason as
/// `PortAggregateModeArg`.
#[derive(Clone, Copy, clap::ValueEnum)]
pub enum BgpAoAlgorithmArg {
    HmacSha1,
    AesCmac,
}

impl From<BgpAoAlgorithmArg> for BgpAoAlgorithm {
    fn from(algorithm: BgpAoAlgorithmArg) -> Self {
        match algorithm {
            BgpAoAlgorithmArg::HmacSha1 => BgpAoAlgorithm::HmacSha1_96,
            BgpAoAlgorithmArg::AesCmac => BgpAoAlgorithm::AesCmac96,
        }
    }
}

#[derive(Parser)]
#[allow(clippy::struct_excessive_bools)] // one CLI flag per independent provisioning toggle
pub struct Args {
    #[arg(long)]
    pub config_socket: Option<PathBuf>,

    #[arg(long, default_value = "eth0")]
    pub interface: String,
    #[arg(long)]
    pub address: IpNet,

    /// Which of `--interface`'s subinterfaces `--address`/`--routing-table`
    /// target — `0` (default) for the untagged/native subinterface,
    /// matching a bare `set interface <name> address ...` in nos-cli.
    /// `1..=4094` targets a real 802.1q VLAN subinterface instead.
    #[arg(long, default_value_t = 0)]
    pub subinterface_tag: u16,

    /// If set, deletes `--interface`'s `--subinterface-tag` subinterface
    /// instead of setting its address/routing-table.
    #[arg(long)]
    pub delete_subinterface: bool,

    /// The interface `--mtu`/`--clear-mtu`/`--switching-profile`/
    /// `--delete-switching-profile` act on, if not `--interface` — so a
    /// phase can change another link without moving the base address.
    #[arg(long)]
    pub link_interface: Option<String>,

    /// If set, sets `--interface`'s own mtu (`InterfaceOp::SetMtu`) — for
    /// verifying `nos-interfaced`'s Linux driver actually applies it to the
    /// real kernel link.
    #[arg(long)]
    pub mtu: Option<u32>,

    /// If set, clears `--interface`'s mtu (`InterfaceOp::ClearMtu`), which
    /// `nos-interfaced` enforces as 1500.
    #[arg(long)]
    pub clear_mtu: bool,

    #[arg(long, default_value = "rt1")]
    pub routing_table: String,

    /// If set, pins `nos-restd` to `--routing-table`, listening on this
    /// address inside its VRF (`RoutingTableOp::SetRestApi`). Mutually
    /// exclusive with `--clear-rest-api`.
    #[arg(long)]
    pub rest_api_address: Option<IpAddr>,

    /// TCP port for `--rest-api-address`.
    #[arg(long, default_value_t = nos_proto::REST_API_PORT_DEFAULT)]
    pub rest_api_port: u16,

    /// If set, unpins `nos-restd` from `--routing-table`
    /// (`RoutingTableOp::ClearRestApi`).
    #[arg(long)]
    pub clear_rest_api: bool,

    #[arg(long, default_value = "r1")]
    pub bgp_instance: String,
    #[arg(long)]
    pub asn: u32,
    #[arg(long)]
    pub router_id: Ipv4Addr,

    #[arg(long, default_value = "pg1")]
    pub peer_group: String,
    #[arg(long)]
    pub remote_as: u32,

    #[arg(long)]
    pub peer: IpAddr,

    /// Adds a static route (`--static-gateway` required) to a
    /// static-routing-instance associated with `--routing-table`. Repeat it
    /// for more than one, all via the same gateway.
    #[arg(long)]
    pub static_route: Vec<IpNet>,
    #[arg(long)]
    pub static_gateway: Option<IpAddr>,
    #[arg(long, default_value = "sri1")]
    pub static_routing_instance: String,

    /// If set, configures `redistribute from static to bgp` on
    /// `--routing-table` — requires `--static-route` to also be set (so the
    /// table has a `static_routing_instance` to redistribute from).
    #[arg(long)]
    pub redistribute: bool,

    /// Names an RPL policy (or `accept-all`/`deny-all`) to filter
    /// redistributed routes through — the redistribute rule's optional
    /// `policy <name>` clause. Only meaningful with `--redistribute`;
    /// omitted, redistribution stays unfiltered.
    #[arg(long)]
    pub redistribute_policy: Option<String>,

    /// If set, configures `redistribute from static to ospf` on
    /// `--routing-table` — makes this router a real RFC 2328 ASBR. Requires
    /// `--static-route` (so the table has a `static_routing_instance` to
    /// redistribute from) and `--ospf-instance` (so the table has an
    /// `ospf_instance` to redistribute into) to also be set. Not mutually
    /// exclusive with `--redistribute`/`--redistribute-to-ospfv3`: the table
    /// keeps one rule per target.
    #[arg(long)]
    pub redistribute_to_ospf: bool,

    /// Names an RPL policy (or `accept-all`/`deny-all`) to filter routes
    /// redistributed into OSPF through. Only meaningful with
    /// `--redistribute-to-ospf`; omitted, redistribution stays unfiltered.
    #[arg(long)]
    pub redistribute_to_ospf_policy: Option<String>,

    /// External metric of the AS-external-LSAs `--redistribute-to-ospf`
    /// sends (1..=16777215; unset = 20).
    #[arg(long)]
    pub redistribute_metric: Option<u32>,

    /// External metric type, 1 or 2, for `--redistribute-to-ospf` (unset = 1).
    #[arg(long)]
    pub redistribute_metric_type: Option<u8>,

    /// If set, removes `--routing-table`'s `to ospf` redistribute rule
    /// (`RoutingTableOp::ClearRedistribute`) — for verifying that a
    /// redistributed prefix's AS-external-LSA is actually withdrawn (RFC
    /// 2328 §14.1) rather than left to age out. Mutually exclusive with
    /// `--redistribute-to-ospf`.
    #[arg(long)]
    pub clear_redistribute_to_ospf: bool,

    /// `--redistribute-to-ospf`'s `OSPFv3` twin: `redistribute from static to
    /// ospfv3` on `--routing-table` (an RFC 5340 ASBR; IPv6 statics only).
    /// Requires `--static-route` and `--ospfv3-instance`.
    #[arg(long)]
    pub redistribute_to_ospfv3: bool,

    /// The RPL policy for `--redistribute-to-ospfv3`.
    #[arg(long)]
    pub redistribute_to_ospfv3_policy: Option<String>,

    /// `--clear-redistribute-to-ospf`'s twin: removes the table's redistribute
    /// rule, so the AS-External-LSAs are flushed.
    #[arg(long)]
    pub clear_redistribute_to_ospfv3: bool,

    /// If set, configures an RFC 2385 TCP MD5 password on `--peer-group`
    /// (`BgpPeerGroupOp::SetMd5Auth`) — for verifying session authentication
    /// end to end (matching passwords on both routers establish; a
    /// mismatched one on either side does not).
    #[arg(long)]
    pub md5_password: Option<String>,

    /// If set (with `--ao-key-secret`), upserts an RFC 5925 TCP-AO key on
    /// `--peer-group` by this `SendID` (`BgpPeerGroupOp::SetAoKey`).
    #[arg(long)]
    pub ao_send_id: Option<u8>,
    /// `RecvID` for the key set by `--ao-send-id`; defaults to the same value.
    #[arg(long)]
    pub ao_recv_id: Option<u8>,
    #[arg(long, value_enum, default_value_t = BgpAoAlgorithmArg::HmacSha1)]
    pub ao_algorithm: BgpAoAlgorithmArg,
    /// Secret for the key set by `--ao-send-id`.
    #[arg(long)]
    pub ao_key_secret: Option<String>,
    /// Marks the key set by `--ao-send-id` as the current key.
    #[arg(long)]
    pub ao_current: bool,
    /// Marks the key set by `--ao-send-id` as the rnext key.
    #[arg(long)]
    pub ao_rnext: bool,
    /// Sets `exclude_options` on the key set by `--ao-send-id`
    /// (`TCP_AO_KEYF_EXCLUDE_OPT`, RFC 5925 §5.2) — both peers must agree.
    #[arg(long)]
    pub ao_exclude_options: bool,
    /// Promotes an already-configured TCP-AO key to current, without
    /// resending its secret (`BgpPeerGroupOp::SetAoCurrentKey`) — for
    /// exercising RFC 5925 §7.5 rollover.
    #[arg(long)]
    pub ao_promote_current: Option<u8>,
    /// Removes a configured TCP-AO key by `SendID`
    /// (`BgpPeerGroupOp::RemoveAoKey`).
    #[arg(long)]
    pub ao_remove_key: Option<u8>,

    /// If set, marks `--peer-group` as an RFC 4456 route-reflector client
    /// (requires `--remote-as` to equal `--asn`, i.e. an iBGP peer-group).
    /// Calling this tool again with the same `--peer-group` but a different
    /// `--peer` adds a second client to the same peer-group, since
    /// `BgpPeerOp::Set` upserts by remote-address.
    #[arg(long)]
    pub route_reflector_client: bool,

    /// If set, marks `--peer-group` as an RFC 7947 route-server client
    /// (requires `--remote-as` to differ from `--asn`, i.e. an eBGP
    /// peer-group). Mutually exclusive with `--route-reflector-client`.
    #[arg(long)]
    pub route_server_client: bool,

    /// If set, `--peer-group` exchanges RFC 8097 RPKI validation states
    /// (requires an iBGP peer-group).
    #[arg(long)]
    pub announce_rpki_state: bool,

    /// If set, adds `address-family l2vpn-evpn` (RFC 7432, AFI 25 / SAFI 70)
    /// to `--peer-group`, alongside the default IPv4 unicast.
    #[arg(long)]
    pub evpn: bool,

    /// If set, overrides `--peer-group`'s connect-retry time in seconds
    /// (`BgpPeerGroupOp::SetConnectRetryTime`). The default is RFC 4271's
    /// 120s, which leaves both sides Idle that long after a collision.
    #[arg(long)]
    pub connect_retry_time: Option<u16>,

    /// If set, sets `--peer-group`'s `MinRouteAdvertisementInterval` in seconds
    /// (`BgpPeerGroupOp::SetMrai`).
    #[arg(long)]
    pub mrai: Option<u16>,

    /// If set, sets `--peer-group`'s RFC 7313 route refresh stale time in
    /// seconds (`BgpPeerGroupOp::SetRouteRefreshStaleTime`).
    #[arg(long)]
    pub route_refresh_stale_time: Option<u16>,

    /// If any is set, enables `--peer-group`'s RFC 2439 flap damping
    /// (`BgpPeerGroupOp::SetDamping`); the ones left out keep RFC 7196's defaults.
    #[arg(long)]
    pub damping_half_life: Option<u32>,
    #[arg(long)]
    pub damping_reuse: Option<u32>,
    #[arg(long)]
    pub damping_suppress: Option<u32>,
    #[arg(long)]
    pub damping_max_suppress: Option<u32>,

    /// Disables `--peer-group`'s flap damping (`BgpPeerGroupOp::ClearDamping`).
    #[arg(long)]
    pub clear_damping: bool,

    /// If set, sets `--peer-group`'s vendor local-as
    /// (`BgpPeerGroupOp::SetLocalAs`), with the two flags below.
    #[arg(long)]
    pub local_as: Option<u32>,
    #[arg(long)]
    pub local_as_no_prepend: bool,
    #[arg(long)]
    pub local_as_replace_as: bool,

    /// If set, sets `--peer-group`'s RFC 7911 ADD-PATH (`receive`, `send`
    /// or `both`; `BgpPeerGroupOp::SetAddPath`).
    #[arg(long, value_parser = parse_add_path)]
    pub add_path: Option<nos_proto::BgpAddPath>,

    /// If set, sets `--peer-group`'s RFC 7911 `add_path_send_count`
    /// (`BgpPeerGroupOp::SetAddPathSendCount`).
    #[arg(long)]
    pub add_path_send_count: Option<u8>,

    /// If set, sets `--peer-group`'s RFC 9234 role (`provider`, `route-server`,
    /// `route-server-client`, `customer` or `peer`; `BgpPeerGroupOp::SetRole`).
    #[arg(long, value_parser = parse_role)]
    pub role: Option<nos_proto::BgpRole>,

    /// RFC 9234 strict mode on `--peer-group` (`BgpPeerGroupOp::SetStrictMode`).
    #[arg(long)]
    pub strict_mode: bool,

    /// One `<family>=<limit>` per repetition (`ipv4`, `ipv6`, `l2vpn-evpn`):
    /// sets `--peer-group`'s RFC 4486 maximum-prefix for that family
    /// (`BgpPeerGroupOp::SetMaximumPrefix`), with the two flags below.
    #[arg(long = "maximum-prefix", value_parser = parse_maximum_prefix)]
    pub maximum_prefix: Vec<(AddressFamily, u32)>,
    /// Applied to every `--maximum-prefix` given: log only, never close.
    #[arg(long)]
    pub maximum_prefix_warning_only: bool,
    /// Applied to every `--maximum-prefix` given: retry after this many
    /// seconds (0, the default, stays down until cleared).
    #[arg(long, default_value_t = 0)]
    pub maximum_prefix_restart_interval: u16,
    /// Removes that family's maximum-prefix (`ClearMaximumPrefix`).
    #[arg(long = "clear-maximum-prefix", value_parser = parse_family)]
    pub clear_maximum_prefix: Vec<AddressFamily>,

    /// If set, sets `--peer-group`'s RFC 5082 `max-hops`
    /// (`BgpPeerGroupOp::SetMaxHops`).
    #[arg(long)]
    pub max_hops: Option<u8>,

    /// If set, administratively shuts `--peer-group` with this RFC 9003
    /// shutdown message (`BgpPeerGroupOp::SetShutdown`); an empty string
    /// shuts it without a message.
    #[arg(long)]
    pub shutdown_peer_group: Option<String>,

    /// If set, administratively shuts `--peer` alone, with this message
    /// (`BgpPeerOp::SetShutdown`); an empty string means no message.
    #[arg(long)]
    pub shutdown_peer: Option<String>,

    /// If set, clears `--peer-group`'s shutdown (`BgpPeerGroupOp::ClearShutdown`).
    #[arg(long)]
    pub unshutdown_peer_group: bool,

    /// If set, clears `--peer`'s own shutdown (`BgpPeerOp::ClearShutdown`).
    #[arg(long)]
    pub unshutdown_peer: bool,

    /// If set, configures `--bgp-instance`'s RFC 4456 cluster-id
    /// (`BgpInstanceOp::SetClusterId`) — only meaningful alongside
    /// `--route-reflector-client`.
    #[arg(long)]
    pub cluster_id: Option<Ipv4Addr>,

    /// BGP multipath: how many equal paths' next hops `--bgp-instance`
    /// installs (`BgpInstanceOp::SetMaximumPaths`).
    #[arg(long)]
    pub maximum_paths: Option<u8>,

    /// RFC 4724 graceful restart (on by default): turn it off on
    /// `--bgp-instance`. Any `--*graceful-restart`/`--gr-*` flag replaces
    /// the whole setting (`BgpInstanceOp::SetGracefulRestart`) with what the
    /// flags given say; with none, it's left alone.
    #[arg(long)]
    pub no_graceful_restart: bool,

    /// Graceful restart restart time, seconds (see `--no-graceful-restart`).
    #[arg(long)]
    pub gr_restart_time: Option<u16>,

    /// Graceful restart stale time, seconds (see `--no-graceful-restart`).
    #[arg(long)]
    pub gr_stale_time: Option<u16>,

    /// Graceful restart selection deferral time, seconds (see
    /// `--no-graceful-restart`).
    #[arg(long)]
    pub gr_selection_deferral_time: Option<u16>,

    /// Puts graceful restart back to its default: on, default timers.
    #[arg(long)]
    pub clear_graceful_restart: bool,

    /// RFC 5065: makes `--bgp-instance` a confederation member, with this
    /// identifier (`BgpInstanceOp::SetConfederationIdentifier`).
    #[arg(long)]
    pub confederation_id: Option<u32>,

    /// Another member AS of the confederation, repeatable
    /// (`BgpInstanceOp::AddConfederationPeer`).
    #[arg(long)]
    pub confederation_peer: Vec<u32>,

    /// An RFC 8210 RPKI cache for `--bgp-instance`, `<addr>:<port>`,
    /// repeatable; its preference is its position (`BgpInstanceOp::SetRpkiCache`).
    #[arg(long)]
    pub rpki_cache: Vec<std::net::SocketAddr>,

    /// An RFC 4271 §9.2.2.2 aggregate on `--bgp-instance`, repeatable
    /// (`BgpInstanceOp::SetAggregate`, with the two flags below).
    #[arg(long)]
    pub aggregate_address: Vec<IpNet>,
    #[arg(long)]
    pub aggregate_as_set: bool,
    #[arg(long)]
    pub aggregate_summary_only: bool,
    /// Removes an aggregate, repeatable (`BgpInstanceOp::RemoveAggregate`).
    #[arg(long)]
    pub remove_aggregate_address: Vec<IpNet>,

    /// Removes a static route from `--static-routing-instance`, repeatable
    /// (`StaticRouteOp::Delete`).
    #[arg(long)]
    pub remove_static_route: Vec<IpNet>,

    /// Runs BFD on every `--static-route` (single-hop, `bfd-profile fast`
    /// with `--bfd-interval-ms` intervals, multiplier 3): the routes stay
    /// out of the RIB until the session to `--static-gateway` is Up.
    #[arg(long)]
    pub bfd_static: bool,
    #[arg(long, default_value_t = 100)]
    pub bfd_interval_ms: u32,
    /// RFC 9468: `bfd-unsolicited fast` (same profile, `--bfd-interval-ms`
    /// intervals) on the subinterface `--interface`/`--subinterface-tag`.
    #[arg(long)]
    pub bfd_unsolicited: bool,
    /// Removes that subinterface's `bfd-unsolicited` again (the profile stays).
    #[arg(long)]
    pub no_bfd_unsolicited: bool,
    /// Sets `bfd fast` (same profile, `--bfd-interval-ms` intervals) on
    /// `--peer-group` of `--bgp-instance`.
    #[arg(long)]
    pub bfd_bgp: bool,
    /// Removes the peer-group's `bfd` again (the profile stays).
    #[arg(long)]
    pub no_bfd_bgp: bool,
    /// Sets `bfd fast` (same profile) on `--ospf-profile` of `--ospf-area`.
    #[arg(long)]
    pub ospf_bfd: bool,
    /// Removes that profile's `bfd` again.
    #[arg(long)]
    pub no_ospf_bfd: bool,
    /// `--ospf-bfd` for `--ospfv3-profile` of `--ospfv3-area`.
    #[arg(long)]
    pub ospfv3_bfd: bool,
    #[arg(long)]
    pub no_ospfv3_bfd: bool,
    /// Authentication on `bfd-profile fast`, `<method>:<key-id>:<secret>`
    /// (method: simple-password, keyed-md5, meticulous-md5, keyed-sha1,
    /// meticulous-sha1).
    #[arg(long, value_parser = parse_bfd_auth)]
    pub bfd_auth: Option<nos_proto::schema::BfdAuth>,
    /// Removes the profile's authentication again.
    #[arg(long)]
    pub no_bfd_auth: bool,
    /// `echo-mode` of `bfd-profile fast` (`affiliated`, `unaffiliated` or `disabled`); needs
    /// one of the `--bfd-*`/`--*-bfd` flags that create the profile.
    #[arg(long, value_parser = parse_echo_mode)]
    pub bfd_echo_mode: Option<nos_proto::schema::EchoMode>,
    /// `echo-interval` of `bfd-profile fast`, milliseconds.
    #[arg(long)]
    pub bfd_echo_interval: Option<u32>,
    /// `padded-pdu-size` of `bfd-profile fast` (RFC 9764), bytes.
    #[arg(long)]
    pub bfd_padded_pdu_size: Option<u16>,
    /// S-BFD (#294): profile `sb` (mode sbfd, `--bfd-interval-ms` intervals)
    /// guards these `--static-route`s; one per repetition.
    #[arg(long)]
    pub sbfd_static_route: Vec<IpNet>,
    /// `sbfd-remote-discriminator` of profile `sb`, an IPv4 address.
    #[arg(long)]
    pub sbfd_remote_discriminator: Option<std::net::Ipv4Addr>,
    /// The S-BFD reflector's discriminators, one per repetition (replaces
    /// the list).
    #[arg(long)]
    pub sbfd_reflector: Vec<std::net::Ipv4Addr>,
    /// Removes every S-BFD reflector discriminator.
    #[arg(long)]
    pub no_sbfd_reflector: bool,

    #[arg(long)]
    pub save: bool,

    /// If set (with `--policy-source-file`), creates/updates a
    /// `PolicyDefinition` named `<policy-name>` from that file's content —
    /// for verifying RPL import/export/redistribute policy end to end.
    /// Independent of `--import-policy`/`--export-policy`/
    /// `--redistribute-policy`, which point a peer-group or redistribute
    /// rule *at* a policy by name; this just defines one.
    #[arg(long)]
    pub policy_name: Option<String>,
    #[arg(long)]
    pub policy_source_file: Option<PathBuf>,

    /// Overrides `--peer-group`'s import policy (defaults to `accept-all` —
    /// see root CLAUDE.md's "Default-deny rollout impact": every peer-group
    /// this tool provisions needs an explicit policy in each direction, or
    /// the two-router scenarios below would establish sessions but exchange
    /// zero routes).
    #[arg(long, default_value = "accept-all")]
    pub import_policy: String,
    #[arg(long, default_value = "accept-all")]
    pub export_policy: String,

    /// If set, ensures a loopback interface for `--routing-table` (named
    /// `loopback-<routing-table>`, per `nos_proto::LOOPBACK_PREFIX` — the
    /// naming convention alone marks it as a loopback, no separate flag)
    /// and adds this address to it. Mutually exclusive with
    /// `--delete-loopback`.
    #[arg(long)]
    pub loopback_address: Option<IpNet>,

    /// If set, deletes `--routing-table`'s loopback interface
    /// (`loopback-<routing-table>`) instead of creating/updating one.
    /// Mutually exclusive with `--loopback-address`.
    #[arg(long)]
    pub delete_loopback: bool,

    /// If set, removes this address from `--routing-table`'s loopback
    /// interface before applying `--loopback-address` (if also set) —
    /// `InterfaceOp::AddAddress` only ever adds, and `crate::reconcile`'s
    /// `resolve_loopback_prefix` reads `addresses[0]`, so reassigning a
    /// loopback from one address to another (e.g. the `abr` scenario
    /// repurposing the `ospf-spf` scenario's own loopback into a second
    /// area) needs the old one actually removed, not just superseded.
    #[arg(long)]
    pub loopback_remove_address: Option<IpNet>,

    /// If set, attaches this OSPF profile name to `--routing-table`'s
    /// loopback interface (`InterfaceOp::SetOspfProfile`) — for verifying
    /// `nos-ospfd` originates a real stub-network Router-LSA link for it
    /// (see `docs/protocols/ospf-internals.md`'s "SPF and route installation"). Mutually exclusive with
    /// `--clear-ospf-loopback-profile`.
    #[arg(long)]
    pub ospf_loopback_profile: Option<String>,

    /// If set, clears the loopback interface's OSPF profile attachment
    /// instead of setting one. Mutually exclusive with
    /// `--ospf-loopback-profile`.
    #[arg(long)]
    pub clear_ospf_loopback_profile: bool,

    /// Which broadcast domain `--broadcast-domain-svi-address`/
    /// `--delete-broadcast-domain-svi` target.
    #[arg(long, default_value = "bd-svi")]
    pub broadcast_domain: String,

    /// If set, ensures `--broadcast-domain` and adds this address to it,
    /// associating it with `--routing-table` (its VRF) — making the
    /// domain's own bridge device an SVI (switch virtual interface).
    /// Mutually exclusive with `--delete-broadcast-domain-svi`.
    #[arg(long)]
    pub broadcast_domain_svi_address: Option<IpNet>,

    /// Puts `--broadcast-domain-svi-address`'s SVI in this routing table
    /// instead of `--routing-table` (an EVPN IP-VRF from `--l3vni-table`,
    /// for symmetric IRB).
    #[arg(long)]
    pub broadcast_domain_svi_table: Option<String>,

    /// If set, deletes `--broadcast-domain` outright instead of
    /// creating/updating its SVI. Mutually exclusive with
    /// `--broadcast-domain-svi-address`.
    #[arg(long)]
    pub delete_broadcast_domain_svi: bool,

    /// EVPN on `--broadcast-domain` (ensured if missing): its VNI. The rest
    /// of the `--evpn-*` flags require it; see `BroadcastDomain::vni`.
    #[arg(long)]
    pub evpn_vni: Option<u32>,

    /// EVPN Route Distinguisher of `--broadcast-domain` (`asn:nn`).
    #[arg(long)]
    pub evpn_rd: Option<String>,

    /// Route Target added to `--broadcast-domain`'s import list (repeatable).
    #[arg(long)]
    pub evpn_rt_import: Vec<String>,

    /// Route Target added to `--broadcast-domain`'s export list (repeatable).
    #[arg(long)]
    pub evpn_rt_export: Vec<String>,

    /// `vtep-source interface <name>` on `--broadcast-domain`. Mutually
    /// exclusive with `--evpn-vtep-source-loopback`.
    #[arg(long)]
    pub evpn_vtep_source_interface: Option<String>,

    /// Label of the address to use, paired with either vtep-source flag.
    #[arg(long)]
    pub evpn_vtep_source_label: Option<String>,

    /// `vtep-source loopback` on `--broadcast-domain`.
    #[arg(long)]
    pub evpn_vtep_source_loopback: bool,

    /// `redistribute from mac to bgp <instance>` on `--broadcast-domain`.
    #[arg(long)]
    pub evpn_redistribute_bgp: Option<String>,

    /// `redistribute from arp to bgp <instance>` on `--broadcast-domain`
    /// (must be the same instance as `--evpn-redistribute-bgp`).
    #[arg(long)]
    pub evpn_redistribute_arp_bgp: Option<String>,

    /// `redistribute from connected to bgp <instance>` on `--broadcast-domain`
    /// (must be the same instance as `--evpn-redistribute-bgp`).
    #[arg(long)]
    pub evpn_redistribute_connected_bgp: Option<String>,

    /// `neigh-suppress` (ARP/ND suppression) on `--broadcast-domain`: `true`
    /// sets it, `false` clears it.
    #[arg(long)]
    pub evpn_neigh_suppress: Option<bool>,

    /// EVPN IP-VRF: the routing table (ensured) `--l3vni*` apply to, with
    /// `--bgp-instance` as its underlay instance.
    #[arg(long, default_value = "tenant")]
    pub l3vni_table: String,

    /// The L3 VNI of `--l3vni-table` (`RoutingTableOp::SetEvpn`); requires
    /// `--l3vni-rd`, `--l3vni-rt` and `--l3vni-vtep-source-interface`.
    #[arg(long)]
    pub l3vni: Option<u32>,

    #[arg(long)]
    pub l3vni_rd: Option<String>,

    /// Route Target both imported and exported by `--l3vni-table`.
    #[arg(long)]
    pub l3vni_rt: Option<String>,

    #[arg(long)]
    pub l3vni_vtep_source_interface: Option<String>,

    /// Puts this interface's untagged subinterface, with `--l3vni-address`,
    /// in `--l3vni-table` (the tenant's attached subnet).
    #[arg(long)]
    pub l3vni_interface: Option<String>,

    #[arg(long)]
    pub l3vni_address: Option<IpNet>,

    /// Clears `--l3vni-table`'s EVPN config (`RoutingTableOp::ClearEvpn`).
    #[arg(long)]
    pub l3vni_clear: bool,

    /// If set, undoes the EVPN config of `--broadcast-domain`: clears
    /// redistribute, vtep-source, rd and vni (in that order, so validation
    /// passes) and removes any route target named by `--evpn-rt-import`/
    /// `--evpn-rt-export`. Mutually exclusive with the setting flags.
    #[arg(long)]
    pub evpn_clear: bool,

    /// If set, points `--peer-group`'s source-address at this named
    /// interface (`BgpPeerGroupOp::SetSourceAddress` with
    /// `SourceAddress::Interface`). Mutually exclusive with
    /// `--source-address-loopback`/`--clear-source-address`.
    #[arg(long)]
    pub source_address_interface: Option<String>,

    /// If set, points `--peer-group`'s source-address at this instance's own
    /// loopback interface (`SourceAddress::Loopback`) — no interface name
    /// needed, derived from `--routing-table` by nos-bgpd itself at
    /// runtime. Mutually exclusive with
    /// `--source-address-interface`/`--clear-source-address`.
    #[arg(long)]
    pub source_address_loopback: bool,

    /// Paired with `--source-address-interface`/`--source-address-loopback`
    /// to disambiguate which of that interface's addresses to use.
    #[arg(long)]
    pub source_address_label: Option<String>,

    /// If set, clears `--peer-group`'s source-address
    /// (`BgpPeerGroupOp::ClearSourceAddress`). Mutually exclusive with
    /// `--source-address-interface`/`--source-address-loopback`.
    #[arg(long)]
    pub clear_source_address: bool,

    /// If set, creates this switching profile (if missing), populates it
    /// from `--switching-profile-member`, and assigns it to `--interface`
    /// (`InterfaceOp::SetSwitchingProfile`). Mutually exclusive with
    /// `--delete-switching-profile`.
    #[arg(long)]
    pub switching_profile: Option<String>,

    /// One `DOMAIN:TAG` pair per repetition (`TAG` is `untagged` or a
    /// dot1q id `1..=4094`), added as a member of `--switching-profile`
    /// (creating the named broadcast domain if missing). Only meaningful
    /// with `--switching-profile` also set.
    #[arg(long = "switching-profile-member")]
    pub switching_profile_members: Vec<String>,

    /// If set, clears `--interface`'s switching-profile assignment
    /// instead of setting one. Mutually exclusive with
    /// `--switching-profile`.
    #[arg(long)]
    pub delete_switching_profile: bool,

    /// If set, creates this port aggregate (a Linux bond) if missing, and
    /// enslaves every `--enslave-interface-into-port-aggregate` member into
    /// it (`PortAggregateOp::Ensure`, `InterfaceOp::SetPortAggregate`).
    #[arg(long)]
    pub port_aggregate: Option<String>,

    /// The aggregate's mode: `xor` (static, every member enslaved
    /// unconditionally) or `lacp` (real IEEE 802.1AX negotiation via
    /// `nos-lacpd` — see `lacp/CLAUDE.md`). Only meaningful with
    /// `--port-aggregate` also set.
    #[arg(long, value_enum, default_value_t = PortAggregateModeArg::Xor)]
    pub port_aggregate_mode: PortAggregateModeArg,

    /// If set (requires `--port-aggregate`), sets the aggregate's LACP
    /// timeout rate (`PortAggregateOp::SetLacpRate`).
    #[arg(long, value_enum)]
    pub lacp_rate: Option<LacpRateArg>,

    /// If set (requires `--port-aggregate`), sets the aggregate's own mtu
    /// (`PortAggregateOp::SetMtu`).
    #[arg(long)]
    pub port_aggregate_mtu: Option<u32>,

    /// If set (requires `--port-aggregate`), adds this address to the
    /// aggregate's tag-0 subinterface in `--routing-table`
    /// (`PortAggregateSubinterfaceOp::AddAddress` + `SetRoutingTable`).
    #[arg(long)]
    pub port_aggregate_address: Option<IpNet>,

    /// If set (requires `--port-aggregate`), sets the aggregate's EVPN
    /// Ethernet Segment Identifier (`PortAggregateOp::SetEsi`).
    #[arg(long)]
    pub port_aggregate_esi: Option<String>,

    /// If set (requires `--port-aggregate`), removes the aggregate's ESI
    /// (`PortAggregateOp::ClearEsi`).
    #[arg(long)]
    pub delete_port_aggregate_esi: bool,

    /// If set (requires `--port-aggregate`), sets how the PEs sharing the
    /// aggregate's Ethernet Segment divide the traffic
    /// (`PortAggregateOp::SetRedundancyMode`); needs an ESI at commit time.
    #[arg(long, value_enum)]
    pub port_aggregate_redundancy_mode: Option<EsRedundancyArg>,

    /// The `spanning-tree mode`. Unset means `disabled`, not the schema's
    /// `rstp` default: since #326 an STP-on bridge port stays blocked until
    /// `nos-stpd` (#327) opens it, which would black-hole every phase that
    /// forwards through a bridge.
    #[arg(long, value_enum)]
    pub stp_mode: Option<StpModeArg>,

    /// `spanning-tree priority` (a multiple of 4096); unset keeps the default.
    #[arg(long)]
    pub stp_priority: Option<u16>,

    /// `spanning-tree force-version` (`stp` = 802.1D only); unset leaves it.
    #[arg(long, value_enum)]
    pub stp_force_version: Option<StpForceVersionArg>,

    /// Creates the `stp-port-profile` [`STP_PROT_PROFILE`] and attaches it to
    /// this interface (#320); the fields come from `--stp-profile-field`.
    #[arg(long)]
    pub stp_profile_interface: Option<String>,

    /// `field=json` edit of [`STP_PROT_PROFILE`] (`bpdu-guard=true`,
    /// `edge-port="Admin"`); an empty value (`bpdu-guard-recovery=`) deletes
    /// the field. Repeatable.
    #[arg(long)]
    pub stp_profile_field: Vec<String>,

    /// Detach [`STP_PROT_PROFILE`] from `--stp-profile-interface`.
    #[arg(long)]
    pub stp_profile_detach: bool,

    /// `spanning-tree region` as `NAME:REVISION` (MSTP, #321).
    #[arg(long)]
    pub stp_region: Option<String>,

    /// `spanning-tree mst-instance` as `ID:PRIORITY`. Repeatable.
    #[arg(long)]
    pub stp_mst_instance: Vec<String>,

    /// `broadcast-domain <BD> stp-instance <ID>` as `BD:ID`. Repeatable.
    #[arg(long)]
    pub stp_domain_instance: Vec<String>,

    /// `broadcast-domain <BD> stp-priority <PRIO>` as `BD:PRIO` (Rapid-PVST+,
    /// #322). Repeatable.
    #[arg(long)]
    pub stp_domain_priority: Vec<String>,

    /// `switching-profile <SP> member <BD> stp-cost <COST>` as `SP:BD:COST`
    /// (Rapid-PVST+, #322). Repeatable.
    #[arg(long)]
    pub stp_member_cost: Vec<String>,

    /// `mst-instance <ID> cost <COST>` of [`STP_PROT_PROFILE`] as `ID:COST`
    /// (needs `--stp-profile-interface`). Repeatable.
    #[arg(long)]
    pub stp_profile_mst_cost: Vec<String>,

    /// If set (requires `--port-aggregate`), sets the aggregate's Ethernet
    /// Segment DF election algorithm (`PortAggregateOp::SetDfAlgorithm`);
    /// needs an ESI at commit time. `modulo` resets it.
    #[arg(long, value_enum)]
    pub port_aggregate_df_algorithm: Option<DfAlgorithmArg>,

    /// If set (requires `--port-aggregate`), overrides the aggregate's LACP
    /// Actor System ID (`PortAggregateOp::SetLacpSystemId`).
    #[arg(long)]
    pub lacp_system_id: Option<String>,

    /// If set (requires `--port-aggregate`), sets the aggregate's LACP Actor
    /// System Priority (`PortAggregateOp::SetLacpSystemPriority`).
    #[arg(long)]
    pub lacp_system_priority: Option<u16>,

    /// If set (requires `--port-aggregate`), sets the aggregate's LACP
    /// `min-links` (`PortAggregateOp::SetMinLinks`).
    #[arg(long)]
    pub min_links: Option<u16>,

    /// If set (requires `--port-aggregate`), runs micro-BFD with this
    /// `bfd-profile` on the aggregate's members (`PortAggregateOp::SetBfd`);
    /// needs `--port-aggregate-bfd-peer` and a bond address at commit time.
    /// `fast` also creates that profile (`--bfd-interval-ms` intervals).
    #[arg(long)]
    pub port_aggregate_bfd: Option<String>,

    /// If set (requires `--port-aggregate`), the peer address of the
    /// aggregate's micro-BFD sessions (`PortAggregateOp::SetBfdPeer`).
    #[arg(long)]
    pub port_aggregate_bfd_peer: Option<std::net::IpAddr>,

    /// If set (requires `--port-aggregate`), sets the LACP Actor Port Priority
    /// of every `--enslave-interface-into-port-aggregate` member
    /// (`InterfaceOp::SetLacpPortPriority`).
    #[arg(long)]
    pub lacp_port_priority: Option<u16>,

    /// If set (requires `--port-aggregate`), sets the LACP mode of every
    /// `--enslave-interface-into-port-aggregate` member
    /// (`InterfaceOp::SetLacpMode`).
    #[arg(long, value_enum)]
    pub lacp_mode: Option<LacpModeArg>,

    /// If set (requires `--port-aggregate`), makes the aggregate an untagged
    /// member of this broadcast domain: ensures the domain, a switching
    /// profile `<aggregate>-sp` holding it, and assigns that profile to the
    /// aggregate.
    #[arg(long)]
    pub port_aggregate_untagged_domain: Option<String>,

    /// One interface name per repetition, ensured and enslaved into
    /// `--port-aggregate` (`InterfaceOp::Ensure` + `InterfaceOp::SetPortAggregate`).
    /// Only meaningful with `--port-aggregate` also set.
    #[arg(long = "enslave-interface-into-port-aggregate")]
    pub port_aggregate_members: Vec<String>,

    /// One interface name per repetition: clears that interface's
    /// `port_aggregate` reference (`InterfaceOp::ClearPortAggregate`),
    /// withdrawing just that member while leaving the aggregate and its other
    /// members in place. Independent of `--port-aggregate`.
    #[arg(long = "clear-port-aggregate-member")]
    pub clear_port_aggregate_members: Vec<String>,

    /// One `<name>=<clear password>` per repetition: creates the user or sets
    /// its password (`UserOp::SetPassword`). `nos-configd` hashes it on load /
    /// on apply. The first `=` separates the two, so a password may contain `=`.
    #[arg(long = "user", value_parser = parse_user)]
    pub users: Vec<(String, String)>,

    /// If set, sets the top-level hostname (`ConfigOp::SetHostname`) — what
    /// `nos-lldpd` advertises as its System Name.
    #[arg(long)]
    pub hostname: Option<String>,

    /// One interface name per repetition: ensured, then `lldp transmit`
    /// enabled (`InterfaceOp::SetLldpTransmit`) — for verifying `nos-lldpd`
    /// really advertises on that link.
    #[arg(long = "lldp-transmit-interface")]
    pub lldp_transmit_interfaces: Vec<String>,

    /// Same as `--lldp-transmit-interface`, for `lldp receive`.
    #[arg(long = "lldp-receive-interface")]
    pub lldp_receive_interfaces: Vec<String>,

    /// One interface name per repetition: `lldp transmit` disabled again
    /// (`SetLldpTransmit { enabled: false }`), leaving `lldp receive` alone.
    #[arg(long = "no-lldp-transmit-interface")]
    pub no_lldp_transmit_interfaces: Vec<String>,

    /// Same as `--no-lldp-transmit-interface`, for `lldp receive`.
    #[arg(long = "no-lldp-receive-interface")]
    pub no_lldp_receive_interfaces: Vec<String>,

    /// If set, the system-wide LLDP `tx-interval` in seconds
    /// (`LldpOp::SetTxInterval`).
    #[arg(long)]
    pub lldp_tx_interval: Option<u16>,

    /// If set, the system-wide LLDP `tx-hold` (`LldpOp::SetTxHold`).
    #[arg(long)]
    pub lldp_tx_hold: Option<u8>,

    /// One LLDP management address per repetition, each advertised in its
    /// own Management Address TLV (`LldpOp::AddManagementAddress`).
    #[arg(long = "lldp-management-address")]
    pub lldp_management_addresses: Vec<IpAddr>,

    /// One LLDP management address per repetition to stop advertising
    /// (`LldpOp::RemoveManagementAddress`).
    #[arg(long = "no-lldp-management-address")]
    pub no_lldp_management_addresses: Vec<IpAddr>,

    /// Ensures this remote syslog collector (`LoggingOp::EnsureSyslog`); every
    /// other `--syslog-*` flag of the invocation applies to it. One per run.
    #[arg(long)]
    pub syslog_server: Option<String>,

    /// The collector's address (`LoggingOp::SetSyslogAddress`).
    #[arg(long)]
    pub syslog_address: Option<IpAddr>,

    /// The collector's port (`LoggingOp::SetSyslogPort`).
    #[arg(long)]
    pub syslog_port: Option<u16>,

    /// `udp`, `tcp` or `tls` (`LoggingOp::SetSyslogTransport`).
    #[arg(long)]
    pub syslog_transport: Option<String>,

    /// The routing table whose VRF the socket is scoped into.
    #[arg(long)]
    pub syslog_routing_table: Option<String>,

    /// Minimum severity: `error`, `warn`, `info`, `debug` or `trace`.
    #[arg(long)]
    pub syslog_level: Option<String>,

    /// `local0` to `local7`.
    #[arg(long)]
    pub syslog_facility: Option<String>,

    /// A PEM CA certificate file (read here, sent as text) the TLS collector's
    /// certificate must chain to (`LoggingOp::SetSyslogTlsTrustAnchor`).
    #[arg(long)]
    pub syslog_trust_anchor_file: Option<PathBuf>,

    /// `SHA-256:AB:CD:...` of the TLS collector's certificate
    /// (`LoggingOp::SetSyslogTlsFingerprint`).
    #[arg(long)]
    pub syslog_fingerprint: Option<String>,

    /// The DNS name the TLS collector's certificate must carry.
    #[arg(long)]
    pub syslog_server_name: Option<String>,

    /// Allows TLS 1.2 with classical key exchange (`SetSyslogTlsAllowTls12`).
    #[arg(long)]
    pub syslog_allow_tls12: bool,

    /// Turns `--syslog-allow-tls12` off again.
    #[arg(long)]
    pub no_syslog_allow_tls12: bool,

    /// One collector per repetition to remove (`LoggingOp::RemoveSyslog`).
    #[arg(long = "no-syslog-server")]
    pub no_syslog_servers: Vec<String>,

    /// One `<interface>=<group>` per repetition (group is `nearest-bridge`,
    /// `non-tpmr` or `customer-bridge`): sets that interface's LLDP
    /// destination group (`InterfaceOp::SetLldpDestination`).
    #[arg(long = "lldp-destination-interface")]
    pub lldp_destination_interfaces: Vec<String>,

    /// If set (requires `--port-aggregate`, naming which one), deletes the
    /// port aggregate outright instead of ensuring/enslaving into it
    /// (`PortAggregateOp::Delete`) — for verifying the real kernel bond
    /// device (and its members' enslavement) is torn down.
    #[arg(long)]
    pub delete_port_aggregate: bool,

    /// If set, ensures this OSPF instance, sets its router-id
    /// (`--ospf-router-id`, required alongside this), and associates it
    /// with `--routing-table` (`RoutingTableOp::SetOspfInstance`) — for
    /// verifying `nos-watchdogd` dynamically spawns `nos-ospfd` for it.
    #[arg(long)]
    pub ospf_instance: Option<String>,
    #[arg(long)]
    pub ospf_router_id: Option<Ipv4Addr>,
    /// RFC 3623 graceful-restart grace period (seconds) for that instance
    /// (requires `--ospf-instance`); `0` clears it.
    #[arg(long)]
    pub ospf_graceful_restart_grace_period: Option<u16>,
    /// RFC 6860 prefix suppression for that instance (requires
    /// `--ospf-instance`): `true` turns it on, `false` off.
    #[arg(long)]
    pub ospf_prefix_suppression: Option<bool>,
    /// RFC 6987 `max-metric router-lsa on-startup <secs>` for that instance
    /// (requires `--ospf-instance`); `0` clears it.
    #[arg(long)]
    pub ospf_max_metric_on_startup: Option<u32>,
    /// RFC 6987 `max-metric router-lsa on-shutdown <secs>` for that instance
    /// (requires `--ospf-instance`); `0` clears it.
    #[arg(long)]
    pub ospf_max_metric_on_shutdown: Option<u8>,
    /// RFC 6987 `max-metric router-lsa administrative` for that instance
    /// (requires `--ospf-instance`): `true` turns it on, `false` off.
    #[arg(long)]
    pub ospf_max_metric_administrative: Option<bool>,
    /// RFC 8770 `host-router` for that instance (requires `--ospf-instance`):
    /// `true` turns it on, `false` off.
    #[arg(long)]
    pub ospf_host_router: Option<bool>,
    /// RFC 7490 `remote-lfa` for that instance (requires `--ospf-instance`):
    /// `true` turns it on, `false` off.
    #[arg(long)]
    pub ospf_remote_lfa: Option<bool>,

    /// If set (requires `--ospf-instance`), ensures this OSPF area under it
    /// (`OspfAreaOp::Ensure`).
    #[arg(long)]
    pub ospf_area: Option<Ipv4Addr>,
    /// `normal`, `stub`, `totally-stubby`, `nssa` or `nssa-no-summary` for
    /// `--ospf-area`
    /// (`OspfAreaOp::SetAreaType`).
    #[arg(long, requires = "ospf_area", value_parser = parse_ospf_area_type)]
    pub ospf_area_type: Option<OspfAreaType>,
    /// The default summary's cost into a stub `--ospf-area`
    /// (`OspfAreaOp::SetStubDefaultCost`); `0` clears it.
    #[arg(long, requires = "ospf_area")]
    pub ospf_stub_default_cost: Option<u16>,
    /// `<cidr>[:not-advertise]`: an RFC 2328 §3.5 range on `--ospf-area`
    /// (`OspfAreaOp::SetRange`, upserted).
    #[arg(long, requires = "ospf_area")]
    pub ospf_area_range: Option<String>,
    /// Removes that range from `--ospf-area` (`OspfAreaOp::RemoveRange`).
    #[arg(long, requires = "ospf_area")]
    pub ospf_clear_area_range: Option<Ipv4Net>,
    /// `<transit-area>:<router-id>`, with `--ospf-instance`: an RFC 2328 §15
    /// virtual link through that area (`OspfAreaOp::SetVirtualLink`, upserted).
    #[arg(long, requires = "ospf_instance")]
    pub ospf_virtual_link: Option<String>,
    /// `<transit-area>:<router-id>`, with `--ospf-instance`: removes that
    /// virtual link (`OspfAreaOp::RemoveVirtualLink`).
    #[arg(long, requires = "ospf_instance")]
    pub ospf_clear_virtual_link: Option<String>,
    /// If set (requires `--ospf-area`), ensures this OSPF profile under it
    /// (`OspfProfileOp::Ensure`).
    #[arg(long)]
    pub ospf_profile: Option<String>,
    /// If set, attaches this profile name to `--interface`'s
    /// `--subinterface-tag` subinterface (`SubinterfaceOp::SetOspfProfile`)
    /// — for verifying `nos-ospfd` logs the attachment.
    #[arg(long)]
    pub ospf_interface_profile: Option<String>,
    /// If set, attaches this profile name to `--broadcast-domain`'s own SVI
    /// (`BroadcastDomainOp::SetOspfProfile`) — for verifying `nos-ospfd`'s
    /// broadcast-network-type Hello/DR-BDR-election path. Combine with
    /// `--broadcast-domain-svi-address`/`--switching-profile`/
    /// `--switching-profile-member` to build the whole attach point.
    #[arg(long)]
    pub ospf_broadcast_domain_profile: Option<String>,

    /// If set (requires `--ospf-profile`), configures an RFC 2328 Appendix
    /// D.2 simple password on it (`OspfProfileOp::SetSimpleAuth`).
    /// Mutually exclusive with `--ospf-crypto-key` (RFC 2328's Simple and
    /// Cryptographic auth types are themselves mutually exclusive).
    #[arg(long)]
    pub ospf_simple_password: Option<String>,

    /// If set (requires `--ospf-profile`), configures a single RFC 2328
    /// Appendix D.3 / RFC 5709 cryptographic auth key on it
    /// (`OspfProfileOp::SetCryptoKey`, marked current) — `<key-id>:
    /// <algorithm>:<key>`, algorithm one of `md5`/`hmac-sha1`/
    /// `hmac-sha256`/`hmac-sha384`/`hmac-sha512` — for verifying session
    /// authentication end to end (matching keys on both routers establish;
    /// a mismatched one on either side does not).
    #[arg(long)]
    pub ospf_crypto_key: Option<String>,

    /// If set (requires `--ospf-profile`), overrides the MTU OSPF believes
    /// this profile's links have (`OspfProfileOp::SetMtu`) — for verifying
    /// real-MTU-driven DBD pagination independent of the interface's own
    /// real kernel MTU.
    #[arg(long)]
    pub ospf_profile_mtu: Option<u16>,

    /// If set (requires `--ospf-profile`), toggles `mtu-ignore` on it
    /// (`OspfProfileOp::SetMtuIgnore`), the RFC 2328 §10.6 DBD MTU check.
    #[arg(long)]
    pub ospf_mtu_ignore: Option<bool>,

    /// If set (requires `--ospf-profile`), overrides this profile's
    /// hello-interval (`OspfProfileOp::SetHelloInterval`) — for verifying
    /// RFC 2328 §10.5's packet-validity check drops a Hello whose
    /// hello-interval doesn't match the receiving interface's own.
    #[arg(long)]
    pub ospf_profile_hello_interval: Option<u16>,

    /// If set (requires `--ospf-profile`), forces this profile's network type:
    /// `point-to-point`, `broadcast`, `point-to-multipoint`, or `clear` to go
    /// back to the per-attach-point default.
    #[arg(long)]
    pub ospf_profile_network_type: Option<String>,

    /// If set (requires `--ospf-profile`), enables/disables RFC 7474
    /// extended cryptographic sequence numbers on it
    /// (`OspfProfileOp::SetExtendedSequenceNumbers`) — needs a matching
    /// hmac-sha `--ospf-crypto-key` to commit.
    #[arg(long)]
    pub ospf_extended_seq: Option<bool>,

    /// If set, adds this IPv6 address to `--interface`'s
    /// `--subinterface-tag` subinterface alongside `--address` — `OSPFv3`
    /// (RFC 5340) needs a real IPv6 prefix on the link, distinct from
    /// `--address`'s own (typically IPv4, for BGP) subnet; an IPv6 EVPN
    /// underlay selects it by `--address6-label`.
    #[arg(long)]
    pub address6: Option<IpNet>,
    /// The label of `--address6` (requires it).
    #[arg(long, requires = "address6")]
    pub address6_label: Option<String>,

    /// Same shape as `--ospf-instance`/`--ospf-router-id`, joining `OSPFv3`
    /// instead (`RoutingTableOp::SetOspfv3Instance`).
    #[arg(long)]
    pub ospfv3_instance: Option<String>,
    #[arg(long)]
    pub ospfv3_router_id: Option<Ipv4Addr>,
    /// RFC 8362 Full mode for that instance (requires `--ospfv3-instance`).
    #[arg(long)]
    pub ospfv3_extended_lsa: bool,
    /// RFC 5187 graceful-restart grace period (seconds) for that instance
    /// (requires `--ospfv3-instance`).
    #[arg(long)]
    pub ospfv3_graceful_restart_grace_period: Option<u16>,

    /// Same shape as `--ospf-area` (requires `--ospfv3-instance`).
    #[arg(long)]
    pub ospfv3_area: Option<Ipv4Addr>,
    /// Same shape as `--ospf-profile` (requires `--ospfv3-area`).
    #[arg(long)]
    pub ospfv3_profile: Option<String>,
    /// If set (requires `--ospfv3-profile`), overrides the MTU `OSPFv3`
    /// believes the profile's links have (`Ospfv3ProfileOp::SetMtu`).
    #[arg(long)]
    pub ospfv3_profile_mtu: Option<u16>,
    /// If set (requires `--ospfv3-profile`), toggles `mtu-ignore` on it
    /// (`Ospfv3ProfileOp::SetMtuIgnore`).
    #[arg(long)]
    pub ospfv3_mtu_ignore: Option<bool>,
    /// If set (requires `--ospfv3-profile`), the profile's RFC 5340 Instance
    /// ID (`Ospfv3ProfileOp::SetInstanceId`); `0` clears it.
    #[arg(long)]
    pub ospfv3_instance_id: Option<u8>,
    /// If set (requires `--ospfv3-profile`), configures a single RFC 7166
    /// authentication-trailer key on it (`Ospfv3ProfileOp::SetCryptoKey`,
    /// marked current) — `<key-id>:<algorithm>:<key>`, key-id 0-65535 (the
    /// 16-bit Security Association ID), algorithm one of `hmac-sha1`/
    /// `hmac-sha256`/`hmac-sha384`/`hmac-sha512` (no md5 in RFC 7166).
    #[arg(long)]
    pub ospfv3_crypto_key: Option<String>,
    /// Same shape as `--ospf-interface-profile`, joining `OSPFv3` instead
    /// (`SubinterfaceOp::SetOspfv3Profile`).
    #[arg(long)]
    pub ospfv3_interface_profile: Option<String>,
    /// Same shape as `--ospf-broadcast-domain-profile`, joining `OSPFv3`
    /// instead (`BroadcastDomainOp::SetOspfv3Profile`).
    #[arg(long)]
    pub ospfv3_broadcast_domain_profile: Option<String>,
    /// Detaches `OSPFv3` from `--broadcast-domain`
    /// (`BroadcastDomainOp::ClearOspfv3Profile`).
    #[arg(long, conflicts_with = "ospfv3_broadcast_domain_profile")]
    pub clear_ospfv3_broadcast_domain_profile: bool,

    /// If set, adds this IPv6 address to `--routing-table`'s loopback
    /// interface (`loopback-<routing-table>`) alongside `--loopback-address`
    /// — `OSPFv3` only ever advertises IPv6 prefixes.
    #[arg(long)]
    pub ospfv3_loopback_address: Option<IpNet>,

    /// Same shape as `--ospf-loopback-profile`, joining `OSPFv3` instead.
    /// Mutually exclusive with `--clear-ospfv3-loopback-profile`.
    #[arg(long)]
    pub ospfv3_loopback_profile: Option<String>,

    /// Same shape as `--clear-ospf-loopback-profile`, joining `OSPFv3`
    /// instead. Mutually exclusive with `--ospfv3-loopback-profile`.
    #[arg(long)]
    pub clear_ospfv3_loopback_profile: bool,

    /// If set, adds this IPv6 address to `--broadcast-domain`'s SVI
    /// alongside `--broadcast-domain-svi-address`.
    #[arg(long)]
    pub ospfv3_broadcast_domain_svi_address: Option<IpNet>,
}

impl Args {
    /// Whether any flag needs `bfd-profile fast` (with `--bfd-interval-ms`).
    fn wants_bfd_profile(&self) -> bool {
        self.bfd_static
            || self.bfd_unsolicited
            || self.bfd_bgp
            || self.ospf_bfd
            || self.ospfv3_bfd
            || self.port_aggregate_bfd.as_deref() == Some(BFD_PROFILE)
    }
}

/// Builds the ordered `ConfigOp` list for one provisioning invocation — pure,
/// so a caller can apply it over IPC (this crate's bin) or locally onto a
/// `Config` (`nos-e2e`, which then PUTs the result over the REST API).
fn parse_ospf_area_type(s: &str) -> Result<OspfAreaType, String> {
    match s {
        "normal" => Ok(OspfAreaType::Normal),
        "stub" => Ok(OspfAreaType::Stub),
        "totally-stubby" => Ok(OspfAreaType::TotallyStubby),
        "nssa" => Ok(OspfAreaType::Nssa),
        "nssa-no-summary" => Ok(OspfAreaType::NssaNoSummary),
        _ => Err(format!(
            "unknown area type {s:?} (normal, stub, totally-stubby, nssa, nssa-no-summary)"
        )),
    }
}

fn parse_family(s: &str) -> Result<AddressFamily, String> {
    AddressFamily::ALL
        .into_iter()
        .find(|af| af.as_str() == s)
        .ok_or_else(|| format!("unknown address family '{s}' (ipv4, ipv6, l2vpn-evpn)"))
}

fn parse_add_path(s: &str) -> Result<nos_proto::BgpAddPath, String> {
    use nos_proto::BgpAddPath::{Both, Receive, Send};
    [Receive, Send, Both]
        .into_iter()
        .find(|m| m.as_str() == s)
        .ok_or_else(|| format!("unknown add-path mode '{s}' (receive, send, both)"))
}

fn parse_role(s: &str) -> Result<nos_proto::BgpRole, String> {
    use nos_proto::BgpRole::{Customer, Peer, Provider, RouteServer, RouteServerClient};
    [Provider, RouteServer, RouteServerClient, Customer, Peer]
        .into_iter()
        .find(|r| r.as_str() == s)
        .ok_or_else(|| {
            format!(
                "unknown role '{s}' (provider, route-server, route-server-client, customer, peer)"
            )
        })
}

fn parse_maximum_prefix(s: &str) -> Result<(AddressFamily, u32), String> {
    let (af, n) = s
        .split_once('=')
        .ok_or_else(|| "expected <family>=<limit>".to_string())?;
    Ok((parse_family(af)?, n.parse().map_err(|e| format!("{e}"))?))
}

fn parse_user(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(n, p)| (n.to_string(), p.to_string()))
        .ok_or_else(|| "expected <name>=<password>".to_string())
}

/// The `--evpn-*` flags -> `BroadcastDomainOp`s on `--broadcast-domain`.
fn evpn_ops(args: &Args) -> anyhow::Result<Vec<ConfigOp>> {
    let name = || args.broadcast_domain.clone();
    let op = |o| ConfigOp::BroadcastDomain(o);
    let setting = args.evpn_vni.is_some()
        || args.evpn_rd.is_some()
        || args.evpn_vtep_source_interface.is_some()
        || args.evpn_vtep_source_loopback
        || args.evpn_redistribute_bgp.is_some()
        || args.evpn_redistribute_arp_bgp.is_some()
        || args.evpn_redistribute_connected_bgp.is_some()
        || args.evpn_neigh_suppress.is_some();
    if args.evpn_clear && setting {
        bail!("--evpn-clear is mutually exclusive with the other --evpn-* setting flags");
    }
    if args.evpn_vtep_source_interface.is_some() && args.evpn_vtep_source_loopback {
        bail!(
            "--evpn-vtep-source-interface and --evpn-vtep-source-loopback are mutually exclusive"
        );
    }
    let mut ops = Vec::new();
    if args.evpn_clear {
        for (import, list) in [(true, &args.evpn_rt_import), (false, &args.evpn_rt_export)] {
            for rt in list {
                ops.push(op(BroadcastDomainOp::RemoveRouteTarget {
                    name: name(),
                    import,
                    route_target: rt.clone(),
                }));
            }
        }
        ops.push(op(BroadcastDomainOp::SetNeighSuppress {
            name: name(),
            enabled: false,
        }));
        ops.push(op(BroadcastDomainOp::ClearArpRedistribute { name: name() }));
        ops.push(op(BroadcastDomainOp::ClearConnectedRedistribute {
            name: name(),
        }));
        ops.push(op(BroadcastDomainOp::ClearMacRedistribute { name: name() }));
        ops.push(op(BroadcastDomainOp::ClearVtepSource { name: name() }));
        ops.push(op(BroadcastDomainOp::ClearRd { name: name() }));
        ops.push(op(BroadcastDomainOp::ClearVni { name: name() }));
        return Ok(ops);
    }
    if !setting && args.evpn_rt_import.is_empty() && args.evpn_rt_export.is_empty() {
        return Ok(ops);
    }
    ops.push(op(BroadcastDomainOp::Ensure { name: name() }));
    if let Some(vni) = args.evpn_vni {
        ops.push(op(BroadcastDomainOp::SetVni { name: name(), vni }));
    }
    if let Some(rd) = &args.evpn_rd {
        ops.push(op(BroadcastDomainOp::SetRd {
            name: name(),
            rd: rd.clone(),
        }));
    }
    for (import, list) in [(true, &args.evpn_rt_import), (false, &args.evpn_rt_export)] {
        for rt in list {
            ops.push(op(BroadcastDomainOp::AddRouteTarget {
                name: name(),
                import,
                route_target: rt.clone(),
            }));
        }
    }
    let label = args.evpn_vtep_source_label.clone();
    if let Some(interface) = &args.evpn_vtep_source_interface {
        ops.push(op(BroadcastDomainOp::SetVtepSource {
            name: name(),
            vtep_source: SourceAddress::Interface {
                interface: interface.clone(),
                label,
            },
        }));
    } else if args.evpn_vtep_source_loopback {
        ops.push(op(BroadcastDomainOp::SetVtepSource {
            name: name(),
            vtep_source: SourceAddress::Loopback { label },
        }));
    }
    if let Some(instance) = &args.evpn_redistribute_bgp {
        ops.push(op(BroadcastDomainOp::SetMacRedistribute {
            name: name(),
            bgp_instance: instance.clone(),
        }));
    }
    if let Some(instance) = &args.evpn_redistribute_arp_bgp {
        ops.push(op(BroadcastDomainOp::SetArpRedistribute {
            name: name(),
            bgp_instance: instance.clone(),
        }));
    }
    if let Some(instance) = &args.evpn_redistribute_connected_bgp {
        ops.push(op(BroadcastDomainOp::SetConnectedRedistribute {
            name: name(),
            bgp_instance: instance.clone(),
        }));
    }
    if let Some(enabled) = args.evpn_neigh_suppress {
        ops.push(op(BroadcastDomainOp::SetNeighSuppress {
            name: name(),
            enabled,
        }));
    }
    Ok(ops)
}

/// The `--l3vni*` flags -> ops on `--l3vni-table` (and its attached subnet).
fn l3vni_ops(args: &Args) -> anyhow::Result<Vec<ConfigOp>> {
    let name = || args.l3vni_table.clone();
    let mut ops = Vec::new();
    if args.l3vni.is_some() || args.l3vni_clear || args.l3vni_interface.is_some() {
        ops.push(ConfigOp::RoutingTable(RoutingTableOp::Ensure {
            name: name(),
        }));
    }
    if let (Some(interface), Some(address)) = (&args.l3vni_interface, args.l3vni_address) {
        ops.push(ConfigOp::Subinterface(SubinterfaceOp::AddAddress {
            interface: interface.clone(),
            tag: 0,
            address,
            label: None,
        }));
        ops.push(ConfigOp::Subinterface(SubinterfaceOp::SetRoutingTable {
            interface: interface.clone(),
            tag: 0,
            routing_table: name(),
        }));
    }
    if args.l3vni_clear {
        ops.push(ConfigOp::RoutingTable(RoutingTableOp::ClearEvpn {
            name: name(),
        }));
    } else if let Some(vni) = args.l3vni {
        let (Some(rd), Some(rt), Some(interface)) = (
            &args.l3vni_rd,
            &args.l3vni_rt,
            &args.l3vni_vtep_source_interface,
        ) else {
            bail!("--l3vni needs --l3vni-rd, --l3vni-rt and --l3vni-vtep-source-interface");
        };
        ops.push(ConfigOp::RoutingTable(RoutingTableOp::SetEvpn {
            name: name(),
            evpn: RoutingTableEvpn {
                l3_vni: Some(vni),
                rd: Some(rd.clone()),
                route_targets_import: vec![rt.clone()],
                route_targets_export: vec![rt.clone()],
                vtep_source: Some(SourceAddress::Interface {
                    interface: interface.clone(),
                    label: None,
                }),
                bgp_instance: Some(args.bgp_instance.clone()),
            },
        }));
    }
    Ok(ops)
}

/// `<transit-area>:<router-id>`, as `--ospf-virtual-link`/`--ospf-clear-virtual-link` take it.
fn virtual_link_spec(flag: &str, spec: &str) -> anyhow::Result<(Ipv4Addr, Ipv4Addr)> {
    let (area, router) = spec
        .split_once(':')
        .with_context(|| format!("{flag}: expected <transit-area>:<router-id>"))?;
    let area_id: Ipv4Addr = area
        .parse()
        .with_context(|| format!("{flag}: bad area {area:?}"))?;
    let router_id: Ipv4Addr = router
        .parse()
        .with_context(|| format!("{flag}: bad router id {router:?}"))?;
    Ok((area_id, router_id))
}

/// `--bfd-auth <method>:<key-id>:<secret>`.
fn parse_bfd_auth(s: &str) -> Result<nos_proto::schema::BfdAuth, String> {
    use nos_proto::schema::{BfdAuth, BfdAuthMethod as M};
    let mut it = s.splitn(3, ':');
    let (Some(m), Some(id), Some(key)) = (it.next(), it.next(), it.next()) else {
        return Err("expected <method>:<key-id>:<secret>".into());
    };
    let method = match m {
        "simple-password" => M::SimplePassword,
        "keyed-md5" => M::KeyedMd5,
        "meticulous-md5" => M::MeticulousMd5,
        "keyed-sha1" => M::KeyedSha1,
        "meticulous-sha1" => M::MeticulousSha1,
        _ => return Err(format!("unknown method {m:?}")),
    };
    Ok(BfdAuth {
        key_id: id.parse().map_err(|e| format!("key id: {e}"))?,
        method,
        key: key.into(),
    })
}

/// `--bfd-echo-mode <affiliated|unaffiliated|disabled>`.
fn parse_echo_mode(s: &str) -> Result<nos_proto::schema::EchoMode, String> {
    use nos_proto::schema::EchoMode;
    match s {
        "affiliated" => Ok(EchoMode::Affiliated),
        "unaffiliated" => Ok(EchoMode::Unaffiliated),
        "disabled" => Ok(EchoMode::Disabled),
        _ => Err(format!(
            "expected affiliated, unaffiliated or disabled, got {s:?}"
        )),
    }
}

/// The profile `--bfd-static` creates and references.
pub const BFD_PROFILE: &str = "fast";

/// The `stp-port-profile` `--port-aggregate-esi` creates (`edge-port admin`,
/// `bpdu-guard`) and attaches to the aggregate: a commit with an ESI
/// aggregate is refused without one (#317) unless spanning tree is disabled.
pub const STP_GUARD_PROFILE: &str = "esi-guard";

/// The `stp-port-profile` `--stp-profile-interface` creates and attaches (#320).
pub const STP_PROT_PROFILE: &str = "e2e-prot";

/// The S-BFD initiator profile `--sbfd-static-route` creates and references.
pub const SBFD_PROFILE: &str = "sb";

/// `SetTransactionPath` edits for `--bfd-static`: `ConfigOp` has no variant
/// for a profile's intervals or a route's `bfd` reference, so these go in
/// through the generic path edit after the ops.
pub fn bfd_paths(args: &Args) -> Vec<(Vec<String>, Option<String>)> {
    let mut v = vec![(
        vec!["spanning-tree".to_string(), "mode".to_string()],
        Some(format!("\"{:?}\"", stp_mode(args))),
    )];
    if let Some(p) = args.stp_priority {
        v.push((
            vec!["spanning-tree".to_string(), "priority".to_string()],
            Some(p.to_string()),
        ));
    }
    if let Some(f) = args.stp_force_version {
        let f: nos_proto::schema::StpForceVersion = f.into();
        v.push((
            vec!["spanning-tree".to_string(), "force-version".to_string()],
            Some(format!("\"{f:?}\"")),
        ));
    }
    v.extend(mst_paths(args));
    if let (Some(agg), Some(_)) = (&args.port_aggregate, &args.port_aggregate_esi) {
        let guard = |field: &str| {
            vec![
                "stp-port-profile".to_string(),
                STP_GUARD_PROFILE.to_string(),
                field.to_string(),
            ]
        };
        v.extend([
            (guard("edge-port"), Some("\"Admin\"".to_string())),
            (guard("bpdu-guard"), Some("true".to_string())),
            (
                vec![
                    "port-aggregate".to_string(),
                    agg.clone(),
                    "stp-port-profile".to_string(),
                ],
                Some(format!("\"{STP_GUARD_PROFILE}\"")),
            ),
        ]);
    }
    if let Some(iface) = &args.stp_profile_interface {
        for f in &args.stp_profile_field {
            let (field, value) = f.split_once('=').unwrap_or((f, ""));
            v.push((
                vec![
                    "stp-port-profile".to_string(),
                    STP_PROT_PROFILE.to_string(),
                    field.to_string(),
                ],
                (!value.is_empty()).then(|| value.to_string()),
            ));
        }
        for (id, cost) in args
            .stp_profile_mst_cost
            .iter()
            .filter_map(|f| f.split_once(':'))
        {
            v.push((
                vec![
                    "stp-port-profile".to_string(),
                    STP_PROT_PROFILE.to_string(),
                    "mst-instance".to_string(),
                    id.to_string(),
                    "cost".to_string(),
                ],
                Some(cost.to_string()),
            ));
        }
        v.push((
            vec![
                "interface".to_string(),
                iface.clone(),
                "stp-port-profile".to_string(),
            ],
            (!args.stp_profile_detach).then(|| format!("\"{STP_PROT_PROFILE}\"")),
        ));
    }
    if args.bfd_bgp || args.no_bfd_bgp {
        v.push((
            vec![
                "bgp-instance".to_string(),
                args.bgp_instance.clone(),
                "peer-group".to_string(),
                args.peer_group.clone(),
                "bfd".to_string(),
            ],
            args.bfd_bgp.then(|| format!("\"{BFD_PROFILE}\"")),
        ));
    }
    for (version, instance, area, profile, on, off) in [
        (
            "ospf",
            &args.ospf_instance,
            args.ospf_area,
            &args.ospf_profile,
            args.ospf_bfd,
            args.no_ospf_bfd,
        ),
        (
            "ospfv3",
            &args.ospfv3_instance,
            args.ospfv3_area,
            &args.ospfv3_profile,
            args.ospfv3_bfd,
            args.no_ospfv3_bfd,
        ),
    ] {
        if let (true, Some(instance), Some(area), Some(profile)) =
            (on || off, instance, area, profile)
        {
            v.push((
                vec![
                    format!("{version}-instance"),
                    instance.clone(),
                    "area".to_string(),
                    area.to_string(),
                    "profile".to_string(),
                    profile.clone(),
                    "bfd".to_string(),
                ],
                on.then(|| format!("\"{BFD_PROFILE}\"")),
            ));
        }
    }
    if args.bfd_auth.is_some() || args.no_bfd_auth {
        v.push((
            vec![
                "bfd-profile".to_string(),
                BFD_PROFILE.to_string(),
                "auth".to_string(),
            ],
            args.bfd_auth
                .as_ref()
                .map(|a| serde_json::to_string(a).expect("BfdAuth serializes")),
        ));
    }
    if !args.sbfd_static_route.is_empty() {
        let sb = |field: &str| {
            vec![
                "bfd-profile".to_string(),
                SBFD_PROFILE.to_string(),
                field.to_string(),
            ]
        };
        let ms = args.bfd_interval_ms.to_string();
        v.extend([
            (
                sb("mode"),
                Some(
                    serde_json::to_string(&nos_proto::schema::BfdMode::Sbfd)
                        .expect("BfdMode serializes"),
                ),
            ),
            (sb("min-tx-interval"), Some(ms.clone())),
            (sb("min-rx-interval"), Some(ms)),
        ]);
        if let Some(d) = args.sbfd_remote_discriminator {
            v.push((sb("sbfd-remote-discriminator"), Some(format!("\"{d}\""))));
        }
        for subnet in &args.sbfd_static_route {
            v.push((
                vec![
                    "static-routing-instance".to_string(),
                    args.static_routing_instance.clone(),
                    "route".to_string(),
                    subnet.to_string(),
                    "bfd".to_string(),
                ],
                Some(format!("\"{SBFD_PROFILE}\"")),
            ));
        }
    }
    if !args.sbfd_reflector.is_empty() || args.no_sbfd_reflector {
        v.push((
            vec!["sbfd-reflector".to_string(), "discriminator".to_string()],
            Some(serde_json::to_string(&args.sbfd_reflector).expect("addresses serialize")),
        ));
    }
    if !args.wants_bfd_profile() {
        return v;
    }
    let profile = |field: &str| {
        vec![
            "bfd-profile".to_string(),
            BFD_PROFILE.to_string(),
            field.to_string(),
        ]
    };
    let ms = args.bfd_interval_ms.to_string();
    v.extend([
        (profile("min-tx-interval"), Some(ms.clone())),
        (profile("min-rx-interval"), Some(ms)),
    ]);
    if let Some(m) = args.bfd_echo_mode {
        v.push((
            profile("echo-mode"),
            Some(serde_json::to_string(&m).expect("EchoMode serializes")),
        ));
    }
    if let Some(ms) = args.bfd_echo_interval {
        v.push((profile("echo-interval"), Some(ms.to_string())));
    }
    if let Some(n) = args.bfd_padded_pdu_size {
        v.push((profile("padded-pdu-size"), Some(n.to_string())));
    }
    for subnet in args.static_route.iter().filter(|_| args.bfd_static) {
        v.push((
            vec![
                "static-routing-instance".to_string(),
                args.static_routing_instance.clone(),
                "route".to_string(),
                subnet.to_string(),
                "bfd".to_string(),
            ],
            Some(format!("\"{BFD_PROFILE}\"")),
        ));
    }
    v
}

/// The path edits of `--stp-region`, `--stp-mst-instance` and
/// `--stp-domain-instance` (flags are `A:B`; a malformed one is skipped).
fn mst_paths(args: &Args) -> Vec<(Vec<String>, Option<String>)> {
    let st = |rest: &[&str]| -> Vec<String> {
        std::iter::once("spanning-tree")
            .chain(rest.iter().copied())
            .map(str::to_string)
            .collect()
    };
    let mut v = Vec::new();
    if let Some((name, rev)) = args.stp_region.as_deref().and_then(|r| r.rsplit_once(':')) {
        v.push((st(&["region", "name"]), Some(format!("\"{name}\""))));
        v.push((st(&["region", "revision"]), Some(rev.to_string())));
    }
    for (id, prio) in args
        .stp_mst_instance
        .iter()
        .filter_map(|f| f.split_once(':'))
    {
        v.push((
            st(&["mst-instance", id, "priority"]),
            Some(prio.to_string()),
        ));
    }
    for (bd, id) in args
        .stp_domain_instance
        .iter()
        .filter_map(|f| f.split_once(':'))
    {
        v.push((
            ["broadcast-domain", bd, "stp-instance"]
                .map(str::to_string)
                .to_vec(),
            Some(id.to_string()),
        ));
    }
    for (bd, prio) in args
        .stp_domain_priority
        .iter()
        .filter_map(|f| f.split_once(':'))
    {
        v.push((
            ["broadcast-domain", bd, "stp-priority"]
                .map(str::to_string)
                .to_vec(),
            Some(prio.to_string()),
        ));
    }
    for f in &args.stp_member_cost {
        let mut it = f.splitn(3, ':');
        if let (Some(sp), Some(bd), Some(cost)) = (it.next(), it.next(), it.next()) {
            v.push((
                ["switching-profile", sp, "member", bd, "stp-cost"]
                    .map(str::to_string)
                    .to_vec(),
                Some(cost.to_string()),
            ));
        }
    }
    v
}

/// `--stp-mode`, `disabled` when unset (see `Args::stp_mode`).
fn stp_mode(args: &Args) -> nos_proto::StpMode {
    args.stp_mode
        .map_or(nos_proto::StpMode::Disabled, Into::into)
}

/// One `--stp-profile-field name=json` on `p`: the kebab-case name is the
/// REST/CLI field, an empty value deletes it. Panics on a malformed flag (a
/// test fixture).
fn set_profile_field(p: &mut nos_proto::schema::StpPortProfile, flag: &str) {
    let (field, value) = flag.split_once('=').unwrap_or((flag, ""));
    let mut json = serde_json::to_value(&*p).expect("profile serializes");
    json[field.replace('-', "_")] = if value.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(value).expect("--stp-profile-field value is JSON")
    };
    *p = serde_json::from_value(json).expect("profile field has the right type");
}

/// [`mst_paths`] applied straight to a local `Config`.
fn apply_mst(args: &Args, config: &mut nos_proto::Config) {
    let st = &mut config.spanning_tree;
    if let Some((name, rev)) = args.stp_region.as_deref().and_then(|r| r.rsplit_once(':')) {
        st.region.name = name.to_string();
        st.region.revision = rev.parse().unwrap_or_default();
    }
    for (id, prio) in args
        .stp_mst_instance
        .iter()
        .filter_map(|f| f.split_once(':'))
    {
        let (Ok(id), Ok(priority)) = (id.parse(), prio.parse()) else {
            continue;
        };
        match st.mst_instances.iter_mut().find(|m| m.id == id) {
            Some(m) => m.priority = priority,
            None => st
                .mst_instances
                .push(nos_proto::schema::MstInstance { id, priority }),
        }
    }
    for (bd, id) in args
        .stp_domain_instance
        .iter()
        .filter_map(|f| f.split_once(':'))
    {
        for d in config.broadcast_domains.iter_mut().filter(|d| d.name == bd) {
            d.stp_instance = id.parse().ok();
        }
    }
    for (bd, prio) in args
        .stp_domain_priority
        .iter()
        .filter_map(|f| f.split_once(':'))
    {
        for d in config.broadcast_domains.iter_mut().filter(|d| d.name == bd) {
            d.stp_priority = prio.parse().ok();
        }
    }
    for f in &args.stp_member_cost {
        let mut it = f.splitn(3, ':');
        if let (Some(sp), Some(bd), Some(cost)) = (it.next(), it.next(), it.next()) {
            for p in config
                .switching_profiles
                .iter_mut()
                .filter(|p| p.name == sp)
            {
                for m in p.members.iter_mut().filter(|m| m.broadcast_domain == bd) {
                    m.stp_cost = cost.parse().ok();
                }
            }
        }
    }
}

/// `bfd_paths` applied straight to a local `Config` (the e2e harness edits
/// one in place instead of sending path edits).
pub fn apply_bfd(args: &Args, config: &mut nos_proto::Config) {
    config.spanning_tree.mode = stp_mode(args);
    if let Some(p) = args.stp_priority {
        config.spanning_tree.priority = p;
    }
    if let Some(f) = args.stp_force_version {
        config.spanning_tree.force_version = Some(f.into());
    }
    apply_mst(args, config);
    if let (Some(agg), Some(_)) = (&args.port_aggregate, &args.port_aggregate_esi) {
        for p in config
            .stp_port_profiles
            .iter_mut()
            .filter(|p| p.name == STP_GUARD_PROFILE)
        {
            p.edge_port = nos_proto::schema::EdgePort::Admin;
            p.bpdu_guard = true;
        }
        for a in config.port_aggregates.iter_mut().filter(|a| &a.name == agg) {
            a.stp_port_profile = Some(STP_GUARD_PROFILE.to_string());
        }
    }
    if let Some(iface) = &args.stp_profile_interface {
        for p in config
            .stp_port_profiles
            .iter_mut()
            .filter(|p| p.name == STP_PROT_PROFILE)
        {
            for f in &args.stp_profile_field {
                set_profile_field(p, f);
            }
            for (id, cost) in args
                .stp_profile_mst_cost
                .iter()
                .filter_map(|f| f.split_once(':'))
            {
                let (Ok(id), Ok(cost)) = (id.parse(), cost.parse()) else {
                    continue;
                };
                match p.mst_instances.iter_mut().find(|m| m.id == id) {
                    Some(m) => m.cost = Some(cost),
                    None => p.mst_instances.push(nos_proto::schema::StpPortMstInstance {
                        id,
                        cost: Some(cost),
                        ..Default::default()
                    }),
                }
            }
        }
        for i in config.interfaces.iter_mut().filter(|i| &i.name == iface) {
            i.stp_port_profile = (!args.stp_profile_detach).then(|| STP_PROT_PROFILE.to_string());
        }
    }
    for i in config
        .bgp_instances
        .iter_mut()
        .filter(|i| i.name == args.bgp_instance)
    {
        for g in i
            .peer_groups
            .iter_mut()
            .filter(|g| g.name == args.peer_group)
        {
            if args.bfd_bgp {
                g.bfd = Some(BFD_PROFILE.to_string());
            } else if args.no_bfd_bgp {
                g.bfd = None;
            }
        }
    }
    for i in config
        .ospf_instances
        .iter_mut()
        .filter(|i| args.ospf_instance.as_ref() == Some(&i.name))
    {
        for a in i
            .areas
            .iter_mut()
            .filter(|a| args.ospf_area == Some(a.area_id))
        {
            for p in a
                .profiles
                .iter_mut()
                .filter(|p| args.ospf_profile.as_ref() == Some(&p.name))
            {
                if args.ospf_bfd {
                    p.bfd = Some(BFD_PROFILE.to_string());
                } else if args.no_ospf_bfd {
                    p.bfd = None;
                }
            }
        }
    }
    for i in config
        .ospfv3_instances
        .iter_mut()
        .filter(|i| args.ospfv3_instance.as_ref() == Some(&i.name))
    {
        for a in i
            .areas
            .iter_mut()
            .filter(|a| args.ospfv3_area == Some(a.area_id))
        {
            for p in a
                .profiles
                .iter_mut()
                .filter(|p| args.ospfv3_profile.as_ref() == Some(&p.name))
            {
                if args.ospfv3_bfd {
                    p.bfd = Some(BFD_PROFILE.to_string());
                } else if args.no_ospfv3_bfd {
                    p.bfd = None;
                }
            }
        }
    }
    if args.bfd_auth.is_some() || args.no_bfd_auth {
        for p in config
            .bfd_profiles
            .iter_mut()
            .filter(|p| p.name == BFD_PROFILE)
        {
            p.auth.clone_from(&args.bfd_auth);
        }
    }
    if !args.sbfd_static_route.is_empty() {
        for p in config
            .bfd_profiles
            .iter_mut()
            .filter(|p| p.name == SBFD_PROFILE)
        {
            p.mode = nos_proto::schema::BfdMode::Sbfd;
            p.min_tx_interval = args.bfd_interval_ms;
            p.min_rx_interval = args.bfd_interval_ms;
            if let Some(d) = args.sbfd_remote_discriminator {
                p.sbfd_remote_discriminator = Some(d);
            }
        }
        for i in config
            .static_routing_instances
            .iter_mut()
            .filter(|i| i.name == args.static_routing_instance)
        {
            for r in i
                .routes
                .iter_mut()
                .filter(|r| args.sbfd_static_route.contains(&r.subnet))
            {
                r.bfd = Some(SBFD_PROFILE.to_string());
            }
        }
    }
    if !args.sbfd_reflector.is_empty() || args.no_sbfd_reflector {
        config
            .sbfd_reflector
            .discriminators
            .clone_from(&args.sbfd_reflector);
    }
    if !args.wants_bfd_profile() {
        return;
    }
    for p in config
        .bfd_profiles
        .iter_mut()
        .filter(|p| p.name == BFD_PROFILE)
    {
        p.min_tx_interval = args.bfd_interval_ms;
        p.min_rx_interval = args.bfd_interval_ms;
        if let Some(m) = args.bfd_echo_mode {
            p.echo_mode = m;
        }
        if let Some(ms) = args.bfd_echo_interval {
            p.echo_interval = ms;
        }
        if let Some(n) = args.bfd_padded_pdu_size {
            p.padded_pdu_size = Some(n);
        }
    }
    for i in config
        .static_routing_instances
        .iter_mut()
        .filter(|i| args.bfd_static && i.name == args.static_routing_instance)
    {
        for r in i
            .routes
            .iter_mut()
            .filter(|r| args.static_route.contains(&r.subnet))
        {
            r.bfd = Some(BFD_PROFILE.to_string());
        }
    }
}

pub fn build_ops(args: &Args) -> anyhow::Result<Vec<ConfigOp>> {
    let link = args.link_interface.as_ref().unwrap_or(&args.interface);
    let mut ops = vec![ConfigOp::Interface(InterfaceOp::Ensure {
        name: args.interface.clone(),
    })];
    if link != &args.interface {
        ops.push(ConfigOp::Interface(InterfaceOp::Ensure {
            name: link.clone(),
        }));
    }
    if args.stp_profile_interface.is_some() {
        ops.push(ConfigOp::StpPortProfile(StpPortProfileOp::Ensure {
            name: STP_PROT_PROFILE.to_string(),
        }));
    }
    if let Some(mtu) = args.mtu {
        ops.push(ConfigOp::Interface(InterfaceOp::SetMtu {
            name: link.clone(),
            mtu,
        }));
    }
    if args.clear_mtu {
        ops.push(ConfigOp::Interface(InterfaceOp::ClearMtu {
            name: link.clone(),
        }));
    }
    if args.delete_subinterface {
        ops.push(ConfigOp::Subinterface(SubinterfaceOp::Delete {
            interface: args.interface.clone(),
            tag: args.subinterface_tag,
        }));
    } else {
        ops.push(ConfigOp::Subinterface(SubinterfaceOp::AddAddress {
            interface: args.interface.clone(),
            tag: args.subinterface_tag,
            address: args.address,
            label: None,
        }));
        ops.push(ConfigOp::Subinterface(SubinterfaceOp::SetRoutingTable {
            interface: args.interface.clone(),
            tag: args.subinterface_tag,
            routing_table: args.routing_table.clone(),
        }));
        if let Some(address) = args.address6 {
            ops.push(ConfigOp::Subinterface(SubinterfaceOp::AddAddress {
                interface: args.interface.clone(),
                tag: args.subinterface_tag,
                address,
                label: args.address6_label.clone(),
            }));
        }
    }
    ops.extend([
        ConfigOp::RoutingTable(RoutingTableOp::Ensure {
            name: args.routing_table.clone(),
        }),
        ConfigOp::RoutingTable(RoutingTableOp::SetBgpInstance {
            name: args.routing_table.clone(),
            bgp_instance: args.bgp_instance.clone(),
        }),
        ConfigOp::BgpInstance(BgpInstanceOp::Ensure {
            name: args.bgp_instance.clone(),
        }),
        ConfigOp::BgpInstance(BgpInstanceOp::SetAsn {
            name: args.bgp_instance.clone(),
            asn: args.asn,
        }),
        ConfigOp::BgpInstance(BgpInstanceOp::SetRouterId {
            name: args.bgp_instance.clone(),
            router_id: args.router_id,
        }),
        ConfigOp::BgpPeerGroup(BgpPeerGroupOp::Ensure {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
        }),
        ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetRemoteAs {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            remote_as: args.remote_as,
        }),
        ConfigOp::BgpPeerGroup(BgpPeerGroupOp::AddAddressFamily {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            af: AddressFamily::Ipv4Unicast,
        }),
        // `import_policy`/`export_policy` default to `deny-all` (see root
        // CLAUDE.md's "Default-deny rollout impact") — every router this
        // tool provisions needs both set explicitly (`accept-all` unless
        // overridden via `--import-policy`/`--export-policy`), or
        // verify-bgp.sh's phases (which predate RPL and expect every route
        // to flow unconditionally) would establish sessions but exchange
        // zero routes.
        ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetImportPolicy {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            import_policy: args.import_policy.clone(),
        }),
        ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetExportPolicy {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            export_policy: args.export_policy.clone(),
        }),
        ConfigOp::BgpPeer(BgpPeerOp::Set {
            instance: args.bgp_instance.clone(),
            remote_address: args.peer,
            peer_group: args.peer_group.clone(),
        }),
    ]);

    if args.wants_bfd_profile() {
        ops.push(ConfigOp::BfdProfile(BfdProfileOp::Ensure {
            name: BFD_PROFILE.to_string(),
        }));
    }
    if !args.sbfd_static_route.is_empty() {
        ops.push(ConfigOp::BfdProfile(BfdProfileOp::Ensure {
            name: SBFD_PROFILE.to_string(),
        }));
    }

    if !args.static_route.is_empty() {
        let gateway = args
            .static_gateway
            .context("--static-gateway is required when --static-route is set")?;
        ops.push(ConfigOp::StaticRoutingInstance(
            StaticRoutingInstanceOp::Ensure {
                name: args.static_routing_instance.clone(),
            },
        ));
        for &subnet in &args.static_route {
            ops.push(ConfigOp::StaticRoute(StaticRouteOp::Set {
                instance: args.static_routing_instance.clone(),
                subnet,
                gateway,
            }));
        }
        ops.push(ConfigOp::RoutingTable(
            RoutingTableOp::SetStaticRoutingInstance {
                name: args.routing_table.clone(),
                static_routing_instance: args.static_routing_instance.clone(),
            },
        ));
    } else if args.redistribute || args.redistribute_to_ospf || args.redistribute_to_ospfv3 {
        bail!(
            "--redistribute/--redistribute-to-ospf/--redistribute-to-ospfv3 require \
             --static-route (and --static-gateway) to also be set"
        );
    }

    if args.redistribute {
        ops.push(ConfigOp::RoutingTable(RoutingTableOp::SetRedistribute {
            name: args.routing_table.clone(),
            redistribute: Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Bgp,
                policy: args.redistribute_policy.clone(),
                metric: None,
                metric_type: None,
            },
        }));
    }
    if (args.redistribute_metric.is_some() || args.redistribute_metric_type.is_some())
        && !args.redistribute_to_ospf
    {
        bail!("--redistribute-metric/--redistribute-metric-type require --redistribute-to-ospf");
    }
    if args.redistribute_to_ospf {
        if args.ospf_instance.is_none() {
            bail!("--redistribute-to-ospf requires --ospf-instance to also be set");
        }
        ops.push(ConfigOp::RoutingTable(RoutingTableOp::SetRedistribute {
            name: args.routing_table.clone(),
            redistribute: Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Ospf,
                policy: args.redistribute_to_ospf_policy.clone(),
                metric: args.redistribute_metric,
                metric_type: args.redistribute_metric_type,
            },
        }));
    }
    if args.redistribute_to_ospfv3 {
        if args.ospfv3_instance.is_none() {
            bail!("--redistribute-to-ospfv3 requires --ospfv3-instance to also be set");
        }
        ops.push(ConfigOp::RoutingTable(RoutingTableOp::SetRedistribute {
            name: args.routing_table.clone(),
            redistribute: Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Ospfv3,
                policy: args.redistribute_to_ospfv3_policy.clone(),
                metric: None,
                metric_type: None,
            },
        }));
    }
    if args.clear_redistribute_to_ospfv3 {
        if args.redistribute_to_ospfv3 {
            bail!("--clear-redistribute-to-ospfv3 is mutually exclusive with --redistribute-to-ospfv3");
        }
        ops.push(ConfigOp::RoutingTable(RoutingTableOp::ClearRedistribute {
            name: args.routing_table.clone(),
            to: RedistributeTarget::Ospfv3,
        }));
    }
    if args.clear_redistribute_to_ospf {
        if args.redistribute_to_ospf {
            bail!("--clear-redistribute-to-ospf is mutually exclusive with --redistribute-to-ospf");
        }
        ops.push(ConfigOp::RoutingTable(RoutingTableOp::ClearRedistribute {
            name: args.routing_table.clone(),
            to: RedistributeTarget::Ospf,
        }));
    }

    if let Some(password) = args.md5_password.clone() {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetMd5Auth {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            password,
        }));
    }

    if let (Some(send_id), Some(secret)) = (args.ao_send_id, args.ao_key_secret.clone()) {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetAoKey {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            key: BgpAoKey {
                send_id,
                recv_id: args.ao_recv_id.unwrap_or(send_id),
                algorithm: args.ao_algorithm.into(),
                key: secret,
                is_current: args.ao_current,
                is_rnext: args.ao_rnext,
                exclude_options: args.ao_exclude_options,
            },
        }));
    }
    if let Some(send_id) = args.ao_promote_current {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetAoCurrentKey {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            send_id,
        }));
    }
    if let Some(send_id) = args.ao_remove_key {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::RemoveAoKey {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            send_id,
        }));
    }

    if args.evpn {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::AddAddressFamily {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            af: AddressFamily::L2vpnEvpn,
        }));
    }
    if args.route_reflector_client {
        ops.push(ConfigOp::BgpPeerGroup(
            BgpPeerGroupOp::SetRouteReflectorClient {
                instance: args.bgp_instance.clone(),
                name: args.peer_group.clone(),
            },
        ));
    }
    if args.announce_rpki_state {
        ops.push(ConfigOp::BgpPeerGroup(
            BgpPeerGroupOp::SetAnnounceRpkiState {
                instance: args.bgp_instance.clone(),
                name: args.peer_group.clone(),
                enabled: true,
            },
        ));
    }
    if args.route_server_client {
        ops.push(ConfigOp::BgpPeerGroup(
            BgpPeerGroupOp::SetRouteServerClient {
                instance: args.bgp_instance.clone(),
                name: args.peer_group.clone(),
            },
        ));
    }
    if let Some(cluster_id) = args.cluster_id {
        ops.push(ConfigOp::BgpInstance(BgpInstanceOp::SetClusterId {
            name: args.bgp_instance.clone(),
            cluster_id,
        }));
    }
    if let Some(maximum_paths) = args.maximum_paths {
        ops.push(ConfigOp::BgpInstance(BgpInstanceOp::SetMaximumPaths {
            name: args.bgp_instance.clone(),
            maximum_paths,
        }));
    }
    if args.no_graceful_restart
        || args.clear_graceful_restart
        || args.gr_restart_time.is_some()
        || args.gr_stale_time.is_some()
        || args.gr_selection_deferral_time.is_some()
    {
        ops.push(ConfigOp::BgpInstance(BgpInstanceOp::SetGracefulRestart {
            name: args.bgp_instance.clone(),
            graceful_restart: nos_proto::BgpGracefulRestart {
                disabled: args.no_graceful_restart,
                restart_time: args.gr_restart_time,
                stale_time: args.gr_stale_time,
                selection_deferral_time: args.gr_selection_deferral_time,
            },
        }));
    }
    if let Some(identifier) = args.confederation_id {
        ops.push(ConfigOp::BgpInstance(
            BgpInstanceOp::SetConfederationIdentifier {
                name: args.bgp_instance.clone(),
                identifier,
            },
        ));
    }
    for &asn in &args.confederation_peer {
        ops.push(ConfigOp::BgpInstance(BgpInstanceOp::AddConfederationPeer {
            name: args.bgp_instance.clone(),
            asn,
        }));
    }
    for (preference, cache) in args.rpki_cache.iter().enumerate() {
        ops.push(ConfigOp::BgpInstance(BgpInstanceOp::SetRpkiCache {
            name: args.bgp_instance.clone(),
            cache: nos_proto::RpkiCache {
                address: cache.ip(),
                port: cache.port(),
                preference: u8::try_from(preference).unwrap_or(u8::MAX),
            },
        }));
    }
    for &prefix in &args.aggregate_address {
        ops.push(ConfigOp::BgpInstance(BgpInstanceOp::SetAggregate {
            name: args.bgp_instance.clone(),
            aggregate: nos_proto::BgpAggregate {
                prefix,
                as_set: args.aggregate_as_set,
                summary_only: args.aggregate_summary_only,
            },
        }));
    }
    for &prefix in &args.remove_aggregate_address {
        ops.push(ConfigOp::BgpInstance(BgpInstanceOp::RemoveAggregate {
            name: args.bgp_instance.clone(),
            prefix,
        }));
    }
    for &subnet in &args.remove_static_route {
        ops.push(ConfigOp::StaticRoute(StaticRouteOp::Delete {
            instance: args.static_routing_instance.clone(),
            subnet,
        }));
    }

    if let Some(connect_retry_time) = args.connect_retry_time {
        ops.push(ConfigOp::BgpPeerGroup(
            BgpPeerGroupOp::SetConnectRetryTime {
                instance: args.bgp_instance.clone(),
                name: args.peer_group.clone(),
                connect_retry_time,
            },
        ));
    }

    if let Some(mrai) = args.mrai {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetMrai {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            mrai,
        }));
    }

    if let Some(seconds) = args.route_refresh_stale_time {
        ops.push(ConfigOp::BgpPeerGroup(
            BgpPeerGroupOp::SetRouteRefreshStaleTime {
                instance: args.bgp_instance.clone(),
                name: args.peer_group.clone(),
                seconds,
            },
        ));
    }

    if let Some(max_hops) = args.max_hops {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetMaxHops {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            max_hops,
        }));
    }

    let message = |m: &String| (!m.is_empty()).then(|| m.clone());
    if let Some(m) = &args.shutdown_peer_group {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetShutdown {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            message: message(m),
        }));
    }
    if args.unshutdown_peer_group {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearShutdown {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
        }));
    }
    if let Some(m) = &args.shutdown_peer {
        ops.push(ConfigOp::BgpPeer(BgpPeerOp::SetShutdown {
            instance: args.bgp_instance.clone(),
            remote_address: args.peer,
            message: message(m),
        }));
    }
    if args.unshutdown_peer {
        ops.push(ConfigOp::BgpPeer(BgpPeerOp::ClearShutdown {
            instance: args.bgp_instance.clone(),
            remote_address: args.peer,
        }));
    }

    if [
        args.damping_half_life,
        args.damping_reuse,
        args.damping_suppress,
        args.damping_max_suppress,
    ]
    .iter()
    .any(Option::is_some)
    {
        let d = nos_proto::BgpDamping::default();
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetDamping {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            damping: nos_proto::BgpDamping {
                half_life: args.damping_half_life.unwrap_or(d.half_life),
                reuse: args.damping_reuse.unwrap_or(d.reuse),
                suppress: args.damping_suppress.unwrap_or(d.suppress),
                max_suppress: args.damping_max_suppress.unwrap_or(d.max_suppress),
            },
        }));
    }
    if let Some(asn) = args.local_as {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetLocalAs {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            local_as: nos_proto::BgpLocalAs {
                asn,
                no_prepend: args.local_as_no_prepend,
                replace_as: args.local_as_replace_as,
            },
        }));
    }
    if let Some(mode) = args.add_path {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetAddPath {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            mode,
        }));
    }
    if let Some(count) = args.add_path_send_count {
        ops.push(ConfigOp::BgpPeerGroup(
            BgpPeerGroupOp::SetAddPathSendCount {
                instance: args.bgp_instance.clone(),
                name: args.peer_group.clone(),
                count,
            },
        ));
    }
    if let Some(role) = args.role {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetRole {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            role,
        }));
    }
    if args.strict_mode {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetStrictMode {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            enabled: true,
        }));
    }
    if args.clear_damping {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearDamping {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
        }));
    }
    for &(family, limit) in &args.maximum_prefix {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetMaximumPrefix {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            family,
            limit: nos_proto::BgpPrefixLimit {
                limit,
                warning_only: args.maximum_prefix_warning_only,
                restart_interval: args.maximum_prefix_restart_interval,
            },
        }));
    }
    for &family in &args.clear_maximum_prefix {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearMaximumPrefix {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            family,
        }));
    }

    if let Some(name) = args.policy_name.clone() {
        let path = args
            .policy_source_file
            .clone()
            .context("--policy-source-file is required when --policy-name is set")?;
        let source = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        ops.push(ConfigOp::PolicyDefinition(PolicyDefinitionOp::Ensure {
            name: name.clone(),
        }));
        ops.push(ConfigOp::PolicyDefinition(PolicyDefinitionOp::SetSource {
            name,
            source,
        }));
    } else if args.policy_source_file.is_some() {
        bail!("--policy-source-file requires --policy-name to also be set");
    }

    if args.loopback_address.is_some() && args.delete_loopback {
        bail!("--loopback-address and --delete-loopback are mutually exclusive");
    }
    let loopback_name = format!("loopback-{}", args.routing_table);
    if let Some(address) = args.loopback_remove_address {
        ops.push(ConfigOp::Interface(InterfaceOp::RemoveAddress {
            name: loopback_name.clone(),
            address,
        }));
    }
    if let Some(address) = args.loopback_address {
        ops.push(ConfigOp::Interface(InterfaceOp::Ensure {
            name: loopback_name.clone(),
        }));
        ops.push(ConfigOp::Interface(InterfaceOp::AddAddress {
            name: loopback_name.clone(),
            address,
            label: None,
        }));
    }
    if args.delete_loopback {
        ops.push(ConfigOp::Interface(InterfaceOp::Delete {
            name: loopback_name.clone(),
        }));
    }

    if args.ospf_loopback_profile.is_some() && args.clear_ospf_loopback_profile {
        bail!("--ospf-loopback-profile and --clear-ospf-loopback-profile are mutually exclusive");
    }
    if let Some(profile) = args.ospf_loopback_profile.clone() {
        // An ospf_profile on a loopback requires routing_table also set on
        // the same Interface (`valid_addressing_split`) -- VRF enslavement
        // itself is derived from the loopback's name, but the validator
        // still demands the field be explicit, mirroring the Subinterface/
        // BroadcastDomain OSPF requirement.
        ops.push(ConfigOp::Interface(InterfaceOp::SetRoutingTable {
            name: loopback_name.clone(),
            routing_table: args.routing_table.clone(),
        }));
        ops.push(ConfigOp::Interface(InterfaceOp::SetOspfProfile {
            name: loopback_name.clone(),
            ospf_profile: profile,
        }));
    }
    if args.clear_ospf_loopback_profile {
        ops.push(ConfigOp::Interface(InterfaceOp::ClearOspfProfile {
            name: loopback_name.clone(),
        }));
    }

    // Same shape as `--ospf-loopback-profile`, joining `OSPFv3` instead —
    // `--ospfv3-loopback-address` adds a second (IPv6) address to the same
    // loopback interface `--loopback-address` (typically IPv4) already
    // ensures, since `OSPFv3` only ever advertises IPv6 prefixes.
    if args.ospfv3_loopback_profile.is_some() && args.clear_ospfv3_loopback_profile {
        bail!(
            "--ospfv3-loopback-profile and --clear-ospfv3-loopback-profile are mutually exclusive"
        );
    }
    if let Some(address) = args.ospfv3_loopback_address {
        ops.push(ConfigOp::Interface(InterfaceOp::Ensure {
            name: loopback_name.clone(),
        }));
        ops.push(ConfigOp::Interface(InterfaceOp::AddAddress {
            name: loopback_name.clone(),
            address,
            label: None,
        }));
    }
    if let Some(profile) = args.ospfv3_loopback_profile.clone() {
        ops.push(ConfigOp::Interface(InterfaceOp::SetRoutingTable {
            name: loopback_name.clone(),
            routing_table: args.routing_table.clone(),
        }));
        ops.push(ConfigOp::Interface(InterfaceOp::SetOspfv3Profile {
            name: loopback_name.clone(),
            ospfv3_profile: profile,
        }));
    }
    if args.clear_ospfv3_loopback_profile {
        ops.push(ConfigOp::Interface(InterfaceOp::ClearOspfv3Profile {
            name: loopback_name,
        }));
    }

    if args.broadcast_domain_svi_address.is_some() && args.delete_broadcast_domain_svi {
        bail!(
            "--broadcast-domain-svi-address and --delete-broadcast-domain-svi are mutually \
             exclusive"
        );
    }
    if let Some(address) = args.broadcast_domain_svi_address {
        ops.push(ConfigOp::BroadcastDomain(BroadcastDomainOp::Ensure {
            name: args.broadcast_domain.clone(),
        }));
        ops.push(ConfigOp::BroadcastDomain(BroadcastDomainOp::AddAddress {
            name: args.broadcast_domain.clone(),
            address,
            label: None,
        }));
        if args.broadcast_domain_svi_table.is_none() {
            ops.push(ConfigOp::BroadcastDomain(
                BroadcastDomainOp::SetRoutingTable {
                    name: args.broadcast_domain.clone(),
                    routing_table: args.routing_table.clone(),
                },
            ));
        }
    }
    if args.delete_broadcast_domain_svi {
        ops.push(ConfigOp::BroadcastDomain(BroadcastDomainOp::Delete {
            name: args.broadcast_domain.clone(),
        }));
    }

    ops.extend(evpn_ops(args)?);
    ops.extend(l3vni_ops(args)?);
    // After `--l3vni*`, which ensures the table.
    if let (Some(_), Some(table)) = (
        args.broadcast_domain_svi_address,
        &args.broadcast_domain_svi_table,
    ) {
        ops.push(ConfigOp::BroadcastDomain(
            BroadcastDomainOp::SetRoutingTable {
                name: args.broadcast_domain.clone(),
                routing_table: table.clone(),
            },
        ));
    }

    // Adds a second (IPv6) address to `--broadcast-domain`'s SVI alongside
    // `--broadcast-domain-svi-address` — same dual-stack rationale as
    // `--address6`/`--ospfv3-loopback-address`.
    if let Some(address) = args.ospfv3_broadcast_domain_svi_address {
        ops.push(ConfigOp::BroadcastDomain(BroadcastDomainOp::Ensure {
            name: args.broadcast_domain.clone(),
        }));
        ops.push(ConfigOp::BroadcastDomain(BroadcastDomainOp::AddAddress {
            name: args.broadcast_domain.clone(),
            address,
            label: None,
        }));
    }

    let source_address_flags = [
        args.source_address_interface.is_some(),
        args.source_address_loopback,
        args.clear_source_address,
    ];
    if source_address_flags.iter().filter(|set| **set).count() > 1 {
        bail!(
            "--source-address-interface, --source-address-loopback, and \
             --clear-source-address are mutually exclusive"
        );
    }
    if let Some(interface) = args.source_address_interface.clone() {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetSourceAddress {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            source: SourceAddress::Interface {
                interface,
                label: args.source_address_label.clone(),
            },
        }));
    } else if args.source_address_loopback {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetSourceAddress {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            source: SourceAddress::Loopback {
                label: args.source_address_label.clone(),
            },
        }));
    } else if args.clear_source_address {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearSourceAddress {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
        }));
    }

    if args.switching_profile.is_some() && args.delete_switching_profile {
        bail!("--switching-profile and --delete-switching-profile are mutually exclusive");
    }
    if let Some(profile) = args.switching_profile.clone() {
        ops.push(ConfigOp::SwitchingProfile(SwitchingProfileOp::Ensure {
            name: profile.clone(),
        }));
        for member in &args.switching_profile_members {
            let (domain, tag) = member.split_once(':').with_context(|| {
                format!("--switching-profile-member {member} must be DOMAIN:TAG")
            })?;
            let tag = if tag.eq_ignore_ascii_case("untagged") {
                VlanTag::Untagged
            } else {
                VlanTag::Dot1q(tag.parse().with_context(|| {
                    format!("invalid vlan tag '{tag}' in --switching-profile-member {member}")
                })?)
            };
            ops.push(ConfigOp::BroadcastDomain(BroadcastDomainOp::Ensure {
                name: domain.to_string(),
            }));
            ops.push(ConfigOp::SwitchingProfile(SwitchingProfileOp::AddMember {
                name: profile.clone(),
                broadcast_domain: domain.to_string(),
                tag,
            }));
        }
        ops.push(ConfigOp::Interface(InterfaceOp::SetSwitchingProfile {
            name: link.clone(),
            switching_profile: profile,
        }));
    } else if !args.switching_profile_members.is_empty() {
        bail!("--switching-profile-member requires --switching-profile to also be set");
    }
    if args.delete_switching_profile {
        ops.push(ConfigOp::Interface(InterfaceOp::ClearSwitchingProfile {
            name: link.clone(),
        }));
    }

    if args.delete_port_aggregate {
        let name = args
            .port_aggregate
            .clone()
            .context("--delete-port-aggregate requires --port-aggregate to also be set")?;
        // Clear each member's own reference first — committing the deletion
        // while a member interface still points at this now-gone aggregate
        // would fail commit-time validation (`port_aggregate_reference_valid`).
        for member in &args.port_aggregate_members {
            ops.push(ConfigOp::Interface(InterfaceOp::ClearPortAggregate {
                name: member.clone(),
            }));
        }
        ops.push(ConfigOp::PortAggregate(PortAggregateOp::Delete { name }));
    } else if let Some(name) = args.port_aggregate.clone() {
        ops.push(ConfigOp::PortAggregate(PortAggregateOp::Ensure {
            name: name.clone(),
            mode: args.port_aggregate_mode.into(),
        }));
        if let Some(rate) = args.lacp_rate {
            ops.push(ConfigOp::PortAggregate(PortAggregateOp::SetLacpRate {
                name: name.clone(),
                rate: rate.into(),
            }));
        }
        if let Some(mtu) = args.port_aggregate_mtu {
            ops.push(ConfigOp::PortAggregate(PortAggregateOp::SetMtu {
                name: name.clone(),
                mtu,
            }));
        }
        if let Some(address) = args.port_aggregate_address {
            ops.push(ConfigOp::PortAggregateSubinterface(
                PortAggregateSubinterfaceOp::AddAddress {
                    port_aggregate: name.clone(),
                    tag: 0,
                    address,
                    label: None,
                },
            ));
            ops.push(ConfigOp::PortAggregateSubinterface(
                PortAggregateSubinterfaceOp::SetRoutingTable {
                    port_aggregate: name.clone(),
                    tag: 0,
                    routing_table: args.routing_table.clone(),
                },
            ));
        }
        if let Some(esi) = args.port_aggregate_esi.clone() {
            ops.push(ConfigOp::StpPortProfile(StpPortProfileOp::Ensure {
                name: STP_GUARD_PROFILE.to_string(),
            }));
            ops.push(ConfigOp::PortAggregate(PortAggregateOp::SetEsi {
                name: name.clone(),
                esi,
            }));
        }
        if args.delete_port_aggregate_esi {
            ops.push(ConfigOp::PortAggregate(PortAggregateOp::ClearEsi {
                name: name.clone(),
            }));
        }
        if let Some(mode) = args.port_aggregate_redundancy_mode {
            ops.push(ConfigOp::PortAggregate(
                PortAggregateOp::SetRedundancyMode {
                    name: name.clone(),
                    mode: mode.into(),
                },
            ));
        }
        if let Some(algorithm) = args.port_aggregate_df_algorithm {
            ops.push(ConfigOp::PortAggregate(PortAggregateOp::SetDfAlgorithm {
                name: name.clone(),
                algorithm: algorithm.into(),
            }));
        }
        if let Some(system_id) = args.lacp_system_id.clone() {
            ops.push(ConfigOp::PortAggregate(PortAggregateOp::SetLacpSystemId {
                name: name.clone(),
                system_id,
            }));
        }
        if let Some(priority) = args.lacp_system_priority {
            ops.push(ConfigOp::PortAggregate(
                PortAggregateOp::SetLacpSystemPriority {
                    name: name.clone(),
                    priority,
                },
            ));
        }
        if let Some(min_links) = args.min_links {
            ops.push(ConfigOp::PortAggregate(PortAggregateOp::SetMinLinks {
                name: name.clone(),
                min_links,
            }));
        }
        if let Some(profile) = args.port_aggregate_bfd.clone() {
            ops.push(ConfigOp::PortAggregate(PortAggregateOp::SetBfd {
                name: name.clone(),
                profile,
            }));
        }
        if let Some(peer) = args.port_aggregate_bfd_peer {
            ops.push(ConfigOp::PortAggregate(PortAggregateOp::SetBfdPeer {
                name: name.clone(),
                peer,
            }));
        }
        if let Some(domain) = args.port_aggregate_untagged_domain.clone() {
            let profile = format!("{name}-sp");
            ops.push(ConfigOp::BroadcastDomain(BroadcastDomainOp::Ensure {
                name: domain.clone(),
            }));
            ops.push(ConfigOp::SwitchingProfile(SwitchingProfileOp::Ensure {
                name: profile.clone(),
            }));
            ops.push(ConfigOp::SwitchingProfile(SwitchingProfileOp::AddMember {
                name: profile.clone(),
                broadcast_domain: domain,
                tag: VlanTag::Untagged,
            }));
            ops.push(ConfigOp::PortAggregate(
                PortAggregateOp::SetSwitchingProfile {
                    name: name.clone(),
                    switching_profile: profile,
                },
            ));
        }
        for member in &args.port_aggregate_members {
            ops.push(ConfigOp::Interface(InterfaceOp::Ensure {
                name: member.clone(),
            }));
            ops.push(ConfigOp::Interface(InterfaceOp::SetPortAggregate {
                name: member.clone(),
                port_aggregate: name.clone(),
            }));
            if let Some(mode) = args.lacp_mode {
                ops.push(ConfigOp::Interface(InterfaceOp::SetLacpMode {
                    name: member.clone(),
                    mode: mode.into(),
                }));
            }
            if let Some(priority) = args.lacp_port_priority {
                ops.push(ConfigOp::Interface(InterfaceOp::SetLacpPortPriority {
                    name: member.clone(),
                    priority,
                }));
            }
        }
    } else if args.port_aggregate_mtu.is_some()
        || args.port_aggregate_address.is_some()
        || args.port_aggregate_esi.is_some()
        || args.delete_port_aggregate_esi
        || args.port_aggregate_redundancy_mode.is_some()
        || args.port_aggregate_df_algorithm.is_some()
        || args.lacp_system_id.is_some()
        || args.lacp_system_priority.is_some()
        || args.min_links.is_some()
        || args.port_aggregate_bfd.is_some()
        || args.port_aggregate_bfd_peer.is_some()
        || args.lacp_port_priority.is_some()
        || args.lacp_mode.is_some()
        || args.port_aggregate_untagged_domain.is_some()
        || args.lacp_rate.is_some()
        || !args.port_aggregate_members.is_empty()
    {
        bail!(
            "--port-aggregate-mtu/--port-aggregate-address/--port-aggregate-esi/--port-aggregate-redundancy-mode/--port-aggregate-df-algorithm/--lacp-system-id/--lacp-system-priority/--min-links/--port-aggregate-bfd/--port-aggregate-bfd-peer/--lacp-port-priority/--lacp-mode/--port-aggregate-untagged-domain/--lacp-rate/--enslave-interface-into-port-aggregate require --port-aggregate to also be set"
        );
    }

    for member in &args.clear_port_aggregate_members {
        ops.push(ConfigOp::Interface(InterfaceOp::ClearPortAggregate {
            name: member.clone(),
        }));
    }

    if let Some(hostname) = args.hostname.clone() {
        ops.push(ConfigOp::SetHostname(hostname));
    }

    for (name, password) in &args.users {
        ops.push(ConfigOp::User(UserOp::SetPassword {
            name: name.clone(),
            password: password.clone(),
        }));
    }

    // (interface, transmit-or-receive, enabled) — each interface is ensured
    // first, since the toggle ops require it to already exist.
    let lldp_toggles = args
        .lldp_transmit_interfaces
        .iter()
        .map(|i| (i, true, true))
        .chain(
            args.lldp_receive_interfaces
                .iter()
                .map(|i| (i, false, true)),
        )
        .chain(
            args.no_lldp_transmit_interfaces
                .iter()
                .map(|i| (i, true, false)),
        )
        .chain(
            args.no_lldp_receive_interfaces
                .iter()
                .map(|i| (i, false, false)),
        );
    for (name, transmit, enabled) in lldp_toggles {
        ops.push(ConfigOp::Interface(InterfaceOp::Ensure {
            name: name.clone(),
        }));
        ops.push(ConfigOp::Interface(if transmit {
            InterfaceOp::SetLldpTransmit {
                name: name.clone(),
                enabled,
            }
        } else {
            InterfaceOp::SetLldpReceive {
                name: name.clone(),
                enabled,
            }
        }));
    }

    if let Some(secs) = args.lldp_tx_interval {
        ops.push(ConfigOp::Lldp(LldpOp::SetTxInterval { secs }));
    }
    if let Some(hold) = args.lldp_tx_hold {
        ops.push(ConfigOp::Lldp(LldpOp::SetTxHold { hold }));
    }
    for &address in &args.lldp_management_addresses {
        ops.push(ConfigOp::Lldp(LldpOp::AddManagementAddress { address }));
    }
    for &address in &args.no_lldp_management_addresses {
        ops.push(ConfigOp::Lldp(LldpOp::RemoveManagementAddress { address }));
    }
    if let Some(name) = &args.syslog_server {
        let n = || name.clone();
        ops.push(ConfigOp::Logging(LoggingOp::EnsureSyslog { name: n() }));
        if let Some(address) = args.syslog_address {
            ops.push(ConfigOp::Logging(LoggingOp::SetSyslogAddress {
                name: n(),
                address,
            }));
        }
        if let Some(port) = args.syslog_port {
            ops.push(ConfigOp::Logging(LoggingOp::SetSyslogPort {
                name: n(),
                port: Some(port),
            }));
        }
        if let Some(t) = &args.syslog_transport {
            let transport = match t.as_str() {
                "udp" => SyslogTransport::Udp,
                "tcp" => SyslogTransport::Tcp,
                "tls" => SyslogTransport::Tls,
                _ => bail!("--syslog-transport is udp, tcp or tls, not '{t}'"),
            };
            ops.push(ConfigOp::Logging(LoggingOp::SetSyslogTransport {
                name: n(),
                transport,
            }));
        }
        if let Some(file) = &args.syslog_trust_anchor_file {
            let pem = std::fs::read_to_string(file)
                .with_context(|| format!("reading {}", file.display()))?;
            ops.push(ConfigOp::Logging(LoggingOp::SetSyslogTlsTrustAnchor {
                name: n(),
                pem: Some(pem),
            }));
        }
        if let Some(fingerprint) = &args.syslog_fingerprint {
            ops.push(ConfigOp::Logging(LoggingOp::SetSyslogTlsFingerprint {
                name: n(),
                fingerprint: Some(fingerprint.clone()),
            }));
        }
        if let Some(server_name) = &args.syslog_server_name {
            ops.push(ConfigOp::Logging(LoggingOp::SetSyslogTlsServerName {
                name: n(),
                server_name: Some(server_name.clone()),
            }));
        }
        if args.syslog_allow_tls12 || args.no_syslog_allow_tls12 {
            ops.push(ConfigOp::Logging(LoggingOp::SetSyslogTlsAllowTls12 {
                name: n(),
                allow: args.syslog_allow_tls12,
            }));
        }
        if let Some(rt) = &args.syslog_routing_table {
            ops.push(ConfigOp::Logging(LoggingOp::SetSyslogRoutingTable {
                name: n(),
                routing_table: Some(rt.clone()),
            }));
        }
        if let Some(l) = &args.syslog_level {
            let level = match l.as_str() {
                "error" => LogLevel::Error,
                "warn" => LogLevel::Warn,
                "info" => LogLevel::Info,
                "debug" => LogLevel::Debug,
                "trace" => LogLevel::Trace,
                _ => bail!("unknown --syslog-level '{l}'"),
            };
            ops.push(ConfigOp::Logging(LoggingOp::SetSyslogLevel {
                name: n(),
                level: Some(level),
            }));
        }
        if let Some(f) = &args.syslog_facility {
            const FACILITIES: [SyslogFacility; 8] = [
                SyslogFacility::Local0,
                SyslogFacility::Local1,
                SyslogFacility::Local2,
                SyslogFacility::Local3,
                SyslogFacility::Local4,
                SyslogFacility::Local5,
                SyslogFacility::Local6,
                SyslogFacility::Local7,
            ];
            let facility = f
                .strip_prefix("local")
                .and_then(|d| d.parse::<usize>().ok())
                .and_then(|i| FACILITIES.get(i).copied())
                .with_context(|| format!("unknown --syslog-facility '{f}'"))?;
            ops.push(ConfigOp::Logging(LoggingOp::SetSyslogFacility {
                name: n(),
                facility: Some(facility),
            }));
        }
    }
    for name in &args.no_syslog_servers {
        ops.push(ConfigOp::Logging(LoggingOp::RemoveSyslog {
            name: name.clone(),
        }));
    }
    for spec in &args.lldp_destination_interfaces {
        let (name, group) = spec
            .split_once('=')
            .context("--lldp-destination-interface takes <interface>=<group>")?;
        let destination = LldpDestination::from_name(group)
            .with_context(|| format!("unknown lldp destination group '{group}'"))?;
        ops.push(ConfigOp::Interface(InterfaceOp::Ensure {
            name: name.to_string(),
        }));
        ops.push(ConfigOp::Interface(InterfaceOp::SetLldpDestination {
            name: name.to_string(),
            destination,
        }));
    }

    if let Some(address) = args.rest_api_address {
        if args.clear_rest_api {
            bail!("--rest-api-address and --clear-rest-api are mutually exclusive");
        }
        ops.push(ConfigOp::RoutingTable(RoutingTableOp::SetRestApi {
            name: args.routing_table.clone(),
            address,
            port: args.rest_api_port,
        }));
    } else if args.clear_rest_api {
        ops.push(ConfigOp::RoutingTable(RoutingTableOp::ClearRestApi {
            name: args.routing_table.clone(),
        }));
    }

    if let Some(name) = args.ospf_instance.clone() {
        let router_id = args
            .ospf_router_id
            .context("--ospf-router-id is required when --ospf-instance is set")?;
        ops.push(ConfigOp::OspfInstance(OspfInstanceOp::Ensure {
            name: name.clone(),
        }));
        ops.push(ConfigOp::OspfInstance(OspfInstanceOp::SetRouterId {
            name: name.clone(),
            router_id,
        }));
        if let Some(grace_period) = args.ospf_graceful_restart_grace_period {
            ops.push(ConfigOp::OspfInstance(
                OspfInstanceOp::SetGracefulRestartGracePeriod {
                    name: name.clone(),
                    grace_period: (grace_period != 0).then_some(grace_period),
                },
            ));
        }
        if let Some(enabled) = args.ospf_remote_lfa {
            ops.push(ConfigOp::OspfInstance(OspfInstanceOp::SetRemoteLfa {
                name: name.clone(),
                enabled,
            }));
        }
        if let Some(enabled) = args.ospf_prefix_suppression {
            ops.push(ConfigOp::OspfInstance(
                OspfInstanceOp::SetPrefixSuppression {
                    name: name.clone(),
                    enabled,
                },
            ));
        }
        if let Some(seconds) = args.ospf_max_metric_on_startup {
            ops.push(ConfigOp::OspfInstance(
                OspfInstanceOp::SetMaxMetricOnStartup {
                    name: name.clone(),
                    seconds: (seconds != 0).then_some(seconds),
                },
            ));
        }
        if let Some(seconds) = args.ospf_max_metric_on_shutdown {
            ops.push(ConfigOp::OspfInstance(
                OspfInstanceOp::SetMaxMetricOnShutdown {
                    name: name.clone(),
                    seconds: (seconds != 0).then_some(seconds),
                },
            ));
        }
        if let Some(enabled) = args.ospf_max_metric_administrative {
            ops.push(ConfigOp::OspfInstance(
                OspfInstanceOp::SetMaxMetricAdministrative {
                    name: name.clone(),
                    enabled,
                },
            ));
        }
        if let Some(enabled) = args.ospf_host_router {
            ops.push(ConfigOp::OspfInstance(OspfInstanceOp::SetHostRouter {
                name: name.clone(),
                enabled,
            }));
        }
        ops.push(ConfigOp::RoutingTable(RoutingTableOp::SetOspfInstance {
            name: args.routing_table.clone(),
            ospf_instance: name,
        }));
    } else if args.ospf_router_id.is_some() {
        bail!("--ospf-router-id requires --ospf-instance to also be set");
    }

    if let Some(spec) = &args.ospf_virtual_link {
        let instance = args.ospf_instance.clone().unwrap_or_default();
        let (area_id, router_id) = virtual_link_spec("--ospf-virtual-link", spec)?;
        ops.push(ConfigOp::OspfArea(OspfAreaOp::Ensure {
            instance: instance.clone(),
            area_id,
        }));
        ops.push(ConfigOp::OspfArea(OspfAreaOp::SetVirtualLink {
            instance,
            area_id,
            router_id,
        }));
    }
    if let Some(spec) = &args.ospf_clear_virtual_link {
        let (area_id, router_id) = virtual_link_spec("--ospf-clear-virtual-link", spec)?;
        ops.push(ConfigOp::OspfArea(OspfAreaOp::RemoveVirtualLink {
            instance: args.ospf_instance.clone().unwrap_or_default(),
            area_id,
            router_id,
        }));
    }

    if let Some(area_id) = args.ospf_area {
        let instance = args
            .ospf_instance
            .clone()
            .context("--ospf-area requires --ospf-instance to also be set")?;
        ops.push(ConfigOp::OspfArea(OspfAreaOp::Ensure {
            instance: instance.clone(),
            area_id,
        }));
        if let Some(area_type) = args.ospf_area_type {
            ops.push(ConfigOp::OspfArea(OspfAreaOp::SetAreaType {
                instance: instance.clone(),
                area_id,
                area_type,
            }));
        }
        if let Some(cost) = args.ospf_stub_default_cost {
            ops.push(ConfigOp::OspfArea(OspfAreaOp::SetStubDefaultCost {
                instance: instance.clone(),
                area_id,
                cost: (cost != 0).then_some(cost),
            }));
        }
        if let Some(spec) = &args.ospf_area_range {
            let (cidr, not_advertise) = match spec.strip_suffix(":not-advertise") {
                Some(cidr) => (cidr, true),
                None => (spec.as_str(), false),
            };
            ops.push(ConfigOp::OspfArea(OspfAreaOp::SetRange {
                instance: instance.clone(),
                area_id,
                cidr: cidr
                    .parse()
                    .with_context(|| format!("--ospf-area-range: bad cidr {cidr:?}"))?,
                not_advertise,
            }));
        }
        if let Some(cidr) = args.ospf_clear_area_range {
            ops.push(ConfigOp::OspfArea(OspfAreaOp::RemoveRange {
                instance: instance.clone(),
                area_id,
                cidr,
            }));
        }
        if let Some(name) = args.ospf_profile.clone() {
            ops.push(ConfigOp::OspfProfile(OspfProfileOp::Ensure {
                instance: instance.clone(),
                area_id,
                name: name.clone(),
            }));
            if let Some(mtu) = args.ospf_profile_mtu {
                ops.push(ConfigOp::OspfProfile(OspfProfileOp::SetMtu {
                    instance: instance.clone(),
                    area_id,
                    name: name.clone(),
                    mtu,
                }));
            }
            if let Some(enabled) = args.ospf_mtu_ignore {
                ops.push(ConfigOp::OspfProfile(OspfProfileOp::SetMtuIgnore {
                    instance: instance.clone(),
                    area_id,
                    name: name.clone(),
                    enabled,
                }));
            }
            if let Some(kind) = args.ospf_profile_network_type.as_deref() {
                let (instance, name) = (instance.clone(), name.clone());
                ops.push(ConfigOp::OspfProfile(match kind {
                    "clear" => OspfProfileOp::ClearNetworkType {
                        instance,
                        area_id,
                        name,
                    },
                    _ => OspfProfileOp::SetNetworkType {
                        instance,
                        area_id,
                        name,
                        network_type: match kind {
                            "point-to-point" => NetworkType::PointToPoint,
                            "broadcast" => NetworkType::Broadcast,
                            "point-to-multipoint" => NetworkType::PointToMultipoint,
                            other => bail!("--ospf-profile-network-type: unknown {other:?}"),
                        },
                    },
                }));
            }
            if let Some(hello_interval) = args.ospf_profile_hello_interval {
                ops.push(ConfigOp::OspfProfile(OspfProfileOp::SetHelloInterval {
                    instance: instance.clone(),
                    area_id,
                    name: name.clone(),
                    hello_interval,
                }));
            }
            if let Some(password) = args.ospf_simple_password.clone() {
                ops.push(ConfigOp::OspfProfile(OspfProfileOp::SetSimpleAuth {
                    instance: instance.clone(),
                    area_id,
                    name: name.clone(),
                    password,
                }));
            }
            if let Some(enabled) = args.ospf_extended_seq {
                ops.push(ConfigOp::OspfProfile(
                    OspfProfileOp::SetExtendedSequenceNumbers {
                        instance: instance.clone(),
                        area_id,
                        name: name.clone(),
                        enabled,
                    },
                ));
            }
            if let Some(spec) = args.ospf_crypto_key.clone() {
                let key = parse_ospf_crypto_key(&spec)?;
                ops.push(ConfigOp::OspfProfile(OspfProfileOp::SetCryptoKey {
                    instance,
                    area_id,
                    name,
                    key,
                }));
            }
        } else {
            if args.ospf_simple_password.is_some() {
                bail!("--ospf-simple-password requires --ospf-profile to also be set");
            }
            if args.ospf_crypto_key.is_some() {
                bail!("--ospf-crypto-key requires --ospf-profile to also be set");
            }
            if args.ospf_profile_mtu.is_some() {
                bail!("--ospf-profile-mtu requires --ospf-profile to also be set");
            }
            if args.ospf_mtu_ignore.is_some() {
                bail!("--ospf-mtu-ignore requires --ospf-profile to also be set");
            }
            if args.ospf_profile_network_type.is_some() {
                bail!("--ospf-profile-network-type requires --ospf-profile to also be set");
            }
            if args.ospf_profile_hello_interval.is_some() {
                bail!("--ospf-profile-hello-interval requires --ospf-profile to also be set");
            }
            if args.ospf_extended_seq.is_some() {
                bail!("--ospf-extended-seq requires --ospf-profile to also be set");
            }
        }
    } else if args.ospf_profile.is_some() {
        bail!("--ospf-profile requires --ospf-area to also be set");
    } else if args.ospf_simple_password.is_some() || args.ospf_crypto_key.is_some() {
        bail!("--ospf-simple-password/--ospf-crypto-key require --ospf-profile to also be set");
    } else if args.ospf_profile_mtu.is_some()
        || args.ospf_mtu_ignore.is_some()
        || args.ospf_profile_network_type.is_some()
        || args.ospf_profile_hello_interval.is_some()
        || args.ospf_extended_seq.is_some()
    {
        bail!(
            "--ospf-profile-mtu/--ospf-profile-hello-interval/--ospf-extended-seq require \
             --ospf-profile to also be set"
        );
    }

    if let Some(profile) = args.ospf_interface_profile.clone() {
        ops.push(ConfigOp::Subinterface(SubinterfaceOp::SetOspfProfile {
            interface: args.interface.clone(),
            tag: args.subinterface_tag,
            ospf_profile: profile,
        }));
    }

    if let Some(profile) = args.ospf_broadcast_domain_profile.clone() {
        ops.push(ConfigOp::BroadcastDomain(
            BroadcastDomainOp::SetOspfProfile {
                name: args.broadcast_domain.clone(),
                ospf_profile: profile,
            },
        ));
    }

    if let Some(name) = args.ospfv3_instance.clone() {
        let router_id = args
            .ospfv3_router_id
            .context("--ospfv3-router-id is required when --ospfv3-instance is set")?;
        ops.push(ConfigOp::Ospfv3Instance(Ospfv3InstanceOp::Ensure {
            name: name.clone(),
        }));
        ops.push(ConfigOp::Ospfv3Instance(Ospfv3InstanceOp::SetRouterId {
            name: name.clone(),
            router_id,
        }));
        if args.ospfv3_extended_lsa {
            ops.push(ConfigOp::Ospfv3Instance(Ospfv3InstanceOp::SetExtendedLsa {
                name: name.clone(),
                enabled: true,
            }));
        }
        if let Some(grace_period) = args.ospfv3_graceful_restart_grace_period {
            ops.push(ConfigOp::Ospfv3Instance(
                Ospfv3InstanceOp::SetGracefulRestartGracePeriod {
                    name: name.clone(),
                    grace_period: Some(grace_period),
                },
            ));
        }
        ops.push(ConfigOp::RoutingTable(RoutingTableOp::SetOspfv3Instance {
            name: args.routing_table.clone(),
            ospfv3_instance: name,
        }));
    } else if args.ospfv3_router_id.is_some() {
        bail!("--ospfv3-router-id requires --ospfv3-instance to also be set");
    }

    if let Some(area_id) = args.ospfv3_area {
        let instance = args
            .ospfv3_instance
            .clone()
            .context("--ospfv3-area requires --ospfv3-instance to also be set")?;
        ops.push(ConfigOp::Ospfv3Area(Ospfv3AreaOp::Ensure {
            instance: instance.clone(),
            area_id,
        }));
        if let Some(name) = args.ospfv3_profile.clone() {
            ops.push(ConfigOp::Ospfv3Profile(Ospfv3ProfileOp::Ensure {
                instance: instance.clone(),
                area_id,
                name: name.clone(),
            }));
            if let Some(mtu) = args.ospfv3_profile_mtu {
                ops.push(ConfigOp::Ospfv3Profile(Ospfv3ProfileOp::SetMtu {
                    instance: instance.clone(),
                    area_id,
                    name: name.clone(),
                    mtu,
                }));
            }
            if let Some(enabled) = args.ospfv3_mtu_ignore {
                ops.push(ConfigOp::Ospfv3Profile(Ospfv3ProfileOp::SetMtuIgnore {
                    instance: instance.clone(),
                    area_id,
                    name: name.clone(),
                    enabled,
                }));
            }
            if let Some(id) = args.ospfv3_instance_id {
                ops.push(ConfigOp::Ospfv3Profile(Ospfv3ProfileOp::SetInstanceId {
                    instance: instance.clone(),
                    area_id,
                    name: name.clone(),
                    instance_id: (id != 0).then_some(id),
                }));
            }
            if let Some(spec) = args.ospfv3_crypto_key.clone() {
                let key = parse_ospf_crypto_key(&spec)?;
                if key.algorithm == OspfCryptoAlgorithm::Md5 {
                    bail!("--ospfv3-crypto-key: RFC 7166 has no md5, use an hmac-sha algorithm");
                }
                ops.push(ConfigOp::Ospfv3Profile(Ospfv3ProfileOp::SetCryptoKey {
                    instance,
                    area_id,
                    name,
                    key,
                }));
            }
        } else if args.ospfv3_profile_mtu.is_some()
            || args.ospfv3_mtu_ignore.is_some()
            || args.ospfv3_crypto_key.is_some()
            || args.ospfv3_instance_id.is_some()
        {
            bail!(
                "--ospfv3-profile-mtu/--ospfv3-mtu-ignore/--ospfv3-crypto-key/--ospfv3-instance-id require --ospfv3-profile to also be set"
            );
        }
    } else if args.ospfv3_profile.is_some() {
        bail!("--ospfv3-profile requires --ospfv3-area to also be set");
    }

    if args.bfd_unsolicited {
        ops.push(ConfigOp::Subinterface(SubinterfaceOp::SetBfdUnsolicited {
            interface: args.interface.clone(),
            tag: args.subinterface_tag,
            bfd_unsolicited: BFD_PROFILE.to_string(),
        }));
    }
    if args.no_bfd_unsolicited {
        ops.push(ConfigOp::Subinterface(
            SubinterfaceOp::ClearBfdUnsolicited {
                interface: args.interface.clone(),
                tag: args.subinterface_tag,
            },
        ));
    }

    if let Some(profile) = args.ospfv3_interface_profile.clone() {
        ops.push(ConfigOp::Subinterface(SubinterfaceOp::SetOspfv3Profile {
            interface: args.interface.clone(),
            tag: args.subinterface_tag,
            ospfv3_profile: profile,
        }));
    }

    if let Some(profile) = args.ospfv3_broadcast_domain_profile.clone() {
        ops.push(ConfigOp::BroadcastDomain(
            BroadcastDomainOp::SetOspfv3Profile {
                name: args.broadcast_domain.clone(),
                ospfv3_profile: profile,
            },
        ));
    }
    if args.clear_ospfv3_broadcast_domain_profile {
        ops.push(ConfigOp::BroadcastDomain(
            BroadcastDomainOp::ClearOspfv3Profile {
                name: args.broadcast_domain.clone(),
            },
        ));
    }
    Ok(ops)
}

/// Parses `--ospf-crypto-key`/`--ospfv3-crypto-key`'s `<key-id>:<algorithm>:
/// <key>` shape into a single `OspfCryptoKey`, always marked current — this
/// tool only ever provisions one active key at a time (rotation isn't part
/// of the e2e scenario these flags exist for). `<key-id>` is 0-65535; a
/// classic `OSPFv2` key above 255 is refused at commit, not here.
fn parse_ospf_crypto_key(spec: &str) -> anyhow::Result<OspfCryptoKey> {
    let mut parts = spec.splitn(3, ':');
    let (Some(key_id), Some(algorithm), Some(key)) = (parts.next(), parts.next(), parts.next())
    else {
        bail!("--ospf-crypto-key must be <key-id>:<algorithm>:<key>, got '{spec}'");
    };
    let key_id = key_id
        .parse::<u16>()
        .with_context(|| format!("invalid --ospf-crypto-key key-id in '{spec}'"))?;
    let algorithm = match algorithm {
        "md5" => OspfCryptoAlgorithm::Md5,
        "hmac-sha1" => OspfCryptoAlgorithm::HmacSha1,
        "hmac-sha256" => OspfCryptoAlgorithm::HmacSha256,
        "hmac-sha384" => OspfCryptoAlgorithm::HmacSha384,
        "hmac-sha512" => OspfCryptoAlgorithm::HmacSha512,
        other => bail!("unknown --ospf-crypto-key algorithm '{other}' in '{spec}'"),
    };
    Ok(OspfCryptoKey {
        key_id,
        algorithm,
        key: key.to_string(),
        is_current: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `build_ops` over the required base flags plus `extra`.
    fn ops(extra: &[&str]) -> anyhow::Result<Vec<ConfigOp>> {
        let base = [
            "nos-provision",
            "--address",
            "10.0.0.1/24",
            "--asn",
            "65001",
            "--router-id",
            "1.1.1.1",
            "--remote-as",
            "65002",
            "--peer",
            "10.0.0.2",
        ];
        build_ops(&Args::try_parse_from(base.iter().chain(extra))?)
    }

    fn err(extra: &[&str]) -> String {
        format!("{:#}", ops(extra).unwrap_err())
    }

    fn has(ops: &[ConfigOp], op: &ConfigOp) {
        assert!(ops.contains(op), "{op:?} missing from {ops:#?}");
    }

    #[test]
    fn base_router() {
        let ops = ops(&[]).unwrap();
        assert_eq!(ops.len(), 14);
        has(
            &ops,
            &ConfigOp::BgpPeer(BgpPeerOp::Set {
                instance: "r1".into(),
                remote_address: "10.0.0.2".parse().unwrap(),
                peer_group: "pg1".into(),
            }),
        );
        has(
            &ops,
            &ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetImportPolicy {
                instance: "r1".into(),
                name: "pg1".into(),
                import_policy: "accept-all".into(),
            }),
        );
    }

    #[test]
    fn ospf_area_stub_and_range_flags() {
        let ops = ops(&[
            "--ospf-instance",
            "o",
            "--ospf-router-id",
            "1.1.1.1",
            "--ospf-area",
            "0.0.0.1",
            "--ospf-area-type",
            "totally-stubby",
            "--ospf-stub-default-cost",
            "0",
            "--ospf-area-range",
            "10.1.0.0/16:not-advertise",
            "--ospf-clear-area-range",
            "10.2.0.0/16",
        ])
        .unwrap();
        let (instance, area_id) = (String::from("o"), "0.0.0.1".parse().unwrap());
        has(
            &ops,
            &ConfigOp::OspfArea(OspfAreaOp::SetAreaType {
                instance: instance.clone(),
                area_id,
                area_type: OspfAreaType::TotallyStubby,
            }),
        );
        has(
            &ops,
            &ConfigOp::OspfArea(OspfAreaOp::SetStubDefaultCost {
                instance: instance.clone(),
                area_id,
                cost: None,
            }),
        );
        has(
            &ops,
            &ConfigOp::OspfArea(OspfAreaOp::SetRange {
                instance: instance.clone(),
                area_id,
                cidr: "10.1.0.0/16".parse().unwrap(),
                not_advertise: true,
            }),
        );
        has(
            &ops,
            &ConfigOp::OspfArea(OspfAreaOp::RemoveRange {
                instance,
                area_id,
                cidr: "10.2.0.0/16".parse().unwrap(),
            }),
        );
        assert!(err(&["--ospf-area-type", "stub"]).contains("--ospf-area"));
    }

    #[test]
    fn ospf_virtual_link_flag() {
        let set = ops(&[
            "--ospf-instance",
            "o",
            "--ospf-router-id",
            "1.1.1.1",
            "--ospf-virtual-link",
            "0.0.0.1:2.2.2.2",
        ])
        .unwrap();
        has(
            &set,
            &ConfigOp::OspfArea(OspfAreaOp::SetVirtualLink {
                instance: "o".into(),
                area_id: "0.0.0.1".parse().unwrap(),
                router_id: "2.2.2.2".parse().unwrap(),
            }),
        );
        assert!(err(&["--ospf-virtual-link", "0.0.0.1:2.2.2.2"]).contains("ospf-instance"));
        let cleared = ops(&[
            "--ospf-instance",
            "o",
            "--ospf-router-id",
            "1.1.1.1",
            "--ospf-clear-virtual-link",
            "0.0.0.1:2.2.2.2",
        ])
        .unwrap();
        has(
            &cleared,
            &ConfigOp::OspfArea(OspfAreaOp::RemoveVirtualLink {
                instance: "o".into(),
                area_id: "0.0.0.1".parse().unwrap(),
                router_id: "2.2.2.2".parse().unwrap(),
            }),
        );
    }

    #[test]
    fn every_bgp_flag() {
        let ops = ops(&[
            "--mtu",
            "9000",
            "--address6",
            "2001:db8::1/64",
            "--address6-label",
            "v6",
            "--static-route",
            "192.0.2.0/24",
            "--static-gateway",
            "10.0.0.254",
            "--redistribute",
            "--redistribute-policy",
            "p",
            "--md5-password",
            "s",
            "--ao-send-id",
            "1",
            "--ao-key-secret",
            "k",
            "--ao-algorithm",
            "aes-cmac",
            "--ao-current",
            "--ao-rnext",
            "--ao-exclude-options",
            "--ao-promote-current",
            "2",
            "--ao-remove-key",
            "3",
            "--evpn",
            "--route-reflector-client",
            "--route-server-client",
            "--cluster-id",
            "9.9.9.9",
            "--connect-retry-time",
            "3",
            "--mrai",
            "30",
            "--route-refresh-stale-time",
            "5",
            "--max-hops",
            "1",
            "--shutdown-peer-group",
            "",
            "--unshutdown-peer-group",
            "--shutdown-peer",
            "bye",
            "--unshutdown-peer",
            "--damping-half-life",
            "20",
            "--clear-damping",
            "--local-as",
            "65009",
            "--local-as-replace-as",
            "--add-path",
            "receive",
            "--add-path-send-count",
            "3",
            "--maximum-prefix",
            "ipv4=2",
            "--maximum-prefix-warning-only",
            "--maximum-prefix-restart-interval",
            "5",
            "--clear-maximum-prefix",
            "l2vpn-evpn",
            "--source-address-interface",
            "eth1",
            "--source-address-label",
            "l",
            "--rest-api-address",
            "10.0.0.1",
            "--hostname",
            "h",
            "--user",
            "e2e=a=b",
        ])
        .unwrap();
        let pg = ConfigOp::BgpPeerGroup;
        has(
            &ops,
            &pg(BgpPeerGroupOp::SetAoKey {
                instance: "r1".into(),
                name: "pg1".into(),
                key: BgpAoKey {
                    send_id: 1,
                    recv_id: 1,
                    algorithm: BgpAoAlgorithm::AesCmac96,
                    key: "k".into(),
                    is_current: true,
                    is_rnext: true,
                    exclude_options: true,
                },
            }),
        );
        has(
            &ops,
            &pg(BgpPeerGroupOp::SetShutdown {
                instance: "r1".into(),
                name: "pg1".into(),
                message: None,
            }),
        );
        has(
            &ops,
            &ConfigOp::BgpPeer(BgpPeerOp::SetShutdown {
                instance: "r1".into(),
                remote_address: "10.0.0.2".parse().unwrap(),
                message: Some("bye".into()),
            }),
        );
        has(
            &ops,
            &pg(BgpPeerGroupOp::SetDamping {
                instance: "r1".into(),
                name: "pg1".into(),
                damping: nos_proto::BgpDamping {
                    half_life: 20,
                    ..Default::default()
                },
            }),
        );
        has(
            &ops,
            &pg(BgpPeerGroupOp::SetLocalAs {
                instance: "r1".into(),
                name: "pg1".into(),
                local_as: nos_proto::BgpLocalAs {
                    asn: 65009,
                    no_prepend: false,
                    replace_as: true,
                },
            }),
        );
        has(
            &ops,
            &pg(BgpPeerGroupOp::SetAddPath {
                instance: "r1".into(),
                name: "pg1".into(),
                mode: nos_proto::BgpAddPath::Receive,
            }),
        );
        has(
            &ops,
            &pg(BgpPeerGroupOp::SetAddPathSendCount {
                instance: "r1".into(),
                name: "pg1".into(),
                count: 3,
            }),
        );
        has(
            &ops,
            &pg(BgpPeerGroupOp::SetMaximumPrefix {
                instance: "r1".into(),
                name: "pg1".into(),
                family: AddressFamily::Ipv4Unicast,
                limit: nos_proto::BgpPrefixLimit {
                    limit: 2,
                    warning_only: true,
                    restart_interval: 5,
                },
            }),
        );
        has(
            &ops,
            &pg(BgpPeerGroupOp::ClearMaximumPrefix {
                instance: "r1".into(),
                name: "pg1".into(),
                family: AddressFamily::L2vpnEvpn,
            }),
        );
        has(
            &ops,
            &ConfigOp::User(UserOp::SetPassword {
                name: "e2e".into(),
                password: "a=b".into(),
            }),
        );
        has(
            &ops,
            &ConfigOp::RoutingTable(RoutingTableOp::SetRestApi {
                name: "rt1".into(),
                address: "10.0.0.1".parse().unwrap(),
                port: nos_proto::REST_API_PORT_DEFAULT,
            }),
        );
    }

    #[test]
    fn every_interface_and_l2_flag() {
        let ops = ops(&[
            "--loopback-address",
            "192.0.2.1/32",
            "--loopback-remove-address",
            "192.0.2.2/32",
            "--ospf-loopback-profile",
            "p",
            "--ospfv3-loopback-address",
            "2001:db8::1/128",
            "--ospfv3-loopback-profile",
            "p6",
            "--broadcast-domain-svi-address",
            "10.1.0.1/24",
            "--ospfv3-broadcast-domain-svi-address",
            "2001:db8:1::1/64",
            "--evpn-vni",
            "100",
            "--evpn-rd",
            "65001:1",
            "--evpn-rt-import",
            "65001:1",
            "--evpn-rt-export",
            "65001:2",
            "--evpn-vtep-source-interface",
            "lo",
            "--evpn-redistribute-bgp",
            "r1",
            "--evpn-redistribute-arp-bgp",
            "r1",
            "--evpn-redistribute-connected-bgp",
            "r1",
            "--evpn-neigh-suppress",
            "true",
            "--switching-profile",
            "sp",
            "--switching-profile-member",
            "bd1:untagged",
            "--switching-profile-member",
            "bd2:20",
            "--port-aggregate",
            "bond0",
            "--port-aggregate-mode",
            "lacp",
            "--lacp-rate",
            "fast",
            "--port-aggregate-mtu",
            "9000",
            "--port-aggregate-esi",
            "00:11:22:33:44:55:66:77:88:99",
            "--delete-port-aggregate-esi",
            "--port-aggregate-redundancy-mode",
            "single-active",
            "--lacp-system-id",
            "02:00:00:00:00:01",
            "--lacp-system-priority",
            "100",
            "--min-links",
            "2",
            "--port-aggregate-bfd",
            "fast",
            "--port-aggregate-bfd-peer",
            "10.0.0.2",
            "--lacp-port-priority",
            "200",
            "--lacp-mode",
            "passive",
            "--port-aggregate-untagged-domain",
            "bd1",
            "--enslave-interface-into-port-aggregate",
            "eth1",
            "--clear-port-aggregate-member",
            "eth3",
            "--lldp-transmit-interface",
            "eth1",
            "--lldp-receive-interface",
            "eth1",
            "--no-lldp-transmit-interface",
            "eth2",
            "--no-lldp-receive-interface",
            "eth2",
            "--lldp-tx-interval",
            "5",
            "--lldp-tx-hold",
            "3",
            "--lldp-management-address",
            "10.0.0.1",
            "--lldp-management-address",
            "10.0.0.2",
            "--no-lldp-management-address",
            "10.0.0.3",
            "--lldp-destination-interface",
            "eth1=customer-bridge",
            "--syslog-server",
            "c1",
            "--syslog-address",
            "192.0.2.9",
            "--syslog-transport",
            "tcp",
            "--syslog-facility",
            "local3",
            "--syslog-level",
            "debug",
            "--no-syslog-server",
            "old",
        ])
        .unwrap();
        has(
            &ops,
            &ConfigOp::Logging(LoggingOp::SetSyslogFacility {
                name: "c1".into(),
                facility: Some(SyslogFacility::Local3),
            }),
        );
        has(
            &ops,
            &ConfigOp::Logging(LoggingOp::SetSyslogTransport {
                name: "c1".into(),
                transport: SyslogTransport::Tcp,
            }),
        );
        has(
            &ops,
            &ConfigOp::Logging(LoggingOp::RemoveSyslog { name: "old".into() }),
        );
        has(
            &ops,
            &ConfigOp::SwitchingProfile(SwitchingProfileOp::AddMember {
                name: "sp".into(),
                broadcast_domain: "bd2".into(),
                tag: VlanTag::Dot1q(20),
            }),
        );
        has(
            &ops,
            &ConfigOp::PortAggregate(PortAggregateOp::SetLacpSystemPriority {
                name: "bond0".into(),
                priority: 100,
            }),
        );
        has(
            &ops,
            &ConfigOp::PortAggregate(PortAggregateOp::SetMinLinks {
                name: "bond0".into(),
                min_links: 2,
            }),
        );
        has(
            &ops,
            &ConfigOp::PortAggregate(PortAggregateOp::SetBfd {
                name: "bond0".into(),
                profile: "fast".into(),
            }),
        );
        has(
            &ops,
            &ConfigOp::PortAggregate(PortAggregateOp::SetBfdPeer {
                name: "bond0".into(),
                peer: "10.0.0.2".parse().unwrap(),
            }),
        );
        has(
            &ops,
            &ConfigOp::Interface(InterfaceOp::SetLacpPortPriority {
                name: "eth1".into(),
                priority: 200,
            }),
        );
        has(
            &ops,
            &ConfigOp::Interface(InterfaceOp::SetLacpMode {
                name: "eth1".into(),
                mode: nos_proto::LacpMode::Passive,
            }),
        );
        has(
            &ops,
            &ConfigOp::PortAggregate(PortAggregateOp::SetSwitchingProfile {
                name: "bond0".into(),
                switching_profile: "bond0-sp".into(),
            }),
        );
        has(
            &ops,
            &ConfigOp::Interface(InterfaceOp::SetLldpReceive {
                name: "eth2".into(),
                enabled: false,
            }),
        );
        has(
            &ops,
            &ConfigOp::Interface(InterfaceOp::SetLldpDestination {
                name: "eth1".into(),
                destination: LldpDestination::CustomerBridge,
            }),
        );
        has(
            &ops,
            &ConfigOp::Lldp(LldpOp::AddManagementAddress {
                address: "10.0.0.2".parse().unwrap(),
            }),
        );
        has(
            &ops,
            &ConfigOp::Lldp(LldpOp::RemoveManagementAddress {
                address: "10.0.0.3".parse().unwrap(),
            }),
        );
        has(
            &ops,
            &ConfigOp::BroadcastDomain(BroadcastDomainOp::AddRouteTarget {
                name: "bd-svi".into(),
                import: false,
                route_target: "65001:2".into(),
            }),
        );
        has(
            &ops,
            &ConfigOp::BroadcastDomain(BroadcastDomainOp::SetNeighSuppress {
                name: "bd-svi".into(),
                enabled: true,
            }),
        );
    }

    #[test]
    fn every_ospf_flag() {
        let ops = ops(&[
            "--static-route",
            "192.0.2.0/24",
            "--static-gateway",
            "10.0.0.254",
            "--redistribute-to-ospf",
            "--ospf-instance",
            "o1",
            "--ospf-router-id",
            "1.1.1.1",
            "--ospf-area",
            "0.0.0.0",
            "--ospf-profile",
            "p",
            "--ospf-profile-mtu",
            "68",
            "--ospf-profile-hello-interval",
            "2",
            "--ospf-simple-password",
            "pw",
            "--ospf-extended-seq",
            "true",
            "--ospf-crypto-key",
            "1:hmac-sha256:k",
            "--ospf-interface-profile",
            "p",
            "--ospf-broadcast-domain-profile",
            "p",
            "--ospfv3-instance",
            "o3",
            "--ospfv3-router-id",
            "1.1.1.1",
            "--ospfv3-extended-lsa",
            "--ospfv3-graceful-restart-grace-period",
            "120",
            "--ospfv3-area",
            "0.0.0.0",
            "--ospfv3-profile",
            "p6",
            "--ospfv3-profile-mtu",
            "1280",
            "--ospfv3-instance-id",
            "7",
            "--ospfv3-crypto-key",
            "300:hmac-sha512:k",
            "--ospfv3-interface-profile",
            "p6",
            "--ospfv3-broadcast-domain-profile",
            "p6",
        ])
        .unwrap();
        has(
            &ops,
            &ConfigOp::Ospfv3Profile(Ospfv3ProfileOp::SetCryptoKey {
                instance: "o3".into(),
                area_id: Ipv4Addr::UNSPECIFIED,
                name: "p6".into(),
                key: OspfCryptoKey {
                    key_id: 300,
                    algorithm: OspfCryptoAlgorithm::HmacSha512,
                    key: "k".into(),
                    is_current: true,
                },
            }),
        );
        has(
            &ops,
            &ConfigOp::Ospfv3Profile(Ospfv3ProfileOp::SetInstanceId {
                instance: "o3".into(),
                area_id: Ipv4Addr::UNSPECIFIED,
                name: "p6".into(),
                instance_id: Some(7),
            }),
        );
        has(
            &ops,
            &ConfigOp::RoutingTable(RoutingTableOp::SetRedistribute {
                name: "rt1".into(),
                redistribute: Redistribute {
                    from: RedistributeSource::Static,
                    to: RedistributeTarget::Ospf,
                    policy: None,
                    metric: None,
                    metric_type: None,
                },
            }),
        );
    }

    #[test]
    fn redistribute_to_ospfv3_flags() {
        let base = [
            "--static-route",
            "2001:db8:77::/48",
            "--static-gateway",
            "2001:db8::1",
            "--ospfv3-instance",
            "o3",
            "--ospfv3-router-id",
            "1.1.1.1",
        ];
        let set = ops(&[
            &base[..],
            &["--redistribute-to-ospfv3-policy", "p"],
            &["--redistribute-to-ospfv3"],
        ]
        .concat())
        .unwrap();
        has(
            &set,
            &ConfigOp::RoutingTable(RoutingTableOp::SetRedistribute {
                name: "rt1".into(),
                redistribute: Redistribute {
                    from: RedistributeSource::Static,
                    to: RedistributeTarget::Ospfv3,
                    policy: Some("p".into()),
                    metric: None,
                    metric_type: None,
                },
            }),
        );
        has(
            &ops(&["--clear-redistribute-to-ospfv3"]).unwrap(),
            &ConfigOp::RoutingTable(RoutingTableOp::ClearRedistribute {
                name: "rt1".into(),
                to: RedistributeTarget::Ospfv3,
            }),
        );
        assert!(err(&["--redistribute-to-ospfv3"]).contains("--static-route"));
        assert!(err(&[
            "--static-route",
            "2001:db8:77::/48",
            "--static-gateway",
            "2001:db8::1",
            "--redistribute-to-ospfv3"
        ])
        .contains("--ospfv3-instance"));
    }

    #[test]
    fn clearing_and_deleting_flags() {
        let all = ops(&[
            "--delete-subinterface",
            "--clear-redistribute-to-ospf",
            "--delete-loopback",
            "--clear-ospf-loopback-profile",
            "--clear-ospfv3-loopback-profile",
            "--clear-ospfv3-broadcast-domain-profile",
            "--delete-broadcast-domain-svi",
            "--evpn-clear",
            "--evpn-rt-import",
            "65001:1",
            "--source-address-loopback",
            "--delete-switching-profile",
            "--port-aggregate",
            "bond0",
            "--delete-port-aggregate",
            "--enslave-interface-into-port-aggregate",
            "eth1",
            "--clear-rest-api",
        ])
        .unwrap();
        has(
            &all,
            &ConfigOp::Interface(InterfaceOp::ClearPortAggregate {
                name: "eth1".into(),
            }),
        );
        has(
            &all,
            &ConfigOp::BroadcastDomain(BroadcastDomainOp::ClearVni {
                name: "bd-svi".into(),
            }),
        );
        has(
            &all,
            &ConfigOp::BroadcastDomain(BroadcastDomainOp::SetNeighSuppress {
                name: "bd-svi".into(),
                enabled: false,
            }),
        );
        has(
            &all,
            &ConfigOp::BroadcastDomain(BroadcastDomainOp::ClearOspfv3Profile {
                name: "bd-svi".into(),
            }),
        );
        assert!(!all
            .iter()
            .any(|o| matches!(o, ConfigOp::Subinterface(SubinterfaceOp::AddAddress { .. }))));
        let clear = ops(&["--clear-source-address", "--evpn-vtep-source-loopback"]).unwrap();
        has(
            &clear,
            &ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearSourceAddress {
                instance: "r1".into(),
                name: "pg1".into(),
            }),
        );
    }

    #[test]
    fn policy_file() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "accept\n").unwrap();
        let result = ops(&[
            "--policy-name",
            "p",
            "--policy-source-file",
            file.path().to_str().unwrap(),
        ]);
        has(
            &result.unwrap(),
            &ConfigOp::PolicyDefinition(PolicyDefinitionOp::SetSource {
                name: "p".into(),
                source: "accept\n".into(),
            }),
        );
    }

    #[test]
    fn static_route_can_be_repeated() {
        let result = ops(&[
            "--static-route",
            "192.0.2.128/25",
            "--static-route",
            "192.0.2.128/26",
            "--static-gateway",
            "10.0.0.9",
        ])
        .unwrap();
        for subnet in ["192.0.2.128/25", "192.0.2.128/26"] {
            has(
                &result,
                &ConfigOp::StaticRoute(StaticRouteOp::Set {
                    instance: "sri1".into(),
                    subnet: subnet.parse().unwrap(),
                    gateway: "10.0.0.9".parse().unwrap(),
                }),
            );
        }
    }

    #[test]
    fn inconsistent_flags_are_refused() {
        let static_route = [
            "--static-route",
            "192.0.2.0/24",
            "--static-gateway",
            "10.0.0.9",
        ];
        for (flags, needle) in [
            (&["--static-route", "192.0.2.0/24"][..], "--static-gateway"),
            (&["--redistribute"], "require --static-route"),
            (
                &[&static_route[..], &["--redistribute-to-ospf"]].concat(),
                "requires --ospf-instance",
            ),
            (
                &[
                    &static_route[..],
                    &[
                        "--ospf-instance",
                        "o1",
                        "--redistribute-to-ospf",
                        "--clear-redistribute-to-ospf",
                    ],
                ]
                .concat(),
                "mutually exclusive",
            ),
            (&["--policy-name", "p"], "--policy-source-file is required"),
            (&["--policy-source-file", "/x"], "requires --policy-name"),
            (
                &[
                    "--policy-name",
                    "p",
                    "--policy-source-file",
                    "/nonexistent/x",
                ],
                "reading",
            ),
            (
                &["--loopback-address", "192.0.2.1/32", "--delete-loopback"],
                "mutually exclusive",
            ),
            (
                &[
                    "--ospf-loopback-profile",
                    "p",
                    "--clear-ospf-loopback-profile",
                ],
                "mutually exclusive",
            ),
            (
                &[
                    "--ospfv3-loopback-profile",
                    "p",
                    "--clear-ospfv3-loopback-profile",
                ],
                "mutually exclusive",
            ),
            (
                &[
                    "--broadcast-domain-svi-address",
                    "10.1.0.1/24",
                    "--delete-broadcast-domain-svi",
                ],
                "mutually exclusive",
            ),
            (&["--evpn-clear", "--evpn-vni", "1"], "mutually exclusive"),
            (
                &[
                    "--evpn-vtep-source-interface",
                    "lo",
                    "--evpn-vtep-source-loopback",
                ],
                "mutually exclusive",
            ),
            (
                &["--source-address-loopback", "--clear-source-address"],
                "mutually exclusive",
            ),
            (
                &["--switching-profile", "sp", "--delete-switching-profile"],
                "mutually exclusive",
            ),
            (
                &[
                    "--switching-profile",
                    "sp",
                    "--switching-profile-member",
                    "bd1",
                ],
                "DOMAIN:TAG",
            ),
            (
                &[
                    "--switching-profile",
                    "sp",
                    "--switching-profile-member",
                    "bd1:x",
                ],
                "invalid vlan tag",
            ),
            (
                &["--switching-profile-member", "bd1:1"],
                "requires --switching-profile",
            ),
            (&["--delete-port-aggregate"], "requires --port-aggregate"),
            (&["--lacp-rate", "slow"], "require --port-aggregate"),
            (&["--lacp-system-priority", "1"], "require --port-aggregate"),
            (&["--min-links", "2"], "require --port-aggregate"),
            (&["--lacp-port-priority", "1"], "require --port-aggregate"),
            (&["--lacp-mode", "passive"], "require --port-aggregate"),
            (
                &["--lldp-destination-interface", "eth1"],
                "<interface>=<group>",
            ),
            (
                &["--lldp-destination-interface", "eth1=nope"],
                "unknown lldp destination",
            ),
            (
                &["--rest-api-address", "10.0.0.1", "--clear-rest-api"],
                "mutually exclusive",
            ),
            (&["--ospf-instance", "o"], "--ospf-router-id is required"),
            (&["--ospf-router-id", "1.1.1.1"], "requires --ospf-instance"),
            (&["--ospf-area", "0.0.0.0"], "requires --ospf-instance"),
            (&["--ospf-profile", "p"], "requires --ospf-area"),
            (&["--ospf-simple-password", "x"], "require --ospf-profile"),
            (&["--ospf-profile-mtu", "68"], "require --ospf-profile"),
            (
                &["--ospfv3-instance", "o"],
                "--ospfv3-router-id is required",
            ),
            (
                &["--ospfv3-router-id", "1.1.1.1"],
                "requires --ospfv3-instance",
            ),
            (&["--ospfv3-area", "0.0.0.0"], "requires --ospfv3-instance"),
            (&["--ospfv3-profile", "p"], "requires --ospfv3-area"),
        ] {
            let e = err(flags);
            assert!(e.contains(needle), "{flags:?}: {e}");
        }
        let ospf = [
            "--ospf-instance",
            "o",
            "--ospf-router-id",
            "1.1.1.1",
            "--ospf-area",
            "0.0.0.0",
        ];
        for flag in [
            ["--ospf-simple-password", "x"],
            ["--ospf-crypto-key", "1:md5:k"],
            ["--ospf-profile-mtu", "68"],
            ["--ospf-profile-hello-interval", "2"],
            ["--ospf-extended-seq", "true"],
        ] {
            let e = err(&[&ospf[..], &flag].concat());
            assert!(e.contains("requires --ospf-profile"), "{flag:?}: {e}");
        }
        let ospfv3 = [
            "--ospfv3-instance",
            "o",
            "--ospfv3-router-id",
            "1.1.1.1",
            "--ospfv3-area",
            "0.0.0.0",
        ];
        let e = err(&[&ospfv3[..], &["--ospfv3-profile-mtu", "1280"]].concat());
        assert!(e.contains("require --ospfv3-profile"), "{e}");
        let e = err(&[
            &ospfv3[..],
            &["--ospfv3-profile", "p", "--ospfv3-crypto-key", "1:md5:k"],
        ]
        .concat());
        assert!(e.contains("no md5"), "{e}");
    }

    #[test]
    fn crypto_key_parsing() {
        for (alg, want) in [
            ("md5", OspfCryptoAlgorithm::Md5),
            ("hmac-sha1", OspfCryptoAlgorithm::HmacSha1),
            ("hmac-sha256", OspfCryptoAlgorithm::HmacSha256),
            ("hmac-sha384", OspfCryptoAlgorithm::HmacSha384),
            ("hmac-sha512", OspfCryptoAlgorithm::HmacSha512),
        ] {
            let key = parse_ospf_crypto_key(&format!("7:{alg}:a:b")).unwrap();
            assert_eq!(
                (key.key_id, key.algorithm, key.key.as_str()),
                (7, want, "a:b")
            );
        }
        for bad in ["1:md5", "x:md5:k", "1:sha3:k"] {
            assert!(parse_ospf_crypto_key(bad).is_err(), "{bad}");
        }
        assert!(parse_user("nopassword").is_err());
    }

    #[test]
    fn bfd_auth_flag_becomes_a_json_path_edit() {
        let a = parse_bfd_auth("meticulous-sha1:2:s3:cret").unwrap();
        assert_eq!((a.key_id, a.key.as_str()), (2, "s3:cret"));
        assert!(parse_bfd_auth("nope:1:k").is_err());
        assert!(parse_bfd_auth("keyed-md5:300:k").is_err());
        let args = Args::try_parse_from([
            "nos-provision",
            "--address",
            "10.0.0.1/24",
            "--asn",
            "1",
            "--router-id",
            "1.1.1.1",
            "--remote-as",
            "2",
            "--peer",
            "10.0.0.2",
            "--bfd-auth",
            "keyed-md5:1:k",
        ])
        .unwrap();
        let (path, value) = bfd_paths(&args).pop().unwrap();
        assert_eq!(path, ["bfd-profile", "fast", "auth"]);
        assert_eq!(
            value.as_deref(),
            Some(r#"{"key_id":1,"method":"KeyedMd5","key":"k"}"#)
        );
    }

    #[test]
    fn sbfd_flags_become_profile_route_and_reflector_edits() {
        let args = Args::try_parse_from([
            "nos-provision",
            "--address",
            "10.0.0.1/24",
            "--asn",
            "1",
            "--router-id",
            "1.1.1.1",
            "--remote-as",
            "2",
            "--peer",
            "10.0.0.2",
            "--static-route",
            "198.51.100.0/24",
            "--static-gateway",
            "10.0.0.2",
            "--sbfd-static-route",
            "198.51.100.0/24",
            "--sbfd-remote-discriminator",
            "10.77.0.1",
            "--sbfd-reflector",
            "10.0.0.1",
            "--sbfd-reflector",
            "10.77.0.1",
        ])
        .unwrap();
        let edits = bfd_paths(&args);
        let get = |p: &[&str]| {
            edits
                .iter()
                .find(|(path, _)| path == p)
                .and_then(|(_, v)| v.clone())
        };
        assert_eq!(
            get(&["bfd-profile", "sb", "mode"]).as_deref(),
            Some("\"Sbfd\"")
        );
        assert_eq!(
            get(&["bfd-profile", "sb", "sbfd-remote-discriminator"]).as_deref(),
            Some("\"10.77.0.1\"")
        );
        assert_eq!(
            get(&[
                "static-routing-instance",
                &args.static_routing_instance,
                "route",
                "198.51.100.0/24",
                "bfd"
            ])
            .as_deref(),
            Some("\"sb\"")
        );
        assert_eq!(
            get(&["sbfd-reflector", "discriminator"]).as_deref(),
            Some(r#"["10.0.0.1","10.77.0.1"]"#)
        );
        assert!(build_ops(&args)
            .unwrap()
            .contains(&ConfigOp::BfdProfile(BfdProfileOp::Ensure {
                name: "sb".into()
            })));

        // The same flags applied straight to a local Config (the e2e seed).
        let mut cfg = nos_proto::Config::default();
        for op in build_ops(&args).unwrap() {
            op.apply(&mut cfg).unwrap();
        }
        apply_bfd(&args, &mut cfg);
        let sb = cfg.bfd_profiles.iter().find(|p| p.name == "sb").unwrap();
        assert_eq!(sb.mode, nos_proto::schema::BfdMode::Sbfd);
        assert_eq!(
            sb.sbfd_remote_discriminator,
            Some("10.77.0.1".parse().unwrap())
        );
        assert_eq!(cfg.sbfd_reflector.discriminators.len(), 2);
        assert_eq!(
            cfg.static_routing_instances[0].routes[0].bfd.as_deref(),
            Some("sb")
        );
    }

    #[test]
    fn esi_aggregate_gets_the_stp_guard_profile() {
        let args = Args::try_parse_from([
            "nos-provision",
            "--address",
            "10.0.0.1/24",
            "--asn",
            "1",
            "--router-id",
            "1.1.1.1",
            "--remote-as",
            "2",
            "--peer",
            "10.0.0.2",
            "--port-aggregate",
            "bond1",
            "--port-aggregate-esi",
            "00:11:22:33:44:55:66:77:88:99",
        ])
        .unwrap();
        let edits = bfd_paths(&args);
        let get = |p: &[&str]| {
            edits
                .iter()
                .find(|(path, _)| path == p)
                .and_then(|(_, v)| v.clone())
        };
        assert_eq!(
            get(&["stp-port-profile", "esi-guard", "edge-port"]).as_deref(),
            Some("\"Admin\"")
        );
        assert_eq!(
            get(&["stp-port-profile", "esi-guard", "bpdu-guard"]).as_deref(),
            Some("true")
        );
        assert_eq!(
            get(&["port-aggregate", "bond1", "stp-port-profile"]).as_deref(),
            Some("\"esi-guard\"")
        );
        // Applied to a local Config (the e2e seed):
        let mut cfg = nos_proto::Config::default();
        for op in build_ops(&args).unwrap() {
            op.apply(&mut cfg).unwrap();
        }
        apply_bfd(&args, &mut cfg);
        assert!(
            cfg.stp_port_profiles[0].bpdu_guard
                && cfg.port_aggregates[0].stp_port_profile.is_some()
        );
        // ... and the same edits, replayed as path writes, give the same config.
        let mut via_paths = nos_proto::Config::default();
        for op in build_ops(&args).unwrap() {
            op.apply(&mut via_paths).unwrap();
        }
        let mut doc = serde_json::to_value(&via_paths).unwrap();
        for (path, value) in &edits {
            let v = value.as_deref().map(|v| serde_json::from_str(v).unwrap());
            nos_proto::config_path::set(&mut doc, path, v.unwrap()).unwrap();
        }
        assert_eq!(
            serde_json::from_value::<nos_proto::Config>(doc).unwrap(),
            cfg
        );
    }

    #[test]
    fn bfd_echo_flags_become_profile_path_edits() {
        let args = Args::try_parse_from([
            "nos-provision",
            "--address",
            "10.0.0.1/24",
            "--asn",
            "1",
            "--router-id",
            "1.1.1.1",
            "--remote-as",
            "2",
            "--peer",
            "10.0.0.2",
            "--bfd-bgp",
            "--bfd-echo-mode",
            "affiliated",
            "--bfd-echo-interval",
            "70",
            "--bfd-padded-pdu-size",
            "1500",
        ])
        .unwrap();
        let edits = bfd_paths(&args);
        let get = |f: &str| {
            edits
                .iter()
                .find(|(p, _)| p == &["bfd-profile", "fast", f])
                .and_then(|(_, v)| v.clone())
        };
        assert_eq!(get("echo-mode").as_deref(), Some("\"Affiliated\""));
        assert_eq!(get("echo-interval").as_deref(), Some("70"));
        assert_eq!(get("padded-pdu-size").as_deref(), Some("1500"));
        assert_eq!(
            parse_echo_mode("unaffiliated"),
            Ok(nos_proto::schema::EchoMode::Unaffiliated)
        );
        assert!(parse_echo_mode("bogus").is_err());
    }

    #[test]
    fn mstp_flags_become_path_edits_and_the_same_local_config() {
        let args = Args::try_parse_from([
            "nos-provision",
            "--address",
            "10.0.0.1/24",
            "--asn",
            "1",
            "--router-id",
            "1.1.1.1",
            "--remote-as",
            "2",
            "--peer",
            "10.0.0.2",
            "--stp-mode",
            "mstp",
            "--stp-region",
            "lab:3",
            "--stp-mst-instance",
            "1:4096",
            "--stp-domain-instance",
            "bd1:1",
            "--stp-profile-interface",
            "eth1",
            "--stp-profile-mst-cost",
            "1:100000",
        ])
        .unwrap();
        let edits = bfd_paths(&args);
        let get = |p: &[&str]| {
            edits
                .iter()
                .find(|(path, _)| path == p)
                .and_then(|(_, v)| v.clone())
        };
        assert_eq!(get(&["spanning-tree", "mode"]).as_deref(), Some("\"Mstp\""));
        assert_eq!(
            get(&["spanning-tree", "region", "name"]).as_deref(),
            Some("\"lab\"")
        );
        assert_eq!(
            get(&["spanning-tree", "region", "revision"]).as_deref(),
            Some("3")
        );
        assert_eq!(
            get(&["spanning-tree", "mst-instance", "1", "priority"]).as_deref(),
            Some("4096")
        );
        assert_eq!(
            get(&["broadcast-domain", "bd1", "stp-instance"]).as_deref(),
            Some("1")
        );
        assert_eq!(
            get(&[
                "stp-port-profile",
                STP_PROT_PROFILE,
                "mst-instance",
                "1",
                "cost"
            ])
            .as_deref(),
            Some("100000")
        );

        let mut cfg = nos_proto::Config::default();
        cfg.broadcast_domains.push(nos_proto::BroadcastDomain {
            name: "bd1".into(),
            ..Default::default()
        });
        cfg.stp_port_profiles
            .push(nos_proto::schema::StpPortProfile {
                name: STP_PROT_PROFILE.into(),
                ..Default::default()
            });
        apply_bfd(&args, &mut cfg);
        assert_eq!(cfg.spanning_tree.region.name, "lab");
        assert_eq!(cfg.spanning_tree.region.revision, 3);
        assert_eq!(cfg.spanning_tree.mst_instances[0].priority, 4096);
        assert_eq!(cfg.broadcast_domains[0].stp_instance, Some(1));
        assert_eq!(
            cfg.stp_port_profiles[0].mst_instances[0].cost,
            Some(100_000)
        );
    }

    #[test]
    fn rapid_pvst_flags_become_path_edits_and_the_same_local_config() {
        let args = Args::try_parse_from([
            "nos-provision",
            "--address",
            "10.0.0.1/24",
            "--asn",
            "1",
            "--router-id",
            "1.1.1.1",
            "--remote-as",
            "2",
            "--peer",
            "10.0.0.2",
            "--stp-mode",
            "rapid-pvst",
            "--stp-domain-priority",
            "bd1:4096",
            "--stp-member-cost",
            "sp1:bd1:100000",
        ])
        .unwrap();
        let edits = bfd_paths(&args);
        let get = |p: &[&str]| {
            edits
                .iter()
                .find(|(path, _)| path == p)
                .and_then(|(_, v)| v.clone())
        };
        assert_eq!(
            get(&["spanning-tree", "mode"]).as_deref(),
            Some("\"RapidPvst\"")
        );
        assert_eq!(
            get(&["broadcast-domain", "bd1", "stp-priority"]).as_deref(),
            Some("4096")
        );
        assert_eq!(
            get(&["switching-profile", "sp1", "member", "bd1", "stp-cost"]).as_deref(),
            Some("100000")
        );

        let mut cfg = nos_proto::Config::default();
        cfg.broadcast_domains.push(nos_proto::BroadcastDomain {
            name: "bd1".into(),
            ..Default::default()
        });
        cfg.switching_profiles.push(nos_proto::SwitchingProfile {
            name: "sp1".into(),
            members: vec![nos_proto::SwitchingProfileMember {
                broadcast_domain: "bd1".into(),
                ..Default::default()
            }],
        });
        apply_bfd(&args, &mut cfg);
        assert_eq!(cfg.broadcast_domains[0].stp_priority, Some(4096));
        assert_eq!(cfg.switching_profiles[0].members[0].stp_cost, Some(100_000));
    }
}
