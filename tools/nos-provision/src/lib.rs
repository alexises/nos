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

use ipnet::IpNet;
use nos_proto::{
    AddressFamily, BgpInstanceOp, BgpPeerGroupOp, BgpPeerOp, BroadcastDomainOp, ConfigOp,
    EsRedundancy, InterfaceOp, LacpRate, LldpDestination, LldpOp, OspfAreaOp, OspfCryptoAlgorithm,
    OspfCryptoKey, OspfInstanceOp, OspfProfileOp, Ospfv3AreaOp, Ospfv3InstanceOp, Ospfv3ProfileOp,
    PolicyDefinitionOp, PortAggregateMode, PortAggregateOp, Redistribute, RedistributeSource,
    RedistributeTarget, RoutingTableOp, SourceAddress, StaticRouteOp, StaticRoutingInstanceOp,
    SubinterfaceOp, SwitchingProfileOp, UserOp, VlanTag,
};

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

    /// If set, sets `--interface`'s own mtu (`InterfaceOp::SetMtu`) — for
    /// verifying `nos-interfaced`'s Linux driver actually applies it to the
    /// real kernel link.
    #[arg(long)]
    pub mtu: Option<u32>,

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

    /// If set, adds one static route (`--static-gateway` required) to a
    /// static-routing-instance associated with `--routing-table`.
    #[arg(long)]
    pub static_route: Option<IpNet>,
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
    /// exclusive with `--redistribute` at the tool level, but
    /// `RoutingTableOp::SetRedistribute` only stores one `Redistribute` rule
    /// per table — setting both in one invocation just has the second
    /// `SetRedistribute` op overwrite the first.
    #[arg(long)]
    pub redistribute_to_ospf: bool,

    /// Names an RPL policy (or `accept-all`/`deny-all`) to filter routes
    /// redistributed into OSPF through. Only meaningful with
    /// `--redistribute-to-ospf`; omitted, redistribution stays unfiltered.
    #[arg(long)]
    pub redistribute_to_ospf_policy: Option<String>,

    /// If set, configures an RFC 2385 TCP MD5 password on `--peer-group`
    /// (`BgpPeerGroupOp::SetMd5Auth`) — for verifying session authentication
    /// end to end (matching passwords on both routers establish; a
    /// mismatched one on either side does not).
    #[arg(long)]
    pub md5_password: Option<String>,

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
    /// (see `ospf/CLAUDE.md`'s SPF section). Mutually exclusive with
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

    /// If set (requires `--port-aggregate`), overrides the aggregate's LACP
    /// Actor System ID (`PortAggregateOp::SetLacpSystemId`).
    #[arg(long)]
    pub lacp_system_id: Option<String>,

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

    /// If set, the LLDP management address advertised in the Management
    /// Address TLV (`LldpOp::SetManagementAddress`).
    #[arg(long)]
    pub lldp_management_address: Option<IpAddr>,

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

    /// If set (requires `--ospf-instance`), ensures this OSPF area under it
    /// (`OspfAreaOp::Ensure`).
    #[arg(long)]
    pub ospf_area: Option<Ipv4Addr>,
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

    /// If set, adds this IPv6 address to `--interface`'s
    /// `--subinterface-tag` subinterface alongside `--address` — `OSPFv3`
    /// (RFC 5340) needs a real IPv6 prefix on the link, distinct from
    /// `--address`'s own (typically IPv4, for BGP) subnet.
    #[arg(long)]
    pub ospfv3_address: Option<IpNet>,

    /// Same shape as `--ospf-instance`/`--ospf-router-id`, joining `OSPFv3`
    /// instead (`RoutingTableOp::SetOspfv3Instance`).
    #[arg(long)]
    pub ospfv3_instance: Option<String>,
    #[arg(long)]
    pub ospfv3_router_id: Option<Ipv4Addr>,
    /// RFC 8362 Full mode for that instance (requires `--ospfv3-instance`).
    #[arg(long)]
    pub ospfv3_extended_lsa: bool,

    /// Same shape as `--ospf-area` (requires `--ospfv3-instance`).
    #[arg(long)]
    pub ospfv3_area: Option<Ipv4Addr>,
    /// Same shape as `--ospf-profile` (requires `--ospfv3-area`).
    #[arg(long)]
    pub ospfv3_profile: Option<String>,
    /// Same shape as `--ospf-interface-profile`, joining `OSPFv3` instead
    /// (`SubinterfaceOp::SetOspfv3Profile`).
    #[arg(long)]
    pub ospfv3_interface_profile: Option<String>,
    /// Same shape as `--ospf-broadcast-domain-profile`, joining `OSPFv3`
    /// instead (`BroadcastDomainOp::SetOspfv3Profile`).
    #[arg(long)]
    pub ospfv3_broadcast_domain_profile: Option<String>,

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

/// Builds the ordered `ConfigOp` list for one provisioning invocation — pure,
/// so a caller can apply it over IPC (this crate's bin) or locally onto a
/// `Config` (`nos-e2e`, which then PUTs the result over the REST API).
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
        || args.evpn_redistribute_connected_bgp.is_some();
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
    Ok(ops)
}

pub fn build_ops(args: &Args) -> anyhow::Result<Vec<ConfigOp>> {
    let mut ops = vec![ConfigOp::Interface(InterfaceOp::Ensure {
        name: args.interface.clone(),
    })];
    if let Some(mtu) = args.mtu {
        ops.push(ConfigOp::Interface(InterfaceOp::SetMtu {
            name: args.interface.clone(),
            mtu,
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
        if let Some(address) = args.ospfv3_address {
            ops.push(ConfigOp::Subinterface(SubinterfaceOp::AddAddress {
                interface: args.interface.clone(),
                tag: args.subinterface_tag,
                address,
                label: None,
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

    if let Some(subnet) = args.static_route {
        let gateway = args
            .static_gateway
            .context("--static-gateway is required when --static-route is set")?;
        ops.push(ConfigOp::StaticRoutingInstance(
            StaticRoutingInstanceOp::Ensure {
                name: args.static_routing_instance.clone(),
            },
        ));
        ops.push(ConfigOp::StaticRoute(StaticRouteOp::Set {
            instance: args.static_routing_instance.clone(),
            subnet,
            gateway,
        }));
        ops.push(ConfigOp::RoutingTable(
            RoutingTableOp::SetStaticRoutingInstance {
                name: args.routing_table.clone(),
                static_routing_instance: args.static_routing_instance.clone(),
            },
        ));
    } else if args.redistribute || args.redistribute_to_ospf {
        bail!(
            "--redistribute/--redistribute-to-ospf require --static-route (and \
             --static-gateway) to also be set"
        );
    }

    if args.redistribute {
        ops.push(ConfigOp::RoutingTable(RoutingTableOp::SetRedistribute {
            name: args.routing_table.clone(),
            redistribute: Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Bgp,
                policy: args.redistribute_policy.clone(),
            },
        }));
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
            },
        }));
    }

    if let Some(password) = args.md5_password.clone() {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetMd5Auth {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
            password,
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
    if args.clear_damping {
        ops.push(ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearDamping {
            instance: args.bgp_instance.clone(),
            name: args.peer_group.clone(),
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
        ops.push(ConfigOp::BroadcastDomain(
            BroadcastDomainOp::SetRoutingTable {
                name: args.broadcast_domain.clone(),
                routing_table: args.routing_table.clone(),
            },
        ));
    }
    if args.delete_broadcast_domain_svi {
        ops.push(ConfigOp::BroadcastDomain(BroadcastDomainOp::Delete {
            name: args.broadcast_domain.clone(),
        }));
    }

    ops.extend(evpn_ops(args)?);

    // Adds a second (IPv6) address to `--broadcast-domain`'s SVI alongside
    // `--broadcast-domain-svi-address` — same dual-stack rationale as
    // `--ospfv3-address`/`--ospfv3-loopback-address`.
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
            name: args.interface.clone(),
            switching_profile: profile,
        }));
    } else if !args.switching_profile_members.is_empty() {
        bail!("--switching-profile-member requires --switching-profile to also be set");
    }
    if args.delete_switching_profile {
        ops.push(ConfigOp::Interface(InterfaceOp::ClearSwitchingProfile {
            name: args.interface.clone(),
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
        if let Some(esi) = args.port_aggregate_esi.clone() {
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
        if let Some(system_id) = args.lacp_system_id.clone() {
            ops.push(ConfigOp::PortAggregate(PortAggregateOp::SetLacpSystemId {
                name: name.clone(),
                system_id,
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
        }
    } else if args.port_aggregate_mtu.is_some()
        || args.port_aggregate_esi.is_some()
        || args.delete_port_aggregate_esi
        || args.port_aggregate_redundancy_mode.is_some()
        || args.lacp_system_id.is_some()
        || args.port_aggregate_untagged_domain.is_some()
        || args.lacp_rate.is_some()
        || !args.port_aggregate_members.is_empty()
    {
        bail!(
            "--port-aggregate-mtu/--port-aggregate-esi/--port-aggregate-redundancy-mode/--lacp-system-id/--port-aggregate-untagged-domain/--lacp-rate/--enslave-interface-into-port-aggregate require --port-aggregate to also be set"
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
    if let Some(address) = args.lldp_management_address {
        ops.push(ConfigOp::Lldp(LldpOp::SetManagementAddress { address }));
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
        ops.push(ConfigOp::RoutingTable(RoutingTableOp::SetOspfInstance {
            name: args.routing_table.clone(),
            ospf_instance: name,
        }));
    } else if args.ospf_router_id.is_some() {
        bail!("--ospf-router-id requires --ospf-instance to also be set");
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
            if let Some(password) = args.ospf_simple_password.clone() {
                ops.push(ConfigOp::OspfProfile(OspfProfileOp::SetSimpleAuth {
                    instance: instance.clone(),
                    area_id,
                    name: name.clone(),
                    password,
                }));
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
        }
    } else if args.ospf_profile.is_some() {
        bail!("--ospf-profile requires --ospf-area to also be set");
    } else if args.ospf_simple_password.is_some() || args.ospf_crypto_key.is_some() {
        bail!("--ospf-simple-password/--ospf-crypto-key require --ospf-profile to also be set");
    } else if args.ospf_profile_mtu.is_some() {
        bail!("--ospf-profile-mtu requires --ospf-profile to also be set");
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
                instance,
                area_id,
                name,
            }));
        }
    } else if args.ospfv3_profile.is_some() {
        bail!("--ospfv3-profile requires --ospfv3-area to also be set");
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
    Ok(ops)
}

/// Parses `--ospf-crypto-key`'s `<key-id>:<algorithm>:<key>` shape into a
/// single `OspfCryptoKey`, always marked current — this tool only ever
/// provisions one active key at a time (rotation isn't part of the e2e
/// scenario this flag exists for).
fn parse_ospf_crypto_key(spec: &str) -> anyhow::Result<OspfCryptoKey> {
    let mut parts = spec.splitn(3, ':');
    let (Some(key_id), Some(algorithm), Some(key)) = (parts.next(), parts.next(), parts.next())
    else {
        bail!("--ospf-crypto-key must be <key-id>:<algorithm>:<key>, got '{spec}'");
    };
    let key_id = key_id
        .parse::<u8>()
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
