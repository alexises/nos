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
use futures::{SinkExt, StreamExt};
use ipnet::IpNet;
use nos_proto::{
    AddressFamily, BgpInstanceOp, BgpPeerGroupOp, BgpPeerOp, BroadcastDomainOp, ConfigOp, Event,
    InterfaceOp, IpcCodec, LacpRate, LldpDestination, LldpOp, OspfAreaOp, OspfCryptoAlgorithm,
    OspfCryptoKey, OspfInstanceOp, OspfProfileOp, Ospfv3AreaOp, Ospfv3InstanceOp, Ospfv3ProfileOp,
    PolicyDefinitionOp, PortAggregateMode, PortAggregateOp, Redistribute, RedistributeSource,
    RedistributeTarget, Request, RoutingTableOp, SourceAddress, StaticRouteOp,
    StaticRoutingInstanceOp, SubinterfaceOp, SwitchingProfileOp, TransactionBase, VlanTag,
};
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite};

/// Clap-facing mirror of `nos_proto::PortAggregateMode` — `clap::ValueEnum`
/// can't be derived on a `nos-proto` type directly (that crate stays
/// dependency-free of `clap`, per the star-dependency rule).
#[derive(Clone, Copy, clap::ValueEnum)]
enum PortAggregateModeArg {
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

/// Clap-facing mirror of `nos_proto::LacpRate`, for the same reason as
/// `PortAggregateModeArg`.
#[derive(Clone, Copy, clap::ValueEnum)]
enum LacpRateArg {
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
struct Args {
    #[arg(long)]
    config_socket: PathBuf,

    #[arg(long, default_value = "eth0")]
    interface: String,
    #[arg(long)]
    address: IpNet,

    /// Which of `--interface`'s subinterfaces `--address`/`--routing-table`
    /// target — `0` (default) for the untagged/native subinterface,
    /// matching a bare `set interface <name> address ...` in nos-cli.
    /// `1..=4094` targets a real 802.1q VLAN subinterface instead.
    #[arg(long, default_value_t = 0)]
    subinterface_tag: u16,

    /// If set, deletes `--interface`'s `--subinterface-tag` subinterface
    /// instead of setting its address/routing-table.
    #[arg(long)]
    delete_subinterface: bool,

    /// If set, sets `--interface`'s own mtu (`InterfaceOp::SetMtu`) — for
    /// verifying `nos-interfaced`'s Linux driver actually applies it to the
    /// real kernel link.
    #[arg(long)]
    mtu: Option<u32>,

    #[arg(long, default_value = "rt1")]
    routing_table: String,

    /// If set, pins `nos-restd` to `--routing-table`, listening on this
    /// address inside its VRF (`RoutingTableOp::SetRestApi`). Mutually
    /// exclusive with `--clear-rest-api`.
    #[arg(long)]
    rest_api_address: Option<IpAddr>,

    /// TCP port for `--rest-api-address`.
    #[arg(long, default_value_t = nos_proto::REST_API_PORT_DEFAULT)]
    rest_api_port: u16,

    /// If set, unpins `nos-restd` from `--routing-table`
    /// (`RoutingTableOp::ClearRestApi`).
    #[arg(long)]
    clear_rest_api: bool,

    #[arg(long, default_value = "r1")]
    bgp_instance: String,
    #[arg(long)]
    asn: u32,
    #[arg(long)]
    router_id: Ipv4Addr,

    #[arg(long, default_value = "pg1")]
    peer_group: String,
    #[arg(long)]
    remote_as: u32,

    #[arg(long)]
    peer: IpAddr,

    /// If set, adds one static route (`--static-gateway` required) to a
    /// static-routing-instance associated with `--routing-table`.
    #[arg(long)]
    static_route: Option<IpNet>,
    #[arg(long)]
    static_gateway: Option<IpAddr>,
    #[arg(long, default_value = "sri1")]
    static_routing_instance: String,

    /// If set, configures `redistribute from static to bgp` on
    /// `--routing-table` — requires `--static-route` to also be set (so the
    /// table has a `static_routing_instance` to redistribute from).
    #[arg(long)]
    redistribute: bool,

    /// Names an RPL policy (or `accept-all`/`deny-all`) to filter
    /// redistributed routes through — the redistribute rule's optional
    /// `policy <name>` clause. Only meaningful with `--redistribute`;
    /// omitted, redistribution stays unfiltered.
    #[arg(long)]
    redistribute_policy: Option<String>,

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
    redistribute_to_ospf: bool,

    /// Names an RPL policy (or `accept-all`/`deny-all`) to filter routes
    /// redistributed into OSPF through. Only meaningful with
    /// `--redistribute-to-ospf`; omitted, redistribution stays unfiltered.
    #[arg(long)]
    redistribute_to_ospf_policy: Option<String>,

    /// If set, configures an RFC 2385 TCP MD5 password on `--peer-group`
    /// (`BgpPeerGroupOp::SetMd5Auth`) — for verifying session authentication
    /// end to end (matching passwords on both routers establish; a
    /// mismatched one on either side does not).
    #[arg(long)]
    md5_password: Option<String>,

    /// If set, marks `--peer-group` as an RFC 4456 route-reflector client
    /// (requires `--remote-as` to equal `--asn`, i.e. an iBGP peer-group).
    /// Calling this tool again with the same `--peer-group` but a different
    /// `--peer` adds a second client to the same peer-group, since
    /// `BgpPeerOp::Set` upserts by remote-address.
    #[arg(long)]
    route_reflector_client: bool,

    /// If set, marks `--peer-group` as an RFC 7947 route-server client
    /// (requires `--remote-as` to differ from `--asn`, i.e. an eBGP
    /// peer-group). Mutually exclusive with `--route-reflector-client`.
    #[arg(long)]
    route_server_client: bool,

    /// If set, configures `--bgp-instance`'s RFC 4456 cluster-id
    /// (`BgpInstanceOp::SetClusterId`) — only meaningful alongside
    /// `--route-reflector-client`.
    #[arg(long)]
    cluster_id: Option<Ipv4Addr>,

    #[arg(long)]
    save: bool,

    /// If set (with `--policy-source-file`), creates/updates a
    /// `PolicyDefinition` named `<policy-name>` from that file's content —
    /// for verifying RPL import/export/redistribute policy end to end.
    /// Independent of `--import-policy`/`--export-policy`/
    /// `--redistribute-policy`, which point a peer-group or redistribute
    /// rule *at* a policy by name; this just defines one.
    #[arg(long)]
    policy_name: Option<String>,
    #[arg(long)]
    policy_source_file: Option<PathBuf>,

    /// Overrides `--peer-group`'s import policy (defaults to `accept-all` —
    /// see root CLAUDE.md's "Default-deny rollout impact": every peer-group
    /// this tool provisions needs an explicit policy in each direction, or
    /// the two-router scenarios below would establish sessions but exchange
    /// zero routes).
    #[arg(long, default_value = "accept-all")]
    import_policy: String,
    #[arg(long, default_value = "accept-all")]
    export_policy: String,

    /// If set, ensures a loopback interface for `--routing-table` (named
    /// `loopback-<routing-table>`, per `nos_proto::LOOPBACK_PREFIX` — the
    /// naming convention alone marks it as a loopback, no separate flag)
    /// and adds this address to it. Mutually exclusive with
    /// `--delete-loopback`.
    #[arg(long)]
    loopback_address: Option<IpNet>,

    /// If set, deletes `--routing-table`'s loopback interface
    /// (`loopback-<routing-table>`) instead of creating/updating one.
    /// Mutually exclusive with `--loopback-address`.
    #[arg(long)]
    delete_loopback: bool,

    /// If set, removes this address from `--routing-table`'s loopback
    /// interface before applying `--loopback-address` (if also set) —
    /// `InterfaceOp::AddAddress` only ever adds, and `crate::reconcile`'s
    /// `resolve_loopback_prefix` reads `addresses[0]`, so reassigning a
    /// loopback from one address to another (e.g. the `abr` scenario
    /// repurposing the `ospf-spf` scenario's own loopback into a second
    /// area) needs the old one actually removed, not just superseded.
    #[arg(long)]
    loopback_remove_address: Option<IpNet>,

    /// If set, attaches this OSPF profile name to `--routing-table`'s
    /// loopback interface (`InterfaceOp::SetOspfProfile`) — for verifying
    /// `nos-ospfd` originates a real stub-network Router-LSA link for it
    /// (see `ospf/CLAUDE.md`'s SPF section). Mutually exclusive with
    /// `--clear-ospf-loopback-profile`.
    #[arg(long)]
    ospf_loopback_profile: Option<String>,

    /// If set, clears the loopback interface's OSPF profile attachment
    /// instead of setting one. Mutually exclusive with
    /// `--ospf-loopback-profile`.
    #[arg(long)]
    clear_ospf_loopback_profile: bool,

    /// Which broadcast domain `--broadcast-domain-svi-address`/
    /// `--delete-broadcast-domain-svi` target.
    #[arg(long, default_value = "bd-svi")]
    broadcast_domain: String,

    /// If set, ensures `--broadcast-domain` and adds this address to it,
    /// associating it with `--routing-table` (its VRF) — making the
    /// domain's own bridge device an SVI (switch virtual interface).
    /// Mutually exclusive with `--delete-broadcast-domain-svi`.
    #[arg(long)]
    broadcast_domain_svi_address: Option<IpNet>,

    /// If set, deletes `--broadcast-domain` outright instead of
    /// creating/updating its SVI. Mutually exclusive with
    /// `--broadcast-domain-svi-address`.
    #[arg(long)]
    delete_broadcast_domain_svi: bool,

    /// If set, points `--peer-group`'s source-address at this named
    /// interface (`BgpPeerGroupOp::SetSourceAddress` with
    /// `SourceAddress::Interface`). Mutually exclusive with
    /// `--source-address-loopback`/`--clear-source-address`.
    #[arg(long)]
    source_address_interface: Option<String>,

    /// If set, points `--peer-group`'s source-address at this instance's own
    /// loopback interface (`SourceAddress::Loopback`) — no interface name
    /// needed, derived from `--routing-table` by nos-bgpd itself at
    /// runtime. Mutually exclusive with
    /// `--source-address-interface`/`--clear-source-address`.
    #[arg(long)]
    source_address_loopback: bool,

    /// Paired with `--source-address-interface`/`--source-address-loopback`
    /// to disambiguate which of that interface's addresses to use.
    #[arg(long)]
    source_address_label: Option<String>,

    /// If set, clears `--peer-group`'s source-address
    /// (`BgpPeerGroupOp::ClearSourceAddress`). Mutually exclusive with
    /// `--source-address-interface`/`--source-address-loopback`.
    #[arg(long)]
    clear_source_address: bool,

    /// If set, creates this switching profile (if missing), populates it
    /// from `--switching-profile-member`, and assigns it to `--interface`
    /// (`InterfaceOp::SetSwitchingProfile`). Mutually exclusive with
    /// `--delete-switching-profile`.
    #[arg(long)]
    switching_profile: Option<String>,

    /// One `DOMAIN:TAG` pair per repetition (`TAG` is `untagged` or a
    /// dot1q id `1..=4094`), added as a member of `--switching-profile`
    /// (creating the named broadcast domain if missing). Only meaningful
    /// with `--switching-profile` also set.
    #[arg(long = "switching-profile-member")]
    switching_profile_members: Vec<String>,

    /// If set, clears `--interface`'s switching-profile assignment
    /// instead of setting one. Mutually exclusive with
    /// `--switching-profile`.
    #[arg(long)]
    delete_switching_profile: bool,

    /// If set, creates this port aggregate (a Linux bond) if missing, and
    /// enslaves every `--enslave-interface-into-port-aggregate` member into
    /// it (`PortAggregateOp::Ensure`, `InterfaceOp::SetPortAggregate`).
    #[arg(long)]
    port_aggregate: Option<String>,

    /// The aggregate's mode: `xor` (static, every member enslaved
    /// unconditionally) or `lacp` (real IEEE 802.1AX negotiation via
    /// `nos-lacpd` — see `lacp/CLAUDE.md`). Only meaningful with
    /// `--port-aggregate` also set.
    #[arg(long, value_enum, default_value_t = PortAggregateModeArg::Xor)]
    port_aggregate_mode: PortAggregateModeArg,

    /// If set (requires `--port-aggregate`), sets the aggregate's LACP
    /// timeout rate (`PortAggregateOp::SetLacpRate`).
    #[arg(long, value_enum)]
    lacp_rate: Option<LacpRateArg>,

    /// If set (requires `--port-aggregate`), sets the aggregate's own mtu
    /// (`PortAggregateOp::SetMtu`).
    #[arg(long)]
    port_aggregate_mtu: Option<u32>,

    /// One interface name per repetition, ensured and enslaved into
    /// `--port-aggregate` (`InterfaceOp::Ensure` + `InterfaceOp::SetPortAggregate`).
    /// Only meaningful with `--port-aggregate` also set.
    #[arg(long = "enslave-interface-into-port-aggregate")]
    port_aggregate_members: Vec<String>,

    /// One interface name per repetition: clears that interface's
    /// `port_aggregate` reference (`InterfaceOp::ClearPortAggregate`),
    /// withdrawing just that member while leaving the aggregate and its other
    /// members in place. Independent of `--port-aggregate`.
    #[arg(long = "clear-port-aggregate-member")]
    clear_port_aggregate_members: Vec<String>,

    /// If set, sets the top-level hostname (`ConfigOp::SetHostname`) — what
    /// `nos-lldpd` advertises as its System Name.
    #[arg(long)]
    hostname: Option<String>,

    /// One interface name per repetition: ensured, then `lldp transmit`
    /// enabled (`InterfaceOp::SetLldpTransmit`) — for verifying `nos-lldpd`
    /// really advertises on that link.
    #[arg(long = "lldp-transmit-interface")]
    lldp_transmit_interfaces: Vec<String>,

    /// Same as `--lldp-transmit-interface`, for `lldp receive`.
    #[arg(long = "lldp-receive-interface")]
    lldp_receive_interfaces: Vec<String>,

    /// One interface name per repetition: `lldp transmit` disabled again
    /// (`SetLldpTransmit { enabled: false }`), leaving `lldp receive` alone.
    #[arg(long = "no-lldp-transmit-interface")]
    no_lldp_transmit_interfaces: Vec<String>,

    /// Same as `--no-lldp-transmit-interface`, for `lldp receive`.
    #[arg(long = "no-lldp-receive-interface")]
    no_lldp_receive_interfaces: Vec<String>,

    /// If set, the system-wide LLDP `tx-interval` in seconds
    /// (`LldpOp::SetTxInterval`).
    #[arg(long)]
    lldp_tx_interval: Option<u16>,

    /// If set, the system-wide LLDP `tx-hold` (`LldpOp::SetTxHold`).
    #[arg(long)]
    lldp_tx_hold: Option<u8>,

    /// If set, the LLDP management address advertised in the Management
    /// Address TLV (`LldpOp::SetManagementAddress`).
    #[arg(long)]
    lldp_management_address: Option<IpAddr>,

    /// One `<interface>=<group>` per repetition (group is `nearest-bridge`,
    /// `non-tpmr` or `customer-bridge`): sets that interface's LLDP
    /// destination group (`InterfaceOp::SetLldpDestination`).
    #[arg(long = "lldp-destination-interface")]
    lldp_destination_interfaces: Vec<String>,

    /// If set (requires `--port-aggregate`, naming which one), deletes the
    /// port aggregate outright instead of ensuring/enslaving into it
    /// (`PortAggregateOp::Delete`) — for verifying the real kernel bond
    /// device (and its members' enslavement) is torn down.
    #[arg(long)]
    delete_port_aggregate: bool,

    /// If set, ensures this OSPF instance, sets its router-id
    /// (`--ospf-router-id`, required alongside this), and associates it
    /// with `--routing-table` (`RoutingTableOp::SetOspfInstance`) — for
    /// verifying `nos-watchdogd` dynamically spawns `nos-ospfd` for it.
    #[arg(long)]
    ospf_instance: Option<String>,
    #[arg(long)]
    ospf_router_id: Option<Ipv4Addr>,

    /// If set (requires `--ospf-instance`), ensures this OSPF area under it
    /// (`OspfAreaOp::Ensure`).
    #[arg(long)]
    ospf_area: Option<Ipv4Addr>,
    /// If set (requires `--ospf-area`), ensures this OSPF profile under it
    /// (`OspfProfileOp::Ensure`).
    #[arg(long)]
    ospf_profile: Option<String>,
    /// If set, attaches this profile name to `--interface`'s
    /// `--subinterface-tag` subinterface (`SubinterfaceOp::SetOspfProfile`)
    /// — for verifying `nos-ospfd` logs the attachment.
    #[arg(long)]
    ospf_interface_profile: Option<String>,
    /// If set, attaches this profile name to `--broadcast-domain`'s own SVI
    /// (`BroadcastDomainOp::SetOspfProfile`) — for verifying `nos-ospfd`'s
    /// broadcast-network-type Hello/DR-BDR-election path. Combine with
    /// `--broadcast-domain-svi-address`/`--switching-profile`/
    /// `--switching-profile-member` to build the whole attach point.
    #[arg(long)]
    ospf_broadcast_domain_profile: Option<String>,

    /// If set (requires `--ospf-profile`), configures an RFC 2328 Appendix
    /// D.2 simple password on it (`OspfProfileOp::SetSimpleAuth`).
    /// Mutually exclusive with `--ospf-crypto-key` (RFC 2328's Simple and
    /// Cryptographic auth types are themselves mutually exclusive).
    #[arg(long)]
    ospf_simple_password: Option<String>,

    /// If set (requires `--ospf-profile`), configures a single RFC 2328
    /// Appendix D.3 / RFC 5709 cryptographic auth key on it
    /// (`OspfProfileOp::SetCryptoKey`, marked current) — `<key-id>:
    /// <algorithm>:<key>`, algorithm one of `md5`/`hmac-sha1`/
    /// `hmac-sha256`/`hmac-sha384`/`hmac-sha512` — for verifying session
    /// authentication end to end (matching keys on both routers establish;
    /// a mismatched one on either side does not).
    #[arg(long)]
    ospf_crypto_key: Option<String>,

    /// If set (requires `--ospf-profile`), overrides the MTU OSPF believes
    /// this profile's links have (`OspfProfileOp::SetMtu`) — for verifying
    /// real-MTU-driven DBD pagination independent of the interface's own
    /// real kernel MTU.
    #[arg(long)]
    ospf_profile_mtu: Option<u16>,

    /// If set, adds this IPv6 address to `--interface`'s
    /// `--subinterface-tag` subinterface alongside `--address` — `OSPFv3`
    /// (RFC 5340) needs a real IPv6 prefix on the link, distinct from
    /// `--address`'s own (typically IPv4, for BGP) subnet.
    #[arg(long)]
    ospfv3_address: Option<IpNet>,

    /// Same shape as `--ospf-instance`/`--ospf-router-id`, joining `OSPFv3`
    /// instead (`RoutingTableOp::SetOspfv3Instance`).
    #[arg(long)]
    ospfv3_instance: Option<String>,
    #[arg(long)]
    ospfv3_router_id: Option<Ipv4Addr>,

    /// Same shape as `--ospf-area` (requires `--ospfv3-instance`).
    #[arg(long)]
    ospfv3_area: Option<Ipv4Addr>,
    /// Same shape as `--ospf-profile` (requires `--ospfv3-area`).
    #[arg(long)]
    ospfv3_profile: Option<String>,
    /// Same shape as `--ospf-interface-profile`, joining `OSPFv3` instead
    /// (`SubinterfaceOp::SetOspfv3Profile`).
    #[arg(long)]
    ospfv3_interface_profile: Option<String>,
    /// Same shape as `--ospf-broadcast-domain-profile`, joining `OSPFv3`
    /// instead (`BroadcastDomainOp::SetOspfv3Profile`).
    #[arg(long)]
    ospfv3_broadcast_domain_profile: Option<String>,

    /// If set, adds this IPv6 address to `--routing-table`'s loopback
    /// interface (`loopback-<routing-table>`) alongside `--loopback-address`
    /// — `OSPFv3` only ever advertises IPv6 prefixes.
    #[arg(long)]
    ospfv3_loopback_address: Option<IpNet>,

    /// Same shape as `--ospf-loopback-profile`, joining `OSPFv3` instead.
    /// Mutually exclusive with `--clear-ospfv3-loopback-profile`.
    #[arg(long)]
    ospfv3_loopback_profile: Option<String>,

    /// Same shape as `--clear-ospf-loopback-profile`, joining `OSPFv3`
    /// instead. Mutually exclusive with `--ospfv3-loopback-profile`.
    #[arg(long)]
    clear_ospfv3_loopback_profile: bool,

    /// If set, adds this IPv6 address to `--broadcast-domain`'s SVI
    /// alongside `--broadcast-domain-svi-address`.
    #[arg(long)]
    ospfv3_broadcast_domain_svi_address: Option<IpNet>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let stream = UnixStream::connect(&args.config_socket)
        .await
        .with_context(|| format!("connecting to {}", args.config_socket.display()))?;
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, IpcCodec::<Event>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<Request>::default());

    let txn = "verify".to_string();

    send(
        &mut writer,
        &mut reader,
        Request::OpenTransaction {
            name: txn.clone(),
            base: TransactionBase::Current,
        },
    )
    .await?;

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

    if let Some(name) = args.policy_name.clone() {
        let path = args
            .policy_source_file
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
        || args.lacp_rate.is_some()
        || !args.port_aggregate_members.is_empty()
    {
        bail!(
            "--port-aggregate-mtu/--lacp-rate/--enslave-interface-into-port-aggregate require --port-aggregate to also be set"
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

    for op in ops {
        send(
            &mut writer,
            &mut reader,
            Request::ApplyOp {
                name: txn.clone(),
                op,
            },
        )
        .await?;
    }

    send(
        &mut writer,
        &mut reader,
        Request::CommitTransaction { name: txn.clone() },
    )
    .await?;

    if args.save {
        send(&mut writer, &mut reader, Request::Save).await?;
    }

    println!("provisioning complete");
    Ok(())
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

async fn send(
    writer: &mut FramedWrite<tokio::net::unix::OwnedWriteHalf, IpcCodec<Request>>,
    reader: &mut FramedRead<tokio::net::unix::OwnedReadHalf, IpcCodec<Event>>,
    req: Request,
) -> anyhow::Result<()> {
    let label = format!("{req:?}");
    writer.send(req).await.context("sending request")?;
    match reader.next().await {
        Some(Ok(Event::Error(e))) => bail!("{label} -> error: {e}"),
        Some(Ok(event)) => {
            eprintln!("{label} -> {event:?}");
            Ok(())
        }
        Some(Err(e)) => bail!("{label} -> transport error: {e}"),
        None => bail!("{label} -> connection closed"),
    }
}
