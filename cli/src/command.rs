use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use nos_proto::{
    AddressFamily, BgpAoAlgorithm, BroadcastDomainOp, EsRedundancy, LacpRate, LldpDestination,
    NetworkType, NextHopMode, OspfCryptoAlgorithm, PortAggregateMode, PortAggregateOp,
    Redistribute, RedistributeSource, RedistributeTarget, SourceAddress, TransactionBase, VlanTag,
    REST_API_PORT_DEFAULT,
};

/// A single field edit targeting a BGP instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpInstanceField {
    Asn(u32),
    RouterId(Ipv4Addr),
    ClusterId(Ipv4Addr),
}

// `OspfInstance` has exactly one editable field today, so — unlike
// `BgpInstance`/`BgpPeerGroup` — it has no `Field` enum of its own; the
// fully-qualified `SetTarget::OspfInstance` carries `router_id` directly.
// The context-relative `set router-id <ip>` form is shared with
// `BgpInstanceField::RouterId` instead of getting a parallel variant here —
// `Command::parse` is mode-unaware (see `cli/CLAUDE.md`) and can't emit two
// different `Command`s for the same literal token sequence, so
// `session::resolve_in_transaction` disambiguates by `path` at resolve
// time.

/// A single field edit targeting a BGP peer-group. Not `Copy` — the auth
/// variants carry owned `String` key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpPeerGroupField {
    RemoteAs(u32),
    SourceAddress(SourceAddress),
    AddressFamily(AddressFamily),
    HoldTime(u16),
    KeepaliveInterval(u16),
    ConnectRetryTime(u16),
    Mrai(u16),
    Damping(nos_proto::BgpDamping),
    MaxHops(u8),
    /// `shutdown [<message>]`.
    Shutdown(Option<String>),
    Md5Password(String),
    /// A new (or replacement) TCP-AO key — `current`/`rnext` are set via the
    /// separate `AoCurrentKey`/`AoRnextKey` variants, not here.
    AoKey {
        send_id: u8,
        recv_id: u8,
        algorithm: BgpAoAlgorithm,
        key: String,
    },
    AoCurrentKey(u8),
    AoRnextKey(u8),
    NextHop(NextHopMode),
    /// `route-reflector-client` — always sets it to `true`; clearing goes
    /// through `DeleteTarget::RouteReflectorClient`.
    RouteReflectorClient,
    /// `route-server-client` — always sets it to `true`; clearing goes
    /// through `DeleteTarget::RouteServerClient`.
    RouteServerClient,
    /// `import-policy <name>` — `<name>` is any `PolicyDefinition`, or the
    /// reserved `accept-all`/`deny-all` names; not validated here, only at
    /// commit time.
    ImportPolicy(String),
    ExportPolicy(String),
}

/// A single field edit targeting an `OspfProfile`. Not `Copy` — the auth
/// variants carry owned `String` key material, mirroring
/// `BgpPeerGroupField`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OspfProfileField {
    HelloInterval(u16),
    DeadInterval(u16),
    Cost(u16),
    Priority(u8),
    Mtu(u16),
    NetworkType(NetworkType),
    SimplePassword(String),
    /// A new (or replacement) crypto key — `current` is set via the
    /// separate `CryptoCurrentKey` variant, not here.
    CryptoKey {
        key_id: u8,
        algorithm: OspfCryptoAlgorithm,
        key: String,
    },
    CryptoCurrentKey(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditTarget {
    BgpInstance {
        name: String,
    },
    /// Fully-qualified — works from anywhere in configuration mode.
    BgpPeerGroup {
        instance: String,
        name: String,
    },
    /// Context-relative — only valid while navigated into a BGP instance.
    PeerGroupRelative {
        name: String,
    },
    RoutingTable {
        name: String,
    },
    OspfInstance {
        name: String,
    },
    /// Fully-qualified — works from anywhere in configuration mode.
    OspfArea {
        instance: String,
        area_id: Ipv4Addr,
    },
    /// Context-relative — only valid while navigated into an OSPF instance.
    OspfAreaRelative {
        area_id: Ipv4Addr,
    },
    /// Fully-qualified — works from anywhere in configuration mode.
    OspfProfile {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
    },
    /// Context-relative — only valid while navigated into an OSPF area.
    OspfProfileRelative {
        name: String,
    },
    /// Fully-qualified — works from anywhere in configuration mode. `edit
    /// area <area-id>`/`edit profile <name>` (`OspfAreaRelative`/
    /// `OspfProfileRelative` above) are shared, path-disambiguated tokens
    /// between `OSPFv2` and `OSPFv3` — see `Path::ospf_instance`'s doc
    /// comment in `session.rs`.
    Ospfv3Instance {
        name: String,
    },
    /// Fully-qualified — works from anywhere in configuration mode.
    Ospfv3Area {
        instance: String,
        area_id: Ipv4Addr,
    },
    /// Fully-qualified — works from anywhere in configuration mode.
    Ospfv3Profile {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
    },
    StaticRoutingInstance {
        name: String,
    },
    Interface {
        name: String,
    },
    PolicyDefinition {
        name: String,
    },
    CommunityAlias {
        name: String,
    },
    CommunityGroup {
        name: String,
    },
    PrefixList {
        name: String,
    },
    BroadcastDomain {
        name: String,
    },
    SwitchingProfile {
        name: String,
    },
    PortAggregate {
        name: String,
    },
}

/// Which half of LLDP a `set`/`delete ... lldp <direction>` command toggles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LldpDirection {
    Transmit,
    Receive,
}

/// A system-wide `lldp` setting (`Config.lldp`), for `set lldp <setting> <value>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LldpSetting {
    TxInterval(u16),
    TxHold(u8),
    ManagementAddress(IpAddr),
}

/// Which `lldp` setting a `delete lldp <setting>` command clears.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LldpSettingKind {
    TxInterval,
    TxHold,
    ManagementAddress,
}

fn parse_lldp_direction(token: &str) -> LldpDirection {
    if token == "transmit" {
        LldpDirection::Transmit
    } else {
        LldpDirection::Receive
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetTarget {
    /// Fully-qualified — works from anywhere in configuration mode.
    BgpInstance {
        name: String,
        field: BgpInstanceField,
    },
    /// Context-relative — only valid while navigated into a BGP instance.
    Relative { field: BgpInstanceField },
    /// `set mtu <n>` — ambiguous by token alone, shared between a physical
    /// interface's own mtu and an `OspfProfile`'s mtu override, resolved by
    /// `path` at resolve time (mirrors `Relative`'s BgpInstance/OspfInstance
    /// sharing of `set router-id <ip>`).
    MtuRelative(u16),
    /// A top-level scalar with no navigation context — works from anywhere
    /// in configuration mode, regardless of the current path.
    Hostname(String),
    /// `set user <name> password <clear>` — creates the user if missing.
    UserPassword { name: String, password: String },
    /// Fully-qualified peer-group field edit — works from anywhere in
    /// configuration mode.
    BgpPeerGroup {
        instance: String,
        group: String,
        field: BgpPeerGroupField,
    },
    /// Context-relative — only valid while navigated into a peer-group.
    PeerGroupRelative { field: BgpPeerGroupField },
    /// Fully-qualified peer upsert — works from anywhere in configuration
    /// mode.
    BgpPeer {
        instance: String,
        remote_address: IpAddr,
        peer_group: String,
    },
    /// Context-relative — only valid while navigated into a BGP instance
    /// (peers are siblings of peer-groups, not reachable from inside one).
    PeerRelative {
        remote_address: IpAddr,
        peer_group: String,
    },
    /// `set bgp instance <i> peer <addr> shutdown [<message>]`.
    BgpPeerShutdown {
        instance: String,
        remote_address: IpAddr,
        message: Option<String>,
    },
    /// Context-relative — only valid while navigated into a BGP instance.
    PeerShutdownRelative {
        remote_address: IpAddr,
        message: Option<String>,
    },
    /// Fully-qualified — works from anywhere in configuration mode.
    RoutingTable { name: String, bgp_instance: String },
    /// Context-relative — only valid while navigated into a routing table.
    RoutingTableRelative { bgp_instance: String },
    /// Fully-qualified — works from anywhere in configuration mode.
    RoutingTableStaticRoutingInstance {
        name: String,
        static_routing_instance: String,
    },
    /// Context-relative — only valid while navigated into a routing table.
    RoutingTableStaticRoutingInstanceRelative { static_routing_instance: String },
    /// Fully-qualified — works from anywhere in configuration mode.
    RoutingTableOspfInstance { name: String, ospf_instance: String },
    /// Context-relative — only valid while navigated into a routing table.
    RoutingTableOspfInstanceRelative { ospf_instance: String },
    /// Same shape as `RoutingTableOspfInstance`, joining `OSPFv3` instead.
    RoutingTableOspfv3Instance {
        name: String,
        ospfv3_instance: String,
    },
    /// Context-relative — only valid while navigated into a routing table.
    RoutingTableOspfv3InstanceRelative { ospfv3_instance: String },
    /// `set routing-table <name> rest-api address <ip> [port <n>]` — pins
    /// `nos-restd` to the table. `port` is already defaulted by the parser.
    RoutingTableRestApi {
        name: String,
        address: IpAddr,
        port: u16,
    },
    /// Context-relative — only valid while navigated into a routing table.
    RoutingTableRestApiRelative { address: IpAddr, port: u16 },
    /// Fully-qualified — works from anywhere in configuration mode. No
    /// context-relative form — see `BgpInstanceField`'s doc comment on why
    /// `set router-id <ip>` while navigated into an `OspfInstance` reuses
    /// `SetTarget::Relative { field: BgpInstanceField::RouterId }` instead.
    OspfInstance { name: String, router_id: Ipv4Addr },
    /// Fully-qualified `OspfProfile` field edit — works from anywhere in
    /// configuration mode.
    OspfProfile {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
        field: OspfProfileField,
    },
    /// Context-relative — only valid while navigated into an `OspfProfile`.
    OspfProfileRelative { field: OspfProfileField },
    /// Fully-qualified — works from anywhere in configuration mode. No
    /// context-relative form of its own — the relative
    /// `hello-interval`/`dead-interval`/`cost`/`priority`/`network-type`/
    /// `mtu` tokens are shared with `OspfProfileRelative`/`MtuRelative`
    /// above, disambiguated by `path` at resolve time (an `Ospfv3Profile`
    /// has no `auth`, so `SimplePassword`/`CryptoKey`/`CryptoCurrentKey`
    /// resolve to an error there).
    Ospfv3Instance { name: String, router_id: Ipv4Addr },
    /// `set ospfv3 instance <name> extended-lsa` — RFC 8362 Full mode on.
    Ospfv3InstanceExtendedLsa { name: String },
    /// Fully-qualified `Ospfv3Profile` field edit — works from anywhere in
    /// configuration mode.
    Ospfv3Profile {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
        field: OspfProfileField,
    },
    /// Fully-qualified — works from anywhere in configuration mode.
    RoutingTableRedistribute {
        name: String,
        redistribute: Redistribute,
    },
    /// Context-relative — only valid while navigated into a routing table.
    RoutingTableRedistributeRelative { redistribute: Redistribute },
    /// Fully-qualified route upsert — works from anywhere in configuration
    /// mode.
    StaticRoute {
        instance: String,
        subnet: IpNet,
        gateway: IpAddr,
    },
    /// Context-relative — only valid while navigated into a static routing
    /// instance.
    StaticRouteRelative { subnet: IpNet, gateway: IpAddr },
    /// Fully-qualified — works from anywhere in configuration mode.
    InterfaceAddress {
        name: String,
        address: IpNet,
        label: Option<String>,
    },
    /// Context-relative — only valid while navigated into an interface.
    InterfaceAddressRelative {
        address: IpNet,
        label: Option<String>,
    },
    /// Fully-qualified — works from anywhere in configuration mode.
    InterfaceRoutingTable { name: String, routing_table: String },
    /// Context-relative — only valid while navigated into an interface.
    InterfaceRoutingTableRelative { routing_table: String },
    /// Fully-qualified — works from anywhere in configuration mode. Always
    /// physical-interface-level, like `InterfaceSwitchingProfile` — `mtu` is
    /// a link-layer property, not part of the per-subinterface addressing
    /// split.
    InterfaceMtu { name: String, mtu: u32 },
    /// `set interface <name> lldp transmit|receive` — fully-qualified.
    /// Physical-interface-level, like `InterfaceMtu`.
    InterfaceLldp {
        name: String,
        direction: LldpDirection,
    },
    /// `set lldp transmit|receive` — context-relative, only valid while
    /// navigated into an interface.
    InterfaceLldpRelative { direction: LldpDirection },
    /// `set interface <name> lldp destination <group>` — fully-qualified.
    InterfaceLldpDestination {
        name: String,
        destination: LldpDestination,
    },
    /// `set lldp destination <group>` — context-relative.
    InterfaceLldpDestinationRelative { destination: LldpDestination },
    /// `set lldp tx-interval|tx-hold|management-address <value>` — a
    /// system-wide scalar, valid from anywhere in configuration mode.
    Lldp(LldpSetting),
    /// Fully-qualified — works from anywhere in configuration mode.
    InterfaceSwitchingProfile {
        name: String,
        switching_profile: String,
    },
    /// Context-relative — only valid while navigated into an interface.
    InterfaceSwitchingProfileRelative { switching_profile: String },
    /// Fully-qualified — works from anywhere in configuration mode.
    InterfaceOspfProfile { name: String, ospf_profile: String },
    /// Context-relative — only valid while navigated into a loopback
    /// interface, a subinterface, or a broadcast domain.
    InterfaceOspfProfileRelative { ospf_profile: String },
    /// Same shape as `InterfaceOspfProfile`, joining `OSPFv3` instead — its
    /// own token (`ospfv3` vs `ospf`), not shared/ambiguous.
    InterfaceOspfv3Profile {
        name: String,
        ospfv3_profile: String,
    },
    /// Context-relative — only valid while navigated into a loopback
    /// interface, a subinterface, or a broadcast domain.
    InterfaceOspfv3ProfileRelative { ospfv3_profile: String },
    /// Fully-qualified — works from anywhere in configuration mode.
    CommunityAliasValue { name: String, value: String },
    /// Context-relative — only valid while navigated into a community-alias.
    CommunityAliasValueRelative { value: String },
    /// Fully-qualified — works from anywhere in configuration mode.
    CommunityGroupMember { name: String, member: String },
    /// Context-relative — only valid while navigated into a community-group.
    CommunityGroupMemberRelative { member: String },
    /// Fully-qualified — works from anywhere in configuration mode.
    PrefixListEntry {
        name: String,
        cidr: IpNet,
        range: Option<(u8, u8)>,
    },
    /// Context-relative — only valid while navigated into a prefix-list.
    PrefixListEntryRelative {
        cidr: IpNet,
        range: Option<(u8, u8)>,
    },
    /// Fully-qualified — works from anywhere in configuration mode.
    BroadcastDomainAddress {
        name: String,
        address: IpNet,
        label: Option<String>,
    },
    /// Fully-qualified — works from anywhere in configuration mode.
    BroadcastDomainRoutingTable { name: String, routing_table: String },
    /// A `set broadcast domain <name> {vni|rd|route-target|vtep-source|redistribute}`
    /// EVPN edit: the parser builds the op itself (one variant instead of
    /// five parallel target/field types).
    BroadcastDomainEvpn(BroadcastDomainOp),
    /// `set port-aggregate <name> {esi|lacp-system-id} <value>`: the parser
    /// builds the op itself, like `BroadcastDomainEvpn`.
    PortAggregateField(PortAggregateOp),
    /// Context-relative — only valid while navigated into a port aggregate.
    PortAggregateEsiRelative { esi: String },
    /// Context-relative — only valid while navigated into a port aggregate.
    PortAggregateLacpSystemIdRelative { system_id: String },
    /// Fully-qualified — works from anywhere in configuration mode. Upserts
    /// by `broadcast_domain` within the named switching profile.
    SwitchingProfileMember {
        name: String,
        broadcast_domain: String,
        tag: VlanTag,
    },
    /// Context-relative — only valid while navigated into a switching
    /// profile.
    SwitchingProfileMemberRelative {
        broadcast_domain: String,
        tag: VlanTag,
    },
    /// Fully-qualified — works from anywhere in configuration mode.
    PortAggregateMode {
        name: String,
        mode: PortAggregateMode,
    },
    /// Context-relative — only valid while navigated into a port aggregate.
    PortAggregateModeRelative { mode: PortAggregateMode },
    /// Fully-qualified — works from anywhere in configuration mode.
    PortAggregateLacpRate { name: String, rate: LacpRate },
    /// Context-relative — only valid while navigated into a port aggregate.
    PortAggregateLacpRateRelative { rate: LacpRate },
    /// Fully-qualified — works from anywhere in configuration mode.
    PortAggregateRedundancyMode { name: String, mode: EsRedundancy },
    /// Context-relative — only valid while navigated into a port aggregate.
    PortAggregateRedundancyModeRelative { mode: EsRedundancy },
    /// Fully-qualified — works from anywhere in configuration mode.
    InterfacePortAggregate {
        name: String,
        port_aggregate: String,
    },
    /// Context-relative — only valid while navigated into an interface.
    InterfacePortAggregateRelative { port_aggregate: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteTarget {
    /// Bare `delete` — deletes whatever the current navigation context is.
    Current,
    User {
        name: String,
    },
    BgpInstance {
        name: String,
    },
    BgpPeerGroup {
        instance: String,
        name: String,
    },
    PeerGroupRelative {
        name: String,
    },
    BgpPeer {
        instance: String,
        remote_address: IpAddr,
    },
    PeerRelative {
        remote_address: IpAddr,
    },
    /// `delete bgp instance <i> peer <addr> shutdown`.
    BgpPeerShutdown {
        instance: String,
        remote_address: IpAddr,
    },
    /// Only valid while navigated into a BGP instance.
    PeerShutdownRelative {
        remote_address: IpAddr,
    },
    /// `delete shutdown` — only valid while navigated into a peer-group.
    Shutdown,
    /// `delete source-address` — only valid while navigated into a
    /// peer-group.
    SourceAddress,
    /// `delete address-family ipv4|ipv6|l2vpn-evpn` — only valid while navigated into
    /// a peer-group.
    AddressFamily(AddressFamily),
    /// `delete hold-time` — only valid while navigated into a peer-group.
    HoldTime,
    /// `delete keepalive-interval` — only valid while navigated into a
    /// peer-group.
    KeepaliveInterval,
    /// `delete connect-retry-time` — only valid while navigated into a
    /// peer-group.
    ConnectRetryTime,
    /// `delete mrai` — only valid while navigated into a peer-group.
    Mrai,
    /// `delete damping` — only valid while navigated into a peer-group.
    Damping,
    /// `delete max-hops` — only valid while navigated into a peer-group.
    MaxHops,
    /// `delete auth` — shared with an `OspfProfile`'s crypto/simple auth
    /// (its schema has no field enum of its own to carry a separate
    /// variant, mirroring `BgpInstanceField::RouterId`'s exact precedent) —
    /// only valid while navigated into a peer-group or an OSPF profile,
    /// resolved by path in `session::resolve_in_transaction`.
    Auth,
    /// `delete ao-key <send-id>` — only valid while navigated into a
    /// peer-group. (An OSPF profile's crypto key removal is `delete
    /// crypto-key <key-id>`, its own token, since `ao-key`'s literal isn't
    /// shared.)
    AoKey(u8),
    /// `delete crypto-key <key-id>` — only valid while navigated into an
    /// `OspfProfile`.
    CryptoKey(u8),
    /// `delete next-hop` — only valid while navigated into a peer-group.
    NextHop,
    /// `delete route-reflector-client` — only valid while navigated into a
    /// peer-group.
    RouteReflectorClient,
    /// `delete route-server-client` — only valid while navigated into a
    /// peer-group.
    RouteServerClient,
    /// `delete import-policy` — only valid while navigated into a
    /// peer-group.
    ImportPolicy,
    /// `delete export-policy` — only valid while navigated into a
    /// peer-group.
    ExportPolicy,
    /// `delete bgp instance <name> cluster-id` — qualified clear.
    BgpInstanceClusterId {
        name: String,
    },
    /// `delete cluster-id` — relative clear, only valid while navigated into
    /// a BGP instance.
    BgpInstanceClusterIdRelative,
    RoutingTable {
        name: String,
    },
    /// `delete routing-table <name> bgp-instance` — qualified clear.
    RoutingTableBgpInstance {
        name: String,
    },
    /// `delete bgp-instance` — relative clear, only valid while navigated
    /// into a routing table.
    RoutingTableBgpInstanceRelative,
    /// `delete routing-table <name> static-routing-instance` — qualified
    /// clear.
    RoutingTableStaticRoutingInstance {
        name: String,
    },
    /// `delete static-routing-instance` — relative clear, only valid while
    /// navigated into a routing table.
    RoutingTableStaticRoutingInstanceRelative,
    /// `delete routing-table <name> ospf-instance` — qualified clear.
    RoutingTableOspfInstance {
        name: String,
    },
    /// `delete ospf-instance` — relative clear, only valid while navigated
    /// into a routing table.
    RoutingTableOspfInstanceRelative,
    /// `delete routing-table <name> ospfv3-instance` — qualified clear.
    RoutingTableOspfv3Instance {
        name: String,
    },
    /// `delete ospfv3-instance` — relative clear, only valid while navigated
    /// into a routing table.
    RoutingTableOspfv3InstanceRelative,
    /// `delete routing-table <name> rest-api` — qualified clear.
    RoutingTableRestApi {
        name: String,
    },
    /// `delete rest-api` — relative clear, only valid while navigated into a
    /// routing table.
    RoutingTableRestApiRelative,
    OspfInstance {
        name: String,
    },
    /// `delete ospf instance <name> area <area-id>` — qualified.
    OspfArea {
        instance: String,
        area_id: Ipv4Addr,
    },
    /// `delete area <area-id>` — relative, only valid while navigated into
    /// an OSPF instance.
    OspfAreaRelative {
        area_id: Ipv4Addr,
    },
    /// `delete ospf instance <name> area <area-id> profile <profile-name>`
    /// — qualified.
    OspfProfile {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
    },
    /// `delete profile <profile-name>` — relative, only valid while
    /// navigated into an OSPF area.
    OspfProfileRelative {
        name: String,
    },
    /// `delete ospfv3 instance <name>` — qualified.
    Ospfv3Instance {
        name: String,
    },
    /// `delete ospfv3 instance <name> extended-lsa` — RFC 8362 Full mode off.
    Ospfv3InstanceExtendedLsa {
        name: String,
    },
    /// `delete ospfv3 instance <name> area <area-id>` — qualified.
    Ospfv3Area {
        instance: String,
        area_id: Ipv4Addr,
    },
    /// `delete ospfv3 instance <name> area <area-id> profile <profile-name>`
    /// — qualified.
    Ospfv3Profile {
        instance: String,
        area_id: Ipv4Addr,
        name: String,
    },
    /// `delete hello-interval` — only valid while navigated into an
    /// `OspfProfile` or an `Ospfv3Profile` (disambiguated by path).
    HelloInterval,
    /// `delete dead-interval` — only valid while navigated into an
    /// `OspfProfile`.
    DeadInterval,
    /// `delete cost` — only valid while navigated into an `OspfProfile`.
    Cost,
    /// `delete priority` — only valid while navigated into an
    /// `OspfProfile`.
    Priority,
    /// `delete network-type` — only valid while navigated into an
    /// `OspfProfile`.
    NetworkType,
    /// `delete mtu` — ambiguous by token alone, shared between a physical
    /// interface's own mtu and an `OspfProfile`'s mtu override, resolved by
    /// `path` at resolve time (mirrors `SetTarget::MtuRelative`).
    MtuRelative,
    /// `delete routing-table <name> redistribute` — qualified clear.
    RoutingTableRedistribute {
        name: String,
    },
    /// `delete redistribute` — relative clear, only valid while navigated
    /// into a routing table.
    RoutingTableRedistributeRelative,
    StaticRoutingInstance {
        name: String,
    },
    StaticRoute {
        instance: String,
        subnet: IpNet,
    },
    /// Only valid while navigated into a static routing instance.
    StaticRouteRelative {
        subnet: IpNet,
    },
    Interface {
        name: String,
    },
    /// `delete interface <name> address <cidr>` — qualified.
    InterfaceAddress {
        name: String,
        address: IpNet,
    },
    /// `delete address <cidr>` — relative, only valid while navigated into
    /// an interface.
    InterfaceAddressRelative {
        address: IpNet,
    },
    /// `delete interface <name> routing-table` — qualified clear.
    InterfaceRoutingTable {
        name: String,
    },
    /// `delete routing-table` — relative clear, only valid while navigated
    /// into an interface.
    InterfaceRoutingTableRelative,
    /// `delete interface <name> mtu` — qualified clear.
    InterfaceMtu {
        name: String,
    },
    /// `delete interface <name> lldp transmit|receive` — qualified disable.
    InterfaceLldp {
        name: String,
        direction: LldpDirection,
    },
    /// `delete lldp transmit|receive` — relative disable, only valid while
    /// navigated into an interface.
    InterfaceLldpRelative {
        direction: LldpDirection,
    },
    /// `delete interface <name> lldp destination` — qualified reset.
    InterfaceLldpDestination {
        name: String,
    },
    /// `delete lldp destination` — relative reset.
    InterfaceLldpDestinationRelative,
    /// `delete lldp tx-interval|tx-hold|management-address`.
    Lldp(LldpSettingKind),
    /// `delete interface <name> switching-profile` — qualified clear.
    InterfaceSwitchingProfile {
        name: String,
    },
    /// `delete switching-profile` — relative clear, only valid while
    /// navigated into an interface.
    InterfaceSwitchingProfileRelative,
    /// `delete interface <name> ospf` — qualified clear.
    InterfaceOspfProfile {
        name: String,
    },
    /// `delete ospf` — relative clear, only valid while navigated into a
    /// loopback interface, a subinterface, or a broadcast domain.
    InterfaceOspfProfileRelative,
    /// `delete interface <name> ospfv3` — qualified clear.
    InterfaceOspfv3Profile {
        name: String,
    },
    /// `delete ospfv3` — relative clear, only valid while navigated into a
    /// loopback interface, a subinterface, or a broadcast domain.
    InterfaceOspfv3ProfileRelative,
    CommunityAlias {
        name: String,
    },
    CommunityGroup {
        name: String,
    },
    /// `delete community-group <name> member <m>` — qualified.
    CommunityGroupMember {
        name: String,
        member: String,
    },
    /// `delete member <m>` — relative, only valid while navigated into a
    /// community-group.
    CommunityGroupMemberRelative {
        member: String,
    },
    PrefixList {
        name: String,
    },
    /// `delete prefix-list <name> entry <cidr> [range <min> <max>]` —
    /// qualified.
    PrefixListEntry {
        name: String,
        cidr: IpNet,
        range: Option<(u8, u8)>,
    },
    /// `delete entry <cidr> [range <min> <max>]` — relative, only valid
    /// while navigated into a prefix-list.
    PrefixListEntryRelative {
        cidr: IpNet,
        range: Option<(u8, u8)>,
    },
    BroadcastDomain {
        name: String,
    },
    /// `delete broadcast domain <name> address <cidr>` — qualified.
    BroadcastDomainAddress {
        name: String,
        address: IpNet,
    },
    /// `delete broadcast domain <name> routing-table` — qualified clear.
    BroadcastDomainRoutingTable {
        name: String,
    },
    /// The `delete` counterpart of `SetTarget::BroadcastDomainEvpn`.
    BroadcastDomainEvpn(BroadcastDomainOp),
    /// The `delete` counterpart of `SetTarget::PortAggregateField`.
    PortAggregateField(PortAggregateOp),
    /// Context-relative — the aggregate comes from `path` at resolve time.
    PortAggregateEsiRelative,
    /// Context-relative — the aggregate comes from `path` at resolve time.
    PortAggregateLacpSystemIdRelative,
    SwitchingProfile {
        name: String,
    },
    /// `delete switching-profile <name> broadcast-domain <domain>` —
    /// qualified.
    SwitchingProfileMember {
        name: String,
        broadcast_domain: String,
    },
    /// `delete broadcast-domain <domain>` — relative, only valid while
    /// navigated into a switching profile.
    SwitchingProfileMemberRelative {
        broadcast_domain: String,
    },
    PortAggregate {
        name: String,
    },
    /// `delete interface <name> port-aggregate` — qualified clear.
    InterfacePortAggregate {
        name: String,
    },
    /// `delete port-aggregate` — relative clear, only valid while navigated
    /// into an interface (clears its membership, not the aggregate itself —
    /// use `delete port-aggregate <name>` for that).
    InterfacePortAggregateRelative,
}

/// A parsed REPL input line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    ShowConfig,
    /// `show this` — only meaningful in configuration mode.
    Show,
    /// `show route <table>` (whole table) or `show route <table> <address>`
    /// (longest-prefix-match lookup).
    ShowRoute {
        table: String,
        address: Option<IpAddr>,
    },
    /// `show fdb <domain>` — one broadcast domain's forwarding database.
    ShowFdb {
        domain: String,
    },
    /// `show interface` (every interface) or `show interface <name>` (one).
    ShowInterface {
        name: Option<String>,
    },
    /// `show port-aggregate` (every aggregate) or `show port-aggregate
    /// <name>` (one).
    ShowPortAggregate {
        name: Option<String>,
    },
    /// `show lacp` (every aggregate) or `show lacp <name>` (one).
    ShowLacp {
        name: Option<String>,
    },
    /// `show lldp neighbors` — every LLDP neighbor heard on any interface.
    ShowLldpNeighbors,
    /// `show log [<source>] [--follow]` — a one-shot buffer snapshot,
    /// optionally filtered to one source, or a live tail with `--follow`.
    ShowLog {
        source: Option<String>,
        follow: bool,
    },
    /// `show bgp brief` — a one-line-per-peer session summary across every
    /// configured BGP instance.
    ShowBgpBrief,
    /// `show bgp evpn` — every EVPN route received by every configured BGP
    /// instance.
    ShowBgpEvpn,
    /// `show ospf neigh` — a one-line-per-link neighbor summary across every
    /// configured OSPF instance.
    ShowOspfNeigh,
    /// `show ospf database` — every installed LSA's header, across every
    /// configured OSPF instance.
    ShowOspfDatabase,
    /// `show ospfv3 neigh` — mirrors `ShowOspfNeigh`, across every
    /// configured `Ospfv3Instance`.
    ShowOspfv3Neigh,
    /// `show ospfv3 database` — mirrors `ShowOspfDatabase`, across every
    /// configured `Ospfv3Instance`.
    ShowOspfv3Database,
    /// `clear bgp <instance> <peer> soft-in` — ask `<peer>`'s live session
    /// on `<instance>` to resend its routes (RFC 2918 route refresh).
    ClearBgpSoftIn {
        instance: String,
        peer: IpAddr,
    },
    Save,
    Help,
    /// `exit` | `quit` | `end`
    Exit,
    Configure {
        name: String,
        /// `None` when `from ...` was omitted (defaults to `Current`).
        base: Option<TransactionBase>,
    },
    Edit(EditTarget),
    Set(SetTarget),
    Delete(DeleteTarget),
    /// `edit source` — only valid while navigated into a policy-definition;
    /// opens `$EDITOR`/`$VISUAL`/`nano` on its current source. See root
    /// `CLAUDE.md`'s "nos-cli editing UX".
    EditSource,
    /// `show source` — only valid while navigated into a policy-definition.
    ShowSource,
    /// `set source line <n> <text>` — only valid while navigated into a
    /// policy-definition. `<text>` is the raw remainder of the line
    /// (leading whitespace preserved) since RPL's indentation is
    /// semantically meaningful — parsed outside the generic
    /// `split_whitespace()` matcher below, see `parse`'s doc comment.
    SetSourceLine {
        line: usize,
        text: String,
    },
    /// `delete source line <n>` — only valid while navigated into a
    /// policy-definition.
    DeleteSourceLine {
        line: usize,
    },
    Up,
    Top,
    Commit,
    /// `discard` | `abort`
    Discard,
    /// `diff` — only meaningful in configuration mode.
    Diff,
    Empty,
    Unknown(String),
}

fn parse_redundancy_mode(token: &str) -> EsRedundancy {
    if token == "single-active" {
        EsRedundancy::SingleActive
    } else {
        EsRedundancy::AllActive
    }
}

fn parse_lacp_rate(token: &str) -> LacpRate {
    if token == "fast" {
        LacpRate::Fast
    } else {
        LacpRate::Slow
    }
}

impl Command {
    pub fn parse(line: &str) -> Self {
        let trimmed = line.trim();
        parse_inner(trimmed).unwrap_or_else(|| Command::Unknown(trimmed.to_string()))
    }
}

/// The command table. Anything that doesn't match a row — an unknown token
/// sequence, or an argument that fails to parse — returns `None`, which
/// `Command::parse` turns into the one `Command::Unknown`. That is why no row
/// here spells out its own failure case.
fn parse_inner(trimmed: &str) -> Option<Command> {
    // `set source line <n> <text>` is the one command whose value must
    // preserve leading whitespace verbatim — RPL's indentation is
    // semantically meaningful — so it's parsed here, before the generic
    // `split_whitespace()` matcher below would otherwise collapse it.
    if let Some(rest) = trimmed.strip_prefix("set source line ") {
        let space_idx = rest.find(' ')?;
        return Some(Command::SetSourceLine {
            line: rest[..space_idx].parse::<usize>().ok()?,
            text: rest[space_idx + 1..].to_string(),
        });
    }
    match trimmed.split_whitespace().collect::<Vec<_>>().as_slice() {
        ["show", rest @ ..] => parse_show(rest),
        ["edit", rest @ ..] => parse_edit(rest),
        ["set", rest @ ..] => parse_set(rest),
        ["delete", rest @ ..] => parse_delete(rest),
        rest => parse_bare(rest),
    }
}

/// Read-only `show` commands. Valid in any mode; none of them touch a transaction.
fn parse_show(t: &[&str]) -> Option<Command> {
    Some(match t {
        ["config"] => Command::ShowConfig,
        ["this"] => Command::Show,
        ["route", table] => Command::ShowRoute {
            table: (*table).to_string(),
            address: None,
        },
        ["route", table, addr] => Command::ShowRoute {
            table: (*table).to_string(),
            address: Some(addr.parse::<IpAddr>().ok()?),
        },
        ["fdb", domain] => Command::ShowFdb {
            domain: (*domain).to_string(),
        },
        ["interface"] => Command::ShowInterface { name: None },
        ["interface", name] => Command::ShowInterface {
            name: Some((*name).to_string()),
        },
        ["port-aggregate"] => Command::ShowPortAggregate { name: None },
        ["port-aggregate", name] => Command::ShowPortAggregate {
            name: Some((*name).to_string()),
        },
        ["lldp", "neighbors"] => Command::ShowLldpNeighbors,
        ["lacp"] => Command::ShowLacp { name: None },
        ["lacp", name] => Command::ShowLacp {
            name: Some((*name).to_string()),
        },
        ["log"] => Command::ShowLog {
            source: None,
            follow: false,
        },
        ["log", "--follow"] => Command::ShowLog {
            source: None,
            follow: true,
        },
        ["log", source] => Command::ShowLog {
            source: Some((*source).to_string()),
            follow: false,
        },
        ["log", source, "--follow"] => Command::ShowLog {
            source: Some((*source).to_string()),
            follow: true,
        },
        ["bgp", "brief"] => Command::ShowBgpBrief,
        ["bgp", "evpn"] => Command::ShowBgpEvpn,
        ["ospf", "neigh"] => Command::ShowOspfNeigh,
        ["ospf", "database"] => Command::ShowOspfDatabase,
        ["ospfv3", "neigh"] => Command::ShowOspfv3Neigh,
        ["ospfv3", "database"] => Command::ShowOspfv3Database,
        ["source"] => Command::ShowSource,
        _ => return None,
    })
}

/// `edit` — create-if-missing, then navigate into the object.
fn parse_edit(t: &[&str]) -> Option<Command> {
    Some(match t {
        ["bgp", "instance", name] => Command::Edit(EditTarget::BgpInstance {
            name: (*name).to_string(),
        }),
        ["bgp", "instance", instance, "peer-group", group] => {
            Command::Edit(EditTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                name: (*group).to_string(),
            })
        }
        ["peer-group", group] => Command::Edit(EditTarget::PeerGroupRelative {
            name: (*group).to_string(),
        }),
        ["routing-table", name] => Command::Edit(EditTarget::RoutingTable {
            name: (*name).to_string(),
        }),
        ["ospf", "instance", name] => Command::Edit(EditTarget::OspfInstance {
            name: (*name).to_string(),
        }),
        ["ospf", "instance", instance, "area", area_id] => Command::Edit(EditTarget::OspfArea {
            instance: (*instance).to_string(),
            area_id: area_id.parse::<Ipv4Addr>().ok()?,
        }),
        ["area", area_id] => Command::Edit(EditTarget::OspfAreaRelative {
            area_id: area_id.parse::<Ipv4Addr>().ok()?,
        }),
        ["ospf", "instance", instance, "area", area_id, "profile", name] => {
            Command::Edit(EditTarget::OspfProfile {
                instance: (*instance).to_string(),
                area_id: area_id.parse::<Ipv4Addr>().ok()?,
                name: (*name).to_string(),
            })
        }
        ["profile", name] => Command::Edit(EditTarget::OspfProfileRelative {
            name: (*name).to_string(),
        }),
        ["ospfv3", "instance", name] => Command::Edit(EditTarget::Ospfv3Instance {
            name: (*name).to_string(),
        }),
        ["ospfv3", "instance", instance, "area", area_id] => {
            Command::Edit(EditTarget::Ospfv3Area {
                instance: (*instance).to_string(),
                area_id: area_id.parse::<Ipv4Addr>().ok()?,
            })
        }
        ["ospfv3", "instance", instance, "area", area_id, "profile", name] => {
            Command::Edit(EditTarget::Ospfv3Profile {
                instance: (*instance).to_string(),
                area_id: area_id.parse::<Ipv4Addr>().ok()?,
                name: (*name).to_string(),
            })
        }
        ["static-routing-instance", name] => Command::Edit(EditTarget::StaticRoutingInstance {
            name: (*name).to_string(),
        }),
        ["interface", name] => Command::Edit(EditTarget::Interface {
            name: (*name).to_string(),
        }),
        ["policy-definition", name] => Command::Edit(EditTarget::PolicyDefinition {
            name: (*name).to_string(),
        }),
        ["community-alias", name] => Command::Edit(EditTarget::CommunityAlias {
            name: (*name).to_string(),
        }),
        ["community-group", name] => Command::Edit(EditTarget::CommunityGroup {
            name: (*name).to_string(),
        }),
        ["prefix-list", name] => Command::Edit(EditTarget::PrefixList {
            name: (*name).to_string(),
        }),
        ["broadcast", "domain", name] => Command::Edit(EditTarget::BroadcastDomain {
            name: (*name).to_string(),
        }),
        ["switching-profile", name] => Command::Edit(EditTarget::SwitchingProfile {
            name: (*name).to_string(),
        }),
        ["port-aggregate", name] => Command::Edit(EditTarget::PortAggregate {
            name: (*name).to_string(),
        }),
        ["source"] => Command::EditSource,
        _ => return None,
    })
}

/// `set` — every field assignment, in both its fully-qualified and its
/// path-relative form.
/// The tail of `set broadcast domain <name> ...` for the EVPN fields.
fn broadcast_domain_evpn_set(name: &str, rest: &[&str]) -> Option<BroadcastDomainOp> {
    let name = name.to_string();
    Some(match rest {
        ["vni", n] => BroadcastDomainOp::SetVni {
            name,
            vni: n.parse().ok()?,
        },
        ["rd", rd] => BroadcastDomainOp::SetRd {
            name,
            rd: (*rd).to_string(),
        },
        ["route-target", dir @ ("import" | "export"), rt] => BroadcastDomainOp::AddRouteTarget {
            name,
            import: *dir == "import",
            route_target: (*rt).to_string(),
        },
        ["vtep-source", "interface", ifname] => BroadcastDomainOp::SetVtepSource {
            name,
            vtep_source: SourceAddress::Interface {
                interface: (*ifname).to_string(),
                label: None,
            },
        },
        ["vtep-source", "interface", ifname, "label", label] => BroadcastDomainOp::SetVtepSource {
            name,
            vtep_source: SourceAddress::Interface {
                interface: (*ifname).to_string(),
                label: Some((*label).to_string()),
            },
        },
        ["vtep-source", "loopback"] => BroadcastDomainOp::SetVtepSource {
            name,
            vtep_source: SourceAddress::Loopback { label: None },
        },
        ["vtep-source", "loopback", "label", label] => BroadcastDomainOp::SetVtepSource {
            name,
            vtep_source: SourceAddress::Loopback {
                label: Some((*label).to_string()),
            },
        },
        ["redistribute", "from", "mac", "to", "bgp", instance] => {
            BroadcastDomainOp::SetMacRedistribute {
                name,
                bgp_instance: (*instance).to_string(),
            }
        }
        ["redistribute", "from", "arp", "to", "bgp", instance] => {
            BroadcastDomainOp::SetArpRedistribute {
                name,
                bgp_instance: (*instance).to_string(),
            }
        }
        ["redistribute", "from", "connected", "to", "bgp", instance] => {
            BroadcastDomainOp::SetConnectedRedistribute {
                name,
                bgp_instance: (*instance).to_string(),
            }
        }
        _ => return None,
    })
}

/// The tail of `delete broadcast domain <name> ...` for the EVPN fields.
fn broadcast_domain_evpn_delete(name: &str, rest: &[&str]) -> Option<BroadcastDomainOp> {
    let name = name.to_string();
    Some(match rest {
        ["vni"] => BroadcastDomainOp::ClearVni { name },
        ["rd"] => BroadcastDomainOp::ClearRd { name },
        ["route-target", dir @ ("import" | "export"), rt] => BroadcastDomainOp::RemoveRouteTarget {
            name,
            import: *dir == "import",
            route_target: (*rt).to_string(),
        },
        ["vtep-source"] => BroadcastDomainOp::ClearVtepSource { name },
        ["redistribute"] | ["redistribute", "from", "mac"] => {
            BroadcastDomainOp::ClearMacRedistribute { name }
        }
        ["redistribute", "from", "arp"] => BroadcastDomainOp::ClearArpRedistribute { name },
        ["redistribute", "from", "connected"] => {
            BroadcastDomainOp::ClearConnectedRedistribute { name }
        }
        _ => return None,
    })
}

/// The tail of `set port-aggregate <name> ...` for the ESI / LACP system-id fields.
fn port_aggregate_field_set(name: &str, rest: &[&str]) -> Option<PortAggregateOp> {
    let name = name.to_string();
    Some(match rest {
        ["esi", esi] => PortAggregateOp::SetEsi {
            name,
            esi: (*esi).to_string(),
        },
        ["lacp-system-id", id] => PortAggregateOp::SetLacpSystemId {
            name,
            system_id: (*id).to_string(),
        },
        _ => return None,
    })
}

/// The tail of `delete port-aggregate <name> ...`.
fn port_aggregate_field_delete(name: &str, rest: &[&str]) -> Option<PortAggregateOp> {
    let name = name.to_string();
    Some(match rest {
        ["esi"] => PortAggregateOp::ClearEsi { name },
        ["lacp-system-id"] => PortAggregateOp::ClearLacpSystemId { name },
        _ => return None,
    })
}

/// The free-text tail of `shutdown [<message>]`; `None` when omitted.
fn join_message(words: &[&str]) -> Option<String> {
    (!words.is_empty()).then(|| words.join(" "))
}

fn parse_set(t: &[&str]) -> Option<Command> {
    Some(match t {
        ["bgp", "instance", name, "asn", n] => Command::Set(SetTarget::BgpInstance {
            name: (*name).to_string(),
            field: BgpInstanceField::Asn(n.parse::<u32>().ok()?),
        }),
        ["bgp", "instance", name, "router-id", ip] => Command::Set(SetTarget::BgpInstance {
            name: (*name).to_string(),
            field: BgpInstanceField::RouterId(ip.parse::<Ipv4Addr>().ok()?),
        }),
        ["bgp", "instance", name, "cluster-id", ip] => Command::Set(SetTarget::BgpInstance {
            name: (*name).to_string(),
            field: BgpInstanceField::ClusterId(ip.parse::<Ipv4Addr>().ok()?),
        }),
        ["asn", n] => Command::Set(SetTarget::Relative {
            field: BgpInstanceField::Asn(n.parse::<u32>().ok()?),
        }),
        ["router-id", ip] => Command::Set(SetTarget::Relative {
            field: BgpInstanceField::RouterId(ip.parse::<Ipv4Addr>().ok()?),
        }),
        ["cluster-id", ip] => Command::Set(SetTarget::Relative {
            field: BgpInstanceField::ClusterId(ip.parse::<Ipv4Addr>().ok()?),
        }),
        ["hostname", name] => Command::Set(SetTarget::Hostname((*name).to_string())),
        ["user", name, "password", password] => Command::Set(SetTarget::UserPassword {
            name: (*name).to_string(),
            password: (*password).to_string(),
        }),
        ["bgp", "instance", instance, "peer-group", group, "remote-as", n] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::RemoteAs(n.parse::<u32>().ok()?),
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "source-address", "interface", ifname] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::SourceAddress(SourceAddress::Interface {
                    interface: (*ifname).to_string(),
                    label: None,
                }),
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "source-address", "interface", ifname, "label", label] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::SourceAddress(SourceAddress::Interface {
                    interface: (*ifname).to_string(),
                    label: Some((*label).to_string()),
                }),
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "source-address", "loopback"] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::SourceAddress(SourceAddress::Loopback { label: None }),
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "source-address", "loopback", "label", label] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::SourceAddress(SourceAddress::Loopback {
                    label: Some((*label).to_string()),
                }),
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "address-family", "ipv4"] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::AddressFamily(AddressFamily::Ipv4Unicast),
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "address-family", "ipv6"] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::AddressFamily(AddressFamily::Ipv6Unicast),
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "address-family", "l2vpn-evpn"] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::AddressFamily(AddressFamily::L2vpnEvpn),
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "hold-time", n] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::HoldTime(n.parse::<u16>().ok()?),
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "keepalive-interval", n] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::KeepaliveInterval(n.parse::<u16>().ok()?),
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "connect-retry-time", n] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::ConnectRetryTime(n.parse::<u16>().ok()?),
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "max-hops", n] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::MaxHops(n.parse::<u8>().ok()?),
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "mrai", n] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::Mrai(n.parse::<u16>().ok()?),
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "shutdown", msg @ ..] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::Shutdown(join_message(msg)),
            })
        }
        ["bgp", "instance", instance, "peer", ip, "shutdown", msg @ ..] => {
            Command::Set(SetTarget::BgpPeerShutdown {
                instance: (*instance).to_string(),
                remote_address: ip.parse::<IpAddr>().ok()?,
                message: join_message(msg),
            })
        }
        ["peer", ip, "shutdown", msg @ ..] => Command::Set(SetTarget::PeerShutdownRelative {
            remote_address: ip.parse::<IpAddr>().ok()?,
            message: join_message(msg),
        }),
        ["shutdown", msg @ ..] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::Shutdown(join_message(msg)),
        }),
        ["bgp", "instance", instance, "peer-group", group, "damping", rest @ ..] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::Damping(parse_damping(rest)?),
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "next-hop", "self"] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::NextHop(NextHopMode::SelfAddress),
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "next-hop", "unchanged"] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::NextHop(NextHopMode::Unchanged),
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "route-reflector-client"] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::RouteReflectorClient,
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "route-server-client"] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::RouteServerClient,
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "import-policy", name] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::ImportPolicy((*name).to_string()),
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "export-policy", name] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::ExportPolicy((*name).to_string()),
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "md5-password", password] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::Md5Password((*password).to_string()),
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "ao-key", send_id, recv_id, algorithm, key] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::AoKey {
                    send_id: send_id.parse::<u8>().ok()?,
                    recv_id: recv_id.parse::<u8>().ok()?,
                    algorithm: parse_ao_algorithm(algorithm)?,
                    key: (*key).to_string(),
                },
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "ao-key", send_id, "current"] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::AoCurrentKey(send_id.parse::<u8>().ok()?),
            })
        }
        ["bgp", "instance", instance, "peer-group", group, "ao-key", send_id, "rnext"] => {
            Command::Set(SetTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                group: (*group).to_string(),
                field: BgpPeerGroupField::AoRnextKey(send_id.parse::<u8>().ok()?),
            })
        }
        ["remote-as", n] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::RemoteAs(n.parse::<u32>().ok()?),
        }),
        ["source-address", "interface", ifname] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::SourceAddress(SourceAddress::Interface {
                interface: (*ifname).to_string(),
                label: None,
            }),
        }),
        ["source-address", "interface", ifname, "label", label] => {
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::SourceAddress(SourceAddress::Interface {
                    interface: (*ifname).to_string(),
                    label: Some((*label).to_string()),
                }),
            })
        }
        ["source-address", "loopback"] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::SourceAddress(SourceAddress::Loopback { label: None }),
        }),
        ["source-address", "loopback", "label", label] => {
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::SourceAddress(SourceAddress::Loopback {
                    label: Some((*label).to_string()),
                }),
            })
        }
        ["address-family", "ipv4"] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::AddressFamily(AddressFamily::Ipv4Unicast),
        }),
        ["address-family", "ipv6"] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::AddressFamily(AddressFamily::Ipv6Unicast),
        }),
        ["address-family", "l2vpn-evpn"] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::AddressFamily(AddressFamily::L2vpnEvpn),
        }),
        ["next-hop", "self"] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::NextHop(NextHopMode::SelfAddress),
        }),
        ["next-hop", "unchanged"] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::NextHop(NextHopMode::Unchanged),
        }),
        ["route-reflector-client"] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::RouteReflectorClient,
        }),
        ["route-server-client"] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::RouteServerClient,
        }),
        ["import-policy", name] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::ImportPolicy((*name).to_string()),
        }),
        ["export-policy", name] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::ExportPolicy((*name).to_string()),
        }),
        ["hold-time", n] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::HoldTime(n.parse::<u16>().ok()?),
        }),
        ["keepalive-interval", n] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::KeepaliveInterval(n.parse::<u16>().ok()?),
        }),
        ["connect-retry-time", n] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::ConnectRetryTime(n.parse::<u16>().ok()?),
        }),
        ["max-hops", n] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::MaxHops(n.parse::<u8>().ok()?),
        }),
        ["mrai", n] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::Mrai(n.parse::<u16>().ok()?),
        }),
        ["damping", rest @ ..] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::Damping(parse_damping(rest)?),
        }),
        ["md5-password", password] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::Md5Password((*password).to_string()),
        }),
        ["ao-key", send_id, recv_id, algorithm, key] => {
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::AoKey {
                    send_id: send_id.parse::<u8>().ok()?,
                    recv_id: recv_id.parse::<u8>().ok()?,
                    algorithm: parse_ao_algorithm(algorithm)?,
                    key: (*key).to_string(),
                },
            })
        }
        ["ao-key", send_id, "current"] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::AoCurrentKey(send_id.parse::<u8>().ok()?),
        }),
        ["ao-key", send_id, "rnext"] => Command::Set(SetTarget::PeerGroupRelative {
            field: BgpPeerGroupField::AoRnextKey(send_id.parse::<u8>().ok()?),
        }),
        ["bgp", "instance", instance, "peer", ip, "peer-group", group] => {
            Command::Set(SetTarget::BgpPeer {
                instance: (*instance).to_string(),
                remote_address: ip.parse::<IpAddr>().ok()?,
                peer_group: (*group).to_string(),
            })
        }
        ["peer", ip, "peer-group", group] => Command::Set(SetTarget::PeerRelative {
            remote_address: ip.parse::<IpAddr>().ok()?,
            peer_group: (*group).to_string(),
        }),
        ["routing-table", name, "bgp-instance", instance] => {
            Command::Set(SetTarget::RoutingTable {
                name: (*name).to_string(),
                bgp_instance: (*instance).to_string(),
            })
        }
        ["bgp-instance", instance] => Command::Set(SetTarget::RoutingTableRelative {
            bgp_instance: (*instance).to_string(),
        }),
        ["routing-table", name, "static-routing-instance", instance] => {
            Command::Set(SetTarget::RoutingTableStaticRoutingInstance {
                name: (*name).to_string(),
                static_routing_instance: (*instance).to_string(),
            })
        }
        ["static-routing-instance", instance] => {
            Command::Set(SetTarget::RoutingTableStaticRoutingInstanceRelative {
                static_routing_instance: (*instance).to_string(),
            })
        }
        ["routing-table", name, "ospf-instance", instance] => {
            Command::Set(SetTarget::RoutingTableOspfInstance {
                name: (*name).to_string(),
                ospf_instance: (*instance).to_string(),
            })
        }
        ["ospf-instance", instance] => Command::Set(SetTarget::RoutingTableOspfInstanceRelative {
            ospf_instance: (*instance).to_string(),
        }),
        ["routing-table", name, "ospfv3-instance", instance] => {
            Command::Set(SetTarget::RoutingTableOspfv3Instance {
                name: (*name).to_string(),
                ospfv3_instance: (*instance).to_string(),
            })
        }
        ["ospfv3-instance", instance] => {
            Command::Set(SetTarget::RoutingTableOspfv3InstanceRelative {
                ospfv3_instance: (*instance).to_string(),
            })
        }
        ["routing-table", name, "rest-api", "address", address] => {
            Command::Set(SetTarget::RoutingTableRestApi {
                name: (*name).to_string(),
                address: address.parse().ok()?,
                port: REST_API_PORT_DEFAULT,
            })
        }
        ["routing-table", name, "rest-api", "address", address, "port", port] => {
            Command::Set(SetTarget::RoutingTableRestApi {
                name: (*name).to_string(),
                address: address.parse().ok()?,
                port: port.parse().ok()?,
            })
        }
        ["rest-api", "address", address] => Command::Set(SetTarget::RoutingTableRestApiRelative {
            address: address.parse().ok()?,
            port: REST_API_PORT_DEFAULT,
        }),
        ["rest-api", "address", address, "port", port] => {
            Command::Set(SetTarget::RoutingTableRestApiRelative {
                address: address.parse().ok()?,
                port: port.parse().ok()?,
            })
        }
        ["ospf", "instance", name, "router-id", ip] => Command::Set(SetTarget::OspfInstance {
            name: (*name).to_string(),
            router_id: ip.parse::<Ipv4Addr>().ok()?,
        }),
        ["ospfv3", "instance", name, "extended-lsa"] => {
            Command::Set(SetTarget::Ospfv3InstanceExtendedLsa {
                name: (*name).to_string(),
            })
        }
        ["ospfv3", "instance", name, "router-id", ip] => Command::Set(SetTarget::Ospfv3Instance {
            name: (*name).to_string(),
            router_id: ip.parse::<Ipv4Addr>().ok()?,
        }),
        ["routing-table", name, "redistribute", "from", "static", "to", "bgp"] => {
            Command::Set(SetTarget::RoutingTableRedistribute {
                name: (*name).to_string(),
                redistribute: Redistribute {
                    from: RedistributeSource::Static,
                    to: RedistributeTarget::Bgp,
                    policy: None,
                },
            })
        }
        ["routing-table", name, "redistribute", "from", "static", "to", "bgp", "policy", policy] => {
            Command::Set(SetTarget::RoutingTableRedistribute {
                name: (*name).to_string(),
                redistribute: Redistribute {
                    from: RedistributeSource::Static,
                    to: RedistributeTarget::Bgp,
                    policy: Some((*policy).to_string()),
                },
            })
        }
        ["redistribute", "from", "static", "to", "bgp"] => {
            Command::Set(SetTarget::RoutingTableRedistributeRelative {
                redistribute: Redistribute {
                    from: RedistributeSource::Static,
                    to: RedistributeTarget::Bgp,
                    policy: None,
                },
            })
        }
        ["redistribute", "from", "static", "to", "bgp", "policy", policy] => {
            Command::Set(SetTarget::RoutingTableRedistributeRelative {
                redistribute: Redistribute {
                    from: RedistributeSource::Static,
                    to: RedistributeTarget::Bgp,
                    policy: Some((*policy).to_string()),
                },
            })
        }
        ["routing-table", name, "redistribute", "from", "static", "to", "ospf"] => {
            Command::Set(SetTarget::RoutingTableRedistribute {
                name: (*name).to_string(),
                redistribute: Redistribute {
                    from: RedistributeSource::Static,
                    to: RedistributeTarget::Ospf,
                    policy: None,
                },
            })
        }
        ["routing-table", name, "redistribute", "from", "static", "to", "ospf", "policy", policy] => {
            Command::Set(SetTarget::RoutingTableRedistribute {
                name: (*name).to_string(),
                redistribute: Redistribute {
                    from: RedistributeSource::Static,
                    to: RedistributeTarget::Ospf,
                    policy: Some((*policy).to_string()),
                },
            })
        }
        ["redistribute", "from", "static", "to", "ospf"] => {
            Command::Set(SetTarget::RoutingTableRedistributeRelative {
                redistribute: Redistribute {
                    from: RedistributeSource::Static,
                    to: RedistributeTarget::Ospf,
                    policy: None,
                },
            })
        }
        ["redistribute", "from", "static", "to", "ospf", "policy", policy] => {
            Command::Set(SetTarget::RoutingTableRedistributeRelative {
                redistribute: Redistribute {
                    from: RedistributeSource::Static,
                    to: RedistributeTarget::Ospf,
                    policy: Some((*policy).to_string()),
                },
            })
        }
        ["static-routing-instance", name, "route", subnet, "gateway", addr] => {
            Command::Set(SetTarget::StaticRoute {
                instance: (*name).to_string(),
                subnet: subnet.parse::<IpNet>().ok()?,
                gateway: addr.parse::<IpAddr>().ok()?,
            })
        }
        ["route", subnet, "gateway", addr] => Command::Set(SetTarget::StaticRouteRelative {
            subnet: subnet.parse::<IpNet>().ok()?,
            gateway: addr.parse::<IpAddr>().ok()?,
        }),
        ["interface", name, "address", addr] => Command::Set(SetTarget::InterfaceAddress {
            name: (*name).to_string(),
            address: addr.parse::<IpNet>().ok()?,
            label: None,
        }),
        ["interface", name, "address", addr, "label", label] => {
            Command::Set(SetTarget::InterfaceAddress {
                name: (*name).to_string(),
                address: addr.parse::<IpNet>().ok()?,
                label: Some((*label).to_string()),
            })
        }
        ["address", addr] => Command::Set(SetTarget::InterfaceAddressRelative {
            address: addr.parse::<IpNet>().ok()?,
            label: None,
        }),
        ["address", addr, "label", label] => Command::Set(SetTarget::InterfaceAddressRelative {
            address: addr.parse::<IpNet>().ok()?,
            label: Some((*label).to_string()),
        }),
        ["interface", name, "routing-table", table] => {
            Command::Set(SetTarget::InterfaceRoutingTable {
                name: (*name).to_string(),
                routing_table: (*table).to_string(),
            })
        }
        ["routing-table", table] => Command::Set(SetTarget::InterfaceRoutingTableRelative {
            routing_table: (*table).to_string(),
        }),
        ["interface", name, "lldp", dir @ ("transmit" | "receive")] => {
            Command::Set(SetTarget::InterfaceLldp {
                name: (*name).to_string(),
                direction: parse_lldp_direction(dir),
            })
        }
        ["lldp", dir @ ("transmit" | "receive")] => {
            Command::Set(SetTarget::InterfaceLldpRelative {
                direction: parse_lldp_direction(dir),
            })
        }
        ["interface", name, "lldp", "destination", group] => {
            Command::Set(SetTarget::InterfaceLldpDestination {
                name: (*name).to_string(),
                destination: LldpDestination::from_name(group)?,
            })
        }
        ["lldp", "destination", group] => {
            Command::Set(SetTarget::InterfaceLldpDestinationRelative {
                destination: LldpDestination::from_name(group)?,
            })
        }
        ["lldp", "tx-interval", secs] => {
            Command::Set(SetTarget::Lldp(LldpSetting::TxInterval(secs.parse().ok()?)))
        }
        ["lldp", "tx-hold", hold] => {
            Command::Set(SetTarget::Lldp(LldpSetting::TxHold(hold.parse().ok()?)))
        }
        ["lldp", "management-address", addr] => Command::Set(SetTarget::Lldp(
            LldpSetting::ManagementAddress(addr.parse().ok()?),
        )),
        ["interface", name, "mtu", mtu] => Command::Set(SetTarget::InterfaceMtu {
            name: (*name).to_string(),
            mtu: mtu.parse::<u32>().ok()?,
        }),
        ["mtu", mtu] => Command::Set(SetTarget::MtuRelative(mtu.parse::<u16>().ok()?)),
        ["interface", name, "switching-profile", profile] => {
            Command::Set(SetTarget::InterfaceSwitchingProfile {
                name: (*name).to_string(),
                switching_profile: (*profile).to_string(),
            })
        }
        ["switching-profile", profile] => {
            Command::Set(SetTarget::InterfaceSwitchingProfileRelative {
                switching_profile: (*profile).to_string(),
            })
        }
        ["interface", name, "ospf", profile] => Command::Set(SetTarget::InterfaceOspfProfile {
            name: (*name).to_string(),
            ospf_profile: (*profile).to_string(),
        }),
        ["ospf", profile] => Command::Set(SetTarget::InterfaceOspfProfileRelative {
            ospf_profile: (*profile).to_string(),
        }),
        ["interface", name, "ospfv3", profile] => Command::Set(SetTarget::InterfaceOspfv3Profile {
            name: (*name).to_string(),
            ospfv3_profile: (*profile).to_string(),
        }),
        ["ospfv3", profile] => Command::Set(SetTarget::InterfaceOspfv3ProfileRelative {
            ospfv3_profile: (*profile).to_string(),
        }),
        ["ospf", "instance", instance, "area", area_id, "profile", name, "hello-interval", n] => {
            Command::Set(SetTarget::OspfProfile {
                instance: (*instance).to_string(),
                area_id: area_id.parse().ok()?,
                name: (*name).to_string(),
                field: OspfProfileField::HelloInterval(n.parse::<u16>().ok()?),
            })
        }
        ["ospf", "instance", instance, "area", area_id, "profile", name, "dead-interval", n] => {
            Command::Set(SetTarget::OspfProfile {
                instance: (*instance).to_string(),
                area_id: area_id.parse().ok()?,
                name: (*name).to_string(),
                field: OspfProfileField::DeadInterval(n.parse::<u16>().ok()?),
            })
        }
        ["ospf", "instance", instance, "area", area_id, "profile", name, "cost", n] => {
            Command::Set(SetTarget::OspfProfile {
                instance: (*instance).to_string(),
                area_id: area_id.parse().ok()?,
                name: (*name).to_string(),
                field: OspfProfileField::Cost(n.parse::<u16>().ok()?),
            })
        }
        ["ospf", "instance", instance, "area", area_id, "profile", name, "priority", n] => {
            Command::Set(SetTarget::OspfProfile {
                instance: (*instance).to_string(),
                area_id: area_id.parse().ok()?,
                name: (*name).to_string(),
                field: OspfProfileField::Priority(n.parse::<u8>().ok()?),
            })
        }
        ["ospf", "instance", instance, "area", area_id, "profile", name, "mtu", n] => {
            Command::Set(SetTarget::OspfProfile {
                instance: (*instance).to_string(),
                area_id: area_id.parse().ok()?,
                name: (*name).to_string(),
                field: OspfProfileField::Mtu(n.parse::<u16>().ok()?),
            })
        }
        ["ospf", "instance", instance, "area", area_id, "profile", name, "network-type", "point-to-point"] => {
            Command::Set(SetTarget::OspfProfile {
                instance: (*instance).to_string(),
                area_id: area_id.parse().ok()?,
                name: (*name).to_string(),
                field: OspfProfileField::NetworkType(NetworkType::PointToPoint),
            })
        }
        ["ospf", "instance", instance, "area", area_id, "profile", name, "network-type", "broadcast"] => {
            Command::Set(SetTarget::OspfProfile {
                instance: (*instance).to_string(),
                area_id: area_id.parse().ok()?,
                name: (*name).to_string(),
                field: OspfProfileField::NetworkType(NetworkType::Broadcast),
            })
        }
        ["ospf", "instance", instance, "area", area_id, "profile", name, "simple-password", password] => {
            Command::Set(SetTarget::OspfProfile {
                instance: (*instance).to_string(),
                area_id: area_id.parse().ok()?,
                name: (*name).to_string(),
                field: OspfProfileField::SimplePassword((*password).to_string()),
            })
        }
        ["ospf", "instance", instance, "area", area_id, "profile", name, "crypto-key", key_id, algorithm, key] => {
            Command::Set(SetTarget::OspfProfile {
                instance: (*instance).to_string(),
                area_id: area_id.parse().ok()?,
                name: (*name).to_string(),
                field: OspfProfileField::CryptoKey {
                    key_id: key_id.parse::<u8>().ok()?,
                    algorithm: parse_ospf_crypto_algorithm(algorithm)?,
                    key: (*key).to_string(),
                },
            })
        }
        ["ospf", "instance", instance, "area", area_id, "profile", name, "crypto-key", key_id, "current"] => {
            Command::Set(SetTarget::OspfProfile {
                instance: (*instance).to_string(),
                area_id: area_id.parse().ok()?,
                name: (*name).to_string(),
                field: OspfProfileField::CryptoCurrentKey(key_id.parse::<u8>().ok()?),
            })
        }
        ["ospfv3", "instance", instance, "area", area_id, "profile", name, "hello-interval", n] => {
            Command::Set(SetTarget::Ospfv3Profile {
                instance: (*instance).to_string(),
                area_id: area_id.parse().ok()?,
                name: (*name).to_string(),
                field: OspfProfileField::HelloInterval(n.parse::<u16>().ok()?),
            })
        }
        ["ospfv3", "instance", instance, "area", area_id, "profile", name, "dead-interval", n] => {
            Command::Set(SetTarget::Ospfv3Profile {
                instance: (*instance).to_string(),
                area_id: area_id.parse().ok()?,
                name: (*name).to_string(),
                field: OspfProfileField::DeadInterval(n.parse::<u16>().ok()?),
            })
        }
        ["ospfv3", "instance", instance, "area", area_id, "profile", name, "cost", n] => {
            Command::Set(SetTarget::Ospfv3Profile {
                instance: (*instance).to_string(),
                area_id: area_id.parse().ok()?,
                name: (*name).to_string(),
                field: OspfProfileField::Cost(n.parse::<u16>().ok()?),
            })
        }
        ["ospfv3", "instance", instance, "area", area_id, "profile", name, "priority", n] => {
            Command::Set(SetTarget::Ospfv3Profile {
                instance: (*instance).to_string(),
                area_id: area_id.parse().ok()?,
                name: (*name).to_string(),
                field: OspfProfileField::Priority(n.parse::<u8>().ok()?),
            })
        }
        ["ospfv3", "instance", instance, "area", area_id, "profile", name, "mtu", n] => {
            Command::Set(SetTarget::Ospfv3Profile {
                instance: (*instance).to_string(),
                area_id: area_id.parse().ok()?,
                name: (*name).to_string(),
                field: OspfProfileField::Mtu(n.parse::<u16>().ok()?),
            })
        }
        ["ospfv3", "instance", instance, "area", area_id, "profile", name, "network-type", "point-to-point"] => {
            Command::Set(SetTarget::Ospfv3Profile {
                instance: (*instance).to_string(),
                area_id: area_id.parse().ok()?,
                name: (*name).to_string(),
                field: OspfProfileField::NetworkType(NetworkType::PointToPoint),
            })
        }
        ["ospfv3", "instance", instance, "area", area_id, "profile", name, "network-type", "broadcast"] => {
            Command::Set(SetTarget::Ospfv3Profile {
                instance: (*instance).to_string(),
                area_id: area_id.parse().ok()?,
                name: (*name).to_string(),
                field: OspfProfileField::NetworkType(NetworkType::Broadcast),
            })
        }
        ["hello-interval", n] => Command::Set(SetTarget::OspfProfileRelative {
            field: OspfProfileField::HelloInterval(n.parse::<u16>().ok()?),
        }),
        ["dead-interval", n] => Command::Set(SetTarget::OspfProfileRelative {
            field: OspfProfileField::DeadInterval(n.parse::<u16>().ok()?),
        }),
        ["cost", n] => Command::Set(SetTarget::OspfProfileRelative {
            field: OspfProfileField::Cost(n.parse::<u16>().ok()?),
        }),
        ["priority", n] => Command::Set(SetTarget::OspfProfileRelative {
            field: OspfProfileField::Priority(n.parse::<u8>().ok()?),
        }),
        ["network-type", "point-to-point"] => Command::Set(SetTarget::OspfProfileRelative {
            field: OspfProfileField::NetworkType(NetworkType::PointToPoint),
        }),
        ["network-type", "broadcast"] => Command::Set(SetTarget::OspfProfileRelative {
            field: OspfProfileField::NetworkType(NetworkType::Broadcast),
        }),
        ["simple-password", password] => Command::Set(SetTarget::OspfProfileRelative {
            field: OspfProfileField::SimplePassword((*password).to_string()),
        }),
        ["crypto-key", key_id, algorithm, key] => Command::Set(SetTarget::OspfProfileRelative {
            field: OspfProfileField::CryptoKey {
                key_id: key_id.parse::<u8>().ok()?,
                algorithm: parse_ospf_crypto_algorithm(algorithm)?,
                key: (*key).to_string(),
            },
        }),
        ["crypto-key", key_id, "current"] => Command::Set(SetTarget::OspfProfileRelative {
            field: OspfProfileField::CryptoCurrentKey(key_id.parse::<u8>().ok()?),
        }),
        ["broadcast", "domain", name, "address", addr] => {
            Command::Set(SetTarget::BroadcastDomainAddress {
                name: (*name).to_string(),
                address: addr.parse::<IpNet>().ok()?,
                label: None,
            })
        }
        ["broadcast", "domain", name, "address", addr, "label", label] => {
            Command::Set(SetTarget::BroadcastDomainAddress {
                name: (*name).to_string(),
                address: addr.parse::<IpNet>().ok()?,
                label: Some((*label).to_string()),
            })
        }
        ["broadcast", "domain", name, "routing-table", table] => {
            Command::Set(SetTarget::BroadcastDomainRoutingTable {
                name: (*name).to_string(),
                routing_table: (*table).to_string(),
            })
        }
        ["broadcast", "domain", name, rest @ ..]
            if broadcast_domain_evpn_set(name, rest).is_some() =>
        {
            Command::Set(SetTarget::BroadcastDomainEvpn(broadcast_domain_evpn_set(
                name, rest,
            )?))
        }
        ["port-aggregate", name, rest @ ..] if port_aggregate_field_set(name, rest).is_some() => {
            Command::Set(SetTarget::PortAggregateField(port_aggregate_field_set(
                name, rest,
            )?))
        }
        ["community-alias", name, "value", value] => Command::Set(SetTarget::CommunityAliasValue {
            name: (*name).to_string(),
            value: (*value).to_string(),
        }),
        ["value", value] => Command::Set(SetTarget::CommunityAliasValueRelative {
            value: (*value).to_string(),
        }),
        ["community-group", name, "member", member] => {
            Command::Set(SetTarget::CommunityGroupMember {
                name: (*name).to_string(),
                member: (*member).to_string(),
            })
        }
        ["member", member] => Command::Set(SetTarget::CommunityGroupMemberRelative {
            member: (*member).to_string(),
        }),
        ["prefix-list", name, "entry", cidr] => Command::Set(SetTarget::PrefixListEntry {
            name: (*name).to_string(),
            cidr: cidr.parse::<IpNet>().ok()?,
            range: None,
        }),
        ["prefix-list", name, "entry", cidr, "range", min, max] => {
            Command::Set(SetTarget::PrefixListEntry {
                name: (*name).to_string(),
                cidr: cidr.parse::<IpNet>().ok()?,
                range: Some((min.parse::<u8>().ok()?, max.parse::<u8>().ok()?)),
            })
        }
        ["entry", cidr] => Command::Set(SetTarget::PrefixListEntryRelative {
            cidr: cidr.parse::<IpNet>().ok()?,
            range: None,
        }),
        ["prefix-list", name, "entry", cidr, "orlonger"] => {
            let cidr = cidr.parse::<IpNet>().ok()?;
            Command::Set(SetTarget::PrefixListEntry {
                name: (*name).to_string(),
                range: Some((cidr.prefix_len(), cidr.max_prefix_len())),
                cidr,
            })
        }
        ["prefix-list", name, "entry", cidr, "upto", max] => {
            let cidr = cidr.parse::<IpNet>().ok()?;
            Command::Set(SetTarget::PrefixListEntry {
                name: (*name).to_string(),
                range: Some((cidr.prefix_len(), max.parse::<u8>().ok()?)),
                cidr,
            })
        }
        ["entry", cidr, "orlonger"] => {
            let cidr = cidr.parse::<IpNet>().ok()?;
            Command::Set(SetTarget::PrefixListEntryRelative {
                range: Some((cidr.prefix_len(), cidr.max_prefix_len())),
                cidr,
            })
        }
        ["entry", cidr, "upto", max] => {
            let cidr = cidr.parse::<IpNet>().ok()?;
            Command::Set(SetTarget::PrefixListEntryRelative {
                range: Some((cidr.prefix_len(), max.parse::<u8>().ok()?)),
                cidr,
            })
        }
        ["entry", cidr, "range", min, max] => Command::Set(SetTarget::PrefixListEntryRelative {
            cidr: cidr.parse::<IpNet>().ok()?,
            range: Some((min.parse::<u8>().ok()?, max.parse::<u8>().ok()?)),
        }),
        ["switching-profile", name, "broadcast-domain", domain, "tag", "dot1q", id] => {
            Command::Set(SetTarget::SwitchingProfileMember {
                name: (*name).to_string(),
                broadcast_domain: (*domain).to_string(),
                tag: VlanTag::Dot1q(id.parse::<u16>().ok()?),
            })
        }
        ["switching-profile", name, "broadcast-domain", domain, "tag", "untagged"] => {
            Command::Set(SetTarget::SwitchingProfileMember {
                name: (*name).to_string(),
                broadcast_domain: (*domain).to_string(),
                tag: VlanTag::Untagged,
            })
        }
        ["broadcast-domain", domain, "tag", "dot1q", id] => {
            Command::Set(SetTarget::SwitchingProfileMemberRelative {
                broadcast_domain: (*domain).to_string(),
                tag: VlanTag::Dot1q(id.parse::<u16>().ok()?),
            })
        }
        ["broadcast-domain", domain, "tag", "untagged"] => {
            Command::Set(SetTarget::SwitchingProfileMemberRelative {
                broadcast_domain: (*domain).to_string(),
                tag: VlanTag::Untagged,
            })
        }
        ["port-aggregate", name, "mode", "xor"] => Command::Set(SetTarget::PortAggregateMode {
            name: (*name).to_string(),
            mode: PortAggregateMode::Xor,
        }),
        ["port-aggregate", name, "mode", "lacp"] => Command::Set(SetTarget::PortAggregateMode {
            name: (*name).to_string(),
            mode: PortAggregateMode::Lacp,
        }),
        ["port-aggregate", name, "lacp-rate", rate @ ("fast" | "slow")] => {
            Command::Set(SetTarget::PortAggregateLacpRate {
                name: (*name).to_string(),
                rate: parse_lacp_rate(rate),
            })
        }
        ["port-aggregate", name, "redundancy-mode", mode @ ("all-active" | "single-active")] => {
            Command::Set(SetTarget::PortAggregateRedundancyMode {
                name: (*name).to_string(),
                mode: parse_redundancy_mode(mode),
            })
        }
        ["redundancy-mode", mode @ ("all-active" | "single-active")] => {
            Command::Set(SetTarget::PortAggregateRedundancyModeRelative {
                mode: parse_redundancy_mode(mode),
            })
        }
        ["esi", esi] => Command::Set(SetTarget::PortAggregateEsiRelative {
            esi: (*esi).to_string(),
        }),
        ["lacp-system-id", id] => Command::Set(SetTarget::PortAggregateLacpSystemIdRelative {
            system_id: (*id).to_string(),
        }),
        ["lacp-rate", rate @ ("fast" | "slow")] => {
            Command::Set(SetTarget::PortAggregateLacpRateRelative {
                rate: parse_lacp_rate(rate),
            })
        }
        ["mode", "xor"] => Command::Set(SetTarget::PortAggregateModeRelative {
            mode: PortAggregateMode::Xor,
        }),
        ["mode", "lacp"] => Command::Set(SetTarget::PortAggregateModeRelative {
            mode: PortAggregateMode::Lacp,
        }),
        ["interface", name, "port-aggregate", aggregate] => {
            Command::Set(SetTarget::InterfacePortAggregate {
                name: (*name).to_string(),
                port_aggregate: (*aggregate).to_string(),
            })
        }
        ["port-aggregate", aggregate] => Command::Set(SetTarget::InterfacePortAggregateRelative {
            port_aggregate: (*aggregate).to_string(),
        }),
        _ => return None,
    })
}

/// `delete` — the mirror of [`parse_set`], plus whole-object deletion.
fn parse_delete(t: &[&str]) -> Option<Command> {
    Some(match t {
        ["source", "line", n] => Command::DeleteSourceLine {
            line: n.parse::<usize>().ok()?,
        },
        [] => Command::Delete(DeleteTarget::Current),
        ["user", name] => Command::Delete(DeleteTarget::User {
            name: (*name).to_string(),
        }),
        ["bgp", "instance", name] => Command::Delete(DeleteTarget::BgpInstance {
            name: (*name).to_string(),
        }),
        ["bgp", "instance", instance, "peer-group", group] => {
            Command::Delete(DeleteTarget::BgpPeerGroup {
                instance: (*instance).to_string(),
                name: (*group).to_string(),
            })
        }
        ["peer-group", group] => Command::Delete(DeleteTarget::PeerGroupRelative {
            name: (*group).to_string(),
        }),
        ["bgp", "instance", name, "cluster-id"] => {
            Command::Delete(DeleteTarget::BgpInstanceClusterId {
                name: (*name).to_string(),
            })
        }
        ["cluster-id"] => Command::Delete(DeleteTarget::BgpInstanceClusterIdRelative),
        ["bgp", "instance", instance, "peer", ip] => Command::Delete(DeleteTarget::BgpPeer {
            instance: (*instance).to_string(),
            remote_address: ip.parse::<IpAddr>().ok()?,
        }),
        ["bgp", "instance", instance, "peer", ip, "shutdown"] => {
            Command::Delete(DeleteTarget::BgpPeerShutdown {
                instance: (*instance).to_string(),
                remote_address: ip.parse::<IpAddr>().ok()?,
            })
        }
        ["peer", ip, "shutdown"] => Command::Delete(DeleteTarget::PeerShutdownRelative {
            remote_address: ip.parse::<IpAddr>().ok()?,
        }),
        ["shutdown"] => Command::Delete(DeleteTarget::Shutdown),
        ["peer", ip] => Command::Delete(DeleteTarget::PeerRelative {
            remote_address: ip.parse::<IpAddr>().ok()?,
        }),
        ["source-address"] => Command::Delete(DeleteTarget::SourceAddress),
        ["address-family", "ipv4"] => {
            Command::Delete(DeleteTarget::AddressFamily(AddressFamily::Ipv4Unicast))
        }
        ["address-family", "ipv6"] => {
            Command::Delete(DeleteTarget::AddressFamily(AddressFamily::Ipv6Unicast))
        }
        ["address-family", "l2vpn-evpn"] => {
            Command::Delete(DeleteTarget::AddressFamily(AddressFamily::L2vpnEvpn))
        }
        ["next-hop"] => Command::Delete(DeleteTarget::NextHop),
        ["route-reflector-client"] => Command::Delete(DeleteTarget::RouteReflectorClient),
        ["route-server-client"] => Command::Delete(DeleteTarget::RouteServerClient),
        ["import-policy"] => Command::Delete(DeleteTarget::ImportPolicy),
        ["export-policy"] => Command::Delete(DeleteTarget::ExportPolicy),
        ["hold-time"] => Command::Delete(DeleteTarget::HoldTime),
        ["keepalive-interval"] => Command::Delete(DeleteTarget::KeepaliveInterval),
        ["connect-retry-time"] => Command::Delete(DeleteTarget::ConnectRetryTime),
        ["mrai"] => Command::Delete(DeleteTarget::Mrai),
        ["damping"] => Command::Delete(DeleteTarget::Damping),
        ["max-hops"] => Command::Delete(DeleteTarget::MaxHops),
        ["auth"] => Command::Delete(DeleteTarget::Auth),
        ["ao-key", send_id] => Command::Delete(DeleteTarget::AoKey(send_id.parse::<u8>().ok()?)),
        ["routing-table", name] => Command::Delete(DeleteTarget::RoutingTable {
            name: (*name).to_string(),
        }),
        ["routing-table", name, "bgp-instance"] => {
            Command::Delete(DeleteTarget::RoutingTableBgpInstance {
                name: (*name).to_string(),
            })
        }
        ["bgp-instance"] => Command::Delete(DeleteTarget::RoutingTableBgpInstanceRelative),
        ["routing-table", name, "static-routing-instance"] => {
            Command::Delete(DeleteTarget::RoutingTableStaticRoutingInstance {
                name: (*name).to_string(),
            })
        }
        ["static-routing-instance"] => {
            Command::Delete(DeleteTarget::RoutingTableStaticRoutingInstanceRelative)
        }
        ["routing-table", name, "ospf-instance"] => {
            Command::Delete(DeleteTarget::RoutingTableOspfInstance {
                name: (*name).to_string(),
            })
        }
        ["ospf-instance"] => Command::Delete(DeleteTarget::RoutingTableOspfInstanceRelative),
        ["routing-table", name, "ospfv3-instance"] => {
            Command::Delete(DeleteTarget::RoutingTableOspfv3Instance {
                name: (*name).to_string(),
            })
        }
        ["ospfv3-instance"] => Command::Delete(DeleteTarget::RoutingTableOspfv3InstanceRelative),
        ["routing-table", name, "rest-api"] => Command::Delete(DeleteTarget::RoutingTableRestApi {
            name: (*name).to_string(),
        }),
        ["rest-api"] => Command::Delete(DeleteTarget::RoutingTableRestApiRelative),
        ["ospf", "instance", name] => Command::Delete(DeleteTarget::OspfInstance {
            name: (*name).to_string(),
        }),
        ["ospf", "instance", instance, "area", area_id] => {
            Command::Delete(DeleteTarget::OspfArea {
                instance: (*instance).to_string(),
                area_id: area_id.parse::<Ipv4Addr>().ok()?,
            })
        }
        ["area", area_id] => Command::Delete(DeleteTarget::OspfAreaRelative {
            area_id: area_id.parse::<Ipv4Addr>().ok()?,
        }),
        ["ospf", "instance", instance, "area", area_id, "profile", name] => {
            Command::Delete(DeleteTarget::OspfProfile {
                instance: (*instance).to_string(),
                area_id: area_id.parse::<Ipv4Addr>().ok()?,
                name: (*name).to_string(),
            })
        }
        ["profile", name] => Command::Delete(DeleteTarget::OspfProfileRelative {
            name: (*name).to_string(),
        }),
        ["ospfv3", "instance", name, "extended-lsa"] => {
            Command::Delete(DeleteTarget::Ospfv3InstanceExtendedLsa {
                name: (*name).to_string(),
            })
        }
        ["ospfv3", "instance", name] => Command::Delete(DeleteTarget::Ospfv3Instance {
            name: (*name).to_string(),
        }),
        ["ospfv3", "instance", instance, "area", area_id] => {
            Command::Delete(DeleteTarget::Ospfv3Area {
                instance: (*instance).to_string(),
                area_id: area_id.parse::<Ipv4Addr>().ok()?,
            })
        }
        ["ospfv3", "instance", instance, "area", area_id, "profile", name] => {
            Command::Delete(DeleteTarget::Ospfv3Profile {
                instance: (*instance).to_string(),
                area_id: area_id.parse::<Ipv4Addr>().ok()?,
                name: (*name).to_string(),
            })
        }
        ["hello-interval"] => Command::Delete(DeleteTarget::HelloInterval),
        ["dead-interval"] => Command::Delete(DeleteTarget::DeadInterval),
        ["cost"] => Command::Delete(DeleteTarget::Cost),
        ["priority"] => Command::Delete(DeleteTarget::Priority),
        ["network-type"] => Command::Delete(DeleteTarget::NetworkType),
        ["crypto-key", key_id] => {
            Command::Delete(DeleteTarget::CryptoKey(key_id.parse::<u8>().ok()?))
        }
        ["routing-table", name, "redistribute"] => {
            Command::Delete(DeleteTarget::RoutingTableRedistribute {
                name: (*name).to_string(),
            })
        }
        ["redistribute"] => Command::Delete(DeleteTarget::RoutingTableRedistributeRelative),
        ["static-routing-instance", name] => Command::Delete(DeleteTarget::StaticRoutingInstance {
            name: (*name).to_string(),
        }),
        ["static-routing-instance", name, "route", subnet] => {
            Command::Delete(DeleteTarget::StaticRoute {
                instance: (*name).to_string(),
                subnet: subnet.parse::<IpNet>().ok()?,
            })
        }
        ["route", subnet] => Command::Delete(DeleteTarget::StaticRouteRelative {
            subnet: subnet.parse::<IpNet>().ok()?,
        }),
        ["interface", name] => Command::Delete(DeleteTarget::Interface {
            name: (*name).to_string(),
        }),
        ["interface", name, "address", addr] => Command::Delete(DeleteTarget::InterfaceAddress {
            name: (*name).to_string(),
            address: addr.parse::<IpNet>().ok()?,
        }),
        ["address", addr] => Command::Delete(DeleteTarget::InterfaceAddressRelative {
            address: addr.parse::<IpNet>().ok()?,
        }),
        ["interface", name, "routing-table"] => {
            Command::Delete(DeleteTarget::InterfaceRoutingTable {
                name: (*name).to_string(),
            })
        }
        ["routing-table"] => Command::Delete(DeleteTarget::InterfaceRoutingTableRelative),
        ["interface", name, "lldp", dir @ ("transmit" | "receive")] => {
            Command::Delete(DeleteTarget::InterfaceLldp {
                name: (*name).to_string(),
                direction: parse_lldp_direction(dir),
            })
        }
        ["lldp", dir @ ("transmit" | "receive")] => {
            Command::Delete(DeleteTarget::InterfaceLldpRelative {
                direction: parse_lldp_direction(dir),
            })
        }
        ["interface", name, "lldp", "destination"] => {
            Command::Delete(DeleteTarget::InterfaceLldpDestination {
                name: (*name).to_string(),
            })
        }
        ["lldp", "destination"] => Command::Delete(DeleteTarget::InterfaceLldpDestinationRelative),
        ["lldp", "tx-interval"] => Command::Delete(DeleteTarget::Lldp(LldpSettingKind::TxInterval)),
        ["lldp", "tx-hold"] => Command::Delete(DeleteTarget::Lldp(LldpSettingKind::TxHold)),
        ["lldp", "management-address"] => {
            Command::Delete(DeleteTarget::Lldp(LldpSettingKind::ManagementAddress))
        }
        ["interface", name, "mtu"] => Command::Delete(DeleteTarget::InterfaceMtu {
            name: (*name).to_string(),
        }),
        ["mtu"] => Command::Delete(DeleteTarget::MtuRelative),
        ["esi"] => Command::Delete(DeleteTarget::PortAggregateEsiRelative),
        ["lacp-system-id"] => Command::Delete(DeleteTarget::PortAggregateLacpSystemIdRelative),
        ["interface", name, "switching-profile"] => {
            Command::Delete(DeleteTarget::InterfaceSwitchingProfile {
                name: (*name).to_string(),
            })
        }
        ["switching-profile"] => Command::Delete(DeleteTarget::InterfaceSwitchingProfileRelative),
        ["interface", name, "ospf"] => Command::Delete(DeleteTarget::InterfaceOspfProfile {
            name: (*name).to_string(),
        }),
        ["ospf"] => Command::Delete(DeleteTarget::InterfaceOspfProfileRelative),
        ["interface", name, "ospfv3"] => Command::Delete(DeleteTarget::InterfaceOspfv3Profile {
            name: (*name).to_string(),
        }),
        ["ospfv3"] => Command::Delete(DeleteTarget::InterfaceOspfv3ProfileRelative),
        ["community-alias", name] => Command::Delete(DeleteTarget::CommunityAlias {
            name: (*name).to_string(),
        }),
        ["community-group", name] => Command::Delete(DeleteTarget::CommunityGroup {
            name: (*name).to_string(),
        }),
        ["community-group", name, "member", member] => {
            Command::Delete(DeleteTarget::CommunityGroupMember {
                name: (*name).to_string(),
                member: (*member).to_string(),
            })
        }
        ["member", member] => Command::Delete(DeleteTarget::CommunityGroupMemberRelative {
            member: (*member).to_string(),
        }),
        ["prefix-list", name] => Command::Delete(DeleteTarget::PrefixList {
            name: (*name).to_string(),
        }),
        ["prefix-list", name, "entry", cidr] => Command::Delete(DeleteTarget::PrefixListEntry {
            name: (*name).to_string(),
            cidr: cidr.parse::<IpNet>().ok()?,
            range: None,
        }),
        ["prefix-list", name, "entry", cidr, "range", min, max] => {
            Command::Delete(DeleteTarget::PrefixListEntry {
                name: (*name).to_string(),
                cidr: cidr.parse::<IpNet>().ok()?,
                range: Some((min.parse::<u8>().ok()?, max.parse::<u8>().ok()?)),
            })
        }
        ["entry", cidr] => Command::Delete(DeleteTarget::PrefixListEntryRelative {
            cidr: cidr.parse::<IpNet>().ok()?,
            range: None,
        }),
        ["prefix-list", name, "entry", cidr, "orlonger"] => {
            let cidr = cidr.parse::<IpNet>().ok()?;
            Command::Delete(DeleteTarget::PrefixListEntry {
                name: (*name).to_string(),
                range: Some((cidr.prefix_len(), cidr.max_prefix_len())),
                cidr,
            })
        }
        ["prefix-list", name, "entry", cidr, "upto", max] => {
            let cidr = cidr.parse::<IpNet>().ok()?;
            Command::Delete(DeleteTarget::PrefixListEntry {
                name: (*name).to_string(),
                range: Some((cidr.prefix_len(), max.parse::<u8>().ok()?)),
                cidr,
            })
        }
        ["entry", cidr, "orlonger"] => {
            let cidr = cidr.parse::<IpNet>().ok()?;
            Command::Delete(DeleteTarget::PrefixListEntryRelative {
                range: Some((cidr.prefix_len(), cidr.max_prefix_len())),
                cidr,
            })
        }
        ["entry", cidr, "upto", max] => {
            let cidr = cidr.parse::<IpNet>().ok()?;
            Command::Delete(DeleteTarget::PrefixListEntryRelative {
                range: Some((cidr.prefix_len(), max.parse::<u8>().ok()?)),
                cidr,
            })
        }
        ["entry", cidr, "range", min, max] => {
            Command::Delete(DeleteTarget::PrefixListEntryRelative {
                cidr: cidr.parse::<IpNet>().ok()?,
                range: Some((min.parse::<u8>().ok()?, max.parse::<u8>().ok()?)),
            })
        }
        ["broadcast", "domain", name] => Command::Delete(DeleteTarget::BroadcastDomain {
            name: (*name).to_string(),
        }),
        ["broadcast", "domain", name, "address", addr] => {
            Command::Delete(DeleteTarget::BroadcastDomainAddress {
                name: (*name).to_string(),
                address: addr.parse::<IpNet>().ok()?,
            })
        }
        ["broadcast", "domain", name, "routing-table"] => {
            Command::Delete(DeleteTarget::BroadcastDomainRoutingTable {
                name: (*name).to_string(),
            })
        }
        ["broadcast", "domain", name, rest @ ..]
            if broadcast_domain_evpn_delete(name, rest).is_some() =>
        {
            Command::Delete(DeleteTarget::BroadcastDomainEvpn(
                broadcast_domain_evpn_delete(name, rest)?,
            ))
        }
        ["port-aggregate", name, rest @ ..]
            if port_aggregate_field_delete(name, rest).is_some() =>
        {
            Command::Delete(DeleteTarget::PortAggregateField(
                port_aggregate_field_delete(name, rest)?,
            ))
        }
        ["switching-profile", name] => Command::Delete(DeleteTarget::SwitchingProfile {
            name: (*name).to_string(),
        }),
        ["switching-profile", name, "broadcast-domain", domain] => {
            Command::Delete(DeleteTarget::SwitchingProfileMember {
                name: (*name).to_string(),
                broadcast_domain: (*domain).to_string(),
            })
        }
        ["broadcast-domain", domain] => {
            Command::Delete(DeleteTarget::SwitchingProfileMemberRelative {
                broadcast_domain: (*domain).to_string(),
            })
        }
        ["port-aggregate", name] => Command::Delete(DeleteTarget::PortAggregate {
            name: (*name).to_string(),
        }),
        ["interface", name, "port-aggregate"] => {
            Command::Delete(DeleteTarget::InterfacePortAggregate {
                name: (*name).to_string(),
            })
        }
        ["port-aggregate"] => Command::Delete(DeleteTarget::InterfacePortAggregateRelative),
        _ => return None,
    })
}

/// Everything with no object verb in front of it: shell mechanics
/// (`help`, `exit`, `up`), transaction control, and `clear`.
fn parse_bare(t: &[&str]) -> Option<Command> {
    Some(match t {
        [] => Command::Empty,
        ["clear", "bgp", instance, peer, "soft-in"] => Command::ClearBgpSoftIn {
            instance: (*instance).to_string(),
            peer: peer.parse::<IpAddr>().ok()?,
        },
        ["save"] => Command::Save,
        ["help"] => Command::Help,
        ["exit" | "quit" | "end"] => Command::Exit,
        ["commit"] => Command::Commit,
        ["discard" | "abort"] => Command::Discard,
        ["diff"] => Command::Diff,
        ["up"] => Command::Up,
        ["top"] => Command::Top,
        ["configure", name] => Command::Configure {
            name: (*name).to_string(),
            base: None,
        },
        ["configure", name, "from", "blank"] => Command::Configure {
            name: (*name).to_string(),
            base: Some(TransactionBase::Blank),
        },
        ["configure", name, "from", "current"] => Command::Configure {
            name: (*name).to_string(),
            base: Some(TransactionBase::Current),
        },
        _ => return None,
    })
}

fn parse_ao_algorithm(token: &str) -> Option<BgpAoAlgorithm> {
    match token {
        "hmac-sha1" => Some(BgpAoAlgorithm::HmacSha1_96),
        "aes-cmac" => Some(BgpAoAlgorithm::AesCmac96),
        _ => None,
    }
}

/// `[half-life N] [reuse N] [suppress N] [max-suppress N]` in any order;
/// omitted values keep `BgpDamping::default()` (RFC 7196).
fn parse_damping(mut t: &[&str]) -> Option<nos_proto::BgpDamping> {
    let mut d = nos_proto::BgpDamping::default();
    while let [key, n, rest @ ..] = t {
        let n = n.parse::<u32>().ok()?;
        match *key {
            "half-life" => d.half_life = n,
            "reuse" => d.reuse = n,
            "suppress" => d.suppress = n,
            "max-suppress" => d.max_suppress = n,
            _ => return None,
        }
        t = rest;
    }
    t.is_empty().then_some(d)
}

fn parse_ospf_crypto_algorithm(token: &str) -> Option<OspfCryptoAlgorithm> {
    match token {
        "md5" => Some(OspfCryptoAlgorithm::Md5),
        "hmac-sha1" => Some(OspfCryptoAlgorithm::HmacSha1),
        "hmac-sha256" => Some(OspfCryptoAlgorithm::HmacSha256),
        "hmac-sha384" => Some(OspfCryptoAlgorithm::HmacSha384),
        "hmac-sha512" => Some(OspfCryptoAlgorithm::HmacSha512),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_shutdown_with_and_without_a_message() {
        assert_eq!(
            Command::parse("set shutdown planned maintenance"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::Shutdown(Some("planned maintenance".to_string())),
            })
        );
        assert_eq!(
            Command::parse("set peer 192.0.2.1 shutdown"),
            Command::Set(SetTarget::PeerShutdownRelative {
                remote_address: "192.0.2.1".parse().unwrap(),
                message: None,
            })
        );
        assert_eq!(
            Command::parse("delete shutdown"),
            Command::Delete(DeleteTarget::Shutdown)
        );
        assert_eq!(
            Command::parse("delete bgp instance r1 peer 192.0.2.1 shutdown"),
            Command::Delete(DeleteTarget::BgpPeerShutdown {
                instance: "r1".to_string(),
                remote_address: "192.0.2.1".parse().unwrap(),
            })
        );
    }

    #[test]
    fn parses_max_hops() {
        assert_eq!(
            Command::parse("set max-hops 1"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::MaxHops(1)
            })
        );
        assert_eq!(
            Command::parse("delete max-hops"),
            Command::Delete(DeleteTarget::MaxHops)
        );
    }

    #[test]
    fn parses_damping() {
        assert_eq!(
            Command::parse("set damping suppress 2000 half-life 30"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::Damping(nos_proto::BgpDamping {
                    suppress: 2000,
                    half_life: 30,
                    ..Default::default()
                }),
            })
        );
        assert_eq!(
            Command::parse("delete damping"),
            Command::Delete(DeleteTarget::Damping)
        );
    }

    #[test]
    fn parses_mrai() {
        assert_eq!(
            Command::parse("set mrai 30"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::Mrai(30),
            })
        );
        assert_eq!(
            Command::parse("delete mrai"),
            Command::Delete(DeleteTarget::Mrai)
        );
    }

    #[test]
    fn show_config() {
        assert_eq!(Command::parse("show config"), Command::ShowConfig);
    }

    #[test]
    fn show_config_extra_whitespace() {
        assert_eq!(Command::parse("  show   config  "), Command::ShowConfig);
    }

    #[test]
    fn show_this() {
        assert_eq!(Command::parse("show this"), Command::Show);
    }

    #[test]
    fn bare_show_is_unknown() {
        assert_eq!(Command::parse("show"), Command::Unknown("show".to_string()));
    }

    #[test]
    fn show_route_whole_table() {
        assert_eq!(
            Command::parse("show route rt1"),
            Command::ShowRoute {
                table: "rt1".to_string(),
                address: None,
            }
        );
    }

    #[test]
    fn show_route_with_address() {
        assert_eq!(
            Command::parse("show route rt1 10.0.0.5"),
            Command::ShowRoute {
                table: "rt1".to_string(),
                address: Some("10.0.0.5".parse().unwrap()),
            }
        );
    }

    #[test]
    fn show_route_with_invalid_address_is_unknown() {
        assert_eq!(
            Command::parse("show route rt1 not-an-address"),
            Command::Unknown("show route rt1 not-an-address".to_string())
        );
    }

    #[test]
    fn edit_port_aggregate() {
        assert_eq!(
            Command::parse("edit port-aggregate bond1"),
            Command::Edit(EditTarget::PortAggregate {
                name: "bond1".to_string(),
            })
        );
    }

    #[test]
    fn set_port_aggregate_mode() {
        assert_eq!(
            Command::parse("set port-aggregate bond1 mode xor"),
            Command::Set(SetTarget::PortAggregateMode {
                name: "bond1".to_string(),
                mode: PortAggregateMode::Xor,
            })
        );
        assert_eq!(
            Command::parse("set mode xor"),
            Command::Set(SetTarget::PortAggregateModeRelative {
                mode: PortAggregateMode::Xor,
            })
        );
    }

    #[test]
    fn set_and_delete_interface_port_aggregate() {
        assert_eq!(
            Command::parse("set interface eth0 port-aggregate bond1"),
            Command::Set(SetTarget::InterfacePortAggregate {
                name: "eth0".to_string(),
                port_aggregate: "bond1".to_string(),
            })
        );
        assert_eq!(
            Command::parse("set port-aggregate bond1"),
            Command::Set(SetTarget::InterfacePortAggregateRelative {
                port_aggregate: "bond1".to_string(),
            })
        );
        assert_eq!(
            Command::parse("delete interface eth0 port-aggregate"),
            Command::Delete(DeleteTarget::InterfacePortAggregate {
                name: "eth0".to_string(),
            })
        );
        assert_eq!(
            Command::parse("delete port-aggregate"),
            Command::Delete(DeleteTarget::InterfacePortAggregateRelative)
        );
    }

    #[test]
    fn delete_port_aggregate() {
        assert_eq!(
            Command::parse("delete port-aggregate bond1"),
            Command::Delete(DeleteTarget::PortAggregate {
                name: "bond1".to_string(),
            })
        );
    }

    #[test]
    fn show_lldp_neighbors() {
        assert_eq!(
            Command::parse("show lldp neighbors"),
            Command::ShowLldpNeighbors
        );
        assert_eq!(
            Command::parse("show lldp"),
            Command::Unknown("show lldp".to_string())
        );
    }

    #[test]
    fn set_and_delete_lldp_qualified_and_relative() {
        assert_eq!(
            Command::parse("set interface eth1 lldp transmit"),
            Command::Set(SetTarget::InterfaceLldp {
                name: "eth1".to_string(),
                direction: LldpDirection::Transmit,
            })
        );
        assert_eq!(
            Command::parse("set lldp receive"),
            Command::Set(SetTarget::InterfaceLldpRelative {
                direction: LldpDirection::Receive,
            })
        );
        assert_eq!(
            Command::parse("delete interface eth1 lldp receive"),
            Command::Delete(DeleteTarget::InterfaceLldp {
                name: "eth1".to_string(),
                direction: LldpDirection::Receive,
            })
        );
        assert_eq!(
            Command::parse("delete lldp transmit"),
            Command::Delete(DeleteTarget::InterfaceLldpRelative {
                direction: LldpDirection::Transmit,
            })
        );
        assert_eq!(
            Command::parse("set lldp both"),
            Command::Unknown("set lldp both".to_string())
        );
    }

    #[test]
    fn show_lacp() {
        assert_eq!(
            Command::parse("show lacp"),
            Command::ShowLacp { name: None }
        );
        assert_eq!(
            Command::parse("show lacp bond1"),
            Command::ShowLacp {
                name: Some("bond1".to_string()),
            }
        );
    }

    #[test]
    fn set_lacp_rate() {
        assert_eq!(
            Command::parse("set port-aggregate bond1 lacp-rate fast"),
            Command::Set(SetTarget::PortAggregateLacpRate {
                name: "bond1".to_string(),
                rate: LacpRate::Fast,
            })
        );
        assert_eq!(
            Command::parse("set lacp-rate slow"),
            Command::Set(SetTarget::PortAggregateLacpRateRelative {
                rate: LacpRate::Slow,
            })
        );
        assert_eq!(
            Command::parse("set lacp-rate medium"),
            Command::Unknown("set lacp-rate medium".to_string())
        );
    }

    #[test]
    fn set_redundancy_mode() {
        assert_eq!(
            Command::parse("set port-aggregate bond1 redundancy-mode single-active"),
            Command::Set(SetTarget::PortAggregateRedundancyMode {
                name: "bond1".to_string(),
                mode: EsRedundancy::SingleActive,
            })
        );
        assert_eq!(
            Command::parse("set redundancy-mode all-active"),
            Command::Set(SetTarget::PortAggregateRedundancyModeRelative {
                mode: EsRedundancy::AllActive,
            })
        );
        assert_eq!(
            Command::parse("set redundancy-mode both"),
            Command::Unknown("set redundancy-mode both".to_string())
        );
    }

    #[test]
    fn show_port_aggregate() {
        assert_eq!(
            Command::parse("show port-aggregate"),
            Command::ShowPortAggregate { name: None }
        );
        assert_eq!(
            Command::parse("show port-aggregate bond1"),
            Command::ShowPortAggregate {
                name: Some("bond1".to_string()),
            }
        );
    }

    #[test]
    fn set_source_line_preserves_leading_whitespace() {
        assert_eq!(
            Command::parse("set source line 2     accept"),
            Command::SetSourceLine {
                line: 2,
                text: "    accept".to_string(),
            }
        );
    }

    #[test]
    fn set_source_line_preserves_deep_indentation() {
        // The generic split_whitespace() matcher used by every other
        // command would collapse this to a single space — this command's
        // whole reason for a dedicated pre-check is that RPL's indentation
        // is semantically meaningful and must survive verbatim.
        assert_eq!(
            Command::parse("set source line 5         set this.bgp.local_pref = 150"),
            Command::SetSourceLine {
                line: 5,
                text: "        set this.bgp.local_pref = 150".to_string(),
            }
        );
    }

    #[test]
    fn set_source_line_with_no_text_is_unknown() {
        assert_eq!(
            Command::parse("set source line 3"),
            Command::Unknown("set source line 3".to_string())
        );
    }

    #[test]
    fn set_source_line_with_non_numeric_line_is_unknown() {
        assert_eq!(
            Command::parse("set source line abc accept"),
            Command::Unknown("set source line abc accept".to_string())
        );
    }

    #[test]
    fn delete_source_line() {
        assert_eq!(
            Command::parse("delete source line 4"),
            Command::DeleteSourceLine { line: 4 }
        );
    }

    #[test]
    fn edit_policy_definition_and_source() {
        assert_eq!(
            Command::parse("edit policy-definition p1"),
            Command::Edit(EditTarget::PolicyDefinition {
                name: "p1".to_string()
            })
        );
        assert_eq!(Command::parse("edit source"), Command::EditSource);
        assert_eq!(Command::parse("show source"), Command::ShowSource);
    }

    #[test]
    fn set_and_delete_import_export_policy_relative() {
        assert_eq!(
            Command::parse("set import-policy accept-all"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::ImportPolicy("accept-all".to_string()),
            })
        );
        assert_eq!(
            Command::parse("set export-policy deny-all"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::ExportPolicy("deny-all".to_string()),
            })
        );
        assert_eq!(
            Command::parse("delete import-policy"),
            Command::Delete(DeleteTarget::ImportPolicy)
        );
        assert_eq!(
            Command::parse("delete export-policy"),
            Command::Delete(DeleteTarget::ExportPolicy)
        );
    }

    #[test]
    fn save() {
        assert_eq!(Command::parse("save"), Command::Save);
    }

    #[test]
    fn help() {
        assert_eq!(Command::parse("help"), Command::Help);
    }

    #[test]
    fn exit_quit_and_end() {
        assert_eq!(Command::parse("exit"), Command::Exit);
        assert_eq!(Command::parse("quit"), Command::Exit);
        assert_eq!(Command::parse("end"), Command::Exit);
    }

    #[test]
    fn commit() {
        assert_eq!(Command::parse("commit"), Command::Commit);
    }

    #[test]
    fn discard_and_abort() {
        assert_eq!(Command::parse("discard"), Command::Discard);
        assert_eq!(Command::parse("abort"), Command::Discard);
    }

    #[test]
    fn diff() {
        assert_eq!(Command::parse("diff"), Command::Diff);
    }

    #[test]
    fn up_and_top() {
        assert_eq!(Command::parse("up"), Command::Up);
        assert_eq!(Command::parse("top"), Command::Top);
    }

    #[test]
    fn empty_line() {
        assert_eq!(Command::parse(""), Command::Empty);
        assert_eq!(Command::parse("   "), Command::Empty);
    }

    #[test]
    fn unknown_command() {
        assert_eq!(
            Command::parse("show interfaces"),
            Command::Unknown("show interfaces".to_string())
        );
    }

    #[test]
    fn configure_default_base() {
        assert_eq!(
            Command::parse("configure my-txn"),
            Command::Configure {
                name: "my-txn".to_string(),
                base: None,
            }
        );
    }

    #[test]
    fn configure_from_blank() {
        assert_eq!(
            Command::parse("configure my-txn from blank"),
            Command::Configure {
                name: "my-txn".to_string(),
                base: Some(TransactionBase::Blank),
            }
        );
    }

    #[test]
    fn configure_from_current() {
        assert_eq!(
            Command::parse("configure my-txn from current"),
            Command::Configure {
                name: "my-txn".to_string(),
                base: Some(TransactionBase::Current),
            }
        );
    }

    #[test]
    fn edit_bgp_instance() {
        assert_eq!(
            Command::parse("edit bgp instance R1"),
            Command::Edit(EditTarget::BgpInstance {
                name: "R1".to_string()
            })
        );
    }

    #[test]
    fn set_bgp_instance_asn_qualified() {
        assert_eq!(
            Command::parse("set bgp instance R1 asn 65001"),
            Command::Set(SetTarget::BgpInstance {
                name: "R1".to_string(),
                field: BgpInstanceField::Asn(65001),
            })
        );
    }

    #[test]
    fn set_bgp_instance_router_id_qualified() {
        assert_eq!(
            Command::parse("set bgp instance R1 router-id 10.0.0.1"),
            Command::Set(SetTarget::BgpInstance {
                name: "R1".to_string(),
                field: BgpInstanceField::RouterId(Ipv4Addr::new(10, 0, 0, 1)),
            })
        );
    }

    #[test]
    fn set_asn_qualified_with_malformed_number_is_unknown() {
        assert_eq!(
            Command::parse("set bgp instance R1 asn abc"),
            Command::Unknown("set bgp instance R1 asn abc".to_string())
        );
    }

    #[test]
    fn set_asn_relative() {
        assert_eq!(
            Command::parse("set asn 65001"),
            Command::Set(SetTarget::Relative {
                field: BgpInstanceField::Asn(65001),
            })
        );
    }

    #[test]
    fn set_router_id_relative() {
        assert_eq!(
            Command::parse("set router-id 10.0.0.1"),
            Command::Set(SetTarget::Relative {
                field: BgpInstanceField::RouterId(Ipv4Addr::new(10, 0, 0, 1)),
            })
        );
    }

    #[test]
    fn set_router_id_relative_malformed_ip_is_unknown() {
        assert_eq!(
            Command::parse("set router-id not-an-ip"),
            Command::Unknown("set router-id not-an-ip".to_string())
        );
    }

    #[test]
    fn set_and_delete_lldp_destination_and_system_settings() {
        assert_eq!(
            Command::parse("set interface eth1 lldp destination customer-bridge"),
            Command::Set(SetTarget::InterfaceLldpDestination {
                name: "eth1".to_string(),
                destination: LldpDestination::CustomerBridge,
            })
        );
        assert_eq!(
            Command::parse("set lldp destination non-tpmr"),
            Command::Set(SetTarget::InterfaceLldpDestinationRelative {
                destination: LldpDestination::NonTpmr,
            })
        );
        assert_eq!(
            Command::parse("set lldp destination bogus"),
            Command::Unknown("set lldp destination bogus".to_string())
        );
        assert_eq!(
            Command::parse("set lldp tx-interval 5"),
            Command::Set(SetTarget::Lldp(LldpSetting::TxInterval(5)))
        );
        assert_eq!(
            Command::parse("set lldp tx-hold 3"),
            Command::Set(SetTarget::Lldp(LldpSetting::TxHold(3)))
        );
        assert_eq!(
            Command::parse("set lldp management-address 2001:db8::1"),
            Command::Set(SetTarget::Lldp(LldpSetting::ManagementAddress(
                "2001:db8::1".parse().unwrap()
            )))
        );
        assert_eq!(
            Command::parse("set lldp tx-interval fast"),
            Command::Unknown("set lldp tx-interval fast".to_string())
        );
        assert_eq!(
            Command::parse("delete interface eth1 lldp destination"),
            Command::Delete(DeleteTarget::InterfaceLldpDestination {
                name: "eth1".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete lldp destination"),
            Command::Delete(DeleteTarget::InterfaceLldpDestinationRelative)
        );
        assert_eq!(
            Command::parse("delete lldp management-address"),
            Command::Delete(DeleteTarget::Lldp(LldpSettingKind::ManagementAddress))
        );
    }

    #[test]
    fn set_hostname() {
        assert_eq!(
            Command::parse("set hostname router1"),
            Command::Set(SetTarget::Hostname("router1".to_string()))
        );
    }

    #[test]
    fn set_and_delete_user() {
        assert_eq!(
            Command::parse("set user alice password s3cret"),
            Command::Set(SetTarget::UserPassword {
                name: "alice".to_string(),
                password: "s3cret".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete user alice"),
            Command::Delete(DeleteTarget::User {
                name: "alice".to_string()
            })
        );
    }

    #[test]
    fn delete_bare() {
        assert_eq!(
            Command::parse("delete"),
            Command::Delete(DeleteTarget::Current)
        );
    }

    #[test]
    fn delete_bgp_instance_qualified() {
        assert_eq!(
            Command::parse("delete bgp instance R1"),
            Command::Delete(DeleteTarget::BgpInstance {
                name: "R1".to_string()
            })
        );
    }

    #[test]
    fn edit_bgp_peer_group_qualified() {
        assert_eq!(
            Command::parse("edit bgp instance R1 peer-group PG1"),
            Command::Edit(EditTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                name: "PG1".to_string(),
            })
        );
    }

    #[test]
    fn edit_peer_group_relative() {
        assert_eq!(
            Command::parse("edit peer-group PG1"),
            Command::Edit(EditTarget::PeerGroupRelative {
                name: "PG1".to_string()
            })
        );
    }

    #[test]
    fn set_bgp_peer_group_remote_as_qualified() {
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 remote-as 65001"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::RemoteAs(65001),
            })
        );
    }

    #[test]
    fn set_bgp_peer_group_source_address_qualified() {
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 source-address interface eth0"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::SourceAddress(SourceAddress::Interface {
                    interface: "eth0".to_string(),
                    label: None,
                }),
            })
        );
        assert_eq!(
            Command::parse(
                "set bgp instance R1 peer-group PG1 source-address interface eth0 label mgmt"
            ),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::SourceAddress(SourceAddress::Interface {
                    interface: "eth0".to_string(),
                    label: Some("mgmt".to_string()),
                }),
            })
        );
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 source-address loopback"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::SourceAddress(SourceAddress::Loopback { label: None }),
            })
        );
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 source-address loopback label mgmt"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::SourceAddress(SourceAddress::Loopback {
                    label: Some("mgmt".to_string()),
                }),
            })
        );
    }

    #[test]
    fn set_source_address_relative() {
        assert_eq!(
            Command::parse("set source-address interface eth0"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::SourceAddress(SourceAddress::Interface {
                    interface: "eth0".to_string(),
                    label: None,
                }),
            })
        );
        assert_eq!(
            Command::parse("set source-address interface eth0 label mgmt"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::SourceAddress(SourceAddress::Interface {
                    interface: "eth0".to_string(),
                    label: Some("mgmt".to_string()),
                }),
            })
        );
        assert_eq!(
            Command::parse("set source-address loopback"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::SourceAddress(SourceAddress::Loopback { label: None }),
            })
        );
        assert_eq!(
            Command::parse("set source-address loopback label mgmt"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::SourceAddress(SourceAddress::Loopback {
                    label: Some("mgmt".to_string()),
                }),
            })
        );
    }

    #[test]
    fn set_bgp_peer_group_address_family_qualified() {
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 address-family ipv4"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::AddressFamily(AddressFamily::Ipv4Unicast),
            })
        );
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 address-family ipv6"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::AddressFamily(AddressFamily::Ipv6Unicast),
            })
        );
    }

    #[test]
    fn set_bgp_peer_group_timers_qualified() {
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 hold-time 30"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::HoldTime(30),
            })
        );
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 keepalive-interval 10"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::KeepaliveInterval(10),
            })
        );
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 connect-retry-time 45"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::ConnectRetryTime(45),
            })
        );
    }

    #[test]
    fn set_bgp_peer_group_next_hop_qualified() {
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 next-hop self"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::NextHop(NextHopMode::SelfAddress),
            })
        );
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 next-hop unchanged"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::NextHop(NextHopMode::Unchanged),
            })
        );
    }

    #[test]
    fn set_peer_group_next_hop_relative() {
        assert_eq!(
            Command::parse("set next-hop self"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::NextHop(NextHopMode::SelfAddress),
            })
        );
        assert_eq!(
            Command::parse("set next-hop unchanged"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::NextHop(NextHopMode::Unchanged),
            })
        );
    }

    #[test]
    fn delete_peer_group_next_hop_relative() {
        assert_eq!(
            Command::parse("delete next-hop"),
            Command::Delete(DeleteTarget::NextHop)
        );
    }

    #[test]
    fn set_bgp_peer_group_route_reflector_and_server_client_qualified() {
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 route-reflector-client"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::RouteReflectorClient,
            })
        );
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 route-server-client"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::RouteServerClient,
            })
        );
    }

    #[test]
    fn set_peer_group_route_reflector_and_server_client_relative() {
        assert_eq!(
            Command::parse("set route-reflector-client"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::RouteReflectorClient,
            })
        );
        assert_eq!(
            Command::parse("set route-server-client"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::RouteServerClient,
            })
        );
    }

    #[test]
    fn delete_peer_group_route_reflector_and_server_client_relative() {
        assert_eq!(
            Command::parse("delete route-reflector-client"),
            Command::Delete(DeleteTarget::RouteReflectorClient)
        );
        assert_eq!(
            Command::parse("delete route-server-client"),
            Command::Delete(DeleteTarget::RouteServerClient)
        );
    }

    #[test]
    fn set_and_delete_bgp_instance_cluster_id_qualified() {
        assert_eq!(
            Command::parse("set bgp instance R1 cluster-id 1.2.3.4"),
            Command::Set(SetTarget::BgpInstance {
                name: "R1".to_string(),
                field: BgpInstanceField::ClusterId(Ipv4Addr::new(1, 2, 3, 4)),
            })
        );
        assert_eq!(
            Command::parse("delete bgp instance R1 cluster-id"),
            Command::Delete(DeleteTarget::BgpInstanceClusterId {
                name: "R1".to_string(),
            })
        );
    }

    #[test]
    fn set_and_delete_bgp_instance_cluster_id_relative() {
        assert_eq!(
            Command::parse("set cluster-id 1.2.3.4"),
            Command::Set(SetTarget::Relative {
                field: BgpInstanceField::ClusterId(Ipv4Addr::new(1, 2, 3, 4)),
            })
        );
        assert_eq!(
            Command::parse("delete cluster-id"),
            Command::Delete(DeleteTarget::BgpInstanceClusterIdRelative)
        );
    }

    #[test]
    fn set_peer_group_timers_relative() {
        assert_eq!(
            Command::parse("set hold-time 30"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::HoldTime(30),
            })
        );
        assert_eq!(
            Command::parse("set keepalive-interval 10"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::KeepaliveInterval(10),
            })
        );
        assert_eq!(
            Command::parse("set connect-retry-time 45"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::ConnectRetryTime(45),
            })
        );
    }

    #[test]
    fn delete_peer_group_timers_relative() {
        assert_eq!(
            Command::parse("delete hold-time"),
            Command::Delete(DeleteTarget::HoldTime)
        );
        assert_eq!(
            Command::parse("delete keepalive-interval"),
            Command::Delete(DeleteTarget::KeepaliveInterval)
        );
        assert_eq!(
            Command::parse("delete connect-retry-time"),
            Command::Delete(DeleteTarget::ConnectRetryTime)
        );
    }

    #[test]
    fn set_ospf_profile_fields_qualified() {
        assert_eq!(
            Command::parse("set ospf instance o1 area 0.0.0.0 profile p1 hello-interval 5"),
            Command::Set(SetTarget::OspfProfile {
                instance: "o1".to_string(),
                area_id: "0.0.0.0".parse().unwrap(),
                name: "p1".to_string(),
                field: OspfProfileField::HelloInterval(5),
            })
        );
        assert_eq!(
            Command::parse("set ospf instance o1 area 0.0.0.0 profile p1 dead-interval 20"),
            Command::Set(SetTarget::OspfProfile {
                instance: "o1".to_string(),
                area_id: "0.0.0.0".parse().unwrap(),
                name: "p1".to_string(),
                field: OspfProfileField::DeadInterval(20),
            })
        );
        assert_eq!(
            Command::parse("set ospf instance o1 area 0.0.0.0 profile p1 cost 15"),
            Command::Set(SetTarget::OspfProfile {
                instance: "o1".to_string(),
                area_id: "0.0.0.0".parse().unwrap(),
                name: "p1".to_string(),
                field: OspfProfileField::Cost(15),
            })
        );
        assert_eq!(
            Command::parse("set ospf instance o1 area 0.0.0.0 profile p1 priority 200"),
            Command::Set(SetTarget::OspfProfile {
                instance: "o1".to_string(),
                area_id: "0.0.0.0".parse().unwrap(),
                name: "p1".to_string(),
                field: OspfProfileField::Priority(200),
            })
        );
        assert_eq!(
            Command::parse(
                "set ospf instance o1 area 0.0.0.0 profile p1 network-type point-to-point"
            ),
            Command::Set(SetTarget::OspfProfile {
                instance: "o1".to_string(),
                area_id: "0.0.0.0".parse().unwrap(),
                name: "p1".to_string(),
                field: OspfProfileField::NetworkType(NetworkType::PointToPoint),
            })
        );
        assert_eq!(
            Command::parse("set ospf instance o1 area 0.0.0.0 profile p1 network-type broadcast"),
            Command::Set(SetTarget::OspfProfile {
                instance: "o1".to_string(),
                area_id: "0.0.0.0".parse().unwrap(),
                name: "p1".to_string(),
                field: OspfProfileField::NetworkType(NetworkType::Broadcast),
            })
        );
    }

    #[test]
    fn set_ospf_profile_fields_relative() {
        assert_eq!(
            Command::parse("set hello-interval 5"),
            Command::Set(SetTarget::OspfProfileRelative {
                field: OspfProfileField::HelloInterval(5),
            })
        );
        assert_eq!(
            Command::parse("set dead-interval 20"),
            Command::Set(SetTarget::OspfProfileRelative {
                field: OspfProfileField::DeadInterval(20),
            })
        );
        assert_eq!(
            Command::parse("set cost 15"),
            Command::Set(SetTarget::OspfProfileRelative {
                field: OspfProfileField::Cost(15),
            })
        );
        assert_eq!(
            Command::parse("set priority 200"),
            Command::Set(SetTarget::OspfProfileRelative {
                field: OspfProfileField::Priority(200),
            })
        );
        assert_eq!(
            Command::parse("set network-type point-to-point"),
            Command::Set(SetTarget::OspfProfileRelative {
                field: OspfProfileField::NetworkType(NetworkType::PointToPoint),
            })
        );
        assert_eq!(
            Command::parse("set network-type broadcast"),
            Command::Set(SetTarget::OspfProfileRelative {
                field: OspfProfileField::NetworkType(NetworkType::Broadcast),
            })
        );
    }

    #[test]
    fn delete_ospf_profile_fields_relative() {
        assert_eq!(
            Command::parse("delete hello-interval"),
            Command::Delete(DeleteTarget::HelloInterval)
        );
        assert_eq!(
            Command::parse("delete dead-interval"),
            Command::Delete(DeleteTarget::DeadInterval)
        );
        assert_eq!(
            Command::parse("delete cost"),
            Command::Delete(DeleteTarget::Cost)
        );
        assert_eq!(
            Command::parse("delete priority"),
            Command::Delete(DeleteTarget::Priority)
        );
        assert_eq!(
            Command::parse("delete network-type"),
            Command::Delete(DeleteTarget::NetworkType)
        );
    }

    #[test]
    fn set_ospf_simple_password_qualified_and_relative() {
        assert_eq!(
            Command::parse("set ospf instance o1 area 0.0.0.0 profile p1 simple-password hunter2"),
            Command::Set(SetTarget::OspfProfile {
                instance: "o1".to_string(),
                area_id: "0.0.0.0".parse().unwrap(),
                name: "p1".to_string(),
                field: OspfProfileField::SimplePassword("hunter2".to_string()),
            })
        );
        assert_eq!(
            Command::parse("set simple-password hunter2"),
            Command::Set(SetTarget::OspfProfileRelative {
                field: OspfProfileField::SimplePassword("hunter2".to_string()),
            })
        );
    }

    #[test]
    fn set_ospf_crypto_key_qualified_and_relative() {
        assert_eq!(
            Command::parse(
                "set ospf instance o1 area 0.0.0.0 profile p1 crypto-key 1 hmac-sha256 secret"
            ),
            Command::Set(SetTarget::OspfProfile {
                instance: "o1".to_string(),
                area_id: "0.0.0.0".parse().unwrap(),
                name: "p1".to_string(),
                field: OspfProfileField::CryptoKey {
                    key_id: 1,
                    algorithm: OspfCryptoAlgorithm::HmacSha256,
                    key: "secret".to_string(),
                },
            })
        );
        assert_eq!(
            Command::parse("set crypto-key 1 md5 secret"),
            Command::Set(SetTarget::OspfProfileRelative {
                field: OspfProfileField::CryptoKey {
                    key_id: 1,
                    algorithm: OspfCryptoAlgorithm::Md5,
                    key: "secret".to_string(),
                },
            })
        );
    }

    #[test]
    fn set_ospf_crypto_key_bad_algorithm_is_unknown() {
        assert_eq!(
            Command::parse("set crypto-key 1 rot13 secret"),
            Command::Unknown("set crypto-key 1 rot13 secret".to_string())
        );
    }

    #[test]
    fn set_ospf_crypto_current_key() {
        assert_eq!(
            Command::parse("set crypto-key 1 current"),
            Command::Set(SetTarget::OspfProfileRelative {
                field: OspfProfileField::CryptoCurrentKey(1),
            })
        );
        assert_eq!(
            Command::parse("set ospf instance o1 area 0.0.0.0 profile p1 crypto-key 1 current"),
            Command::Set(SetTarget::OspfProfile {
                instance: "o1".to_string(),
                area_id: "0.0.0.0".parse().unwrap(),
                name: "p1".to_string(),
                field: OspfProfileField::CryptoCurrentKey(1),
            })
        );
    }

    #[test]
    fn delete_ospf_crypto_key() {
        assert_eq!(
            Command::parse("delete crypto-key 1"),
            Command::Delete(DeleteTarget::CryptoKey(1))
        );
    }

    #[test]
    fn set_md5_password_qualified_and_relative() {
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 md5-password hunter2"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::Md5Password("hunter2".to_string()),
            })
        );
        assert_eq!(
            Command::parse("set md5-password hunter2"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::Md5Password("hunter2".to_string()),
            })
        );
    }

    #[test]
    fn set_ao_key_qualified_and_relative() {
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 ao-key 1 2 hmac-sha1 secret"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::AoKey {
                    send_id: 1,
                    recv_id: 2,
                    algorithm: BgpAoAlgorithm::HmacSha1_96,
                    key: "secret".to_string(),
                },
            })
        );
        assert_eq!(
            Command::parse("set ao-key 1 2 aes-cmac secret"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::AoKey {
                    send_id: 1,
                    recv_id: 2,
                    algorithm: BgpAoAlgorithm::AesCmac96,
                    key: "secret".to_string(),
                },
            })
        );
    }

    #[test]
    fn set_ao_key_bad_algorithm_is_unknown() {
        assert_eq!(
            Command::parse("set ao-key 1 2 rot13 secret"),
            Command::Unknown("set ao-key 1 2 rot13 secret".to_string())
        );
    }

    #[test]
    fn set_ao_key_current_and_rnext() {
        assert_eq!(
            Command::parse("set ao-key 1 current"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::AoCurrentKey(1),
            })
        );
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 ao-key 1 rnext"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::AoRnextKey(1),
            })
        );
    }

    #[test]
    fn delete_auth_and_ao_key() {
        assert_eq!(
            Command::parse("delete auth"),
            Command::Delete(DeleteTarget::Auth)
        );
        assert_eq!(
            Command::parse("delete ao-key 1"),
            Command::Delete(DeleteTarget::AoKey(1))
        );
    }

    #[test]
    fn set_remote_as_relative() {
        assert_eq!(
            Command::parse("set remote-as 65001"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::RemoteAs(65001),
            })
        );
    }

    #[test]
    fn set_peer_qualified_and_relative() {
        assert_eq!(
            Command::parse("set bgp instance R1 peer 192.0.2.1 peer-group PG1"),
            Command::Set(SetTarget::BgpPeer {
                instance: "R1".to_string(),
                remote_address: "192.0.2.1".parse::<IpAddr>().unwrap(),
                peer_group: "PG1".to_string(),
            })
        );
        assert_eq!(
            Command::parse("set peer 192.0.2.1 peer-group PG1"),
            Command::Set(SetTarget::PeerRelative {
                remote_address: "192.0.2.1".parse::<IpAddr>().unwrap(),
                peer_group: "PG1".to_string(),
            })
        );
    }

    #[test]
    fn delete_bgp_peer_group_qualified_and_relative() {
        assert_eq!(
            Command::parse("delete bgp instance R1 peer-group PG1"),
            Command::Delete(DeleteTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                name: "PG1".to_string(),
            })
        );
        assert_eq!(
            Command::parse("delete peer-group PG1"),
            Command::Delete(DeleteTarget::PeerGroupRelative {
                name: "PG1".to_string()
            })
        );
    }

    #[test]
    fn delete_peer_qualified_and_relative() {
        assert_eq!(
            Command::parse("delete bgp instance R1 peer 192.0.2.1"),
            Command::Delete(DeleteTarget::BgpPeer {
                instance: "R1".to_string(),
                remote_address: "192.0.2.1".parse::<IpAddr>().unwrap(),
            })
        );
        assert_eq!(
            Command::parse("delete peer 192.0.2.1"),
            Command::Delete(DeleteTarget::PeerRelative {
                remote_address: "192.0.2.1".parse::<IpAddr>().unwrap(),
            })
        );
    }

    #[test]
    fn edit_routing_table() {
        assert_eq!(
            Command::parse("edit routing-table rt1"),
            Command::Edit(EditTarget::RoutingTable {
                name: "rt1".to_string()
            })
        );
    }

    #[test]
    fn edit_static_routing_instance() {
        assert_eq!(
            Command::parse("edit static-routing-instance sri1"),
            Command::Edit(EditTarget::StaticRoutingInstance {
                name: "sri1".to_string()
            })
        );
    }

    #[test]
    fn set_routing_table_bgp_instance_qualified_and_relative() {
        assert_eq!(
            Command::parse("set routing-table rt1 bgp-instance r1"),
            Command::Set(SetTarget::RoutingTable {
                name: "rt1".to_string(),
                bgp_instance: "r1".to_string(),
            })
        );
        assert_eq!(
            Command::parse("set bgp-instance r1"),
            Command::Set(SetTarget::RoutingTableRelative {
                bgp_instance: "r1".to_string(),
            })
        );
    }

    #[test]
    fn set_routing_table_static_routing_instance_qualified_and_relative() {
        assert_eq!(
            Command::parse("set routing-table rt1 static-routing-instance sri1"),
            Command::Set(SetTarget::RoutingTableStaticRoutingInstance {
                name: "rt1".to_string(),
                static_routing_instance: "sri1".to_string(),
            })
        );
        assert_eq!(
            Command::parse("set static-routing-instance sri1"),
            Command::Set(SetTarget::RoutingTableStaticRoutingInstanceRelative {
                static_routing_instance: "sri1".to_string(),
            })
        );
    }

    #[test]
    fn set_routing_table_redistribute_qualified_and_relative() {
        let redistribute = Redistribute {
            from: RedistributeSource::Static,
            to: RedistributeTarget::Bgp,
            policy: None,
        };
        assert_eq!(
            Command::parse("set routing-table rt1 redistribute from static to bgp"),
            Command::Set(SetTarget::RoutingTableRedistribute {
                name: "rt1".to_string(),
                redistribute: redistribute.clone(),
            })
        );
        assert_eq!(
            Command::parse("set redistribute from static to bgp"),
            Command::Set(SetTarget::RoutingTableRedistributeRelative { redistribute })
        );
    }

    #[test]
    fn set_routing_table_redistribute_with_policy_qualified_and_relative() {
        let redistribute = Redistribute {
            from: RedistributeSource::Static,
            to: RedistributeTarget::Bgp,
            policy: Some("p1".to_string()),
        };
        assert_eq!(
            Command::parse("set routing-table rt1 redistribute from static to bgp policy p1"),
            Command::Set(SetTarget::RoutingTableRedistribute {
                name: "rt1".to_string(),
                redistribute: redistribute.clone(),
            })
        );
        assert_eq!(
            Command::parse("set redistribute from static to bgp policy p1"),
            Command::Set(SetTarget::RoutingTableRedistributeRelative { redistribute })
        );
    }

    #[test]
    fn set_routing_table_redistribute_to_ospf_qualified_and_relative() {
        let redistribute = Redistribute {
            from: RedistributeSource::Static,
            to: RedistributeTarget::Ospf,
            policy: None,
        };
        assert_eq!(
            Command::parse("set routing-table rt1 redistribute from static to ospf"),
            Command::Set(SetTarget::RoutingTableRedistribute {
                name: "rt1".to_string(),
                redistribute: redistribute.clone(),
            })
        );
        assert_eq!(
            Command::parse("set redistribute from static to ospf"),
            Command::Set(SetTarget::RoutingTableRedistributeRelative { redistribute })
        );
    }

    #[test]
    fn set_routing_table_redistribute_to_ospf_with_policy_qualified_and_relative() {
        let redistribute = Redistribute {
            from: RedistributeSource::Static,
            to: RedistributeTarget::Ospf,
            policy: Some("p1".to_string()),
        };
        assert_eq!(
            Command::parse("set routing-table rt1 redistribute from static to ospf policy p1"),
            Command::Set(SetTarget::RoutingTableRedistribute {
                name: "rt1".to_string(),
                redistribute: redistribute.clone(),
            })
        );
        assert_eq!(
            Command::parse("set redistribute from static to ospf policy p1"),
            Command::Set(SetTarget::RoutingTableRedistributeRelative { redistribute })
        );
    }

    #[test]
    fn set_static_route_qualified_and_relative() {
        assert_eq!(
            Command::parse("set static-routing-instance sri1 route 10.0.0.0/24 gateway 10.0.0.1"),
            Command::Set(SetTarget::StaticRoute {
                instance: "sri1".to_string(),
                subnet: "10.0.0.0/24".parse().unwrap(),
                gateway: "10.0.0.1".parse().unwrap(),
            })
        );
        assert_eq!(
            Command::parse("set route 10.0.0.0/24 gateway 10.0.0.1"),
            Command::Set(SetTarget::StaticRouteRelative {
                subnet: "10.0.0.0/24".parse().unwrap(),
                gateway: "10.0.0.1".parse().unwrap(),
            })
        );
    }

    #[test]
    fn set_static_route_malformed_subnet_is_unknown() {
        assert_eq!(
            Command::parse("set route not-a-subnet gateway 10.0.0.1"),
            Command::Unknown("set route not-a-subnet gateway 10.0.0.1".to_string())
        );
    }

    #[test]
    fn delete_routing_table_and_its_associations() {
        assert_eq!(
            Command::parse("delete routing-table rt1"),
            Command::Delete(DeleteTarget::RoutingTable {
                name: "rt1".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete routing-table rt1 bgp-instance"),
            Command::Delete(DeleteTarget::RoutingTableBgpInstance {
                name: "rt1".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete bgp-instance"),
            Command::Delete(DeleteTarget::RoutingTableBgpInstanceRelative)
        );
        assert_eq!(
            Command::parse("delete routing-table rt1 static-routing-instance"),
            Command::Delete(DeleteTarget::RoutingTableStaticRoutingInstance {
                name: "rt1".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete static-routing-instance"),
            Command::Delete(DeleteTarget::RoutingTableStaticRoutingInstanceRelative)
        );
        assert_eq!(
            Command::parse("delete routing-table rt1 redistribute"),
            Command::Delete(DeleteTarget::RoutingTableRedistribute {
                name: "rt1".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete redistribute"),
            Command::Delete(DeleteTarget::RoutingTableRedistributeRelative)
        );
    }

    #[test]
    fn delete_static_routing_instance_and_its_routes() {
        assert_eq!(
            Command::parse("delete static-routing-instance sri1"),
            Command::Delete(DeleteTarget::StaticRoutingInstance {
                name: "sri1".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete static-routing-instance sri1 route 10.0.0.0/24"),
            Command::Delete(DeleteTarget::StaticRoute {
                instance: "sri1".to_string(),
                subnet: "10.0.0.0/24".parse().unwrap(),
            })
        );
        assert_eq!(
            Command::parse("delete route 10.0.0.0/24"),
            Command::Delete(DeleteTarget::StaticRouteRelative {
                subnet: "10.0.0.0/24".parse().unwrap(),
            })
        );
    }

    #[test]
    fn delete_source_address_and_address_family() {
        assert_eq!(
            Command::parse("delete source-address"),
            Command::Delete(DeleteTarget::SourceAddress)
        );
        assert_eq!(
            Command::parse("delete address-family ipv4"),
            Command::Delete(DeleteTarget::AddressFamily(AddressFamily::Ipv4Unicast))
        );
        assert_eq!(
            Command::parse("delete address-family ipv6"),
            Command::Delete(DeleteTarget::AddressFamily(AddressFamily::Ipv6Unicast))
        );
        assert_eq!(
            Command::parse("delete address-family l2vpn-evpn"),
            Command::Delete(DeleteTarget::AddressFamily(AddressFamily::L2vpnEvpn))
        );
        assert_eq!(
            Command::parse("set address-family l2vpn-evpn"),
            Command::Set(SetTarget::PeerGroupRelative {
                field: BgpPeerGroupField::AddressFamily(AddressFamily::L2vpnEvpn),
            })
        );
        assert_eq!(
            Command::parse("set bgp instance R1 peer-group PG1 address-family l2vpn-evpn"),
            Command::Set(SetTarget::BgpPeerGroup {
                instance: "R1".to_string(),
                group: "PG1".to_string(),
                field: BgpPeerGroupField::AddressFamily(AddressFamily::L2vpnEvpn),
            })
        );
    }

    #[test]
    fn show_log_variants() {
        assert_eq!(
            Command::parse("show log"),
            Command::ShowLog {
                source: None,
                follow: false,
            }
        );
        assert_eq!(
            Command::parse("show log --follow"),
            Command::ShowLog {
                source: None,
                follow: true,
            }
        );
        assert_eq!(
            Command::parse("show log nos-ribd[rt1]"),
            Command::ShowLog {
                source: Some("nos-ribd[rt1]".to_string()),
                follow: false,
            }
        );
        assert_eq!(
            Command::parse("show log nos-ribd[rt1] --follow"),
            Command::ShowLog {
                source: Some("nos-ribd[rt1]".to_string()),
                follow: true,
            }
        );
    }

    #[test]
    fn show_bgp_brief() {
        assert_eq!(Command::parse("show bgp brief"), Command::ShowBgpBrief);
    }

    #[test]
    fn show_bgp_evpn() {
        assert_eq!(Command::parse("show bgp evpn"), Command::ShowBgpEvpn);
    }

    #[test]
    fn show_ospf_neigh() {
        assert_eq!(Command::parse("show ospf neigh"), Command::ShowOspfNeigh);
    }

    #[test]
    fn clear_bgp_soft_in() {
        assert_eq!(
            Command::parse("clear bgp r1 10.0.0.1 soft-in"),
            Command::ClearBgpSoftIn {
                instance: "r1".to_string(),
                peer: "10.0.0.1".parse().unwrap(),
            }
        );
        assert_eq!(
            Command::parse("clear bgp r1 not-an-ip soft-in"),
            Command::Unknown("clear bgp r1 not-an-ip soft-in".to_string())
        );
    }

    #[test]
    fn show_interface_all_and_named() {
        assert_eq!(
            Command::parse("show interface"),
            Command::ShowInterface { name: None }
        );
        assert_eq!(
            Command::parse("show interface eth0"),
            Command::ShowInterface {
                name: Some("eth0".to_string())
            }
        );
    }

    #[test]
    fn edit_interface() {
        assert_eq!(
            Command::parse("edit interface eth0"),
            Command::Edit(EditTarget::Interface {
                name: "eth0".to_string()
            })
        );
    }

    #[test]
    fn set_interface_address_qualified_and_relative() {
        assert_eq!(
            Command::parse("set interface eth0 address 10.0.0.1/24"),
            Command::Set(SetTarget::InterfaceAddress {
                name: "eth0".to_string(),
                address: "10.0.0.1/24".parse().unwrap(),
                label: None,
            })
        );
        assert_eq!(
            Command::parse("set address 10.0.0.1/24"),
            Command::Set(SetTarget::InterfaceAddressRelative {
                address: "10.0.0.1/24".parse().unwrap(),
                label: None,
            })
        );
    }

    #[test]
    fn set_interface_address_with_label_qualified_and_relative() {
        assert_eq!(
            Command::parse("set interface eth0 address 10.0.0.1/24 label mgmt"),
            Command::Set(SetTarget::InterfaceAddress {
                name: "eth0".to_string(),
                address: "10.0.0.1/24".parse().unwrap(),
                label: Some("mgmt".to_string()),
            })
        );
        assert_eq!(
            Command::parse("set address 10.0.0.1/24 label mgmt"),
            Command::Set(SetTarget::InterfaceAddressRelative {
                address: "10.0.0.1/24".parse().unwrap(),
                label: Some("mgmt".to_string()),
            })
        );
    }

    #[test]
    fn set_interface_address_malformed_is_unknown() {
        assert_eq!(
            Command::parse("set interface eth0 address not-a-cidr"),
            Command::Unknown("set interface eth0 address not-a-cidr".to_string())
        );
    }

    #[test]
    fn set_interface_routing_table_qualified_and_relative() {
        assert_eq!(
            Command::parse("set interface eth0 routing-table rt1"),
            Command::Set(SetTarget::InterfaceRoutingTable {
                name: "eth0".to_string(),
                routing_table: "rt1".to_string(),
            })
        );
        assert_eq!(
            Command::parse("set routing-table rt1"),
            Command::Set(SetTarget::InterfaceRoutingTableRelative {
                routing_table: "rt1".to_string(),
            })
        );
    }

    #[test]
    fn set_interface_mtu_qualified() {
        assert_eq!(
            Command::parse("set interface eth0 mtu 9000"),
            Command::Set(SetTarget::InterfaceMtu {
                name: "eth0".to_string(),
                mtu: 9000,
            })
        );
    }

    #[test]
    fn set_mtu_relative_is_ambiguous_by_token_alone() {
        // Resolved against `Path::Interface` or `Path::OspfProfile` at
        // resolve time — see `SetTarget::MtuRelative`'s doc comment.
        assert_eq!(
            Command::parse("set mtu 9000"),
            Command::Set(SetTarget::MtuRelative(9000))
        );
    }

    #[test]
    fn set_ospf_profile_mtu_qualified() {
        assert_eq!(
            Command::parse("set ospf instance o1 area 0.0.0.0 profile p1 mtu 1400"),
            Command::Set(SetTarget::OspfProfile {
                instance: "o1".to_string(),
                area_id: "0.0.0.0".parse().unwrap(),
                name: "p1".to_string(),
                field: OspfProfileField::Mtu(1400),
            })
        );
    }

    #[test]
    fn set_interface_switching_profile_qualified_and_relative() {
        assert_eq!(
            Command::parse("set interface eth0 switching-profile sp1"),
            Command::Set(SetTarget::InterfaceSwitchingProfile {
                name: "eth0".to_string(),
                switching_profile: "sp1".to_string(),
            })
        );
        assert_eq!(
            Command::parse("set switching-profile sp1"),
            Command::Set(SetTarget::InterfaceSwitchingProfileRelative {
                switching_profile: "sp1".to_string(),
            })
        );
    }

    #[test]
    fn edit_ospf_area_qualified_and_relative() {
        assert_eq!(
            Command::parse("edit ospf instance o1 area 0.0.0.0"),
            Command::Edit(EditTarget::OspfArea {
                instance: "o1".to_string(),
                area_id: "0.0.0.0".parse().unwrap(),
            })
        );
        assert_eq!(
            Command::parse("edit area 0.0.0.0"),
            Command::Edit(EditTarget::OspfAreaRelative {
                area_id: "0.0.0.0".parse().unwrap(),
            })
        );
    }

    #[test]
    fn edit_ospf_profile_qualified_and_relative() {
        assert_eq!(
            Command::parse("edit ospf instance o1 area 0.0.0.0 profile p1"),
            Command::Edit(EditTarget::OspfProfile {
                instance: "o1".to_string(),
                area_id: "0.0.0.0".parse().unwrap(),
                name: "p1".to_string(),
            })
        );
        assert_eq!(
            Command::parse("edit profile p1"),
            Command::Edit(EditTarget::OspfProfileRelative {
                name: "p1".to_string(),
            })
        );
    }

    #[test]
    fn set_interface_ospf_profile_qualified_and_relative() {
        assert_eq!(
            Command::parse("set interface eth0 ospf p1"),
            Command::Set(SetTarget::InterfaceOspfProfile {
                name: "eth0".to_string(),
                ospf_profile: "p1".to_string(),
            })
        );
        assert_eq!(
            Command::parse("set ospf p1"),
            Command::Set(SetTarget::InterfaceOspfProfileRelative {
                ospf_profile: "p1".to_string(),
            })
        );
    }

    #[test]
    fn delete_ospf_area_qualified_and_relative() {
        assert_eq!(
            Command::parse("delete ospf instance o1 area 0.0.0.0"),
            Command::Delete(DeleteTarget::OspfArea {
                instance: "o1".to_string(),
                area_id: "0.0.0.0".parse().unwrap(),
            })
        );
        assert_eq!(
            Command::parse("delete area 0.0.0.0"),
            Command::Delete(DeleteTarget::OspfAreaRelative {
                area_id: "0.0.0.0".parse().unwrap(),
            })
        );
    }

    #[test]
    fn delete_ospf_profile_qualified_and_relative() {
        assert_eq!(
            Command::parse("delete ospf instance o1 area 0.0.0.0 profile p1"),
            Command::Delete(DeleteTarget::OspfProfile {
                instance: "o1".to_string(),
                area_id: "0.0.0.0".parse().unwrap(),
                name: "p1".to_string(),
            })
        );
        assert_eq!(
            Command::parse("delete profile p1"),
            Command::Delete(DeleteTarget::OspfProfileRelative {
                name: "p1".to_string(),
            })
        );
    }

    #[test]
    fn delete_interface_ospf_profile_qualified_and_relative() {
        assert_eq!(
            Command::parse("delete interface eth0 ospf"),
            Command::Delete(DeleteTarget::InterfaceOspfProfile {
                name: "eth0".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete ospf"),
            Command::Delete(DeleteTarget::InterfaceOspfProfileRelative)
        );
    }

    #[test]
    fn delete_interface_qualified() {
        assert_eq!(
            Command::parse("delete interface eth0"),
            Command::Delete(DeleteTarget::Interface {
                name: "eth0".to_string()
            })
        );
    }

    #[test]
    fn delete_interface_address_qualified_and_relative() {
        assert_eq!(
            Command::parse("delete interface eth0 address 10.0.0.1/24"),
            Command::Delete(DeleteTarget::InterfaceAddress {
                name: "eth0".to_string(),
                address: "10.0.0.1/24".parse().unwrap(),
            })
        );
        assert_eq!(
            Command::parse("delete address 10.0.0.1/24"),
            Command::Delete(DeleteTarget::InterfaceAddressRelative {
                address: "10.0.0.1/24".parse().unwrap(),
            })
        );
    }

    #[test]
    fn delete_interface_routing_table_qualified_and_relative() {
        assert_eq!(
            Command::parse("delete interface eth0 routing-table"),
            Command::Delete(DeleteTarget::InterfaceRoutingTable {
                name: "eth0".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete routing-table"),
            Command::Delete(DeleteTarget::InterfaceRoutingTableRelative)
        );
    }

    #[test]
    fn delete_interface_mtu_qualified() {
        assert_eq!(
            Command::parse("delete interface eth0 mtu"),
            Command::Delete(DeleteTarget::InterfaceMtu {
                name: "eth0".to_string()
            })
        );
    }

    #[test]
    fn delete_mtu_relative_is_ambiguous_by_token_alone() {
        assert_eq!(
            Command::parse("delete mtu"),
            Command::Delete(DeleteTarget::MtuRelative)
        );
    }

    #[test]
    fn delete_interface_switching_profile_qualified_and_relative() {
        assert_eq!(
            Command::parse("delete interface eth0 switching-profile"),
            Command::Delete(DeleteTarget::InterfaceSwitchingProfile {
                name: "eth0".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete switching-profile"),
            Command::Delete(DeleteTarget::InterfaceSwitchingProfileRelative)
        );
    }

    #[test]
    fn edit_community_alias_group_and_prefix_list() {
        assert_eq!(
            Command::parse("edit community-alias CUSTOMER_A"),
            Command::Edit(EditTarget::CommunityAlias {
                name: "CUSTOMER_A".to_string()
            })
        );
        assert_eq!(
            Command::parse("edit community-group CUSTOMERS"),
            Command::Edit(EditTarget::CommunityGroup {
                name: "CUSTOMERS".to_string()
            })
        );
        assert_eq!(
            Command::parse("edit prefix-list BLOCKS"),
            Command::Edit(EditTarget::PrefixList {
                name: "BLOCKS".to_string()
            })
        );
    }

    #[test]
    fn set_community_alias_value_qualified_and_relative() {
        assert_eq!(
            Command::parse("set community-alias CUSTOMER_A value 65000:100"),
            Command::Set(SetTarget::CommunityAliasValue {
                name: "CUSTOMER_A".to_string(),
                value: "65000:100".to_string(),
            })
        );
        assert_eq!(
            Command::parse("set value 65000:100"),
            Command::Set(SetTarget::CommunityAliasValueRelative {
                value: "65000:100".to_string(),
            })
        );
    }

    #[test]
    fn set_community_group_member_qualified_and_relative() {
        assert_eq!(
            Command::parse("set community-group CUSTOMERS member CUSTOMER_A"),
            Command::Set(SetTarget::CommunityGroupMember {
                name: "CUSTOMERS".to_string(),
                member: "CUSTOMER_A".to_string(),
            })
        );
        assert_eq!(
            Command::parse("set member 65000:200"),
            Command::Set(SetTarget::CommunityGroupMemberRelative {
                member: "65000:200".to_string(),
            })
        );
    }

    #[test]
    fn set_prefix_list_entry_orlonger_and_upto_shorthands() {
        assert_eq!(
            Command::parse("set prefix-list BLOCKS entry 10.0.0.0/8 orlonger"),
            Command::Set(SetTarget::PrefixListEntry {
                name: "BLOCKS".to_string(),
                cidr: "10.0.0.0/8".parse().unwrap(),
                range: Some((8, 32)),
            })
        );
        assert_eq!(
            Command::parse("set entry 10.0.0.0/8 upto 24"),
            Command::Set(SetTarget::PrefixListEntryRelative {
                cidr: "10.0.0.0/8".parse().unwrap(),
                range: Some((8, 24)),
            })
        );
    }

    #[test]
    fn set_prefix_list_entry_with_and_without_range() {
        assert_eq!(
            Command::parse("set prefix-list BLOCKS entry 10.0.0.0/8"),
            Command::Set(SetTarget::PrefixListEntry {
                name: "BLOCKS".to_string(),
                cidr: "10.0.0.0/8".parse().unwrap(),
                range: None,
            })
        );
        assert_eq!(
            Command::parse("set prefix-list BLOCKS entry 10.0.0.0/8 range 24 32"),
            Command::Set(SetTarget::PrefixListEntry {
                name: "BLOCKS".to_string(),
                cidr: "10.0.0.0/8".parse().unwrap(),
                range: Some((24, 32)),
            })
        );
        assert_eq!(
            Command::parse("set entry 10.0.0.0/8"),
            Command::Set(SetTarget::PrefixListEntryRelative {
                cidr: "10.0.0.0/8".parse().unwrap(),
                range: None,
            })
        );
        assert_eq!(
            Command::parse("set entry 10.0.0.0/8 range 24 32"),
            Command::Set(SetTarget::PrefixListEntryRelative {
                cidr: "10.0.0.0/8".parse().unwrap(),
                range: Some((24, 32)),
            })
        );
    }

    #[test]
    fn set_prefix_list_entry_malformed_is_unknown() {
        assert_eq!(
            Command::parse("set prefix-list BLOCKS entry not-a-cidr"),
            Command::Unknown("set prefix-list BLOCKS entry not-a-cidr".to_string())
        );
        assert_eq!(
            Command::parse("set entry 10.0.0.0/8 range not-a-number 32"),
            Command::Unknown("set entry 10.0.0.0/8 range not-a-number 32".to_string())
        );
    }

    #[test]
    fn delete_community_alias_group_member_and_prefix_list_entry() {
        assert_eq!(
            Command::parse("delete community-alias CUSTOMER_A"),
            Command::Delete(DeleteTarget::CommunityAlias {
                name: "CUSTOMER_A".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete community-group CUSTOMERS member CUSTOMER_A"),
            Command::Delete(DeleteTarget::CommunityGroupMember {
                name: "CUSTOMERS".to_string(),
                member: "CUSTOMER_A".to_string(),
            })
        );
        assert_eq!(
            Command::parse("delete member CUSTOMER_A"),
            Command::Delete(DeleteTarget::CommunityGroupMemberRelative {
                member: "CUSTOMER_A".to_string(),
            })
        );
        assert_eq!(
            Command::parse("delete prefix-list BLOCKS"),
            Command::Delete(DeleteTarget::PrefixList {
                name: "BLOCKS".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete prefix-list BLOCKS entry 10.0.0.0/8 range 24 32"),
            Command::Delete(DeleteTarget::PrefixListEntry {
                name: "BLOCKS".to_string(),
                cidr: "10.0.0.0/8".parse().unwrap(),
                range: Some((24, 32)),
            })
        );
        assert_eq!(
            Command::parse("delete entry 10.0.0.0/8"),
            Command::Delete(DeleteTarget::PrefixListEntryRelative {
                cidr: "10.0.0.0/8".parse().unwrap(),
                range: None,
            })
        );
    }

    #[test]
    fn show_ospfv3_neigh_and_database() {
        assert_eq!(
            Command::parse("show ospfv3 neigh"),
            Command::ShowOspfv3Neigh
        );
        assert_eq!(
            Command::parse("show ospfv3 database"),
            Command::ShowOspfv3Database
        );
    }

    #[test]
    fn edit_ospfv3_instance() {
        assert_eq!(
            Command::parse("edit ospfv3 instance o1"),
            Command::Edit(EditTarget::Ospfv3Instance {
                name: "o1".to_string()
            })
        );
    }

    #[test]
    fn edit_ospfv3_area_qualified_and_relative_shares_ospf_token() {
        assert_eq!(
            Command::parse("edit ospfv3 instance o1 area 0.0.0.0"),
            Command::Edit(EditTarget::Ospfv3Area {
                instance: "o1".to_string(),
                area_id: "0.0.0.0".parse().unwrap(),
            })
        );
        // The relative form is the same token sequence (and Command) as
        // OSPFv2's — disambiguated by path at resolve time, not parse time.
        assert_eq!(
            Command::parse("edit area 0.0.0.0"),
            Command::Edit(EditTarget::OspfAreaRelative {
                area_id: "0.0.0.0".parse().unwrap(),
            })
        );
    }

    #[test]
    fn edit_ospfv3_profile_qualified_and_relative_shares_ospf_token() {
        assert_eq!(
            Command::parse("edit ospfv3 instance o1 area 0.0.0.0 profile p1"),
            Command::Edit(EditTarget::Ospfv3Profile {
                instance: "o1".to_string(),
                area_id: "0.0.0.0".parse().unwrap(),
                name: "p1".to_string(),
            })
        );
        assert_eq!(
            Command::parse("edit profile p1"),
            Command::Edit(EditTarget::OspfProfileRelative {
                name: "p1".to_string(),
            })
        );
    }

    #[test]
    fn set_and_delete_ospfv3_instance_extended_lsa() {
        assert_eq!(
            Command::parse("set ospfv3 instance o1 extended-lsa"),
            Command::Set(SetTarget::Ospfv3InstanceExtendedLsa {
                name: "o1".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete ospfv3 instance o1 extended-lsa"),
            Command::Delete(DeleteTarget::Ospfv3InstanceExtendedLsa {
                name: "o1".to_string()
            })
        );
    }

    #[test]
    fn set_ospfv3_instance_router_id() {
        assert_eq!(
            Command::parse("set ospfv3 instance o1 router-id 2.2.2.2"),
            Command::Set(SetTarget::Ospfv3Instance {
                name: "o1".to_string(),
                router_id: "2.2.2.2".parse().unwrap(),
            })
        );
    }

    #[test]
    fn set_ospfv3_profile_fields_qualified() {
        assert_eq!(
            Command::parse("set ospfv3 instance o1 area 0.0.0.0 profile p1 hello-interval 5"),
            Command::Set(SetTarget::Ospfv3Profile {
                instance: "o1".to_string(),
                area_id: "0.0.0.0".parse().unwrap(),
                name: "p1".to_string(),
                field: OspfProfileField::HelloInterval(5),
            })
        );
        assert_eq!(
            Command::parse(
                "set ospfv3 instance o1 area 0.0.0.0 profile p1 network-type point-to-point"
            ),
            Command::Set(SetTarget::Ospfv3Profile {
                instance: "o1".to_string(),
                area_id: "0.0.0.0".parse().unwrap(),
                name: "p1".to_string(),
                field: OspfProfileField::NetworkType(NetworkType::PointToPoint),
            })
        );
    }

    #[test]
    fn delete_ospfv3_instance_area_profile_qualified() {
        assert_eq!(
            Command::parse("delete ospfv3 instance o1"),
            Command::Delete(DeleteTarget::Ospfv3Instance {
                name: "o1".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete ospfv3 instance o1 area 0.0.0.0"),
            Command::Delete(DeleteTarget::Ospfv3Area {
                instance: "o1".to_string(),
                area_id: "0.0.0.0".parse().unwrap(),
            })
        );
        assert_eq!(
            Command::parse("delete ospfv3 instance o1 area 0.0.0.0 profile p1"),
            Command::Delete(DeleteTarget::Ospfv3Profile {
                instance: "o1".to_string(),
                area_id: "0.0.0.0".parse().unwrap(),
                name: "p1".to_string(),
            })
        );
    }

    #[test]
    fn set_interface_ospfv3_profile_qualified_and_relative() {
        assert_eq!(
            Command::parse("set interface eth0 ospfv3 p1"),
            Command::Set(SetTarget::InterfaceOspfv3Profile {
                name: "eth0".to_string(),
                ospfv3_profile: "p1".to_string(),
            })
        );
        assert_eq!(
            Command::parse("set ospfv3 p1"),
            Command::Set(SetTarget::InterfaceOspfv3ProfileRelative {
                ospfv3_profile: "p1".to_string(),
            })
        );
    }

    #[test]
    fn delete_interface_ospfv3_profile_qualified_and_relative() {
        assert_eq!(
            Command::parse("delete interface eth0 ospfv3"),
            Command::Delete(DeleteTarget::InterfaceOspfv3Profile {
                name: "eth0".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete ospfv3"),
            Command::Delete(DeleteTarget::InterfaceOspfv3ProfileRelative)
        );
    }

    #[test]
    fn set_and_delete_routing_table_ospfv3_instance_qualified_and_relative() {
        assert_eq!(
            Command::parse("set routing-table rt1 ospfv3-instance o1"),
            Command::Set(SetTarget::RoutingTableOspfv3Instance {
                name: "rt1".to_string(),
                ospfv3_instance: "o1".to_string(),
            })
        );
        assert_eq!(
            Command::parse("set ospfv3-instance o1"),
            Command::Set(SetTarget::RoutingTableOspfv3InstanceRelative {
                ospfv3_instance: "o1".to_string(),
            })
        );
        assert_eq!(
            Command::parse("delete routing-table rt1 ospfv3-instance"),
            Command::Delete(DeleteTarget::RoutingTableOspfv3Instance {
                name: "rt1".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete ospfv3-instance"),
            Command::Delete(DeleteTarget::RoutingTableOspfv3InstanceRelative)
        );
    }

    #[test]
    fn set_and_delete_routing_table_rest_api() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            Command::parse("set routing-table rt1 rest-api address 10.0.0.1"),
            Command::Set(SetTarget::RoutingTableRestApi {
                name: "rt1".to_string(),
                address: addr,
                port: 8080,
            })
        );
        assert_eq!(
            Command::parse("set rest-api address 10.0.0.1 port 9000"),
            Command::Set(SetTarget::RoutingTableRestApiRelative {
                address: addr,
                port: 9000,
            })
        );
        assert!(matches!(
            Command::parse("set rest-api address not-an-ip"),
            Command::Unknown(_)
        ));
        assert_eq!(
            Command::parse("delete routing-table rt1 rest-api"),
            Command::Delete(DeleteTarget::RoutingTableRestApi {
                name: "rt1".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete rest-api"),
            Command::Delete(DeleteTarget::RoutingTableRestApiRelative)
        );
    }

    #[test]
    fn port_aggregate_esi_and_lacp_system_id() {
        assert_eq!(
            Command::parse("set port-aggregate bond1 esi 00:11:22:33:44:55:66:77:88:99"),
            Command::Set(SetTarget::PortAggregateField(PortAggregateOp::SetEsi {
                name: "bond1".to_string(),
                esi: "00:11:22:33:44:55:66:77:88:99".to_string(),
            }))
        );
        assert_eq!(
            Command::parse("delete port-aggregate bond1 lacp-system-id"),
            Command::Delete(DeleteTarget::PortAggregateField(
                PortAggregateOp::ClearLacpSystemId {
                    name: "bond1".to_string()
                }
            ))
        );
        // Relative forms, valid while navigated into an aggregate.
        assert_eq!(
            Command::parse("set esi 00:11:22:33:44:55:66:77:88:99"),
            Command::Set(SetTarget::PortAggregateEsiRelative {
                esi: "00:11:22:33:44:55:66:77:88:99".to_string()
            })
        );
        assert_eq!(
            Command::parse("set lacp-system-id 02:00:00:00:00:01"),
            Command::Set(SetTarget::PortAggregateLacpSystemIdRelative {
                system_id: "02:00:00:00:00:01".to_string()
            })
        );
        assert_eq!(
            Command::parse("delete esi"),
            Command::Delete(DeleteTarget::PortAggregateEsiRelative)
        );
        assert_eq!(
            Command::parse("delete lacp-system-id"),
            Command::Delete(DeleteTarget::PortAggregateLacpSystemIdRelative)
        );
        // The aggregate itself is still deletable.
        assert!(matches!(
            Command::parse("delete port-aggregate bond1"),
            Command::Delete(DeleteTarget::PortAggregate { .. })
        ));
    }

    #[test]
    fn broadcast_domain_evpn_set_and_delete() {
        assert_eq!(
            Command::parse("set broadcast domain bd1 vni 10100"),
            Command::Set(SetTarget::BroadcastDomainEvpn(BroadcastDomainOp::SetVni {
                name: "bd1".to_string(),
                vni: 10100
            }))
        );
        assert_eq!(
            Command::parse("set broadcast domain bd1 route-target import 65000:10100"),
            Command::Set(SetTarget::BroadcastDomainEvpn(
                BroadcastDomainOp::AddRouteTarget {
                    name: "bd1".to_string(),
                    import: true,
                    route_target: "65000:10100".to_string()
                }
            ))
        );
        assert_eq!(
            Command::parse("set broadcast domain bd1 redistribute from mac to bgp r1"),
            Command::Set(SetTarget::BroadcastDomainEvpn(
                BroadcastDomainOp::SetMacRedistribute {
                    name: "bd1".to_string(),
                    bgp_instance: "r1".to_string()
                }
            ))
        );
        assert_eq!(
            Command::parse("delete broadcast domain bd1 redistribute"),
            Command::Delete(DeleteTarget::BroadcastDomainEvpn(
                BroadcastDomainOp::ClearMacRedistribute {
                    name: "bd1".to_string()
                }
            ))
        );
        assert_eq!(
            Command::parse("set broadcast domain bd1 redistribute from arp to bgp r1"),
            Command::Set(SetTarget::BroadcastDomainEvpn(
                BroadcastDomainOp::SetArpRedistribute {
                    name: "bd1".to_string(),
                    bgp_instance: "r1".to_string()
                }
            ))
        );
        assert_eq!(
            Command::parse("set broadcast domain bd1 redistribute from connected to bgp r1"),
            Command::Set(SetTarget::BroadcastDomainEvpn(
                BroadcastDomainOp::SetConnectedRedistribute {
                    name: "bd1".to_string(),
                    bgp_instance: "r1".to_string()
                }
            ))
        );
        for (cmd, op) in [
            (
                "mac",
                BroadcastDomainOp::ClearMacRedistribute {
                    name: "bd1".to_string(),
                },
            ),
            (
                "arp",
                BroadcastDomainOp::ClearArpRedistribute {
                    name: "bd1".to_string(),
                },
            ),
            (
                "connected",
                BroadcastDomainOp::ClearConnectedRedistribute {
                    name: "bd1".to_string(),
                },
            ),
        ] {
            assert_eq!(
                Command::parse(&format!(
                    "delete broadcast domain bd1 redistribute from {cmd}"
                )),
                Command::Delete(DeleteTarget::BroadcastDomainEvpn(op))
            );
        }
        // Existing forms are untouched.
        assert!(matches!(
            Command::parse("set broadcast domain bd1 routing-table rt1"),
            Command::Set(SetTarget::BroadcastDomainRoutingTable { .. })
        ));
    }

    #[test]
    fn show_fdb_takes_one_domain() {
        assert_eq!(
            Command::parse("show fdb bd1"),
            Command::ShowFdb {
                domain: "bd1".to_string()
            }
        );
        assert_eq!(
            Command::parse("show fdb"),
            Command::Unknown("show fdb".to_string())
        );
    }
}
