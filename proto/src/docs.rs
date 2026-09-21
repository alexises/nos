use serde::{Deserialize, Serialize};

/// Identifies *what an operation does*, independent of any one client's
/// concrete invocation syntax. One entry per server-meaningful operation —
/// mirrors `Request` variants and `ConfigOp`/`BgpInstanceOp` variants that
/// have a client-reachable counterpart. Purely client-local mechanics (e.g.
/// a shell's own navigation commands) have no `Topic` — they're not
/// something `nos-config` has any notion of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Topic {
    /// `Request::Get`
    ShowRunningConfig,
    /// `Request::Save`
    Save,
    /// `Request::OpenTransaction`
    OpenTransaction,
    /// `Request::GetTransaction`
    GetTransaction,
    /// `Request::CommitTransaction`
    CommitTransaction,
    /// `Request::DiscardTransaction`
    DiscardTransaction,
    /// `Request::DiffTransaction`
    DiffTransaction,
    /// `ConfigOp::BgpInstance(BgpInstanceOp::Ensure)`
    EnsureBgpInstance,
    /// `ConfigOp::BgpInstance(BgpInstanceOp::SetAsn)`
    SetBgpInstanceAsn,
    /// `ConfigOp::BgpInstance(BgpInstanceOp::SetRouterId)`
    SetBgpInstanceRouterId,
    /// `ConfigOp::BgpInstance(BgpInstanceOp::Delete)`
    DeleteBgpInstance,
    /// `ConfigOp::SetHostname`
    SetHostname,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::Ensure)`
    EnsureBgpPeerGroup,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetRemoteAs)`
    SetBgpPeerGroupRemoteAs,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetSourceAddress)`
    SetBgpPeerGroupSourceAddress,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearSourceAddress)`
    ClearBgpPeerGroupSourceAddress,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::AddAddressFamily)`
    AddBgpPeerGroupAddressFamily,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::RemoveAddressFamily)`
    RemoveBgpPeerGroupAddressFamily,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::Delete)`
    DeleteBgpPeerGroup,
    /// `ConfigOp::BgpPeer(BgpPeerOp::Set)`
    SetBgpPeer,
    /// `ConfigOp::BgpPeer(BgpPeerOp::Delete)`
    DeleteBgpPeer,
    /// `ConfigOp::RoutingTable(RoutingTableOp::Ensure)`
    EnsureRoutingTable,
    /// `ConfigOp::RoutingTable(RoutingTableOp::SetBgpInstance)`
    SetRoutingTableBgpInstance,
    /// `ConfigOp::RoutingTable(RoutingTableOp::ClearBgpInstance)`
    ClearRoutingTableBgpInstance,
    /// `ConfigOp::RoutingTable(RoutingTableOp::SetStaticRoutingInstance)`
    SetRoutingTableStaticRoutingInstance,
    /// `ConfigOp::RoutingTable(RoutingTableOp::ClearStaticRoutingInstance)`
    ClearRoutingTableStaticRoutingInstance,
    /// `ConfigOp::RoutingTable(RoutingTableOp::SetRedistribute)`
    SetRoutingTableRedistribute,
    /// `ConfigOp::RoutingTable(RoutingTableOp::ClearRedistribute)`
    ClearRoutingTableRedistribute,
    /// `ConfigOp::RoutingTable(RoutingTableOp::Delete)`
    DeleteRoutingTable,
    /// `ConfigOp::StaticRoutingInstance(StaticRoutingInstanceOp::Ensure)`
    EnsureStaticRoutingInstance,
    /// `ConfigOp::StaticRoutingInstance(StaticRoutingInstanceOp::Delete)`
    DeleteStaticRoutingInstance,
    /// `ConfigOp::StaticRoute(StaticRouteOp::Set)`
    SetStaticRoute,
    /// `ConfigOp::StaticRoute(StaticRouteOp::Delete)`
    DeleteStaticRoute,
    /// `ConfigOp::Interface(InterfaceOp::Ensure)`
    EnsureInterface,
    /// `ConfigOp::Interface(InterfaceOp::AddAddress)`
    AddInterfaceAddress,
    /// `ConfigOp::Interface(InterfaceOp::RemoveAddress)`
    RemoveInterfaceAddress,
    /// `ConfigOp::Interface(InterfaceOp::SetRoutingTable)`
    SetInterfaceRoutingTable,
    /// `ConfigOp::Interface(InterfaceOp::ClearRoutingTable)`
    ClearInterfaceRoutingTable,
    /// `ConfigOp::Interface(InterfaceOp::Delete)`
    DeleteInterface,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetHoldTime)`
    SetBgpPeerGroupHoldTime,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearHoldTime)`
    ClearBgpPeerGroupHoldTime,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetKeepaliveInterval)`
    SetBgpPeerGroupKeepaliveInterval,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearKeepaliveInterval)`
    ClearBgpPeerGroupKeepaliveInterval,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetConnectRetryTime)`
    SetBgpPeerGroupConnectRetryTime,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearConnectRetryTime)`
    ClearBgpPeerGroupConnectRetryTime,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetMd5Auth)`
    SetBgpPeerGroupMd5Auth,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetAoKey)`
    SetBgpPeerGroupAoKey,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::RemoveAoKey)`
    RemoveBgpPeerGroupAoKey,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetAoCurrentKey)`
    SetBgpPeerGroupAoCurrentKey,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetAoRnextKey)`
    SetBgpPeerGroupAoRnextKey,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearAuth)`
    ClearBgpPeerGroupAuth,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetNextHop)`
    SetBgpPeerGroupNextHop,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearNextHop)`
    ClearBgpPeerGroupNextHop,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetRouteReflectorClient)`
    SetBgpPeerGroupRouteReflectorClient,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearRouteReflectorClient)`
    ClearBgpPeerGroupRouteReflectorClient,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::SetRouteServerClient)`
    SetBgpPeerGroupRouteServerClient,
    /// `ConfigOp::BgpPeerGroup(BgpPeerGroupOp::ClearRouteServerClient)`
    ClearBgpPeerGroupRouteServerClient,
    /// `ConfigOp::BgpInstance(BgpInstanceOp::SetClusterId)`
    SetBgpInstanceClusterId,
    /// `ConfigOp::BgpInstance(BgpInstanceOp::ClearClusterId)`
    ClearBgpInstanceClusterId,
    /// `ConfigOp::BroadcastDomain(BroadcastDomainOp::Ensure)`
    EnsureBroadcastDomain,
    /// `ConfigOp::BroadcastDomain(BroadcastDomainOp::Delete)`
    DeleteBroadcastDomain,
    /// `ConfigOp::BroadcastDomain(BroadcastDomainOp::AddAddress)`
    AddBroadcastDomainAddress,
    /// `ConfigOp::BroadcastDomain(BroadcastDomainOp::RemoveAddress)`
    RemoveBroadcastDomainAddress,
    /// `ConfigOp::BroadcastDomain(BroadcastDomainOp::SetRoutingTable)`
    SetBroadcastDomainRoutingTable,
    /// `ConfigOp::BroadcastDomain(BroadcastDomainOp::ClearRoutingTable)`
    ClearBroadcastDomainRoutingTable,
    /// `ConfigOp::SwitchingProfile(SwitchingProfileOp::Ensure)`
    EnsureSwitchingProfile,
    /// `ConfigOp::SwitchingProfile(SwitchingProfileOp::AddMember)`
    AddSwitchingProfileMember,
    /// `ConfigOp::SwitchingProfile(SwitchingProfileOp::RemoveMember)`
    RemoveSwitchingProfileMember,
    /// `ConfigOp::SwitchingProfile(SwitchingProfileOp::Delete)`
    DeleteSwitchingProfile,
    /// `ConfigOp::Interface(InterfaceOp::SetSwitchingProfile)`
    SetInterfaceSwitchingProfile,
    /// `ConfigOp::Interface(InterfaceOp::ClearSwitchingProfile)`
    ClearInterfaceSwitchingProfile,
    /// `ConfigOp::Interface(InterfaceOp::SetMtu)`
    SetInterfaceMtu,
    /// `ConfigOp::Interface(InterfaceOp::ClearMtu)`
    ClearInterfaceMtu,
    /// `ConfigOp::Interface(InterfaceOp::SetLldpTransmit)`
    SetInterfaceLldpTransmit,
    /// `ConfigOp::Interface(InterfaceOp::SetLldpReceive)`
    SetInterfaceLldpReceive,
    /// `ConfigOp::OspfInstance(OspfInstanceOp::Ensure)`
    EnsureOspfInstance,
    /// `ConfigOp::OspfInstance(OspfInstanceOp::SetRouterId)`
    SetOspfInstanceRouterId,
    /// `ConfigOp::OspfInstance(OspfInstanceOp::Delete)`
    DeleteOspfInstance,
    /// `ConfigOp::RoutingTable(RoutingTableOp::SetOspfInstance)`
    SetRoutingTableOspfInstance,
    /// `ConfigOp::RoutingTable(RoutingTableOp::ClearOspfInstance)`
    ClearRoutingTableOspfInstance,
    /// `ConfigOp::OspfArea(OspfAreaOp::Ensure)`
    EnsureOspfArea,
    /// `ConfigOp::OspfArea(OspfAreaOp::Delete)`
    DeleteOspfArea,
    /// `ConfigOp::OspfProfile(OspfProfileOp::Ensure)`
    EnsureOspfProfile,
    /// `ConfigOp::OspfProfile(OspfProfileOp::Delete)`
    DeleteOspfProfile,
    /// `ConfigOp::Interface(InterfaceOp::SetOspfProfile)` /
    /// `ConfigOp::Subinterface(SubinterfaceOp::SetOspfProfile)` /
    /// `ConfigOp::BroadcastDomain(BroadcastDomainOp::SetOspfProfile)`
    SetInterfaceOspfProfile,
    /// `ConfigOp::Interface(InterfaceOp::ClearOspfProfile)` /
    /// `ConfigOp::Subinterface(SubinterfaceOp::ClearOspfProfile)` /
    /// `ConfigOp::BroadcastDomain(BroadcastDomainOp::ClearOspfProfile)`
    ClearInterfaceOspfProfile,
    /// `ConfigOp::OspfProfile(OspfProfileOp::SetHelloInterval)`
    SetOspfProfileHelloInterval,
    /// `ConfigOp::OspfProfile(OspfProfileOp::ClearHelloInterval)`
    ClearOspfProfileHelloInterval,
    /// `ConfigOp::OspfProfile(OspfProfileOp::SetDeadInterval)`
    SetOspfProfileDeadInterval,
    /// `ConfigOp::OspfProfile(OspfProfileOp::ClearDeadInterval)`
    ClearOspfProfileDeadInterval,
    /// `ConfigOp::OspfProfile(OspfProfileOp::SetCost)`
    SetOspfProfileCost,
    /// `ConfigOp::OspfProfile(OspfProfileOp::ClearCost)`
    ClearOspfProfileCost,
    /// `ConfigOp::OspfProfile(OspfProfileOp::SetPriority)`
    SetOspfProfilePriority,
    /// `ConfigOp::OspfProfile(OspfProfileOp::ClearPriority)`
    ClearOspfProfilePriority,
    /// `ConfigOp::OspfProfile(OspfProfileOp::SetMtu)`
    SetOspfProfileMtu,
    /// `ConfigOp::OspfProfile(OspfProfileOp::ClearMtu)`
    ClearOspfProfileMtu,
    /// `ConfigOp::OspfProfile(OspfProfileOp::SetNetworkType)`
    SetOspfProfileNetworkType,
    /// `ConfigOp::OspfProfile(OspfProfileOp::ClearNetworkType)`
    ClearOspfProfileNetworkType,
    /// `ConfigOp::OspfProfile(OspfProfileOp::SetSimpleAuth)`
    SetOspfProfileSimpleAuth,
    /// `ConfigOp::OspfProfile(OspfProfileOp::SetCryptoKey)`
    SetOspfProfileCryptoKey,
    /// `ConfigOp::OspfProfile(OspfProfileOp::RemoveCryptoKey)`
    RemoveOspfProfileCryptoKey,
    /// `ConfigOp::OspfProfile(OspfProfileOp::SetCryptoCurrentKey)`
    SetOspfProfileCryptoCurrentKey,
    /// `ConfigOp::OspfProfile(OspfProfileOp::ClearAuth)`
    ClearOspfProfileAuth,
    /// `ConfigOp::PortAggregate(PortAggregateOp::Ensure)`
    EnsurePortAggregate,
    /// `ConfigOp::PortAggregate(PortAggregateOp::Delete)`
    DeletePortAggregate,
    /// `ConfigOp::PortAggregate(PortAggregateOp::SetMode)`
    SetPortAggregateMode,
    /// `ConfigOp::Interface(InterfaceOp::SetPortAggregate)`
    SetInterfacePortAggregate,
    /// `ConfigOp::Interface(InterfaceOp::ClearPortAggregate)`
    ClearInterfacePortAggregate,
    /// `ConfigOp::PortAggregate(PortAggregateOp::SetLacpRate)`
    SetPortAggregateLacpRate,
    /// `ConfigOp::Interface(InterfaceOp::SetLldpDestination)`
    SetInterfaceLldpDestination,
    /// `ConfigOp::Lldp(LldpOp::SetTxInterval)`
    SetLldpTxInterval,
    /// `ConfigOp::Lldp(LldpOp::SetTxHold)`
    SetLldpTxHold,
    /// `ConfigOp::Lldp(LldpOp::SetManagementAddress)`
    SetLldpManagementAddress,
    /// `ConfigOp::BroadcastDomain(BroadcastDomainOp::SetVni)` / `ClearVni`
    SetBroadcastDomainVni,
    /// `ConfigOp::BroadcastDomain(BroadcastDomainOp::SetRd)` / `ClearRd`
    SetBroadcastDomainRd,
    /// `ConfigOp::BroadcastDomain(BroadcastDomainOp::AddRouteTarget)` / `RemoveRouteTarget`
    AddBroadcastDomainRouteTarget,
    /// `ConfigOp::BroadcastDomain(BroadcastDomainOp::SetVtepSource)` / `ClearVtepSource`
    SetBroadcastDomainVtepSource,
    /// `ConfigOp::BroadcastDomain(BroadcastDomainOp::SetMacRedistribute)` / `ClearMacRedistribute`
    SetBroadcastDomainMacRedistribute,
}

/// What an operation does, authored by `nos-config` and served to any client
/// over IPC (`Request::Describe` / `Event::Descriptions`). Deliberately has
/// no "usage" field — exact invocation syntax (argument order, keywords) is
/// specific to each client and doesn't belong here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandDoc {
    pub topic: Topic,
    /// One-line description.
    pub summary: String,
    /// Fuller explanation, including caveats or side effects.
    pub detail: String,
}
