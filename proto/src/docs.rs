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
