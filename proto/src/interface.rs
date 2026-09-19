use std::net::Ipv6Addr;

use serde::{Deserialize, Serialize};

use crate::schema::InterfaceAddress;

/// One interface's current desired state, as reconciled by `nos-interfaced`
/// from the running config. This reflects *desired* state — `nos-interfaced`
/// does not yet apply it to the OS (see `interface/CLAUDE.md`), so it is not
/// necessarily what the kernel actually has configured.
///
/// `addresses`/`routing_table` are populated only for a loopback interface
/// (flat L3 config, unchanged); every other interface's L3 config lives in
/// `subinterfaces` instead — see `schema::Subinterface`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InterfaceStatus {
    pub name: String,
    pub addresses: Vec<InterfaceAddress>,
    pub routing_table: Option<String>,
    pub switching_profile: Option<String>,
    /// If set, names the `PortAggregate` this interface is a static bonded
    /// member of — same shape/role as `switching_profile`.
    pub port_aggregate: Option<String>,
    /// This interface's configured MTU, or `1500` (Linux's own default) if
    /// unset — reflects desired config like every other field here, applies
    /// uniformly to every one of `subinterfaces` (MTU is a physical-link
    /// property, inherited by VLAN sub-links, not set per tag).
    pub mtu: u32,
    pub subinterfaces: Vec<SubinterfaceStatus>,
    /// This interface's kernel-assigned IPv6 link-local address (`fe80::/10`
    /// scope), if the Linux driver has observed one — `None` until the
    /// kernel auto-assigns it (or under the `noop` driver, always). Unlike
    /// every other field here, this reflects **observed kernel state**, not
    /// desired config: `nos-interfaced` never writes a link-local address
    /// itself (see `interface/CLAUDE.md`'s "never touch kernel-auto-assigned
    /// addresses" note) — it only surfaces what the kernel already assigned,
    /// purely so a consumer like `nos-ospfv3d` can source real RFC 5340
    /// Hello/Link-LSA traffic from it without its own kernel access.
    pub link_local_address: Option<Ipv6Addr>,
}

/// The wire twin of `schema::Subinterface` — one VLAN-scoped L3 attachment
/// point on a physical interface, `tag == 0` for the untagged/native case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubinterfaceStatus {
    pub tag: u16,
    pub addresses: Vec<InterfaceAddress>,
    pub routing_table: Option<String>,
    /// See `InterfaceStatus.link_local_address` — same observed-kernel-state
    /// semantics, scoped to this subinterface's own kernel device.
    pub link_local_address: Option<Ipv6Addr>,
}

/// The wire twin of `schema::BroadcastDomain` — a domain's own bridge
/// device's flat L3 config (same shape as a loopback interface's, see
/// `schema::BroadcastDomain`'s doc comment).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BroadcastDomainStatus {
    pub name: String,
    pub addresses: Vec<InterfaceAddress>,
    pub routing_table: Option<String>,
    /// See `InterfaceStatus.link_local_address` — same observed-kernel-state
    /// semantics, scoped to this domain's own bridge device.
    pub link_local_address: Option<Ipv6Addr>,
    /// The real Linux bridge device name the `linux` driver allocated for
    /// this domain (e.g. `br1`) — `None` until the driver has actually
    /// created it (or under the `noop` driver, a synthesized placeholder).
    /// `nos-ospfd` needs this to bind its raw protocol-89 socket to the
    /// domain's own bridge device rather than the shared VRF device (see
    /// `ospf/CLAUDE.md`'s "LSA exchange" section for why per-link binding,
    /// not VRF-wide binding, is required).
    pub bridge_name: Option<String>,
}

/// The wire twin of `schema::PortAggregate` — a static Linux bonding
/// device's config, the same shape as `InterfaceStatus` minus the
/// loopback-only flat `addresses`/`routing_table` fields (a bond is never a
/// loopback — all its L3 config lives in `subinterfaces`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortAggregateStatus {
    pub name: String,
    pub mode: crate::schema::PortAggregateMode,
    pub switching_profile: Option<String>,
    pub mtu: u32,
    pub subinterfaces: Vec<SubinterfaceStatus>,
    /// See `InterfaceStatus.link_local_address` — same observed-kernel-state
    /// semantics, scoped to this bond's own kernel device.
    pub link_local_address: Option<Ipv6Addr>,
    /// The real Linux bond device name the `linux` driver allocated for this
    /// aggregate (e.g. `bond1`) — `None` until the driver has actually
    /// created it (or under the `noop` driver, a synthesized placeholder).
    pub bond_name: Option<String>,
}

/// One `PortAggregate`'s current 802.1AX-negotiated active-member set,
/// pushed by the owning (single, system-wide) `nos-lacpd` instance to
/// `nos-interfaced` over a persistent connection — the data-plane push
/// counterpart of `RibRequest::PushBgpRoutes` (see root `CLAUDE.md`'s
/// "Config plane vs data plane"). Unlike that route push, this is always a
/// **full resend of the whole set**, never incremental `Add`/`Remove`: a
/// `PortAggregate` realistically has a handful of members, so there is no
/// batching win, and a full resend collapses "on every negotiation change"
/// and "on reconnect" into the same one code path. Only meaningful for a
/// `PortAggregateMode::Lacp` aggregate — `nos-lacpd` never pushes for a
/// `Xor` one, whose members are enslaved unconditionally regardless.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LacpAggregateMembers {
    pub aggregate: String,
    pub active_members: Vec<String>,
}

/// Messages sent from a client to `nos-interfaced`'s IPC socket.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index, so reordering breaks wire compatibility with
/// already-built binaries.
#[derive(Debug, Serialize, Deserialize)]
pub enum InterfaceRequest {
    /// One-shot: every interface currently configured.
    GetInterfaces,
    /// One-shot: a single named interface.
    GetInterface { name: String },
    /// One-shot: a single named broadcast domain.
    GetBroadcastDomain { name: String },
    /// One-shot: every port aggregate currently configured.
    GetPortAggregates,
    /// One-shot: a single named port aggregate.
    GetPortAggregate { name: String },
    /// Fire-and-forget, sent by `nos-lacpd`: replaces the given aggregate's
    /// active-member set and applies it to the kernel bond immediately
    /// (not deferred to the periodic re-apply tick), gating which of its
    /// `Lacp`-mode members are currently enslaved. No reply.
    PushLacpMembers(LacpAggregateMembers),
}

/// Messages sent from `nos-interfaced` to a client.
#[derive(Debug, Serialize, Deserialize)]
pub enum InterfaceEvent {
    /// Reply to `GetInterfaces`.
    Interfaces(Vec<InterfaceStatus>),
    /// Reply to `GetInterface` when the named interface exists.
    Interface(InterfaceStatus),
    /// Reply to `GetInterface`/`GetBroadcastDomain`/`GetPortAggregate` when
    /// no such interface/domain/aggregate is configured.
    NotFound,
    /// Reply to `GetBroadcastDomain` when the named domain exists.
    BroadcastDomain(BroadcastDomainStatus),
    /// Reply to `GetPortAggregates`.
    PortAggregates(Vec<PortAggregateStatus>),
    /// Reply to `GetPortAggregate` when the named aggregate exists.
    PortAggregate(PortAggregateStatus),
}
