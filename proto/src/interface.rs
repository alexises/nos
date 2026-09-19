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
}

/// Messages sent from `nos-interfaced` to a client.
#[derive(Debug, Serialize, Deserialize)]
pub enum InterfaceEvent {
    /// Reply to `GetInterfaces`.
    Interfaces(Vec<InterfaceStatus>),
    /// Reply to `GetInterface` when the named interface exists.
    Interface(InterfaceStatus),
    /// Reply to `GetInterface`/`GetBroadcastDomain` when no such
    /// interface/domain is configured.
    NotFound,
    /// Reply to `GetBroadcastDomain` when the named domain exists.
    BroadcastDomain(BroadcastDomainStatus),
}
