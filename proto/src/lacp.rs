//! `nos-lacpd`'s IPC query protocol — backs `nos-cli`'s `show lacp`. Mirrors
//! `bgp`/`ospf`'s shape: a one-shot `GetSummary` request/event pair framed
//! by `IpcCodec` over a Unix socket resolved via the watchdog broker
//! (`ServiceRef::Lacp` — a single, system-wide instance, so unlike
//! `BgpRequest`/`OspfRequest` there is no per-instance socket to pick
//! between).

use serde::{Deserialize, Serialize};

/// 802.1AX §6.4.12 Receive Machine states.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LacpReceiveState {
    Initialize,
    PortDisabled,
    LacpDisabled,
    Expired,
    Defaulted,
    Current,
}

/// 802.1AX §6.4.15 Mux Machine states. `Distributing` is the only state in
/// which this port belongs in the aggregate's active-member set pushed to
/// `nos-interfaced` (`nos_proto::interface::LacpAggregateMembers`).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LacpMuxState {
    Detached,
    Waiting,
    Attached,
    Collecting,
    Distributing,
}

/// One member port's current LACP state, for `show lacp`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)] // wire status flags, one per fact
pub struct LacpPortStatus {
    pub interface: String,
    pub actor_port_number: u16,
    pub receive_state: LacpReceiveState,
    pub mux_state: LacpMuxState,
    /// Known only once a valid LACPDU has been received at least once
    /// (i.e. `receive_state` has reached `Current` at some point).
    pub partner_system_id: Option<[u8; 6]>,
    pub partner_key: Option<u16>,
    pub partner_port_number: Option<u16>,
    /// This port's advertised Actor Port Priority.
    pub actor_port_priority: u16,
    /// This port's configured `lacp-mode` (`Actor_State.LACP_Activity`).
    pub mode: crate::schema::LacpMode,
    pub partner_system_priority: Option<u16>,
    pub partner_port_priority: Option<u16>,
    /// This port's Selection Logic outcome (`selection.rs`) — `true` iff it
    /// agrees with the aggregate's other `Current` ports on partner
    /// identity.
    pub selected: bool,
    /// The partner's advertised Synchronization bit on its most recent
    /// LACPDU.
    pub synchronized: bool,
    /// 802.1AX §6.4.17: this port's own side has been out of sync for a whole
    /// churn-detection time. A churned port is kept out of the bond.
    pub actor_churn: bool,
    /// Same, for the partner's advertised state.
    pub partner_churn: bool,
}

/// One `PortAggregate`'s LACP engine state, for `show lacp [<name>]`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortAggregateLacpSummary {
    pub aggregate: String,
    pub actor_system_id: [u8; 6],
    pub actor_key: u16,
    /// The aggregate's advertised Actor System Priority.
    pub actor_system_priority: u16,
    /// The aggregate's configured `lacp-rate`.
    pub rate: crate::schema::LacpRate,
    pub ports: Vec<LacpPortStatus>,
}

/// Messages sent from a client to `nos-lacpd`'s IPC socket.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index, so reordering breaks wire compatibility with
/// already-built binaries.
#[derive(Debug, Serialize, Deserialize)]
pub enum LacpRequest {
    /// One-shot: every `Lacp`-mode aggregate's current summary.
    GetSummary,
}

/// Messages sent from `nos-lacpd` to a query client.
#[derive(Debug, Serialize, Deserialize)]
pub enum LacpEvent {
    Summary(Vec<PortAggregateLacpSummary>),
}
