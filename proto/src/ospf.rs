//! `nos-ospfd`'s IPC query protocol — backs `nos-cli`'s `show ospf neigh`.
//! Mirrors `bgp`'s shape: a request/event pair framed by `IpcCodec` over a
//! Unix socket resolved via the watchdog broker (`ServiceRef::OspfInstance`).
//!
//! This phase's ceiling is Hello-protocol neighbor discovery only, up to
//! `TwoWay` — see `ospf/CLAUDE.md`. No DBD/LSR/LSU/LSAck, no LSDB, no
//! ExStart/Exchange/Loading/Full.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// A point-to-point link's neighbor state, as reported by `nos-ospfd`.
/// `Down` is an ongoing, valid state (no Hello received yet, or the
/// dead-interval expired) — every configured link reports at least `Down`,
/// never an absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OspfNeighborState {
    Down,
    Init,
    TwoWay,
}

/// One point-to-point link's neighbor summary, for `show ospf neigh`. At
/// most one neighbor per link this phase (point-to-point only, no DR/BDR
/// election — see `ospf/CLAUDE.md`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NeighborSummary {
    /// The attach point's display name, matching
    /// `reconcile::attach_points_for`'s existing `"<interface>.<tag>"`
    /// convention (e.g. `"eth0.100"`).
    pub link: String,
    pub area_id: Ipv4Addr,
    /// Known once at least one Hello has been received on this link.
    pub neighbor_router_id: Option<Ipv4Addr>,
    pub state: OspfNeighborState,
    /// Seconds since the last Hello was received from this neighbor. `None`
    /// if none has ever been received.
    pub last_hello_secs: Option<u64>,
    pub hello_interval: u16,
    pub dead_interval: u16,
}

/// Messages sent from a client to one `nos-ospfd` instance's IPC socket.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index, so reordering breaks wire compatibility with
/// already-built binaries.
#[derive(Debug, Serialize, Deserialize)]
pub enum OspfRequest {
    /// One-shot: every configured link's current neighbor summary.
    GetNeighbors,
}

/// Messages sent from `nos-ospfd` to a query client.
#[derive(Debug, Serialize, Deserialize)]
pub enum OspfEvent {
    Neighbors(Vec<NeighborSummary>),
}
