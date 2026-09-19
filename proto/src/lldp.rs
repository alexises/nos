//! `nos-lldpd`'s IPC query protocol — backs `nos-cli`'s `show lldp neighbors`.
//! Mirrors `lacp`'s shape: a one-shot request/event pair framed by `IpcCodec`
//! over a Unix socket resolved via the watchdog broker (`ServiceRef::Lldp` — a
//! single, system-wide instance, so no per-instance socket to pick between).

use serde::{Deserialize, Serialize};

/// One remote system heard on one local interface, for `show lldp neighbors`.
///
/// Chassis/Port IDs are already formatted for display by `nos-lldpd` (a MAC
/// subtype as `aa:bb:..`, an interface-name subtype as its text, anything
/// else as hex) — this type is deliberately not a faithful copy of the
/// 802.1AB subtype/value pair, since nothing downstream needs to interpret it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LldpNeighbor {
    pub local_interface: String,
    pub chassis_id: String,
    pub port_id: String,
    pub port_description: Option<String>,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    /// The capabilities the neighbor has *enabled*, by name (e.g. `router`).
    pub capabilities: Vec<String>,
    /// Seconds until this entry ages out, unless refreshed first.
    pub ttl_remaining_secs: u32,
}

/// Messages sent from a client to `nos-lldpd`'s IPC socket.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index, so reordering breaks wire compatibility with
/// already-built binaries.
#[derive(Debug, Serialize, Deserialize)]
pub enum LldpRequest {
    /// One-shot: every currently-known neighbor, across every interface.
    GetNeighbors,
}

/// Messages sent from `nos-lldpd` to a query client.
#[derive(Debug, Serialize, Deserialize)]
pub enum LldpEvent {
    Neighbors(Vec<LldpNeighbor>),
}
