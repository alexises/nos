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
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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
    /// Management addresses the neighbor advertised (already formatted).
    pub management_addresses: Vec<String>,
    /// Seconds until this entry ages out, unless refreshed first.
    pub ttl_remaining_secs: u32,
}

/// One LLDP-enabled interface's IEEE 802.1AB §9.2.6 statistics (the
/// LLDP-MIB `lldpStatsTxPortTable`/`lldpStatsRxPortTable` counters), for
/// `show lldp statistics`. Every counter resets only when `nos-lldpd`
/// restarts or LLDP is turned off on that interface.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LldpLinkStats {
    pub interface: String,
    /// `statsFramesOutTotal`: LLDPDUs sent (periodic, fast-start, shutdown).
    pub frames_out: u64,
    /// `statsFramesInTotal`: valid LLDPDUs received (our own reflected frames
    /// excluded).
    pub frames_in: u64,
    /// `statsFramesInErrorsTotal`: received frames that failed validation.
    pub frames_in_errors: u64,
    /// `statsFramesDiscardedTotal`: every invalid frame, plus every frame
    /// dropped because the neighbor table was full.
    pub frames_discarded: u64,
    /// `statsTLVsDiscardedTotal`: optional TLVs dropped (a malformed or non-IP
    /// Management Address, or one past the per-LLDPDU cap).
    pub tlvs_discarded: u64,
    /// `statsTLVsUnrecognizedTotal`: reserved TLV types and every
    /// organizationally-specific TLV.
    pub tlvs_unrecognized: u64,
    /// `statsAgeoutsTotal`: neighbors dropped because their TTL lapsed.
    pub ageouts: u64,
    /// New neighbors refused because the table was full (802.1AB
    /// tooManyNeighbors; this port's share of `lldpStatsRemTablesDrops`).
    pub too_many_neighbors: u64,
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
    /// One-shot: every LLDP-enabled interface's counters.
    GetStatistics,
}

/// Messages sent from `nos-lldpd` to a query client.
#[derive(Debug, Serialize, Deserialize)]
pub enum LldpEvent {
    Neighbors(Vec<LldpNeighbor>),
    Statistics(Vec<LldpLinkStats>),
}
