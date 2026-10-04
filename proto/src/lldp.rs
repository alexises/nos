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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// IEEE 802.1 Port VLAN ID (0: the port has none).
    pub port_vlan_id: Option<u16>,
    /// IEEE 802.1 VLAN Name TLVs, in the order received.
    pub vlan_names: Vec<LldpVlanName>,
    /// IEEE 802.1 (or the deprecated 802.3) Link Aggregation TLV.
    pub link_aggregation: Option<LldpLinkAggregation>,
    /// IEEE 802.3 Maximum Frame Size, in bytes.
    pub max_frame_size: Option<u16>,
    /// IEEE 802.3 MAC/PHY Configuration/Status TLV.
    pub mac_phy: Option<LldpMacPhy>,
}

/// One VLAN a neighbor's port carries, with its name.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LldpVlanName {
    pub id: u16,
    pub name: String,
}

/// A neighbor port's link aggregation state.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LldpLinkAggregation {
    /// The port can be aggregated.
    pub capable: bool,
    /// The port is in an aggregation now.
    pub enabled: bool,
    /// The aggregated port id (the sender's aggregate ifIndex), 0 when not
    /// aggregated.
    pub port_id: u32,
}

/// A neighbor port's IEEE 802.3 auto-negotiation and MAU type.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LldpMacPhy {
    pub autoneg_supported: bool,
    pub autoneg_enabled: bool,
    /// PMD auto-negotiation advertised capability bits (IANA-MAU-MIB
    /// `IANAifMauAutoNegCapBits`).
    pub advertised: u16,
    /// Operational MAU type (IANA-MAU-MIB `IANAifMauTypeListBits` index).
    pub mau_type: u16,
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
    /// Management Address, or one past the per-LLDPDU cap; a malformed or
    /// repeated 802.1/802.3 TLV nos decodes, or a VLAN Name past the cap).
    pub tlvs_discarded: u64,
    /// `statsTLVsUnrecognizedTotal`: reserved TLV types and every
    /// organizationally-specific TLV nos doesn't decode (LLDP-MED, DCBX, …).
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
