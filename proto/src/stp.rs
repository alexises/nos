//! `nos-stpd`'s IPC query protocol — backs `show spanning-tree` and
//! `GET /v1/spanning-tree`. One-shot request/event pair framed by `IpcCodec`,
//! resolved through the broker (`ServiceRef::Stp`, a single instance), like
//! `lldp`.

use serde::{Deserialize, Serialize};

use crate::schema::StpMode;

/// IEEE 802.1Q 13.4 port role (the CIST's).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StpRole {
    Root,
    Designated,
    Alternate,
    Backup,
    #[default]
    Disabled,
}

impl StpRole {
    pub fn as_str(self) -> &'static str {
        match self {
            StpRole::Root => "root",
            StpRole::Designated => "designated",
            StpRole::Alternate => "alternate",
            StpRole::Backup => "backup",
            StpRole::Disabled => "disabled",
        }
    }
}

/// The port state as the core sees it (the kernel's `Blocking` is `Discarding`).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StpState {
    #[default]
    Discarding,
    Learning,
    Forwarding,
}

impl StpState {
    pub fn as_str(self) -> &'static str {
        match self {
            StpState::Discarding => "discarding",
            StpState::Learning => "learning",
            StpState::Forwarding => "forwarding",
        }
    }
}

/// One spanning-tree port. Bridge and port ids are display strings
/// (`8000.02:aa:bb:cc:dd:ee`, `128.1`), as `LldpNeighbor` does.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StpPortInfo {
    pub name: String,
    pub role: StpRole,
    pub state: StpState,
    /// Path cost this port adds to the root path.
    pub cost: u32,
    pub priority: u8,
    /// The designated bridge/port on this port's segment.
    pub designated_bridge: String,
    pub designated_port: String,
}

/// `show spanning-tree`. `enabled: false` (mode not `rstp`) leaves the rest at
/// its default.
///
/// Fields are only ever appended (MSTI views, #323, extend it).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StpSummary {
    pub enabled: bool,
    pub mode: StpMode,
    pub bridge_id: String,
    pub root_id: String,
    pub root_path_cost: u32,
    /// `None` when this bridge is the root.
    pub root_port: Option<String>,
    pub hello_time_secs: u8,
    pub max_age_secs: u8,
    pub forward_delay_secs: u8,
    pub ports: Vec<StpPortInfo>,
}

impl Default for StpSummary {
    fn default() -> Self {
        StpSummary {
            enabled: false,
            mode: StpMode::Disabled,
            bridge_id: String::new(),
            root_id: String::new(),
            root_path_cost: 0,
            root_port: None,
            hello_time_secs: 0,
            max_age_secs: 0,
            forward_delay_secs: 0,
            ports: Vec::new(),
        }
    }
}

/// Messages sent from a client to `nos-stpd`. Append-only (postcard encodes
/// the variant index).
#[derive(Debug, Serialize, Deserialize)]
pub enum StpRequest {
    GetSummary,
}

/// Messages sent from `nos-stpd` to a query client.
#[derive(Debug, Serialize, Deserialize)]
pub enum StpEvent {
    Summary(StpSummary),
}
