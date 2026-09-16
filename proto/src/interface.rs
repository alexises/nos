use serde::{Deserialize, Serialize};

use crate::schema::InterfaceAddress;

/// One interface's current desired state, as reconciled by `nos-interfaced`
/// from the running config. This reflects *desired* state — `nos-interfaced`
/// does not yet apply it to the OS (see `interface/CLAUDE.md`), so it is not
/// necessarily what the kernel actually has configured.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InterfaceStatus {
    pub name: String,
    pub addresses: Vec<InterfaceAddress>,
    pub routing_table: Option<String>,
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
}

/// Messages sent from `nos-interfaced` to a client.
#[derive(Debug, Serialize, Deserialize)]
pub enum InterfaceEvent {
    /// Reply to `GetInterfaces`.
    Interfaces(Vec<InterfaceStatus>),
    /// Reply to `GetInterface` when the named interface exists.
    Interface(InterfaceStatus),
    /// Reply to `GetInterface` when no such interface is configured.
    NotFound,
}
