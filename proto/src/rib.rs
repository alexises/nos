use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Wire twin of `nos-rib`'s internal `RouteSource` — kept separate so
/// `nos-rib`'s own domain type doesn't need to derive wire traits it has no
/// other use for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteSourceKind {
    Static,
    Bgp,
}

/// One candidate route for a prefix.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteEntry {
    pub gateway: IpAddr,
    pub source: RouteSourceKind,
}

/// One prefix's full candidate list, ordered best (winner) to worst by
/// source preference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrefixRoutes {
    pub prefix: IpNet,
    pub candidates: Vec<RouteEntry>,
}

/// Messages sent from a client to a `nos-ribd` instance's IPC socket.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index, so reordering breaks wire compatibility with
/// already-built binaries.
#[derive(Debug, Serialize, Deserialize)]
pub enum RibRequest {
    /// One-shot: every prefix currently in the table, each with its full
    /// candidate list, prefixes in ascending CIDR order.
    GetRoutes,
    /// One-shot: longest-prefix-match lookup for one destination address.
    Lookup { addr: IpAddr },
    /// One-shot: this table's Linux VRF interface name, if its driver has
    /// allocated/created one. The only cross-daemon consumer today is
    /// `nos-interfaced`'s Linux driver, resolving which device to enslave
    /// an interface into — see root `CLAUDE.md`'s "Endpoint broker"
    /// section for how it finds this instance's socket
    /// (`ServiceRef::RibTable`). No table name is carried on the request:
    /// which table you're asking about is implicit in which per-table
    /// `nos-ribd` socket you connected to, exactly like `GetRoutes`/
    /// `Lookup` above.
    GetVrfName,
    /// One-shot: this table's allocated kernel table id, if any — backs
    /// loopback kernel device naming (`lo<table_id>`) in `nos-interfaced`'s
    /// Linux driver. Symmetric to `GetVrfName`; no table name carried, same
    /// reasoning.
    GetTableId,
}

/// Messages sent from a `nos-ribd` instance to a client.
#[derive(Debug, Serialize, Deserialize)]
pub enum RibEvent {
    /// Reply to `GetRoutes`.
    Routes(Vec<PrefixRoutes>),
    /// Reply to `Lookup` when a covering prefix exists.
    Match(PrefixRoutes),
    /// Reply to `Lookup` when no configured prefix covers the address (no
    /// default route).
    NoMatch,
    /// A human-readable error message from the daemon.
    Error(String),
    /// Reply to `GetVrfName`. `None` if no VRF has been allocated/created
    /// yet (or the running driver never backs a table with a real VRF at
    /// all, e.g. a no-op driver) — a normal, expected transient state, not
    /// an error.
    VrfName(Option<String>),
    /// Reply to `GetTableId`. `None` under the same conditions as
    /// `VrfName(None)` — normal/transient, never an error.
    TableId(Option<u32>),
}
