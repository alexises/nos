use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Identifies one addressable IPC service that a client might want to reach.
/// Resolved by `nos-watchdogd`'s broker (`Request::ResolveEndpoint` in
/// `WatchdogRequest`) rather than assumed from a hardcoded default, since the
/// watchdog is the one process that actually spawns every other daemon and
/// knows where it currently lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceRef {
    /// `nos-configd`'s own IPC socket. The watchdog always knows this — it's
    /// passed to the watchdog itself via its own `--config-socket` arg.
    Config,
    /// The `nos-ribd` instance currently serving one routing table, named by
    /// the table's config key.
    RibTable(String),
}

/// Messages sent from a client to `nos-watchdogd`'s broker socket.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index, so reordering breaks wire compatibility with
/// already-built binaries.
#[derive(Debug, Serialize, Deserialize)]
pub enum WatchdogRequest {
    /// One-shot: resolve where to reach the given service right now.
    ResolveEndpoint { service: ServiceRef },
}

/// Messages sent from `nos-watchdogd` to a broker client.
#[derive(Debug, Serialize, Deserialize)]
pub enum WatchdogEvent {
    /// The service is currently reachable at this Unix socket path.
    Endpoint(PathBuf),
    /// No such service is currently running/known (e.g. the routing table
    /// isn't configured, or its `nos-ribd` hasn't finished starting yet).
    NotAvailable,
}
