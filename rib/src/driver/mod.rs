use std::collections::HashMap;

use async_trait::async_trait;
use nos_proto::IpNet;
use thiserror::Error;

use crate::rib::RibEntry;

pub mod linux;
pub mod noop;
pub mod route_channel;
pub mod table_registry;

pub use linux::LinuxRibDriver;
pub use noop::NoopRibDriver;

/// Errors from applying `Rib` state to a real (or simulated) OS backend.
/// Never fatal to the daemon — every call site logs and keeps running, the
/// same resilience philosophy as a failed config fetch (see
/// `reconcile::resync`).
#[derive(Debug, Error)]
pub enum DriverError {
    #[error("netlink error: {0}")]
    Netlink(#[from] rtnetlink::Error),
    #[error("table-id registry error: {0}")]
    Registry(#[from] std::io::Error),
}

/// Applies one routing table's computed best-path state to the OS (or a
/// stand-in). One instance lives for the process lifetime, shared as
/// `Arc<dyn RibDriver>` between `reconcile::run` and `server::start`.
/// Implementations own all "current vs desired" diffing internally (e.g.
/// dumping live kernel routes and computing an add/remove patch) — callers
/// always pass full desired state, never a precomputed patch, mirroring the
/// existing full-rebuild pattern in `rib::build_from_config`.
#[async_trait]
pub trait RibDriver: Send + Sync {
    /// Ensures a kernel VRF/table for `table_name` exists — allocating and
    /// persisting a fresh id on first use, or reusing the previously-
    /// persisted one across restarts — and installs the *winning* route
    /// per prefix from `best_routes` into it. `Rib`'s multi-candidate view
    /// stays a `show route` query-serving concern, never installed
    /// wholesale.
    async fn apply(
        &self,
        table_name: &str,
        best_routes: &HashMap<IpNet, RibEntry>,
    ) -> Result<(), DriverError>;

    /// Deletes every route in `table_name`'s kernel table and the VRF
    /// device itself. Leaves any persisted table-id registry entry
    /// untouched, so a later `apply` for the same `table_name` (an
    /// ordinary restart, not necessarily a real removal — see
    /// `reconcile::run`) recreates the exact same VRF name.
    async fn teardown(&self, table_name: &str) -> Result<(), DriverError>;

    /// Current VRF interface name for `table_name`, if one has been
    /// allocated/created — backs `RibRequest::GetVrfName`. `None` for
    /// `NoopRibDriver` (no real VRF ever exists), or if `apply` hasn't
    /// successfully run yet. Read-only — never allocates.
    async fn vrf_name(&self, table_name: &str) -> Option<String>;

    /// Current kernel table id for `table_name`, if one has been
    /// allocated — backs `RibRequest::GetTableId`. `None` for
    /// `NoopRibDriver`, or if `apply` hasn't successfully run yet.
    /// Read-only — never allocates.
    async fn table_id(&self, table_name: &str) -> Option<u32>;
}
