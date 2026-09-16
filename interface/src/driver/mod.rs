//! Applies an interface's desired state to the real OS (or a stand-in).
//!
//! `nos-interfaced` never creates interfaces (see `CLAUDE.md`'s scope
//! section) — a driver only ever configures ones that already exist in the
//! netns. `NoopInterfaceDriver` (today's log-only behavior) is the
//! platform-agnostic default; `LinuxInterfaceDriver` is the real `rtnetlink`
//! implementation, selected via `--driver` in `main.rs`. This split exists
//! so a future non-Linux/hardware backend can be added without touching
//! `state.rs`/`reconcile.rs`.

pub mod linux;
pub mod noop;
pub mod rib_client;

use async_trait::async_trait;
use thiserror::Error;

pub use linux::LinuxInterfaceDriver;
pub use noop::NoopInterfaceDriver;

use crate::state::InterfaceState;

#[derive(Debug, Error)]
pub enum DriverError {
    #[error("netlink error: {0}")]
    Netlink(#[from] rtnetlink::Error),
    #[error("i/o error opening netlink connection: {0}")]
    Io(#[from] std::io::Error),
    #[error("created loopback device {0} but could not find it afterwards")]
    LoopbackNotFound(String),
}

/// One instance lives for the process lifetime, constructed in `main.rs`
/// from the `--driver` flag and shared as `Arc<dyn InterfaceDriver>` with
/// `reconcile::run`. Implementations own all "current vs desired" diffing
/// internally (e.g. dumping live kernel addresses, computing add/remove) —
/// callers always pass full desired state, never a precomputed patch,
/// mirroring the existing full-rebuild pattern in `state::build_from_config`.
#[async_trait]
pub trait InterfaceDriver: Send + Sync {
    /// Applies `desired`'s addresses, admin-up state, and (if
    /// `desired.routing_table` is set) VRF enslavement. The VRF's Linux
    /// interface name is resolved by the driver itself, by asking the
    /// owning `nos-ribd` instance over IPC (see `linux::LinuxInterfaceDriver`
    /// and `rib_client`) — "not resolvable yet" (that table's `nos-ribd`
    /// isn't running, or hasn't created its VRF yet) is an expected,
    /// transient condition, not an error: the driver silently leaves
    /// enslavement as-is and relies on the caller's periodic re-apply to
    /// retry.
    async fn apply(&self, desired: &InterfaceState) -> Result<(), DriverError>;

    /// Called once per resync for every interface name present in the
    /// *previous* resync's `Interfaces` but absent from the current one
    /// (removed from config outright). Un-enslaves from any VRF and
    /// removes any addresses previously applied; a no-op if the interface
    /// no longer exists in the netns. For a loopback name (see
    /// `nos_proto::loopback_table_name`), also deletes the kernel device
    /// this driver created for it — `name` alone is always sufficient to
    /// recompute what that device is.
    async fn remove(&self, name: &str) -> Result<(), DriverError>;
}
