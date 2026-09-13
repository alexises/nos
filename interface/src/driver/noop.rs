use async_trait::async_trait;
use tracing::info;

use super::{DriverError, InterfaceDriver};
use crate::state::InterfaceState;

/// Platform-agnostic default: logs the state that would be applied but
/// never touches the OS network stack. Preserves today's placeholder
/// behavior for non-Linux hosts and for tests.
pub struct NoopInterfaceDriver;

#[async_trait]
impl InterfaceDriver for NoopInterfaceDriver {
    async fn apply(&self, desired: &InterfaceState) -> Result<(), DriverError> {
        info!(
            interface = %desired.name,
            addresses = ?desired.addresses,
            routing_table = ?desired.routing_table,
            "would apply interface configuration (noop driver — no OS effect)"
        );
        Ok(())
    }

    async fn remove(&self, name: &str) -> Result<(), DriverError> {
        info!(
            interface = %name,
            "would remove interface configuration (noop driver — no OS effect)"
        );
        Ok(())
    }
}
