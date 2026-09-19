use async_trait::async_trait;
use tracing::debug;

use super::{DriverError, InterfaceDriver};
use crate::state::{BroadcastDomainState, InterfaceState};

/// Platform-agnostic default: logs the state that would be applied but
/// never touches the OS network stack. Preserves today's placeholder
/// behavior for non-Linux hosts and for tests.
pub struct NoopInterfaceDriver;

#[async_trait]
impl InterfaceDriver for NoopInterfaceDriver {
    async fn apply(&self, desired: &InterfaceState) -> Result<(), DriverError> {
        debug!(
            interface = %desired.name,
            addresses = ?desired.addresses,
            routing_table = ?desired.routing_table,
            subinterfaces = ?desired.subinterfaces,
            "would apply interface configuration (noop driver — no OS effect)"
        );
        Ok(())
    }

    async fn remove(&self, name: &str) -> Result<(), DriverError> {
        debug!(
            interface = %name,
            "would remove interface configuration (noop driver — no OS effect)"
        );
        Ok(())
    }

    async fn ensure_broadcast_domain(
        &self,
        desired: &BroadcastDomainState,
    ) -> Result<String, DriverError> {
        debug!(
            domain = %desired.name,
            addresses = ?desired.addresses,
            routing_table = ?desired.routing_table,
            "would ensure broadcast domain bridge (noop driver — no OS effect)"
        );
        Ok(format!("noop-br-{}", desired.name))
    }

    async fn remove_broadcast_domain(&self, domain: &str) -> Result<(), DriverError> {
        debug!(
            domain = %domain,
            "would remove broadcast domain bridge (noop driver — no OS effect)"
        );
        Ok(())
    }

    async fn link_local_address(&self, _kernel_interface: &str) -> Option<std::net::Ipv6Addr> {
        None
    }
}
