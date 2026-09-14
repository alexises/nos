use std::collections::HashMap;

use async_trait::async_trait;
use nos_proto::IpNet;
use tracing::debug;

use super::{DriverError, RibDriver};
use crate::rib::RibEntry;

/// Placeholder driver, matching the original (pre-driver) behavior of this
/// crate: logs the routes it would install, never touches the kernel or any
/// file. Default off-Linux, and available everywhere via `--driver noop`.
#[derive(Debug, Default)]
pub struct NoopRibDriver;

#[async_trait]
impl RibDriver for NoopRibDriver {
    async fn apply(
        &self,
        table_name: &str,
        best_routes: &HashMap<IpNet, RibEntry>,
    ) -> Result<(), DriverError> {
        debug!(
            table = %table_name,
            prefixes = best_routes.len(),
            "would install routes into a kernel VRF/table (noop driver — no OS effect)"
        );
        Ok(())
    }

    async fn teardown(&self, table_name: &str) -> Result<(), DriverError> {
        debug!(
            table = %table_name,
            "would tear down the kernel VRF/table (noop driver — no OS effect)"
        );
        Ok(())
    }

    async fn vrf_name(&self, _table_name: &str) -> Option<String> {
        None
    }
}
