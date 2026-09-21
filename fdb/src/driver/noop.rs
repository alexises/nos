use std::collections::BTreeSet;
use std::net::IpAddr;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::info;

use super::{DriverError, FdbDriver, Mac};

/// Log-only backend (`--driver noop`): no OS effect, no local MAC feed.
pub struct NoopFdbDriver;

#[async_trait]
impl FdbDriver for NoopFdbDriver {
    async fn ensure_vxlan(
        &self,
        vni: u32,
        vtep: IpAddr,
        underlay: &str,
        bridge: &str,
    ) -> Result<(), DriverError> {
        info!(vni, vtep = %vtep, underlay = %underlay, bridge = %bridge, "noop driver: ensure vxlan");
        Ok(())
    }
    async fn remove_vxlan(&self, vni: u32) -> Result<(), DriverError> {
        info!(vni, "noop driver: remove vxlan");
        Ok(())
    }
    async fn set_remote_mac(&self, _: u32, _: Mac, _: IpAddr) -> Result<(), DriverError> {
        Ok(())
    }
    async fn del_remote_mac(&self, _: u32, _: Mac, _: IpAddr) -> Result<(), DriverError> {
        Ok(())
    }
    async fn add_flood(&self, _: u32, _: IpAddr) -> Result<(), DriverError> {
        Ok(())
    }
    async fn del_flood(&self, _: u32, _: IpAddr) -> Result<(), DriverError> {
        Ok(())
    }
    async fn local_macs(&self, _: &str, _: u32) -> Result<BTreeSet<Mac>, DriverError> {
        Ok(BTreeSet::new())
    }
    fn watch_neigh(&self) -> Option<mpsc::UnboundedReceiver<()>> {
        None
    }
}
