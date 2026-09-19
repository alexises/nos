use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nos_proto::ServiceRef;
use tokio::sync::RwLock;
use tracing::debug;

/// Cheap-`Clone` handle (like `nos-config`'s `ConfigStore`) over the live
/// mapping from routing-table/BGP-instance name to its `nos-ribd`/`nos-bgpd`
/// instance's IPC socket. Updated by `instances::manage` as instances are
/// spawned/stopped, and read by `broker::start` to answer `ResolveEndpoint`
/// requests.
#[derive(Clone, Default)]
pub struct EndpointRegistry {
    rib_tables: Arc<RwLock<HashMap<String, PathBuf>>>,
    bgp_instances: Arc<RwLock<HashMap<String, PathBuf>>>,
    ospf_instances: Arc<RwLock<HashMap<String, PathBuf>>>,
    ospfv3_instances: Arc<RwLock<HashMap<String, PathBuf>>>,
}

/// Which of the registry's per-name maps an endpoint belongs to — one per
/// daemon family that `instances::manage` spawns per named config object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    RibTable,
    BgpInstance,
    OspfInstance,
    Ospfv3Instance,
}

impl EndpointKind {
    fn label(self) -> &'static str {
        match self {
            EndpointKind::RibTable => "rib table",
            EndpointKind::BgpInstance => "bgp instance",
            EndpointKind::OspfInstance => "ospf instance",
            EndpointKind::Ospfv3Instance => "ospfv3 instance",
        }
    }
}

impl EndpointRegistry {
    fn map(&self, kind: EndpointKind) -> &RwLock<HashMap<String, PathBuf>> {
        match kind {
            EndpointKind::RibTable => &self.rib_tables,
            EndpointKind::BgpInstance => &self.bgp_instances,
            EndpointKind::OspfInstance => &self.ospf_instances,
            EndpointKind::Ospfv3Instance => &self.ospfv3_instances,
        }
    }

    pub async fn set(&self, kind: EndpointKind, name: &str, socket: PathBuf) {
        debug!(
            kind = kind.label(), name = %name, socket = %socket.display(),
            "registered endpoint"
        );
        self.map(kind)
            .write()
            .await
            .insert(name.to_string(), socket);
    }

    pub async fn remove(&self, kind: EndpointKind, name: &str) {
        debug!(kind = kind.label(), name = %name, "removed endpoint");
        self.map(kind).write().await.remove(name);
    }

    /// Resolves `service` to its current socket path, if known.
    /// `config_socket`/`interfaces_socket`/`log_socket` are always
    /// resolvable — the watchdog is told them directly via its own
    /// `--config-socket`/`--interfaced-listen-socket`/`--log-socket` args, so
    /// none needs to be tracked in the map (there's exactly one
    /// `nos-configd`, one `nos-interfaced`, and one `nos-logd`, unlike
    /// `RibTable`/`BgpInstance`, which are keyed by name because there can be
    /// many).
    pub async fn resolve(
        &self,
        service: &ServiceRef,
        config_socket: &Path,
        interfaces_socket: &Path,
        log_socket: &Path,
    ) -> Option<PathBuf> {
        let (kind, name) = match service {
            ServiceRef::Config => return Some(config_socket.to_path_buf()),
            ServiceRef::Interfaces => return Some(interfaces_socket.to_path_buf()),
            ServiceRef::Log => return Some(log_socket.to_path_buf()),
            ServiceRef::RibTable(name) => (EndpointKind::RibTable, name),
            ServiceRef::BgpInstance(name) => (EndpointKind::BgpInstance, name),
            ServiceRef::OspfInstance(name) => (EndpointKind::OspfInstance, name),
            ServiceRef::Ospfv3Instance(name) => (EndpointKind::Ospfv3Instance, name),
        };
        self.map(kind).read().await.get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG_SOCKET: &str = "/run/nos/config.sock";
    const INTERFACES_SOCKET: &str = "/run/nos/interface.sock";
    const LOG_SOCKET: &str = "/run/nos/log.sock";

    #[tokio::test]
    async fn config_always_resolves() {
        let registry = EndpointRegistry::default();
        let config_socket = Path::new(CONFIG_SOCKET);
        let interfaces_socket = Path::new(INTERFACES_SOCKET);
        let log_socket = Path::new(LOG_SOCKET);
        assert_eq!(
            registry
                .resolve(
                    &ServiceRef::Config,
                    config_socket,
                    interfaces_socket,
                    log_socket
                )
                .await,
            Some(config_socket.to_path_buf())
        );
    }

    #[tokio::test]
    async fn interfaces_always_resolves() {
        let registry = EndpointRegistry::default();
        let config_socket = Path::new(CONFIG_SOCKET);
        let interfaces_socket = Path::new(INTERFACES_SOCKET);
        let log_socket = Path::new(LOG_SOCKET);
        assert_eq!(
            registry
                .resolve(
                    &ServiceRef::Interfaces,
                    config_socket,
                    interfaces_socket,
                    log_socket
                )
                .await,
            Some(interfaces_socket.to_path_buf())
        );
    }

    #[tokio::test]
    async fn log_always_resolves() {
        let registry = EndpointRegistry::default();
        let config_socket = Path::new(CONFIG_SOCKET);
        let interfaces_socket = Path::new(INTERFACES_SOCKET);
        let log_socket = Path::new(LOG_SOCKET);
        assert_eq!(
            registry
                .resolve(
                    &ServiceRef::Log,
                    config_socket,
                    interfaces_socket,
                    log_socket
                )
                .await,
            Some(log_socket.to_path_buf())
        );
    }

    #[tokio::test]
    async fn rib_table_resolves_after_set_and_not_after_remove() {
        let registry = EndpointRegistry::default();
        let config_socket = Path::new(CONFIG_SOCKET);
        let interfaces_socket = Path::new(INTERFACES_SOCKET);
        let log_socket = Path::new(LOG_SOCKET);
        let service = ServiceRef::RibTable("rt1".to_string());

        assert_eq!(
            registry
                .resolve(&service, config_socket, interfaces_socket, log_socket)
                .await,
            None
        );

        registry
            .set(
                EndpointKind::RibTable,
                "rt1",
                PathBuf::from("/run/nos/rib-rt1.sock"),
            )
            .await;
        assert_eq!(
            registry
                .resolve(&service, config_socket, interfaces_socket, log_socket)
                .await,
            Some(PathBuf::from("/run/nos/rib-rt1.sock"))
        );

        registry.remove(EndpointKind::RibTable, "rt1").await;
        assert_eq!(
            registry
                .resolve(&service, config_socket, interfaces_socket, log_socket)
                .await,
            None
        );
    }

    #[tokio::test]
    async fn bgp_instance_resolves_after_set_and_not_after_remove() {
        let registry = EndpointRegistry::default();
        let config_socket = Path::new(CONFIG_SOCKET);
        let interfaces_socket = Path::new(INTERFACES_SOCKET);
        let log_socket = Path::new(LOG_SOCKET);
        let service = ServiceRef::BgpInstance("r1".to_string());

        assert_eq!(
            registry
                .resolve(&service, config_socket, interfaces_socket, log_socket)
                .await,
            None
        );

        registry
            .set(
                EndpointKind::BgpInstance,
                "r1",
                PathBuf::from("/run/nos/bgp-r1.sock"),
            )
            .await;
        assert_eq!(
            registry
                .resolve(&service, config_socket, interfaces_socket, log_socket)
                .await,
            Some(PathBuf::from("/run/nos/bgp-r1.sock"))
        );

        registry.remove(EndpointKind::BgpInstance, "r1").await;
        assert_eq!(
            registry
                .resolve(&service, config_socket, interfaces_socket, log_socket)
                .await,
            None
        );
    }

    #[tokio::test]
    async fn ospf_instance_resolves_after_set_and_not_after_remove() {
        let registry = EndpointRegistry::default();
        let config_socket = Path::new(CONFIG_SOCKET);
        let interfaces_socket = Path::new(INTERFACES_SOCKET);
        let log_socket = Path::new(LOG_SOCKET);
        let service = ServiceRef::OspfInstance("o1".to_string());

        assert_eq!(
            registry
                .resolve(&service, config_socket, interfaces_socket, log_socket)
                .await,
            None
        );

        registry
            .set(
                EndpointKind::OspfInstance,
                "o1",
                PathBuf::from("/run/nos/ospf-o1.sock"),
            )
            .await;
        assert_eq!(
            registry
                .resolve(&service, config_socket, interfaces_socket, log_socket)
                .await,
            Some(PathBuf::from("/run/nos/ospf-o1.sock"))
        );

        registry.remove(EndpointKind::OspfInstance, "o1").await;
        assert_eq!(
            registry
                .resolve(&service, config_socket, interfaces_socket, log_socket)
                .await,
            None
        );
    }
}
