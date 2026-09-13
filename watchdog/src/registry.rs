use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nos_proto::ServiceRef;
use tokio::sync::RwLock;

/// Cheap-`Clone` handle (like `nos-config`'s `ConfigStore`) over the live
/// mapping from routing-table name to its `nos-ribd` instance's IPC socket.
/// Updated by `routing_tables::manage` as instances are spawned/stopped, and
/// read by `broker::start` to answer `ResolveEndpoint` requests.
#[derive(Clone, Default)]
pub struct EndpointRegistry {
    rib_tables: Arc<RwLock<HashMap<String, PathBuf>>>,
}

impl EndpointRegistry {
    pub async fn set_rib_table(&self, name: &str, socket: PathBuf) {
        self.rib_tables
            .write()
            .await
            .insert(name.to_string(), socket);
    }

    pub async fn remove_rib_table(&self, name: &str) {
        self.rib_tables.write().await.remove(name);
    }

    /// Resolves `service` to its current socket path, if known. `config_socket`
    /// is always resolvable — the watchdog is told it directly via its own
    /// `--config-socket` arg, so it never needs to be tracked in the map.
    pub async fn resolve(&self, service: &ServiceRef, config_socket: &Path) -> Option<PathBuf> {
        match service {
            ServiceRef::Config => Some(config_socket.to_path_buf()),
            ServiceRef::RibTable(name) => self.rib_tables.read().await.get(name).cloned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn config_always_resolves() {
        let registry = EndpointRegistry::default();
        let config_socket = Path::new("/run/nos/config.sock");
        assert_eq!(
            registry.resolve(&ServiceRef::Config, config_socket).await,
            Some(config_socket.to_path_buf())
        );
    }

    #[tokio::test]
    async fn rib_table_resolves_after_set_and_not_after_remove() {
        let registry = EndpointRegistry::default();
        let config_socket = Path::new("/run/nos/config.sock");
        let service = ServiceRef::RibTable("rt1".to_string());

        assert_eq!(registry.resolve(&service, config_socket).await, None);

        registry
            .set_rib_table("rt1", PathBuf::from("/run/nos/rib-rt1.sock"))
            .await;
        assert_eq!(
            registry.resolve(&service, config_socket).await,
            Some(PathBuf::from("/run/nos/rib-rt1.sock"))
        );

        registry.remove_rib_table("rt1").await;
        assert_eq!(registry.resolve(&service, config_socket).await, None);
    }
}
