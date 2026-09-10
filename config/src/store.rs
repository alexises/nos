use std::sync::Arc;

use garde::Validate as _;
use tokio::sync::{RwLock, broadcast};

use nos_proto::Config;

use crate::error::ConfigError;

const BROADCAST_CAPACITY: usize = 16;

pub struct ConfigStore {
    running: Arc<RwLock<Config>>,
    candidate: Option<Config>,
    tx: broadcast::Sender<Arc<Config>>,
}

impl ConfigStore {
    pub fn new(initial: Config) -> Self {
        let (tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            running: Arc::new(RwLock::new(initial)),
            candidate: None,
            tx,
        }
    }

    /// Returns a mutable reference to the candidate config, creating one from
    /// the current running config if none exists.
    pub async fn edit_candidate(&mut self) -> &mut Config {
        if self.candidate.is_none() {
            let running = self.running.read().await;
            self.candidate = Some(running.clone());
        }
        self.candidate.as_mut().expect("candidate just set")
    }

    /// Validates the candidate and, if valid, atomically promotes it to running.
    /// Broadcasts the new running config to all subscribers.
    pub async fn commit(&mut self) -> Result<(), ConfigError> {
        let candidate = self.candidate.take().ok_or(ConfigError::NoCandidate)?;
        // Pass the candidate itself as the validation context (cross-reference checks).
        candidate.validate_with(&candidate)?;
        let shared = Arc::new(candidate);
        *self.running.write().await = (*shared).clone();
        // Ignore send errors — no active receivers is not a failure.
        let _ = self.tx.send(shared);
        Ok(())
    }

    pub fn running(&self) -> Arc<RwLock<Config>> {
        Arc::clone(&self.running)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Config>> {
        self.tx.subscribe()
    }

    /// Binds a Unix socket at `socket_path` and starts the IPC server in the background.
    ///
    /// Returns a `JoinHandle` — keep it alive for the server to continue running.
    pub fn start_ipc_server(
        &self,
        socket_path: &std::path::Path,
    ) -> std::io::Result<tokio::task::JoinHandle<()>> {
        crate::server::start(socket_path, Arc::clone(&self.running), self.tx.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use nos_proto::BgpInstance;

    use super::*;

    fn instance(name: &str, asn: u32) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(10, 0, 0, 1),
            asn,
        }
    }

    #[tokio::test]
    async fn commit_valid_candidate_updates_running() {
        let mut store = ConfigStore::new(Config::default());
        store.edit_candidate().await.bgp_instances.push(instance("default", 65000));
        store.commit().await.unwrap();
        let running = store.running().read().await.clone();
        assert_eq!(running.bgp_instances.len(), 1);
        assert_eq!(running.bgp_instances[0].name, "default");
    }

    #[tokio::test]
    async fn commit_invalid_candidate_leaves_running_unchanged() {
        let mut store = ConfigStore::new(Config::default());
        // ASN 0 is invalid
        store.edit_candidate().await.bgp_instances.push(instance("bad", 0));
        assert!(store.commit().await.is_err());
        let running = store.running().read().await.clone();
        assert!(running.bgp_instances.is_empty());
    }

    #[tokio::test]
    async fn commit_without_candidate_returns_error() {
        let mut store = ConfigStore::new(Config::default());
        assert!(store.commit().await.is_err());
    }

    #[tokio::test]
    async fn commit_duplicate_names_returns_error() {
        let mut store = ConfigStore::new(Config::default());
        let cand = store.edit_candidate().await;
        cand.bgp_instances.push(instance("vrf-a", 65001));
        cand.bgp_instances.push(instance("vrf-a", 65002));
        assert!(store.commit().await.is_err());
        // Running must still be empty
        assert!(store.running().read().await.bgp_instances.is_empty());
    }
}
