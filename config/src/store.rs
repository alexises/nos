use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use garde::Validate as _;
use nos_proto::{diff_configs, Config, ConfigDiff, ConfigOp, TransactionBase, TransactionSnapshot};
use tokio::sync::{broadcast, Mutex, RwLock};

use crate::error::ConfigError;

const BROADCAST_CAPACITY: usize = 16;

#[derive(Debug, Clone)]
struct Transaction {
    config: Config,
    dirty: bool,
}

struct Inner {
    running: RwLock<Config>,
    transactions: Mutex<HashMap<String, Transaction>>,
    tx: broadcast::Sender<Arc<Config>>,
    config_path: Option<PathBuf>,
}

/// A cheap, cloneable handle to the daemon's config state: the running
/// config, all named in-progress transactions, and the broadcast channel
/// used to notify subscribers of committed changes.
///
/// Lock ordering: always lock `transactions` before `running` to avoid
/// deadlock (every method below follows this).
#[derive(Clone)]
pub struct ConfigStore(Arc<Inner>);

impl ConfigStore {
    pub fn new(initial: Config, config_path: Option<PathBuf>) -> Self {
        let (tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self(Arc::new(Inner {
            running: RwLock::new(initial),
            transactions: Mutex::new(HashMap::new()),
            tx,
            config_path,
        }))
    }

    pub async fn running_snapshot(&self) -> Config {
        self.0.running.read().await.clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Config>> {
        self.0.tx.subscribe()
    }

    /// Serializes the running config to disk at the daemon's configured
    /// `--config-file` path. Errors if none was configured.
    pub async fn save_to_disk(&self) -> Result<(), ConfigError> {
        let path = self
            .0
            .config_path
            .as_ref()
            .ok_or(ConfigError::PersistenceNotConfigured)?;
        let cfg = self.running_snapshot().await;
        crate::persistence::save_to_disk(&cfg, path)
    }

    /// Opens a named transaction: creates it from `base` if it doesn't
    /// already exist, or resumes its current in-progress config unchanged
    /// (ignoring `base`) if it does.
    pub async fn open_transaction(&self, name: &str, base: TransactionBase) -> TransactionSnapshot {
        let mut txs = self.0.transactions.lock().await;
        if let Some(existing) = txs.get(name) {
            return TransactionSnapshot {
                name: name.to_string(),
                config: existing.config.clone(),
                dirty: existing.dirty,
                resumed: true,
            };
        }
        let config = match base {
            TransactionBase::Blank => Config::default(),
            TransactionBase::Current => self.0.running.read().await.clone(),
        };
        txs.insert(
            name.to_string(),
            Transaction {
                config: config.clone(),
                dirty: false,
            },
        );
        TransactionSnapshot {
            name: name.to_string(),
            config,
            dirty: false,
            resumed: false,
        }
    }

    /// Applies one edit to a named transaction's in-progress config. Never
    /// runs `garde` validation — only `commit_transaction` does.
    pub async fn apply_op(
        &self,
        name: &str,
        op: ConfigOp,
    ) -> Result<TransactionSnapshot, ConfigError> {
        let mut txs = self.0.transactions.lock().await;
        let txn = txs
            .get_mut(name)
            .ok_or_else(|| ConfigError::TransactionNotFound(name.to_string()))?;
        op.apply(&mut txn.config)?;
        txn.dirty = true;
        Ok(TransactionSnapshot {
            name: name.to_string(),
            config: txn.config.clone(),
            dirty: true,
            resumed: true,
        })
    }

    pub async fn get_transaction(&self, name: &str) -> Result<TransactionSnapshot, ConfigError> {
        let txs = self.0.transactions.lock().await;
        let txn = txs
            .get(name)
            .ok_or_else(|| ConfigError::TransactionNotFound(name.to_string()))?;
        Ok(TransactionSnapshot {
            name: name.to_string(),
            config: txn.config.clone(),
            dirty: txn.dirty,
            resumed: true,
        })
    }

    /// Validates the named transaction and, if valid, atomically promotes it
    /// to running, broadcasts the change to subscribers, and removes the
    /// transaction. If invalid, the transaction is left intact so the caller
    /// can keep editing and retry.
    pub async fn commit_transaction(&self, name: &str) -> Result<(), ConfigError> {
        let mut txs = self.0.transactions.lock().await;
        let txn = txs
            .get(name)
            .ok_or_else(|| ConfigError::TransactionNotFound(name.to_string()))?;
        // Pass the config itself as the validation context (cross-reference checks).
        txn.config.validate_with(&txn.config)?;
        let config = txn.config.clone();
        txs.remove(name);
        drop(txs);

        let shared = Arc::new(config);
        *self.0.running.write().await = (*shared).clone();
        // Ignore send errors — no active receivers is not a failure.
        let _ = self.0.tx.send(shared);
        Ok(())
    }

    /// Computes the structural difference between the running config and a
    /// named transaction's in-progress config. Runs no validation — matches
    /// `get_transaction`'s behavior, so an invalid in-progress config can
    /// still be diffed.
    pub async fn diff_transaction(&self, name: &str) -> Result<ConfigDiff, ConfigError> {
        let txs = self.0.transactions.lock().await;
        let candidate = txs
            .get(name)
            .ok_or_else(|| ConfigError::TransactionNotFound(name.to_string()))?
            .config
            .clone();
        drop(txs);
        let running = self.running_snapshot().await;
        Ok(diff_configs(&running, &candidate))
    }

    /// Deletes a named transaction without touching the running config.
    pub async fn discard_transaction(&self, name: &str) -> Result<(), ConfigError> {
        let mut txs = self.0.transactions.lock().await;
        txs.remove(name)
            .ok_or_else(|| ConfigError::TransactionNotFound(name.to_string()))?;
        Ok(())
    }

    /// Binds the given address and starts the IPC server in the background.
    ///
    /// Returns a `JoinHandle` — keep it alive for the server to continue running.
    pub fn start_ipc_server(
        &self,
        addr: &crate::server::ListenAddr,
    ) -> std::io::Result<tokio::task::JoinHandle<()>> {
        crate::server::start(addr, self.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use nos_proto::{BgpInstance, BgpInstanceOp};

    use super::*;

    fn instance(name: &str, asn: u32) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(10, 0, 0, 1),
            asn,
            peer_groups: Vec::new(),
            peers: Vec::new(),
        }
    }

    fn set_asn_op(name: &str, asn: u32) -> ConfigOp {
        ConfigOp::BgpInstance(BgpInstanceOp::SetAsn {
            name: name.to_string(),
            asn,
        })
    }

    fn ensure_op(name: &str) -> ConfigOp {
        ConfigOp::BgpInstance(BgpInstanceOp::Ensure {
            name: name.to_string(),
        })
    }

    fn ensure_routing_table_op(name: &str) -> ConfigOp {
        ConfigOp::RoutingTable(nos_proto::RoutingTableOp::Ensure {
            name: name.to_string(),
        })
    }

    fn set_routing_table_bgp_instance_op(name: &str, bgp_instance: &str) -> ConfigOp {
        ConfigOp::RoutingTable(nos_proto::RoutingTableOp::SetBgpInstance {
            name: name.to_string(),
            bgp_instance: bgp_instance.to_string(),
        })
    }

    fn set_routing_table_static_routing_instance_op(name: &str, sri: &str) -> ConfigOp {
        ConfigOp::RoutingTable(nos_proto::RoutingTableOp::SetStaticRoutingInstance {
            name: name.to_string(),
            static_routing_instance: sri.to_string(),
        })
    }

    fn ensure_static_routing_instance_op(name: &str) -> ConfigOp {
        ConfigOp::StaticRoutingInstance(nos_proto::StaticRoutingInstanceOp::Ensure {
            name: name.to_string(),
        })
    }

    #[tokio::test]
    async fn open_blank_starts_empty_even_if_running_is_not() {
        let store = ConfigStore::new(
            Config {
                bgp_instances: vec![instance("default", 65000)],
                ..Default::default()
            },
            None,
        );
        let snap = store.open_transaction("t1", TransactionBase::Blank).await;
        assert!(snap.config.bgp_instances.is_empty());
        assert!(!snap.dirty);
        assert!(!snap.resumed);
    }

    #[tokio::test]
    async fn open_current_clones_running() {
        let store = ConfigStore::new(
            Config {
                bgp_instances: vec![instance("default", 65000)],
                ..Default::default()
            },
            None,
        );
        let snap = store.open_transaction("t1", TransactionBase::Current).await;
        assert_eq!(snap.config.bgp_instances.len(), 1);
        assert!(!snap.resumed);
    }

    #[tokio::test]
    async fn reopen_resumes_existing_transaction_and_ignores_base() {
        let store = ConfigStore::new(Config::default(), None);
        store.open_transaction("t1", TransactionBase::Blank).await;
        store.apply_op("t1", ensure_op("r1")).await.unwrap();

        let snap = store.open_transaction("t1", TransactionBase::Current).await;
        assert!(snap.resumed);
        assert!(snap.dirty);
        assert_eq!(snap.config.bgp_instances.len(), 1);
        assert_eq!(snap.config.bgp_instances[0].name, "r1");
    }

    #[tokio::test]
    async fn apply_op_updates_transaction_leaves_running_unchanged() {
        let store = ConfigStore::new(Config::default(), None);
        store.open_transaction("t1", TransactionBase::Blank).await;
        let snap = store.apply_op("t1", ensure_op("r1")).await.unwrap();
        assert_eq!(snap.config.bgp_instances.len(), 1);
        assert!(store.running_snapshot().await.bgp_instances.is_empty());
    }

    #[tokio::test]
    async fn apply_op_missing_transaction_returns_error() {
        let store = ConfigStore::new(Config::default(), None);
        let err = store
            .apply_op("missing", ensure_op("r1"))
            .await
            .unwrap_err();
        assert!(matches!(err, ConfigError::TransactionNotFound(n) if n == "missing"));
    }

    #[tokio::test]
    async fn commit_valid_transaction_updates_running_and_removes_transaction() {
        let store = ConfigStore::new(Config::default(), None);
        store.open_transaction("t1", TransactionBase::Blank).await;
        store.apply_op("t1", ensure_op("r1")).await.unwrap();
        store.apply_op("t1", set_asn_op("r1", 65000)).await.unwrap();

        store.commit_transaction("t1").await.unwrap();

        let running = store.running_snapshot().await;
        assert_eq!(running.bgp_instances.len(), 1);
        assert_eq!(running.bgp_instances[0].name, "r1");
        assert!(matches!(
            store.get_transaction("t1").await,
            Err(ConfigError::TransactionNotFound(_))
        ));
    }

    #[tokio::test]
    async fn commit_invalid_transaction_leaves_running_unchanged_and_keeps_transaction_alive() {
        let store = ConfigStore::new(Config::default(), None);
        store.open_transaction("t1", TransactionBase::Blank).await;
        // ASN 0 is invalid, and Ensure leaves asn at the placeholder 0.
        store.apply_op("t1", ensure_op("bad")).await.unwrap();

        assert!(store.commit_transaction("t1").await.is_err());
        assert!(store.running_snapshot().await.bgp_instances.is_empty());

        // The transaction must still be there, editable, for a retry.
        let snap = store.get_transaction("t1").await.unwrap();
        assert_eq!(snap.config.bgp_instances.len(), 1);
    }

    #[tokio::test]
    async fn commit_missing_transaction_returns_error() {
        let store = ConfigStore::new(Config::default(), None);
        assert!(matches!(
            store.commit_transaction("missing").await,
            Err(ConfigError::TransactionNotFound(_))
        ));
    }

    #[tokio::test]
    async fn diff_transaction_reports_changes_against_running() {
        let store = ConfigStore::new(
            Config {
                bgp_instances: vec![instance("r1", 65000)],
                ..Default::default()
            },
            None,
        );
        store.open_transaction("t1", TransactionBase::Current).await;
        store.apply_op("t1", set_asn_op("r1", 65001)).await.unwrap();

        let diff = store.diff_transaction("t1").await.unwrap();
        assert_eq!(diff.bgp_instances.len(), 1);
        assert_eq!(diff.bgp_instances[0].header, "bgp instance r1");
    }

    #[tokio::test]
    async fn diff_transaction_missing_transaction_returns_error() {
        let store = ConfigStore::new(Config::default(), None);
        assert!(matches!(
            store.diff_transaction("missing").await,
            Err(ConfigError::TransactionNotFound(_))
        ));
    }

    #[tokio::test]
    async fn discard_removes_transaction_without_touching_running() {
        let store = ConfigStore::new(Config::default(), None);
        store.open_transaction("t1", TransactionBase::Blank).await;
        store.apply_op("t1", ensure_op("r1")).await.unwrap();

        store.discard_transaction("t1").await.unwrap();

        assert!(matches!(
            store.get_transaction("t1").await,
            Err(ConfigError::TransactionNotFound(_))
        ));
        assert!(store.running_snapshot().await.bgp_instances.is_empty());
    }

    #[tokio::test]
    async fn discard_missing_transaction_returns_error() {
        let store = ConfigStore::new(Config::default(), None);
        assert!(matches!(
            store.discard_transaction("missing").await,
            Err(ConfigError::TransactionNotFound(_))
        ));
    }

    /// `ConfigOp` cannot construct two `BgpInstance`s with the same name
    /// through the public op API (`Ensure` is idempotent per name), so this
    /// seeds the duplicate directly into the transaction map (test-only
    /// access via `super::*`) to confirm `garde` validation genuinely still
    /// runs at commit regardless of how the transaction's `Config` was
    /// populated.
    #[tokio::test]
    async fn commit_duplicate_names_returns_error() {
        let store = ConfigStore::new(Config::default(), None);
        let bad_config = Config {
            bgp_instances: vec![instance("vrf-a", 65001), instance("vrf-a", 65002)],
            ..Default::default()
        };
        store.0.transactions.lock().await.insert(
            "t1".to_string(),
            Transaction {
                config: bad_config,
                dirty: true,
            },
        );

        assert!(store.commit_transaction("t1").await.is_err());
        assert!(store.running_snapshot().await.bgp_instances.is_empty());
    }

    #[tokio::test]
    async fn routing_table_with_both_associations_round_trips_through_commit() {
        let store = ConfigStore::new(Config::default(), None);
        store.open_transaction("t1", TransactionBase::Blank).await;
        store.apply_op("t1", ensure_op("r1")).await.unwrap();
        store.apply_op("t1", set_asn_op("r1", 65000)).await.unwrap();
        store
            .apply_op("t1", ensure_static_routing_instance_op("sri1"))
            .await
            .unwrap();
        store
            .apply_op("t1", ensure_routing_table_op("rt1"))
            .await
            .unwrap();
        store
            .apply_op("t1", set_routing_table_bgp_instance_op("rt1", "r1"))
            .await
            .unwrap();
        store
            .apply_op(
                "t1",
                set_routing_table_static_routing_instance_op("rt1", "sri1"),
            )
            .await
            .unwrap();

        store.commit_transaction("t1").await.unwrap();

        let running = store.running_snapshot().await;
        assert_eq!(running.routing_tables.len(), 1);
        assert_eq!(
            running.routing_tables[0].bgp_instance.as_deref(),
            Some("r1")
        );
        assert_eq!(
            running.routing_tables[0].static_routing_instance.as_deref(),
            Some("sri1")
        );
    }

    #[tokio::test]
    async fn commit_fails_when_routing_table_references_missing_bgp_instance() {
        let store = ConfigStore::new(Config::default(), None);
        store.open_transaction("t1", TransactionBase::Blank).await;
        store
            .apply_op("t1", ensure_routing_table_op("rt1"))
            .await
            .unwrap();
        store
            .apply_op(
                "t1",
                set_routing_table_bgp_instance_op("rt1", "does-not-exist"),
            )
            .await
            .unwrap();

        assert!(store.commit_transaction("t1").await.is_err());
        assert!(store.running_snapshot().await.routing_tables.is_empty());
    }

    #[tokio::test]
    async fn commit_fails_when_two_routing_tables_claim_same_bgp_instance() {
        let store = ConfigStore::new(Config::default(), None);
        store.open_transaction("t1", TransactionBase::Blank).await;
        store.apply_op("t1", ensure_op("r1")).await.unwrap();
        store
            .apply_op("t1", ensure_routing_table_op("rt1"))
            .await
            .unwrap();
        store
            .apply_op("t1", ensure_routing_table_op("rt2"))
            .await
            .unwrap();
        store
            .apply_op("t1", set_routing_table_bgp_instance_op("rt1", "r1"))
            .await
            .unwrap();
        store
            .apply_op("t1", set_routing_table_bgp_instance_op("rt2", "r1"))
            .await
            .unwrap();

        assert!(store.commit_transaction("t1").await.is_err());
        assert!(store.running_snapshot().await.routing_tables.is_empty());
    }

    #[tokio::test]
    async fn commit_fails_when_two_routing_tables_claim_same_static_routing_instance() {
        let store = ConfigStore::new(Config::default(), None);
        store.open_transaction("t1", TransactionBase::Blank).await;
        store
            .apply_op("t1", ensure_static_routing_instance_op("sri1"))
            .await
            .unwrap();
        store
            .apply_op("t1", ensure_routing_table_op("rt1"))
            .await
            .unwrap();
        store
            .apply_op("t1", ensure_routing_table_op("rt2"))
            .await
            .unwrap();
        store
            .apply_op(
                "t1",
                set_routing_table_static_routing_instance_op("rt1", "sri1"),
            )
            .await
            .unwrap();
        store
            .apply_op(
                "t1",
                set_routing_table_static_routing_instance_op("rt2", "sri1"),
            )
            .await
            .unwrap();

        assert!(store.commit_transaction("t1").await.is_err());
        assert!(store.running_snapshot().await.routing_tables.is_empty());
    }

    #[tokio::test]
    async fn static_routing_instance_with_route_round_trips_through_commit() {
        let store = ConfigStore::new(Config::default(), None);
        store.open_transaction("t1", TransactionBase::Blank).await;
        store
            .apply_op("t1", ensure_static_routing_instance_op("sri1"))
            .await
            .unwrap();
        store
            .apply_op(
                "t1",
                ConfigOp::StaticRoute(nos_proto::StaticRouteOp::Set {
                    instance: "sri1".to_string(),
                    subnet: "10.0.0.0/24".parse().unwrap(),
                    gateway: "10.0.0.1".parse().unwrap(),
                }),
            )
            .await
            .unwrap();

        store.commit_transaction("t1").await.unwrap();

        let running = store.running_snapshot().await;
        assert_eq!(running.static_routing_instances.len(), 1);
        assert_eq!(running.static_routing_instances[0].routes.len(), 1);
    }
}
