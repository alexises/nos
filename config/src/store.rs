use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use garde::Validate as _;
use nos_proto::{
    config_path, diff_configs, sync_routing_table_refs, Config, ConfigDiff, ConfigOp,
    TransactionBase, TransactionSnapshot,
};
use tokio::sync::{broadcast, Mutex, RwLock};
use tracing::{debug, info};

use crate::error::ConfigError;
use crate::users::{hash_clear_passwords, normalize_names};

const BROADCAST_CAPACITY: usize = 16;

#[derive(Debug, Clone)]
struct Transaction {
    config: Config,
    dirty: bool,
    /// See `TransactionSnapshot::generation`.
    generation: u64,
}

impl Transaction {
    fn snapshot(&self, name: &str, resumed: bool) -> TransactionSnapshot {
        TransactionSnapshot {
            name: name.to_string(),
            config: self.config.clone(),
            dirty: self.dirty,
            resumed,
            generation: self.generation,
        }
    }

    /// RFC 9110 §13.1.1: `Some(g)` must equal the current generation.
    fn check(&self, if_match: Option<u64>) -> Result<(), ConfigError> {
        match if_match {
            Some(expected) if expected != self.generation => Err(ConfigError::PreconditionFailed {
                expected,
                actual: self.generation,
            }),
            _ => Ok(()),
        }
    }
}

/// One committed change, broadcast to every subscriber connection — the new
/// running config (for classic `Subscribe`), and what changed to produce it
/// (for `SubscribeDiff`). Internal only — never sent over the wire directly;
/// `server.rs` unwraps this into `Event::Config`/`Event::Diff` per connection.
pub(crate) struct CommitUpdate {
    pub config: Config,
    pub diff: ConfigDiff,
}

struct Inner {
    running: RwLock<Config>,
    transactions: Mutex<HashMap<String, Transaction>>,
    tx: broadcast::Sender<Arc<CommitUpdate>>,
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
        let mut initial = initial;
        sync_routing_table_refs(&mut initial);
        // A name loaded from the file is PRECIS-normalized before a clear-text
        // password seeded in the file (or by `seed_default_user`) is hashed here.
        normalize_names(&mut initial.users);
        hash_clear_passwords(&mut initial.users, &[]);
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

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<Arc<CommitUpdate>> {
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
            debug!(transaction = %name, resumed = true, "opened transaction");
            return existing.snapshot(name, true);
        }
        let config = match base {
            TransactionBase::Blank => Config::default(),
            TransactionBase::Current => self.0.running.read().await.clone(),
        };
        let txn = Transaction {
            config,
            dirty: false,
            generation: 0,
        };
        let snap = txn.snapshot(name, false);
        txs.insert(name.to_string(), txn);
        debug!(transaction = %name, ?base, resumed = false, "opened transaction");
        snap
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
        debug!(transaction = %name, ?op, "applying op");
        let users_before = txn.config.users.clone();
        op.apply(&mut txn.config)?;
        self.hash_users(&mut txn.config, &users_before).await;
        txn.dirty = true;
        txn.generation += 1;
        Ok(txn.snapshot(name, true))
    }

    /// Sets or removes the subsection of a named transaction's in-progress
    /// config addressed by `path` (see `nos_proto::config_path`). Atomic under
    /// the transactions lock, and all-or-nothing: the edit is applied to a
    /// JSON copy which must still deserialize as a `Config` before it
    /// replaces the transaction's config. Never runs `garde` validation.
    /// `if_match` (checked under the same lock, so this is a real
    /// compare-and-set) refuses the edit once the generation has moved on.
    pub async fn set_transaction_path(
        &self,
        name: &str,
        path: &[String],
        value: Option<&str>,
        if_match: Option<u64>,
    ) -> Result<TransactionSnapshot, ConfigError> {
        let mut txs = self.0.transactions.lock().await;
        let txn = txs
            .get_mut(name)
            .ok_or_else(|| ConfigError::TransactionNotFound(name.to_string()))?;
        txn.check(if_match)?;
        let users_before = txn.config.users.clone();
        let mut doc = serde_json::to_value(&txn.config)?;
        match value {
            Some(json) => config_path::set(&mut doc, path, serde_json::from_str(json)?)?,
            None => config_path::remove(&mut doc, path)?,
        }
        txn.config = serde_json::from_value(doc)?;
        self.hash_users(&mut txn.config, &users_before).await;
        txn.dirty = true;
        txn.generation += 1;
        debug!(transaction = %name, path = %path.join("/"), remove = value.is_none(), "set transaction path");
        Ok(txn.snapshot(name, true))
    }

    /// PRECIS-normalizes every user name, then hashes any clear-text password
    /// `config` now holds, reusing a matching hash from the transaction's
    /// previous users or the running config. Caller holds the `transactions`
    /// lock (lock order: transactions, running).
    async fn hash_users(&self, config: &mut Config, users_before: &[nos_proto::User]) {
        normalize_names(&mut config.users);
        let running = self.0.running.read().await;
        hash_clear_passwords(&mut config.users, &[users_before, &running.users]);
    }

    pub async fn get_transaction(&self, name: &str) -> Result<TransactionSnapshot, ConfigError> {
        let txs = self.0.transactions.lock().await;
        let txn = txs
            .get(name)
            .ok_or_else(|| ConfigError::TransactionNotFound(name.to_string()))?;
        Ok(txn.snapshot(name, true))
    }

    /// Validates the named transaction and, if valid, atomically promotes it
    /// to running, broadcasts the change to subscribers, and removes the
    /// transaction. If invalid (or `if_match` names a stale generation), the
    /// transaction is left intact so the caller can keep editing and retry.
    pub async fn commit_transaction(
        &self,
        name: &str,
        if_match: Option<u64>,
    ) -> Result<(), ConfigError> {
        let mut txs = self.0.transactions.lock().await;
        let txn = txs
            .get(name)
            .ok_or_else(|| ConfigError::TransactionNotFound(name.to_string()))?;
        txn.check(if_match)?;
        // Pass the config itself as the validation context (cross-reference checks).
        txn.config.validate_with(&txn.config)?;
        if txn.config.users.is_empty() && !self.0.running.read().await.users.is_empty() {
            return Err(ConfigError::NoUsersLeft);
        }
        let mut config = txn.config.clone();
        sync_routing_table_refs(&mut config);
        txs.remove(name);
        drop(txs);

        let mut running = self.0.running.write().await;
        let diff = diff_configs(&running, &config);
        *running = config.clone();
        drop(running);
        info!(transaction = %name, "config committed");
        // Ignore send errors — no active receivers is not a failure.
        let _ = self.0.tx.send(Arc::new(CommitUpdate { config, diff }));
        Ok(())
    }

    /// Swaps `user`'s password hash `old` for `new` in the running config
    /// (see `Request::UpgradePasswordHash`), broadcasting it like a commit.
    pub async fn upgrade_password_hash(
        &self,
        user: &str,
        old: &str,
        new: String,
    ) -> Result<(), ConfigError> {
        if !nos_password::is_hash(&new) {
            return Err(ConfigError::HashUpgradeRefused);
        }
        let mut running = self.0.running.write().await;
        let mut config = running.clone();
        match config
            .users
            .iter_mut()
            .find(|u| u.name == user && u.password == old)
        {
            Some(u) => u.password = new,
            None => return Err(ConfigError::HashUpgradeRefused),
        }
        let diff = diff_configs(&running, &config);
        *running = config.clone();
        drop(running);
        info!(user = %user, "password hash upgraded");
        let _ = self.0.tx.send(Arc::new(CommitUpdate { config, diff }));
        Ok(())
    }

    /// The diff a fresh `SubscribeDiff` connection should see as its initial
    /// event: everything currently in the running config, reported as
    /// `Added` (diffing against an empty config can never produce
    /// `Removed`/`Modified`).
    pub(crate) async fn initial_diff(&self) -> ConfigDiff {
        diff_configs(&Config::default(), &self.running_snapshot().await)
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

    /// Deletes a named transaction without touching the running config
    /// (refused, and kept, if `if_match` names a stale generation).
    pub async fn discard_transaction(
        &self,
        name: &str,
        if_match: Option<u64>,
    ) -> Result<(), ConfigError> {
        let mut txs = self.0.transactions.lock().await;
        txs.get(name)
            .ok_or_else(|| ConfigError::TransactionNotFound(name.to_string()))?
            .check(if_match)?;
        txs.remove(name);
        debug!(transaction = %name, "discarded transaction");
        Ok(())
    }

    /// Binds the given address and starts the IPC server in the background.
    ///
    /// Returns a `JoinHandle` — keep it alive for the server to continue running.
    pub fn start_ipc_server(
        &self,
        addr: &crate::server::ListenAddr,
        identity: &nos_pki::Identity,
    ) -> std::io::Result<tokio::task::JoinHandle<()>> {
        crate::server::start(addr, self.clone(), identity)
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
            cluster_id: None,
            confederation: nos_proto::BgpConfederation::default(),
            rpki_caches: Vec::new(),
            routing_table: None,
            redistribute_policy: None,
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

    fn segs(p: &str) -> Vec<String> {
        p.split('/')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()
    }

    #[tokio::test]
    async fn set_transaction_path_sets_subsection_and_marks_dirty() {
        let store = ConfigStore::new(Config::default(), None);
        store.open_transaction("t", TransactionBase::Blank).await;
        let body = serde_json::to_string(&instance("r1", 65000)).unwrap();
        let snap = store
            .set_transaction_path("t", &segs("bgp-instance/r1"), Some(&body), None)
            .await
            .unwrap();
        assert!(snap.dirty);
        assert_eq!(snap.config.bgp_instances.len(), 1);

        let snap = store
            .set_transaction_path("t", &segs("hostname"), Some("\"rest-host\""), None)
            .await
            .unwrap();
        assert_eq!(snap.config.hostname, "rest-host");

        let snap = store
            .set_transaction_path("t", &segs("bgp-instance/r1"), None, None)
            .await
            .unwrap();
        assert_eq!(snap.config.bgp_instances, [] as [nos_proto::BgpInstance; 0]);
        assert_eq!(
            store.running_snapshot().await.bgp_instances,
            [] as [nos_proto::BgpInstance; 0]
        );
    }

    #[tokio::test]
    async fn set_transaction_path_whole_config_and_failures_leave_it_untouched() {
        let store = ConfigStore::new(Config::default(), None);
        store.open_transaction("t", TransactionBase::Blank).await;
        let whole = Config {
            hostname: "whole".to_string(),
            bgp_instances: vec![instance("r1", 1)],
            ..Default::default()
        };
        store
            .set_transaction_path(
                "t",
                &[],
                Some(&serde_json::to_string(&whole).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Type mismatch: rejected, transaction unchanged.
        assert!(store
            .set_transaction_path("t", &segs("hostname"), Some("42"), None)
            .await
            .is_err());
        // Unknown path / unknown transaction.
        assert!(store
            .set_transaction_path("t", &segs("nope"), Some("1"), None)
            .await
            .is_err());
        assert!(store
            .set_transaction_path("missing", &[], Some("{}"), None)
            .await
            .is_err());
        assert_eq!(store.get_transaction("t").await.unwrap().config, whole);
    }

    #[tokio::test]
    async fn new_derives_routing_table_refs_from_initial_config() {
        let store = ConfigStore::new(
            Config {
                bgp_instances: vec![instance("r1", 65000)],
                routing_tables: vec![nos_proto::RoutingTable {
                    rest_api: None,
                    evpn: nos_proto::RoutingTableEvpn::default(),
                    ospfv3_instance: None,
                    name: "rt1".to_string(),
                    bgp_instance: Some("r1".to_string()),
                    ospf_instance: None,
                    static_routing_instance: None,
                    redistribute: None,
                }],
                ..Default::default()
            },
            None,
        );
        let running = store.running_snapshot().await;
        assert_eq!(
            running.bgp_instances[0].routing_table.as_deref(),
            Some("rt1")
        );
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
        assert_eq!(snap.config.bgp_instances, [] as [nos_proto::BgpInstance; 0]);
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
        assert_eq!(
            store.running_snapshot().await.bgp_instances,
            [] as [nos_proto::BgpInstance; 0]
        );
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

        store.commit_transaction("t1", None).await.unwrap();

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

        assert!(store.commit_transaction("t1", None).await.is_err());
        assert_eq!(
            store.running_snapshot().await.bgp_instances,
            [] as [nos_proto::BgpInstance; 0]
        );

        // The transaction must still be there, editable, for a retry.
        let snap = store.get_transaction("t1").await.unwrap();
        assert_eq!(snap.config.bgp_instances.len(), 1);
    }

    #[tokio::test]
    async fn commit_missing_transaction_returns_error() {
        let store = ConfigStore::new(Config::default(), None);
        assert!(matches!(
            store.commit_transaction("missing", None).await,
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

        store.discard_transaction("t1", None).await.unwrap();

        assert!(matches!(
            store.get_transaction("t1").await,
            Err(ConfigError::TransactionNotFound(_))
        ));
        assert_eq!(
            store.running_snapshot().await.bgp_instances,
            [] as [nos_proto::BgpInstance; 0]
        );
    }

    #[tokio::test]
    async fn generation_counts_edits_and_a_stale_if_match_is_refused_untouched() {
        let store = ConfigStore::new(Config::default(), None);
        assert_eq!(
            store
                .open_transaction("t", TransactionBase::Blank)
                .await
                .generation,
            0
        );
        assert_eq!(
            store
                .apply_op("t", ensure_op("r1"))
                .await
                .unwrap()
                .generation,
            1
        );
        // A matching precondition passes and bumps; `None` is unconditional.
        let snap = store
            .set_transaction_path("t", &segs("hostname"), Some("\"h1\""), Some(1))
            .await
            .unwrap();
        assert_eq!(snap.generation, 2);
        let snap = store
            .set_transaction_path("t", &segs("hostname"), Some("\"h2\""), None)
            .await
            .unwrap();
        assert_eq!(snap.generation, 3);

        // Stale: refused, nothing changed, the transaction stays.
        let stale = Some(2);
        assert!(matches!(
            store
                .set_transaction_path("t", &segs("hostname"), Some("\"h3\""), stale)
                .await,
            Err(ConfigError::PreconditionFailed {
                expected: 2,
                actual: 3
            })
        ));
        assert!(matches!(
            store.commit_transaction("t", stale).await,
            Err(ConfigError::PreconditionFailed { .. })
        ));
        assert!(matches!(
            store.discard_transaction("t", stale).await,
            Err(ConfigError::PreconditionFailed { .. })
        ));
        let snap = store.get_transaction("t").await.unwrap();
        assert_eq!((snap.generation, snap.config.hostname.as_str()), (3, "h2"));
        assert_eq!(
            store.running_snapshot().await.bgp_instances,
            [] as [nos_proto::BgpInstance; 0]
        );

        // Current: discard goes through.
        store.discard_transaction("t", Some(3)).await.unwrap();
        assert!(matches!(
            store.get_transaction("t").await,
            Err(ConfigError::TransactionNotFound(_))
        ));
    }

    #[tokio::test]
    async fn discard_missing_transaction_returns_error() {
        let store = ConfigStore::new(Config::default(), None);
        assert!(matches!(
            store.discard_transaction("missing", None).await,
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
                generation: 0,
            },
        );

        assert!(store.commit_transaction("t1", None).await.is_err());
        assert_eq!(
            store.running_snapshot().await.bgp_instances,
            [] as [nos_proto::BgpInstance; 0]
        );
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

        store.commit_transaction("t1", None).await.unwrap();

        let running = store.running_snapshot().await;
        assert_eq!(running.routing_tables.len(), 1);
        assert_eq!(
            running.routing_tables[0].bgp_instance.as_deref(),
            Some("r1")
        );
        assert_eq!(
            running.bgp_instances[0].routing_table.as_deref(),
            Some("rt1"),
            "commit must derive the reflexive BgpInstance.routing_table reference"
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

        assert!(store.commit_transaction("t1", None).await.is_err());
        assert_eq!(
            store.running_snapshot().await.routing_tables,
            [] as [nos_proto::RoutingTable; 0]
        );
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

        assert!(store.commit_transaction("t1", None).await.is_err());
        assert_eq!(
            store.running_snapshot().await.routing_tables,
            [] as [nos_proto::RoutingTable; 0]
        );
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

        assert!(store.commit_transaction("t1", None).await.is_err());
        assert_eq!(
            store.running_snapshot().await.routing_tables,
            [] as [nos_proto::RoutingTable; 0]
        );
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

        store.commit_transaction("t1", None).await.unwrap();

        let running = store.running_snapshot().await;
        assert_eq!(running.static_routing_instances.len(), 1);
        assert_eq!(running.static_routing_instances[0].routes.len(), 1);
    }

    fn set_password_op(name: &str, password: &str) -> ConfigOp {
        ConfigOp::User(nos_proto::UserOp::SetPassword {
            name: name.to_string(),
            password: password.to_string(),
        })
    }

    async fn commit_password(store: &ConfigStore, tx: &str, name: &str, password: &str) {
        store.open_transaction(tx, TransactionBase::Current).await;
        store
            .apply_op(tx, set_password_op(name, password))
            .await
            .unwrap();
        store.commit_transaction(tx, None).await.unwrap();
    }

    #[tokio::test]
    async fn clear_password_is_hashed_and_resetting_the_same_one_is_no_diff() {
        let store = ConfigStore::new(Config::default(), None);
        commit_password(&store, "t1", "alice", "hunter2").await;
        let hash = store.running_snapshot().await.users[0].password.clone();
        assert!(nos_password::verify("hunter2", &hash));

        // Same clear password again: hash untouched, so the transaction diff is empty.
        store.open_transaction("t2", TransactionBase::Current).await;
        let snap = store
            .apply_op("t2", set_password_op("alice", "hunter2"))
            .await
            .unwrap();
        assert_eq!(snap.config.users[0].password, hash);
        assert!(store.diff_transaction("t2").await.unwrap().is_empty());
        store.discard_transaction("t2", None).await.unwrap();

        // A different password does change it, and shows up as a (hidden) diff.
        store.open_transaction("t3", TransactionBase::Current).await;
        store
            .apply_op("t3", set_password_op("alice", "other"))
            .await
            .unwrap();
        let diff = store.diff_transaction("t3").await.unwrap();
        assert_eq!(diff.users.len(), 1);
        assert_ne!(
            store.get_transaction("t3").await.unwrap().config.users[0].password,
            hash
        );
    }

    #[tokio::test]
    async fn password_hash_upgrade_is_a_compare_and_swap_of_hashes() {
        let store = ConfigStore::new(Config::default(), None);
        commit_password(&store, "t1", "alice", "one").await;
        let old = store.running_snapshot().await.users[0].password.clone();
        let new = nos_password::hash("one");
        let mut rx = store.subscribe();

        assert!(store
            .upgrade_password_hash("alice", "stale", new.clone())
            .await
            .is_err());
        assert!(store
            .upgrade_password_hash("alice", &old, "clear".into())
            .await
            .is_err());
        assert!(store
            .upgrade_password_hash("bob", &old, new.clone())
            .await
            .is_err());
        store
            .upgrade_password_hash("alice", &old, new.clone())
            .await
            .unwrap();
        assert_eq!(store.running_snapshot().await.users[0].password, new);
        assert_eq!(rx.recv().await.unwrap().config.users[0].password, new);
    }

    #[tokio::test]
    async fn reverting_to_the_running_password_inside_a_transaction_is_no_diff() {
        let store = ConfigStore::new(Config::default(), None);
        commit_password(&store, "t1", "alice", "one").await;
        store.open_transaction("t2", TransactionBase::Current).await;
        store
            .apply_op("t2", set_password_op("alice", "two"))
            .await
            .unwrap();
        store
            .apply_op("t2", set_password_op("alice", "one"))
            .await
            .unwrap();
        assert!(store.diff_transaction("t2").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn clear_password_set_through_a_path_put_is_hashed() {
        let store = ConfigStore::new(Config::default(), None);
        store.open_transaction("t", TransactionBase::Blank).await;
        let snap = store
            .set_transaction_path(
                "t",
                &segs("user/bob"),
                Some(r#"{"name":"bob","password":"pw"}"#),
                None,
            )
            .await
            .unwrap();
        assert!(nos_password::verify("pw", &snap.config.users[0].password));
    }

    #[tokio::test]
    async fn clear_password_seeded_at_startup_is_hashed() {
        let mut cfg = Config::default();
        crate::users::seed_default_user(&mut cfg);
        let store = ConfigStore::new(cfg, None);
        let users = store.running_snapshot().await.users;
        assert!(nos_password::verify("admin", &users[0].password));
    }

    #[tokio::test]
    async fn commit_that_removes_every_user_is_refused() {
        let store = ConfigStore::new(Config::default(), None);
        commit_password(&store, "t1", "alice", "pw").await;
        store.open_transaction("t2", TransactionBase::Current).await;
        store
            .apply_op(
                "t2",
                ConfigOp::User(nos_proto::UserOp::Delete {
                    name: "alice".into(),
                }),
            )
            .await
            .unwrap();
        assert!(matches!(
            store.commit_transaction("t2", None).await,
            Err(ConfigError::NoUsersLeft)
        ));
        assert_eq!(store.running_snapshot().await.users.len(), 1);
    }
}
