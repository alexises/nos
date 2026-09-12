# nos-config — Configuration Daemon

Owns the running configuration and exposes it to all component processes via a Unix socket IPC server.

## Responsibilities

- **Config store**: named, server-held transactions (each an independent in-progress `Config`) plus the running config, with atomic commit and garde-based validation.
- **IPC server**: accepts connections from component processes, handles `Get`, `Subscribe`/`Unsubscribe`, `Save`, and the transaction lifecycle requests (`OpenTransaction`, `ApplyOp`, `GetTransaction`, `CommitTransaction`, `DiscardTransaction`).
- **Change propagation**: broadcasts committed configs (whether from `Save`-adjacent tooling or a transaction commit) to all subscribed connections.
- **Persistence**: loads the running config from disk at startup and writes it back out on `Save`.

## What lives here vs nos-proto

All **wire types** (`Config`, `BgpInstance`, `Request`, `Event`, `ConfigOp`, `IpcCodec`) live in `nos-proto`.  
`nos-config` owns the **store logic** and the **server** — nothing about wire types.

## Key types

| Type | File | Role |
|------|------|------|
| `ConfigStore` | `store.rs` | Cheap `Clone` handle (`Arc<Inner>`) over `running: RwLock<Config>` + `transactions: Mutex<HashMap<String, Transaction>>` + `broadcast::Sender` + `config_path` |
| `ConfigError` | `error.rs` | `Validation`, `TransactionNotFound`, `Op`, `PersistenceNotConfigured`, `Io`, `Persistence`, `Serialization` |
| `server::start()` | `server.rs` | Binds `UnixListener`, spawns per-connection tasks, each holding a cloned `ConfigStore` |
| `persistence::{save_to_disk, load_or_default}` | `persistence.rs` | Serialize/atomically write, and load-with-fallback, the config file |

## ConfigStore API

```rust
ConfigStore::new(initial, config_path)          // create with an initial running config + optional persistence path
store.running_snapshot().await                  // Config — a clone of the current running config
store.subscribe()                               // broadcast::Receiver<Arc<Config>>
store.save_to_disk().await                      // persist running config to config_path

store.open_transaction(name, base).await        // TransactionSnapshot — create from Blank/Current, or resume if `name` exists
store.apply_op(name, op).await                  // Result<TransactionSnapshot, ConfigError> — mutate a transaction, no validation
store.get_transaction(name).await               // Result<TransactionSnapshot, ConfigError>
store.commit_transaction(name).await            // validate → promote to running → broadcast → remove transaction
store.discard_transaction(name).await           // remove transaction without touching running

store.start_ipc_server(&addr)                   // bind socket, start accept loop
```

Lock ordering: always lock `transactions` before `running` to avoid deadlock.

## IPC server

`server::start()` binds a `UnixListener` and spawns an accept loop, each connection sharing a cloned `ConfigStore`. Per-connection:
- `Request::Get` → send `Event::Config(current_running)` once.
- `Request::Subscribe` → send snapshot, then spawn a forwarder task that bridges `broadcast::Receiver` → `mpsc::Sender`. The select loop drains the `mpsc::Receiver` and forwards `Event::Config` to the client.
- `Request::Unsubscribe` → abort the forwarder task.
- `Request::Save` → serializes the running config as YAML and atomically writes it to the daemon's `--config-file` path; replies `Event::Saved` on success, `Event::Error` if no `--config-file` was configured or the write fails.
- `Request::OpenTransaction`/`ApplyOp`/`GetTransaction`/`CommitTransaction`/`DiscardTransaction` → thin calls into the matching `ConfigStore` method (see `dispatch_request` in `server.rs`), replying `Event::Transaction`/`Event::Committed`/`Event::Discarded`/`Event::Error`.
- Connection drop → forwarder task is aborted, connection task exits. **Transactions have no lifecycle tie to connections** — they live purely in `ConfigStore`, keyed by name, so a dropped connection never loses or discards one; only an explicit `DiscardTransaction` does.

## Socket path convention

By convention (not yet enforced by code), the socket lives at `/run/nos/config.sock`. In tests, use a `tempfile::tempdir()` path.

## Config file convention

By convention (not yet enforced elsewhere), the persisted config file lives at `/var/lib/nos/config.yaml`, overridable via `--config-file`. A missing file at startup falls back silently to `Config::default()`; a malformed file at startup is a fatal error — it is never silently discarded in favor of a default.
