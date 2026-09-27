# nos-config — Configuration Daemon

Owns the running configuration and exposes it to all component processes via a Unix socket IPC server.

## Responsibilities

- **Config store**: named, server-held transactions (each an independent in-progress `Config`) plus the running config, with atomic commit and garde-based validation.
- **IPC server**: accepts connections from component processes, handles `Get`, `Subscribe`/`SubscribeDiff`/`Unsubscribe`, `Save`, and the transaction lifecycle requests (`OpenTransaction`, `ApplyOp`, `GetTransaction`, `CommitTransaction`, `DiscardTransaction`, `DiffTransaction`).
- **Change propagation**: broadcasts each commit's new config *and* the diff that produced it to all subscribed connections — `Subscribe` connections get the full config, `SubscribeDiff` connections get just the diff, scoped to the sections they asked for.
- **Persistence**: loads the running config from disk at startup and writes it back out on `Save`.

## What lives here vs nos-proto

All **wire types** (`Config`, `BgpInstance`, `Request`, `Event`, `ConfigOp`, `IpcCodec`) live in `nos-proto`.  
`nos-config` owns the **store logic** and the **server** — nothing about wire types.

## Key types

| Type | File | Role |
|------|------|------|
| `ConfigStore` | `store.rs` | Cheap `Clone` handle (`Arc<Inner>`) over `running: RwLock<Config>` + `transactions: Mutex<HashMap<String, Transaction>>` + `broadcast::Sender<Arc<CommitUpdate>>` + `config_path` |
| `CommitUpdate` | `store.rs` | Internal (never sent over the wire directly) — one commit's `{ config: Config, diff: ConfigDiff }`, broadcast together so `Subscribe` and `SubscribeDiff` connections can each take the half they need |
| `ConfigError` | `error.rs` | `Validation`, `NoUsersLeft` (a commit may not remove every user), `TransactionNotFound`, `PreconditionFailed` (an `if_match` named a stale generation — message prefixed `precondition failed`, which `nos-restd` maps to 412), `Op`, `PersistenceNotConfigured`, `Io`, `Persistence`, `Serialization` |
| `server::start()` | `server.rs` | Binds a TLS `nos_pki::Listener` on a Unix socket (`ListenAddr::Unix` only — the TCP listener was removed, since it would bypass mTLS), spawns per-connection tasks (handshake inside the task) each holding a cloned `ConfigStore` and the peer's role/name from its certificate |
| `authz::allowed()` | `authz.rs` | Pure per-request allow-list: config reads (`Get`/`Subscribe*`/`Describe`) for every authenticated daemon and `User`; edits/`Save` for `User`/`Restd` only. No wildcard arm — a new `Request` variant won't compile until classified. A refused request gets `Event::Error("permission denied")` and the connection is closed |
| `users::{hash_clear_passwords, seed_default_user}` | `users.rs` | Replaces clear-text `User.password`s with argon2id hashes (reusing an earlier hash the clear text still verifies against, so re-setting a password is no diff); called by `ConfigStore` after every edit and on load. `seed_default_user` adds `admin`/`admin` when there are no users (called from `main.rs`) |
| `persistence::{save_to_disk, load_or_default}` | `persistence.rs` | Serialize/atomically write, and load-with-fallback, the config file |

## ConfigStore API

```rust
ConfigStore::new(initial, config_path)          // create with an initial running config + optional persistence path
store.running_snapshot().await                  // Config — a clone of the current running config
store.subscribe()                               // broadcast::Receiver<Arc<CommitUpdate>> — pub(crate), server.rs only
store.initial_diff().await                      // ConfigDiff — running vs. Config::default(), for a fresh SubscribeDiff connection's first event
store.save_to_disk().await                      // persist running config to config_path

store.open_transaction(name, base).await        // TransactionSnapshot — create from Blank/Current, or resume if `name` exists
store.apply_op(name, op).await                  // Result<TransactionSnapshot, ConfigError> — mutate a transaction, no validation
store.set_transaction_path(name, path, value, if_match).await  // set/remove one JSON subsection (nos-restd), no validation
store.get_transaction(name).await               // Result<TransactionSnapshot, ConfigError>
store.commit_transaction(name, if_match).await  // validate → promote to running → broadcast → remove transaction
store.discard_transaction(name, if_match).await // remove transaction without touching running
store.diff_transaction(name).await              // Result<ConfigDiff, ConfigError> — running vs. transaction, no validation

store.start_ipc_server(&addr, &identity)        // bind TLS socket, start accept loop
```

Lock ordering: always lock `transactions` before `running` to avoid deadlock.

Every `Transaction` carries a `generation: u64` (0 when created, +1 per successful `apply_op`/`set_transaction_path`), reported in every `TransactionSnapshot`. `if_match: Option<u64>` on `set_transaction_path`/`commit_transaction`/`discard_transaction` (and the matching `Request` variants) is an RFC 9110 §13.1.1 precondition: `Some(g)` is compared against the current generation under the same `transactions` lock the mutation takes, so it is a real compare-and-set, and a mismatch is `ConfigError::PreconditionFailed` with nothing changed (the transaction stays); `None` is unconditional — `nos-cli`/`nos-provision` never send one, only `nos-restd` does (its `ETag`/`If-Match`).

## IPC server

`server::start()` binds a `UnixListener` and spawns an accept loop, each connection sharing a cloned `ConfigStore`. Per-connection:
- `Request::Get` → send `Event::Config(current_running)` once.
- `Request::Subscribe` → send the current full snapshot, then spawn a forwarder task that bridges `broadcast::Receiver<Arc<CommitUpdate>>` → `mpsc::Sender<Event>`, building `Event::Config(update.config.clone())` per commit. The select loop drains the `mpsc::Receiver` and forwards whatever `Event` it built to the client.
- `Request::SubscribeDiff { scopes }` → send `store.initial_diff().await.scoped(&scopes)` as the first `Event::Diff`, then spawn a forwarder that builds `Event::Diff(update.diff.scoped(&scopes))` per commit and skips sending it when `ConfigDiff::is_empty()` — a scoped subscriber is never woken for a commit outside its scopes.
- `Request::Unsubscribe` → abort whichever forwarder task (`Subscribe` or `SubscribeDiff`) is active.
- `Request::Save` → serializes the running config as YAML and atomically writes it to the daemon's `--config-file` path; replies `Event::Saved` on success, `Event::Error` if no `--config-file` was configured or the write fails.
- `Request::OpenTransaction`/`ApplyOp`/`GetTransaction`/`CommitTransaction`/`DiscardTransaction`/`DiffTransaction` → thin calls into the matching `ConfigStore` method (see `dispatch_request` in `server.rs`), replying `Event::Transaction`/`Event::Committed`/`Event::Discarded`/`Event::Diff`/`Event::Error`.
- Connection drop → forwarder task is aborted, connection task exits. **Transactions have no lifecycle tie to connections** — they live purely in `ConfigStore`, keyed by name, so a dropped connection never loses or discards one; only an explicit `DiscardTransaction` does.

**Half-closed subscriber connections stay open.** A `Subscribe`/`SubscribeDiff` client is documented (see `client::subscribe` in `nos-cli`) to send its request then never write to the connection again — "the caller owns its lifetime." If the per-connection loop treated EOF/an error on the *request* read side as reason to tear down the whole connection, every such client would stop receiving events right after their first one (this was a real, previously-unnoticed bug — no existing test dropped its write half while still reading, so it went uncaught until `SubscribeDiff`'s own tests exercised that exact pattern end-to-end). The fix: once a subscription (`sub_task`) is active, EOF/an error on `reader` only disables further request reads (`reader_open = false`) — it does not `break` the connection. The connection then stays alive purely to keep draining `sub_rx` into `writer` until a write actually fails (the client is truly gone), at which point it closes and aborts the forwarder task. Without an active subscription, EOF/error still ends the connection immediately, as before.

## Socket path convention

By convention (not yet enforced by code), the socket lives at `/run/nos/config.sock`. In tests, use a `tempfile::tempdir()` path.

## Config file convention

By convention (not yet enforced elsewhere), the persisted config file lives at `/var/lib/nos/config.yaml`, overridable via `--config-file`. A missing file at startup falls back silently to `Config::default()`; a malformed file at startup is a fatal error — it is never silently discarded in favor of a default.
