# Configuration daemon internals

How `nos-config` is built, moved from `config/CLAUDE.md` (#264) so the always-loaded file keeps only rules and pitfalls. The rules to respect when editing the crate are in [`config/CLAUDE.md`](../../config/CLAUDE.md).

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
