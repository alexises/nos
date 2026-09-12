# nos-proto — Shared Protocol Types

Single source of truth for all inter-process wire contracts in NOS.

## Why this crate exists

Component processes (`nos-bgp`, `nos-rib`, …) must not depend on `nos-config` internals — only on the shared types they exchange. By owning all shared types here, we get:
- **Protocol sync at compile time**: change a type → compiler breaks every consumer immediately.
- **Clean dependency graph**: components depend on `nos-proto`, not on each other.

## Contents

| Module | Purpose |
|--------|---------|
| `schema/` | Config tree types: `Config`, `BgpInstance`. Derived `garde::Validate` for commit-time validation. |
| `validators` | Generic reusable validation helpers (e.g. `unique_in`). |
| `ops/` | Section-scoped edit types applied to a transaction's in-progress config (e.g. `BgpInstanceOp`), wrapped by `ConfigOp`. Never validated — only `garde` at commit time is. |
| `ipc` | IPC message types: `Request` (client→server) and `Event` (server→client), plus `TransactionBase` and `TransactionSnapshot`. |
| `codec` | `IpcCodec<T>`: framing codec (4-byte LE length prefix + postcard payload). |

## Wire format

```
┌──────────────┬──────────────────────────┐
│ 4-byte LE u32│ postcard-encoded payload  │
│  (length)    │  (Request or Event enum)  │
└──────────────┴──────────────────────────┘
```

Use `IpcCodec<T>` with `tokio_util::codec::{FramedRead, FramedWrite}` to get typed async send/recv over a `UnixStream`.

## Adding a new config section

1. Add the new struct in `schema/` deriving `Serialize, Deserialize, garde::Validate`.
2. Add `#[garde(context(Config as ctx))]` and use the context for any cross-references.
3. Add the field to `Config` in `schema/mod.rs` with `#[garde(dive)]`.
4. Add a sibling `<Section>Op` enum in `ops/<section>.rs` with a synchronous `apply(&self, config: &mut Config) -> Result<(), OpError>` (create/update/delete by name, no `garde` validation — that only runs at commit), then add a `ConfigOp` variant wrapping it in `ops/mod.rs`.
5. Re-export from `lib.rs` if it's part of the public API.

## Wire compatibility

`Request`/`Event` variants must always be **appended**, never inserted or reordered — `postcard` encodes enum variants by index, so reordering breaks compatibility with already-built binaries.
