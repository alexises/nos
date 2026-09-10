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
| `ipc` | IPC message types: `Request` (client→server) and `Event` (server→client). |
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
4. Re-export from `lib.rs` if it's part of the public API.
