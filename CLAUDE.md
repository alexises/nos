# NOS — Network Operating System

A network operating system built from scratch in Rust.

## Components

| Directory | Crate | Purpose |
|-----------|-------|---------|
| `proto/` | `nos-proto` | Shared wire types, IPC codec — single source of truth for all inter-process contracts |
| `config/` | `nos-config` | Configuration store and IPC server |
| `bgp/` | `nos-bgp` | BGP-4 implementation |
| `cli/` | `nos-cli` | Interactive shell (binary `nos`) — main user-facing entry point |

## Architecture

### Process model

Each component (BGP, RIB, OSPF, …) runs as a dedicated OS process. No component shares memory with another.

```
┌──────────────────────────────────────────────────────┐
│  nos-config process                                  │
│  ConfigStore (candidate/running) + IPC server        │
│  Listens on: /run/nos/config.sock                    │
└───────────────────────┬──────────────────────────────┘
                        │ Unix socket (nos-proto wire protocol)
          ┌─────────────┼─────────────┬─────────────┐
          ▼             ▼             ▼             ▼
    nos-bgp         nos-rib       nos-ospf       nos-cli
    process         process       process        (shell)
    (future)        (future)
```

### IPC transport

**Transport:** Unix domain sockets (`tokio::net::UnixListener` / `UnixStream`).  
**Serialization:** `postcard` (binary, compact, serde-based, no-alloc capable).  
**Framing:** 4-byte little-endian length prefix + postcard payload (see `nos-proto::codec::IpcCodec`).

This gives maximum performance for intra-host IPC with full Rust type safety — no HTTP overhead, no IDL outside the type system.

### Protocol spec sync

All wire types live in `nos-proto`. Since every component imports its message types from there, changing a type causes a **compile error in every consumer immediately** — stronger than protobuf's silent field-drop. This is the mechanism that keeps all processes in sync.

### Dependency graph

```
nos-proto   (no NOS dependencies)
    ↑               ↑
nos-config      nos-bgp, nos-rib, nos-ospf, nos-cli, …
(server)        (clients)
```

Component crates depend on `nos-proto` for types and `nos-proto::IpcCodec` for the framing codec. They do **not** depend on `nos-config` internals.

### Config subscription protocol

```
Client → Server:
  Request::Get          one-shot read of the current running config
  Request::Subscribe    receive current snapshot + all future commits
  Request::Unsubscribe  stop receiving updates (connection stays open)

Server → Client:
  Event::Config(Config) config snapshot (initial + on every commit)
  Event::Error(String)  error from the daemon
```

### Config plane vs data plane

| Plane | Transport | Pattern |
|-------|-----------|---------|
| Config (this work) | Unix socket + postcard | Request/subscribe |
| Data (future, e.g. BGP→RIB routes) | Unix socket + postcard | High-frequency streaming |

Both planes use the same transport stack. The data plane will use a separate socket path and separate message types defined in `nos-proto`.

## Development

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all
```
