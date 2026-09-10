# nos-config — Configuration Daemon

Owns the running configuration and exposes it to all component processes via a Unix socket IPC server.

## Responsibilities

- **Config store**: candidate/running split with atomic commit and garde-based validation.
- **IPC server**: accepts connections from component processes, handles `Get` and `Subscribe`/`Unsubscribe` requests.
- **Change propagation**: broadcasts committed configs to all subscribed connections.

## What lives here vs nos-proto

All **wire types** (`Config`, `BgpInstance`, `Request`, `Event`, `IpcCodec`) live in `nos-proto`.  
`nos-config` owns the **store logic** and the **server** — nothing about wire types.

## Key types

| Type | File | Role |
|------|------|------|
| `ConfigStore` | `store.rs` | Holds `running: Arc<RwLock<Config>>` + `candidate: Option<Config>` + `broadcast::Sender` |
| `ConfigError` | `error.rs` | `Validation`, `NoCandidate`, `Io` |
| `server::start()` | `server.rs` | Binds `UnixListener`, spawns per-connection tasks |

## ConfigStore API

```rust
ConfigStore::new(initial)          // create with an initial running config
store.edit_candidate().await       // &mut Config — create/access candidate
store.commit().await               // validate → promote candidate → broadcast
store.running()                    // Arc<RwLock<Config>> — direct read access
store.subscribe()                  // broadcast::Receiver<Arc<Config>>
store.start_ipc_server(&path)      // bind socket, start accept loop
```

## IPC server

`server::start()` binds a `UnixListener` and spawns an accept loop. Per-connection:
- `Request::Get` → send `Event::Config(current_running)` once.
- `Request::Subscribe` → send snapshot, then spawn a forwarder task that bridges `broadcast::Receiver` → `mpsc::Sender`. The select loop drains the `mpsc::Receiver` and forwards `Event::Config` to the client.
- `Request::Unsubscribe` → abort the forwarder task.
- Connection drop → forwarder task is aborted, connection task exits.

## Socket path convention

By convention (not yet enforced by code), the socket lives at `/run/nos/config.sock`. In tests, use a `tempfile::tempdir()` path.
