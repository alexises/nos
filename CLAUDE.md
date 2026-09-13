# NOS — Network Operating System

A network operating system built from scratch in Rust.

## Components

| Directory | Crate | Purpose |
|-----------|-------|---------|
| `proto/` | `nos-proto` | Shared wire types, IPC codec — single source of truth for all inter-process contracts |
| `config/` | `nos-config` | Configuration store and IPC server |
| `bgp/` | `nos-bgp` | BGP-4 implementation |
| `cli/` | `nos-cli` | Interactive shell (binary `nos`) — main user-facing entry point |
| `watchdog/` | `nos-watchdog` | Process supervisor — starts and restarts the other component processes |

## Architecture

### Process model

Each component (BGP, RIB, OSPF, …) runs as a dedicated OS process. No component shares memory with another.

```
┌──────────────────────────────────────────────────────┐
│  nos-config process                                  │
│  ConfigStore (named transactions/running) + IPC      │
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
  Request::Get                 one-shot read of the current running config
  Request::Subscribe           receive current snapshot + all future commits
  Request::Unsubscribe         stop receiving updates (connection stays open)
  Request::Save                persist the current running config to disk
  Request::OpenTransaction     open (or resume) a named transaction from blank/current
  Request::ApplyOp             apply one edit (e.g. a BgpInstanceOp) to a named transaction
  Request::GetTransaction      one-shot read of a named transaction's in-progress config
  Request::CommitTransaction   validate, promote to running, broadcast, and delete the transaction
  Request::DiscardTransaction  delete a named transaction without touching running config
  Request::Describe            one-shot fetch of one operation's documentation, by Topic

Server → Client:
  Event::Config(Config)             config snapshot (initial + on every commit, incl. via a transaction commit)
  Event::Error(String)              error from the daemon
  Event::Saved                      confirms the running config was persisted (reply to Save)
  Event::Transaction(Snapshot)      a named transaction's current state (reply to Open/Apply/Get)
  Event::Committed                  confirms a transaction was committed
  Event::Discarded                  confirms a transaction was discarded
  Event::Description(CommandDoc)    one operation's documentation (reply to Describe)
```

`Describe`/`Description` exist so that command/operation documentation (what an operation does, in human terms) is authored once in `nos-config` and shared by every client, rather than duplicated per-client — see `nos-cli`'s `spec.rs`/`help_menu.rs` for the reference consumer. It's scoped to a single `Topic` per request (not a bulk catalog fetch) so a client only ever fetches the docs it actually displays.

### Named transactions

Editing the config happens inside a **named transaction**, held server-side in `nos-config`, not tied to any one connection. `OpenTransaction` creates it from a blank config or a clone of the running config (`TransactionBase::Blank`/`Current`), or — if a transaction with that name already exists — resumes its current in-progress state unchanged. `CommitTransaction` validates the transaction and, if valid, atomically replaces the running config and broadcasts it to every `Subscribe`d connection (the same fan-out `Get`/`Subscribe` already use); on invalid input the transaction is left alive so the caller can keep editing. `DiscardTransaction` deletes it outright. Because transactions live only in the daemon and are addressed by name, a client can disconnect (crash, Ctrl-C, network drop) and resume the same transaction later from a fresh connection — see `nos-cli`'s `configure <name>` command.

### Config plane vs data plane

| Plane | Transport | Pattern |
|-------|-----------|---------|
| Config (this work) | Unix socket + postcard | Request/subscribe |
| Data (future, e.g. BGP→RIB routes) | Unix socket + postcard | High-frequency streaming |

Both planes use the same transport stack. The data plane will use a separate socket path and separate message types defined in `nos-proto`.

### Process supervision

`nos-watchdog` (binary `nos-watchdogd`) starts and supervises the other component processes — today `nos-configd` and `nos-bgpd` — as OS child processes. It is the container's entrypoint: on startup it spawns both children concurrently (no dependency ordering between them yet) and, if either exits, respawns it after an exponential backoff (starting at 1s, doubling, capped at 30s), resetting the backoff to 1s once a process has stayed up for 60s. It has no IPC dependency on `nos-proto` — v1 supervises purely by watching process exit, not by health-checking over the config socket. On SIGTERM or SIGINT, it sends SIGINT to each child (the signal both `nos-configd` and `nos-bgpd` already handle via `tokio::signal::ctrl_c()`), waits up to 10s for a clean exit, then force-kills and exits itself.

## Development

```bash
make check   # build + fmt + clippy + test (matches CI's fast jobs)
make fix     # auto-fix formatting and clippy-fixable lints
make help    # list all available targets
```

Containerized test environment:

```bash
make docker-build                        # build the nos-watchdogd/nos-configd/nos-bgpd/nos Docker image
docker compose up -d watchdog            # run the watchdog (which starts nos-configd + nos-bgpd) in a container
docker compose run --rm cli              # interactive shell, as its own container, sharing configd's socket
```

`watchdog` and `cli` share the same image and an `nos-run` volume mounted at `/run/nos`, so `cli` reaches the daemon over the same Unix socket path both binaries default to. `watchdog` also gets an `nos-data` volume at `/var/lib/nos` so `save`d config survives container restarts. `docker compose exec watchdog nos` still works too — it just runs the shell inside the watchdog's own container instead of a separate one.

Or run the underlying commands directly:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all
```
