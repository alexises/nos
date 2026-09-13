# NOS — Network Operating System

A network operating system built from scratch in Rust.

## Components

| Directory | Crate | Purpose |
|-----------|-------|---------|
| `proto/` | `nos-proto` | Shared wire types, IPC codec — single source of truth for all inter-process contracts |
| `config/` | `nos-config` | Configuration store and IPC server |
| `bgp/` | `nos-bgp` | BGP-4 implementation |
| `rib/` | `nos-rib` | Routing information base daemon — best-path selection per routing table |
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
    (future)
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

`nos-watchdog` (binary `nos-watchdogd`) starts and supervises the other component processes as OS child processes, and is the container's entrypoint. It always runs exactly one supervised `nos-configd`. For BGP, rather than a single static `nos-bgpd`, the watchdog subscribes to `nos-configd` over its own `--config-socket` connection (`Request::SubscribeDiff`, independent of whatever address is forwarded to the `nos-configd` child via the opaque `--configd-arg` pass-through) and dynamically spawns one `nos-bgpd --instance <name>` per `BgpInstance` in the live config. It reconciles on every diff it receives: a fresh connection's first diff is synthesized against an empty config (so every currently-configured instance shows up as `Added`) and is treated as the authoritative full membership list — anything already running that isn't in it gets stopped, closing the gap where an instance removed while disconnected could otherwise leak as an orphan process — while every later diff on the same connection is applied incrementally (`Added`/`Removed` only, `Modified` is a no-op since the `nos-bgpd` stub doesn't read instance parameters yet). The config subscription itself reconnects on a fixed 1s delay with no backoff if dropped (distinct from the exponential process-crash backoff below) — since `nos-configd` is supervised independently, its own crash/restart is transparent to already-running `nos-bgpd` instances. Every supervised process (`nos-configd` and each per-instance `nos-bgpd`) is respawned after an exponential backoff on unexpected exit (starting at 1s, doubling, capped at 30s, resetting to 1s once it's stayed up for 60s). On SIGTERM or SIGINT to the watchdog, or an instance's removal from config, its process is sent SIGINT (the signal `nos-configd`/`nos-bgpd` handle via `tokio::signal::ctrl_c()`), given up to 10s to exit cleanly, then force-killed — on watchdog shutdown this happens for every remaining process before it exits, so nothing is left orphaned.

RIB tables follow the identical dynamic-spawn pattern: the watchdog subscribes to `DiffScope::RoutingTables` and spawns one `nos-ribd --table <name>` per `RoutingTable` in the live config, with the same first-diff-is-authoritative reconciliation, fixed 1s reconnect delay, and exponential per-process crash backoff as BGP instances. `Modified` is likewise a no-op at this level — a table's `bgp_instance`/`static_routing_instance` association changing doesn't restart its `nos-ribd`, since that process independently subscribes to config (`RoutingTables` and `StaticRoutingInstances`) and re-resolves its own associations on every relevant diff, rebuilding its in-memory RIB from a fresh `Request::Get` rather than losing state to a restart.

`nos-config`'s IPC protocol supports this via `Request::SubscribeDiff { scopes }`: a subscriber names which `ConfigDiff` sections it cares about (`DiffScope::{Hostname,BgpInstances,RoutingTables,StaticRoutingInstances}`) and only receives `Event::Diff` for commits that touch a requested scope — commits outside every requested scope are never sent. This is a separate, additive path alongside the original `Request::Subscribe`/`Event::Config` (full snapshot on every commit, used by `nos-cli`'s live hostname prompt), which is unchanged. Both paths rely on a documented but easy-to-miss connection-lifecycle rule in `server.rs`: a subscriber (of either kind) is expected to send its request and then never write to the connection again — "the caller owns its lifetime" — so the server must not treat EOF/an error on the *request* side of a subscribed connection as reason to close the whole connection; it only stops reading further requests; the connection stays open to keep pushing events until the client is actually gone (detected when writing to it fails).

### Endpoint broker

Because the watchdog is the one process that actually spawns every other daemon, it also acts as the directory for "how do I reach daemon X" — a small broker protocol (`nos_proto::broker`: `WatchdogRequest::ResolveEndpoint { service: ServiceRef }` → `WatchdogEvent::Endpoint(PathBuf)` or `NotAvailable`), served on its own socket (`--listen-socket`, default `/run/nos/watchdog.sock`) by `watchdog::broker`. `ServiceRef::Config` always resolves to the watchdog's own `--config-socket` argument (tracked directly, not in the registry); `ServiceRef::RibTable(name)` resolves via `watchdog::registry::EndpointRegistry`, populated when `routing_tables::manage` spawns/stops each `nos-ribd --table <name>` instance with its own assigned socket path (`/run/nos/rib-<name>.sock`, passed to the child via `--listen-socket`, alongside `--watchdog-socket` so it can resolve `nos-configd` itself the same way). `nos-cli` and `nos-ribd` both resolve `nos-configd`'s address through this broker at startup instead of assuming the hardcoded default (`nos-cli` falls back to the conventional default and warns if the broker is unreachable, preserving its existing "startup never blocks" resilience; `nos-ribd` retries indefinitely, since it's an unattended daemon). `nos-bgpd` is still a placeholder with no config connection at all, so it isn't wired into this yet.

Each `nos-ribd` instance also gains a real IPC listener for route queries (`nos_proto::rib`: `RibRequest::GetRoutes` / `RibRequest::Lookup { addr }` → `RibEvent::Routes(Vec<PrefixRoutes>)` / `Match(PrefixRoutes)` / `NoMatch`), backing `nos-cli`'s `show route <table>` (whole table) and `show route <table> <address>` (longest-prefix-match) commands — resolved via the broker, then queried directly, with every candidate route per prefix shown ordered best-to-worst rather than only the winner, since `Rib` is multi-source.

## Development

```bash
make check   # build + fmt + clippy + test (matches CI's fast jobs)
make fix     # auto-fix formatting and clippy-fixable lints
make help    # list all available targets
```

Containerized test environment:

```bash
make docker-build                        # build the nos-watchdogd/nos-configd/nos-bgpd/nos-ribd/nos Docker image
docker compose up -d watchdog            # run the watchdog (which starts nos-configd + nos-bgpd + nos-ribd) in a container
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
