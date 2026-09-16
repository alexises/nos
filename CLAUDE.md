# NOS — Network Operating System

A network operating system built from scratch in Rust.

## Components

| Directory | Crate | Purpose |
|-----------|-------|---------|
| `proto/` | `nos-proto` | Shared wire types, IPC codec — single source of truth for all inter-process contracts |
| `tcp-auth/` | `nos-tcp-auth` | Raw Linux `setsockopt` bindings for TCP session authentication (`TCP_MD5SIG`, TCP-AO) — no NOS dependencies, like `nos-proto` |
| `rpl/` | `nos-rpl` | Routing Policy Language — compiler and VM for BGP import/export policy scripts, no NOS dependencies, like `nos-proto` |
| `config/` | `nos-config` | Configuration store and IPC server |
| `bgp/` | `nos-bgp` | BGP-4 implementation |
| `rib/` | `nos-rib` | Routing information base daemon — best-path selection per routing table, applied to the kernel via a Linux driver (VRF device + routes) |
| `interface/` | `nos-interface` | Interface reconciliation daemon — one process manages every configured interface, applying addresses and VRF enslavement to the kernel via a Linux driver |
| `log/` | `nos-log` | Log collection daemon (`nos-logd`) — a single process collects structured log entries pushed by every other daemon into a bounded, disk-backed buffer, queryable by `nos-cli` |
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

`nos-watchdog` (binary `nos-watchdogd`) starts and supervises the other component processes as OS child processes, and is the container's entrypoint. It always runs exactly one supervised `nos-configd`. For BGP, rather than a single static `nos-bgpd`, the watchdog subscribes to `nos-configd` over its own `--config-socket` connection (`Request::SubscribeDiff`, independent of whatever address is forwarded to the `nos-configd` child via the opaque `--configd-arg` pass-through) and dynamically spawns one `nos-bgpd --instance <name>` per `BgpInstance` in the live config. It reconciles on every diff it receives: a fresh connection's first diff is synthesized against an empty config (so every currently-configured instance shows up as `Added`) and is treated as the authoritative full membership list — anything already running that isn't in it gets stopped, closing the gap where an instance removed while disconnected could otherwise leak as an orphan process — while every later diff on the same connection is applied incrementally (`Added`/`Removed` only — `Modified` is a no-op at this level, since `nos-bgpd`, like `nos-ribd`, independently subscribes to config and re-resolves its own peers/VRF on every relevant diff rather than needing a restart). The config subscription itself reconnects on a fixed 1s delay with no backoff if dropped (distinct from the exponential process-crash backoff below) — since `nos-configd` is supervised independently, its own crash/restart is transparent to already-running `nos-bgpd` instances. Every supervised process (`nos-configd` and each per-instance `nos-bgpd`) is respawned after an exponential backoff on unexpected exit (starting at 1s, doubling, capped at 30s, resetting to 1s once it's stayed up for 60s). On SIGTERM or SIGINT to the watchdog, or an instance's removal from config, its process is sent SIGINT (the signal `nos-configd`/`nos-bgpd` handle via `tokio::signal::ctrl_c()`), given up to 10s to exit cleanly, then force-killed — on watchdog shutdown this happens for every remaining process before it exits, so nothing is left orphaned.

RIB tables follow the identical dynamic-spawn pattern: the watchdog subscribes to `DiffScope::RoutingTables` and spawns one `nos-ribd --table <name>` per `RoutingTable` in the live config, with the same first-diff-is-authoritative reconciliation, fixed 1s reconnect delay, and exponential per-process crash backoff as BGP instances. `Modified` is likewise a no-op at this level — a table's `bgp_instance`/`static_routing_instance` association changing doesn't restart its `nos-ribd`, since that process independently subscribes to config (`RoutingTables` and `StaticRoutingInstances`) and re-resolves its own associations on every relevant diff, rebuilding its in-memory RIB from a fresh `Request::Get` rather than losing state to a restart.

Interfaces are supervised differently: unlike `nos-bgpd`/`nos-ribd`, `nos-interfaced` is a single fixed process — the watchdog always runs exactly one, the same way it always runs exactly one `nos-configd` — rather than one instance per `Interface` in config. Every interface is an OS resource in the same network namespace, so there's no isolation benefit to a per-interface process, and a single process avoids spawn/teardown churn on every interface add/remove. `nos-interfaced` itself subscribes to `DiffScope::Interfaces` and reconciles every configured interface internally on each diff.

`nos-logd` is supervised the same way as `nos-interfaced` — one fixed process, spawned first among the watchdog's children so the window before it's reachable is as short as possible — since log collection has no per-config-object scope to spawn one instance per. It has no config subscription of its own at all: every other supervised process (`nos-configd`, each `nos-bgpd`/`nos-ribd` instance, `nos-interfaced`, and the watchdog itself) is simply handed `nos-logd`'s address directly via a constructed `--log-socket <path>` argument at spawn time — the same pattern already used for `--config-socket`, rather than a broker round trip, since (like `nos-configd`'s own address) it's needed unconditionally by every process from the moment it starts, not resolved lazily. See "Log collection" below.

`nos-config`'s IPC protocol supports this via `Request::SubscribeDiff { scopes }`: a subscriber names which `ConfigDiff` sections it cares about (`DiffScope::{Hostname,BgpInstances,RoutingTables,StaticRoutingInstances,Interfaces}`) and only receives `Event::Diff` for commits that touch a requested scope — commits outside every requested scope are never sent. This is a separate, additive path alongside the original `Request::Subscribe`/`Event::Config` (full snapshot on every commit, used by `nos-cli`'s live hostname prompt), which is unchanged. Both paths rely on a documented but easy-to-miss connection-lifecycle rule in `server.rs`: a subscriber (of either kind) is expected to send its request and then never write to the connection again — "the caller owns its lifetime" — so the server must not treat EOF/an error on the *request* side of a subscribed connection as reason to close the whole connection; it only stops reading further requests; the connection stays open to keep pushing events until the client is actually gone (detected when writing to it fails).

### Endpoint broker

Because the watchdog is the one process that actually spawns every other daemon, it also acts as the directory for "how do I reach daemon X" — a small broker protocol (`nos_proto::broker`: `WatchdogRequest::ResolveEndpoint { service: ServiceRef }` → `WatchdogEvent::Endpoint(PathBuf)` or `NotAvailable`), served on its own socket (`--listen-socket`, default `/run/nos/watchdog.sock`) by `watchdog::broker`. `ServiceRef::Config` always resolves to the watchdog's own `--config-socket` argument (tracked directly, not in the registry); `ServiceRef::RibTable(name)`/`ServiceRef::BgpInstance(name)` resolve via `watchdog::registry::EndpointRegistry`, populated when `routing_tables::manage`/`bgp_instances::manage` spawn/stop each `nos-ribd --table <name>`/`nos-bgpd --instance <name>` instance with its own assigned socket path (`/run/nos/rib-<name>.sock`/`/run/nos/bgp-<name>.sock`, passed to the child via `--listen-socket`, alongside `--watchdog-socket` so it can resolve `nos-configd` itself the same way). `ServiceRef::Interfaces`/`ServiceRef::Log` resolve the same way as `ServiceRef::Config` — directly from the watchdog's own `--interfaced-listen-socket`/`--log-socket` arguments, tracked, not in the registry, since there's exactly one `nos-interfaced` and one `nos-logd` instance rather than one per name. `nos-cli`, `nos-ribd`, `nos-interfaced`, and `nos-bgpd` all resolve `nos-configd`'s address through this broker at startup instead of assuming the hardcoded default (`nos-cli` falls back to the conventional default and warns if the broker is unreachable, preserving its existing "startup never blocks" resilience; `nos-ribd`/`nos-interfaced`/`nos-bgpd` retry indefinitely, since they're unattended daemons). `nos-bgpd` also resolves its own owning `nos-ribd` instance the same way (`ServiceRef::RibTable`, see below) to learn its VRF. `nos-logd`'s own address, unlike every other `ServiceRef`, is never resolved by another *daemon* through this broker — the watchdog hands it out directly via `--log-socket` at spawn time instead (see "Process supervision" above); only `nos-cli` resolves `ServiceRef::Log`/`ServiceRef::BgpInstance` through the broker, since it isn't itself spawned by the watchdog.

Each `nos-ribd` instance also gains a real IPC listener for route queries (`nos_proto::rib`: `RibRequest::GetRoutes` / `RibRequest::Lookup { addr }` → `RibEvent::Routes(Vec<PrefixRoutes>)` / `Match(PrefixRoutes)` / `NoMatch`), backing `nos-cli`'s `show route <table>` (whole table) and `show route <table> <address>` (longest-prefix-match) commands — resolved via the broker, then queried directly, with every candidate route per prefix shown ordered best-to-worst rather than only the winner, since `Rib` is multi-source.

`nos-interfaced` similarly gains a real IPC listener for interface queries (`nos_proto::interface`: `InterfaceRequest::GetInterfaces` / `GetInterface { name }` → `InterfaceEvent::Interfaces(Vec<InterfaceStatus>)` / `Interface(InterfaceStatus)` / `NotFound`), backing `nos-cli`'s `show interface` (every interface) and `show interface <name>` (one) commands.

Each `nos-bgpd` instance similarly gains a real IPC listener for session-summary queries (`nos_proto::bgp`: `BgpRequest::GetSummary` → `BgpEvent::Summary(Vec<PeerSummary>)`), backing `nos-cli`'s `show bgp brief` — a router-wide summary (no instance argument) that iterates every `BgpInstance` in the running config, resolves each one's `nos-bgpd` via `ServiceRef::BgpInstance(name)`, and queries each independently, printing a per-instance "not running" line rather than aborting when one instance's daemon isn't reachable. Each peer's summary reports its FSM state (`Idle`/`OpenSent`/`OpenConfirm`/`Established` — `Idle` is a reporting-only value meaning no connection attempt has an OPEN in flight yet, since `nos-bgp::fsm` itself only models the latter three), remote AS/BGP ID once negotiated, uptime since `Established`, and the negotiated hold-time/keepalive — sourced from a shared per-peer `nos_bgp::status::PeerStatus` (a `tokio::sync::watch` channel owned by `nos-bgp::collision::PeerSlot`, since a peer's active and passive connection attempts share one `PeerSlot` and only one becomes canonical) that `fsm::run` writes at the same transition points it already calls `PeerSlot::on_open`/`mark_established`.

### Linux drivers

Both `nos-ribd` and `nos-interfaced` apply their reconciled desired state to the real Linux network stack via `rtnetlink`, behind a swappable `Driver` trait per crate (`interface::driver::InterfaceDriver`, `rib::driver::RibDriver`) selected with `--driver linux|noop` (default `linux` on Linux, `noop` elsewhere — the `noop` driver is today's original log-only placeholder behavior, kept as a portability/test fallback). This is deliberately in-process rather than a separate privileged process, so a future non-Linux/hardware backend only needs a new `Driver` impl, not new IPC or supervision wiring. Both binaries run as the unprivileged `nos` user; the kernel access their Linux drivers need comes from `CAP_NET_ADMIN`/`CAP_NET_RAW` file capabilities baked onto the two binaries at image build time plus a matching `cap_add` on the `watchdog` container (see `Dockerfile`/`docker-compose.yml`).

`nos-ribd`'s Linux driver owns creating a Linux VRF device + kernel routing table for its `RoutingTable`, allocating a kernel table id on first use and persisting the name→id mapping to a local file (`--table-registry-path`, default `/var/lib/nos/linux-driver/table-ids.yaml`) purely so a crash/restart reuses the same id and VRF name — this file is never read by any other process. On shutdown (the same SIGINT used for both "watchdog is stopping" and "this table was removed from config") it deletes the kernel VRF and its routes, but never the registry entry, so an ordinary restart recreates the identically-named VRF.

Because `nos-interfaced` needs to enslave an interface into the VRF device that backs its configured `routing_table`, but has no way to derive that VRF's real Linux interface name on its own (it's allocated entirely inside `nos-ribd`'s driver), `nos-ribd`'s per-table socket gains one more request: `RibRequest::GetVrfName` → `RibEvent::VrfName(Option<String>)`. `nos-interfaced`'s Linux driver resolves the owning `nos-ribd` instance via the broker (`ServiceRef::RibTable(name)`) and queries it directly — **this is the first direct daemon-to-daemon IPC link in the system** (every other component only ever talks to `nos-configd` or the watchdog broker). A `None` answer (table not running yet, or running but hasn't created its VRF yet) is treated as an ordinary transient condition, not an error, and retried automatically by both daemons' periodic re-apply tick (in addition to their existing config-diff-triggered resync) — needed here specifically because "the other daemon became ready" isn't a config change either daemon would otherwise be notified of. The same live per-table socket is expected to be reused by a future feature having `nos-ribd` query `nos-interfaced`'s existing `GetInterfaces` to compute directly-connected routes from interface addresses — not yet implemented.

`nos-bgpd` resolves its VRF the same way: a `BgpInstance` carries a reflexive, read-only `routing_table` field (mirrored by `nos-config` from the owning `RoutingTable`'s `bgp_instance` reference on every commit — never independently editable, and never shown in `nos-cli`'s config rendering, since it exists purely for `nos-bgpd` to read over IPC), which it resolves to a VRF name via the same `ServiceRef::RibTable` + `GetVrfName` call `nos-interfaced` uses. A `BgpInstance` with no owning `RoutingTable` is treated as invalid operating state, not a "default VRF" fallback — `nos-bgpd` never opens a session for it, only logging an error and rechecking on every resync in case config is fixed. Once a VRF name is resolved, `nos-bgpd` opens raw, VRF-scoped TCP connectivity to its configured peers (both an active outbound connect per peer and a shared passive listener on port 179, scoped into the VRF via `SO_BINDTODEVICE` rather than `rtnetlink` since no interface/route is being programmed) — the foundation the BGP FSM (OPEN/KEEPALIVE message exchange) will be layered on top of later.

### Session authentication

A `BgpPeerGroup` carries an optional `auth` field (RFC 2385 TCP MD5, or RFC 5925 TCP-AO with key rotation — see `bgp/CLAUDE.md`'s "Session authentication" for the wire-level detail). Neither mechanism has a maintained Rust binding, so the raw `setsockopt(TCP_MD5SIG)`/`setsockopt(TCP_AO_*)` calls live in their own crate, `tcp-auth/` (`nos-tcp-auth`) — no NOS dependencies, like `nos-proto`, and the one crate in the workspace whose whole purpose is `unsafe` FFI (every other crate stays within the workspace's `unsafe_code = "warn"` default). Secrets are stored **clear-text** in config, like every other field — this system has no encryption-at-rest anywhere, and `nos-cli` renders them in the clear too.

### Routing policy language (RPL)

A `BgpPeerGroup`'s `import_policy`/`export_policy` (each an `Option<String>` naming a `PolicyDefinition`, `None` defaulting to `deny-all` — this NOS never leaves a direction unfiltered) reference a small imperative script language, `nos-rpl` (`rpl/`), compiled once by `nos-config` at commit time (rejecting an invalid script before it can be referenced) and again — cached — by each `nos-bgpd` instance that uses it (`bgp/src/policy.rs`'s `PolicyCache`). `nos-rpl` has no NOS-internal dependencies, like `nos-proto`/`nos-tcp-auth`: it exposes a plain `Input`/`BgpInput` shape a consumer adapts its own route type into (`bgp/src/rib.rs`'s `to_policy_input`), and a `Verdict` the consumer applies back onto its own route.

**Language**: Python-style significant indentation, one statement per line. A script is a flat list of statements — `if`/`elif`/`else` (an `if` with no `else`, or any branch not itself terminating, is an ordinary non-terminating statement, not a self-contained policy), `set this.<field> = <expr>` (numeric fields only — `local_pref`/`med`), `this.<field>.add(..)`/`.remove(..)`/`.clear()` (community-list fields only, see below), and the two terminals `accept`/`reject`. `check.rs`'s `check_termination` rejects at compile time any script where some path never reaches a terminal statement, or where a statement follows one that already terminated its block — a policy can never silently fall through.

**Fields** (`this.prefix`, `this.bgp.*`) are a fixed table in `schema.rs` (`FieldId`/`FieldType`/`FIELDS`), each either a plain scalar (`this.bgp.origin`, compared with `==`; `this.bgp.local_pref`, settable), an optional scalar unreadable directly until set (`this.bgp.med`), or a list (`this.bgp.as_path`, `this.bgp.cluster_list`, `this.bgp.communities`/`extended_communities`/`large_communities`) exposing only `.length` and `.contains(..)` for matching — never read as a whole value. `this.prefix in 10.0.0.0/8` and `this.bgp.as_path.contains(65010)` are the two prefix/as-path matching idioms; the three community fields extend the same `.contains(..)` idiom with `AA:NN` (standard, RFC 1997), `type:subtype:value` (extended, RFC 4360), and `ga:ld1:ld2` (large, RFC 8092) colon-separated literals — disambiguated by the target field's type, not the literal's own shape, and requiring no lexer support beyond the `:` token the block-syntax colon already uses (a colon literal's `Int` parts are only ever consumed by `parse_atom` when immediately followed by another `Int`, which a block-starting colon, always followed by a newline, never is). Community fields are the only list fields that are also mutable: `.add(65000:100)`/`.remove(65000:100)` add/remove one value, `.clear()` empties the list — real policy wants incremental edits, not whole-list literal replacement, so there's no list-value syntax at all.

**Execution model**: `codegen.rs` compiles the AST straight to bytecode (`vm::Op`) in one pass that doubles as type-checking — no separate type-check pass, since emission needs the same field-resolution work a type-checker would. `vm::run` executes against a fixed-size operand stack (`MAX_STACK_DEPTH`, compile-time-bounded, no heap allocation on the hot path — this runs once per route, per peer, per update) plus a handful of mutable locals seeded from the input and threaded through execution exactly like ordinary variables (`this.bgp.local_pref` read after a `set` sees the new value in the same pass) — `cur_local_pref`/`cur_med` for the two settable scalars, and `cur_communities`/`cur_extended_communities`/`cur_large_communities` (each a `Cow` over the input's borrowed slice — the one deliberate exception to "no heap allocation," since a script that actually calls `.add`/`.remove`/`.clear` needs to hand back an owned list through `Verdict::Accept`, but `Cow::to_mut()` only clones on that first actual write, and a `Reject` verdict never pays for it at all). `Verdict::Accept` always carries the current value of every mutable field, whether or not the script touched it — same guarantee for the three community lists as for `local_pref`/`med`.

**Built-in system policies**: `ACCEPT_ALL`/`DENY_ALL` (`accept-all`/`deny-all`) are compiled once (`LazyLock`) from `"accept\n"`/`"reject\n"` rather than stored as `PolicyDefinition` config entries — nothing to edit, nothing to delete, and every peer-group's unset `import_policy`/`export_policy` resolves to `deny-all`.

**Explicitly out of scope (v1)**: named/reusable community-list or as-path-list objects (matching is always against an inline literal, the same as prefix/as-path matching today); any capability beyond `bgp` (e.g. a future `this.static.*` for a different attach point) — `nos-rpl`'s two attach points (BGP import/export) both guarantee the exact same `Input` shape today, so there's no per-attach-point capability variation to model yet.

### Log collection

Every daemon (`nos-configd`, each `nos-bgpd`/`nos-ribd` instance, `nos-interfaced`, `nos-watchdogd`) already logs via `tracing`; `nos-log` adds a second `tracing_subscriber::Layer` (`log_client::ForwardingLayer`, reimplemented per-crate like `config_client.rs`/`watchdog_client.rs` rather than shared, per the star dependency graph) alongside each process's existing `fmt` layer, so stdout/`docker logs` output is unaffected. The layer converts every `tracing::Event` into a `nos_proto::log::LogEntry` (timestamp, level, source identity, target, message, structured fields), pushes it onto a small bounded channel (dropping the oldest on backpressure — logging must never block the caller), and a background task drains that channel into one long-lived `LogRequest::Push` connection to `nos-logd`, reconnecting on a fixed 1s delay like every other reconnect loop in this codebase.

`nos-logd` holds an in-memory, bounded ring buffer (`--capacity`, default 10,000 entries) behind `log::store::LogStore`, persisted to `--log-store-path` (default `/var/lib/nos/log/entries.jsonl`, one JSON line per entry, compacted back down to `--capacity` lines once the file grows past twice that) so recent history survives a restart — the one daemon in this system with disk-backed state purely for its own sake, rather than for cross-restart identity like `nos-ribd`'s table registry. `nos_proto::log`'s `LogRequest`/`LogEvent` serve three request shapes on one socket (`--listen-socket`, default `/run/nos/log.sock`): `Push` (fire-and-forget, no reply, from every other daemon), `GetLogs { source, limit }` (`nos-cli`'s one-shot `show log [<source>]`), and `Tail { source }` (`nos-cli`'s `show log --follow`, replying once with the current buffer before streaming further `Line`s from a `tokio::sync::broadcast` channel until the client disconnects).

## Development

```bash
make check   # build + fmt + clippy + test (matches CI's fast jobs)
make fix     # auto-fix formatting and clippy-fixable lints
make help    # list all available targets
```

Containerized test environment:

```bash
make docker-build                        # build the nos-watchdogd/nos-configd/nos-bgpd/nos-ribd/nos-interfaced/nos-logd/nos Docker image
docker compose up -d watchdog            # run the watchdog (which starts nos-configd + nos-bgpd + nos-ribd + nos-interfaced + nos-logd) in a container
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

### Two-router BGP verification

`tools/verify-bgp.sh` stands up two independent `nos-watchdogd` containers on a shared docker network, configures each as a full BGP router peering the other, and checks the logs for a real OPEN/KEEPALIVE handshake reaching `Established`, a hold-timer/reconnect cycle after a peer vanishes, (best-effort, timing-dependent) an RFC 4271 §6.8 collision-resolution event, (`redistribute`) a static route configured on one router actually being redistributed into BGP, advertised over a real UPDATE message, and learned into the other router's Adj-RIB-In/Loc-RIB, (`auth`) that a matching RFC 2385 TCP MD5 password configured on both routers' peer-groups still establishes while a mismatched password on either side does not (verified against the real kernel's `TCP_MD5SIG` enforcement, not simulated), (`policy`) that a real RPL import policy on one router actually rejects a specific redistributed prefix and that reverting to `accept-all` lets it back in, (`communities`) that a real RPL export policy's `.add(..)` tags a redistributed prefix with an RFC 1997 `COMMUNITY` value that survives wire encoding/decoding into the other router's Loc-RIB, and (`reflector`/`route-server`) that a third container in a hub-and-spoke topology actually exercises RFC 4456 route reflection / RFC 7947 route-server transparency over real sessions:

```bash
tools/verify-bgp.sh up            # build image + provisioning tool, start both routers, configure them as peers
tools/verify-bgp.sh established   # wait for both sides to log "bgp session established"
tools/verify-bgp.sh reconnect     # kill one side's nos-bgpd, confirm the other detects it and both re-establish
tools/verify-bgp.sh collision     # restart both nos-bgpd processes at once, check for/report a collision event
tools/verify-bgp.sh redistribute  # configure a static route + "redistribute from static to bgp" on router-a, confirm router-b learns and installs it
tools/verify-bgp.sh auth          # configure a matching md5-password on both routers (still establishes), then a mismatched one (does not)
tools/verify-bgp.sh policy        # configure a real RPL import policy on router-b rejecting the redistributed prefix, then revert to accept-all
tools/verify-bgp.sh communities   # configure a real RPL export policy on router-a tagging the redistributed prefix with a community, confirm router-b learns it
tools/verify-bgp.sh reflector     # stand up a third router, verify RFC 4456 route reflection over real sessions
tools/verify-bgp.sh route-server  # stand up a third router, verify RFC 7947 route-server transparency over real sessions
tools/verify-bgp.sh logs [n]      # tail both (or all three) containers' logs
tools/verify-bgp.sh down          # tear down containers, volumes, and the network
tools/verify-bgp.sh all           # up + established + reconnect + collision + redistribute + auth + policy + communities + reflector + route-server, in sequence
```

`nos-cli`'s interactive shell (reedline) can't be scripted over a plain pipe — piped stdin fails with `readline error: No such device or address` — so provisioning goes through `tools/nos-provision`, a small standalone binary that speaks `nos-configd`'s IPC protocol directly (`OpenTransaction`/`ApplyOp`/`CommitTransaction`) using `nos-proto`'s own types, rather than through the shell. It's a workspace member but not meant to be run outside this script; `verify-bgp.sh` builds it via the same `rust:1-slim-bookworm` image the Dockerfile's builder stage uses, into a separate `target/docker-verify/` directory, so its binary's glibc version matches the `debian:bookworm-slim` runtime containers regardless of what the host toolchain would otherwise produce.

<!-- rtk-instructions v2 -->
# Command output

Command output here is condensed to save tokens, keeping every signal and
dropping costly noise. Treat it as the complete result: run commands
normally, and batch related commands into one call to avoid extra turns.
Truncated results state their recovery path in their own output. Re-run a
command as `rtk proxy <cmd>` only when its result is unusable: empty when
output was clearly expected, contradicting its exit code, or garbled.
<!-- /rtk-instructions -->