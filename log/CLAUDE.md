# nos-log — Log Collection Daemon

Collects structured log entries pushed by every other component process into a bounded, disk-backed buffer, queryable by `nos-cli` (binary `nos-logd`, a single fixed process — supervised the same way as `nos-interfaced`, since log collection has no per-config-object scope to spawn one instance per).

## Scope

Every other daemon forwards its own `tracing` events here over one long-lived `LogRequest::Push` connection (see `log_client.rs` in each of `bgp/`, `config/`, `rib/`, `interface/`, `watchdog/` — reimplemented per crate rather than shared, per the root `CLAUDE.md`'s star dependency graph, exactly like each crate's own `config_client.rs`/`watchdog_client.rs`). `nos-logd` itself never forwards its own logs anywhere — it's the foundation, and logs to stdout only via a plain `tracing_subscriber::fmt::init()`.

The buffer is bounded (`--capacity`, default 10,000 entries, oldest evicted first) and mirrored to disk (`--log-store-path`, default `/var/lib/nos/log/entries.jsonl`) so recent history survives a restart — the one daemon in this system with disk-backed state purely for its own sake, rather than for cross-restart identity like `nos-ribd`'s table registry.

There is an external query API: `server.rs` serves `nos_proto::log::{LogRequest, LogEvent}` for `nos-cli`'s `show log`/`show log --follow` commands (see root `CLAUDE.md`'s "Endpoint broker" section for how `nos-cli` finds this instance's socket — `ServiceRef::Log`, resolved directly by the watchdog like `ServiceRef::Config`/`Interfaces`, since there's exactly one instance). Every other daemon, by contrast, is handed this socket directly via `--log-socket` at spawn time rather than resolving it through the broker — see root `CLAUDE.md`'s "Process supervision" section.

## Modules

| Module | Role |
|--------|------|
| `main.rs` | Arg parsing (`--listen-socket` default `/run/nos/log.sock`, `--log-store-path`, `--capacity`), loads persisted entries to seed the buffer, SIGINT+SIGTERM shutdown wait, spawns `persistence::run` and `server::start` sharing one `LogStore` |
| `store.rs` | `LogStore` — cheap-`Clone` handle (like `nos-config`'s `ConfigStore`) over a bounded `VecDeque<LogEntry>`, a `tokio::sync::broadcast::Sender` for live `Tail` subscribers, and the channel feeding the persistence task. `record` (append + evict + broadcast + forward to disk), `snapshot` (filtered, capped read), `subscribe` (a fresh broadcast receiver) |
| `persistence.rs` | `load_recent` (seeds the buffer at startup, oldest-first, tolerating a missing or partially-malformed file) and `run` (the background task appending one JSON line per entry, compacting back down to `--capacity` lines via the same temp-file-then-rename atomic pattern as `nos-config`'s `persistence::save_to_disk` once the file grows past twice that) |
| `server.rs` | Binds `--listen-socket` and serves `LogRequest::Push` (records, no reply — the connection a forwarding daemon holds open for its whole lifetime), `GetLogs` (one-shot filtered/capped snapshot), and `Tail` (one initial snapshot reply, then streams new matching entries from the store's broadcast channel until the client disconnects) |

## Wire protocol

`nos_proto::log`'s `LogRequest`/`LogEvent` share one socket for three shapes, distinguished by request variant rather than three separate listeners: `Push(LogEntry)` (fire-and-forget, from every other daemon), `GetLogs { source, limit }` and `Tail { source }` (`nos-cli`'s snapshot and live-tail queries respectively). See `proto/CLAUDE.md`'s `log` entry for the exact types.
