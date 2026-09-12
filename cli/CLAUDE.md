# nos-cli — Interactive Shell

The main user-facing entry point of NOS. A small REPL (binary name `nos`) built on `reedline`.

## What lives here vs nos-proto / nos-config

`nos-cli` depends only on `nos-proto` for wire types (`Config`, `Request`, `Event`, `IpcCodec`) — it does **not** depend on `nos-config` internals, matching the rule in the root `CLAUDE.md` that client components never depend on the config daemon directly. It dials the daemon's Unix socket the same way any future component client would.

## Modules

| Module | Role |
|--------|------|
| `main.rs` | Arg parsing (`--config-socket`), the reedline REPL loop, mode-aware prompt, dispatch of `session::Resolved` actions |
| `command.rs` | `Command::parse(&str) -> Command` — pure parsing, no I/O, no mode awareness |
| `session.rs` | `Mode` (`Operational` / `Configuration { transaction, path, dirty }`), `Path` (navigation position), and `resolve(&Mode, Command) -> Resolved` — the pure semantic layer mapping a command plus current mode to a concrete action |
| `client.rs` | One-shot IPC calls to `nos-configd`: `fetch_running_config`, `save_running_config`, `open_transaction`, `apply_op`, `get_transaction`, `commit_transaction`, `discard_transaction` |
| `format.rs` | `render_config`, `render_bgp_instance`, `render_transaction` — human-readable rendering (`Config`/`BgpInstance` only derive `Debug`, no `Display`) |

## Commands

| Command | Behavior |
|---------|----------|
| `show config` | Sends `Request::Get` to `nos-configd`, prints the returned running config (works in any mode) |
| `save` | Sends `Request::Save` to `nos-configd`; persists the running config to disk (operational mode only) |
| `configure <name> [from blank\|current]` | Enters configuration mode on a named transaction — creates it if new (default base: `current`), resumes it unchanged if it already exists |
| `edit bgp instance <name>` | Creates the instance in the transaction if missing, then navigates into it |
| `set asn <n>` / `set router-id <ip>` | Sets a field on the current BGP instance (only valid while navigated into one) |
| `set bgp instance <name> asn <n>\|router-id <ip>` | Fully-qualified form — works from the transaction root without navigating |
| `delete` / `delete bgp instance <name>` | Deletes the current instance (returns to the transaction root) or a named one |
| `up` / `top` | Navigates back to the transaction root |
| `show` (bare) | Shows the transaction, or just the current BGP instance if navigated into one |
| `commit` | Validates and commits the transaction, replacing the running config and returning to operational mode; on validation failure the transaction stays open for another attempt |
| `discard` / `abort` | Deletes the transaction without touching the running config |
| `help` | Lists available commands |
| `exit` / `quit` / `end` | Exits the shell (operational mode); in configuration mode, returns to operational mode — prompting for commit/discard/leave-open first if there are uncommitted changes |

Command matching is exact-token only (no case-folding or abbreviations).

## Mode and navigation

The shell tracks a local `Mode` (`session.rs`) — `Operational` or `Configuration { transaction, path, dirty }` — purely as client-side UI state; the daemon has no notion of "the current CLI session." `path` supports one level of nesting today (`Root` or `BgpInstance(name)`); the prompt reflects it (`nos>`, `nos(<txn>)>`, `nos(<txn>/bgp:<name>)>`). Since named transactions live entirely server-side, an abnormal exit (Ctrl-C, Ctrl-D, kill, dropped connection) never loses or discards one — only the explicit `discard`/`abort` command does, or choosing "discard" at the uncommitted-changes prompt on plain `exit`.

## Connection behavior

Each command dials the daemon fresh (`UnixStream::connect` → split → `FramedRead<Event>`/`FramedWrite<Request>` → one `Request` → single `Event` reply → connection dropped). No persistent connection is held across commands — the transaction name plus the CLI's local `Mode` are the only state carried between commands; revisit the one-shot style only if a `Subscribe`-based live command is added.

Default socket path is `/run/nos/config.sock`, overridable via `--config-socket <path>`.
