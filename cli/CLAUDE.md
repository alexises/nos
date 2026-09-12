# nos-cli — Interactive Shell

The main user-facing entry point of NOS. A small REPL (binary name `nos`) built on `reedline`.

## What lives here vs nos-proto / nos-config

`nos-cli` depends only on `nos-proto` for wire types (`Config`, `Request`, `Event`, `IpcCodec`) — it does **not** depend on `nos-config` internals, matching the rule in the root `CLAUDE.md` that client components never depend on the config daemon directly. It dials the daemon's Unix socket the same way any future component client would.

## Modules

| Module | Role |
|--------|------|
| `main.rs` | Arg parsing (`--config-socket`), the reedline REPL loop, command dispatch |
| `command.rs` | `Command::parse(&str) -> Command` — pure parsing, no I/O |
| `client.rs` | `fetch_running_config(&Path) -> Result<Config, ClientError>`, `save_running_config(&Path) -> Result<(), ClientError>` — one-shot IPC calls to `nos-configd` |
| `format.rs` | `render_config(&Config) -> String` — human-readable rendering (`Config`/`BgpInstance` only derive `Debug`, no `Display`) |

## Commands

| Command | Behavior |
|---------|----------|
| `show config` | Sends `Request::Get` to `nos-configd`, prints the returned config |
| `save` | Sends `Request::Save` to `nos-configd`; persists the running config to disk |
| `help` | Lists available commands |
| `exit` / `quit` | Exits the shell |

Not yet implemented: `configure`, `set`, `delete`, `commit`, or any other command that edits the candidate config. Command matching is exact-token only (no case-folding or abbreviations) for now.

## Connection behavior

Each command dials the daemon fresh (`UnixStream::connect` → split → `FramedRead<Event>`/`FramedWrite<Request>` → one `Request` → single `Event` reply → connection dropped). No persistent connection is held across commands — revisit only if a `Subscribe`-based live command is added.

Default socket path is `/run/nos/config.sock`, overridable via `--config-socket <path>`.
