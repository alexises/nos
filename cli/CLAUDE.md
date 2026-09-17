# nos-cli — Interactive Shell

The main user-facing entry point of NOS. A small REPL (binary name `nos`) built on `reedline`.

## What lives here vs nos-proto / nos-config

`nos-cli` depends only on `nos-proto` for wire types (`Config`, `Request`, `Event`, `IpcCodec`, `CommandDoc`, `Topic`, `ServiceRef`, `WatchdogRequest`/`WatchdogEvent`, `RibRequest`/`RibEvent`, `InterfaceRequest`/`InterfaceEvent`, `LogRequest`/`LogEvent`, `BgpRequest`/`BgpEvent`) — it does **not** depend on `nos-config` internals, matching the rule in the root `CLAUDE.md` that client components never depend on the config daemon directly. It dials each daemon's Unix socket the same way any future component client would.

## Modules

| Module | Role |
|--------|------|
| `main.rs` | Arg parsing (`--watchdog-socket`), resolves `nos-configd`'s address via the watchdog broker at startup (falling back to the conventional default and warning if unreachable), the reedline REPL loop (completer + menus + keybindings), mode-aware prompt, `DocCache`/`doc_for`/`doc_for_blocking`, dispatch of `session::Resolved` actions |
| `command.rs` | `Command::parse(&str) -> Command` — pure parsing, no I/O, no mode awareness |
| `session.rs` | `Mode` (`Operational` / `Configuration { transaction, path, dirty }`), `Path` (navigation position), and `resolve(&Mode, Command) -> Resolved` — the pure semantic layer mapping a command plus current mode to a concrete action |
| `spec.rs` | `COMMAND_SPECS` — the CLI's own grammar table (token syntax + which `Mode`/`Path` each command is valid in). Owns *syntax* only; see "Help, `?`, and Tab-completion" for where the descriptive text comes from |
| `completer.rs` | `NosCompleter` — a `reedline::Completer` driven by `spec::COMMAND_SPECS`, shared by Tab-completion and the live `?` key |
| `help_menu.rs` | `HelpMenu` — the `reedline::Menu` backing the live `?` key (brief vs. detailed views) |
| `client.rs` | One-shot IPC calls to `nos-configd`: `fetch_running_config`, `save_running_config`, `open_transaction`, `apply_op`, `get_transaction`, `commit_transaction`, `discard_transaction`, `diff_transaction`, `describe` — plus `subscribe`, the one long-lived exception (see "Connection behavior") |
| `watchdog_client.rs` | `resolve(watchdog_socket, service) -> Result<Option<PathBuf>, _>` — one-shot `WatchdogRequest::ResolveEndpoint` call against `nos-watchdogd`'s broker socket; `Ok(None)` means the broker is reachable but reports the service unavailable |
| `rib_client.rs` | One-shot IPC calls to a resolved `nos-ribd` instance: `get_routes` (`RibRequest::GetRoutes`), `lookup` (`RibRequest::Lookup`) |
| `interface_client.rs` | One-shot IPC calls to the resolved `nos-interfaced` instance: `get_interfaces` (`InterfaceRequest::GetInterfaces`), `get_interface` (`InterfaceRequest::GetInterface`) |
| `log_client.rs` | IPC calls to the resolved `nos-logd` instance: `get_logs` (one-shot `LogRequest::GetLogs`) and `tail` (long-lived, like `client::subscribe` — sends `LogRequest::Tail` and returns the reader for the caller to loop on) |
| `bgp_client.rs` | One-shot IPC call to a resolved `nos-bgpd` instance: `get_summary` (`BgpRequest::GetSummary`) |
| `format.rs` | `render_config`, `render_bgp_instance`, `render_routing_table`, `render_static_routing_instance`, `render_interface`, `render_transaction`, `render_diff`, `render_prefix_routes`, `render_interface_statuses`, `render_log_entries`/`render_log_entry`, `render_bgp_summary` — human-readable rendering (`Config`/`BgpInstance` only derive `Debug`, no `Display`). `render_diff` is also the one place that emits ANSI color/highlight codes, hand-rolled rather than via a color crate. `render_log_entry` is the one place `chrono` is used, to format `LogEntry.timestamp_ms` as RFC 3339 |

## Commands

| Command | Behavior |
|---------|----------|
| `show config` | Sends `Request::Get` to `nos-configd`, prints the returned running config (works in any mode) |
| `show route <table>` | Resolves `<table>`'s `nos-ribd` instance via the watchdog broker, then `RibRequest::GetRoutes` — every prefix, every candidate route ordered best to worst (works in any mode) |
| `show route <table> <address>` | Same resolution, then `RibRequest::Lookup { addr }` — a longest-prefix-match lookup, printing every candidate for the matched prefix ordered best to worst, or "no route matches" (works in any mode) |
| `save` | Sends `Request::Save` to `nos-configd`; persists the running config to disk (operational mode only) |
| `configure <name> [from blank\|current]` | Enters configuration mode on a named transaction — creates it if new (default base: `current`), resumes it unchanged if it already exists |
| `edit bgp instance <name>` | Creates the instance in the transaction if missing, then navigates into it |
| `set asn <n>` / `set router-id <router-id>` | Sets a field on the current BGP instance (only valid while navigated into one) |
| `set bgp instance <name> asn <n>\|router-id <router-id>` | Fully-qualified form — works from the transaction root without navigating |
| `set hostname <name>` | Sets the top-level `hostname` field — works from anywhere in configuration mode, since hostname has no navigation context |
| `delete` / `delete bgp instance <name>` | Deletes the current instance (returns to the transaction root) or a named one |
| `edit routing-table <name>` | Creates the routing table in the transaction if missing, then navigates into it |
| `set bgp-instance <instance>` / `set routing-table <name> bgp-instance <instance>` | Associates a BGP instance with a routing table (relative / fully-qualified) |
| `set static-routing-instance <instance>` / `set routing-table <name> static-routing-instance <instance>` | Associates a static routing instance with a routing table (relative / fully-qualified) |
| `delete` / `delete routing-table <name>` | Deletes the current routing table (returns to the transaction root) or a named one |
| `edit static-routing-instance <name>` | Creates the static routing instance in the transaction if missing, then navigates into it |
| `set route <subnet> gateway <address>` / `set static-routing-instance <name> route <subnet> gateway <address>` | Adds or repoints a static route (relative / fully-qualified) |
| `delete route <subnet>` / `delete static-routing-instance <name> route <subnet>` | Removes a static route (relative / fully-qualified) |
| `delete` / `delete static-routing-instance <name>` | Deletes the current static routing instance (returns to the transaction root) or a named one |
| `show interface` | Resolves `nos-interfaced`'s single instance via the watchdog broker, then `InterfaceRequest::GetInterfaces` — every interface's reconciled addresses and routing-table assignment (works in any mode) |
| `show interface <name>` | Same resolution, then `InterfaceRequest::GetInterface { name }`, or "not found" if unconfigured (works in any mode) |
| `show log [<source>]` | Resolves `nos-logd`'s single instance via the watchdog broker, then `LogRequest::GetLogs` — the current buffer, optionally filtered to entries whose source exactly matches `<source>` (works in any mode) |
| `show log [<source>] --follow` | Same resolution, then `LogRequest::Tail` — prints the current buffer, then streams new matching entries live until Ctrl-C or the connection is lost (works in any mode) |
| `show bgp brief` | Fetches the running config for the list of `BgpInstance`s, resolves each one's `nos-bgpd` via the watchdog broker, then `BgpRequest::GetSummary` — each peer's FSM state, remote AS, uptime, and negotiated hold-time; an instance whose `nos-bgpd` isn't running is reported individually rather than aborting the command (works in any mode) |
| `edit interface <name>` | Creates the interface in the transaction if missing, then navigates into it |
| `set address <cidr>` / `set interface <name> address <cidr>` | Adds an IP address to the interface's address list (relative / fully-qualified) |
| `delete address <cidr>` / `delete interface <name> address <cidr>` | Removes an IP address from the interface's address list (relative / fully-qualified) |
| `set routing-table <table>` / `set interface <name> routing-table <table>` | Associates a routing table (VRF) with an interface (relative / fully-qualified) |
| `delete routing-table` / `delete interface <name> routing-table` | Clears an interface's routing-table association (relative / fully-qualified) |
| `set switching-profile <profile>` / `set interface <name> switching-profile <profile>` | Associates a switching profile with an interface, trunking it into one or more broadcast domains (relative / fully-qualified) |
| `delete switching-profile` / `delete interface <name> switching-profile` | Clears an interface's switching-profile association (relative / fully-qualified) |
| `delete` / `delete interface <name>` | Deletes the current interface (returns to the transaction root) or a named one |
| `edit community-alias <name>` | Creates the community-alias in the transaction if missing, then navigates into it |
| `set value <literal>` / `set community-alias <name> value <literal>` | Sets the alias's community literal (relative / fully-qualified) |
| `delete` / `delete community-alias <name>` | Deletes the current community-alias (returns to the transaction root) or a named one |
| `edit community-group <name>` | Creates the community-group in the transaction if missing, then navigates into it |
| `set member <alias-or-literal>` / `set community-group <name> member <alias-or-literal>` | Adds a member (an existing community-alias's name, or an inline literal) to the group (relative / fully-qualified) |
| `delete member <m>` / `delete community-group <name> member <m>` | Removes a member from the group (relative / fully-qualified) |
| `delete` / `delete community-group <name>` | Deletes the current community-group (returns to the transaction root) or a named one |
| `edit prefix-list <name>` | Creates the prefix-list in the transaction if missing, then navigates into it |
| `set entry <cidr> [range <min> <max>]` / `set prefix-list <name> entry <cidr> [range <min> <max>]` | Adds an entry (exact-match, or a length range narrowing `<cidr>`) to the list (relative / fully-qualified) |
| `delete entry <cidr> [range <min> <max>]` / `delete prefix-list <name> entry <cidr> [range <min> <max>]` | Removes an entry from the list (relative / fully-qualified) |
| `delete` / `delete prefix-list <name>` | Deletes the current prefix-list (returns to the transaction root) or a named one |
| `up` / `top` | Navigates back to the transaction root |
| `show this` | Shows the transaction, or just the current BGP instance/routing table/static routing instance if navigated into one |
| `diff` | Shows what the transaction changes relative to the running config — colored `+`/`-` lines, word-level highlighting of the changed portion of a value, and an unstyled section header shown as context wherever a field inside it changed |
| `commit` | Validates and commits the transaction, replacing the running config and returning to operational mode; on validation failure the transaction stays open for another attempt |
| `discard` / `abort` | Deletes the transaction without touching the running config |
| `help` | Lists available commands |
| `exit` / `quit` / `end` | Exits the shell (operational mode); in configuration mode, returns to operational mode — prompting for commit/discard/leave-open first if there are uncommitted changes |

Command matching is exact-token only (no case-folding or abbreviations).

## Help, `?`, and Tab-completion

`help` (typed + Enter), the live `?` key, and Tab-completion are all driven by the one grammar table in `spec.rs` (`COMMAND_SPECS`), filtered to the current `Mode`/`Path` via `spec::availability_matches` — so all three always agree on what's valid to type next, and none of them ever show a configuration-only command outside a transaction (or vice versa).

`spec.rs` only owns **syntax** (token order, e.g. `"set bgp instance <name> asn <n>"`) and **availability**. The *semantic* explanation of what a command does — `summary`/`detail` text — is **not** duplicated here: for any command backed by a real `nos-config` operation, `spec::Doc::FromConfig(topic)` points at a `nos_proto::docs::Topic`, resolved at display time via `Request::Describe { topic }` / `Event::Description(CommandDoc)`. This is deliberate — `nos-cli` won't be the only client talking to `nos-config`, so the explanation of what e.g. `SetAsn` does belongs with the daemon, not copied into each client. Only the handful of purely local shell mechanics with no server-side meaning (`help`, `exit`/`quit`/`end`, `up`, `top`) carry their text directly as `spec::Doc::Local`.

Each topic is fetched **at most once per session, lazily** — only when something actually needs to display it — and cached in `main.rs`'s `DocCache` (`Arc<Mutex<HashMap<Topic, CommandDoc>>>`, starts empty; there is deliberately no bulk fetch at startup). `doc_for` (async, used by `print_help`) and `doc_for_blocking` (used by `NosCompleter`/`HelpMenu`, which run inside reedline's synchronous callbacks) are both cache-first, falling back to a placeholder string if `nos-configd` is unreachable rather than failing the whole shell.

- **Tab** opens/cycles `completion_menu` (a stock `reedline::ColumnarMenu`) backed by `NosCompleter` (`completer.rs`), which completes both literal keywords and, for an `edit`/`set`/`delete bgp instance <Tab>` slot, live BGP instance names fetched from the current transaction (`client::get_transaction`, blocking via `tokio::task::block_in_place` since `Completer::complete` is synchronous).
- **`?`** is a live keystroke, not a submitted command — it's bound (alongside Tab) in `main.rs`'s `keybindings()`, on top of `default_emacs_keybindings()`. The first press activates `nos_help` (a custom `Menu` impl, `help_menu.rs`) showing each candidate's `usage` + one-line summary; a second consecutive press switches the same menu to a fuller `usage` + detail view, both sourced from the one already-cached `CommandDoc` (a `?` never issues a second fetch just to go from brief to detailed). This exploits `reedline`'s own event semantics: `ReedlineEvent::Menu(name)` only fires when no menu is active, so `UntilFound([Menu("nos_help"), MenuPageNext])` routes a repeat press to `MenuPageNext`, which `HelpMenu` interprets as "show more detail" rather than literal pagination.
- `HelpMenu` is read-only — `can_quick_complete`/`can_partially_complete` are `false` and `replace_in_buffer` is a no-op, so it never edits the typed line. Pressing Enter while it (or the Tab menu) is active dismisses the menu without submitting, matching `reedline`'s standard menu-Enter behavior; a second Enter submits normally.

## Mode and navigation

The shell tracks a local `Mode` (`session.rs`) — `Operational` or `Configuration { transaction, path, dirty }` — purely as client-side UI state; the daemon has no notion of "the current CLI session." `path` supports one level of nesting (`Root`, `BgpInstance(name)`, `BgpPeerGroup{..}`, `RoutingTable(name)`, `StaticRoutingInstance(name)`, `Interface(name)`, `CommunityAlias(name)`, `CommunityGroup(name)`, or `PrefixList(name)` — all but `BgpInstance`/`BgpPeerGroup` have no navigable child, since a routing table's associations, a static routing instance's routes, an interface's addresses/routing-table, a community-alias's value, a community-group's members, and a prefix-list's entries are all edited without a further navigation step); the prompt reflects it (`<hostname>>`, `<hostname>(<txn>)>`, `<hostname>(<txn>/bgp:<name>)>`, `<hostname>(<txn>/routing-table:<name>)>`, `<hostname>(<txn>/static-routing-instance:<name>)>`, `<hostname>(<txn>/interface:<name>)>`, `<hostname>(<txn>/community-alias:<name>)>`, `<hostname>(<txn>/community-group:<name>)>`, `<hostname>(<txn>/prefix-list:<name>)>`), where `<hostname>` is the config's live `hostname` field (see "Connection behavior"), not a fixed literal. Since named transactions live entirely server-side, an abnormal exit (Ctrl-C, Ctrl-D, kill, dropped connection) never loses or discards one — only the explicit `discard`/`abort` command does, or choosing "discard" at the uncommitted-changes prompt on plain `exit`.

## Connection behavior

Each command dials the daemon fresh (`UnixStream::connect` → split → `FramedRead<Event>`/`FramedWrite<Request>` → one `Request` → single `Event` reply → connection dropped). No persistent connection is held across commands — the transaction name plus the CLI's local `Mode` are the only state carried between commands.

**Two deliberate exceptions.** `show log --follow` opens a long-lived `LogRequest::Tail` connection too, but unlike the hostname subscription below it's the foreground action of that one command — `show_log` loops on it directly (via `tokio::select!` against `tokio::signal::ctrl_c()`) until the user interrupts it or the connection breaks, then returns control to the REPL; it isn't a background task and isn't reconnected on drop.

The other exception: at shell startup, `main.rs` spawns a background task (`subscribe_hostname_task`) that opens exactly one long-lived `Request::Subscribe` connection (via `client::subscribe`) purely to keep the prompt's hostname live. It loops on `Event::Config` for the shell's whole lifetime, updates a shared `Arc<Mutex<String>>`, and — only when the value actually changes — triggers an in-place prompt repaint via `reedline::Reedline::repaint_signal()`'s handle, so the prompt updates even while the shell is sitting idle with no keystroke. `RepaintSignal` itself isn't reachable outside the `reedline` crate in this version (its type lives in a private module despite the constructor method being public), so the handle is captured in a `move || ...` closure rather than named directly. On disconnect or error the task retries after a fixed 1s delay — no backoff — since it's the shell's only long-lived connection and a daemon restart shouldn't permanently freeze the prompt. The initial hostname is still seeded from a one-shot `fetch_running_config` at startup, and shell startup never blocks or fails if the daemon is briefly unreachable. Every other command still dials one-shot as before.

`nos-configd`'s address is no longer a fixed default: it's resolved once at startup via `nos-watchdogd`'s broker socket (`--watchdog-socket <path>`, default `/run/nos/watchdog.sock`) and reused for the whole session. If the broker is unreachable or reports `nos-configd` unavailable, the shell warns and falls back to the conventional `/run/nos/config.sock` rather than failing startup. `show route`'s `nos-ribd` resolution and `show interface`'s `nos-interfaced` resolution both happen fresh per command instead — routing-table instances come and go during a session, and while there's only ever one `nos-interfaced`, dialing fresh keeps the same resolve-then-query shape as `show route`.
