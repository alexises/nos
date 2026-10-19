# Config protocol and transactions

Contributor-facing; moved from the root `CLAUDE.md` (#260). Operator view: [docs/README.md](../README.md).


```
Client → Server:
  Request::Get                 one-shot read of the current running config
  Request::Subscribe           receive current snapshot + all future commits
  Request::Unsubscribe         stop receiving updates (connection stays open)
  Request::Save                persist the current running config to disk
  Request::OpenTransaction     open (or resume) a named transaction from blank/current
  Request::ApplyOp             apply one edit (e.g. a BgpInstanceOp) to a named transaction
  Request::GetTransaction      one-shot read of a named transaction's in-progress config
  Request::CommitTransaction   validate, promote to running, broadcast, and delete the transaction (if_match: optional generation precondition, RFC 9110 §13.1.1)
  Request::DiscardTransaction  delete a named transaction without touching running config (if_match as above)
  Request::Describe            one-shot fetch of one operation's documentation, by Topic
  Request::SetTransactionPath  set/remove one subsection of a named transaction by URL-style path (whole config for an empty path) — see nos_proto::config_path (if_match as above)

Server → Client:
  Event::Config(Config)             config snapshot (initial + on every commit, incl. via a transaction commit)
  Event::Error(String)              error from the daemon
  Event::Saved                      confirms the running config was persisted (reply to Save)
  Event::Transaction(Snapshot)      a named transaction's current state (reply to Open/Apply/Get/SetTransactionPath), incl. its generation (0 at open, +1 per edit — nos-restd's ETag)
  Event::Committed                  confirms a transaction was committed
  Event::Discarded                  confirms a transaction was discarded
  Event::Description(CommandDoc)    one operation's documentation (reply to Describe)
```

`Describe`/`Description` exist so that the shell's help text (what a command does, in human terms, for the CLI's user) is authored once in `nos-config` and shared by every client, rather than duplicated per-client. A `Topic` is one config-tree node or field — named by the mandatory `#[cli(topic = …)]` on every schema field (`nos-proto-derive`, see [Schema reference](../schema-reference.md)), so a field can't exist without its CLI help — or one show/shell command (`nos-cli`'s `spec.rs` rows). `nos-cli`'s config commands (`edit`/`set`/`delete`), their help, `?`, Tab and usage are all generated from that schema tree (`cli/src/config_grammar.rs`, #109) and sent as `SetTransactionPath`, the same generic write REST uses. The schema's `///` comments are the REST API's (Swagger) text, deliberately separate. It's scoped to a single `Topic` per request (not a bulk catalog fetch) so a client only ever fetches the docs it actually displays.

### Named transactions

Editing the config happens inside a **named transaction**, held server-side in `nos-config`, not tied to any one connection. `OpenTransaction` creates it from a blank config or a clone of the running config (`TransactionBase::Blank`/`Current`), or — if a transaction with that name already exists — resumes its current in-progress state unchanged. `CommitTransaction` validates the transaction and, if valid, atomically replaces the running config and broadcasts it to every `Subscribe`d connection (the same fan-out `Get`/`Subscribe` already use); on invalid input the transaction is left alive so the caller can keep editing. `DiscardTransaction` deletes it outright. Because transactions live only in the daemon and are addressed by name, a client can disconnect (crash, Ctrl-C, network drop) and resume the same transaction later from a fresh connection — see `nos-cli`'s `configure <name>` command.

### Persistence

- `save_to_disk` writes a temp file, fsyncs it, renames it over `config.yaml`, then fsyncs the directory.
- Before each save the previous `config.yaml` is copied (same durable write) to `config.yaml.bak`, but only if it still parses, so a corrupt primary never replaces the last good backup.
- On start, a primary that fails to parse falls back to `config.yaml.bak` with an `error!` ("primary config corrupt, loaded backup"); the next commit rewrites the primary.
- If the backup is missing or also corrupt, `nos-configd` refuses to start (never a silent default).

### Config plane vs data plane

| Plane | Transport | Pattern |
|-------|-----------|---------|
| Config | Unix socket + postcard | Request/subscribe |
| Data (e.g. BGP→RIB routes) | Unix socket + postcard | Fire-and-forget push over a persistent connection |

Both planes use the same transport stack. In practice the data plane so far reuses each target daemon's existing per-instance socket and request/event enum (e.g. `nos-ribd`'s `RibRequest::PushBgpRoutes`, `nos-bgpd`'s `BgpRequest::RedistributeRoutes`) rather than a dedicated separate socket/message-type pair — a fire-and-forget variant appended to the same `Request`-style enum the config plane already frames with `IpcCodec`, sent over one long-lived connection (`Full` snapshot on connect, incremental `Add`/`Remove` after), same pattern as `nos-logd`'s `LogRequest::Push`. A future high-enough-volume feed could still justify a dedicated socket/message-type pair instead.

