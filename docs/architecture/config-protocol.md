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
  Request::SetTransactionPath  set/remove one subsection of a named transaction by URL-style path (whole config for an empty path) — see nos_proto::config_path (if_match as above); an optional `position` (`ListPosition`: First/Last/Before(k)/After(k)) inserts or moves the list element the path names (#539)
  Request::UserExists          cheap auth probe (#755): is this name in `Config.users`? `Restd` only; replies with no config data
  Request::ListBgpInstances / ListOspfInstances / ListOspfv3Instances   instance names only (#759): what `nos-restd`'s show routes iterate, without shipping the config. `Restd` only
  Request::GetRestApi { table }  that routing table's pinned `rest_api` (#759, #758): the listener's per-tick "what is wanted" probe. `Restd` only

Server → Client:
  Event::Config(Config)             config snapshot (initial + on every commit, incl. via a transaction commit)
  Event::Error(String)              error from the daemon
  Event::Saved                      confirms the running config was persisted (reply to Save)
  Event::Transaction(Snapshot)      a named transaction's current state (reply to Open/Apply/Get/SetTransactionPath), incl. its generation (0 at open, +1 per edit — nos-restd's ETag)
  Event::Committed { warnings }     confirms a commit, with non-blocking advice (#501)
  Event::Discarded                  confirms a transaction was discarded
  Event::Description(CommandDoc)    one operation's documentation (reply to Describe)
  Event::UserExists(bool)           reply to UserExists
  Event::InstanceNames(Vec<String>) reply to the three List*Instances requests
  Event::RestApi(Option<RestApi>)   reply to GetRestApi (`None` = table absent or not pinned)
```

`Describe`/`Description` exist so that the shell's help text (what a command does, in human terms, for the CLI's user) is authored once in `nos-config` and shared by every client, rather than duplicated per-client. A `Topic` is one config-tree node or field — named by the mandatory `#[cli(topic = …)]` on every schema field (`nos-proto-derive`, see [Schema reference](../schema-reference.md)), so a field can't exist without its CLI help — or one show/shell command (`nos-cli`'s `spec.rs` rows). `nos-cli`'s config commands (`edit`/`set`/`delete`), their help, `?`, Tab and usage are all generated from that schema tree (`cli/src/config_grammar.rs`, #109) and sent as `SetTransactionPath`, the same generic write REST uses. The schema's `///` comments are the REST API's (Swagger) text, deliberately separate. It's scoped to a single `Topic` per request (not a bulk catalog fetch) so a client only ever fetches the docs it actually displays.

### Named transactions

Editing the config happens inside a **named transaction**, held server-side in `nos-config`, not tied to any one connection. `OpenTransaction` creates it from a blank config or a clone of the running config (`TransactionBase::Blank`/`Current`), or — if a transaction with that name already exists — resumes its current in-progress state unchanged. `CommitTransaction` validates the transaction and, if valid, atomically replaces the running config and broadcasts it to every `Subscribe`d connection (the same fan-out `Get`/`Subscribe` already use); on invalid input the transaction is left alive so the caller can keep editing. `DiscardTransaction` deletes it outright. Because transactions live only in the daemon and are addressed by name, a client can disconnect (crash, Ctrl-C, network drop) and resume the same transaction later from a fresh connection — see `nos-cli`'s `configure <name>` command.

### Persistence

- `save_to_disk` writes a temp file, fsyncs it, renames it over `config.yaml`, then fsyncs the directory.
- Before each save the previous `config.yaml` is copied (same durable write) to `config.yaml.bak`, but only if it still parses, so a corrupt primary never replaces the last good backup.
- On start, a primary that fails to parse falls back to `config.yaml.bak` with an `error!` ("primary config corrupt, loaded backup"), and the primary is rewritten from the backup immediately (a failed restore is logged; the load still succeeds).
- If the backup is missing or also corrupt, `nos-configd` refuses to start (never a silent default).

### Framing limit

- `IpcCodec` frames are a 4-byte LE length plus a postcard payload of at most `nos_proto::codec::MAX_FRAME` (16 MiB).
- A longer length is `InvalidData` on decode (checked before any buffer is reserved, so a hostile `ff ff ff ff` costs nothing) and the connection is dropped.
- An incomplete frame reserves at most `RESERVE_CHUNK` (64 KiB) per `decode` call, so memory grows as bytes arrive, never the full declared length up front.
- Encode rejects an over-cap payload too, so an oversize message fails at the sender.
- Payloads that can legitimately grow past the cap are cut to fit:
  - `nos-bgpd` → `nos-ribd` `PushBgpRoutes` (a full IPv4 table is ~1M routes, 10 MB and up with backups, multipath and IPv6): `BgpRouteUpdate::frames` sends at most `BGP_PUSH_CHUNK` (2048) routes per frame. A larger `Full` goes as `FullPart`s closed by a `Full`; `nos-ribd` stages the parts per connection and swaps the whole set in at the closing `Full` (log: `assembled chunked bgp route snapshot … parts=N`), so it never publishes half a table. A connection lost mid-snapshot drops what was staged; the reconnect sends a fresh `Full`.
  - `nos-bgpd` `GetRoutesPage`, `GetEvpnRoutesPage`, `GetFlowspecRoutesPage`, `GetVpnRoutesPage` (`show bgp routes|evpn|flowspec|vpnv4|vpnv6`, `GET /v1/bgp/...`, #722/#723): same count limit and byte budget, keyed by `BgpRouteCursor`, but over a per-connection sorted key snapshot (`bgp/src/page.rs`, [BGP internals](../protocols/bgp-internals.md)) because the BGP RIB is not ordered.
  - `nos-ribd` `GetRoutesPage` (`show route`, `GET /v1/routes/{table}`, #713): at most `ROUTES_PAGE_MAX` (1000) prefixes per reply and cut early at a ~8 MiB encoded estimate (half of `MAX_FRAME`); the cursor is the last prefix returned. Keyset paging, no snapshot: a table that changes mid-walk never loops or repeats a prefix, but a walk may miss or include a concurrent change. `Rib` stays a `HashMap`, so a page is one O(n) pass under the read lock.
  - `nos-logd` `GetLogs`/`Tail` replies: capped at `store::REPLY_BYTES` (just under 16 MiB), newest entries kept, oldest left out.
  - `nos-bgpd` → `nos-ribd`/`nos-fdbd` `PushEvpnRoutes` (#719, #720): `EvpnUpdate::split()` cuts a `Full` by encoded bytes (`evpn_push_budget()`, 4 MiB). Receivers stage the `FullPart`s per connection (`EvpnUpdate::absorb`) and apply the whole set once, on the closing `Full` (log: `assembled chunked evpn route snapshot … parts=N`, `table=` on ribd, `domain=` on fdbd). Staged parts are uncapped; a lost connection drops them.
- Known payloads still sent whole (fail past 16 MiB, the connection drops): the `Full` snapshots of `PushVpnRoutes`/`PushOspfRoutes`/`RedistributeRoutes`.

### Commit diffs (#751)

- A commit builds one `ConfigDiff` per visibility class (`ViewClass::of(role)`, what `Config::for_role` hides), not one per `SubscribeDiff` subscriber: `CommitUpdate::diff_for(role)` fills a lazy `OnceCell` per class, so concurrent subscribers wait for a single computation and share an `Arc<ConfigDiff>`.
- The diff runs in `spawn_blocking`, off the runtime workers. If it panics, those subscribers skip that commit (warning logged).
- `diff_configs` indexes each keyed list by key and skips equal elements: O(n) in the list length, no `Value` cloned. Duplicate keys still pair with the first match.
- `Subscribe` (full config) keeps its per-subscriber `for_role` clone.
- Lean ring slots (#773): a `CommitUpdate` shares its `config` with running, and holds the previous config only until every visibility class with a live `SubscribeDiff` subscriber at send time has its diff, then drops it. A slot then keeps `config` plus the diffs.
  - The store counts live diff subscribers per class (`ConfigStore::subscribe_diff`, released when the forwarder task ends). Registering and `broadcast::Sender::subscribe` happen under one lock, so a commit owes exactly the classes of the receivers that get it.
  - The class that sees everything (`User`, `Restd`) diffs the shared configs directly. Other classes build their `for_role` projections inside the diff task and drop them with it.
  - A commit with no diff subscriber keeps no previous config.

### Memory profiling (#766, #767)

- Image: `CARGO_FEATURES="nos-config/dhat-heap nos-rest/dhat-heap" make docker-build` (the Dockerfile passes one `--features` to the multi-`--bin` build; cargo resolves both `pkg/feature` entries). Default and release builds are unchanged. The dhat image inflates RSS: read RSS only from a default image.
- Watchdog args: `--configd-arg=--profile-memory-out=/tmp/dhat-configd.json --restd-arg=--profile-memory-out=/tmp/dhat-restd-{name}.json`. The watchdog replaces a literal `{name}` in pass-through flags with the instance name, so each `nos-restd` (one per table) gets its own file. The lab takes extra watchdog args from `NOS_E2E_WATCHDOG_ARGS` (space-separated) on `nos-e2e up`.
- Wave load: `LOGD_MEM_ROUTER=b [WAVE_COUNT=12] [WAVE_ROUTES=5500] [WAVE_IDLE=0] cargo run -p nos-e2e -- mem-wave`. Each wave opens a transaction on running, `PUT`s `WAVE_ROUTES` static routes one per request (spread over `ceil(total/25000)` instances), commits, and logs every `nos-*` daemon's `VmRSS`/`VmHWM` plus the cgroup after the commit and after `WAVE_IDLE` seconds. It fails if `nos-configd` or `nos-restd` changes pid.
- At the end it prints the running config's JSON size, SIGINTs `nos-configd` and `nos-restd`, and prints their dhat `t-gmax`/`t-end` and the top 8 program points by max bytes, total bytes and bytes live at exit (2 frames below the allocator plus the first 3 `nos_*` frames). A non-dhat image just logs that there is no report. Not a phase (asserts nothing, not in `phases::ALL`).
- On the dhat image use a smaller load, e.g. `WAVE_COUNT=4 WAVE_ROUTES=2500`: dhat slows each allocation, and until #774 every `PUT` still replies with the whole transaction (O(config)), so the default 12 x 5500 takes hours. Read RSS from the default image, attribution from dhat.
- For a deeper split than the log lines, copy the report out before `down` (`docker exec router-b cat /tmp/dhat-configd.json > configd.json`) and load it in https://nnethercote.github.io/dh_view/dh_view.html.
- `cargo test -p nos-config --test resident -- --nocapture`: counting allocator over ~66k static routes with three `SubscribeDiff` subscribers (`User`, `Watchdog`, `Bgpd`, one per kind of visibility class) through `ConfigStore::subscribe_diff`. It runs 4 commits sharing 2000 single-route edits (`NOS_RESIDENT_PUTS` overrides) and prints one `Config`'s live size and these peaks:
  - per-`PUT` transient of `edit_transaction_path` (the edit without the snapshot reply), asserted at most 16 KiB;
  - the first `PUT` of each transaction, which unshares running (one copy), asserted at most two `Config`s;
  - store-level commit transient, asserted at most one `Config`;
  - the subscribers' diff transient, printed only (~75 `Config`s at 66k: `diff_configs` walks both configs as JSON for each class);
  - live heap after the commits, broadcast ring included, asserted at most half a `Config`. Tokio drops a ring slot's value once every receiver has read it, so only a lagging receiver keeps a commit alive.
- Measured at 66k in a debug build (#773): commit transient 0.14 `Config`, live after 4 commits ~0, per-`PUT` transient 11.6 `Config`s.
- After #775: per-`PUT` transient 1.7 KB (was 11.6 `Config`s, ~49 MB), first `PUT` 1.38 `Config`s, live after 4 commits below the seed (running re-cloned with exact capacities).

### Path edits (#775)

- `set_transaction_path` costs the addressed part, not the config (`config/src/path_edit.rs`):
  - one element of a top-level list (`bgp-instance/r1/...`) or one top-level section goes through JSON and back;
  - `static-routing-instance/<n>/route/<subnet>[/...]` touches one route of the typed list (key scan without allocation);
  - an empty path takes the whole-config route (the config through JSON and back).
- The edit is planned on the transaction's config under the lock; every check (path, key, anchor, JSON body, `<hidden>` masks) runs first, then the change applies in place with `Arc::make_mut`. A failed edit changes nothing. The first edit after `open(Current)` copies running once.
- A `users` edit goes through the off-lock argon2 hashing, then stores only the user list if the generation did not move.
- A differential unit test replays random edit sequences through both routes and requires the same configs and the same errors.
- `edit_transaction_path` is the same edit returning only the new generation (the subsection reply of #774 builds on it).

### Config plane vs data plane

| Plane | Transport | Pattern |
|-------|-----------|---------|
| Config | Unix socket + postcard | Request/subscribe |
| Data (e.g. BGP→RIB routes) | Unix socket + postcard | Fire-and-forget push over a persistent connection |

Both planes use the same transport stack. In practice the data plane so far reuses each target daemon's existing per-instance socket and request/event enum (e.g. `nos-ribd`'s `RibRequest::PushBgpRoutes`, `nos-bgpd`'s `BgpRequest::RedistributeRoutes`) rather than a dedicated separate socket/message-type pair — a fire-and-forget variant appended to the same `Request`-style enum the config plane already frames with `IpcCodec`, sent over one long-lived connection (`Full` snapshot on connect, incremental `Add`/`Remove` after), same pattern as `nos-logd`'s `LogRequest::Push`. A future high-enough-volume feed could still justify a dedicated socket/message-type pair instead.

