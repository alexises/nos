# nos-proto — Shared Protocol Types

Single source of truth for all inter-process wire contracts in NOS.

## Why this crate exists

Component processes (`nos-bgp`, `nos-rib`, …) must not depend on `nos-config` internals — only on the shared types they exchange. By owning all shared types here, we get:
- **Protocol sync at compile time**: change a type → compiler breaks every consumer immediately.
- **Clean dependency graph**: components depend on `nos-proto`, not on each other.

## Contents

| Module | Purpose |
|--------|---------|
| `schema/` | Config tree types: `Config`, `BgpInstance`, `BgpPeerGroup`, `BgpPeer`, `RoutingTable`, `StaticRoutingInstance`, `StaticRoute`. Derived `garde::Validate` for commit-time validation. `BgpPeerGroup`/`BgpPeer` nest one level under `BgpInstance`, showing the pattern for a section nested under another section rather than directly under `Config`; `StaticRoute` nests one level under `StaticRoutingInstance` the same way. `RoutingTable` shows the pattern for a section that only *references* other top-level sections by name (`bgp_instance`, `static_routing_instance`) rather than owning them. |
| `validators` | Generic reusable validation helpers (e.g. `unique_in`). Validators that need to search *across* a nested collection (e.g. peer-group name uniqueness scoped globally, not per-instance), or check a cross-reference (e.g. `RoutingTable.bgp_instance` naming an existing instance claimed by at most one table), live next to their owning schema type instead, since they're not generic. |
| `ops/` | Section-scoped edit types applied to a transaction's in-progress config (e.g. `BgpInstanceOp`, `BgpPeerGroupOp`, `RoutingTableOp`), wrapped by `ConfigOp`. Never validated — only `garde` at commit time is. A nested section's `Op` variants carry the owning parent's key too (e.g. `BgpPeerGroupOp::SetRemoteAs { instance, name, .. }`, `StaticRouteOp::Set { instance, subnet, .. }`). |
| `diff/` | Structural config comparison: `diff_configs(base, candidate) -> ConfigDiff`, plus one `diff_<section>` helper per section (e.g. `diff_bgp_instances`, `diff_bgp_peer_groups`, `diff_routing_tables`). Pure and synchronous, like `ops/`'s `apply` — only what changed is included, nothing unchanged. `SectionDiff.subsections` nests one section inside another for a nested config section (e.g. `diff_static_routing_instances` nesting `diff_static_routes`). Each `SectionDiff` carries both a display-only `header` (e.g. `"bgp instance r1"`, for `nos-cli`'s renderer) and a structured `name` (the section's identifying key as a plain string — an instance's `name`, a peer's `remote_address`, a route's `subnet` — so a machine consumer never has to parse `header`). `DiffScope` names one top-level `ConfigDiff` section; `ConfigDiff::scoped(&self, scopes)` returns a copy keeping only the requested sections, used by `SubscribeDiff` subscribers to receive only what they asked for. |
| `ipc` | IPC message types: `Request` (client→server) and `Event` (server→client), plus `TransactionBase` and `TransactionSnapshot`. `Request::SubscribeDiff { scopes: Vec<DiffScope> }` streams `Event::Diff(ConfigDiff)` scoped to `scopes` — an initial diff against an empty config, then one per commit touching a requested scope — as an alternative to `Request::Subscribe`'s full-snapshot `Event::Config` stream. |
| `broker` | `ServiceRef` (`Config` / `RibTable(String)`), `WatchdogRequest::ResolveEndpoint { service }`, `WatchdogEvent::Endpoint(PathBuf)` / `NotAvailable` — `nos-watchdogd`'s endpoint-resolution protocol, so no client needs to hardcode another daemon's socket path. |
| `rib` | `RibRequest::GetRoutes` / `Lookup { addr }`, `RibEvent::Routes(Vec<PrefixRoutes>)` / `Match(PrefixRoutes)` / `NoMatch` / `Error`, plus `PrefixRoutes` (a prefix + its candidates, best-to-worst) and the wire twins `RouteEntry`/`RouteSourceKind` of `nos-rib`'s internal `RibEntry`/`RouteSource` — `nos-ribd`'s route-query protocol. |
| `paths` | `DEFAULT_CONFIG_SOCKET`/`DEFAULT_WATCHDOG_SOCKET` — the two bootstrap socket defaults that stay fixed rather than being resolved via the broker. |
| `codec` | `IpcCodec<T>`: framing codec (4-byte LE length prefix + postcard payload). Generic over any `Serialize + DeserializeOwned` type, so it frames the config, broker, and RIB protocols alike. |

## Wire format

```
┌──────────────┬──────────────────────────┐
│ 4-byte LE u32│ postcard-encoded payload  │
│  (length)    │  (Request or Event enum)  │
└──────────────┴──────────────────────────┘
```

Use `IpcCodec<T>` with `tokio_util::codec::{FramedRead, FramedWrite}` to get typed async send/recv over a `UnixStream`.

## Adding a new config section

1. Add the new struct in `schema/` deriving `Serialize, Deserialize, garde::Validate`.
2. Add `#[garde(context(Config as ctx))]` and use the context for any cross-references.
3. Add the field to `Config` in `schema/mod.rs` with `#[garde(dive)]`.
4. Add a sibling `<Section>Op` enum in `ops/<section>.rs` with a synchronous `apply(&self, config: &mut Config) -> Result<(), OpError>` (create/update/delete by name, no `garde` validation — that only runs at commit), then add a `ConfigOp` variant wrapping it in `ops/mod.rs`.
5. Re-export from `lib.rs` if it's part of the public API.

## Adding a scalar top-level field

For a single always-present scalar with exactly one possible edit (e.g. `hostname`), skip the dedicated `<Section>Op` enum and file — that convention exists to give named/keyed collections per-name create/update/delete semantics, which a lone scalar doesn't need:

1. Add the field directly to `Config` in `schema/mod.rs` with its own `#[garde(...)]` rule(s). If the desired default isn't the field type's own `Default::default()` (e.g. `hostname` defaults to `"nos"`, not `""`), add `#[serde(default = "some_fn")]` on the field — required so pre-existing on-disk config missing that key still deserializes — and give `Config` a manual `impl Default` instead of deriving it.
2. Add one `ConfigOp` variant directly in `ops/mod.rs`'s enum (e.g. `SetHostname(String)`), with an `apply` arm that sets the field. No new `OpError` variant needed unless the edit can fail structurally.

## Wire compatibility

`Request`/`Event` variants must always be **appended**, never inserted or reordered — `postcard` encodes enum variants by index, so reordering breaks compatibility with already-built binaries.
