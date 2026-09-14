# nos-bgp — BGP Component

BGP-4 implementation for NOS (binary `nos-bgpd`, one process per `BgpInstance`, dynamically spawned by `nos-watchdog` — see root `CLAUDE.md`'s "Process supervision" section).

## Scope

This is the first real BGP feature: **VRF-scoped raw TCP connectivity**, not yet a BGP FSM. `nos-bgpd` resolves its own configured peers and VRF from `nos-configd`, then opens/accepts TCP connections to/from those peers, correctly scoped into the right VRF — but sends and parses no BGP messages (no OPEN/KEEPALIVE, no session state machine) yet. That's deliberately left for a later feature to layer on top of this connectivity.

### VRF resolution

A `BgpInstance` carries a reflexive, read-only `routing_table: Option<String>` field (`nos-proto`'s `derive::sync_routing_table_refs`, mirrored from the owning `RoutingTable.bgp_instance` on every config load/commit — see `proto/CLAUDE.md`). `nos-bgpd` reads this directly instead of scanning every `RoutingTable`, then resolves the named table's real Linux VRF interface name the same way `nos-interfaced` does: `ServiceRef::RibTable(name)` via the watchdog broker, then `RibRequest::GetVrfName` directly against that `nos-ribd` instance (`rib_client::get_vrf_name`).

This resolves to one of three states (`session::VrfRequirement`):
- **`Invalid`** — no owning routing table at all. Treated as a config error, **not** a "run unscoped in the default VRF" fallback — BGP always belongs to a VRF in this system. Logged as an error every resync; no session or listener is ever opened while in this state.
- **`Pending`** — an owning table exists but its VRF isn't allocated/known yet (the table's `nos-ribd` instance isn't up, or hasn't created its VRF yet). A normal, transient condition, logged at `debug`, retried by the periodic re-apply tick.
- **`Resolved(name)`** — the VRF's real Linux interface name. Only in this state does `nos-bgpd` open anything.

### Raw TCP session model

Once resolved, `session::SessionManager` maintains, per configured peer, both sides of a TCP session, scoped into the VRF via `SO_BINDTODEVICE` (`tcp.rs`, `socket2::SockRef` over a `tokio::net::TcpSocket` — a socket-level equivalent of `nos-ribd`/`nos-interfaced`'s `rtnetlink`-based VRF enslavement, since no interface or route is being programmed here):
- **Active**: a per-peer retry loop attempts an outbound connect (fixed interval, a placeholder for a real `ConnectRetryTimer` once the FSM exists) to the peer's `remote_address:179`, optionally bound to its peer-group's `source_address`.
- **Passive**: one shared listener (`0.0.0.0:179` + `[::]:179`) accepts inbound connections, matching the remote IP against the configured peer set; an unconfigured remote is rejected.

At most one open session per peer is allowed at a time, tracked via an `AtomicBool` "occupied" flag shared between that peer's active task and the passive accept handler — whichever side claims the flag first wins. **This is a documented simplification**: real RFC 4271 §6.8 collision resolution compares router-IDs learned from an OPEN message, which doesn't exist yet; first-connected-wins will be replaced once the FSM does.

No bytes received on an established session are parsed — `hold_until_closed` just reads-and-discards until the connection drops, at which point the slot frees up and the active side resumes retrying.

## Modules

| Module | Role |
|--------|------|
| `main.rs` | Arg parsing (`--instance`, `--watchdog-socket`, `--log-socket`), resolves `nos-configd`'s address via the watchdog broker before starting, SIGINT+SIGTERM shutdown wait, spawns `reconcile::run` |
| `config_client.rs` | Own `fetch_config` (`Request::Get`) / `subscribe_diff` (`Request::SubscribeDiff`) — reimplemented rather than shared with `nos-cli`/`nos-watchdog`/`nos-rib`/`nos-interface`, per the root `CLAUDE.md`'s star dependency graph |
| `watchdog_client.rs` | `resolve_with_retry` (used once at startup for `ServiceRef::Config`) and `resolve_once` (used every resync for `ServiceRef::RibTable`, where "not available" must return quickly rather than block) |
| `rib_client.rs` | One-shot `get_vrf_name` — the client side of `RibRequest::GetVrfName` |
| `reconcile.rs` | Steady-state loop: subscribes to `BgpInstances`/`RoutingTables` diffs purely as a resync trigger, always re-fetching the whole config; also re-applies on a fixed 10s timer, since VRF readiness is an external condition no config diff signals. `classify_vrf` is the pure VRF-state classification, unit-tested directly. Hands `(VrfRequirement, Vec<ResolvedPeer>)` to `session::SessionManager::reconcile` on every trigger |
| `session.rs` | `SessionManager` — owns every peer's active/passive TCP state and the shared listener; `reconcile` (add/remove/restart peers, rebind the listener on VRF change) is the sole entry point. `diff_peers` is the pure peer-set diffing, unit-tested directly (mirrors `nos-interface`'s `diff_addresses`) |
| `tcp.rs` | `connect`/`bind_listener` — the two VRF-scoped socket primitives, via `tokio::net::TcpSocket` + `socket2::SockRef::bind_device` |
| `log_client.rs` | `ForwardingLayer` — the `tracing` → `nos-logd` forwarder, reimplemented per-crate like every other daemon's |
