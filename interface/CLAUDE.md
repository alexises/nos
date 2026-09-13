# nos-interface — Interface Reconciliation Daemon

Reconciles configured network interfaces against the OS (binary `nos-interfaced`, a single process for every interface — unlike `nos-ribd`, `nos-watchdog` spawns exactly one instance regardless of how many `Interface` sections exist in config).

## Scope

**Placeholder only for now: no real OS/netlink effect.** `state::apply_interface` logs the address list and routing-table (VRF) assignment it *would* apply to each interface, but never actually touches the kernel network stack. Real application — adding/removing addresses, binding the interface to its routing table's VRF device — is a follow-up, most likely via the `rtnetlink` crate, and will need `NET_ADMIN` in the container. This mirrors how `nos-bgpd` is currently a placeholder with no real BGP logic.

There is an external query API: `server.rs` serves `nos_proto::interface::{InterfaceRequest, InterfaceEvent}` for `nos-cli`'s `show interface` command (see root `CLAUDE.md`'s "Endpoint broker" section for how a client finds this instance's socket — `ServiceRef::Interfaces`, resolved directly by the watchdog like `ServiceRef::Config`, since there's exactly one instance). Because there's no real OS application yet, a query reflects *desired* state (from the running config), not necessarily what the kernel actually has configured.

## Why one process for all interfaces, unlike nos-ribd

`RoutingTable`/`BgpInstance` each get an isolated in-memory computation (a RIB, a BGP session) that benefits from process isolation and independent restart. An interface is not an isolated resource — every `nos-interfaced` instance would ultimately be reaching into the same OS network namespace — so there's no isolation benefit to one process per interface, and per-interface spawn/teardown would only add churn on every config edit. See root `CLAUDE.md`'s "Process supervision" section for how `nos-watchdog` supervises this as a single fixed process, the same way it supervises `nos-configd`.

## Modules

| Module | Role |
|--------|------|
| `main.rs` | Arg parsing (`--watchdog-socket`, `--listen-socket`, default `/run/nos/interface.sock`), resolves `nos-configd`'s address via the watchdog broker before starting, SIGINT+SIGTERM shutdown wait, spawns `reconcile::run` and `server::start` sharing one `Arc<RwLock<Interfaces>>` |
| `state.rs` | `InterfaceState`, `Interfaces` (a name-keyed collection, mirroring `nos-rib`'s `Rib`), `build_from_config`, and the `apply_interface` placeholder |
| `config_client.rs` | Own `fetch_config` (`Request::Get`) / `subscribe_diff` (`Request::SubscribeDiff`) — reimplemented rather than shared with `nos-cli`/`nos-watchdog`/`nos-rib`, per the root `CLAUDE.md`'s star dependency graph |
| `watchdog_client.rs` | Own `resolve_with_retry` — resolves `nos-configd`'s address via the watchdog broker, retrying indefinitely (fixed 1s delay) until it succeeds or shutdown fires |
| `reconcile.rs` | Steady-state loop: subscribes to `Interfaces` diffs purely as a resync trigger, always re-fetching the whole config and rebuilding `Interfaces` from scratch rather than applying diffs incrementally (diffs carry only display strings, not structured data); writes the rebuilt `Interfaces` through the shared `Arc<RwLock<Interfaces>>` |
| `server.rs` | Binds `--listen-socket` and serves `InterfaceRequest::GetInterfaces`/`GetInterface` from the shared `Arc<RwLock<Interfaces>>`, read-locked per request |
