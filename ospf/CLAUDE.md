# nos-ospf — OSPF Component

OSPF daemon for NOS (binary `nos-ospfd`, one process per `OspfInstance`, dynamically spawned by `nos-watchdog` — see root `CLAUDE.md`'s "Process supervision" section).

## Scope

This is a **config-only skeleton today** — no OSPF wire protocol (Hello, LSAs, areas, neighbors) exists yet. `nos-ospfd` resolves `nos-configd`'s address via the watchdog broker, subscribes to `OspfInstances` diffs purely as a resync trigger, and on each resync logs its own instance's `router_id` and reflexive `routing_table` association (mirrored from the owning `RoutingTable.ospf_instance`, exactly like `BgpInstance.routing_table` — see `proto/CLAUDE.md`'s `sync_routing_table_refs`). It opens no sockets, programs no kernel state, and has no IPC query listener of its own — `nos-watchdog` spawns it with no `--listen-socket`, and there is no `ServiceRef::OspfInstance` registration in `EndpointRegistry` yet (the `ServiceRef`/registry plumbing already exists for whichever future change gives it one).

## Modules

| Module | Role |
|--------|------|
| `main.rs` | Arg parsing (`--instance`, `--watchdog-socket`, `--log-socket`), resolves `nos-configd`'s address via the watchdog broker before starting, SIGINT+SIGTERM shutdown wait, spawns `reconcile::run` |
| `config_client.rs` | Own `fetch_config` (`Request::Get`) / `subscribe_diff` (`Request::SubscribeDiff`) — reimplemented rather than shared with the other component crates, per the root `CLAUDE.md`'s star dependency graph |
| `watchdog_client.rs` | `resolve_with_retry` (used once at startup for `ServiceRef::Config`) |
| `reconcile.rs` | Steady-state loop: subscribes to `OspfInstances` diffs purely as a resync trigger, always re-fetching the whole config and logging this instance's `router_id`/`routing_table` |
| `log_client.rs` | `ForwardingLayer` — the `tracing` → `nos-logd` forwarder, reimplemented per-crate like every other daemon's |
