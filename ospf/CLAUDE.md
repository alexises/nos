# nos-ospf — OSPF Component

OSPF daemon for NOS (binary `nos-ospfd`, one process per `OspfInstance`, dynamically spawned by `nos-watchdog` — see root `CLAUDE.md`'s "Process supervision" section).

## Scope

This is a **config-only skeleton today** — no OSPF wire protocol (Hello, LSAs, neighbors) exists yet. `nos-ospfd` resolves `nos-configd`'s address via the watchdog broker, subscribes to `OspfInstances` diffs purely as a resync trigger, and on each resync logs its own instance's `router_id`, reflexive `routing_table` association (mirrored from the owning `RoutingTable.ospf_instance`, exactly like `BgpInstance.routing_table` — see `proto/CLAUDE.md`'s `sync_routing_table_refs`), its `OspfArea`s (dotted-quad `area_id`, see `proto/CLAUDE.md`), and each area's `OspfProfile`s along with every L3 attach point (a loopback `Interface`, a physical interface's `Subinterface`, or a `BroadcastDomain`'s own SVI) currently referencing that profile by name via its `ospf_profile` field — resolved locally from the same `fetch_config` call, since it already carries `interfaces`/`broadcast_domains` too, no extra IPC round trip needed. `nos-rpl`-style policy/attribute handling and any wire-protocol interface parameters (hello/dead interval, cost, network type) are not modeled yet — `OspfProfile` is currently just a name, a placeholder for those to land on later without a schema reshape. It opens no sockets, programs no kernel state, and has no IPC query listener of its own — `nos-watchdog` spawns it with no `--listen-socket`, and there is no `ServiceRef::OspfInstance` registration in `EndpointRegistry` yet (the `ServiceRef`/registry plumbing already exists for whichever future change gives it one).

## Modules

| Module | Role |
|--------|------|
| `main.rs` | Arg parsing (`--instance`, `--watchdog-socket`, `--log-socket`), resolves `nos-configd`'s address via the watchdog broker before starting, SIGINT+SIGTERM shutdown wait, spawns `reconcile::run` |
| `config_client.rs` | Own `fetch_config` (`Request::Get`) / `subscribe_diff` (`Request::SubscribeDiff`) — reimplemented rather than shared with the other component crates, per the root `CLAUDE.md`'s star dependency graph |
| `watchdog_client.rs` | `resolve_with_retry` (used once at startup for `ServiceRef::Config`) |
| `reconcile.rs` | Steady-state loop: subscribes to `OspfInstances` diffs purely as a resync trigger, always re-fetching the whole config and logging this instance's `router_id`/`routing_table`/areas/profiles and each profile's attached interfaces (`attach_points_for`) |
