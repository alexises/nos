# nos-interface — Interface Reconciliation Daemon

Reconciles configured network interfaces against the OS (binary `nos-interfaced`, a single process for every interface — unlike `nos-ribd`, `nos-watchdog` spawns exactly one instance regardless of how many `Interface` sections exist in config).

## Scope

Applies configured interface state (addresses, admin-up, VRF enslavement) to the OS through a swappable **driver** (`driver::InterfaceDriver`), selected via `--driver` (default `linux` on Linux, `noop` elsewhere/for tests):
- `driver::noop::NoopInterfaceDriver` — logs the state that would be applied; no OS effect. Today's original placeholder behavior, kept as the portable default.
- `driver::linux::LinuxInterfaceDriver` — the real implementation, via the `rtnetlink` crate. Only ever *configures* interfaces already present in the netns (see "Why one process for all interfaces" below) — it never creates virtual interfaces (no dummy/veth/vlan/bridge support). Diffs live kernel state (addresses, current VRF master) against desired state on every call rather than trusting any cached record of what it applied last, which makes it self-healing against out-of-band kernel drift. Address reconciliation never touches a kernel-reported address at scope `Link` (e.g. IPv6 link-local) — NOS only owns addresses it put there itself. Requires `NET_ADMIN`/`NET_RAW`; see the `Dockerfile`/`docker-compose.yml`.

**Cross-daemon IPC to `nos-ribd`.** When an interface's `routing_table` is set, `LinuxInterfaceDriver` needs the real Linux interface name of that table's VRF device — but VRF creation and table-id allocation are owned entirely by the *owning* `nos-ribd` instance's own driver (see `rib/CLAUDE.md`), not derivable independently. So the driver resolves that table's `nos-ribd` socket via the watchdog broker (`ServiceRef::RibTable(name)`) and asks it directly over IPC (`RibRequest::GetVrfName` → `RibEvent::VrfName(Option<String>)`, see `driver::rib_client`) — the first direct daemon-to-daemon link in this codebase (see root `CLAUDE.md`). "Not resolvable yet" (broker doesn't know that table, connect failure, or rib hasn't created a VRF yet) is a normal, expected, frequently-recurring condition, never an error — it's silently retried by the periodic re-apply tick (`reconcile::REAPPLY_INTERVAL`), not just on the next config diff, since the other daemon's readiness isn't itself a config change.

There is an external query API: `server.rs` serves `nos_proto::interface::{InterfaceRequest, InterfaceEvent}` for `nos-cli`'s `show interface` command (see root `CLAUDE.md`'s "Endpoint broker" section for how a client finds this instance's socket — `ServiceRef::Interfaces`, resolved directly by the watchdog like `ServiceRef::Config`, since there's exactly one instance). A query reflects *desired* state (from the running config) — with the `linux` driver running, that's normally also what the kernel has, but the two can transiently diverge (e.g. right after a config change, or if the VRF isn't up yet).

## Why one process for all interfaces, unlike nos-ribd

`RoutingTable`/`BgpInstance` each get an isolated in-memory computation (a RIB, a BGP session) that benefits from process isolation and independent restart. An interface is not an isolated resource — every `nos-interfaced` instance would ultimately be reaching into the same OS network namespace — so there's no isolation benefit to one process per interface, and per-interface spawn/teardown would only add churn on every config edit. See root `CLAUDE.md`'s "Process supervision" section for how `nos-watchdog` supervises this as a single fixed process, the same way it supervises `nos-configd`.

## Modules

| Module | Role |
|--------|------|
| `main.rs` | Arg parsing (`--watchdog-socket`, `--listen-socket` default `/run/nos/interface.sock`, `--driver` default platform-dependent), resolves `nos-configd`'s address via the watchdog broker before starting, constructs the selected `InterfaceDriver`, SIGINT+SIGTERM shutdown wait, spawns `reconcile::run` and `server::start` sharing one `Arc<RwLock<Interfaces>>` |
| `state.rs` | `InterfaceState`, `Interfaces` (a name-keyed collection, mirroring `nos-rib`'s `Rib`), `build_from_config` (now async — calls `driver.apply` per interface and `driver.remove` for any interface dropped from config since the previous resync) |
| `driver/mod.rs` | `InterfaceDriver` trait (`apply`, `remove`), `DriverError` |
| `driver/noop.rs` | `NoopInterfaceDriver` |
| `driver/linux.rs` | `LinuxInterfaceDriver` — real `rtnetlink` implementation |
| `driver/rib_client.rs` | One-shot `get_vrf_name` — the client side of the new cross-daemon `RibRequest::GetVrfName` IPC |
| `config_client.rs` | Own `fetch_config` (`Request::Get`) / `subscribe_diff` (`Request::SubscribeDiff`) — reimplemented rather than shared with `nos-cli`/`nos-watchdog`/`nos-rib`, per the root `CLAUDE.md`'s star dependency graph |
| `watchdog_client.rs` | `resolve_with_retry` — resolves `nos-configd`'s address via the watchdog broker, retrying indefinitely (fixed 1s delay) until it succeeds or shutdown fires; `resolve_once` — a non-retrying sibling used by `LinuxInterfaceDriver` to resolve a routing table's `nos-ribd` instance on every reconcile pass, where "not available" must return quickly rather than block |
| `reconcile.rs` | Steady-state loop: subscribes to `Interfaces` diffs purely as a resync trigger, always re-fetching the whole config and rebuilding `Interfaces` from scratch rather than applying diffs incrementally (diffs carry only display strings, not structured data); also re-applies on a fixed `REAPPLY_INTERVAL` (10s) even without a new diff, since VRF readiness is an external condition no config diff signals; writes the rebuilt `Interfaces` through the shared `Arc<RwLock<Interfaces>>` |
| `server.rs` | Binds `--listen-socket` and serves `InterfaceRequest::GetInterfaces`/`GetInterface` from the shared `Arc<RwLock<Interfaces>>`, read-locked per request |
