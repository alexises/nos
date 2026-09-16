# nos-rib — RIB Component

Computes the best route per prefix for one routing table (binary `nos-ribd`, one process per `RoutingTable`, spawned by `nos-watchdog`).

## Scope

The internal `Rib` (`src/rib.rs`) is modeled as multi-source (`RouteSource::Static` / `RouteSource::Bgp`) so best-path selection is real, discriminating logic, but only `Static` (from a `StaticRoutingInstance` in the running config) is ever populated — there is no BGP→RIB data-plane protocol yet. Adding one later only requires a new populator constructing `RouteSource::Bgp` entries; `Rib`'s public shape doesn't need to change.

**OS application is now real**, via a swappable `driver` (`src/driver/`, see below) — `--driver linux` (the default on Linux) creates an actual Linux VRF device + kernel routing table per routing table and installs the winning route per prefix into it; `--driver noop` (the default off-Linux) keeps the old log-only behavior for tests/dev. Only the *best* route per prefix is ever installed to the kernel — `Rib`'s multi-candidate view stays a query-serving concern.

There is an external query API: `server.rs` serves `nos_proto::rib::{RibRequest, RibEvent}` for `nos-cli`'s `show route` command (see root `CLAUDE.md`'s "Endpoint broker" section for how a client finds this instance's socket), plus `GetVrfName` — the first direct daemon-to-daemon IPC link in this codebase, letting `nos-interfaced` ask this instance for its Linux VRF interface name so it can enslave interfaces into it by name — and `GetTableId`, symmetric to `GetVrfName`, letting `nos-interfaced` learn this table's raw numeric kernel table id so it can name a loopback interface's kernel device (`lo<table_id>`).

## Modules

| Module | Role |
|--------|------|
| `main.rs` | Arg parsing (`--table`, `--watchdog-socket`, `--listen-socket`, `--driver`, `--table-registry-path`), resolves `nos-configd`'s address via the watchdog broker before starting, SIGINT+SIGTERM shutdown wait, spawns `reconcile::run` and `server::start` sharing one `Arc<RwLock<Rib>>` and the driver |
| `rib.rs` | `RouteSource`, `RibEntry`, `Rib` (best-path selection: `best_route`/`best_routes` for the winner only, `all_routes`/`lookup` for every candidate per prefix — the latter used to serve `RibRequest`), `build_from_config` |
| `driver/mod.rs` | `RibDriver` trait (`apply`, `teardown`, `vrf_name`, `table_id`) and `DriverError` — the swappable OS backend, so a future non-Linux/hardware driver can be added without touching `reconcile.rs` |
| `driver/noop.rs` | `NoopRibDriver` — today's original log-only behavior |
| `driver/linux.rs` | `LinuxRibDriver` — real `rtnetlink` calls: creates/ups the VRF link, diffs live kernel routes in that table against the desired best-path set and adds/removes the difference |
| `driver/table_registry.rs` | `nos-ribd`'s **own private** persisted state (`--table-registry-path`, default `/var/lib/nos/linux-driver/table-ids.yaml`): allocates a kernel table id (100–252, avoiding Linux's reserved 0/253/254/255) for this table's name on first use and remembers it across restarts, so a crash/restart recreates the same VRF name. Exclusively locked (via `fs2`) around the allocate-and-persist sequence since multiple `nos-ribd` instances share this one file. **No other process ever reads this file** — see `GetVrfName` above for how `nos-interfaced` learns the name instead. |
| `config_client.rs` | Own `fetch_config` (`Request::Get`) / `subscribe_diff` (`Request::SubscribeDiff`) — reimplemented rather than shared with `nos-cli`/`nos-watchdog`, per the root `CLAUDE.md`'s star dependency graph |
| `watchdog_client.rs` | Own `resolve_with_retry` — resolves `nos-configd`'s address via the watchdog broker, retrying indefinitely (fixed 1s delay) until it succeeds or shutdown fires |
| `reconcile.rs` | Steady-state loop: subscribes to `RoutingTables`/`StaticRoutingInstances` diffs purely as a resync trigger, always re-fetching the whole config and rebuilding the `Rib` from scratch rather than applying diffs incrementally (diffs carry only display strings, not structured route data); calls `driver.apply` with the recomputed best routes; writes the rebuilt `Rib` through the shared `Arc<RwLock<Rib>>`. Also re-applies on a fixed 10s timer even without a new diff — a config commit is not the only thing that can require re-applying (e.g. the VRF just didn't exist yet on an earlier attempt, or kernel state drifted out of band). On exit, calls `driver.teardown` to delete the kernel VRF + its routes — this runs on **every** SIGINT nos-watchdog sends (both an ordinary restart and a real table removal look identical to this process), which is why `teardown` never touches the table-id registry: the next `apply` must recreate the exact same VRF name. |
| `server.rs` | Binds `--listen-socket` and serves `RibRequest::GetRoutes`/`Lookup`/`GetVrfName`/`GetTableId` from the shared `Arc<RwLock<Rib>>` (read-locked per request) and driver (`driver.vrf_name`/`driver.table_id`) |

`table.bgp_instance` is deliberately never read — see `rib.rs`'s `build_from_config` doc comment.
