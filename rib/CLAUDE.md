# nos-rib — RIB Component

Computes the best route per prefix for one routing table (binary `nos-ribd`, one process per `RoutingTable`, spawned by `nos-watchdog`).

## Scope

In-memory only for now: no kernel/netlink route installation. The internal `Rib` (`src/rib.rs`) is modeled as multi-source (`RouteSource::Static` / `RouteSource::Bgp`) so best-path selection is real, discriminating logic, but only `Static` (from a `StaticRoutingInstance` in the running config) is ever populated — there is no BGP→RIB data-plane protocol yet. Adding one later only requires a new populator constructing `RouteSource::Bgp` entries; `Rib`'s public shape doesn't need to change.

There is now an external query API: `server.rs` serves `nos_proto::rib::{RibRequest, RibEvent}` for `nos-cli`'s `show route` command (see root `CLAUDE.md`'s "Endpoint broker" section for how a client finds this instance's socket).

## Modules

| Module | Role |
|--------|------|
| `main.rs` | Arg parsing (`--table`, `--watchdog-socket`, `--listen-socket`), resolves `nos-configd`'s address via the watchdog broker before starting, SIGINT+SIGTERM shutdown wait, spawns `reconcile::run` and `server::start` sharing one `Arc<RwLock<Rib>>` |
| `rib.rs` | `RouteSource`, `RibEntry`, `Rib` (best-path selection: `best_route`/`best_routes` for the winner only, `all_routes`/`lookup` for every candidate per prefix — the latter used to serve `RibRequest`), `build_from_config` |
| `config_client.rs` | Own `fetch_config` (`Request::Get`) / `subscribe_diff` (`Request::SubscribeDiff`) — reimplemented rather than shared with `nos-cli`/`nos-watchdog`, per the root `CLAUDE.md`'s star dependency graph |
| `watchdog_client.rs` | Own `resolve_with_retry` — resolves `nos-configd`'s address via the watchdog broker, retrying indefinitely (fixed 1s delay) until it succeeds or shutdown fires |
| `reconcile.rs` | Steady-state loop: subscribes to `RoutingTables`/`StaticRoutingInstances` diffs purely as a resync trigger, always re-fetching the whole config and rebuilding the `Rib` from scratch rather than applying diffs incrementally (diffs carry only display strings, not structured route data); writes the rebuilt `Rib` through the shared `Arc<RwLock<Rib>>` |
| `server.rs` | Binds `--listen-socket` and serves `RibRequest::GetRoutes`/`Lookup` from the shared `Arc<RwLock<Rib>>`, read-locked per request |

`table.bgp_instance` is deliberately never read — see `rib.rs`'s `build_from_config` doc comment.
