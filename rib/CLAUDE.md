# nos-rib — RIB Component

Computes the best route per prefix for one routing table (binary `nos-ribd`, one process per `RoutingTable`, spawned by `nos-watchdog`).

## Scope

In-memory only for now: no kernel/netlink route installation, no external query API. The internal `Rib` (`src/rib.rs`) is modeled as multi-source (`RouteSource::Static` / `RouteSource::Bgp`) so best-path selection is real, discriminating logic, but only `Static` (from a `StaticRoutingInstance` in the running config) is ever populated — there is no BGP→RIB data-plane protocol yet. Adding one later only requires a new populator constructing `RouteSource::Bgp` entries; `Rib`'s public shape doesn't need to change.

## Modules

| Module | Role |
|--------|------|
| `main.rs` | Arg parsing (`--table`, `--config-socket`), SIGINT+SIGTERM shutdown wait, spawns `reconcile::run` |
| `rib.rs` | `RouteSource`, `RibEntry`, `Rib` (best-path selection), `build_from_config` |
| `config_client.rs` | Own `fetch_config` (`Request::Get`) / `subscribe_diff` (`Request::SubscribeDiff`) — reimplemented rather than shared with `nos-cli`/`nos-watchdog`, per the root `CLAUDE.md`'s star dependency graph |
| `reconcile.rs` | Steady-state loop: subscribes to `RoutingTables`/`StaticRoutingInstances` diffs purely as a resync trigger, always re-fetching the whole config and rebuilding the `Rib` from scratch rather than applying diffs incrementally (diffs carry only display strings, not structured route data) |

`table.bgp_instance` is deliberately never read — see `rib.rs`'s `build_from_config` doc comment.
