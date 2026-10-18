# nos-interface — Interface Reconciliation Daemon

Reconciles configured network interfaces against the OS (binary `nos-interfaced`, a single process for every interface — unlike `nos-ribd`, `nos-watchdog` spawns exactly one instance regardless of how many `Interface` sections exist in config).

## Why one process for all interfaces, unlike nos-ribd

`RoutingTable`/`BgpInstance` each get an isolated in-memory computation (a RIB, a BGP session) that benefits from process isolation and independent restart. An interface is not an isolated resource — every `nos-interfaced` instance would ultimately be reaching into the same OS network namespace — so there's no isolation benefit to one process per interface, and per-interface spawn/teardown would only add churn on every config edit. See `docs/architecture/supervision.md` for how `nos-watchdog` supervises this as a single fixed process, the same way it supervises `nos-configd`.


## Rules that bite

- **Drivers.** `driver::InterfaceDriver` is selected by `--driver` (`linux` on Linux, `noop` elsewhere and in tests; `noop` only logs). The `linux` driver (`rtnetlink`) diffs live kernel state on every call and trusts no record of what it applied, so it self-heals against drift. Needs `NET_ADMIN`/`NET_RAW`.
- **Creates only what it owns.** It configures existing interfaces and never creates one, except a `loopback-<table>` interface (a `dummy` device `lo<table_id>`), one Linux bridge per `BroadcastDomain` (`br<id>`, `driver::bridge_registry`), 802.1q sub-interfaces (`<interface>.<tag>`) and `PortAggregate` bonds (`bond<id>`, `driver::port_aggregate_registry`). Registry files are private to this driver.
- **MTU.** `desired.mtu.unwrap_or(DEFAULT_MTU)` (1500) is enforced on every link and bond; a bond member with no `mtu` is left to the bonding driver. Kernel-reported `Link`-scope addresses are never touched; `InterfaceAddress.label` is stored but not applied.
- **One bridge per domain**, never one 802.1Q-aware bridge: the dot1q tag is local to an interface. A `BroadcastDomain`'s own `addresses`/`routing_table` make its bridge an SVI, reconciled by `ensure_broadcast_domain`.
- **Every tag>0 sub-link goes through `reconcile_tagged_subinterfaces`** over the union of `Dot1q` switching-profile tags and L3 `Subinterface` tags; scanning them separately deletes the other kind's live sub-link. It first raises an admin-down parent (kernel `ENETDOWN` otherwise) unless err-disabled, where `ENETDOWN` on the sub-link `up` is deferred to the next resync (#338).
- **Bonds are always `BondMode::BalanceXor`** (`bond_mode_of`), for `Xor` and `Lacp`; never the kernel `Ieee8023Ad`, which would swallow LACPDUs. For `Lacp`, enslavement is gated on `Interfaces.lacp_active_members`, pushed by `nos-lacpd` (`PushLacpMembers`, applied at once by `driver.apply`) and carried forward by `build_from_config`, never rebuilt from config. A `PortAggregate.bfd` adds `bfd_up_members` (`PushBfdMembers`, `Role::Bfdd` only, same treatment): active = `lacp_ok && bfd_ok`, no push = not Up.
- **Link watcher.** `driver/links.rs`'s `LinkHub` mirrors the kernel link table (`RTMGRP_LINK` + 30 s re-dump) and `SubscribeLinks` streams it (snapshot first, again after lag; `observed: false` under noop). `ospfd`/`ospfv3d`/`stpd` only; the stream owns its connection.
- **Spanning tree (#326).** While `spanning-tree mode` is not `disabled` (`InterfaceState.stp.on`), a bridge port is DISABLED (`StpPortState::Blocking`; the kernel undoes BLOCKING on a `BR_NO_STP` bridge) with an ingress `flower`+`gact drop` BPDU trap (`driver/tc.rs`, protocol 802.2: untagged frames only, #322) until `nos-stpd` pushes a state (`SetStpPortStates`, remembered in `Interfaces.stp_port_states` like `lacp_active_members`). Off, it undoes only what it did (`StpMemory`: `nos-fdbd` also disables ports). Never touches a VXLAN port. `reconcile_stp_port` runs after every enslavement and every `up`. `SetErrDisabled` (#320, `Role::Stpd`) puts the port in `Interfaces.err_disabled` (carried over resyncs): `apply`/`ensure_port_aggregate` then write the link down instead of up. Kernel findings: `docs/internals/stp.md`.
- **Order inside a resync:** bridges, then bonds, then each interface's `apply`.
- **Cross-daemon links.** To `nos-ribd`: `GetVrfName`/`GetTableId` via `ServiceRef::RibTable`; "not resolvable yet" is normal and retried by the 10s `reconcile::REAPPLY_INTERVAL`. Served queries (`GetInterfaces`, `GetInterface`, `GetBroadcastDomain`, `GetPortAggregates`, `GetPortAggregate`) report desired state; `allowed` admits `Role::Ribd` to them, never to `PushLacpMembers`.

## Modules

| Module | Role |
|---|---|
| `main.rs` | Args (`--watchdog-socket`, `--listen-socket`, `--driver`, `--bridge-registry-path`, `--port-aggregate-registry-path`), shared `Arc<RwLock<Interfaces>>` |
| `state.rs` | `InterfaceState`, `BroadcastDomainState`, `PortAggregateState`, `Interfaces`, async `build_from_config` |
| `driver/` | `mod.rs` trait, `noop.rs`, `linux.rs`, `links.rs` (pure link table), `bridge_registry.rs`, `port_aggregate_registry.rs`, `rib_client.rs`, `tc.rs` (hand-built BPDU trap) |
| `reconcile.rs` | Diff-triggered full resync plus the 10s tick |
| `server.rs` | Status queries, `PushLacpMembers`/`PushBfdMembers`, `SetStpPortStates`/`FlushFdb`, `SubscribeLinks` stream |
| `driver/rib_client.rs` | One-shot queries over `nos_daemon::ipc::one_shot`; config/watchdog clients are `nos-daemon`'s |

Details: [internals](../docs/internals/interface.md) (driver call sequences, registries, daemon-to-daemon links, per-module notes), [interfaces](../docs/protocols/interfaces.md), [L2 switching](../docs/protocols/l2-switching.md), [port aggregation](../docs/protocols/port-aggregation-lacp.md).
