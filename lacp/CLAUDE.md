# nos-lacp — LACP (IEEE 802.1AX) Daemon

A real, from-scratch Link Aggregation Control Protocol implementation for NOS (binary `nos-lacpd`, a single fixed process — see root `CLAUDE.md`'s "Process supervision" section for why, the same reasoning as `nos-interfaced`/`nos-logd`: `PortAggregate` has no per-VRF/per-instance multiplicity to key a dynamic per-object spawn off).

## Scope and the critical design boundary

`nos-lacpd` runs the real protocol — raw `AF_PACKET` LACPDU exchange and the IEEE 802.1AX Actor/Partner state machines — for every `Lacp`-mode `PortAggregate`'s member ports. It **never touches rtnetlink and never creates or modifies the kernel bond device itself**. `nos-interfaced` remains the sole owner of that (`ensure_port_aggregate`/`port_aggregate_registry`, see `interface/CLAUDE.md`); `nos-lacpd` only computes which member ports are currently negotiated into the aggregate and pushes that decision over IPC (`InterfaceRequest::PushLacpMembers`, fire-and-forget, the data-plane-push pattern this NOS already uses for `RibRequest::PushBgpRoutes`).

**The kernel bond is created identically for `Xor` and `Lacp` modes** — `BondMode::BalanceXor` in both cases (`interface::driver::linux::bond_mode_of`). It must never be created as the kernel's own `BondMode::Ieee8023Ad`: that mode installs an `rx_handler` on every slave that intercepts slow-protocol (ethertype `0x8809`) frames in-kernel before userspace ever sees them, which would silently starve `nos-lacpd`'s own raw sockets of every LACPDU it needs — defeating the entire from-scratch design. The `PortAggregateMode` only changes which control plane decides *membership*, never the kernel driver's own bonding algorithm.

## The state machines (802.1AX §6.4, simplified for this crate's model)

Each currently-configured member port gets its own `link::run` task (spawned/stopped by `aggregate::AggregateManager`, one per `Lacp`-mode `PortAggregate`, mirroring `ospf::link::LinkManager`), running three interacting machines:

- **Receive Machine** (`receive_machine.rs`, §6.4.12): `Expired`/`Defaulted`/`Current`. Simplified from the full standard's six states — `Initialize`/`PortDisabled`/`LacpDisabled` collapse into the task's own startup (`Event::Started`, entered once, never revisited), since a `link::run` task exists only while its port is a configured, running aggregate member in the first place; there's no separate "port administratively disabled but task still alive" state to model. `Current`'s own timeout duration (`Current_While_Timer`) follows *our own* configured `lacp-rate` (Short 3s for `fast`, Long 90s for `slow`) — 802.1AX §6.4.12: the timer measures how long *we* tolerate silence from the partner, and our advertised `LACP_Timeout` bit is what tells the partner how fast to send.
- **Periodic Transmission Machine** (`periodic_tx_machine.rs`, §6.4.13): `interval_for(receive_state, partner_wants_fast)`. Always Fast (1s) while there's no live partner (`Expired`/`Defaulted`) — fast-until-heard matters because a port whose link comes up after its first send would otherwise sit silent for a whole Slow interval. Once `Current`, the interval follows the **partner's** advertised `LACP_Timeout` bit (Fast 1s if it asked for short timeouts, else Slow 30s), per the standard: the partner's timeout bit says how often *it* expects to hear from us.
- **Transmit on change, not on receipt** (`link::needs_transmit`, 802.1AX's NTT): an event-driven send happens only if the PDU we'd advertise differs from the last one sent. Replying to *every* received LACPDU made two peers ping-pong at wire speed; with this they settle as soon as their states agree.
- **Mux Machine** (`mux_machine.rs`, §6.4.15/Figure 6-11): `Detached`/`Waiting`/`Attached`/`Collecting`/`Distributing`, including a real (if short, `AGGREGATE_WAIT_TIME` = 2s) `Waiting` state — 802.1AX's own aggregate-wait-time settling period, kept faithful to spec despite this crate having no dynamic cross-aggregate reassignment to actually protect against. **`Distributing` is the only state in which a port belongs in the active-member set pushed to `nos-interfaced`.**

Each machine is a pure `step(state, event) -> (state, Action)` function, unit-tested directly per transition — no I/O, mirroring `ospf_common::neighbor`'s own pure-step precedent. `link.rs` is the impure, I/O-owning caller: owns the `socket::LacpSocket`, drives the three machines off real timer ticks and real received LACPDUs, and reports every observable change (Receive state → `current`, last-recorded partner identity, Mux state) into a shared map (`link::PortObservation`) that `aggregate::AggregateManager`'s own background task consumes.

**Internal state is never `nos_proto::lacp`'s wire types directly** (`ReceiveState`/`MuxState` in this crate vs. `nos_proto::LacpReceiveState`/`LacpMuxState`) — same convention as `ospf::link::InterfaceState` vs. `nos_proto::LinkInterfaceState`: this crate's own state isn't necessarily wire-serializable forever.

### `lacp-rate` (LACP fast)

`PortAggregate.lacp_rate` (`LacpRate::{Slow (default), Fast}`, `set port-aggregate <name> lacp-rate fast|slow`) is the one CLI-exposed protocol knob. It drives two things on every member port, both from the same value (`link::LinkConfig.rate`):

- the **TIMEOUT bit** we advertise in Actor_State (`link::actor_state_byte`) — set means "send to me every 1s";
- **our own** `Current_While_Timer` duration (3s vs 90s, `receive_machine::Event::LacpduReceived { we_advertise_short_timeout }`).

Our own *transmit* rate is deliberately **not** driven by our own `lacp-rate` — it follows what the partner asks for (see above). So two peers with different rates interoperate: each sends at the rate the other requested and tolerates silence for the duration matching its own request. A rate change re-runs `aggregate::AggregateManager::reconcile`, which restarts member links (a rate can't be swapped into a live `link::run`).

## Selection Logic — deliberately config-scoped (§6.4.14, narrowed)

`selection.rs` never discovers aggregate membership from the wire the way real 802.1AX Selection Logic does. `PortAggregate` membership is already a config-defined, operator-fixed reference (`Interface.port_aggregate`), and the kernel bond device is already fixed by `nos-interfaced` independent of LACP — so `select` only ever compares ports already belonging to the *same configured* aggregate, and its job is to confirm the wire agrees with what was configured (every `Current` port reporting a consistent partner system-id + key), not to replace config-driven membership with wire-driven discovery. A `Current` port whose partner identity disagrees with the aggregate's majority is excluded — a basic split-detection, tie broken by input order for determinism. This is the deliberate, permanent v1 design, not a temporary cut.

Re-run by `aggregate::AggregateManager`'s background `selection_loop` task every time any port's observation changes (edge-triggered via a `tokio::sync::Notify`, not polled) — its outcome both feeds each port's own `mux_machine::Event::SelectionChanged` (via a per-port `tokio::sync::watch` channel) and, together with each port's live `MuxState`, recomputes the `Distributing`-state subset pushed to `nos-interfaced`.

## Actor identity — no new persisted registry

Unlike `interface::driver::port_aggregate_registry`'s YAML-backed bond-id allocator, LACP's Actor identity needs no persisted file:

- **System ID**: a locally-administered unicast MAC derived (FNV-1a) from the machine's hostname and machine-id (`aggregate::local_system_id`), fixed for the life of the process — deliberately **not** derived from any member port. Bonding rewrites its slaves' MACs (the first slave enslaved lends its MAC to the bond, every other slave takes it over), so a port-derived ID changed whenever enslavement order did, which restarted every link in a loop. `ponytail:` two machines sharing both hostname and machine-id would collide; upgrade path is a persisted random id file. **Overridable per aggregate** with `PortAggregate.lacp_system_id` (`set port-aggregate <n> lacp-system-id <mac>`): `AggregateManager::reconcile` takes it as `Option<[u8; 6]>` and, like a `lacp-rate` change, restarts every member link when the effective id changes. Its purpose is EVPN multi-homing — two PEs sharing an ESI must present the same actor to the customer device, or it can't bundle its links across them — see `fdb/CLAUDE.md`.
- **Key**: assigned sequentially in-process, per aggregate name, the first time `reconcile.rs` sees it — not persisted (only needs to differ between simultaneously-active aggregates on this instance).
- **System/Port Priority**: fixed `32768` (802.1AX default). **Port Number**: the member's real kernel ifindex (masked to 16 bits).

`lacp-rate` is the only CLI-exposed knob (see above) — priorities remain hardcoded 802.1AX defaults.

## Robustness rules learned the hard way (each has a regression test)

Every one of these was a real hot loop or stall found by running `nos-e2e lacp` against real containers:

- **Never leave an elapsed deadline armed.** `link::run` uses `sleep_until(deadline)` arms; a deadline left in the past re-fires on every loop iteration, flooding the log and the wire. Handling any timer-expiry event must move its deadline forward (`apply_mux_action`/`apply_receive_action`) — but `Action::None` must *not* disarm a still-pending timer.
- **Ignore our own frames.** An `AF_PACKET` socket also receives its own outgoing frames (`socket::payload_of_foreign_frame` drops them by source MAC); otherwise a port negotiates with itself.
- **Only signal on a real change.** `watch::Sender::send` wakes the receiver even for an identical value, so `aggregate::set_if_changed` and `link::report`'s dedupe exist to break the report → re-select → notify feedback loop.
- **A down link is not fatal.** `ENETDOWN` on read/send (link administratively down, or just coming up) is retried (`socket::is_link_down`), not a reason for the link task to exit; a task that does end on its own is respawned by `reconcile`.

## Explicitly deferred (documented, not silently missing)

- **Marker Protocol** (§6.5) — only matters for guaranteed frame ordering during a live port move between aggregators; irrelevant with config-fixed membership.
- **Full dynamic cross-aggregate Selection Logic** — see the Selection Logic section above; permanent, not temporary.
- **Per-port priority/system-priority knobs** — fixed at the 802.1AX default (32768).

## Modules

| Module | Role |
|--------|------|
| `main.rs` | Single-instance daemon args (`--watchdog-socket`, `--listen-socket`, `--log-socket` — mirrors `interface/src/main.rs`'s shape, not `ospf/src/main.rs`'s per-`--instance` one), resolves `nos-configd` via the broker, starts `server::start`, spawns `reconcile::run` and `interface_client::run` sharing one `mpsc` channel |
| `packet.rs` | Hand-rolled LACPDU encode/decode (802.1AX §6.4.2.3 Figure 6-2's fixed 110-byte layout: Actor/Partner Information TLVs, Collector Information TLV, Terminator TLV) — pure, no I/O, round-trip unit-tested in-file, mirroring `ospf::packet`'s style. No parsing crate: the LACPDU has no variable-length fields |
| `socket.rs` | A thin wrapper over the shared `nos-l2-socket` crate (`L2Socket`, also used by `nos-lldp`) fixing its ethertype/group/buffer; `LacpSocket` — a raw `AF_PACKET`/`SOCK_RAW` socket bound to **one physical member interface** (never the bond, never a VRF — same reasoning as `ospf::socket`'s own interface-scoped bind: no demux, so binding wider leaks other links' traffic), restricted to ethertype `0x8809` and joined to the slow-protocols multicast MAC `01:80:C2:00:00:02` via `PACKET_ADD_MEMBERSHIP` (most NIC drivers otherwise never pass an arbitrary multicast destination up to userspace at all). The raw `libc`/`unsafe` (`sockaddr_ll` construction, `PACKET_ADD_MEMBERSHIP`'s `packet_mreq`) now lives in `l2-socket/`, not here. The shared `recv` also drops frames not addressed to the joined group — LACPDUs only ever go to `01:80:C2:00:00:02` |
| `receive_machine.rs` | §6.4.12 Receive Machine — pure `step`, see above |
| `periodic_tx_machine.rs` | §6.4.13 Periodic Transmission Machine timing (`interval_for`) — see above |
| `churn_machine.rs` | §6.4.17 Actor/Partner Churn Detection — pure `step`; `link.rs` runs one per side per port (60s, `NOS_LACP_CHURN_SECS` shortens it for e2e). Beyond the standard's diagnostic-only role, a port with either side `Churn` is left out of the active-member set (no traffic on it); reported as `actor_churn`/`partner_churn` in `show lacp` / `GET /v1/lacp` |
| `mux_machine.rs` | §6.4.15 Mux Machine — pure `step`, see above |
| `selection.rs` | Config-scoped Selection Logic — pure `select`, see above |
| `link.rs` | Per-port owning struct + `run()` — mirrors `ospf::link.rs`'s per-link shape: owns the socket and all three state machines, drives them off real timer deadlines (`tokio::select!` over the periodic-send ticker, the `Current_While_Timer`, the Mux `Wait_While_Timer`, a `selected` watch-channel, and packet receive), reports every change into the shared observation map |
| `aggregate.rs` | `AggregateManager` — one per configured `Lacp`-mode `PortAggregate`; `reconcile` spawns/stops member `link::run` tasks (restarting *every* member if the resolved Actor System ID changes); an internal `selection_loop` task re-runs `selection::select` on every observation change, feeds each port's own `selected` channel, and pushes the recomputed `Distributing`-state set |
| `interface_client.rs` | Owns the persistent push connection to `nos-interfaced` (`InterfaceRequest::PushLacpMembers`) — full-resend-only (no `Full`/`Add`/`Remove` split like `RibRequest::PushBgpRoutes`; an aggregate has too few members for incremental batching to be worth the complexity), caching every aggregate's last-known state locally so a fresh/reconnected connection can resend everything in one pass |
| `server.rs` | Serves `nos_proto::lacp`'s `LacpRequest::GetSummary` on `--listen-socket` (default `/run/nos/lacp.sock`, registered with the broker as `ServiceRef::Lacp`), reading the shared `reconcile::SharedAggregates` map — each aggregate's `AggregateManager::summary()` (per-port Receive/Mux state, partner identity, `selected`/`synchronized`). Backs `nos-cli`'s `show lacp [<name>]`. Read-only: never touches an aggregate's state |
| `config_client.rs` / `watchdog_client.rs` | Own reimplementations (`fetch_config`/`subscribe_diff`, `resolve_with_retry`/`resolve_once`) — per the root `CLAUDE.md`'s star dependency graph, not shared with `nos-interfaced`/`nos-bgp`/etc |
| `reconcile.rs` | Steady-state loop: subscribes to `DiffScope::{Interfaces, PortAggregates}` purely as a resync trigger, always re-fetching the whole config, filters `port_aggregates` for `mode == Lacp`, resolves each one's member set from `Interface.port_aggregate`, drives one `AggregateManager` per name (creating/`shutdown`-ing as aggregates are added/removed from config) — plus a fixed 10s safety-net tick, mirroring `interface::reconcile`'s shape |

## `nos-e2e lacp`

Real two-container verification (see root `CLAUDE.md`'s "Two-router end-to-end verification"): both routers get a real `Lacp`-mode `PortAggregate` over two member links, proving real LACPDU exchange converges both sides' Mux Machines to `Distributing` on both links and that `nos-interfaced` only then enslaves each negotiated member into the real kernel bond. Both routers run `lacp-rate fast`, then the phase withdraws `eth2` from router-b's aggregate by config (router-b stops speaking LACP on it; the link stays up) and confirms router-a's own Receive Machine timeout and the resulting kernel-level release **within 30s** — far under the 90s Long timer, so passing proves the fast rate is really in effect — before tearing the aggregate down.

`show lacp` itself isn't exercised by the e2e phase: `nos-cli` has no scriptable one-shot mode (see root `CLAUDE.md`), so the `LacpRequest::GetSummary` round trip is covered by `lacp/tests/server.rs` (real socket, real `AggregateManager`) and `cli/tests/lacp_client.rs`.

**The member links are direct veth pairs between the two containers' network namespaces, not docker networks** (unlike the static `port-aggregate` phase): a docker network is a Linux bridge, and a Linux bridge never forwards the `01:80:C2:00:00:02` slow-protocols address (the kernel refuses to enable it — it's in the restricted link-local group range), so no LACPDU could ever cross one. A throwaway privileged helper container with iproute2 creates the pairs (`World::link_veths`). The link-loss check withdraws a member by config rather than taking a link down because each `nos-interfaced` re-applies "admin up" on every 10s resync, which would undo a `link set down`.
