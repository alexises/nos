# nos-lldp — LLDP (IEEE 802.1AB) Daemon

A real, from-scratch Link Layer Discovery Protocol implementation for NOS (binary `nos-lldpd`, a single fixed process — see root `CLAUDE.md`'s "Process supervision" section; same reasoning as `nos-lacpd`/`nos-interfaced`/`nos-logd`: LLDP has no per-VRF/per-instance multiplicity to key a dynamic per-object spawn off).

## Scope

`nos-lldpd` runs one raw `AF_PACKET` socket per LLDP-enabled **physical** interface, transmitting this system's identity and recording the neighbors it hears. It **never touches rtnetlink** and owns no kernel state — `nos-interfaced` already brings every configured physical interface admin-up, which is all LLDP needs. It has `CAP_NET_RAW` only. It exists as its own daemon (rather than a module of `nos-interfaced`) because it parses untrusted frames from the wire: a bug in a decoder should not take down interface reconciliation.

Config is two independent booleans on `Interface` (`lldp_transmit`, `lldp_receive`, both off by default, physical interfaces only — `valid_lldp_physical_only` rejects them on a `loopback-*` interface at commit time). CLI: `set|delete interface <name> lldp transmit|receive`, and `show lldp neighbors`. A member of a `PortAggregate` is an ordinary `Interface`, so LLDP runs on the physical members, never on the bond device (as the standard requires).

Three more knobs, none of which enable LLDP by themselves:

- **Timers** (system-wide, `Config.lldp`, `nos_proto::LldpSettings`): `set lldp tx-interval <secs>` (`msgTxInterval`, 1–3600, default 30) and `set lldp tx-hold <n>` (`msgTxHold`, 1–100, default 4). The advertised TTL is `hold × interval` (default 120s) and `LldpSettings::check` rejects a product over 65535, since the TTL field is 16 bits and the two ranges alone allow 360000. The daemon reads them through `LldpSettings::effective_*`, the same helpers the validator uses.
- **Management address** (system-wide): `set lldp management-address <ip>` — one IPv4/IPv6 unicast address, advertised on every LLDP-enabled link. It is taken as configured, not checked against any interface's addresses.
- **Destination group** (per interface, `Interface.lldp_destination`): `set interface <name> lldp destination nearest-bridge|non-tpmr|customer-bridge` → `01:80:C2:00:00:{0E,03,00}`. Physical interfaces only, like the on/off flags.

A change to any of these restarts the affected links (`LinkConfig` equality): a shutdown LLDPDU, then a fresh advertisement, so neighbors briefly drop and relearn. Not worth an in-place timer hot-swap.

## What is sent

`link::local_pdu`: Chassis ID (subtype 4, a MAC), Port ID (subtype 5, the interface name), TTL, Port Description (interface name), System Name (the config's `hostname`), System Description (`nos <version>`), System Capabilities, Management Address (if configured), End.

- **Capabilities**: *supported* is always Router|Bridge; *enabled* is Router, plus Bridge when the interface has a `switching_profile` (`LinkConfig.bridge`) — i.e. when it is actually a bridge port.
- **Management Address TLV**: address subtype 1/2 (IPv4/IPv6), interface numbering subtype 1 ("unknown", number 0 — the address is system-wide, not tied to this port), no OID. The shutdown LLDPDU carries none.

- **Chassis MAC** is a locally-administered unicast MAC derived (FNV-1a) from the machine's hostname + machine-id (`reconcile::local_system_id`, copied from `nos-lacp`'s Actor System ID — same `ponytail:` caveat: two machines sharing both would collide and ignore each other as "our own frame"; upgrade path is a persisted random id file).
- **Destination** is the interface's configured group (default "nearest bridge" `01:80:C2:00:00:0E`). The socket joins that one group and the shared receive path drops any frame not addressed to it, so two ends on different groups never see each other — including each other's shutdown LLDPDU (the old group still gets it when one side reconfigures first). One group per interface; sending on several is not supported.

## Behavior worth knowing

- **Shutdown LLDPDU.** When a link with `transmit` stops for any reason (config change, interface removed, daemon shutdown), `link::run` sends a TTL-0 LLDPDU (`shutdown_pdu`, mandatory TLVs only) on the way out. Receivers drop the neighbor immediately instead of waiting out the 120s TTL. `nos-e2e lldp` depends on this.
- **Immediate reply to a *new* neighbor** (`link::handle_rx` returns `true`): a simplified 802.1AB fast-start. Without it a peer that came up after us would learn us only at our next 30s tick. Only a `New` neighbor triggers it — a refresh never does — so two systems settle after one exchange rather than ping-ponging.
- **Neighbor identity** is (chassis id, port id), so one chassis heard on two ports is two neighbors. `NeighborTable` is capped at `MAX_NEIGHBORS_PER_LINK` (32) per interface: input is untrusted, and a hostile segment must not be able to grow the table without bound (802.1AB models the same limit as "too many neighbors"). Existing neighbors can still refresh when full.
- **Own frames are ignored twice**: `socket::payload_of_foreign_frame` drops frames whose source MAC is the port's own (an `AF_PACKET` socket also sees its own outgoing frames), and `link::handle_rx` drops any LLDPDU carrying our own chassis id (a looped cable or mirror port).
- **A down link is not fatal, and a down send is retried in 1s.** `ENETDOWN` on read/send is retried/skipped (`socket::is_link_down`); a periodic transmit that finds the link down is retried after `LINK_DOWN_RETRY` (1s) rather than waiting out the 30s interval — found by the e2e phase: `nos-interfaced` admin-ups a newly-configured interface on its own schedule, so the link task's first (immediate) transmit can lose that race; a task that ends on its own (socket can't open because the interface isn't in the netns yet, or a hard read error) is respawned by `reconcile` on its next resync.
- **Never leave an elapsed deadline armed** — the same rule as `nos-lacp/CLAUDE.md`. The expiry branch of `link::run`'s `select!` is guarded by `deadline.is_some()`, and handling it removes the entry the deadline belonged to.

## Decode robustness

`packet::decode` is the one place untrusted bytes are parsed. It bounds-checks every TLV length, requires the first three TLVs to be Chassis ID, Port ID and TTL in order (and rejects a repeat of them), skips unknown/organizationally-specific TLVs, ignores anything after the End TLV (Ethernet padding), and never panics. The Management Address TLV is optional and untrusted, so a truncated, internally inconsistent, or non-IP one is *skipped* rather than rejecting the whole LLDPDU (which would hide the neighbor), and at most `MAX_MANAGEMENT_ADDRESSES` (4) are kept per LLDPDU since every one is stored and printed. Free-text TLVs (Port Description, System Name/Description) have control characters replaced at decode time (`packet::lossy`), since they are printed into `nos-cli` output and logs and a neighbor is untrusted — an ANSI escape sequence or carriage return must not reach an operator's terminal; Chassis/Port IDs go through the same check in `text_or_hex`. Each rejection path has a unit test.

## Explicitly deferred (documented, not silently missing)

- **LLDP-MED / DCBX / other organizationally-specific TLVs** (received ones are skipped, never stored). NOS has no voice VLAN, PoE, location or QoS/PFC/ETS feature for them to describe, so nothing could honestly be advertised.
- **Several destination groups per interface** — one group each, chosen in config.
- **Full 802.1AB txFast burst** — replaced by the single immediate reply to a new neighbor above.
- **Bridge capability e2e** — the bit is unit-tested (`link::local_pdu`, `reconcile::desired_links`); an e2e would need a switching-profile port on the veth link.

## Modules

| Module | Role |
|--------|------|
| `main.rs` | Single-instance daemon args (`--watchdog-socket`, `--listen-socket`, `--log-socket` — the same shape as `lacp/src/main.rs`); resolves `nos-configd` via the broker, starts `server::start`, spawns `reconcile::run`. On shutdown signal every running link sends its shutdown LLDPDU before the process exits |
| `packet.rs` | Hand-rolled TLV encode/decode — pure, no I/O, round-trip and reject tests in-file. `Lldpdu::chassis_display`/`port_display`/`enabled_capability_names` render the wire values for `show lldp neighbors` |
| `socket.rs` | A thin wrapper over the shared `nos-l2-socket` crate (`l2-socket/`, also used by `nos-lacp` — a leaf crate, so the star dependency graph holds): `open(interface, group)` fixes ethertype `0x88CC` and the receive buffer. The raw `AF_PACKET`/`unsafe` code lives there, not here |
| `neighbor.rs` | Pure `NeighborTable` — `apply` (`New`/`Refreshed`/`Removed`/`Ignored`), `expire`, `next_expiry`, `snapshot`. The caller passes `now` in, so aging is unit-tested without sleeping |
| `link.rs` | Per-interface task — `run()` owns the socket and drives it with `tokio::select!` over the 30s transmit ticker, the receive socket, and the next-expiry deadline. `handle_rx`/`expire`/`local_pdu`/`shutdown_pdu` are separately unit-tested. `SharedNeighbors` (`Arc<Mutex<HashMap<interface, NeighborTable>>>`) is what `server.rs` reads |
| `reconcile.rs` | Subscribes to `DiffScope::{Interfaces, Hostname}` purely as a resync trigger, always re-fetching the whole config, and keeps one link per interface with either flag set. A change to that interface's flags or to the hostname (System Name) restarts its link (`LinkConfig` equality); a finished task is respawned; a fixed 10s safety-net tick retries a link whose interface wasn't there yet. `desired_links` is the pure, unit-tested part |
| `server.rs` | Serves `nos_proto::lldp`'s `LldpRequest::GetNeighbors` on `--listen-socket` (default `/run/nos/lldp.sock`, registered with the broker as `ServiceRef::Lldp`). Read-only. Backs `nos-cli`'s `show lldp neighbors` |
| `config_client.rs` / `watchdog_client.rs` | Own reimplementations (`fetch_config`/`subscribe_diff`, `resolve_with_retry`/`resolve_once`) — per the root `CLAUDE.md`'s star dependency graph, not shared with the other daemons |

## `nos-e2e lldp`

Real two-container verification (see root `CLAUDE.md`'s "Two-router end-to-end verification"). It reuses the `lacp` scenario's direct veth pairs (`World::link_veths`) between the two routers' network namespaces: a docker network is a Linux bridge, and a bridge never forwards `01:80:C2:00:00:0E` (it is in the reserved link-local group range), so no LLDPDU could ever cross one. It enables `lldp transmit` + `lldp receive` on both routers' `eth1` and confirms each `nos-lldpd` logs `lldp neighbor learned` with the other's System Name (`--hostname` in `nos-provision`, since both would otherwise advertise the default `nos`) and port id `eth1`. It then turns transmit off on router-b and confirms router-a logs `lldp neighbor removed … reason="shutdown"` (tracing quotes a string field) **within 30s** — far under the 120s TTL, so passing proves the TTL-0 shutdown frame is handled, not that the entry aged out. Then transmit comes back and both sides learn each other again (router-b within 15s, well inside router-a's 30s interval, because of the immediate reply to a new neighbor). Dropping receive on router-a restarts its link transmit-only, and disabling everything stops the link.

The TTL-expiry path itself (`NeighborTable::expire`, `link::expire`) is not exercised end to end — a real 120s wait isn't worth the CI time — and is covered by injected-clock unit tests instead. `show lldp neighbors` isn't exercised by the e2e phase either (`nos-cli` has no scriptable one-shot mode, see root `CLAUDE.md`); the `LldpRequest::GetNeighbors` round trip is covered by `lldp/tests/server.rs` (real socket) and `cli/tests/lldp_client.rs`.
