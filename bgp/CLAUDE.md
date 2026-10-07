# nos-bgp — BGP Component

BGP-4 implementation for NOS (binary `nos-bgpd`, one process per `BgpInstance`, dynamically spawned by `nos-watchdog` — see `docs/architecture/supervision.md`).

Details: behaviour and config in `docs/protocols/bgp.md`, `docs/protocols/evpn-vxlan.md`, `docs/protocols/routing-policy.md`; how it is built (functions, log lines, `ponytail:` ceilings, per-feature walk-throughs) in `docs/protocols/bgp-internals.md`; e2e phases in `docs/e2e-phases.md`. This file keeps only the rules to respect when editing the crate.

## Scope

`nos-bgpd` resolves its peers and VRF from `nos-configd`, runs the RFC 4271 FSM over VRF-scoped TCP, keeps the RIBs, and pushes best routes to the owning `nos-ribd` and EVPN routes to/from `nos-fdbd`/`nos-ribd`. `bgp/TODO.md` lists what is open.

## VRF resolution

`BgpInstance.routing_table` is a reflexive field (`proto/CLAUDE.md`); `nos-bgpd` resolves it to a Linux VRF name through `ServiceRef::RibTable` + `RibRequest::GetVrfName` (`session::VrfRequirement`):
- `Invalid` (no owning table): a config error, never a "default VRF" fallback; nothing is opened, error logged every resync.
- `Pending` (table exists, VRF not yet created): transient, `debug` log, retried by the 10s tick (VRF readiness is no config diff).
- `Resolved(name)`: the only state in which anything opens.

## Raw TCP session model

- Per peer, an active retry loop plus one shared passive listener (`0.0.0.0:179` + `[::]:179`), both scoped into the VRF by `SO_BINDTODEVICE` (`tcp.rs`).
- Skip dialing while `PeerSlot::is_established` (either role), or every tick causes a collision.
- Retry sleep is jittered `[0.75, 1] x connect_retry_time` (`session::jittered`) and each `tcp::connect` is bounded by it, so an unanswered SYN (`SYN_SENT` flake, #158) can't hold the Active role ~2 min.
- **Both roles must be stopped on reconcile.** `peer_tasks` owns only the active loop; passive sessions live on the `PeerSlot` (`set_passive_task`/`stop_passive`). Both stops are `abort()`s that skip `fsm::run`'s exit path, so `reconcile_peers` calls `BgpRib::peer_disconnected` itself, or Adj-RIB-In/`peer_outbox` outlive the session and routes stay in the Loc-RIB.

## Session authentication

- Socket-level only: `fsm.rs` never sees it. MD5 or TCP-AO, mutually exclusive (one per socket); raw `setsockopt` lives in `nos-tcp-auth`, `nos-bgp` only calls its safe wrappers. `reconcile::resync` -> `session::ResolvedAuth`; any change restarts the peer (`diff_peers`) except what `session::ao_delta` expresses.
- The listener is shared, so keys are installed on the listening socket scoped per peer address (`applied_auth`, `sync_listener_auth`; `spawn_listeners` primes them on every bind).
- `tcp::apply_auth(on_listener)` strips `set_current`/`set_rnext` for a socket in `LISTEN` (`TCP_AO_ADD_KEY` returns `EINVAL` otherwise); the active side keeps them.
- `nos_tcp_auth::add_ao_key`/`delete_ao_key` set `ifindex = 0`, not `-1` (only meaningful with `TCP_AO_KEYF_IFINDEX`, never used); anything else is `EINVAL` and blocks every key install.
- Hitless rollover (#83): the kernel does RFC 5925 §7.5.2 per connection; config `is_current` only seeds new connections. `ao_delta` returns `None` (restart) for MD5, a kept key whose RecvID/algorithm/secret/`exclude_options` changed, or an add reusing a removed RecvID. Otherwise an Established session gets `FsmCommand::UpdateAo`, `PeerSlot::auth()`/`set_auth()` seed new connections. Only rnext is pushed to a live socket (also on accept), never `set_current`; any error (expected `EBUSY`) resets.

## GTSM / `max-hops`

`tcp::bind_listener` always sets TTL 255 or a GTSM active side drops the SYN-ACK; the minimum TTL is per socket (`apply_max_hops`).

## BGP finite state machine

- `fsm::step` is the pure transition core, unit-tested; `fsm::run` owns the framed socket and timers. `UPDATE`/`ROUTE_REFRESH` bypass `step` (short-circuited in `run`'s read branch, meaningful only once `Established`).
- Every well-formed inbound message resets the hold timer (RFC 4271 §4.4), centrally in the read branch.
- Hold/keepalive/connect-retry defaults and floors live in `nos_proto` because `nos-config` validates the same rules; the OPEN check order is in the internals page.
- The `PeerSlot` command channel is polled only while `Established` (collision resolves before), so one task contends for it.
- 4-octet AS: `AS_TRANS` without capability 65 is a bad peer AS; a peer without it gets `BgpCodec::two_octet_as` (`AS4_PATH` merge). RFC 9072 OPEN is emitted only above 255 bytes.

## Aggregation (#78)

All in `rib/aggregate.rs`: runs before `fan_out` in `recompute_and_propagate`; the aggregate is a local candidate in `BgpRib.aggregated`, next-hop-self and never pushed to `nos-ribd` (no discard route); a route-server client's `propagate_add_path` view is untouched. Ceilings are `ponytail:` comments there. `ATOMIC_AGGREGATE`/`AGGREGATOR` pass through verbatim; RPL cannot read them. A loop-dropped received route is an implicit withdraw (`withdraw_announced`).

## Malformed UPDATE (RFC 7606)

`parse_update` resets the session only for framing errors; a bad attribute value or missing mandatory attribute is treat-as-withdraw, rewritten there (NLRI -> `withdrawn_routes`, `mp_reach` -> `mp_unreach`, `attributes = None`), so `BgpRib::handle_update` needs no special case.

## Damping

Penalty is keyed by (peer, prefix) in `damping::Damping`; an identical re-announcement is no change (keeps `received_at`, no re-propagation, #160).

## Collision resolution

`collision::PeerSlot` is shared by both roles. An already-`Established` connection beats an ID compare; a tie keeps the first registered. `fsm::run` calls `BgpRib::peer_disconnected` **only if it registered** (its `registered` flag), or a collision loser wipes the winner's `adj_rib_in`/`peer_outbox`; guarded by `handshake.rs`'s `collision_leaves_exactly_one_side_running`.

## Administrative shutdown

`session::cease_reason` picks the Cease subcode for every session `reconcile_peers` stops (2 shutdown with an RFC 9003 message, 3 de-configured, 6 other change); `FsmCommand::Cease` carries already-encoded `data`.

## Maximum prefixes

Counters (`path_counts`) are kept only by `put_path`/`take_path`, the sole Adj-RIB-In mutators (`prefix_counters_match_a_recount_through_every_mutation`). The hold lives on `PeerSlot`; the Cease is queued once (a queued command outlives the session). 

## Route refresh

Route Refresh (2) and Enhanced (70) are advertised unconditionally. The RFC 7313 stale deadline is one per family, scoped to the session (`stale_until`). `send_route_refresh` sends nothing without the peer's capability.

## RPKI

Runs inside `nos-bgpd` (owner decision on #17). `BgpRib::set_vrps` re-validates in place; only peers whose import policy `reads_validation_state()` are route-refreshed, 5s after the first change of a burst. RFC 8097 wire order (0 valid, 1 not-found, 2 invalid) differs from `nos_rpl::ValidationState`'s discriminants.

## Graceful restart (#12)

- Pure decisions in `gr.rs`; F bit from `BgpRib::gr_forwarding`; `peer_disconnected(peer, Disconnect)` with `Transport`/`Graceful`/`Hard` (`fsm::disconnect_kind`).
- A Cease with N exchanged goes out as a Hard Reset (subcodes 1-4); 6 stays graceful. SIGINT sends Cease/Administrative Shutdown first (`SessionManager::shutdown`) so peers stop forwarding to a vanished VRF.
- Deferral (`gr::Deferral`) blocks every outbound path (`fan_out`, `propagate_add_path`, `resend_all`, EVPN, `push_snapshot`) and also waits for `nos-ribd`'s first redistribution `Full` (`redistribute_seen`).

## Confederations, local-as, roles

- `session::PeerKind` (`Internal`/`ConfedExternal`/`External`) drives what each peer sees; `ResolvedPeer::open_as` gives the OPEN AS, `PeerOutbox::prepend_external` (shared by `build_advertisement` and `evpn_out::advertise`) the path prepend.

| Toward | OPEN `My AS` | AS_PATH |
|---|---|---|
| `Internal` | member AS | unchanged |
| `ConfedExternal` | member AS | member AS in an `AS_CONFED_SEQUENCE` |
| `External` | identifier (or `local-as`) | confed segments stripped, identifier prepended |

- Step 6 ranks external > confed-external > internal (`peer_rank`); the RFC 4456 gate stays keyed on `Internal`. RPL sees the flat path (`AsPath::flat`).
- Validation: `bgp_instance::valid_local_as`/`valid_role`/`valid_route_reflection_and_server`. Roles/OTC (#220, #221): `fsm::negotiate_role`, `otc_leak`.

## Route reflection / route server

Route-server candidates (`rs_candidates`) are never filtered by feasibility or aggregates (RFC 7947 transparency).

## ADD-PATH (#13)

- The codec's rx set (reader `add_path_afis`) and tx set (writer) differ; encoding writes an id whenever the update has one, so the RIB must never hand a tx session an id-less NLRI.
- `propagate_add_path` runs first in `recompute_and_propagate`, before the "best unchanged" return (a non-best path can change the top N), and beside `fan_out` in `aggregate.rs`.
- A path keeps its id while selected; an entering path takes the lowest freed id, else `add_path_next_id` (monotonic per (peer, prefix), `ponytail:` never recycled). Step 10 compares `(peer, path id)`.

## Communities

Well-known values get no suppression; the RFC 4360 transitive bit is enforced on eBGP export (#162).

## EVPN and MAC mobility

- `AddressFamily::L2vpnEvpn` is appended last in the enum (postcard indexes by position). `evpn_adj_rib_in` is keyed by `EvpnNlri::route_key` (attribute fields zeroed, #188); import policy and best path do not apply (RFC 7432 §15 aside).
- MAC mobility has **no withdraw**: a sequence number only means something relative to the last one seen, so `MacMobility` forgets a `(VNI, MAC)` only after an hour of silence (`EXPIRE`).
- Same ESI is not a move (#172): `MacMobility::holds`; otherwise PEs on one segment bump each other into a frozen duplicate.
- `nos-bgpd` is dumb about origination: `nos-fdbd`/`nos-ribd` supply RD, RTs, VTEP and VNI (`evpn_local` keyed by `EvpnSource`); `fdb_push_client` polls every 1s and Route-Target filtering is the consumer's.

## Backup path, multipath (#70)

`backups`/`multipaths` are updated before the `unchanged` early return so a sibling reaches `nos-ribd` through the 1s poll without touching Loc-RIB or advertisements; only `best` is advertised. Multipath = ties on steps 1-7 plus the same neighbouring AS; a backup must not share an installed next hop.

## IGP cost, next-hop feasibility

`igp_client.rs` polls `nos-ribd` every 2s (`RibRequest::IgpCosts`). Infeasible candidates (`next_hop_feasible`) leave the decision and the backup pick entirely, except before the first `set_igp` (`igp_ready`) and for route-server clients. `set_igp` re-decides every Adj-RIB-In prefix, not only the Loc-RIB.

## Memory profiling

`--features dhat-heap` swaps in `dhat` (how-to: `docs/architecture/development.md`).

## Performance

Known ceilings (single `Mutex<BgpRib>`, one prefix per UPDATE, per-route `info!`) are quantified by `tools/bench-bgp.sh`: run it around RIB hot-path changes. `RibRoute::as_path`/`cluster_list` are `Arc<Vec<_>>`; `Arc::make_mut` in `build_advertisement` is the one real copy.

## Modules

| Module | Role |
|--------|------|
| `main.rs`, `reconcile.rs` | Startup, resync on diffs plus a 10s tick (`classify_vrf`, `restart_check`) |
| `session.rs`, `tcp.rs`, `collision.rs` | `SessionManager`, `diff_peers`, `ao_delta`; VRF-scoped sockets; `PeerSlot` |
| `fsm.rs`, `status.rs`, `gr.rs`, `mrai.rs`, `damping.rs`, `mac_mobility.rs` | State machine and per-peer state |
| `message.rs`, `evpn.rs`, `as_path.rs` | Wire codecs (`BgpCodec` is BGP, not postcard) |
| `rib.rs`, `rib/` | Adj-RIB/Loc-RIB, decision, `aggregate.rs`, `evpn_out.rs` |
| `rib_push_client.rs`, `fdb_push_client.rs`, `igp_client.rs` | 1s/2s polls to `nos-ribd`/`nos-fdbd` (`ponytail:` `Notify` if sub-second); a `nos-ribd` restart goes unnoticed until the next change |
| `config_client.rs`, `watchdog_client.rs`, `rib_client.rs` | Reimplemented clients (star dependency graph) |
| `rpki/`, `server.rs` | `vrp.rs`/`rtr.rs`; `--listen-socket`, `allowed(role, &request)` with no wildcard arm |

Tests: `bgp/tests/` (`handshake.rs`, `session.rs`); e2e phases per feature in `docs/e2e-phases.md`.
