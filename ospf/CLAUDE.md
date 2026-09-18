# nos-ospf — OSPF Component

OSPF daemon for NOS (binary `nos-ospfd`, one process per `OspfInstance`, dynamically spawned by `nos-watchdog` — see root `CLAUDE.md`'s "Process supervision" section).

## Scope

`nos-ospfd` resolves its own configured instance/areas/profiles from `nos-configd`, and runs a real RFC 2328 Hello protocol on every `Subinterface.ospf_profile` attach point — a real raw protocol-89 socket, VRF-scoped, joined to the AllSPFRouters (224.0.0.5) multicast group. This is a deliberately small first phase, matching how `nos-bgp` originally shipped OPEN/KEEPALIVE-only before route exchange landed later:

- **Neighbor FSM depth**: `Down` → `Init` → `TwoWay` only (`ospf::neighbor::NeighborState`). No DBD/LSR/LSU/LSAck, no LSDB, no `ExStart`/`Exchange`/`Loading`/`Full` — those need real LSAs to synchronize, which don't exist yet. `TwoWay` (both sides list each other in their Hellos) is this phase's "established" milestone.
- **Network type**: point-to-point only. Only `Subinterface.ospf_profile` attach points (a VLAN sub-interface modeling one link to one peer) get a real Hello FSM/socket. A loopback (`Interface.ospf_profile`) attach point has no peer to Hello with, and a `BroadcastDomain.ospf_profile` (multi-access SVI) attach point needs DR/BDR election (RFC 2328 §9.4) — both stay **log-only**, resolved purely from the already-fetched `Config` exactly as before this phase (`reconcile::attach_points_for`). Point-to-point OSPF still Hellos via multicast 224.0.0.5, not unicast — RFC 2328 has no unicast Hello — "point-to-point" here only means no DR/BDR election and at most one neighbor per link, keyed by router-id.

`OspfProfile` carries `hello_interval`/`dead_interval: Option<u16>` (`None` defaults to `HELLO_INTERVAL_DEFAULT`/`DEAD_INTERVAL_DEFAULT`, 10s/40s — RFC 2328 Appendix C.3's point-to-point defaults), validated (`dead_interval` must exceed `hello_interval` when both are set) the same way `BgpPeerGroup.hold_time`/`keepalive_interval` are, one level up on `OspfArea.profiles` (`ospf_profile::valid_profile_timers`). No `network_type`/`cost` field yet — every `Subinterface` attach point this phase touches is implicitly point-to-point, and cost has no meaning without real SPF.

## Modules

| Module | Role |
|--------|------|
| `main.rs` | Arg parsing (`--instance`, `--watchdog-socket`, `--listen-socket`, `--log-socket`), resolves `nos-configd`'s address via the watchdog broker before starting, SIGINT+SIGTERM shutdown wait, spawns `reconcile::run` and `server::start` sharing one `Arc<link::LinkManager>` |
| `config_client.rs` | Own `fetch_config` (`Request::Get`) / `subscribe_diff` (`Request::SubscribeDiff`) — reimplemented rather than shared with the other component crates, per the root `CLAUDE.md`'s star dependency graph |
| `watchdog_client.rs` | `resolve_with_retry` (used once at startup for `ServiceRef::Config`) and `resolve_once` (used every resync for `ServiceRef::RibTable`/`ServiceRef::Interfaces`, where "not available" must return quickly rather than block) |
| `rib_client.rs` | One-shot `get_vrf_name` — the client side of `RibRequest::GetVrfName`, reimplemented from `nos-bgp`'s own copy per the star dependency rule |
| `interface_client.rs` | One-shot `get_interface` — the client side of `InterfaceRequest::GetInterface`, likewise reimplemented from `nos-bgp`'s own copy |
| `packet.rs` | RFC 2328 Appendix A.3.1/A.3.2 Hello packet wire format (`encode_hello`/`decode_hello`) — pure, no I/O. Checksum is the standard RFC 1071 ones-complement-of-ones-complement-sum (same as IP/TCP/ICMP), **not** OSPFv3's Fletcher checksum or the LSA checksum (RFC 905 Annex B) — neither applies since this phase has no LSAs. Network mask, router-priority, and DR/BDR fields are always sent zeroed and ignored on decode — meaningless on a point-to-point link (RFC 2328 §10.5) |
| `neighbor.rs` | `step(NeighborState, Event) -> NeighborState` — the pure RFC 2328 §10.5 neighbor transition table, restricted to `Down`/`Init`/`TwoWay`, unit-tested directly with no I/O |
| `socket.rs` | `OspfSocket` — a raw protocol-89 socket, VRF-scoped via `socket2::Socket::bind_device` (`SO_BINDTODEVICE`, the same mechanism `bgp/src/tcp.rs` uses for TCP), joined to 224.0.0.5 on the link's own local address (`join_multicast_v4`). `recv_hello` strips the IP header raw sockets always deliver on receive (even without `IP_HDRINCL`) using the IHL nibble |
| `link.rs` | `LinkConfig`/`LinkStatus`/`run` — one point-to-point link's Hello send ticker + dead-interval inactivity timer + neighbor FSM driver, and `LinkManager`, the OSPF analogue of `bgp::session::SessionManager` (much smaller: no shared listener, no auth, no collision resolution). `LinkManager::reconcile` diffs desired links by attach-point (restart on any resolved-field change, exactly like `bgp::session::diff_peers`) and treats a link whose driver task ended on its own (e.g. socket-open failure) as "not currently running" so the next resync/re-apply tick respawns it |
| `reconcile.rs` | Steady-state loop: subscribes to `OspfInstances` diffs purely as a resync trigger, always re-fetching the whole config, plus a fixed 10s re-apply tick (same justification as `nos-bgp`'s own `REAPPLY_INTERVAL` — VRF/interface readiness is an external condition no config diff signals). Logs this instance's `router_id`/`routing_table`/areas/profiles and each profile's attached interfaces (`attach_points_for`, unchanged) exactly as before this phase; additionally resolves each `Subinterface.ospf_profile` attach point's VRF (`resolve_vrf`, mirroring `nos-bgp`'s) and local address (`resolve_local_address`, mirroring `nos-bgp`'s `resolve_source_address`) and hands the resulting `LinkConfig`s to `LinkManager::reconcile` |
| `server.rs` | Binds `--listen-socket` and serves `OspfRequest::GetNeighbors` from `LinkManager::neighbor_summaries` (backs `nos-cli`'s `show ospf neigh`) — resolved via the watchdog broker's `ServiceRef::OspfInstance`, the same pattern `nos-bgpd`/`nos-ribd`/`nos-interfaced`'s query listeners use |

## Watchdog/broker wiring

`nos-watchdogd` gives every `nos-ospfd` instance a real `--listen-socket` (`/run/nos/ospf-<name>.sock`) and registers it in `EndpointRegistry` under `EndpointKind::OspfInstance` — the `ServiceRef`/registry plumbing that already existed generically (see root `CLAUDE.md`'s "Endpoint broker") is now actually wired up, not just present.
