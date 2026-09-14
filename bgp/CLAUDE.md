# nos-bgp — BGP Component

BGP-4 implementation for NOS (binary `nos-bgpd`, one process per `BgpInstance`, dynamically spawned by `nos-watchdog` — see root `CLAUDE.md`'s "Process supervision" section).

## Scope

`nos-bgpd` resolves its own configured peers and VRF from `nos-configd`, opens/accepts VRF-scoped TCP connections to/from those peers (see "Raw TCP session model" below), and now runs a real BGP-4 finite state machine (RFC 4271) over each connection: OPEN/KEEPALIVE exchange up through the `Established` state, with hold-timer/keepalive-timer maintenance and real RFC 4271 §6.8 collision resolution. Route exchange (UPDATE messages, RIB integration) is deliberately still out of scope — a future feature layers that on top of `Established` sessions. See "BGP finite state machine" below.

### VRF resolution

A `BgpInstance` carries a reflexive, read-only `routing_table: Option<String>` field (`nos-proto`'s `derive::sync_routing_table_refs`, mirrored from the owning `RoutingTable.bgp_instance` on every config load/commit — see `proto/CLAUDE.md`). `nos-bgpd` reads this directly instead of scanning every `RoutingTable`, then resolves the named table's real Linux VRF interface name the same way `nos-interfaced` does: `ServiceRef::RibTable(name)` via the watchdog broker, then `RibRequest::GetVrfName` directly against that `nos-ribd` instance (`rib_client::get_vrf_name`).

This resolves to one of three states (`session::VrfRequirement`):
- **`Invalid`** — no owning routing table at all. Treated as a config error, **not** a "run unscoped in the default VRF" fallback — BGP always belongs to a VRF in this system. Logged as an error every resync; no session or listener is ever opened while in this state.
- **`Pending`** — an owning table exists but its VRF isn't allocated/known yet (the table's `nos-ribd` instance isn't up, or hasn't created its VRF yet). A normal, transient condition, logged at `debug`, retried by the periodic re-apply tick.
- **`Resolved(name)`** — the VRF's real Linux interface name. Only in this state does `nos-bgpd` open anything.

### Raw TCP session model

Once resolved, `session::SessionManager` maintains, per configured peer, both sides of a TCP session, scoped into the VRF via `SO_BINDTODEVICE` (`tcp.rs`, `socket2::SockRef` over a `tokio::net::TcpSocket` — a socket-level equivalent of `nos-ribd`/`nos-interfaced`'s `rtnetlink`-based VRF enslavement, since no interface or route is being programmed here):
- **Active**: a per-peer retry loop attempts an outbound connect (`fsm::CONNECT_RETRY_TIME`, RFC 4271's own suggested `ConnectRetryTimer` default) to the peer's `remote_address:179`, optionally bound to its peer-group's `source_address` — but skips dialing out entirely whenever `PeerSlot::is_established` is already true (in either role), so a session held open by the passive side doesn't see a redundant, pointless outbound attempt (and the collision it would otherwise trigger) every `CONNECT_RETRY_TIME`. Found via real two-container verification — see "Verification" below.
- **Passive**: one shared listener (`0.0.0.0:179` + `[::]:179`) accepts inbound connections, matching the remote IP against the configured peer set; an unconfigured remote is rejected.

Once a `TcpStream` exists (either side), `fsm::run` takes over — see "BGP finite state machine" below.

### BGP finite state machine

`fsm.rs` implements the RFC 4271 states that need message exchange — `OpenSent`, `OpenConfirm`, `Established` — layered on top of the raw TCP connectivity above (Idle/Connect/Active remain `session.rs`'s retry-loop behavior; `fsm::run` is spawned only once a stream already exists, replacing what used to be `hold_until_closed`). `fsm::step` is the pure transition core (state + event -> next state + actions), unit-tested directly; `fsm::run` is the async orchestrator that owns the `BgpCodec`-framed socket and the hold/keepalive timers.

OPEN validation (`fsm::handle_open`) checks, in order: BGP version (must be 4), the peer's real ASN against the configured `BgpPeerGroup.remote_as` (see "Four-octet AS numbers" below), the BGP Identifier's validity (`message::is_valid_bgp_identifier` — rejects `0.0.0.0`, multicast, broadcast), and the proposed hold time (`0`, or `>= 3` per RFC 4271 §6.2 — `1`/`2` are invalid). Any failure sends the matching RFC 4271 §6 `NOTIFICATION` (Error Code `OpenMessage`, the specific subcode) and closes; a hold-timer expiry at any state sends `NOTIFICATION(HoldTimerExpired)`. The negotiated hold time is `min(local, remote)`; keepalive interval is derived as `negotiated_hold / 3` (not separately configurable); a negotiated hold time of `0` disables both timers entirely, per RFC 4271. No per-peer-group timer config exists yet — `fsm::HOLD_TIME_DEFAULT` (90s) is a single hardcoded local proposal, a deliberate scope decision (see the constant's doc comment for rationale).

Every well-formed inbound message (not just KEEPALIVE) resets the hold timer, per RFC 4271 §4.4 — handled centrally in `fsm::run`'s read branch rather than per-message-type. An `Unhandled` message (UPDATE, or anything unrecognized) is logged and ignored rather than treated as an error, since route exchange doesn't exist yet.

### Four-octet AS numbers (RFC 6793)

`BgpInstance.asn`/`BgpPeerGroup.remote_as` are `u32`, wider than OPEN's plain 2-byte "My Autonomous System" field, so `message::build_open` always advertises the four-octet AS number capability (code 65) and uses `AS_TRANS` (23456) as the 2-byte field's placeholder whenever the real ASN doesn't fit. `message::effective_remote_asn` reads the real value back out — preferring the capability when present, falling back to the plain field for interop with peers that never send it. An `AS_TRANS` value with no backing capability is treated as a malformed/bad-peer-AS OPEN, since it's otherwise meaningless.

### Collision resolution (RFC 4271 §6.8)

`collision::PeerSlot` (one per configured peer, shared between its active-connect task and the passive accept handler) implements real router-ID-based collision resolution — not a "first TCP connection wins" simplification. Both an active and a passive connection for the same peer are allowed to proceed through OPEN exchange; `PeerSlot::on_open` records each connection's BGP Identifier and, once both sides have one, resolves the winner:

- higher local BGP Identifier keeps the connection this system initiated (active); closes the accepted (passive) one; the reverse if the peer's ID is higher.
- a connection already `Established` always beats a later collision, regardless of ID comparison (RFC 4271 §6.8) — in practice, over real sockets, this is almost always which side actually decides the outcome, since one connection's OPEN/KEEPALIVE round trip typically completes well before the other side's OPEN is even processed. The pure ID-comparison path is exercised deterministically by `collision.rs`'s own unit tests (calling `PeerSlot::on_open` directly, no sockets), rather than by timing-dependent integration tests.
- a tie (duplicate/misconfigured router-id) keeps whichever connection registered first and logs a warning.

The loser is torn down with `NOTIFICATION(Cease, ConnectionCollisionResolution)` (RFC 4486 §7), signaled via a `tokio::sync::Notify` handle so its own `fsm::run` task sends the notification itself before closing — never a bare socket drop.

## Modules

| Module | Role |
|--------|------|
| `main.rs` | Arg parsing (`--instance`, `--watchdog-socket`, `--log-socket`), resolves `nos-configd`'s address via the watchdog broker before starting, SIGINT+SIGTERM shutdown wait, spawns `reconcile::run` |
| `config_client.rs` | Own `fetch_config` (`Request::Get`) / `subscribe_diff` (`Request::SubscribeDiff`) — reimplemented rather than shared with `nos-cli`/`nos-watchdog`/`nos-rib`/`nos-interface`, per the root `CLAUDE.md`'s star dependency graph |
| `watchdog_client.rs` | `resolve_with_retry` (used once at startup for `ServiceRef::Config`) and `resolve_once` (used every resync for `ServiceRef::RibTable`, where "not available" must return quickly rather than block) |
| `rib_client.rs` | One-shot `get_vrf_name` — the client side of `RibRequest::GetVrfName` |
| `reconcile.rs` | Steady-state loop: subscribes to `BgpInstances`/`RoutingTables` diffs purely as a resync trigger, always re-fetching the whole config; also re-applies on a fixed 10s timer, since VRF readiness is an external condition no config diff signals. `classify_vrf` is the pure VRF-state classification, unit-tested directly. Hands `(VrfRequirement, LocalIdentity, Vec<ResolvedPeer>)` to `session::SessionManager::reconcile` on every trigger |
| `session.rs` | `SessionManager` — owns every peer's active/passive TCP+FSM state and the shared listener; `reconcile` (add/remove/restart peers, rebind the listener on VRF change) is the sole entry point. `diff_peers` is the pure peer-set diffing, unit-tested directly (mirrors `nos-interface`'s `diff_addresses`); a peer restarts on any field change, including `remote_as` |
| `tcp.rs` | `connect`/`bind_listener` — the two VRF-scoped socket primitives, via `tokio::net::TcpSocket` + `socket2::SockRef::bind_device` |
| `message.rs` | RFC 4271 BGP-4 wire format: the common header, OPEN/KEEPALIVE/NOTIFICATION bodies, the RFC 6793 four-octet AS capability, and `BgpCodec` (a hand-rolled `tokio_util::codec::{Encoder,Decoder}` — BGP's wire format is incompatible with `nos-proto`'s postcard-based `IpcCodec`, and is a contract with external routers rather than an inter-NOS-daemon one, so it lives here, not in `nos-proto`) |
| `fsm.rs` | The BGP finite state machine (`OpenSent`/`OpenConfirm`/`Established`) — see "BGP finite state machine" above |
| `collision.rs` | RFC 4271 §6.8 connection collision resolution — see "Collision resolution" above |
| `log_client.rs` | `ForwardingLayer` — the `tracing` → `nos-logd` forwarder, reimplemented per-crate like every other daemon's |
