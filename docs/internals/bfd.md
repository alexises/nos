# BFD internals

How `nos-bfd` is built. The library (#296) plus the daemon `nos-bfdd` (#297). Rules to respect when editing: [`bfd/CLAUDE.md`](../../bfd/CLAUDE.md). The profile that feeds it: [protocols/bfd.md](../protocols/bfd.md).

## Modules

- `packet`: RFC 5880 §4.1 mandatory section (24 bytes) codec.
    - `decode` applies the stateless §6.8.6 checks; `check_session` is the stateful pair (session lookup, A-bit mismatch) the session code calls.
    - The A bit decodes to `DecodeError::AuthUnsupported` until #289.
- `fsm`: `step(state, event) -> (state, Option<diag>)`, the §6.8.6 table; `may_transmit` covers `passive` (§6.1) and Remote Min RX 0.
- `timers`: `Timers`, `now` and the jitter draw passed in.
- `authz`: `allowed(role, &BfdRequest)`, no wildcard arm.
- Wire types live in `nos_proto::bfd`.

## FSM

| State | Rx Down | Rx Init | Rx Up | Rx AdminDown | Detect timeout |
|-------|---------|---------|-------|--------------|----------------|
| AdminDown | stay | stay | stay | stay | stay |
| Down | Init | Up | stay | stay | stay |
| Init | stay | Up | Up | Down (diag 3) | Down (diag 1) |
| Up | Down (diag 3) | stay | stay | Down (diag 3) | Down (diag 1) |

- Local `AdminDown` event: any state goes to AdminDown (diag 7); `AdminUp` brings AdminDown back to Down (diag 0).
- Demand mode is not implemented: D is sent 0 and a received D is ignored.

## Timer rules

- TX interval: `max(local desired min TX, remote required min RX)`; at least 1 s while not Up (also advertised as Desired Min TX).
- Detection time: `remote detect mult x max(local required min RX, remote desired min TX)`.
- Jitter: the caller draws 75..=100 (clamped; 75..=90 when the local detect mult is 1).
- Changing an interval opens a Poll sequence (P=1 on every packet); the new value takes effect locally on Final. An incoming P is answered with F.
- When a session reaches Up the caller restores the configured Desired Min TX with `Timers::change` (starts a Poll sequence); `Timers` does not watch the state itself.

## Add a packet field

- Add it to `Packet`, `encode` and `decode`, then extend `round_trip_with_every_flag` and `known_wire_bytes`.
- A check that needs no session goes in `decode` with its own `DecodeError` variant and a named `rx_*` test.

## The daemon

- `nos-bfdd` is one fixed process (`/run/nos/bfd.sock`, `ServiceRef::Bfd`). Clients `Register` a session on a persistent connection and get `BfdEvent::State` (current state first, then each change).
- `Manager` keeps one task per `SessionKey`, shared by every client that registered it; the last client leaving drops it.
- A re-`Register` with a different profile is the profile edit: intervals go through Poll/Final, `shutdown` through AdminDown.
- Sockets (RFC 5881): one receive socket per (table, family) on UDP 3784, bound to the table's VRF; one connected transmit socket per session with a random source port in 49152-65535 and TTL 255. Received TTL must be 255.
- The VRF device comes from the table's `nos-ribd` (`GetVrfName`); a session whose VRF or local address is not ready retries every second.

## Static routes (`nos-ribd`)

- `rib/src/bfd_client.rs` registers the gateway of every static route with a `bfd` reference (one session per gateway).
- A route is left out of the RIB until its gateway's session is `Up`; `Down`, `Init` and `AdminDown` all take it out. While `nos-bfdd` is unreachable nothing is up (fail closed); after a reconnect everything is registered again.
- `reconcile::resync` reads the up set and re-runs when it changes.

## Check it by hand

- `cargo run -p nos-e2e -- bfd` proves both ways Up, the route withdrawn and restored around a dropped UDP 3784, and interop with FRR `bfdd`.
- `docker exec router-a ...` has no `ip`/`tcpdump`: use the netns helper images from `tools/e2e` to sniff.
