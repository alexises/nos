# BFD internals

How `nos-bfd` is built. Library only for now (#296); the daemon, sockets and sessions come with #297. Rules to respect when editing: [`bfd/CLAUDE.md`](../../bfd/CLAUDE.md). The profile that feeds it: [protocols/bfd.md](../protocols/bfd.md).

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
