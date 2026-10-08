# nos-bfd — BFD (RFC 5880) core

Pure library for now (#296): no sockets, no tokio, no daemon. `nos-bfdd` (#297) builds on it. Depends only on `nos-proto`.

| Module | Purpose |
|--------|---------|
| `packet` | 24-byte control packet codec, §6.8.6 reception checks |
| `fsm` | `step(state, event)` state machine, `may_transmit` (passive) |
| `timers` | Interval negotiation, jitter, Poll/Final, detection time |
| `authz` | `allowed(role, &BfdRequest)` for the future server |

Wire types (`BfdRequest`, `BfdEvent`, `SessionKey`, `BfdState`, `BfdDiag`) are in `nos-proto::bfd`; `ServiceRef::Bfd` / `Role::Bfdd` in `broker`.

## Rules that bite

- `decode` never panics: use `get`/`try_into`, never index untrusted bytes.
- The A bit is rejected until #289; a session needing auth rejects every packet via `check_session`.
- `timers` takes `now` and the jitter percentage as arguments; never call `Instant::now()` or an RNG in the lib.
- Discriminators are allocated by the daemon, never 0.
- `BfdRequest`/`BfdEvent` variants are appended, never reordered (postcard).
- A new `BfdRequest` variant must be classified in `authz::allowed` (no wildcard arm).
- No Echo (Required Min Echo RX sent 0, until #290), no demand mode.
- Desired Min TX is advertised as at least 1 s while not Up; the caller calls `Timers::change` with the configured value on reaching Up.

Details: [docs/internals/bfd.md](../docs/internals/bfd.md).
