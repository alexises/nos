# nos-bfd — BFD (RFC 5880/5881) library and `nos-bfdd`

The pure core (#296) plus the single system-wide daemon `nos-bfdd` (#297), a fixed process like `nos-lldpd`. Single-hop and multihop; its clients are `nos-ribd`'s `bfd_client.rs` (static routes), `nos-bgpd`'s (peer-groups, #286) and `nos-ospfd`/`nos-ospfv3d`'s (#288).

| Module | Purpose |
|--------|---------|
| `packet` | control packet codec (parses the auth section), §6.8.6 reception checks |
| `auth` | RFC 5880 §6.7: auth section sign/parse, digests, `AuthState` (key, old key, sequence window) |
| `fsm` | `step(state, event)` state machine, `may_transmit` (passive) |
| `timers` | Interval negotiation, jitter, Poll/Final, detection time |
| `authz` | `allowed(role, &BfdRequest)` |
| `session` | `Core` (pure: packets and clock in, packets out) and `run`, one tokio task per session |
| `manager` | Session table, refcount per client, `Demux` (rx packet to session), `Net` trait |
| `server` | `--listen-socket`: `Register` streams `BfdEvent::State`, `GetSessions` replies once |
| `socket` | UDP 3784/4784 sockets (`UdpNet`); excluded from coverage, `nos-e2e`'s `bfd` phase is its test |
| `watchdog_client` | Broker lookups, the table's VRF device via `nos-ribd` `GetVrfName` |

Wire types are in `nos-proto::bfd`; `ServiceRef::Bfd` / `Role::Bfdd` in `broker`.

## Rules that bite

- `decode` never panics: use `get`/`try_into`, never index untrusted bytes.
- Auth (#289): `Core::authenticate` before `on_packet`, `Core::sign` on every send; a failed packet must not reach the FSM or timers. A profile edit keeps the old key valid for 4 detection times. #294 adds reflector auth on top.
- `timers` and `Core` take `now` and the jitter percentage as arguments; only `session::run` reads the clock.
- Discriminators come from the manager's counter (random start), never 0.
- `BfdRequest`/`BfdEvent` variants are appended, never reordered (postcard). A new `BfdRequest` must be classified in `authz::allowed`.
- No Echo (until #290), no demand mode. Multihop (#287): UDP 4784, TTL checked per session in `Demux::route`; no destination address in the zero-discriminator demux (`ponytail:` in `manager.rs`).
- Desired Min TX is floored at 1 s while not Up by `Timers` itself; reaching Up needs no `change`.
- The profile travels in `Register`; a re-`Register` with a changed profile runs Poll/Final (no flap), `shutdown` goes AdminDown. `nos-bfdd` subscribes to no config.
- A client's connection drop releases its sessions; the last client drops the session. Request-side EOF ends the connection (`ponytail:` in `server.rs`).
- A TX socket must bind an explicit source address (`socket::local_for`): bound to a VRF with a wildcard source the kernel sends from 0.0.0.0.
- RX: UDP 3784 per (table, family) bound to the VRF; TTL must be exactly 255. Demux is by Your Discriminator, else (table, source address): no interface in the key (`ponytail:` in `manager.rs`).
- `BfdEvent::State.control_plane_independent` is the C bit at both ends (`nos-bfdd` always sets its own; the remote's is from the last received packet): BGP flushes routes on Down only when it is set (RFC 5882 §4.3).
- Log anchors the e2e relies on: `bfd session up peer=`, `bfd session down peer= diag=`.

Details: [docs/internals/bfd.md](../docs/internals/bfd.md).
