# BFD internals

How `nos-bfd` is built. The library (#296) plus the daemon `nos-bfdd` (#297). Rules to respect when editing: [`bfd/CLAUDE.md`](../../bfd/CLAUDE.md). The profile that feeds it: [protocols/bfd.md](../protocols/bfd.md).

## Modules

- `packet`: RFC 5880 §4.1 control packet codec.
    - `decode` applies the stateless §6.8.6 checks; with the A bit it also parses the authentication section into `Packet.auth` (`DecodeError::BadAuthSection` when malformed). `encode` writes the mandatory section only.
- `auth`: RFC 5880 §4.2-4.4/§6.7. `sign` appends the section, `AuthState` holds a session's key, old key, `RcvAuthSeq`/`AuthSeqKnown` and `XmitAuthSeq`.
- `fsm`: `step(state, event) -> (state, Option<diag>)`, the §6.8.6 table; `may_transmit` covers `passive` (§6.1) and Remote Min RX 0.
- `timers`: `Timers`, `now` and the jitter draw passed in.
- `authz`: `allowed(role, &BfdRequest)`, no wildcard arm.
- `echo`: the Echo packet, pure. `payload` (our discriminator and a sequence), `build` (IPv4/IPv6 + UDP 3785 from a port in 49152-65535, TTL 255, source = destination = our address, checksums), `parse` (accepts TTL 254..=255, checks both addresses, checksums, payload length).
- `neigh`: the neighbour's MAC from an `rtnetlink` neighbour dump (usable states only), never written.
- Wire types live in `nos_proto::bfd`.

## Authentication

- `Core::authenticate(now, &Packet)` runs before `on_packet` and `Core::sign` wraps every outgoing packet; a failed packet never reaches the FSM or the timers.
- The digest is MD5/SHA1 over the packet with the digest field replaced by the key zero-padded to 16/20 bytes; digests and passwords compare in constant time.
- Replay window: keyed accepts `[RcvAuthSeq, RcvAuthSeq + 3 x DetectMult]`, meticulous `(RcvAuthSeq, ...]`, wrap-aware; unknown (`AuthSeqKnown` false) accepts any, and silence of 2 detection times forgets it.
- `XmitAuthSeq` starts random; meticulous bumps it per packet, keyed once per detection time.
- A profile edit goes through `AuthState::set`: the new key signs at once, the previous one stays acceptable for 4 detection times; a method change resets `AuthSeqKnown`.
- `session::run` logs `bfd auth failed` (rate limited to one per 10 s per session); `Status` and `BfdSessionView` carry `auth_method`, `auth_key_id`, `auth_failures`.
- Unit tests check digests against an independent re-implementation of the RFC recipe in `auth.rs` tests. `ponytail:` no FRR positive proof: FRR `bfdd` has no §6.7 support, so `nos-e2e`'s `bfd-auth` only proves the negative case against it.
- #294 (S-BFD) will add reflector authentication on top of this module.

## FSM

| State | Rx Down | Rx Init | Rx Up | Rx AdminDown | Detect timeout |
|-------|---------|---------|-------|--------------|----------------|
| AdminDown | stay | stay | stay | stay | stay |
| Down | Init | Up | stay | stay | stay |
| Init | stay | Up | Up | Down (diag 3) | Down (diag 1) |
| Up | Down (diag 3) | stay | stay | Down (diag 3) | Down (diag 1) |

- An echo timeout only moves an Up session: it goes Down with diag 2.

- Local `AdminDown` event: any state goes to AdminDown (diag 7); `AdminUp` brings AdminDown back to Down (diag 0).
- Demand mode is not implemented: D is sent 0 and a received D is ignored.

## Echo

- `Core` owns the sub-state: `sync_echo` starts Echo when `echo_wanted` (transport present, profile `Affiliated`, state Up, remote Required Min Echo RX > 0) and stops it otherwise. Both directions go through `Timers::change`, so Desired Min TX is raised to 1 s (and restored) by an ordinary Poll sequence.
- `echo_due(now)` hands out the next sequence number, `on_echo(now, seq)` records a returned one (`seq` must be new and sent); `echo_expired` after `echo interval x detect multiplier` without one applies `Event::EchoTimeout`, which takes an Up session to Down with diag 2.
- `session::run` sends with `EchoTx` and receives sequences on the `EchoPath` channel; `Core::set_echo_path` tells the core whether a transport exists.
- Transport (`socket.rs`, `nos-l2-socket`'s `L2Unicast`): an `AF_PACKET` socket on the session's interface, a kernel BPF filter for UDP port 3785, frames sent to the neighbour's MAC. The returned packet carries our own address as source, which the IP stack drops as a martian, so receiving at the packet layer is the only way. The socket is bound to the interface, so it works for a VRF-enslaved one.
- Tapping a packet socket sits after the `tc` ingress hook, so a `tc` drop on UDP 3785 starves Echo (this is how `bfd-echo` injects the failure).
- `ponytail:` the echo transport is opened once at session start; a later-appearing address needs a re-`Register` of a new session. Echo timing has no jitter.

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
- Sockets (RFC 5881, RFC 5883): one receive socket per (table, family, multihop) on UDP 3784 or 4784, bound to the table's VRF; one connected transmit socket per session with a random source port in 49152-65535 and TTL 255. `Demux::route` checks the TTL per session with `ttl_ok`: exactly 255 single-hop, at least the profile's `minimum_ttl` multihop.
- Multihop: the key keeps `multihop` and `local`, never an interface; the transmit socket binds to the VRF and to `local`, else to `kernel_source` (a connected UDP socket's local address, no packet sent). Zero-discriminator demux is by (table, source, multihop). `ponytail:` no destination address in it (RFC 5883 §4 names the pair), so two multihop sessions to one peer from different local addresses in one table collide; add `IP_PKTINFO` if that matters.
- The VRF device comes from the table's `nos-ribd` (`GetVrfName`); a session whose VRF or local address is not ready retries every second.

## Static routes (`nos-ribd`)

- `rib/src/bfd_client.rs` registers the gateway of every static route with a `bfd` reference (one session per gateway), multihop when `!Config::is_connected(table, gateway)`; `local` is left to `nos-bfdd`.
- A route is left out of the RIB until its gateway's session is `Up`; `Down`, `Init` and `AdminDown` all take it out. While `nos-bfdd` is unreachable nothing is up (fail closed); after a reconnect everything is registered again.
- `reconcile::resync` reads the up set and re-runs when it changes.

## Querying sessions

- `BfdRequest::GetSessions { peer }` is a one-shot request answered with `BfdEvent::Sessions(Vec<BfdSessionView>)`, ordered by (table, peer); `peer: Some(ip)` filters in the daemon.
- `BfdSessionView` carries the `SessionKey` (table, peer, optional local/interface, multihop), `state`, `diag`, both discriminators, the negotiated `tx_interval_us` and `detection_time_us`. There is no uptime or receive interval in it.
- Single-hop sessions are keyed by (table, peer address) only: `nos-ribd` registers with `interface: None`, so `show` prints no interface; a BGP multihop session also shows its `local`.
- Only `Role::User` (`nos-cli`) and `Role::Restd` may ask (`authz::allowed`); `cli/src/bfd_client.rs` and `rest/src/show.rs::bfd_sessions` are the two clients.

## Check it by hand

- `nos show bfd sessions` or `GET /v1/bfd/sessions` lists what the daemon holds.
- `cargo run -p nos-e2e -- bfd-auth` proves matching and wrong keys, a live key and method change without a flap, and the unauthenticated FRR staying down.
- `cargo run -p nos-e2e -- bfd-echo` proves Echo active on both ends with Control slowed to 1 s, `echo-function-failed` when only UDP 3785 is dropped, recovery, and an FRR `bfdd` (`echo receive-interval 50`) with Echo running.
- `cargo run -p nos-e2e -- bfd` proves both ways Up (also read back over `GET /v1/bfd/sessions`), the route withdrawn and restored around a dropped UDP 3784, and interop with FRR `bfdd`.
- `docker exec router-a ...` has no `ip`/`tcpdump`: use the netns helper images from `tools/e2e` to sniff.
