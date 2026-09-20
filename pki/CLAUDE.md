# nos-pki — IPC transport security

Mutual TLS over Unix sockets for every NOS daemon connection, with `nos-watchdogd` as the certificate authority. A leaf crate with **no NOS dependencies**, like `nos-password`/`nos-tcp-auth`: it deals in `PeerId { role, name }` strings; `nos_proto::Role`/`ServiceRef::role()`/`instance()` say who is expected.

## Model

- **Identity = a URI SAN**, `nos://<role>/<name>` (`PeerId`; `name` is percent-escaped, empty for singleton daemons). Every leaf also carries the fixed DNS SAN `nos.internal`, purely so rustls's stock WebPKI verifiers have a `ServerName` to check. Chain, expiry and key usage are the stock verifiers' job; *who the peer is* is checked by us right after the handshake, before any application byte moves (`Identity::connect` against an expected `PeerId`/role; servers get the peer from `Incoming::handshake`/`handshake_as`).
- **TLS 1.3 only, no session resumption or tickets.** A resumed session skips certificate verification, which would let an expired or rotated-out identity straight back in.
- **`Ca`** (`ca.rs`) is ephemeral, in `nos-watchdogd`'s memory only. `issue` mints a fresh keypair + leaf; `sign_csr` certifies a client-made CSR taking **only the public key from it** — the SAN is set by the CA from the identity it authenticated, never from the CSR (`csr_signing_takes_the_key_but_never_the_identity`).
- **`Identity`** (`identity.rs`) is a swappable handle (`arc-swap`) that rustls's client/server resolvers read at *handshake* time, so `update` rotates a certificate with no reconnect logic: new connections use it, established ones are untouched. An identity can be `anonymous` (trusts a CA, holds no certificate) — for the login socket — and get its certificate later with `set_certificate`.
- **Delivery**: `Bundle` (`ca`, `cert`, `key`, DER) has a length-prefixed frame encoding. The watchdog writes one to each child's **piped stdin** at spawn and another every `--pki-rotate-every`; `Identity::from_stdin` reads the first and rotates on the rest from a plain `std::thread` (a blocked tokio stdin read would stall runtime shutdown). The key never touches argv, the environment or disk. There is **no plaintext fallback** — no identity, no daemon.
- **Process-wide identity**: `Identity::from_stdin` (daemons) or `install` (`nos`, `nos-provision`, after login) sets the identity every outbound `nos_pki::connect(path, role, name)` / `connect_role(path, role)` uses, so call sites don't thread a handle through session managers and drivers. Servers take an explicit `&Identity` (`identity.listen(path)`); `listen_optional_client_auth` is only for the broker's login path. `connect_role` checks the role but not the name — for a client that has only a socket path from the broker.
- **`Listener::accept`** returns an `Incoming` *without* handshaking; callers run `handshake`/`handshake_as` inside their per-connection task (5s timeout), so a slow or hostile peer never stalls the accept loop.

## Testing

`testing` feature (a dev-dependency feature of every crate that tests IPC): `testing::shared()` is one CA for the whole test process, and under this feature `global()` falls back to a `user/test` identity from it, so a fake server is `shared().identity("ribd", "rt1").listen(path)` and the client under test needs no setup. Production builds never enable it.

## Known ceilings

- Role-level authorization only (each server's `allowed(role, &request)`); `bgpd/r2` could still push into `rt1`'s RIB. Binding an instance to its table needs a config lookup.
- The CA is regenerated on every watchdog start (which restarts every child anyway); nothing persists it, so there is no CRL and no CA rotation.
- The user certificate `nos` holds is renewed at half its lifetime; if renewal keeps failing until it expires, commands fail and the shell must be restarted.
