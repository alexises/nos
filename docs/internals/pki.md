# PKI internals

How `nos-pki` is built, moved from `pki/CLAUDE.md` (#264) so the always-loaded file keeps only rules and pitfalls. The rules to respect when editing the crate are in [`pki/CLAUDE.md`](../../pki/CLAUDE.md).

## Model (revocation and REST server)

- **Revocation (RFC 5280 §5 CRL, IPC CA only)**:
  - `Ca::revoke(&[Serial])` adds certificates (`Serial::of(cert_der)`: serial + expiry) and returns the re-signed CRL; `crl_der` is the current one. Entries whose certificate has expired are dropped on every re-sign, and the CRL number grows by one each time. `next_update` is set but never enforced, so a CRL can't expire under a daemon.
  - `Identity::set_crl` (also called by `update` when the bundle's `crl` is non-empty and new) rebuilds the client and both server configs with `with_crls`, checking the leaf only (the one CA is never revoked). It logs `ipc crl updated entries=<n>`. A `Listener` reads the identity's current config on every `accept`, so a CRL that arrives after `listen` applies to the next peer.
  - Revocation stops **new** handshakes only: an established connection is untouched, like rotation.
  - webpki verifies the ML-DSA-65 CRL signature with the same algorithm list as the chain (`an_ml_dsa_crl_is_enforced_by_both_verifiers`).
  - What gets revoked is the watchdog's business (`watchdog/src/pki.rs`): every leaf minted for a spawn when that process exits (crash, restart, instance removed, `rest-api` unpinned, watchdog stopping), and every IPC certificate issued to a user when the user is deleted or its password hash changes (a `DiffScope::Users` subscription; a re-hash the broker did itself at login is not a change). It logs `certificates revoked role=… name=… serials=…`. A routine rotation revokes nothing: a rotated-out leaf stays valid until it expires (`leaf_lifetime - rotate_every`, 16h by default).
- **REST (`rest.rs`)** — the only place other crates get rustls from. `RestServer` holds the REST-CA client verifier (client certificate *optional* at the TLS layer, because `POST /v1/login` must be reachable without one; the caller refuses everything else to an anonymous peer), a hot-swappable server certificate (`set_certificate`, from `Ca::sign_server_csr`: IP SANs from the caller, never the CSR), ALPN `h2`/`http/1.1`, and `accept(tcp)`, which handshakes and returns the user the client certificate names. It also returns the certificate's serial, which `nos-restd` sends to the watchdog's allowlist of live REST certificates (the REST CA has no CRL). `client_config(rest_ca_pem, identity)` is the matching client config for `reqwest::ClientBuilder::tls_backend_preconfigured`, the e2e harness and tests.

## Policy details moved from CLAUDE.md

- **`Policy::Syslog`** (`syslog.rs`, #71): `nos-logd` as a TLS *client* of a syslog collector (RFC 5425/9662) it does not control, so no NOS CA: the collector is trusted by a configured CA (`WebPkiServerVerifier`, name = IP/DNS SAN) or by its certificate's SHA-256 (`Fingerprint` verifier; still checks the handshake signature). Same key exchange/cipher/TLS 1.3 as the others, but certificate signatures are the classical webpki set. A documented deviation from RFC 9662 (which wants TLS 1.2). No client certificate, resumption off, no early data (RFC 9662 §6).

- **The `allow-tls12` opt-in is the crate's one classical path**, built only in `syslog.rs` (`allow_tls12_provider`, never in `policy.rs`): TLS 1.2 with the four ECDHE-AES-GCM suites and `X25519`/`P-256`/`P-384`, `require_ems`. Each classical group is wrapped in `Tls12Only` (`usable_for_version` true only for TLS 1.2), so rustls can neither send a classical TLS 1.3 key share nor accept a HelloRetryRequest for one: TLS 1.3 stays `X25519MLKEM768`-only. Locked by `ipc_and_rest_policies_are_unchanged`, `tls12_client_is_refused_on_ipc_and_rest` and `allow_tls12_groups_are_tls12_only`. `TLS_RSA_WITH_AES_128_CBC_SHA` is not offered (no RSA key transport or CBC in rustls).

**Two gotchas of the versions in use** (rcgen 0.14, x509-parser 0.18, rustls 0.23): rcgen can *generate* and *sign with* ML-DSA, but its CSR parser can't verify an ML-DSA request (x509-parser has no ML-DSA verification) and its public-key-info parser doesn't know the algorithm. So `Ca::sign_csr` parses the CSR with x509-parser, verifies the proof-of-possession itself with webpki's algorithm for the CA's `KeyAlg`, and hands rcgen a small `PublicKeyData` (`CsrKey`) in that algorithm. If rcgen grows ML-DSA parsing, that whole detour can go. aws-lc-sys also needs a C toolchain at build time (the `rust:slim` builder image has one; no cmake needed).


## Identity and accept (full text)

- **Process-wide identity**: `Identity::from_stdin` (daemons) or `install` (`nos`, `nos-provision`, after login) sets the identity every outbound `nos_pki::connect(path, role, name)` / `connect_role(path, role)` uses, so call sites don't thread a handle through session managers and drivers. Servers take an explicit `&Identity` (`identity.listen(path)`); `listen_optional_client_auth` is only for the broker's login path. `connect_role` checks the role but not the name — for a client that has only a socket path from the broker.

- **`Listener::accept`** returns an `Incoming` *without* handshaking; callers run `handshake`/`handshake_as` inside their per-connection task (5s timeout), so a slow or hostile peer never stalls the accept loop.

## Delivery (full text)

- **Delivery**: `Bundle` (`ca`, `cert`, `key`, `crl`, DER) has a length-prefixed frame encoding. The watchdog writes one to each child's **piped stdin** at spawn, another every `--pki-rotate-every`, and the current leaf again with the new CRL whenever the CRL changes; `Identity::from_stdin` reads the first and applies the rest from a plain `std::thread` (a blocked tokio stdin read would stall runtime shutdown). The key never touches argv, the environment or disk. There is **no plaintext fallback** — no identity, no daemon.
