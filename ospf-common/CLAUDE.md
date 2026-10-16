# nos-ospf-common — logic shared by OSPFv2 and OSPFv3

Pure, address-family-agnostic code used by `nos-ospf` and `nos-ospfv3`. No NOS dependencies (not even `nos-proto`), no I/O; the only external crate is `tokio` with the `sync` feature, for `Lsdb`'s `Notify`.

## Modules

- `neighbor`, `election`: RFC 2328 §10.5 neighbor FSM and §9.4 DR/BDR election (identical in RFC 5340).
- `bfd`: `bfd_wanted`, the neighbor-state rule for which neighbors get a BFD session.
- `lsa`: the `LsaHeader` and `Lsa` traits, `MAX_AGE`, and the RFC 2328 §13.1 `is_newer` ordering (a provided method of `LsaHeader`).
- `lsdb`: the generic `Lsdb<L: Lsa>` store, `InstallOutcome`, `MIN_LS_ARRIVAL`, `MAX_AGE_HOLD_TICKS`.

## Rules

- **Traits carry identity only.** `LsaHeader` exposes key, sequence, age, checksum, length and advertising router; `Lsa` exposes its header. Bodies, scope (area/link/AS), type numbering and wire codecs stay in the daemons.
- **No family-wide trait.** Where v2 and v3 differ, the shared function takes a per-call closure or a plain argument; never add a `Family` trait.
- **The key is an associated type** (`LsaHeader::Key`): v2's `lsa_type` is a `u8`, v3's a `u16`. `advertising_router()` is on the header so `age_and_evict` can apply the RFC 3623/5187 grace `hold` set without bounds on `Key`.
- **Daemons alias, not wrap**: each daemon has `pub type Lsdb = nos_ospf_common::lsdb::Lsdb<Lsa>` and re-exports the constants, so call sites stay `Lsdb::new()`. `lsa::is_newer` in each daemon only delegates to the trait method.
- **Two install paths**: `install` (self-originated, paced by `MinLSInterval` elsewhere) and `install_received` (flooding, paced by `MIN_LS_ARRIVAL`; `TooSoon` means not installed, not acked, not counted as answering a request). `remove` and eviction also clear the pacing clock.
- A flushed (`MAX_AGE`) entry is held `MAX_AGE_HOLD_TICKS` ticks so the periodic full-LSDB resend can carry it to every neighbor before it is evicted; a superseding install restarts the hold.
- `Lsdb` fires its `Notify` on every change that can alter SPF input (install, remove, evict), never on a rejected install.

## Tests

- `lsa::test_lsa` is a ~20-line `Lsa`/`LsaHeader` (a `u32` key) so store and ordering tests need no daemon types. Daemon-side tests only cover their trait impls and the aliases.
- Behaviour that needs a kernel or two processes belongs in a `nos-ospf*` test or a `nos-e2e` phase (`docs/e2e-phases.md`), not here.
