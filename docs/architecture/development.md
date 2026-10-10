# Development: toolchain, CI and containers

Contributor-facing; moved from the root `CLAUDE.md` (#260).

**Rust toolchain.** Local `make` and CI run the same commands on the same toolchain (#153, #180):

- `ci.yml` pins `RUST_TOOLCHAIN` (fmt, clippy, test, coverage) and `MIRI_TOOLCHAIN` (a dated nightly, for `make miri`); `rust-toolchain.toml` pins the same stable. Every CI job runs the Makefile target (`make fmt`, `make clippy`, …), so commands, flags and `RUSTFLAGS` live in one place.
- Every Rust `make` target depends on `toolchain-check`, which fails when `rust-toolchain.toml` ≠ `RUST_TOOLCHAIN` and prints where cargo runs: `toolchain: 1.99.0 (native)` when local `rustc` is the pin (rustup, CI), else `(docker nos-ci:<pin>-<nightly>)` — the `tools/ci/Dockerfile` image (`make ci-image`, built on first use), with its own `target/ci` and cargo home under `target/`. A host without rustup (Fedora's older `rustc`) therefore still gets CI's exact clippy lints and nightly.
- The nightly cron runs two canaries that only warn: `Clippy (stable canary)` on the newest stable (also on every push/PR) and `Miri (nightly canary)` on the newest nightly.
- The `alert` job opens one `ci-red` issue (or comments on the open one) when any job or canary is red outside a PR. Branch protection isn't available on this plan, so nothing blocks a red merge: merge only after `gh pr checks <N> --watch` is all green.

To bump:

- Change `RUST_TOOLCHAIN` (ci.yml) and `channel` (rust-toolchain.toml) together; `make toolchain-check` enforces it.
- Bump `MIRI_TOOLCHAIN` to a recent nightly date that ships `miri`.
- Run `make ci-image check miri` — on a host without the new toolchain it runs in the new `nos-ci` image automatically.
- Fix the new lints and deprecations in the same PR. A lint an older toolchain doesn't know only prints an `unknown_lints` warning, which `-D warnings` doesn't promote.
- The PR touches `ci.yml`, so every job runs on it: don't merge until `gh pr checks` is all green, Miri included.
- Close any open `ci-red` issue the bump fixes.

The release `Dockerfile` floats on `rust:1-slim-bookworm`, harmless since release builds don't use `-D warnings`.

`watchdog/tests/system.rs` is the unprivileged whole-stack smoke test: the real `nos-watchdogd` supervising every real daemon (`--driver noop`, every socket and state file under a temp dir — `--run-dir` moves the per-instance `<prefix>-<name>.sock` sockets off `/run/nos`), provisioned by the real `nos-provision`, reconfigured, then stopped with SIGTERM. It needs every daemon binary built next to `nos-watchdogd`, which is why each daemon crate has at least one integration test (`tests/bin.rs` where nothing else existed); a single-package run without them skips.

**Fake IPC servers for tests** (`nos-test-support`, #347):

- Use it instead of a per-crate `serve_once`: `FakeConfigd`, `FakeWatchdog`, `FakeRibd`, `FakeInterfaced`, or `Fakes::start(&[Fake::Configd(cfg), Fake::Watchdog, Fake::Ribd("rt1".into()), Fake::Interfaced])` for a whole set with one watchdog pre-filled for exactly the started services.
- A service left out of `Fakes::start` has no socket and the watchdog answers `NotAvailable` for it: that is how a test reaches a daemon's "unreachable" branch.
- Every fake loops on accept and speaks real mutual TLS. The client must dial the fake's identity: configd, watchdog and interfaced use the empty name, ribd uses the routing-table name (`nos_pki::connect(path, "ribd", "rt1")`).
- Resync tests: `connections()` counts accepted dials, `close_connections()` (`close_stream()` on configd) forces a redial, `FakeConfigd::push_diff` feeds `SubscribeDiff` subscribers, `FakeInterfaced::push_link` feeds `SubscribeLinks`.
- Fire-and-forget requests (`Push*`, `SetStpPortStates`, `FlushFdb`, `SetErrDisabled`) are recorded: `take_pushed()` drains them. `serve` + `Reply` builds a one-off fake for any other protocol.
- Dev-dependency only, with the feature: `nos-test-support = { workspace = true, features = ["fakes"] }`. Without `fakes` the crate is empty, so `cargo build --workspace` never turns on `nos-pki/testing` for the daemons.

Containerized test environment:

```bash
make docker-build                        # build the nos-watchdogd/nos-configd/nos-bgpd/nos-ribd/nos-interfaced/nos-logd/nos-ospfd/nos-ospfv3d/nos-lacpd/nos-lldpd/nos-fdbd/nos-restd/nos Docker image
docker compose up -d watchdog            # run the watchdog (which starts nos-configd + nos-bgpd + nos-ribd + nos-interfaced + nos-logd + nos-ospfd + nos-ospfv3d + nos-lacpd + nos-lldpd, a nos-fdbd per broadcast domain with a vni, and a nos-restd per pinned routing table) in a container
docker compose run --rm cli              # interactive shell, as its own container, sharing configd's socket
```

`watchdog` and `cli` share the same image and an `nos-run` volume mounted at `/run/nos`, so `cli` reaches the daemon over the same Unix socket path both binaries default to. `watchdog` also gets an `nos-data` volume at `/var/lib/nos` so `save`d config survives container restarts. `docker compose exec watchdog nos` still works too — it just runs the shell inside the watchdog's own container instead of a separate one.

**Memory profiling**: `docker build --build-arg CARGO_FEATURES=nos-bgp/dhat-heap -t nos .` builds `nos-bgpd` with `dhat` heap profiling (see `docs/protocols/bgp-internals.md`'s "Memory profiling"); run it via `docker compose run --rm watchdog --bgpd-arg --profile-memory-out=/var/lib/nos/dhat-heap.json` (`--bgpd-arg` is `nos-watchdogd`'s existing opaque pass-through to every spawned `nos-bgpd` instance — no watchdog code involved) and load the resulting report from the `nos-data` volume at https://nnethercote.github.io/dh_view/dh_view.html.

Or run the underlying commands directly:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all
```
