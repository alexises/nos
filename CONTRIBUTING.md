# Contributing

- Build and test: see "Build natively" in [`README.md`](README.md); `make check` must pass before you push.
- A change that programs the kernel, adds a cross-daemon IPC call or changes what is advertised over a real session needs an `nos-e2e` phase, and you must run it. Rules and template: the "New features require an end-to-end Docker verification phase" section of [`CLAUDE.md`](CLAUDE.md); phase list in [`docs/e2e-phases.md`](docs/e2e-phases.md).
- Pure logic (validators, codecs, bytecode) needs unit tests only.
- Docs live under `docs/`: bullets, how-to focus, tables only for tabular data.
- One PR per issue; do not lower the coverage floor (`COVERAGE_MIN` in the `Makefile`).

## The `ponytail:` marker

- A `ponytail:` comment marks a deliberate simplification with a known ceiling.
- The text names the ceiling and the upgrade path, e.g. `// ponytail: linear scan, index by prefix past ~10k routes`.
- List them all: `grep -rn 'ponytail:' --include='*.rs' --include='*.md' .`
- Before removing one, make sure the ceiling it names is gone.

## Coding agents

Agents read [`CLAUDE.md`](CLAUDE.md) and the `CLAUDE.md` of each crate they touch.
