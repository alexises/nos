.DEFAULT_GOAL := help
export RUSTFLAGS ?= -D warnings

IMAGE ?= nos:local
# e.g. CARGO_FEATURES=nos-bgp/dhat-heap make docker-build — see bgp/CLAUDE.md's
# "Memory profiling" note. Empty by default: no behavior change.
CARGO_FEATURES ?=
# Line-coverage floor for `make coverage` (and CI, which runs it) — 90%
# since #131 (measured 91.7%); raise it as tests land, never lower it.
COVERAGE_MIN ?= 90

.PHONY: help toolchain-check build fmt fmt-fix clippy clippy-fix fix test test-plain \
        deny audit sast miri coverage mutants check ci tools docker-lint docker-build \
        e2e-preflight docs-fix

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN{FS=":.*## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# Local == CI: rustc must be the toolchain pinned in rust-toolchain.toml, which must equal
# ci.yml's RUST_TOOLCHAIN. Install with `rustup toolchain install 1.99.0` (rustup reads the
# file automatically). Escape hatch: ALLOW_TOOLCHAIN_MISMATCH=1.
toolchain-check: ## Fail unless local rustc == CI's pinned toolchain
	@pin=$$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml); \
	ci=$$(sed -n 's/^ *RUST_TOOLCHAIN: *"\(.*\)"/\1/p' .github/workflows/ci.yml); \
	have=$$(rustc --version | awk '{print $$2}'); \
	[ "$$pin" = "$$ci" ] || { echo "rust-toolchain.toml ($$pin) != ci.yml RUST_TOOLCHAIN ($$ci)"; exit 1; }; \
	[ "$$have" = "$$pin" ] || [ -n "$$ALLOW_TOOLCHAIN_MISMATCH" ] || { \
	  echo "rustc $$have != CI's $$pin: run 'rustup toolchain install $$pin' (or ALLOW_TOOLCHAIN_MISMATCH=1)"; exit 1; }

build: toolchain-check ## Build the whole workspace
	cargo build --workspace

fmt: toolchain-check ## Check formatting (matches CI)
	cargo fmt --all -- --check

fmt-fix: ## Apply formatting
	cargo fmt --all

clippy: toolchain-check ## Lint the whole workspace, warnings deny (matches CI)
	cargo clippy --workspace --all-targets

clippy-fix: ## Apply clippy's auto-fixable suggestions, then re-check
	cargo clippy --fix --workspace --all-targets --allow-dirty --allow-staged
	$(MAKE) clippy

fix: fmt-fix clippy-fix ## Autofix everything that has an autofix (fmt + clippy --fix)

test: toolchain-check ## Run tests via nextest (matches CI)
	@command -v cargo-nextest >/dev/null 2>&1 || { echo "cargo-nextest not found — run 'make tools'"; exit 1; }
	cargo nextest run --workspace

test-plain: ## Run tests via plain `cargo test` (no extra tool needed)
	cargo test --workspace

deny: ## Check license/ban/source policy (matches CI)
	@command -v cargo-deny >/dev/null 2>&1 || { echo "cargo-deny not found — run 'make tools'"; exit 1; }
	cargo deny check

audit: ## Check for known security advisories (matches CI)
	@command -v cargo-audit >/dev/null 2>&1 || { echo "cargo-audit not found — run 'make tools'"; exit 1; }
	cargo audit

sast: ## Static analysis with semgrep's p/rust ruleset (matches CI; needs docker)
	docker run --rm -v "$(CURDIR):/src" semgrep/semgrep semgrep scan --config p/rust --exclude target --error --metrics=off /src

miri: ## Run miri UB checks on the pure-logic crates (needs a nightly toolchain + miri component; slow, matches CI)
	@command -v cargo-miri >/dev/null 2>&1 || { echo "cargo-miri not found — needs rustup + 'rustup +nightly component add miri'"; exit 1; }
	RUSTFLAGS="-D warnings -A deprecated" MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test -p nos-rpl -p nos-ospf-common -p nos-proto

coverage: ## Collect test coverage as lcov.info, failing under COVERAGE_MIN% lines (matches CI)
	@command -v cargo-llvm-cov >/dev/null 2>&1 || { echo "cargo-llvm-cov not found — run 'make tools'"; exit 1; }
	cargo llvm-cov --workspace --ignore-filename-regex '/tools/e2e/|/driver/linux\.rs$$|/driver/route_channel\.rs$$|/l2-socket/|/ospf(v3)?/src/socket\.rs$$' \
		--fail-under-lines $(COVERAGE_MIN) --lcov --output-path lcov.info

mutants: ## Run mutation testing (needs a nightly toolchain; slow — CI only runs this on schedule)
	@command -v cargo-mutants >/dev/null 2>&1 || { echo "cargo-mutants not found — run 'make tools'"; exit 1; }
	cargo +nightly mutants --workspace

docs-fix: ## Regenerate docs/openapi.json from nos-restd's OpenAPI document
	UPDATE_OPENAPI_SNAPSHOT=1 cargo test -p nos-rest --test openapi_snapshot

check: build fmt clippy test ## Fast local check: build + fmt + clippy + test (run before pushing)

ci: check deny audit ## Everything check does, plus deny/audit (skips slow nightly-only miri/mutants)

tools: ## Install optional cargo subcommands used by deny/audit/coverage/mutants/test targets
	cargo install --locked cargo-nextest cargo-deny cargo-audit cargo-llvm-cov cargo-mutants

docker-lint: ## Lint the Dockerfile with hadolint
	@command -v hadolint >/dev/null 2>&1 || { echo "hadolint not found — install it (already available in this env)"; exit 1; }
	hadolint Dockerfile

docker-build: docker-lint ## Lint, then build the nos Docker image (nos-watchdogd + nos-configd + nos-bgpd + nos-ribd + nos-interfaced + nos-logd + nos-ospfd + nos)
	docker build --build-arg CARGO_FEATURES=$(CARGO_FEATURES) -t $(IMAGE) .

e2e-preflight: ## Kernel-module + image-capability checks nos-e2e needs (same script CI runs)
	IMAGE=$(IMAGE) tools/ci/e2e-preflight.sh
