.DEFAULT_GOAL := help
export RUSTFLAGS ?= -D warnings

IMAGE ?= nos:local
# e.g. CARGO_FEATURES=nos-bgp/dhat-heap make docker-build — see docs/architecture/development.md's
# "Memory profiling" note. Empty by default: no behavior change.
CARGO_FEATURES ?=
# Line-coverage floor for `make coverage` (and CI, which runs it) — 90%
# since #131 (measured 91.7%); raise it as tests land, never lower it.
COVERAGE_MIN ?= 90

.PHONY: help ci-image toolchain-check build fmt fmt-fix clippy clippy-fix fix test test-plain \
        deny audit sast miri coverage mutants check ci tools docker-lint docker-build \
        e2e-preflight docs-fix claude-md-size

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN{FS=":.*## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# Local == CI (#180): every Rust target runs on the toolchain CI pins. PIN is
# rust-toolchain.toml's channel (must equal ci.yml's RUST_TOOLCHAIN), MIRI_TOOLCHAIN is
# ci.yml's dated nightly. If the local rustc already is PIN (rustup reads the file), RUN
# is empty and cargo runs natively, as on CI. Otherwise RUN runs it in the nos-ci image
# (tools/ci/Dockerfile, built by `make ci-image`), with its own target dir and cargo
# home under target/ so it never mixes with the host toolchain's build.
PIN := $(shell sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)
MIRI_TOOLCHAIN := $(shell sed -n 's/^ *MIRI_TOOLCHAIN: *"\(.*\)"/\1/p' .github/workflows/ci.yml)
CI_IMAGE := nos-ci:$(PIN)-$(MIRI_TOOLCHAIN)
ifeq ($(shell rustc --version 2>/dev/null | awk '{print $$2}'),$(PIN))
RUN :=
else
RUN := docker run --rm --user $(shell id -u):$(shell id -g) -v $(CURDIR):/src -w /src \
	-e RUSTFLAGS -e MIRIFLAGS -e UPDATE_OPENAPI_SNAPSHOT -e CARGO_TERM_COLOR \
	-e HOME=/src/target/ci-home -e CARGO_HOME=/src/target/ci-cargo -e CARGO_TARGET_DIR=/src/target/ci \
	$(CI_IMAGE)
endif

ci-image: ## Build the nos-ci toolchain image if this host needs it and it is missing
	@[ -z "$(RUN)" ] || docker image inspect $(CI_IMAGE) >/dev/null 2>&1 || \
	  docker build --build-arg RUST_TOOLCHAIN=$(PIN) --build-arg MIRI_TOOLCHAIN=$(MIRI_TOOLCHAIN) \
	    -t $(CI_IMAGE) tools/ci

toolchain-check: ci-image ## Fail unless rust-toolchain.toml == ci.yml's RUST_TOOLCHAIN; say where cargo runs
	@ci=$$(sed -n 's/^ *RUST_TOOLCHAIN: *"\(.*\)"/\1/p' .github/workflows/ci.yml); \
	[ "$(PIN)" = "$$ci" ] || { echo "rust-toolchain.toml ($(PIN)) != ci.yml RUST_TOOLCHAIN ($$ci)"; exit 1; }; \
	echo "toolchain: $(PIN) ($(if $(RUN),docker $(CI_IMAGE),native))"

build: toolchain-check ## Build the whole workspace
	$(RUN) cargo build --workspace

fmt: toolchain-check ## Check formatting (matches CI)
	$(RUN) cargo fmt --all -- --check

fmt-fix: toolchain-check ## Apply formatting
	$(RUN) cargo fmt --all

clippy: toolchain-check ## Lint the whole workspace, warnings deny (matches CI)
	$(RUN) cargo clippy --workspace --all-targets

clippy-fix: toolchain-check ## Apply clippy's auto-fixable suggestions, then re-check
	$(RUN) cargo clippy --fix --workspace --all-targets --allow-dirty --allow-staged
	$(MAKE) clippy

fix: fmt-fix clippy-fix ## Autofix everything that has an autofix (fmt + clippy --fix)

test: toolchain-check ## Run tests via nextest (matches CI)
	$(RUN) cargo nextest run --workspace

test-plain: toolchain-check ## Run tests via plain `cargo test` (no extra tool needed)
	$(RUN) cargo test --workspace

deny: toolchain-check ## Check license/ban/source policy (matches CI)
	$(RUN) cargo deny check

audit: toolchain-check ## Check for known security advisories (matches CI)
	$(RUN) cargo audit

sast: ## Static analysis with semgrep's p/rust ruleset (matches CI; needs docker)
	docker run --rm -v "$(CURDIR):/src" semgrep/semgrep semgrep scan --config p/rust --exclude target --error --metrics=off /src

miri: toolchain-check ## Run miri UB checks on the pure-logic crates on ci.yml's MIRI_TOOLCHAIN (slow, matches CI)
	RUSTFLAGS="-D warnings -A deprecated" MIRIFLAGS="-Zmiri-disable-isolation" $(RUN) cargo +$(MIRI_TOOLCHAIN) miri test -p nos-rpl -p nos-ospf-common -p nos-proto

coverage: toolchain-check ## Collect test coverage as lcov.info, failing under COVERAGE_MIN% lines (matches CI)
	$(RUN) cargo llvm-cov --workspace --ignore-filename-regex '/tools/e2e/|/driver/linux\.rs$$|/driver/route_channel\.rs$$|/l2-socket/|/ospf(v3)?/src/socket\.rs$$|/bfd/src/socket\.rs$$' \
		--fail-under-lines $(COVERAGE_MIN) --lcov --output-path lcov.info

mutants: ## Run mutation testing (needs a nightly toolchain; slow — CI only runs this on schedule)
	@command -v cargo-mutants >/dev/null 2>&1 || { echo "cargo-mutants not found — run 'make tools'"; exit 1; }
	cargo +nightly mutants --workspace

docs-fix: toolchain-check ## Regenerate docs/openapi.json from nos-restd's OpenAPI document
	UPDATE_OPENAPI_SNAPSHOT=1 $(RUN) cargo test -p nos-rest --test openapi_snapshot

claude-md-size: ## Fail when a CLAUDE.md exceeds its ceiling in tools/ci/claude-md-budget.txt
	tools/ci/check-claude-md.sh

check: claude-md-size build fmt clippy test ## Fast local check: build + fmt + clippy + test (run before pushing)

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
