.DEFAULT_GOAL := help
export RUSTFLAGS ?= -D warnings

IMAGE ?= nos:local

.PHONY: help build fmt fmt-fix clippy clippy-fix fix test test-plain \
        deny audit geiger miri mutants check ci tools docker-lint docker-build

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN{FS=":.*## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

build: ## Build the whole workspace
	cargo build --workspace

fmt: ## Check formatting (matches CI)
	cargo fmt --all -- --check

fmt-fix: ## Apply formatting
	cargo fmt --all

clippy: ## Lint the whole workspace, warnings deny (matches CI)
	cargo clippy --workspace --all-targets

clippy-fix: ## Apply clippy's auto-fixable suggestions, then re-check
	cargo clippy --fix --workspace --all-targets --allow-dirty --allow-staged
	$(MAKE) clippy

fix: fmt-fix clippy-fix ## Autofix everything that has an autofix (fmt + clippy --fix)

test: ## Run tests via nextest (matches CI)
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

geiger: ## Inventory unsafe code (matches CI)
	@command -v cargo-geiger >/dev/null 2>&1 || { echo "cargo-geiger not found — run 'make tools'"; exit 1; }
	cargo geiger --workspace

miri: ## Run miri UB checks (needs a nightly toolchain + miri component; slow)
	@command -v cargo-miri >/dev/null 2>&1 || { echo "cargo-miri not found — needs rustup + 'rustup +nightly component add miri'"; exit 1; }
	cargo +nightly miri test --workspace

mutants: ## Run mutation testing (needs a nightly toolchain; slow — CI only runs this on schedule)
	@command -v cargo-mutants >/dev/null 2>&1 || { echo "cargo-mutants not found — run 'make tools'"; exit 1; }
	cargo +nightly mutants --workspace

check: build fmt clippy test ## Fast local check: build + fmt + clippy + test (run before pushing)

ci: check deny audit geiger ## Everything check does, plus deny/audit/geiger (skips slow nightly-only miri/mutants)

tools: ## Install optional cargo subcommands used by deny/audit/geiger/mutants/test targets
	cargo install --locked cargo-nextest cargo-deny cargo-audit cargo-geiger cargo-mutants

docker-lint: ## Lint the Dockerfile with hadolint
	@command -v hadolint >/dev/null 2>&1 || { echo "hadolint not found — install it (already available in this env)"; exit 1; }
	hadolint Dockerfile

docker-build: docker-lint ## Lint, then build the nos Docker image (nos-watchdogd + nos-configd + nos-bgpd + nos-ribd + nos-interfaced + nos-logd + nos)
	docker build -t $(IMAGE) .
