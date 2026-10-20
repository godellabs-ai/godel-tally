.DEFAULT_GOAL := help

.PHONY: help fmt lint test check audit secret-scan compose-check build web-install web-lint web-test web-typecheck web-build web-e2e run up down schemas schema-check registry-lint registry-build dev dev-api dev-web dev-collector data-up release-readiness package release-local docker-up docker-down

COMPOSE ?= $(shell docker compose version >/dev/null 2>&1 && echo "docker compose" || echo "docker-compose")
COMPOSE_FILE ?= docker-compose.yml
DEV_COMPOSE_FILE ?= docker-compose.dev.yml
GITLEAKS_IMAGE ?= ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f

help:
	@echo "Gödel Tally: single binary + PostgreSQL + ClickHouse"
	@echo "  make build       Build release tallyd with embedded UI (no Docker)"
	@echo "  make run         Run the built binary locally at https://localhost:8443"
	@echo "  make dev         Native Rust/Next.js live reload; Docker databases by default"
	@echo "  make data-up     Start databases (TALLY_DB_MODE=docker|apple|existing)"
	@echo "  make down        Stop local database containers, preserving volumes"
	@echo "  make docker-up   Optional full Docker deployment (builds the Tally image)"
	@echo "  make check       Format, lint, test and validate the embedded UI"
	@echo "  make package     Create a release archive for this host architecture"
	@echo "  make release-local Build all four release archives on a Mac (no GitHub Actions)"
	@echo "Customer installation: bash install.sh --db native (default)"

fmt:
	cargo fmt --all

lint: registry-build web-build
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test: registry-build web-build
	cargo test --workspace --all-features

web-install:
	npm --prefix apps/web ci

web-lint:
	npm --prefix apps/web run lint

web-test:
	npm --prefix apps/web test

web-typecheck:
	npm --prefix apps/web run typecheck

web-build:
	npm --prefix apps/web run build

web-e2e:
	npm --prefix apps/web run e2e

schemas:
	cargo run -q -p tally-registry-cli -- schemas --output .

schema-check:
	cargo run -q -p tally-registry-cli -- schemas --output . --check

registry-lint:
	cargo run -q -p tally-registry-cli -- lint --source registry-data/source

registry-build:
	cargo run -q -p tally-registry-cli -- build --source registry-data/source --output registry-data/dist

check: registry-build web-build
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	cargo test --workspace --all-features
	$(MAKE) schema-check
	$(MAKE) registry-lint
	npm --prefix apps/web run lint
	npm --prefix apps/web test
	npm --prefix apps/web run typecheck

audit:
	cargo deny check advisories bans licenses sources
	npm --prefix apps/web audit --audit-level=moderate

secret-scan:
	@set -e; if [ -f .git ]; then abs_git_dir="$$(git rev-parse --absolute-git-dir)"; git_root="$${abs_git_dir%%/modules/*}"; git_suffix="$${abs_git_dir#$$git_root}"; docker run --rm -e GIT_DIR="/.git$$git_suffix" -e GIT_WORK_TREE=/repo -v "$(CURDIR):/repo:ro" -v "$$git_root:/.git:ro" $(GITLEAKS_IMAGE) git /repo --config=/repo/.gitleaks.toml --no-banner --no-color --redact; else docker run --rm -v "$(CURDIR):/repo:ro" $(GITLEAKS_IMAGE) git /repo --config=/repo/.gitleaks.toml --no-banner --no-color --redact; fi
	@{ git ls-files -co --exclude-standard | while IFS= read -r file; do [ -f "$$file" ] || continue; case "$$file" in *.gif|*.ico|*.png|*.zst) continue ;; esac; printf '\nFILE: %s\n' "$$file"; sed -n '1,$$p' "$$file"; done; } | docker run --rm -i -v "$(CURDIR):/repo:ro" $(GITLEAKS_IMAGE) stdin --config=/repo/.gitleaks.toml --no-banner --no-color --redact

compose-check:
	TALLY_SECRET_KEY=compose-validation-only TALLY_POSTGRES_PASSWORD=validation TALLY_CLICKHOUSE_PASSWORD=validation $(COMPOSE) -f "$(COMPOSE_FILE)" config --quiet
	TALLY_SECRET_KEY=compose-validation-only TALLY_POSTGRES_PASSWORD=validation TALLY_CLICKHOUSE_PASSWORD=validation $(COMPOSE) -f "$(COMPOSE_FILE)" -f "$(DEV_COMPOSE_FILE)" config --quiet

build: registry-build web-build
	cargo build --locked --release -p tallyd --features embedded-ui

package: build
	bash scripts/package-release.sh

release-local:
	bash scripts/build-release.sh

data-up:
	bash scripts/data-services.sh up

dev: registry-build
	bash dev-run.sh

dev-api: registry-build
	cargo run -p tallyd

dev-web:
	npm --prefix apps/web run dev

# Optional independent receiver/CLI; normal dev and production already include the worker.
dev-collector: registry-build
	cargo run -p tallyd -- collector --help

release-readiness: check
	bash scripts/test-deployment.sh

run:
	bash prod-run.sh

up: run

down:
	bash scripts/data-services.sh stop

docker-up:
	bash scripts/docker-run.sh

docker-down:
	$(COMPOSE) -f "$(COMPOSE_FILE)" down
