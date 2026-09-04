# ========================================================================================================
#
#    dP        oo          dP         dP    888888ba           oo       dP
#    88                    88         88    88    `8b                   88
#    88        dP .d8888b. 88d888b. d8888P a88aaaa8P' 88d888b. dP .d888b88 .d8888b. .d8888b.
#    88        88 88'  `88 88'  `88   88    88   `8b. 88'  `88 88 88'  `88 88'  `88 88ooood8
#    88        88 88.  .88 88    88   88    88    .88 88       88 88.  .88 88.  .88 88.  ...
#    88888888P dP `8888P88 dP    dP   dP    88888888P dP       dP `88888P8 `8888P88 `88888P'
#                      .88                                                      .88
#                  d8888P                                                   d8888P
#
#    ====================> AuthZ
#
#    Makefile for the project
#    Author: @stephane-segning
#
# ========================================================================================================

# Variable for passing commands like `just build c="app"`
c := ""

# ----------------------------------------------------------

# Initialize the project
init:
	docker compose -p lightbridge-authz -f compose.yaml build {{c}}

# Show this help
help:
	@just --summary

# Pull the image
pull:
	docker compose -p lightbridge-authz -f compose.yaml pull {{c}}

# Build the project
build:
	docker compose -p lightbridge-authz -f compose.yaml build {{c}}

# Stage the pinned authz-ui bundle into ./dist/static (what config/default.yaml's static_dir
# defaults to). Uses the ONE pin in ./Dockerfile -- never restate it here.
stage-authz-ui:
	@bash -ec 'set -euo pipefail; ref="$(sed -n "s/^ARG AUTHZ_UI_REF=//p" Dockerfile | head -n1)"; [ -n "$ref" ] || { echo "no ARG AUTHZ_UI_REF= in ./Dockerfile" >&2; exit 1; }; echo "staging $ref"; ctr="authz-ui-stage-$$"; docker pull --platform linux/amd64 "$ref"; docker create --name "$ctr" "$ref" /nonexistent >/dev/null; trap "docker rm -f \"$ctr\" >/dev/null 2>&1 || true" EXIT; mkdir -p dist/static; docker cp "$ctr:/dist/." dist/static/; ls -lash dist/static/'

# Start the project
up:
	docker compose -p lightbridge-authz -f compose.yaml up -d --remove-orphans --build {{c}}

# Start a single service
up-single app:
	docker compose -p lightbridge-authz -f compose.yaml up -d --remove-orphans --build {{app}} {{c}}

# Start the project (without rebuild)
up-no-build:
	docker compose -p lightbridge-authz -f compose.yaml up -d --remove-orphans {{c}}

# Show images
img:
	docker compose -p lightbridge-authz -f compose.yaml images {{c}}

# Start the project (without rebuild)
start:
	docker compose -p lightbridge-authz -f compose.yaml start {{c}}

# Stop the project
down:
	docker compose -p lightbridge-authz -f compose.yaml down {{c}}

# Destroy the project
destroy:
	docker compose -p lightbridge-authz -f compose.yaml down -v {{c}}

# Stop containers
stop:
	docker compose -p lightbridge-authz -f compose.yaml stop {{c}}

# Restart the project
restart:
	docker compose -p lightbridge-authz -f compose.yaml stop {{c}}
	docker compose -p lightbridge-authz -f compose.yaml up -d {{c}}

# Show logs
logs:
	docker compose -p lightbridge-authz -f compose.yaml logs --tail=100 -f {{c}}

# Show API logs
logs-api:
	docker compose -p lightbridge-authz -f compose.yaml logs --tail=100 -f authz-api {{c}}

# Show OPA logs
logs-opa:
	docker compose -p lightbridge-authz -f compose.yaml logs --tail=100 -f authz-opa {{c}}

# Show usage API logs
logs-usage:
	docker compose -p lightbridge-authz -f compose.yaml logs --tail=100 -f authz-usage {{c}}

# Show MCP API logs
logs-mcp:
	docker compose -p lightbridge-authz -f compose.yaml logs --tail=100 -f authz-mcp {{c}}

# Show status
ps:
	docker compose -p lightbridge-authz -f compose.yaml ps {{c}}

# Show all containers
ps-all:
	docker compose -p lightbridge-authz -f compose.yaml ps --all {{c}}

# Run migrations once
migrate:
	docker compose -p lightbridge-authz -f compose.yaml run --rm authz-migrate

# Run usage migrations once
usage-migrate:
	docker compose -p lightbridge-authz -f compose.yaml run --rm authz-usage-migrate

# Run Authorino integration test setup
it-authorino:
	@just it-authorino-down
	docker compose -p lightbridge-authz -f compose.yaml -f compose.it.yaml up -d --build
	docker compose -p lightbridge-authz -f compose.yaml -f compose.it.yaml run --rm it-authorino

# Cleanup Authorino integration test setup
it-authorino-down:
	docker compose -p lightbridge-authz -f compose.yaml -f compose.it.yaml down -v

# Run integration checks across API/OPA/Usage/MCP services
it-servers:
	@just it-servers-down
	docker compose -p lightbridge-authz -f compose.yaml -f compose.it.yaml up -d --build
	docker compose -p lightbridge-authz -f compose.yaml -f compose.it.yaml run --rm it-servers

# Cleanup service integration test setup
it-servers-down:
	docker compose -p lightbridge-authz -f compose.yaml -f compose.it.yaml down -v

# Run end-to-end checks against authz-idp (discovery, browser/device flows, token exchange, introspection, revocation)
it-idp:
	@just it-idp-down
	docker compose -p lightbridge-authz -f compose.yaml -f compose.it.yaml up -d --build
	docker compose -p lightbridge-authz -f compose.yaml -f compose.it.yaml run --rm it-idp

# Cleanup authz-idp integration test setup
it-idp-down:
	docker compose -p lightbridge-authz -f compose.yaml -f compose.it.yaml down -v

# Show stats
stats:
	docker compose -p lightbridge-authz -f compose.yaml stats {{c}}

# Run load tests against the OPA endpoint
load-test:
	@bash -ec 'set -euo pipefail; cmd="docker compose -p lightbridge-authz -f compose.yaml"; ${cmd} up -d authz-tls postgresql authz-migrate authz-opa; trap "${cmd} down authz-tls postgresql authz-migrate authz-opa" EXIT; sleep 5; cargo test -p lightbridge-authz-rest --features load-tests --test load_tests -- --host https://localhost:13001 -u 10 -r 2 -t 30s --accept-invalid-certs'

# Run database-backed integration tests.
# `lightbridge-authz`'s own `mcp_tool_it_tests` runs here too (lightbridge-authz#645): the MCP
# procedure tools reach the same database through the same `Procedures` registry the two RPC
# listeners use, and the per-tool `RpcScope` switch that lets one MCP listener serve both the crud
# and budget halves is only observable against a real cratestack policy evaluation.
# Brings up Postgres + Redis (the cratestack RPC surface's rate limiter is Redis-backed, ADR-0003)
# and runs migrations against the shared DB (the rest crate's RPC integration tests connect the
# cratestack pool directly to DATABASE_URL, unlike the api-key crate's ephemeral sqlx::test DBs).
# lightbridge-authz-usage-rest's own ephemeral sqlx::test suites (`repo_it_tests`,
# `spend_query_it_tests`, `scope_ownership_it_tests` -- #570/#578) run against this SAME
# `postgresql` service, not a dedicated Timescale container:
# `migrations-usage/20260829000001_usage_event_latency.sql` is deliberately written to
# degrade on vanilla Postgres, and production runs plain Postgres today (#549 Finding 2).
# Timescale-shaped CI is deferred to the epic's Phase 1 storage rewrite, gated on the #581 D1
# image decision.
# The usage it-tests guard is PER-BINARY (each of repo_it_tests/spend_query_it_tests/
# scope_ownership_it_tests/retention_it_tests must itself report >0 passed), not an aggregate
# total -- an aggregate
# would hide one binary silently reporting "0 tests, exit 0" as long as the other two still pass
# a nonzero count, the same "a skipped test is not a passing test" failure mode AGENTS.md warns
# about, just moved one level up from an individual test to an individual binary.
it-tests:
	@bash -ec 'set -euo pipefail; cmd="docker compose -p lightbridge-authz -f compose.yaml"; ${cmd} up -d postgresql redis; ${cmd} up authz-migrate --exit-code-from authz-migrate; trap "${cmd} down postgresql redis authz-migrate" EXIT; sleep 2; export DATABASE_URL="postgres://postgres:postgres@localhost:5432/lightbridge_authz"; export AUTHZ_REDIS_URL="redis://127.0.0.1:6379"; cargo test -p lightbridge-authz-api-key --features it-tests --tests; cargo test -p lightbridge-authz-budget --features it-tests --tests; cargo test -p lightbridge-authz-rest --features it-tests; cargo test -p lightbridge-authz --features it-tests --test mcp_tool_it_tests; check_binary() { log_file=$(mktemp); cargo test -p lightbridge-authz-usage-rest --features it-tests --test "$1" 2>&1 | tee "${log_file}"; passed=$(grep -oE "[0-9]+ passed" "${log_file}" | grep -oE "^[0-9]+" | tail -1 || true); echo "$1 passed: ${passed:-0}"; if [ -z "${passed}" ] || [ "${passed}" -eq 0 ]; then echo "$1 reported 0 passed tests -- a skip is not a pass"; exit 1; fi; }; check_binary repo_it_tests; check_binary spend_query_it_tests; check_binary scope_ownership_it_tests; check_binary retention_it_tests'

all-checks:
	@echo "Running Rust formatting, lint, and checks"
	cargo fmt --all
	cargo deny check
	cargo fix --workspace --allow-dirty
	cargo clippy --workspace --all-targets --all-features --fix --allow-dirty -- -D warnings
	cargo check --workspace --all-targets --all-features
