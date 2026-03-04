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
	docker compose -p lightbridge-authz -f compose.yaml -f compose.it.yaml up -d --build
	docker compose -p lightbridge-authz -f compose.yaml -f compose.it.yaml run --rm it-authorino

# Cleanup Authorino integration test setup
it-authorino-down:
	docker compose -p lightbridge-authz -f compose.yaml -f compose.it.yaml down -v

# Run integration checks across API/OPA/Usage/MCP services
it-servers:
	docker compose -p lightbridge-authz -f compose.yaml -f compose.it.yaml up -d --build
	docker compose -p lightbridge-authz -f compose.yaml -f compose.it.yaml run --rm it-servers

# Cleanup service integration test setup
it-servers-down:
	docker compose -p lightbridge-authz -f compose.yaml -f compose.it.yaml down -v

# Show stats
stats:
	docker compose -p lightbridge-authz -f compose.yaml stats {{c}}

# Run load tests against the OPA endpoint
load-test:
	@bash -ec 'set -euo pipefail; cmd="docker compose -p lightbridge-authz -f compose.yaml"; ${cmd} up -d authz-tls postgresql authz-migrate authz-opa; trap "${cmd} down authz-tls postgresql authz-migrate authz-opa" EXIT; sleep 5; cargo test -p lightbridge-authz-rest --features load-tests --test load_tests -- --host https://localhost:13001 -u 10 -r 2 -t 30s --accept-invalid-certs'

# Run database-backed integration tests
it-tests:
	@bash -ec 'set -euo pipefail; cmd="docker compose -p lightbridge-authz -f compose.yaml"; ${cmd} up -d postgresql; trap "${cmd} down postgresql" EXIT; sleep 3; export DATABASE_URL="postgres://postgres:postgres@localhost:5432/lightbridge_authz"; cargo test -p lightbridge-authz-api-key --features it-tests --tests'

all-checks:
	@echo "Running Rust formatting, lint, and checks"
	cargo fmt
	cargo deny check
	cargo fix --allow-dirty
	cargo clippy --all-targets --all-features --fix --allow-dirty -- -D warnings
	cargo check --all-targets --all-features
