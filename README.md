# Lightbridge Authz

Lightbridge Authz is an API-key storage and validation service with two HTTP servers: a CRUD API for managing accounts/projects/keys and an Authorino OPA-facing API secured with basic auth.

- Workspace layout is defined in [Cargo.toml](Cargo.toml:1).
- Core exports are in [crates/lightbridge-authz-core/src/lib.rs](crates/lightbridge-authz-core/src/lib.rs:1).
- HTTP server entry points are [start_api_server()](crates/lightbridge-authz-rest/src/lib.rs:32) and [start_opa_server()](crates/lightbridge-authz-rest/src/lib.rs:57).
- CLI entry is [main()](app/lightbridge-authz/src/main.rs:37), with subcommands declared at [enum Commands](app/lightbridge-authz/src/utils/cli.rs:11).

## Why?

- Centralize API key storage and validation logic behind a single core.
- Provide a CRUD API for administration plus a dedicated OPA interface for runtime validation.
- Use a single YAML config to keep deployments simple and reproducible.

## Actual

- Core library exposes config loading, error types, DB primitives, and API key models, see re-exports in [lib.rs](crates/lightbridge-authz-core/src/lib.rs:7).
- REST crate exposes async server start functions: [start_api_server()](crates/lightbridge-authz-rest/src/lib.rs:32) and [start_opa_server()](crates/lightbridge-authz-rest/src/lib.rs:57).
- CLI parses commands and flags using clap, see [Cli](app/lightbridge-authz/src/utils/cli.rs:4), [Commands](app/lightbridge-authz/src/utils/cli.rs:11), and [main()](app/lightbridge-authz/src/main.rs:20).
- Configuration lives in [config/default.yaml](config/default.yaml:1).

## Constraints

- Rust 2024 edition (workspace-wide).
- Single-source configuration via YAML files.
- Error handling centralized in core; prefer using the core Result and Error.
- Avoid putting too much logic in one file; favor small, focused modules.

## Installation

- Prerequisites:
  - Rust stable toolchain.
  - PostgreSQL (if using the database features).
- Clone the repo and build:
  - cargo build
  - cargo test
- Optional: set DATABASE_URL if different from the YAML configuration.

Workspace crates are listed in [Cargo.toml](Cargo.toml:2).

## Usage

- Prepare a config file patterned after [config/default.yaml](config/default.yaml:1).

Example run commands (CLI parsing defined at [app/lightbridge-authz/src/main.rs](app/lightbridge-authz/src/main.rs:1)):

- Run API server:
  - cargo run -p lightbridge-authz -- api --config ./config/default.yaml
- Run OPA server:
  - cargo run -p lightbridge-authz -- opa --config ./config/default.yaml
- Validate config:
  - cargo run -p lightbridge-authz -- config --config ./config/default.yaml --check_config
- Healthcheck:
  - cargo run -p lightbridge-authz-healthcheck -- -r 3000

## API Documentation

Current status: HTTP API + OPA servers are available.

- CRUD API:
  - Entrypoint: [start_api_server()](crates/lightbridge-authz-rest/src/lib.rs:32).
  - Routes (prefix `/api/v1`):
    - Accounts: POST/GET `/accounts`, GET/PATCH/DELETE `/accounts/{account_id}`
    - Projects: POST/GET `/accounts/{account_id}/projects`, GET/PATCH/DELETE `/projects/{project_id}`
    - API Keys: POST/GET `/projects/{project_id}/api-keys`, GET/PATCH/DELETE `/api-keys/{key_id}`
    - Lifecycle: POST `/api-keys/{key_id}/revoke`, POST `/api-keys/{key_id}/rotate`
- OPA API:
  - Entrypoint: [start_opa_server()](crates/lightbridge-authz-rest/src/lib.rs:57).
  - Route: POST `/v1/opa/validate` (Basic auth).

## Configuration

Base config example: [config/default.yaml](config/default.yaml:1)

- server.api.address: string IP to bind.
- server.api.port: numeric port.
- server.api.tls.cert_path / key_path: TLS certificate + key.
- server.opa.address: string IP to bind.
- server.opa.port: numeric port.
- server.opa.tls.cert_path / key_path: TLS certificate + key.
- server.opa.basic_auth.username/password: Basic auth for Authorino OPA.

TLS is required for both servers. Provide PEM-encoded cert/key pairs at the paths configured in the YAML files (e.g., `/tls/api.crt` and `/tls/api.key`).

When using `compose.yaml`, the `authz-tls` service generates self-signed certs and stores them in the `authz_tls` volume, which is mounted into the `authz-api` and `authz-opa` containers at `/tls`.
- logging.level: log level string, see [level](config/default.yaml:7).
- auth.api_keys: list of allowed API keys, see [api_keys](config/default.yaml:9).
- database.url: Postgres connection string, see [url](config/default.yaml:13).

Core config loader is exposed from [load_from_path()](crates/lightbridge-authz-core/src/lib.rs:8) and [Config](crates/lightbridge-authz-core/src/lib.rs:8).

## Development

- Primary crates:
  - Core: [crates/lightbridge-authz-core](crates/lightbridge-authz-core/src/lib.rs:1)
  - HTTP servers: [crates/lightbridge-authz-rest](crates/lightbridge-authz-rest/src/lib.rs:1)
  - CLI: [app/lightbridge-authz](app/lightbridge-authz/src/main.rs:1)
  - Healthcheck: [app/lightbridge-authz-healthcheck](app/lightbridge-authz-healthcheck/src/main.rs:1)
  - Migrate runner: [app/lightbridge-authz-migrate](app/lightbridge-authz-migrate/src/main.rs:1)
  - API facade: [crates/lightbridge-authz-api](crates/lightbridge-authz-api/src/lib.rs:1)

- Testing:
  - Run all: cargo test

- Logging:
  - Provided by tracing; level set via config [logging.level](config/default.yaml:7).

## Contributing

- Fork and create a feature branch.
- Ensure rustfmt and clippy pass.
- Add tests in the respective crate's tests/ directory.
- Open a PR with a clear description and link relevant code areas:
  - Core changes around [Error, Result](crates/lightbridge-authz-core/src/lib.rs:9).
  - CLI surface at [Commands](app/lightbridge-authz/src/utils/cli.rs:11).
  - HTTP servers at [start_api_server()](crates/lightbridge-authz-rest/src/lib.rs:32) and [start_opa_server()](crates/lightbridge-authz-rest/src/lib.rs:57).

## License

No LICENSE file found in the repository at this time. Add a LICENSE file (e.g., MIT, Apache-2.0) at the repo root and reference it here once chosen.
