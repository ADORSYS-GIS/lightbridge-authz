# Lightbridge Authz

Lightbridge Authz is a modular authorization and API-key validation service with pluggable transports (REST and gRPC), a shared core library for configuration, persistence, and errors, and a CLI to run servers and perform basic checks.

- Workspace layout is defined in [Cargo.toml](Cargo.toml:1).
- Core exports are in [crates/lightbridge-authz-core/src/lib.rs](crates/lightbridge-authz-core/src/lib.rs:1).
- REST server entry point is [start_rest_server()](crates/lightbridge-authz-rest/src/lib.rs:4).
- gRPC server entry point is [start_grpc_server()](crates/lightbridge-authz-grpc/src/lib.rs:19).
- CLI entry is [main()](crates/lightbridge-authz-cli/src/main.rs:37), with subcommands declared at [enum Commands](crates/lightbridge-authz-cli/src/main.rs:11).

## Why?

- Centralize API key validation and authorization logic behind a transport-agnostic core.
- Provide REST and gRPC frontends for flexible integration.
- Use a single YAML config to keep deployments simple and reproducible.

## Actual

- Core library exposes config loading, error types, DB primitives, and API key models, see re-exports in [lib.rs](crates/lightbridge-authz-core/src/lib.rs:7).
- REST and gRPC crates currently expose async server start functions: [start_rest_server()](crates/lightbridge-authz-rest/src/lib.rs:4) and [start_grpc_server()](crates/lightbridge-authz-grpc/src/lib.rs:19). They are placeholders ready for wiring.
- CLI parses commands and flags using clap, see [Cli](crates/lightbridge-authz-cli/src/main.rs:6), [Commands](crates/lightbridge-authz-cli/src/main.rs:11), and [main()](crates/lightbridge-authz-cli/src/main.rs:37).
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

Example run commands (CLI parsing defined at [crates/lightbridge-authz-cli/src/main.rs](crates/lightbridge-authz-cli/src/main.rs:1)):

- Run REST server (placeholder implementation):
  - cargo run -p lightbridge-authz-cli -- serve --config ./config/default.yaml --rest
- Run gRPC server (placeholder implementation):
  - cargo run -p lightbridge-authz-cli -- serve --config ./config/default.yaml --grpc
- Validate config:
  - cargo run -p lightbridge-authz-cli -- config --config ./config/default.yaml --check_config
- Client health (transport argument parsed at [transport](crates/lightbridge-authz-cli/src/main.rs:30) and health flag at [health](crates/lightbridge-authz-cli/src/main.rs:33)):
  - cargo run -p lightbridge-authz-cli -- client --config ./config/default.yaml --transport rest --health

## API Documentation

Current status: REST and gRPC servers are scaffolds.

- REST:
  - Entrypoint: [start_rest_server()](crates/lightbridge-authz-rest/src/lib.rs:4).
  - Planned endpoints:
    - POST /v1/keys/validate: Validate an API key.
    - GET /health: Health check.
- gRPC:
  - Entrypoint: [start_grpc_server()](crates/lightbridge-authz-grpc/src/lib.rs:19).
  - Planned services:
    - Authz.ValidateKey: Validate an API key.
    - Health.Check: Health check.

Proto definitions will live under the proto crate (see [crates/lightbridge-authz-proto](crates/lightbridge-authz-proto/src/lib.rs:1) and build script [build.rs](crates/lightbridge-authz-proto/build.rs:1)).

## Configuration

Base config example: [config/default.yaml](config/default.yaml:1)

- server.grpc.address: string IP to bind, see [address](config/default.yaml:4).
- server.grpc.port: numeric port, see [port](config/default.yaml:5).
- logging.level: log level string, see [level](config/default.yaml:7).
- auth.api_keys: list of allowed API keys, see [api_keys](config/default.yaml:9).
- database.url: Postgres connection string, see [url](config/default.yaml:13).

Core config loader is exposed from [load_from_path()](crates/lightbridge-authz-core/src/lib.rs:8) and [Config](crates/lightbridge-authz-core/src/lib.rs:8).

## Development

- Primary crates:
  - Core: [crates/lightbridge-authz-core](crates/lightbridge-authz-core/src/lib.rs:1)
  - REST: [crates/lightbridge-authz-rest](crates/lightbridge-authz-rest/src/lib.rs:1)
  - gRPC: [crates/lightbridge-authz-grpc](crates/lightbridge-authz-grpc/src/lib.rs:1)
  - CLI: [crates/lightbridge-authz-cli](crates/lightbridge-authz-cli/src/main.rs:1)
  - API facade: [crates/lightbridge-authz-api](crates/lightbridge-authz-api/src/lib.rs:1)
  - Proto: [crates/lightbridge-authz-proto](crates/lightbridge-authz-proto/src/lib.rs:1)

- Testing:
  - Integration tests live in tests/ folders like [crates/lightbridge-authz-rest/tests/api_tests.rs](crates/lightbridge-authz-rest/tests/api_tests.rs:1).
  - Run all: cargo test

- Logging:
  - Provided by tracing; level set via config [logging.level](config/default.yaml:7).

## Contributing

- Fork and create a feature branch.
- Ensure rustfmt and clippy pass.
- Add tests in the respective crate's tests/ directory.
- Open a PR with a clear description and link relevant code areas:
  - Core changes around [Error, Result](crates/lightbridge-authz-core/src/lib.rs:9).
  - CLI surface at [Commands](crates/lightbridge-authz-cli/src/main.rs:11).
  - REST/gRPC servers at [start_rest_server()](crates/lightbridge-authz-rest/src/lib.rs:4) and [start_grpc_server()](crates/lightbridge-authz-grpc/src/lib.rs:19).

## License

No LICENSE file found in the repository at this time. Add a LICENSE file (e.g., MIT, Apache-2.0) at the repo root and reference it here once chosen.
