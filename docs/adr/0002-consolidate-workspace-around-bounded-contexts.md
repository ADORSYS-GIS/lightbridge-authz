# ADR-0002: Consolidate the workspace around bounded contexts

- Status: Proposed
- Date: 2026-07-10
- Decision owners: Lightbridge Authz maintainers

## Context

The repository currently has fourteen active Cargo packages for approximately 9,700 lines of
production Rust. Its package graph was built around technical layers and deployment surfaces rather
than independently versioned capabilities.

The result is a high-maintenance dependency structure:

- `lightbridge-authz-core` is a shared hub for domain, configuration, SQLx, TLS, tracing, errors,
  and crypto.
- `lightbridge-authz-api-key` owns persistence for every authz aggregate.
- `lightbridge-authz-rest` owns application behavior as well as transport concerns.
- `lightbridge-authz-mcp` depends on REST to construct and reuse application behavior.
- Migration, healthcheck, and app packages contain mostly wiring.
- The usage bounded context is independent operationally but still imports the authz core package.

The largest source files and historical churn are concentrated in the authz repository, MCP
transport, OTLP ingestion, and REST application implementation. Splitting these files into more
packages would not reduce their responsibilities or change coupling.

## Decision

Replace the current workspace with two production packages and one optional development package:

1. `lightbridge-authz`: the authz/control-plane bounded context.
2. `lightbridge-usage`: the usage and cost bounded context.
3. `lightbridge-e2e`: optional integration-test support with no production dependency.

Deployment boundaries remain separate runtime modes. They are not represented as separate library
packages unless a component later demonstrates independent versioning or reuse.

### Authz package

The authz package will provide one application layer consumed by HTTP, introspection, OAuth, and
MCP adapters.

```text
services/authz/
  Cargo.toml
  src/
    main.rs
    domain/
      account.rs
      project.rs
      credential.rs
      membership.rs
      token.rs
    application/
      accounts.rs
      projects.rs
      credentials.rs
      validation.rs
      token_exchange.rs
      ports.rs
    adapters/
      postgres/
      oidc/
      signing/
      http/
      mcp/
    runtime/
      config.rs
      telemetry.rs
      server.rs
```

The binary will expose subcommands for `api`, `introspection`, `mcp`, `migrate`, `check-config`, and
`healthcheck`. Deployments can continue running independent processes and exposing independent
services.

### Usage package

The usage package remains separate because it has a different database, scaling profile, retention
policy, and dependency set.

```text
services/usage/
  Cargo.toml
  src/
    main.rs
    domain.rs
    application.rs
    postgres.rs
    ingest.rs
    query.rs
    runtime.rs
```

The preferred public telemetry boundary is an OpenTelemetry Collector. It receives OTLP protocols,
applies limits and normalization, and forwards a narrow authenticated usage-event contract to the
Rust service. This removes responsibility for supporting three OTLP signals, JSON, protobuf, and
gzip from the application.

If that design cannot preserve required telemetry semantics, the OTLP receiver remains inside the
usage package but is separated from normalization and persistence.

### Shared code

There will be no replacement `core` or `common` package during the initial migration. Code remains
inside its bounded context until it has multiple stable consumers and a cohesive public API.

Small duplication between independent services is preferred over coupling both services to a new
shared infrastructure hub.

## Credential strategy

Supporting random opaque secrets, upstream token-exchanged credentials, and locally signed JWTs
behind one API multiplies lifecycle, testing, and incident-response requirements.

The maintenance-first target is:

- API keys are opaque, high-entropy credentials.
- API-key revocation and context resolution use introspection.
- User authentication, OAuth sessions, and RFC 8693 token exchange remain the responsibility of
  Keycloak or another dedicated identity provider.

This permits removal of local signing keys, refresh-token storage, local OIDC discovery, and the
native token endpoint.

If local token exchange is an explicit product requirement, it remains as a single isolated adapter
with separate domain types and tests. The other issuance strategies should still be removed or made
explicitly separate credential kinds.

## Dependency policy

Dependencies are adopted when they remove an entire protocol or cross-cutting responsibility, not
when they replace a small helper.

### Adopt

| Responsibility | Dependency |
| --- | --- |
| Layered file and environment configuration | `config` with YAML support |
| Route and OpenAPI registration | `utoipa-axum` |
| Typed Basic and Bearer headers | `axum-extra` |
| Request validation | `garde` and `axum-valid` |
| PATCH missing/null/value semantics | `serde_with` |
| Secret-bearing configuration and tokens | `secrecy` |
| Constant-time credential comparison | `subtle` |
| Identifiers | `uuid` with UUIDv7 |
| OpenTelemetry attribute constants | `opentelemetry-semantic-conventions` |

`jsonwebtoken` already provides JWK and JWK-set types, so the separate `jwks` model dependency can
be removed. `aliri_oauth2::Authority` may replace the remaining remote JWKS refresh and validation
implementation only after a compatibility and maintenance evaluation.

### Retain

- Axum and Tower
- SQLx and its dynamic `QueryBuilder`
- `rmcp`
- Postgres and Timescale
- `tracing` and OpenTelemetry

### Reject for this restructuring

- A new ORM: authorization CTEs, transactions, and usage aggregation remain explicit SQL.
- A second SQL query builder: SQLx already provides the required dynamic query construction.
- A new HTTP framework: it would create migration churn without changing ownership.
- An OAuth server crate without RFC 8693 support: custom token-exchange behavior would remain.

## Data model direction

The breaking schema revision should introduce:

- Native UUID columns using UUIDv7 and typed Rust ID newtypes.
- Checked or enumerated credential status and credential kind values.
- Explicit membership roles such as `owner`, `admin`, and `member`.
- Explicit account deletion instead of a membership-deletion trigger.
- `allowed_models TEXT[] NULL`, where `NULL` means all models and an empty array means no models.
- Typed project-limit columns or a validated project-limits table.
- Refresh-token foreign keys, token-family identifiers, reuse detection, and revocation timestamps
  if refresh tokens remain.
- Encrypted or externally managed signing keys if local signing remains.
- Append-only audit events separate from mutable credential usage columns.
- Authenticated usage queries with tenant authorization.

## Security requirements carried into the migration

- Unknown credential states must fail closed.
- Usage ingest must be private or authenticated and protected by request limits.
- Usage query authorization must enforce tenant membership.
- Secret material must not implement revealing `Debug` or `Serialize` behavior.
- Normalized telemetry attributes must not be logged wholesale.
- Forwarded host and protocol headers are trusted only behind an explicit proxy policy.
- Validation telemetry updates must not make the authorization decision dependent on a synchronous
  write unless that behavior is deliberately required.
- Client-facing errors use stable typed responses and do not expose internal SQL or upstream error
  bodies.

## Migration sequence

### 1. Establish contract safety

- Run every feature-gated database, store, signing, and token-exchange test in CI.
- Snapshot OpenAPI documents and MCP tool schemas.
- Add credential fixtures for every issuance mode that exists during migration.
- Correct documentation drift before changing behavior.

### 2. Introduce the authz package

- Add the new package alongside the old packages.
- Introduce pure domain types and one application service.
- Replace configuration, validation, header parsing, and error response infrastructure.
- Continue using the existing database schema initially.

### 3. Move persistence by feature

- Move account and membership behavior.
- Move projects and limits.
- Move credentials and validation.
- Move signing and token exchange only if retained.
- Keep authorization checks adjacent to each application use case.

HTTP and MCP parity tests must pass after each slice moves.

### 4. Rebuild usage ingestion

- Place an OpenTelemetry Collector in front of the service when feasible.
- Define a narrow internal usage-event contract.
- Replay captured trace, metric, and log fixtures through old and new pipelines.
- Compare normalized rows and aggregate query results.
- Add authentication and authorization before exposing the new query route.

### 5. Introduce schema v2

- Create new tables alongside existing tables.
- Backfill and validate counts and invariants.
- Dual-read or dual-write only where rollback requirements justify the added complexity.
- Publish versioned HTTP and MCP contracts.
- Remove legacy tables after the rollback window.

### 6. Remove the old workspace

Delete the current `core`, `api`, `api-key`, `bearer`, `rest`, `mcp`, migration, test-utils,
healthcheck, and wrapper-app packages after all deployment modes use the new packages.

## Consequences

### Positive

- Package boundaries match independently operated bounded contexts.
- HTTP and MCP share application behavior without transport coupling.
- Fewer manifests, feature combinations, release artifacts, and dependency edges.
- Configuration, authentication parsing, validation, and telemetry protocols rely on maintained
  implementations.
- Security-sensitive credential modes become explicit.
- Database and API breaking changes have a documented cutover path.

### Negative

- The migration temporarily carries old and new application paths.
- A one-binary authz package can produce a larger binary unless features or separate binary targets
  are retained.
- Moving OTLP reception to a Collector adds an operational component.
- UUID and schema changes require data migration and client coordination.
- Selecting one credential strategy removes configuration flexibility and requires a product
  decision.

## Alternatives considered

### Keep the current packages and split large files

Rejected because file splitting would not change the dependency graph or ownership of application
behavior.

### Create more domain-specific crates

Rejected for the first migration. Accounts, projects, credentials, and memberships change together
and share one database transaction boundary. Modules are sufficient until independent reuse is
demonstrated.

### Merge usage into authz

Rejected because usage has a separate data store, scaling profile, retention lifecycle, and public
protocol boundary.

### Replace SQLx with an ORM

Rejected because the complex behavior is in authorization and aggregation queries rather than row
mapping boilerplate.

## Verification baseline

The cartography that produced this decision used:

- `cargo check --workspace --all-targets --all-features`
- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --workspace`
- `cargo deny check`

At the time of this ADR, the commands passed, but the default workspace test command did not execute
eighteen feature-gated database and token-exchange tests. Closing that CI gap is the first migration
gate.
