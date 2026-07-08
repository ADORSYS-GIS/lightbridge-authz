# Architecture

`lightbridge-authz` is a Rust (edition 2024) Cargo **workspace**: thin `app/*` binaries over layered
`crates/*`, deployed as several services that share one Postgres/Timescale database. A request takes one
of four roles.

## Services & callers

The **OPA / validation server** (`authz-opa`) is the internal, Basic-auth surface with **three**
responsibilities: API-key validation for Authorino, dynamic-metadata enrichment, and — since the
resolve-by-project work — the IdP **`/idp/v1/resolve-context`** endpoint the Keycloak SPI calls during a
`project_id` token exchange.

```mermaid
flowchart LR
    subgraph callers["Callers"]
        UI["Self-service UI /<br/>CRUD clients"]
        KC["Keycloak +<br/>Lightbridge SPI"]
        AZ["Authorino<br/>(API gateway)"]
        MC["MCP clients"]
        OT["OTEL exporters"]
    end

    subgraph authz["lightbridge-authz workspace"]
        API["authz-api :13000<br/>OAuth2/JWT CRUD · /api/v1/*"]
        OPA["authz-opa :13001 · Basic auth<br/>/v1/opa/validate<br/>/v1/authorino/validate<br/>/idp/v1/resolve-context"]
        MCP["lightbridge-mcp :13003<br/>MCP tools over /mcp · JWKS bearer"]
        USG["lightbridge-authz-usage :13002<br/>OTLP ingest + /v1/usage/query"]
    end

    DB[("Postgres / Timescale<br/>accounts · projects · api_keys<br/>account_memberships · usage")]

    UI -->|"Bearer JWT"| API
    MC -->|"Bearer JWT"| MCP
    AZ -->|"validate API key"| OPA
    KC -->|"resolve-context<br/>(token exchange)"| OPA
    OT -->|"OTLP traces/metrics"| USG

    API --- DB
    OPA --- DB
    MCP --- DB
    USG --- DB
```

Ports are the host-exposed Compose ports; inside containers services bind `:3000`/`:3001`/`:3002`. All
local TLS is self-signed — use `curl -k`.

## Crate layering

`app/*` are thin entrypoints; the logic lives in `crates/*`. Only `lightbridge-authz-api-key` talks to the
`accounts`/`projects`/`api_keys` tables, and every error funnels through the centralized `Result`/`Error`
in `-core`.

```mermaid
flowchart TB
    subgraph apps["app/* — thin binaries"]
        A1["lightbridge-authz<br/>serve · api · opa · migrate"]
        A2["lightbridge-mcp"]
        A3["lightbridge-authz-usage"]
    end

    REST["lightbridge-authz-rest<br/>axum glue · TLS · middleware<br/>handlers/authorino · handlers/idp (resolve-context)"]
    APIC["lightbridge-authz-api<br/>routers · controllers · OpenAPI"]
    MCPC["lightbridge-authz-mcp<br/>MCP tool handlers"]
    BEARER["lightbridge-authz-bearer<br/>JWT validation via JWKS"]
    KEY["lightbridge-authz-api-key<br/>SQLx entities + repo.rs<br/>(only crate touching the tables)"]
    CORE["lightbridge-authz-core<br/>config · Result/Error · crypto · DB pool"]

    A1 --> REST
    A2 --> MCPC
    A3 --> CORE
    REST --> APIC
    REST --> BEARER
    APIC --> KEY
    MCPC --> KEY
    KEY --> CORE
    APIC --> CORE
    BEARER --> CORE
```

## Flow: IdP token exchange → `resolve-context`

The Keycloak adapter ([lightbridge-keycloak-spi](https://github.com/adorsys-gis/lightbridge-keycloak-spi))
resolves `(subject, project_id)` to tenant context during a token exchange and seals it into the JWT. The
endpoint is Basic-auth protected (the pair is enumerable) and membership-enforced; every miss is a uniform
`404`. See [ADR-0001](adr/0001-resolve-context-by-subject-and-project.md).

```mermaid
sequenceDiagram
    participant KC as Keycloak + SPI
    participant OPA as authz-opa :13001
    participant REPO as api-key repo.rs
    participant DB as Postgres

    KC->>OPA: POST /idp/v1/resolve-context<br/>Basic auth · {subject, project_id}
    OPA->>REPO: resolve_context(subject, project_id)
    REPO->>DB: SELECT project + account_id<br/>JOIN account_memberships (subject)
    alt subject is a member of the project's account
        DB-->>REPO: row {account_id, project_id}
        REPO-->>OPA: Ok
        OPA-->>KC: 200 {account_id, project_id}
    else non-member / unknown project
        DB-->>REPO: no row
        REPO-->>OPA: Error::NotFound
        OPA-->>KC: 404 (uniform — no existence leak)
    end
```

## Flow: Authorino API-key validation

Authorino (not end users) calls the validation surface with the presented key. Only `key_hash`
(SHA-256) + `key_prefix` are stored — the plaintext `secret` is returned **only** on create/rotate — so
validation hashes the presented key and looks it up.

```mermaid
sequenceDiagram
    participant GW as API gateway
    participant AZ as Authorino
    participant OPA as authz-opa :13001
    participant DB as Postgres

    GW->>AZ: request carrying an API key
    AZ->>OPA: POST /v1/authorino/validate<br/>Basic auth · {api_key, ip, metadata}
    OPA->>OPA: SHA-256(api_key) → key_hash + key_prefix
    OPA->>DB: lookup by key_hash, check revoked / expired
    alt valid
        DB-->>OPA: api_key + project + account
        OPA-->>AZ: 200 enriched {api_key, project, account}<br/>+ Authorino dynamic metadata
        AZ-->>GW: allow (with metadata)
    else revoked / expired / unknown
        OPA-->>AZ: deny
        AZ-->>GW: 401 / 403
    end
```

> `allowed_models` NULL or `[]` means "all models allowed". The two migration sets are independent:
> `migrations/` (authz) and `migrations-usage/` (usage/Timescale).
