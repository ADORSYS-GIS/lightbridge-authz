# lightbridge-authz-stack

Umbrella chart for the full lightbridge-authz stack. It deploys the same image several ways:

| Component | Subchart | Subcommand | Surface |
| --- | --- | --- | --- |
| `api` | `lightbridge-authz` | `api` | the CRUD/RPC API |
| `opa` | `lightbridge-authz` | `opa` | the Authorino-facing policy endpoint (basic auth) |
| `idp` | `lightbridge-authz` | `idp` | OIDC — `/oauth2/token`, discovery, JWKS |
| `budget` | `lightbridge-authz` | `budget` | `/budget/rpc/{op_id}` |
| `mcp` | `lightbridge-mcp` | `serve` | the MCP endpoint |
| `usage` | `lightbridge-authz-usage` | — | OTLP ingest + the mTLS query listener |

`api`, `opa`, `idp` and `budget` are four **aliases of one subchart**. That matters: a value set
on one alias is invisible to the other three.

## Configure once

The first five components mount a `config.yaml` that is meant to agree on oauth2 signing and
`claim_mappers`, rbac `role_permissions`, `database`, `federation` and `otel`. Write it **once**:

```yaml
global:
  lightbridge:
    # A YAML OBJECT — never a string. This is the single source of truth for every component.
    sharedConfig:
      logging:
        level: "${RUST_LOG}"
      database:
        url: "${DATABASE_URL}"
        pool_size: 10
      oauth2:
        type: self
        rbac:
          roles_claim: lightbridge_api_roles
          role_permissions:
            lightbridge-editor: ["project:*", "apikey:*"]

api:
  # Merged OVER sharedConfig, for this component only.
  # Maps merge recursively; scalars and LISTS are replaced wholesale.
  configOverrides:
    otel:
      service_name: lightbridge-authz-api

opa:
  configOverrides:
    otel:
      service_name: lightbridge-authz-opa
  # Deleted AFTER the merge. A merge can add a key; it can never take one away, and opa has no
  # Redis of its own.
  configOmit:
    - redis
```

Two things are worth knowing before you use it:

- **`global.lightbridge.sharedConfig` replaces the chart's own default, it does not merge into
  it.** The subcharts ship local-dev-shaped defaults (`keycloak:9100`, a fixed
  `oauth2.relying_party.state_encryption_key`). Deep-merging those under a production config
  would leak every key you did not restate; supplying `sharedConfig` discards them entirely.
  Leave it empty (the chart default) and each subchart falls back to its own dev config, so
  `helm install` still gives you a working local stack.
- **Env placeholders keep working.** `$VAR`, `${VAR}`, `${VAR-default}` and `${VAR:-default}` are
  substituted by the binary at startup, textually, before the YAML is parsed. The renderer quotes
  every scalar carrying one, so a secret containing a YAML metacharacter cannot break the parse.

Full contract, diagrams and the reasoning: [`docs/single-source-config.md`](../../docs/single-source-config.md)
and the header of [`charts/lightbridge-authz/templates/_config.tpl`](../lightbridge-authz/templates/_config.tpl).

`lightbridge-authz-usage` is not wired into `sharedConfig` — its config is a different schema, not
a variation on the same one (see the doc's *Scope* section). It keeps its own
`configMaps.config.data`.

## Tests

```sh
helm plugin install https://github.com/helm-unittest/helm-unittest --version 0.6.0
helm dependency build charts/lightbridge-authz && helm unittest charts/lightbridge-authz
helm dependency build charts/lightbridge-mcp   && helm unittest charts/lightbridge-mcp
```

`templates/_config.tpl` is duplicated **byte-for-byte** into both leaf charts, because each is
published and installable on its own and Helm has no cross-chart library short of a library
dependency. Helm's template namespace is global, so two *different* definitions of the same name
inside this umbrella chart would silently resolve to whichever parsed last — CI diffs the two
files to keep that from happening.
