# RBAC: JWT claim → permission mapping

Authentication is delegated to Keycloak; **authorization** is decided here. Every request to the
CRUD API (`authz-api`) and the MCP server (`lightbridge-mcp`) is gated on a **permission**. This
document describes how the roles Keycloak puts on a JWT become permissions, and which permission
each operation requires.

> Ownership still applies. RBAC is a *coarse capability* check (may this caller create projects at
> all?). The existing per-row `account_memberships` model still decides *which* accounts/projects a
> caller can touch. A request must pass **both**: the RBAC gate (or it is `403 Forbidden`) and the
> membership check (or it is `404 Not Found`).

## How it works

1. Keycloak issues a JWT carrying the caller's roles in a single, flat, top-level claim.
2. `lightbridge-authz-bearer` validates the JWT (JWKS) and reads that claim by name.
3. Each role string is mapped to a set of permissions via configuration.
4. The union of those permissions is attached to the request.
5. A single enforcement point checks the permission the requested operation needs; a caller who
   lacks it is rejected with `403 Forbidden` before the handler runs.

Enforcement is centralized, so the handlers/tools themselves contain no authorization code:

- **REST** — an `authorize` middleware (`crates/lightbridge-authz-rest/src/middleware`) runs after
  `bearer_auth` and after route matching. It maps the matched `(method, route pattern)` to the
  required permission and checks it. It **fails closed**: a protected route with no mapping, a
  missing matched path, or a missing token is denied.
- **MCP** — `call_tool` maps the tool name to the required permission and checks it before
  dispatching. It likewise fails closed (an unmapped tool name is rejected).

The `(method, path)` → permission and tool → permission maps are the single sources of truth and
must stay in sync with the tables below. The claim is read at request time; the role→permission map
is compiled once at startup (wildcards expanded), so the request-time check is a plain set lookup.

## Configuration (`oauth2.rbac`)

```yaml
oauth2:
  rbac:
    # Top-level JWT claim carrying the caller's roles. Configurable; defaults to "roles".
    # Value may be a JSON array of strings, or a single space-delimited string.
    roles_claim: "${RBAC_ROLES_CLAIM:-roles}"

    # Each role → the permission grants it confers. When this map is omitted/empty, the
    # built-in default mapping below is used instead.
    role_permissions:
      lightbridge-admin:
        - "*"                # every permission
      lightbridge-editor:
        - "account:read"
        - "project:*"        # every project action
        - "apikey:*"         # every api-key action
      lightbridge-viewer:
        - "account:read"
        - "project:read"
        - "apikey:read"
```

A **grant** is one of:

| Grant form            | Meaning                                    | Example          |
| --------------------- | ------------------------------------------ | ---------------- |
| `*`                   | every permission (super-admin)             | `*`              |
| `<resource>:*`        | every action on a resource                 | `project:*`      |
| `<resource>:<action>` | a single permission                        | `account:delete` |

Unknown grant strings are logged and ignored — they never widen access. A role present in the JWT
but absent from the map grants nothing.

### Configurable claim name

`roles_claim` selects which JWT claim is read. The default `roles` matches the protocol mapper the
dev realm installs (`oidc-usermodel-realm-role-mapper` → top-level `roles` array). Point it at any
other flat claim (e.g. a custom `permissions` claim emitted by your own mapper) without a rebuild.

## Default role → permission mapping

Used when `oauth2.rbac.role_permissions` is not configured
(`lightbridge_authz_core::authz::default_role_permissions`):

| Role                 | Grants                                | Effective permissions                              |
| -------------------- | ------------------------------------- | -------------------------------------------------- |
| `lightbridge-admin`  | `*`                                   | all permissions                                    |
| `lightbridge-editor` | `account:read`, `project:*`, `apikey:*` | read accounts; full project + api-key lifecycle   |
| `lightbridge-viewer` | `account:read`, `project:read`, `apikey:read` | read-only                                    |

## Permissions and the operations they gate

Each permission is the canonical `resource:action` string used in config and grants. Both the REST
endpoint and the equivalent MCP tool require the same permission.

| Permission         | REST endpoint                                   | MCP tool                       |
| ------------------ | ----------------------------------------------- | ------------------------------ |
| `account:create`   | `POST /api/v1/accounts`                         | `create-account`               |
| `account:read`     | `GET /api/v1/accounts`, `GET .../accounts/{id}` | `list-accounts`, `get-account` |
| `account:update`   | `PATCH /api/v1/accounts/{id}`                   | `update-account`               |
| `account:delete`   | `DELETE /api/v1/accounts/{id}`                  | `delete-account`               |
| `account:disable`  | `POST .../accounts/{id}/disable`, `.../enable`  | `disable-account`, `enable-account` |
| `project:create`   | `POST /api/v1/accounts/{id}/projects`           | `create-project`               |
| `project:read`     | `GET .../projects`, `GET /api/v1/projects/{id}` | `list-projects`, `get-project` |
| `project:update`   | `PATCH /api/v1/projects/{id}`                   | `update-project`               |
| `project:delete`   | `DELETE /api/v1/projects/{id}`                  | `delete-project`               |
| `project:disable`  | `POST .../projects/{id}/disable`, `.../enable`  | `disable-project`, `enable-project` |
| `apikey:create`    | `POST /api/v1/projects/{id}/api-keys`           | `create-api-key`               |
| `apikey:read`      | `GET .../api-keys`, `GET /api/v1/api-keys/{id}` | `list-api-keys`, `get-api-key` |
| `apikey:update`    | `PATCH /api/v1/api-keys/{id}`                   | `update-api-key`               |
| `apikey:delete`    | `DELETE /api/v1/api-keys/{id}`                  | `delete-api-key`               |
| `apikey:revoke`    | `POST /api/v1/api-keys/{id}/revoke`             | `revoke-api-key`               |
| `apikey:rotate`    | `POST /api/v1/api-keys/{id}/rotate`             | `rotate-api-key`               |
| `apikey:validate`  | — (OPA server, Basic-auth)                      | `validate-api-key`, `validate-authorino-api-key` |

`read` covers both the list and get operations for a resource. The OPA validation endpoints
(`/v1/opa/validate`, `/v1/authorino/validate`) are protected by Basic auth, not JWT, so they are
outside RBAC; the equivalent MCP validation tools (which run behind JWT) require `apikey:validate`.

## Keycloak setup

The dev realm (`.docker/keycloak_config/realm.json`) shows the required wiring:

- **Realm roles** `lightbridge-admin` / `lightbridge-editor` / `lightbridge-viewer`.
- The seeded user is granted `lightbridge-admin` (`realmRoles`).
- A protocol mapper on `test-client` (`oidc-usermodel-realm-role-mapper`) emits the user's realm
  roles into a top-level, multivalued `roles` claim on the **access token**:

  ```json
  {
    "name": "lightbridge-roles",
    "protocolMapper": "oidc-usermodel-realm-role-mapper",
    "config": {
      "claim.name": "roles",
      "jsonType.label": "String",
      "multivalued": "true",
      "access.token.claim": "true"
    }
  }
  ```

For your own realm, create the roles, assign them to users/groups, and add an equivalent mapper
whose `claim.name` matches `oauth2.rbac.roles_claim`.

## Account / project suspension (data-plane authorization)

RBAC above gates the **control plane** (who may call the management API). Suspension gates the
**data plane** (whether an issued API key still works at the gateway).

An admin holding `account:disable` / `project:disable` can soft-disable a tenant without deleting
anything:

- `POST /api/v1/accounts/{id}/disable` · `POST /api/v1/accounts/{id}/enable`
- `POST /api/v1/projects/{id}/disable` · `POST /api/v1/projects/{id}/enable`

Disabling sets `status = 'suspended'` on the row. The `api_key_validation` SQL view resolves the
full cascade (`account → project → key`) in one indexed read, so **every API key beneath a
suspended account or project immediately fails validation** — no token reissue, no per-key writes.
It takes effect within the gateway's auth-cache TTL. `validate_api_key_context`
(`crates/lightbridge-authz-rest/src/handlers/opa.rs`) reads this view and reports the key as
inactive with a precise reason (`account_suspended`, `project_suspended`, `key_revoked`,
`key_expired`).

### 401 vs 403 at the gateway

API keys are JWTs, so Authorino evaluates them in two phases, and the phase that fails determines
the status code:

| Situation | Failing phase | Status |
|---|---|---|
| Missing / malformed / **expired** JWT (bad signature or `exp`) | Identity (JWKS) | **401 Unauthorized** |
| Valid JWT, but key revoked or **account/project suspended** | Authorization (liveness rule) | **403 Forbidden** |

So "the JWT passes but OPA refuses" is precisely the authorization-phase deny: the introspection
metadata reports `active: false`, the `active == true` authorization rule fails, and Authorino
returns 403. See `docs/authorino-usage.md` for the AuthConfig.
