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
| `project:create`   | `POST /api/v1/accounts/{id}/projects`           | `create-project`               |
| `project:read`     | `GET .../projects`, `GET /api/v1/projects/{id}` | `list-projects`, `get-project` |
| `project:update`   | `PATCH /api/v1/projects/{id}`                   | `update-project`               |
| `project:delete`   | `DELETE /api/v1/projects/{id}`                  | `delete-project`               |
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
