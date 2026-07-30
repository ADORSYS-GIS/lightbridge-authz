# RBAC: JWT claim → permission mapping

Authentication is delegated to Keycloak; **authorization** is decided here. Every request to the
CRUD API (`authz-api`) and the MCP server (`lightbridge-mcp`) is gated on a **permission**. This
document describes how the roles Keycloak puts on a JWT become permissions, and which permission
each operation requires.

> Ownership still applies. RBAC is a *coarse capability* check (may this caller create projects at
> all?). Account ownership (`accounts.id = sub`) and the per-row `project_members` roster still
> decide *which* accounts/projects a caller can touch. A request must pass **both**: the RBAC gate
> (or it is `403 Forbidden`) and the membership check (or it is `404 Not Found`).

## How it works

1. Keycloak issues a JWT carrying the caller's roles in a single, flat, top-level claim.
2. `lightbridge-authz-bearer` validates the JWT (JWKS) and reads that claim by name.
3. Each role string is mapped to a set of permissions via configuration.
4. The union of those permissions is attached to the request.
5. A single enforcement point checks the permission the requested operation needs; a caller who
   lacks it is rejected with `403 Forbidden` before the handler runs.

Enforcement is centralized, so the handlers/tools themselves contain no authorization code:

- **CRUD API (RPC)** — an `rpc_authorize` middleware
  (`crates/lightbridge-authz-rest/src/rpc_authorize.rs`) wraps the cratestack RPC router as its
  **outermost** layer. For every `POST /rpc/{op_id}` it extracts the bearer token, validates it via
  the same `BearerTokenServiceTrait` used everywhere (reusing the `TokenInfo.permissions` set it
  already computes), maps the `op_id` to the required permission, and rejects with `403 Forbidden`
  **before the request reaches cratestack's dispatch** if the token lacks it. It **fails closed**: an
  unmapped op-id and any missing/invalid token are denied. `POST /rpc/batch` is a special case — see
  "Batch RPC: per-frame RBAC" below.
- **CratestackAuthProvider** (`crates/lightbridge-authz-rest/src/auth_provider.rs`) enforces the
  *same* `op_id` → permission map a second time, from inside cratestack's own dispatch. Redundant for
  a unary call (already checked by `rpc_authorize` above), but this is what actually authorizes a
  `POST /rpc/batch` request: cratestack calls this provider once per frame, each time with that
  frame's own canonical `/rpc/<op_id>` path, so every frame in a batch is authorized independently.
- **MCP** — `call_tool` maps the tool name to the required permission and checks it before
  dispatching. It likewise fails closed (an unmapped tool name is rejected).

### Two gates on the CRUD surface, in order

The CRUD surface (`authz-api`) migrated to cratestack-generated RPC routing (see
`docs/adr/0003-cratestack-crud-migration.md`). Authorization there is now **two independent layers,
both mandatory, evaluated in this order**:

1. **RBAC gate (coarse capability) — first.** The `rpc_authorize` middleware above. Answers "may
   this caller perform this *kind* of operation at all?" A caller lacking the permission gets
   `403 Forbidden` and the request never reaches cratestack. This is the layer this document's
   `op_id` → permission table defines.
2. **Membership policy (per-tenant ownership) — second.** cratestack's generated `@@allow` policies
   on the schema (`crates/lightbridge-authz-api/schema/authz.cstack`), which check
   `account.id == auth().id || members.some.accountId == auth().id`. Answers "does this specific
   account/project/key belong to this caller, or to a project they sit on?" A non-member gets a
   policy-driven empty result / `404`.

So a `lightbridge-viewer` who is a legitimate account member is still blocked from
create/update/delete by gate 1 (they hold only `*:read`), and a `lightbridge-editor` acting on an
account they do **not** belong to passes gate 1 but is stopped by gate 2. Both must pass.

RBAC enforcement on non-CRUD paths — OPA/Authorino validation and `/idp/v1/resolve-context` (Basic
auth, outside RBAC) — is unchanged, and the MCP enforcement above is unaffected.

### Batch RPC: per-frame RBAC

`POST /rpc/batch` bundles multiple ops in one JSON array of frames (`{id, op, input}`), each
carrying its own `op` (op-id). `rpc_authorize` is a URL-derived, whole-HTTP-request gate — it has no
visibility into the frames inside the body, so it cannot check a single permission for the batch call
the way it does for `POST /rpc/{op_id}`. Instead:

1. **`rpc_authorize`** requires only that the caller present *some* valid, active bearer token, then
   forwards the request — a wholly unauthenticated batch call still gets a clean top-level `401`
   rather than a `200` envelope full of per-frame `unauthenticated` errors.
2. **`CratestackAuthProvider::authenticate`** does the actual permission check, once per frame:
   cratestack's batch dispatch calls it once for every frame, each time with that frame's own
   canonical `/rpc/<op_id>` path, and it looks that op-id up in the *same* map `rpc_authorize` uses
   for unary calls. A frame whose op the caller lacks permission for fails independently with
   `{"error": {"code": "permission_denied", ...}}` in its own slot — the rest of the batch, and the
   overall `200`, are unaffected.

One token authorizes every frame in a batch (there's one `Authorization` header per HTTP request, not
per frame) — so a batch mixing a permitted read and a forbidden write for the *same* caller returns
`200` with the read's `output` in one frame and a `permission_denied` `error` in the other. Membership
(`@@allow`) is still the second gate per frame, exactly as for unary calls.

The `op_id` → permission and tool → permission maps are the single sources of truth and must stay in
sync with the tables below. The claim is read at request time; the role→permission map is compiled
once at startup (wildcards expanded), so the request-time check is a plain set lookup.

## Configuration (`oauth2.rbac`)

```yaml
oauth2:
  rbac:
    # Top-level JWT claim carrying the caller's roles. Configurable; defaults to
    # "lightbridge_api_roles" (matches the dev realm's protocol mapper).
    # Value may be a JSON array of strings, or a single space-delimited string.
    roles_claim: "${RBAC_ROLES_CLAIM:-lightbridge_api_roles}"

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

> **Wildcards expand dynamically over the whole permission set.** `<resource>:*` and `*` include
> **every** action on that resource — that means `project:*` grants `project:disable` (suspend a
> project → invalidate all its keys) and `*` grants `account:disable`, not just the CRUD verbs. So
> `lightbridge-editor` (`project:*`) can suspend projects, and any operator config using
> `<resource>:*` inherits new actions as they are added. If you want CRUD without the disable
> capability, list the individual grants instead of a wildcard.

### Configurable claim name

`roles_claim` selects which JWT claim is read. The default `lightbridge_api_roles` matches the
protocol mapper the dev realm installs (`oidc-usermodel-realm-role-mapper` → top-level
`lightbridge_api_roles` array — named to match the frontend's `getJwtRoles` expectations). Point it
at any other flat claim (e.g. a custom `permissions` claim emitted by your own mapper) without a
rebuild.

## Default role → permission mapping

Used when `oauth2.rbac.role_permissions` is not configured
(`lightbridge_authz_core::authz::default_role_permissions`):

| Role                 | Grants                                | Effective permissions                              |
| -------------------- | ------------------------------------- | -------------------------------------------------- |
| `lightbridge-admin`  | `*`                                   | all permissions                                    |
| `lightbridge-editor` | `account:read`, `project:*`, `apikey:*` | read accounts; full project + api-key lifecycle   |
| `lightbridge-viewer` | `account:read`, `project:read`, `apikey:read` | read-only                                    |

## Permissions and the operations they gate

Each permission is the canonical `resource:action` string used in config and grants. On the CRUD
API the operation is an RPC `op_id` (`POST /rpc/{op_id}`); the equivalent MCP tool requires the same
permission. cratestack's `op_id` scheme is `model.<Model>.<verb>` (verb ∈ `list|get|create|update|
delete`) for generated model CRUD and `procedure.<name>` for the hand-written procedures.

This table is the source of truth for `rpc_authorize::required_permission`. **Any RPC `op_id` not
listed here is denied unconditionally (fail closed).**

| Permission        | RPC `op_id`                                          | MCP tool                            |
| ----------------- | ---------------------------------------------------- | ----------------------------------- |
| `account:create`  | `model.Account.create`                               | `create-account`                    |
| `account:read`    | `model.Account.list`, `model.Account.get`, `model.AccountSummary.list`, `model.AccountSummary.get` | `list-accounts`, `get-account` |
| `account:update`  | `model.Account.update`                               | `update-account`                    |
| `account:delete`  | `procedure.deleteAccountPermanently`                 | `delete-account`                    |
| `account:disable` | `procedure.disableAccount`, `procedure.enableAccount`| `disable-account`, `enable-account` |
| `project:create`  | `model.Project.create`                               | `create-project`                    |
| `project:read`    | `model.Project.list`, `model.Project.get`            | `list-projects`, `get-project`      |
| `project:update`  | `model.Project.update`, `procedure.setDefaultProject` | `update-project`, `set-default-project` |
| `project:delete`  | `model.Project.delete`                               | `delete-project`                    |
| `project:disable` | `procedure.disableProject`, `procedure.enableProject`| `disable-project`, `enable-project` |
| `project:member`  | `procedure.addProjectMember`, `procedure.removeProjectMember`, `procedure.setProjectMemberRole`, `procedure.setProjectMemberQuotaTier` | `add-project-member`, `remove-project-member`, `set-project-member-role`, `set-project-member-quota-tier` |
| `apikey:create`   | `procedure.createApiKey`                             | `create-api-key`                    |
| `apikey:read`     | `model.ApiKey.list`, `model.ApiKey.get`              | `list-api-keys`, `get-api-key`      |
| `apikey:update`   | `model.ApiKey.update`                                | `update-api-key`                    |
| `apikey:delete`   | `model.ApiKey.delete`                                | `delete-api-key`                    |
| `apikey:revoke`   | `procedure.revokeApiKey`                             | `revoke-api-key`                    |
| `apikey:rotate`   | `procedure.rotateApiKey`                             | `rotate-api-key`                    |
| `apikey:validate` | — (OPA server, Basic-auth)                           | `validate-api-key`, `validate-authorino-api-key` |

`read` covers both the list and get operations for a resource.

**Deliberately unmapped → denied (defense in depth):**

- `model.ApiKey.create` — the schema removed its `@@allow("create")`, so the generic create verb is
  already fail-closed at the policy layer; the RBAC gate denies it too. API-key creation is
  server-side only, via `procedure.createApiKey` (the server generates + hashes the secret and
  validates the billing plan; a caller can never supply `keyHash`/`keyPrefix`/`billingPlan`).
- `model.Account.delete` — the generic delete verb carries no `@@allow` at all and is denied here
  too. Account deletion is `procedure.deleteAccountPermanently` only, whose SQL check is simply "the
  caller is this account".
- `model.ProjectMember.*` — that model is policy-locked to read-only with no generated mutation
  verbs; roster changes go through the `addProjectMember` / `removeProjectMember` /
  `setProjectMemberRole` / `setProjectMemberQuotaTier` procedures, which enforce the lead check in
  SQL (see "Project roles" below for why it cannot be an `@@allow` predicate).

`/rpc/batch` is not in this fail-closed list — it's handled specially with real per-frame permission
enforcement; see "Batch RPC: per-frame RBAC" above.

> **Field-level immutability on `ApiKey` update.** The coarse `apikey:update` gate allows
> `model.ApiKey.update`, but the schema additionally marks the key's server-managed columns
> (`status`, `keyHash`, `billingPlan`, `keyPrefix`, `projectId`, `revokedAt`, timestamps) as
> `@readonly` / `@server_only`, so they are dropped from the generated `UpdateApiKeyInput`. The
> update surface is therefore `{ name, expiresAt }` only — a caller with `apikey:update` cannot flip
> a key's `status`, overwrite its `keyHash`, or change its `billingPlan`; those transitions are
> reachable exclusively through `apikey:rotate` / `apikey:revoke` / `apikey:create`.

The OPA validation endpoints (introspection / `/idp/v1/resolve-context`) are protected by Basic
auth, not JWT, so they are outside RBAC; the equivalent MCP validation tools (which run behind JWT)
require `apikey:validate`.

## Keycloak setup

The dev realm (`.docker/keycloak_config/realm.json`) shows the required wiring:

- **Realm roles** `lightbridge-admin` / `lightbridge-editor` / `lightbridge-viewer`.
- The seeded user is granted `lightbridge-admin` (`realmRoles`).
- A protocol mapper on `test-client` (`oidc-usermodel-realm-role-mapper`) emits the user's realm
  roles into a top-level, multivalued `lightbridge_api_roles` claim on the **access token**:

  ```json
  {
    "name": "lightbridge-roles",
    "protocolMapper": "oidc-usermodel-realm-role-mapper",
    "config": {
      "claim.name": "lightbridge_api_roles",
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
anything, via the RPC procedures (`account:disable` gates both disable and enable, `project:disable`
likewise):

- `procedure.disableAccount` · `procedure.enableAccount`
- `procedure.disableProject` · `procedure.enableProject`

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
## Project membership (who a tenant's resources belong to)

RBAC decides *what actions* a caller may attempt; **membership** decides *whose* projects and API
keys they act on. Since ADR-0006 there is **no account-level membership at all** — a person's
identity in this system *is* their `accountId`, and `accounts.id` holds their JWT `sub` verbatim.
So "does this account belong to me" is a primary-key comparison (`accounts.id = sub`), not a join.

A caller can see or mutate a project (and every API key beneath it) if either:

- they own the account the project belongs to (`projects.account_id = sub`), or
- they hold a `project_members` row for it (`project_members.account_id = sub`).

Enforced in SQL on every project/key query — RBAC is checked first (else `403`), then membership
(else `404`).

Membership is **project-level**. An account's *default* project has no roster at all: nothing ever
inserts a `project_members` row for it, so the "no membership concept on the default project"
requirement falls out of the data model rather than needing a special case in policy.

A caller holding `project:member` manages a roster directly (no invite/accept handshake):

- `procedure.addProjectMember` with `{ projectId, accountId, role? }` — add a member by their
  account id (which is their subject). `role` defaults to `"member"`. Idempotent on the membership
  itself; use `setProjectMemberRole` to change an existing member's role.
- `procedure.removeProjectMember` with `{ projectId, accountId }` — remove a member. Unlike the
  account-membership model this replaces, there is **no** last-member invariant to enforce: the
  project's owning account is a standing authority over the roster, so a project can never be left
  with nobody able to administer it.
- `procedure.setProjectMemberRole` with `{ projectId, accountId, role }` — `"lead"` or `"member"`.
- `procedure.setProjectMemberQuotaTier` with `{ projectId, accountId, quotaTier }` — the member's
  per-project spending ceiling, validated against the configured tier catalogue at write time.

All four are **lead-gated**: the acting caller must own the project's account or hold `role = "lead"`
on that project. A caller who is neither gets a uniform `404`, the same non-leaking pattern used
everywhere on this surface.

### Project roles

Every `project_members` row carries a `role` — `"lead"` or `"member"` — plus an optional
`quota_tier`. Role is a **second, finer authorization layer inside a single project**, distinct from
the coarse RBAC gate above (global, JWT-role-driven) and from membership itself (binary).

| Role     | Can do beyond plain membership |
| -------- | ------------------------------- |
| `member` | Nothing extra — read/update the project and its API keys, same as any member. |
| `lead`   | + roster add/remove, + `setProjectMemberRole`, + `setProjectMemberQuotaTier`, + `createApiKey`. |

API-key creation is lead-gated deliberately: a key is live spending power with no per-request human
in the loop, so letting any member mint unlimited keys would remove the lead's ability to bound the
project's blast radius. It is cheaper to loosen this later than to tighten it after people depend on
the loose behaviour.

**Why this isn't expressed as an `@@allow` schema policy, unlike membership itself:** cratestack's
relation-quantifier policy predicates (`project.members.some.accountId == auth().id`) resolve each
dotted path to exactly one target scalar field per relation hop — there is no support for a compound
condition jointly checked on the *same* related row. Writing
`members.some.accountId == auth().id && members.some.role == "lead"` would compile to two
independent `EXISTS` checks ("some member matches me" AND, separately, "some member — any member —
is a lead"), not "the member row matching me is also a lead". So role gating lives entirely in
hand-written SQL inside the procedures above (confirmed by reading
`cratestack-macros/src/policy/model/relation_path.rs`) rather than in the schema's `@@allow`
policies. ADR-0005 first hit this limitation with account roles; ADR-0006 re-confirmed it for
project roles.

### The default project can't be hard-deleted

The first project ever created under an account is marked `isDefault = true` — server-computed once
at insert time by a `BEFORE INSERT` trigger (`migrations/20260725000001_default_account_project.sql`),
since `model.Project.create` is the generic cratestack verb and has no hand-written hook for the
"is this the account's first project" computation. A partial unique index
(`projects_account_id_default_uidx`) backstops the race where two concurrent first-project creates
for the same brand-new account would otherwise both see zero existing rows. `isDefault Boolean
@readonly` keeps it out of the generated create/update inputs, so a raw RPC caller can never supply
or overwrite it.

This is a hard safety rail, not a role check: `model.Project.delete`'s `@@allow` policy denies a
default project outright. Suspending (`disableProject`) still works — only the permanent-delete path
is blocked, so a tenant can never accidentally wipe out their only project and every API key
underneath it with no way back.

There is **no** equivalent default-*account* concept. One account is one person, so there is nothing
to default away from; the `accounts.is_default` column and the `setDefaultAccount` procedure that
briefly existed were removed by ADR-0006 (`migrations/20260727000006_accounts_drop_is_default.sql`).

### Escape hatch: reassigning the default (`setDefaultProject`)

Because the default project can never be hard-deleted, an account's bootstrap project would be
*permanently* undeletable if `isDefault` could never move — so it can, but only through
`setDefaultProject(projectId)`, never through the generic `model.Project.update` (the field stays
`@readonly`). It promotes a different project to default while atomically demoting whichever project
is currently default, in a single transaction (`StoreRepo::set_default_project`) — never a bare
"unset then set" a caller could race against. The partial unique index still backstops the
invariant: if two reassignments for the same account raced past the unset step, the second
`SET is_default = true` would hit a unique-constraint conflict (surfaced as `409 Conflict`) rather
than silently leaving two defaults.

Once a different project is promoted, the old default is a plain row and `model.Project.delete`
works on it normally. Coarsely the procedure requires `project:update` — reassigning `isDefault` is
conceptually an update, just one that cannot go through the generic verb. A caller who owns neither
the account nor a roster seat gets a uniform `404`.
