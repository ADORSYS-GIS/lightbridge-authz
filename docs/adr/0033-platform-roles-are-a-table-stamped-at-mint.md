# ADR-0033: Platform roles are a table, stamped at mint

- Status: Accepted
- Date: 2026-09-02
- Decision owners: @stephane-segning
- Story: [lightbridge-authz#650](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/650)
- Builds on: [ADR-0014](0014-budget-tier-claim-via-token-mint-not-keycloak-writeback.md) (claims are
  resolved from our own tables at mint time, never written back to Keycloak),
  [ADR-0024](0024-we-own-our-users-accounts-are-federated-identities.md) (a person is `users.id`),
  [ADR-0026](0026-one-identity-may-own-many-accounts.md) (one person, many accounts),
  [ADR-0006](0006-project-membership-supersedes-account-roles.md) (project membership, not account
  roles), [ADR-0038 (webank-context)](https://github.com/ADORSYS-GIS/webank-context/blob/master/decisions/0038-cratestack-is-the-only-database-api.md)
  (cratestack is the only sanctioned database API — this adds a recorded exception)
- Related: [#262](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/262) ("full RBAC"), whose
  real content this ADR finally names: admin was never a role anyone assigned.

## Context

### The prod finding: everyone was an admin

`ai-helm-values/environments/prod/values/lightbridge-app.yaml:266-273` (repeated verbatim at 863
and 1172) configures the roles claim mapper as:

```yaml
map:
  owner:  ["lightbridge-admin"]
  lead:   ["lightbridge-editor"]
  member: ["lightbridge-viewer"]
```

`owner` is `ClaimSource::ProjectRole`'s value for "the acting subject owns the account this project
belongs to" — the same owner-is-implicitly-authorized rule `authorize_project_lead` applies. Under
ADR-0026, **every signed-in person owns an account**: their home account is created for them on
first login, and it is the account they act in by default. So the mapper's first line fires for
essentially every human on the platform, and **every authenticated user was minted
`lightbridge-admin`** — which the default role map expands to `*`, i.e. every one of the 35
permissions in the enum.

This was not a bug in a line of code. It was a configuration whose meaning quietly changed
underneath it: `owner` meant something much narrower when the mapper was written (pre-ADR-0026,
"one account = one person, and most people have none"), and ADR-0026 turned it into "everyone",
with no line of YAML changing. Nothing in the system could have flagged that, because nothing in
the system knew that "who should be an admin" was a question anybody had answered.

That is the actual content of #262 "full RBAC". The permission enum, the role → permission map, the
two-gate composition in `docs/rbac.md` — all of it worked exactly as designed. The missing piece was
never enforcement. It was that **admin was a default rather than a decision**, so there was nothing
for the enforcement to enforce.

### What "fixing it" cannot mean

Two obvious-looking fixes are both wrong:

- **Drop `owner` from the mapper.** Then account owners get no role at all and cannot use the
  product they own. The roster mapping (`lead`/`member`) only covers people on somebody else's
  project.
- **Write roles back to Keycloak.** ADR-0014 settled this: a claim this service depends on must be
  resolved from this service's own tables at mint time. A Keycloak attribute write-back is a second
  source of truth, an extra failure mode, and unavailable to any deployment not brokering Keycloak.

## Decision

### D1 — `platform_role_grants` is a table, and a grant is a decision with a name on it

Migration `20260902000006` adds:

```
platform_role_grants(
  id TEXT PRIMARY KEY,                 -- CUID2
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  granted_by TEXT,                     -- NULL = CLI bootstrap
  granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ,              -- NULL = active
  reason TEXT
)
UNIQUE (user_id, role) WHERE revoked_at IS NULL
```

Three properties are load-bearing:

- **Keyed on the PERSON (`users.id`), not an account.** ADR-0026 lets one person own several
  accounts; a platform role follows the human across all of them. Every caller translates through
  `StoreRepo::resolve_user_id_for_account` rather than assuming `account_id == user_id` — true for
  every grandfathered row, not true in general.
- **Revocation is a soft delete.** "X held admin between these two timestamps, granted by Y, because
  Z" is the whole point. A second revoke of the same grant is a no-op, never a re-stamp: the
  original `revoked_at` is the audit fact.
- **The unique index is PARTIAL, over active rows.** Grant → revoke → grant is a normal history, not
  a conflict, and the same index is what makes `grantPlatformRole` idempotent (`ON CONFLICT … WHERE
  revoked_at IS NULL DO NOTHING`, then read the existing row back).

`role` is free TEXT with no `CHECK` and no enum: the role catalogue is operator configuration
(`oauth2.rbac.role_permissions`), so a database constraint would hard-code one deployment's config
into the schema. Validation lives where the catalogue is actually known — both writers
(`grantPlatformRole` and `rbac grant`) refuse a role absent from it, because a row for
`lightbridge-admn` confers nothing while looking exactly like a successful grant.

### D2 — `ClaimSource::PlatformRoles`, resolved at mint, fail-closed

A second claim source reads the acting subject's active grants while minting, exactly as
`ClaimSource::ProjectRole` reads `project_members`. It runs on all three human-plane mint paths —
token exchange, refresh, and the `authorization_code` grant — because all three go through the same
`resolve_mapped_claims`.

Fail-closed, matching `resolve_quota_tier` rather than `resolve_budget_tier`: **a lookup failure
refuses the mint.** Omitting the claim instead would produce a token whose roles are empty, which
`permissions_for_roles` reads as "no permissions" — indistinguishable on the wire from a
legitimately unprivileged user, turning a database blip into a silent authorization failure that
looks like a policy decision.

An **empty grant set is not a failure**. A person granted nothing resolves to nothing, falls through
to the mapper's `default`, and mints normally.

### D3 — Several mappers on one claim MERGE (union, deduped), never overwrite

This is the mechanism the whole cutover rests on. The post-cutover prod config declares two mappers
against `lightbridge_api_roles`:

```yaml
claim_mappers:
  - claim: lightbridge_api_roles
    source: project_role
    map:
      owner:  ["lightbridge-viewer"]
      lead:   ["lightbridge-editor"]
      member: ["lightbridge-viewer"]
    default: []
  - claim: lightbridge_api_roles
    source: platform_roles
    default: []
```

and the emitted claim is the deduplicated union of both, in mapper-declaration order. Last-one-wins
would make the roles claim depend on YAML ordering — a values-file edit must not be able to cause
that class of silent authorization surprise.

The two sources apply `map` differently, deliberately, because they mean different things:
`project_role` resolves to a ROSTER POSITION (`owner`/`lead`/`member`), which is not a role name and
must be translated, so an unmapped value falls through to `default`. `platform_roles` resolves to
role names already, so an unmapped value **contributes itself** — an operator who grants
`lightbridge-admin` gets `lightbridge-admin` in the claim without also maintaining an identity
mapping they would have to extend for every new role.

### D4 — Account owners default to `lightbridge-viewer`

The owner's binding ruling (2026-09-02), choosing `viewer` over `editor` on the grounds that editor
(`project:*`, `apikey:*`, `account:create`) is too broad to hand every signed-in human by default.
An owner who needs more asks for it, and somebody grants it, and there is a row saying who and why.

This ADR ships the *capability*; the prod values change is ai-helm-values B1, and it is sequenced
**after** the image carrying migration `20260902000006` is live. A `platform_roles` mapper
configured before its table exists refuses every mint — that is the fail-closed contract in D2
working exactly as designed, and it would take the whole human plane down.

### D5 — Propagation is bounded by the access-token TTL; revocation is made immediate

A grant reaches a person's token at the next mint, not before. That is ADR-0014's property, not a
new compromise, and it is documented in `docs/rbac.md` rather than papered over. For a GRANT that is
fine: gaining a capability a few minutes late is not a security event.

For a REVOCATION it is not fine on its own — a still-valid access token keeps carrying the role, and
worse, a refresh would keep re-minting it from the same live session for as long as the refresh
chain lived. So `revokePlatformRole` (and `rbac revoke`) also run the existing
`revokeSubjectSessions` path for **every account the person owns**, forcing a fresh login instead of
a silent re-mint. The worst case collapses to the remaining lifetime of one already-issued access
token.

### D6 — `rbac:manage` is its own permission; `getMyAccess` needs none

`Permission::RbacManage` gates `listPlatformRoleGrants`, `grantPlatformRole` and
`revokePlatformRole`. Its own permission, not a reuse of `user:read` or any `account:*` grant,
because it is the one capability that can hand out every other capability: whoever can write this
table can make themselves `lightbridge-admin`. It is in `lightbridge-admin`'s default `*` and in no
other default role.

`getMyAccess() → { userId, roles[], permissions[] }` is the deliberate opposite: **served to any
authenticated caller, gated on nothing**. It is the sole entry in
`rpc_permission_map::AUTHENTICATED_ONLY_OP_IDS`, the enumerated exception to the fail-closed
"unmapped op-id is denied" rule, and it is a list rather than a heuristic precisely so that adding
another is a conscious edit somebody reviews.

Gating it would defeat its purpose — the console calls it to find out what it may render, so a
permission requirement makes "you may not ask what you may do" a reachable state — and the natural
candidates all make it worse: `rbac:manage` would restrict it to the admins who need it least, and
any permission every role happens to hold today is an accident of the default map that an operator's
own `role_permissions` can revoke. It discloses nothing either way: every value it returns is
already derivable from the token the caller is holding.

Both halves of its answer are **read back out of the auth context**, not re-derived: `roles` from
the context's `roles` extension, `permissions` from the `auth().perm*` booleans that
`build_context` populated from the caller's real `TokenInfo::has_permission` verdicts. A console
that re-implemented the role → permission map would drift from the server's, and the drift surfaces
as a screen offering an action the backend then refuses — or, worse, hiding one it would have
allowed.

### D7 — The CLI is the bootstrap, and it is the only way the first admin can exist

`lightbridge-authz rbac {grant,revoke,list}`, one-shot against the configured database, no server —
the `idp jwk rotate` pattern, deployable as a k8s Job or `kubectl exec`. This is not a convenience:
`grantPlatformRole` requires `rbac:manage`, which requires a role, which after the cutover nobody is
minted by default. The CLI breaks the cycle by writing the row directly, with `granted_by = NULL`
recording exactly that.

`--user` accepts a `users.id` or an email. **An email matching more than one person is a hard
refusal, never a pick.** Two people can genuinely share an email string here — `federated_identities`
is unique on `(issuer, subject)`, not on `email`, so the same address logged in through two realms is
two rows, two accounts and two `users` rows. Choosing one would grant admin to the wrong human,
silently, with no signal that it happened. The error lists every candidate id so the retry can name
one exactly.

### D8 — Hand-written SQL (ADR-0038 exception)

`platform_role_grants` is deliberately absent from `crates/lightbridge-authz-api/schema/authz.cstack`,
for two independent reasons:

1. The hot read runs on the **token-mint path inside `authz-idp`**, which builds no cratestack
   client at all — a model here would be unreachable from the one caller that matters most.
2. The grant's idempotency is an `ON CONFLICT … WHERE revoked_at IS NULL DO NOTHING` against a
   **partial** unique index, and revocation is an `UPDATE … WHERE revoked_at IS NULL RETURNING` —
   the same class of single-statement conditional write as `consume_authorization_code` and
   `consume_secret_claim`, which generated CRUD cannot express.

Recorded in AGENTS.md's Persistence exception list.

## Consequences

- **The security hole closes only when B1 ships.** This story adds the capability; prod still maps
  `owner → lightbridge-admin` until ai-helm-values changes it. The order is non-negotiable:
  A2 → **A5** → B3 (bootstrap the first admins) → B1 (flip the mapper) → C9 (console gating). Any
  other order locks every operator out of `/admin/*`.
- **A `platform_roles` mapper configured before its table exists stops all token minting.** That is
  D2's fail-closed contract, correct and load-bearing, and it is exactly why B1 waits for the image.
- **`getMyAccess` becomes the console's only source of truth for gating.** `isAdmin(roles)` in the
  console is dead code the moment C9 lands.
- **Grants accumulate history forever.** Deliberate. The table is measured in dozens of rows per
  deployment, and the history is the product.
- **Nothing here touches `project_members`.** Per-project roles are unchanged (ADR-0006); a platform
  role and a project role are different questions with different answers.

## Alternatives considered

- **An `is_admin BOOLEAN` on `users`.** No granter, no timestamp, no reason, no history, and no way
  to express a second role. The audit trail is the feature.
- **Keycloak realm roles.** ADR-0014 settled it: a second source of truth for a claim this service
  depends on, unavailable to any deployment not brokering Keycloak.
- **Precedence between the two claim sources** (platform roles WIN over project roles, or vice
  versa). Rejected: neither is more authoritative than the other, and any precedence rule makes the
  claim depend on an ordering the operator cannot see in the emitted token. Union is the only rule
  that is obviously right by inspection.
- **Making `getMyAccess` recompute permissions from `oauth2.rbac`.** Rejected: two evaluations of
  the same map is one more than the number that can be correct. It reads the map's own output
  instead.
