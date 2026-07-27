# ADR-0006: Project membership supersedes account roles

- Status: Accepted
- Date: 2026-07-24
- Decision owners: Lightbridge Authz maintainers
- Supersedes: ADR-0005's account membership roles (`owner`/`admin`/`member` on
  `account_memberships`), and the account-level membership model ADR-0002
  introduced (`account_memberships` itself, not just its role column)

## Context

Epic ai-helm#531 ("project-based AI governance") was, from the start, meant to introduce
project-level membership and per-project/per-member quota tiers. ADR-0005 landed account-level
membership roles (`owner`/`admin`/`member`) shortly before the epic's full product vision was
articulated in a whiteboard session between the user and their project lead. That vision resolved
the intended shape unambiguously, and it isn't "roles on top of account membership" — it's a
different axis entirely:

- **A person's defining identity in the system is their `accountId`.** One account = one person.
  There is **no account-level membership of any kind** — not roles on it, not a roster, nothing.
- Every account has a **default project**, auto-provisioned, with **no membership concept at
  all** ("you, working alone" — no roster, no invites, not even the owner listed as a member).
- A **project** (other than the default one) groups people working toward a shared goal and has a
  real roster: `ProjectMember` rows, `{project, account, role: lead|member, quotaTier}`.
- **`billingIdentity` moves from `Account` to `Project`** — one project, one billing identity
  ("who's paying"), because one account can have several projects billed to different parties
  (e.g. a consultant with three client projects).
- Two tiers of spending ceiling, both drawn from the same governance tier catalog: a pooled
  per-project ceiling (`Project.projectQuota`) and a per-member ceiling
  (`ProjectMember.quotaTier`, settable only by the project's lead). The account's own default-project
  usage needs an equivalent value too, but there's no `ProjectMember` row to hang it on (the
  default project has no roster) — it lives directly on `Account` as `defaultQuota`.

Account-level roles briefly coexisted with this in-flight project-membership work and turned out
not to be the right axis once the full vision was articulated — this ADR retires them in favor of
project-only membership, which was the epic's actual target all along.

Two implementation forks the epic's handoff plan left open are resolved as part of this decision
(confirmed directly with the user, not inferred):

- **Account creation stays explicit**, matching `converse-frontends`' existing self-service
  bootstrap pattern (`useEnsureDefaultAccount` → `procedures.createAccount`, then
  `useEnsureDefaultProject` → `projects.create`) — not a new implicit, SPI-side auto-provisioning
  path. `createAccount` remains the only way to create an account, same as today.
- **Project selection for the human/Keycloak plane uses per-session token exchange** (re-mint the
  JWT via `lightbridge-keycloak-spi` to switch projects), not a per-request
  `x-lightbridge-project` header — this keeps the introspection-fast requirement (below) clean:
  no per-request project resolution needed at all, since the JWT already carries it.

## Decision

### Schema (`crates/lightbridge-authz-api/schema/authz.cstack`)

- **`Account`**: `billingIdentity` removed (moved to `Project`, see below); `memberships
  AccountMembership[]` relation removed entirely. New `defaultQuota String?` field (governance
  tier catalog, config-validated at write time — same pattern `billingPlan` already uses). `@@allow`
  for read/update simplifies from `memberships.some.subject == auth().id` to `id == auth().id`
  directly, since there is no more membership indirection at the account level at all. Still no
  `@@allow("create"/"delete", ...)` — account creation stays exclusively through the `createAccount`
  procedure (explicit, per the resolved fork above), and deletion stays exclusively through
  `deleteAccountPermanently`.
- **`Project`**: gains `billingIdentity String @unique` (moved from `Account`), `projectQuota
  String?` (pooled ceiling, same tier-catalog validation), `isDefault Boolean @readonly` (true only
  for the auto-provisioned, roster-less project), and a `members ProjectMember[]` relation. All four
  `@@allow` predicates move from `account.memberships.some.subject == auth().id` to `account.id ==
  auth().id || members.some.accountId == auth().id` (create/delete stay account-owner-only). This
  buys a structural invariant for free: a default project has zero `ProjectMember` rows by
  construction (nothing ever inserts one for it), so `members.some.accountId == auth().id` is
  always false there — "no membership concept on the default project" falls out of the data model,
  no `isDefault` branching needed anywhere in policy.
- **New `ProjectMember` model**, replacing `AccountMembership` as the relation-target-only synthetic-`id`
  model (same reasoning: the real table has a composite PK cratestack can't use as a scalar `@id`,
  so a schema-only `id` field exists purely for `.some`/`.every`/`.none` policy traversal and must
  never reach cratestack's migration generator — tracked at cratestack/cratestack#136, same gap
  `AccountMembership` hit). Fields: `projectId`, `accountId` (a real FK, unlike `AccountMembership`'s
  raw `subject` string — a project member IS an account, per the vision), `role` (`"lead"` |
  `"member"`), `quotaTier` (tier-catalog validated). Read-only via `@@allow` — no create/update/delete,
  same as `AccountMembership`; roster mutations stay hand-written procedures.
- **`ApiKey`**: read/update/delete policies move from `project.account.memberships.some.subject ==
  auth().id` to `project.account.id == auth().id || project.members.some.accountId == auth().id`.

### Why this still isn't an `@@allow` schema policy for lead-gated actions

Same limitation ADR-0005 already documented for account roles, now re-confirmed for project roles:
cratestack's relation-quantifier policy predicates resolve each dotted path to exactly one target
scalar field per relation hop (`cratestack-macros/src/policy/model/relation_path.rs`) — there is no
way to express "the member row matching my subject must ALSO have role=lead" as a single joint
condition on one related row. Lead-gated mutations (roster add/remove, quotaTier changes, allowlist
edits, gated API-key creation) stay hand-written procedures with role checks in SQL, mirroring
ADR-0005's pattern exactly, just re-targeted at project leadership instead of account ownership.

### Migrations (`migrations/`)

Four new forward-only migrations, in order (each depends on the previous leaving nothing without a
home mid-migration):

1. `20260724000001_create_project_members.sql` — new `project_members` table, shape mirrors
   `account_memberships` (composite PK, no `id`/`updated_at`/`deleted_at`), but with a real
   `account_id` FK instead of a raw subject string, plus `role` and `quota_tier`. Deliberately no
   `prune_*`-style trigger — a project with zero members is normal (every default project has one
   forever), not an error state to auto-delete on.
2. `20260724000002_projects_billing_identity_and_quota.sql` — adds `billing_identity`,
   `project_quota`, `is_default` to `projects`; backfills every existing account's earliest project
   (or a newly-inserted one, for accounts with none) as its default project, carrying the account's
   old `billing_identity`; synthesizes a unique placeholder billing identity for any other
   pre-existing (non-default) project, since account-level billing was previously shared across an
   account's projects and there's no other 1:1 source value to backfill from.
3. `20260724000003_accounts_drop_billing_identity_add_default_quota.sql` — drops the now-redundant
   `accounts.billing_identity` (and its unique index), adds `accounts.default_quota`.
4. `20260724000004_drop_account_memberships.sql` — drops the `prune_account_without_memberships`
   trigger/function and the `account_memberships` table itself. This makes ADR-0005's role-column
   migration (`20260722000001_account_membership_roles.sql`) dead weight — its target table no
   longer exists. That migration is not reverted or edited in place (migrations are never edited
   after landing, per this repo's convention); it is simply superseded by this one dropping the
   whole table it altered.

### What this ADR does not (yet) build

Scoped tightly to schema + migrations, matching how ADR-0003 and ADR-0005 each landed their own
slice incrementally. Explicitly **not** built in this pass, and expected to leave the following
temporarily red until a follow-up procedure pass lands:

- The hand-written procedures this schema change implies (`addProjectMember`,
  `removeProjectMember`, `setProjectMemberRole`, `setProjectMemberQuotaTier`, lead-gated
  `createApiKey`/rotate/revoke, `updateProjectAllowedModels`).
- The existing `addAccountMember`/`removeAccountMember`/`setAccountMemberRole`/`disableAccount`/
  `enableAccount`/`deleteAccountPermanently` procedures' Rust implementations, which query
  `account_memberships` directly (`crates/lightbridge-authz-api-key/src/repo.rs`) and will fail to
  compile once migration 4 drops that table. `deleteAccountPermanently`'s authorization in
  particular simplifies conceptually once there's no more membership/role concept to gate with —
  "the caller is this account" — but that rewrite is follow-up work, not part of this ADR's landed
  scope.
- The RBAC op-id maps in `crates/lightbridge-authz-rest/src/rpc_authorize.rs` and
  `app/lightbridge-authz/src/mcp.rs`'s `required_tool_permission` (both need new entries for the
  project-membership procedures above).
- JWT claim minting (`crates/lightbridge-authz-rest/src/signing.rs`) extended with `role`/
  `quotaTier`/`projectQuota`, and introspection (`crates/lightbridge-authz-rest/src/handlers/
  introspect.rs`) simplified to the active/revoked-only check the epic's "introspection must be
  JWT-only" requirement calls for.

## Reconciliation with the upstream default-account work (2026-07-26)

This ADR was drafted against `main` at `09f9fb9`. Eight commits landed upstream before any of it was
committed, three of which collide with it head-on — `#148` (default account/project undeletable),
`#152` (`setDefaultAccount`/`setDefaultProject` reassignment), `#156` (backfill fix). The collisions
and their resolutions:

### `accounts.id` is the JWT subject

The schema above uses `id == auth().id` on `Account` and `account.id == auth().id` everywhere else.
That only holds if the account's primary key *is* the caller's subject — otherwise every policy on
every pre-existing row fail-closes the moment `account_memberships` disappears, because nothing else
maps a person to an account. The original draft left this implicit and shipped no migration for it;
`20260727000004_accounts_id_becomes_subject.sql` closes the gap.

`createAccount` therefore no longer generates a `cuid2` — it inserts the caller's subject as the id,
and a second call from the same subject is a `Conflict`. Two consequences worth stating plainly:

- Account ids stop being opaque. They are Keycloak subject UUIDs, and they appear in URLs, logs and
  the `account_id` JWT claim. This was already true of the claim's *value* in practice; it is now
  true by construction.
- `account_id` becomes derivable from the token without touching the database, which is what makes
  the introspection requirement below reachable.

The remap picks each account's owning subject (preferring the `owner` role, then oldest membership),
and for a subject holding several accounts keeps the oldest as survivor, re-parenting the others'
projects onto it. Accounts with **zero** memberships are left untouched: they are already unreachable
under today's membership-scoped policies, so deleting them would destroy data to no benefit. The
separate usage database (`migrations-usage/`) is append-only telemetry and is deliberately not
remapped — historical usage rows keep the old account ids.

**Non-owner members lose access.** Only owners survive the remap; a subject who was merely a member
of someone else's account is not converted into a project member, and loses access when the
membership table is dropped. This was decided explicitly rather than by omission: converting them
would mean auto-creating an account per orphaned subject, and the audit trail of "who can reach
what" matters more here than saving project leads a few `addProjectMember` calls. The migration
carries the query operators should run to count who is affected before applying it.

### The default-*account* concept is removed

`#148`/`#152` gave `accounts` an `is_default` flag, a "your first account cannot be hard-deleted"
rule, and a `setDefaultAccount` procedure to reassign it. All three presuppose that one subject may
hold several accounts. Under "one account = one person" that is impossible, so the flag would be
permanently `true` for every row and the reassignment procedure would have nothing to choose
between. `20260727000006_accounts_drop_is_default.sql` drops the column; the procedure, its repo
method, its RBAC entry and its tests go with it.

The default-*project* half of that same work is **kept and relied upon**: `projects.is_default`, its
`BEFORE INSERT` trigger, the partial unique index making "at most one default project per account"
race-safe, and `setDefaultProject`. It expresses exactly the auto-provisioned, roster-less project
this ADR already called for, and does it in the DB rather than in policy. This ADR's own migration
no longer adds `projects.is_default` — `20260725000001` owns it.

### Migration renumbering

The four migrations listed above were renumbered from `20260724*` to `20260727*` so they sort after
upstream's `20260725000001` and `20260726000001`. Not cosmetic: at the old numbers, `20260724000002`
would have added a `projects.is_default` column that `20260725000001` also adds, and `20260724000004`
would have dropped `account_memberships` out from under `20260726000001`'s backfill, which reads it.
Renumbering is legitimate here only because none of the four had ever been committed to `main` — the
"migrations are immutable once landed" rule is about migrations other databases have already applied.

### Quota tiers are config-validated, and the catalog may be empty

`Account.defaultQuota`, `Project.projectQuota` and `ProjectMember.quotaTier` are validated at write
time against an operator-configured catalog rather than a DB table, because Envoy Gateway's
`BackendTrafficPolicy` can only enforce a small, statically-rendered menu of tiers — a
freely-creatable DB table would not save anyone a chart deploy. An **empty or absent catalog accepts
any value**, so existing deployments and charts keep working until `ai-helm-values` supplies one.
A deliberate "don't break the fleet on upgrade" choice, not an oversight.

### Introspection stays authoritative — the "one lookup" rewrite was not justified

The epic asked for introspection to shrink to a single active/revoked check, with everything else
decoded from JWT claims. Measuring it before building it retired that requirement.

Per uncached call, introspection now does **three** round trips: the indexed `api_key_validation`
view read, the usage-telemetry `UPDATE` (which returns the api-key row, so it doubles as that
fetch), and a project read supplying `allowed_models`/`project_quota`. A fourth — an account read
used only for an id the view had already returned — was pure waste and has been deleted.

Authorino caches the result for 30s keyed on `jti`, and only for API keys, so this runs roughly
twice a minute per active key per replica, against a database this repo's own load test measures at
600-1000 rps with 10-20ms latency. There is no bottleneck here to fix.

What the rewrite would have cost is the reason not to do it: claims are frozen at mint time, so a
quota or plan change would not take effect until the key was rotated. Keeping the lookup means it
lands within the cache TTL. `x-project-id`/`x-project-quota` are therefore sourced from the
introspection response at the gateway; `role`/`quotaTier` remain claim-sourced because they are
per-member values and an API key belongs to a project, not to a roster seat.

This supersedes the "What this ADR does not (yet) build" bullet promising a claims-only
introspection.

### The model allowlist is enforceable, and is now enforced

`allowed_models` had been returned by introspection since before this epic and consumed by nothing.
The doubt was whether Authorino could see the requested model at all, since it arrives in the
request body and `ext_authz` is configured with `with_request_body: {}`.

It can. Verified against the live gateway's filter chain (`config_dump`, 2026-07-27): on the
external chain (`api.ai.camer.digital`) `ext_proc/aigateway` is filter 1 and `ext_authz` is filter
7, so `x-ai-eg-model` is already populated when Authorino evaluates. The AI Gateway places its
ext-proc first by design — it must parse the raw body to extract the model before routing, which is
the same ordering `ai-helm` ADR-0079 established when it ruled out per-user span attribution.

Two findings worth carrying forward, because both contradict a reasonable assumption:

- **The ordering is per filter chain, not global.** The internal chain
  (`core-gateway-internal…svc.cluster.local`) runs `ext_authz` first and `ext_proc` second, so no
  model-dependent rule can ever fire there. That is acceptable: internal identities are Kubernetes
  service accounts and static API keys, carrying no project and therefore no allowlist.
- **The AuthConfig CRD has no `cel:` authorization type** — only `patternMatching`, `opa`,
  `kubernetesSubjectAccessReview` and `spicedb`. The rule is a
  `patternMatching.patterns[].predicate`. This matters because the ArgoCD app sets
  `ignoreMissingValueFiles`, so a schema-rejected AuthConfig fails quietly rather than loudly.

Enforcement fails open in three directions — no `api_key_id`, an absent or empty allowlist (both
`NULL` and `[]` mean "all models"), or no concrete model header. Only an explicit, non-empty
allowlist that does not contain a concretely-requested model denies.

## Consequences

### Positive

- Closes the actual gap epic ai-helm#531 was chartered for — project-scoped membership and
  two-tier quota, not account-scoped roles. ADR-0005's roles were a well-reasoned step at the time
  but solved the wrong layer once the full vision was clear.
- The default-project invariant ("no membership on it") is now structural, not policy-branched —
  one less thing a future reviewer has to reason about per operation.
- `billingIdentity` moving to `Project` directly enables the vision's stated motivating case (one
  account, several projects, different billing parties) that account-level billing identity could
  never express.

### Negative

- This pass leaves the repo in a deliberately temporary broken-compile state for the procedures
  listed under "What this ADR does not (yet) build" above — expected, not a regression, but real
  until the follow-up procedure pass lands.
- A second full membership-model rewrite in as many weeks (ADR-0002 → ADR-0005 → this) is real
  churn; justified here because the product vision itself changed underneath the epic, not because
  of a design mistake in ADR-0005 on its own terms.
- Existing non-default projects (accounts with more than one project pre-migration) get a
  synthesized placeholder `billingIdentity` with no real-world billing meaning — operators need a
  follow-up pass to assign real values where it matters.

## Alternatives considered

### Implicit account provisioning at SPI/token-exchange time

The epic's original handoff plan recommended this (lazy-provision account + default project on
first authenticated request, no explicit `createAccount` call). Rejected — the user confirmed
`converse-frontends`' existing self-service bootstrap flow (explicit `createAccount` then
`Project.create`, client-driven) should be kept as-is rather than replaced with new backend
auto-create behavior.

### Per-request project-selection header (`x-lightbridge-project`)

Simpler client-side change, more flexible, but requires a live per-request metadata lookup — the
wrong shape for the "introspection must be JWT-claims-only" requirement. Rejected in favor of
per-session token exchange (re-mint the JWT to switch projects), matching the epic's own
recommendation.

### Keep `AccountMembership`'s composite-key limitation open, revisit `ProjectMember`'s shape once cratestack/cratestack#136 lands

Considered leaving `ProjectMember` without the synthetic-`id` workaround in the hope the upstream
composite-key gap closes soon. Rejected for this pass — the gap is still open as of this ADR (same
status ADR-0005 found it in), and blocking this schema change on an upstream fix with no committed
timeline isn't worth it when the workaround is already proven safe by `AccountMembership`'s own
history.
