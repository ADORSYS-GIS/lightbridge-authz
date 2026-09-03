# ADR-0018: A `model_policy` enum on `projects` makes "no models allowed" a reachable state, defaulting to today's allow-all behavior

- Status: Accepted
- Date: 2026-08-21
- Decision owners: Stephane Segning Lambou

> **Partially superseded, 2026-09-03 (#430, PR #454).** The `model_policy` (and `allowed_models`)
> **claim** is gone from every minted token; `authz-opa` introspection is the sole source of both
> for every caller shape. Everything else in this ADR stands: the `projects.model_policy` enum, the
> `ModelPolicy::from` fail-closed parse to `DenyAll`, `setProjectModelPolicy`'s allowlist guard,
> and the gateway's ADR-0018 semantics (`allow_all` / `allowlist` / `deny_all` / unrecognised ->
> deny) are unchanged -- the policy is enforced from the same values, read live rather than frozen
> at mint. See `ADORSYS-GIS/ai-helm-values#296` for the CEL arms this makes dead.

## Context

**Most of the per-model access control story here is already built and running in production.**
This ADR is a small addition to a live system, not new infrastructure — it exists to close one
specific gap in it.

1. **The enforcement rule is live.** `ai-helm-values`
   `environments/prod/values/security-policies.yaml:432-454` defines an Authorino
   `patternMatching.predicate` named `lightbridge-model-allowed`:

   ```
   !has(auth.metadata.lightbridgeintrospect) ||
   !has(auth.metadata.lightbridgeintrospect.allowed_models) ||
   size(auth.metadata.lightbridgeintrospect.allowed_models) == 0 ||
   !("x-ai-eg-model" in request.headers) ||
   request.headers["x-ai-eg-model"] == "" ||
   (request.headers["x-ai-eg-model"] in auth.metadata.lightbridgeintrospect.allowed_models)
   ```

   It is gated on `auth.identity.api_key_id != ""` and `auth.identity.iss !=
   https://auth.verif.fyi/realms/camer-digital` — i.e. it only ever evaluates on the **API-key
   plane**. The human/OIDC plane skips this rule's `when` entirely.

2. **The model name reaches the gateway as `x-ai-eg-model`**, a header Envoy AI Gateway's ext_proc
   extracts from the request body ahead of Authorino in the external filter chain (documented
   in-line at `security-policies.yaml:406-421`, verified against a live `config_dump`).

3. **Introspection already returns `allowed_models`** —
   `crates/lightbridge-authz-rest/src/handlers/introspect.rs:62`
   (`allowed_models: validated.project.allowed_models.clone()`), sourced from the project row.

4. **Token-exchange already stamps `allowed_models` as a claim**, at both mint and refresh —
   `crates/lightbridge-authz-rest/src/oauth2_op/store.rs:425-462` (`handle_token_exchange`) and the
   mirrored block in `handle_refresh_token` (~line 690). So the human/OIDC plane already carries
   this data on the token today, even though — per point 1 — no gateway rule reads it yet.

5. **`allowed_models` lives on `projects` only**, not `api_keys`. It was added in
   `migrations/20260203000001_init_authz.sql:13` as `allowed_models JSONB NOT NULL DEFAULT
   '[]'::jsonb`, then made nullable by `migrations/20260220000001_refactor_models.sql` (dropping
   the `NOT NULL`/default so `NULL` could be distinguished from `[]` at the domain layer). ⚠️
   **`AGENTS.md`/`CLAUDE.md` (they are the same file — `CLAUDE.md` is a symlink to `AGENTS.md`)
   currently states at line 364 that `api_keys` "includes `allowed_models`". That is stale** and
   is corrected as a standalone doc fix alongside this ADR (Ticket 6, below) — left uncorrected, it
   would send the next implementer to the wrong table.

6. **`Project.allowedModels` has no server-side catalogue validation.** It is a bare `Json?` in
   `crates/lightbridge-authz-api/schema/authz.cstack`, confirmed during #393's investigation. A
   project can already allowlist a model id that does not exist, and nothing complains — the entry
   just never matches, so it is silently harmless today. That changes under this ADR (Decision 5).

**The one thing that makes deny-by-default impossible today: `NULL` and `[]` both mean "all models
allowed."** This is documented behavior (`AGENTS.md`/`CLAUDE.md`: *"`NULL` or `[]` (empty list) are
interpreted as 'all models allowed'"*; restated in the CEL predicate's own comment at
`security-policies.yaml:423-431`: *"NULL/[] means 'all models' per AGENTS.md"*), and it is baked
into both the domain-layer collapse (`refactor_models.sql`'s migration note: *"DB [] (empty array)
-> Domain Some(vec![]) ... DB null -> Domain None ... the logic in the repo will handle the
mapping"*) and the CEL's own `size(...) == 0 || ...` escape hatch. The practical consequence: **the
project-scoped "block everything" state is unreachable**, and clearing the model picker in the
frontend UI does not lock a project down — it *widens* access to every model, which is the exact
opposite of what an operator clearing a list would expect.

The repo owner's decision: *"Allow by default, use a model_policy enum."*

## Decision

### 1. A `model_policy` enum on `projects`, three values, defaulting to `allow_all`

```
enum ModelPolicy {
  allow_all   // any model — today's behavior; the default
  allowlist   // only models in allowed_models; an empty list now genuinely means "nothing"
  deny_all    // no models
}
```

Stored as a new `projects.model_policy` column (migration, default `'allow_all'`, `NOT NULL`).
Every existing row backfills to `allow_all` — the value that reproduces today's behavior exactly,
for every project, with no operator action required. Deploying this migration alone changes
nothing observable; it only makes the other two states reachable going forward.

### 2. `allowed_models` keeps its existing meaning, but is only *consulted* when `model_policy = allowlist`

Under `allow_all`, `allowed_models` is ignored regardless of its contents (so existing `NULL`/`[]`
rows, and any stale entries a project happens to carry, stay inert — no data migration needed on
that column). Under `deny_all`, it is also ignored — nothing is allowed regardless of the list.
Only under `allowlist` does the list's contents matter, and — this is the behavioral change this
ADR exists to enable — **an empty list under `allowlist` denies every model**. That is the
previously-unreachable "block everything" state Context called out.

### 3. Both planes carry `model_policy`

- **Introspection** (`crates/lightbridge-authz-rest/src/handlers/introspect.rs`) gains a
  `model_policy` field on the response, sourced from `validated.project.model_policy`, alongside
  the existing `allowed_models` field — same call, same row, no new query.
- **Token-exchange** (`crates/lightbridge-authz-rest/src/oauth2_op/store.rs`) stamps
  `model_policy` as an access-token `extra` claim at both `handle_token_exchange` and
  `handle_refresh_token`, following the same shape `budget_tier`/`quota_tier` already use at
  those two call sites (`access_extra.insert("model_policy".to_string(),
  Value::String(model_policy))`) — re-resolved on every exchange and refresh, never carried
  forward from a stale token, matching ADR-0014's and ADR-0017's "re-resolve, don't copy" rule for
  claims minted from a live source of truth.

This is what lets a later gateway rule (Ticket 4) read `model_policy` on the human/OIDC plane,
where introspection never runs at all (`docs/governance-model-and-enforcement.md` §4.7) — the claim
is the only mechanism that plane could ever have, the same reasoning ADR-0017 already established
for `quota_tier` on this same plane.

### 4. The existing fail-open CEL clauses stay — and are now coherent, not a compromise

`lightbridge-model-allowed`'s own comment already states the rationale for its three fail-open
escape hatches: *"Closing any of these would turn an opa blip into a full outage."* That reasoning
is unchanged and this ADR does not touch it. What changes is *why it is now the right call and not
merely an accepted risk*: with `allow_all` as the default, an introspection outage failing open
resolves to **the same answer** a healthy request from a default-policy project would get anyway —
fail-open and default-policy converge. The behavior is no longer "we had to pick between safety and
availability," it is "the safe answer and the available answer are the same answer" for the common
case.

**The residual, stated plainly:** a project on `allowlist` or `deny_all` *also* fails open during
an introspection outage — the CEL's `!has(auth.metadata.lightbridgeintrospect)` clause cannot tell
"opa is down" apart from "this project allows everything," because both look like "no metadata."
That is an accepted trade under this ADR, not an oversight. The mitigation is already in place by
Decision 3: the claim path carries `model_policy` on the token itself, independent of introspection
being reachable at request time — a future gateway rule that prefers the claim over introspection
metadata (or a fallback ordering that checks the claim when metadata is absent) can close this
residual without a design change here. That is deliberately left as a follow-up, not solved in this
ADR — see "Follow-ups."

### 5. Catalogue validation of `allowed_models` becomes a precondition for `allowlist` mode, not cleanup

Issue #393 investigated exactly this question — whether `updateProject` should validate
`Project.allowedModels` against the operator catalogue — and deliberately deferred it ("do not add
this now"), for three reasons recorded there: it was carved out of that ticket's scope, backfilling
existing stale/renamed ids needed its own design pass, and the catalogue itself was, at the time,
not yet a stable static value to validate against. That third blocker is resolved: #393's own
follow-up (`ai-helm-values` PR #282) generates `lightbridge-app.yaml`'s `config.models` block
statically from `models.yaml` at commit time, with a CI drift check — so the catalogue `updateProject`
would validate against is now exactly the plain, deploy-time-static config value #393's decision
comment anticipated, with no live dependency and no new fail-mode question.

**The severity of skipping this validation changes under `allowlist`, which is why it is a
precondition here rather than the same "cleanup, someday" item #393 left it as.** Today, an
unvalidated typo in `allowed_models` (a renamed or nonexistent model id) is harmless: it just never
matches an incoming `x-ai-eg-model`, and — because `allow_all` is what actually governs access —
every real model still works regardless of what the stale entry says. Under `allowlist`, the same
typo is a **lockout** of a model the operator meant to grant, and it presents to that operator as an
outage ("my project can't reach GPT-4.1 and I didn't touch anything"), not as a validation error
they can act on. A project cannot safely be moved to `allowlist` mode without this guard, so Ticket
2 (catalogue validation) must land with or before Ticket 1 (the enum itself) — see Consequences.

## Consequences

- **Deploy ordering is a hard constraint, not a preference.** The backend (schema column,
  introspection field, token-exchange claim) must ship and be *running* in the target environment
  before the `ai-helm-values` CEL rewrite (Ticket 3) that reads `model_policy`. A CEL expression
  referencing a metadata field that does not yet exist on the wire evaluates that field as absent —
  which, per Decision 4's own escape hatches, currently means "allow" for the model-check clauses
  that already exist, but a *rewritten* predicate assuming `model_policy` is always present could
  behave differently. In this estate, `lightbridge-authz` container images auto-promote to prod on
  merge, while `ai-helm-values` changes are manual (`workflow_dispatch`) — so "PR #N merged" is not
  "PR #N deployed" for the gateway side, and Ticket 3 must gate on the backend PR being live in
  prod, not merely merged.
- **No behavioral change on deploy.** Every existing project defaults to `allow_all`; nothing
  currently working stops working the moment the migration lands.
- **`allowlist` mode is not safely usable until Ticket 2 (catalogue validation) ships.** An operator
  who moves a project to `allowlist` before that guard exists can lock themselves out of a model via
  a typo with no server-side signal that anything is wrong.
- **The human/OIDC plane gets no enforcement from this ADR alone.** Decision 3 puts `model_policy`
  on the claim, but the existing `lightbridge-model-allowed` rule's `when` clause excludes any
  request without `api_key_id` — i.e. every human request. A sibling rule (Ticket 4) is needed to
  actually enforce this on that plane; until it ships, `model_policy`/`allowed_models` ride on the
  human-plane token unused, same as `allowed_models` does today.
- **Per-member model restriction remains out of scope.** `allowed_models`/`model_policy` are
  project-scoped. "This user cannot access this model, but their project-mate can" is not
  addressed here — see Follow-ups.

## Alternatives considered

- **Reinterpret `[]` as deny-all, `NULL` as allow-all, without a new enum.** Rejected: this
  silently changes behavior for every existing project that happens to have `allowed_models = []`
  today, with no operator action and no migration to signal it. Worse, the frontend's model picker
  already writes `[]` when a user clears every checkbox (today, intentionally meaning "allow
  everything" — see Context) — under this alternative, that exact same user action would flip to
  meaning "deny everything," locking the project out on the next deploy with no code change on the
  frontend side at all. The enum makes the three states explicit and requires an operator to
  actively choose `allowlist` before an empty list can mean "nothing."
- **Per-API-key allowlists instead of (or in addition to) project-scoped ones.** Rejected for this
  ADR, deferred as a follow-up: `allowed_models` is a `projects` column by design (point 5 in
  Context), and the real unmet need this ADR was not asked to solve — "one member of a project
  should not reach a model their project-mates can" — needs a `project_members` column resolved the
  same way `quota_tier` already is (ADR-0017), not a rework of the project-level mechanism. See
  Follow-ups.
- **Enforce per-backend instead of at the gateway.** Rejected: every model backend would need to
  duplicate the same allowlist check, multiplying the number of places this logic can drift or be
  forgotten, and losing the single decision point the gateway currently is (Authorino, one
  `patternMatching` predicate, one place to audit).

## Follow-ups

- **Per-member model allowlists** (sized as a follow-up epic, not a ticket): the case of "a *user*,
  not a project, that cannot access a model." Needs a `project_members` column and a claim/
  introspection path resolved the way `ProjectMember.quotaTier` already is per ADR-0017, plus its
  own gateway rule layered on top of (not replacing) the project-level `model_policy` this ADR
  introduces.
- **Closing the introspection-outage residual from Decision 4** — preferring the token claim over
  introspection metadata (or falling back to it) so an `allowlist`/`deny_all` project does not fail
  open during an opa blip the way it does today. Not solved here; the claim exists so this is a
  gateway-side follow-up once there is operational appetite for it.
