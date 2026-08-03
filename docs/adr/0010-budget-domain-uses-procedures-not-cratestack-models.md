# ADR-0010: The budget domain is hand-written procedures, not cratestack models

- Status: Proposed
- Date: 2026-08-03
- Decision owners: @stephane-segning

## Context

Epic #188 (dynamic budget refill) needs a new domain: an immutable budget-grant ledger,
derived balances, augmentation requests, and a policy engine (rule data first, OPA-Wasm
second per ADR-0007) evaluated against discrete budget tiers (ADR-0008). None of this exists
yet in code -- this PR is the first slice that lays down where it lives.

Every other CRUD-shaped surface in this repository (`Account`, `Project`, `ProjectMember`,
`ApiKey`) is declared as a cratestack `model` block in
`crates/lightbridge-authz-api/schema/authz.cstack`, which generates its `list|get|create|
update|delete` verbs, `@@allow`/`@@deny` policy checks, and nested filter/order/include
modules. The obvious move would be to add `BudgetGrant` and `BudgetAugmentationRequest`
models the same way. Two things already evidenced in this repository argue against it.

**1. The ledger must refuse `UPDATE`/`DELETE`, not merely have them fail-closed.**

`crates/lightbridge-authz-rest/src/rpc_authorize.rs` documents the pattern this repo already
uses when a cratestack model has verbs that must never succeed: `ProjectMember` "is
policy-locked to read-only and has no generated mutation verbs; denied here too for defense
in depth" -- i.e. the schema first drops the model's `@@allow` for those verbs, and the
RBAC map denies the op-id *again* as a second layer, because a bare model declaration still
generates the verb and its route. A cratestack `model BudgetGrant { ... }` would generate
`model.BudgetGrant.update` and `model.BudgetGrant.delete` regardless of what policy
attributes we attach, and the actual guarantee would live in the same fail-closed RBAC map
as everything else -- an application-layer belt, not a storage-layer refusal. An append-only
ledger is a stronger invariant than "no caller happens to be authorized to mutate it": it
should be that the storage layer has no code path capable of an `UPDATE`/`DELETE` at all.
That is only true of a hand-written repository that simply never issues those statements.

**2. This schema's relation codegen has already produced a measured, near-fatal blowup from
exactly this shape of extra relation path.**

`crates/lightbridge-authz-api/schema/authz.cstack`'s `ProjectMember` model documents, in its
own comments, why `ProjectMember.accountId` is "deliberately a bare scalar with NO `account
Account @relation`": `Account` and `Project` are already directly connected
(`Account.projects`), so adding `ProjectMember.account` "makes `ProjectMember` a SECOND path
between them," and "cratestack's relation codegen walks every acyclic path through the
relation graph to emit nested filter/order/include modules." The file records the measured
cost of that one extra edge: `cargo check` on the `lightbridge-authz-api` crate "consumed
~51 GB (16 GB RAM + 36 GB swap) over 36 minutes and was still growing when the CI runner
killed it." That comment also names the fix as removing the relation, not increasing
runner memory.

A `BudgetGrant` (and `BudgetAugmentationRequest`) model needs both `accountId` and
`projectId` to answer the questions this domain actually asks ("what has this account been
granted", "what is outstanding for this project"). Declared as relations, each field is a
new edge in a graph that already has one instance of exactly this multiplicative behavior
on record. This is not a hypothetical extrapolation from the `ProjectMember` incident; it is
the same mechanism (an additional path between two already-connected models) that produced
the measured 51 GB/36-minute build before CI killed it.

## Decision

The budget domain -- grants ledger, materialized balances, augmentation requests, and policy
sets/revisions -- is implemented as a new workspace crate, `lightbridge-authz-budget`,
holding:

- domain types (grant, balance, augmentation request, policy set/revision, decision
  contract per ADR-0007),
- a hand-written repository issuing explicit SQL (`INSERT`-only for the ledger table; no
  `UPDATE`/`DELETE` statement exists in the module for it),
- the policy engine (the rule-data evaluator first, OPA-Wasm behind the same contract
  later).

It is wired into `lightbridge-authz-rest` through hand-written cratestack `procedure`
declarations added to `authz.cstack` -- **procedures only, no `model` blocks for this
domain.** Procedures already have precedent in this schema for operations that need
hand-written invariant checks beyond what `@@allow` can express (`createAccount`,
`createApiKey`, `addProjectMember`/`removeProjectMember`/`setProjectMemberRole`/
`setProjectMemberQuotaTier`); the budget domain uses the same mechanism for its entire
surface rather than for a subset of write paths.

This PR itself adds only the crate skeleton (`Cargo.toml`, a documented empty `lib.rs`) and
this ADR. The domain types, repository, procedures, and policy engine are later PRs in the
epic #188 delivery sequence.

## Consequences

### Positive

- The append-only guarantee is enforced where it matters: no code path in the repository can
  emit `UPDATE`/`DELETE` against the ledger table, independent of any policy/RBAC
  configuration.
- No new edges are added to `authz.cstack`'s relation graph, so this domain carries none of
  the measured relation-codegen cost, regardless of how many fields the budget domain ends up
  needing on `Account`/`Project`.
- The procedure mechanism, the fail-closed RBAC map, and the hand-written-repository pattern
  are all already established idioms in this codebase (`lightbridge-authz-api-key`,
  `rpc_authorize.rs`) -- this is not a new architectural style, just this domain using the
  path already reserved for "logic `@@allow` can't express" instead of the path reserved for
  generated CRUD.

### Negative

- No generated list/filter/pagination/OpenAPI-adjacent machinery for this domain -- every
  query shape (list grants for an account, outstanding balance for a project, pending
  augmentation requests) is hand-written SQL and a hand-written response type. This is more
  code than a `model` block would have produced for the read paths that *are* safe to expose
  generically.
- Two patterns now exist side by side in the same schema file: cratestack `model` blocks for
  the account/project/api-key surface, and hand-written `procedure`s plus an entirely
  separate crate for the budget surface. A future contributor needs this ADR to understand
  why the budget domain didn't just get its own models.

### Neutral / follow-ups

- If a later phase needs a read-only, non-sensitive projection of budget data (e.g. a
  dashboard aggregate analogous to `AccountSummary`), a cratestack `view` may still be
  appropriate for that narrow slice -- this decision is about the ledger and its mutating
  operations, not a blanket ban on cratestack constructs anywhere near this domain.
- Re-evaluate this decision if cratestack's relation codegen changes its complexity
  characteristics (see the 0.5.0 changelog note in the root `Cargo.toml` about
  `cratestack/cratestack#252`/`#253`, which was a related but distinct exponential-codegen
  bug already fixed upstream) -- but the append-only enforcement argument (reason 1) holds
  independent of any codegen performance fix.

## Alternatives considered

- **Cratestack `model` blocks with fail-closed RBAC** -- rejected. This is exactly the
  `ProjectMember` pattern (`rpc_authorize.rs`): a model declares mutation verbs and a
  separate RBAC map denies them. That is a weaker enforcement point for an append-only
  invariant than a repository that cannot emit the statement at all, and it still adds
  `accountId`/`projectId` relation edges with the same multiplicative risk documented for
  `ProjectMember.account`.
- **Extend the existing `lightbridge-authz-api-key` crate/repo** -- rejected. That crate is
  entities-and-repository for the existing authz aggregates (accounts, projects, project
  members, API keys); it has no policy engine and shouldn't grow one. Mixing the budget
  ledger's append-only repository and its rule-data/OPA-Wasm evaluator into a crate scoped to
  a different domain's persistence would blur a boundary that is otherwise clean, for no
  reuse benefit -- the two domains don't share a transaction boundary the way the existing
  authz aggregates do.

## Related

- ADR-0006 (project membership supersedes account roles) -- the relation-graph precedent
  this decision cites (`ProjectMember.account`, the measured 51 GB/36-minute build).
- ADR-0007 (refill decisions: rule data first, OPA-Wasm second) -- the decision contract the
  policy engine in `lightbridge-authz-budget` implements.
- ADR-0008 (refills are discrete budget tiers) -- the tier design the policy engine evaluates
  against.
- Epic #188 (dynamic budget refill).
