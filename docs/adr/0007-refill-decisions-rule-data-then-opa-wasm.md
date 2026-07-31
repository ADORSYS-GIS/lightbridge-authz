# ADR-0007: Refill decisions come from rule data first, OPA-Wasm second, behind one contract

- Status: Proposed
- Date: 2026-07-31
- Decision owners: @stephane-segning

## Context

Refill requests need a policy: auto-approve small ones, cap some, send others for review,
deny the rest. Administrators must be able to change that policy without a code deploy.

The source plan specifies real Rego compiled to OPA-Wasm and embedded in this service, with
two authoring levels: **rule data** as structured JSON for ordinary administrators, and
**arbitrary Rego** for a restricted `policy-admin` role.

Two things shape the decision. First, ~all the rule-data examples are threshold comparisons
over fields the host already computed -- a plain Rust evaluator covers them completely.
Second, arbitrary Rego buys things rule data genuinely cannot express: cross-entity queries
("approve only if no other project member refilled this period"), set and aggregate logic,
and computed relationships ("approve up to 20% of last period's consumption"). Those are
wanted.

⚠️ Note also the platform history: OPA was **removed** from the gateway on 2026-06-04 after
a missing Secret in an ext_authz HTTP metadata step 404'd the entire gateway. That is not
this. This is an **embedded** evaluator in a control-plane API, off the inference path,
with a last-known-good fallback. The blast radius is not comparable, and the name should not
do the arguing.

## Decision

Define **one decision contract** and put two engines behind it:

```json
{
  "effect": "auto_approve | auto_approve_capped | manual_review | deny | no_action",
  "approvedAmountMicros": 0,
  "maximumAmountMicros": 5000000,
  "reasonCodes": ["..."],
  "matchedRuleIds": ["..."],
  "policyRevision": "budget-policy-42",
  "obligations": { "requiredApproverRole": "budget-approver" }
}
```

1. **Rust rule-data evaluator** ships first. It is the path ordinary administrators use and
   is needed regardless of whether Rego exists.
2. **OPA-Wasm** ships second, behind the same contract, for the `policy-admin` role:
   bundle build/sign/verify, atomic hot-swap, last-known-good fallback, evaluation timeout,
   active revision on the health endpoint.

**OPA decides; this service mutates.** The evaluator never inserts grants, never touches
Redis, never fetches state and never calls out. The host loads every fact, locks the
balance, evaluates, **re-validates hard invariants in application and SQL**, applies
atomically, and records the decision with its policy revision.

On any compile, load, evaluation or schema-validation failure the safe default is
`manual_review` or `deny` -- **never** automatic approval.

## Consequences

**Positive**
- The whole policy lifecycle (versioning, staging, activation, rollback, simulation,
  decision logs) is built and tested on the cheap engine first; Wasm then lands onto a
  lifecycle that already works.
- Ordinary administrators never write executable policy.
- Because the contract is the seam, swapping or adding an engine is contained.

**Negative**
- Two engines to maintain. Justified only because both authoring levels are genuinely
  wanted -- if arbitrary Rego had not been, the second engine would not exist.

**Neutral / follow-ups**
- ⚠️ Not every Rego built-in compiles to Wasm. Verify the ones the production policy needs
  during the Wasm phase. Passing `now` in as input rather than calling `time.now_ns()` is
  already the right instinct.
- Separate `budget:policy-write` from `budget:policy-activate`. With arbitrary Rego, write
  means "ship executable code into the decision path"; it should not be the same identity
  that activates it.
- Re-evaluate a pending request under lock at approval time. State may have moved while it waited.

## Alternatives considered

- **OPA-Wasm only, from the start** -- rejected as sequencing: it front-loads the bundle
  machinery before the lifecycle exists to plug it into.
- **Rule data only, forever** -- rejected: it cannot express the cross-entity rules that are wanted.
- **Policy as code deployed with the service** -- rejected: every threshold change becomes a release.

## Related

- ADR-0006 (the ledger the decision writes into), ADR-0008 (enforcement)
- Runbook: `docs/runbooks/roll-back-a-budget-policy.md`
