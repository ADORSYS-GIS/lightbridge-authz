# Budget decision contract

This document specifies the seam between "policy says yes/no" and everything downstream that
consumes that answer, for the dynamic budget refill epic (#188). It is written for someone who
has never read `crates/lightbridge-authz-budget/src/` and who needs to implement a **second**
policy engine (per ADR-0007, an OPA-Wasm engine, in a later phase) against this contract without
reading the first engine's source.

Source of truth: [ADR-0007](adr/0007-refill-decisions-rule-data-then-opa-wasm.md) (the decision
to define one contract with two engines behind it), [ADR-0008](adr/0008-refills-are-discrete-budget-tiers.md)
(the tier ladder and "two unaided rungs per period" rule the facts below support), and
[ADR-0009](adr/0009-budget-grants-are-an-immutable-ledger.md) (the ledger a granted decision
writes into).

The types described here live in `crates/lightbridge-authz-budget/src/facts.rs` and
`crates/lightbridge-authz-budget/src/decision.rs`. **This PR defines only the shape** -- no
evaluator implements `PolicyEngine` yet, and no code in this crate populates a `Facts` value from
the database. Both land in later PRs.

## The fact set (`Facts`)

`PolicyEngine::evaluate` is a pure function: it receives a `Facts` value and a requested amount,
and returns a `Decision`. It never fetches state, never touches the database, never calls out.
Everything it might need must already be sitting in `Facts` when `evaluate` is called. This is
deliberate (ADR-0007: "the host loads every fact, locks, evaluates, re-validates hard invariants
in application and SQL, applies atomically") -- the evaluator's job is narrowly to decide, not to
gather.

```rust
pub struct Facts {
    pub effective_balance_micros: i64,
    pub self_service_grant_count: i32,
    pub spend_this_period: Spend,
    pub spend_last_period: Spend,
}
```

| Field | What it is | Where the host gets it |
| --- | --- | --- |
| `effective_balance_micros` | The account's expiry/revocation-aware effective balance for the requested period. | `BudgetRepo::effective_balance(budget_account_id, period, as_of)` -- **not** the raw `budget_balances.effective_budget_micros` column, which does not account for expiry, and **not** `BudgetRepo::rebuild_all_balances`, which replays the whole ledger and is the wrong tool for reading one row's current state. |
| `self_service_grant_count` | How many *unaided* (auto-approved) self-service refills this account has already used in the current period -- the counter ADR-0008's "two unaided rungs per period" rule caps. | Read directly off the `budget_balances` row's `self_service_grant_count` column for `(budget_account_id, period)`. |
| `spend_this_period` | Spend for the period being evaluated. | `SpendReader::spend_for_account(account_id, period)` for the current `Period`. |
| `spend_last_period` | Spend for the immediately preceding period -- e.g. to support a rule like "approve up to 20% of last period's consumption" (ADR-0007's own example). | `SpendReader::spend_for_account(account_id, period.previous())` -- `Period::previous()` computes the prior calendar month, including the December-of-prior-year rollover from January. |

### `Spend`, not a bare number

Both spend fields are the `Spend` enum from `crates/lightbridge-authz-budget/src/spend.rs`, not a
plain `i64`:

```rust
pub enum Spend {
    Known(i64),
    Unavailable,
}
```

`SUM(total_cost)` over zero matching rows is SQL `NULL`, not zero -- an account with no usage
rows (broken ingest, a retention rollout, or simply a brand-new account) is not the same thing as
an account that provably spent nothing, and a policy decision must not conflate the two.

**An evaluator must not silently treat `Spend::Unavailable` as zero.** If an evaluator's rule
logic needs a spend fact and that fact is `Unavailable`, the evaluator must itself fail closed --
resolve to `Deny` or `ManualReview`, with a `reason_codes` entry saying which fact was missing --
never substitute `0` and proceed as if spend were known. This is the one property this contract
existed to make impossible to get wrong by accident: the type itself forces every caller and
every evaluator to handle "we don't know" as a distinct branch, not a default.

## The decision (`Decision`)

`evaluate` returns a `Decision` (or a `BudgetError`, reserved for failures the caller itself must
react to -- see below):

```json
{
  "effect": "auto_approve | auto_approve_capped | manual_review | deny | no_action",
  "approved_amount_micros": 0,
  "maximum_amount_micros": 5000000,
  "reason_codes": ["..."],
  "matched_rule_ids": ["..."],
  "policy_revision": "budget-policy-42",
  "obligations": { "required_approver_role": "budget-approver" }
}
```

Every field is present on every `Decision` regardless of `effect` -- a caller never has to guess
which fields are populated for which effect; fields that don't apply are simply left at their
zero/empty value (e.g. `approved_amount_micros: 0` on a `Deny`).

| Field | Meaning |
| --- | --- |
| `effect` | See the table below. |
| `approved_amount_micros` | How much was actually approved. `0` unless `effect` is `auto_approve` or `auto_approve_capped`. |
| `maximum_amount_micros` | The ceiling the evaluator computed for this request, whether or not it was fully granted (e.g. what `auto_approve_capped` capped against). |
| `reason_codes` | Machine-readable strings explaining the decision (e.g. `over_unaided_rung_limit`, `spend_this_period_unavailable`). Always populate this on `Deny`/`ManualReview` so the caller can record *why*. |
| `matched_rule_ids` | Which rule(s) in the active policy revision produced this decision. Empty is valid (e.g. a hard-coded fail-closed path with no matching rule). |
| `policy_revision` | An identifier for the policy version that produced this decision, so decisions are auditable against the policy that was active at the time. |
| `obligations` | Side conditions the caller must satisfy in addition to granting or not granting. Currently one named field, `required_approver_role` -- see below. |

### What a caller does for each `Effect`

| `Effect` | Caller action |
| --- | --- |
| `AutoApprove` | Grant `approved_amount_micros` immediately via `BudgetRepo::grant`. |
| `AutoApproveCapped` | Same as `AutoApprove`, but `approved_amount_micros` is less than what was requested (capped at `maximum_amount_micros` or another evaluator-computed ceiling); grant the capped amount via `BudgetRepo::grant`. |
| `ManualReview` | Do not grant. Queue the request for a human holding the role named in `obligations.required_approver_role`. |
| `Deny` | Do not grant. Record why via `reason_codes`; surface this to the requester. |
| `NoAction` | Do not grant. Distinct from `Deny` for cases where no decision was actually needed (e.g. a request that turned out to be a no-op) -- record via `reason_codes` if useful, but this is not a rejection to surface as an error. |

### `Obligations`

```rust
pub struct Obligations {
    pub required_approver_role: Option<String>,
}
```

Modeled as a named optional field, not a free-form map: ADR-0007 gives exactly one obligation
kind ("which role must review a `ManualReview` decision"), and a generic
`HashMap<String, serde_json::Value>` would be speculative ahead of a second kind actually being
needed. Populate `required_approver_role` when `effect` is `ManualReview`; leave it `None`
otherwise. If a second obligation kind becomes necessary, add another named field rather than
introducing a generic map at that point either.

## The fail-closed rule

This is the property that matters most about this contract, and the first thing any test suite
for a new engine should check:

> On any compile, load, evaluation, or schema-validation failure, the safe default is
> `manual_review` or `deny` -- **never** automatic approval. (ADR-0007)

Concretely:

- An evaluator that hits an internal error mid-evaluation (a malformed rule, a timeout, a bug)
  must still resolve to a `Decision` with `effect: Deny` or `effect: ManualReview`. It must never
  produce `AutoApprove`/`AutoApproveCapped` as a fallback, and it must never let an error silently
  propagate into "no decision was made, so nothing was denied, so proceed."
- `PolicyEngine::evaluate` also has a `Result<Decision, BudgetError>` return type. A `BudgetError`
  is reserved for failures where the caller itself must react and cannot receive a `Decision` at
  all (for example: the engine could not be invoked). An evaluator that *can* run to completion
  should prefer returning `Ok(Decision { effect: Deny | ManualReview, .. })` over an `Err`, because
  a `Decision` carries `reason_codes` that an `Err` cannot, and downstream consumers (audit logs,
  the requester-facing message) are built around reading a `Decision`.
- A missing or unusable input fact (in particular `Spend::Unavailable` for a fact the evaluator's
  rules need) is not "assume the best case and continue" -- it is "unknown", and unknown routes to
  the strictest branch, exactly like an unparseable JWT claim elsewhere in this codebase routes to
  the strictest branch rather than a default.

Any second engine built against this contract (OPA-Wasm, per ADR-0007) must preserve this
property exactly: whatever failure mode is specific to that engine (a Wasm module that fails to
load, a bundle signature that doesn't verify, an evaluation that times out) must still resolve to
`Deny` or `ManualReview`, never to automatic approval.

## What is explicitly out of scope of this contract (as of this PR)

- No evaluator implements `PolicyEngine` yet. This PR defines the trait and the types it moves
  data through; the Rust rule-data evaluator ADR-0007 calls for lands in a later PR.
- No code in this crate assembles a `Facts` value from the database. The `BudgetRepo`/
  `SpendReader` calls in the table above describe where a caller *would* get each fact; wiring
  those calls together into one procedure belongs to whichever later PR builds the actual
  request-handling flow.
