# Budget refill UI contract

Audience: whoever picks up the `lightbridge-ss` (converse-frontends) side of Story #191. This repo
(`lightbridge-authz`) owns the RPC surface; the self-service refill UI lives in a different repo and
this repo's PRs cannot produce the screenshot evidence #191's own Verification section requires — see
that story for the full picture. This doc orients a frontend engineer on the RPC shapes and the
behaviors that need explicit copy, without duplicating the schema.

Source of truth: `crates/lightbridge-authz-api/schema/authz.cstack` (search for
`AugmentationRequest`, `requestBudgetRefill`, `listPendingAugmentationRequests`,
`approveAugmentationRequest`, `rejectAugmentationRequest`) is the authoritative field list. This doc
explains what those fields *mean*; if it and the schema ever disagree, the schema wins.

## The four RPCs

All four require a bearer token (OIDC user session token). None accept an "act on behalf of"
parameter — the reviewing/requesting identity is always the authenticated caller.

### `requestBudgetRefill` — self-service ask for more budget

```
mutation requestBudgetRefill(args: {
  budgetAccountId: string
  accountId: string
  projectId?: string
  period: string        // "YYYY-MM", the calendar month being refilled
  idempotencyKey?: string
}): AugmentationRequest
```

- `budgetAccountId` / `accountId`: today these are always the same value (the caller's own account
  — see the schema's own doc comment for why two separate-looking fields both carry it). Pass the
  signed-in user's account id for both.
- `period`: the calendar month the refill applies to, e.g. `"2026-08"`. Almost always "the current
  month" from the UI's perspective.
- `idempotencyKey`: **generate and send one on every submit.** The client, not the server, owns
  idempotency keys here — a double-click or a retried request with the same key returns the
  original outcome instead of being evaluated twice. Use a fresh UUID/cuid per logical user action
  (one click = one key), not a fixed constant.
- Returns an `AugmentationRequest` — see "Response shape" below for what to render from it.

Requires the caller to hold `budget:self-refill`. A caller who lacks it gets a `403`; the UI should
not normally let a user reach this action if their role doesn't carry it, but should still handle a
`403` gracefully (generic "you don't have permission" messaging) rather than assuming it can't
happen.

### `listPendingAugmentationRequests` — the admin review queue (read)

```
procedure listPendingAugmentationRequests(args: {
  budgetAccountId?: string
}): AugmentationRequest[]
```

Omit `budgetAccountId` (or pass `null`) for the whole cross-account queue (an admin's global view);
pass a specific account id to scope to one account. Requires `budget:review`.

### `approveAugmentationRequest` — approve a queued request

```
mutation approveAugmentationRequest(args: {
  requestId: string
}): AugmentationRequest
```

Grants the requested amount and returns the updated row. Requires `budget:review`. Idempotent
against retries/double-clicks and safe against a concurrent reject on the same request (server-side
locking — the UI does not need to do anything special here beyond normal "disable the button while
in flight" hygiene).

### `rejectAugmentationRequest` — reject a queued request

```
mutation rejectAugmentationRequest(args: {
  requestId: string
  reason: string        // required, non-empty
}): AugmentationRequest
```

`reason` is mandatory — the form must not let a reviewer submit a rejection with an empty reason
field. The server validates this too (both in the schema and at the service layer), but a
client-side check gives the reviewer immediate feedback instead of a round-trip error.

## Response shape: `AugmentationRequest`

The fields a UI actually needs to render, in plain terms (the schema has the exhaustive list):

| Field | Meaning for the UI |
| --- | --- |
| `status` | See "Status values" below — drives which screen/message to show. |
| `requestedTier` | The rung being requested, e.g. `"b-30"`. Not usually shown raw to a user — pair with your own tier→dollar-amount display copy if you have one. |
| `requestedAmountMicros` | The dollar amount as a decimal string in **micro-USD** (divide by 1,000,000 for dollars). String, not a number — see "Why amounts are strings" below. |
| `approvedAmountMicros` | Set only once a grant happened (`auto_approved` / `partially_approved` / `approved`); same micro-USD string encoding. `null` otherwise. |
| `policyReasonCodes` | Machine-readable reason codes (e.g. `"within_unaided_allowance"`, `"unaided_allowance_exhausted"`, `"already_at_top_rung"`). Useful for debugging/support tooling; not designed to be shown to an end user verbatim — write your own copy per code, or fall back to a generic message for codes you don't have copy for yet. |
| `rejectionReason` | Present only when `status == "denied"` **and a human rejected it** (as opposed to a policy denial — see below). Always show this verbatim when present; see "Rejection reasons" below. |
| `grantId` | Present when a grant was actually issued. Not usually shown directly, but its presence/absence is a reliable way to tell "did this produce money" apart from `status` alone if you want a belt-and-suspenders check. |
| `createdAt` / `reviewedAt` | Timestamps for queue/history views. |

### Why amounts are strings

`requestedAmountMicros`/`approvedAmountMicros` are decimal strings, not numbers. This is
deliberate: the generated TypeScript client types the schema's `Int` as a plain JS `number`, which
silently loses precision above 2^53 — a real risk for a micro-USD integer. Parse them with a
big-number-safe method (`BigInt(...)`, or divide as a string-aware decimal) rather than
`Number(...)` if you need arbitrary precision; for display purposes at realistic budget amounts,
`Number(...) / 1_000_000` is fine in practice, but don't round-trip the raw string through `Number`
for anything that gets sent back to an API.

## Status values and what to show

| `status` | What happened | What the UI should say |
| --- | --- | --- |
| `auto_approved` | Granted immediately, in full. | "You've been granted $X." Pair with the token-refresh-delay note below. |
| `partially_approved` | Granted, but capped below the requested tier by policy. | Same as `auto_approved`, but the granted amount (`approvedAmountMicros`) may be less than what was requested (`requestedAmountMicros`) — show the actual granted amount, not the requested one. |
| `pending_review` | Queued for a human. Not denied, not granted yet. | "Your request is under review" — explicitly NOT "denied" and NOT "granted". Avoid implying a timeline the system doesn't promise (see #191: "admins will action the queue promptly enough... if not, that's a policy problem, not an engineering one" — don't paper over a slow queue with a UI promise). |
| `denied` | Refused — either by policy (e.g. already at the top rung) or by a human reviewer. | If `rejectionReason` is present, show it verbatim (a human rejected it). If not, this was a policy-level refusal (e.g. `policyReasonCodes` contains `"already_at_top_rung"`) — show a clear, specific message from your own reason-code copy table, not a generic "denied". |
| `approved` | A queued request was approved by a reviewer and granted. | Same messaging as `auto_approved`/`partially_approved` — from the end user's perspective these all mean "you got more budget," just via different paths. |
| `created` / `evaluating` | Transient states the RPC surface should never actually return to a caller (every procedure here only returns after evaluation/review has completed) — if you see one, treat it as unexpected and log it, don't build a screen for it. |
| `cancelled` / `expired` / `applied` | Not reachable through any of the four RPCs in this PR — reserved for later phases (queue expiry, the Phase 6a/6b gateway-apply step). No UI needed yet. |

## Two behaviors that will look like bugs and are not

Both are called out explicitly in #191 and must be **stated in the UI**, not just documented here.

### 1. A refill grants the full new tier, not a delta

Moving up a rung replaces the period's effective budget with the **new tier's full amount** — it
does not add to whatever was left. A user at $40-of-$50 who refills to the $100 rung has $100 for
the rest of the period, not $110 ($50 + $60 shortfall made up), and their prior $40 of spend this
period no longer counts against the new ceiling.

**UI implication:** show something like "You now have $100 for the rest of this period" — an
absolute statement — never a running total that implies addition. If you show spend-so-far
alongside the new ceiling, make clear the ceiling reset, not accumulated.

### 2. Today, a refill has no gateway effect at all — not "until the next token refresh," none

**Present-tense, as of this writing: a successful `requestBudgetRefill` changes the ledger and
nothing else.** A `grantId` on an `auto_approved`/`approved` response means the grant is
**recorded**, full stop. Nothing at the gateway reads the budget ledger — `requestBudgetRefill`
does not write `x-quota-tier`, does not touch `project_members.quota_tier` or
`projects.project_quota`, and no code path anywhere in this repo writes a budget-tier claim to
Keycloak (confirmed against `crates/lightbridge-authz-budget/src/refill.rs`,
`crates/lightbridge-authz-rest/src/lib.rs`'s `Procedures` impl, and
[`docs/governance-model-and-enforcement.md`](./governance-model-and-enforcement.md)'s "A second,
newer budget system exists and is not yet connected here" section, which states this in full: *"…
has zero effect on anything this document describes: it does not write `x-quota-tier` … and
nothing in §3's header pipeline reads from it."*). **There is no token-refresh delay to describe,
because there is no path from a grant to gateway enforcement at all yet** — describing this as "it
takes effect on your next token refresh" would be actively wrong: refreshing changes nothing, since
nothing downstream of the ledger is watching it.

**UI implication:** immediately after a successful refill, say so plainly and do not promise a
timeline for enforcement — e.g. "Granted. This increases your recorded budget; it does not change
what's enforced yet." Do not show a success state that implies the user can go spend the new amount
soon, on refresh or otherwise, and do not use language like "takes effect on your next login" —
that promises something the system does not do today and would itself generate the "it didn't
work" support ticket per #191's own risk callout, just delayed instead of immediate.

**Planned (not yet implemented) — for context, not for present-tense UI copy.** Connecting the
ledger to gateway enforcement is a two-phase, both-still-open plan:

- **Phase 6a** — re-key the enforcement `BackendTrafficPolicy` rules from the current per-plan
  rules onto the `x-budget-tier` ladder (ADR-0008). Runbook:
  [`docs/runbooks/budget-tier-rekey-cutover.md`](./runbooks/budget-tier-rekey-cutover.md).
- **Phase 6b** — write the granted tier back to Keycloak (a group attribute or similar) so it
  reaches a token's claims at all, which is the precondition for "takes effect on refresh" ever
  becoming true.

Full picture, including the "quick reference — what governs what" table showing the budget ledger's
row as not-yet-live:
[`docs/governance-model-and-enforcement.md`](./governance-model-and-enforcement.md).

## Rejection reasons must always be shown

Per #191's own implementation note: "a rejection without a visible reason turns into a support
conversation." Whenever `status == "denied"` and `rejectionReason` is non-null, surface it verbatim
to the user — don't summarize, don't truncate silently, don't hide it behind a "contact support"
link. If `rejectionReason` is null but `status == "denied"`, that's a policy-level refusal (see the
status table above) — use `policyReasonCodes` to pick an appropriate message instead.

## Paper trail

This RPC surface was built across a PR sequence in `lightbridge-authz` implementing Story #191
(epic #188):

- #213 — augmentation-request ledger and repository
- #214 — self-service refill orchestration (`RefillService`)
- #215 — admin review queue (`ReviewService`)
- the PR that added this doc — wires both into the RPC surface described above

If this doc doesn't answer a question you have, #191's own body (acceptance criteria,
implementation notes, the two "will look like bugs" behaviors) and the PRs above are the next place
to look — the Rust implementation and its doc comments (particularly
`crates/lightbridge-authz-budget/src/refill.rs` and `review.rs`) are the actual source of truth for
edge-case behavior this doc simplifies for a frontend audience.

## Known gap: no internal/API-key-client refusal yet

#191's acceptance criteria call for `requestBudgetRefill` to be refused for an internal/API-key
client ("refills are OIDC users only"). That refusal is **not implemented** as of this RPC surface
landing — see the PR description for the investigation and the tracking follow-up issue. This
doesn't change anything about how the UI should call these RPCs (a real end-user session token
works exactly as described above); it's called out here so nobody building against this contract
assumes that acceptance criterion is already enforced server-side.
