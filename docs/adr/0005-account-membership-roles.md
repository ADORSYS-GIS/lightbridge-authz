# ADR-0005: Account membership roles (owner/admin/member)

- Status: Accepted
- Superseded by: ADR-0006 (project membership replaces account-level membership and roles
  entirely, once the epic ai-helm#531 product vision was fully articulated)
- Date: 2026-07-22
- Decision owners: Lightbridge Authz maintainers

## Context

ADR-0002's "Data model direction" stated an intent — "Explicit membership roles such as `owner`,
`admin`, and `member`" — that was never implemented. Every `account_memberships` row was, until now,
undifferentiated: any member of an account could add/remove other members, suspend/resume the
account, and (before ADR-0003's cratestack migration) delete it outright. There was no way to add
someone with read-only or resource-management access without also giving them full membership-roster
and account-lifecycle control.

This sits on top of ADR-0003's cratestack CRUD migration and its RBAC gate (`docs/rbac.md`,
`crates/lightbridge-authz-rest/src/rpc_authorize.rs`) — that gate is global and JWT-role-driven
("may this caller attempt this *kind* of operation at all"), and account membership itself is binary
("is this caller a member of this account"). Neither expresses "within *this* account, what may
*this specific member* do."

## Decision

`account_memberships` gains a `role` column — `"owner"` | `"admin"` | `"member"`
(`migrations/20260722000001_account_membership_roles.sql`, DB `CHECK` constraint; backfilled by
promoting each account's earliest member, by `created_at`, to `"owner"` — matching
`createAccount`'s existing "creator is the sole initial member" behavior, so the natural creator
becomes the natural owner). `createAccount` now seeds the creator as `"owner"` explicitly going
forward.

Role gates only account-scoped membership-management and destructive operations —
`addAccountMember`, `removeAccountMember`, `setAccountMemberRole` (new), `disableAccount`/
`enableAccount`, `deleteAccountPermanently` (new, see below). Project and api-key
create/read/update/delete stay open to any member of the account, unchanged — this ADR does not
extend role-gating there.

Rules, enforced in hand-written SQL inside each procedure (see `docs/rbac.md`, "Account roles" for
the full table):

- `owner`/`admin` can add/remove members and disable/enable the account.
- Granting or revoking the `owner` role, removing another owner, and account-wide role changes
  (`setAccountMemberRole`) are `owner`-only.
- `deleteAccountPermanently` is `owner`-only.
- The account's last remaining `owner` can never be removed or demoted (checked before every
  `removeAccountMember`/`setAccountMemberRole` call) — an account can never end up with members but
  zero owners.

### Why this isn't an `@@allow` schema policy

cratestack's relation-quantifier policy predicates resolve each dotted path
(`account.memberships.some.subject`) to exactly one target scalar field per relation hop — confirmed
by reading `cratestack-macros/src/policy/model/relation_path.rs`, which tracks a single
`target_field`/`target_column` per resolved path with no support for a compound condition on the
*same* related row. `memberships.some.subject == auth().id && memberships.some.role == "owner"`
would compile to two independent `EXISTS` subqueries — "some member matches my subject" and,
separately, "some member (any member) has role owner" — not "the member row matching my subject also
has role owner." So role checks live entirely in hand-written SQL inside the five affected
procedures, the same pattern ADR-0003 already established for invariants generated CRUD can't
express (e.g. "cannot remove the last member").

### `deleteAccountPermanently` replaces `model.Account.delete`

Account deletion moved off the generic cratestack CRUD delete verb entirely, for the same reason:
role-gating (owner-only) can't be expressed as `@@allow`, so `Account`'s schema no longer declares
`@@allow("delete", ...)` at all, and `model.Account.delete` is denied unconditionally at both the
policy layer (no allow rule) and the RBAC layer (removed from `rpc_authorize.rs`'s map, defense in
depth, same pattern as `model.ApiKey.create`). A new `deleteAccountPermanently` procedure
(hand-written sqlx, owner-only) replaces it — MCP's pre-existing `delete-account` tool, which called
the generic client delete, was repointed to the new procedure rather than left silently broken (it
still compiled — the generic client method exists regardless of policy — but would have failed every
call at runtime once the `@@allow` was removed).

### Naming note

The new procedure is `deleteAccountPermanently`, not `deleteAccount`: cratestack's codegen always
emits a `handle_delete_<model_snake_case>` handler for a model's delete verb — `handle_delete_account`
— regardless of whether that verb has an `@@allow` rule (the routing/dispatch scaffolding exists,
even for a policy-denied verb). A procedure literally named `deleteAccount` collides with that
reserved identifier at compile time (`E0428: the name 'handle_delete_account' is defined multiple
times`) — confirmed by an actual compile, not inferred. Worth remembering for any future
procedure named `<verb><Model>` where `<verb>` is one of cratestack's own CRUD verbs.

## Consequences

### Positive

- Closes a real gap ADR-0002 identified and never implemented — accounts can now have genuinely
  read/resource-only members distinct from people who can manage the roster or delete the account.
- Two lockout-avoidance invariants (last owner can't be removed/demoted) prevent a real operational
  failure mode: an account with members but no one able to perform owner-only actions.
- `deleteAccountPermanently` closes a latent bug (the pre-existing `delete-account` MCP tool would
  have silently failed every call after ADR-0003's `Account.delete` policy removal, since it compiled
  fine but was policy-denied at runtime).

### Negative

- A fourth authorization axis (global RBAC, tenant membership, project scope, now account role) —
  more surface for a reviewer to reason about per operation. Documented exhaustively in
  `docs/rbac.md`'s "Account roles" table specifically to keep this legible.
- Role gating is entirely hand-written SQL, not schema-declarative like membership itself — a future
  role-gated operation has to remember to add its own check rather than getting it "for free" from an
  `@@allow` policy, since the DSL can't express it.
- Existing accounts predating this migration had their role assigned by backfill heuristic (earliest
  member = owner), not an explicit decision by anyone — correct for the common case (single-creator
  accounts) but worth a sanity pass if any account was ever created with multiple simultaneous initial
  members through a path other than `createAccount`.

## Alternatives considered

### Express role as an `@@allow` policy predicate

Rejected — not expressible in cratestack-pg 0.4.13's policy DSL (see "Why this isn't an `@@allow`
schema policy" above); confirmed by reading the actual resolver, not assumed.

### Extend role-gating to project/api-key operations too

Rejected for this pass. Scoped tightly to account-level membership-management and destructive
operations, which is what was asked for and what ADR-0002 originally called out. Project/api-key
role-gating (e.g. "only admins can rotate keys") is a distinct, larger product decision, not bundled
in here.

### Keep `deleteAccount` as the procedure name, rename the model verb instead

Not possible — the colliding identifier is generated by cratestack for the model's delete verb
regardless of the procedure name; renaming the *procedure* was the only side under this codebase's
control.
