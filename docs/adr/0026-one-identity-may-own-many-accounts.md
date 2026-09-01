# ADR-0026: one identity may own many accounts — ownership moves to `users`, `auth().id` stays put

- Status: Proposed
- Date: 2026-08-30
- Decision owners: Stephane Segning Lambou
- Implements: ADR-0025 Stage 5 (`createAccount` mints a CUID2) — the "requires its own RFC-weight
  review" gate that stage carries
- Amends: ADR-0006 ("a person's defining identity is their `accountId`"; "one account = one
  person") — already amended once by ADR-0024, finished here
- Amends: ADR-0024 Q1's compatibility line ("`createAccount` still inserts `id = subject`,
  untouched"). Does NOT complete its Follow-up 1 (`user_id` as a JWT claim) — see D2 for why
  that turned out to be unnecessary
- Source of truth: https://github.com/ADORSYS-GIS/lightbridge-authz/issues/563
  (console revamp epic: https://github.com/ADORSYS-GIS/converse-frontends/issues/368)

## Context

The console's workspace switcher and self-service flows are shaped for a person who holds more
than one account. The schema makes a second account structurally impossible, in one line —
`crates/lightbridge-authz-api-key/src/repo.rs:399-433`:

```rust
let new_account = NewAccountRow { id: subject.to_string(), .. };
// INSERT INTO accounts (id, ..) -> 23505 -> Error::Conflict("account already exists for subject")
```

`accounts.id` **is** the caller's subject (ADR-0006), so "create a second account" and "create a
second account with the same primary key" are the same statement.

### What is already built, and what #563 actually needs

Issue #563 describes the pre-ADR-0025 world ("there is no subject→accounts relation at all").
That is no longer accurate, and the difference matters because it shrinks this change
considerably:

- **ADR-0024** added `users`, `federated_identities`, and `accounts.user_id NOT NULL REFERENCES
  users(id)` — an ownership edge that is *already* one-user-to-many-accounts capable (a plain FK,
  a non-unique index `idx_accounts_user_id`).
- **ADR-0025 Stages 1-3** added the one-seam translation `(issuer, sub) -> account_id`
  (`StoreRepo::resolve_account_for_federated_subject`) and the `AccountId` newtype. Every
  repository method below that seam already takes an account id, never a raw subject
  (`repo.rs:1179-1181`). **`auth().id` is therefore already an account id, not a raw `sub`** —
  the `account.id == auth().id` policies are correctly typed today, not broken.

So the three real blockers are narrow:

1. `create_account` writes `id = subject` (above).
2. The `accounts_set_user` `BEFORE INSERT` trigger forces `NEW.user_id := NEW.id`
   (`migrations/20260825000001_users_and_federated_identities.sql:58-68`), so the 1:N edge exists
   but always has exactly one row on the N side.
3. Every ownership `@@allow` and every "list/lookup mine" query is keyed on the account id rather
   than the owner.

## Decision

### D1 — Ownership is `accounts.user_id -> users.id`. No new subject-shaped column.

The obvious-looking alternative — `accounts.owner_subject TEXT`, backfilled `= id` — is
**rejected**. It re-stores a raw IdP subject as an authorization key, which is (a) issuer-blind,
so two issuers minting the same `sub` collide exactly the way ADR-0024 exists to prevent, and (b)
the precise construction `lightbridge_authz_core::identity::AccountId`'s own doc bans ("Never
construct one from a raw bearer `sub` claim"). It would also duplicate what
`federated_identities (issuer, subject)` already stores authoritatively, forcing a "which one
wins" rule, and ADR-0025 Stage 5 would have to delete it again.

`accounts.user_id` already exists, is already `NOT NULL`, already indexed, already FK'd, and needs
no backfill (`20260825000001:43-47` already ran `users.id := accounts.id` for every row). The
change is to stop the trigger forcing `user_id = id` and start writing the *caller's* user id.

### D2 — `auth().id` does not move, and it needs no companion field

`auth().id` remains the **acting account** — the account ADR-0025's seam resolves the presented
identity to. Ownership policies re-key from the account's own id onto its owner column:

| clause | before | after |
|---|---|---|
| `Account` read | `id == auth().id` | `userId == auth().id` |
| `Project` create/read/update/delete | `account.id == auth().id` | `account.userId == auth().id` |
| `ApiKey` read/update/delete | `project.account.id == auth().id` | `project.account.userId == auth().id` |
| roster membership | `members.some.accountId == auth().id` | **unchanged** — see D5 |

Comparing an owner column against an *account*-shaped auth field is sound because of one property,
which D4 exists to preserve and which a test pins:

> **`accounts.user_id` is always the owner's HOME-account id — always a value `auth().id` can equal.**

A person's home account (the one `federated_identities` adopted, the only id `auth().id` is ever
set to) always satisfies `user_id == id`; a second account inherits that same `user_id`. So
"accounts whose owner is me" and "accounts whose `user_id` equals my acting account id" are the
same set.

An earlier draft of this ADR added an `auth().userId` field carrying the person separately, fed by
a new `user_id` access-token claim (completing ADR-0024 Follow-up 1). **Rejected as built and
removed before landing**: the value it would carry is provably always equal to `auth().id`, so it
was a second name for an existing field, plus a token-claim migration, plus a compatibility
fallback for tokens minted before it existed — none of which buys a distinction the data can
actually express today. The cost of the simpler choice is that the invariant above becomes
load-bearing rather than incidental, which is paid down by stating it at every site that depends
on it (`Account.userId`'s schema comment, `create_account`'s doc comment, the migration header)
and by `accounts_user_id_is_always_a_home_account_id` failing loudly if it ever stops holding.

If a future change genuinely separates the two — re-keying `users.id` to a minted id, or letting a
person act as an account that is not their home account (D7) — reinstating `auth().userId` is the
correct move, and the invariant test is what will force that conversation instead of letting the
policies silently match nothing.

`Account` gains `userId String @readonly` — a plain **scalar**, not a relation. ADR-0024's measured
cratestack codegen blowup (~51 GB, 36 min, CI-killed) was specifically a second *relation* path
between already-connected models; a scalar carries none of that risk, and `Project.account.userId`
traverses only the one relation that already exists.

### D3 — Which account gets which kind of id, and why the anchor keeps the subject

ADR-0025 Stage 5 specified that `createAccount` stops inserting the subject and mints a CUID2,
"with the creating subject's `federated_identities` row pointing at it from the start." Building it
that way surfaced a problem Stage 5's sketch did not account for, so this ADR refines it:

- **An identity's FIRST account keeps `id = subject`.** That account is the identity's **anchor**.
  `federated_identities` adopts an account by matching `accounts.id == subject`
  (`resolve_account_for_federated_subject_detailed`), so minting a CUID2 here would break adoption
  for every brand-new signup: the grandfather lookup finds nothing, the resolver falls through to
  ADR-0025's `NoAccount` bootstrap arm forever, and the person's own account is invisible to them.
  Stage 5's answer was to have `createAccount` write the adoption row itself — but that requires
  the issuer, which the procedure does not have, and it would make a *second* account able to adopt
  the identity, which D6 forbids.
- **Every subsequent account gets a minted CUID2** (ADR-0039, via the one chokepoint) and inherits
  the owner's existing `user_id`. It anchors no identity; it is a pure owned tenant.

The rule generalises cleanly: **an account that anchors an identity is keyed by that identity's
subject; an account that anchors nothing gets a house-format minted id.** Two id populations
coexist, exactly as Stage 5 predicted — and per AGENTS.md's id-opacity rule nothing may branch on
which population an id belongs to.

A second `createAccount` call is now an ordinary success. `Error::Conflict` survives for exactly
one case: two concurrent bootstraps racing for the same anchor id.

This deliberately does NOT cross Stage 5's "point of no return" for the federation machinery.
ADR-0025's grandfather branch and `NoAccount` bootstrap fallback keep working unchanged, and their
deletion condition is unchanged too (the ADR-0025 residue query reaching zero) rather than being
tied to this ADR shipping.

### D4 — Deleting the anchor while other accounts are owned is refused

`deleteAccountPermanently` widens from "the target must BE me" to "the target must be owned by the
same person as me", like every other account verb. One case has to be refused rather than widened:
deleting the **anchor** while the owner still holds other accounts would cascade away the
`federated_identities` row, so the next login resolves through the bootstrap fallback to a subject
with no `accounts` row, `user_id = (SELECT user_id FROM accounts WHERE id = $subject)` yields
`NULL`, and every surviving account matches nothing — permanently unreachable, with its projects
and keys still live.

Refused explicitly with `BadRequest`, not by letting the `WHERE` clause fail to match: a
non-matching predicate surfaces as `NotFound`, which reads as "that account does not exist" and
tells the owner nothing about what to do. Deleting the anchor when it is the *only* account is
untouched, pre-ADR-0026 behaviour.

### D5 — Membership stays account-keyed, and the roster is guarded instead

`project_members.account_id REFERENCES accounts(id)` — *"a project member IS an account"*
(`20260727000001:7-9`). #563 asks for this to be reviewed. The review's conclusion is: **do not
change it in this pass, and close the footgun it opens.**

Widening the policy to "any account I own" would need `members.some.account.userId ==
auth().userId` — a `ProjectMember -> Account` relation, which is the exact second-relation-path
codegen blowup ADR-0024 documented and `ProjectMember.account` was removed for. That route is
closed. The alternative (denormalising `user_id` onto `project_members`) is a real option but
needs its own pass.

Leaving it alone is safe today only because a person has one account. After D3 it is not: if a
lead adds a member's *non-home* account to a roster, that member — acting as their home account —
silently gets no access. So `addProjectMember` gains a guard: **the target account must be a home
account** (one with an adopting `federated_identities` row). Rosters can then only ever name the
account `auth().id` will actually be, and `members.some.accountId == auth().id` stays exactly
correct.

### D6 — `federated_identities_account_uidx` stays. One identity still adopts one home account.

The unique index making at most one federated identity adopt a given account
(`20260825000001:108`) is **untouched**. Dropping it — the obvious way to let one login "own" many
accounts through the federation table — would remove the structural guarantee that a second issuer
presenting a colliding `sub` cannot silently merge onto an existing account. That is a
cross-tenant merge: the security bug ADR-0024 was written to close, and its `Error::Conflict`
depends on that `23505`.

Ownership does not need it. A person's *home* account (the one their login adopts, the one that
becomes `auth().id`) stays 1:1 with their identity; the accounts they *own* are the 1:N dimension,
carried by `user_id`. These are different relations and this ADR keeps them apart deliberately.

### D7 — Ownership widens across the whole hand-written procedure surface, not just the policies

The cratestack `@@allow` clauses only govern the generic `model.*` verbs. Every hand-written
procedure in `repo.rs` carried its own ownership check, and each was written as
`projects.account_id = <acting account>` — which silently means "the project's account IS me".
Left alone, an owner would get `NotFound` on a project inside their own second account from
`createApiKey`, `updateProject`, `listApiKeys`, `addProjectMember`, `setProjectQuota` and the rest,
while the model verbs happily returned it. Half-widened is worse than either end state, so all of
them move together: 16 SQL owner-branches plus `authorize_project_lead` and `create_project`'s
`account_auth` CTE now compare by OWNER (`accounts.user_id`) instead of by account identity.

Two things deliberately did NOT move:

- **The member branch** (`pm.account_id = <acting account>`) still compares the acting account
  directly, per D5 — a roster may only ever name an anchor account.
- **`find_default_project_id`** still resolves against `auth().id`, i.e. the anchor's default
  project. "My default project" has to mean one thing, and the anchor is the only non-arbitrary
  choice.

`resolve_context` widened along with the rest, which means a second account's projects ARE mintable
as human-plane token context. An earlier draft of this ADR held it back over the budget domain:
`budget_tier` is resolved from `context.account_id` (the project's owning account) while
`getMyBudgetBalance` / `budget:read-own` / self-service refill key on `auth().id` (the anchor), so
a person could top up one budget and spend another. That reasoning was wrong to single out here —
**the divergence already exists and is already accepted**: any project MEMBER working on someone
else's project has exactly this split today, and ADR-0008/ADR-0014 describe it as intended
(`budget_tier` is the project tenant's budget; `budget:read-own` is your own). Widening ownership
introduces no new shape, only a new way to reach an existing one.

### D8 — "Which account am I acting as" is still out of scope

`auth().id` is the anchor account, always. This ADR adds no account switcher: no grant gains an
`account_id` parameter, `sessions` and `exchange_refresh_tokens` are untouched, and the budget
domain keeps keying on `auth().id` exactly as ADR-0008 describes.

What a second account IS after this ADR: a fully owned tenant whose projects and API keys the owner
creates, reads, updates and deletes, whose projects can carry a token context, and whose API keys
work on the data plane (`authz-opa` introspection resolves key → project → account without
consulting `auth().id` at all).

What it is not: an identity. The person's `sub`, their sessions, their self-service budget and their
roster memberships all remain anchored to the first account. Making the *acting* account
selectable — the console's workspace switcher — is the follow-up, and it is where the budget
re-keying question has to be settled rather than dodged.

## Mechanics, verified against cratestack 0.8.12

Read from the crate sources, not inferred. Recorded here because each one is a way this change
could silently compile into something that never matches.

- **The pin is `=0.8.12`.** AGENTS.md's Persistence section still says `=0.8.0`; that is stale, and
  every capability below was checked against 0.8.12.
- **`auth()` is schema-declared, not hard-coded.** `auth Principal { ... }` (`authz.cstack`) is
  parsed into an auth block and `auth().X` resolves by exact field-name match, so ADDING a field is
  a one-line schema edit plus one `fields.push` in `auth_provider::build_context` (shared by the
  RPC and MCP surfaces, so there is no second ingress that could leave it unset). This is what made
  the rejected `auth().userId` cheap to build — and cheap to remove again once D2 established it
  carried no information `auth().id` did not.
- **Relation traversal ends on a scalar, at unbounded depth**, and each hop's `@relation` must be
  exactly one local field to one reference. `account.userId` (one hop, ends on a scalar) is valid;
  `ApiKey`'s existing `project.account.id` already proves two.
- **Types must match exactly** on any relation-form comparison — hence `Account.userId` is
  declared `String` (required), matching `auth().id`. (For the *plain scalar* form the type check only
  runs when negated, so a mismatched type would compile and silently never match; not a risk here,
  but the reason the types are stated explicitly rather than left to inference.)
- **Create policies evaluate against the submitted input row.** A relation predicate on `create`
  first requires the parent column to be present in the create input, else it returns `false`
  outright. So `Project.accountId` MUST stay a plain settable field — marking it `@readonly` or
  `@default(...)` would turn `@@allow("create", account.userId == auth().userId)` into deny-all,
  silently. This is a standing constraint on `Project`, not something this ADR changes.
- **`@readonly` does keep a field out of the generated create input** (contradicting the in-file
  comment at `authz.cstack:229-234`, which is wrong about the Rust type — a client may still *send*
  the key and have it silently ignored, which is the behaviour that comment recorded empirically).
  Safe for `Account.userId` specifically because `Account` has no generic create verb at all —
  `createAccount` is a procedure with hand-written SQL. A required `@readonly` column on a model
  that DID have a generic create would break every insert with a NOT NULL violation unless it also
  carried a DB default or trigger.
- **Read policies filter; they do not reject.** `@@allow("read", ...)` lowers into the SQL `WHERE`
  clause, so widening it changes which rows come back, never the status code. `create`/`update`/
  `delete` and every procedure hard-gate instead.
- **The gated clause suffix is generated, never hand-typed.** Edit only the base expression, then
  run `UPDATE_SCHEMA_POLICIES=1 cargo test -p lightbridge-authz-rest --test schema_policy_sync_tests`
  to re-append `&& auth().rpcScope == ... && auth().perm... == true`, and keep every clause on one
  line with the base expression parenthesized.
- **Nothing is generated to disk.** `cratestack::include_server_schema!` is a proc macro
  (`crates/lightbridge-authz-api/src/lib.rs:27`); there is no `build.rs` and no committed
  `generated/`. A policy the generator cannot compile is a `rustc` error, not a runtime surprise.

## Consequences

- **ADR-0006's "one account = one person" is now fully retired.** ADR-0024 replaced the identity
  half (`users.id` is the person); this ADR retires the cardinality half. What survives: there is
  still no account-*level* membership, and the project-membership/billing/quota apparatus is
  untouched.
- **Two `accounts.id` populations coexist permanently** (stored subjects, minted CUID2s). This is
  ADR-0025 Stage 5's named consequence, accepted here. Stage 6 (re-keying grandfathered ids) stays
  unbuilt and may never happen.
- **ADR-0025's `NoAccount` bootstrap fallback does NOT close yet.** Stage 5's deletion condition
  said `createAccount` would write its own adopting `federated_identities` row, closing the window.
  That is deliberately not done here: writing an adoption row from `createAccount` would let a
  *second* account adopt the identity, which D6 forbids. The fallback and the grandfather branch
  stay, and their deletion condition is restated as: the ADR-0025 residue query reaching zero.
- **A person with no account still cannot bootstrap except through `createAccount`** — unchanged.
- Nothing in the wire format changes on the day this ships (D2).

## Alternatives considered

### `accounts.owner_subject TEXT`, backfilled from `id`

Rejected — see D1. Cheapest migration, but stores a raw subject as an authorization key,
issuer-blind, duplicates `federated_identities`, and Stage 5 would delete it again.

### Make `auth().id` the person (`users.id`) rather than adding `auth().userId`

Rejected. It is superficially tidier — one identity field instead of two — and is also
wire-invariant today. But `auth().id` feeds `sessions.subject`, `budget_account_id`,
`revoke_sessions_and_cascade`, and the minted `sub`; redefining it from "account" to "person"
changes the meaning of all four at once, in a change whose blast radius is already large. Keeping
`auth().id` fixed and adding a field confines the semantic change to the clauses that actually
express ownership.

### Drop `federated_identities_account_uidx` and let the federation table carry multi-account

Rejected — see D6. Trades a structural cross-tenant-merge guarantee for a relation `user_id`
already provides.

## Postscript (2026-08-30): the migration was renumbered after merge

`migrations/20260830000001_accounts_owned_by_users.sql` is now
`migrations/20260830000003_accounts_owned_by_users.sql`. #568 renamed it as a pure `git mv`, so the
file itself carries no record of why — and it must stay that way, which is the point of putting
this here instead.

**What happened.** #565 landed the same day carrying its own `20260830000001`
(`federated_identities_add_profile_claims`). SQLx keys `_sqlx_migrations` by the numeric VERSION,
not the filename, so two files sharing a prefix collide on that table's primary key: the second to
apply fails `23505` and aborts the entire migration run. Locally that is every `sqlx::test` in the
workspace dying at setup; in a deployment it is `authz-migrate` failing at startup, so nothing comes
up at all. `main` went red at `8625902`.

**Neither PR's CI could have caught it.** Each branch contained only its own migration, so the
collision existed solely in the merge result — #564 and #565 were both green individually.

**Which file moved, and why that is not arbitrary.** Production had ALREADY recorded
`20260830000001` as #565's migration. A version some environment has durably applied cannot be
reassigned: `_sqlx_migrations` is the record of what actually ran there, and rewriting a live row's
meaning leaves a database silently disagreeing with its own schema. THIS migration had never been
applied anywhere durable, so it was the one that could safely move. Renumbering is legitimate only
under exactly that condition — the same bar ADR-0006 records for its own `20260724` -> `20260727`
renumber, where none of the four had ever reached `main`. When both sides have been applied,
renumbering is off the table and the answer is a new forward migration.

**Why this text is here and not in the migration.** SQLx stores a checksum of each migration's
BYTES and validates it on every run, so editing an applied migration — even to add a comment —
aborts the next migrate with a version mismatch. Drafting this as a header comment on the `.sql`
was rejected for exactly that reason: the safety of such an edit depends on no environment having
applied the file yet, which is a property that can lapse between opening a PR and merging it (the
7.0.0 release PR was open at the time). A migration's bytes are frozen the moment they ship;
its reasoning belongs somewhere that can still be corrected.

The reusable form of all of this — the pre-flight check and the two rules — is in AGENTS.md's
Migrations section.

## Related

- ADR-0006 (amended — the cardinality half retired here)
- ADR-0024 (the `users`/`federated_identities` model this builds on; its Follow-up 1 is NOT
  completed here — D2 records why it proved unnecessary)
- ADR-0025 (Stage 5 implemented here; the wire-invariance property D2 preserves)
- ADR-0038 (cratestack is the only sanctioned database API — `accounts` DDL stays hand-written
  per ADR-0003's own reversal)
- ADR-0039 (CUID2 is the house id format — D4's minted id)

## Follow-ups (not built here)

- Account switching: which account a session/token acts as (D7), and the console workspace
  switcher that consumes it.
- Re-keying the budget domain off a single `budget_account_id` (D7).
- Roster membership by person rather than by account (D5) — needs `project_members.user_id` or a
  cratestack relation that does not blow codegen up.
- Deleting ADR-0025's grandfather branch + `NoAccount` fallback once the residue query is zero.
