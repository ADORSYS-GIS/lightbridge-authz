# ADR 0001: Resolve tenant context by subject + project, drop the single-use `request_id`

- Status: Accepted
- Date: 2026-07-07
- Supersedes: the Identity Request Service shipped in #65 (mint + single-use `request_id` + `identity_requests` table)

## Context

The `lightbridge-keycloak-spi` adapter seals `account_id`/`project_id` into issued JWTs. The first
implementation (#65) did this with an opaque, single-use `request_id`: a client minted one
(`POST /api/v1/idp/requests`, bearer-auth, bound to the caller's subject and a project), and the
Keycloak token-exchange provider relayed it to `POST /idp/v1/resolve-context`, which consumed it
(single-use + TTL + subject enforcement) and returned the context.

The only thing this bought was carrying a project selection, already authorized against membership,
across the Keycloak trust boundary. But the subject is **already** present in the exchanged token —
Keycloak authenticated it. So `request_id` was re-supplying an identity Keycloak already had, at the
cost of a stateful table, a mint endpoint, single-use/TTL/consume logic, and an extra round-trip.

## Decision

Resolve context **statelessly** from the two facts already available at token-exchange time: the
authenticated `subject` and a `project_id` the client names as a form param on the exchange.

- `POST /idp/v1/resolve-context` takes `{subject, project_id}` and returns `{account_id, project_id}`,
  authorized by the existing `account_memberships` CTE. A non-member or unknown project is a uniform
  `404`. It is idempotent.
- The endpoint moves **behind Basic auth** (the OPA/validation server's existing credentials). Under
  #65 an unauthenticated endpoint was safe because `request_id` was an unguessable single-use secret;
  `(subject, project_id)` is enumerable, so the endpoint must authenticate its caller.
- Removed: the `identity_requests` table (drop migration), the mint endpoint + controller, the
  `create_identity_request`/`consume_identity_request` repo methods, and the single-use/TTL DTOs.
- The SPI keeps its token-exchange provider and dumb protocol mapper; it now reads a `project_id`
  form param instead of `request_id` (see the SPI repo's corresponding ADR).

## Consequences

- Far less code and no per-issuance database write; one membership-authorized `SELECT`.
- Fail-closed is preserved: the token-exchange provider rejects the exchange when resolution returns
  `404`, so a token is never issued with missing context.
- The `resolve_context(subject, project_id)` repo primitive is reusable in-process — e.g. when the
  CRUD surface later gains claim/`project:manage`-based authorization.
- Trade-off: this reverts most of #65. Acceptable because nothing external was pinned to the
  `request_id` contract yet. IdP-agnostic opacity (any IdP relaying an opaque handle) is given up in
  favour of a plain `resolve(subject, project)` call — acceptable while Keycloak is the only IdP.
