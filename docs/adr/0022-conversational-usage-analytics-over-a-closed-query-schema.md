# ADR-0022: Conversational usage analytics via function-calling over the existing, closed usage query schema

- Status: Proposed
- Date: 2026-08-23
- Decision owners: Stephane Segning Lambou

## Context

The owner wants a "chat with your data" experience for lightbridge's usage analytics — comparable
to Midday's assistant — where a user asks a question in natural language (*"what did project X
spend on gpt-4 last week?"*), the system understands the usage data, answers, and can potentially
**generate a dashboard on the fly** rather than only rendering one of a fixed set of charts. This
is a **blocking design document**: it decides the backend contract and the now-settled stack
(assistant-ui + eve), not the implementation code, and (per the questions left open below) not the
full picture either — the specific provider/gateway eve points at, and the chat surface's placement
inside `converse-frontends`, are explicitly out of scope here.

### The reflex implementation, and why it is wrong here

The obvious approach is text-to-SQL: let the model write a query against `usage_events` directly.
That is a real, well-known engineering problem — the moment a model can emit arbitrary SQL, the
task becomes "build and maintain a query sandbox" (statement allowlisting, resource limits,
injection defense, a permissions layer reimplemented at the SQL-string level). None of that is
needed here, because **the usage query surface this repo already has is not a free-text query
interface — it is a closed, typed parameter space**, verified below. The model does not write a
query; it fills a struct whose every field is either enum-constrained or already parameter-bound.
That is the load-bearing fact this whole ADR rests on, so it is verified first, in detail, rather
than asserted.

### Verified current state (against `origin/main`, not this worktree)

> **Update (2026-08-31):** `UsageScope` below has since grown a 5th variant, `All`
> (estate-wide, no entity filter, gated on the `usage:read-all` permission rather than
> an ownership predicate) — the closed-schema property this section verifies is
> unaffected by that addition (still enum-constrained, no free-text field). See
> `crates/lightbridge-authz-usage/src/models/mod.rs` and `docs/lightbridge-query-api.md`
> for the current shape; the bullet below is left as originally verified.

**The usage query API itself:**

- `UsageQueryRequest` (`crates/lightbridge-authz-usage/src/models/mod.rs:15-28`) has exactly eight
  fields: `scope` (a 4-value `UsageScope` enum — `User`/`ApiKey`/`Project`/`Account`, lines 30-36),
  `scope_id: String`, `start_time`/`end_time: DateTime<Utc>`, `bucket: String` (the one free-form
  field, defaulted via `default_bucket` to `"1 hour"`), `filters: UsageQueryFilters` (eight
  `Option<String>` fields — `account_id`, `project_id`, `api_key_id`, `user_id`, `user_name`,
  `model`, `metric_name`, `signal_type`, lines 54-63), `group_by: Vec<UsageGroupBy>` (an 8-value
  enum — `AccountId`/`ProjectId`/`ApiKeyId`/`UserId`/`UserName`/`Model`/`MetricName`/`SignalType`,
  lines 39-49), and `limit: u32`. There is no field anywhere in this struct that accepts a raw
  query fragment, a column name, or an operator.
- `bucket` is the only field not already enum- or bind-parameter-constrained, and it is
  double-gated. First, **regex validation**: `validate_bucket_interval`
  (`crates/lightbridge-authz-usage/src/repo.rs:321-329`) rejects any value that doesn't match
  `^\d+\s+(second|seconds|minute|minutes|hour|hours|day|days)$` (`repo.rs:322-324`) before the
  query is even built (`repo.rs:136`, the first line of `query_usage`) — confirmed by its own test
  cases (`repo.rs:349-352`) rejecting `"hour"`, `"1month"`, and `"1 week"`. Second, even after
  passing that regex, the value is never string-interpolated into SQL: it is bound as a parameter
  via `sqlx::QueryBuilder::push_bind` (`repo.rs:144`, `builder.push_bind(&input.bucket)`, cast with
  `CAST($1 AS interval)`) exactly like every other value in the query (`start_time`/`end_time` at
  `repo.rs:214,216`; `scope_id` at `repo.rs:221-233` depending on `scope`; each filter at
  `repo.rs:239-267`; `limit` at `repo.rs:277`). `group_by` selects which of eight fixed,
  hard-coded column names (`repo.rs:148-198`, `append_dimension`, `repo.rs:304-318`) appear in the
  `GROUP BY` clause — the model can choose *which* of eight known columns to group on, never
  supply an arbitrary one.
- So: a model filling this struct can misjudge *which* scope, filter, or grouping answers the
  user's question — it cannot construct a query shape the API wasn't already built to run, and it
  cannot inject SQL through any field, including the one free-form string.

**What does not exist yet, in this repo:**

- **No usage-query tool on `lightbridge-mcp` today.** `lightbridge-mcp`
  (`app/lightbridge-authz/src/mcp.rs`) exposes 20+ tools over the authz CRUD/RPC surface —
  accounts, projects, roster, API keys, validation — gated centrally in `call_tool`
  (`mcp.rs:207-224`: derive `TokenInfo` from the request context, `require(required)` the tool's
  permission at `mcp.rs:217`, or refuse with `unknown tool` for anything not in
  `required_tool_permission`, `mcp.rs:396-428`). `grep -ni usage app/lightbridge-authz/src/mcp.rs`
  returns exactly three lines, none of them a tool. This confirms, correcting the task brief's "I
  believe" to a verified fact: **no usage tool exists on MCP today.**
- **No `usage:*` permission exists.** `Permission` (`crates/lightbridge-authz-core/src/authz.rs:28`
  onward) has no usage-domain variant — only `account:*`, `project:*`, `apikey:*`, `budget:*`,
  `session:*`.
- **No LLM client dependency exists anywhere in this workspace**, verified before the owner's stack
  update below: `grep -riE '\bllm\b|gpt|genai|chat.?completion|claude|openai|anthropic-sdk|
  async-openai|llm_client|rig-core|langchain'` against the root `Cargo.toml` and every crate/app
  manifest returns nothing.
- **The usage service's query listener requires and verifies a client certificate; the ingest
  listener does not.** `UsageServerGroup` (`crates/lightbridge-authz-usage/src/config.rs:15-31`):
  `usage` is the unauthenticated ingest listener; `query` is the mTLS-required listener carrying
  `/usage/v1/usage/query` and `/usage/v1/spend/query`, split onto its own port because "rustls
  integration enforces client-certificate verification at the listener level, not per-route"
  (`config.rs:22-31`). Enforcement lives in `build_mtls_config`
  (`crates/lightbridge-authz-core/src/server.rs:83-114`), whose own doc comment states the
  fail-closed contract directly: "a misconfigured trust anchor must refuse to start, never silently
  fall back to `with_no_client_auth`" (`server.rs:84-88`). The existing precedent for a caller of
  this listener is `authz-budget`'s `UsageServiceSpendReader`
  (`crates/lightbridge-authz-budget/src/spend.rs:166-211`), which presents a client identity from
  `client_cert_path`/`client_key_path` and fails every possible error mode to `Spend::Unavailable`,
  never to `Known(0)` or a fabricated answer (`spend.rs:186-209`).
- Redis-backed rate limiting already exists and is reusable: `cratestack_redis::
  RedisRateLimitStore` (re-exported and thinly wrapped in
  `crates/lightbridge-authz-rest/src/ratelimit_redis.rs`) implements the pluggable
  `RateLimitStore` trait `authz-api`'s rate-limiting middleware already runs against.
- **Deployment shape precedent.** This repo already splits services with the same underlying
  binary into their own Helm charts and CI image targets: `charts/lightbridge-authz-usage` and
  `charts/lightbridge-mcp` are each their own chart, distinct from `charts/lightbridge-authz`
  (the api/opa/idp/budget multi-subcommand chart). `.github/workflows/ci.yml`'s `container-build`
  job builds three separate images from one matrix (`runtime`, `mcp-runtime`, `usage-runtime`,
  `ci.yml:93-97`) — but every one of those three still shares the same upstream `binaries` job
  (`ci.yml:90`, `needs: [binaries]`) and the same `.github/actions/container-build` composite
  action, which unconditionally downloads a prebuilt `dist-binaries.tar.gz` artifact and builds
  `Dockerfile.dist` (`.github/actions/container-build/action.yml:55-64,74-92`). That composite is
  Rust-build-artifact-shaped by construction; cosign signing (`action.yml:122-130`) is the one
  piece genuinely reusable as-is for a non-Rust image.

**What does not exist yet, in `converse-frontends`:**

- **No `usage.ts` (or equivalent) hook.** Checked against that repo's `origin/main`:
  `packages/hooks/src/*.ts` has `accounts.ts`, `budget.ts`, `projects.ts`, `api-keys.ts`, `rbac.ts`,
  and others, but no usage-query hook. `converse-frontends` ADR-0008
  (`docs/adr/0008-console-shell-inversion-and-visual-direction.md`) states this explicitly: *"the
  usage surface is a Grafana link-out, not an in-app dashboard. No usage-query hook exists yet"*
  (line 26).
- **No chat surface exists.** `git grep -in chat` against `converse-frontends`' `origin/main` under
  `apps/` and `packages/` returns nothing.
- **Chart primitives for fixed dashboards exist, but are not wired to the usage API yet.**
  `converse-frontends` ADR-0008 Decision 7 commits to three dashboards ("Overview" nav group) over
  this same usage query API — spend-by-project-and-model, per-model latency distribution,
  budget/quota consumption — built on `react-native-svg` + `d3-scale`/`d3-shape` (Decision 9).
  `converse-frontends#202` ("feat(ui): add chart primitives for ADR-0008's three dashboards",
  merged 2026-08-23) landed `TimeSeriesChart`/`HistogramChart`/`RidgelineChart` plus
  `ChartAxis`/`ChartLegend`/`ChartTooltip` under `packages/ui/src/components/{time-series-chart,
  histogram-chart,ridgeline-chart,chart-axis,chart-legend,chart-tooltip,chart-core}/`, taking plain
  `values: number[]`/`points: {x,y}[]` data — the same shape `UsageQueryResponse.points[]` provides
  — but its own Scope section is explicit that wiring the usage API is "deliberately not touched."
- **The app is Expo + React Native Web, not Next.js.** `converse-frontends` ADR-0006
  (`docs/adr/0006-expo-ui-not-adopted-web.md`) states the app "is built with Expo + React Native but
  **ships as a pure web app** (React Native Web)." ADR-0007
  (`docs/adr/0007-console-visual-theme-system.md`) established a CVA + CSS-variable theming system
  (retained, re-pointed by ADR-0008). ADR-0008 committed to an Axiom-derived near-black palette,
  "monochrome-plus-signal-orange" accent rule (never decorative), and a floating-panel-over-floor
  shell (`docs/adr/0008-console-shell-inversion-and-visual-direction.md:114-157`, `converse-frontends`
  repo). This matters for the frontend-placement question below.

**assistant-ui and eve, verified against their live docs (2026-08-23):**

- **assistant-ui** is a React component library for AI chat, targeting three surfaces — "React"
  (web), "React Native" (iOS/Android), and "React Ink" (terminal) — sharing "Same primitives on
  web, native, and the terminal" (`assistant-ui.com/docs`). It lists first-party runtime adapters
  including Vercel AI SDK, LangGraph, Google ADK, AG-UI, A2A, OpenCode, and **Eve**
  (`assistant-ui.com/docs/runtimes/pick-a-runtime`). The Eve-specific integration is a real,
  documented package — `@assistant-ui/eve`, with a Next.js-specific wrapper `eve/next` —
  described as wrapping Eve's `useEveAgent`/`useEveAgentRuntime` hook and exposing it as an
  assistant-ui `ExternalStoreRuntime`, so "Eve owns the session stream while assistant-ui renders
  messages, reasoning, dynamic tool calls, and approval requests"
  (`assistant-ui.com/docs/runtimes/eve/overview` — note the correct path has an `/overview` suffix;
  the bare `/docs/runtimes/eve` URL 404s). **The only documented setup path wires through Next.js**
  (`withEve(withAui(nextConfig))`); nothing fetched shows a React-Native-specific integration path
  for this particular runtime adapter, distinct from assistant-ui's general RN support. This is a
  real, unresolved compatibility question for `converse-frontends` — see Decision 5 and the open
  questions.
- **eve** (`eve.dev`, Vercel's agent framework) is TypeScript/**Node.js 24+**, scaffolded via `npx
  eve@latest init`, with filesystem-based configuration under `agent/`: `tools/` (typed executable
  integrations), **`connections/`** ("External MCP and OpenAPI services" — "A connection wires an
  agent into an external server you don't author, either an MCP server ... or any HTTP API with an
  OpenAPI document"), `skills/`, `subagents/`, `channels/` (HTTP/messaging entry points), and
  `agent.ts` (runtime model/settings config). Connections are defined with
  `defineMcpClientConnection` (URL + description + optional `auth`/`headers`/`approval`); the model
  never sees a connection's URL or credentials and calls tools by qualified name,
  `<connection>__<tool>`.
- **eve's model configuration** defaults to routing through the Vercel AI Gateway
  (`AI_GATEWAY_API_KEY`/`VERCEL_OIDC_TOKEN`) but supports direct providers by installing "its AI SDK
  provider package and set[ting] the provider's API key" — plain environment variables, read from
  whatever `agent.ts` (plain TypeScript) is written to read.
- **eve is self-hostable, independent of Vercel.** `eve build` followed by `PORT=3000 eve start
  --host 0.0.0.0` "produces a standard Nitro Node server you can run anywhere (container, VM,
  behind your own proxy)" — a normal Node HTTP service, not a Vercel-only artifact.
- **eve's HTTP channel authentication fails closed by default**, independently of this repo's own
  convention: "production traffic is rejected unless you configure an authenticator that accepts
  it" (`eve.dev/docs/guides/auth-and-route-protection`). Available authenticators include
  `vercelOidc()`, `localDev()` (local-only), `httpBasic()`, `jwtHmac()`, `jwtEcdsa()`, `oidc()`,
  `none()` (explicit anonymous), and custom `AuthFn` implementations.
- **eve does carry a per-caller identity, correcting the task brief's working assumption that it
  might be single-user only.** Route auth's result is exposed inside the agent as
  `ctx.session.auth.current`/`ctx.session.auth.initiator`. Connections and tools can be
  `principalType: "user"` — keyed to "the authenticated user already attached to the eve
  session" — rather than `principalType: "app"` (one shared credential for every session, the
  default). The per-user path is documented concretely for eve's own OAuth broker (Vercel Connect,
  `auth: connect("linear/myagent")`) and for a plain custom credential lookup (`auth: { getToken:
  async () => ({ token: ... }) }`). **What is not confirmed by anything fetched**: whether a plain
  `getToken()` callback receives the current request's `ctx.session.auth.current` (so it could
  read back an already-validated, already-attached end-user JWT and hand it to `lightbridge-mcp`
  verbatim), or whether `principalType: "user"` is only wired up for the Vercel-Connect OAuth-broker
  path specifically. This is the crux integration question — see Decision 6.

## Decision

### 1. Function-calling over `UsageQueryRequest`, never text-to-SQL

The model is given `UsageQueryRequest`'s shape as a function/tool schema and asked to fill it in —
choose a `scope`, pick `group_by` dimensions, set `filters`, phrase a `bucket` string, set a time
range. It never sees a SQL dialect, a table name, or a column beyond the eight `group_by`/`filters`
identifiers already exposed as enum variants and struct fields. There is no generated SQL to
sandbox, because there is no generated SQL — every value the model can emit was already going to be
validated (`validate_bucket_interval`) or parameter-bound (`push_bind`) by the existing,
already-shipped, already-tested `query_usage` path (`repo.rs:131-303`). This ADR adds **zero** new
database surface. If this schema were not already closed this way, this decision would not hold and
text-to-SQL-with-a-sandbox would need to be revisited on its own merits (see "Alternatives
considered").

### 2. `scope`/`scope_id` is derived server-side and overwritten after the model responds — never read from the model's or the agent runtime's output

This is the decision that actually protects tenant isolation, and it is deliberately stronger than
"validate what the model proposed." Wherever the request finally lands — always inside
`lightbridge-mcp`'s Rust process, per Decision 6 below, regardless of what called it — the tool
handler that receives the filled-in `UsageQueryRequest` **discards whatever `scope`/`scope_id`
arrived in the arguments** and substitutes values derived from the caller's own JWT (`TokenInfo`,
resolved centrally at `mcp.rs:207-215`/`token_info_from_request_context`, `mcp.rs:431-445`) before
the request reaches `authz-usage` at all. This mirrors the existing pattern every other MCP tool
already uses — `create_account_tool` never takes a `subject` parameter; it calls
`subject_from_request_context` (`mcp.rs:387-391`) and passes that, not anything from `params`, to
`issuer.create_account` (`mcp.rs:848-865`).

The distinction matters because of what a bug in each version costs. "The model (or the agent
runtime relaying it) proposed a tenant and we checked it" is one comparison away from "the proposal
was checked and the check had a bug" — a validation defect there is a cross-tenant data leak,
silently, the first time it's wrong. "It never had a say" means the same bug class is structurally
unreachable: there is no branch where a wrong or adversarial `scope_id` reaches the query, because
the field sent to `authz-usage` never came from that untrusted input in the first place. This is
this repo's own standing rule (`AGENTS.md`, "Failure modes — does the unavailable branch become the
permissive branch?", `AGENTS.md:163`) applied to a new kind of caller — an LLM, and now a whole
TypeScript agent runtime relaying it, are exactly the "unavailable" case that rule already
anticipates: a component whose output cannot be trusted to be either correct or non-adversarial —
so its proposed scope is not "unknown, treated cautiously," it is **never consulted** at all.

### 3. Output is a declarative chart spec — a chart type plus a query spec — never generated code

"Generate dashboards on the fly" is satisfied by the model choosing *which* chart shape answers the
question (e.g. `{ "chart_type": "time_series", "query": <UsageQueryRequest, scope pre-overwritten>
}`) from the existing rendering vocabulary, not by emitting React/JS/any executable artifact. The
chart types available are exactly the primitives `converse-frontends#202` already built for
ADR-0008's three fixed dashboards — `TimeSeriesChart`, `HistogramChart`, `RidgelineChart` — which
already consume plain point data rather than a query result object, and which already implement
ADR-0008's monochrome-plus-accent chart colour rule. This ADR does not add a fourth chart type or a
code-generation path.

### 4. Numbers render from the query response, never from model prose

Any figure shown to the user — a dollar total, a token count, a request rate — comes from
`UsageQueryResponse.points[]` (`models/mod.rs:65-83`), rendered by the chart primitive or read
directly off the response object. The model's own text output is narration *about* the numbers,
never the arithmetic source of them.

### 5. The stack is decided: assistant-ui for the chat UI, eve as the agent runtime

The owner has decided this, not left it open: **assistant-ui** (`assistant-ui.com`) is the chat UI
component library, and **eve** (`eve.dev`) is the agent runtime. Verified above: these two are
designed to compose — assistant-ui ships a first-party `@assistant-ui/eve` runtime adapter — and
eve is a real, self-hostable Node.js 24+ service with filesystem-based config, not a Vercel-only
product. This settles *how* the model is invoked and *what* renders the chat, but explicitly not
*which* model/provider (Decision 9, still open) or *where in `converse-frontends`* the chat surface
lives (still open — see "Open questions").

### 6. eve consumes `lightbridge-mcp` as an MCP connection; authorization stays in Rust — but the per-user identity path through eve is not yet confirmed to exist

The clean design, and the one this ADR adopts: eve's usage-related tool calls are not a
direct HTTP client of `authz-usage`; they are a `connections/lightbridge.ts` entry
(`defineMcpClientConnection`) pointed at `lightbridge-mcp`'s `/mcp` endpoint, which the model
reaches through eve's `connection_search`/qualified-name mechanism (`lightbridge__query-usage`,
following eve's own naming convention). This keeps every authorization decision — the RBAC gate in
`call_tool` (`mcp.rs:207-224`), and Decision 2's scope-overwrite — inside Rust, where the rest of
this repo's auth boundary already lives, rather than asking eve's TypeScript to reimplement any of
it. This repo's own ADR-0021 (browser SSO) makes the same argument in spirit, even though the
mechanism there was different: that ADR's Alternatives-considered section rejected putting the RP
leg to Keycloak in a separate Next.js app specifically because it "splits the authentication
boundary across two runtimes and two languages," forcing this repo's review priority #1 to be
"independently re-verified in a second codebase this repo's own lint/test/`deny.toml` discipline
does not reach" (`docs/adr/0021-browser-sso-hosted-login-page-and-session-cookie.md`, Alternatives
considered). This design is actually a
stronger position than that comparison implies: eve is never asked to make an authorization
*decision* at all, only to relay a request and (per the open question below) a credential — every
decision remains in the one already-audited place.

**The crux, unresolved, integration question — stated plainly, not assumed away:** `lightbridge-mcp`
is bearer-JWT-gated, and Decision 2 depends on the request reaching it carrying the *actual
end-user's* identity, not a shared service identity — every question in this feature is asked by a
specific authenticated caller, and the answer must be scoped to that caller. eve does have a
real per-caller identity mechanism (`ctx.session.auth.current`, `principalType: "user"` connections,
a token cache keyed by issuer+principal id) — this is confirmed, and corrects the possibility that
eve might only support a single, app-wide identity. What is **not** confirmed by anything in eve's
published docs is whether a plain `getToken()` connection-auth callback can read back the *same*
JWT that authenticated the inbound chat request (`ctx.session.auth.current`) and hand it, unmodified,
to the `lightbridge-mcp` connection as its bearer token — versus the documented per-user path being
specific to eve's own OAuth broker (Vercel Connect), which would negotiate a *different* credential
than the lightbridge-issued JWT `lightbridge-mcp` actually validates. **This is a blocking unknown
for the design, not a detail to fill in later**: if plain end-user-JWT passthrough is not supported
the way described, the alternative is running an eve agent instance scoped to one user's request
(with that user's token pinned into its connection config for the request's lifetime) rather than a
long-lived shared agent process relaying arbitrary callers' tokens through a generic callback — a
materially different deployment shape. This must be proven with a working spike against real
`lightbridge-mcp`/eve instances before an implementation ticket can be written, not assumed from the
docs alone.

### 7. eve deploys as its own image and chart — a genuinely new kind of CI job, not a matrix entry

This repo already has precedent for splitting a component into its own chart even when it shares a
binary family: `charts/lightbridge-authz-usage` and `charts/lightbridge-mcp` are each already
separate from `charts/lightbridge-authz`. eve follows that same shape — its own chart, its own
image. But the cost is real and should be stated honestly, not glossed: unlike
`usage-runtime`/`mcp-runtime` (`ci.yml:93-97`), which are two more `--target`s of the same
`Dockerfile.dist` sharing the one `binaries` (`cargo build`) job and the one
`.github/actions/container-build` composite, **eve is Node.js, so it cannot share any of that** —
that composite action unconditionally downloads a prebuilt `dist-binaries.tar.gz` artifact and
builds `Dockerfile.dist` (`.github/actions/container-build/action.yml:55-64,74-92`), both
Rust-build-artifact-shaped by construction. An eve image needs its own build job (checkout, `npm
install`/`eve build`, its own Dockerfile) — closer to introducing a second application into this
repo's CI than extending the existing one. The one piece of existing infrastructure that *is*
reusable as-is is cosign signing (`action.yml:122-130`), which signs whatever image reference it's
given regardless of how the image was built. ArgoCD/`argocd-image-updater` wiring for a new image is
not verified here — it lives in the separate GitOps repo this repo's own deploy docs point at, and
was not fetched for this ADR.

### 8. The usage-listener mTLS client identity is held by `lightbridge-mcp` (or a Rust component fronting it), never by eve

Because Decision 6 routes usage queries through `lightbridge-mcp` rather than having eve call
`authz-usage` directly, eve never needs to hold a client certificate for `authz-usage`'s mTLS query
listener — `lightbridge-mcp` does, following the exact pattern `authz-budget`'s
`UsageServiceSpendReader` already established (`client_cert_path`/`client_key_path`,
`spend.rs:166-211`). This is a direct, positive consequence of Decision 6: it is not merely that
authorization stays in Rust, but that the one piece of infrastructure a browser (or a Node.js
process without a CA-signed identity) structurally cannot present — an mTLS client cert — never has
to leave Rust's custody either.

### 9. Model provider/credentials are environment-configured, never hardcoded

The owner's requirement — "the model must be configurable, not hardcoded, not compiled in" — is
satisfied by eve's own model-configuration mechanism, which already reads provider selection and
credentials from environment variables (`AI_GATEWAY_API_KEY`/`VERCEL_OIDC_TOKEN` for the default
Vercel AI Gateway path, or a provider-specific API-key variable for a direct AI-SDK provider) rather
than a value baked into `agent.ts` at build time. This composes directly with how this repo already
handles prod configuration: `config/default.yaml` is wholly replaced by `ai-helm-values` in
production (see AGENTS.md, "Configuration"), and the loader's `${VAR:-default}` interpolation is the
established pattern for "a value that must differ per environment." The eve chart's deployment
values — not a checked-in file — are the thing that must carry the actual provider/model choice, the
same way every other per-environment secret in this estate already works. This ADR does not attempt
to specify or edit `ai-helm-values` itself; that is implementation-ticket work.

### 10. Prompt injection through the data itself is a narration-only risk, never an access risk

`user_name`, `model`, `metric_name`, and (via joined project/account context) project/API-key names
are user-controlled strings that flow into `UsageQueryResponse.points[]` and would enter the
model's context when it narrates results. Decision 2 already bounds the *access* impact of an
injected string — it cannot widen `scope`/`scope_id`, because that field is never read from
untrusted input at any point in the chain (model, eve, or the MCP transport) — but it says nothing
about *narration* impact: a `user_name` engineered to read like an instruction could still attempt
to steer the model's response text. This ADR's answer is that model output is treated as
**untrusted display text, never as instructions and never as anything executed**: it is rendered in
the chat transcript like any other untrusted string, it does not gain the ability to trigger a
second tool call on its own say-so, and Decision 4 already means it cannot corrupt the actual
figures shown.

### 11. Rate limiting and cost: reuse the existing Redis-backed limiter, do not build a second one

Every question a user asks costs one LLM call plus one `usage_events` aggregate query. This repo
already has a working, tested, Redis-backed `RateLimitStore` (`cratestack_redis::
RedisRateLimitStore`, wrapped in `crates/lightbridge-authz-rest/src/ratelimit_redis.rs`) wired into
`authz-api`'s middleware. The usage-query MCP tool reuses that same store and mechanism — enforced
in Rust, at `lightbridge-mcp`, the same place Decision 2's scope-overwrite already runs, not
reinvented on the eve side. Exact bucket/burst parameters are implementation-ticket tuning.

## Turn lifecycle

```mermaid
sequenceDiagram
    participant U as User (assistant-ui chat UI —<br/>placement TBD, converse-frontends)
    participant E as eve agent runtime<br/>(Node.js, own image — Decision 7)
    participant L as LLM (self — provider/gateway TBD)
    participant M as lightbridge-mcp<br/>(app/.../mcp.rs:207-224 call_tool)
    participant Q as authz-usage query listener<br/>(mTLS, /usage/v1/usage/query)
    participant DB as usage_events (Postgres/Timescale)

    U->>E: "What did project X spend on gpt-4 last week?"
    Note over E: HTTP channel route auth (fails closed by default —<br/>eve.dev/docs/guides/auth-and-route-protection)
    alt no authenticator accepts the request
        E-->>U: refused — eve's own fail-closed default
    else authenticated, ctx.session.auth.current set
        E->>L: prompt + lightbridge__query-usage tool schema
        L-->>E: tool_call lightbridge__query-usage(scope="project", scope_id="proj_X" [proposed], bucket="1 day", filters={model:"gpt-4"}, group_by=[...])
        Note over E,M: OPEN QUESTION (Decision 6): does eve's connection<br/>getToken() forward ctx.session.auth.current's own JWT,<br/>unmodified, as the Authorization header here? Not yet confirmed.
        E->>M: MCP call_tool("query-usage", args, Authorization: Bearer TOKEN)
        activate M
        M->>M: token_info_from_request_context (mcp.rs:207-215)
        alt caller lacks usage:read permission
            M-->>E: refused — 403 (mcp.rs:217, token_info.require)
        else bucket fails regex
            M-->>E: refused — 400 (repo.rs:321-324, validate_bucket_interval)
        else authorized and well-formed
            Note over M: PIVOT: discard proposed scope/scope_id;<br/>substitute TokenInfo-derived values (Decision 2)<br/>same pattern as create_account_tool, mcp.rs:848-865
            M->>Q: POST /usage/v1/usage/query (client cert presented by M, Decision 8)<br/>server-derived scope/scope_id + proposed bucket/filters/group_by
            alt no/invalid client certificate
                Q-->>M: TLS handshake refused (server.rs:83-114 build_mtls_config)
            else certificate accepted
                Q->>DB: parameterized SQL (push_bind everywhere, repo.rs:144-277)
                alt query error
                    DB-->>Q: error
                    Q-->>M: refused — never a fabricated number (Decision 4)
                else success
                    DB-->>Q: rows
                    Q-->>M: UsageQueryResponse{points:[...]}
                    M-->>E: points[]
                end
            end
        end
        deactivate M
        E->>L: points[] + request for chart_type + narration
        L-->>E: {chart_spec:{type:"time_series", query: already-scope-overwritten}, narration:"text"}
        E-->>U: renders TimeSeriesChart from points[] (converse-frontends#202);<br/>narration shown as plain, untrusted text (Decision 10)
    end
```

```mermaid
stateDiagram-v2
    [*] --> RouteAuth: chat request arrives at eve
    RouteAuth --> RefusedNoAuthenticator: no authenticator accepts it\n(eve fails closed by default)
    RouteAuth --> Proposed: ctx.session.auth.current set;\nLLM emits query-usage tool call
    Proposed --> RefusedNoPermission: caller lacks usage:read\n(mcp.rs:217)
    Proposed --> RefusedBadBucket: bucket fails regex\n(repo.rs:321-324)
    Proposed --> ScopeOverwritten: lightbridge-mcp discards proposed\nscope/scope_id, substitutes\nTokenInfo-derived values (Decision 2)
    ScopeOverwritten --> RefusedNoClientCert: lightbridge-mcp presents no/invalid\nmTLS client cert to authz-usage (Decision 8)
    ScopeOverwritten --> Executed: query_usage runs parameterized SQL\n(repo.rs:131-303)
    Executed --> RefusedQueryError: DB/query error — fails closed,\nnever a fabricated figure (Decision 4)
    Executed --> Rendered: points[] returned;\nchart spec + narration drafted
    Rendered --> Proposed: follow-up question (new turn)
    Rendered --> [*]
    RefusedNoAuthenticator --> [*]
    RefusedNoPermission --> [*]
    RefusedBadBucket --> [*]
    RefusedNoClientCert --> [*]
    RefusedQueryError --> [*]
```

## Consequences

### Positive

- Zero new database surface: the entire "how do we let an LLM query usage data safely" problem
  reduces to "constrain a function-call schema and overwrite one field," because the schema was
  already closed before this ADR existed.
- Tenant isolation is structurally, not procedurally, enforced — an LLM prompt-injection or
  reasoning failure, or a bug anywhere in eve's TypeScript, cannot become a cross-tenant data leak,
  because the field that would leak it is never read from any of that untrusted input.
- Reuses four pieces of already-built, already-reviewed infrastructure: the usage query API, the
  MCP tool-routing/RBAC machinery, `converse-frontends`' chart primitives, and (per the owner's
  stack decision) two purpose-built, actively maintained products (assistant-ui, eve) instead of a
  hand-rolled chat runtime.
- Decision 6's MCP-connection design means the mTLS requirement (Decision 8), which already exists
  for an unrelated caller (`authz-budget`'s spend reader), turns out to be exactly the right
  constraint here too — it stays entirely inside the Rust services that already hold that identity,
  and eve never needs to acquire one.

### Negative

- **A new component (eve, plus its wiring to `lightbridge-mcp`) is a real, if now better-scoped,
  build.** This ADR specifies its contract, but the per-user-identity mechanism (Decision 6) is
  explicitly unconfirmed and blocking — the first implementation step has to be a spike proving or
  disproving JWT passthrough before any ticket can commit to a specific deployment shape.
- **This introduces a Node.js service into an otherwise-Rust estate, and the cost is more than "one
  more CI matrix entry."** Decision 7 spells out why: eve cannot share the `binaries` job or the
  `container-build` composite's Rust-artifact assumptions, so it needs its own build job — a
  meaningfully bigger lift than `usage-runtime`/`mcp-runtime` were, which only added Dockerfile
  targets to an already-Rust pipeline.
- **Latency and cost compound per turn**: at minimum one LLM call to propose the query, one
  DB aggregate, and (as drawn) a second LLM call for narration/chart-spec drafting — a single user
  question can be two model round-trips plus a network hop through eve and `lightbridge-mcp` to
  `authz-usage`. Decision 11's rate limiting bounds abuse but does not remove the per-turn latency
  cost.
- **The model can still ask a wrong, if safe, question.** Decision 2 guarantees a wrong `scope`
  proposal cannot leak data, but not that the model picks the *right* filters/group_by for the
  user's actual question — a bad answer is still possible, just never an unauthorized one.
- **A new `Permission` variant and its RBAC wiring (`docs/rbac.md`) is real, if small, follow-up
  work** — this ADR intentionally leaves its exact name undecided rather than picking one without
  the usual RBAC-doc review this codebase gives every other permission addition.
- **The assistant-ui↔eve↔React-Native-Web compatibility question is real and unresolved** (see
  Decision 5 and Open questions) — the only documented wiring path is Next.js-shaped, and
  `converse-frontends` is Expo/RNW, not Next.js.

### Neutral / follow-ups

- The exact shape of the "chart spec" object (field names, which chart-type strings map to which
  `converse-frontends` component) is an implementation-ticket decision made jointly with the
  `converse-frontends` team, not decided here.
- Whether narration and chart-spec selection are one model call or two (as drawn in the sequence
  diagram) is an implementation detail; either is compatible with every decision above.
- The new `usage:read`-shaped permission's exact name, default role grants, and `docs/rbac.md`
  update are implementation-ticket work, not decided here.
- ArgoCD/`argocd-image-updater` wiring for the new eve image is not decided or verified here — it
  is a GitOps-repo concern outside this ADR's reach.

## Alternatives considered

- **Text-to-SQL against `usage_events` directly.** Rejected. This is the reflex approach and the
  one this ADR exists specifically to avoid, because it would require building and maintaining a
  SQL sandbox for a problem the existing typed API already solves. It would only become the right
  call if `UsageQueryRequest` were *not* already a closed parameter space; that is not the case
  today (see Context), and if it ever becomes the case, this decision should be revisited on its
  own record, not silently worked around by loosening the schema.
- **Expose the raw Timescale connection to the model or to eve.** Rejected for the same core reason
  as text-to-SQL, more severely: it removes every one of the API's existing guardrails at once, and
  it would require whatever calls the database to hold direct database credentials in addition to
  (or instead of) the mTLS identity Decision 8 already requires `lightbridge-mcp` to hold.
- **eve calling `authz-usage`'s query API directly, bypassing `lightbridge-mcp`.** Rejected — this
  is the option Decision 6 explicitly argues against: it would put Decision 2's scope-overwrite
  logic in TypeScript, duplicate `lightbridge-mcp`'s RBAC gate in a second codebase, and require eve
  itself to hold the mTLS client identity Decision 8 keeps in Rust. Routing through
  `lightbridge-mcp`'s already-audited authorization boundary instead costs one extra network hop and
  buys back everything this alternative would have put at risk.
- **No chat — ship more fixed dashboards instead.** Rejected as the *sole* answer, not as
  worthless: `converse-frontends` ADR-0008's three dashboards (Decision 7 there) are exactly this,
  already decided, already partially built (`#202`'s primitives), and this ADR does not replace or
  slow them down. But "more fixed dashboards" cannot satisfy the owner's actual ask — ad hoc,
  free-form questions a dashboard designer didn't anticipate. The two are complementary: fixed
  dashboards for known, recurring questions; this ADR's contract for everything else.

## Open questions — explicitly not decided here

1. **Whether eve can propagate a per-request end-user's own JWT through to an MCP connection's
   auth callback, unmodified — the blocking integration question from Decision 6.** eve has a real
   per-caller identity model (`ctx.session.auth.current`, `principalType: "user"`), but nothing
   fetched from eve's docs confirms a plain `getToken()` callback can read that identity back out
   and forward the exact token `lightbridge-mcp` needs to validate, as opposed to the per-user path
   being specific to eve's own OAuth broker (Vercel Connect), which negotiates a different
   credential entirely. This must be proven with a spike, not assumed, before an implementation
   ticket can commit to a deployment shape (a long-lived shared eve agent vs. a per-request-scoped
   one).
2. **Which provider/gateway eve points at** — the Vercel AI Gateway default, the estate's own AI
   gateway (referenced elsewhere but not integrated with anything in this repo today), or a direct
   provider. Decision 9 only settles that the choice must be environment-configured, not which
   choice is made.
3. **Which surface hosts the chat UI, and whether assistant-ui's Eve runtime binding actually works
   under Expo/React-Native-Web.** `converse-frontends` ADR-0008 already folds "usage" into its
   `Overview` nav group as fixed dashboards; whether conversational usage analytics becomes a new
   mode within that group or its own nav destination is a `converse-frontends` product/IA decision
   needing its own companion ADR there — not decided here. That companion ADR should start from a
   confirmed answer to the compatibility question this ADR only surfaces: the only documented
   `@assistant-ui/eve` wiring path is Next.js-shaped (`eve/next`'s `withEve`), while
   `converse-frontends` is Expo + React Native Web, not Next.js; and ADR-0008's visual direction
   (near-black Axiom palette, monochrome-plus-signal-orange, floating-panel shell, CVA + CSS-variable
   theming) means an unstyled-primitives integration is likely the only one consistent with the
   existing design system, not whatever pre-styled (Tailwind/shadcn-oriented) flavor assistant-ui
   may ship by default for React-DOM consumers — this was not independently confirmed against
   assistant-ui's live docs in this session (repeated fetches of styling-specific pages 404'd) and
   should be checked directly before that companion ADR is written.

## Follow-ups

1. **Spike: prove or disprove end-user JWT passthrough from eve to `lightbridge-mcp`** (Open
   question 1) against real instances of both, before any implementation ticket commits to a
   deployment shape.
2. Open a tracking issue for the `query-usage` MCP tool (Decision 6): new `#[tool(...)]` handler in
   `app/lightbridge-authz/src/mcp.rs`, a new `usage:read`-shaped `Permission` variant plus
   `docs/rbac.md` update, and an mTLS client identity (`client_cert_path`/`client_key_path`,
   mirroring `UsageServiceSpendReader`) wired into `lightbridge-mcp`'s config to call `authz-usage`'s
   query listener (Decision 8).
3. Design eve's own image/chart/CI job (Decision 7): a new build job independent of the `binaries`/
   `container-build` Rust pipeline, reusing only the cosign-signing step, plus a new Helm chart
   following the `lightbridge-authz-usage`/`lightbridge-mcp` precedent.
4. Wire Decision 11's rate limiting onto the new tool, at `lightbridge-mcp`, choosing bucket/burst
   parameters appropriate to "one LLM-proposed query per user turn."
5. A companion ADR in `converse-frontends` deciding the chat surface's placement in the nav and its
   styling approach (Open question 3), and the exact chart-spec object shape consumed by
   `TimeSeriesChart`/`HistogramChart`/`RidgelineChart`.
6. A decision (owner's, per Open question 2) on which provider/gateway eve points at, expressed as
   environment configuration per Decision 9 — before any implementation ticket for the chat backend
   itself.
