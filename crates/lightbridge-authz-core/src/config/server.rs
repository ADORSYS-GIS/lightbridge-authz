use crate::config::budget_internal::BudgetInternalServer;
use crate::config::budget_server::BudgetServer;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Server {
    pub api: ApiServer,
    pub opa: OpaServer,
    /// `authz-idp`'s server block (ADR-0012 Phase 1): address/port/TLS for the OIDC broker
    /// service that carries discovery/JWKS/token-exchange off `authz-api`. Optional, like
    /// `redis`/`usage_service` above — `authz-api`, `authz-opa`, `lightbridge-mcp`, and the
    /// usage service all load this same `Config` type but never read this field, so a config
    /// file written before `authz-idp` existed keeps loading unchanged. Only `Commands::Idp`
    /// requires it to be `Some`, and fails fast with a clear error at startup if it is missing
    /// when that command actually runs (see `app/lightbridge-authz/src/main.rs`).
    #[serde(default)]
    pub idp: Option<IdpServer>,
    /// `authz-budget`'s server block: address/port/TLS for the budget-domain microservice that
    /// carries the `budget:*`-gated RPC procedures off `authz-api` (hard cutover, not a
    /// transitional duplication like `idp` above — see `docs/architecture/budget.md`). Optional
    /// for the same reason `idp` is: every other command loads this same `Config` type but never
    /// reads this field, so a config file written before `authz-budget` existed keeps loading
    /// unchanged. Only `Commands::Budget` requires it to be `Some`, and fails fast with a clear
    /// error at startup if it is missing when that command actually runs (see
    /// `app/lightbridge-authz/src/main.rs`).
    #[serde(default)]
    pub budget: Option<BudgetServer>,
    /// `authz-budget`'s **second**, mTLS-only listener (ADR-0034, lightbridge-authz#658): the
    /// service-to-service read `GET /budget/v1/remaining` the gateway's Dynamic Budget Limiter
    /// calls through Authorino. Shaped exactly like `lightbridge-authz-usage`'s
    /// `UsageServerGroup::query` (#347) and for the identical reason — `axum-server`'s rustls
    /// integration enforces client-certificate verification per **listener**, not per route, so
    /// this cannot be a route on the bearer-JWT RPC listener above without locking out the
    /// console.
    ///
    /// `Option`, like `idp`/`budget` above, and for the same operational reason recorded on
    /// [`IdpServer::static_dir`]: prod's config is a wholesale override living in the separate
    /// `ai-helm-values` repo, and prod tracks `main` HEAD via argocd-image-updater with no
    /// release-tag gate — a hard-required field here would crash-loop `authz-budget` on the very
    /// next promotion, taking the console's whole budget surface down. When it is absent the
    /// listener is simply not bound and `startup` logs why; the gateway side of ADR-0034 is
    /// values-gated off in the same state, so the two halves cannot be enabled independently by
    /// accident.
    ///
    /// When it IS present, `shared_secret` is **mandatory** and startup fails without it. This
    /// listener answers a cross-account balance question with no per-caller ownership check at
    /// all; serving it without a credential is exactly the silent degrade this codebase's
    /// fail-closed rule forbids. The credential is a shared secret in a custom header, **not**
    /// mTLS -- Authorino v0.24.0 cannot present a client certificate, so the shape ADR-0034 first
    /// specified is unreachable by its only caller. See [`BudgetInternalServer`].
    #[serde(default)]
    pub budget_internal: Option<BudgetInternalServer>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiServer {
    pub address: String,
    pub port: u16,
    pub tls: Tls,
    /// Hostnames or `host:port` authorities accepted in the inbound `Host` header by the MCP
    /// streamable-HTTP transport (DNS-rebinding protection). Only consumed by the MCP server; when
    /// unset it keeps the secure default (`localhost`/`127.0.0.1`/`::1`).
    #[serde(default)]
    pub allowed_hosts: Option<Vec<String>>,
    /// Optional base path the generated RPC CRUD surface is mounted under. Unset (the default)
    /// serves the ops at `/rpc/<op_id>`; setting e.g. `/api` serves them at `/api/rpc/<op_id>` so
    /// `authz-api` can match a generated client whose `basePath` is `/api` without an edge rewrite.
    /// Only the RPC surface moves — the health probes, `/.well-known/*`, and `/oauth2/token` stay at
    /// the root. Only consumed by `authz-api`; `opa`/`mcp`/usage ignore it. A leading slash is added
    /// if missing and a trailing slash is stripped; empty or `/` is treated as unset (root mount).
    #[serde(default)]
    pub rpc_base_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpaServer {
    pub address: String,
    pub port: u16,
    pub tls: Tls,
    pub basic_auth: BasicAuth,
}

/// `authz-idp`'s server block (ADR-0012 Phase 1). Deliberately narrower than [`OpaServer`]: every
/// route this server mounts (`.well-known/*`, `/oauth2/token`, `/oauth2/revoke`, the health
/// probes) is public by design — the presented `subject_token`/`client_assertion` is itself the
/// credential (see `token_exchange.rs`'s module doc comment) — so there is no `basic_auth` block
/// to carry, unlike [`OpaServer`].
#[derive(Debug, Clone, Deserialize)]
pub struct IdpServer {
    pub address: String,
    pub port: u16,
    pub tls: Tls,
    /// ADR-0021 Decisions 1 + 10 (#442): filesystem path to the hosted login page's Vite
    /// production build (built in `converse-frontends` as `apps/authz-ui`, consumed here as a
    /// digest-pinned OCI artifact — see ADR-0029; an `index.html` plus a content-hashed
    /// `assets/` directory built with Vite `base: "/ui/"`), mounted under `build_idp_router`'s
    /// `/ui` path prefix (`.nest_service("/ui", ..)`), never at the router root. This server
    /// always mounts it unconditionally (AGENTS.md's "no dormant flags" convention) -- an
    /// operator who has not built the frontend yet gets a working server whose `/ui/*` paths
    /// 404 until the assets exist, not a server with the feature silently switched off.
    ///
    /// Defaults to [`default_idp_static_dir`] (`/app/static`) when the key is omitted from
    /// config -- **not optional in behavior, but optional in config**. This distinction is
    /// load-bearing: prod's `authz-idp` config is a wholesale override living in a separate repo
    /// (`ai-helm-values`) that this PR cannot touch, and prod tracks `main` HEAD directly via
    /// argocd-image-updater with no release-tag gate. A hard-required field here would mean the
    /// very next promotion after this merges ships a binary that refuses to deserialize prod's
    /// (not-yet-updated) config and crash-loops `authz-idp` -- taking out `/oauth2/token`,
    /// `/oauth2/revoke`, discovery, and (once Authorino's JWKS cache expires) every API-key JWT
    /// validation at the gateway. `/app/static` is a safe default for every containerised
    /// deployment because it is exactly where `Dockerfile`/`Dockerfile.dist` already copy
    /// `dist/static` on the `runtime` image -- zero config change required anywhere.
    /// `config/default.yaml`/`.docker/authz/container.yaml` still set this key explicitly (this
    /// default exists for configs this repo does not own, not to make the local ones lazy).
    #[serde(default = "default_idp_static_dir")]
    pub static_dir: String,
}

/// See [`IdpServer::static_dir`]'s doc comment for why this default exists and why `/app/static`
/// is the right value.
fn default_idp_static_dir() -> String {
    "/app/static".to_owned()
}

#[derive(Debug, Clone, Deserialize)]
pub struct Tls {
    pub cert_path: String,
    pub key_path: String,
    /// Path to a PEM-encoded CA bundle used to require and verify a client certificate on every
    /// connection to this listener (mTLS). Optional: when unset (every server today except
    /// `authz-usage` once #347 lands), this listener behaves exactly as before -- server-only
    /// TLS, no client-certificate check. When set, [`crate::server::serve_tls`] builds a
    /// `rustls::ServerConfig` with a `WebPkiClientVerifier` over this trust store instead of
    /// `with_no_client_auth`: a connection presenting no client certificate, an expired one, or
    /// one not signed by a CA in this bundle is refused at the TLS handshake, before any
    /// application code runs. There is no "accept but don't require" mode here deliberately --
    /// `WebPkiClientVerifier`'s default (no `allow_unauthenticated()`) is fail-closed by
    /// construction, matching this codebase's rule that an unknown/unverifiable caller routes to
    /// the strictest branch, never a permissive default.
    ///
    /// An unreadable path, a bundle with zero parseable PEM certificates, or a bundle that fails
    /// to build into a verifier is a hard startup failure naming the path -- the same
    /// fail-closed convention `UsageServiceClient::ca_bundle_path` already uses on the client
    /// side of this same call.
    #[serde(default)]
    pub client_ca_bundle_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}
