use serde::Deserialize;

pub mod api_key_expiry;
pub mod billing;
pub mod budget_internal;
pub mod budget_server;
pub mod claim_mapper;
pub mod infrastructure;
pub mod loader;
pub mod model_catalog;
pub mod oauth2;
pub mod quota_tiers;
pub mod server;
mod unknown_keys;
mod unknown_keys_data;

pub use api_key_expiry::ApiKeyExpiry;
pub use billing::{Billing, BillingLimits, BillingPlan, deserialize_null_default};
pub use budget_internal::BudgetInternalServer;
pub use budget_server::BudgetServer;
pub use claim_mapper::{ClaimMapper, ClaimSource};
pub use infrastructure::{Database, Logging, Otel, Redis, SecretClaim, UsageServiceClient};
pub use loader::{load_from_path, load_yaml_from_path};
pub use model_catalog::{ModelCatalog, ModelCatalogEntry};
pub use oauth2::{
    Federation, JwtSigning, Oauth2, Oauth2Issuance, Oauth2TokenExchange, Oauth2Type, OauthClient,
    OauthClientType, OidcRelyingParty,
};
pub use quota_tiers::{QuotaTier, QuotaTiers};
pub use server::{ApiServer, BasicAuth, IdpServer, OpaServer, Server, Tls};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: Server,
    pub logging: Logging,
    pub database: Database,
    /// Redis connection. **Mandatory at startup for `authz-api`, `authz-idp`, and
    /// `authz-budget`** (see `start_api_server`/`start_idp_server`/`start_budget_server` in
    /// `crates/lightbridge-authz-rest/src/lib.rs`, and AGENTS.md's "Redis is a mandatory
    /// dependency" house rule) -- each of those three refuses to start with this unset, loudly,
    /// rather than degrade. Used for Redis-backed rate limiting on `authz-api`/`authz-budget`
    /// (see `docs/adr/0003-cratestack-crud-migration.md`, "Rate limiting (Redis-backed)") and for
    /// `authz-idp`'s `private_key_jwt` client-assertion replay-protection store (ADR-0011,
    /// Decision 6) whenever `oauth2.token_exchange` is enabled.
    ///
    /// The field itself stays `Option` at the `Config` level -- not `Redis` -- because
    /// `authz-opa`, `lightbridge-mcp`, and the usage service load this same `Config` type and are
    /// deliberately freed from needing Redis at all, so a config file that omits `redis` entirely
    /// must still load for them. Enforcement of "mandatory for api/idp/budget" therefore happens
    /// per-component at server startup, not by making this field required for every consumer of
    /// `Config`.
    #[serde(default)]
    pub redis: Option<Redis>,
    /// HTTP client config for calling `lightbridge-authz-usage`'s `/usage/v1/spend/query`
    /// endpoint, used by the budget domain's `UsageServiceSpendReader`
    /// (`crates/lightbridge-authz-budget/src/spend.rs`) to read `usage_events.total_cost` sums
    /// without either service reaching into the other's database directly. Carries no credential
    /// by default; `client_cert_path`/`client_key_path` (#347) let it present a client
    /// certificate for mTLS when the usage service's listener requires one — see
    /// `UsageServiceSpendReader`'s own doc comment. Optional, like `redis` above: only the
    /// budget domain's spend reads need it, so a config file that omits it entirely still loads
    /// (and budget refill spend facts report `Spend::Unavailable`, per `UnavailableSpendReader`'s
    /// doc comment).
    #[serde(default)]
    pub usage_service: Option<UsageServiceClient>,
    pub oauth2: Oauth2,
    pub otel: Otel,
    /// Billing plans a caller may attach to an API key at creation time. The catalogue is defined
    /// entirely by the operator (env-driven) — there is no plan table or entity. A `CreateApiKey`
    /// must name one of these plans (by `id`) or the request is rejected.
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub billing: Billing,
    /// Governance quota tiers a caller may attach to `Account.defaultQuota`, `Project.projectQuota`,
    /// or `ProjectMember.quotaTier` (ADR-0006). Unlike `billing` above, an empty/absent catalogue is
    /// the supported default — every value is accepted uncritically until an operator supplies a
    /// real tier catalogue (see `QuotaTiers::is_allowed`).
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub quota_tiers: QuotaTiers,
    /// The operator-configured AI-model catalogue backing `listModelCatalog` (a read-only display
    /// aid for a `Project.allowedModels` editor) **and**, since #415 (ADR-0018 Decision 5), the
    /// validation source `setProjectAllowedModels` checks every `allowedModels` entry against
    /// before writing. Same env-driven loading shape as `billing` above, and like `quota_tiers`
    /// (unlike `billing`) an empty/absent catalogue is the supported default: a deployment that has
    /// not configured a catalogue yet accepts any `allowedModels` value uncritically (see
    /// `ModelCatalog::invalid_ids`), same "no behavior change until populated" contract
    /// `quota_tiers` already established, rather than failing to start.
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub models: ModelCatalog,
    /// Operator-configured ceiling on how far in the future `createApiKey`/`rotateApiKey` may set
    /// `expires_at` (lightbridge-authz#395: every API key must carry an expiry, no more nullable
    /// "never expires" keys). Unlike `quota_tiers`/`models` above, an absent/null block is NOT an
    /// escape hatch to "unlimited" -- `ApiKeyExpiry::default()` resolves it to a real 90-day
    /// ceiling instead, because a missing config value here is "unknown", and unknown must route
    /// to the strictest reading, never the most permissive one (see that type's own doc comment).
    /// A value that fails to parse (e.g. a non-numeric `max_lifetime_days`) fails config load
    /// entirely rather than silently falling back to anything -- also fail-closed, for the same
    /// reason.
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub api_key_expiry: ApiKeyExpiry,
    /// Single-use secret-claim delivery (GHSA-9pc6-965v-2c44, #538). Mandatory for
    /// `lightbridge-mcp`, which issues the claims, and for `authz-idp`, which redeems them; both
    /// refuse to start without it rather than fall back to returning a secret inline.
    ///
    /// `Option` at this level for the same reason `redis` above is: `authz-api`, `authz-opa`,
    /// `authz-budget` and the usage service all load this same `Config` and never touch secret
    /// claims, so a config omitting the section entirely must still load for them. Enforcement is
    /// per-component at startup, never by making the field required for every consumer of
    /// `Config`.
    #[serde(default)]
    pub secret_claim: Option<SecretClaim>,
}
