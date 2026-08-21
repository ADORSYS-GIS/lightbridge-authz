use crate::error::{Error, Result};
use regex::{Captures, Regex};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_yaml::from_str;
use std::env;
use std::fs::read_to_string;
use std::sync::LazyLock;
use utoipa::ToSchema;

static RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$([a-zA-Z_][a-zA-Z0-9_]*)|\$\{([a-zA-Z_][a-zA-Z0-9_]*)(?:(:-|-)([^}]*))?\}")
        .expect("env-interpolation regex is a compile-time constant and always parses")
});

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
}

/// The operator-configured catalogue of billing plans. Populated from env — either a single
/// `BILLING_PLANS` JSON-array env var (e.g. `plans: "${BILLING_PLANS}"`) or an inline YAML/JSON
/// sequence of plan objects.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Billing {
    #[serde(default, deserialize_with = "deserialize_plan_list")]
    pub plans: Vec<BillingPlan>,
}

/// A single billing plan. `id` is the stable key stored on the API key and named in
/// `CreateApiKey`; `name` is the human-facing label for UIs; `limits` carries the plan's
/// rate/usage envelope (all fields optional — absent means "unset / unlimited").
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct BillingPlan {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<BillingLimits>,
}

/// Rate/usage limits attached to a billing plan. Purely descriptive here — enforcement lives at
/// the edge (e.g. Authorino), which reads these via token introspection. Convention: an omitted
/// field (or an entirely omitted `limits` block, e.g. an unlimited "enterprise" plan) means *no
/// limit* for that dimension; the edge must treat an absent value as unlimited, not as "deny".
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct BillingLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_second: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_day: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_month: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrent_requests: Option<i32>,
}

impl Billing {
    /// Whether a plan with this `id` is configured.
    pub fn is_allowed(&self, id: &str) -> bool {
        self.get(id).is_some()
    }

    /// Look up a plan by its `id`.
    pub fn get(&self, id: &str) -> Option<&BillingPlan> {
        if id.is_empty() {
            return None;
        }
        self.plans.iter().find(|p| p.id == id)
    }

    /// The configured plan ids, for error messages.
    pub fn plan_ids(&self) -> Vec<&str> {
        self.plans.iter().map(|p| p.id.as_str()).collect()
    }

    /// Validates the catalogue for a server that issues API keys: it must be non-empty, every plan
    /// must have a non-empty `id`, and ids must be unique. Called at startup by the key-issuing
    /// servers so a misconfiguration fails loudly instead of silently rejecting every
    /// `CreateApiKey` with a `400`.
    pub fn validate(&self) -> Result<()> {
        if self.plans.is_empty() {
            return Err(Error::Server(
                "billing.plans is empty: configure at least one billing plan (API-key creation \
                 requires a valid plan)"
                    .to_string(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for plan in &self.plans {
            if plan.id.trim().is_empty() {
                return Err(Error::Server(
                    "billing.plans contains a plan with an empty id".to_string(),
                ));
            }
            if !seen.insert(plan.id.as_str()) {
                return Err(Error::Server(format!(
                    "billing.plans contains a duplicate plan id '{}'",
                    plan.id
                )));
            }
        }
        Ok(())
    }
}

/// Deserializes an optional field to its `Default` when the YAML value is null (rather than
/// erroring). Lets `billing:` with no value fall back to an empty catalogue.
fn deserialize_null_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// Accepts a JSON-array string (the single-env-var case, e.g. `${BILLING_PLANS}`), an inline
/// YAML/JSON sequence of plan objects, or null/blank. A null value or a blank/unset env var yields
/// an empty catalogue rather than a parse error.
fn deserialize_plan_list<'de, D>(deserializer: D) -> std::result::Result<Vec<BillingPlan>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct PlansVisitor;

    impl<'de> serde::de::Visitor<'de> for PlansVisitor {
        type Value = Vec<BillingPlan>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a JSON-array string, a sequence of billing plans, or null")
        }

        fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
            Ok(Vec::new())
        }

        fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
            Ok(Vec::new())
        }

        fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(self)
        }

        fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Ok(Vec::new());
            }
            serde_json::from_str(trimmed).map_err(E::custom)
        }

        fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut plans = Vec::new();
            while let Some(plan) = seq.next_element::<BillingPlan>()? {
                plans.push(plan);
            }
            Ok(plans)
        }
    }

    deserializer.deserialize_any(PlansVisitor)
}

/// Operator-configured catalogue of governance quota tiers (ADR-0006). Referenced by three write
/// paths -- `Account.defaultQuota`, `Project.projectQuota`, `ProjectMember.quotaTier` -- all
/// validated against this catalogue at write time (config, not DB), same shape and env-driven
/// loading (`QUOTA_TIERS` JSON-array string, or an inline YAML/JSON sequence) as `Billing` above.
/// Deliberately more permissive than `Billing`, though: `Billing::validate` requires a key-issuing
/// server to configure a non-empty catalogue, but an empty/absent tier catalogue here is the
/// supported default (see `is_allowed`) so existing deployments and charts keep working before
/// `ai-helm-values` supplies a real catalogue.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct QuotaTiers {
    #[serde(default, deserialize_with = "deserialize_tier_list")]
    pub tiers: Vec<QuotaTier>,
}

/// A single governance quota tier. `id` is the stable key stored on `Account.defaultQuota`,
/// `Project.projectQuota`, and `ProjectMember.quotaTier`; `name` is the human-facing label.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct QuotaTier {
    pub id: String,
    pub name: String,
}

impl QuotaTiers {
    /// Whether `tier` may be written to `Account.defaultQuota`, `Project.projectQuota`, or
    /// `ProjectMember.quotaTier`. `None` (the field left unset) is always allowed. Otherwise: an
    /// empty catalogue accepts any value uncritically (the deliberate default -- see the type-level
    /// doc comment); a non-empty catalogue accepts only a configured tier `id`.
    pub fn is_allowed(&self, tier: Option<&str>) -> bool {
        let Some(tier) = tier else {
            return true;
        };
        if self.tiers.is_empty() {
            return true;
        }
        self.tiers.iter().any(|t| t.id == tier)
    }

    /// Look up a tier by its `id`.
    pub fn get(&self, id: &str) -> Option<&QuotaTier> {
        if id.is_empty() {
            return None;
        }
        self.tiers.iter().find(|t| t.id == id)
    }

    /// The configured tier ids, for error messages.
    pub fn tier_ids(&self) -> Vec<&str> {
        self.tiers.iter().map(|t| t.id.as_str()).collect()
    }
}

/// Accepts a JSON-array string (the single-env-var case, e.g. `${QUOTA_TIERS}`), an inline
/// YAML/JSON sequence of tier objects, or null/blank. A null value or a blank/unset env var yields
/// an empty catalogue rather than a parse error -- mirrors `deserialize_plan_list` above.
fn deserialize_tier_list<'de, D>(deserializer: D) -> std::result::Result<Vec<QuotaTier>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct TiersVisitor;

    impl<'de> serde::de::Visitor<'de> for TiersVisitor {
        type Value = Vec<QuotaTier>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a JSON-array string, a sequence of quota tiers, or null")
        }

        fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
            Ok(Vec::new())
        }

        fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
            Ok(Vec::new())
        }

        fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(self)
        }

        fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Ok(Vec::new());
            }
            serde_json::from_str(trimmed).map_err(E::custom)
        }

        fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut tiers = Vec::new();
            while let Some(tier) = seq.next_element::<QuotaTier>()? {
                tiers.push(tier);
            }
            Ok(tiers)
        }
    }

    deserializer.deserialize_any(TiersVisitor)
}

/// The operator-configured catalogue of AI models a `Project.allowedModels` editor may offer, and
/// -- since #415 (ADR-0018 Decision 5) -- the catalogue `setProjectAllowedModels` validates every
/// `allowedModels` entry against before writing. Populated from env — either a single
/// `MODEL_CATALOG` JSON-array env var (e.g. `models: "${MODEL_CATALOG}"`) or an inline YAML/JSON
/// sequence of model objects — the same shape and env-driven loading as `Billing`/`QuotaTiers`
/// above. Unlike `Billing`, an empty/absent catalogue is the supported default (see the
/// `Config::models` field doc comment and `invalid_ids` below): nothing here needs to fail startup
/// when unset, and until an operator populates a real catalogue every `allowedModels` value is
/// accepted uncritically, same as `QuotaTiers::is_allowed`'s contract for an empty tier list.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ModelCatalog {
    #[serde(default, deserialize_with = "deserialize_model_list")]
    pub models: Vec<ModelCatalogEntry>,
}

/// A single catalogue entry. `id` is the model id a caller would place in
/// `Project.allowedModels`; `name` is the human-facing label for a UI checkbox list.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct ModelCatalogEntry {
    pub id: String,
    pub name: String,
}

impl ModelCatalog {
    /// The configured model ids, mainly useful for tests/diagnostics -- `listModelCatalog` itself
    /// returns the full entries, not just ids.
    pub fn model_ids(&self) -> Vec<&str> {
        self.models.iter().map(|m| m.id.as_str()).collect()
    }

    /// Validates `models` (a `Project.allowedModels` write, e.g. from `setProjectAllowedModels`)
    /// against this catalogue, returning the entries (deduplicated, in the caller's order) that are
    /// not configured. An empty return means the write is allowed.
    ///
    /// `None` (the field left unset -- "all models allowed", unrelated to catalogue membership) is
    /// always allowed, matching `QuotaTiers::is_allowed`'s `None`-always-passes contract. An
    /// empty/absent catalogue accepts anything, including `Some(vec![...])` with entries that would
    /// otherwise be unrecognized -- the deliberate "no behavior change until populated" default (see
    /// this type's own doc comment), same as `QuotaTiers::is_allowed` for an empty tier list. This is
    /// the one asymmetry with `Billing::is_allowed`/`QuotaTiers::is_allowed`, which each validate a
    /// single scalar: `allowedModels` is a list, so a single invalid entry among otherwise-valid ones
    /// must still be named, not just accepted-or-rejected as a whole -- see the returned `Vec` above.
    pub fn invalid_ids<'a>(&self, models: Option<&'a [String]>) -> Vec<&'a str> {
        let Some(models) = models else {
            return Vec::new();
        };
        if self.models.is_empty() {
            return Vec::new();
        }
        let mut invalid: Vec<&str> = Vec::new();
        for id in models {
            let known = self.models.iter().any(|m| m.id == *id);
            if !known && !invalid.contains(&id.as_str()) {
                invalid.push(id.as_str());
            }
        }
        invalid
    }
}

/// Accepts a JSON-array string (the single-env-var case, e.g. `${MODEL_CATALOG}`), an inline
/// YAML/JSON sequence of model objects, or null/blank. A null value or a blank/unset env var yields
/// an empty catalogue rather than a parse error -- mirrors `deserialize_plan_list`/
/// `deserialize_tier_list` above.
fn deserialize_model_list<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<ModelCatalogEntry>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ModelsVisitor;

    impl<'de> serde::de::Visitor<'de> for ModelsVisitor {
        type Value = Vec<ModelCatalogEntry>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a JSON-array string, a sequence of model catalogue entries, or null")
        }

        fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
            Ok(Vec::new())
        }

        fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
            Ok(Vec::new())
        }

        fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(self)
        }

        fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Ok(Vec::new());
            }
            serde_json::from_str(trimmed).map_err(E::custom)
        }

        fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut models = Vec::new();
            while let Some(model) = seq.next_element::<ModelCatalogEntry>()? {
                models.push(model);
            }
            Ok(models)
        }
    }

    deserializer.deserialize_any(ModelsVisitor)
}

/// Operator-configured ceiling on `api_keys.expires_at` (lightbridge-authz#395). Every
/// `createApiKey`/`rotateApiKey` write is validated against this: `expiresAt` must be present, in
/// the future, and no further out than `now + max_lifetime_days`
/// (`AuthzStoreImpl::validate_expires_at`, `crates/lightbridge-authz-rest/src/handlers/mod.rs`).
///
/// Deliberately the opposite default posture from `QuotaTiers`/`ModelCatalog` above: those two
/// treat an empty/absent catalogue as "accept anything" because they gate optional, informational
/// fields. This gates a mandatory credential-lifetime ceiling, so absent must resolve to a real,
/// conservative number (90 days) instead -- never to "no ceiling". `Default` and serde's
/// `#[serde(default)]` both route through the same `default_api_key_max_lifetime_days` constant so
/// "field omitted from YAML" and "struct built directly in Rust with `..Default::default()`" can
/// never disagree.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ApiKeyExpiry {
    #[serde(default = "default_api_key_max_lifetime_days")]
    pub max_lifetime_days: u32,
}

impl Default for ApiKeyExpiry {
    fn default() -> Self {
        Self {
            max_lifetime_days: default_api_key_max_lifetime_days(),
        }
    }
}

fn default_api_key_max_lifetime_days() -> u32 {
    90
}

impl ApiKeyExpiry {
    /// Fails startup loudly on a nonsensical ceiling, mirroring `Billing::validate`'s and
    /// `ApiKeyJwtSigner::from_config`'s own startup guards (`oauth2.signing.ttl_seconds must be
    /// positive`) -- a misconfigured ceiling must never silently become "no ceiling" (zero days
    /// would make every `createApiKey` call fail instead, which is the fail-closed direction, but
    /// still worth rejecting loudly at startup rather than discovering it via a wall of runtime
    /// 400s).
    pub fn validate(&self) -> Result<()> {
        if self.max_lifetime_days == 0 {
            return Err(Error::Server(
                "api_key_expiry.max_lifetime_days must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Otel {
    pub enabled: bool,
    pub otlp_endpoint: String,
    pub service_name: String,
}

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
}

/// `authz-budget`'s server block. Shaped like [`IdpServer`] (address/port/TLS, no `basic_auth`):
/// every route this server mounts is behind the same bearer-JWT `rpc_authorize` gate `authz-api`
/// already uses, not Basic auth like [`OpaServer`]. Unlike `idp`, this server's RPC surface is
/// mounted under a fixed `/budget` path prefix (`build_budget_router`) rather than at the
/// configurable root `authz-api` uses — there is no `rpc_base_path` field here because the prefix
/// is not optional, it is what makes the service reachable behind a shared gateway origin
/// alongside `authz-api` (see `docs/architecture/budget.md`).
#[derive(Debug, Clone, Deserialize)]
pub struct BudgetServer {
    pub address: String,
    pub port: u16,
    pub tls: Tls,
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

#[derive(Debug, Clone, Deserialize)]
pub struct Logging {
    pub level: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Database {
    pub url: String,
    pub pool_size: Option<u32>,
}

/// HTTP client config for `lightbridge-authz-budget`'s `UsageServiceSpendReader` to call
/// `lightbridge-authz-usage`'s `/usage/v1/spend/query` endpoint. See `Config::usage_service`'s
/// doc comment for why this replaced a direct database connection. `client_cert_path`/
/// `client_key_path` (#347) present a client certificate for mTLS when the usage service
/// requires one; see `UsageServiceSpendReader`'s own doc comment for the full posture.
#[derive(Debug, Clone, Deserialize)]
pub struct UsageServiceClient {
    /// Base URL of the usage service, e.g. `https://authz-usage:3002`. A trailing slash is
    /// stripped if present.
    pub base_url: String,
    /// Skip TLS certificate verification when calling the usage service. Local Compose serves
    /// every authz service over a self-signed certificate with no shared CA bundle available to
    /// mount, so a client that verifies certificates strictly can never reach it there. Defaults
    /// to `false`.
    ///
    /// This must NOT be set in production. The doc comment here previously claimed production
    /// "must never set this" on the assumption that production terminates a publicly-trusted
    /// certificate — it does not: production terminates a cert-manager-issued *self-signed*
    /// certificate (`ClusterIssuer/self-signed-ca`), the same shape as local Compose. The correct
    /// production mechanism is `ca_bundle_path` below, which verifies against that specific CA
    /// instead of either trusting nothing (`insecure_skip_verify`) or falling back to a system
    /// trust store that was never going to contain this private CA anyway.
    #[serde(default)]
    pub insecure_skip_verify: bool,
    /// Path to a PEM-encoded CA bundle used to verify the usage service's certificate, e.g.
    /// `/etc/lightbridge/tls/ca.crt` (the `ca.crt` cert-manager writes into the same `authz-tls`
    /// Secret this service already mounts for its own server certificate — see
    /// `crates/lightbridge-authz-core/src/config/mod.rs`'s `Tls` type). This is the production
    /// mechanism: it verifies the usage service's certificate is signed by the cluster's own CA,
    /// rather than skipping verification entirely. Optional — when unset, verification falls
    /// back to the platform's default trust store (or, if `insecure_skip_verify` is `true`, to no
    /// verification at all, for local Compose only). An unreadable path or a bundle that fails to
    /// parse as PEM is a hard startup failure naming the path — never a silent fallback to
    /// skip-verify or to the system trust store (an unusable trust anchor is "unknown", which per
    /// this codebase's fail-closed rule must route to the strictest branch: refuse to start,
    /// rather than start with a weaker guarantee than configured).
    #[serde(default)]
    pub ca_bundle_path: Option<String>,
    /// Path to a PEM-encoded client certificate this reader presents to the usage service for
    /// mTLS (#347), e.g. `/etc/lightbridge/tls/tls.crt` -- the same certificate this pod already
    /// mounts for its own server listener (`Tls::cert_path`), reused as a client identity
    /// because the deployed cert already carries both `serverAuth` and `clientAuth` in its
    /// `extendedKeyUsage` (confirmed against the live cluster: `kubectl -n converse get
    /// certificate authz-tls -o yaml` shows `usages: [server auth, client auth]`). Must be set
    /// together with `client_key_path` below -- setting exactly one of the two is a hard
    /// construction error, never a silent "connect without an identity" fallback. Both unset
    /// (the default) means this reader presents no client certificate, exactly as before #347.
    #[serde(default)]
    pub client_cert_path: Option<String>,
    /// Private key matching `client_cert_path` above, e.g. `/etc/lightbridge/tls/tls.key`. See
    /// that field's doc comment.
    #[serde(default)]
    pub client_key_path: Option<String>,
    /// Per-request timeout in milliseconds. Defaults to 5000 (5s).
    #[serde(default = "default_usage_service_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_usage_service_timeout_ms() -> u64 {
    5_000
}

/// Redis connection settings. `url` is a standard `redis://[:password@]host:port[/db]`
/// connection string, e.g. `redis://redis:6379` in Compose or `redis://localhost:6379`
/// for non-container local runs (see `config/default.yaml`, `.docker/authz/container.yaml`),
/// or `rediss://[:password@]host:port[/db]` for TLS (lightbridge-authz#363) — real
/// deployments talk to the cluster's TLS-only `redis-ha`.
#[derive(Debug, Clone, Deserialize)]
pub struct Redis {
    pub url: String,
    /// PEM file trusted as the sole root when `url` uses `rediss://`. `redis-ha`'s TLS
    /// listener presents a certificate signed by the cluster's internal self-signed CA
    /// (the same `ClusterIssuer/self-signed-ca` root as `usage_service.ca_bundle_path` and
    /// the `authz-tls` Secret's `ca.crt` already mounted at `/etc/lightbridge/tls/ca.crt`),
    /// which is never in the OS/public trust store, so this is required whenever `url` is
    /// `rediss://` — see `redis_tls::build_redis_client`. `redis-ha` requires no client
    /// certificate (`tls-auth-clients no`), so unlike `usage_service` there is no
    /// `client_cert_path`/`client_key_path` pair here. Ignored for plain `redis://` URLs
    /// (local Compose). An unreadable or unparseable path, like every other CA-bundle
    /// config in this codebase, is a hard startup failure, never a silent fallback.
    #[serde(default)]
    pub ca_bundle_path: Option<String>,
}

/// Credential-issuance mode. REQUIRED and has no default — the operator must state it explicitly,
/// because it decides how every API key is minted. `self` mints self-signed JWTs via
/// `oauth2.signing`; `external` exchanges the credential at an upstream IdP (e.g. Keycloak) via
/// `oauth2.issuance`. The two are mutually exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Oauth2Type {
    #[serde(rename = "self")]
    SelfSigned,
    External,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Oauth2 {
    /// REQUIRED credential-issuance mode (`self` or `external`). No default — a missing `type`
    /// fails config load rather than silently picking a mode.
    #[serde(rename = "type")]
    pub oauth2_type: Oauth2Type,
    pub jwks_url: String,
    #[serde(default)]
    pub oauth2_url: Option<String>,
    #[serde(default)]
    pub issuer_url: Option<String>,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    #[serde(default)]
    pub issuance: Option<Oauth2Issuance>,
    /// Expected audience(s) for JWT validation. If set, the JWT's `aud` claim must
    /// contain at least one of these values. Can be a single value or multiple values.
    #[serde(default)]
    pub audience: Option<Vec<String>>,
    /// Optional self-signing config: when enabled, issued API keys are RS256 JWTs signed
    /// by this service (rather than opaque secrets or Keycloak-exchanged tokens).
    #[serde(default)]
    pub signing: Option<JwtSigning>,
    /// Optional native RFC 8693 token-exchange: when enabled, this service exchanges an
    /// upstream IdP access token for a short-lived, project-scoped self-signed JWT (and an
    /// optional refresh token). Requires `type: self` (the exchanged token is signed by this
    /// service). Independent of `issuance`, which proxies exchange to an upstream IdP.
    #[serde(default)]
    pub token_exchange: Option<Oauth2TokenExchange>,
    /// Role-based access control: which JWT claim carries the caller's roles and how those roles
    /// map to permissions. When omitted, the built-in default mapping is used
    /// (`crate::authz::default_role_permissions`).
    #[serde(default)]
    pub rbac: crate::authz::Rbac,
    /// Real, config-sourced OAuth2/OIDC clients permitted to use the native token-exchange
    /// endpoint (ADR-0011, Decision 5). Sourced from YAML only -- no database table, no
    /// cratestack model (see that decision's revisit trigger: self-service client registration,
    /// not needed today). Empty by default: token-exchange with no registered clients means every
    /// request fails client authentication (`invalid_client`), not that the endpoint is
    /// unprotected. Mapped onto `authkestra_op::client::ClientRegistration` in
    /// `lightbridge_authz_rest::oauth2_op` (kept out of this crate so `core` never depends on
    /// `authkestra-op`).
    #[serde(default)]
    pub clients: Vec<OauthClient>,
}

/// A registered OAuth2/OIDC client (ADR-0011, Decision 5). Mirrors
/// `authkestra_op::client::ClientRegistration`'s 9 fields minus the two this service never needs:
/// `client_secret_hash` (always `None` -- Decision 6 bans secret-based client auth outright) and
/// `redirect_uris` (always empty -- these are machine clients presenting a `subject_token` they
/// already hold, never a browser running the authorization-code flow this service structurally
/// never serves; see ADR-0011 Context).
#[derive(Debug, Clone, Deserialize)]
pub struct OauthClient {
    pub client_id: String,
    /// `public` (no client authentication beyond the `client_id` itself) or `confidential`
    /// (`private_key_jwt` only -- ADR-0011 Decision 6 bans `client_secret_basic`/
    /// `client_secret_post` for every client this service registers).
    #[serde(rename = "type")]
    pub client_type: OauthClientType,
    /// Scopes this client may request. Intersected with `Oauth2TokenExchange.allowed_scopes` (the
    /// server-wide ceiling) at exchange/refresh time -- neither list alone is authoritative.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Grant types this client may use, as raw RFC 8693/OAuth2 grant-type strings (e.g.
    /// `"urn:ietf:params:oauth:grant-type:token-exchange"`, `"refresh_token"`). Only those two are
    /// ever meaningful here -- this service never runs `authorization_code` or the device flow (no
    /// user store, ADR-0011 Context) -- but the list is not restricted at the config-parsing layer
    /// so an operator typo surfaces as "client not authorized for this grant type" at request time
    /// rather than a silent config-load failure.
    #[serde(default)]
    pub grant_types: Vec<String>,
    /// Downstream audiences this client may request via the token-exchange `audience` parameter.
    /// Per ADR-0011 Decision 5 the minted access token's `aud`/`azp` default to this client's own
    /// `client_id` when no `audience` is requested; requesting anything else requires it to be
    /// listed here.
    #[serde(default)]
    pub allowed_audiences: Vec<String>,
    /// Inline JWK Set (`{"keys": [...]}`) -- the public half of a `confidential` client's keypair,
    /// used to verify its `private_key_jwt` client assertions (RFC 7523 §2.2). Required for
    /// `confidential` clients, ignored for `public` ones. Deliberately no `jwks_uri` counterpart
    /// (ADR-0011 Decision 6): this service takes no HTTP-client dependency for client
    /// authentication, so a confidential client's public key is a config value, not a fetch.
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,
}

/// A client's authentication method at the token endpoint (ADR-0011, Decision 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OauthClientType {
    Public,
    Confidential,
}

impl Oauth2 {
    pub fn is_self_signed(&self) -> bool {
        matches!(self.oauth2_type, Oauth2Type::SelfSigned)
    }

    pub fn is_external(&self) -> bool {
        matches!(self.oauth2_type, Oauth2Type::External)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtSigning {
    /// `iss` claim and the OIDC issuer URL Authorino discovers the JWKS from.
    pub issuer: String,
    /// Optional `aud` claim stamped on issued tokens.
    #[serde(default)]
    pub audience: Option<String>,
    /// Default token lifetime in seconds and the hard cap on any frontend-requested expiry.
    #[serde(default = "default_signing_ttl_seconds")]
    pub ttl_seconds: i64,
    /// Auto-rotate the active signing key once it is older than this many days (checked at
    /// startup). The rotated-out key is marked stale and kept in the JWKS for verification.
    #[serde(default = "default_max_key_age_days")]
    pub max_key_age_days: i64,
}

fn default_signing_ttl_seconds() -> i64 {
    7_776_000
}

fn default_max_key_age_days() -> i64 {
    30
}

#[derive(Debug, Clone, Deserialize)]
pub struct Oauth2Issuance {
    #[serde(default)]
    pub grant_type: Option<String>,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub subject_token_type: Option<String>,
    #[serde(default)]
    pub requested_token_type: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Oauth2TokenExchange {
    #[serde(default)]
    pub enabled: bool,
    /// Lifetime of the exchanged access JWT, in seconds. Kept short (session-scoped) because
    /// these tokens are only revocable by expiry; renewal flows through the refresh token.
    #[serde(default = "default_exchange_access_ttl_seconds")]
    pub access_ttl_seconds: i64,
    /// Lifetime of an issued refresh token, in seconds. Refresh tokens are stored hashed and are
    /// revocable, so they carry the long-lived session; only minted when `offline_access` is
    /// requested and permitted.
    #[serde(default = "default_exchange_refresh_ttl_seconds")]
    pub refresh_ttl_seconds: i64,
    /// Scopes a client may request on exchange. `offline_access` gates refresh-token issuance.
    #[serde(default = "default_exchange_allowed_scopes")]
    pub allowed_scopes: Vec<String>,
    /// Absolute cap on a refresh-token *chain*'s lifetime, in seconds, independent of
    /// `refresh_ttl_seconds`. Each rotation resets the individual token's own `expires_at` to
    /// `now() + refresh_ttl_seconds`, so without this a session that keeps refreshing before
    /// every expiry never actually ends -- this is the ceiling that stops it. Set once, when a
    /// chain is born (the offline-scope exchange grant), and inherited unchanged by every
    /// rotation thereafter (`exchange_refresh_tokens.chain_expires_at`); a refresh presented
    /// after this deadline is refused with `invalid_grant` regardless of the individual token's
    /// own remaining `expires_at`. Defaults to 90 days -- longer than `refresh_ttl_seconds`'
    /// 30-day default (a session that refreshes at least once a month lives up to 3 rotations
    /// past the individual TTL before hitting the cap), short enough that a forgotten/leaked
    /// session cannot outlive it indefinitely.
    #[serde(default = "default_exchange_refresh_absolute_ttl_seconds")]
    pub refresh_absolute_ttl_seconds: i64,
}

fn default_exchange_access_ttl_seconds() -> i64 {
    900
}

fn default_exchange_refresh_ttl_seconds() -> i64 {
    2_592_000
}

fn default_exchange_refresh_absolute_ttl_seconds() -> i64 {
    7_776_000
}

fn default_exchange_allowed_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
        "offline_access".to_string(),
    ]
}

pub fn load_from_path<P: AsRef<std::path::Path>>(path: P) -> Result<Config> {
    load_yaml_from_path(path)
}

pub fn load_yaml_from_path<T, P>(path: P) -> Result<T>
where
    T: DeserializeOwned,
    P: AsRef<std::path::Path>,
{
    let content = read_to_string(path)?;
    let interpolated = interpolate_env_vars(&content);
    let cfg: T = from_str(&interpolated)?;
    Ok(cfg)
}

/// Interpolates environment variables in the given string.
/// Supports:
/// - $VAR
/// - ${VAR}
/// - ${VAR-default}
/// - ${VAR:-default}
///
/// Behavior mostly matches GNU envsubst:
/// - unresolved variables are replaced with an empty string
///
/// It additionally supports a subset of shell default expansion to make config
/// defaults ergonomic without external preprocessing.
fn interpolate_env_vars(content: &str) -> String {
    RE.replace_all(content, |caps: &Captures| {
        if let Some(var_name) = caps.get(1) {
            // $VAR
            env::var(var_name.as_str()).unwrap_or_default()
        } else if let Some(var_name) = caps.get(2) {
            // ${VAR}, ${VAR-default}, ${VAR:-default}
            let name = var_name.as_str();
            let operator = caps.get(3).map(|m| m.as_str());
            let default_value = caps.get(4).map(|m| m.as_str()).unwrap_or_default();

            match operator {
                None => env::var(name).unwrap_or_default(),
                Some("-") => env::var(name).unwrap_or_else(|_| default_value.to_string()),
                Some(":-") => match env::var(name) {
                    Ok(value) if !value.is_empty() => value,
                    _ => default_value.to_string(),
                },
                Some(_) => caps
                    .get(0)
                    .expect("capture group 0 always exists on a match")
                    .as_str()
                    .to_string(),
            }
        } else {
            caps.get(0)
                .expect("capture group 0 always exists on a match")
                .as_str()
                .to_string()
        }
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_interpolate_env_vars() {
        unsafe {
            env::set_var("TEST_VAR", "foo");
            env::set_var("TEST_VAR_2", "bar");
            env::set_var("EMPTY_VAR", "");
        }

        // $VAR
        assert_eq!(interpolate_env_vars("$TEST_VAR"), "foo");
        assert_eq!(
            interpolate_env_vars("prefix_$TEST_VAR.suffix"),
            "prefix_foo.suffix"
        );

        // ${VAR}
        assert_eq!(interpolate_env_vars("${TEST_VAR}"), "foo");
        assert_eq!(
            interpolate_env_vars("prefix_${TEST_VAR}_suffix"),
            "prefix_foo_suffix"
        );

        // Mixed
        assert_eq!(
            interpolate_env_vars("$TEST_VAR and ${TEST_VAR_2} and $NON_EXISTENT"),
            "foo and bar and "
        );

        // Not set -> empty string
        assert_eq!(interpolate_env_vars("$NOT_SET"), "");
        assert_eq!(interpolate_env_vars("${NOT_SET}"), "");

        // ${VAR-default} and ${VAR:-default}
        assert_eq!(interpolate_env_vars("${TEST_VAR-default}"), "foo");
        assert_eq!(interpolate_env_vars("${NOT_SET-default}"), "default");
        assert_eq!(interpolate_env_vars("${EMPTY_VAR-default}"), "");
        assert_eq!(interpolate_env_vars("${TEST_VAR:-default}"), "foo");
        assert_eq!(interpolate_env_vars("${NOT_SET:-default}"), "default");
        assert_eq!(interpolate_env_vars("${EMPTY_VAR:-default}"), "default");

        // Unsupported syntax remains unchanged
        assert_eq!(
            interpolate_env_vars("${TEST_VAR:default}"),
            "${TEST_VAR:default}"
        );
        assert_eq!(
            interpolate_env_vars("${NON_EXISTENT:default_with_spaces}"),
            "${NON_EXISTENT:default_with_spaces}"
        );

        unsafe {
            env::remove_var("TEST_VAR");
            env::remove_var("TEST_VAR_2");
            env::remove_var("EMPTY_VAR");
        }
    }

    #[test]
    fn oauth2_type_self_parses() {
        let cfg: Oauth2 = from_str("type: self\njwks_url: \"http://x\"\n").unwrap();
        assert_eq!(cfg.oauth2_type, Oauth2Type::SelfSigned);
        assert!(cfg.is_self_signed());
        assert!(!cfg.is_external());
    }

    #[test]
    fn oauth2_type_external_parses() {
        let cfg: Oauth2 = from_str("type: external\njwks_url: \"http://x\"\n").unwrap();
        assert_eq!(cfg.oauth2_type, Oauth2Type::External);
        assert!(cfg.is_external());
    }

    #[test]
    fn oauth2_type_is_required_no_default() {
        let err = from_str::<Oauth2>("jwks_url: \"http://x\"\n").unwrap_err();
        assert!(
            err.to_string().contains("type"),
            "missing oauth2.type must fail config load, got: {err}"
        );
    }

    #[test]
    fn oauth2_type_rejects_unknown_value() {
        assert!(from_str::<Oauth2>("type: opaque\njwks_url: \"http://x\"\n").is_err());
    }

    #[test]
    fn billing_plans_parse_from_json_env_string() {
        let json = r#"[{"id":"free","name":"Free","limits":{"requests_per_second":5,"requests_per_month":10000}},{"id":"pro","name":"Pro"}]"#;
        let billing: Billing = from_str(&format!("plans: '{json}'\n")).unwrap();
        assert_eq!(billing.plan_ids(), vec!["free", "pro"]);
        assert!(billing.is_allowed("pro"));
        assert!(!billing.is_allowed("scale"));
        assert!(!billing.is_allowed(""));

        let free = billing.get("free").unwrap();
        assert_eq!(free.name, "Free");
        let limits = free.limits.as_ref().unwrap();
        assert_eq!(limits.requests_per_second, Some(5));
        assert_eq!(limits.requests_per_month, Some(10000));
        assert_eq!(limits.concurrent_requests, None);
        assert!(billing.get("pro").unwrap().limits.is_none());
    }

    #[test]
    fn billing_plans_parse_from_inline_sequence() {
        let yaml = "plans:\n  - id: free\n    name: Free\n  - id: pro\n    name: Pro\n    limits:\n      concurrent_requests: 20\n";
        let billing: Billing = from_str(yaml).unwrap();
        assert_eq!(billing.plan_ids(), vec!["free", "pro"]);
        assert_eq!(
            billing
                .get("pro")
                .unwrap()
                .limits
                .as_ref()
                .unwrap()
                .concurrent_requests,
            Some(20)
        );
    }

    #[test]
    fn billing_plans_empty_when_unset() {
        let billing: Billing = from_str("{}\n").unwrap();
        assert!(billing.plans.is_empty());
        assert!(!billing.is_allowed("free"));

        let blank: Billing = from_str("plans: \"\"\n").unwrap();
        assert!(blank.plans.is_empty());
    }

    #[test]
    fn billing_plans_null_is_tolerated_as_empty() {
        let via_plans_null: Billing = from_str("plans: null\n").unwrap();
        assert!(via_plans_null.plans.is_empty());

        let via_plans_bare: Billing = from_str("plans:\n").unwrap();
        assert!(via_plans_bare.plans.is_empty());

        #[derive(Deserialize)]
        struct Wrap {
            #[serde(default, deserialize_with = "deserialize_null_default")]
            billing: Billing,
        }
        let via_billing_null: Wrap = from_str("billing:\n").unwrap();
        assert!(via_billing_null.billing.plans.is_empty());
    }

    #[test]
    fn billing_validate_rejects_empty_dup_and_blank_ids() {
        assert!(Billing::default().validate().is_err());

        let dup: Billing =
            from_str("plans:\n  - id: free\n    name: Free\n  - id: free\n    name: Free2\n")
                .unwrap();
        let err = dup.validate().unwrap_err().to_string();
        assert!(err.contains("duplicate plan id 'free'"), "got: {err}");

        let blank: Billing = from_str("plans:\n  - id: \"\"\n    name: Nameless\n").unwrap();
        assert!(
            blank
                .validate()
                .unwrap_err()
                .to_string()
                .contains("empty id")
        );

        let ok: Billing =
            from_str("plans:\n  - id: free\n    name: Free\n  - id: pro\n    name: Pro\n").unwrap();
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn model_catalog_parse_from_json_env_string() {
        let json = r#"[{"id":"dev-model-a","name":"Dev Model A"},{"id":"dev-model-b","name":"Dev Model B"}]"#;
        let catalog: ModelCatalog = from_str(&format!("models: '{json}'\n")).unwrap();
        assert_eq!(catalog.model_ids(), vec!["dev-model-a", "dev-model-b"]);
        assert_eq!(catalog.models[0].name, "Dev Model A");
        assert_eq!(catalog.models[1].name, "Dev Model B");
    }

    #[test]
    fn model_catalog_parse_from_inline_sequence() {
        let yaml = "models:\n  - id: dev-model-a\n    name: Dev Model A\n  - id: dev-model-b\n    name: Dev Model B\n";
        let catalog: ModelCatalog = from_str(yaml).unwrap();
        assert_eq!(catalog.model_ids(), vec!["dev-model-a", "dev-model-b"]);
    }

    #[test]
    fn model_catalog_empty_when_unset() {
        let catalog: ModelCatalog = from_str("{}\n").unwrap();
        assert!(catalog.models.is_empty());

        let blank: ModelCatalog = from_str("models: \"\"\n").unwrap();
        assert!(blank.models.is_empty());
    }

    #[test]
    fn model_catalog_null_is_tolerated_as_empty() {
        let via_models_null: ModelCatalog = from_str("models: null\n").unwrap();
        assert!(via_models_null.models.is_empty());

        let via_models_bare: ModelCatalog = from_str("models:\n").unwrap();
        assert!(via_models_bare.models.is_empty());

        #[derive(Deserialize)]
        struct Wrap {
            #[serde(default, deserialize_with = "deserialize_null_default")]
            models: ModelCatalog,
        }
        let via_wrapper_null: Wrap = from_str("models:\n").unwrap();
        assert!(via_wrapper_null.models.models.is_empty());
    }

    // #415 (ADR-0018 Decision 5): `ModelCatalog::invalid_ids` is the validation `setProjectAllowedModels`
    // gates on. Mirrors `QuotaTiers::is_allowed`'s own test shape (configured/rejected/`None`/empty)
    // one section up, adjusted for "a list, not a scalar, so name the offending entries".
    fn configured_catalog() -> ModelCatalog {
        ModelCatalog {
            models: vec![
                ModelCatalogEntry {
                    id: "gpt-4.1-mini".to_string(),
                    name: "GPT-4.1 Mini".to_string(),
                },
                ModelCatalogEntry {
                    id: "claude-3.7".to_string(),
                    name: "Claude 3.7".to_string(),
                },
            ],
        }
    }

    #[test]
    fn model_catalog_invalid_ids_accepts_configured_entries() {
        let catalog = configured_catalog();
        let models = vec!["gpt-4.1-mini".to_string(), "claude-3.7".to_string()];
        assert!(catalog.invalid_ids(Some(&models)).is_empty());
    }

    #[test]
    fn model_catalog_invalid_ids_names_unconfigured_entries() {
        let catalog = configured_catalog();
        let models = vec![
            "gpt-4.1-mini".to_string(),
            "gtp-4.1-typo".to_string(),
            "also-unknown".to_string(),
        ];
        assert_eq!(
            catalog.invalid_ids(Some(&models)),
            vec!["gtp-4.1-typo", "also-unknown"]
        );
    }

    #[test]
    fn model_catalog_invalid_ids_deduplicates_the_same_bad_entry() {
        let catalog = configured_catalog();
        let models = vec!["typo".to_string(), "typo".to_string()];
        assert_eq!(catalog.invalid_ids(Some(&models)), vec!["typo"]);
    }

    #[test]
    fn model_catalog_invalid_ids_allows_none() {
        let catalog = configured_catalog();
        assert!(catalog.invalid_ids(None).is_empty());
    }

    #[test]
    fn model_catalog_invalid_ids_accepts_anything_when_catalogue_is_empty() {
        let catalog = ModelCatalog::default();
        let models = vec!["anything-goes".to_string()];
        assert!(
            catalog.invalid_ids(Some(&models)).is_empty(),
            "an empty/absent catalogue must accept any value, same default as QuotaTiers::is_allowed"
        );
    }

    // lightbridge-authz#395: unlike `QuotaTiers`/`ModelCatalog` above, `ApiKeyExpiry` must default
    // to a real, conservative ceiling (90 days) rather than "accept anything" when the config
    // block is entirely absent -- mirrors the null-tolerance tests above but asserts the opposite
    // failure-mode requirement (default is restrictive, not permissive).
    #[test]
    fn api_key_expiry_defaults_to_ninety_days_when_unset() {
        let cfg: ApiKeyExpiry = from_str("{}\n").unwrap();
        assert_eq!(cfg.max_lifetime_days, 90);
        assert_eq!(ApiKeyExpiry::default().max_lifetime_days, 90);
    }

    #[test]
    fn api_key_expiry_null_is_tolerated_as_the_default_not_unlimited() {
        #[derive(Deserialize)]
        struct Wrap {
            #[serde(default, deserialize_with = "deserialize_null_default")]
            api_key_expiry: ApiKeyExpiry,
        }
        let via_wrapper_null: Wrap = from_str("api_key_expiry:\n").unwrap();
        assert_eq!(via_wrapper_null.api_key_expiry.max_lifetime_days, 90);
    }

    #[test]
    fn api_key_expiry_parses_a_configured_ceiling() {
        let cfg: ApiKeyExpiry = from_str("max_lifetime_days: 30\n").unwrap();
        assert_eq!(cfg.max_lifetime_days, 30);
    }

    #[test]
    fn api_key_expiry_validate_rejects_zero() {
        let err = ApiKeyExpiry {
            max_lifetime_days: 0,
        }
        .validate()
        .unwrap_err();
        assert!(format!("{err}").contains("must be greater than 0"));
    }

    #[test]
    fn api_key_expiry_validate_accepts_the_default() {
        assert!(ApiKeyExpiry::default().validate().is_ok());
    }

    #[test]
    fn config_without_redis_or_usage_service_still_loads() {
        let yaml = "\
server:
  api:
    address: \"0.0.0.0\"
    port: 3000
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
  opa:
    address: \"0.0.0.0\"
    port: 3001
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
    basic_auth:
      username: \"u\"
      password: \"p\"
logging:
  level: \"info\"
database:
  url: \"postgres://postgres:postgres@localhost:5432/lightbridge_authz\"
oauth2:
  type: self
  jwks_url: \"http://localhost/jwks\"
otel:
  enabled: true
  otlp_endpoint: \"http://localhost:4317\"
  service_name: \"svc\"
";
        let cfg: Config = from_str(yaml).expect("config omitting redis/usage_service must load");
        assert!(cfg.redis.is_none());
        assert!(cfg.usage_service.is_none());
        assert!(
            cfg.server.idp.is_none(),
            "a config file written before authz-idp existed must keep loading, with idp unset"
        );
        assert!(
            cfg.server.budget.is_none(),
            "a config file written before authz-budget existed must keep loading, with budget unset"
        );
    }

    #[test]
    fn config_with_budget_server_parses_it() {
        let yaml = "\
server:
  api:
    address: \"0.0.0.0\"
    port: 3000
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
  opa:
    address: \"0.0.0.0\"
    port: 3001
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
    basic_auth:
      username: \"u\"
      password: \"p\"
  budget:
    address: \"0.0.0.0\"
    port: 3005
    tls:
      cert_path: \"budget.crt\"
      key_path: \"budget.key\"
logging:
  level: \"info\"
database:
  url: \"postgres://postgres:postgres@localhost:5432/lightbridge_authz\"
oauth2:
  type: self
  jwks_url: \"http://localhost/jwks\"
otel:
  enabled: true
  otlp_endpoint: \"http://localhost:4317\"
  service_name: \"svc\"
";
        let cfg: Config = from_str(yaml).expect("config with server.budget must load");
        let budget = cfg.server.budget.expect("server.budget must be set");
        assert_eq!(budget.address, "0.0.0.0");
        assert_eq!(budget.port, 3005);
        assert_eq!(budget.tls.cert_path, "budget.crt");
        assert_eq!(budget.tls.key_path, "budget.key");
    }

    #[test]
    fn config_with_idp_server_parses_it() {
        let yaml = "\
server:
  api:
    address: \"0.0.0.0\"
    port: 3000
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
  opa:
    address: \"0.0.0.0\"
    port: 3001
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
    basic_auth:
      username: \"u\"
      password: \"p\"
  idp:
    address: \"0.0.0.0\"
    port: 3004
    tls:
      cert_path: \"idp.crt\"
      key_path: \"idp.key\"
logging:
  level: \"info\"
database:
  url: \"postgres://postgres:postgres@localhost:5432/lightbridge_authz\"
oauth2:
  type: self
  jwks_url: \"http://localhost/jwks\"
otel:
  enabled: true
  otlp_endpoint: \"http://localhost:4317\"
  service_name: \"svc\"
";
        let cfg: Config = from_str(yaml).expect("config with server.idp must load");
        let idp = cfg.server.idp.expect("server.idp must be set");
        assert_eq!(idp.address, "0.0.0.0");
        assert_eq!(idp.port, 3004);
        assert_eq!(idp.tls.cert_path, "idp.crt");
        assert_eq!(idp.tls.key_path, "idp.key");
    }

    #[test]
    fn config_with_usage_service_parses_it() {
        let yaml = "\
server:
  api:
    address: \"0.0.0.0\"
    port: 3000
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
  opa:
    address: \"0.0.0.0\"
    port: 3001
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
    basic_auth:
      username: \"u\"
      password: \"p\"
logging:
  level: \"info\"
database:
  url: \"postgres://postgres:postgres@localhost:5432/lightbridge_authz\"
usage_service:
  base_url: \"https://authz-usage:3002\"
  insecure_skip_verify: true
  timeout_ms: 2500
oauth2:
  type: self
  jwks_url: \"http://localhost/jwks\"
otel:
  enabled: true
  otlp_endpoint: \"http://localhost:4317\"
  service_name: \"svc\"
";
        let cfg: Config = from_str(yaml).expect("config with usage_service must load");
        let usage_service = cfg.usage_service.expect("usage_service must be set");
        assert_eq!(usage_service.base_url, "https://authz-usage:3002");
        assert!(usage_service.insecure_skip_verify);
        assert_eq!(usage_service.timeout_ms, 2500);
        assert_eq!(usage_service.ca_bundle_path, None);
    }

    #[test]
    fn config_with_usage_service_ca_bundle_path_parses_it() {
        let yaml = "\
server:
  api:
    address: \"0.0.0.0\"
    port: 3000
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
  opa:
    address: \"0.0.0.0\"
    port: 3001
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
    basic_auth:
      username: \"u\"
      password: \"p\"
logging:
  level: \"info\"
database:
  url: \"postgres://postgres:postgres@localhost:5432/lightbridge_authz\"
usage_service:
  base_url: \"https://lightbridge-usage.converse.svc:3000\"
  insecure_skip_verify: false
  ca_bundle_path: \"/etc/lightbridge/tls/ca.crt\"
oauth2:
  type: self
  jwks_url: \"http://localhost/jwks\"
otel:
  enabled: true
  otlp_endpoint: \"http://localhost:4317\"
  service_name: \"svc\"
";
        let cfg: Config =
            from_str(yaml).expect("config with usage_service.ca_bundle_path must load");
        let usage_service = cfg.usage_service.expect("usage_service must be set");
        assert!(!usage_service.insecure_skip_verify);
        assert_eq!(
            usage_service.ca_bundle_path.as_deref(),
            Some("/etc/lightbridge/tls/ca.crt")
        );
    }

    /// lightbridge-authz#363: a `redis:` block with no `ca_bundle_path` (local Compose's plain
    /// `redis://`) must still parse -- the field is optional, defaulting to `None`, not a
    /// required key that would break every existing `redis: { url: ... }` deployment config.
    #[test]
    fn config_with_redis_url_only_parses_ca_bundle_path_as_none() {
        let yaml = "\
server:
  api:
    address: \"0.0.0.0\"
    port: 3000
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
  opa:
    address: \"0.0.0.0\"
    port: 3001
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
    basic_auth:
      username: \"u\"
      password: \"p\"
logging:
  level: \"info\"
database:
  url: \"postgres://postgres:postgres@localhost:5432/lightbridge_authz\"
redis:
  url: \"redis://localhost:6379\"
oauth2:
  type: self
  jwks_url: \"http://localhost/jwks\"
otel:
  enabled: true
  otlp_endpoint: \"http://localhost:4317\"
  service_name: \"svc\"
";
        let cfg: Config = from_str(yaml).expect("config with a plain redis.url must load");
        let redis = cfg.redis.expect("redis must be set");
        assert_eq!(redis.url, "redis://localhost:6379");
        assert_eq!(redis.ca_bundle_path, None);
    }

    /// lightbridge-authz#363: a `rediss://` deployment sets `redis.ca_bundle_path` alongside
    /// `redis.url` -- the shape `redis_tls::build_redis_client` expects.
    #[test]
    fn config_with_redis_ca_bundle_path_parses_it() {
        let yaml = "\
server:
  api:
    address: \"0.0.0.0\"
    port: 3000
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
  opa:
    address: \"0.0.0.0\"
    port: 3001
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
    basic_auth:
      username: \"u\"
      password: \"p\"
logging:
  level: \"info\"
database:
  url: \"postgres://postgres:postgres@localhost:5432/lightbridge_authz\"
redis:
  url: \"rediss://:pw@redis-ha-haproxy.redis-system.svc.cluster.local:6379\"
  ca_bundle_path: \"/etc/lightbridge/tls/ca.crt\"
oauth2:
  type: self
  jwks_url: \"http://localhost/jwks\"
otel:
  enabled: true
  otlp_endpoint: \"http://localhost:4317\"
  service_name: \"svc\"
";
        let cfg: Config = from_str(yaml).expect("config with redis.ca_bundle_path must load");
        let redis = cfg.redis.expect("redis must be set");
        assert_eq!(
            redis.url,
            "rediss://:pw@redis-ha-haproxy.redis-system.svc.cluster.local:6379"
        );
        assert_eq!(
            redis.ca_bundle_path.as_deref(),
            Some("/etc/lightbridge/tls/ca.crt")
        );
    }

    #[test]
    fn config_with_usage_service_client_identity_parses_it() {
        let yaml = "\
server:
  api:
    address: \"0.0.0.0\"
    port: 3000
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
  opa:
    address: \"0.0.0.0\"
    port: 3001
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
    basic_auth:
      username: \"u\"
      password: \"p\"
logging:
  level: \"info\"
database:
  url: \"postgres://postgres:postgres@localhost:5432/lightbridge_authz\"
usage_service:
  base_url: \"https://lightbridge-usage.converse.svc:3006\"
  insecure_skip_verify: false
  ca_bundle_path: \"/etc/lightbridge/tls/ca.crt\"
  client_cert_path: \"/etc/lightbridge/tls/tls.crt\"
  client_key_path: \"/etc/lightbridge/tls/tls.key\"
oauth2:
  type: self
  jwks_url: \"http://localhost/jwks\"
otel:
  enabled: true
  otlp_endpoint: \"http://localhost:4317\"
  service_name: \"svc\"
";
        let cfg: Config =
            from_str(yaml).expect("config with usage_service client identity must load");
        let usage_service = cfg.usage_service.expect("usage_service must be set");
        assert_eq!(
            usage_service.client_cert_path.as_deref(),
            Some("/etc/lightbridge/tls/tls.crt")
        );
        assert_eq!(
            usage_service.client_key_path.as_deref(),
            Some("/etc/lightbridge/tls/tls.key")
        );
    }

    #[test]
    fn config_with_usage_service_defaults_client_identity_to_unset() {
        let yaml = "\
server:
  api:
    address: \"0.0.0.0\"
    port: 3000
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
  opa:
    address: \"0.0.0.0\"
    port: 3001
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
    basic_auth:
      username: \"u\"
      password: \"p\"
logging:
  level: \"info\"
database:
  url: \"postgres://postgres:postgres@localhost:5432/lightbridge_authz\"
usage_service:
  base_url: \"https://lightbridge-usage.converse.svc:3006\"
oauth2:
  type: self
  jwks_url: \"http://localhost/jwks\"
otel:
  enabled: true
  otlp_endpoint: \"http://localhost:4317\"
  service_name: \"svc\"
";
        let cfg: Config =
            from_str(yaml).expect("config with usage_service must load without client identity");
        let usage_service = cfg.usage_service.expect("usage_service must be set");
        assert_eq!(usage_service.client_cert_path, None);
        assert_eq!(usage_service.client_key_path, None);
    }

    #[test]
    fn config_with_usage_service_defaults_insecure_skip_verify_and_timeout() {
        let yaml = "\
server:
  api:
    address: \"0.0.0.0\"
    port: 3000
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
  opa:
    address: \"0.0.0.0\"
    port: 3001
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
    basic_auth:
      username: \"u\"
      password: \"p\"
logging:
  level: \"info\"
database:
  url: \"postgres://postgres:postgres@localhost:5432/lightbridge_authz\"
usage_service:
  base_url: \"https://authz-usage:3002\"
oauth2:
  type: self
  jwks_url: \"http://localhost/jwks\"
otel:
  enabled: true
  otlp_endpoint: \"http://localhost:4317\"
  service_name: \"svc\"
";
        let cfg: Config = from_str(yaml).expect("config with usage_service must load");
        let usage_service = cfg.usage_service.expect("usage_service must be set");
        assert!(!usage_service.insecure_skip_verify);
        assert_eq!(usage_service.timeout_ms, 5_000);
        assert_eq!(usage_service.ca_bundle_path, None);
    }

    // #177: `QuotaTiers::is_allowed` is the enforcement primitive the write paths call. These
    // cover its four cases directly; `crates/lightbridge-authz-rest/src/handlers/mod.rs` carries
    // the corresponding "is it actually wired into a write path" tests.
    fn configured_tiers() -> QuotaTiers {
        QuotaTiers {
            tiers: vec![
                QuotaTier {
                    id: "bronze".to_string(),
                    name: "Bronze".to_string(),
                },
                QuotaTier {
                    id: "gold".to_string(),
                    name: "Gold".to_string(),
                },
            ],
        }
    }

    #[test]
    fn quota_tiers_is_allowed_none_is_always_allowed() {
        assert!(configured_tiers().is_allowed(None));
        assert!(QuotaTiers::default().is_allowed(None));
    }

    #[test]
    fn quota_tiers_is_allowed_empty_catalogue_accepts_anything() {
        let empty = QuotaTiers::default();
        assert!(empty.is_allowed(Some("anything")));
        assert!(empty.is_allowed(Some("medim")));
    }

    #[test]
    fn quota_tiers_is_allowed_accepts_a_configured_id() {
        assert!(configured_tiers().is_allowed(Some("bronze")));
        assert!(configured_tiers().is_allowed(Some("gold")));
    }

    #[test]
    fn quota_tiers_is_allowed_rejects_an_unconfigured_id() {
        assert!(!configured_tiers().is_allowed(Some("medim")));
        assert!(!configured_tiers().is_allowed(Some("")));
    }
}
