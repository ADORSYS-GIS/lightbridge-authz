pub mod authorino;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// RFC 7662 token introspection request (form-encoded).
#[derive(Debug, Deserialize, ToSchema)]
pub struct IntrospectRequest {
    /// The opaque API key to introspect.
    pub token: String,
    /// Optional hint about the token type; ignored (only access tokens are supported).
    #[serde(default)]
    pub token_type_hint: Option<String>,
}

/// RFC 7662 token introspection response. When `active` is false, all other fields are omitted.
#[derive(Debug, Serialize, ToSchema)]
pub struct IntrospectResponse {
    /// Whether the key is currently valid (exists, `Active`, not expired).
    pub active: bool,
    /// Subject of the credential (the API key id).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Owning account id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    /// Owning project id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// The API key id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_id: Option<String>,
    /// The API key status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_status: Option<String>,
    /// Billing plan id the key is minted on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_plan: Option<String>,
    /// Human-facing name of the billing plan, resolved from config (absent when the id is not in
    /// the configured catalogue).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_plan_name: Option<String>,
    /// Rate/usage limits of the billing plan, resolved from config.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_plan_limits: Option<lightbridge_authz_core::config::BillingLimits>,
    /// Models the project is allowed to use (empty/absent means all).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_models: Option<Vec<String>>,
    /// ADR-0018's three-value access-control policy governing which models this project's keys
    /// may reach (`"allow_all"`/`"allowlist"`/`"deny_all"`) -- sourced from the same project row
    /// as `allowed_models` above (no extra query). An unrecognized stored value is parsed
    /// fail-closed to `"deny_all"` by `lightbridge_authz_core::dto::ModelPolicy::from`, never
    /// silently widened to `"allow_all"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_policy: Option<String>,
    /// The project's pooled spending ceiling, from the governance tier catalogue (ADR-0006).
    /// Costs no extra query — it rides on the project row already loaded for `allowed_models` —
    /// and keeps the gateway's `x-project-quota` header sourced from the database rather than from
    /// a claim frozen at mint time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_quota: Option<String>,
    /// The key owner's roster role on the project (`lead`/`member`), absent when they hold no
    /// `project_members` row — normal for the project's owning account, since ownership and roster
    /// membership are separate standings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// The key owner's per-member ceiling from the governance tier catalogue. Absent means no
    /// per-member ceiling applies and the caller is bounded by `project_quota` alone.
    ///
    /// This is what lets Authorino stamp a non-empty `x-quota-tier`, which ai-helm's ADR-0094
    /// rate-limit rules match with an `Exact` selector — without it those rules can never fire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_tier: Option<String>,
    /// Expiry as a Unix timestamp, when the key has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// ADR-0034 §15: this account's live ledger balance for the current period, `ceiling − spend`
    /// in signed, unclamped micro-USD, read from `budget_remaining_snapshots`.
    ///
    /// **Absent means UNKNOWN, and the gateway must read it as such.** There is no snapshot yet,
    /// or the stored one describes a period that has since rolled over, or the read failed. The
    /// AuthConfig publishes `known: false` for an absent value and the Lua refuses with `503
    /// budget_unavailable` — never `402 budget_exhausted`, which would bill a user for our own
    /// latency. Serialising a `0` here instead of omitting the field would be exactly that bug.
    ///
    /// Carrying it on THIS response is what makes the gateway's budget check cost zero extra
    /// calls: it rides on an introspection Authorino already makes, and it costs `authz-opa` one
    /// primary-key probe on a connection it already holds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_remaining_micros: Option<i64>,
    /// When this account's budget next changes on its own — the winning ADR-0032 reset schedule's
    /// `next_run_at`, else midnight UTC on the 1st of the next month. Present exactly when
    /// `budget_remaining_micros` is; it is what the `402` body tells the user to wait for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_next_reset_at: Option<chrono::DateTime<chrono::Utc>>,
    /// How old `budget_remaining_micros` is, in seconds.
    ///
    /// Reported rather than hidden: the single-call design trades freshness for a per-request cost
    /// of one indexed read, and a consumer acting on the number is entitled to see the window it
    /// is acting inside. It is a LOWER bound on staleness — the OTLP ingest lag sits on top of it
    /// and nothing in this process can measure that.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_snapshot_age_seconds: Option<u64>,
}

impl IntrospectResponse {
    /// Builds the canonical inactive response (`{"active": false}`).
    pub fn inactive() -> Self {
        Self {
            active: false,
            sub: None,
            account_id: None,
            project_id: None,
            api_key_id: None,
            api_key_status: None,
            billing_plan: None,
            billing_plan_name: None,
            billing_plan_limits: None,
            allowed_models: None,
            model_policy: None,
            project_quota: None,
            role: None,
            quota_tier: None,
            exp: None,
            budget_remaining_micros: None,
            budget_next_reset_at: None,
            budget_snapshot_age_seconds: None,
        }
    }
}
