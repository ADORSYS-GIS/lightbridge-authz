use axum::Form;
use axum::body::to_bytes;
use axum::http::StatusCode;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use lightbridge_authz_core::identity::AccountId;
use lightbridge_authz_core::{
    Account, ApiKey, ApiKeyStatus, ApiKeyValidation, ModelPolicy, Project, ResolveContextRequest,
    ResolvedContext, ResourceStatus, async_trait,
    config::{BasicAuth, Billing, BillingLimits, BillingPlan},
    error::{Error, Result},
};
use lightbridge_authz_rest::OpaState;
use lightbridge_authz_rest::SessionStatusRow;
use lightbridge_authz_rest::auth_provider::SubjectResolver;
use lightbridge_authz_rest::handlers::idp::resolve_context as resolve_context_endpoint;
use lightbridge_authz_rest::handlers::introspect::introspect_api_key;
use lightbridge_authz_rest::models::IntrospectRequest;
use lightbridge_authz_rest::signing::generate_rs256_key;
use serde::Serialize;
use serde_json::Value;
use std::sync::{Arc, Mutex};

/// ADR-0025 Stage 2: a controllable [`SubjectResolver`] test double for
/// `handlers::idp::resolve_context` -- unlike every other test in this file (which never
/// exercises that handler and so gets a trust-everything default via [`mk_state`]), the two
/// resolve-context tests below need to control resolution outcome directly.
struct MockResolver {
    /// `Ok` resolves to this account id unconditionally; `Err` is cloned into a fresh
    /// `Error::Forbidden` per call (`Error` is not `Clone`, so this stores just the message).
    outcome: std::result::Result<String, String>,
}

#[async_trait]
impl SubjectResolver for MockResolver {
    async fn resolve(&self, _iss: &str, _sub: &str) -> Result<AccountId> {
        match &self.outcome {
            Ok(account_id) => Ok(AccountId::assert_already_resolved(account_id.clone())),
            Err(message) => Err(Error::Forbidden(message.clone())),
        }
    }
}

type UsageCalls = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// Controls what `MockOpaRepo::find_session_status` answers for ADR-0020/#437's session-status
/// check in `resolve_exchange_token_context`. `Active` is the default so every pre-existing
/// exchange-token test above (none of which cares about session revocation) keeps passing
/// unchanged; the session-specific tests near the bottom of this file override it explicitly.
#[derive(Debug, Clone, Default)]
enum MockSessionStatus {
    #[default]
    Active,
    Revoked,
    Expired,
    NotFound,
    /// The fail-closed case (#437's hard requirement): the lookup itself errors, and
    /// `resolve_exchange_token_context` must propagate `Err`, never `Ok(None)`/`Ok(Some(..))`.
    LookupErrors,
}

#[derive(Debug)]
struct MockOpaRepo {
    api_key: Option<ApiKey>,
    project: Option<Project>,
    account: Option<Account>,
    usage_calls: UsageCalls,
    /// Raw JWK JSON this mock's `list_verification_jwks` serves -- what
    /// `handlers::exchange_token::verify_self_issued_token` checks a presented token's signature
    /// against. Empty by default (every API-key-focused test above needs none of this).
    verification_jwks: Vec<Value>,
    /// What `resolve_context` resolves to for the exchange-token tests below. `None` means "not a
    /// member" (`Err(Error::NotFound)`, mirroring the real `StoreRepo::resolve_context`'s own
    /// uniform-404 contract), `Some` means the subject currently resolves to this tenant context.
    member_context: Option<ResolvedContext>,
    /// `project_member_role`/`project_member_quota_tier` mock answers for the exchange-token
    /// tests below.
    member_role: Option<String>,
    member_quota_tier: Option<String>,
    /// ADR-0020/#437: what `find_session_status` answers for the `sid` the presented exchange
    /// token carries. See [`MockSessionStatus`].
    session_status: MockSessionStatus,
    /// ADR-0025: when `Some`, `resolve_context` asserts the `subject` it is called with equals
    /// this value, panicking otherwise -- lets `resolve_context_endpoint_resolves_through_federated_identities`
    /// prove the RESOLVED account id (not the raw presented subject) is what reaches this
    /// repository method. `None` (every other test in this file) skips the check.
    expected_subject: Option<String>,
}

#[async_trait]
impl lightbridge_authz_rest::OpaRepoTrait for MockOpaRepo {
    async fn record_api_key_usage(&self, key_id: &str, ip: Option<String>) -> Result<ApiKey> {
        self.usage_calls
            .lock()
            .expect("lock should work")
            .push((key_id.to_string(), ip));
        Ok(self.api_key.clone().expect("api key should exist in mock"))
    }

    async fn find_api_key_validation_by_hash(
        &self,
        _key_hash: &str,
    ) -> Result<Option<ApiKeyValidation>> {
        let Some(api_key) = self.api_key.clone() else {
            return Ok(None);
        };
        let now = Utc::now();
        let project_suspended = self
            .project
            .as_ref()
            .map(|p| p.status != ResourceStatus::Active)
            .unwrap_or(false);
        let account_suspended = self
            .account
            .as_ref()
            .map(|a| a.status != ResourceStatus::Active)
            .unwrap_or(false);
        let effective_status = if api_key.status != ApiKeyStatus::Active {
            "key_revoked"
        } else if api_key.expires_at.map(|e| e <= now).unwrap_or(false) {
            "key_expired"
        } else if project_suspended {
            "project_suspended"
        } else if account_suspended {
            "account_suspended"
        } else {
            "active"
        };
        Ok(Some(ApiKeyValidation {
            api_key_id: api_key.id.clone(),
            key_hash: api_key.key_hash.clone(),
            project_id: api_key.project_id.clone(),
            account_id: self
                .account
                .as_ref()
                .map(|a| a.id.clone())
                .unwrap_or_default(),
            // A key owned by a roster member rather than the project's owning account, so the
            // per-member tier is populated and reaches `IntrospectResponse.quota_tier`. The
            // owner-owned case (both `None`) is the other half, covered by the mcp fixture.
            owner_account_id: "member-subject".to_string(),
            owner_role: Some("member".to_string()),
            owner_quota_tier: Some("t-s".to_string()),
            api_key_status: api_key.status.to_string(),
            project_status: self
                .project
                .as_ref()
                .map(|p| p.status.to_string())
                .unwrap_or_else(|| "active".to_string()),
            account_status: self
                .account
                .as_ref()
                .map(|a| a.status.to_string())
                .unwrap_or_else(|| "active".to_string()),
            expires_at: api_key.expires_at,
            effective_status: effective_status.to_string(),
        }))
    }

    async fn get_project(&self, _subject: &str, _project_id: &str) -> Result<Option<Project>> {
        Ok(self.project.clone())
    }

    async fn get_account(&self, _subject: &str, _account_id: &str) -> Result<Option<Account>> {
        Ok(self.account.clone())
    }

    async fn get_project_by_id(&self, _project_id: &str) -> Result<Option<Project>> {
        Ok(self.project.clone())
    }

    async fn get_account_by_id(&self, _account_id: &str) -> Result<Option<Account>> {
        Ok(self.account.clone())
    }

    async fn resolve_context(
        &self,
        _subject: &str,
        _project_id: &str,
    ) -> Result<lightbridge_authz_core::ResolvedContext> {
        if let Some(expected) = &self.expected_subject {
            assert_eq!(
                _subject, expected,
                "resolve_context must be called with the RESOLVED account id, never the raw \
                 presented subject"
            );
        }
        self.member_context.clone().ok_or(Error::NotFound)
    }

    async fn project_member_role(
        &self,
        _project_id: &str,
        _subject: &str,
    ) -> Result<Option<String>> {
        Ok(self.member_role.clone())
    }

    async fn project_member_quota_tier(
        &self,
        _project_id: &str,
        _subject: &str,
    ) -> Result<Option<String>> {
        Ok(self.member_quota_tier.clone())
    }

    async fn list_verification_jwks(&self) -> Result<Vec<Value>> {
        Ok(self.verification_jwks.clone())
    }

    async fn find_session_status(&self, _session_id: &str) -> Result<Option<SessionStatusRow>> {
        match self.session_status {
            MockSessionStatus::Active => Ok(Some(SessionStatusRow {
                status: "active".to_string(),
                expires_at: Utc::now() + Duration::hours(1),
            })),
            MockSessionStatus::Revoked => Ok(Some(SessionStatusRow {
                status: "revoked".to_string(),
                expires_at: Utc::now() + Duration::hours(1),
            })),
            MockSessionStatus::Expired => Ok(Some(SessionStatusRow {
                status: "active".to_string(),
                expires_at: Utc::now() - Duration::hours(1),
            })),
            MockSessionStatus::NotFound => Ok(None),
            MockSessionStatus::LookupErrors => {
                Err(Error::Server("session store unreachable".to_string()))
            }
        }
    }
}

fn mk_api_key(status: ApiKeyStatus, expires_at: Option<chrono::DateTime<Utc>>) -> ApiKey {
    ApiKey {
        id: "key_1".to_string(),
        project_id: "proj_1".to_string(),
        name: "demo".to_string(),
        key_prefix: "lbk_demo".to_string(),
        key_hash: "hash".to_string(),
        created_at: Utc::now(),
        expires_at,
        status,
        last_used_at: None,
        last_ip: None,
        revoked_at: None,
        billing_plan: "free".to_string(),
        updated_at: Utc::now(),
    }
}

fn mk_project() -> Project {
    Project {
        id: "proj_1".to_string(),
        account_id: "acct_1".to_string(),
        name: "demo-project".to_string(),
        allowed_models: Some(vec!["gpt-4.1-mini".to_string()]),
        default_limits: None,
        billing_plan: "free".to_string(),
        billing_identity: "acme".to_string(),
        project_quota: None,
        status: ResourceStatus::Active,
        is_default: false,
        model_policy: ModelPolicy::AllowAll,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn mk_account() -> Account {
    Account {
        id: "acct_1".to_string(),
        // A home account owns itself (`user_id == id`) -- the ADR-0026 invariant the
        // `userId == auth().id` read policy rests on.
        user_id: "acct_1".to_string(),
        default_quota: None,
        status: ResourceStatus::Active,
        name: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn mk_state(repo: MockOpaRepo) -> Arc<OpaState> {
    Arc::new(OpaState {
        repo: Arc::new(repo),
        basic_auth: BasicAuth {
            username: "authorino".to_string(),
            password: "change-me".to_string(),
        },
        billing: Arc::new(Billing {
            plans: vec![BillingPlan {
                id: "free".to_string(),
                name: "Free".to_string(),
                limits: Some(BillingLimits {
                    requests_per_second: Some(5),
                    requests_per_day: Some(1000),
                    requests_per_month: None,
                    concurrent_requests: Some(2),
                }),
            }],
        }),
        api_key_audience: Some(TEST_API_KEY_AUDIENCE.to_string()),
        // Trust-everything default: none of the pre-existing tests in this file exercise
        // `handlers::idp::resolve_context` (the one handler that actually calls this) --
        // `resolve_context_endpoint_resolves_through_federated_identities` and
        // `returns_404_not_403_for_an_unfederated_subject` below build their own `OpaState`
        // directly with a [`MockResolver`] instead of going through this helper.
        resolver: Arc::new(MockResolver {
            outcome: Ok("acct_1".to_string()),
        }),
        federation_issuer: "https://keycloak.example.test/realms/dev".to_string(),
    })
}

fn mk_state_with_resolver(repo: MockOpaRepo, resolver: MockResolver) -> Arc<OpaState> {
    Arc::new(OpaState {
        repo: Arc::new(repo),
        basic_auth: BasicAuth {
            username: "authorino".to_string(),
            password: "change-me".to_string(),
        },
        billing: Arc::new(Billing {
            plans: vec![BillingPlan {
                id: "free".to_string(),
                name: "Free".to_string(),
                limits: None,
            }],
        }),
        api_key_audience: None,
        resolver: Arc::new(resolver),
        federation_issuer: "https://keycloak.example.test/realms/dev".to_string(),
    })
}

fn bare_mock_opa_repo(member_context: Option<ResolvedContext>) -> MockOpaRepo {
    MockOpaRepo {
        api_key: None,
        project: None,
        account: None,
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: vec![],
        member_context,
        member_role: None,
        member_quota_tier: None,
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    }
}

/// ADR-0025 Stage 2: `handlers::idp::resolve_context` translates the presented `(issuer, subject)`
/// through `SubjectResolver` before ever reaching `StoreRepo::resolve_context` -- proves the
/// resolved account id (not the raw presented subject) is what reaches the tenant-context lookup
/// and comes back on the wire.
#[tokio::test]
async fn resolve_context_endpoint_resolves_through_federated_identities() {
    let context = ResolvedContext {
        account_id: "resolved-acct".to_string(),
        project_id: "proj_1".to_string(),
    };
    // `expected_subject` makes the mock PANIC (failing the test) unless
    // `StoreRepo::resolve_context` is called with the RESOLVED value, never the raw presented
    // "kc-sub-1" -- the two are deliberately DIFFERENT strings here so a call site that forwards
    // the raw subject cannot pass by coincidence.
    let mut repo = bare_mock_opa_repo(Some(context));
    repo.expected_subject = Some("resolved-acct".to_string());
    let state = mk_state_with_resolver(
        repo,
        MockResolver {
            outcome: Ok("resolved-acct".to_string()),
        },
    );

    let response = resolve_context_endpoint(
        axum::extract::State(state),
        axum::Json(ResolveContextRequest {
            subject: Some("kc-sub-1".to_string()),
            project_id: Some("proj_1".to_string()),
            issuer: Some("https://keycloak.example.test/realms/dev".to_string()),
        }),
    )
    .await
    .expect("a resolvable subject must succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should be readable");
    let payload: ResolvedContext =
        serde_json::from_slice(&body).expect("body should decode as ResolvedContext");
    assert_eq!(payload.account_id, "resolved-acct");
    assert_eq!(payload.project_id, "proj_1");
}

/// THE non-leaking-oracle test: a resolver refusal (untrusted issuer, or no federated identity/
/// no grandfathered account) must map to the exact same uniform `Error::NotFound` this endpoint's
/// own not-a-member branch already returns -- never a distinct status a caller could use to
/// distinguish "wrong issuer"/"no such account" from "not a member of this project".
#[tokio::test]
async fn returns_404_not_403_for_an_unfederated_subject() {
    // `member_context: Some(..)` deliberately: if the endpoint ever stopped calling the resolver
    // (or ignored its error) and fell through to `resolve_context` directly, this mock would
    // happily return a context and the test would observe a 200, not the expected refusal --
    // proving the 404 here comes from the RESOLVER, not from a downstream not-a-member miss.
    let state = mk_state_with_resolver(
        bare_mock_opa_repo(Some(ResolvedContext {
            account_id: "should-never-be-reached".to_string(),
            project_id: "proj_1".to_string(),
        })),
        MockResolver {
            outcome: Err("no federated identity for this subject".to_string()),
        },
    );

    let err = resolve_context_endpoint(
        axum::extract::State(state),
        axum::Json(ResolveContextRequest {
            subject: Some("unfederated-sub".to_string()),
            project_id: Some("proj_1".to_string()),
            issuer: Some("https://untrusted-issuer.example".to_string()),
        }),
    )
    .await
    .expect_err("a resolver refusal must surface as an error, not a 200");

    assert!(
        matches!(err, Error::NotFound),
        "a resolver Forbidden must map to the SAME uniform NotFound resolve_context's own \
         not-a-member branch returns -- never a distinct status that would let a caller \
         distinguish \"wrong issuer\"/\"no such account\" from \"not a member\", got {err:?}"
    );
}

async fn introspect(state: Arc<OpaState>, token: &str) -> (StatusCode, Value) {
    let response = introspect_api_key(
        axum::extract::State(state),
        Form(IntrospectRequest {
            token: token.to_string(),
            token_type_hint: Some("access_token".to_string()),
        }),
    )
    .await
    .expect("handler should return response");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should be readable");
    let payload: Value = serde_json::from_slice(&body).expect("body should be valid json");
    (status, payload)
}

#[tokio::test]
async fn introspect_returns_active_with_context_and_records_usage() {
    let expires_at = Utc::now() + Duration::minutes(10);
    let usage_calls = Arc::new(Mutex::new(vec![]));
    let state = mk_state(MockOpaRepo {
        api_key: Some(mk_api_key(ApiKeyStatus::Active, Some(expires_at))),
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: usage_calls.clone(),
        verification_jwks: Vec::new(),
        member_context: None,
        member_role: None,
        member_quota_tier: None,
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, "lbk_secret_valid").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], true);
    assert_eq!(payload["account_id"], "acct_1");
    assert_eq!(payload["project_id"], "proj_1");
    assert_eq!(payload["api_key_id"], "key_1");
    assert_eq!(payload["api_key_status"], "active");
    assert_eq!(payload["billing_plan"], "free");
    assert_eq!(payload["billing_plan_name"], "Free");
    assert_eq!(payload["billing_plan_limits"]["requests_per_second"], 5);
    assert_eq!(payload["billing_plan_limits"]["concurrent_requests"], 2);
    assert!(
        payload["billing_plan_limits"]
            .get("requests_per_month")
            .is_none(),
        "unset limit fields must be omitted"
    );
    assert_eq!(
        payload["allowed_models"],
        serde_json::json!(["gpt-4.1-mini"])
    );
    assert_eq!(
        payload["model_policy"], "allow_all",
        "the default policy must be reflected on the wire as the default project's model_policy"
    );
    assert_eq!(payload["exp"], expires_at.timestamp());

    // The per-member governance tier, resolved from the key OWNER's `project_members` row. This is
    // the field Authorino stamps as `x-quota-tier`, which ai-helm's ADR-0094 rate-limit rules match
    // with an `Exact` selector — if it stops being returned those rules silently never fire, and
    // per-member ceilings go unenforced with nothing failing. Hence asserted here explicitly.
    assert_eq!(payload["quota_tier"], "t-s");
    assert_eq!(payload["role"], "member");

    let calls = usage_calls.lock().expect("lock should work").clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "key_1");
}

#[tokio::test]
async fn introspect_omits_name_and_limits_for_plan_absent_from_catalogue() {
    let mut api_key = mk_api_key(ApiKeyStatus::Active, None);
    api_key.billing_plan = "removed-plan".to_string();
    let state = mk_state(MockOpaRepo {
        api_key: Some(api_key),
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: Vec::new(),
        member_context: None,
        member_role: None,
        member_quota_tier: None,
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, "lbk_secret_valid").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], true);
    assert_eq!(
        payload["billing_plan"], "removed-plan",
        "the stored plan id is always returned"
    );
    assert!(
        payload.get("billing_plan_name").is_none(),
        "an id not in the catalogue resolves to no name"
    );
    assert!(
        payload.get("billing_plan_limits").is_none(),
        "an id not in the catalogue resolves to no limits"
    );
}

#[tokio::test]
async fn introspect_returns_inactive_when_revoked() {
    let state = mk_state(MockOpaRepo {
        api_key: Some(mk_api_key(ApiKeyStatus::Revoked, None)),
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: Vec::new(),
        member_context: None,
        member_role: None,
        member_quota_tier: None,
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, "lbk_secret_revoked").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
    assert!(payload.get("account_id").is_none());
    assert!(payload.get("api_key_id").is_none());
}

#[tokio::test]
async fn introspect_returns_inactive_when_missing() {
    let state = mk_state(MockOpaRepo {
        api_key: None,
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: Vec::new(),
        member_context: None,
        member_role: None,
        member_quota_tier: None,
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, "lbk_secret_missing").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
}

#[tokio::test]
async fn introspect_returns_inactive_when_expired() {
    let state = mk_state(MockOpaRepo {
        api_key: Some(mk_api_key(
            ApiKeyStatus::Active,
            Some(Utc::now() - Duration::seconds(1)),
        )),
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: Vec::new(),
        member_context: None,
        member_role: None,
        member_quota_tier: None,
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, "lbk_secret_expired").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
}

#[tokio::test]
async fn introspect_returns_inactive_when_account_suspended() {
    let mut account = mk_account();
    account.status = ResourceStatus::Suspended;
    let state = mk_state(MockOpaRepo {
        api_key: Some(mk_api_key(ApiKeyStatus::Active, None)),
        project: Some(mk_project()),
        account: Some(account),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: Vec::new(),
        member_context: None,
        member_role: None,
        member_quota_tier: None,
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, "lbk_secret_suspended_account").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
    assert!(payload.get("account_id").is_none());
}

#[tokio::test]
async fn introspect_returns_inactive_when_project_suspended() {
    let mut project = mk_project();
    project.status = ResourceStatus::Suspended;
    let state = mk_state(MockOpaRepo {
        api_key: Some(mk_api_key(ApiKeyStatus::Active, None)),
        project: Some(project),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: Vec::new(),
        member_context: None,
        member_role: None,
        member_quota_tier: None,
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, "lbk_secret_suspended_project").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
}

#[tokio::test]
async fn introspect_omits_allowed_models_when_null() {
    let mut project = mk_project();
    project.allowed_models = None;
    let state = mk_state(MockOpaRepo {
        api_key: Some(mk_api_key(ApiKeyStatus::Active, None)),
        project: Some(project),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: Vec::new(),
        member_context: None,
        member_role: None,
        member_quota_tier: None,
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, "lbk_secret_valid").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], true);
    assert!(
        payload.get("allowed_models").is_none(),
        "allowed_models should be omitted when the project allows all models"
    );
    assert!(
        payload.get("exp").is_none(),
        "exp should be omitted when the key has no expiry"
    );
}

#[tokio::test]
async fn introspect_returns_empty_allowed_models_when_empty() {
    let mut project = mk_project();
    project.allowed_models = Some(vec![]);
    let state = mk_state(MockOpaRepo {
        api_key: Some(mk_api_key(ApiKeyStatus::Active, None)),
        project: Some(project),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: Vec::new(),
        member_context: None,
        member_role: None,
        member_quota_tier: None,
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, "lbk_secret_valid").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], true);
    assert!(payload["allowed_models"].is_array());
    assert_eq!(payload["allowed_models"].as_array().unwrap().len(), 0);
}

/// ADR-0018 acceptance criterion: each of the three `model_policy` values round-trips through
/// introspection unchanged.
#[tokio::test]
async fn introspect_round_trips_each_model_policy_value() {
    for (policy, wire_value) in [
        (ModelPolicy::AllowAll, "allow_all"),
        (ModelPolicy::Allowlist, "allowlist"),
        (ModelPolicy::DenyAll, "deny_all"),
    ] {
        let mut project = mk_project();
        project.model_policy = policy;
        let state = mk_state(MockOpaRepo {
            api_key: Some(mk_api_key(ApiKeyStatus::Active, None)),
            project: Some(project),
            account: Some(mk_account()),
            usage_calls: Arc::new(Mutex::new(vec![])),
            verification_jwks: Vec::new(),
            member_context: None,
            member_role: None,
            member_quota_tier: None,
            session_status: MockSessionStatus::Active,
            expected_subject: None,
        });

        let (status, payload) = introspect(state, "lbk_secret_valid").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            payload["model_policy"], wire_value,
            "model_policy {policy:?} must round-trip as {wire_value:?}"
        );
    }
}

/// House rule: an unparseable/unknown stored `model_policy` value must be refused (routed to the
/// strict `deny_all` branch), never silently defaulted to the permissive `allow_all`. This proves
/// the fail-closed behavior end-to-end through the introspection response, not only at the
/// `ModelPolicy::from` unit-test level (`lightbridge-authz-core/src/dto.rs`).
#[tokio::test]
async fn introspect_fails_closed_to_deny_all_for_an_unknown_stored_model_policy_value() {
    let mut project = mk_project();
    project.model_policy =
        ModelPolicy::from("some-future-value-this-build-does-not-know".to_string());
    let state = mk_state(MockOpaRepo {
        api_key: Some(mk_api_key(ApiKeyStatus::Active, None)),
        project: Some(project),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: Vec::new(),
        member_context: None,
        member_role: None,
        member_quota_tier: None,
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, "lbk_secret_valid").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        payload["model_policy"], "deny_all",
        "an unrecognized stored value must resolve to the strict deny_all branch, never allow_all"
    );
}

// ── Exchange-token (RFC 8693) introspection ─────────────────────────────────────────────────
//
// A native token-exchange access token (`TokenExchangeOpStore`, `oauth2_op/store.rs`) is never
// hashed into `api_keys` -- it carries a session CUID2 in the same `api_key_id` claim slot a real
// self-signed API-key JWT uses, but there is no `api_keys` row behind it. These tests exercise
// `handlers::introspect::introspect_api_key`'s second dispatch branch
// (`handlers::exchange_token::resolve_exchange_token_context`), which verifies the token against
// THIS service's own signing keys and re-resolves current project authorization live, rather than
// trusting any claim on the token itself for authorization data.

struct TestSigningKey {
    kid: String,
    private_key_pem: String,
    public_jwk: Value,
}

fn mk_signing_key() -> TestSigningKey {
    let generated = generate_rs256_key().expect("rsa key generation should succeed");
    TestSigningKey {
        kid: generated.kid,
        private_key_pem: generated.private_key_pem,
        public_jwk: generated.public_jwk,
    }
}

/// `oauth2.signing.audience` as configured on `mk_state`'s `OpaState::api_key_audience` --
/// mirrors production's `"lightbridge-api-key"` (`ai-helm-values`, `lightbridge-app.yaml`'s
/// `signing:` block). A token whose `azp` equals this is refused by
/// `handlers::exchange_token::verify_self_issued_token` regardless of `api_keys` row state.
const TEST_API_KEY_AUDIENCE: &str = "lightbridge-api-key";
/// A representative token-exchange client id -- varies per client, never registered under
/// `TEST_API_KEY_AUDIENCE` (see `verify_self_issued_token`'s doc comment for why that convention
/// is what makes `azp` a reliable discriminant).
const TEST_EXCHANGE_CLIENT_ID: &str = "governance-auth-cli";

#[derive(Serialize)]
struct ExchangeTokenClaims {
    sub: String,
    exp: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_key_id: Option<String>,
    /// ADR-0020 Decision 2: `sid` now carries the same real, persisted session id as
    /// `api_key_id` for a token-exchange-minted access token (rather than an independent,
    /// unpersisted `cuid2()` mint) -- see `crate::signing::access_token_extra`. Modelled here as
    /// its own optional claim (not aliased to `api_key_id`) so tests can exercise "no `sid`
    /// claim at all" (a pre-ADR-0020 token) independently of `api_key_id`'s own presence.
    #[serde(skip_serializing_if = "Option::is_none")]
    sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    azp: Option<String>,
}

fn sign_exchange_token(key: &TestSigningKey, claims: &ExchangeTokenClaims) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());
    let encoding_key = EncodingKey::from_rsa_pem(key.private_key_pem.as_bytes())
        .expect("generated PEM should parse as an RSA encoding key");
    encode(&header, claims, &encoding_key).expect("signing a well-formed claim set should succeed")
}

fn mk_member_context() -> ResolvedContext {
    ResolvedContext {
        account_id: "acct_1".to_string(),
        project_id: "proj_1".to_string(),
    }
}

#[tokio::test]
async fn introspect_resolves_active_exchange_session_with_live_project_authorization_data() {
    let key = mk_signing_key();
    let token = sign_exchange_token(
        &key,
        &ExchangeTokenClaims {
            sub: "human-subject-1".to_string(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp() as usize,
            account_id: Some("acct_1".to_string()),
            project_id: Some("proj_1".to_string()),
            api_key_id: Some("session_abc123".to_string()),
            sid: Some("session_abc123".to_string()),
            azp: Some(TEST_EXCHANGE_CLIENT_ID.to_string()),
        },
    );
    let state = mk_state(MockOpaRepo {
        api_key: None,
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: vec![key.public_jwk.clone()],
        member_context: Some(mk_member_context()),
        member_role: Some("lead".to_string()),
        member_quota_tier: Some("t-m".to_string()),
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, &token).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], true);
    assert_eq!(payload["account_id"], "acct_1");
    assert_eq!(payload["project_id"], "proj_1");
    assert_eq!(
        payload["sub"], "session_abc123",
        "sub should be the token's own session id, not the human subject or a real api_key_id"
    );
    assert!(
        payload.get("api_key_id").is_none(),
        "there is no api_keys row behind an exchange session"
    );
    assert!(payload.get("api_key_status").is_none());
    assert!(
        payload.get("exp").is_none(),
        "no persisted expiry to report for an exchange session"
    );
    assert_eq!(payload["billing_plan"], "free");
    assert_eq!(payload["billing_plan_name"], "Free");
    assert_eq!(
        payload["allowed_models"],
        serde_json::json!(["gpt-4.1-mini"])
    );
    assert_eq!(payload["model_policy"], "allow_all");
    assert_eq!(payload["role"], "lead");
    assert_eq!(payload["quota_tier"], "t-m");
}

#[tokio::test]
async fn introspect_returns_inactive_for_an_expired_exchange_token() {
    let key = mk_signing_key();
    let token = sign_exchange_token(
        &key,
        &ExchangeTokenClaims {
            sub: "human-subject-1".to_string(),
            exp: (Utc::now() - Duration::minutes(5)).timestamp() as usize,
            account_id: Some("acct_1".to_string()),
            project_id: Some("proj_1".to_string()),
            api_key_id: Some("session_abc123".to_string()),
            sid: Some("session_abc123".to_string()),
            azp: Some(TEST_EXCHANGE_CLIENT_ID.to_string()),
        },
    );
    let state = mk_state(MockOpaRepo {
        api_key: None,
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: vec![key.public_jwk.clone()],
        member_context: Some(mk_member_context()),
        member_role: None,
        member_quota_tier: None,
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, &token).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
}

#[tokio::test]
async fn introspect_returns_inactive_for_a_token_signed_by_an_unknown_key() {
    let signing_key = mk_signing_key();
    let unrelated_key = mk_signing_key();
    let token = sign_exchange_token(
        &signing_key,
        &ExchangeTokenClaims {
            sub: "human-subject-1".to_string(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp() as usize,
            account_id: Some("acct_1".to_string()),
            project_id: Some("proj_1".to_string()),
            api_key_id: Some("session_abc123".to_string()),
            sid: Some("session_abc123".to_string()),
            azp: Some(TEST_EXCHANGE_CLIENT_ID.to_string()),
        },
    );
    let state = mk_state(MockOpaRepo {
        api_key: None,
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        // The verifier only trusts `unrelated_key` -- proves signature/kid mismatch fails closed,
        // not merely "some key exists somewhere".
        verification_jwks: vec![unrelated_key.public_jwk.clone()],
        member_context: Some(mk_member_context()),
        member_role: None,
        member_quota_tier: None,
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, &token).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
}

#[tokio::test]
async fn introspect_returns_inactive_for_a_self_issued_token_with_no_project_claim() {
    // Mirrors an id_token's claim shape (`signing::id_token_extra`): no `project_id`/`account_id`
    // at all. A validly-signed-by-us token with no tenant claim must still fail closed rather than
    // being treated as an exchange session with an empty project.
    let key = mk_signing_key();
    let token = sign_exchange_token(
        &key,
        &ExchangeTokenClaims {
            sub: "human-subject-1".to_string(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp() as usize,
            account_id: None,
            project_id: None,
            api_key_id: None,
            sid: None,
            azp: Some(TEST_EXCHANGE_CLIENT_ID.to_string()),
        },
    );
    let state = mk_state(MockOpaRepo {
        api_key: None,
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: vec![key.public_jwk.clone()],
        member_context: Some(mk_member_context()),
        member_role: None,
        member_quota_tier: None,
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, &token).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
}

#[tokio::test]
async fn introspect_returns_inactive_when_exchange_subject_is_no_longer_a_member() {
    let key = mk_signing_key();
    let token = sign_exchange_token(
        &key,
        &ExchangeTokenClaims {
            sub: "human-subject-1".to_string(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp() as usize,
            account_id: Some("acct_1".to_string()),
            project_id: Some("proj_1".to_string()),
            api_key_id: Some("session_abc123".to_string()),
            sid: Some("session_abc123".to_string()),
            azp: Some(TEST_EXCHANGE_CLIENT_ID.to_string()),
        },
    );
    let state = mk_state(MockOpaRepo {
        api_key: None,
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: vec![key.public_jwk.clone()],
        // No member_context configured -- resolve_context refuses (Error::NotFound), exactly the
        // live-membership re-check firing for a subject removed from the roster since mint time.
        member_context: None,
        member_role: None,
        member_quota_tier: None,
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, &token).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
}

#[tokio::test]
async fn introspect_returns_inactive_when_exchange_project_is_suspended() {
    let key = mk_signing_key();
    let token = sign_exchange_token(
        &key,
        &ExchangeTokenClaims {
            sub: "human-subject-1".to_string(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp() as usize,
            account_id: Some("acct_1".to_string()),
            project_id: Some("proj_1".to_string()),
            api_key_id: Some("session_abc123".to_string()),
            sid: Some("session_abc123".to_string()),
            azp: Some(TEST_EXCHANGE_CLIENT_ID.to_string()),
        },
    );
    let mut project = mk_project();
    project.status = ResourceStatus::Suspended;
    let state = mk_state(MockOpaRepo {
        api_key: None,
        project: Some(project),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: vec![key.public_jwk.clone()],
        member_context: Some(mk_member_context()),
        member_role: None,
        member_quota_tier: None,
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, &token).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
}

#[tokio::test]
async fn introspect_returns_inactive_when_exchange_account_is_suspended() {
    let key = mk_signing_key();
    let token = sign_exchange_token(
        &key,
        &ExchangeTokenClaims {
            sub: "human-subject-1".to_string(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp() as usize,
            account_id: Some("acct_1".to_string()),
            project_id: Some("proj_1".to_string()),
            api_key_id: Some("session_abc123".to_string()),
            sid: Some("session_abc123".to_string()),
            azp: Some(TEST_EXCHANGE_CLIENT_ID.to_string()),
        },
    );
    let mut account = mk_account();
    account.status = ResourceStatus::Suspended;
    let state = mk_state(MockOpaRepo {
        api_key: None,
        project: Some(mk_project()),
        account: Some(account),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: vec![key.public_jwk.clone()],
        member_context: Some(mk_member_context()),
        member_role: None,
        member_quota_tier: None,
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, &token).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
}

/// **The critical revocation-integrity regression.** A revoked (or expired) self-signed API-key
/// JWT is still a perfectly valid signature under this service's own keys -- revocation only
/// flips `api_keys.status`, it cannot un-sign an already-issued JWT. If introspection ever fell
/// through to exchange-token verification after an `api_keys` row lookup came back inactive, a
/// revoked key's own still-good signature would resurrect it as an "active" exchange session,
/// silently defeating revocation. This proves the dispatch never does that: an `api_keys` row
/// existing (here, in the `Revoked` state) short-circuits straight to `{"active": false}`, even
/// though every precondition the exchange path would need (valid signature, a resolvable member
/// context) is deliberately ALSO satisfied here.
#[tokio::test]
async fn a_revoked_api_key_jwt_is_never_reinterpreted_as_an_active_exchange_session() {
    let key = mk_signing_key();
    let token = sign_exchange_token(
        &key,
        &ExchangeTokenClaims {
            sub: "human-subject-1".to_string(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp() as usize,
            account_id: Some("acct_1".to_string()),
            project_id: Some("proj_1".to_string()),
            // Shaped like a real self-signed API-key JWT: `api_key_id` names the actual
            // (now-revoked) key row, not a session id, and `azp` is the fixed API-key audience.
            api_key_id: Some("key_1".to_string()),
            sid: Some("key_1".to_string()),
            azp: Some(TEST_API_KEY_AUDIENCE.to_string()),
        },
    );
    let state = mk_state(MockOpaRepo {
        api_key: Some(mk_api_key(ApiKeyStatus::Revoked, None)),
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        // Everything the exchange path would need to succeed IS present, to prove it is never
        // reached, not merely that it happens to fail too.
        verification_jwks: vec![key.public_jwk.clone()],
        member_context: Some(mk_member_context()),
        member_role: Some("lead".to_string()),
        member_quota_tier: Some("t-m".to_string()),
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, &token).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
    assert!(
        payload.get("role").is_none(),
        "no exchange-path authorization data must leak through for a revoked key"
    );
    assert!(payload.get("quota_tier").is_none());
}

/// **The `azp`-gate regression -- proves the guarantee holds even with NO `api_keys` row at
/// all**, the exact shape a hard-deleted key would present (unlike the test above, which proves
/// the row-existence check wins when a row IS present). `StoreRepo::delete_api_key` -- a
/// hand-written hard `DELETE FROM api_keys` that would have produced precisely this scenario --
/// has been removed because of this, but this test does not rely on that removal either: it
/// proves `verify_self_issued_token` independently refuses any token whose `azp` matches the
/// configured API-key audience, regardless of what the `api_keys` table currently contains.
#[tokio::test]
async fn a_token_carrying_the_api_key_audience_as_azp_is_refused_even_with_no_api_keys_row() {
    let key = mk_signing_key();
    let token = sign_exchange_token(
        &key,
        &ExchangeTokenClaims {
            sub: "human-subject-1".to_string(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp() as usize,
            account_id: Some("acct_1".to_string()),
            project_id: Some("proj_1".to_string()),
            api_key_id: Some("key_1".to_string()),
            sid: Some("key_1".to_string()),
            azp: Some(TEST_API_KEY_AUDIENCE.to_string()),
        },
    );
    let state = mk_state(MockOpaRepo {
        // No api_keys row at all -- the hard-delete scenario. Every other precondition the
        // exchange path needs IS satisfied, to prove the azp gate alone is what refuses this.
        api_key: None,
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: vec![key.public_jwk.clone()],
        member_context: Some(mk_member_context()),
        member_role: Some("lead".to_string()),
        member_quota_tier: Some("t-m".to_string()),
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, &token).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
    assert!(
        payload.get("role").is_none(),
        "no exchange-path authorization data must leak through for an API-key-shaped azp"
    );
}

/// The fail-closed half of the `azp` gate: a token with NO `azp` claim at all must also be
/// refused, not treated as "obviously not an API key." A self-signed API-key JWT minted under an
/// unconfigured `oauth2.signing.audience` carries no `azp` claim either (`access_token_extra`
/// only inserts it `if let Some(azp) = azp`), so an absent `azp` is genuinely ambiguous and must
/// resolve to the more conservative reading.
#[tokio::test]
async fn a_token_with_no_azp_claim_at_all_is_refused() {
    let key = mk_signing_key();
    let token = sign_exchange_token(
        &key,
        &ExchangeTokenClaims {
            sub: "human-subject-1".to_string(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp() as usize,
            account_id: Some("acct_1".to_string()),
            project_id: Some("proj_1".to_string()),
            api_key_id: Some("session_abc123".to_string()),
            sid: Some("session_abc123".to_string()),
            azp: None,
        },
    );
    let state = mk_state(MockOpaRepo {
        api_key: None,
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: vec![key.public_jwk.clone()],
        member_context: Some(mk_member_context()),
        member_role: None,
        member_quota_tier: None,
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, &token).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
}

// ============================================================================================
// ADR-0020 Decision 4 / #437: `resolve_exchange_token_context` gains a session-status lookup
// keyed on `claims.sid`, joining the existing checks above. Three outcomes, exercised below:
// session found+active (already covered by every test above, all of which default to
// `MockSessionStatus::Active`), session found but not active/expired/not-found (`active: false`,
// same as every other fail-to-inactive branch), and the session lookup itself erroring (`Err`,
// never `Ok(None)`/`Ok(Some(..))` -- the one hard, fail-closed requirement of this whole ADR).
// ============================================================================================

#[tokio::test]
async fn introspect_returns_inactive_when_session_is_revoked() {
    let key = mk_signing_key();
    let token = sign_exchange_token(
        &key,
        &ExchangeTokenClaims {
            sub: "human-subject-1".to_string(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp() as usize,
            account_id: Some("acct_1".to_string()),
            project_id: Some("proj_1".to_string()),
            api_key_id: Some("session_abc123".to_string()),
            sid: Some("session_abc123".to_string()),
            azp: Some(TEST_EXCHANGE_CLIENT_ID.to_string()),
        },
    );
    let state = mk_state(MockOpaRepo {
        api_key: None,
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: vec![key.public_jwk.clone()],
        member_context: Some(mk_member_context()),
        member_role: Some("lead".to_string()),
        member_quota_tier: Some("t-m".to_string()),
        session_status: MockSessionStatus::Revoked,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, &token).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        payload["active"], false,
        "a revoked session must resolve inactive, even though every other check would pass"
    );
}

#[tokio::test]
async fn introspect_returns_inactive_when_session_is_expired() {
    let key = mk_signing_key();
    let token = sign_exchange_token(
        &key,
        &ExchangeTokenClaims {
            sub: "human-subject-1".to_string(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp() as usize,
            account_id: Some("acct_1".to_string()),
            project_id: Some("proj_1".to_string()),
            api_key_id: Some("session_abc123".to_string()),
            sid: Some("session_abc123".to_string()),
            azp: Some(TEST_EXCHANGE_CLIENT_ID.to_string()),
        },
    );
    let state = mk_state(MockOpaRepo {
        api_key: None,
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: vec![key.public_jwk.clone()],
        member_context: Some(mk_member_context()),
        member_role: Some("lead".to_string()),
        member_quota_tier: Some("t-m".to_string()),
        session_status: MockSessionStatus::Expired,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, &token).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
}

#[tokio::test]
async fn introspect_returns_inactive_when_session_row_not_found() {
    let key = mk_signing_key();
    let token = sign_exchange_token(
        &key,
        &ExchangeTokenClaims {
            sub: "human-subject-1".to_string(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp() as usize,
            account_id: Some("acct_1".to_string()),
            project_id: Some("proj_1".to_string()),
            api_key_id: Some("session_abc123".to_string()),
            sid: Some("session_abc123".to_string()),
            azp: Some(TEST_EXCHANGE_CLIENT_ID.to_string()),
        },
    );
    let state = mk_state(MockOpaRepo {
        api_key: None,
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: vec![key.public_jwk.clone()],
        member_context: Some(mk_member_context()),
        member_role: Some("lead".to_string()),
        member_quota_tier: Some("t-m".to_string()),
        session_status: MockSessionStatus::NotFound,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, &token).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        payload["active"], false,
        "an unrecognized sid (e.g. a pre-ADR-0020 token) must resolve inactive, not error"
    );
}

#[tokio::test]
async fn introspect_returns_inactive_when_no_sid_claim_at_all() {
    let key = mk_signing_key();
    let token = sign_exchange_token(
        &key,
        &ExchangeTokenClaims {
            sub: "human-subject-1".to_string(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp() as usize,
            account_id: Some("acct_1".to_string()),
            project_id: Some("proj_1".to_string()),
            api_key_id: Some("session_abc123".to_string()),
            sid: None,
            azp: Some(TEST_EXCHANGE_CLIENT_ID.to_string()),
        },
    );
    let state = mk_state(MockOpaRepo {
        api_key: None,
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: vec![key.public_jwk.clone()],
        member_context: Some(mk_member_context()),
        member_role: Some("lead".to_string()),
        member_quota_tier: Some("t-m".to_string()),
        // Deliberately Active -- proves the ABSENCE of a `sid` claim alone is what resolves this
        // inactive, not the session lookup (which would never even be called).
        session_status: MockSessionStatus::Active,
        expected_subject: None,
    });

    let (status, payload) = introspect(state, &token).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
}

/// **The fail-closed regression test #437 requires as a hard, non-optional gate.** A session-store
/// lookup error must propagate as `Err`, never collapse into `Ok(None)` (which the HTTP layer
/// would render as an indistinguishable, safe-looking `{"active": false}`) and never `Ok(Some(..))`
/// (`active: true`). Calls `resolve_exchange_token_context` directly (not through
/// `introspect_api_key`, which would `?`-propagate the same `Err` up through
/// `axum::response::Result`'s `IntoResponse` machinery into a 500 -- asserting `Err` here is the
/// more precise, one-hop check of the actual contract this ADR adds).
#[tokio::test]
async fn resolve_exchange_token_context_errors_when_session_lookup_fails_never_active_true() {
    let key = mk_signing_key();
    let token = sign_exchange_token(
        &key,
        &ExchangeTokenClaims {
            sub: "human-subject-1".to_string(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp() as usize,
            account_id: Some("acct_1".to_string()),
            project_id: Some("proj_1".to_string()),
            api_key_id: Some("session_abc123".to_string()),
            sid: Some("session_abc123".to_string()),
            azp: Some(TEST_EXCHANGE_CLIENT_ID.to_string()),
        },
    );
    let state = mk_state(MockOpaRepo {
        api_key: None,
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
        verification_jwks: vec![key.public_jwk.clone()],
        // Every other precondition is satisfied (a real member context, an active project/
        // account) so this test proves the session-lookup error ALONE is what refuses the call --
        // not some other, unrelated failure hiding behind it.
        member_context: Some(mk_member_context()),
        member_role: Some("lead".to_string()),
        member_quota_tier: Some("t-m".to_string()),
        session_status: MockSessionStatus::LookupErrors,
        expected_subject: None,
    });

    let result = lightbridge_authz_rest::handlers::exchange_token::resolve_exchange_token_context(
        &state, &token,
    )
    .await;

    assert!(
        result.is_err(),
        "a session-store lookup error must propagate as Err, never Ok(None)/Ok(Some(..)): {result:?}"
    );

    // Also assert the HTTP-layer consequence: the same error, reached through the real
    // introspection entrypoint, must surface as a hard failure (never a 200 with any `active`
    // value) -- proving the fail-closed branch takes the exact same existing error route every
    // other `Err` case in this function already uses (a bare `?`), not a new, invented response
    // shape.
    let http_result = introspect_api_key(
        axum::extract::State(state),
        Form(IntrospectRequest {
            token: token.clone(),
            token_type_hint: Some("access_token".to_string()),
        }),
    )
    .await;
    assert!(
        http_result.is_err(),
        "the HTTP introspection entrypoint must also refuse, not silently resolve `active: false`"
    );
}
