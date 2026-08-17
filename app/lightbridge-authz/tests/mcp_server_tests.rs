// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Regression guard for the "lightbridge-mcp is freed from the mandatory-Redis requirement" half
//! of AGENTS.md's "Redis is a mandatory dependency" house rule: `authz-api`, `authz-idp`, and
//! `authz-budget` all now hard-require `Config.redis`, but `authz-opa` and `lightbridge-mcp` stay
//! exempt. `start_mcp_server` (unlike `start_api_server`/`start_idp_server`/`start_budget_server`)
//! doesn't take a `redis` parameter at all, so this proves the whole startup sequence -- billing/
//! rbac validation, optional signing-key bootstrap, cratestack pool, router assembly, TLS load --
//! still runs to completion with no Redis configured anywhere, failing only for a reason this test
//! deliberately induces, never anything Redis-shaped.

use std::sync::Arc;

use lightbridge_authz::mcp::start_mcp_server;
use lightbridge_authz_core::config::{
    ApiServer, BasicAuth, Billing, BillingPlan, Oauth2, Oauth2Type, Tls,
};
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};

fn lazy_pool() -> Arc<dyn DbPoolTrait> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        // Bounded so a deliberately-dead pool fails fast: sqlx's default
        // `acquire_timeout` is 30s, and every test that touches one paid it in full.
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
        .expect("lazy pool should be constructible");
    Arc::new(DbPool::from_pool(pool))
}

fn bad_tls() -> Tls {
    Tls {
        cert_path: "/nonexistent/mcp-server-tests/cert.pem".to_string(),
        key_path: "/nonexistent/mcp-server-tests/key.pem".to_string(),
        client_ca_bundle_path: None,
    }
}

fn external_oauth2() -> Oauth2 {
    Oauth2 {
        oauth2_type: Oauth2Type::External,
        jwks_url: "http://jwks".to_string(),
        oauth2_url: None,
        issuer_url: None,
        authorization_endpoint: None,
        token_endpoint: None,
        registration_endpoint: None,
        issuance: None,
        audience: None,
        signing: None,
        token_exchange: None,
        rbac: Default::default(),
        clients: Vec::new(),
    }
}

fn sample_billing() -> Billing {
    Billing {
        plans: vec![BillingPlan {
            id: "free".to_string(),
            name: "Free".to_string(),
            limits: None,
        }],
    }
}

/// `lightbridge-mcp` never needed Redis in the first place -- `start_mcp_server`'s signature has
/// no `redis` parameter, unlike its `authz-api`/`authz-idp`/`authz-budget` siblings. Whatever this
/// deliberately-offline call eventually fails on (an unset/unreachable `DATABASE_URL`, or the
/// bogus TLS cert paths once a database is reachable), it must never be Redis: nothing in this
/// call graph reads `Config.redis` at all.
#[tokio::test]
async fn start_mcp_server_runs_without_redis_and_never_fails_on_it() {
    let api = ApiServer {
        address: "127.0.0.1".to_string(),
        port: 0,
        tls: bad_tls(),
        allowed_hosts: None,
        rpc_base_path: None,
    };
    let basic_auth = BasicAuth {
        username: "authorino".to_string(),
        password: "change-me".to_string(),
    };
    let result = start_mcp_server(
        &api,
        &external_oauth2(),
        &basic_auth,
        &sample_billing(),
        lazy_pool(),
    )
    .await;
    let err = result.expect_err("this deliberately offline call must fail on something");
    assert!(
        !format!("{err}").to_lowercase().contains("redis"),
        "lightbridge-mcp must never fail for a redis-shaped reason: got {err}"
    );
}
