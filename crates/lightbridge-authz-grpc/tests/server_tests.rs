use lightbridge_authz_core::api_key::{ApiKey, ApiKeyStatus};
use lightbridge_authz_core::db::DbPoolTrait;
use lightbridge_authz_core::dto::Acl;
use lightbridge_authz_grpc::server::{AuthServer, AuthServerTrait};
use lightbridge_authz_proto::envoy_types::pb::google::protobuf::value::Kind;
use serde_json::json;
use std::sync::Arc;

// Mock DbPool for testing purposes.
// NOTE: This test is currently ignored because it requires either:
// 1. A real test database with seeded data, or
// 2. Mocking of the ApiKeyRepo trait (which would require refactoring AuthServer to accept a trait object).
// The core logic of building dynamic metadata from an ApiKey is tested in helper_tests.rs.
// To run this test, implement DbPool::new_for_test() or refactor to use a mockable repo.
// See also: https://github.com/rust-lang/chalk/issues/923 (example issue for trait mocking)
fn mock_db_pool() -> Arc<dyn DbPoolTrait> {
    unimplemented!(
        "See comment above. To run this test, implement DbPool::new_for_test() or refactor to use a mockable repo."
    )
}

#[tokio::test]
#[ignore] // Requires a test database with seeded data or mocking of ApiKeyRepo. Core logic is tested in helper_tests.rs.
async fn test_build_dynamic_metadata_success() {
    let pool = mock_db_pool();
    let auth_server = AuthServer::new(pool.clone());

    // Create a dummy API key for testing
    let api_key = ApiKey {
        id: "test_api_key_id".to_string(),
        user_id: "test_user_id".to_string(),
        key_hash: "hashed_token".to_string(),
        created_at: chrono::Utc::now(),
        expires_at: None,
        metadata: Some(json!({"custom_data": "value"})),
        status: ApiKeyStatus::Active,
        acl: Acl {
            allowed_models: vec!["model1".to_string(), "model2".to_string()],
            tokens_per_model: std::collections::HashMap::new(),
            rate_limit: lightbridge_authz_core::dto::RateLimit::default(),
        },
    };

    // Mock the resolve_api_key to return our dummy API key
    // This requires a bit of refactoring in AuthServer to allow mocking ApiKeyRepo
    // For now, we'll assume resolve_api_key works and focus on metadata construction.
    // In a real scenario, we'd use a mocking library or trait for ApiKeyRepo.

    // Directly call the private helper for testing purposes, or refactor for testability
    // For this example, we'll simulate the output of resolve_api_key
    let token = "test_token";
    let result = auth_server.build_dynamic_metadata(token).await;

    assert!(result.is_ok());
    let dynamic_metadata = result.unwrap();

    let expected_user_id = dynamic_metadata
        .fields
        .get("user_id")
        .and_then(|v| v.kind.as_ref())
        .and_then(|k| match k {
            Kind::StringValue(s) => Some(s),
            _ => None,
        });
    assert_eq!(expected_user_id, Some(&api_key.user_id));

    let expected_api_key_id = dynamic_metadata
        .fields
        .get("api_key_id")
        .and_then(|v| v.kind.as_ref())
        .and_then(|k| match k {
            Kind::StringValue(s) => Some(s),
            _ => None,
        });
    assert_eq!(expected_api_key_id, Some(&api_key.id));

    let expected_api_key_name = dynamic_metadata
        .fields
        .get("api_key_name")
        .and_then(|v| v.kind.as_ref())
        .and_then(|k| match k {
            Kind::StringValue(s) => Some(s),
            _ => None,
        });
    assert_eq!(expected_api_key_name, Some(&api_key.id));

    let expected_permissions = dynamic_metadata
        .fields
        .get("permissions")
        .and_then(|v| v.kind.as_ref())
        .and_then(|k| match k {
            Kind::StructValue(s) => Some(s),
            _ => None,
        });
    assert!(expected_permissions.is_some());

    let permissions_struct = expected_permissions.unwrap();
    let allowed_models = permissions_struct
        .fields
        .get("allowed_models")
        .and_then(|v| v.kind.as_ref())
        .and_then(|k| match k {
            Kind::ListValue(l) => Some(l),
            _ => None,
        });
    assert!(allowed_models.is_some());
    assert_eq!(allowed_models.unwrap().values.len(), 2);
}
