use anyhow::anyhow;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::bb8::PooledConnection;
use lightbridge_authz_core::api_key::ApiKey;
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::db::DbPoolTrait;
use lightbridge_authz_core::dto::{Acl, RateLimit};
use lightbridge_authz_core::error::{Error, Result};
use lightbridge_authz_grpc::server::{AuthServer, AuthServerTrait};
use serde_json::json;
use std::sync::Arc;

#[derive(Debug)]
struct MockDbPool;

#[async_trait]
impl DbPoolTrait for MockDbPool {
    async fn get(&self) -> Result<PooledConnection<'_, AsyncPgConnection>> {
        Err(Error::Any(anyhow!(
            "MockDbPool::get is not implemented for tests that require database access."
        )))
    }
}

// Mock DbPool for testing purposes.
fn mock_db_pool() -> Arc<dyn DbPoolTrait> {
    Arc::new(MockDbPool)
}

#[tokio::test]
async fn test_json_value_to_prost_value() {
    // Create a mock AuthServer for testing
    // For helper functions that don't require database access, we can create a minimal instance
    let auth_server = AuthServer::new(crate::mock_db_pool());

    let test_json = json!({
        "string_field": "value",
        "number_field": 42.5,
        "bool_field": true,
        "null_field": null,
        "array_field": [1, 2, 3],
        "object_field": {
            "nested_string": "nested_value"
        }
    });

    let prost_value = auth_server.json_value_to_prost_value(test_json);

    // Assert the structure of the converted prost_value
    let struct_value = match prost_value.kind {
        Some(
            lightbridge_authz_proto::envoy_types::pb::google::protobuf::value::Kind::StructValue(s),
        ) => s,
        _ => panic!("Expected StructValue"),
    };

    assert_eq!(
        struct_value
            .fields
            .get("string_field")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                lightbridge_authz_proto::envoy_types::pb::google::protobuf::value::Kind::StringValue(s) => Some(s),
                _ => None,
            }),
        Some(&"value".to_string())
    );

    assert_eq!(
        struct_value
            .fields
            .get("number_field")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                lightbridge_authz_proto::envoy_types::pb::google::protobuf::value::Kind::NumberValue(n) => Some(n),
                _ => None,
            }),
        Some(&42.5)
    );

    assert_eq!(
        struct_value
            .fields
            .get("bool_field")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                lightbridge_authz_proto::envoy_types::pb::google::protobuf::value::Kind::BoolValue(b) => Some(b),
                _ => None,
            }),
        Some(&true)
    );

    assert_eq!(
        struct_value
            .fields
            .get("null_field")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                lightbridge_authz_proto::envoy_types::pb::google::protobuf::value::Kind::NullValue(_) => Some(&0),
                _ => None,
            }),
        Some(&0)
    );

    let array_value = struct_value
        .fields
        .get("array_field")
        .and_then(|v| v.kind.as_ref())
        .and_then(|k| match k {
            lightbridge_authz_proto::envoy_types::pb::google::protobuf::value::Kind::ListValue(
                l,
            ) => Some(l),
            _ => None,
        });

    assert!(array_value.is_some());
    assert_eq!(array_value.unwrap().values.len(), 3);

    let nested_object = struct_value
        .fields
        .get("object_field")
        .and_then(|v| v.kind.as_ref())
        .and_then(|k| match k {
            lightbridge_authz_proto::envoy_types::pb::google::protobuf::value::Kind::StructValue(s) => Some(s),
            _ => None,
        });

    assert!(nested_object.is_some());
    assert_eq!(
        nested_object
            .unwrap()
            .fields
            .get("nested_string")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                lightbridge_authz_proto::envoy_types::pb::google::protobuf::value::Kind::StringValue(s) => Some(s),
                _ => None,
            }),
        Some(&"nested_value".to_string())
    );
}

#[tokio::test]
async fn test_api_key_to_dynamic_metadata() {
    // Create a mock AuthServer for testing
    let auth_server = AuthServer::new(crate::mock_db_pool());

    let api_key = ApiKey {
        id: "test_api_key_id".to_string(),
        user_id: "test_user_id".to_string(),
        key_hash: "hashed_token".to_string(),
        created_at: chrono::Utc::now(),
        expires_at: None,
        metadata: None,
        status: lightbridge_authz_core::api_key::ApiKeyStatus::Active,
        acl: Acl {
            allowed_models: vec!["model1".to_string(), "model2".to_string()],
            tokens_per_model: std::collections::HashMap::new(),
            rate_limit: RateLimit {
                requests: 100,
                window_seconds: 60,
            },
        },
    };

    let result = auth_server.api_key_to_dynamic_metadata(api_key);
    assert!(result.is_ok());
    let dynamic_metadata = result.unwrap();

    let fields = &dynamic_metadata.fields;

    assert_eq!(
        fields.get("user_id").and_then(|v| v.kind.as_ref()).and_then(|k| match k {
            lightbridge_authz_proto::envoy_types::pb::google::protobuf::value::Kind::StringValue(s) => Some(s),
            _ => None,
        }),
        Some(&"test_user_id".to_string())
    );

    assert_eq!(
        fields.get("api_key_id").and_then(|v| v.kind.as_ref()).and_then(|k| match k {
            lightbridge_authz_proto::envoy_types::pb::google::protobuf::value::Kind::StringValue(s) => Some(s),
            _ => None,
        }),
        Some(&"test_api_key_id".to_string())
    );

    assert_eq!(
        fields.get("api_key_name").and_then(|v| v.kind.as_ref()).and_then(|k| match k {
            lightbridge_authz_proto::envoy_types::pb::google::protobuf::value::Kind::StringValue(s) => Some(s),
            _ => None,
        }),
        Some(&"test_api_key_id".to_string())
    );

    let permissions = fields.get("permissions").and_then(|v| v.kind.as_ref()).and_then(|k| match k {
        lightbridge_authz_proto::envoy_types::pb::google::protobuf::value::Kind::StructValue(s) => Some(s),
        _ => None,
    });
    assert!(permissions.is_some());

    let permissions_fields = &permissions.unwrap().fields;
    let allowed_models = permissions_fields
        .get("allowed_models")
        .and_then(|v| v.kind.as_ref())
        .and_then(|k| match k {
            lightbridge_authz_proto::envoy_types::pb::google::protobuf::value::Kind::ListValue(
                l,
            ) => Some(l),
            _ => None,
        });
    assert!(allowed_models.is_some());
    assert_eq!(allowed_models.unwrap().values.len(), 2);
}
