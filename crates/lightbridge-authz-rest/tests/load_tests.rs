use goose::prelude::*;
use serde_json::json;
use std::env;

/// Task to validate an API key against the OPA endpoint.
async fn validate_api_key(user: &mut GooseUser) -> TransactionResult {
    let api_key = env::var("AUTHZ_API_KEY").unwrap_or_else(|_| "lbk_demo_key".to_string());

    let request_body = json!({
        "api_key": api_key,
        "ip": "127.0.0.1"
    });

    let request_builder = user
        .get_request_builder(&GooseMethod::Post, "/v1/opa/validate")?
        .json(&request_body)
        .basic_auth("authorino", Some("change-me"));

    let goose_request = goose::goose::GooseRequest::builder()
        .set_request_builder(request_builder)
        .build();

    let _goose_response = user.request(goose_request).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    GooseAttack::initialize()?
        .register_scenario(
            scenario!("ValidateApiKey").register_transaction(transaction!(validate_api_key)),
        )
        .set_default(GooseDefault::Host, "https://127.0.0.1:13001")?
        .execute()
        .await?;

    Ok(())
}
