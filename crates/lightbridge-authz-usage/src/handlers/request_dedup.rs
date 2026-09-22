//! Stable request-grain keys. Never hash prompt/completion content or use receive time.
use std::collections::HashMap;

use serde_json::Value;

use crate::normalizer::extract_string;

/// Namespace a request ID by the identity that owns it, so equal provider request IDs
/// from two accounts do not suppress each other's rows. Source and observed_at are
/// separate columns of the unique index. JSON tuple encoding avoids delimiter collisions.
pub fn request_key(attrs: &HashMap<String, Value>) -> Option<String> {
    let request = extract_string(attrs, &["x-request-id", "client_request_id", "request_id"])?;
    let account = extract_string(attrs, &super::identity_keys::ACCOUNT_KEYS);
    let user = extract_string(attrs, &super::identity_keys::USER_KEYS);
    Some(serde_json::json!([account, user, request]).to_string())
}
