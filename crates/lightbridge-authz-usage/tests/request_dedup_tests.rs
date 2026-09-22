use std::collections::HashMap;

use lightbridge_authz_usage_rest::handlers::request_dedup::request_key;
use serde_json::json;

#[test]
fn request_keys_are_stable_and_scoped_without_content() {
    let mut attrs = HashMap::from([
        ("account_id".to_owned(), json!("account-a")),
        ("user_id".to_owned(), json!("user-a")),
        ("client_request_id".to_owned(), json!("request-1")),
    ]);
    let original = request_key(&attrs).expect("synthetic fixture operation must succeed");
    attrs.insert("prompt".to_owned(), json!("not part of the key"));
    assert_eq!(request_key(&attrs).as_ref(), Some(&original));
    attrs.insert("account_id".to_owned(), json!("account-b"));
    assert_ne!(request_key(&attrs).as_ref(), Some(&original));
    attrs.remove("client_request_id");
    assert_eq!(request_key(&attrs), None);
}

#[test]
fn request_key_distinguishes_tuple_boundaries() {
    let first = HashMap::from([
        ("account_id".to_owned(), json!("a:b")),
        ("user_id".to_owned(), json!("c")),
        ("request_id".to_owned(), json!("d")),
    ]);
    let second = HashMap::from([
        ("account_id".to_owned(), json!("a")),
        ("user_id".to_owned(), json!("b:c")),
        ("request_id".to_owned(), json!("d")),
    ]);
    assert_ne!(request_key(&first), request_key(&second));
}
