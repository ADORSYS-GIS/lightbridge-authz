use lightbridge_authz_bearer::TokenInfo;

#[test]
fn token_info_debug_never_leaks_the_access_token() {
    let info = TokenInfo {
        active: true,
        sub: "user-sub-123".to_string(),
        exp: 42,
        aud: vec!["lightbridge-api-key".to_string()],
        access_token: "eyJ.super-secret-bearer.value".to_string(),
    };

    let rendered = format!("{info:?}");

    assert!(
        !rendered.contains("super-secret-bearer"),
        "access_token must never appear in TokenInfo Debug output: {rendered}"
    );
    assert!(rendered.contains("<redacted>"));
    assert!(rendered.contains("user-sub-123"));
}
