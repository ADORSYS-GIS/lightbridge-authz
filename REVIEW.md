# Code Review Findings

This document outlines the findings of the code review.

## Summary

The code review identified several critical issues spanning security, performance, and code correctness. Key findings include SQL injection vulnerabilities, sensitive data exposure in API responses, lack of transactional integrity for database operations, and performance bottlenecks due to N+1 query patterns. The review also highlighted weak API key generation, improper error handling that leaks internal details, and missing graceful shutdown mechanisms. Actionable recommendations are provided to address each finding.

## Issues Found

### Security vulnerabilities

*   **SQL injection via string-built UPDATE:** `ApiKeyRepo::patch()` builds SQL with `format!` including `expires_at`, `metadata` (serialized with `unwrap`), and `status`, then executes via `diesel::sql_query`. Risk: injection and invalid quoting. Use Diesel changesets instead.
*   **Sensitive data exposure in API responses:** `ApiKey` struct (includes `key_hash`) and returned directly by controllers, e.g. `create_api_key()`, `get_api_key()`. Do not expose `key_hash`; create a response DTO without sensitive fields.
*   **Panic and uncontrolled error disclosure:** `start_rest_server()` bind/serve unwraps and (`crates/lightbridge-authz-rest/src/lib.rs:32`). Replace `unwrap` with proper error propagation using core `Error`. `IntoResponse` for `Error` returns `self.to_string()`. Leaks internal error details. Return generic message; log detailed errors server-side.
*   **Weak API key generation and handling:** `APIKeyHandlerImpl::create_api_key()` uses "some_key". Must generate cryptographically secure secrets and return only once; store only hash. `create_api_key()`: Uses UUID string; prefer 32+ bytes from a CSPRNG (e.g., `rand::rngs::OsRng`) and a restricted alphabet. Never log or store plaintext.

### Performance issues

*   **N+1 queries fetching ACL per API key:** `ApiKeyRow::into_api_key()` fetches ACL and used within `list()` loop. Join or batch-load ACL and models to avoid N+1.
*   **Missing transactions for multi-statement updates:** `AclRepo::create()` multi-inserts, `AclRepo::update()` delete+insert and `AclRepo::delete()` multi-deletes are not wrapped in a transaction. Use `diesel_async` transaction to ensure consistency.
*   **Connection pool settings hard-coded:** `DbPool::new()` ignores configured `pool_size`. Wire to `Database::pool_size`.
*   **Repeated allocation in list():** `Vec` push in loop. Reserve capacity with `rows.len()` or `map/collect`.

### Potential bugs / correctness

*   **Silent fallback for unknown status:** `into_api_key()` maps unknown status to `Active`. Should error or use a robust enum mapping; storing canonical strings consistently.
*   **Unwrap on `serde_json::to_string` in SQL builder:** `unwrap()`. Can panic. Avoid unwraps and do not build SQL strings.
*   **Inconsistent deletion semantics:** `delete_api_key()` revokes then returns `Ok` ignoring errors. Return actual result and error on failure.
*   **gRPC placeholder validation:** `ApiKeyService::validate_api_key()` constant check. Document as stub or implement DB check; currently misleading.
*   **Misclassified client errors:** controllers UUID parse mapped to `NotFound` and (`crates/lightbridge-authz-rest/src/handlers.rs:41`). Should be 400 Bad Request, not 404.

### Code style and API design

*   **Error typing:** controllers map invalid UUID to `NotFound`. Prefer a specific error variant for invalid input and map to 400. `api-key` crate uses `Error::Any` for invalid key. Add a dedicated error variant.
*   **DTO boundaries:** Expose response types separate from DB models to prevent accidental leakage of fields like `key_hash`; add response structs in the API crate.
*   **Pagination:** `list_api_keys` fixed 100,0. Add limit/offset parameters with sane bounds.
*   **Blocking I/O and shutdown:** REST server lacks graceful shutdown. `axum::serve(...)`. Add signal handling and `with_graceful_shutdown`. CLI unwraps config load `unwrap()` on `load_from_path` and (`crates/lightbridge-authz-cli/src/main.rs:79`). Return errors instead of panicking.
*   **Missing tests and docs coverage:** Placeholder tests. `tests` module placeholder. Add tests for create/get/patch/revoke paths, including ACL persistence and error cases.
