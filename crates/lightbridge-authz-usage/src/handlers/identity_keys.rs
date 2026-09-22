//! Existing request identity aliases, shared by extraction and natural-key scoping.
//! Moved unchanged from ingest.rs to keep its grandfathered size ceiling.

pub(super) const ACCOUNT_KEYS: [&str; 5] = [
    "account_id",
    "account.id",
    "x-account-id",
    "authz.account_id",
    "lb.account_id",
];
pub(super) const PROJECT_KEYS: [&str; 5] = [
    "project_id",
    "project.id",
    "x-project-id",
    "authz.project_id",
    "lb.project_id",
];
pub(super) const API_KEY_KEYS: [&str; 5] = [
    "api_key_id",
    "api_key.id",
    "x-api-key-id",
    "authz.api_key_id",
    "lb.api_key_id",
];
pub(super) const USER_KEYS: [&str; 6] = [
    "user_id",
    "user.id",
    "end_user.id",
    "lc_user_id",
    "x-user-id",
    "authz.user_id",
];
pub(super) const USER_NAME_KEYS: [&str; 6] = [
    "user_name",
    "user.name",
    "end_user.name",
    "lc_user_name",
    "x-user-name",
    "authz.user_name",
];
