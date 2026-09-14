//! Shared authentication and scope-authorization gate for every query listener endpoint that
//! requires an end-user bearer token and an ownership check (#570, #648, #586).
//!
//! Extracted from `handlers::query::query_usage` so that the day/seat grain and execution grain
//! endpoints (Tickets B/C/D under #586) can reuse the same gate without duplicating the
//! authentication/authorization logic or the fail-closed conventions.
//!
//! ## Scope models
//!
//! Different grain tables support different subsets of the five `UsageScope` variants:
//!
//! - **Legacy** (`usage_events`): all five scopes (`user`, `api_key`, `project`, `account`, `all`).
//! - **Day/Seat** (`usage_day_facts`, `usage_seat_snapshots`): only `user` (self-ownership via
//!   JWT subject) and `all` (`usage:read-all` permission). `account`/`project`/`api_key` are
//!   rejected with `400` because these grains have no per-account/per-project/per-key ownership
//!   authority.
//!
//! ## Fail-closed convention
//!
//! A missing or invalid bearer token is `Unauthorized` (401). An authenticated caller whose scope
//! is refused is `Forbidden` (403). A scope unsupported for the current grain is
//! `BadRequest` (400). There is never a permissive default -- every unknown state resolves to the
//! strictest applicable refusal.
//!
//! Split across `auth.rs` (bearer extraction + authentication), `scope.rs` (scope authorization)
//! and `validate.rs` (common request validation) purely because a single file would sit over the
//! LoC-gate ceiling (lightbridge-governance#172) -- the same reason `rpc_permission_map.rs` is
//! separate from `rpc_authorize.rs`. Moved verbatim, and this `mod.rs` re-exports everything, so
//! every existing `handlers::ownership::{...}` path (`query.rs`, the scope-authorization tests in
//! `tests/ownership_scope_tests.rs`) still resolves. The pairing the gate participates in is
//! unchanged: `query_usage` still calls `authenticate` then `authorize_scope` in the same order,
//! and the scope tests still walk the same scope × permission matrix.

mod auth;
mod scope;
mod validate;

pub use auth::{AuthOutcome, authenticate, extract_bearer_token, forbidden, unauthorized};
pub use scope::{GrainScope, ScopeAuthOutcome, authorize_scope};
pub use validate::validate_common_request;
