# API Key Data Model

This document outlines the data structures for the API Key management system.

## Why?

We need a robust way to manage API keys, including their association with users and fine-grained access control.

## Actual

### Rust Structs

Here are the proposed Rust structs to represent the API keys and their associated Access Control Lists (ACLs).

```rust
use std::collections::HashMap;
use uuid::Uuid;

/// Represents a single API Key.
pub struct ApiKey {
    /// The unique identifier for the API Key.
    pub id: Uuid,
    /// The user associated with this API Key.
    pub user_id: Uuid,
    /// The API Key string.
    pub key: String,
    /// The Access Control List for this API Key.
    pub acl: Acl,
}

/// Defines the Access Control List (ACL) for an API Key.
pub struct Acl {
    /// A list of models that the API Key is allowed to access.
    pub allowed_models: Vec<String>,
    /// A map of model names to their respective token limits.
    pub tokens_per_model: HashMap<String, u64>,
    /// The rate-limiting configuration for the API Key.
    pub rate_limit: RateLimit,
}

/// Configures rate-limiting for an API Key.
pub struct RateLimit {
    /// The number of allowed requests per window.
    pub requests: u32,
    /// The time window in seconds.
    pub window_seconds: u32,
}
```

### Database Schema

To store this information, we can use a combination of tables.

**`api_keys` table:**

| Column    | Type      | Description                               |
| :-------- | :-------- | :---------------------------------------- |
| `id`      | `UUID`    | Primary Key                               |
| `user_id` | `UUID`    | Foreign key to the `users` table          |
| `key`     | `TEXT`    | The hashed API key                        |
| `acl_id`  | `UUID`    | Foreign key to the `acls` table           |
| `created_at` | `TIMESTAMPTZ` | Timestamp of creation |
| `updated_at` | `TIMESTAMPTZ` | Timestamp of last update |

**`acls` table:**

| Column           | Type          | Description                               |
| :--------------- | :------------ | :---------------------------------------- |
| `id`             | `UUID`        | Primary Key                               |
| `rate_limit_requests` | `INTEGER` | Number of requests for rate limiting      |
| `rate_limit_window` | `INTEGER` | Time window in seconds for rate limiting  |
| `created_at`     | `TIMESTAMPTZ` | Timestamp of creation |
| `updated_at`     | `TIMESTAMPTZ` | Timestamp of last update |

**`acl_models` table:**

| Column      | Type      | Description                               |
| :---------- | :-------- | :---------------------------------------- |
| `acl_id`    | `UUID`    | Foreign key to the `acls` table           |
| `model_name`| `TEXT`    | The name of the allowed model             |
| `token_limit`| `BIGINT` | The token limit for this model            |

This schema normalizes the data, allowing for a flexible and scalable ACL system. An API key has one ACL, and an ACL can have multiple model permissions.

## How to?

1.  Create a migration to add the `api_keys`, `acls`, and `acl_models` tables.
2.  Implement the Rust structs in `crates/lightbridge-authz-core/src/api_key.rs`.
3.  Create the necessary functions to interact with the database.
