# Technical Specification: Refactor `lightbridge-authz-rest` and `allowed_models`

## 1. Overview
This document outlines the plan to refactor the `lightbridge-authz-rest` crate to improve code organization and maintainability. It also details the design for a typed Authorino metadata struct and updates to the `allowed_models` logic in `lightbridge-authz-core`.

## 2. Folder Structure Redesign (`crates/lightbridge-authz-rest`)

The `src/` directory will be reorganized as follows:

```
crates/lightbridge-authz-rest/src/
├── handlers/
│   ├── mod.rs
│   ├── crud.rs       # AuthzStoreImpl (from handlers.rs)
│   ├── opa.rs        # OPA/Authorino validation handlers (from lib.rs)
│   └── system.rs     # Health and Root handlers (from lib.rs)
├── routers/
│   ├── mod.rs
│   ├── api.rs        # CRUD API router construction
│   └── opa.rs        # OPA/Authorino router construction
├── models/
│   ├── mod.rs
│   ├── opa.rs        # OpaCheckRequest, OpaCheckResponse, OpaErrorResponse
│   └── authorino.rs  # AuthorinoCheckRequest, AuthorinoCheckResponse, AuthorinoMetadata
├── middleware/
│   ├── mod.rs        # Existing middleware logic (basic_auth, bearer_auth)
└── lib.rs            # Entry point, re-exports, server startup logic
```

### Migration Plan

| Source File | Symbol/Function | Destination File | Notes |
| :--- | :--- | :--- | :--- |
| `src/handlers.rs` | `AuthzStoreImpl` | `src/handlers/crud.rs` | |
| `src/lib.rs` | `root_handler`, `health_handler` | `src/handlers/system.rs` | |
| `src/lib.rs` | `validate_api_key`, `validate_authorino_api_key` | `src/handlers/opa.rs` | Also `validate_api_key_context` helper |
| `src/lib.rs` | `OpaCheckRequest`, `OpaCheckResponse`, `OpaErrorResponse` | `src/models/opa.rs` | |
| `src/lib.rs` | `AuthorinoCheckRequest`, `AuthorinoCheckResponse` | `src/models/authorino.rs` | Will be updated to use new Metadata struct |
| `src/middleware.rs` | All content | `src/middleware/mod.rs` | |
| `src/lib.rs` | `start_api_server` logic | `src/routers/api.rs` | Extract router construction logic |
| `src/lib.rs` | `start_opa_server` logic | `src/routers/opa.rs` | Extract router construction logic |

## 3. Authorino Metadata Struct Design

A new struct `AuthorinoMetadata` will be created in `src/models/authorino.rs` to handle the dynamic metadata requirement while providing type safety for known fields.

```rust
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct AuthorinoMetadata {
    // Standard fields injected by the validation logic
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_id: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_status: Option<String>,

    // Capture any other fields sent by Authorino/Envoy
    #[serde(flatten)]
    #[schema(value_type = Object)]
    pub other: HashMap<String, Value>,
}

impl AuthorinoMetadata {
    pub fn new(other: HashMap<String, Value>) -> Self {
        Self {
            account_id: None,
            project_id: None,
            api_key_id: None,
            api_key_status: None,
            other,
        }
    }
}
```

The `AuthorinoCheckRequest` and `AuthorinoCheckResponse` structs will be updated to use this new type.

```rust
#[derive(Debug, Deserialize, ToSchema)]
pub struct AuthorinoCheckRequest {
    pub api_key: String,
    pub ip: Option<String>,
    #[serde(default)]
    pub metadata: HashMap<String, Value>, // Keep as HashMap in request to easily feed into Metadata struct
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthorinoCheckResponse {
    pub api_key: lightbridge_authz_core::ApiKey,
    pub project: lightbridge_authz_core::Project,
    pub account: lightbridge_authz_core::Account,
    pub dynamic_metadata: AuthorinoMetadata,
}
```

## 4. Allowed Models Logic Design

The `allowed_models` field in `Project` and `CreateProject` DTOs (in `crates/lightbridge-authz-core/src/dto.rs`) will be changed from `Vec<String>` to `Option<Vec<String>>`.

### Logic
- `None`: All models are allowed (wildcard).
- `Some([])` (Empty Vector): No models are allowed (deny all).
- `Some(["model-a"])`: Only listed models are allowed.

### Changes in `crates/lightbridge-authz-core/src/dto.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Project {
    // ... other fields
    #[serde(default)] // defaults to None
    pub allowed_models: Option<Vec<String>>,
    // ...
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateProject {
    // ... other fields
    #[serde(default)]
    pub allowed_models: Option<Vec<String>>,
    // ...
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateProject {
    // ... other fields
    pub allowed_models: Option<Option<Vec<String>>>, // Double Option to distinguish "no update" vs "update to None"
    // ...
}
```

### Database Considerations
The `projects` table defines `allowed_models` as `JSONB NOT NULL DEFAULT '[]'::jsonb`.
- We will **not** change the database schema in this task (no migration).
- We will handle the mapping in the repository layer (`crates/lightbridge-authz-api-key/src/repo.rs` and `entities/project_row.rs`).
- **Mapping Strategy**:
    - DB `[]` (empty array) -> Domain `Some(vec![])` (Deny All).
    - DB `null` (if it were nullable) -> Domain `None` (Allow All).
    - **Problem**: The DB column is `NOT NULL` and defaults to `[]`.
    - **Solution**: We need to decide how to represent "Allow All" in the DB without a schema change.
        - Option A: Use a special value like `["*"]`.
        - Option B: Treat `[]` as "Allow All" and `["__none__"]` as "Deny All".
        - Option C: Change the column to nullable (requires migration).
    - **Decision**: Since I cannot run migrations easily without potentially breaking things or requiring a restart, and the user asked for "Logic Design" for `allowed_models`, I will assume we can interpret `null` if we could, but given the constraint, I will propose:
        - **Update the DB schema to allow NULL**. This is the cleanest way.
        - Migration: `ALTER TABLE projects ALTER COLUMN allowed_models DROP NOT NULL; ALTER TABLE projects ALTER COLUMN allowed_models DROP DEFAULT;`
        - If migration is not possible, we will use `null` in JSONB. JSONB columns can hold a JSON `null` value even if the column is `NOT NULL`? No, `NOT NULL` prevents SQL NULL. It does not prevent JSON `null` if it's a valid JSON value, but usually `NOT NULL` on JSONB means the column value itself cannot be SQL NULL.
        - **Revised Decision**: I will create a migration to make `allowed_models` nullable. This aligns with `Option<Vec<String>>`.
        - Migration file: `migrations/20260220000001_make_allowed_models_nullable.sql`.
        - Content: `ALTER TABLE projects ALTER COLUMN allowed_models DROP NOT NULL; ALTER TABLE projects ALTER COLUMN allowed_models SET DEFAULT NULL;`

### Repository Changes
- `ProjectRow` struct in `crates/lightbridge-authz-api-key/src/entities/project_row.rs`:
    - Change `allowed_models: serde_json::Value` to `allowed_models: Option<serde_json::Value>` (if SQL NULL) or handle `Value::Null`.
    - Actually, `sqlx` maps JSONB to `serde_json::Value`. If the column is nullable, it maps to `Option<serde_json::Value>`.
- `StoreRepo::create_project`:
    - Map `CreateProject.allowed_models` (`Option<Vec<String>>`) to `serde_json::Value`.
    - `None` -> `Value::Null` (or SQL NULL).
    - `Some(vec)` -> `Value::Array(...)`.
- `StoreRepo::get_project`:
    - Map DB value back to `Option<Vec<String>>`.

## 5. Execution Steps

1.  **Refactor `lightbridge-authz-rest`**:
    - Create directories.
    - Move and split code.
    - Fix imports.
2.  **Implement `AuthorinoMetadata`**:
    - Add struct.
    - Update handlers.
3.  **Update `allowed_models`**:
    - Create migration to make `allowed_models` nullable.
    - Update DTOs in `core`.
    - Update `repo` and `entities` in `api-key`.

