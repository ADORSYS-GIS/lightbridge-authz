pub mod account_row;
pub mod api_key_row;
pub mod new_account_row;
pub mod new_api_key_row;
pub mod new_project_row;
pub mod project_row;

pub mod schema {
    diesel::table! {
        accounts (id) {
            id -> Text,
            billing_identity -> Text,
            owners_admins -> Jsonb,
            created_at -> Timestamptz,
            updated_at -> Timestamptz,
        }
    }

    diesel::table! {
        projects (id) {
            id -> Text,
            account_id -> Text,
            name -> Text,
            allowed_models -> Jsonb,
            default_limits -> Jsonb,
            billing_plan -> Text,
            created_at -> Timestamptz,
            updated_at -> Timestamptz,
        }
    }

    diesel::table! {
        api_keys (id) {
            id -> Text,
            project_id -> Text,
            name -> Text,
            key_prefix -> Text,
            key_hash -> Text,
            created_at -> Timestamptz,
            expires_at -> Nullable<Timestamptz>,
            status -> Text,
            last_used_at -> Nullable<Timestamptz>,
            last_ip -> Nullable<Text>,
            last_region -> Nullable<Text>,
            revoked_at -> Nullable<Timestamptz>,
        }
    }

    diesel::joinable!(projects -> accounts (account_id));
    diesel::joinable!(api_keys -> projects (project_id));

    diesel::allow_tables_to_appear_in_same_query!(accounts, projects, api_keys,);
}
