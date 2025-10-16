pub mod acl_model_row;
pub mod acl_row;
pub mod api_key_row;
pub mod new_acl_model_row;
pub mod new_acl_row;
pub mod new_api_key_row;

pub mod schema {
    diesel::table! {
        acl_models (id) {
            id -> Text,
            name -> Text,
            model -> Text,
        }
    }

    diesel::table! {
        acls (id) {
            id -> Text,
            api_key_id -> Text,
            permission -> Text,
        }
    }

    diesel::table! {
        api_keys (id) {
            id -> Text,
            user_id -> Text,
            name -> Text,
            key_hash -> Text,
            created_at -> Timestamptz,
            expires_at -> Nullable<Timestamptz>,
            last_used_at -> Nullable<Timestamptz>,
            revoked_at -> Nullable<Timestamptz>,
        }
    }

    diesel::joinable!(acls -> api_keys (api_key_id));

    diesel::allow_tables_to_appear_in_same_query!(acl_models, acls, api_keys,);
}
