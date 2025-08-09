diesel::table! {
    use diesel::sql_types::*;
    api_keys (id) {
        id -> Uuid,
        key_hash -> Text,
        created_at -> Timestamptz,
        expires_at -> Nullable<Timestamptz>,
        metadata -> Nullable<Jsonb>,
        status -> Text,
        acl_id -> Uuid,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    acls (id) {
        id -> Uuid,
        rate_limit_requests -> Integer,
        rate_limit_window -> Integer,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    acl_models (acl_id, model_name) {
        acl_id -> Uuid,
        model_name -> Text,
        token_limit -> BigInt,
    }
}

diesel::joinable!(api_keys -> acls (acl_id));
diesel::joinable!(acl_models -> acls (acl_id));

diesel::allow_tables_to_appear_in_same_query!(api_keys, acls, acl_models,);
