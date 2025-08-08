diesel::table! {
    use diesel::sql_types::*;
    api_keys (id) {
        id -> Uuid,
        key_hash -> Text,
        created_at -> Timestamptz,
        expires_at -> Nullable<Timestamptz>,
        metadata -> Nullable<Jsonb>,
        status -> Text,
    }
}
