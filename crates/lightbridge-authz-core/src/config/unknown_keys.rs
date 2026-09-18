use serde_yaml::Value;
use tracing::warn;

use super::unknown_keys_data::{DEPRECATED_KEYS, KNOWN_KEYS};

/// Inspect the interpolated YAML document a [`Config`](super::Config) was just parsed from and
/// `warn!` on every key it maps that the config structs do not accept (unknown) or that carries a
/// recorded deprecation hint. Parse failure is deliberately tolerated here as a no-op: by this
/// point `Config::deserialize` has already accepted the document, so the only documents this
/// rejects are ones that never got loaded in the first place.
pub(super) fn warn_unknown_keys_in_config(yaml: &str) {
    if let Ok(value) = serde_yaml::from_str::<Value>(yaml) {
        walk(&value, "");
    }
}

fn walk(value: &Value, path: &str) {
    let Value::Mapping(mapping) = value else {
        return;
    };

    let Some(known_fields) = get_known_fields(path) else {
        return;
    };

    for (k_val, v_val) in mapping {
        let Some(k_str) = k_val.as_str() else {
            continue;
        };

        let full_key = if path.is_empty() {
            k_str.to_string()
        } else {
            format!("{path}.{k_str}")
        };

        if let Some(hint) = get_deprecated_hint(&full_key) {
            warn!("Configuration key '{full_key}' is deprecated: {hint}");
        } else if !known_fields.contains(&k_str) {
            warn!("Unknown configuration key '{full_key}' ignored");
        } else {
            walk(v_val, &full_key);
        }
    }
}

fn get_known_fields(path: &str) -> Option<&'static [&'static str]> {
    KNOWN_KEYS
        .iter()
        .find(|(p, _)| *p == path)
        .map(|(_, fields)| *fields)
}

fn get_deprecated_hint(full_key: &str) -> Option<&'static str> {
    DEPRECATED_KEYS
        .iter()
        .find(|(k, _)| *k == full_key)
        .map(|(_, hint)| *hint)
}
