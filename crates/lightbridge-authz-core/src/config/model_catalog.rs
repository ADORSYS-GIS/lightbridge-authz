use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The operator-configured catalogue of AI models a `Project.allowedModels` editor may offer, and
/// -- since #415 (ADR-0018 Decision 5) -- the catalogue `setProjectAllowedModels` validates every
/// `allowedModels` entry against before writing. Populated from env — either a single
/// `MODEL_CATALOG` JSON-array env var (e.g. `models: "${MODEL_CATALOG}"`) or an inline YAML/JSON
/// sequence of model objects — the same shape and env-driven loading as `billing::Billing`/
/// `quota_tiers::QuotaTiers`. Unlike `Billing`, an empty/absent catalogue is the supported
/// default (see the
/// `Config::models` field doc comment and `invalid_ids` below): nothing here needs to fail startup
/// when unset, and until an operator populates a real catalogue every `allowedModels` value is
/// accepted uncritically, same as `QuotaTiers::is_allowed`'s contract for an empty tier list.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ModelCatalog {
    #[serde(default, deserialize_with = "deserialize_model_list")]
    pub models: Vec<ModelCatalogEntry>,
}

/// A single catalogue entry. `id` is the model id a caller would place in
/// `Project.allowedModels`; `name` is the human-facing label for a UI checkbox list.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct ModelCatalogEntry {
    pub id: String,
    pub name: String,
}

impl ModelCatalog {
    /// The configured model ids, mainly useful for tests/diagnostics -- `listModelCatalog` itself
    /// returns the full entries, not just ids.
    pub fn model_ids(&self) -> Vec<&str> {
        self.models.iter().map(|m| m.id.as_str()).collect()
    }

    /// Validates `models` (a `Project.allowedModels` write, e.g. from `setProjectAllowedModels`)
    /// against this catalogue, returning the entries (deduplicated, in the caller's order) that are
    /// not configured. An empty return means the write is allowed.
    ///
    /// `None` (the field left unset -- "all models allowed", unrelated to catalogue membership) is
    /// always allowed, matching `QuotaTiers::is_allowed`'s `None`-always-passes contract. An
    /// empty/absent catalogue accepts anything, including `Some(vec![...])` with entries that would
    /// otherwise be unrecognized -- the deliberate "no behavior change until populated" default (see
    /// this type's own doc comment), same as `QuotaTiers::is_allowed` for an empty tier list. This is
    /// the one asymmetry with `Billing::is_allowed`/`QuotaTiers::is_allowed`, which each validate a
    /// single scalar: `allowedModels` is a list, so a single invalid entry among otherwise-valid ones
    /// must still be named, not just accepted-or-rejected as a whole -- see the returned `Vec` above.
    pub fn invalid_ids<'a>(&self, models: Option<&'a [String]>) -> Vec<&'a str> {
        let Some(models) = models else {
            return Vec::new();
        };
        if self.models.is_empty() {
            return Vec::new();
        }
        let mut invalid: Vec<&str> = Vec::new();
        for id in models {
            let known = self.models.iter().any(|m| m.id == *id);
            if !known && !invalid.contains(&id.as_str()) {
                invalid.push(id.as_str());
            }
        }
        invalid
    }
}

/// Accepts a JSON-array string (the single-env-var case, e.g. `${MODEL_CATALOG}`), an inline
/// YAML/JSON sequence of model objects, or null/blank. A null value or a blank/unset env var yields
/// an empty catalogue rather than a parse error -- mirrors `billing::deserialize_plan_list` and
/// `quota_tiers::deserialize_tier_list`.
fn deserialize_model_list<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<ModelCatalogEntry>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ModelsVisitor;

    impl<'de> serde::de::Visitor<'de> for ModelsVisitor {
        type Value = Vec<ModelCatalogEntry>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a JSON-array string, a sequence of model catalogue entries, or null")
        }

        fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
            Ok(Vec::new())
        }

        fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
            Ok(Vec::new())
        }

        fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(self)
        }

        fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Ok(Vec::new());
            }
            serde_json::from_str(trimmed).map_err(E::custom)
        }

        fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut models = Vec::new();
            while let Some(model) = seq.next_element::<ModelCatalogEntry>()? {
                models.push(model);
            }
            Ok(models)
        }
    }

    deserializer.deserialize_any(ModelsVisitor)
}
