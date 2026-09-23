use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Operator-configured catalogue of governance quota tiers (ADR-0006). Referenced by three write
/// paths -- `Account.defaultQuota`, `Project.projectQuota`, `ProjectMember.quotaTier` -- all
/// validated against this catalogue at write time (config, not DB), same shape and env-driven
/// loading (`QUOTA_TIERS` JSON-array string, or an inline YAML/JSON sequence) as `Billing` above.
/// Deliberately more permissive than `Billing`, though: `Billing::validate` requires a key-issuing
/// server to configure a non-empty catalogue, but an empty/absent tier catalogue here is the
/// supported default (see `is_allowed`) so existing deployments and charts keep working before
/// `ai-helm-values` supplies a real catalogue.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct QuotaTiers {
    #[serde(default, deserialize_with = "deserialize_tier_list")]
    pub tiers: Vec<QuotaTier>,
}

/// A single governance quota tier. `id` is the stable key stored on `Account.defaultQuota`,
/// `Project.projectQuota`, and `ProjectMember.quotaTier`; `name` is the human-facing label.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct QuotaTier {
    pub id: String,
    pub name: String,
}

impl QuotaTiers {
    /// Whether `tier` may be written to `Account.defaultQuota`, `Project.projectQuota`, or
    /// `ProjectMember.quotaTier`. `None` (the field left unset) is always allowed. Otherwise: an
    /// empty catalogue accepts any value uncritically (the deliberate default -- see the type-level
    /// doc comment); a non-empty catalogue accepts only a configured tier `id`.
    ///
    /// # Examples
    ///
    /// ```
    /// use lightbridge_authz_core::config::{QuotaTier, QuotaTiers};
    ///
    /// let tiers = QuotaTiers {
    ///     tiers: vec![QuotaTier { id: "bronze".into(), name: "Bronze".into() }],
    /// };
    ///
    /// assert!(tiers.is_allowed(None), "unset tier is always allowed");
    /// assert!(tiers.is_allowed(Some("bronze")), "configured tier is allowed");
    /// assert!(!tiers.is_allowed(Some("gold")), "unconfigured tier is rejected");
    ///
    /// let empty = QuotaTiers::default();
    /// assert!(empty.is_allowed(Some("anything")), "empty catalogue accepts any value");
    /// ```
    pub fn is_allowed(&self, tier: Option<&str>) -> bool {
        let Some(tier) = tier else {
            return true;
        };
        if self.tiers.is_empty() {
            return true;
        }
        self.tiers.iter().any(|t| t.id == tier)
    }

    /// Look up a tier by its `id`.
    pub fn get(&self, id: &str) -> Option<&QuotaTier> {
        if id.is_empty() {
            return None;
        }
        self.tiers.iter().find(|t| t.id == id)
    }

    /// The configured tier ids, for error messages.
    pub fn tier_ids(&self) -> Vec<&str> {
        self.tiers.iter().map(|t| t.id.as_str()).collect()
    }
}

/// Accepts a JSON-array string (the single-env-var case, e.g. `${QUOTA_TIERS}`), an inline
/// YAML/JSON sequence of tier objects, or null/blank. A null value or a blank/unset env var yields
/// an empty catalogue rather than a parse error -- mirrors `deserialize_plan_list` above.
fn deserialize_tier_list<'de, D>(deserializer: D) -> std::result::Result<Vec<QuotaTier>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct TiersVisitor;

    impl<'de> serde::de::Visitor<'de> for TiersVisitor {
        type Value = Vec<QuotaTier>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a JSON-array string, a sequence of quota tiers, or null")
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
            let mut tiers = Vec::new();
            while let Some(tier) = seq.next_element::<QuotaTier>()? {
                tiers.push(tier);
            }
            Ok(tiers)
        }
    }

    deserializer.deserialize_any(TiersVisitor)
}
