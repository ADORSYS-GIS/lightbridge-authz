use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The operator-configured catalogue of billing plans. Populated from env — either a single
/// `BILLING_PLANS` JSON-array env var (e.g. `plans: "${BILLING_PLANS}"`) or an inline YAML/JSON
/// sequence of plan objects.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Billing {
    #[serde(default, deserialize_with = "deserialize_plan_list")]
    pub plans: Vec<BillingPlan>,
}

/// A single billing plan. `id` is the stable key stored on the API key and named in
/// `CreateApiKey`; `name` is the human-facing label for UIs; `limits` carries the plan's
/// rate/usage envelope (all fields optional — absent means "unset / unlimited").
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct BillingPlan {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<BillingLimits>,
}

/// Rate/usage limits attached to a billing plan. Purely descriptive here — enforcement lives at
/// the edge (e.g. Authorino), which reads these via token introspection. Convention: an omitted
/// field (or an entirely omitted `limits` block, e.g. an unlimited "enterprise" plan) means *no
/// limit* for that dimension; the edge must treat an absent value as unlimited, not as "deny".
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct BillingLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_second: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_day: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_month: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrent_requests: Option<i32>,
}

impl Billing {
    /// Whether a plan with this `id` is configured.
    pub fn is_allowed(&self, id: &str) -> bool {
        self.get(id).is_some()
    }

    /// Look up a plan by its `id`.
    pub fn get(&self, id: &str) -> Option<&BillingPlan> {
        if id.is_empty() {
            return None;
        }
        self.plans.iter().find(|p| p.id == id)
    }

    /// The configured plan ids, for error messages.
    pub fn plan_ids(&self) -> Vec<&str> {
        self.plans.iter().map(|p| p.id.as_str()).collect()
    }

    /// Validates the catalogue for a server that issues API keys: it must be non-empty, every plan
    /// must have a non-empty `id`, and ids must be unique. Called at startup by the key-issuing
    /// servers so a misconfiguration fails loudly instead of silently rejecting every
    /// `CreateApiKey` with a `400`.
    pub fn validate(&self) -> Result<()> {
        if self.plans.is_empty() {
            return Err(Error::Server(
                "billing.plans is empty: configure at least one billing plan (API-key creation \
                 requires a valid plan)"
                    .to_string(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for plan in &self.plans {
            if plan.id.trim().is_empty() {
                return Err(Error::Server(
                    "billing.plans contains a plan with an empty id".to_string(),
                ));
            }
            if !seen.insert(plan.id.as_str()) {
                return Err(Error::Server(format!(
                    "billing.plans contains a duplicate plan id '{}'",
                    plan.id
                )));
            }
        }
        Ok(())
    }
}

/// Deserializes an optional field to its `Default` when the YAML value is null (rather than
/// erroring). Lets `billing:` with no value fall back to an empty catalogue.
pub fn deserialize_null_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// Accepts a JSON-array string (the single-env-var case, e.g. `${BILLING_PLANS}`), an inline
/// YAML/JSON sequence of plan objects, or null/blank. A null value or a blank/unset env var yields
/// an empty catalogue rather than a parse error.
fn deserialize_plan_list<'de, D>(deserializer: D) -> std::result::Result<Vec<BillingPlan>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct PlansVisitor;

    impl<'de> serde::de::Visitor<'de> for PlansVisitor {
        type Value = Vec<BillingPlan>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a JSON-array string, a sequence of billing plans, or null")
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
            let mut plans = Vec::new();
            while let Some(plan) = seq.next_element::<BillingPlan>()? {
                plans.push(plan);
            }
            Ok(plans)
        }
    }

    deserializer.deserialize_any(PlansVisitor)
}
