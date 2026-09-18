use crate::error::{Error, Result};
use serde::Deserialize;

/// Operator-configured ceiling on `api_keys.expires_at` (lightbridge-authz#395). Every
/// `createApiKey`/`rotateApiKey` write is validated against this: `expiresAt` must be present, in
/// the future, and no further out than `now + max_lifetime_days`
/// (`AuthzStoreImpl::validate_expires_at`, `crates/lightbridge-authz-rest/src/handlers/mod.rs`).
///
/// Deliberately the opposite default posture from `QuotaTiers`/`ModelCatalog` above: those two
/// treat an empty/absent catalogue as "accept anything" because they gate optional, informational
/// fields. This gates a mandatory credential-lifetime ceiling, so absent must resolve to a real,
/// conservative number (90 days) instead -- never to "no ceiling". `Default` and serde's
/// `#[serde(default)]` both route through the same `default_api_key_max_lifetime_days` constant so
/// "field omitted from YAML" and "struct built directly in Rust with `..Default::default()`" can
/// never disagree.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ApiKeyExpiry {
    #[serde(default = "default_api_key_max_lifetime_days")]
    pub max_lifetime_days: u32,
}

impl Default for ApiKeyExpiry {
    fn default() -> Self {
        Self {
            max_lifetime_days: default_api_key_max_lifetime_days(),
        }
    }
}

fn default_api_key_max_lifetime_days() -> u32 {
    90
}

impl ApiKeyExpiry {
    /// Fails startup loudly on a nonsensical ceiling, mirroring `Billing::validate`'s and
    /// `ApiKeyJwtSigner::from_config`'s own startup guards (`oauth2.signing.ttl_seconds must be
    /// positive`) -- a misconfigured ceiling must never silently become "no ceiling" (zero days
    /// would make every `createApiKey` call fail instead, which is the fail-closed direction, but
    /// still worth rejecting loudly at startup rather than discovering it via a wall of runtime
    /// 400s).
    pub fn validate(&self) -> Result<()> {
        if self.max_lifetime_days == 0 {
            return Err(Error::Server(
                "api_key_expiry.max_lifetime_days must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }
}
