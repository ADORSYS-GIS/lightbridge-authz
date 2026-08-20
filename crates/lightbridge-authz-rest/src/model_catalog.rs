//! Live read-through client for `listModelCatalog` against the `ai-models-info` service's
//! `/v1/models/info` endpoint (issue #393).
//!
//! `ai-models-info` (deployed by the sibling `ai-helm`/`ai-helm-values` repos, chart
//! `charts/ai-models-info`) already renders an OpenRouter-shape JSON catalog from the SAME
//! `models.yaml` data the `aii-models` ArgoCD ApplicationSet deploys real gateway routes from,
//! already filtered by that chart's own `ai-models-info.catalog` Helm helper to exactly the
//! subset a `Project.allowedModels` picker needs (enabled, non-`embedding`/`reranker` kind, not
//! `disableExternal`). `ModelCatalogClient` consumes `data[].id`/`data[].name` from that payload
//! verbatim -- no additional kind/enabled/disableExternal filtering is reimplemented here, since
//! that would just duplicate business logic that already lives correctly in the ai-helm chart.
//!
//! This replaces a second, hand-maintained `Config.models` catalogue that had no connection to
//! that same data and could silently drift from it -- the exact bug shape this repo has already
//! shipped twice (stale frontend RBAC map; the `allowed_models` cratestack/sqlx encoding bug,
//! #282/#283).
//!
//! `listModelCatalog` is a read-only display aid, not an authorization gate (see that procedure's
//! doc comment in `crates/lightbridge-authz-api/schema/authz.cstack`), so every way this HTTP call
//! can fail -- unreachable, timeout, non-2xx, unparseable body -- degrades to `None` here rather
//! than propagating an error; the caller (`Procedures::list_model_catalog` in `lib.rs`) falls back
//! to the static `Config.models` catalogue on `None`, exactly like `UsageServiceSpendReader`
//! degrading to `Spend::Unavailable` on the same class of failure.

use lightbridge_authz_api::schema;
use lightbridge_authz_core::config::ModelCatalogServiceClient;
use lightbridge_authz_core::error::{Error, Result};
use serde::Deserialize;

/// A single entry of the `ai-models-info` payload's `data[]` array. The real payload also carries
/// `architecture`, `pricing`, `context_length`, `supported_parameters`, `top_provider`, and more --
/// deliberately NOT modeled here (no `#[serde(deny_unknown_fields)]`) so those fields are silently
/// ignored rather than causing a deserialization failure.
#[derive(Debug, Clone, Deserialize)]
struct ModelsInfoEntry {
    id: String,
    name: String,
}

/// The top-level `ai-models-info` payload shape: `{"data": [...]}`.
#[derive(Debug, Clone, Deserialize)]
struct ModelsInfoCatalog {
    data: Vec<ModelsInfoEntry>,
}

/// HTTP client for the `ai-models-info` service's `/v1/models/info` endpoint. Built once at
/// server startup (see `start_api_server`), not per-request -- mirrors
/// `UsageServiceSpendReader`/`OAuth2TokenIssuer`'s own single-client-instance convention.
#[derive(Debug)]
pub struct ModelCatalogClient {
    client: reqwest::Client,
    url: String,
}

impl ModelCatalogClient {
    /// Builds a client against `config.base_url` (trailing slash stripped, `/v1/models/info`
    /// appended), with a per-request timeout of `config.timeout_ms`. Deliberately no TLS
    /// options -- `ai-models-info` serves plain HTTP in every environment this has been verified
    /// against (see `ModelCatalogServiceClient`'s own doc comment), so there is nothing to
    /// configure here beyond the timeout.
    pub fn new(config: &ModelCatalogServiceClient) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|err| {
                Error::Server(format!("failed to build model-catalog-service HTTP client: {err}"))
            })?;
        let base_url = config.base_url.trim_end_matches('/');
        Ok(Self {
            client,
            url: format!("{base_url}/v1/models/info"),
        })
    }

    /// Fetches the live catalog, mapping each `data[]` entry 1:1 onto the wire
    /// `ModelCatalogEntry` shape `listModelCatalog` returns. Returns `None` on any failure --
    /// network error, non-2xx status, or a body that doesn't parse -- logging a `tracing::warn!`
    /// naming the failure in each case, so a caller can fall back to the static catalogue without
    /// turning a display-aid dependency outage into a failed RPC call.
    pub async fn fetch(&self) -> Option<Vec<schema::ModelCatalogEntry>> {
        let response = match self.client.get(&self.url).send().await {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    url = %self.url,
                    "model-catalog-service request failed; falling back to the static model catalogue"
                );
                return None;
            }
        };

        if !response.status().is_success() {
            tracing::warn!(
                status = %response.status(),
                url = %self.url,
                "model-catalog-service returned a non-success status; falling back to the static model catalogue"
            );
            return None;
        }

        let body: ModelsInfoCatalog = match response.json().await {
            Ok(body) => body,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    url = %self.url,
                    "model-catalog-service returned a body that did not parse; falling back to the static model catalogue"
                );
                return None;
            }
        };

        Some(
            body.data
                .into_iter()
                .map(|entry| schema::ModelCatalogEntry {
                    id: entry.id,
                    name: entry.name,
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::MockServer;

    fn config(base_url: String) -> ModelCatalogServiceClient {
        ModelCatalogServiceClient {
            base_url,
            timeout_ms: 2_000,
        }
    }

    #[tokio::test]
    async fn fetch_maps_data_entries_and_ignores_extra_fields() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/v1/models/info");
            then.status(200).json_body(serde_json::json!({
                "data": [
                    {
                        "id": "adorsys-coder",
                        "name": "Adorsys Coder (MiniMax M2.7)",
                        "architecture": {"modality": "text"},
                        "context_length": 196608,
                        "pricing": {"prompt": "0", "completion": "0"},
                        "supported_parameters": ["temperature"],
                        "top_provider": {"is_moderated": false}
                    },
                    {"id": "dev-model-b", "name": "Dev Model B"}
                ]
            }));
        });

        let client = ModelCatalogClient::new(&config(server.base_url())).expect("client builds");
        let entries = client.fetch().await.expect("fetch succeeds");

        mock.assert();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, "adorsys-coder");
        assert_eq!(entries[0].name, "Adorsys Coder (MiniMax M2.7)");
        assert_eq!(entries[1].id, "dev-model-b");
        assert_eq!(entries[1].name, "Dev Model B");
    }

    #[tokio::test]
    async fn fetch_returns_none_on_non_success_status() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/v1/models/info");
            then.status(500);
        });

        let client = ModelCatalogClient::new(&config(server.base_url())).expect("client builds");
        assert!(client.fetch().await.is_none());
    }

    #[tokio::test]
    async fn fetch_returns_none_on_unparseable_body() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/v1/models/info");
            then.status(200).body("not json");
        });

        let client = ModelCatalogClient::new(&config(server.base_url())).expect("client builds");
        assert!(client.fetch().await.is_none());
    }

    #[tokio::test]
    async fn fetch_returns_none_when_unreachable() {
        let config = config("http://127.0.0.1:1".to_string());
        let client = ModelCatalogClient::new(&config).expect("client builds");
        assert!(client.fetch().await.is_none());
    }
}
