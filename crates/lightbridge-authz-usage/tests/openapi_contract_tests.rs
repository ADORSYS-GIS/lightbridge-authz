//! OpenAPI contract tests for the usage service.
//!
//! These live in the integration-test tree (not `src/lib.rs`) because `lib.rs` is grandfathered at
//! its LoC-gate ceiling (lightbridge-governance#172) and the contract tests would push it over.
//! `lightbridge_authz_usage_rest::usage_openapi_doc()` exposes the generated document publicly so
//! the tests can reach it from here. `tests/` files are reported by the LoC gate, never failed.

use lightbridge_authz_usage_rest::usage_openapi_doc;
use serde_json::Value;

fn usage_openapi() -> Value {
    serde_json::to_value(usage_openapi_doc()).expect("openapi should serialize")
}

#[test]
fn usage_openapi_should_expose_usage_paths() {
    let doc = usage_openapi();
    let paths = doc["paths"]
        .as_object()
        .expect("openapi paths should be an object");

    assert!(
        paths.contains_key("/usage/v1/usage/query"),
        "expected usage query endpoint in openapi paths"
    );
    assert!(
        paths.contains_key("/v1/otel/traces"),
        "expected traces ingest endpoint in openapi paths"
    );
    assert!(
        paths.contains_key("/v1/otel/metrics"),
        "expected metrics ingest endpoint in openapi paths"
    );
    assert!(
        paths.contains_key("/v1/otel/logs"),
        "expected logs ingest endpoint in openapi paths"
    );
    assert!(
        paths.contains_key("/usage/v1/spend/query"),
        "expected spend query endpoint in openapi paths"
    );
}

/// Guards the seam between this service and the console. `converse-frontends` hand-maintains
/// `openapi/usage.backend.yaml` and generates its typed client from it, so a latency field
/// that silently stops being published here would surface over there as a chart of nothing --
/// exactly the "permanent apology" state this whole change exists to remove. Asserting the
/// published schema, not just the Rust struct, is what makes that drift fail here first.
#[test]
fn usage_openapi_should_publish_the_latency_percentile_contract() {
    let doc = usage_openapi();
    let point = &doc["components"]["schemas"]["UsageSeriesPoint"]["properties"];

    for field in [
        "latency_samples",
        "latency_p50_ms",
        "latency_p95_ms",
        "latency_p99_ms",
    ] {
        assert!(
            point.get(field).is_some(),
            "expected UsageSeriesPoint.{field} in the published schema"
        );
    }

    let required: Vec<&str> = doc["components"]["schemas"]["UsageSeriesPoint"]["required"]
        .as_array()
        .expect("UsageSeriesPoint should declare required fields")
        .iter()
        .filter_map(|value| value.as_str())
        .collect();

    assert!(
        required.contains(&"latency_samples"),
        "latency_samples is always present and must be required, got {required:?}"
    );
}

/// The 2026-09-03 query-cost work: `metrics` is the console's lever for skipping the
/// latency percentiles, so both halves of the contract -- the request field and the response
/// echo -- are pinned in the published schema. A caller that cannot see the field cannot use
/// it, and a caller that cannot see the echo cannot tell "no latency samples" from "I did not
/// ask for percentiles".
#[test]
fn usage_openapi_should_publish_the_metrics_selection_contract() {
    let doc = usage_openapi();

    let metrics: Vec<&str> = doc["components"]["schemas"]["UsageMetric"]["enum"]
        .as_array()
        .expect("UsageMetric should publish an enum")
        .iter()
        .map(|v| v.as_str().expect("enum values are strings"))
        .collect();
    assert_eq!(metrics, vec!["totals", "latency_percentiles"]);

    assert!(
        doc["components"]["schemas"]["UsageQueryRequest"]["properties"]["metrics"].is_object(),
        "expected UsageQueryRequest.metrics in the published schema"
    );
    let required: Vec<&str> = doc["components"]["schemas"]["UsageQueryRequest"]["required"]
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assert!(
        !required.contains(&"metrics"),
        "metrics must stay optional -- every caller written before it existed omits it"
    );

    assert!(
        doc["components"]["schemas"]["UsageQueryResponse"]["properties"]["metrics"].is_object(),
        "expected UsageQueryResponse.metrics in the published schema"
    );
}

/// #578: pins `UsageQueryResponse.truncated` in the published schema, the same seam
/// `usage_openapi_should_publish_the_latency_percentile_contract` above guards for the
/// latency fields -- a client generated from `openapi/usage.backend.yaml` needs this field to
/// exist and be required to ever render a truncation notice at all.
#[test]
fn usage_openapi_should_publish_the_truncated_field() {
    let doc = usage_openapi();
    let response = &doc["components"]["schemas"]["UsageQueryResponse"];

    assert!(
        response["properties"].get("truncated").is_some(),
        "expected UsageQueryResponse.truncated in the published schema"
    );

    let required: Vec<&str> = response["required"]
        .as_array()
        .expect("UsageQueryResponse should declare required fields")
        .iter()
        .filter_map(|value| value.as_str())
        .collect();
    assert!(
        required.contains(&"truncated"),
        "truncated is always present and must be required, got {required:?}"
    );
}

/// #570: pins the 401/403 responses `/usage/v1/usage/query` now documents (bearer
/// authentication + ownership check), so a silent regression back to "no auth check
/// documented" fails here first.
#[test]
fn usage_openapi_should_publish_query_endpoint_auth_responses() {
    let doc = usage_openapi();
    let responses = &doc["paths"]["/usage/v1/usage/query"]["post"]["responses"];

    assert!(
        responses.get("401").is_some(),
        "expected /usage/v1/usage/query to document a 401 response"
    );
    assert!(
        responses.get("403").is_some(),
        "expected /usage/v1/usage/query to document a 403 response"
    );
}

/// #570: `/usage/v1/spend/query` now refuses a request carrying an `Authorization` header --
/// pins the 403 response that behavior is documented under.
#[test]
fn usage_openapi_should_publish_spend_endpoint_forbidden_response() {
    let doc = usage_openapi();
    let responses = &doc["paths"]["/usage/v1/spend/query"]["post"]["responses"];

    assert!(
        responses.get("403").is_some(),
        "expected /usage/v1/spend/query to document a 403 response"
    );
}

/// #732 (review follow-up): pins the 401/403 responses the execution query endpoint documents,
/// mirroring `usage_openapi_should_publish_query_endpoint_auth_responses` for the legacy
/// endpoint -- a silent regression back to "no auth check documented" fails here first.
#[test]
fn usage_openapi_should_publish_execution_query_auth_responses() {
    let doc = usage_openapi();
    let responses = &doc["paths"]["/usage/v1/usage/executions/query"]["post"]["responses"];

    assert!(
        responses.get("401").is_some(),
        "expected /usage/v1/usage/executions/query to document a 401 response"
    );
    assert!(
        responses.get("403").is_some(),
        "expected /usage/v1/usage/executions/query to document a 403 response"
    );
}

/// #648: the same console-facing seam as the latency/truncation guards above, for the three
/// usage dimensions. `converse-frontends` hand-maintains `openapi/usage.backend.yaml` and
/// generates its typed client from it, so these enum values ARE the contract -- a rename here
/// that is not mirrored there turns "cost by channel" into a 400 nobody notices until a
/// dashboard is blank. Asserting the published document (not just the Rust enum) is what
/// makes that drift fail on this side first.
#[test]
fn usage_openapi_should_publish_the_usage_dimension_contract() {
    let doc = usage_openapi();

    let group_by: Vec<&str> = doc["components"]["schemas"]["UsageGroupBy"]["enum"]
        .as_array()
        .expect("UsageGroupBy should publish an enum")
        .iter()
        .filter_map(|value| value.as_str())
        .collect();
    assert_eq!(
        group_by,
        vec![
            "account_id",
            "project_id",
            "api_key_id",
            "user_id",
            "user_name",
            "model",
            "metric_name",
            "signal_type",
            "source",
            "azp",
            "operation",
            "billing_plan",
        ],
        "UsageGroupBy's published values are the console's client contract"
    );

    let filters = &doc["components"]["schemas"]["UsageQueryFilters"]["properties"];
    for field in ["source", "azp", "operation", "billing_plan", "operation_in"] {
        assert!(
            filters.get(field).is_some(),
            "expected UsageQueryFilters.{field} in the published schema"
        );
    }
    assert_eq!(
        filters["operation_in"]["items"]["type"], "string",
        "operation_in must publish as an array of strings"
    );

    let point = &doc["components"]["schemas"]["UsageSeriesPoint"]["properties"];
    for field in ["source", "azp", "operation", "billing_plan"] {
        assert!(
            point.get(field).is_some(),
            "expected UsageSeriesPoint.{field} in the published schema"
        );
    }
}

/// #726: pins the execution-grain query endpoint in the published OpenAPI doc, the same seam
/// `usage_openapi_should_expose_usage_paths` guards for the legacy query endpoint -- a client
/// generated from `openapi/usage.backend.yaml` needs this path to exist to ever call it.
#[test]
fn usage_openapi_should_publish_execution_query_path() {
    let doc = usage_openapi();
    let paths = doc["paths"]
        .as_object()
        .expect("openapi paths should be an object");
    assert!(
        paths.contains_key("/usage/v1/usage/executions/query"),
        "expected the execution query endpoint in openapi paths"
    );
}

/// #726: pins the `ExecutionSeriesPoint` schema, and specifically that `total_cost` is
/// nullable -- `None` (unknown) must survive serialization as `null`, never `0`
/// (governance#188). A client generated from `openapi/usage.backend.yaml` needs to know the
/// field can be absent to render "unknown" rather than "free".
#[test]
fn usage_openapi_should_publish_execution_schema_with_nullable_total_cost() {
    let doc = usage_openapi();
    let point = &doc["components"]["schemas"]["ExecutionSeriesPoint"]["properties"];

    for field in [
        "bucket_start",
        "source",
        "model",
        "provider",
        "executions_count",
        "total_duration_ms",
        "total_cost",
        "total_input_tokens",
        "total_output_tokens",
        "tool_call_count",
    ] {
        assert!(
            point.get(field).is_some(),
            "expected ExecutionSeriesPoint.{field} in the published schema"
        );
    }

    let required: Vec<&str> = doc["components"]["schemas"]["ExecutionSeriesPoint"]["required"]
        .as_array()
        .expect("ExecutionSeriesPoint should declare required fields")
        .iter()
        .filter_map(|value| value.as_str())
        .collect();
    assert!(
        !required.contains(&"total_cost"),
        "total_cost must stay optional (nullable) in the published schema, got {required:?}"
    );

    // Absence from `required` alone would also pass for a non-nullable field clients may omit --
    // a different contract than "may be null". Pin the nullability marker itself (utoipa emits
    // OpenAPI 3.1-style `type: ["integer", "null"]` for `Option<i64>`).
    let cost_type: Vec<String> = match point["total_cost"]["type"].as_array() {
        Some(values) => values
            .iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect(),
        None => point["total_cost"]["type"]
            .as_str()
            .map(|value| vec![value.to_string()])
            .unwrap_or_default(),
    };
    assert!(
        cost_type.contains(&"null".to_string()),
        "total_cost must publish as nullable (type contains \"null\"), got {cost_type:?}"
    );
}

#[test]
fn usage_openapi_should_be_openapi_3() {
    let doc = usage_openapi();
    let version = doc["openapi"]
        .as_str()
        .expect("openapi version should be a string");
    assert!(
        version.starts_with("3."),
        "expected an OpenAPI 3.x document, got {version}"
    );
}
