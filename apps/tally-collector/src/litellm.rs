use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use reqwest::{Url, header::HeaderValue};
use serde::{Deserialize, Serialize};
use tally_connectors::{
    LITELLM_USAGE_PROJECTION_SCHEMA_VERSION, MAX_BATCH_OBSERVATIONS, MAX_IMPORT_BYTES,
};
use tally_core::{Hostname, RequestClientKind, RequestClientObservation};

use crate::pull_support::{NativeEnterpriseSnapshot, bounded_response};

#[derive(Deserialize)]
struct LitellmModelGroupInfoResponse {
    data: Vec<LitellmModelGroupInfo>,
}

#[derive(Deserialize)]
struct LitellmModelGroupInfo {
    model_group: String,
    #[serde(default)]
    providers: Vec<String>,
}

#[derive(Deserialize)]
struct LitellmSpendLogsResponse {
    #[serde(default)]
    data: Vec<LitellmSpendLog>,
    total: usize,
}

#[derive(Deserialize)]
struct LitellmSpendLog {
    request_id: String,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    custom_llm_provider: Option<String>,
    #[serde(default)]
    model_group: Option<String>,
    #[serde(default)]
    api_base: Option<String>,
    #[serde(default, rename = "startTime")]
    start_time: Option<DateTime<Utc>>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    end_user: Option<String>,
    #[serde(default)]
    requester_ip_address: Option<String>,
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    request_tags: Option<Vec<String>>,
    #[serde(default)]
    metadata: Option<LitellmSpendMetadata>,
}

#[derive(Default, Deserialize)]
struct LitellmSpendMetadata {
    #[serde(default)]
    model_group: Option<String>,
    #[serde(default)]
    user_api_key_user_id: Option<String>,
    #[serde(default)]
    user_api_key_user_email: Option<String>,
    #[serde(default)]
    requester_ip_address: Option<String>,
    #[serde(default)]
    user_agent: Option<String>,
    #[serde(default)]
    spend_logs_metadata: Option<LitellmRequestContext>,
    #[serde(default)]
    requester_metadata: Option<LitellmRequestContext>,
    #[serde(default)]
    proxy_server_request: Option<LitellmRequestContext>,
}

// Deserialize only attribution fields; all other headers, bodies, keys and metadata are ignored.
#[derive(Default, Deserialize)]
struct LitellmRequestContext {
    #[serde(default)]
    source_hostname: Option<String>,
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    headers: Option<LitellmAttributionHeaders>,
}

#[derive(Default, Deserialize)]
struct LitellmAttributionHeaders {
    #[serde(default, rename = "user-agent")]
    user_agent: Option<String>,
    #[serde(default, rename = "x-tally-source-hostname")]
    source_hostname: Option<String>,
    #[serde(default, rename = "x-tally-agent-id")]
    agent_id: Option<String>,
}

#[derive(Serialize)]
struct LitellmProjection {
    schema_version: &'static str,
    endpoint_ref: String,
    observed_at: DateTime<Utc>,
    model_groups: Vec<LitellmProjectionGroup>,
    usage: Vec<LitellmProjectionUsage>,
}

#[derive(Serialize)]
struct LitellmProjectionGroup {
    model_group: String,
    providers: Vec<String>,
}

#[derive(Serialize)]
struct LitellmProjectionUsage {
    request_id: String,
    provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    observed_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requester_ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_client: Option<RequestClientObservation>,
}

pub(crate) struct LitellmPullOutcome {
    pub snapshot: NativeEnterpriseSnapshot,
    pub window_end: DateTime<Utc>,
    pub usage_truncated: bool,
}

/// Validates an operator-referenced `LiteLLM` origin: HTTPS except for an explicit loopback HTTP
/// development origin, no credentials, no query, no fragment, and no path so the pull can only
/// reach the fixed read-only route.
pub(crate) fn litellm_api_base(value: &str) -> Result<Url> {
    let mut url = Url::parse(value).context("invalid LiteLLM base URL reference")?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("LiteLLM base URL requires a host"))?;
    let ip_literal = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let loopback = host.eq_ignore_ascii_case("localhost")
        || ip_literal
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "LiteLLM base URL must use HTTPS unless it is an HTTP loopback origin"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "LiteLLM base URL cannot contain credentials"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "LiteLLM base URL cannot contain query or fragment data"
    );
    ensure!(
        matches!(url.path(), "" | "/"),
        "LiteLLM base URL cannot contain a path"
    );
    url.set_path("/");
    Ok(url)
}

/// Pulls the bounded `LiteLLM` model-group inventory and projects only capability metadata.
///
/// `record_count` includes every bounded provider pair so uncatalogued providers reach the
/// authorization queue rather than being mistaken for an empty poll.
#[allow(clippy::too_many_lines)] // Keeps both bounded read-only endpoints in one atomic pull.
pub(crate) async fn pull_litellm(
    api_base: &Url,
    api_key: &str,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    record_limit: usize,
    client: &reqwest::Client,
) -> Result<LitellmPullOutcome> {
    ensure!(
        !api_key.is_empty() && api_key.len() <= 2_048,
        "invalid LiteLLM key reference"
    );
    let mut authorization = HeaderValue::from_str(&format!("Bearer {api_key}"))
        .context("invalid LiteLLM key reference")?;
    authorization.set_sensitive(true);
    ensure!(window_start < window_end, "invalid LiteLLM usage window");
    ensure!(
        (1..=5_000).contains(&record_limit),
        "invalid LiteLLM usage record limit"
    );
    let url = api_base
        .join("model_group/info")
        .context("build fixed LiteLLM model-group URL")?;
    let response = client
        .get(url)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .context("LiteLLM model-group request failed")?;
    let bytes = bounded_response(response, "LiteLLM").await?;
    let payload: LitellmModelGroupInfoResponse =
        serde_json::from_slice(&bytes).context("invalid LiteLLM model-group response")?;
    drop(bytes);
    ensure!(
        payload.data.len() <= MAX_BATCH_OBSERVATIONS,
        "LiteLLM model-group cap exceeded"
    );
    let mut groups = Vec::new();
    let mut seen_groups = BTreeSet::new();
    let mut provider_pairs = 0_usize;
    let mut providers_by_group = BTreeMap::new();
    for group in payload.data {
        let model_group = group.model_group.trim().to_owned();
        ensure!(
            !model_group.is_empty()
                && model_group.len() <= 512
                && !model_group.chars().any(char::is_control),
            "invalid LiteLLM model group identifier"
        );
        ensure!(
            seen_groups.insert(model_group.clone()),
            "duplicate LiteLLM model group"
        );
        let providers = group
            .providers
            .iter()
            .map(|provider| provider.trim().to_ascii_lowercase())
            .filter(|provider| safe_provider_token(provider))
            .collect::<BTreeSet<_>>();
        if providers.is_empty() {
            continue;
        }
        provider_pairs = provider_pairs.saturating_add(providers.len());
        providers_by_group.insert(model_group.clone(), providers.clone());
        groups.push(LitellmProjectionGroup {
            model_group,
            providers: providers.into_iter().collect(),
        });
    }
    groups.sort_by(|left, right| left.model_group.cmp(&right.model_group));
    let (spend_logs, usage_truncated) = fetch_spend_logs(
        api_base,
        api_key,
        window_start,
        window_end,
        record_limit,
        client,
    )
    .await?;
    let usage = spend_logs
        .into_iter()
        .filter_map(|record| project_usage(record, &providers_by_group))
        .collect::<Vec<_>>();
    ensure!(
        provider_pairs.saturating_add(usage.len()) <= MAX_BATCH_OBSERVATIONS,
        "LiteLLM projection record cap exceeded"
    );
    let usage_count = usage.len();
    let data = serde_json::to_vec(&LitellmProjection {
        schema_version: LITELLM_USAGE_PROJECTION_SCHEMA_VERSION,
        endpoint_ref: api_base.as_str().to_owned(),
        observed_at: window_end,
        model_groups: groups,
        usage,
    })?;
    ensure!(
        data.len() <= MAX_IMPORT_BYTES,
        "LiteLLM projection is too large"
    );
    Ok(LitellmPullOutcome {
        snapshot: NativeEnterpriseSnapshot {
            data,
            record_count: provider_pairs.saturating_add(usage_count),
        },
        window_end,
        usage_truncated,
    })
}

async fn fetch_spend_logs(
    api_base: &Url,
    api_key: &str,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    record_limit: usize,
    client: &reqwest::Client,
) -> Result<(Vec<LitellmSpendLog>, bool)> {
    let page_size = record_limit.min(1_000);
    let mut authorization = HeaderValue::from_str(&format!("Bearer {api_key}"))
        .context("invalid LiteLLM key reference")?;
    authorization.set_sensitive(true);
    let mut logs = Vec::new();
    let mut expected_total = None;
    for page in 1..=record_limit.div_ceil(page_size) {
        let mut url = api_base
            .join("spend/logs/v2")
            .context("build fixed LiteLLM spend-log URL")?;
        url.query_pairs_mut()
            .append_pair(
                "start_date",
                &window_start.format("%Y-%m-%d %H:%M:%S").to_string(),
            )
            .append_pair(
                "end_date",
                &window_end.format("%Y-%m-%d %H:%M:%S").to_string(),
            )
            .append_pair("page", &page.to_string())
            .append_pair("page_size", &page_size.to_string())
            .append_pair("sort_by", "startTime")
            .append_pair("sort_order", "asc");
        let response = client
            .get(url)
            .header(reqwest::header::AUTHORIZATION, authorization.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .context("LiteLLM spend-log request failed")?;
        let bytes = bounded_response(response, "LiteLLM spend logs").await?;
        let result: LitellmSpendLogsResponse =
            serde_json::from_slice(&bytes).context("invalid LiteLLM spend-log response")?;
        ensure!(
            result.data.len() <= page_size && result.total >= logs.len() + result.data.len(),
            "LiteLLM spend-log page count was inconsistent"
        );
        if let Some(total) = expected_total {
            ensure!(
                total == result.total,
                "LiteLLM spend-log total changed while paging"
            );
        } else {
            expected_total = Some(result.total);
        }
        ensure!(
            !result.data.is_empty() || logs.len() >= result.total,
            "LiteLLM spend-log page ended before the reported total"
        );
        let page_count = result.data.len();
        logs.extend(result.data.into_iter().take(record_limit - logs.len()));
        if logs.len() >= result.total || logs.len() == record_limit {
            let truncated = result.total > logs.len();
            return Ok((logs, truncated));
        }
        ensure!(
            page_count == page_size,
            "LiteLLM spend-log page ended before the reported total"
        );
    }
    anyhow::bail!("LiteLLM spend-log pagination exceeded its bounded page count")
}

fn project_usage(
    record: LitellmSpendLog,
    providers_by_group: &BTreeMap<String, BTreeSet<String>>,
) -> Option<LitellmProjectionUsage> {
    let metadata = record.metadata.unwrap_or_default();
    let observed_at = record.start_time?;
    let model = bounded_text(record.model, 512)?;
    let provider = record
        .custom_llm_provider
        .as_deref()
        .and_then(normalized_provider)
        .map(str::to_owned)
        .or_else(|| provider_from_model(&model))
        .or_else(|| {
            let group = record
                .model_group
                .as_deref()
                .or(metadata.model_group.as_deref())?;
            let providers = providers_by_group.get(group)?;
            (providers.len() == 1)
                .then(|| providers.iter().next().cloned())
                .flatten()
        })?;
    if !safe_provider_token(&provider) {
        return None;
    }
    let request_id = bounded_text(Some(record.request_id), 2_048)?;
    let (source_hostname, request_client) =
        project_client_metadata(&metadata, record.agent_id, record.request_tags.as_deref());
    let user = [
        record.end_user,
        metadata.user_api_key_user_email,
        record.user,
        metadata.user_api_key_user_id,
    ]
    .into_iter()
    .find_map(|value| bounded_text(value, 512));
    // Only source-native IP fields are accepted. Host, X-Forwarded-For and arbitrary headers
    // cannot establish a trustworthy client address and must never be promoted to source IP.
    let requester_ip_address = [record.requester_ip_address, metadata.requester_ip_address]
        .into_iter()
        .flatten()
        .find_map(|value| value.parse::<IpAddr>().ok().map(|ip| ip.to_string()));
    let destination_url = record.api_base.and_then(|value| sanitized_origin(&value));
    Some(LitellmProjectionUsage {
        request_id,
        provider,
        model: Some(model),
        observed_at,
        user,
        requester_ip_address,
        destination_url,
        source_hostname,
        request_client,
    })
}

fn project_client_metadata(
    metadata: &LitellmSpendMetadata,
    agent_id: Option<String>,
    request_tags: Option<&[String]>,
) -> (Option<String>, Option<RequestClientObservation>) {
    let contexts = [
        metadata.spend_logs_metadata.as_ref(),
        metadata.requester_metadata.as_ref(),
        metadata.proxy_server_request.as_ref(),
    ];
    let source_hostname = contexts.iter().flatten().find_map(|context| {
        [
            context.source_hostname.as_deref(),
            context
                .headers
                .as_ref()
                .and_then(|headers| headers.source_hostname.as_deref()),
        ]
        .into_iter()
        .flatten()
        .find_map(|value| {
            Hostname::parse(value)
                .ok()
                .map(|host| host.as_str().to_owned())
        })
    });
    let name = metadata
        .user_agent
        .as_deref()
        .and_then(RequestClientKind::from_user_agent)
        .or_else(|| {
            contexts.iter().flatten().find_map(|context| {
                context
                    .headers
                    .as_ref()?
                    .user_agent
                    .as_deref()
                    .and_then(RequestClientKind::from_user_agent)
            })
        })
        .or_else(|| {
            request_tags
                .unwrap_or_default()
                .iter()
                .take(64)
                .find_map(|tag| {
                    tag.strip_prefix("User-Agent: ")
                        .and_then(RequestClientKind::from_user_agent)
                })
        });
    let agent_id = agent_id
        .filter(|value| RequestClientObservation::valid_agent_id(value))
        .or_else(|| {
            contexts.iter().flatten().find_map(|context| {
                [
                    context.agent_id.as_deref(),
                    context
                        .headers
                        .as_ref()
                        .and_then(|headers| headers.agent_id.as_deref()),
                ]
                .into_iter()
                .flatten()
                .find(|value| RequestClientObservation::valid_agent_id(value))
                .map(str::to_owned)
            })
        });
    let request_client = (name.is_some() || agent_id.is_some())
        .then_some(RequestClientObservation { name, agent_id });
    (source_hostname, request_client)
}

fn provider_from_model(model: &str) -> Option<String> {
    let provider = model.split_once('/').map(|(provider, _)| provider)?;
    normalized_provider(provider).map(str::to_owned)
}

fn normalized_provider(provider: &str) -> Option<&str> {
    let normalized = match provider {
        "vertex_ai" | "vertex_ai-language-models" => "gemini",
        "mistral" => "mistral_ai",
        value => value,
    };
    safe_provider_token(normalized).then_some(normalized)
}

fn bounded_text(value: Option<String>, max: usize) -> Option<String> {
    value.map(|value| value.trim().to_owned()).filter(|value| {
        !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
    })
}

fn sanitized_origin(value: &str) -> Option<String> {
    let mut url = Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
    {
        return None;
    }
    url.set_path("/");
    url.set_query(None);
    url.set_fragment(None);
    Some(url.to_string())
}

fn safe_provider_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, extract::Query, routing::get};

    #[test]
    fn request_attribution_is_extracted_before_headers_and_user_agent_are_discarded() {
        let record: LitellmSpendLog = serde_json::from_value(serde_json::json!({
            "request_id":"request-real-client", "model":"deepseek-chat",
            "custom_llm_provider":"deepseek", "startTime":"2026-10-06T07:48:04Z",
            "end_user":"aishu@acme.test", "requester_ip_address":"localhost:4000",
            "api_base":"https://api.deepseek.com/beta/chat/completions?secret=URL_CANARY",
            "metadata": {
                "requester_ip_address":"10.24.3.8", "user_agent":"LangChain-agent/1.0 UA_CANARY",
                "user_api_key":"KEY_CANARY", "spend_logs_metadata": {
                    "source_hostname":"Aishu-Laptop.local", "agent_id":"agent-aishu-1", "prompt":"CONTENT_CANARY"
                },
                "proxy_server_request":{"headers":{"authorization":"HEADER_CANARY","host":"gateway.example:4000","x-forwarded-for":"198.51.100.99"},"body":{"messages":["BODY_CANARY"]}}
            }
        })).expect("spend row");
        let usage = project_usage(record, &BTreeMap::new()).expect("usage");
        assert_eq!(usage.user.as_deref(), Some("aishu@acme.test"));
        assert_eq!(usage.requester_ip_address.as_deref(), Some("10.24.3.8"));
        assert_eq!(usage.source_hostname.as_deref(), Some("aishu-laptop.local"));
        assert_eq!(
            usage.request_client.as_ref().unwrap().name,
            Some(RequestClientKind::LangChain)
        );
        assert_eq!(
            usage.request_client.as_ref().unwrap().agent_id.as_deref(),
            Some("agent-aishu-1")
        );
        assert_eq!(
            usage.destination_url.as_deref(),
            Some("https://api.deepseek.com/")
        );
        let encoded = serde_json::to_string(&usage).unwrap();
        for forbidden in [
            "CANARY",
            "user_agent",
            "headers",
            "x-forwarded-for",
            "prompt",
            "api_key",
            "beta/chat/completions",
        ] {
            assert!(!encoded.contains(forbidden), "retained {forbidden}");
        }
    }

    #[test]
    fn tags_and_explicit_headers_are_bounded_hints_not_proxy_identity() {
        let mut record = serde_json::json!({
            "request_id":"request-tags", "model":"deepseek-chat", "custom_llm_provider":"deepseek",
            "startTime":"2026-10-06T07:48:04Z", "requester_ip_address":"localhost:4000", "agent_id":"https://secret.example/?key=secret",
            "request_tags":["arbitrary-secret-tag", "User-Agent: LangChain/0.2.11"],
            "metadata":{"proxy_server_request":{"headers":{"host":"localhost:4000","x-forwarded-for":"203.0.113.7","authorization":"HEADER_CANARY"}}}
        });
        let usage = project_usage(
            serde_json::from_value(record.clone()).unwrap(),
            &BTreeMap::new(),
        )
        .unwrap();
        assert!(usage.requester_ip_address.is_none());
        assert!(usage.source_hostname.is_none());
        assert_eq!(
            usage.request_client.unwrap(),
            RequestClientObservation {
                name: Some(RequestClientKind::LangChain),
                agent_id: None
            }
        );
        record["request_tags"] = serde_json::Value::Null;
        record["metadata"]["proxy_server_request"]["headers"]["user-agent"] =
            "OpenCode/1.18.30".into();
        record["metadata"]["proxy_server_request"]["headers"]["x-tally-source-hostname"] =
            "laptop-42.local".into();
        record["metadata"]["proxy_server_request"]["headers"]["x-tally-agent-id"] =
            "local-agent-42".into();
        let usage = project_usage(
            serde_json::from_value(record.clone()).unwrap(),
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(usage.source_hostname.as_deref(), Some("laptop-42.local"));
        assert_eq!(
            usage.request_client.unwrap().name,
            Some(RequestClientKind::OpenCode)
        );
        record["metadata"] = serde_json::Value::Null;
        assert!(
            project_usage(serde_json::from_value(record).unwrap(), &BTreeMap::new())
                .unwrap()
                .request_client
                .is_none()
        );
    }

    #[test]
    fn malformed_end_user_does_not_hide_native_user_attribution() {
        let record = serde_json::from_value(serde_json::json!({
            "request_id":"request-user", "model":"deepseek-chat", "custom_llm_provider":"deepseek",
            "startTime":"2026-10-06T07:48:04Z", "end_user":" ", "metadata":{"user_api_key_user_email":"owner@example.test"}
        })).unwrap();
        assert_eq!(
            project_usage(record, &BTreeMap::new())
                .unwrap()
                .user
                .as_deref(),
            Some("owner@example.test")
        );
    }

    #[tokio::test]
    async fn spend_logs_read_all_pages_before_advancing_the_window() {
        let app = Router::new().route(
            "/spend/logs/v2",
            get(|Query(query): Query<BTreeMap<String, String>>| async move {
                let page: usize = query["page"].parse().expect("page");
                let size: usize = query["page_size"].parse().expect("page size");
                let start = (page - 1) * size;
                let data = (start..(start + size).min(1_200))
                    .map(|id| serde_json::json!({"request_id":format!("request-{id}")}))
                    .collect::<Vec<_>>();
                Json(serde_json::json!({"data":data,"total":1200}))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local spend fixture");
        let base = Url::parse(&format!(
            "http://{}/",
            listener.local_addr().expect("local address")
        ))
        .expect("fixture URL");
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let start = "2026-09-15T10:00:00Z".parse().expect("start");
        let end = "2026-09-15T10:05:00Z".parse().expect("end");
        let client = reqwest::Client::new();
        let (logs, truncated) = fetch_spend_logs(&base, "test", start, end, 5_000, &client)
            .await
            .expect("all logs");
        assert_eq!(logs.len(), 1_200);
        assert_eq!(logs[1_199].request_id, "request-1199");
        assert!(!truncated);
        let (logs, truncated) = fetch_spend_logs(&base, "test", start, end, 1_000, &client)
            .await
            .expect("capped logs");
        assert_eq!(logs.len(), 1_000);
        assert!(truncated);
        server.abort();
    }

    #[test]
    fn spend_page_requires_a_total_before_advancing_time() {
        assert!(serde_json::from_slice::<LitellmSpendLogsResponse>(br#"{"data":[]}"#).is_err());
        let complete: LitellmSpendLogsResponse =
            serde_json::from_slice(br#"{"data":[],"total":0}"#).expect("complete page");
        assert_eq!(complete.total, 0);
    }
    #[test]
    fn litellm_origin_requires_https_except_for_explicit_loopback() {
        let url = litellm_api_base("https://litellm.internal.example:4000").expect("URL");
        assert_eq!(url.as_str(), "https://litellm.internal.example:4000/");
        assert!(litellm_api_base("http://localhost:4000").is_ok());
        assert!(litellm_api_base("http://127.0.0.1:4000").is_ok());
        assert!(litellm_api_base("http://127.23.45.67:4000").is_ok());
        assert!(litellm_api_base("http://[::1]:4000").is_ok());
        assert!(litellm_api_base("http://litellm.internal.example:4000").is_err());
        assert!(litellm_api_base("http://10.0.0.4:4000").is_err());
        assert!(litellm_api_base("http://0.0.0.0:4000").is_err());
        assert!(litellm_api_base("https://user:secret@litellm.example").is_err());
        assert!(litellm_api_base("https://litellm.example/admin").is_err());
        assert!(litellm_api_base("https://litellm.example/?key=sk-secret").is_err());
    }

    #[test]
    fn litellm_projection_drops_unrequested_metadata_and_keeps_safe_provider_tokens() {
        let payload: LitellmModelGroupInfoResponse = serde_json::from_slice(
            br#"{
              "data":[
                {
                  "model_group":"claude-prod",
                  "providers":["Anthropic","bedrock","Invalid Provider!"],
                  "max_input_tokens":200000,
                  "input_cost_per_token":0.000003,
                  "supported_openai_params":["LITELLM_PARAM_CANARY"]
                },
                {"model_group":"local-only","providers":["ollama_chat"]}
              ]
            }"#,
        )
        .expect("permissive parse");
        assert_eq!(payload.data.len(), 2);
        let normalized = payload.data[0]
            .providers
            .iter()
            .map(|provider| provider.trim().to_ascii_lowercase())
            .filter(|provider| safe_provider_token(provider))
            .collect::<Vec<_>>();
        assert_eq!(normalized, ["anthropic", "bedrock"]);
        assert_eq!(normalized.len(), 2);
        let projected = serde_json::to_string(&LitellmProjectionGroup {
            model_group: payload.data[0].model_group.clone(),
            providers: normalized,
        })
        .expect("projection");
        assert!(!projected.contains("CANARY"));
        assert!(!projected.contains("max_input_tokens"));
    }

    #[test]
    fn litellm_v1_99_spend_log_prefers_the_request_end_user() {
        let record: LitellmSpendLog = serde_json::from_slice(
            br#"{
              "request_id":"chatcmpl-tally-e2e",
              "model":"ollama/qwen2.5:0.5b",
              "custom_llm_provider":"ollama",
              "model_group":"free-qwen",
              "api_base":"http://host.docker.internal:11434/api/generate",
              "startTime":"2026-09-07T13:49:13.859Z",
              "user":"default_user_id",
              "end_user":"tally-e2e-user@example.com",
              "requester_ip_address":"172.20.0.1",
              "metadata":{"user_api_key_user_id":"default_user_id"}
            }"#,
        )
        .expect("LiteLLM v1.99 spend log");
        let usage = project_usage(record, &BTreeMap::new()).expect("projected usage");
        assert_eq!(usage.user.as_deref(), Some("tally-e2e-user@example.com"));
        assert_eq!(usage.provider, "ollama");
        assert_eq!(usage.model.as_deref(), Some("ollama/qwen2.5:0.5b"));
        assert_eq!(usage.requester_ip_address.as_deref(), Some("172.20.0.1"));
        assert_eq!(
            usage.destination_url.as_deref(),
            Some("http://host.docker.internal:11434/")
        );
    }
}
