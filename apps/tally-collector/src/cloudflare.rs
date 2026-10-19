use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Duration, Utc};
use reqwest::{Url, header::HeaderValue};
use serde::{Deserialize, Serialize, de::IgnoredAny};
use tally_connectors::{
    AI_GATEWAY_PROJECTION_SCHEMA_VERSION, MAX_BATCH_OBSERVATIONS, MAX_IMPORT_BYTES,
};
use tally_core::Hostname;

use crate::pull_support::{NativeEnterpriseSnapshot, bounded_response};

const MAX_PAGES: usize = 100;
const PAGE_SIZE: usize = 100;

#[derive(Debug, Clone, Copy)]
enum CasbApplication {
    Anthropic,
    Openai,
}

impl CasbApplication {
    const ALL: [Self; 2] = [Self::Anthropic, Self::Openai];

    const fn query(self) -> &'static str {
        match self {
            Self::Anthropic => "ANTHROPIC",
            Self::Openai => "OPENAI",
        }
    }

    const fn projection(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::Openai => "openai",
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct CloudflareEnvelope<T> {
    pub(crate) result: Vec<T>,
    pub(crate) success: bool,
    #[serde(default)]
    pub(crate) result_info: Option<CloudflareResultInfo>,
}

#[derive(Deserialize)]
pub(crate) struct CloudflareResultInfo {
    #[serde(default)]
    pub(crate) total_pages: Option<usize>,
    #[serde(default)]
    pub(crate) total_count: Option<usize>,
}

#[derive(Deserialize)]
struct CloudflareIntegration {
    id: String,
    status: String,
    is_paused: bool,
    updated: DateTime<Utc>,
    application: IgnoredAny,
}

#[derive(Serialize)]
struct CasbProjectionEnvelope {
    result: Vec<CasbProjectionIntegration>,
    success: bool,
}

#[derive(Serialize)]
struct CasbProjectionIntegration {
    id: String,
    application: CasbProjectionApplication,
    status: &'static str,
    is_paused: bool,
    updated: DateTime<Utc>,
}

#[derive(Serialize)]
struct CasbProjectionApplication {
    id: &'static str,
}

pub(crate) async fn pull_casb(
    account_id: &str,
    api_token: &str,
    client: &reqwest::Client,
) -> Result<NativeEnterpriseSnapshot> {
    ensure!(
        safe_account_id(account_id),
        "invalid Cloudflare account reference"
    );
    ensure!(
        !api_token.is_empty() && api_token.len() <= 2_048,
        "invalid Cloudflare token reference"
    );
    let mut authorization = HeaderValue::from_str(&format!("Bearer {api_token}"))
        .context("invalid Cloudflare token reference")?;
    authorization.set_sensitive(true);
    let mut projected = Vec::new();
    let mut seen = BTreeSet::new();
    for application in CasbApplication::ALL {
        for page in 1..=MAX_PAGES {
            let mut url = casb_url(account_id)?;
            url.query_pairs_mut()
                .append_pair("application", application.query())
                .append_pair("order", "application")
                .append_pair("direction", "asc")
                .append_pair("page_size", &PAGE_SIZE.to_string())
                .append_pair("page", &page.to_string());
            let response = client
                .get(url)
                .header(reqwest::header::AUTHORIZATION, authorization.clone())
                .send()
                .await
                .context("Cloudflare CASB request failed")?;
            let bytes = bounded_response(response, "Cloudflare CASB").await?;
            let envelope: CloudflareEnvelope<CloudflareIntegration> =
                serde_json::from_slice(&bytes).context("invalid Cloudflare CASB response")?;
            ensure!(envelope.success, "Cloudflare CASB request was unsuccessful");
            let page_count = envelope.result.len();
            for integration in envelope.result {
                let _ = integration.application;
                ensure!(
                    seen.insert(integration.id.clone()),
                    "duplicate Cloudflare CASB integration"
                );
                ensure!(
                    projected.len() < MAX_BATCH_OBSERVATIONS,
                    "Cloudflare CASB resource cap exceeded"
                );
                projected.push(CasbProjectionIntegration {
                    id: integration.id,
                    application: CasbProjectionApplication {
                        id: application.projection(),
                    },
                    status: casb_status(&integration.status),
                    is_paused: integration.is_paused,
                    updated: integration.updated,
                });
            }
            ensure!(
                projected.len() <= MAX_BATCH_OBSERVATIONS,
                "Cloudflare CASB resource cap exceeded"
            );
            let complete = envelope
                .result_info
                .and_then(|info| info.total_pages)
                .is_some_and(|total| page >= total)
                || page_count < PAGE_SIZE;
            if complete {
                break;
            }
            ensure!(page < MAX_PAGES, "Cloudflare CASB page cap exceeded");
        }
    }
    projected.sort_by(|left, right| left.id.cmp(&right.id));
    let record_count = projected.len();
    let data = serde_json::to_vec(&CasbProjectionEnvelope {
        result: projected,
        success: true,
    })?;
    ensure!(
        data.len() <= MAX_IMPORT_BYTES,
        "Cloudflare CASB projection is too large"
    );
    Ok(NativeEnterpriseSnapshot { data, record_count })
}

fn casb_url(account_id: &str) -> Result<Url> {
    Url::parse(&format!(
        "https://api.cloudflare.com/client/v4/accounts/{account_id}/one/integrations"
    ))
    .context("build fixed Cloudflare CASB URL")
}

pub(crate) fn safe_account_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn casb_status(value: &str) -> &'static str {
    match value {
        "Healthy" | "healthy" => "healthy",
        "Unhealthy" | "unhealthy" | "Offline" | "offline" => "unhealthy",
        "Initializing" | "initializing" | "Pending" | "pending" => "pending",
        "Failed" | "failed" => "failed",
        _ => "unknown",
    }
}

const AI_GATEWAY_PAGE_SIZE: usize = 50;
const AI_GATEWAY_MAX_PAGES: usize = 100;
/// Bounded metadata-only sample per gateway and poll; counts are lower bounds when exceeded.
// Fifty logs per vendor page; the 10,000-observation import cap bounds a full scan to 200 pages.
const AI_GATEWAY_MAX_LOG_PAGES: usize = 200;
/// GraphQL analytics nodes have per-node row ceilings, so keep every poll explicitly bounded.
const ZT_GATEWAY_ROW_LIMIT: usize = 1_000;
/// Exclude still-filling minute buckets so overlapping polls do not admit changing partial counts.
const ZT_GATEWAY_SETTLING_SECONDS: i64 = 300;

pub(crate) async fn pull_zt_gateway(
    account_id: &str,
    api_token: &str,
    window_seconds: i64,
    client: &reqwest::Client,
) -> Result<NativeEnterpriseSnapshot> {
    zt_gateway::pull_cloudflare_zt_gateway(account_id, api_token, window_seconds, client).await
}

pub(crate) async fn pull_ai_gateway(
    account_id: &str,
    api_token: &str,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    usage_record_limit: usize,
    client: &reqwest::Client,
) -> Result<AiGatewayPullResult> {
    ai_gateway::pull_cloudflare_ai_gateway(
        account_id,
        api_token,
        window_start,
        window_end,
        usage_record_limit,
        client,
    )
    .await
}

pub(crate) use ai_gateway::AiGatewayPullResult;

mod zt_gateway {
    use super::{
        Context, DateTime, Deserialize, Duration, HeaderValue, MAX_BATCH_OBSERVATIONS,
        MAX_IMPORT_BYTES, NativeEnterpriseSnapshot, Result, Serialize, Utc, ZT_GATEWAY_ROW_LIMIT,
        ZT_GATEWAY_SETTLING_SECONDS, bounded_response, ensure, safe_account_id,
    };

    #[derive(Serialize)]
    struct GraphQlRequest<'a> {
        query: &'a str,
        variables: GraphQlVariables<'a>,
    }

    #[derive(Serialize)]
    struct GraphQlVariables<'a> {
        #[serde(rename = "accountTag")]
        account_tag: &'a str,
        start: String,
        end: String,
        limit: usize,
    }

    #[derive(Deserialize)]
    struct GraphQlResponse {
        #[serde(default)]
        data: Option<GraphQlData>,
    }

    #[derive(Deserialize)]
    struct GraphQlData {
        viewer: GraphQlViewer,
    }

    #[derive(Deserialize)]
    struct GraphQlViewer {
        accounts: Vec<GraphQlAccount>,
    }

    #[derive(Deserialize)]
    struct GraphQlAccount {
        #[serde(default, rename = "gatewayResolverQueriesAdaptiveGroups")]
        dns_groups: Vec<GraphQlResolverGroup>,
        #[serde(default, rename = "gatewayL7RequestsAdaptiveGroups")]
        http_groups: Vec<GraphQlHttpGroup>,
    }

    #[derive(Deserialize)]
    struct GraphQlResolverGroup {
        count: u64,
        dimensions: GraphQlResolverDimensions,
    }

    #[derive(Deserialize)]
    struct GraphQlResolverDimensions {
        #[serde(rename = "queryNameReversed")]
        query_name_reversed: String,
        #[serde(default, rename = "resolverDecision")]
        resolver_decision: Option<u16>,
        #[serde(rename = "ts")]
        timestamp: DateTime<Utc>,
    }

    #[derive(Deserialize)]
    struct GraphQlHttpGroup {
        count: u64,
        dimensions: GraphQlHttpDimensions,
    }

    #[derive(Deserialize)]
    struct GraphQlHttpDimensions {
        #[serde(default)]
        action: Option<String>,
        #[serde(default, rename = "deviceId")]
        device_id: Option<String>,
        #[serde(default)]
        email: Option<String>,
        #[serde(default, rename = "httpHost")]
        http_host: Option<String>,
        #[serde(default, rename = "sourceInternalIp")]
        source_internal_ip: Option<String>,
        #[serde(rename = "ts")]
        timestamp: DateTime<Utc>,
        #[serde(default, rename = "userId")]
        user_id: Option<String>,
    }

    /// This shape deliberately matches the privacy-bounded Gateway NDJSON normalizer. It cannot
    /// carry an actor because the aggregate GraphQL dataset does not expose one.
    #[derive(Serialize)]
    struct GatewayDnsAggregateRecord {
        #[serde(rename = "TallySource")]
        tally_source: &'static str,
        #[serde(rename = "Datetime")]
        datetime: DateTime<Utc>,
        #[serde(rename = "QueryName")]
        query_name: String,
        #[serde(rename = "ResolverDecision", skip_serializing_if = "Option::is_none")]
        resolver_decision: Option<&'static str>,
        #[serde(rename = "RequestCount")]
        request_count: u64,
    }

    /// Gateway HTTP analytics retains the source device and user dimensions separately from the
    /// requested destination. It is aggregated by closed minute rather than treated as raw logs.
    #[derive(Serialize)]
    struct GatewayHttpAggregateRecord {
        #[serde(rename = "TallySource")]
        tally_source: &'static str,
        #[serde(rename = "ActionName", skip_serializing_if = "Option::is_none")]
        action_name: Option<String>,
        #[serde(rename = "Datetime")]
        datetime: DateTime<Utc>,
        #[serde(rename = "DeviceID", skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
        #[serde(rename = "Email", skip_serializing_if = "Option::is_none")]
        email: Option<String>,
        #[serde(rename = "HTTPHost", skip_serializing_if = "Option::is_none")]
        http_host: Option<String>,
        #[serde(rename = "RequestCount")]
        request_count: u64,
        #[serde(rename = "SourceInternalIP", skip_serializing_if = "Option::is_none")]
        source_internal_ip: Option<String>,
        #[serde(rename = "UserID", skip_serializing_if = "Option::is_none")]
        user_id: Option<String>,
    }

    const fn resolver_decision_label(value: u16) -> Option<&'static str> {
        match value {
            1 => Some("allowed_by_query_name"),
            2 => Some("blocked_by_query_name"),
            3 => Some("blocked_by_category"),
            4 => Some("allowed_on_no_location"),
            5 => Some("allowed_on_no_policy_match"),
            6 => Some("blocked_always_category"),
            7 => Some("override_for_safe_search"),
            8 => Some("override_applied"),
            9 => Some("blocked_rule"),
            10 => Some("allowed_rule"),
            _ => None,
        }
    }

    fn admissible_query_name(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 253
            && value.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
    }

    fn unreverse_query_name(value: &str) -> String {
        value
            .split('.')
            .rev()
            .filter(|label| !label.is_empty())
            .collect::<Vec<_>>()
            .join(".")
    }

    fn project_gateway_groups(accounts: Vec<GraphQlAccount>) -> Result<NativeEnterpriseSnapshot> {
        let mut dns_records = Vec::new();
        let mut http_records = Vec::new();
        for account in accounts {
            ensure!(
                account.dns_groups.len() < ZT_GATEWAY_ROW_LIMIT,
                "Cloudflare Zero Trust Gateway DNS group cap reached"
            );
            ensure!(
                account.http_groups.len() < ZT_GATEWAY_ROW_LIMIT,
                "Cloudflare Zero Trust Gateway HTTP group cap reached"
            );
            for group in account.dns_groups {
                let query_name = unreverse_query_name(&group.dimensions.query_name_reversed);
                if group.count == 0 || !admissible_query_name(&query_name) {
                    continue;
                }
                ensure!(
                    dns_records.len().saturating_add(http_records.len()) < MAX_BATCH_OBSERVATIONS,
                    "Cloudflare Zero Trust Gateway group cap exceeded"
                );
                dns_records.push(GatewayDnsAggregateRecord {
                    tally_source: "graphql_dns",
                    datetime: group.dimensions.timestamp,
                    query_name,
                    resolver_decision: group
                        .dimensions
                        .resolver_decision
                        .and_then(resolver_decision_label),
                    request_count: group.count,
                });
            }
            for group in account.http_groups {
                if group.count == 0
                    || group
                        .dimensions
                        .http_host
                        .as_deref()
                        .is_none_or(|host| host.trim().is_empty())
                {
                    continue;
                }
                ensure!(
                    dns_records.len().saturating_add(http_records.len()) < MAX_BATCH_OBSERVATIONS,
                    "Cloudflare Zero Trust Gateway group cap exceeded"
                );
                http_records.push(GatewayHttpAggregateRecord {
                    tally_source: "graphql_http",
                    action_name: group.dimensions.action,
                    datetime: group.dimensions.timestamp,
                    device_id: group.dimensions.device_id,
                    email: group.dimensions.email,
                    http_host: group.dimensions.http_host,
                    request_count: group.count,
                    source_internal_ip: group.dimensions.source_internal_ip,
                    user_id: group.dimensions.user_id,
                });
            }
        }
        dns_records.sort_by(|left, right| {
            left.datetime
                .cmp(&right.datetime)
                .then_with(|| left.query_name.cmp(&right.query_name))
                .then_with(|| left.resolver_decision.cmp(&right.resolver_decision))
        });
        http_records.sort_by(|left, right| {
            left.datetime
                .cmp(&right.datetime)
                .then_with(|| left.http_host.cmp(&right.http_host))
                .then_with(|| left.email.cmp(&right.email))
                .then_with(|| left.user_id.cmp(&right.user_id))
                .then_with(|| left.device_id.cmp(&right.device_id))
                .then_with(|| left.source_internal_ip.cmp(&right.source_internal_ip))
                .then_with(|| left.action_name.cmp(&right.action_name))
        });
        let record_count = dns_records.len().saturating_add(http_records.len());
        let mut data = Vec::new();
        for record in dns_records {
            serde_json::to_writer(&mut data, &record)?;
            data.push(b'\n');
        }
        for record in http_records {
            serde_json::to_writer(&mut data, &record)?;
            data.push(b'\n');
        }
        ensure!(
            data.len() <= MAX_IMPORT_BYTES,
            "Cloudflare Zero Trust Gateway projection is too large"
        );
        Ok(NativeEnterpriseSnapshot { data, record_count })
    }

    pub(crate) async fn pull_cloudflare_zt_gateway(
        account_id: &str,
        api_token: &str,
        window_seconds: i64,
        client: &reqwest::Client,
    ) -> Result<NativeEnterpriseSnapshot> {
        ensure!(
            safe_account_id(account_id),
            "invalid Cloudflare account reference"
        );
        ensure!(
            !api_token.is_empty() && api_token.len() <= 2_048,
            "invalid Cloudflare token reference"
        );
        ensure!(
            (60..=604_800).contains(&window_seconds),
            "Zero Trust Gateway window must be between 60 and 604800 seconds"
        );
        let mut authorization = HeaderValue::from_str(&format!("Bearer {api_token}"))
            .context("invalid Cloudflare token reference")?;
        authorization.set_sensitive(true);
        let observed_at = Utc::now();
        let end = observed_at - Duration::seconds(ZT_GATEWAY_SETTLING_SECONDS);
        let start = end - Duration::seconds(window_seconds);
        let response = client
            .post("https://api.cloudflare.com/client/v4/graphql")
            .header(reqwest::header::AUTHORIZATION, authorization)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&GraphQlRequest {
                query: ZT_GATEWAY_QUERY,
                variables: GraphQlVariables {
                    account_tag: account_id,
                    start: start.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    end: end.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    limit: ZT_GATEWAY_ROW_LIMIT,
                },
            })
            .send()
            .await
            .context("Cloudflare Zero Trust Gateway analytics request failed")?;
        let bytes = bounded_response(response, "Cloudflare Zero Trust Gateway").await?;
        let payload: GraphQlResponse =
            serde_json::from_slice(&bytes).context("invalid Cloudflare analytics response")?;
        let accounts = payload
            .data
            .context("Cloudflare analytics response contained no data")?
            .viewer
            .accounts;
        project_gateway_groups(accounts)
    }

    const ZT_GATEWAY_QUERY: &str = r"
query TallyGatewayQueries($accountTag: string!, $start: Time, $end: Time, $limit: Int!) {
  viewer {
    accounts(filter: { accountTag: $accountTag }) {
      gatewayResolverQueriesAdaptiveGroups(
        filter: { datetime_gt: $start, datetime_lt: $end }
        limit: $limit
        orderBy: [datetimeMinute_ASC]
      ) {
        count
        dimensions {
          queryNameReversed
          resolverDecision
          ts: datetimeMinute
        }
      }
      gatewayL7RequestsAdaptiveGroups(
        filter: { datetime_gt: $start, datetime_lt: $end }
        limit: $limit
        orderBy: [datetimeMinute_ASC]
      ) {
        count
        dimensions {
          action
          deviceId
          email
          httpHost
          sourceInternalIp
          ts: datetimeMinute
          userId
        }
      }
    }
  }
}";

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn query_is_bounded_and_requests_http_source_attribution() {
            assert!(ZT_GATEWAY_QUERY.contains("gatewayResolverQueriesAdaptiveGroups"));
            assert!(ZT_GATEWAY_QUERY.contains("gatewayL7RequestsAdaptiveGroups"));
            assert!(ZT_GATEWAY_QUERY.contains("datetime_lt: $end"));
            for required in [
                "email",
                "userId",
                "deviceId",
                "sourceInternalIp",
                "httpHost",
            ] {
                assert!(ZT_GATEWAY_QUERY.contains(required));
            }
            for forbidden in ["url", "requestId", "policyName", "redirectTargetURI"] {
                assert!(!ZT_GATEWAY_QUERY.contains(forbidden));
            }
            assert_eq!(unreverse_query_name("com.openai.api"), "api.openai.com");
        }

        #[test]
        fn aggregate_projection_matches_the_gateway_ndjson_shape() {
            let record = GatewayDnsAggregateRecord {
                tally_source: "graphql_dns",
                datetime: "2026-08-18T08:30:00Z".parse().expect("timestamp"),
                query_name: "api.openai.com".into(),
                resolver_decision: resolver_decision_label(5),
                request_count: 37,
            };
            let projected = serde_json::to_string(&record).expect("projection");
            assert!(projected.contains("\"TallySource\":\"graphql_dns\""));
            assert!(projected.contains("\"QueryName\":\"api.openai.com\""));
            assert!(projected.contains("\"RequestCount\":37"));
            assert!(!projected.contains("Email"));

            let http = GatewayHttpAggregateRecord {
                tally_source: "graphql_http",
                action_name: Some("allow".into()),
                datetime: "2026-08-18T08:31:00Z".parse().expect("timestamp"),
                device_id: Some("device-1".into()),
                email: Some("person@example.com".into()),
                http_host: Some("api.openai.com".into()),
                request_count: 12,
                source_internal_ip: Some("100.96.0.2".into()),
                user_id: Some("user-1".into()),
            };
            let projected = serde_json::to_string(&http).expect("HTTP projection");
            assert!(projected.contains("\"TallySource\":\"graphql_http\""));
            assert!(projected.contains("\"HTTPHost\":\"api.openai.com\""));
            assert!(projected.contains("\"DeviceID\":\"device-1\""));
            assert!(projected.contains("\"RequestCount\":12"));
            assert!(!projected.contains("URL"));
        }
    }
}

mod ai_gateway {
    use super::{
        AI_GATEWAY_MAX_LOG_PAGES, AI_GATEWAY_MAX_PAGES, AI_GATEWAY_PAGE_SIZE,
        AI_GATEWAY_PROJECTION_SCHEMA_VERSION, BTreeSet, CloudflareEnvelope, CloudflareResultInfo,
        Context, DateTime, Deserialize, Duration, HeaderValue, Hostname, MAX_BATCH_OBSERVATIONS,
        MAX_IMPORT_BYTES, NativeEnterpriseSnapshot, Result, Serialize, Url, Utc, bounded_response,
        ensure, safe_account_id,
    };
    #[derive(Deserialize)]
    struct AiGatewayListEntry {
        id: String,
    }

    #[derive(Deserialize)]
    struct AiGatewayLogEntry {
        id: String,
        #[serde(default)]
        provider: Option<String>,
        #[serde(default)]
        model: Option<String>,
        created_at: DateTime<Utc>,
        #[serde(default)]
        metadata: Option<serde_json::Value>,
    }

    #[derive(Serialize)]
    struct AiGatewayProjection {
        schema_version: &'static str,
        account_ref: String,
        observed_at: DateTime<Utc>,
        gateways: Vec<AiGatewayProjectionGateway>,
    }

    #[derive(Serialize)]
    struct AiGatewayProjectionGateway {
        id: String,
        providers: Vec<AiGatewayProjectionProvider>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        usage: Vec<AiGatewayProjectionUsage>,
    }

    #[derive(Serialize)]
    struct AiGatewayProjectionProvider {
        provider: String,
        request_count: u64,
    }

    #[derive(Default, Deserialize, Serialize)]
    struct AiGatewaySizes {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request_size: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        response_size: Option<u64>,
    }

    #[derive(Deserialize)]
    struct AiGatewayDetail {
        success: bool,
        result: AiGatewaySizes,
    }

    #[derive(Serialize)]
    struct AiGatewayProjectionUsage {
        #[serde(flatten)]
        sizes: AiGatewaySizes,
        id: String,
        provider: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        model: Option<String>,
        observed_at: DateTime<Utc>,
        #[serde(skip_serializing_if = "Option::is_none")]
        email: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        user_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
    }

    fn ai_gateway_url(account_id: &str, suffix: &str) -> Result<Url> {
        Url::parse(&format!(
            "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai-gateway/gateways{suffix}"
        ))
        .context("build fixed Cloudflare AI Gateway URL")
    }

    /// Accepts a gateway identifier that is safe to place in a fixed URL path.
    ///
    /// Cloudflare enforces a lowercase-only pattern (`^[a-z0-9_]+(?:-[a-z0-9_]+)*$`) for gateway
    /// identifiers. The alphabet stays bounded to ASCII lowercase alphanumerics, `_` and `-` so no
    /// separator, escape, or control byte can alter the request path.
    fn safe_ai_gateway_id(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 64
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
    }

    fn safe_ai_gateway_provider(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 64
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
    }

    fn ai_gateway_logs_url(
        account_id: &str,
        gateway_id: &str,
        page: usize,
        per_page: usize,
        window_start: DateTime<Utc>,
        window_end: DateTime<Utc>,
    ) -> Result<Url> {
        let mut url = ai_gateway_url(account_id, &format!("/{gateway_id}/logs"))?;
        url.query_pairs_mut()
            .append_pair("page", &page.to_string())
            .append_pair("per_page", &per_page.to_string())
            .append_pair("order_by", "created_at")
            .append_pair("order_by_direction", "desc")
            .append_pair("filters[0][key]", "created_at")
            .append_pair("filters[0][operator]", "gt")
            .append_pair(
                "filters[0][value][0]",
                &window_start.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            )
            .append_pair("filters[1][key]", "created_at")
            .append_pair("filters[1][operator]", "lt")
            .append_pair(
                "filters[1][value][0]",
                &window_end.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            );
        Ok(url)
    }

    /// Pulls the bounded Cloudflare AI Gateway inventory plus a metadata-only provider usage sample.
    ///
    /// Gateway/log lists provide inventory; up to 200 log-detail requests per poll contribute
    /// explicit request/response size counters only. Extra detail fields are discarded. The
    /// per-log `request`/`response` body routes are never requested. `record_count` counts the
    /// gateway capabilities plus provider pairs with a verified public registry entry.
    pub(crate) async fn pull_cloudflare_ai_gateway(
        account_id: &str,
        api_token: &str,
        window_start: DateTime<Utc>,
        window_end: DateTime<Utc>,
        usage_record_limit: usize,
        client: &reqwest::Client,
    ) -> Result<AiGatewayPullResult> {
        ensure!(
            safe_account_id(account_id),
            "invalid Cloudflare account reference"
        );
        ensure!(
            !api_token.is_empty() && api_token.len() <= 2_048,
            "invalid Cloudflare token reference"
        );
        ensure!(
            window_start < window_end && window_end - window_start <= Duration::days(7),
            "Cloudflare AI Gateway window must be positive and at most seven days"
        );
        ensure!(
            (1..=MAX_BATCH_OBSERVATIONS).contains(&usage_record_limit),
            "Cloudflare AI Gateway record limit is invalid"
        );
        let mut authorization = HeaderValue::from_str(&format!("Bearer {api_token}"))
            .context("invalid Cloudflare token reference")?;
        authorization.set_sensitive(true);
        let observed_at = window_end;

        let listing = list_ai_gateways(account_id, &authorization, client).await?;
        // Reporting a healthy empty poll here would read as "this account runs no AI gateways",
        // which is the opposite of what happened.
        ensure!(
            listing.skipped == 0 || !listing.gateway_ids.is_empty(),
            "every Cloudflare AI Gateway identifier was outside the safe alphabet"
        );
        let mut gateway_ids = listing.gateway_ids;
        gateway_ids.sort();

        let mut gateways = Vec::with_capacity(gateway_ids.len());
        let mut record_count = gateway_ids.len();
        let mut remaining = usage_record_limit;
        let mut usage_truncated = false;
        // Bound additional API work across the entire poll, including many small gateways.
        // Unmeasured requests remain unknown, and rate/permission failures do not lose inventory.
        let mut size_budget = 200_usize;
        for gateway_id in &gateway_ids {
            let mut sample = if remaining == 0 {
                // Probe the remaining gateways instead of assuming they contain logs. An exact
                // limit on one gateway must not pin an otherwise complete time window forever.
                let probe = sample_ai_gateway_usage(
                    account_id,
                    gateway_id,
                    &authorization,
                    window_start,
                    window_end,
                    1,
                    client,
                )
                .await?;
                usage_truncated |= !probe.usage.is_empty() || probe.truncated;
                AiGatewayUsageSample::default()
            } else {
                sample_ai_gateway_usage(
                    account_id,
                    gateway_id,
                    &authorization,
                    window_start,
                    window_end,
                    remaining,
                    client,
                )
                .await?
            };
            for usage in &mut sample.usage {
                if size_budget == 0 {
                    break;
                }
                let Some(url) = ai_gateway_detail_url(account_id, gateway_id, &usage.id)? else {
                    continue;
                };
                size_budget -= 1;
                if let Ok(sizes) = ai_gateway_sizes(url, &authorization, client).await {
                    usage.sizes = sizes;
                } else {
                    size_budget = 0;
                    break;
                }
            }
            remaining = remaining.saturating_sub(sample.usage.len());
            usage_truncated |= sample.truncated;
            record_count = record_count.saturating_add(sample.usage.len());
            gateways.push(AiGatewayProjectionGateway {
                id: gateway_id.clone(),
                providers: Vec::new(),
                usage: sample.usage,
            });
        }

        let record_count = if gateways.is_empty() { 0 } else { record_count };
        let data = serde_json::to_vec(&AiGatewayProjection {
            schema_version: AI_GATEWAY_PROJECTION_SCHEMA_VERSION,
            account_ref: account_id.to_owned(),
            observed_at,
            gateways,
        })?;
        ensure!(
            data.len() <= MAX_IMPORT_BYTES,
            "Cloudflare AI Gateway projection is too large"
        );
        Ok(AiGatewayPullResult {
            snapshot: NativeEnterpriseSnapshot { data, record_count },
            window_end,
            usage_truncated,
        })
    }

    pub(crate) struct AiGatewayPullResult {
        pub(crate) snapshot: NativeEnterpriseSnapshot,
        pub(crate) window_end: DateTime<Utc>,
        pub(crate) usage_truncated: bool,
    }

    /// The gateways an account exposes, plus how many were unusable.
    struct AiGatewayListing {
        gateway_ids: Vec<String>,
        /// Identifiers outside the safe URL-path alphabet. Never silently zero: reported so an
        /// operator can tell "this account has no gateways" from "Tally could not read them".
        skipped: usize,
    }

    /// Enumerates the account's AI Gateways over the bounded, paginated list route.
    ///
    /// Identifiers are held to a bounded machine alphabet, duplicates are refused rather than
    /// merged, and the batch cap is enforced as pages accumulate.
    async fn list_ai_gateways(
        account_id: &str,
        authorization: &HeaderValue,
        client: &reqwest::Client,
    ) -> Result<AiGatewayListing> {
        let mut gateway_ids = Vec::new();
        let mut seen = BTreeSet::new();
        let mut skipped = 0_usize;
        for page in 1..=AI_GATEWAY_MAX_PAGES {
            let mut url = ai_gateway_url(account_id, "")?;
            url.query_pairs_mut()
                .append_pair("page", &page.to_string())
                .append_pair("per_page", &AI_GATEWAY_PAGE_SIZE.to_string());
            let response = client
                .get(url)
                .header(reqwest::header::AUTHORIZATION, authorization.clone())
                .send()
                .await
                .context("Cloudflare AI Gateway list request failed")?;
            let bytes = bounded_response(response, "Cloudflare AI Gateway").await?;
            let envelope: CloudflareEnvelope<AiGatewayListEntry> =
                serde_json::from_slice(&bytes).context("invalid Cloudflare AI Gateway response")?;
            ensure!(
                envelope.success,
                "Cloudflare AI Gateway request was unsuccessful"
            );
            let page_count = envelope.result.len();
            for gateway in envelope.result {
                if !safe_ai_gateway_id(&gateway.id) {
                    // One unusable identifier must not cost the operator the whole account's
                    // inventory. Skip it and count it; the caller refuses to report a healthy
                    // empty poll if skipping is the only reason nothing was found.
                    skipped += 1;
                    continue;
                }
                ensure!(
                    seen.insert(gateway.id.clone()),
                    "duplicate Cloudflare AI Gateway"
                );
                ensure!(
                    gateway_ids.len() < MAX_BATCH_OBSERVATIONS,
                    "Cloudflare AI Gateway cap exceeded"
                );
                gateway_ids.push(gateway.id);
            }
            let complete = envelope
                .result_info
                .and_then(|info| info.total_pages)
                .is_some_and(|total| page >= total)
                || page_count < AI_GATEWAY_PAGE_SIZE;
            if complete {
                break;
            }
            ensure!(
                page < AI_GATEWAY_MAX_PAGES,
                "Cloudflare AI Gateway page cap exceeded"
            );
        }
        Ok(AiGatewayListing {
            gateway_ids,
            skipped,
        })
    }

    fn ai_gateway_detail_url(
        account_id: &str,
        gateway_id: &str,
        log_id: &str,
    ) -> Result<Option<Url>> {
        // Log IDs must be a single opaque segment; never permit /request or /response routes.
        if log_id.is_empty()
            || log_id.len() > 256
            || !log_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Ok(None);
        }
        ai_gateway_url(account_id, &format!("/{gateway_id}/logs/{log_id}")).map(Some)
    }

    async fn ai_gateway_sizes(
        url: Url,
        authorization: &HeaderValue,
        client: &reqwest::Client,
    ) -> Result<AiGatewaySizes> {
        let response = client
            .get(url)
            .header(reqwest::header::AUTHORIZATION, authorization.clone())
            .send()
            .await
            .context("Cloudflare AI Gateway size metadata request failed")?;
        let bytes = bounded_response(response, "Cloudflare AI Gateway size metadata").await?;
        // Do not deserialize request_head, response_head, headers, prompts, or arbitrary metadata.
        let detail: AiGatewayDetail =
            serde_json::from_slice(&bytes).context("invalid AI Gateway size metadata")?;
        ensure!(
            detail.success,
            "Cloudflare AI Gateway size metadata unavailable"
        );
        Ok(detail.result)
    }

    /// Counts provider usage for one gateway from the **payload-free log list** route only.
    ///
    /// The per-log `request` and `response` body routes are never contacted, so prompts and
    /// completions cannot enter Tally even when the gateway has payload logging enabled. Reaching
    /// the page cap is a documented bounded sample rather than an error: counts are lower bounds
    /// for extremely busy gateways.
    #[allow(clippy::too_many_lines)]
    async fn sample_ai_gateway_usage(
        account_id: &str,
        gateway_id: &str,
        authorization: &HeaderValue,
        window_start: DateTime<Utc>,
        window_end: DateTime<Utc>,
        record_limit: usize,
        client: &reqwest::Client,
    ) -> Result<AiGatewayUsageSample> {
        let mut usage = Vec::new();
        let mut seen = BTreeSet::new();
        let mut more_pages = false;
        for page in 1..=AI_GATEWAY_MAX_LOG_PAGES {
            // Offset pagination requires an invariant page size. Shrinking per_page as the local
            // budget runs out would move page 2 back into page 1 and duplicate or skip logs.
            let per_page = AI_GATEWAY_PAGE_SIZE;
            let url = ai_gateway_logs_url(
                account_id,
                gateway_id,
                page,
                per_page,
                window_start,
                window_end,
            )?;
            let response = client
                .get(url)
                .header(reqwest::header::AUTHORIZATION, authorization.clone())
                .send()
                .await
                .context("Cloudflare AI Gateway log-list request failed")?;
            let bytes = bounded_response(response, "Cloudflare AI Gateway logs").await?;
            let envelope: CloudflareEnvelope<AiGatewayLogEntry> = serde_json::from_slice(&bytes)
                .context("invalid Cloudflare AI Gateway log response")?;
            ensure!(
                envelope.success,
                "Cloudflare AI Gateway log request was unsuccessful"
            );
            let page_count = envelope.result.len();
            let mut page_truncated = false;
            for (index, entry) in envelope.result.into_iter().enumerate() {
                if entry.created_at <= window_start || entry.created_at >= window_end {
                    continue;
                }
                let Some(provider) = entry
                    .provider
                    .as_deref()
                    .map(|provider| provider.trim().to_ascii_lowercase())
                    .filter(|provider| safe_ai_gateway_provider(provider))
                else {
                    continue;
                };
                ensure!(
                    !entry.id.is_empty()
                        && entry.id.len() <= 2_048
                        && !entry.id.chars().any(char::is_control),
                    "Cloudflare AI Gateway log ID was invalid"
                );
                ensure!(
                    seen.insert(entry.id.clone()),
                    "duplicate Cloudflare AI Gateway log"
                );
                let model = entry.model.as_deref().and_then(normalized_model_reference);
                let (email, user_id, hostname) =
                    projected_ai_gateway_actor(entry.metadata.as_ref());
                ensure!(
                    usage.len() < MAX_BATCH_OBSERVATIONS,
                    "Cloudflare AI Gateway log cap exceeded"
                );
                usage.push(AiGatewayProjectionUsage {
                    sizes: AiGatewaySizes::default(),
                    id: entry.id,
                    provider,
                    model,
                    observed_at: entry.created_at,
                    email,
                    user_id,
                    hostname,
                });
                if usage.len() == record_limit {
                    page_truncated = index + 1 < page_count;
                    break;
                }
            }
            let complete =
                log_page_complete(envelope.result_info.as_ref(), page, per_page, page_count);
            more_pages = !complete;
            if usage.len() == record_limit {
                if !page_truncated && !complete {
                    // A full final page is ambiguous without result_info. Check the next page
                    // before calling a complete window truncated.
                    let probe_url = ai_gateway_logs_url(
                        account_id,
                        gateway_id,
                        page + 1,
                        per_page,
                        window_start,
                        window_end,
                    )?;
                    let probe_response = client
                        .get(probe_url)
                        .header(reqwest::header::AUTHORIZATION, authorization.clone())
                        .send()
                        .await
                        .context("Cloudflare AI Gateway final-page probe failed")?;
                    let probe_bytes =
                        bounded_response(probe_response, "Cloudflare AI Gateway logs").await?;
                    let probe: CloudflareEnvelope<AiGatewayLogEntry> =
                        serde_json::from_slice(&probe_bytes)
                            .context("invalid Cloudflare AI Gateway final-page response")?;
                    ensure!(
                        probe.success && probe.result.len() <= per_page,
                        "Cloudflare AI Gateway final-page probe was invalid"
                    );
                    page_truncated = !probe.result.is_empty();
                }
                usage.sort_by(|left, right| {
                    left.observed_at
                        .cmp(&right.observed_at)
                        .then_with(|| left.id.cmp(&right.id))
                });
                return Ok(AiGatewayUsageSample {
                    usage,
                    truncated: page_truncated,
                });
            }
            if complete {
                break;
            }
        }
        usage.sort_by(|left, right| {
            left.observed_at
                .cmp(&right.observed_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(AiGatewayUsageSample {
            usage,
            truncated: more_pages,
        })
    }

    fn log_page_complete(
        info: Option<&CloudflareResultInfo>,
        page: usize,
        per_page: usize,
        page_count: usize,
    ) -> bool {
        info.and_then(|info| {
            info.total_pages
                .map(|total| page >= total)
                .or_else(|| info.total_count.map(|total| page * per_page >= total))
        })
        .unwrap_or(page_count < per_page)
    }

    #[derive(Default)]
    struct AiGatewayUsageSample {
        usage: Vec<AiGatewayProjectionUsage>,
        truncated: bool,
    }

    fn normalized_model_reference(value: &str) -> Option<String> {
        let value = value.trim();
        (!value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control))
            .then(|| value.to_owned())
    }

    fn projected_ai_gateway_actor(
        metadata: Option<&serde_json::Value>,
    ) -> (Option<String>, Option<String>, Option<String>) {
        let parsed;
        let object = match metadata {
            Some(serde_json::Value::Object(object)) => Some(object),
            Some(serde_json::Value::String(value)) => {
                parsed = serde_json::from_str::<serde_json::Value>(value).ok();
                parsed.as_ref().and_then(serde_json::Value::as_object)
            }
            _ => None,
        };
        let Some(object) = object else {
            return (None, None, None);
        };
        let email = ["email", "user_email", "userEmail", "user"]
            .into_iter()
            .find_map(|key| object.get(key).and_then(serde_json::Value::as_str))
            .and_then(recognized_email);
        let user_id = ["cf.user_id", "user_id", "userId"]
            .into_iter()
            .find_map(|key| object.get(key).and_then(serde_json::Value::as_str))
            .or_else(|| {
                object
                    .get("cf")
                    .and_then(serde_json::Value::as_object)
                    .and_then(|cf| cf.get("user_id"))
                    .and_then(serde_json::Value::as_str)
            })
            .and_then(recognized_user_id);
        let hostname = ["hostname", "device_hostname", "deviceHostname", "host"]
            .into_iter()
            .find_map(|key| object.get(key).and_then(serde_json::Value::as_str))
            .and_then(|value| Hostname::parse(value).ok())
            .map(|value| value.as_str().to_owned());
        (email, user_id, hostname)
    }

    fn recognized_email(value: &str) -> Option<String> {
        let value = value.trim().to_ascii_lowercase();
        let (local, domain) = value.split_once('@')?;
        if value.len() > 254
            || local.is_empty()
            || local.len() > 64
            || value.bytes().any(|byte| byte.is_ascii_whitespace())
            || domain.contains('@')
            || Hostname::parse(domain).is_err()
        {
            return None;
        }
        Some(value)
    }

    fn recognized_user_id(value: &str) -> Option<String> {
        let value = value.trim();
        (!value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control))
            .then(|| value.to_owned())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn log_detail_keeps_only_size_counters() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("listen");
            let address = listener.local_addr().expect("address");
            let app = axum::Router::new().route(
                "/logs/log-1",
                axum::routing::get(|| async {
                    axum::Json(serde_json::json!({"success":true,"result":{
                        "request_size":0,"response_size":4096,
                        "request_head":"PROMPT_CANARY","response_head":"COMPLETION_CANARY",
                        "headers":{"authorization":"SECRET_CANARY"}
                    }}))
                }),
            );
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.expect("serve");
            });
            let sizes = ai_gateway_sizes(
                Url::parse(&format!("http://{address}/logs/log-1")).expect("URL"),
                &HeaderValue::from_static("Bearer fixture"),
                &reqwest::Client::new(),
            )
            .await
            .expect("sizes");
            server.abort();
            assert_eq!(sizes.request_size, Some(0));
            assert_eq!(sizes.response_size, Some(4096));
            assert!(
                !serde_json::to_string(&sizes)
                    .expect("projection")
                    .contains("CANARY")
            );
            let missing: AiGatewayDetail =
                serde_json::from_str(r#"{"success":true,"result":{}}"#).expect("absent counters");
            assert_eq!(missing.result.request_size, None);
        }

        #[test]
        fn size_metadata_routes_cannot_reach_payloads() {
            for id in [
                "../request",
                "log-1/response",
                "%2frequest",
                "",
                "x?body=true",
            ] {
                assert!(
                    ai_gateway_detail_url("account", "gateway", id)
                        .expect("route")
                        .is_none()
                );
            }
            assert!(
                ai_gateway_detail_url("account", "gateway", "log-123")
                    .expect("route")
                    .expect("safe")
                    .path()
                    .ends_with("/gateway/logs/log-123")
            );
        }

        #[test]
        fn a_full_page_is_complete_when_the_provider_count_matches() {
            let info = CloudflareResultInfo {
                total_pages: None,
                total_count: Some(50),
            };
            assert!(log_page_complete(Some(&info), 1, 50, 50));
            assert!(!log_page_complete(None, 1, 50, 50));
        }
        #[test]
        fn ai_gateway_origins_and_identifiers_are_fixed_and_bounded() {
            let url = ai_gateway_url("0123456789abcdef0123456789abcdef", "").expect("URL");
            assert_eq!(url.host_str(), Some("api.cloudflare.com"));
            assert_eq!(url.scheme(), "https");
            assert!(safe_ai_gateway_id("production-claude-gateway"));
            // Cloudflare enforces lowercase-only gateway identifiers
            // (pattern: ^[a-z0-9_]+(?:-[a-z0-9_]+)*$).
            assert!(!safe_ai_gateway_id("Production-Gateway"));
            assert!(!safe_ai_gateway_id("TeamAlpha_GW2"));
            assert!(safe_ai_gateway_id("team_alpha_gw2"));
            // Anything that could alter the request path stays refused.
            assert!(!safe_ai_gateway_id("Gateway With Spaces"));
            assert!(!safe_ai_gateway_id("gw/../../escape"));
            assert!(!safe_ai_gateway_id("gw%2Fescape"));
            assert!(!safe_ai_gateway_id("gw.escape"));
            assert!(!safe_ai_gateway_id(""));
            assert!(!safe_ai_gateway_id(&"g".repeat(65)));
            assert!(safe_ai_gateway_provider("google-ai-studio"));
            assert!(!safe_ai_gateway_provider("Provider Payload"));
        }

        #[test]
        fn ai_gateway_log_window_uses_supported_exclusive_time_operators() {
            let start = "2026-09-03T13:40:00Z".parse().expect("start");
            let end = "2026-09-03T14:00:00Z".parse().expect("end");
            let url = ai_gateway_logs_url(
                "0123456789abcdef0123456789abcdef",
                "production-gateway",
                1,
                50,
                start,
                end,
            )
            .expect("log URL");
            let query = url
                .query_pairs()
                .collect::<std::collections::HashMap<_, _>>();
            assert_eq!(
                query
                    .get("filters[0][operator]")
                    .map(std::convert::AsRef::as_ref),
                Some("gt")
            );
            assert_eq!(
                query
                    .get("filters[1][operator]")
                    .map(std::convert::AsRef::as_ref),
                Some("lt")
            );
            assert!(!query.values().any(|value| value == "lte"));
        }

        /// A single unusable identifier previously aborted the pull, so one oddly named gateway
        /// zeroed an entire account's AI inventory — indistinguishable from having no gateways.
        #[test]
        fn one_unusable_gateway_identifier_does_not_discard_the_account() {
            let envelope: CloudflareEnvelope<AiGatewayListEntry> = serde_json::from_slice(
            br#"{"result":[{"id":"lab-gateway"},{"id":"bad/../id"},{"id":"Production-Gateway"}],
                 "success":true,"result_info":{"page":1,"total_pages":1}}"#,
        )
        .expect("envelope");

            let mut kept = Vec::new();
            let mut skipped = 0_usize;
            for gateway in envelope.result {
                if safe_ai_gateway_id(&gateway.id) {
                    kept.push(gateway.id);
                } else {
                    skipped += 1;
                }
            }
            assert_eq!(kept, vec!["lab-gateway"]);
            assert_eq!(skipped, 2);
        }

        #[test]
        fn ai_gateway_log_entries_project_only_actionable_identity_fields() {
            let entry: AiGatewayLogEntry = serde_json::from_slice(
            br#"{
              "id":"log-1","provider":"OpenAI","model":"llama-3.2","cached":false,
              "tokens_in":100,"tokens_out":50,"cost":0.01,"duration":812,"success":true,
              "metadata":"{\"email\":\"User@Example.com\",\"cf.user_id\":\"access-subject-1\",\"hostname\":\"LAPTOP-42\",\"secret\":\"AIGW_METADATA_CANARY\"}","created_at":"2026-08-18T07:59:00Z"
            }"#,
        )
        .expect("permissive log parse");
            let provider = entry
                .provider
                .as_deref()
                .map(|provider| provider.trim().to_ascii_lowercase())
                .filter(|provider| safe_ai_gateway_provider(provider));
            assert_eq!(provider.as_deref(), Some("openai"));
            let (email, user_id, hostname) = projected_ai_gateway_actor(entry.metadata.as_ref());
            let projected = serde_json::to_string(&AiGatewayProjectionUsage {
                sizes: AiGatewaySizes::default(),
                id: entry.id,
                provider: provider.expect("provider"),
                model: entry.model.as_deref().and_then(normalized_model_reference),
                observed_at: entry.created_at,
                email,
                user_id,
                hostname,
            })
            .expect("projection");
            assert!(!projected.contains("CANARY"));
            assert!(!projected.contains("tokens_in"));
            assert!(projected.contains("user@example.com"));
            assert!(projected.contains("access-subject-1"));
            assert!(projected.contains("laptop-42"));
            assert!(projected.contains("llama-3.2"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn casb_origin_and_statuses_are_fixed() {
        let url = casb_url("0123456789abcdef0123456789abcdef").expect("URL");
        assert_eq!(url.host_str(), Some("api.cloudflare.com"));
        assert_eq!(url.scheme(), "https");
        assert_eq!(casb_status("Healthy"), "healthy");
        assert_eq!(casb_status("customer-content"), "unknown");
        assert!(!safe_account_id("account/path"));
    }

    #[test]
    fn casb_projection_drops_unrequested_metadata() {
        let casb: CloudflareEnvelope<CloudflareIntegration> = serde_json::from_slice(
            br#"{
          "result":[{
            "id":"182bd5e5-6e1a-4fe4-a799-aa6d9a6ab26e",
            "application":{"slug":"OPENAI","name":"CASB_APPLICATION_CANARY"},
            "status":"Healthy","is_paused":false,"updated":"2026-08-13T08:00:00Z",
            "name":"CASB_INTEGRATION_CANARY","health_details":[{"message":"CONTENT_CANARY"}]
          }],
          "success":true
        }"#,
        )
        .expect("CASB response");
        let integration = casb.result.into_iter().next().expect("integration");
        let projected = serde_json::to_string(&CasbProjectionIntegration {
            id: integration.id,
            application: CasbProjectionApplication { id: "openai" },
            status: casb_status(&integration.status),
            is_paused: integration.is_paused,
            updated: integration.updated,
        })
        .expect("projection");
        assert!(!projected.contains("CANARY"));
    }
}
