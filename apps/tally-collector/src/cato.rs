use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use reqwest::{Url, header::HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tally_connectors::{
    CATO_NETWORKS_PROJECTION_SCHEMA_VERSION, MAX_BATCH_OBSERVATIONS, MAX_IMPORT_BYTES,
};

use crate::pull_support::{NativeEnterpriseSnapshot, bounded_response};

const EVENTS_FEED_QUERY: &str = r"query eventsFeed($accountIDs: [ID!], $marker: String) {
  eventsFeed(accountIDs: $accountIDs, marker: $marker) {
    marker
    fetchedCount
    accounts {
      id
      records {
        time
        fieldsMap
      }
    }
  }
}";

#[derive(Deserialize)]
struct GraphResponse {
    #[serde(default)]
    data: Option<GraphData>,
    #[serde(default)]
    errors: Vec<Value>,
}

#[derive(Deserialize)]
struct GraphData {
    #[serde(rename = "eventsFeed")]
    events_feed: EventsFeed,
}

#[derive(Deserialize)]
struct EventsFeed {
    #[serde(default)]
    marker: Option<String>,
    #[serde(rename = "fetchedCount")]
    fetched_count: u64,
    #[serde(default)]
    accounts: Vec<EventsAccount>,
}

#[derive(Deserialize)]
struct EventsAccount {
    id: String,
    #[serde(default)]
    records: Vec<EventRecord>,
}

#[derive(Deserialize)]
struct EventRecord {
    #[serde(default)]
    time: Option<Value>,
    #[serde(rename = "fieldsMap", default)]
    fields_map: Map<String, Value>,
}

#[derive(Serialize)]
struct CatoProjection {
    schema_version: &'static str,
    account_id: String,
    observed_at: DateTime<Utc>,
    events: Vec<CatoProjectionEvent>,
}

#[derive(Serialize)]
struct CatoProjectionEvent {
    id: String,
    observed_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    src_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dst_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dest_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dest_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    bytes_sent: Option<u64>,
    bytes_received: Option<u64>,
    external_id: Option<String>,
    identity_source: Option<String>,
    mcp_path: bool,
}

pub(crate) struct CatoPullOutcome {
    pub snapshot: NativeEnterpriseSnapshot,
    pub marker_after: Option<String>,
    pub window_end: DateTime<Utc>,
    pub backlog_hint: bool,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn pull_events_feed(
    api_hostname: &str,
    account_id: &str,
    api_key: &str,
    marker: Option<&str>,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    record_limit: usize,
    client: &reqwest::Client,
) -> Result<CatoPullOutcome> {
    ensure!(
        !account_id.is_empty()
            && account_id.len() <= 20
            && account_id.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid Cato account ID"
    );
    ensure!(safe_value(api_key, 4_096), "invalid Cato API key");
    ensure!(
        marker.is_none_or(|value| safe_value(value, 2_048)),
        "invalid Cato EventsFeed marker"
    );
    ensure!(window_start < window_end, "invalid Cato event window");
    ensure!(
        (1..=3_000).contains(&record_limit) && record_limit <= MAX_BATCH_OBSERVATIONS,
        "invalid Cato result limit"
    );
    let api_url = cato_api_url(api_hostname)?;
    let mut header = HeaderValue::from_str(api_key).context("invalid Cato API key")?;
    header.set_sensitive(true);
    let response = client
        .post(api_url)
        .header("x-api-key", header)
        .header(reqwest::header::ACCEPT, "application/json")
        .json(&serde_json::json!({
            "query": EVENTS_FEED_QUERY,
            "variables": {
                "accountIDs": [account_id],
                "marker": marker,
            }
        }))
        .send()
        .await
        .context("Cato EventsFeed request failed")?;
    let response_bytes = bounded_response(response, "Cato EventsFeed").await?;
    let response: GraphResponse =
        serde_json::from_slice(&response_bytes).context("invalid Cato EventsFeed response")?;
    drop(response_bytes);
    ensure!(
        response.errors.is_empty(),
        "Cato EventsFeed returned GraphQL errors"
    );
    let feed = response
        .data
        .context("Cato EventsFeed response omitted data")?
        .events_feed;
    ensure!(
        feed.fetched_count <= 3_000,
        "Cato EventsFeed count exceeded API limit"
    );
    let mut records = Vec::new();
    for account in feed.accounts {
        ensure!(
            account.id == account_id,
            "Cato EventsFeed account scope mismatch"
        );
        records.extend(account.records);
    }
    ensure!(
        u64::try_from(records.len()).unwrap_or(u64::MAX) == feed.fetched_count,
        "Cato EventsFeed record count is inconsistent"
    );
    // EventsFeed does not accept a page-size argument. Its marker is the position *after*
    // the entire response, so truncating to the configured legacy limit would lose events.
    // The provider's 3,000-record maximum fits the Tally import cap; consume it atomically.
    let events = project_records(&records, window_end);
    let record_count = events.len();
    let data = serde_json::to_vec(&CatoProjection {
        schema_version: CATO_NETWORKS_PROJECTION_SCHEMA_VERSION,
        account_id: account_ref(account_id),
        observed_at: window_end,
        events,
    })?;
    ensure!(
        data.len() <= MAX_IMPORT_BYTES,
        "Cato projection is too large"
    );
    ensure!(
        feed.marker
            .as_deref()
            .is_some_and(|value| safe_value(value, 2_048)),
        "Cato EventsFeed omitted a valid next marker"
    );
    let marker_after = feed.marker;
    Ok(CatoPullOutcome {
        snapshot: NativeEnterpriseSnapshot { data, record_count },
        marker_after,
        window_end,
        backlog_hint: feed.fetched_count == 3_000,
    })
}

pub(crate) fn cato_api_url(api_hostname: &str) -> Result<Url> {
    ensure!(
        api_hostname == api_hostname.to_ascii_lowercase()
            && api_hostname.len() <= 253
            && !api_hostname.contains('/')
            && (api_hostname == "api.catonetworks.com"
                || (api_hostname.starts_with("api.")
                    && api_hostname.ends_with(".catonetworks.com"))),
        "invalid Cato API hostname"
    );
    Url::parse(&format!("https://{api_hostname}/api/v1/graphql2")).context("build Cato API URL")
}

#[allow(clippy::too_many_lines)]
fn project_record(record: &EventRecord, window_end: DateTime<Utc>) -> Option<CatoProjectionEvent> {
    // The queue marker, not event time, determines what has been read. Delayed queue records may
    // be hours old; discarding them against the previous poll time would lose them permanently.
    let observed_at = record
        .time
        .as_ref()
        .or_else(|| record.fields_map.get("time"))
        .and_then(parse_event_time)?;
    if observed_at > window_end + chrono::Duration::minutes(5) {
        return None;
    }
    let src_ip = bounded_field(
        &record.fields_map,
        &["src_ip", "source_ip", "src_isp_ip"],
        64,
    );
    let dst_ip = bounded_field(
        &record.fields_map,
        &["dest_ip", "dst_ip", "destination_ip"],
        64,
    );
    let dest_domain = bounded_field(
        &record.fields_map,
        &[
            "dest_domain",
            "destination_domain",
            "domain",
            "url",
            "request_url",
        ],
        2_048,
    )
    .and_then(|value| normalized_domain(&value));
    let dest_port = integer_field(
        &record.fields_map,
        &["dest_port", "dst_port", "destination_port"],
    )
    .and_then(|value| u16::try_from(value).ok());
    let user_id = bounded_field(
        &record.fields_map,
        &[
            "sdp_user_email",
            "ad_user_name",
            "user_email",
            "user_name",
            "username",
            "sdp_user_email",
            "user",
        ],
        512,
    );
    let hostname = bounded_field(
        &record.fields_map,
        &[
            "src_host",
            "source_host",
            "device_name",
            "host_name",
            "hostname",
        ],
        512,
    );
    let action = bounded_field(&record.fields_map, &["action", "event_action"], 256);
    let id = bounded_field(&record.fields_map, &["event_id", "id"], 512).unwrap_or_else(|| {
        let bytes = serde_json::to_vec(&(
            observed_at,
            &src_ip,
            &dst_ip,
            &dest_domain,
            dest_port,
            &user_id,
            &hostname,
            &action,
        ))
        .unwrap_or_default();
        hex::encode(Sha256::digest(bytes))
    });
    Some(CatoProjectionEvent {
        id,
        observed_at,
        src_ip,
        dst_ip,
        dest_domain,
        dest_port,
        user_id,
        hostname,
        action,
        bytes_sent: integer_field(
            &record.fields_map,
            &["bytes_sent", "sent_bytes", "upstream_bytes"],
        ),
        bytes_received: integer_field(
            &record.fields_map,
            &["bytes_received", "received_bytes", "downstream_bytes"],
        ),
        external_id: bounded_field(&record.fields_map, &["externalId", "external_id"], 64),
        identity_source: if bounded_field(&record.fields_map, &["sdp_user_email"], 512).is_some() {
            Some("sdp".into())
        } else if bounded_field(&record.fields_map, &["ad_user_name"], 512).is_some() {
            Some("user_awareness".into())
        } else {
            None
        },
        mcp_path: bounded_field(&record.fields_map, &["url", "request_url"], 2048)
            .and_then(|s| Url::parse(&s).ok())
            .is_some_and(|url| matches!(url.path(), "/mcp" | "/mcp/")),
    })
}

fn project_records(records: &[EventRecord], window_end: DateTime<Utc>) -> Vec<CatoProjectionEvent> {
    records
        .iter()
        .filter_map(|record| project_record(record, window_end))
        .collect()
}

fn parse_event_time(value: &Value) -> Option<DateTime<Utc>> {
    let text = value.as_str();
    text.and_then(|text| text.parse::<DateTime<Utc>>().ok())
        .or_else(|| {
            value
                .as_i64()
                .or_else(|| text.and_then(|text| text.parse::<i64>().ok()))
                .and_then(DateTime::from_timestamp_millis)
        })
}

fn bounded_field(fields: &Map<String, Value>, names: &[&str], max_len: usize) -> Option<String> {
    names.iter().find_map(|name| {
        fields
            .get(*name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| {
                !value.is_empty() && value.len() <= max_len && !value.chars().any(char::is_control)
            })
            .map(str::to_owned)
    })
}

fn integer_field(fields: &Map<String, Value>, names: &[&str]) -> Option<u64> {
    names.iter().find_map(|name| {
        let value = fields.get(*name)?;
        value
            .as_u64()
            .or_else(|| value.as_str()?.parse::<u64>().ok())
    })
}

fn normalized_domain(value: &str) -> Option<String> {
    if let Ok(url) = Url::parse(value) {
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return None;
        }
        return url.host_str().map(str::to_ascii_lowercase);
    }
    let value = value.trim_end_matches('.').to_ascii_lowercase();
    (!value.is_empty()).then_some(value)
}

fn safe_value(value: &str, max_len: usize) -> bool {
    value.trim() == value
        && !value.is_empty()
        && value.len() <= max_len
        && !value.chars().any(char::is_control)
}

fn account_ref(account_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"godel-tally:cato-account:v1\0");
    hasher.update(account_id.as_bytes());
    format!("ct1_{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_is_fixed_to_cato_https_graphql_origin() {
        assert_eq!(
            cato_api_url("api.catonetworks.com")
                .expect("global")
                .as_str(),
            "https://api.catonetworks.com/api/v1/graphql2"
        );
        assert!(cato_api_url("api.us1.catonetworks.com").is_ok());
        assert!(cato_api_url("evil.example.com").is_err());
        assert!(cato_api_url("api.catonetworks.com/other").is_err());
    }

    #[test]
    fn event_record_projects_only_shutdown_attribution_fields() {
        let end = "2026-09-15T11:00:00Z".parse().expect("end");
        let record: EventRecord = serde_json::from_value(serde_json::json!({
            "time": "2026-09-15T10:30:00Z",
            "fieldsMap": {
                "event_id": "event-7",
                "src_ip": "192.0.2.7",
                "dest_ip": "203.0.113.7",
                "url": "https://api.deepseek.com/v1/chat/completions",
                "dest_port": "443",
                "user_email": "employee@example.com",
                "device_name": "laptop-7",
                "action": "allow",
                "event_message": "must-not-survive"
            }
        }))
        .expect("record");
        let event = project_record(&record, end).expect("project");
        let projected = serde_json::to_string(&event).expect("serialize");
        assert!(projected.contains("api.deepseek.com"));
        assert!(projected.contains("employee@example.com"));
        assert!(projected.contains("laptop-7"));
        assert!(!projected.contains("must-not-survive"));
    }

    #[test]
    fn full_provider_page_keeps_old_queue_events_after_legacy_limit() {
        let end: DateTime<Utc> = "2026-09-15T11:00:00Z".parse().expect("end");
        let records = (0..3_000)
            .map(|id| EventRecord {
                time: None,
                fields_map: serde_json::from_value(serde_json::json!({
                    "event_id": format!("event-{id}"),
                    "time": "1789380000000",
                    "domain": "api.example.com"
                }))
                .expect("fields"),
            })
            .collect::<Vec<_>>();
        let projected = project_records(&records, end);
        assert_eq!(projected.len(), 3_000);
        assert_eq!(projected[2_999].id, "event-2999");
    }
}
