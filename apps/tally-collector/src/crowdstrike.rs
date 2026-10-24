use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use reqwest::{Url, header::HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tally_connectors::{
    CROWDSTRIKE_EDR_DNS_PROJECTION_SCHEMA_VERSION, MAX_BATCH_OBSERVATIONS, MAX_IMPORT_BYTES,
};

use crate::pull_support::{NativeEnterpriseSnapshot, bounded_response};

const SEARCH_REPOSITORY: &str = "search-all";
const MAX_SEARCH_POLLS: usize = 20;
const SEARCH_PAGE_SIZE: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FalconCloud {
    Us1,
    Us2,
    Eu1,
}

impl FalconCloud {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "us-1" => Some(Self::Us1),
            "us-2" => Some(Self::Us2),
            "eu-1" => Some(Self::Eu1),
            _ => None,
        }
    }

    pub(crate) const fn key(self) -> &'static str {
        match self {
            Self::Us1 => "us-1",
            Self::Us2 => "us-2",
            Self::Eu1 => "eu-1",
        }
    }

    fn api_base(self) -> &'static str {
        match self {
            Self::Us1 => "https://api.crowdstrike.com/",
            Self::Us2 => "https://api.us-2.crowdstrike.com/",
            Self::Eu1 => "https://api.eu-1.crowdstrike.com/",
        }
    }
}

#[derive(Deserialize)]
struct FalconOAuthResponse {
    access_token: String,
    #[serde(default)]
    token_type: Option<String>,
}

#[derive(Deserialize)]
struct SearchStarted {
    id: String,
}

#[derive(Deserialize)]
struct SearchStatus {
    #[serde(default)]
    done: bool,
    #[serde(default)]
    events: Vec<SearchEvent>,
}

#[derive(Deserialize)]
struct SearchEvent {
    #[serde(default)]
    timestamp: Option<Value>,
    #[serde(default)]
    attributes: Map<String, Value>,
}

#[derive(Serialize)]
struct EdrDnsProjection {
    schema_version: &'static str,
    customer_ref: String,
    observed_at: DateTime<Utc>,
    events: Vec<EdrDnsProjectionEvent>,
}

#[derive(Serialize)]
struct EdrDnsProjectionEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    event_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_unique_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_unique_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_started_at: Option<DateTime<Utc>>,
    id: String,
    observed_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_id: Option<String>,
}

pub(crate) struct EdrDnsPullOutcome {
    pub snapshot: NativeEnterpriseSnapshot,
    pub window_end: DateTime<Utc>,
    pub result_limit_reached: bool,
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn pull_edr_dns(
    cloud: FalconCloud,
    client_id: &str,
    client_secret: &str,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    record_limit: usize,
    client: &reqwest::Client,
) -> Result<EdrDnsPullOutcome> {
    ensure!(
        safe_credential(client_id, 512) && safe_credential(client_secret, 2_048),
        "invalid Falcon OAuth credential"
    );
    ensure!(window_start < window_end, "invalid EDR search window");
    ensure!(
        (1..=5_000).contains(&record_limit) && record_limit <= MAX_BATCH_OBSERVATIONS,
        "invalid EDR result limit"
    );
    let api_base = Url::parse(cloud.api_base()).context("invalid fixed Falcon API origin")?;
    let oauth_url = api_base
        .join("oauth2/token")
        .context("build fixed Falcon OAuth URL")?;
    let oauth_form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", client_id)
        .append_pair("client_secret", client_secret)
        .finish();
    let oauth_response = client
        .post(oauth_url)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(oauth_form)
        .send()
        .await
        .context("Falcon OAuth request failed")?;
    let oauth_bytes = bounded_response(oauth_response, "Falcon OAuth").await?;
    let oauth: FalconOAuthResponse =
        serde_json::from_slice(&oauth_bytes).context("invalid Falcon OAuth response")?;
    drop(oauth_bytes);
    ensure!(
        !oauth.access_token.is_empty()
            && oauth.access_token.len() <= 8_192
            && oauth
                .token_type
                .as_deref()
                .is_none_or(|token_type| token_type.eq_ignore_ascii_case("bearer")),
        "invalid Falcon OAuth token"
    );
    let mut authorization = HeaderValue::from_str(&format!("Bearer {}", oauth.access_token))
        .context("invalid Falcon OAuth token")?;
    authorization.set_sensitive(true);
    let search_url = api_base
        .join(&format!(
            "humio/api/v1/repositories/{SEARCH_REPOSITORY}/queryjobs"
        ))
        .context("build fixed Falcon NGSIEM search URL")?;
    let fetch_limit = record_limit.saturating_add(1);
    let query = edr_dns_query(fetch_limit);
    let search_response = client
        .post(search_url.clone())
        .header(reqwest::header::AUTHORIZATION, authorization.clone())
        .header(reqwest::header::ACCEPT, "application/json")
        .json(&serde_json::json!({
            "queryString": query,
            "start": window_start.timestamp_millis(),
            "end": window_end.timestamp_millis(),
            "isLive": false,
        }))
        .send()
        .await
        .context("Falcon NGSIEM search request failed")?;
    let started_bytes = bounded_response(search_response, "Falcon NGSIEM search").await?;
    let started: SearchStarted =
        serde_json::from_slice(&started_bytes).context("invalid Falcon NGSIEM search response")?;
    drop(started_bytes);
    ensure!(safe_search_id(&started.id), "invalid Falcon search job ID");
    let status_url = search_url
        .join(&format!("queryjobs/{}", started.id))
        .context("build fixed Falcon NGSIEM status URL")?;
    let events = read_search_events(&status_url, &authorization, fetch_limit, client).await?;
    let result_limit_reached = events.len() > record_limit;
    let projected = events
        .iter()
        .take(record_limit)
        .filter_map(|event| project_event(event, window_start, window_end))
        .collect::<Vec<_>>();
    let record_count = projected.len();
    let customer_ref = customer_ref(cloud, client_id);
    let data = serde_json::to_vec(&EdrDnsProjection {
        schema_version: CROWDSTRIKE_EDR_DNS_PROJECTION_SCHEMA_VERSION,
        customer_ref,
        observed_at: window_end,
        events: projected,
    })?;
    ensure!(
        data.len() <= MAX_IMPORT_BYTES,
        "EDR projection is too large"
    );
    Ok(EdrDnsPullOutcome {
        snapshot: NativeEnterpriseSnapshot { data, record_count },
        window_end,
        result_limit_reached,
    })
}

async fn read_search_events(
    status_url: &Url,
    authorization: &HeaderValue,
    fetch_limit: usize,
    client: &reqwest::Client,
) -> Result<Vec<SearchEvent>> {
    let page_size = fetch_limit.min(SEARCH_PAGE_SIZE);
    let page_url = |offset: usize| {
        let mut url = (*status_url).clone();
        url.query_pairs_mut()
            .append_pair("paginationLimit", &page_size.to_string())
            .append_pair("paginationOffset", &offset.to_string());
        url
    };
    let mut events = None;
    for _ in 0..MAX_SEARCH_POLLS {
        tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
        let response = client
            .get(page_url(0))
            .header(reqwest::header::AUTHORIZATION, authorization.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .context("Falcon NGSIEM status request failed")?;
        let status_bytes = bounded_response(response, "Falcon NGSIEM status").await?;
        let status: SearchStatus = serde_json::from_slice(&status_bytes)
            .context("invalid Falcon NGSIEM status response")?;
        drop(status_bytes);
        ensure!(
            status.events.len() <= page_size,
            "Falcon NGSIEM response exceeded the requested page size"
        );
        if status.done {
            events = Some(status.events);
            break;
        }
    }
    let mut events = events.context("Falcon NGSIEM search did not complete within 30 seconds")?;
    // The query-job endpoint returns a page, not the full sorted result. Page through the
    // completed query before advancing its time cursor; otherwise a busy window silently loses
    // every event after the first page.
    while events.len() < fetch_limit && events.len() % page_size == 0 {
        let offset = events.len();
        let response = client
            .get(page_url(offset))
            .header(reqwest::header::AUTHORIZATION, authorization.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .context("Falcon NGSIEM page request failed")?;
        let page_bytes = bounded_response(response, "Falcon NGSIEM page").await?;
        let page: SearchStatus =
            serde_json::from_slice(&page_bytes).context("invalid Falcon NGSIEM page response")?;
        ensure!(page.done, "Falcon NGSIEM query changed while paging");
        ensure!(
            page.events.len() <= page_size,
            "Falcon NGSIEM page exceeded the requested size"
        );
        if page.events.is_empty() {
            break;
        }
        events.extend(page.events.into_iter().take(fetch_limit - offset));
    }
    Ok(events)
}

fn edr_dns_query(record_limit: usize) -> String {
    format!(
        r"#repo=base_sensor
| (#event_simpleName=DnsRequest OR #event_simpleName=NetworkConnectIP4 OR #event_simpleName=NetworkConnectIP6 OR #event_simpleName=ProcessRollup2)
| sort(@timestamp, order=asc, limit={record_limit})
| select([@id, @timestamp, #event_simpleName, DomainName, ComputerName, UserName, aid, ContextProcessId, TargetProcessId, RawProcessId, ParentProcessId, ImageFileName, ParentBaseFileName, ProcessStartTime, LocalAddressIP4, LocalAddressIP6, RemoteAddressIP4, RemoteAddressIP6, RemotePort, Protocol])"
    )
}

fn project_event(
    event: &SearchEvent,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
) -> Option<EdrDnsProjectionEvent> {
    let observed_at = attribute_value(&event.attributes, &["@timestamp"])
        .or(event.timestamp.as_ref())
        .and_then(parse_timestamp)?;
    if observed_at < window_start || observed_at >= window_end {
        return None;
    }
    let token = |names: &[&str]| {
        attribute_value(&event.attributes, names)
            .and_then(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .or_else(|| v.as_u64().map(|v| v.to_string()))
            })
            .filter(|v| bounded_value(v, 128))
    };
    let process_started_at =
        attribute_value(&event.attributes, &["ProcessStartTime"]).and_then(parse_process_timestamp);
    let event_kind = projected_string(
        &event.attributes,
        &["#event_simpleName", "event_simpleName"],
    );
    let native_process_field = if event_kind.as_deref() == Some("ProcessRollup2") {
        "TargetProcessId"
    } else {
        "ContextProcessId"
    };
    let mut projected = EdrDnsProjectionEvent {
        event_kind,
        executable: projected_string(&event.attributes, &["ImageFileName"])
            .as_deref()
            .and_then(tally_core::ProcessObservation::executable_basename),
        process_id: token(&["RawProcessId"]),
        process_unique_id: token(&[native_process_field]),
        parent_executable: projected_string(&event.attributes, &["ParentBaseFileName"])
            .as_deref()
            .and_then(tally_core::ProcessObservation::executable_basename),
        parent_unique_id: token(&["ParentProcessId"]),
        source_ip: projected_string(&event.attributes, &["LocalAddressIP4", "LocalAddressIP6"]),
        remote_ip: projected_string(&event.attributes, &["RemoteAddressIP4", "RemoteAddressIP6"]),
        protocol: token(&["Protocol"]),
        remote_port: token(&["RemotePort"]).and_then(|v| v.parse().ok()),
        process_started_at,

        id: attribute_string(&event.attributes, &["@id", "id", "event_id"])
            .filter(|value| bounded_value(value, 512))
            .unwrap_or_default(),
        observed_at,
        user_id: projected_string(&event.attributes, &["UserName"]),
        hostname: projected_string(&event.attributes, &["ComputerName"]),
        destination_domain: projected_string(&event.attributes, &["DomainName"]),
        agent_id: projected_string(&event.attributes, &["aid"]),
    };
    if projected.id.is_empty() {
        let bytes = serde_json::to_vec(&projected).ok()?;
        projected.id = hex::encode(Sha256::digest(bytes));
    }
    Some(projected)
}

fn attribute_value<'a>(attributes: &'a Map<String, Value>, paths: &[&str]) -> Option<&'a Value> {
    paths.iter().find_map(|path| {
        attributes.get(*path).or_else(|| {
            let mut segments = path.split('.');
            let first = segments.next()?;
            let mut value = attributes.get(first)?;
            for segment in segments {
                value = value.as_object()?.get(segment)?;
            }
            Some(value)
        })
    })
}

fn attribute_string(attributes: &Map<String, Value>, paths: &[&str]) -> Option<String> {
    attribute_value(attributes, paths)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn projected_string(attributes: &Map<String, Value>, paths: &[&str]) -> Option<String> {
    attribute_string(attributes, paths).filter(|value| bounded_value(value, 512))
}

fn parse_process_timestamp(value: &Value) -> Option<DateTime<Utc>> {
    let raw = value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.as_number().map(ToString::to_string))?;
    if let Ok(timestamp) = raw.parse::<DateTime<Utc>>() {
        return Some(timestamp);
    }
    if let Some((seconds, fraction)) = raw.split_once('.') {
        if fraction.len() > 9 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let nanos = format!("{fraction:0<9}").parse().ok()?;
        return DateTime::from_timestamp(seconds.parse().ok()?, nanos);
    }
    let epoch = raw.parse::<i64>().ok()?;
    if (1_000_000_000_000..10_000_000_000_000).contains(&epoch) {
        DateTime::from_timestamp_millis(epoch)
    } else if (1_000_000_000..10_000_000_000).contains(&epoch) {
        DateTime::from_timestamp(epoch, 0)
    } else {
        None
    }
}

fn parse_timestamp(value: &Value) -> Option<DateTime<Utc>> {
    if let Some(millis) = value.as_i64() {
        return DateTime::from_timestamp_millis(millis);
    }
    let value = value.as_str()?;
    value.parse::<DateTime<Utc>>().ok().or_else(|| {
        value
            .parse::<i64>()
            .ok()
            .and_then(DateTime::from_timestamp_millis)
    })
}

fn bounded_value(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len && !value.chars().any(char::is_control)
}

fn safe_credential(value: &str, max_len: usize) -> bool {
    value.trim() == value && bounded_value(value, max_len)
}

fn safe_search_id(value: &str) -> bool {
    bounded_value(value, 512)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn customer_ref(cloud: FalconCloud, client_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"godel-tally:crowdstrike-customer:v1\0");
    hasher.update(cloud.key().as_bytes());
    hasher.update(b"\0");
    hasher.update(client_id.as_bytes());
    format!("cs1_{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, extract::Query, routing::get};
    use std::collections::BTreeMap;

    #[test]
    fn query_requests_dns_network_and_process_events_with_allowlisted_fields() {
        let query = edr_dns_query(500);
        assert!(query.contains("#repo=base_sensor"));
        assert!(query.contains("#event_simpleName=DnsRequest"));
        assert!(query.contains("limit=500"));
        assert!(query.contains("DomainName"));
        assert!(!query.contains("CommandLine"));
        assert!(query.contains("ImageFileName"));
        assert!(query.contains("ContextProcessId"));
        assert!(query.contains("ProcessRollup2"));
    }

    #[test]
    fn projects_only_allowlisted_edr_dns_fields_from_search_events() {
        let event: SearchEvent = serde_json::from_value(serde_json::json!({
            "timestamp": 1_788_775_200_000_i64,
            "attributes": {
                "@id": "evt-1",
                "DomainName": "chatgpt.com",
                "ComputerName": "laptop.example.com",
                "UserName": "analyst@example.com",
                "aid": "agent-7",
                "CommandLine": "must never survive",
                "SHA256HashData": "secret"
            }
        }))
        .expect("search event");
        let start = "2026-09-07T09:00:00Z".parse().expect("start");
        let end = "2026-09-07T11:00:00Z".parse().expect("end");
        let projected = project_event(&event, start, end).expect("projection");
        let value = serde_json::to_value(projected).expect("serialize");
        let serialized = value.to_string();
        assert!(serialized.contains("analyst@example.com"));
        assert!(!serialized.contains("must never survive"));
        assert!(!serialized.contains("SHA256HashData"));
    }

    #[test]
    fn process_and_connection_events_share_native_process_keys_without_commands() {
        let start = "2026-09-07T09:00:00Z".parse().unwrap();
        let end = "2026-09-07T11:00:00Z".parse().unwrap();
        let project = |kind: &str, native: &str| {
            let mut attributes = serde_json::json!({"@id":kind,"#event_simpleName":kind,"aid":"sensor-1","ComputerName":"host-1","RawProcessId":"42","ParentProcessId":"parent-1","ImageFileName":"/usr/bin/curl","ProcessStartTime":"1788775200.123","LocalAddressIP4":"10.0.0.8","RemoteAddressIP4":"10.0.0.9","RemotePort":"443","CommandLine":"PRIVATE-COMMAND"});
            attributes[native] = serde_json::json!("native-7");
            let event: SearchEvent = serde_json::from_value(
                serde_json::json!({"timestamp":1_788_775_200_000_i64,"attributes":attributes}),
            )
            .unwrap();
            project_event(&event, start, end).unwrap()
        };
        let process = serde_json::to_value(project("ProcessRollup2", "TargetProcessId")).unwrap();
        let network =
            serde_json::to_value(project("NetworkConnectIP4", "ContextProcessId")).unwrap();
        assert_eq!(process["process_unique_id"], network["process_unique_id"]);
        assert_eq!(process["process_id"], "42");
        assert_eq!(process["executable"], "curl");
        assert!(!process.to_string().contains("PRIVATE-COMMAND"));
    }

    #[tokio::test]
    async fn completed_search_reads_every_result_page_before_checkpointing() {
        let app = Router::new().route(
            "/queryjobs/test",
            get(|Query(query): Query<BTreeMap<String, String>>| async move {
                let offset: usize = query["paginationOffset"].parse().expect("offset");
                let size: usize = query["paginationLimit"].parse().expect("page size");
                let events = (offset..(offset + size).min(650))
                    .map(|id| serde_json::json!({"attributes":{"@id":format!("event-{id}")}}))
                    .collect::<Vec<_>>();
                Json(serde_json::json!({"done":true,"events":events}))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local search fixture");
        let url = Url::parse(&format!(
            "http://{}/queryjobs/test",
            listener.local_addr().expect("local address")
        ))
        .expect("fixture URL");
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let client = reqwest::Client::new();
        let authorization = HeaderValue::from_static("Bearer test");
        let limited = read_search_events(&url, &authorization, 501, &client)
            .await
            .expect("read through the limit probe");
        assert_eq!(limited.len(), 501);
        assert_eq!(limited[500].attributes["@id"], "event-500");
        let complete = read_search_events(&url, &authorization, 700, &client)
            .await
            .expect("read complete search");
        assert_eq!(complete.len(), 650);
        assert_eq!(complete[649].attributes["@id"], "event-649");
        server.abort();
    }
}
