use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use reqwest::{Url, header::HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tally_connectors::{
    MAX_BATCH_OBSERVATIONS, MAX_IMPORT_BYTES, MICROSOFT_DEFENDER_PROJECTION_SCHEMA_VERSION,
};
use uuid::Uuid;

use crate::pull_support::{NativeEnterpriseSnapshot, bounded_response};

#[derive(Deserialize)]
struct OAuthResponse {
    access_token: String,
    #[serde(default)]
    token_type: Option<String>,
}

#[derive(Deserialize)]
struct HuntingResponse {
    #[serde(default)]
    results: Vec<Map<String, Value>>,
}

#[derive(Serialize)]
struct DefenderProjection {
    schema_version: &'static str,
    customer_ref: String,
    observed_at: DateTime<Utc>,
    events: Vec<DefenderProjectionEvent>,
}

#[derive(Serialize)]
struct DefenderProjectionEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    directory_object_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    directory_device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os_platform: Option<String>,
    event_table: String,
    id: String,
    observed_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_unique_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_file_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_process_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_started_at: Option<DateTime<Utc>>,
}

pub(crate) struct DefenderPullOutcome {
    pub snapshot: NativeEnterpriseSnapshot,
    pub window_end: DateTime<Utc>,
    pub result_limit_reached: bool,
}

pub(crate) async fn pull_defender_network_events(
    tenant_id: &str,
    client_id: &str,
    client_secret: &str,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    record_limit: usize,
    client: &reqwest::Client,
) -> Result<DefenderPullOutcome> {
    Uuid::parse_str(tenant_id).context("invalid Microsoft tenant ID")?;
    Uuid::parse_str(client_id).context("invalid Microsoft application client ID")?;
    ensure!(
        safe_credential(client_secret, 4_096),
        "invalid Microsoft client secret"
    );
    ensure!(window_start < window_end, "invalid Defender hunting window");
    ensure!(
        (1..=5_000).contains(&record_limit) && record_limit <= MAX_BATCH_OBSERVATIONS,
        "invalid Defender result limit"
    );

    let login_base = Url::parse("https://login.microsoftonline.com/")
        .context("invalid fixed Microsoft login origin")?;
    let token_url = login_base
        .join(&format!("{tenant_id}/oauth2/v2.0/token"))
        .context("build Microsoft token URL")?;
    let token_form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", client_id)
        .append_pair("client_secret", client_secret)
        .append_pair("scope", "https://graph.microsoft.com/.default")
        .append_pair("grant_type", "client_credentials")
        .finish();
    let token_response = client
        .post(token_url)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(token_form)
        .send()
        .await
        .context("Microsoft OAuth request failed")?;
    let token_bytes = bounded_response(token_response, "Microsoft OAuth").await?;
    let token: OAuthResponse =
        serde_json::from_slice(&token_bytes).context("invalid Microsoft OAuth response")?;
    drop(token_bytes);
    ensure!(
        safe_credential(&token.access_token, 16_384)
            && token
                .token_type
                .as_deref()
                .is_none_or(|kind| kind.eq_ignore_ascii_case("bearer")),
        "invalid Microsoft OAuth token"
    );
    let mut authorization = HeaderValue::from_str(&format!("Bearer {}", token.access_token))
        .context("invalid Microsoft OAuth token")?;
    authorization.set_sensitive(true);

    let fetch_limit = record_limit.saturating_add(1);
    let response = client
        .post("https://graph.microsoft.com/v1.0/security/runHuntingQuery")
        .header(reqwest::header::AUTHORIZATION, authorization)
        .header(reqwest::header::ACCEPT, "application/json")
        .json(&serde_json::json!({
            "query": defender_network_query(fetch_limit),
            "timespan": format!(
                "{}/{}",
                window_start.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                window_end.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            )
        }))
        .send()
        .await
        .context("Microsoft Graph hunting request failed")?;
    let response_bytes = bounded_response(response, "Microsoft Graph hunting").await?;
    let hunting: HuntingResponse = serde_json::from_slice(&response_bytes)
        .context("invalid Microsoft Graph hunting response")?;
    drop(response_bytes);
    ensure!(
        hunting.results.len() <= fetch_limit,
        "Microsoft Graph returned more hunting rows than requested"
    );
    let result_limit_reached = hunting.results.len() > record_limit;
    let events = hunting
        .results
        .iter()
        .take(record_limit)
        .filter_map(|row| project_row(row, window_start, window_end))
        .collect::<Vec<_>>();
    let record_count = events.len();
    let data = serde_json::to_vec(&DefenderProjection {
        schema_version: MICROSOFT_DEFENDER_PROJECTION_SCHEMA_VERSION,
        customer_ref: tenant_ref(tenant_id),
        observed_at: window_end,
        events,
    })?;
    ensure!(
        data.len() <= MAX_IMPORT_BYTES,
        "Defender projection is too large"
    );
    Ok(DefenderPullOutcome {
        snapshot: NativeEnterpriseSnapshot { data, record_count },
        window_end,
        result_limit_reached,
    })
}

fn defender_network_query(limit: usize) -> String {
    format!(
        "union (DeviceNetworkEvents | project Timestamp, ReportId, DeviceId, DeviceName, InitiatingProcessAccountUpn, InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessAccountObjectId, ActionType, RemoteUrl, RemoteIP, RemotePort, LocalIP, LocalPort, Protocol, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCreationTime, InitiatingProcessParentFileName, InitiatingProcessParentId, InitiatingProcessUniqueId=tostring(column_ifexists(\"InitiatingProcessUniqueId\", \"\")), EventTable=\"DeviceNetworkEvents\"), (DeviceInfo | project Timestamp, ReportId, DeviceId, DeviceName, AadDeviceId, OSPlatform, EventTable=\"DeviceInfo\")\n| order by Timestamp asc\n| take {limit}"
    )
}

fn project_row(
    row: &Map<String, Value>,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
) -> Option<DefenderProjectionEvent> {
    let observed_at = field(row, &["Timestamp", "timestamp"])?
        .parse::<DateTime<Utc>>()
        .ok()?;
    if observed_at < window_start || observed_at >= window_end {
        return None;
    }
    let device_id = bounded_field(row, &["DeviceId", "deviceId"], 512);
    let hostname = bounded_field(row, &["DeviceName", "deviceName"], 512);
    let mut user_id = bounded_field(
        row,
        &[
            "InitiatingProcessAccountUpn",
            "initiatingProcessAccountUpn",
            "InitiatingProcessAccountName",
            "initiatingProcessAccountName",
        ],
        512,
    );
    if let Some(user) = user_id.as_mut()
        && !user.contains(['@', '\\'])
        && let Some(scope) = bounded_field(
            row,
            &["InitiatingProcessAccountDomain", "DeviceId", "DeviceName"],
            512,
        )
    {
        *user = format!("{scope}\\{user}");
    }
    let action_type = bounded_field(row, &["ActionType", "actionType"], 256);
    let remote_url = bounded_field(row, &["RemoteUrl", "remoteUrl"], 2_048);
    let remote_ip = bounded_field(row, &["RemoteIP", "remoteIP", "remoteIp"], 64);
    let remote_port = integer_field(row, &["RemotePort", "remotePort"])
        .and_then(|value| u16::try_from(value).ok());
    let id = bounded_field(row, &["ReportId", "reportId"], 512).unwrap_or_else(|| {
        let digest = serde_json::to_vec(&(
            observed_at,
            &device_id,
            &hostname,
            &user_id,
            &action_type,
            &remote_url,
            &remote_ip,
            remote_port,
        ))
        .map_or_else(
            |_| Sha256::digest([]).to_vec(),
            |bytes| Sha256::digest(bytes).to_vec(),
        );
        hex::encode(digest)
    });
    Some(DefenderProjectionEvent {
        directory_object_id: bounded_field(row, &["InitiatingProcessAccountObjectId"], 64),
        source_port: integer_field(row, &["LocalPort"]).and_then(|v| v.try_into().ok()),
        protocol: bounded_field(row, &["Protocol"], 16),
        directory_device_id: bounded_field(row, &["AadDeviceId"], 64),
        os_platform: bounded_field(row, &["OSPlatform"], 128),
        event_table: bounded_field(row, &["EventTable"], 64)
            .unwrap_or_else(|| "DeviceNetworkEvents".into()),
        id,
        observed_at,
        device_id,
        hostname,
        user_id,
        action_type,
        remote_url,
        remote_ip,
        remote_port,
        source_ip: bounded_field(row, &["LocalIP"], 64),
        file_name: bounded_field(row, &["InitiatingProcessFileName"], 128),
        process_id: integer_field(row, &["InitiatingProcessId"]).map(|v| v.to_string()),
        process_started_at: field(row, &["InitiatingProcessCreationTime"])
            .and_then(|v| v.parse().ok()),
        process_unique_id: bounded_field(row, &["InitiatingProcessUniqueId"], 128),
        parent_file_name: bounded_field(row, &["InitiatingProcessParentFileName"], 128),
        parent_process_id: integer_field(row, &["InitiatingProcessParentId"])
            .map(|v| v.to_string()),
    })
}

fn field<'a>(row: &'a Map<String, Value>, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .filter_map(|name| row.get(*name).and_then(Value::as_str))
        .map(str::trim)
        .find(|value| !value.is_empty())
}

fn bounded_field(row: &Map<String, Value>, names: &[&str], max_len: usize) -> Option<String> {
    field(row, names)
        .filter(|value| value.len() <= max_len && !value.chars().any(char::is_control))
        .map(str::to_owned)
}

fn integer_field(row: &Map<String, Value>, names: &[&str]) -> Option<u64> {
    names.iter().find_map(|name| {
        let value = row.get(*name)?;
        value
            .as_u64()
            .or_else(|| value.as_str()?.parse::<u64>().ok())
    })
}

fn safe_credential(value: &str, max_len: usize) -> bool {
    value.trim() == value
        && !value.is_empty()
        && value.len() <= max_len
        && !value.chars().any(char::is_control)
}

fn tenant_ref(tenant_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"godel-tally:microsoft-defender-tenant:v1\0");
    hasher.update(tenant_id.as_bytes());
    format!("md1_{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hunting_query_is_bounded_and_projects_only_attribution_fields() {
        let query = defender_network_query(501);
        assert!(query.contains("DeviceNetworkEvents"));
        assert!(query.contains("DeviceInfo"));
        assert!(query.contains("AadDeviceId"));
        assert!(query.contains("InitiatingProcessAccountUpn"));
        assert!(query.contains("RemoteUrl"));
        assert!(query.ends_with("take 501"));
        assert!(!query.contains("ProcessCommandLine"));
        assert!(query.contains("InitiatingProcessFileName"));
        assert!(query.contains("LocalIP"));
        assert!(query.contains("InitiatingProcessCreationTime"));
    }

    #[test]
    fn graph_row_projects_user_endpoint_and_destination_without_extra_fields() {
        let start = "2026-09-15T10:00:00Z".parse().expect("start");
        let end = "2026-09-15T11:00:00Z".parse().expect("end");
        let row = serde_json::from_value::<Map<String, Value>>(serde_json::json!({
            "Timestamp": "2026-09-15T10:30:00Z",
            "ReportId": "42",
            "DeviceId": "device-7",
            "DeviceName": "laptop-7.example.com",
            "InitiatingProcessAccountUpn": "employee@example.com",
            "ActionType": "ConnectionSuccess",
            "RemoteUrl": "api.openai.com",
            "RemoteIP": "203.0.113.8",
            "RemotePort": 443,
            "ProcessCommandLine": "must-not-survive"
        }))
        .expect("row");
        let event = project_row(&row, start, end).expect("project");
        let projected = serde_json::to_string(&event).expect("serialize");
        assert!(projected.contains("employee@example.com"));
        assert!(projected.contains("api.openai.com"));
        assert!(!projected.contains("must-not-survive"));
    }

    #[test]
    fn blank_upn_falls_back_to_the_scoped_process_account() {
        let start = "2026-10-24T12:00:00Z".parse().unwrap();
        let end = "2026-10-24T13:00:00Z".parse().unwrap();
        let mut row = serde_json::from_value::<Map<String, Value>>(serde_json::json!({
            "Timestamp":"2026-10-24T12:15:00Z", "DeviceId":"device-1",
            "DeviceName":"laptop", "InitiatingProcessAccountUpn":"  ",
            "InitiatingProcessAccountName":"_trustd", "InitiatingProcessAccountDomain":"",
            "InitiatingProcessFileName":"microsoft edge helper"
        }))
        .unwrap();
        let event = project_row(&row, start, end).unwrap();
        assert_eq!(event.user_id.as_deref(), Some("device-1\\_trustd"));
        assert_eq!(event.file_name.as_deref(), Some("microsoft edge helper"));
        row.insert(
            "InitiatingProcessAccountUpn".into(),
            Value::String("user@example.test".into()),
        );
        assert_eq!(
            project_row(&row, start, end).unwrap().user_id.as_deref(),
            Some("user@example.test")
        );
    }
}
