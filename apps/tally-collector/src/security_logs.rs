//! Read-only, paged Rapid7 `InsightIDR` and Netskope event pulls.
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use reqwest::{Url, header::HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tally_connectors::{
    SecurityLogRecord, SecurityLogSource, netskope_api_origin, rapid7_api_origin,
};

use crate::pull_support::bounded_response;
use crate::{
    EVENT_SETTLE_SECONDS, JobCredentials, MAX_EVENT_WINDOW_SECONDS, PreparedJob, VendorAdapter,
    valid_initial_backfill_seconds,
};
use tally_connectors::{Cursor, PseudonymizationKey, VendorImportConfig};
use tally_store_postgres::{LeasedConnectorJob, PostgresStore};
use uuid::Uuid;

const PAGE_SIZE: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageCursor {
    start: i64,
    end: i64,
    offset: usize,
    next: Option<String>,
}

#[derive(Deserialize)]
struct Config {
    kind: String,
    source_lineage_id: String,
    backfill_seconds: String,
    initial_start: i64,
    region: Option<String>,
    event_type: Option<String>,
}

struct Page {
    records: Vec<SecurityLogRecord>,
    next: Option<String>,
    more: bool,
}

fn encode_page(source: SecurityLogSource, cursor: &PageCursor) -> Result<String> {
    Ok(format!(
        "{}page:{}",
        source.cursor_prefix(),
        hex::encode(serde_json::to_vec(cursor)?)
    ))
}

fn decode_page(source: SecurityLogSource, cursor: &str) -> Result<PageCursor> {
    let encoded = cursor
        .strip_prefix(&format!("{}page:", source.cursor_prefix()))
        .context("invalid page cursor")?;
    ensure!(encoded.len() <= 32_768, "oversized cursor");
    let page: PageCursor = serde_json::from_slice(&hex::decode(encoded)?)?;
    ensure!(
        page.start < page.end && page.end - page.start <= 3_600_000 && page.offset <= 10_000_000,
        "invalid cursor bounds"
    );
    Ok(page)
}

pub(crate) fn cursor_has_more(source: SecurityLogSource, cursor: &str, now: DateTime<Utc>) -> bool {
    if decode_page(source, cursor).is_ok() {
        return true;
    }
    cursor
        .strip_prefix(source.cursor_prefix())
        .and_then(|value| value.parse::<i64>().ok())
        .is_some_and(|through| now.timestamp_millis() - through > 360_000)
}

pub(crate) async fn prepare(
    postgres: &PostgresStore,
    credentials: &JobCredentials,
    client: &reqwest::Client,
    job: &LeasedConnectorJob,
    source: SecurityLogSource,
) -> Result<PreparedJob, &'static str> {
    prepare_inner(postgres, credentials, client, job, source)
        .await
        .map_err(|_| "security_log_pull_failed")
}

async fn prepare_inner(
    postgres: &PostgresStore,
    credentials: &JobCredentials,
    client: &reqwest::Client,
    job: &LeasedConnectorJob,
    source: SecurityLogSource,
) -> Result<PreparedJob> {
    let config: Config = serde_json::from_value(job.config_refs.clone())?;
    ensure!(
        config.kind == source.connector_type() && job.connector_type == source.connector_type(),
        "connector type mismatch"
    );
    let backfill = config.backfill_seconds.parse::<u32>()?;
    ensure!(valid_initial_backfill_seconds(backfill), "invalid backfill");
    let descriptor = source.descriptor();
    let before = postgres
        .connector_cursor(job.connector_instance_id)
        .await?
        .unwrap_or_default();
    let Some(cursor) = plan_cursor(source, &before, config.initial_start, Utc::now())? else {
        return Ok(PreparedJob::EmptyPoll {
            descriptor,
            cursor_before: before.clone(),
            cursor_after: before,
        });
    };
    ensure!(cursor.end <= Utc::now().timestamp_millis(), "future cursor");
    let page = fetch_page(&config, credentials, client, source, &cursor).await?;
    let checkpoint = if page.more {
        encode_page(
            source,
            &PageCursor {
                offset: cursor
                    .offset
                    .checked_add(PAGE_SIZE)
                    .context("page offset overflow")?,
                next: page.next,
                ..cursor
            },
        )?
    } else {
        format!("{}{}", source.cursor_prefix(), cursor.end)
    };
    if page.records.is_empty() {
        return Ok(PreparedJob::EmptyPoll {
            descriptor,
            cursor_before: before,
            cursor_after: checkpoint,
        });
    }
    let identity = postgres.get_or_create_installation_identity().await?;
    ensure!(
        identity.installation_id == job.installation_id,
        "installation mismatch"
    );
    let input = serde_json::to_vec(&page.records)?;
    let adapter = match source {
        SecurityLogSource::Rapid7Edr => VendorAdapter::Rapid7Edr,
        SecurityLogSource::Netskope => VendorAdapter::Netskope,
    };
    let outcome = adapter.normalize(
        &input,
        &VendorImportConfig {
            installation_id: job.installation_id,
            connector_instance_id: job.connector_instance_id,
            implementation_version: env!("CARGO_PKG_VERSION").into(),
            source_lineage_id: Some(config.source_lineage_id.clone()),
            received_at: Utc::now(),
            checkpoint: Cursor(checkpoint.clone()),
            pseudonymization_key: PseudonymizationKey::new(identity.pseudonymization_key())?,
        },
    )?;
    Ok(PreparedJob::Source {
        descriptor,
        adapter,
        input,
        checkpoint,
        source_lineage_id: config.source_lineage_id,
        expected_canonical_digest: outcome.batch.receipt.canonical_digest,
        cloud: None,
        casb_account_id: None,
    })
}

fn plan_cursor(
    source: SecurityLogSource,
    before: &str,
    initial_start: i64,
    now: DateTime<Utc>,
) -> Result<Option<PageCursor>> {
    if before.contains(":page:") {
        return decode_page(source, before).map(Some);
    }
    let previous = if before.is_empty() {
        DateTime::from_timestamp_millis(initial_start)
    } else {
        before
            .strip_prefix(source.cursor_prefix())
            .and_then(|value| value.parse::<i64>().ok())
            .and_then(DateTime::from_timestamp_millis)
    }
    .context("invalid connector cursor")?;
    let start = DateTime::from_timestamp(previous.timestamp(), 0).context("invalid start")?;
    let settled = DateTime::from_timestamp(now.timestamp() - EVENT_SETTLE_SECONDS, 0)
        .context("invalid settled time")?;
    if start >= settled {
        return Ok(None);
    }
    // Keep the saved start even after an outage. A seven-day initial backfill must not
    // become invalid simply because the first scheduled run starts a few seconds later.
    let end = (start + chrono::Duration::seconds(MAX_EVENT_WINDOW_SECONDS)).min(settled);
    Ok(Some(PageCursor {
        start: start.timestamp_millis(),
        end: end.timestamp_millis(),
        offset: 0,
        next: None,
    }))
}

async fn fetch_page(
    config: &Config,
    credentials: &JobCredentials,
    client: &reqwest::Client,
    source: SecurityLogSource,
    cursor: &PageCursor,
) -> Result<Page> {
    Ok(match source {
        SecurityLogSource::Rapid7Edr => {
            ensure!(
                config.source_lineage_id == "rapid7:insightidr_dns",
                "invalid lineage"
            );
            let origin = rapid7_api_origin(config.region.as_deref().context("missing region")?)
                .context("invalid region")?;
            let log_id = credentials.require("log_id").map_err(anyhow::Error::msg)?;
            Uuid::parse_str(log_id).context("invalid log ID")?;
            pull_rapid7_page(
                client,
                &Url::parse(&origin)?,
                log_id,
                credentials.require("api_key").map_err(anyhow::Error::msg)?,
                cursor,
            )
            .await?
        }
        SecurityLogSource::Netskope => {
            let origin = netskope_api_origin(
                credentials
                    .require("tenant_url")
                    .map_err(anyhow::Error::msg)?,
            )
            .context("invalid tenant")?;
            let event_type = config.event_type.as_deref().context("missing event type")?;
            ensure!(
                matches!(event_type, "page" | "application")
                    && config.source_lineage_id == format!("netskope:{event_type}"),
                "invalid event type"
            );
            pull_netskope_page(
                client,
                &Url::parse(&origin)?,
                event_type,
                credentials
                    .require("api_token")
                    .map_err(anyhow::Error::msg)?,
                cursor,
            )
            .await?
        }
    })
}

fn sensitive_header(value: &str) -> Result<HeaderValue> {
    ensure!(
        !value.is_empty() && value.len() <= 4096,
        "invalid API credential"
    );
    let mut header = HeaderValue::from_str(value).context("invalid API credential")?;
    header.set_sensitive(true);
    Ok(header)
}

fn rapid7_link(base: &Url, value: &str) -> Result<Url> {
    let url = base.join(value).context("invalid pagination link")?;
    ensure!(
        url.origin() == base.origin()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.path().starts_with("/log_search/query/"),
        "unsafe pagination link"
    );
    Ok(url)
}

#[derive(Deserialize)]
struct Rapid7Response {
    events: Vec<Rapid7Event>,
    #[serde(default)]
    links: Vec<Rapid7Link>,
}
#[derive(Deserialize)]
struct Rapid7Event {
    message: String,
    timestamp: i64,
    sequence_number: Option<Value>,
}
#[derive(Deserialize)]
struct Rapid7Link {
    rel: String,
    href: String,
}

async fn pull_rapid7_page(
    client: &reqwest::Client,
    base: &Url,
    log_id: &str,
    key: &str,
    cursor: &PageCursor,
) -> Result<Page> {
    let mut url = if let Some(next) = &cursor.next {
        rapid7_link(base, next)?
    } else {
        let mut url = base.join(&format!("/log_search/query/logs/{log_id}"))?;
        // Rapid7's bounds are inclusive; our saved end is exclusive.
        url.query_pairs_mut()
            .append_pair("from", &cursor.start.to_string())
            .append_pair("to", &(cursor.end - 1).to_string())
            .append_pair("per_page", &PAGE_SIZE.to_string());
        url
    };
    for attempt in 0..15 {
        let response = client
            .get(url.clone())
            .header("x-api-key", sensitive_header(key)?)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .context("Rapid7 request failed")?;
        let pending = response.status() == reqwest::StatusCode::ACCEPTED;
        let data: Rapid7Response =
            serde_json::from_slice(&bounded_response(response, "Rapid7 Log Search").await?)
                .context("invalid Rapid7 response")?;
        if pending {
            let poll = data
                .links
                .iter()
                .find(|link| link.rel == "Self")
                .context("missing query polling link")?;
            url = rapid7_link(base, &poll.href)?;
            ensure!(
                attempt < 14,
                "Rapid7 query did not complete; cursor retained"
            );
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            continue;
        }
        ensure!(data.events.len() <= PAGE_SIZE, "oversized Rapid7 page");
        let next = data
            .links
            .iter()
            .find(|link| link.rel == "Next")
            .map(|link| rapid7_link(base, &link.href))
            .transpose()?
            .map(|url| url.to_string());
        ensure!(
            next.as_ref()
                .is_none_or(|value| Some(value) != cursor.next.as_ref()),
            "repeated Rapid7 page"
        );
        let records = data
            .events
            .iter()
            .map(project_rapid7)
            .collect::<Result<Vec<_>>>()?;
        return Ok(Page {
            records,
            more: next.is_some(),
            next,
        });
    }
    anyhow::bail!("Rapid7 query did not complete")
}

#[derive(Deserialize)]
struct NetskopeResponse {
    ok: u8,
    result: Vec<Value>,
}
async fn pull_netskope_page(
    client: &reqwest::Client,
    base: &Url,
    event_type: &str,
    token: &str,
    cursor: &PageCursor,
) -> Result<Page> {
    let mut url = base.join(&format!("/api/v2/events/data/{event_type}"))?;
    url.query_pairs_mut()
        .append_pair("starttime", &(cursor.start / 1000).to_string())
        .append_pair("endtime", &((cursor.end - 1) / 1000).to_string())
        .append_pair("limit", &PAGE_SIZE.to_string())
        .append_pair("offset", &cursor.offset.to_string());
    let response = client
        .get(url)
        .header("Netskope-Api-Token", sensitive_header(token)?)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .context("Netskope request failed")?;
    let data: NetskopeResponse =
        serde_json::from_slice(&bounded_response(response, "Netskope Events").await?)
            .context("invalid Netskope response")?;
    ensure!(
        data.ok == 1 && data.result.len() <= PAGE_SIZE,
        "Netskope query failed or exceeded page limit"
    );
    let more = data.result.len() == PAGE_SIZE;
    let records = data
        .result
        .into_iter()
        .map(|value| project_netskope(&value))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    Ok(Page {
        records,
        next: None,
        more,
    })
}

fn text(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|value| match value {
            Value::String(text) => Some(text.trim().to_owned()),
            Value::Number(number) => Some(number.to_string()),
            _ => None,
        })
        .filter(|value| {
            !value.is_empty() && value.len() <= 2048 && !value.chars().any(char::is_control)
        })
}
fn timestamp(value: &Value) -> Option<DateTime<Utc>> {
    value
        .as_str()
        .and_then(|text| text.parse::<DateTime<Utc>>().ok())
        .or_else(|| {
            let number = value
                .as_i64()
                .or_else(|| value.as_str()?.parse::<i64>().ok())?;
            if number >= 100_000_000_000 {
                DateTime::from_timestamp_millis(number)
            } else {
                DateTime::from_timestamp(number, 0)
            }
        })
}
fn host(value: &str) -> Option<String> {
    let host = if value.contains("://") {
        Url::parse(value).ok()?.host_str()?.to_owned()
    } else {
        value.to_owned()
    };
    tally_core::Hostname::parse(&host)
        .ok()
        .map(|host| host.as_str().to_owned())
}
fn count(value: &Value, key: &str) -> Result<u64> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(1),
        Some(value) => value
            .as_u64()
            .or_else(|| value.as_str()?.parse().ok())
            .filter(|value| *value > 0)
            .context("invalid event count"),
    }
}
fn source_ip(value: &Value, key: &str) -> Option<String> {
    text(value, key)
        .and_then(|ip| tally_core::IpAddress::parse(&ip).ok())
        .map(|ip| ip.as_str().into())
}
fn project_rapid7(event: &Rapid7Event) -> Result<SecurityLogRecord> {
    ensure!(
        event.message.len() <= tally_connectors::MAX_RECORD_BYTES,
        "oversized Rapid7 event"
    );
    let value: Value =
        serde_json::from_str(&event.message).context("expected normalized DNS Query JSON")?;
    let domain = text(&value, "query")
        .and_then(|value| host(&value))
        .context("expected DNS Query destination")?;
    let id = text(&value, "entry_id")
        .or_else(|| {
            event
                .sequence_number
                .as_ref()
                .and_then(|value| text(&serde_json::json!({"id":value}), "id"))
        })
        .context("missing event identity")?;
    Ok(SecurityLogRecord {
        id,
        observed_at: value
            .get("timestamp")
            .and_then(timestamp)
            .or_else(|| DateTime::from_timestamp_millis(event.timestamp))
            .context("invalid Rapid7 timestamp")?,
        host: domain,
        user: text(&value, "user"),
        hostname: text(&value, "asset").and_then(|value| host(&value)),
        device_id: value
            .pointer("/r7_context/asset/rrn")
            .and_then(Value::as_str)
            .filter(|value| value.len() <= 512)
            .map(str::to_owned),
        source_ip: source_ip(&value, "source_address"),
        action: value
            .get("query_blocked")
            .and_then(|blocked| match blocked {
                Value::Bool(true) => Some("block"),
                Value::Bool(false) => Some("allow"),
                Value::String(value) if value.eq_ignore_ascii_case("true") => Some("block"),
                Value::String(value) if value.eq_ignore_ascii_case("false") => Some("allow"),
                _ => None,
            })
            .map(str::to_owned),
        count: count(&value, "observation_count")?,
    })
}
fn project_netskope(value: &Value) -> Result<Option<SecurityLogRecord>> {
    let Some(domain) = text(value, "url")
        .and_then(|value| host(&value))
        .or_else(|| text(value, "domain").and_then(|value| host(&value)))
    else {
        return Ok(None);
    };
    let observed_at = value
        .get("timestamp")
        .and_then(timestamp)
        .context("invalid Netskope timestamp")?;
    let id = text(value, "_id")
        .or_else(|| text(value, "id"))
        .context("missing Netskope event identity")?;
    Ok(Some(SecurityLogRecord {
        id,
        observed_at,
        host: domain,
        user: text(value, "user").or_else(|| text(value, "userkey")),
        hostname: text(value, "hostname").and_then(|value| host(&value)),
        device_id: text(value, "nsdeviceuid"),
        source_ip: source_ip(value, "srcip").or_else(|| source_ip(value, "userip")),
        action: text(value, "action"),
        count: count(value, "count")?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_logs_cursor_round_trip_and_scope_checks() {
        let cursor = PageCursor {
            start: 1_792_213_200_000,
            end: 1_792_213_260_000,
            offset: 500,
            next: None,
        };
        let encoded = encode_page(SecurityLogSource::Netskope, &cursor).unwrap();
        assert_eq!(
            decode_page(SecurityLogSource::Netskope, &encoded)
                .unwrap()
                .offset,
            500
        );
        assert!(decode_page(SecurityLogSource::Rapid7Edr, &encoded).is_err());
        assert!(cursor_has_more(
            SecurityLogSource::Netskope,
            &encoded,
            Utc::now()
        ));
        let base = Url::parse("https://us.api.insight.rapid7.com").unwrap();
        for value in [
            "https://evil.test/log_search/query/next",
            "https://user@us.api.insight.rapid7.com/log_search/query/next",
            "/management/logs",
            "//evil.test/log_search/query/next",
        ] {
            assert!(rapid7_link(&base, value).is_err());
        }
    }

    #[test]
    fn security_logs_initial_retry_keeps_the_configured_start() {
        let now = DateTime::from_timestamp(1_792_213_200, 0).unwrap();
        let start = (now - chrono::Duration::seconds(3900)).timestamp_millis();
        for source in [SecurityLogSource::Rapid7Edr, SecurityLogSource::Netskope] {
            let first = plan_cursor(source, "", start, now).unwrap().unwrap();
            let retry = plan_cursor(source, "", start, now + chrono::Duration::minutes(10))
                .unwrap()
                .unwrap();
            assert_eq!(first.start, retry.start);
            assert_eq!(first.end, retry.end);
            assert!(plan_cursor(source, "wrong-prefix:123", start, now).is_err());
            let oldest = (now - chrono::Duration::seconds(604_800 + EVENT_SETTLE_SECONDS))
                .timestamp_millis();
            let delayed = plan_cursor(source, "", oldest, now + chrono::Duration::minutes(1))
                .unwrap()
                .unwrap();
            assert_eq!(delayed.start, oldest);
            assert_eq!(delayed.end - delayed.start, 300_000);
        }
    }

    #[test]
    fn security_logs_projection_discards_content_and_keeps_source_counts() {
        let event = Rapid7Event { timestamp: 1_792_213_200_000, sequence_number: Some(1.into()), message: serde_json::json!({
            "query":"api.openai.com", "asset":"LAPTOP-42", "user":"person@example.com", "observation_count":"3", "query_blocked":"true", "source_data":"SECRET", "custom_data":{"command_line":"SECRET"}
        }).to_string() };
        let record = project_rapid7(&event).unwrap();
        assert_eq!(record.action.as_deref(), Some("block"));
        assert_eq!(record.count, 3);
        assert_eq!(record.hostname.as_deref(), Some("laptop-42"));
        assert!(!serde_json::to_string(&record).unwrap().contains("SECRET"));
        let netskope = serde_json::json!({"_id":"event-1", "timestamp":1_792_213_200, "url":"https://api.openai.com/v1/responses?prompt=SECRET", "object":"SECRET", "user":"person@example.com"});
        let record = project_netskope(&netskope).unwrap().unwrap();
        assert_eq!(record.host, "api.openai.com");
        assert!(!serde_json::to_string(&record).unwrap().contains("SECRET"));
        assert!(
            project_netskope(&serde_json::json!({"app":"Offline app"}))
                .unwrap()
                .is_none()
        );
        assert!(
            project_netskope(
                &serde_json::json!({"url":"https://api.openai.com", "timestamp":1_792_213_200})
            )
            .is_err()
        );
    }

    // Runs the production HTTP pullers against the documented contract fixtures via Postman.
    // postman simulation run postman/simulations/security-logs.sim.yaml --port 4909
    // TALLY_SECURITY_SIM_URL=http://127.0.0.1:4909 cargo test -p tally-collector --lib security_logs_http_simulation -- --ignored
    #[tokio::test]
    #[ignore = "requires the local Postman security-logs simulation"]
    async fn security_logs_http_simulation() {
        let base =
            Url::parse(&std::env::var("TALLY_SECURITY_SIM_URL").expect("simulation URL")).unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-mock-slug", HeaderValue::from_static("security-logs"));
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let cursor = PageCursor {
            start: 1_792_213_200_000,
            end: 1_792_213_260_000,
            offset: 0,
            next: None,
        };
        let page = pull_rapid7_page(
            &client,
            &base,
            "00000000-0000-0000-0000-000000000001",
            "fixture-key",
            &cursor,
        )
        .await
        .unwrap();
        assert_eq!(page.records.len(), 1);
        assert!(page.more);
        assert!(
            !serde_json::to_string(&page.records)
                .unwrap()
                .contains("PRIVATE_")
        );
        let next_cursor = PageCursor {
            next: page.next,
            ..cursor.clone()
        };
        let next = pull_rapid7_page(
            &client,
            &base,
            "00000000-0000-0000-0000-000000000001",
            "fixture-key",
            &next_cursor,
        )
        .await
        .unwrap();
        assert!(next.records.is_empty() && !next.more);
        for event_type in ["page", "application"] {
            let page = pull_netskope_page(&client, &base, event_type, "fixture-key", &cursor)
                .await
                .unwrap();
            assert_eq!(page.records.len(), 500);
            assert!(page.more);
            assert!(
                !serde_json::to_string(&page.records)
                    .unwrap()
                    .contains("PRIVATE_")
            );
            let next = pull_netskope_page(
                &client,
                &base,
                event_type,
                "fixture-key",
                &PageCursor {
                    offset: 500,
                    ..cursor.clone()
                },
            )
            .await
            .unwrap();
            assert!(next.records.is_empty() && !next.more);
        }
        for key in ["unauthorized", "rate-limited", "unavailable"] {
            assert!(
                pull_netskope_page(&client, &base, "page", key, &cursor)
                    .await
                    .is_err()
            );
            assert!(
                pull_rapid7_page(
                    &client,
                    &base,
                    "00000000-0000-0000-0000-000000000001",
                    key,
                    &cursor
                )
                .await
                .is_err()
            );
        }
        // Pulls cannot mutate the caller's durable checkpoint on a failed page.
        assert_eq!(cursor.offset, 0);
        assert!(cursor.next.is_none());
    }
}
