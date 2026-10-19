use crate::VendorAdapter;
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use reqwest::Response;
use tally_connectors::{
    AwsStaticCredentials, AzureServicePrincipalCredentials, GcpServiceAccountCredentials,
};
use tally_store_postgres::{LeasedConnectorJob, PostgresStore};

const MAX_PAGE_BYTES: usize = 16 * 1_024 * 1_024;

pub(crate) fn report_due_age(job: &LeasedConnectorJob, now: DateTime<Utc>) {
    let age_seconds = (now - job.next_run_at).num_seconds();
    if age_seconds > 60 {
        eprintln!(
            "tally_connector_due_age_seconds job_id={} seconds={age_seconds}",
            job.job_id
        );
    }
}

/// Sources that commit one time slice at a time can run again promptly while behind. This is
/// checked only after the import has durably advanced the cursor, so retries cannot skip data.
pub(crate) async fn needs_catch_up(
    postgres: &PostgresStore,
    job: &LeasedConnectorJob,
    now: DateTime<Utc>,
) -> Result<bool> {
    let kind = job
        .config_refs
        .get("kind")
        .and_then(serde_json::Value::as_str);
    if matches!(
        kind,
        Some("cloudflare_gateway_logpush_s3_v1" | "cloudflare_zero_trust_gateway_v1")
    ) {
        let cursor = postgres
            .connector_cursor(job.connector_instance_id)
            .await
            .context("read committed Logpush cursor for catch-up")?;
        return Ok(cursor.as_deref().is_some_and(|cursor| {
            cursor.starts_with("s3-backlog1:") || cursor.starts_with("cfzt1:s3-backlog1:")
        }));
    }
    if kind == Some("managed_agents_v1") {
        let cursor = postgres
            .connector_cursor(job.connector_instance_id)
            .await
            .context("read committed managed agent inventory cursor")?;
        return Ok(cursor
            .as_deref()
            .is_some_and(crate::managed_agents::cursor_has_more));
    }
    if kind == Some("nextdns_api_v1") {
        let cursor = postgres
            .connector_cursor(job.connector_instance_id)
            .await
            .context("read committed NextDNS cursor for catch-up")?;
        return Ok(cursor
            .as_deref()
            .and_then(crate::nextdns::parse_cursor)
            .is_some_and(|cursor| {
                cursor.page_cursor.is_some() || now.timestamp_millis() - cursor.from_millis > 60_000
            }));
    }
    if kind == Some("cato_networks_events_feed_v1") {
        let cursor = postgres
            .connector_cursor(job.connector_instance_id)
            .await
            .context("read committed Cato marker for catch-up")?;
        let full_page = cursor
            .as_deref()
            .and_then(|cursor| cursor.strip_prefix("cato-events-v1:"))
            .and_then(|encoded| hex::decode(encoded).ok())
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|cursor| {
                cursor
                    .get("backlog_hint")
                    .and_then(serde_json::Value::as_bool)
            })
            .unwrap_or(false);
        return Ok(full_page);
    }
    if let Some(source) = match kind {
        Some("rapid7_edr_insightidr_api_v1") => {
            Some(tally_connectors::SecurityLogSource::Rapid7Edr)
        }
        Some("netskope_events_api_v1") => Some(tally_connectors::SecurityLogSource::Netskope),
        _ => None,
    } {
        let cursor = postgres.connector_cursor(job.connector_instance_id).await?;
        return Ok(cursor
            .as_deref()
            .is_some_and(|cursor| crate::security_logs::cursor_has_more(source, cursor, now)));
    }
    let prefix = match kind {
        Some("crowdstrike_edr_ngsiem_api_v1") => "ca1:",
        Some("microsoft_defender_graph_hunting_v1") => "microsoft-defender-v1:",
        Some("litellm_api_v1") => "litellm2:",
        Some("ai_gateway_api_v1") => "aigw1:",
        _ => return Ok(false),
    };
    let cursor = postgres
        .connector_cursor(job.connector_instance_id)
        .await
        .context("read committed connector cursor for catch-up")?;
    let Some(observed_through) = cursor
        .as_deref()
        .and_then(|value| value.strip_prefix(prefix))
        .and_then(|value| value.parse::<i64>().ok())
        .and_then(DateTime::from_timestamp_millis)
    else {
        return Ok(false);
    };
    let backlog_seconds = (now - observed_through).num_seconds() - 300;
    if backlog_seconds > 60 {
        eprintln!(
            "tally_connector_backlog_seconds job_id={} seconds={backlog_seconds}",
            job.job_id
        );
    }
    Ok(backlog_seconds > 60)
}

#[derive(Debug)]
pub(crate) struct NativeCloudSnapshot {
    pub data: Vec<u8>,
    pub record_count: usize,
}

#[derive(Debug)]
pub(crate) struct NativeNetworkSnapshot {
    pub data: Vec<u8>,
    pub record_count: usize,
    pub cursor_after: String,
}

#[derive(Debug)]
pub(crate) struct NativeNetworkPull<'a> {
    pub adapter: VendorAdapter,
    pub account_id: &'a str,
    pub network_id: &'a str,
    pub region: &'a str,
    pub log_group: Option<&'a str>,
    pub workspace_resource: Option<&'a str>,
    pub cursor_before: &'a str,
    pub initial_lookback_seconds: u32,
    pub now: DateTime<Utc>,
    pub credentials: NativeNetworkCredentials,
}

#[derive(Debug, Default)]
pub(crate) struct NativeNetworkCredentials {
    pub aws: Option<AwsStaticCredentials>,
    pub azure: Option<AzureServicePrincipalCredentials>,
    pub gcp: Option<GcpServiceAccountCredentials>,
}

#[derive(Debug)]
pub(crate) struct NativeEnterpriseSnapshot {
    pub data: Vec<u8>,
    pub record_count: usize,
}

pub(crate) async fn bounded_response(
    mut response: Response,
    source: &'static str,
) -> Result<Vec<u8>> {
    let status = response.status();
    ensure!(
        status.is_success(),
        "{source} request was unsuccessful (HTTP {status})"
    );
    if response
        .content_length()
        .is_some_and(|length| length > u64::try_from(MAX_PAGE_BYTES).unwrap_or(u64::MAX))
    {
        bail!("{source} response is too large");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("read bounded provider response")?
    {
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= MAX_PAGE_BYTES,
            "{source} response is too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
