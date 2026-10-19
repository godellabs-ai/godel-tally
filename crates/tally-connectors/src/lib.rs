//! Connector SDK, deterministic admission batches, and privacy-safe file import foundations.

mod cato;
mod managed_agents;
pub use managed_agents::{
    import_managed_agents_json, managed_agents_descriptor, managed_agents_scope_valid,
};
mod agent_signatures;
mod cloud;
mod crowdstrike;
mod defender;
mod enterprise;
mod flow;
mod gateway;
pub mod purview;
mod vendor;

pub use cloud::{
    AwsStaticCredentials, AzureServicePrincipalCredentials, GcpServiceAccountCredentials,
    ManagedCloudImportConfig, ManagedCloudImportError, ManagedCloudImportOutcome,
    ManagedCloudImportStats, ManagedCloudRedactionControl, ManagedCloudRedactionProof,
    ManagedCloudScope, ManagedCloudTransport, aws_managed_ai_api_descriptor,
    aws_managed_ai_descriptor, azure_managed_ai_api_descriptor, azure_managed_ai_descriptor,
    gcp_vertex_ai_api_descriptor, gcp_vertex_ai_descriptor, import_aws_managed_ai_json,
    import_azure_managed_ai_json, import_gcp_vertex_ai_json,
};
pub use crowdstrike::{
    CROWDSTRIKE_EDR_DNS_PROJECTION_SCHEMA_VERSION, crowdstrike_edr_api_descriptor,
    import_crowdstrike_edr_dns_json,
};
pub use flow::{
    CloudFlowProvider, cloud_flow_api_descriptor, cloud_flow_descriptor,
    cloud_mapping_api_descriptor, cloud_mapping_descriptor, import_cloud_flow_api_json,
    import_cloud_flow_json, import_cloud_mapping_api_json, import_cloud_mapping_json,
};

pub use enterprise::{
    cloudflare_casb_api_descriptor, cloudflare_casb_descriptor, import_cloudflare_casb_api_json,
    import_cloudflare_casb_json, import_kubernetes_api_json, import_kubernetes_api_pull_json,
    kubernetes_api_descriptor, kubernetes_api_pull_descriptor,
};

pub use gateway::{
    AI_GATEWAY_PROJECTION_SCHEMA_VERSION, AI_GATEWAY_REGISTRY_ENTRY,
    LITELLM_PROJECTION_SCHEMA_VERSION, LITELLM_USAGE_PROJECTION_SCHEMA_VERSION,
    ai_gateway_registry_entry_for_provider, cloudflare_ai_gateway_api_descriptor,
    cloudflare_ai_gateway_descriptor, import_cloudflare_ai_gateway_api_json,
    import_cloudflare_ai_gateway_json, import_litellm_model_groups_api_json,
    import_litellm_model_groups_json, litellm_model_groups_api_descriptor,
    litellm_model_groups_descriptor, litellm_registry_entry_for_provider,
};

pub use cato::{
    CATO_NETWORKS_PROJECTION_SCHEMA_VERSION, cato_networks_api_descriptor,
    import_cato_networks_json,
};
pub use defender::{
    MICROSOFT_DEFENDER_PROJECTION_SCHEMA_VERSION, defender_stream_descriptor,
    import_defender_stream_json, import_microsoft_defender_json,
    microsoft_defender_edr_api_descriptor,
};
pub use vendor::{
    NextDnsApiPageMetadata, PseudonymizationKey, RedactionProof, SecurityLogRecord,
    SecurityLogSource, VendorImportConfig, VendorImportError, VendorImportOutcome,
    VendorImportStats, cloudflare_gateway_descriptor, cloudflare_gateway_logpush_s3_descriptor,
    cloudflare_zero_trust_gateway_descriptor, import_cloudflare_gateway_logpush_s3_ndjson,
    import_cloudflare_gateway_ndjson, import_cloudflare_zero_trust_gateway_ndjson,
    import_nextdns_api_json, import_nextdns_csv, import_palo_alto_ndjson,
    import_security_logs_json, import_zscaler_ndjson, inspect_nextdns_api_page,
    netskope_api_origin, nextdns_api_descriptor, nextdns_descriptor, palo_alto_descriptor,
    rapid7_api_origin, zscaler_descriptor,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tally_core::{
    ConnectorRef, DigestAlgorithm, EvidenceReceipt, Hostname, IpAddress,
    OBSERVATION_SCHEMA_VERSION, Observation, ObservationKind,
};
use thiserror::Error;
use uuid::Uuid;

pub const MAX_BATCH_OBSERVATIONS: usize = 10_000;
pub const MAX_IMPORT_BYTES: usize = 64 * 1_024 * 1_024;
pub const MAX_RECORD_BYTES: usize = 64 * 1_024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorDescriptor {
    pub connector_type: String,
    pub display_name: String,
    pub implementation_version: String,
    pub source_vendor: String,
    pub source_product: String,
    pub record_variants: Vec<String>,
    pub transport: ConnectorTransport,
    pub required_permissions: Vec<String>,
    pub requested_fields: Vec<String>,
    pub prohibited_fields: Vec<String>,
    pub cursor_semantics: String,
    pub replay_capability: ReplayCapability,
    pub health_capabilities: Vec<String>,
    pub coverage_capabilities: Vec<String>,
    pub privacy_contract: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorTransport {
    Pull,
    Push,
    Stream,
    File,
    Scanner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayCapability {
    DurableCursor,
    OverlapWindow,
    SourceManagedRetry,
    FileReplay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollOutcome {
    pub next_cursor: Cursor,
    pub records_read: u64,
    pub accepted: u64,
    pub ignored: u64,
    pub rejected: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchReceipt {
    pub installation_id: Uuid,
    pub connector_instance_id: Uuid,
    pub connector_type: String,
    pub implementation_version: String,
    pub checkpoint: Cursor,
    pub observation_count: u64,
    /// Content-addressed idempotency key over canonical normalized observations.
    pub canonical_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationBatch {
    pub receipt: BatchReceipt,
    pub observations: Vec<Observation>,
}

impl ObservationBatch {
    /// Creates a deterministic, content-addressed admission batch.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] if the batch is empty/oversized, mixes installation or connector
    /// identities, uses an unsupported schema, or cannot be canonically serialized.
    pub fn build(
        mut observations: Vec<Observation>,
        checkpoint: Cursor,
    ) -> Result<Self, AdmissionError> {
        let first = observations.first().ok_or(AdmissionError::EmptyBatch)?;
        if observations.len() > MAX_BATCH_OBSERVATIONS {
            return Err(AdmissionError::BatchTooLarge(observations.len()));
        }
        let installation_id = first.installation_id;
        let connector_instance_id = first.connector.instance_id;
        let connector_type = first.connector.connector_type.clone();
        let implementation_version = first.connector.implementation_version.clone();

        for observation in &observations {
            if observation.schema_version != OBSERVATION_SCHEMA_VERSION {
                return Err(AdmissionError::UnsupportedSchema);
            }
            if observation.installation_id != installation_id {
                return Err(AdmissionError::MixedInstallations);
            }
            if observation.connector.instance_id != connector_instance_id {
                return Err(AdmissionError::MixedConnectors);
            }
            if observation.connector.connector_type != connector_type
                || observation.connector.implementation_version != implementation_version
            {
                return Err(AdmissionError::MixedConnectorImplementations);
            }
        }

        observations.sort_by_key(|observation| observation.observation_id);
        if let Some(duplicate) = observations
            .windows(2)
            .find(|pair| pair[0].observation_id == pair[1].observation_id)
        {
            return Err(AdmissionError::DuplicateObservation(
                duplicate[0].observation_id,
            ));
        }
        let canonical_digest = batch_digest(&observations)?;
        Ok(Self {
            receipt: BatchReceipt {
                installation_id,
                connector_instance_id,
                connector_type,
                implementation_version,
                checkpoint,
                observation_count: observations.len() as u64,
                canonical_digest,
            },
            observations,
        })
    }
}

fn batch_digest(observations: &[Observation]) -> Result<String, AdmissionError> {
    let mut hasher = Sha256::new();
    hasher.update(OBSERVATION_SCHEMA_VERSION.as_bytes());
    for observation in observations {
        let mut canonical = observation.clone();
        canonical.received_at = canonical.observed_at;
        let bytes = serde_json::to_vec(&canonical).map_err(|_| AdmissionError::Serialization)?;
        hash_field(&mut hasher, &bytes);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

/// Non-secret capability contract for the generic DNS file connector.
///
/// Every admission path registers its connector so the run ledger and the connector card have a
/// descriptor to describe; without one, imported evidence has no source to attribute it to.
#[must_use]
pub fn generic_dns_descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor {
        connector_type: "generic_dns_file".into(),
        display_name: "Generic DNS file".into(),
        implementation_version: env!("CARGO_PKG_VERSION").into(),
        source_vendor: "generic".into(),
        source_product: "DNS resolver export".into(),
        record_variants: vec!["csv".into(), "ndjson".into()],
        transport: ConnectorTransport::File,
        required_permissions: vec!["read access to the resolver export".into()],
        requested_fields: vec![
            "timestamp".into(),
            "query".into(),
            "client_ip".into(),
            "response_code".into(),
            "action".into(),
        ],
        prohibited_fields: vec![
            "any column outside the accepted five; unknown fields fail closed".into(),
        ],
        cursor_semantics: "operator-supplied source window label; file replay is deterministic"
            .into(),
        replay_capability: ReplayCapability::FileReplay,
        health_capabilities: vec!["normalization quality".into()],
        coverage_capabilities: vec!["source time range".into()],
        privacy_contract:
            "Only the five accepted fields are read; source bytes are discarded after normalization."
                .into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsImportFormat {
    Csv,
    Ndjson,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsImportConfig {
    pub installation_id: Uuid,
    pub connector_instance_id: Uuid,
    pub implementation_version: String,
    pub source_lineage_id: Option<String>,
    /// Fixed per run so replaying the same source window remains deterministic.
    pub received_at: DateTime<Utc>,
    pub checkpoint: Cursor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsImportStats {
    pub records_read: u64,
    pub accepted: u64,
    pub ignored: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsImportOutcome {
    pub batch: ObservationBatch,
    pub stats: DnsImportStats,
}

/// Imports generic DNS metadata and immediately discards the supplied bytes after normalization.
///
/// The accepted CSV headers / NDJSON fields are `timestamp`, `query`, `client_ip`,
/// `response_code`, and `action`. Unknown fields fail closed so content-bearing data cannot be
/// silently retained.
///
/// # Errors
///
/// Returns [`DnsImportError`] for oversized input, malformed records, unsafe host/IP/token values,
/// or an invalid resulting admission batch. Errors identify a row but never echo source content.
pub fn import_dns(
    input: &[u8],
    format: DnsImportFormat,
    config: &DnsImportConfig,
) -> Result<DnsImportOutcome, DnsImportError> {
    if input.len() > MAX_IMPORT_BYTES {
        return Err(DnsImportError::ImportTooLarge(input.len()));
    }
    let records = match format {
        DnsImportFormat::Csv => parse_csv(input)?,
        DnsImportFormat::Ndjson => parse_ndjson(input)?,
    };
    if records.is_empty() {
        return Err(DnsImportError::NoRecords);
    }

    let records_read = records.len() as u64;
    let mut observations = records
        .into_iter()
        .enumerate()
        .map(|(index, record)| normalize_dns(record, index + 1, config))
        .collect::<Result<Vec<_>, _>>()?;
    observations.sort_by_key(|observation| observation.observation_id);
    observations.dedup_by_key(|observation| observation.observation_id);
    let accepted = observations.len() as u64;
    let batch = ObservationBatch::build(observations, config.checkpoint.clone())?;
    Ok(DnsImportOutcome {
        batch,
        stats: DnsImportStats {
            records_read,
            accepted,
            ignored: records_read.saturating_sub(accepted),
        },
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DnsInputRecord {
    timestamp: String,
    query: String,
    #[serde(default)]
    client_ip: Option<String>,
    #[serde(default)]
    response_code: Option<String>,
    #[serde(default)]
    action: Option<String>,
}

#[derive(Debug, Serialize)]
struct CanonicalDnsRecord<'a> {
    observed_at: DateTime<Utc>,
    query: &'a str,
    client_ip: Option<&'a str>,
    response_code: Option<&'a str>,
    action: Option<&'a str>,
}

fn parse_csv(input: &[u8]) -> Result<Vec<DnsInputRecord>, DnsImportError> {
    let mut reader = csv::ReaderBuilder::new()
        .trim(csv::Trim::All)
        .from_reader(input);
    reader
        .deserialize()
        .enumerate()
        .map(|(index, record)| {
            record.map_err(|_| DnsImportError::MalformedRecord { row: index + 2 })
        })
        .collect()
}

fn parse_ndjson(input: &[u8]) -> Result<Vec<DnsInputRecord>, DnsImportError> {
    input
        .split(|byte| *byte == b'\n')
        .enumerate()
        .filter(|(_, line)| !line.iter().all(u8::is_ascii_whitespace))
        .map(|(index, line)| {
            if line.len() > MAX_RECORD_BYTES {
                return Err(DnsImportError::RecordTooLarge { row: index + 1 });
            }
            serde_json::from_slice(line)
                .map_err(|_| DnsImportError::MalformedRecord { row: index + 1 })
        })
        .collect()
}

fn normalize_dns(
    record: DnsInputRecord,
    row: usize,
    config: &DnsImportConfig,
) -> Result<Observation, DnsImportError> {
    let observed_at = DateTime::parse_from_rfc3339(&record.timestamp)
        .map_err(|_| DnsImportError::InvalidTimestamp { row })?
        .with_timezone(&Utc);
    let host = Hostname::parse(&record.query).map_err(|_| DnsImportError::InvalidHost { row })?;
    let client_ip = record
        .client_ip
        .as_deref()
        .map(IpAddress::parse)
        .transpose()
        .map_err(|_| DnsImportError::InvalidClientIp { row })?;
    validate_token(record.response_code.as_deref(), row)?;
    validate_token(record.action.as_deref(), row)?;

    let canonical = CanonicalDnsRecord {
        observed_at,
        query: host.as_str(),
        client_ip: client_ip.as_ref().map(IpAddress::as_str),
        response_code: record.response_code.as_deref(),
        action: record.action.as_deref(),
    };
    let canonical_bytes =
        serde_json::to_vec(&canonical).map_err(|_| DnsImportError::Serialization { row })?;
    let digest = hex::encode(Sha256::digest(&canonical_bytes));
    let observation_id = Uuid::new_v5(
        &Uuid::NAMESPACE_OID,
        format!("{}:{digest}", config.connector_instance_id).as_bytes(),
    );

    let mut observation = Observation::new(
        config.installation_id,
        observed_at,
        ConnectorRef {
            instance_id: config.connector_instance_id,
            connector_type: "generic_dns_file".into(),
            implementation_version: config.implementation_version.clone(),
            source_lineage_id: config.source_lineage_id.clone(),
        },
        ObservationKind::DnsQuery,
        EvidenceReceipt::RecordDigest {
            algorithm: DigestAlgorithm::Sha256,
            digest,
        },
    );
    observation.observation_id = observation_id;
    observation.received_at = config.received_at;
    observation.actor.source_ip = client_ip;
    observation.destination.host = Some(host);
    observation.network.protocol = Some("dns".into());
    observation.network.request_count = Some(1);
    observation.outcome.response_code = record.response_code;
    observation.outcome.action = record.action;
    Ok(observation)
}

fn validate_token(value: Option<&str>, row: usize) -> Result<(), DnsImportError> {
    if value.is_some_and(|value| {
        value.is_empty()
            || value.len() > 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    }) {
        return Err(DnsImportError::InvalidToken { row });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AdmissionError {
    #[error("observation batch is empty")]
    EmptyBatch,
    #[error("observation batch contains {0} records; maximum is {MAX_BATCH_OBSERVATIONS}")]
    BatchTooLarge(usize),
    #[error("observation batch mixes installation identities")]
    MixedInstallations,
    #[error("observation batch mixes connector identities")]
    MixedConnectors,
    #[error("observation batch mixes connector types or implementation versions")]
    MixedConnectorImplementations,
    #[error("observation batch contains duplicate observation id {0}")]
    DuplicateObservation(Uuid),
    #[error("observation batch uses an unsupported schema")]
    UnsupportedSchema,
    #[error("observation batch could not be canonically serialized")]
    Serialization,
}

#[derive(Debug, Error)]
pub enum DnsImportError {
    #[error("DNS import contains no records")]
    NoRecords,
    #[error("DNS import is {0} bytes; maximum is {MAX_IMPORT_BYTES}")]
    ImportTooLarge(usize),
    #[error("DNS import record {row} exceeds the safe size limit")]
    RecordTooLarge { row: usize },
    #[error("DNS import record {row} is malformed or has unknown fields")]
    MalformedRecord { row: usize },
    #[error("DNS import record {row} has an invalid timestamp")]
    InvalidTimestamp { row: usize },
    #[error("DNS import record {row} has an invalid DNS hostname")]
    InvalidHost { row: usize },
    #[error("DNS import record {row} has an invalid client IP")]
    InvalidClientIp { row: usize },
    #[error("DNS import record {row} has an invalid status token")]
    InvalidToken { row: usize },
    #[error("DNS import record {row} could not be normalized")]
    Serialization { row: usize },
    #[error(transparent)]
    Admission(#[from] AdmissionError),
}

#[async_trait]
pub trait ObservationSink: Send {
    async fn write(&mut self, observation: Observation) -> Result<(), ConnectorError>;
}

#[async_trait]
pub trait Connector: Send + Sync {
    fn descriptor(&self) -> ConnectorDescriptor;
    async fn validate(&self) -> Result<(), ConnectorError>;
    async fn poll(
        &self,
        cursor: &Cursor,
        sink: &mut dyn ObservationSink,
    ) -> Result<PollOutcome, ConnectorError>;
}

#[derive(Debug, Error)]
pub enum ConnectorError {
    #[error("source is unavailable")]
    SourceUnavailable,
    #[error("source credentials are invalid or insufficient")]
    Unauthorized,
    #[error("source record is invalid: {0}")]
    InvalidRecord(&'static str),
    #[error("observation sink is unavailable")]
    SinkUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> DnsImportConfig {
        DnsImportConfig {
            installation_id: Uuid::parse_str("018f6cd4-4aaf-7bb4-a3b2-a7524ec43711").expect("UUID"),
            connector_instance_id: Uuid::parse_str("018f6cd4-4aaf-7bb4-a3b2-a7524ec43712")
                .expect("UUID"),
            implementation_version: "1.0.0".into(),
            source_lineage_id: Some("resolver-east".into()),
            received_at: "2026-08-13T10:05:00Z".parse().expect("timestamp"),
            checkpoint: Cursor("window:2026-08-13T10:00:00Z".into()),
        }
    }

    #[test]
    fn generic_dns_csv_normalizes_without_retaining_source_bytes() {
        let input = b"timestamp,query,client_ip,response_code,action\n\
2026-08-13T10:00:00Z,API.OpenAI.com.,10.0.0.7,NOERROR,allowed\n";
        let outcome = import_dns(input, DnsImportFormat::Csv, &config()).expect("valid import");
        assert_eq!(outcome.stats.records_read, 1);
        assert_eq!(
            outcome.batch.observations[0]
                .destination
                .host
                .as_ref()
                .map(Hostname::as_str),
            Some("api.openai.com")
        );
        let serialized = serde_json::to_string(&outcome).expect("serialize outcome");
        assert!(!serialized.contains("API.OpenAI.com."));
        assert!(!serialized.contains("timestamp,query"));
    }

    #[test]
    fn replay_and_input_order_produce_the_same_batch() {
        let first = b"{\"timestamp\":\"2026-08-13T10:00:02Z\",\"query\":\"api.anthropic.com\"}\n\
{\"timestamp\":\"2026-08-13T10:00:01Z\",\"query\":\"api.openai.com\"}\n";
        let reversed = b"{\"timestamp\":\"2026-08-13T10:00:01Z\",\"query\":\"api.openai.com\"}\n\
{\"timestamp\":\"2026-08-13T10:00:02Z\",\"query\":\"api.anthropic.com\"}\n";
        let first = import_dns(first, DnsImportFormat::Ndjson, &config()).expect("valid import");
        let replay =
            import_dns(reversed, DnsImportFormat::Ndjson, &config()).expect("valid import");
        assert_eq!(first.batch, replay.batch);
    }

    #[test]
    fn receipt_is_stable_across_receive_time_and_checkpoint_changes() {
        let input = b"{\"timestamp\":\"2026-08-13T10:00:01Z\",\"query\":\"api.openai.com\"}\n";
        let first = import_dns(input, DnsImportFormat::Ndjson, &config()).expect("valid import");
        let mut later = config();
        later.received_at = "2026-08-13T11:00:00Z".parse().expect("timestamp");
        later.checkpoint = Cursor("different-source-window-label".into());
        let replay = import_dns(input, DnsImportFormat::Ndjson, &later).expect("valid import");
        assert_eq!(
            first.batch.receipt.canonical_digest,
            replay.batch.receipt.canonical_digest
        );
        assert_eq!(
            first.batch.observations[0].observation_id,
            replay.batch.observations[0].observation_id
        );
    }

    #[test]
    fn duplicate_source_records_are_collapsed_before_admission() {
        let input = b"{\"timestamp\":\"2026-08-13T10:00:01Z\",\"query\":\"api.openai.com\"}\n\
{\"timestamp\":\"2026-08-13T10:00:01Z\",\"query\":\"api.openai.com\"}\n";
        let outcome = import_dns(input, DnsImportFormat::Ndjson, &config()).expect("valid import");
        assert_eq!(outcome.stats.records_read, 2);
        assert_eq!(outcome.stats.accepted, 1);
        assert_eq!(outcome.stats.ignored, 1);
    }

    #[test]
    fn content_bearing_unknown_fields_fail_without_echoing_values() {
        let canary = "ULTRA_SECRET_PROMPT_CANARY";
        let input = format!(
            "{{\"timestamp\":\"2026-08-13T10:00:00Z\",\"query\":\"api.openai.com\",\"message\":\"{canary}\"}}"
        );
        let error = import_dns(input.as_bytes(), DnsImportFormat::Ndjson, &config())
            .expect_err("unknown content field must fail");
        assert!(matches!(error, DnsImportError::MalformedRecord { row: 1 }));
        assert!(!error.to_string().contains(canary));
    }

    #[test]
    fn malformed_source_values_never_appear_in_errors() {
        let input = b"timestamp,query,client_ip,response_code,action\nnot-a-time,secret.invalid/path,not-an-ip,NOERROR,allowed\n";
        let error = import_dns(input, DnsImportFormat::Csv, &config()).expect_err("invalid");
        assert_eq!(
            error.to_string(),
            "DNS import record 1 has an invalid timestamp"
        );
        assert!(!error.to_string().contains("secret.invalid"));
    }
}
