mod security_logs;
pub use security_logs::{
    SecurityLogRecord, SecurityLogSource, import_security_logs_json, netskope_api_origin,
    rapid7_api_origin,
};

use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tally_core::{
    ConnectorRef, DigestAlgorithm, EvidenceReceipt, Hostname, IdentityObservation,
    IdentitySubjectKind, IpAddress, Observation, ObservationKind,
};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::{
    AdmissionError, ConnectorDescriptor, ConnectorTransport, Cursor, MAX_BATCH_OBSERVATIONS,
    MAX_IMPORT_BYTES, MAX_RECORD_BYTES, ObservationBatch, ReplayCapability,
};

type HmacSha256 = Hmac<Sha256>;

const IMPLEMENTATION_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, PartialEq, Eq)]
pub struct PseudonymizationKey([u8; 32]);

impl std::fmt::Debug for PseudonymizationKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PseudonymizationKey([REDACTED])")
    }
}

impl PseudonymizationKey {
    /// Creates an installation-local pseudonymization key.
    ///
    /// # Errors
    ///
    /// Returns [`VendorImportError`] unless exactly 32 bytes are supplied.
    pub fn new(bytes: &[u8]) -> Result<Self, VendorImportError> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| VendorImportError::InvalidPseudonymizationKey)?;
        Ok(Self(bytes))
    }

    /// Parses either 32 raw bytes or a newline-terminated 64-character hexadecimal key file.
    ///
    /// # Errors
    ///
    /// Returns [`VendorImportError`] when the file is not one of those exact non-ambiguous forms.
    pub fn parse_file(bytes: &[u8]) -> Result<Self, VendorImportError> {
        if bytes.len() == 32 {
            return Self::new(bytes);
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| VendorImportError::InvalidPseudonymizationKey)?
            .trim_end_matches(['\r', '\n']);
        if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(VendorImportError::InvalidPseudonymizationKey);
        }
        let decoded =
            hex::decode(text).map_err(|_| VendorImportError::InvalidPseudonymizationKey)?;
        Self::new(&decoded)
    }

    pub(crate) fn pseudonym(&self, namespace: &'static str, value: &str) -> String {
        self.pseudonym_bytes(namespace, value.trim().to_ascii_lowercase().as_bytes())
    }

    /// Stable installation-local identity for a source ID, preserving its case.
    pub fn pseudonym_exact(&self, namespace: &'static str, value: &str) -> String {
        self.pseudonym_bytes(namespace, value.trim().as_bytes())
    }

    fn pseudonym_bytes(&self, namespace: &'static str, value: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("fixed-size HMAC key");
        mac.update(b"godel-tally:pseudonym:v1\0");
        mac.update(namespace.as_bytes());
        mac.update(b"\0");
        mac.update(value);
        format!("p1_{}", hex::encode(mac.finalize().into_bytes()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorImportConfig {
    pub installation_id: Uuid,
    pub connector_instance_id: Uuid,
    pub implementation_version: String,
    pub source_lineage_id: Option<String>,
    pub received_at: DateTime<Utc>,
    pub checkpoint: Cursor,
    pub pseudonymization_key: PseudonymizationKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VendorImportStats {
    pub records_read: u64,
    pub accepted: u64,
    pub ignored: u64,
    pub rejected: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionProof {
    pub connector_type: String,
    pub pseudonymization: String,
    pub discarded_fields: Vec<String>,
    pub source_bytes_retained: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VendorImportOutcome {
    pub batch: ObservationBatch,
    pub stats: VendorImportStats,
    pub redaction: RedactionProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextDnsApiPageMetadata {
    pub next_page_cursor: Option<String>,
    pub last_observed_at: Option<DateTime<Utc>>,
    pub record_count: usize,
}

pub fn nextdns_descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor {
        connector_type: "nextdns_csv_v1".into(),
        display_name: "NextDNS".into(),
        implementation_version: IMPLEMENTATION_VERSION.into(),
        source_vendor: "NextDNS".into(),
        source_product: "Logs CSV export".into(),
        record_variants: vec!["official_csv_export".into()],
        transport: ConnectorTransport::File,
        required_permissions: vec!["configuration logs export".into()],
        requested_fields: vec![
            "timestamp".into(), "domain".into(), "query_type".into(), "protocol".into(),
            "client_ip".into(), "status".into(), "device_id".into(), "device_name".into(),
            "device_local_ip when present".into(),
        ],
        prohibited_fields: vec!["device_model".into(), "reasons".into()],
        cursor_semantics: "timestamp plus normalized record digest; overlap replay safe".into(),
        replay_capability: ReplayCapability::FileReplay,
        health_capabilities: vec!["normalization quality".into(), "source freshness".into()],
        coverage_capabilities: vec!["endpoint hostname".into(), "source time range".into()],
        privacy_contract: "Valid endpoint hostnames and source addresses are retained for response; unrelated labels, models, reasons, and source bytes are discarded.".into(),
    }
}

pub fn nextdns_api_descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor {
        connector_type: "nextdns_logs_api_v1".into(),
        display_name: "NextDNS live logs".into(),
        implementation_version: IMPLEMENTATION_VERSION.into(),
        source_vendor: "NextDNS".into(),
        source_product: "Logs API".into(),
        record_variants: vec!["logs_api_json".into()],
        transport: ConnectorTransport::Pull,
        required_permissions: vec!["profile logs read through X-Api-Key".into()],
        requested_fields: vec![
            "timestamp".into(), "domain".into(), "protocol".into(), "clientIp".into(),
            "status".into(), "device.id".into(), "device.name".into(),
            "device.localIp when present".into(),
        ],
        prohibited_fields: vec![
            "client".into(), "device.model".into(), "reasons".into(),
            "tracker".into(),
        ],
        cursor_semantics: "inclusive timestamp watermark plus source pagination cursor; overlap replay safe".into(),
        replay_capability: ReplayCapability::DurableCursor,
        health_capabilities: vec![
            "API connectivity".into(), "cursor freshness".into(), "normalization quality".into(),
        ],
        coverage_capabilities: vec![
            "endpoint hostname".into(), "source time range".into(), "source lag".into(),
        ],
        privacy_contract: "API keys remain environment-only. Endpoint hostnames and source addresses are retained when valid; unrelated labels, reasons, trackers, and source bytes are discarded.".into(),
    }
}

pub fn cloudflare_gateway_descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor {
        connector_type: "cloudflare_gateway_dns_logpush_v1".into(),
        display_name: "Cloudflare Gateway DNS and HTTP".into(),
        implementation_version: IMPLEMENTATION_VERSION.into(),
        source_vendor: "Cloudflare".into(),
        source_product: "Gateway DNS and HTTP Logpush".into(),
        record_variants: vec!["gateway_dns_ndjson".into(), "gateway_http_ndjson".into(), "zero_trust_network_sessions".into()],
        transport: ConnectorTransport::Push,
        required_permissions: vec!["Logs Write or operator-owned Logpush destination read".into()],
        requested_fields: vec![
            "Datetime".into(), "QueryID".into(), "QueryName".into(),
            "QueryTypeName".into(), "RCode".into(), "ResolverDecision".into(),
            "Protocol".into(), "DeviceID".into(), "DeviceName".into(), "Email".into(),
            "UserID".into(), "SourceIP and SourceInternalIP".into(), "DstIP or DestinationIP".into(),
            "DstPort or DestinationPort".into(), "HTTPHost".into(),
            "URL (inspected in memory)".into(),
            "Network sessions: SessionID, SessionEndTime, SNI, ResolvedFQDN, OriginIP, OriginPort, BytesSent, BytesReceived".into(),
        ],
        prohibited_fields: vec![
            "PolicyName".into(), "RedirectTargetURI".into(), "RData".into(),
            "URL path and query after in-memory AI signature detection".into(),
        ],
        cursor_semantics: "QueryID with Datetime watermark; Logpush destination owns delivery retry".into(),
        replay_capability: ReplayCapability::SourceManagedRetry,
        health_capabilities: vec!["delivery freshness".into(), "normalization quality".into()],
        coverage_capabilities: vec!["endpoint user".into(), "endpoint hostname".into(), "source lag".into()],
        privacy_contract: "Endpoint emails or bounded source user IDs, device hostnames, source addresses, and AI destination hostnames are retained for findings. HTTP URLs are inspected in memory only for bounded model-request paths, then paths, queries, policy labels, redirects, RData, and source bytes are discarded.".into(),
    }
}

pub fn cloudflare_gateway_logpush_s3_descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor {
        connector_type: "cloudflare_gateway_http_logpush_s3_v1".into(),
        display_name: "Cloudflare Zero Trust Gateway".into(),
        implementation_version: IMPLEMENTATION_VERSION.into(),
        source_vendor: "Cloudflare".into(),
        source_product: "Gateway HTTP Logpush through an S3-compatible destination".into(),
        record_variants: vec!["gateway_http_logpush_ndjson_gzip".into(), "zero_trust_network_sessions".into()],
        transport: ConnectorTransport::Pull,
        required_permissions: vec![
            "Cloudflare Zero Trust Enterprise Logpush entitlement".into(),
            "Gateway HTTP (gateway_http) or zero_trust_network_sessions Logpush job".into(),
            "bucket-scoped S3 ListBucket and GetObject access".into(),
        ],
        requested_fields: vec![
            "Datetime".into(),
            "RequestID".into(),
            "HTTPHost".into(),
            "URL (inspected in memory)".into(),
            "Network sessions: SessionID, SessionEndTime, SNI, ResolvedFQDN, OriginIP, OriginPort, BytesSent, BytesReceived".into(),
            "DestinationIP and DestinationPort".into(),
            "SourceIP and SourceInternalIP".into(),
            "DeviceID and DeviceName".into(),
            "Email and UserID".into(),
            "HTTPMethod".into(),
            "Action".into(),
        ],
        prohibited_fields: vec![
            "PolicyName, category names, and application labels".into(),
            "RedirectTargetURI, Referer, and UserAgent".into(),
            "headers, files, DLP matches, and payload content".into(),
            "URL path and query after in-memory AI signature detection".into(),
            "source object bytes after normalization".into(),
        ],
        cursor_semantics:
            "exclusive lexicographic object-key watermark over bounded S3 listings".into(),
        replay_capability: ReplayCapability::DurableCursor,
        health_capabilities: vec![
            "S3 destination connectivity".into(),
            "cursor freshness".into(),
            "normalization quality".into(),
        ],
        coverage_capabilities: vec![
            "endpoint user".into(),
            "endpoint device".into(),
            "endpoint source address".into(),
            "AI destination".into(),
            "source lag".into(),
        ],
        privacy_contract: "Endpoint emails or bounded source user IDs, device hostnames, source addresses, and AI destination hostnames are retained for findings. HTTP URLs are inspected in memory only for bounded model-request paths, then paths, queries, headers, content, unrelated labels, and source object bytes are discarded.".into(),
    }
}

/// Describes the scheduled Cloudflare Zero Trust Gateway source.
///
/// DNS and HTTP analytics are always pulled through Cloudflare's account GraphQL API. A customer
/// may also provide a Gateway HTTP Logpush destination exposed through an S3-compatible API for
/// per-request metadata beyond the default aggregate analytics.
pub fn cloudflare_zero_trust_gateway_descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor {
        connector_type: "cloudflare_zero_trust_gateway_v1".into(),
        display_name: "Cloudflare Zero Trust Gateway".into(),
        implementation_version: IMPLEMENTATION_VERSION.into(),
        source_vendor: "Cloudflare".into(),
        source_product:
            "Gateway DNS and HTTP GraphQL analytics with optional HTTP Logpush through S3"
                .into(),
        record_variants: vec![
            "gateway_resolver_queries_adaptive_group_v1".into(),
            "gateway_l7_requests_adaptive_group_v1".into(),
            "optional_gateway_http_logpush_ndjson_gzip".into(),
            "optional_zero_trust_network_sessions".into(),
        ],
        transport: ConnectorTransport::Pull,
        required_permissions: vec!["Account Analytics Read".into()],
        requested_fields: vec![
            "DNS query name, resolver decision, minute, and aggregate request count".into(),
            "HTTP destination host, action, minute, and aggregate request count".into(),
            "HTTP source internal IP, device ID, Email, and UserID".into(),
            "Optional Logpush: Datetime, RequestID, HTTPHost, and URL inspected in memory".into(),
            "Optional Logpush: destination IP and port".into(),
            "Optional Logpush: source IPs, device ID/name, Email, and UserID".into(),
            "Optional Logpush: HTTP method and action".into(),
            "Optional network sessions: SessionID, SessionEndTime, SNI, ResolvedFQDN, OriginIP, OriginPort, BytesSent, BytesReceived".into(),
        ],
        prohibited_fields: vec![
            "DNS policy names, categories, resolved addresses, and source response bytes".into(),
            "HTTP policy, category, application, redirect, referer, and user-agent labels".into(),
            "headers, files, DLP matches, payload content, and source object bytes".into(),
            "URL path and query after bounded in-memory AI signature detection".into(),
        ],
        cursor_semantics: "closed DNS and HTTP minute-window replay plus an optional exclusive S3 object-key watermark".into(),
        replay_capability: ReplayCapability::DurableCursor,
        health_capabilities: vec![
            "Cloudflare analytics connectivity".into(),
            "optional S3 destination connectivity".into(),
            "cursor freshness".into(),
            "normalization quality".into(),
        ],
        coverage_capabilities: vec![
            "aggregate AI destination DNS activity".into(),
            "aggregate AI destination HTTP activity".into(),
            "endpoint user, device, and source address for HTTP activity".into(),
            "optional per-request Gateway HTTP metadata".into(),
            "source lag".into(),
        ],
        privacy_contract: "The default GraphQL source retains aggregate destination hostnames, bounded decisions, minute buckets, counts, and Cloudflare-supplied HTTP user and source-device attribution. Optional Gateway HTTP Logpush adds per-request metadata. URL paths, queries, headers, content, unrelated labels, and source bytes are discarded after bounded in-memory detection.".into(),
    }
}

pub fn zscaler_descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor {
        connector_type: "zscaler_zia_nss_web_v1".into(),
        display_name: "Zscaler ZIA / NSS".into(),
        implementation_version: IMPLEMENTATION_VERSION.into(),
        source_vendor: "Zscaler".into(),
        source_product: "ZIA Nanolog Streaming Service web logs".into(),
        record_variants: vec!["vm_nss_json".into(), "cloud_nss_json".into()],
        transport: ConnectorTransport::Stream,
        required_permissions: vec!["NSS web feed configured with Tally allowlist".into()],
        requested_fields: vec![
            "time".into(), "record_id".into(), "login".into(), "host".into(),
            "url or eurl".into(), "action".into(), "url_category".into(), "protocol".into(),
            "client_ip".into(), "server_ip".into(), "server_port".into(),
            "request_size".into(), "response_size".into(), "device_hostname".into(),
            "client internet IP and source-native login when present".into(),
            "request/response JSON content (inspected in memory only)".into(),
        ],
        prohibited_fields: vec![
            "url path/query".into(), "cookies".into(), "headers".into(),
            "request/response content after in-memory AI signature detection".into(), "user agent".into(), "department".into(),
            "sourcetype".into(),
        ],
        cursor_semantics: "record ID plus source timestamp; Cloud NSS recovery limits surface as coverage".into(),
        replay_capability: ReplayCapability::SourceManagedRetry,
        health_capabilities: vec!["stream connectivity".into(), "cursor freshness".into(), "normalization quality".into()],
        coverage_capabilities: vec!["endpoint user".into(), "endpoint hostname".into(), "source lag".into()],
        privacy_contract: "Endpoint emails or bounded source-native login names, valid hostnames, and source addresses are retained for findings. URL paths and bounded JSON content are inspected in memory for AI request signatures, then content, paths, queries, headers, cookies, and unrelated labels are discarded.".into(),
    }
}

pub fn palo_alto_descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor {
        connector_type: "palo_alto_strata_https_v1".into(),
        display_name: "Palo Alto Prisma Access".into(),
        implementation_version: IMPLEMENTATION_VERSION.into(),
        source_vendor: "Palo Alto Networks".into(),
        source_product: "Strata Logging Service HTTPS forwarding".into(),
        record_variants: vec!["firewall_traffic_https".into(), "url_https".into()],
        transport: ConnectorTransport::Push,
        required_permissions: vec!["Strata Logging Service HTTPS log forwarding".into()],
        requested_fields: vec![
            "TimeGenerated".into(), "SequenceNumber".into(), "Type".into(),
            "SourceAddress".into(), "DestinationAddress".into(), "DestinationPort".into(),
            "SourceUser".into(), "SourceDeviceHost".into(), "DestinationDeviceHost".into(),
            "SourceUserInfoName, SourceUserInfoDomain, and SourceUserInfoUUID".into(),
            "URLDomain and X-Forwarded-ForIP".into(),
            "URL".into(),
            "Application".into(), "URLCategory".into(), "Protocol".into(), "Action".into(),
            "BytesSent".into(), "BytesReceived".into(),
        ],
        prohibited_fields: vec![
            "URL path/query".into(), "HTTPHeaders".into(), "FileURL".into(),
            "user agent".into(), "threat payload".into(),
            "outer time/host/source".into(),
        ],
        cursor_semantics: "sequence number plus TimeGenerated; capability detected per tenant/API generation".into(),
        replay_capability: ReplayCapability::SourceManagedRetry,
        health_capabilities: vec!["API or forwarding connectivity".into(), "cursor freshness".into(), "normalization quality".into()],
        coverage_capabilities: vec!["endpoint user".into(), "endpoint hostname".into(), "source lag".into()],
        privacy_contract: "Endpoint emails or bounded source-native login names, valid hostnames, and source addresses are retained for response; URL paths/queries, headers, file URLs, user agents, threat payloads, and source bytes are discarded.".into(),
    }
}

/// Normalizes an official `NextDNS` CSV export without retaining labels or source bytes.
///
/// # Errors
///
/// Returns [`VendorImportError`] for oversized/malformed inputs or unsafe metadata.
pub fn import_nextdns_csv(
    input: &[u8],
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    check_import_size(input)?;
    let mut reader = csv::ReaderBuilder::new()
        .trim(csv::Trim::All)
        .from_reader(input);
    let records = reader
        .deserialize::<NextDnsRecord>()
        .enumerate()
        .map(|(index, record)| {
            record.map_err(|_| VendorImportError::MalformedRecord { row: index + 2 })
        })
        .collect::<Result<Vec<_>, _>>()?;
    normalize_records(
        records,
        config,
        "nextdns_csv_v1",
        &[
            "dnssec",
            "reasons",
            "destination_country",
            "root_domain",
            "device_model",
            "device_local_ip",
            "matched_name",
            "client_name",
        ],
        normalize_nextdns,
    )
}

/// Inspects bounded `NextDNS` Logs API pagination metadata without retaining source bytes.
///
/// # Errors
///
/// Returns [`VendorImportError`] for oversized, malformed, or unsafe responses.
pub fn inspect_nextdns_api_page(input: &[u8]) -> Result<NextDnsApiPageMetadata, VendorImportError> {
    check_import_size(input)?;
    let envelope: NextDnsApiEnvelope =
        serde_json::from_slice(input).map_err(|_| VendorImportError::MalformedRecord { row: 1 })?;
    let mut last_observed_at: Option<DateTime<Utc>> = None;
    for (index, record) in envelope.data.iter().enumerate() {
        let observed_at = parse_time(TimeValue::Text(record.timestamp.clone()), index + 1)?;
        last_observed_at =
            Some(last_observed_at.map_or(observed_at, |current| current.max(observed_at)));
    }
    let next_page_cursor = envelope
        .meta
        .and_then(|meta| meta.pagination)
        .and_then(|pagination| pagination.cursor)
        .map(|cursor| validate_nextdns_cursor(&cursor))
        .transpose()?;
    Ok(NextDnsApiPageMetadata {
        next_page_cursor,
        last_observed_at,
        record_count: envelope.data.len(),
    })
}

/// Normalizes one `NextDNS` Logs API JSON page without retaining source bytes.
///
/// # Errors
///
/// Returns [`VendorImportError`] for oversized/malformed inputs or unsafe metadata.
pub fn import_nextdns_api_json(
    input: &[u8],
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    check_import_size(input)?;
    let envelope: NextDnsApiEnvelope =
        serde_json::from_slice(input).map_err(|_| VendorImportError::MalformedRecord { row: 1 })?;
    normalize_records(
        envelope.data,
        config,
        "nextdns_logs_api_v1",
        &[
            "root",
            "tracker",
            "encrypted",
            "client",
            "device.model",
            "device.localIp",
            "reasons",
        ],
        normalize_nextdns_api,
    )
}

/// Normalizes Cloudflare Gateway DNS Logpush NDJSON.
///
/// # Errors
///
/// Returns [`VendorImportError`] for oversized/malformed inputs or unsafe metadata.
pub fn import_cloudflare_gateway_ndjson(
    input: &[u8],
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    normalize_records(
        parse_ndjson(input)?,
        config,
        "cloudflare_gateway_dns_logpush_v1",
        &[
            "PolicyName",
            "RedirectTargetURI",
            "RData",
            "CategoryNames and ApplicationNames",
            "ResolvedIPs",
            "URL path/query after bounded AI request signature detection",
        ],
        normalize_cloudflare_input,
    )
}

/// Normalizes bounded Cloudflare Gateway HTTP Logpush NDJSON read from an S3-compatible
/// destination.
///
/// Admits `gateway_http` and `zero_trust_network_sessions`. It does not accept the
/// similarly named Cloudflare AI Gateway Logpush dataset.
///
/// # Errors
///
/// Returns [`VendorImportError`] for oversized/malformed inputs or unsafe metadata.
pub fn import_cloudflare_gateway_logpush_s3_ndjson(
    input: &[u8],
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    normalize_records(
        parse_ndjson::<CloudflareLogpushRecord>(input)?,
        config,
        "cloudflare_gateway_http_logpush_s3_v1",
        &[
            "PolicyName",
            "RedirectTargetURI",
            "Referer",
            "UserAgent",
            "AddedHeaders, DeletedHeaders, and SetHeaders",
            "MatchedCategoryNames",
            "QueryCategoryNames",
            "file and DLP metadata",
            "URL path/query after bounded AI request signature detection",
        ],
        normalize_cloudflare_http_logpush_input,
    )
}

/// Normalizes the combined scheduled Cloudflare Zero Trust Gateway projection. The input may
/// contain aggregate DNS rows from GraphQL and, when configured, Gateway HTTP Logpush rows.
///
/// # Errors
///
/// Returns [`VendorImportError`] for oversized/malformed inputs or unsafe metadata.
pub fn import_cloudflare_zero_trust_gateway_ndjson(
    input: &[u8],
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    normalize_records(
        parse_ndjson::<CloudflareZeroTrustRecordInput>(input)?,
        config,
        "cloudflare_zero_trust_gateway_v1",
        &[
            "DNS policy names, categories, resolved addresses, and source response bytes",
            "HTTP policy, category, application, redirect, referer, and user-agent labels",
            "headers, files, DLP matches, payload content, and source object bytes",
            "URL path/query after bounded AI request signature detection",
        ],
        normalize_cloudflare_zero_trust_gateway_input,
    )
}

/// Normalizes the documented Tally allowlisted Zscaler NSS JSON feed shape.
///
/// # Errors
///
/// Returns [`VendorImportError`] for oversized/malformed inputs or unsafe metadata.
pub fn import_zscaler_ndjson(
    input: &[u8],
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    normalize_records(
        parse_ndjson(input)?,
        config,
        "zscaler_zia_nss_web_v1",
        &[
            "url path/query",
            "department",
            "device_owner",
            "user_agent",
            "cookies",
            "request_content",
            "response_content",
            "sourcetype",
        ],
        normalize_zscaler_input,
    )
}

/// Normalizes Palo Alto Strata HTTPS-forwarded traffic/URL NDJSON.
///
/// # Errors
///
/// Returns [`VendorImportError`] for oversized/malformed inputs or unsafe metadata.
pub fn import_palo_alto_ndjson(
    input: &[u8],
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    normalize_records(
        parse_ndjson(input)?,
        config,
        "palo_alto_strata_https_v1",
        &[
            "URL path/query",
            "HTTPHeaders",
            "FileURL",
            "UserAgent",
            "ThreatPayload",
            "outer time/host/source",
        ],
        normalize_palo_alto_input,
    )
}

fn normalize_records<T>(
    records: Vec<T>,
    config: &VendorImportConfig,
    connector_type: &'static str,
    discarded_fields: &[&'static str],
    normalize: fn(T, usize, &VendorImportConfig) -> Result<Option<Observation>, VendorImportError>,
) -> Result<VendorImportOutcome, VendorImportError> {
    if records.is_empty() {
        return Err(VendorImportError::NoRecords);
    }
    let records_read = records.len() as u64;
    let mut observations = Vec::with_capacity(records.len());
    for (index, record) in records.into_iter().enumerate() {
        if let Some(observation) = normalize(record, index + 1, config)? {
            observations.push(observation);
        }
    }
    observations.sort_by_key(|observation| observation.observation_id);
    observations.dedup_by_key(|observation| observation.observation_id);
    let accepted = observations.len() as u64;
    if observations.is_empty() {
        return Err(VendorImportError::NoAcceptedRecords);
    }
    Ok(VendorImportOutcome {
        batch: ObservationBatch::build(observations, config.checkpoint.clone())?,
        stats: VendorImportStats {
            records_read,
            accepted,
            ignored: records_read.saturating_sub(accepted),
            rejected: 0,
        },
        redaction: RedactionProof {
            connector_type: connector_type.into(),
            pseudonymization: "hmac_sha256_installation_key_v1".into(),
            discarded_fields: discarded_fields.iter().map(ToString::to_string).collect(),
            source_bytes_retained: false,
        },
    })
}

#[derive(Debug, Deserialize)]
struct NextDnsApiEnvelope {
    data: Vec<NextDnsApiRecord>,
    #[serde(default)]
    meta: Option<NextDnsApiMeta>,
}

#[derive(Debug, Deserialize)]
struct NextDnsApiMeta {
    #[serde(default)]
    pagination: Option<NextDnsApiPagination>,
}

#[derive(Debug, Deserialize)]
struct NextDnsApiPagination {
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NextDnsApiRecord {
    timestamp: String,
    domain: String,
    #[serde(default)]
    root: Option<String>,
    #[serde(default)]
    tracker: Option<String>,
    #[serde(default)]
    encrypted: Option<bool>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    client_ip: Option<String>,
    #[serde(default)]
    client: Option<String>,
    #[serde(default)]
    device: Option<NextDnsApiDevice>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    reasons: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NextDnsApiDevice {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    local_ip: Option<String>,
}

fn normalize_nextdns_api(
    record: NextDnsApiRecord,
    row: usize,
    config: &VendorImportConfig,
) -> Result<Option<Observation>, VendorImportError> {
    let device_id = record
        .device
        .as_ref()
        .and_then(|device| device.id.as_deref());
    let device_key = device_id
        .filter(|value| !value.trim().is_empty())
        .map(|value| config.pseudonymization_key.pseudonym("device", value));
    let endpoint_hostname = record
        .device
        .as_ref()
        .and_then(|device| device.name.as_deref())
        .and_then(normalized_hostname);
    let local_ip = parse_optional_ip(
        record
            .device
            .as_ref()
            .and_then(|device| device.local_ip.as_deref()),
        row,
        "device.localIp",
    )?;
    if let Some(device) = record.device {
        drop((device.name, device.model));
    }
    drop((
        record.root,
        record.tracker,
        record.encrypted,
        record.client,
        record.reasons,
    ));
    let observed_at = parse_time(TimeValue::Text(record.timestamp), row)?;
    let host = parse_host(&record.domain, row)?;
    let source_ip = parse_optional_ip(record.client_ip.as_deref(), row, "clientIp")?;
    let protocol = optional_token(record.protocol.as_deref(), row, "protocol")?;
    let status = optional_token(record.status.as_deref(), row, "status")?;
    let safe = SafeRecord {
        request_client: None,
        observed_at,
        host: Some(host.as_str()),
        destination_ip: None,
        destination_port: None,
        source_ip: source_ip.as_ref().map(IpAddress::as_str),
        alternate_source_ip: local_ip.as_ref().map(IpAddress::as_str),
        identity: None,
        email: None,
        source_subject: None,
        source_subject_kind: None,
        device: device_key.as_deref(),
        hostname: endpoint_hostname.as_deref(),
        protocol: protocol.as_deref(),
        action: status.as_deref(),
        result: None,
        category: None,
        application: None,
        bytes_sent: None,
        bytes_received: None,
        request_count: 1,
        source_record_id: None,
        ai_request: false,
        ai_request_evaluated: false,
        declared_model_id: None,
    };
    Ok(Some(observation_from_safe(
        &safe,
        config,
        "nextdns_logs_api_v1",
        ObservationKind::DnsQuery,
    )?))
}

fn validate_nextdns_cursor(value: &str) -> Result<String, VendorImportError> {
    if value.is_empty()
        || value.len() > 512
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(VendorImportError::InvalidField {
            row: 1,
            field: "meta.pagination.cursor",
        });
    }
    Ok(value.to_owned())
}

#[derive(Debug, Deserialize)]
struct NextDnsRecord {
    timestamp: String,
    domain: String,
    #[serde(default)]
    query_type: Option<String>,
    #[serde(default)]
    dnssec: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    client_ip: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    reasons: Option<String>,
    #[serde(default)]
    destination_country: Option<String>,
    #[serde(default)]
    root_domain: Option<String>,
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    device_name: Option<String>,
    #[serde(default)]
    device_model: Option<String>,
    #[serde(default)]
    device_local_ip: Option<String>,
    #[serde(default)]
    matched_name: Option<String>,
    #[serde(default)]
    client_name: Option<String>,
}

fn normalize_nextdns(
    record: NextDnsRecord,
    row: usize,
    config: &VendorImportConfig,
) -> Result<Option<Observation>, VendorImportError> {
    let endpoint_hostname = record.device_name.as_deref().and_then(normalized_hostname);
    let local_ip = parse_optional_ip(record.device_local_ip.as_deref(), row, "device_local_ip")?;
    drop((
        record.dnssec,
        record.reasons,
        record.destination_country,
        record.root_domain,
        record.device_model,
        record.matched_name,
        record.client_name,
    ));
    let observed_at = parse_time(TimeValue::Text(record.timestamp), row)?;
    let host = parse_host(&record.domain, row)?;
    let source_ip = parse_optional_ip(record.client_ip.as_deref(), row, "client_ip")?;
    let protocol = optional_token(record.protocol.as_deref(), row, "protocol")?;
    let query_type = optional_token(record.query_type.as_deref(), row, "query_type")?;
    let status = optional_token(record.status.as_deref(), row, "status")?;
    let device_key = record
        .device_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| config.pseudonymization_key.pseudonym("device", value));
    let safe = SafeRecord {
        request_client: None,
        observed_at,
        host: Some(host.as_str()),
        destination_ip: None,
        destination_port: None,
        source_ip: source_ip.as_ref().map(IpAddress::as_str),
        alternate_source_ip: local_ip.as_ref().map(IpAddress::as_str),
        identity: None,
        email: None,
        source_subject: None,
        source_subject_kind: None,
        device: device_key.as_deref(),
        hostname: endpoint_hostname.as_deref(),
        protocol: protocol.as_deref(),
        action: status.as_deref(),
        result: query_type.as_deref(),
        category: None,
        application: None,
        bytes_sent: None,
        bytes_received: None,
        request_count: 1,
        source_record_id: None,
        ai_request: false,
        ai_request_evaluated: false,
        declared_model_id: None,
    };
    Ok(Some(observation_from_safe(
        &safe,
        config,
        "nextdns_csv_v1",
        ObservationKind::DnsQuery,
    )?))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CloudflareRecord {
    #[serde(alias = "datetime")]
    datetime: TimeValue,
    #[serde(alias = "query_name")]
    query_name: String,
    #[serde(default, rename = "QueryID", alias = "query_id")]
    query_id: Option<String>,
    #[serde(default, alias = "query_type_name")]
    query_type_name: Option<String>,
    #[serde(default, rename = "RCode", alias = "r_code")]
    r_code: Option<i64>,
    #[serde(default, alias = "resolver_decision")]
    resolver_decision: Option<String>,
    #[serde(default, alias = "request_count")]
    request_count: Option<u64>,
    #[serde(default, alias = "protocol")]
    protocol: Option<String>,
    #[serde(default, rename = "DeviceID", alias = "device_id")]
    device_id: Option<String>,
    #[serde(default, alias = "device_name")]
    device_name: Option<String>,
    #[serde(default, alias = "email")]
    email: Option<String>,
    #[serde(default, rename = "UserID", alias = "user_id")]
    user_id: Option<String>,
    #[serde(
        default,
        rename = "SrcIP",
        alias = "SourceIP",
        alias = "source_ip",
        alias = "src_ip"
    )]
    src_ip: Option<String>,
    #[serde(default, rename = "SourceInternalIP", alias = "source_internal_ip")]
    source_internal_ip: Option<String>,
    #[serde(
        default,
        rename = "DstIP",
        alias = "DestinationIP",
        alias = "destination_ip",
        alias = "dst_ip"
    )]
    dst_ip: Option<String>,
    #[serde(
        default,
        rename = "DstPort",
        alias = "DestinationPort",
        alias = "destination_port",
        alias = "dst_port"
    )]
    dst_port: Option<u16>,
    #[serde(default, alias = "location")]
    location: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CloudflareHttpRecord {
    #[serde(default, rename = "TallySource", alias = "tally_source")]
    tally_source: Option<String>,
    #[serde(alias = "datetime")]
    datetime: TimeValue,
    #[serde(
        default,
        rename = "RequestID",
        alias = "request_id",
        alias = "requestid"
    )]
    request_id: Option<String>,
    #[serde(default, rename = "HTTPHost", alias = "http_host", alias = "httphost")]
    http_host: Option<String>,
    #[serde(default, rename = "URL", alias = "url")]
    url: Option<String>,
    #[serde(
        default,
        rename = "DestinationIP",
        alias = "destination_ip",
        alias = "destinationip"
    )]
    destination_ip: Option<String>,
    #[serde(
        default,
        rename = "DestinationPort",
        alias = "destination_port",
        alias = "destinationport"
    )]
    destination_port: Option<u16>,
    #[serde(
        default,
        rename = "SourceInternalIP",
        alias = "source_internal_ip",
        alias = "sourceinternalip"
    )]
    source_internal_ip: Option<String>,
    #[serde(default, rename = "SourceIP", alias = "source_ip", alias = "sourceip")]
    source_ip: Option<String>,
    #[serde(default, rename = "DeviceID", alias = "device_id", alias = "deviceid")]
    device_id: Option<String>,
    #[serde(default, alias = "device_name", alias = "devicename")]
    device_name: Option<String>,
    #[serde(default, alias = "email")]
    email: Option<String>,
    #[serde(default, rename = "UserID", alias = "user_id", alias = "userid")]
    user_id: Option<String>,
    #[serde(
        default,
        rename = "HTTPMethod",
        alias = "http_method",
        alias = "httpmethod"
    )]
    http_method: Option<FlexibleId>,
    #[serde(
        default,
        rename = "HTTPMethodName",
        alias = "http_method_name",
        alias = "httpmethodname"
    )]
    http_method_name: Option<String>,
    #[serde(default, alias = "action")]
    action: Option<FlexibleId>,
    #[serde(
        default,
        rename = "ActionName",
        alias = "action_name",
        alias = "actionname"
    )]
    action_name: Option<String>,
    #[serde(default, rename = "RequestCount", alias = "request_count")]
    request_count: Option<u64>,
    #[serde(
        default,
        rename = "UserAgent",
        alias = "user_agent",
        alias = "useragent"
    )]
    user_agent: Option<String>,
}

// Gateway HTTP logs do not report transfer sizes. Network-session Logpush does, and must
// remain a distinct record shape so file sizes and request counts cannot become sent bytes.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CloudflareNetworkSession {
    #[serde(rename = "SessionID")]
    session_id: String,
    session_end_time: TimeValue,
    #[serde(default, rename = "SNI")]
    sni: Option<String>,
    #[serde(default, rename = "ResolvedFQDN")]
    resolved_fqdn: Option<String>,
    #[serde(default, rename = "OriginIP")]
    origin_ip: Option<String>,
    #[serde(default)]
    origin_port: Option<u16>,
    #[serde(default, rename = "SourceIP")]
    source_ip: Option<String>,
    #[serde(default, rename = "SourceInternalIP")]
    source_internal_ip: Option<String>,
    #[serde(default, rename = "DeviceID")]
    device_id: Option<String>,
    #[serde(default)]
    device_name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default, rename = "UserID")]
    user_id: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default, deserialize_with = "optional_byte_count")]
    bytes_sent: Option<u64>,
    #[serde(default, deserialize_with = "optional_byte_count")]
    bytes_received: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CloudflareLogpushRecord {
    Session(CloudflareNetworkSession),
    Http(CloudflareHttpRecord),
}

fn normalize_cloudflare_session(
    record: CloudflareNetworkSession,
    row: usize,
    config: &VendorImportConfig,
    connector_type: &'static str,
) -> Result<Option<Observation>, VendorImportError> {
    let protocol = optional_token(record.protocol.as_deref(), row, "Protocol")?;
    let http = CloudflareHttpRecord {
        user_agent: None,
        tally_source: None,
        datetime: record.session_end_time,
        request_id: Some(format!("network-session:{}", record.session_id)),
        http_host: record
            .sni
            .filter(|host| !host.trim().is_empty())
            .or(record.resolved_fqdn),
        url: None,
        destination_ip: record.origin_ip,
        destination_port: record.origin_port,
        source_internal_ip: record.source_internal_ip,
        source_ip: record.source_ip,
        device_id: record.device_id,
        device_name: record.device_name,
        email: record.email,
        user_id: record.user_id,
        http_method: None,
        http_method_name: None,
        action: None,
        action_name: None,
        request_count: None,
    };
    let mut observation = normalize_cloudflare_http(http, row, config, connector_type)?;
    if let Some(observation) = observation.as_mut() {
        observation.kind = ObservationKind::NetworkFlow;
        observation.network.protocol = protocol;
        observation.network.request_count = None;
        observation.network.bytes_sent = record.bytes_sent;
        observation.network.bytes_received = record.bytes_received;
    }
    Ok(observation)
}

// NSS and firewall JSON feeds commonly encode counters as decimal strings. Missing and
// measured zero are distinct; negative, fractional, and overflowing values are invalid.
fn optional_byte_count<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(serde_json::Value::String(value)) if value.trim().is_empty() || value == "-" => {
            Ok(None)
        }
        Some(serde_json::Value::String(value))
            if value.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            value
                .parse::<u64>()
                .map(Some)
                .map_err(serde::de::Error::custom)
        }
        Some(serde_json::Value::Number(value)) if value.as_u64().is_some() => Ok(value.as_u64()),
        _ => Err(serde::de::Error::custom("invalid byte counter")),
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CloudflareRecordInput {
    Session(CloudflareNetworkSession),
    Dns(CloudflareRecord),
    Http(CloudflareHttpRecord),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct CloudflareGraphqlDnsRecord {
    tally_source: String,
    datetime: TimeValue,
    query_name: String,
    #[serde(default)]
    resolver_decision: Option<String>,
    request_count: u64,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CloudflareZeroTrustRecordInput {
    Session(Box<CloudflareNetworkSession>),
    Dns(CloudflareGraphqlDnsRecord),
    Http(Box<CloudflareHttpRecord>),
}

fn normalize_cloudflare_input(
    record: CloudflareRecordInput,
    row: usize,
    config: &VendorImportConfig,
) -> Result<Option<Observation>, VendorImportError> {
    normalize_cloudflare_record(record, row, config, "cloudflare_gateway_dns_logpush_v1")
}

fn normalize_cloudflare_http_logpush_input(
    record: CloudflareLogpushRecord,
    row: usize,
    config: &VendorImportConfig,
) -> Result<Option<Observation>, VendorImportError> {
    match record {
        CloudflareLogpushRecord::Session(record) => normalize_cloudflare_session(
            record,
            row,
            config,
            "cloudflare_gateway_http_logpush_s3_v1",
        ),
        CloudflareLogpushRecord::Http(record) => {
            normalize_cloudflare_http(record, row, config, "cloudflare_gateway_http_logpush_s3_v1")
        }
    }
}

fn normalize_cloudflare_zero_trust_gateway_input(
    record: CloudflareZeroTrustRecordInput,
    row: usize,
    config: &VendorImportConfig,
) -> Result<Option<Observation>, VendorImportError> {
    match record {
        CloudflareZeroTrustRecordInput::Session(record) => {
            normalize_cloudflare_session(*record, row, config, "cloudflare_zero_trust_gateway_v1")
        }
        CloudflareZeroTrustRecordInput::Dns(record) => {
            if record.tally_source != "graphql_dns" {
                return Err(VendorImportError::InvalidField {
                    row,
                    field: "TallySource",
                });
            }
            normalize_cloudflare(
                CloudflareRecord {
                    datetime: record.datetime,
                    query_name: record.query_name,
                    query_id: None,
                    query_type_name: None,
                    r_code: None,
                    resolver_decision: record.resolver_decision,
                    request_count: Some(record.request_count),
                    protocol: Some("dns".to_owned()),
                    device_id: None,
                    device_name: None,
                    email: None,
                    user_id: None,
                    src_ip: None,
                    source_internal_ip: None,
                    dst_ip: None,
                    dst_port: None,
                    location: None,
                },
                row,
                config,
                "cloudflare_zero_trust_gateway_v1",
            )
        }
        CloudflareZeroTrustRecordInput::Http(record) => {
            if record
                .tally_source
                .as_deref()
                .is_some_and(|source| source != "graphql_http" || record.request_count.is_none())
            {
                return Err(VendorImportError::InvalidField {
                    row,
                    field: "TallySource",
                });
            }
            normalize_cloudflare_http(*record, row, config, "cloudflare_zero_trust_gateway_v1")
        }
    }
}

fn normalize_cloudflare_record(
    record: CloudflareRecordInput,
    row: usize,
    config: &VendorImportConfig,
    connector_type: &'static str,
) -> Result<Option<Observation>, VendorImportError> {
    match record {
        CloudflareRecordInput::Session(record) => {
            normalize_cloudflare_session(record, row, config, connector_type)
        }
        CloudflareRecordInput::Dns(record) => {
            normalize_cloudflare(record, row, config, connector_type)
        }
        CloudflareRecordInput::Http(record) => {
            normalize_cloudflare_http(record, row, config, connector_type)
        }
    }
}

fn normalize_cloudflare(
    record: CloudflareRecord,
    row: usize,
    config: &VendorImportConfig,
    connector_type: &'static str,
) -> Result<Option<Observation>, VendorImportError> {
    if record.request_count == Some(0) {
        return Err(VendorImportError::InvalidField {
            row,
            field: "RequestCount",
        });
    }
    let request_count = record.request_count.unwrap_or(1);
    let endpoint_hostname = record.device_name.as_deref().and_then(normalized_hostname);
    drop(record.location);
    if record.query_name.trim() == "." {
        return Ok(None);
    }
    let observed_at = parse_time(record.datetime, row)?;
    let host = parse_host(&record.query_name, row)?;
    let source_ip = parse_optional_ip(record.src_ip.as_deref(), row, "SrcIP")?;
    let source_internal_ip = parse_optional_ip(
        record.source_internal_ip.as_deref(),
        row,
        "SourceInternalIP",
    )?;
    let destination_ip = parse_optional_ip(record.dst_ip.as_deref(), row, "DstIP")?;
    let protocol = optional_token(record.protocol.as_deref(), row, "Protocol")?;
    let query_type = optional_token(record.query_type_name.as_deref(), row, "QueryTypeName")?;
    let decision = optional_label(record.resolver_decision.as_deref(), row, "ResolverDecision")?;
    let rcode = record.r_code.map(|value| value.to_string());
    // Email is optional enrichment. A malformed source value must not discard otherwise valid
    // DNS evidence; retain and pseudonymize it only when it is a recognized address.
    let email = record.email.as_deref().and_then(recognized_email);
    let source_subject = record.user_id.as_deref().and_then(recognized_subject);
    let identity = email
        .as_deref()
        .or(source_subject.as_deref())
        .map(|value| config.pseudonymization_key.pseudonym("identity", value));
    let device = record
        .device_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| config.pseudonymization_key.pseudonym("device", value));
    let source_record_id = validate_record_id(record.query_id.as_deref(), row)?;
    let safe = SafeRecord {
        request_client: None,
        observed_at,
        host: Some(host.as_str()),
        destination_ip: destination_ip.as_ref().map(IpAddress::as_str),
        destination_port: record.dst_port,
        source_ip: source_ip.as_ref().map(IpAddress::as_str),
        alternate_source_ip: source_internal_ip.as_ref().map(IpAddress::as_str),
        identity: identity.as_deref(),
        email: email.as_deref(),
        source_subject: source_subject.as_deref(),
        source_subject_kind: source_subject
            .as_ref()
            .map(|_| IdentitySubjectKind::SourceUserId),
        device: device.as_deref(),
        hostname: endpoint_hostname.as_deref(),
        protocol: protocol.as_deref(),
        action: decision.as_deref(),
        result: rcode.as_deref().or(query_type.as_deref()),
        category: None,
        application: None,
        bytes_sent: None,
        bytes_received: None,
        request_count,
        source_record_id: source_record_id.as_deref(),
        ai_request: false,
        ai_request_evaluated: false,
        declared_model_id: None,
    };
    Ok(Some(observation_from_safe(
        &safe,
        config,
        connector_type,
        ObservationKind::DnsQuery,
    )?))
}

fn normalize_cloudflare_http(
    record: CloudflareHttpRecord,
    row: usize,
    config: &VendorImportConfig,
    connector_type: &'static str,
) -> Result<Option<Observation>, VendorImportError> {
    if record.request_count == Some(0) {
        return Err(VendorImportError::InvalidField {
            row,
            field: "RequestCount",
        });
    }
    let request_client = record
        .user_agent
        .as_deref()
        .and_then(tally_core::RequestClientKind::from_user_agent)
        .map(|name| tally_core::RequestClientObservation {
            name: Some(name),
            agent_id: None,
        });
    let request_count = record.request_count.unwrap_or(1);
    let observed_at = parse_time(record.datetime, row)?;
    let host_value = record
        .http_host
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .or_else(|| record.url.as_deref().and_then(extract_url_host));
    let host = host_value
        .as_deref()
        .map(|value| parse_host(value, row))
        .transpose()?;
    let destination_ip = parse_optional_ip(record.destination_ip.as_deref(), row, "DestinationIP")?;
    if host.is_none() && destination_ip.is_none() {
        return Err(VendorImportError::InvalidField {
            row,
            field: "HTTPHost",
        });
    }
    let source_ip = parse_optional_ip(record.source_ip.as_deref(), row, "SourceIP")?;
    let source_internal_ip = parse_optional_ip(
        record.source_internal_ip.as_deref(),
        row,
        "SourceInternalIP",
    )?;
    let protocol = (record.http_method.is_some() || record.http_method_name.is_some())
        .then(|| "https".to_owned());
    let action_value = record
        .action_name
        .as_deref()
        .or_else(|| record.action.as_ref().map(|value| value.0.as_str()));
    let action = optional_label(action_value, row, "Action")?;
    let email = record.email.as_deref().and_then(recognized_email);
    let source_subject = record.user_id.as_deref().and_then(recognized_subject);
    let identity = email
        .as_deref()
        .or(source_subject.as_deref())
        .map(|value| config.pseudonymization_key.pseudonym("identity", value));
    let endpoint_hostname = record.device_name.as_deref().and_then(normalized_hostname);
    let device = record
        .device_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| config.pseudonymization_key.pseudonym("device", value));
    let source_record_id = validate_record_id(record.request_id.as_deref(), row)?;
    let (ai_request_evaluated, ai_request, declared_model_id) =
        ai_request_signature(record.url.as_deref(), None, None);
    let safe = SafeRecord {
        request_client,
        observed_at,
        host: host.as_ref().map(Hostname::as_str),
        destination_ip: destination_ip.as_ref().map(IpAddress::as_str),
        destination_port: record.destination_port,
        source_ip: source_ip.as_ref().map(IpAddress::as_str),
        alternate_source_ip: source_internal_ip.as_ref().map(IpAddress::as_str),
        identity: identity.as_deref(),
        email: email.as_deref(),
        source_subject: source_subject.as_deref(),
        source_subject_kind: source_subject
            .as_ref()
            .map(|_| IdentitySubjectKind::SourceUserId),
        device: device.as_deref(),
        hostname: endpoint_hostname.as_deref(),
        protocol: protocol.as_deref(),
        action: action.as_deref(),
        result: None,
        category: None,
        application: None,
        bytes_sent: None,
        bytes_received: None,
        request_count,
        source_record_id: source_record_id.as_deref(),
        ai_request,
        ai_request_evaluated,
        declared_model_id: declared_model_id.as_deref(),
    };
    Ok(Some(observation_from_safe(
        &safe,
        config,
        connector_type,
        ObservationKind::HttpMetadata,
    )?))
}

#[derive(Debug, Deserialize)]
struct ZscalerRecord {
    time: TimeValue,
    #[serde(default, alias = "recordid")]
    record_id: Option<String>,
    #[serde(default)]
    login: Option<String>,
    #[serde(default)]
    #[serde(alias = "dept")]
    department: Option<String>,
    #[serde(default, alias = "deviceowner")]
    device_owner: Option<String>,
    #[serde(default, alias = "devicehostname")]
    device_hostname: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    #[serde(alias = "eurl")]
    url: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default, alias = "urlclass")]
    url_category: Option<String>,
    #[serde(default, alias = "proto")]
    protocol: Option<String>,
    #[serde(default, alias = "clientip", alias = "cip")]
    client_ip: Option<String>,
    #[serde(default, alias = "cintip", alias = "client_internet_ip")]
    client_internet_ip: Option<String>,
    #[serde(default, alias = "serverip", alias = "sip")]
    server_ip: Option<String>,
    #[serde(default, alias = "serverport", alias = "srv_dport")]
    server_port: Option<u16>,
    #[serde(
        default,
        alias = "requestsize",
        alias = "reqsize",
        deserialize_with = "optional_byte_count"
    )]
    request_size: Option<u64>,
    #[serde(
        default,
        alias = "responsesize",
        alias = "respsize",
        deserialize_with = "optional_byte_count"
    )]
    response_size: Option<u64>,
    #[serde(default)]
    #[serde(alias = "ua")]
    user_agent: Option<String>,
    #[serde(default)]
    cookies: Option<String>,
    #[serde(default)]
    request_content: Option<String>,
    #[serde(default)]
    response_content: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ZscalerRecordInput {
    Direct(ZscalerRecord),
    Event {
        event: ZscalerRecord,
        #[serde(default)]
        sourcetype: Option<String>,
    },
}

fn normalize_zscaler_input(
    input: ZscalerRecordInput,
    row: usize,
    config: &VendorImportConfig,
) -> Result<Option<Observation>, VendorImportError> {
    let record = match input {
        ZscalerRecordInput::Direct(record) => record,
        ZscalerRecordInput::Event { event, sourcetype } => {
            drop(sourcetype);
            event
        }
    };
    normalize_zscaler(record, row, config)
}

fn normalize_zscaler(
    record: ZscalerRecord,
    row: usize,
    config: &VendorImportConfig,
) -> Result<Option<Observation>, VendorImportError> {
    let request_client = record
        .user_agent
        .as_deref()
        .and_then(tally_core::RequestClientKind::from_user_agent)
        .map(|name| tally_core::RequestClientObservation {
            name: Some(name),
            agent_id: None,
        });
    let (ai_request_evaluated, ai_request, declared_model_id) = ai_request_signature(
        record.url.as_deref(),
        record.request_content.as_deref(),
        record.response_content.as_deref(),
    );
    drop((
        record.department,
        record.user_agent,
        record.cookies,
        record.request_content,
        record.response_content,
    ));
    let observed_at = parse_time(record.time, row)?;
    let host_value = record
        .host
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .or_else(|| record.url.as_deref().and_then(extract_url_host));
    let host = host_value
        .as_deref()
        .map(|value| parse_host(value, row))
        .transpose()?;
    let destination_ip = parse_optional_ip(record.server_ip.as_deref(), row, "server_ip")?;
    if host.is_none() && destination_ip.is_none() {
        return Err(VendorImportError::InvalidField { row, field: "host" });
    }
    let source_ip = parse_optional_ip(record.client_ip.as_deref(), row, "client_ip")?;
    let client_internet_ip = parse_optional_ip(
        record.client_internet_ip.as_deref(),
        row,
        "client_internet_ip",
    )?;
    let protocol = optional_token(record.protocol.as_deref(), row, "protocol")?;
    let action = optional_label(record.action.as_deref(), row, "action")?;
    let category = optional_label(record.url_category.as_deref(), row, "url_category")?;
    let identity_source = record.login.as_deref().or(record.device_owner.as_deref());
    let identity = identity_source
        .filter(|value| !value.trim().is_empty())
        .map(|value| config.pseudonymization_key.pseudonym("identity", value));
    let email = identity_source.and_then(recognized_email);
    let source_subject = identity_source
        .filter(|_| email.is_none())
        .and_then(recognized_subject);
    let endpoint_hostname = record
        .device_hostname
        .as_deref()
        .and_then(normalized_hostname);
    let device = record
        .device_hostname
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| config.pseudonymization_key.pseudonym("device", value));
    let source_record_id = validate_record_id(record.record_id.as_deref(), row)?;
    let safe = SafeRecord {
        request_client,
        observed_at,
        host: host.as_ref().map(Hostname::as_str),
        destination_ip: destination_ip.as_ref().map(IpAddress::as_str),
        destination_port: record.server_port,
        source_ip: source_ip.as_ref().map(IpAddress::as_str),
        alternate_source_ip: client_internet_ip.as_ref().map(IpAddress::as_str),
        identity: identity.as_deref(),
        email: email.as_deref(),
        source_subject: source_subject.as_deref(),
        source_subject_kind: source_subject
            .as_ref()
            .map(|_| IdentitySubjectKind::UserName),
        device: device.as_deref(),
        hostname: endpoint_hostname.as_deref(),
        protocol: protocol.as_deref(),
        action: action.as_deref(),
        result: None,
        category: category.as_deref(),
        application: None,
        bytes_sent: record.request_size,
        bytes_received: record.response_size,
        request_count: 1,
        source_record_id: source_record_id.as_deref(),
        ai_request,
        ai_request_evaluated,
        declared_model_id: declared_model_id.as_deref(),
    };
    Ok(Some(observation_from_safe(
        &safe,
        config,
        "zscaler_zia_nss_web_v1",
        ObservationKind::HttpMetadata,
    )?))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PaloAltoRecord {
    #[serde(alias = "time_generated")]
    time_generated: TimeValue,
    #[serde(
        default,
        alias = "SequenceNo",
        alias = "sequence_number",
        alias = "sequence_no"
    )]
    sequence_number: Option<FlexibleId>,
    #[serde(default, rename = "Type")]
    log_type: Option<String>,
    #[serde(default, alias = "source_address", alias = "src")]
    source_address: Option<String>,
    #[serde(default, alias = "destination_address", alias = "dst")]
    destination_address: Option<String>,
    #[serde(default, alias = "destination_port", alias = "dport")]
    destination_port: Option<u16>,
    #[serde(default, alias = "source_user", alias = "src_user", alias = "user")]
    source_user: Option<String>,
    #[serde(default, alias = "source_user_info_name")]
    source_user_info_name: Option<String>,
    #[serde(default, alias = "source_user_info_domain")]
    source_user_info_domain: Option<String>,
    #[serde(
        default,
        rename = "SourceUserInfoUUID",
        alias = "source_user_info_uuid"
    )]
    source_user_info_uuid: Option<String>,
    #[serde(default, alias = "source_device_host")]
    source_device_host: Option<String>,
    #[serde(default, alias = "destination_device_host")]
    destination_device_host: Option<String>,
    #[serde(default, rename = "URLDomain", alias = "url_domain")]
    url_domain: Option<String>,
    #[serde(default, rename = "X-Forwarded-ForIP", alias = "x_forwarded_for_ip")]
    x_forwarded_for_ip: Option<String>,
    #[serde(default, rename = "URL")]
    url: Option<String>,
    #[serde(default)]
    application: Option<String>,
    #[serde(default, rename = "URLCategory")]
    url_category: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(
        default,
        alias = "bytes_sent",
        deserialize_with = "optional_byte_count"
    )]
    bytes_sent: Option<u64>,
    #[serde(
        default,
        alias = "bytes_received",
        alias = "bytes_recv",
        deserialize_with = "optional_byte_count"
    )]
    bytes_received: Option<u64>,
    #[serde(default, rename = "HTTPHeaders")]
    http_headers: Option<String>,
    #[serde(default, rename = "FileURL")]
    file_url: Option<String>,
    #[serde(default)]
    user_agent: Option<String>,
    #[serde(default)]
    threat_payload: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PaloAltoRecordInput {
    Direct(PaloAltoRecord),
    Event {
        event: PaloAltoRecord,
        #[serde(default)]
        time: Option<TimeValue>,
        #[serde(default)]
        host: Option<String>,
        #[serde(default)]
        source: Option<String>,
    },
}

#[allow(clippy::too_many_lines)] // Keep the bounded source projection together.
fn normalize_palo_alto_input(
    input: PaloAltoRecordInput,
    row: usize,
    config: &VendorImportConfig,
) -> Result<Option<Observation>, VendorImportError> {
    let record = match input {
        PaloAltoRecordInput::Direct(record) => record,
        PaloAltoRecordInput::Event {
            event,
            time,
            host,
            source,
        } => {
            drop((time, host, source));
            event
        }
    };
    normalize_palo_alto(record, row, config)
}

#[allow(clippy::too_many_lines)] // Keep the bounded source projection together.
fn normalize_palo_alto(
    record: PaloAltoRecord,
    row: usize,
    config: &VendorImportConfig,
) -> Result<Option<Observation>, VendorImportError> {
    let request_client = record
        .user_agent
        .as_deref()
        .and_then(tally_core::RequestClientKind::from_user_agent)
        .map(|name| tally_core::RequestClientObservation {
            name: Some(name),
            agent_id: None,
        });
    let (ai_request_evaluated, ai_request, declared_model_id) =
        ai_request_signature(record.url.as_deref(), None, None);
    let source_identity = palo_source_identity(&record);
    let host = palo_destination_host(&record, row)?;
    drop((
        record.http_headers,
        record.file_url,
        record.user_agent,
        record.threat_payload,
    ));
    let observed_at = parse_time(record.time_generated, row)?;
    let destination_ip = parse_optional_ip(
        record.destination_address.as_deref(),
        row,
        "DestinationAddress",
    )?;
    if host.is_none() && destination_ip.is_none() {
        return Err(VendorImportError::InvalidField {
            row,
            field: "DestinationAddress",
        });
    }
    let source_ip = parse_optional_ip(record.source_address.as_deref(), row, "SourceAddress")?;
    let forwarded_source_ip = parse_optional_ip(
        record.x_forwarded_for_ip.as_deref(),
        row,
        "X-Forwarded-ForIP",
    )?;
    let protocol = optional_token(record.protocol.as_deref(), row, "Protocol")?;
    let action = optional_label(record.action.as_deref(), row, "Action")?;
    let category = optional_label(record.url_category.as_deref(), row, "URLCategory")?;
    let application = optional_label(record.application.as_deref(), row, "Application")?;
    let composed_source_user = source_identity.as_ref().map(|(value, _)| value);
    let identity = composed_source_user
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(|value| config.pseudonymization_key.pseudonym("identity", value));
    let email = composed_source_user
        .map(String::as_str)
        .and_then(recognized_email);
    let source_subject = composed_source_user
        .map(String::as_str)
        .filter(|_| email.is_none())
        .and_then(recognized_subject);
    let source_subject_kind = source_subject
        .as_ref()
        .and_then(|_| source_identity.as_ref().map(|(_, kind)| *kind));
    let endpoint_hostname = record
        .source_device_host
        .as_deref()
        .and_then(normalized_hostname);
    let device = record
        .source_device_host
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| config.pseudonymization_key.pseudonym("device", value));
    let record_id = record.sequence_number.map(|value| value.0);
    let source_record_id = validate_record_id(record_id.as_deref(), row)?;
    let log_type = optional_token(record.log_type.as_deref(), row, "Type")?;
    let safe = SafeRecord {
        request_client,
        observed_at,
        host: host.as_ref().map(Hostname::as_str),
        destination_ip: destination_ip.as_ref().map(IpAddress::as_str),
        destination_port: record.destination_port,
        source_ip: source_ip.as_ref().map(IpAddress::as_str),
        alternate_source_ip: forwarded_source_ip.as_ref().map(IpAddress::as_str),
        identity: identity.as_deref(),
        email: email.as_deref(),
        source_subject: source_subject.as_deref(),
        source_subject_kind,
        device: device.as_deref(),
        hostname: endpoint_hostname.as_deref(),
        protocol: protocol.as_deref(),
        action: action.as_deref(),
        result: log_type.as_deref(),
        category: category.as_deref(),
        application: application.as_deref(),
        bytes_sent: record.bytes_sent,
        bytes_received: record.bytes_received,
        request_count: 1,
        source_record_id: source_record_id.as_deref(),
        ai_request,
        ai_request_evaluated,
        declared_model_id: declared_model_id.as_deref(),
    };
    Ok(Some(observation_from_safe(
        &safe,
        config,
        "palo_alto_strata_https_v1",
        if host.is_some() {
            ObservationKind::HttpMetadata
        } else {
            ObservationKind::NetworkFlow
        },
    )?))
}

fn palo_source_identity(record: &PaloAltoRecord) -> Option<(String, IdentitySubjectKind)> {
    record
        .source_user
        .as_deref()
        .and_then(recognized_subject)
        .map(|value| (value, IdentitySubjectKind::UserName))
        .or_else(|| {
            let name = record.source_user_info_name.as_deref()?.trim();
            let domain = record
                .source_user_info_domain
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let value =
                domain.map_or_else(|| name.to_owned(), |domain| format!("{domain}\\{name}"));
            recognized_subject(&value).map(|value| (value, IdentitySubjectKind::UserName))
        })
        .or_else(|| {
            record
                .source_user_info_uuid
                .as_deref()
                .and_then(recognized_subject)
                .map(|value| (value, IdentitySubjectKind::SourceUserId))
        })
}

fn palo_destination_host(
    record: &PaloAltoRecord,
    row: usize,
) -> Result<Option<Hostname>, VendorImportError> {
    record
        .url_domain
        .as_deref()
        .and_then(normalized_hostname)
        .or_else(|| record.url.as_deref().and_then(extract_url_host))
        .or_else(|| {
            record
                .destination_device_host
                .as_deref()
                .and_then(normalized_hostname)
        })
        .map(|value| parse_host(&value, row))
        .transpose()
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum TimeValue {
    Text(String),
    Integer(i64),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum FlexibleIdValue {
    Text(String),
    Integer(i64),
    Unsigned(u64),
}

#[derive(Debug)]
struct FlexibleId(String);

impl<'de> Deserialize<'de> for FlexibleId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = FlexibleIdValue::deserialize(deserializer)?;
        Ok(Self(match value {
            FlexibleIdValue::Text(value) => value,
            FlexibleIdValue::Integer(value) => value.to_string(),
            FlexibleIdValue::Unsigned(value) => value.to_string(),
        }))
    }
}

#[derive(Serialize)]
struct SafeRecord<'a> {
    request_client: Option<tally_core::RequestClientObservation>,
    observed_at: DateTime<Utc>,
    host: Option<&'a str>,
    destination_ip: Option<&'a str>,
    destination_port: Option<u16>,
    source_ip: Option<&'a str>,
    alternate_source_ip: Option<&'a str>,
    identity: Option<&'a str>,
    email: Option<&'a str>,
    source_subject: Option<&'a str>,
    source_subject_kind: Option<IdentitySubjectKind>,
    device: Option<&'a str>,
    hostname: Option<&'a str>,
    protocol: Option<&'a str>,
    action: Option<&'a str>,
    result: Option<&'a str>,
    category: Option<&'a str>,
    application: Option<&'a str>,
    bytes_sent: Option<u64>,
    bytes_received: Option<u64>,
    request_count: u64,
    source_record_id: Option<&'a str>,
    ai_request: bool,
    ai_request_evaluated: bool,
    declared_model_id: Option<&'a str>,
}

#[allow(clippy::too_many_lines)] // Keep the bounded source projection together.
fn observation_from_safe(
    safe: &SafeRecord<'_>,
    config: &VendorImportConfig,
    connector_type: &'static str,
    kind: ObservationKind,
) -> Result<Observation, VendorImportError> {
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&safe).map_err(|_| VendorImportError::Serialization)?,
    ));
    let stable_part = safe.source_record_id.unwrap_or(&digest);
    let observation_id = Uuid::new_v5(
        &Uuid::NAMESPACE_OID,
        format!("{}:{stable_part}", config.connector_instance_id).as_bytes(),
    );
    let receipt = safe.source_record_id.map_or_else(
        || EvidenceReceipt::RecordDigest {
            algorithm: DigestAlgorithm::Sha256,
            digest: digest.clone(),
        },
        |source_record_id| EvidenceReceipt::CheckpointDigest {
            checkpoint: source_record_id.to_owned(),
            canonical_record_digest: digest.clone(),
        },
    );
    let mut observation = Observation::new(
        config.installation_id,
        safe.observed_at,
        ConnectorRef {
            instance_id: config.connector_instance_id,
            connector_type: connector_type.into(),
            implementation_version: config.implementation_version.clone(),
            source_lineage_id: config.source_lineage_id.clone(),
        },
        kind,
        receipt,
    );
    observation.observation_id = observation_id;
    observation.received_at = config.received_at;
    for (value, role) in [
        (safe.source_ip, tally_core::AddressRole::ObservedSource),
        (
            safe.alternate_source_ip,
            if connector_type.contains("cloudflare") {
                tally_core::AddressRole::Warp
            } else {
                tally_core::AddressRole::Unknown
            },
        ),
    ] {
        if let Some(ip) = value.and_then(|v| IpAddress::parse(v).ok()) {
            observation
                .inventory
                .addresses
                .push(tally_core::AddressObservation {
                    address: ip,
                    role,
                    valid_from: safe.observed_at,
                    valid_until: None,
                    network_key: None,
                });
        }
    }
    observation.inventory.device_key_kind = Some(
        if connector_type.starts_with("zscaler") || connector_type.starts_with("palo_alto") {
            tally_core::DeviceIdentifierKind::HostnameAlias
        } else {
            tally_core::DeviceIdentifierKind::SourceNative
        },
    );
    observation
        .actor
        .request_client
        .clone_from(&safe.request_client);
    observation.actor.source_ip = safe
        .source_ip
        .map(IpAddress::parse)
        .transpose()
        .map_err(|_| VendorImportError::Serialization)?;
    if let Some(alternate_source_ip) = safe
        .alternate_source_ip
        .map(IpAddress::parse)
        .transpose()
        .map_err(|_| VendorImportError::Serialization)?
        .filter(|value| observation.actor.source_ip.as_ref() != Some(value))
    {
        observation
            .actor
            .additional_source_ips
            .push(alternate_source_ip);
    }
    observation.actor.device_key = safe.device.map(str::to_owned);
    observation.actor.hostname = safe.hostname.map(str::to_owned);
    observation.actor.identity =
        safe.identity
            .or(safe.email)
            .or(safe.source_subject)
            .map(|subject| {
                let subject_key = safe.identity.map_or_else(
                    || config.pseudonymization_key.pseudonym("identity", subject),
                    str::to_owned,
                );
                IdentityObservation {
                    subject_key,
                    email: safe.email.map(str::to_owned),
                    source_subject: safe.source_subject.map(str::to_owned),
                    source_subject_kind: safe.source_subject_kind,
                    authority: None,
                    directory_key: None,
                    application_key: None,
                    display_label: None,
                }
            });
    observation.destination.host = safe
        .host
        .map(Hostname::parse)
        .transpose()
        .map_err(|_| VendorImportError::Serialization)?;
    observation.destination.ip = safe
        .destination_ip
        .map(IpAddress::parse)
        .transpose()
        .map_err(|_| VendorImportError::Serialization)?;
    observation.destination.port = safe.destination_port;
    observation.network.protocol = safe.protocol.map(str::to_owned);
    observation.network.request_count = Some(safe.request_count);
    observation.network.bytes_sent = safe.bytes_sent;
    observation.network.bytes_received = safe.bytes_received;
    observation.outcome.action = safe.action.map(str::to_owned);
    observation.outcome.result = safe.result.map(str::to_owned);
    observation.service.source_category = safe.category.map(str::to_owned);
    observation.service.vendor_application_id = safe.application.map(str::to_owned);
    observation.service.ai_request = safe.ai_request;
    observation.service.ai_request_evaluated = safe.ai_request_evaluated;
    observation.service.declared_model_id = safe.declared_model_id.map(str::to_owned);
    Ok(observation)
}

fn parse_ndjson<T: DeserializeOwned>(input: &[u8]) -> Result<Vec<T>, VendorImportError> {
    check_import_size(input)?;
    if input
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| *byte == b'[')
    {
        let values: Vec<serde_json::Value> = serde_json::from_slice(input)
            .map_err(|_| VendorImportError::MalformedRecord { row: 1 })?;
        if values.len() > MAX_BATCH_OBSERVATIONS {
            return Err(VendorImportError::Admission(AdmissionError::BatchTooLarge(
                values.len(),
            )));
        }
        return values
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                if serde_json::to_vec(&value).map_or(true, |bytes| bytes.len() > MAX_RECORD_BYTES) {
                    return Err(VendorImportError::RecordTooLarge { row: index + 1 });
                }
                serde_json::from_value(value)
                    .map_err(|_| VendorImportError::MalformedRecord { row: index + 1 })
            })
            .collect();
    }
    input
        .split(|byte| *byte == b'\n')
        .enumerate()
        .filter(|(_, line)| !line.iter().all(u8::is_ascii_whitespace))
        .map(|(index, line)| {
            if line.len() > MAX_RECORD_BYTES {
                return Err(VendorImportError::RecordTooLarge { row: index + 1 });
            }
            serde_json::from_slice(line)
                .map_err(|_| VendorImportError::MalformedRecord { row: index + 1 })
        })
        .collect()
}

fn check_import_size(input: &[u8]) -> Result<(), VendorImportError> {
    if input.len() > MAX_IMPORT_BYTES {
        return Err(VendorImportError::ImportTooLarge(input.len()));
    }
    Ok(())
}

fn parse_time(value: TimeValue, row: usize) -> Result<DateTime<Utc>, VendorImportError> {
    match value {
        TimeValue::Text(value) if value.parse::<i64>().is_ok() => parse_time(
            TimeValue::Integer(
                value
                    .parse()
                    .map_err(|_| VendorImportError::InvalidTimestamp { row })?,
            ),
            row,
        ),
        TimeValue::Text(value) => DateTime::parse_from_rfc3339(value.trim())
            .map(|value| value.with_timezone(&Utc))
            .map_err(|_| VendorImportError::InvalidTimestamp { row }),
        TimeValue::Integer(value) => {
            let timestamp = if value.unsigned_abs() >= 100_000_000_000_000_000 {
                Some(DateTime::from_timestamp_nanos(value))
            } else if value.unsigned_abs() >= 100_000_000_000_000 {
                DateTime::from_timestamp_micros(value)
            } else if value.unsigned_abs() >= 100_000_000_000 {
                DateTime::from_timestamp_millis(value)
            } else {
                DateTime::from_timestamp(value, 0)
            };
            timestamp.ok_or(VendorImportError::InvalidTimestamp { row })
        }
    }
}

fn parse_host(value: &str, row: usize) -> Result<Hostname, VendorImportError> {
    Hostname::parse(value).map_err(|_| VendorImportError::InvalidField { row, field: "host" })
}

fn parse_optional_ip(
    value: Option<&str>,
    row: usize,
    field: &'static str,
) -> Result<Option<IpAddress>, VendorImportError> {
    value
        .filter(|value| !value.trim().is_empty())
        .map(IpAddress::parse)
        .transpose()
        .map_err(|_| VendorImportError::InvalidField { row, field })
}

fn normalized_hostname(value: &str) -> Option<String> {
    Hostname::parse(value)
        .ok()
        .map(|hostname| hostname.as_str().to_owned())
}

/// Recognizes only bounded, protocol-level model request shapes and returns the public model
/// reference when one is present. Source content is inspected in this stack frame and discarded;
/// neither the body nor a body digest is copied into the observation.
fn ai_request_signature(
    url: Option<&str>,
    request_content: Option<&str>,
    response_content: Option<&str>,
) -> (bool, bool, Option<String>) {
    let evaluated = url.is_some_and(http_request_material_available)
        || request_content.is_some_and(|value| !value.trim().is_empty())
        || response_content.is_some_and(|value| !value.trim().is_empty());
    let path_match = url.is_some_and(ai_request_path);
    let model = request_content
        .and_then(ai_model_from_json)
        .or_else(|| response_content.and_then(ai_model_from_json));
    (evaluated, path_match || model.is_some(), model)
}

fn http_request_material_available(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    if let Ok(url) = Url::parse(value) {
        return url.path() != "/" || url.query().is_some();
    }
    let without_fragment = value.split('#').next().unwrap_or(value);
    if without_fragment.contains('?') {
        return true;
    }
    let path = if let Some(path) = without_fragment.strip_prefix('/') {
        path
    } else {
        without_fragment
            .split_once('/')
            .map_or("", |(_, path)| path)
    };
    !path.trim_matches('/').is_empty()
}

fn ai_request_path(value: &str) -> bool {
    let path = Url::parse(value).ok().map_or_else(
        || value.split(['?', '#']).next().unwrap_or(value).to_owned(),
        |url| url.path().to_owned(),
    );
    let path = path.trim_end_matches('/').to_ascii_lowercase();
    [
        "/chat/completions",
        "/v1/chat/completions",
        "/v1/responses",
        "/v1/messages",
        "/v1/completions",
        "/v1/embeddings",
        "/v1/images/generations",
        "/v1/audio/transcriptions",
        "/v1/audio/speech",
        "/api/chat",
        "/api/generate",
        "/api/embed",
    ]
    .iter()
    .any(|signature| path == *signature || path.ends_with(signature))
        || (path.contains("/models/")
            && [":generatecontent", ":streamgeneratecontent", ":predict"]
                .iter()
                .any(|suffix| path.ends_with(suffix)))
}

fn ai_model_from_json(value: &str) -> Option<String> {
    const MAX_INSPECTED_CONTENT_BYTES: usize = 64 * 1024;
    if value.is_empty() || value.len() > MAX_INSPECTED_CONTENT_BYTES {
        return None;
    }
    let parsed: serde_json::Value = serde_json::from_str(value).ok()?;
    ai_model_from_object(parsed.as_object()?).or_else(|| {
        parsed
            .get("request")
            .and_then(serde_json::Value::as_object)
            .and_then(ai_model_from_object)
    })
}

fn ai_model_from_object(object: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    let has_ai_shape = [
        "messages",
        "prompt",
        "input",
        "tools",
        "max_tokens",
        "max_completion_tokens",
        "choices",
        "output",
        "candidates",
        "usage",
    ]
    .iter()
    .any(|key| object.contains_key(*key))
        || object
            .get("object")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| matches!(value, "chat.completion" | "response" | "list"));
    if !has_ai_shape {
        return None;
    }
    object
        .get("model")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|model| {
            !model.is_empty() && model.len() <= 512 && !model.chars().any(char::is_control)
        })
        .map(str::to_owned)
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

fn recognized_subject(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return None;
    }
    Some(value.to_owned())
}

fn optional_token(
    value: Option<&str>,
    row: usize,
    field: &'static str,
) -> Result<Option<String>, VendorImportError> {
    value
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            let value = value.trim();
            if value.len() > 64
                || !value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/')
                })
            {
                Err(VendorImportError::InvalidField { row, field })
            } else {
                Ok(value.to_ascii_lowercase())
            }
        })
        .transpose()
}

fn optional_label(
    value: Option<&str>,
    row: usize,
    field: &'static str,
) -> Result<Option<String>, VendorImportError> {
    value
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            let value = value.trim();
            if value.len() > 128
                || !value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b' ' | b'_' | b'-' | b'.' | b'/' | b'&' | b':')
                })
            {
                Err(VendorImportError::InvalidField { row, field })
            } else {
                Ok(value.to_owned())
            }
        })
        .transpose()
}

fn validate_record_id(
    value: Option<&str>,
    row: usize,
) -> Result<Option<String>, VendorImportError> {
    value
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            let value = value.trim();
            if value.len() > 160
                || !value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
                })
            {
                Err(VendorImportError::InvalidField {
                    row,
                    field: "record_id",
                })
            } else {
                Ok(value.to_owned())
            }
        })
        .transpose()
}

fn extract_url_host(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let authority = trimmed
        .split_once("://")
        .map_or(trimmed, |(_, remainder)| remainder)
        .split(['/', '?', '#'])
        .next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    if authority.starts_with('[') {
        return None;
    }
    Some(authority.split(':').next()?.to_owned())
}

#[derive(Debug, Error)]
pub enum VendorImportError {
    #[error("pseudonymization key must contain exactly 32 bytes")]
    InvalidPseudonymizationKey,
    #[error("vendor import contains no records")]
    NoRecords,
    #[error("vendor import contains no accepted records")]
    NoAcceptedRecords,
    #[error("vendor import is {0} bytes; maximum is {MAX_IMPORT_BYTES}")]
    ImportTooLarge(usize),
    #[error("vendor import record {row} exceeds the safe size limit")]
    RecordTooLarge { row: usize },
    #[error("vendor import record {row} is malformed")]
    MalformedRecord { row: usize },
    #[error("vendor import record {row} has an invalid timestamp")]
    InvalidTimestamp { row: usize },
    #[error("vendor import record {row} has invalid {field} metadata")]
    InvalidField { row: usize, field: &'static str },
    #[error("vendor import record could not be normalized")]
    Serialization,
    #[error(transparent)]
    Admission(#[from] AdmissionError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct GoldenObservation {
        host: Option<String>,
        source_ip: Option<String>,
        protocol: Option<String>,
        action: Option<String>,
        result: Option<String>,
        identity_pseudonymized: bool,
        device_pseudonymized: bool,
        destination_ip: Option<String>,
        destination_port: Option<u16>,
        category: Option<String>,
        application: Option<String>,
        bytes_sent: Option<u64>,
        bytes_received: Option<u64>,
    }

    #[derive(Debug, Deserialize)]
    struct RedactionAssertions {
        must_not_contain: Vec<String>,
        must_contain: Vec<String>,
    }

    fn config() -> VendorImportConfig {
        VendorImportConfig {
            installation_id: Uuid::parse_str("018f6cd4-4aaf-7bb4-a3b2-a7524ec43711").expect("UUID"),
            connector_instance_id: Uuid::parse_str("018f6cd4-4aaf-7bb4-a3b2-a7524ec43731")
                .expect("UUID"),
            implementation_version: "1.0.0".into(),
            source_lineage_id: Some("fixture".into()),
            received_at: "2026-08-13T10:05:00Z".parse().expect("timestamp"),
            checkpoint: Cursor("fixture-window".into()),
            pseudonymization_key: PseudonymizationKey::new(&[7; 32]).expect("key"),
        }
    }

    #[test]
    fn cloudflare_network_sessions_keep_directional_bytes_and_private_fields_out() {
        let input = br#"{"SessionID":"session-1","SessionEndTime":"1786615500000000000","SNI":"api.openai.com","OriginIP":"203.0.113.34","OriginPort":443,"SourceInternalIP":"100.96.0.2","DeviceName":"LAPTOP-42","Email":"person@example.com","Protocol":"TCP","BytesSent":"0","BytesReceived":512,"request_body":"CONTENT_CANARY"}"#;
        for import in [
            import_cloudflare_gateway_ndjson,
            import_cloudflare_gateway_logpush_s3_ndjson,
            import_cloudflare_zero_trust_gateway_ndjson,
        ] {
            let first = import(input, &config()).expect("network session");
            let repeated = import(input, &config()).expect("replay");
            let observation = &first.batch.observations[0];
            assert_eq!(
                observation.observation_id,
                repeated.batch.observations[0].observation_id
            );
            assert_eq!(observation.network.bytes_sent, Some(0));
            assert_eq!(observation.network.bytes_received, Some(512));
            assert_eq!(observation.network.request_count, None);
            assert_eq!(observation.network.protocol.as_deref(), Some("tcp"));
            assert_eq!(observation.kind, ObservationKind::NetworkFlow);
            assert_eq!(observation.observed_at, config().received_at);
            assert_eq!(observation.actor.hostname.as_deref(), Some("laptop-42"));
            assert!(
                !serde_json::to_string(&first)
                    .expect("projection")
                    .contains("CONTENT_CANARY")
            );
        }
        let missing = br#"{"SessionID":"session-2","SessionEndTime":"2026-08-13T10:05:00Z","ResolvedFQDN":"api.openai.com"}"#;
        assert_eq!(
            import_cloudflare_gateway_logpush_s3_ndjson(missing, &config())
                .expect("unknown counters")
                .batch
                .observations[0]
                .network
                .bytes_sent,
            None
        );
        let http = br#"{"RequestID":"request-1","Datetime":"2026-08-13T10:05:00Z","HTTPHost":"api.openai.com","BlockedFileSize":4000,"RequestCount":2}"#;
        assert_eq!(
            import_cloudflare_gateway_logpush_s3_ndjson(http, &config())
                .expect("HTTP metadata")
                .batch
                .observations[0]
                .network
                .bytes_sent,
            None
        );
    }

    #[test]
    fn vendor_byte_counters_accept_feed_strings_without_conflating_missing_and_zero() {
        for sent in [
            serde_json::json!(0),
            serde_json::json!("0"),
            serde_json::json!("4096"),
            serde_json::Value::Null,
        ] {
            let expected = match &sent {
                serde_json::Value::String(value) => value.parse().ok(),
                value => value.as_u64(),
            };
            let zscaler = serde_json::to_vec(&serde_json::json!({"time":"2026-08-13T10:05:00Z","host":"api.openai.com","reqsize":sent,"respsize":"512"})).expect("fixture");
            let palo = serde_json::to_vec(&serde_json::json!({"time_generated":"2026-08-13T10:05:00Z","URLDomain":"api.openai.com","bytes_sent":sent,"bytes_recv":"512"})).expect("fixture");
            let z = import_zscaler_ndjson(&zscaler, &config()).expect("NSS string counters");
            let p =
                import_palo_alto_ndjson(&palo, &config()).expect("firewall snake-case counters");
            for outcome in [z, p] {
                assert_eq!(outcome.batch.observations[0].network.bytes_sent, expected);
                assert_eq!(
                    outcome.batch.observations[0].network.bytes_received,
                    Some(512)
                );
            }
        }
        for bad in [
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!("18446744073709551616"),
        ] {
            let input = serde_json::to_vec(&serde_json::json!({"time":"2026-08-13T10:05:00Z","host":"api.openai.com","reqsize":bad})).expect("fixture");
            assert!(import_zscaler_ndjson(&input, &config()).is_err());
        }
    }

    #[test]
    fn pseudonymization_is_stable_scoped_and_redacted_in_debug() {
        let key = PseudonymizationKey::new(&[7; 32]).expect("key");
        assert_eq!(
            key.pseudonym("device", " Laptop-A "),
            key.pseudonym("device", "laptop-a")
        );
        assert_ne!(
            key.pseudonym("device", "laptop-a"),
            key.pseudonym("identity", "laptop-a")
        );
        assert!(!format!("{key:?}").contains("0707"));
        let hex_file = format!("{}\n", "07".repeat(32));
        assert_eq!(
            PseudonymizationKey::parse_file(hex_file.as_bytes()).expect("hex"),
            key
        );
    }

    #[test]
    fn nextdns_discards_labels_reasons_and_canary() {
        let input = b"timestamp,domain,query_type,dnssec,protocol,client_ip,status,reasons,destination_country,root_domain,device_id,device_name,device_model,device_local_ip,matched_name,client_name,prompt\n2026-08-13T10:00:00Z,api.openai.com,A,true,DNS-over-HTTPS,203.0.113.8,allowed,ULTRA_SECRET_PROMPT_CANARY,US,openai.com,dev-1,Jane Laptop,MacBook,10.0.0.2,api.openai.com,nextdns-ios,ULTRA_SECRET_PROMPT_CANARY\n";
        let outcome = import_nextdns_csv(input, &config()).expect("normalize");
        let serialized = serde_json::to_string(&outcome).expect("serialize");
        assert!(!serialized.contains("ULTRA_SECRET_PROMPT_CANARY"));
        assert!(!serialized.contains("Jane Laptop"));
        assert!(serialized.contains("p1_"));
    }

    #[test]
    fn nextdns_api_page_is_normalized_and_privacy_bounded() {
        let input = br#"{
            "data": [{
                "timestamp": "2026-08-13T10:00:10.338Z",
                "domain": "api.openai.com",
                "root": "openai.com",
                "tracker": "ULTRA_SECRET_PROMPT_CANARY",
                "encrypted": true,
                "protocol": "DNS-over-HTTPS",
                "clientIp": "203.0.113.8",
                "client": "private-profile-label",
                "device": {
                    "id": "device-1",
                    "name": "Jane's laptop",
                    "model": "MacBook Pro",
                    "localIp": "10.0.0.8"
                },
                "status": "default",
                "reasons": [{"name": "ULTRA_SECRET_PROMPT_CANARY"}]
            }],
            "meta": {"pagination": {"cursor": "j2k3zl3b4v"}}
        }"#;
        let metadata = inspect_nextdns_api_page(input).expect("metadata");
        assert_eq!(metadata.record_count, 1);
        assert_eq!(metadata.next_page_cursor.as_deref(), Some("j2k3zl3b4v"));
        assert_eq!(
            metadata.last_observed_at,
            Some("2026-08-13T10:00:10.338Z".parse().expect("timestamp"))
        );

        let outcome = import_nextdns_api_json(input, &config()).expect("normalize");
        let serialized = serde_json::to_string(&outcome).expect("serialize");
        assert!(serialized.contains("api.openai.com"));
        assert!(serialized.contains("p1_"));
        for discarded in [
            "ULTRA_SECRET_PROMPT_CANARY",
            "private-profile-label",
            "Jane's laptop",
            "MacBook Pro",
        ] {
            assert!(!serialized.contains(discarded));
        }
        assert!(serialized.contains("10.0.0.8"));
        assert_eq!(outcome.redaction.connector_type, "nextdns_logs_api_v1");
        assert!(!outcome.redaction.source_bytes_retained);
    }

    #[test]
    fn nextdns_api_cursor_rejects_unsafe_source_metadata() {
        let input = br#"{
            "data": [{"timestamp":"2026-08-13T10:00:00Z","domain":"example.com"}],
            "meta": {"pagination": {"cursor": "cursor/with/query?content=1"}}
        }"#;
        assert!(matches!(
            inspect_nextdns_api_page(input),
            Err(VendorImportError::InvalidField {
                field: "meta.pagination.cursor",
                ..
            })
        ));
    }

    #[test]
    fn cloudflare_root_query_is_ignored_and_endpoint_email_is_retained() {
        let input = b"{\"Datetime\":\"2026-08-13T10:00:00Z\",\"QueryID\":\"q-1\",\"QueryName\":\".\"}\n{\"Datetime\":\"2026-08-13T10:00:01Z\",\"QueryID\":\"q-2\",\"QueryName\":\"api.anthropic.com\",\"Email\":\"person@example.com\",\"DeviceName\":\"ULTRA_SECRET_PROMPT_CANARY\"}\n{\"Datetime\":\"2026-08-13T10:00:02Z\",\"QueryID\":\"q-3\",\"QueryName\":\"api.openai.com\",\"Email\":\"not-an-email\"}\n";
        let outcome = import_cloudflare_gateway_ndjson(input, &config()).expect("normalize");
        assert_eq!(outcome.stats.ignored, 1);
        assert_eq!(outcome.stats.accepted, 2);
        let serialized = serde_json::to_string(&outcome).expect("serialize");
        assert!(serialized.contains("person@example.com"));
        assert!(!serialized.contains("ULTRA_SECRET_PROMPT_CANARY"));
    }

    #[test]
    fn cloudflare_dns_retains_documented_destination_endpoint_fields() {
        let input = br#"{"Datetime":"2026-08-13T10:00:00Z","QueryID":"q-dst-1","QueryName":"chatgpt.com","SrcIP":"10.0.0.8","DstIP":"203.0.113.53","DstPort":53}"#;
        let outcome = import_cloudflare_gateway_ndjson(input, &config()).expect("normalize");
        let observation = &outcome.batch.observations[0];
        assert_eq!(
            observation.destination.ip.as_ref().map(IpAddress::as_str),
            Some("203.0.113.53")
        );
        assert_eq!(observation.destination.port, Some(53));
    }

    #[test]
    fn cloudflare_http_logpush_keeps_actor_context_and_only_marks_ai_paths() {
        let input = br#"{"Datetime":"2026-08-13T10:00:00Z","RequestID":"r-1","HTTPHost":"api.openai.com","URL":"https://api.openai.com/v1/responses?prompt=ULTRA_SECRET_PROMPT_CANARY","DestinationIP":"203.0.113.10","SourceInternalIP":"10.0.0.8","SourceIP":"198.51.100.8","DeviceID":"device-1","DeviceName":"LAPTOP-42","Email":"person@example.com","HTTPMethod":"POST","Action":"allow"}
{"Datetime":"2026-08-13T10:00:01Z","RequestID":"r-2","HTTPHost":"sentry.example.com","URL":"https://sentry.example.com/api/123/store","SourceIP":"10.0.0.9","DeviceName":"LAPTOP-43","HTTPMethod":"POST","Action":"allow"}
"#;
        let outcome = import_cloudflare_gateway_ndjson(input, &config()).expect("normalize");
        assert_eq!(outcome.stats.accepted, 2);
        let ai = outcome
            .batch
            .observations
            .iter()
            .find(|observation| {
                observation
                    .destination
                    .host
                    .as_ref()
                    .is_some_and(|host| host.as_str() == "api.openai.com")
            })
            .expect("AI request");
        assert_eq!(ai.kind, ObservationKind::HttpMetadata);
        assert!(ai.service.ai_request);
        assert_eq!(ai.actor.hostname.as_deref(), Some("laptop-42"));
        assert_eq!(
            ai.actor
                .identity
                .as_ref()
                .and_then(|identity| identity.email.as_deref()),
            Some("person@example.com")
        );
        assert_eq!(
            ai.actor.source_ip.as_ref().map(IpAddress::as_str),
            Some("198.51.100.8")
        );
        assert_eq!(
            ai.actor
                .additional_source_ips
                .iter()
                .map(IpAddress::as_str)
                .collect::<Vec<_>>(),
            vec!["10.0.0.8"]
        );
        assert!(outcome.batch.observations.iter().any(|observation| {
            observation
                .destination
                .host
                .as_ref()
                .is_some_and(|host| host.as_str() == "sentry.example.com")
                && observation.service.ai_request_evaluated
                && !observation.service.ai_request
        }));
        let serialized = serde_json::to_string(&outcome).expect("serialize");
        assert!(!serialized.contains("/v1/responses"));
        assert!(!serialized.contains("ULTRA_SECRET_PROMPT_CANARY"));
    }

    #[test]
    fn cloudflare_http_snake_case_retains_actionable_user_and_device_addresses() {
        let input = br#"{"session_id":"00000000000000000000000000000001","datetime":1788443425,"request_id":"00000000000000000000000000000002","user_id":"00000000-0000-4000-8000-000000000001","email":"person@example.com","device_id":"00000000-0000-4000-8000-000000000002","action":1,"action_name":"allow","http_host":"chat.z.ai","http_method":2,"http_method_name":"POST","url":"https://chat.z.ai/api/v2/chat/completions?discarded=true","source_ip":"198.51.100.8","source_internal_ip":"100.96.0.2","destination_ip":"203.0.113.34","destination_port":443}"#;
        let _: CloudflareHttpRecord =
            serde_json::from_slice(input).expect("snake_case HTTP record shape");
        let _: CloudflareRecordInput =
            serde_json::from_slice(input).expect("snake_case Gateway record shape");
        let outcome = import_cloudflare_gateway_ndjson(input, &config()).expect("normalize");
        let observation = &outcome.batch.observations[0];
        assert!(observation.service.ai_request);
        assert_eq!(
            observation
                .actor
                .identity
                .as_ref()
                .and_then(|identity| identity.email.as_deref()),
            Some("person@example.com")
        );
        assert_eq!(
            observation.actor.source_ip.as_ref().map(IpAddress::as_str),
            Some("198.51.100.8")
        );
        assert_eq!(
            observation
                .actor
                .additional_source_ips
                .iter()
                .map(IpAddress::as_str)
                .collect::<Vec<_>>(),
            vec!["100.96.0.2"]
        );
        assert_eq!(observation.destination.port, Some(443));
        let serialized = serde_json::to_string(&outcome).expect("serialize");
        assert!(!serialized.contains("discarded=true"));
    }

    #[test]
    fn cloudflare_gateway_http_logpush_uses_s3_connector_type() {
        let input = br#"{"datetime":"2026-09-03T13:50:22.942Z","requestid":"request-1","userid":"user-1","email":"person@example.com","deviceid":"device-1","devicename":"LAPTOP-42","action":"allow","httphost":"api.openai.com","httpmethod":"POST","url":"https://api.openai.com/v1/responses?discarded=true","sourceip":"198.51.100.8","sourceinternalip":"100.96.0.2","destinationip":"203.0.113.34","destinationport":443}"#;
        let outcome = import_cloudflare_gateway_logpush_s3_ndjson(input, &config())
            .expect("normalize Gateway HTTP Logpush record");
        let observation = &outcome.batch.observations[0];
        assert_eq!(
            observation.connector.connector_type,
            "cloudflare_gateway_http_logpush_s3_v1"
        );
        assert_eq!(
            observation
                .actor
                .identity
                .as_ref()
                .and_then(|identity| identity.email.as_deref()),
            Some("person@example.com")
        );
        assert_eq!(observation.actor.hostname.as_deref(), Some("laptop-42"));
        assert_eq!(
            outcome.redaction.connector_type,
            observation.connector.connector_type
        );
        assert!(
            !serde_json::to_string(&outcome)
                .expect("serialize")
                .contains("discarded=true")
        );
    }

    #[test]
    fn cloudflare_gateway_s3_descriptor_supports_http_and_network_sessions() {
        let descriptor = cloudflare_gateway_logpush_s3_descriptor();
        assert_eq!(descriptor.transport, ConnectorTransport::Pull);
        assert!(
            descriptor
                .required_permissions
                .iter()
                .any(|permission| permission.contains("gateway_http"))
        );
        assert!(
            descriptor
                .requested_fields
                .iter()
                .any(|field| field == "DeviceID and DeviceName")
        );
        assert!(
            descriptor
                .requested_fields
                .iter()
                .all(|field| !field.contains("QueryName"))
        );
    }

    #[test]
    fn cloudflare_zero_trust_gateway_combines_api_counts_and_optional_logpush() {
        let input = br#"{"TallySource":"graphql_dns","Datetime":"2026-09-03T13:49:00Z","QueryName":"api.openai.com","ResolverDecision":"allowed_rule","RequestCount":37}
{"TallySource":"graphql_http","Datetime":"2026-09-03T13:50:00Z","Email":"person@example.com","UserID":"user-1","DeviceID":"device-1","HTTPHost":"api.openai.com","SourceInternalIP":"100.96.0.2","ActionName":"allow","RequestCount":247}
{"Datetime":"2026-09-03T13:50:22Z","RequestID":"request-1","Email":"person@example.com","DeviceName":"LAPTOP-42","HTTPHost":"api.openai.com","URL":"https://api.openai.com/v1/responses?discarded=true","SourceInternalIP":"100.96.0.2","DestinationPort":443}
"#;
        let outcome = import_cloudflare_zero_trust_gateway_ndjson(input, &config())
            .expect("combined Gateway projection");
        assert_eq!(outcome.stats.accepted, 3);
        let dns = outcome
            .batch
            .observations
            .iter()
            .find(|observation| observation.kind == ObservationKind::DnsQuery)
            .expect("DNS aggregate");
        assert_eq!(dns.network.request_count, Some(37));
        assert!(dns.actor.identity.is_none());
        let http = outcome
            .batch
            .observations
            .iter()
            .find(|observation| observation.network.request_count == Some(247))
            .expect("HTTP aggregate");
        assert_eq!(http.actor.hostname, None);
        assert!(http.actor.device_key.is_some());
        assert_eq!(
            http.actor
                .identity
                .as_ref()
                .and_then(|identity| identity.email.as_deref()),
            Some("person@example.com")
        );
        assert!(
            http.actor
                .additional_source_ips
                .iter()
                .any(|address| address.as_str() == "100.96.0.2")
        );
        assert_eq!(
            http.destination.host.as_ref().map(Hostname::as_str),
            Some("api.openai.com")
        );
        assert!(!http.service.ai_request_evaluated);
        let logpush = outcome
            .batch
            .observations
            .iter()
            .find(|observation| observation.actor.hostname.as_deref() == Some("laptop-42"))
            .expect("Logpush HTTP event");
        assert!(logpush.service.ai_request);
        let serialized = serde_json::to_string(&outcome).expect("serialize");
        assert!(!serialized.contains("discarded=true"));
        assert_eq!(
            outcome.redaction.connector_type,
            "cloudflare_zero_trust_gateway_v1"
        );
    }

    #[test]
    fn cloudflare_zero_trust_gateway_rejects_untrusted_aggregate_discriminators() {
        let input = br#"{"TallySource":"other_http","Datetime":"2026-09-03T13:50:00Z","HTTPHost":"api.openai.com","RequestCount":1}
"#;
        assert!(import_cloudflare_zero_trust_gateway_ndjson(input, &config()).is_err());
    }

    #[test]
    fn cloudflare_gateway_http_logpush_rejects_the_ai_gateway_dataset_shape() {
        let input = br#"{"id":"log-1","created_at":"2026-09-03T13:50:22.942Z","provider":"openai","model":"gpt-5"}"#;
        assert!(import_cloudflare_gateway_logpush_s3_ndjson(input, &config()).is_err());
    }

    #[test]
    fn zscaler_strips_url_path_and_content_fields() {
        let input = b"{\"time\":1786615200,\"record_id\":\"z-1\",\"login\":\"person@example.com\",\"device_hostname\":\"laptop-1\",\"url\":\"https://api.openai.com/v1/chat?prompt=ULTRA_SECRET_PROMPT_CANARY\",\"action\":\"Allowed\",\"protocol\":\"HTTPS\",\"request_content\":\"ULTRA_SECRET_PROMPT_CANARY\"}\n";
        let outcome = import_zscaler_ndjson(input, &config()).expect("normalize");
        let serialized = serde_json::to_string(&outcome).expect("serialize");
        assert!(serialized.contains("api.openai.com"));
        assert!(!serialized.contains("/v1/chat"));
        assert!(!serialized.contains("ULTRA_SECRET_PROMPT_CANARY"));
        assert!(serialized.contains("person@example.com"));
        assert!(serialized.contains("laptop-1"));
        assert!(!outcome.batch.observations[0].service.ai_request);
    }

    #[test]
    fn zscaler_marks_a_model_request_body_without_retaining_it() {
        let input = br#"{"time":1786615200,"record_id":"z-ai-1","url":"https://gateway.example.com/proxy","action":"Allowed","protocol":"HTTPS","request_content":"{\"model\":\"gpt-5\",\"messages\":[{\"role\":\"user\",\"content\":\"BODY_CANARY\"}]}"}
"#;
        let outcome = import_zscaler_ndjson(input, &config()).expect("normalize");
        let observation = &outcome.batch.observations[0];
        assert!(observation.service.ai_request);
        assert_eq!(
            observation.service.declared_model_id.as_deref(),
            Some("gpt-5")
        );
        let serialized = serde_json::to_string(&outcome).expect("serialize");
        assert!(!serialized.contains("BODY_CANARY"));
        assert!(!serialized.contains("messages"));
    }

    #[test]
    fn http_signature_distinguishes_domain_only_from_checked_regular_requests() {
        assert_eq!(
            ai_request_signature(Some("api.openai.com"), None, None),
            (false, false, None)
        );
        assert_eq!(
            ai_request_signature(Some("https://api.openai.com/health"), None, None),
            (true, false, None)
        );
        assert_eq!(
            ai_request_signature(Some("https://api.openai.com/v1/responses"), None, None),
            (true, true, None)
        );
    }

    #[test]
    fn zscaler_accepts_cloud_nss_json_array_event_wrappers() {
        let input = br#"[
            {"sourcetype":"zscalernss-web","event":{"time":1786615200,"recordid":"z-1","login":"person@example.com","url":"https://api.openai.com/v1/chat?prompt=ULTRA_SECRET_PROMPT_CANARY","action":"Allowed","urlclass":"AI and ML","clientip":"10.0.0.8"}}
        ]"#;
        let outcome = import_zscaler_ndjson(input, &config()).expect("Cloud NSS JSON array");
        assert_eq!(outcome.stats.accepted, 1);
        let serialized = serde_json::to_string(&outcome).expect("serialize");
        assert!(serialized.contains("api.openai.com"));
        assert!(!serialized.contains("zscalernss-web"));
        assert!(serialized.contains("person@example.com"));
        assert!(!outcome.batch.observations[0].service.ai_request);
        assert!(!serialized.contains("ULTRA_SECRET_PROMPT_CANARY"));
    }

    #[test]
    fn zscaler_accepts_documented_nss_field_tokens() {
        let input = br#"{"time":1786615200,"recordid":"z-2","login":"CORP\\alice","devicehostname":"LAPTOP-42","host":"api.openai.com","proto":"HTTPS","cip":"10.0.0.8","cintip":"198.51.100.8","sip":"203.0.113.10","srv_dport":443,"reqsize":128,"respsize":512,"action":"Allowed"}"#;
        let _: ZscalerRecord = serde_json::from_slice(input).expect("Zscaler record shape");
        let outcome = import_zscaler_ndjson(input, &config()).expect("NSS field tokens");
        let observation = &outcome.batch.observations[0];
        assert_eq!(observation.actor.hostname.as_deref(), Some("laptop-42"));
        assert_eq!(observation.destination.port, Some(443));
        assert_eq!(observation.network.bytes_sent, Some(128));
        assert_eq!(observation.network.bytes_received, Some(512));
        assert_eq!(
            observation
                .actor
                .additional_source_ips
                .iter()
                .map(IpAddress::as_str)
                .collect::<Vec<_>>(),
            vec!["198.51.100.8"]
        );
        assert_eq!(
            observation
                .actor
                .identity
                .as_ref()
                .and_then(|identity| identity.source_subject.as_deref()),
            Some("CORP\\alice")
        );
    }

    #[test]
    fn zscaler_accepts_documented_elastic_eurl_actor_fields() {
        let input = br#"{"time":1786615200,"login":"person@example.com","eurl":"https://api.openai.com/v1/responses","proto":"HTTPS","cip":"10.0.0.8","sip":"203.0.113.10","deviceowner":"person@example.com","devicehostname":"LAPTOP-42","dept":"Engineering","ua":"discard-me","action":"Allowed"}"#;
        let outcome = import_zscaler_ndjson(input, &config()).expect("Elastic NSS fields");
        let observation = &outcome.batch.observations[0];
        assert_eq!(
            observation.destination.host.as_ref().map(Hostname::as_str),
            Some("api.openai.com")
        );
        assert_eq!(observation.actor.hostname.as_deref(), Some("laptop-42"));
        assert_eq!(
            observation
                .actor
                .identity
                .as_ref()
                .and_then(|identity| identity.email.as_deref()),
            Some("person@example.com")
        );
        assert!(observation.service.ai_request);
        assert!(
            !serde_json::to_string(&outcome)
                .expect("serialize")
                .contains("discard-me")
        );
    }

    #[test]
    fn palo_alto_url_and_headers_never_survive() {
        let input = b"{\"TimeGenerated\":1786615200000000,\"SequenceNumber\":7003061085139304175,\"Type\":\"url\",\"SourceAddress\":\"10.0.0.7\",\"DestinationAddress\":\"203.0.113.10\",\"DestinationPort\":443,\"SourceUser\":\"person@example.com\",\"URL\":\"api.anthropic.com/v1/messages?prompt=ULTRA_SECRET_PROMPT_CANARY\",\"Application\":\"ssl\",\"URLCategory\":\"AI and ML\",\"Protocol\":\"tcp\",\"Action\":\"allow\",\"HTTPHeaders\":\"Authorization: ULTRA_SECRET_PROMPT_CANARY\"}\n";
        let outcome = import_palo_alto_ndjson(input, &config()).expect("normalize");
        let serialized = serde_json::to_string(&outcome).expect("serialize");
        assert!(serialized.contains("api.anthropic.com"));
        assert!(!serialized.contains("/v1/messages"));
        assert!(!serialized.contains("ULTRA_SECRET_PROMPT_CANARY"));
        assert!(serialized.contains("person@example.com"));
        assert!(outcome.batch.observations[0].service.ai_request);
    }

    #[test]
    fn palo_alto_accepts_gzip_receiver_json_array_shape_after_decompression() {
        let input = br#"[
            {"TimeGenerated":"2026-08-13T10:00:00Z","SequenceNumber":1,"Type":"traffic","DestinationAddress":"203.0.113.10","DestinationPort":443,"Application":"ssl","Protocol":"tcp","Action":"allow"},
            {"TimeGenerated":"2026-08-13T10:00:01Z","SequenceNumber":2,"Type":"url","URL":"api.openai.com/v1/chat?prompt=ULTRA_SECRET_PROMPT_CANARY","HTTPHeaders":"Authorization: ULTRA_SECRET_PROMPT_CANARY"}
        ]"#;
        let outcome = import_palo_alto_ndjson(input, &config()).expect("JSON array");
        assert_eq!(outcome.stats.records_read, 2);
        let serialized = serde_json::to_string(&outcome).expect("serialize");
        assert!(serialized.contains("api.openai.com"));
        assert!(!serialized.contains("/v1/chat"));
        assert!(!serialized.contains("ULTRA_SECRET_PROMPT_CANARY"));
    }

    #[test]
    fn palo_alto_accepts_snake_case_https_field_names() {
        let input = br#"{"time_generated":"2026-08-13T10:00:00Z","sequence_no":"3","Type":"url","src":"10.0.0.7","dst":"203.0.113.10","dport":443,"user":"person@example.com","source_device_host":"LAPTOP-43","URL":"api.anthropic.com/v1/messages","Protocol":"tcp","Action":"allow"}"#;
        let _: PaloAltoRecord = serde_json::from_slice(input).expect("Palo Alto record shape");
        let outcome = import_palo_alto_ndjson(input, &config()).expect("HTTPS field names");
        let observation = &outcome.batch.observations[0];
        assert_eq!(observation.actor.hostname.as_deref(), Some("laptop-43"));
        assert_eq!(
            observation
                .actor
                .identity
                .as_ref()
                .and_then(|identity| identity.email.as_deref()),
            Some("person@example.com")
        );
        assert_eq!(observation.destination.port, Some(443));
    }

    #[test]
    fn palo_alto_retains_documented_destination_device_hostname() {
        let input = br#"{"TimeGenerated":"2026-08-13T10:00:00Z","SequenceNo":"4","Type":"traffic","SourceAddress":"10.0.0.7","DestinationAddress":"203.0.113.10","DestinationPort":443,"SourceUser":"person@example.com","SourceDeviceHost":"LAPTOP-43","DestinationDeviceHost":"API.OPENAI.COM","Protocol":"tcp","Action":"allow"}"#;
        let outcome = import_palo_alto_ndjson(input, &config()).expect("HTTPS fields");
        let observation = &outcome.batch.observations[0];
        assert_eq!(
            observation.destination.host.as_ref().map(Hostname::as_str),
            Some("api.openai.com")
        );
        assert_eq!(observation.actor.hostname.as_deref(), Some("laptop-43"));
    }

    #[test]
    fn palo_alto_retains_documented_user_domain_destination_and_forwarded_ip() {
        let input = br#"{"TimeGenerated":"2026-08-13T10:00:00Z","SequenceNo":"5","Type":"url","SourceAddress":"10.0.0.7","X-Forwarded-ForIP":"198.51.100.7","DestinationAddress":"203.0.113.10","DestinationPort":443,"SourceUserInfoName":"alice","SourceUserInfoDomain":"CORP","SourceDeviceHost":"LAPTOP-43","URLDomain":"API.OPENAI.COM","Protocol":"tcp","Action":"allow"}"#;
        let outcome = import_palo_alto_ndjson(input, &config()).expect("HTTPS fields");
        let observation = &outcome.batch.observations[0];
        assert_eq!(
            observation.destination.host.as_ref().map(Hostname::as_str),
            Some("api.openai.com")
        );
        assert_eq!(
            observation
                .actor
                .identity
                .as_ref()
                .and_then(|identity| identity.source_subject.as_deref()),
            Some("CORP\\alice")
        );
        assert_eq!(
            observation
                .actor
                .additional_source_ips
                .iter()
                .map(IpAddress::as_str)
                .collect::<Vec<_>>(),
            vec!["198.51.100.7"]
        );
    }

    #[test]
    fn palo_alto_accepts_stacked_json_event_wrapper() {
        let input = br#"{"time":1786615200,"host":"stream-logfwd20","source":"Palo Alto Networks FLS LF","event":{"TimeGenerated":"2026-08-13T10:00:00Z","SequenceNumber":1,"Type":"url","URL":"api.anthropic.com/v1/messages?prompt=ULTRA_SECRET_PROMPT_CANARY","Action":"allow"}}"#;
        let outcome = import_palo_alto_ndjson(input, &config()).expect("stacked JSON");
        assert_eq!(outcome.stats.accepted, 1);
        let serialized = serde_json::to_string(&outcome).expect("serialize");
        assert!(serialized.contains("api.anthropic.com"));
        assert!(!serialized.contains("stream-logfwd20"));
        assert!(!serialized.contains("ULTRA_SECRET_PROMPT_CANARY"));
    }

    #[test]
    fn vendor_golden_fixtures_match_mapping_stats_and_redaction_contracts() {
        let cases: [(&str, VendorImportOutcome, &str, &str); 4] = [
            (
                "nextdns",
                import_nextdns_csv(
                    include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../testdata/connectors/nextdns/v1/input.csv"
                    )),
                    &config(),
                )
                .expect("NextDNS fixture"),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../testdata/connectors/nextdns/v1/expected.stats.json"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../testdata/connectors/nextdns/v1/expected.observations.json"
                )),
            ),
            (
                "cloudflare-gateway",
                import_cloudflare_gateway_ndjson(
                    include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../testdata/connectors/cloudflare-gateway/v1/input.ndjson"
                    )),
                    &config(),
                )
                .expect("Cloudflare fixture"),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../testdata/connectors/cloudflare-gateway/v1/expected.stats.json"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../testdata/connectors/cloudflare-gateway/v1/expected.observations.json"
                )),
            ),
            (
                "zscaler",
                import_zscaler_ndjson(
                    include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../testdata/connectors/zscaler/v1/input.ndjson"
                    )),
                    &config(),
                )
                .expect("Zscaler fixture"),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../testdata/connectors/zscaler/v1/expected.stats.json"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../testdata/connectors/zscaler/v1/expected.observations.json"
                )),
            ),
            (
                "palo-alto",
                import_palo_alto_ndjson(
                    include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../testdata/connectors/palo-alto/v1/input.ndjson"
                    )),
                    &config(),
                )
                .expect("Palo Alto fixture"),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../testdata/connectors/palo-alto/v1/expected.stats.json"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../testdata/connectors/palo-alto/v1/expected.observations.json"
                )),
            ),
        ];

        for (name, outcome, expected_stats, expected_observations) in cases {
            let expected_stats: VendorImportStats =
                serde_json::from_str(expected_stats).expect("stats fixture");
            assert_eq!(outcome.stats, expected_stats, "{name} stats");
            let expected: Vec<GoldenObservation> =
                serde_json::from_str(expected_observations).expect("observations fixture");
            let actual = outcome
                .batch
                .observations
                .iter()
                .map(project)
                .collect::<Vec<_>>();
            assert_eq!(actual, expected, "{name} observations");
            assert_redaction(name, &outcome);
        }
    }

    fn project(observation: &Observation) -> GoldenObservation {
        GoldenObservation {
            host: observation
                .destination
                .host
                .as_ref()
                .map(|value| value.as_str().to_owned()),
            source_ip: observation
                .actor
                .source_ip
                .as_ref()
                .map(|value| value.as_str().to_owned()),
            protocol: observation.network.protocol.clone(),
            action: observation.outcome.action.clone(),
            result: observation.outcome.result.clone(),
            identity_pseudonymized: observation.actor.identity.as_ref().is_some_and(|value| {
                value.subject_key.starts_with("p1_") && value.display_label.is_none()
            }),
            device_pseudonymized: observation
                .actor
                .device_key
                .as_ref()
                .is_some_and(|value| value.starts_with("p1_")),
            destination_ip: observation
                .destination
                .ip
                .as_ref()
                .map(|value| value.as_str().to_owned()),
            destination_port: observation.destination.port,
            category: observation.service.source_category.clone(),
            application: observation.service.vendor_application_id.clone(),
            bytes_sent: observation.network.bytes_sent,
            bytes_received: observation.network.bytes_received,
        }
    }

    fn assert_redaction(name: &str, outcome: &VendorImportOutcome) {
        let assertions_path = format!(
            "{}/../../testdata/connectors/{name}/v1/redaction.assertions.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let assertions: RedactionAssertions =
            serde_json::from_slice(&std::fs::read(assertions_path).expect("redaction fixture"))
                .expect("redaction assertions");
        let serialized = serde_json::to_string(outcome).expect("serialize outcome");
        for canary in assertions.must_not_contain {
            assert!(!serialized.contains(&canary), "{name} retained {canary}");
        }
        for marker in assertions.must_contain {
            assert!(serialized.contains(&marker), "{name} omitted {marker}");
        }
    }
}
