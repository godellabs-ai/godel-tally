//! `CrowdStrike` Falcon EDR DNS, network and process telemetry normalization.
//!
//! This connector accepts only the collector-produced allowlisted projection of EDR
//! `DnsRequest` events from Falcon Next-Gen SIEM. Raw event-search results never cross the
//! normalization boundary.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tally_core::{
    ConnectorRef, DigestAlgorithm, EvidenceReceipt, Hostname, IdentityAuthority,
    IdentityObservation, IdentitySubjectKind, Observation, ObservationKind,
};

use crate::{
    ConnectorDescriptor, ConnectorTransport, ObservationBatch, ReplayCapability,
    VendorImportConfig, VendorImportError, VendorImportOutcome, VendorImportStats,
};

const CONNECTOR_TYPE: &str = "crowdstrike_edr_ngsiem_api_v1";

pub const CROWDSTRIKE_EDR_DNS_PROJECTION_SCHEMA_VERSION: &str = "crowdstrike_edr_dns_projection_v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EdrDnsProjection {
    schema_version: String,
    customer_ref: String,
    observed_at: DateTime<Utc>,
    events: Vec<EdrDnsEvent>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EdrDnsEvent {
    #[serde(default)]
    event_kind: Option<String>,
    #[serde(default)]
    executable: Option<String>,
    #[serde(default)]
    process_id: Option<String>,
    #[serde(default)]
    process_unique_id: Option<String>,
    #[serde(default)]
    parent_executable: Option<String>,
    #[serde(default)]
    parent_unique_id: Option<String>,
    #[serde(default)]
    source_ip: Option<String>,
    #[serde(default)]
    remote_ip: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    remote_port: Option<u16>,
    #[serde(default)]
    process_started_at: Option<DateTime<Utc>>,
    id: String,
    observed_at: DateTime<Utc>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    destination_domain: Option<String>,
    #[serde(default)]
    agent_id: Option<String>,
}

#[derive(Serialize)]
struct CanonicalEdrDnsQuery<'a> {
    process: &'a tally_core::ProcessObservation,
    source_ip: Option<&'a str>,
    remote_ip: Option<&'a str>,
    remote_port: Option<u16>,
    event_kind: Option<&'a str>,
    tenant_key: &'a str,
    application_key: &'a str,
    request_key: &'a str,
    registry_entry_id: Option<&'a str>,
    user_id: Option<&'a str>,
    hostname: Option<&'a str>,
    destination_domain: Option<&'a str>,
    device_key: Option<&'a str>,
    observed_at: DateTime<Utc>,
}

#[must_use]
pub fn crowdstrike_edr_api_descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor {
        connector_type: CONNECTOR_TYPE.to_owned(),
        display_name: "CrowdStrike Falcon EDR".to_owned(),
        implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
        source_vendor: "CrowdStrike".to_owned(),
        source_product: "Falcon Insight EDR DNS, network and process telemetry via Falcon Next-Gen SIEM"
            .to_owned(),
        record_variants: vec!["DnsRequest".into(),"ProcessRollup2".into(),"NetworkConnectIP4/IP6".into()],
        transport: ConnectorTransport::Pull,
        required_permissions: vec![
            "Falcon Insight EDR subscription with base_sensor DNS, network and process telemetry".to_owned(),
            "Falcon OAuth2 API client with humio-auth-proxy:read access".to_owned(),
            "operator access to search Falcon EDR sensor events in LogScale".to_owned(),
        ],
        requested_fields: vec![
            "event ID and timestamp".to_owned(),
            "DNS domain, Falcon endpoint hostname, and Falcon agent ID".to_owned(),
            "source user name when supplied by the event".to_owned(),
            "native process identity, executable basename, parent identity and source/destination tuple".to_owned(),
        ],
        prohibited_fields: vec![
            "process command lines, full executable paths, file hashes, or registry values"
                .to_owned(),
            "HTTP bodies, headers, URL paths, and arbitrary event attributes"
                .to_owned(),
            "identity display names and geolocation".to_owned(),
            "raw Falcon or LogScale response bytes and unselected event attributes".to_owned(),
        ],
        cursor_semantics:
            "timestamp watermark with a bounded five-minute overlap; replay is idempotent"
                .to_owned(),
        replay_capability: ReplayCapability::OverlapWindow,
        health_capabilities: vec![
            "Falcon OAuth and NGSIEM query reachability".to_owned(),
            "endpoint DNS, network and process event freshness".to_owned(),
            "normalization quality and result-limit detection".to_owned(),
        ],
        coverage_capabilities: vec![
            "endpoint DNS requests to registry-recognized AI services".to_owned(),
            "source user and endpoint attribution when supplied by EDR telemetry".to_owned(),
        ],
        privacy_contract: "The collector queries allowlisted base_sensor DNS, network and process events and emits an explicit allowlist of event ID, timestamp, DNS domain, endpoint hostname, source user name, and Falcon agent ID. Tally retains validated user names and endpoint hostnames for attribution, pseudonymizes tenant/application/device identifiers, and retains bounded executable basenames, native process identities and network tuples. Command lines, full image paths, hashes and arbitrary source fields are discarded. DNS is not a completed invocation.".to_owned(),
    }
}

/// Imports the privacy-safe projection produced by the native Falcon NGSIEM puller.
///
/// Unknown fields fail closed. Events without a registry-recognized provider are ignored instead
/// of creating speculative AI findings.
///
/// # Errors
///
/// Returns [`VendorImportError`] when the projection is empty, oversized, malformed, contains an
/// unknown field, or violates a bounded metadata or admission invariant.
#[allow(clippy::too_many_lines)]
pub fn import_crowdstrike_edr_dns_json(
    input: &[u8],
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    validate_input(input)?;
    let projection: EdrDnsProjection =
        serde_json::from_slice(input).map_err(|_| VendorImportError::MalformedRecord { row: 1 })?;
    if projection.schema_version != CROWDSTRIKE_EDR_DNS_PROJECTION_SCHEMA_VERSION {
        return Err(VendorImportError::InvalidField {
            row: 1,
            field: "schema_version",
        });
    }
    validate_identifier(&projection.customer_ref, 1, "customer_ref", 256)?;
    if projection.events.is_empty() {
        return Err(VendorImportError::NoRecords);
    }
    if projection.events.len() > crate::MAX_BATCH_OBSERVATIONS {
        return Err(VendorImportError::InvalidField {
            row: 1,
            field: "record_count",
        });
    }

    let tenant_key = config
        .pseudonymization_key
        .pseudonym_exact("crowdstrike_customer", &projection.customer_ref);
    let mut observations = Vec::new();
    let records_read = u64::try_from(projection.events.len()).unwrap_or(u64::MAX);
    for (index, event) in projection.events.into_iter().enumerate() {
        let row = index + 1;
        validate_identifier(&event.id, row, "event_id", 512)?;
        if event.observed_at > projection.observed_at + chrono::Duration::minutes(5) {
            return Err(VendorImportError::InvalidTimestamp { row });
        }
        let registry_entry_id = registry_entry_for_event(&event, row)?;
        let user_id = optional_text(event.user_id.as_deref(), row, "user_id", 512)?;
        let hostname = event
            .hostname
            .as_deref()
            .map(Hostname::parse)
            .transpose()
            .map_err(|_| VendorImportError::InvalidField {
                row,
                field: "hostname",
            })?;
        let destination_domain = event
            .destination_domain
            .as_deref()
            .map(Hostname::parse)
            .transpose()
            .map_err(|_| VendorImportError::InvalidField {
                row,
                field: "destination_domain",
            })?;
        let agent_id = optional_text(event.agent_id.as_deref(), row, "agent_id", 512)?;
        let application_identity = registry_entry_id.unwrap_or("unresolved");
        let application_key = config.pseudonymization_key.pseudonym_exact(
            "crowdstrike_edr_application",
            &format!("{}:{application_identity}", projection.customer_ref),
        );
        let request_key = config.pseudonymization_key.pseudonym_exact(
            "crowdstrike_edr_event",
            &format!("{}:{}", projection.customer_ref, event.id),
        );
        let device_key = agent_id.map(|value| {
            config
                .pseudonymization_key
                .pseudonym_exact("crowdstrike_endpoint", value)
        });
        let safe_token = |value: &Option<String>| {
            value
                .as_deref()
                .filter(|v| {
                    v.len() <= 128
                        && !v.is_empty()
                        && v.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':'))
                })
                .map(str::to_owned)
        };
        if event.event_kind.as_deref().is_some_and(|v| {
            ![
                "DnsRequest",
                "ProcessRollup2",
                "NetworkConnectIP4",
                "NetworkConnectIP6",
            ]
            .contains(&v)
        }) {
            return Err(VendorImportError::InvalidField {
                row,
                field: "event_kind",
            });
        }
        let process = tally_core::ProcessObservation {
            executable: event
                .executable
                .as_deref()
                .and_then(tally_core::ProcessObservation::executable_basename),
            pid: safe_token(&event.process_id),
            unique_id: safe_token(&event.process_unique_id),
            started_at: event.process_started_at,
            parent_executable: event
                .parent_executable
                .as_deref()
                .and_then(tally_core::ProcessObservation::executable_basename),
            parent_pid: None,
            parent_unique_id: safe_token(&event.parent_unique_id),
        };
        let source_ip = event
            .source_ip
            .as_deref()
            .map(tally_core::IpAddress::parse)
            .transpose()
            .map_err(|_| VendorImportError::InvalidField {
                row,
                field: "source_ip",
            })?;
        let remote_ip = event
            .remote_ip
            .as_deref()
            .map(tally_core::IpAddress::parse)
            .transpose()
            .map_err(|_| VendorImportError::InvalidField {
                row,
                field: "remote_ip",
            })?;
        if registry_entry_id.is_none()
            && device_key.is_none()
            && user_id.is_none()
            && hostname.is_none()
            && source_ip.is_none()
            && process.is_empty()
        {
            continue;
        }
        let canonical = CanonicalEdrDnsQuery {
            process: &process,
            source_ip: source_ip.as_ref().map(tally_core::IpAddress::as_str),
            remote_ip: remote_ip.as_ref().map(tally_core::IpAddress::as_str),
            remote_port: event.remote_port,
            event_kind: event.event_kind.as_deref(),
            tenant_key: &tenant_key,
            application_key: &application_key,
            request_key: &request_key,
            registry_entry_id,
            user_id,
            hostname: hostname.as_ref().map(Hostname::as_str),
            destination_domain: destination_domain.as_ref().map(Hostname::as_str),
            device_key: device_key.as_deref(),
            observed_at: event.observed_at,
        };
        let digest = canonical_digest(&canonical)?;
        let mut observation = base_observation(config, event.observed_at, &digest);
        observation.saas.tenant_key = Some(tenant_key.clone());
        observation.saas.application_key = Some(application_key.clone());
        observation.service.vendor_application_id = registry_entry_id.map(str::to_owned);
        observation.service.source_category = Some("crowdstrike_edr_dns".to_owned());
        observation.service.ai_request = false;
        observation.service.ai_request_evaluated = false;
        observation.destination.host = destination_domain;
        observation.network.request_count = Some(1);
        observation.process = process;
        observation.actor.source_ip = source_ip;
        observation.destination.ip = remote_ip;
        observation.destination.port = event.remote_port;
        observation.network.destination_port = event.remote_port;
        observation.network.protocol = event
            .protocol
            .as_deref()
            .filter(|v| v.len() <= 16 && v.bytes().all(|b| b.is_ascii_alphanumeric()))
            .map(str::to_owned);
        observation.inventory.user_role = Some(tally_core::IdentityRole::ProcessAccount);
        observation.kind = match event.event_kind.as_deref() {
            Some("ProcessRollup2") => ObservationKind::NetworkMapping,
            Some("NetworkConnectIP4" | "NetworkConnectIP6") => ObservationKind::NetworkFlow,
            _ => ObservationKind::DnsQuery,
        };
        if let Some((kind, name)) = observation
            .process
            .executable
            .as_deref()
            .and_then(|file| crate::agent_signatures::identify(file, ""))
        {
            observation.agent.key = Some(config.pseudonymization_key.pseudonym_exact(
                "falcon_process",
                &format!(
                        "{}:{}:{}",
                        device_key.as_deref().unwrap_or("unknown"),
                        observation
                            .process
                            .unique_id
                            .as_deref()
                            .unwrap_or("unknown"),
                        name
                    ),
            ));
            observation.agent.name = Some(name);
            observation.agent.kind = Some(kind.into());
            observation.agent.platform = Some("endpoint".into());
            observation.agent.state = Some("observed".into());
        }
        observation.actor.device_key = device_key;
        observation.inventory.device_key_kind =
            Some(tally_core::DeviceIdentifierKind::SourceNative);
        observation.actor.hostname = hostname.map(|value| value.as_str().to_owned());
        observation.actor.identity = user_id.map(|subject| {
            let email = recognized_email(subject);
            IdentityObservation {
                subject_key: config.pseudonymization_key.pseudonym_exact(
                    "identity",
                    &if recognized_email(subject).is_some() {
                        subject.to_ascii_lowercase()
                    } else {
                        format!(
                            "{}:{subject}",
                            observation
                                .actor
                                .device_key
                                .as_deref()
                                .unwrap_or(&request_key)
                        )
                    },
                ),
                email,
                source_subject: Some(subject.to_owned()),
                source_subject_kind: Some(IdentitySubjectKind::UserName),
                authority: Some(IdentityAuthority::SourceNative),
                directory_key: None,
                application_key: Some(application_key),
                display_label: None,
            }
        });
        observation.outcome.action = Some("dns_request".to_owned());
        observations.push(observation);
    }
    finish_import(observations, records_read, config)
}

fn registry_entry_for_event(
    event: &EdrDnsEvent,
    row: usize,
) -> Result<Option<&'static str>, VendorImportError> {
    let Some(domain) = event.destination_domain.as_deref() else {
        return Ok(None);
    };
    let domain = validate_lookup_text(domain, row)?;
    Ok(registry_entry_for_label(domain))
}

pub(crate) fn registry_entry_for_label(value: &str) -> Option<&'static str> {
    let raw = value.trim().to_ascii_lowercase();
    let token = raw.replace([' ', '_'], "-");
    match token.as_str() {
        "chatgpt" | "openai-chatgpt" => Some("app.openai.chatgpt"),
        "openai" | "openai-api" => Some("svc.openai.api"),
        "claude" | "anthropic" | "anthropic-claude" => Some("svc.anthropic.api"),
        "github-copilot" => Some("svc.github.copilot"),
        "gemini" | "google-gemini" | "google-ai-studio" => Some("svc.google.gemini_api"),
        "deepseek" | "deepseek-api" => Some("svc.deepseek.api"),
        "deepseek-chat" => Some("app.deepseek.chat"),
        "cohere" => Some("svc.cohere.api"),
        "mistral" | "mistral-ai" => Some("svc.mistral.api"),
        "perplexity" => Some("svc.perplexity.api"),
        "openrouter" => Some("svc.openrouter.api"),
        "groq" => Some("svc.groq.api"),
        "xai" | "x-ai" | "grok" => Some("svc.xai.api"),
        _ if host_matches(&raw, "chatgpt.com") => Some("app.openai.chatgpt"),
        _ if host_matches(&raw, "api.openai.com") => Some("svc.openai.api"),
        _ if host_matches(&raw, "claude.ai") || host_matches(&raw, "api.anthropic.com") => {
            Some("svc.anthropic.api")
        }
        _ if host_matches(&raw, "copilot-proxy.githubusercontent.com") => {
            Some("svc.github.copilot")
        }
        _ if host_matches(&raw, "generativelanguage.googleapis.com") => {
            Some("svc.google.gemini_api")
        }
        _ if host_matches(&raw, "chat.deepseek.com") => Some("app.deepseek.chat"),
        _ if host_matches(&raw, "api.deepseek.com") => Some("svc.deepseek.api"),
        _ if host_matches(&raw, "api.cohere.com") => Some("svc.cohere.api"),
        _ if host_matches(&raw, "api.mistral.ai") => Some("svc.mistral.api"),
        _ if host_matches(&raw, "api.perplexity.ai") => Some("svc.perplexity.api"),
        _ if host_matches(&raw, "openrouter.ai") => Some("svc.openrouter.api"),
        _ if host_matches(&raw, "api.groq.com") => Some("svc.groq.api"),
        _ if host_matches(&raw, "api.x.ai") => Some("svc.xai.api"),
        _ => None,
    }
}

fn host_matches(value: &str, suffix: &str) -> bool {
    value == suffix
        || value
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn validate_input(input: &[u8]) -> Result<(), VendorImportError> {
    if input.is_empty() {
        return Err(VendorImportError::NoRecords);
    }
    if input.len() > crate::MAX_IMPORT_BYTES {
        return Err(VendorImportError::ImportTooLarge(input.len()));
    }
    Ok(())
}

fn validate_identifier(
    value: &str,
    row: usize,
    field: &'static str,
    max_len: usize,
) -> Result<(), VendorImportError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > max_len || trimmed.chars().any(char::is_control) {
        return Err(VendorImportError::InvalidField { row, field });
    }
    Ok(())
}

fn optional_text<'a>(
    value: Option<&'a str>,
    row: usize,
    field: &'static str,
    max_len: usize,
) -> Result<Option<&'a str>, VendorImportError> {
    value
        .map(|value| {
            validate_identifier(value, row, field, max_len)?;
            Ok(value.trim())
        })
        .transpose()
}

fn validate_lookup_text(value: &str, row: usize) -> Result<&str, VendorImportError> {
    validate_identifier(value, row, "provider_identity", 512)?;
    Ok(value.trim())
}

pub(crate) fn recognized_email(value: &str) -> Option<String> {
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

fn base_observation(
    config: &VendorImportConfig,
    observed_at: DateTime<Utc>,
    digest: &str,
) -> Observation {
    let mut observation = Observation::new(
        config.installation_id,
        observed_at,
        ConnectorRef {
            instance_id: config.connector_instance_id,
            connector_type: CONNECTOR_TYPE.to_owned(),
            implementation_version: config.implementation_version.clone(),
            source_lineage_id: config.source_lineage_id.clone(),
        },
        ObservationKind::DnsQuery,
        EvidenceReceipt::RecordDigest {
            algorithm: DigestAlgorithm::Sha256,
            digest: digest.to_owned(),
        },
    );
    observation.observation_id = uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        format!(
            "godel-tally:crowdstrike-edr:{}:{}:{digest}",
            config.connector_instance_id,
            config
                .source_lineage_id
                .as_deref()
                .unwrap_or("connector_default")
        )
        .as_bytes(),
    );
    observation.received_at = config.received_at;
    observation
}

fn canonical_digest(value: &impl Serialize) -> Result<String, VendorImportError> {
    let bytes = serde_json::to_vec(value).map_err(|_| VendorImportError::Serialization)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn finish_import(
    mut observations: Vec<Observation>,
    records_read: u64,
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    observations.sort_by_key(|observation| observation.observation_id);
    observations.dedup_by_key(|observation| observation.observation_id);
    let accepted = u64::try_from(observations.len()).unwrap_or(u64::MAX);
    if accepted == 0 {
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
        redaction: crate::RedactionProof {
            connector_type: CONNECTOR_TYPE.to_owned(),
            pseudonymization: "hmac_sha256_installation_key_v1".to_owned(),
            discarded_fields: vec![
                "process command lines, full image paths, file hashes, and registry values"
                    .to_owned(),
                "raw HTTP metadata, identity display names, and arbitrary attributes".to_owned(),
                "raw Falcon and LogScale response bytes".to_owned(),
            ],
            source_bytes_retained: false,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cursor, PseudonymizationKey};
    use uuid::Uuid;

    fn config() -> VendorImportConfig {
        VendorImportConfig {
            installation_id: Uuid::from_u128(1),
            connector_instance_id: Uuid::from_u128(2),
            implementation_version: "test".to_owned(),
            source_lineage_id: Some("crowdstrike_edr:ngsiem_dns".to_owned()),
            received_at: "2026-09-07T10:01:00Z".parse().expect("timestamp"),
            checkpoint: Cursor("ca1:1788775260000".to_owned()),
            pseudonymization_key: PseudonymizationKey::new(&[7_u8; 32]).expect("key"),
        }
    }

    #[test]
    fn normalizes_edr_dns_without_retaining_unselected_fields() {
        let input = br#"{
            "schema_version":"crowdstrike_edr_dns_projection_v1",
            "customer_ref":"tenant-fingerprint",
            "observed_at":"2026-09-07T10:01:00Z",
            "events":[{
                "id":"evt-1",
                "observed_at":"2026-09-07T10:00:00Z",
                "user_id":"analyst@example.com",
                "hostname":"laptop-17.example.com",
                "destination_domain":"chatgpt.com",
                "agent_id":"agent-7"
            }]
        }"#;
        let outcome = import_crowdstrike_edr_dns_json(input, &config()).expect("import");
        assert_eq!(outcome.stats.records_read, 1);
        assert_eq!(outcome.stats.accepted, 1);
        let observation = &outcome.batch.observations[0];
        assert_eq!(observation.kind, ObservationKind::DnsQuery);
        assert_eq!(
            observation.service.vendor_application_id.as_deref(),
            Some("app.openai.chatgpt")
        );
        assert_eq!(
            observation.actor.hostname.as_deref(),
            Some("laptop-17.example.com")
        );
        assert_eq!(
            observation
                .actor
                .identity
                .as_ref()
                .and_then(|identity| identity.email.as_deref()),
            Some("analyst@example.com")
        );
        let serialized = serde_json::to_string(&outcome.batch).expect("serialize");
        assert!(!serialized.contains("evt-1"));
        assert!(!serialized.contains("agent-7"));
    }

    #[test]
    fn ignores_unrecognized_applications_instead_of_inventing_findings() {
        let input = br#"{
            "schema_version":"crowdstrike_edr_dns_projection_v1",
            "customer_ref":"tenant-fingerprint",
            "observed_at":"2026-09-07T10:01:00Z",
            "events":[{
                "id":"evt-unknown",
                "observed_at":"2026-09-07T10:00:00Z",
                "destination_domain":"unknown-ai-site.example"
            }]
        }"#;
        let error = import_crowdstrike_edr_dns_json(input, &config())
            .expect_err("unknown domain must not produce usage");
        assert!(matches!(error, VendorImportError::NoAcceptedRecords));
        assert_eq!(registry_entry_for_label("not-openai.example"), None);
        assert_eq!(registry_entry_for_label("openai.example.invalid"), None);
    }

    #[test]
    fn rejects_unallowlisted_edr_fields() {
        let input = br#"{
            "schema_version":"crowdstrike_edr_dns_projection_v1",
            "customer_ref":"tenant-fingerprint",
            "observed_at":"2026-09-07T10:01:00Z",
            "events":[{
                "id":"evt-1",
                "observed_at":"2026-09-07T10:00:00Z",
                "destination_domain":"chatgpt.com",
                "CommandLine":"unallowlisted"
            }]
        }"#;
        assert!(matches!(
            import_crowdstrike_edr_dns_json(input, &config()),
            Err(VendorImportError::MalformedRecord { .. })
        ));
    }
}
