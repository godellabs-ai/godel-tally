use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tally_core::{
    ConnectorRef, DigestAlgorithm, EvidenceReceipt, Hostname, IdentityAuthority,
    IdentityObservation, IdentitySubjectKind, IpAddress, Observation, ObservationKind,
};

use crate::{
    ConnectorDescriptor, ConnectorTransport, ObservationBatch, ReplayCapability,
    VendorImportConfig, VendorImportError, VendorImportOutcome, VendorImportStats,
};

const CONNECTOR_TYPE: &str = "cato_networks_api_v1";
pub const CATO_NETWORKS_PROJECTION_SCHEMA_VERSION: &str = "cato_networks_projection_v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatoProjection {
    schema_version: String,
    account_id: String,
    #[serde(rename = "observed_at")]
    _observed_at: DateTime<Utc>,
    events: Vec<CatoEvent>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatoEvent {
    id: String,
    observed_at: DateTime<Utc>,
    #[serde(default)]
    src_ip: Option<String>,
    #[serde(default)]
    dst_ip: Option<String>,
    #[serde(default)]
    dest_domain: Option<String>,
    #[serde(default)]
    dest_port: Option<u16>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    bytes_sent: Option<u64>,
    #[serde(default)]
    bytes_received: Option<u64>,
    #[serde(default)]
    external_id: Option<String>,
    #[serde(default)]
    identity_source: Option<String>,
    #[serde(default)]
    mcp_path: bool,
}

#[derive(Serialize)]
struct CanonicalCatoUsage<'a> {
    account_key: &'a str,
    request_key: &'a str,
    src_ip: Option<&'a str>,
    dst_ip: Option<&'a str>,
    dest_domain: Option<&'a str>,
    dest_port: Option<u16>,
    user_id: Option<&'a str>,
    hostname: Option<&'a str>,
    registry_entry_id: Option<&'a str>,
    action: Option<&'a str>,
    observed_at: DateTime<Utc>,
}

#[must_use]
pub fn cato_networks_api_descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor {
        connector_type: CONNECTOR_TYPE.to_owned(),
        display_name: "Cato Networks SASE".to_owned(),
        implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
        source_vendor: "Cato Networks".to_owned(),
        source_product: "Cato SASE Cloud".to_owned(),
        record_variants: vec!["CatoEvent".to_owned()],
        transport: ConnectorTransport::Pull,
        required_permissions: vec![
            "Cato API read access".to_owned(),
        ],
        requested_fields: vec![
            "reported bytes_sent and bytes_received".to_owned(),
            "event ID and timestamp".to_owned(),
            "source IP, user identity, and source hostname".to_owned(),
            "destination domain, IP, port, and action".to_owned(),
        ],
        prohibited_fields: vec![
            "full payload and sensitive PII".to_owned(),
        ],
        cursor_semantics: "opaque EventsFeed marker committed after each complete provider page; replay is idempotent".to_owned(),
        replay_capability: ReplayCapability::OverlapWindow,
        health_capabilities: vec!["API reachability".to_owned()],
        coverage_capabilities: vec!["network flows".to_owned()],
        privacy_contract: "Retains source identity and endpoint plus destination network metadata needed to locate Shadow AI usage. Event messages, payloads, and unrelated fields are discarded.".to_owned(),
    }
}

/// Converts a bounded Cato `EventsFeed` projection into normalized Tally observations.
///
/// # Errors
///
/// Returns [`VendorImportError`] when the projection is empty, oversized, malformed, uses an
/// unsupported schema version, contains an invalid field, or cannot build a canonical batch.
#[allow(clippy::too_many_lines)] // Keep the field validation and privacy projection linear.
pub fn import_cato_networks_json(
    input: &[u8],
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    if input.is_empty() {
        return Err(VendorImportError::NoRecords);
    }
    if input.len() > crate::MAX_IMPORT_BYTES {
        return Err(VendorImportError::ImportTooLarge(input.len()));
    }
    let projection: CatoProjection =
        serde_json::from_slice(input).map_err(|_| VendorImportError::MalformedRecord { row: 1 })?;
    if projection.schema_version != CATO_NETWORKS_PROJECTION_SCHEMA_VERSION {
        return Err(VendorImportError::InvalidField {
            row: 1,
            field: "schema_version",
        });
    }
    if projection.events.is_empty() {
        return Err(VendorImportError::NoRecords);
    }

    let account_key = config
        .pseudonymization_key
        .pseudonym_exact("cato_account", &projection.account_id);

    let mut observations = Vec::new();
    let records_read = u64::try_from(projection.events.len()).unwrap_or(u64::MAX);

    for (index, event) in projection.events.into_iter().enumerate() {
        let row = index.saturating_add(1);
        validate_text(&event.id, row, "id", 512)?;
        let source_ip = event
            .src_ip
            .as_deref()
            .map(IpAddress::parse)
            .transpose()
            .map_err(|_| VendorImportError::InvalidField {
                row,
                field: "src_ip",
            })?;
        let destination_ip = event
            .dst_ip
            .as_deref()
            .map(IpAddress::parse)
            .transpose()
            .map_err(|_| VendorImportError::InvalidField {
                row,
                field: "dst_ip",
            })?;
        let destination_host = event
            .dest_domain
            .as_deref()
            .map(Hostname::parse)
            .transpose()
            .map_err(|_| VendorImportError::InvalidField {
                row,
                field: "dest_domain",
            })?;
        let user_id = optional_text(event.user_id.as_deref(), row, "user_id", 512)?;
        let hostname = optional_text(event.hostname.as_deref(), row, "hostname", 512)?;
        let action = optional_text(event.action.as_deref(), row, "action", 256)?;
        let registry_entry_id = destination_host
            .as_ref()
            .and_then(|host| crate::crowdstrike::registry_entry_for_label(host.as_str()));
        let request_key = config.pseudonymization_key.pseudonym_exact(
            "cato_event",
            &format!("{}:{}", projection.account_id, event.id),
        );
        let canonical = CanonicalCatoUsage {
            account_key: &account_key,
            request_key: &request_key,
            src_ip: source_ip.as_ref().map(IpAddress::as_str),
            dst_ip: destination_ip.as_ref().map(IpAddress::as_str),
            dest_domain: destination_host.as_ref().map(Hostname::as_str),
            dest_port: event.dest_port,
            user_id,
            hostname,
            registry_entry_id,
            action,
            observed_at: event.observed_at,
        };
        let bytes = serde_json::to_vec(&canonical).map_err(|_| VendorImportError::Serialization)?;
        let digest = hex::encode(Sha256::digest(bytes));

        let mut observation = Observation::new(
            config.installation_id,
            event.observed_at,
            ConnectorRef {
                instance_id: config.connector_instance_id,
                connector_type: CONNECTOR_TYPE.to_owned(),
                implementation_version: config.implementation_version.clone(),
                source_lineage_id: config.source_lineage_id.clone(),
            },
            ObservationKind::HttpMetadata,
            EvidenceReceipt::RecordDigest {
                algorithm: DigestAlgorithm::Sha256,
                digest: digest.clone(),
            },
        );
        observation.observation_id = uuid::Uuid::new_v5(
            &uuid::Uuid::NAMESPACE_URL,
            format!(
                "godel-tally:cato:{}:{}:{digest}",
                config.connector_instance_id,
                config
                    .source_lineage_id
                    .as_deref()
                    .unwrap_or("connector_default")
            )
            .as_bytes(),
        );
        observation.received_at = config.received_at;
        observation.saas.tenant_key = Some(account_key.clone());
        observation.actor.source_ip = source_ip;
        observation.actor.hostname = hostname.map(str::to_owned);
        observation.actor.identity = user_id.map(|subject| IdentityObservation {
            subject_key: config
                .pseudonymization_key
                .pseudonym_exact("identity", subject),
            email: crate::crowdstrike::recognized_email(subject),
            source_subject: Some(subject.to_owned()),
            source_subject_kind: Some(IdentitySubjectKind::UserName),
            authority: Some(IdentityAuthority::SourceNative),
            directory_key: None,
            application_key: None,
            display_label: None,
        });
        observation.destination.ip = destination_ip;
        observation.destination.host = destination_host;
        observation.destination.port = event.dest_port;
        observation.network.destination_port = event.dest_port;
        observation.service.vendor_application_id = registry_entry_id.map(str::to_owned);
        observation.service.source_category = Some("cato_events_feed".to_owned());
        observation.outcome.action = action.map(str::to_owned);

        observation.network.bytes_sent = event.bytes_sent;
        observation.network.bytes_received = event.bytes_received;
        observation.agent.directory_object_id = event
            .external_id
            .as_deref()
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
            .map(|id| {
                config
                    .pseudonymization_key
                    .pseudonym_exact("entra_object", &id.to_string())
            });
        let (confidence, basis) = match (user_id, event.identity_source.as_deref()) {
            (Some(_), Some("sdp")) => ("strong", "Cato SDP authenticated user"),
            (Some(_), Some("user_awareness")) => (
                "inferred",
                "Cato User Awareness IP mapping; candidate identity, NAT or address reuse may be ambiguous",
            ),
            (Some(_), _) => (
                "source_reported",
                "Cato source user; identity mechanism not supplied",
            ),
            (None, _) => ("unattributed", "Cato did not supply a user identity"),
        };
        observation.agent.attribution_confidence = Some(confidence.into());
        observation.agent.attribution_basis = Some(basis.into());
        if event.mcp_path
            && let Some(host) = &observation.destination.host
        {
            observation.agent.key = Some(format!("https:{}:mcp", host.as_str()));
            observation.agent.name = Some(format!("{} /mcp", host.as_str()));
            observation.agent.kind = Some("mcp_server".into());
            observation.agent.platform = Some("remote".into());
            observation.agent.state = Some("candidate".into());
            observation.agent.attribution_basis = Some(format!(
                "{basis}. MCP path heuristic only; protocol not confirmed"
            ));
        }
        let digest = hex::encode(Sha256::digest(
            serde_json::to_vec(&(&digest, &observation.agent, &observation.network))
                .map_err(|_| VendorImportError::Serialization)?,
        ));
        observation.observation_id =
            uuid::Uuid::new_v5(&config.connector_instance_id, digest.as_bytes());
        observation.source = EvidenceReceipt::RecordDigest {
            algorithm: DigestAlgorithm::Sha256,
            digest,
        };
        observations.push(observation);
    }

    observations.sort_by_key(|obs| obs.observation_id);
    observations.dedup_by_key(|obs| obs.observation_id);
    let accepted = u64::try_from(observations.len()).unwrap_or(u64::MAX);

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
                "event message, payload, threat details, and unrelated EventsFeed fields"
                    .to_owned(),
                "raw Cato GraphQL response bytes and source event IDs".to_owned(),
            ],
            source_bytes_retained: false,
        },
    })
}

fn validate_text(
    value: &str,
    row: usize,
    field: &'static str,
    max_len: usize,
) -> Result<(), VendorImportError> {
    if value.trim().is_empty()
        || value.trim() != value
        || value.len() > max_len
        || value.chars().any(char::is_control)
    {
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
            validate_text(value, row, field, max_len)?;
            Ok(value)
        })
        .transpose()
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
            source_lineage_id: Some("cato:network".to_owned()),
            received_at: "2026-09-07T10:01:00Z".parse().expect("timestamp"),
            checkpoint: Cursor("cato:123".to_owned()),
            pseudonymization_key: PseudonymizationKey::new(&[7_u8; 32]).expect("key"),
        }
    }

    #[test]
    fn normalizes_cato_events() {
        let input = br#"{
            "schema_version":"cato_networks_projection_v1",
            "account_id":"acc-1",
            "observed_at":"2026-09-07T10:01:00Z",
            "events":[{
                "id":"evt-1",
                "observed_at":"2026-09-07T10:00:00Z",
                "src_ip":"192.168.1.100",
                "dst_ip":"10.0.0.1",
                "dest_domain":"api.deepseek.com",
                "dest_port":443,
                "user_id":"employee@example.com",
                "hostname":"laptop-42",
                "action":"allow"
            }]
        }"#;
        let outcome = import_cato_networks_json(input, &config()).expect("import");
        assert_eq!(outcome.stats.records_read, 1);
        assert_eq!(outcome.stats.accepted, 1);
        let observation = &outcome.batch.observations[0];
        assert_eq!(observation.kind, ObservationKind::HttpMetadata);
        assert_eq!(observation.outcome.action.as_deref(), Some("allow"));
        assert_eq!(observation.actor.hostname.as_deref(), Some("laptop-42"));
        assert_eq!(
            observation
                .actor
                .identity
                .as_ref()
                .and_then(|identity| identity.email.as_deref()),
            Some("employee@example.com")
        );
        assert_eq!(observation.destination.port, Some(443));
        assert_eq!(
            observation.service.vendor_application_id.as_deref(),
            Some("svc.deepseek.api")
        );
        let serialized = serde_json::to_string(&outcome.batch).expect("serialize");
        assert!(!serialized.contains("evt-1"));
    }
}
