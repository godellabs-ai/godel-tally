//! Shared allowlisted metadata projection for scheduled Rapid7 and Netskope pulls.
use super::{
    ConnectorDescriptor, ConnectorTransport, IMPLEMENTATION_VERSION, ReplayCapability, SafeRecord,
    VendorImportConfig, VendorImportError, VendorImportOutcome, normalize_records,
    normalized_hostname, observation_from_safe, optional_label, parse_host, parse_ndjson,
    parse_optional_ip, recognized_email, recognized_subject, validate_record_id,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tally_core::{IdentitySubjectKind, IpAddress, Observation, ObservationKind};
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityLogSource {
    Rapid7Edr,
    Netskope,
}

impl SecurityLogSource {
    #[must_use]
    pub const fn connector_type(self) -> &'static str {
        match self {
            Self::Rapid7Edr => "rapid7_edr_insightidr_api_v1",
            Self::Netskope => "netskope_events_api_v1",
        }
    }

    #[must_use]
    pub const fn cursor_prefix(self) -> &'static str {
        match self {
            Self::Rapid7Edr => "rapid7-v1:",
            Self::Netskope => "netskope-v1:",
        }
    }

    #[must_use]
    pub fn descriptor(self) -> ConnectorDescriptor {
        let (name, vendor, product, permissions) = match self {
            Self::Rapid7Edr => (
                "Rapid7 EDR",
                "Rapid7",
                "InsightIDR normalized DNS Query logs",
                "Read-only Insight platform API key with Log Search access to the selected DNS Query log",
            ),
            Self::Netskope => (
                "Netskope",
                "Netskope",
                "REST API v2 page or application events",
                "REST API v2 token with Read access to the selected /api/v2/events/data/page or /application endpoint",
            ),
        };
        ConnectorDescriptor {
            connector_type: self.connector_type().into(),
            display_name: name.into(),
            implementation_version: IMPLEMENTATION_VERSION.into(),
            source_vendor: vendor.into(),
            source_product: product.into(),
            record_variants: vec!["allowlisted_security_event_v1".into()],
            transport: ConnectorTransport::Pull,
            required_permissions: vec![permissions.into()],
            requested_fields: vec!["event ID, timestamp, destination domain, source user, endpoint hostname, device ID, source IP, action and reported event count".into()],
            prohibited_fields: vec!["URL paths and queries, payloads, headers, files, process command lines, custom fields and raw source bytes".into()],
            cursor_semantics: "Settled time windows with durable page checkpoints; retries replay the same page and deduplicate event IDs".into(),
            replay_capability: ReplayCapability::DurableCursor,
            health_capabilities: vec!["API reachability".into(), "bounded pagination".into(), "source freshness".into()],
            coverage_capabilities: vec!["AI service destinations".into(), "source-supplied user and endpoint attribution".into()],
            privacy_contract: "Only the explicit metadata projection crosses the ingestion boundary. Destination URLs become hostnames; user and endpoint attribution is validated, internal identifiers are pseudonymized, and source content is discarded. DNS or web access alone does not establish model invocation.".into(),
        }
    }
}

/// Validates an Insight platform region before constructing a fixed vendor origin.
#[must_use]
pub fn rapid7_api_origin(region: &str) -> Option<String> {
    matches!(region, "us" | "us2" | "us3" | "eu" | "ca" | "au" | "ap")
        .then(|| format!("https://{region}.api.insight.rapid7.com"))
}

/// Accepts commercial Netskope tenant origins only, without credentials or paths.
#[must_use]
pub fn netskope_api_origin(value: &str) -> Option<String> {
    let url = Url::parse(value).ok()?;
    let host = url.host_str()?;
    (url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && host
            .strip_suffix(".goskope.com")
            .is_some_and(|tenant| !tenant.is_empty()))
    .then(|| url.origin().ascii_serialization())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityLogRecord {
    pub id: String,
    pub observed_at: DateTime<Utc>,
    pub host: String,
    pub user: Option<String>,
    pub hostname: Option<String>,
    pub device_id: Option<String>,
    pub source_ip: Option<String>,
    pub action: Option<String>,
    pub count: u64,
}

/// Imports only collector-projected security metadata, never raw vendor event bodies.
///
/// # Errors
/// Returns an error for malformed, oversized, or unsafe metadata.
pub fn import_security_logs_json(
    input: &[u8],
    source: SecurityLogSource,
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    let normalize = match source {
        SecurityLogSource::Rapid7Edr => normalize_rapid7,
        SecurityLogSource::Netskope => normalize_netskope,
    };
    normalize_records(
        parse_ndjson::<SecurityLogRecord>(input)?,
        config,
        source.connector_type(),
        &[
            "URL paths and queries",
            "payloads, headers, files and command lines",
            "unselected fields and source bytes",
        ],
        normalize,
    )
}

fn normalize_rapid7(
    record: SecurityLogRecord,
    row: usize,
    config: &VendorImportConfig,
) -> Result<Option<Observation>, VendorImportError> {
    normalize(record, row, config, SecurityLogSource::Rapid7Edr)
}
fn normalize_netskope(
    record: SecurityLogRecord,
    row: usize,
    config: &VendorImportConfig,
) -> Result<Option<Observation>, VendorImportError> {
    normalize(record, row, config, SecurityLogSource::Netskope)
}
fn normalize(
    record: SecurityLogRecord,
    row: usize,
    config: &VendorImportConfig,
    source: SecurityLogSource,
) -> Result<Option<Observation>, VendorImportError> {
    let host = parse_host(&record.host, row)?;
    if record.count == 0 || record.observed_at > config.received_at + chrono::Duration::minutes(5) {
        return Err(VendorImportError::InvalidField {
            row,
            field: "timestamp_or_count",
        });
    }
    validate_record_id(Some(&record.id), row)?;
    let record_id = config
        .pseudonymization_key
        .pseudonym_exact("security_event", &record.id);
    let email = record.user.as_deref().and_then(recognized_email);
    let subject = record
        .user
        .as_deref()
        .filter(|_| email.is_none())
        .and_then(recognized_subject);
    let identity = record
        .user
        .as_deref()
        .map(|user| config.pseudonymization_key.pseudonym("identity", user));
    let hostname = record.hostname.as_deref().and_then(normalized_hostname);
    let device = record
        .device_id
        .as_deref()
        .or(hostname.as_deref())
        .map(|id| config.pseudonymization_key.pseudonym_exact("device", id));
    let ip = parse_optional_ip(record.source_ip.as_deref(), row, "source_ip")?;
    let action = optional_label(record.action.as_deref(), row, "action")?;
    let safe = SafeRecord {
        observed_at: record.observed_at,
        host: Some(host.as_str()),
        destination_ip: None,
        destination_port: None,
        source_ip: ip.as_ref().map(IpAddress::as_str),
        alternate_source_ip: None,
        identity: identity.as_deref(),
        email: email.as_deref(),
        source_subject: subject.as_deref(),
        source_subject_kind: subject.as_ref().map(|_| IdentitySubjectKind::UserName),
        device: device.as_deref(),
        hostname: hostname.as_deref(),
        protocol: None,
        action: action.as_deref(),
        result: None,
        category: None,
        application: None,
        bytes_sent: None,
        bytes_received: None,
        request_count: record.count,
        source_record_id: Some(&record_id),
        ai_request: false,
        ai_request_evaluated: false,
        declared_model_id: None,
    };
    let kind = match source {
        SecurityLogSource::Rapid7Edr => ObservationKind::DnsQuery,
        SecurityLogSource::Netskope => ObservationKind::HttpMetadata,
    };
    let observation = observation_from_safe(&safe, config, source.connector_type(), kind)?;
    drop(record);
    Ok(Some(observation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cursor, PseudonymizationKey};
    use uuid::Uuid;
    #[test]
    fn security_logs_validate_origins() {
        assert!(rapid7_api_origin("eu").is_some());
        assert!(rapid7_api_origin("evil.test").is_none());
        assert_eq!(
            netskope_api_origin("https://tenant.goskope.com/"),
            Some("https://tenant.goskope.com".into())
        );
        for value in [
            "http://tenant.goskope.com",
            "https://tenant.goskope.com.evil.test",
            "https://user@tenant.goskope.com",
            "https://tenant.goskope.com/api",
            "https://tenant.goskope.com?token=secret",
            "https://127.0.0.1",
        ] {
            assert!(netskope_api_origin(value).is_none(), "{value}");
        }
    }
    #[test]
    fn security_logs_preserve_attribution_and_deduplicate_without_payloads() {
        let config = VendorImportConfig {
            installation_id: Uuid::nil(),
            connector_instance_id: Uuid::from_u128(1),
            implementation_version: "test".into(),
            source_lineage_id: None,
            received_at: "2026-08-13T11:00:00Z".parse().unwrap(),
            checkpoint: Cursor("test".into()),
            pseudonymization_key: PseudonymizationKey::new(&[7; 32]).unwrap(),
        };
        let record = serde_json::json!({"id":"source-id", "observed_at":"2026-08-13T10:05:00Z", "host":"api.openai.com", "user":"person@example.com", "hostname":"LAPTOP-42", "device_id":"raw-device", "source_ip":"10.0.0.8", "action":"allow", "count":3});
        for source in [SecurityLogSource::Rapid7Edr, SecurityLogSource::Netskope] {
            let input = serde_json::to_vec(&vec![&record, &record]).unwrap();
            let result = import_security_logs_json(&input, source, &config).unwrap();
            assert_eq!(result.batch.observations.len(), 1);
            let observation = &result.batch.observations[0];
            assert_eq!(observation.actor.hostname.as_deref(), Some("laptop-42"));
            assert_eq!(
                observation
                    .actor
                    .identity
                    .as_ref()
                    .unwrap()
                    .email
                    .as_deref(),
                Some("person@example.com")
            );
            assert_eq!(observation.network.request_count, Some(3));
            let serialized = serde_json::to_string(&result).unwrap();
            assert!(!serialized.contains("raw-device"));
            assert!(!serialized.contains("source-id"));
            let mut unsafe_record = record.clone();
            unsafe_record["payload"] = "SECRET".into();
            assert!(
                import_security_logs_json(
                    &serde_json::to_vec(&vec![unsafe_record]).unwrap(),
                    source,
                    &config
                )
                .is_err()
            );
        }
    }
}
