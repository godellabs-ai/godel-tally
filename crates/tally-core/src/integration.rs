use chrono::{DateTime, Duration, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    AuthorizationStatus, BasisPoints, EntityRef, EvidenceQuality, Lifecycle, RelationshipPredicate,
    RiskSeverity, Surface,
};

pub const INTEGRATION_SCHEMA_VERSION: &str = "1.0.0-alpha.1";
pub const HOST_CONTEXT_ISSUER: &str = "tally-host";
pub const HOST_CONTEXT_AUDIENCE: &str = "godel-tally";
const MAX_HOST_CONTEXT_LIFETIME: Duration = Duration::minutes(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContributionProducer {
    GodelTally,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceLinkContribution {
    pub schema_version: String,
    pub producer: ContributionProducer,
    pub evidence_id: Uuid,
    pub observation_id: Uuid,
    pub source_kind: String,
    pub receipt_sha256: String,
    pub observed_at: DateTime<Utc>,
    pub availability: EvidenceAvailability,
    pub resource_path: String,
}

impl EvidenceLinkContribution {
    /// Validates the content-free evidence reference shared with the host product.
    ///
    /// # Errors
    ///
    /// Returns [`IntegrationContractError`] when a version, token, digest, or resource path is
    /// outside the frozen integration contract.
    pub fn validate(&self) -> Result<(), IntegrationContractError> {
        validate_schema_version(&self.schema_version)?;
        if !safe_machine_token(&self.source_kind, 64) {
            return Err(IntegrationContractError::UnsafeSourceKind);
        }
        if !lowercase_sha256(&self.receipt_sha256) {
            return Err(IntegrationContractError::InvalidDigest);
        }
        validate_resource_path(&self.resource_path)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAvailability {
    Dereferenceable,
    ReceiptOnly,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct InventoryRelationshipSummary {
    pub relationship_id: Uuid,
    pub subject: EntityRef,
    pub predicate: RelationshipPredicate,
    pub object: EntityRef,
    pub confidence: BasisPoints,
    pub valid_from: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    pub revision: i64,
}

impl InventoryRelationshipSummary {
    fn validate(&self) -> Result<(), IntegrationContractError> {
        if self.subject.entity_id == self.object.entity_id {
            return Err(IntegrationContractError::SelfRelationship);
        }
        if self
            .valid_until
            .is_some_and(|until| until < self.valid_from)
        {
            return Err(IntegrationContractError::InvalidValidity);
        }
        validate_revision(self.revision)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct InventoryContribution {
    pub schema_version: String,
    pub producer: ContributionProducer,
    pub contribution_id: Uuid,
    pub installation_id: Uuid,
    pub entity: EntityRef,
    pub display_label: String,
    pub surface: Surface,
    pub lifecycle: Lifecycle,
    pub authorization: AuthorizationStatus,
    pub evidence_quality: EvidenceQuality,
    pub confidence: BasisPoints,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub relationships: Vec<InventoryRelationshipSummary>,
    pub evidence: Vec<EvidenceLinkContribution>,
    pub resource_path: String,
    pub revision: i64,
}

impl InventoryContribution {
    /// Validates a bounded, read-only inventory projection for a host application.
    ///
    /// # Errors
    ///
    /// Returns [`IntegrationContractError`] when the contribution is unbounded, temporally
    /// invalid, contains an unsafe label/path, or embeds an invalid evidence reference.
    pub fn validate(&self) -> Result<(), IntegrationContractError> {
        validate_schema_version(&self.schema_version)?;
        validate_label(&self.display_label, 160)?;
        if self.last_seen < self.first_seen {
            return Err(IntegrationContractError::InvalidValidity);
        }
        validate_revision(self.revision)?;
        validate_resource_path(&self.resource_path)?;
        if self.relationships.len() > 128 || self.evidence.len() > 128 {
            return Err(IntegrationContractError::UnboundedCollection);
        }
        for relationship in &self.relationships {
            relationship.validate()?;
        }
        for evidence in &self.evidence {
            evidence.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorSourceFamily {
    Dns,
    SecureWebGateway,
    NetworkScanner,
    ManagedCloud,
    CloudFlow,
    CloudResourceMapping,
    CasbCapability,
    KubernetesApi,
    AiGateway,
    FileImport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorHealth {
    Healthy,
    Degraded,
    Stale,
    Paused,
    Error,
    Unknown,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorManagementCapability {
    View,
    ConfigureReference,
    Pause,
    Resume,
    Retry,
    BackfillPreview,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorContribution {
    pub schema_version: String,
    pub producer: ContributionProducer,
    pub connector_id: String,
    pub connector_type: String,
    pub display_label: String,
    pub source_family: ConnectorSourceFamily,
    pub health: ConnectorHealth,
    pub capabilities: Vec<ConnectorManagementCapability>,
    pub setup_schema_path: String,
    pub permission_manifest_path: String,
    pub resource_path: String,
    pub updated_at: DateTime<Utc>,
    pub revision: i64,
}

impl ConnectorContribution {
    /// Validates a connector descriptor that cannot carry credential values.
    ///
    /// # Errors
    ///
    /// Returns [`IntegrationContractError`] for unsafe identifiers, labels, paths, ordering, or
    /// revision metadata.
    pub fn validate(&self) -> Result<(), IntegrationContractError> {
        validate_schema_version(&self.schema_version)?;
        if !safe_machine_token(&self.connector_id, 128)
            || !safe_machine_token(&self.connector_type, 96)
        {
            return Err(IntegrationContractError::UnsafeConnectorIdentifier);
        }
        validate_label(&self.display_label, 160)?;
        validate_capabilities(&self.capabilities)?;
        validate_resource_path(&self.setup_schema_path)?;
        validate_resource_path(&self.permission_manifest_path)?;
        validate_resource_path(&self.resource_path)?;
        validate_revision(self.revision)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FindingContributionStatus {
    Open,
    Resolved,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct FindingContribution {
    pub schema_version: String,
    pub producer: ContributionProducer,
    pub finding_id: Uuid,
    pub system_id: Uuid,
    pub title: String,
    pub severity: RiskSeverity,
    pub status: FindingContributionStatus,
    pub policy_id: String,
    pub policy_version: String,
    pub factor_codes: Vec<String>,
    pub evidence: Vec<EvidenceLinkContribution>,
    pub resource_path: String,
    pub updated_at: DateTime<Utc>,
    pub revision: i64,
}

impl FindingContribution {
    /// Validates a discovery finding projection without introducing a second policy workflow.
    ///
    /// # Errors
    ///
    /// Returns [`IntegrationContractError`] when labels, factor identifiers, evidence, or revision
    /// metadata violate the frozen contribution contract.
    pub fn validate(&self) -> Result<(), IntegrationContractError> {
        validate_schema_version(&self.schema_version)?;
        validate_label(&self.title, 200)?;
        if !safe_machine_token(&self.policy_id, 128)
            || !safe_machine_token(&self.policy_version, 64)
            || self.factor_codes.len() > 64
            || self
                .factor_codes
                .iter()
                .any(|code| !safe_machine_token(code, 96))
        {
            return Err(IntegrationContractError::UnsafeFindingMetadata);
        }
        if self.evidence.len() > 128 {
            return Err(IntegrationContractError::UnboundedCollection);
        }
        for evidence in &self.evidence {
            evidence.validate()?;
        }
        validate_resource_path(&self.resource_path)?;
        validate_revision(self.revision)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportMetricContribution {
    pub metric_code: String,
    pub label: String,
    pub value: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportSectionContribution {
    pub schema_version: String,
    pub producer: ContributionProducer,
    pub section_id: String,
    pub title: String,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub metrics: Vec<ReportMetricContribution>,
    pub resource_path: String,
    pub generated_at: DateTime<Utc>,
    pub revision: i64,
}

impl ReportSectionContribution {
    /// Validates a bounded, sanitized section consumed by Gate's report generator.
    ///
    /// # Errors
    ///
    /// Returns [`IntegrationContractError`] when the section is unbounded or contains unsafe
    /// labels, metric codes, paths, validity, or revision metadata.
    pub fn validate(&self) -> Result<(), IntegrationContractError> {
        validate_schema_version(&self.schema_version)?;
        if !safe_machine_token(&self.section_id, 96) {
            return Err(IntegrationContractError::UnsafeReportMetadata);
        }
        validate_label(&self.title, 160)?;
        if self.window_end < self.window_start {
            return Err(IntegrationContractError::InvalidValidity);
        }
        if self.metrics.len() > 64 {
            return Err(IntegrationContractError::UnboundedCollection);
        }
        for metric in &self.metrics {
            if !safe_machine_token(&metric.metric_code, 96) {
                return Err(IntegrationContractError::UnsafeReportMetadata);
            }
            validate_label(&metric.label, 120)?;
        }
        validate_resource_path(&self.resource_path)?;
        validate_revision(self.revision)
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TallyCapability {
    ReadInventory,
    ReadEvidence,
    ReadConnectors,
    ManageConnectorReferences,
    RunScanner,
    ManageRegistry,
    ManageLocalAuthorization,
    PurgeEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HostRequestContext {
    pub schema_version: String,
    pub issuer: String,
    pub audience: String,
    pub actor_key: String,
    pub capabilities: Vec<TallyCapability>,
    pub correlation_id: Uuid,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl HostRequestContext {
    fn validate(&self, now: DateTime<Utc>) -> Result<(), IntegrationContractError> {
        validate_schema_version(&self.schema_version)?;
        if self.issuer != HOST_CONTEXT_ISSUER || self.audience != HOST_CONTEXT_AUDIENCE {
            return Err(IntegrationContractError::InvalidHostAuthority);
        }
        if !safe_machine_token(&self.actor_key, 160) {
            return Err(IntegrationContractError::UnsafeActorKey);
        }
        validate_capabilities(&self.capabilities)?;
        let lifetime = self.expires_at - self.issued_at;
        if lifetime <= Duration::zero()
            || lifetime > MAX_HOST_CONTEXT_LIFETIME
            || self.expires_at <= now
            || self.issued_at > now + Duration::seconds(30)
        {
            return Err(IntegrationContractError::InvalidHostContextLifetime);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HostSignatureAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HostContextSignature {
    pub algorithm: HostSignatureAlgorithm,
    pub key_id: String,
    pub signature_base64url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedHostRequestContext {
    pub context: HostRequestContext,
    pub signature: HostContextSignature,
}

impl SignedHostRequestContext {
    /// Validates authority, audience, lifetime, capabilities, and detached-signature shape.
    /// Cryptographic verification remains the host adapter's responsibility.
    ///
    /// # Errors
    ///
    /// Returns [`IntegrationContractError`] when the context or signature envelope is malformed.
    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), IntegrationContractError> {
        self.context.validate(now)?;
        if !safe_machine_token(&self.signature.key_id, 128)
            || self.signature.signature_base64url.len() != 86
            || !self
                .signature
                .signature_base64url
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(IntegrationContractError::InvalidSignatureEnvelope);
        }
        Ok(())
    }

    /// Returns the deterministic JSON bytes that a host signs and Tally verifies.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] only if the frozen context cannot be serialized.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&self.context)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationContractBundle {
    pub inventory: InventoryContribution,
    pub connector: ConnectorContribution,
    pub finding: FindingContribution,
    pub evidence_link: EvidenceLinkContribution,
    pub report_section: ReportSectionContribution,
    pub host_request: SignedHostRequestContext,
}

impl IntegrationContractBundle {
    /// Validates the checked-in compatibility fixture as one coherent contract bundle.
    ///
    /// # Errors
    ///
    /// Returns [`IntegrationContractError`] from the first invalid contribution.
    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), IntegrationContractError> {
        self.inventory.validate()?;
        self.connector.validate()?;
        self.finding.validate()?;
        self.evidence_link.validate()?;
        self.report_section.validate()?;
        self.host_request.validate(now)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IntegrationContractError {
    #[error("unsupported integration schema version")]
    UnsupportedSchemaVersion,
    #[error("a display label is empty, unbounded, or contains control characters")]
    UnsafeLabel,
    #[error("source kind is not a bounded machine token")]
    UnsafeSourceKind,
    #[error("connector identifier is not a bounded machine token")]
    UnsafeConnectorIdentifier,
    #[error("finding metadata is unsafe or unbounded")]
    UnsafeFindingMetadata,
    #[error("report metadata is unsafe or unbounded")]
    UnsafeReportMetadata,
    #[error("actor key must be an opaque host-scoped machine token")]
    UnsafeActorKey,
    #[error("digest must be a lowercase SHA-256 value")]
    InvalidDigest,
    #[error("resource path must remain inside the Tally API namespace")]
    UnsafeResourcePath,
    #[error("validity interval ends before it begins")]
    InvalidValidity,
    #[error("revision must be at least one")]
    InvalidRevision,
    #[error("a relationship cannot point an entity to itself")]
    SelfRelationship,
    #[error("a contract collection is unbounded")]
    UnboundedCollection,
    #[error("capabilities must be non-empty, bounded, sorted, and unique")]
    InvalidCapabilities,
    #[error("host context issuer or audience is invalid")]
    InvalidHostAuthority,
    #[error("host context is expired or exceeds the five-minute lifetime")]
    InvalidHostContextLifetime,
    #[error("host context signature envelope is malformed")]
    InvalidSignatureEnvelope,
}

fn validate_schema_version(value: &str) -> Result<(), IntegrationContractError> {
    if value == INTEGRATION_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(IntegrationContractError::UnsupportedSchemaVersion)
    }
}

fn validate_label(value: &str, max_len: usize) -> Result<(), IntegrationContractError> {
    if value.is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
        Err(IntegrationContractError::UnsafeLabel)
    } else {
        Ok(())
    }
}

fn validate_revision(revision: i64) -> Result<(), IntegrationContractError> {
    if revision < 1 {
        Err(IntegrationContractError::InvalidRevision)
    } else {
        Ok(())
    }
}

fn validate_resource_path(value: &str) -> Result<(), IntegrationContractError> {
    if value.starts_with("/api/v1/tally/")
        && value.len() <= 512
        && !value.contains("..")
        && !value.contains(['?', '#', '\\'])
        && !value.chars().any(char::is_control)
    {
        Ok(())
    } else {
        Err(IntegrationContractError::UnsafeResourcePath)
    }
}

fn validate_capabilities<T: Ord>(capabilities: &[T]) -> Result<(), IntegrationContractError> {
    if capabilities.is_empty()
        || capabilities.len() > 16
        || capabilities.windows(2).any(|pair| pair[0] >= pair[1])
    {
        Err(IntegrationContractError::InvalidCapabilities)
    } else {
        Ok(())
    }
}

fn safe_machine_token(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'-' | b'.' | b':')
        })
}

fn lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> IntegrationContractBundle {
        serde_json::from_str(include_str!(
            "../../../testdata/integration/v1/contracts.json"
        ))
        .expect("integration fixture")
    }

    fn previous_minor_fixture() -> IntegrationContractBundle {
        serde_json::from_str(include_str!(
            "../../../testdata/integration/previous-minor/contracts.json"
        ))
        .expect("previous-compatible integration fixture")
    }

    #[test]
    fn compatibility_fixture_is_valid_and_canonical() {
        let fixture = fixture();
        let now = DateTime::parse_from_rfc3339("2026-08-14T10:02:00Z")
            .expect("time")
            .with_timezone(&Utc);
        fixture.validate(now).expect("valid contract bundle");

        let first = serde_json::to_vec(&fixture).expect("first serialization");
        let decoded: IntegrationContractBundle =
            serde_json::from_slice(&first).expect("fixture replay");
        let second = serde_json::to_vec(&decoded).expect("second serialization");
        assert_eq!(first, second);
        assert_eq!(
            fixture.host_request.signing_bytes().expect("signing bytes"),
            decoded
                .host_request
                .signing_bytes()
                .expect("replayed bytes")
        );
    }

    #[test]
    fn previous_minor_fixture_remains_compatible_and_canonical() {
        let fixture = previous_minor_fixture();
        let now = DateTime::parse_from_rfc3339("2026-08-14T10:02:00Z")
            .expect("time")
            .with_timezone(&Utc);
        fixture
            .validate(now)
            .expect("previous-compatible contract bundle");
        let first = serde_json::to_vec(&fixture).expect("first serialization");
        let decoded: IntegrationContractBundle =
            serde_json::from_slice(&first).expect("fixture replay");
        let second = serde_json::to_vec(&decoded).expect("second serialization");
        assert_eq!(first, second);
    }

    #[test]
    fn contract_has_no_identity_provider_or_user_management_surface() {
        let schema = serde_json::to_string(&schemars::schema_for!(IntegrationContractBundle))
            .expect("integration schema");
        for prohibited in [
            "okta",
            "entra",
            "oauth_grant",
            "email",
            "upn",
            "group_name",
            "role",
            "password",
            "api_key",
            "prompt",
            "response_body",
        ] {
            assert!(
                !schema.to_ascii_lowercase().contains(prohibited),
                "integration schema contains prohibited surface {prohibited}"
            );
        }
    }

    #[test]
    fn host_context_rejects_pii_shaped_actor_and_long_lifetime() {
        let mut signed = fixture().host_request;
        let now = DateTime::parse_from_rfc3339("2026-08-14T10:02:00Z")
            .expect("time")
            .with_timezone(&Utc);
        signed.context.actor_key = "person@example.com".to_owned();
        assert_eq!(
            signed.validate(now),
            Err(IntegrationContractError::UnsafeActorKey)
        );

        signed.context.actor_key = "host_actor:01".to_owned();
        signed.context.expires_at = signed.context.issued_at + Duration::minutes(6);
        assert_eq!(
            signed.validate(now),
            Err(IntegrationContractError::InvalidHostContextLifetime)
        );
    }

    #[test]
    fn unknown_fields_fail_closed() {
        let mut value = serde_json::to_value(fixture().connector).expect("connector JSON");
        value["credential_value"] = serde_json::json!("must-not-cross-boundary");
        assert!(serde_json::from_value::<ConnectorContribution>(value).is_err());
    }

    #[test]
    fn integration_schema_excludes_host_owned_identity_entity_kinds() {
        let schema = serde_json::to_string(&schemars::schema_for!(InventoryContribution))
            .expect("inventory schema");
        assert!(!schema.contains("oauth_application"));
        assert!(!schema.contains("identity_activity"));
        assert!(!schema.contains("\"identity\""));
    }
}
