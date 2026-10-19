//! Stable domain contracts for Gödel Tally.
//!
//! This crate deliberately contains no database, HTTP, or connector implementation. Most
//! importantly, the observation contract has no place to put prompt, response, document, message,
//! source-code, clipboard, or request-body content.

mod attribution;
mod claim;
mod entity;
mod integration;
mod observation;

pub use attribution::{
    AttributionConflict, AttributionConflictStatus, AttributionConflictType,
    AttributionContractError, AttributionReplayCheckpoint, EntityKey, EntityKeyAuthority,
    EntityKeyStatus, EntityRelationship, RelationshipEvidence, RelationshipPredicate,
    RelationshipStatus, RelationshipSupportRole,
};
pub use claim::{
    BasisPoints, BasisPointsError, Claim, ClaimClass, ClaimPredicate, ClaimStatus, RiskFinding,
    RiskSeverity, RuleRef,
};
pub use entity::{
    AiSystemView, AuthorizationStatus, Entity, EntityKind, EntityRef, EvidenceQuality, Lifecycle,
    Surface,
};
pub use integration::{
    ConnectorContribution, ConnectorHealth, ConnectorManagementCapability, ConnectorSourceFamily,
    ContributionProducer, EvidenceAvailability, EvidenceLinkContribution, FindingContribution,
    FindingContributionStatus, HOST_CONTEXT_AUDIENCE, HOST_CONTEXT_ISSUER, HostContextSignature,
    HostRequestContext, HostSignatureAlgorithm, INTEGRATION_SCHEMA_VERSION,
    IntegrationContractBundle, IntegrationContractError, InventoryContribution,
    InventoryRelationshipSummary, ReportMetricContribution, ReportSectionContribution,
    SignedHostRequestContext, TallyCapability,
};
pub use observation::{
    ActorObservation, AgentObservation, CloudLifecycleState, CloudObservation, CloudProvider,
    CloudProviderService, CloudResourceKind, CloudUsageKind, ConnectorRef, DestinationObservation,
    DigestAlgorithm, EvidenceReceipt, FlowDirection, Hostname, IdentityAuthority,
    IdentityObservation, IdentitySubjectKind, IpAddress, NetworkObservation, Observation,
    ObservationKind, OutcomeObservation, RequestClientKind, RequestClientObservation,
    SaasCapabilityState, SaasObservation, SaasSanctionStatus, ServiceObservation, WorkloadKind,
    WorkloadObservation,
};

/// Current wire schema for canonical observations.
pub const OBSERVATION_SCHEMA_VERSION: &str = "1.0.0-alpha.4";
