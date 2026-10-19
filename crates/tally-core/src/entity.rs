use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{BasisPoints, RiskFinding};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct Entity {
    pub entity_id: Uuid,
    pub kind: EntityKind,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub revision: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Provider,
    Product,
    ModelFamily,
    ServiceEndpoint,
    Deployment,
    SaasTenant,
    PseudonymousActor,
    CloudAccount,
    CloudResource,
    KubernetesCluster,
    KubernetesNamespace,
    Workload,
    NetworkAsset,
    NetworkZone,
    OrganizationScope,
    AiSystem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct EntityRef {
    pub entity_id: Uuid,
    pub kind: EntityKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct AiSystemView {
    pub system_id: Uuid,
    pub display_name: String,
    pub surface: Surface,
    pub lifecycle: Lifecycle,
    pub authorization: AuthorizationStatus,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub evidence_quality: EvidenceQuality,
    pub confidence: BasisPoints,
    pub findings: Vec<RiskFinding>,
    pub revision: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    SelfHosted,
    ExternalApi,
    Assistant,
    EmbeddedSaas,
    ManagedCloud,
    ModelHub,
    AgentOrMcp,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Observed,
    Active,
    Stale,
    Retired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    Discovered,
    UnderReview,
    Authorized,
    Unauthorized,
    Retired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceQuality {
    Strong,
    Moderate,
    Weak,
    Conflicted,
    Unknown,
}
