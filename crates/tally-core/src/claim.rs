use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::EntityRef;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct Claim {
    pub claim_id: Uuid,
    pub subject: EntityRef,
    pub predicate: ClaimPredicate,
    pub value: serde_json::Value,
    pub class: ClaimClass,
    pub confidence: BasisPoints,
    pub status: ClaimStatus,
    pub valid_from: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<RuleRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_version: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimPredicate {
    Provider,
    Product,
    ModelFamily,
    Surface,
    Owner,
    Actor,
    Destination,
    Deployment,
    ResourceExists,
    ResourceUsed,
    ResourceLifecycle,
    CapabilityEnabled,
    SanctionStatus,
    Jurisdiction,
    Authorization,
    Custom(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimClass {
    Observed,
    Derived,
    Declared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Active,
    Superseded,
    Disputed,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct RuleRef {
    pub rule_id: String,
    pub version: String,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema, ToSchema,
)]
#[serde(transparent)]
pub struct BasisPoints(u16);

impl BasisPoints {
    pub const ZERO: Self = Self(0);
    pub const MAX: Self = Self(10_000);

    /// Creates a bounded basis-points value.
    ///
    /// # Errors
    ///
    /// Returns [`BasisPointsError`] when `value` is greater than 10,000.
    pub fn new(value: u16) -> Result<Self, BasisPointsError> {
        if value <= Self::MAX.0 {
            Ok(Self(value))
        } else {
            Err(BasisPointsError(value))
        }
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("basis points must be between 0 and 10000, got {0}")]
pub struct BasisPointsError(u16);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct RiskFinding {
    pub finding_id: Uuid,
    pub policy_id: String,
    pub policy_version: String,
    pub title: String,
    pub severity: RiskSeverity,
    pub factor_codes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RiskSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_range_is_enforced() {
        assert_eq!(BasisPoints::new(10_000).expect("max").get(), 10_000);
        assert!(BasisPoints::new(10_001).is_err());
    }
}
