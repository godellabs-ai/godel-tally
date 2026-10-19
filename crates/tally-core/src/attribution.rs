use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{BasisPoints, EntityRef, RuleRef};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct EntityKey {
    pub installation_id: Uuid,
    pub key_type: String,
    pub key_value: String,
    pub entity_id: Uuid,
    pub authority: EntityKeyAuthority,
    pub strength: BasisPoints,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub status: EntityKeyStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_observation_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_lineage_id: Option<String>,
    pub revision: i64,
}

impl EntityKey {
    /// Validates bounded key metadata and temporal invariants.
    ///
    /// # Errors
    ///
    /// Returns [`AttributionContractError`] for an unsafe key type/value, lineage token, time
    /// interval, or revision.
    pub fn validate(&self) -> Result<(), AttributionContractError> {
        if !safe_machine_token(&self.key_type, 64) {
            return Err(AttributionContractError::UnsafeKeyType);
        }
        if self.key_value.is_empty()
            || self.key_value.len() > 512
            || self.key_value.chars().any(char::is_control)
        {
            return Err(AttributionContractError::UnsafeKeyValue);
        }
        if self.last_seen < self.first_seen {
            return Err(AttributionContractError::InvalidValidity);
        }
        if self.revision < 1 {
            return Err(AttributionContractError::InvalidRevision);
        }
        if self
            .source_lineage_id
            .as_deref()
            .is_some_and(|value| !safe_opaque_token(value, 160))
        {
            return Err(AttributionContractError::UnsafeLineage);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntityKeyAuthority {
    ProviderResource,
    Casb,
    IdentityDirectory,
    KubernetesApi,
    Registry,
    LocalOperator,
    NetworkMapping,
    DerivedRule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntityKeyStatus {
    Active,
    Disputed,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct EntityRelationship {
    pub relationship_id: Uuid,
    pub installation_id: Uuid,
    pub subject: EntityRef,
    pub predicate: RelationshipPredicate,
    pub object: EntityRef,
    pub confidence: BasisPoints,
    pub status: RelationshipStatus,
    pub valid_from: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<RuleRef>,
    pub independent_lineage_count: u32,
    pub created_at: DateTime<Utc>,
    pub revision: i64,
}

impl EntityRelationship {
    pub fn deterministic_id(
        installation_id: Uuid,
        subject_entity_id: Uuid,
        predicate: RelationshipPredicate,
        object_entity_id: Uuid,
    ) -> Uuid {
        Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!(
                "godel-tally:relationship:{installation_id}:{subject_entity_id}:{}:{object_entity_id}",
                predicate.as_str()
            )
            .as_bytes(),
        )
    }

    /// Validates deterministic identity, direction, validity, rule, and revision invariants.
    ///
    /// # Errors
    ///
    /// Returns [`AttributionContractError`] when the relationship cannot be persisted safely.
    pub fn validate(&self) -> Result<(), AttributionContractError> {
        if self.subject.entity_id == self.object.entity_id {
            return Err(AttributionContractError::SelfRelationship);
        }
        let expected = Self::deterministic_id(
            self.installation_id,
            self.subject.entity_id,
            self.predicate,
            self.object.entity_id,
        );
        if self.relationship_id != expected {
            return Err(AttributionContractError::NonDeterministicRelationshipId);
        }
        if self
            .valid_until
            .is_some_and(|until| until < self.valid_from)
        {
            return Err(AttributionContractError::InvalidValidity);
        }
        if self.revision < 1 {
            return Err(AttributionContractError::InvalidRevision);
        }
        if self.rule.as_ref().is_some_and(|rule| {
            !safe_machine_token(&rule.rule_id, 128) || !safe_machine_token(&rule.version, 64)
        }) {
            return Err(AttributionContractError::UnsafeRule);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipPredicate {
    Contains,
    Uses,
    Assigned,
    Enables,
    Serves,
    AddressOf,
    Owns,
    MemberOf,
}

impl RelationshipPredicate {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Contains => "contains",
            Self::Uses => "uses",
            Self::Assigned => "assigned",
            Self::Enables => "enables",
            Self::Serves => "serves",
            Self::AddressOf => "address_of",
            Self::Owns => "owns",
            Self::MemberOf => "member_of",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipStatus {
    Active,
    Superseded,
    Disputed,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct RelationshipEvidence {
    pub relationship_id: Uuid,
    pub observation_id: Uuid,
    pub source_lineage_id: String,
    pub support_role: RelationshipSupportRole,
    /// Source-authoritative start for this individual evidence link, when supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,
    /// Source-authoritative end for this individual evidence link, when supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
}

impl RelationshipEvidence {
    /// Validates the bounded lineage token used for independent-source counting.
    ///
    /// # Errors
    ///
    /// Returns [`AttributionContractError`] if the token is unsafe or unbounded.
    pub fn validate(&self) -> Result<(), AttributionContractError> {
        if !safe_opaque_token(&self.source_lineage_id, 160) {
            return Err(AttributionContractError::UnsafeLineage);
        }
        if self.valid_from.is_none() && self.valid_until.is_some() {
            return Err(AttributionContractError::InvalidValidity);
        }
        if self
            .valid_from
            .zip(self.valid_until)
            .is_some_and(|(from, until)| until < from)
        {
            return Err(AttributionContractError::InvalidValidity);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipSupportRole {
    Supporting,
    Contradicting,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct AttributionConflict {
    pub conflict_id: Uuid,
    pub installation_id: Uuid,
    pub conflict_type: AttributionConflictType,
    pub subject_entity_id: Uuid,
    pub source_relationship_id: Uuid,
    pub source_observation_id: Uuid,
    pub candidate_count: u32,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub status: AttributionConflictStatus,
    pub rule: RuleRef,
    pub evidence_observation_ids: Vec<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revision: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttributionConflictType {
    CompetingNetworkMapping,
    CompetingSystemMapping,
}

impl AttributionConflictType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompetingNetworkMapping => "competing_network_mapping",
            Self::CompetingSystemMapping => "competing_system_mapping",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttributionConflictStatus {
    Open,
    Cleared,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct AttributionReplayCheckpoint {
    pub installation_id: Uuid,
    pub resolver: RuleRef,
    pub observation_high_watermark: DateTime<Utc>,
    pub projection_digest: String,
    pub revision: i64,
    pub updated_at: DateTime<Utc>,
}

impl AttributionReplayCheckpoint {
    /// Validates resolver identity, projection digest, and revision invariants.
    ///
    /// # Errors
    ///
    /// Returns [`AttributionContractError`] when the checkpoint is unsafe or malformed.
    pub fn validate(&self) -> Result<(), AttributionContractError> {
        if !safe_machine_token(&self.resolver.rule_id, 128)
            || !safe_machine_token(&self.resolver.version, 64)
        {
            return Err(AttributionContractError::UnsafeRule);
        }
        if self.projection_digest.len() != 64
            || !self
                .projection_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AttributionContractError::InvalidProjectionDigest);
        }
        if self.revision < 1 {
            return Err(AttributionContractError::InvalidRevision);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AttributionContractError {
    #[error("entity key type is not a bounded machine token")]
    UnsafeKeyType,
    #[error("entity key value is empty, unbounded, or contains control characters")]
    UnsafeKeyValue,
    #[error("source lineage identifier is empty, unbounded, or contains control characters")]
    UnsafeLineage,
    #[error("relationship rule reference is unsafe")]
    UnsafeRule,
    #[error("validity interval ends before it begins")]
    InvalidValidity,
    #[error("revision must be at least one")]
    InvalidRevision,
    #[error("a relationship cannot point an entity to itself")]
    SelfRelationship,
    #[error("relationship identifier does not match its deterministic identity")]
    NonDeterministicRelationshipId,
    #[error("projection digest must be a lowercase SHA-256 value")]
    InvalidProjectionDigest,
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

fn safe_opaque_token(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EntityKind;

    fn relationship() -> EntityRelationship {
        let installation_id = Uuid::from_u128(1);
        let subject = EntityRef {
            entity_id: Uuid::from_u128(2),
            kind: EntityKind::Workload,
        };
        let object = EntityRef {
            entity_id: Uuid::from_u128(3),
            kind: EntityKind::AiSystem,
        };
        EntityRelationship {
            relationship_id: EntityRelationship::deterministic_id(
                installation_id,
                subject.entity_id,
                RelationshipPredicate::Uses,
                object.entity_id,
            ),
            installation_id,
            subject,
            predicate: RelationshipPredicate::Uses,
            object,
            confidence: BasisPoints::MAX,
            status: RelationshipStatus::Active,
            valid_from: DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("timestamp"),
            valid_until: None,
            rule: Some(RuleRef {
                rule_id: "exact_provider_key".to_owned(),
                version: "1".to_owned(),
            }),
            independent_lineage_count: 1,
            created_at: DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("timestamp"),
            revision: 1,
        }
    }

    #[test]
    fn relationship_id_is_stable_and_directional() {
        let relationship = relationship();
        assert!(relationship.validate().is_ok());
        assert_eq!(
            relationship.relationship_id,
            EntityRelationship::deterministic_id(
                relationship.installation_id,
                relationship.subject.entity_id,
                relationship.predicate,
                relationship.object.entity_id,
            )
        );
        assert_ne!(
            relationship.relationship_id,
            EntityRelationship::deterministic_id(
                relationship.installation_id,
                relationship.object.entity_id,
                relationship.predicate,
                relationship.subject.entity_id,
            )
        );
    }

    #[test]
    fn relationship_rejects_self_edges_and_invalid_intervals() {
        let mut self_edge = relationship();
        self_edge.object = self_edge.subject;
        self_edge.relationship_id = EntityRelationship::deterministic_id(
            self_edge.installation_id,
            self_edge.subject.entity_id,
            self_edge.predicate,
            self_edge.object.entity_id,
        );
        assert_eq!(
            self_edge.validate(),
            Err(AttributionContractError::SelfRelationship)
        );

        let mut invalid_interval = relationship();
        invalid_interval.valid_until = invalid_interval
            .valid_from
            .checked_sub_signed(chrono::Duration::seconds(1));
        assert_eq!(
            invalid_interval.validate(),
            Err(AttributionContractError::InvalidValidity)
        );
    }

    #[test]
    fn entity_key_rejects_content_shaped_metadata() {
        let at = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("timestamp");
        let mut key = EntityKey {
            installation_id: Uuid::from_u128(1),
            key_type: "aws_resource_key".to_owned(),
            key_value: "p1_123".to_owned(),
            entity_id: Uuid::from_u128(2),
            authority: EntityKeyAuthority::ProviderResource,
            strength: BasisPoints::MAX,
            first_seen: at,
            last_seen: at,
            status: EntityKeyStatus::Active,
            source_observation_id: Some(Uuid::from_u128(3)),
            source_lineage_id: Some("aws:account:p1_456".to_owned()),
            revision: 1,
        };
        assert!(key.validate().is_ok());
        key.key_value = "unsafe\nvalue".to_owned();
        assert_eq!(
            key.validate(),
            Err(AttributionContractError::UnsafeKeyValue)
        );
    }
}
