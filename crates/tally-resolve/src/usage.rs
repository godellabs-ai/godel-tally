use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tally_core::{
    AttributionConflict, AttributionConflictStatus, AttributionConflictType, BasisPoints, Claim,
    ClaimClass, ClaimPredicate, ClaimStatus, EntityKind, EntityRef, EntityRelationship,
    RelationshipEvidence, RelationshipPredicate, RelationshipStatus, RelationshipSupportRole,
    RuleRef,
};
use thiserror::Error;
use uuid::Uuid;

use crate::RESOLVER_RULE_VERSION;

pub const CLOUD_USAGE_RULE_ID: &str = "cloud_network_usage_exact_path";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageEvidenceInput {
    pub observation_id: Uuid,
    pub source_lineage_id: String,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudUsageProjectionInput {
    pub installation_id: Uuid,
    pub source_asset_id: Uuid,
    pub destination_asset_id: Uuid,
    pub mapped_resource_id: Uuid,
    pub system_id: Uuid,
    pub flow_relationship_id: Uuid,
    pub mapping_relationship_id: Uuid,
    pub serves_relationship_id: Uuid,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub flow_evidence: UsageEvidenceInput,
    pub mapping_evidence: Vec<UsageEvidenceInput>,
    pub inventory_evidence: Vec<UsageEvidenceInput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedCloudUsage {
    pub relationship: EntityRelationship,
    pub relationship_evidence: Vec<RelationshipEvidence>,
    pub claim: Claim,
    pub claim_evidence_observation_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudUsageConflictInput {
    pub installation_id: Uuid,
    pub destination_asset_id: Uuid,
    pub flow_relationship_id: Uuid,
    pub flow_observation_id: Uuid,
    pub conflict_type: AttributionConflictType,
    pub candidate_count: u32,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub evidence_observation_ids: Vec<Uuid>,
}

/// Produces a deterministic, content-free conflict for one ambiguous flow attribution.
///
/// # Errors
///
/// Returns [`CloudUsageResolutionError::InvalidConflict`] when candidate count, evidence bounds,
/// or the validity interval cannot form a safe conflict projection.
pub fn resolve_cloud_usage_conflict(
    input: &CloudUsageConflictInput,
) -> Result<AttributionConflict, CloudUsageResolutionError> {
    if input.candidate_count < 2
        || input.valid_until <= input.valid_from
        || input.evidence_observation_ids.is_empty()
        || input.evidence_observation_ids.len() > 256
    {
        return Err(CloudUsageResolutionError::InvalidConflict);
    }
    let mut evidence_observation_ids = input.evidence_observation_ids.clone();
    evidence_observation_ids.sort_unstable();
    evidence_observation_ids.dedup();
    let conflict_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!(
            "godel-tally:attribution-conflict:{}:{}:{}:{}",
            input.installation_id,
            input.flow_relationship_id,
            input.flow_observation_id,
            input.conflict_type.as_str()
        )
        .as_bytes(),
    );
    Ok(AttributionConflict {
        conflict_id,
        installation_id: input.installation_id,
        conflict_type: input.conflict_type,
        subject_entity_id: input.destination_asset_id,
        source_relationship_id: input.flow_relationship_id,
        source_observation_id: input.flow_observation_id,
        candidate_count: input.candidate_count,
        valid_from: input.valid_from,
        valid_until: input.valid_until,
        status: AttributionConflictStatus::Open,
        rule: rule(),
        evidence_observation_ids,
        created_at: input.valid_from,
        updated_at: input.valid_from,
        revision: 1,
    })
}

/// Projects one exact, unambiguous network-flow path into a bounded system-use assertion.
///
/// The claim explicitly records that the evidence proves a network exchange, not an invocation or
/// any request/response content.
///
/// # Errors
///
/// Returns [`CloudUsageResolutionError`] when entity kinds, validity, deterministic relationship
/// identities, or the three-source evidence chain are incomplete or inconsistent.
pub fn resolve_cloud_usage(
    input: &CloudUsageProjectionInput,
) -> Result<ResolvedCloudUsage, CloudUsageResolutionError> {
    validate_input(input)?;
    let subject = EntityRef {
        entity_id: input.source_asset_id,
        kind: EntityKind::NetworkAsset,
    };
    let object = EntityRef {
        entity_id: input.system_id,
        kind: EntityKind::AiSystem,
    };
    let relationship_id = EntityRelationship::deterministic_id(
        input.installation_id,
        subject.entity_id,
        RelationshipPredicate::Uses,
        object.entity_id,
    );
    let rule = rule();
    let confidence =
        BasisPoints::new(9_500).map_err(|_| CloudUsageResolutionError::InvalidEntityPath)?;
    let relationship = EntityRelationship {
        relationship_id,
        installation_id: input.installation_id,
        subject,
        predicate: RelationshipPredicate::Uses,
        object,
        confidence,
        status: RelationshipStatus::Active,
        valid_from: input.valid_from,
        valid_until: Some(input.valid_until),
        rule: Some(rule.clone()),
        independent_lineage_count: 0,
        created_at: input.valid_from,
        revision: 1,
    };
    let mut evidence =
        Vec::with_capacity(1 + input.mapping_evidence.len() + input.inventory_evidence.len());
    evidence.push(input.flow_evidence.clone());
    evidence.extend(input.mapping_evidence.iter().cloned());
    evidence.extend(input.inventory_evidence.iter().cloned());
    evidence.sort_by_key(|item| item.observation_id);
    evidence.dedup_by_key(|item| item.observation_id);
    let relationship_evidence = evidence
        .iter()
        .map(|item| RelationshipEvidence {
            relationship_id,
            observation_id: item.observation_id,
            source_lineage_id: item.source_lineage_id.clone(),
            support_role: RelationshipSupportRole::Supporting,
            valid_from: item.valid_from,
            valid_until: item.valid_until,
        })
        .collect::<Vec<_>>();
    let value = serde_json::json!({
        "activity": "network_exchange",
        "invocation_proven": false
    });
    let claim_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!(
            "godel-tally:cloud-usage-claim:{}:{}:{}:{}",
            input.system_id,
            input.flow_evidence.observation_id,
            input.mapped_resource_id,
            RESOLVER_RULE_VERSION
        )
        .as_bytes(),
    );
    let claim = Claim {
        claim_id,
        subject: object,
        predicate: ClaimPredicate::ResourceUsed,
        value,
        class: ClaimClass::Derived,
        confidence,
        status: ClaimStatus::Active,
        valid_from: input.valid_from,
        valid_until: Some(input.valid_until),
        rule: Some(rule),
        registry_version: None,
        created_at: input.valid_from,
    };
    let claim_evidence_observation_ids = evidence
        .into_iter()
        .map(|item| item.observation_id)
        .collect();
    Ok(ResolvedCloudUsage {
        relationship,
        relationship_evidence,
        claim,
        claim_evidence_observation_ids,
    })
}

fn validate_input(input: &CloudUsageProjectionInput) -> Result<(), CloudUsageResolutionError> {
    if input.valid_until <= input.valid_from {
        return Err(CloudUsageResolutionError::InvalidValidity);
    }
    if input.mapping_evidence.is_empty() || input.inventory_evidence.is_empty() {
        return Err(CloudUsageResolutionError::IncompleteEvidence);
    }
    if input.source_asset_id == input.destination_asset_id
        || input.destination_asset_id == input.mapped_resource_id
        || input.mapped_resource_id == input.system_id
    {
        return Err(CloudUsageResolutionError::InvalidEntityPath);
    }
    let expected_flow = EntityRelationship::deterministic_id(
        input.installation_id,
        input.source_asset_id,
        RelationshipPredicate::Uses,
        input.destination_asset_id,
    );
    let expected_mapping = EntityRelationship::deterministic_id(
        input.installation_id,
        input.destination_asset_id,
        RelationshipPredicate::AddressOf,
        input.mapped_resource_id,
    );
    let expected_serves = EntityRelationship::deterministic_id(
        input.installation_id,
        input.mapped_resource_id,
        RelationshipPredicate::Serves,
        input.system_id,
    );
    if input.flow_relationship_id != expected_flow
        || input.mapping_relationship_id != expected_mapping
        || input.serves_relationship_id != expected_serves
    {
        return Err(CloudUsageResolutionError::InvalidEntityPath);
    }
    Ok(())
}

fn rule() -> RuleRef {
    RuleRef {
        rule_id: CLOUD_USAGE_RULE_ID.to_owned(),
        version: RESOLVER_RULE_VERSION.to_owned(),
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CloudUsageResolutionError {
    #[error("cloud usage path has an invalid validity intersection")]
    InvalidValidity,
    #[error("cloud usage path does not contain flow, mapping, and inventory evidence")]
    IncompleteEvidence,
    #[error("cloud usage path contains inconsistent deterministic entity relationships")]
    InvalidEntityPath,
    #[error("cloud usage attribution conflict is incomplete or unbounded")]
    InvalidConflict,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> CloudUsageProjectionInput {
        let installation_id = Uuid::parse_str("018f6cd4-4aaf-7bb4-a3b2-a7524ec43711").unwrap();
        let source_asset_id = Uuid::parse_str("018f6cd4-4aaf-7bb4-a3b2-a7524ec43721").unwrap();
        let destination_asset_id = Uuid::parse_str("018f6cd4-4aaf-7bb4-a3b2-a7524ec43722").unwrap();
        let mapped_resource_id = Uuid::parse_str("018f6cd4-4aaf-7bb4-a3b2-a7524ec43723").unwrap();
        let system_id = Uuid::parse_str("018f6cd4-4aaf-7bb4-a3b2-a7524ec43724").unwrap();
        let evidence = |suffix: &str| UsageEvidenceInput {
            observation_id: Uuid::new_v5(&Uuid::NAMESPACE_URL, suffix.as_bytes()),
            source_lineage_id: format!("fixture:{suffix}"),
            valid_from: Some("2026-08-13T10:00:00Z".parse().unwrap()),
            valid_until: Some("2026-08-13T10:05:00Z".parse().unwrap()),
        };
        CloudUsageProjectionInput {
            installation_id,
            source_asset_id,
            destination_asset_id,
            mapped_resource_id,
            system_id,
            flow_relationship_id: EntityRelationship::deterministic_id(
                installation_id,
                source_asset_id,
                RelationshipPredicate::Uses,
                destination_asset_id,
            ),
            mapping_relationship_id: EntityRelationship::deterministic_id(
                installation_id,
                destination_asset_id,
                RelationshipPredicate::AddressOf,
                mapped_resource_id,
            ),
            serves_relationship_id: EntityRelationship::deterministic_id(
                installation_id,
                mapped_resource_id,
                RelationshipPredicate::Serves,
                system_id,
            ),
            valid_from: "2026-08-13T10:00:00Z".parse().unwrap(),
            valid_until: "2026-08-13T10:05:00Z".parse().unwrap(),
            flow_evidence: evidence("flow"),
            mapping_evidence: vec![evidence("mapping")],
            inventory_evidence: vec![evidence("inventory")],
        }
    }

    #[test]
    fn exact_path_creates_bounded_non_invocation_usage_with_three_evidence_links() {
        let resolved = resolve_cloud_usage(&fixture()).unwrap();
        assert_eq!(resolved.claim.predicate, ClaimPredicate::ResourceUsed);
        assert_eq!(resolved.claim.value["activity"], "network_exchange");
        assert_eq!(resolved.claim.value["invocation_proven"], false);
        assert_eq!(resolved.claim_evidence_observation_ids.len(), 3);
        assert_eq!(resolved.relationship_evidence.len(), 3);
        assert_eq!(
            resolved.relationship.valid_until,
            resolved.claim.valid_until
        );
    }

    #[test]
    fn malformed_or_incomplete_paths_fail_closed() {
        let mut missing = fixture();
        missing.mapping_evidence.clear();
        assert_eq!(
            resolve_cloud_usage(&missing),
            Err(CloudUsageResolutionError::IncompleteEvidence)
        );
        let mut wrong_edge = fixture();
        wrong_edge.serves_relationship_id = Uuid::nil();
        assert_eq!(
            resolve_cloud_usage(&wrong_edge),
            Err(CloudUsageResolutionError::InvalidEntityPath)
        );
    }

    #[test]
    fn competing_mappings_create_a_content_free_deterministic_conflict() {
        let value = fixture();
        let input = CloudUsageConflictInput {
            installation_id: value.installation_id,
            destination_asset_id: value.destination_asset_id,
            flow_relationship_id: value.flow_relationship_id,
            flow_observation_id: value.flow_evidence.observation_id,
            conflict_type: AttributionConflictType::CompetingNetworkMapping,
            candidate_count: 2,
            valid_from: value.valid_from,
            valid_until: value.valid_until,
            evidence_observation_ids: vec![
                value.mapping_evidence[0].observation_id,
                value.flow_evidence.observation_id,
            ],
        };
        let first = resolve_cloud_usage_conflict(&input).unwrap();
        let second = resolve_cloud_usage_conflict(&input).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.status, AttributionConflictStatus::Open);
        assert_eq!(first.candidate_count, 2);
    }
}
