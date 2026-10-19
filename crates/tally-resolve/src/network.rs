use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tally_core::{
    BasisPoints, CloudProvider, Entity, EntityKey, EntityKeyAuthority, EntityKeyStatus, EntityKind,
    EntityRef, EntityRelationship, Observation, ObservationKind, RelationshipEvidence,
    RelationshipPredicate, RelationshipStatus, RelationshipSupportRole, RuleRef,
};
use thiserror::Error;
use uuid::Uuid;

use crate::RESOLVER_RULE_VERSION;

const NETWORK_RULE_ID: &str = "cloud_network_exact_key";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedCloudNetwork {
    pub entities: Vec<Entity>,
    pub keys: Vec<EntityKey>,
    pub relationships: Vec<ResolvedNetworkRelationship>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedNetworkRelationship {
    pub relationship: EntityRelationship,
    pub evidence: Vec<RelationshipEvidence>,
}

/// Resolves a normalized flow or endpoint mapping into deterministic, time-valid network graph
/// entities and relationships.
///
/// # Errors
///
/// Returns [`NetworkResolutionError`] when required keys or validity metadata are missing, a key is
/// not an installation pseudonym, or a flow would create a self edge.
#[allow(clippy::too_many_lines)]
pub fn resolve_cloud_network(
    observation: &Observation,
) -> Result<ResolvedCloudNetwork, NetworkResolutionError> {
    if !matches!(
        observation.kind,
        ObservationKind::NetworkFlow | ObservationKind::NetworkMapping
    ) {
        return Err(NetworkResolutionError::UnsupportedObservationKind);
    }
    let provider = observation
        .cloud
        .provider
        .ok_or(NetworkResolutionError::MissingField("provider"))?;
    let account_key = pseudonym(observation.cloud.account_key.as_deref(), "account_key")?;
    let network_key = pseudonym(observation.network.network_key.as_deref(), "network_key")?;
    let valid_until = observation
        .network
        .valid_until
        .ok_or(NetworkResolutionError::MissingField("valid_until"))?;
    if valid_until <= observation.observed_at {
        return Err(NetworkResolutionError::InvalidValidity);
    }
    let lineage = observation
        .connector
        .source_lineage_id
        .clone()
        .unwrap_or_else(|| format!("connector:{}", observation.connector.instance_id));
    let account_id = stable_id(observation.installation_id, "cloud_account", account_key);
    let network_id = stable_id(observation.installation_id, "network_zone", network_key);
    let mut entities = vec![
        entity(
            account_id,
            EntityKind::CloudAccount,
            format!(
                "{} account {}",
                provider_label(provider),
                short_key(account_key)
            ),
            observation.observed_at,
        ),
        entity(
            network_id,
            EntityKind::NetworkZone,
            format!(
                "{} network {}",
                provider_label(provider),
                short_key(network_key)
            ),
            observation.observed_at,
        ),
    ];
    let mut keys = vec![
        key(
            observation,
            account_id,
            account_key_type(provider),
            account_key,
            EntityKeyAuthority::ProviderResource,
            valid_until,
        ),
        key(
            observation,
            network_id,
            network_key_type(provider),
            network_key,
            EntityKeyAuthority::NetworkMapping,
            valid_until,
        ),
    ];
    let mut relationships = vec![relationship(
        observation,
        EntityRef {
            entity_id: account_id,
            kind: EntityKind::CloudAccount,
        },
        RelationshipPredicate::Contains,
        EntityRef {
            entity_id: network_id,
            kind: EntityKind::NetworkZone,
        },
        valid_until,
        &lineage,
    )];

    match observation.kind {
        ObservationKind::NetworkMapping => resolve_mapping(
            observation,
            provider,
            network_id,
            valid_until,
            &lineage,
            &mut entities,
            &mut keys,
            &mut relationships,
        )?,
        ObservationKind::NetworkFlow => resolve_flow(
            observation,
            provider,
            network_id,
            valid_until,
            &lineage,
            &mut entities,
            &mut keys,
            &mut relationships,
        )?,
        _ => unreachable!("kind was validated above"),
    }
    entities.sort_by_key(|entity| entity.entity_id);
    entities.dedup_by_key(|entity| entity.entity_id);
    keys.sort_by(|left, right| {
        left.key_type
            .cmp(&right.key_type)
            .then_with(|| left.key_value.cmp(&right.key_value))
    });
    keys.dedup_by(|left, right| {
        left.key_type == right.key_type && left.key_value == right.key_value
    });
    relationships.sort_by_key(|item| item.relationship.relationship_id);
    relationships.dedup_by_key(|item| item.relationship.relationship_id);
    Ok(ResolvedCloudNetwork {
        entities,
        keys,
        relationships,
    })
}

#[allow(clippy::too_many_arguments)]
fn resolve_mapping(
    observation: &Observation,
    provider: CloudProvider,
    network_id: Uuid,
    valid_until: DateTime<Utc>,
    lineage: &str,
    entities: &mut Vec<Entity>,
    keys: &mut Vec<EntityKey>,
    relationships: &mut Vec<ResolvedNetworkRelationship>,
) -> Result<(), NetworkResolutionError> {
    let endpoint_key = pseudonym(
        observation.network.destination_endpoint_key.as_deref(),
        "destination_endpoint_key",
    )?;
    let resource_key = pseudonym(
        observation.network.mapped_resource_key.as_deref(),
        "mapped_resource_key",
    )?;
    let endpoint_id = stable_id(observation.installation_id, "network_asset", endpoint_key);
    let resource_id = stable_id(observation.installation_id, "cloud_resource", resource_key);
    entities.extend([
        entity(
            endpoint_id,
            EntityKind::NetworkAsset,
            format!("Network endpoint {}", short_key(endpoint_key)),
            observation.observed_at,
        ),
        entity(
            resource_id,
            EntityKind::CloudResource,
            format!(
                "{} resource {}",
                provider_label(provider),
                short_key(resource_key)
            ),
            observation.observed_at,
        ),
    ]);
    keys.extend([
        key(
            observation,
            endpoint_id,
            endpoint_key_type(provider),
            endpoint_key,
            EntityKeyAuthority::NetworkMapping,
            valid_until,
        ),
        key(
            observation,
            resource_id,
            resource_key_type(provider),
            resource_key,
            EntityKeyAuthority::ProviderResource,
            valid_until,
        ),
    ]);
    relationships.extend([
        relationship(
            observation,
            EntityRef {
                entity_id: network_id,
                kind: EntityKind::NetworkZone,
            },
            RelationshipPredicate::Contains,
            EntityRef {
                entity_id: endpoint_id,
                kind: EntityKind::NetworkAsset,
            },
            valid_until,
            lineage,
        ),
        relationship(
            observation,
            EntityRef {
                entity_id: endpoint_id,
                kind: EntityKind::NetworkAsset,
            },
            RelationshipPredicate::AddressOf,
            EntityRef {
                entity_id: resource_id,
                kind: EntityKind::CloudResource,
            },
            valid_until,
            lineage,
        ),
    ]);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn resolve_flow(
    observation: &Observation,
    provider: CloudProvider,
    network_id: Uuid,
    valid_until: DateTime<Utc>,
    lineage: &str,
    entities: &mut Vec<Entity>,
    keys: &mut Vec<EntityKey>,
    relationships: &mut Vec<ResolvedNetworkRelationship>,
) -> Result<(), NetworkResolutionError> {
    let source_key = pseudonym(
        observation.network.source_endpoint_key.as_deref(),
        "source_endpoint_key",
    )?;
    let destination_key = pseudonym(
        observation.network.destination_endpoint_key.as_deref(),
        "destination_endpoint_key",
    )?;
    if source_key == destination_key {
        return Err(NetworkResolutionError::SelfFlow);
    }
    let source_id = stable_id(observation.installation_id, "network_asset", source_key);
    let destination_id = stable_id(
        observation.installation_id,
        "network_asset",
        destination_key,
    );
    for (entity_id, endpoint_key) in [(source_id, source_key), (destination_id, destination_key)] {
        entities.push(entity(
            entity_id,
            EntityKind::NetworkAsset,
            format!("Network endpoint {}", short_key(endpoint_key)),
            observation.observed_at,
        ));
        keys.push(key(
            observation,
            entity_id,
            endpoint_key_type(provider),
            endpoint_key,
            EntityKeyAuthority::NetworkMapping,
            valid_until,
        ));
        relationships.push(relationship(
            observation,
            EntityRef {
                entity_id: network_id,
                kind: EntityKind::NetworkZone,
            },
            RelationshipPredicate::Contains,
            EntityRef {
                entity_id,
                kind: EntityKind::NetworkAsset,
            },
            valid_until,
            lineage,
        ));
    }
    if observation.outcome.action.as_deref() == Some("accepted") {
        relationships.push(relationship(
            observation,
            EntityRef {
                entity_id: source_id,
                kind: EntityKind::NetworkAsset,
            },
            RelationshipPredicate::Uses,
            EntityRef {
                entity_id: destination_id,
                kind: EntityKind::NetworkAsset,
            },
            valid_until,
            lineage,
        ));
    }
    Ok(())
}

fn entity(id: Uuid, kind: EntityKind, display_name: String, created_at: DateTime<Utc>) -> Entity {
    Entity {
        entity_id: id,
        kind,
        display_name,
        created_at,
        revision: 1,
    }
}

fn key(
    observation: &Observation,
    entity_id: Uuid,
    key_type: &str,
    key_value: &str,
    authority: EntityKeyAuthority,
    valid_until: DateTime<Utc>,
) -> EntityKey {
    EntityKey {
        installation_id: observation.installation_id,
        key_type: key_type.to_owned(),
        key_value: key_value.to_owned(),
        entity_id,
        authority,
        strength: BasisPoints::MAX,
        first_seen: observation.observed_at,
        last_seen: valid_until,
        status: EntityKeyStatus::Active,
        source_observation_id: Some(observation.observation_id),
        source_lineage_id: observation.connector.source_lineage_id.clone(),
        revision: 1,
    }
}

fn relationship(
    observation: &Observation,
    subject: EntityRef,
    predicate: RelationshipPredicate,
    object: EntityRef,
    valid_until: DateTime<Utc>,
    lineage: &str,
) -> ResolvedNetworkRelationship {
    let relationship_id = EntityRelationship::deterministic_id(
        observation.installation_id,
        subject.entity_id,
        predicate,
        object.entity_id,
    );
    ResolvedNetworkRelationship {
        relationship: EntityRelationship {
            relationship_id,
            installation_id: observation.installation_id,
            subject,
            predicate,
            object,
            confidence: BasisPoints::MAX,
            status: RelationshipStatus::Active,
            valid_from: observation.observed_at,
            valid_until: Some(valid_until),
            rule: Some(RuleRef {
                rule_id: NETWORK_RULE_ID.to_owned(),
                version: RESOLVER_RULE_VERSION.to_owned(),
            }),
            independent_lineage_count: 1,
            created_at: observation.received_at,
            revision: 1,
        },
        evidence: vec![RelationshipEvidence {
            relationship_id,
            observation_id: observation.observation_id,
            source_lineage_id: lineage.to_owned(),
            support_role: RelationshipSupportRole::Supporting,
            valid_from: Some(observation.observed_at),
            valid_until: Some(valid_until),
        }],
    }
}

fn stable_id(installation_id: Uuid, kind: &str, key: &str) -> Uuid {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("godel-tally:{kind}:{installation_id}:{key}").as_bytes(),
    )
}

fn pseudonym<'a>(
    value: Option<&'a str>,
    field: &'static str,
) -> Result<&'a str, NetworkResolutionError> {
    let value = value.ok_or(NetworkResolutionError::MissingField(field))?;
    if value.len() != 67
        || !value.starts_with("p1_")
        || !value[3..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(NetworkResolutionError::UnsafeKey(field));
    }
    Ok(value)
}

fn short_key(value: &str) -> &str {
    value.get(3..11).unwrap_or("unknown")
}

const fn provider_label(provider: CloudProvider) -> &'static str {
    match provider {
        CloudProvider::Aws => "AWS",
        CloudProvider::Azure => "Azure",
        CloudProvider::Gcp => "Google Cloud",
    }
}

const fn account_key_type(provider: CloudProvider) -> &'static str {
    match provider {
        CloudProvider::Aws => "aws_account_key",
        CloudProvider::Azure => "azure_subscription_key",
        CloudProvider::Gcp => "gcp_project_key",
    }
}

const fn network_key_type(provider: CloudProvider) -> &'static str {
    match provider {
        CloudProvider::Aws => "aws_network_key",
        CloudProvider::Azure => "azure_network_key",
        CloudProvider::Gcp => "gcp_network_key",
    }
}

const fn endpoint_key_type(provider: CloudProvider) -> &'static str {
    match provider {
        CloudProvider::Aws => "aws_network_endpoint_key",
        CloudProvider::Azure => "azure_network_endpoint_key",
        CloudProvider::Gcp => "gcp_network_endpoint_key",
    }
}

const fn resource_key_type(provider: CloudProvider) -> &'static str {
    match provider {
        CloudProvider::Aws => "aws_resource_key",
        CloudProvider::Azure => "azure_resource_key",
        CloudProvider::Gcp => "gcp_resource_key",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NetworkResolutionError {
    #[error("unsupported observation kind")]
    UnsupportedObservationKind,
    #[error("normalized network observation is missing {0}")]
    MissingField(&'static str),
    #[error("normalized network observation has unsafe {0}")]
    UnsafeKey(&'static str),
    #[error("normalized network observation has invalid validity")]
    InvalidValidity,
    #[error("network flow endpoints must be distinct")]
    SelfFlow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_core::{
        ConnectorRef, DigestAlgorithm, EvidenceReceipt, NetworkObservation, OutcomeObservation,
    };

    fn observation(kind: ObservationKind) -> Observation {
        let at = "2026-08-13T10:00:00Z".parse().unwrap();
        let mut observation = Observation::new(
            Uuid::parse_str("018f6cd4-4aaf-7bb4-a3b2-a7524ec43711").unwrap(),
            at,
            ConnectorRef {
                instance_id: Uuid::parse_str("018f6cd4-4aaf-7bb4-a3b2-a7524ec43741").unwrap(),
                connector_type: "aws_vpc_flow_fixture_v1".to_owned(),
                implementation_version: "1".to_owned(),
                source_lineage_id: Some("fixture".to_owned()),
            },
            kind,
            EvidenceReceipt::RecordDigest {
                algorithm: DigestAlgorithm::Sha256,
                digest: "a".repeat(64),
            },
        );
        observation.cloud.provider = Some(CloudProvider::Aws);
        observation.cloud.account_key = Some(format!("p1_{}", "a".repeat(64)));
        observation.network = NetworkObservation {
            network_key: Some(format!("p1_{}", "b".repeat(64))),
            source_endpoint_key: Some(format!("p1_{}", "c".repeat(64))),
            destination_endpoint_key: Some(format!("p1_{}", "d".repeat(64))),
            mapped_resource_key: (kind == ObservationKind::NetworkMapping)
                .then(|| format!("p1_{}", "e".repeat(64))),
            valid_until: Some("2026-08-13T10:05:00Z".parse().unwrap()),
            ..NetworkObservation::default()
        };
        observation.outcome = OutcomeObservation {
            action: Some("accepted".to_owned()),
            ..OutcomeObservation::default()
        };
        observation
    }

    #[test]
    fn mapping_resource_id_matches_managed_cloud_resolution_namespace() {
        let observation = observation(ObservationKind::NetworkMapping);
        let resolved = resolve_cloud_network(&observation).unwrap();
        let resource_key = observation.network.mapped_resource_key.as_deref().unwrap();
        let expected = stable_id(observation.installation_id, "cloud_resource", resource_key);
        assert!(
            resolved
                .entities
                .iter()
                .any(|entity| entity.entity_id == expected)
        );
        assert!(resolved.relationships.iter().any(|edge| {
            edge.relationship.predicate == RelationshipPredicate::AddressOf
                && edge.relationship.object.entity_id == expected
        }));
    }

    #[test]
    fn rejected_flow_creates_no_uses_edge() {
        let mut observation = observation(ObservationKind::NetworkFlow);
        observation.outcome.action = Some("rejected".to_owned());
        let resolved = resolve_cloud_network(&observation).unwrap();
        assert!(
            !resolved
                .relationships
                .iter()
                .any(|edge| edge.relationship.predicate == RelationshipPredicate::Uses)
        );
    }
}
