use serde::{Deserialize, Serialize};
use tally_core::{
    AiSystemView, AuthorizationStatus, BasisPoints, Claim, ClaimClass, ClaimPredicate, ClaimStatus,
    CloudLifecycleState, CloudProvider, CloudProviderService, CloudResourceKind, Entity, EntityKey,
    EntityKeyAuthority, EntityKeyStatus, EntityKind, EntityRef, EntityRelationship,
    EvidenceQuality, Lifecycle, Observation, ObservationKind, RelationshipEvidence,
    RelationshipPredicate, RelationshipStatus, RelationshipSupportRole, RuleRef, Surface,
};
use thiserror::Error;
use uuid::Uuid;

use crate::{RESOLVER_RULE_VERSION, ResolvedSystem};

const CLOUD_RULE_ID: &str = "managed_cloud_inventory_exact_key";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedCloudInventory {
    pub entities: Vec<Entity>,
    pub keys: Vec<EntityKey>,
    pub relationships: Vec<ResolvedCloudRelationship>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<ResolvedSystem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedCloudRelationship {
    pub relationship: EntityRelationship,
    pub evidence: Vec<RelationshipEvidence>,
}

/// Resolves a privacy-normalized managed-cloud observation into stable account, scope, resource,
/// and optional AI-system projections. Inventory establishes existence, never usage.
///
/// # Errors
///
/// Returns [`CloudResolutionError`] when required cloud fields are absent, an identifier is not an
/// installation-local pseudonym, or deterministic claim serialization fails.
pub fn resolve_cloud_inventory(
    observation: &Observation,
) -> Result<ResolvedCloudInventory, CloudResolutionError> {
    if !is_managed_cloud_inventory_observation(observation) {
        return Err(CloudResolutionError::UnsupportedObservationKind);
    }

    let fields = cloud_fields(observation)?;
    let ids = cloud_entity_ids(observation, fields);
    let lineage = source_lineage(observation);
    let mut entities = context_entities(observation, fields, ids);
    let mut keys = context_keys(observation, fields, ids);
    let mut relationships = context_relationships(observation, ids, &lineage);
    let system = resolve_cloud_system(observation, fields, ids, &lineage)?;
    if let Some((entity, key, edge, _)) = system.as_ref() {
        entities.push(entity.clone());
        keys.push(key.clone());
        relationships.push(edge.clone());
    }

    entities.sort_by_key(|entity| entity.entity_id);
    keys.sort_by(|left, right| {
        left.key_type
            .cmp(&right.key_type)
            .then_with(|| left.key_value.cmp(&right.key_value))
    });
    relationships.sort_by_key(|item| item.relationship.relationship_id);

    Ok(ResolvedCloudInventory {
        entities,
        keys,
        relationships,
        system: system.map(|(_, _, _, system)| system),
    })
}

/// Returns whether an observation carries managed-cloud inventory identity.
///
/// Provider catalogs can describe an available capability without proving that a customer
/// deployed or used it, so those records retain [`ObservationKind::SaasCapability`] while still
/// using the managed-cloud resolver.
#[must_use]
pub fn is_managed_cloud_inventory_observation(observation: &Observation) -> bool {
    matches!(
        observation.kind,
        ObservationKind::CloudResource | ObservationKind::SaasCapability
    ) && !observation.cloud.is_empty()
}

#[derive(Clone, Copy)]
struct CloudFields<'a> {
    provider: CloudProvider,
    service: CloudProviderService,
    resource_kind: CloudResourceKind,
    account_key: &'a str,
    scope_key: &'a str,
    resource_key: &'a str,
    region: &'a str,
}

#[derive(Clone, Copy)]
struct CloudEntityIds {
    account: Uuid,
    scope: Uuid,
    resource: Uuid,
}

fn cloud_fields(observation: &Observation) -> Result<CloudFields<'_>, CloudResolutionError> {
    Ok(CloudFields {
        provider: observation
            .cloud
            .provider
            .ok_or(CloudResolutionError::MissingCloudField("provider"))?,
        service: observation
            .cloud
            .provider_service
            .ok_or(CloudResolutionError::MissingCloudField("provider_service"))?,
        resource_kind: observation
            .cloud
            .resource_kind
            .ok_or(CloudResolutionError::MissingCloudField("resource_kind"))?,
        account_key: required_pseudonym(observation.cloud.account_key.as_deref(), "account_key")?,
        scope_key: required_pseudonym(observation.cloud.scope_key.as_deref(), "scope_key")?,
        resource_key: required_pseudonym(
            observation.cloud.resource_key.as_deref(),
            "resource_key",
        )?,
        region: observation
            .cloud
            .region
            .as_deref()
            .ok_or(CloudResolutionError::MissingCloudField("region"))?,
    })
}

fn cloud_entity_ids(observation: &Observation, fields: CloudFields<'_>) -> CloudEntityIds {
    CloudEntityIds {
        account: stable_entity_id(
            observation.installation_id,
            "cloud_account",
            fields.account_key,
        ),
        scope: stable_entity_id(observation.installation_id, "cloud_scope", fields.scope_key),
        resource: stable_entity_id(
            observation.installation_id,
            "cloud_resource",
            fields.resource_key,
        ),
    }
}

fn context_entities(
    observation: &Observation,
    fields: CloudFields<'_>,
    ids: CloudEntityIds,
) -> Vec<Entity> {
    vec![
        Entity {
            entity_id: ids.account,
            kind: EntityKind::CloudAccount,
            display_name: format!(
                "{} account {}",
                provider_label(fields.provider),
                short_key(fields.account_key)
            ),
            created_at: observation.observed_at,
            revision: 1,
        },
        Entity {
            entity_id: ids.scope,
            kind: EntityKind::OrganizationScope,
            display_name: format!(
                "{} {} scope {}",
                provider_label(fields.provider),
                fields.region,
                short_key(fields.scope_key)
            ),
            created_at: observation.observed_at,
            revision: 1,
        },
        Entity {
            entity_id: ids.resource,
            kind: EntityKind::CloudResource,
            display_name: format!(
                "{} {} {}",
                service_label(fields.service),
                resource_kind_label(fields.resource_kind),
                short_key(fields.resource_key)
            ),
            created_at: observation.observed_at,
            revision: 1,
        },
    ]
}

fn context_keys(
    observation: &Observation,
    fields: CloudFields<'_>,
    ids: CloudEntityIds,
) -> Vec<EntityKey> {
    [
        (
            ids.account,
            account_key_type(fields.provider),
            fields.account_key,
        ),
        (ids.scope, scope_key_type(fields.provider), fields.scope_key),
        (
            ids.resource,
            resource_key_type(fields.provider),
            fields.resource_key,
        ),
    ]
    .into_iter()
    .map(|(entity_id, key_type, key_value)| {
        entity_key(
            observation,
            entity_id,
            key_type,
            key_value,
            EntityKeyAuthority::ProviderResource,
        )
    })
    .collect()
}

fn context_relationships(
    observation: &Observation,
    ids: CloudEntityIds,
    lineage: &str,
) -> Vec<ResolvedCloudRelationship> {
    vec![
        relationship(
            observation,
            EntityRef {
                entity_id: ids.account,
                kind: EntityKind::CloudAccount,
            },
            RelationshipPredicate::Contains,
            EntityRef {
                entity_id: ids.scope,
                kind: EntityKind::OrganizationScope,
            },
            lineage,
        ),
        relationship(
            observation,
            EntityRef {
                entity_id: ids.scope,
                kind: EntityKind::OrganizationScope,
            },
            RelationshipPredicate::Contains,
            EntityRef {
                entity_id: ids.resource,
                kind: EntityKind::CloudResource,
            },
            lineage,
        ),
    ]
}

fn resolve_cloud_system(
    observation: &Observation,
    fields: CloudFields<'_>,
    ids: CloudEntityIds,
    lineage: &str,
) -> Result<
    Option<(Entity, EntityKey, ResolvedCloudRelationship, ResolvedSystem)>,
    CloudResolutionError,
> {
    if !inference_capable(fields.resource_kind)
        || observation.kind != ObservationKind::CloudResource
    {
        return Ok(None);
    }
    let stable_key = format!("cloud_system:{}", fields.resource_key);
    let system_id = stable_entity_id(observation.installation_id, "ai_system", &stable_key);
    let display_name = observation.service.declared_model_id.as_ref().map_or_else(
        || {
            format!(
                "{} {} {}",
                service_label(fields.service),
                resource_kind_label(fields.resource_kind),
                short_key(fields.resource_key)
            )
        },
        |model| {
            format!(
                "{} {} · {model}",
                service_label(fields.service),
                resource_kind_label(fields.resource_kind)
            )
        },
    );
    let system_ref = EntityRef {
        entity_id: system_id,
        kind: EntityKind::AiSystem,
    };
    let entity = Entity {
        entity_id: system_id,
        kind: EntityKind::AiSystem,
        display_name: display_name.clone(),
        created_at: observation.observed_at,
        revision: 1,
    };
    let key = entity_key(
        observation,
        system_id,
        "cloud_system_key",
        &stable_key,
        EntityKeyAuthority::DerivedRule,
    );
    let edge = relationship(
        observation,
        EntityRef {
            entity_id: ids.resource,
            kind: EntityKind::CloudResource,
        },
        RelationshipPredicate::Serves,
        system_ref,
        lineage,
    );
    let system = ResolvedSystem {
        entity: entity.clone(),
        stable_key,
        view: AiSystemView {
            system_id,
            display_name,
            surface: Surface::ManagedCloud,
            lifecycle: Lifecycle::Observed,
            authorization: AuthorizationStatus::Discovered,
            first_seen: observation.observed_at,
            last_seen: observation.observed_at,
            evidence_quality: EvidenceQuality::Strong,
            confidence: BasisPoints::MAX,
            findings: Vec::new(),
            revision: 1,
        },
        claims: cloud_claims(
            observation,
            system_ref,
            fields.provider,
            fields.service,
            fields.resource_kind,
        )?,
        supporting_observation_id: observation.observation_id,
    };
    Ok(Some((entity, key, edge, system)))
}

fn cloud_claims(
    observation: &Observation,
    subject: EntityRef,
    provider: CloudProvider,
    service: CloudProviderService,
    resource_kind: CloudResourceKind,
) -> Result<Vec<Claim>, CloudResolutionError> {
    let lifecycle = observation
        .cloud
        .lifecycle_state
        .unwrap_or(CloudLifecycleState::Unknown);
    let mut claims = vec![
        claim(
            observation,
            subject,
            ClaimPredicate::Provider,
            serde_json::to_value(provider)?,
        )?,
        claim(
            observation,
            subject,
            ClaimPredicate::Product,
            serde_json::to_value(service)?,
        )?,
        claim(
            observation,
            subject,
            ClaimPredicate::Surface,
            serde_json::to_value(Surface::ManagedCloud)?,
        )?,
        claim(
            observation,
            subject,
            ClaimPredicate::Deployment,
            serde_json::to_value(resource_kind)?,
        )?,
        claim(
            observation,
            subject,
            ClaimPredicate::ResourceExists,
            serde_json::Value::Bool(true),
        )?,
        claim(
            observation,
            subject,
            ClaimPredicate::ResourceLifecycle,
            serde_json::to_value(lifecycle)?,
        )?,
    ];
    if let Some(model_id) = observation.service.declared_model_id.as_ref() {
        claims.push(claim(
            observation,
            subject,
            ClaimPredicate::ModelFamily,
            serde_json::Value::String(model_id.clone()),
        )?);
    }
    claims.sort_by_key(|item| item.claim_id);
    Ok(claims)
}

fn claim(
    observation: &Observation,
    subject: EntityRef,
    predicate: ClaimPredicate,
    value: serde_json::Value,
) -> Result<Claim, CloudResolutionError> {
    let identity = serde_json::to_vec(&(&predicate, &value))?;
    Ok(Claim {
        claim_id: Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!(
                "godel-tally:cloud-claim:{}:{}:{}",
                subject.entity_id,
                observation.observation_id,
                hex::encode(identity)
            )
            .as_bytes(),
        ),
        subject,
        predicate,
        value,
        class: ClaimClass::Observed,
        confidence: BasisPoints::MAX,
        status: ClaimStatus::Active,
        valid_from: observation.observed_at,
        valid_until: None,
        rule: Some(rule()),
        registry_version: None,
        created_at: observation.received_at,
    })
}

fn entity_key(
    observation: &Observation,
    entity_id: Uuid,
    key_type: &str,
    key_value: &str,
    authority: EntityKeyAuthority,
) -> EntityKey {
    EntityKey {
        installation_id: observation.installation_id,
        key_type: key_type.to_owned(),
        key_value: key_value.to_owned(),
        entity_id,
        authority,
        strength: BasisPoints::MAX,
        first_seen: observation.observed_at,
        last_seen: observation.observed_at,
        status: EntityKeyStatus::Active,
        source_observation_id: Some(observation.observation_id),
        source_lineage_id: Some(source_lineage(observation)),
        revision: 1,
    }
}

fn relationship(
    observation: &Observation,
    subject: EntityRef,
    predicate: RelationshipPredicate,
    object: EntityRef,
    lineage: &str,
) -> ResolvedCloudRelationship {
    let relationship_id = EntityRelationship::deterministic_id(
        observation.installation_id,
        subject.entity_id,
        predicate,
        object.entity_id,
    );
    ResolvedCloudRelationship {
        relationship: EntityRelationship {
            relationship_id,
            installation_id: observation.installation_id,
            subject,
            predicate,
            object,
            confidence: BasisPoints::MAX,
            status: RelationshipStatus::Active,
            valid_from: observation.observed_at,
            valid_until: None,
            rule: Some(rule()),
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
            valid_until: None,
        }],
    }
}

fn stable_entity_id(installation_id: Uuid, kind: &str, key: &str) -> Uuid {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("godel-tally:{kind}:{installation_id}:{key}").as_bytes(),
    )
}

fn required_pseudonym<'a>(
    value: Option<&'a str>,
    field: &'static str,
) -> Result<&'a str, CloudResolutionError> {
    let value = value.ok_or(CloudResolutionError::MissingCloudField(field))?;
    if !value.starts_with("p1_")
        || value.len() != 67
        || !value[3..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(CloudResolutionError::UnsafeCloudIdentifier(field));
    }
    Ok(value)
}

fn source_lineage(observation: &Observation) -> String {
    observation
        .connector
        .source_lineage_id
        .clone()
        .unwrap_or_else(|| format!("connector:{}", observation.connector.instance_id))
}

const fn provider_label(provider: CloudProvider) -> &'static str {
    match provider {
        CloudProvider::Aws => "AWS",
        CloudProvider::Azure => "Azure",
        CloudProvider::Gcp => "Google Cloud",
    }
}

const fn service_label(service: CloudProviderService) -> &'static str {
    match service {
        CloudProviderService::AwsBedrock => "Amazon Bedrock",
        CloudProviderService::AwsSagemaker => "Amazon SageMaker",
        CloudProviderService::AzureOpenai => "Azure OpenAI",
        CloudProviderService::AzureAiFoundry => "Microsoft Foundry",
        CloudProviderService::GcpVertexAi => "Vertex AI",
    }
}

const fn resource_kind_label(kind: CloudResourceKind) -> &'static str {
    match kind {
        CloudResourceKind::OrganizationScope => "organization scope",
        CloudResourceKind::AccountScope => "account scope",
        CloudResourceKind::FoundationModel => "foundation model",
        CloudResourceKind::ModelArtifact => "model artifact",
        CloudResourceKind::ModelDeployment => "deployment",
        CloudResourceKind::InferenceEndpoint => "endpoint",
        CloudResourceKind::Agent => "agent",
        CloudResourceKind::KnowledgeBase => "knowledge base",
        CloudResourceKind::NetworkInterface => "network interface",
        CloudResourceKind::Workload => "workload",
    }
}

const fn inference_capable(kind: CloudResourceKind) -> bool {
    matches!(
        kind,
        CloudResourceKind::ModelDeployment
            | CloudResourceKind::InferenceEndpoint
            | CloudResourceKind::Agent
    )
}

const fn account_key_type(provider: CloudProvider) -> &'static str {
    match provider {
        CloudProvider::Aws => "aws_account",
        CloudProvider::Azure => "azure_subscription",
        CloudProvider::Gcp => "gcp_project",
    }
}

const fn scope_key_type(provider: CloudProvider) -> &'static str {
    match provider {
        CloudProvider::Aws => "aws_region_scope",
        CloudProvider::Azure => "azure_account_scope",
        CloudProvider::Gcp => "gcp_location_scope",
    }
}

const fn resource_key_type(provider: CloudProvider) -> &'static str {
    match provider {
        CloudProvider::Aws => "aws_resource",
        CloudProvider::Azure => "azure_resource",
        CloudProvider::Gcp => "gcp_resource",
    }
}

fn short_key(value: &str) -> &str {
    value.get(..11).unwrap_or(value)
}

fn rule() -> RuleRef {
    RuleRef {
        rule_id: CLOUD_RULE_ID.to_owned(),
        version: RESOLVER_RULE_VERSION.to_owned(),
    }
}

#[derive(Debug, Error)]
pub enum CloudResolutionError {
    #[error("observation is not managed-cloud inventory")]
    UnsupportedObservationKind,
    #[error("managed-cloud observation is missing required field {0}")]
    MissingCloudField(&'static str),
    #[error("managed-cloud field {0} is not an installation-local pseudonym")]
    UnsafeCloudIdentifier(&'static str),
    #[error("serialize deterministic managed-cloud claim identity: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use tally_core::{CloudObservation, ConnectorRef, DigestAlgorithm, EvidenceReceipt};

    use super::*;

    fn fixture(kind: ObservationKind, resource_kind: CloudResourceKind) -> Observation {
        let observed_at = "2026-08-13T12:00:00Z".parse().expect("timestamp");
        let mut observation = Observation::new(
            Uuid::from_u128(1),
            observed_at,
            ConnectorRef {
                instance_id: Uuid::from_u128(2),
                connector_type: "aws_managed_ai_inventory_file_v1".to_owned(),
                implementation_version: "1".to_owned(),
                source_lineage_id: Some("cloud:fixture:primary".to_owned()),
            },
            kind,
            EvidenceReceipt::RecordDigest {
                algorithm: DigestAlgorithm::Sha256,
                digest: "00".repeat(32),
            },
        );
        observation.observation_id = Uuid::from_u128(3);
        observation.received_at = Utc::now();
        observation.cloud.provider = Some(CloudProvider::Aws);
        observation.cloud.provider_service = Some(CloudProviderService::AwsBedrock);
        observation.cloud.account_key = Some(format!("p1_{}", "1".repeat(64)));
        observation.cloud.scope_key = Some(format!("p1_{}", "2".repeat(64)));
        observation.cloud.resource_key = Some(format!("p1_{}", "3".repeat(64)));
        observation.cloud.region = Some("us-east-1".to_owned());
        observation.cloud.resource_kind = Some(resource_kind);
        observation.cloud.lifecycle_state = Some(CloudLifecycleState::Active);
        observation
    }

    #[test]
    fn inference_resource_is_stable_without_claiming_usage() {
        let observation = fixture(
            ObservationKind::CloudResource,
            CloudResourceKind::ModelDeployment,
        );
        let first = resolve_cloud_inventory(&observation).expect("resolve");
        let replay = resolve_cloud_inventory(&observation).expect("replay");
        assert_eq!(first, replay);
        let system = first.system.expect("system");
        assert_eq!(system.view.lifecycle, Lifecycle::Observed);
        assert!(
            system
                .claims
                .iter()
                .any(|claim| claim.predicate == ClaimPredicate::ResourceExists)
        );
        assert!(
            !system
                .claims
                .iter()
                .any(|claim| claim.predicate == ClaimPredicate::ResourceUsed)
        );
        assert_eq!(first.relationships.len(), 3);
    }

    #[test]
    fn catalog_resource_does_not_invent_a_system() {
        let observation = fixture(
            ObservationKind::SaasCapability,
            CloudResourceKind::FoundationModel,
        );
        let resolved = resolve_cloud_inventory(&observation).expect("resolve catalog");
        assert!(resolved.system.is_none());
        assert_eq!(resolved.relationships.len(), 2);
    }

    #[test]
    fn provider_neutral_saas_capability_is_not_managed_cloud_inventory() {
        let mut observation = fixture(
            ObservationKind::SaasCapability,
            CloudResourceKind::FoundationModel,
        );
        observation.cloud = CloudObservation::default();
        assert!(!is_managed_cloud_inventory_observation(&observation));
        assert!(matches!(
            resolve_cloud_inventory(&observation),
            Err(CloudResolutionError::UnsupportedObservationKind)
        ));
    }

    #[test]
    fn raw_provider_identifier_is_rejected() {
        let mut observation = fixture(
            ObservationKind::CloudResource,
            CloudResourceKind::InferenceEndpoint,
        );
        observation.cloud.resource_key = Some("arn:aws:sagemaker:secret".to_owned());
        assert!(matches!(
            resolve_cloud_inventory(&observation),
            Err(CloudResolutionError::UnsafeCloudIdentifier("resource_key"))
        ));
    }
}
