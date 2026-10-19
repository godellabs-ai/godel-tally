use serde::{Deserialize, Serialize};
use tally_core::{
    AiSystemView, AuthorizationStatus, BasisPoints, Claim, ClaimClass, ClaimPredicate, ClaimStatus,
    Entity, EntityKey, EntityKeyAuthority, EntityKeyStatus, EntityKind, EntityRef,
    EntityRelationship, EvidenceQuality, Lifecycle, Observation, ObservationKind,
    RelationshipEvidence, RelationshipPredicate, RelationshipStatus, RelationshipSupportRole,
    RuleRef, SaasCapabilityState, Surface, WorkloadKind,
};
use thiserror::Error;
use uuid::Uuid;

use crate::{RESOLVER_RULE_VERSION, ResolvedSystem};

const CASB_RULE_ID: &str = "casb_capability_exact_key";
const KUBERNETES_RULE_ID: &str = "kubernetes_api_exact_uid";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedEnterpriseDiscovery {
    pub entities: Vec<Entity>,
    pub keys: Vec<EntityKey>,
    pub relationships: Vec<ResolvedEnterpriseRelationship>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<ResolvedSystem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedEnterpriseRelationship {
    pub relationship: EntityRelationship,
    pub evidence: Vec<RelationshipEvidence>,
}

/// Resolves a content-free CASB capability into a stable `SaaS` tenant and AI-system projection.
///
/// A configured capability proves only source-native availability; it never claims that a person
/// used the application or that Tally authored the sanction state.
///
/// # Errors
///
/// Returns [`EnterpriseResolutionError`] when required pseudonyms, registry identifiers, or source
/// state are missing or unsafe.
///
/// # Panics
///
/// Panics only if the compile-time confidence constant is outside the basis-points range.
#[allow(clippy::too_many_lines)]
pub fn resolve_saas_capability(
    observation: &Observation,
) -> Result<ResolvedEnterpriseDiscovery, EnterpriseResolutionError> {
    if observation.kind != ObservationKind::SaasCapability {
        return Err(EnterpriseResolutionError::UnsupportedObservationKind);
    }
    let tenant_key = pseudonym(observation.saas.tenant_key.as_deref(), "tenant_key")?;
    let _application_key = pseudonym(
        observation.saas.application_key.as_deref(),
        "application_key",
    )?;
    let capability_state = observation
        .saas
        .capability_state
        .ok_or(EnterpriseResolutionError::MissingField("capability_state"))?;
    let sanction_status = observation
        .saas
        .sanction_status
        .ok_or(EnterpriseResolutionError::MissingField("sanction_status"))?;
    let registry_entry_id = safe_registry_entry(
        observation.service.vendor_application_id.as_deref(),
        "vendor_application_id",
    )?;
    let tenant_id = stable_id(observation.installation_id, "saas_tenant", tenant_key);
    let system_stable_key = format!("saas_capability:{tenant_key}:{registry_entry_id}");
    let system_id = stable_id(observation.installation_id, "ai_system", &system_stable_key);
    let lineage = source_lineage(observation);
    let tenant_ref = EntityRef {
        entity_id: tenant_id,
        kind: EntityKind::SaasTenant,
    };
    let system_ref = EntityRef {
        entity_id: system_id,
        kind: EntityKind::AiSystem,
    };
    let display_name = format!(
        "{} · tenant {}",
        registry_label(registry_entry_id),
        short_key(tenant_key)
    );
    let entities = vec![
        entity(
            tenant_id,
            EntityKind::SaasTenant,
            format!("SaaS tenant {}", short_key(tenant_key)),
            observation,
        ),
        entity(
            system_id,
            EntityKind::AiSystem,
            display_name.clone(),
            observation,
        ),
    ];
    let keys = vec![
        key(
            observation,
            tenant_id,
            "casb_tenant_key",
            tenant_key,
            EntityKeyAuthority::Casb,
        ),
        key(
            observation,
            system_id,
            "casb_system_key",
            &system_stable_key,
            EntityKeyAuthority::DerivedRule,
        ),
    ];
    let relationships = if capability_state == SaasCapabilityState::Enabled {
        vec![relationship(
            observation,
            tenant_ref,
            RelationshipPredicate::Enables,
            system_ref,
            &lineage,
            CASB_RULE_ID,
        )]
    } else {
        Vec::new()
    };
    let confidence = BasisPoints::new(9_000).expect("static basis points");
    let claims = vec![
        claim(
            observation,
            system_ref,
            ClaimPredicate::Product,
            serde_json::Value::String(registry_entry_id.to_owned()),
            CASB_RULE_ID,
            confidence,
        )?,
        claim(
            observation,
            system_ref,
            ClaimPredicate::Surface,
            serde_json::to_value(Surface::EmbeddedSaas)?,
            CASB_RULE_ID,
            confidence,
        )?,
        claim(
            observation,
            system_ref,
            ClaimPredicate::CapabilityEnabled,
            serde_json::Value::Bool(capability_state == SaasCapabilityState::Enabled),
            CASB_RULE_ID,
            confidence,
        )?,
        claim(
            observation,
            system_ref,
            ClaimPredicate::SanctionStatus,
            serde_json::to_value(sanction_status)?,
            CASB_RULE_ID,
            confidence,
        )?,
    ];
    Ok(ResolvedEnterpriseDiscovery {
        entities: sorted_entities(entities),
        keys: sorted_keys(keys),
        relationships,
        system: Some(ResolvedSystem {
            entity: entity(
                system_id,
                EntityKind::AiSystem,
                display_name.clone(),
                observation,
            ),
            stable_key: system_stable_key,
            view: AiSystemView {
                system_id,
                display_name,
                surface: Surface::EmbeddedSaas,
                lifecycle: Lifecycle::Observed,
                authorization: AuthorizationStatus::Discovered,
                first_seen: observation.observed_at,
                last_seen: observation.observed_at,
                evidence_quality: EvidenceQuality::Moderate,
                confidence,
                findings: Vec::new(),
                revision: 1,
            },
            claims,
            supporting_observation_id: observation.observation_id,
        }),
    })
}

/// Resolves a normalized read-only Kubernetes API resource into cluster, namespace, workload,
/// optional service-address, and optional AI-runtime system projections.
///
/// # Errors
///
/// Returns [`EnterpriseResolutionError`] when the observation lacks exact pseudonymous UIDs,
/// contains an unsafe runtime ID, or would create an invalid graph edge.
///
/// # Panics
///
/// Panics only if the compile-time confidence constant is outside the basis-points range.
#[allow(clippy::too_many_lines)]
pub fn resolve_kubernetes_resource(
    observation: &Observation,
) -> Result<ResolvedEnterpriseDiscovery, EnterpriseResolutionError> {
    if observation.kind != ObservationKind::KubernetesResource {
        return Err(EnterpriseResolutionError::UnsupportedObservationKind);
    }
    let cluster_key = pseudonym(observation.workload.cluster_key.as_deref(), "cluster_key")?;
    let namespace_key = pseudonym(
        observation.workload.namespace_key.as_deref(),
        "namespace_key",
    )?;
    let workload_key = pseudonym(observation.workload.workload_key.as_deref(), "workload_key")?;
    let workload_kind = observation
        .workload
        .workload_kind
        .ok_or(EnterpriseResolutionError::MissingField("workload_kind"))?;
    let namespace_name = observation
        .workload
        .namespace_name
        .as_deref()
        .map(|value| safe_kubernetes_name(value, "namespace_name"))
        .transpose()?;
    let workload_name = observation
        .workload
        .workload_name
        .as_deref()
        .map(|value| safe_kubernetes_name(value, "workload_name"))
        .transpose()?;
    let runtime_registry_entry_id = observation
        .workload
        .runtime_registry_entry_id
        .as_deref()
        .map(|value| safe_registry_entry(Some(value), "runtime_registry_entry_id"))
        .transpose()?;
    let runtime_image = observation
        .workload
        .runtime_image
        .as_deref()
        .map(|value| safe_runtime_image(value, "runtime_image"))
        .transpose()?;
    let endpoint_key = observation
        .network
        .destination_endpoint_key
        .as_deref()
        .map(|value| pseudonym(Some(value), "destination_endpoint_key"))
        .transpose()?;
    let lineage = source_lineage(observation);
    let cluster_id = stable_id(observation.installation_id, "k8s_cluster", cluster_key);
    let namespace_id = stable_id(observation.installation_id, "k8s_namespace", namespace_key);
    let workload_id = stable_id(observation.installation_id, "workload", workload_key);
    let cluster_ref = EntityRef {
        entity_id: cluster_id,
        kind: EntityKind::KubernetesCluster,
    };
    let namespace_ref = EntityRef {
        entity_id: namespace_id,
        kind: EntityKind::KubernetesNamespace,
    };
    let workload_ref = EntityRef {
        entity_id: workload_id,
        kind: EntityKind::Workload,
    };
    let namespace_display_name = namespace_name.map_or_else(
        || format!("Kubernetes namespace {}", short_key(namespace_key)),
        |name| format!("Kubernetes namespace {name}"),
    );
    let workload_display_name = match (namespace_name, workload_name) {
        (Some(namespace), Some(workload)) => format!(
            "Kubernetes {} {namespace}/{workload}",
            workload_kind_label(workload_kind)
        ),
        (_, Some(workload)) => format!(
            "Kubernetes {} {workload}",
            workload_kind_label(workload_kind)
        ),
        _ => format!(
            "Kubernetes {} {}",
            workload_kind_label(workload_kind),
            short_key(workload_key)
        ),
    };
    let mut entities = vec![
        entity(
            cluster_id,
            EntityKind::KubernetesCluster,
            format!("Kubernetes cluster {}", short_key(cluster_key)),
            observation,
        ),
        entity(
            namespace_id,
            EntityKind::KubernetesNamespace,
            namespace_display_name,
            observation,
        ),
        entity(
            workload_id,
            EntityKind::Workload,
            workload_display_name,
            observation,
        ),
    ];
    let mut keys = vec![
        key(
            observation,
            cluster_id,
            "k8s_cluster_uid_key",
            cluster_key,
            EntityKeyAuthority::KubernetesApi,
        ),
        key(
            observation,
            namespace_id,
            "k8s_namespace_uid_key",
            namespace_key,
            EntityKeyAuthority::KubernetesApi,
        ),
        key(
            observation,
            workload_id,
            "k8s_workload_uid_key",
            workload_key,
            EntityKeyAuthority::KubernetesApi,
        ),
    ];
    let mut relationships = vec![
        relationship(
            observation,
            cluster_ref,
            RelationshipPredicate::Contains,
            namespace_ref,
            &lineage,
            KUBERNETES_RULE_ID,
        ),
        relationship(
            observation,
            namespace_ref,
            RelationshipPredicate::Contains,
            workload_ref,
            &lineage,
            KUBERNETES_RULE_ID,
        ),
    ];
    if let Some(endpoint_key) = endpoint_key {
        let endpoint_id = stable_id(observation.installation_id, "network_asset", endpoint_key);
        let endpoint_ref = EntityRef {
            entity_id: endpoint_id,
            kind: EntityKind::NetworkAsset,
        };
        entities.push(entity(
            endpoint_id,
            EntityKind::NetworkAsset,
            format!("Kubernetes service endpoint {}", short_key(endpoint_key)),
            observation,
        ));
        keys.push(key(
            observation,
            endpoint_id,
            "k8s_service_endpoint_key",
            endpoint_key,
            EntityKeyAuthority::KubernetesApi,
        ));
        relationships.push(relationship(
            observation,
            endpoint_ref,
            RelationshipPredicate::AddressOf,
            workload_ref,
            &lineage,
            KUBERNETES_RULE_ID,
        ));
    }
    let system = runtime_registry_entry_id
        .map(|registry_entry_id| {
            kubernetes_system(
                observation,
                workload_ref,
                workload_key,
                workload_kind,
                registry_entry_id,
                KubernetesRemediationLocator {
                    namespace_name,
                    workload_name,
                    runtime_image,
                },
                &lineage,
            )
        })
        .transpose()?;
    if let Some((system_entity, system_key, system_edge, _)) = system.as_ref() {
        entities.push(system_entity.clone());
        keys.push(system_key.clone());
        relationships.push(system_edge.clone());
    }
    Ok(ResolvedEnterpriseDiscovery {
        entities: sorted_entities(entities),
        keys: sorted_keys(keys),
        relationships,
        system: system.map(|(_, _, _, system)| system),
    })
}

#[derive(Clone, Copy)]
struct KubernetesRemediationLocator<'a> {
    namespace_name: Option<&'a str>,
    workload_name: Option<&'a str>,
    runtime_image: Option<&'a str>,
}

fn kubernetes_system(
    observation: &Observation,
    workload_ref: EntityRef,
    workload_key: &str,
    workload_kind: WorkloadKind,
    registry_entry_id: &str,
    locator: KubernetesRemediationLocator<'_>,
    lineage: &str,
) -> Result<
    (
        Entity,
        EntityKey,
        ResolvedEnterpriseRelationship,
        ResolvedSystem,
    ),
    EnterpriseResolutionError,
> {
    let stable_key = format!("k8s_runtime:{workload_key}:{registry_entry_id}");
    let system_id = stable_id(observation.installation_id, "ai_system", &stable_key);
    let system_ref = EntityRef {
        entity_id: system_id,
        kind: EntityKind::AiSystem,
    };
    let display_name =
        kubernetes_system_display(registry_entry_id, workload_kind, workload_key, locator);
    let system_entity = entity(
        system_id,
        EntityKind::AiSystem,
        display_name.clone(),
        observation,
    );
    let system_key = key(
        observation,
        system_id,
        "k8s_runtime_system_key",
        &stable_key,
        EntityKeyAuthority::DerivedRule,
    );
    let edge = relationship(
        observation,
        workload_ref,
        RelationshipPredicate::Serves,
        system_ref,
        lineage,
        KUBERNETES_RULE_ID,
    );
    let confidence = BasisPoints::new(9_500).expect("static basis points");
    let claims = vec![
        claim(
            observation,
            system_ref,
            ClaimPredicate::Product,
            serde_json::Value::String(registry_entry_id.to_owned()),
            KUBERNETES_RULE_ID,
            confidence,
        )?,
        claim(
            observation,
            system_ref,
            ClaimPredicate::Surface,
            serde_json::to_value(Surface::SelfHosted)?,
            KUBERNETES_RULE_ID,
            confidence,
        )?,
        claim(
            observation,
            system_ref,
            ClaimPredicate::Deployment,
            serde_json::to_value(workload_kind)?,
            KUBERNETES_RULE_ID,
            confidence,
        )?,
        claim(
            observation,
            system_ref,
            ClaimPredicate::ResourceExists,
            serde_json::Value::Bool(true),
            KUBERNETES_RULE_ID,
            confidence,
        )?,
    ];
    Ok((
        system_entity.clone(),
        system_key,
        edge,
        ResolvedSystem {
            entity: system_entity,
            stable_key,
            view: AiSystemView {
                system_id,
                display_name,
                surface: Surface::SelfHosted,
                lifecycle: Lifecycle::Observed,
                authorization: AuthorizationStatus::Discovered,
                first_seen: observation.observed_at,
                last_seen: observation.observed_at,
                evidence_quality: EvidenceQuality::Strong,
                confidence,
                findings: Vec::new(),
                revision: 1,
            },
            claims,
            supporting_observation_id: observation.observation_id,
        },
    ))
}

fn kubernetes_system_display(
    registry_entry_id: &str,
    workload_kind: WorkloadKind,
    workload_key: &str,
    locator: KubernetesRemediationLocator<'_>,
) -> String {
    let workload_locator = match (locator.namespace_name, locator.workload_name) {
        (Some(namespace), Some(workload)) => format!("{namespace}/{workload}"),
        (_, Some(workload)) => workload.to_owned(),
        _ => short_key(workload_key).to_owned(),
    };
    locator.runtime_image.map_or_else(
        || {
            format!(
                "{} · {} {workload_locator}",
                registry_label(registry_entry_id),
                workload_kind_label(workload_kind)
            )
        },
        |image| {
            format!(
                "{} · {} {workload_locator} · {image}",
                registry_label(registry_entry_id),
                workload_kind_label(workload_kind)
            )
        },
    )
}

fn entity(
    entity_id: Uuid,
    kind: EntityKind,
    display_name: String,
    observation: &Observation,
) -> Entity {
    Entity {
        entity_id,
        kind,
        display_name,
        created_at: observation.observed_at,
        revision: 1,
    }
}

fn key(
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
    rule_id: &str,
) -> ResolvedEnterpriseRelationship {
    let relationship_id = EntityRelationship::deterministic_id(
        observation.installation_id,
        subject.entity_id,
        predicate,
        object.entity_id,
    );
    ResolvedEnterpriseRelationship {
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
            rule: Some(RuleRef {
                rule_id: rule_id.to_owned(),
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
            valid_until: None,
        }],
    }
}

fn claim(
    observation: &Observation,
    subject: EntityRef,
    predicate: ClaimPredicate,
    value: serde_json::Value,
    rule_id: &str,
    confidence: BasisPoints,
) -> Result<Claim, EnterpriseResolutionError> {
    let digest = hex::encode(serde_json::to_vec(&(&predicate, &value))?);
    Ok(Claim {
        claim_id: Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!(
                "godel-tally:enterprise-claim:{}:{}:{digest}",
                subject.entity_id, observation.observation_id
            )
            .as_bytes(),
        ),
        subject,
        predicate,
        value,
        class: ClaimClass::Observed,
        confidence,
        status: ClaimStatus::Active,
        valid_from: observation.observed_at,
        valid_until: None,
        rule: Some(RuleRef {
            rule_id: rule_id.to_owned(),
            version: RESOLVER_RULE_VERSION.to_owned(),
        }),
        registry_version: None,
        created_at: observation.received_at,
    })
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
) -> Result<&'a str, EnterpriseResolutionError> {
    let value = value.ok_or(EnterpriseResolutionError::MissingField(field))?;
    if !value.starts_with("p1_")
        || value.len() != 67
        || !value[3..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(EnterpriseResolutionError::UnsafeIdentifier(field));
    }
    Ok(value)
}

fn safe_registry_entry<'a>(
    value: Option<&'a str>,
    field: &'static str,
) -> Result<&'a str, EnterpriseResolutionError> {
    let value = value.ok_or(EnterpriseResolutionError::MissingField(field))?;
    if value.len() > 96
        || !(value.starts_with("svc.") || value.starts_with("runtime."))
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(EnterpriseResolutionError::UnsafeIdentifier(field));
    }
    Ok(value)
}

fn safe_kubernetes_name<'a>(
    value: &'a str,
    field: &'static str,
) -> Result<&'a str, EnterpriseResolutionError> {
    let valid = !value.is_empty()
        && value.len() <= 253
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    if !valid {
        return Err(EnterpriseResolutionError::UnsafeIdentifier(field));
    }
    Ok(value)
}

fn safe_runtime_image<'a>(
    value: &'a str,
    field: &'static str,
) -> Result<&'a str, EnterpriseResolutionError> {
    if value.is_empty()
        || value.len() > 512
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(EnterpriseResolutionError::UnsafeIdentifier(field));
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

fn short_key(value: &str) -> &str {
    value.get(3..11).unwrap_or("unknown")
}

fn registry_label(value: &str) -> &'static str {
    match value {
        "svc.anthropic.api" => "Anthropic API",
        "svc.github.copilot" => "GitHub Copilot",
        "svc.google.gemini_api" => "Google Gemini API",
        "svc.openai.api" => "OpenAI API",
        "runtime.ollama" => "Ollama",
        "runtime.triton" => "NVIDIA Triton",
        "runtime.vllm" => "vLLM",
        _ => "AI service",
    }
}

const fn workload_kind_label(kind: WorkloadKind) -> &'static str {
    match kind {
        WorkloadKind::Deployment => "deployment",
        WorkloadKind::StatefulSet => "stateful set",
        WorkloadKind::DaemonSet => "daemon set",
        WorkloadKind::Job => "job",
        WorkloadKind::CronJob => "cron job",
        WorkloadKind::Pod => "pod",
        WorkloadKind::Service => "service",
        WorkloadKind::Node => "node",
    }
}

fn sorted_entities(mut values: Vec<Entity>) -> Vec<Entity> {
    values.sort_by_key(|entity| entity.entity_id);
    values.dedup_by_key(|entity| entity.entity_id);
    values
}

fn sorted_keys(mut values: Vec<EntityKey>) -> Vec<EntityKey> {
    values.sort_by(|left, right| {
        left.key_type
            .cmp(&right.key_type)
            .then_with(|| left.key_value.cmp(&right.key_value))
    });
    values.dedup_by(|left, right| {
        left.key_type == right.key_type && left.key_value == right.key_value
    });
    values
}

#[derive(Debug, Error)]
pub enum EnterpriseResolutionError {
    #[error("observation kind is unsupported")]
    UnsupportedObservationKind,
    #[error("required field is missing: {0}")]
    MissingField(&'static str),
    #[error("identifier is not a safe installation pseudonym or registry token: {0}")]
    UnsafeIdentifier(&'static str),
    #[error("claim serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use tally_core::{
        ConnectorRef, DigestAlgorithm, EvidenceReceipt, SaasObservation, SaasSanctionStatus,
        WorkloadObservation,
    };

    use super::*;

    fn observation(kind: ObservationKind) -> Observation {
        let mut observation = Observation::new(
            Uuid::nil(),
            "2026-08-13T08:00:00Z".parse().expect("time"),
            ConnectorRef {
                instance_id: Uuid::nil(),
                connector_type: "enterprise_fixture".to_owned(),
                implementation_version: "1".to_owned(),
                source_lineage_id: Some("enterprise:fixture".to_owned()),
            },
            kind,
            EvidenceReceipt::RecordDigest {
                algorithm: DigestAlgorithm::Sha256,
                digest: "ab".repeat(32),
            },
        );
        observation.received_at = Utc::now();
        observation
    }

    #[test]
    fn casb_capability_creates_tenant_system_without_usage_claim() {
        let mut observation = observation(ObservationKind::SaasCapability);
        observation.saas = SaasObservation {
            tenant_key: Some(format!("p1_{}", "1".repeat(64))),
            application_key: Some(format!("p1_{}", "2".repeat(64))),
            capability_state: Some(SaasCapabilityState::Enabled),
            sanction_status: Some(SaasSanctionStatus::Unknown),
        };
        observation.service.vendor_application_id = Some("svc.openai.api".to_owned());
        let first = resolve_saas_capability(&observation).expect("resolve");
        let replay = resolve_saas_capability(&observation).expect("replay");
        assert_eq!(first, replay);
        let system = first.system.expect("system");
        assert!(
            system
                .claims
                .iter()
                .any(|claim| claim.predicate == ClaimPredicate::CapabilityEnabled)
        );
        assert!(
            !system
                .claims
                .iter()
                .any(|claim| claim.predicate == ClaimPredicate::ResourceUsed)
        );
        assert_eq!(first.relationships.len(), 1);
    }

    #[test]
    fn kubernetes_runtime_creates_scope_workload_and_system_edges() {
        let mut observation = observation(ObservationKind::KubernetesResource);
        observation.workload = WorkloadObservation {
            cluster_key: Some(format!("p1_{}", "1".repeat(64))),
            namespace_key: Some(format!("p1_{}", "2".repeat(64))),
            workload_key: Some(format!("p1_{}", "3".repeat(64))),
            workload_kind: Some(WorkloadKind::Deployment),
            namespace_name: Some("tally-e2e".to_owned()),
            workload_name: Some("unsanctioned-ollama".to_owned()),
            runtime_registry_entry_id: Some("runtime.ollama".to_owned()),
            runtime_image: Some("docker.io/ollama/ollama:latest".to_owned()),
            ..WorkloadObservation::default()
        };
        let resolved = resolve_kubernetes_resource(&observation).expect("resolve");
        assert_eq!(resolved.entities.len(), 4);
        assert_eq!(resolved.relationships.len(), 3);
        let system = resolved.system.expect("system");
        assert_eq!(
            system.view.display_name,
            "Ollama · deployment tally-e2e/unsanctioned-ollama · docker.io/ollama/ollama:latest"
        );
        assert!(resolved.entities.iter().any(|entity| {
            entity.kind == EntityKind::Workload
                && entity.display_name == "Kubernetes deployment tally-e2e/unsanctioned-ollama"
        }));
    }

    #[test]
    fn raw_enterprise_identifiers_are_rejected() {
        let mut observation = observation(ObservationKind::KubernetesResource);
        observation.workload.cluster_key = Some("raw-cluster".to_owned());
        observation.workload.namespace_key = Some(format!("p1_{}", "2".repeat(64)));
        observation.workload.workload_key = Some(format!("p1_{}", "3".repeat(64)));
        observation.workload.workload_kind = Some(WorkloadKind::Deployment);
        assert!(matches!(
            resolve_kubernetes_resource(&observation),
            Err(EnterpriseResolutionError::UnsafeIdentifier("cluster_key"))
        ));
    }
}
