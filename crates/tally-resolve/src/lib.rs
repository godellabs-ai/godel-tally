//! Deterministic, evidence-linked stable-identity resolution.

mod cloud;
mod enterprise;
mod network;
mod usage;

pub use cloud::{
    CloudResolutionError, ResolvedCloudInventory, ResolvedCloudRelationship,
    is_managed_cloud_inventory_observation, resolve_cloud_inventory,
};
pub use enterprise::{
    EnterpriseResolutionError, ResolvedEnterpriseDiscovery, ResolvedEnterpriseRelationship,
    resolve_kubernetes_resource, resolve_saas_capability,
};
pub use network::{
    NetworkResolutionError, ResolvedCloudNetwork, ResolvedNetworkRelationship,
    resolve_cloud_network,
};
pub use usage::{
    CLOUD_USAGE_RULE_ID, CloudUsageConflictInput, CloudUsageProjectionInput,
    CloudUsageResolutionError, ResolvedCloudUsage, UsageEvidenceInput, resolve_cloud_usage,
    resolve_cloud_usage_conflict,
};

use serde::{Deserialize, Serialize};
use tally_core::{
    AiSystemView, AuthorizationStatus, BasisPoints, Claim, ClaimClass, ClaimPredicate, ClaimStatus,
    Entity, EntityKind, EntityRef, EvidenceQuality, Lifecycle, Observation, RuleRef, Surface,
};
use tally_detect::DetectionOutcome;
use tally_registry_lib::{MatchHit, RegistryBundle};
use thiserror::Error;
use uuid::Uuid;

pub const RESOLVER_RULE_VERSION: &str = "1.0.0-alpha.1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedSystem {
    pub entity: Entity,
    pub stable_key: String,
    pub view: AiSystemView,
    pub claims: Vec<Claim>,
    pub supporting_observation_id: Uuid,
}

/// Resolves registry matches into stable AI-system entities and evidence-linked claims.
///
/// A registry entry has one stable system ID per installation. Reprocessing the same observation
/// produces byte-equivalent IDs and claims. Unknown or insufficient observations produce no
/// system rather than an invented entity.
///
/// # Errors
///
/// Returns [`ResolutionError`] if detection refers to a missing registry entry, confidence is out
/// of range, or a claim value cannot be serialized.
pub fn resolve(
    observation: &Observation,
    detection: &DetectionOutcome,
    registry: &RegistryBundle,
) -> Result<Vec<ResolvedSystem>, ResolutionError> {
    let mut systems = detection
        .matches
        .iter()
        .map(|hit| resolve_hit(observation, hit, registry))
        .collect::<Result<Vec<_>, _>>()?;
    systems.sort_by_key(|system| system.entity.entity_id);
    systems.dedup_by_key(|system| system.entity.entity_id);
    Ok(systems)
}

fn resolve_hit(
    observation: &Observation,
    hit: &MatchHit,
    registry: &RegistryBundle,
) -> Result<ResolvedSystem, ResolutionError> {
    let entry = registry
        .entries
        .iter()
        .find(|entry| entry.id == hit.entry_id)
        .ok_or_else(|| ResolutionError::MissingRegistryEntry(hit.entry_id.clone()))?;
    let stable_key = format!("registry_entry:{}", entry.id);
    let system_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!(
            "godel-tally:system:{}:{stable_key}",
            observation.installation_id
        )
        .as_bytes(),
    );
    let surface = surface(entry.surfaces.first().map(String::as_str));
    let confidence = BasisPoints::new(hit.confidence_bps)?;
    let entity_ref = EntityRef {
        entity_id: system_id,
        kind: EntityKind::AiSystem,
    };
    let entity = Entity {
        entity_id: system_id,
        kind: EntityKind::AiSystem,
        display_name: entry.name.clone(),
        created_at: observation.observed_at,
        revision: 1,
    };
    let mut claims = vec![claim(
        entity_ref,
        ClaimPredicate::Product,
        serde_json::Value::String(entry.id.clone()),
        hit,
        observation,
        &registry.version,
    )?];
    claims.push(claim(
        entity_ref,
        ClaimPredicate::Surface,
        serde_json::to_value(surface)?,
        hit,
        observation,
        &registry.version,
    )?);
    if let Some(destination) = destination_value(observation) {
        claims.push(claim(
            entity_ref,
            ClaimPredicate::Destination,
            serde_json::Value::String(destination),
            hit,
            observation,
            &registry.version,
        )?);
    }
    claims.sort_by_key(|claim| claim.claim_id);

    Ok(ResolvedSystem {
        entity,
        stable_key,
        view: AiSystemView {
            system_id,
            display_name: entry.name.clone(),
            surface,
            lifecycle: Lifecycle::Observed,
            authorization: AuthorizationStatus::Discovered,
            first_seen: observation.observed_at,
            last_seen: observation.observed_at,
            evidence_quality: evidence_quality(hit.confidence_bps),
            confidence,
            findings: Vec::new(),
            revision: 1,
        },
        claims,
        supporting_observation_id: observation.observation_id,
    })
}

fn claim(
    subject: EntityRef,
    predicate: ClaimPredicate,
    value: serde_json::Value,
    hit: &MatchHit,
    observation: &Observation,
    registry_version: &str,
) -> Result<Claim, ResolutionError> {
    let identity = serde_json::to_vec(&(&predicate, &value))?;
    let claim_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!(
            "godel-tally:claim:{}:{}:{}",
            subject.entity_id,
            observation.observation_id,
            hex::encode(identity)
        )
        .as_bytes(),
    );
    Ok(Claim {
        claim_id,
        subject,
        predicate,
        value,
        class: ClaimClass::Derived,
        confidence: BasisPoints::new(hit.confidence_bps)?,
        status: ClaimStatus::Active,
        valid_from: observation.observed_at,
        valid_until: None,
        rule: Some(RuleRef {
            rule_id: format!("registry:{}", hit.matcher_id),
            version: RESOLVER_RULE_VERSION.into(),
        }),
        registry_version: Some(registry_version.into()),
        created_at: observation.received_at,
    })
}

fn destination_value(observation: &Observation) -> Option<String> {
    observation
        .destination
        .host
        .as_ref()
        .map(|host| host.as_str().to_owned())
        .or_else(|| {
            observation.destination.ip.as_ref().map(|ip| {
                observation.destination.port.map_or_else(
                    || ip.as_str().to_owned(),
                    |port| format!("{}:{port}", ip.as_str()),
                )
            })
        })
}

fn surface(value: Option<&str>) -> Surface {
    match value {
        Some("self_hosted_api") => Surface::SelfHosted,
        Some("external_api") => Surface::ExternalApi,
        Some("developer_tool" | "browser_application") => Surface::Assistant,
        Some("embedded_saas") => Surface::EmbeddedSaas,
        Some("managed_cloud") => Surface::ManagedCloud,
        Some("model_hub") => Surface::ModelHub,
        Some("agent_or_mcp") => Surface::AgentOrMcp,
        _ => Surface::Unknown,
    }
}

fn evidence_quality(confidence_bps: u16) -> EvidenceQuality {
    match confidence_bps {
        9_000..=10_000 => EvidenceQuality::Strong,
        7_000..=8_999 => EvidenceQuality::Moderate,
        1..=6_999 => EvidenceQuality::Weak,
        _ => EvidenceQuality::Unknown,
    }
}

#[derive(Debug, Error)]
pub enum ResolutionError {
    #[error("detection references missing registry entry {0}")]
    MissingRegistryEntry(String),
    #[error(transparent)]
    Confidence(#[from] tally_core::BasisPointsError),
    #[error("serialize deterministic claim identity: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{NaiveDate, Utc};
    use tally_core::{ConnectorRef, DigestAlgorithm, EvidenceReceipt, Hostname, ObservationKind};
    use tally_detect::detect;
    use tally_registry_lib::{
        Evidence, EvidenceType, MatchProduces, Matcher, MatcherRule, ProofKind,
        REGISTRY_SCHEMA_VERSION, RegistryEntry, RegistryEntryKind, RegistryEntryStatus,
        RegistrySource,
    };

    use super::*;

    fn fixture() -> (Observation, RegistryBundle) {
        let observed_at = "2026-08-13T10:00:00Z".parse().expect("timestamp");
        let mut observation = Observation::new(
            Uuid::parse_str("018f6cd4-4aaf-7bb4-a3b2-a7524ec43711").expect("UUID"),
            observed_at,
            ConnectorRef {
                instance_id: Uuid::nil(),
                connector_type: "dns".into(),
                implementation_version: "1".into(),
                source_lineage_id: None,
            },
            ObservationKind::DnsQuery,
            EvidenceReceipt::RecordDigest {
                algorithm: DigestAlgorithm::Sha256,
                digest: "00".repeat(32),
            },
        );
        observation.observation_id =
            Uuid::parse_str("018f6cd4-4aaf-7bb4-a3b2-a7524ec43713").expect("UUID");
        observation.received_at = Utc::now();
        observation.destination.host = Some(Hostname::parse("api.openai.com").expect("host"));
        let date = NaiveDate::from_ymd_opt(2026, 8, 13).expect("date");
        let registry = RegistrySource {
            schema_version: REGISTRY_SCHEMA_VERSION.into(),
            version: "fixture".into(),
            fingerprints: Vec::new(),
            entries: vec![RegistryEntry {
                id: "svc.openai.api".into(),
                kind: RegistryEntryKind::Service,
                name: "OpenAI API".into(),
                provider_ref: None,
                categories: vec!["llm_api".into()],
                surfaces: vec!["external_api".into()],
                facts: BTreeMap::new(),
                matchers: vec![Matcher {
                    id: "host.api".into(),
                    rule: MatcherRule::HostExact {
                        value: "api.openai.com".into(),
                    },
                    produces: MatchProduces {
                        entity_ref: "svc.openai.api".into(),
                        proof: ProofKind::ServiceContact,
                    },
                    confidence_bps: 9_900,
                    verified_at: date,
                    evidence: vec![Evidence {
                        source_type: EvidenceType::VendorDocumentation,
                        url: "https://platform.openai.com/docs/api-reference/models".into(),
                        verified_at: date,
                        reviewer: "test".into(),
                    }],
                }],
                status: RegistryEntryStatus::Active,
            }],
        }
        .compile("fixture")
        .expect("compile")
        .bundle;
        (observation, registry)
    }

    #[test]
    fn replay_produces_identical_system_and_claim_ids() {
        let (observation, registry) = fixture();
        let detection = detect(&observation, &registry).expect("detect");
        let first = resolve(&observation, &detection, &registry).expect("resolve");
        let replay = resolve(&observation, &detection, &registry).expect("resolve replay");
        assert_eq!(first, replay);
        assert_eq!(first[0].view.display_name, "OpenAI API");
        assert_eq!(first[0].view.surface, Surface::ExternalApi);
        assert_eq!(first[0].claims.len(), 3);
    }

    #[test]
    fn later_evidence_keeps_system_id_but_gets_new_claim_ids() {
        let (observation, registry) = fixture();
        let detection = detect(&observation, &registry).expect("detect");
        let first = resolve(&observation, &detection, &registry).expect("resolve");
        let mut later = observation.clone();
        later.observation_id = Uuid::now_v7();
        let later_detection = detect(&later, &registry).expect("detect later");
        let second = resolve(&later, &later_detection, &registry).expect("resolve later");
        assert_eq!(first[0].entity.entity_id, second[0].entity.entity_id);
        assert_ne!(first[0].claims[0].claim_id, second[0].claims[0].claim_id);
    }

    #[test]
    fn unmatched_observation_does_not_invent_a_system() {
        let (mut observation, registry) = fixture();
        observation.destination.host = Some(Hostname::parse("unknown.example").expect("host"));
        let detection = detect(&observation, &registry).expect("detect");
        assert_eq!(
            resolve(&observation, &detection, &registry).expect("resolve"),
            [] as [ResolvedSystem; 0]
        );
    }
}
