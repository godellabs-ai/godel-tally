//! Deterministic observation-to-registry matching.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use tally_core::Observation;
use tally_registry_lib::{MatchHit, RegistryBundle, RegistryError};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionOutcome {
    pub observation_id: uuid::Uuid,
    pub registry_version: String,
    pub matches: Vec<MatchHit>,
    pub classification: DetectionClassification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionClassification {
    Classified,
    UnknownCandidate,
    InsufficientMetadata,
}

/// Matches only normalized, non-content fields whose matcher proof is declared by the registry.
///
/// # Errors
///
/// Returns [`DetectionError`] when the registry or a DNS-shaped observation host is invalid.
/// Valid single-label OS hostnames remain attribution evidence but are not registry match inputs.
pub fn detect(
    observation: &Observation,
    registry: &RegistryBundle,
) -> Result<DetectionOutcome, DetectionError> {
    registry.validate()?;
    let hosts = observation
        .destination
        .host
        .iter()
        .chain(observation.service.tls_server_name.iter())
        .map(tally_core::Hostname::as_str)
        .collect::<BTreeSet<_>>();

    let mut matches = Vec::new();
    for host in &hosts {
        if !host.contains('.') {
            continue;
        }
        matches.extend(registry.match_host(host)?);
    }
    if let Some(fingerprint_id) = &observation.service.scanner_fingerprint_id {
        matches.extend(registry.match_fingerprint(fingerprint_id));
    }
    matches.sort_by(|left, right| {
        right
            .confidence_bps
            .cmp(&left.confidence_bps)
            .then_with(|| left.entry_id.cmp(&right.entry_id))
            .then_with(|| left.matcher_id.cmp(&right.matcher_id))
    });
    matches.dedup_by(|left, right| {
        left.entry_id == right.entry_id && left.matcher_id == right.matcher_id
    });

    let classification = if !matches.is_empty() {
        DetectionClassification::Classified
    } else if hosts.is_empty() && observation.service.scanner_fingerprint_id.is_none() {
        DetectionClassification::InsufficientMetadata
    } else {
        DetectionClassification::UnknownCandidate
    };
    Ok(DetectionOutcome {
        observation_id: observation.observation_id,
        registry_version: registry.version.clone(),
        matches,
        classification,
    })
}

#[derive(Debug, Error)]
pub enum DetectionError {
    #[error("registry matching failed: {0}")]
    Registry(#[from] RegistryError),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{NaiveDate, Utc};
    use tally_core::{ConnectorRef, DigestAlgorithm, EvidenceReceipt, Hostname, ObservationKind};
    use tally_registry_lib::{
        Evidence, EvidenceType, FingerprintAssertion, HttpFingerprint, MatchProduces, Matcher,
        MatcherRule, ProofKind, REGISTRY_SCHEMA_VERSION, RegistryEntry, RegistryEntryKind,
        RegistryEntryStatus, RegistrySource, SafeHttpMethod,
    };

    use super::*;

    fn observation(host: Option<&str>) -> Observation {
        let mut observation = Observation::new(
            uuid::Uuid::nil(),
            Utc::now(),
            ConnectorRef {
                instance_id: uuid::Uuid::nil(),
                connector_type: "test".to_owned(),
                implementation_version: "1".to_owned(),
                source_lineage_id: None,
            },
            ObservationKind::DnsQuery,
            EvidenceReceipt::RecordDigest {
                algorithm: DigestAlgorithm::Sha256,
                digest: "00".repeat(32),
            },
        );
        observation.destination.host = host.map(|value| Hostname::parse(value).expect("host"));
        observation
    }

    fn registry() -> RegistryBundle {
        let date = NaiveDate::from_ymd_opt(2026, 8, 13).expect("date");
        RegistrySource {
            schema_version: REGISTRY_SCHEMA_VERSION.to_owned(),
            version: "test-v1".to_owned(),
            fingerprints: vec![HttpFingerprint {
                id: "fingerprint.ollama.version_v1".to_owned(),
                ports: vec![11_434],
                method: SafeHttpMethod::Get,
                request: None,
                path: "/api/version".to_owned(),
                accepted_content_types: vec!["application/json".to_owned()],
                max_response_bytes: 4_096,
                timeout_millis: 1_500,
                assertions: vec![FingerprintAssertion::JsonStringPresent {
                    field: "version".to_owned(),
                    fact: "version".to_owned(),
                }],
                verified_at: date,
                evidence: vec![Evidence {
                    source_type: EvidenceType::VendorDocumentation,
                    url: "https://docs.ollama.com/api/version".to_owned(),
                    verified_at: date,
                    reviewer: "maintainer".to_owned(),
                }],
            }],
            entries: vec![
                RegistryEntry {
                    id: "svc.openai.api".to_owned(),
                    kind: RegistryEntryKind::Service,
                    name: "OpenAI API".to_owned(),
                    provider_ref: None,
                    categories: vec!["llm_api".to_owned()],
                    surfaces: vec!["external_api".to_owned()],
                    facts: BTreeMap::new(),
                    matchers: vec![Matcher {
                        id: "host.api".to_owned(),
                        rule: MatcherRule::HostExact {
                            value: "api.openai.com".to_owned(),
                        },
                        produces: MatchProduces {
                            entity_ref: "svc.openai.api".to_owned(),
                            proof: ProofKind::ServiceContact,
                        },
                        confidence_bps: 9_900,
                        verified_at: date,
                        evidence: vec![Evidence {
                            source_type: EvidenceType::VendorDocumentation,
                            url: "https://platform.openai.com/docs/api-reference/models".to_owned(),
                            verified_at: date,
                            reviewer: "maintainer".to_owned(),
                        }],
                    }],
                    status: RegistryEntryStatus::Active,
                },
                RegistryEntry {
                    id: "runtime.ollama".to_owned(),
                    kind: RegistryEntryKind::Runtime,
                    name: "Ollama".to_owned(),
                    provider_ref: None,
                    categories: vec!["runtime".to_owned()],
                    surfaces: vec!["self_hosted_api".to_owned()],
                    facts: BTreeMap::new(),
                    matchers: vec![Matcher {
                        id: "scanner.version".to_owned(),
                        rule: MatcherRule::ScannerFingerprint {
                            fingerprint_ref: "fingerprint.ollama.version_v1".to_owned(),
                        },
                        produces: MatchProduces {
                            entity_ref: "runtime.ollama".to_owned(),
                            proof: ProofKind::RuntimeReachable,
                        },
                        confidence_bps: 9_800,
                        verified_at: date,
                        evidence: vec![Evidence {
                            source_type: EvidenceType::VendorDocumentation,
                            url: "https://docs.ollama.com/api/version".to_owned(),
                            verified_at: date,
                            reviewer: "maintainer".to_owned(),
                        }],
                    }],
                    status: RegistryEntryStatus::Active,
                },
            ],
        }
        .compile("fixture")
        .expect("compile")
        .bundle
    }

    #[test]
    fn exact_host_is_classified_with_proof() {
        let outcome = detect(&observation(Some("API.OpenAI.com.")), &registry()).expect("detect");
        assert_eq!(outcome.classification, DetectionClassification::Classified);
        assert_eq!(outcome.matches[0].entry_id, "svc.openai.api");
    }

    #[test]
    fn unknown_host_remains_candidate() {
        let outcome = detect(&observation(Some("unknown.example")), &registry()).expect("detect");
        assert_eq!(
            outcome.classification,
            DetectionClassification::UnknownCandidate
        );
        assert_eq!(outcome.matches, [] as [tally_registry_lib::MatchHit; 0]);
    }

    #[test]
    fn single_label_os_hostname_remains_an_unmatched_candidate() {
        let outcome = detect(&observation(Some("workstation-1")), &registry())
            .expect("single-label attribution hostname");
        assert_eq!(
            outcome.classification,
            DetectionClassification::UnknownCandidate
        );
        assert_eq!(outcome.matches, [] as [tally_registry_lib::MatchHit; 0]);
    }

    #[test]
    fn missing_host_is_not_mislabeled_unknown_service() {
        let outcome = detect(&observation(None), &registry()).expect("detect");
        assert_eq!(
            outcome.classification,
            DetectionClassification::InsufficientMetadata
        );
    }

    #[test]
    fn scanner_fingerprint_is_classified_without_inventing_a_host() {
        let mut observation = observation(None);
        observation.kind = ObservationKind::ScanFingerprint;
        observation.service.scanner_fingerprint_id =
            Some("fingerprint.ollama.version_v1".to_owned());
        let outcome = detect(&observation, &registry()).expect("detect scanner evidence");
        assert_eq!(outcome.classification, DetectionClassification::Classified);
        assert_eq!(outcome.matches[0].entry_id, "runtime.ollama");
        assert_eq!(outcome.matches[0].confidence_bps, 9_800);
    }
}
