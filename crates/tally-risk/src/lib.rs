//! Versioned, deterministic policy-pack evaluation.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tally_core::{
    AiSystemView, AuthorizationStatus, EvidenceQuality, RiskFinding, RiskSeverity, Surface,
};
use uuid::Uuid;

pub const BASELINE_POLICY_ID: &str = "baseline-shadow-ai";
pub const BASELINE_POLICY_VERSION: &str = "1";
const FINDING_NAMESPACE: Uuid = Uuid::from_u128(0x4c915150_aa43_4ad3_b2a4_0a5fb4dd305b);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyPackRef {
    pub policy_id: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskFactor {
    pub code: String,
    pub explanation: String,
    pub weight: i16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluationInput<'a> {
    pub system: &'a AiSystemView,
    pub evidence_source_count: u32,
    pub evaluated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluatedFinding {
    pub finding: RiskFinding,
    pub factors: Vec<RiskFactor>,
}

/// Evaluates the Phase 1 baseline pack without using product origin, geography, or opaque scoring.
///
/// The policy is deliberately small: it identifies systems needing authorization, weak or stale
/// evidence, and single-source detections. Every output has stable identity and named factors.
pub fn evaluate_baseline(input: &PolicyEvaluationInput<'_>) -> Vec<EvaluatedFinding> {
    let mut findings = Vec::new();
    let system = input.system;

    if matches!(
        system.authorization,
        AuthorizationStatus::Discovered | AuthorizationStatus::UnderReview
    ) {
        let (rule, title, severity, surface_weight) = if matches!(
            system.surface,
            Surface::ExternalApi
                | Surface::Assistant
                | Surface::EmbeddedSaas
                | Surface::ManagedCloud
        ) {
            (
                "authorization.external_unreviewed",
                "External AI system needs authorization review",
                RiskSeverity::High,
                30,
            )
        } else {
            (
                "authorization.unreviewed",
                "AI system needs authorization review",
                RiskSeverity::Medium,
                15,
            )
        };
        findings.push(finding(
            system.system_id,
            rule,
            title,
            severity,
            vec![
                factor(
                    "authorization_pending",
                    "The system is discovered or under review; no authorization decision is active.",
                    40,
                ),
                factor(
                    "network_surface",
                    "The severity reflects the observed service surface, not vendor origin or geography.",
                    surface_weight,
                ),
            ],
        ));
    }

    if input.evidence_source_count < 2 {
        findings.push(finding(
            system.system_id,
            "evidence.single_source",
            "Detection relies on one evidence source",
            RiskSeverity::Low,
            vec![factor(
                "single_source",
                "No independent connector has corroborated this system yet.",
                15,
            )],
        ));
    }

    if matches!(
        system.evidence_quality,
        EvidenceQuality::Weak | EvidenceQuality::Unknown | EvidenceQuality::Conflicted
    ) {
        findings.push(finding(
            system.system_id,
            "evidence.quality_review",
            "Evidence quality needs review",
            RiskSeverity::Low,
            vec![factor(
                "evidence_quality",
                "The resolver marked the current evidence weak, unknown, or conflicted.",
                15,
            )],
        ));
    }

    if input.evaluated_at.signed_duration_since(system.last_seen) > Duration::hours(24) {
        findings.push(finding(
            system.system_id,
            "evidence.stale",
            "System evidence is stale",
            RiskSeverity::Low,
            vec![factor(
                "stale_evidence",
                "No supporting observation has arrived within the 24-hour baseline window.",
                10,
            )],
        ));
    }

    findings.sort_by_key(|finding| finding.finding.finding_id);
    findings
}

fn finding(
    system_id: Uuid,
    rule: &str,
    title: &str,
    severity: RiskSeverity,
    factors: Vec<RiskFactor>,
) -> EvaluatedFinding {
    let identity = format!("{system_id}:{BASELINE_POLICY_ID}:{BASELINE_POLICY_VERSION}:{rule}");
    EvaluatedFinding {
        finding: RiskFinding {
            finding_id: Uuid::new_v5(&FINDING_NAMESPACE, identity.as_bytes()),
            policy_id: BASELINE_POLICY_ID.to_owned(),
            policy_version: BASELINE_POLICY_VERSION.to_owned(),
            title: title.to_owned(),
            severity,
            factor_codes: factors.iter().map(|factor| factor.code.clone()).collect(),
        },
        factors,
    }
}

fn factor(code: &str, explanation: &str, weight: i16) -> RiskFactor {
    RiskFactor {
        code: code.to_owned(),
        explanation: explanation.to_owned(),
        weight,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_core::{BasisPoints, Lifecycle};

    fn system(authorization: AuthorizationStatus, surface: Surface) -> AiSystemView {
        AiSystemView {
            system_id: Uuid::parse_str("05c4c6e1-5555-5dcf-84b2-6489689db8c9").expect("uuid"),
            display_name: "Example API".to_owned(),
            surface,
            lifecycle: Lifecycle::Active,
            authorization,
            first_seen: DateTime::parse_from_rfc3339("2026-08-10T10:00:00Z")
                .expect("time")
                .with_timezone(&Utc),
            last_seen: DateTime::parse_from_rfc3339("2026-08-13T10:00:00Z")
                .expect("time")
                .with_timezone(&Utc),
            evidence_quality: EvidenceQuality::Strong,
            confidence: BasisPoints::new(9_800).expect("confidence"),
            findings: vec![],
            revision: 1,
        }
    }

    #[test]
    fn external_discovered_system_has_explainable_stable_findings() {
        let system = system(AuthorizationStatus::Discovered, Surface::ExternalApi);
        let input = PolicyEvaluationInput {
            system: &system,
            evidence_source_count: 1,
            evaluated_at: DateTime::parse_from_rfc3339("2026-08-13T13:00:00Z")
                .expect("time")
                .with_timezone(&Utc),
        };
        let first = evaluate_baseline(&input);
        let replay = evaluate_baseline(&input);
        assert_eq!(first, replay);
        assert_eq!(first.len(), 2);
        assert!(first.iter().any(|finding| {
            finding.finding.severity == RiskSeverity::High
                && finding
                    .finding
                    .factor_codes
                    .contains(&"authorization_pending".to_owned())
        }));
    }

    #[test]
    fn authorized_corroborated_system_has_no_baseline_findings() {
        let system = system(AuthorizationStatus::Authorized, Surface::ExternalApi);
        let input = PolicyEvaluationInput {
            system: &system,
            evidence_source_count: 2,
            evaluated_at: DateTime::parse_from_rfc3339("2026-08-13T13:00:00Z")
                .expect("time")
                .with_timezone(&Utc),
        };
        assert_eq!(evaluate_baseline(&input), [] as [EvaluatedFinding; 0]);
    }
}
