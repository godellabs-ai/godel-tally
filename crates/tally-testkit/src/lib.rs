//! Deterministic fixtures shared by Tally tests.

use chrono::{TimeZone, Utc};
use tally_core::{
    BasisPoints, Claim, ClaimClass, ClaimPredicate, ClaimStatus, ConnectorRef, DigestAlgorithm,
    Entity, EntityKind, EntityRef, EvidenceReceipt, Observation, ObservationKind,
};
use uuid::Uuid;

/// Returns a deterministic, content-free observation for tests and examples.
///
/// # Panics
///
/// Panics only if the compile-time fixture timestamp is invalid.
pub fn observation_fixture() -> Observation {
    let observed_at = Utc
        .with_ymd_and_hms(2026, 8, 13, 12, 0, 0)
        .single()
        .expect("fixture time is valid");
    Observation::new(
        Uuid::nil(),
        observed_at,
        ConnectorRef {
            instance_id: Uuid::nil(),
            connector_type: "fixture".to_owned(),
            implementation_version: "1".to_owned(),
            source_lineage_id: Some("fixture-lineage".to_owned()),
        },
        ObservationKind::DnsQuery,
        EvidenceReceipt::RecordDigest {
            algorithm: DigestAlgorithm::Sha256,
            digest: "00".repeat(32),
        },
    )
}

/// Returns the stable entity used by the storage acceptance check.
///
/// # Panics
///
/// Panics only if the compile-time fixture timestamp is invalid.
pub fn entity_fixture() -> Entity {
    Entity {
        entity_id: Uuid::from_u128(0x0198_0000_0000_7000_8000_0000_0000_0001),
        kind: EntityKind::AiSystem,
        display_name: "Tally storage acceptance fixture".to_owned(),
        created_at: Utc
            .with_ymd_and_hms(2026, 8, 13, 12, 0, 0)
            .single()
            .expect("fixture time is valid"),
        revision: 1,
    }
}

/// Returns the stable claim used by the storage acceptance check.
///
/// # Panics
///
/// Panics only if the compile-time fixture timestamp or confidence is invalid.
pub fn claim_fixture() -> Claim {
    let entity = entity_fixture();
    Claim {
        claim_id: Uuid::from_u128(0x0198_0000_0000_7000_8000_0000_0000_0002),
        subject: EntityRef {
            entity_id: entity.entity_id,
            kind: entity.kind,
        },
        predicate: ClaimPredicate::Surface,
        value: serde_json::json!("self_hosted"),
        class: ClaimClass::Derived,
        confidence: BasisPoints::new(10_000).expect("fixture confidence is valid"),
        status: ClaimStatus::Active,
        valid_from: entity.created_at,
        valid_until: None,
        rule: None,
        registry_version: Some("acceptance-fixture-v1".to_owned()),
        created_at: entity.created_at,
    }
}
