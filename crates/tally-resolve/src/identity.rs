//! Conservative event-time device resolution. Address candidates never establish a request actor.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tally_core::IpAddress;
use uuid::Uuid;

pub const IDENTITY_RULE_VERSION: &str = "identity:v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEvidence {
    pub installation_id: Uuid,
    pub entity_id: Uuid,
    pub connector_id: Uuid,
    pub observation_id: Uuid,
    pub source_scope: String,
    pub network_key: Option<String>,
    pub device_key: Option<String>,
    pub hostname: Option<String>,
    pub addresses: Vec<IpAddress>,
    pub observed_at: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityResolutionStatus {
    Observed,
    Correlated,
    Ambiguous,
    Unresolved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceResolution {
    pub device_id: Option<Uuid>,
    pub hostname: Option<String>,
    pub status: IdentityResolutionStatus,
    pub reason: String,
    pub evidence: Vec<Uuid>,
    pub rule: String,
}

fn private_address(ip: &IpAddress) -> bool {
    match ip.as_str().parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v)) => v.is_private(),
        Ok(std::net::IpAddr::V6(v)) => v.is_unique_local(),
        _ => false,
    }
}

pub fn resolve_device(event: &DeviceEvidence, candidates: &[DeviceEvidence]) -> DeviceResolution {
    let mut matching = Vec::new();
    for candidate in candidates {
        if !candidate.active
            || candidate.installation_id != event.installation_id
            || candidate.source_scope != event.source_scope
            || candidate.observed_at > event.observed_at
            || candidate.valid_until.is_some_and(|v| v < event.observed_at)
        {
            continue;
        }
        let direct = event.device_key.is_some()
            && candidate.device_key == event.device_key
            && candidate.connector_id == event.connector_id;
        let address_match = event.network_key.is_some()
            && candidate.network_key == event.network_key
            && candidate
                .valid_until
                .is_some_and(|v| v >= event.observed_at)
            && event
                .addresses
                .iter()
                .any(|ip| private_address(ip) && candidate.addresses.contains(ip));
        if direct || address_match {
            matching.push((candidate, direct));
        }
    }
    if matching.iter().any(|(_, direct)| *direct) {
        matching.retain(|(_, direct)| *direct);
    }
    let mut entities = matching
        .iter()
        .map(|(c, _)| c.entity_id)
        .collect::<Vec<_>>();
    entities.sort();
    entities.dedup();
    let direct = matching.iter().any(|(_, direct)| *direct);
    let status = if entities.is_empty() {
        IdentityResolutionStatus::Unresolved
    } else if entities.len() > 1 {
        IdentityResolutionStatus::Ambiguous
    } else if direct {
        IdentityResolutionStatus::Observed
    } else {
        IdentityResolutionStatus::Ambiguous
    };
    let reason=match status {IdentityResolutionStatus::Observed=>"Source-scoped stable device identifier; original user/process facts remain authoritative.",IdentityResolutionStatus::Ambiguous=>"Address evidence supplies candidates only. A unique row in incomplete inventory does not establish unique IP ownership or a request actor.",_=>"No compatible stable identifier or scoped event-time address evidence. Public/shared addresses, missing scope and stale snapshots cannot identify a device."}.to_owned();
    let mut evidence = matching
        .iter()
        .map(|(c, _)| c.observation_id)
        .collect::<Vec<_>>();
    evidence.sort();
    evidence.dedup();
    let device_id = if direct && entities.len() == 1 {
        Some(entities[0])
    } else {
        None
    };
    let hostname = device_id.and_then(|id| {
        matching
            .iter()
            .filter(|(c, _)| c.entity_id == id)
            .max_by_key(|(c, _)| c.observed_at)
            .and_then(|(c, _)| c.hostname.clone())
    });
    DeviceResolution {
        device_id,
        hostname,
        status,
        reason,
        evidence,
        rule: IDENTITY_RULE_VERSION.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fact() -> DeviceEvidence {
        DeviceEvidence {
            installation_id: Uuid::now_v7(),
            entity_id: Uuid::now_v7(),
            connector_id: Uuid::now_v7(),
            observation_id: Uuid::now_v7(),
            source_scope: "tenant".into(),
            network_key: Some("site-a".into()),
            device_key: Some("native-id".into()),
            hostname: Some("laptop".into()),
            addresses: vec![IpAddress::parse("10.0.0.8").unwrap()],
            observed_at: Utc::now(),
            valid_until: None,
            active: true,
        }
    }
    #[test]
    fn stable_identity_is_scoped() {
        let event = fact();
        assert_eq!(
            resolve_device(&event, std::slice::from_ref(&event)).device_id,
            Some(event.entity_id)
        );
        let mut other = event.clone();
        other.installation_id = Uuid::now_v7();
        assert_eq!(resolve_device(&event, &[other]).device_id, None);
    }
    #[test]
    fn nat_dhcp_reuse_and_incomplete_inventory_never_establish_a_person() {
        let mut event = fact();
        event.device_key = None;
        let mut candidate = event.clone();
        candidate.connector_id = Uuid::now_v7();
        candidate.observed_at -= chrono::Duration::minutes(1);
        candidate.valid_until = Some(event.observed_at + chrono::Duration::minutes(1));
        assert_eq!(
            resolve_device(&event, std::slice::from_ref(&candidate)).status,
            IdentityResolutionStatus::Ambiguous
        );
        candidate.network_key = Some("site-b".into());
        assert_eq!(
            resolve_device(&event, &[candidate]).status,
            IdentityResolutionStatus::Unresolved
        );
    }
    #[test]
    fn public_ipv6_and_expired_evidence_are_not_matches() {
        let mut event = fact();
        event.device_key = None;
        event.addresses = vec![IpAddress::parse("2001:db8::1").unwrap()];
        let mut candidate = event.clone();
        candidate.observed_at -= chrono::Duration::minutes(1);
        candidate.valid_until = Some(event.observed_at);
        assert_eq!(
            resolve_device(&event, std::slice::from_ref(&candidate)).evidence,
            Vec::<Uuid>::new()
        );
        event.addresses = vec![IpAddress::parse("fd00::8").unwrap()];
        candidate.addresses = event.addresses.clone();
        candidate.valid_until = Some(event.observed_at - chrono::Duration::seconds(1));
        assert_eq!(
            resolve_device(&event, &[candidate]).evidence,
            Vec::<Uuid>::new()
        );
    }
    #[test]
    fn process_and_model_are_never_resolution_outputs() {
        let event = fact();
        let value =
            serde_json::to_value(resolve_device(&event, std::slice::from_ref(&event))).unwrap();
        assert!(value.get("user").is_none());
        assert!(value.get("model").is_none());
        assert!(value.get("process").is_none());
    }
}
