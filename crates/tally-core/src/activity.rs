//! Bounded source facts. A process, an agent signature, and a client hint are separate evidence.
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessObservation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_unique_id: Option<String>,
}

impl ProcessObservation {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// Read an executable-path field, never a command-line field. Strip personal paths and
    /// reject control characters, shell syntax and option-like arguments. Spaces and parentheses
    /// are legitimate parts of macOS/Windows executable names.
    pub fn executable_basename(value: &str) -> Option<String> {
        let name = value.rsplit(['/', '\\']).next()?;
        (!name.is_empty()
            && name.len() <= 128
            && name.trim() == name
            && !value.contains(" -")
            && !value.chars().any(char::is_control)
            && name.chars().any(char::is_alphanumeric)
            && name
                .chars()
                .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ' | '(' | ')')))
        .then(|| name.to_owned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityRole {
    AssociatedUser,
    RequestActor,
    ProcessAccount,
    AssignedOwner,
    PrimaryUser,
    EnrolledBy,
    LastLoggedIn,
    ServicePrincipal,
    CloudPrincipal,
    Creator,
    KeyOwner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct InventoryIdentifier {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AddressRole {
    ObservedSource,
    LocalInterface,
    PublicEgress,
    Proxy,
    Warp,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeviceIdentifierKind {
    SourceNative,
    ClientSupplied,
    HostnameAlias,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AddressObservation {
    pub address: crate::IpAddress,
    pub role: AddressRole,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub network_key: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct InventoryObservation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_key_kind: Option<DeviceIdentifierKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<AddressObservation>,
    /// Set only by a successfully completed, bounded inventory snapshot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_at: Option<DateTime<Utc>>,
    /// Device report/check-in time, distinct from when an inventory assignment was observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reported_at: Option<DateTime<Utc>>,
    /// Installation-HMAC directory scope, only when the source identifies the directory tenant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory_tenant_key: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identifiers: Vec<InventoryIdentifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// Bounded device display name, separate from a validated hostname/FQDN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_role: Option<IdentityRole>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(default)]
    pub retired: bool,
}
impl InventoryObservation {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// A single source-associated activity; never constructed by multiplying finding summaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct ActivityAttribution {
    #[serde(default)]
    pub device_key_kind: Option<DeviceIdentifierKind>,
    pub observation_id: uuid::Uuid,
    pub observed_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub connector: crate::ConnectorRef,
    pub actor: crate::ActorObservation,
    pub destination: crate::DestinationObservation,
    pub process: ProcessObservation,
    pub agent: crate::AgentObservation,
    pub workload: crate::WorkloadObservation,
    pub network: crate::NetworkObservation,
    pub model: Option<String>,
    pub user_role: Option<IdentityRole>,
    pub source: crate::EvidenceReceipt,
    #[serde(default)]
    pub source_scope: Option<String>,
    #[serde(default)]
    pub fields: std::collections::BTreeMap<String, FieldEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttributionBasis {
    Observed,
    SourceReported,
    Correlated,
    Configured,
    Ambiguous,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct FieldEvidence {
    pub basis: AttributionBasis,
    pub dataset: String,
    pub source_field: String,
    pub observed_at: DateTime<Utc>,
    pub observation_id: uuid::Uuid,
    pub rule: Option<String>,
}

impl From<&crate::Observation> for ActivityAttribution {
    #[allow(clippy::too_many_lines)] // Keep the per-field provenance mapping beside its values.
    fn from(o: &crate::Observation) -> Self {
        let mut fields = std::collections::BTreeMap::new();
        let endpoint = o.connector.connector_type.contains("defender");
        for (field, present, source, basis, rule) in [
            (
                "user",
                o.actor.identity.is_some(),
                if endpoint {
                    "InitiatingProcessAccountUpn / InitiatingProcessAccountName"
                } else {
                    "actor.identity"
                },
                if o.agent.attribution_confidence.as_deref() == Some("inferred") {
                    AttributionBasis::Correlated
                } else {
                    AttributionBasis::SourceReported
                },
                None,
            ),
            (
                "device",
                o.actor.hostname.is_some() || o.actor.device_key.is_some(),
                if endpoint {
                    "DeviceName / DeviceId"
                } else {
                    "actor.hostname / actor.device_key"
                },
                AttributionBasis::SourceReported,
                None,
            ),
            (
                "process",
                o.process.executable.is_some(),
                if endpoint {
                    "InitiatingProcessFileName"
                } else {
                    "process.executable"
                },
                AttributionBasis::Observed,
                None,
            ),
            (
                "agent",
                o.agent.name.is_some(),
                "agent.name",
                if o.agent.state.as_deref() == Some("declared")
                    || o.connector.connector_type.contains("_agents_")
                {
                    AttributionBasis::Configured
                } else {
                    AttributionBasis::Correlated
                },
                Some("agent_signatures:v1".to_owned()),
            ),
            (
                "client",
                o.actor.request_client.is_some(),
                "actor.request_client",
                AttributionBasis::SourceReported,
                None,
            ),
            (
                "model",
                o.service.declared_model_id.is_some(),
                "service.declared_model_id",
                if o.service.ai_request {
                    AttributionBasis::SourceReported
                } else {
                    AttributionBasis::Configured
                },
                None,
            ),
        ] {
            fields.insert(
                field.to_owned(),
                FieldEvidence {
                    basis: if present {
                        basis
                    } else {
                        AttributionBasis::Unavailable
                    },
                    dataset: o
                        .service
                        .source_category
                        .clone()
                        .unwrap_or_else(|| o.connector.connector_type.clone()),
                    source_field: source.into(),
                    observed_at: o.observed_at,
                    observation_id: o.observation_id,
                    rule: if present { rule } else { None },
                },
            );
        }
        Self {
            device_key_kind: o.inventory.device_key_kind,
            observation_id: o.observation_id,
            observed_at: o.observed_at,
            received_at: o.received_at,
            connector: o.connector.clone(),
            actor: o.actor.clone(),
            destination: o.destination.clone(),
            process: o.process.clone(),
            agent: o.agent.clone(),
            workload: o.workload.clone(),
            network: o.network.clone(),
            model: o.service.declared_model_id.clone(),
            user_role: o.inventory.user_role.clone().or_else(|| {
                o.actor.identity.as_ref().map(|_| {
                    if o.cloud.provider.is_some() {
                        IdentityRole::CloudPrincipal
                    } else {
                        IdentityRole::AssociatedUser
                    }
                })
            }),
            source: o.source.clone(),
            fields,
            source_scope: o
                .saas
                .tenant_key
                .clone()
                .or_else(|| o.cloud.account_key.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn executable_names_never_retain_paths_or_arguments() {
        assert_eq!(
            ProcessObservation::executable_basename("C:\\Users\\alex\\claude.exe"),
            Some("claude.exe".into())
        );
        assert_eq!(
            ProcessObservation::executable_basename("/usr/bin/python3"),
            Some("python3".into())
        );
        assert_eq!(
            ProcessObservation::executable_basename("claude --token secret"),
            None
        );
        assert_eq!(ProcessObservation::executable_basename("evil\nname"), None);
        for name in [
            "microsoft edge helper",
            "code helper (plugin)",
            "Microsoft Edge.exe",
        ] {
            assert_eq!(
                ProcessObservation::executable_basename(name).as_deref(),
                Some(name)
            );
        }
        assert_eq!(
            ProcessObservation::executable_basename(
                "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
            ),
            Some("Microsoft Edge".into())
        );
        for value in [
            "node -e secret",
            "name;secret",
            "$(secret)",
            " name",
            "name\tsecret",
            "..",
        ] {
            assert_eq!(ProcessObservation::executable_basename(value), None);
        }
    }
}
