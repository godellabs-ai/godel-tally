use std::net::IpAddr;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::OBSERVATION_SCHEMA_VERSION;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct Observation {
    pub schema_version: String,
    pub observation_id: Uuid,
    pub installation_id: Uuid,
    pub observed_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub connector: ConnectorRef,
    pub kind: ObservationKind,
    #[serde(default, skip_serializing_if = "ActorObservation::is_empty")]
    pub actor: ActorObservation,
    #[serde(default, skip_serializing_if = "DestinationObservation::is_empty")]
    pub destination: DestinationObservation,
    #[serde(default, skip_serializing_if = "NetworkObservation::is_empty")]
    pub network: NetworkObservation,
    #[serde(default, skip_serializing_if = "ServiceObservation::is_empty")]
    pub service: ServiceObservation,
    #[serde(default, skip_serializing_if = "CloudObservation::is_empty")]
    pub cloud: CloudObservation,
    #[serde(default, skip_serializing_if = "SaasObservation::is_empty")]
    pub saas: SaasObservation,
    #[serde(default, skip_serializing_if = "WorkloadObservation::is_empty")]
    pub workload: WorkloadObservation,
    #[serde(default, skip_serializing_if = "OutcomeObservation::is_empty")]
    pub outcome: OutcomeObservation,
    #[serde(default, skip_serializing_if = "AgentObservation::is_empty")]
    pub agent: AgentObservation,
    pub source: EvidenceReceipt,
}

impl Observation {
    pub fn new(
        installation_id: Uuid,
        observed_at: DateTime<Utc>,
        connector: ConnectorRef,
        kind: ObservationKind,
        source: EvidenceReceipt,
    ) -> Self {
        Self {
            schema_version: OBSERVATION_SCHEMA_VERSION.to_owned(),
            observation_id: Uuid::now_v7(),
            installation_id,
            observed_at,
            received_at: Utc::now(),
            connector,
            kind,
            actor: ActorObservation::default(),
            destination: DestinationObservation::default(),
            network: NetworkObservation::default(),
            service: ServiceObservation::default(),
            cloud: CloudObservation::default(),
            saas: SaasObservation::default(),
            workload: WorkloadObservation::default(),
            outcome: OutcomeObservation::default(),
            agent: AgentObservation::default(),
            source,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct ConnectorRef {
    pub instance_id: Uuid,
    pub connector_type: String,
    pub implementation_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_lineage_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    /// Metadata from an instrumented agent runtime, without prompts or tool content.
    AgentActivity,
    DnsQuery,
    HttpMetadata,
    NetworkFlow,
    NetworkMapping,
    ScanFingerprint,
    CloudResource,
    CloudUsage,
    SaasCapability,
    KubernetesResource,
    RegistryPull,
    ConnectorHealth,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct ActorObservation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_key: Option<String>,
    /// Endpoint hostname when the source supplies one. Unlike `device_key`, this is retained so
    /// operators can locate a device that is using an AI provider or model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<IpAddress>,
    /// Other source addresses reported for the same device, such as a LAN address alongside the
    /// public egress address. Connectors retain only validated IP literals and findings de-duplicate
    /// them before persistence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_source_ips: Vec<IpAddress>,
    /// Bounded client/framework hint and explicit source agent ID. A client hint is not proof
    /// that a particular agent process exists. Raw headers and user-agent strings are discarded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_client: Option<RequestClientObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload: Option<WorkloadObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestClientObservation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<RequestClientKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
}

/// Allowlisted public client/framework names, never arbitrary user-agent text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RequestClientKind {
    #[serde(rename = "langchain")]
    LangChain,
    #[serde(rename = "langgraph")]
    LangGraph,
    #[serde(rename = "opencode")]
    OpenCode,
    Cursor,
    ClaudeCode,
    Codex,
    OpenaiPython,
    OpenaiNode,
    Curl,
}

impl RequestClientKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LangChain => "langchain",
            Self::LangGraph => "langgraph",
            Self::OpenCode => "opencode",
            Self::Cursor => "cursor",
            Self::ClaudeCode => "claude_code",
            Self::Codex => "codex",
            Self::OpenaiPython => "openai_python",
            Self::OpenaiNode => "openai_node",
            Self::Curl => "curl",
        }
    }
    /// Extracts a recognized product token, not a substring or arbitrary tag value.
    #[must_use]
    pub fn from_user_agent(value: &str) -> Option<Self> {
        if value.len() > 2_048 || value.chars().any(char::is_control) {
            return None;
        }
        let clients = value
            .split_ascii_whitespace()
            .filter_map(|token| {
                let token = token.trim_matches(['(', ')', ';']).to_ascii_lowercase();
                let product = token.split('/').next()?;
                match product {
                    "langchain" | "langchain-agent" => Some(Self::LangChain),
                    "langgraph" => Some(Self::LangGraph),
                    "opencode" => Some(Self::OpenCode),
                    "cursor" | "cursor-ide" => Some(Self::Cursor),
                    "claude-code" | "claude-cli" => Some(Self::ClaudeCode),
                    "codex" | "codex-cli" | "codex-tui" => Some(Self::Codex),
                    "openai-python" => Some(Self::OpenaiPython),
                    "openai-node" => Some(Self::OpenaiNode),
                    "curl" => Some(Self::Curl),
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        clients
            .iter()
            .copied()
            .find(|client| !matches!(client, Self::OpenaiPython | Self::OpenaiNode | Self::Curl))
            .or_else(|| clients.first().copied())
    }
}

impl RequestClientObservation {
    /// Source identifiers are opaque bounded ID tokens, not URLs, headers, or free-form text.
    #[must_use]
    pub fn valid_agent_id(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 256
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
            })
    }
}

impl ActorObservation {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct IdentityObservation {
    /// Installation-local pseudonymous key by default.
    pub subject_key: String,
    /// Endpoint user email when the connector supplies one. This is retained for findings so an
    /// operator can contact the user responsible for the observed usage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Bounded source-native identity when the source does not report an email address. This may
    /// be a login name or an immutable provider user ID and is retained so an operator can resolve
    /// the responsible user in the source system.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_subject_kind: Option<IdentitySubjectKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority: Option<IdentityAuthority>,
    /// Installation-local pseudonym for the source directory, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory_key: Option<String>,
    /// Installation-local pseudonym for the application, when the activity is app-scoped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_key: Option<String>,
    /// Reserved for explicit operator metadata. Source-provided names are not copied here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_label: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityAuthority {
    SourceNative,
    GateCorrelation,
    CloudIam,
    LocalOperator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySubjectKind {
    UserName,
    SourceUserId,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct WorkloadObservation {
    /// Deprecated wire compatibility field. If present, the value must already be an
    /// installation-local pseudonym; connectors must never place a raw provider account ID here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    /// Deprecated wire compatibility field. If present, the value must already be an
    /// installation-local pseudonym.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    /// Deprecated wire compatibility field. If present, the value must already be an
    /// installation-local pseudonym.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Deprecated wire compatibility field. If present, the value must already be an
    /// installation-local pseudonym.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload_kind: Option<WorkloadKind>,
    /// Validated Kubernetes namespace name retained so operators can locate and remediate the
    /// workload. This is never populated from labels, annotations, or workload content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_name: Option<String>,
    /// Validated Kubernetes object name retained so operators can locate and remediate the
    /// workload discovered by a read-only Kubernetes connector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload_name: Option<String>,
    /// Registry-controlled public runtime identifier matched in memory from resource metadata.
    /// Labels and annotations are never copied here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_registry_entry_id: Option<String>,
    /// Exact bounded container image reference for the single allowlisted AI runtime matched in
    /// this workload. Unrelated sidecar images are discarded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_image: Option<String>,
}

impl WorkloadObservation {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadKind {
    Deployment,
    StatefulSet,
    DaemonSet,
    Job,
    CronJob,
    Pod,
    Service,
    Node,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct SaasObservation {
    /// Installation-local pseudonym for the source CASB account or tenant boundary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_key: Option<String>,
    /// Installation-local pseudonym for the source integration/application instance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_key: Option<String>,
    /// Bounded source-native capability state. This proves configuration, never user activity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_state: Option<SaasCapabilityState>,
    /// Source-native sanction metadata. Tally does not author or enforce this state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sanction_status: Option<SaasSanctionStatus>,
}

impl SaasObservation {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SaasCapabilityState {
    Enabled,
    Disabled,
    Paused,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SaasSanctionStatus {
    Sanctioned,
    Unsanctioned,
    Monitored,
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct DestinationObservation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<Hostname>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// A registry-approved static prefix only; never a full path, query, or fragment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_resource_id: Option<String>,
}

impl DestinationObservation {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct NetworkObservation {
    /// Installation-local pseudonym for the provider network/VPC/VNet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_key: Option<String>,
    /// Installation-local pseudonym for the source address within its provider network.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_endpoint_key: Option<String>,
    /// Installation-local pseudonym for the destination address within its provider network.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_endpoint_key: Option<String>,
    /// Mapping-only: installation-local pseudonym matching managed-cloud inventory resource keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapped_resource_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packets: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_sent: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_received: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_millis: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<FlowDirection>,
    /// End of a source-authoritative flow or mapping validity window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
}

impl NetworkObservation {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FlowDirection {
    Ingress,
    Egress,
    Lateral,
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct ServiceObservation {
    /// Registry-controlled identifier for a matched, benign scanner fingerprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_fingerprint_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_application_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_model_id: Option<String>,
    /// True only when a connector recognized a bounded AI inference request signature while
    /// normalizing transient HTTP metadata or content. Raw paths, bodies, headers, prompts, and
    /// responses are never retained to prove this bit.
    #[serde(default, skip_serializing_if = "is_false")]
    pub ai_request: bool,
    /// True when HTTP path or body material was available and a connector completed the bounded
    /// AI request signature check. A checked regular request must not be admitted solely because
    /// its hostname belongs to a known provider.
    #[serde(default, skip_serializing_if = "is_false")]
    pub ai_request_evaluated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_server_name: Option<Hostname>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_certificate_sha256: Option<String>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

impl ServiceObservation {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct CloudObservation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<CloudProvider>,
    /// Installation-local pseudonym for a provider account, subscription, or project account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_key: Option<String>,
    /// Installation-local pseudonym for the containing subscription, project, or account scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_key: Option<String>,
    /// Provider-controlled region token. Connectors reject arbitrary or user-controlled values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_kind: Option<CloudResourceKind>,
    /// Installation-local pseudonym derived from the provider-native resource identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_service: Option<CloudProviderService>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<CloudLifecycleState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_kind: Option<CloudUsageKind>,
}

impl CloudObservation {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CloudProviderService {
    AwsBedrock,
    AwsSagemaker,
    AzureOpenai,
    AzureAiFoundry,
    GcpVertexAi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CloudResourceKind {
    OrganizationScope,
    AccountScope,
    FoundationModel,
    ModelArtifact,
    ModelDeployment,
    InferenceEndpoint,
    Agent,
    KnowledgeBase,
    NetworkInterface,
    Workload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CloudLifecycleState {
    Provisioning,
    Active,
    Updating,
    Failed,
    Deleting,
    Deleted,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CloudUsageKind {
    Invocation,
    ControlPlane,
    NetworkFlow,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct OutcomeObservation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code: Option<String>,
}

impl OutcomeObservation {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EvidenceReceipt {
    ExternalPointer {
        source_record_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        location_hint: Option<String>,
    },
    RecordDigest {
        algorithm: DigestAlgorithm,
        digest: String,
    },
    CheckpointDigest {
        checkpoint: String,
        canonical_record_digest: String,
    },
    ScannerTranscriptDigest {
        probe_id: Uuid,
        transcript_digest: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DigestAlgorithm {
    Sha256,
    Blake3,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(transparent)]
pub struct Hostname(String);

impl Hostname {
    /// Parses and normalizes a DNS hostname.
    ///
    /// # Errors
    ///
    /// Returns [`HostnameError`] when the hostname or one of its labels is invalid.
    pub fn parse(input: &str) -> Result<Self, HostnameError> {
        let normalized = input.trim().trim_end_matches('.').to_ascii_lowercase();
        if normalized.is_empty() || normalized.len() > 253 {
            return Err(HostnameError::InvalidLength);
        }
        if normalized
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63 || !valid_label(label))
        {
            return Err(HostnameError::InvalidLabel);
        }
        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_label(label: &str) -> bool {
    !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HostnameError {
    #[error("hostname length is invalid")]
    InvalidLength,
    #[error("hostname contains an invalid label")]
    InvalidLabel,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(transparent)]
pub struct IpAddress(String);

impl IpAddress {
    /// Parses an IPv4 or IPv6 address into its canonical string representation.
    ///
    /// # Errors
    ///
    /// Returns [`IpAddressError`] when `input` is not a valid IP address.
    pub fn parse(input: &str) -> Result<Self, IpAddressError> {
        input
            .parse::<IpAddr>()
            .map(|value| Self(value.to_string()))
            .map_err(|_| IpAddressError)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("IP address is invalid")]
pub struct IpAddressError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_names_are_allowlisted_and_match_wire_tokens() {
        for (value, expected) in [
            ("LangChain-agent/1.0", Some(RequestClientKind::LangChain)),
            (
                "openai-python/3.0 LangChain/0.2.11",
                Some(RequestClientKind::LangChain),
            ),
            (
                "opencode/1.18.30 ai-sdk/provider-utils/4.0.23",
                Some(RequestClientKind::OpenCode),
            ),
            ("secret=LangChain/1.0", None),
            ("NotLangChain/1.0", None),
            ("LangChain/1.0\nsecret", None),
        ] {
            assert_eq!(RequestClientKind::from_user_agent(value), expected);
            if let Some(client) = expected {
                assert_eq!(serde_json::to_value(client).unwrap(), client.as_str());
            }
        }
        assert!(RequestClientKind::from_user_agent(&"x".repeat(2_049)).is_none());
        assert!(!RequestClientObservation::valid_agent_id(
            "https://example.test/?key=secret"
        ));
        assert!(RequestClientObservation::valid_agent_id(
            "agent-42:workload_7"
        ));
    }

    #[test]
    fn hostname_is_normalized() {
        let host = Hostname::parse(" API.Anthropic.COM. ").expect("valid host");
        assert_eq!(host.as_str(), "api.anthropic.com");
    }

    #[test]
    fn hostname_rejects_unsafe_shape() {
        assert!(Hostname::parse("api.anthropic.com/path?q=secret").is_err());
        assert!(Hostname::parse("-broken.example").is_err());
    }

    #[test]
    fn ip_address_is_canonical() {
        let ip = IpAddress::parse("2001:0db8::1").expect("valid IP address");
        assert_eq!(ip.as_str(), "2001:db8::1");
    }

    #[test]
    fn observation_serialization_has_no_content_field() {
        let observation = Observation::new(
            Uuid::nil(),
            Utc::now(),
            ConnectorRef {
                instance_id: Uuid::nil(),
                connector_type: "test".to_owned(),
                implementation_version: "0".to_owned(),
                source_lineage_id: None,
            },
            ObservationKind::DnsQuery,
            EvidenceReceipt::RecordDigest {
                algorithm: DigestAlgorithm::Sha256,
                digest: "00".repeat(32),
            },
        );
        let value = serde_json::to_value(observation).expect("serialize observation");
        let mut keys = Vec::new();
        collect_keys(&value, &mut keys);
        for forbidden in [
            "prompt",
            "response_body",
            "request_body",
            "document",
            "message",
            "source_code",
            "clipboard",
            "headers",
            "cookies",
            "token",
        ] {
            assert!(!keys.contains(&forbidden), "found {forbidden}");
        }
    }

    fn collect_keys<'a>(value: &'a serde_json::Value, keys: &mut Vec<&'a str>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    keys.push(key);
                    collect_keys(value, keys);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    collect_keys(value, keys);
                }
            }
            _ => {}
        }
    }
}

/// Allowlisted agent metadata. Command lines are inspected transiently; only a recognized
/// executable/package signature is retained, never arbitrary arguments or source content.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct AgentObservation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_process_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribution_confidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribution_basis: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory_object_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_file: Option<String>,
}
impl AgentObservation {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}
