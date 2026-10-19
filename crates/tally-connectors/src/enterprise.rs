use std::{collections::BTreeSet, net::IpAddr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::IgnoredAny};
use sha2::{Digest, Sha256};
use tally_core::{
    ConnectorRef, DigestAlgorithm, EvidenceReceipt, Hostname, Observation, ObservationKind,
    SaasCapabilityState, SaasSanctionStatus, WorkloadKind,
};

use crate::{
    ConnectorDescriptor, ConnectorTransport, ObservationBatch, ReplayCapability,
    VendorImportConfig, VendorImportError, VendorImportOutcome, VendorImportStats,
};

const CLOUDFLARE_CASB_CONNECTOR_TYPE: &str = "cloudflare_casb_integrations_file_v1";
const CLOUDFLARE_CASB_API_CONNECTOR_TYPE: &str = "cloudflare_casb_integrations_api_v1";
const KUBERNETES_CONNECTOR_TYPE: &str = "kubernetes_api_discovery_file_v1";
const KUBERNETES_API_CONNECTOR_TYPE: &str = "kubernetes_api_discovery_pull_v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CasbAiApplication {
    Anthropic,
    Openai,
}

impl CasbAiApplication {
    const fn registry_entry(self) -> &'static str {
        match self {
            Self::Anthropic => "svc.anthropic.api",
            Self::Openai => "svc.openai.api",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CasbIntegrationStatus {
    Healthy,
    Unhealthy,
    Pending,
    Failed,
    Unknown,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudflareCasbEnvelope {
    result: Vec<CloudflareCasbIntegration>,
    success: bool,
    #[serde(default, rename = "errors")]
    _errors: Option<IgnoredAny>,
    #[serde(default, rename = "messages")]
    _messages: Option<IgnoredAny>,
    #[serde(default, rename = "result_info")]
    _result_info: Option<IgnoredAny>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudflareCasbApplication {
    id: CasbAiApplication,
    #[serde(default, rename = "name")]
    _name: Option<IgnoredAny>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudflareCasbIntegration {
    id: String,
    application: CloudflareCasbApplication,
    status: CasbIntegrationStatus,
    is_paused: bool,
    updated: DateTime<Utc>,
    #[serde(default, rename = "name")]
    _name: Option<IgnoredAny>,
    #[serde(default, rename = "auth_method")]
    _auth_method: Option<IgnoredAny>,
    #[serde(default, rename = "authorization_link")]
    _authorization_link: Option<IgnoredAny>,
    #[serde(default, rename = "components")]
    _components: Option<IgnoredAny>,
    #[serde(default, rename = "link")]
    _link: Option<IgnoredAny>,
    #[serde(default, rename = "created")]
    _created: Option<IgnoredAny>,
    #[serde(default, rename = "credentials_expiry")]
    _credentials_expiry: Option<IgnoredAny>,
    #[serde(default, rename = "dlp_profiles")]
    _dlp_profiles: Option<IgnoredAny>,
    #[serde(default, rename = "health_details")]
    _health_details: Option<IgnoredAny>,
    #[serde(default, rename = "organization_id")]
    _organization_id: Option<IgnoredAny>,
    #[serde(default, rename = "use_cases")]
    _use_cases: Option<IgnoredAny>,
}

#[derive(Serialize)]
struct CanonicalCasbCapability<'a> {
    tenant_key: &'a str,
    application_key: &'a str,
    registry_entry_id: &'a str,
    capability_state: SaasCapabilityState,
    sanction_status: SaasSanctionStatus,
    observed_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KubernetesDiscoveryProjection {
    schema_version: String,
    cluster_uid: String,
    observed_at: DateTime<Utc>,
    resources: Vec<KubernetesResourceRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KubernetesResourceRecord {
    uid: String,
    namespace_uid: String,
    #[serde(default)]
    namespace_name: Option<String>,
    #[serde(default)]
    workload_name: Option<String>,
    kind: WorkloadKind,
    #[serde(default)]
    images: Vec<String>,
    #[serde(default)]
    service_ip: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default, rename = "name")]
    _name: Option<IgnoredAny>,
    #[serde(default, rename = "labels")]
    _labels: Option<IgnoredAny>,
    #[serde(default, rename = "annotations")]
    _annotations: Option<IgnoredAny>,
}

#[derive(Serialize)]
struct CanonicalKubernetesResource<'a> {
    cluster_key: &'a str,
    namespace_key: &'a str,
    workload_key: &'a str,
    kind: WorkloadKind,
    runtime_registry_entry_id: Option<&'a str>,
    runtime_image: Option<&'a str>,
    namespace_name: Option<&'a str>,
    workload_name: Option<&'a str>,
    endpoint_key: Option<&'a str>,
    hostname: Option<&'a str>,
    observed_at: DateTime<Utc>,
}

pub fn cloudflare_casb_descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor {
        connector_type: CLOUDFLARE_CASB_CONNECTOR_TYPE.to_owned(),
        display_name: "Cloudflare CASB AI capabilities".to_owned(),
        implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
        source_vendor: "Cloudflare".to_owned(),
        source_product: "Cloudflare One CASB integrations".to_owned(),
        record_variants: vec!["casb_integration_detail_v2".to_owned()],
        transport: ConnectorTransport::File,
        required_permissions: vec!["Zero Trust Read".to_owned()],
        requested_fields: vec![
            "integration ID".to_owned(),
            "bounded known AI application ID".to_owned(),
            "integration status and pause state".to_owned(),
            "updated timestamp".to_owned(),
        ],
        prohibited_fields: vec![
            "credentials, authorization links, or authentication metadata".to_owned(),
            "finding assets, content, DLP details, or health remediation text".to_owned(),
            "integration display names, user identities, or activity".to_owned(),
            "source response bytes".to_owned(),
        ],
        cursor_semantics: "immutable integration snapshot checkpoint".to_owned(),
        replay_capability: ReplayCapability::FileReplay,
        health_capabilities: vec!["integration status".to_owned(), "source freshness".to_owned()],
        coverage_capabilities: vec![
            "known AI SaaS capability".to_owned(),
            "CASB tenant boundary".to_owned(),
        ],
        privacy_contract: "Account and integration IDs are installation-HMAC pseudonymized; names, credentials, findings, health detail, user activity, and source bytes are discarded.".to_owned(),
    }
}

pub fn cloudflare_casb_api_descriptor() -> ConnectorDescriptor {
    let mut descriptor = cloudflare_casb_descriptor();
    CLOUDFLARE_CASB_API_CONNECTOR_TYPE.clone_into(&mut descriptor.connector_type);
    "Cloudflare CASB AI capabilities (native pull)".clone_into(&mut descriptor.display_name);
    descriptor.transport = ConnectorTransport::Pull;
    "complete bounded snapshot digest; pagination is consumed within each poll"
        .clone_into(&mut descriptor.cursor_semantics);
    descriptor.replay_capability = ReplayCapability::DurableCursor;
    descriptor
}

pub fn kubernetes_api_descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor {
        connector_type: KUBERNETES_CONNECTOR_TYPE.to_owned(),
        display_name: "Kubernetes API discovery".to_owned(),
        implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
        source_vendor: "Kubernetes".to_owned(),
        source_product: "Read-only Kubernetes API".to_owned(),
        record_variants: vec![
            "apps/v1 deployments".to_owned(),
            "apps/v1 statefulsets".to_owned(),
            "apps/v1 daemonsets".to_owned(),
            "batch/v1 jobs".to_owned(),
            "batch/v1 cronjobs".to_owned(),
            "v1 pods".to_owned(),
            "v1 services".to_owned(),
        ],
        transport: ConnectorTransport::File,
        required_permissions: vec![
            "get,list deployments.apps".to_owned(),
            "get,list statefulsets.apps".to_owned(),
            "get,list daemonsets.apps".to_owned(),
            "get,list jobs.batch".to_owned(),
            "get,list cronjobs.batch".to_owned(),
            "get,list pods".to_owned(),
            "get,list services".to_owned(),
            "get,list namespaces".to_owned(),
        ],
        requested_fields: vec![
            "resource, namespace, and cluster UIDs".to_owned(),
            "container image references for allowlisted runtime matching and remediation".to_owned(),
            "namespace and workload names for remediation".to_owned(),
            "private service IP for in-memory pseudonymization".to_owned(),
            "pod node hostname for endpoint attribution".to_owned(),
        ],
        prohibited_fields: vec![
            "secrets, configmaps, logs, exec, attach, proxy, or mutation verbs".to_owned(),
            "labels, annotations, environment variables, or command arguments".to_owned(),
            "raw UIDs, unrelated sidecar image names, service IPs, or API response bodies".to_owned(),
            "pod or node host access and DaemonSet installation".to_owned(),
        ],
        cursor_semantics: "resourceVersion is held only by the native collector; normalized snapshots replay by caller checkpoint".to_owned(),
        replay_capability: ReplayCapability::FileReplay,
        health_capabilities: vec!["API reachability".to_owned(), "snapshot freshness".to_owned()],
        coverage_capabilities: vec![
            "cluster and namespace scope".to_owned(),
            "workload and service inventory".to_owned(),
            "node, namespace, workload, and matched runtime image attribution".to_owned(),
        ],
        privacy_contract: "UIDs and private service IPs are installation-HMAC pseudonymized. Validated namespace, workload, pod-node, and single allowlisted AI-runtime image locators are retained for remediation; labels, annotations, unrelated images, API bodies, and workload content are discarded.".to_owned(),
    }
}

pub fn kubernetes_api_pull_descriptor() -> ConnectorDescriptor {
    let mut descriptor = kubernetes_api_descriptor();
    KUBERNETES_API_CONNECTOR_TYPE.clone_into(&mut descriptor.connector_type);
    "Kubernetes API discovery (native pull)".clone_into(&mut descriptor.display_name);
    descriptor.transport = ConnectorTransport::Pull;
    "complete bounded API snapshot digest; pagination tokens remain in memory"
        .clone_into(&mut descriptor.cursor_semantics);
    descriptor.replay_capability = ReplayCapability::DurableCursor;
    descriptor
}

/// Imports a strict Cloudflare CASB integration snapshot and retains only AI capability metadata.
///
/// # Errors
///
/// Returns [`VendorImportError`] when the response shape, bounded application/status metadata, or
/// admission batch fails closed.
pub fn import_cloudflare_casb_json(
    input: &[u8],
    account_id: &str,
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    import_cloudflare_casb_with_type(input, account_id, config, CLOUDFLARE_CASB_CONNECTOR_TYPE)
}

/// Imports a native Cloudflare CASB pull projection using the native connector identity.
///
/// # Errors
///
/// Returns [`VendorImportError`] under the same fail-closed conditions as
/// [`import_cloudflare_casb_json`].
pub fn import_cloudflare_casb_api_json(
    input: &[u8],
    account_id: &str,
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    import_cloudflare_casb_with_type(
        input,
        account_id,
        config,
        CLOUDFLARE_CASB_API_CONNECTOR_TYPE,
    )
}

fn import_cloudflare_casb_with_type(
    input: &[u8],
    account_id: &str,
    config: &VendorImportConfig,
    connector_type: &'static str,
) -> Result<VendorImportOutcome, VendorImportError> {
    validate_input(input)?;
    validate_identifier(account_id, 1, "account_id")?;
    let envelope: CloudflareCasbEnvelope =
        serde_json::from_slice(input).map_err(|_| VendorImportError::MalformedRecord { row: 1 })?;
    if !envelope.success || envelope.result.is_empty() {
        return Err(VendorImportError::NoRecords);
    }
    if envelope.result.len() > crate::MAX_BATCH_OBSERVATIONS {
        return Err(VendorImportError::InvalidField {
            row: 1,
            field: "record_count",
        });
    }
    let tenant_key = config
        .pseudonymization_key
        .pseudonym_exact("casb_tenant", account_id);
    let mut observations = Vec::with_capacity(envelope.result.len());
    for (index, record) in envelope.result.into_iter().enumerate() {
        let row = index + 1;
        validate_identifier(&record.id, row, "integration_id")?;
        let application_key = config
            .pseudonymization_key
            .pseudonym_exact("casb_application", &format!("{account_id}:{}", record.id));
        let capability_state = if record.is_paused {
            SaasCapabilityState::Paused
        } else if record.status == CasbIntegrationStatus::Healthy {
            SaasCapabilityState::Enabled
        } else {
            SaasCapabilityState::Unknown
        };
        let registry_entry_id = record.application.id.registry_entry();
        let canonical = CanonicalCasbCapability {
            tenant_key: &tenant_key,
            application_key: &application_key,
            registry_entry_id,
            capability_state,
            sanction_status: SaasSanctionStatus::Unknown,
            observed_at: record.updated,
        };
        let digest = canonical_digest(&canonical)?;
        let mut observation = base_observation(
            config,
            connector_type,
            ObservationKind::SaasCapability,
            record.updated,
            &digest,
        );
        observation.saas.tenant_key = Some(tenant_key.clone());
        observation.saas.application_key = Some(application_key);
        observation.saas.capability_state = Some(capability_state);
        observation.saas.sanction_status = Some(SaasSanctionStatus::Unknown);
        observation.service.vendor_application_id = Some(registry_entry_id.to_owned());
        observation.outcome.action = Some(
            match capability_state {
                SaasCapabilityState::Enabled => "capability_enabled",
                SaasCapabilityState::Paused => "capability_paused",
                SaasCapabilityState::Disabled => "capability_disabled",
                SaasCapabilityState::Unknown => "capability_unknown",
            }
            .to_owned(),
        );
        observations.push(observation);
    }
    finish_import(
        observations,
        connector_type,
        config,
        vec![
            "raw account and integration identifiers".to_owned(),
            "integration and application display names".to_owned(),
            "authentication, authorization, health, DLP, and use-case metadata".to_owned(),
            "finding assets, user activity, and source response bytes".to_owned(),
        ],
    )
}

/// Imports a content-free projection produced by read-only Kubernetes list calls.
///
/// # Errors
///
/// Returns [`VendorImportError`] when resource identity, image, service-address, or schema bounds
/// are invalid or the normalized batch cannot be built.
pub fn import_kubernetes_api_json(
    input: &[u8],
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    import_kubernetes_with_type(input, config, KUBERNETES_CONNECTOR_TYPE)
}

/// Imports a native Kubernetes pull projection using the native connector identity.
///
/// # Errors
///
/// Returns [`VendorImportError`] under the same fail-closed conditions as
/// [`import_kubernetes_api_json`].
pub fn import_kubernetes_api_pull_json(
    input: &[u8],
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    import_kubernetes_with_type(input, config, KUBERNETES_API_CONNECTOR_TYPE)
}

#[allow(clippy::too_many_lines)] // Sequential field admission keeps the privacy boundary auditable.
fn import_kubernetes_with_type(
    input: &[u8],
    config: &VendorImportConfig,
    connector_type: &'static str,
) -> Result<VendorImportOutcome, VendorImportError> {
    validate_input(input)?;
    let projection: KubernetesDiscoveryProjection =
        serde_json::from_slice(input).map_err(|_| VendorImportError::MalformedRecord { row: 1 })?;
    if projection.schema_version != "kubernetes_api_discovery_projection_v1" {
        return Err(VendorImportError::InvalidField {
            row: 1,
            field: "schema_version",
        });
    }
    validate_identifier(&projection.cluster_uid, 1, "cluster_uid")?;
    if projection.resources.is_empty() {
        return Err(VendorImportError::NoRecords);
    }
    if projection.resources.len() > crate::MAX_BATCH_OBSERVATIONS {
        return Err(VendorImportError::InvalidField {
            row: 1,
            field: "record_count",
        });
    }
    let cluster_key = config
        .pseudonymization_key
        .pseudonym_exact("k8s_cluster_uid", &projection.cluster_uid);
    let mut observations = Vec::with_capacity(projection.resources.len());
    for (index, record) in projection.resources.into_iter().enumerate() {
        let row = index + 1;
        validate_identifier(&record.uid, row, "uid")?;
        validate_identifier(&record.namespace_uid, row, "namespace_uid")?;
        let namespace_key = config.pseudonymization_key.pseudonym_exact(
            "k8s_namespace_uid",
            &format!("{}:{}", projection.cluster_uid, record.namespace_uid),
        );
        let workload_key = config.pseudonymization_key.pseudonym_exact(
            "k8s_workload_uid",
            &format!("{}:{}", projection.cluster_uid, record.uid),
        );
        let runtime_match = match_runtime(&record.images, row)?;
        let runtime_registry_entry_id = runtime_match.as_ref().map(|value| value.registry_entry_id);
        let runtime_image = runtime_match.as_ref().and_then(|value| value.image);
        let namespace_name = record
            .namespace_name
            .as_deref()
            .map(|value| validate_kubernetes_name(value, row, "namespace_name"))
            .transpose()?;
        let workload_name = record
            .workload_name
            .as_deref()
            .map(|value| validate_kubernetes_name(value, row, "workload_name"))
            .transpose()?;
        let endpoint_key = record
            .service_ip
            .as_deref()
            .map(|value| private_service_endpoint(value, &cluster_key, config, row))
            .transpose()?;
        let hostname = record
            .hostname
            .as_deref()
            .map(Hostname::parse)
            .transpose()
            .map_err(|_| VendorImportError::InvalidField {
                row,
                field: "hostname",
            })?;
        let canonical = CanonicalKubernetesResource {
            cluster_key: &cluster_key,
            namespace_key: &namespace_key,
            workload_key: &workload_key,
            kind: record.kind,
            runtime_registry_entry_id,
            runtime_image,
            namespace_name,
            workload_name,
            endpoint_key: endpoint_key.as_deref(),
            hostname: hostname.as_ref().map(Hostname::as_str),
            observed_at: projection.observed_at,
        };
        let digest = canonical_digest(&canonical)?;
        let mut observation = base_observation(
            config,
            connector_type,
            ObservationKind::KubernetesResource,
            projection.observed_at,
            &digest,
        );
        observation.workload.cluster_key = Some(cluster_key.clone());
        observation.workload.namespace_key = Some(namespace_key);
        observation.workload.workload_key = Some(workload_key);
        observation.workload.workload_kind = Some(record.kind);
        observation.workload.namespace_name = namespace_name.map(str::to_owned);
        observation.workload.workload_name = workload_name.map(str::to_owned);
        observation.workload.runtime_registry_entry_id =
            runtime_registry_entry_id.map(str::to_owned);
        observation.workload.runtime_image = runtime_image.map(str::to_owned);
        observation.network.destination_endpoint_key = endpoint_key;
        // The pod is running on this node, so this is a server/runtime endpoint rather than the
        // client device that initiated an inference request.
        observation.destination.host = hostname;
        observation.outcome.action = Some("resource_observed".to_owned());
        observations.push(observation);
    }
    finish_import(
        observations,
        connector_type,
        config,
        vec![
            "raw cluster, namespace, resource, and service-address identifiers".to_owned(),
            "labels, annotations, selectors, owner references, and unrelated object metadata"
                .to_owned(),
            "unrelated sidecar image names after allowlisted matching".to_owned(),
            "environment, command, arguments, secrets, logs, and API response bytes".to_owned(),
        ],
    )
}

fn private_service_endpoint(
    value: &str,
    cluster_key: &str,
    config: &VendorImportConfig,
    row: usize,
) -> Result<String, VendorImportError> {
    let address = value
        .parse::<IpAddr>()
        .map_err(|_| VendorImportError::InvalidField {
            row,
            field: "service_ip",
        })?;
    let private = match address {
        IpAddr::V4(address) => address.is_private(),
        IpAddr::V6(address) => (address.segments()[0] & 0xfe00) == 0xfc00,
    };
    if !private {
        return Err(VendorImportError::InvalidField {
            row,
            field: "service_ip",
        });
    }
    Ok(config
        .pseudonymization_key
        .pseudonym_exact("k8s_service_endpoint", &format!("{cluster_key}:{address}")))
}

struct RuntimeMatch<'a> {
    registry_entry_id: &'static str,
    image: Option<&'a str>,
}

fn match_runtime(
    images: &[String],
    row: usize,
) -> Result<Option<RuntimeMatch<'_>>, VendorImportError> {
    if images.len() > 64
        || images.iter().any(|image| {
            image.is_empty()
                || image.len() > 512
                || !image.is_ascii()
                || image
                    .bytes()
                    .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        })
    {
        return Err(VendorImportError::InvalidField {
            row,
            field: "images",
        });
    }
    let mut matches = BTreeSet::new();
    let mut matched_images = BTreeSet::new();
    for image in images {
        let normalized = image.to_ascii_lowercase();
        if normalized.contains("ollama/ollama") {
            matches.insert("runtime.ollama");
            matched_images.insert(image.as_str());
        }
        if normalized.contains("vllm/vllm-openai") {
            matches.insert("runtime.vllm");
            matched_images.insert(image.as_str());
        }
        if normalized.contains("nvidia/tritonserver") {
            matches.insert("runtime.triton");
            matched_images.insert(image.as_str());
        }
    }
    if matches.len() > 1 {
        return Err(VendorImportError::InvalidField {
            row,
            field: "runtime_ambiguity",
        });
    }
    Ok(matches
        .into_iter()
        .next()
        .map(|registry_entry_id| RuntimeMatch {
            registry_entry_id,
            image: (matched_images.len() == 1)
                .then(|| matched_images.into_iter().next())
                .flatten(),
        }))
}

fn validate_kubernetes_name<'a>(
    value: &'a str,
    row: usize,
    field: &'static str,
) -> Result<&'a str, VendorImportError> {
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
        return Err(VendorImportError::InvalidField { row, field });
    }
    Ok(value)
}

fn base_observation(
    config: &VendorImportConfig,
    connector_type: &'static str,
    kind: ObservationKind,
    observed_at: DateTime<Utc>,
    digest: &str,
) -> Observation {
    let mut observation = Observation::new(
        config.installation_id,
        observed_at,
        ConnectorRef {
            instance_id: config.connector_instance_id,
            connector_type: connector_type.to_owned(),
            implementation_version: config.implementation_version.clone(),
            source_lineage_id: config.source_lineage_id.clone(),
        },
        kind,
        EvidenceReceipt::RecordDigest {
            algorithm: DigestAlgorithm::Sha256,
            digest: digest.to_owned(),
        },
    );
    observation.observation_id = uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        format!(
            "godel-tally:enterprise-discovery:{}:{}:{digest}",
            config.connector_instance_id,
            config
                .source_lineage_id
                .as_deref()
                .unwrap_or("connector_default")
        )
        .as_bytes(),
    );
    observation.received_at = config.received_at;
    observation
}

fn finish_import(
    mut observations: Vec<Observation>,
    connector_type: &'static str,
    config: &VendorImportConfig,
    discarded_fields: Vec<String>,
) -> Result<VendorImportOutcome, VendorImportError> {
    let records_read = u64::try_from(observations.len()).unwrap_or(u64::MAX);
    observations.sort_by_key(|observation| observation.observation_id);
    observations.dedup_by_key(|observation| observation.observation_id);
    let accepted = u64::try_from(observations.len()).unwrap_or(u64::MAX);
    if accepted == 0 {
        return Err(VendorImportError::NoRecords);
    }
    Ok(VendorImportOutcome {
        batch: ObservationBatch::build(observations, config.checkpoint.clone())?,
        stats: VendorImportStats {
            records_read,
            accepted,
            ignored: records_read.saturating_sub(accepted),
            rejected: 0,
        },
        redaction: crate::RedactionProof {
            connector_type: connector_type.to_owned(),
            pseudonymization: "hmac_sha256_installation_key_v1".to_owned(),
            discarded_fields,
            source_bytes_retained: false,
        },
    })
}

fn validate_input(input: &[u8]) -> Result<(), VendorImportError> {
    if input.is_empty() {
        return Err(VendorImportError::NoRecords);
    }
    if input.len() > crate::MAX_IMPORT_BYTES {
        return Err(VendorImportError::ImportTooLarge(input.len()));
    }
    Ok(())
}

fn validate_identifier(
    value: &str,
    row: usize,
    field: &'static str,
) -> Result<(), VendorImportError> {
    if value.is_empty() || value.len() > 2_048 || value.chars().any(char::is_control) {
        return Err(VendorImportError::InvalidField { row, field });
    }
    Ok(())
}

fn canonical_digest(value: &impl Serialize) -> Result<String, VendorImportError> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(value).map_err(|_| VendorImportError::Serialization)?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cursor, PseudonymizationKey};

    fn config() -> VendorImportConfig {
        VendorImportConfig {
            installation_id: uuid::Uuid::nil(),
            connector_instance_id: uuid::Uuid::new_v5(
                &uuid::Uuid::NAMESPACE_URL,
                b"enterprise-fixture",
            ),
            implementation_version: "1".to_owned(),
            source_lineage_id: Some("enterprise:fixture".to_owned()),
            received_at: "2026-08-13T09:00:00Z".parse().expect("time"),
            checkpoint: Cursor("fixture:1".to_owned()),
            pseudonymization_key: PseudonymizationKey::new(&[7_u8; 32]).expect("key"),
        }
    }

    #[test]
    fn cloudflare_casb_fixture_is_capability_only_and_replay_safe() {
        let input = include_bytes!("../../../testdata/connectors/cloudflare-casb/v1/input.json");
        let first =
            import_cloudflare_casb_json(input, "account-canary", &config()).expect("CASB fixture");
        let replay =
            import_cloudflare_casb_json(input, "account-canary", &config()).expect("CASB replay");
        assert_eq!(first.batch.receipt, replay.batch.receipt);
        assert_eq!(first.stats.accepted, 2);
        assert!(
            first
                .batch
                .observations
                .iter()
                .all(|observation| observation.kind == ObservationKind::SaasCapability)
        );
        let encoded = serde_json::to_string(&first).expect("serialize");
        for canary in [
            "account-canary",
            "CASB_APP_NAME_CANARY",
            "CASB_INTEGRATION_NAME_CANARY",
            "CASB_AUTH_CANARY",
            "CASB_HEALTH_CANARY",
        ] {
            assert!(!encoded.contains(canary));
        }
    }

    #[test]
    fn kubernetes_fixture_discards_unrelated_names_images_labels_and_addresses() {
        let input = include_bytes!("../../../testdata/connectors/kubernetes-api/v1/input.json");
        let outcome = import_kubernetes_api_json(input, &config()).expect("Kubernetes fixture");
        assert_eq!(outcome.stats.accepted, 4);
        assert!(outcome.batch.observations.iter().all(|observation| {
            observation.kind == ObservationKind::KubernetesResource
                && observation.workload.cluster_key.is_some()
                && observation.workload.namespace_key.is_some()
                && observation.workload.workload_key.is_some()
        }));
        assert!(outcome.batch.observations.iter().any(|observation| {
            observation.workload.runtime_registry_entry_id.as_deref() == Some("runtime.ollama")
                && observation.workload.runtime_image.as_deref()
                    == Some("docker.io/ollama/ollama:0.11.2")
        }));
        assert!(outcome.batch.observations.iter().any(|observation| {
            observation.workload.workload_kind == Some(WorkloadKind::Pod)
                && observation
                    .destination
                    .host
                    .as_ref()
                    .is_some_and(|host| host.as_str() == "ai-worker-01.internal")
        }));
        let encoded = serde_json::to_string(&outcome).expect("serialize");
        for canary in [
            "cluster-production-canary",
            "deployment-ollama-canary",
            "namespace-ai-canary",
            "10.96.14.34",
            "K8S_WORKLOAD_NAME_CANARY",
            "K8S_POD_NAME_CANARY",
            "K8S_LABEL_CANARY",
            "K8S_ANNOTATION_CANARY",
            "registry.internal.example",
        ] {
            assert!(!encoded.contains(canary));
        }
    }

    #[test]
    fn kubernetes_retains_only_bounded_runtime_remediation_locators() {
        let input = br#"{
          "schema_version":"kubernetes_api_discovery_projection_v1",
          "cluster_uid":"cluster-1",
          "observed_at":"2026-08-13T08:05:00Z",
          "resources":[{
            "uid":"pod-1",
            "namespace_uid":"namespace-1",
            "namespace_name":"tally-e2e",
            "workload_name":"unsanctioned-ollama-abc123",
            "kind":"pod",
            "images":["docker.io/ollama/ollama:latest","registry.example/metrics-sidecar:v1"],
            "hostname":"worker-01.internal"
          }]
        }"#;
        let outcome = import_kubernetes_api_json(input, &config()).expect("Kubernetes locators");
        let observation = outcome.batch.observations.first().expect("observation");
        assert_eq!(
            observation.workload.namespace_name.as_deref(),
            Some("tally-e2e")
        );
        assert_eq!(
            observation.workload.workload_name.as_deref(),
            Some("unsanctioned-ollama-abc123")
        );
        assert_eq!(
            observation.workload.runtime_image.as_deref(),
            Some("docker.io/ollama/ollama:latest")
        );
        let encoded = serde_json::to_string(&outcome).expect("serialize");
        assert!(!encoded.contains("metrics-sidecar"));
    }

    #[test]
    fn enterprise_shapes_fail_closed_on_unknown_or_ambiguous_input() {
        let casb = br#"{"result":[],"success":true,"unexpected":"content"}"#;
        assert!(import_cloudflare_casb_json(casb, "account", &config()).is_err());
        let kubernetes = br#"{
            "schema_version":"kubernetes_api_discovery_projection_v1",
            "cluster_uid":"cluster",
            "observed_at":"2026-08-13T08:05:00Z",
            "resources":[{
              "uid":"workload","namespace_uid":"namespace","kind":"deployment",
              "images":["ollama/ollama:v1","vllm/vllm-openai:v1"]
            }]
        }"#;
        assert!(import_kubernetes_api_json(kubernetes, &config()).is_err());
    }

    #[test]
    fn native_enterprise_transports_keep_distinct_replay_identities() {
        let casb = import_cloudflare_casb_api_json(
            include_bytes!("../../../testdata/connectors/cloudflare-casb/v1/input.json"),
            "0123456789abcdef0123456789abcdef",
            &config(),
        )
        .expect("native CASB projection");
        assert!(casb.batch.observations.iter().all(|observation| {
            observation.connector.connector_type == "cloudflare_casb_integrations_api_v1"
        }));
        assert_eq!(
            cloudflare_casb_api_descriptor().transport,
            ConnectorTransport::Pull
        );

        let kubernetes = import_kubernetes_api_pull_json(
            include_bytes!("../../../testdata/connectors/kubernetes-api/v1/input.json"),
            &config(),
        )
        .expect("native Kubernetes projection");
        assert!(kubernetes.batch.observations.iter().all(|observation| {
            observation.connector.connector_type == "kubernetes_api_discovery_pull_v1"
        }));
        assert_eq!(
            kubernetes_api_pull_descriptor().transport,
            ConnectorTransport::Pull
        );
    }
}
