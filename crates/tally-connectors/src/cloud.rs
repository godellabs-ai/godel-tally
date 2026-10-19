use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::IgnoredAny};
use sha2::{Digest, Sha256};
use tally_core::{
    CloudLifecycleState, CloudProvider, CloudProviderService, CloudResourceKind, CloudUsageKind,
    ConnectorRef, DigestAlgorithm, EvidenceReceipt, Hostname, IdentityAuthority,
    IdentityObservation, IdentitySubjectKind, IpAddress, Observation, ObservationKind,
};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AdmissionError, ConnectorDescriptor, ConnectorTransport, Cursor, MAX_IMPORT_BYTES,
    ObservationBatch, PseudonymizationKey, RedactionProof, ReplayCapability, VendorImportOutcome,
    VendorImportStats,
};

#[derive(Clone, PartialEq, Eq)]
pub struct ManagedCloudImportConfig {
    pub installation_id: Uuid,
    pub connector_instance_id: Uuid,
    pub implementation_version: String,
    pub source_lineage_id: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub checkpoint: Cursor,
    pub pseudonymization_key: PseudonymizationKey,
    pub scope: ManagedCloudScope,
    pub transport: ManagedCloudTransport,
}

impl fmt::Debug for ManagedCloudImportConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedCloudImportConfig")
            .field("installation_id", &self.installation_id)
            .field("connector_instance_id", &self.connector_instance_id)
            .field("implementation_version", &self.implementation_version)
            .field("source_lineage_id", &self.source_lineage_id)
            .field("observed_at", &self.observed_at)
            .field("received_at", &self.received_at)
            .field("checkpoint", &self.checkpoint)
            .field("pseudonymization_key", &"[REDACTED]")
            .field("scope", &self.scope)
            .field("transport", &self.transport)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedCloudTransport {
    File,
    NativeApi,
}

/// Optional static AWS access keys, supplied when an operator pastes long-lived IAM user
/// credentials into the connector form. `None` means the collector falls back to its default
/// credential chain (env vars, profile, then IMDS), which is the right mode when the collector
/// itself runs on an EC2 instance or ECS/EKS task with an attached instance role.
#[derive(Clone, PartialEq, Eq)]
pub struct AwsStaticCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Required for temporary STS credentials; absent for long-lived IAM access keys.
    pub session_token: Option<String>,
}

impl fmt::Debug for AwsStaticCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsStaticCredentials")
            .field("access_key_id", &"[REDACTED]")
            .field("secret_access_key", &"[REDACTED]")
            .field(
                "session_token",
                &if self.session_token.is_some() {
                    "[REDACTED]"
                } else {
                    "none"
                },
            )
            .finish()
    }
}

/// An Azure service principal supplied for one connector instance. `None` on the scope uses the
/// collector's existing workload, developer, or managed-identity credential chain.
#[derive(Clone, PartialEq, Eq)]
pub struct AzureServicePrincipalCredentials {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
}

impl fmt::Debug for AzureServicePrincipalCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureServicePrincipalCredentials")
            .field("tenant_id", &"[REDACTED]")
            .field("client_id", &"[REDACTED]")
            .field("client_secret", &"[REDACTED]")
            .finish()
    }
}

/// A Google Cloud service-account key JSON document supplied for one connector instance. `None`
/// on the scope uses application-default credentials, including an attached VM service account.
#[derive(Clone, PartialEq, Eq)]
pub struct GcpServiceAccountCredentials {
    pub json: String,
}

impl fmt::Debug for GcpServiceAccountCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpServiceAccountCredentials")
            .field("json", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ManagedCloudScope {
    Aws {
        account_id: String,
        region: String,
        /// Long-lived IAM user keys. `None` defers to the default credential chain
        /// (env → profile → IMDS), which is the recommended mode for a collector VM.
        static_credentials: Option<AwsStaticCredentials>,
    },
    Azure {
        subscription_id: String,
        account_resource_id: String,
        region: String,
        /// Optional Log Analytics workspace used to read Azure `OpenAI` request-usage diagnostics.
        /// Inventory remains available without it, but request findings require this source.
        workspace_resource: Option<String>,
        static_credentials: Option<AzureServicePrincipalCredentials>,
    },
    Gcp {
        project_id: String,
        location: String,
        static_credentials: Option<GcpServiceAccountCredentials>,
    },
}

/// Stable, redacted label for the AWS credential mode in `Debug` output: either `None` for the
/// default chain (env → profile → IMDS) or `"static-keys"` for an explicit key pair. The actual
/// values never reach the formatter.
fn static_credentials_repr(scope: &ManagedCloudScope) -> &'static str {
    if let ManagedCloudScope::Aws {
        static_credentials: Some(_),
        ..
    } = scope
    {
        "static-keys"
    } else {
        "default-chain"
    }
}

impl fmt::Debug for ManagedCloudScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aws { region, .. } => formatter
                .debug_struct("Aws")
                .field("account_id", &"[REDACTED]")
                .field("region", region)
                .field("static_credentials", &static_credentials_repr(self))
                .finish(),
            Self::Azure {
                region,
                static_credentials,
                ..
            } => formatter
                .debug_struct("Azure")
                .field("subscription_id", &"[REDACTED]")
                .field("account_resource_id", &"[REDACTED]")
                .field("region", region)
                .field(
                    "authentication",
                    &if static_credentials.is_some() {
                        "service-principal"
                    } else {
                        "collector-identity"
                    },
                )
                .finish(),
            Self::Gcp {
                location,
                static_credentials,
                ..
            } => formatter
                .debug_struct("Gcp")
                .field("project_id", &"[REDACTED]")
                .field("location", location)
                .field(
                    "authentication",
                    &if static_credentials.is_some() {
                        "service-account-key"
                    } else {
                        "collector-identity"
                    },
                )
                .finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedCloudImportStats {
    pub records_read: u64,
    pub accepted: u64,
    pub ignored: u64,
    pub rejected: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedCloudRedactionProof {
    pub controls: Vec<ManagedCloudRedactionControl>,
    pub canonical_batch_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedCloudRedactionControl {
    SourceBytesDiscarded,
    RawResourceIdentifiersDiscarded,
    CustomerLabelsDiscarded,
    CustomerTagsDiscarded,
    IdentifiersInstallationPseudonymized,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedCloudImportOutcome {
    pub batch: ObservationBatch,
    pub stats: ManagedCloudImportStats,
    pub redaction: ManagedCloudRedactionProof,
}

impl From<ManagedCloudImportOutcome> for VendorImportOutcome {
    fn from(value: ManagedCloudImportOutcome) -> Self {
        Self {
            redaction: RedactionProof {
                connector_type: value.batch.receipt.connector_type.clone(),
                pseudonymization: "hmac_sha256_installation_key_v1".to_owned(),
                discarded_fields: vec![
                    "raw resource/account/scope identifiers".to_owned(),
                    "resource names and descriptions".to_owned(),
                    "tags, labels, system data, and metadata".to_owned(),
                    "source response bytes and pagination links/tokens".to_owned(),
                ],
                source_bytes_retained: false,
            },
            stats: VendorImportStats {
                records_read: value.stats.records_read,
                accepted: value.stats.accepted,
                ignored: value.stats.ignored,
                rejected: value.stats.rejected,
            },
            batch: value.batch,
        }
    }
}

pub fn aws_managed_ai_descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor {
        connector_type: "aws_managed_ai_inventory_file_v1".to_owned(),
        display_name: "AWS managed AI inventory".to_owned(),
        implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
        source_vendor: "Amazon Web Services".to_owned(),
        source_product: "Bedrock and SageMaker".to_owned(),
        record_variants: vec![
            "bedrock_list_provisioned_model_throughputs".to_owned(),
            "bedrock_list_agents_plus_get_agent".to_owned(),
            "bedrock_get_inference_profile_for_agent_profiles".to_owned(),
            "sagemaker_list_endpoints".to_owned(),
            "sagemaker_list_models".to_owned(),
            "cloudtrail_bedrock_invocation".to_owned(),
        ],
        transport: ConnectorTransport::File,
        required_permissions: vec![
            "bedrock:ListProvisionedModelThroughputs".to_owned(),
            "bedrock:ListAgents".to_owned(),
            "bedrock:GetAgent".to_owned(),
            "bedrock:GetInferenceProfile".to_owned(),
            "sagemaker:ListEndpoints".to_owned(),
            "sagemaker:ListModels".to_owned(),
            "cloudtrail:LookupEvents".to_owned(),
        ],
        requested_fields: vec![
            "provider resource identifiers".to_owned(),
            "provider model identifiers".to_owned(),
            "bounded lifecycle states".to_owned(),
            "request ID, time, IAM principal, caller IP, model, and service endpoint".to_owned(),
        ],
        prohibited_fields: cloud_prohibited_fields(),
        cursor_semantics: "caller-supplied immutable export checkpoint".to_owned(),
        replay_capability: ReplayCapability::FileReplay,
        health_capabilities: vec!["mapping validity".to_owned(), "source freshness".to_owned()],
        coverage_capabilities: vec![
            "resource existence".to_owned(),
            "foundation models configured on Bedrock agents".to_owned(),
            "successful Bedrock invocations from CloudTrail event history".to_owned(),
            "account and region scope".to_owned(),
        ],
        privacy_contract: "Resource/account and request identifiers are installation-HMAC pseudonymized. Successful invocation time, IAM principal, caller IP, model, service host, and bounded agent display name are retained for inventory and finding attribution; prompts, responses, request bodies, access-key IDs, tokens, costs, other customer names, descriptions, tags, source bodies, and pagination URLs are discarded.".to_owned(),
    }
}

pub fn aws_managed_ai_api_descriptor() -> ConnectorDescriptor {
    native_api_descriptor(
        aws_managed_ai_descriptor(),
        "aws_managed_ai_inventory_api_v1",
        "AWS managed AI native inventory",
    )
}

pub fn azure_managed_ai_descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor {
        connector_type: "azure_managed_ai_inventory_file_v1".to_owned(),
        display_name: "Azure managed AI inventory".to_owned(),
        implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
        source_vendor: "Microsoft Azure".to_owned(),
        source_product: "Azure OpenAI and Microsoft Foundry".to_owned(),
        record_variants: vec![
            "cognitive_services_deployments_list".to_owned(),
            "azure_openai_request_usage".to_owned(),
        ],
        transport: ConnectorTransport::File,
        required_permissions: vec![
            "Microsoft.CognitiveServices/accounts/read".to_owned(),
            "Microsoft.CognitiveServices/accounts/deployments/read".to_owned(),
            "Microsoft.CognitiveServices/accounts/managedComputeDeployments/read".to_owned(),
            "Microsoft.OperationalInsights/workspaces/read".to_owned(),
            "Microsoft.OperationalInsights/workspaces/query/read".to_owned(),
        ],
        requested_fields: vec![
            "deployment resource identifiers".to_owned(),
            "provider model identifiers".to_owned(),
            "bounded provisioning state".to_owned(),
            "request ID, time, principal, caller IP, model, and service endpoint".to_owned(),
        ],
        prohibited_fields: cloud_prohibited_fields(),
        cursor_semantics: "caller-supplied immutable export checkpoint".to_owned(),
        replay_capability: ReplayCapability::FileReplay,
        health_capabilities: vec!["mapping validity".to_owned(), "source freshness".to_owned()],
        coverage_capabilities: vec![
            "deployment existence".to_owned(),
            "successful model invocations from Azure Monitor request logs".to_owned(),
            "subscription, account, and region scope".to_owned(),
        ],
        privacy_contract: "ARM and request identifiers are installation-HMAC pseudonymized. Successful invocation time, principal, caller IP, model, and service host are retained for finding attribution; prompts, responses, bodies, token counts, costs, deployment names, resource groups, tags, system data, source bodies, and next links are discarded.".to_owned(),
    }
}

pub fn azure_managed_ai_api_descriptor() -> ConnectorDescriptor {
    native_api_descriptor(
        azure_managed_ai_descriptor(),
        "azure_managed_ai_inventory_api_v1",
        "Azure managed AI native inventory",
    )
}

pub fn gcp_vertex_ai_descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor {
        connector_type: "gcp_vertex_ai_inventory_file_v1".to_owned(),
        display_name: "Google Cloud Vertex AI inventory".to_owned(),
        implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
        source_vendor: "Google Cloud".to_owned(),
        source_product: "Vertex AI".to_owned(),
        record_variants: vec![
            "vertex_endpoints_list".to_owned(),
            "vertex_models_list".to_owned(),
            "vertex_data_access_audit_invocation".to_owned(),
        ],
        transport: ConnectorTransport::File,
        required_permissions: vec![
            "aiplatform.endpoints.list".to_owned(),
            "aiplatform.models.list".to_owned(),
            "logging.logEntries.list".to_owned(),
            "logging.privateLogEntries.list".to_owned(),
        ],
        requested_fields: vec![
            "endpoint/model resource names".to_owned(),
            "deployed model references".to_owned(),
            "request ID, time, IAM principal, caller IP, model, and service endpoint".to_owned(),
        ],
        prohibited_fields: cloud_prohibited_fields(),
        cursor_semantics: "caller-supplied immutable export checkpoint".to_owned(),
        replay_capability: ReplayCapability::FileReplay,
        health_capabilities: vec!["mapping validity".to_owned(), "source freshness".to_owned()],
        coverage_capabilities: vec![
            "endpoint and model existence".to_owned(),
            "successful model invocations from Data Access audit logs".to_owned(),
            "project and location scope".to_owned(),
        ],
        privacy_contract: "Project/resource and request identifiers are installation-HMAC pseudonymized. Successful invocation time, IAM principal, caller IP, model, and service host are retained for finding attribution; prompts, responses, request bodies, labels, metadata, tokens, costs, source bodies, and page tokens are discarded.".to_owned(),
    }
}

pub fn gcp_vertex_ai_api_descriptor() -> ConnectorDescriptor {
    native_api_descriptor(
        gcp_vertex_ai_descriptor(),
        "gcp_vertex_ai_inventory_api_v1",
        "Google Cloud Vertex AI native inventory",
    )
}

fn native_api_descriptor(
    mut descriptor: ConnectorDescriptor,
    connector_type: &str,
    display_name: &str,
) -> ConnectorDescriptor {
    connector_type.clone_into(&mut descriptor.connector_type);
    display_name.clone_into(&mut descriptor.display_name);
    descriptor.transport = ConnectorTransport::Pull;
    "content digest and provider observation time for each bounded poll"
        .clone_into(&mut descriptor.cursor_semantics);
    descriptor.replay_capability = ReplayCapability::DurableCursor;
    descriptor
}

fn cloud_prohibited_fields() -> Vec<String> {
    [
        "credentials",
        "prompts",
        "request or response bodies",
        "resource display names other than explicitly retained agent names",
        "descriptions",
        "tags or labels",
        "prompt and response content",
        "tokens and cost",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// Imports a strict bundle of recorded Bedrock and `SageMaker` list responses.
///
/// # Errors
///
/// Returns [`ManagedCloudImportError`] for an unsafe scope, oversized/malformed fixture, provider
/// shape drift, or invalid resource identity. Source values are never included in errors.
#[allow(clippy::too_many_lines)]
pub fn import_aws_managed_ai_json(
    input: &[u8],
    config: &ManagedCloudImportConfig,
) -> Result<ManagedCloudImportOutcome, ManagedCloudImportError> {
    let (account_id, region) = aws_scope(config)?;
    let fixture: AwsManagedAiFixture = parse_fixture(input)?;
    let scope_identifier = format!("{account_id}:{region}");
    let mut resources = Vec::new();
    let usages = fixture
        .invocations
        .into_iter()
        .map(|invocation| CloudUsageInput {
            provider: CloudProvider::Aws,
            provider_service: invocation
                .service
                .as_deref()
                .and_then(aws_invocation_service),
            account_identifier: account_id.to_owned(),
            scope_identifier: scope_identifier.clone(),
            region: region.to_owned(),
            invocation,
        })
        .collect::<Vec<_>>();

    for summary in fixture
        .provisioned_model_throughputs
        .provisioned_model_summaries
    {
        validate_resource_identifier(&summary.provisioned_model_arn)?;
        let public_model = summary
            .foundation_model_arn
            .as_deref()
            .and_then(public_model_from_aws_arn)
            .map(str::to_owned);
        resources.push(CloudResourceInput {
            observation_kind: ObservationKind::CloudResource,
            provider: CloudProvider::Aws,
            provider_service: CloudProviderService::AwsBedrock,
            account_identifier: account_id.to_owned(),
            scope_identifier: scope_identifier.clone(),
            region: region.to_owned(),
            resource_identifier: summary.provisioned_model_arn,
            resource_kind: CloudResourceKind::ModelDeployment,
            public_model_id: public_model,
            display_name: None,
            lifecycle: aws_resource_lifecycle(&summary.status),
            action: "resource_enumerated",
        });
    }
    for summary in fixture.agents.agent_summaries {
        validate_resource_identifier(&summary.agent_id)?;
        let identity = format!("{account_id}:{region}:bedrock-agent:{}", summary.agent_id);
        resources.push(CloudResourceInput {
            observation_kind: ObservationKind::CloudResource,
            provider: CloudProvider::Aws,
            provider_service: CloudProviderService::AwsBedrock,
            account_identifier: account_id.to_owned(),
            scope_identifier: scope_identifier.clone(),
            region: region.to_owned(),
            resource_identifier: identity,
            resource_kind: CloudResourceKind::Agent,
            public_model_id: summary
                .foundation_model
                .as_deref()
                .and_then(public_model_from_aws_reference)
                .map(str::to_owned),
            display_name: summary
                .agent_name
                .as_ref()
                .and_then(serde_json::Value::as_str)
                .filter(|name| {
                    !name.is_empty() && name.len() <= 256 && !name.chars().any(char::is_control)
                })
                .map(str::to_owned),
            lifecycle: aws_resource_lifecycle(&summary.agent_status),
            action: "resource_enumerated",
        });
    }
    for summary in fixture.sagemaker_endpoints.endpoints {
        validate_resource_identifier(&summary.endpoint_arn)?;
        resources.push(CloudResourceInput {
            observation_kind: ObservationKind::CloudResource,
            provider: CloudProvider::Aws,
            provider_service: CloudProviderService::AwsSagemaker,
            account_identifier: account_id.to_owned(),
            scope_identifier: scope_identifier.clone(),
            region: region.to_owned(),
            resource_identifier: summary.endpoint_arn,
            resource_kind: CloudResourceKind::InferenceEndpoint,
            public_model_id: None,
            display_name: None,
            lifecycle: aws_resource_lifecycle(&summary.endpoint_status),
            action: "resource_enumerated",
        });
    }
    for summary in fixture.sagemaker_models.models {
        validate_resource_identifier(&summary.model_arn)?;
        resources.push(CloudResourceInput {
            observation_kind: ObservationKind::CloudResource,
            provider: CloudProvider::Aws,
            provider_service: CloudProviderService::AwsSagemaker,
            account_identifier: account_id.to_owned(),
            scope_identifier: scope_identifier.clone(),
            region: region.to_owned(),
            resource_identifier: summary.model_arn,
            resource_kind: CloudResourceKind::ModelArtifact,
            public_model_id: None,
            display_name: None,
            lifecycle: CloudLifecycleState::Active,
            action: "resource_enumerated",
        });
    }
    finish_import(resources, usages, config)
}

/// Imports a strict recorded Azure Cognitive Services deployment list response.
///
/// # Errors
///
/// Returns [`ManagedCloudImportError`] for unsafe scope, provider shape drift, or a deployment
/// outside the configured account scope.
pub fn import_azure_managed_ai_json(
    input: &[u8],
    service: CloudProviderService,
    config: &ManagedCloudImportConfig,
) -> Result<ManagedCloudImportOutcome, ManagedCloudImportError> {
    if !matches!(
        service,
        CloudProviderService::AzureOpenai | CloudProviderService::AzureAiFoundry
    ) {
        return Err(ManagedCloudImportError::ServiceMismatch);
    }
    let ManagedCloudScope::Azure {
        subscription_id,
        account_resource_id,
        region,
        ..
    } = &config.scope
    else {
        return Err(ManagedCloudImportError::ScopeMismatch);
    };
    validate_scope(subscription_id, region)?;
    validate_resource_identifier(account_resource_id)?;
    let fixture: AzureDeploymentsFixture = parse_fixture(input)?;
    let expected_prefix = format!("{}/deployments/", account_resource_id.trim_end_matches('/'));
    let mut resources = Vec::new();
    let usages = fixture
        .invocations
        .into_iter()
        .map(|invocation| CloudUsageInput {
            provider: CloudProvider::Azure,
            provider_service: Some(service),
            account_identifier: subscription_id.to_owned(),
            scope_identifier: account_resource_id.to_owned(),
            region: region.to_owned(),
            invocation,
        })
        .collect::<Vec<_>>();
    for deployment in fixture.value {
        validate_resource_identifier(&deployment.id)?;
        if !deployment
            .id
            .to_ascii_lowercase()
            .starts_with(&expected_prefix.to_ascii_lowercase())
        {
            return Err(ManagedCloudImportError::ResourceOutsideScope);
        }
        let public_model = deployment
            .properties
            .model
            .as_ref()
            .and_then(|model| safe_public_model(&model.name))
            .map(str::to_owned);
        resources.push(CloudResourceInput {
            observation_kind: ObservationKind::CloudResource,
            provider: CloudProvider::Azure,
            provider_service: service,
            account_identifier: subscription_id.to_owned(),
            scope_identifier: account_resource_id.to_owned(),
            region: region.to_owned(),
            resource_identifier: deployment.id,
            resource_kind: CloudResourceKind::ModelDeployment,
            public_model_id: public_model,
            display_name: None,
            lifecycle: azure_lifecycle(&deployment.properties.provisioning_state),
            action: "resource_enumerated",
        });
    }
    finish_import(resources, usages, config)
}

/// Imports strict recorded Vertex AI endpoint and model list responses.
///
/// # Errors
///
/// Returns [`ManagedCloudImportError`] for unsafe scope, provider shape drift, or a resource outside
/// the configured project/location.
pub fn import_gcp_vertex_ai_json(
    input: &[u8],
    config: &ManagedCloudImportConfig,
) -> Result<ManagedCloudImportOutcome, ManagedCloudImportError> {
    let ManagedCloudScope::Gcp {
        project_id,
        location,
        ..
    } = &config.scope
    else {
        return Err(ManagedCloudImportError::ScopeMismatch);
    };
    validate_scope(project_id, location)?;
    let fixture: GcpVertexFixture = parse_fixture(input)?;
    let expected_prefix = format!("projects/{project_id}/locations/{location}/");
    let scope_identifier = format!("projects/{project_id}");
    let mut resources = Vec::new();
    let usages = fixture
        .invocations
        .into_iter()
        .map(|invocation| CloudUsageInput {
            provider: CloudProvider::Gcp,
            provider_service: Some(CloudProviderService::GcpVertexAi),
            account_identifier: project_id.to_owned(),
            scope_identifier: scope_identifier.clone(),
            region: location.to_owned(),
            invocation,
        })
        .collect::<Vec<_>>();
    for endpoint in fixture.endpoints.endpoints {
        validate_gcp_resource(&endpoint.name, &expected_prefix)?;
        let endpoint_name = endpoint.name;
        resources.push(CloudResourceInput {
            observation_kind: ObservationKind::CloudResource,
            provider: CloudProvider::Gcp,
            provider_service: CloudProviderService::GcpVertexAi,
            account_identifier: project_id.to_owned(),
            scope_identifier: scope_identifier.clone(),
            region: location.to_owned(),
            resource_identifier: endpoint_name.clone(),
            resource_kind: CloudResourceKind::InferenceEndpoint,
            public_model_id: None,
            display_name: None,
            lifecycle: CloudLifecycleState::Active,
            action: "resource_enumerated",
        });
        for deployed in endpoint.deployed_models {
            validate_resource_identifier(&deployed.id)?;
            let identity = format!("{endpoint_name}:deployed-model:{}", deployed.id);
            resources.push(CloudResourceInput {
                observation_kind: ObservationKind::CloudResource,
                provider: CloudProvider::Gcp,
                provider_service: CloudProviderService::GcpVertexAi,
                account_identifier: project_id.to_owned(),
                scope_identifier: scope_identifier.clone(),
                region: location.to_owned(),
                resource_identifier: identity,
                resource_kind: CloudResourceKind::ModelDeployment,
                public_model_id: deployed
                    .model
                    .as_deref()
                    .and_then(public_gcp_model)
                    .map(str::to_owned),
                display_name: None,
                lifecycle: CloudLifecycleState::Active,
                action: "resource_enumerated",
            });
        }
    }
    for model in fixture.models.models {
        validate_gcp_resource(&model.name, &expected_prefix)?;
        resources.push(CloudResourceInput {
            observation_kind: ObservationKind::CloudResource,
            provider: CloudProvider::Gcp,
            provider_service: CloudProviderService::GcpVertexAi,
            account_identifier: project_id.to_owned(),
            scope_identifier: scope_identifier.clone(),
            region: location.to_owned(),
            resource_identifier: model.name,
            resource_kind: CloudResourceKind::ModelArtifact,
            public_model_id: None,
            display_name: None,
            lifecycle: CloudLifecycleState::Active,
            action: "resource_enumerated",
        });
    }
    finish_import(resources, usages, config)
}

struct CloudUsageInput {
    provider: CloudProvider,
    provider_service: Option<CloudProviderService>,
    account_identifier: String,
    scope_identifier: String,
    region: String,
    invocation: ManagedAiInvocation,
}

#[derive(Serialize)]
struct CanonicalCloudUsage<'a> {
    provider: CloudProvider,
    provider_service: CloudProviderService,
    account_key: &'a str,
    scope_key: &'a str,
    region: &'a str,
    request_key: &'a str,
    model_id: Option<&'a str>,
    actor: Option<&'a str>,
    source_ip: Option<&'a str>,
    destination_host: &'a str,
    observed_at: DateTime<Utc>,
    action: &'static str,
    result: &'a str,
}

struct CloudResourceInput {
    observation_kind: ObservationKind,
    provider: CloudProvider,
    provider_service: CloudProviderService,
    account_identifier: String,
    scope_identifier: String,
    region: String,
    resource_identifier: String,
    resource_kind: CloudResourceKind,
    public_model_id: Option<String>,
    display_name: Option<String>,
    lifecycle: CloudLifecycleState,
    action: &'static str,
}

#[derive(Serialize)]
struct CanonicalCloudResource<'a> {
    provider: CloudProvider,
    provider_service: CloudProviderService,
    account_key: &'a str,
    scope_key: &'a str,
    region: &'a str,
    resource_key: &'a str,
    resource_kind: CloudResourceKind,
    public_model_id: Option<&'a str>,
    display_name: Option<&'a str>,
    lifecycle: CloudLifecycleState,
    action: &'a str,
    observed_at: DateTime<Utc>,
}

fn normalize_resource(
    resource: CloudResourceInput,
    config: &ManagedCloudImportConfig,
) -> Result<Observation, ManagedCloudImportError> {
    validate_resource_identifier(&resource.resource_identifier)?;
    let account_key = config
        .pseudonymization_key
        .pseudonym_exact("cloud_account", &resource.account_identifier);
    let scope_key = config
        .pseudonymization_key
        .pseudonym_exact("cloud_scope", &resource.scope_identifier);
    let resource_key = config
        .pseudonymization_key
        .pseudonym_exact("cloud_resource", &resource.resource_identifier);
    let canonical = CanonicalCloudResource {
        provider: resource.provider,
        provider_service: resource.provider_service,
        account_key: &account_key,
        scope_key: &scope_key,
        region: &resource.region,
        resource_key: &resource_key,
        resource_kind: resource.resource_kind,
        public_model_id: resource.public_model_id.as_deref(),
        display_name: resource.display_name.as_deref(),
        lifecycle: resource.lifecycle,
        action: resource.action,
        observed_at: config.observed_at,
    };
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&canonical).map_err(|_| ManagedCloudImportError::Serialization)?,
    ));
    let mut observation = Observation::new(
        config.installation_id,
        config.observed_at,
        ConnectorRef {
            instance_id: config.connector_instance_id,
            connector_type: connector_type(resource.provider, config.transport).to_owned(),
            implementation_version: config.implementation_version.clone(),
            source_lineage_id: config.source_lineage_id.clone(),
        },
        resource.observation_kind,
        EvidenceReceipt::RecordDigest {
            algorithm: DigestAlgorithm::Sha256,
            digest: digest.clone(),
        },
    );
    let source_lineage = config
        .source_lineage_id
        .as_deref()
        .unwrap_or("connector_default");
    observation.observation_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!(
            "godel-tally:cloud:{}:{source_lineage}:{digest}",
            config.connector_instance_id,
        )
        .as_bytes(),
    );
    observation.received_at = config.received_at;
    observation.cloud.provider = Some(resource.provider);
    observation.cloud.account_key = Some(account_key);
    observation.cloud.scope_key = Some(scope_key.clone());
    observation.cloud.region = Some(resource.region);
    observation.cloud.resource_kind = Some(resource.resource_kind);
    if resource.resource_kind == CloudResourceKind::Agent {
        observation.agent.key = Some(resource_key.clone());
        observation.agent.name = resource
            .display_name
            .or_else(|| Some("Managed cloud agent".into()));
        observation.agent.kind = Some("agent".into());
        observation.agent.platform = Some(format!("{:?}", resource.provider_service));
        observation.agent.state = Some(format!("{:?}", resource.lifecycle).to_lowercase());
        observation.agent.attribution_confidence = Some("unattributed".into());
        observation.agent.attribution_basis = Some(
            "Cloud control-plane inventory; execution and human ownership are not implied".into(),
        );
    }
    observation.cloud.resource_key = Some(resource_key);
    observation.cloud.provider_service = Some(resource.provider_service);
    observation.cloud.lifecycle_state = Some(resource.lifecycle);
    observation.service.source_category = Some("cloud_inventory".to_owned());
    observation.service.declared_model_id = resource.public_model_id;
    observation.outcome.action = Some(resource.action.to_owned());
    Ok(observation)
}

#[allow(clippy::too_many_lines)] // Keeps one canonical request-evidence boundary auditable.
fn normalize_usage(
    usage: CloudUsageInput,
    config: &ManagedCloudImportConfig,
) -> Result<Observation, ManagedCloudImportError> {
    let ManagedAiInvocation {
        request_id,
        service: _,
        model_id,
        principal_email,
        principal,
        source_ip,
        destination_host,
        observed_at,
        result,
    } = usage.invocation;
    validate_resource_identifier(&request_id)?;
    let provider_service = usage
        .provider_service
        .ok_or(ManagedCloudImportError::ServiceMismatch)?;
    let model_id = model_id
        .as_deref()
        .map(validate_public_model)
        .transpose()?
        .map(str::to_owned);
    let principal_email = principal_email
        .as_deref()
        .map(validate_cloud_email)
        .transpose()?
        .map(str::to_owned);
    let principal = principal
        .as_deref()
        .map(validate_cloud_subject)
        .transpose()?
        .map(str::to_owned);
    let source_ip = source_ip
        .as_deref()
        .map(IpAddress::parse)
        .transpose()
        .map_err(|_| ManagedCloudImportError::InvalidUsageAttribution)?;
    let destination_host = Hostname::parse(&destination_host)
        .map_err(|_| ManagedCloudImportError::InvalidUsageAttribution)?;
    let account_key = config
        .pseudonymization_key
        .pseudonym_exact("cloud_account", &usage.account_identifier);
    let scope_key = config
        .pseudonymization_key
        .pseudonym_exact("cloud_scope", &usage.scope_identifier);
    let request_key = config
        .pseudonymization_key
        .pseudonym_exact("cloud_invocation", &request_id);
    let result = result.as_deref().unwrap_or("success");
    if !matches!(result, "success" | "failure") {
        return Err(ManagedCloudImportError::InvalidUsageAttribution);
    }
    let action = if result == "success" {
        "model_invoked"
    } else {
        "model_invocation_attempted"
    };
    let actor = principal_email.as_deref().or(principal.as_deref());
    let canonical = CanonicalCloudUsage {
        provider: usage.provider,
        provider_service,
        account_key: &account_key,
        scope_key: &scope_key,
        region: &usage.region,
        request_key: &request_key,
        model_id: model_id.as_deref(),
        actor,
        source_ip: source_ip.as_ref().map(IpAddress::as_str),
        destination_host: destination_host.as_str(),
        observed_at,
        action,
        result,
    };
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&canonical).map_err(|_| ManagedCloudImportError::Serialization)?,
    ));
    let mut observation = Observation::new(
        config.installation_id,
        observed_at,
        ConnectorRef {
            instance_id: config.connector_instance_id,
            connector_type: connector_type(usage.provider, config.transport).to_owned(),
            implementation_version: config.implementation_version.clone(),
            source_lineage_id: config.source_lineage_id.clone(),
        },
        ObservationKind::CloudUsage,
        EvidenceReceipt::RecordDigest {
            algorithm: DigestAlgorithm::Sha256,
            digest: digest.clone(),
        },
    );
    let source_lineage = config
        .source_lineage_id
        .as_deref()
        .unwrap_or("connector_default");
    observation.observation_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!(
            "godel-tally:cloud-usage:{}:{source_lineage}:{request_key}",
            config.connector_instance_id
        )
        .as_bytes(),
    );
    observation.received_at = config.received_at;
    observation.cloud.provider = Some(usage.provider);
    observation.cloud.provider_service = Some(provider_service);
    observation.cloud.account_key = Some(account_key);
    observation.cloud.scope_key = Some(scope_key.clone());
    observation.cloud.region = Some(usage.region);
    observation.cloud.usage_kind = Some(CloudUsageKind::Invocation);
    observation.service.source_category = Some("cloud_ai_invocation".to_owned());
    observation.service.declared_model_id = model_id;
    observation.service.ai_request = true;
    observation.service.ai_request_evaluated = true;
    observation.actor.source_ip = source_ip;
    if let Some(subject) = actor {
        observation.actor.identity = Some(IdentityObservation {
            subject_key: config
                .pseudonymization_key
                .pseudonym_exact("identity", subject),
            email: principal_email,
            source_subject: principal,
            source_subject_kind: Some(IdentitySubjectKind::SourceUserId),
            authority: Some(IdentityAuthority::CloudIam),
            directory_key: None,
            application_key: Some(scope_key),
            display_label: None,
        });
    }
    observation.destination.host = Some(destination_host);
    observation.destination.port = Some(443);
    observation.network.request_count = Some(1);
    observation.outcome.action = Some(action.to_owned());
    observation.outcome.result = Some(result.to_owned());
    Ok(observation)
}

fn finish_import(
    resources: Vec<CloudResourceInput>,
    usages: Vec<CloudUsageInput>,
    config: &ManagedCloudImportConfig,
) -> Result<ManagedCloudImportOutcome, ManagedCloudImportError> {
    let records_read = resources.len().saturating_add(usages.len()) as u64;
    let mut observations = resources
        .into_iter()
        .map(|resource| normalize_resource(resource, config))
        .collect::<Result<Vec<_>, _>>()?;
    observations.extend(
        usages
            .into_iter()
            .map(|usage| normalize_usage(usage, config))
            .collect::<Result<Vec<_>, _>>()?,
    );
    observations.sort_by_key(|observation| observation.observation_id);
    observations.dedup_by_key(|observation| observation.observation_id);
    let accepted = observations.len() as u64;
    let batch = ObservationBatch::build(observations, config.checkpoint.clone())?;
    Ok(ManagedCloudImportOutcome {
        redaction: ManagedCloudRedactionProof {
            controls: vec![
                ManagedCloudRedactionControl::SourceBytesDiscarded,
                ManagedCloudRedactionControl::RawResourceIdentifiersDiscarded,
                ManagedCloudRedactionControl::CustomerLabelsDiscarded,
                ManagedCloudRedactionControl::CustomerTagsDiscarded,
                ManagedCloudRedactionControl::IdentifiersInstallationPseudonymized,
            ],
            canonical_batch_digest: batch.receipt.canonical_digest.clone(),
        },
        batch,
        stats: ManagedCloudImportStats {
            records_read,
            accepted,
            ignored: records_read.saturating_sub(accepted),
            rejected: 0,
        },
    })
}

fn aws_scope(config: &ManagedCloudImportConfig) -> Result<(&str, &str), ManagedCloudImportError> {
    let ManagedCloudScope::Aws {
        account_id, region, ..
    } = &config.scope
    else {
        return Err(ManagedCloudImportError::ScopeMismatch);
    };
    validate_scope(account_id, region)?;
    Ok((account_id, region))
}

fn parse_fixture<T: for<'de> Deserialize<'de>>(input: &[u8]) -> Result<T, ManagedCloudImportError> {
    if input.len() > MAX_IMPORT_BYTES {
        return Err(ManagedCloudImportError::ImportTooLarge(input.len()));
    }
    serde_json::from_slice(input).map_err(|_| ManagedCloudImportError::MalformedFixture)
}

fn validate_scope(identifier: &str, region: &str) -> Result<(), ManagedCloudImportError> {
    validate_resource_identifier(identifier)?;
    if region.is_empty()
        || region.len() > 63
        || !region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(ManagedCloudImportError::InvalidRegion);
    }
    Ok(())
}

fn validate_resource_identifier(value: &str) -> Result<(), ManagedCloudImportError> {
    if value.is_empty() || value.len() > 2_048 || value.chars().any(char::is_control) {
        return Err(ManagedCloudImportError::InvalidResourceIdentifier);
    }
    Ok(())
}

fn validate_public_model(value: &str) -> Result<&str, ManagedCloudImportError> {
    safe_public_model(value).ok_or(ManagedCloudImportError::InvalidUsageAttribution)
}

fn validate_cloud_subject(value: &str) -> Result<&str, ManagedCloudImportError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(ManagedCloudImportError::InvalidUsageAttribution);
    }
    Ok(value)
}

fn validate_cloud_email(value: &str) -> Result<&str, ManagedCloudImportError> {
    let value = validate_cloud_subject(value)?;
    let mut parts = value.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if local.is_empty()
        || domain.is_empty()
        || parts.next().is_some()
        || value.len() > 254
        || domain.starts_with('.')
        || domain.ends_with('.')
        || !value.is_ascii()
        || value.chars().any(char::is_whitespace)
    {
        return Err(ManagedCloudImportError::InvalidUsageAttribution);
    }
    Ok(value)
}

fn aws_invocation_service(value: &str) -> Option<CloudProviderService> {
    match value {
        "bedrock" => Some(CloudProviderService::AwsBedrock),
        "sagemaker" => Some(CloudProviderService::AwsSagemaker),
        _ => None,
    }
}

fn validate_gcp_resource(
    value: &str,
    expected_prefix: &str,
) -> Result<(), ManagedCloudImportError> {
    validate_resource_identifier(value)?;
    if !value.starts_with(expected_prefix) {
        return Err(ManagedCloudImportError::ResourceOutsideScope);
    }
    Ok(())
}

fn safe_public_model(value: &str) -> Option<&str> {
    (!value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        }))
    .then_some(value)
}

fn public_model_from_aws_arn(value: &str) -> Option<&str> {
    value
        .split_once(":foundation-model/")
        .and_then(|(_, model)| safe_public_model(model))
}

fn public_model_from_aws_reference(value: &str) -> Option<&str> {
    if value.starts_with("arn:") {
        public_model_from_aws_arn(value)
    } else {
        safe_public_model(value)
    }
}

fn public_gcp_model(value: &str) -> Option<&str> {
    let (_, publisher_and_model) = value.split_once("publishers/")?;
    let (publisher, model) = publisher_and_model.split_once("/models/")?;
    if safe_public_model(publisher).is_some() && safe_public_model(model).is_some() {
        Some(publisher_and_model)
    } else {
        None
    }
}

const fn connector_type(provider: CloudProvider, transport: ManagedCloudTransport) -> &'static str {
    match (provider, transport) {
        (CloudProvider::Aws, ManagedCloudTransport::File) => "aws_managed_ai_inventory_file_v1",
        (CloudProvider::Azure, ManagedCloudTransport::File) => "azure_managed_ai_inventory_file_v1",
        (CloudProvider::Gcp, ManagedCloudTransport::File) => "gcp_vertex_ai_inventory_file_v1",
        (CloudProvider::Aws, ManagedCloudTransport::NativeApi) => "aws_managed_ai_inventory_api_v1",
        (CloudProvider::Azure, ManagedCloudTransport::NativeApi) => {
            "azure_managed_ai_inventory_api_v1"
        }
        (CloudProvider::Gcp, ManagedCloudTransport::NativeApi) => "gcp_vertex_ai_inventory_api_v1",
    }
}

fn aws_resource_lifecycle(value: &str) -> CloudLifecycleState {
    match value {
        "InService" | "PREPARED" => CloudLifecycleState::Active,
        "Creating" | "CREATING" | "PREPARING" | "NOT_PREPARED" => CloudLifecycleState::Provisioning,
        "Updating" | "UPDATING" | "VERSIONING" | "SYSTEM_UPDATING" | "ROLLING_BACK" => {
            CloudLifecycleState::Updating
        }
        "Failed" | "FAILED" | "UPDATE_FAILED" => CloudLifecycleState::Failed,
        "Deleting" | "DELETING" | "OUT_OF_SERVICE" => CloudLifecycleState::Deleting,
        _ => CloudLifecycleState::Unknown,
    }
}

fn azure_lifecycle(value: &str) -> CloudLifecycleState {
    match value.to_ascii_lowercase().as_str() {
        "succeeded" => CloudLifecycleState::Active,
        "creating" | "accepted" => CloudLifecycleState::Provisioning,
        "updating" => CloudLifecycleState::Updating,
        "failed" | "canceled" => CloudLifecycleState::Failed,
        "deleting" => CloudLifecycleState::Deleting,
        "deleted" => CloudLifecycleState::Deleted,
        _ => CloudLifecycleState::Unknown,
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AwsManagedAiFixture {
    // Older file snapshots may contain the provider-wide Bedrock catalog. It is accepted only
    // for wire compatibility and deliberately ignored: availability is not deployment or usage.
    #[serde(default)]
    _foundation_models: Option<IgnoredAny>,
    provisioned_model_throughputs: AwsProvisionedModelsResponse,
    agents: AwsAgentsResponse,
    sagemaker_endpoints: AwsEndpointsResponse,
    sagemaker_models: AwsModelsResponse,
    #[serde(default)]
    invocations: Vec<ManagedAiInvocation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AwsProvisionedModelsResponse {
    #[serde(default)]
    provisioned_model_summaries: Vec<AwsProvisionedModelSummary>,
    #[serde(default, rename = "nextToken")]
    _next_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AwsProvisionedModelSummary {
    provisioned_model_arn: String,
    #[serde(default)]
    foundation_model_arn: Option<String>,
    status: String,
    #[serde(default, rename = "provisionedModelName")]
    _provisioned_model_name: Option<serde_json::Value>,
    #[serde(default, rename = "modelArn")]
    _model_arn: Option<serde_json::Value>,
    #[serde(default, rename = "desiredModelArn")]
    _desired_model_arn: Option<serde_json::Value>,
    #[serde(default, rename = "modelUnits")]
    _model_units: Option<serde_json::Value>,
    #[serde(default, rename = "desiredModelUnits")]
    _desired_model_units: Option<serde_json::Value>,
    #[serde(default, rename = "commitmentDuration")]
    _commitment_duration: Option<serde_json::Value>,
    #[serde(default, rename = "commitmentExpirationTime")]
    _commitment_expiration_time: Option<serde_json::Value>,
    #[serde(default, rename = "creationTime")]
    _creation_time: Option<serde_json::Value>,
    #[serde(default, rename = "lastModifiedTime")]
    _last_modified_time: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AwsAgentsResponse {
    #[serde(default)]
    agent_summaries: Vec<AwsAgentSummary>,
    #[serde(default, rename = "nextToken")]
    _next_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AwsAgentSummary {
    agent_id: String,
    agent_status: String,
    #[serde(default)]
    foundation_model: Option<String>,
    #[serde(default, rename = "agentName")]
    agent_name: Option<serde_json::Value>,
    #[serde(default, rename = "description")]
    _description: Option<serde_json::Value>,
    #[serde(default, rename = "guardrailConfiguration")]
    _guardrail_configuration: Option<serde_json::Value>,
    #[serde(default, rename = "latestAgentVersion")]
    _latest_agent_version: Option<serde_json::Value>,
    #[serde(default, rename = "updatedAt")]
    _updated_at: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
struct AwsEndpointsResponse {
    #[serde(default)]
    endpoints: Vec<AwsEndpointSummary>,
    #[serde(default, rename = "NextToken")]
    _next_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
struct AwsEndpointSummary {
    endpoint_arn: String,
    endpoint_status: String,
    #[serde(default, rename = "EndpointName")]
    _endpoint_name: Option<serde_json::Value>,
    #[serde(default, rename = "CreationTime")]
    _creation_time: Option<serde_json::Value>,
    #[serde(default, rename = "LastModifiedTime")]
    _last_modified_time: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
struct AwsModelsResponse {
    #[serde(default)]
    models: Vec<AwsSagemakerModelSummary>,
    #[serde(default, rename = "NextToken")]
    _next_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
struct AwsSagemakerModelSummary {
    model_arn: String,
    #[serde(default, rename = "ModelName")]
    _model_name: Option<serde_json::Value>,
    #[serde(default, rename = "CreationTime")]
    _creation_time: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AzureDeploymentsFixture {
    value: Vec<AzureDeployment>,
    #[serde(default)]
    invocations: Vec<ManagedAiInvocation>,
    #[serde(default, rename = "nextLink")]
    _next_link: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AzureDeployment {
    id: String,
    properties: AzureDeploymentProperties,
    #[serde(default, rename = "name")]
    _name: Option<serde_json::Value>,
    #[serde(default, rename = "type")]
    _resource_type: Option<serde_json::Value>,
    #[serde(default, rename = "etag")]
    _etag: Option<serde_json::Value>,
    #[serde(default, rename = "sku")]
    _sku: Option<serde_json::Value>,
    #[serde(default, rename = "tags")]
    _tags: Option<serde_json::Value>,
    #[serde(default, rename = "systemData")]
    _system_data: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AzureDeploymentProperties {
    provisioning_state: String,
    #[serde(default)]
    model: Option<AzureDeploymentModel>,
    #[serde(default, rename = "raiPolicyName")]
    _rai_policy_name: Option<serde_json::Value>,
    #[serde(default, rename = "versionUpgradeOption")]
    _version_upgrade_option: Option<serde_json::Value>,
    #[serde(default, rename = "currentCapacity")]
    _current_capacity: Option<serde_json::Value>,
    #[serde(default, rename = "capabilities")]
    _capabilities: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AzureDeploymentModel {
    name: String,
    #[serde(default, rename = "format")]
    _format: Option<serde_json::Value>,
    #[serde(default, rename = "version")]
    _version: Option<serde_json::Value>,
    #[serde(default, rename = "source")]
    _source: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GcpVertexFixture {
    endpoints: GcpEndpointsResponse,
    models: GcpModelsResponse,
    #[serde(default)]
    invocations: Vec<ManagedAiInvocation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ManagedAiInvocation {
    request_id: String,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    model_id: Option<String>,
    #[serde(default)]
    principal_email: Option<String>,
    #[serde(default)]
    principal: Option<String>,
    #[serde(default)]
    source_ip: Option<String>,
    destination_host: String,
    observed_at: DateTime<Utc>,
    #[serde(default)]
    result: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GcpEndpointsResponse {
    #[serde(default)]
    endpoints: Vec<GcpEndpoint>,
    #[serde(default, rename = "nextPageToken")]
    _next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GcpEndpoint {
    name: String,
    #[serde(default)]
    deployed_models: Vec<GcpDeployedModel>,
    #[serde(default, rename = "displayName")]
    _display_name: Option<serde_json::Value>,
    #[serde(default, rename = "description")]
    _description: Option<serde_json::Value>,
    #[serde(default, rename = "labels")]
    _labels: Option<serde_json::Value>,
    #[serde(default, rename = "createTime")]
    _create_time: Option<serde_json::Value>,
    #[serde(default, rename = "updateTime")]
    _update_time: Option<serde_json::Value>,
    #[serde(default, rename = "etag")]
    _etag: Option<serde_json::Value>,
    #[serde(default, rename = "network")]
    _network: Option<serde_json::Value>,
    #[serde(default, rename = "trafficSplit")]
    _traffic_split: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GcpDeployedModel {
    id: String,
    #[serde(default)]
    model: Option<String>,
    #[serde(default, rename = "displayName")]
    _display_name: Option<serde_json::Value>,
    #[serde(default, rename = "createTime")]
    _create_time: Option<serde_json::Value>,
    #[serde(default, rename = "dedicatedResources")]
    _dedicated_resources: Option<serde_json::Value>,
    #[serde(default, rename = "automaticResources")]
    _automatic_resources: Option<serde_json::Value>,
    #[serde(default, rename = "serviceAccount")]
    _service_account: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GcpModelsResponse {
    #[serde(default)]
    models: Vec<GcpModel>,
    #[serde(default, rename = "nextPageToken")]
    _next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GcpModel {
    name: String,
    #[serde(default, rename = "displayName")]
    _display_name: Option<serde_json::Value>,
    #[serde(default, rename = "description")]
    _description: Option<serde_json::Value>,
    #[serde(default, rename = "versionId")]
    _version_id: Option<serde_json::Value>,
    #[serde(default, rename = "versionAliases")]
    _version_aliases: Option<serde_json::Value>,
    #[serde(default, rename = "labels")]
    _labels: Option<serde_json::Value>,
    #[serde(default, rename = "createTime")]
    _create_time: Option<serde_json::Value>,
    #[serde(default, rename = "updateTime")]
    _update_time: Option<serde_json::Value>,
    #[serde(default, rename = "metadata")]
    _metadata: Option<serde_json::Value>,
    #[serde(default, rename = "artifactUri")]
    _artifact_uri: Option<serde_json::Value>,
    #[serde(default, rename = "containerSpec")]
    _container_spec: Option<serde_json::Value>,
    #[serde(default, rename = "etag")]
    _etag: Option<serde_json::Value>,
}

#[derive(Debug, Error)]
pub enum ManagedCloudImportError {
    #[error("managed-cloud import is {0} bytes; maximum is {MAX_IMPORT_BYTES}")]
    ImportTooLarge(usize),
    #[error("managed-cloud fixture is malformed or contains an unknown field")]
    MalformedFixture,
    #[error("managed-cloud fixture does not match the configured provider scope")]
    ScopeMismatch,
    #[error("managed-cloud service does not match the importer")]
    ServiceMismatch,
    #[error("managed-cloud region or location is invalid")]
    InvalidRegion,
    #[error("managed-cloud resource identifier is empty, unbounded, or unsafe")]
    InvalidResourceIdentifier,
    #[error("managed-cloud invocation attribution is malformed or unsafe")]
    InvalidUsageAttribution,
    #[error("managed-cloud resource is outside the configured account, project, or location")]
    ResourceOutsideScope,
    #[error("managed-cloud normalized record could not be serialized")]
    Serialization,
    #[error(transparent)]
    Admission(#[from] AdmissionError),
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSTALLATION_ID: Uuid = Uuid::from_u128(0x018f_6cd4_4aaf_7bb4_a3b2_a752_4ec4_3711);

    fn base_config(scope: ManagedCloudScope) -> ManagedCloudImportConfig {
        ManagedCloudImportConfig {
            installation_id: INSTALLATION_ID,
            connector_instance_id: Uuid::from_u128(0x018f_6cd4_4aaf_7bb4_a3b2_a752_4ec4_3799),
            implementation_version: "1.0.0".to_owned(),
            source_lineage_id: Some("cloud:fixture:primary".to_owned()),
            observed_at: "2026-08-13T12:00:00Z".parse().expect("timestamp"),
            received_at: "2026-08-13T12:05:00Z".parse().expect("timestamp"),
            checkpoint: Cursor("fixture-window-1".to_owned()),
            pseudonymization_key: PseudonymizationKey::new(&[7; 32]).expect("key"),
            scope,
            transport: ManagedCloudTransport::File,
        }
    }

    fn assert_private_and_replay_safe(
        first: &ManagedCloudImportOutcome,
        replay: &ManagedCloudImportOutcome,
    ) {
        assert_eq!(first.batch.receipt, replay.batch.receipt);
        assert_eq!(first.batch.observations, replay.batch.observations);
        let serialized = serde_json::to_string(first).expect("serialize");
        for discarded in [
            "ULTRA_SECRET_PROMPT_CANARY",
            "private-resource-group",
            "secret-project-label",
            "person@example.com",
        ] {
            assert!(!serialized.contains(discarded), "retained {discarded}");
        }
        assert!(serialized.contains("p1_"));
        for expected in [
            ManagedCloudRedactionControl::SourceBytesDiscarded,
            ManagedCloudRedactionControl::RawResourceIdentifiersDiscarded,
            ManagedCloudRedactionControl::CustomerLabelsDiscarded,
            ManagedCloudRedactionControl::CustomerTagsDiscarded,
            ManagedCloudRedactionControl::IdentifiersInstallationPseudonymized,
        ] {
            assert!(first.redaction.controls.contains(&expected));
        }
    }

    #[test]
    fn aws_fixture_ignores_catalog_and_maps_only_customer_resources() {
        let config = base_config(ManagedCloudScope::Aws {
            account_id: "111122223333".to_owned(),
            region: "us-east-1".to_owned(),
            static_credentials: None,
        });
        let input = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/connectors/aws-managed-ai/v1/input.json"
        ));
        let first = import_aws_managed_ai_json(input, &config).expect("AWS fixture");
        let replay = import_aws_managed_ai_json(input, &config).expect("AWS replay");
        assert_eq!(first.stats.accepted, 4);
        assert!(
            first
                .batch
                .observations
                .iter()
                .any(|o| o.agent.name.as_deref() == Some("Support triage"))
        );
        assert_eq!(
            first
                .batch
                .observations
                .iter()
                .filter(|observation| observation.kind == ObservationKind::SaasCapability)
                .count(),
            0
        );
        assert!(first.batch.observations.iter().any(|observation| {
            observation.cloud.resource_kind == Some(CloudResourceKind::Agent)
                && observation.service.declared_model_id.as_deref()
                    == Some("anthropic.claude-3-sonnet-20240229-v1:0")
        }));
        assert_private_and_replay_safe(&first, &replay);
    }

    #[test]
    fn separate_lineages_produce_separate_observation_evidence() {
        let mut primary = base_config(ManagedCloudScope::Aws {
            account_id: "111122223333".to_owned(),
            static_credentials: None,
            region: "us-east-1".to_owned(),
        });
        let input = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/connectors/aws-managed-ai/v1/input.json"
        ));
        let first = import_aws_managed_ai_json(input, &primary).expect("primary lineage");
        primary.source_lineage_id = Some("cloud:fixture:corroborating".to_owned());
        let corroborating =
            import_aws_managed_ai_json(input, &primary).expect("corroborating lineage");

        assert_ne!(
            first.batch.observations[0].observation_id,
            corroborating.batch.observations[0].observation_id
        );
        let primary_keys = first
            .batch
            .observations
            .iter()
            .filter_map(|observation| observation.cloud.resource_key.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let corroborating_keys = corroborating
            .batch
            .observations
            .iter()
            .filter_map(|observation| observation.cloud.resource_key.clone())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(primary_keys, corroborating_keys);
    }

    #[test]
    fn azure_fixture_enforces_account_scope_and_discards_arm_labels() {
        let account_resource_id = "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/private-resource-group/providers/Microsoft.CognitiveServices/accounts/tally-ai";
        let config = base_config(ManagedCloudScope::Azure {
            subscription_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_owned(),
            account_resource_id: account_resource_id.to_owned(),
            region: "eastus2".to_owned(),
            workspace_resource: None,
            static_credentials: None,
        });
        let input = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/connectors/azure-managed-ai/v1/input.json"
        ));
        let first =
            import_azure_managed_ai_json(input, CloudProviderService::AzureAiFoundry, &config)
                .expect("Azure fixture");
        let replay =
            import_azure_managed_ai_json(input, CloudProviderService::AzureAiFoundry, &config)
                .expect("Azure replay");
        assert_eq!(first.stats.accepted, 1);
        assert_private_and_replay_safe(&first, &replay);

        let outside = base_config(ManagedCloudScope::Azure {
            subscription_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_owned(),
            account_resource_id: format!("{account_resource_id}-other"),
            region: "eastus2".to_owned(),
            workspace_resource: None,
            static_credentials: None,
        });
        assert!(matches!(
            import_azure_managed_ai_json(input, CloudProviderService::AzureOpenai, &outside),
            Err(ManagedCloudImportError::ResourceOutsideScope)
        ));
    }

    #[test]
    fn gcp_fixture_creates_endpoint_deployment_and_model_without_labels() {
        let config = base_config(ManagedCloudScope::Gcp {
            project_id: "tally-fixture-project".to_owned(),
            location: "us-central1".to_owned(),
            static_credentials: None,
        });
        let input = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/connectors/gcp-vertex-ai/v1/input.json"
        ));
        let first = import_gcp_vertex_ai_json(input, &config).expect("GCP fixture");
        let replay = import_gcp_vertex_ai_json(input, &config).expect("GCP replay");
        assert_eq!(first.stats.accepted, 3);
        assert_private_and_replay_safe(&first, &replay);
        assert!(first.batch.observations.iter().any(|observation| {
            observation.service.declared_model_id.as_deref() == Some("google/models/gemini-2.5-pro")
        }));
    }

    #[test]
    fn managed_invocation_retains_only_actionable_attribution() {
        let config = base_config(ManagedCloudScope::Gcp {
            project_id: "tally-fixture-project".to_owned(),
            location: "us-central1".to_owned(),
            static_credentials: None,
        });
        let input = br#"{"endpoints":{"endpoints":[]},"models":{"models":[]},"invocations":[{"requestId":"request-1","modelId":"gemini-2.5-flash","principalEmail":"person@example.com","sourceIp":"203.0.113.10","destinationHost":"us-central1-aiplatform.googleapis.com","observedAt":"2026-09-04T16:12:34Z"}]}"#;
        let imported = import_gcp_vertex_ai_json(input, &config).expect("GCP invocation");
        assert_eq!(imported.stats.accepted, 1);
        let usage = &imported.batch.observations[0];
        assert_eq!(usage.kind, ObservationKind::CloudUsage);
        assert_eq!(usage.cloud.usage_kind, Some(CloudUsageKind::Invocation));
        assert_eq!(
            usage.service.declared_model_id.as_deref(),
            Some("gemini-2.5-flash")
        );
        assert_eq!(
            usage.actor.source_ip.as_ref().map(IpAddress::as_str),
            Some("203.0.113.10")
        );
        assert_eq!(
            usage
                .actor
                .identity
                .as_ref()
                .and_then(|identity| identity.email.as_deref()),
            Some("person@example.com")
        );
        assert_eq!(usage.destination.port, Some(443));
        let serialized = serde_json::to_string(&imported).expect("serialized import");
        assert!(!serialized.contains("request-1"));
    }

    #[test]
    fn fixture_shape_drift_fails_without_echoing_source_values() {
        let config = base_config(ManagedCloudScope::Aws {
            account_id: "111122223333".to_owned(),
            static_credentials: None,
            region: "us-east-1".to_owned(),
        });
        let input = br#"{"foundationModels":{"modelSummaries":[]},"provisionedModelThroughputs":{"provisionedModelSummaries":[]},"agents":{"agentSummaries":[]},"sagemakerEndpoints":{"Endpoints":[]},"sagemakerModels":{"Models":[]},"prompt":"ULTRA_SECRET_PROMPT_CANARY"}"#;
        let error = import_aws_managed_ai_json(input, &config).expect_err("unknown field");
        let rendered = error.to_string();
        assert!(!rendered.contains("ULTRA_SECRET_PROMPT_CANARY"));
        assert_eq!(
            rendered,
            "managed-cloud fixture is malformed or contains an unknown field"
        );
    }

    #[test]
    fn descriptors_request_read_only_permissions() {
        for descriptor in [
            aws_managed_ai_descriptor(),
            azure_managed_ai_descriptor(),
            gcp_vertex_ai_descriptor(),
        ] {
            assert!(
                descriptor.required_permissions.iter().all(|permission| {
                    let normalized = permission.to_ascii_lowercase();
                    normalized.contains("list")
                        || normalized.contains("get")
                        || normalized.contains("lookup")
                        || normalized.ends_with("/read")
                }),
                "{} requested a non-read permission",
                descriptor.connector_type
            );
            assert!(descriptor.prohibited_fields.contains(&"prompts".to_owned()));
        }
    }
}
