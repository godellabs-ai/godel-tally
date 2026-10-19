use std::{
    collections::BTreeMap, env, fs, io::Read, net::SocketAddr, path::PathBuf, time::Duration,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand, ValueEnum};
use flate2::read::GzDecoder;
use reqwest::{Url, header::HeaderValue, redirect::Policy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tally_config::{SecretCipher, TallyConfig};
use tally_connectors::{
    CloudFlowProvider, ConnectorDescriptor, Cursor, MAX_IMPORT_BYTES, ManagedCloudImportConfig,
    ManagedCloudScope, ManagedCloudTransport, PseudonymizationKey, VendorImportConfig,
    VendorImportError, VendorImportOutcome, aws_managed_ai_api_descriptor,
    aws_managed_ai_descriptor, azure_managed_ai_api_descriptor, azure_managed_ai_descriptor,
    cato_networks_api_descriptor, cloud_flow_api_descriptor, cloud_flow_descriptor,
    cloud_mapping_api_descriptor, cloud_mapping_descriptor, cloudflare_ai_gateway_api_descriptor,
    cloudflare_ai_gateway_descriptor, cloudflare_casb_api_descriptor, cloudflare_casb_descriptor,
    cloudflare_gateway_descriptor, cloudflare_gateway_logpush_s3_descriptor,
    cloudflare_zero_trust_gateway_descriptor, crowdstrike_edr_api_descriptor,
    gcp_vertex_ai_api_descriptor, gcp_vertex_ai_descriptor, import_aws_managed_ai_json,
    import_azure_managed_ai_json, import_cato_networks_json, import_cloud_flow_api_json,
    import_cloud_flow_json, import_cloud_mapping_api_json, import_cloud_mapping_json,
    import_cloudflare_ai_gateway_api_json, import_cloudflare_ai_gateway_json,
    import_cloudflare_casb_api_json, import_cloudflare_casb_json,
    import_cloudflare_gateway_logpush_s3_ndjson, import_cloudflare_gateway_ndjson,
    import_cloudflare_zero_trust_gateway_ndjson, import_crowdstrike_edr_dns_json,
    import_gcp_vertex_ai_json, import_kubernetes_api_json, import_kubernetes_api_pull_json,
    import_litellm_model_groups_api_json, import_litellm_model_groups_json,
    import_microsoft_defender_json, import_nextdns_api_json, import_nextdns_csv,
    import_palo_alto_ndjson, import_zscaler_ndjson, inspect_nextdns_api_page,
    kubernetes_api_descriptor, kubernetes_api_pull_descriptor, litellm_model_groups_api_descriptor,
    litellm_model_groups_descriptor, microsoft_defender_edr_api_descriptor, nextdns_api_descriptor,
    nextdns_descriptor, palo_alto_descriptor, zscaler_descriptor,
};
use tally_core::CloudProviderService;
use tally_store_postgres::{
    ConnectorJobCompletion, ConnectorJobMode, ConnectorJobSpec, ConnectorJobStatus,
    ConnectorRunRecord, ConnectorRunStatus, LeasedConnectorJob, PostgresStore, SealedCredentials,
};
use uuid::Uuid;

mod aws;
mod azure;
mod cato;
mod cloudflare;
mod crowdstrike;
mod defender;
mod gcp;
mod kubernetes;
mod litellm;
mod managed_agents;
mod nextdns;
mod provider;
mod pull_support;
mod s3_logpush;
mod security_logs;

const INITIAL_BACKFILL_MIN_SECONDS: u32 = 60;
const INITIAL_BACKFILL_MAX_SECONDS: u32 = 604_800;
const EVENT_SETTLE_SECONDS: i64 = 300;
const MAX_EVENT_WINDOW_SECONDS: i64 = 300;
type EventWindow = (DateTime<Utc>, DateTime<Utc>);

fn valid_initial_backfill_seconds(value: u32) -> bool {
    (INITIAL_BACKFILL_MIN_SECONDS..=INITIAL_BACKFILL_MAX_SECONDS).contains(&value)
}

// A settled, exclusive-end window replaces the fixed five-minute replay overlap. The replay
// overlap alone could fill a 5,000-row result before any new events were read. Each completed
// window has a durable checkpoint; a saturated window is retried at half its width.
fn next_event_window(
    cursor: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    backfill_seconds: u32,
) -> Result<Option<EventWindow>, &'static str> {
    let settled = now - chrono::Duration::seconds(EVENT_SETTLE_SECONDS);
    let settled =
        DateTime::from_timestamp(settled.timestamp(), 0).ok_or("connector_cursor_invalid")?;
    let start =
        cursor.unwrap_or_else(|| settled - chrono::Duration::seconds(i64::from(backfill_seconds)));
    // Legacy millisecond cursors may not be second-aligned. Re-read their final partial second
    // so the Graph timespan's second precision cannot skip rows during upgrade.
    let start = DateTime::from_timestamp(start.timestamp(), 0).ok_or("connector_cursor_invalid")?;
    if start >= settled {
        return Ok(None);
    }
    if start < settled - chrono::Duration::days(7) {
        return Err("connector_backlog_exceeds_window");
    }
    Ok(Some((
        start,
        (start + chrono::Duration::seconds(MAX_EVENT_WINDOW_SECONDS)).min(settled),
    )))
}

fn shrink_event_window(start: DateTime<Utc>, end: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let seconds = (end - start).num_seconds();
    (seconds > 1).then(|| start + chrono::Duration::seconds((seconds / 2).max(1)))
}

#[derive(Debug, Parser)]
#[command(
    name = "tally-collector",
    version,
    about = "Gödel Tally outbound connector runner"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate the process without reading a source or opening a connection.
    Check,
    /// Print a connector's non-secret capability and privacy contract.
    Descriptor {
        #[arg(value_enum)]
        adapter: VendorAdapter,
    },
    /// Preview or commit a bounded vendor export/feed fixture.
    RunFile(RunFileArgs),
    /// Create or update a durable scheduled file/feed job using an environment-name source ref.
    ScheduleFile(ScheduleFileArgs),
    /// Create or update a durable `NextDNS` Logs API pull job.
    ScheduleNextdnsApi(ScheduleNextDnsApiArgs),
    /// Create or update a native managed-cloud inventory pull job.
    ScheduleCloud(ScheduleCloudArgs),
    /// Create or update a native cloud flow or network-mapping pull job.
    ScheduleCloudNetwork(ScheduleCloudNetworkArgs),
    /// Create or update a native Cloudflare CASB capability pull job.
    ScheduleCasb(ScheduleCasbArgs),
    /// Create or update a native read-only Kubernetes API discovery job.
    ScheduleKubernetes(ScheduleKubernetesArgs),
    /// Create or update a native read-only `LiteLLM` model-group discovery job.
    ScheduleLitellm(ScheduleLitellmArgs),
    /// Create or update a native read-only Cloudflare AI Gateway discovery job.
    ScheduleAiGateway(ScheduleAiGatewayArgs),
    /// Create or update a `CrowdStrike` Falcon EDR DNS telemetry job.
    ScheduleCrowdstrikeEdr(ScheduleCrowdstrikeEdrArgs),
    /// Create or update a Cloudflare Gateway DNS job with optional HTTP Logpush enrichment.
    ScheduleZtGateway(ScheduleZtGatewayArgs),
    /// Lease and execute durable connector jobs.
    Worker(WorkerArgs),
    /// Receive an authenticated vendor HTTPS-forwarding stream behind a TLS reverse proxy.
    Receive(ReceiverArgs),
    /// Load the deterministic, clearly labeled synthetic evaluation estate.
    DemoSeed,
}

#[derive(Debug, Args)]
struct RunFileArgs {
    #[arg(long, value_enum)]
    adapter: VendorAdapter,
    #[arg(long)]
    file: PathBuf,
    #[arg(long)]
    installation_id: Uuid,
    #[arg(long)]
    connector_instance_id: Uuid,
    /// Opaque source watermark or file-window label.
    #[arg(long)]
    checkpoint: String,
    /// Non-secret account/feed lineage label.
    #[arg(long)]
    source_lineage_id: Option<String>,
    /// Managed cloud or CASB: environment variable containing the raw account scope.
    #[arg(long)]
    account_id_env: Option<String>,
    /// Azure only: environment variable containing the Cognitive Services account resource ID.
    #[arg(long)]
    scope_id_env: Option<String>,
    /// Managed cloud: provider-controlled region or location token.
    #[arg(long)]
    region: Option<String>,
    /// Managed cloud: source snapshot time; defaults to the file modification time.
    #[arg(long)]
    observed_at: Option<DateTime<Utc>>,
    /// Path to a 32-byte raw or 64-character hexadecimal installation-local identity key.
    #[arg(long)]
    pseudonymization_key_file: PathBuf,
    /// Write the validated batch; without this flag the command emits a preview only.
    #[arg(long)]
    commit: bool,
}

#[derive(Debug, Args)]
struct ScheduleFileArgs {
    #[arg(long, value_enum)]
    adapter: VendorAdapter,
    /// Environment variable whose value is the current source file path. The value is never stored.
    #[arg(long)]
    source_path_env: String,
    /// Run cadence in seconds (60 through 86400).
    #[arg(long, default_value_t = 300)]
    interval_seconds: u32,
    #[arg(long)]
    connector_instance_id: Option<Uuid>,
    /// Managed cloud or CASB: environment variable containing the raw account scope.
    #[arg(long)]
    account_id_env: Option<String>,
    /// Azure only: environment variable containing the Cognitive Services account resource ID.
    #[arg(long)]
    scope_id_env: Option<String>,
    /// Managed cloud: provider-controlled region or location token.
    #[arg(long)]
    region: Option<String>,
    /// Create or update the schedule without making it due.
    #[arg(long)]
    paused: bool,
}

#[derive(Debug, Args)]
struct ScheduleNextDnsApiArgs {
    /// `NextDNS` profile machine identifier. It is safe to store as connector metadata.
    #[arg(long)]
    profile_id: String,
    /// Environment variable containing the API key. The key value is never stored.
    #[arg(long, default_value = "TALLY_NEXTDNS_API_KEY")]
    api_key_env: String,
    /// Initial bounded lookback in seconds (60 through 604800).
    #[arg(long, default_value_t = 3_600)]
    backfill_seconds: u32,
    /// Maximum records fetched per page (1 through 1000).
    #[arg(long, default_value_t = 1_000)]
    record_limit: u32,
    /// Poll cadence in seconds (60 through 86400).
    #[arg(long, default_value_t = 60)]
    interval_seconds: u32,
    #[arg(long)]
    connector_instance_id: Option<Uuid>,
    /// Create or update the schedule without making it due.
    #[arg(long)]
    paused: bool,
}

#[derive(Debug, Args)]
struct ScheduleCloudArgs {
    /// Native provider API adapter (for example, aws-managed-ai-api).
    #[arg(long, value_enum)]
    adapter: VendorAdapter,
    /// Environment variable containing the account, subscription, or project ID.
    #[arg(long)]
    account_id_env: String,
    /// Azure only: environment variable containing the Cognitive Services account resource ID.
    #[arg(long)]
    scope_id_env: Option<String>,
    /// Azure only: environment variable containing the Log Analytics workspace ARM ID used for
    /// request-usage diagnostics.
    #[arg(long)]
    workspace_resource_env: Option<String>,
    /// Provider-controlled region or location token.
    #[arg(long)]
    region: String,
    #[command(flatten)]
    credentials: CloudCredentialArgs,
    /// Poll cadence in seconds (60 through 86400).
    #[arg(long, default_value_t = 300)]
    interval_seconds: u32,
    #[arg(long)]
    connector_instance_id: Option<Uuid>,
    /// Create or update the schedule without making it due.
    #[arg(long)]
    paused: bool,
}

#[derive(Debug, Args)]
struct ScheduleCloudNetworkArgs {
    /// Native provider network adapter.
    #[arg(long, value_enum)]
    adapter: VendorAdapter,
    /// Environment variable containing the provider account or project ID.
    #[arg(long)]
    account_id_env: String,
    /// Environment variable containing the VPC/network machine ID.
    #[arg(long)]
    network_id_env: String,
    /// AWS/Azure only: fixed public commercial region.
    #[arg(long)]
    region: Option<String>,
    /// AWS flow only: environment variable containing the `CloudWatch` log-group name.
    #[arg(long)]
    log_group_env: Option<String>,
    /// Azure flow only: environment variable containing the Log Analytics workspace ARM ID.
    #[arg(long)]
    workspace_resource_env: Option<String>,
    #[command(flatten)]
    credentials: CloudCredentialArgs,
    /// Initial bounded lookback in seconds (300 through 3600).
    #[arg(long, default_value_t = 3_600)]
    backfill_seconds: u32,
    /// Poll cadence in seconds (60 through 86400).
    #[arg(long, default_value_t = 300)]
    interval_seconds: u32,
    #[arg(long)]
    connector_instance_id: Option<Uuid>,
    /// Create or update the schedule without making it due.
    #[arg(long)]
    paused: bool,
}

/// Optional explicit cloud credentials. When omitted, each SDK uses its standard workload
/// credential chain (including attached VM, container, or Kubernetes identities).
#[derive(Debug, Args, Default)]
#[allow(clippy::struct_field_names)] // The `_env` suffix is part of the operator-facing CLI contract.
struct CloudCredentialArgs {
    /// AWS only: environment variable containing an access key ID.
    #[arg(long)]
    aws_access_key_id_env: Option<String>,
    /// AWS only: environment variable containing the corresponding secret access key.
    #[arg(long)]
    aws_secret_access_key_env: Option<String>,
    /// AWS only: environment variable containing the STS session token for temporary keys.
    #[arg(long)]
    aws_session_token_env: Option<String>,
    /// Azure only: environment variable containing the service-principal tenant ID.
    #[arg(long)]
    azure_tenant_id_env: Option<String>,
    /// Azure only: environment variable containing the service-principal client ID.
    #[arg(long)]
    azure_client_id_env: Option<String>,
    /// Azure only: environment variable containing the service-principal client secret.
    #[arg(long)]
    azure_client_secret_env: Option<String>,
    /// Google Cloud only: environment variable containing a service-account JSON document.
    #[arg(long)]
    gcp_service_account_json_env: Option<String>,
}

#[derive(Debug, Args)]
struct ScheduleCasbArgs {
    /// Environment variable containing the Cloudflare account ID.
    #[arg(long, default_value = "TALLY_CLOUDFLARE_ACCOUNT_ID")]
    account_id_env: String,
    /// Environment variable containing a Zero Trust Read API token.
    #[arg(long, default_value = "TALLY_CLOUDFLARE_API_TOKEN")]
    api_token_env: String,
    #[arg(long, default_value_t = 300)]
    interval_seconds: u32,
    #[arg(long)]
    connector_instance_id: Option<Uuid>,
    #[arg(long)]
    paused: bool,
}

#[derive(Debug, Args)]
struct ScheduleKubernetesArgs {
    /// Use the pod's projected service-account token, CA, and Kubernetes service address.
    #[arg(long, conflicts_with_all = ["api_url_env", "bearer_token_env", "ca_file_env"])]
    in_cluster: bool,
    /// Environment variable containing the HTTPS Kubernetes API origin.
    #[arg(long, requires = "bearer_token_env")]
    api_url_env: Option<String>,
    /// Environment variable containing a read-only service-account bearer token.
    #[arg(long, requires = "api_url_env")]
    bearer_token_env: Option<String>,
    /// Optional environment variable containing a PEM CA file path.
    #[arg(long)]
    ca_file_env: Option<String>,
    #[arg(long, default_value_t = 300)]
    interval_seconds: u32,
    #[arg(long)]
    connector_instance_id: Option<Uuid>,
    #[arg(long)]
    paused: bool,
}

#[derive(Debug, Args)]
struct ScheduleZtGatewayArgs {
    /// Environment variable containing the Cloudflare account ID.
    #[arg(long, default_value = "TALLY_CLOUDFLARE_ACCOUNT_ID")]
    account_id_env: String,
    /// Environment variable containing an Account Analytics Read API token.
    #[arg(long, default_value = "TALLY_CLOUDFLARE_ANALYTICS_TOKEN")]
    api_token_env: String,
    /// Aggregate Gateway HTTP and DNS window per poll (60 through 604800 seconds).
    #[arg(long, default_value_t = 3_600)]
    window_seconds: u32,
    /// Optional HTTPS S3-compatible origin for Gateway HTTP Logpush enrichment.
    #[arg(long)]
    endpoint_url: Option<String>,
    /// Optional bucket receiving `gateway_http` or `zero_trust_network_sessions` Logpush.
    #[arg(long)]
    bucket: Option<String>,
    /// Optional dedicated object-key prefix for the Logpush job.
    #[arg(long, default_value = "")]
    prefix: String,
    /// Signing region. Cloudflare R2 uses `auto`.
    #[arg(long, default_value = "auto")]
    region: String,
    /// Environment variable containing the optional S3 access key ID.
    #[arg(long)]
    access_key_id_env: Option<String>,
    /// Environment variable containing the optional S3 secret access key.
    #[arg(long)]
    secret_access_key_env: Option<String>,
    /// Maximum Logpush objects read per poll.
    #[arg(long, default_value_t = 32)]
    object_limit: u32,
    #[arg(long, default_value_t = 300)]
    interval_seconds: u32,
    #[arg(long)]
    connector_instance_id: Option<Uuid>,
    #[arg(long)]
    paused: bool,
}

#[derive(Debug, Args)]
struct ScheduleAiGatewayArgs {
    /// Environment variable containing the Cloudflare account ID.
    #[arg(long, default_value = "TALLY_CLOUDFLARE_ACCOUNT_ID")]
    account_id_env: String,
    /// Environment variable containing an AI Gateway Read API token.
    #[arg(long, default_value = "TALLY_CLOUDFLARE_AI_GATEWAY_TOKEN")]
    api_token_env: String,
    /// Initial bounded lookback in seconds (60 through 604800).
    #[arg(long, default_value_t = 3_600)]
    backfill_seconds: u32,
    /// Maximum usage records fetched per poll (1 through 5000).
    #[arg(long, default_value_t = 1_000)]
    record_limit: u32,
    #[arg(long, default_value_t = 300)]
    interval_seconds: u32,
    #[arg(long)]
    connector_instance_id: Option<Uuid>,
    #[arg(long)]
    paused: bool,
}

#[derive(Debug, Args)]
struct ScheduleCrowdstrikeEdrArgs {
    /// Falcon cloud: us-1, us-2, or eu-1.
    #[arg(long, default_value = "us-1")]
    cloud: String,
    /// Environment variable containing the Falcon OAuth client ID.
    #[arg(long, default_value = "TALLY_CROWDSTRIKE_CLIENT_ID")]
    client_id_env: String,
    /// Environment variable containing the Falcon OAuth client secret.
    #[arg(long, default_value = "TALLY_CROWDSTRIKE_CLIENT_SECRET")]
    client_secret_env: String,
    /// Initial bounded DNS-telemetry lookback in seconds (60 through 604800).
    #[arg(long, default_value_t = 3_600)]
    backfill_seconds: u32,
    /// Maximum DNS events fetched per poll (1 through 5000).
    #[arg(long, default_value_t = 1_000)]
    record_limit: u32,
    #[arg(long, default_value_t = 300)]
    interval_seconds: u32,
    #[arg(long)]
    connector_instance_id: Option<Uuid>,
    #[arg(long)]
    paused: bool,
}

#[derive(Debug, Args)]
struct ScheduleLitellmArgs {
    /// Environment variable containing the HTTPS `LiteLLM` proxy origin, or HTTP loopback for
    /// local development.
    #[arg(long, default_value = "TALLY_LITELLM_BASE_URL")]
    base_url_env: String,
    /// Environment variable containing a read-capable `LiteLLM` virtual key.
    #[arg(long, default_value = "TALLY_LITELLM_API_KEY")]
    api_key_env: String,
    /// Initial bounded request-log lookback in seconds (60 through 604800).
    #[arg(long, default_value_t = 3_600)]
    backfill_seconds: u32,
    /// Maximum request records fetched per poll (1 through 1000).
    #[arg(long, default_value_t = 1_000)]
    record_limit: u32,
    #[arg(long, default_value_t = 300)]
    interval_seconds: u32,
    #[arg(long)]
    connector_instance_id: Option<Uuid>,
    #[arg(long)]
    paused: bool,
}

#[derive(Debug, Args)]
struct WorkerArgs {
    /// Claim the current due window once, then exit.
    #[arg(long)]
    once: bool,
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u16).range(1..=60))]
    poll_seconds: u16,
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u16).range(30..=3600))]
    lease_seconds: u16,
}

#[derive(Debug, Args)]
struct ReceiverArgs {
    #[arg(long, value_enum)]
    adapter: PushAdapter,
    /// Loopback listener for a same-host TLS reverse proxy.
    #[arg(long, default_value = "127.0.0.1:8790")]
    bind: SocketAddr,
    /// Explicitly permit a wildcard/non-loopback HTTP bind when TLS is terminated elsewhere.
    #[arg(long)]
    allow_non_loopback: bool,
    /// Environment variable containing the exact expected Authorization header value.
    #[arg(long)]
    authorization_env: String,
    #[arg(long)]
    connector_instance_id: Option<Uuid>,
    /// Non-secret feed/account machine label used in provenance.
    #[arg(long, default_value = "vendor_push")]
    source_lineage_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum VendorAdapter {
    DefenderStream,
    ServicenowAgents,
    N8nAgents,
    CopilotStudioAgents,
    LanggraphAgents,
    DifyAgents,
    OpenaiAgents,
    ClaudeAgents,
    GeminiAgents,
    Nextdns,
    NextdnsApi,
    CloudflareGateway,
    Zscaler,
    PaloAlto,
    AwsManagedAi,
    AwsManagedAiApi,
    AzureOpenai,
    AzureOpenaiApi,
    AzureAiFoundry,
    AzureAiFoundryApi,
    GcpVertexAi,
    GcpVertexAiApi,
    AwsCloudFlow,
    AwsNetworkMapping,
    AzureCloudFlow,
    AzureNetworkMapping,
    GcpCloudFlow,
    GcpNetworkMapping,
    AwsCloudFlowApi,
    AwsNetworkMappingApi,
    AzureCloudFlowApi,
    AzureNetworkMappingApi,
    GcpCloudFlowApi,
    GcpNetworkMappingApi,
    CloudflareCasb,
    CloudflareCasbApi,
    KubernetesApi,
    KubernetesApiPull,
    Litellm,
    LitellmApi,
    CloudflareAiGateway,
    CloudflareAiGatewayApi,
    CrowdstrikeEdr,
    Rapid7Edr,
    Netskope,
    MicrosoftDefenderApi,
    CatoNetworksApi,
    CloudflareZeroTrustGateway,
    CloudflareGatewayLogpushS3,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PushAdapter {
    DefenderStream,
    CloudflareGateway,
    Zscaler,
    PaloAlto,
}

impl PushAdapter {
    const fn vendor(self) -> VendorAdapter {
        match self {
            Self::DefenderStream => VendorAdapter::DefenderStream,
            Self::CloudflareGateway => VendorAdapter::CloudflareGateway,
            Self::Zscaler => VendorAdapter::Zscaler,
            Self::PaloAlto => VendorAdapter::PaloAlto,
        }
    }
}

impl VendorAdapter {
    const fn key(self) -> &'static str {
        match self {
            Self::DefenderStream => "defender_stream",
            Self::ServicenowAgents => "servicenow_agents",
            Self::N8nAgents => "n8n_agents",
            Self::CopilotStudioAgents => "copilot_studio_agents",
            Self::LanggraphAgents => "langgraph_agents",
            Self::DifyAgents => "dify_agents",
            Self::OpenaiAgents => "openai_agents",
            Self::ClaudeAgents => "claude_agents",
            Self::GeminiAgents => "gemini_agents",
            Self::Nextdns => "nextdns",
            Self::NextdnsApi => "nextdns_api",
            Self::CloudflareGateway => "cloudflare_gateway",
            Self::Zscaler => "zscaler",
            Self::PaloAlto => "palo_alto",
            Self::AwsManagedAi => "aws_managed_ai",
            Self::AwsManagedAiApi => "aws_managed_ai_api",
            Self::AzureOpenai => "azure_openai",
            Self::AzureOpenaiApi => "azure_openai_api",
            Self::AzureAiFoundry => "azure_ai_foundry",
            Self::AzureAiFoundryApi => "azure_ai_foundry_api",
            Self::GcpVertexAi => "gcp_vertex_ai",
            Self::GcpVertexAiApi => "gcp_vertex_ai_api",
            Self::AwsCloudFlow => "aws_cloud_flow",
            Self::AwsNetworkMapping => "aws_network_mapping",
            Self::AzureCloudFlow => "azure_cloud_flow",
            Self::AzureNetworkMapping => "azure_network_mapping",
            Self::GcpCloudFlow => "gcp_cloud_flow",
            Self::GcpNetworkMapping => "gcp_network_mapping",
            Self::AwsCloudFlowApi => "aws_cloud_flow_api",
            Self::AwsNetworkMappingApi => "aws_network_mapping_api",
            Self::AzureCloudFlowApi => "azure_cloud_flow_api",
            Self::AzureNetworkMappingApi => "azure_network_mapping_api",
            Self::GcpCloudFlowApi => "gcp_cloud_flow_api",
            Self::GcpNetworkMappingApi => "gcp_network_mapping_api",
            Self::CloudflareCasb => "cloudflare_casb",
            Self::CloudflareCasbApi => "cloudflare_casb_api",
            Self::KubernetesApi => "kubernetes_api",
            Self::KubernetesApiPull => "kubernetes_api_pull",
            Self::Litellm => "litellm",
            Self::LitellmApi => "litellm_api",
            Self::CloudflareAiGateway => "cloudflare_ai_gateway",
            Self::CloudflareAiGatewayApi => "cloudflare_ai_gateway_api",
            Self::Rapid7Edr => "rapid7_edr",
            Self::Netskope => "netskope",
            Self::CrowdstrikeEdr => "crowdstrike_edr",
            Self::MicrosoftDefenderApi => "microsoft_defender_api",
            Self::CatoNetworksApi => "cato_networks_api",
            Self::CloudflareZeroTrustGateway => "cloudflare_zero_trust_gateway",
            Self::CloudflareGatewayLogpushS3 => "cloudflare_gateway_logpush_s3",
        }
    }

    fn from_key(value: &str) -> Option<Self> {
        match value {
            "defender_stream" => Some(Self::DefenderStream),
            "servicenow_agents" => Some(Self::ServicenowAgents),
            "n8n_agents" => Some(Self::N8nAgents),
            "copilot_studio_agents" => Some(Self::CopilotStudioAgents),
            "langgraph_agents" => Some(Self::LanggraphAgents),
            "dify_agents" => Some(Self::DifyAgents),
            "openai_agents" => Some(Self::OpenaiAgents),
            "claude_agents" => Some(Self::ClaudeAgents),
            "gemini_agents" => Some(Self::GeminiAgents),
            "nextdns" => Some(Self::Nextdns),
            "nextdns_api" => Some(Self::NextdnsApi),
            "cloudflare_gateway" => Some(Self::CloudflareGateway),
            "zscaler" => Some(Self::Zscaler),
            "palo_alto" => Some(Self::PaloAlto),
            "aws_managed_ai" => Some(Self::AwsManagedAi),
            "aws_managed_ai_api" => Some(Self::AwsManagedAiApi),
            "azure_openai" => Some(Self::AzureOpenai),
            "azure_openai_api" => Some(Self::AzureOpenaiApi),
            "azure_ai_foundry" => Some(Self::AzureAiFoundry),
            "azure_ai_foundry_api" => Some(Self::AzureAiFoundryApi),
            "gcp_vertex_ai" => Some(Self::GcpVertexAi),
            "gcp_vertex_ai_api" => Some(Self::GcpVertexAiApi),
            "aws_cloud_flow" => Some(Self::AwsCloudFlow),
            "aws_network_mapping" => Some(Self::AwsNetworkMapping),
            "azure_cloud_flow" => Some(Self::AzureCloudFlow),
            "azure_network_mapping" => Some(Self::AzureNetworkMapping),
            "gcp_cloud_flow" => Some(Self::GcpCloudFlow),
            "gcp_network_mapping" => Some(Self::GcpNetworkMapping),
            "aws_cloud_flow_api" => Some(Self::AwsCloudFlowApi),
            "aws_network_mapping_api" => Some(Self::AwsNetworkMappingApi),
            "azure_cloud_flow_api" => Some(Self::AzureCloudFlowApi),
            "azure_network_mapping_api" => Some(Self::AzureNetworkMappingApi),
            "gcp_cloud_flow_api" => Some(Self::GcpCloudFlowApi),
            "gcp_network_mapping_api" => Some(Self::GcpNetworkMappingApi),
            "cloudflare_casb" => Some(Self::CloudflareCasb),
            "cloudflare_casb_api" => Some(Self::CloudflareCasbApi),
            "kubernetes_api" => Some(Self::KubernetesApi),
            "kubernetes_api_pull" => Some(Self::KubernetesApiPull),
            "litellm" => Some(Self::Litellm),
            "litellm_api" => Some(Self::LitellmApi),
            "cloudflare_ai_gateway" => Some(Self::CloudflareAiGateway),
            "cloudflare_ai_gateway_api" => Some(Self::CloudflareAiGatewayApi),
            "rapid7_edr" => Some(Self::Rapid7Edr),
            "netskope" => Some(Self::Netskope),
            "crowdstrike_edr" => Some(Self::CrowdstrikeEdr),
            "microsoft_defender_api" => Some(Self::MicrosoftDefenderApi),
            "cato_networks_api" => Some(Self::CatoNetworksApi),
            "cloudflare_zero_trust_gateway" => Some(Self::CloudflareZeroTrustGateway),
            "cloudflare_gateway_logpush_s3" => Some(Self::CloudflareGatewayLogpushS3),
            _ => None,
        }
    }

    fn descriptor(self) -> ConnectorDescriptor {
        match self {
            Self::DefenderStream => tally_connectors::defender_stream_descriptor(),
            Self::ServicenowAgents => tally_connectors::managed_agents_descriptor("servicenow"),
            Self::N8nAgents => tally_connectors::managed_agents_descriptor("n8n"),
            Self::CopilotStudioAgents => {
                tally_connectors::managed_agents_descriptor("copilot_studio")
            }
            Self::LanggraphAgents => tally_connectors::managed_agents_descriptor("langgraph"),
            Self::DifyAgents => tally_connectors::managed_agents_descriptor("dify"),
            Self::OpenaiAgents => tally_connectors::managed_agents_descriptor("openai"),
            Self::ClaudeAgents => tally_connectors::managed_agents_descriptor("claude"),
            Self::GeminiAgents => tally_connectors::managed_agents_descriptor("gemini"),
            Self::Nextdns => nextdns_descriptor(),
            Self::NextdnsApi => nextdns_api_descriptor(),
            Self::CloudflareGateway => cloudflare_gateway_descriptor(),
            Self::Zscaler => zscaler_descriptor(),
            Self::PaloAlto => palo_alto_descriptor(),
            Self::AwsManagedAi => aws_managed_ai_descriptor(),
            Self::AwsManagedAiApi => aws_managed_ai_api_descriptor(),
            Self::AzureOpenai | Self::AzureAiFoundry => azure_managed_ai_descriptor(),
            Self::AzureOpenaiApi | Self::AzureAiFoundryApi => azure_managed_ai_api_descriptor(),
            Self::GcpVertexAi => gcp_vertex_ai_descriptor(),
            Self::GcpVertexAiApi => gcp_vertex_ai_api_descriptor(),
            Self::AwsCloudFlow => cloud_flow_descriptor(CloudFlowProvider::Aws),
            Self::AwsNetworkMapping => cloud_mapping_descriptor(CloudFlowProvider::Aws),
            Self::AzureCloudFlow => cloud_flow_descriptor(CloudFlowProvider::Azure),
            Self::AzureNetworkMapping => cloud_mapping_descriptor(CloudFlowProvider::Azure),
            Self::GcpCloudFlow => cloud_flow_descriptor(CloudFlowProvider::Gcp),
            Self::GcpNetworkMapping => cloud_mapping_descriptor(CloudFlowProvider::Gcp),
            Self::AwsCloudFlowApi => cloud_flow_api_descriptor(CloudFlowProvider::Aws),
            Self::AwsNetworkMappingApi => cloud_mapping_api_descriptor(CloudFlowProvider::Aws),
            Self::AzureCloudFlowApi => cloud_flow_api_descriptor(CloudFlowProvider::Azure),
            Self::AzureNetworkMappingApi => cloud_mapping_api_descriptor(CloudFlowProvider::Azure),
            Self::GcpCloudFlowApi => cloud_flow_api_descriptor(CloudFlowProvider::Gcp),
            Self::GcpNetworkMappingApi => cloud_mapping_api_descriptor(CloudFlowProvider::Gcp),
            Self::CloudflareCasb => cloudflare_casb_descriptor(),
            Self::CloudflareCasbApi => cloudflare_casb_api_descriptor(),
            Self::KubernetesApi => kubernetes_api_descriptor(),
            Self::KubernetesApiPull => kubernetes_api_pull_descriptor(),
            Self::Litellm => litellm_model_groups_descriptor(),
            Self::LitellmApi => litellm_model_groups_api_descriptor(),
            Self::CloudflareAiGateway => cloudflare_ai_gateway_descriptor(),
            Self::CloudflareAiGatewayApi => cloudflare_ai_gateway_api_descriptor(),
            Self::Rapid7Edr => tally_connectors::SecurityLogSource::Rapid7Edr.descriptor(),
            Self::Netskope => tally_connectors::SecurityLogSource::Netskope.descriptor(),
            Self::CrowdstrikeEdr => crowdstrike_edr_api_descriptor(),
            Self::MicrosoftDefenderApi => microsoft_defender_edr_api_descriptor(),
            Self::CatoNetworksApi => cato_networks_api_descriptor(),
            Self::CloudflareZeroTrustGateway => cloudflare_zero_trust_gateway_descriptor(),
            Self::CloudflareGatewayLogpushS3 => cloudflare_gateway_logpush_s3_descriptor(),
        }
    }

    #[allow(clippy::too_many_lines)] // Keep provider dispatch a flat, auditable table.
    fn normalize(self, input: &[u8], config: &VendorImportConfig) -> Result<VendorImportOutcome> {
        match self {
            Self::DefenderStream => {
                tally_connectors::import_defender_stream_json(input, config).map_err(Into::into)
            }
            Self::ServicenowAgents
            | Self::N8nAgents
            | Self::CopilotStudioAgents
            | Self::LanggraphAgents
            | Self::OpenaiAgents
            | Self::ClaudeAgents
            | Self::GeminiAgents
            | Self::DifyAgents => {
                tally_connectors::import_managed_agents_json(input, config).map_err(Into::into)
            }
            Self::Nextdns => import_nextdns_csv(input, config).map_err(Into::into),
            Self::NextdnsApi => import_nextdns_api_json(input, config).map_err(Into::into),
            Self::CloudflareGateway => {
                import_cloudflare_gateway_ndjson(input, config).map_err(Into::into)
            }
            Self::Zscaler => import_zscaler_ndjson(input, config).map_err(Into::into),
            Self::PaloAlto => import_palo_alto_ndjson(input, config).map_err(Into::into),
            Self::AwsCloudFlow => {
                import_cloud_flow_json(input, CloudFlowProvider::Aws, config).map_err(Into::into)
            }
            Self::AwsNetworkMapping => {
                import_cloud_mapping_json(input, CloudFlowProvider::Aws, config).map_err(Into::into)
            }
            Self::AzureCloudFlow => {
                import_cloud_flow_json(input, CloudFlowProvider::Azure, config).map_err(Into::into)
            }
            Self::AzureNetworkMapping => {
                import_cloud_mapping_json(input, CloudFlowProvider::Azure, config)
                    .map_err(Into::into)
            }
            Self::GcpCloudFlow => {
                import_cloud_flow_json(input, CloudFlowProvider::Gcp, config).map_err(Into::into)
            }
            Self::GcpNetworkMapping => {
                import_cloud_mapping_json(input, CloudFlowProvider::Gcp, config).map_err(Into::into)
            }
            Self::AwsCloudFlowApi => {
                import_cloud_flow_api_json(input, CloudFlowProvider::Aws, config)
                    .map_err(Into::into)
            }
            Self::AwsNetworkMappingApi => {
                import_cloud_mapping_api_json(input, CloudFlowProvider::Aws, config)
                    .map_err(Into::into)
            }
            Self::AzureCloudFlowApi => {
                import_cloud_flow_api_json(input, CloudFlowProvider::Azure, config)
                    .map_err(Into::into)
            }
            Self::AzureNetworkMappingApi => {
                import_cloud_mapping_api_json(input, CloudFlowProvider::Azure, config)
                    .map_err(Into::into)
            }
            Self::GcpCloudFlowApi => {
                import_cloud_flow_api_json(input, CloudFlowProvider::Gcp, config)
                    .map_err(Into::into)
            }
            Self::GcpNetworkMappingApi => {
                import_cloud_mapping_api_json(input, CloudFlowProvider::Gcp, config)
                    .map_err(Into::into)
            }
            Self::KubernetesApi => import_kubernetes_api_json(input, config).map_err(Into::into),
            Self::KubernetesApiPull => {
                import_kubernetes_api_pull_json(input, config).map_err(Into::into)
            }
            Self::Litellm => import_litellm_model_groups_json(input, config).map_err(Into::into),
            Self::LitellmApi => {
                import_litellm_model_groups_api_json(input, config).map_err(Into::into)
            }
            Self::CloudflareAiGateway => {
                import_cloudflare_ai_gateway_json(input, config).map_err(Into::into)
            }
            Self::CloudflareAiGatewayApi => {
                import_cloudflare_ai_gateway_api_json(input, config).map_err(Into::into)
            }
            Self::Rapid7Edr => tally_connectors::import_security_logs_json(
                input,
                tally_connectors::SecurityLogSource::Rapid7Edr,
                config,
            )
            .map_err(Into::into),
            Self::Netskope => tally_connectors::import_security_logs_json(
                input,
                tally_connectors::SecurityLogSource::Netskope,
                config,
            )
            .map_err(Into::into),
            Self::CrowdstrikeEdr => {
                import_crowdstrike_edr_dns_json(input, config).map_err(Into::into)
            }
            Self::MicrosoftDefenderApi => {
                import_microsoft_defender_json(input, config).map_err(Into::into)
            }
            Self::CatoNetworksApi => import_cato_networks_json(input, config).map_err(Into::into),
            Self::CloudflareZeroTrustGateway => {
                import_cloudflare_zero_trust_gateway_ndjson(input, config).map_err(Into::into)
            }
            Self::CloudflareGatewayLogpushS3 => {
                import_cloudflare_gateway_logpush_s3_ndjson(input, config).map_err(Into::into)
            }
            Self::CloudflareCasb | Self::CloudflareCasbApi => {
                bail!("CASB adapter requires an explicit account scope")
            }
            Self::AwsManagedAi
            | Self::AwsManagedAiApi
            | Self::AzureOpenai
            | Self::AzureOpenaiApi
            | Self::AzureAiFoundry
            | Self::AzureAiFoundryApi
            | Self::GcpVertexAi
            | Self::GcpVertexAiApi => {
                bail!("managed-cloud adapter requires an explicit cloud scope")
            }
        }
    }

    const fn is_managed_cloud(self) -> bool {
        matches!(
            self,
            Self::AwsManagedAi
                | Self::AwsManagedAiApi
                | Self::AzureOpenai
                | Self::AzureOpenaiApi
                | Self::AzureAiFoundry
                | Self::AzureAiFoundryApi
                | Self::GcpVertexAi
                | Self::GcpVertexAiApi
        )
    }

    const fn is_native_cloud(self) -> bool {
        matches!(
            self,
            Self::AwsManagedAiApi
                | Self::AzureOpenaiApi
                | Self::AzureAiFoundryApi
                | Self::GcpVertexAiApi
        )
    }

    const fn is_native_cloud_network(self) -> bool {
        matches!(
            self,
            Self::AwsCloudFlowApi
                | Self::AwsNetworkMappingApi
                | Self::AzureCloudFlowApi
                | Self::AzureNetworkMappingApi
                | Self::GcpCloudFlowApi
                | Self::GcpNetworkMappingApi
        )
    }

    const fn is_casb(self) -> bool {
        matches!(self, Self::CloudflareCasb | Self::CloudflareCasbApi)
    }

    fn normalize_casb(
        self,
        input: &[u8],
        account_id: &str,
        config: &VendorImportConfig,
    ) -> Result<VendorImportOutcome> {
        match self {
            Self::CloudflareCasb => {
                import_cloudflare_casb_json(input, account_id, config).map_err(Into::into)
            }
            Self::CloudflareCasbApi => {
                import_cloudflare_casb_api_json(input, account_id, config).map_err(Into::into)
            }
            _ => bail!("adapter is not CASB"),
        }
    }

    const fn is_native_enterprise(self) -> bool {
        matches!(
            self,
            Self::CloudflareCasbApi
                | Self::KubernetesApiPull
                | Self::LitellmApi
                | Self::CloudflareAiGatewayApi
                | Self::Rapid7Edr
                | Self::Netskope
                | Self::CrowdstrikeEdr
                | Self::MicrosoftDefenderApi
                | Self::CatoNetworksApi
                | Self::CloudflareZeroTrustGateway
                | Self::CloudflareGatewayLogpushS3
        )
    }

    const fn cloud_transport(self) -> ManagedCloudTransport {
        if self.is_native_cloud() {
            ManagedCloudTransport::NativeApi
        } else {
            ManagedCloudTransport::File
        }
    }

    fn normalize_cloud(
        self,
        input: &[u8],
        config: &ManagedCloudImportConfig,
    ) -> Result<VendorImportOutcome> {
        let outcome = match self {
            Self::AwsManagedAi | Self::AwsManagedAiApi => import_aws_managed_ai_json(input, config),
            Self::AzureOpenai | Self::AzureOpenaiApi => {
                import_azure_managed_ai_json(input, CloudProviderService::AzureOpenai, config)
            }
            Self::AzureAiFoundry | Self::AzureAiFoundryApi => {
                import_azure_managed_ai_json(input, CloudProviderService::AzureAiFoundry, config)
            }
            Self::GcpVertexAi | Self::GcpVertexAiApi => import_gcp_vertex_ai_json(input, config),
            _ => bail!("adapter is not managed cloud"),
        }?;
        Ok(outcome.into())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduledFileConfig {
    kind: String,
    adapter: String,
    source_lineage_id: String,
    #[serde(default)]
    region: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduledNextDnsApiConfig {
    kind: String,
    profile_id: String,
    source_lineage_id: String,
    backfill_seconds: String,
    #[serde(default = "default_record_limit_ref")]
    record_limit: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduledCloudApiConfig {
    kind: String,
    adapter: String,
    source_lineage_id: String,
    region: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduledCloudNetworkApiConfig {
    kind: String,
    adapter: String,
    source_lineage_id: String,
    #[serde(default)]
    region: Option<String>,
    backfill_seconds: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduledCasbApiConfig {
    kind: String,
    source_lineage_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduledKubernetesApiConfig {
    kind: String,
    source_lineage_id: String,
    auth_mode: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduledLitellmApiConfig {
    kind: String,
    source_lineage_id: String,
    #[serde(default = "default_backfill_seconds_ref")]
    backfill_seconds: String,
    #[serde(default = "default_record_limit_ref")]
    record_limit: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduledAiGatewayApiConfig {
    kind: String,
    source_lineage_id: String,
    #[serde(default = "default_backfill_seconds_ref")]
    backfill_seconds: String,
    #[serde(default = "default_record_limit_ref")]
    record_limit: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduledCrowdstrikeEdrConfig {
    kind: String,
    source_lineage_id: String,
    cloud: String,
    #[serde(default = "default_backfill_seconds_ref")]
    backfill_seconds: String,
    #[serde(default = "default_record_limit_ref")]
    record_limit: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduledMicrosoftDefenderConfig {
    kind: String,
    source_lineage_id: String,
    #[serde(default = "default_backfill_seconds_ref")]
    backfill_seconds: String,
    #[serde(default = "default_record_limit_ref")]
    record_limit: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduledCatoNetworksConfig {
    kind: String,
    source_lineage_id: String,
    api_hostname: String,
    #[serde(default = "default_backfill_seconds_ref")]
    backfill_seconds: String,
    #[serde(default = "default_record_limit_ref")]
    record_limit: String,
}

fn default_backfill_seconds_ref() -> String {
    "3600".to_owned()
}

fn default_record_limit_ref() -> String {
    "1000".to_owned()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduledCloudflareGatewayLogpushS3Config {
    kind: String,
    source_lineage_id: String,
    endpoint_url: String,
    bucket: String,
    prefix: String,
    region: String,
    object_limit: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduledCloudflareZeroTrustGatewayConfig {
    kind: String,
    source_lineage_id: String,
    window_seconds: String,
    endpoint_url: String,
    bucket: String,
    prefix: String,
    region: String,
    object_limit: String,
}

#[derive(Debug)]
struct CloudNetworkScheduleReferences {
    region: String,
    log_group_env: Option<String>,
    workspace_resource_env: Option<String>,
    credential_chain: &'static str,
}

#[derive(Debug)]
struct ValidatedCloudNetworkConfig {
    config: ScheduledCloudNetworkApiConfig,
    adapter: VendorAdapter,
    backfill_seconds: u32,
    region: String,
}

#[derive(Debug)]
struct CloudNetworkRuntimeValues {
    account_id: String,
    network_id: String,
    log_group: Option<String>,
    workspace_resource: Option<String>,
    credentials: pull_support::NativeNetworkCredentials,
}

#[derive(Debug, Deserialize)]
struct CommitReceipt {
    run_id: Uuid,
    batch_id: Uuid,
    disposition: String,
    status: String,
    accepted: u64,
    deduplicated: u64,
    findings_updated: usize,
    canonical_digest: String,
    content_retained: bool,
}

#[derive(Debug, Serialize)]
struct ApiImportPreviewRequest<'a> {
    adapter: &'a str,
    connector_instance_id: Uuid,
    source_lineage_id: &'a str,
    checkpoint: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cloud_scope: Option<ApiManagedCloudScope<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    casb_account_id: Option<&'a str>,
    data: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
enum ApiManagedCloudScope<'a> {
    Aws {
        account_id: &'a str,
        region: &'a str,
    },
    Azure {
        subscription_id: &'a str,
        account_resource_id: &'a str,
        region: &'a str,
    },
    Gcp {
        project_id: &'a str,
        location: &'a str,
    },
}

#[derive(Debug, Clone)]
struct CloudImportSource {
    observed_at: DateTime<Utc>,
    scope: ManagedCloudScope,
}

impl CloudImportSource {
    fn api_scope(&self) -> ApiManagedCloudScope<'_> {
        match &self.scope {
            ManagedCloudScope::Aws {
                account_id, region, ..
            } => ApiManagedCloudScope::Aws { account_id, region },
            ManagedCloudScope::Azure {
                subscription_id,
                account_resource_id,
                region,
                ..
            } => ApiManagedCloudScope::Azure {
                subscription_id,
                account_resource_id,
                region,
            },
            ManagedCloudScope::Gcp {
                project_id,
                location,
                ..
            } => ApiManagedCloudScope::Gcp {
                project_id,
                location,
            },
        }
    }
}

#[derive(Debug, Deserialize)]
struct ApiImportPreviewResponse {
    canonical_digest: String,
    writes_data: bool,
    source_bytes_retained: bool,
    content_retained: bool,
}

#[derive(Debug, Serialize)]
struct ApiImportCommitRequest<'a> {
    #[serde(flatten)]
    preview: ApiImportPreviewRequest<'a>,
    confirm_canonical_digest: &'a str,
}

#[derive(Debug)]
struct ApiImportSource<'a> {
    adapter: VendorAdapter,
    connector_instance_id: Uuid,
    source_lineage_id: &'a str,
    checkpoint: &'a str,
    input: &'a [u8],
    expected_canonical_digest: &'a str,
    cloud: Option<&'a CloudImportSource>,
    casb_account_id: Option<&'a str>,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum PreparedJob {
    Source {
        descriptor: ConnectorDescriptor,
        adapter: VendorAdapter,
        input: Vec<u8>,
        checkpoint: String,
        source_lineage_id: String,
        expected_canonical_digest: String,
        cloud: Option<CloudImportSource>,
        casb_account_id: Option<String>,
    },
    EmptyPoll {
        descriptor: ConnectorDescriptor,
        cursor_before: String,
        cursor_after: String,
    },
}

#[derive(Debug, Clone)]
struct ReceiverState {
    client: reqwest::Client,
    api_base: Url,
    adapter: VendorAdapter,
    installation_id: Uuid,
    connector_instance_id: Uuid,
    source_lineage_id: String,
    pseudonymization_key: PseudonymizationKey,
    authorization_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
enum ReceiverFailure {
    Unauthorized,
    PayloadTooLarge,
    EncodingUnsupported,
    PayloadInvalid,
    TallyUnavailable,
}

impl ReceiverFailure {
    const fn status(self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::EncodingUnsupported => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::PayloadInvalid => StatusCode::BAD_REQUEST,
            Self::TallyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::Unauthorized => "receiver_unauthorized",
            Self::PayloadTooLarge => "receiver_payload_too_large",
            Self::EncodingUnsupported => "receiver_encoding_unsupported",
            Self::PayloadInvalid => "receiver_payload_invalid",
            Self::TallyUnavailable => "tally_ingestion_unavailable",
        }
    }
}

impl IntoResponse for ReceiverFailure {
    fn into_response(self) -> Response {
        (
            self.status(),
            Json(serde_json::json!({
                "code": self.code(),
                "content_retained": false
            })),
        )
            .into_response()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    run_cli(std::env::args()).await
}

/// Execute collector commands using the same CLI in standalone and bundled deployments.
///
/// # Errors
/// Returns an error if the selected connector operation fails.
pub async fn run_cli(args: impl IntoIterator<Item = String>) -> Result<()> {
    match Cli::parse_from(args).command {
        Command::Check => {
            println!("tally-collector runtime is ready; no source was contacted");
            Ok(())
        }
        Command::Descriptor { adapter } => {
            println!("{}", serde_json::to_string_pretty(&adapter.descriptor())?);
            Ok(())
        }
        Command::RunFile(args) => run_file(args).await,
        Command::ScheduleFile(args) => schedule_file(args).await,
        Command::ScheduleNextdnsApi(args) => schedule_nextdns_api(args).await,
        Command::ScheduleCloud(args) => schedule_cloud(args).await,
        Command::ScheduleCloudNetwork(args) => schedule_cloud_network(args).await,
        Command::ScheduleCasb(args) => schedule_casb(args).await,
        Command::ScheduleKubernetes(args) => schedule_kubernetes(args).await,
        Command::ScheduleLitellm(args) => schedule_litellm(args).await,
        Command::ScheduleAiGateway(args) => schedule_ai_gateway(args).await,
        Command::ScheduleCrowdstrikeEdr(args) => schedule_crowdstrike_edr(args).await,
        Command::ScheduleZtGateway(args) => schedule_zt_gateway(args).await,
        Command::Worker(args) => Box::pin(worker(args)).await,
        Command::Receive(args) => receive(args).await,
        Command::DemoSeed => demo_seed().await,
    }
}

async fn demo_seed() -> Result<()> {
    const SOURCES: &[(VendorAdapter, &[u8])] = &[
        (
            VendorAdapter::Nextdns,
            include_bytes!("../../../testdata/connectors/nextdns/v1/input.csv"),
        ),
        (
            VendorAdapter::CloudflareGateway,
            include_bytes!("../../../testdata/connectors/cloudflare-gateway/v1/input.ndjson"),
        ),
        (
            VendorAdapter::Zscaler,
            include_bytes!("../../../testdata/connectors/zscaler/v1/input.ndjson"),
        ),
        (
            VendorAdapter::PaloAlto,
            include_bytes!("../../../testdata/connectors/palo-alto/v1/input.ndjson"),
        ),
    ];

    let config = TallyConfig::from_env().context("load Tally configuration")?;
    let api_base = tally_api_base(&config)?;
    let client = collector_http_client()?;
    let mut accepted = 0_u64;
    let mut deduplicated = 0_u64;
    let mut resolved_system_updates = 0_usize;
    let mut runs = Vec::with_capacity(SOURCES.len());
    let anchor = Utc::now()
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("midnight is a valid time")
        .and_utc();

    for (adapter, input) in SOURCES {
        let connector_instance_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("godel-tally:synthetic-demo-v1:{}", adapter.key()).as_bytes(),
        );
        let checkpoint = format!(
            "synthetic-demo-v1-{}-{}",
            anchor.format("%Y-%m-%d"),
            adapter.key()
        );
        let data = dated_demo_fixture(input, anchor)?;
        let preview = ApiImportPreviewRequest {
            adapter: adapter.key(),
            connector_instance_id,
            source_lineage_id: "synthetic_demo_v1",
            checkpoint: &checkpoint,
            observed_at: None,
            cloud_scope: None,
            casb_account_id: None,
            data: &data,
        };
        let receipt = preview_and_commit(&client, &api_base, preview, None).await?;
        accepted = accepted.saturating_add(receipt.accepted);
        deduplicated = deduplicated.saturating_add(receipt.deduplicated);
        resolved_system_updates = resolved_system_updates.saturating_add(receipt.findings_updated);
        runs.push(serde_json::json!({
            "adapter": adapter.key(),
            "status": receipt.status,
            "accepted": receipt.accepted,
            "deduplicated": receipt.deduplicated,
        }));
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "estate": "synthetic_demo_v1",
            "label": "Synthetic demo evidence — not observed from this network",
            "sources": runs,
            "accepted": accepted,
            "deduplicated": deduplicated,
            "resolved_system_updates": resolved_system_updates,
            "content_retained": false,
            "replay_safe": true,
        }))?
    );
    Ok(())
}

fn dated_demo_fixture(input: &[u8], anchor: DateTime<Utc>) -> Result<String> {
    let fixture = std::str::from_utf8(input).context("embedded demo fixture must be UTF-8")?;
    let next_second = anchor + chrono::Duration::seconds(1);
    Ok(fixture
        .replace("1786615200000000", &anchor.timestamp_micros().to_string())
        .replace("1786615200", &anchor.timestamp().to_string())
        .replace(
            "2026-08-13T10:00:01Z",
            &next_second.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        )
        .replace(
            "2026-08-13T10:00:00Z",
            &anchor.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ))
}

#[allow(clippy::too_many_lines)]
/// Reads the named environment variables once and seals their values for durable storage.
///
/// The CLI still takes variable *names* so a secret never lands in shell history, but it resolves
/// them here, at configuration time. The worker then reads only what `PostgreSQL` holds and never
/// depends on the collector process's environment at poll time.
fn seal_environment_credentials(entries: &[(&str, Option<&str>)]) -> Result<SealedCredentials> {
    let cipher = SecretCipher::from_env().context("load TALLY_SECRET_KEY")?;
    let mut bundle = BTreeMap::new();
    for (key, variable) in entries {
        let Some(variable) = variable else { continue };
        let value = env::var(variable).with_context(|| format!("read {variable}"))?;
        ensure!(
            !value.is_empty() && value.len() <= 64 * 1_024 && !value.contains('\0'),
            "{variable} must hold a non-empty value of at most 65536 bytes"
        );
        bundle.insert((*key).to_owned(), value);
    }
    let plaintext = serde_json::to_string(&bundle).context("encode credential bundle")?;
    let (nonce, ciphertext) = cipher
        .encrypt(&plaintext)
        .map_err(|error| anyhow!("seal connector credentials: {error}"))?;
    Ok(SealedCredentials { nonce, ciphertext })
}

async fn schedule_file(args: ScheduleFileArgs) -> Result<()> {
    ensure!(
        !args.adapter.is_native_cloud()
            && !args.adapter.is_native_cloud_network()
            && !args.adapter.is_native_enterprise(),
        "native cloud adapters must use their native schedule command"
    );
    ensure!(
        safe_environment_name(&args.source_path_env),
        "source path environment reference must be an uppercase machine name"
    );
    ensure!(
        (60..=86_400).contains(&args.interval_seconds),
        "schedule interval must be between 60 and 86400 seconds"
    );
    validate_cloud_reference_shape(
        args.adapter,
        args.account_id_env.as_deref(),
        args.scope_id_env.as_deref(),
        args.region.as_deref(),
    )
    .map_err(anyhow::Error::msg)?;
    let postgres = connect_postgres().await?;
    let identity = postgres
        .get_or_create_installation_identity()
        .await
        .context("load installation identity")?;
    let descriptor = args.adapter.descriptor();
    let connector_identity = if args.adapter.is_casb() {
        format!(
            "godel-tally:{}:{}:{}",
            identity.installation_id,
            descriptor.connector_type,
            args.account_id_env.as_deref().unwrap_or_default()
        )
    } else {
        format!(
            "godel-tally:{}:{}",
            identity.installation_id, descriptor.connector_type
        )
    };
    let connector_instance_id = args
        .connector_instance_id
        .unwrap_or_else(|| Uuid::new_v5(&Uuid::NAMESPACE_URL, connector_identity.as_bytes()));
    postgres
        .register_connector(identity.installation_id, connector_instance_id, &descriptor)
        .await
        .context("register scheduled connector")?;
    let job_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("godel-tally:connector-job:{connector_instance_id}").as_bytes(),
    );
    let now = Utc::now();
    let config_refs = file_schedule_job_config(&args);
    let credentials = seal_environment_credentials(&[
        ("source_path", Some(args.source_path_env.as_str())),
        ("account_id", args.account_id_env.as_deref()),
        ("scope_id", args.scope_id_env.as_deref()),
    ])?;
    postgres
        .put_connector_job(&ConnectorJobSpec {
            job_id,
            connector_instance_id,
            mode: ConnectorJobMode::Scheduled,
            status: if args.paused {
                ConnectorJobStatus::Paused
            } else {
                ConnectorJobStatus::Enabled
            },
            schedule_seconds: Some(args.interval_seconds),
            next_run_at: (!args.paused).then_some(now),
            config_refs,
            credentials: Some(credentials),
            updated_at: now,
        })
        .await
        .context("store connector schedule")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "job_id": job_id,
            "connector_instance_id": connector_instance_id,
            "connector_type": descriptor.connector_type,
            "status": if args.paused { "paused" } else { "enabled" },
            "interval_seconds": args.interval_seconds,
            "source_reference": args.source_path_env,
            "credentials_sealed": true,
            "plaintext_credentials_stored": false,
            "content_retained": false
        }))?
    );
    Ok(())
}

fn file_schedule_job_config(args: &ScheduleFileArgs) -> serde_json::Value {
    let mut config_refs = serde_json::json!({
        "kind": "file_env_v1",
        "adapter": args.adapter.key(),
        "source_lineage_id": "scheduled_file_env"
    });
    if let (Some(object), Some(region)) = (config_refs.as_object_mut(), args.region.as_ref()) {
        object.insert(
            "region".to_owned(),
            serde_json::Value::String(region.clone()),
        );
    }
    config_refs
}

#[allow(clippy::too_many_lines)] // Keeps schedule validation, sealing, and persistence together.
async fn schedule_cloud(args: ScheduleCloudArgs) -> Result<()> {
    ensure!(
        args.adapter.is_native_cloud(),
        "schedule-cloud requires a native managed-cloud API adapter"
    );
    ensure!(
        (60..=86_400).contains(&args.interval_seconds),
        "schedule interval must be between 60 and 86400 seconds"
    );
    validate_cloud_reference_shape(
        args.adapter,
        Some(&args.account_id_env),
        args.scope_id_env.as_deref(),
        Some(&args.region),
    )
    .map_err(anyhow::Error::msg)?;
    validate_cloud_auth_references(args.adapter, &args.credentials)?;
    ensure!(
        args.workspace_resource_env.is_none()
            || (matches!(
                args.adapter,
                VendorAdapter::AzureOpenaiApi | VendorAdapter::AzureAiFoundryApi
            ) && args
                .workspace_resource_env
                .as_deref()
                .is_some_and(safe_environment_name)),
        "only Azure managed AI accepts a workspace environment reference"
    );
    let postgres = connect_postgres().await?;
    let identity = postgres
        .get_or_create_installation_identity()
        .await
        .context("load installation identity")?;
    let descriptor = args.adapter.descriptor();
    let source_lineage_id = format!("{}:native", args.adapter.key());
    let connector_instance_id = args.connector_instance_id.unwrap_or_else(|| {
        Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!(
                "godel-tally:{}:{}:{}:{}:{}",
                identity.installation_id,
                descriptor.connector_type,
                args.account_id_env,
                args.scope_id_env.as_deref().unwrap_or("-"),
                args.region
            )
            .as_bytes(),
        )
    });
    postgres
        .register_connector(identity.installation_id, connector_instance_id, &descriptor)
        .await
        .context("register native managed-cloud connector")?;
    let job_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("godel-tally:connector-job:{connector_instance_id}").as_bytes(),
    );
    let now = Utc::now();
    let config_refs = serde_json::json!({
        "kind": "cloud_api_v1",
        "adapter": args.adapter.key(),
        "source_lineage_id": source_lineage_id,
        "region": args.region,
    });
    let credentials = seal_environment_credentials(&[
        ("account_id", Some(args.account_id_env.as_str())),
        ("scope_id", args.scope_id_env.as_deref()),
        ("workspace_resource", args.workspace_resource_env.as_deref()),
        (
            "aws_access_key_id",
            args.credentials.aws_access_key_id_env.as_deref(),
        ),
        (
            "aws_secret_access_key",
            args.credentials.aws_secret_access_key_env.as_deref(),
        ),
        (
            "aws_session_token",
            args.credentials.aws_session_token_env.as_deref(),
        ),
        (
            "azure_tenant_id",
            args.credentials.azure_tenant_id_env.as_deref(),
        ),
        (
            "azure_client_id",
            args.credentials.azure_client_id_env.as_deref(),
        ),
        (
            "azure_client_secret",
            args.credentials.azure_client_secret_env.as_deref(),
        ),
        (
            "gcp_service_account_json",
            args.credentials.gcp_service_account_json_env.as_deref(),
        ),
    ])?;
    postgres
        .put_connector_job(&ConnectorJobSpec {
            job_id,
            connector_instance_id,
            mode: ConnectorJobMode::Scheduled,
            status: if args.paused {
                ConnectorJobStatus::Paused
            } else {
                ConnectorJobStatus::Enabled
            },
            schedule_seconds: Some(args.interval_seconds),
            next_run_at: (!args.paused).then_some(now),
            config_refs,
            credentials: Some(credentials),
            updated_at: now,
        })
        .await
        .context("store native managed-cloud schedule")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "job_id": job_id,
            "connector_instance_id": connector_instance_id,
            "connector_type": descriptor.connector_type,
            "status": if args.paused { "paused" } else { "enabled" },
            "interval_seconds": args.interval_seconds,
            "account_reference": args.account_id_env,
            "scope_reference": args.scope_id_env,
            "region": args.region,
            "credential_chain": "provider_standard",
            "credentials_sealed": true,
            "plaintext_credentials_stored": false,
            "source_bytes_retained": false,
            "content_retained": false
        }))?
    );
    Ok(())
}

#[allow(clippy::too_many_lines)] // Keeps schedule validation, sealing, and persistence together.
async fn schedule_cloud_network(args: ScheduleCloudNetworkArgs) -> Result<()> {
    ensure!(
        args.adapter.is_native_cloud_network(),
        "schedule-cloud-network requires a native cloud-network API adapter"
    );
    ensure!(
        safe_environment_name(&args.account_id_env) && safe_environment_name(&args.network_id_env),
        "cloud-network references must be uppercase environment names"
    );
    let references = cloud_network_schedule_references(&args)?;
    validate_cloud_auth_references(args.adapter, &args.credentials)?;
    let region = references.region.as_str();
    let log_group_env = references.log_group_env.as_deref();
    let workspace_resource_env = references.workspace_resource_env.as_deref();
    ensure!(
        (300..=3_600).contains(&args.backfill_seconds),
        "initial lookback must be between 300 and 3600 seconds"
    );
    ensure!(
        (60..=86_400).contains(&args.interval_seconds),
        "schedule interval must be between 60 and 86400 seconds"
    );
    let postgres = connect_postgres().await?;
    let identity = postgres
        .get_or_create_installation_identity()
        .await
        .context("load installation identity")?;
    let descriptor = args.adapter.descriptor();
    let connector_instance_id = args.connector_instance_id.unwrap_or_else(|| {
        Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!(
                "godel-tally:{}:{}:{}:{}:{}:{}:{}",
                identity.installation_id,
                descriptor.connector_type,
                args.account_id_env,
                args.network_id_env,
                region,
                log_group_env.unwrap_or_default(),
                workspace_resource_env.unwrap_or_default()
            )
            .as_bytes(),
        )
    });
    postgres
        .register_connector(identity.installation_id, connector_instance_id, &descriptor)
        .await
        .context("register native cloud-network connector")?;
    let job_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("godel-tally:connector-job:{connector_instance_id}").as_bytes(),
    );
    let now = Utc::now();
    let config_refs = cloud_network_job_config(&args, &references);
    let credentials = seal_environment_credentials(&[
        ("account_id", Some(args.account_id_env.as_str())),
        ("network_id", Some(args.network_id_env.as_str())),
        ("log_group", log_group_env),
        ("workspace_resource", workspace_resource_env),
        (
            "aws_access_key_id",
            args.credentials.aws_access_key_id_env.as_deref(),
        ),
        (
            "aws_secret_access_key",
            args.credentials.aws_secret_access_key_env.as_deref(),
        ),
        (
            "aws_session_token",
            args.credentials.aws_session_token_env.as_deref(),
        ),
        (
            "azure_tenant_id",
            args.credentials.azure_tenant_id_env.as_deref(),
        ),
        (
            "azure_client_id",
            args.credentials.azure_client_id_env.as_deref(),
        ),
        (
            "azure_client_secret",
            args.credentials.azure_client_secret_env.as_deref(),
        ),
        (
            "gcp_service_account_json",
            args.credentials.gcp_service_account_json_env.as_deref(),
        ),
    ])?;
    postgres
        .put_connector_job(&ConnectorJobSpec {
            job_id,
            connector_instance_id,
            mode: ConnectorJobMode::Scheduled,
            status: if args.paused {
                ConnectorJobStatus::Paused
            } else {
                ConnectorJobStatus::Enabled
            },
            schedule_seconds: Some(args.interval_seconds),
            next_run_at: (!args.paused).then_some(now),
            config_refs,
            credentials: Some(credentials),
            updated_at: now,
        })
        .await
        .context("store native cloud-network schedule")?;
    print_cloud_network_schedule_receipt(
        &args,
        &descriptor,
        connector_instance_id,
        job_id,
        &references,
    )?;
    Ok(())
}

async fn schedule_casb(args: ScheduleCasbArgs) -> Result<()> {
    ensure!(
        safe_environment_name(&args.account_id_env) && safe_environment_name(&args.api_token_env),
        "CASB references must be uppercase environment names"
    );
    let descriptor = VendorAdapter::CloudflareCasbApi.descriptor();
    store_native_enterprise_schedule(
        descriptor,
        args.connector_instance_id,
        args.interval_seconds,
        args.paused,
        format!("{}:{}", args.account_id_env, args.api_token_env),
        serde_json::json!({
            "kind": "casb_api_v1",
            "source_lineage_id": "cloudflare_casb_api:native",
        }),
        seal_environment_credentials(&[
            ("account_id", Some(args.account_id_env.as_str())),
            ("api_token", Some(args.api_token_env.as_str())),
        ])?,
    )
    .await
}

async fn schedule_kubernetes(args: ScheduleKubernetesArgs) -> Result<()> {
    let explicit_api_url = args
        .api_url_env
        .as_deref()
        .unwrap_or("TALLY_KUBERNETES_API_URL");
    let explicit_bearer_token = args
        .bearer_token_env
        .as_deref()
        .unwrap_or("TALLY_KUBERNETES_BEARER_TOKEN");
    if !args.in_cluster {
        ensure!(
            safe_environment_name(explicit_api_url)
                && safe_environment_name(explicit_bearer_token)
                && args
                    .ca_file_env
                    .as_deref()
                    .is_none_or(safe_environment_name),
            "Kubernetes references must be uppercase environment names"
        );
    }
    let descriptor = VendorAdapter::KubernetesApiPull.descriptor();
    let config_refs = serde_json::json!({
        "kind": "kubernetes_api_v1",
        "source_lineage_id": "kubernetes_api:native",
        "auth_mode": if args.in_cluster { "in_cluster" } else { "explicit_bearer" },
    });
    let credentials = if args.in_cluster {
        seal_environment_credentials(&[])?
    } else {
        seal_environment_credentials(&[
            ("api_url", Some(explicit_api_url)),
            ("bearer_token", Some(explicit_bearer_token)),
            ("ca_file_path", args.ca_file_env.as_deref()),
        ])?
    };
    store_native_enterprise_schedule(
        descriptor,
        args.connector_instance_id,
        args.interval_seconds,
        args.paused,
        if args.in_cluster {
            "in_cluster_service_account".to_owned()
        } else {
            format!(
                "{explicit_api_url}:{explicit_bearer_token}:{}",
                args.ca_file_env.as_deref().unwrap_or_default()
            )
        },
        config_refs,
        credentials,
    )
    .await
}

async fn schedule_litellm(args: ScheduleLitellmArgs) -> Result<()> {
    ensure!(
        safe_environment_name(&args.base_url_env) && safe_environment_name(&args.api_key_env),
        "LiteLLM references must be uppercase environment names"
    );
    ensure!(
        valid_initial_backfill_seconds(args.backfill_seconds),
        "LiteLLM backfill must be between 60 and 604800 seconds"
    );
    ensure!(
        (1..=5_000).contains(&args.record_limit),
        "LiteLLM record limit must be between 1 and 5000"
    );
    let descriptor = VendorAdapter::LitellmApi.descriptor();
    store_native_enterprise_schedule(
        descriptor,
        args.connector_instance_id,
        args.interval_seconds,
        args.paused,
        format!("{}:{}", args.base_url_env, args.api_key_env),
        serde_json::json!({
            "kind": "litellm_api_v1",
            "source_lineage_id": "litellm_api:native",
            "backfill_seconds": args.backfill_seconds.to_string(),
            "record_limit": args.record_limit.to_string(),
        }),
        seal_environment_credentials(&[
            ("base_url", Some(args.base_url_env.as_str())),
            ("api_key", Some(args.api_key_env.as_str())),
        ])?,
    )
    .await
}

async fn schedule_zt_gateway(args: ScheduleZtGatewayArgs) -> Result<()> {
    ensure!(
        safe_environment_name(&args.account_id_env) && safe_environment_name(&args.api_token_env),
        "Zero Trust Gateway references must be uppercase environment names"
    );
    ensure!(
        (60..=604_800).contains(&args.window_seconds),
        "aggregate window must be between 60 and 604800 seconds"
    );
    let optional_s3 = match (
        args.endpoint_url.as_deref(),
        args.bucket.as_deref(),
        args.access_key_id_env.as_deref(),
        args.secret_access_key_env.as_deref(),
    ) {
        (None, None, None, None) if args.prefix.is_empty() => None,
        (
            Some(endpoint_url),
            Some(bucket),
            Some(access_key_id_env),
            Some(secret_access_key_env),
        ) => {
            ensure!(
                safe_environment_name(access_key_id_env)
                    && safe_environment_name(secret_access_key_env),
                "Gateway Logpush credential references must be uppercase environment names"
            );
            let endpoint = s3_logpush::s3_endpoint(endpoint_url)?;
            ensure!(
                (1..=128).contains(&args.object_limit),
                "object limit must be between 1 and 128"
            );
            ensure!(
                !bucket.is_empty()
                    && bucket.len() <= 255
                    && !bucket.contains('/')
                    && args.prefix.len() <= 1_024
                    && !bucket
                        .chars()
                        .chain(args.prefix.chars())
                        .any(char::is_control),
                "invalid Gateway Logpush bucket or prefix"
            );
            ensure!(safe_cloud_region(&args.region), "invalid signing region");
            Some((endpoint, bucket, access_key_id_env, secret_access_key_env))
        }
        _ => bail!("optional Gateway HTTP Logpush settings must be supplied together"),
    };
    let endpoint_url = optional_s3
        .as_ref()
        .map_or("", |(endpoint, _, _, _)| endpoint.as_str());
    let bucket = optional_s3.as_ref().map_or("", |(_, bucket, _, _)| *bucket);
    let descriptor = VendorAdapter::CloudflareZeroTrustGateway.descriptor();
    store_native_enterprise_schedule(
        descriptor,
        args.connector_instance_id,
        args.interval_seconds,
        args.paused,
        format!("{}:{}", args.account_id_env, args.api_token_env),
        serde_json::json!({
            "kind": "cloudflare_zero_trust_gateway_v1",
            "source_lineage_id": "cloudflare_zero_trust_gateway:graphql_optional_s3",
            "window_seconds": args.window_seconds.to_string(),
            "endpoint_url": endpoint_url,
            "bucket": bucket,
            "prefix": args.prefix,
            "region": args.region,
            "object_limit": args.object_limit.to_string(),
        }),
        seal_environment_credentials(&[
            ("account_id", Some(args.account_id_env.as_str())),
            ("api_token", Some(args.api_token_env.as_str())),
            ("access_key_id", args.access_key_id_env.as_deref()),
            ("secret_access_key", args.secret_access_key_env.as_deref()),
        ])?,
    )
    .await
}

async fn schedule_ai_gateway(args: ScheduleAiGatewayArgs) -> Result<()> {
    ensure!(
        safe_environment_name(&args.account_id_env) && safe_environment_name(&args.api_token_env),
        "AI Gateway references must be uppercase environment names"
    );
    ensure!(
        valid_initial_backfill_seconds(args.backfill_seconds),
        "initial lookback must be between 60 and 604800 seconds"
    );
    ensure!(
        (1..=5_000).contains(&args.record_limit),
        "record limit must be between 1 and 5000"
    );
    let descriptor = VendorAdapter::CloudflareAiGatewayApi.descriptor();
    store_native_enterprise_schedule(
        descriptor,
        args.connector_instance_id,
        args.interval_seconds,
        args.paused,
        format!("{}:{}", args.account_id_env, args.api_token_env),
        serde_json::json!({
            "kind": "ai_gateway_api_v1",
            "source_lineage_id": "cloudflare_ai_gateway_api:native",
            "backfill_seconds": args.backfill_seconds.to_string(),
            "record_limit": args.record_limit.to_string(),
        }),
        seal_environment_credentials(&[
            ("account_id", Some(args.account_id_env.as_str())),
            ("api_token", Some(args.api_token_env.as_str())),
        ])?,
    )
    .await
}

async fn schedule_crowdstrike_edr(args: ScheduleCrowdstrikeEdrArgs) -> Result<()> {
    ensure!(
        safe_environment_name(&args.client_id_env)
            && safe_environment_name(&args.client_secret_env),
        "CrowdStrike credential references must be uppercase environment names"
    );
    let cloud = crowdstrike::FalconCloud::parse(&args.cloud)
        .ok_or_else(|| anyhow!("Falcon cloud must be us-1, us-2, or eu-1"))?;
    ensure!(
        valid_initial_backfill_seconds(args.backfill_seconds),
        "EDR backfill must be between 60 and 604800 seconds"
    );
    ensure!(
        (1..=5_000).contains(&args.record_limit),
        "EDR record limit must be between 1 and 5000"
    );
    let descriptor = VendorAdapter::CrowdstrikeEdr.descriptor();
    store_native_enterprise_schedule(
        descriptor,
        args.connector_instance_id,
        args.interval_seconds,
        args.paused,
        format!(
            "{}:{}:{}",
            cloud.key(),
            args.client_id_env,
            args.client_secret_env
        ),
        serde_json::json!({
            "kind": "crowdstrike_edr_ngsiem_api_v1",
            "source_lineage_id": "crowdstrike_edr:ngsiem_dns",
            "cloud": cloud.key(),
            "backfill_seconds": args.backfill_seconds.to_string(),
            "record_limit": args.record_limit.to_string(),
        }),
        seal_environment_credentials(&[
            ("client_id", Some(args.client_id_env.as_str())),
            ("client_secret", Some(args.client_secret_env.as_str())),
        ])?,
    )
    .await
}

async fn store_native_enterprise_schedule(
    descriptor: ConnectorDescriptor,
    requested_connector_instance_id: Option<Uuid>,
    interval_seconds: u32,
    paused: bool,
    identity_suffix: String,
    config_refs: serde_json::Value,
    credentials: SealedCredentials,
) -> Result<()> {
    ensure!(
        (60..=86_400).contains(&interval_seconds),
        "schedule interval must be between 60 and 86400 seconds"
    );
    let postgres = connect_postgres().await?;
    let identity = postgres
        .get_or_create_installation_identity()
        .await
        .context("load installation identity")?;
    let connector_instance_id = requested_connector_instance_id.unwrap_or_else(|| {
        Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!(
                "godel-tally:{}:{}:{identity_suffix}",
                identity.installation_id, descriptor.connector_type
            )
            .as_bytes(),
        )
    });
    postgres
        .register_connector(identity.installation_id, connector_instance_id, &descriptor)
        .await
        .context("register native enterprise connector")?;
    let job_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("godel-tally:connector-job:{connector_instance_id}").as_bytes(),
    );
    let now = Utc::now();
    postgres
        .put_connector_job(&ConnectorJobSpec {
            job_id,
            connector_instance_id,
            mode: ConnectorJobMode::Scheduled,
            status: if paused {
                ConnectorJobStatus::Paused
            } else {
                ConnectorJobStatus::Enabled
            },
            schedule_seconds: Some(interval_seconds),
            next_run_at: (!paused).then_some(now),
            config_refs,
            credentials: Some(credentials),
            updated_at: now,
        })
        .await
        .context("store native enterprise schedule")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "job_id": job_id,
            "connector_instance_id": connector_instance_id,
            "connector_type": descriptor.connector_type,
            "status": if paused { "paused" } else { "enabled" },
            "interval_seconds": interval_seconds,
            "configuration_stored": "environment_references_only",
            "credential_stored": false,
            "raw_identifiers_stored": false,
            "source_bytes_retained": false,
            "content_retained": false
        }))?
    );
    Ok(())
}

fn cloud_network_job_config(
    args: &ScheduleCloudNetworkArgs,
    references: &CloudNetworkScheduleReferences,
) -> serde_json::Value {
    serde_json::json!({
        "kind": "cloud_network_api_v1",
        "adapter": args.adapter.key(),
        "source_lineage_id": format!("{}:native", args.adapter.key()),
        "region": references.region,
        "backfill_seconds": args.backfill_seconds.to_string()
    })
}

fn cloud_network_schedule_references(
    args: &ScheduleCloudNetworkArgs,
) -> Result<CloudNetworkScheduleReferences> {
    match args.adapter {
        VendorAdapter::AwsCloudFlowApi | VendorAdapter::AwsNetworkMappingApi => {
            aws_network_schedule_references(args)
        }
        VendorAdapter::AzureCloudFlowApi | VendorAdapter::AzureNetworkMappingApi => {
            azure_network_schedule_references(args)
        }
        VendorAdapter::GcpCloudFlowApi | VendorAdapter::GcpNetworkMappingApi => {
            gcp_network_schedule_references(args)
        }
        _ => bail!("native cloud-network adapter is unsupported"),
    }
}

fn aws_network_schedule_references(
    args: &ScheduleCloudNetworkArgs,
) -> Result<CloudNetworkScheduleReferences> {
    let region = required_network_region(args, "AWS")?;
    ensure!(
        args.workspace_resource_env.is_none(),
        "AWS network schedules do not accept an Azure workspace reference"
    );
    let log_group_env = match args.adapter {
        VendorAdapter::AwsCloudFlowApi => args
            .log_group_env
            .as_deref()
            .filter(|value| safe_environment_name(value))
            .map(str::to_owned)
            .ok_or_else(|| {
                anyhow!("AWS flow schedules require a log-group environment reference")
            })?,
        VendorAdapter::AwsNetworkMappingApi => {
            ensure!(
                args.log_group_env.is_none(),
                "AWS mapping schedules do not accept a log-group reference"
            );
            return Ok(CloudNetworkScheduleReferences {
                region,
                log_group_env: None,
                workspace_resource_env: None,
                credential_chain: "aws_standard",
            });
        }
        _ => bail!("AWS network adapter is unsupported"),
    };
    Ok(CloudNetworkScheduleReferences {
        region,
        log_group_env: Some(log_group_env),
        workspace_resource_env: None,
        credential_chain: "aws_standard",
    })
}

fn azure_network_schedule_references(
    args: &ScheduleCloudNetworkArgs,
) -> Result<CloudNetworkScheduleReferences> {
    let region = required_network_region(args, "Azure")?;
    ensure!(
        args.log_group_env.is_none(),
        "Azure network schedules do not accept an AWS log-group reference"
    );
    let workspace_resource_env = match args.adapter {
        VendorAdapter::AzureCloudFlowApi => Some(
            args.workspace_resource_env
                .as_deref()
                .filter(|value| safe_environment_name(value))
                .map(str::to_owned)
                .ok_or_else(|| {
                    anyhow!(
                        "Azure flow schedules require a workspace resource environment reference"
                    )
                })?,
        ),
        VendorAdapter::AzureNetworkMappingApi => {
            ensure!(
                args.workspace_resource_env.is_none(),
                "Azure mapping schedules do not accept a workspace reference"
            );
            None
        }
        _ => bail!("Azure network adapter is unsupported"),
    };
    Ok(CloudNetworkScheduleReferences {
        region,
        log_group_env: None,
        workspace_resource_env,
        credential_chain: "azure_standard",
    })
}

fn gcp_network_schedule_references(
    args: &ScheduleCloudNetworkArgs,
) -> Result<CloudNetworkScheduleReferences> {
    ensure!(
        args.region.as_deref().is_none_or(|value| value == "global"),
        "Google Cloud network schedules use the global API"
    );
    ensure!(
        args.log_group_env.is_none() && args.workspace_resource_env.is_none(),
        "Google Cloud network schedules do not accept provider-specific flow references"
    );
    Ok(CloudNetworkScheduleReferences {
        region: "global".to_owned(),
        log_group_env: None,
        workspace_resource_env: None,
        credential_chain: "google_application_default",
    })
}

fn required_network_region(args: &ScheduleCloudNetworkArgs, provider: &str) -> Result<String> {
    args.region
        .as_deref()
        .filter(|value| safe_cloud_region(value))
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("{provider} network schedules require a safe region"))
}

fn print_cloud_network_schedule_receipt(
    args: &ScheduleCloudNetworkArgs,
    descriptor: &ConnectorDescriptor,
    connector_instance_id: Uuid,
    job_id: Uuid,
    references: &CloudNetworkScheduleReferences,
) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "job_id": job_id,
            "connector_instance_id": connector_instance_id,
            "connector_type": descriptor.connector_type,
            "status": if args.paused { "paused" } else { "enabled" },
            "interval_seconds": args.interval_seconds,
            "account_reference": args.account_id_env,
            "network_reference": args.network_id_env,
            "region": references.region,
            "log_group_reference": references.log_group_env,
            "workspace_resource_reference": references.workspace_resource_env,
            "credential_chain": references.credential_chain,
            "credential_stored": false,
            "raw_identifiers_stored": false,
            "source_bytes_retained": false,
            "content_retained": false
        }))?
    );
    Ok(())
}

async fn schedule_nextdns_api(args: ScheduleNextDnsApiArgs) -> Result<()> {
    ensure!(
        safe_nextdns_profile_id(&args.profile_id),
        "NextDNS profile ID must be a bounded machine identifier"
    );
    ensure!(
        safe_environment_name(&args.api_key_env),
        "API key environment reference must be an uppercase machine name"
    );
    ensure!(
        valid_initial_backfill_seconds(args.backfill_seconds),
        "initial lookback must be between 60 and 604800 seconds"
    );
    ensure!(
        (1..=1_000).contains(&args.record_limit),
        "record limit must be between 1 and 1000"
    );
    ensure!(
        (60..=86_400).contains(&args.interval_seconds),
        "schedule interval must be between 60 and 86400 seconds"
    );
    let postgres = connect_postgres().await?;
    let identity = postgres
        .get_or_create_installation_identity()
        .await
        .context("load installation identity")?;
    let descriptor = nextdns_api_descriptor();
    let connector_instance_id = args.connector_instance_id.unwrap_or_else(|| {
        Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!(
                "godel-tally:{}:{}:{}",
                identity.installation_id, descriptor.connector_type, args.profile_id
            )
            .as_bytes(),
        )
    });
    postgres
        .register_connector(identity.installation_id, connector_instance_id, &descriptor)
        .await
        .context("register NextDNS API connector")?;
    let job_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("godel-tally:connector-job:{connector_instance_id}").as_bytes(),
    );
    let now = Utc::now();
    postgres
        .put_connector_job(&ConnectorJobSpec {
            job_id,
            connector_instance_id,
            mode: ConnectorJobMode::Scheduled,
            status: if args.paused {
                ConnectorJobStatus::Paused
            } else {
                ConnectorJobStatus::Enabled
            },
            schedule_seconds: Some(args.interval_seconds),
            next_run_at: (!args.paused).then_some(now),
            config_refs: serde_json::json!({
                "kind": "nextdns_api_v1",
                "profile_id": args.profile_id,
                "source_lineage_id": "nextdns_api",
                "backfill_seconds": args.backfill_seconds.to_string(),
                "record_limit": args.record_limit.to_string()
            }),
            credentials: Some(seal_environment_credentials(&[(
                "api_key",
                Some(args.api_key_env.as_str()),
            )])?),
            updated_at: now,
        })
        .await
        .context("store NextDNS API schedule")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "job_id": job_id,
            "connector_instance_id": connector_instance_id,
            "connector_type": descriptor.connector_type,
            "status": if args.paused { "paused" } else { "enabled" },
            "interval_seconds": args.interval_seconds,
            "initial_backfill_seconds": args.backfill_seconds,
            "initial_record_limit": args.record_limit,
            "profile_id": args.profile_id,
            "api_key_reference": args.api_key_env,
            "api_key_stored": false,
            "source_bytes_retained": false,
            "content_retained": false
        }))?
    );
    Ok(())
}

async fn receive(args: ReceiverArgs) -> Result<()> {
    ensure!(
        args.bind.ip().is_loopback() || args.allow_non_loopback,
        "receiver binds outside loopback only with --allow-non-loopback behind TLS termination"
    );
    ensure!(
        safe_environment_name(&args.authorization_env),
        "authorization environment reference must be an uppercase machine name"
    );
    ensure!(
        safe_lineage_id(&args.source_lineage_id),
        "source lineage must be a bounded machine label"
    );
    let authorization = env::var(&args.authorization_env)
        .context("load the receiver Authorization header from its environment reference")?;
    ensure!(
        (8..=1_024).contains(&authorization.len()) && HeaderValue::from_str(&authorization).is_ok(),
        "receiver Authorization header is invalid"
    );
    let authorization_sha256: [u8; 32] = Sha256::digest(authorization.as_bytes()).into();
    drop(authorization);

    let config = TallyConfig::from_env().context("load Tally configuration")?;
    let postgres = connect_postgres().await?;
    let identity = postgres
        .get_or_create_installation_identity()
        .await
        .context("load installation identity")?;
    let adapter = args.adapter.vendor();
    let descriptor = adapter.descriptor();
    let connector_instance_id = args.connector_instance_id.unwrap_or_else(|| {
        Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!(
                "godel-tally:{}:{}:{}",
                identity.installation_id, descriptor.connector_type, args.source_lineage_id
            )
            .as_bytes(),
        )
    });
    postgres
        .register_connector(identity.installation_id, connector_instance_id, &descriptor)
        .await
        .context("register push connector")?;
    let state = ReceiverState {
        client: collector_http_client()?,
        api_base: tally_api_base(&config)?,
        adapter,
        installation_id: identity.installation_id,
        connector_instance_id,
        source_lineage_id: args.source_lineage_id,
        pseudonymization_key: PseudonymizationKey::new(identity.pseudonymization_key())
            .context("load installation pseudonymization key")?,
        authorization_sha256,
    };
    let app = Router::new()
        .route("/healthz", get(receiver_health))
        .route("/ingest", post(receive_push))
        .layer(DefaultBodyLimit::max(MAX_IMPORT_BYTES))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .context("bind vendor push receiver")?;
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "status": "ready",
            "adapter": adapter.key(),
            "bind": args.bind,
            "ingest_path": "/ingest",
            "tls_terminated_here": false,
            "authorization_stored": false,
            "source_bytes_retained": false,
            "content_retained": false
        }))?
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .context("serve vendor push receiver")?;
    Ok(())
}

async fn receiver_health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ready",
        "accepts": "authenticated_metadata",
        "content_retained": false
    }))
}

async fn receive_push(
    State(state): State<ReceiverState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ReceiverFailure> {
    if !receiver_authorized(&headers, &state.authorization_sha256) {
        return Err(ReceiverFailure::Unauthorized);
    }
    let input = decode_push_payload(&headers, &body)?;
    if (state.adapter == VendorAdapter::CloudflareGateway && cloudflare_ownership_probe(&input))
        || empty_vendor_probe(&input)
    {
        drop(input);
        return Ok(StatusCode::NO_CONTENT);
    }
    let received_at = Utc::now();
    let provisional = state
        .adapter
        .normalize(
            &input,
            &VendorImportConfig {
                installation_id: state.installation_id,
                connector_instance_id: state.connector_instance_id,
                implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
                source_lineage_id: Some(state.source_lineage_id.clone()),
                received_at,
                checkpoint: Cursor("push-preview-v1".into()),
                pseudonymization_key: state.pseudonymization_key.clone(),
            },
        )
        .map_err(|_| ReceiverFailure::PayloadInvalid)?;
    let expected_canonical_digest = provisional.batch.receipt.canonical_digest.clone();
    drop(provisional);
    let checkpoint = format!("canonical:{expected_canonical_digest}");
    let receipt = commit_through_api(
        &state.client,
        &state.api_base,
        &ApiImportSource {
            adapter: state.adapter,
            connector_instance_id: state.connector_instance_id,
            source_lineage_id: &state.source_lineage_id,
            checkpoint: &checkpoint,
            input: &input,
            expected_canonical_digest: &expected_canonical_digest,
            cloud: None,
            casb_account_id: None,
        },
    )
    .await
    .map_err(|_| ReceiverFailure::TallyUnavailable)?;
    drop(input);
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "connector_instance_id": state.connector_instance_id,
            "run_id": receipt.run_id,
            "batch_id": receipt.batch_id,
            "status": receipt.status,
            "accepted": receipt.accepted,
            "deduplicated": receipt.deduplicated,
            "findings_updated": receipt.findings_updated,
            "content_retained": false
        }))
        .unwrap_or_else(|_| "{\"status\":\"receipt_unavailable\"}".to_owned())
    );
    Ok(StatusCode::NO_CONTENT)
}

fn receiver_authorized(headers: &HeaderMap, expected_sha256: &[u8; 32]) -> bool {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let provided: [u8; 32] = Sha256::digest(value.as_bytes()).into();
    bool::from(expected_sha256.ct_eq(&provided))
}

fn decode_push_payload(headers: &HeaderMap, body: &[u8]) -> Result<Vec<u8>, ReceiverFailure> {
    if body.is_empty() {
        return Err(ReceiverFailure::PayloadInvalid);
    }
    let content_encoding = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok());
    if content_encoding.is_some_and(|value| {
        !value.eq_ignore_ascii_case("gzip") && !value.eq_ignore_ascii_case("identity")
    }) {
        return Err(ReceiverFailure::EncodingUnsupported);
    }
    let gzip = content_encoding.is_some_and(|value| value.eq_ignore_ascii_case("gzip"))
        || body.starts_with(&[0x1f, 0x8b]);
    if !gzip {
        if body.len() > MAX_IMPORT_BYTES {
            return Err(ReceiverFailure::PayloadTooLarge);
        }
        return Ok(body.to_vec());
    }
    let decoder = GzDecoder::new(body);
    let mut output = Vec::new();
    decoder
        .take(u64::try_from(MAX_IMPORT_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut output)
        .map_err(|_| ReceiverFailure::PayloadInvalid)?;
    if output.len() > MAX_IMPORT_BYTES {
        return Err(ReceiverFailure::PayloadTooLarge);
    }
    Ok(output)
}

fn cloudflare_ownership_probe(input: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(input).is_ok_and(|value| {
        value.as_object().is_some_and(|object| {
            object.len() == 1
                && object.get("content").and_then(serde_json::Value::as_str) == Some("tests")
        })
    })
}

fn empty_vendor_probe(input: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(input).is_ok_and(|value| match value {
        serde_json::Value::Array(values) => values.is_empty(),
        serde_json::Value::Object(object) if object.is_empty() => true,
        serde_json::Value::Object(object) if object.len() == 1 => object
            .values()
            .next()
            .and_then(serde_json::Value::as_array)
            .is_some_and(Vec::is_empty),
        _ => false,
    })
}

async fn worker(args: WorkerArgs) -> Result<()> {
    let config = TallyConfig::from_env().context("load Tally configuration")?;
    let postgres = connect_postgres().await?;
    let cipher = SecretCipher::from_env().context("load TALLY_SECRET_KEY")?;
    let api_base = tally_api_base(&config)?;
    let client = collector_http_client()?;
    let lease_owner = Uuid::now_v7();
    loop {
        let claimed = run_due_window(
            &postgres,
            &cipher,
            &client,
            &api_base,
            lease_owner,
            args.lease_seconds,
        )
        .await?;
        if args.once {
            println!("connector worker completed one due window: {claimed} job(s)");
            return Ok(());
        }
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.context("listen for connector worker shutdown")?;
                println!("connector worker stopped; active leases remain recoverable after expiry");
                return Ok(());
            }
            () = tokio::time::sleep(Duration::from_secs(u64::from(args.poll_seconds))) => {}
        }
    }
}

async fn run_due_window(
    postgres: &PostgresStore,
    cipher: &SecretCipher,
    client: &reqwest::Client,
    api_base: &Url,
    lease_owner: Uuid,
    lease_seconds: u16,
) -> Result<usize> {
    let jobs = postgres
        .lease_due_connector_jobs(lease_owner, Utc::now(), lease_seconds, 4)
        .await
        .context("lease due connector jobs")?;
    let count = jobs.len();
    let mut running = tokio::task::JoinSet::new();
    for job in jobs {
        pull_support::report_due_age(&job, Utc::now());
        let postgres = postgres.clone();
        let cipher = cipher.clone();
        let client = client.clone();
        let api_base = api_base.clone();
        running.spawn(async move {
            let started_at = Utc::now();
            let execution = execute_scheduled_job(
                &postgres,
                &cipher,
                &client,
                &api_base,
                &job,
                started_at,
                lease_seconds,
            );
            tokio::pin!(execution);
            let heartbeat_period = Duration::from_secs(u64::from(lease_seconds) / 4);
            let mut heartbeat = tokio::time::interval_at(
                tokio::time::Instant::now() + heartbeat_period,
                heartbeat_period,
            );
            let result = loop {
                tokio::select! {
                    result = &mut execution => break result?,
                    _ = heartbeat.tick() => {
                        postgres.renew_connector_job_lease(
                            job.job_id, lease_owner, Utc::now(), lease_seconds,
                        ).await.context("renew connector lease while fetching provider data")?;
                    }
                }
            };
            let (outcome, error_code) = match result {
                Ok(outcome) => (outcome, None),
                Err(code) => (ConnectorRunStatus::Failed, Some(code.to_owned())),
            };
            let catch_up = if outcome == ConnectorRunStatus::Completed {
                pull_support::needs_catch_up(&postgres, &job, Utc::now()).await?
            } else {
                false
            };
            let view = postgres
                .complete_connector_job(&ConnectorJobCompletion {
                    job_id: job.job_id,
                    lease_owner,
                    outcome,
                    error_code: error_code.clone(),
                    finished_at: Utc::now(),
                    catch_up,
                })
                .await
                .context("complete connector schedule attempt")?;
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "job_id": job.job_id,
                    "connector_instance_id": job.connector_instance_id,
                    "outcome": outcome,
                    "error_code": error_code,
                    "next_run_at": view.next_run_at,
                    "content_retained": false
                }))?
            );
            Ok::<(), anyhow::Error>(())
        });
    }
    let mut first_error = None;
    while let Some(result) = running.join_next().await {
        if let Err(error) = result
            .context("connector task panicked")
            .and_then(|result| result)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(count)
}

async fn execute_scheduled_job(
    postgres: &PostgresStore,
    cipher: &SecretCipher,
    client: &reqwest::Client,
    api_base: &Url,
    job: &LeasedConnectorJob,
    started_at: DateTime<Utc>,
    lease_seconds: u16,
) -> Result<Result<ConnectorRunStatus, &'static str>> {
    let result = prepare_scheduled_job(postgres, cipher, client, job).await;
    let prepared = match result {
        Ok(value) => value,
        Err(code) => {
            record_job_failure(postgres, job, started_at, code).await?;
            return Ok(Err(code));
        }
    };
    match prepared {
        PreparedJob::Source {
            descriptor,
            adapter,
            input,
            checkpoint,
            source_lineage_id,
            expected_canonical_digest,
            cloud,
            casb_account_id,
        } => {
            postgres
                .renew_connector_job_lease(job.job_id, job.lease_owner, Utc::now(), lease_seconds)
                .await
                .context("renew connector job lease before admission")?;
            let result = commit_through_api(
                client,
                api_base,
                &ApiImportSource {
                    adapter,
                    connector_instance_id: job.connector_instance_id,
                    source_lineage_id: &source_lineage_id,
                    checkpoint: &checkpoint,
                    input: &input,
                    expected_canonical_digest: &expected_canonical_digest,
                    cloud: cloud.as_ref(),
                    casb_account_id: casb_account_id.as_deref(),
                },
            )
            .await;
            drop(input);
            let Ok(receipt) = result else {
                record_job_failure(postgres, job, started_at, "connector_commit_failed").await?;
                return Ok(Err("connector_commit_failed"));
            };
            if receipt.canonical_digest.len() != 64
                || receipt.content_retained
                || descriptor.connector_type != job.connector_type
            {
                record_job_failure(postgres, job, started_at, "connector_receipt_invalid").await?;
                return Ok(Err("connector_receipt_invalid"));
            }
            let Ok(status) = parse_run_status(&receipt.status) else {
                record_job_failure(postgres, job, started_at, "connector_receipt_invalid").await?;
                return Ok(Err("connector_receipt_invalid"));
            };
            Ok(Ok(status))
        }
        PreparedJob::EmptyPoll {
            descriptor,
            cursor_before,
            cursor_after,
        } => {
            record_empty_poll(
                postgres,
                job,
                started_at,
                descriptor,
                cursor_before,
                cursor_after,
            )
            .await?;
            Ok(Ok(ConnectorRunStatus::Completed))
        }
    }
}

async fn prepare_scheduled_job(
    postgres: &PostgresStore,
    cipher: &SecretCipher,
    client: &reqwest::Client,
    job: &LeasedConnectorJob,
) -> Result<PreparedJob, &'static str> {
    let kind = job
        .config_refs
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or("connector_config_invalid")?;
    // Unsealed once per run and dropped with this scope, so plaintext credentials exist only
    // while the lease is held.
    let credentials = JobCredentials::open(cipher, job)?;
    match kind {
        "file_env_v1" => prepare_scheduled_file(postgres, &credentials, job).await,
        "nextdns_api_v1" => prepare_nextdns_api(postgres, &credentials, client, job).await,
        "cloud_api_v1" => prepare_scheduled_cloud(postgres, &credentials, client, job).await,
        "cloud_network_api_v1" => {
            prepare_scheduled_cloud_network(postgres, &credentials, client, job).await
        }
        "casb_api_v1" => prepare_scheduled_casb(postgres, &credentials, client, job).await,
        "kubernetes_api_v1" => prepare_scheduled_kubernetes(postgres, &credentials, job).await,
        "managed_agents_v1" => managed_agents::prepare(postgres, &credentials, client, job).await,
        "litellm_api_v1" => prepare_scheduled_litellm(postgres, &credentials, client, job).await,
        "ai_gateway_api_v1" => {
            prepare_scheduled_ai_gateway(postgres, &credentials, client, job).await
        }
        "rapid7_edr_insightidr_api_v1" => {
            security_logs::prepare(
                postgres,
                &credentials,
                client,
                job,
                tally_connectors::SecurityLogSource::Rapid7Edr,
            )
            .await
        }
        "netskope_events_api_v1" => {
            security_logs::prepare(
                postgres,
                &credentials,
                client,
                job,
                tally_connectors::SecurityLogSource::Netskope,
            )
            .await
        }
        "crowdstrike_edr_ngsiem_api_v1" => {
            prepare_scheduled_crowdstrike_edr(postgres, &credentials, client, job).await
        }
        "microsoft_defender_graph_hunting_v1" => {
            prepare_scheduled_microsoft_defender(postgres, &credentials, client, job).await
        }
        "cato_networks_events_feed_v1" => {
            prepare_scheduled_cato_networks(postgres, &credentials, client, job).await
        }
        "cloudflare_zero_trust_gateway_v1" => {
            prepare_scheduled_cloudflare_zero_trust_gateway(postgres, &credentials, client, job)
                .await
        }
        "cloudflare_gateway_logpush_s3_v1" => {
            prepare_scheduled_cloudflare_gateway_logpush(postgres, &credentials, job).await
        }
        _ => Err("connector_config_invalid"),
    }
}

#[allow(clippy::too_many_lines)]
async fn prepare_scheduled_microsoft_defender(
    postgres: &PostgresStore,
    credentials: &JobCredentials,
    client: &reqwest::Client,
    job: &LeasedConnectorJob,
) -> Result<PreparedJob, &'static str> {
    let config: ScheduledMicrosoftDefenderConfig =
        serde_json::from_value(job.config_refs.clone()).map_err(|_| "connector_config_invalid")?;
    if config.kind != "microsoft_defender_graph_hunting_v1"
        || config.source_lineage_id != "microsoft_defender:device_network_events"
    {
        return Err("connector_config_invalid");
    }
    let backfill_seconds = config
        .backfill_seconds
        .parse::<u32>()
        .ok()
        .filter(|seconds| valid_initial_backfill_seconds(*seconds))
        .ok_or("connector_config_invalid")?;
    let record_limit = config
        .record_limit
        .parse::<usize>()
        .ok()
        .filter(|limit| (1..=5_000).contains(limit))
        .ok_or("connector_config_invalid")?;
    let descriptor = VendorAdapter::MicrosoftDefenderApi.descriptor();
    if descriptor.connector_type != job.connector_type {
        return Err("connector_type_mismatch");
    }
    let identity = postgres
        .get_or_create_installation_identity()
        .await
        .map_err(|_| "installation_identity_unavailable")?;
    if identity.installation_id != job.installation_id {
        return Err("installation_identity_mismatch");
    }
    let tenant_id = credentials
        .require("tenant_id")
        .map_err(|_| "microsoft_tenant_ref_unavailable")?;
    let client_id = credentials
        .require("client_id")
        .map_err(|_| "microsoft_client_ref_unavailable")?;
    let client_secret = credentials
        .require("client_secret")
        .map_err(|_| "secret_ref_unavailable")?;
    let cursor_before = postgres
        .connector_cursor(job.connector_instance_id)
        .await
        .map_err(|_| "connector_cursor_unavailable")?
        .unwrap_or_default();
    let previous = if cursor_before.is_empty() {
        None
    } else {
        Some(parse_microsoft_defender_cursor(&cursor_before).ok_or("connector_cursor_invalid")?)
    };
    let Some((window_start, mut window_end)) =
        next_event_window(previous, Utc::now(), backfill_seconds)?
    else {
        return Ok(PreparedJob::EmptyPoll {
            descriptor,
            cursor_after: cursor_before.clone(),
            cursor_before,
        });
    };
    let pull = loop {
        let pull = defender::pull_defender_network_events(
            tenant_id,
            client_id,
            client_secret,
            window_start,
            window_end,
            record_limit,
            client,
        )
        .await
        .map_err(|error| {
            eprintln!("microsoft_defender_pull_failed: {error:?}");
            "microsoft_defender_pull_failed"
        })?;
        if !pull.result_limit_reached {
            break pull;
        }
        window_end = shrink_event_window(window_start, window_end)
            .ok_or("microsoft_defender_record_limit_reached")?;
    };
    let checkpoint = encode_microsoft_defender_cursor(pull.window_end);
    let snapshot = pull.snapshot;
    if snapshot.record_count == 0 {
        drop(snapshot.data);
        return Ok(PreparedJob::EmptyPoll {
            descriptor,
            cursor_before,
            cursor_after: checkpoint,
        });
    }
    let outcome = VendorAdapter::MicrosoftDefenderApi
        .normalize(
            &snapshot.data,
            &VendorImportConfig {
                installation_id: job.installation_id,
                connector_instance_id: job.connector_instance_id,
                implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
                source_lineage_id: Some(config.source_lineage_id.clone()),
                received_at: Utc::now(),
                checkpoint: Cursor(checkpoint.clone()),
                pseudonymization_key: PseudonymizationKey::new(identity.pseudonymization_key())
                    .map_err(|_| "installation_key_invalid")?,
            },
        )
        .map_err(|error| {
            eprintln!("microsoft_defender_normalization_failed: {error:?}");
            "source_normalization_failed"
        })?;
    Ok(PreparedJob::Source {
        descriptor,
        adapter: VendorAdapter::MicrosoftDefenderApi,
        input: snapshot.data,
        checkpoint,
        source_lineage_id: config.source_lineage_id,
        expected_canonical_digest: outcome.batch.receipt.canonical_digest,
        cloud: None,
        casb_account_id: None,
    })
}

#[allow(clippy::too_many_lines)]
async fn prepare_scheduled_cato_networks(
    postgres: &PostgresStore,
    credentials: &JobCredentials,
    client: &reqwest::Client,
    job: &LeasedConnectorJob,
) -> Result<PreparedJob, &'static str> {
    let config: ScheduledCatoNetworksConfig =
        serde_json::from_value(job.config_refs.clone()).map_err(|_| "connector_config_invalid")?;
    if config.kind != "cato_networks_events_feed_v1"
        || config.source_lineage_id != "cato_networks:events_feed"
        || cato::cato_api_url(&config.api_hostname).is_err()
    {
        return Err("connector_config_invalid");
    }
    let backfill_seconds = config
        .backfill_seconds
        .parse::<u32>()
        .ok()
        .filter(|seconds| valid_initial_backfill_seconds(*seconds))
        .ok_or("connector_config_invalid")?;
    let record_limit = config
        .record_limit
        .parse::<usize>()
        .ok()
        .filter(|limit| (1..=3_000).contains(limit))
        .ok_or("connector_config_invalid")?;
    let descriptor = VendorAdapter::CatoNetworksApi.descriptor();
    if descriptor.connector_type != job.connector_type {
        return Err("connector_type_mismatch");
    }
    let identity = postgres
        .get_or_create_installation_identity()
        .await
        .map_err(|_| "installation_identity_unavailable")?;
    if identity.installation_id != job.installation_id {
        return Err("installation_identity_mismatch");
    }
    let account_id = credentials
        .require("account_id")
        .map_err(|_| "cato_account_ref_unavailable")?;
    let api_key = credentials
        .require("api_key")
        .map_err(|_| "secret_ref_unavailable")?;
    let cursor_before = postgres
        .connector_cursor(job.connector_instance_id)
        .await
        .map_err(|_| "connector_cursor_unavailable")?
        .unwrap_or_default();
    let previous = if cursor_before.is_empty() {
        None
    } else {
        Some(parse_cato_networks_cursor(&cursor_before).ok_or("connector_cursor_invalid")?)
    };
    let window_end = Utc::now();
    let window_start = previous
        .as_ref()
        .map_or_else(
            || window_end - chrono::Duration::seconds(i64::from(backfill_seconds)),
            |cursor| cursor.observed_through - chrono::Duration::minutes(5),
        )
        .max(window_end - chrono::Duration::seconds(i64::from(INITIAL_BACKFILL_MAX_SECONDS)));
    if window_start >= window_end {
        return Err("connector_cursor_invalid");
    }
    let pull = cato::pull_events_feed(
        &config.api_hostname,
        account_id,
        api_key,
        previous
            .as_ref()
            .and_then(|cursor| cursor.marker.as_deref()),
        window_start,
        window_end,
        record_limit,
        client,
    )
    .await
    .map_err(|error| {
        eprintln!("cato_networks_pull_failed: {error:?}");
        "cato_networks_pull_failed"
    })?;
    let marker_after = pull
        .marker_after
        .or_else(|| previous.as_ref().and_then(|cursor| cursor.marker.clone()));
    let checkpoint = encode_cato_networks_cursor(marker_after, pull.window_end, pull.backlog_hint)
        .map_err(|_| "connector_cursor_invalid")?;
    let snapshot = pull.snapshot;
    if snapshot.record_count == 0 {
        drop(snapshot.data);
        return Ok(PreparedJob::EmptyPoll {
            descriptor,
            cursor_before,
            cursor_after: checkpoint,
        });
    }
    let outcome = VendorAdapter::CatoNetworksApi
        .normalize(
            &snapshot.data,
            &VendorImportConfig {
                installation_id: job.installation_id,
                connector_instance_id: job.connector_instance_id,
                implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
                source_lineage_id: Some(config.source_lineage_id.clone()),
                received_at: Utc::now(),
                checkpoint: Cursor(checkpoint.clone()),
                pseudonymization_key: PseudonymizationKey::new(identity.pseudonymization_key())
                    .map_err(|_| "installation_key_invalid")?,
            },
        )
        .map_err(|error| {
            eprintln!("cato_networks_normalization_failed: {error:?}");
            "source_normalization_failed"
        })?;
    Ok(PreparedJob::Source {
        descriptor,
        adapter: VendorAdapter::CatoNetworksApi,
        input: snapshot.data,
        checkpoint,
        source_lineage_id: config.source_lineage_id,
        expected_canonical_digest: outcome.batch.receipt.canonical_digest,
        cloud: None,
        casb_account_id: None,
    })
}

#[allow(clippy::too_many_lines)]
async fn prepare_scheduled_crowdstrike_edr(
    postgres: &PostgresStore,
    credentials: &JobCredentials,
    client: &reqwest::Client,
    job: &LeasedConnectorJob,
) -> Result<PreparedJob, &'static str> {
    let config: ScheduledCrowdstrikeEdrConfig =
        serde_json::from_value(job.config_refs.clone()).map_err(|_| "connector_config_invalid")?;
    if config.kind != "crowdstrike_edr_ngsiem_api_v1"
        || config.source_lineage_id != "crowdstrike_edr:ngsiem_dns"
    {
        return Err("connector_config_invalid");
    }
    let cloud = crowdstrike::FalconCloud::parse(&config.cloud).ok_or("connector_config_invalid")?;
    let backfill_seconds = config
        .backfill_seconds
        .parse::<u32>()
        .ok()
        .filter(|seconds| valid_initial_backfill_seconds(*seconds))
        .ok_or("connector_config_invalid")?;
    let record_limit = config
        .record_limit
        .parse::<usize>()
        .ok()
        .filter(|limit| (1..=5_000).contains(limit))
        .ok_or("connector_config_invalid")?;
    let descriptor = VendorAdapter::CrowdstrikeEdr.descriptor();
    if descriptor.connector_type != job.connector_type {
        return Err("connector_type_mismatch");
    }
    let identity = postgres
        .get_or_create_installation_identity()
        .await
        .map_err(|_| "installation_identity_unavailable")?;
    if identity.installation_id != job.installation_id {
        return Err("installation_identity_mismatch");
    }
    let client_id = credentials
        .require("client_id")
        .map_err(|_| "crowdstrike_client_id_unavailable")?;
    let client_secret = credentials
        .require("client_secret")
        .map_err(|_| "secret_ref_unavailable")?;
    let cursor_before = postgres
        .connector_cursor(job.connector_instance_id)
        .await
        .map_err(|_| "connector_cursor_unavailable")?
        .unwrap_or_default();
    let previous = if cursor_before.is_empty() {
        None
    } else {
        Some(parse_crowdstrike_edr_cursor(&cursor_before).ok_or("connector_cursor_invalid")?)
    };
    let Some((window_start, mut window_end)) =
        next_event_window(previous, Utc::now(), backfill_seconds)?
    else {
        return Ok(PreparedJob::EmptyPoll {
            descriptor,
            cursor_after: cursor_before.clone(),
            cursor_before,
        });
    };
    let pull = loop {
        let pull = crowdstrike::pull_edr_dns(
            cloud,
            client_id,
            client_secret,
            window_start,
            window_end,
            record_limit,
            client,
        )
        .await
        .map_err(|error| {
            eprintln!("crowdstrike_edr_pull_failed: {error:?}");
            "crowdstrike_edr_pull_failed"
        })?;
        if !pull.result_limit_reached {
            break pull;
        }
        window_end = shrink_event_window(window_start, window_end)
            .ok_or("crowdstrike_edr_record_limit_reached")?;
    };
    let checkpoint = encode_crowdstrike_edr_cursor(pull.window_end);
    let snapshot = pull.snapshot;
    if snapshot.record_count == 0 {
        drop(snapshot.data);
        return Ok(PreparedJob::EmptyPoll {
            descriptor,
            cursor_before,
            cursor_after: checkpoint,
        });
    }
    let outcome = VendorAdapter::CrowdstrikeEdr
        .normalize(
            &snapshot.data,
            &VendorImportConfig {
                installation_id: job.installation_id,
                connector_instance_id: job.connector_instance_id,
                implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
                source_lineage_id: Some(config.source_lineage_id.clone()),
                received_at: Utc::now(),
                checkpoint: Cursor(checkpoint.clone()),
                pseudonymization_key: PseudonymizationKey::new(identity.pseudonymization_key())
                    .map_err(|_| "installation_key_invalid")?,
            },
        )
        .map_err(|error| {
            eprintln!("crowdstrike_edr_normalization_failed: {error:?}");
            "source_normalization_failed"
        })?;
    Ok(PreparedJob::Source {
        descriptor,
        adapter: VendorAdapter::CrowdstrikeEdr,
        input: snapshot.data,
        checkpoint,
        source_lineage_id: config.source_lineage_id,
        expected_canonical_digest: outcome.batch.receipt.canonical_digest,
        cloud: None,
        casb_account_id: None,
    })
}

async fn prepare_scheduled_cloudflare_gateway_logpush(
    postgres: &PostgresStore,
    credentials: &JobCredentials,
    job: &LeasedConnectorJob,
) -> Result<PreparedJob, &'static str> {
    let config: ScheduledCloudflareGatewayLogpushS3Config =
        serde_json::from_value(job.config_refs.clone()).map_err(|_| "connector_config_invalid")?;
    let object_limit = config
        .object_limit
        .parse::<usize>()
        .ok()
        .filter(|limit| (1..=128).contains(limit))
        .ok_or("connector_config_invalid")?;
    if config.kind != "cloudflare_gateway_logpush_s3_v1"
        || !safe_lineage_id(&config.source_lineage_id)
        || s3_logpush::s3_endpoint(&config.endpoint_url).is_err()
        || config.bucket.is_empty()
        || config.bucket.len() > 255
        || config.bucket.contains('/')
        || config.prefix.len() > 1_024
        || config
            .bucket
            .chars()
            .chain(config.prefix.chars())
            .any(char::is_control)
        || !safe_cloud_region(&config.region)
    {
        return Err("connector_config_invalid");
    }
    let descriptor = VendorAdapter::CloudflareGatewayLogpushS3.descriptor();
    if descriptor.connector_type != job.connector_type {
        return Err("connector_type_mismatch");
    }
    let identity = postgres
        .get_or_create_installation_identity()
        .await
        .map_err(|_| "installation_identity_unavailable")?;
    if identity.installation_id != job.installation_id {
        return Err("installation_identity_mismatch");
    }
    let access_key_id = credentials
        .require("access_key_id")
        .map_err(|_| "secret_ref_unavailable")?;
    let secret_access_key = credentials
        .require("secret_access_key")
        .map_err(|_| "secret_ref_unavailable")?;
    let cursor_before = postgres
        .connector_cursor(job.connector_instance_id)
        .await
        .map_err(|_| "connector_cursor_unavailable")?
        .unwrap_or_default();
    let pull = s3_logpush::pull_gateway_http(&s3_logpush::S3LogpushPull {
        endpoint_url: &config.endpoint_url,
        bucket: &config.bucket,
        prefix: &config.prefix,
        region: &config.region,
        access_key_id,
        secret_access_key,
        object_limit,
        cursor_before: &cursor_before,
    })
    .await
    .map_err(|error| {
        eprintln!("cloudflare_gateway_logpush_pull_failed: {error:?}");
        "cloudflare_gateway_logpush_pull_failed"
    })?;
    let checkpoint = pull.cursor_after;
    let snapshot = pull.snapshot;
    if snapshot.record_count == 0 {
        drop(snapshot.data);
        return Ok(PreparedJob::EmptyPoll {
            descriptor,
            cursor_before,
            cursor_after: checkpoint,
        });
    }
    let outcome = VendorAdapter::CloudflareGatewayLogpushS3
        .normalize(
            &snapshot.data,
            &VendorImportConfig {
                installation_id: job.installation_id,
                connector_instance_id: job.connector_instance_id,
                implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
                source_lineage_id: Some(config.source_lineage_id.clone()),
                received_at: Utc::now(),
                checkpoint: Cursor(checkpoint.clone()),
                pseudonymization_key: PseudonymizationKey::new(identity.pseudonymization_key())
                    .map_err(|_| "installation_key_invalid")?,
            },
        )
        .map_err(|_| "source_normalization_failed")?;
    Ok(PreparedJob::Source {
        descriptor,
        adapter: VendorAdapter::CloudflareGatewayLogpushS3,
        input: snapshot.data,
        checkpoint,
        source_lineage_id: config.source_lineage_id,
        expected_canonical_digest: outcome.batch.receipt.canonical_digest,
        cloud: None,
        casb_account_id: None,
    })
}

fn cloudflare_gateway_s3_cursor(cursor: &str) -> Result<&str, &'static str> {
    if cursor.is_empty() {
        return Ok("");
    }
    cursor
        .strip_prefix("cfzt1:")
        .ok_or("connector_cursor_invalid")
}

const fn cloudflare_zero_trust_normalization_error(error: &VendorImportError) -> &'static str {
    match error {
        VendorImportError::NoRecords => "source_normalization_no_records",
        VendorImportError::NoAcceptedRecords => "source_normalization_no_accepted_records",
        VendorImportError::ImportTooLarge(_) => "source_normalization_import_too_large",
        VendorImportError::RecordTooLarge { .. } => "source_normalization_record_too_large",
        VendorImportError::MalformedRecord { .. } => "source_normalization_malformed_record",
        VendorImportError::InvalidTimestamp { .. } => "source_normalization_invalid_timestamp",
        VendorImportError::InvalidField { .. } => "source_normalization_invalid_field",
        VendorImportError::Serialization => "source_normalization_serialization_failed",
        VendorImportError::InvalidPseudonymizationKey | VendorImportError::Admission(_) => {
            "source_normalization_admission_failed"
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn prepare_scheduled_cloudflare_zero_trust_gateway(
    postgres: &PostgresStore,
    credentials: &JobCredentials,
    client: &reqwest::Client,
    job: &LeasedConnectorJob,
) -> Result<PreparedJob, &'static str> {
    let config: ScheduledCloudflareZeroTrustGatewayConfig =
        serde_json::from_value(job.config_refs.clone()).map_err(|_| "connector_config_invalid")?;
    let window_seconds = config
        .window_seconds
        .parse::<i64>()
        .ok()
        .filter(|seconds| (60..=604_800).contains(seconds))
        .ok_or("connector_config_invalid")?;
    let object_limit = config
        .object_limit
        .parse::<usize>()
        .ok()
        .filter(|limit| (1..=128).contains(limit))
        .ok_or("connector_config_invalid")?;
    let s3_enabled = !config.endpoint_url.is_empty();
    let s3_config_valid = if s3_enabled {
        s3_logpush::s3_endpoint(&config.endpoint_url).is_ok()
            && !config.bucket.is_empty()
            && config.bucket.len() <= 255
            && !config.bucket.contains('/')
            && config.prefix.len() <= 1_024
            && !config
                .bucket
                .chars()
                .chain(config.prefix.chars())
                .any(char::is_control)
            && safe_cloud_region(&config.region)
    } else {
        config.bucket.is_empty() && config.prefix.is_empty()
    };
    if config.kind != "cloudflare_zero_trust_gateway_v1"
        || config.source_lineage_id != "cloudflare_zero_trust_gateway:graphql_optional_s3"
        || !s3_config_valid
    {
        return Err("connector_config_invalid");
    }
    let descriptor = VendorAdapter::CloudflareZeroTrustGateway.descriptor();
    if descriptor.connector_type != job.connector_type {
        return Err("connector_type_mismatch");
    }
    let identity = postgres
        .get_or_create_installation_identity()
        .await
        .map_err(|_| "installation_identity_unavailable")?;
    if identity.installation_id != job.installation_id {
        return Err("installation_identity_mismatch");
    }
    let account_id = credentials
        .require("account_id")
        .map_err(|_| "gateway_account_ref_unavailable")?;
    let api_token = credentials
        .require("api_token")
        .map_err(|_| "secret_ref_unavailable")?;
    let cursor_before = postgres
        .connector_cursor(job.connector_instance_id)
        .await
        .map_err(|_| "connector_cursor_unavailable")?
        .unwrap_or_default();
    let s3_cursor_before = cloudflare_gateway_s3_cursor(&cursor_before)?;
    let dns_snapshot = cloudflare::pull_zt_gateway(account_id, api_token, window_seconds, client)
        .await
        .map_err(|error| {
            eprintln!("cloudflare_gateway_dns_pull_failed: {error:?}");
            "cloudflare_gateway_dns_pull_failed"
        })?;
    let mut input = dns_snapshot.data;
    let mut record_count = dns_snapshot.record_count;
    let mut s3_cursor_after = String::new();
    if s3_enabled {
        let access_key_id = credentials
            .require("access_key_id")
            .map_err(|_| "secret_ref_unavailable")?;
        let secret_access_key = credentials
            .require("secret_access_key")
            .map_err(|_| "secret_ref_unavailable")?;
        let pull = s3_logpush::pull_gateway_http(&s3_logpush::S3LogpushPull {
            endpoint_url: &config.endpoint_url,
            bucket: &config.bucket,
            prefix: &config.prefix,
            region: &config.region,
            access_key_id,
            secret_access_key,
            object_limit,
            cursor_before: s3_cursor_before,
        })
        .await
        .map_err(|error| {
            eprintln!("cloudflare_gateway_logpush_pull_failed: {error:?}");
            "cloudflare_gateway_logpush_pull_failed"
        })?;
        let separator = usize::from(!input.is_empty() && !input.ends_with(b"\n"));
        if input
            .len()
            .saturating_add(separator)
            .saturating_add(pull.snapshot.data.len())
            > MAX_IMPORT_BYTES
        {
            return Err("source_projection_too_large");
        }
        if separator == 1 {
            input.push(b'\n');
        }
        input.extend_from_slice(&pull.snapshot.data);
        record_count = record_count.saturating_add(pull.snapshot.record_count);
        s3_cursor_after = pull.cursor_after;
    }
    let checkpoint = format!("cfzt1:{s3_cursor_after}");
    if record_count == 0 {
        drop(input);
        return Ok(PreparedJob::EmptyPoll {
            descriptor,
            cursor_before,
            cursor_after: checkpoint,
        });
    }
    let outcome = VendorAdapter::CloudflareZeroTrustGateway
        .normalize(
            &input,
            &VendorImportConfig {
                installation_id: job.installation_id,
                connector_instance_id: job.connector_instance_id,
                implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
                source_lineage_id: Some(config.source_lineage_id.clone()),
                received_at: Utc::now(),
                checkpoint: Cursor(checkpoint.clone()),
                pseudonymization_key: PseudonymizationKey::new(identity.pseudonymization_key())
                    .map_err(|_| "installation_key_invalid")?,
            },
        )
        .map_err(|error| {
            eprintln!("cloudflare_zero_trust_normalization_failed: {error:?}");
            error.downcast_ref::<VendorImportError>().map_or(
                "source_normalization_failed",
                cloudflare_zero_trust_normalization_error,
            )
        })?;
    Ok(PreparedJob::Source {
        descriptor,
        adapter: VendorAdapter::CloudflareZeroTrustGateway,
        input,
        checkpoint,
        source_lineage_id: config.source_lineage_id,
        expected_canonical_digest: outcome.batch.receipt.canonical_digest,
        cloud: None,
        casb_account_id: None,
    })
}

#[allow(clippy::too_many_lines)]
async fn prepare_scheduled_ai_gateway(
    postgres: &PostgresStore,
    credentials: &JobCredentials,
    client: &reqwest::Client,
    job: &LeasedConnectorJob,
) -> Result<PreparedJob, &'static str> {
    let config: ScheduledAiGatewayApiConfig =
        serde_json::from_value(job.config_refs.clone()).map_err(|_| "connector_config_invalid")?;
    if config.kind != "ai_gateway_api_v1" || !safe_lineage_id(&config.source_lineage_id) {
        return Err("connector_config_invalid");
    }
    let backfill_seconds = config
        .backfill_seconds
        .parse::<u32>()
        .ok()
        .filter(|seconds| valid_initial_backfill_seconds(*seconds))
        .ok_or("connector_config_invalid")?;
    let record_limit = config
        .record_limit
        .parse::<usize>()
        .ok()
        .filter(|limit| (1..=5_000).contains(limit))
        .ok_or("connector_config_invalid")?;
    let descriptor = VendorAdapter::CloudflareAiGatewayApi.descriptor();
    if descriptor.connector_type != job.connector_type {
        return Err("connector_type_mismatch");
    }
    let identity = postgres
        .get_or_create_installation_identity()
        .await
        .map_err(|_| "installation_identity_unavailable")?;
    if identity.installation_id != job.installation_id {
        return Err("installation_identity_mismatch");
    }
    let account_id = credentials
        .require("account_id")
        .map_err(|_| "ai_gateway_account_ref_unavailable")?;
    let api_token = credentials
        .require("api_token")
        .map_err(|_| "secret_ref_unavailable")?;
    let cursor_before = postgres
        .connector_cursor(job.connector_instance_id)
        .await
        .map_err(|_| "connector_cursor_unavailable")?
        .unwrap_or_default();
    // Schedules created before the timestamp cursor used a content digest. Treat that legacy
    // watermark as a bounded first poll so upgrades do not strand existing connectors.
    let previous = if cursor_before.is_empty() || cursor_before.starts_with("ai-gateway-api:") {
        None
    } else {
        Some(parse_ai_gateway_pull_cursor(&cursor_before).ok_or("connector_cursor_invalid")?)
    };
    let Some((window_start, mut window_end)) =
        next_event_window(previous, Utc::now(), backfill_seconds)?
    else {
        return Ok(PreparedJob::EmptyPoll {
            descriptor,
            cursor_after: cursor_before.clone(),
            cursor_before,
        });
    };
    let pull = loop {
        // Cloudflare supports gt/lt but not inclusive bounds here. Re-read the preceding
        // second so logs exactly on the durable timestamp boundary remain discoverable.
        let pull = cloudflare::pull_ai_gateway(
            account_id,
            api_token,
            window_start - chrono::Duration::seconds(1),
            window_end,
            record_limit,
            client,
        )
        .await
        .map_err(|e| {
            eprintln!("ai_gateway_inventory_pull_failed: {e:?}");
            "ai_gateway_inventory_pull_failed"
        })?;
        if !pull.usage_truncated {
            break pull;
        }
        window_end = shrink_event_window(window_start, window_end)
            .ok_or("ai_gateway_record_limit_exceeded")?;
    };
    let checkpoint = encode_ai_gateway_pull_cursor(pull.window_end);
    let snapshot = pull.snapshot;
    if snapshot.record_count == 0 {
        drop(snapshot.data);
        return Ok(PreparedJob::EmptyPoll {
            descriptor,
            cursor_before,
            cursor_after: checkpoint,
        });
    }
    let outcome = VendorAdapter::CloudflareAiGatewayApi
        .normalize(
            &snapshot.data,
            &VendorImportConfig {
                installation_id: job.installation_id,
                connector_instance_id: job.connector_instance_id,
                implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
                source_lineage_id: Some(config.source_lineage_id.clone()),
                received_at: Utc::now(),
                checkpoint: Cursor(checkpoint.clone()),
                pseudonymization_key: PseudonymizationKey::new(identity.pseudonymization_key())
                    .map_err(|_| "installation_key_invalid")?,
            },
        )
        .map_err(|_| "source_normalization_failed")?;
    Ok(PreparedJob::Source {
        descriptor,
        adapter: VendorAdapter::CloudflareAiGatewayApi,
        input: snapshot.data,
        checkpoint,
        source_lineage_id: config.source_lineage_id,
        expected_canonical_digest: outcome.batch.receipt.canonical_digest,
        cloud: None,
        casb_account_id: None,
    })
}

#[allow(clippy::too_many_lines)]
async fn prepare_scheduled_litellm(
    postgres: &PostgresStore,
    credentials: &JobCredentials,
    client: &reqwest::Client,
    job: &LeasedConnectorJob,
) -> Result<PreparedJob, &'static str> {
    let config: ScheduledLitellmApiConfig =
        serde_json::from_value(job.config_refs.clone()).map_err(|_| "connector_config_invalid")?;
    if config.kind != "litellm_api_v1" || !safe_lineage_id(&config.source_lineage_id) {
        return Err("connector_config_invalid");
    }
    let descriptor = VendorAdapter::LitellmApi.descriptor();
    if descriptor.connector_type != job.connector_type {
        return Err("connector_type_mismatch");
    }
    let identity = postgres
        .get_or_create_installation_identity()
        .await
        .map_err(|_| "installation_identity_unavailable")?;
    if identity.installation_id != job.installation_id {
        return Err("installation_identity_mismatch");
    }
    let base_url = credentials
        .require("base_url")
        .map_err(|_| "litellm_base_ref_unavailable")?;
    let api_base = litellm::litellm_api_base(base_url).map_err(|_| "litellm_base_ref_invalid")?;
    let api_key = credentials
        .require("api_key")
        .map_err(|_| "secret_ref_unavailable")?;
    let backfill_seconds = config
        .backfill_seconds
        .parse::<u32>()
        .ok()
        .filter(|value| valid_initial_backfill_seconds(*value))
        .ok_or("connector_config_invalid")?;
    let record_limit = config
        .record_limit
        .parse::<usize>()
        .ok()
        .filter(|value| (1..=5_000).contains(value))
        .ok_or("connector_config_invalid")?;
    let cursor_before = postgres
        .connector_cursor(job.connector_instance_id)
        .await
        .map_err(|_| "connector_cursor_unavailable")?
        .unwrap_or_default();
    let previous = if cursor_before.is_empty() || cursor_before.starts_with("litellm-api:") {
        None
    } else {
        Some(parse_litellm_pull_cursor(&cursor_before).ok_or("connector_cursor_invalid")?)
    };
    let Some((window_start, mut window_end)) =
        next_event_window(previous, Utc::now(), backfill_seconds)?
    else {
        return Ok(PreparedJob::EmptyPoll {
            descriptor,
            cursor_after: cursor_before.clone(),
            cursor_before,
        });
    };
    let pull = loop {
        let pull = litellm::pull_litellm(
            &api_base,
            api_key,
            window_start,
            window_end,
            record_limit,
            client,
        )
        .await
        .map_err(|error| {
            eprintln!("litellm_gateway_pull_failed: {error:?}");
            "litellm_gateway_pull_failed"
        })?;
        if !pull.usage_truncated {
            break pull;
        }
        window_end =
            shrink_event_window(window_start, window_end).ok_or("litellm_record_limit_exceeded")?;
    };
    let checkpoint = encode_litellm_pull_cursor(pull.window_end);
    let snapshot = pull.snapshot;
    if snapshot.record_count == 0 {
        drop(snapshot.data);
        return Ok(PreparedJob::EmptyPoll {
            descriptor,
            cursor_before,
            cursor_after: checkpoint,
        });
    }
    let outcome = VendorAdapter::LitellmApi
        .normalize(
            &snapshot.data,
            &VendorImportConfig {
                installation_id: job.installation_id,
                connector_instance_id: job.connector_instance_id,
                implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
                source_lineage_id: Some(config.source_lineage_id.clone()),
                received_at: Utc::now(),
                checkpoint: Cursor(checkpoint.clone()),
                pseudonymization_key: PseudonymizationKey::new(identity.pseudonymization_key())
                    .map_err(|_| "installation_key_invalid")?,
            },
        )
        .map_err(|_| "source_normalization_failed")?;
    Ok(PreparedJob::Source {
        descriptor,
        adapter: VendorAdapter::LitellmApi,
        input: snapshot.data,
        checkpoint,
        source_lineage_id: config.source_lineage_id,
        expected_canonical_digest: outcome.batch.receipt.canonical_digest,
        cloud: None,
        casb_account_id: None,
    })
}

async fn prepare_scheduled_casb(
    postgres: &PostgresStore,
    credentials: &JobCredentials,
    client: &reqwest::Client,
    job: &LeasedConnectorJob,
) -> Result<PreparedJob, &'static str> {
    let config: ScheduledCasbApiConfig =
        serde_json::from_value(job.config_refs.clone()).map_err(|_| "connector_config_invalid")?;
    if config.kind != "casb_api_v1" || !safe_lineage_id(&config.source_lineage_id) {
        return Err("connector_config_invalid");
    }
    let descriptor = VendorAdapter::CloudflareCasbApi.descriptor();
    if descriptor.connector_type != job.connector_type {
        return Err("connector_type_mismatch");
    }
    let identity = postgres
        .get_or_create_installation_identity()
        .await
        .map_err(|_| "installation_identity_unavailable")?;
    if identity.installation_id != job.installation_id {
        return Err("installation_identity_mismatch");
    }
    let account_id = credentials
        .require("account_id")
        .map_err(|_| "casb_account_ref_unavailable")?;
    if !safe_raw_cloud_identifier(account_id) {
        return Err("casb_account_ref_invalid");
    }
    let api_token = credentials
        .require("api_token")
        .map_err(|_| "secret_ref_unavailable")?;
    let snapshot = cloudflare::pull_casb(account_id, api_token, client)
        .await
        .map_err(|_| "casb_inventory_pull_failed")?;
    let cursor_before = postgres
        .connector_cursor(job.connector_instance_id)
        .await
        .map_err(|_| "connector_cursor_unavailable")?
        .unwrap_or_default();
    let checkpoint = format!("casb-api:{}", hex::encode(Sha256::digest(&snapshot.data)));
    if snapshot.record_count == 0 {
        drop(snapshot.data);
        return Ok(PreparedJob::EmptyPoll {
            descriptor,
            cursor_before,
            cursor_after: checkpoint,
        });
    }
    let outcome = VendorAdapter::CloudflareCasbApi
        .normalize_casb(
            &snapshot.data,
            account_id,
            &VendorImportConfig {
                installation_id: job.installation_id,
                connector_instance_id: job.connector_instance_id,
                implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
                source_lineage_id: Some(config.source_lineage_id.clone()),
                received_at: Utc::now(),
                checkpoint: Cursor(checkpoint.clone()),
                pseudonymization_key: PseudonymizationKey::new(identity.pseudonymization_key())
                    .map_err(|_| "installation_key_invalid")?,
            },
        )
        .map_err(|_| "source_normalization_failed")?;
    Ok(PreparedJob::Source {
        descriptor,
        adapter: VendorAdapter::CloudflareCasbApi,
        input: snapshot.data,
        checkpoint,
        source_lineage_id: config.source_lineage_id,
        expected_canonical_digest: outcome.batch.receipt.canonical_digest,
        cloud: None,
        casb_account_id: Some(account_id.to_owned()),
    })
}

#[allow(clippy::too_many_lines)] // One bounded poll owns auth material through normalization.
async fn prepare_scheduled_kubernetes(
    postgres: &PostgresStore,
    credentials: &JobCredentials,
    job: &LeasedConnectorJob,
) -> Result<PreparedJob, &'static str> {
    let config: ScheduledKubernetesApiConfig =
        serde_json::from_value(job.config_refs.clone()).map_err(|_| "connector_config_invalid")?;
    if config.kind != "kubernetes_api_v1"
        || !safe_lineage_id(&config.source_lineage_id)
        || !matches!(config.auth_mode.as_str(), "explicit_bearer" | "in_cluster")
    {
        return Err("connector_config_invalid");
    }
    let descriptor = VendorAdapter::KubernetesApiPull.descriptor();
    if descriptor.connector_type != job.connector_type {
        return Err("connector_type_mismatch");
    }
    let identity = postgres
        .get_or_create_installation_identity()
        .await
        .map_err(|_| "installation_identity_unavailable")?;
    if identity.installation_id != job.installation_id {
        return Err("installation_identity_mismatch");
    }
    let (api_base, bearer_token, supplied_ca_pem, ca_path) = if config.auth_mode == "in_cluster" {
        let host =
            env::var("KUBERNETES_SERVICE_HOST").map_err(|_| "kubernetes_api_ref_unavailable")?;
        let port = env::var("KUBERNETES_SERVICE_PORT_HTTPS")
            .or_else(|_| env::var("KUBERNETES_SERVICE_PORT"))
            .unwrap_or_else(|_| "443".to_owned());
        let api_base = kubernetes::kubernetes_in_cluster_api_base(&host, &port)
            .map_err(|_| "kubernetes_api_ref_invalid")?;
        let token = read_bounded_text_file(
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            16_384,
            "secret_ref_unavailable",
            "kubernetes_token_ref_invalid",
        )?;
        (
            api_base,
            token,
            None,
            Some("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"),
        )
    } else {
        let api_url = credentials
            .require("api_url")
            .map_err(|_| "kubernetes_api_ref_unavailable")?;
        let api_base =
            kubernetes::kubernetes_api_base(api_url).map_err(|_| "kubernetes_api_ref_invalid")?;
        let token = credentials
            .require("bearer_token")
            .map_err(|_| "secret_ref_unavailable")?
            .to_owned();
        (
            api_base,
            token,
            credentials.get("ca_pem").map(str::as_bytes),
            credentials.get("ca_file_path"),
        )
    };
    // In-cluster files are re-read for every poll so projected service-account rotation is
    // honored. Explicit Console configurations carry the selected PEM in the sealed credential
    // bundle and never depend on a path on the Console host.
    let ca_pem = if let Some(ca_pem) = supplied_ca_pem {
        if ca_pem.is_empty() || ca_pem.len() > 1_048_576 {
            return Err("kubernetes_ca_ref_invalid");
        }
        Some(ca_pem.to_vec())
    } else {
        ca_path
            .map(|path| {
                let metadata = fs::metadata(path).map_err(|_| "kubernetes_ca_ref_unavailable")?;
                if metadata.len() == 0 || metadata.len() > 1_048_576 {
                    return Err("kubernetes_ca_ref_invalid");
                }
                fs::read(path).map_err(|_| "kubernetes_ca_ref_unavailable")
            })
            .transpose()?
    };
    let client = kubernetes::kubernetes_client(ca_pem.as_deref())
        .map_err(|_| "kubernetes_client_invalid")?;
    drop(ca_pem);
    let snapshot = kubernetes::pull_kubernetes(&api_base, &bearer_token, &client)
        .await
        .map_err(|_| "kubernetes_inventory_pull_failed")?;
    let cursor_before = postgres
        .connector_cursor(job.connector_instance_id)
        .await
        .map_err(|_| "connector_cursor_unavailable")?
        .unwrap_or_default();
    let checkpoint = format!(
        "kubernetes-api:{}",
        hex::encode(Sha256::digest(&snapshot.data))
    );
    if snapshot.record_count == 0 {
        drop(snapshot.data);
        return Ok(PreparedJob::EmptyPoll {
            descriptor,
            cursor_before,
            cursor_after: checkpoint,
        });
    }
    let outcome = VendorAdapter::KubernetesApiPull
        .normalize(
            &snapshot.data,
            &VendorImportConfig {
                installation_id: job.installation_id,
                connector_instance_id: job.connector_instance_id,
                implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
                source_lineage_id: Some(config.source_lineage_id.clone()),
                received_at: Utc::now(),
                checkpoint: Cursor(checkpoint.clone()),
                pseudonymization_key: PseudonymizationKey::new(identity.pseudonymization_key())
                    .map_err(|_| "installation_key_invalid")?,
            },
        )
        .map_err(|_| "source_normalization_failed")?;
    Ok(PreparedJob::Source {
        descriptor,
        adapter: VendorAdapter::KubernetesApiPull,
        input: snapshot.data,
        checkpoint,
        source_lineage_id: config.source_lineage_id,
        expected_canonical_digest: outcome.batch.receipt.canonical_digest,
        cloud: None,
        casb_account_id: None,
    })
}

async fn prepare_scheduled_file(
    postgres: &PostgresStore,
    credentials: &JobCredentials,
    job: &LeasedConnectorJob,
) -> Result<PreparedJob, &'static str> {
    let config: ScheduledFileConfig =
        serde_json::from_value(job.config_refs.clone()).map_err(|_| "connector_config_invalid")?;
    if config.kind != "file_env_v1" {
        return Err("connector_config_invalid");
    }
    let adapter = VendorAdapter::from_key(&config.adapter).ok_or("connector_adapter_invalid")?;
    validate_cloud_credential_shape(
        adapter,
        credentials.get("account_id"),
        credentials.get("scope_id"),
        config.region.as_deref(),
    )?;
    let descriptor = adapter.descriptor();
    if descriptor.connector_type != job.connector_type {
        return Err("connector_type_mismatch");
    }
    let identity = postgres
        .get_or_create_installation_identity()
        .await
        .map_err(|_| "installation_identity_unavailable")?;
    if identity.installation_id != job.installation_id {
        return Err("installation_identity_mismatch");
    }
    let source_path = credentials
        .require("source_path")
        .map_err(|_| "source_ref_unavailable")?;
    let metadata = fs::metadata(source_path).map_err(|_| "source_ref_unavailable")?;
    if metadata.len() == 0 || metadata.len() > u64::try_from(MAX_IMPORT_BYTES).unwrap_or(u64::MAX) {
        return Err("source_size_invalid");
    }
    let input = fs::read(source_path).map_err(|_| "source_read_failed")?;
    let checkpoint = format!("sha256:{}", hex::encode(Sha256::digest(&input)));
    let received_at = Utc::now();
    let pseudonymization_key = PseudonymizationKey::new(identity.pseudonymization_key())
        .map_err(|_| "installation_key_invalid")?;
    let cloud = credential_cloud_scope(
        credentials,
        adapter,
        config.region.as_deref(),
        file_observed_at(&metadata)?,
    )?;
    let casb_account_id = credential_casb_account_id(credentials, adapter)?;
    let outcome = if let Some(cloud) = &cloud {
        adapter.normalize_cloud(
            &input,
            &ManagedCloudImportConfig {
                installation_id: job.installation_id,
                connector_instance_id: job.connector_instance_id,
                implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
                source_lineage_id: Some(config.source_lineage_id.clone()),
                observed_at: cloud.observed_at,
                received_at,
                checkpoint: Cursor(checkpoint.clone()),
                pseudonymization_key,
                scope: cloud.scope.clone(),
                transport: ManagedCloudTransport::File,
            },
        )
    } else if let Some(account_id) = &casb_account_id {
        adapter.normalize_casb(
            &input,
            account_id,
            &VendorImportConfig {
                installation_id: job.installation_id,
                connector_instance_id: job.connector_instance_id,
                implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
                source_lineage_id: Some(config.source_lineage_id.clone()),
                received_at,
                checkpoint: Cursor(checkpoint.clone()),
                pseudonymization_key,
            },
        )
    } else {
        adapter.normalize(
            &input,
            &VendorImportConfig {
                installation_id: job.installation_id,
                connector_instance_id: job.connector_instance_id,
                implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
                source_lineage_id: Some(config.source_lineage_id.clone()),
                received_at,
                checkpoint: Cursor(checkpoint.clone()),
                pseudonymization_key,
            },
        )
    }
    .map_err(|_| "source_normalization_failed")?;
    Ok(PreparedJob::Source {
        descriptor,
        adapter,
        input,
        checkpoint,
        source_lineage_id: config.source_lineage_id,
        expected_canonical_digest: outcome.batch.receipt.canonical_digest,
        cloud,
        casb_account_id,
    })
}

async fn prepare_scheduled_cloud(
    postgres: &PostgresStore,
    credentials: &JobCredentials,
    client: &reqwest::Client,
    job: &LeasedConnectorJob,
) -> Result<PreparedJob, &'static str> {
    let config: ScheduledCloudApiConfig =
        serde_json::from_value(job.config_refs.clone()).map_err(|_| "connector_config_invalid")?;
    let adapter = VendorAdapter::from_key(&config.adapter).ok_or("connector_adapter_invalid")?;
    if config.kind != "cloud_api_v1"
        || !adapter.is_native_cloud()
        || !safe_lineage_id(&config.source_lineage_id)
    {
        return Err("connector_config_invalid");
    }
    let descriptor = adapter.descriptor();
    if descriptor.connector_type != job.connector_type {
        return Err("connector_type_mismatch");
    }
    let identity = postgres
        .get_or_create_installation_identity()
        .await
        .map_err(|_| "installation_identity_unavailable")?;
    if identity.installation_id != job.installation_id {
        return Err("installation_identity_mismatch");
    }
    let observed_at = Utc::now();
    let cloud = credential_cloud_scope(credentials, adapter, Some(&config.region), observed_at)?
        .ok_or("connector_config_invalid")?;
    let snapshot = provider::pull_inventory(adapter, &cloud.scope, client)
        .await
        .map_err(|error| {
            eprintln!(
                "managed cloud pull failed for connector {} ({}): {error}",
                job.connector_instance_id, config.adapter
            );
            "cloud_inventory_pull_failed"
        })?;
    let cursor_before = postgres
        .connector_cursor(job.connector_instance_id)
        .await
        .map_err(|_| "connector_cursor_unavailable")?
        .unwrap_or_default();
    let checkpoint = format!(
        "cloud-api-{}-{}",
        observed_at.timestamp_millis(),
        hex::encode(Sha256::digest(&snapshot.data))
    );
    if snapshot.record_count == 0 {
        drop(snapshot.data);
        return Ok(PreparedJob::EmptyPoll {
            descriptor,
            cursor_before,
            cursor_after: checkpoint,
        });
    }
    let outcome = adapter
        .normalize_cloud(
            &snapshot.data,
            &ManagedCloudImportConfig {
                installation_id: job.installation_id,
                connector_instance_id: job.connector_instance_id,
                implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
                source_lineage_id: Some(config.source_lineage_id.clone()),
                observed_at,
                received_at: Utc::now(),
                checkpoint: Cursor(checkpoint.clone()),
                pseudonymization_key: PseudonymizationKey::new(identity.pseudonymization_key())
                    .map_err(|_| "installation_key_invalid")?,
                scope: cloud.scope.clone(),
                transport: adapter.cloud_transport(),
            },
        )
        .map_err(|_| "source_normalization_failed")?;
    Ok(PreparedJob::Source {
        descriptor,
        adapter,
        input: snapshot.data,
        checkpoint,
        source_lineage_id: config.source_lineage_id,
        expected_canonical_digest: outcome.batch.receipt.canonical_digest,
        cloud: Some(cloud),
        casb_account_id: None,
    })
}

async fn prepare_scheduled_cloud_network(
    postgres: &PostgresStore,
    credentials: &JobCredentials,
    client: &reqwest::Client,
    job: &LeasedConnectorJob,
) -> Result<PreparedJob, &'static str> {
    let validated = validate_scheduled_cloud_network(credentials, job)?;
    let config = &validated.config;
    let adapter = validated.adapter;
    let backfill_seconds = validated.backfill_seconds;
    let region = validated.region.as_str();
    let descriptor = adapter.descriptor();
    if descriptor.connector_type != job.connector_type {
        return Err("connector_type_mismatch");
    }
    let identity = postgres
        .get_or_create_installation_identity()
        .await
        .map_err(|_| "installation_identity_unavailable")?;
    if identity.installation_id != job.installation_id {
        return Err("installation_identity_mismatch");
    }
    let CloudNetworkRuntimeValues {
        account_id,
        network_id,
        log_group,
        workspace_resource,
        credentials: cloud_credentials,
    } = cloud_network_runtime_values(credentials)?;
    let cursor_before = postgres
        .connector_cursor(job.connector_instance_id)
        .await
        .map_err(|_| "connector_cursor_unavailable")?
        .unwrap_or_default();
    let snapshot = provider::pull_network(
        &pull_support::NativeNetworkPull {
            adapter,
            account_id: &account_id,
            network_id: &network_id,
            region,
            log_group: log_group.as_deref(),
            workspace_resource: workspace_resource.as_deref(),
            cursor_before: &cursor_before,
            initial_lookback_seconds: backfill_seconds,
            now: Utc::now(),
            credentials: cloud_credentials,
        },
        client,
    )
    .await
    .map_err(|error| {
        eprintln!(
            "cloud network pull failed for connector {} ({}): {error}",
            job.connector_instance_id, config.adapter
        );
        "cloud_network_pull_failed"
    })?;
    if snapshot.record_count == 0 {
        drop(snapshot.data);
        return Ok(PreparedJob::EmptyPoll {
            descriptor,
            cursor_before,
            cursor_after: snapshot.cursor_after,
        });
    }
    let checkpoint = snapshot.cursor_after;
    let outcome = adapter
        .normalize(
            &snapshot.data,
            &VendorImportConfig {
                installation_id: job.installation_id,
                connector_instance_id: job.connector_instance_id,
                implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
                source_lineage_id: Some(config.source_lineage_id.clone()),
                received_at: Utc::now(),
                checkpoint: Cursor(checkpoint.clone()),
                pseudonymization_key: PseudonymizationKey::new(identity.pseudonymization_key())
                    .map_err(|_| "installation_key_invalid")?,
            },
        )
        .map_err(|_| "source_normalization_failed")?;
    Ok(PreparedJob::Source {
        descriptor,
        adapter,
        input: snapshot.data,
        checkpoint,
        source_lineage_id: config.source_lineage_id.clone(),
        expected_canonical_digest: outcome.batch.receipt.canonical_digest,
        cloud: None,
        casb_account_id: None,
    })
}

fn cloud_network_runtime_values(
    credentials: &JobCredentials,
) -> Result<CloudNetworkRuntimeValues, &'static str> {
    let values = CloudNetworkRuntimeValues {
        account_id: credentials
            .require("account_id")
            .map_err(|_| "cloud_account_ref_unavailable")?
            .to_owned(),
        network_id: credentials
            .require("network_id")
            .map_err(|_| "cloud_network_ref_unavailable")?
            .to_owned(),
        log_group: credentials.get("log_group").map(str::to_owned),
        workspace_resource: credentials.get("workspace_resource").map(str::to_owned),
        credentials: pull_support::NativeNetworkCredentials {
            aws: aws_static_credentials(credentials)?,
            azure: azure_service_principal_credentials(credentials)?,
            gcp: gcp_service_account_credentials(credentials)?,
        },
    };
    if !safe_raw_cloud_identifier(&values.account_id)
        || !safe_raw_cloud_identifier(&values.network_id)
        || values
            .log_group
            .as_deref()
            .is_some_and(|value| !safe_raw_cloud_identifier(value))
        || values
            .workspace_resource
            .as_deref()
            .is_some_and(|value| !safe_raw_cloud_identifier(value))
    {
        return Err("cloud_network_ref_invalid");
    }
    Ok(values)
}

fn validate_scheduled_cloud_network(
    credentials: &JobCredentials,
    job: &LeasedConnectorJob,
) -> Result<ValidatedCloudNetworkConfig, &'static str> {
    let config: ScheduledCloudNetworkApiConfig =
        serde_json::from_value(job.config_refs.clone()).map_err(|_| "connector_config_invalid")?;
    let adapter = VendorAdapter::from_key(&config.adapter).ok_or("connector_adapter_invalid")?;
    let backfill_seconds = config
        .backfill_seconds
        .parse::<u32>()
        .ok()
        .filter(|seconds| (300..=3_600).contains(seconds))
        .ok_or("connector_config_invalid")?;
    let region = config.region.as_deref().unwrap_or("global").to_owned();
    let log_group = credentials.get("log_group");
    let workspace_resource = credentials.get("workspace_resource");
    let provider_shape_valid = match adapter {
        VendorAdapter::AwsCloudFlowApi => {
            safe_cloud_region(&region) && log_group.is_some() && workspace_resource.is_none()
        }
        VendorAdapter::AwsNetworkMappingApi | VendorAdapter::AzureNetworkMappingApi => {
            safe_cloud_region(&region) && log_group.is_none() && workspace_resource.is_none()
        }
        VendorAdapter::AzureCloudFlowApi => {
            safe_cloud_region(&region) && log_group.is_none() && workspace_resource.is_some()
        }
        VendorAdapter::GcpCloudFlowApi | VendorAdapter::GcpNetworkMappingApi => {
            region == "global" && log_group.is_none() && workspace_resource.is_none()
        }
        _ => false,
    };
    if config.kind != "cloud_network_api_v1"
        || !adapter.is_native_cloud_network()
        || !provider_shape_valid
        || !safe_lineage_id(&config.source_lineage_id)
    {
        return Err("connector_config_invalid");
    }
    Ok(ValidatedCloudNetworkConfig {
        config,
        adapter,
        backfill_seconds,
        region,
    })
}

#[allow(clippy::too_many_lines)]
async fn prepare_nextdns_api(
    postgres: &PostgresStore,
    credentials: &JobCredentials,
    client: &reqwest::Client,
    job: &LeasedConnectorJob,
) -> Result<PreparedJob, &'static str> {
    let config: ScheduledNextDnsApiConfig =
        serde_json::from_value(job.config_refs.clone()).map_err(|_| "connector_config_invalid")?;
    if config.kind != "nextdns_api_v1"
        || !safe_nextdns_profile_id(&config.profile_id)
        || !safe_lineage_id(&config.source_lineage_id)
    {
        return Err("connector_config_invalid");
    }
    let backfill_seconds = config
        .backfill_seconds
        .parse::<u32>()
        .ok()
        .filter(|seconds| valid_initial_backfill_seconds(*seconds))
        .ok_or("connector_config_invalid")?;
    let record_limit = config
        .record_limit
        .parse::<u32>()
        .ok()
        .filter(|limit| (1..=1_000).contains(limit))
        .ok_or("connector_config_invalid")?;
    let descriptor = nextdns_api_descriptor();
    if descriptor.connector_type != job.connector_type {
        return Err("connector_type_mismatch");
    }
    let identity = postgres
        .get_or_create_installation_identity()
        .await
        .map_err(|_| "installation_identity_unavailable")?;
    if identity.installation_id != job.installation_id {
        return Err("installation_identity_mismatch");
    }
    let cursor_before = postgres
        .connector_cursor(job.connector_instance_id)
        .await
        .map_err(|_| "connector_cursor_unavailable")?
        .unwrap_or_default();
    let now = Utc::now();
    let pull_cursor = if cursor_before.is_empty() {
        nextdns::NextDnsPullCursor {
            from_millis: (now - chrono::Duration::seconds(i64::from(backfill_seconds)))
                .timestamp_millis(),
            page_cursor: None,
        }
    } else {
        nextdns::parse_cursor(&cursor_before).ok_or("connector_cursor_invalid")?
    };
    let api_key = credentials
        .require("api_key")
        .map_err(|_| "secret_ref_unavailable")?;
    let input = nextdns::fetch_page(
        api_key,
        client,
        &config.profile_id,
        &pull_cursor,
        record_limit,
    )
    .await?;
    let page = inspect_nextdns_api_page(&input).map_err(|_| "source_normalization_failed")?;
    if page.record_count == 0 && page.next_page_cursor.is_some() {
        eprintln!(
            "nextdns_empty_page_cursor_discarded connector_instance_id={}",
            job.connector_instance_id
        );
    }
    let last_source_at = if page.record_count == 0 {
        postgres
            .connector_last_source_at(job.connector_instance_id)
            .await
            .map_err(|_| "connector_cursor_unavailable")?
    } else {
        None
    };
    let next_cursor = nextdns::next_cursor(&pull_cursor, &page, now, last_source_at);
    let checkpoint = nextdns::encode_cursor(&next_cursor);
    if page.record_count == 0 {
        drop(input);
        return Ok(PreparedJob::EmptyPoll {
            descriptor,
            cursor_before,
            cursor_after: checkpoint,
        });
    }
    let outcome = import_nextdns_api_json(
        &input,
        &VendorImportConfig {
            installation_id: job.installation_id,
            connector_instance_id: job.connector_instance_id,
            implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
            source_lineage_id: Some(config.source_lineage_id.clone()),
            received_at: Utc::now(),
            checkpoint: Cursor(checkpoint.clone()),
            pseudonymization_key: PseudonymizationKey::new(identity.pseudonymization_key())
                .map_err(|_| "installation_key_invalid")?,
        },
    )
    .map_err(|_| "source_normalization_failed")?;
    Ok(PreparedJob::Source {
        descriptor,
        adapter: VendorAdapter::NextdnsApi,
        input,
        checkpoint,
        source_lineage_id: config.source_lineage_id,
        expected_canonical_digest: outcome.batch.receipt.canonical_digest,
        cloud: None,
        casb_account_id: None,
    })
}

async fn record_job_failure(
    postgres: &PostgresStore,
    job: &LeasedConnectorJob,
    started_at: DateTime<Utc>,
    error_code: &'static str,
) -> Result<()> {
    let cursor = postgres
        .connector_cursor(job.connector_instance_id)
        .await
        .context("load connector cursor for job failure")?
        .unwrap_or_default();
    let redaction_digest = hex::encode(Sha256::digest(
        br#"{"normalized":false,"source_bytes_retained":false}"#,
    ));
    postgres
        .record_connector_run(&ConnectorRunRecord {
            run_id: Uuid::now_v7(),
            connector_instance_id: job.connector_instance_id,
            installation_id: job.installation_id,
            connector_type: job.connector_type.clone(),
            status: ConnectorRunStatus::Failed,
            started_at,
            completed_at: Utc::now(),
            cursor_before: cursor.clone(),
            cursor_after: cursor,
            first_source_at: None,
            last_source_at: None,
            records_read: 0,
            accepted: 0,
            ignored: 0,
            rejected: 0,
            deduplicated: 0,
            batch_id: None,
            error_code: Some(error_code.to_owned()),
            redaction_digest,
        })
        .await
        .context("record scheduled connector failure")?;
    Ok(())
}

async fn record_empty_poll(
    postgres: &PostgresStore,
    job: &LeasedConnectorJob,
    started_at: DateTime<Utc>,
    descriptor: ConnectorDescriptor,
    cursor_before: String,
    cursor_after: String,
) -> Result<()> {
    postgres
        .register_connector(job.installation_id, job.connector_instance_id, &descriptor)
        .await
        .context("register empty connector poll")?;
    postgres
        .record_connector_run(&ConnectorRunRecord {
            run_id: Uuid::now_v7(),
            connector_instance_id: job.connector_instance_id,
            installation_id: job.installation_id,
            connector_type: job.connector_type.clone(),
            status: ConnectorRunStatus::Completed,
            started_at,
            completed_at: Utc::now(),
            cursor_before,
            cursor_after,
            first_source_at: None,
            last_source_at: None,
            records_read: 0,
            accepted: 0,
            ignored: 0,
            rejected: 0,
            deduplicated: 0,
            batch_id: None,
            error_code: None,
            redaction_digest: hex::encode(Sha256::digest(
                br#"{"normalized":true,"source_bytes_retained":false}"#,
            )),
        })
        .await
        .context("record empty connector poll")?;
    Ok(())
}

async fn commit_through_api(
    client: &reqwest::Client,
    api_base: &Url,
    source: &ApiImportSource<'_>,
) -> Result<CommitReceipt> {
    ensure!(
        safe_lineage_id(source.source_lineage_id),
        "unsafe source lineage ID"
    );
    let data = std::str::from_utf8(source.input).context("connector source must be UTF-8")?;
    let preview_request = ApiImportPreviewRequest {
        adapter: source.adapter.key(),
        connector_instance_id: source.connector_instance_id,
        source_lineage_id: source.source_lineage_id,
        checkpoint: source.checkpoint,
        observed_at: source.cloud.map(|cloud| cloud.observed_at),
        cloud_scope: source.cloud.map(CloudImportSource::api_scope),
        casb_account_id: source.casb_account_id,
        data,
    };
    preview_and_commit(
        client,
        api_base,
        preview_request,
        Some(source.expected_canonical_digest),
    )
    .await
}

async fn preview_and_commit(
    client: &reqwest::Client,
    api_base: &Url,
    preview_request: ApiImportPreviewRequest<'_>,
    expected_canonical_digest: Option<&str>,
) -> Result<CommitReceipt> {
    let token = SecretCipher::from_env()
        .context("load collector import credential")?
        .collector_import_token();
    let mut token_header =
        HeaderValue::from_str(&token).context("encode collector import credential")?;
    token_header.set_sensitive(true);
    let preview_response = client
        .post(api_base.join("imports/preview")?)
        .header("x-tally-collector-token", token_header.clone())
        .json(&preview_request)
        .send()
        .await
        .context("reach the local Tally ingestion service")?;
    ensure!(
        preview_response.status() == StatusCode::OK,
        "the local Tally ingestion preview rejected the connector batch"
    );
    let preview: ApiImportPreviewResponse = preview_response
        .json()
        .await
        .context("decode local Tally ingestion preview")?;
    ensure!(
        !preview.writes_data && !preview.source_bytes_retained && !preview.content_retained,
        "the local Tally ingestion preview violated the privacy contract"
    );
    ensure!(
        preview.canonical_digest.len() == 64
            && preview
                .canonical_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "the local Tally ingestion preview returned an invalid digest"
    );
    if let Some(expected) = expected_canonical_digest {
        ensure!(
            preview.canonical_digest == expected,
            "the local Tally ingestion preview did not match the collector's normalized batch"
        );
    }
    let commit_request = ApiImportCommitRequest {
        preview: preview_request,
        confirm_canonical_digest: &preview.canonical_digest,
    };
    let commit_response = client
        .post(api_base.join("imports")?)
        .header("x-tally-collector-token", token_header)
        .json(&commit_request)
        .send()
        .await
        .context("commit through the local Tally ingestion service")?;
    ensure!(
        commit_response.status() == StatusCode::OK,
        "the local Tally ingestion service rejected the preview-bound commit"
    );
    let receipt: CommitReceipt = commit_response
        .json()
        .await
        .context("decode local Tally ingestion receipt")?;
    ensure!(
        receipt.canonical_digest == preview.canonical_digest && !receipt.content_retained,
        "the local Tally ingestion receipt violated the preview or privacy contract"
    );
    Ok(receipt)
}

fn collector_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("godel-tally-collector/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build bounded connector HTTP client")
}

fn tally_api_base(config: &TallyConfig) -> Result<Url> {
    // Containerized workers cannot assume the API listens on their own loopback; an operator may
    // point the worker at the internal service explicitly. Otherwise the loopback-derived bind
    // keeps the default single-host deployment as the only implicit target.
    if let Ok(base) = env::var("TALLY_API_URL") {
        let url = Url::parse(&base).context("TALLY_API_URL is not a valid URL")?;
        ensure!(
            matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
            "TALLY_API_URL must be an absolute http(s) URL"
        );
        return Ok(url);
    }
    let bind = config.http_bind;
    ensure!(
        bind.ip().is_loopback() || bind.ip().is_unspecified(),
        "connector worker requires a loopback or wildcard Tally API bind"
    );
    let loopback = if bind.is_ipv4() {
        std::net::SocketAddr::from(([127, 0, 0, 1], bind.port()))
    } else {
        std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], bind.port()))
    };
    Url::parse(&format!("http://{loopback}/api/v1/tally/")).context("build local Tally API URL")
}

fn parse_run_status(value: &str) -> Result<ConnectorRunStatus> {
    match value {
        "completed" => Ok(ConnectorRunStatus::Completed),
        "duplicate" => Ok(ConnectorRunStatus::Duplicate),
        _ => bail!("the local Tally ingestion receipt returned an invalid status"),
    }
}

fn safe_environment_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase())
}

fn read_bounded_text_file(
    path: &str,
    max_bytes: u64,
    unavailable: &'static str,
    invalid: &'static str,
) -> Result<String, &'static str> {
    let metadata = fs::metadata(path).map_err(|_| unavailable)?;
    if metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(invalid);
    }
    let value = fs::read_to_string(path).map_err(|_| unavailable)?;
    let value = value.trim();
    if value.is_empty() || value.contains('\0') {
        return Err(invalid);
    }
    Ok(value.to_owned())
}

/// The credentials an operator typed into a connector form, unsealed for one leased run.
///
/// Values live only as long as the run that unsealed them: the collector reads them, hands them
/// to the source client, and drops the map. Nothing here is written to disk, logged, or returned.
struct JobCredentials(BTreeMap<String, String>);

impl JobCredentials {
    /// Unseals the bundle stored on the leased job.
    ///
    /// A job with no sealed bundle yields an empty map rather than an error, so a source that
    /// needs no credentials still runs.
    fn open(cipher: &SecretCipher, job: &LeasedConnectorJob) -> Result<Self, &'static str> {
        let Some(sealed) = job.credentials.as_ref() else {
            return Ok(Self(BTreeMap::new()));
        };
        let plaintext = cipher
            .decrypt(&sealed.nonce, &sealed.ciphertext)
            .map_err(|_| "connector_credentials_unsealable")?;
        serde_json::from_str(&plaintext)
            .map(Self)
            .map_err(|_| "connector_credentials_invalid")
    }

    /// Returns a credential the source cannot run without.
    fn require(&self, key: &str) -> Result<&str, &'static str> {
        self.get(key).ok_or("connector_credential_missing")
    }

    /// Returns an optional credential, treating an empty value as absent so a blank form field
    /// and an omitted one mean the same thing.
    fn get(&self, key: &str) -> Option<&str> {
        self.0
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }
}

fn validate_cloud_reference_shape(
    adapter: VendorAdapter,
    account_id_env: Option<&str>,
    scope_id_env: Option<&str>,
    region: Option<&str>,
) -> Result<(), &'static str> {
    if adapter.is_casb() {
        return if account_id_env.is_some_and(safe_environment_name)
            && scope_id_env.is_none()
            && region.is_none()
        {
            Ok(())
        } else {
            Err("CASB adapter requires only a safe account environment reference")
        };
    }
    if !adapter.is_managed_cloud() {
        return if account_id_env.is_none() && scope_id_env.is_none() && region.is_none() {
            Ok(())
        } else {
            Err("cloud scope options require a managed-cloud adapter")
        };
    }
    if !account_id_env.is_some_and(safe_environment_name) || !region.is_some_and(safe_cloud_region)
    {
        return Err(
            "managed-cloud adapter requires safe account environment and region references",
        );
    }
    let azure = matches!(
        adapter,
        VendorAdapter::AzureOpenai
            | VendorAdapter::AzureOpenaiApi
            | VendorAdapter::AzureAiFoundry
            | VendorAdapter::AzureAiFoundryApi
    );
    if (azure && !scope_id_env.is_some_and(safe_environment_name))
        || (!azure && scope_id_env.is_some())
    {
        return Err("Azure requires a scope environment reference; other providers prohibit it");
    }
    Ok(())
}

/// Value-oriented counterpart to [`validate_cloud_reference_shape`] for the durable worker, which
/// receives the operator's actual identifiers from the sealed bundle rather than variable names.
fn validate_cloud_credential_shape(
    adapter: VendorAdapter,
    account_id: Option<&str>,
    scope_id: Option<&str>,
    region: Option<&str>,
) -> Result<(), &'static str> {
    if adapter.is_casb() {
        return if account_id.is_some_and(safe_raw_cloud_identifier)
            && scope_id.is_none()
            && region.is_none()
        {
            Ok(())
        } else {
            Err("CASB adapter requires only a bounded account identifier")
        };
    }
    if !adapter.is_managed_cloud() {
        return if account_id.is_none() && scope_id.is_none() && region.is_none() {
            Ok(())
        } else {
            Err("cloud scope options require a managed-cloud adapter")
        };
    }
    if !account_id.is_some_and(safe_raw_cloud_identifier) || !region.is_some_and(safe_cloud_region)
    {
        return Err("managed-cloud adapter requires a bounded account identifier and region");
    }
    let azure = matches!(
        adapter,
        VendorAdapter::AzureOpenai
            | VendorAdapter::AzureOpenaiApi
            | VendorAdapter::AzureAiFoundry
            | VendorAdapter::AzureAiFoundryApi
    );
    if (azure && !scope_id.is_some_and(safe_raw_cloud_identifier)) || (!azure && scope_id.is_some())
    {
        return Err("Azure requires a scope identifier; other providers prohibit it");
    }
    Ok(())
}

fn load_casb_account_id(
    adapter: VendorAdapter,
    account_id_env: Option<&str>,
) -> Result<Option<String>, &'static str> {
    if !adapter.is_casb() {
        return Ok(None);
    }
    let account_id = env::var(account_id_env.ok_or("connector_config_invalid")?)
        .map_err(|_| "casb_account_ref_unavailable")?;
    if !safe_raw_cloud_identifier(&account_id) {
        return Err("casb_account_ref_invalid");
    }
    Ok(Some(account_id))
}

fn load_cloud_scope(
    adapter: VendorAdapter,
    account_id_env: Option<&str>,
    scope_id_env: Option<&str>,
    region: Option<&str>,
    observed_at: DateTime<Utc>,
) -> Result<Option<CloudImportSource>, &'static str> {
    validate_cloud_reference_shape(adapter, account_id_env, scope_id_env, region)?;
    if !adapter.is_managed_cloud() {
        return Ok(None);
    }
    let account_id = env::var(account_id_env.ok_or("connector_config_invalid")?)
        .map_err(|_| "cloud_account_ref_unavailable")?;
    if !safe_raw_cloud_identifier(&account_id) {
        return Err("cloud_account_ref_invalid");
    }
    let region = region.ok_or("connector_config_invalid")?.to_owned();
    let scope = match adapter {
        VendorAdapter::AwsManagedAi | VendorAdapter::AwsManagedAiApi => ManagedCloudScope::Aws {
            account_id,
            region,
            static_credentials: None,
        },
        VendorAdapter::AzureOpenai
        | VendorAdapter::AzureOpenaiApi
        | VendorAdapter::AzureAiFoundry
        | VendorAdapter::AzureAiFoundryApi => {
            let account_resource_id = env::var(scope_id_env.ok_or("connector_config_invalid")?)
                .map_err(|_| "cloud_scope_ref_unavailable")?;
            if !safe_raw_cloud_identifier(&account_resource_id) {
                return Err("cloud_scope_ref_invalid");
            }
            ManagedCloudScope::Azure {
                subscription_id: account_id,
                account_resource_id,
                region,
                workspace_resource: None,
                static_credentials: None,
            }
        }
        VendorAdapter::GcpVertexAi | VendorAdapter::GcpVertexAiApi => ManagedCloudScope::Gcp {
            project_id: account_id,
            location: region,
            static_credentials: None,
        },
        _ => return Err("connector_adapter_invalid"),
    };
    Ok(Some(CloudImportSource { observed_at, scope }))
}

fn file_observed_at(metadata: &fs::Metadata) -> Result<DateTime<Utc>, &'static str> {
    metadata
        .modified()
        .map(DateTime::<Utc>::from)
        .map_err(|_| "source_timestamp_unavailable")
}

/// Builds the managed-cloud scope for a scheduled run from the unsealed credential bundle.
fn credential_cloud_scope(
    credentials: &JobCredentials,
    adapter: VendorAdapter,
    region: Option<&str>,
    observed_at: DateTime<Utc>,
) -> Result<Option<CloudImportSource>, &'static str> {
    validate_cloud_credential_shape(
        adapter,
        credentials.get("account_id"),
        credentials.get("scope_id"),
        region,
    )?;
    if !adapter.is_managed_cloud() {
        return Ok(None);
    }
    let account_id = credentials
        .require("account_id")
        .map_err(|_| "cloud_account_ref_unavailable")?;
    if !safe_raw_cloud_identifier(account_id) {
        return Err("cloud_account_ref_invalid");
    }
    let account_id = account_id.to_owned();
    let region = region.ok_or("connector_config_invalid")?.to_owned();
    let scope = match adapter {
        VendorAdapter::AwsManagedAi | VendorAdapter::AwsManagedAiApi => ManagedCloudScope::Aws {
            account_id,
            region,
            static_credentials: aws_static_credentials(credentials)?,
        },
        VendorAdapter::AzureOpenai
        | VendorAdapter::AzureOpenaiApi
        | VendorAdapter::AzureAiFoundry
        | VendorAdapter::AzureAiFoundryApi => {
            let account_resource_id = credentials
                .require("scope_id")
                .map_err(|_| "cloud_scope_ref_unavailable")?;
            if !safe_raw_cloud_identifier(account_resource_id) {
                return Err("cloud_scope_ref_invalid");
            }
            ManagedCloudScope::Azure {
                subscription_id: account_id,
                account_resource_id: account_resource_id.to_owned(),
                region,
                workspace_resource: credentials.get("workspace_resource").map(str::to_owned),
                static_credentials: azure_service_principal_credentials(credentials)?,
            }
        }
        VendorAdapter::GcpVertexAi | VendorAdapter::GcpVertexAiApi => ManagedCloudScope::Gcp {
            project_id: account_id,
            location: region,
            static_credentials: gcp_service_account_credentials(credentials)?,
        },
        _ => return Err("connector_adapter_invalid"),
    };
    Ok(Some(CloudImportSource { observed_at, scope }))
}

fn aws_static_credentials(
    credentials: &JobCredentials,
) -> Result<Option<tally_connectors::AwsStaticCredentials>, &'static str> {
    match (
        credentials.get("aws_access_key_id"),
        credentials.get("aws_secret_access_key"),
        credentials.get("aws_session_token"),
    ) {
        (None, None, None) => Ok(None),
        (Some(access_key_id), Some(secret_access_key), session_token)
            if safe_aws_access_key_id(access_key_id)
                && safe_aws_secret_access_key(secret_access_key)
                && session_token.is_none_or(safe_cloud_credential_value) =>
        {
            Ok(Some(tally_connectors::AwsStaticCredentials {
                access_key_id: access_key_id.to_owned(),
                secret_access_key: secret_access_key.to_owned(),
                session_token: session_token.map(str::to_owned),
            }))
        }
        (Some(_), Some(_), _) => Err("cloud_aws_credentials_invalid"),
        _ => Err("cloud_aws_credentials_partial"),
    }
}

fn validate_cloud_auth_references(
    adapter: VendorAdapter,
    references: &CloudCredentialArgs,
) -> Result<()> {
    let all = [
        references.aws_access_key_id_env.as_deref(),
        references.aws_secret_access_key_env.as_deref(),
        references.aws_session_token_env.as_deref(),
        references.azure_tenant_id_env.as_deref(),
        references.azure_client_id_env.as_deref(),
        references.azure_client_secret_env.as_deref(),
        references.gcp_service_account_json_env.as_deref(),
    ];
    ensure!(
        all.into_iter().flatten().all(safe_environment_name),
        "cloud credential references must be uppercase environment names"
    );
    let aws = matches!(
        adapter,
        VendorAdapter::AwsManagedAiApi
            | VendorAdapter::AwsCloudFlowApi
            | VendorAdapter::AwsNetworkMappingApi
    );
    let azure = matches!(
        adapter,
        VendorAdapter::AzureOpenaiApi
            | VendorAdapter::AzureAiFoundryApi
            | VendorAdapter::AzureCloudFlowApi
            | VendorAdapter::AzureNetworkMappingApi
    );
    let gcp = matches!(
        adapter,
        VendorAdapter::GcpVertexAiApi
            | VendorAdapter::GcpCloudFlowApi
            | VendorAdapter::GcpNetworkMappingApi
    );
    let aws_pair = (
        references.aws_access_key_id_env.is_some(),
        references.aws_secret_access_key_env.is_some(),
    );
    ensure!(
        aws_pair.0 == aws_pair.1
            && (references.aws_session_token_env.is_none() || (aws_pair.0 && aws)),
        "AWS access key and secret references must be supplied together; a session token requires both"
    );
    ensure!(
        aws || (!aws_pair.0 && references.aws_session_token_env.is_none()),
        "AWS credential references are only valid for AWS connectors"
    );
    let azure_count = [
        references.azure_tenant_id_env.is_some(),
        references.azure_client_id_env.is_some(),
        references.azure_client_secret_env.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    ensure!(
        (azure && matches!(azure_count, 0 | 3)) || (!azure && azure_count == 0),
        "Azure service-principal references must be supplied together and only for Azure connectors"
    );
    ensure!(
        gcp || references.gcp_service_account_json_env.is_none(),
        "Google service-account references are only valid for Google Cloud connectors"
    );
    Ok(())
}

fn azure_service_principal_credentials(
    credentials: &JobCredentials,
) -> Result<Option<tally_connectors::AzureServicePrincipalCredentials>, &'static str> {
    match (
        credentials.get("azure_tenant_id"),
        credentials.get("azure_client_id"),
        credentials.get("azure_client_secret"),
    ) {
        (None, None, None) => Ok(None),
        (Some(tenant_id), Some(client_id), Some(client_secret))
            if safe_cloud_credential_value(tenant_id)
                && safe_cloud_credential_value(client_id)
                && safe_cloud_credential_value(client_secret) =>
        {
            Ok(Some(tally_connectors::AzureServicePrincipalCredentials {
                tenant_id: tenant_id.to_owned(),
                client_id: client_id.to_owned(),
                client_secret: client_secret.to_owned(),
            }))
        }
        _ => Err("cloud_azure_credentials_invalid"),
    }
}

fn gcp_service_account_credentials(
    credentials: &JobCredentials,
) -> Result<Option<tally_connectors::GcpServiceAccountCredentials>, &'static str> {
    let Some(json) = credentials.get("gcp_service_account_json") else {
        return Ok(None);
    };
    if !safe_gcp_service_account_json(json) {
        return Err("cloud_gcp_credentials_invalid");
    }
    Ok(Some(tally_connectors::GcpServiceAccountCredentials {
        json: json.to_owned(),
    }))
}

/// Reads the CASB account identifier a scheduled run needs from the unsealed credential bundle.
fn credential_casb_account_id(
    credentials: &JobCredentials,
    adapter: VendorAdapter,
) -> Result<Option<String>, &'static str> {
    if !adapter.is_casb() {
        return Ok(None);
    }
    let account_id = credentials
        .require("account_id")
        .map_err(|_| "casb_account_ref_unavailable")?;
    if !safe_raw_cloud_identifier(account_id) {
        return Err("casb_account_ref_invalid");
    }
    Ok(Some(account_id.to_owned()))
}

fn safe_cloud_region(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// AWS access key IDs are uppercase ASCII alphanumeric, 16 to 128 characters. Anything outside
/// that shape is rejected up front so a stray UI paste cannot leak into the SDK.
fn safe_aws_access_key_id(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

/// AWS secret access keys are 40 characters of mixed-case base64-ish (alphanumeric plus `/` and
/// `+`). We accept a slightly wider band (16–256) to cover rotated keys and downstream forms
/// without storing anything that isn't already in that character class.
fn safe_aws_secret_access_key(value: &str) -> bool {
    (16..=256).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'+' | b'='))
}

fn safe_cloud_credential_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4_096
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn safe_gcp_service_account_json(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64 * 1_024
        && value.trim() == value
        && serde_json::from_str::<serde_json::Value>(value).is_ok_and(|json| json.is_object())
}

fn safe_raw_cloud_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 2_048 && !value.chars().any(char::is_control)
}

fn safe_nextdns_profile_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn safe_lineage_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn encode_ai_gateway_pull_cursor(observed_through: DateTime<Utc>) -> String {
    format!("aigw1:{}", observed_through.timestamp_millis())
}

fn parse_ai_gateway_pull_cursor(value: &str) -> Option<DateTime<Utc>> {
    value
        .strip_prefix("aigw1:")?
        .parse::<i64>()
        .ok()
        .and_then(DateTime::from_timestamp_millis)
}

fn encode_litellm_pull_cursor(observed_through: DateTime<Utc>) -> String {
    format!("litellm2:{}", observed_through.timestamp_millis())
}

fn parse_litellm_pull_cursor(value: &str) -> Option<DateTime<Utc>> {
    value
        .strip_prefix("litellm2:")?
        .parse::<i64>()
        .ok()
        .and_then(DateTime::from_timestamp_millis)
}

fn encode_crowdstrike_edr_cursor(observed_through: DateTime<Utc>) -> String {
    format!("ca1:{}", observed_through.timestamp_millis())
}

fn parse_crowdstrike_edr_cursor(value: &str) -> Option<DateTime<Utc>> {
    value
        .strip_prefix("ca1:")?
        .parse::<i64>()
        .ok()
        .and_then(DateTime::from_timestamp_millis)
}

fn encode_microsoft_defender_cursor(observed_through: DateTime<Utc>) -> String {
    format!(
        "microsoft-defender-v1:{}",
        observed_through.timestamp_millis()
    )
}

fn parse_microsoft_defender_cursor(value: &str) -> Option<DateTime<Utc>> {
    value
        .strip_prefix("microsoft-defender-v1:")?
        .parse::<i64>()
        .ok()
        .and_then(DateTime::from_timestamp_millis)
}

#[derive(Debug, Serialize, Deserialize)]
struct CatoNetworksCursor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    marker: Option<String>,
    observed_through: DateTime<Utc>,
    #[serde(default)]
    backlog_hint: bool,
}

fn encode_cato_networks_cursor(
    marker: Option<String>,
    observed_through: DateTime<Utc>,
    backlog_hint: bool,
) -> Result<String> {
    ensure!(
        marker.as_deref().is_none_or(|value| {
            !value.is_empty()
                && value.len() <= 2_048
                && value.trim() == value
                && !value.chars().any(char::is_control)
        }),
        "invalid Cato marker"
    );
    let encoded = serde_json::to_vec(&CatoNetworksCursor {
        marker,
        observed_through,
        backlog_hint,
    })?;
    Ok(format!("cato-events-v1:{}", hex::encode(encoded)))
}

fn parse_cato_networks_cursor(value: &str) -> Option<CatoNetworksCursor> {
    let encoded = value.strip_prefix("cato-events-v1:")?;
    if encoded.is_empty() || encoded.len() > 8_192 {
        return None;
    }
    let bytes = hex::decode(encoded).ok()?;
    let cursor = serde_json::from_slice::<CatoNetworksCursor>(&bytes).ok()?;
    if cursor.marker.as_deref().is_some_and(|marker| {
        marker.is_empty()
            || marker.len() > 2_048
            || marker.trim() != marker
            || marker.chars().any(char::is_control)
    }) {
        return None;
    }
    Some(cursor)
}

async fn run_file(args: RunFileArgs) -> Result<()> {
    ensure!(
        !args.adapter.is_native_cloud() && !args.adapter.is_native_enterprise(),
        "native pull adapters do not accept recorded files"
    );
    let metadata = fs::metadata(&args.file)
        .with_context(|| format!("inspect connector input {}", args.file.display()))?;
    let input = fs::read(&args.file)
        .with_context(|| format!("read connector input {}", args.file.display()))?;
    let key_bytes = fs::read(&args.pseudonymization_key_file).with_context(|| {
        format!(
            "read pseudonymization key {}",
            args.pseudonymization_key_file.display()
        )
    })?;
    let pseudonymization_key = PseudonymizationKey::parse_file(&key_bytes)
        .context("load 32-byte raw or 64-character hexadecimal pseudonymization key")?;
    drop(key_bytes);
    let (descriptor, outcome, cloud, casb_account_id) =
        normalize_run_file(&args, &input, &metadata, pseudonymization_key)?;
    if !args.commit {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "mode": "preview",
                "descriptor": descriptor,
                "stats": outcome.stats,
                "receipt": outcome.batch.receipt,
                "redaction": outcome.redaction,
                "sample": outcome.batch.observations.iter().take(10).collect::<Vec<_>>(),
            }))?
        );
        eprintln!("Preview only: no observations or connector state were written.");
        return Ok(());
    }
    let config = TallyConfig::from_env().context("load Tally configuration")?;
    let api_base = tally_api_base(&config)?;
    let receipt = commit_through_api(
        &collector_http_client()?,
        &api_base,
        &ApiImportSource {
            adapter: args.adapter,
            connector_instance_id: args.connector_instance_id,
            source_lineage_id: args
                .source_lineage_id
                .as_deref()
                .unwrap_or("collector_file"),
            checkpoint: &args.checkpoint,
            input: &input,
            expected_canonical_digest: &outcome.batch.receipt.canonical_digest,
            cloud: cloud.as_ref(),
            casb_account_id: casb_account_id.as_deref(),
        },
    )
    .await?;
    drop(input);
    ensure!(
        receipt.canonical_digest == outcome.batch.receipt.canonical_digest,
        "Tally API normalization did not match the local preview"
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "mode": "commit",
            "run_id": receipt.run_id,
            "batch_id": receipt.batch_id,
            "disposition": receipt.disposition,
            "status": receipt.status,
            "stats": outcome.stats,
            "accepted": receipt.accepted,
            "deduplicated": receipt.deduplicated,
            "findings_updated": receipt.findings_updated,
            "redaction": outcome.redaction,
            "content_retained": receipt.content_retained,
        }))?
    );
    Ok(())
}

fn normalize_run_file(
    args: &RunFileArgs,
    input: &[u8],
    metadata: &fs::Metadata,
    pseudonymization_key: PseudonymizationKey,
) -> Result<(
    ConnectorDescriptor,
    VendorImportOutcome,
    Option<CloudImportSource>,
    Option<String>,
)> {
    validate_cloud_reference_shape(
        args.adapter,
        args.account_id_env.as_deref(),
        args.scope_id_env.as_deref(),
        args.region.as_deref(),
    )
    .map_err(anyhow::Error::msg)?;
    ensure!(
        args.adapter.is_managed_cloud() || args.observed_at.is_none(),
        "--observed-at is only valid for managed-cloud fixtures"
    );
    let descriptor = args.adapter.descriptor();
    let received_at = Utc::now();
    let observed_at = args.observed_at.map_or_else(
        || file_observed_at(metadata).map_err(anyhow::Error::msg),
        Ok,
    )?;
    let cloud = load_cloud_scope(
        args.adapter,
        args.account_id_env.as_deref(),
        args.scope_id_env.as_deref(),
        args.region.as_deref(),
        observed_at,
    )
    .map_err(anyhow::Error::msg)?;
    let casb_account_id = load_casb_account_id(args.adapter, args.account_id_env.as_deref())
        .map_err(anyhow::Error::msg)?;
    let outcome = if let Some(cloud) = &cloud {
        args.adapter.normalize_cloud(
            input,
            &ManagedCloudImportConfig {
                installation_id: args.installation_id,
                connector_instance_id: args.connector_instance_id,
                implementation_version: env!("CARGO_PKG_VERSION").into(),
                source_lineage_id: args.source_lineage_id.clone(),
                observed_at: cloud.observed_at,
                received_at,
                checkpoint: Cursor(args.checkpoint.clone()),
                pseudonymization_key,
                scope: cloud.scope.clone(),
                transport: ManagedCloudTransport::File,
            },
        )
    } else if let Some(account_id) = &casb_account_id {
        args.adapter.normalize_casb(
            input,
            account_id,
            &VendorImportConfig {
                installation_id: args.installation_id,
                connector_instance_id: args.connector_instance_id,
                implementation_version: env!("CARGO_PKG_VERSION").into(),
                source_lineage_id: args.source_lineage_id.clone(),
                received_at,
                checkpoint: Cursor(args.checkpoint.clone()),
                pseudonymization_key,
            },
        )
    } else {
        args.adapter.normalize(
            input,
            &VendorImportConfig {
                installation_id: args.installation_id,
                connector_instance_id: args.connector_instance_id,
                implementation_version: env!("CARGO_PKG_VERSION").into(),
                source_lineage_id: args.source_lineage_id.clone(),
                received_at,
                checkpoint: Cursor(args.checkpoint.clone()),
                pseudonymization_key,
            },
        )
    }
    .context("normalize vendor metadata")?;
    Ok((descriptor, outcome, cloud, casb_account_id))
}

async fn connect_postgres() -> Result<PostgresStore> {
    let config = TallyConfig::from_env().context("load Tally storage configuration")?;
    let postgres = PostgresStore::connect(config.postgres_url.expose())
        .await
        .context("connect to PostgreSQL")?;
    postgres.migrate().await.context("migrate PostgreSQL")?;
    Ok(postgres)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_windows_advance_from_the_checkpoint_and_split_full_windows() {
        let now: DateTime<Utc> = "2026-09-15T11:00:00Z".parse().expect("now");
        let (start, end) = next_event_window(None, now, 3_600)
            .expect("initial window")
            .expect("due");
        assert_eq!(start.to_rfc3339(), "2026-09-15T09:55:00+00:00");
        assert_eq!(end.to_rfc3339(), "2026-09-15T10:00:00+00:00");
        let split = shrink_event_window(start, end).expect("split");
        assert_eq!(split.to_rfc3339(), "2026-09-15T09:57:30+00:00");
        let (next_start, _) = next_event_window(Some(split), now, 3_600)
            .expect("next window")
            .expect("due");
        assert_eq!(next_start, split);
        assert!(
            next_event_window(Some(now), now, 3_600)
                .expect("idle")
                .is_none()
        );
        assert!(shrink_event_window(start, start + chrono::Duration::seconds(1)).is_none());
    }

    #[test]
    fn cato_marker_preserves_the_full_page_hint_and_old_cursors() {
        let now: DateTime<Utc> = "2026-09-15T11:00:00Z".parse().expect("now");
        let encoded = encode_cato_networks_cursor(Some("opaque-marker".into()), now, true)
            .expect("encode marker");
        let cursor = parse_cato_networks_cursor(&encoded).expect("decode marker");
        assert_eq!(cursor.marker.as_deref(), Some("opaque-marker"));
        assert!(cursor.backlog_hint);
        let legacy = format!(
            "cato-events-v1:{}",
            hex::encode(
                serde_json::to_vec(&serde_json::json!({
                    "marker":"opaque-marker", "observed_through":now
                }))
                .expect("legacy cursor")
            )
        );
        assert!(
            !parse_cato_networks_cursor(&legacy)
                .expect("legacy marker")
                .backlog_hint
        );
    }
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write as _;
    use tower::ServiceExt as _;

    #[test]
    fn demo_fixtures_roll_to_a_stable_current_day_without_losing_canaries() {
        let anchor = "2032-04-05T00:00:00Z".parse().expect("timestamp");
        let nextdns = dated_demo_fixture(
            include_bytes!("../../../testdata/connectors/nextdns/v1/input.csv"),
            anchor,
        )
        .expect("dated fixture");
        let zscaler = dated_demo_fixture(
            include_bytes!("../../../testdata/connectors/zscaler/v1/input.ndjson"),
            anchor,
        )
        .expect("dated fixture");
        let palo_alto = dated_demo_fixture(
            include_bytes!("../../../testdata/connectors/palo-alto/v1/input.ndjson"),
            anchor,
        )
        .expect("dated fixture");
        assert!(nextdns.contains("2032-04-05T00:00:00Z"));
        assert!(zscaler.contains("1964736000"));
        assert!(palo_alto.contains("1964736000000000"));
        assert!(nextdns.contains("ULTRA_SECRET_PROMPT_CANARY"));
    }

    #[test]
    fn run_file_requires_every_privacy_boundary_input() {
        assert!(
            Cli::try_parse_from([
                "tally-collector",
                "run-file",
                "--adapter",
                "nextdns",
                "--file",
                "input.csv"
            ])
            .is_err()
        );
    }

    #[test]
    fn descriptor_never_contains_secret_values() {
        let serialized = serde_json::to_string(&VendorAdapter::Zscaler.descriptor()).expect("json");
        assert!(
            serialized
                .contains("Endpoint emails or bounded source-native login names, valid hostnames")
        );
        assert!(!serialized.contains("api_key"));
    }

    #[test]
    fn scheduled_sources_accept_only_environment_names() {
        assert!(safe_environment_name("TALLY_NEXTDNS_SOURCE_FILE"));
        assert!(!safe_environment_name("/Users/operator/private.csv"));
        assert!(!safe_environment_name("tally_nextdns_source_file"));
    }

    #[test]
    fn schedule_command_requires_every_safety_input() {
        assert!(
            Cli::try_parse_from(["tally-collector", "schedule-file", "--adapter", "nextdns"])
                .is_err()
        );
    }

    #[test]
    fn managed_cloud_schedules_require_environment_references() {
        assert!(
            Cli::try_parse_from([
                "tally-collector",
                "schedule-file",
                "--adapter",
                "aws-managed-ai",
                "--source-path-env",
                "TALLY_AWS_AI_INVENTORY_FILE",
                "--account-id-env",
                "TALLY_AWS_ACCOUNT_ID",
                "--region",
                "us-east-1"
            ])
            .is_ok()
        );
        assert!(
            validate_cloud_reference_shape(
                VendorAdapter::AwsManagedAi,
                Some("TALLY_AWS_ACCOUNT_ID"),
                None,
                Some("us-east-1")
            )
            .is_ok()
        );
        assert!(
            validate_cloud_reference_shape(
                VendorAdapter::AzureAiFoundry,
                Some("TALLY_AZURE_SUBSCRIPTION_ID"),
                None,
                Some("eastus2")
            )
            .is_err()
        );
        assert!(
            validate_cloud_reference_shape(
                VendorAdapter::Nextdns,
                Some("TALLY_AWS_ACCOUNT_ID"),
                None,
                Some("us-east-1")
            )
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "tally-collector",
                "schedule-cloud",
                "--adapter",
                "aws-managed-ai-api",
                "--account-id-env",
                "TALLY_AWS_ACCOUNT_ID",
                "--region",
                "us-east-1"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "tally-collector",
                "schedule-cloud",
                "--adapter",
                "azure-openai-api",
                "--account-id-env",
                "TALLY_AZURE_SUBSCRIPTION_ID",
                "--region",
                "eastus2"
            ])
            .is_ok()
        );
    }

    #[test]
    fn native_cloud_auth_supports_default_chains_and_complete_explicit_credentials() {
        assert!(
            validate_cloud_auth_references(
                VendorAdapter::AwsManagedAiApi,
                &CloudCredentialArgs::default()
            )
            .is_ok()
        );
        let aws = CloudCredentialArgs {
            aws_access_key_id_env: Some("TALLY_AWS_ACCESS_KEY_ID".to_owned()),
            aws_secret_access_key_env: Some("TALLY_AWS_SECRET_ACCESS_KEY".to_owned()),
            aws_session_token_env: Some("TALLY_AWS_SESSION_TOKEN".to_owned()),
            ..CloudCredentialArgs::default()
        };
        assert!(validate_cloud_auth_references(VendorAdapter::AwsCloudFlowApi, &aws).is_ok());
        let partial_aws = CloudCredentialArgs {
            aws_access_key_id_env: Some("TALLY_AWS_ACCESS_KEY_ID".to_owned()),
            ..CloudCredentialArgs::default()
        };
        assert!(
            validate_cloud_auth_references(VendorAdapter::AwsManagedAiApi, &partial_aws).is_err()
        );
        let azure = CloudCredentialArgs {
            azure_tenant_id_env: Some("TALLY_AZURE_TENANT_ID".to_owned()),
            azure_client_id_env: Some("TALLY_AZURE_CLIENT_ID".to_owned()),
            azure_client_secret_env: Some("TALLY_AZURE_CLIENT_SECRET".to_owned()),
            ..CloudCredentialArgs::default()
        };
        assert!(
            validate_cloud_auth_references(VendorAdapter::AzureNetworkMappingApi, &azure).is_ok()
        );
        assert!(validate_cloud_auth_references(VendorAdapter::GcpVertexAiApi, &azure).is_err());
        let gcp = CloudCredentialArgs {
            gcp_service_account_json_env: Some("TALLY_GCP_SERVICE_ACCOUNT_JSON".to_owned()),
            ..CloudCredentialArgs::default()
        };
        assert!(validate_cloud_auth_references(VendorAdapter::GcpNetworkMappingApi, &gcp).is_ok());
    }

    #[test]
    fn aws_temporary_credentials_keep_the_session_token() {
        let credentials = JobCredentials(BTreeMap::from([
            (
                "aws_access_key_id".to_owned(),
                "ASIA1234567890ABCDEF".to_owned(),
            ),
            (
                "aws_secret_access_key".to_owned(),
                "0123456789012345678901234567890123456789".to_owned(),
            ),
            ("aws_session_token".to_owned(), "session-token".to_owned()),
        ]));
        let resolved = aws_static_credentials(&credentials)
            .expect("valid credentials")
            .expect("explicit credentials");
        assert_eq!(resolved.session_token.as_deref(), Some("session-token"));
    }

    #[test]
    fn enterprise_file_schedules_keep_raw_scope_out_of_configuration() {
        assert!(
            Cli::try_parse_from([
                "tally-collector",
                "schedule-file",
                "--adapter",
                "cloudflare-casb",
                "--source-path-env",
                "TALLY_CASB_SNAPSHOT_FILE",
                "--account-id-env",
                "TALLY_CLOUDFLARE_ACCOUNT_ID"
            ])
            .is_ok()
        );
        assert!(
            validate_cloud_reference_shape(
                VendorAdapter::CloudflareCasb,
                Some("TALLY_CLOUDFLARE_ACCOUNT_ID"),
                None,
                None
            )
            .is_ok()
        );
        assert!(
            validate_cloud_reference_shape(
                VendorAdapter::CloudflareCasb,
                Some("raw-account-id"),
                None,
                None
            )
            .is_err()
        );
        assert!(
            validate_cloud_reference_shape(VendorAdapter::KubernetesApi, None, None, None).is_ok()
        );
        assert!(
            validate_cloud_reference_shape(
                VendorAdapter::KubernetesApi,
                Some("TALLY_CLUSTER_ID"),
                None,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn native_enterprise_commands_accept_only_reference_names() {
        assert!(
            Cli::try_parse_from([
                "tally-collector",
                "schedule-casb",
                "--account-id-env",
                "TALLY_CLOUDFLARE_ACCOUNT_ID",
                "--api-token-env",
                "TALLY_CLOUDFLARE_API_TOKEN"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from(["tally-collector", "schedule-kubernetes", "--in-cluster"]).is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "tally-collector",
                "schedule-kubernetes",
                "--in-cluster",
                "--api-url-env",
                "TALLY_KUBERNETES_API_URL",
                "--bearer-token-env",
                "TALLY_KUBERNETES_BEARER_TOKEN"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "tally-collector",
                "schedule-kubernetes",
                "--api-url-env",
                "TALLY_KUBERNETES_API_URL"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "tally-collector",
                "schedule-kubernetes",
                "--api-url-env",
                "TALLY_KUBERNETES_API_URL",
                "--bearer-token-env",
                "TALLY_KUBERNETES_BEARER_TOKEN",
                "--ca-file-env",
                "TALLY_KUBERNETES_CA_FILE"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "tally-collector",
                "schedule-litellm",
                "--base-url-env",
                "TALLY_LITELLM_BASE_URL",
                "--api-key-env",
                "TALLY_LITELLM_API_KEY"
            ])
            .is_ok()
        );
        assert!(!safe_environment_name("https://cluster.example:6443"));
        assert!(!safe_environment_name("bearer-token-canary"));
        assert!(!safe_environment_name("https://litellm.example:4000"));
        assert!(!safe_environment_name("sk-litellm-key-canary"));
        assert!(
            Cli::try_parse_from([
                "tally-collector",
                "schedule-crowdstrike-edr",
                "--cloud",
                "eu-1",
                "--client-id-env",
                "TALLY_CROWDSTRIKE_CLIENT_ID",
                "--client-secret-env",
                "TALLY_CROWDSTRIKE_CLIENT_SECRET",
            ])
            .is_ok()
        );
        assert!(VendorAdapter::CrowdstrikeEdr.is_native_enterprise());
        assert!(
            Cli::try_parse_from(["tally-collector", "schedule-zt-gateway"]).is_ok(),
            "DNS analytics uses safe default environment references"
        );
        assert!(
            Cli::try_parse_from([
                "tally-collector",
                "schedule-zt-gateway",
                "--endpoint-url",
                "https://0123456789abcdef.r2.cloudflarestorage.com",
                "--bucket",
                "gateway-http-logs",
                "--access-key-id-env",
                "TALLY_CLOUDFLARE_LOGPUSH_ACCESS_KEY_ID",
                "--secret-access-key-env",
                "TALLY_CLOUDFLARE_LOGPUSH_SECRET_ACCESS_KEY"
            ])
            .is_ok()
        );
    }

    #[test]
    fn combined_gateway_cursor_keeps_only_the_optional_s3_watermark() {
        assert_eq!(
            cloudflare_gateway_s3_cursor("cfzt1:cfs31:616263"),
            Ok("cfs31:616263")
        );
        assert_eq!(cloudflare_gateway_s3_cursor(""), Ok(""));
        assert!(cloudflare_gateway_s3_cursor("cfs31:616263").is_err());
    }

    #[test]
    fn litellm_adapters_normalize_the_fixture_and_reject_recorded_native_files() {
        let input = include_bytes!("../../../testdata/connectors/litellm/v1/input.json");
        let outcome = VendorAdapter::Litellm
            .normalize(
                input,
                &VendorImportConfig {
                    installation_id: Uuid::nil(),
                    connector_instance_id: Uuid::new_v5(
                        &Uuid::NAMESPACE_URL,
                        b"litellm-collector-fixture",
                    ),
                    implementation_version: "1".to_owned(),
                    source_lineage_id: Some("golden-litellm".to_owned()),
                    received_at: "2026-08-18T09:00:00Z".parse().expect("time"),
                    checkpoint: Cursor("fixture:1".to_owned()),
                    pseudonymization_key: PseudonymizationKey::new(&[7_u8; 32]).expect("key"),
                },
            )
            .expect("LiteLLM fixture normalizes");
        assert_eq!(outcome.stats.accepted, 4);
        assert!(VendorAdapter::LitellmApi.is_native_enterprise());
        assert!(!VendorAdapter::Litellm.is_native_enterprise());
        let encoded = serde_json::to_string(&outcome).expect("serialize");
        assert!(encoded.contains("litellm.internal.example"));
        assert!(encoded.contains("gpt-production-routing"));
    }

    #[test]
    fn ai_gateway_adapters_normalize_the_fixture_and_require_native_scheduling() {
        let input =
            include_bytes!("../../../testdata/connectors/cloudflare-ai-gateway/v1/input.json");
        let outcome = VendorAdapter::CloudflareAiGateway
            .normalize(
                input,
                &VendorImportConfig {
                    installation_id: Uuid::nil(),
                    connector_instance_id: Uuid::new_v5(
                        &Uuid::NAMESPACE_URL,
                        b"ai-gateway-collector-fixture",
                    ),
                    implementation_version: "1".to_owned(),
                    source_lineage_id: Some("golden-ai-gateway".to_owned()),
                    received_at: "2026-08-18T09:00:00Z".parse().expect("time"),
                    checkpoint: Cursor("fixture:1".to_owned()),
                    pseudonymization_key: PseudonymizationKey::new(&[7_u8; 32]).expect("key"),
                },
            )
            .expect("AI Gateway fixture normalizes");
        assert_eq!(outcome.stats.accepted, 5);
        assert!(VendorAdapter::CloudflareAiGatewayApi.is_native_enterprise());
        assert!(!VendorAdapter::CloudflareAiGateway.is_native_enterprise());
        let encoded = serde_json::to_string(&outcome).expect("serialize");
        assert!(!encoded.contains("aigw-account-canary"));
        assert!(!encoded.contains("AIGW_GATEWAY_NAME_CANARY"));

        assert!(
            Cli::try_parse_from([
                "tally-collector",
                "schedule-ai-gateway",
                "--account-id-env",
                "TALLY_CLOUDFLARE_ACCOUNT_ID",
                "--api-token-env",
                "TALLY_CLOUDFLARE_AI_GATEWAY_TOKEN"
            ])
            .is_ok()
        );
    }

    #[test]
    fn nextdns_api_schedule_requires_profile_and_accepts_secret_reference() {
        assert!(
            Cli::try_parse_from([
                "tally-collector",
                "schedule-nextdns-api",
                "--profile-id",
                "abc123",
                "--api-key-env",
                "TALLY_NEXTDNS_API_KEY"
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["tally-collector", "schedule-nextdns-api"]).is_err());
    }

    #[test]
    fn legacy_log_pull_schedules_receive_bounded_defaults() {
        let nextdns: ScheduledNextDnsApiConfig = serde_json::from_value(serde_json::json!({
            "kind": "nextdns_api_v1",
            "profile_id": "abc123",
            "source_lineage_id": "nextdns_api",
            "backfill_seconds": "3600"
        }))
        .expect("legacy NextDNS config");
        assert_eq!(nextdns.record_limit, "1000");

        let ai_gateway: ScheduledAiGatewayApiConfig = serde_json::from_value(serde_json::json!({
            "kind": "ai_gateway_api_v1",
            "source_lineage_id": "cloudflare_ai_gateway_api:native"
        }))
        .expect("legacy AI Gateway config");
        assert_eq!(ai_gateway.backfill_seconds, "3600");
        assert_eq!(ai_gateway.record_limit, "1000");
    }

    #[test]
    fn initial_backfill_accepts_at_most_seven_days() {
        assert!(!valid_initial_backfill_seconds(59));
        assert!(valid_initial_backfill_seconds(60));
        assert!(valid_initial_backfill_seconds(604_800));
        assert!(!valid_initial_backfill_seconds(604_801));
    }

    #[test]
    fn receiver_authorization_is_exact_and_content_free() {
        let expected: [u8; 32] = Sha256::digest(b"Bearer receiver-secret").into();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer receiver-secret"),
        );
        assert!(receiver_authorized(&headers, &expected));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer receiver-secret-2"),
        );
        assert!(!receiver_authorized(&headers, &expected));
        assert!(!format!("{:?}", ReceiverFailure::Unauthorized).contains("receiver-secret"));
    }

    #[test]
    fn receiver_decompresses_bounded_gzip_and_recognizes_vendor_probes() {
        let source = br#"{"content":"tests"}"#;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(source).expect("compress");
        let compressed = encoder.finish().expect("finish gzip");
        let decoded = decode_push_payload(&HeaderMap::new(), &compressed).expect("decode");
        assert_eq!(decoded, source);
        assert!(cloudflare_ownership_probe(&decoded));
        assert!(empty_vendor_probe(br#"{"logs":[]}"#));
        assert!(!empty_vendor_probe(br#"{"logs":[{"host":"example.com"}]}"#));
    }

    #[test]
    fn receiver_rejects_unsupported_content_encoding() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("br"));
        assert!(matches!(
            decode_push_payload(&headers, b"metadata"),
            Err(ReceiverFailure::EncodingUnsupported)
        ));
    }

    #[test]
    fn receiver_cli_requires_an_authorization_reference() {
        assert!(
            Cli::try_parse_from([
                "tally-collector",
                "receive",
                "--adapter",
                "cloudflare-gateway",
                "--authorization-env",
                "TALLY_CLOUDFLARE_RECEIVER_AUTHORIZATION"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "tally-collector",
                "receive",
                "--adapter",
                "cloudflare-gateway"
            ])
            .is_err()
        );
    }

    #[tokio::test]
    async fn cloudflare_gzip_ownership_probe_passes_auth_without_ingestion() {
        let authorization = "Bearer receiver-secret";
        let state = ReceiverState {
            client: collector_http_client().expect("client"),
            api_base: Url::parse("http://127.0.0.1:9/api/v1/tally/").expect("URL"),
            adapter: VendorAdapter::CloudflareGateway,
            installation_id: Uuid::nil(),
            connector_instance_id: Uuid::nil(),
            source_lineage_id: "test_push".into(),
            pseudonymization_key: PseudonymizationKey::new(&[7; 32]).expect("key"),
            authorization_sha256: Sha256::digest(authorization.as_bytes()).into(),
        };
        let app = Router::new()
            .route("/ingest", post(receive_push))
            .with_state(state);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(br#"{"content":"tests"}"#)
            .expect("compress");
        let response = app
            .oneshot(
                axum::http::Request::post("/ingest")
                    .header(header::AUTHORIZATION, authorization)
                    .header(header::CONTENT_ENCODING, "gzip")
                    .body(axum::body::Body::from(encoder.finish().expect("gzip")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
