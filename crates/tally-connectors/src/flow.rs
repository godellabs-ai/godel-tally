use std::net::IpAddr;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tally_core::{
    CloudProvider, CloudProviderService, CloudResourceKind, ConnectorRef, DigestAlgorithm,
    EvidenceReceipt, FlowDirection, Hostname, IpAddress, Observation, ObservationKind,
};

use crate::{
    ConnectorDescriptor, ConnectorTransport, ObservationBatch, ReplayCapability,
    VendorImportConfig, VendorImportError, VendorImportOutcome, VendorImportStats,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudFlowProvider {
    Aws,
    Azure,
    Gcp,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudFlowFixture {
    provider: CloudFlowProviderWire,
    account_id: String,
    region: String,
    network_id: String,
    #[serde(default)]
    ignored_records: u64,
    records: Vec<CloudFlowRecord>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CloudFlowProviderWire {
    Aws,
    Azure,
    Gcp,
}

impl CloudFlowProviderWire {
    const fn domain(self) -> CloudProvider {
        match self {
            Self::Aws => CloudProvider::Aws,
            Self::Azure => CloudProvider::Azure,
            Self::Gcp => CloudProvider::Gcp,
        }
    }

    const fn adapter(self) -> CloudFlowProvider {
        match self {
            Self::Aws => CloudFlowProvider::Aws,
            Self::Azure => CloudFlowProvider::Azure,
            Self::Gcp => CloudFlowProvider::Gcp,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudFlowRecord {
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    source_ip: String,
    destination_ip: String,
    #[serde(default)]
    source_hostname: Option<String>,
    #[serde(default)]
    destination_hostname: Option<String>,
    #[serde(default)]
    source_port: Option<u16>,
    #[serde(default)]
    destination_port: Option<u16>,
    protocol: String,
    #[serde(default)]
    packets: Option<u64>,
    #[serde(default)]
    bytes: Option<u64>,
    #[serde(default)]
    bytes_received: Option<u64>,
    direction: FlowDirection,
    decision: FlowDecision,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum FlowDecision {
    Accepted,
    Rejected,
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudMappingFixture {
    provider: CloudFlowProviderWire,
    account_id: String,
    region: String,
    network_id: String,
    records: Vec<CloudMappingRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudMappingRecord {
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    private_ip: String,
    interface_id: String,
    resource_id: String,
    resource_kind: MappedResourceKind,
    #[serde(default)]
    hostname: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum MappedResourceKind {
    NetworkInterface,
    ModelDeployment,
    InferenceEndpoint,
    Workload,
}

impl MappedResourceKind {
    const fn domain(self) -> CloudResourceKind {
        match self {
            Self::NetworkInterface => CloudResourceKind::NetworkInterface,
            Self::ModelDeployment => CloudResourceKind::ModelDeployment,
            Self::InferenceEndpoint => CloudResourceKind::InferenceEndpoint,
            Self::Workload => CloudResourceKind::Workload,
        }
    }
}

#[derive(Serialize)]
struct CanonicalFlow<'a> {
    provider: CloudProvider,
    network_key: &'a str,
    source_key: &'a str,
    destination_key: &'a str,
    source_hostname: Option<&'a str>,
    destination_hostname: Option<&'a str>,
    protocol: &'a str,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    packets: Option<u64>,
    bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_received: Option<u64>,
    direction: FlowDirection,
    decision: FlowDecision,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
}

#[derive(Serialize)]
struct CanonicalMapping<'a> {
    provider: CloudProvider,
    network_key: &'a str,
    endpoint_key: &'a str,
    resource_key: &'a str,
    resource_kind: MappedResourceKind,
    hostname: Option<&'a str>,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
}

pub fn cloud_flow_descriptor(provider: CloudFlowProvider) -> ConnectorDescriptor {
    let (connector_type, display_name, vendor, product) = match provider {
        CloudFlowProvider::Aws => (
            "aws_vpc_flow_fixture_v1",
            "AWS VPC flow metadata",
            "Amazon Web Services",
            "VPC Flow Logs",
        ),
        CloudFlowProvider::Azure => (
            "azure_vnet_flow_fixture_v1",
            "Azure virtual network flow metadata",
            "Microsoft Azure",
            "Virtual Network Flow Logs",
        ),
        CloudFlowProvider::Gcp => (
            "gcp_vpc_flow_fixture_v1",
            "Google VPC flow metadata",
            "Google Cloud",
            "VPC Flow Logs",
        ),
    };
    flow_descriptor(connector_type, display_name, vendor, product, "flow_window")
}

pub fn cloud_mapping_descriptor(provider: CloudFlowProvider) -> ConnectorDescriptor {
    let (connector_type, display_name, vendor, product) = match provider {
        CloudFlowProvider::Aws => (
            "aws_network_mapping_fixture_v1",
            "AWS network resource mappings",
            "Amazon Web Services",
            "EC2 network interfaces",
        ),
        CloudFlowProvider::Azure => (
            "azure_network_mapping_fixture_v1",
            "Azure network resource mappings",
            "Microsoft Azure",
            "Network interfaces",
        ),
        CloudFlowProvider::Gcp => (
            "gcp_network_mapping_fixture_v1",
            "Google network resource mappings",
            "Google Cloud",
            "Compute network interfaces",
        ),
    };
    let mut descriptor = flow_descriptor(
        connector_type,
        display_name,
        vendor,
        product,
        "mapping_validity",
    );
    descriptor
        .requested_fields
        .push("validated endpoint hostname when the provider exposes one".to_owned());
    descriptor
        .prohibited_fields
        .retain(|field| !field.starts_with("hostnames,"));
    descriptor
        .prohibited_fields
        .push("DNS aliases, tags, labels, display names, and unvalidated host strings".to_owned());
    "Addresses and provider identifiers are installation-HMAC pseudonymized in memory; validated endpoint hostnames are retained for attribution; payloads, aliases, labels, other names, raw identifiers, and source bytes are discarded."
        .clone_into(&mut descriptor.privacy_contract);
    descriptor
}

pub fn cloud_flow_api_descriptor(provider: CloudFlowProvider) -> ConnectorDescriptor {
    let (connector_type, display_name, permissions): (&str, &str, &[&str]) = match provider {
        CloudFlowProvider::Aws => (
            "aws_vpc_flow_api_v1",
            "AWS VPC flow metadata native pull",
            &["ec2:DescribeFlowLogs", "logs:FilterLogEvents"],
        ),
        CloudFlowProvider::Azure => (
            "azure_vnet_flow_api_v1",
            "Azure virtual network flow metadata native pull",
            &[
                "Microsoft.Network/virtualNetworks/read",
                "Microsoft.OperationalInsights/workspaces/read",
                "Microsoft.OperationalInsights/workspaces/query/read",
                "Microsoft.OperationalInsights/workspaces/query/NTANetAnalytics/read",
            ],
        ),
        CloudFlowProvider::Gcp => (
            "gcp_vpc_flow_api_v1",
            "Google VPC flow metadata native pull",
            &["logging.logEntries.list"],
        ),
    };
    native_flow_descriptor(
        cloud_flow_descriptor(provider),
        connector_type,
        display_name,
        permissions,
    )
}

pub fn cloud_mapping_api_descriptor(provider: CloudFlowProvider) -> ConnectorDescriptor {
    let (connector_type, display_name, permissions): (&str, &str, &[&str]) = match provider {
        CloudFlowProvider::Aws => (
            "aws_network_mapping_api_v1",
            "AWS network resource mapping native pull",
            &["ec2:DescribeNetworkInterfaces"],
        ),
        CloudFlowProvider::Azure => (
            "azure_network_mapping_api_v1",
            "Azure network resource mapping native pull",
            &[
                "Microsoft.Network/virtualNetworks/read",
                "Microsoft.Network/networkInterfaces/read",
                "Microsoft.Compute/virtualMachines/read",
            ],
        ),
        CloudFlowProvider::Gcp => (
            "gcp_network_mapping_api_v1",
            "Google network resource mapping native pull",
            &["compute.instances.list"],
        ),
    };
    native_flow_descriptor(
        cloud_mapping_descriptor(provider),
        connector_type,
        display_name,
        permissions,
    )
}

fn native_flow_descriptor(
    mut descriptor: ConnectorDescriptor,
    connector_type: &str,
    display_name: &str,
    permissions: &[&str],
) -> ConnectorDescriptor {
    connector_type.clone_into(&mut descriptor.connector_type);
    display_name.clone_into(&mut descriptor.display_name);
    descriptor.transport = ConnectorTransport::Pull;
    descriptor.required_permissions = permissions
        .iter()
        .map(|permission| (*permission).to_owned())
        .collect();
    "versioned UTC watermark with bounded overlap replay; provider page tokens are discarded"
        .clone_into(&mut descriptor.cursor_semantics);
    descriptor.replay_capability = ReplayCapability::OverlapWindow;
    descriptor
}

fn flow_descriptor(
    connector_type: &str,
    display_name: &str,
    vendor: &str,
    product: &str,
    record_variant: &str,
) -> ConnectorDescriptor {
    ConnectorDescriptor {
        connector_type: connector_type.to_owned(),
        display_name: display_name.to_owned(),
        implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
        source_vendor: vendor.to_owned(),
        source_product: product.to_owned(),
        record_variants: vec![record_variant.to_owned()],
        transport: ConnectorTransport::File,
        required_permissions: vec!["read-only network metadata export".to_owned()],
        requested_fields: vec![
            "bounded validity window".to_owned(),
            "network-scoped endpoint addresses".to_owned(),
            "bounded protocol, ports, direction, decision, and counters".to_owned(),
            "provider resource mapping identifier when applicable".to_owned(),
            "validated source or destination hostname when the provider exposes one".to_owned(),
            "source and destination IPs for actionable correlated findings".to_owned(),
        ],
        prohibited_fields: vec![
            "packet or application payloads".to_owned(),
            "raw account, network, interface, or resource identifiers".to_owned(),
            "DNS aliases, tags, labels, display names, and unvalidated host strings".to_owned(),
            "source response bytes".to_owned(),
        ],
        cursor_semantics: "immutable export checkpoint with deterministic overlap replay".to_owned(),
        replay_capability: ReplayCapability::FileReplay,
        health_capabilities: vec!["mapping/flow freshness".to_owned(), "normalization quality".to_owned()],
        coverage_capabilities: vec!["provider account and network scope".to_owned(), "valid time window".to_owned()],
        privacy_contract: "Provider identifiers are installation-HMAC pseudonymized in memory. Validated source/destination IPs and endpoint hostnames remain transient unless exact AI evidence correlation promotes them into an actionable finding; payloads, aliases, labels, other names, raw provider identifiers, and source bytes are discarded.".to_owned(),
    }
}

/// Imports a strict provider-neutral projection of AWS, Azure, or Google flow metadata.
///
/// # Errors
///
/// Returns [`VendorImportError`] when the envelope, provider, window, endpoint, protocol, counters,
/// or admission batch violates the bounded privacy contract.
pub fn import_cloud_flow_json(
    input: &[u8],
    provider: CloudFlowProvider,
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    import_cloud_flow_json_inner(input, provider, config, false)
}

/// Imports a native provider projection with a pull-connector identity.
///
/// # Errors
///
/// Returns [`VendorImportError`] under the same fail-closed contract as
/// [`import_cloud_flow_json`].
pub fn import_cloud_flow_api_json(
    input: &[u8],
    provider: CloudFlowProvider,
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    import_cloud_flow_json_inner(input, provider, config, true)
}

fn import_cloud_flow_json_inner(
    input: &[u8],
    provider: CloudFlowProvider,
    config: &VendorImportConfig,
    native: bool,
) -> Result<VendorImportOutcome, VendorImportError> {
    validate_input_size(input)?;
    let fixture: CloudFlowFixture =
        serde_json::from_slice(input).map_err(|_| VendorImportError::MalformedRecord { row: 1 })?;
    if fixture.provider.adapter() != provider {
        return Err(VendorImportError::InvalidField {
            row: 1,
            field: "provider",
        });
    }
    let context = flow_context(
        fixture.provider,
        &fixture.account_id,
        &fixture.region,
        &fixture.network_id,
        config,
        1,
    )?;
    let records_read = u64::try_from(fixture.records.len())
        .ok()
        .and_then(|records| records.checked_add(fixture.ignored_records))
        .filter(|records| *records <= crate::MAX_BATCH_OBSERVATIONS as u64)
        .ok_or(VendorImportError::InvalidField {
            row: 1,
            field: "record_count",
        })?;
    let mut observations = Vec::with_capacity(fixture.records.len());
    let connector_type = connector_type(fixture.provider.domain(), false, native);
    for (index, record) in fixture.records.into_iter().enumerate() {
        observations.push(normalize_flow(
            &record,
            &context,
            config,
            connector_type,
            index + 1,
        )?);
    }
    finish_flow_import(observations, records_read, connector_type, config)
}

/// Imports a strict provider-neutral projection of cloud endpoint-to-resource mappings.
///
/// # Errors
///
/// Returns [`VendorImportError`] when the envelope, provider, validity, private endpoint, resource
/// identifier, or admission batch violates the bounded privacy contract.
pub fn import_cloud_mapping_json(
    input: &[u8],
    provider: CloudFlowProvider,
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    import_cloud_mapping_json_inner(input, provider, config, false)
}

/// Imports a native provider mapping projection with a pull-connector identity.
///
/// # Errors
///
/// Returns [`VendorImportError`] under the same fail-closed contract as
/// [`import_cloud_mapping_json`].
pub fn import_cloud_mapping_api_json(
    input: &[u8],
    provider: CloudFlowProvider,
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    import_cloud_mapping_json_inner(input, provider, config, true)
}

fn import_cloud_mapping_json_inner(
    input: &[u8],
    provider: CloudFlowProvider,
    config: &VendorImportConfig,
    native: bool,
) -> Result<VendorImportOutcome, VendorImportError> {
    validate_input_size(input)?;
    let fixture: CloudMappingFixture =
        serde_json::from_slice(input).map_err(|_| VendorImportError::MalformedRecord { row: 1 })?;
    if fixture.provider.adapter() != provider {
        return Err(VendorImportError::InvalidField {
            row: 1,
            field: "provider",
        });
    }
    let context = flow_context(
        fixture.provider,
        &fixture.account_id,
        &fixture.region,
        &fixture.network_id,
        config,
        1,
    )?;
    let records_read = fixture.records.len() as u64;
    let mut observations = Vec::with_capacity(fixture.records.len());
    let connector_type = connector_type(fixture.provider.domain(), true, native);
    for (index, record) in fixture.records.into_iter().enumerate() {
        observations.push(normalize_mapping(
            &record,
            &context,
            config,
            connector_type,
            index + 1,
        )?);
    }
    finish_flow_import(observations, records_read, connector_type, config)
}

struct FlowContext {
    provider: CloudProvider,
    region: String,
    account_key: String,
    network_key: String,
}

fn flow_context(
    provider: CloudFlowProviderWire,
    account_id: &str,
    region: &str,
    network_id: &str,
    config: &VendorImportConfig,
    row: usize,
) -> Result<FlowContext, VendorImportError> {
    validate_identifier(account_id, row, "account_id")?;
    validate_identifier(network_id, row, "network_id")?;
    if region.is_empty()
        || region.len() > 63
        || !region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(VendorImportError::InvalidField {
            row,
            field: "region",
        });
    }
    Ok(FlowContext {
        provider: provider.domain(),
        region: region.to_owned(),
        account_key: config
            .pseudonymization_key
            .pseudonym_exact("cloud_account", account_id),
        network_key: config.pseudonymization_key.pseudonym_exact(
            "cloud_network",
            &format!(
                "{}:{account_id}:{region}:{network_id}",
                provider_name(provider)
            ),
        ),
    })
}

fn validate_flow_counters(record: &CloudFlowRecord, row: usize) -> Result<(), VendorImportError> {
    if record.packets == Some(0)
        || [record.packets, record.bytes, record.bytes_received]
            .into_iter()
            .flatten()
            .any(|counter| counter > MAX_FLOW_COUNTER)
    {
        return Err(VendorImportError::InvalidField {
            row,
            field: "counters",
        });
    }
    Ok(())
}

fn flow_identity_bytes(
    record: &CloudFlowRecord,
    provider: CloudProvider,
) -> (Option<u64>, Option<u64>) {
    // Older Azure collectors hashed the sum, omitting zero. Preserve replay identity while
    // storing the corrected directions. Counters have already passed the bounded validation.
    if provider == CloudProvider::Azure {
        let total = record.bytes.unwrap_or(0) + record.bytes_received.unwrap_or(0);
        ((total > 0).then_some(total), None)
    } else {
        (record.bytes, record.bytes_received)
    }
}

fn normalize_flow(
    record: &CloudFlowRecord,
    context: &FlowContext,
    config: &VendorImportConfig,
    connector_type: &'static str,
    row: usize,
) -> Result<Observation, VendorImportError> {
    validate_flow_window(record.window_start, record.window_end, row)?;
    let source_ip = parse_ip(&record.source_ip, row, "source_ip")?;
    let destination_ip = parse_ip(&record.destination_ip, row, "destination_ip")?;
    let protocol = safe_protocol(&record.protocol, row)?;
    let source_hostname = record
        .source_hostname
        .as_deref()
        .map(Hostname::parse)
        .transpose()
        .map_err(|_| VendorImportError::InvalidField {
            row,
            field: "source_hostname",
        })?;
    let destination_hostname = record
        .destination_hostname
        .as_deref()
        .map(Hostname::parse)
        .transpose()
        .map_err(|_| VendorImportError::InvalidField {
            row,
            field: "destination_hostname",
        })?;
    validate_flow_counters(record, row)?;
    let source_key = endpoint_key(context, source_ip, config);
    let destination_key = endpoint_key(context, destination_ip, config);
    let (identity_bytes, identity_received) = flow_identity_bytes(record, context.provider);
    let canonical = CanonicalFlow {
        provider: context.provider,
        network_key: &context.network_key,
        source_key: &source_key,
        destination_key: &destination_key,
        source_hostname: source_hostname.as_ref().map(Hostname::as_str),
        destination_hostname: destination_hostname.as_ref().map(Hostname::as_str),
        protocol,
        source_port: record.source_port,
        destination_port: record.destination_port,
        packets: record.packets,
        bytes: identity_bytes,
        bytes_received: identity_received,
        direction: record.direction,
        decision: record.decision,
        window_start: record.window_start,
        window_end: record.window_end,
    };
    let digest = canonical_digest(&canonical)?;
    let mut observation = base_observation(
        config,
        connector_type,
        ObservationKind::NetworkFlow,
        record.window_start,
        &digest,
    );
    observation.cloud.provider = Some(context.provider);
    observation.cloud.account_key = Some(context.account_key.clone());
    observation.cloud.region = Some(context.region.clone());
    observation.cloud.usage_kind = Some(tally_core::CloudUsageKind::NetworkFlow);
    observation.network.network_key = Some(context.network_key.clone());
    observation.network.source_endpoint_key = Some(source_key);
    observation.network.destination_endpoint_key = Some(destination_key);
    observation.network.protocol = Some(protocol.to_owned());
    observation.network.source_port = record.source_port;
    observation.network.destination_port = record.destination_port;
    observation.network.packets = record.packets;
    observation.network.bytes_sent = record.bytes;
    observation.network.bytes_received = record.bytes_received;
    observation.network.direction = Some(record.direction);
    observation.network.valid_until = Some(record.window_end);
    observation.actor.hostname = source_hostname.map(|value| value.as_str().to_owned());
    observation.actor.source_ip = Some(IpAddress::parse(&source_ip.to_string()).map_err(|_| {
        VendorImportError::InvalidField {
            row,
            field: "source_ip",
        }
    })?);
    observation.destination.host = destination_hostname;
    observation.destination.ip =
        Some(IpAddress::parse(&destination_ip.to_string()).map_err(|_| {
            VendorImportError::InvalidField {
                row,
                field: "destination_ip",
            }
        })?);
    observation.destination.port = record.destination_port;
    observation.cloud.provider_service = flow_provider_service(&observation);
    observation.outcome.action = Some(
        match record.decision {
            FlowDecision::Accepted => "accepted",
            FlowDecision::Rejected => "rejected",
            FlowDecision::Unknown => "unknown",
        }
        .to_owned(),
    );
    Ok(observation)
}

fn flow_provider_service(observation: &Observation) -> Option<CloudProviderService> {
    // Azure's native Traffic Analytics projection supplies this validated service family from
    // its per-address Cognitive Services tag. Preserve the binding even when the small embedded
    // fingerprint registry lacks Azure domains. This remains NetworkFlow evidence, not an AI
    // invocation; generic Azure TLS traffic and lookalike hostnames stay unclassified.
    (observation.cloud.provider == Some(CloudProvider::Azure)
        && observation.network.protocol.as_deref() == Some("tcp")
        && observation.destination.port == Some(443)
        && observation.destination.host.as_ref().is_some_and(|host| {
            host.as_str() == "openai.azure.com" || host.as_str().ends_with(".openai.azure.com")
        }))
    .then_some(CloudProviderService::AzureOpenai)
}

fn normalize_mapping(
    record: &CloudMappingRecord,
    context: &FlowContext,
    config: &VendorImportConfig,
    connector_type: &'static str,
    row: usize,
) -> Result<Observation, VendorImportError> {
    validate_window(record.valid_from, record.valid_until, row)?;
    let private_ip = parse_ip(&record.private_ip, row, "private_ip")?;
    if !is_private(private_ip) {
        return Err(VendorImportError::InvalidField {
            row,
            field: "private_ip",
        });
    }
    validate_identifier(&record.interface_id, row, "interface_id")?;
    validate_identifier(&record.resource_id, row, "resource_id")?;
    let hostname = record
        .hostname
        .as_deref()
        .map(Hostname::parse)
        .transpose()
        .map_err(|_| VendorImportError::InvalidField {
            row,
            field: "hostname",
        })?;
    let endpoint_key = endpoint_key(context, private_ip, config);
    let resource_key = config
        .pseudonymization_key
        .pseudonym_exact("cloud_resource", &record.resource_id);
    let canonical = CanonicalMapping {
        provider: context.provider,
        network_key: &context.network_key,
        endpoint_key: &endpoint_key,
        resource_key: &resource_key,
        resource_kind: record.resource_kind,
        hostname: hostname.as_ref().map(Hostname::as_str),
        valid_from: record.valid_from,
        valid_until: record.valid_until,
    };
    let digest = canonical_digest(&canonical)?;
    let mut observation = base_observation(
        config,
        connector_type,
        ObservationKind::NetworkMapping,
        record.valid_from,
        &digest,
    );
    observation.cloud.provider = Some(context.provider);
    observation.cloud.account_key = Some(context.account_key.clone());
    observation.cloud.region = Some(context.region.clone());
    observation.cloud.resource_kind = Some(record.resource_kind.domain());
    observation.network.network_key = Some(context.network_key.clone());
    observation.network.destination_endpoint_key = Some(endpoint_key);
    observation.network.mapped_resource_key = Some(resource_key);
    observation.network.valid_until = Some(record.valid_until);
    // A mapping describes the resource at the mapped address. Preserve its provider hostname as
    // the server endpoint; actor.hostname is reserved for source/client devices from usage logs.
    observation.destination.host = hostname;
    observation.outcome.action = Some("address_mapped".to_owned());
    Ok(observation)
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
            "godel-tally:cloud-flow:{}:{}:{digest}",
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

fn finish_flow_import(
    mut observations: Vec<Observation>,
    records_read: u64,
    connector_type: &'static str,
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    if observations.is_empty() {
        return Err(VendorImportError::NoRecords);
    }
    observations.sort_by_key(|observation| observation.observation_id);
    observations.dedup_by_key(|observation| observation.observation_id);
    let accepted = observations.len() as u64;
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
            discarded_fields: vec![
                "raw IP, account, network, interface, and resource identifiers".to_owned(),
                "packet payloads, hostnames, DNS names, tags, labels, and display names".to_owned(),
                "source response bytes".to_owned(),
            ],
            source_bytes_retained: false,
        },
    })
}

fn endpoint_key(context: &FlowContext, address: IpAddr, config: &VendorImportConfig) -> String {
    config.pseudonymization_key.pseudonym_exact(
        "network_endpoint",
        &format!(
            "{}:{}:{}:{}",
            provider_name_from_domain(context.provider),
            context.account_key,
            context.network_key,
            address
        ),
    )
}

const MAX_FLOW_COUNTER: u64 = 1_000_000_000_000_000;

fn validate_input_size(input: &[u8]) -> Result<(), VendorImportError> {
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

fn validate_window(
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    row: usize,
) -> Result<(), VendorImportError> {
    if end <= start || end - start > Duration::hours(1) || start > Utc::now() + Duration::minutes(5)
    {
        return Err(VendorImportError::InvalidField {
            row,
            field: "validity_window",
        });
    }
    Ok(())
}

fn validate_flow_window(
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    row: usize,
) -> Result<(), VendorImportError> {
    // Google Cloud represents single-packet dropped flows as point observations with identical
    // first/last packet timestamps. They are valid flow evidence, while reversed or overly broad
    // windows remain invalid. Resource mappings continue to require a positive validity interval.
    if end < start || end - start > Duration::hours(1) || start > Utc::now() + Duration::minutes(5)
    {
        return Err(VendorImportError::InvalidField {
            row,
            field: "validity_window",
        });
    }
    Ok(())
}

fn parse_ip(value: &str, row: usize, field: &'static str) -> Result<IpAddr, VendorImportError> {
    value
        .parse()
        .map_err(|_| VendorImportError::InvalidField { row, field })
}

fn is_private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private(),
        IpAddr::V6(address) => (address.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn safe_protocol(value: &str, row: usize) -> Result<&'static str, VendorImportError> {
    match value.to_ascii_lowercase().as_str() {
        "tcp" | "6" => Ok("tcp"),
        "udp" | "17" => Ok("udp"),
        "icmp" | "1" | "58" => Ok("icmp"),
        "other" => Ok("other"),
        _ => Err(VendorImportError::InvalidField {
            row,
            field: "protocol",
        }),
    }
}

fn canonical_digest(value: &impl Serialize) -> Result<String, VendorImportError> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(value).map_err(|_| VendorImportError::Serialization)?,
    )))
}

const fn connector_type(provider: CloudProvider, mapping: bool, native: bool) -> &'static str {
    match (provider, mapping, native) {
        (CloudProvider::Aws, false, false) => "aws_vpc_flow_fixture_v1",
        (CloudProvider::Azure, false, false) => "azure_vnet_flow_fixture_v1",
        (CloudProvider::Gcp, false, false) => "gcp_vpc_flow_fixture_v1",
        (CloudProvider::Aws, true, false) => "aws_network_mapping_fixture_v1",
        (CloudProvider::Azure, true, false) => "azure_network_mapping_fixture_v1",
        (CloudProvider::Gcp, true, false) => "gcp_network_mapping_fixture_v1",
        (CloudProvider::Aws, false, true) => "aws_vpc_flow_api_v1",
        (CloudProvider::Azure, false, true) => "azure_vnet_flow_api_v1",
        (CloudProvider::Gcp, false, true) => "gcp_vpc_flow_api_v1",
        (CloudProvider::Aws, true, true) => "aws_network_mapping_api_v1",
        (CloudProvider::Azure, true, true) => "azure_network_mapping_api_v1",
        (CloudProvider::Gcp, true, true) => "gcp_network_mapping_api_v1",
    }
}

const fn provider_name(provider: CloudFlowProviderWire) -> &'static str {
    match provider {
        CloudFlowProviderWire::Aws => "aws",
        CloudFlowProviderWire::Azure => "azure",
        CloudFlowProviderWire::Gcp => "gcp",
    }
}

const fn provider_name_from_domain(provider: CloudProvider) -> &'static str {
    match provider {
        CloudProvider::Aws => "aws",
        CloudProvider::Azure => "azure",
        CloudProvider::Gcp => "gcp",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cursor, PseudonymizationKey};
    use uuid::Uuid;

    fn config() -> VendorImportConfig {
        VendorImportConfig {
            installation_id: Uuid::parse_str("018f6cd4-4aaf-7bb4-a3b2-a7524ec43711").unwrap(),
            connector_instance_id: Uuid::parse_str("018f6cd4-4aaf-7bb4-a3b2-a7524ec43741").unwrap(),
            implementation_version: "1.0.0".to_owned(),
            source_lineage_id: Some("fixture".to_owned()),
            received_at: "2026-08-13T10:05:00Z".parse().unwrap(),
            checkpoint: Cursor("fixture-window".to_owned()),
            pseudonymization_key: PseudonymizationKey::new(&[7; 32]).unwrap(),
        }
    }

    #[test]
    fn directional_flow_bytes_preserve_zero_missing_and_reverse_traffic() {
        let mut input: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../testdata/connectors/azure-cloud-flow/v1/input.json"
        ))
        .expect("fixture");
        input["records"][0]["bytes"] = serde_json::json!(0);
        input["records"][0]["bytes_received"] = serde_json::json!(256);
        let outcome = import_cloud_flow_json(
            &serde_json::to_vec(&input).expect("input"),
            CloudFlowProvider::Azure,
            &config(),
        )
        .expect("flow");
        assert_eq!(outcome.batch.observations[0].network.bytes_sent, Some(0));
        assert_eq!(
            outcome.batch.observations[0].network.bytes_received,
            Some(256)
        );
        let directional_id = outcome.batch.observations[0].observation_id;
        let mut legacy = input.clone();
        legacy["records"][0]["bytes"] = serde_json::json!(256);
        legacy["records"][0]
            .as_object_mut()
            .expect("record")
            .remove("bytes_received");
        let replay = import_cloud_flow_json(
            &serde_json::to_vec(&legacy).expect("input"),
            CloudFlowProvider::Azure,
            &config(),
        )
        .expect("legacy flow");
        assert_eq!(
            replay.batch.observations[0].observation_id, directional_id,
            "direction fix must not double-count previously imported Azure flows"
        );
        input["records"][0]
            .as_object_mut()
            .expect("record")
            .remove("bytes");
        let outcome = import_cloud_flow_json(
            &serde_json::to_vec(&input).expect("input"),
            CloudFlowProvider::Azure,
            &config(),
        )
        .expect("flow");
        assert_eq!(outcome.batch.observations[0].network.bytes_sent, None);
        assert_eq!(
            outcome.batch.observations[0].network.bytes_received,
            Some(256)
        );
    }

    #[test]
    fn azure_openai_flow_service_binding_is_narrow_and_not_an_invocation() {
        for (provider, host, protocol, port, expected) in [
            ("azure", "openai.azure.com", "tcp", 443, true),
            ("azure", "account.openai.azure.com", "tcp", 443, true),
            ("azure", "openai.azure.com.evil.example", "tcp", 443, false),
            ("azure", "notopenai.azure.com", "tcp", 443, false),
            ("azure", "storage.example.com", "tcp", 443, false),
            ("aws", "openai.azure.com", "tcp", 443, false),
            ("azure", "openai.azure.com", "udp", 443, false),
            ("azure", "openai.azure.com", "tcp", 8443, false),
        ] {
            let data = serde_json::to_vec(&serde_json::json!({
                "provider": provider, "account_id": "111122223333", "region": "test-region",
                "network_id": "test-network", "records": [{
                    "window_start": "2026-08-13T10:00:00Z", "window_end": "2026-08-13T10:05:00Z",
                    "source_ip": "10.0.0.4", "destination_ip": "20.125.157.138",
                    "destination_hostname": host, "destination_port": port,
                    "protocol": protocol, "direction": "egress", "decision": "accepted"
                }]
            }))
            .unwrap();
            let adapter = if provider == "azure" {
                CloudFlowProvider::Azure
            } else {
                CloudFlowProvider::Aws
            };
            let imported = import_cloud_flow_api_json(&data, adapter, &config()).unwrap();
            let observation = &imported.batch.observations[0];
            assert_eq!(
                observation.cloud.provider_service,
                expected.then_some(CloudProviderService::AzureOpenai)
            );
            assert_eq!(observation.kind, ObservationKind::NetworkFlow);
            assert_eq!(
                observation.cloud.usage_kind,
                Some(tally_core::CloudUsageKind::NetworkFlow)
            );
            assert!(!observation.service.ai_request);
        }
    }

    #[test]
    fn flow_retains_actionable_ips_while_mapping_discards_raw_provider_ids() {
        let flow = br#"{"provider":"aws","account_id":"111122223333","region":"us-east-1","network_id":"vpc-raw","records":[{"window_start":"2026-08-13T10:00:00Z","window_end":"2026-08-13T10:05:00Z","source_ip":"10.0.0.10","destination_ip":"10.0.0.20","source_port":49152,"destination_port":443,"protocol":"tcp","packets":7,"bytes":1024,"direction":"egress","decision":"accepted"}]}"#;
        let mapping = br#"{"provider":"aws","account_id":"111122223333","region":"us-east-1","network_id":"vpc-raw","records":[{"valid_from":"2026-08-13T10:00:00Z","valid_until":"2026-08-13T11:00:00Z","private_ip":"10.0.0.20","interface_id":"eni-raw-CONTENT_CANARY","resource_id":"arn:aws:sagemaker:us-east-1:111122223333:endpoint/private-name","resource_kind":"inference_endpoint","hostname":"MODEL-HOST-1.INTERNAL"}]}"#;
        let flow = import_cloud_flow_json(flow, CloudFlowProvider::Aws, &config()).unwrap();
        let mapping =
            import_cloud_mapping_json(mapping, CloudFlowProvider::Aws, &config()).unwrap();
        assert_eq!(
            mapping.batch.observations[0].cloud.resource_kind,
            Some(CloudResourceKind::InferenceEndpoint)
        );
        assert_eq!(
            mapping.batch.observations[0]
                .destination
                .host
                .as_ref()
                .map(Hostname::as_str),
            Some("model-host-1.internal")
        );
        assert_eq!(
            flow.batch.observations[0]
                .actor
                .source_ip
                .as_ref()
                .map(IpAddress::as_str),
            Some("10.0.0.10")
        );
        assert_eq!(
            flow.batch.observations[0]
                .destination
                .ip
                .as_ref()
                .map(IpAddress::as_str),
            Some("10.0.0.20")
        );
        let serialized = serde_json::to_string(&mapping).unwrap();
        for forbidden in [
            "10.0.0.20",
            "111122223333",
            "vpc-raw",
            "eni-raw",
            "private-name",
            "CONTENT_CANARY",
        ] {
            assert!(!serialized.contains(forbidden));
        }
        assert!(serialized.contains("p1_"));
    }

    #[test]
    fn account_and_network_namespaces_prevent_endpoint_collisions() {
        let source = br#"{"provider":"aws","account_id":"111122223333","region":"us-east-1","network_id":"vpc-a","records":[{"window_start":"2026-08-13T10:00:00Z","window_end":"2026-08-13T10:05:00Z","source_ip":"10.0.0.10","destination_ip":"10.0.0.20","protocol":"tcp","direction":"lateral","decision":"accepted"}]}"#;
        let other = br#"{"provider":"aws","account_id":"111122223333","region":"us-east-1","network_id":"vpc-b","records":[{"window_start":"2026-08-13T10:00:00Z","window_end":"2026-08-13T10:05:00Z","source_ip":"10.0.0.10","destination_ip":"10.0.0.20","protocol":"tcp","direction":"lateral","decision":"accepted"}]}"#;
        let other_account = br#"{"provider":"aws","account_id":"444455556666","region":"us-east-1","network_id":"vpc-a","records":[{"window_start":"2026-08-13T10:00:00Z","window_end":"2026-08-13T10:05:00Z","source_ip":"10.0.0.10","destination_ip":"10.0.0.20","protocol":"tcp","direction":"lateral","decision":"accepted"}]}"#;
        let first = import_cloud_flow_json(source, CloudFlowProvider::Aws, &config()).unwrap();
        let second = import_cloud_flow_json(other, CloudFlowProvider::Aws, &config()).unwrap();
        let third =
            import_cloud_flow_json(other_account, CloudFlowProvider::Aws, &config()).unwrap();
        assert_ne!(
            first.batch.observations[0].network.source_endpoint_key,
            second.batch.observations[0].network.source_endpoint_key
        );
        assert_ne!(
            first.batch.observations[0].network.source_endpoint_key,
            third.batch.observations[0].network.source_endpoint_key
        );
    }

    #[test]
    fn unsafe_windows_unknown_fields_and_public_mappings_fail_closed() {
        let public = br#"{"provider":"gcp","account_id":"tally-project","region":"us-central1","network_id":"default","records":[{"valid_from":"2026-08-13T10:00:00Z","valid_until":"2026-08-13T11:00:00Z","private_ip":"8.8.8.8","interface_id":"nic","resource_id":"projects/tally-project/zones/us-central1-a/instances/x","resource_kind":"workload"}]}"#;
        assert!(import_cloud_mapping_json(public, CloudFlowProvider::Gcp, &config()).is_err());
        let unknown = br#"{"provider":"aws","account_id":"a","region":"us-east-1","network_id":"vpc","prompt":"CONTENT_CANARY","records":[]}"#;
        let error = import_cloud_flow_json(unknown, CloudFlowProvider::Aws, &config()).unwrap_err();
        assert!(!error.to_string().contains("CONTENT_CANARY"));
        let oversized_counter = br#"{"provider":"aws","account_id":"a","region":"us-east-1","network_id":"vpc","records":[{"window_start":"2026-08-13T10:00:00Z","window_end":"2026-08-13T10:05:00Z","source_ip":"10.0.0.10","destination_ip":"10.0.0.20","protocol":"tcp","packets":1000000000000001,"direction":"lateral","decision":"accepted"}]}"#;
        assert!(
            import_cloud_flow_json(oversized_counter, CloudFlowProvider::Aws, &config()).is_err()
        );
    }

    #[test]
    fn checked_in_provider_fixtures_share_the_contract_and_redaction_boundary() {
        let fixtures = [
            (
                CloudFlowProvider::Aws,
                include_bytes!("../../../testdata/connectors/aws-cloud-flow/v1/input.json")
                    .as_slice(),
                include_bytes!("../../../testdata/connectors/aws-network-mapping/v1/input.json")
                    .as_slice(),
            ),
            (
                CloudFlowProvider::Azure,
                include_bytes!("../../../testdata/connectors/azure-cloud-flow/v1/input.json")
                    .as_slice(),
                include_bytes!("../../../testdata/connectors/azure-network-mapping/v1/input.json")
                    .as_slice(),
            ),
            (
                CloudFlowProvider::Gcp,
                include_bytes!("../../../testdata/connectors/gcp-cloud-flow/v1/input.json")
                    .as_slice(),
                include_bytes!("../../../testdata/connectors/gcp-network-mapping/v1/input.json")
                    .as_slice(),
            ),
        ];
        for (provider, flow, mapping) in fixtures {
            let flow = import_cloud_flow_json(flow, provider, &config()).unwrap();
            let mapping = import_cloud_mapping_json(mapping, provider, &config()).unwrap();
            assert_eq!(flow.stats.accepted, 1);
            assert_eq!(mapping.stats.accepted, 1);
            let flow_serialized = serde_json::to_string(&flow).unwrap();
            assert!(
                ["10.20.0.", "10.30.0.", "10.40.0.",]
                    .iter()
                    .any(|prefix| flow_serialized.contains(prefix))
            );
            let mapping_serialized = serde_json::to_string(&mapping).unwrap();
            assert!(!mapping_serialized.contains("CONTENT_CANARY"));
            assert!(!mapping_serialized.contains("10.20.0."));
            assert!(!mapping_serialized.contains("10.30.0."));
            assert!(!mapping_serialized.contains("10.40.0."));
        }
    }

    #[test]
    fn native_projection_has_a_distinct_pull_identity() {
        let flow = include_bytes!("../../../testdata/connectors/gcp-cloud-flow/v1/input.json");
        let mapping =
            include_bytes!("../../../testdata/connectors/gcp-network-mapping/v1/input.json");
        let flow = import_cloud_flow_api_json(flow, CloudFlowProvider::Gcp, &config()).unwrap();
        let mapping =
            import_cloud_mapping_api_json(mapping, CloudFlowProvider::Gcp, &config()).unwrap();
        assert_eq!(flow.batch.receipt.connector_type, "gcp_vpc_flow_api_v1");
        assert_eq!(
            mapping.batch.receipt.connector_type,
            "gcp_network_mapping_api_v1"
        );
        assert_eq!(
            cloud_flow_api_descriptor(CloudFlowProvider::Gcp).transport,
            ConnectorTransport::Pull
        );
        assert_eq!(
            cloud_mapping_api_descriptor(CloudFlowProvider::Gcp).replay_capability,
            ReplayCapability::OverlapWindow
        );
    }

    #[test]
    fn native_flow_projection_accounts_for_provider_status_records() {
        let input = br#"{"provider":"aws","account_id":"111122223333","region":"us-east-1","network_id":"vpc-12345678","ignored_records":2,"records":[{"window_start":"2026-08-13T10:00:00Z","window_end":"2026-08-13T10:01:00Z","source_ip":"10.0.0.10","destination_ip":"10.0.0.20","source_port":50000,"destination_port":443,"protocol":"tcp","packets":2,"bytes":128,"direction":"unknown","decision":"accepted"}]}"#;
        let outcome = import_cloud_flow_api_json(input, CloudFlowProvider::Aws, &config()).unwrap();
        assert_eq!(outcome.stats.records_read, 3);
        assert_eq!(outcome.stats.accepted, 1);
        assert_eq!(outcome.stats.ignored, 2);

        let over_cap = format!(
            "{{\"provider\":\"aws\",\"account_id\":\"111122223333\",\"region\":\"us-east-1\",\"network_id\":\"vpc-12345678\",\"ignored_records\":{},\"records\":[]}}",
            crate::MAX_BATCH_OBSERVATIONS + 1
        );
        assert!(
            import_cloud_flow_api_json(over_cap.as_bytes(), CloudFlowProvider::Aws, &config())
                .is_err()
        );
    }

    #[test]
    fn native_gcp_projection_accepts_a_point_in_time_dropped_flow() {
        let input = br#"{"provider":"gcp","account_id":"tally-project","region":"global","network_id":"tally-vpc","ignored_records":0,"records":[{"window_start":"2026-08-13T10:00:00Z","window_end":"2026-08-13T10:00:00Z","source_ip":"203.0.113.10","destination_ip":"10.0.0.8","source_port":47326,"destination_port":22,"protocol":"tcp","packets":1,"direction":"ingress","decision":"rejected"}]}"#;
        let outcome = import_cloud_flow_api_json(input, CloudFlowProvider::Gcp, &config()).unwrap();
        assert_eq!(outcome.stats.accepted, 1);
        assert_eq!(
            outcome.batch.observations[0].outcome.action.as_deref(),
            Some("rejected")
        );
    }
}
