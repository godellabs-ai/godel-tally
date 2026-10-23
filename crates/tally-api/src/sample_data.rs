//! A versioned, isolated evaluation workspace. No credentials, schedules or network calls.
mod catalog;
use super::{
    ApiError, AppState, ConnectorDescriptor, ImportAdapterInput, ProblemDetails, enum_name,
    scanner_descriptor,
};
use axum::{Json, http::StatusCode};
use catalog::{AGENTS, MODELS, PEOPLE, PROVIDERS, platform_for, provider_for};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::AssertSqlSafe;
use sqlx::{Connection, PgConnection};
use std::collections::{BTreeMap, BTreeSet};
use tally_core::{
    AgentObservation, CloudLifecycleState, CloudObservation, CloudProvider, CloudProviderService,
    CloudResourceKind, CloudUsageKind, ConnectorRef, EvidenceReceipt, FlowDirection, Hostname,
    IdentityAuthority, IdentityObservation, Observation, ObservationKind, RequestClientKind,
    RequestClientObservation, SaasCapabilityState, SaasObservation, SaasSanctionStatus,
    WorkloadKind, WorkloadObservation,
};
use tally_observation_buffer::estate::project;
use tally_store_postgres::DataInventory;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SamplePlan {
    dataset_id: Uuid,
    created_at: DateTime<Utc>,
    observations: Vec<Observation>,
    rows: BTreeMap<String, Vec<serde_json::Value>>,
    connector_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct SampleDataStatus {
    present: bool,
    state: String,
    created_at: Option<DateTime<Utc>>,
    counts: DataInventory,
    connector_types: Vec<String>,
    categories: Vec<String>,
    observation_kinds: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoveSampleDataRequest {
    confirmation: String,
}

fn sample_descriptors() -> Vec<ConnectorDescriptor> {
    let adapters = [
        ImportAdapterInput::DefenderStream,
        ImportAdapterInput::ServicenowAgents,
        ImportAdapterInput::N8nAgents,
        ImportAdapterInput::CopilotStudioAgents,
        ImportAdapterInput::LanggraphAgents,
        ImportAdapterInput::DifyAgents,
        ImportAdapterInput::OpenaiAgents,
        ImportAdapterInput::ClaudeAgents,
        ImportAdapterInput::GeminiAgents,
        ImportAdapterInput::Nextdns,
        ImportAdapterInput::NextdnsApi,
        ImportAdapterInput::CloudflareGateway,
        ImportAdapterInput::Zscaler,
        ImportAdapterInput::PaloAlto,
        ImportAdapterInput::AwsManagedAi,
        ImportAdapterInput::AwsManagedAiApi,
        ImportAdapterInput::AzureOpenai,
        ImportAdapterInput::AzureOpenaiApi,
        ImportAdapterInput::AzureAiFoundry,
        ImportAdapterInput::AzureAiFoundryApi,
        ImportAdapterInput::GcpVertexAi,
        ImportAdapterInput::GcpVertexAiApi,
        ImportAdapterInput::AwsCloudFlow,
        ImportAdapterInput::AwsNetworkMapping,
        ImportAdapterInput::AzureCloudFlow,
        ImportAdapterInput::AzureNetworkMapping,
        ImportAdapterInput::GcpCloudFlow,
        ImportAdapterInput::GcpNetworkMapping,
        ImportAdapterInput::AwsCloudFlowApi,
        ImportAdapterInput::AwsNetworkMappingApi,
        ImportAdapterInput::AzureCloudFlowApi,
        ImportAdapterInput::AzureNetworkMappingApi,
        ImportAdapterInput::GcpCloudFlowApi,
        ImportAdapterInput::GcpNetworkMappingApi,
        ImportAdapterInput::CloudflareCasb,
        ImportAdapterInput::CloudflareCasbApi,
        ImportAdapterInput::KubernetesApi,
        ImportAdapterInput::KubernetesApiPull,
        ImportAdapterInput::Litellm,
        ImportAdapterInput::LitellmApi,
        ImportAdapterInput::CloudflareAiGateway,
        ImportAdapterInput::CloudflareAiGatewayApi,
        ImportAdapterInput::CrowdstrikeEdr,
        ImportAdapterInput::Rapid7Edr,
        ImportAdapterInput::Netskope,
        ImportAdapterInput::MicrosoftDefenderApi,
        ImportAdapterInput::CatoNetworksApi,
        ImportAdapterInput::CloudflareZeroTrustGateway,
    ];
    let mut descriptors = adapters
        .into_iter()
        .map(ImportAdapterInput::descriptor)
        .collect::<Vec<_>>();
    descriptors.push(tally_connectors::generic_dns_descriptor());
    descriptors.push(scanner_descriptor());
    descriptors.sort_by(|a, b| a.connector_type.cmp(&b.connector_type));
    descriptors.dedup_by(|a, b| a.connector_type == b.connector_type);
    descriptors
}

const KINDS: [ObservationKind; 12] = [
    ObservationKind::AgentActivity,
    ObservationKind::DnsQuery,
    ObservationKind::HttpMetadata,
    ObservationKind::NetworkFlow,
    ObservationKind::NetworkMapping,
    ObservationKind::ScanFingerprint,
    ObservationKind::CloudResource,
    ObservationKind::CloudUsage,
    ObservationKind::SaasCapability,
    ObservationKind::KubernetesResource,
    ObservationKind::RegistryPull,
    ObservationKind::ConnectorHealth,
];
const CATEGORIES: [&str; 4] = [
    "AI platforms",
    "AI gateways",
    "Internet security",
    "Infrastructure",
];

fn sample_kind(connector: &str) -> ObservationKind {
    if hosted_agent_platform(connector).is_some() {
        ObservationKind::SaasCapability
    } else if connector.contains("agents") {
        ObservationKind::AgentActivity
    } else if connector.contains("mapping") {
        ObservationKind::NetworkMapping
    } else if connector.contains("flow") {
        ObservationKind::NetworkFlow
    } else if connector.contains("inventory") || connector.contains("vertex") {
        ObservationKind::CloudResource
    } else if connector.contains("kubernetes") {
        ObservationKind::KubernetesResource
    } else if connector.contains("casb") {
        ObservationKind::SaasCapability
    } else if connector.contains("scanner") {
        ObservationKind::ScanFingerprint
    } else if connector.contains("dns") || connector == "rapid7_edr_insightidr_api_v1" {
        ObservationKind::DnsQuery
    } else {
        ObservationKind::HttpMetadata
    }
}

fn hosted_agent_platform(connector: &str) -> Option<&'static str> {
    match connector {
        "openai_agents_api_v1" => Some("openai"),
        "claude_agents_api_v1" => Some("claude"),
        "gemini_agents_api_v1" => Some("gemini"),
        _ => None,
    }
}

impl SamplePlan {
    fn id(&self, key: &str) -> Uuid {
        Uuid::new_v5(&self.dataset_id, key.as_bytes())
    }
    fn push(&mut self, table: &str, row: serde_json::Value) {
        self.rows.entry(table.to_owned()).or_default().push(row);
    }
    fn ids(&self, table: &str, column: &str) -> Vec<Uuid> {
        self.rows
            .get(table)
            .into_iter()
            .flatten()
            .filter_map(|r| r.get(column)?.as_str()?.parse().ok())
            .collect()
    }
    fn observation_ids(&self) -> Vec<Uuid> {
        self.observations.iter().map(|o| o.observation_id).collect()
    }
    fn estate_ids(&self) -> Vec<Uuid> {
        self.observations
            .iter()
            .flat_map(project)
            .map(|r| r.id)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

#[allow(clippy::too_many_lines)] // The manifest is deliberately assembled together for auditable ownership.
fn build_plan(installation: Uuid, created_at: DateTime<Utc>) -> SamplePlan {
    let mut plan = SamplePlan {
        dataset_id: Uuid::now_v7(),
        created_at,
        observations: vec![],
        rows: BTreeMap::new(),
        connector_types: vec![],
    };
    let ns = format!("sample.{}", plan.dataset_id.simple());
    let timestamp = created_at;
    for (index, provider) in PROVIDERS.iter().enumerate() {
        plan.push("ai_providers", serde_json::json!({"provider_id": plan.id(&format!("provider:{index}")), "key": format!("{ns}.{index}"),
            "name": provider.name, "category": provider.category, "country_code": provider.country, "catalog": true,
            "sanctioned": provider.sanctioned(), "created_at": timestamp, "updated_at": timestamp}));
    }
    // One private model record per real model, shared across all observed providers. Preserve
    // canonical catalog keys and decisions by keeping the IDs and aliases dataset-specific.
    for (index, model) in MODELS.iter().enumerate() {
        let model_key = format!("{ns}.model.{index}");
        plan.push("ai_models", serde_json::json!({"model_id":plan.id(&format!("model:{index}")),"key":model_key,
            "name":model.name,"family":model.family,"owner_provider_id":plan.id(&format!("provider:{}",model.owner)),
            "country_code":PROVIDERS[model.owner].country,"modalities":model.modalities,"capabilities":model.capabilities,
            "aliases":[model_key],"catalog":true,"sanctioned":PROVIDERS[model.owner].sanctioned(),
            "created_at":timestamp,"updated_at":timestamp}));
    }
    // Private enterprise egress names avoid sharing identity with a live vendor endpoint.
    // The tenant suffix is also used for devices and users, so removal cannot affect real data.
    let tenant = format!(
        "northstar-{}.example",
        &plan.dataset_id.simple().to_string()[..12]
    );
    let descriptors = sample_descriptors();
    for (index, descriptor) in descriptors.into_iter().enumerate() {
        let connector = plan.id(&format!("connector:{}", descriptor.connector_type));
        let batch = plan.id(&format!("batch:{index}"));
        let digest = hex::encode(Sha256::digest(format!("sample:{batch}")));
        plan.connector_types.push(descriptor.connector_type.clone());
        plan.push("connector_states", serde_json::json!({"connector_instance_id": connector, "installation_id": installation,
            "connector_type": descriptor.connector_type, "implementation_version": descriptor.implementation_version,
            "display_name": descriptor.display_name, "friendly_name": format!("{} · Production",descriptor.display_name),
            "transport": descriptor.transport, "descriptor": descriptor, "health": "paused", "last_batch_id": batch,
            "last_success_at": timestamp, "last_poll_at": timestamp, "last_source_at": timestamp,
            "records_read_total": 3, "accepted_total": 3, "redaction_digest": digest, "updated_at": timestamp}));
        plan.push("connector_runs", serde_json::json!({"run_id":plan.id(&format!("run:{index}")),"connector_instance_id":connector,
            "installation_id":installation,"connector_type":descriptor.connector_type,"status":"completed","started_at":timestamp,
            "completed_at":timestamp,"cursor_before":format!("{}",timestamp.timestamp()-3600),"cursor_after":timestamp.timestamp().to_string(),"first_source_at":timestamp,"last_source_at":timestamp,
            "records_read":3,"accepted":3,"ignored":0,"rejected":0,"deduplicated":0,"batch_id":batch,"redaction_digest":digest}));
        plan.push("ingestion_batches", serde_json::json!({"batch_id":batch,"connector_instance_id":connector,"installation_id":installation,
            "batch_digest":digest,"observation_count":3,"checkpoint":timestamp.timestamp().to_string(),"status":"completed","accepted_at":timestamp,"completed_at":timestamp}));
        for scenario in 0..3 {
            let key = format!("{index}:{scenario}");
            let observation_id = plan.id(&format!("observation:{key}"));
            let at = timestamp
                - chrono::Duration::minutes(
                    i64::try_from(index * 3 + scenario).expect("bounded sample catalog"),
                );
            let provider_index = provider_for(&descriptor.connector_type, index, scenario);
            let provider_profile = &PROVIDERS[provider_index];
            let model_index = provider_profile.models[scenario];
            let provider = plan.id(&format!("provider:{provider_index}"));
            let model = plan.id(&format!("model:{model_index}"));
            let model_key = format!("{ns}.model.{model_index}");
            let person_index = (index + scenario) % PEOPLE.len();
            let (person, device, _) = PEOPLE[person_index];
            let (agent_name, workload) = AGENTS[person_index];
            let host = plan.id(&format!("host:{person_index}"));
            let user = plan.id(&format!("user:{person_index}"));
            let destination = plan.id(&format!("destination:{provider_index}"));
            let host_name = format!("{}.corp.{tenant}", device.to_lowercase());
            let email = format!("{person}@{tenant}");
            let destination_name = format!("{}.ai.{tenant}", provider_profile.gateway);
            let evidence = match sample_kind(&descriptor.connector_type) {
                ObservationKind::DnsQuery
                | ObservationKind::NetworkFlow
                | ObservationKind::NetworkMapping => "network_activity",
                ObservationKind::HttpMetadata => "ai_usage",
                _ => "resource_discovery",
            };
            let finding = plan.id(&format!(
                "finding:{provider_index}:{model_index}:{evidence}"
            ));
            let kind = sample_kind(&descriptor.connector_type);
            let mut o = Observation::new(
                installation,
                at,
                ConnectorRef {
                    instance_id: connector,
                    connector_type: descriptor.connector_type.clone(),
                    implementation_version: descriptor.implementation_version.clone(),
                    source_lineage_id: Some(format!("sample:{}", plan.dataset_id)),
                },
                kind,
                EvidenceReceipt::ExternalPointer {
                    source_record_id: format!("sample:{observation_id}"),
                    location_hint: Some(format!("{} / Production", descriptor.display_name)),
                },
            );
            o.observation_id = observation_id;
            o.received_at = at;
            if let Some(platform) = hosted_agent_platform(&descriptor.connector_type) {
                o.service.vendor_application_id = Some(format!("{ns}.{provider_index}"));
                o.service.declared_model_id = Some(model_key);
                o.agent = AgentObservation {
                    key: Some(format!("{ns}.agent.{key}")),
                    name: Some(
                        ["Research assistant", "Support triage", "Release reviewer"][scenario]
                            .into(),
                    ),
                    kind: Some("agent".into()),
                    platform: Some(platform.into()),
                    state: Some(
                        if platform == "claude" && scenario == 2 {
                            "archived"
                        } else {
                            "configured"
                        }
                        .into(),
                    ),
                    attribution_confidence: Some("unattributed".into()),
                    attribution_basis: Some(
                        "Configured inventory from the platform API; execution is not implied"
                            .into(),
                    ),
                    ..AgentObservation::default()
                };
                plan.observations.push(o);
                continue;
            }
            o.actor.hostname = Some(host_name.clone());
            o.actor.device_key = Some(format!("{ns}.device.{key}"));
            o.actor.identity = Some(IdentityObservation {
                subject_key: format!("{ns}.user.{person_index}"),
                email: Some(email.clone()),
                source_subject: None,
                source_subject_kind: None,
                authority: Some(IdentityAuthority::LocalOperator),
                directory_key: None,
                application_key: None,
                display_label: None,
            });
            o.actor.request_client = Some(RequestClientObservation {
                name: Some(
                    [
                        RequestClientKind::LangGraph,
                        RequestClientKind::Cursor,
                        RequestClientKind::ClaudeCode,
                    ][scenario],
                ),
                agent_id: Some(format!("{workload}-prod")),
            });
            o.destination.host = Some(Hostname::parse(&destination_name).expect("sample hostname"));
            o.destination.port = Some(443);
            o.service.vendor_application_id = Some(format!("{ns}.{provider_index}"));
            o.service.declared_model_id = Some(model_key.clone());
            o.service.ai_request = evidence == "ai_usage";
            o.service.ai_request_evaluated = true;
            o.network.bytes_sent = Some(2048 + index as u64 * 100);
            o.network.bytes_received = Some(16384 + index as u64 * 512);
            o.network.request_count = Some(1);
            o.network.direction = Some(FlowDirection::Egress);
            o.network.protocol = Some("tcp".into());
            o.outcome.action = Some(["allowed", "blocked", "observed"][scenario].into());
            o.outcome.result = Some(["completed", "policy_denied", "recorded"][scenario].into());
            // Managed workflows retain their reported names. Other observations identify the AI
            // application/runtime (Ollama, LiteLLM, etc.); models remain service metadata.
            let managed = descriptor.connector_type.contains("agents");
            let application = if managed {
                agent_name
            } else {
                provider_profile.name
            };
            let platform = if managed {
                platform_for(&descriptor.connector_type)
            } else {
                provider_profile.name
            };
            o.agent = AgentObservation {
                key: Some(format!("{ns}.agent.{key}")),
                name: Some(match scenario {
                    1 => "GitHub MCP Server".into(),
                    2 => format!("{application} · Workspace tools"),
                    _ => application.into(),
                }),
                kind: Some(["agent", "mcp_server", "mcp_config"][scenario].into()),
                platform: Some(platform.into()),
                parent_key: (scenario > 0).then(|| format!("{ns}.caller.{key}")),
                parent_name: (scenario > 0).then(|| application.into()),
                state: Some(["active", "paused", "draft"][scenario].into()),
                attribution_confidence: Some("source_reported".into()),
                attribution_basis: Some(
                    "Application identity and device reported by the source".into(),
                ),
                ..AgentObservation::default()
            };
            o.workload = WorkloadObservation {
                workload_key: Some(format!("{ns}.workload.{key}")),
                namespace_name: Some("ai-platform".into()),
                workload_name: Some(format!("{workload}-prod")),
                workload_kind: Some(WorkloadKind::Deployment),
                runtime_image: Some(
                    match provider_index {
                        8 => "ollama/ollama:0.6.2",
                        9 => "vllm/vllm-openai:v0.8.5",
                        _ => "ghcr.io/northstar/ai-workflows:2.4.1",
                    }
                    .into(),
                ),
                ..WorkloadObservation::default()
            };
            if matches!(
                kind,
                ObservationKind::CloudResource
                    | ObservationKind::NetworkFlow
                    | ObservationKind::NetworkMapping
            ) {
                let provider = if descriptor.connector_type.starts_with("aws") {
                    CloudProvider::Aws
                } else if descriptor.connector_type.starts_with("azure") {
                    CloudProvider::Azure
                } else {
                    CloudProvider::Gcp
                };
                o.cloud = CloudObservation {
                    provider: Some(provider),
                    account_key: Some(format!("{ns}.account.{index}")),
                    scope_key: Some(format!("{ns}.scope.{index}")),
                    region: Some(
                        match provider {
                            CloudProvider::Aws => "us-east-1",
                            CloudProvider::Azure => "eastus",
                            CloudProvider::Gcp => "us-central1",
                        }
                        .into(),
                    ),
                    resource_kind: Some(
                        [
                            CloudResourceKind::Agent,
                            CloudResourceKind::ModelDeployment,
                            CloudResourceKind::InferenceEndpoint,
                        ][scenario],
                    ),
                    resource_key: Some(format!("{ns}.cloud.{key}")),
                    lifecycle_state: Some(CloudLifecycleState::Active),
                    provider_service: Some(match provider {
                        CloudProvider::Aws => CloudProviderService::AwsBedrock,
                        CloudProvider::Azure => CloudProviderService::AzureAiFoundry,
                        CloudProvider::Gcp => CloudProviderService::GcpVertexAi,
                    }),
                    usage_kind: Some(if kind == ObservationKind::NetworkFlow {
                        CloudUsageKind::NetworkFlow
                    } else {
                        CloudUsageKind::ControlPlane
                    }),
                };
            }
            if kind == ObservationKind::SaasCapability {
                o.saas = SaasObservation {
                    tenant_key: Some(format!("{ns}.tenant")),
                    application_key: Some(format!("{ns}.app.{key}")),
                    capability_state: Some(SaasCapabilityState::Enabled),
                    sanction_status: Some(if provider_profile.sanctioned() {
                        SaasSanctionStatus::Sanctioned
                    } else {
                        SaasSanctionStatus::Unsanctioned
                    }),
                };
            }
            plan.push("ai_provider_models",serde_json::json!({"provider_id":provider,"model_id":model,"source":"connector","first_seen":at,"last_seen":at}));
            plan.push("endpoint_hosts",serde_json::json!({"endpoint_host_id":host,"kind":"hostname","value":host_name,"first_seen":at,"last_seen":at}));
            plan.push("endpoint_users",serde_json::json!({"endpoint_user_id":user,"kind":"email","value":email,"email":email,"first_seen":at,"last_seen":at}));
            plan.push("destination_hosts",serde_json::json!({"destination_host_id":destination,"kind":"hostname","value":destination_name,"first_seen":at,"last_seen":at}));
            // Findings aggregate repeated sightings of the same provider/model/evidence, as
            // live ingestion does. Keep every underlying observation and attribution link.
            let findings = plan.rows.entry("findings".into()).or_default();
            if let Some(row) = findings
                .iter_mut()
                .find(|row| row["finding_id"] == finding.to_string())
            {
                row["usage_count"] = serde_json::json!(
                    row["usage_count"].as_u64().unwrap() + u64::from(evidence == "ai_usage")
                );
                row["first_used_at"] = serde_json::json!(at);
            } else {
                plan.push("findings",serde_json::json!({"finding_id":finding,"installation_id":installation,"provider_id":provider,"model_id":model,
                    "evidence_kind":evidence,"first_used_at":at,"last_used_at":at,"usage_count":i32::from(evidence=="ai_usage"),"created_at":at,"updated_at":at}));
            }
            plan.push("finding_observations",serde_json::json!({"observation_id":observation_id,"finding_id":finding,"observed_at":at,"counts_as_usage":evidence=="ai_usage"}));
            plan.push("finding_hosts",serde_json::json!({"finding_id":finding,"endpoint_host_id":host,"role":"source","port":0,"first_seen":at,"last_seen":at}));
            plan.push("finding_users",serde_json::json!({"finding_id":finding,"endpoint_user_id":user,"first_seen":at,"last_seen":at}));
            plan.push("finding_destinations",serde_json::json!({"finding_id":finding,"destination_host_id":destination,"port":443,"first_seen":at,"last_seen":at}));
            plan.push("finding_connectors",serde_json::json!({"finding_id":finding,"connector_instance_id":connector,"first_seen":at,"last_seen":at}));
            plan.push("finding_workloads",serde_json::json!({"finding_id":finding,"namespace_name":o.workload.namespace_name,"workload_name":o.workload.workload_name,
                "workload_kind":"deployment","runtime_image":o.workload.runtime_image,"first_seen":at,"last_seen":at}));
            plan.push("finding_clients",serde_json::json!({"finding_id":finding,"client_name":o.actor.request_client.as_ref().unwrap().name,
                "agent_id":o.actor.request_client.as_ref().unwrap().agent_id,"connector_instance_id":connector,"first_seen":at,"last_seen":at}));
            plan.observations.push(o);
        }
    }
    // Non-usage event types are included as metadata examples, not additional inference requests.
    for (index, kind) in KINDS.iter().enumerate() {
        if !plan.observations.iter().any(|o| o.kind == *kind) {
            let mut o = plan.observations[index].clone();
            o.observation_id = plan.id(&format!("kind:{index}"));
            o.kind = *kind;
            o.service.ai_request = false;
            o.network.request_count = None;
            o.source = EvidenceReceipt::ExternalPointer {
                source_record_id: format!("sample:{}", o.observation_id),
                location_hint: Some("Platform operations".into()),
            };
            plan.observations.push(o);
        }
    }
    // Application reviews mirror provider defaults, so the evaluation graph includes both
    // sanctioned and unsanctioned agent paths. Named managed agents remain awaiting review;
    // their provider/model decisions still come from findings, not an invented agent approval.
    let mut reviews = BTreeMap::new();
    for observation in &plan.observations {
        let managed = observation.connector.connector_type.contains("agents");
        let sanctioned = if managed {
            None
        } else {
            plan.rows["ai_providers"]
                .iter()
                .find(|row| {
                    row["key"].as_str() == observation.service.vendor_application_id.as_deref()
                })
                .and_then(|row| row["sanctioned"].as_bool())
        };
        for record in project(observation)
            .into_iter()
            .filter(|record| record.detail.kind == "agent")
        {
            reviews.insert(
                record.id,
                (
                    sanctioned,
                    observation.agent.state.as_deref() == Some("archived"),
                ),
            );
        }
    }
    for (entity_id, (sanctioned, flagged)) in reviews {
        plan.push("tally_estate_reviews",serde_json::json!({"installation_id":installation,"entity_id":entity_id,"sanctioned":sanctioned,"flagged":flagged,"updated_at":timestamp}));
    }
    for table in ["connector_states", "connector_runs", "ingestion_batches"] {
        for row in plan.rows.get_mut(table).expect("sample connector rows") {
            let id = row["connector_instance_id"].as_str().expect("connector ID");
            let events = plan
                .observations
                .iter()
                .filter(|o| o.connector.instance_id.to_string() == id)
                .collect::<Vec<_>>();
            let count = serde_json::json!(events.len());
            let columns: &[&str] = match table {
                "connector_states" => &["records_read_total", "accepted_total"],
                "connector_runs" => &["records_read", "accepted"],
                _ => &["observation_count"],
            };
            for column in columns {
                row[column] = count.clone();
            }
        }
    }
    let scan = plan.id("scan");
    plan.push("scan_jobs",serde_json::json!({"scan_id":scan,"idempotency_key":scan,"request_fingerprint":"platform-discovery","scope_digest":"0".repeat(64),
        "plan":{"version":tally_scanner::SCAN_PLAN_VERSION,"targets":["192.0.2.10"],"ports":[443],"host_count":1,"probe_count":1,"allow_public":false,"public_target_authorization":false,"scope_digest":"0".repeat(64),"sample":true},"execution_policy":{"concurrency":1,"connect_timeout_millis":1500,"sample":true},"status":"completed","authorized_by":"Platform Operations",
        "authorization_acknowledged_at":timestamp,"created_at":timestamp,"started_at":timestamp,"finished_at":timestamp,"planned_probes":1,"completed_probes":1,
        "open_port_count":1,"fingerprint_attempt_count":1,"fingerprint_match_count":1,"resolved_system_count":1,"results":[{"address":"192.0.2.10","port":443,"state":"open","duration_millis":12}],"content_retained":false}));
    plan.push("audit_log",serde_json::json!({"audit_id":plan.id("audit"),"at":timestamp,"actor":"Evaluation workspace","action":"evaluation_workspace.created",
        "entity_type":"evaluation_workspace","entity_id":plan.dataset_id.to_string(),"detail":{"sample":true,"description":"Evaluation dataset installed; no live connectors or network probes"}}));
    plan
}

const TABLES: [&str; 18] = [
    "ai_providers",
    "ai_models",
    "ai_provider_models",
    "connector_states",
    "connector_runs",
    "ingestion_batches",
    "endpoint_hosts",
    "endpoint_users",
    "destination_hosts",
    "findings",
    "finding_observations",
    "finding_hosts",
    "finding_users",
    "finding_destinations",
    "finding_connectors",
    "finding_workloads",
    "finding_clients",
    "tally_estate_reviews",
];

// A detached connection is closed on drop, including cancellation and error paths. This keeps a
// session advisory lock out of the pool and serializes sample operations across host processes.
pub(super) async fn lock_workspace(
    state: &AppState,
    installation: Uuid,
) -> Result<PgConnection, ApiError> {
    let mut connection = state
        .postgres
        .pool()
        .acquire()
        .await
        .map_err(ApiError::dependency)?
        .detach();
    sqlx::query("SELECT pg_advisory_lock(hashtextextended($1, 0))")
        .bind(format!("tally.sample:{installation}"))
        .execute(&mut connection)
        .await
        .map_err(ApiError::dependency)?;
    Ok(connection)
}

async fn read_plan(
    state: &AppState,
    installation: Uuid,
) -> Result<Option<(String, SamplePlan)>, ApiError> {
    let row = sqlx::query_as::<_, (String, serde_json::Value)>(
        "SELECT state, manifest FROM tally_sample_workspace WHERE installation_id=$1",
    )
    .bind(installation)
    .fetch_optional(state.postgres.pool())
    .await
    .map_err(ApiError::dependency)?;
    row.map(|(phase, manifest)| {
        serde_json::from_value(manifest)
            .map(|plan| (phase, plan))
            .map_err(ApiError::dependency)
    })
    .transpose()
}

async fn installation(state: &AppState) -> Result<Uuid, ApiError> {
    Ok(state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?
        .installation_id)
}

#[utoipa::path(get, path="/api/v1/tally/data/sample", responses((status=200,body=SampleDataStatus)))]
pub(crate) async fn status(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<SampleDataStatus>, ApiError> {
    status_for(&state).await.map(Json)
}

async fn status_for(state: &AppState) -> Result<SampleDataStatus, ApiError> {
    let current = read_plan(state, installation(state).await?).await?;
    let mut result = SampleDataStatus {
        present: current.is_some(),
        state: "absent".into(),
        created_at: None,
        counts: DataInventory::default(),
        connector_types: sample_descriptors()
            .into_iter()
            .map(|d| d.connector_type)
            .collect(),
        categories: CATEGORIES.iter().map(ToString::to_string).collect(),
        observation_kinds: KINDS.iter().map(|k| enum_name(*k, "unknown")).collect(),
    };
    if let Some((phase, plan)) = current {
        result.state = phase;
        result.created_at = Some(plan.created_at);
        result.connector_types = plan.connector_types.clone();
        result.counts = counts(state, &plan).await?;
    }
    Ok(result)
}

async fn count_owned(
    state: &AppState,
    plan: &SamplePlan,
    table: &str,
    column: &str,
) -> Result<u64, ApiError> {
    let count = sqlx::query_scalar::<_, i64>(AssertSqlSafe(format!(
        "SELECT count(*) FROM {table} WHERE {column}=ANY($1)"
    )))
    .bind(plan.ids(table, column))
    .fetch_one(state.postgres.pool())
    .await
    .map_err(ApiError::dependency)?;
    Ok(count.cast_unsigned())
}

async fn counts(state: &AppState, plan: &SamplePlan) -> Result<DataInventory, ApiError> {
    let (ai_logs, inventory_entities) = state
        .observations
        .sample_record_counts(&plan.observation_ids(), &plan.estate_ids())
        .await
        .map_err(ApiError::dependency)?;
    Ok(DataInventory{ai_logs,inventory_entities,
        findings:count_owned(state,plan,"findings","finding_id").await?,
        endpoint_hosts:count_owned(state,plan,"endpoint_hosts","endpoint_host_id").await?,
        destination_hosts:count_owned(state,plan,"destination_hosts","destination_host_id").await?,
        endpoint_users:count_owned(state,plan,"endpoint_users","endpoint_user_id").await?,
        connectors:count_owned(state,plan,"connector_states","connector_instance_id").await?,
        connector_runs:count_owned(state,plan,"connector_runs","run_id").await?,
        ingestion_receipts:count_owned(state,plan,"ingestion_batches","batch_id").await?,
        scanner_runs:count_owned(state,plan,"scan_jobs","scan_id").await?,
        audit_events:count_owned(state,plan,"audit_log","audit_id").await?,
        registry_sanctions:sqlx::query_scalar::<_,i64>("SELECT (SELECT count(*) FROM ai_providers WHERE provider_id=ANY($1) AND sanctioned IS NOT NULL)+(SELECT count(*) FROM ai_models WHERE model_id=ANY($2) AND sanctioned IS NOT NULL)+(SELECT count(*) FROM tally_estate_reviews WHERE entity_id=ANY($3) AND (sanctioned IS NOT NULL OR flagged))")
            .bind(plan.ids("ai_providers","provider_id")).bind(plan.ids("ai_models","model_id")).bind(plan.estate_ids()).fetch_one(state.postgres.pool()).await.map_err(ApiError::dependency)?.cast_unsigned(),
    })
}

async fn insert_records(
    connection: &mut PgConnection,
    table: &str,
    rows: &[serde_json::Value],
) -> Result<(), ApiError> {
    let Some(object) = rows.first().and_then(serde_json::Value::as_object) else {
        return Ok(());
    };
    // Table names come from the fixed list above, columns from our versioned manifest. Validate
    // identifiers before constructing SQL; all data is passed as a JSON parameter.
    if !object
        .keys()
        .all(|key| !key.is_empty() && key.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
    {
        return Err(ApiError::dependency_message("sample_manifest_invalid"));
    }
    let columns = object
        .keys()
        .map(|key| format!("\"{key}\""))
        .collect::<Vec<_>>()
        .join(",");
    sqlx::query(AssertSqlSafe(format!("INSERT INTO {table} ({columns}) SELECT {columns} FROM jsonb_populate_recordset(NULL::{table}, $1) ON CONFLICT DO NOTHING")))
        .bind(serde_json::json!(rows)).execute(connection).await.map_err(ApiError::dependency)?;
    Ok(())
}

#[utoipa::path(post, path="/api/v1/tally/data/sample", responses((status=200,body=SampleDataStatus),(status=409,body=ProblemDetails)))]
pub(crate) async fn add(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<SampleDataStatus>, ApiError> {
    let _guard = state.purge_lock.lock().await;
    let installation = installation(&state).await?;
    let mut connection = lock_workspace(&state, installation).await?;
    let plan = match read_plan(&state, installation).await? {
        Some((phase, _)) if phase == "removing" => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "sample_removal_in_progress",
            ));
        }
        Some((_, plan)) => plan,
        None => build_plan(installation, Utc::now()),
    };
    sqlx::query("INSERT INTO tally_sample_workspace (installation_id,dataset_id,version,state,created_at,manifest) VALUES ($1,$2,1,'adding',$3,$4) ON CONFLICT (installation_id) DO UPDATE SET state='adding'")
        .bind(installation).bind(plan.dataset_id).bind(plan.created_at).bind(serde_json::to_value(&plan).map_err(ApiError::dependency)?)
        .execute(&mut connection).await.map_err(ApiError::dependency)?;
    // Publish durable provenance before either storage write. Replays use the original IDs and times.
    state
        .observations
        .append_observations(
            &plan.observations,
            &hex::encode(Sha256::digest(plan.dataset_id.as_bytes())),
        )
        .await
        .map_err(ApiError::dependency)?;
    let mut transaction = connection.begin().await.map_err(ApiError::dependency)?;
    for table in TABLES.into_iter().chain(["scan_jobs", "audit_log"]) {
        if let Some(rows) = plan.rows.get(table) {
            insert_records(&mut transaction, table, rows).await?;
        }
    }
    sqlx::query("UPDATE tally_sample_workspace SET state='ready' WHERE installation_id=$1")
        .bind(installation)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::dependency)?;
    transaction.commit().await.map_err(ApiError::dependency)?;
    status_for(&state).await.map(Json)
}

#[utoipa::path(post, path="/api/v1/tally/data/sample/delete", request_body=RemoveSampleDataRequest, responses((status=200,body=SampleDataStatus),(status=422,body=ProblemDetails)))]
pub(crate) async fn remove(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(request): Json<RemoveSampleDataRequest>,
) -> Result<Json<SampleDataStatus>, ApiError> {
    if request.confirmation != "delete evaluation data" {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "sample_confirmation_invalid",
        ));
    }
    let _guard = state.purge_lock.lock().await;
    let installation = installation(&state).await?;
    let mut connection = lock_workspace(&state, installation).await?;
    if let Some((_, plan)) = read_plan(&state, installation).await? {
        sqlx::query("UPDATE tally_sample_workspace SET state='removing' WHERE installation_id=$1")
            .bind(installation)
            .execute(&mut connection)
            .await
            .map_err(ApiError::dependency)?;
        state
            .observations
            .delete_sample_records(&plan.observation_ids(), &plan.estate_ids())
            .await
            .map_err(ApiError::dependency)?;
        let mut transaction = connection.begin().await.map_err(ApiError::dependency)?;
        for (table, column) in [
            ("findings", "finding_id"),
            ("connector_states", "connector_instance_id"),
            ("scan_jobs", "scan_id"),
            ("audit_log", "audit_id"),
        ] {
            sqlx::query(AssertSqlSafe(format!(
                "DELETE FROM {table} WHERE {column}=ANY($1)"
            )))
            .bind(plan.ids(table, column))
            .execute(&mut *transaction)
            .await
            .map_err(ApiError::dependency)?;
        }
        // Preserve any owned entity subsequently referenced by non-sample records.
        for (table, column, reference) in [
            ("endpoint_hosts", "endpoint_host_id", "finding_hosts"),
            ("endpoint_users", "endpoint_user_id", "finding_users"),
            (
                "destination_hosts",
                "destination_host_id",
                "finding_destinations",
            ),
            ("ai_models", "model_id", "findings"),
        ] {
            sqlx::query(AssertSqlSafe(format!("DELETE FROM {table} WHERE {column}=ANY($1) AND NOT EXISTS (SELECT 1 FROM {reference} r WHERE r.{column}={table}.{column})")))
                .bind(plan.ids(table,column)).execute(&mut *transaction).await.map_err(ApiError::dependency)?;
        }
        sqlx::query("DELETE FROM ai_providers p WHERE provider_id=ANY($1) AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.provider_id=p.provider_id) AND NOT EXISTS (SELECT 1 FROM ai_models m WHERE m.owner_provider_id=p.provider_id) AND NOT EXISTS (SELECT 1 FROM ai_provider_models pm WHERE pm.provider_id=p.provider_id)")
            .bind(plan.ids("ai_providers", "provider_id")).execute(&mut *transaction).await.map_err(ApiError::dependency)?;
        sqlx::query(
            "DELETE FROM tally_estate_reviews WHERE installation_id=$1 AND entity_id=ANY($2)",
        )
        .bind(installation)
        .bind(plan.estate_ids())
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::dependency)?;
        sqlx::query("DELETE FROM tally_sample_workspace WHERE installation_id=$1")
            .bind(installation)
            .execute(&mut *transaction)
            .await
            .map_err(ApiError::dependency)?;
        transaction.commit().await.map_err(ApiError::dependency)?;
    }
    status_for(&state).await.map(Json)
}

pub(super) async fn connector_ids(state: &AppState) -> Result<BTreeSet<Uuid>, ApiError> {
    Ok(read_plan(state, installation(state).await?)
        .await?
        .map_or_else(BTreeSet::new, |(_, plan)| {
            plan.ids("connector_states", "connector_instance_id")
                .into_iter()
                .collect()
        }))
}

pub(super) async fn require_live_connector(state: &AppState, id: Uuid) -> Result<(), ApiError> {
    let owned=sqlx::query_scalar::<_,bool>("SELECT EXISTS (SELECT 1 FROM tally_sample_workspace WHERE manifest->'rows'->'connector_states' @> jsonb_build_array(jsonb_build_object('connector_instance_id',$1::text)))")
        .bind(id.to_string()).fetch_one(state.postgres.pool()).await.map_err(ApiError::dependency)?;
    if owned {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "sample_connector_read_only",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{data_inventory, data_preview, state_from_store};
    use axum::extract::State;
    use std::sync::Arc;
    use tally_config::SecretCipher;
    use tally_observation_buffer::ObservationBuffer;
    use tally_store_postgres::PostgresStore;

    fn enum_values(value: &serde_json::Value) -> BTreeSet<String> {
        let mut result = BTreeSet::new();
        if let Some(values) = value.get("enum").and_then(serde_json::Value::as_array) {
            result.extend(values.iter().filter_map(|v| v.as_str().map(str::to_owned)));
        }
        if let Some(value) = value.get("const").and_then(serde_json::Value::as_str) {
            result.insert(value.to_owned());
        }
        if let Some(values) = value.get("oneOf").and_then(serde_json::Value::as_array) {
            for v in values {
                result.extend(enum_values(v));
            }
        }
        result
    }

    #[test]
    fn sample_workspace_covers_catalog_categories_events_and_governance() {
        let plan = build_plan(Uuid::new_v4(), Utc::now());
        for observation in &plan.observations {
            if hosted_agent_platform(&observation.connector.connector_type).is_some() {
                assert_eq!(observation.kind, ObservationKind::SaasCapability);
                assert_eq!(observation.agent.kind.as_deref(), Some("agent"));
                assert!(observation.actor.identity.is_none());
                assert!(observation.actor.hostname.is_none());
                assert!(observation.network.request_count.is_none());
            }
        }
        let catalog = include_str!("../../../apps/web/lib/connector-catalog.ts");
        for section in catalog.split("connectorTypes:").skip(1) {
            let list = section.split(']').next().unwrap();
            for connector in list.split('"').skip(1).step_by(2) {
                assert!(
                    plan.connector_types.iter().any(|t| t == connector),
                    "missing sample for {connector}"
                );
            }
        }
        assert!(plan.connector_types.iter().any(|t| t == "native_scanner"));
        assert_eq!(plan.connector_types.len(), sample_descriptors().len());
        for kind in KINDS {
            assert!(
                plan.observations.iter().any(|o| o.kind == kind),
                "missing {kind:?}"
            );
        }
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../specs/observation.schema.json")).unwrap();
        assert_eq!(
            KINDS
                .iter()
                .map(|k| enum_name(*k, "unknown"))
                .collect::<BTreeSet<_>>(),
            enum_values(&schema["$defs"]["ObservationKind"]),
            "new event kinds need sample coverage"
        );
        let categories = catalog
            .split("category: \"")
            .skip(1)
            .filter_map(|s| s.split('"').next())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            categories,
            BTreeSet::from([
                "ai-platforms",
                "ai-gateways",
                "internet-security",
                "infrastructure"
            ])
        );
        assert_eq!(plan.rows["ai_providers"].len(), PROVIDERS.len());
        assert_eq!(plan.rows["ai_models"].len(), MODELS.len());
        for sanction in [serde_json::json!(true), serde_json::json!(false)] {
            assert!(
                plan.rows["ai_models"]
                    .iter()
                    .any(|r| r["sanctioned"] == sanction)
            );
        }
        for kind in ["ai_usage", "network_activity", "resource_discovery"] {
            assert!(
                plan.rows["findings"]
                    .iter()
                    .any(|r| r["evidence_kind"] == kind)
            );
        }
        assert!(!plan.rows.contains_key("connector_jobs"));
        let encoded = serde_json::to_value(&plan).unwrap();
        let restored: SamplePlan = serde_json::from_value(encoded).unwrap();
        assert_eq!(plan.observation_ids(), restored.observation_ids());
        assert_eq!(plan.estate_ids(), restored.estate_ids());
        let kinds = plan
            .observations
            .iter()
            .flat_map(project)
            .map(|r| r.detail.kind)
            .collect::<BTreeSet<_>>();
        for kind in [
            "identity",
            "device",
            "agent",
            "mcp_server",
            "mcp_config",
            "workload",
            "model",
            "provider",
            "endpoint",
        ] {
            assert!(kinds.contains(kind), "missing graph node {kind}");
        }
    }

    #[test]
    fn realistic_names_keep_private_identities_and_aggregate_usage() {
        let installation = Uuid::new_v4();
        let plan = build_plan(installation, Utc::now());
        let other = build_plan(installation, Utc::now());
        let ids = plan.estate_ids().into_iter().collect::<BTreeSet<_>>();
        assert!(other.estate_ids().iter().all(|id| !ids.contains(id)));
        for (table, column) in [
            ("ai_providers", "name"),
            ("ai_models", "name"),
            ("connector_states", "friendly_name"),
        ] {
            for row in &plan.rows[table] {
                let name = row[column].as_str().unwrap().to_lowercase();
                assert!(
                    !name.contains("sample") && !name.contains("dummy"),
                    "{name}"
                );
            }
        }
        assert_eq!(plan.rows["ai_models"].len(), 10);
        assert_eq!(
            plan.rows["ai_providers"]
                .iter()
                .map(|p| p["category"].as_str().unwrap())
                .collect::<BTreeSet<_>>()
                .len(),
            6
        );
        let usage_count: u64 = plan.rows["findings"]
            .iter()
            .map(|f| f["usage_count"].as_u64().unwrap())
            .sum();
        assert_eq!(
            usage_count,
            plan.observations
                .iter()
                .filter(|o| o.service.ai_request)
                .count() as u64
        );
        assert!(plan.rows["findings"].len() < plan.observations.len());
        for o in &plan.observations {
            assert!(!o.agent.name.as_deref().unwrap().contains("Sample"));
            if let Some(workload) = &o.workload.workload_name {
                assert!(!workload.contains("sample"));
            } else {
                assert!(hosted_agent_platform(&o.connector.connector_type).is_some());
            }
            let provider = o.service.vendor_application_id.as_deref().unwrap();
            if o.connector.connector_type.starts_with("aws") {
                assert!(provider.ends_with(".3"));
            }
            if o.connector.connector_type.starts_with("azure") {
                assert!(provider.ends_with(".4"));
            }
            if o.connector.connector_type.starts_with("gcp") {
                assert!(provider.ends_with(".5"));
            }
        }
    }

    #[test]
    fn evaluation_graph_has_application_agents_and_reported_mcp_callers() {
        let plan = build_plan(Uuid::new_v4(), Utc::now());
        let records = plan
            .observations
            .iter()
            .flat_map(project)
            .filter(|record| record.detail.kind == "agent")
            .map(|record| (record.id, record.detail.name))
            .collect::<BTreeMap<_, _>>();
        for application in ["Ollama", "LiteLLM", "vLLM"] {
            let ids = records
                .iter()
                .filter(|(_, name)| name.as_str() == application)
                .map(|(id, _)| id.to_string())
                .collect::<BTreeSet<_>>();
            assert!(!ids.is_empty(), "missing application agent {application}");
            let reviews = plan.rows["tally_estate_reviews"]
                .iter()
                .filter(|row| ids.contains(row["entity_id"].as_str().unwrap()))
                .collect::<Vec<_>>();
            assert_eq!(reviews.len(), ids.len());
            assert!(reviews.iter().all(|row| row["sanctioned"] == false));
        }
        assert!(
            records
                .values()
                .all(|name| { MODELS.iter().all(|model| !name.contains(model.name)) })
        );
        for observation in &plan.observations {
            if matches!(
                observation.agent.kind.as_deref(),
                Some("mcp_server" | "mcp_config")
            ) {
                assert!(observation.agent.parent_key.is_some());
                assert!(observation.agent.parent_name.is_some());
                assert!(project(observation).iter().any(|record| {
                    record.record_type == "edge"
                        && matches!(record.detail.kind.as_str(), "calls" | "spawns")
                }));
            } else {
                assert!(observation.agent.parent_key.is_none());
            }
        }
        let reviews = &plan.rows["tally_estate_reviews"];
        assert!(reviews.iter().any(|row| row["sanctioned"] == true));
        assert!(reviews.iter().any(|row| row["sanctioned"].is_null()));
        assert!(reviews.iter().any(|row| row["flagged"] == true));
    }

    #[test]
    fn evaluation_sanctions_follow_enterprise_providers_and_model_owners() {
        let plan = build_plan(Uuid::new_v4(), Utc::now());
        let sanctioned_names = |table: &str| {
            plan.rows[table]
                .iter()
                .filter(|row| row["sanctioned"] == true)
                .map(|row| row["name"].as_str().unwrap())
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(
            sanctioned_names("ai_providers"),
            BTreeSet::from([
                "OpenAI",
                "Anthropic",
                "Google AI",
                "Amazon Bedrock",
                "Azure AI Foundry",
                "Google Vertex AI",
                "Microsoft 365 Copilot",
            ])
        );
        assert_eq!(
            sanctioned_names("ai_models"),
            BTreeSet::from([
                "GPT-4o",
                "GPT-4o mini",
                "Whisper",
                "Claude Sonnet 4",
                "Claude 3.5 Haiku",
                "Gemini 2.5 Pro",
                "Gemini 2.5 Flash",
                "GPT Image 1",
            ])
        );
        for table in ["ai_providers", "ai_models"] {
            assert!(
                plan.rows[table]
                    .iter()
                    .all(|row| row["sanctioned"].is_boolean())
            );
        }
        for observation in &plan.observations {
            let Some(sanction) = observation.saas.sanction_status else {
                continue;
            };
            let provider = plan.rows["ai_providers"]
                .iter()
                .find(|provider| {
                    provider["key"].as_str() == observation.service.vendor_application_id.as_deref()
                })
                .unwrap();
            let expected = if provider["sanctioned"] == true {
                SaasSanctionStatus::Sanctioned
            } else {
                SaasSanctionStatus::Unsanctioned
            };
            assert_eq!(sanction, expected);
        }
        // Hosting an unapproved model on an approved platform does not approve the model.
        assert!(plan.rows["findings"].iter().any(|finding| {
            finding["provider_id"] == plan.id("provider:3").to_string()
                && finding["model_id"] == plan.id("model:7").to_string()
        }));
        assert_eq!(plan.rows["ai_models"][7]["sanctioned"], false);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // One lifecycle test exercises both stores and preservation of existing data.
    #[ignore = "requires an isolated TALLY_SAMPLE_TEST_POSTGRES_URL; optional TALLY_SAMPLE_TEST_CLICKHOUSE_URL"]
    async fn sample_workspace_roundtrip_preserves_existing_data() {
        let url =
            std::env::var("TALLY_SAMPLE_TEST_POSTGRES_URL").expect("disposable PostgreSQL URL");
        assert!(
            url::Url::parse(&url)
                .unwrap()
                .path()
                .ends_with("/tally_sample_test"),
            "dedicated test database required"
        );
        let store = Arc::new(PostgresStore::connect(&url).await.unwrap());
        store.migrate().await.unwrap();
        let mut state = state_from_store(store.clone(), SecretCipher::from_bytes([7; 32]))
            .await
            .unwrap();
        let installation = installation(&state).await.unwrap();
        if let Ok(url) = std::env::var("TALLY_SAMPLE_TEST_CLICKHOUSE_URL") {
            state.observations = Arc::new(
                ObservationBuffer::persistent(&url, "tally_sample_test", installation, 90).unwrap(),
            );
            state.observations.migrate().await.unwrap();
        }
        // Independent operational data must survive add, repair and removal, including an orphan
        // host (sample removal must never run a global orphan cleanup).
        let provider = Uuid::now_v7();
        let finding = Uuid::now_v7();
        let host = Uuid::now_v7();
        sqlx::query("INSERT INTO ai_providers(provider_id,key,name,category,catalog) VALUES($1,$2,'Existing production provider','direct_provider',false)")
            .bind(provider).bind(provider.to_string()).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO findings(finding_id,installation_id,provider_id,first_used_at,last_used_at,usage_count) VALUES($1,$2,$3,now(),now(),5)")
            .bind(finding).bind(installation).bind(provider).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO endpoint_hosts(endpoint_host_id,kind,value,first_seen,last_seen) VALUES($1,'hostname',$2,now(),now())")
            .bind(host).bind(format!("existing-{host}.example.test")).execute(store.pool()).await.unwrap();
        let mut existing = build_plan(installation, Utc::now()).observations[0].clone();
        existing.observation_id = Uuid::now_v7();
        state
            .observations
            .append_observation(&existing)
            .await
            .unwrap();
        // Clean up a previous interrupted test's sample workspace, preserving the operational rows.
        let _ = remove(
            State(state.clone()),
            Json(RemoveSampleDataRequest {
                confirmation: "delete evaluation data".into(),
            }),
        )
        .await
        .unwrap();
        let baseline = data_inventory(State(state.clone())).await.unwrap().0;
        let added = add(State(state.clone())).await.unwrap().0;
        assert!(added.present);
        assert_eq!(added.state, "ready");
        assert!(added.counts.findings > 20);
        assert!(added.counts.ai_logs > 100);
        assert!(added.counts.inventory_entities > 0);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM connector_jobs")
                .fetch_one(store.pool())
                .await
                .unwrap(),
            0
        );
        let mut peer = state.clone();
        peer.purge_lock = Arc::new(tokio::sync::Mutex::new(()));
        let (first, second) = tokio::join!(add(State(state.clone())), add(State(peer)));
        let again = first.unwrap().0;
        assert_eq!(
            added.counts,
            second.unwrap().0.counts,
            "separate API instances serialize sample writes"
        );
        assert_eq!(
            added.counts, again.counts,
            "replaying add must not inflate counts"
        );
        let (_, plan) = read_plan(&state, installation).await.unwrap().unwrap();
        // Fixture decisions must track the same defaults used by fresh registry seeds and resets.
        for (index, provider) in PROVIDERS.iter().enumerate() {
            let expected: bool = sqlx::query_scalar("SELECT tally_default_provider_sanction($1)")
                .bind(provider.registry_key)
                .fetch_one(store.pool())
                .await
                .unwrap();
            let actual: bool =
                sqlx::query_scalar("SELECT sanctioned FROM ai_providers WHERE provider_id=$1")
                    .bind(plan.id(&format!("provider:{index}")))
                    .fetch_one(store.pool())
                    .await
                    .unwrap();
            assert_eq!(actual, expected, "{}", provider.registry_key);
        }
        for (index, model) in MODELS.iter().enumerate() {
            let expected: bool = sqlx::query_scalar("SELECT tally_default_provider_sanction($1)")
                .bind(PROVIDERS[model.owner].registry_key)
                .fetch_one(store.pool())
                .await
                .unwrap();
            let actual: bool =
                sqlx::query_scalar("SELECT sanctioned FROM ai_models WHERE model_id=$1")
                    .bind(plan.id(&format!("model:{index}")))
                    .fetch_one(store.pool())
                    .await
                    .unwrap();
            assert_eq!(actual, expected, "{}", model.name);
        }
        // Real imports must resolve to canonical models, even though evaluation rows have
        // identical display names and independently editable decisions. Exercise ingestion itself.
        for model in MODELS {
            let live_finding = store
                .record_usage(&tally_store_postgres::ObservedUsage {
                    observation_id: Uuid::now_v7(),
                    installation_id: installation,
                    provider_key: provider.to_string(),
                    provider_name: "Existing production provider".into(),
                    provider_category: "direct_provider".into(),
                    provider_country_code: Some("US".into()),
                    provider_catalogued: false,
                    model_reference: Some(model.name.into()),
                    observed_at: Utc::now(),
                    connector_instance_id: plan.ids("connector_states", "connector_instance_id")[0],
                    evidence_kind: tally_store_postgres::FindingEvidenceKind::AiUsage,
                    counts_as_usage: true,
                    endpoints: vec![],
                    destinations: vec![],
                    workloads: vec![],
                    user_identity: None,
                    request_client: None,
                })
                .await
                .unwrap();
            let resolved: Uuid =
                sqlx::query_scalar("SELECT model_id FROM findings WHERE finding_id=$1")
                    .bind(live_finding)
                    .fetch_one(store.pool())
                    .await
                    .unwrap();
            assert!(
                !plan.ids("ai_models", "model_id").contains(&resolved),
                "evaluation model captured a live import: {}",
                model.name
            );
            sqlx::query("DELETE FROM findings WHERE finding_id=$1")
                .bind(live_finding)
                .execute(store.pool())
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM ai_provider_models WHERE provider_id=$1")
            .bind(provider)
            .execute(store.pool())
            .await
            .unwrap();
        assert_eq!(
            require_live_connector(
                &state,
                plan.ids("connector_states", "connector_instance_id")[0]
            )
            .await
            .unwrap_err()
            .code,
            "sample_connector_read_only"
        );
        let all = data_preview::preview(
            State(state.clone()),
            Json(data_preview::DataTarget {
                scopes: vec!["all".into()],
                before: None,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(all, data_inventory(State(state.clone())).await.unwrap().0);
        let cutoff = data_preview::preview(
            State(state.clone()),
            Json(data_preview::DataTarget {
                scopes: vec!["findings".into(), "ai_logs".into()],
                before: Some(plan.created_at - chrono::Duration::minutes(30)),
            }),
        )
        .await
        .unwrap()
        .0;
        assert!(cutoff.findings > 0 && cutoff.findings < added.counts.findings);
        assert_eq!(cutoff.connectors, 0);
        assert!(cutoff.ai_logs > 0 && cutoff.ai_logs < added.counts.ai_logs);
        let listed = crate::connectors(State(state.clone())).await.unwrap().0;
        assert_eq!(
            listed.items.iter().filter(|c| c.sample).count(),
            added.connector_types.len()
        );
        let after_cutoff = crate::delete_data(
            State(state.clone()),
            Json(crate::DeleteDataRequest {
                confirmation: "DELETE SELECTED DATA".into(),
                scopes: vec!["ai_logs".into()],
                before: Some(plan.created_at - chrono::Duration::minutes(30)),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(
            after_cutoff.ai_logs,
            baseline.ai_logs + added.counts.ai_logs - cutoff.ai_logs
        );
        // The selected-data deletion leaves its own audit record, which removal preserves.
        let baseline = crate::DataInventory {
            audit_events: baseline.audit_events + 1,
            ..baseline.clone()
        };
        assert_eq!(status_for(&state).await.unwrap().state, "partial");
        assert_eq!(
            add(State(state.clone())).await.unwrap().0.counts,
            added.counts
        );
        // A partial dataset can be repaired from durable provenance without changing its identities.
        sqlx::query("DELETE FROM findings WHERE finding_id=$1")
            .bind(plan.ids("findings", "finding_id")[0])
            .execute(store.pool())
            .await
            .unwrap();
        let repaired = add(State(state.clone())).await.unwrap().0;
        assert_eq!(added.counts, repaired.counts);
        assert_eq!(
            remove(
                State(state.clone()),
                Json(RemoveSampleDataRequest {
                    confirmation: "wrong".into()
                })
            )
            .await
            .unwrap_err()
            .code,
            "sample_confirmation_invalid"
        );
        sqlx::query("UPDATE tally_sample_workspace SET state='removing' WHERE installation_id=$1")
            .bind(installation)
            .execute(store.pool())
            .await
            .unwrap();
        assert_eq!(
            add(State(state.clone())).await.unwrap_err().code,
            "sample_removal_in_progress"
        );
        let removed = remove(
            State(state.clone()),
            Json(RemoveSampleDataRequest {
                confirmation: "delete evaluation data".into(),
            }),
        )
        .await
        .unwrap()
        .0;
        assert!(!removed.present);
        assert_eq!(
            data_inventory(State(state.clone())).await.unwrap().0,
            baseline
        );
        assert!(
            state
                .observations
                .get_observation(existing.observation_id)
                .await
                .unwrap()
                .is_some()
        );
        let _ = remove(
            State(state.clone()),
            Json(RemoveSampleDataRequest {
                confirmation: "delete evaluation data".into(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            data_inventory(State(state.clone())).await.unwrap().0,
            baseline
        );
        // Re-add after removal creates a fresh workspace and remains fully removable.
        assert!(add(State(state.clone())).await.unwrap().0.present);
        let _ = remove(
            State(state.clone()),
            Json(RemoveSampleDataRequest {
                confirmation: "delete evaluation data".into(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            data_inventory(State(state.clone())).await.unwrap().0,
            baseline
        );
    }
}
