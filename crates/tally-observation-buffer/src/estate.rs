//! Durable inventory projection shared by standalone Tally and embedding hosts.
use serde::{Deserialize, Serialize};
use tally_core::{CloudResourceKind, Observation};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EstateRecord {
    pub id: Uuid,
    pub record_type: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub detail: EstateDetail,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EstateDetail {
    pub kind: String,
    pub name: String,
    pub source: Option<Uuid>,
    pub target: Option<Uuid>,
    pub platform: Option<String>,
    pub state: Option<String>,
    pub confidence: String,
    pub basis: String,
    pub connector_id: Uuid,
    pub connector_type: String,
    pub observation_id: Uuid,
    pub registry_entry_id: Option<String>,
    pub hostname: Option<String>,
    pub source_ip: Option<String>,
    pub model: Option<String>,
    pub process_id: Option<String>,
    pub parent_process_id: Option<String>,
    pub region: Option<String>,
    pub identity_kind: Option<String>,
    pub config_file: Option<String>,
    pub port: Option<u16>,
    pub namespace: Option<String>,
    pub workload_kind: Option<String>,
    pub runtime_image: Option<String>,
    pub model_family: Option<String>,
    pub model_catalog_key: Option<String>,
    pub model_owner: Option<String>,
    pub country_code: Option<String>,
    pub modalities: Option<Vec<String>>,
    pub capabilities: Option<Vec<String>>,
    pub model_providers: Option<Vec<String>>,
    pub evidence_sources: Option<Vec<String>>,
    pub additional_source_ips: Option<Vec<String>>,
}

/// Deterministic identities never join people using an IP address. An Entra object ID is used
/// only when supplied by the source; otherwise the source-scoped identity is preserved.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn project(observation: &Observation) -> Vec<EstateRecord> {
    let mut graph = Projection {
        observation,
        records: Vec::new(),
    };
    let agent = &observation.agent;
    let actor = &observation.actor;
    let person = actor.identity.as_ref().map(|identity| {
        let key = agent
            .directory_object_id
            .as_deref()
            .unwrap_or(&identity.subject_key);
        let label = identity
            .email
            .as_deref()
            .or(identity.source_subject.as_deref())
            .unwrap_or("Unresolved identity");
        graph.node("identity", key, label, None)
    });
    let local_hostname = if is_ingress_flow(observation) {
        observation
            .destination
            .host
            .as_ref()
            .map(tally_core::Hostname::as_str)
    } else {
        actor.hostname.as_deref()
    };
    let local_ip = if is_ingress_flow(observation) {
        observation.destination.ip.as_ref()
    } else {
        actor.source_ip.as_ref()
    };
    let device_key = local_hostname
        .map(str::to_lowercase)
        .or_else(|| actor.device_key.as_deref().map(str::to_lowercase))
        .or_else(|| local_ip.map(|ip| format!("source-ip:{}", ip.as_str())));
    let device = device_key.as_deref().map(|key| {
        graph.node(
            "device",
            key,
            local_hostname.unwrap_or_else(|| {
                local_ip.map_or("Unresolved endpoint", tally_core::IpAddress::as_str)
            }),
            None,
        )
    });
    let workload = observation.workload.workload_key.as_deref().map(|key| {
        graph.node(
            "workload",
            key,
            observation
                .workload
                .workload_name
                .as_deref()
                .unwrap_or("AI workload"),
            None,
        )
    });
    let runtime = agent.key.as_deref().map(|key| {
        graph.node(
            agent.kind.as_deref().unwrap_or("agent"),
            key,
            agent.name.as_deref().unwrap_or("AI agent"),
            None,
        )
    });
    let cloud_runtime =
        if runtime.is_none() && observation.cloud.resource_kind == Some(CloudResourceKind::Agent) {
            observation
                .cloud
                .resource_key
                .as_deref()
                .map(|key| graph.node("agent", key, "Managed cloud agent", None))
        } else {
            None
        };
    let runtime = runtime.or(cloud_runtime);
    let parent = agent.parent_key.as_deref().map(|key| {
        graph.node(
            "agent",
            key,
            agent.parent_name.as_deref().unwrap_or("Parent agent"),
            None,
        )
    });
    if let (Some(parent), Some(child)) = (parent, runtime) {
        graph.edge(
            parent,
            child,
            if agent.kind.as_deref() == Some("mcp_server") {
                "calls"
            } else {
                "spawns"
            },
        );
    }
    if let Some(device) = device {
        if let Some(person) = person {
            graph.edge(
                person,
                device,
                if local_hostname.is_some() {
                    "observed on"
                } else {
                    "observed from"
                },
            );
        }
        if let Some(runtime) = parent.or(runtime) {
            graph.edge(
                device,
                runtime,
                if agent.platform.as_deref() == Some("remote") {
                    "connects to"
                } else if agent.kind.as_deref() == Some("mcp_config") {
                    "declares"
                } else {
                    "runs"
                },
            );
        }
    } else if let (Some(person), Some(runtime)) = (person, runtime) {
        graph.edge(person, runtime, "associated with");
    }
    if let (Some(workload), Some(runtime)) = (workload, runtime) {
        graph.edge(
            workload,
            runtime,
            if agent.platform.as_deref() == Some("n8n") {
                "contains"
            } else {
                "hosts"
            },
        );
    }
    let provider = observation
        .service
        .vendor_application_id
        .as_deref()
        .map(|entry| graph.node("provider", entry, entry, Some(entry)));
    let remote_hostname = if is_ingress_flow(observation) {
        actor.hostname.as_deref()
    } else {
        observation
            .destination
            .host
            .as_ref()
            .map(tally_core::Hostname::as_str)
    };
    let destination = remote_hostname.map(|host| {
        graph.node(
            "endpoint",
            host,
            host,
            observation.service.vendor_application_id.as_deref(),
        )
    });
    let model = observation
        .service
        .declared_model_id
        .as_deref()
        .map(|name| {
            let key = format!(
                "{}:{name}",
                observation
                    .service
                    .vendor_application_id
                    .as_deref()
                    .unwrap_or("unknown")
            );
            graph.node(
                "model",
                &key,
                name,
                observation.service.vendor_application_id.as_deref(),
            )
        });
    let origin = runtime.or(workload).or(device).or(person);
    if let (Some(source), Some(target)) = (origin, destination.or(model).or(provider)) {
        graph.edge(
            source,
            target,
            if observation.agent.platform.as_deref() == Some("n8n") {
                "configured to use"
            } else if observation.service.ai_request {
                "calls"
            } else {
                "observed connection"
            },
        );
    }
    if let (Some(endpoint), Some(provider)) = (destination, provider) {
        graph.edge(endpoint, provider, "provided by");
    }
    if let (Some(model), Some(provider)) = (model, provider) {
        graph.edge(model, provider, "provided by");
    }
    if let (Some(endpoint), Some(model)) = (destination, model) {
        graph.edge(endpoint, model, "serves");
    }
    // Cloud model/deployment inventory can lack a DNS endpoint and a declared model name.
    if runtime.is_none()
        && let Some(key) = observation.cloud.resource_key.as_deref()
    {
        let resource = graph.node("workload", key, "Managed AI resource", None);
        if let Some(provider) = provider {
            graph.edge(resource, provider, "provided by");
        }
    }
    graph.records
}

fn is_ingress_flow(o: &Observation) -> bool {
    o.cloud.usage_kind == Some(tally_core::CloudUsageKind::NetworkFlow)
        && o.network.direction == Some(tally_core::FlowDirection::Ingress)
}

struct Projection<'a> {
    observation: &'a Observation,
    records: Vec<EstateRecord>,
}
impl Projection<'_> {
    fn detail(&self) -> EstateDetail {
        let o = self.observation;
        EstateDetail {
            confidence: o.agent.attribution_confidence.clone().unwrap_or_else(|| {
                if o.actor.identity.is_some() {
                    "source_reported"
                } else {
                    "unattributed"
                }
                .to_owned()
            }),
            basis: o
                .agent
                .attribution_basis
                .clone()
                .unwrap_or_else(|| "Source metadata; no IP-based identity join".to_owned()),
            connector_id: o.connector.instance_id,
            connector_type: o.connector.connector_type.clone(),
            observation_id: o.observation_id,
            platform: o.agent.platform.clone(),
            state: o.agent.state.clone(),
            hostname: if is_ingress_flow(o) {
                o.destination
                    .host
                    .as_ref()
                    .map(|host| host.as_str().to_owned())
            } else {
                o.actor.hostname.clone()
            },
            source_ip: if is_ingress_flow(o) {
                o.destination.ip.as_ref()
            } else {
                o.actor.source_ip.as_ref()
            }
            .map(|ip| ip.as_str().to_owned()),
            model: o.service.declared_model_id.clone(),
            process_id: o.agent.process_id.clone(),
            parent_process_id: o.agent.parent_process_id.clone(),
            region: o.cloud.region.clone(),
            identity_kind: o.agent.identity_kind.clone(),
            config_file: o.agent.config_file.clone(),
            namespace: o.workload.namespace_name.clone(),
            workload_kind: o.workload.workload_kind.and_then(|kind| {
                serde_json::to_value(kind)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
            }),
            runtime_image: o.workload.runtime_image.clone(),
            additional_source_ips: Some(
                o.actor
                    .additional_source_ips
                    .iter()
                    .map(|ip| ip.as_str().to_owned())
                    .collect(),
            ),
            ..EstateDetail::default()
        }
    }
    fn node(&mut self, kind: &str, key: &str, name: &str, registry: Option<&str>) -> Uuid {
        let id = Uuid::new_v5(
            &self.observation.installation_id,
            format!("estate:{kind}:{key}").as_bytes(),
        );
        let mut detail = self.detail();
        if kind == "endpoint" {
            detail.port = self.observation.destination.port;
        }
        if kind == "device" && key.starts_with("source-ip:") {
            detail.state = Some("source address".into());
            detail.basis.push_str(". A source IP can be a proxy or shared address; it does not prove a unique device.");
        }
        kind.clone_into(&mut detail.kind);
        detail.name = name.chars().take(256).collect();
        detail.registry_entry_id = registry.map(str::to_owned);
        self.push(id, "node", detail);
        id
    }
    fn edge(&mut self, source: Uuid, target: Uuid, relationship: &str) {
        let id = Uuid::new_v5(
            &self.observation.installation_id,
            format!(
                "estate:{source}:{target}:{relationship}:{}",
                self.observation.connector.instance_id
            )
            .as_bytes(),
        );
        let mut detail = self.detail();
        relationship.clone_into(&mut detail.kind);
        relationship.clone_into(&mut detail.name);
        detail.source = Some(source);
        detail.target = Some(target);
        self.push(id, "edge", detail);
    }
    fn push(&mut self, id: Uuid, record_type: &str, detail: EstateDetail) {
        self.records.push(EstateRecord {
            id,
            record_type: record_type.to_owned(),
            first_seen: self.observation.observed_at.timestamp_millis(),
            last_seen: self.observation.observed_at.timestamp_millis(),
            detail,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_mcp_calls_keep_parent_relationships_distinct_from_subagents() {
        let mut observation = Observation::new(
            Uuid::from_u128(1),
            chrono::Utc::now(),
            tally_core::ConnectorRef {
                instance_id: Uuid::from_u128(2),
                connector_type: "runtime".into(),
                implementation_version: "test".into(),
                source_lineage_id: None,
            },
            tally_core::ObservationKind::AgentActivity,
            tally_core::EvidenceReceipt::ExternalPointer {
                source_record_id: "event-1".into(),
                location_hint: None,
            },
        );
        observation.agent.key = Some("child".into());
        observation.agent.name = Some("GitHub MCP".into());
        observation.agent.kind = Some("mcp_server".into());
        observation.agent.parent_key = Some("coding-install".into());
        observation.agent.parent_name = Some("Codex".into());
        let records = project(&observation);
        let parent = records.iter().find(|r| r.detail.name == "Codex").unwrap();
        let child = records
            .iter()
            .find(|r| r.detail.name == "GitHub MCP")
            .unwrap();
        assert!(records.iter().any(|r| r.detail.kind == "calls"
            && r.detail.source == Some(parent.id)
            && r.detail.target == Some(child.id)));
        observation.agent.kind = Some("agent".into());
        assert!(
            project(&observation)
                .iter()
                .any(|r| r.detail.kind == "spawns")
        );
    }
}
