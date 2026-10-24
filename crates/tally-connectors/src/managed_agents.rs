//! Read-only managed-agent metadata. Never retain workflow parameters, prompts or credentials.
use crate::{
    ConnectorDescriptor, ConnectorTransport, ObservationBatch, ReplayCapability,
    VendorImportConfig, VendorImportError, VendorImportOutcome, VendorImportStats,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tally_core::{
    ConnectorRef, DigestAlgorithm, EvidenceReceipt, IdentityAuthority, IdentityObservation,
    IdentitySubjectKind, Observation, ObservationKind,
};

/// Hosted providers use fixed origins; scope selectors cannot contain credentials or URL syntax.
#[must_use]
pub fn managed_agents_scope_valid(platform: &str, origin: &str, scope: Option<&str>) -> bool {
    let expected = match platform {
        "openai" => "https://api.openai.com",
        "claude" => "https://api.anthropic.com",
        "gemini" => "https://generativelanguage.googleapis.com",
        _ => return scope.is_none(),
    };
    if origin.trim_end_matches('/') != expected {
        return false;
    }
    scope.is_none_or(|scope| {
        let token = |s: &str| {
            !s.is_empty()
                && s.len() <= 128
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        };
        if platform == "gemini" {
            let parts = scope.split('/').collect::<Vec<_>>();
            parts.len() == 4
                && parts[0] == "projects"
                && token(parts[1])
                && parts[2] == "locations"
                && token(parts[3])
        } else {
            token(scope)
        }
    })
}

#[must_use]
pub fn managed_agents_descriptor(platform: &str) -> ConnectorDescriptor {
    let (name, permission) = match platform {
        "servicenow" => ("ServiceNow AI Agents", "Table API read ACL on sn_aia_agent"),
        "n8n" => ("n8n AI workflows", "workflow:read (public API)"),
        "copilot_studio" => (
            "Microsoft Copilot Studio",
            "Dataverse application user with read access to the bot table",
        ),
        "langgraph" => (
            "LangSmith / LangGraph agents",
            "LangSmith API key authorized to search assistants in the deployment",
        ),
        "dify" => (
            "Dify AI application",
            "Application-scoped API key with access to /v1/info",
        ),
        "openai" => (
            "OpenAI Agents",
            "Project API key with read access to the Agents API",
        ),
        "claude" => (
            "Claude Managed Agents",
            "Workspace API key with Managed Agents read access",
        ),
        "gemini" => (
            "Gemini AI Studio Managed Agents",
            "Gemini API key for the project containing the saved agents",
        ),
        _ => ("Unknown managed AI platform", "Unsupported platform"),
    };
    ConnectorDescriptor {
        connector_type: format!("{platform}_agents_api_v1"), display_name: name.into(),
        source_vendor: platform.into(), source_product: "Managed AI agents".into(), implementation_version: env!("CARGO_PKG_VERSION").into(),
        record_variants: vec!["agent configuration metadata".into()], transport: ConnectorTransport::Pull,
        required_permissions: vec![permission.into()],
        requested_fields: vec!["AI resource ID, display name, configured or archived state, configured model, kind, graph ID or creator when supplied".into()], prohibited_fields: vec!["prompts, instructions, workflow parameters, credentials and execution bodies".into()],
        cursor_semantics: "One bounded page per poll, durably checkpointed after ingestion; complete inventories repeat. Dify reads one configured application per connection.".into(), replay_capability: ReplayCapability::DurableCursor,
        health_capabilities: vec!["API reachability and read permission".into()], coverage_capabilities: vec!["configured agents, not agent executions".into()],
        privacy_contract: "Retains allowlisted AI inventory metadata; all workflow content and credentials are discarded before admission.".into(),
    }
}
#[derive(Deserialize)]
struct Projection {
    platform: String,
    origin: String,
    #[serde(default)]
    scope: Option<String>,
    observed_at: DateTime<Utc>,
    records: Vec<Value>,
}

/// Normalize `ServiceNow` Table API or n8n workflow metadata supplied by the bounded collector.
/// # Errors
/// Returns an error for malformed, unsupported or oversized projections.
#[allow(
    clippy::too_many_lines,
    clippy::case_sensitive_file_extension_comparisons
)] // n8n node type suffixes are case-sensitive API identifiers.
pub fn import_managed_agents_json(
    input: &[u8],
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    if input.len() > crate::MAX_IMPORT_BYTES {
        return Err(VendorImportError::ImportTooLarge(input.len()));
    }
    let p: Projection =
        serde_json::from_slice(input).map_err(|_| VendorImportError::MalformedRecord { row: 1 })?;
    if !matches!(
        p.platform.as_str(),
        "n8n"
            | "servicenow"
            | "copilot_studio"
            | "langgraph"
            | "dify"
            | "openai"
            | "claude"
            | "gemini"
    ) || p.records.len() > 250
    {
        return Err(VendorImportError::InvalidField {
            row: 1,
            field: "platform_or_page_size",
        });
    }
    let origin = url::Url::parse(&p.origin).map_err(|_| VendorImportError::InvalidField {
        row: 1,
        field: "origin",
    })?;
    let origin = origin.origin().ascii_serialization();
    let mut observations = Vec::new();
    for record in &p.records {
        if p.platform == "servicenow" {
            if let (Some(id), Some(name)) = (text(record, "sys_id"), text(record, "name")) {
                let mut o = base(&p, config);
                o.agent.key = Some(
                    config
                        .pseudonymization_key
                        .pseudonym_exact("managed_agent", &format!("{origin}:{id}")),
                );
                o.agent.name = Some(name);
                o.agent.kind = Some("agent".into());
                o.agent.state = Some(
                    if boolean(record.get("active")) {
                        "active"
                    } else {
                        "inactive"
                    }
                    .into(),
                );
                if let Some(creator) = text(record, "sys_created_by") {
                    identity(&mut o, &creator, &origin, config);
                }
                observations.push(o);
            }
        } else if p.platform == "n8n" {
            if let (Some(id), Some(name), Some(nodes)) = (
                text(record, "id"),
                text(record, "name"),
                record.get("nodes").and_then(Value::as_array),
            ) {
                if nodes.len() > 2000 {
                    return Err(VendorImportError::InvalidField {
                        row: 1,
                        field: "workflow_nodes_exceeded",
                    });
                }
                for node in nodes {
                    let Some(node_type) = text(node, "type") else {
                        continue;
                    };
                    if !node_type.starts_with("@n8n/n8n-nodes-langchain.") {
                        continue;
                    }
                    let kind = if node_type.ends_with(".agent") || node_type.ends_with(".agentTool")
                    {
                        "agent"
                    } else if node_type.ends_with(".mcpTrigger") {
                        "mcp_server"
                    } else {
                        "workflow"
                    };
                    let Some(node_id) = text(node, "id") else {
                        continue;
                    };
                    let mut o = base(&p, config);
                    o.agent.key = Some(
                        config
                            .pseudonymization_key
                            .pseudonym_exact("managed_agent", &format!("{origin}:{id}:{node_id}")),
                    );
                    o.workload.workload_key = Some(
                        config
                            .pseudonymization_key
                            .pseudonym_exact("managed_workflow", &format!("{origin}:{id}")),
                    );
                    o.workload.workload_name = Some(name.clone());
                    o.agent.name = Some(format!(
                        "{} / {}",
                        name,
                        text(node, "name").unwrap_or(node_type)
                    ));
                    o.agent.kind = Some(kind.into());
                    o.agent.state = Some(
                        if boolean(record.get("active")) {
                            "active"
                        } else {
                            "inactive"
                        }
                        .into(),
                    );
                    // Only a bounded literal model identifier is useful; expressions and parameters
                    // may contain secrets or prompts and are deliberately not copied.
                    if let Some(model) = node
                        .pointer("/parameters/model")
                        .and_then(Value::as_str)
                        .filter(|s| {
                            s.len() <= 128
                                && s.bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b"._-:/".contains(&b))
                        })
                    {
                        o.service.declared_model_id = Some(model.to_owned());
                    }
                    observations.push(o);
                }
            }
        } else {
            observations.push(platform_agent(record, &p, &origin, config)?);
        }
    }
    let accepted = observations.len() as u64;
    // A control receipt allows ordinary-workflow-only pages to advance without retaining them.
    if observations.is_empty() {
        let mut o = base(&p, config);
        o.kind = ObservationKind::ConnectorHealth;
        observations.push(o);
    }
    for o in &mut observations {
        let digest = hex::encode(Sha256::digest(
            serde_json::to_vec(&(&o.agent, &o.service, &o.workload, &o.actor, o.observed_at))
                .map_err(|_| VendorImportError::Serialization)?,
        ));
        o.observation_id = uuid::Uuid::new_v5(&config.connector_instance_id, digest.as_bytes());
        o.source = EvidenceReceipt::RecordDigest {
            algorithm: DigestAlgorithm::Sha256,
            digest,
        };
    }
    observations.sort_by_key(|o| o.observation_id);
    observations.dedup_by_key(|o| o.observation_id);
    Ok(VendorImportOutcome {
        batch: ObservationBatch::build(observations, config.checkpoint.clone())?,
        stats: VendorImportStats {
            records_read: p.records.len() as u64,
            accepted,
            ignored: if accepted == 0 {
                p.records.len() as u64
            } else {
                0
            },
            rejected: 0,
        },
        redaction: crate::RedactionProof {
            connector_type: format!("{}_agents_api_v1", p.platform),
            pseudonymization: "hmac_sha256_installation_key_v1".into(),
            discarded_fields: vec![
                "workflow parameters, credentials, prompts, instructions, execution data".into(),
            ],
            source_bytes_retained: false,
        },
    })
}
fn platform_agent(
    record: &Value,
    p: &Projection,
    origin: &str,
    config: &VendorImportConfig,
) -> Result<Observation, VendorImportError> {
    let id = text(
        record,
        if p.platform == "copilot_studio" {
            "botid"
        } else if p.platform == "langgraph" {
            "assistant_id"
        } else {
            "id"
        },
    )
    .ok_or(VendorImportError::InvalidField {
        row: 1,
        field: "agent_id",
    })?;
    let mut o = base(p, config);
    let hosted = matches!(p.platform.as_str(), "openai" | "claude" | "gemini");
    // Gemini IDs are user-chosen and may repeat across projects. An unscoped key's
    // inventory is isolated by connection, including after credential rotation.
    let scoped_origin = if hosted {
        format!(
            "{origin}:{}",
            p.scope
                .clone()
                .unwrap_or_else(|| config.connector_instance_id.to_string())
        )
    } else {
        origin.to_owned()
    };
    o.agent.key = Some(config.pseudonymization_key.pseudonym_exact(
        "managed_agent",
        &format!("{}:{scoped_origin}:{id}", p.platform),
    ));
    o.agent.name = Some(
        text(record, "name")
            .or_else(|| text(record, "display_name"))
            .unwrap_or_else(|| {
                if hosted {
                    id.clone()
                } else {
                    "Unnamed AI application".into()
                }
            }),
    );
    o.agent.kind = Some(
        if p.platform == "dify" && text(record, "mode").as_deref() != Some("agent-chat") {
            "workflow"
        } else {
            "agent"
        }
        .into(),
    );
    o.agent.state = Some(
        if p.platform == "copilot_studio" {
            match record.get("statecode").and_then(Value::as_u64) {
                Some(0) => "active",
                Some(1) => "inactive",
                _ => "configured",
            }
        } else if p.platform == "claude" && record.get("archived_at").is_some_and(|v| !v.is_null())
        {
            "archived"
        } else {
            "configured"
        }
        .into(),
    );
    if hosted {
        o.service.vendor_application_id = Some(
            match p.platform.as_str() {
                "openai" => "provider.openai",
                "claude" => "provider.anthropic",
                _ => "provider.google",
            }
            .into(),
        );
        o.service.declared_model_id = text(record, "model")
            .or_else(|| record.get("model").and_then(|model| text(model, "id")))
            .or_else(|| {
                record
                    .get("agent_config")
                    .and_then(|config| text(config, "model"))
            })
            .filter(|model| {
                model.len() <= 128
                    && model
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-:/".contains(&b))
            });
    }
    if p.platform == "langgraph"
        && let Some(graph) = text(record, "graph_id")
    {
        o.workload.workload_key = Some(
            config
                .pseudonymization_key
                .pseudonym_exact("managed_graph", &format!("{origin}:{graph}")),
        );
        o.workload.workload_name = Some(graph);
    }
    Ok(o)
}

fn base(p: &Projection, config: &VendorImportConfig) -> Observation {
    let mut o = Observation::new(
        config.installation_id,
        p.observed_at,
        ConnectorRef {
            instance_id: config.connector_instance_id,
            connector_type: format!("{}_agents_api_v1", p.platform),
            implementation_version: config.implementation_version.clone(),
            source_lineage_id: config.source_lineage_id.clone(),
        },
        ObservationKind::SaasCapability,
        EvidenceReceipt::RecordDigest {
            algorithm: DigestAlgorithm::Sha256,
            digest: "0".repeat(64),
        },
    );
    o.received_at = config.received_at;
    o.agent.platform = Some(p.platform.clone());
    o.agent.attribution_confidence = Some("unattributed".into());
    o.agent.attribution_basis =
        Some("Configured inventory from the platform API; execution is not implied".into());
    o
}
fn identity(o: &mut Observation, creator: &str, origin: &str, config: &VendorImportConfig) {
    o.inventory.user_role = Some(tally_core::IdentityRole::Creator);
    o.actor.identity = Some(IdentityObservation {
        subject_key: config.pseudonymization_key.pseudonym_exact(
            "managed_creator",
            &format!(
                "{}:{origin}:{creator}",
                o.agent.platform.as_deref().unwrap_or_default()
            ),
        ),
        email: crate::crowdstrike::recognized_email(creator),
        source_subject: Some(creator.to_owned()),
        source_subject_kind: Some(IdentitySubjectKind::UserName),
        authority: Some(IdentityAuthority::SourceNative),
        directory_key: None,
        application_key: None,
        display_label: None,
    });
    o.agent.attribution_confidence = Some("source_reported".into());
    o.agent.attribution_basis =
        Some("Platform record creator; not evidence of who executed the agent".into());
    o.agent.identity_kind = Some("creator".into());
}
fn text(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|v| {
            v.as_str()
                .map(str::to_owned)
                .or_else(|| v.as_u64().map(|n| n.to_string()))
        })
        .filter(|s| !s.is_empty() && s.len() <= 512 && !s.chars().any(char::is_control))
}
fn boolean(value: Option<&Value>) -> bool {
    value.is_some_and(|v| v == true || v == "true")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosted_agents_retain_models_and_state_without_content_and_isolate_scopes() {
        for (platform, record, name, model, state) in [
            (
                "openai",
                serde_json::json!({"id":"a1","name":"Research","model":"gpt-5","instructions":"PRIVATE_CONTENT_CANARY"}),
                "Research",
                "gpt-5",
                "configured",
            ),
            (
                "claude",
                serde_json::json!({"id":"a1","name":"Archived agent","model":{"id":"claude-sonnet-4-6"},"archived_at":"2026-10-15T00:00:00Z","system":"PRIVATE_CONTENT_CANARY"}),
                "Archived agent",
                "claude-sonnet-4-6",
                "archived",
            ),
            (
                "gemini",
                serde_json::json!({"id":"research","display_name":"Research","agent_config":{"model":"gemini-2.5-pro"},"system_instruction":"PRIVATE_CONTENT_CANARY","base_environment":{"env":{"TOKEN":"PRIVATE_CONTENT_CANARY"}}}),
                "Research",
                "gemini-2.5-pro",
                "configured",
            ),
        ] {
            let config = config();
            let mut value = serde_json::json!({"platform":platform,"origin":"https://provider.example","scope":"project-one","observed_at":"2026-10-16T00:00:00Z","records":[record]});
            let import = |v: &Value| {
                import_managed_agents_json(&serde_json::to_vec(v).unwrap(), &config).unwrap()
            };
            let first = import(&value);
            let observation = &first.batch.observations[0];
            assert_eq!(observation.agent.name.as_deref(), Some(name));
            assert_eq!(
                observation.service.declared_model_id.as_deref(),
                Some(model)
            );
            assert_eq!(observation.agent.state.as_deref(), Some(state));
            assert_eq!(observation.agent.kind.as_deref(), Some("agent"));
            assert_eq!(
                observation.agent.attribution_confidence.as_deref(),
                Some("unattributed")
            );
            assert!(observation.actor.identity.is_none());
            assert!(
                !serde_json::to_string(&first)
                    .unwrap()
                    .contains("PRIVATE_CONTENT_CANARY")
            );
            assert_eq!(
                observation.agent.key,
                import(&value).batch.observations[0].agent.key
            );
            value["scope"] = Value::String("project-two".into());
            assert_ne!(
                observation.agent.key,
                import(&value).batch.observations[0].agent.key
            );
            value["records"][0]["name"] = Value::Null;
            value["records"][0]["display_name"] = Value::Null;
            assert_eq!(
                import(&value).batch.observations[0].agent.name,
                text(&value["records"][0], "id")
            );
        }
    }

    #[test]
    fn hosted_agent_origins_and_scope_selectors_are_bounded() {
        for (platform, origin, scope) in [
            ("openai", "https://api.openai.com", "proj_test"),
            ("claude", "https://api.anthropic.com", "wrkspc_test"),
            (
                "gemini",
                "https://generativelanguage.googleapis.com",
                "projects/test/locations/global",
            ),
        ] {
            assert!(managed_agents_scope_valid(platform, origin, Some(scope)));
            assert!(managed_agents_scope_valid(platform, origin, None));
            assert!(!managed_agents_scope_valid(
                platform,
                "https://attacker.example",
                Some(scope)
            ));
            assert!(!managed_agents_scope_valid(platform, origin, Some("")));
            assert!(!managed_agents_scope_valid(
                platform,
                origin,
                Some("secret\r\nheader:value")
            ));
        }
        assert!(!managed_agents_scope_valid(
            "gemini",
            "https://generativelanguage.googleapis.com",
            Some("projects/test")
        ));
        assert!(!managed_agents_scope_valid(
            "dify",
            "https://api.dify.ai",
            Some("project")
        ));
    }
    fn config() -> VendorImportConfig {
        VendorImportConfig {
            installation_id: uuid::Uuid::from_u128(1),
            connector_instance_id: uuid::Uuid::from_u128(2),
            implementation_version: "test".into(),
            source_lineage_id: None,
            received_at: Utc::now(),
            checkpoint: crate::Cursor("page1".into()),
            pseudonymization_key: crate::PseudonymizationKey::new(&[7; 32]).unwrap(),
        }
    }
    #[test]
    fn managed_platforms_keep_inventory_without_content_or_execution_claims() {
        let rows = [
            (
                "copilot_studio",
                serde_json::json!({"botid":"bot1","name":"Support copilot","statecode":1,"configuration":"PRIVATE_CONTENT_CANARY","_ownerid_value":"not-a-person"}),
                "agent",
                "inactive",
            ),
            (
                "langgraph",
                serde_json::json!({"assistant_id":"a1","name":"Triage","graph_id":"support","config":{"prompt":"PRIVATE_CONTENT_CANARY"},"metadata":{"secret":"PRIVATE_CONTENT_CANARY"}}),
                "agent",
                "configured",
            ),
            (
                "dify",
                serde_json::json!({"id":"app1","name":"Helpdesk","mode":"agent-chat","description":"PRIVATE_CONTENT_CANARY"}),
                "agent",
                "configured",
            ),
            (
                "dify",
                serde_json::json!({"id":"app2","name":"Routing","mode":"workflow"}),
                "workflow",
                "configured",
            ),
        ];
        for (platform, record, kind, state) in rows {
            let config = config();
            let value = serde_json::json!({"platform":platform,"origin":"https://platform.example","observed_at":"2026-10-09T00:00:00Z","records":[record]});
            let input = serde_json::to_vec(&value).unwrap();
            let normalized = import_managed_agents_json(&input, &config).unwrap();
            let o = &normalized.batch.observations[0];
            assert_eq!(o.agent.kind.as_deref(), Some(kind));
            assert_eq!(o.agent.state.as_deref(), Some(state));
            assert!(o.actor.identity.is_none());
            assert!(
                o.agent
                    .attribution_basis
                    .as_ref()
                    .unwrap()
                    .contains("execution is not implied")
            );
            assert!(
                !serde_json::to_string(&normalized.batch)
                    .unwrap()
                    .contains("PRIVATE_CONTENT_CANARY")
            );
            assert_eq!(
                o.observation_id,
                import_managed_agents_json(&input, &config)
                    .unwrap()
                    .batch
                    .observations[0]
                    .observation_id
            );
        }
    }
    #[test]
    fn n8n_keeps_ai_nodes_without_workflow_content() {
        let value = serde_json::json!({"platform":"n8n","origin":"https://n8n.example.com","observed_at":"2026-10-07T00:00:00Z","records":[{"id":"wf1","name":"Support","active":true,"nodes":[{"id":"a","name":"Triage","type":"@n8n/n8n-nodes-langchain.agent","parameters":{"prompt":"secret-prompt-canary"},"credentials":{"key":"secret-key-canary"}},{"id":"b","name":"Normal HTTP","type":"n8n-nodes-base.httpRequest"}]}]});
        let result =
            import_managed_agents_json(&serde_json::to_vec(&value).unwrap(), &config()).unwrap();
        assert_eq!(result.stats.accepted, 1);
        assert_eq!(
            result.batch.observations[0]
                .workload
                .workload_name
                .as_deref(),
            Some("Support")
        );
        assert_eq!(
            result.batch.observations[0].agent.name.as_deref(),
            Some("Support / Triage")
        );
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(!encoded.contains("secret-prompt-canary"));
        assert!(!encoded.contains("secret-key-canary"));
        assert!(!encoded.contains("Normal HTTP"));
    }
    #[test]
    fn ordinary_workflow_page_can_checkpoint_without_becoming_inventory() {
        let value = serde_json::json!({"platform":"n8n","origin":"https://n8n.example.com","observed_at":"2026-10-07T00:00:00Z","records":[{"id":"wf1","name":"Normal","nodes":[{"id":"a","type":"n8n-nodes-base.httpRequest"}]}]});
        let result =
            import_managed_agents_json(&serde_json::to_vec(&value).unwrap(), &config()).unwrap();
        assert_eq!(result.stats.accepted, 0);
        assert_eq!(
            result.batch.observations[0].kind,
            ObservationKind::ConnectorHealth
        );
        assert!(result.batch.observations[0].agent.key.is_none());
    }
    #[test]
    fn servicenow_creator_is_not_an_execution_claim() {
        let value = serde_json::json!({"platform":"servicenow","origin":"https://demo.service-now.com","observed_at":"2026-10-07T00:00:00Z","records":[{"sys_id":"agent1","name":"IT triage","active":"false","sys_created_by":"admin","instructions":"instructions-canary"}]});
        let result =
            import_managed_agents_json(&serde_json::to_vec(&value).unwrap(), &config()).unwrap();
        let agent = &result.batch.observations[0].agent;
        assert_eq!(agent.state.as_deref(), Some("inactive"));
        assert_eq!(agent.identity_kind.as_deref(), Some("creator"));
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("instructions-canary")
        );
    }
}
