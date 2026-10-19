mod legacy;
pub(super) mod review;

use super::{
    ApiError, AppState, Arc, CloudUsageKind, Deserialize, Hostname, IpAddress, Json, Observation,
    ObservationBuffer, Query, RegistryBundle, StatusCode, Utc, detect,
};

/// Attach persistent AI telemetry using a caller-supplied `ClickHouse` database. Gate supplies its
/// existing database; standalone Tally supplies its own. A `PostgreSQL` advisory transaction lock
/// serializes Tally's independent `ClickHouse` migration series across API and worker processes.
///
/// Hosts pass `apply_migrations = false` in API processes and `true` in the migration-owning
/// worker. Standalone tallyd owns both roles.
///
/// # Errors
/// Returns an error on invalid configuration, unavailable storage, or migration/checksum failure.
pub async fn with_clickhouse(
    mut state: AppState,
    url: &str,
    database: &str,
    retention_days: u16,
    apply_migrations: bool,
) -> anyhow::Result<AppState> {
    let identity = state.postgres.get_or_create_installation_identity().await?;
    let observations =
        ObservationBuffer::persistent(url, database, identity.installation_id, retention_days)?;
    if apply_migrations {
        let mut transaction = state.postgres.pool().begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(714835921043)")
            .execute(&mut *transaction)
            .await?;
        observations.migrate().await?;
        legacy::bootstrap(&mut transaction, &observations, identity.installation_id).await?;
        transaction.commit().await?;
    } else {
        observations.verify_migrations().await?;
    }
    state.observations = Arc::new(observations);
    Ok(state)
}

/// Common admission boundary for every connector and scanner. AI model/control-plane inventory
/// is retained even without invocation evidence. Explicitly evaluated non-AI HTTP is rejected.
fn retained_ai(
    observations: &[Observation],
    registry: &RegistryBundle,
) -> Result<Vec<Observation>, ApiError> {
    let mut retained = Vec::new();
    for observation in observations {
        if observation.service.ai_request_evaluated
            && !observation.service.ai_request
            && observation.agent.key.is_none()
        {
            continue;
        }
        let detection = detect(observation, registry)
            .map_err(|_| ApiError::dependency_message("registry_detection_failed"))?;
        let cloud_ai = observation.cloud.provider_service.is_some()
            && (observation.cloud.usage_kind == Some(CloudUsageKind::Invocation)
                || matches!(
                    observation.cloud.resource_kind,
                    Some(
                        tally_core::CloudResourceKind::Agent
                            | tally_core::CloudResourceKind::FoundationModel
                            | tally_core::CloudResourceKind::ModelArtifact
                            | tally_core::CloudResourceKind::ModelDeployment
                            | tally_core::CloudResourceKind::InferenceEndpoint
                            | tally_core::CloudResourceKind::KnowledgeBase
                    )
                ));
        let explicit = observation
            .workload
            .runtime_registry_entry_id
            .as_deref()
            .or(observation.service.vendor_application_id.as_deref());
        let entry = explicit
            .and_then(|id| registry.entries.iter().find(|entry| entry.id == id))
            .or_else(|| {
                detection.matches.first().and_then(|hit| {
                    registry
                        .entries
                        .iter()
                        .find(|entry| entry.id == hit.entry_id)
                })
            });
        if observation.agent.key.is_none()
            && !cloud_ai
            && entry.is_none()
            && !observation.service.ai_request
        {
            continue;
        }
        let mut observation = observation.clone();
        if let Some(entry) = entry {
            observation.service.vendor_application_id = Some(entry.id.clone());
            if entry.id == "runtime.mcp_streamable_http" && observation.agent.key.is_none() {
                let host = observation
                    .destination
                    .host
                    .as_ref()
                    .map(Hostname::as_str)
                    .or_else(|| observation.destination.ip.as_ref().map(IpAddress::as_str))
                    .unwrap_or("unknown");
                observation.agent.key = Some(format!(
                    "mcp:{host}:{}",
                    observation.destination.port.unwrap_or(443)
                ));
                observation.agent.name = Some(format!("MCP server · {host}"));
                observation.agent.kind = Some("mcp_server".into());
                observation.agent.platform = Some("remote".into());
                observation.agent.state = Some("observed".into());
            }
        }
        retained.push(observation);
    }
    Ok(retained)
}

/// Embedding hosts feed normalized, content-free metadata through the same AI admission boundary.
/// # Errors
/// Returns an error when admission or durable storage fails.
pub async fn retain_ai_observations(
    state: &AppState,
    observations: &[Observation],
    digest: &str,
) -> anyhow::Result<()> {
    append_ai(state, observations, digest)
        .await
        .map_err(|error| anyhow::anyhow!("Tally AI admission failed: {}", error.code))
}

pub(super) async fn append_ai(
    state: &AppState,
    observations: &[Observation],
    digest: &str,
) -> Result<(), ApiError> {
    state
        .observations
        .record_coverage(observations)
        .await
        .map_err(ApiError::dependency)?;
    let registry = state.registry.snapshot();
    let mut retained = retained_ai(observations, &registry)?;
    let candidates = correlation_candidates(state, observations).await?;
    for usage in super::correlate_cloud_flows(observations, &candidates, &registry)? {
        if retained
            .iter()
            .any(|o| o.observation_id == usage.observation_id)
        {
            continue;
        }
        if let Some(flow) = candidates
            .iter()
            .find(|o| o.observation_id == usage.observation_id)
        {
            let mut flow = flow.clone();
            flow.agent.attribution_confidence = Some("inferred".into());
            flow.agent.attribution_basis = Some("Unique cloud service, account and time-window match to an AI invocation; not an IP-based person join".into());
            flow.service.vendor_application_id = registry
                .entries
                .iter()
                .find(|e| {
                    e.id == usage.provider_key || e.id == format!("provider.{}", usage.provider_key)
                })
                .map(|e| e.id.clone());
            retained.push(flow);
        }
    }
    state
        .observations
        .append_observations(&retained, digest)
        .await
        .map_err(ApiError::dependency)?;
    let pending = observations
        .iter()
        .filter(|o| super::cloud_flow_is_correlation_candidate(o))
        .cloned()
        .collect::<Vec<_>>();
    state
        .pending_flows
        .append_observations(&pending, digest)
        .await
        .map_err(ApiError::dependency)?;
    state
        .pending_flows
        .delete_selected(
            true,
            false,
            Some((Utc::now() - chrono::Duration::minutes(30)).timestamp_millis()),
        )
        .await
        .map_err(ApiError::dependency)
}

pub(super) async fn correlation_candidates(
    state: &AppState,
    current: &[Observation],
) -> Result<Vec<Observation>, ApiError> {
    let mut candidates = state
        .observations
        .list_recent_observations(500, None)
        .await
        .map_err(ApiError::dependency)?;
    let cutoff = (Utc::now() - chrono::Duration::minutes(30)).timestamp_millis();
    candidates.extend(
        state
            .pending_flows
            .list_observations_since(10_000, Some(cutoff))
            .await
            .map_err(ApiError::dependency)?,
    );
    candidates.extend_from_slice(current);
    candidates.sort_by_key(|o| o.observation_id);
    candidates.dedup_by_key(|o| o.observation_id);
    Ok(candidates)
}

#[derive(Default, Deserialize)]
pub(super) struct EstateQuery {
    limit: Option<u32>,
    after: Option<uuid::Uuid>,
}

/// Bounded estate page for hosts that enrich inventory with their own governance decisions.
/// # Errors
/// Returns an error if inventory, reviews or catalog enrichment cannot be read.
pub async fn read_inventory(
    state: &AppState,
    limit: Option<u32>,
    after: Option<uuid::Uuid>,
) -> anyhow::Result<serde_json::Value> {
    inventory(
        axum::extract::State(state.clone()),
        Query(EstateQuery { limit, after }),
    )
    .await
    .map(|value| value.0)
    .map_err(|error| anyhow::anyhow!("Tally inventory unavailable: {}", error.code))
}

#[utoipa::path(get, path = "/api/v1/tally/estate", responses((status = 200, body = serde_json::Value)))]
pub(super) async fn inventory(
    axum::extract::State(state): axum::extract::State<AppState>,
    Query(query): Query<EstateQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let endpoint_devices = state
        .observations
        .coverage_count()
        .await
        .map_err(ApiError::dependency)?;
    let limit = query.limit.unwrap_or(500).clamp(1, 2000);
    let mut records = state
        .observations
        .estate(limit + 1, query.after)
        .await
        .map_err(ApiError::dependency)?;
    let more = records.len() > limit as usize;
    records.truncate(limit as usize);
    let next_cursor = more.then(|| records.last().map(|r| r.id)).flatten();
    let registry = state.registry.snapshot();
    let (providers, models) = tokio::join!(
        state.postgres.list_registry_providers(),
        catalog_models(&state, &records),
    );
    let providers = providers.map_err(ApiError::dependency)?;
    let models = models?;
    let review_rows = estate_reviews(&state, &records).await?;
    let records = records
        .into_iter()
        .map(|mut record| {
            let entry = record
                .detail
                .registry_entry_id
                .as_deref()
                .and_then(|id| registry.entries.iter().find(|entry| entry.id == id));
            if record.detail.kind == "provider"
                && let Some(entry) = entry
            {
                record.detail.name.clone_from(&entry.name);
            }
            let provider_key = entry
                .map(|entry| {
                    entry
                        .provider_ref
                        .as_deref()
                        .unwrap_or(&entry.id)
                        .trim_start_matches("provider.")
                })
                .or_else(|| {
                    record
                        .detail
                        .registry_entry_id
                        .as_deref()
                        .map(|id| id.trim_start_matches("provider."))
                })
                .map(str::to_owned);
            let mut sanctioned = if record.detail.kind == "model" {
                enrich_model(&mut record, &models)
            } else if matches!(record.detail.kind.as_str(), "provider" | "endpoint") {
                providers
                    .iter()
                    .find(|p| Some(p.key.as_str()) == provider_key.as_deref())
                    .and_then(|p| p.sanctioned)
            } else {
                None
            };
            let model = models
                .iter()
                .find(|m| Some(m.key.as_str()) == record.detail.model_catalog_key.as_deref());
            let provider = providers
                .iter()
                .find(|p| Some(p.key.as_str()) == provider_key.as_deref());
            if let Some(provider) =
                provider.filter(|_| entry.is_none() && record.detail.kind == "provider")
            {
                record.detail.name.clone_from(&provider.name);
            }
            let registry_id = if record.detail.kind == "model" {
                model.map(|m| m.model_id)
            } else if record.detail.kind == "provider" {
                provider.map(|p| p.provider_id)
            } else {
                None
            };
            let review = review_rows.get(&record.id);
            if let Some(decision) = review.and_then(|r| r.0) {
                sanctioned = Some(decision);
            }
            let mut value = serde_json::to_value(record).map_err(ApiError::dependency)?;
            value["sanctioned"] = serde_json::json!(sanctioned);
            value["flagged"] = serde_json::json!(review.is_some_and(|r| r.1));
            value["review_sanctioned"] = serde_json::json!(review.and_then(|r| r.0));
            value["registry_id"] = serde_json::json!(registry_id);
            Ok::<_, ApiError>(value)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(
        serde_json::json!({ "records": records, "next_cursor": next_cursor, "coverage": {
        "endpoint_devices_30d": endpoint_devices,
        "scope": "Observed and configured AI only. Coverage depends on connected sources and their permissions.",
        "limits": ["Network-only evidence cannot identify a local agent or stdio MCP server.", "Configured agents and MCP configuration files prove declared inventory, not execution.", "Identity comes from source metadata; Tally does not attribute users by IP alone.", "Devices include reported source addresses. An IP can be shared or belong to a proxy; it does not prove a unique device.", "Inventory survives AI log retention. Historical finding attribution does not prove request-level user/device co-occurrence."]
    } }),
    ))
}

type ReviewMap = std::collections::BTreeMap<uuid::Uuid, (Option<bool>, bool)>;
async fn estate_reviews(
    state: &AppState,
    records: &[tally_observation_buffer::estate::EstateRecord],
) -> Result<ReviewMap, ApiError> {
    let installation = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?
        .installation_id;
    let review_rows = sqlx::query_as::<_,(uuid::Uuid,Option<bool>,bool)>("SELECT entity_id,sanctioned,flagged FROM tally_estate_reviews WHERE installation_id=$1 AND entity_id=ANY($2)").bind(installation).bind(records.iter().map(|r|r.id).collect::<Vec<_>>()).fetch_all(state.postgres.pool()).await.map_err(ApiError::dependency)?;
    Ok(review_rows
        .into_iter()
        .map(|(id, sanctioned, flagged)| (id, (sanctioned, flagged)))
        .collect())
}

#[derive(Clone, Deserialize)]
struct CatalogModel {
    model_id: uuid::Uuid,
    key: String,
    name: String,
    aliases: Vec<String>,
    family: String,
    country_code: Option<String>,
    modalities: Vec<String>,
    capabilities: Vec<String>,
    owner_name: Option<String>,
    provider_names: Vec<String>,
    sanctioned: Option<bool>,
}

async fn catalog_models(
    state: &AppState,
    records: &[tally_observation_buffer::estate::EstateRecord],
) -> Result<Vec<CatalogModel>, ApiError> {
    // Enrich only this bounded page; avoid the full registry's finding-count aggregation.
    let mut keys = records
        .iter()
        .filter(|r| r.detail.kind == "model")
        .flat_map(|r| model_reference_keys(r.detail.model.as_deref().unwrap_or(&r.detail.name)))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query_scalar::<_, serde_json::Value>(
        r"
        SELECT jsonb_build_object(
            'model_id',m.model_id,'key',m.key,'name',m.name,'aliases',m.aliases,'family',m.family,'country_code',m.country_code,
            'modalities',m.modalities,'capabilities',m.capabilities,'sanctioned',m.sanctioned,
            'owner_name',owner.name,
            'provider_names',COALESCE((SELECT jsonb_agg(DISTINCT p.name)
                FROM ai_provider_models pm JOIN ai_providers p USING(provider_id)
                WHERE pm.model_id=m.model_id),'[]')
        ) FROM ai_models m LEFT JOIN ai_providers owner ON owner.provider_id=m.owner_provider_id
        WHERE m.key=ANY($1) OR m.name=ANY($1) OR m.aliases && $1::text[]
    ",
    )
    .bind(keys)
    .fetch_all(state.postgres.pool())
    .await
    .map_err(ApiError::dependency)?;
    rows.into_iter()
        .map(|row| serde_json::from_value(row).map_err(ApiError::dependency))
        .collect()
}

fn enrich_model(
    record: &mut tally_observation_buffer::estate::EstateRecord,
    models: &[CatalogModel],
) -> Option<bool> {
    let keys = model_reference_keys(
        record
            .detail
            .model
            .as_deref()
            .unwrap_or(&record.detail.name),
    );
    let mut candidates = models.iter().filter(|model| {
        keys.iter()
            .any(|key| *key == model.key || model.aliases.iter().any(|alias| alias == key))
            || (record.detail.model.is_none() && record.detail.name == model.name)
    });
    let model = candidates.next()?;
    if candidates.next().is_some() {
        return None;
    }
    record.detail.name.clone_from(&model.name);
    record.detail.model.get_or_insert_with(|| model.key.clone());
    record.detail.model_catalog_key = Some(model.key.clone());
    record.detail.model_family = Some(model.family.clone());
    record.detail.country_code.clone_from(&model.country_code);
    record.detail.modalities = Some(model.modalities.clone());
    record.detail.capabilities = Some(model.capabilities.clone());
    record.detail.model_providers = Some(model.provider_names.clone());
    record.detail.model_owner.clone_from(&model.owner_name);
    model.sanctioned
}

fn model_reference_keys(reference: &str) -> Vec<&str> {
    let mut keys = vec![reference];
    // Bedrock's public Claude IDs add a vendor prefix and optional release/version suffixes.
    // Only strip that documented namespace; arbitrary source model IDs remain exact matches.
    // https://docs.aws.amazon.com/bedrock/latest/userguide/claude-messages-extended-thinking.html
    let bedrock = ["us.", "eu.", "apac.", "global."]
        .iter()
        .find_map(|prefix| reference.strip_prefix(prefix))
        .unwrap_or(reference);
    let Some(mut alias) = bedrock
        .strip_prefix("anthropic.")
        .filter(|s| s.starts_with("claude-"))
    else {
        return keys;
    };
    keys.push(alias);
    if let Some((base, version)) = alias.rsplit_once("-v")
        && version.split(':').count() <= 2
        && version
            .split(':')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    {
        alias = base;
        keys.push(alias);
    }
    if let Some((base, release)) = alias.rsplit_once('-')
        && release.len() == 8
        && release.bytes().all(|b| b.is_ascii_digit())
        && chrono::NaiveDate::parse_from_str(release, "%Y%m%d").is_ok()
    {
        keys.push(base);
    }
    keys
}

#[derive(Default, Deserialize)]
pub(super) struct ActivityQuery {
    entity_id: Option<uuid::Uuid>,
    days: Option<u16>,
}
#[utoipa::path(get,path="/api/v1/tally/estate/activity",responses((status=200,body=serde_json::Value)))]
pub(super) async fn activity(
    axum::extract::State(state): axum::extract::State<AppState>,
    Query(query): Query<ActivityQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let days = query.days.unwrap_or(30);
    if ![7, 30].contains(&days) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "activity_window_invalid",
        ));
    }
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    let until = Utc::now().timestamp_millis();
    let since = until - i64::from(days) * 86_400_000;
    let summary = state
        .observations
        .activity(identity.installation_id, query.entity_id, since, until)
        .await
        .map_err(ApiError::dependency)?;
    Ok(Json(
        serde_json::json!({"days":days,"since":since,"until":until,"summary":summary,"scope":"Retained AI telemetry only. Configured inventory is not execution; bytes are included only when supplied by a source. Multiple sources may observe the same traffic."}),
    ))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ActivityRecordsQuery {
    days: u16,
    record_ids: Vec<uuid::Uuid>,
}
#[utoipa::path(post,path="/api/v1/tally/estate/activity/query",request_body=ActivityRecordsQuery,responses((status=200,body=serde_json::Value)))]
pub(super) async fn activity_records(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(query): Json<ActivityRecordsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if ![7, 30].contains(&query.days)
        || query.record_ids.is_empty()
        || query.record_ids.len() > 2000
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "activity_scope_invalid",
        ));
    }
    let installation = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?
        .installation_id;
    let until = Utc::now().timestamp_millis();
    let since = until - i64::from(query.days) * 86_400_000;
    let summary = state
        .observations
        .activity_for_records(installation, &query.record_ids, since, until)
        .await
        .map_err(ApiError::dependency)?;
    Ok(Json(
        serde_json::json!({"days":query.days,"since":since,"until":until,"summary":summary,"scope":"Retained AI records mentioning these loaded entities or relationships. Each observation is counted once even when it mentions several selected records. Configured inventory is not execution. Bytes require source measurements; independent sources may observe the same traffic."}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admission_discards_non_ai_and_preserves_agents_without_network() {
        let (registry, _) = crate::embedded_registry().expect("registry");
        let ordinary = crate::tests::usage_observation(tally_core::ObservationKind::DnsQuery);
        let mut ordinary = ordinary;
        ordinary.destination.host = Some(Hostname::parse("example.org").unwrap());
        ordinary.service = tally_core::ServiceObservation::default();
        let mut agent = ordinary.clone();
        agent.agent.key = Some("device:claude".into());
        agent.agent.name = Some("Claude Code".into());
        let rows = retained_ai(&[ordinary, agent], &registry).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].agent.name.as_deref(), Some("Claude Code"));
    }

    #[test]
    fn source_addresses_remain_visible_without_inventing_people_or_hostnames() {
        let mut observation =
            crate::tests::usage_observation(tally_core::ObservationKind::HttpMetadata);
        observation.actor = tally_core::ActorObservation {
            source_ip: Some(IpAddress::parse("10.20.1.14").unwrap()),
            ..Default::default()
        };
        let records = tally_observation_buffer::estate::project(&observation);
        let device = records
            .iter()
            .find(|r| r.detail.kind == "device")
            .expect("source endpoint");
        assert_eq!(device.detail.name, "10.20.1.14");
        assert_eq!(device.detail.state.as_deref(), Some("source address"));
        assert!(device.detail.hostname.is_none());
        assert!(
            device
                .detail
                .basis
                .contains("does not prove a unique device")
        );
        assert!(!records.iter().any(|r| r.detail.kind == "identity"));
    }

    #[test]
    fn model_details_use_the_catalog_and_the_models_own_sanction_decision() {
        use tally_observation_buffer::estate::{EstateDetail, EstateRecord};
        let model = CatalogModel {
            model_id: uuid::Uuid::new_v4(),
            key: "gpt-5".into(),
            name: "GPT-5".into(),
            aliases: vec![],
            family: "GPT".into(),
            country_code: Some("US".into()),
            modalities: vec!["text".into(), "image".into()],
            capabilities: vec!["tool_use".into()],
            sanctioned: Some(false),
            provider_names: vec!["OpenAI".into()],
            owner_name: Some("OpenAI".into()),
        };
        let mut record = EstateRecord {
            id: uuid::Uuid::now_v7(),
            record_type: "node".into(),
            first_seen: 1,
            last_seen: 2,
            detail: EstateDetail {
                kind: "model".into(),
                name: "GPT-5".into(),
                ..Default::default()
            },
        };
        assert_eq!(
            enrich_model(&mut record, std::slice::from_ref(&model)),
            Some(false)
        );
        assert_eq!(record.detail.model.as_deref(), Some("gpt-5"));
        assert_eq!(record.detail.model_family.as_deref(), Some("GPT"));
        assert_eq!(record.detail.modalities.as_ref(), Some(&model.modalities));
        assert_eq!(
            record.detail.capabilities.as_ref(),
            Some(&model.capabilities)
        );
        record.detail.name = "GPT-5".into();
        record.detail.model = Some("unknown-source-model".into());
        assert_eq!(enrich_model(&mut record, &[model]), None);
    }

    #[test]
    fn bedrock_models_match_catalog_aliases_and_preserve_source_ids() {
        use tally_observation_buffer::estate::{EstateDetail, EstateRecord};
        for (reference, key, alias) in [
            (
                "anthropic.claude-haiku-4-5-20251001-v1:0",
                "claude-haiku-4.5",
                "claude-haiku-4-5",
            ),
            (
                "anthropic.claude-sonnet-4-6",
                "claude-sonnet-4.6",
                "claude-sonnet-4-6",
            ),
        ] {
            let model = CatalogModel {
                model_id: uuid::Uuid::new_v4(),
                key: key.into(),
                name: key.into(),
                aliases: vec![alias.into()],
                family: "Claude".into(),
                country_code: None,
                modalities: vec!["text".into()],
                capabilities: vec!["tool_use".into()],
                owner_name: Some("Anthropic".into()),
                provider_names: vec!["Amazon Bedrock".into()],
                sanctioned: None,
            };
            let mut record = EstateRecord {
                id: uuid::Uuid::now_v7(),
                record_type: "node".into(),
                first_seen: 1,
                last_seen: 2,
                detail: EstateDetail {
                    kind: "model".into(),
                    name: reference.into(),
                    model: Some(reference.into()),
                    ..Default::default()
                },
            };
            enrich_model(&mut record, std::slice::from_ref(&model));
            assert_eq!(record.detail.model.as_deref(), Some(reference));
            assert_eq!(record.detail.model_catalog_key.as_deref(), Some(key));
            assert_eq!(record.detail.model_family.as_deref(), Some("Claude"));
            // A conflicting catalog alias must never choose an arbitrary model or sanction.
            assert_eq!(enrich_model(&mut record, &[model.clone(), model]), None);
        }
    }

    #[test]
    fn model_reference_normalization_is_restricted_to_bedrock_claude_ids() {
        assert!(
            model_reference_keys("us.anthropic.claude-haiku-4-5-20251001-v1:0")
                .contains(&"claude-haiku-4-5")
        );
        for reference in [
            "custom.claude-haiku-4-5-20251001-v1:0",
            "claude-haiku-4-5-20251001-v1:0",
            "unknown-source-model",
        ] {
            assert_eq!(model_reference_keys(reference), vec![reference]);
        }
        assert!(
            !model_reference_keys("anthropic.claude-haiku-4-5-20251301-v1:0")
                .contains(&"claude-haiku-4-5")
        );
        assert!(
            !model_reference_keys("anthropic.claude-haiku-4-5-20251001-vlatest")
                .contains(&"claude-haiku-4-5")
        );
    }
}
