use super::{ApiError, AppState, DateTime, Deserialize, Json, Path, Query, StatusCode};

#[utoipa::path(get, path="/api/v1/tally/connectors/capabilities", responses((status=200, description="Connector evidence boundaries and observed field coverage")))]
pub(super) async fn capabilities(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    let register: serde_json::Value =
        serde_json::from_str(include_str!("../../../specs/connector-capabilities.json"))
            .map_err(ApiError::dependency)?;
    let observed:Vec<(serde_json::Value,)> = sqlx::query_as("SELECT jsonb_build_object('connector_instance_id', c.connector_instance_id, 'connector_type', c.connector_type, 'retained_activity_count', count(a.observation_id), 'process_count',count(a.observation_id) FILTER (WHERE a.context#>>'{process,executable}' IS NOT NULL), 'user_count',count(a.observation_id) FILTER (WHERE a.context#>>'{actor,identity}' IS NOT NULL), 'model_count',count(a.observation_id) FILTER (WHERE a.context->>'model' IS NOT NULL), 'client_hint_count',count(a.observation_id) FILTER (WHERE a.context#>>'{actor,request_client}' IS NOT NULL), 'last_activity_at',max(a.observed_at), 'identity_facts',(SELECT count(*) FROM identity_facts f WHERE f.installation_id=$1 AND f.connector_instance_id=c.connector_instance_id)) FROM connector_states c LEFT JOIN finding_activity a ON a.connector_instance_id=c.connector_instance_id AND a.installation_id=$1 WHERE c.installation_id=$1 GROUP BY c.connector_instance_id,c.connector_type ORDER BY c.connector_instance_id LIMIT 500")
        .bind(identity.installation_id).fetch_all(state.postgres.pool()).await.map_err(ApiError::dependency)?;
    Ok(Json(
        serde_json::json!({"register":register,"observed":observed.into_iter().map(|v|v.0).collect::<Vec<_>>(),"coverage_scope":"Retained activity and source identity facts; absent fields do not imply a source supports them."}),
    ))
}

#[derive(Default, Deserialize)]
pub(super) struct ActivityQuery {
    before: Option<String>,
    observation_id: Option<uuid::Uuid>,
    limit: Option<u16>,
}

#[utoipa::path(get, path="/api/v1/tally/findings/{finding_id}/activity", params(("finding_id"=uuid::Uuid,Path)), responses((status=200, description="Paginated source-associated finding activities")))]
pub(super) async fn activity(
    axum::extract::State(state): axum::extract::State<AppState>,
    Path(finding): Path<uuid::Uuid>,
    Query(query): Query<ActivityQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let before = query
        .before
        .as_deref()
        .map(|v| {
            let (ms, id) = v
                .split_once(':')
                .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "invalid_activity_cursor"))?;
            let time = ms
                .parse()
                .ok()
                .and_then(DateTime::from_timestamp_millis)
                .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "invalid_activity_cursor"))?;
            let id = uuid::Uuid::parse_str(id)
                .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_activity_cursor"))?;
            Ok((time, id))
        })
        .transpose()?;
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    let limit = i64::from(query.limit.unwrap_or(25).clamp(1, 200));
    let mut items = state
        .postgres
        .filtered_finding_activity(
            identity.installation_id,
            finding,
            before,
            limit + 1,
            query.observation_id,
        )
        .await
        .map_err(ApiError::dependency)?;
    let more = items.len() > usize::try_from(limit).unwrap_or(200);
    items.truncate(usize::try_from(limit).unwrap_or(200));
    let next = more
        .then(|| {
            items
                .last()
                .map(|a| format!("{}:{}", a.observed_at.timestamp_millis(), a.observation_id))
        })
        .flatten();
    let mut enriched = Vec::new();
    for activity in items {
        let context = state
            .postgres
            .activity_identity_context(identity.installation_id, &activity)
            .await
            .map_err(ApiError::dependency)?;
        let mut value = serde_json::to_value(activity).map_err(ApiError::dependency)?;
        let revisions:Vec<(serde_json::Value,)>=sqlx::query_as("SELECT jsonb_build_object('context',context,'conflicts',conflicts,'created_at',created_at) FROM finding_activity_revisions WHERE finding_id=$1 AND observation_id=$2 ORDER BY created_at DESC LIMIT 5")
            .bind(finding).bind(value["observation_id"].as_str().and_then(|v|uuid::Uuid::parse_str(v).ok()).ok_or_else(||ApiError::dependency_message("invalid_activity_identity"))?).fetch_all(state.postgres.pool()).await.map_err(ApiError::dependency)?;
        value["source_revisions"] =
            serde_json::json!(revisions.into_iter().map(|r| r.0).collect::<Vec<_>>());
        value["enrichment"] = context;
        enriched.push(value);
    }
    Ok(Json(
        serde_json::json!({"items":enriched,"next_cursor":next,"legacy_associations_available":false}),
    ))
}
