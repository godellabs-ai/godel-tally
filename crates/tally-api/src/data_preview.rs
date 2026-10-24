//! Counts use the same predicates and cascades as operational deletion.
use super::{ApiError, AppState, ProblemDetails};
use axum::{Json, http::StatusCode};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::AssertSqlSafe;
use tally_store_postgres::DataInventory;
use utoipa::ToSchema;

#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DataTarget {
    pub scopes: Vec<String>,
    pub before: Option<DateTime<Utc>>,
}
impl DataTarget {
    pub fn validate(&self) -> Result<(), ApiError> {
        const SCOPES: [&str; 9] = [
            "all",
            "ai_logs",
            "inventory",
            "findings",
            "connector_history",
            "connectors",
            "scanner_history",
            "audit_logs",
            "registry_sanctions",
        ];
        if self.scopes.is_empty()
            || self.scopes.len() > SCOPES.len()
            || self.scopes.iter().any(|s| !SCOPES.contains(&s.as_str()))
        {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "data_delete_request_invalid",
            ));
        }
        Ok(())
    }
    fn has(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == "all" || s == scope)
    }
}

#[utoipa::path(post,path="/api/v1/tally/data/preview",request_body=DataTarget,responses((status=200,body=DataInventory),(status=422,body=ProblemDetails)))]
#[allow(clippy::too_many_lines)] // Compute all scoped preview counts without mutating any store.
pub(crate) async fn preview(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(target): Json<DataTarget>,
) -> Result<Json<DataInventory>, ApiError> {
    target.validate()?;
    let mut result = DataInventory::default();
    if target.has("ai_logs") || target.has("inventory") {
        let (logs, nodes) = state
            .observations
            .deletion_counts(target.before.map(|t| t.timestamp_millis()))
            .await
            .map_err(ApiError::dependency)?;
        if target.has("ai_logs") {
            result.ai_logs = logs;
        }
        if target.has("inventory") {
            let installation = state
                .postgres
                .get_or_create_installation_identity()
                .await
                .map_err(ApiError::dependency)?
                .installation_id;
            result.inventory_entities = nodes
                + state
                    .postgres
                    .identity_inventory_count(installation, target.before)
                    .await
                    .map_err(ApiError::dependency)?;
        }
    }
    let pool = state.postgres.pool();
    // A repeatable snapshot keeps the multi-table preview internally consistent. Deletion remains
    // subject to new ingestion, as in Gate; the UI refreshes this preview before confirmation.
    let mut tx = pool.begin().await.map_err(ApiError::dependency)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(ApiError::dependency)?;
    for (table, time, output) in [
        ("findings", "last_used_at", &mut result.findings),
        ("connector_runs", "completed_at", &mut result.connector_runs),
        (
            "ingestion_batches",
            "accepted_at",
            &mut result.ingestion_receipts,
        ),
        ("scan_jobs", "created_at", &mut result.scanner_runs),
        ("audit_log", "at", &mut result.audit_events),
    ] {
        let selected = match table {
            "findings" => target.has("findings"),
            "connector_runs" | "ingestion_batches" => {
                target.has("connector_history") || target.has("connectors")
            }
            "scan_jobs" => target.has("scanner_history"),
            _ => target.has("audit_logs"),
        };
        if selected {
            let cutoff = if target.has("connectors")
                && matches!(table, "connector_runs" | "ingestion_batches")
            {
                None
            } else {
                target.before
            };
            *output = sqlx::query_scalar::<_, i64>(AssertSqlSafe(format!(
                "SELECT count(*) FROM {table} WHERE $1::timestamptz IS NULL OR {time}<$1"
            )))
            .bind(cutoff)
            .fetch_one(&mut *tx)
            .await
            .map_err(ApiError::dependency)?
            .cast_unsigned();
        }
    }
    if target.has("findings") {
        for (table, id, links, output) in [
            (
                "endpoint_hosts",
                "endpoint_host_id",
                "finding_hosts",
                &mut result.endpoint_hosts,
            ),
            (
                "endpoint_users",
                "endpoint_user_id",
                "finding_users",
                &mut result.endpoint_users,
            ),
            (
                "destination_hosts",
                "destination_host_id",
                "finding_destinations",
                &mut result.destination_hosts,
            ),
        ] {
            *output=sqlx::query_scalar::<_,i64>(AssertSqlSafe(format!("SELECT count(*) FROM {table} e WHERE NOT EXISTS (SELECT 1 FROM {links} l JOIN findings f USING(finding_id) WHERE l.{id}=e.{id} AND $1::timestamptz IS NOT NULL AND f.last_used_at >= $1)")))
                .bind(target.before).fetch_one(&mut *tx).await.map_err(ApiError::dependency)?.cast_unsigned();
        }
    }
    if target.has("connectors") {
        result.connectors = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM connector_states")
            .fetch_one(&mut *tx)
            .await
            .map_err(ApiError::dependency)?
            .cast_unsigned();
    }
    if target.has("registry_sanctions") {
        result.registry_sanctions=sqlx::query_scalar::<_,i64>("SELECT (SELECT count(*) FROM ai_providers WHERE sanctioned IS DISTINCT FROM (catalog AND tally_default_provider_sanction(key))) + (SELECT count(*) FROM ai_models WHERE sanctioned IS DISTINCT FROM (catalog AND tally_default_provider_sanction((SELECT key FROM ai_providers WHERE provider_id = ai_models.owner_provider_id)))) + (SELECT count(*) FROM tally_estate_reviews WHERE (sanctioned IS NOT NULL OR flagged) AND ($1::timestamptz IS NULL OR updated_at<$1))")
            .bind(target.before).fetch_one(&mut *tx).await.map_err(ApiError::dependency)?.cast_unsigned();
    }
    tx.commit().await.map_err(ApiError::dependency)?;
    Ok(Json(result))
}
