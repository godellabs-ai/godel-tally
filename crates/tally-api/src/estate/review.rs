use super::{ApiError, AppState, Json, StatusCode};
use axum::extract::State;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReviewAction {
    Sanction,
    Unsanction,
    ClearSanction,
    Flag,
    ClearFlag,
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReviewRequest {
    entity_id: Uuid,
    action: ReviewAction,
}

#[utoipa::path(post, path="/api/v1/tally/registry/estate-reviews", request_body=ReviewRequest, responses((status=200,body=serde_json::Value)))]
pub(crate) async fn update(
    State(state): State<AppState>,
    Json(request): Json<ReviewRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    let record = state
        .observations
        .estate_entity(identity.installation_id, request.entity_id)
        .await
        .map_err(ApiError::dependency)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "estate_entity_not_found"))?;
    if matches!(
        request.action,
        ReviewAction::Sanction | ReviewAction::Unsanction | ReviewAction::ClearSanction
    ) && !matches!(
        record.detail.kind.as_str(),
        "agent" | "workflow" | "mcp_server" | "mcp_config" | "endpoint" | "workload"
    ) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "use_registry_sanctions_for_models_and_providers",
        ));
    }
    let mut transaction = state
        .postgres
        .pool()
        .begin()
        .await
        .map_err(ApiError::dependency)?;
    sqlx::query("INSERT INTO tally_estate_reviews (installation_id,entity_id) VALUES ($1,$2) ON CONFLICT DO NOTHING").bind(identity.installation_id).bind(request.entity_id).execute(&mut *transaction).await.map_err(ApiError::dependency)?;
    let action = match request.action {
        ReviewAction::Flag | ReviewAction::ClearFlag => {
            let flagged = matches!(request.action, ReviewAction::Flag);
            sqlx::query("UPDATE tally_estate_reviews SET flagged=$3,updated_at=now() WHERE installation_id=$1 AND entity_id=$2").bind(identity.installation_id).bind(request.entity_id).bind(flagged).execute(&mut *transaction).await.map_err(ApiError::dependency)?;
            if flagged {
                "estate.flag"
            } else {
                "estate.clear_flag"
            }
        }
        _ => {
            let sanctioned = match request.action {
                ReviewAction::Sanction => Some(true),
                ReviewAction::Unsanction => Some(false),
                _ => None,
            };
            sqlx::query("UPDATE tally_estate_reviews SET sanctioned=$3,updated_at=now() WHERE installation_id=$1 AND entity_id=$2").bind(identity.installation_id).bind(request.entity_id).bind(sanctioned).execute(&mut *transaction).await.map_err(ApiError::dependency)?;
            match sanctioned {
                Some(true) => "estate.sanction",
                Some(false) => "estate.unsanction",
                None => "estate.clear_sanction",
            }
        }
    };
    sqlx::query("INSERT INTO audit_log (audit_id,actor,action,entity_type,entity_id,detail) VALUES ($1,'local_operator',$2,'estate_entity',$3,$4)")
        .bind(Uuid::now_v7()).bind(action).bind(request.entity_id.to_string()).bind(serde_json::json!({"installation_id":identity.installation_id,"kind":record.detail.kind,"content_retained":false})).execute(&mut *transaction).await.map_err(ApiError::dependency)?;
    transaction.commit().await.map_err(ApiError::dependency)?;
    Ok(Json(
        serde_json::json!({"entity_id":request.entity_id,"saved":true}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SecretCipher, state_from_store};
    use std::sync::Arc;
    use tally_core::ObservationKind;
    use tally_store_postgres::PostgresStore;

    #[test]
    fn review_request_rejects_untrusted_fields_and_unknown_actions() {
        let id = Uuid::now_v7();
        assert!(
            serde_json::from_value::<ReviewRequest>(
                serde_json::json!({"entity_id":id,"action":"sanction","installation_id":id})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<ReviewRequest>(
                serde_json::json!({"entity_id":id,"action":"block"})
            )
            .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires an empty disposable TALLY_DISPOSABLE_POSTGRES_URL"]
    #[allow(clippy::too_many_lines)] // One durable review lifecycle in an isolated database.
    async fn live_reviews_persist_are_scoped_and_audited() {
        let url = std::env::var("TALLY_DISPOSABLE_POSTGRES_URL").unwrap();
        let store = Arc::new(PostgresStore::connect(&url).await.unwrap());
        store.migrate().await.unwrap();
        store.migrate().await.unwrap();
        assert_eq!(store.migration_head().await.unwrap(), 18);
        let state = state_from_store(store.clone(), SecretCipher::from_bytes([7; 32]))
            .await
            .unwrap();
        let installation = store
            .get_or_create_installation_identity()
            .await
            .unwrap()
            .installation_id;
        let mut record = crate::tests::usage_observation(ObservationKind::HttpMetadata);
        record.installation_id = installation;
        record.agent.key = Some("review-fixture".into());
        record.agent.name = Some("Review fixture".into());
        record.service.declared_model_id = Some("review-model".into());
        let mut foreign = record.clone();
        foreign.installation_id = Uuid::now_v7();
        foreign.observation_id = Uuid::now_v7();
        state
            .observations
            .append_observations(&[record.clone(), foreign.clone()], &"ab".repeat(32))
            .await
            .unwrap();
        let baseline = store.data_inventory().await.unwrap().registry_sanctions;
        let projected = tally_observation_buffer::estate::project(&record);
        let Json(activity) = super::super::activity_records(
            State(state.clone()),
            Json(super::super::ActivityRecordsQuery {
                days: 7,
                record_ids: projected.iter().map(|r| r.id).collect(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(activity["summary"]["records"], 1);
        assert_eq!(
            super::super::activity_records(
                State(state.clone()),
                Json(super::super::ActivityRecordsQuery {
                    days: 7,
                    record_ids: vec![]
                })
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            super::super::activity_records(
                State(state.clone()),
                Json(super::super::ActivityRecordsQuery {
                    days: 365,
                    record_ids: vec![projected[0].id]
                })
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::BAD_REQUEST
        );

        let agent = projected.iter().find(|r| r.detail.kind == "agent").unwrap();
        for action in [
            ReviewAction::Flag,
            ReviewAction::Sanction,
            ReviewAction::Unsanction,
        ] {
            let _ = update(
                State(state.clone()),
                Json(ReviewRequest {
                    entity_id: agent.id,
                    action,
                }),
            )
            .await
            .unwrap();
        }
        let saved = sqlx::query_as::<_,(Option<bool>,bool)>("SELECT sanctioned,flagged FROM tally_estate_reviews WHERE installation_id=$1 AND entity_id=$2").bind(installation).bind(agent.id).fetch_one(store.pool()).await.unwrap();
        assert_eq!(saved, (Some(false), true));
        assert_eq!(
            store.data_inventory().await.unwrap().registry_sanctions,
            baseline + 1
        );
        let restarted = state_from_store(store.clone(), SecretCipher::from_bytes([7; 32]))
            .await
            .unwrap();
        restarted
            .observations
            .append_observations(&[record], &"ab".repeat(32))
            .await
            .unwrap();
        let Json(inventory) = super::super::inventory(
            State(restarted),
            axum::extract::Query(super::super::EstateQuery::default()),
        )
        .await
        .unwrap();
        let entity = inventory["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == agent.id.to_string())
            .unwrap();
        assert_eq!(entity["sanctioned"], false);
        assert_eq!(entity["flagged"], true);
        let foreign_id = tally_observation_buffer::estate::project(&foreign)
            .into_iter()
            .find(|r| r.detail.kind == "agent")
            .unwrap()
            .id;
        assert_eq!(
            update(
                State(state.clone()),
                Json(ReviewRequest {
                    entity_id: foreign_id,
                    action: ReviewAction::Flag
                })
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::NOT_FOUND
        );
        let model = projected.iter().find(|r| r.detail.kind == "model").unwrap();
        assert_eq!(
            update(
                State(state.clone()),
                Json(ReviewRequest {
                    entity_id: model.id,
                    action: ReviewAction::Sanction
                })
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        for action in [ReviewAction::ClearFlag, ReviewAction::ClearSanction] {
            let _ = update(
                State(state.clone()),
                Json(ReviewRequest {
                    entity_id: agent.id,
                    action,
                }),
            )
            .await
            .unwrap();
        }
        let saved = sqlx::query_as::<_,(Option<bool>,bool)>("SELECT sanctioned,flagged FROM tally_estate_reviews WHERE installation_id=$1 AND entity_id=$2").bind(installation).bind(agent.id).fetch_one(store.pool()).await.unwrap();
        assert_eq!(saved, (None, false));
        assert_eq!(
            store.data_inventory().await.unwrap().registry_sanctions,
            baseline
        );
        let audits = sqlx::query_as::<_, (String, serde_json::Value)>(
            "SELECT action,detail FROM audit_log WHERE entity_id=$1 ORDER BY at,audit_id",
        )
        .bind(agent.id.to_string())
        .fetch_all(store.pool())
        .await
        .unwrap();
        assert_eq!(audits.len(), 5);
        assert!(audits.iter().all(|(_, detail)| detail["installation_id"]
            == installation.to_string()
            && detail["content_retained"] == false
            && detail.get("name").is_none()));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM tally_estate_reviews")
                .fetch_one(store.pool())
                .await
                .unwrap(),
            1
        );
        store
            .delete_data(
                &["registry_sanctions".into()],
                Some(chrono::Utc::now() - chrono::Duration::days(1)),
            )
            .await
            .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM tally_estate_reviews")
                .fetch_one(store.pool())
                .await
                .unwrap(),
            1,
            "date cutoff preserves recent reviews"
        );
        store
            .delete_data(&["registry_sanctions".into()], None)
            .await
            .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM tally_estate_reviews")
                .fetch_one(store.pool())
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit_log WHERE entity_id=$1")
                .bind(agent.id.to_string())
                .fetch_one(store.pool())
                .await
                .unwrap(),
            5,
            "clearing decisions preserves audit history"
        );
    }
}
