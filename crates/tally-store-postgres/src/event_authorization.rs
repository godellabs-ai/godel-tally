use super::{GovernanceFindingStatus, PostgresStore, PostgresStoreError};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct EventRegistryEntity {
    pub id: Uuid,
    pub name: String,
    pub key: String,
    pub sanctioned: Option<bool>,
}

/// Registry context for one exact event link; never includes aggregate user or endpoint data.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct EventFindingContext {
    pub observation_id: Uuid,
    pub finding_id: Uuid,
    pub evidence_kind: String,
    pub status: GovernanceFindingStatus,
    pub provider: EventRegistryEntity,
    pub model: Option<EventRegistryEntity>,
    pub model_version: Option<String>,
}

impl PostgresStore {
    /// Resolve provider/model context only for the events on the requested page.
    ///
    /// # Errors
    /// Returns an error when the scoped query or context decoding fails.
    pub async fn event_finding_contexts(
        &self,
        installation_id: Uuid,
        observation_ids: &[Uuid],
    ) -> Result<Vec<EventFindingContext>, PostgresStoreError> {
        if observation_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_scalar::<_, serde_json::Value>(r"
            SELECT jsonb_build_object(
                'observation_id', fo.observation_id, 'finding_id', f.finding_id,
                'evidence_kind', f.evidence_kind,
                'status', CASE
                    WHEN p.sanctioned = FALSE OR m.sanctioned = FALSE THEN 'unsanctioned'
                    WHEN p.sanctioned IS NULL OR (f.model_id IS NOT NULL AND m.sanctioned IS NULL)
                        THEN 'authorization_queue'
                    ELSE 'sanctioned' END,
                'provider', jsonb_build_object('id', p.provider_id, 'name', p.name, 'key', p.key, 'sanctioned', p.sanctioned),
                'model', CASE WHEN m.model_id IS NULL THEN NULL ELSE
                    jsonb_build_object('id', m.model_id, 'name', m.name, 'key', m.key, 'sanctioned', m.sanctioned) END,
                'model_version', f.model_version
            )
            FROM finding_observations fo
            JOIN findings f USING (finding_id)
            JOIN ai_providers p USING (provider_id)
            LEFT JOIN ai_models m USING (model_id)
            WHERE f.installation_id = $1 AND fo.observation_id = ANY($2)
            ORDER BY fo.observation_id, f.finding_id
        ").bind(installation_id).bind(observation_ids).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| serde_json::from_value(row).map_err(Into::into))
            .collect()
    }

    /// IDs for the current authorization decision of each linked event.
    ///
    /// Unsanctioned takes precedence over undecided, then sanctioned, across all
    /// findings linked to the same observation. For the authorization queue, return
    /// its complement so the event store can also include observations without a finding.
    /// This deliberately has no findings-list limit and uses exact observation links.
    ///
    /// # Errors
    /// Returns an error when the authorization query fails.
    pub async fn event_authorization_ids(
        &self,
        installation_id: Uuid,
        status: GovernanceFindingStatus,
    ) -> Result<Vec<Uuid>, PostgresStoreError> {
        let rank: i32 = match status {
            GovernanceFindingStatus::Unsanctioned => 0,
            GovernanceFindingStatus::AuthorizationQueue => 1,
            GovernanceFindingStatus::Sanctioned => 2,
        };
        Ok(sqlx::query_scalar::<_, Uuid>(r"
            SELECT fo.observation_id
            FROM finding_observations fo
            JOIN findings f USING (finding_id)
            JOIN ai_providers p USING (provider_id)
            LEFT JOIN ai_models m USING (model_id)
            WHERE f.installation_id = $1
            GROUP BY fo.observation_id
            HAVING (min(CASE
                WHEN p.sanctioned = FALSE OR m.sanctioned = FALSE THEN 0
                WHEN p.sanctioned IS NULL OR (f.model_id IS NOT NULL AND m.sanctioned IS NULL) THEN 1
                ELSE 2 END) = $2) <> $3
            ORDER BY fo.observation_id
        ")
            .bind(installation_id).bind(rank)
            .bind(status == GovernanceFindingStatus::AuthorizationQueue)
            .fetch_all(&self.pool).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ModelFixture::{Absent, WithStatus};

    enum ModelFixture {
        Absent,
        WithStatus(Option<bool>),
    }

    #[tokio::test]
    #[ignore = "requires a disposable TALLY_EVENT_STATUS_TEST_POSTGRES_URL"]
    async fn event_authorization_tracks_live_decisions_and_exact_scoped_links() {
        let url = std::env::var("TALLY_EVENT_STATUS_TEST_POSTGRES_URL").unwrap();
        assert!(
            url::Url::parse(&url)
                .unwrap()
                .path()
                .starts_with("/tally_event_status_test_")
        );
        let store = PostgresStore::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        let installation = Uuid::now_v7();
        let other_installation = Uuid::now_v7();
        for id in [installation, other_installation] {
            sqlx::query("INSERT INTO installations (installation_id, name) VALUES ($1, 'Test')")
                .bind(id)
                .execute(&store.pool)
                .await
                .unwrap();
        }
        let approved = add_finding(&store, installation, Some(true), Absent).await;
        let denied = add_finding(&store, installation, Some(false), Absent).await;
        let pending = add_finding(&store, installation, Some(true), WithStatus(None)).await;
        let model_denied =
            add_finding(&store, installation, Some(true), WithStatus(Some(false))).await;
        let provider_pending =
            add_finding(&store, installation, None, WithStatus(Some(true))).await;
        let other_denied = add_finding(&store, other_installation, Some(false), Absent).await;
        for (event, finding) in [
            (1, approved),
            (2, denied),
            (3, pending),
            (4, model_denied),
            (5, approved),
            (5, pending),
            (6, approved),
            (6, denied),
            (7, provider_pending),
            (1, other_denied),
        ] {
            sqlx::query("INSERT INTO finding_observations (observation_id, finding_id, observed_at) VALUES ($1, $2, now())")
                .bind(Uuid::from_u128(event)).bind(finding).execute(&store.pool).await.unwrap();
        }
        for (status, ids) in [
            (GovernanceFindingStatus::Unsanctioned, vec![2, 4, 6]),
            (GovernanceFindingStatus::Sanctioned, vec![1]),
            // Queue uses the complement: undecided and unlinked IDs are included by ClickHouse.
            (
                GovernanceFindingStatus::AuthorizationQueue,
                vec![1, 2, 4, 6],
            ),
        ] {
            assert_eq!(
                store
                    .event_authorization_ids(installation, status)
                    .await
                    .unwrap(),
                ids.into_iter().map(Uuid::from_u128).collect::<Vec<_>>()
            );
        }
        verify_contexts(&store, installation, other_denied, model_denied).await;
        sqlx::query("UPDATE ai_providers SET sanctioned=TRUE WHERE provider_id=(SELECT provider_id FROM findings WHERE finding_id=$1)")
            .bind(denied).execute(&store.pool).await.unwrap();
        assert_eq!(
            store
                .event_authorization_ids(installation, GovernanceFindingStatus::Sanctioned)
                .await
                .unwrap(),
            [1, 2, 6].map(Uuid::from_u128)
        );
    }

    async fn verify_contexts(
        store: &PostgresStore,
        installation: Uuid,
        other_denied: Uuid,
        model_denied: Uuid,
    ) {
        let contexts = store
            .event_finding_contexts(
                installation,
                &[
                    Uuid::from_u128(1),
                    Uuid::from_u128(4),
                    Uuid::from_u128(6),
                    Uuid::from_u128(99),
                ],
            )
            .await
            .unwrap();
        assert_eq!(contexts.len(), 4);
        assert!(
            !contexts
                .iter()
                .any(|context| context.finding_id == other_denied)
        );
        let model_context = contexts
            .iter()
            .find(|context| context.finding_id == model_denied)
            .unwrap();
        assert_eq!(model_context.provider.sanctioned, Some(true));
        assert_eq!(
            model_context.model.as_ref().unwrap().sanctioned,
            Some(false)
        );
        assert_eq!(model_context.status, GovernanceFindingStatus::Unsanctioned);
        assert_eq!(
            contexts
                .iter()
                .filter(|context| context.observation_id == Uuid::from_u128(6))
                .count(),
            2
        );
    }

    async fn add_finding(
        store: &PostgresStore,
        installation: Uuid,
        provider_status: Option<bool>,
        model_status: ModelFixture,
    ) -> Uuid {
        let provider = Uuid::now_v7();
        sqlx::query("INSERT INTO ai_providers (provider_id, key, name, category, sanctioned) VALUES ($1, $2, 'Provider', 'direct_provider', $3)")
            .bind(provider).bind(provider.to_string()).bind(provider_status).execute(&store.pool).await.unwrap();
        let mut model = None;
        if let WithStatus(status) = model_status {
            let id = Uuid::now_v7();
            sqlx::query("INSERT INTO ai_models (model_id, key, name, family, sanctioned) VALUES ($1, $2, 'Model', 'test', $3)")
                .bind(id).bind(id.to_string()).bind(status).execute(&store.pool).await.unwrap();
            model = Some(id);
        }
        let finding = Uuid::now_v7();
        sqlx::query("INSERT INTO findings (finding_id, installation_id, provider_id, model_id, first_used_at, last_used_at) VALUES ($1, $2, $3, $4, now(), now())")
            .bind(finding).bind(installation).bind(provider).bind(model).execute(&store.pool).await.unwrap();
        finding
    }
}
