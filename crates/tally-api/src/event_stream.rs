use super::{ApiError, AppState, ProblemDetails};
use axum::{Json, extract::Query, http::StatusCode};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tally_core::{Observation, ObservationKind};
use tally_observation_buffer::event_stream::{EventAuthorizationFilter, EventStreamFilter};
use tally_store_postgres::{EventFindingContext, GovernanceFindingStatus};
use utoipa::{IntoParams, ToSchema};

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(super) struct StreamQuery {
    /// Current provider/model authorization: `all`, `unsanctioned`, `authorization_queue`, or `sanctioned`.
    status: Option<String>,
    /// One-based page number. Out-of-range pages clamp to the last page.
    page: Option<u64>,
    /// Rows per page, 1 through 500; defaults to 100.
    page_size: Option<u16>,
    /// Inclusive observation time lower bound, Unix milliseconds.
    from: Option<i64>,
    /// Inclusive observation time upper bound, Unix milliseconds.
    until: Option<i64>,
    /// Reuse the returned receipt-time cutoff while paging. Refresh to obtain a new cutoff.
    snapshot: Option<i64>,
    /// Case-insensitive literal search across retained event metadata and event/source IDs.
    q: Option<String>,
    /// Exact observation kind (`snake_case`).
    kind: Option<String>,
    connector_id: Option<uuid::Uuid>,
    /// Case-insensitive literal match against source action, result, or response code.
    outcome: Option<String>,
    /// newest (default) or oldest, with observation ID as a deterministic tie breaker.
    sort: Option<String>,
}

impl StreamQuery {
    fn authorization_status(&self) -> Result<Option<GovernanceFindingStatus>, ApiError> {
        match self.status.as_deref().unwrap_or("all") {
            "all" => Ok(None),
            "unsanctioned" => Ok(Some(GovernanceFindingStatus::Unsanctioned)),
            "authorization_queue" => Ok(Some(GovernanceFindingStatus::AuthorizationQueue)),
            "sanctioned" => Ok(Some(GovernanceFindingStatus::Sanctioned)),
            _ => Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_event_stream_query",
            )),
        }
    }
    fn filter(&self, installation_id: uuid::Uuid, now: i64) -> Result<EventStreamFilter, ApiError> {
        self.authorization_status()?;
        let invalid = || ApiError::new(StatusCode::BAD_REQUEST, "invalid_event_stream_query");
        let snapshot = self.snapshot.unwrap_or(now).min(now);
        let from = self.from.unwrap_or(0);
        let until = self.until.unwrap_or(snapshot);
        if from < 0
            || until < from
            || snapshot < 0
            || self.page == Some(0)
            || self
                .page_size
                .is_some_and(|size| !(1..=500).contains(&size))
            || self
                .sort
                .as_deref()
                .is_some_and(|sort| !["newest", "oldest"].contains(&sort))
        {
            return Err(invalid());
        }
        let text = |value: &Option<String>| -> Result<String, ApiError> {
            let value = value.as_deref().unwrap_or("").trim();
            if value.len() > 256 || value.chars().any(char::is_control) {
                return Err(invalid());
            }
            Ok(value.to_owned())
        };
        let kind = text(&self.kind)?;
        if !kind.is_empty()
            && serde_json::from_value::<ObservationKind>(serde_json::json!(kind)).is_err()
        {
            return Err(invalid());
        }
        Ok(EventStreamFilter {
            installation_id,
            from,
            until,
            snapshot,
            query: text(&self.q)?,
            kind,
            connector_id: self.connector_id,
            outcome: text(&self.outcome)?,
            oldest_first: self.sort.as_deref() == Some("oldest"),
            authorization: None,
        })
    }
}

#[derive(Serialize, ToSchema)]
pub(super) struct StreamSource {
    connector_id: uuid::Uuid,
    label: String,
}

#[derive(Serialize, ToSchema)]
pub(super) struct StreamResponse {
    items: Vec<Observation>,
    total: u64,
    page: u64,
    page_size: u16,
    total_pages: u64,
    snapshot: i64,
    sources: Vec<StreamSource>,
    /// Current registry context linked to the exact events on this page.
    findings: Vec<EventFindingContext>,
}

#[utoipa::path(get, path = "/api/v1/tally/event-stream", params(StreamQuery), responses(
    (status = 200, body = StreamResponse), (status = 400, body = ProblemDetails)
))]
pub(super) async fn event_stream(
    axum::extract::State(state): axum::extract::State<AppState>,
    Query(query): Query<StreamQuery>,
) -> Result<Json<StreamResponse>, ApiError> {
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    let mut filter = query.filter(identity.installation_id, Utc::now().timestamp_millis())?;
    if let Some(status) = query.authorization_status()? {
        filter.authorization = Some(EventAuthorizationFilter {
            observation_ids: state
                .postgres
                .event_authorization_ids(identity.installation_id, status)
                .await
                .map_err(ApiError::dependency)?
                .into_iter()
                .collect(),
            exclude: status == GovernanceFindingStatus::AuthorizationQueue,
        });
    }
    let (page, connectors) = tokio::join!(
        state.observations.event_stream(
            &filter,
            query.page.unwrap_or(1),
            query.page_size.unwrap_or(100)
        ),
        state.postgres.list_connector_labels(),
    );
    let page = page.map_err(ApiError::dependency)?;
    let findings = state
        .postgres
        .event_finding_contexts(
            identity.installation_id,
            &page
                .items
                .iter()
                .map(|item| item.observation_id)
                .collect::<Vec<_>>(),
        )
        .await
        .map_err(ApiError::dependency)?;
    let mut sources = connectors
        .map_err(ApiError::dependency)?
        .into_iter()
        .map(|connector| StreamSource {
            connector_id: connector.connector_instance_id,
            label: if connector.friendly_name.trim().is_empty() {
                connector.display_name
            } else {
                connector.friendly_name
            },
        })
        .collect::<Vec<_>>();
    // Deleted connectors remain selectable on pages containing their immutable events.
    for item in &page.items {
        if !sources
            .iter()
            .any(|source| source.connector_id == item.connector.instance_id)
        {
            sources.push(StreamSource {
                connector_id: item.connector.instance_id,
                label: item.connector.connector_type.clone(),
            });
        }
    }
    sources.sort_by(|a, b| {
        a.label
            .cmp(&b.label)
            .then(a.connector_id.cmp(&b.connector_id))
    });
    Ok(Json(StreamResponse {
        items: page.items,
        total: page.total,
        page: page.page,
        page_size: page.page_size,
        total_pages: page.total_pages,
        snapshot: filter.snapshot,
        sources,
        findings,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_bounds_and_literal_filters() {
        let id = uuid::Uuid::nil();
        for size in [100, 250, 500] {
            assert!(
                StreamQuery {
                    page_size: Some(size),
                    ..Default::default()
                }
                .filter(id, 123)
                .is_ok()
            );
        }
        let query = StreamQuery {
            q: Some("  O'Reilly \\ %_  ".into()),
            ..Default::default()
        };
        let filter = query.filter(id, 123).unwrap();
        assert_eq!(filter.query, "O'Reilly \\ %_");
        assert_eq!((filter.from, filter.until, filter.snapshot), (0, 123, 123));
        for query in [
            StreamQuery {
                status: Some("allowed".into()),
                ..Default::default()
            },
            StreamQuery {
                page: Some(0),
                ..Default::default()
            },
            StreamQuery {
                page_size: Some(501),
                ..Default::default()
            },
            StreamQuery {
                from: Some(200),
                until: Some(100),
                ..Default::default()
            },
            StreamQuery {
                kind: Some("invalid".into()),
                ..Default::default()
            },
            StreamQuery {
                sort: Some("DESC; DROP".into()),
                ..Default::default()
            },
            StreamQuery {
                q: Some("\nsearch".into()),
                outcome: Some("bad\tvalue".into()),
                ..Default::default()
            },
        ] {
            assert!(query.filter(id, 123).is_err());
        }
        assert!(
            StreamQuery::default()
                .authorization_status()
                .unwrap()
                .is_none()
        );
        for status in ["all", "unsanctioned", "authorization_queue", "sanctioned"] {
            assert!(
                StreamQuery {
                    status: Some(status.into()),
                    ..Default::default()
                }
                .filter(id, 123)
                .is_ok()
            );
        }
    }
}
