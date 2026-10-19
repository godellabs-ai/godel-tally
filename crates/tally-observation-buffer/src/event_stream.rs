//! Filter and page individual retained observations without grouping distinct event IDs.
use crate::{ObservationBuffer, ObservationBufferError};
use std::collections::BTreeSet;
use tally_core::Observation;
use uuid::Uuid;

// Keep the searchable fields identical in the in-memory and ClickHouse adapters.
pub(crate) const SEARCH_PATHS: &[&[&str]] = &[
    &["kind"],
    &["connector", "connector_type"],
    &["actor", "hostname"],
    &["actor", "source_ip"],
    &["actor", "identity", "email"],
    &["actor", "identity", "display_label"],
    &["actor", "identity", "source_subject"],
    &["actor", "identity", "subject_key"],
    &["actor", "request_client", "name"],
    &["actor", "request_client", "agent_id"],
    &["destination", "host"],
    &["destination", "ip"],
    &["service", "tls_server_name"],
    &["service", "declared_model_id"],
    &["service", "vendor_application_id"],
    &["outcome", "action"],
    &["outcome", "result"],
    &["outcome", "response_code"],
];

#[derive(Debug, Clone)]
pub struct EventStreamFilter {
    pub installation_id: Uuid,
    pub from: i64,
    pub until: i64,
    pub snapshot: i64,
    pub query: String,
    pub kind: String,
    pub connector_id: Option<Uuid>,
    pub outcome: String,
    pub oldest_first: bool,
    pub authorization: Option<EventAuthorizationFilter>,
}

#[derive(Debug, Clone)]
pub struct EventAuthorizationFilter {
    pub observation_ids: BTreeSet<Uuid>,
    /// Queue filtering excludes decided IDs, retaining unlinked observations for review.
    pub exclude: bool,
}

#[derive(Debug)]
pub struct EventStreamPage {
    pub items: Vec<Observation>,
    pub total: u64,
    pub page: u64,
    pub page_size: u16,
    pub total_pages: u64,
}

pub(crate) fn page_bounds(total: u64, page: u64, size: u16) -> (u64, u16, u64) {
    let size = size.clamp(1, 500);
    let pages = total.div_ceil(u64::from(size)).max(1);
    (page.clamp(1, pages), size, pages)
}

impl ObservationBuffer {
    /// Returns a server-filtered page, including an exact count of retained matches.
    ///
    /// # Errors
    /// Returns an error if the persistent observation store is unavailable.
    pub async fn event_stream(
        &self,
        filter: &EventStreamFilter,
        page: u64,
        page_size: u16,
    ) -> Result<EventStreamPage, ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            return store.event_stream(filter, page, page_size).await;
        }
        let mut items = self
            .observations
            .read()
            .await
            .values()
            .filter(|item| matches(item, filter))
            .cloned()
            .collect::<Vec<_>>();
        items.sort_by_key(|item| (item.observed_at.timestamp_millis(), item.observation_id));
        if !filter.oldest_first {
            items.reverse();
        }
        let total = items.len() as u64;
        let (page, page_size, total_pages) = page_bounds(total, page, page_size);
        let offset = usize::try_from((page - 1) * u64::from(page_size)).unwrap_or(usize::MAX);
        let items = items
            .into_iter()
            .skip(offset)
            .take(usize::from(page_size))
            .collect();
        Ok(EventStreamPage {
            items,
            total,
            page,
            page_size,
            total_pages,
        })
    }
}

fn matches(item: &Observation, filter: &EventStreamFilter) -> bool {
    if item.installation_id != filter.installation_id
        || item.observed_at.timestamp_millis() < filter.from
        || item.observed_at.timestamp_millis() > filter.until
        || item.received_at.timestamp_millis() > filter.snapshot
        || filter
            .connector_id
            .is_some_and(|id| item.connector.instance_id != id)
        || filter.authorization.as_ref().is_some_and(|authorization| {
            authorization.observation_ids.contains(&item.observation_id) == authorization.exclude
        })
    {
        return false;
    }
    let value = serde_json::to_value(item).expect("serializable observation");
    let field = |path: &[&str]| {
        path.iter()
            .fold(&value, |value, key| &value[*key])
            .as_str()
            .unwrap_or("")
            .to_owned()
    };
    if !filter.kind.is_empty() && field(&["kind"]) != filter.kind {
        return false;
    }
    if !filter.outcome.is_empty()
        && !["action", "result", "response_code"].iter().any(|key| {
            field(&["outcome", key])
                .to_lowercase()
                .contains(&filter.outcome.to_lowercase())
        })
    {
        return false;
    }
    filter.query.is_empty()
        || SEARCH_PATHS
            .iter()
            .map(|path| field(path))
            .chain(
                item.actor
                    .additional_source_ips
                    .iter()
                    .map(|ip| ip.as_str().to_owned()),
            )
            .chain([
                item.observation_id.to_string(),
                item.connector.instance_id.to_string(),
            ])
            .any(|value| value.to_lowercase().contains(&filter.query.to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use tally_core::{ConnectorRef, DigestAlgorithm, EvidenceReceipt, ObservationKind};

    #[allow(clippy::too_many_lines)] // Run the same pagination/filter/replay scenario against both stores.
    async fn verify_stream(store: &ObservationBuffer, installation: Uuid) {
        let time = Utc::now() - Duration::hours(1);
        let mut rows = (1..=65)
            .map(|id| {
                let mut item = Observation::new(
                    installation,
                    time,
                    ConnectorRef {
                        instance_id: Uuid::from_u128(100),
                        connector_type: "test_source".into(),
                        implementation_version: "test".into(),
                        source_lineage_id: None,
                    },
                    ObservationKind::HttpMetadata,
                    EvidenceReceipt::RecordDigest {
                        algorithm: DigestAlgorithm::Sha256,
                        digest: "0".repeat(64),
                    },
                );
                item.observation_id = Uuid::from_u128(id);
                item.received_at = time;
                item.actor.hostname =
                    Some(if id % 2 == 0 { "host-even" } else { "host-odd" }.into());
                item.service.declared_model_id = Some("same-model".into());
                item.outcome.result = Some("allowed".into());
                item
            })
            .collect::<Vec<_>>();
        // The same destination/model/time must not merge distinct observation IDs.
        rows[0].actor.additional_source_ips =
            vec![tally_core::IpAddress::parse("10.9.8.7").unwrap()];
        rows[0].actor.hostname = Some("O'Reilly \\ %_".into());
        store
            .append_observations(&rows, &"0".repeat(64))
            .await
            .unwrap();
        store.append_observation(&rows[0]).await.unwrap();
        let filter = EventStreamFilter {
            installation_id: installation,
            from: 0,
            until: time.timestamp_millis(),
            snapshot: time.timestamp_millis(),
            query: String::new(),
            kind: String::new(),
            connector_id: None,
            outcome: String::new(),
            oldest_first: false,
            authorization: None,
        };
        let first = store.event_stream(&filter, 1, 25).await.unwrap();
        assert_eq!(
            (first.total, first.total_pages, first.items.len()),
            (65, 3, 25)
        );
        assert_eq!(first.items[0].observation_id, Uuid::from_u128(65));
        verify_authorization(store, &filter).await;
        for size in [100, 250, 500] {
            let page = store.event_stream(&filter, 1, size).await.unwrap();
            assert_eq!(
                (page.page_size, page.total_pages, page.items.len()),
                (size, 1, 65)
            );
        }
        let third = store.event_stream(&filter, 3, 25).await.unwrap();
        assert_eq!((third.page, third.items.len()), (3, 15));
        assert_eq!(
            third.items.last().unwrap().observation_id,
            rows[0].observation_id
        );
        assert_eq!(
            store
                .event_stream(&filter, u64::MAX, 25)
                .await
                .unwrap()
                .page,
            3
        );
        let even = store
            .event_stream(
                &EventStreamFilter {
                    query: "HOST-EVEN".into(),
                    ..filter.clone()
                },
                2,
                10,
            )
            .await
            .unwrap();
        assert_eq!(
            (even.total, even.total_pages, even.items.len()),
            (32, 4, 10)
        );
        assert!(
            even.items
                .iter()
                .all(|row| row.actor.hostname.as_deref() == Some("host-even"))
        );
        let escaped = store
            .event_stream(
                &EventStreamFilter {
                    query: "O'Reilly \\ %_".into(),
                    ..filter.clone()
                },
                1,
                25,
            )
            .await
            .unwrap();
        assert_eq!(escaped.total, 1);
        assert_eq!(
            store
                .event_stream(
                    &EventStreamFilter {
                        query: "10.9.8.7".into(),
                        ..filter.clone()
                    },
                    1,
                    25
                )
                .await
                .unwrap()
                .total,
            1
        );
        for query in ["' OR 1=1 --", "not-present"] {
            let empty = store
                .event_stream(
                    &EventStreamFilter {
                        query: query.into(),
                        ..filter.clone()
                    },
                    999,
                    25,
                )
                .await
                .unwrap();
            assert_eq!((empty.total, empty.page, empty.total_pages), (0, 1, 1));
        }
        let combined = store
            .event_stream(
                &EventStreamFilter {
                    query: "same-model".into(),
                    kind: "http_metadata".into(),
                    connector_id: Some(Uuid::from_u128(100)),
                    outcome: "ALLOW".into(),
                    oldest_first: true,
                    ..filter.clone()
                },
                1,
                10,
            )
            .await
            .unwrap();
        assert_eq!(combined.total, 65);
        assert_eq!(combined.items[0].observation_id, rows[0].observation_id);
        for changed in [
            EventStreamFilter {
                kind: "dns_query".into(),
                ..filter.clone()
            },
            EventStreamFilter {
                from: time.timestamp_millis() + 1,
                until: i64::MAX,
                ..filter.clone()
            },
            EventStreamFilter {
                connector_id: Some(Uuid::nil()),
                ..filter.clone()
            },
            EventStreamFilter {
                outcome: "denied".into(),
                ..filter.clone()
            },
        ] {
            assert_eq!(store.event_stream(&changed, 1, 25).await.unwrap().total, 0);
        }
        let mut late = rows[0].clone();
        late.observation_id = Uuid::from_u128(66);
        late.received_at = time + Duration::seconds(1);
        store.append_observation(&late).await.unwrap();
        assert_eq!(store.event_stream(&filter, 1, 25).await.unwrap().total, 65);
        assert_eq!(
            store
                .event_stream(
                    &EventStreamFilter {
                        snapshot: late.received_at.timestamp_millis(),
                        ..filter
                    },
                    1,
                    25
                )
                .await
                .unwrap()
                .total,
            66
        );
    }

    #[tokio::test]
    async fn event_stream_filters_counts_and_pages_distinct_observations() {
        let store = ObservationBuffer::new();
        let installation = Uuid::now_v7();
        verify_stream(&store, installation).await;
        let other = EventStreamFilter {
            installation_id: Uuid::now_v7(),
            from: 0,
            until: i64::MAX,
            snapshot: i64::MAX,
            query: String::new(),
            kind: String::new(),
            connector_id: None,
            outcome: String::new(),
            oldest_first: false,
            authorization: None,
        };
        assert_eq!(store.event_stream(&other, 1, 25).await.unwrap().total, 0);
    }

    async fn verify_authorization(store: &ObservationBuffer, filter: &EventStreamFilter) {
        let ids = (1..=65)
            .filter(|id| id % 3 == 0)
            .map(Uuid::from_u128)
            .collect::<BTreeSet<_>>();
        let selected = EventStreamFilter {
            authorization: Some(EventAuthorizationFilter {
                observation_ids: ids.clone(),
                exclude: false,
            }),
            ..filter.clone()
        };
        let third = store.event_stream(&selected, 3, 10).await.unwrap();
        assert_eq!(
            (third.total, third.total_pages, third.items.len()),
            (21, 3, 1)
        );
        assert_eq!(third.items[0].observation_id, Uuid::from_u128(3));
        let complement = EventStreamFilter {
            authorization: Some(EventAuthorizationFilter {
                observation_ids: ids.clone(),
                exclude: true,
            }),
            ..filter.clone()
        };
        let page = store.event_stream(&complement, 1, 100).await.unwrap();
        assert_eq!(page.total, 44);
        assert!(
            page.items
                .iter()
                .all(|item| !ids.contains(&item.observation_id))
        );
        for exclude in [false, true] {
            let empty = EventStreamFilter {
                authorization: Some(EventAuthorizationFilter {
                    observation_ids: BTreeSet::new(),
                    exclude,
                }),
                ..filter.clone()
            };
            assert_eq!(
                store.event_stream(&empty, 1, 25).await.unwrap().total,
                if exclude { 65 } else { 0 }
            );
        }
        // IDs are uploaded as data, not a SQL literal or a URL-sized IN expression.
        let large = EventStreamFilter {
            authorization: Some(EventAuthorizationFilter {
                observation_ids: (1..=15_000).map(Uuid::from_u128).collect(),
                exclude: false,
            }),
            ..filter.clone()
        };
        assert_eq!(store.event_stream(&large, 1, 25).await.unwrap().total, 65);
    }

    #[tokio::test]
    #[ignore = "requires TALLY_TEST_CLICKHOUSE_URL with permission to create a temporary database"]
    async fn event_stream_live_clickhouse() {
        let url = std::env::var("TALLY_TEST_CLICKHOUSE_URL").unwrap();
        let installation = Uuid::now_v7();
        let database = format!("tally_event_stream_test_{}", installation.simple());
        let admin = crate::clickhouse::ClickHouse::new(&url, "default", installation, 90).unwrap();
        admin
            .execute(&format!("CREATE DATABASE {database}"))
            .await
            .unwrap();
        let store = ObservationBuffer::persistent(&url, &database, installation, 90).unwrap();
        store.clickhouse.as_ref().unwrap().migrate().await.unwrap();
        verify_stream(&store, installation).await;
        let other =
            crate::clickhouse::ClickHouse::new(&url, &database, Uuid::now_v7(), 90).unwrap();
        assert_eq!(other.count(None).await.unwrap(), 0);
        admin
            .execute(&format!("DROP DATABASE {database}"))
            .await
            .unwrap();
    }
}
