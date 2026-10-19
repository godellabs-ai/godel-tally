//! Observation storage: `ClickHouse` in production, an in-memory adapter for isolated tests.
//! AI admission is shared across all connectors in tally-api, before storage.

mod clickhouse;
pub mod estate;
pub mod event_stream;
pub use clickhouse::activity::{ActivityDay, ActivitySummary};

use std::{collections::BTreeMap, fmt, sync::Arc};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tally_core::Observation;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

pub const OBSERVATION_BUFFER_VERSION: &str = clickhouse::MIGRATION_HEAD;
const MAX_BUFFERED_OBSERVATIONS: usize = 10_000;

#[derive(Clone, Default)]
pub struct ObservationBuffer {
    observations: Arc<RwLock<BTreeMap<Uuid, Observation>>>,
    clickhouse: Option<clickhouse::ClickHouse>,
}

impl fmt::Debug for ObservationBuffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservationBuffer")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationBufferSnapshot {
    pub version: String,
    pub observation_count: u64,
    pub observation_sha256: String,
}

// The fallible async interface intentionally matches the ingestion store boundary while the
// implementation dispatches to persistent storage when configured.
#[allow(
    clippy::missing_errors_doc,
    clippy::unused_async,
    clippy::unused_async_trait_impl
)]
impl ObservationBuffer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn persistent(
        url: &str,
        database: &str,
        installation_id: Uuid,
        retention_days: u16,
    ) -> Result<Self, ObservationBufferError> {
        Ok(Self {
            clickhouse: Some(clickhouse::ClickHouse::new(
                url,
                database,
                installation_id,
                retention_days,
            )?),
            ..Self::default()
        })
    }

    pub async fn estate(
        &self,
        limit: u32,
        after: Option<Uuid>,
    ) -> Result<Vec<estate::EstateRecord>, ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            return store.estate(limit, after).await;
        }
        let mut records = BTreeMap::<Uuid, estate::EstateRecord>::new();
        for observation in self.observations.read().await.values() {
            for record in estate::project(observation) {
                records
                    .entry(record.id)
                    .and_modify(|existing| {
                        existing.first_seen = existing.first_seen.min(record.first_seen);
                        if record.last_seen >= existing.last_seen {
                            existing.last_seen = record.last_seen;
                            existing.detail = record.detail.clone();
                        }
                    })
                    .or_insert(record);
            }
        }
        Ok(records
            .into_values()
            .filter(|r| after.is_none_or(|id| r.id > id))
            .take(limit.clamp(1, 2001) as usize)
            .collect())
    }

    pub async fn activity(
        &self,
        installation: Uuid,
        id: Option<Uuid>,
        since: i64,
        until: i64,
    ) -> Result<ActivitySummary, ObservationBufferError> {
        self.activity_for_records(installation, id.as_slice(), since, until)
            .await
    }
    pub async fn activity_for_records(
        &self,
        installation: Uuid,
        ids: &[Uuid],
        since: i64,
        until: i64,
    ) -> Result<ActivitySummary, ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            if store.installation_id != installation {
                return Err(ObservationBufferError::Storage(
                    "installation scope mismatch".into(),
                ));
            }
            return store.activity_for_records(ids, since, until).await;
        }
        let observations = self.observations.read().await;
        let mut summary = ActivitySummary::default();
        let mut daily = BTreeMap::<i64, ActivityDay>::new();
        for o in observations.values().filter(|o| {
            o.installation_id == installation
                && (since..=until).contains(&o.observed_at.timestamp_millis())
                && (ids.is_empty() || estate::project(o).iter().any(|r| ids.contains(&r.id)))
        }) {
            let time = o.observed_at.timestamp_millis();
            let day = daily
                .entry(time.div_euclid(86_400_000) * 86_400_000)
                .or_insert_with(|| ActivityDay {
                    day: time.div_euclid(86_400_000) * 86_400_000,
                    ..Default::default()
                });
            day.records += 1;
            day.requests += u64::from(o.service.ai_request);
            day.byte_reports +=
                u64::from(o.network.bytes_sent.is_some() || o.network.bytes_received.is_some());
            day.sent_reports += u64::from(o.network.bytes_sent.is_some());
            day.received_reports += u64::from(o.network.bytes_received.is_some());
            day.bytes_sent = day
                .bytes_sent
                .saturating_add(o.network.bytes_sent.unwrap_or(0));
            day.bytes_received = day
                .bytes_received
                .saturating_add(o.network.bytes_received.unwrap_or(0));
            summary.first_seen = Some(summary.first_seen.map_or(time, |v| v.min(time)));
            summary.last_seen = Some(summary.last_seen.map_or(time, |v| v.max(time)));
        }
        summary.daily = daily.into_values().collect();
        for day in &summary.daily {
            summary.records += day.records;
            summary.requests += day.requests;
            summary.byte_reports += day.byte_reports;
            summary.sent_reports += day.sent_reports;
            summary.received_reports += day.received_reports;
            summary.bytes_sent = summary.bytes_sent.saturating_add(day.bytes_sent);
            summary.bytes_received = summary.bytes_received.saturating_add(day.bytes_received);
        }
        Ok(summary)
    }
    pub async fn estate_entity(
        &self,
        installation: Uuid,
        id: Uuid,
    ) -> Result<Option<estate::EstateRecord>, ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            if store.installation_id != installation {
                return Err(ObservationBufferError::Storage(
                    "installation scope mismatch".into(),
                ));
            }
            return store.estate_entity(id).await;
        }
        Ok(self
            .observations
            .read()
            .await
            .values()
            .filter(|o| o.installation_id == installation)
            .flat_map(estate::project)
            .filter(|r| r.id == id && r.record_type == "node")
            .max_by_key(|r| r.last_seen))
    }
    pub async fn entity_logs(
        &self,
        installation: Uuid,
        id: Uuid,
        limit: u16,
        before: Option<(i64, Uuid)>,
        since: i64,
    ) -> Result<Vec<Observation>, ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            if store.installation_id != installation {
                return Err(ObservationBufferError::Storage(
                    "installation scope mismatch".into(),
                ));
            }
            return store.entity_logs(id, limit, before, since).await;
        }
        let mut observations = self
            .observations
            .read()
            .await
            .values()
            .filter(|o| {
                o.installation_id == installation
                    && o.observed_at.timestamp_millis() >= since
                    && before.is_none_or(|cursor| {
                        (o.observed_at.timestamp_millis(), o.observation_id) < cursor
                    })
                    && estate::project(o).iter().any(|r| r.id == id)
            })
            .cloned()
            .collect::<Vec<_>>();
        observations.sort_by_key(|o| std::cmp::Reverse((o.observed_at, o.observation_id)));
        observations.truncate(usize::from(limit));
        Ok(observations)
    }
    pub async fn record_coverage(
        &self,
        observations: &[Observation],
    ) -> Result<(), ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            return store.record_coverage(observations).await;
        }
        Ok(())
    }
    pub async fn coverage_count(&self) -> Result<u64, ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            return store.coverage_count().await;
        }
        Ok(0)
    }
    pub async fn write_inventory(
        &self,
        records: &[estate::EstateRecord],
    ) -> Result<(), ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            return store.write_inventory(records).await;
        }
        Ok(())
    }
    pub async fn bootstrap_needed(&self) -> Result<bool, ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            return store.bootstrap_needed().await;
        }
        Ok(false)
    }
    pub async fn finish_bootstrap(&self) -> Result<(), ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            return store.finish_bootstrap().await;
        }
        Ok(())
    }
    pub async fn estate_count(&self) -> Result<u64, ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            return store.estate_count().await;
        }
        Ok(self
            .estate(2001, None)
            .await?
            .iter()
            .filter(|r| r.record_type == "node")
            .count() as u64)
    }
    pub async fn delete_selected(
        &self,
        logs: bool,
        inventory: bool,
        before: Option<i64>,
    ) -> Result<(), ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            return store.delete_selected(logs, inventory, before).await;
        }
        if logs || inventory {
            self.observations
                .write()
                .await
                .retain(|_, o| before.is_some_and(|t| o.observed_at.timestamp_millis() >= t));
        }
        Ok(())
    }
    /// Remove only the exact records owned by a sample workspace manifest.
    pub async fn delete_sample_records(
        &self,
        observations: &[Uuid],
        estate: &[Uuid],
    ) -> Result<(), ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            return store.delete_sample_records(observations, estate).await;
        }
        self.observations
            .write()
            .await
            .retain(|id, _| !observations.contains(id));
        Ok(())
    }

    pub async fn sample_record_counts(
        &self,
        observations: &[Uuid],
        estate: &[Uuid],
    ) -> Result<(u64, u64), ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            return store.sample_record_counts(observations, estate).await;
        }
        let buffer = self.observations.read().await;
        let logs = buffer.keys().filter(|id| observations.contains(id)).count() as u64;
        let nodes = buffer
            .values()
            .flat_map(estate::project)
            .filter(|r| r.record_type == "node" && estate.contains(&r.id))
            .map(|r| r.id)
            .collect::<std::collections::BTreeSet<_>>()
            .len() as u64;
        Ok((logs, nodes))
    }

    pub async fn deletion_counts(
        &self,
        before: Option<i64>,
    ) -> Result<(u64, u64), ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            return store.deletion_counts(before).await;
        }
        let buffer = self.observations.read().await;
        let logs = buffer
            .values()
            .filter(|o| before.is_none_or(|t| o.observed_at.timestamp_millis() < t))
            .count() as u64;
        let mut nodes = std::collections::BTreeMap::<Uuid, i64>::new();
        for r in buffer
            .values()
            .flat_map(estate::project)
            .filter(|r| r.record_type == "node")
        {
            nodes
                .entry(r.id)
                .and_modify(|t| *t = (*t).max(r.last_seen))
                .or_insert(r.last_seen);
        }
        Ok((
            logs,
            nodes
                .values()
                .filter(|t| before.is_none_or(|cutoff| **t < cutoff))
                .count() as u64,
        ))
    }

    pub async fn verify_migrations(&self) -> Result<(), ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            return store.verify_migrations().await;
        }
        Ok(())
    }
    pub async fn migrate(&self) -> Result<(), ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            return store.migrate().await;
        }
        Ok(())
    }

    pub async fn ping(&self) -> Result<(), ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            return store.ping().await;
        }
        Ok(())
    }

    pub async fn migration_head(&self) -> Result<String, ObservationBufferError> {
        Ok(OBSERVATION_BUFFER_VERSION.to_owned())
    }

    pub async fn continuity_snapshot(
        &self,
        installation_id: Uuid,
    ) -> Result<ObservationBufferSnapshot, ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            if installation_id != store.installation_id {
                return Err(ObservationBufferError::Storage(
                    "installation scope mismatch".into(),
                ));
            }
            return store.snapshot().await;
        }
        let observations = self.observations.read().await;
        let mut rows = observations
            .values()
            .filter(|item| item.installation_id == installation_id)
            .map(serde_json::to_vec)
            .collect::<Result<Vec<_>, _>>()?;
        rows.sort();
        let mut digest = Sha256::new();
        digest.update(b"godel-tally-transient-buffer-v1\0");
        for row in &rows {
            digest.update(u64::try_from(row.len()).unwrap_or(u64::MAX).to_be_bytes());
            digest.update(row);
        }
        Ok(ObservationBufferSnapshot {
            version: OBSERVATION_BUFFER_VERSION.to_owned(),
            observation_count: rows.len() as u64,
            observation_sha256: hex::encode(digest.finalize()),
        })
    }

    pub async fn observation_count(&self) -> Result<u64, ObservationBufferError> {
        self.observation_count_since(None).await
    }

    pub async fn observation_count_since(
        &self,
        since_millis: Option<i64>,
    ) -> Result<u64, ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            return store.count(since_millis).await;
        }
        let since = since_millis.unwrap_or(i64::MIN);
        Ok(self
            .observations
            .read()
            .await
            .values()
            .filter(|item| item.observed_at.timestamp_millis() >= since)
            .count() as u64)
    }

    pub async fn installation_observation_count(
        &self,
        installation_id: Uuid,
    ) -> Result<u64, ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            if installation_id != store.installation_id {
                return Ok(0);
            }
            return store.count(None).await;
        }
        Ok(self
            .observations
            .read()
            .await
            .values()
            .filter(|item| item.installation_id == installation_id)
            .count() as u64)
    }

    pub async fn purge_installation(
        &self,
        installation_id: Uuid,
    ) -> Result<(), ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            return store.purge(installation_id).await;
        }
        self.observations
            .write()
            .await
            .retain(|_, item| item.installation_id != installation_id);
        Ok(())
    }

    pub async fn list_observations(
        &self,
        limit: u32,
    ) -> Result<Vec<Observation>, ObservationBufferError> {
        self.list_observations_since(limit, None).await
    }

    pub async fn list_observations_since(
        &self,
        limit: u32,
        since_millis: Option<i64>,
    ) -> Result<Vec<Observation>, ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            return store.list(limit, None, since_millis, false).await;
        }
        let since = since_millis.unwrap_or(i64::MIN);
        let mut values = self
            .observations
            .read()
            .await
            .values()
            .filter(|item| item.observed_at.timestamp_millis() >= since)
            .cloned()
            .collect::<Vec<_>>();
        values.sort_by_key(|item| (item.observed_at, item.observation_id));
        values.truncate(limit.clamp(1, 100_000) as usize);
        Ok(values)
    }

    pub async fn list_recent_observations(
        &self,
        limit: u16,
        before: Option<(i64, Uuid)>,
    ) -> Result<Vec<Observation>, ObservationBufferError> {
        self.list_recent_observations_since(limit, before, None)
            .await
    }

    pub async fn list_recent_observations_since(
        &self,
        limit: u16,
        before: Option<(i64, Uuid)>,
        since_millis: Option<i64>,
    ) -> Result<Vec<Observation>, ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            return store
                .list(u32::from(limit.clamp(1, 500)), before, since_millis, true)
                .await;
        }
        let since = since_millis.unwrap_or(i64::MIN);
        let mut values = self
            .observations
            .read()
            .await
            .values()
            .filter(|item| item.observed_at.timestamp_millis() >= since)
            .filter(|item| {
                before.is_none_or(|cursor| {
                    (item.observed_at.timestamp_millis(), item.observation_id) < cursor
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        values.sort_by_key(|item| std::cmp::Reverse((item.observed_at, item.observation_id)));
        values.truncate(usize::from(limit.clamp(1, 500)));
        Ok(values)
    }

    pub async fn append_observation(
        &self,
        observation: &Observation,
    ) -> Result<(), ObservationBufferError> {
        self.append_observations(std::slice::from_ref(observation), &"0".repeat(64))
            .await
    }

    pub async fn append_observations(
        &self,
        observations: &[Observation],
        batch_digest: &str,
    ) -> Result<(), ObservationBufferError> {
        if batch_digest.len() != 64 || !batch_digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ObservationBufferError::InvalidBatchDigest);
        }
        if let Some(store) = &self.clickhouse {
            return store.append(observations).await;
        }
        let mut buffer = self.observations.write().await;
        for observation in observations {
            buffer.insert(observation.observation_id, observation.clone());
        }
        while buffer.len() > MAX_BUFFERED_OBSERVATIONS {
            let oldest = buffer
                .iter()
                .min_by_key(|(_, item)| (item.received_at, item.observation_id))
                .map(|(id, _)| *id);
            if let Some(oldest) = oldest {
                buffer.remove(&oldest);
            } else {
                break;
            }
        }
        Ok(())
    }

    pub async fn get_observation(
        &self,
        observation_id: Uuid,
    ) -> Result<Option<Observation>, ObservationBufferError> {
        if let Some(store) = &self.clickhouse {
            return store.get(observation_id).await;
        }
        Ok(self.observations.read().await.get(&observation_id).cloned())
    }
}

#[derive(Debug, Error)]
pub enum ObservationBufferError {
    #[error("{0}")]
    Storage(String),
    #[error("observation serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("batch digest must be a 64-character hexadecimal SHA-256 value")]
    InvalidBatchDigest,
}

#[cfg(test)]
mod activity_tests {
    use super::*;
    use chrono::{Duration, Utc};
    use tally_core::{ConnectorRef, DigestAlgorithm, EvidenceReceipt, Hostname, ObservationKind};

    fn observation(installation: Uuid) -> Observation {
        let mut o = Observation::new(
            installation,
            Utc::now(),
            ConnectorRef {
                instance_id: Uuid::now_v7(),
                connector_type: "fixture".into(),
                implementation_version: "1".into(),
                source_lineage_id: None,
            },
            ObservationKind::HttpMetadata,
            EvidenceReceipt::RecordDigest {
                algorithm: DigestAlgorithm::Sha256,
                digest: "ab".repeat(32),
            },
        );
        o.agent.key = Some("agent-fixture".into());
        o.agent.name = Some("Agent fixture".into());
        o.destination.host = Some(Hostname::parse("api.openai.com").unwrap());
        o.service.ai_request = true;
        o
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // One replay/window/scope scenario with real node and edge projection.
    async fn activity_replay_scope_window_measurements_and_connection_logs() {
        let store = ObservationBuffer::new();
        let installation = Uuid::now_v7();
        let mut first = observation(installation);
        first.observed_at -= Duration::days(1);
        first.network.bytes_sent = Some(0); // measured zero, not unknown
        let mut second = first.clone();
        second.observation_id = Uuid::now_v7();
        second.observed_at += Duration::days(1);
        second.network.bytes_sent = None;
        second.network.bytes_received = Some(2048);
        let foreign = observation(Uuid::now_v7());
        store
            .append_observations(&[first.clone(), second.clone(), foreign], &"ab".repeat(32))
            .await
            .unwrap();
        store
            .append_observations(&[second.clone()], &"ab".repeat(32))
            .await
            .unwrap();
        let activity = store
            .activity(installation, None, i64::MIN, i64::MAX)
            .await
            .unwrap();
        assert_eq!(
            (
                activity.records,
                activity.requests,
                activity.sent_reports,
                activity.received_reports,
                activity.bytes_sent,
                activity.bytes_received
            ),
            (2, 2, 1, 1, 0, 2048)
        );
        let ids = estate::project(&second)
            .into_iter()
            .map(|r| r.id)
            .collect::<Vec<_>>();
        assert_eq!(
            store
                .activity_for_records(installation, &ids, i64::MIN, i64::MAX)
                .await
                .unwrap()
                .records,
            2,
            "several matching nodes/edges must not multiply a single event"
        );
        assert_eq!(activity.daily.len(), 2);
        assert_eq!(
            activity.first_seen,
            Some(first.observed_at.timestamp_millis())
        );
        assert_eq!(
            activity.last_seen,
            Some(second.observed_at.timestamp_millis())
        );
        let edge = estate::project(&second)
            .into_iter()
            .find(|r| r.record_type == "edge")
            .unwrap();
        assert_eq!(
            store
                .activity(installation, Some(edge.id), i64::MIN, i64::MAX)
                .await
                .unwrap()
                .records,
            2
        );
        assert_eq!(
            store
                .activity(installation, Some(Uuid::nil()), i64::MIN, i64::MAX)
                .await
                .unwrap()
                .records,
            0
        );
        let page = store
            .entity_logs(installation, edge.id, 1, None, i64::MIN)
            .await
            .unwrap();
        assert_eq!(page, vec![second.clone()]);
        let cursor = Some((second.observed_at.timestamp_millis(), second.observation_id));
        assert_eq!(
            store
                .entity_logs(installation, edge.id, 1, cursor, i64::MIN)
                .await
                .unwrap(),
            vec![first]
        );
        assert_eq!(
            store
                .entity_logs(Uuid::nil(), edge.id, 50, None, i64::MIN)
                .await
                .unwrap(),
            [] as [tally_core::Observation; 0]
        );
        assert_eq!(
            store
                .activity(
                    installation,
                    None,
                    second.observed_at.timestamp_millis(),
                    i64::MAX
                )
                .await
                .unwrap()
                .records,
            1
        );
    }
}
