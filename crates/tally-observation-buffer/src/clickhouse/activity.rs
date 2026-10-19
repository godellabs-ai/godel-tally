use super::{ClickHouse, Observation, ObservationBufferError, Uuid, error, estate};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ActivityDay {
    pub day: i64,
    pub records: u64,
    pub requests: u64,
    pub byte_reports: u64,
    pub sent_reports: u64,
    pub received_reports: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ActivitySummary {
    pub records: u64,
    pub requests: u64,
    pub byte_reports: u64,
    pub sent_reports: u64,
    pub received_reports: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
    pub daily: Vec<ActivityDay>,
}
#[derive(Serialize)]
struct ActivityRow {
    installation_id: Uuid,
    observation_id: Uuid,
    observed_at: i64,
    received_at: i64,
    record_ids: Vec<Uuid>,
    bytes_sent: Option<u64>,
    bytes_received: Option<u64>,
    ai_request: u8,
    expires_at: i64,
}
impl ActivityRow {
    fn new(o: &Observation, expires_at: i64) -> Self {
        Self {
            installation_id: o.installation_id,
            observation_id: o.observation_id,
            observed_at: o.observed_at.timestamp_millis(),
            received_at: o.received_at.timestamp_millis(),
            record_ids: estate::project(o).into_iter().map(|r| r.id).collect(),
            bytes_sent: o.network.bytes_sent,
            bytes_received: o.network.bytes_received,
            ai_request: u8::from(o.service.ai_request),
            expires_at,
        }
    }
}
impl ClickHouse {
    pub(super) async fn write_activity(
        &self,
        observations: &[Observation],
    ) -> Result<(), ObservationBufferError> {
        let rows = observations
            .iter()
            .map(|o| {
                ActivityRow::new(
                    o,
                    o.observed_at.timestamp() + i64::from(self.retention_days) * 86_400,
                )
            })
            .collect::<Vec<_>>();
        self.insert_activity(&rows).await
    }
    async fn insert_activity(&self, rows: &[ActivityRow]) -> Result<(), ObservationBufferError> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut query = String::from("INSERT INTO tally_ai_activity FORMAT JSONEachRow\n");
        for row in rows {
            if row.installation_id != self.installation_id {
                return Err(error("installation scope mismatch"));
            }
            query.push_str(&serde_json::to_string(row)?);
            query.push('\n');
        }
        self.execute(&query).await.map(|_| ())
    }
    #[cfg(test)]
    pub async fn activity(
        &self,
        id: Option<Uuid>,
        since: i64,
        until: i64,
    ) -> Result<ActivitySummary, ObservationBufferError> {
        self.activity_for_records(id.as_slice(), since, until).await
    }
    pub async fn activity_for_records(
        &self,
        ids: &[Uuid],
        since: i64,
        until: i64,
    ) -> Result<ActivitySummary, ObservationBufferError> {
        let entity = if ids.is_empty() {
            String::new()
        } else {
            format!(
                " AND hasAny(record_ids, [{}])",
                ids.iter()
                    .map(|id| format!("toUUID('{id}')"))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        let filter = format!(
            "{} AND observed_at >= {since} AND observed_at <= {until} AND expires_at > now(){entity}",
            self.scope()
        );
        let totals = "count() AS records, sum(ai_request) AS requests, countIf(isNotNull(tally_ai_activity.bytes_sent) OR isNotNull(tally_ai_activity.bytes_received)) AS byte_reports, countIf(isNotNull(tally_ai_activity.bytes_sent)) AS sent_reports, countIf(isNotNull(tally_ai_activity.bytes_received)) AS received_reports, sum(ifNull(tally_ai_activity.bytes_sent,0)) AS bytes_sent, sum(ifNull(tally_ai_activity.bytes_received,0)) AS bytes_received";
        let mut summary = self.rows::<ActivitySummary>(&format!("SELECT {totals}, minOrNull(observed_at) AS first_seen, maxOrNull(observed_at) AS last_seen, [] AS daily FROM tally_ai_activity FINAL WHERE {filter} SETTINGS optimize_move_to_prewhere_if_final = 0")).await?.into_iter().next().unwrap_or_default();
        summary.daily = self.rows::<ActivityDay>(&format!("SELECT intDiv(observed_at,86400000)*86400000 AS day, {totals} FROM tally_ai_activity FINAL WHERE {filter} GROUP BY day ORDER BY day SETTINGS optimize_move_to_prewhere_if_final = 0")).await?;
        Ok(summary)
    }
    pub async fn entity_logs(
        &self,
        id: Uuid,
        limit: u16,
        before: Option<(i64, Uuid)>,
        since: i64,
    ) -> Result<Vec<Observation>, ObservationBufferError> {
        #[derive(Deserialize)]
        struct Row {
            payload: String,
        }
        let cursor = before.map_or(String::new(), |(time, id)| {
            format!(" AND (observed_at, observation_id) < ({time},toUUID('{id}'))")
        });
        self.rows::<Row>(&format!("SELECT payload FROM tally_ai_events FINAL WHERE {} AND expires_at > now() AND (observed_at,observation_id) IN (SELECT observed_at,observation_id FROM tally_ai_activity FINAL WHERE {} AND observed_at >= {since} AND expires_at > now() AND has(record_ids,toUUID('{id}')){cursor} ORDER BY observed_at DESC, observation_id DESC LIMIT {} ) ORDER BY observed_at DESC, observation_id DESC SETTINGS optimize_move_to_prewhere_if_final = 0",self.scope(),self.scope(),limit.clamp(1,500))).await?.into_iter().map(|r| serde_json::from_str(&r.payload).map_err(Into::into)).collect()
    }
    pub async fn estate_entity(
        &self,
        id: Uuid,
    ) -> Result<Option<estate::EstateRecord>, ObservationBufferError> {
        #[derive(Deserialize)]
        struct Row {
            first_seen: i64,
            last_seen: i64,
            detail: String,
        }
        self.rows::<Row>(&format!("SELECT min(first_seen) AS first_seen, max(last_seen) AS last_seen,argMaxMerge(detail) AS detail FROM tally_estate WHERE {} AND id=toUUID('{id}') AND record_type='node' GROUP BY id LIMIT 1",self.scope())).await?.into_iter().next().map(|r| Ok(estate::EstateRecord { id,record_type:"node".into(),first_seen:r.first_seen,last_seen:r.last_seen,detail:serde_json::from_str(&r.detail)? })).transpose()
    }
}
