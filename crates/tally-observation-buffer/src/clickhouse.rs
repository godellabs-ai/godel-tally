#![allow(clippy::items_after_statements)]
use crate::{
    ObservationBufferError,
    estate::{self, EstateRecord},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{fmt, time::Duration};
use tally_core::Observation;
use uuid::Uuid;
pub mod activity;
mod event_stream;

pub const MIGRATION_HEAD: &str = "tally-clickhouse-baseline-0003";
const MIGRATION_LEDGER_DDL: &str = "CREATE TABLE IF NOT EXISTS tally_schema_migrations (version String, checksum String, applied_at DateTime DEFAULT now()) ENGINE = ReplacingMergeTree ORDER BY version";
struct Migration {
    version: &'static str,
    sql: &'static str,
}
impl Migration {
    fn checksum(&self) -> String {
        hex::encode(Sha256::digest(self.sql.as_bytes()))
    }
    fn verify(&self, checksum: &str) -> Result<(), ObservationBufferError> {
        if checksum == self.checksum() {
            Ok(())
        } else {
            Err(error(&format!(
                "Tally ClickHouse migration checksum mismatch for {}; expected {}, found {checksum}",
                self.version,
                self.checksum()
            )))
        }
    }
}
const MIGRATIONS: &[Migration] = &[
    Migration {
        version: "0001_ai_events",
        sql: include_str!("../../../migrations/clickhouse/0001_ai_events.sql"),
    },
    Migration {
        version: "0002_estate",
        sql: include_str!("../../../migrations/clickhouse/0002_estate.sql"),
    },
    Migration {
        version: "0003_endpoint_coverage",
        sql: include_str!("../../../migrations/clickhouse/0003_endpoint_coverage.sql"),
    },
];
#[derive(Deserialize)]
struct AppliedMigration {
    version: String,
    checksum: String,
}

#[derive(Clone)]
pub struct ClickHouse {
    client: reqwest::Client,
    url: url::Url,
    pub installation_id: Uuid,
    retention_days: u16,
}
impl fmt::Debug for ClickHouse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TallyClickHouse")
            .field("installation_id", &self.installation_id)
            .finish_non_exhaustive()
    }
}
#[derive(Deserialize)]
struct Payload {
    payload: String,
}
#[derive(Deserialize)]
struct Count {
    count: u64,
}

impl ClickHouse {
    pub fn new(
        endpoint: &str,
        database: &str,
        installation_id: Uuid,
        retention_days: u16,
    ) -> Result<Self, ObservationBufferError> {
        let mut url = url::Url::parse(endpoint).map_err(|_| error("invalid ClickHouse URL"))?;
        if !matches!(url.scheme(), "http" | "https")
            || database.is_empty()
            || !database
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || !(1..=3650).contains(&retention_days)
        {
            return Err(error("invalid ClickHouse configuration"));
        }
        let mut headers = reqwest::header::HeaderMap::new();
        let mut credentials: Vec<(String, String)> = url
            .query_pairs()
            .filter(|(k, _)| k == "user" || k == "password")
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        if !url.username().is_empty() {
            credentials.push(("user".into(), url.username().to_owned()));
        }
        if let Some(password) = url.password() {
            credentials.push(("password".into(), password.to_owned()));
        }
        for (key, value) in credentials {
            let mut header = reqwest::header::HeaderValue::from_str(&value)
                .map_err(|_| error("invalid ClickHouse credential"))?;
            header.set_sensitive(true);
            headers.insert(
                if key == "user" {
                    "x-clickhouse-user"
                } else {
                    "x-clickhouse-key"
                },
                header,
            );
        }
        let _ = url.set_username("");
        let _ = url.set_password(None);
        url.set_query(None);
        url.set_fragment(None);
        url.query_pairs_mut()
            .append_pair("database", database)
            .append_pair("output_format_json_quote_64bit_integers", "0");
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| error("ClickHouse client initialization failed"))?;
        Ok(Self {
            client,
            url,
            installation_id,
            retention_days,
        })
    }
    pub async fn execute(&self, sql: &str) -> Result<String, ObservationBufferError> {
        let response = self
            .client
            .post(self.url.clone())
            .body(sql.to_owned())
            .send()
            .await
            .map_err(|_| error("ClickHouse request failed"))?;
        Self::response_text(response).await
    }
    async fn response_text(response: reqwest::Response) -> Result<String, ObservationBufferError> {
        if !response.status().is_success() {
            return Err(error(&format!(
                "ClickHouse returned HTTP {}",
                response.status().as_u16()
            )));
        }
        // Response errors deliberately exclude SQL/payload/URL, all of which may contain telemetry.
        let mut response = response;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| error("ClickHouse response failed"))?
        {
            if body.len().saturating_add(chunk.len()) > 64 * 1024 * 1024 {
                return Err(error("ClickHouse response limit exceeded"));
            }
            body.extend_from_slice(&chunk);
        }
        String::from_utf8(body).map_err(|_| error("invalid ClickHouse response"))
    }
    async fn rows<T: DeserializeOwned>(&self, sql: &str) -> Result<Vec<T>, ObservationBufferError> {
        let body = self.execute(&format!("{sql} FORMAT JSONEachRow")).await?;
        body.lines()
            .filter(|s| !s.is_empty())
            .map(|s| serde_json::from_str(s).map_err(Into::into))
            .collect()
    }
    pub async fn ping(&self) -> Result<(), ObservationBufferError> {
        self.execute("SELECT 1").await.map(|_| ())
    }
    // API hosts verify the entire series without DDL; workers apply it under the PostgreSQL lock.
    pub async fn verify_migrations(&self) -> Result<(), ObservationBufferError> {
        let applied = self.applied_migrations().await?;
        for migration in MIGRATIONS {
            let row = applied.iter().find(|row| row.version == migration.version).ok_or_else(|| error(&format!("Tally ClickHouse migration {} is missing; start the migration-owning worker first", migration.version)))?;
            migration.verify(&row.checksum)?;
        }
        Ok(())
    }
    async fn applied_migrations(&self) -> Result<Vec<AppliedMigration>, ObservationBufferError> {
        self.rows("SELECT version, checksum FROM tally_schema_migrations FINAL")
            .await
    }
    /// The caller serializes migrations using the shared PostgreSQL advisory transaction lock.
    pub async fn migrate(&self) -> Result<(), ObservationBufferError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            match self.ping().await {
                Ok(()) => break,
                Err(ObservationBufferError::Storage(message))
                    if message == "ClickHouse request failed"
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(error) => return Err(error),
            }
        }
        self.execute(MIGRATION_LEDGER_DDL).await?;
        let applied = self.applied_migrations().await?;
        // Reject unknown changes before applying any pending DDL.
        for migration in MIGRATIONS {
            if let Some(row) = applied.iter().find(|row| row.version == migration.version) {
                migration.verify(&row.checksum)?;
            }
        }
        for migration in MIGRATIONS {
            if applied.iter().any(|row| row.version == migration.version) {
                continue;
            }
            for statement in migration
                .sql
                .split(';')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                self.execute(statement).await?;
            }
            self.execute(&format!(
                "INSERT INTO tally_schema_migrations (version, checksum) VALUES ('{}', '{}')",
                migration.version,
                migration.checksum()
            ))
            .await?;
        }
        Ok(())
    }
    fn scope(&self) -> String {
        format!("installation_id = '{}'", self.installation_id)
    }
    pub async fn append(&self, observations: &[Observation]) -> Result<(), ObservationBufferError> {
        if observations.is_empty() {
            return Ok(());
        }
        if observations
            .iter()
            .any(|o| o.installation_id != self.installation_id)
        {
            return Err(error("installation scope mismatch"));
        }
        #[derive(Serialize)]
        struct Event<'a> {
            installation_id: Uuid,
            observation_id: Uuid,
            observed_at: i64,
            received_at: i64,
            connector_id: Uuid,
            connector_type: &'a str,
            payload: String,
            expires_at: i64,
        }
        let mut events = String::from("INSERT INTO tally_ai_events FORMAT JSONEachRow\n");
        let mut estate = String::from(
            "INSERT INTO tally_estate SELECT installation_id, id, record_type, min(observed_at), max(observed_at), argMaxState(detail, observed_at) FROM input('installation_id UUID, id UUID, record_type String, observed_at Int64, detail String') GROUP BY installation_id, id, record_type FORMAT JSONEachRow\n",
        );
        let mut records = 0;
        for o in observations {
            let event = Event {
                installation_id: o.installation_id,
                observation_id: o.observation_id,
                observed_at: o.observed_at.timestamp_millis(),
                received_at: o.received_at.timestamp_millis(),
                connector_id: o.connector.instance_id,
                connector_type: &o.connector.connector_type,
                payload: serde_json::to_string(o)?,
                expires_at: o.observed_at.timestamp() + i64::from(self.retention_days) * 86400,
            };
            events.push_str(&serde_json::to_string(&event)?);
            events.push('\n');
            for record in estate::project(o) {
                estate.push_str(&serde_json::to_string(&serde_json::json!({"installation_id":o.installation_id,"id":record.id,"record_type":record.record_type,"observed_at":record.last_seen,"detail":serde_json::to_string(&record.detail)?}))?);
                estate.push('\n');
                records += 1;
            }
        }
        // Admission checkpoints advance only after all writes succeed. Every write is replay safe.
        self.execute(&events).await?;
        self.write_activity(observations).await?;
        if records > 0 {
            self.execute(&estate).await?;
        }
        Ok(())
    }
    pub async fn record_coverage(
        &self,
        observations: &[Observation],
    ) -> Result<(), ObservationBufferError> {
        let mut rows = String::new();
        for o in observations
            .iter()
            .filter(|o| o.service.source_category.as_deref() == Some("defender:DeviceInfo"))
        {
            if o.installation_id != self.installation_id {
                return Err(error("installation scope mismatch"));
            }
            if let Some(device_key) = &o.actor.device_key {
                rows.push_str(&serde_json::to_string(&serde_json::json!({"installation_id":self.installation_id,"device_key":device_key,"last_seen":o.observed_at.timestamp_millis()}))?);
                rows.push('\n');
            }
        }
        if !rows.is_empty() {
            self.execute(&format!(
                "INSERT INTO tally_endpoint_coverage FORMAT JSONEachRow\n{rows}"
            ))
            .await?;
        }
        Ok(())
    }
    pub async fn coverage_count(&self) -> Result<u64, ObservationBufferError> {
        Ok(self.rows::<Count>(&format!("SELECT count() AS count FROM (SELECT device_key FROM tally_endpoint_coverage WHERE {} GROUP BY device_key HAVING max(last_seen) >= toUnixTimestamp64Milli(now64()) - 2592000000)",self.scope())).await?.first().map_or(0,|r|r.count))
    }
    pub async fn write_inventory(
        &self,
        records: &[EstateRecord],
    ) -> Result<(), ObservationBufferError> {
        if records.is_empty() {
            return Ok(());
        }
        let mut query = String::from(
            "INSERT INTO tally_estate SELECT installation_id, id, record_type, min(first_seen), max(last_seen), argMaxState(detail, last_seen) FROM input('installation_id UUID, id UUID, record_type String, first_seen Int64, last_seen Int64, detail String') GROUP BY installation_id, id, record_type FORMAT JSONEachRow\n",
        );
        for record in records {
            query.push_str(&serde_json::to_string(&serde_json::json!({"installation_id":self.installation_id,"id":record.id,"record_type":record.record_type,"first_seen":record.first_seen,"last_seen":record.last_seen,"detail":serde_json::to_string(&record.detail)?}))?);
            query.push('\n');
        }
        self.execute(&query).await.map(|_| ())
    }
    pub async fn bootstrap_needed(&self) -> Result<bool, ObservationBufferError> {
        Ok(self.rows::<Count>(&format!("SELECT count() AS count FROM tally_schema_migrations WHERE version = 'legacy_findings_inventory_v2:{}'",self.installation_id)).await?.first().is_none_or(|row| row.count == 0))
    }
    pub async fn finish_bootstrap(&self) -> Result<(), ObservationBufferError> {
        self.execute(&format!("INSERT INTO tally_schema_migrations (version, checksum) VALUES ('legacy_findings_inventory_v2:{}', 'metadata-only-v2')",self.installation_id)).await.map(|_| ())
    }
    pub async fn estate_count(&self) -> Result<u64, ObservationBufferError> {
        Ok(self
            .rows::<Count>(&format!(
                "SELECT uniqExact(id) AS count FROM tally_estate WHERE {} AND record_type = 'node'",
                self.scope()
            ))
            .await?
            .first()
            .map_or(0, |row| row.count))
    }
    pub async fn delete_sample_records(
        &self,
        observations: &[Uuid],
        estate: &[Uuid],
    ) -> Result<(), ObservationBufferError> {
        // Values are typed UUIDs from a server-owned manifest, never SQL supplied by a caller.
        for (table, column, ids) in [
            ("tally_ai_events", "observation_id", observations),
            ("tally_ai_activity", "observation_id", observations),
            ("tally_estate", "id", estate),
        ] {
            for chunk in ids.chunks(500) {
                let ids = chunk
                    .iter()
                    .map(|id| format!("'{id}'"))
                    .collect::<Vec<_>>()
                    .join(",");
                self.execute(&format!("ALTER TABLE {table} DELETE WHERE {} AND {column} IN ({ids}) SETTINGS mutations_sync = 2", self.scope())).await?;
            }
        }
        Ok(())
    }

    pub async fn sample_record_counts(
        &self,
        observations: &[Uuid],
        estate: &[Uuid],
    ) -> Result<(u64, u64), ObservationBufferError> {
        let mut counts = [0, 0];
        for (index, ids) in [observations, estate].into_iter().enumerate() {
            for chunk in ids.chunks(500) {
                let ids = chunk
                    .iter()
                    .map(|id| format!("'{id}'"))
                    .collect::<Vec<_>>()
                    .join(",");
                let query = if index == 0 {
                    format!(
                        "SELECT count() AS count FROM tally_ai_events FINAL WHERE {} AND observation_id IN ({ids}) AND expires_at > now()",
                        self.scope()
                    )
                } else {
                    format!(
                        "SELECT count() AS count FROM (SELECT id FROM tally_estate WHERE {} AND record_type = 'node' AND id IN ({ids}) GROUP BY id)",
                        self.scope()
                    )
                };
                counts[index] += self
                    .rows::<Count>(&query)
                    .await?
                    .first()
                    .map_or(0, |r| r.count);
            }
        }
        Ok((counts[0], counts[1]))
    }

    pub async fn deletion_counts(
        &self,
        before: Option<i64>,
    ) -> Result<(u64, u64), ObservationBufferError> {
        let logs_cutoff = before.map_or_else(String::new, |t| format!(" AND observed_at < {t}"));
        let estate_cutoff =
            before.map_or_else(String::new, |t| format!(" HAVING max(last_seen) < {t}"));
        let logs = self.rows::<Count>(&format!("SELECT count() AS count FROM tally_ai_events FINAL WHERE {} AND expires_at > now(){logs_cutoff}", self.scope())).await?.first().map_or(0, |r|r.count);
        let nodes = self.rows::<Count>(&format!("SELECT count() AS count FROM (SELECT id FROM tally_estate WHERE {} AND record_type = 'node' GROUP BY id{estate_cutoff})", self.scope())).await?.first().map_or(0, |r|r.count);
        Ok((logs, nodes))
    }

    pub async fn delete_selected(
        &self,
        logs: bool,
        inventory: bool,
        before: Option<i64>,
    ) -> Result<(), ObservationBufferError> {
        if logs {
            let cutoff = before.map_or(String::new(), |time| format!(" AND observed_at < {time}"));
            self.execute(&format!(
                "ALTER TABLE tally_ai_activity DELETE WHERE {}{cutoff} SETTINGS mutations_sync = 2",
                self.scope()
            ))
            .await?;
            self.execute(&format!(
                "ALTER TABLE tally_ai_events DELETE WHERE {}{cutoff} SETTINGS mutations_sync = 2",
                self.scope()
            ))
            .await?;
        }
        if inventory {
            let cutoff = before.map_or(String::new(), |time| format!(" AND last_seen < {time}"));
            self.execute(&format!("ALTER TABLE tally_endpoint_coverage DELETE WHERE {}{cutoff} SETTINGS mutations_sync = 2",self.scope())).await?;
            if let Some(cutoff) = before {
                #[derive(Deserialize)]
                struct Id {
                    id: Uuid,
                }
                loop {
                    let ids = self.rows::<Id>(&format!("SELECT id FROM tally_estate WHERE {} GROUP BY id HAVING max(last_seen) < {cutoff} LIMIT 500",self.scope())).await?;
                    if ids.is_empty() {
                        break;
                    }
                    let ids = ids
                        .iter()
                        .map(|row| format!("toUUID('{}')", row.id))
                        .collect::<Vec<_>>()
                        .join(",");
                    self.execute(&format!("ALTER TABLE tally_estate DELETE WHERE {} AND id IN ({ids}) SETTINGS mutations_sync = 2",self.scope())).await?;
                }
            } else {
                self.execute(&format!(
                    "ALTER TABLE tally_estate DELETE WHERE {} SETTINGS mutations_sync = 2",
                    self.scope()
                ))
                .await?;
            }
        }
        Ok(())
    }
    pub async fn count(&self, since: Option<i64>) -> Result<u64, ObservationBufferError> {
        Ok(self.rows::<Count>(&format!("SELECT count() AS count FROM tally_ai_events FINAL WHERE {} AND observed_at >= {} AND expires_at > now()", self.scope(), since.unwrap_or(i64::MIN))).await?.first().map_or(0, |r| r.count))
    }
    pub async fn list(
        &self,
        limit: u32,
        before: Option<(i64, Uuid)>,
        since: Option<i64>,
        descending: bool,
    ) -> Result<Vec<Observation>, ObservationBufferError> {
        let cursor = before.map_or(String::new(), |(time, id)| {
            format!(" AND (observed_at, observation_id) < ({time}, toUUID('{id}'))")
        });
        let direction = if descending { "DESC" } else { "ASC" };
        let rows = self.rows::<Payload>(&format!("SELECT payload FROM tally_ai_events FINAL WHERE {} AND observed_at >= {} AND expires_at > now(){cursor} ORDER BY observed_at {direction}, observation_id {direction} LIMIT {}", self.scope(), since.unwrap_or(i64::MIN), limit.clamp(1,100_000))).await?;
        rows.into_iter()
            .map(|r| serde_json::from_str(&r.payload).map_err(Into::into))
            .collect()
    }
    pub async fn get(&self, id: Uuid) -> Result<Option<Observation>, ObservationBufferError> {
        let rows = self.rows::<Payload>(&format!("SELECT payload FROM tally_ai_events FINAL WHERE {} AND observation_id = '{id}' AND expires_at > now() LIMIT 1", self.scope())).await?;
        rows.first()
            .map(|r| serde_json::from_str(&r.payload).map_err(Into::into))
            .transpose()
    }
    pub async fn estate(
        &self,
        limit: u32,
        after: Option<Uuid>,
    ) -> Result<Vec<EstateRecord>, ObservationBufferError> {
        #[derive(Deserialize)]
        struct Row {
            id: Uuid,
            record_type: String,
            first_seen: i64,
            last_seen: i64,
            detail: String,
        }
        let cursor = after.map_or(String::new(), |id| format!(" AND id > toUUID('{id}')"));
        self.rows::<Row>(&format!("SELECT id, record_type, min(first_seen) AS first_seen, max(last_seen) AS last_seen, argMaxMerge(detail) AS detail FROM tally_estate WHERE {}{cursor} GROUP BY record_type, id ORDER BY id LIMIT {}", self.scope(), limit.clamp(1,2001))).await?.into_iter().map(|r| Ok(EstateRecord { id:r.id, record_type:r.record_type, first_seen:r.first_seen, last_seen:r.last_seen, detail:serde_json::from_str(&r.detail)? })).collect()
    }
    pub async fn snapshot(
        &self,
    ) -> Result<crate::ObservationBufferSnapshot, ObservationBufferError> {
        #[derive(Deserialize)]
        struct Snapshot {
            count: u64,
            digest: String,
        }
        let rows = self.rows::<Snapshot>(&format!("SELECT count() AS count, hex(SHA256(concat(toString(count()), ':', toString(groupBitXor(cityHash64(payload)))))) AS digest FROM tally_ai_events FINAL WHERE {} AND expires_at > now()", self.scope())).await?;
        let row = rows
            .first()
            .ok_or_else(|| error("missing continuity snapshot"))?;
        Ok(crate::ObservationBufferSnapshot {
            version: MIGRATION_HEAD.into(),
            observation_count: row.count,
            observation_sha256: row.digest.to_lowercase(),
        })
    }
    pub async fn purge(&self, installation_id: Uuid) -> Result<(), ObservationBufferError> {
        if installation_id != self.installation_id {
            return Err(error("installation scope mismatch"));
        }
        for table in [
            "tally_ai_activity",
            "tally_ai_events",
            "tally_estate",
            "tally_endpoint_coverage",
        ] {
            self.execute(&format!(
                "ALTER TABLE {table} DELETE WHERE {} SETTINGS mutations_sync = 2",
                self.scope()
            ))
            .await?;
        }
        Ok(())
    }
}
fn error(message: &str) -> ObservationBufferError {
    ObservationBufferError::Storage(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};
    use tally_core::{ConnectorRef, DigestAlgorithm, EvidenceReceipt, ObservationKind};

    fn observation(installation_id: Uuid, observed_at: chrono::DateTime<Utc>) -> Observation {
        let mut o = Observation::new(
            installation_id,
            observed_at,
            ConnectorRef {
                instance_id: Uuid::from_u128(12),
                connector_type: "defender_stream".into(),
                implementation_version: "test".into(),
                source_lineage_id: None,
            },
            ObservationKind::HttpMetadata,
            EvidenceReceipt::RecordDigest {
                algorithm: DigestAlgorithm::Sha256,
                digest: "0".repeat(64),
            },
        );
        o.agent.key = Some("device:agent".into());
        o.agent.name = Some("Fixture agent".into());
        o.agent.kind = Some("agent".into());
        o
    }
    #[test]
    fn secrets_are_not_debuggable_and_database_is_validated() {
        let store = ClickHouse::new(
            "http://localhost:8123?user=test&password=secret-canary",
            "tally",
            Uuid::nil(),
            90,
        )
        .unwrap();
        assert!(!format!("{store:?}").contains("secret-canary"));
        assert!(!store.url.as_str().contains("secret-canary"));
        assert!(ClickHouse::new("http://localhost:8123", "tally;DROP", Uuid::nil(), 90).is_err());
    }
    #[test]
    fn migration_checksums_require_the_tally_schema() {
        for migration in MIGRATIONS {
            assert!(migration.verify(&migration.checksum()).is_ok());
            for checksum in [
                "ae5d77b51d363cb05e00819fcf54a1b5115e53a0ce1020c60409ee126f9a264e",
                "bef0a543ef5212f157555e8c3f7adb5f2b7d9fe8325f1cfef706e103ae2a24b8",
                "unknown-checksum",
            ] {
                assert!(migration.verify(checksum).is_err());
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires a disposable TALLY_TEST_CLICKHOUSE_URL and TALLY_TEST_CLICKHOUSE_DATABASE"]
    #[allow(clippy::too_many_lines)] // One disposable-store upgrade/replay/retention scenario.
    async fn live_retention_replay_restart_scope_and_migration() {
        let url = std::env::var("TALLY_TEST_CLICKHOUSE_URL").unwrap();
        let database = std::env::var("TALLY_TEST_CLICKHOUSE_DATABASE").unwrap();
        assert!(
            database.starts_with("tally_estate_test_"),
            "requires a disposable database"
        );
        let installation = Uuid::now_v7();
        let store = ClickHouse::new(&url, &database, installation, 90).unwrap();
        store.migrate().await.unwrap();
        store.migrate().await.unwrap();
        store.verify_migrations().await.unwrap();
        let old = observation(installation, Utc::now() - ChronoDuration::days(120));
        let mut current = observation(installation, Utc::now());
        current.service.ai_request = true;
        current.network.bytes_received = Some(1024);
        // A missing sent measurement must remain distinct from a measured zero.
        current.network.bytes_sent = None;
        store.append(&[old.clone(), current.clone()]).await.unwrap();
        store.append(std::slice::from_ref(&current)).await.unwrap();
        assert_eq!(
            store.count(None).await.unwrap(),
            1,
            "source replay must not double count logs"
        );
        let measured = store.activity(None, i64::MIN, i64::MAX).await.unwrap();
        assert_eq!(
            (
                measured.records,
                measured.requests,
                measured.sent_reports,
                measured.received_reports,
                measured.bytes_received
            ),
            (1, 1, 0, 1, 1024)
        );
        let inventory = store.estate(100, None).await.unwrap();
        assert_eq!(inventory.len(), 1);
        let ids = estate::project(&current)
            .into_iter()
            .map(|r| r.id)
            .collect::<Vec<_>>();
        assert_eq!(
            store
                .activity_for_records(&ids, i64::MIN, i64::MAX)
                .await
                .unwrap()
                .records,
            1
        );

        assert_eq!(inventory[0].first_seen, old.observed_at.timestamp_millis());
        assert_eq!(
            inventory[0].last_seen,
            current.observed_at.timestamp_millis()
        );
        let restarted = ClickHouse::new(&url, &database, installation, 90).unwrap();
        assert!(
            restarted
                .get(current.observation_id)
                .await
                .unwrap()
                .is_some()
        );
        let other = ClickHouse::new(&url, &database, Uuid::now_v7(), 90).unwrap();
        assert!(other.get(current.observation_id).await.unwrap().is_none());
        assert!(other.estate(100, None).await.unwrap().is_empty());
        assert_eq!(
            other
                .activity(None, i64::MIN, i64::MAX)
                .await
                .unwrap()
                .records,
            0
        );
        assert_eq!(
            store
                .activity(Some(inventory[0].id), i64::MIN, i64::MAX)
                .await
                .unwrap()
                .records,
            1
        );
        assert_eq!(
            other
                .entity_logs(inventory[0].id, 50, None, i64::MIN)
                .await
                .unwrap(),
            [] as [tally_core::Observation; 0]
        );
        assert_eq!(
            store
                .entity_logs(inventory[0].id, 50, None, i64::MIN)
                .await
                .unwrap(),
            vec![current.clone()]
        );
        assert!(other.append(std::slice::from_ref(&current)).await.is_err());
        store
            .delete_selected(
                false,
                true,
                Some((Utc::now() - ChronoDuration::days(1)).timestamp_millis()),
            )
            .await
            .unwrap();
        assert_eq!(
            store.estate(100, None).await.unwrap().len(),
            1,
            "cutoff keeps recently observed inventory"
        );
        store.delete_selected(true, false, None).await.unwrap();
        assert_eq!(store.count(None).await.unwrap(), 0);
        assert_eq!(
            store
                .activity(None, i64::MIN, i64::MAX)
                .await
                .unwrap()
                .records,
            0,
            "deleting logs must remove the derived activity index too"
        );
        assert_eq!(
            store.estate(100, None).await.unwrap().len(),
            1,
            "inventory survives all log deletion"
        );
        assert_eq!(store.snapshot().await.unwrap().observation_count, 0);
        store.purge(installation).await.unwrap();
        assert!(store.estate(100, None).await.unwrap().is_empty());
        store.execute("INSERT INTO tally_schema_migrations (version,checksum) VALUES ('0001_ai_events','tampered')").await.unwrap();
        assert!(store.verify_migrations().await.is_err());
        assert!(
            store.migrate().await.is_err(),
            "applied migrations cannot change silently"
        );
    }
}
