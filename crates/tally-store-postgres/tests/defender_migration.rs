//! Legacy placeholder corrections must preserve usage and source revision history.
use chrono::{Duration, Utc};
use tally_core::{
    ActivityAttribution, ConnectorRef, DeviceIdentifierKind, DigestAlgorithm, EvidenceReceipt,
    IpAddress, Observation, ObservationKind, ProcessObservation,
};
use tally_store_postgres::{FindingEvidenceKind, ObservedUsage, PostgresStore};
use uuid::Uuid;

fn usage(o: &Observation) -> ObservedUsage {
    ObservedUsage {
        observation_id: o.observation_id,
        installation_id: o.installation_id,
        provider_key: "openai".into(),
        provider_name: "OpenAI".into(),
        provider_category: "direct_provider".into(),
        provider_country_code: Some("US".into()),
        provider_catalogued: true,
        model_reference: Some("gpt-4o".into()),
        observed_at: o.observed_at,
        connector_instance_id: o.connector.instance_id,
        evidence_kind: FindingEvidenceKind::AiUsage,
        counts_as_usage: true,
        endpoints: Vec::new(),
        destinations: Vec::new(),
        workloads: Vec::new(),
        user_identity: None,
        request_client: o.actor.request_client.clone(),
        activity: Some(ActivityAttribution::from(o)),
    }
}

#[tokio::test]
#[ignore = "requires TALLY_DISPOSABLE_POSTGRES_URL pointing to a disposable database"]
#[allow(clippy::too_many_lines)]
async fn defender_placeholder_migration_preserves_evidence_and_separates_processes() {
    let store = PostgresStore::connect(&std::env::var("TALLY_DISPOSABLE_POSTGRES_URL").unwrap())
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let installation = store
        .get_or_create_installation_identity()
        .await
        .unwrap()
        .installation_id;
    let connector = Uuid::now_v7();
    store
        .register_connector(
            installation,
            connector,
            &tally_connectors::microsoft_defender_edr_api_descriptor(),
        )
        .await
        .unwrap();
    let at = Utc::now() - Duration::minutes(10);
    let mut first = Observation::new(
        installation,
        at,
        ConnectorRef {
            instance_id: connector,
            connector_type: "microsoft_defender_edr_api_v1".into(),
            implementation_version: "legacy".into(),
            source_lineage_id: None,
        },
        ObservationKind::HttpMetadata,
        EvidenceReceipt::RecordDigest {
            algorithm: DigestAlgorithm::Sha256,
            digest: "ab".repeat(32),
        },
    );
    first.actor.device_key = Some("device-key".into());
    first.inventory.device_key_kind = Some(DeviceIdentifierKind::SourceNative);
    first.actor.source_ip = Some(IpAddress::parse("0.0.0.0").unwrap());
    first.process = ProcessObservation {
        executable: Some("curl".into()),
        pid: Some("42".into()),
        unique_id: Some("0".into()),
        started_at: Some(at - Duration::minutes(1)),
        ..ProcessObservation::default()
    };
    let mut second = first.clone();
    second.observation_id = Uuid::now_v7();
    second.process.pid = Some("43".into());
    second.process.executable = Some("python3".into());
    store
        .record_identity_observations(&[first.clone(), second.clone()])
        .await
        .unwrap();
    let finding = store.record_usage(&usage(&first)).await.unwrap();
    store.record_usage(&usage(&second)).await.unwrap();
    let before: i64 = sqlx::query_scalar("SELECT usage_count FROM findings WHERE finding_id=$1")
        .bind(finding)
        .fetch_one(store.pool())
        .await
        .unwrap();
    // Emulate rows written by the old normalizer, then execute the actual upgrade SQL.
    sqlx::raw_sql(include_str!(
        "../../../migrations/postgres/0014_defender_placeholders.sql"
    ))
    .execute(store.pool())
    .await
    .unwrap();
    let facts:Vec<(String,serde_json::Value)>=sqlx::query_as("SELECT process_key,context FROM endpoint_process_facts WHERE connector_instance_id=$1 ORDER BY process_key").bind(connector).fetch_all(store.pool()).await.unwrap();
    assert_eq!(facts.len(), 2);
    assert!(facts[0].0.starts_with("pid:42:"));
    assert!(facts[1].0.starts_with("pid:43:"));
    assert!(
        facts
            .iter()
            .all(|(_, c)| c["process"]["unique_id"].is_null())
    );
    let activity = store
        .finding_activity(installation, finding, None, 10)
        .await
        .unwrap();
    assert_eq!(activity.len(), 2);
    assert!(
        activity
            .iter()
            .all(|a| a.process.unique_id.is_none() && a.actor.source_ip.is_none())
    );
    let raw:i64=sqlx::query_scalar("SELECT count(*) FROM finding_activity_revisions WHERE finding_id=$1 AND context#>>'{process,unique_id}'='0' AND context#>>'{actor,source_ip}'='0.0.0.0'").bind(finding).fetch_one(store.pool()).await.unwrap();
    assert_eq!(raw, 2);
    let zero_addresses:i64=sqlx::query_scalar("SELECT count(*) FROM identity_facts WHERE connector_instance_id=$1 AND attributes->'addresses' ? '0.0.0.0'").bind(connector).fetch_one(store.pool()).await.unwrap();
    assert_eq!(zero_addresses, 0);
    first.process.unique_id = None;
    first.actor.source_ip = None;
    store.record_usage(&usage(&first)).await.unwrap();
    let after: i64 = sqlx::query_scalar("SELECT usage_count FROM findings WHERE finding_id=$1")
        .bind(finding)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(before, after, "migration and replay must not add usage");
    // Existing scopes with a checked empty window report backlog, even without a source timestamp.
    let through = at - Duration::days(2);
    sqlx::query("UPDATE connector_states SET cursor_value=$2,health='healthy' WHERE connector_instance_id=$1").bind(connector).bind(format!("microsoft-defender-v1:{}",through.timestamp_millis())).execute(store.pool()).await.unwrap();
    let state = store
        .list_connector_states()
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.connector_instance_id == connector)
        .unwrap();
    assert_eq!(
        state.polled_through().unwrap().timestamp_millis(),
        through.timestamp_millis()
    );
    assert!(state.backlog_seconds(Utc::now()).unwrap() > 86_400);
    assert_eq!(state.health, tally_store_postgres::ConnectorHealth::Delayed);
    assert!(state.last_source_at.is_none());
    // A caught-up poll stays healthy while waiting for its normal next schedule.
    let last_poll = Utc::now() - Duration::minutes(5);
    sqlx::query("UPDATE connector_states SET cursor_value=$2,last_poll_at=$3 WHERE connector_instance_id=$1").bind(connector).bind(format!("microsoft-defender-v1:{}",(last_poll-Duration::minutes(5)).timestamp_millis())).bind(last_poll).execute(store.pool()).await.unwrap();
    let idle = store
        .list_connector_states()
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.connector_instance_id == connector)
        .unwrap();
    assert_eq!(idle.health, tally_store_postgres::ConnectorHealth::Healthy);
    assert!(idle.backlog_seconds(Utc::now()).unwrap() >= 300);
    // The replay receipt must accept the same seven-day bound as the preview, preserve usage,
    // and remain idempotent after the cursor reset.
    let job_id = Uuid::now_v7();
    store.put_connector_job(&tally_store_postgres::ConnectorJobSpec {
        job_id, connector_instance_id: connector,
        mode:tally_store_postgres::ConnectorJobMode::Scheduled,
        status:tally_store_postgres::ConnectorJobStatus::Paused,
        schedule_seconds:Some(300), next_run_at:None,
        config_refs:serde_json::json!({"kind":"microsoft_defender_graph_hunting_v1","source_lineage_id":"microsoft_defender:device_network_events","backfill_seconds":"3600","record_limit":"5000"}),
        credentials:None, updated_at:Utc::now(),
    }).await.unwrap();
    let preview = store
        .preview_connector_backfill(installation, job_id, 604_800)
        .await
        .unwrap();
    let request = tally_store_postgres::ConnectorBackfillCommit {
        installation_id: installation,
        job_id,
        lookback_seconds: 604_800,
        preview_digest: preview.preview_digest,
        request_sha256: "cd".repeat(32),
        idempotency_key: Uuid::now_v7(),
        committed_at: Utc::now(),
    };
    let receipt = store.commit_connector_backfill(&request).await.unwrap();
    assert!(!receipt.replayed);
    assert_eq!(receipt.receipt.lookback_seconds, 604_800);
    assert!(
        store
            .commit_connector_backfill(&request)
            .await
            .unwrap()
            .replayed
    );
    assert_eq!(
        store.connector_cursor(connector).await.unwrap().as_deref(),
        Some("")
    );
}
