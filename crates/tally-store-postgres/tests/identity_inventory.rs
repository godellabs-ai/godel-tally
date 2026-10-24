//! Run only against a fresh disposable database, never a customer installation.
use chrono::{Duration, Utc};
use tally_core::{
    ActivityAttribution, AgentObservation, ConnectorRef, DestinationObservation,
    DeviceIdentifierKind, DigestAlgorithm, EvidenceReceipt, Hostname, IdentityAuthority,
    IdentityObservation, IdentityRole, IdentitySubjectKind, InventoryIdentifier, Observation,
    ObservationKind, ProcessObservation,
};
use tally_store_postgres::{FindingEvidenceKind, ObservedUsage, PostgresStore};
use uuid::Uuid;

fn user(email: &str) -> IdentityObservation {
    IdentityObservation {
        subject_key: email.into(),
        email: Some(email.into()),
        source_subject: Some(email.into()),
        source_subject_kind: Some(IdentitySubjectKind::SourceUserId),
        authority: Some(IdentityAuthority::SourceNative),
        directory_key: None,
        application_key: None,
        display_label: None,
    }
}
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
#[ignore = "requires TALLY_DISPOSABLE_POSTGRES_URL pointing to a fresh database"]
#[allow(clippy::too_many_lines)] // One disposable database exercises the complete identity lifecycle.
async fn live_identity_inventory_activity_aliases_retirement_and_corrections() {
    let url = std::env::var("TALLY_DISPOSABLE_POSTGRES_URL").expect("disposable database URL");
    let store = PostgresStore::connect(&url).await.unwrap();
    store.migrate().await.unwrap();
    assert!(
        store.list_governance_findings(10).await.unwrap().is_empty(),
        "use a fresh database"
    );
    let installation = store
        .get_or_create_installation_identity()
        .await
        .unwrap()
        .installation_id;
    let source = Uuid::now_v7();
    let mdm = Uuid::now_v7();
    let mut descriptor = tally_connectors::microsoft_defender_edr_api_descriptor();
    descriptor.connector_type = "test_metadata_v1".into();
    store
        .register_connector(installation, source, &descriptor)
        .await
        .unwrap();
    store
        .register_connector(
            installation,
            mdm,
            &tally_connectors::MdmProvider::Intune.descriptor(),
        )
        .await
        .unwrap();
    let at = Utc::now() - Duration::minutes(10);
    let mut event = Observation::new(
        installation,
        at,
        ConnectorRef {
            instance_id: source,
            connector_type: "test_metadata_v1".into(),
            implementation_version: "test".into(),
            source_lineage_id: Some("source-a".into()),
        },
        ObservationKind::HttpMetadata,
        EvidenceReceipt::RecordDigest {
            algorithm: DigestAlgorithm::Sha256,
            digest: "a".repeat(64),
        },
    );
    event.actor.device_key = Some("source-device-a".into());
    event.actor.hostname = Some("laptop-a.example.test".into());
    event.actor.identity = Some(user("alice@example.test"));
    event.inventory.device_key_kind = Some(DeviceIdentifierKind::SourceNative);
    event.inventory.user_role = Some(IdentityRole::ProcessAccount);
    event.saas.tenant_key = Some("source-tenant-a".into());
    event.destination.host = Some(Hostname::parse("api.openai.com").unwrap());
    event.process = ProcessObservation {
        executable: Some("claude".into()),
        pid: Some("42".into()),
        unique_id: Some("native-process-1".into()),
        started_at: Some(at - Duration::minutes(1)),
        ..ProcessObservation::default()
    };
    event.agent.name = Some("Claude Code".into());
    event.service.declared_model_id = Some("gpt-4o".into());
    event.service.ai_request = true;
    store
        .record_identity_observations(&[event.clone()])
        .await
        .unwrap();
    let finding = store.record_usage(&usage(&event)).await.unwrap();
    store
        .record_identity_observations(&[event.clone()])
        .await
        .unwrap();
    store.record_usage(&usage(&event)).await.unwrap();
    assert_eq!(
        store.list_governance_findings(10).await.unwrap()[0].usage_count,
        1
    );
    let activities = store
        .finding_activity(installation, finding, None, 10)
        .await
        .unwrap();
    assert_eq!(activities.len(), 1);
    assert_eq!(
        activities[0]
            .actor
            .identity
            .as_ref()
            .unwrap()
            .email
            .as_deref(),
        Some("alice@example.test")
    );
    let mut revision = event.clone();
    revision.actor.hostname = Some("contradictory.example.test".into());
    revision.actor.request_client = Some(tally_core::RequestClientObservation {
        name: Some(tally_core::RequestClientKind::Curl),
        agent_id: None,
    });
    store.record_usage(&usage(&revision)).await.unwrap();
    let original = store
        .finding_activity(installation, finding, None, 10)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(original.actor.hostname, event.actor.hostname);
    assert!(original.actor.request_client.is_some());
    let (conflicts,):(i64,)=sqlx::query_as("SELECT count(*) FROM finding_activity_revisions WHERE finding_id=$1 AND conflicts<>'[]'::jsonb").bind(finding).fetch_one(store.pool()).await.unwrap();
    assert_eq!(conflicts, 1);
    assert_eq!(
        store.list_governance_findings(10).await.unwrap()[0].usage_count,
        1
    );
    let directory_device = Uuid::now_v7();
    let mut inventory = event.clone();
    inventory.observation_id = Uuid::now_v7();
    inventory.observed_at = at + Duration::minutes(1);
    inventory.kind = ObservationKind::NetworkMapping;
    inventory.process = ProcessObservation::default();
    inventory.agent = AgentObservation::default();
    inventory.actor.identity = None;
    inventory.service = tally_core::ServiceObservation::default();
    inventory.destination = DestinationObservation::default();
    inventory.inventory.directory_tenant_key = Some("directory-scope-a".into());
    inventory.inventory.identifiers = vec![InventoryIdentifier {
        kind: "entra_device_id".into(),
        value: directory_device.to_string(),
    }];
    store
        .record_identity_observations(&[inventory.clone()])
        .await
        .unwrap();
    let canonical = tally_store_postgres::identity::identity_ids(&inventory)
        .0
        .unwrap();
    let mut owner = inventory.clone();
    owner.connector.instance_id = mdm;
    owner.connector.connector_type = "intune_inventory_v1".into();
    owner.observation_id = Uuid::now_v7();
    owner.observed_at = at + Duration::minutes(2);
    owner.actor.device_key = Some("intune-native-device".into());
    owner.actor.identity = Some(user("owner@example.test"));
    owner.inventory.user_role = Some(IdentityRole::AssignedOwner);
    owner.inventory.snapshot_at = Some(owner.observed_at);
    owner.saas.tenant_key = Some("source-tenant-mdm".into());
    store
        .record_identity_observations(&[owner.clone()])
        .await
        .unwrap();
    // Full snapshots may contain multiple people in the same relationship role.
    // A refresh must keep both; a later replacement expires only absent members.
    for seconds in [15, 30] {
        let mut first = owner.clone();
        first.observation_id = Uuid::now_v7();
        first.observed_at = at + Duration::minutes(2) + Duration::seconds(seconds);
        first.inventory.snapshot_at = Some(first.observed_at);
        let mut second = first.clone();
        second.observation_id = Uuid::now_v7();
        second.actor.identity = Some(user("second-owner@example.test"));
        store
            .record_identity_observations(&[first, second])
            .await
            .unwrap();
    }
    let devices = store
        .identity_inventory(installation, "device", "laptop-a", Uuid::nil(), 50)
        .await
        .unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].entity_id, canonical);
    assert!(devices[0].facts.len() >= 3);
    let before = store
        .activity_identity_context(installation, &ActivityAttribution::from(&event))
        .await
        .unwrap();
    assert_ne!(before["device"]["device_id"], canonical.to_string());
    assert_eq!(before["related_users"], serde_json::json!([]));
    let mut partial = event.clone();
    partial.observation_id = Uuid::now_v7();
    partial.observed_at = at + Duration::minutes(3);
    partial.actor.identity = None;
    partial.process.executable = None;
    store
        .record_identity_observations(&[partial.clone()])
        .await
        .unwrap();
    store.record_usage(&usage(&partial)).await.unwrap();
    let context = store
        .activity_identity_context(installation, &ActivityAttribution::from(&partial))
        .await
        .unwrap();
    assert_eq!(context["device"]["device_id"], canonical.to_string());
    assert_eq!(context["request_actor_inferred"], false);
    assert_eq!(context["process"]["process"]["executable"], "claude");
    assert_eq!(context["related_users"][0]["role"], "assigned_owner");
    assert_eq!(
        context["related_users"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["user_id"].as_str().unwrap())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        2
    );
    assert!(partial.actor.identity.is_none());
    let mut reused = partial.clone();
    reused.process.unique_id = Some("different-native-process".into());
    assert!(
        store
            .activity_identity_context(installation, &ActivityAttribution::from(&reused))
            .await
            .unwrap()["process"]
            .is_null()
    );
    store
        .complete_inventory_snapshot(installation, mdm, at + Duration::minutes(4), &[])
        .await
        .unwrap();
    let mut later = partial.clone();
    later.observed_at = at + Duration::minutes(5);
    let context = store
        .activity_identity_context(installation, &ActivityAttribution::from(&later))
        .await
        .unwrap();
    assert_eq!(context["device"]["device_id"], canonical.to_string());
    assert_eq!(context["related_users"], serde_json::json!([]));
    let isolated = store
        .activity_identity_context(Uuid::now_v7(), &ActivityAttribution::from(&partial))
        .await
        .unwrap();
    assert!(isolated["device"]["device_id"].is_null());
    assert!(isolated["process"].is_null());
    let mut other = event.clone();
    other.observation_id = Uuid::now_v7();
    other.actor.device_key = Some("other-device".into());
    other.actor.hostname = Some("laptop-b.example.test".into());
    other.actor.identity = Some(user("bob@example.test"));
    store
        .record_identity_observations(&[other.clone()])
        .await
        .unwrap();
    let other_id = tally_store_postgres::identity::identity_ids(&other)
        .0
        .unwrap();
    let correction = store
        .correct_identity(
            installation,
            other_id,
            canonical,
            "Fixture operator verified a source alias",
        )
        .await
        .unwrap();
    assert!(
        store
            .correct_identity(installation, canonical, other_id, "cycle")
            .await
            .is_err()
    );
    assert!(
        store
            .undo_identity_correction(installation, correction)
            .await
            .unwrap()
    );
    assert!(
        !store
            .undo_identity_correction(installation, correction)
            .await
            .unwrap()
    );
    for _ in 0..10 {
        store.process_identity_replay().await.unwrap();
    }
    let status = store.identity_replay_status(installation).await.unwrap();
    assert_eq!(
        status["completed_generation"],
        status["requested_generation"]
    );
    let reconnected = PostgresStore::connect(&url).await.unwrap();
    assert_eq!(
        reconnected
            .finding_activity(installation, finding, None, 10)
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        reconnected.list_governance_findings(10).await.unwrap()[0].usage_count,
        2
    );
    assert!(
        !reconnected
            .identity_inventory(installation, "user", "alice", Uuid::nil(), 10)
            .await
            .unwrap()
            .is_empty()
    );
    let before_counts = store
        .identity_inventory_count(installation, None)
        .await
        .unwrap();
    store.delete_data(&["ai_logs".into()], None).await.unwrap();
    assert_eq!(
        store
            .identity_inventory_count(installation, None)
            .await
            .unwrap(),
        before_counts
    );
    assert_eq!(
        store
            .finding_activity(installation, finding, None, 10)
            .await
            .unwrap(),
        Vec::<ActivityAttribution>::new()
    );
}
