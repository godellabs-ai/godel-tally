//! PostgreSQL-backed durable state for the AI registry, findings, connectors, scans, and audit.

mod activity;
mod event_authorization;
pub mod identity;
pub use event_authorization::{EventFindingContext, EventRegistryEntity};

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool, postgres::PgPoolOptions};
use tally_connectors::{BatchReceipt, ConnectorDescriptor, ConnectorTransport};
use tally_core::{
    AiSystemView, AttributionConflict, AttributionConflictStatus, AttributionContractError,
    AttributionReplayCheckpoint, AuthorizationStatus, Claim, Entity, EntityKey, EntityKind,
    EntityRelationship, RelationshipEvidence, RelationshipStatus, RequestClientKind,
    RequestClientObservation, RiskSeverity,
};
use tally_resolve::{
    CloudUsageConflictInput, CloudUsageProjectionInput, ResolvedCloudUsage, ResolvedSystem,
    UsageEvidenceInput,
};
use tally_risk::{EvaluatedFinding, RiskFactor};
use thiserror::Error;
use url::Url;
use utoipa::ToSchema;
use uuid::Uuid;

tokio::task_local! {
    static AUDIT_ACTOR: String;
}

/// Runs `future` with `actor` recorded on every audit event it writes.
pub async fn with_audit_actor<F: std::future::Future>(actor: String, future: F) -> F::Output {
    AUDIT_ACTOR.scope(actor, future).await
}

/// The signed-in user behind the current request, or `local_operator` for work that no
/// user started, such as scheduled connector runs or embedded hosts without an identity.
#[must_use]
pub fn audit_actor() -> String {
    AUDIT_ACTOR
        .try_with(Clone::clone)
        .unwrap_or_else(|_| "local_operator".to_owned())
}

const GOVERNANCE_FINDINGS_SQL: &str = r"
            SELECT jsonb_build_object(
                'finding_id', f.finding_id,
                'evidence_kind', f.evidence_kind,
                'status', CASE
                    WHEN p.sanctioned = FALSE OR m.sanctioned = FALSE THEN 'unsanctioned'
                    WHEN p.sanctioned IS NULL OR (f.model_id IS NOT NULL AND m.sanctioned IS NULL)
                        THEN 'authorization_queue'
                    ELSE 'sanctioned'
                END,
                'violation_reasons', ARRAY_REMOVE(ARRAY[
                    CASE WHEN p.sanctioned = FALSE THEN 'provider_unsanctioned' END,
                    CASE WHEN m.sanctioned = FALSE THEN 'model_unsanctioned' END
                ], NULL),
                'provider', jsonb_build_object(
                    'provider_id', p.provider_id, 'key', p.key, 'name', p.name,
                    'category', p.category, 'country_code', p.country_code,
                    'catalog', p.catalog, 'sanctioned', p.sanctioned,
                    'model_count', (SELECT count(*) FROM ai_provider_models pm WHERE pm.provider_id = p.provider_id),
                    'finding_count', (SELECT count(*) FROM findings pf WHERE pf.provider_id = p.provider_id),
                    'last_used_at', (SELECT max(pf.last_used_at) FROM findings pf WHERE pf.provider_id = p.provider_id)
                ),
                'model', CASE WHEN m.model_id IS NULL THEN NULL ELSE jsonb_build_object(
                    'model_id', m.model_id, 'key', m.key, 'name', m.name,
                    'family', m.family, 'country_code', m.country_code,
                    'modalities', m.modalities, 'capabilities', m.capabilities,
                    'catalog', m.catalog, 'sanctioned', m.sanctioned,
                    'provider_ids', COALESCE((SELECT jsonb_agg(pm.provider_id ORDER BY pm.provider_id) FROM ai_provider_models pm WHERE pm.model_id = m.model_id), '[]'),
                    'provider_names', COALESCE((SELECT jsonb_agg(p2.name ORDER BY p2.name) FROM ai_provider_models pm JOIN ai_providers p2 ON p2.provider_id = pm.provider_id WHERE pm.model_id = m.model_id), '[]'),
                    'finding_count', (SELECT count(*) FROM findings mf WHERE mf.model_id = m.model_id),
                    'last_used_at', (SELECT max(mf.last_used_at) FROM findings mf WHERE mf.model_id = m.model_id)
                ) END,
                'model_version', f.model_version,
                'first_used_at', f.first_used_at,
                'last_used_at', f.last_used_at,
                'usage_count', f.usage_count,
                'endpoints', COALESCE((
                    SELECT jsonb_agg(jsonb_build_object(
                        'endpoint_host_id', h.endpoint_host_id, 'kind', h.kind, 'value', h.value,
                        'role', fh.role, 'port', NULLIF(fh.port, 0),
                        'first_seen', fh.first_seen, 'last_seen', fh.last_seen
                    ) ORDER BY fh.role, h.value, fh.port)
                    FROM finding_hosts fh JOIN endpoint_hosts h USING (endpoint_host_id)
                    WHERE fh.finding_id = f.finding_id
                ), '[]'),
                'destinations', COALESCE((
                    SELECT jsonb_agg(jsonb_build_object(
                        'destination_host_id', d.destination_host_id,
                        'kind', d.kind, 'value', d.value,
                        'port', NULLIF(fd.port, 0),
                        'first_seen', fd.first_seen, 'last_seen', fd.last_seen
                    ) ORDER BY d.value, fd.port)
                    FROM finding_destinations fd
                    JOIN destination_hosts d USING (destination_host_id)
                    WHERE fd.finding_id = f.finding_id
                ), '[]'),
                'users', COALESCE((
                    SELECT jsonb_agg(jsonb_build_object(
                        'endpoint_user_id', u.endpoint_user_id, 'kind', u.kind,
                        'value', u.value, 'email', u.email,
                        'first_seen', fu.first_seen, 'last_seen', fu.last_seen
                    ) ORDER BY u.kind, u.value)
                    FROM finding_users fu JOIN endpoint_users u USING (endpoint_user_id)
                    WHERE fu.finding_id = f.finding_id
                ), '[]'),
                'connectors', COALESCE((
                    SELECT jsonb_agg(jsonb_build_object(
                        'connector_instance_id', c.connector_instance_id,
                        'name', COALESCE(NULLIF(c.friendly_name, ''), c.display_name),
                        'connector_type', c.connector_type,
                        'first_seen', fc.first_seen, 'last_seen', fc.last_seen
                    ) ORDER BY COALESCE(NULLIF(c.friendly_name, ''), c.display_name), c.connector_instance_id)
                    FROM finding_connectors fc JOIN connector_states c USING (connector_instance_id)
                    WHERE fc.finding_id = f.finding_id
                ), '[]'),
                'clients', COALESCE((
                    SELECT jsonb_agg(jsonb_build_object(
                        'name', NULLIF(cl.client_name, ''), 'agent_id', NULLIF(cl.agent_id, ''),
                        'connector_instance_id', cl.connector_instance_id,
                        'first_seen', cl.first_seen, 'last_seen', cl.last_seen
                    ) ORDER BY cl.client_name, cl.agent_id, cl.connector_instance_id)
                    FROM finding_clients cl WHERE cl.finding_id = f.finding_id
                ), '[]'),
                'workloads', COALESCE((
                    SELECT jsonb_agg(jsonb_build_object(
                        'namespace_name', fw.namespace_name,
                        'workload_name', fw.workload_name,
                        'workload_kind', fw.workload_kind,
                        'runtime_image', NULLIF(fw.runtime_image, ''),
                        'first_seen', fw.first_seen,
                        'last_seen', fw.last_seen
                    ) ORDER BY fw.namespace_name, fw.workload_name, fw.workload_kind, fw.runtime_image)
                    FROM finding_workloads fw
                    WHERE fw.finding_id = f.finding_id
                ), '[]')
            )
            FROM findings f
            JOIN ai_providers p ON p.provider_id = f.provider_id
            LEFT JOIN ai_models m ON m.model_id = f.model_id
            ORDER BY
                CASE WHEN p.sanctioned = FALSE OR m.sanctioned = FALSE THEN 0
                     WHEN p.sanctioned IS NULL OR (f.model_id IS NOT NULL AND m.sanctioned IS NULL) THEN 1
                     ELSE 2 END,
                f.last_used_at DESC, f.finding_id
            LIMIT $1
            ";

// Keep the migration bundle embedded so a native binary can upgrade an existing data service.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations/postgres");

/// Latest `PostgreSQL` schema version understood by this Tally binary.
pub const POSTGRES_MIGRATION_HEAD: i64 = 14;

const RELATIONSHIP_JSON_SELECT: &str = r"
    SELECT jsonb_build_object(
        'relationship_id', r.relationship_id,
        'installation_id', r.installation_id,
        'subject', jsonb_build_object('entity_id', r.subject_entity_id, 'kind', se.kind),
        'predicate', r.predicate,
        'object', jsonb_build_object('entity_id', r.object_entity_id, 'kind', oe.kind),
        'confidence', r.confidence_bps,
        'status', r.status,
        'valid_from', r.valid_from,
        'valid_until', r.valid_until,
        'rule', r.rule,
        'independent_lineage_count', r.independent_lineage_count,
        'created_at', r.created_at,
        'revision', r.revision
    )
    FROM entity_relationships r
    JOIN entities se ON se.entity_id = r.subject_entity_id
    JOIN entities oe ON oe.entity_id = r.object_entity_id
    WHERE r.installation_id = $1 AND r.relationship_id = $2
";

const ENTITY_RESOLUTION_STATE_SQL: &str = r"
    SELECT jsonb_build_object(
        'source', (
            SELECT jsonb_build_object(
                'entity_id', e.entity_id, 'kind', e.kind, 'display_name', e.display_name,
                'created_at', e.created_at, 'revision', e.revision
            )
            FROM entities e
            WHERE e.entity_id = $2
              AND (
                EXISTS (
                    SELECT 1 FROM entity_keys k
                    WHERE k.installation_id = $1 AND k.entity_id = e.entity_id
                )
                OR EXISTS (
                    SELECT 1 FROM entity_relationships r
                    WHERE r.installation_id = $1
                      AND (r.subject_entity_id = e.entity_id OR r.object_entity_id = e.entity_id)
                )
                OR EXISTS (
                    SELECT 1 FROM ai_system_views v
                    WHERE v.installation_id = $1 AND v.system_id = e.entity_id
                )
              )
        ),
        'target', (
            SELECT jsonb_build_object(
                'entity_id', e.entity_id, 'kind', e.kind, 'display_name', e.display_name,
                'created_at', e.created_at, 'revision', e.revision
            )
            FROM entities e
            WHERE e.entity_id = $3
              AND (
                EXISTS (
                    SELECT 1 FROM entity_keys k
                    WHERE k.installation_id = $1 AND k.entity_id = e.entity_id
                )
                OR EXISTS (
                    SELECT 1 FROM entity_relationships r
                    WHERE r.installation_id = $1
                      AND (r.subject_entity_id = e.entity_id OR r.object_entity_id = e.entity_id)
                )
                OR EXISTS (
                    SELECT 1 FROM ai_system_views v
                    WHERE v.installation_id = $1 AND v.system_id = e.entity_id
                )
              )
        ),
        'source_is_alias', EXISTS (
            SELECT 1 FROM entity_resolution_aliases
            WHERE installation_id = $1 AND alias_entity_id = $2 AND active
        ),
        'source_has_aliases', EXISTS (
            SELECT 1 FROM entity_resolution_aliases
            WHERE installation_id = $1 AND canonical_entity_id = $2 AND active
        ),
        'target_is_alias', EXISTS (
            SELECT 1 FROM entity_resolution_aliases
            WHERE installation_id = $1 AND alias_entity_id = $3 AND active
        ),
        'active_merge_event_id', (
            SELECT merge_event_id FROM entity_resolution_aliases
            WHERE installation_id = $1 AND alias_entity_id = $2
              AND canonical_entity_id = $3 AND active
        ),
        'impact', jsonb_build_object(
            'key_count', (
                SELECT count(*) FROM entity_keys
                WHERE installation_id = $1 AND entity_id = $2
            ),
            'claim_count', (
                SELECT count(*) FROM claims WHERE subject_entity_id = $2
            ),
            'relationship_count', (
                SELECT count(*) FROM entity_relationships
                WHERE installation_id = $1
                  AND (subject_entity_id = $2 OR object_entity_id = $2)
            ),
            'finding_count', (
                SELECT count(*) FROM findings WHERE system_id = $2
            )
        )
    )
";

#[derive(Debug, Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuitySetDigest {
    pub count: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostgresContinuitySnapshot {
    pub migration_head: i64,
    pub sets: BTreeMap<String, ContinuitySetDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudUsageProjectionScan {
    pub projections: Vec<CloudUsageProjectionInput>,
    pub conflicts: Vec<CloudUsageConflictInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphRelationshipView {
    pub relationship: EntityRelationship,
    pub evidence_count: u32,
}

#[derive(Debug, Deserialize)]
struct CanonicalGraphRelationshipRow {
    relationship: EntityRelationship,
    evidence_observation_ids: Vec<Uuid>,
    source_lineage_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityResolutionOperation {
    Merge,
    Split,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityResolutionImpact {
    pub key_count: u64,
    pub claim_count: u64,
    pub relationship_count: u64,
    pub finding_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityResolutionPreviewData {
    pub operation: EntityResolutionOperation,
    pub source: Entity,
    pub target: Entity,
    pub merge_event_id: Option<Uuid>,
    pub impact: EntityResolutionImpact,
    pub preview_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityResolutionCommit {
    pub installation_id: Uuid,
    pub operation: EntityResolutionOperation,
    pub source_entity_id: Uuid,
    pub target_entity_id: Uuid,
    pub source_revision: i64,
    pub target_revision: i64,
    pub merge_event_id: Option<Uuid>,
    pub preview_digest: String,
    pub request_sha256: String,
    pub idempotency_key: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityResolutionEventView {
    pub event_id: Uuid,
    pub installation_id: Uuid,
    pub operation: EntityResolutionOperation,
    pub source_entity_id: Uuid,
    pub target_entity_id: Uuid,
    pub source_display_name: String,
    pub target_display_name: String,
    pub merge_event_id: Option<Uuid>,
    pub source_revision: i64,
    pub target_revision: i64,
    pub source_current_revision: i64,
    pub target_current_revision: i64,
    pub active: bool,
    pub preview_digest: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub content_retained: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityResolutionWrite {
    pub event: EntityResolutionEventView,
    pub replayed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorBackfillSourceKind {
    NextdnsApi,
    CloudFlowApi,
    MicrosoftDefenderApi,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorBackfillPreview {
    pub job_id: Uuid,
    pub connector_instance_id: Uuid,
    pub source_kind: ConnectorBackfillSourceKind,
    pub job_status: ConnectorJobStatus,
    pub lookback_seconds: u32,
    pub minimum_lookback_seconds: u32,
    pub maximum_lookback_seconds: u32,
    pub cursor_present: bool,
    pub job_updated_at: DateTime<Utc>,
    pub preview_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorBackfillCommit {
    pub installation_id: Uuid,
    pub job_id: Uuid,
    pub lookback_seconds: u32,
    pub preview_digest: String,
    pub request_sha256: String,
    pub idempotency_key: Uuid,
    pub committed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorBackfillReceipt {
    pub request_id: Uuid,
    pub job_id: Uuid,
    pub connector_instance_id: Uuid,
    pub source_kind: ConnectorBackfillSourceKind,
    pub job_status: ConnectorJobStatus,
    pub lookback_seconds: u32,
    pub cursor_was_present: bool,
    pub scheduled_now: bool,
    pub preview_digest: String,
    pub committed_at: DateTime<Utc>,
    pub content_retained: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorBackfillWrite {
    pub receipt: ConnectorBackfillReceipt,
    pub replayed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorBackfillCapability {
    pub source_kind: ConnectorBackfillSourceKind,
    pub minimum_lookback_seconds: u32,
    pub maximum_lookback_seconds: u32,
}

#[derive(Debug, Deserialize)]
struct ConnectorBackfillState {
    installation_id: Uuid,
    job: ConnectorJobView,
    cursor_present: bool,
}

#[derive(Debug, Deserialize)]
struct EntityResolutionState {
    source: Option<Entity>,
    target: Option<Entity>,
    source_is_alias: bool,
    source_has_aliases: bool,
    target_is_alias: bool,
    active_merge_event_id: Option<Uuid>,
    impact: EntityResolutionImpact,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct CloudUsagePathRow {
    installation_id: Uuid,
    source_asset_id: Uuid,
    destination_asset_id: Uuid,
    flow_relationship_id: Uuid,
    flow_observation_id: Uuid,
    flow_lineage_id: String,
    flow_valid_from: DateTime<Utc>,
    flow_valid_until: DateTime<Utc>,
    mapping_relationship_id: Uuid,
    mapped_resource_id: Uuid,
    mapping_observation_id: Uuid,
    mapping_lineage_id: String,
    mapping_valid_from: DateTime<Utc>,
    mapping_valid_until: Option<DateTime<Utc>>,
    mapping_count: i64,
    serves_relationship_id: Option<Uuid>,
    system_id: Option<Uuid>,
    inventory_observation_id: Option<Uuid>,
    inventory_lineage_id: Option<String>,
    inventory_valid_from: Option<DateTime<Utc>>,
    inventory_valid_until: Option<DateTime<Utc>>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct InstallationIdentity {
    pub installation_id: Uuid,
    pseudonymization_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredRegistryOverlay {
    pub overlay_id: String,
    pub installation_id: Uuid,
    pub overlay: serde_json::Value,
    pub overlay_sha256: String,
    pub entry_count: i32,
    pub matcher_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub content_retained: bool,
}

impl StoredRegistryOverlay {
    pub fn digest_matches(&self) -> bool {
        serde_json::to_vec(&self.overlay)
            .is_ok_and(|bytes| hex::encode(Sha256::digest(bytes)) == self.overlay_sha256)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RegistryOverlayCreate {
    pub overlay_id: String,
    pub installation_id: Uuid,
    pub overlay: serde_json::Value,
    pub overlay_sha256: String,
    pub request_sha256: String,
    pub entry_count: i32,
    pub matcher_count: i32,
    pub idempotency_key: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RegistryOverlayWrite {
    pub overlay: StoredRegistryOverlay,
    pub replayed: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClassificationRuleSetCreate {
    pub rule_set_id: Uuid,
    pub idempotency_key: Uuid,
    pub installation_id: Uuid,
    pub request_sha256: String,
    pub preview_digest: String,
    pub decision: String,
    pub rules: serde_json::Value,
    pub rules_sha256: String,
    pub matched_systems: Vec<ClassificationSystemExpectation>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassificationSystemExpectation {
    pub system_id: Uuid,
    pub authorization_status: String,
    pub revision: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassificationRuleSetView {
    pub rule_set_id: Uuid,
    pub installation_id: Uuid,
    pub preview_digest: String,
    pub decision: String,
    pub rules: serde_json::Value,
    pub rules_sha256: String,
    pub matched_system_ids: Vec<Uuid>,
    pub changed_system_ids: Vec<Uuid>,
    pub matched_system_count: i32,
    pub changed_system_count: i32,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub active: bool,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub deactivated_by: Option<String>,
    pub content_retained: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClassificationRuleSetWrite {
    pub rule_set: ClassificationRuleSetView,
    pub replayed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassificationApplyOutcome {
    Applied,
    Unchanged,
    Conflict,
}

impl std::fmt::Debug for InstallationIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstallationIdentity")
            .field("installation_id", &self.installation_id)
            .field("pseudonymization_key", &"[REDACTED]")
            .finish()
    }
}

impl InstallationIdentity {
    pub const fn pseudonymization_key(&self) -> &[u8; 32] {
        &self.pseudonymization_key
    }
}

impl PostgresStore {
    /// Reuses a host application's existing `PostgreSQL` pool.
    ///
    /// Tally owns its tables and migration definitions, while an embedding product can share the
    /// same database and connection budget instead of opening a second pool.
    #[must_use]
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Opens the `PostgreSQL` connection pool.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the database cannot be reached or authenticated.
    pub async fn connect(url: &str) -> Result<Self, PostgresStoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(url)
            .await?;
        Ok(Self { pool })
    }

    /// Applies embedded `PostgreSQL` migrations.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when a migration cannot be applied.
    pub async fn migrate(&self) -> Result<(), PostgresStoreError> {
        self.restore_archived_upgrade_migrations().await?;
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    async fn restore_archived_upgrade_migrations(&self) -> Result<(), PostgresStoreError> {
        let archive_exists = sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass('tally_upgrade_newer_migrations') IS NOT NULL",
        )
        .fetch_one(&self.pool)
        .await?;
        if !archive_exists {
            return Ok(());
        }

        // An upgrade to an older host archives unsupported migration entries,
        // retaining their schema and data. When a later host supports them,
        // restore their original checksums so SQLx validates rather than replays
        // already-applied SQL. Keep the archive as a record of the import.
        let mut transaction = self.pool.begin().await?;
        sqlx::query("LOCK TABLE _sqlx_migrations IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *transaction)
            .await?;
        for migration in MIGRATOR.iter() {
            sqlx::query(
                "INSERT INTO _sqlx_migrations SELECT * FROM tally_upgrade_newer_migrations
                 WHERE version = $1 AND success ON CONFLICT (version) DO NOTHING",
            )
            .bind(migration.version)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Verifies that `PostgreSQL` accepts a trivial query.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the service is unavailable.
    pub async fn ping(&self) -> Result<(), PostgresStoreError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    /// Returns the highest successfully applied `PostgreSQL` migration without changing schema.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the migration ledger cannot be queried.
    pub async fn migration_head(&self) -> Result<i64, PostgresStoreError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(max(version), 0)::bigint FROM _sqlx_migrations WHERE success",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Computes content-free continuity digests from one repeatable-read database snapshot.
    ///
    /// Raw entity keys, connector cursors, names, claim values, and audit details are hashed only
    /// in memory and never returned by this method.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the snapshot cannot be read or committed.
    #[allow(clippy::too_many_lines)] // The audited SQL set inventory is intentionally explicit.
    pub async fn continuity_snapshot(
        &self,
        installation_id: Uuid,
    ) -> Result<PostgresContinuitySnapshot, PostgresStoreError> {
        const SET_QUERIES: &[(&str, &str)] = &[
            (
                "entities",
                r"
                SELECT jsonb_build_array(e.entity_id, e.kind, e.display_name, e.created_at, e.revision)::text
                FROM entities e
                WHERE e.entity_id IN (
                    SELECT entity_id FROM entity_keys WHERE installation_id = $1
                    UNION SELECT system_id FROM ai_system_views WHERE installation_id = $1
                    UNION SELECT subject_entity_id FROM entity_relationships WHERE installation_id = $1
                    UNION SELECT object_entity_id FROM entity_relationships WHERE installation_id = $1
                )
                ORDER BY e.entity_id
                ",
            ),
            (
                "entity_keys",
                r"
                SELECT jsonb_build_array(
                    key_type, key_value, entity_id, first_seen, last_seen, source_authority,
                    strength_bps, status, source_observation_id, source_lineage_id, revision
                )::text
                FROM entity_keys WHERE installation_id = $1
                ORDER BY key_type, key_value, entity_id
                ",
            ),
            (
                "systems",
                r"
                SELECT jsonb_build_array(
                    system_id, registry_entry_id, display_name, surface, lifecycle,
                    authorization_status, first_seen, last_seen, evidence_quality,
                    confidence_bps, revision
                )::text
                FROM ai_system_views WHERE installation_id = $1
                ORDER BY system_id
                ",
            ),
            (
                "claims",
                r"
                SELECT jsonb_build_array(
                    c.claim_id, c.subject_entity_id, c.predicate, c.value, c.class,
                    c.confidence_bps, c.status, c.valid_from, c.valid_until, c.rule,
                    c.registry_version, c.created_at
                )::text
                FROM claims c
                WHERE c.subject_entity_id IN (
                    SELECT entity_id FROM entity_keys WHERE installation_id = $1
                    UNION SELECT system_id FROM ai_system_views WHERE installation_id = $1
                )
                ORDER BY c.claim_id
                ",
            ),
            (
                "claim_evidence",
                r"
                SELECT jsonb_build_array(ce.claim_id, ce.observation_id, ce.support_role)::text
                FROM claim_evidence ce
                JOIN claims c ON c.claim_id = ce.claim_id
                WHERE c.subject_entity_id IN (
                    SELECT entity_id FROM entity_keys WHERE installation_id = $1
                    UNION SELECT system_id FROM ai_system_views WHERE installation_id = $1
                )
                ORDER BY ce.claim_id, ce.observation_id
                ",
            ),
            (
                "relationships",
                r"
                SELECT jsonb_build_array(
                    relationship_id, subject_entity_id, predicate, object_entity_id,
                    confidence_bps, status, valid_from, valid_until, rule,
                    independent_lineage_count, created_at, revision
                )::text
                FROM entity_relationships WHERE installation_id = $1
                ORDER BY relationship_id
                ",
            ),
            (
                "relationship_evidence",
                r"
                SELECT jsonb_build_array(
                    re.relationship_id, re.observation_id, re.source_lineage_id,
                    re.support_role, re.valid_from, re.valid_until
                )::text
                FROM relationship_evidence re
                JOIN entity_relationships r ON r.relationship_id = re.relationship_id
                WHERE r.installation_id = $1
                ORDER BY re.relationship_id, re.observation_id
                ",
            ),
            (
                "findings",
                r"
                SELECT jsonb_build_array(
                    f.finding_id, f.system_id, f.policy_id, f.policy_version, f.title,
                    f.severity, f.status, f.factor_codes, f.factors, f.system_revision,
                    f.evidence_source_count, f.first_evaluated_at, f.last_evaluated_at
                )::text
                FROM findings f
                JOIN ai_system_views v ON v.system_id = f.system_id
                WHERE v.installation_id = $1
                ORDER BY f.finding_id
                ",
            ),
            (
                "connector_cursors",
                r"
                SELECT jsonb_build_array(
                    connector_instance_id, connector_type, implementation_version, cursor_value,
                    health, last_batch_id, last_success_at, last_error_code, updated_at
                )::text
                FROM connector_states WHERE installation_id = $1
                ORDER BY connector_instance_id
                ",
            ),
            (
                "resolution_history",
                r"
                SELECT row_value FROM (
                    SELECT 'event:' || event_id::text AS row_key, jsonb_build_array(
                        'event', event_id, operation, source_entity_id, target_entity_id,
                        merge_event_id, source_revision, target_revision, preview_digest,
                        created_at, created_by, content_retained
                    )::text AS row_value
                    FROM entity_resolution_events WHERE installation_id = $1
                    UNION ALL
                    SELECT 'alias:' || alias_entity_id::text AS row_key, jsonb_build_array(
                        'alias', alias_entity_id, canonical_entity_id, merge_event_id, active,
                        created_at, retired_at, retired_by_event_id
                    )::text AS row_value
                    FROM entity_resolution_aliases WHERE installation_id = $1
                ) rows ORDER BY row_key
                ",
            ),
            (
                "purge_receipts",
                r"
                SELECT jsonb_build_array(
                    purge_id, preview_digest, requested_counts, deleted_counts, status,
                    failure_code, requested_at, completed_at, requested_by, content_retained
                )::text
                FROM purge_receipts WHERE installation_id = $1
                ORDER BY purge_id
                ",
            ),
            (
                "estate_reviews",
                "SELECT jsonb_build_array(entity_id,sanctioned,flagged,updated_at)::text FROM tally_estate_reviews WHERE installation_id=$1 ORDER BY entity_id",
            ),
            (
                "audit_records",
                r"
                SELECT jsonb_build_array(
                    audit_id, at, actor, action, entity_type, entity_id, detail
                )::text
                FROM audit_log WHERE $1::uuid IS NOT NULL
                ORDER BY audit_id
                ",
            ),
        ];

        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *transaction)
            .await?;
        let migration_head = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(max(version), 0)::bigint FROM _sqlx_migrations WHERE success",
        )
        .fetch_one(&mut *transaction)
        .await?;
        let mut sets = BTreeMap::new();
        for (name, query) in SET_QUERIES {
            let rows = sqlx::query_scalar::<_, String>(*query)
                .bind(installation_id)
                .fetch_all(&mut *transaction)
                .await?;
            sets.insert((*name).to_owned(), continuity_set_digest(rows));
        }
        transaction.commit().await?;
        Ok(PostgresContinuitySnapshot {
            migration_head,
            sets,
        })
    }

    /// Loads or creates the single-organization installation identity and pseudonymization key.
    ///
    /// The key never leaves the store/runtime boundary and is redacted from `Debug` output.
    /// Existing non-nil connector state is adopted so upgrades preserve the current estate.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when secure randomness or the transaction fails.
    pub async fn get_or_create_installation_identity(
        &self,
    ) -> Result<InstallationIdentity, PostgresStoreError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('godel-tally-installation-identity'))")
            .execute(&mut *transaction)
            .await?;
        let existing = sqlx::query_as::<_, (Uuid, Vec<u8>)>(
            "SELECT installation_id, pseudonymization_key FROM installation_secrets WHERE singleton = TRUE",
        )
        .fetch_optional(&mut *transaction)
        .await?;
        let (installation_id, key) = if let Some(existing) = existing {
            existing
        } else {
            let installation_id = sqlx::query_scalar::<_, Uuid>(
                r"
                SELECT installation_id
                FROM connector_states
                WHERE installation_id <> '00000000-0000-0000-0000-000000000000'::uuid
                GROUP BY installation_id
                ORDER BY count(*) DESC, installation_id
                LIMIT 1
                ",
            )
            .fetch_optional(&mut *transaction)
            .await?
            .unwrap_or_else(Uuid::now_v7);
            let mut key = [0_u8; 32];
            getrandom::fill(&mut key)
                .map_err(|error| PostgresStoreError::Entropy(error.to_string()))?;
            sqlx::query(
                "INSERT INTO installations (installation_id, name) VALUES ($1, 'Gödel Tally') ON CONFLICT (installation_id) DO NOTHING",
            )
            .bind(installation_id)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "INSERT INTO installation_secrets (singleton, installation_id, pseudonymization_key) VALUES (TRUE, $1, $2)",
            )
            .bind(installation_id)
            .bind(key.as_slice())
            .execute(&mut *transaction)
            .await?;
            (installation_id, key.to_vec())
        };
        transaction.commit().await?;
        let pseudonymization_key: [u8; 32] = key
            .try_into()
            .map_err(|_| PostgresStoreError::InvalidInstallationKey)?;
        Ok(InstallationIdentity {
            installation_id,
            pseudonymization_key,
        })
    }

    /// Lists active installation-local registry overlays in deterministic order.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when a stored overlay cannot be read or decoded.
    pub async fn list_registry_overlays(
        &self,
        installation_id: Uuid,
    ) -> Result<Vec<StoredRegistryOverlay>, PostgresStoreError> {
        let values = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT jsonb_build_object(
                'overlay_id', overlay_id,
                'installation_id', installation_id,
                'overlay', overlay,
                'overlay_sha256', overlay_sha256,
                'entry_count', entry_count,
                'matcher_count', matcher_count,
                'created_at', created_at,
                'updated_at', updated_at,
                'content_retained', content_retained
            )
            FROM local_registry_overlays
            WHERE installation_id = $1
            ORDER BY created_at, overlay_id
            ",
        )
        .bind(installation_id)
        .fetch_all(&self.pool)
        .await?;
        values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Creates one immutable local registry overlay with idempotency and content-free audit.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the overlay contract is unsafe, its identifier already
    /// exists, an idempotency key conflicts, or persistence fails.
    pub async fn create_registry_overlay(
        &self,
        request: &RegistryOverlayCreate,
    ) -> Result<RegistryOverlayWrite, PostgresStoreError> {
        validate_registry_overlay_create(request)?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('godel-tally-registry-overlays'))")
            .execute(&mut *transaction)
            .await?;
        if let Some((digest, response)) =
            sqlx::query_as::<_, (String, serde_json::Value)>(
                "SELECT request_sha256, response FROM local_registry_mutations WHERE idempotency_key = $1",
            )
            .bind(request.idempotency_key)
            .fetch_optional(&mut *transaction)
            .await?
        {
            if digest != request.request_sha256 {
                return Err(PostgresStoreError::IdempotencyConflict);
            }
            transaction.rollback().await?;
            return Ok(RegistryOverlayWrite {
                overlay: serde_json::from_value(response)?,
                replayed: true,
            });
        }
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM local_registry_overlays WHERE overlay_id = $1)",
        )
        .bind(&request.overlay_id)
        .fetch_one(&mut *transaction)
        .await?;
        if exists {
            return Err(PostgresStoreError::RegistryOverlayExists);
        }
        sqlx::query(
            r"
            INSERT INTO local_registry_overlays (
                overlay_id, installation_id, overlay, overlay_sha256, entry_count,
                matcher_count, created_at, updated_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
            ",
        )
        .bind(&request.overlay_id)
        .bind(request.installation_id)
        .bind(&request.overlay)
        .bind(&request.overlay_sha256)
        .bind(request.entry_count)
        .bind(request.matcher_count)
        .bind(request.created_at)
        .execute(&mut *transaction)
        .await?;
        let overlay = StoredRegistryOverlay {
            overlay_id: request.overlay_id.clone(),
            installation_id: request.installation_id,
            overlay: request.overlay.clone(),
            overlay_sha256: request.overlay_sha256.clone(),
            entry_count: request.entry_count,
            matcher_count: request.matcher_count,
            created_at: request.created_at,
            updated_at: request.created_at,
            content_retained: false,
        };
        let response = serde_json::to_value(&overlay)?;
        sqlx::query(
            r"
            INSERT INTO local_registry_mutations (
                idempotency_key, installation_id, overlay_id, request_sha256, response, created_at
            ) VALUES ($1,$2,$3,$4,$5,$6)
            ",
        )
        .bind(request.idempotency_key)
        .bind(request.installation_id)
        .bind(&request.overlay_id)
        .bind(&request.request_sha256)
        .bind(&response)
        .bind(request.created_at)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO audit_log (audit_id, at, actor, action, entity_type, entity_id, detail)
            VALUES ($1,$2,$5,'registry.overlay.created','registry_overlay',$3,$4)
            ",
        )
        .bind(Uuid::now_v7())
        .bind(request.created_at)
        .bind(&request.overlay_id)
        .bind(serde_json::json!({
            "overlay_sha256": request.overlay_sha256,
            "entry_count": request.entry_count,
            "matcher_count": request.matcher_count,
            "content_retained": false,
        }))
        .bind(audit_actor())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(RegistryOverlayWrite {
            overlay,
            replayed: false,
        })
    }

    /// Lists immutable local host-classification rule sets newest first.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when durable rule sets cannot be read or decoded.
    pub async fn list_classification_rule_sets(
        &self,
        installation_id: Uuid,
        limit: u16,
    ) -> Result<Vec<ClassificationRuleSetView>, PostgresStoreError> {
        let values = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT to_jsonb(s) - 'idempotency_key' - 'request_sha256'
                - 'deactivation_idempotency_key' - 'deactivation_request_sha256'
            FROM classification_rule_sets s
            WHERE installation_id = $1
            ORDER BY created_at DESC, rule_set_id DESC
            LIMIT $2
            ",
        )
        .bind(installation_id)
        .bind(i64::from(limit.clamp(1, 1_000)))
        .fetch_all(&self.pool)
        .await?;
        values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Lists all active host-classification rule sets newest first.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when durable rule sets cannot be read or decoded.
    pub async fn list_active_classification_rule_sets(
        &self,
        installation_id: Uuid,
    ) -> Result<Vec<ClassificationRuleSetView>, PostgresStoreError> {
        let values = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT to_jsonb(s) - 'idempotency_key' - 'request_sha256'
                - 'deactivation_idempotency_key' - 'deactivation_request_sha256'
            FROM classification_rule_sets s
            WHERE installation_id = $1 AND active
            ORDER BY created_at DESC, rule_set_id DESC
            LIMIT 1000
            ",
        )
        .bind(installation_id)
        .fetch_all(&self.pool)
        .await?;
        values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Loads a rule set by idempotency key without exposing its request fingerprint publicly.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the durable rule set cannot be read or decoded.
    pub async fn get_classification_rule_set_by_idempotency(
        &self,
        installation_id: Uuid,
        idempotency_key: Uuid,
    ) -> Result<Option<(String, ClassificationRuleSetView)>, PostgresStoreError> {
        let row = sqlx::query_as::<_, (String, serde_json::Value)>(
            r"
            SELECT request_sha256, to_jsonb(s) - 'idempotency_key' - 'request_sha256'
                - 'deactivation_idempotency_key' - 'deactivation_request_sha256'
            FROM classification_rule_sets s
            WHERE installation_id = $1 AND idempotency_key = $2
            ",
        )
        .bind(installation_id)
        .bind(idempotency_key)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(request_sha256, value)| Ok((request_sha256, serde_json::from_value(value)?)))
            .transpose()
    }

    /// Commits an exact preview-bound rule set and its resulting authorization transitions.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the contract is unsafe, the preview estate changed,
    /// idempotency conflicts, or the transaction cannot be committed.
    #[allow(clippy::too_many_lines)]
    pub async fn create_classification_rule_set(
        &self,
        request: &ClassificationRuleSetCreate,
    ) -> Result<ClassificationRuleSetWrite, PostgresStoreError> {
        validate_classification_rule_set(request)?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('godel-tally-classification-rules'))")
            .execute(&mut *transaction)
            .await?;
        if let Some((digest, value)) = sqlx::query_as::<_, (String, serde_json::Value)>(
            r"
                SELECT request_sha256,
                    to_jsonb(s) - 'idempotency_key' - 'request_sha256'
                        - 'deactivation_idempotency_key' - 'deactivation_request_sha256'
                FROM classification_rule_sets s WHERE idempotency_key = $1
                ",
        )
        .bind(request.idempotency_key)
        .fetch_optional(&mut *transaction)
        .await?
        {
            if digest != request.request_sha256 {
                return Err(PostgresStoreError::IdempotencyConflict);
            }
            transaction.rollback().await?;
            return Ok(ClassificationRuleSetWrite {
                rule_set: serde_json::from_value(value)?,
                replayed: true,
            });
        }
        validate_no_classification_conflict(&mut transaction, request).await?;
        let rule_set_count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM classification_rule_sets WHERE installation_id = $1",
        )
        .bind(request.installation_id)
        .fetch_one(&mut *transaction)
        .await?;
        if rule_set_count >= 1_000 {
            return Err(PostgresStoreError::UnsafeClassificationRuleSet);
        }
        let matched_system_ids = request
            .matched_systems
            .iter()
            .map(|system| system.system_id)
            .collect::<Vec<_>>();
        let rows = sqlx::query_as::<_, (Uuid, String, i64)>(
            r"
            SELECT system_id, authorization_status, revision
            FROM ai_system_views
            WHERE installation_id = $1 AND system_id = ANY($2)
            ORDER BY system_id
            FOR UPDATE
            ",
        )
        .bind(request.installation_id)
        .bind(&matched_system_ids)
        .fetch_all(&mut *transaction)
        .await?;
        let estate_matches_preview = rows.len() == request.matched_systems.len()
            && rows.iter().zip(&request.matched_systems).all(
                |((system_id, status, revision), expected)| {
                    *system_id == expected.system_id
                        && status == &expected.authorization_status
                        && *revision == expected.revision
                },
            );
        if !estate_matches_preview {
            return Err(PostgresStoreError::ClassificationPreviewChanged);
        }
        let target_status = request.decision.as_str();
        let changed = rows
            .iter()
            .filter(|(_, status, _)| status != target_status && status != "retired")
            .map(|(system_id, _, _)| *system_id)
            .collect::<Vec<_>>();
        let value = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            INSERT INTO classification_rule_sets (
                rule_set_id, idempotency_key, installation_id, request_sha256,
                preview_digest, decision, rules, rules_sha256, matched_system_ids,
                changed_system_ids, matched_system_count, changed_system_count,
                created_at, created_by
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'local_operator')
            RETURNING to_jsonb(classification_rule_sets) - 'idempotency_key' - 'request_sha256'
            ",
        )
        .bind(request.rule_set_id)
        .bind(request.idempotency_key)
        .bind(request.installation_id)
        .bind(&request.request_sha256)
        .bind(&request.preview_digest)
        .bind(&request.decision)
        .bind(&request.rules)
        .bind(&request.rules_sha256)
        .bind(&matched_system_ids)
        .bind(&changed)
        .bind(i32::try_from(matched_system_ids.len()).unwrap_or(i32::MAX))
        .bind(i32::try_from(changed.len()).unwrap_or(i32::MAX))
        .bind(request.created_at)
        .fetch_one(&mut *transaction)
        .await?;
        for (system_id, from_status, revision) in rows
            .into_iter()
            .filter(|(_, status, _)| status != target_status && status != "retired")
        {
            let transition_id = Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                format!(
                    "godel-tally:classification-transition:{}:{system_id}",
                    request.rule_set_id
                )
                .as_bytes(),
            );
            sqlx::query(
                r"
                INSERT INTO authorization_transitions (
                    transition_id, system_id, from_status, to_status, reason_code, actor,
                    previous_revision, new_revision, idempotency_key, at, rule_set_id
                ) VALUES ($1,$2,$3,$4,$5,'local_policy',$6,$7,$8,$9,$10)
                ",
            )
            .bind(transition_id)
            .bind(system_id)
            .bind(&from_status)
            .bind(target_status)
            .bind(if target_status == "authorized" {
                "domain_rule_authorized"
            } else {
                "domain_rule_unauthorized"
            })
            .bind(revision)
            .bind(revision + 1)
            .bind(transition_id)
            .bind(request.created_at)
            .bind(request.rule_set_id)
            .execute(&mut *transaction)
            .await?;
            let result = sqlx::query(
                r"
                UPDATE ai_system_views
                SET authorization_status = $2, revision = revision + 1
                WHERE system_id = $1 AND revision = $3
                ",
            )
            .bind(system_id)
            .bind(target_status)
            .bind(revision)
            .execute(&mut *transaction)
            .await?;
            if result.rows_affected() != 1 {
                return Err(PostgresStoreError::ClassificationPreviewChanged);
            }
        }
        sqlx::query(
            r"
            INSERT INTO audit_log (audit_id, at, actor, action, entity_type, entity_id, detail)
            VALUES ($1,$2,$5,'classification.rules.created','classification_rule_set',$3,$4)
            ",
        )
        .bind(Uuid::now_v7())
        .bind(request.created_at)
        .bind(request.rule_set_id.to_string())
        .bind(serde_json::json!({
            "preview_digest": &request.preview_digest,
            "rules_sha256": request.rules_sha256,
            "decision": request.decision,
            "rule_count": request.rules.as_array().map_or(0, Vec::len),
            "matched_system_count": matched_system_ids.len(),
            "changed_system_count": changed.len(),
            "content_retained": false,
        }))
        .bind(audit_actor())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(ClassificationRuleSetWrite {
            rule_set: serde_json::from_value(value)?,
            replayed: false,
        })
    }

    /// Deactivates a persistent rule set without rewriting its immutable decision receipt.
    ///
    /// Existing system decisions remain unchanged and can be reviewed through the ordinary
    /// authorization workflow. Future evidence no longer applies the deactivated rule.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] for unsafe fingerprints, idempotency conflicts, missing or
    /// already inactive rule sets, and persistence failures.
    pub async fn deactivate_classification_rule_set(
        &self,
        installation_id: Uuid,
        rule_set_id: Uuid,
        idempotency_key: Uuid,
        request_sha256: &str,
        deactivated_at: DateTime<Utc>,
    ) -> Result<ClassificationRuleSetWrite, PostgresStoreError> {
        if !valid_lower_sha256(request_sha256) {
            return Err(PostgresStoreError::UnsafeClassificationRuleSet);
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('godel-tally-classification-rules'))")
            .execute(&mut *transaction)
            .await?;
        if let Some((existing_rule_set_id, existing_digest, value)) =
            sqlx::query_as::<_, (Uuid, String, serde_json::Value)>(
                r"
                SELECT rule_set_id, deactivation_request_sha256,
                    to_jsonb(s) - 'idempotency_key' - 'request_sha256'
                        - 'deactivation_idempotency_key' - 'deactivation_request_sha256'
                FROM classification_rule_sets s
                WHERE deactivation_idempotency_key = $1
                ",
            )
            .bind(idempotency_key)
            .fetch_optional(&mut *transaction)
            .await?
        {
            if existing_rule_set_id != rule_set_id || existing_digest != request_sha256 {
                return Err(PostgresStoreError::IdempotencyConflict);
            }
            transaction.rollback().await?;
            return Ok(ClassificationRuleSetWrite {
                rule_set: serde_json::from_value(value)?,
                replayed: true,
            });
        }
        let active = sqlx::query_scalar::<_, bool>(
            "SELECT active FROM classification_rule_sets WHERE installation_id = $1 AND rule_set_id = $2 FOR UPDATE",
        )
        .bind(installation_id)
        .bind(rule_set_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(PostgresStoreError::ClassificationRuleSetNotFound)?;
        if !active {
            return Err(PostgresStoreError::ClassificationRuleSetInactive);
        }
        let value = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            UPDATE classification_rule_sets
            SET active = FALSE, deactivated_at = $3, deactivated_by = 'local_operator',
                deactivation_idempotency_key = $4, deactivation_request_sha256 = $5
            WHERE installation_id = $1 AND rule_set_id = $2 AND active
            RETURNING to_jsonb(classification_rule_sets) - 'idempotency_key' - 'request_sha256'
                - 'deactivation_idempotency_key' - 'deactivation_request_sha256'
            ",
        )
        .bind(installation_id)
        .bind(rule_set_id)
        .bind(deactivated_at)
        .bind(idempotency_key)
        .bind(request_sha256)
        .fetch_one(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO audit_log (audit_id, at, actor, action, entity_type, entity_id, detail)
            VALUES ($1,$2,$5,'classification.rules.deactivated','classification_rule_set',$3,$4)
            ",
        )
        .bind(Uuid::now_v7())
        .bind(deactivated_at)
        .bind(rule_set_id.to_string())
        .bind(serde_json::json!({
            "rule_set_id": rule_set_id,
            "content_retained": false,
        }))
        .bind(audit_actor())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(ClassificationRuleSetWrite {
            rule_set: serde_json::from_value(value)?,
            replayed: false,
        })
    }

    /// Applies one durable host decision to a newly resolved system.
    ///
    /// The rule-set decision is loaded from storage, prior opposite rule application fails closed,
    /// retired systems remain terminal, and replay is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the rule set/system is missing or persistence fails.
    #[allow(clippy::too_many_lines)]
    pub async fn apply_classification_rule_set_to_system(
        &self,
        installation_id: Uuid,
        rule_set_id: Uuid,
        system_id: Uuid,
        applied_at: DateTime<Utc>,
    ) -> Result<ClassificationApplyOutcome, PostgresStoreError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('godel-tally-classification-rules'))")
            .execute(&mut *transaction)
            .await?;
        let (decision, active) = sqlx::query_as::<_, (String, bool)>(
            "SELECT decision, active FROM classification_rule_sets WHERE installation_id = $1 AND rule_set_id = $2",
        )
        .bind(installation_id)
        .bind(rule_set_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(PostgresStoreError::ClassificationRuleSetNotFound)?;
        if !active {
            transaction.rollback().await?;
            return Ok(ClassificationApplyOutcome::Unchanged);
        }
        let (current_status, revision) = sqlx::query_as::<_, (String, i64)>(
            "SELECT authorization_status, revision FROM ai_system_views WHERE installation_id = $1 AND system_id = $2 FOR UPDATE",
        )
        .bind(installation_id)
        .bind(system_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(PostgresStoreError::SystemNotFound)?;
        if current_status == "retired" || current_status == decision {
            transaction.rollback().await?;
            return Ok(ClassificationApplyOutcome::Unchanged);
        }
        let prior_rule_decision = sqlx::query_scalar::<_, String>(
            r"
            SELECT rules.decision
            FROM authorization_transitions transition
            JOIN classification_rule_sets rules ON rules.rule_set_id = transition.rule_set_id
            WHERE transition.system_id = $1 AND transition.rule_set_id IS NOT NULL AND rules.active
            ORDER BY transition.at DESC, transition.transition_id DESC
            LIMIT 1
            ",
        )
        .bind(system_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if prior_rule_decision.is_some_and(|prior| prior != decision) {
            let audit_id = classification_conflict_audit_id(system_id, &[rule_set_id]);
            sqlx::query(
                r"
                INSERT INTO audit_log (audit_id, at, actor, action, entity_type, entity_id, detail)
                VALUES ($1,$2,'local_policy','classification.rules.conflict','ai_system',$3,$4)
                ON CONFLICT (audit_id) DO NOTHING
                ",
            )
            .bind(audit_id)
            .bind(applied_at)
            .bind(system_id.to_string())
            .bind(serde_json::json!({
                "rule_set_ids": [rule_set_id],
                "content_retained": false,
            }))
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            return Ok(ClassificationApplyOutcome::Conflict);
        }
        let transition_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("godel-tally:classification-transition:{rule_set_id}:{system_id}").as_bytes(),
        );
        if sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM authorization_transitions WHERE transition_id = $1)",
        )
        .bind(transition_id)
        .fetch_one(&mut *transaction)
        .await?
        {
            transaction.rollback().await?;
            return Ok(ClassificationApplyOutcome::Unchanged);
        }
        let result = sqlx::query(
            "UPDATE ai_system_views SET authorization_status = $2, revision = revision + 1 WHERE system_id = $1 AND revision = $3",
        )
        .bind(system_id)
        .bind(&decision)
        .bind(revision)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(PostgresStoreError::ClassificationPreviewChanged);
        }
        sqlx::query(
            r"
            INSERT INTO authorization_transitions (
                transition_id, system_id, from_status, to_status, reason_code, actor,
                previous_revision, new_revision, idempotency_key, at, rule_set_id
            ) VALUES ($1,$2,$3,$4,$5,'local_policy',$6,$7,$1,$8,$9)
            ",
        )
        .bind(transition_id)
        .bind(system_id)
        .bind(&current_status)
        .bind(&decision)
        .bind(if decision == "authorized" {
            "domain_rule_authorized"
        } else {
            "domain_rule_unauthorized"
        })
        .bind(revision)
        .bind(revision + 1)
        .bind(applied_at)
        .bind(rule_set_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO audit_log (audit_id, at, actor, action, entity_type, entity_id, detail)
            VALUES ($1,$2,'local_policy','classification.rules.applied','ai_system',$3,$4)
            ",
        )
        .bind(Uuid::now_v7())
        .bind(applied_at)
        .bind(system_id.to_string())
        .bind(serde_json::json!({
            "rule_set_id": rule_set_id,
            "decision": decision,
            "content_retained": false,
        }))
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(ClassificationApplyOutcome::Applied)
    }

    /// Records a fail-closed system conflict between differently decided rule sets.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the content-free audit receipt cannot be written.
    pub async fn record_classification_rule_conflict(
        &self,
        system_id: Uuid,
        rule_set_ids: &[Uuid],
        at: DateTime<Utc>,
    ) -> Result<(), PostgresStoreError> {
        if rule_set_ids.len() < 2
            || rule_set_ids.len() > 1_000
            || !rule_set_ids.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(PostgresStoreError::UnsafeClassificationRuleSet);
        }
        let audit_id = classification_conflict_audit_id(system_id, rule_set_ids);
        sqlx::query(
            r"
            INSERT INTO audit_log (audit_id, at, actor, action, entity_type, entity_id, detail)
            VALUES ($1,$2,'local_policy','classification.rules.conflict','ai_system',$3,$4)
            ON CONFLICT (audit_id) DO NOTHING
            ",
        )
        .bind(audit_id)
        .bind(at)
        .bind(system_id.to_string())
        .bind(serde_json::json!({
            "rule_set_ids": rule_set_ids,
            "content_retained": false,
        }))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Counts connector instances that have attempted ingestion.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the overview query fails.
    pub async fn active_connector_count(&self) -> Result<u64, PostgresStoreError> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM connector_states WHERE health <> 'never_run'",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Counts the installation-scoped state affected by a full local data purge.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when any count query fails.
    pub async fn purge_preview_counts(
        &self,
        installation_id: Uuid,
    ) -> Result<PurgeCounts, PostgresStoreError> {
        let row = sqlx::query_as::<
            _,
            (
                i64,
                i64,
                i64,
                i64,
                i64,
                i64,
                i64,
                i64,
                i64,
                i64,
                i64,
                i64,
                i64,
                i64,
                i64,
                i64,
            ),
        >(
            r"
            SELECT
              (SELECT count(*) FROM connector_states WHERE installation_id = $1),
              (SELECT count(*) FROM connector_runs WHERE installation_id = $1),
              (SELECT count(*) FROM connector_jobs j JOIN connector_states s ON s.connector_instance_id = j.connector_instance_id WHERE s.installation_id = $1),
              (SELECT count(*) FROM connector_backfill_requests WHERE installation_id = $1),
              (SELECT count(*) FROM ingestion_batches WHERE installation_id = $1),
              (SELECT count(*) FROM ai_system_views WHERE installation_id = $1),
              (SELECT count(*) FROM findings f JOIN ai_system_views v ON v.system_id = f.system_id WHERE v.installation_id = $1),
              (SELECT count(*) FROM claims c WHERE c.subject_entity_id IN (SELECT entity_id FROM entity_keys WHERE installation_id = $1)),
              (SELECT count(*) FROM claim_evidence ce JOIN claims c ON c.claim_id = ce.claim_id WHERE c.subject_entity_id IN (SELECT entity_id FROM entity_keys WHERE installation_id = $1)),
              (SELECT count(*) FROM authorization_transitions t JOIN ai_system_views v ON v.system_id = t.system_id WHERE v.installation_id = $1),
              (SELECT count(*) FROM mutation_idempotency m JOIN ai_system_views v ON v.system_id = m.entity_id WHERE v.installation_id = $1),
              (SELECT count(*) FROM local_registry_overlays WHERE installation_id = $1),
              (SELECT count(*) FROM local_registry_mutations WHERE installation_id = $1),
              (SELECT count(*) FROM classification_rule_sets WHERE installation_id = $1),
              (SELECT count(*) FROM scan_jobs),
              (SELECT count(*) FROM audit_log)
            ",
        )
        .bind(installation_id)
        .fetch_one(&self.pool)
        .await?;
        let attribution_row = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64, i64, i64)>(
            r"
            SELECT
              (SELECT count(DISTINCT entity_id) FROM entity_keys WHERE installation_id = $1),
              (SELECT count(*) FROM entity_keys WHERE installation_id = $1),
              (SELECT count(*) FROM entity_relationships WHERE installation_id = $1),
              (SELECT count(*) FROM relationship_evidence e JOIN entity_relationships r ON r.relationship_id = e.relationship_id WHERE r.installation_id = $1),
              (SELECT count(*) FROM attribution_replay_checkpoints WHERE installation_id = $1),
              (SELECT count(*) FROM attribution_conflicts WHERE installation_id = $1),
              (SELECT count(*) FROM entity_resolution_events WHERE installation_id = $1),
              (SELECT count(*) FROM entity_resolution_aliases WHERE installation_id = $1)
            ",
        )
        .bind(installation_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(PurgeCounts {
            observations: 0,
            connectors: count_u64(row.0),
            connector_runs: count_u64(row.1),
            connector_jobs: count_u64(row.2),
            connector_backfill_requests: count_u64(row.3),
            ingestion_batches: count_u64(row.4),
            systems: count_u64(row.5),
            findings: count_u64(row.6),
            claims: count_u64(row.7),
            evidence_links: count_u64(row.8),
            authorization_transitions: count_u64(row.9),
            mutation_receipts: count_u64(row.10),
            registry_overlays: count_u64(row.11),
            registry_mutation_receipts: count_u64(row.12),
            classification_rule_sets: count_u64(row.13),
            scans: count_u64(row.14),
            audit_events: count_u64(row.15),
            entities: count_u64(attribution_row.0),
            entity_keys: count_u64(attribution_row.1),
            relationships: count_u64(attribution_row.2),
            relationship_evidence: count_u64(attribution_row.3),
            attribution_checkpoints: count_u64(attribution_row.4),
            attribution_conflicts: count_u64(attribution_row.5),
            entity_resolution_events: count_u64(attribution_row.6),
            entity_resolution_aliases: count_u64(attribution_row.7),
        })
    }

    /// Durably records an operator-authorized purge before either database is mutated.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] for an invalid digest, conflicting idempotency key, or
    /// database failure.
    pub async fn begin_purge(
        &self,
        installation_id: Uuid,
        purge_id: Uuid,
        preview_digest: &str,
        requested_counts: &PurgeCounts,
        requested_at: DateTime<Utc>,
    ) -> Result<PurgeReceipt, PostgresStoreError> {
        validate_purge_digest(preview_digest)?;
        let requested_json = serde_json::to_value(requested_counts)?;
        if let Some(receipt) = self.get_purge_receipt(purge_id).await? {
            if receipt.preview_digest != preview_digest
                || receipt.requested_counts != *requested_counts
            {
                return Err(PostgresStoreError::IdempotencyConflict);
            }
            return Ok(receipt);
        }
        sqlx::query(
            r"
            INSERT INTO purge_receipts (
              purge_id, installation_id, preview_digest, requested_counts, status,
              requested_at, requested_by
            ) VALUES ($1,$2,$3,$4,'planned',$5,'local_operator')
            ",
        )
        .bind(purge_id)
        .bind(installation_id)
        .bind(preview_digest)
        .bind(requested_json)
        .bind(requested_at)
        .execute(&self.pool)
        .await?;
        self.get_purge_receipt(purge_id)
            .await?
            .ok_or(PostgresStoreError::PurgeNotFound)
    }

    /// Loads one durable purge receipt for idempotent replay.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the receipt cannot be decoded.
    pub async fn get_purge_receipt(
        &self,
        purge_id: Uuid,
    ) -> Result<Option<PurgeReceipt>, PostgresStoreError> {
        let row = sqlx::query_as::<_, (Uuid, String, serde_json::Value, Option<serde_json::Value>, String)>(
            "SELECT purge_id, preview_digest, requested_counts, deleted_counts, status FROM purge_receipts WHERE purge_id = $1",
        )
        .bind(purge_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(purge_id, preview_digest, requested, deleted, status)| {
            Ok(PurgeReceipt {
                purge_id,
                preview_digest,
                requested_counts: serde_json::from_value(requested)?,
                deleted_counts: deleted.map(serde_json::from_value).transpose()?,
                status,
            })
        })
        .transpose()
    }

    /// Deletes installation data transactionally and completes the precommitted purge receipt.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when a database operation fails.
    pub async fn purge_installation_data(
        &self,
        installation_id: Uuid,
        purge_id: Uuid,
        preview_digest: &str,
        requested_counts: &PurgeCounts,
    ) -> Result<PurgeCounts, PostgresStoreError> {
        validate_purge_digest(preview_digest)?;
        let mut transaction = self.pool.begin().await?;
        let (status, receipt_counts) = sqlx::query_as::<_, (String, serde_json::Value)>(
            "SELECT status, requested_counts FROM purge_receipts WHERE purge_id = $1 AND installation_id = $2 AND preview_digest = $3 FOR UPDATE",
        )
        .bind(purge_id)
        .bind(installation_id)
        .bind(preview_digest)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(PostgresStoreError::PurgeNotFound)?;
        let receipt_counts: PurgeCounts = serde_json::from_value(receipt_counts)?;
        if receipt_counts != *requested_counts {
            transaction.rollback().await?;
            return Err(PostgresStoreError::IdempotencyConflict);
        }
        if status == "completed" {
            transaction.rollback().await?;
            return self
                .get_purge_receipt(purge_id)
                .await?
                .and_then(|receipt| receipt.deleted_counts)
                .ok_or(PostgresStoreError::PurgeNotFound);
        }
        let entity_ids = sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT entity_id FROM entity_keys WHERE installation_id = $1
            UNION
            SELECT system_id FROM ai_system_views WHERE installation_id = $1
            ",
        )
        .bind(installation_id)
        .fetch_all(&mut *transaction)
        .await?;
        let connector_ids = sqlx::query_scalar::<_, Uuid>(
            "SELECT connector_instance_id FROM connector_states WHERE installation_id = $1 FOR UPDATE",
        )
        .bind(installation_id)
        .fetch_all(&mut *transaction)
        .await?;
        let deleted = requested_counts.clone();
        Self::delete_purge_rows(
            &mut transaction,
            &entity_ids,
            &connector_ids,
            installation_id,
        )
        .await?;
        let completed_at = Utc::now();
        let deleted_json = serde_json::to_value(&deleted)?;
        sqlx::query(
            "UPDATE purge_receipts SET status = 'completed', deleted_counts = $2, completed_at = $3, failure_code = NULL WHERE purge_id = $1",
        )
        .bind(purge_id)
        .bind(&deleted_json)
        .bind(completed_at)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO audit_log (audit_id, at, actor, action, entity_type, entity_id, detail)
            VALUES ($1,$2,$5,'data.purge.completed','purge',$3,$4)
            ",
        )
        .bind(Uuid::now_v7())
        .bind(completed_at)
        .bind(purge_id.to_string())
        .bind(serde_json::json!({
            "preview_digest": preview_digest,
            "deleted_counts": deleted,
            "content_retained": false,
        }))
        .bind(audit_actor())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(deleted)
    }

    async fn delete_purge_rows(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        entity_ids: &[Uuid],
        connector_ids: &[Uuid],
        installation_id: Uuid,
    ) -> Result<(), PostgresStoreError> {
        for statement in [
            "DELETE FROM finding_activity WHERE installation_id=$1",
            "DELETE FROM identity_facts WHERE installation_id=$1",
            "DELETE FROM identity_device_aliases WHERE installation_id=$1",
            "DELETE FROM endpoint_process_facts WHERE installation_id=$1",
            "DELETE FROM inventory_source_presence WHERE installation_id=$1",
            "DELETE FROM inventory_sync_status WHERE installation_id=$1",
            "DELETE FROM inventory_presence_events WHERE installation_id=$1",
            "DELETE FROM identity_links WHERE installation_id=$1",
            "DELETE FROM identity_corrections WHERE installation_id=$1",
            "DELETE FROM identity_replay_jobs WHERE installation_id=$1",
            "DELETE FROM identity_enrichments WHERE installation_id=$1",
        ] {
            sqlx::query(statement)
                .bind(installation_id)
                .execute(&mut **transaction)
                .await?;
        }
        sqlx::query("DELETE FROM tally_estate_reviews WHERE installation_id=$1")
            .bind(installation_id)
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DELETE FROM audit_log")
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DELETE FROM scan_jobs")
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DELETE FROM local_registry_overlays WHERE installation_id = $1")
            .bind(installation_id)
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DELETE FROM classification_rule_sets WHERE installation_id = $1")
            .bind(installation_id)
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DELETE FROM attribution_replay_checkpoints WHERE installation_id = $1")
            .bind(installation_id)
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DELETE FROM entity_relationships WHERE installation_id = $1")
            .bind(installation_id)
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DELETE FROM entity_resolution_events WHERE installation_id = $1")
            .bind(installation_id)
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DELETE FROM mutation_idempotency WHERE entity_id = ANY($1)")
            .bind(entity_ids)
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DELETE FROM authorization_transitions WHERE system_id = ANY($1)")
            .bind(entity_ids)
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DELETE FROM findings WHERE system_id = ANY($1)")
            .bind(entity_ids)
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DELETE FROM claims WHERE subject_entity_id = ANY($1)")
            .bind(entity_ids)
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DELETE FROM ai_system_views WHERE system_id = ANY($1)")
            .bind(entity_ids)
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DELETE FROM entity_keys WHERE installation_id = $1")
            .bind(installation_id)
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DELETE FROM entities WHERE entity_id = ANY($1)")
            .bind(entity_ids)
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DELETE FROM connector_jobs WHERE connector_instance_id = ANY($1)")
            .bind(connector_ids)
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DELETE FROM connector_runs WHERE connector_instance_id = ANY($1)")
            .bind(connector_ids)
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DELETE FROM ingestion_batches WHERE installation_id = $1")
            .bind(installation_id)
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DELETE FROM connector_states WHERE installation_id = $1")
            .bind(installation_id)
            .execute(&mut **transaction)
            .await
            .map_err(connector_delete_error)?;
        Ok(())
    }

    /// Marks a precommitted purge attempt failed with a bounded machine code. The same purge ID
    /// may be retried safely.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] for an unsafe code or database failure.
    pub async fn fail_purge(
        &self,
        purge_id: Uuid,
        failure_code: &str,
    ) -> Result<(), PostgresStoreError> {
        if !safe_code(failure_code) {
            return Err(PostgresStoreError::UnsafeFailureCode);
        }
        sqlx::query(
            "UPDATE purge_receipts SET status = 'failed', failure_code = $2 WHERE purge_id = $1 AND status <> 'completed'",
        )
        .bind(purge_id)
        .bind(failure_code)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Registers a connector instance and its non-secret capability descriptor, leaving any
    /// operator-chosen friendly name already on the row untouched.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when descriptor serialization or persistence fails.
    pub async fn register_connector(
        &self,
        installation_id: Uuid,
        connector_instance_id: Uuid,
        descriptor: &ConnectorDescriptor,
    ) -> Result<(), PostgresStoreError> {
        self.register_connector_named(installation_id, connector_instance_id, descriptor, None)
            .await
    }

    /// Registers a connector instance, its descriptor, and the operator's label for it.
    ///
    /// `friendly_name` is what separates two instances of the same connector type -- the staging
    /// cluster from the production one -- and only the console form supplies it. `None` keeps
    /// whatever label the row already holds, so the collector re-registering a descriptor on
    /// every poll never erases a name an operator typed. `Some("")` clears it.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the name is unsafe, or when descriptor serialization
    /// or persistence fails.
    pub async fn register_connector_named(
        &self,
        installation_id: Uuid,
        connector_instance_id: Uuid,
        descriptor: &ConnectorDescriptor,
        friendly_name: Option<&str>,
    ) -> Result<(), PostgresStoreError> {
        if friendly_name.is_some_and(|name| !safe_connector_friendly_name(name)) {
            return Err(PostgresStoreError::ConnectorFriendlyNameInvalid);
        }
        sqlx::query(
            r"
            INSERT INTO connector_states (
                connector_instance_id, installation_id, connector_type, implementation_version,
                display_name, transport, descriptor, friendly_name
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,COALESCE($8, ''))
            ON CONFLICT (connector_instance_id) DO UPDATE SET
                connector_type = EXCLUDED.connector_type,
                implementation_version = EXCLUDED.implementation_version,
                display_name = EXCLUDED.display_name,
                transport = EXCLUDED.transport,
                descriptor = EXCLUDED.descriptor,
                friendly_name = COALESCE($8, connector_states.friendly_name),
                updated_at = now()
            ",
        )
        .bind(connector_instance_id)
        .bind(installation_id)
        .bind(&descriptor.connector_type)
        .bind(&descriptor.implementation_version)
        .bind(&descriptor.display_name)
        .bind(enum_string(descriptor.transport, "file")?)
        .bind(serde_json::to_value(descriptor)?)
        .bind(friendly_name)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Creates or updates the single durable execution schedule for a connector instance.
    ///
    /// `config_refs` is restricted to bounded machine references; paths, plaintext secrets, and
    /// source data are rejected by the store contract. Operator-entered credentials arrive already
    /// sealed and are stored as opaque bytes. An actively leased job cannot be reconfigured.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the job contract is unsafe, leased, or cannot be stored.
    pub async fn put_connector_job(
        &self,
        job: &ConnectorJobSpec,
    ) -> Result<Uuid, PostgresStoreError> {
        validate_connector_job(job)?;
        let mode = enum_string(job.mode, "scheduled")?;
        let status = enum_string(job.status, "enabled")?;
        let next_run_at = (job.status == ConnectorJobStatus::Enabled)
            .then_some(job.next_run_at)
            .flatten();
        let mut transaction = self.pool.begin().await?;
        let (nonce, ciphertext) = job.credentials.as_ref().map_or((None, None), |sealed| {
            (Some(sealed.nonce.clone()), Some(sealed.ciphertext.clone()))
        });
        let job_id = sqlx::query_scalar::<_, Uuid>(
            r"
            INSERT INTO connector_jobs (
                job_id, connector_instance_id, mode, status, schedule_seconds,
                next_run_at, config_refs, secret_nonce, secret_ciphertext, created_at, updated_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)
            ON CONFLICT (connector_instance_id) DO UPDATE SET
                mode = EXCLUDED.mode,
                status = EXCLUDED.status,
                schedule_seconds = EXCLUDED.schedule_seconds,
                next_run_at = EXCLUDED.next_run_at,
                config_refs = EXCLUDED.config_refs,
                -- A request that omits credentials is reconfiguring the schedule, not
                -- clearing the secrets, so the stored pair survives untouched.
                secret_nonce = COALESCE(EXCLUDED.secret_nonce, connector_jobs.secret_nonce),
                secret_ciphertext =
                    COALESCE(EXCLUDED.secret_ciphertext, connector_jobs.secret_ciphertext),
                last_error_code = CASE WHEN EXCLUDED.secret_ciphertext IS NOT NULL
                    THEN NULL ELSE connector_jobs.last_error_code END,
                consecutive_failures = CASE WHEN EXCLUDED.secret_ciphertext IS NOT NULL
                    THEN 0 ELSE connector_jobs.consecutive_failures END,
                updated_at = EXCLUDED.updated_at
            WHERE connector_jobs.lease_owner IS NULL OR connector_jobs.lease_until <= EXCLUDED.updated_at
            RETURNING job_id
            ",
        )
        .bind(job.job_id)
        .bind(job.connector_instance_id)
        .bind(&mode)
        .bind(&status)
        .bind(job.schedule_seconds.map(i64::from))
        .bind(next_run_at)
        .bind(&job.config_refs)
        .bind(nonce)
        .bind(ciphertext)
        .bind(job.updated_at)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(PostgresStoreError::ConnectorJobLeased)?;
        sqlx::query(
            r"
            INSERT INTO audit_log (audit_id, at, actor, action, entity_type, entity_id, detail)
            VALUES ($1,$2,$5,'connector.schedule.upserted','connector_job',$3,$4)
            ",
        )
        .bind(Uuid::now_v7())
        .bind(job.updated_at)
        .bind(job_id.to_string())
        .bind(serde_json::json!({
            "connector_instance_id": job.connector_instance_id,
            "mode": mode,
            "status": status,
            "schedule_seconds": job.schedule_seconds,
            "source_reference_kind": job.config_refs.get("kind"),
            "credentials_sealed": job.credentials.is_some(),
            "content_retained": false,
        }))
        .bind(audit_actor())
        .execute(&mut *transaction)
        .await?;
        sqlx::query("INSERT INTO identity_replay_jobs(installation_id) SELECT installation_id FROM connector_states WHERE connector_instance_id=$1 ON CONFLICT(installation_id) DO UPDATE SET requested_generation=identity_replay_jobs.requested_generation+1,updated_at=now()")
            .bind(job.connector_instance_id).execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(job_id)
    }

    /// Claims due connector jobs with `PostgreSQL` row locks so multiple collectors cannot execute
    /// the same schedule concurrently. Expired leases are eligible for recovery.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] for unsafe lease parameters or database failures.
    pub async fn lease_due_connector_jobs(
        &self,
        lease_owner: Uuid,
        now: DateTime<Utc>,
        lease_seconds: u16,
        limit: u16,
    ) -> Result<Vec<LeasedConnectorJob>, PostgresStoreError> {
        if !(30..=3_600).contains(&lease_seconds) || !(1..=32).contains(&limit) {
            return Err(PostgresStoreError::UnsafeConnectorJob);
        }
        let lease_until = now + chrono::Duration::seconds(i64::from(lease_seconds));
        let rows = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            WITH due AS (
                SELECT job_id
                FROM connector_jobs
                WHERE status = 'enabled'
                  AND next_run_at IS NOT NULL
                  AND next_run_at <= $2
                  AND (lease_until IS NULL OR lease_until <= $2)
                ORDER BY next_run_at, job_id
                FOR UPDATE SKIP LOCKED
                LIMIT $4
            ), claimed AS (
                UPDATE connector_jobs AS jobs SET
                    lease_owner = $1,
                    lease_until = $3,
                    last_started_at = $2,
                    -- The previous attempt finished before this one started, so keeping
                    -- its timestamp would leave last_finished_at behind last_started_at
                    -- and violate connector_jobs_finish_order_check. Clearing it also
                    -- states the truth while the attempt is in flight: it has not
                    -- finished. last_outcome and last_error_code deliberately survive so
                    -- the connector card can still show how the previous attempt ended.
                    last_finished_at = NULL,
                    attempt_count = attempt_count + 1,
                    updated_at = $2
                FROM due
                WHERE jobs.job_id = due.job_id
                RETURNING jobs.*
            )
            SELECT jsonb_build_object(
                'job_id', claimed.job_id,
                'connector_instance_id', claimed.connector_instance_id,
                'installation_id', states.installation_id,
                'connector_type', states.connector_type,
                'mode', claimed.mode,
                'schedule_seconds', claimed.schedule_seconds,
                'next_run_at', claimed.next_run_at,
                'lease_owner', claimed.lease_owner,
                'lease_until', claimed.lease_until,
                'config_refs', claimed.config_refs,
                'credentials', CASE WHEN claimed.secret_ciphertext IS NULL THEN NULL ELSE
                    jsonb_build_object(
                        'nonce', encode(claimed.secret_nonce, 'hex'),
                        'ciphertext', encode(claimed.secret_ciphertext, 'hex')
                    )
                END,
                'attempt_count', claimed.attempt_count,
                'consecutive_failures', claimed.consecutive_failures
            )
            FROM claimed
            JOIN connector_states AS states
              ON states.connector_instance_id = claimed.connector_instance_id
            ORDER BY claimed.next_run_at, claimed.job_id
            ",
        )
        .bind(lease_owner)
        .bind(now)
        .bind(lease_until)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Extends an active connector lease while a bounded source run is making progress.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] if the owner no longer holds the lease or parameters are unsafe.
    pub async fn renew_connector_job_lease(
        &self,
        job_id: Uuid,
        lease_owner: Uuid,
        now: DateTime<Utc>,
        lease_seconds: u16,
    ) -> Result<(), PostgresStoreError> {
        if !(30..=3_600).contains(&lease_seconds) {
            return Err(PostgresStoreError::UnsafeConnectorJob);
        }
        let updated = sqlx::query(
            r"
            UPDATE connector_jobs SET lease_until = $4, updated_at = $3
            WHERE job_id = $1 AND lease_owner = $2
            ",
        )
        .bind(job_id)
        .bind(lease_owner)
        .bind(now)
        .bind(now + chrono::Duration::seconds(i64::from(lease_seconds)))
        .execute(&self.pool)
        .await?
        .rows_affected();
        if updated == 1 {
            Ok(())
        } else {
            Err(PostgresStoreError::ConnectorJobLeaseLost)
        }
    }

    /// Completes a leased attempt, clears the lease, and computes its next durable run time.
    /// Successful scheduled jobs resume at their configured cadence; failures use bounded
    /// exponential retry backoff and one-shot/cancelled jobs pause.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] for an unsafe error code, lost lease, or database failure.
    pub async fn complete_connector_job(
        &self,
        completion: &ConnectorJobCompletion,
    ) -> Result<ConnectorJobView, PostgresStoreError> {
        if completion
            .error_code
            .as_deref()
            .is_some_and(|code| !safe_code(code))
            || (completion.outcome == ConnectorRunStatus::Failed && completion.error_code.is_none())
            || (completion.outcome != ConnectorRunStatus::Failed && completion.error_code.is_some())
        {
            return Err(PostgresStoreError::UnsafeConnectorJob);
        }
        let mut transaction = self.pool.begin().await?;
        let current = sqlx::query_as::<_, (String, Option<i64>, i64)>(
            r"
            SELECT mode, schedule_seconds, consecutive_failures
            FROM connector_jobs
            WHERE job_id = $1 AND lease_owner = $2
            FOR UPDATE
            ",
        )
        .bind(completion.job_id)
        .bind(completion.lease_owner)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(PostgresStoreError::ConnectorJobLeaseLost)?;
        let (status, mut next_run_at, consecutive_failures) = connector_job_next_state(
            &current.0,
            current.1,
            current.2,
            completion.outcome,
            completion.finished_at,
        )?;
        if completion.catch_up
            && completion.outcome == ConnectorRunStatus::Completed
            && let Some(next) = next_run_at.as_mut()
        {
            *next = (*next).min(completion.finished_at + chrono::Duration::seconds(15));
        }
        let outcome = enum_string(completion.outcome, "failed")?;
        let value = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            UPDATE connector_jobs SET
                status = $3,
                next_run_at = $4,
                lease_owner = NULL,
                lease_until = NULL,
                consecutive_failures = $5,
                last_finished_at = $6,
                last_outcome = $7,
                last_error_code = $8,
                updated_at = $6
            WHERE job_id = $1 AND lease_owner = $2
            RETURNING connector_job_json(connector_jobs)
            ",
        )
        .bind(completion.job_id)
        .bind(completion.lease_owner)
        .bind(status)
        .bind(next_run_at)
        .bind(consecutive_failures)
        .bind(completion.finished_at)
        .bind(outcome)
        .bind(&completion.error_code)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(PostgresStoreError::ConnectorJobLeaseLost)?;
        transaction.commit().await?;
        serde_json::from_value(value).map_err(Into::into)
    }

    /// Lists durable connector schedules without returning source paths or secret values.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the schedule projection cannot be loaded.
    pub async fn list_connector_jobs(&self) -> Result<Vec<ConnectorJobView>, PostgresStoreError> {
        let values = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT connector_job_json(jobs)
            FROM connector_jobs AS jobs
            ORDER BY jobs.updated_at DESC, jobs.job_id
            ",
        )
        .fetch_all(&self.pool)
        .await?;
        values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Loads the encrypted configuration material for one connector edit without decrypting it.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the connector job cannot be read.
    pub async fn connector_job_edit_view(
        &self,
        connector_instance_id: Uuid,
    ) -> Result<Option<ConnectorJobEditView>, PostgresStoreError> {
        let row = sqlx::query_as::<_, (serde_json::Value, Option<Vec<u8>>, Option<Vec<u8>>)>(
            r"
            SELECT config_refs, secret_nonce, secret_ciphertext
            FROM connector_jobs
            WHERE connector_instance_id = $1
            ",
        )
        .bind(connector_instance_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(
            |(config_refs, nonce, ciphertext)| match (nonce, ciphertext) {
                (Some(nonce), Some(ciphertext)) => Ok(ConnectorJobEditView {
                    config_refs,
                    credentials: Some(SealedCredentials { nonce, ciphertext }),
                }),
                (None, None) => Ok(ConnectorJobEditView {
                    config_refs,
                    credentials: None,
                }),
                _ => Err(PostgresStoreError::UnsafeConnectorJob),
            },
        )
        .transpose()
    }

    /// Moves one connector's next scheduled run forward to `requested_at` so the collector claims
    /// it on its next due window. This is the on-demand "sync now" path: it stays inside the
    /// leasing contract, so an attempt already in flight is reported rather than duplicated, and
    /// it never widens the connector's bounded source window.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the schedule is missing or belongs to another
    /// installation, is paused, is actively leased, or the update cannot be persisted.
    pub async fn request_connector_sync(
        &self,
        installation_id: Uuid,
        connector_instance_id: Uuid,
        requested_at: DateTime<Utc>,
    ) -> Result<ConnectorJobView, PostgresStoreError> {
        let mut transaction = self.pool.begin().await?;
        let (job_id, status, lease_until) =
            sqlx::query_as::<_, (Uuid, String, Option<DateTime<Utc>>)>(
                r"
            SELECT jobs.job_id, jobs.status, jobs.lease_until
            FROM connector_jobs AS jobs
            JOIN connector_states AS states
              ON states.connector_instance_id = jobs.connector_instance_id
            WHERE jobs.connector_instance_id = $1 AND states.installation_id = $2
            FOR UPDATE OF jobs
            ",
            )
            .bind(connector_instance_id)
            .bind(installation_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(PostgresStoreError::ConnectorJobNotFound)?;
        if lease_until.is_some_and(|lease_until| lease_until > requested_at) {
            return Err(PostgresStoreError::ConnectorJobLeased);
        }
        if status != "enabled" {
            return Err(PostgresStoreError::ConnectorJobPaused);
        }
        let value = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            UPDATE connector_jobs SET
                next_run_at = $2,
                updated_at = $2
            WHERE job_id = $1
            RETURNING connector_job_json(connector_jobs)
            ",
        )
        .bind(job_id)
        .bind(requested_at)
        .fetch_one(&mut *transaction)
        .await?;
        let job: ConnectorJobView = serde_json::from_value(value)?;
        Self::record_connector_sync_request(&mut transaction, &job, requested_at, "connector")
            .await?;
        transaction.commit().await?;
        Ok(job)
    }

    /// Brings every enabled, unleased schedule in the installation due at `requested_at`. Paused
    /// schedules and attempts already in flight are counted, not disturbed, so the caller can say
    /// what was queued and what was left alone.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the sweep cannot be persisted.
    pub async fn request_all_connector_syncs(
        &self,
        installation_id: Uuid,
        requested_at: DateTime<Utc>,
    ) -> Result<ConnectorSyncSweep, PostgresStoreError> {
        let mut transaction = self.pool.begin().await?;
        let (skipped_paused, skipped_leased) = sqlx::query_as::<_, (i64, i64)>(
            r"
            SELECT
                count(*) FILTER (WHERE jobs.status <> 'enabled'),
                count(*) FILTER (
                    WHERE jobs.status = 'enabled' AND jobs.lease_until > $2
                )
            FROM connector_jobs AS jobs
            JOIN connector_states AS states
              ON states.connector_instance_id = jobs.connector_instance_id
            WHERE states.installation_id = $1
            ",
        )
        .bind(installation_id)
        .bind(requested_at)
        .fetch_one(&mut *transaction)
        .await?;
        let due = sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT jobs.job_id
            FROM connector_jobs AS jobs
            JOIN connector_states AS states
              ON states.connector_instance_id = jobs.connector_instance_id
            WHERE states.installation_id = $1
              AND jobs.status = 'enabled'
              AND (jobs.lease_until IS NULL OR jobs.lease_until <= $2)
            ORDER BY jobs.job_id
            FOR UPDATE OF jobs
            ",
        )
        .bind(installation_id)
        .bind(requested_at)
        .fetch_all(&mut *transaction)
        .await?;
        let values = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            UPDATE connector_jobs SET
                next_run_at = $2,
                updated_at = $2
            WHERE job_id = ANY($1)
            RETURNING connector_job_json(connector_jobs)
            ",
        )
        .bind(&due)
        .bind(requested_at)
        .fetch_all(&mut *transaction)
        .await?;
        let triggered = values
            .into_iter()
            .map(serde_json::from_value::<ConnectorJobView>)
            .collect::<Result<Vec<_>, _>>()?;
        for job in &triggered {
            Self::record_connector_sync_request(
                &mut transaction,
                job,
                requested_at,
                "all_connectors",
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(ConnectorSyncSweep {
            triggered,
            skipped_leased: count_u64(skipped_leased),
            skipped_paused: count_u64(skipped_paused),
        })
    }

    async fn record_connector_sync_request(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        job: &ConnectorJobView,
        requested_at: DateTime<Utc>,
        scope: &str,
    ) -> Result<(), PostgresStoreError> {
        sqlx::query(
            r"
            INSERT INTO audit_log (audit_id, at, actor, action, entity_type, entity_id, detail)
            VALUES ($1,$2,$5,'connector.sync.requested','connector_job',$3,$4)
            ",
        )
        .bind(Uuid::now_v7())
        .bind(requested_at)
        .bind(job.job_id.to_string())
        .bind(serde_json::json!({
            "connector_instance_id": job.connector_instance_id,
            "scope": scope,
            "next_run_at": requested_at,
            "source_reference_kind": job.config_refs.get("kind"),
            "content_retained": false,
        }))
        .bind(audit_actor())
        .execute(&mut **transaction)
        .await?;
        Ok(())
    }

    /// Removes one connector: its schedule, its sealed credentials, its run receipts, and its
    /// ingestion ledger rows. Observations the connector already contributed are evidence and
    /// stay where they are; deleting those is the purge path's job.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the connector is missing or belongs to another
    /// installation, its schedule is actively leased, or the deletion cannot be persisted.
    pub async fn delete_connector(
        &self,
        installation_id: Uuid,
        connector_instance_id: Uuid,
        deleted_at: DateTime<Utc>,
    ) -> Result<ConnectorDeletion, PostgresStoreError> {
        let mut transaction = self.pool.begin().await?;
        let (connector_type, display_name, friendly_name) =
            sqlx::query_as::<_, (String, String, String)>(
                r"
            SELECT connector_type, display_name, friendly_name
            FROM connector_states
            WHERE connector_instance_id = $1 AND installation_id = $2
            FOR UPDATE
            ",
            )
            .bind(connector_instance_id)
            .bind(installation_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(PostgresStoreError::ConnectorNotFound)?;
        let job = sqlx::query_as::<_, (Uuid, Option<DateTime<Utc>>)>(
            r"
            SELECT job_id, lease_until
            FROM connector_jobs
            WHERE connector_instance_id = $1
            FOR UPDATE
            ",
        )
        .bind(connector_instance_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if job
            .as_ref()
            .and_then(|(_, lease_until)| *lease_until)
            .is_some_and(|lease_until| lease_until > deleted_at)
        {
            return Err(PostgresStoreError::ConnectorJobLeased);
        }
        // Same order as the installation-wide purge: the schedule (and, by cascade, its
        // backfill receipts) first, then the run receipts and ingestion ledger that reference
        // the instance, and the state row last so nothing points at a missing parent.
        let schedule_deleted =
            sqlx::query("DELETE FROM connector_jobs WHERE connector_instance_id = $1")
                .bind(connector_instance_id)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
        let runs_deleted =
            sqlx::query("DELETE FROM connector_runs WHERE connector_instance_id = $1")
                .bind(connector_instance_id)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
        let ingestion_batches_deleted =
            sqlx::query("DELETE FROM ingestion_batches WHERE connector_instance_id = $1")
                .bind(connector_instance_id)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
        sqlx::query("DELETE FROM connector_states WHERE connector_instance_id = $1")
            .bind(connector_instance_id)
            .execute(&mut *transaction)
            .await
            .map_err(connector_delete_error)?;
        sqlx::query("INSERT INTO identity_replay_jobs(installation_id) VALUES($1) ON CONFLICT(installation_id) DO UPDATE SET requested_generation=identity_replay_jobs.requested_generation+1,updated_at=now()")
            .bind(installation_id).execute(&mut *transaction).await?;
        let deletion = ConnectorDeletion {
            connector_instance_id,
            connector_type,
            display_name,
            friendly_name,
            job_id: job.map(|(job_id, _)| job_id),
            schedule_deleted: schedule_deleted > 0,
            runs_deleted,
            ingestion_batches_deleted,
            deleted_at,
        };
        sqlx::query(
            r"
            INSERT INTO audit_log (audit_id, at, actor, action, entity_type, entity_id, detail)
            VALUES ($1,$2,$5,'connector.deleted','connector',$3,$4)
            ",
        )
        .bind(Uuid::now_v7())
        .bind(deleted_at)
        .bind(connector_instance_id.to_string())
        .bind(serde_json::json!({
            "connector_type": deletion.connector_type,
            "job_id": deletion.job_id,
            "schedule_deleted": deletion.schedule_deleted,
            "runs_deleted": deletion.runs_deleted,
            "ingestion_batches_deleted": deletion.ingestion_batches_deleted,
            "observations_retained": true,
            "content_retained": false,
        }))
        .bind(audit_actor())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(deletion)
    }

    /// Previews a bounded cursor reset for one time-windowed pull connector.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the job is missing, belongs to another installation,
    /// does not support backfill, or the requested lookback is outside its source-specific bound.
    pub async fn preview_connector_backfill(
        &self,
        installation_id: Uuid,
        job_id: Uuid,
        lookback_seconds: u32,
    ) -> Result<ConnectorBackfillPreview, PostgresStoreError> {
        let value = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT jsonb_build_object(
                'installation_id', states.installation_id,
                'job', connector_job_json(jobs),
                'cursor_present', states.cursor_value <> ''
            )
            FROM connector_jobs jobs
            JOIN connector_states states
              ON states.connector_instance_id = jobs.connector_instance_id
            WHERE jobs.job_id = $1
            ",
        )
        .bind(job_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(PostgresStoreError::ConnectorJobNotFound)?;
        let state: ConnectorBackfillState = serde_json::from_value(value)?;
        if state.installation_id != installation_id {
            return Err(PostgresStoreError::ConnectorJobNotFound);
        }
        connector_backfill_preview(&state, lookback_seconds, Utc::now())
    }

    /// Commits a preview-bound connector cursor reset without deleting existing evidence.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the idempotency contract conflicts, the job is leased,
    /// the preview is stale, the source is ineligible, or persistence fails.
    #[allow(clippy::too_many_lines)] // One transaction keeps the cursor reset, receipt, and audit atomic.
    pub async fn commit_connector_backfill(
        &self,
        request: &ConnectorBackfillCommit,
    ) -> Result<ConnectorBackfillWrite, PostgresStoreError> {
        if !valid_lower_sha256(&request.preview_digest)
            || !valid_lower_sha256(&request.request_sha256)
        {
            return Err(PostgresStoreError::UnsafeConnectorBackfill);
        }
        let mut transaction = self.pool.begin().await?;
        if let Some((request_sha256, response)) = sqlx::query_as::<_, (String, serde_json::Value)>(
            r"
                SELECT request_sha256, response
                FROM connector_backfill_requests
                WHERE installation_id = $1 AND idempotency_key = $2
                ",
        )
        .bind(request.installation_id)
        .bind(request.idempotency_key)
        .fetch_optional(&mut *transaction)
        .await?
        {
            if request_sha256 != request.request_sha256 {
                return Err(PostgresStoreError::ConnectorBackfillIdempotencyConflict);
            }
            transaction.rollback().await?;
            return Ok(ConnectorBackfillWrite {
                receipt: serde_json::from_value(response)?,
                replayed: true,
            });
        }
        let value = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT jsonb_build_object(
                'installation_id', states.installation_id,
                'job', connector_job_json(jobs),
                'cursor_present', states.cursor_value <> ''
            )
            FROM connector_jobs jobs
            JOIN connector_states states
              ON states.connector_instance_id = jobs.connector_instance_id
            WHERE jobs.job_id = $1
            FOR UPDATE OF jobs, states
            ",
        )
        .bind(request.job_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(PostgresStoreError::ConnectorJobNotFound)?;
        let state: ConnectorBackfillState = serde_json::from_value(value)?;
        if state.installation_id != request.installation_id {
            return Err(PostgresStoreError::ConnectorJobNotFound);
        }
        if state
            .job
            .lease_until
            .is_some_and(|lease_until| lease_until > request.committed_at)
        {
            return Err(PostgresStoreError::ConnectorJobLeased);
        }
        let preview =
            connector_backfill_preview(&state, request.lookback_seconds, request.committed_at)?;
        if preview.preview_digest != request.preview_digest {
            return Err(PostgresStoreError::ConnectorBackfillPreviewChanged);
        }
        let scheduled_now = state.job.status == ConnectorJobStatus::Enabled;
        sqlx::query(
            r"
            UPDATE connector_jobs SET
                config_refs = jsonb_set(
                    config_refs, '{backfill_seconds}', to_jsonb(CAST($2 AS text)), true
                ),
                next_run_at = CASE WHEN status = 'enabled' THEN $3 ELSE NULL END,
                updated_at = $3
            WHERE job_id = $1
            ",
        )
        .bind(request.job_id)
        .bind(i64::from(request.lookback_seconds))
        .bind(request.committed_at)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE connector_states SET cursor_value = '', updated_at = $2 WHERE connector_instance_id = $1",
        )
        .bind(state.job.connector_instance_id)
        .bind(request.committed_at)
        .execute(&mut *transaction)
        .await?;

        let request_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!(
                "godel-tally:connector-backfill:{}:{}",
                request.installation_id, request.idempotency_key
            )
            .as_bytes(),
        );
        let receipt = ConnectorBackfillReceipt {
            request_id,
            job_id: request.job_id,
            connector_instance_id: state.job.connector_instance_id,
            source_kind: preview.source_kind,
            job_status: state.job.status,
            lookback_seconds: request.lookback_seconds,
            cursor_was_present: state.cursor_present,
            scheduled_now,
            preview_digest: request.preview_digest.clone(),
            committed_at: request.committed_at,
            content_retained: false,
        };
        let response = serde_json::to_value(&receipt)?;
        sqlx::query(
            r"
            INSERT INTO connector_backfill_requests (
                request_id, installation_id, job_id, connector_instance_id, idempotency_key,
                request_sha256, preview_digest, lookback_seconds, source_kind,
                cursor_was_present, scheduled_now, response, created_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
            ",
        )
        .bind(request_id)
        .bind(request.installation_id)
        .bind(request.job_id)
        .bind(state.job.connector_instance_id)
        .bind(request.idempotency_key)
        .bind(&request.request_sha256)
        .bind(&request.preview_digest)
        .bind(i64::from(request.lookback_seconds))
        .bind(enum_string(preview.source_kind, "cloud_flow_api")?)
        .bind(state.cursor_present)
        .bind(scheduled_now)
        .bind(response)
        .bind(request.committed_at)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO audit_log (audit_id, at, actor, action, entity_type, entity_id, detail)
            VALUES ($1,$2,$5,'connector.backfill.committed','connector_job',$3,$4)
            ",
        )
        .bind(Uuid::now_v7())
        .bind(request.committed_at)
        .bind(request.job_id.to_string())
        .bind(serde_json::json!({
            "request_id": request_id,
            "connector_instance_id": state.job.connector_instance_id,
            "source_kind": enum_string(preview.source_kind, "cloud_flow_api")?,
            "lookback_seconds": request.lookback_seconds,
            "cursor_was_present": state.cursor_present,
            "scheduled_now": scheduled_now,
            "preview_digest": request.preview_digest,
            "content_retained": false,
        }))
        .bind(audit_actor())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(ConnectorBackfillWrite {
            receipt,
            replayed: false,
        })
    }

    /// Returns the last durably completed cursor for a connector instance.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the cursor lookup fails.
    pub async fn connector_cursor(
        &self,
        connector_instance_id: Uuid,
    ) -> Result<Option<String>, PostgresStoreError> {
        sqlx::query_scalar(
            "SELECT cursor_value FROM connector_states WHERE connector_instance_id = $1",
        )
        .bind(connector_instance_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Returns the newest source timestamp committed for a connector.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the lookup fails.
    pub async fn connector_last_source_at(
        &self,
        connector_instance_id: Uuid,
    ) -> Result<Option<DateTime<Utc>>, PostgresStoreError> {
        sqlx::query_scalar(
            "SELECT last_source_at FROM connector_states WHERE connector_instance_id = $1",
        )
        .bind(connector_instance_id)
        .fetch_optional(&self.pool)
        .await
        .map(Option::flatten)
        .map_err(Into::into)
    }

    /// Persists one completed connector attempt and advances cumulative health statistics.
    ///
    /// A run ID is unique, so retrying the same database write does not double-count totals.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when a code is unsafe or the transaction fails.
    pub async fn record_connector_run(
        &self,
        run: &ConnectorRunRecord,
    ) -> Result<(), PostgresStoreError> {
        if run
            .error_code
            .as_deref()
            .is_some_and(|code| !safe_code(code))
        {
            return Err(PostgresStoreError::UnsafeFailureCode);
        }
        let mut transaction = self.pool.begin().await?;
        let inserted = sqlx::query_scalar::<_, Uuid>(
            r"
            INSERT INTO connector_runs (
                run_id, connector_instance_id, installation_id, connector_type, status,
                started_at, completed_at, cursor_before, cursor_after, first_source_at,
                last_source_at, records_read, accepted, ignored, rejected, deduplicated,
                batch_id, error_code, redaction_digest
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
            ON CONFLICT (run_id) DO NOTHING
            RETURNING run_id
            ",
        )
        .bind(run.run_id)
        .bind(run.connector_instance_id)
        .bind(run.installation_id)
        .bind(&run.connector_type)
        .bind(enum_string(run.status, "failed")?)
        .bind(run.started_at)
        .bind(run.completed_at)
        .bind(&run.cursor_before)
        .bind(&run.cursor_after)
        .bind(run.first_source_at)
        .bind(run.last_source_at)
        .bind(count_i64(run.records_read))
        .bind(count_i64(run.accepted))
        .bind(count_i64(run.ignored))
        .bind(count_i64(run.rejected))
        .bind(count_i64(run.deduplicated))
        .bind(run.batch_id)
        .bind(&run.error_code)
        .bind(&run.redaction_digest)
        .fetch_optional(&mut *transaction)
        .await?;
        if inserted.is_some() {
            let lag_seconds = run
                .last_source_at
                .map(|source_at| (run.completed_at - source_at).num_seconds().max(0));
            let health = match run.status {
                ConnectorRunStatus::Completed | ConnectorRunStatus::Duplicate
                    if lag_seconds.is_some_and(|lag| lag > 900) =>
                {
                    "delayed"
                }
                ConnectorRunStatus::Completed | ConnectorRunStatus::Duplicate => "healthy",
                ConnectorRunStatus::Failed => "error",
                ConnectorRunStatus::Cancelled => "paused",
            };
            sqlx::query(
                r"
                UPDATE connector_states SET
                    health = $2,
                    cursor_value = CASE WHEN $13 THEN $3 ELSE cursor_value END,
                    last_poll_at = $4,
                    last_source_at = GREATEST(last_source_at, $5),
                    lag_seconds = CASE WHEN $5 IS NULL THEN lag_seconds ELSE
                        GREATEST(0, EXTRACT(EPOCH FROM ($4 - $5))::bigint) END,
                    records_read_total = records_read_total + $6,
                    accepted_total = accepted_total + $7,
                    ignored_total = ignored_total + $8,
                    rejected_total = rejected_total + $9,
                    deduplicated_total = deduplicated_total + $10,
                    last_error_code = $11,
                    redaction_digest = $12,
                    updated_at = now()
                WHERE connector_instance_id = $1
                ",
            )
            .bind(run.connector_instance_id)
            .bind(health)
            .bind(&run.cursor_after)
            .bind(run.completed_at)
            .bind(run.last_source_at)
            .bind(count_i64(run.records_read))
            .bind(count_i64(run.accepted))
            .bind(count_i64(run.ignored))
            .bind(count_i64(run.rejected))
            .bind(count_i64(run.deduplicated))
            .bind(&run.error_code)
            .bind(&run.redaction_digest)
            .bind(matches!(
                run.status,
                ConnectorRunStatus::Completed | ConnectorRunStatus::Duplicate
            ))
            .execute(&mut *transaction)
            .await?;
            put_connector_run_audit(&mut transaction, run).await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Lists connector health projections for the console.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the query or projection decoding fails.
    pub async fn list_connector_states(
        &self,
    ) -> Result<Vec<ConnectorStateView>, PostgresStoreError> {
        let values = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT jsonb_build_object(
                'connector_instance_id', connector_instance_id,
                'connector_type', connector_type,
                'display_name', display_name,
                'friendly_name', friendly_name,
                'implementation_version', implementation_version,
                'transport', transport,
                'health', health,
                'cursor_value', cursor_value,
                'last_success_at', last_success_at,
                'last_poll_at', last_poll_at,
                'last_source_at', last_source_at,
                'lag_seconds', lag_seconds,
                'records_read_total', records_read_total,
                'accepted_total', accepted_total,
                'ignored_total', ignored_total,
                'rejected_total', rejected_total,
                'deduplicated_total', deduplicated_total,
                'last_error_code', last_error_code,
                'redaction_digest', redaction_digest,
                'descriptor', descriptor
            )
            FROM connector_states
            ORDER BY COALESCE(NULLIF(friendly_name, ''), display_name), connector_instance_id
            ",
        )
        .fetch_all(&self.pool)
        .await?;
        values
            .into_iter()
            .map(|value| {
                serde_json::from_value::<ConnectorStateView>(value).map(|mut state| {
                    if state.health == ConnectorHealth::Healthy
                        && state
                            .backlog_seconds(state.last_poll_at.unwrap_or_else(Utc::now))
                            .is_some_and(|lag| lag > 60)
                    {
                        state.health = ConnectorHealth::Delayed;
                    }
                    state
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Lists just the labels every registered connector answers to.
    ///
    /// The evidence feed resolves a connector label for every observation it renders, so it
    /// reads this instead of [`PostgresStore::list_connector_states`]: the health counters and
    /// the descriptor blob are dead weight on that path.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the query fails.
    pub async fn list_connector_labels(
        &self,
    ) -> Result<Vec<ConnectorLabelView>, PostgresStoreError> {
        sqlx::query_as::<_, (Uuid, String, String, String)>(
            r"
            SELECT connector_instance_id, connector_type, display_name, friendly_name
            FROM connector_states
            ",
        )
        .fetch_all(&self.pool)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(
                    |(connector_instance_id, connector_type, display_name, friendly_name)| {
                        ConnectorLabelView {
                            connector_instance_id,
                            connector_type,
                            display_name,
                            friendly_name,
                        }
                    },
                )
                .collect()
        })
        .map_err(Into::into)
    }

    /// Inserts or updates a stable entity record.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when serialization or persistence fails.
    pub async fn put_entity(&self, entity: &Entity) -> Result<(), PostgresStoreError> {
        sqlx::query(
            r"
            INSERT INTO entities (entity_id, kind, display_name, created_at, revision)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (entity_id) DO UPDATE SET
                display_name = EXCLUDED.display_name,
                revision = GREATEST(entities.revision, EXCLUDED.revision)
            ",
        )
        .bind(entity.entity_id)
        .bind(
            serde_json::to_value(entity.kind)?
                .as_str()
                .unwrap_or("unknown"),
        )
        .bind(&entity.display_name)
        .bind(entity.created_at)
        .bind(entity.revision)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Retrieves an entity by stable identifier.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when querying or deserializing the record fails.
    pub async fn get_entity(&self, entity_id: Uuid) -> Result<Option<Entity>, PostgresStoreError> {
        let value = sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT jsonb_build_object(\
                'entity_id', entity_id, \
                'kind', kind, \
                'display_name', display_name, \
                'created_at', created_at, \
                'revision', revision) \
             FROM entities WHERE entity_id = $1",
        )
        .bind(entity_id)
        .fetch_optional(&self.pool)
        .await?;
        value
            .map(serde_json::from_value)
            .transpose()
            .map_err(Into::into)
    }

    /// Lists a stable, installation-scoped page of graph entities without exposing entity keys.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when querying or decoding the graph projection fails.
    pub async fn list_entities(
        &self,
        installation_id: Uuid,
        kind: Option<EntityKind>,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<Entity>, PostgresStoreError> {
        let values = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT jsonb_build_object(
                'entity_id', e.entity_id,
                'kind', e.kind,
                'display_name', e.display_name,
                'created_at', e.created_at,
                'revision', e.revision
            )
            FROM entities e
            WHERE ($2::text IS NULL OR e.kind = $2)
              AND NOT EXISTS (
                SELECT 1 FROM entity_resolution_aliases a
                WHERE a.installation_id = $1 AND a.alias_entity_id = e.entity_id AND a.active
              )
              AND (
                EXISTS (
                    SELECT 1 FROM entity_keys k
                    WHERE k.installation_id = $1 AND k.entity_id = e.entity_id
                )
                OR EXISTS (
                    SELECT 1 FROM entity_relationships r
                    WHERE r.installation_id = $1
                      AND (r.subject_entity_id = e.entity_id OR r.object_entity_id = e.entity_id)
                )
                OR EXISTS (
                    SELECT 1 FROM ai_system_views v
                    WHERE v.installation_id = $1 AND v.system_id = e.entity_id
                )
              )
            ORDER BY e.created_at DESC, e.entity_id
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(installation_id)
        .bind(kind.map(enum_value).transpose()?)
        .bind(i64::from(limit.clamp(1, 500)))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await?;
        values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Counts installation-scoped graph entities for an optional kind.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the bounded count fails.
    pub async fn entity_count(
        &self,
        installation_id: Uuid,
        kind: Option<EntityKind>,
    ) -> Result<u64, PostgresStoreError> {
        let count = sqlx::query_scalar::<_, i64>(
            r"
            SELECT count(*)
            FROM entities e
            WHERE ($2::text IS NULL OR e.kind = $2)
              AND NOT EXISTS (
                SELECT 1 FROM entity_resolution_aliases a
                WHERE a.installation_id = $1 AND a.alias_entity_id = e.entity_id AND a.active
              )
              AND (
                EXISTS (
                    SELECT 1 FROM entity_keys k
                    WHERE k.installation_id = $1 AND k.entity_id = e.entity_id
                )
                OR EXISTS (
                    SELECT 1 FROM entity_relationships r
                    WHERE r.installation_id = $1
                      AND (r.subject_entity_id = e.entity_id OR r.object_entity_id = e.entity_id)
                )
                OR EXISTS (
                    SELECT 1 FROM ai_system_views v
                    WHERE v.installation_id = $1 AND v.system_id = e.entity_id
                )
              )
            ",
        )
        .bind(installation_id)
        .bind(kind.map(enum_value).transpose()?)
        .fetch_one(&self.pool)
        .await?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Loads an installation-scoped set of entities by stable identifier.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when querying or decoding the requested entities fails.
    pub async fn get_scoped_entities(
        &self,
        installation_id: Uuid,
        entity_ids: &[Uuid],
    ) -> Result<Vec<Entity>, PostgresStoreError> {
        if entity_ids.is_empty() {
            return Ok(Vec::new());
        }
        let values = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT jsonb_build_object(
                'entity_id', e.entity_id,
                'kind', e.kind,
                'display_name', e.display_name,
                'created_at', e.created_at,
                'revision', e.revision
            )
            FROM entities e
            WHERE e.entity_id = ANY($2)
              AND (
                EXISTS (
                    SELECT 1 FROM entity_keys k
                    WHERE k.installation_id = $1 AND k.entity_id = e.entity_id
                )
                OR EXISTS (
                    SELECT 1 FROM entity_relationships r
                    WHERE r.installation_id = $1
                      AND (r.subject_entity_id = e.entity_id OR r.object_entity_id = e.entity_id)
                )
                OR EXISTS (
                    SELECT 1 FROM ai_system_views v
                    WHERE v.installation_id = $1 AND v.system_id = e.entity_id
                )
              )
            ORDER BY e.entity_id
            ",
        )
        .bind(installation_id)
        .bind(entity_ids)
        .fetch_all(&self.pool)
        .await?;
        values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Builds a deterministic, content-free preview of an entity merge.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when either entity is outside the installation, revisions
    /// changed, entity kinds differ, or the requested projection would create an alias chain.
    pub async fn preview_entity_merge(
        &self,
        installation_id: Uuid,
        source_entity_id: Uuid,
        target_entity_id: Uuid,
        source_revision: i64,
        target_revision: i64,
    ) -> Result<EntityResolutionPreviewData, PostgresStoreError> {
        let state = self
            .entity_resolution_state(installation_id, source_entity_id, target_entity_id)
            .await?;
        build_entity_resolution_preview(
            EntityResolutionOperation::Merge,
            state,
            source_revision,
            target_revision,
            None,
        )
    }

    /// Builds a deterministic preview that reverses one active merge event.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the active alias no longer matches the supplied merge
    /// event, either revision changed, or the entities are outside the installation.
    pub async fn preview_entity_split(
        &self,
        installation_id: Uuid,
        source_entity_id: Uuid,
        target_entity_id: Uuid,
        source_revision: i64,
        target_revision: i64,
        merge_event_id: Uuid,
    ) -> Result<EntityResolutionPreviewData, PostgresStoreError> {
        let state = self
            .entity_resolution_state(installation_id, source_entity_id, target_entity_id)
            .await?;
        build_entity_resolution_preview(
            EntityResolutionOperation::Split,
            state,
            source_revision,
            target_revision,
            Some(merge_event_id),
        )
    }

    /// Commits a previewed merge or split as an append-only, idempotent resolution event.
    ///
    /// The immutable attribution ledger is never rewritten. Only the reversible alias projection
    /// changes, and both entity revisions advance so stale previews fail closed.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] for a stale preview, invalid resolution topology,
    /// idempotency mismatch, or persistence failure.
    #[allow(clippy::too_many_lines)] // One auditable transaction keeps validation, alias, revision, and audit atomic.
    pub async fn commit_entity_resolution(
        &self,
        request: &EntityResolutionCommit,
    ) -> Result<EntityResolutionWrite, PostgresStoreError> {
        validate_entity_resolution_commit(request)?;
        let mut transaction = self.pool.begin().await?;

        if let Some((request_sha256, value)) = sqlx::query_as::<_, (String, serde_json::Value)>(
            r"
                SELECT request_sha256, jsonb_build_object(
                    'event_id', event_id,
                    'installation_id', installation_id,
                    'operation', operation,
                    'source_entity_id', source_entity_id,
                    'target_entity_id', target_entity_id,
                    'source_display_name', (
                        SELECT display_name FROM entities WHERE entity_id = source_entity_id
                    ),
                    'target_display_name', (
                        SELECT display_name FROM entities WHERE entity_id = target_entity_id
                    ),
                    'merge_event_id', merge_event_id,
                    'source_revision', source_revision,
                    'target_revision', target_revision,
                    'source_current_revision', (
                        SELECT revision FROM entities WHERE entity_id = source_entity_id
                    ),
                    'target_current_revision', (
                        SELECT revision FROM entities WHERE entity_id = target_entity_id
                    ),
                    'active', operation = 'merge' AND EXISTS (
                        SELECT 1 FROM entity_resolution_aliases a
                        WHERE a.installation_id = entity_resolution_events.installation_id
                          AND a.merge_event_id = entity_resolution_events.event_id AND a.active
                    ),
                    'preview_digest', preview_digest,
                    'created_at', created_at,
                    'created_by', created_by,
                    'content_retained', content_retained
                )
                FROM entity_resolution_events
                WHERE installation_id = $1 AND idempotency_key = $2
                FOR UPDATE
                ",
        )
        .bind(request.installation_id)
        .bind(request.idempotency_key)
        .fetch_optional(&mut *transaction)
        .await?
        {
            if request_sha256 != request.request_sha256 {
                return Err(PostgresStoreError::EntityResolutionIdempotencyConflict);
            }
            let event = serde_json::from_value(value)?;
            transaction.commit().await?;
            return Ok(EntityResolutionWrite {
                event,
                replayed: true,
            });
        }

        let locked = sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT entity_id FROM entities
            WHERE entity_id = ANY($1)
            ORDER BY entity_id
            FOR UPDATE
            ",
        )
        .bind([request.source_entity_id, request.target_entity_id])
        .fetch_all(&mut *transaction)
        .await?;
        if locked.len() != 2 {
            return Err(PostgresStoreError::EntityResolutionEntityNotFound);
        }
        sqlx::query(
            r"
            SELECT alias_entity_id FROM entity_resolution_aliases
            WHERE installation_id = $1
              AND (
                alias_entity_id = ANY($2)
                OR canonical_entity_id = ANY($2)
              )
            ORDER BY alias_entity_id
            FOR UPDATE
            ",
        )
        .bind(request.installation_id)
        .bind([request.source_entity_id, request.target_entity_id])
        .fetch_all(&mut *transaction)
        .await?;

        let value = sqlx::query_scalar::<_, serde_json::Value>(ENTITY_RESOLUTION_STATE_SQL)
            .bind(request.installation_id)
            .bind(request.source_entity_id)
            .bind(request.target_entity_id)
            .fetch_one(&mut *transaction)
            .await?;
        let state: EntityResolutionState = serde_json::from_value(value)?;
        let preview = build_entity_resolution_preview(
            request.operation,
            state,
            request.source_revision,
            request.target_revision,
            request.merge_event_id,
        )?;
        if preview.preview_digest != request.preview_digest {
            return Err(PostgresStoreError::EntityResolutionPreviewChanged);
        }

        let event_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!(
                "godel-tally:entity-resolution-event:{}:{}",
                request.installation_id, request.idempotency_key
            )
            .as_bytes(),
        );
        let operation = enum_value(request.operation)?;
        sqlx::query(
            r"
            INSERT INTO entity_resolution_events (
                event_id, installation_id, operation, source_entity_id, target_entity_id,
                merge_event_id, source_revision, target_revision, preview_digest,
                request_sha256, idempotency_key, created_at, created_by, content_retained
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'local_operator',FALSE)
            ",
        )
        .bind(event_id)
        .bind(request.installation_id)
        .bind(operation)
        .bind(request.source_entity_id)
        .bind(request.target_entity_id)
        .bind(request.merge_event_id)
        .bind(request.source_revision)
        .bind(request.target_revision)
        .bind(&request.preview_digest)
        .bind(&request.request_sha256)
        .bind(request.idempotency_key)
        .bind(request.created_at)
        .execute(&mut *transaction)
        .await?;

        match request.operation {
            EntityResolutionOperation::Merge => {
                sqlx::query(
                    r"
                    INSERT INTO entity_resolution_aliases (
                        installation_id, alias_entity_id, canonical_entity_id, merge_event_id,
                        active, created_at, retired_at, retired_by_event_id
                    ) VALUES ($1,$2,$3,$4,TRUE,$5,NULL,NULL)
                    ON CONFLICT (installation_id, alias_entity_id) DO UPDATE SET
                        canonical_entity_id = EXCLUDED.canonical_entity_id,
                        merge_event_id = EXCLUDED.merge_event_id,
                        active = TRUE,
                        created_at = EXCLUDED.created_at,
                        retired_at = NULL,
                        retired_by_event_id = NULL
                    WHERE NOT entity_resolution_aliases.active
                    ",
                )
                .bind(request.installation_id)
                .bind(request.source_entity_id)
                .bind(request.target_entity_id)
                .bind(event_id)
                .bind(request.created_at)
                .execute(&mut *transaction)
                .await?;
            }
            EntityResolutionOperation::Split => {
                let changed = sqlx::query(
                    r"
                    UPDATE entity_resolution_aliases SET
                        active = FALSE,
                        retired_at = $5,
                        retired_by_event_id = $6
                    WHERE installation_id = $1 AND alias_entity_id = $2
                      AND canonical_entity_id = $3 AND merge_event_id = $4 AND active
                    ",
                )
                .bind(request.installation_id)
                .bind(request.source_entity_id)
                .bind(request.target_entity_id)
                .bind(request.merge_event_id)
                .bind(request.created_at)
                .bind(event_id)
                .execute(&mut *transaction)
                .await?;
                if changed.rows_affected() != 1 {
                    return Err(PostgresStoreError::InvalidEntityResolution);
                }
            }
        }

        sqlx::query("UPDATE entities SET revision = revision + 1 WHERE entity_id = ANY($1)")
            .bind([request.source_entity_id, request.target_entity_id])
            .execute(&mut *transaction)
            .await?;
        sqlx::query("UPDATE ai_system_views SET revision = revision + 1 WHERE system_id = ANY($1)")
            .bind([request.source_entity_id, request.target_entity_id])
            .execute(&mut *transaction)
            .await?;

        sqlx::query(
            r"
            INSERT INTO audit_log (audit_id, at, actor, action, entity_type, entity_id, detail)
            VALUES ($1,$2,$6,$3,'entity_resolution',$4,$5)
            ",
        )
        .bind(Uuid::now_v7())
        .bind(request.created_at)
        .bind(match request.operation {
            EntityResolutionOperation::Merge => "entity_resolution.merged",
            EntityResolutionOperation::Split => "entity_resolution.split",
        })
        .bind(event_id.to_string())
        .bind(serde_json::json!({
            "source_entity_id": request.source_entity_id,
            "target_entity_id": request.target_entity_id,
            "merge_event_id": request.merge_event_id,
            "preview_digest": request.preview_digest,
            "key_count": preview.impact.key_count,
            "claim_count": preview.impact.claim_count,
            "relationship_count": preview.impact.relationship_count,
            "finding_count": preview.impact.finding_count,
            "evidence_mutated": false,
            "content_retained": false,
        }))
        .bind(audit_actor())
        .execute(&mut *transaction)
        .await?;

        let event = EntityResolutionEventView {
            event_id,
            installation_id: request.installation_id,
            operation: request.operation,
            source_entity_id: request.source_entity_id,
            target_entity_id: request.target_entity_id,
            source_display_name: preview.source.display_name,
            target_display_name: preview.target.display_name,
            merge_event_id: request.merge_event_id,
            source_revision: request.source_revision,
            target_revision: request.target_revision,
            source_current_revision: request.source_revision + 1,
            target_current_revision: request.target_revision + 1,
            active: matches!(request.operation, EntityResolutionOperation::Merge),
            preview_digest: request.preview_digest.clone(),
            created_at: request.created_at,
            created_by: "local_operator".to_owned(),
            content_retained: false,
        };
        transaction.commit().await?;
        Ok(EntityResolutionWrite {
            event,
            replayed: false,
        })
    }

    /// Lists the recent append-only entity-resolution ledger for operator undo and audit views.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the bounded ledger query or decoding fails.
    pub async fn list_entity_resolution_events(
        &self,
        installation_id: Uuid,
        limit: u16,
    ) -> Result<Vec<EntityResolutionEventView>, PostgresStoreError> {
        let values = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT jsonb_build_object(
                'event_id', event_id,
                'installation_id', installation_id,
                'operation', operation,
                'source_entity_id', source_entity_id,
                'target_entity_id', target_entity_id,
                'source_display_name', (
                    SELECT display_name FROM entities WHERE entity_id = source_entity_id
                ),
                'target_display_name', (
                    SELECT display_name FROM entities WHERE entity_id = target_entity_id
                ),
                'merge_event_id', merge_event_id,
                'source_revision', source_revision,
                'target_revision', target_revision,
                'source_current_revision', (
                    SELECT revision FROM entities WHERE entity_id = source_entity_id
                ),
                'target_current_revision', (
                    SELECT revision FROM entities WHERE entity_id = target_entity_id
                ),
                'active', operation = 'merge' AND EXISTS (
                    SELECT 1 FROM entity_resolution_aliases a
                    WHERE a.installation_id = entity_resolution_events.installation_id
                      AND a.merge_event_id = entity_resolution_events.event_id AND a.active
                ),
                'preview_digest', preview_digest,
                'created_at', created_at,
                'created_by', created_by,
                'content_retained', content_retained
            )
            FROM entity_resolution_events
            WHERE installation_id = $1
            ORDER BY created_at DESC, event_id DESC
            LIMIT $2
            ",
        )
        .bind(installation_id)
        .bind(i64::from(limit.clamp(1, 200)))
        .fetch_all(&self.pool)
        .await?;
        values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    async fn entity_resolution_state(
        &self,
        installation_id: Uuid,
        source_entity_id: Uuid,
        target_entity_id: Uuid,
    ) -> Result<EntityResolutionState, PostgresStoreError> {
        let value = sqlx::query_scalar::<_, serde_json::Value>(ENTITY_RESOLUTION_STATE_SQL)
            .bind(installation_id)
            .bind(source_entity_id)
            .bind(target_entity_id)
            .fetch_one(&self.pool)
            .await?;
        serde_json::from_value(value).map_err(Into::into)
    }

    /// Persists a time-valid authoritative key without allowing arrival order to move it between
    /// entities. Exact replays are no-ops; material changes require a higher revision.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the contract is unsafe, the key is already bound to a
    /// different entity, a stale revision is supplied, or persistence fails.
    pub async fn put_entity_key(&self, key: &EntityKey) -> Result<(), PostgresStoreError> {
        key.validate()?;
        let authority = enum_value(key.authority)?;
        let status = enum_value(key.status)?;
        let stored = sqlx::query_scalar::<_, Uuid>(
            r"
            INSERT INTO entity_keys (
                installation_id, key_type, key_value, entity_id, first_seen, last_seen,
                source_authority, strength_bps, status, source_observation_id,
                source_lineage_id, revision
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
            ON CONFLICT (installation_id, key_type, key_value) DO UPDATE SET
                first_seen = LEAST(entity_keys.first_seen, EXCLUDED.first_seen),
                last_seen = GREATEST(entity_keys.last_seen, EXCLUDED.last_seen),
                source_authority = EXCLUDED.source_authority,
                strength_bps = EXCLUDED.strength_bps,
                status = EXCLUDED.status,
                source_observation_id = CASE
                    WHEN EXCLUDED.last_seen >= entity_keys.last_seen
                    THEN EXCLUDED.source_observation_id
                    ELSE entity_keys.source_observation_id
                END,
                source_lineage_id = CASE
                    WHEN EXCLUDED.last_seen >= entity_keys.last_seen
                    THEN EXCLUDED.source_lineage_id
                    ELSE entity_keys.source_lineage_id
                END,
                revision = GREATEST(entity_keys.revision, EXCLUDED.revision)
            WHERE entity_keys.entity_id = EXCLUDED.entity_id
              AND (
                entity_keys.revision < EXCLUDED.revision
                OR (
                    entity_keys.source_authority = EXCLUDED.source_authority
                    AND entity_keys.strength_bps = EXCLUDED.strength_bps
                    AND entity_keys.status = EXCLUDED.status
                )
              )
            RETURNING entity_id
            ",
        )
        .bind(key.installation_id)
        .bind(&key.key_type)
        .bind(&key.key_value)
        .bind(key.entity_id)
        .bind(key.first_seen)
        .bind(key.last_seen)
        .bind(authority)
        .bind(i32::from(key.strength.get()))
        .bind(status)
        .bind(key.source_observation_id)
        .bind(&key.source_lineage_id)
        .bind(key.revision)
        .fetch_optional(&self.pool)
        .await?;
        if stored.is_none() {
            return Err(PostgresStoreError::EntityKeyConflict);
        }
        Ok(())
    }

    /// Persists a deterministic relationship and its immutable evidence links atomically.
    /// Independent lineage count is recomputed from supporting evidence rather than trusted from
    /// the caller.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the relationship/evidence contract is invalid, evidence
    /// is missing, revisions conflict, or persistence fails.
    pub async fn put_entity_relationship(
        &self,
        relationship: &EntityRelationship,
        evidence: &[RelationshipEvidence],
    ) -> Result<EntityRelationship, PostgresStoreError> {
        validate_relationship_write(relationship, evidence)?;
        let mut transaction = self.pool.begin().await?;
        Self::put_entity_relationship_transaction(&mut transaction, relationship, evidence).await?;
        transaction.commit().await?;

        self.get_entity_relationship(relationship.installation_id, relationship.relationship_id)
            .await?
            .ok_or(PostgresStoreError::RelationshipNotFound)
    }

    async fn put_entity_relationship_transaction(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        relationship: &EntityRelationship,
        evidence: &[RelationshipEvidence],
    ) -> Result<(), PostgresStoreError> {
        let predicate = enum_value(relationship.predicate)?;
        let status = enum_value(relationship.status)?;
        let rule = relationship
            .rule
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?;
        let stored = sqlx::query_scalar::<_, Uuid>(
            r"
            INSERT INTO entity_relationships (
                relationship_id, installation_id, subject_entity_id, predicate,
                object_entity_id, confidence_bps, status, valid_from, valid_until, rule,
                independent_lineage_count, created_at, revision
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,0,$11,$12)
            ON CONFLICT (relationship_id) DO UPDATE SET
                confidence_bps = EXCLUDED.confidence_bps,
                status = EXCLUDED.status,
                valid_from = LEAST(entity_relationships.valid_from, EXCLUDED.valid_from),
                valid_until = CASE
                    WHEN entity_relationships.revision < EXCLUDED.revision
                        THEN EXCLUDED.valid_until
                    WHEN entity_relationships.valid_until IS NULL
                        THEN NULL
                    WHEN EXCLUDED.valid_until IS NULL
                        THEN entity_relationships.valid_until
                    ELSE GREATEST(entity_relationships.valid_until, EXCLUDED.valid_until)
                END,
                rule = EXCLUDED.rule,
                created_at = LEAST(entity_relationships.created_at, EXCLUDED.created_at),
                revision = GREATEST(entity_relationships.revision, EXCLUDED.revision)
            WHERE entity_relationships.installation_id = EXCLUDED.installation_id
              AND entity_relationships.subject_entity_id = EXCLUDED.subject_entity_id
              AND entity_relationships.predicate = EXCLUDED.predicate
              AND entity_relationships.object_entity_id = EXCLUDED.object_entity_id
              AND (
                entity_relationships.revision < EXCLUDED.revision
                OR (
                    entity_relationships.confidence_bps = EXCLUDED.confidence_bps
                    AND entity_relationships.status = EXCLUDED.status
                    AND entity_relationships.rule IS NOT DISTINCT FROM EXCLUDED.rule
                )
              )
            RETURNING relationship_id
            ",
        )
        .bind(relationship.relationship_id)
        .bind(relationship.installation_id)
        .bind(relationship.subject.entity_id)
        .bind(predicate)
        .bind(relationship.object.entity_id)
        .bind(i32::from(relationship.confidence.get()))
        .bind(status)
        .bind(relationship.valid_from)
        .bind(relationship.valid_until)
        .bind(rule)
        .bind(relationship.created_at)
        .bind(relationship.revision)
        .fetch_optional(&mut **transaction)
        .await?;
        if stored.is_none() {
            return Err(PostgresStoreError::RelationshipRevisionConflict);
        }

        Self::put_relationship_evidence(transaction, evidence).await?;
        sqlx::query(
            r"
            UPDATE entity_relationships
            SET independent_lineage_count = (
                SELECT count(DISTINCT source_lineage_id)
                FROM relationship_evidence
                WHERE relationship_id = $1 AND support_role = 'supporting'
            )
            WHERE relationship_id = $1
            ",
        )
        .bind(relationship.relationship_id)
        .execute(&mut **transaction)
        .await?;
        Ok(())
    }

    async fn put_relationship_evidence(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        evidence: &[RelationshipEvidence],
    ) -> Result<(), PostgresStoreError> {
        for item in evidence {
            let support_role = enum_value(item.support_role)?;
            let stored = sqlx::query_scalar::<_, Uuid>(
                r"
                INSERT INTO relationship_evidence (
                    relationship_id, observation_id, source_lineage_id, support_role,
                    valid_from, valid_until
                ) VALUES ($1,$2,$3,$4,$5,$6)
                ON CONFLICT (relationship_id, observation_id) DO UPDATE SET
                    source_lineage_id = EXCLUDED.source_lineage_id
                WHERE relationship_evidence.source_lineage_id = EXCLUDED.source_lineage_id
                  AND relationship_evidence.support_role = EXCLUDED.support_role
                  AND relationship_evidence.valid_from IS NOT DISTINCT FROM EXCLUDED.valid_from
                  AND relationship_evidence.valid_until IS NOT DISTINCT FROM EXCLUDED.valid_until
                RETURNING observation_id
                ",
            )
            .bind(item.relationship_id)
            .bind(item.observation_id)
            .bind(&item.source_lineage_id)
            .bind(support_role)
            .bind(item.valid_from)
            .bind(item.valid_until)
            .fetch_optional(&mut **transaction)
            .await?;
            if stored.is_none() {
                return Err(PostgresStoreError::RelationshipEvidenceConflict);
            }
        }
        Ok(())
    }

    /// Retrieves one relationship with typed subject/object entities.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the graph projection cannot be decoded.
    pub async fn get_entity_relationship(
        &self,
        installation_id: Uuid,
        relationship_id: Uuid,
    ) -> Result<Option<EntityRelationship>, PostgresStoreError> {
        let value = sqlx::query_scalar::<_, serde_json::Value>(RELATIONSHIP_JSON_SELECT)
            .bind(installation_id)
            .bind(relationship_id)
            .fetch_optional(&self.pool)
            .await?;
        value
            .map(serde_json::from_value)
            .transpose()
            .map_err(Into::into)
    }

    /// Lists a bounded, stable page of relationships adjacent to an optional entity.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the graph query or decoding fails.
    pub async fn list_entity_relationships(
        &self,
        installation_id: Uuid,
        adjacent_to: Option<Uuid>,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<EntityRelationship>, PostgresStoreError> {
        let values = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT jsonb_build_object(
                'relationship_id', r.relationship_id,
                'installation_id', r.installation_id,
                'subject', jsonb_build_object('entity_id', r.subject_entity_id, 'kind', se.kind),
                'predicate', r.predicate,
                'object', jsonb_build_object('entity_id', r.object_entity_id, 'kind', oe.kind),
                'confidence', r.confidence_bps,
                'status', r.status,
                'valid_from', r.valid_from,
                'valid_until', r.valid_until,
                'rule', r.rule,
                'independent_lineage_count', r.independent_lineage_count,
                'created_at', r.created_at,
                'revision', r.revision
            )
            FROM entity_relationships r
            JOIN entities se ON se.entity_id = r.subject_entity_id
            JOIN entities oe ON oe.entity_id = r.object_entity_id
            WHERE r.installation_id = $1
              AND ($2::uuid IS NULL OR r.subject_entity_id = $2 OR r.object_entity_id = $2)
            ORDER BY r.valid_from DESC, r.relationship_id
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(installation_id)
        .bind(adjacent_to)
        .bind(i64::from(limit.clamp(1, 500)))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await?;
        values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Counts relationships adjacent to an optional entity within one installation.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the bounded count fails.
    pub async fn entity_relationship_count(
        &self,
        installation_id: Uuid,
        adjacent_to: Option<Uuid>,
    ) -> Result<u64, PostgresStoreError> {
        let count = sqlx::query_scalar::<_, i64>(
            r"
            SELECT count(*)
            FROM entity_relationships
            WHERE installation_id = $1
              AND ($2::uuid IS NULL OR subject_entity_id = $2 OR object_entity_id = $2)
            ",
        )
        .bind(installation_id)
        .bind(adjacent_to)
        .fetch_one(&self.pool)
        .await?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Lists current relationships adjacent to a bounded entity frontier for graph expansion.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the graph query or projection decoding fails.
    pub async fn list_graph_relationships(
        &self,
        installation_id: Uuid,
        adjacent_to: &[Uuid],
        limit: u16,
    ) -> Result<Vec<GraphRelationshipView>, PostgresStoreError> {
        if adjacent_to.is_empty() {
            return Ok(Vec::new());
        }
        let values = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT jsonb_build_object(
                'relationship', jsonb_build_object(
                    'relationship_id', r.relationship_id,
                    'installation_id', r.installation_id,
                    'subject', jsonb_build_object(
                        'entity_id', COALESCE(subject_alias.canonical_entity_id, r.subject_entity_id),
                        'kind', se.kind
                    ),
                    'predicate', r.predicate,
                    'object', jsonb_build_object(
                        'entity_id', COALESCE(object_alias.canonical_entity_id, r.object_entity_id),
                        'kind', oe.kind
                    ),
                    'confidence', r.confidence_bps,
                    'status', r.status,
                    'valid_from', r.valid_from,
                    'valid_until', r.valid_until,
                    'rule', r.rule,
                    'independent_lineage_count', r.independent_lineage_count,
                    'created_at', r.created_at,
                    'revision', r.revision
                ),
                'evidence_observation_ids', COALESCE((
                    SELECT jsonb_agg(DISTINCT evidence.observation_id ORDER BY evidence.observation_id)
                    FROM relationship_evidence evidence
                    WHERE evidence.relationship_id = r.relationship_id
                ), '[]'::jsonb),
                'source_lineage_ids', COALESCE((
                    SELECT jsonb_agg(DISTINCT evidence.source_lineage_id ORDER BY evidence.source_lineage_id)
                    FROM relationship_evidence evidence
                    WHERE evidence.relationship_id = r.relationship_id
                ), '[]'::jsonb)
            )
            FROM entity_relationships r
            LEFT JOIN entity_resolution_aliases subject_alias
              ON subject_alias.installation_id = r.installation_id
             AND subject_alias.alias_entity_id = r.subject_entity_id AND subject_alias.active
            LEFT JOIN entity_resolution_aliases object_alias
              ON object_alias.installation_id = r.installation_id
             AND object_alias.alias_entity_id = r.object_entity_id AND object_alias.active
            JOIN entities se
              ON se.entity_id = COALESCE(subject_alias.canonical_entity_id, r.subject_entity_id)
            JOIN entities oe
              ON oe.entity_id = COALESCE(object_alias.canonical_entity_id, r.object_entity_id)
            WHERE r.installation_id = $1
              AND r.status IN ('active', 'disputed')
              AND COALESCE(subject_alias.canonical_entity_id, r.subject_entity_id)
                    <> COALESCE(object_alias.canonical_entity_id, r.object_entity_id)
              AND (
                COALESCE(subject_alias.canonical_entity_id, r.subject_entity_id) = ANY($2)
                OR COALESCE(object_alias.canonical_entity_id, r.object_entity_id) = ANY($2)
              )
            ORDER BY r.valid_from DESC, r.relationship_id
            LIMIT $3
            ",
        )
        .bind(installation_id)
        .bind(adjacent_to)
        .bind(i64::from(limit.clamp(1, 501)).saturating_mul(16).min(10_000))
        .fetch_all(&self.pool)
        .await?;
        let rows = values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<CanonicalGraphRelationshipRow>, _>>()?;
        Ok(canonicalize_graph_relationships(rows, limit.clamp(1, 501)))
    }

    /// Finds bounded, exact cloud network usage paths and competing mapping conflicts.
    ///
    /// The query operates only on pseudonymous entity UUIDs, time-valid relationship evidence,
    /// and resolver-controlled rule identifiers. No source address or provider identifier is
    /// present in this projection surface.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the graph query fails, the bounded row cap is reached,
    /// or a stored time-valid evidence row cannot be projected safely.
    #[allow(clippy::too_many_lines)] // The bulk of this function is one auditable bounded SQL CTE.
    pub async fn scan_cloud_usage_projections(
        &self,
        installation_id: Uuid,
        limit: u16,
    ) -> Result<CloudUsageProjectionScan, PostgresStoreError> {
        let flow_limit = i64::from(limit.clamp(1, 10_000));
        let row_cap = flow_limit.saturating_mul(64).min(100_000);
        let rows = sqlx::query_as::<_, CloudUsagePathRow>(
            r"
            WITH flow_rows AS (
                SELECT
                    flow.installation_id,
                    account_network.subject_entity_id AS account_id,
                    flow.subject_entity_id AS source_asset_id,
                    flow.object_entity_id AS destination_asset_id,
                    flow.relationship_id AS flow_relationship_id,
                    flow_evidence.observation_id AS flow_observation_id,
                    flow_evidence.source_lineage_id AS flow_lineage_id,
                    flow_evidence.valid_from AS flow_valid_from,
                    flow_evidence.valid_until AS flow_valid_until
                FROM entity_relationships flow
                JOIN entities source_asset
                  ON source_asset.entity_id = flow.subject_entity_id
                 AND source_asset.kind = 'network_asset'
                JOIN entities destination_asset
                  ON destination_asset.entity_id = flow.object_entity_id
                 AND destination_asset.kind = 'network_asset'
                JOIN relationship_evidence flow_evidence
                  ON flow_evidence.relationship_id = flow.relationship_id
                 AND flow_evidence.support_role = 'supporting'
                 AND flow_evidence.valid_from IS NOT NULL
                 AND flow_evidence.valid_until IS NOT NULL
                JOIN entity_relationships network_contains
                  ON network_contains.installation_id = flow.installation_id
                 AND network_contains.predicate = 'contains'
                 AND network_contains.status = 'active'
                 AND network_contains.object_entity_id = flow.object_entity_id
                JOIN entities network
                  ON network.entity_id = network_contains.subject_entity_id
                 AND network.kind = 'network_zone'
                JOIN entity_relationships account_network
                  ON account_network.installation_id = flow.installation_id
                 AND account_network.predicate = 'contains'
                 AND account_network.status = 'active'
                 AND account_network.object_entity_id = network.entity_id
                JOIN entities account
                  ON account.entity_id = account_network.subject_entity_id
                 AND account.kind = 'cloud_account'
                WHERE flow.installation_id = $1
                  AND flow.predicate = 'uses'
                  AND flow.status = 'active'
                  AND flow.rule->>'rule_id' = 'cloud_network_exact_key'
                  AND flow_evidence.valid_until > flow_evidence.valid_from
                ORDER BY flow_evidence.valid_from, flow_evidence.observation_id
                LIMIT $2
            ),
            mapping_rows AS (
                SELECT
                    flow.*,
                    mapping.relationship_id AS mapping_relationship_id,
                    mapping.object_entity_id AS mapped_resource_id,
                    mapping_evidence.observation_id AS mapping_observation_id,
                    mapping_evidence.source_lineage_id AS mapping_lineage_id,
                    mapping_evidence.valid_from AS mapping_valid_from,
                    mapping_evidence.valid_until AS mapping_valid_until
                FROM flow_rows flow
                JOIN entity_relationships mapping
                  ON mapping.installation_id = flow.installation_id
                 AND mapping.predicate = 'address_of'
                 AND mapping.status = 'active'
                 AND mapping.subject_entity_id = flow.destination_asset_id
                 AND mapping.rule->>'rule_id' = 'cloud_network_exact_key'
                JOIN entities resource
                  ON resource.entity_id = mapping.object_entity_id
                 AND resource.kind = 'cloud_resource'
                JOIN relationship_evidence mapping_evidence
                  ON mapping_evidence.relationship_id = mapping.relationship_id
                 AND mapping_evidence.support_role = 'supporting'
                 AND mapping_evidence.valid_from IS NOT NULL
                WHERE mapping_evidence.valid_from < flow.flow_valid_until
                  AND COALESCE(mapping_evidence.valid_until, 'infinity'::timestamptz)
                      > flow.flow_valid_from
            ),
            mapping_counts AS (
                SELECT installation_id, flow_relationship_id, flow_observation_id,
                       count(DISTINCT mapping_relationship_id) AS mapping_count
                FROM mapping_rows
                GROUP BY installation_id, flow_relationship_id, flow_observation_id
            )
            SELECT
                mapping.installation_id,
                mapping.source_asset_id,
                mapping.destination_asset_id,
                mapping.flow_relationship_id,
                mapping.flow_observation_id,
                mapping.flow_lineage_id,
                mapping.flow_valid_from,
                mapping.flow_valid_until,
                mapping.mapping_relationship_id,
                mapping.mapped_resource_id,
                mapping.mapping_observation_id,
                mapping.mapping_lineage_id,
                mapping.mapping_valid_from,
                mapping.mapping_valid_until,
                counts.mapping_count,
                serves.relationship_id AS serves_relationship_id,
                serves.object_entity_id AS system_id,
                inventory_evidence.observation_id AS inventory_observation_id,
                inventory_evidence.source_lineage_id AS inventory_lineage_id,
                inventory_evidence.valid_from AS inventory_valid_from,
                inventory_evidence.valid_until AS inventory_valid_until
            FROM mapping_rows mapping
            JOIN mapping_counts counts
              ON counts.installation_id = mapping.installation_id
             AND counts.flow_relationship_id = mapping.flow_relationship_id
             AND counts.flow_observation_id = mapping.flow_observation_id
            LEFT JOIN entity_relationships account_scope
              ON account_scope.installation_id = mapping.installation_id
             AND account_scope.subject_entity_id = mapping.account_id
             AND account_scope.predicate = 'contains'
             AND account_scope.status = 'active'
            LEFT JOIN entities scope
              ON scope.entity_id = account_scope.object_entity_id
             AND scope.kind = 'organization_scope'
            LEFT JOIN entity_relationships scope_resource
              ON scope_resource.installation_id = mapping.installation_id
             AND scope_resource.subject_entity_id = scope.entity_id
             AND scope_resource.object_entity_id = mapping.mapped_resource_id
             AND scope_resource.predicate = 'contains'
             AND scope_resource.status = 'active'
            LEFT JOIN entity_relationships serves
              ON serves.installation_id = mapping.installation_id
             AND serves.subject_entity_id = scope_resource.object_entity_id
             AND serves.predicate = 'serves'
             AND serves.status = 'active'
            LEFT JOIN entities system
              ON system.entity_id = serves.object_entity_id
             AND system.kind = 'ai_system'
            LEFT JOIN relationship_evidence inventory_evidence
              ON inventory_evidence.relationship_id = serves.relationship_id
             AND inventory_evidence.support_role = 'supporting'
            ORDER BY mapping.flow_valid_from, mapping.flow_observation_id,
                     mapping.mapping_relationship_id, mapping.mapping_observation_id,
                     serves.relationship_id, inventory_evidence.observation_id
            LIMIT $3
            ",
        )
        .bind(installation_id)
        .bind(flow_limit)
        .bind(row_cap)
        .fetch_all(&self.pool)
        .await?;
        if i64::try_from(rows.len()).unwrap_or(i64::MAX) == row_cap {
            return Err(PostgresStoreError::CloudUsageProjectionTooLarge);
        }
        project_cloud_usage_rows(rows)
    }

    /// Atomically persists one derived usage relationship, bounded claim, and every supporting
    /// flow, mapping, and inventory evidence link.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the projection is inconsistent, conflicts with an
    /// immutable replay, or cannot be committed atomically.
    pub async fn put_cloud_usage_projection(
        &self,
        projection: &ResolvedCloudUsage,
    ) -> Result<(), PostgresStoreError> {
        validate_relationship_write(&projection.relationship, &projection.relationship_evidence)?;
        if projection.claim.subject != projection.relationship.object
            || projection.claim.predicate != tally_core::ClaimPredicate::ResourceUsed
            || projection.claim.valid_from != projection.relationship.valid_from
            || projection.claim.valid_until != projection.relationship.valid_until
            || projection.claim_evidence_observation_ids.is_empty()
            || projection.claim_evidence_observation_ids.len() > 256
        {
            return Err(PostgresStoreError::CloudUsageProjectionInvalid);
        }
        let relationship_observations = projection
            .relationship_evidence
            .iter()
            .map(|item| item.observation_id)
            .collect::<BTreeSet<_>>();
        let claim_observations = projection
            .claim_evidence_observation_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if relationship_observations != claim_observations {
            return Err(PostgresStoreError::CloudUsageProjectionInvalid);
        }
        let mut transaction = self.pool.begin().await?;
        Self::put_entity_relationship_transaction(
            &mut transaction,
            &projection.relationship,
            &projection.relationship_evidence,
        )
        .await?;
        put_claim_transaction(&mut transaction, &projection.claim).await?;
        for observation_id in &projection.claim_evidence_observation_ids {
            let stored = sqlx::query_scalar::<_, Uuid>(
                r"
                INSERT INTO claim_evidence (claim_id, observation_id, support_role)
                VALUES ($1, $2, 'supporting')
                ON CONFLICT (claim_id, observation_id) DO UPDATE SET
                    support_role = EXCLUDED.support_role
                WHERE claim_evidence.support_role = EXCLUDED.support_role
                RETURNING observation_id
                ",
            )
            .bind(projection.claim.claim_id)
            .bind(observation_id)
            .fetch_optional(&mut *transaction)
            .await?;
            if stored.is_none() {
                return Err(PostgresStoreError::ClaimEvidenceConflict);
            }
        }
        let updated = sqlx::query(
            r"
            UPDATE ai_system_views
            SET lifecycle = 'active',
                last_seen = GREATEST(last_seen, $2),
                revision = CASE
                    WHEN lifecycle <> 'active' OR last_seen < $2 THEN revision + 1
                    ELSE revision
                END
            WHERE system_id = $1
            ",
        )
        .bind(projection.claim.subject.entity_id)
        .bind(
            projection
                .claim
                .valid_until
                .unwrap_or(projection.claim.valid_from),
        )
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(PostgresStoreError::CloudUsageProjectionInvalid);
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Persists or refreshes one deterministic, content-free attribution conflict.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the conflict contract, immutable identity, revision, or
    /// database write is invalid.
    pub async fn put_attribution_conflict(
        &self,
        conflict: &AttributionConflict,
    ) -> Result<(), PostgresStoreError> {
        validate_attribution_conflict(conflict)?;
        let stored = sqlx::query_scalar::<_, Uuid>(
            r"
            INSERT INTO attribution_conflicts (
                conflict_id, installation_id, conflict_type, subject_entity_id,
                source_relationship_id, source_observation_id, candidate_count, valid_from,
                valid_until, status, rule, evidence_observation_ids, created_at, updated_at,
                revision
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
            ON CONFLICT (conflict_id) DO UPDATE SET
                candidate_count = EXCLUDED.candidate_count,
                valid_from = EXCLUDED.valid_from,
                valid_until = EXCLUDED.valid_until,
                status = EXCLUDED.status,
                rule = EXCLUDED.rule,
                evidence_observation_ids = EXCLUDED.evidence_observation_ids,
                updated_at = CASE
                    WHEN ROW(
                        attribution_conflicts.candidate_count,
                        attribution_conflicts.valid_from,
                        attribution_conflicts.valid_until,
                        attribution_conflicts.status,
                        attribution_conflicts.rule,
                        attribution_conflicts.evidence_observation_ids
                    ) IS DISTINCT FROM ROW(
                        EXCLUDED.candidate_count,
                        EXCLUDED.valid_from,
                        EXCLUDED.valid_until,
                        EXCLUDED.status,
                        EXCLUDED.rule,
                        EXCLUDED.evidence_observation_ids
                    ) THEN now()
                    ELSE attribution_conflicts.updated_at
                END,
                revision = CASE
                    WHEN ROW(
                        attribution_conflicts.candidate_count,
                        attribution_conflicts.valid_from,
                        attribution_conflicts.valid_until,
                        attribution_conflicts.status,
                        attribution_conflicts.rule,
                        attribution_conflicts.evidence_observation_ids
                    ) IS DISTINCT FROM ROW(
                        EXCLUDED.candidate_count,
                        EXCLUDED.valid_from,
                        EXCLUDED.valid_until,
                        EXCLUDED.status,
                        EXCLUDED.rule,
                        EXCLUDED.evidence_observation_ids
                    ) THEN attribution_conflicts.revision + 1
                    ELSE attribution_conflicts.revision
                END
            WHERE attribution_conflicts.installation_id = EXCLUDED.installation_id
              AND attribution_conflicts.conflict_type = EXCLUDED.conflict_type
              AND attribution_conflicts.subject_entity_id = EXCLUDED.subject_entity_id
              AND attribution_conflicts.source_relationship_id = EXCLUDED.source_relationship_id
              AND attribution_conflicts.source_observation_id = EXCLUDED.source_observation_id
            RETURNING conflict_id
            ",
        )
        .bind(conflict.conflict_id)
        .bind(conflict.installation_id)
        .bind(enum_value(conflict.conflict_type)?)
        .bind(conflict.subject_entity_id)
        .bind(conflict.source_relationship_id)
        .bind(conflict.source_observation_id)
        .bind(i32::try_from(conflict.candidate_count).unwrap_or(i32::MAX))
        .bind(conflict.valid_from)
        .bind(conflict.valid_until)
        .bind(enum_value(conflict.status)?)
        .bind(serde_json::to_value(&conflict.rule)?)
        .bind(&conflict.evidence_observation_ids)
        .bind(conflict.created_at)
        .bind(conflict.updated_at)
        .bind(conflict.revision)
        .fetch_optional(&self.pool)
        .await?;
        if stored.is_none() {
            return Err(PostgresStoreError::AttributionConflictRevisionConflict);
        }
        Ok(())
    }

    /// Clears an earlier ambiguity once an exact path is available for the same flow evidence.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the update cannot be applied.
    pub async fn clear_cloud_usage_conflict(
        &self,
        installation_id: Uuid,
        flow_relationship_id: Uuid,
        flow_observation_id: Uuid,
        updated_at: DateTime<Utc>,
    ) -> Result<(), PostgresStoreError> {
        sqlx::query(
            r"
            UPDATE attribution_conflicts
            SET status = 'cleared',
                updated_at = GREATEST(updated_at, $4),
                revision = revision + 1
            WHERE installation_id = $1
              AND source_relationship_id = $2
              AND source_observation_id = $3
              AND status = 'open'
            ",
        )
        .bind(installation_id)
        .bind(flow_relationship_id)
        .bind(flow_observation_id)
        .bind(updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Marks flow-derived usage projections disputed when the same flow has competing exact paths.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the reconciliation transaction cannot be committed.
    pub async fn dispute_cloud_usage_projection(
        &self,
        installation_id: Uuid,
        flow_observation_id: Uuid,
    ) -> Result<(), PostgresStoreError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            r#"
            UPDATE claims claim
            SET status = 'disputed'
            WHERE claim.status = 'active'
              AND claim.predicate = '"resource_used"'
              AND claim.rule->>'rule_id' = 'cloud_network_usage_exact_path'
              AND EXISTS (
                  SELECT 1 FROM claim_evidence evidence
                  WHERE evidence.claim_id = claim.claim_id
                    AND evidence.observation_id = $2
              )
              AND EXISTS (
                  SELECT 1 FROM ai_system_views system
                  WHERE system.system_id = claim.subject_entity_id
                    AND system.installation_id = $1
              )
            "#,
        )
        .bind(installation_id)
        .bind(flow_observation_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            UPDATE entity_relationships relationship
            SET status = 'disputed', revision = revision + 1
            WHERE relationship.installation_id = $1
              AND relationship.status = 'active'
              AND relationship.rule->>'rule_id' = 'cloud_network_usage_exact_path'
              AND EXISTS (
                  SELECT 1 FROM relationship_evidence evidence
                  WHERE evidence.relationship_id = relationship.relationship_id
                    AND evidence.observation_id = $2
              )
            ",
        )
        .bind(installation_id)
        .bind(flow_observation_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r#"
            UPDATE ai_system_views system
            SET lifecycle = 'observed', revision = revision + 1
            WHERE system.installation_id = $1
              AND system.lifecycle = 'active'
              AND NOT EXISTS (
                  SELECT 1 FROM claims claim
                  WHERE claim.subject_entity_id = system.system_id
                    AND claim.predicate = '"resource_used"'
                    AND claim.status = 'active'
              )
            "#,
        )
        .bind(installation_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Lists a bounded, stable page of attribution conflicts.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when a conflict row cannot be queried or decoded.
    pub async fn list_attribution_conflicts(
        &self,
        installation_id: Uuid,
        status: Option<AttributionConflictStatus>,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<AttributionConflict>, PostgresStoreError> {
        let values = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT jsonb_build_object(
                'conflict_id', conflict_id,
                'installation_id', installation_id,
                'conflict_type', conflict_type,
                'subject_entity_id', subject_entity_id,
                'source_relationship_id', source_relationship_id,
                'source_observation_id', source_observation_id,
                'candidate_count', candidate_count,
                'valid_from', valid_from,
                'valid_until', valid_until,
                'status', status,
                'rule', rule,
                'evidence_observation_ids', to_jsonb(evidence_observation_ids),
                'created_at', created_at,
                'updated_at', updated_at,
                'revision', revision
            )
            FROM attribution_conflicts
            WHERE installation_id = $1
              AND ($2::text IS NULL OR status = $2)
            ORDER BY updated_at DESC, conflict_id
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(installation_id)
        .bind(status.map(enum_value).transpose()?)
        .bind(i64::from(limit.clamp(1, 500)))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await?;
        values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Counts attribution conflicts for one installation and optional status.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when `PostgreSQL` cannot evaluate the bounded count.
    pub async fn attribution_conflict_count(
        &self,
        installation_id: Uuid,
        status: Option<AttributionConflictStatus>,
    ) -> Result<u64, PostgresStoreError> {
        let count = sqlx::query_scalar::<_, i64>(
            r"
            SELECT count(*)
            FROM attribution_conflicts
            WHERE installation_id = $1
              AND ($2::text IS NULL OR status = $2)
            ",
        )
        .bind(installation_id)
        .bind(status.map(enum_value).transpose()?)
        .fetch_one(&self.pool)
        .await?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Advances an attribution replay checkpoint without permitting revision or time rollback.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] for an invalid contract, conflicting replay, or database
    /// failure.
    pub async fn put_attribution_replay_checkpoint(
        &self,
        checkpoint: &AttributionReplayCheckpoint,
    ) -> Result<(), PostgresStoreError> {
        checkpoint.validate()?;
        let stored = sqlx::query_scalar::<_, i64>(
            r"
            INSERT INTO attribution_replay_checkpoints (
                installation_id, resolver_id, resolver_version, observation_high_watermark,
                projection_digest, revision, updated_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7)
            ON CONFLICT (installation_id, resolver_id) DO UPDATE SET
                resolver_version = EXCLUDED.resolver_version,
                observation_high_watermark = EXCLUDED.observation_high_watermark,
                projection_digest = EXCLUDED.projection_digest,
                revision = EXCLUDED.revision,
                updated_at = EXCLUDED.updated_at
            WHERE (
                attribution_replay_checkpoints.revision < EXCLUDED.revision
                AND attribution_replay_checkpoints.observation_high_watermark <= EXCLUDED.observation_high_watermark
            ) OR (
                attribution_replay_checkpoints.revision = EXCLUDED.revision
                AND attribution_replay_checkpoints.resolver_version = EXCLUDED.resolver_version
                AND attribution_replay_checkpoints.observation_high_watermark = EXCLUDED.observation_high_watermark
                AND attribution_replay_checkpoints.projection_digest = EXCLUDED.projection_digest
                AND attribution_replay_checkpoints.updated_at = EXCLUDED.updated_at
            )
            RETURNING revision
            ",
        )
        .bind(checkpoint.installation_id)
        .bind(&checkpoint.resolver.rule_id)
        .bind(&checkpoint.resolver.version)
        .bind(checkpoint.observation_high_watermark)
        .bind(&checkpoint.projection_digest)
        .bind(checkpoint.revision)
        .bind(checkpoint.updated_at)
        .fetch_optional(&self.pool)
        .await?;
        if stored.is_none() {
            return Err(PostgresStoreError::AttributionCheckpointConflict);
        }
        Ok(())
    }

    /// Persists an immutable, versioned claim.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when serialization or insertion fails.
    pub async fn put_claim(&self, claim: &Claim) -> Result<(), PostgresStoreError> {
        sqlx::query(
            r"
            INSERT INTO claims (
                claim_id, subject_entity_id, predicate, value, class, confidence_bps, status,
                valid_from, valid_until, rule, registry_version, created_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
            ON CONFLICT (claim_id) DO NOTHING
            ",
        )
        .bind(claim.claim_id)
        .bind(claim.subject.entity_id)
        .bind(serde_json::to_value(&claim.predicate)?.to_string())
        .bind(&claim.value)
        .bind(
            serde_json::to_value(claim.class)?
                .as_str()
                .unwrap_or("derived"),
        )
        .bind(i32::from(claim.confidence.get()))
        .bind(
            serde_json::to_value(claim.status)?
                .as_str()
                .unwrap_or("active"),
        )
        .bind(claim.valid_from)
        .bind(claim.valid_until)
        .bind(serde_json::to_value(&claim.rule)?)
        .bind(&claim.registry_version)
        .bind(claim.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Retrieves a claim and its typed subject by stable identifier.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when querying or deserializing the record fails.
    pub async fn get_claim(&self, claim_id: Uuid) -> Result<Option<Claim>, PostgresStoreError> {
        let value = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT jsonb_build_object(
                'claim_id', c.claim_id,
                'subject', jsonb_build_object(
                    'entity_id', c.subject_entity_id,
                    'kind', e.kind
                ),
                'predicate', c.predicate::jsonb,
                'value', c.value,
                'class', c.class,
                'confidence', c.confidence_bps,
                'status', c.status,
                'valid_from', c.valid_from,
                'valid_until', c.valid_until,
                'rule', c.rule,
                'registry_version', c.registry_version,
                'created_at', c.created_at
            )
            FROM claims c
            JOIN entities e ON e.entity_id = c.subject_entity_id
            WHERE c.claim_id = $1
            ",
        )
        .bind(claim_id)
        .fetch_optional(&self.pool)
        .await?;
        value
            .map(serde_json::from_value)
            .transpose()
            .map_err(Into::into)
    }

    /// Persists a deterministic system projection, stable key, claims, and evidence links.
    ///
    /// Replaying identical resolution output is a no-op. Later evidence advances first/last seen
    /// and revision only when the projection materially changes.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when serialization or the transaction fails.
    pub async fn put_resolved_system(
        &self,
        installation_id: Uuid,
        resolved: &ResolvedSystem,
    ) -> Result<(), PostgresStoreError> {
        let (key_type, key_authority) = if resolved.stable_key.starts_with("cloud_system:") {
            ("cloud_system_key", "derived_rule")
        } else {
            ("registry_entry", "registry")
        };
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            r"
            INSERT INTO entities (entity_id, kind, display_name, created_at, revision)
            VALUES ($1, 'ai_system', $2, $3, $4)
            ON CONFLICT (entity_id) DO UPDATE SET
                display_name = EXCLUDED.display_name,
                revision = GREATEST(entities.revision, EXCLUDED.revision)
            ",
        )
        .bind(resolved.entity.entity_id)
        .bind(&resolved.entity.display_name)
        .bind(resolved.entity.created_at)
        .bind(resolved.entity.revision)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO entity_keys (
                installation_id, key_type, key_value, entity_id, first_seen, last_seen,
                source_authority, strength_bps, status, source_observation_id, revision
            ) VALUES ($1, $2, $3, $4, $5, $5, $6, $7, 'active', $8, 1)
            ON CONFLICT (installation_id, key_type, key_value) DO UPDATE SET
                first_seen = LEAST(entity_keys.first_seen, EXCLUDED.first_seen),
                last_seen = GREATEST(entity_keys.last_seen, EXCLUDED.last_seen),
                source_observation_id = CASE
                    WHEN EXCLUDED.last_seen >= entity_keys.last_seen
                    THEN EXCLUDED.source_observation_id
                    ELSE entity_keys.source_observation_id
                END
            WHERE entity_keys.entity_id = EXCLUDED.entity_id
            ",
        )
        .bind(installation_id)
        .bind(key_type)
        .bind(&resolved.stable_key)
        .bind(resolved.entity.entity_id)
        .bind(resolved.view.first_seen)
        .bind(key_authority)
        .bind(i32::from(resolved.view.confidence.get()))
        .bind(resolved.supporting_observation_id)
        .execute(&mut *transaction)
        .await?;
        put_system_view(&mut transaction, installation_id, resolved).await?;
        for claim in &resolved.claims {
            put_claim_transaction(&mut transaction, claim).await?;
            sqlx::query(
                r"
                INSERT INTO claim_evidence (claim_id, observation_id, support_role)
                VALUES ($1, $2, 'supporting')
                ON CONFLICT (claim_id, observation_id) DO NOTHING
                ",
            )
            .bind(claim.claim_id)
            .bind(resolved.supporting_observation_id)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Lists stable AI-system projections in recent-evidence order.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the inventory query or deserialization fails.
    pub async fn list_ai_systems(
        &self,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<AiSystemView>, PostgresStoreError> {
        let values = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT jsonb_build_object(
                'system_id', v.system_id,
                'display_name', v.display_name,
                'surface', v.surface,
                'lifecycle', v.lifecycle,
                'authorization', v.authorization_status,
                'first_seen', LEAST(v.first_seen, COALESCE((
                    SELECT min(alias_view.first_seen)
                    FROM entity_resolution_aliases a
                    JOIN ai_system_views alias_view ON alias_view.system_id = a.alias_entity_id
                    WHERE a.installation_id = v.installation_id
                      AND a.canonical_entity_id = v.system_id AND a.active
                ), v.first_seen)),
                'last_seen', GREATEST(v.last_seen, COALESCE((
                    SELECT max(alias_view.last_seen)
                    FROM entity_resolution_aliases a
                    JOIN ai_system_views alias_view ON alias_view.system_id = a.alias_entity_id
                    WHERE a.installation_id = v.installation_id
                      AND a.canonical_entity_id = v.system_id AND a.active
                ), v.last_seen)),
                'evidence_quality', v.evidence_quality,
                'confidence', v.confidence_bps,
                'findings', COALESCE((
                    SELECT jsonb_agg(jsonb_build_object(
                        'finding_id', f.finding_id,
                        'policy_id', f.policy_id,
                        'policy_version', f.policy_version,
                        'title', f.title,
                        'severity', f.severity,
                        'factor_codes', to_jsonb(f.factor_codes)
                    ) ORDER BY f.severity DESC, f.finding_id)
                    FROM findings f
                    WHERE f.status = 'open' AND (
                        f.system_id = v.system_id OR EXISTS (
                            SELECT 1 FROM entity_resolution_aliases a
                            WHERE a.installation_id = v.installation_id
                              AND a.canonical_entity_id = v.system_id
                              AND a.alias_entity_id = f.system_id AND a.active
                        )
                    )
                ), '[]'::jsonb),
                'revision', v.revision
            )
            FROM ai_system_views v
            WHERE NOT EXISTS (
                SELECT 1 FROM entity_resolution_aliases a
                WHERE a.installation_id = v.installation_id
                  AND a.alias_entity_id = v.system_id AND a.active
            )
            ORDER BY v.last_seen DESC, v.system_id
            LIMIT $1 OFFSET $2
            ",
        )
        .bind(i64::from(limit.clamp(1, 200)))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await?;
        values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Counts stable AI-system projections.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the inventory count fails.
    pub async fn ai_system_count(&self) -> Result<u64, PostgresStoreError> {
        let count = sqlx::query_scalar::<_, i64>(
            r"
            SELECT count(*) FROM ai_system_views v
            WHERE NOT EXISTS (
                SELECT 1 FROM entity_resolution_aliases a
                WHERE a.installation_id = v.installation_id
                  AND a.alias_entity_id = v.system_id AND a.active
            )
            ",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Loads one current AI-system projection, including open findings.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the projection cannot be read or decoded.
    pub async fn get_ai_system(
        &self,
        system_id: Uuid,
    ) -> Result<Option<AiSystemView>, PostgresStoreError> {
        let value = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            WITH requested AS (
                SELECT COALESCE((
                    SELECT canonical_entity_id FROM entity_resolution_aliases
                    WHERE alias_entity_id = $1 AND active
                ), $1) AS system_id
            )
            SELECT jsonb_build_object(
                'system_id', v.system_id,
                'display_name', v.display_name,
                'surface', v.surface,
                'lifecycle', v.lifecycle,
                'authorization', v.authorization_status,
                'first_seen', v.first_seen,
                'last_seen', v.last_seen,
                'evidence_quality', v.evidence_quality,
                'confidence', v.confidence_bps,
                'findings', COALESCE((
                    SELECT jsonb_agg(jsonb_build_object(
                        'finding_id', f.finding_id,
                        'policy_id', f.policy_id,
                        'policy_version', f.policy_version,
                        'title', f.title,
                        'severity', f.severity,
                        'factor_codes', to_jsonb(f.factor_codes)
                    ) ORDER BY f.severity DESC, f.finding_id)
                    FROM findings f
                    WHERE f.status = 'open' AND (
                        f.system_id = v.system_id OR EXISTS (
                            SELECT 1 FROM entity_resolution_aliases a
                            WHERE a.installation_id = v.installation_id
                              AND a.canonical_entity_id = v.system_id
                              AND a.alias_entity_id = f.system_id AND a.active
                        )
                    )
                ), '[]'::jsonb),
                'revision', v.revision
            )
            FROM ai_system_views v
            JOIN requested ON requested.system_id = v.system_id
            ",
        )
        .bind(system_id)
        .fetch_optional(&self.pool)
        .await?;
        value
            .map(serde_json::from_value)
            .transpose()
            .map_err(Into::into)
    }

    /// Lists typed claims and their immutable observation references for a system.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when evidence links cannot be read or decoded.
    pub async fn list_system_evidence(
        &self,
        system_id: Uuid,
    ) -> Result<Vec<ClaimEvidenceView>, PostgresStoreError> {
        let values = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            WITH requested AS (
                SELECT COALESCE((
                    SELECT canonical_entity_id FROM entity_resolution_aliases
                    WHERE alias_entity_id = $1 AND active
                ), $1) AS system_id
            )
            SELECT jsonb_build_object(
                'claim', jsonb_build_object(
                    'claim_id', c.claim_id,
                    'subject', jsonb_build_object(
                        'entity_id', c.subject_entity_id,
                        'kind', e.kind
                    ),
                    'predicate', c.predicate::jsonb,
                    'value', c.value,
                    'class', c.class,
                    'confidence', c.confidence_bps,
                    'status', c.status,
                    'valid_from', c.valid_from,
                    'valid_until', c.valid_until,
                    'rule', c.rule,
                    'registry_version', c.registry_version,
                    'created_at', c.created_at
                ),
                'observation_ids', COALESCE(
                    jsonb_agg(ce.observation_id ORDER BY ce.observation_id)
                        FILTER (WHERE ce.observation_id IS NOT NULL),
                    '[]'::jsonb
                )
            )
            FROM claims c
            JOIN entities e ON e.entity_id = c.subject_entity_id
            LEFT JOIN claim_evidence ce ON ce.claim_id = c.claim_id
            CROSS JOIN requested
            WHERE c.subject_entity_id = requested.system_id OR EXISTS (
                SELECT 1 FROM entity_resolution_aliases a
                JOIN ai_system_views v ON v.installation_id = a.installation_id
                WHERE v.system_id = requested.system_id
                  AND a.canonical_entity_id = requested.system_id
                  AND a.alias_entity_id = c.subject_entity_id AND a.active
            )
            GROUP BY c.claim_id, e.kind
            ORDER BY c.created_at, c.claim_id
            ",
        )
        .bind(system_id)
        .fetch_all(&self.pool)
        .await?;
        values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Returns every current system-to-observation evidence edge for coverage computation.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the evidence index cannot be read.
    pub async fn list_system_evidence_index(
        &self,
    ) -> Result<Vec<SystemEvidenceEdge>, PostgresStoreError> {
        sqlx::query_as::<_, (Uuid, Uuid)>(
            r"
            SELECT DISTINCT COALESCE(a.canonical_entity_id, c.subject_entity_id), ce.observation_id
            FROM claims c
            JOIN claim_evidence ce ON ce.claim_id = c.claim_id
            JOIN ai_system_views v ON v.system_id = c.subject_entity_id
            LEFT JOIN entity_resolution_aliases a
              ON a.installation_id = v.installation_id
             AND a.alias_entity_id = c.subject_entity_id AND a.active
            WHERE c.status = 'active'
            ORDER BY COALESCE(a.canonical_entity_id, c.subject_entity_id), ce.observation_id
            ",
        )
        .fetch_all(&self.pool)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|(system_id, observation_id)| SystemEvidenceEdge {
                    system_id,
                    observation_id,
                })
                .collect()
        })
        .map_err(Into::into)
    }

    /// Replaces the open result set for one system and one policy version.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when finding serialization or persistence fails.
    pub async fn replace_system_findings(
        &self,
        system: &AiSystemView,
        policy_id: &str,
        policy_version: &str,
        evidence_source_count: u32,
        evaluated_at: DateTime<Utc>,
        findings: &[EvaluatedFinding],
    ) -> Result<(), PostgresStoreError> {
        if !safe_code_with_punctuation(policy_id) || !safe_code_with_punctuation(policy_version) {
            return Err(PostgresStoreError::UnsafePolicyIdentifier);
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            r"
            UPDATE findings SET status = 'resolved', last_evaluated_at = $4
            WHERE system_id = $1 AND policy_id = $2 AND policy_version = $3
              AND status = 'open'
            ",
        )
        .bind(system.system_id)
        .bind(policy_id)
        .bind(policy_version)
        .bind(evaluated_at)
        .execute(&mut *transaction)
        .await?;

        for evaluated in findings {
            let finding = &evaluated.finding;
            sqlx::query(
                r"
                INSERT INTO findings (
                    finding_id, system_id, policy_id, policy_version, title, severity, status,
                    factor_codes, factors, system_revision, evidence_source_count,
                    first_evaluated_at, last_evaluated_at
                ) VALUES ($1,$2,$3,$4,$5,$6,'open',$7,$8,$9,$10,$11,$11)
                ON CONFLICT (finding_id) DO UPDATE SET
                    title = EXCLUDED.title,
                    severity = EXCLUDED.severity,
                    status = 'open',
                    factor_codes = EXCLUDED.factor_codes,
                    factors = EXCLUDED.factors,
                    system_revision = EXCLUDED.system_revision,
                    evidence_source_count = EXCLUDED.evidence_source_count,
                    last_evaluated_at = EXCLUDED.last_evaluated_at
                ",
            )
            .bind(finding.finding_id)
            .bind(system.system_id)
            .bind(&finding.policy_id)
            .bind(&finding.policy_version)
            .bind(&finding.title)
            .bind(enum_string(finding.severity, "informational")?)
            .bind(&finding.factor_codes)
            .bind(serde_json::to_value(&evaluated.factors)?)
            .bind(system.revision)
            .bind(i32::try_from(evidence_source_count).unwrap_or(i32::MAX))
            .bind(evaluated_at)
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            r"
            INSERT INTO audit_log (audit_id, at, actor, action, entity_type, entity_id, detail)
            VALUES ($1,$2,'system:tally-risk','risk.evaluated','ai_system',$3,$4)
            ",
        )
        .bind(Uuid::now_v7())
        .bind(evaluated_at)
        .bind(system.system_id.to_string())
        .bind(serde_json::json!({
            "policy_id": policy_id,
            "policy_version": policy_version,
            "system_revision": system.revision,
            "evidence_source_count": evidence_source_count,
            "open_finding_count": findings.len(),
        }))
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Lists current and resolved findings in recent-evaluation order.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when findings cannot be read or decoded.
    pub async fn list_findings(&self, limit: u16) -> Result<Vec<FindingView>, PostgresStoreError> {
        let values = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT jsonb_build_object(
                'finding_id', f.finding_id,
                'system_id', f.system_id,
                'system_name', v.display_name,
                'policy_id', f.policy_id,
                'policy_version', f.policy_version,
                'title', f.title,
                'severity', f.severity,
                'status', f.status,
                'factor_codes', to_jsonb(f.factor_codes),
                'factors', f.factors,
                'system_revision', f.system_revision,
                'evidence_source_count', f.evidence_source_count,
                'first_evaluated_at', f.first_evaluated_at,
                'last_evaluated_at', f.last_evaluated_at
            )
            FROM findings f
            JOIN ai_system_views v ON v.system_id = f.system_id
            ORDER BY (f.status = 'open') DESC,
                CASE f.severity
                    WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
                    WHEN 'low' THEN 2 ELSE 1
                END DESC,
                f.last_evaluated_at DESC, f.finding_id
            LIMIT $1
            ",
        )
        .bind(i64::from(limit.clamp(1, 500)))
        .fetch_all(&self.pool)
        .await?;
        values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Applies an authorization transition with optimistic concurrency, idempotency, and audit.
    ///
    /// # Errors
    ///
    /// Returns a typed [`PostgresStoreError`] for conflicts, invalid transitions, or persistence
    /// failures. The local Phase 1 actor is fixed; no free-form user content is accepted.
    pub async fn transition_authorization(
        &self,
        request: &AuthorizationTransitionRequest,
    ) -> Result<AuthorizationTransitionResult, PostgresStoreError> {
        let request_fingerprint = authorization_request_fingerprint(request)?;
        let mut transaction = self.pool.begin().await?;
        if let Some((existing_fingerprint, response)) =
            sqlx::query_as::<_, (String, serde_json::Value)>(
                "SELECT request_fingerprint, response FROM mutation_idempotency WHERE idempotency_key = $1",
            )
            .bind(request.idempotency_key)
            .fetch_optional(&mut *transaction)
            .await?
        {
            if existing_fingerprint != request_fingerprint {
                return Err(PostgresStoreError::IdempotencyConflict);
            }
            let transition = serde_json::from_value(response)?;
            transaction.rollback().await?;
            return Ok(AuthorizationTransitionResult {
                replayed: true,
                transition,
            });
        }

        let current = sqlx::query_as::<_, (String, i64)>(
            "SELECT authorization_status, revision FROM ai_system_views WHERE system_id = $1 FOR UPDATE",
        )
        .bind(request.system_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(PostgresStoreError::SystemNotFound)?;
        if current.1 != request.expected_revision {
            return Err(PostgresStoreError::RevisionConflict {
                current_revision: current.1,
            });
        }
        let from_status: AuthorizationStatus =
            serde_json::from_value(serde_json::Value::String(current.0))?;
        if from_status == request.to_status {
            return Err(PostgresStoreError::AuthorizationUnchanged);
        }
        if !authorization_transition_allowed(from_status, request.to_status) {
            return Err(PostgresStoreError::InvalidAuthorizationTransition);
        }
        if !authorization_reason_allowed(request.to_status, request.reason_code) {
            return Err(PostgresStoreError::InvalidAuthorizationReason);
        }

        let at = Utc::now();
        let transition = AuthorizationTransitionView {
            transition_id: Uuid::now_v7(),
            system_id: request.system_id,
            from_status,
            to_status: request.to_status,
            reason_code: request.reason_code,
            actor: audit_actor(),
            previous_revision: current.1,
            new_revision: current.1 + 1,
            idempotency_key: request.idempotency_key,
            at,
        };
        put_authorization_transition(&mut transaction, request, &request_fingerprint, &transition)
            .await?;
        transaction.commit().await?;
        Ok(AuthorizationTransitionResult {
            replayed: false,
            transition,
        })
    }

    /// Lists recent append-only operational and governance audit events.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when audit rows cannot be read or decoded.
    pub async fn list_audit_events(
        &self,
        limit: u16,
    ) -> Result<Vec<AuditEventView>, PostgresStoreError> {
        let values = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT jsonb_build_object(
                'audit_id', audit_id,
                'at', at,
                'actor', actor,
                'action', action,
                'entity_type', entity_type,
                'entity_id', entity_id,
                'detail', detail
            )
            FROM audit_log
            ORDER BY at DESC, audit_id DESC
            LIMIT $1
            ",
        )
        .bind(i64::from(limit.clamp(1, 500)))
        .fetch_all(&self.pool)
        .await?;
        values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Claims a content-addressed ingestion batch before immutable observations are appended.
    ///
    /// A completed digest is returned as a duplicate, a concurrently active digest as in-progress,
    /// and a previously failed digest is reopened for deterministic retry.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the ledger cannot be read or updated.
    pub async fn begin_ingestion(
        &self,
        receipt: &BatchReceipt,
    ) -> Result<BatchAdmission, PostgresStoreError> {
        let batch_id = stable_batch_id(receipt);
        let mut transaction = self.pool.begin().await?;
        let inserted = sqlx::query_scalar::<_, Uuid>(
            r"
            INSERT INTO ingestion_batches (
                batch_id, connector_instance_id, batch_digest, observation_count,
                installation_id, checkpoint, status
            ) VALUES ($1, $2, $3, $4, $5, $6, 'writing')
            ON CONFLICT (connector_instance_id, batch_digest) DO NOTHING
            RETURNING batch_id
            ",
        )
        .bind(batch_id)
        .bind(receipt.connector_instance_id)
        .bind(&receipt.canonical_digest)
        .bind(i64::try_from(receipt.observation_count).unwrap_or(i64::MAX))
        .bind(receipt.installation_id)
        .bind(&receipt.checkpoint.0)
        .fetch_optional(&mut *transaction)
        .await?;

        let (batch_id, disposition) = if inserted.is_some() {
            (batch_id, BatchDisposition::Accepted)
        } else {
            let (existing_id, status) = sqlx::query_as::<_, (Uuid, String)>(
                r"
                SELECT batch_id, status FROM ingestion_batches
                WHERE connector_instance_id = $1 AND batch_digest = $2
                FOR UPDATE
                ",
            )
            .bind(receipt.connector_instance_id)
            .bind(&receipt.canonical_digest)
            .fetch_one(&mut *transaction)
            .await?;
            if status == "failed" {
                sqlx::query(
                    r"
                    UPDATE ingestion_batches SET
                        status = 'writing', failure_code = NULL, completed_at = NULL,
                        accepted_at = now()
                    WHERE batch_id = $1
                    ",
                )
                .bind(existing_id)
                .execute(&mut *transaction)
                .await?;
                (existing_id, BatchDisposition::Retry)
            } else if status == "completed" {
                (existing_id, BatchDisposition::Duplicate)
            } else {
                (existing_id, BatchDisposition::InProgress)
            }
        };
        transaction.commit().await?;
        Ok(BatchAdmission {
            batch_id,
            disposition,
        })
    }

    /// Atomically marks a batch complete and advances its connector cursor.
    ///
    /// Returns `false` when the batch was already finalized, making completion idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the ledger transaction fails.
    pub async fn complete_ingestion(&self, batch_id: Uuid) -> Result<bool, PostgresStoreError> {
        let mut transaction = self.pool.begin().await?;
        let completed = Self::complete_ingestion_in_transaction(&mut transaction, batch_id).await?;
        if completed {
            transaction.commit().await?;
        } else {
            transaction.rollback().await?;
        }
        Ok(completed)
    }

    async fn complete_ingestion_in_transaction(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        batch_id: Uuid,
    ) -> Result<bool, PostgresStoreError> {
        let completed = sqlx::query_as::<_, (Uuid, String)>(
            r"
            UPDATE ingestion_batches SET status = 'completed', completed_at = now()
            WHERE batch_id = $1 AND status = 'writing'
            RETURNING connector_instance_id, checkpoint
            ",
        )
        .bind(batch_id)
        .fetch_optional(&mut **transaction)
        .await?;
        if let Some((connector_instance_id, checkpoint)) = completed {
            sqlx::query(
                r"
                UPDATE connector_states SET
                    cursor_value = $2, health = 'healthy', last_batch_id = $1,
                    last_success_at = now(), last_error_code = NULL, updated_at = now()
                WHERE connector_instance_id = $3
                ",
            )
            .bind(batch_id)
            .bind(checkpoint)
            .bind(connector_instance_id)
            .execute(&mut **transaction)
            .await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Marks a batch failed with a bounded machine-readable code; source content is never stored.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the code is unsafe or the ledger update fails.
    pub async fn fail_ingestion(
        &self,
        batch_id: Uuid,
        failure_code: &str,
    ) -> Result<(), PostgresStoreError> {
        if failure_code.is_empty()
            || failure_code.len() > 64
            || !failure_code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(PostgresStoreError::UnsafeFailureCode);
        }
        let mut transaction = self.pool.begin().await?;
        let connector_instance_id = sqlx::query_scalar::<_, Uuid>(
            r"
            UPDATE ingestion_batches SET status = 'failed', failure_code = $2
            WHERE batch_id = $1 AND status = 'writing'
            RETURNING connector_instance_id
            ",
        )
        .bind(batch_id)
        .bind(failure_code)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(connector_instance_id) = connector_instance_id {
            sqlx::query(
                r"
                UPDATE connector_states SET
                    health = 'error', last_error_code = $2, updated_at = now()
                WHERE connector_instance_id = $1
                ",
            )
            .bind(connector_instance_id)
            .bind(failure_code)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

impl PostgresStore {
    /// Persists an authorization-bound scan receipt before any probe can be scheduled.
    ///
    /// # Errors
    ///
    /// Returns a typed conflict when an idempotency key is reused for a different request, or a
    /// storage error when the receipt cannot be committed.
    pub async fn create_scan_job(
        &self,
        request: &ScanJobCreate,
    ) -> Result<(ScanJobView, bool), PostgresStoreError> {
        let mut transaction = self.pool.begin().await?;
        if let Some((fingerprint, value)) = sqlx::query_as::<_, (String, serde_json::Value)>(
            r"
                SELECT request_fingerprint, to_jsonb(s) - 'request_fingerprint'
                FROM scan_jobs s WHERE idempotency_key = $1
                ",
        )
        .bind(request.idempotency_key)
        .fetch_optional(&mut *transaction)
        .await?
        {
            if fingerprint != request.request_fingerprint {
                return Err(PostgresStoreError::IdempotencyConflict);
            }
            let job = serde_json::from_value(value)?;
            transaction.rollback().await?;
            return Ok((job, true));
        }

        let value = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            INSERT INTO scan_jobs (
                scan_id, idempotency_key, request_fingerprint, scope_digest, plan,
                execution_policy, status, authorized_by, authorization_acknowledged_at,
                created_at, planned_probes
            ) VALUES ($1,$2,$3,$4,$5,$6,'planned','local_operator',$7,$7,$8)
            RETURNING to_jsonb(scan_jobs) - 'request_fingerprint'
            ",
        )
        .bind(request.scan_id)
        .bind(request.idempotency_key)
        .bind(&request.request_fingerprint)
        .bind(&request.scope_digest)
        .bind(&request.plan)
        .bind(&request.execution_policy)
        .bind(request.created_at)
        .bind(count_i64(request.planned_probes))
        .fetch_one(&mut *transaction)
        .await?;
        put_scan_audit(
            &mut transaction,
            request.scan_id,
            request.created_at,
            "scan.authorized",
            serde_json::json!({
                "scope_digest": request.scope_digest,
                "planned_probes": request.planned_probes,
                "content_retained": false,
            }),
        )
        .await?;
        transaction.commit().await?;
        Ok((serde_json::from_value(value)?, false))
    }

    /// Marks a durably planned scan as running.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the transition cannot be persisted.
    pub async fn start_scan_job(&self, scan_id: Uuid) -> Result<bool, PostgresStoreError> {
        let started_at = Utc::now();
        let mut transaction = self.pool.begin().await?;
        let started = sqlx::query_scalar::<_, Uuid>(
            r"
            UPDATE scan_jobs SET status = 'running', started_at = $2
            WHERE scan_id = $1 AND status = 'planned'
            RETURNING scan_id
            ",
        )
        .bind(scan_id)
        .bind(started_at)
        .fetch_optional(&mut *transaction)
        .await?
        .is_some();
        if started {
            put_scan_audit(
                &mut transaction,
                scan_id,
                started_at,
                "scan.started",
                serde_json::json!({"content_retained": false}),
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(started)
    }

    /// Persists bounded reachability results and a terminal scan status.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the terminal status is invalid or persistence fails.
    pub async fn complete_scan_job(
        &self,
        update: &ScanJobCompletion,
    ) -> Result<(), PostgresStoreError> {
        if !matches!(
            update.status,
            ScanJobStatus::Completed | ScanJobStatus::Cancelled
        ) {
            return Err(PostgresStoreError::InvalidScanStatus);
        }
        let status = enum_string(update.status, "failed")?;
        let mut transaction = self.pool.begin().await?;
        let updated = sqlx::query_scalar::<_, Uuid>(
            r"
            UPDATE scan_jobs SET
                status = $2, finished_at = $3, completed_probes = $4,
                open_port_count = $5, results = $6, fingerprint_attempt_count = $7,
                fingerprint_match_count = $8, resolved_system_count = $9, error_code = NULL
            WHERE scan_id = $1 AND status IN ('running', 'cancel_requested')
            RETURNING scan_id
            ",
        )
        .bind(update.scan_id)
        .bind(&status)
        .bind(update.finished_at)
        .bind(count_i64(update.completed_probes))
        .bind(count_i64(update.open_port_count))
        .bind(&update.results)
        .bind(count_i64(update.fingerprint_attempt_count))
        .bind(count_i64(update.fingerprint_match_count))
        .bind(count_i64(update.resolved_system_count))
        .fetch_optional(&mut *transaction)
        .await?;
        if updated.is_none() {
            return Err(PostgresStoreError::InvalidScanStatus);
        }
        put_scan_audit(
            &mut transaction,
            update.scan_id,
            update.finished_at,
            if update.status == ScanJobStatus::Completed {
                "scan.completed"
            } else {
                "scan.cancelled"
            },
            serde_json::json!({
                "completed_probes": update.completed_probes,
                "open_port_count": update.open_port_count,
                "fingerprint_attempt_count": update.fingerprint_attempt_count,
                "fingerprint_match_count": update.fingerprint_match_count,
                "resolved_system_count": update.resolved_system_count,
                "content_retained": false,
            }),
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Records a bounded machine-readable scan failure.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the code is unsafe or persistence fails.
    pub async fn fail_scan_job(
        &self,
        scan_id: Uuid,
        error_code: &str,
    ) -> Result<(), PostgresStoreError> {
        if !safe_code(error_code) {
            return Err(PostgresStoreError::UnsafeFailureCode);
        }
        let finished_at = Utc::now();
        let mut transaction = self.pool.begin().await?;
        let updated = sqlx::query_scalar::<_, Uuid>(
            r"
            UPDATE scan_jobs SET status = 'failed', finished_at = $2, error_code = $3
            WHERE scan_id = $1 AND status IN ('planned', 'running', 'cancel_requested')
            RETURNING scan_id
            ",
        )
        .bind(scan_id)
        .bind(finished_at)
        .bind(error_code)
        .fetch_optional(&mut *transaction)
        .await?;
        if updated.is_some() {
            put_scan_audit(
                &mut transaction,
                scan_id,
                finished_at,
                "scan.failed",
                serde_json::json!({"error_code": error_code, "content_retained": false}),
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Requests cancellation for a planned or running scan.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the job is missing, terminal, or cannot be updated.
    pub async fn request_scan_cancellation(
        &self,
        scan_id: Uuid,
    ) -> Result<ScanJobView, PostgresStoreError> {
        let at = Utc::now();
        let mut transaction = self.pool.begin().await?;
        let value = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            UPDATE scan_jobs SET
                status = CASE WHEN status = 'planned' THEN 'cancelled'
                    ELSE 'cancel_requested' END,
                finished_at = CASE WHEN status = 'planned' THEN $2 ELSE finished_at END
            WHERE scan_id = $1 AND status IN ('planned', 'running')
            RETURNING to_jsonb(scan_jobs) - 'request_fingerprint'
            ",
        )
        .bind(scan_id)
        .bind(at)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(value) = value else {
            let exists = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM scan_jobs WHERE scan_id = $1)",
            )
            .bind(scan_id)
            .fetch_one(&mut *transaction)
            .await?;
            return Err(if exists {
                PostgresStoreError::InvalidScanStatus
            } else {
                PostgresStoreError::ScanNotFound
            });
        };
        let job: ScanJobView = serde_json::from_value(value)?;
        put_scan_audit(
            &mut transaction,
            scan_id,
            at,
            if job.status == ScanJobStatus::Cancelled {
                "scan.cancelled"
            } else {
                "scan.cancel_requested"
            },
            serde_json::json!({"content_retained": false}),
        )
        .await?;
        transaction.commit().await?;
        Ok(job)
    }

    /// Returns one durable scan receipt and its content-free results.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the lookup or decoding fails.
    pub async fn get_scan_job(
        &self,
        scan_id: Uuid,
    ) -> Result<Option<ScanJobView>, PostgresStoreError> {
        let value = sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT to_jsonb(s) - 'request_fingerprint' FROM scan_jobs s WHERE scan_id = $1",
        )
        .bind(scan_id)
        .fetch_optional(&self.pool)
        .await?;
        value
            .map(serde_json::from_value)
            .transpose()
            .map_err(Into::into)
    }

    /// Lists recent durable scan receipts.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when rows cannot be read or decoded.
    pub async fn list_scan_jobs(&self, limit: u16) -> Result<Vec<ScanJobView>, PostgresStoreError> {
        let values = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT to_jsonb(s) - 'request_fingerprint' FROM scan_jobs s
            ORDER BY created_at DESC, scan_id DESC LIMIT $1
            ",
        )
        .bind(i64::from(limit.clamp(1, 100)))
        .fetch_all(&self.pool)
        .await?;
        values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Fails jobs whose in-memory worker disappeared during a process restart.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when reconciliation fails.
    pub async fn recover_interrupted_scans(&self) -> Result<u64, PostgresStoreError> {
        let at = Utc::now();
        let mut transaction = self.pool.begin().await?;
        let interrupted = sqlx::query_scalar::<_, Uuid>(
            r"
            UPDATE scan_jobs SET status = 'failed', finished_at = $1,
                error_code = 'process_restarted'
            WHERE status IN ('planned', 'running', 'cancel_requested')
            RETURNING scan_id
            ",
        )
        .bind(at)
        .fetch_all(&mut *transaction)
        .await?;
        for scan_id in &interrupted {
            put_scan_audit(
                &mut transaction,
                *scan_id,
                at,
                "scan.failed",
                serde_json::json!({
                    "error_code": "process_restarted",
                    "content_retained": false,
                }),
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(interrupted.len() as u64)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedUsage {
    pub observation_id: Uuid,
    pub installation_id: Uuid,
    pub provider_key: String,
    pub provider_name: String,
    pub provider_category: String,
    pub provider_country_code: Option<String>,
    pub provider_catalogued: bool,
    pub model_reference: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub connector_instance_id: Uuid,
    pub evidence_kind: FindingEvidenceKind,
    /// False for corroborating evidence (for example a correlated flow) that enriches a finding
    /// but does not represent another use of the AI system.
    pub counts_as_usage: bool,
    pub endpoints: Vec<EndpointIdentity>,
    pub destinations: Vec<DestinationIdentity>,
    pub workloads: Vec<WorkloadIdentity>,
    pub user_identity: Option<UserIdentity>,
    pub request_client: Option<RequestClientObservation>,
    pub activity: Option<tally_core::ActivityAttribution>,
}

/// Attribution attached to an already-resolved finding subject.
///
/// Embedding applications can use this contract to add observations for host-owned finding
/// subjects without extending Tally's provider and model registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingObservationContext {
    pub observation_id: Uuid,
    pub installation_id: Uuid,
    pub observed_at: DateTime<Utc>,
    pub connector_instance_id: Uuid,
    pub counts_as_usage: bool,
    pub endpoints: Vec<EndpointIdentity>,
    pub destinations: Vec<DestinationIdentity>,
    pub workloads: Vec<WorkloadIdentity>,
    pub user_identity: Option<UserIdentity>,
    pub request_client: Option<RequestClientObservation>,
    pub activity: Option<tally_core::ActivityAttribution>,
}

impl From<&ObservedUsage> for FindingObservationContext {
    fn from(usage: &ObservedUsage) -> Self {
        Self {
            observation_id: usage.observation_id,
            installation_id: usage.installation_id,
            observed_at: usage.observed_at,
            connector_instance_id: usage.connector_instance_id,
            counts_as_usage: usage.counts_as_usage,
            endpoints: usage.endpoints.clone(),
            destinations: usage.destinations.clone(),
            workloads: usage.workloads.clone(),
            user_identity: usage.user_identity.clone(),
            request_client: usage.request_client.clone(),
            activity: usage.activity.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FindingEvidenceKind {
    AiUsage,
    NetworkActivity,
    ResourceDiscovery,
}

impl FindingEvidenceKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AiUsage => "ai_usage",
            Self::NetworkActivity => "network_activity",
            Self::ResourceDiscovery => "resource_discovery",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointIdentity {
    pub kind: String,
    pub value: String,
    pub role: String,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationIdentity {
    pub kind: String,
    pub value: String,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadIdentity {
    pub namespace_name: String,
    pub workload_name: String,
    pub workload_kind: String,
    pub runtime_image: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserIdentity {
    pub kind: String,
    pub value: String,
    pub email: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RegistryProviderView {
    pub provider_id: Uuid,
    pub key: String,
    pub name: String,
    pub category: String,
    pub country_code: Option<String>,
    pub catalog: bool,
    pub sanctioned: Option<bool>,
    pub model_count: u64,
    pub finding_count: u64,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RegistryModelView {
    pub model_id: Uuid,
    pub key: String,
    pub name: String,
    pub family: String,
    pub country_code: Option<String>,
    pub modalities: Vec<String>,
    pub capabilities: Vec<String>,
    pub catalog: bool,
    pub sanctioned: Option<bool>,
    pub provider_ids: Vec<Uuid>,
    pub provider_names: Vec<String>,
    pub finding_count: u64,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FindingEndpointView {
    pub endpoint_host_id: Uuid,
    pub kind: String,
    pub value: String,
    pub role: String,
    pub port: Option<u16>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FindingDestinationView {
    pub destination_host_id: Uuid,
    pub kind: String,
    pub value: String,
    pub port: Option<u16>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FindingUserView {
    pub endpoint_user_id: Uuid,
    pub kind: String,
    pub value: String,
    pub email: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FindingConnectorView {
    pub connector_instance_id: Uuid,
    pub name: String,
    pub connector_type: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FindingWorkloadView {
    pub namespace_name: String,
    pub workload_name: String,
    pub workload_kind: String,
    pub runtime_image: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FindingClientView {
    pub name: Option<RequestClientKind>,
    pub agent_id: Option<String>,
    pub connector_instance_id: Uuid,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceFindingStatus {
    Unsanctioned,
    AuthorizationQueue,
    Sanctioned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct GovernanceFindingView {
    pub finding_id: Uuid,
    pub status: GovernanceFindingStatus,
    pub violation_reasons: Vec<String>,
    #[schema(value_type = String, example = "ai_usage")]
    pub evidence_kind: FindingEvidenceKind,
    pub provider: RegistryProviderView,
    pub model: Option<RegistryModelView>,
    pub model_version: Option<String>,
    pub first_used_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub usage_count: u64,
    pub endpoints: Vec<FindingEndpointView>,
    pub destinations: Vec<FindingDestinationView>,
    pub users: Vec<FindingUserView>,
    pub connectors: Vec<FindingConnectorView>,
    pub workloads: Vec<FindingWorkloadView>,
    #[serde(default)]
    pub clients: Vec<FindingClientView>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TallyOverviewSummary {
    pub providers_observed: u64,
    pub models_observed: u64,
    pub unsanctioned: u64,
    pub authorization_queue: u64,
    pub sanctioned: u64,
    pub users: u64,
    pub hosts: u64,
    pub connectors: u64,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DataInventory {
    #[serde(default)]
    pub ai_logs: u64,
    #[serde(default)]
    pub inventory_entities: u64,
    pub findings: u64,
    pub endpoint_hosts: u64,
    pub destination_hosts: u64,
    pub endpoint_users: u64,
    pub connectors: u64,
    pub connector_runs: u64,
    pub ingestion_receipts: u64,
    pub scanner_runs: u64,
    pub audit_events: u64,
    pub registry_sanctions: u64,
}

impl DataInventory {
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.ai_logs
            .saturating_add(self.inventory_entities)
            .saturating_add(self.findings)
            .saturating_add(self.endpoint_hosts)
            .saturating_add(self.destination_hosts)
            .saturating_add(self.endpoint_users)
            .saturating_add(self.connectors)
            .saturating_add(self.connector_runs)
            .saturating_add(self.ingestion_receipts)
            .saturating_add(self.scanner_runs)
            .saturating_add(self.audit_events)
            .saturating_add(self.registry_sanctions)
    }
}

impl PostgresStore {
    /// Converts one transient normalized observation into the minimal durable governance model.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the finding transaction cannot be completed.
    #[allow(clippy::too_many_lines)]
    pub async fn record_usage(&self, usage: &ObservedUsage) -> Result<Uuid, PostgresStoreError> {
        let mut transaction = self.pool.begin().await?;
        let finding_id = Self::record_usage_in_transaction(&mut transaction, usage).await?;
        transaction.commit().await?;
        Ok(finding_id)
    }

    /// Converts a bounded set of transient observations into the minimal durable governance model
    /// in one transaction. Observation ids keep this replay-safe when an asynchronous host bridge
    /// retries a batch after writing it but before advancing its own cursor.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when any finding in the batch cannot be written. The whole
    /// transaction is rolled back so callers can safely retry the same batch.
    pub async fn record_usages(
        &self,
        usages: &[ObservedUsage],
    ) -> Result<usize, PostgresStoreError> {
        let mut transaction = self.pool.begin().await?;
        let mut finding_ids = BTreeSet::new();
        for usage in usages {
            finding_ids.insert(Self::record_usage_in_transaction(&mut transaction, usage).await?);
        }
        transaction.commit().await?;
        Ok(finding_ids.len())
    }

    /// Writes every finding derived from one admitted receipt and finalizes that receipt in the
    /// same `PostgreSQL` transaction. A failed write therefore cannot leave partial usage counts or
    /// advance the connector cursor.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when a finding cannot be written or the receipt is no longer
    /// in the writable state.
    pub async fn complete_ingestion_with_usage(
        &self,
        batch_id: Uuid,
        usages: &[ObservedUsage],
    ) -> Result<usize, PostgresStoreError> {
        let mut transaction = self.pool.begin().await?;
        let mut finding_ids = BTreeSet::new();
        for usage in usages {
            finding_ids.insert(Self::record_usage_in_transaction(&mut transaction, usage).await?);
        }
        if !Self::complete_ingestion_in_transaction(&mut transaction, batch_id).await? {
            return Err(PostgresStoreError::IngestionStateConflict);
        }
        transaction.commit().await?;
        Ok(finding_ids.len())
    }

    #[allow(clippy::too_many_lines)]
    async fn record_usage_in_transaction(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        usage: &ObservedUsage,
    ) -> Result<Uuid, PostgresStoreError> {
        let provider_id = sqlx::query_scalar::<_, Uuid>(
            r"
            INSERT INTO ai_providers (key, name, category, country_code, catalog, sanctioned)
            VALUES (
                $1,$2,$3,$4,
                $5 AND EXISTS (SELECT 1 FROM ai_provider_domains WHERE provider_key = $1),
                CASE WHEN $5 AND EXISTS (SELECT 1 FROM ai_provider_domains WHERE provider_key = $1)
                     THEN tally_default_provider_sanction($1) ELSE FALSE END
            )
            ON CONFLICT (key) DO UPDATE SET
                name = EXCLUDED.name,
                updated_at = now()
            RETURNING provider_id
            ",
        )
        .bind(&usage.provider_key)
        .bind(&usage.provider_name)
        .bind(&usage.provider_category)
        .bind(&usage.provider_country_code)
        .bind(usage.provider_catalogued)
        .fetch_one(&mut **transaction)
        .await?;

        let model_identity = usage
            .model_reference
            .as_deref()
            .and_then(normalized_model_identity);
        let model_version = model_identity
            .as_ref()
            .and_then(|(_, _, version)| version.clone());
        let model_id = if let Some((base_reference, aliases, _)) = model_identity {
            let existing = sqlx::query_scalar::<_, Uuid>(
                r"
                SELECT model_id FROM ai_models m
                WHERE (key = ANY($1) OR lower(name) = ANY($1) OR aliases && $1)
                  AND NOT EXISTS (
                    SELECT 1 FROM tally_sample_workspace s
                    WHERE s.manifest->'rows'->'ai_models' @>
                      jsonb_build_array(jsonb_build_object('model_id', m.model_id::text))
                  )
                ORDER BY catalog DESC, name
                LIMIT 1
                ",
            )
            .bind(&aliases)
            .fetch_optional(&mut **transaction)
            .await?;
            let model_id = if let Some(model_id) = existing {
                model_id
            } else {
                let key = format!(
                    "discovered.{}",
                    hex::encode(Sha256::digest(base_reference.as_bytes()))
                );
                sqlx::query_scalar::<_, Uuid>(
                    r"
                    INSERT INTO ai_models (
                        key, name, family, owner_provider_id, country_code, modalities,
                        capabilities, aliases, catalog, sanctioned
                    ) VALUES ($1,$2,$2,$3,$4,'{text}','{}',$5,FALSE,FALSE)
                    ON CONFLICT (key) DO UPDATE SET updated_at = now()
                    RETURNING model_id
                    ",
                )
                .bind(key)
                .bind(base_reference)
                .bind(provider_id)
                .bind(&usage.provider_country_code)
                .bind(aliases)
                .fetch_one(&mut **transaction)
                .await?
            };
            sqlx::query(
                r"
                INSERT INTO ai_provider_models (
                    provider_id, model_id, source, first_seen, last_seen
                ) VALUES ($1,$2,'connector',$3,$3)
                ON CONFLICT (provider_id, model_id) DO UPDATE SET
                    last_seen = GREATEST(ai_provider_models.last_seen, EXCLUDED.last_seen),
                    first_seen = LEAST(ai_provider_models.first_seen, EXCLUDED.first_seen)
                ",
            )
            .bind(provider_id)
            .bind(model_id)
            .bind(usage.observed_at)
            .execute(&mut **transaction)
            .await?;
            Some(model_id)
        } else {
            None
        };

        let finding_id = sqlx::query_scalar::<_, Uuid>(
            r"
            INSERT INTO findings (
                installation_id, provider_id, model_id, model_version, evidence_kind,
                first_used_at, last_used_at, usage_count
            ) VALUES ($1,$2,$3,$4,$5,$6,$6,0)
            ON CONFLICT ON CONSTRAINT findings_usage_identity_key DO UPDATE SET
                updated_at = now()
            RETURNING finding_id
            ",
        )
        .bind(usage.installation_id)
        .bind(provider_id)
        .bind(model_id)
        .bind(&model_version)
        .bind(usage.evidence_kind.as_str())
        .bind(usage.observed_at)
        .fetch_one(&mut **transaction)
        .await?;

        let context = FindingObservationContext::from(usage);
        Self::record_finding_context(transaction, finding_id, &context).await?;
        Ok(finding_id)
    }

    /// Adds replay-safe observation and attribution links to an existing finding.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when any observation or attribution write fails.
    #[allow(clippy::too_many_lines)] // Keep the atomic attribution transaction easy to audit.
    pub async fn record_finding_context(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        finding_id: Uuid,
        usage: &FindingObservationContext,
    ) -> Result<Uuid, PostgresStoreError> {
        sqlx::query(
            r"
            INSERT INTO finding_observations (
                observation_id, finding_id, observed_at, counts_as_usage
            ) VALUES ($1,$2,$3,$4)
            ON CONFLICT (observation_id, finding_id) DO UPDATE SET
                counts_as_usage = finding_observations.counts_as_usage
                                  AND EXCLUDED.counts_as_usage
            ",
        )
        .bind(usage.observation_id)
        .bind(finding_id)
        .bind(usage.observed_at)
        .bind(usage.counts_as_usage)
        .execute(&mut **transaction)
        .await?;
        sqlx::query(
            r"
            UPDATE findings SET
                first_used_at = CASE WHEN $3 THEN LEAST(first_used_at, $2)
                                     ELSE first_used_at END,
                last_used_at = CASE WHEN $3 THEN GREATEST(last_used_at, $2)
                                    ELSE last_used_at END,
                usage_count = (
                    SELECT count(*) FROM finding_observations
                    WHERE finding_id = $1 AND counts_as_usage
                ),
                updated_at = now()
            WHERE finding_id = $1
            ",
        )
        .bind(finding_id)
        .bind(usage.observed_at)
        .bind(usage.counts_as_usage)
        .execute(&mut **transaction)
        .await?;

        sqlx::query(
            r"
            INSERT INTO finding_connectors (
                finding_id, connector_instance_id, first_seen, last_seen
            ) VALUES ($1,$2,$3,$3)
            ON CONFLICT (finding_id, connector_instance_id) DO UPDATE SET
                first_seen = LEAST(finding_connectors.first_seen, EXCLUDED.first_seen),
                last_seen = GREATEST(finding_connectors.last_seen, EXCLUDED.last_seen)
            ",
        )
        .bind(finding_id)
        .bind(usage.connector_instance_id)
        .bind(usage.observed_at)
        .execute(&mut **transaction)
        .await?;

        if activity::record_activity(transaction, finding_id, usage).await? {
            sqlx::query("INSERT INTO identity_replay_jobs(installation_id) VALUES($1) ON CONFLICT(installation_id) DO UPDATE SET requested_generation=identity_replay_jobs.requested_generation+1,updated_at=now()")
                .bind(usage.installation_id).execute(&mut **transaction).await?;
        }

        for endpoint in &usage.endpoints {
            upsert_finding_endpoint(transaction, finding_id, endpoint, usage.observed_at).await?;
        }
        if let Some(client) = &usage.request_client {
            sqlx::query(
                r"
                INSERT INTO finding_clients (
                    finding_id, connector_instance_id, client_name, agent_id, first_seen, last_seen
                ) VALUES ($1,$2,$3,$4,$5,$5)
                ON CONFLICT (finding_id, connector_instance_id, client_name, agent_id) DO UPDATE SET
                    first_seen = LEAST(finding_clients.first_seen, EXCLUDED.first_seen),
                    last_seen = GREATEST(finding_clients.last_seen, EXCLUDED.last_seen)
                ",
            )
            .bind(finding_id)
            .bind(usage.connector_instance_id)
            .bind(
                client
                    .name
                    .map(RequestClientKind::as_str)
                    .unwrap_or_default(),
            )
            .bind(client.agent_id.as_deref().unwrap_or_default())
            .bind(usage.observed_at)
            .execute(&mut **transaction)
            .await?;
        }
        for destination in &usage.destinations {
            upsert_finding_destination(transaction, finding_id, destination, usage.observed_at)
                .await?;
        }
        for workload in &usage.workloads {
            sqlx::query(
                r"
                INSERT INTO finding_workloads (
                    finding_id, namespace_name, workload_name, workload_kind, runtime_image,
                    first_seen, last_seen
                ) VALUES ($1,$2,$3,$4,$5,$6,$6)
                ON CONFLICT (
                    finding_id, namespace_name, workload_name, workload_kind, runtime_image
                ) DO UPDATE SET
                    first_seen = LEAST(finding_workloads.first_seen, EXCLUDED.first_seen),
                    last_seen = GREATEST(finding_workloads.last_seen, EXCLUDED.last_seen)
                ",
            )
            .bind(finding_id)
            .bind(&workload.namespace_name)
            .bind(&workload.workload_name)
            .bind(&workload.workload_kind)
            .bind(workload.runtime_image.as_deref().unwrap_or_default())
            .bind(usage.observed_at)
            .execute(&mut **transaction)
            .await?;
        }
        if let Some(identity) = usage.user_identity.as_ref() {
            let endpoint_user_id = sqlx::query_scalar::<_, Uuid>(
                r"
                INSERT INTO endpoint_users (kind, value, email, first_seen, last_seen)
                VALUES ($1,$2,$3,$4,$4)
                ON CONFLICT (kind, identity_key) DO UPDATE SET
                    email = COALESCE(endpoint_users.email, EXCLUDED.email),
                    first_seen = LEAST(endpoint_users.first_seen, EXCLUDED.first_seen),
                    last_seen = GREATEST(endpoint_users.last_seen, EXCLUDED.last_seen)
                RETURNING endpoint_user_id
                ",
            )
            .bind(&identity.kind)
            .bind(&identity.value)
            .bind(&identity.email)
            .bind(usage.observed_at)
            .fetch_one(&mut **transaction)
            .await?;
            sqlx::query(
                r"
                INSERT INTO finding_users (finding_id, endpoint_user_id, first_seen, last_seen)
                VALUES ($1,$2,$3,$3)
                ON CONFLICT (finding_id, endpoint_user_id) DO UPDATE SET
                    first_seen = LEAST(finding_users.first_seen, EXCLUDED.first_seen),
                    last_seen = GREATEST(finding_users.last_seen, EXCLUDED.last_seen)
                ",
            )
            .bind(finding_id)
            .bind(endpoint_user_id)
            .bind(usage.observed_at)
            .execute(&mut **transaction)
            .await?;
        }
        Ok(finding_id)
    }

    /// Lists providers with observed usage and available-model counts.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the registry query fails.
    pub async fn list_registry_providers(
        &self,
    ) -> Result<Vec<RegistryProviderView>, PostgresStoreError> {
        let values = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT jsonb_build_object(
                'provider_id', p.provider_id,
                'key', p.key,
                'name', p.name,
                'category', p.category,
                'country_code', p.country_code,
                'catalog', p.catalog,
                'sanctioned', p.sanctioned,
                'model_count', count(DISTINCT pm.model_id),
                'finding_count', count(DISTINCT f.finding_id),
                'last_used_at', max(f.last_used_at)
            )
            FROM ai_providers p
            LEFT JOIN ai_provider_models pm ON pm.provider_id = p.provider_id
            LEFT JOIN findings f ON f.provider_id = p.provider_id
            WHERE EXISTS (SELECT 1 FROM ai_provider_domains d WHERE d.provider_key = p.key)
              AND (p.catalog OR p.sanctioned IS NOT NULL
                   OR EXISTS (SELECT 1 FROM findings observed WHERE observed.provider_id = p.provider_id))
            GROUP BY p.provider_id
            ORDER BY p.name
            ",
        )
        .fetch_all(&self.pool)
        .await?;
        values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Returns reviewed AI service domains for actionable providers.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the registry query fails.
    pub async fn list_provider_domains(
        &self,
    ) -> Result<BTreeMap<String, Vec<String>>, PostgresStoreError> {
        let rows = sqlx::query_as::<_, (String, String)>(
            "SELECT provider_key, domain FROM ai_provider_domains ORDER BY provider_key, domain",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut domains = BTreeMap::<String, Vec<String>>::new();
        for (provider_key, domain) in rows {
            domains.entry(provider_key).or_default().push(domain);
        }
        Ok(domains)
    }

    /// Lists global models with their providers and observed usage counts.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the registry query fails.
    pub async fn list_registry_models(&self) -> Result<Vec<RegistryModelView>, PostgresStoreError> {
        let values = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT jsonb_build_object(
                'model_id', m.model_id,
                'key', m.key,
                'name', m.name,
                'family', m.family,
                'country_code', m.country_code,
                'modalities', m.modalities,
                'capabilities', m.capabilities,
                'catalog', m.catalog,
                'sanctioned', m.sanctioned,
                'provider_ids', COALESCE(
                    jsonb_agg(DISTINCT p.provider_id) FILTER (WHERE p.provider_id IS NOT NULL), '[]'
                ),
                'provider_names', COALESCE(
                    jsonb_agg(DISTINCT p.name) FILTER (WHERE p.name IS NOT NULL), '[]'
                ),
                'finding_count', count(DISTINCT f.finding_id),
                'last_used_at', max(f.last_used_at)
            )
            FROM ai_models m
            LEFT JOIN ai_provider_models pm ON pm.model_id = m.model_id
            LEFT JOIN ai_providers p ON p.provider_id = pm.provider_id
            LEFT JOIN findings f ON f.model_id = m.model_id
            WHERE m.catalog OR m.sanctioned IS NOT NULL
               OR EXISTS (SELECT 1 FROM findings observed WHERE observed.model_id = m.model_id)
            GROUP BY m.model_id
            ORDER BY m.family, m.name
            ",
        )
        .fetch_all(&self.pool)
        .await?;
        values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Applies one atomic sanction decision to providers and global models.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the decision or audit transaction fails.
    pub async fn set_registry_sanctions(
        &self,
        provider_ids: &[Uuid],
        model_ids: &[Uuid],
        sanctioned: bool,
    ) -> Result<u64, PostgresStoreError> {
        let mut transaction = self.pool.begin().await?;
        let provider_count = sqlx::query(
            "UPDATE ai_providers p SET sanctioned = $2, updated_at = now() WHERE p.provider_id = ANY($1) AND EXISTS (SELECT 1 FROM ai_provider_domains d WHERE d.provider_key = p.key)",
        )
        .bind(provider_ids)
        .bind(sanctioned)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if provider_count != provider_ids.iter().collect::<BTreeSet<_>>().len() as u64 {
            return Err(PostgresStoreError::InvalidRegistrySanction);
        }
        let model_count = sqlx::query(
            "UPDATE ai_models SET sanctioned = $2, updated_at = now() WHERE model_id = ANY($1)",
        )
        .bind(model_ids)
        .bind(sanctioned)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let affected = provider_count.saturating_add(model_count);
        sqlx::query(
            r"
            INSERT INTO audit_log (audit_id, actor, action, entity_type, entity_id, detail)
            VALUES ($1,$4,'registry.sanction.updated','registry',$2,$3)
            ",
        )
        .bind(Uuid::now_v7())
        .bind(if provider_ids.len() + model_ids.len() == 1 {
            provider_ids
                .first()
                .or_else(|| model_ids.first())
                .map_or_else(|| "bulk".to_owned(), ToString::to_string)
        } else {
            "bulk".to_owned()
        })
        .bind(serde_json::json!({
            "sanctioned": sanctioned,
            "provider_ids": provider_ids,
            "model_ids": model_ids,
            "affected": affected
        }))
        .bind(audit_actor())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(affected)
    }

    /// Lists unique findings with their endpoint, user, and connector context.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the finding query fails.
    #[allow(clippy::too_many_lines)] // Keep the bounded JSON projection in one database query.
    pub async fn list_governance_findings(
        &self,
        limit: u16,
    ) -> Result<Vec<GovernanceFindingView>, PostgresStoreError> {
        let values = sqlx::query_scalar::<_, serde_json::Value>(GOVERNANCE_FINDINGS_SQL)
            .bind(i64::from(limit.clamp(1, 500)))
            .fetch_all(&self.pool)
            .await?;
        values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Returns the compact operational summary for the overview screen.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the aggregate query fails.
    pub async fn tally_overview(&self) -> Result<TallyOverviewSummary, PostgresStoreError> {
        let value = sqlx::query_scalar::<_, serde_json::Value>(
            r"
            SELECT jsonb_build_object(
                'providers_observed', count(DISTINCT f.provider_id),
                'models_observed', count(DISTINCT f.model_id),
                'unsanctioned', count(*) FILTER (WHERE p.sanctioned = FALSE OR m.sanctioned = FALSE),
                'authorization_queue', count(*) FILTER (
                    WHERE p.sanctioned IS DISTINCT FROM FALSE
                      AND (f.model_id IS NULL OR m.sanctioned IS DISTINCT FROM FALSE)
                      AND (
                          p.sanctioned IS NULL
                          OR (f.model_id IS NOT NULL AND m.sanctioned IS NULL)
                      )
                ),
                'sanctioned', count(*) FILTER (
                    WHERE p.sanctioned = TRUE AND (f.model_id IS NULL OR m.sanctioned = TRUE)
                ),
                'users', (SELECT count(*) FROM endpoint_users),
                'hosts', (SELECT count(*) FROM endpoint_hosts),
                'connectors', (SELECT count(*) FROM connector_states),
                'last_used_at', (SELECT max(last_used_at) FROM findings)
            )
            FROM findings f
            JOIN ai_providers p ON p.provider_id = f.provider_id
            LEFT JOIN ai_models m ON m.model_id = f.model_id
            ",
        )
        .fetch_one(&self.pool)
        .await?;
        serde_json::from_value(value).map_err(Into::into)
    }

    /// Counts each removable durable data category.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when a count query fails.
    pub async fn data_inventory(&self) -> Result<DataInventory, PostgresStoreError> {
        let installation = self
            .get_or_create_installation_identity()
            .await?
            .installation_id;
        let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64)>(
            r"
            SELECT
                (SELECT count(*) FROM findings),
                (SELECT count(*) FROM endpoint_hosts),
                (SELECT count(*) FROM destination_hosts),
                (SELECT count(*) FROM endpoint_users),
                (SELECT count(*) FROM connector_states),
                (SELECT count(*) FROM connector_runs),
                (SELECT count(*) FROM ingestion_batches),
                (SELECT count(*) FROM scan_jobs),
                (SELECT count(*) FROM audit_log),
                (SELECT count(*) FROM ai_providers WHERE sanctioned IS DISTINCT FROM (catalog AND tally_default_provider_sanction(key)))
                + (SELECT count(*) FROM ai_models WHERE sanctioned IS DISTINCT FROM (catalog AND tally_default_provider_sanction((SELECT key FROM ai_providers WHERE provider_id = ai_models.owner_provider_id))))
                + (SELECT count(*) FROM tally_estate_reviews WHERE installation_id=$1 AND (sanctioned IS NOT NULL OR flagged))
            ",
        )
        .bind(installation)
        .fetch_one(&self.pool)
        .await?;
        Ok(DataInventory {
            ai_logs: 0,
            inventory_entities: 0,
            findings: count_u64(row.0),
            endpoint_hosts: count_u64(row.1),
            destination_hosts: count_u64(row.2),
            endpoint_users: count_u64(row.3),
            connectors: count_u64(row.4),
            connector_runs: count_u64(row.5),
            ingestion_receipts: count_u64(row.6),
            scanner_runs: count_u64(row.7),
            audit_events: count_u64(row.8),
            registry_sanctions: count_u64(row.9),
        })
    }

    /// Deletes the selected operational scopes and returns the remaining counts.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError`] when the deletion transaction fails.
    #[allow(clippy::too_many_lines)] // All selected data scopes share one deletion transaction and audit receipt.
    pub async fn delete_data(
        &self,
        scopes: &[String],
        before: Option<DateTime<Utc>>,
    ) -> Result<DataInventory, PostgresStoreError> {
        let installation = self
            .get_or_create_installation_identity()
            .await?
            .installation_id;
        let mut transaction = self.pool.begin().await?;
        let all = scopes.iter().any(|scope| scope == "all");
        let cutoff = before.unwrap_or_else(Utc::now);
        if all || scopes.iter().any(|scope| scope == "inventory") {
            sqlx::query("DELETE FROM identity_links l WHERE installation_id=$1 AND ($2::boolean OR NOT EXISTS(SELECT 1 FROM identity_facts f WHERE f.installation_id=l.installation_id AND f.observation_id=l.observation_id AND f.last_seen>=$3))").bind(installation).bind(before.is_none()).bind(cutoff).execute(&mut *transaction).await?;
            sqlx::query("DELETE FROM identity_facts WHERE installation_id=$1 AND ($2::boolean OR last_seen<$3)").bind(installation).bind(before.is_none()).bind(cutoff).execute(&mut *transaction).await?;
            sqlx::query("DELETE FROM identity_device_aliases a WHERE installation_id=$1 AND ($2::boolean OR NOT EXISTS(SELECT 1 FROM identity_facts f WHERE f.installation_id=a.installation_id AND f.observation_id=a.observation_id AND f.connector_instance_id=a.connector_instance_id))").bind(installation).bind(before.is_none()).execute(&mut *transaction).await?;
            sqlx::query("DELETE FROM identity_corrections c WHERE installation_id=$1 AND ($2::boolean OR NOT EXISTS(SELECT 1 FROM identity_facts f WHERE f.installation_id=c.installation_id AND f.entity_id IN (c.subject_id,c.target_id)))").bind(installation).bind(before.is_none()).execute(&mut *transaction).await?;
            sqlx::query("DELETE FROM endpoint_process_facts WHERE installation_id=$1 AND ($2::boolean OR observed_at<$3)").bind(installation).bind(before.is_none()).bind(cutoff).execute(&mut *transaction).await?;
            sqlx::query("DELETE FROM inventory_presence_events WHERE installation_id=$1 AND ($2::boolean OR observed_at<$3)").bind(installation).bind(before.is_none()).bind(cutoff).execute(&mut *transaction).await?;
            sqlx::query("DELETE FROM inventory_source_presence WHERE installation_id=$1 AND ($2::boolean OR last_snapshot_at<$3)").bind(installation).bind(before.is_none()).bind(cutoff).execute(&mut *transaction).await?;
            sqlx::query("DELETE FROM inventory_sync_status WHERE installation_id=$1 AND ($2::boolean OR completed_at<$3)").bind(installation).bind(before.is_none()).bind(cutoff).execute(&mut *transaction).await?;
            sqlx::query("DELETE FROM identity_enrichments WHERE installation_id=$1")
                .bind(installation)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("DELETE FROM identity_replay_jobs WHERE installation_id=$1")
                .bind(installation)
                .execute(&mut *transaction)
                .await?;
        }

        if scopes
            .iter()
            .any(|scope| scope == "inventory" || scope == "connectors")
        {
            sqlx::query("INSERT INTO identity_replay_jobs(installation_id) VALUES($1) ON CONFLICT(installation_id) DO UPDATE SET requested_generation=identity_replay_jobs.requested_generation+1,updated_at=now()")
                .bind(installation).execute(&mut *transaction).await?;
        }
        if all || scopes.iter().any(|scope| scope == "ai_logs") {
            sqlx::query("DELETE FROM endpoint_process_facts WHERE installation_id=$1 AND ($2::boolean OR observed_at<$3)").bind(installation).bind(before.is_none()).bind(cutoff).execute(&mut *transaction).await?;
            sqlx::query("DELETE FROM finding_activity WHERE installation_id=$1 AND ($2::boolean OR observed_at<$3)").bind(installation).bind(before.is_none()).bind(cutoff).execute(&mut *transaction).await?;
            sqlx::query("DELETE FROM identity_enrichments e WHERE e.installation_id=$1 AND NOT EXISTS(SELECT 1 FROM finding_activity a WHERE a.installation_id=e.installation_id AND a.observation_id=e.observation_id)").bind(installation).execute(&mut *transaction).await?;
        }
        if all || scopes.iter().any(|scope| scope == "findings") {
            sqlx::query("DELETE FROM findings WHERE $1::boolean OR last_used_at < $2")
                .bind(before.is_none())
                .bind(cutoff)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("DELETE FROM endpoint_hosts WHERE NOT EXISTS (SELECT 1 FROM finding_hosts fh WHERE fh.endpoint_host_id = endpoint_hosts.endpoint_host_id)")
                .execute(&mut *transaction)
                .await?;
            sqlx::query("DELETE FROM destination_hosts WHERE NOT EXISTS (SELECT 1 FROM finding_destinations fd WHERE fd.destination_host_id = destination_hosts.destination_host_id)")
                .execute(&mut *transaction)
                .await?;
            sqlx::query("DELETE FROM endpoint_users WHERE NOT EXISTS (SELECT 1 FROM finding_users fu WHERE fu.endpoint_user_id = endpoint_users.endpoint_user_id)")
                .execute(&mut *transaction)
                .await?;
        }
        if all || scopes.iter().any(|scope| scope == "connector_history") {
            sqlx::query("DELETE FROM connector_runs WHERE $1::boolean OR completed_at < $2")
                .bind(before.is_none())
                .bind(cutoff)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("DELETE FROM ingestion_batches WHERE $1::boolean OR accepted_at < $2")
                .bind(before.is_none())
                .bind(cutoff)
                .execute(&mut *transaction)
                .await?;
        }
        if all || scopes.iter().any(|scope| scope == "connectors") {
            sqlx::query("DELETE FROM connector_states")
                .execute(&mut *transaction)
                .await
                .map_err(connector_delete_error)?;
        }
        if all || scopes.iter().any(|scope| scope == "scanner_history") {
            sqlx::query("DELETE FROM scan_jobs WHERE $1::boolean OR created_at < $2")
                .bind(before.is_none())
                .bind(cutoff)
                .execute(&mut *transaction)
                .await?;
        }
        let mut audit_entries_deleted = 0;
        if all || scopes.iter().any(|scope| scope == "audit_logs") {
            audit_entries_deleted =
                sqlx::query("DELETE FROM audit_log WHERE $1::boolean OR at < $2")
                    .bind(before.is_none())
                    .bind(cutoff)
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected();
        }
        if all || scopes.iter().any(|scope| scope == "registry_sanctions") {
            sqlx::query("DELETE FROM tally_estate_reviews WHERE installation_id=$3 AND ($1::boolean OR updated_at < $2)")
                .bind(before.is_none())
                .bind(cutoff)
                .bind(installation)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("UPDATE ai_providers SET sanctioned = (catalog AND tally_default_provider_sanction(key)), updated_at = now()")
                .execute(&mut *transaction).await?;
            sqlx::query("UPDATE ai_models SET sanctioned = (catalog AND tally_default_provider_sanction((SELECT key FROM ai_providers WHERE provider_id = ai_models.owner_provider_id))), updated_at = now()")
                .execute(&mut *transaction).await?;
        }
        sqlx::query("UPDATE tally_sample_workspace SET state='partial' WHERE installation_id=$1")
            .bind(installation)
            .execute(&mut *transaction)
            .await?;
        // Written after the deletions so a purge of the audit log still leaves this record.
        sqlx::query(
            r"
            INSERT INTO audit_log (audit_id, actor, action, entity_type, entity_id, detail)
            VALUES ($1,$2,'data.deleted','data',$3,$4)
            ",
        )
        .bind(Uuid::now_v7())
        .bind(audit_actor())
        .bind(installation.to_string())
        .bind(serde_json::json!({
            "scopes": scopes,
            "before": before,
            "audit_entries_deleted": audit_entries_deleted,
        }))
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        self.data_inventory().await
    }
}

/// A host embedding Tally may keep its own state keyed to a connector with `ON DELETE RESTRICT`
/// (for example, blocklist rules it pushed to the vendor and must remove first). Report that as a
/// refusal the operator can act on instead of an unavailable database. `RESTRICT` raises
/// `restrict_violation` (23001); `NO ACTION` raises `foreign_key_violation` (23503).
fn connector_delete_error(error: sqlx::Error) -> PostgresStoreError {
    match &error {
        sqlx::Error::Database(database)
            if matches!(database.code().as_deref(), Some("23001" | "23503")) =>
        {
            PostgresStoreError::ConnectorDeleteBlocked
        }
        _ => error.into(),
    }
}

fn split_model_reference(reference: &str) -> (&str, Option<&str>) {
    let reference = reference.trim();
    let valid_separator = |index: usize| index > 0 && index + 1 < reference.len();
    let separator = [reference.rfind('@'), reference.rfind(':')]
        .into_iter()
        .flatten()
        .filter(|index| valid_separator(*index))
        .max();
    separator.map_or((reference, None), |index| {
        let (base, version) = reference.split_at(index);
        (base.trim(), Some(version[1..].trim()))
    })
}

fn normalized_model_identity(reference: &str) -> Option<(String, Vec<String>, Option<String>)> {
    let normalized = reference.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    let (versionless_reference, version) = split_model_reference(&normalized);
    let base_reference = versionless_reference
        .rsplit_once('/')
        .map_or(versionless_reference, |(_, leaf)| leaf)
        .trim();
    if base_reference.is_empty() {
        return None;
    }
    let version = version
        .filter(|version| !version.is_empty() && version.len() <= 160)
        .map(str::to_owned);
    let versionless_reference = versionless_reference.to_owned();
    let base_reference = base_reference.to_owned();
    let aliases = BTreeSet::from([normalized, versionless_reference, base_reference.clone()])
        .into_iter()
        .collect();
    Some((base_reference, aliases, version))
}

async fn upsert_finding_endpoint(
    transaction: &mut PgConnection,
    finding_id: Uuid,
    endpoint: &EndpointIdentity,
    observed_at: DateTime<Utc>,
) -> Result<(), PostgresStoreError> {
    let endpoint_host_id = sqlx::query_scalar::<_, Uuid>(
        r"
        INSERT INTO endpoint_hosts (kind, value, first_seen, last_seen)
        VALUES ($1,$2,$3,$3)
        ON CONFLICT (kind, value) DO UPDATE SET
            first_seen = LEAST(endpoint_hosts.first_seen, EXCLUDED.first_seen),
            last_seen = GREATEST(endpoint_hosts.last_seen, EXCLUDED.last_seen)
        RETURNING endpoint_host_id
        ",
    )
    .bind(&endpoint.kind)
    .bind(&endpoint.value)
    .bind(observed_at)
    .fetch_one(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO finding_hosts (finding_id, endpoint_host_id, role, port, first_seen, last_seen)
        VALUES ($1,$2,$3,$4,$5,$5)
        ON CONFLICT (finding_id, endpoint_host_id, role, port) DO UPDATE SET
            first_seen = LEAST(finding_hosts.first_seen, EXCLUDED.first_seen),
            last_seen = GREATEST(finding_hosts.last_seen, EXCLUDED.last_seen)
        ",
    )
    .bind(finding_id)
    .bind(endpoint_host_id)
    .bind(&endpoint.role)
    .bind(i32::from(endpoint.port.unwrap_or(0)))
    .bind(observed_at)
    .execute(&mut *transaction)
    .await?;
    Ok(())
}

async fn upsert_finding_destination(
    transaction: &mut PgConnection,
    finding_id: Uuid,
    destination: &DestinationIdentity,
    observed_at: DateTime<Utc>,
) -> Result<(), PostgresStoreError> {
    let destination_host_id = sqlx::query_scalar::<_, Uuid>(
        r"
        INSERT INTO destination_hosts (kind, value, first_seen, last_seen)
        VALUES ($1,$2,$3,$3)
        ON CONFLICT (kind, value) DO UPDATE SET
            first_seen = LEAST(destination_hosts.first_seen, EXCLUDED.first_seen),
            last_seen = GREATEST(destination_hosts.last_seen, EXCLUDED.last_seen)
        RETURNING destination_host_id
        ",
    )
    .bind(&destination.kind)
    .bind(&destination.value)
    .bind(observed_at)
    .fetch_one(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO finding_destinations (
            finding_id, destination_host_id, port, first_seen, last_seen
        )
        VALUES ($1,$2,$3,$4,$4)
        ON CONFLICT (finding_id, destination_host_id, port) DO UPDATE SET
            first_seen = LEAST(finding_destinations.first_seen, EXCLUDED.first_seen),
            last_seen = GREATEST(finding_destinations.last_seen, EXCLUDED.last_seen)
        ",
    )
    .bind(finding_id)
    .bind(destination_host_id)
    .bind(i32::from(destination.port.unwrap_or(0)))
    .bind(observed_at)
    .execute(&mut *transaction)
    .await?;
    Ok(())
}

async fn put_scan_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scan_id: Uuid,
    at: DateTime<Utc>,
    action: &'static str,
    detail: serde_json::Value,
) -> Result<(), PostgresStoreError> {
    sqlx::query(
        r"
        INSERT INTO audit_log (audit_id, at, actor, action, entity_type, entity_id, detail)
        VALUES ($1,$2,$6,$3,'scan',$4,$5)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(at)
    .bind(action)
    .bind(scan_id.to_string())
    .bind(detail)
    .bind(audit_actor())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn put_connector_run_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    run: &ConnectorRunRecord,
) -> Result<(), PostgresStoreError> {
    sqlx::query(
        r"
        INSERT INTO audit_log (
            audit_id, at, actor, action, entity_type, entity_id, detail
        ) VALUES ($1,$2,'system:tally-collector','connector.run.recorded',
            'connector',$3,$4)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(run.completed_at)
    .bind(run.connector_instance_id.to_string())
    .bind(serde_json::json!({
        "run_id": run.run_id,
        "status": enum_string(run.status, "failed")?,
        "records_read": run.records_read,
        "accepted": run.accepted,
        "ignored": run.ignored,
        "rejected": run.rejected,
        "deduplicated": run.deduplicated,
        "cursor_advanced": run.cursor_before != run.cursor_after,
        "redaction_digest": &run.redaction_digest,
    }))
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn put_authorization_transition(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: &AuthorizationTransitionRequest,
    request_fingerprint: &str,
    transition: &AuthorizationTransitionView,
) -> Result<(), PostgresStoreError> {
    sqlx::query(
        r"
        UPDATE ai_system_views SET authorization_status = $2, revision = $3
        WHERE system_id = $1
        ",
    )
    .bind(request.system_id)
    .bind(enum_string(request.to_status, "discovered")?)
    .bind(transition.new_revision)
    .execute(&mut **transaction)
    .await?;
    sqlx::query("UPDATE entities SET revision = GREATEST(revision, $2) WHERE entity_id = $1")
        .bind(request.system_id)
        .bind(transition.new_revision)
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        r"
        INSERT INTO authorization_transitions (
            transition_id, system_id, from_status, to_status, reason_code, actor,
            previous_revision, new_revision, idempotency_key, at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        ",
    )
    .bind(transition.transition_id)
    .bind(transition.system_id)
    .bind(enum_string(transition.from_status, "discovered")?)
    .bind(enum_string(transition.to_status, "discovered")?)
    .bind(enum_string(transition.reason_code, "needs_owner_review")?)
    .bind(&transition.actor)
    .bind(transition.previous_revision)
    .bind(transition.new_revision)
    .bind(transition.idempotency_key)
    .bind(transition.at)
    .execute(&mut **transaction)
    .await?;
    let response = serde_json::to_value(transition)?;
    sqlx::query(
        r"
        INSERT INTO mutation_idempotency (
            idempotency_key, action, entity_id, request_fingerprint, response, created_at
        ) VALUES ($1,'authorization.transition',$2,$3,$4,$5)
        ",
    )
    .bind(request.idempotency_key)
    .bind(request.system_id)
    .bind(request_fingerprint)
    .bind(&response)
    .bind(transition.at)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO audit_log (audit_id, at, actor, action, entity_type, entity_id, detail)
        VALUES ($1,$2,$3,'authorization.changed','ai_system',$4,$5)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(transition.at)
    .bind(&transition.actor)
    .bind(request.system_id.to_string())
    .bind(serde_json::json!({
        "from_status": enum_string(transition.from_status, "discovered")?,
        "to_status": enum_string(transition.to_status, "discovered")?,
        "reason_code": enum_string(transition.reason_code, "needs_owner_review")?,
        "previous_revision": transition.previous_revision,
        "new_revision": transition.new_revision,
        "idempotency_key": transition.idempotency_key,
    }))
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn put_system_view(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    installation_id: Uuid,
    resolved: &ResolvedSystem,
) -> Result<(), PostgresStoreError> {
    let view = &resolved.view;
    let registry_entry_id = resolved
        .stable_key
        .strip_prefix("registry_entry:")
        .unwrap_or(&resolved.stable_key);
    sqlx::query(
        r"
        INSERT INTO ai_system_views (
            system_id, installation_id, registry_entry_id, display_name, surface, lifecycle,
            authorization_status, first_seen, last_seen, evidence_quality, confidence_bps, revision
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        ON CONFLICT (system_id) DO UPDATE SET
            display_name = EXCLUDED.display_name,
            first_seen = LEAST(ai_system_views.first_seen, EXCLUDED.first_seen),
            last_seen = GREATEST(ai_system_views.last_seen, EXCLUDED.last_seen),
            confidence_bps = GREATEST(ai_system_views.confidence_bps, EXCLUDED.confidence_bps),
            evidence_quality = CASE
                WHEN EXCLUDED.confidence_bps > ai_system_views.confidence_bps
                THEN EXCLUDED.evidence_quality ELSE ai_system_views.evidence_quality END,
            revision = ai_system_views.revision + 1
        WHERE EXCLUDED.first_seen < ai_system_views.first_seen
           OR EXCLUDED.last_seen > ai_system_views.last_seen
           OR EXCLUDED.confidence_bps > ai_system_views.confidence_bps
        ",
    )
    .bind(view.system_id)
    .bind(installation_id)
    .bind(registry_entry_id)
    .bind(&view.display_name)
    .bind(enum_string(view.surface, "unknown")?)
    .bind(enum_string(view.lifecycle, "observed")?)
    .bind(enum_string(view.authorization, "discovered")?)
    .bind(view.first_seen)
    .bind(view.last_seen)
    .bind(enum_string(view.evidence_quality, "unknown")?)
    .bind(i32::from(view.confidence.get()))
    .bind(view.revision)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn put_claim_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    claim: &Claim,
) -> Result<(), PostgresStoreError> {
    let predicate = serde_json::to_value(&claim.predicate)?.to_string();
    let class = enum_string(claim.class, "derived")?;
    let status = enum_string(claim.status, "active")?;
    let rule = serde_json::to_value(&claim.rule)?;
    let stored = sqlx::query_scalar::<_, Uuid>(
        r"
        INSERT INTO claims (
            claim_id, subject_entity_id, predicate, value, class, confidence_bps, status,
            valid_from, valid_until, rule, registry_version, created_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        ON CONFLICT (claim_id) DO UPDATE SET
            created_at = LEAST(claims.created_at, EXCLUDED.created_at)
        WHERE claims.subject_entity_id = EXCLUDED.subject_entity_id
          AND claims.predicate = EXCLUDED.predicate
          AND claims.value = EXCLUDED.value
          AND claims.class = EXCLUDED.class
          AND claims.confidence_bps = EXCLUDED.confidence_bps
          AND claims.status = EXCLUDED.status
          AND claims.valid_from = EXCLUDED.valid_from
          AND claims.valid_until IS NOT DISTINCT FROM EXCLUDED.valid_until
          AND claims.rule IS NOT DISTINCT FROM EXCLUDED.rule
          AND claims.registry_version IS NOT DISTINCT FROM EXCLUDED.registry_version
        RETURNING claim_id
        ",
    )
    .bind(claim.claim_id)
    .bind(claim.subject.entity_id)
    .bind(predicate)
    .bind(&claim.value)
    .bind(class)
    .bind(i32::from(claim.confidence.get()))
    .bind(status)
    .bind(claim.valid_from)
    .bind(claim.valid_until)
    .bind(rule)
    .bind(&claim.registry_version)
    .bind(claim.created_at)
    .fetch_optional(&mut **transaction)
    .await?;
    if stored.is_none() {
        return Err(PostgresStoreError::ClaimConflict);
    }
    Ok(())
}

fn enum_string(
    value: impl serde::Serialize,
    fallback: &'static str,
) -> Result<String, serde_json::Error> {
    Ok(serde_json::to_value(value)?
        .as_str()
        .unwrap_or(fallback)
        .to_owned())
}

fn count_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn enum_value<T: Serialize>(value: T) -> Result<String, PostgresStoreError> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| {
            PostgresStoreError::Json(serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "enum did not serialize as a string",
            )))
        })
}

fn project_cloud_usage_rows(
    rows: Vec<CloudUsagePathRow>,
) -> Result<CloudUsageProjectionScan, PostgresStoreError> {
    let mut grouped = BTreeMap::<(Uuid, Uuid), Vec<CloudUsagePathRow>>::new();
    for row in rows {
        grouped
            .entry((row.flow_relationship_id, row.flow_observation_id))
            .or_default()
            .push(row);
    }
    let mut projections = Vec::new();
    let mut conflicts = Vec::new();
    for rows in grouped.into_values() {
        let first = rows
            .first()
            .ok_or(PostgresStoreError::CloudUsageProjectionInvalid)?;
        let mappings = rows
            .iter()
            .map(|row| row.mapping_relationship_id)
            .collect::<BTreeSet<_>>();
        let mapping_count = u32::try_from(first.mapping_count)
            .map_err(|_| PostgresStoreError::CloudUsageProjectionInvalid)?;
        if mapping_count < 1 || usize::try_from(mapping_count).ok() != Some(mappings.len()) {
            return Err(PostgresStoreError::CloudUsageProjectionInvalid);
        }
        if mapping_count > 1 {
            conflicts.push(cloud_usage_conflict(
                first,
                &rows,
                mapping_count,
                tally_core::AttributionConflictType::CompetingNetworkMapping,
            )?);
            continue;
        }
        let system_paths = rows
            .iter()
            .filter_map(|row| {
                row.serves_relationship_id
                    .zip(row.system_id)
                    .zip(row.inventory_observation_id)
                    .map(|((relationship_id, system_id), _)| (relationship_id, system_id))
            })
            .collect::<BTreeSet<_>>();
        if system_paths.len() > 1 {
            conflicts.push(cloud_usage_conflict(
                first,
                &rows,
                u32::try_from(system_paths.len())
                    .map_err(|_| PostgresStoreError::CloudUsageProjectionInvalid)?,
                tally_core::AttributionConflictType::CompetingSystemMapping,
            )?);
            continue;
        }
        let Some((serves_relationship_id, system_id)) = system_paths.into_iter().next() else {
            continue;
        };
        projections.push(cloud_usage_projection(
            first,
            &rows,
            serves_relationship_id,
            system_id,
        )?);
    }
    projections.sort_by_key(|item| {
        (
            item.valid_from,
            item.flow_evidence.observation_id,
            item.system_id,
        )
    });
    conflicts.sort_by_key(|item| {
        (
            item.valid_from,
            item.flow_observation_id,
            item.destination_asset_id,
        )
    });
    Ok(CloudUsageProjectionScan {
        projections,
        conflicts,
    })
}

fn cloud_usage_conflict(
    first: &CloudUsagePathRow,
    rows: &[CloudUsagePathRow],
    candidate_count: u32,
    conflict_type: tally_core::AttributionConflictType,
) -> Result<CloudUsageConflictInput, PostgresStoreError> {
    let mut evidence_observation_ids = BTreeSet::new();
    evidence_observation_ids.insert(first.flow_observation_id);
    evidence_observation_ids.extend(rows.iter().map(|row| row.mapping_observation_id));
    evidence_observation_ids.extend(rows.iter().filter_map(|row| row.inventory_observation_id));
    if evidence_observation_ids.len() > 256 {
        return Err(PostgresStoreError::CloudUsageProjectionTooLarge);
    }
    Ok(CloudUsageConflictInput {
        installation_id: first.installation_id,
        destination_asset_id: first.destination_asset_id,
        flow_relationship_id: first.flow_relationship_id,
        flow_observation_id: first.flow_observation_id,
        conflict_type,
        candidate_count,
        valid_from: first.flow_valid_from,
        valid_until: first.flow_valid_until,
        evidence_observation_ids: evidence_observation_ids.into_iter().collect(),
    })
}

fn cloud_usage_projection(
    first: &CloudUsagePathRow,
    rows: &[CloudUsagePathRow],
    serves_relationship_id: Uuid,
    system_id: Uuid,
) -> Result<CloudUsageProjectionInput, PostgresStoreError> {
    let mut mapping_evidence = BTreeMap::new();
    let mut inventory_evidence = BTreeMap::new();
    for row in rows {
        mapping_evidence
            .entry(row.mapping_observation_id)
            .or_insert_with(|| UsageEvidenceInput {
                observation_id: row.mapping_observation_id,
                source_lineage_id: row.mapping_lineage_id.clone(),
                valid_from: Some(row.mapping_valid_from),
                valid_until: row.mapping_valid_until,
            });
        if row.serves_relationship_id == Some(serves_relationship_id)
            && row.system_id == Some(system_id)
            && let (Some(observation_id), Some(source_lineage_id)) = (
                row.inventory_observation_id,
                row.inventory_lineage_id.as_ref(),
            )
        {
            inventory_evidence
                .entry(observation_id)
                .or_insert_with(|| UsageEvidenceInput {
                    observation_id,
                    source_lineage_id: source_lineage_id.clone(),
                    valid_from: row.inventory_valid_from,
                    valid_until: row.inventory_valid_until,
                });
        }
    }
    let best_window = mapping_evidence
        .values()
        .filter_map(|evidence| {
            let mapping_from = evidence.valid_from?;
            let from = first.flow_valid_from.max(mapping_from);
            let until = first
                .flow_valid_until
                .min(evidence.valid_until.unwrap_or(first.flow_valid_until));
            (until > from).then_some((from, until))
        })
        .max_by(|left, right| {
            (left.1 - left.0)
                .cmp(&(right.1 - right.0))
                .then_with(|| right.0.cmp(&left.0))
        })
        .ok_or(PostgresStoreError::CloudUsageProjectionInvalid)?;
    if inventory_evidence.is_empty() {
        return Err(PostgresStoreError::CloudUsageProjectionInvalid);
    }
    Ok(CloudUsageProjectionInput {
        installation_id: first.installation_id,
        source_asset_id: first.source_asset_id,
        destination_asset_id: first.destination_asset_id,
        mapped_resource_id: first.mapped_resource_id,
        system_id,
        flow_relationship_id: first.flow_relationship_id,
        mapping_relationship_id: first.mapping_relationship_id,
        serves_relationship_id,
        valid_from: best_window.0,
        valid_until: best_window.1,
        flow_evidence: UsageEvidenceInput {
            observation_id: first.flow_observation_id,
            source_lineage_id: first.flow_lineage_id.clone(),
            valid_from: Some(first.flow_valid_from),
            valid_until: Some(first.flow_valid_until),
        },
        mapping_evidence: mapping_evidence.into_values().collect(),
        inventory_evidence: inventory_evidence.into_values().collect(),
    })
}

fn validate_relationship_write(
    relationship: &EntityRelationship,
    evidence: &[RelationshipEvidence],
) -> Result<(), PostgresStoreError> {
    relationship.validate()?;
    if evidence.is_empty() {
        return Err(PostgresStoreError::RelationshipEvidenceRequired);
    }
    for item in evidence {
        item.validate()?;
        if item.relationship_id != relationship.relationship_id {
            return Err(PostgresStoreError::RelationshipEvidenceMismatch);
        }
    }
    Ok(())
}

fn validate_attribution_conflict(conflict: &AttributionConflict) -> Result<(), PostgresStoreError> {
    if conflict.candidate_count < 2
        || conflict.valid_until <= conflict.valid_from
        || conflict.revision < 1
        || conflict.updated_at < conflict.created_at
        || conflict.evidence_observation_ids.is_empty()
        || conflict.evidence_observation_ids.len() > 256
        || !conflict
            .evidence_observation_ids
            .contains(&conflict.source_observation_id)
        || !safe_code_with_punctuation(&conflict.rule.rule_id)
        || !safe_code_with_punctuation(&conflict.rule.version)
    {
        return Err(PostgresStoreError::InvalidAttributionConflict);
    }
    let mut sorted = conflict.evidence_observation_ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted != conflict.evidence_observation_ids {
        return Err(PostgresStoreError::InvalidAttributionConflict);
    }
    let expected_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!(
            "godel-tally:attribution-conflict:{}:{}:{}:{}",
            conflict.installation_id,
            conflict.source_relationship_id,
            conflict.source_observation_id,
            conflict.conflict_type.as_str()
        )
        .as_bytes(),
    );
    if conflict.conflict_id != expected_id {
        return Err(PostgresStoreError::InvalidAttributionConflict);
    }
    Ok(())
}

fn count_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn canonicalize_graph_relationships(
    rows: Vec<CanonicalGraphRelationshipRow>,
    limit: u16,
) -> Vec<GraphRelationshipView> {
    let mut grouped = BTreeMap::<
        (Uuid, String, Uuid),
        (EntityRelationship, BTreeSet<Uuid>, BTreeSet<String>),
    >::new();
    for row in rows {
        let mut relationship = row.relationship;
        relationship.relationship_id = EntityRelationship::deterministic_id(
            relationship.installation_id,
            relationship.subject.entity_id,
            relationship.predicate,
            relationship.object.entity_id,
        );
        let key = (
            relationship.subject.entity_id,
            relationship.predicate.as_str().to_owned(),
            relationship.object.entity_id,
        );
        let observations = row
            .evidence_observation_ids
            .into_iter()
            .collect::<BTreeSet<_>>();
        let lineages = row.source_lineage_ids.into_iter().collect::<BTreeSet<_>>();
        if let Some((stored, stored_observations, stored_lineages)) = grouped.get_mut(&key) {
            stored.confidence = stored.confidence.max(relationship.confidence);
            if relationship.status == RelationshipStatus::Disputed {
                stored.status = RelationshipStatus::Disputed;
            }
            stored.valid_from = stored.valid_from.min(relationship.valid_from);
            stored.valid_until = match (stored.valid_until, relationship.valid_until) {
                (Some(current), Some(next)) => Some(current.max(next)),
                _ => None,
            };
            if stored.rule != relationship.rule {
                stored.rule = None;
            }
            stored.created_at = stored.created_at.min(relationship.created_at);
            stored.revision = stored.revision.max(relationship.revision);
            stored_observations.extend(observations);
            stored_lineages.extend(lineages);
        } else {
            grouped.insert(key, (relationship, observations, lineages));
        }
    }
    let mut projected = grouped
        .into_values()
        .map(|(mut relationship, observations, lineages)| {
            relationship.independent_lineage_count =
                u32::try_from(lineages.len()).unwrap_or(u32::MAX);
            GraphRelationshipView {
                relationship,
                evidence_count: u32::try_from(observations.len()).unwrap_or(u32::MAX),
            }
        })
        .collect::<Vec<_>>();
    projected.sort_by(|left, right| {
        right
            .relationship
            .valid_from
            .cmp(&left.relationship.valid_from)
            .then_with(|| {
                left.relationship
                    .relationship_id
                    .cmp(&right.relationship.relationship_id)
            })
    });
    projected.truncate(usize::from(limit));
    projected
}

#[derive(Serialize)]
struct EntityResolutionDigest<'a> {
    schema: &'static str,
    operation: EntityResolutionOperation,
    source_entity_id: Uuid,
    source_kind: EntityKind,
    source_revision: i64,
    target_entity_id: Uuid,
    target_kind: EntityKind,
    target_revision: i64,
    merge_event_id: Option<Uuid>,
    impact: &'a EntityResolutionImpact,
    evidence_mutated: bool,
    content_retained: bool,
}

fn build_entity_resolution_preview(
    operation: EntityResolutionOperation,
    state: EntityResolutionState,
    source_revision: i64,
    target_revision: i64,
    merge_event_id: Option<Uuid>,
) -> Result<EntityResolutionPreviewData, PostgresStoreError> {
    let source = state
        .source
        .ok_or(PostgresStoreError::EntityResolutionEntityNotFound)?;
    let target = state
        .target
        .ok_or(PostgresStoreError::EntityResolutionEntityNotFound)?;
    if source.entity_id == target.entity_id
        || source.kind != target.kind
        || source_revision < 1
        || target_revision < 1
    {
        return Err(PostgresStoreError::InvalidEntityResolution);
    }
    if source.revision != source_revision || target.revision != target_revision {
        return Err(PostgresStoreError::EntityResolutionRevisionConflict {
            source_revision: source.revision,
            target_revision: target.revision,
        });
    }
    match operation {
        EntityResolutionOperation::Merge => {
            if merge_event_id.is_some()
                || state.source_is_alias
                || state.source_has_aliases
                || state.target_is_alias
            {
                return Err(PostgresStoreError::InvalidEntityResolution);
            }
        }
        EntityResolutionOperation::Split => {
            if !state.source_is_alias
                || state.source_has_aliases
                || state.target_is_alias
                || merge_event_id.is_none()
                || state.active_merge_event_id != merge_event_id
            {
                return Err(PostgresStoreError::InvalidEntityResolution);
            }
        }
    }
    let digest_payload = EntityResolutionDigest {
        schema: "godel-tally/entity-resolution-preview/v1",
        operation,
        source_entity_id: source.entity_id,
        source_kind: source.kind,
        source_revision,
        target_entity_id: target.entity_id,
        target_kind: target.kind,
        target_revision,
        merge_event_id,
        impact: &state.impact,
        evidence_mutated: false,
        content_retained: false,
    };
    let preview_digest = hex::encode(Sha256::digest(serde_json::to_vec(&digest_payload)?));
    Ok(EntityResolutionPreviewData {
        operation,
        source,
        target,
        merge_event_id,
        impact: state.impact,
        preview_digest,
    })
}

fn validate_entity_resolution_commit(
    request: &EntityResolutionCommit,
) -> Result<(), PostgresStoreError> {
    if request.source_entity_id == request.target_entity_id
        || request.source_revision < 1
        || request.target_revision < 1
        || !valid_lower_sha256(&request.preview_digest)
        || !valid_lower_sha256(&request.request_sha256)
        || matches!(request.operation, EntityResolutionOperation::Merge)
            && request.merge_event_id.is_some()
        || matches!(request.operation, EntityResolutionOperation::Split)
            && request.merge_event_id.is_none()
    {
        return Err(PostgresStoreError::InvalidEntityResolution);
    }
    Ok(())
}

fn validate_purge_digest(value: &str) -> Result<(), PostgresStoreError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(PostgresStoreError::InvalidPurgeDigest)
    }
}

fn safe_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Bounds the operator-typed connector label the same way the column CHECK does.
///
/// An empty name is the "unset" value, so it is accepted and clears whatever was stored.
/// Control characters are rejected outright: the name is rendered in the console and echoed
/// into audit detail, and neither should have to defend against a smuggled newline.
fn safe_connector_friendly_name(name: &str) -> bool {
    name.trim() == name && name.chars().count() <= 120 && !name.chars().any(char::is_control)
}

fn safe_code_with_punctuation(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 96
        && code.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
}

fn validate_registry_overlay_create(
    request: &RegistryOverlayCreate,
) -> Result<(), PostgresStoreError> {
    let digest_valid = [&request.overlay_sha256, &request.request_sha256]
        .into_iter()
        .all(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        });
    let overlay_valid = request.overlay.is_object()
        && serde_json::to_vec(&request.overlay).is_ok_and(|bytes| {
            bytes.len() <= 131_072 && hex::encode(Sha256::digest(&bytes)) == request.overlay_sha256
        });
    if !safe_code_with_punctuation(&request.overlay_id)
        || !digest_valid
        || !overlay_valid
        || !(1..=32).contains(&request.entry_count)
        || !(1..=256).contains(&request.matcher_count)
    {
        return Err(PostgresStoreError::UnsafeRegistryOverlay);
    }
    Ok(())
}

fn validate_classification_rule_set(
    request: &ClassificationRuleSetCreate,
) -> Result<(), PostgresStoreError> {
    let digest_valid = |digest: &str| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    };
    let rules_valid = request.rules.as_array().is_some_and(|rules| {
        (1..=500).contains(&rules.len())
            && serde_json::to_vec(&request.rules).is_ok_and(|bytes| {
                bytes.len() <= 131_072 && hex::encode(Sha256::digest(bytes)) == request.rules_sha256
            })
    });
    let systems_valid = request.matched_systems.len() <= 10_000
        && request
            .matched_systems
            .windows(2)
            .all(|pair| pair[0].system_id < pair[1].system_id)
        && request.matched_systems.iter().all(|system| {
            system.revision >= 0
                && matches!(
                    system.authorization_status.as_str(),
                    "discovered" | "under_review" | "authorized" | "unauthorized" | "retired"
                )
        });
    if !matches!(request.decision.as_str(), "authorized" | "unauthorized")
        || !digest_valid(&request.request_sha256)
        || !digest_valid(&request.preview_digest)
        || !digest_valid(&request.rules_sha256)
        || !rules_valid
        || !systems_valid
    {
        return Err(PostgresStoreError::UnsafeClassificationRuleSet);
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredClassificationHostRule {
    kind: String,
    host: String,
}

async fn validate_no_classification_conflict(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: &ClassificationRuleSetCreate,
) -> Result<(), PostgresStoreError> {
    let requested_rules =
        serde_json::from_value::<Vec<StoredClassificationHostRule>>(request.rules.clone())?;
    if requested_rules
        .iter()
        .any(|rule| !matches!(rule.kind.as_str(), "exact" | "suffix"))
    {
        return Err(PostgresStoreError::UnsafeClassificationRuleSet);
    }
    let existing = sqlx::query_as::<_, (String, serde_json::Value, Vec<Uuid>)>(
        r"
        SELECT decision, rules, matched_system_ids
        FROM classification_rule_sets
        WHERE installation_id = $1 AND active AND decision <> $2
        ",
    )
    .bind(request.installation_id)
    .bind(&request.decision)
    .fetch_all(&mut **transaction)
    .await?;
    for (_, rules, matched_system_ids) in existing {
        let rules = serde_json::from_value::<Vec<StoredClassificationHostRule>>(rules)?;
        let domain_overlap = requested_rules.iter().any(|requested| {
            rules
                .iter()
                .any(|stored| stored_classification_rules_overlap(requested, stored))
        });
        let system_overlap = request
            .matched_systems
            .iter()
            .any(|system| matched_system_ids.binary_search(&system.system_id).is_ok());
        if domain_overlap || system_overlap {
            return Err(PostgresStoreError::ClassificationRuleConflict);
        }
    }
    Ok(())
}

fn stored_classification_rules_overlap(
    first: &StoredClassificationHostRule,
    second: &StoredClassificationHostRule,
) -> bool {
    fn suffix_matches(suffix: &str, host: &str) -> bool {
        host == suffix
            || host
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    }
    match (first.kind.as_str(), second.kind.as_str()) {
        ("exact", "exact") => first.host == second.host,
        ("exact", "suffix") => suffix_matches(&second.host, &first.host),
        ("suffix", "exact") => suffix_matches(&first.host, &second.host),
        ("suffix", "suffix") => {
            suffix_matches(&first.host, &second.host) || suffix_matches(&second.host, &first.host)
        }
        _ => true,
    }
}

fn valid_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn continuity_set_digest(mut rows: Vec<String>) -> ContinuitySetDigest {
    rows.sort_unstable();
    let count = u64::try_from(rows.len()).unwrap_or(u64::MAX);
    let mut digest = Sha256::new();
    digest.update(b"godel-tally-continuity-set-v1\0");
    for row in rows {
        digest.update(u64::try_from(row.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(row.as_bytes());
    }
    ContinuitySetDigest {
        count,
        sha256: hex::encode(digest.finalize()),
    }
}

fn classification_conflict_audit_id(system_id: Uuid, rule_set_ids: &[Uuid]) -> Uuid {
    let mut input = format!("godel-tally:classification-conflict:{system_id}");
    for rule_set_id in rule_set_ids {
        input.push(':');
        input.push_str(&rule_set_id.to_string());
    }
    Uuid::new_v5(&Uuid::NAMESPACE_URL, input.as_bytes())
}

/// Returns the bounded backfill policy for an eligible time-windowed source.
#[must_use]
pub fn connector_backfill_capability(
    config_refs: &serde_json::Value,
) -> Option<ConnectorBackfillCapability> {
    let kind = config_refs.get("kind")?.as_str()?;
    if kind == "microsoft_defender_graph_hunting_v1" {
        return Some(ConnectorBackfillCapability {
            source_kind: ConnectorBackfillSourceKind::MicrosoftDefenderApi,
            minimum_lookback_seconds: 60,
            maximum_lookback_seconds: 604_800,
        });
    }
    if kind == "nextdns_api_v1" {
        return Some(ConnectorBackfillCapability {
            source_kind: ConnectorBackfillSourceKind::NextdnsApi,
            minimum_lookback_seconds: 60,
            maximum_lookback_seconds: 86_400,
        });
    }
    let adapter = config_refs.get("adapter")?.as_str()?;
    if kind == "cloud_network_api_v1"
        && matches!(
            adapter,
            "aws_cloud_flow_api" | "azure_cloud_flow_api" | "gcp_cloud_flow_api"
        )
    {
        return Some(ConnectorBackfillCapability {
            source_kind: ConnectorBackfillSourceKind::CloudFlowApi,
            minimum_lookback_seconds: 300,
            maximum_lookback_seconds: 3_600,
        });
    }
    None
}

fn connector_backfill_preview(
    state: &ConnectorBackfillState,
    lookback_seconds: u32,
    at: DateTime<Utc>,
) -> Result<ConnectorBackfillPreview, PostgresStoreError> {
    if state
        .job
        .lease_until
        .is_some_and(|lease_until| lease_until > at)
    {
        return Err(PostgresStoreError::ConnectorJobLeased);
    }
    let policy = connector_backfill_capability(&state.job.config_refs)
        .ok_or(PostgresStoreError::ConnectorBackfillUnsupported)?;
    if !(policy.minimum_lookback_seconds..=policy.maximum_lookback_seconds)
        .contains(&lookback_seconds)
    {
        return Err(PostgresStoreError::ConnectorBackfillOutOfRange);
    }
    let preview_digest = hex::encode(Sha256::digest(serde_json::to_vec(&(
        "connector_backfill_preview_v1",
        state.installation_id,
        state.job.job_id,
        state.job.connector_instance_id,
        policy.source_kind,
        state.job.status,
        state.job.schedule_seconds,
        state.job.updated_at,
        state.cursor_present,
        lookback_seconds,
        policy.minimum_lookback_seconds,
        policy.maximum_lookback_seconds,
        false,
    ))?));
    Ok(ConnectorBackfillPreview {
        job_id: state.job.job_id,
        connector_instance_id: state.job.connector_instance_id,
        source_kind: policy.source_kind,
        job_status: state.job.status,
        lookback_seconds,
        minimum_lookback_seconds: policy.minimum_lookback_seconds,
        maximum_lookback_seconds: policy.maximum_lookback_seconds,
        cursor_present: state.cursor_present,
        job_updated_at: state.job.updated_at,
        preview_digest,
    })
}

fn validate_connector_job(job: &ConnectorJobSpec) -> Result<(), PostgresStoreError> {
    let schedule_valid = match job.mode {
        ConnectorJobMode::Scheduled => job
            .schedule_seconds
            .is_some_and(|seconds| (60..=86_400).contains(&seconds)),
        ConnectorJobMode::OneShot | ConnectorJobMode::Continuous => job.schedule_seconds.is_none(),
    };
    let due_time_valid = job.status == ConnectorJobStatus::Paused || job.next_run_at.is_some();
    let credentials_valid = job
        .credentials
        .as_ref()
        .is_none_or(SealedCredentials::is_well_formed);
    if !schedule_valid
        || !due_time_valid
        || !credentials_valid
        || !safe_connector_refs(&job.config_refs)
    {
        return Err(PostgresStoreError::UnsafeConnectorJob);
    }
    Ok(())
}

fn safe_connector_refs(value: &serde_json::Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.is_empty() || serde_json::to_vec(value).map_or(true, |bytes| bytes.len() > 4_096) {
        return false;
    }
    if object.get("kind").and_then(serde_json::Value::as_str)
        == Some("cloudflare_gateway_logpush_s3_v1")
    {
        return safe_cloudflare_gateway_logpush_s3_refs(object);
    }
    if object.get("kind").and_then(serde_json::Value::as_str)
        == Some("cloudflare_zero_trust_gateway_v1")
    {
        return safe_cloudflare_zero_trust_gateway_refs(object);
    }
    object.iter().all(|(key, value)| {
        safe_code(key)
            && value.as_str().is_some_and(|text| {
                !text.is_empty()
                    && text.len() <= 128
                    && text.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
                    })
            })
    })
}

fn safe_cloudflare_zero_trust_gateway_refs(
    object: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    const KEYS: [&str; 8] = [
        "kind",
        "source_lineage_id",
        "window_seconds",
        "endpoint_url",
        "bucket",
        "prefix",
        "region",
        "object_limit",
    ];
    if object.len() != KEYS.len() || !KEYS.iter().all(|key| object.contains_key(*key)) {
        return false;
    }
    let Some(endpoint_value) = object
        .get("endpoint_url")
        .and_then(serde_json::Value::as_str)
    else {
        return false;
    };
    let Some(bucket) = object.get("bucket").and_then(serde_json::Value::as_str) else {
        return false;
    };
    let Some(prefix) = object.get("prefix").and_then(serde_json::Value::as_str) else {
        return false;
    };
    let storage_disabled = endpoint_value.is_empty() && bucket.is_empty() && prefix.is_empty();
    let storage_enabled = Url::parse(endpoint_value).is_ok_and(|endpoint| {
        endpoint.scheme() == "https"
            && endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.host_str().is_some()
            && matches!(endpoint.path(), "" | "/")
            && endpoint.query().is_none()
            && endpoint.fragment().is_none()
    }) && (3..=255).contains(&bucket.len())
        && bucket.trim() == bucket
        && !bucket.contains('/')
        && !bucket.chars().any(char::is_control)
        && prefix.len() <= 1_024
        && !prefix.chars().any(char::is_control);
    let window_is_safe = object
        .get("window_seconds")
        .and_then(serde_json::Value::as_str)
        .and_then(|window| window.parse::<u32>().ok())
        .is_some_and(|window| (60..=86_400).contains(&window));
    let region_is_safe = object
        .get("region")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|region| {
            !region.is_empty()
                && region.len() <= 63
                && region
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        });
    let object_limit_is_safe = object
        .get("object_limit")
        .and_then(serde_json::Value::as_str)
        .and_then(|limit| limit.parse::<u16>().ok())
        .is_some_and(|limit| (1..=128).contains(&limit));
    (storage_disabled || storage_enabled)
        && window_is_safe
        && region_is_safe
        && object_limit_is_safe
        && object.get("source_lineage_id").is_some_and(|lineage| {
            lineage.as_str() == Some("cloudflare_zero_trust_gateway:graphql_optional_s3")
        })
}

fn safe_cloudflare_gateway_logpush_s3_refs(
    object: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    const KEYS: [&str; 7] = [
        "kind",
        "source_lineage_id",
        "endpoint_url",
        "bucket",
        "prefix",
        "region",
        "object_limit",
    ];
    if object.len() != KEYS.len() || !KEYS.iter().all(|key| object.contains_key(*key)) {
        return false;
    }
    let Some(endpoint) = object
        .get("endpoint_url")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Url::parse(value).ok())
    else {
        return false;
    };
    let endpoint_is_https_origin = endpoint.scheme() == "https"
        && endpoint.username().is_empty()
        && endpoint.password().is_none()
        && endpoint.host_str().is_some()
        && matches!(endpoint.path(), "" | "/")
        && endpoint.query().is_none()
        && endpoint.fragment().is_none();
    let bucket_is_safe = object
        .get("bucket")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|bucket| {
            (3..=255).contains(&bucket.len())
                && bucket.trim() == bucket
                && !bucket.contains('/')
                && !bucket.chars().any(char::is_control)
        });
    let prefix_is_safe = object
        .get("prefix")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|prefix| prefix.len() <= 1_024 && !prefix.chars().any(char::is_control));
    let region_is_safe = object
        .get("region")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|region| {
            !region.is_empty()
                && region.len() <= 63
                && region
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        });
    let object_limit_is_safe = object
        .get("object_limit")
        .and_then(serde_json::Value::as_str)
        .and_then(|limit| limit.parse::<u16>().ok())
        .is_some_and(|limit| (1..=128).contains(&limit));
    endpoint_is_https_origin
        && bucket_is_safe
        && prefix_is_safe
        && region_is_safe
        && object_limit_is_safe
        && object
            .get("source_lineage_id")
            .is_some_and(|lineage| lineage.as_str() == Some("cloudflare_gateway_http_logpush:s3"))
}

fn connector_job_next_state(
    mode: &str,
    schedule_seconds: Option<i64>,
    previous_failures: i64,
    outcome: ConnectorRunStatus,
    finished_at: DateTime<Utc>,
) -> Result<(&'static str, Option<DateTime<Utc>>, i64), PostgresStoreError> {
    if outcome == ConnectorRunStatus::Cancelled || mode == "one_shot" {
        return Ok((
            "paused",
            None,
            i64::from(outcome == ConnectorRunStatus::Failed),
        ));
    }
    if outcome == ConnectorRunStatus::Failed {
        let failures = previous_failures.saturating_add(1).min(1_000_000);
        let exponent = u32::try_from(failures.saturating_sub(1).min(6)).unwrap_or(6);
        let retry_seconds = 60_i64.saturating_mul(2_i64.saturating_pow(exponent));
        return Ok((
            "enabled",
            Some(finished_at + chrono::Duration::seconds(retry_seconds)),
            failures,
        ));
    }
    let delay = match mode {
        "scheduled" => schedule_seconds.filter(|seconds| (60..=86_400).contains(seconds)),
        "continuous" => Some(5),
        _ => None,
    }
    .ok_or(PostgresStoreError::UnsafeConnectorJob)?;
    Ok((
        "enabled",
        Some(finished_at + chrono::Duration::seconds(delay)),
        0,
    ))
}

fn authorization_request_fingerprint(
    request: &AuthorizationTransitionRequest,
) -> Result<String, serde_json::Error> {
    let canonical = serde_json::to_vec(&serde_json::json!({
        "system_id": request.system_id,
        "expected_revision": request.expected_revision,
        "to_status": enum_string(request.to_status, "discovered")?,
        "reason_code": enum_string(request.reason_code, "needs_owner_review")?,
    }))?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

fn authorization_transition_allowed(from: AuthorizationStatus, to: AuthorizationStatus) -> bool {
    match from {
        AuthorizationStatus::Discovered => matches!(
            to,
            AuthorizationStatus::UnderReview
                | AuthorizationStatus::Authorized
                | AuthorizationStatus::Unauthorized
                | AuthorizationStatus::Retired
        ),
        AuthorizationStatus::UnderReview => matches!(
            to,
            AuthorizationStatus::Discovered
                | AuthorizationStatus::Authorized
                | AuthorizationStatus::Unauthorized
                | AuthorizationStatus::Retired
        ),
        AuthorizationStatus::Authorized | AuthorizationStatus::Unauthorized => {
            matches!(
                to,
                AuthorizationStatus::UnderReview
                    | AuthorizationStatus::Authorized
                    | AuthorizationStatus::Unauthorized
                    | AuthorizationStatus::Retired
            ) && from != to
        }
        AuthorizationStatus::Retired => false,
    }
}

const fn authorization_reason_allowed(
    to: AuthorizationStatus,
    reason: AuthorizationReason,
) -> bool {
    match to {
        AuthorizationStatus::UnderReview => matches!(reason, AuthorizationReason::NeedsOwnerReview),
        AuthorizationStatus::Authorized => {
            matches!(reason, AuthorizationReason::SanctionedBusinessUse)
        }
        AuthorizationStatus::Unauthorized => {
            matches!(reason, AuthorizationReason::KnownPersonalUse)
        }
        AuthorizationStatus::Retired => matches!(
            reason,
            AuthorizationReason::DuplicateOrFalsePositive | AuthorizationReason::ServiceRetired
        ),
        AuthorizationStatus::Discovered => false,
    }
}

fn stable_batch_id(receipt: &BatchReceipt) -> Uuid {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!(
            "godel-tally:batch:{}:{}",
            receipt.connector_instance_id, receipt.canonical_digest
        )
        .as_bytes(),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchDisposition {
    Accepted,
    Retry,
    Duplicate,
    InProgress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchAdmission {
    pub batch_id: Uuid,
    pub disposition: BatchDisposition,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PurgeCounts {
    pub observations: u64,
    pub connectors: u64,
    pub connector_runs: u64,
    pub connector_jobs: u64,
    pub connector_backfill_requests: u64,
    pub ingestion_batches: u64,
    pub systems: u64,
    pub findings: u64,
    pub claims: u64,
    pub evidence_links: u64,
    pub authorization_transitions: u64,
    pub mutation_receipts: u64,
    pub registry_overlays: u64,
    pub registry_mutation_receipts: u64,
    pub classification_rule_sets: u64,
    pub scans: u64,
    pub audit_events: u64,
    pub entities: u64,
    pub entity_keys: u64,
    pub relationships: u64,
    pub relationship_evidence: u64,
    pub attribution_checkpoints: u64,
    pub attribution_conflicts: u64,
    pub entity_resolution_events: u64,
    pub entity_resolution_aliases: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeReceipt {
    pub purge_id: Uuid,
    pub preview_digest: String,
    pub requested_counts: PurgeCounts,
    pub deleted_counts: Option<PurgeCounts>,
    pub status: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorRunStatus {
    Completed,
    Duplicate,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorRunRecord {
    pub run_id: Uuid,
    pub connector_instance_id: Uuid,
    pub installation_id: Uuid,
    pub connector_type: String,
    pub status: ConnectorRunStatus,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: chrono::DateTime<chrono::Utc>,
    pub cursor_before: String,
    pub cursor_after: String,
    pub first_source_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_source_at: Option<chrono::DateTime<chrono::Utc>>,
    pub records_read: u64,
    pub accepted: u64,
    pub ignored: u64,
    pub rejected: u64,
    pub deduplicated: u64,
    pub batch_id: Option<Uuid>,
    pub error_code: Option<String>,
    pub redaction_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorJobMode {
    OneShot,
    Scheduled,
    Continuous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorJobStatus {
    Enabled,
    Paused,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConnectorJobSpec {
    pub job_id: Uuid,
    pub connector_instance_id: Uuid,
    pub mode: ConnectorJobMode,
    pub status: ConnectorJobStatus,
    pub schedule_seconds: Option<u32>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub config_refs: serde_json::Value,
    /// Sealed connector credentials. `None` keeps whatever the row already holds, so a
    /// pause or interval change does not have to re-send the operator's secrets.
    pub credentials: Option<SealedCredentials>,
    pub updated_at: DateTime<Utc>,
}

/// Connector credentials sealed with the installation-local `TALLY_SECRET_KEY`.
///
/// The store never sees plaintext: the caller encrypts, and only the collector decrypts
/// after it holds a lease. Serialized as hex because the lease projection travels as JSON.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedCredentials {
    #[serde(with = "hex_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for SealedCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SealedCredentials([REDACTED])")
    }
}

impl SealedCredentials {
    /// Rejects a sealed pair whose shape cannot have come from the cipher: the nonce is
    /// exactly 12 bytes, and the ciphertext carries at least a 16-byte Poly1305 tag.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.nonce.len() == 12 && (17..=65_536).contains(&self.ciphertext.len())
    }
}

mod hex_bytes {
    use serde::{Deserialize as _, Deserializer, Serializer, de::Error as _};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        hex::decode(&text).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeasedConnectorJob {
    pub job_id: Uuid,
    pub connector_instance_id: Uuid,
    pub installation_id: Uuid,
    pub connector_type: String,
    pub mode: ConnectorJobMode,
    pub schedule_seconds: Option<i64>,
    pub next_run_at: DateTime<Utc>,
    pub lease_owner: Uuid,
    pub lease_until: DateTime<Utc>,
    pub config_refs: serde_json::Value,
    #[serde(default)]
    pub credentials: Option<SealedCredentials>,
    pub attempt_count: i64,
    pub consecutive_failures: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorJobCompletion {
    pub job_id: Uuid,
    pub lease_owner: Uuid,
    pub outcome: ConnectorRunStatus,
    pub error_code: Option<String>,
    pub finished_at: DateTime<Utc>,
    /// A bounded source window was committed but the source cursor still trails the settled end.
    pub catch_up: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorJobView {
    pub job_id: Uuid,
    pub connector_instance_id: Uuid,
    pub mode: ConnectorJobMode,
    pub status: ConnectorJobStatus,
    pub schedule_seconds: Option<i64>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub lease_owner: Option<Uuid>,
    pub lease_until: Option<DateTime<Utc>>,
    pub config_refs: serde_json::Value,
    /// Whether the row holds sealed credentials. The bytes themselves are never projected.
    #[serde(default)]
    pub credentials_stored: bool,
    pub attempt_count: i64,
    pub consecutive_failures: i64,
    pub last_started_at: Option<DateTime<Utc>>,
    pub last_finished_at: Option<DateTime<Utc>>,
    pub last_outcome: Option<ConnectorRunStatus>,
    pub last_error_code: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The encrypted configuration material needed by the API to service a connector edit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorJobEditView {
    pub config_refs: serde_json::Value,
    pub credentials: Option<SealedCredentials>,
}

/// What one on-demand sweep across every registered schedule actually did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorSyncSweep {
    /// Schedules now due; the collector claims them on its next poll.
    pub triggered: Vec<ConnectorJobView>,
    /// Attempts already in flight, left to finish on their own lease.
    pub skipped_leased: u64,
    /// Schedules an operator paused; an on-demand run does not override that.
    pub skipped_paused: u64,
}

/// Receipt for a removed connector. Counts describe rows deleted from `PostgreSQL` only:
/// observations the connector contributed remain in the evidence store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorDeletion {
    pub connector_instance_id: Uuid,
    pub connector_type: String,
    pub display_name: String,
    pub friendly_name: String,
    pub job_id: Option<Uuid>,
    pub schedule_deleted: bool,
    pub runs_deleted: u64,
    pub ingestion_batches_deleted: u64,
    pub deleted_at: DateTime<Utc>,
}

/// The names one registered connector answers to, without its health or descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorLabelView {
    pub connector_instance_id: Uuid,
    pub connector_type: String,
    pub display_name: String,
    /// Empty when the operator never named this instance.
    pub friendly_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorStateView {
    pub connector_instance_id: Uuid,
    pub connector_type: String,
    /// Catalog label for the connector type, rewritten from the descriptor on every registration.
    pub display_name: String,
    /// The operator's own label for this instance. Empty when never set; readers fall back to
    /// [`ConnectorStateView::display_name`].
    pub friendly_name: String,
    pub implementation_version: String,
    pub transport: ConnectorTransport,
    pub health: ConnectorHealth,
    pub cursor_value: String,
    pub last_success_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_poll_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_source_at: Option<chrono::DateTime<chrono::Utc>>,
    pub lag_seconds: Option<i64>,
    pub records_read_total: i64,
    pub accepted_total: i64,
    pub ignored_total: i64,
    pub rejected_total: i64,
    pub deduplicated_total: i64,
    pub last_error_code: Option<String>,
    pub redaction_digest: Option<String>,
    pub descriptor: serde_json::Value,
}

impl ConnectorStateView {
    /// The last fully committed Graph query boundary, including windows containing no events.
    pub fn polled_through(&self) -> Option<DateTime<Utc>> {
        if self.connector_type != "microsoft_defender_edr_api_v1" {
            return None;
        }
        self.cursor_value
            .strip_prefix("microsoft-defender-v1:")
            .and_then(|v| v.parse::<i64>().ok())
            .and_then(DateTime::from_timestamp_millis)
    }

    /// History left to scan, excluding Graph's five-minute settling interval.
    pub fn backlog_seconds(&self, now: DateTime<Utc>) -> Option<i64> {
        self.polled_through()
            .map(|through| ((now - through).num_seconds() - 300).max(0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorHealth {
    NeverRun,
    Healthy,
    Delayed,
    Error,
    Paused,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimEvidenceView {
    pub claim: Claim,
    pub observation_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemEvidenceEdge {
    pub system_id: Uuid,
    pub observation_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingView {
    pub finding_id: Uuid,
    pub system_id: Uuid,
    pub system_name: String,
    pub policy_id: String,
    pub policy_version: String,
    pub title: String,
    pub severity: RiskSeverity,
    pub status: String,
    pub factor_codes: Vec<String>,
    pub factors: Vec<RiskFactor>,
    pub system_revision: i64,
    pub evidence_source_count: i32,
    pub first_evaluated_at: DateTime<Utc>,
    pub last_evaluated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationReason {
    SanctionedBusinessUse,
    KnownPersonalUse,
    NeedsOwnerReview,
    DuplicateOrFalsePositive,
    ServiceRetired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationTransitionRequest {
    pub system_id: Uuid,
    pub expected_revision: i64,
    pub to_status: AuthorizationStatus,
    pub reason_code: AuthorizationReason,
    pub idempotency_key: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationTransitionView {
    pub transition_id: Uuid,
    pub system_id: Uuid,
    pub from_status: AuthorizationStatus,
    pub to_status: AuthorizationStatus,
    pub reason_code: AuthorizationReason,
    pub actor: String,
    pub previous_revision: i64,
    pub new_revision: i64,
    pub idempotency_key: Uuid,
    pub at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationTransitionResult {
    pub replayed: bool,
    pub transition: AuthorizationTransitionView,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEventView {
    pub audit_id: Uuid,
    pub at: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub entity_type: String,
    pub entity_id: String,
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanJobStatus {
    Planned,
    Running,
    CancelRequested,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScanJobCreate {
    pub scan_id: Uuid,
    pub idempotency_key: Uuid,
    pub request_fingerprint: String,
    pub scope_digest: String,
    pub plan: serde_json::Value,
    pub execution_policy: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub planned_probes: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScanJobCompletion {
    pub scan_id: Uuid,
    pub status: ScanJobStatus,
    pub finished_at: DateTime<Utc>,
    pub completed_probes: u64,
    pub open_port_count: u64,
    pub fingerprint_attempt_count: u64,
    pub fingerprint_match_count: u64,
    pub resolved_system_count: u64,
    pub results: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanJobView {
    pub scan_id: Uuid,
    pub idempotency_key: Uuid,
    pub scope_digest: String,
    pub plan: serde_json::Value,
    pub execution_policy: serde_json::Value,
    pub status: ScanJobStatus,
    pub authorized_by: String,
    pub authorization_acknowledged_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub planned_probes: i64,
    pub completed_probes: i64,
    pub open_port_count: i64,
    pub fingerprint_attempt_count: i64,
    pub fingerprint_match_count: i64,
    pub resolved_system_count: i64,
    pub results: serde_json::Value,
    pub error_code: Option<String>,
    pub content_retained: bool,
}

#[derive(Debug, Error)]
pub enum PostgresStoreError {
    #[error("postgres query failed: {0}")]
    Sql(#[from] sqlx::Error),
    #[error("postgres migration failed: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("postgres value serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("attribution contract is invalid: {0}")]
    AttributionContract(#[from] AttributionContractError),
    #[error("secure randomness was unavailable: {0}")]
    Entropy(String),
    #[error("stored installation pseudonymization key has an invalid length")]
    InvalidInstallationKey,
    #[error("ingestion failure code is unsafe")]
    UnsafeFailureCode,
    #[error("ingestion batch is no longer writable")]
    IngestionStateConflict,
    #[error("policy identifier is unsafe")]
    UnsafePolicyIdentifier,
    #[error("AI system was not found")]
    SystemNotFound,
    #[error("authorization revision conflict; current revision is {current_revision}")]
    RevisionConflict { current_revision: i64 },
    #[error("idempotency key was already used for a different request")]
    IdempotencyConflict,
    #[error("authorization status is unchanged")]
    AuthorizationUnchanged,
    #[error("authorization transition is invalid")]
    InvalidAuthorizationTransition,
    #[error("authorization reason is invalid for the target status")]
    InvalidAuthorizationReason,
    #[error("scan job was not found")]
    ScanNotFound,
    #[error("scan job status transition is invalid")]
    InvalidScanStatus,
    #[error("purge preview digest is invalid")]
    InvalidPurgeDigest,
    #[error("purge receipt was not found")]
    PurgeNotFound,
    #[error("connector job contract is unsafe")]
    UnsafeConnectorJob,
    #[error("connector job is actively leased")]
    ConnectorJobLeased,
    #[error("connector job was not found")]
    ConnectorJobNotFound,
    #[error("connector job is paused")]
    ConnectorJobPaused,
    #[error("connector was not found")]
    ConnectorNotFound,
    #[error("connector is still referenced by enforcement state outside Tally")]
    ConnectorDeleteBlocked,
    #[error("connector friendly name is unsafe")]
    ConnectorFriendlyNameInvalid,
    #[error("connector job lease is no longer owned by this worker")]
    ConnectorJobLeaseLost,
    #[error("provider sanction requires a reviewed domain mapping")]
    InvalidRegistrySanction,
    #[error("connector source does not support bounded backfill")]
    ConnectorBackfillUnsupported,
    #[error("connector backfill lookback is outside its source-specific bound")]
    ConnectorBackfillOutOfRange,
    #[error("connector backfill contract is unsafe")]
    UnsafeConnectorBackfill,
    #[error("connector backfill preview changed")]
    ConnectorBackfillPreviewChanged,
    #[error("connector backfill idempotency key was already used for another request")]
    ConnectorBackfillIdempotencyConflict,
    #[error("local registry overlay contract is unsafe")]
    UnsafeRegistryOverlay,
    #[error("local registry overlay identifier already exists")]
    RegistryOverlayExists,
    #[error("classification rule set contract is unsafe")]
    UnsafeClassificationRuleSet,
    #[error("classification preview estate changed")]
    ClassificationPreviewChanged,
    #[error("classification rule set was not found")]
    ClassificationRuleSetNotFound,
    #[error("classification rule set is already inactive")]
    ClassificationRuleSetInactive,
    #[error("classification rule set conflicts with an active opposite decision")]
    ClassificationRuleConflict,
    #[error("entity key is already bound differently or has a newer revision")]
    EntityKeyConflict,
    #[error("a relationship requires at least one immutable evidence link")]
    RelationshipEvidenceRequired,
    #[error("relationship evidence points to a different relationship")]
    RelationshipEvidenceMismatch,
    #[error("relationship evidence conflicts with an existing immutable link")]
    RelationshipEvidenceConflict,
    #[error("relationship revision is stale or conflicts with the stored revision")]
    RelationshipRevisionConflict,
    #[error("relationship was not found after persistence")]
    RelationshipNotFound,
    #[error("claim evidence conflicts with an existing immutable link")]
    ClaimEvidenceConflict,
    #[error("claim conflicts with an existing immutable projection")]
    ClaimConflict,
    #[error("cloud usage projection exceeded its bounded graph row cap")]
    CloudUsageProjectionTooLarge,
    #[error("cloud usage projection graph rows are incomplete or inconsistent")]
    CloudUsageProjectionInvalid,
    #[error("attribution conflict contract is invalid")]
    InvalidAttributionConflict,
    #[error("attribution conflict revision is stale or conflicts with stored identity")]
    AttributionConflictRevisionConflict,
    #[error("attribution checkpoint would conflict with or roll back durable progress")]
    AttributionCheckpointConflict,
    #[error("entity resolution target was not found in this installation")]
    EntityResolutionEntityNotFound,
    #[error(
        "entity resolution revisions changed; source is {source_revision} and target is {target_revision}"
    )]
    EntityResolutionRevisionConflict {
        source_revision: i64,
        target_revision: i64,
    },
    #[error("entity resolution topology or operation is invalid")]
    InvalidEntityResolution,
    #[error("entity resolution preview changed")]
    EntityResolutionPreviewChanged,
    #[error("entity resolution idempotency key was already used for a different request")]
    EntityResolutionIdempotencyConflict,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires TALLY_DISPOSABLE_POSTGRES_URL with no findings"]
    async fn live_client_attribution_persists_replays_and_survives_upgrade() {
        let url = std::env::var("TALLY_DISPOSABLE_POSTGRES_URL").expect("disposable database");
        let store = PostgresStore::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        assert_eq!(
            store.list_governance_findings(100).await.unwrap(),
            [] as [GovernanceFindingView; 0]
        );
        let installation_id = store
            .get_or_create_installation_identity()
            .await
            .unwrap()
            .installation_id;
        let connector_instance_id = Uuid::now_v7();
        store
            .register_connector(
                installation_id,
                connector_instance_id,
                &tally_connectors::litellm_model_groups_api_descriptor(),
            )
            .await
            .unwrap();
        let mut usage = ObservedUsage {
            activity: None,
            observation_id: Uuid::now_v7(),
            installation_id,
            provider_key: "openai".to_owned(),
            provider_name: "OpenAI".to_owned(),
            provider_category: "direct_provider".to_owned(),
            provider_country_code: Some("US".to_owned()),
            provider_catalogued: true,
            model_reference: Some("gpt-4.1".to_owned()),
            observed_at: Utc::now(),
            connector_instance_id,
            evidence_kind: FindingEvidenceKind::AiUsage,
            counts_as_usage: true,
            endpoints: vec![EndpointIdentity {
                kind: "hostname".to_owned(),
                value: "laptop-42.local".to_owned(),
                role: "source".to_owned(),
                port: None,
            }],
            destinations: vec![DestinationIdentity {
                kind: "hostname".to_owned(),
                value: "api.openai.com".to_owned(),
                port: Some(443),
            }],
            workloads: Vec::new(),
            user_identity: Some(UserIdentity {
                kind: "email".to_owned(),
                value: "person@example.test".to_owned(),
                email: Some("person@example.test".to_owned()),
            }),
            request_client: None,
        };
        let id = store.record_usage(&usage).await.unwrap();
        usage.request_client = Some(RequestClientObservation {
            name: Some(RequestClientKind::LangChain),
            agent_id: Some("agent-42".to_owned()),
        });
        assert_eq!(store.record_usage(&usage).await.unwrap(), id);
        store.record_usage(&usage).await.unwrap();
        store.migrate().await.unwrap();
        let findings = store.list_governance_findings(100).await.unwrap();
        let finding = findings
            .iter()
            .find(|finding| finding.finding_id == id)
            .unwrap();
        assert_eq!(finding.usage_count, 1);
        assert_eq!(finding.clients.len(), 1);
        assert_eq!(finding.clients[0].name, Some(RequestClientKind::LangChain));
        assert_eq!(finding.clients[0].agent_id.as_deref(), Some("agent-42"));
        assert_eq!(
            finding.clients[0].connector_instance_id,
            connector_instance_id
        );
        assert_eq!(
            finding.users[0].email.as_deref(),
            Some("person@example.test")
        );
        assert_eq!(finding.endpoints[0].value, "laptop-42.local");
        assert_eq!(finding.destinations[0].port, Some(443));
        sqlx::query("DELETE FROM connector_states WHERE connector_instance_id = $1")
            .bind(connector_instance_id)
            .execute(store.pool())
            .await
            .unwrap();
        let finding = store
            .list_governance_findings(100)
            .await
            .unwrap()
            .into_iter()
            .find(|finding| finding.finding_id == id)
            .unwrap();
        assert_eq!(finding.clients, [] as [FindingClientView; 0]);
        assert_eq!(finding.usage_count, 1);
    }

    #[tokio::test]
    #[ignore = "requires TALLY_DISPOSABLE_POSTGRES_URL with no findings"]
    async fn live_overview_counts_match_governance_tabs_for_runtime_providers() {
        let url =
            std::env::var("TALLY_DISPOSABLE_POSTGRES_URL").expect("TALLY_DISPOSABLE_POSTGRES_URL");
        let store = PostgresStore::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");
        assert_eq!(
            store.list_governance_findings(100).await.unwrap(),
            [] as [GovernanceFindingView; 0]
        );
        let installation_id = Uuid::now_v7();
        sqlx::query("INSERT INTO installations (installation_id, name) VALUES ($1, $2)")
            .bind(installation_id)
            .bind("overview regression fixture")
            .execute(store.pool())
            .await
            .unwrap();

        for provider_sanction in [None, Some(false), Some(true)] {
            let provider_id = Uuid::now_v7();
            sqlx::query("INSERT INTO ai_providers (provider_id, key, name, category, catalog, sanctioned) VALUES ($1, $2, 'Runtime without domain mappings', 'local_runtime', FALSE, $3)")
                .bind(provider_id)
                .bind(provider_id.to_string())
                .bind(provider_sanction)
                .execute(store.pool())
                .await
                .unwrap();
            for model_sanction in [None, Some(None), Some(Some(false)), Some(Some(true))] {
                let model_id = if let Some(sanction) = model_sanction {
                    let id = Uuid::now_v7();
                    sqlx::query("INSERT INTO ai_models (model_id, key, name, family, catalog, sanctioned) VALUES ($1, $2, 'Overview model', 'test', FALSE, $3)")
                        .bind(id)
                        .bind(id.to_string())
                        .bind(sanction)
                        .execute(store.pool())
                        .await
                        .unwrap();
                    Some(id)
                } else {
                    None
                };
                sqlx::query("INSERT INTO findings (installation_id, provider_id, model_id, first_used_at, last_used_at, usage_count) VALUES ($1, $2, $3, now(), now(), 1)")
                    .bind(installation_id)
                    .bind(provider_id)
                    .bind(model_id)
                    .execute(store.pool())
                    .await
                    .unwrap();
            }
        }

        let findings = store.list_governance_findings(100).await.unwrap();
        let overview = store.tally_overview().await.unwrap();
        let count = |status: GovernanceFindingStatus| {
            findings
                .iter()
                .filter(|finding| finding.status == status)
                .count() as u64
        };
        assert_eq!(
            overview.unsanctioned,
            count(GovernanceFindingStatus::Unsanctioned)
        );
        assert_eq!(
            overview.authorization_queue,
            count(GovernanceFindingStatus::AuthorizationQueue)
        );
        assert_eq!(
            overview.sanctioned,
            count(GovernanceFindingStatus::Sanctioned)
        );
        assert_eq!(overview.authorization_queue, 4);
        assert_eq!(findings.len(), 12);
    }

    #[test]
    fn published_postgres_migration_head_matches_embedded_bundle() {
        assert_eq!(
            MIGRATOR
                .migrations
                .last()
                .expect("embedded PostgreSQL migration")
                .version,
            POSTGRES_MIGRATION_HEAD
        );
    }

    #[tokio::test]
    #[ignore = "requires an empty disposable TALLY_DISPOSABLE_POSTGRES_URL"]
    async fn live_fresh_baseline_preserves_decisions_on_restart_and_resets_defaults() {
        let url = std::env::var("TALLY_DISPOSABLE_POSTGRES_URL").expect("disposable PostgreSQL");
        let store = PostgresStore::connect(&url).await.expect("connect");
        store.migrate().await.expect("fresh migrations");
        assert_eq!(
            store.migration_head().await.unwrap(),
            POSTGRES_MIGRATION_HEAD
        );
        let invalid_defaults: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM ai_providers WHERE sanctioned IS DISTINCT FROM tally_default_provider_sanction(key)")
            .fetch_one(&store.pool).await.unwrap();
        assert_eq!(invalid_defaults, 0);
        sqlx::query("UPDATE ai_providers SET sanctioned=FALSE WHERE key='openai'")
            .execute(&store.pool)
            .await
            .unwrap();
        store.migrate().await.expect("restart");
        let sanctioned: bool =
            sqlx::query_scalar("SELECT sanctioned FROM ai_providers WHERE key='openai'")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert!(!sanctioned, "restarting must preserve operator decisions");
        store
            .delete_data(&["registry_sanctions".into()], None)
            .await
            .expect("reset");
        let changed = store.data_inventory().await.unwrap();
        assert_eq!(changed.registry_sanctions, 0);
        let sanctioned: bool =
            sqlx::query_scalar("SELECT sanctioned FROM ai_providers WHERE key='openai'")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert!(sanctioned);
    }

    #[test]
    fn scoped_model_reference_keeps_scope_and_nonempty_leaf() {
        let (name, aliases, version) = normalized_model_identity("@cf/deepseek/deepseek-v4-flash")
            .expect("scoped model identity");
        assert_eq!(name, "deepseek-v4-flash");
        assert_eq!(version, None);
        assert_eq!(
            aliases,
            vec![
                "@cf/deepseek/deepseek-v4-flash".to_owned(),
                "deepseek-v4-flash".to_owned()
            ]
        );
    }

    #[test]
    fn model_reference_removes_only_a_valid_trailing_version() {
        let (name, aliases, version) =
            normalized_model_identity("@scope/team/model@V2").expect("versioned model identity");
        assert_eq!(name, "model");
        assert_eq!(version.as_deref(), Some("v2"));
        assert!(aliases.contains(&"@scope/team/model".to_owned()));
        assert!(aliases.contains(&"@scope/team/model@v2".to_owned()));

        let (name, aliases, version) =
            normalized_model_identity("llama3.2:latest").expect("colon-versioned identity");
        assert_eq!(name, "llama3.2");
        assert_eq!(version.as_deref(), Some("latest"));
        assert!(aliases.contains(&"llama3.2:latest".to_owned()));
        assert!(aliases.contains(&"llama3.2".to_owned()));

        assert!(normalized_model_identity("   ").is_none());
        assert!(normalized_model_identity("/").is_none());
    }
    use tally_core::{
        BasisPoints, EntityKind, EntityRef, RelationshipPredicate, RelationshipStatus, RuleRef,
    };

    #[test]
    fn retired_authorization_is_terminal() {
        assert!(!authorization_transition_allowed(
            AuthorizationStatus::Retired,
            AuthorizationStatus::UnderReview
        ));
    }

    #[test]
    fn authorization_fingerprint_excludes_idempotency_key() {
        let base = AuthorizationTransitionRequest {
            system_id: Uuid::nil(),
            expected_revision: 3,
            to_status: AuthorizationStatus::Authorized,
            reason_code: AuthorizationReason::SanctionedBusinessUse,
            idempotency_key: Uuid::now_v7(),
        };
        let mut replay = base.clone();
        replay.idempotency_key = Uuid::now_v7();
        assert_eq!(
            authorization_request_fingerprint(&base).expect("fingerprint"),
            authorization_request_fingerprint(&replay).expect("fingerprint")
        );
    }

    #[test]
    fn authorization_reasons_are_bound_to_decisions() {
        assert!(authorization_reason_allowed(
            AuthorizationStatus::Authorized,
            AuthorizationReason::SanctionedBusinessUse
        ));
        assert!(!authorization_reason_allowed(
            AuthorizationStatus::Authorized,
            AuthorizationReason::NeedsOwnerReview
        ));
    }

    #[test]
    fn installation_identity_debug_never_exposes_the_key() {
        let identity = InstallationIdentity {
            installation_id: Uuid::nil(),
            pseudonymization_key: [7; 32],
        };
        let debug = format!("{identity:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("070707"));
    }

    #[test]
    fn purge_counts_default_is_empty_and_serializable() {
        let counts = PurgeCounts::default();
        assert_eq!(counts.observations, 0);
        assert_eq!(
            serde_json::to_value(counts).expect("serialize")["connectors"],
            0
        );
    }

    #[test]
    fn continuity_set_digest_is_order_independent_and_row_bound() {
        let first = continuity_set_digest(vec!["beta".to_owned(), "alpha".to_owned()]);
        let replay = continuity_set_digest(vec!["alpha".to_owned(), "beta".to_owned()]);
        assert_eq!(first, replay);
        assert_eq!(first.count, 2);
        assert!(valid_lower_sha256(&first.sha256));
        assert_ne!(
            first,
            continuity_set_digest(vec!["alpha".to_owned(), "betamax".to_owned()])
        );
    }

    #[test]
    fn local_registry_overlay_storage_is_bounded_and_digest_only() {
        let overlay = serde_json::json!({"schema_version":"1","id":"local.service.lab"});
        let overlay_sha256 = hex::encode(Sha256::digest(
            serde_json::to_vec(&overlay).expect("serialize"),
        ));
        let request = RegistryOverlayCreate {
            overlay_id: "local.service.lab".to_owned(),
            installation_id: Uuid::nil(),
            overlay,
            overlay_sha256,
            request_sha256: "b".repeat(64),
            entry_count: 1,
            matcher_count: 1,
            idempotency_key: Uuid::nil(),
            created_at: Utc::now(),
        };
        assert!(validate_registry_overlay_create(&request).is_ok());
        let mut unsafe_request = request;
        unsafe_request.overlay_sha256 = "A".repeat(64);
        assert!(matches!(
            validate_registry_overlay_create(&unsafe_request),
            Err(PostgresStoreError::UnsafeRegistryOverlay)
        ));
    }

    #[test]
    fn stored_classification_overlap_is_dns_label_safe() {
        let suffix = StoredClassificationHostRule {
            kind: "suffix".to_owned(),
            host: "example.com".to_owned(),
        };
        let nested = StoredClassificationHostRule {
            kind: "exact".to_owned(),
            host: "api.example.com".to_owned(),
        };
        let neighbor = StoredClassificationHostRule {
            kind: "exact".to_owned(),
            host: "notexample.com".to_owned(),
        };
        assert!(stored_classification_rules_overlap(&suffix, &nested));
        assert!(!stored_classification_rules_overlap(&suffix, &neighbor));
    }

    #[test]
    fn classification_conflict_receipt_is_stable_and_order_bound() {
        let system_id = Uuid::now_v7();
        let first = Uuid::now_v7();
        let second = Uuid::now_v7();
        let receipt = classification_conflict_audit_id(system_id, &[first, second]);
        assert_eq!(
            receipt,
            classification_conflict_audit_id(system_id, &[first, second])
        );
        assert_ne!(
            receipt,
            classification_conflict_audit_id(system_id, &[second, first])
        );
        assert!(valid_lower_sha256(&"ab".repeat(32)));
        assert!(!valid_lower_sha256(&"AB".repeat(32)));
    }

    #[test]
    fn scheduled_connector_jobs_require_safe_machine_references() {
        let mut job = ConnectorJobSpec {
            job_id: Uuid::nil(),
            connector_instance_id: Uuid::nil(),
            mode: ConnectorJobMode::Scheduled,
            status: ConnectorJobStatus::Enabled,
            schedule_seconds: Some(300),
            next_run_at: Some(Utc::now()),
            config_refs: serde_json::json!({
                "kind": "file_env_v1",
                "adapter": "nextdns",
                "source_lineage_id": "scheduled_file_env"
            }),
            credentials: Some(SealedCredentials {
                nonce: vec![0; 12],
                ciphertext: vec![0; 64],
            }),
            updated_at: Utc::now(),
        };
        validate_connector_job(&job).expect("safe schedule");

        job.config_refs = serde_json::json!({
            "kind": "kubernetes_api_v1",
            "source_lineage_id": "kubernetes_api:native"
        });
        validate_connector_job(&job).expect("safe Kubernetes reference-only schedule");

        // A path is source data, not a machine reference: config_refs must refuse it even
        // though the same value is perfectly legal inside the sealed credential bundle.
        job.config_refs["source_path"] = serde_json::json!("/Users/example/private.csv");
        assert!(matches!(
            validate_connector_job(&job),
            Err(PostgresStoreError::UnsafeConnectorJob)
        ));

        job.config_refs = serde_json::json!({
            "kind": "kubernetes_api_v1",
            "source_lineage_id": "kubernetes_api:native"
        });
        // A nonce that is not 12 bytes cannot have come from the cipher.
        job.credentials = Some(SealedCredentials {
            nonce: vec![0; 8],
            ciphertext: vec![0; 64],
        });
        assert!(matches!(
            validate_connector_job(&job),
            Err(PostgresStoreError::UnsafeConnectorJob)
        ));

        // A schedule-only change carries no credentials and keeps whatever the row holds.
        job.credentials = None;
        validate_connector_job(&job).expect("schedule change without credentials");
    }

    #[test]
    fn cloudflare_gateway_logpush_job_accepts_only_bounded_s3_references() {
        let mut job = ConnectorJobSpec {
            job_id: Uuid::nil(),
            connector_instance_id: Uuid::nil(),
            mode: ConnectorJobMode::Scheduled,
            status: ConnectorJobStatus::Enabled,
            schedule_seconds: Some(300),
            next_run_at: Some(Utc::now()),
            config_refs: serde_json::json!({
                "kind": "cloudflare_gateway_logpush_s3_v1",
                "source_lineage_id": "cloudflare_gateway_http_logpush:s3",
                "endpoint_url": "https://0123456789abcdef.r2.cloudflarestorage.com/",
                "bucket": "gateway-http-logs",
                "prefix": "tally/gateway-http/",
                "region": "auto",
                "object_limit": "128"
            }),
            credentials: Some(SealedCredentials {
                nonce: vec![0; 12],
                ciphertext: vec![0; 64],
            }),
            updated_at: Utc::now(),
        };
        validate_connector_job(&job).expect("bounded S3 references");

        job.config_refs["endpoint_url"] = serde_json::json!("https://object.example/private/path");
        assert!(matches!(
            validate_connector_job(&job),
            Err(PostgresStoreError::UnsafeConnectorJob)
        ));

        job.config_refs["endpoint_url"] =
            serde_json::json!("https://0123456789abcdef.r2.cloudflarestorage.com/");
        job.config_refs["unexpected"] = serde_json::json!("value");
        assert!(matches!(
            validate_connector_job(&job),
            Err(PostgresStoreError::UnsafeConnectorJob)
        ));
    }

    #[test]
    fn cloudflare_zero_trust_gateway_accepts_api_only_or_complete_optional_s3() {
        let mut job = ConnectorJobSpec {
            job_id: Uuid::nil(),
            connector_instance_id: Uuid::nil(),
            mode: ConnectorJobMode::Scheduled,
            status: ConnectorJobStatus::Enabled,
            schedule_seconds: Some(300),
            next_run_at: Some(Utc::now()),
            config_refs: serde_json::json!({
                "kind": "cloudflare_zero_trust_gateway_v1",
                "source_lineage_id": "cloudflare_zero_trust_gateway:graphql_optional_s3",
                "window_seconds": "3600",
                "endpoint_url": "",
                "bucket": "",
                "prefix": "",
                "region": "auto",
                "object_limit": "32"
            }),
            credentials: Some(SealedCredentials {
                nonce: vec![0; 12],
                ciphertext: vec![0; 64],
            }),
            updated_at: Utc::now(),
        };
        validate_connector_job(&job).expect("API-only Gateway references");

        job.config_refs["endpoint_url"] =
            serde_json::json!("https://0123456789abcdef.r2.cloudflarestorage.com/");
        job.config_refs["bucket"] = serde_json::json!("gateway-http-logs");
        job.config_refs["prefix"] = serde_json::json!("tally/gateway-http/");
        validate_connector_job(&job).expect("Gateway references with optional S3");

        job.config_refs["bucket"] = serde_json::json!("");
        assert!(matches!(
            validate_connector_job(&job),
            Err(PostgresStoreError::UnsafeConnectorJob)
        ));
    }

    #[test]
    fn connector_backfill_is_source_bounded_and_preview_state_bound() {
        let at: DateTime<Utc> = "2026-08-14T10:00:00Z".parse().expect("timestamp");
        let installation_id = Uuid::now_v7();
        let mut state = ConnectorBackfillState {
            installation_id,
            job: ConnectorJobView {
                job_id: Uuid::now_v7(),
                connector_instance_id: Uuid::now_v7(),
                mode: ConnectorJobMode::Scheduled,
                status: ConnectorJobStatus::Enabled,
                schedule_seconds: Some(300),
                next_run_at: Some(at),
                lease_owner: None,
                lease_until: None,
                config_refs: serde_json::json!({
                    "kind": "nextdns_api_v1",
                    "profile_id": "pseudonymized-profile"
                }),
                credentials_stored: true,
                attempt_count: 1,
                consecutive_failures: 0,
                last_started_at: Some(at),
                last_finished_at: Some(at),
                last_outcome: Some(ConnectorRunStatus::Completed),
                last_error_code: None,
                created_at: at,
                updated_at: at,
            },
            cursor_present: true,
        };

        let first = connector_backfill_preview(&state, 3_600, at).expect("NextDNS preview");
        let replay = connector_backfill_preview(&state, 3_600, at).expect("stable preview");
        assert_eq!(first.preview_digest, replay.preview_digest);
        assert_eq!(first.minimum_lookback_seconds, 60);
        assert_eq!(first.maximum_lookback_seconds, 86_400);
        assert!(matches!(
            connector_backfill_preview(&state, 59, at),
            Err(PostgresStoreError::ConnectorBackfillOutOfRange)
        ));

        state.cursor_present = false;
        let cursor_changed = connector_backfill_preview(&state, 3_600, at).expect("cursor preview");
        assert_ne!(first.preview_digest, cursor_changed.preview_digest);

        state.job.config_refs = serde_json::json!({
            "kind": "cloud_network_api_v1",
            "adapter": "aws_cloud_flow_api"
        });
        let flow = connector_backfill_preview(&state, 900, at).expect("flow preview");
        assert_eq!(flow.minimum_lookback_seconds, 300);
        assert_eq!(flow.maximum_lookback_seconds, 3_600);

        state.job.config_refs["adapter"] = serde_json::json!("aws_network_mapping_api");
        assert!(matches!(
            connector_backfill_preview(&state, 900, at),
            Err(PostgresStoreError::ConnectorBackfillUnsupported)
        ));

        state.job.config_refs = serde_json::json!({"kind":"microsoft_defender_graph_hunting_v1"});
        let defender = connector_backfill_preview(&state, 604_800, at).unwrap();
        assert_eq!(
            defender.source_kind,
            ConnectorBackfillSourceKind::MicrosoftDefenderApi
        );
        assert_eq!(defender.maximum_lookback_seconds, 604_800);
        assert!(matches!(
            connector_backfill_preview(&state, 604_801, at),
            Err(PostgresStoreError::ConnectorBackfillOutOfRange)
        ));
    }

    #[test]
    fn cloud_usage_rows_project_only_one_exact_mapping_and_surface_ambiguity() {
        let installation_id = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"usage-installation");
        let flow_relationship_id = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"flow-edge");
        let flow_observation_id = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"flow-observation");
        let at: DateTime<Utc> = "2026-08-13T10:00:00Z".parse().unwrap();
        let until = at + chrono::Duration::minutes(5);
        let row = |mapping_suffix: &[u8], mapping_count: i64| CloudUsagePathRow {
            installation_id,
            source_asset_id: Uuid::new_v5(&Uuid::NAMESPACE_URL, b"source-asset"),
            destination_asset_id: Uuid::new_v5(&Uuid::NAMESPACE_URL, b"destination-asset"),
            flow_relationship_id,
            flow_observation_id,
            flow_lineage_id: "flow:fixture".to_owned(),
            flow_valid_from: at,
            flow_valid_until: until,
            mapping_relationship_id: Uuid::new_v5(&Uuid::NAMESPACE_URL, mapping_suffix),
            mapped_resource_id: Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                &[mapping_suffix, b"-resource"].concat(),
            ),
            mapping_observation_id: Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                &[mapping_suffix, b"-observation"].concat(),
            ),
            mapping_lineage_id: "mapping:fixture".to_owned(),
            mapping_valid_from: at,
            mapping_valid_until: Some(until),
            mapping_count,
            serves_relationship_id: Some(Uuid::new_v5(&Uuid::NAMESPACE_URL, b"serves-edge")),
            system_id: Some(Uuid::new_v5(&Uuid::NAMESPACE_URL, b"system")),
            inventory_observation_id: Some(Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                b"inventory-observation",
            )),
            inventory_lineage_id: Some("inventory:fixture".to_owned()),
            inventory_valid_from: Some(at),
            inventory_valid_until: None,
        };
        let exact = project_cloud_usage_rows(vec![row(b"mapping-a", 1)]).unwrap();
        assert_eq!(exact.projections.len(), 1);
        assert_eq!(
            exact.conflicts,
            [] as [tally_resolve::CloudUsageConflictInput; 0]
        );

        let ambiguous =
            project_cloud_usage_rows(vec![row(b"mapping-a", 2), row(b"mapping-b", 2)]).unwrap();
        assert_eq!(
            ambiguous.projections,
            [] as [tally_resolve::CloudUsageProjectionInput; 0]
        );
        assert_eq!(ambiguous.conflicts.len(), 1);
        assert_eq!(ambiguous.conflicts[0].candidate_count, 2);
    }

    // The retired entity graph is no longer in the standalone schema. Exercise the
    // durable finding attribution contract used by current connectors instead.
    #[tokio::test]
    #[ignore = "requires TALLY_DISPOSABLE_POSTGRES_URL with no findings"]
    #[allow(clippy::too_many_lines)]
    async fn live_attribution_replays_preserve_connector_context() {
        let url = std::env::var("TALLY_DISPOSABLE_POSTGRES_URL").expect("disposable database");
        let store = PostgresStore::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");
        assert_eq!(
            store.list_governance_findings(100).await.unwrap(),
            [] as [GovernanceFindingView; 0]
        );
        let installation_id = store
            .get_or_create_installation_identity()
            .await
            .unwrap()
            .installation_id;
        let connectors = [Uuid::now_v7(), Uuid::now_v7()];
        for connector in connectors {
            store
                .register_connector(
                    installation_id,
                    connector,
                    &tally_connectors::litellm_model_groups_api_descriptor(),
                )
                .await
                .unwrap();
        }
        let at = DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap();
        let first = ObservedUsage {
            activity: None,
            observation_id: Uuid::now_v7(),
            installation_id,
            provider_key: "openai".into(),
            provider_name: "OpenAI".into(),
            provider_category: "direct_provider".into(),
            provider_country_code: Some("US".into()),
            provider_catalogued: true,
            model_reference: Some("gpt-4.1".into()),
            observed_at: at,
            connector_instance_id: connectors[0],
            evidence_kind: FindingEvidenceKind::AiUsage,
            counts_as_usage: true,
            endpoints: vec![EndpointIdentity {
                kind: "hostname".into(),
                value: "worker.example.test".into(),
                role: "source".into(),
                port: None,
            }],
            destinations: vec![DestinationIdentity {
                kind: "hostname".into(),
                value: "api.openai.com".into(),
                port: Some(443),
            }],
            workloads: vec![WorkloadIdentity {
                namespace_name: "qa".into(),
                workload_name: "agent".into(),
                workload_kind: "deployment".into(),
                runtime_image: None,
            }],
            user_identity: Some(UserIdentity {
                kind: "email".into(),
                value: "person@example.test".into(),
                email: Some("person@example.test".into()),
            }),
            request_client: Some(RequestClientObservation {
                name: Some(RequestClientKind::LangChain),
                agent_id: Some("shared-agent".into()),
            }),
        };
        let second = ObservedUsage {
            observation_id: Uuid::now_v7(),
            connector_instance_id: connectors[1],
            observed_at: at + chrono::Duration::minutes(5),
            ..first.clone()
        };
        let finding_id = store.record_usage(&first).await.unwrap();
        assert_eq!(store.record_usage(&second).await.unwrap(), finding_id);
        // Replays from either connector must neither count again nor duplicate context.
        store
            .record_usages(&[second.clone(), first.clone(), second.clone()])
            .await
            .unwrap();
        store.migrate().await.unwrap();
        let findings = store.list_governance_findings(100).await.unwrap();
        let finding = findings
            .iter()
            .find(|f| f.finding_id == finding_id)
            .unwrap();
        assert_eq!(finding.usage_count, 2);
        assert_eq!(
            finding.clients.len(),
            2,
            "client identity remains scoped to its connector"
        );
        for connector in connectors {
            assert!(
                finding
                    .clients
                    .iter()
                    .any(|client| client.connector_instance_id == connector
                        && client.agent_id.as_deref() == Some("shared-agent"))
            );
        }
        assert_eq!(finding.endpoints.len(), 1);
        assert_eq!(finding.destinations.len(), 1);
        assert_eq!(finding.users.len(), 1);
        let window: (DateTime<Utc>, DateTime<Utc>, i64) = sqlx::query_as(
            "SELECT min(first_seen), max(last_seen), count(*) FROM finding_workloads WHERE finding_id=$1"
        ).bind(finding_id).fetch_one(store.pool()).await.unwrap();
        assert_eq!(window, (at, second.observed_at, 1));
        // A later bad source must roll back the entire batch, including its earlier row.
        let fresh = ObservedUsage {
            observation_id: Uuid::now_v7(),
            ..first.clone()
        };
        let invalid = ObservedUsage {
            observation_id: Uuid::now_v7(),
            connector_instance_id: Uuid::now_v7(),
            ..second
        };
        assert!(store.record_usages(&[fresh, invalid]).await.is_err());
        let count: i64 = sqlx::query_scalar("SELECT usage_count FROM findings WHERE finding_id=$1")
            .bind(finding_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count, 2);
        sqlx::query("DELETE FROM connector_states WHERE connector_instance_id=$1")
            .bind(connectors[0])
            .execute(store.pool())
            .await
            .unwrap();
        let findings = store.list_governance_findings(100).await.unwrap();
        let finding = findings
            .iter()
            .find(|f| f.finding_id == finding_id)
            .unwrap();
        assert_eq!(finding.usage_count, 2);
        assert_eq!(finding.clients.len(), 1);
        assert_eq!(finding.clients[0].connector_instance_id, connectors[1]);
    }

    #[test]
    fn connector_retry_backoff_is_bounded_and_success_resets_failures() {
        let finished = Utc::now();
        let (_, first_retry, failures) = connector_job_next_state(
            "scheduled",
            Some(300),
            0,
            ConnectorRunStatus::Failed,
            finished,
        )
        .expect("first retry");
        assert_eq!(first_retry, Some(finished + chrono::Duration::seconds(60)));
        assert_eq!(failures, 1);

        let (_, capped_retry, _) = connector_job_next_state(
            "scheduled",
            Some(300),
            50,
            ConnectorRunStatus::Failed,
            finished,
        )
        .expect("bounded retry");
        assert_eq!(
            capped_retry,
            Some(finished + chrono::Duration::seconds(3_840))
        );

        let (_, next, failures) = connector_job_next_state(
            "scheduled",
            Some(300),
            5,
            ConnectorRunStatus::Completed,
            finished,
        )
        .expect("successful cadence");
        assert_eq!(next, Some(finished + chrono::Duration::seconds(300)));
        assert_eq!(failures, 0);
    }

    #[test]
    fn entity_resolution_preview_is_deterministic_and_rejects_alias_chains() {
        let at = Utc::now();
        let source = Entity {
            entity_id: Uuid::now_v7(),
            kind: EntityKind::AiSystem,
            display_name: "Source".to_owned(),
            created_at: at,
            revision: 4,
        };
        let target = Entity {
            entity_id: Uuid::now_v7(),
            kind: EntityKind::AiSystem,
            display_name: "Target".to_owned(),
            created_at: at,
            revision: 7,
        };
        let state = EntityResolutionState {
            source: Some(source.clone()),
            target: Some(target.clone()),
            source_is_alias: false,
            source_has_aliases: false,
            target_is_alias: false,
            active_merge_event_id: None,
            impact: EntityResolutionImpact {
                key_count: 2,
                claim_count: 5,
                relationship_count: 3,
                finding_count: 1,
            },
        };
        let first = build_entity_resolution_preview(
            EntityResolutionOperation::Merge,
            state,
            source.revision,
            target.revision,
            None,
        )
        .expect("preview");
        let second = build_entity_resolution_preview(
            EntityResolutionOperation::Merge,
            EntityResolutionState {
                source: Some(source.clone()),
                target: Some(target.clone()),
                source_is_alias: false,
                source_has_aliases: false,
                target_is_alias: false,
                active_merge_event_id: None,
                impact: first.impact,
            },
            source.revision,
            target.revision,
            None,
        )
        .expect("repeated preview");
        assert_eq!(first.preview_digest, second.preview_digest);
        assert!(valid_lower_sha256(&first.preview_digest));

        let chained = build_entity_resolution_preview(
            EntityResolutionOperation::Merge,
            EntityResolutionState {
                source: Some(source),
                target: Some(target),
                source_is_alias: false,
                source_has_aliases: true,
                target_is_alias: false,
                active_merge_event_id: None,
                impact: first.impact,
            },
            4,
            7,
            None,
        );
        assert!(matches!(
            chained,
            Err(PostgresStoreError::InvalidEntityResolution)
        ));
    }

    #[test]
    fn canonical_graph_projection_combines_evidence_without_mutating_rows() {
        let installation_id = Uuid::now_v7();
        let source = Uuid::now_v7();
        let target = Uuid::now_v7();
        let object = Uuid::now_v7();
        let at = Utc::now();
        let relationship = |relationship_id, subject, confidence, status| EntityRelationship {
            relationship_id,
            installation_id,
            subject: EntityRef {
                entity_id: subject,
                kind: EntityKind::AiSystem,
            },
            predicate: RelationshipPredicate::Uses,
            object: EntityRef {
                entity_id: object,
                kind: EntityKind::Product,
            },
            confidence: BasisPoints::new(confidence).expect("confidence"),
            status,
            valid_from: at,
            valid_until: None,
            rule: Some(RuleRef {
                rule_id: "resolution_test".to_owned(),
                version: "1".to_owned(),
            }),
            independent_lineage_count: 1,
            created_at: at,
            revision: 1,
        };
        let observation_a = Uuid::now_v7();
        let observation_b = Uuid::now_v7();
        let projected = canonicalize_graph_relationships(
            vec![
                CanonicalGraphRelationshipRow {
                    relationship: relationship(
                        Uuid::now_v7(),
                        target,
                        7_500,
                        RelationshipStatus::Active,
                    ),
                    evidence_observation_ids: vec![observation_a],
                    source_lineage_ids: vec!["lineage:a".to_owned()],
                },
                CanonicalGraphRelationshipRow {
                    relationship: relationship(
                        Uuid::now_v7(),
                        target,
                        9_000,
                        RelationshipStatus::Disputed,
                    ),
                    evidence_observation_ids: vec![observation_b],
                    source_lineage_ids: vec!["lineage:b".to_owned()],
                },
            ],
            10,
        );
        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0].relationship.subject.entity_id, target);
        assert_eq!(projected[0].relationship.confidence.get(), 9_000);
        assert_eq!(
            projected[0].relationship.status,
            RelationshipStatus::Disputed
        );
        assert_eq!(projected[0].relationship.independent_lineage_count, 2);
        assert_eq!(projected[0].evidence_count, 2);
        assert_eq!(
            projected[0].relationship.relationship_id,
            EntityRelationship::deterministic_id(
                installation_id,
                target,
                RelationshipPredicate::Uses,
                object
            )
        );
        assert_ne!(source, target);
    }

    /// Regression for the scheduler defect where a job could be claimed exactly once.
    ///
    /// The claim advances `last_started_at`; if the previous attempt's `last_finished_at`
    /// survives, it now sits before the new start and violates
    /// `connector_jobs_finish_order_check`, aborting every subsequent claim.
    #[tokio::test]
    #[ignore = "requires TALLY_POSTGRES_URL and a disposable installation scope"]
    #[allow(clippy::too_many_lines)] // Two full claim/complete cycles plus fixture setup.
    async fn live_connector_job_can_be_claimed_again_after_completing() {
        let url = std::env::var("TALLY_POSTGRES_URL").expect("TALLY_POSTGRES_URL");
        let store = PostgresStore::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");

        let installation_id = store
            .get_or_create_installation_identity()
            .await
            .expect("fixture installation")
            .installation_id;
        let connector_instance_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        let descriptor = ConnectorDescriptor {
            connector_type: "generic_dns_file".to_owned(),
            display_name: "Scheduler regression fixture".to_owned(),
            implementation_version: "0.0.0-test".to_owned(),
            source_vendor: "test".to_owned(),
            source_product: "test".to_owned(),
            record_variants: vec!["test".to_owned()],
            transport: ConnectorTransport::File,
            required_permissions: Vec::new(),
            requested_fields: Vec::new(),
            prohibited_fields: Vec::new(),
            cursor_semantics: "test".to_owned(),
            replay_capability: tally_connectors::ReplayCapability::FileReplay,
            health_capabilities: Vec::new(),
            coverage_capabilities: Vec::new(),
            privacy_contract: "test".to_owned(),
        };
        store
            .register_connector(installation_id, connector_instance_id, &descriptor)
            .await
            .expect("register connector");

        let due = Utc::now() - chrono::Duration::seconds(1);
        store
            .put_connector_job(&ConnectorJobSpec {
                job_id,
                connector_instance_id,
                mode: ConnectorJobMode::Scheduled,
                status: ConnectorJobStatus::Enabled,
                schedule_seconds: Some(60),
                next_run_at: Some(due),
                config_refs: serde_json::json!({
                    "kind": "dns_file_v1",
                    "source_lineage_id": "scheduled_file_env"
                }),
                credentials: None,
                updated_at: due,
            })
            .await
            .expect("create job");

        // First cycle: claim, then complete.
        let owner = Uuid::now_v7();
        let claimed = store
            .lease_due_connector_jobs(owner, Utc::now(), 60, 8)
            .await
            .expect("first claim");
        assert!(claimed.iter().any(|job| job.job_id == job_id));
        store
            .complete_connector_job(&ConnectorJobCompletion {
                job_id,
                lease_owner: owner,
                outcome: ConnectorRunStatus::Completed,
                error_code: None,
                finished_at: Utc::now(),
                catch_up: false,
            })
            .await
            .expect("first completion");

        // Make it due again and claim a second time. Before the fix this aborted with
        // connector_jobs_finish_order_check, so a scheduled connector polled exactly once.
        sqlx::query("UPDATE connector_jobs SET next_run_at = $2 WHERE job_id = $1")
            .bind(job_id)
            .bind(Utc::now() - chrono::Duration::seconds(1))
            .execute(&store.pool)
            .await
            .expect("make due again");

        let second_owner = Uuid::now_v7();
        let reclaimed = store
            .lease_due_connector_jobs(second_owner, Utc::now(), 60, 8)
            .await
            .expect("second claim must succeed");
        assert!(
            reclaimed.iter().any(|job| job.job_id == job_id),
            "a completed job must be claimable again"
        );

        let view = store
            .list_connector_jobs()
            .await
            .expect("list jobs")
            .into_iter()
            .find(|job| job.job_id == job_id)
            .expect("job view");
        assert!(
            view.last_finished_at.is_none(),
            "an in-flight attempt must not report a finish time"
        );
        assert_eq!(
            view.last_outcome,
            Some(ConnectorRunStatus::Completed),
            "the previous attempt's outcome stays visible while the next one runs"
        );
        assert_eq!(view.attempt_count, 2);

        store
            .complete_connector_job(&ConnectorJobCompletion {
                job_id,
                lease_owner: second_owner,
                outcome: ConnectorRunStatus::Completed,
                error_code: None,
                finished_at: Utc::now(),
                catch_up: false,
            })
            .await
            .expect("second completion");

        // Leave nothing behind: an enabled job outlives the test and makes any worker
        // sharing this database retry a fixture that no longer has a source.
        sqlx::query("DELETE FROM connector_jobs WHERE job_id = $1")
            .bind(job_id)
            .execute(&store.pool)
            .await
            .expect("remove fixture job");
        // A run ledger entry pins the connector state, so only drop it when nothing
        // references it. Removing the job above is what stops a shared worker retrying.
        sqlx::query(
            r"
            DELETE FROM connector_states
            WHERE connector_instance_id = $1
              AND NOT EXISTS (
                  SELECT 1 FROM connector_runs WHERE connector_instance_id = $1
              )
            ",
        )
        .bind(connector_instance_id)
        .execute(&store.pool)
        .await
        .expect("remove fixture connector");
    }

    /// An embedding host (Gate's vendor blocklist ledger) can pin a connector with
    /// `ON DELETE RESTRICT`. Deleting it must be refused as such, not reported as an outage.
    #[tokio::test]
    #[ignore = "requires TALLY_POSTGRES_URL and a disposable installation scope"]
    async fn live_connector_delete_held_by_host_state_is_refused() {
        let url = std::env::var("TALLY_POSTGRES_URL").expect("TALLY_POSTGRES_URL");
        let store = PostgresStore::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");

        let installation_id = Uuid::now_v7();
        let connector_instance_id = Uuid::now_v7();
        sqlx::query("INSERT INTO installations (installation_id, name) VALUES ($1, $2)")
            .bind(installation_id)
            .bind("connector delete hold fixture")
            .execute(&store.pool)
            .await
            .expect("fixture installation");
        sqlx::query(
            r"
            INSERT INTO connector_states (
                connector_instance_id, installation_id, connector_type, implementation_version,
                display_name, transport
            ) VALUES ($1, $2, 'generic_dns_file', '0.0.0-test', 'Delete hold fixture', 'file')
            ",
        )
        .bind(connector_instance_id)
        .bind(installation_id)
        .execute(&store.pool)
        .await
        .expect("fixture connector");
        sqlx::query(
            r"
            CREATE TABLE IF NOT EXISTS tally_test_connector_holds (
                connector_instance_id UUID PRIMARY KEY
                    REFERENCES connector_states(connector_instance_id) ON DELETE RESTRICT
            )
            ",
        )
        .execute(&store.pool)
        .await
        .expect("hold table");
        sqlx::query("INSERT INTO tally_test_connector_holds (connector_instance_id) VALUES ($1)")
            .bind(connector_instance_id)
            .execute(&store.pool)
            .await
            .expect("hold connector");

        let blocked = store
            .delete_connector(installation_id, connector_instance_id, Utc::now())
            .await;
        // Release the hold before asserting so a failure cannot pin the fixture connector.
        sqlx::query("DELETE FROM tally_test_connector_holds WHERE connector_instance_id = $1")
            .bind(connector_instance_id)
            .execute(&store.pool)
            .await
            .expect("release hold");
        assert!(
            matches!(blocked, Err(PostgresStoreError::ConnectorDeleteBlocked)),
            "{blocked:?}"
        );

        store
            .delete_connector(installation_id, connector_instance_id, Utc::now())
            .await
            .expect("delete once the hold is released");
        sqlx::query("DROP TABLE IF EXISTS tally_test_connector_holds")
            .execute(&store.pool)
            .await
            .expect("drop hold table");
        sqlx::query("DELETE FROM installations WHERE installation_id = $1")
            .bind(installation_id)
            .execute(&store.pool)
            .await
            .expect("remove fixture installation");
    }
}
