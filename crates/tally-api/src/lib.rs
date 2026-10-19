//! Versioned HTTP API for Gödel Tally.

#![allow(dead_code)]

mod data_preview;
mod estate;
mod event_stream;
mod sample_data;
pub use estate::{read_inventory as estate_inventory, retain_ai_observations, with_clickhouse};

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::IpAddr,
    sync::{Arc, RwLock as StandardRwLock},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query},
    http::{HeaderMap, HeaderValue, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tally_config::SecretCipher;
use tally_connectors::{
    CloudFlowProvider, ConnectorDescriptor, ConnectorTransport, Cursor, MAX_IMPORT_BYTES,
    ManagedCloudImportConfig, ManagedCloudScope, ManagedCloudTransport, ObservationBatch,
    PseudonymizationKey, ReplayCapability, VendorImportConfig, VendorImportOutcome,
    aws_managed_ai_api_descriptor, aws_managed_ai_descriptor, azure_managed_ai_api_descriptor,
    azure_managed_ai_descriptor, cato_networks_api_descriptor, cloud_flow_api_descriptor,
    cloud_flow_descriptor, cloud_mapping_api_descriptor, cloud_mapping_descriptor,
    cloudflare_ai_gateway_api_descriptor, cloudflare_ai_gateway_descriptor,
    cloudflare_casb_api_descriptor, cloudflare_casb_descriptor, cloudflare_gateway_descriptor,
    cloudflare_zero_trust_gateway_descriptor, crowdstrike_edr_api_descriptor,
    gcp_vertex_ai_api_descriptor, gcp_vertex_ai_descriptor, import_aws_managed_ai_json,
    import_azure_managed_ai_json, import_cato_networks_json, import_cloud_flow_api_json,
    import_cloud_flow_json, import_cloud_mapping_api_json, import_cloud_mapping_json,
    import_cloudflare_ai_gateway_api_json, import_cloudflare_ai_gateway_json,
    import_cloudflare_casb_api_json, import_cloudflare_casb_json, import_cloudflare_gateway_ndjson,
    import_cloudflare_zero_trust_gateway_ndjson, import_crowdstrike_edr_dns_json,
    import_gcp_vertex_ai_json, import_kubernetes_api_json, import_kubernetes_api_pull_json,
    import_litellm_model_groups_api_json, import_litellm_model_groups_json,
    import_microsoft_defender_json, import_nextdns_api_json, import_nextdns_csv,
    import_palo_alto_ndjson, import_zscaler_ndjson, kubernetes_api_descriptor,
    kubernetes_api_pull_descriptor, litellm_model_groups_api_descriptor,
    litellm_model_groups_descriptor, microsoft_defender_edr_api_descriptor, nextdns_api_descriptor,
    nextdns_descriptor, palo_alto_descriptor, zscaler_descriptor,
};
use tally_core::{
    AiSystemView, AttributionConflict, AttributionConflictStatus, AuthorizationStatus, Claim,
    CloudProviderService, CloudUsageKind, ConnectorContribution,
    ConnectorHealth as ContributionConnectorHealth, ConnectorManagementCapability, ConnectorRef,
    ConnectorSourceFamily, ContributionProducer, Entity, EntityKind, EntityRef, EntityRelationship,
    EvidenceAvailability, EvidenceLinkContribution, EvidenceReceipt, FindingContribution,
    FindingContributionStatus, FlowDirection, Hostname, INTEGRATION_SCHEMA_VERSION,
    IdentitySubjectKind, InventoryContribution, InventoryRelationshipSummary, IpAddress,
    Observation, ObservationKind, ReportMetricContribution, ReportSectionContribution,
    RiskSeverity,
};
use tally_detect::{DetectionClassification, detect};
use tally_observation_buffer::{OBSERVATION_BUFFER_VERSION, ObservationBuffer};
#[cfg(feature = "embedded-registry")]
use tally_registry_lib::verify_artifact;
use tally_registry_lib::{
    Evidence, EvidenceType, FingerprintAssertion, MatchProduces, Matcher, MatcherRule, ProofKind,
    REGISTRY_SCHEMA_VERSION, RegistryBundle, RegistryEntry, RegistryEntryKind, RegistryEntryStatus,
    RegistryManifest, RegistryOverlay, apply_overlays,
};
use tally_resolve::{resolve_cloud_network, resolve_cloud_usage, resolve_cloud_usage_conflict};
use tally_risk::{
    BASELINE_POLICY_ID, BASELINE_POLICY_VERSION, PolicyEvaluationInput, evaluate_baseline,
};
use tally_scanner::{
    DEFAULT_CONNECT_CONCURRENCY, DEFAULT_CONNECT_TIMEOUT_MILLIS, DEFAULT_MAX_HOSTS, DEFAULT_PORTS,
    HARD_MAX_HOSTS, HttpFingerprintAttempt, HttpFingerprintOutcome, MAX_CONNECT_CONCURRENCY,
    MAX_CONNECT_TIMEOUT_MILLIS, ScanCancellation, ScanExecutionPolicy, ScanPlan, ScanRunStatus,
    ScanScope, TcpProbeState, discover_local_scope, execute_http_fingerprints, execute_tcp_connect,
};
use tally_store_postgres::{
    AuthorizationReason, AuthorizationTransitionRequest, BatchDisposition,
    ClassificationApplyOutcome, ClassificationRuleSetCreate, ClassificationRuleSetView,
    ClassificationSystemExpectation, ConnectorBackfillCommit, ConnectorBackfillPreview,
    ConnectorBackfillReceipt, ConnectorDeletion, ConnectorHealth, ConnectorJobMode,
    ConnectorJobSpec, ConnectorJobStatus, ConnectorJobView, ConnectorLabelView, ConnectorRunRecord,
    ConnectorRunStatus, ConnectorStateView, ConnectorSyncSweep, DataInventory, DestinationIdentity,
    EndpointIdentity, EntityResolutionCommit, EntityResolutionEventView, EntityResolutionImpact,
    EntityResolutionOperation, EntityResolutionPreviewData, FindingEvidenceKind, FindingView,
    GovernanceFindingStatus, GovernanceFindingView, ObservedUsage, POSTGRES_MIGRATION_HEAD,
    PostgresStore, PostgresStoreError, PurgeCounts, RegistryModelView, RegistryOverlayCreate,
    RegistryProviderView, ScanJobCompletion, ScanJobCreate, ScanJobStatus, ScanJobView,
    SealedCredentials, StoredRegistryOverlay, SystemEvidenceEdge, TallyOverviewSummary,
    UserIdentity, WorkloadIdentity, connector_backfill_capability,
};
use tokio::sync::{Mutex, RwLock as AsyncRwLock};
use tower_http::trace::TraceLayer;
use url::Url;
use utoipa::{OpenApi, ToSchema};

#[derive(Debug, Clone)]
pub struct AppState {
    pub postgres: Arc<PostgresStore>,
    pub observations: Arc<ObservationBuffer>,
    /// Bounded, process-local pending cloud flows; never written as non-AI logs.
    pub pending_flows: Arc<ObservationBuffer>,
    pub registry: Arc<RegistryRuntime>,
    pub registry_manifest: Arc<RegistryManifest>,
    pub scanner: Arc<ScanRuntime>,
    pub purge_lock: Arc<Mutex<()>>,
    pub classification_lock: Arc<Mutex<()>>,
    pub secret_cipher: Arc<SecretCipher>,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug, Default)]
pub struct ScanRuntime {
    cancellations: AsyncRwLock<HashMap<uuid::Uuid, ScanCancellation>>,
}

#[derive(Debug)]
pub struct RegistryRuntime {
    base: RegistryBundle,
    effective: StandardRwLock<RegistryBundle>,
    overlays: StandardRwLock<Vec<RegistryOverlay>>,
    mutation_lock: Mutex<()>,
}

impl RegistryRuntime {
    /// Builds the effective installation registry from a verified base and durable local overlays.
    ///
    /// # Errors
    ///
    /// Returns a registry invariant error when any stored overlay is unsafe or ambiguous.
    pub fn new(
        base: RegistryBundle,
        overlays: Vec<RegistryOverlay>,
    ) -> Result<Self, tally_registry_lib::RegistryError> {
        let effective = apply_overlays(&base, &overlays)?;
        Ok(Self {
            base,
            effective: StandardRwLock::new(effective),
            overlays: StandardRwLock::new(overlays),
            mutation_lock: Mutex::new(()),
        })
    }

    fn snapshot(&self) -> RegistryBundle {
        self.effective
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn overlays(&self) -> Vec<RegistryOverlay> {
        self.overlays
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn activate(
        &self,
        overlays: Vec<RegistryOverlay>,
    ) -> Result<(), tally_registry_lib::RegistryError> {
        let effective = apply_overlays(&self.base, &overlays)?;
        *self
            .effective
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = effective;
        *self
            .overlays
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = overlays;
        Ok(())
    }

    fn local_entry_ids(&self) -> HashSet<String> {
        self.overlays()
            .into_iter()
            .flat_map(|overlay| overlay.additions.into_iter().map(|entry| entry.id))
            .collect()
    }
}

/// Builds a Tally runtime over a host application's existing `PostgreSQL` pool.
///
/// Schema migration remains the host's startup responsibility, which lets a single migration owner
/// serialize every product upgrade. Tally retains ownership of the embedded registry and storage
/// implementation.
///
/// # Errors
///
/// Returns an error when the embedded registry or persisted local overlays cannot be verified and
/// activated, or when the installation identity cannot be loaded from the host database.
pub async fn state_from_pool(
    pool: sqlx::PgPool,
    secret_cipher: SecretCipher,
) -> anyhow::Result<AppState> {
    state_from_store(Arc::new(PostgresStore::from_pool(pool)), secret_cipher).await
}

/// Builds a Tally runtime from a store already initialized by a standalone or embedding process.
///
/// # Errors
///
/// Returns an error when the embedded registry or persisted local overlays cannot be verified and
/// activated, or when the installation identity cannot be loaded from the store.
pub async fn state_from_store(
    postgres: Arc<PostgresStore>,
    secret_cipher: SecretCipher,
) -> anyhow::Result<AppState> {
    use anyhow::Context as _;

    let (registry, registry_manifest) = embedded_registry()?;
    let state = AppState {
        postgres,
        observations: Arc::new(ObservationBuffer::new()),
        pending_flows: Arc::new(ObservationBuffer::new()),
        registry: Arc::new(
            RegistryRuntime::new(registry, Vec::new())
                .context("activate embedded Tally registry")?,
        ),
        registry_manifest: Arc::new(registry_manifest),
        scanner: Arc::new(ScanRuntime::default()),
        purge_lock: Arc::new(Mutex::new(())),
        classification_lock: Arc::new(Mutex::new(())),
        secret_cipher: Arc::new(secret_cipher),
        started_at: Utc::now(),
    };
    refresh_registry_overlays(&state).await?;
    Ok(state)
}

/// Reloads durable local registry overlays into this process's registry snapshot.
///
/// Embedded API and worker processes have separate memory, so connector execution calls this before
/// admission. The digest check fails closed rather than activating corrupt or speculative entries.
///
/// # Errors
///
/// Returns an error when overlays cannot be loaded, their digests or payloads are invalid, or the
/// resulting registry cannot be activated.
pub async fn refresh_registry_overlays(state: &AppState) -> anyhow::Result<()> {
    use anyhow::{Context as _, ensure};

    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .context("load Tally installation identity")?;
    let _guard = state.registry.mutation_lock.lock().await;
    let stored = state
        .postgres
        .list_registry_overlays(identity.installation_id)
        .await
        .context("load Tally registry overlays")?;
    let overlays = stored
        .into_iter()
        .map(|stored| {
            ensure!(
                stored.digest_matches(),
                "stored Tally registry overlay digest is invalid"
            );
            serde_json::from_value(stored.overlay).context("decode stored Tally registry overlay")
        })
        .collect::<anyhow::Result<Vec<RegistryOverlay>>>()?;
    state
        .registry
        .activate(overlays)
        .context("activate stored Tally registry overlays")
}

/// Verifies and returns the registry artifact shipped by this Tally revision.
///
/// # Errors
///
/// Returns an error when the embedded manifest cannot be decoded or the compressed artifact fails
/// its digest and invariant checks.
#[cfg(feature = "embedded-registry")]
pub fn embedded_registry() -> anyhow::Result<(RegistryBundle, RegistryManifest)> {
    use anyhow::Context as _;

    let manifest = serde_json::from_str::<RegistryManifest>(include_str!(
        "../../../registry-data/dist/tally-registry-2026.08.5.manifest.json"
    ))
    .context("parse embedded Tally registry manifest")?;
    let bundle = verify_artifact(
        include_bytes!("../../../registry-data/dist/tally-registry-2026.08.5.json.zst"),
        &manifest,
    )
    .context("verify embedded Tally registry artifact")?;
    Ok((bundle, manifest))
}

/// Reports that this build intentionally excludes the generated registry artifact.
///
/// This variant is used only by the registry generator itself, which needs the API's OpenAPI
/// document but cannot embed an artifact until it has generated that artifact.
#[cfg(not(feature = "embedded-registry"))]
pub fn embedded_registry() -> anyhow::Result<(RegistryBundle, RegistryManifest)> {
    anyhow::bail!("this Tally build does not include an embedded registry artifact")
}

/// Tally routes without process-level CORS or tracing layers.
///
/// Embedding products mount this router inside their own authentication and middleware stack.
pub fn routes(state: AppState) -> Router {
    const MAX_IMPORT_REQUEST_BYTES: usize = MAX_IMPORT_BYTES * 2 + 65_536;
    Router::new()
        .route("/api/v1/tally/health/live", get(live))
        .route("/api/v1/tally/health/ready", get(ready))
        .route("/api/v1/tally/version", get(version))
        .route("/api/v1/tally/overview", get(overview))
        .route("/api/v1/tally/estate", get(estate::inventory))
        .route("/api/v1/tally/estate/activity", get(estate::activity))
        .route(
            "/api/v1/tally/estate/activity/query",
            post(estate::activity_records),
        )
        .route(
            "/api/v1/tally/registry/estate-reviews",
            post(estate::review::update),
        )
        .route("/api/v1/tally/registry/providers", get(registry_providers))
        .route(
            "/api/v1/tally/registry/provider-domains",
            get(registry_provider_domains),
        )
        .route("/api/v1/tally/registry/models", get(registry_models))
        .route("/api/v1/tally/registry/sanctions", post(registry_sanction))
        .route("/api/v1/tally/findings", get(findings))
        .route(
            "/api/v1/tally/event-stream",
            get(event_stream::event_stream),
        )
        .route("/api/v1/tally/connectors", get(connectors))
        .route(
            "/api/v1/tally/connectors/schedules",
            post(upsert_connector_schedule),
        )
        .route(
            "/api/v1/tally/connectors/{connector_instance_id}/configuration",
            get(connector_configuration),
        )
        .route("/api/v1/tally/connectors/sync", post(sync_all_connectors))
        .route(
            "/api/v1/tally/connectors/{connector_instance_id}",
            delete(delete_connector),
        )
        .route(
            "/api/v1/tally/connectors/{connector_instance_id}/sync",
            post(sync_connector),
        )
        .route(
            "/api/v1/tally/connectors/jobs/{job_id}/backfill/preview",
            post(preview_connector_backfill),
        )
        .route(
            "/api/v1/tally/connectors/jobs/{job_id}/backfill",
            post(commit_connector_backfill),
        )
        .route(
            "/api/v1/tally/imports/preview",
            post(preview_import).layer(DefaultBodyLimit::max(MAX_IMPORT_REQUEST_BYTES)),
        )
        .route(
            "/api/v1/tally/imports",
            post(commit_import).layer(DefaultBodyLimit::max(MAX_IMPORT_REQUEST_BYTES)),
        )
        .route("/api/v1/tally/audit", get(audit))
        .route("/api/v1/tally/data", get(data_inventory))
        .route("/api/v1/tally/data/preview", post(data_preview::preview))
        .route(
            "/api/v1/tally/data/sample",
            get(sample_data::status).post(sample_data::add),
        )
        .route(
            "/api/v1/tally/data/sample/delete",
            post(sample_data::remove),
        )
        .route("/api/v1/tally/data/delete", post(delete_data))
        .route("/api/v1/tally/scans/preview", post(preview_scan))
        .route("/api/v1/tally/scans", get(scans).post(start_scan))
        .route("/api/v1/tally/scans/{scan_id}", get(scan))
        .route("/api/v1/tally/scans/{scan_id}/cancel", post(cancel_scan))
        .route("/api/v1/tally/metrics", get(metrics))
        .with_state(state)
}

/// Standalone Tally router, served through the console's same-origin API proxy.
pub fn router(state: AppState) -> Router {
    routes(state).layer(TraceLayer::new_for_http())
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/health/live",
    responses((status = 200, description = "Process is alive", body = HealthResponse))
)]
async fn live() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: HealthStatus::Healthy,
        postgres: None,
        observations: None,
        checked_at: Utc::now(),
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/health/ready",
    responses(
        (status = 200, description = "Dependencies are ready", body = HealthResponse),
        (status = 503, description = "A dependency is unavailable", body = HealthResponse)
    )
)]
async fn ready(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> (StatusCode, Json<HealthResponse>) {
    let (postgres, observations) = tokio::join!(state.postgres.ping(), state.observations.ping());
    let postgres = DependencyHealth::from_result(&postgres);
    let observations = DependencyHealth::from_result(&observations);
    let is_ready = postgres.healthy && observations.healthy;
    let response = HealthResponse {
        status: if is_ready {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unavailable
        },
        postgres: Some(postgres),
        observations: Some(observations),
        checked_at: Utc::now(),
    };
    (
        if is_ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(response),
    )
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/version",
    responses((status = 200, body = VersionResponse))
)]
async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        product: "godel-tally",
        version: env!("CARGO_PKG_VERSION"),
        api_version: "v1",
    })
}

const PREVIOUS_COMPATIBLE_TALLY_VERSION: &str = "0.1.0-alpha.0";

#[utoipa::path(
    get,
    path = "/api/v1/tally/integration/capabilities",
    responses((status = 200, body = IntegrationCapabilityManifestResponse))
)]
async fn integration_capabilities(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<IntegrationCapabilityManifestResponse>, ApiError> {
    let (postgres_migration_head, observations_migration_head) = tokio::join!(
        state.postgres.migration_head(),
        state.observations.migration_head(),
    );
    let response = build_integration_capability_manifest(
        &state.registry_manifest,
        state.registry.overlays().len(),
        postgres_migration_head.map_err(ApiError::dependency)?,
        &observations_migration_head.map_err(ApiError::dependency)?,
    );
    Ok(Json(response))
}

fn build_integration_capability_manifest(
    registry: &RegistryManifest,
    local_overlay_count: usize,
    postgres_migration_head: i64,
    observations_migration_head: &str,
) -> IntegrationCapabilityManifestResponse {
    let routes = integration_route_capabilities();
    let migrations_compatible = postgres_migration_head == POSTGRES_MIGRATION_HEAD
        && observations_migration_head == OBSERVATION_BUFFER_VERSION;
    let reported_observations_head = if observations_migration_head == OBSERVATION_BUFFER_VERSION {
        observations_migration_head
    } else {
        "incompatible"
    };
    IntegrationCapabilityManifestResponse {
        schema_version: "1.0.0".to_owned(),
        product: "godel-tally".to_owned(),
        product_version: env!("CARGO_PKG_VERSION").to_owned(),
        api_version: "v1".to_owned(),
        integration_schema_version: INTEGRATION_SCHEMA_VERSION.to_owned(),
        supported_integration_schema_versions: vec![INTEGRATION_SCHEMA_VERSION.to_owned()],
        previous_compatible_tally_version: PREVIOUS_COMPATIBLE_TALLY_VERSION.to_owned(),
        routes,
        registry: IntegrationRegistryCapability {
            schema_version: registry.schema_version.clone(),
            version: registry.registry_version.clone(),
            bundle_sha256: registry.bundle_sha256.clone(),
            compressed_sha256: registry.compressed_sha256.clone(),
            verification: "artifact_verified".to_owned(),
            local_overlay_count,
        },
        migrations: IntegrationMigrationCapability {
            postgres_head: postgres_migration_head,
            postgres_required_head: POSTGRES_MIGRATION_HEAD,
            observations_head: reported_observations_head.to_owned(),
            observations_required_head: OBSERVATION_BUFFER_VERSION.to_owned(),
            compatible: migrations_compatible,
        },
        deprecation: IntegrationDeprecationPolicy {
            policy_version: "1".to_owned(),
            minimum_notice_days: 90,
            previous_minor_fixture_required: true,
            removal_requires_schema_major: true,
        },
        content_retained: false,
    }
}

fn integration_route_capabilities() -> Vec<IntegrationRouteCapability> {
    [
        ("inventory", "/api/v1/tally/integration/inventory", 50),
        ("connectors", "/api/v1/tally/integration/connectors", 500),
        ("findings", "/api/v1/tally/integration/findings", 500),
        (
            "evidence_links",
            "/api/v1/tally/integration/evidence-links",
            512,
        ),
        (
            "discovery_summary",
            "/api/v1/tally/integration/report-sections/discovery-summary",
            1,
        ),
    ]
    .into_iter()
    .map(
        |(capability, path, maximum_items)| IntegrationRouteCapability {
            capability: capability.to_owned(),
            method: "GET".to_owned(),
            path: path.to_owned(),
            route_version: "v1".to_owned(),
            maximum_items,
            deprecated: false,
        },
    )
    .collect()
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/registry",
    responses((status = 200, body = RegistryCatalogResponse))
)]
fn registry(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Json<RegistryCatalogResponse> {
    let registry = state.registry.snapshot();
    let local_entry_ids = state.registry.local_entry_ids();
    let local_overlay_count = state.registry.overlays().len();
    let entries = registry
        .entries
        .iter()
        .map(|entry| registry_entry_response(entry, local_entry_ids.contains(&entry.id)))
        .collect::<Vec<_>>();
    let mut kind_counts = std::collections::BTreeMap::new();
    for entry in &entries {
        *kind_counts.entry(entry.kind.clone()).or_insert(0_usize) += 1;
    }
    let fingerprints = registry
        .fingerprints
        .iter()
        .map(|fingerprint| RegistryFingerprintResponse {
            id: fingerprint.id.clone(),
            ports: fingerprint.ports.clone(),
            method: enum_name(fingerprint.method, "unknown"),
            probe_kind: fingerprint
                .request
                .map(|request| enum_name(request, "unknown")),
            path: fingerprint.path.clone(),
            assertion_count: fingerprint.assertions.len(),
            asserted_facts: fingerprint
                .assertions
                .iter()
                .map(fingerprint_fact)
                .collect(),
            evidence_count: fingerprint.evidence.len(),
            verified_at: fingerprint.verified_at.to_string(),
        })
        .collect::<Vec<_>>();
    Json(RegistryCatalogResponse {
        verification: RegistryVerificationResponse {
            status: "artifact_verified".to_owned(),
            checks: vec![
                "compressed_sha256".to_owned(),
                "bundle_sha256".to_owned(),
                "schema_and_invariants".to_owned(),
            ],
            signature_verified: false,
            signature_note: "The embedded development artifact is digest-verified; release artifacts additionally require Sigstore verification before activation.".to_owned(),
        },
        schema_version: registry.schema_version.clone(),
        version: registry.version.clone(),
        source_sha256: registry.source_sha256.clone(),
        bundle_sha256: state.registry_manifest.bundle_sha256.clone(),
        compressed_sha256: state.registry_manifest.compressed_sha256.clone(),
        compiler_version: state.registry_manifest.compiler_version.clone(),
        entry_count: entries.len(),
        matcher_count: entries.iter().map(|entry| entry.matchers.len()).sum(),
        fingerprint_count: fingerprints.len(),
        kind_counts,
        local_overlay_count,
        content_retained: false,
        entries,
        fingerprints,
    })
}

fn registry_entry_response(entry: &RegistryEntry, local: bool) -> RegistryEntryResponse {
    let mut evidence_urls = HashSet::new();
    let mut latest_verified_at = None;
    for evidence in entry
        .facts
        .values()
        .flat_map(|fact| fact.sources.iter())
        .chain(
            entry
                .matchers
                .iter()
                .flat_map(|matcher| matcher.evidence.iter()),
        )
    {
        evidence_urls.insert(evidence.url.as_str());
        latest_verified_at = Some(latest_verified_at.map_or(evidence.verified_at, |current| {
            std::cmp::max(current, evidence.verified_at)
        }));
    }
    RegistryEntryResponse {
        id: entry.id.clone(),
        kind: enum_name(entry.kind, "unknown"),
        name: entry.name.clone(),
        provider_ref: entry.provider_ref.clone(),
        categories: entry.categories.clone(),
        surfaces: entry.surfaces.clone(),
        status: enum_name(entry.status, "unknown"),
        fact_count: entry.facts.len(),
        fact_names: entry.facts.keys().cloned().collect(),
        evidence_source_count: evidence_urls.len(),
        latest_verified_at: latest_verified_at.map(|date| date.to_string()),
        local,
        matchers: entry
            .matchers
            .iter()
            .map(registry_matcher_response)
            .collect(),
    }
}

fn registry_matcher_response(matcher: &Matcher) -> RegistryMatcherResponse {
    let (rule_type, value) = match &matcher.rule {
        MatcherRule::HostExact { value } => ("host_exact", value.clone()),
        MatcherRule::HostSuffix { value } => ("host_suffix", value.clone()),
        MatcherRule::ModelPattern { value } => ("model_pattern", value.clone()),
        MatcherRule::VendorAppId { vendor, value } => {
            ("vendor_app_id", format!("{vendor}:{value}"))
        }
        MatcherRule::ScannerFingerprint { fingerprint_ref } => {
            ("scanner_fingerprint", fingerprint_ref.clone())
        }
    };
    RegistryMatcherResponse {
        id: matcher.id.clone(),
        rule_type: rule_type.to_owned(),
        value,
        proof: enum_name(matcher.produces.proof, "unknown"),
        confidence_bps: matcher.confidence_bps,
        verified_at: matcher.verified_at.to_string(),
        evidence_count: matcher.evidence.len(),
    }
}

fn fingerprint_fact(assertion: &FingerprintAssertion) -> String {
    match assertion {
        FingerprintAssertion::JsonStringPresent { fact, .. } => fact.clone(),
        FingerprintAssertion::JsonStringEquals { field, .. } => field.clone(),
        FingerprintAssertion::JsonArrayPresent { count_fact, .. } => count_fact.clone(),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/registry/entries",
    request_body = LocalRegistryEntryRequest,
    responses(
        (status = 201, body = LocalRegistryEntryResponse),
        (status = 200, body = LocalRegistryEntryResponse),
        (status = 400, body = ProblemDetails),
        (status = 409, body = ProblemDetails),
        (status = 422, body = ProblemDetails)
    )
)]
async fn create_registry_entry(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    Json(request): Json<LocalRegistryEntryRequest>,
) -> Result<(StatusCode, Json<LocalRegistryEntryResponse>), ApiError> {
    let idempotency_key = parse_idempotency_key(&headers)?;
    let request_bytes = serde_json::to_vec(&request).map_err(ApiError::dependency)?;
    let request_sha256 = hex::encode(Sha256::digest(&request_bytes));
    let (overlay, entry_id) = build_local_registry_overlay(&request)?;
    let overlay_id = overlay.id.clone();
    let overlay_value = serde_json::to_value(&overlay).map_err(ApiError::dependency)?;
    let overlay_bytes = serde_json::to_vec(&overlay_value).map_err(ApiError::dependency)?;
    let overlay_sha256 = hex::encode(Sha256::digest(&overlay_bytes));
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    let _guard = state.registry.mutation_lock.lock().await;
    let current = state.registry.overlays();
    let existing_id = current.iter().any(|item| item.id == overlay_id);
    if !existing_id {
        let mut candidate = current.clone();
        candidate.push(overlay.clone());
        apply_overlays(&state.registry.base, &candidate).map_err(|_| {
            ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "registry_overlay_invalid")
        })?;
    }
    let write = state
        .postgres
        .create_registry_overlay(&RegistryOverlayCreate {
            overlay_id: overlay_id.clone(),
            installation_id: identity.installation_id,
            overlay: overlay_value,
            overlay_sha256: overlay_sha256.clone(),
            request_sha256,
            entry_count: 1,
            matcher_count: i32::try_from(overlay.additions[0].matchers.len()).unwrap_or(i32::MAX),
            idempotency_key,
            created_at: Utc::now(),
        })
        .await
        .map_err(ApiError::from_store)?;
    let stored = state
        .postgres
        .list_registry_overlays(identity.installation_id)
        .await
        .map_err(ApiError::dependency)?;
    let overlays = decode_registry_overlays(stored)?;
    state
        .registry
        .activate(overlays)
        .map_err(|_| ApiError::dependency_message("registry_overlay_activation_failed"))?;
    let effective = state.registry.snapshot();
    let entry = effective
        .entries
        .iter()
        .find(|entry| entry.id == entry_id)
        .ok_or_else(|| ApiError::dependency_message("registry_overlay_activation_failed"))?;
    let response = LocalRegistryEntryResponse {
        overlay_id,
        overlay_sha256: write.overlay.overlay_sha256,
        replayed: write.replayed,
        local: true,
        content_retained: false,
        effective_entry_count: effective.entries.len(),
        effective_matcher_count: effective
            .entries
            .iter()
            .map(|entry| entry.matchers.len())
            .sum(),
        entry: registry_entry_response(entry, true),
    };
    Ok((
        if write.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(response),
    ))
}

fn decode_registry_overlays(
    stored: Vec<StoredRegistryOverlay>,
) -> Result<Vec<RegistryOverlay>, ApiError> {
    stored
        .into_iter()
        .map(|stored| {
            if !stored.digest_matches() {
                return Err(ApiError::dependency_message(
                    "stored_registry_overlay_digest_invalid",
                ));
            }
            serde_json::from_value(stored.overlay)
                .map_err(|_| ApiError::dependency_message("stored_registry_overlay_invalid"))
        })
        .collect()
}

fn build_local_registry_overlay(
    request: &LocalRegistryEntryRequest,
) -> Result<(RegistryOverlay, String), ApiError> {
    if !request.acknowledge_local_overlay
        || request.name.trim() != request.name
        || request.name.len() < 2
        || request.name.len() > 100
        || request.name.chars().any(char::is_control)
        || request.categories.is_empty()
        || request.categories.len() > 6
        || request.host_rules.is_empty()
        || request.host_rules.len() > 20
        || request.evidence_url.len() > 2_048
        || !request.evidence_url.starts_with("https://")
        || request.evidence_url.chars().any(char::is_whitespace)
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "registry_entry_invalid",
        ));
    }
    let slug = local_registry_slug(&request.name)
        .ok_or_else(|| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "registry_entry_invalid"))?;
    let kind = request.kind.registry_kind();
    let entry_id = format!("local.{}.{}", request.kind.key(), slug);
    let verified_at = Utc::now().date_naive();
    let evidence = Evidence {
        source_type: EvidenceType::ProjectResearch,
        url: request.evidence_url.clone(),
        verified_at,
        reviewer: "local_operator".to_owned(),
    };
    let mut categories = request
        .categories
        .iter()
        .map(|category| category.key().to_owned())
        .collect::<Vec<_>>();
    categories.sort();
    categories.dedup();
    if categories.len() != request.categories.len() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "registry_entry_invalid",
        ));
    }
    let mut matchers = request
        .host_rules
        .iter()
        .map(|rule| {
            let host = rule.host.trim().trim_end_matches('.').to_ascii_lowercase();
            let matcher_digest = hex::encode(Sha256::digest(
                format!("{}:{host}", rule.kind.key()).as_bytes(),
            ));
            Matcher {
                id: format!("host.{}.{}", rule.kind.key(), &matcher_digest[..12]),
                rule: match rule.kind {
                    LocalHostRuleKind::Exact => MatcherRule::HostExact { value: host },
                    LocalHostRuleKind::Suffix => MatcherRule::HostSuffix { value: host },
                },
                produces: MatchProduces {
                    entity_ref: entry_id.clone(),
                    proof: request.kind.proof(),
                },
                confidence_bps: 8_500,
                verified_at,
                evidence: vec![evidence.clone()],
            }
        })
        .collect::<Vec<_>>();
    matchers.sort_by(|left, right| left.id.cmp(&right.id));
    matchers.dedup_by(|left, right| left.id == right.id);
    if matchers.len() != request.host_rules.len() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "registry_entry_invalid",
        ));
    }
    let entry = RegistryEntry {
        id: entry_id.clone(),
        kind,
        name: request.name.clone(),
        provider_ref: None,
        categories,
        surfaces: vec![request.surface.key().to_owned()],
        facts: std::collections::BTreeMap::new(),
        matchers,
        status: RegistryEntryStatus::Active,
    };
    let overlay = RegistryOverlay {
        schema_version: REGISTRY_SCHEMA_VERSION.to_owned(),
        id: entry_id.clone(),
        additions: vec![entry],
        entries: Vec::new(),
        disabled_matchers: Vec::new(),
    };
    Ok((overlay, entry_id))
}

fn local_registry_slug(name: &str) -> Option<String> {
    let mut slug = String::new();
    let mut separator = false;
    for character in name.chars() {
        if character.is_ascii_alphanumeric() {
            if separator && !slug.is_empty() && slug.len() < 40 {
                slug.push('-');
            }
            separator = false;
            if slug.len() < 40 {
                slug.push(character.to_ascii_lowercase());
            }
        } else {
            separator = true;
        }
    }
    let slug = slug.trim_matches('-').to_owned();
    (!slug.is_empty()).then_some(slug)
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/classification-rules",
    responses((status = 200, body = ClassificationRuleSetsResponse))
)]
async fn classification_rule_sets(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<ClassificationRuleSetsResponse>, ApiError> {
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    let items = state
        .postgres
        .list_classification_rule_sets(identity.installation_id, 100)
        .await
        .map_err(ApiError::dependency)?
        .into_iter()
        .map(classification_rule_set_response)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(ClassificationRuleSetsResponse { items }))
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/classification-rules/preview",
    request_body = ClassificationRulePreviewRequest,
    responses(
        (status = 200, body = ClassificationRulePreviewResponse),
        (status = 422, body = ProblemDetails)
    )
)]
async fn preview_classification_rules(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(request): Json<ClassificationRulePreviewRequest>,
) -> Result<Json<ClassificationRulePreviewResponse>, ApiError> {
    Ok(Json(build_classification_preview(&state, &request).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/classification-rules",
    request_body = ClassificationRuleCommitRequest,
    responses(
        (status = 201, body = ClassificationRuleCommitResponse),
        (status = 200, body = ClassificationRuleCommitResponse),
        (status = 400, body = ProblemDetails),
        (status = 409, body = ProblemDetails),
        (status = 422, body = ProblemDetails)
    )
)]
#[allow(clippy::too_many_lines)]
async fn commit_classification_rules(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ClassificationRuleCommitRequest>,
) -> Result<(StatusCode, Json<ClassificationRuleCommitResponse>), ApiError> {
    if !request.acknowledge_classification {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "classification_acknowledgement_required",
        ));
    }
    let idempotency_key = parse_idempotency_key(&headers)?;
    let request_sha256 = hex::encode(Sha256::digest(
        serde_json::to_vec(&request).map_err(ApiError::dependency)?,
    ));
    let _guard = state.classification_lock.lock().await;
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    if let Some((stored_request_sha256, stored_rule_set)) = state
        .postgres
        .get_classification_rule_set_by_idempotency(identity.installation_id, idempotency_key)
        .await
        .map_err(ApiError::dependency)?
    {
        if stored_request_sha256 != request_sha256 {
            return Err(ApiError::new(StatusCode::CONFLICT, "idempotency_conflict"));
        }
        let changed = stored_rule_set
            .changed_system_ids
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        evaluate_imported_systems(&state, &changed).await?;
        return Ok((
            StatusCode::OK,
            Json(ClassificationRuleCommitResponse {
                replayed: true,
                rule_set: classification_rule_set_response(stored_rule_set)?,
                content_retained: false,
            }),
        ));
    }
    let preview_request = ClassificationRulePreviewRequest {
        decision: request.decision,
        rules: request.rules.clone(),
    };
    let preview = build_classification_preview(&state, &preview_request).await?;
    if preview.observation_window_truncated {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "classification_observation_window_incomplete",
        ));
    }
    if preview.preview_digest != request.confirm_preview_digest {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "classification_preview_changed",
        ));
    }
    let rules_value = serde_json::to_value(&preview.rules).map_err(ApiError::dependency)?;
    let rules_sha256 = hex::encode(Sha256::digest(
        serde_json::to_vec(&rules_value).map_err(ApiError::dependency)?,
    ));
    let write = state
        .postgres
        .create_classification_rule_set(&ClassificationRuleSetCreate {
            rule_set_id: idempotency_key,
            idempotency_key,
            installation_id: identity.installation_id,
            request_sha256,
            preview_digest: preview.preview_digest.clone(),
            decision: request.decision.key().to_owned(),
            rules: rules_value,
            rules_sha256,
            matched_systems: preview
                .systems
                .iter()
                .map(|system| ClassificationSystemExpectation {
                    system_id: system.system_id,
                    authorization_status: system.current_authorization.clone(),
                    revision: system.current_revision,
                })
                .collect(),
            created_at: Utc::now(),
        })
        .await
        .map_err(ApiError::from_store)?;
    let changed = write
        .rule_set
        .changed_system_ids
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    evaluate_imported_systems(&state, &changed).await?;
    let response = ClassificationRuleCommitResponse {
        replayed: write.replayed,
        rule_set: classification_rule_set_response(write.rule_set)?,
        content_retained: false,
    };
    Ok((
        if response.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(response),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/classification-rules/{rule_set_id}/deactivate",
    params(("rule_set_id" = uuid::Uuid, Path, description = "Rule-set identifier")),
    request_body = ClassificationRuleDeactivateRequest,
    responses(
        (status = 200, body = ClassificationRuleDeactivateResponse),
        (status = 400, body = ProblemDetails),
        (status = 404, body = ProblemDetails),
        (status = 409, body = ProblemDetails),
        (status = 422, body = ProblemDetails)
    )
)]
async fn deactivate_classification_rules(
    axum::extract::State(state): axum::extract::State<AppState>,
    Path(rule_set_id): Path<uuid::Uuid>,
    headers: HeaderMap,
    Json(request): Json<ClassificationRuleDeactivateRequest>,
) -> Result<Json<ClassificationRuleDeactivateResponse>, ApiError> {
    if !request.acknowledge_deactivation {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "classification_deactivation_acknowledgement_required",
        ));
    }
    let idempotency_key = parse_idempotency_key(&headers)?;
    let request_sha256 = hex::encode(Sha256::digest(
        serde_json::to_vec(&(rule_set_id, &request)).map_err(ApiError::dependency)?,
    ));
    let _guard = state.classification_lock.lock().await;
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    let write = state
        .postgres
        .deactivate_classification_rule_set(
            identity.installation_id,
            rule_set_id,
            idempotency_key,
            &request_sha256,
            Utc::now(),
        )
        .await
        .map_err(ApiError::from_store)?;
    Ok(Json(ClassificationRuleDeactivateResponse {
        replayed: write.replayed,
        rule_set: classification_rule_set_response(write.rule_set)?,
        existing_system_decisions_changed: false,
        content_retained: false,
    }))
}

#[allow(clippy::too_many_lines)]
async fn build_classification_preview(
    state: &AppState,
    request: &ClassificationRulePreviewRequest,
) -> Result<ClassificationRulePreviewResponse, ApiError> {
    const OBSERVATION_LIMIT: u32 = 100_000;
    let rules = normalize_classification_rules(&request.rules)?;
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    let existing = state
        .postgres
        .list_active_classification_rule_sets(identity.installation_id)
        .await
        .map_err(ApiError::dependency)?;
    reject_classification_conflicts(request.decision, &rules, &existing)?;
    let opposite_rules = existing
        .iter()
        .filter(|rule_set| rule_set.decision != request.decision.key())
        .map(|rule_set| {
            serde_json::from_value::<Vec<ClassificationHostRule>>(rule_set.rules.clone())
                .map_err(|_| ApiError::dependency_message("stored_classification_rules_invalid"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (observations, observation_total, edges) = tokio::join!(
        state.observations.list_observations(OBSERVATION_LIMIT),
        state.observations.observation_count(),
        state.postgres.list_system_evidence_index(),
    );
    let observations = observations.map_err(ApiError::dependency)?;
    let observation_total = observation_total.map_err(ApiError::dependency)?;
    let mut systems_by_observation = HashMap::<uuid::Uuid, BTreeSet<uuid::Uuid>>::new();
    for edge in edges.map_err(ApiError::dependency)? {
        systems_by_observation
            .entry(edge.observation_id)
            .or_default()
            .insert(edge.system_id);
    }
    let mut matched_observation_ids = Vec::new();
    let mut matched_system_events = HashMap::<uuid::Uuid, u64>::new();
    let mut opposite_matched_systems = HashSet::<uuid::Uuid>::new();
    let mut unresolved_observations = 0_u64;
    for observation in &observations {
        let Some(host) = classification_observation_host(observation) else {
            continue;
        };
        if opposite_rules
            .iter()
            .flatten()
            .any(|rule| classification_rule_matches(rule, host))
            && let Some(system_ids) = systems_by_observation.get(&observation.observation_id)
        {
            opposite_matched_systems.extend(system_ids);
        }
        if !rules
            .iter()
            .any(|rule| classification_rule_matches(rule, host))
        {
            continue;
        }
        matched_observation_ids.push(observation.observation_id);
        if let Some(system_ids) = systems_by_observation.get(&observation.observation_id) {
            for system_id in system_ids {
                let count = matched_system_events.entry(*system_id).or_default();
                *count = count.saturating_add(1);
            }
        } else {
            unresolved_observations = unresolved_observations.saturating_add(1);
        }
    }
    matched_observation_ids.sort();
    let mut systems = Vec::new();
    for (system_id, matching_observations) in matched_system_events {
        if let Some(system) = state
            .postgres
            .get_ai_system(system_id)
            .await
            .map_err(ApiError::dependency)?
        {
            systems.push(ClassificationSystemEffect {
                system_id,
                display_name: system.display_name,
                current_authorization: enum_name(system.authorization, "discovered"),
                target_authorization: if system.authorization == AuthorizationStatus::Retired {
                    "retired".to_owned()
                } else {
                    request.decision.key().to_owned()
                },
                current_revision: system.revision,
                matching_observations,
                retired: system.authorization == AuthorizationStatus::Retired,
            });
        }
    }
    systems.sort_by_key(|system| system.system_id);
    if systems
        .iter()
        .any(|system| opposite_matched_systems.contains(&system.system_id))
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "classification_system_conflict",
        ));
    }
    let preview_digest = classification_preview_digest(
        identity.installation_id,
        request.decision,
        &rules,
        &matched_observation_ids,
        &systems,
    )?;
    Ok(ClassificationRulePreviewResponse {
        preview_digest,
        decision: request.decision,
        rules,
        loaded_observations: observations.len(),
        observation_total,
        observation_window_truncated: observation_total
            > u64::try_from(observations.len()).unwrap_or(u64::MAX),
        matched_observations: matched_observation_ids.len(),
        unresolved_observations,
        matched_systems: systems.len(),
        systems,
        content_retained: false,
    })
}

fn classification_preview_digest(
    installation_id: uuid::Uuid,
    decision: ClassificationDecision,
    rules: &[ClassificationHostRule],
    matched_observation_ids: &[uuid::Uuid],
    systems: &[ClassificationSystemEffect],
) -> Result<String, ApiError> {
    let digest_input = (
        "classification-preview-v1",
        installation_id,
        decision,
        rules,
        matched_observation_ids,
        systems
            .iter()
            .map(|system| {
                (
                    system.system_id,
                    system.current_revision,
                    system.current_authorization.as_str(),
                )
            })
            .collect::<Vec<_>>(),
    );
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(&digest_input).map_err(ApiError::dependency)?,
    )))
}

fn normalize_classification_rules(
    input: &[ClassificationHostRule],
) -> Result<Vec<ClassificationHostRule>, ApiError> {
    if input.is_empty() || input.len() > 500 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "classification_rules_invalid",
        ));
    }
    let mut rules = input
        .iter()
        .map(|rule| {
            let host = Hostname::parse(&rule.host).map_err(|_| {
                ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "classification_rules_invalid",
                )
            })?;
            Ok(ClassificationHostRule {
                kind: rule.kind,
                host: host.as_str().to_owned(),
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    rules.sort_by(|left, right| {
        left.kind
            .key()
            .cmp(right.kind.key())
            .then_with(|| left.host.cmp(&right.host))
    });
    rules.dedup_by(|left, right| left.kind.key() == right.kind.key() && left.host == right.host);
    if rules.len() != input.len() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "classification_rules_invalid",
        ));
    }
    Ok(rules)
}

fn reject_classification_conflicts(
    decision: ClassificationDecision,
    rules: &[ClassificationHostRule],
    existing: &[ClassificationRuleSetView],
) -> Result<(), ApiError> {
    for rule_set in existing {
        if rule_set.decision == decision.key() {
            continue;
        }
        let existing_rules =
            serde_json::from_value::<Vec<ClassificationHostRule>>(rule_set.rules.clone())
                .map_err(|_| ApiError::dependency_message("stored_classification_rules_invalid"))?;
        if rules.iter().any(|rule| {
            existing_rules
                .iter()
                .any(|existing| classification_rules_overlap(rule, existing))
        }) {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "classification_rule_conflict",
            ));
        }
    }
    Ok(())
}

fn classification_observation_host(observation: &Observation) -> Option<&str> {
    observation
        .destination
        .host
        .as_ref()
        .or(observation.service.tls_server_name.as_ref())
        .map(Hostname::as_str)
}

fn classification_rule_matches(rule: &ClassificationHostRule, host: &str) -> bool {
    match rule.kind {
        LocalHostRuleKind::Exact => host == rule.host,
        LocalHostRuleKind::Suffix => {
            host == rule.host || host.ends_with(&format!(".{}", rule.host))
        }
    }
}

fn classification_rules_overlap(
    first: &ClassificationHostRule,
    second: &ClassificationHostRule,
) -> bool {
    match (first.kind, second.kind) {
        (LocalHostRuleKind::Exact, LocalHostRuleKind::Exact) => first.host == second.host,
        (LocalHostRuleKind::Exact, LocalHostRuleKind::Suffix) => {
            classification_rule_matches(second, &first.host)
        }
        (LocalHostRuleKind::Suffix, LocalHostRuleKind::Exact) => {
            classification_rule_matches(first, &second.host)
        }
        (LocalHostRuleKind::Suffix, LocalHostRuleKind::Suffix) => {
            classification_rule_matches(first, &second.host)
                || classification_rule_matches(second, &first.host)
        }
    }
}

#[utoipa::path(get, path = "/api/v1/tally/overview", responses((status = 200, body = TallyOverviewSummary)))]
async fn overview(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<TallyOverviewSummary>, ApiError> {
    state
        .postgres
        .tally_overview()
        .await
        .map(Json)
        .map_err(ApiError::dependency)
}

#[utoipa::path(get, path = "/api/v1/tally/registry/providers", responses((status = 200, body = Vec<RegistryProviderView>)))]
async fn registry_providers(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<Vec<RegistryProviderView>>, ApiError> {
    state
        .postgres
        .list_registry_providers()
        .await
        .map(Json)
        .map_err(ApiError::dependency)
}

#[utoipa::path(get, path = "/api/v1/tally/registry/provider-domains", responses((status = 200, body = BTreeMap<String, Vec<String>>)))]
async fn registry_provider_domains(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<BTreeMap<String, Vec<String>>>, ApiError> {
    state
        .postgres
        .list_provider_domains()
        .await
        .map(Json)
        .map_err(ApiError::dependency)
}

#[utoipa::path(get, path = "/api/v1/tally/registry/models", responses((status = 200, body = Vec<RegistryModelView>)))]
async fn registry_models(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<Vec<RegistryModelView>>, ApiError> {
    state
        .postgres
        .list_registry_models()
        .await
        .map(Json)
        .map_err(ApiError::dependency)
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct RegistrySanctionRequest {
    #[serde(default)]
    provider_ids: Vec<uuid::Uuid>,
    #[serde(default)]
    model_ids: Vec<uuid::Uuid>,
    sanctioned: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct RegistrySanctionResponse {
    affected: u64,
}

#[utoipa::path(post, path = "/api/v1/tally/registry/sanctions", request_body = RegistrySanctionRequest, responses((status = 200, body = RegistrySanctionResponse)))]
async fn registry_sanction(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(request): Json<RegistrySanctionRequest>,
) -> Result<Json<RegistrySanctionResponse>, ApiError> {
    let sanction_count = request.provider_ids.len() + request.model_ids.len();
    if sanction_count == 0 || sanction_count > 500 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "registry_sanction_invalid",
        ));
    }
    let affected = state
        .postgres
        .set_registry_sanctions(
            &request.provider_ids,
            &request.model_ids,
            request.sanctioned,
        )
        .await
        .map_err(ApiError::from_store)?;
    Ok(Json(RegistrySanctionResponse { affected }))
}

const ANALYTICS_OBSERVATION_LIMIT: u32 = 100_000;
const ANALYTICS_SYSTEM_LIMIT: usize = 10_000;

#[derive(Debug, Default)]
struct ServiceAdoptionAccumulator {
    event_count: u64,
    actors: HashSet<String>,
    sources: HashSet<String>,
    first_observed_at: Option<DateTime<Utc>>,
    last_observed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Default)]
struct ActorActivityAccumulator {
    event_count: u64,
    unresolved_event_count: u64,
    systems: HashMap<uuid::Uuid, u64>,
    destinations: HashSet<String>,
    sources: HashSet<String>,
    first_observed_at: Option<DateTime<Utc>>,
    last_observed_at: Option<DateTime<Utc>>,
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/analytics",
    params(("window" = Option<String>, Query, description = "Activity window: 24h, 7d, 30d, or all")),
    responses((status = 200, body = AnalyticsResponse))
)]
async fn analytics(
    axum::extract::State(state): axum::extract::State<AppState>,
    Query(query): Query<ActivityWindowQuery>,
) -> Result<Json<AnalyticsResponse>, ApiError> {
    let now = Utc::now();
    let since_millis = query
        .window
        .since(now)
        .map(|value| value.timestamp_millis());
    let (observations, observation_total, systems, evidence_edges) = tokio::join!(
        state
            .observations
            .list_observations_since(ANALYTICS_OBSERVATION_LIMIT, since_millis),
        state.observations.observation_count_since(since_millis),
        load_analytics_systems(&state.postgres),
        state.postgres.list_system_evidence_index(),
    );
    let observations = observations.map_err(ApiError::dependency)?;
    let observation_total = observation_total.map_err(ApiError::dependency)?;
    let (systems, system_total) = systems.map_err(ApiError::dependency)?;
    let evidence_edges = evidence_edges.map_err(ApiError::dependency)?;
    Ok(Json(build_analytics(
        &observations,
        observation_total,
        &systems,
        system_total,
        &evidence_edges,
        query.window,
        since_millis,
    )))
}

async fn load_analytics_systems(
    postgres: &PostgresStore,
) -> Result<(Vec<AiSystemView>, u64), PostgresStoreError> {
    const PAGE_SIZE: u16 = 200;
    let total = postgres.ai_system_count().await?;
    let mut systems = Vec::with_capacity(
        usize::try_from(total)
            .unwrap_or(ANALYTICS_SYSTEM_LIMIT)
            .min(ANALYTICS_SYSTEM_LIMIT),
    );
    while systems.len() < ANALYTICS_SYSTEM_LIMIT {
        let offset = u32::try_from(systems.len()).unwrap_or(u32::MAX);
        let page = postgres.list_ai_systems(PAGE_SIZE, offset).await?;
        let page_len = page.len();
        systems.extend(
            page.into_iter()
                .take(ANALYTICS_SYSTEM_LIMIT - systems.len()),
        );
        if page_len < usize::from(PAGE_SIZE) {
            break;
        }
    }
    Ok((systems, total))
}

fn build_analytics(
    observations: &[Observation],
    observation_total: u64,
    systems: &[AiSystemView],
    system_total: u64,
    evidence_edges: &[SystemEvidenceEdge],
    activity_window: ActivityWindow,
    window_start_millis: Option<i64>,
) -> AnalyticsResponse {
    let system_by_id = systems
        .iter()
        .map(|system| (system.system_id, system))
        .collect::<HashMap<_, _>>();
    let mut systems_by_observation = HashMap::<uuid::Uuid, BTreeSet<uuid::Uuid>>::new();
    for edge in evidence_edges {
        systems_by_observation
            .entry(edge.observation_id)
            .or_default()
            .insert(edge.system_id);
    }
    let mut service_activity = HashMap::<uuid::Uuid, ServiceAdoptionAccumulator>::new();
    let mut actor_activity = HashMap::<String, ActorActivityAccumulator>::new();
    for observation in observations {
        let actor_key = event_actor(observation);
        let source = observation.connector.connector_type.clone();
        let destination = event_destination(observation);
        let system_ids = systems_by_observation.get(&observation.observation_id);
        for system_id in system_ids.into_iter().flatten() {
            if !system_by_id.contains_key(system_id) {
                continue;
            }
            let activity = service_activity.entry(*system_id).or_default();
            activity.event_count = activity.event_count.saturating_add(1);
            activity.sources.insert(source.clone());
            if let Some(actor_key) = actor_key.as_ref() {
                activity.actors.insert(actor_key.clone());
            }
            update_activity_window(
                &mut activity.first_observed_at,
                &mut activity.last_observed_at,
                observation.observed_at,
            );
        }
        if let Some(actor_key) = actor_key {
            let activity = actor_activity.entry(actor_key).or_default();
            activity.event_count = activity.event_count.saturating_add(1);
            activity.sources.insert(source);
            if let Some(destination) = destination {
                activity.destinations.insert(destination);
            }
            if let Some(system_ids) = system_ids {
                for system_id in system_ids {
                    if system_by_id.contains_key(system_id) {
                        let count = activity.systems.entry(*system_id).or_default();
                        *count = count.saturating_add(1);
                    }
                }
            } else {
                activity.unresolved_event_count = activity.unresolved_event_count.saturating_add(1);
            }
            update_activity_window(
                &mut activity.first_observed_at,
                &mut activity.last_observed_at,
                observation.observed_at,
            );
        }
    }
    let service_rank = service_rank_responses(service_activity, &system_by_id);
    let actors = actor_activity_responses(actor_activity, &system_by_id);
    let first_observed_at = observations.iter().map(|item| item.observed_at).min();
    let last_observed_at = observations.iter().map(|item| item.observed_at).max();
    AnalyticsResponse {
        activity_window: activity_window.as_str(),
        window_start: window_start_millis.and_then(DateTime::from_timestamp_millis),
        observation_total,
        loaded_observations: observations.len(),
        observation_window_truncated: observation_total
            > u64::try_from(observations.len()).unwrap_or(u64::MAX),
        system_total,
        loaded_systems: systems.len(),
        system_window_truncated: system_total > u64::try_from(systems.len()).unwrap_or(u64::MAX),
        first_observed_at,
        last_observed_at,
        service_rank,
        authorization: AuthorizationDistributionResponse::from_systems(systems),
        actors,
        content_retained: false,
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum ActivityWindow {
    #[serde(rename = "24h")]
    Hours24,
    #[default]
    #[serde(rename = "7d")]
    Days7,
    #[serde(rename = "30d")]
    Days30,
    All,
}

impl ActivityWindow {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Hours24 => "24h",
            Self::Days7 => "7d",
            Self::Days30 => "30d",
            Self::All => "all",
        }
    }

    fn since(self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        match self {
            Self::Hours24 => Some(now - Duration::hours(24)),
            Self::Days7 => Some(now - Duration::days(7)),
            Self::Days30 => Some(now - Duration::days(30)),
            Self::All => None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ActivityWindowQuery {
    #[serde(default)]
    window: ActivityWindow,
}

fn service_rank_responses(
    activity: HashMap<uuid::Uuid, ServiceAdoptionAccumulator>,
    system_by_id: &HashMap<uuid::Uuid, &AiSystemView>,
) -> Vec<ServiceAdoptionResponse> {
    let mut responses = activity
        .into_iter()
        .filter_map(|(system_id, activity)| {
            let system = system_by_id.get(&system_id)?;
            Some(ServiceAdoptionResponse {
                system_id,
                display_name: system.display_name.clone(),
                authorization: enum_name(system.authorization, "discovered"),
                event_count: activity.event_count,
                unique_actor_count: activity.actors.len(),
                source_count: activity.sources.len(),
                first_observed_at: activity.first_observed_at?,
                last_observed_at: activity.last_observed_at?,
            })
        })
        .collect::<Vec<_>>();
    responses.sort_by(|left, right| {
        right
            .event_count
            .cmp(&left.event_count)
            .then_with(|| left.display_name.cmp(&right.display_name))
            .then_with(|| left.system_id.cmp(&right.system_id))
    });
    responses
}

fn actor_activity_responses(
    activity: HashMap<String, ActorActivityAccumulator>,
    system_by_id: &HashMap<uuid::Uuid, &AiSystemView>,
) -> Vec<ActorActivityResponse> {
    let mut responses = activity
        .into_iter()
        .filter_map(|(actor_key, activity)| {
            let mut actor_systems = activity
                .systems
                .into_iter()
                .filter_map(|(system_id, event_count)| {
                    system_by_id
                        .get(&system_id)
                        .map(|system| ActorSystemActivityResponse {
                            system_id,
                            display_name: system.display_name.clone(),
                            event_count,
                        })
                })
                .collect::<Vec<_>>();
            actor_systems.sort_by(|left, right| {
                right
                    .event_count
                    .cmp(&left.event_count)
                    .then_with(|| left.display_name.cmp(&right.display_name))
            });
            let mut sources = activity.sources.into_iter().collect::<Vec<_>>();
            sources.sort();
            Some(ActorActivityResponse {
                actor_key,
                event_count: activity.event_count,
                unresolved_event_count: activity.unresolved_event_count,
                system_count: actor_systems.len(),
                destination_count: activity.destinations.len(),
                sources,
                first_observed_at: activity.first_observed_at?,
                last_observed_at: activity.last_observed_at?,
                systems: actor_systems,
            })
        })
        .collect::<Vec<_>>();
    responses.sort_by(|left, right| {
        right
            .event_count
            .cmp(&left.event_count)
            .then_with(|| left.actor_key.cmp(&right.actor_key))
    });
    responses.truncate(100);
    responses
}

fn update_activity_window(
    first: &mut Option<DateTime<Utc>>,
    last: &mut Option<DateTime<Utc>>,
    observed_at: DateTime<Utc>,
) {
    if first.is_none_or(|value| observed_at < value) {
        *first = Some(observed_at);
    }
    if last.is_none_or(|value| observed_at > value) {
        *last = Some(observed_at);
    }
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
struct EventsQuery {
    #[serde(default = "default_event_limit")]
    limit: u16,
    cursor: Option<String>,
    #[serde(default)]
    window: ActivityWindow,
}

const fn default_event_limit() -> u16 {
    100
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/events",
    params(
        ("limit" = Option<u16>, Query, description = "Page size, clamped to 1..=200"),
        ("cursor" = Option<String>, Query, description = "Opaque newest-first event cursor"),
        ("window" = Option<String>, Query, description = "Activity window: 24h, 7d, 30d, or all")
    ),
    responses(
        (status = 200, body = DiscoveryEventsResponse),
        (status = 400, body = ProblemDetails)
    )
)]
async fn events(
    axum::extract::State(state): axum::extract::State<AppState>,
    Query(query): Query<EventsQuery>,
) -> Result<Json<DiscoveryEventsResponse>, ApiError> {
    let limit = query.limit.clamp(1, 200);
    let before = query
        .cursor
        .as_deref()
        .map(parse_event_cursor)
        .transpose()?;
    let since_millis = query
        .window
        .since(Utc::now())
        .map(|value| value.timestamp_millis());
    let (observations, observation_total, systems, evidence_edges, connectors) = tokio::join!(
        state
            .observations
            .list_recent_observations_since(limit, before, since_millis),
        state.observations.observation_count_since(since_millis),
        state.postgres.list_ai_systems(200, 0),
        state.postgres.list_system_evidence_index(),
        state.postgres.list_connector_labels(),
    );
    let observations = observations.map_err(ApiError::dependency)?;
    let observation_total = observation_total.map_err(ApiError::dependency)?;
    let system_by_id = systems
        .map_err(ApiError::dependency)?
        .into_iter()
        .map(|system| (system.system_id, system))
        .collect::<HashMap<_, _>>();
    let connector_by_id = connectors
        .map_err(ApiError::dependency)?
        .into_iter()
        .map(|connector| (connector.connector_instance_id, connector))
        .collect::<HashMap<_, _>>();
    let mut systems_by_observation = HashMap::<uuid::Uuid, BTreeSet<uuid::Uuid>>::new();
    for edge in evidence_edges.map_err(ApiError::dependency)? {
        systems_by_observation
            .entry(edge.observation_id)
            .or_default()
            .insert(edge.system_id);
    }

    let next_cursor = (observations.len() == usize::from(limit))
        .then(|| observations.last().map(event_cursor))
        .flatten();
    let items = observations
        .iter()
        .map(|observation| {
            event_response(
                observation,
                systems_by_observation.get(&observation.observation_id),
                &system_by_id,
                &connector_by_id,
            )
        })
        .collect::<Vec<_>>();
    let resolved_events = items.iter().filter(|item| !item.systems.is_empty()).count();
    let unique_systems = items
        .iter()
        .flat_map(|item| item.systems.iter().map(|system| system.system_id))
        .collect::<HashSet<_>>()
        .len();
    let unique_actors = items
        .iter()
        .filter_map(|item| item.actor.as_deref())
        .collect::<HashSet<_>>()
        .len();
    Ok(Json(DiscoveryEventsResponse {
        activity_window: query.window.as_str(),
        window_start: since_millis.and_then(DateTime::from_timestamp_millis),
        total: observation_total,
        page_size: items.len(),
        resolved_events,
        unresolved_events: items.len().saturating_sub(resolved_events),
        unique_systems,
        unique_actors,
        next_cursor,
        content_retained: false,
        items,
    }))
}

fn parse_event_cursor(value: &str) -> Result<(i64, uuid::Uuid), ApiError> {
    if value.len() > 80 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_event_cursor",
        ));
    }
    let (millis, observation_id) = value
        .split_once(':')
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "invalid_event_cursor"))?;
    let millis = millis
        .parse::<i64>()
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_event_cursor"))?;
    if millis < 0 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_event_cursor",
        ));
    }
    let observation_id = uuid::Uuid::parse_str(observation_id)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_event_cursor"))?;
    Ok((millis, observation_id))
}

fn event_cursor(observation: &Observation) -> String {
    format!(
        "{}:{}",
        observation.observed_at.timestamp_millis(),
        observation.observation_id
    )
}

fn event_response(
    observation: &Observation,
    system_ids: Option<&BTreeSet<uuid::Uuid>>,
    system_by_id: &HashMap<uuid::Uuid, AiSystemView>,
    connector_by_id: &HashMap<uuid::Uuid, ConnectorLabelView>,
) -> DiscoveryEventResponse {
    let systems = system_ids
        .into_iter()
        .flatten()
        .filter_map(|system_id| system_by_id.get(system_id))
        .map(|system| EventSystemResponse {
            system_id: system.system_id,
            display_name: system.display_name.clone(),
            surface: enum_name(system.surface, "unknown"),
            evidence_quality: enum_name(system.evidence_quality, "unknown"),
        })
        .collect();
    let (receipt_type, receipt_digest) = receipt_summary(&observation.source);
    // Resolved against the live connector table, so a deleted connector leaves the evidence
    // intact and every derived label null rather than showing a name that no longer exists.
    let connector = connector_by_id.get(&observation.connector.instance_id);
    DiscoveryEventResponse {
        observation_id: observation.observation_id,
        observed_at: observation.observed_at,
        received_at: observation.received_at,
        kind: enum_name(observation.kind, "unknown"),
        connector_instance_id: observation.connector.instance_id,
        connector_id: connector.map(|connector| connector.connector_instance_id),
        connector_friendly_name: connector
            .and_then(|connector| optional_friendly_name(&connector.friendly_name)),
        connector_display_name: connector.map(|connector| connector.display_name.clone()),
        connector_label: connector
            .map(|connector| connector_label(&connector.friendly_name, &connector.display_name)),
        source_type: observation.connector.connector_type.clone(),
        demo: is_demo_observation(observation),
        destination: event_destination(observation),
        actor: event_actor(observation),
        outcome: event_outcome(observation),
        receipt_type,
        receipt_digest,
        systems,
    }
}

fn is_demo_observation(observation: &Observation) -> bool {
    observation
        .connector
        .source_lineage_id
        .as_deref()
        .is_some_and(|lineage| lineage.starts_with("synthetic_demo_"))
}

fn event_destination(observation: &Observation) -> Option<String> {
    let mut destination = observation
        .destination
        .host
        .as_ref()
        .map(|host| host.as_str().to_owned())
        .or_else(|| {
            observation
                .destination
                .ip
                .as_ref()
                .map(|ip| ip.as_str().to_owned())
        })
        .or_else(|| observation.destination.cloud_resource_id.clone())
        .or_else(|| observation.cloud.resource_key.clone())
        .or_else(|| {
            observation
                .service
                .tls_server_name
                .as_ref()
                .map(|host| host.as_str().to_owned())
        })
        .or_else(|| observation.service.declared_model_id.clone());
    if let (Some(value), Some(port)) = (&mut destination, observation.destination.port) {
        value.push(':');
        value.push_str(&port.to_string());
    }
    destination
}

fn event_actor(observation: &Observation) -> Option<String> {
    observation
        .actor
        .identity
        .as_ref()
        .and_then(|identity| identity.email.clone())
        .or_else(|| observation.actor.hostname.clone())
        .or_else(|| {
            observation
                .actor
                .identity
                .as_ref()
                .map(|identity| identity.subject_key.clone())
        })
        .or_else(|| observation.actor.device_key.clone())
        .or_else(|| {
            observation
                .actor
                .source_ip
                .as_ref()
                .map(|ip| format!("ip:{}", ip.as_str()))
        })
}

fn event_outcome(observation: &Observation) -> Option<String> {
    [
        observation.outcome.action.as_deref(),
        observation.outcome.result.as_deref(),
        observation.outcome.response_code.as_deref(),
    ]
    .into_iter()
    .flatten()
    .next()
    .map(str::to_owned)
}

/// Projects the stored connector label, treating the empty string the column uses for "never
/// named" as the absence it is.
fn optional_friendly_name(friendly_name: &str) -> Option<String> {
    (!friendly_name.is_empty()).then(|| friendly_name.to_owned())
}

/// The label to show for a connector: the operator's name when they set one, the catalog label
/// for the connector type otherwise.
fn connector_label(friendly_name: &str, display_name: &str) -> String {
    if friendly_name.is_empty() {
        display_name.to_owned()
    } else {
        friendly_name.to_owned()
    }
}

fn receipt_summary(receipt: &EvidenceReceipt) -> (String, Option<String>) {
    match receipt {
        EvidenceReceipt::ExternalPointer { .. } => ("external_pointer".to_owned(), None),
        EvidenceReceipt::RecordDigest { digest, .. } => {
            ("record_digest".to_owned(), Some(digest.clone()))
        }
        EvidenceReceipt::CheckpointDigest {
            canonical_record_digest,
            ..
        } => (
            "checkpoint_digest".to_owned(),
            Some(canonical_record_digest.clone()),
        ),
        EvidenceReceipt::ScannerTranscriptDigest {
            transcript_digest, ..
        } => (
            "scanner_transcript_digest".to_owned(),
            Some(transcript_digest.clone()),
        ),
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct SystemsQuery {
    #[serde(default = "default_system_limit")]
    limit: u16,
    #[serde(default)]
    offset: u32,
}

const fn default_system_limit() -> u16 {
    50
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/systems",
    params(
        ("limit" = Option<u16>, Query, description = "Page size, clamped to 1..=200"),
        ("offset" = Option<u32>, Query, description = "Zero-based offset")
    ),
    responses((status = 200, body = SystemsResponse))
)]
async fn systems(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Query(query): axum::extract::Query<SystemsQuery>,
) -> Result<Json<SystemsResponse>, StatusCode> {
    let (items, total) = tokio::join!(
        state.postgres.list_ai_systems(query.limit, query.offset),
        state.postgres.ai_system_count()
    );
    Ok(Json(SystemsResponse {
        items: items.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        total: total.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/systems/{system_id}",
    params(("system_id" = uuid::Uuid, Path, description = "Stable AI-system identifier")),
    responses(
        (status = 200, body = tally_core::AiSystemView),
        (status = 404, body = ProblemDetails)
    )
)]
async fn system(
    axum::extract::State(state): axum::extract::State<AppState>,
    Path(system_id): Path<uuid::Uuid>,
) -> Result<(HeaderMap, Json<AiSystemView>), ApiError> {
    let system = state
        .postgres
        .get_ai_system(system_id)
        .await
        .map_err(ApiError::dependency)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "system_not_found"))?;
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::ETAG,
        HeaderValue::from_str(&format!("\"{}\"", system.revision))
            .map_err(|_| ApiError::dependency_message("invalid_system_revision"))?,
    );
    Ok((headers, Json(system)))
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/systems/{system_id}/evidence",
    params(("system_id" = uuid::Uuid, Path, description = "Stable AI-system identifier")),
    responses(
        (status = 200, body = SystemEvidenceResponse),
        (status = 404, body = ProblemDetails)
    )
)]
async fn system_evidence(
    axum::extract::State(state): axum::extract::State<AppState>,
    Path(system_id): Path<uuid::Uuid>,
) -> Result<Json<SystemEvidenceResponse>, ApiError> {
    if state
        .postgres
        .get_ai_system(system_id)
        .await
        .map_err(ApiError::dependency)?
        .is_none()
    {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "system_not_found"));
    }
    let links = state
        .postgres
        .list_system_evidence(system_id)
        .await
        .map_err(ApiError::dependency)?;
    let mut claims = Vec::with_capacity(links.len());
    let mut observation_ids = HashSet::new();
    let mut source_ids = HashSet::new();
    let mut registry_versions = BTreeSet::new();
    for link in links {
        if let Some(version) = &link.claim.registry_version {
            registry_versions.insert(version.clone());
        }
        let mut observations = Vec::with_capacity(link.observation_ids.len());
        for observation_id in link.observation_ids {
            if let Some(observation) = state
                .observations
                .get_observation(observation_id)
                .await
                .map_err(ApiError::dependency)?
            {
                observation_ids.insert(observation.observation_id);
                source_ids.insert(observation.connector.instance_id);
                observations.push(observation);
            }
        }
        claims.push(EvidenceClaimResponse {
            claim: link.claim,
            observations,
        });
    }
    Ok(Json(SystemEvidenceResponse {
        system_id,
        claim_count: claims.len(),
        observation_count: observation_ids.len(),
        independent_source_count: source_ids.len(),
        registry_versions: registry_versions.into_iter().collect(),
        content_retained: false,
        claims,
    }))
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct AttributionConflictsQuery {
    #[serde(default)]
    status: Option<AttributionConflictStatus>,
    #[serde(default = "default_system_limit")]
    limit: u16,
    #[serde(default)]
    offset: u32,
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/attribution/conflicts",
    params(
        ("status" = Option<AttributionConflictStatus>, Query, description = "Optional open or cleared status"),
        ("limit" = Option<u16>, Query, description = "Page size, clamped to 1..=500"),
        ("offset" = Option<u32>, Query, description = "Zero-based offset")
    ),
    responses((status = 200, body = AttributionConflictsResponse))
)]
async fn attribution_conflicts(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Query(query): axum::extract::Query<AttributionConflictsQuery>,
) -> Result<Json<AttributionConflictsResponse>, ApiError> {
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    let (items, total) = tokio::join!(
        state.postgres.list_attribution_conflicts(
            identity.installation_id,
            query.status,
            query.limit,
            query.offset,
        ),
        state
            .postgres
            .attribution_conflict_count(identity.installation_id, query.status)
    );
    Ok(Json(AttributionConflictsResponse {
        total: total.map_err(ApiError::dependency)?,
        items: items.map_err(ApiError::dependency)?,
        content_retained: false,
    }))
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct EntitiesQuery {
    #[serde(default)]
    kind: Option<EntityKind>,
    #[serde(default = "default_system_limit")]
    limit: u16,
    #[serde(default)]
    offset: u32,
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/entities",
    params(
        ("kind" = Option<EntityKind>, Query, description = "Optional Tally entity kind"),
        ("limit" = Option<u16>, Query, description = "Page size, clamped to 1..=500"),
        ("offset" = Option<u32>, Query, description = "Zero-based offset")
    ),
    responses((status = 200, body = EntitiesResponse))
)]
async fn entities(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Query(query): axum::extract::Query<EntitiesQuery>,
) -> Result<Json<EntitiesResponse>, ApiError> {
    let installation_id = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?
        .installation_id;
    let (items, total) = tokio::join!(
        state
            .postgres
            .list_entities(installation_id, query.kind, query.limit, query.offset),
        state.postgres.entity_count(installation_id, query.kind)
    );
    Ok(Json(EntitiesResponse {
        total: total.map_err(ApiError::dependency)?,
        items: items.map_err(ApiError::dependency)?,
        content_retained: false,
    }))
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct RelationshipsQuery {
    #[serde(default)]
    adjacent_to: Option<uuid::Uuid>,
    #[serde(default = "default_system_limit")]
    limit: u16,
    #[serde(default)]
    offset: u32,
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/relationships",
    params(
        ("adjacent_to" = Option<uuid::Uuid>, Query, description = "Optional adjacent entity identifier"),
        ("limit" = Option<u16>, Query, description = "Page size, clamped to 1..=500"),
        ("offset" = Option<u32>, Query, description = "Zero-based offset")
    ),
    responses((status = 200, body = RelationshipsResponse))
)]
async fn relationships(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Query(query): axum::extract::Query<RelationshipsQuery>,
) -> Result<Json<RelationshipsResponse>, ApiError> {
    let installation_id = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?
        .installation_id;
    let (items, total) = tokio::join!(
        state.postgres.list_entity_relationships(
            installation_id,
            query.adjacent_to,
            query.limit,
            query.offset,
        ),
        state
            .postgres
            .entity_relationship_count(installation_id, query.adjacent_to)
    );
    Ok(Json(RelationshipsResponse {
        total: total.map_err(ApiError::dependency)?,
        items: items.map_err(ApiError::dependency)?,
        content_retained: false,
    }))
}

const MAX_GRAPH_DEPTH: u8 = 4;
const MAX_GRAPH_NODES: u16 = 100;
const MAX_GRAPH_EDGES: u16 = 250;

const fn default_graph_depth() -> u8 {
    2
}

const fn default_graph_node_limit() -> u16 {
    MAX_GRAPH_NODES
}

const fn default_graph_edge_limit() -> u16 {
    MAX_GRAPH_EDGES
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct SystemGraphQuery {
    #[serde(default = "default_graph_depth")]
    depth: u8,
    #[serde(default = "default_graph_node_limit")]
    node_limit: u16,
    #[serde(default = "default_graph_edge_limit")]
    edge_limit: u16,
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/systems/{system_id}/graph",
    params(
        ("system_id" = uuid::Uuid, Path, description = "Stable AI-system identifier"),
        ("depth" = Option<u8>, Query, description = "Traversal depth, clamped to 1..=4"),
        ("node_limit" = Option<u16>, Query, description = "Node cap, clamped to 1..=100"),
        ("edge_limit" = Option<u16>, Query, description = "Relationship cap, clamped to 1..=250")
    ),
    responses(
        (status = 200, body = SystemGraphResponse),
        (status = 404, body = ProblemDetails)
    )
)]
async fn system_graph(
    axum::extract::State(state): axum::extract::State<AppState>,
    Path(system_id): Path<uuid::Uuid>,
    axum::extract::Query(query): axum::extract::Query<SystemGraphQuery>,
) -> Result<Json<SystemGraphResponse>, ApiError> {
    let installation_id = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?
        .installation_id;
    let root = state
        .postgres
        .get_scoped_entities(installation_id, &[system_id])
        .await
        .map_err(ApiError::dependency)?;
    if root
        .first()
        .is_none_or(|entity| entity.kind != EntityKind::AiSystem)
    {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "system_not_found"));
    }

    let depth = query.depth.clamp(1, MAX_GRAPH_DEPTH);
    let node_limit = usize::from(query.node_limit.clamp(1, MAX_GRAPH_NODES));
    let edge_limit = usize::from(query.edge_limit.clamp(1, MAX_GRAPH_EDGES));
    let mut node_depths = HashMap::from([(system_id, 0_u8)]);
    let mut frontier = vec![system_id];
    let mut graph_relationships = BTreeMap::new();
    let mut truncated = false;

    for next_depth in 1..=depth {
        if frontier.is_empty() || graph_relationships.len() >= edge_limit {
            truncated |= graph_relationships.len() >= edge_limit;
            break;
        }
        let page = state
            .postgres
            .list_graph_relationships(installation_id, &frontier, 501)
            .await
            .map_err(ApiError::dependency)?;
        truncated |= page.len() == 501;
        let mut next_frontier = BTreeSet::new();
        for item in page {
            let relationship_id = item.relationship.relationship_id;
            if graph_relationships.contains_key(&relationship_id) {
                continue;
            }
            let endpoints = [
                item.relationship.subject.entity_id,
                item.relationship.object.entity_id,
            ];
            let missing = endpoints
                .into_iter()
                .filter(|entity_id| !node_depths.contains_key(entity_id))
                .collect::<BTreeSet<_>>();
            if node_depths.len().saturating_add(missing.len()) > node_limit {
                truncated = true;
                continue;
            }
            if graph_relationships.len() >= edge_limit {
                truncated = true;
                break;
            }
            for entity_id in missing {
                node_depths.insert(entity_id, next_depth);
                next_frontier.insert(entity_id);
            }
            graph_relationships.insert(relationship_id, item);
        }
        frontier = next_frontier.into_iter().collect();
    }

    let entity_ids = node_depths.keys().copied().collect::<Vec<_>>();
    let entities = state
        .postgres
        .get_scoped_entities(installation_id, &entity_ids)
        .await
        .map_err(ApiError::dependency)?;
    if entities.len() != node_depths.len() {
        return Err(ApiError::dependency_message(
            "graph_entity_projection_incomplete",
        ));
    }
    let mut nodes = entities
        .into_iter()
        .map(|entity| GraphNodeResponse {
            depth: node_depths[&entity.entity_id],
            entity,
        })
        .collect::<Vec<_>>();
    nodes.sort_by_key(|node| (node.depth, node.entity.entity_id));

    Ok(Json(SystemGraphResponse {
        root_entity_id: system_id,
        requested_depth: depth,
        nodes,
        relationships: graph_relationships
            .into_values()
            .map(|item| GraphRelationshipResponse {
                relationship: item.relationship,
                evidence_count: item.evidence_count,
            })
            .collect(),
        truncated,
        content_retained: false,
    }))
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct EntityResolutionEventsQuery {
    #[serde(default = "default_system_limit")]
    limit: u16,
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/resolution/events",
    params(("limit" = Option<u16>, Query, description = "Recent event cap, clamped to 1..=200")),
    responses((status = 200, body = EntityResolutionEventsResponse))
)]
async fn entity_resolution_events(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Query(query): axum::extract::Query<EntityResolutionEventsQuery>,
) -> Result<Json<EntityResolutionEventsResponse>, ApiError> {
    let installation_id = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?
        .installation_id;
    let events = state
        .postgres
        .list_entity_resolution_events(installation_id, query.limit)
        .await
        .map_err(ApiError::dependency)?
        .into_iter()
        .map(entity_resolution_event_response)
        .collect();
    Ok(Json(EntityResolutionEventsResponse {
        events,
        content_retained: false,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/resolution/merge/preview",
    request_body = EntityMergePreviewRequest,
    responses(
        (status = 200, body = EntityResolutionPreviewResponse),
        (status = 404, body = ProblemDetails),
        (status = 409, body = ProblemDetails),
        (status = 422, body = ProblemDetails)
    )
)]
async fn preview_entity_merge(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(request): Json<EntityMergePreviewRequest>,
) -> Result<Json<EntityResolutionPreviewResponse>, ApiError> {
    let installation_id = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?
        .installation_id;
    let preview = state
        .postgres
        .preview_entity_merge(
            installation_id,
            request.source_entity_id,
            request.target_entity_id,
            request.source_revision,
            request.target_revision,
        )
        .await
        .map_err(ApiError::from_store)?;
    Ok(Json(entity_resolution_preview_response(preview)))
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/resolution/merge",
    request_body = EntityMergeCommitRequest,
    responses(
        (status = 201, body = EntityResolutionCommitResponse),
        (status = 200, body = EntityResolutionCommitResponse),
        (status = 400, body = ProblemDetails),
        (status = 404, body = ProblemDetails),
        (status = 409, body = ProblemDetails),
        (status = 422, body = ProblemDetails)
    )
)]
async fn commit_entity_merge(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    Json(request): Json<EntityMergeCommitRequest>,
) -> Result<(StatusCode, Json<EntityResolutionCommitResponse>), ApiError> {
    if !request.acknowledge_evidence_preserved {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "resolution_evidence_acknowledgement_required",
        ));
    }
    let idempotency_key = parse_idempotency_key(&headers)?;
    let request_sha256 = hex::encode(Sha256::digest(
        serde_json::to_vec(&("merge", &request)).map_err(ApiError::dependency)?,
    ));
    let installation_id = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?
        .installation_id;
    let write = state
        .postgres
        .commit_entity_resolution(&EntityResolutionCommit {
            installation_id,
            operation: EntityResolutionOperation::Merge,
            source_entity_id: request.source_entity_id,
            target_entity_id: request.target_entity_id,
            source_revision: request.source_revision,
            target_revision: request.target_revision,
            merge_event_id: None,
            preview_digest: request.confirm_preview_digest,
            request_sha256,
            idempotency_key,
            created_at: Utc::now(),
        })
        .await
        .map_err(ApiError::from_store)?;
    let response = entity_resolution_commit_response(write.event, write.replayed);
    Ok((
        if response.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(response),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/resolution/split/preview",
    request_body = EntitySplitPreviewRequest,
    responses(
        (status = 200, body = EntityResolutionPreviewResponse),
        (status = 404, body = ProblemDetails),
        (status = 409, body = ProblemDetails),
        (status = 422, body = ProblemDetails)
    )
)]
async fn preview_entity_split(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(request): Json<EntitySplitPreviewRequest>,
) -> Result<Json<EntityResolutionPreviewResponse>, ApiError> {
    let installation_id = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?
        .installation_id;
    let preview = state
        .postgres
        .preview_entity_split(
            installation_id,
            request.source_entity_id,
            request.target_entity_id,
            request.source_revision,
            request.target_revision,
            request.merge_event_id,
        )
        .await
        .map_err(ApiError::from_store)?;
    Ok(Json(entity_resolution_preview_response(preview)))
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/resolution/split",
    request_body = EntitySplitCommitRequest,
    responses(
        (status = 201, body = EntityResolutionCommitResponse),
        (status = 200, body = EntityResolutionCommitResponse),
        (status = 400, body = ProblemDetails),
        (status = 404, body = ProblemDetails),
        (status = 409, body = ProblemDetails),
        (status = 422, body = ProblemDetails)
    )
)]
async fn commit_entity_split(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    Json(request): Json<EntitySplitCommitRequest>,
) -> Result<(StatusCode, Json<EntityResolutionCommitResponse>), ApiError> {
    if !request.acknowledge_evidence_preserved {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "resolution_evidence_acknowledgement_required",
        ));
    }
    let idempotency_key = parse_idempotency_key(&headers)?;
    let request_sha256 = hex::encode(Sha256::digest(
        serde_json::to_vec(&("split", &request)).map_err(ApiError::dependency)?,
    ));
    let installation_id = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?
        .installation_id;
    let write = state
        .postgres
        .commit_entity_resolution(&EntityResolutionCommit {
            installation_id,
            operation: EntityResolutionOperation::Split,
            source_entity_id: request.source_entity_id,
            target_entity_id: request.target_entity_id,
            source_revision: request.source_revision,
            target_revision: request.target_revision,
            merge_event_id: Some(request.merge_event_id),
            preview_digest: request.confirm_preview_digest,
            request_sha256,
            idempotency_key,
            created_at: Utc::now(),
        })
        .await
        .map_err(ApiError::from_store)?;
    let response = entity_resolution_commit_response(write.event, write.replayed);
    Ok((
        if response.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(response),
    ))
}

fn entity_resolution_preview_response(
    preview: EntityResolutionPreviewData,
) -> EntityResolutionPreviewResponse {
    EntityResolutionPreviewResponse {
        operation: enum_name(preview.operation, "merge"),
        source: preview.source,
        target: preview.target,
        merge_event_id: preview.merge_event_id,
        impact: EntityResolutionImpactResponse::from(preview.impact),
        preview_digest: preview.preview_digest,
        evidence_mutated: false,
        content_retained: false,
    }
}

fn entity_resolution_commit_response(
    event: EntityResolutionEventView,
    replayed: bool,
) -> EntityResolutionCommitResponse {
    let canonical_entity_id = match event.operation {
        EntityResolutionOperation::Merge => event.target_entity_id,
        EntityResolutionOperation::Split => event.source_entity_id,
    };
    EntityResolutionCommitResponse {
        event: entity_resolution_event_response(event),
        canonical_entity_id,
        replayed,
        evidence_mutated: false,
        content_retained: false,
    }
}

fn entity_resolution_event_response(
    event: EntityResolutionEventView,
) -> EntityResolutionEventResponse {
    EntityResolutionEventResponse {
        event_id: event.event_id,
        operation: enum_name(event.operation, "merge"),
        source_entity_id: event.source_entity_id,
        target_entity_id: event.target_entity_id,
        source_display_name: event.source_display_name,
        target_display_name: event.target_display_name,
        merge_event_id: event.merge_event_id,
        source_revision: event.source_revision,
        target_revision: event.target_revision,
        source_current_revision: event.source_current_revision,
        target_current_revision: event.target_current_revision,
        active: event.active,
        preview_digest: event.preview_digest,
        created_at: event.created_at,
        created_by: event.created_by,
        content_retained: event.content_retained,
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/systems/{system_id}/authorization",
    params(("system_id" = uuid::Uuid, Path, description = "Stable AI-system identifier")),
    request_body = AuthorizationRequestBody,
    responses(
        (status = 200, body = AuthorizationResponse),
        (status = 400, body = ProblemDetails),
        (status = 404, body = ProblemDetails),
        (status = 409, body = ProblemDetails),
        (status = 422, body = ProblemDetails),
        (status = 428, body = ProblemDetails)
    )
)]
async fn transition_authorization(
    axum::extract::State(state): axum::extract::State<AppState>,
    Path(system_id): Path<uuid::Uuid>,
    headers: HeaderMap,
    Json(body): Json<AuthorizationRequestBody>,
) -> Result<(HeaderMap, Json<AuthorizationResponse>), ApiError> {
    let if_match = headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_etag_revision)
        .ok_or_else(|| ApiError::new(StatusCode::PRECONDITION_REQUIRED, "if_match_required"))?;
    if if_match != body.expected_revision {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "if_match_revision_mismatch",
        ));
    }
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "idempotency_key_required"))?;
    let result = state
        .postgres
        .transition_authorization(&AuthorizationTransitionRequest {
            system_id,
            expected_revision: body.expected_revision,
            to_status: body.to_status,
            reason_code: body.reason_code.into(),
            idempotency_key,
        })
        .await
        .map_err(ApiError::from_store)?;

    let evidence = state
        .postgres
        .list_system_evidence(system_id)
        .await
        .map_err(ApiError::dependency)?;
    let mut source_ids = HashSet::new();
    for observation_id in evidence
        .iter()
        .flat_map(|link| link.observation_ids.iter().copied())
    {
        if let Some(observation) = state
            .observations
            .get_observation(observation_id)
            .await
            .map_err(ApiError::dependency)?
        {
            source_ids.insert(observation.connector.instance_id);
        }
    }
    let system = state
        .postgres
        .get_ai_system(system_id)
        .await
        .map_err(ApiError::dependency)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "system_not_found"))?;
    let source_count = u32::try_from(source_ids.len()).unwrap_or(u32::MAX);
    let evaluated_at = Utc::now();
    let findings = evaluate_baseline(&PolicyEvaluationInput {
        system: &system,
        evidence_source_count: source_count,
        evaluated_at,
    });
    state
        .postgres
        .replace_system_findings(
            &system,
            BASELINE_POLICY_ID,
            BASELINE_POLICY_VERSION,
            source_count,
            evaluated_at,
            &findings,
        )
        .await
        .map_err(ApiError::dependency)?;
    let system = state
        .postgres
        .get_ai_system(system_id)
        .await
        .map_err(ApiError::dependency)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "system_not_found"))?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        axum::http::header::ETAG,
        HeaderValue::from_str(&format!("\"{}\"", system.revision))
            .map_err(|_| ApiError::dependency_message("invalid_system_revision"))?,
    );
    Ok((
        response_headers,
        Json(AuthorizationResponse {
            replayed: result.replayed,
            transition_id: result.transition.transition_id,
            authorization: system.authorization,
            revision: system.revision,
            findings: system.findings,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/connectors",
    responses((status = 200, body = ConnectorStatesResponse))
)]
async fn connectors(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<ConnectorStatesResponse>, ApiError> {
    let (states, jobs) = tokio::join!(
        state.postgres.list_connector_states(),
        state.postgres.list_connector_jobs()
    );
    let samples = sample_data::connector_ids(&state).await?;
    let items = states
        .map_err(ApiError::dependency)?
        .into_iter()
        .map(|value| {
            let mut response = ConnectorStateResponse::from(value);
            response.sample = samples.contains(&response.connector_instance_id);
            response
        })
        .collect();
    let jobs = jobs
        .map_err(ApiError::dependency)?
        .into_iter()
        .map(ConnectorJobResponse::from)
        .collect();
    Ok(Json(ConnectorStatesResponse { items, jobs }))
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/connectors/{connector_instance_id}/configuration",
    params(("connector_instance_id" = uuid::Uuid, Path, description = "Connector instance ID")),
    responses(
        (status = 200, body = ConnectorConfigurationResponse),
        (status = 404, body = ProblemDetails)
    )
)]
async fn connector_configuration(
    axum::extract::State(state): axum::extract::State<AppState>,
    Path(connector_instance_id): Path<uuid::Uuid>,
) -> Result<Json<ConnectorConfigurationResponse>, ApiError> {
    let job = state
        .postgres
        .connector_job_edit_view(connector_instance_id)
        .await
        .map_err(ApiError::dependency)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "connector_not_found"))?;
    let (credentials, credential_reentry_required) =
        match unseal_connector_credentials(&state.secret_cipher, job.credentials.as_ref()) {
            Ok(credentials) => (credentials, false),
            Err(_) => (BTreeMap::new(), true),
        };
    Ok(Json(ConnectorConfigurationResponse {
        fields: connector_form_configuration(&job.config_refs, &credentials),
        credential_reentry_required,
    }))
}

const MAX_INTEGRATION_PAGE_SIZE: u16 = 50;
const MAX_INTEGRATION_CONNECTORS: usize = 500;
const MAX_INTEGRATION_EVIDENCE_PER_SYSTEM: u16 = 128;
const MAX_INTEGRATION_EVIDENCE_PER_RESPONSE: usize = 512;

#[utoipa::path(
    get,
    path = "/api/v1/tally/integration/inventory",
    params(
        ("limit" = Option<u16>, Query, description = "Page size, clamped to 1..=50"),
        ("offset" = Option<u32>, Query, description = "Zero-based offset")
    ),
    responses((status = 200, body = IntegrationInventoryResponse))
)]
async fn integration_inventory(
    axum::extract::State(state): axum::extract::State<AppState>,
    Query(query): Query<SystemsQuery>,
) -> Result<Json<IntegrationInventoryResponse>, ApiError> {
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    let limit = query.limit.clamp(1, MAX_INTEGRATION_PAGE_SIZE);
    let (systems, total) = tokio::join!(
        state.postgres.list_ai_systems(limit, query.offset),
        state.postgres.ai_system_count(),
    );
    let systems = systems.map_err(ApiError::dependency)?;
    let total = total.map_err(ApiError::dependency)?;
    let system_ids = systems
        .iter()
        .map(|system| system.system_id)
        .collect::<Vec<_>>();
    let (relationships, relationships_may_be_truncated) =
        contribution_relationships_by_system(&state, &system_ids).await?;
    let (evidence, evidence_may_be_truncated) =
        contribution_evidence_by_system(&state, &system_ids).await?;
    let items = systems
        .into_iter()
        .map(|system| {
            let system_id = system.system_id;
            let contribution = InventoryContribution {
                schema_version: INTEGRATION_SCHEMA_VERSION.to_owned(),
                producer: ContributionProducer::GodelTally,
                contribution_id: uuid::Uuid::new_v5(
                    &uuid::Uuid::NAMESPACE_URL,
                    format!(
                        "godel-tally:inventory-contribution:{system_id}:{}",
                        system.revision
                    )
                    .as_bytes(),
                ),
                installation_id: identity.installation_id,
                entity: EntityRef {
                    entity_id: system_id,
                    kind: EntityKind::AiSystem,
                },
                display_label: system.display_name,
                surface: system.surface,
                lifecycle: system.lifecycle,
                authorization: system.authorization,
                evidence_quality: system.evidence_quality,
                confidence: system.confidence,
                first_seen: system.first_seen,
                last_seen: system.last_seen,
                relationships: relationships.get(&system_id).cloned().unwrap_or_default(),
                evidence: evidence.get(&system_id).cloned().unwrap_or_default(),
                resource_path: format!("/api/v1/tally/systems/{system_id}"),
                revision: system.revision,
            };
            contribution
                .validate()
                .map_err(|_| ApiError::dependency_message("integration_projection_invalid"))?;
            Ok(contribution)
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(IntegrationInventoryResponse {
        schema_version: INTEGRATION_SCHEMA_VERSION.to_owned(),
        items,
        total,
        relationships_may_be_truncated,
        evidence_may_be_truncated,
        content_retained: false,
    }))
}

async fn contribution_relationships_by_system(
    state: &AppState,
    system_ids: &[uuid::Uuid],
) -> Result<(HashMap<uuid::Uuid, Vec<InventoryRelationshipSummary>>, bool), ApiError> {
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    let mut result = HashMap::new();
    let mut may_be_truncated = false;
    for system_id in system_ids {
        let relationships = state
            .postgres
            .list_entity_relationships(
                identity.installation_id,
                Some(*system_id),
                MAX_INTEGRATION_EVIDENCE_PER_SYSTEM,
                0,
            )
            .await
            .map_err(ApiError::dependency)?;
        may_be_truncated |= relationships.len() == usize::from(MAX_INTEGRATION_EVIDENCE_PER_SYSTEM);
        result.insert(
            *system_id,
            relationships
                .into_iter()
                .filter(|relationship| {
                    relationship.status == tally_core::RelationshipStatus::Active
                })
                .map(|relationship| inventory_relationship_summary(&relationship))
                .collect(),
        );
    }
    Ok((result, may_be_truncated))
}

fn inventory_relationship_summary(
    relationship: &EntityRelationship,
) -> InventoryRelationshipSummary {
    InventoryRelationshipSummary {
        relationship_id: relationship.relationship_id,
        subject: relationship.subject,
        predicate: relationship.predicate,
        object: relationship.object,
        confidence: relationship.confidence,
        valid_from: relationship.valid_from,
        valid_until: relationship.valid_until,
        revision: relationship.revision,
    }
}

async fn contribution_evidence_by_system(
    state: &AppState,
    system_ids: &[uuid::Uuid],
) -> Result<(HashMap<uuid::Uuid, Vec<EvidenceLinkContribution>>, bool), ApiError> {
    let mut result = HashMap::new();
    let mut emitted = 0_usize;
    let mut may_be_truncated = false;
    for system_id in system_ids {
        let claims = state
            .postgres
            .list_system_evidence(*system_id)
            .await
            .map_err(ApiError::dependency)?;
        let mut seen = HashSet::new();
        let mut links = Vec::new();
        for observation_id in claims
            .into_iter()
            .flat_map(|claim| claim.observation_ids.into_iter())
        {
            if !seen.insert(observation_id) {
                continue;
            }
            if links.len() == usize::from(MAX_INTEGRATION_EVIDENCE_PER_SYSTEM)
                || emitted == MAX_INTEGRATION_EVIDENCE_PER_RESPONSE
            {
                may_be_truncated = true;
                break;
            }
            if let Some(observation) = state
                .observations
                .get_observation(observation_id)
                .await
                .map_err(ApiError::dependency)?
            {
                links.push(evidence_link_contribution(
                    &observation,
                    &format!("/api/v1/tally/systems/{system_id}/evidence"),
                )?);
                emitted += 1;
            }
        }
        result.insert(*system_id, links);
    }
    Ok((result, may_be_truncated))
}

fn evidence_link_contribution(
    observation: &Observation,
    resource_path: &str,
) -> Result<EvidenceLinkContribution, ApiError> {
    let receipt = serde_json::to_vec(&observation.source).map_err(ApiError::dependency)?;
    let link = EvidenceLinkContribution {
        schema_version: INTEGRATION_SCHEMA_VERSION.to_owned(),
        producer: ContributionProducer::GodelTally,
        evidence_id: uuid::Uuid::new_v5(
            &uuid::Uuid::NAMESPACE_URL,
            format!("godel-tally:evidence-link:{}", observation.observation_id).as_bytes(),
        ),
        observation_id: observation.observation_id,
        source_kind: enum_name(observation.kind, "unknown"),
        receipt_sha256: hex::encode(Sha256::digest(receipt)),
        observed_at: observation.observed_at,
        availability: EvidenceAvailability::Dereferenceable,
        resource_path: resource_path.to_owned(),
    };
    link.validate()
        .map_err(|_| ApiError::dependency_message("integration_projection_invalid"))?;
    Ok(link)
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/integration/connectors",
    responses((status = 200, body = IntegrationConnectorsResponse))
)]
async fn integration_connectors(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<IntegrationConnectorsResponse>, ApiError> {
    let states = state
        .postgres
        .list_connector_states()
        .await
        .map_err(ApiError::dependency)?;
    let truncated = states.len() > MAX_INTEGRATION_CONNECTORS;
    let items = states
        .into_iter()
        .take(MAX_INTEGRATION_CONNECTORS)
        .map(|connector| connector_contribution(&connector, state.started_at))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(IntegrationConnectorsResponse {
        schema_version: INTEGRATION_SCHEMA_VERSION.to_owned(),
        items,
        truncated,
        content_retained: false,
    }))
}

fn connector_contribution(
    connector: &ConnectorStateView,
    fallback_at: DateTime<Utc>,
) -> Result<ConnectorContribution, ApiError> {
    let updated_at = [
        connector.last_poll_at,
        connector.last_success_at,
        connector.last_source_at,
    ]
    .into_iter()
    .flatten()
    .max()
    .unwrap_or(fallback_at);
    let contribution = ConnectorContribution {
        schema_version: INTEGRATION_SCHEMA_VERSION.to_owned(),
        producer: ContributionProducer::GodelTally,
        connector_id: connector.connector_instance_id.to_string(),
        connector_type: connector.connector_type.clone(),
        display_label: connector_label(&connector.friendly_name, &connector.display_name),
        source_family: connector_source_family(&connector.connector_type)?,
        health: match connector.health {
            ConnectorHealth::NeverRun => ContributionConnectorHealth::Unknown,
            ConnectorHealth::Healthy => ContributionConnectorHealth::Healthy,
            ConnectorHealth::Delayed => ContributionConnectorHealth::Stale,
            ConnectorHealth::Error => ContributionConnectorHealth::Error,
            ConnectorHealth::Paused => ContributionConnectorHealth::Paused,
        },
        capabilities: vec![ConnectorManagementCapability::View],
        setup_schema_path: "/api/v1/tally/connectors".to_owned(),
        permission_manifest_path: "/api/v1/tally/connectors".to_owned(),
        resource_path: "/api/v1/tally/connectors".to_owned(),
        updated_at,
        revision: updated_at.timestamp_millis().max(1),
    };
    contribution
        .validate()
        .map_err(|_| ApiError::dependency_message("integration_projection_invalid"))?;
    Ok(contribution)
}

fn connector_source_family(connector_type: &str) -> Result<ConnectorSourceFamily, ApiError> {
    let family = if connector_type.contains("network_mapping") {
        ConnectorSourceFamily::CloudResourceMapping
    } else if connector_type.contains("_flow_") {
        ConnectorSourceFamily::CloudFlow
    } else if connector_type.contains("managed_ai")
        || connector_type.contains("vertex_ai")
        || connector_type.contains("azure_openai")
        || connector_type.contains("foundry")
    {
        ConnectorSourceFamily::ManagedCloud
    } else if connector_type.contains("nextdns") || connector_type.contains("generic_dns") {
        ConnectorSourceFamily::Dns
    } else if connector_type.contains("cloudflare_gateway")
        || connector_type.contains("crowdstrike_edr")
        || connector_type.contains("rapid7_edr")
        || connector_type.contains("netskope_events")
        || connector_type.contains("zscaler")
        || connector_type.contains("palo_alto")
    {
        ConnectorSourceFamily::SecureWebGateway
    } else if connector_type.contains("scanner") {
        ConnectorSourceFamily::NetworkScanner
    } else if connector_type.contains("kubernetes") {
        ConnectorSourceFamily::KubernetesApi
    } else if connector_type.contains("casb") {
        ConnectorSourceFamily::CasbCapability
    } else if connector_type.contains("litellm") || connector_type.contains("ai_gateway") {
        ConnectorSourceFamily::AiGateway
    } else if connector_type.contains("file") || connector_type.contains("fixture") {
        ConnectorSourceFamily::FileImport
    } else {
        return Err(ApiError::dependency_message(
            "integration_connector_family_unknown",
        ));
    };
    Ok(family)
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct IntegrationLimitQuery {
    #[serde(default = "default_integration_limit")]
    limit: u16,
}

const fn default_integration_limit() -> u16 {
    100
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/integration/findings",
    params(("limit" = Option<u16>, Query, description = "Result limit, clamped to 1..=500")),
    responses((status = 200, body = IntegrationFindingsResponse))
)]
async fn integration_findings(
    axum::extract::State(state): axum::extract::State<AppState>,
    Query(query): Query<IntegrationLimitQuery>,
) -> Result<Json<IntegrationFindingsResponse>, ApiError> {
    let limit = query.limit.clamp(1, 500);
    let findings = state
        .postgres
        .list_findings(limit)
        .await
        .map_err(ApiError::dependency)?;
    let system_ids = findings
        .iter()
        .map(|finding| finding.system_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let (evidence, evidence_may_be_truncated) =
        contribution_evidence_by_system(&state, &system_ids).await?;
    let items = findings
        .into_iter()
        .map(|finding| finding_contribution(finding, &evidence))
        .collect::<Result<Vec<_>, _>>()?;
    let open = items
        .iter()
        .filter(|finding| finding.status == FindingContributionStatus::Open)
        .count();
    Ok(Json(IntegrationFindingsResponse {
        schema_version: INTEGRATION_SCHEMA_VERSION.to_owned(),
        open,
        items,
        evidence_may_be_truncated,
        content_retained: false,
    }))
}

fn finding_contribution(
    finding: FindingView,
    evidence: &HashMap<uuid::Uuid, Vec<EvidenceLinkContribution>>,
) -> Result<FindingContribution, ApiError> {
    let status = match finding.status.as_str() {
        "open" => FindingContributionStatus::Open,
        "resolved" => FindingContributionStatus::Resolved,
        "superseded" => FindingContributionStatus::Superseded,
        _ => {
            return Err(ApiError::dependency_message(
                "integration_finding_status_unknown",
            ));
        }
    };
    let contribution = FindingContribution {
        schema_version: INTEGRATION_SCHEMA_VERSION.to_owned(),
        producer: ContributionProducer::GodelTally,
        finding_id: finding.finding_id,
        system_id: finding.system_id,
        title: finding.title,
        severity: finding.severity,
        status,
        policy_id: finding.policy_id,
        policy_version: finding.policy_version,
        factor_codes: finding.factor_codes,
        evidence: evidence
            .get(&finding.system_id)
            .cloned()
            .unwrap_or_default(),
        resource_path: "/api/v1/tally/findings".to_owned(),
        updated_at: finding.last_evaluated_at,
        revision: finding.system_revision.max(1),
    };
    contribution
        .validate()
        .map_err(|_| ApiError::dependency_message("integration_projection_invalid"))?;
    Ok(contribution)
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/integration/evidence-links",
    params(("limit" = Option<u16>, Query, description = "Newest evidence links, clamped to 1..=500")),
    responses((status = 200, body = IntegrationEvidenceLinksResponse))
)]
async fn integration_evidence_links(
    axum::extract::State(state): axum::extract::State<AppState>,
    Query(query): Query<IntegrationLimitQuery>,
) -> Result<Json<IntegrationEvidenceLinksResponse>, ApiError> {
    let limit = query.limit.clamp(1, 500);
    let observations = state
        .observations
        .list_recent_observations(limit, None)
        .await
        .map_err(ApiError::dependency)?;
    let items = observations
        .iter()
        .map(|observation| evidence_link_contribution(observation, "/api/v1/tally/events"))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(IntegrationEvidenceLinksResponse {
        schema_version: INTEGRATION_SCHEMA_VERSION.to_owned(),
        items,
        content_retained: false,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/integration/report-sections/discovery-summary",
    responses((status = 200, body = tally_core::ReportSectionContribution))
)]
async fn integration_discovery_summary(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<ReportSectionContribution>, ApiError> {
    let (systems, findings, connectors, observation_count, oldest, newest) = tokio::join!(
        state.postgres.ai_system_count(),
        state.postgres.list_findings(500),
        state.postgres.list_connector_states(),
        state.observations.observation_count(),
        state.observations.list_observations(1),
        state.observations.list_recent_observations(1, None),
    );
    let systems = systems.map_err(ApiError::dependency)?;
    let findings = findings.map_err(ApiError::dependency)?;
    let connectors = connectors.map_err(ApiError::dependency)?;
    let observation_count = observation_count.map_err(ApiError::dependency)?;
    let oldest = oldest.map_err(ApiError::dependency)?;
    let newest = newest.map_err(ApiError::dependency)?;
    let generated_at = Utc::now();
    let window_start = oldest
        .first()
        .map_or(state.started_at, |observation| observation.observed_at);
    let window_end = newest
        .first()
        .map_or(generated_at, |observation| observation.observed_at);
    let metrics = vec![
        ReportMetricContribution {
            metric_code: "systems_observed".to_owned(),
            label: "AI systems observed".to_owned(),
            value: i64::try_from(systems).unwrap_or(i64::MAX),
        },
        ReportMetricContribution {
            metric_code: "open_findings".to_owned(),
            label: "Open discovery findings".to_owned(),
            value: i64::try_from(
                findings
                    .iter()
                    .filter(|finding| finding.status == "open")
                    .count(),
            )
            .unwrap_or(i64::MAX),
        },
        ReportMetricContribution {
            metric_code: "configured_sources".to_owned(),
            label: "Configured discovery sources".to_owned(),
            value: i64::try_from(connectors.len()).unwrap_or(i64::MAX),
        },
        ReportMetricContribution {
            metric_code: "healthy_sources".to_owned(),
            label: "Healthy discovery sources".to_owned(),
            value: i64::try_from(
                connectors
                    .iter()
                    .filter(|connector| connector.health == ConnectorHealth::Healthy)
                    .count(),
            )
            .unwrap_or(i64::MAX),
        },
        ReportMetricContribution {
            metric_code: "observations".to_owned(),
            label: "Discovery observations".to_owned(),
            value: i64::try_from(observation_count).unwrap_or(i64::MAX),
        },
    ];
    let contribution = ReportSectionContribution {
        schema_version: INTEGRATION_SCHEMA_VERSION.to_owned(),
        producer: ContributionProducer::GodelTally,
        section_id: "discovery_summary".to_owned(),
        title: "Agentless discovery summary".to_owned(),
        window_start,
        window_end: window_end.max(window_start),
        metrics,
        resource_path: "/api/v1/tally/overview".to_owned(),
        generated_at,
        revision: generated_at.timestamp_millis().max(1),
    };
    contribution
        .validate()
        .map_err(|_| ApiError::dependency_message("integration_projection_invalid"))?;
    Ok(Json(contribution))
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/connectors/schedules",
    request_body = ConnectorScheduleRequest,
    responses(
        (status = 200, body = ConnectorJobResponse),
        (status = 409, body = ProblemDetails),
        (status = 422, body = ProblemDetails)
    )
)]
async fn upsert_connector_schedule(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(body): Json<ConnectorScheduleRequest>,
) -> Result<Json<ConnectorJobResponse>, ApiError> {
    if !body.acknowledge_source_access
        || !(60..=86_400).contains(&body.interval_seconds)
        || !body
            .friendly_name
            .as_deref()
            .is_none_or(safe_connector_friendly_name)
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "connector_schedule_invalid",
        ));
    }
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    if let Some(id) = body.connector_instance_id {
        sample_data::require_live_connector(&state, id).await?;
    }
    let (existing_credentials, credential_reentry_required) =
        existing_connector_credentials(&state, body.connector_instance_id).await?;
    let plan =
        connector_schedule_source_with_existing(&body.source, existing_credentials.as_ref())?;
    if credential_reentry_required && plan.credentials.is_empty() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "connector_credentials_reentry_required",
        ));
    }
    let connector_instance_id = body.connector_instance_id.unwrap_or_else(|| {
        let identity_key = plan.identity_suffix.as_ref().map_or_else(
            || plan.descriptor.connector_type.clone(),
            |suffix| format!("{}:{suffix}", plan.descriptor.connector_type),
        );
        default_connector_instance_id(identity.installation_id, &identity_key)
    });
    // Seal before anything is written, so a cipher failure cannot leave a schedule registered
    // against credentials that never made it to disk.
    let credentials = if existing_credentials.as_ref() == Some(&plan.credentials) {
        None
    } else {
        seal_connector_credentials(&state.secret_cipher, &plan.credentials)?
    };
    state
        .postgres
        .register_connector_named(
            identity.installation_id,
            connector_instance_id,
            &plan.descriptor,
            body.friendly_name.as_deref(),
        )
        .await
        .map_err(ApiError::dependency)?;
    let job_id = uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        format!("godel-tally:connector-job:{connector_instance_id}").as_bytes(),
    );
    let now = Utc::now();
    state
        .postgres
        .put_connector_job(&ConnectorJobSpec {
            job_id,
            connector_instance_id,
            mode: ConnectorJobMode::Scheduled,
            status: if body.paused {
                ConnectorJobStatus::Paused
            } else {
                ConnectorJobStatus::Enabled
            },
            schedule_seconds: Some(body.interval_seconds),
            next_run_at: (!body.paused).then_some(now),
            config_refs: plan.config_refs,
            credentials,
            updated_at: now,
        })
        .await
        .map_err(|error| match error {
            PostgresStoreError::ConnectorJobLeased => {
                ApiError::new(StatusCode::CONFLICT, "connector_schedule_leased")
            }
            PostgresStoreError::UnsafeConnectorJob => ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "connector_schedule_invalid",
            ),
            other => ApiError::dependency(other),
        })?;
    let job = state
        .postgres
        .list_connector_jobs()
        .await
        .map_err(ApiError::dependency)?
        .into_iter()
        .find(|job| job.job_id == job_id)
        .ok_or_else(|| ApiError::dependency_message("connector_schedule_missing"))?;
    Ok(Json(ConnectorJobResponse::from(job)))
}

async fn existing_connector_credentials(
    state: &AppState,
    connector_instance_id: Option<uuid::Uuid>,
) -> Result<(Option<BTreeMap<String, String>>, bool), ApiError> {
    let Some(connector_instance_id) = connector_instance_id else {
        return Ok((None, false));
    };
    let job = state
        .postgres
        .connector_job_edit_view(connector_instance_id)
        .await
        .map_err(ApiError::dependency)?;
    Ok(match job {
        Some(job) => {
            match unseal_connector_credentials(&state.secret_cipher, job.credentials.as_ref()) {
                Ok(credentials) => (Some(credentials), false),
                Err(_) => (None, true),
            }
        }
        None => (None, false),
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/connectors/sync",
    responses(
        (status = 200, body = ConnectorSyncSweepResponse),
        (status = 503, body = ProblemDetails)
    )
)]
async fn sync_all_connectors(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<ConnectorSyncSweepResponse>, ApiError> {
    let installation_id = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?
        .installation_id;
    let requested_at = Utc::now();
    let sweep = state
        .postgres
        .request_all_connector_syncs(installation_id, requested_at)
        .await
        .map_err(ApiError::from_store)?;
    Ok(Json(ConnectorSyncSweepResponse::from_sweep(
        sweep,
        requested_at,
    )))
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/connectors/{connector_instance_id}/sync",
    params((
        "connector_instance_id" = uuid::Uuid,
        Path,
        description = "Registered connector instance"
    )),
    responses(
        (status = 200, body = ConnectorSyncResponse),
        (status = 404, body = ProblemDetails),
        (status = 409, body = ProblemDetails)
    )
)]
async fn sync_connector(
    axum::extract::State(state): axum::extract::State<AppState>,
    Path(connector_instance_id): Path<uuid::Uuid>,
) -> Result<Json<ConnectorSyncResponse>, ApiError> {
    let installation_id = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?
        .installation_id;
    let requested_at = Utc::now();
    let job = state
        .postgres
        .request_connector_sync(installation_id, connector_instance_id, requested_at)
        .await
        .map_err(ApiError::from_store)?;
    Ok(Json(ConnectorSyncResponse {
        requested_at,
        job: ConnectorJobResponse::from(job),
        content_retained: false,
    }))
}

#[utoipa::path(
    delete,
    path = "/api/v1/tally/connectors/{connector_instance_id}",
    params((
        "connector_instance_id" = uuid::Uuid,
        Path,
        description = "Registered connector instance"
    )),
    responses(
        (status = 200, body = ConnectorDeleteResponse),
        (status = 404, body = ProblemDetails),
        (status = 409, body = ProblemDetails)
    )
)]
async fn delete_connector(
    axum::extract::State(state): axum::extract::State<AppState>,
    Path(connector_instance_id): Path<uuid::Uuid>,
) -> Result<Json<ConnectorDeleteResponse>, ApiError> {
    let installation_id = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?
        .installation_id;
    let deletion = state
        .postgres
        .delete_connector(installation_id, connector_instance_id, Utc::now())
        .await
        .map_err(ApiError::from_store)?;
    Ok(Json(ConnectorDeleteResponse::from(deletion)))
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/connectors/jobs/{job_id}/backfill/preview",
    params(("job_id" = uuid::Uuid, Path, description = "Scheduled connector job")),
    request_body = ConnectorBackfillPreviewRequest,
    responses(
        (status = 200, body = ConnectorBackfillPreviewResponse),
        (status = 404, body = ProblemDetails),
        (status = 409, body = ProblemDetails),
        (status = 422, body = ProblemDetails)
    )
)]
async fn preview_connector_backfill(
    axum::extract::State(state): axum::extract::State<AppState>,
    Path(job_id): Path<uuid::Uuid>,
    Json(request): Json<ConnectorBackfillPreviewRequest>,
) -> Result<Json<ConnectorBackfillPreviewResponse>, ApiError> {
    let installation_id = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?
        .installation_id;
    let preview = state
        .postgres
        .preview_connector_backfill(installation_id, job_id, request.lookback_seconds)
        .await
        .map_err(ApiError::from_store)?;
    Ok(Json(ConnectorBackfillPreviewResponse::from(preview)))
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/connectors/jobs/{job_id}/backfill",
    params(("job_id" = uuid::Uuid, Path, description = "Scheduled connector job")),
    request_body = ConnectorBackfillCommitRequest,
    responses(
        (status = 201, body = ConnectorBackfillCommitResponse),
        (status = 200, body = ConnectorBackfillCommitResponse),
        (status = 400, body = ProblemDetails),
        (status = 404, body = ProblemDetails),
        (status = 409, body = ProblemDetails),
        (status = 422, body = ProblemDetails)
    )
)]
async fn commit_connector_backfill(
    axum::extract::State(state): axum::extract::State<AppState>,
    Path(job_id): Path<uuid::Uuid>,
    headers: HeaderMap,
    Json(request): Json<ConnectorBackfillCommitRequest>,
) -> Result<(StatusCode, Json<ConnectorBackfillCommitResponse>), ApiError> {
    if !request.acknowledge_existing_evidence_preserved {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "connector_backfill_acknowledgement_required",
        ));
    }
    let idempotency_key = parse_idempotency_key(&headers)?;
    let request_sha256 = hex::encode(Sha256::digest(
        serde_json::to_vec(&(job_id, &request)).map_err(ApiError::dependency)?,
    ));
    let installation_id = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?
        .installation_id;
    let write = state
        .postgres
        .commit_connector_backfill(&ConnectorBackfillCommit {
            installation_id,
            job_id,
            lookback_seconds: request.lookback_seconds,
            preview_digest: request.confirm_preview_digest,
            request_sha256,
            idempotency_key,
            committed_at: Utc::now(),
        })
        .await
        .map_err(ApiError::from_store)?;
    let response = ConnectorBackfillCommitResponse::from_receipt(write.receipt, write.replayed);
    Ok((
        if response.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(response),
    ))
}

/// A validated connector schedule: what to register, the non-secret references the collector
/// reads from the job row, and the credentials that get sealed before they touch `PostgreSQL`.
struct ConnectorSchedulePlan {
    descriptor: ConnectorDescriptor,
    config_refs: serde_json::Value,
    credentials: BTreeMap<String, String>,
    /// Distinguishes two schedules of the same connector type. Derived from the identifying
    /// values only — never from a token — so rotating a secret updates the existing connector
    /// instead of orphaning it behind a new one.
    identity_suffix: Option<String>,
}

const INITIAL_BACKFILL_MIN_SECONDS: u32 = 60;
const INITIAL_BACKFILL_MAX_SECONDS: u32 = 604_800;

fn valid_initial_backfill_seconds(value: u32) -> bool {
    (INITIAL_BACKFILL_MIN_SECONDS..=INITIAL_BACKFILL_MAX_SECONDS).contains(&value)
}

fn schedule_invalid() -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "connector_schedule_invalid",
    )
}

/// Digests the identifying credential values into a short, stable instance suffix.
fn credential_identity(parts: &[&str]) -> String {
    let material = parts.join("\u{1f}");
    hex::encode(Sha256::digest(material.as_bytes()))[..16].to_owned()
}

fn credential_bundle<const N: usize>(entries: [(&str, &str); N]) -> BTreeMap<String, String> {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

#[cfg(test)]
fn connector_schedule_source(
    source: &ConnectorScheduleSourceInput,
) -> Result<ConnectorSchedulePlan, ApiError> {
    connector_schedule_source_with_existing(source, None)
}

#[allow(clippy::too_many_lines)]
fn connector_schedule_source_with_existing(
    source: &ConnectorScheduleSourceInput,
    existing_credentials: Option<&BTreeMap<String, String>>,
) -> Result<ConnectorSchedulePlan, ApiError> {
    match source {
        ConnectorScheduleSourceInput::NextdnsApi {
            profile_id,
            api_key,
            initial_backfill_seconds,
            initial_record_limit,
        } => {
            let api_key = retained_credential(api_key, existing_credentials, "api_key")?;
            connector_nextdns_api_schedule(
                profile_id,
                &api_key,
                *initial_backfill_seconds,
                *initial_record_limit,
            )
        }
        ConnectorScheduleSourceInput::ManagedCloud {
            adapter,
            account_id,
            scope_id,
            workspace_resource,
            region,
            aws_access_key_id,
            aws_secret_access_key,
            azure_tenant_id,
            azure_client_id,
            azure_client_secret,
            gcp_service_account_json,
        } => {
            let aws_access_key_id = retained_optional_credential(
                aws_access_key_id.as_deref(),
                existing_credentials,
                "aws_access_key_id",
            );
            let aws_secret_access_key = retained_optional_credential(
                aws_secret_access_key.as_deref(),
                existing_credentials,
                "aws_secret_access_key",
            );
            let azure_tenant_id = retained_optional_credential(
                azure_tenant_id.as_deref(),
                existing_credentials,
                "azure_tenant_id",
            );
            let azure_client_id = retained_optional_credential(
                azure_client_id.as_deref(),
                existing_credentials,
                "azure_client_id",
            );
            let azure_client_secret = retained_optional_credential(
                azure_client_secret.as_deref(),
                existing_credentials,
                "azure_client_secret",
            );
            let gcp_service_account_json = retained_optional_credential(
                gcp_service_account_json.as_deref(),
                existing_credentials,
                "gcp_service_account_json",
            );
            let workspace_resource = retained_optional_credential(
                workspace_resource.as_deref(),
                existing_credentials,
                "workspace_resource",
            );
            connector_cloud_schedule(
                *adapter,
                account_id,
                scope_id.as_deref(),
                workspace_resource.as_deref(),
                region,
                aws_access_key_id.as_deref(),
                aws_secret_access_key.as_deref(),
                azure_tenant_id.as_deref(),
                azure_client_id.as_deref(),
                azure_client_secret.as_deref(),
                gcp_service_account_json.as_deref(),
            )
        }
        ConnectorScheduleSourceInput::CloudNetwork {
            adapter,
            account_id,
            network_id,
            region,
            log_group,
            workspace_resource,
            aws_access_key_id,
            aws_secret_access_key,
            azure_tenant_id,
            azure_client_id,
            azure_client_secret,
            gcp_service_account_json,
            initial_backfill_seconds,
        } => {
            let aws_access_key_id = retained_optional_credential(
                aws_access_key_id.as_deref(),
                existing_credentials,
                "aws_access_key_id",
            );
            let aws_secret_access_key = retained_optional_credential(
                aws_secret_access_key.as_deref(),
                existing_credentials,
                "aws_secret_access_key",
            );
            let azure_tenant_id = retained_optional_credential(
                azure_tenant_id.as_deref(),
                existing_credentials,
                "azure_tenant_id",
            );
            let azure_client_id = retained_optional_credential(
                azure_client_id.as_deref(),
                existing_credentials,
                "azure_client_id",
            );
            let azure_client_secret = retained_optional_credential(
                azure_client_secret.as_deref(),
                existing_credentials,
                "azure_client_secret",
            );
            let gcp_service_account_json = retained_optional_credential(
                gcp_service_account_json.as_deref(),
                existing_credentials,
                "gcp_service_account_json",
            );
            connector_cloud_network_schedule(
                *adapter,
                account_id,
                network_id,
                region.as_deref(),
                log_group.as_deref(),
                workspace_resource.as_deref(),
                aws_access_key_id.as_deref(),
                aws_secret_access_key.as_deref(),
                azure_tenant_id.as_deref(),
                azure_client_id.as_deref(),
                azure_client_secret.as_deref(),
                gcp_service_account_json.as_deref(),
                *initial_backfill_seconds,
            )
        }
        ConnectorScheduleSourceInput::CasbApi {
            account_id,
            api_token,
        } => {
            let api_token = retained_credential(api_token, existing_credentials, "api_token")?;
            connector_enterprise_schedule(
                ImportAdapterInput::CloudflareCasbApi,
                account_id,
                &api_token,
                None,
            )
        }
        ConnectorScheduleSourceInput::KubernetesApi {
            api_url,
            bearer_token,
            ca_pem,
        } => {
            let bearer_token =
                retained_credential(bearer_token, existing_credentials, "bearer_token")?;
            let ca_pem =
                retained_optional_credential(ca_pem.as_deref(), existing_credentials, "ca_pem");
            let mut plan = connector_enterprise_schedule(
                ImportAdapterInput::KubernetesApiPull,
                api_url,
                &bearer_token,
                ca_pem.as_deref(),
            )?;
            // Console-created connectors always use the explicitly supplied bearer token. The
            // collector also supports an in-cluster mode for its CLI, so it requires this field
            // to choose the correct credential source at execution time.
            plan.config_refs["auth_mode"] = serde_json::Value::String("explicit_bearer".to_owned());
            // Existing path-based jobs remain runnable until an operator replaces the CA through
            // the browser. New Console requests cannot submit a host-local path.
            if ca_pem.is_none()
                && let Some(legacy_path) =
                    existing_credentials.and_then(|credentials| credentials.get("ca_file_path"))
            {
                plan.credentials
                    .insert("ca_file_path".to_owned(), legacy_path.clone());
            }
            Ok(plan)
        }
        ConnectorScheduleSourceInput::ManagedAgents {
            platform,
            base_url,
            api_key,
            app_id,
            scope_id,
        } => {
            let api_key = retained_credential(api_key, existing_credentials, "api_key")?;
            if !matches!(
                platform.as_str(),
                "servicenow"
                    | "n8n"
                    | "copilot_studio"
                    | "langgraph"
                    | "dify"
                    | "openai"
                    | "claude"
                    | "gemini"
            ) || (platform == "dify"
                && app_id
                    .as_deref()
                    .and_then(|id| uuid::Uuid::parse_str(id).ok())
                    .is_none())
                || (platform != "dify" && app_id.is_some())
                || !safe_credential_value(&api_key)
                || !safe_managed_origin(base_url)
                || !tally_connectors::managed_agents_scope_valid(
                    platform,
                    base_url,
                    scope_id.as_deref(),
                )
            {
                return Err(schedule_invalid());
            }
            let mut credentials = credential_bundle([
                ("base_url", base_url.as_str()),
                ("api_key", api_key.as_str()),
            ]);
            if let Some(id) = app_id {
                credentials.insert("app_id".into(), id.clone());
            }
            if let Some(scope) = scope_id {
                credentials.insert("scope_id".into(), scope.clone());
            }
            let identity = if matches!(platform.as_str(), "openai" | "claude" | "gemini") {
                credential_identity(&[base_url, scope_id.as_deref().unwrap_or(&api_key)])
            } else if let Some(id) = app_id {
                credential_identity(&[base_url, id])
            } else {
                credential_identity(&[base_url])
            };
            Ok(ConnectorSchedulePlan {
                descriptor: tally_connectors::managed_agents_descriptor(platform),
                config_refs: serde_json::json!({"kind":"managed_agents_v1","platform":platform,"source_lineage_id":format!("{platform}:agent_inventory")}),
                credentials,
                identity_suffix: Some(format!("{platform}:{identity}")),
            })
        }
        ConnectorScheduleSourceInput::LitellmApi {
            base_url,
            api_key,
            initial_backfill_seconds,
            initial_record_limit,
        } => {
            let api_key = retained_credential(api_key, existing_credentials, "api_key")?;
            connector_litellm_schedule(
                base_url,
                &api_key,
                *initial_backfill_seconds,
                *initial_record_limit,
            )
        }
        ConnectorScheduleSourceInput::AiGatewayApi {
            account_id,
            api_token,
            initial_backfill_seconds,
            initial_record_limit,
        } => {
            let api_token = retained_credential(api_token, existing_credentials, "api_token")?;
            connector_ai_gateway_schedule(
                account_id,
                &api_token,
                *initial_backfill_seconds,
                *initial_record_limit,
            )
        }
        ConnectorScheduleSourceInput::Rapid7Edr {
            region,
            log_id,
            api_key,
            initial_backfill_seconds,
        } => {
            let api_key = retained_credential(api_key, existing_credentials, "api_key")?;
            if tally_connectors::rapid7_api_origin(region).is_none()
                || uuid::Uuid::parse_str(log_id).is_err()
                || !safe_credential_value(&api_key)
                || !valid_initial_backfill_seconds(*initial_backfill_seconds)
            {
                return Err(schedule_invalid());
            }
            Ok(ConnectorSchedulePlan {
                descriptor: tally_connectors::SecurityLogSource::Rapid7Edr.descriptor(),
                config_refs: serde_json::json!({"kind":"rapid7_edr_insightidr_api_v1", "source_lineage_id":"rapid7:insightidr_dns", "region":region, "backfill_seconds":initial_backfill_seconds.to_string(), "initial_start":(Utc::now().timestamp() - 300 - i64::from(*initial_backfill_seconds)) * 1000}),
                credentials: credential_bundle([
                    ("log_id", log_id.as_str()),
                    ("api_key", api_key.as_str()),
                ]),
                identity_suffix: Some(format!("rapid7:{}", credential_identity(&[region, log_id]))),
            })
        }
        ConnectorScheduleSourceInput::Netskope {
            tenant_url,
            event_type,
            api_token,
            initial_backfill_seconds,
        } => {
            let api_token = retained_credential(api_token, existing_credentials, "api_token")?;
            let origin =
                tally_connectors::netskope_api_origin(tenant_url).ok_or_else(schedule_invalid)?;
            if !matches!(event_type.as_str(), "page" | "application")
                || !safe_credential_value(&api_token)
                || !valid_initial_backfill_seconds(*initial_backfill_seconds)
            {
                return Err(schedule_invalid());
            }
            Ok(ConnectorSchedulePlan {
                descriptor: tally_connectors::SecurityLogSource::Netskope.descriptor(),
                config_refs: serde_json::json!({"kind":"netskope_events_api_v1", "source_lineage_id":format!("netskope:{event_type}"), "event_type":event_type, "backfill_seconds":initial_backfill_seconds.to_string(), "initial_start":(Utc::now().timestamp() - 300 - i64::from(*initial_backfill_seconds)) * 1000}),
                credentials: credential_bundle([
                    ("tenant_url", origin.as_str()),
                    ("api_token", api_token.as_str()),
                ]),
                identity_suffix: Some(format!(
                    "netskope:{}",
                    credential_identity(&[&origin, event_type])
                )),
            })
        }
        ConnectorScheduleSourceInput::CrowdstrikeEdr {
            cloud,
            client_id,
            client_secret,
            initial_backfill_seconds,
            initial_record_limit,
        } => {
            let client_id = retained_credential(client_id, existing_credentials, "client_id")?;
            let client_secret =
                retained_credential(client_secret, existing_credentials, "client_secret")?;
            connector_crowdstrike_edr_schedule(
                cloud,
                &client_id,
                &client_secret,
                *initial_backfill_seconds,
                *initial_record_limit,
            )
        }
        ConnectorScheduleSourceInput::MicrosoftDefenderApi {
            tenant_id,
            client_id,
            client_secret,
            initial_backfill_seconds,
            initial_record_limit,
        } => {
            let client_id = retained_credential(client_id, existing_credentials, "client_id")?;
            let client_secret =
                retained_credential(client_secret, existing_credentials, "client_secret")?;
            connector_microsoft_defender_schedule(
                tenant_id,
                &client_id,
                &client_secret,
                *initial_backfill_seconds,
                *initial_record_limit,
            )
        }
        ConnectorScheduleSourceInput::CatoNetworksApi {
            account_id,
            api_key,
            api_hostname,
            initial_backfill_seconds,
            initial_record_limit,
        } => {
            let api_key = retained_credential(api_key, existing_credentials, "api_key")?;
            connector_cato_networks_schedule(
                account_id,
                &api_key,
                api_hostname,
                *initial_backfill_seconds,
                *initial_record_limit,
            )
        }
        ConnectorScheduleSourceInput::CloudflareZeroTrustGateway {
            account_id,
            api_token,
            window_seconds,
            endpoint_url,
            bucket,
            prefix,
            region,
            access_key_id,
            secret_access_key,
            object_limit,
        } => {
            let api_token = retained_credential(api_token, existing_credentials, "api_token")?;
            let s3_requested = !endpoint_url.is_empty()
                || !bucket.is_empty()
                || !prefix.is_empty()
                || !access_key_id.is_empty()
                || !secret_access_key.is_empty();
            let (access_key_id, secret_access_key) = if s3_requested {
                (
                    Some(retained_credential(
                        access_key_id,
                        existing_credentials,
                        "access_key_id",
                    )?),
                    Some(retained_credential(
                        secret_access_key,
                        existing_credentials,
                        "secret_access_key",
                    )?),
                )
            } else {
                (None, None)
            };
            connector_cloudflare_zero_trust_gateway_schedule(
                account_id,
                &api_token,
                *window_seconds,
                endpoint_url,
                bucket,
                prefix,
                region,
                access_key_id.as_deref(),
                secret_access_key.as_deref(),
                *object_limit,
            )
        }
    }
}

fn retained_credential(
    submitted: &str,
    existing_credentials: Option<&BTreeMap<String, String>>,
    name: &str,
) -> Result<String, ApiError> {
    if !submitted.is_empty() {
        return Ok(submitted.to_owned());
    }
    existing_credentials
        .and_then(|credentials| credentials.get(name))
        .cloned()
        .ok_or_else(schedule_invalid)
}

fn retained_optional_credential(
    submitted: Option<&str>,
    existing_credentials: Option<&BTreeMap<String, String>>,
    name: &str,
) -> Option<String> {
    submitted
        .map(str::to_owned)
        .or_else(|| existing_credentials.and_then(|credentials| credentials.get(name).cloned()))
}

/// Validates and projects the `NextDNS` Logs API pull schedule.
///
/// Kept out of [`connector_schedule_source`] so that match stays a flat table of variants and
/// every bounds check for this source lives in one place.
fn connector_nextdns_api_schedule(
    profile_id: &str,
    api_key: &str,
    initial_backfill_seconds: u32,
    initial_record_limit: u32,
) -> Result<ConnectorSchedulePlan, ApiError> {
    if !safe_nextdns_profile_id(profile_id)
        || !safe_credential_value(api_key)
        || !valid_initial_backfill_seconds(initial_backfill_seconds)
        || !(1..=1_000).contains(&initial_record_limit)
    {
        return Err(schedule_invalid());
    }
    Ok(ConnectorSchedulePlan {
        descriptor: nextdns_api_descriptor(),
        config_refs: serde_json::json!({
            "kind": "nextdns_api_v1",
            "profile_id": profile_id,
            "source_lineage_id": "nextdns_api",
            "backfill_seconds": initial_backfill_seconds.to_string(),
            "record_limit": initial_record_limit.to_string()
        }),
        credentials: credential_bundle([("api_key", api_key)]),
        identity_suffix: Some(profile_id.to_owned()),
    })
}

fn connector_ai_gateway_schedule(
    account_id: &str,
    api_token: &str,
    initial_backfill_seconds: u32,
    initial_record_limit: u32,
) -> Result<ConnectorSchedulePlan, ApiError> {
    if !safe_credential_value(account_id)
        || !safe_credential_value(api_token)
        || !valid_initial_backfill_seconds(initial_backfill_seconds)
        || !(1..=5_000).contains(&initial_record_limit)
    {
        return Err(schedule_invalid());
    }
    Ok(ConnectorSchedulePlan {
        descriptor: ImportAdapterInput::CloudflareAiGatewayApi.descriptor(),
        config_refs: serde_json::json!({
            "kind": "ai_gateway_api_v1",
            "source_lineage_id": "cloudflare_ai_gateway_api:native",
            "backfill_seconds": initial_backfill_seconds.to_string(),
            "record_limit": initial_record_limit.to_string(),
        }),
        credentials: credential_bundle([("account_id", account_id), ("api_token", api_token)]),
        identity_suffix: Some(format!("ai-gateway:{}", credential_identity(&[account_id]))),
    })
}

fn connector_crowdstrike_edr_schedule(
    cloud: &str,
    client_id: &str,
    client_secret: &str,
    initial_backfill_seconds: u32,
    initial_record_limit: u32,
) -> Result<ConnectorSchedulePlan, ApiError> {
    if !matches!(cloud, "us-1" | "us-2" | "eu-1")
        || !safe_credential_value(client_id)
        || !safe_credential_value(client_secret)
        || !valid_initial_backfill_seconds(initial_backfill_seconds)
        || !(1..=5_000).contains(&initial_record_limit)
    {
        return Err(schedule_invalid());
    }
    Ok(ConnectorSchedulePlan {
        descriptor: ImportAdapterInput::CrowdstrikeEdr.descriptor(),
        config_refs: serde_json::json!({
            "kind": "crowdstrike_edr_ngsiem_api_v1",
            "source_lineage_id": "crowdstrike_edr:ngsiem_dns",
            "cloud": cloud,
            "backfill_seconds": initial_backfill_seconds.to_string(),
            "record_limit": initial_record_limit.to_string(),
        }),
        credentials: credential_bundle([
            ("client_id", client_id),
            ("client_secret", client_secret),
        ]),
        identity_suffix: Some(format!(
            "crowdstrike-edr:{}",
            credential_identity(&[cloud, client_id])
        )),
    })
}

fn connector_microsoft_defender_schedule(
    tenant_id: &str,
    client_id: &str,
    client_secret: &str,
    initial_backfill_seconds: u32,
    initial_record_limit: u32,
) -> Result<ConnectorSchedulePlan, ApiError> {
    if uuid::Uuid::parse_str(tenant_id).is_err()
        || uuid::Uuid::parse_str(client_id).is_err()
        || !safe_credential_value(client_secret)
        || !valid_initial_backfill_seconds(initial_backfill_seconds)
        || !(1..=5_000).contains(&initial_record_limit)
    {
        return Err(schedule_invalid());
    }
    Ok(ConnectorSchedulePlan {
        descriptor: microsoft_defender_edr_api_descriptor(),
        config_refs: serde_json::json!({
            "kind": "microsoft_defender_graph_hunting_v1",
            "source_lineage_id": "microsoft_defender:device_network_events",
            "backfill_seconds": initial_backfill_seconds.to_string(),
            "record_limit": initial_record_limit.to_string(),
        }),
        credentials: credential_bundle([
            ("tenant_id", tenant_id),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ]),
        identity_suffix: Some(format!(
            "microsoft-defender:{}",
            credential_identity(&[tenant_id, client_id])
        )),
    })
}

fn connector_cato_networks_schedule(
    account_id: &str,
    api_key: &str,
    api_hostname: &str,
    initial_backfill_seconds: u32,
    initial_record_limit: u32,
) -> Result<ConnectorSchedulePlan, ApiError> {
    if account_id.is_empty()
        || account_id.len() > 20
        || !account_id.bytes().all(|byte| byte.is_ascii_digit())
        || !safe_credential_value(api_key)
        || !safe_cato_api_hostname(api_hostname)
        || !valid_initial_backfill_seconds(initial_backfill_seconds)
        || !(1..=3_000).contains(&initial_record_limit)
    {
        return Err(schedule_invalid());
    }
    Ok(ConnectorSchedulePlan {
        descriptor: cato_networks_api_descriptor(),
        config_refs: serde_json::json!({
            "kind": "cato_networks_events_feed_v1",
            "source_lineage_id": "cato_networks:events_feed",
            "api_hostname": api_hostname,
            "backfill_seconds": initial_backfill_seconds.to_string(),
            "record_limit": initial_record_limit.to_string(),
        }),
        credentials: credential_bundle([("account_id", account_id), ("api_key", api_key)]),
        identity_suffix: Some(format!(
            "cato-networks:{}",
            credential_identity(&[api_hostname, account_id])
        )),
    })
}

fn safe_cato_api_hostname(value: &str) -> bool {
    value == value.to_ascii_lowercase()
        && value.len() <= 253
        && !value.contains('/')
        && (value == "api.catonetworks.com"
            || (value.starts_with("api.") && value.ends_with(".catonetworks.com")))
}

#[allow(clippy::too_many_arguments)]
fn connector_cloudflare_zero_trust_gateway_schedule(
    account_id: &str,
    api_token: &str,
    window_seconds: u32,
    endpoint_url: &str,
    bucket: &str,
    prefix: &str,
    region: &str,
    access_key_id: Option<&str>,
    secret_access_key: Option<&str>,
    object_limit: u32,
) -> Result<ConnectorSchedulePlan, ApiError> {
    if !safe_cloudflare_account_id(account_id)
        || !safe_credential_value(api_token)
        || !(60..=604_800).contains(&window_seconds)
        || !safe_cloud_region(region)
        || !(1..=128).contains(&object_limit)
    {
        return Err(schedule_invalid());
    }
    let s3_requested = !endpoint_url.is_empty()
        || !bucket.is_empty()
        || !prefix.is_empty()
        || access_key_id.is_some()
        || secret_access_key.is_some();
    let normalized_endpoint = if s3_requested {
        let Some(endpoint) = safe_s3_endpoint(endpoint_url) else {
            return Err(schedule_invalid());
        };
        if !(3..=255).contains(&bucket.len())
            || bucket.trim() != bucket
            || bucket.contains('/')
            || bucket.chars().any(char::is_control)
            || prefix.len() > 1_024
            || prefix.chars().any(char::is_control)
            || access_key_id.is_none_or(|value| !safe_credential_value(value))
            || secret_access_key.is_none_or(|value| !safe_credential_value(value))
        {
            return Err(schedule_invalid());
        }
        endpoint.as_str().to_owned()
    } else {
        String::new()
    };
    let mut credentials = credential_bundle([("account_id", account_id), ("api_token", api_token)]);
    if let (Some(access_key_id), Some(secret_access_key)) = (access_key_id, secret_access_key) {
        credentials.insert("access_key_id".to_owned(), access_key_id.to_owned());
        credentials.insert("secret_access_key".to_owned(), secret_access_key.to_owned());
    }
    Ok(ConnectorSchedulePlan {
        descriptor: cloudflare_zero_trust_gateway_descriptor(),
        config_refs: serde_json::json!({
            "kind": "cloudflare_zero_trust_gateway_v1",
            "source_lineage_id": "cloudflare_zero_trust_gateway:graphql_optional_s3",
            "window_seconds": window_seconds.to_string(),
            "endpoint_url": normalized_endpoint,
            "bucket": bucket,
            "prefix": prefix,
            "region": region,
            "object_limit": object_limit.to_string(),
        }),
        credentials,
        identity_suffix: Some(format!(
            "cloudflare-zero-trust:{}",
            credential_identity(&[account_id])
        )),
    })
}

fn safe_cloudflare_account_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn safe_s3_endpoint(value: &str) -> Option<Url> {
    let mut url = Url::parse(value).ok()?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    url.set_path("/");
    Some(url)
}

fn connector_enterprise_schedule(
    adapter: ImportAdapterInput,
    primary: &str,
    credential: &str,
    ca_pem: Option<&str>,
) -> Result<ConnectorSchedulePlan, ApiError> {
    if !safe_credential_value(primary)
        || !safe_credential_value(credential)
        || !ca_pem.is_none_or(safe_ca_pem)
    {
        return Err(schedule_invalid());
    }
    let (kind, lineage, primary_key, credential_key, label) = match adapter {
        ImportAdapterInput::CloudflareCasbApi if ca_pem.is_none() => (
            "casb_api_v1",
            "cloudflare_casb_api:native",
            "account_id",
            "api_token",
            "casb",
        ),
        ImportAdapterInput::LitellmApi if ca_pem.is_none() => (
            "litellm_api_v1",
            "litellm_api:native",
            "base_url",
            "api_key",
            "litellm",
        ),
        ImportAdapterInput::KubernetesApiPull => (
            "kubernetes_api_v1",
            "kubernetes_api:native",
            "api_url",
            "bearer_token",
            "kubernetes",
        ),
        _ => return Err(schedule_invalid()),
    };
    let mut credentials = credential_bundle([(primary_key, primary), (credential_key, credential)]);
    if let Some(ca_pem) = ca_pem {
        credentials.insert("ca_pem".to_owned(), ca_pem.to_owned());
    }
    Ok(ConnectorSchedulePlan {
        descriptor: adapter.descriptor(),
        config_refs: serde_json::json!({
            "kind": kind,
            "source_lineage_id": lineage,
        }),
        credentials,
        identity_suffix: Some(format!("{label}:{}", credential_identity(&[primary]))),
    })
}

fn connector_litellm_schedule(
    base_url: &str,
    api_key: &str,
    initial_backfill_seconds: u32,
    initial_record_limit: u32,
) -> Result<ConnectorSchedulePlan, ApiError> {
    if !valid_initial_backfill_seconds(initial_backfill_seconds)
        || !(1..=5_000).contains(&initial_record_limit)
    {
        return Err(schedule_invalid());
    }
    let mut plan =
        connector_enterprise_schedule(ImportAdapterInput::LitellmApi, base_url, api_key, None)?;
    plan.config_refs["backfill_seconds"] =
        serde_json::Value::String(initial_backfill_seconds.to_string());
    plan.config_refs["record_limit"] = serde_json::Value::String(initial_record_limit.to_string());
    Ok(plan)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn connector_cloud_network_schedule(
    adapter: ImportAdapterInput,
    account_id: &str,
    network_id: &str,
    region: Option<&str>,
    log_group: Option<&str>,
    workspace_resource: Option<&str>,
    aws_access_key_id: Option<&str>,
    aws_secret_access_key: Option<&str>,
    azure_tenant_id: Option<&str>,
    azure_client_id: Option<&str>,
    azure_client_secret: Option<&str>,
    gcp_service_account_json: Option<&str>,
    initial_backfill_seconds: u32,
) -> Result<ConnectorSchedulePlan, ApiError> {
    let (region, log_group, workspace_resource) = match adapter {
        ImportAdapterInput::AwsCloudFlowApi
            if region.is_some_and(safe_cloud_region)
                && log_group.is_some_and(safe_credential_value)
                && workspace_resource.is_none() =>
        {
            (region.unwrap_or_default(), log_group, None)
        }
        ImportAdapterInput::AwsNetworkMappingApi | ImportAdapterInput::AzureNetworkMappingApi
            if region.is_some_and(safe_cloud_region)
                && log_group.is_none()
                && workspace_resource.is_none() =>
        {
            (region.unwrap_or_default(), None, None)
        }
        ImportAdapterInput::AzureCloudFlowApi
            if region.is_some_and(safe_cloud_region)
                && log_group.is_none()
                && workspace_resource.is_some_and(safe_credential_value) =>
        {
            (region.unwrap_or_default(), None, workspace_resource)
        }
        ImportAdapterInput::GcpCloudFlowApi | ImportAdapterInput::GcpNetworkMappingApi
            if region.is_none_or(|value| value == "global")
                && log_group.is_none()
                && workspace_resource.is_none() =>
        {
            ("global", None, None)
        }
        _ => return Err(schedule_invalid()),
    };
    let aws = matches!(
        adapter,
        ImportAdapterInput::AwsCloudFlowApi | ImportAdapterInput::AwsNetworkMappingApi
    );
    let aws_credentials = match (aws_access_key_id, aws_secret_access_key) {
        (None, None) => None,
        (Some(access_key_id), Some(secret_access_key))
            if safe_credential_value(access_key_id) && safe_credential_value(secret_access_key) =>
        {
            Some((access_key_id, secret_access_key))
        }
        _ => return Err(schedule_invalid()),
    };
    let azure = matches!(
        adapter,
        ImportAdapterInput::AzureCloudFlowApi | ImportAdapterInput::AzureNetworkMappingApi
    );
    let azure_credentials = match (azure_tenant_id, azure_client_id, azure_client_secret) {
        (None, None, None) => None,
        (Some(tenant_id), Some(client_id), Some(client_secret))
            if safe_credential_value(tenant_id)
                && safe_credential_value(client_id)
                && safe_credential_value(client_secret) =>
        {
            Some((tenant_id, client_id, client_secret))
        }
        _ => return Err(schedule_invalid()),
    };
    let gcp = matches!(
        adapter,
        ImportAdapterInput::GcpCloudFlowApi | ImportAdapterInput::GcpNetworkMappingApi
    );
    let gcp_credentials = match gcp_service_account_json {
        None => None,
        Some(json) if safe_gcp_service_account_json(json) => Some(json),
        Some(_) => return Err(schedule_invalid()),
    };
    if !adapter.is_native_cloud_network()
        || !safe_credential_value(account_id)
        || !safe_credential_value(network_id)
        || (!aws && aws_credentials.is_some())
        || (!azure && azure_credentials.is_some())
        || (!gcp && gcp_credentials.is_some())
        || !(300..=3_600).contains(&initial_backfill_seconds)
    {
        return Err(schedule_invalid());
    }
    let adapter_name = enum_name(adapter, "unknown");
    let mut credentials =
        credential_bundle([("account_id", account_id), ("network_id", network_id)]);
    if let Some(log_group) = log_group {
        credentials.insert("log_group".to_owned(), log_group.to_owned());
    }
    if let Some(workspace_resource) = workspace_resource {
        credentials.insert(
            "workspace_resource".to_owned(),
            workspace_resource.to_owned(),
        );
    }
    if let Some((access_key_id, secret_access_key)) = aws_credentials {
        credentials.insert("aws_access_key_id".to_owned(), access_key_id.to_owned());
        credentials.insert(
            "aws_secret_access_key".to_owned(),
            secret_access_key.to_owned(),
        );
    }
    if let Some((tenant_id, client_id, client_secret)) = azure_credentials {
        credentials.insert("azure_tenant_id".to_owned(), tenant_id.to_owned());
        credentials.insert("azure_client_id".to_owned(), client_id.to_owned());
        credentials.insert("azure_client_secret".to_owned(), client_secret.to_owned());
    }
    if let Some(service_account_json) = gcp_credentials {
        credentials.insert(
            "gcp_service_account_json".to_owned(),
            service_account_json.to_owned(),
        );
    }
    Ok(ConnectorSchedulePlan {
        descriptor: adapter.descriptor(),
        config_refs: serde_json::json!({
            "kind": "cloud_network_api_v1",
            "adapter": adapter_name,
            "region": region,
            "source_lineage_id": format!("{adapter_name}:native"),
            "backfill_seconds": initial_backfill_seconds.to_string()
        }),
        identity_suffix: Some(format!(
            "{adapter_name}:{region}:{}",
            credential_identity(&[
                account_id,
                network_id,
                log_group.unwrap_or_default(),
                workspace_resource.unwrap_or_default(),
            ])
        )),
        credentials,
    })
}

#[allow(clippy::too_many_arguments)]
fn connector_cloud_schedule(
    adapter: ImportAdapterInput,
    account_id: &str,
    scope_id: Option<&str>,
    workspace_resource: Option<&str>,
    region: &str,
    aws_access_key_id: Option<&str>,
    aws_secret_access_key: Option<&str>,
    azure_tenant_id: Option<&str>,
    azure_client_id: Option<&str>,
    azure_client_secret: Option<&str>,
    gcp_service_account_json: Option<&str>,
) -> Result<ConnectorSchedulePlan, ApiError> {
    let aws = matches!(adapter, ImportAdapterInput::AwsManagedAiApi);
    let azure = matches!(
        adapter,
        ImportAdapterInput::AzureOpenaiApi | ImportAdapterInput::AzureAiFoundryApi
    );
    let gcp = matches!(adapter, ImportAdapterInput::GcpVertexAiApi);
    let aws_credentials = match (aws_access_key_id, aws_secret_access_key) {
        (None, None) => None,
        (Some(access_key_id), Some(secret_access_key))
            if safe_credential_value(access_key_id) && safe_credential_value(secret_access_key) =>
        {
            Some((access_key_id, secret_access_key))
        }
        _ => return Err(schedule_invalid()),
    };
    let azure_credentials = match (azure_tenant_id, azure_client_id, azure_client_secret) {
        (None, None, None) => None,
        (Some(tenant_id), Some(client_id), Some(client_secret))
            if safe_credential_value(tenant_id)
                && safe_credential_value(client_id)
                && safe_credential_value(client_secret) =>
        {
            Some((tenant_id, client_id, client_secret))
        }
        _ => return Err(schedule_invalid()),
    };
    let gcp_credentials = match gcp_service_account_json {
        None => None,
        Some(json) if safe_gcp_service_account_json(json) => Some(json),
        Some(_) => return Err(schedule_invalid()),
    };
    if !adapter.is_native_cloud()
        || !safe_credential_value(account_id)
        || !safe_cloud_region(region)
        || (azure != scope_id.is_some_and(safe_credential_value))
        || (!azure && workspace_resource.is_some())
        || workspace_resource.is_some_and(|value| !safe_credential_value(value))
        || (!aws && aws_credentials.is_some())
        || (!azure && azure_credentials.is_some())
        || (!gcp && gcp_credentials.is_some())
    {
        return Err(schedule_invalid());
    }
    let mut credentials = credential_bundle([("account_id", account_id)]);
    if let Some(scope_id) = scope_id {
        credentials.insert("scope_id".to_owned(), scope_id.to_owned());
    }
    if let Some(workspace_resource) = workspace_resource {
        credentials.insert(
            "workspace_resource".to_owned(),
            workspace_resource.to_owned(),
        );
    }
    if let Some((access_key_id, secret_access_key)) = aws_credentials {
        credentials.insert("aws_access_key_id".to_owned(), access_key_id.to_owned());
        credentials.insert(
            "aws_secret_access_key".to_owned(),
            secret_access_key.to_owned(),
        );
    }
    if let Some((tenant_id, client_id, client_secret)) = azure_credentials {
        credentials.insert("azure_tenant_id".to_owned(), tenant_id.to_owned());
        credentials.insert("azure_client_id".to_owned(), client_id.to_owned());
        credentials.insert("azure_client_secret".to_owned(), client_secret.to_owned());
    }
    if let Some(service_account_json) = gcp_credentials {
        credentials.insert(
            "gcp_service_account_json".to_owned(),
            service_account_json.to_owned(),
        );
    }
    Ok(ConnectorSchedulePlan {
        descriptor: adapter.descriptor(),
        config_refs: serde_json::json!({
            "kind": "cloud_api_v1",
            "adapter": enum_name(adapter, "unknown"),
            "region": region,
            "source_lineage_id": format!("{}:native", enum_name(adapter, "cloud"))
        }),
        identity_suffix: Some(format!(
            "{}:{region}:{}",
            enum_name(adapter, "cloud"),
            credential_identity(&[
                account_id,
                scope_id.unwrap_or_default(),
                workspace_resource.unwrap_or_default(),
            ])
        )),
        credentials,
    })
}

#[cfg(test)]
fn connector_file_schedule(
    adapter: ImportAdapterInput,
    source_path: &str,
    account_id: Option<&str>,
    scope_id: Option<&str>,
    region: Option<&str>,
) -> Result<ConnectorSchedulePlan, ApiError> {
    let casb = matches!(adapter, ImportAdapterInput::CloudflareCasb)
        && account_id.is_some_and(safe_credential_value)
        && scope_id.is_none()
        && region.is_none();
    let kubernetes = matches!(adapter, ImportAdapterInput::KubernetesApi)
        && account_id.is_none()
        && scope_id.is_none()
        && region.is_none();
    let generic = !adapter.is_managed_cloud()
        && !adapter.is_native_cloud_network()
        && !adapter.is_casb()
        && !adapter.is_kubernetes()
        && account_id.is_none()
        && scope_id.is_none()
        && region.is_none();
    let azure = matches!(
        adapter,
        ImportAdapterInput::AzureOpenai | ImportAdapterInput::AzureAiFoundry
    );
    let managed_cloud = adapter.is_managed_cloud()
        && !adapter.is_native_cloud()
        && account_id.is_some_and(safe_credential_value)
        && region.is_some_and(safe_cloud_region)
        && ((azure && scope_id.is_some_and(safe_credential_value))
            || (!azure && scope_id.is_none()));
    if matches!(adapter, ImportAdapterInput::NextdnsApi)
        || !safe_credential_value(source_path)
        || (!generic && !managed_cloud && !casb && !kubernetes)
    {
        return Err(schedule_invalid());
    }
    let mut config_refs = serde_json::json!({
        "kind": "file_env_v1",
        "adapter": enum_name(adapter, "unknown"),
        "source_lineage_id": "scheduled_file_env"
    });
    if let (Some(object), Some(region)) = (config_refs.as_object_mut(), region) {
        object.insert(
            "region".to_owned(),
            serde_json::Value::String(region.to_owned()),
        );
    }
    let mut credentials = credential_bundle([("source_path", source_path)]);
    for (key, value) in [("account_id", account_id), ("scope_id", scope_id)] {
        if let Some(value) = value {
            credentials.insert(key.to_owned(), value.to_owned());
        }
    }
    Ok(ConnectorSchedulePlan {
        descriptor: adapter.descriptor(),
        config_refs,
        credentials,
        identity_suffix: Some(format!(
            "{}:{}",
            enum_name(adapter, "file"),
            credential_identity(&[
                source_path,
                account_id.unwrap_or_default(),
                scope_id.unwrap_or_default(),
            ])
        )),
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/imports/preview",
    request_body = ImportPreviewRequest,
    responses(
        (status = 200, body = ImportPreviewResponse),
        (status = 413, body = ProblemDetails),
        (status = 422, body = ProblemDetails)
    )
)]
async fn preview_import(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(body): Json<ImportPreviewRequest>,
) -> Result<Json<ImportPreviewResponse>, ApiError> {
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    let (descriptor, outcome) = normalize_import(&body, &identity)?;
    Ok(Json(import_preview_response(&descriptor, &outcome)))
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/imports",
    request_body = ImportCommitRequest,
    responses(
        (status = 200, body = ImportCommitResponse),
        (status = 409, body = ProblemDetails),
        (status = 413, body = ProblemDetails),
        (status = 422, body = ProblemDetails)
    )
)]
#[allow(clippy::too_many_lines)]
async fn commit_import(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(body): Json<ImportCommitRequest>,
) -> Result<Json<ImportCommitResponse>, ApiError> {
    let started_at = Utc::now();
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    let (descriptor, outcome) = normalize_import(&body.preview, &identity)?;
    if outcome.batch.receipt.canonical_digest != body.confirm_canonical_digest {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "import_digest_mismatch",
        ));
    }
    sample_data::require_live_connector(&state, outcome.batch.receipt.connector_instance_id)
        .await?;
    let usages = findings_from_observations(&state, &outcome.batch.observations).await?;
    let receipt = &outcome.batch.receipt;
    let cursor_before = state
        .postgres
        .connector_cursor(receipt.connector_instance_id)
        .await
        .map_err(ApiError::dependency)?
        .unwrap_or_default();
    state
        .postgres
        .register_connector_named(
            receipt.installation_id,
            receipt.connector_instance_id,
            &descriptor,
            body.preview.friendly_name.as_deref(),
        )
        .await
        .map_err(ApiError::dependency)?;
    let admission = state
        .postgres
        .begin_ingestion(receipt)
        .await
        .map_err(ApiError::dependency)?;
    let run_id = uuid::Uuid::now_v7();
    let redaction_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&outcome.redaction).map_err(ApiError::dependency)?,
    ));
    let (status, accepted, deduplicated, findings_updated) = match admission.disposition {
        BatchDisposition::Accepted | BatchDisposition::Retry => {
            if estate::append_ai(
                &state,
                &outcome.batch.observations,
                &receipt.canonical_digest,
            )
            .await
            .is_err()
            {
                state
                    .postgres
                    .fail_ingestion(admission.batch_id, "observations_append_failed")
                    .await
                    .map_err(ApiError::dependency)?;
                let failed = import_run_record(
                    run_id,
                    started_at,
                    cursor_before,
                    &outcome,
                    admission.batch_id,
                    ConnectorRunStatus::Failed,
                    0,
                    0,
                    Some("observations_append_failed".to_owned()),
                    redaction_digest,
                );
                state
                    .postgres
                    .record_connector_run(&failed)
                    .await
                    .map_err(ApiError::dependency)?;
                return Err(ApiError::dependency_message("observations_append_failed"));
            }
            let resolved = match state
                .postgres
                .complete_ingestion_with_usage(admission.batch_id, &usages)
                .await
            {
                Ok(resolved) => resolved,
                Err(error) => {
                    tracing::error!(
                        batch_id = %admission.batch_id,
                        connector_instance_id = %receipt.connector_instance_id,
                        error = %error,
                        "finding batch persistence failed"
                    );
                    state
                        .postgres
                        .fail_ingestion(admission.batch_id, "finding_persist_failed")
                        .await
                        .map_err(ApiError::dependency)?;
                    let failed = import_run_record(
                        run_id,
                        started_at,
                        cursor_before,
                        &outcome,
                        admission.batch_id,
                        ConnectorRunStatus::Failed,
                        0,
                        0,
                        Some("finding_persist_failed".to_owned()),
                        redaction_digest,
                    );
                    state
                        .postgres
                        .record_connector_run(&failed)
                        .await
                        .map_err(ApiError::dependency)?;
                    return Err(ApiError::dependency_message("finding_persist_failed"));
                }
            };
            (
                ConnectorRunStatus::Completed,
                outcome.stats.accepted,
                0,
                resolved,
            )
        }
        // The first successful admission already updated the durable finding. Replay the
        // idempotent AI storage and finding-context writes so evidence from a
        // different connector that arrived later (for example, a VPC flow) can still attach after
        // a restart. finding_observations keeps usage_count replay-safe.
        BatchDisposition::Duplicate => {
            estate::append_ai(
                &state,
                &outcome.batch.observations,
                &receipt.canonical_digest,
            )
            .await
            .map_err(|_| ApiError::dependency_message("observations_append_failed"))?;
            let resolved = state
                .postgres
                .record_usages(&usages)
                .await
                .map_err(|_| ApiError::dependency_message("finding_persist_failed"))?;
            (
                ConnectorRunStatus::Duplicate,
                0,
                outcome.stats.accepted,
                resolved,
            )
        }
        BatchDisposition::InProgress => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "import_already_in_progress",
            ));
        }
    };
    let run = import_run_record(
        run_id,
        started_at,
        cursor_before,
        &outcome,
        admission.batch_id,
        status,
        accepted,
        deduplicated,
        None,
        redaction_digest,
    );
    state
        .postgres
        .record_connector_run(&run)
        .await
        .map_err(ApiError::dependency)?;
    Ok(Json(ImportCommitResponse {
        run_id,
        batch_id: admission.batch_id,
        disposition: enum_name(admission.disposition, "accepted"),
        status: enum_name(status, "completed"),
        accepted,
        deduplicated,
        findings_updated,
        canonical_digest: receipt.canonical_digest.clone(),
        content_retained: false,
    }))
}

#[allow(clippy::too_many_lines)]
fn normalize_import(
    request: &ImportPreviewRequest,
    identity: &tally_store_postgres::InstallationIdentity,
) -> Result<(ConnectorDescriptor, VendorImportOutcome), ApiError> {
    if request
        .friendly_name
        .as_deref()
        .is_some_and(|name| !safe_connector_friendly_name(name))
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "connector_friendly_name_invalid",
        ));
    }
    if request.data.is_empty() || request.data.len() > MAX_IMPORT_BYTES {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "import_size_invalid",
        ));
    }
    if !safe_import_checkpoint(&request.checkpoint) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "import_checkpoint_invalid",
        ));
    }
    if request
        .source_lineage_id
        .as_deref()
        .is_some_and(|value| !safe_import_source_lineage(value))
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "import_source_lineage_invalid",
        ));
    }
    let descriptor = request.adapter.descriptor();
    let connector_instance_id = request.connector_instance_id.unwrap_or_else(|| {
        default_connector_instance_id(identity.installation_id, &descriptor.connector_type)
    });
    let source_lineage_id = Some(
        request
            .source_lineage_id
            .clone()
            .unwrap_or_else(|| "browser_file_import".to_owned()),
    );
    let received_at = Utc::now();
    let checkpoint = Cursor(request.checkpoint.clone());
    let pseudonymization_key = PseudonymizationKey::new(identity.pseudonymization_key())
        .map_err(|_| ApiError::dependency_message("installation_key_invalid"))?;
    let outcome = if request.adapter.is_managed_cloud() {
        if request.casb_account_id.is_some() {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "casb_scope_not_allowed",
            ));
        }
        let observed_at = request.observed_at.ok_or_else(|| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "cloud_observed_at_required",
            )
        })?;
        let scope = managed_cloud_scope(request.adapter, request.cloud_scope.as_ref())?;
        let config = ManagedCloudImportConfig {
            installation_id: identity.installation_id,
            connector_instance_id,
            implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
            source_lineage_id,
            observed_at,
            received_at,
            checkpoint,
            pseudonymization_key,
            scope,
            transport: request.adapter.cloud_transport(),
        };
        normalize_managed_cloud(request.adapter, request.data.as_bytes(), &config)?
    } else if request.adapter.is_casb() {
        if request.cloud_scope.is_some() || request.observed_at.is_some() {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "cloud_scope_not_allowed",
            ));
        }
        let account_id = request.casb_account_id.as_deref().ok_or_else(|| {
            ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "casb_scope_required")
        })?;
        let config = VendorImportConfig {
            installation_id: identity.installation_id,
            connector_instance_id,
            implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
            source_lineage_id,
            received_at,
            checkpoint,
            pseudonymization_key,
        };
        match request.adapter {
            ImportAdapterInput::CloudflareCasb => {
                import_cloudflare_casb_json(request.data.as_bytes(), account_id, &config)
            }
            ImportAdapterInput::CloudflareCasbApi => {
                import_cloudflare_casb_api_json(request.data.as_bytes(), account_id, &config)
            }
            _ => unreachable!("CASB branch accepts only CASB adapters"),
        }
        .map_err(|_| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "import_invalid"))?
    } else {
        if request.cloud_scope.is_some() || request.observed_at.is_some() {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "cloud_scope_not_allowed",
            ));
        }
        if request.casb_account_id.is_some() {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "casb_scope_not_allowed",
            ));
        }
        let config = VendorImportConfig {
            installation_id: identity.installation_id,
            connector_instance_id,
            implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
            source_lineage_id,
            received_at,
            checkpoint,
            pseudonymization_key,
        };
        request
            .adapter
            .normalize_vendor(request.data.as_bytes(), &config)?
    };
    Ok((descriptor, outcome))
}

fn managed_cloud_scope(
    adapter: ImportAdapterInput,
    scope: Option<&ManagedCloudScopeInput>,
) -> Result<ManagedCloudScope, ApiError> {
    match (adapter, scope) {
        (
            ImportAdapterInput::AwsManagedAi | ImportAdapterInput::AwsManagedAiApi,
            Some(ManagedCloudScopeInput::Aws { account_id, region }),
        ) => Ok(ManagedCloudScope::Aws {
            account_id: account_id.clone(),
            region: region.clone(),
            // Static AWS keys only flow through the schedule request's credential bundle; the
            // file/fixture preview path always runs without them.
            static_credentials: None,
        }),
        (
            ImportAdapterInput::AzureOpenai
            | ImportAdapterInput::AzureAiFoundry
            | ImportAdapterInput::AzureOpenaiApi
            | ImportAdapterInput::AzureAiFoundryApi,
            Some(ManagedCloudScopeInput::Azure {
                subscription_id,
                account_resource_id,
                region,
            }),
        ) => Ok(ManagedCloudScope::Azure {
            subscription_id: subscription_id.clone(),
            account_resource_id: account_resource_id.clone(),
            region: region.clone(),
            workspace_resource: None,
            static_credentials: None,
        }),
        (
            ImportAdapterInput::GcpVertexAi | ImportAdapterInput::GcpVertexAiApi,
            Some(ManagedCloudScopeInput::Gcp {
                project_id,
                location,
            }),
        ) => Ok(ManagedCloudScope::Gcp {
            project_id: project_id.clone(),
            location: location.clone(),
            static_credentials: None,
        }),
        _ => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "cloud_scope_invalid",
        )),
    }
}

fn normalize_managed_cloud(
    adapter: ImportAdapterInput,
    input: &[u8],
    config: &ManagedCloudImportConfig,
) -> Result<VendorImportOutcome, ApiError> {
    let outcome = match adapter {
        ImportAdapterInput::AwsManagedAi | ImportAdapterInput::AwsManagedAiApi => {
            import_aws_managed_ai_json(input, config)
        }
        ImportAdapterInput::AzureOpenai | ImportAdapterInput::AzureOpenaiApi => {
            import_azure_managed_ai_json(input, CloudProviderService::AzureOpenai, config)
        }
        ImportAdapterInput::AzureAiFoundry | ImportAdapterInput::AzureAiFoundryApi => {
            import_azure_managed_ai_json(input, CloudProviderService::AzureAiFoundry, config)
        }
        ImportAdapterInput::GcpVertexAi | ImportAdapterInput::GcpVertexAiApi => {
            import_gcp_vertex_ai_json(input, config)
        }
        _ => {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "cloud_adapter_invalid",
            ));
        }
    }
    .map_err(|_| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "import_invalid"))?;
    Ok(outcome.into())
}

fn safe_import_checkpoint(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2_048
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'_' | b'-'))
}

fn safe_import_source_lineage(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'_' | b'-'))
}

/// Bounds a credential the operator typed into the connector form.
///
/// Deliberately permissive about which characters are allowed — API tokens, resource IDs, and
/// filesystem paths all arrive through here — but strict about length and control characters,
/// which are the shapes that turn a credential into a header- or log-injection vector.
/// Bounds the operator-typed connector label before it reaches the store.
///
/// An empty name is the "unset" value and clears whatever was stored, so it is accepted.
fn safe_connector_friendly_name(value: &str) -> bool {
    value.trim() == value && value.chars().count() <= 120 && !value.chars().any(char::is_control)
}

fn safe_credential_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4_096
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn safe_ca_pem(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1_048_576
        && value.starts_with("-----BEGIN CERTIFICATE-----")
        && value.contains("-----END CERTIFICATE-----")
        && !value.contains('\0')
}

fn safe_gcp_service_account_json(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64 * 1_024
        && value.trim() == value
        && serde_json::from_str::<serde_json::Value>(value).is_ok_and(|json| json.is_object())
}

/// Seals the credential bundle with the installation-local `TALLY_SECRET_KEY`.
///
/// Returns `None` for a source that needs no credentials, which leaves whatever the job row
/// already holds untouched rather than erasing it.
fn seal_connector_credentials(
    cipher: &SecretCipher,
    credentials: &BTreeMap<String, String>,
) -> Result<Option<SealedCredentials>, ApiError> {
    if credentials.is_empty() {
        return Ok(None);
    }
    let plaintext = serde_json::to_string(credentials).map_err(ApiError::dependency)?;
    let (nonce, ciphertext) = cipher
        .encrypt(&plaintext)
        .map_err(|_| ApiError::dependency_message("connector_credentials_unsealable"))?;
    Ok(Some(SealedCredentials { nonce, ciphertext }))
}

fn unseal_connector_credentials(
    cipher: &SecretCipher,
    credentials: Option<&SealedCredentials>,
) -> Result<BTreeMap<String, String>, ApiError> {
    let Some(credentials) = credentials else {
        return Ok(BTreeMap::new());
    };
    let plaintext = cipher
        .decrypt(&credentials.nonce, &credentials.ciphertext)
        .map_err(|_| ApiError::dependency_message("connector_credentials_unreadable"))?;
    serde_json::from_str(&plaintext)
        .map_err(|_| ApiError::dependency_message("connector_credentials_unreadable"))
}

#[allow(clippy::too_many_lines)] // Keeps the public allowlist for all connector forms centralized.
fn connector_form_configuration(
    config_refs: &serde_json::Value,
    credentials: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    let Some(kind) = config_refs.get("kind").and_then(serde_json::Value::as_str) else {
        return fields;
    };
    match kind {
        "file_env_v1" => {
            add_reference_fields(&mut fields, config_refs, &["adapter", "region"]);
            add_credential_fields(&mut fields, credentials, &["account_id", "scope_id"]);
        }
        "nextdns_api_v1" => {
            add_reference_fields(&mut fields, config_refs, &["profile_id"]);
            add_renamed_reference_field(
                &mut fields,
                config_refs,
                "backfill_seconds",
                "initial_backfill_seconds",
            );
            add_renamed_reference_field(
                &mut fields,
                config_refs,
                "record_limit",
                "initial_record_limit",
            );
        }
        "cloud_api_v1" => {
            add_reference_fields(&mut fields, config_refs, &["adapter", "region"]);
            add_credential_fields(
                &mut fields,
                credentials,
                &[
                    "account_id",
                    "scope_id",
                    "workspace_resource",
                    "azure_tenant_id",
                    "azure_client_id",
                ],
            );
        }
        "cloud_network_api_v1" => {
            add_reference_fields(&mut fields, config_refs, &["adapter", "region"]);
            add_credential_fields(
                &mut fields,
                credentials,
                &[
                    "account_id",
                    "network_id",
                    "log_group",
                    "workspace_resource",
                    "azure_tenant_id",
                    "azure_client_id",
                ],
            );
            add_renamed_reference_field(
                &mut fields,
                config_refs,
                "backfill_seconds",
                "initial_backfill_seconds",
            );
        }
        "casb_api_v1" => {
            add_credential_fields(&mut fields, credentials, &["account_id"]);
        }
        "ai_gateway_api_v1" => {
            add_credential_fields(&mut fields, credentials, &["account_id"]);
            add_renamed_reference_field(
                &mut fields,
                config_refs,
                "backfill_seconds",
                "initial_backfill_seconds",
            );
            add_renamed_reference_field(
                &mut fields,
                config_refs,
                "record_limit",
                "initial_record_limit",
            );
        }
        "rapid7_edr_insightidr_api_v1" | "netskope_events_api_v1" => {
            add_reference_fields(&mut fields, config_refs, &["region", "event_type"]);
            add_credential_fields(&mut fields, credentials, &["log_id", "tenant_url"]);
            add_renamed_reference_field(
                &mut fields,
                config_refs,
                "backfill_seconds",
                "initial_backfill_seconds",
            );
        }
        "crowdstrike_edr_ngsiem_api_v1" => {
            add_reference_fields(&mut fields, config_refs, &["cloud"]);
            add_renamed_reference_field(
                &mut fields,
                config_refs,
                "backfill_seconds",
                "initial_backfill_seconds",
            );
            add_renamed_reference_field(
                &mut fields,
                config_refs,
                "record_limit",
                "initial_record_limit",
            );
        }
        "microsoft_defender_graph_hunting_v1" => {
            add_credential_fields(&mut fields, credentials, &["tenant_id", "client_id"]);
            add_renamed_reference_field(
                &mut fields,
                config_refs,
                "backfill_seconds",
                "initial_backfill_seconds",
            );
            add_renamed_reference_field(
                &mut fields,
                config_refs,
                "record_limit",
                "initial_record_limit",
            );
        }
        "cato_networks_events_feed_v1" => {
            add_credential_fields(&mut fields, credentials, &["account_id"]);
            add_reference_fields(&mut fields, config_refs, &["api_hostname"]);
            add_renamed_reference_field(
                &mut fields,
                config_refs,
                "backfill_seconds",
                "initial_backfill_seconds",
            );
            add_renamed_reference_field(
                &mut fields,
                config_refs,
                "record_limit",
                "initial_record_limit",
            );
        }
        "cloudflare_zero_trust_gateway_v1" => {
            add_credential_fields(&mut fields, credentials, &["account_id"]);
            add_reference_fields(
                &mut fields,
                config_refs,
                &[
                    "window_seconds",
                    "endpoint_url",
                    "bucket",
                    "prefix",
                    "region",
                    "object_limit",
                ],
            );
        }
        "kubernetes_api_v1" => {
            add_credential_fields(&mut fields, credentials, &["api_url"]);
        }
        "managed_agents_v1" => {
            add_reference_fields(&mut fields, config_refs, &["platform"]);
            add_credential_fields(
                &mut fields,
                credentials,
                &["base_url", "app_id", "scope_id"],
            );
        }
        "litellm_api_v1" => {
            add_credential_fields(&mut fields, credentials, &["base_url"]);
            add_renamed_reference_field(
                &mut fields,
                config_refs,
                "backfill_seconds",
                "initial_backfill_seconds",
            );
            add_renamed_reference_field(
                &mut fields,
                config_refs,
                "record_limit",
                "initial_record_limit",
            );
        }
        _ => {}
    }
    fields
}

fn add_reference_fields(
    fields: &mut BTreeMap<String, String>,
    config_refs: &serde_json::Value,
    keys: &[&str],
) {
    for key in keys {
        if let Some(value) = config_refs.get(*key).and_then(serde_json::Value::as_str) {
            fields.insert((*key).to_owned(), value.to_owned());
        }
    }
}

fn add_renamed_reference_field(
    fields: &mut BTreeMap<String, String>,
    config_refs: &serde_json::Value,
    source: &str,
    target: &str,
) {
    if let Some(value) = config_refs.get(source).and_then(serde_json::Value::as_str) {
        fields.insert(target.to_owned(), value.to_owned());
    }
}

fn add_credential_fields(
    fields: &mut BTreeMap<String, String>,
    credentials: &BTreeMap<String, String>,
    keys: &[&str],
) {
    for key in keys {
        if let Some(value) = credentials.get(*key) {
            fields.insert((*key).to_owned(), value.clone());
        }
    }
}

fn safe_cloud_region(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn safe_nextdns_profile_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn default_connector_instance_id(installation_id: uuid::Uuid, connector_type: &str) -> uuid::Uuid {
    uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        format!("godel-tally:{installation_id}:{connector_type}").as_bytes(),
    )
}

/// Bounded resolution pass over recent immutable observations.
///
/// The daemon holds the only registry, so classification and resolution run here rather than in a
/// client carrying its own bundle. This is the same path an admitted import takes, which means a
/// manual pass and an import produce identical projections, classifications and findings.
#[utoipa::path(
    post,
    path = "/api/v1/tally/resolve",
    request_body = ResolveRequest,
    responses(
        (status = 200, body = ResolveResponse),
        (status = 422, body = ProblemDetails)
    )
)]
async fn resolve_recent_observations(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(request): Json<ResolveRequest>,
) -> Result<Json<ResolveResponse>, ApiError> {
    let limit = request.limit.unwrap_or(DEFAULT_RESOLVE_LIMIT);
    if limit == 0 || limit > MAX_RESOLVE_LIMIT {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "resolve_limit_out_of_range",
        ));
    }
    let observations = state
        .observations
        .list_observations(limit)
        .await
        .map_err(ApiError::dependency)?;

    let registry = state.registry.snapshot();
    let mut classified = 0_u64;
    let mut unknown_candidates = 0_u64;
    let mut insufficient_metadata = 0_u64;
    for observation in &observations {
        let detection = detect(observation, &registry).map_err(ApiError::dependency)?;
        match detection.classification {
            DetectionClassification::Classified => classified += 1,
            DetectionClassification::UnknownCandidate => unknown_candidates += 1,
            DetectionClassification::InsufficientMetadata => insufficient_metadata += 1,
        }
    }
    let resolved_systems = resolve_imported_observations(&state, &observations).await?;

    Ok(Json(ResolveResponse {
        registry_version: state.registry_manifest.registry_version.clone(),
        observations_processed: observations.len() as u64,
        classified,
        unknown_candidates,
        insufficient_metadata,
        resolved_systems: resolved_systems as u64,
        content_retained: false,
    }))
}

async fn resolve_imported_observations(
    state: &AppState,
    observations: &[Observation],
) -> Result<usize, ApiError> {
    let mut finding_ids = HashSet::new();
    for usage in findings_from_observations(state, observations).await? {
        let finding_id = state
            .postgres
            .record_usage(&usage)
            .await
            .map_err(ApiError::dependency)?;
        finding_ids.insert(finding_id);
    }
    Ok(finding_ids.len())
}

/// Builds direct findings and adds a flow connector as supporting context only when one managed
/// invocation and one accepted outbound TLS flow form a unique provider-account and time-scoped
/// pair. Cloud clients may call an AI service in another region, so region is retained as context
/// but is not treated as an equality key. Ambiguous traffic is intentionally left unlinked.
async fn findings_from_observations(
    state: &AppState,
    observations: &[Observation],
) -> Result<Vec<ObservedUsage>, ApiError> {
    let registry = state.registry.snapshot();
    let mut usages = usages_from_observations(observations, &registry)?;
    if !observations.iter().any(|observation| {
        matches!(
            observation.kind,
            ObservationKind::CloudUsage | ObservationKind::NetworkFlow
        )
    }) {
        return Ok(usages);
    }
    let candidates = estate::correlation_candidates(state, observations).await?;
    usages.extend(correlate_cloud_flows(observations, &candidates, &registry)?);
    Ok(usages)
}

fn correlate_cloud_flows(
    current: &[Observation],
    candidates: &[Observation],
    registry: &RegistryBundle,
) -> Result<Vec<ObservedUsage>, ApiError> {
    let current_ids = current
        .iter()
        .map(|observation| observation.observation_id)
        .collect::<HashSet<_>>();
    let invocations = candidates
        .iter()
        .filter(|observation| {
            observation.kind == ObservationKind::CloudUsage
                && observation.cloud.usage_kind == Some(CloudUsageKind::Invocation)
                && observation.service.ai_request
        })
        .collect::<Vec<_>>();
    let flows = candidates
        .iter()
        .filter(|observation| cloud_flow_is_correlation_candidate(observation))
        .collect::<Vec<_>>();
    let mut correlated = Vec::new();
    for invocation in &invocations {
        let same_scope_flow_count = flows
            .iter()
            .filter(|flow| cloud_flow_same_scope(flow, invocation))
            .count();
        let service_match_flow_count = flows
            .iter()
            .filter(|flow| {
                cloud_flow_same_scope(flow, invocation)
                    && cloud_flow_service_matches(flow, invocation)
            })
            .count();
        let matching_flows = flows
            .iter()
            .copied()
            .filter(|flow| cloud_flow_matches_invocation(flow, invocation))
            .collect::<Vec<_>>();
        tracing::debug!(
            invocation_observation_id = %invocation.observation_id,
            candidate_flow_count = flows.len(),
            same_scope_flow_count,
            service_match_flow_count,
            matching_flow_count = matching_flows.len(),
            "evaluated managed-AI and cloud-flow correlation"
        );
        let [flow] = matching_flows.as_slice() else {
            continue;
        };
        if !current_ids.contains(&invocation.observation_id)
            && !current_ids.contains(&flow.observation_id)
        {
            continue;
        }
        if invocations
            .iter()
            .filter(|candidate| cloud_flow_matches_invocation(flow, candidate))
            .count()
            != 1
        {
            continue;
        }
        let Some(mut usage) = usage_from_observation(invocation, registry)? else {
            continue;
        };
        usage.observation_id = flow.observation_id;
        usage.connector_instance_id = flow.connector.instance_id;
        usage.observed_at = invocation.observed_at;
        usage.counts_as_usage = false;
        usage.endpoints.clear();
        let (source_hostname, source_ip) = if flow.network.direction == Some(FlowDirection::Ingress)
        {
            (
                flow.destination.host.as_ref().map(Hostname::as_str),
                flow.destination.ip.as_ref(),
            )
        } else {
            (
                flow.actor.hostname.as_deref(),
                flow.actor.source_ip.as_ref(),
            )
        };
        if let Some(hostname) = source_hostname {
            usage.endpoints.push(EndpointIdentity {
                kind: "hostname".to_owned(),
                value: hostname.to_owned(),
                role: "source".to_owned(),
                port: None,
            });
        }
        if let Some(source_ip) = source_ip {
            usage.endpoints.push(EndpointIdentity {
                kind: "ip_address".to_owned(),
                value: source_ip.as_str().to_owned(),
                role: "source".to_owned(),
                port: None,
            });
        }
        correlated.push(usage);
    }
    correlated.sort_by_key(|usage| (usage.observation_id, usage.connector_instance_id));
    correlated.dedup_by_key(|usage| (usage.observation_id, usage.connector_instance_id));
    Ok(correlated)
}

fn cloud_flow_is_correlation_candidate(observation: &Observation) -> bool {
    observation.kind == ObservationKind::NetworkFlow
        && observation.cloud.usage_kind == Some(CloudUsageKind::NetworkFlow)
        && observation.outcome.action.as_deref() == Some("accepted")
        && observation.network.protocol.as_deref() == Some("tcp")
        && match observation.network.direction {
            Some(FlowDirection::Ingress) => observation.network.source_port == Some(443),
            _ => {
                observation
                    .destination
                    .port
                    .or(observation.network.destination_port)
                    == Some(443)
            }
        }
}

fn cloud_flow_matches_invocation(flow: &Observation, invocation: &Observation) -> bool {
    if !cloud_flow_same_scope(flow, invocation) || !cloud_flow_service_matches(flow, invocation) {
        return false;
    }
    let end = flow.network.valid_until.unwrap_or(flow.observed_at);
    // AWS VPC Flow Logs aggregate traffic into windows whose reported start can trail the
    // CloudTrail event by several seconds. Keep the narrow tolerance for providers with
    // request-level timestamps, while allowing one AWS aggregation interval. The caller still
    // requires a unique flow and a unique invocation, so concurrent TLS traffic fails closed.
    let start_tolerance = if flow.cloud.provider == Some(tally_core::CloudProvider::Aws) {
        Duration::seconds(60)
    } else {
        Duration::seconds(5)
    };
    invocation.observed_at >= flow.observed_at - start_tolerance
        && invocation.observed_at <= end + Duration::seconds(5)
}

fn cloud_flow_same_scope(flow: &Observation, invocation: &Observation) -> bool {
    flow.installation_id == invocation.installation_id
        && flow.cloud.provider.is_some()
        && flow.cloud.provider == invocation.cloud.provider
        && flow.cloud.account_key.is_some()
        && flow.cloud.account_key == invocation.cloud.account_key
        && flow.connector.instance_id != invocation.connector.instance_id
}

fn cloud_flow_service_matches(flow: &Observation, invocation: &Observation) -> bool {
    let flow_service = if flow.network.direction == Some(FlowDirection::Ingress) {
        flow.actor.hostname.as_deref()
    } else {
        flow.destination.host.as_ref().map(Hostname::as_str)
    };
    let Some(flow_service) = flow_service else {
        // Google flow logs expose a serving-product label, and Azure Traffic Analytics exposes a
        // per-address service tag. Requiring those labels avoids correlating guest-agent, storage,
        // and identity traffic from the same VM. Default AWS v2 flow logs have no service label,
        // so AWS alone retains the unique account-and-time fallback.
        if flow.cloud.provider != Some(tally_core::CloudProvider::Aws) {
            return false;
        }
        let invocation_uses_vpc_endpoint = invocation
            .destination
            .host
            .as_ref()
            .is_some_and(|host| host.as_str().ends_with(".vpce.amazonaws.com"));
        return !invocation_uses_vpc_endpoint
            || flow.destination.ip.as_ref().is_some_and(private_ip_address);
    };
    invocation
        .destination
        .host
        .as_ref()
        .is_some_and(|host| host.as_str().ends_with(flow_service))
}

fn private_ip_address(address: &IpAddress) -> bool {
    address
        .as_str()
        .parse::<IpAddr>()
        .is_ok_and(|address| match address {
            IpAddr::V4(address) => address.is_private(),
            IpAddr::V6(address) => (address.segments()[0] & 0xfe00) == 0xfc00,
        })
}

fn usages_from_observations(
    observations: &[Observation],
    registry: &RegistryBundle,
) -> Result<Vec<ObservedUsage>, ApiError> {
    observations
        .iter()
        .map(|observation| usage_from_observation(observation, registry))
        .filter_map(Result::transpose)
        .collect()
}

#[allow(clippy::too_many_lines)]
fn usage_from_observation(
    observation: &Observation,
    registry: &RegistryBundle,
) -> Result<Option<ObservedUsage>, ApiError> {
    // Preserve what the evidence actually proves. Generic inventory, capability, mapping, and
    // health records remain ineligible. An explicitly registry-matched Kubernetes runtime is an
    // actionable resource discovery, not a model invocation.
    let evidence_kind = match observation.kind {
        ObservationKind::DnsQuery | ObservationKind::NetworkFlow => {
            FindingEvidenceKind::NetworkActivity
        }
        ObservationKind::ScanFingerprint | ObservationKind::KubernetesResource => {
            FindingEvidenceKind::ResourceDiscovery
        }
        ObservationKind::HttpMetadata | ObservationKind::CloudUsage => FindingEvidenceKind::AiUsage,
        _ => return Ok(None),
    };
    if observation.kind == ObservationKind::KubernetesResource
        && observation.workload.runtime_registry_entry_id.is_none()
    {
        return Ok(None);
    }
    if observation.kind == ObservationKind::HttpMetadata
        && observation.service.ai_request_evaluated
        && !observation.service.ai_request
    {
        return Ok(None);
    }
    let detection = detect(observation, registry)
        .map_err(|_| ApiError::dependency_message("registry_detection_failed"))?;
    let explicit_entry_id = observation
        .workload
        .runtime_registry_entry_id
        .as_deref()
        .or(observation.service.vendor_application_id.as_deref());
    let matched_entry = explicit_entry_id
        .and_then(|id| registry.entries.iter().find(|entry| entry.id == id))
        .or_else(|| {
            detection.matches.first().and_then(|hit| {
                registry
                    .entries
                    .iter()
                    .find(|entry| entry.id == hit.entry_id)
            })
        });
    let provider_entry = matched_entry.and_then(|entry| {
        if entry.kind == RegistryEntryKind::Provider {
            Some(entry)
        } else {
            entry.provider_ref.as_deref().and_then(|provider_ref| {
                registry
                    .entries
                    .iter()
                    .find(|candidate| candidate.id == provider_ref)
            })
        }
    });

    let cloud_provider = match observation.cloud.provider_service {
        Some(
            tally_core::CloudProviderService::AwsBedrock
            | tally_core::CloudProviderService::AwsSagemaker,
        ) => Some(("aws-bedrock", "Amazon Bedrock", "managed_platform", "US")),
        Some(
            tally_core::CloudProviderService::AzureOpenai
            | tally_core::CloudProviderService::AzureAiFoundry,
        ) => Some(("azure-ai", "Microsoft Azure AI", "managed_platform", "US")),
        Some(tally_core::CloudProviderService::GcpVertexAi) => {
            Some(("google", "Google AI", "managed_platform", "US"))
        }
        None => None,
    };
    let provider = provider_entry
        .map(|entry| {
            (
                entry.id.trim_start_matches("provider.").to_owned(),
                entry.name.clone(),
                registry_provider_category(observation, matched_entry).to_owned(),
                None,
                true,
            )
        })
        .or_else(|| {
            cloud_provider.map(|(key, name, category, country)| {
                (
                    key.to_owned(),
                    name.to_owned(),
                    category.to_owned(),
                    Some(country.to_owned()),
                    true,
                )
            })
        })
        .or_else(|| {
            matched_entry.map(|entry| {
                (
                    entry.id.clone(),
                    entry.name.clone(),
                    registry_provider_category(observation, Some(entry)).to_owned(),
                    None,
                    false,
                )
            })
        })
        .or_else(|| {
            observation
                .service
                .ai_request
                .then_some(explicit_entry_id)
                .flatten()
                .map(|entry_id| {
                    (
                        entry_id.to_owned(),
                        entry_id
                            .strip_prefix("discovered.provider.")
                            .unwrap_or(entry_id)
                            .replace(['.', '_', '-'], " "),
                        "direct_provider".to_owned(),
                        None,
                        false,
                    )
                })
        })
        .or_else(|| {
            (observation.kind == ObservationKind::HttpMetadata && observation.service.ai_request)
                .then_some(observation.destination.host.as_ref())
                .flatten()
                .map(|host| {
                    (
                        format!("discovered.host.{}", host.as_str()),
                        host.as_str().to_owned(),
                        "direct_provider".to_owned(),
                        None,
                        false,
                    )
                })
        })
        .or_else(|| {
            (observation.kind == ObservationKind::HttpMetadata && observation.service.ai_request)
                .then_some(observation.destination.ip.as_ref())
                .flatten()
                .map(|address| {
                    (
                        format!("discovered.ip.{}", address.as_str()),
                        address.as_str().to_owned(),
                        "direct_provider".to_owned(),
                        None,
                        false,
                    )
                })
        });
    let Some((provider_key, provider_name, provider_category, provider_country_code, catalogued)) =
        provider
    else {
        return Ok(None);
    };

    let model_reference = observation.service.declared_model_id.clone();
    let destination_port = observation
        .destination
        .port
        .or(observation.network.destination_port);
    let mut destination_candidates = Vec::with_capacity(3);
    if let Some(host) = observation.destination.host.as_ref() {
        destination_candidates.push(DestinationIdentity {
            kind: "hostname".to_owned(),
            value: host.as_str().to_owned(),
            port: destination_port,
        });
    }
    if let Some(host) = observation.service.tls_server_name.as_ref()
        && !destination_candidates
            .iter()
            .any(|destination| destination.kind == "hostname" && destination.value == host.as_str())
    {
        destination_candidates.push(DestinationIdentity {
            kind: "hostname".to_owned(),
            value: host.as_str().to_owned(),
            port: destination_port,
        });
    }
    if let Some(address) = observation.destination.ip.as_ref() {
        destination_candidates.push(DestinationIdentity {
            kind: "ip_address".to_owned(),
            value: address.as_str().to_owned(),
            port: destination_port,
        });
    }
    let local_service = observation.kind == ObservationKind::ScanFingerprint
        || matches!(
            provider_category.as_str(),
            "local_runtime" | "inference_server"
        );
    let mut endpoints = Vec::with_capacity(3);
    let destinations =
        if local_service {
            endpoints.extend(destination_candidates.into_iter().map(|destination| {
                EndpointIdentity {
                    kind: destination.kind,
                    value: destination.value,
                    role: "local_service".to_owned(),
                    port: destination.port,
                }
            }));
            Vec::new()
        } else {
            destination_candidates
        };
    if let Some(hostname) = observation.actor.hostname.as_ref() {
        endpoints.push(EndpointIdentity {
            kind: "hostname".to_owned(),
            value: hostname.clone(),
            role: "source".to_owned(),
            port: None,
        });
    }
    if let Some(address) = observation.actor.source_ip.as_ref() {
        endpoints.push(EndpointIdentity {
            kind: "ip_address".to_owned(),
            value: address.as_str().to_owned(),
            role: "source".to_owned(),
            port: None,
        });
    }
    for address in observation.actor.additional_source_ips.iter().take(8) {
        if !endpoints
            .iter()
            .any(|endpoint| endpoint.kind == "ip_address" && endpoint.value == address.as_str())
        {
            endpoints.push(EndpointIdentity {
                kind: "ip_address".to_owned(),
                value: address.as_str().to_owned(),
                role: "source".to_owned(),
                port: None,
            });
        }
    }
    let user_identity = observation.actor.identity.as_ref().and_then(|identity| {
        if let Some(email) = identity.email.as_ref() {
            Some(UserIdentity {
                kind: "email".to_owned(),
                value: email.clone(),
                email: Some(email.clone()),
            })
        } else {
            let value = identity.source_subject.as_ref()?;
            let kind = match identity.source_subject_kind? {
                IdentitySubjectKind::UserName => "user_name",
                IdentitySubjectKind::SourceUserId => "source_user_id",
            };
            Some(UserIdentity {
                kind: kind.to_owned(),
                value: value.clone(),
                email: None,
            })
        }
    });
    let workloads = if observation.kind == ObservationKind::KubernetesResource {
        observation
            .workload
            .namespace_name
            .as_ref()
            .zip(observation.workload.workload_name.as_ref())
            .zip(observation.workload.workload_kind)
            .map(|((namespace_name, workload_name), workload_kind)| {
                vec![WorkloadIdentity {
                    namespace_name: namespace_name.clone(),
                    workload_name: workload_name.clone(),
                    workload_kind: kubernetes_workload_kind(workload_kind).to_owned(),
                    runtime_image: observation.workload.runtime_image.clone(),
                }]
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    Ok(Some(ObservedUsage {
        observation_id: observation.observation_id,
        installation_id: observation.installation_id,
        provider_key,
        provider_name,
        provider_category,
        provider_country_code,
        provider_catalogued: catalogued,
        model_reference,
        observed_at: observation.observed_at,
        connector_instance_id: observation.connector.instance_id,
        evidence_kind,
        counts_as_usage: true,
        endpoints,
        destinations,
        workloads,
        user_identity,
        request_client: observation.actor.request_client.clone(),
    }))
}

const fn kubernetes_workload_kind(kind: tally_core::WorkloadKind) -> &'static str {
    match kind {
        tally_core::WorkloadKind::Deployment => "deployment",
        tally_core::WorkloadKind::StatefulSet => "stateful_set",
        tally_core::WorkloadKind::DaemonSet => "daemon_set",
        tally_core::WorkloadKind::Job => "job",
        tally_core::WorkloadKind::CronJob => "cron_job",
        tally_core::WorkloadKind::Pod => "pod",
        tally_core::WorkloadKind::Service => "service",
        tally_core::WorkloadKind::Node => "node",
    }
}

fn registry_provider_category(
    observation: &Observation,
    entry: Option<&RegistryEntry>,
) -> &'static str {
    let has_category = |category: &str| {
        entry.is_some_and(|entry| entry.categories.iter().any(|value| value == category))
    };
    if observation.cloud.provider_service.is_some() {
        "managed_platform"
    } else if has_category("ai_gateway") || has_category("llm_proxy") {
        "ai_gateway"
    } else if has_category("enterprise_application") || has_category("embedded_ai") {
        "enterprise_application"
    } else if has_category("inference_server") {
        "inference_server"
    } else if observation.kind == ObservationKind::ScanFingerprint
        || entry.is_some_and(|entry| entry.id.starts_with("runtime."))
    {
        "local_runtime"
    } else {
        "direct_provider"
    }
}

async fn project_cloud_usage(
    state: &AppState,
    installation_id: uuid::Uuid,
    affected_system_ids: &mut HashSet<uuid::Uuid>,
) -> Result<(), ApiError> {
    let scan = state
        .postgres
        .scan_cloud_usage_projections(installation_id, 10_000)
        .await
        .map_err(|_| ApiError::dependency_message("cloud_usage_scan_failed"))?;
    for input in scan.conflicts {
        let conflict = resolve_cloud_usage_conflict(&input)
            .map_err(|_| ApiError::dependency_message("cloud_usage_conflict_invalid"))?;
        state
            .postgres
            .dispute_cloud_usage_projection(installation_id, input.flow_observation_id)
            .await
            .map_err(|_| ApiError::dependency_message("cloud_usage_dispute_failed"))?;
        state
            .postgres
            .put_attribution_conflict(&conflict)
            .await
            .map_err(|_| ApiError::dependency_message("cloud_usage_conflict_persist_failed"))?;
    }
    for input in scan.projections {
        let projection = resolve_cloud_usage(&input)
            .map_err(|_| ApiError::dependency_message("cloud_usage_resolution_failed"))?;
        state
            .postgres
            .put_cloud_usage_projection(&projection)
            .await
            .map_err(|_| ApiError::dependency_message("cloud_usage_persist_failed"))?;
        state
            .postgres
            .clear_cloud_usage_conflict(
                installation_id,
                input.flow_relationship_id,
                input.flow_evidence.observation_id,
                input.valid_from,
            )
            .await
            .map_err(|_| ApiError::dependency_message("cloud_usage_conflict_clear_failed"))?;
        affected_system_ids.insert(input.system_id);
    }
    Ok(())
}

async fn persist_network_observation(
    state: &AppState,
    observation: &Observation,
) -> Result<(), ApiError> {
    let resolved = resolve_cloud_network(observation)
        .map_err(|_| ApiError::dependency_message("network_resolution_failed"))?;
    for entity in &resolved.entities {
        state
            .postgres
            .put_entity(entity)
            .await
            .map_err(|_| ApiError::dependency_message("network_entity_persist_failed"))?;
    }
    for key in &resolved.keys {
        state
            .postgres
            .put_entity_key(key)
            .await
            .map_err(|_| ApiError::dependency_message("network_key_persist_failed"))?;
    }
    for relationship in &resolved.relationships {
        state
            .postgres
            .put_entity_relationship(&relationship.relationship, &relationship.evidence)
            .await
            .map_err(|error| {
                tracing::warn!(
                    relationship_id = %relationship.relationship.relationship_id,
                    predicate = ?relationship.relationship.predicate,
                    error = %error,
                    "network relationship persistence failed"
                );
                ApiError::dependency_message("network_relationship_persist_failed")
            })?;
    }
    Ok(())
}

async fn apply_persistent_classification_rules(
    state: &AppState,
    system_ids: &HashSet<uuid::Uuid>,
) -> Result<(), ApiError> {
    if system_ids.is_empty() {
        return Ok(());
    }
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    let rule_sets = state
        .postgres
        .list_active_classification_rule_sets(identity.installation_id)
        .await
        .map_err(ApiError::dependency)?
        .into_iter()
        .map(classification_rule_set_response)
        .collect::<Result<Vec<_>, _>>()?;
    if rule_sets.is_empty() {
        return Ok(());
    }
    for system_id in system_ids {
        let evidence = state
            .postgres
            .list_system_evidence(*system_id)
            .await
            .map_err(ApiError::dependency)?;
        let observation_ids = evidence
            .into_iter()
            .flat_map(|link| link.observation_ids)
            .collect::<BTreeSet<_>>();
        let mut matching_rule_set_ids = BTreeSet::new();
        let mut decisions = BTreeSet::new();
        for observation_id in observation_ids {
            let Some(observation) = state
                .observations
                .get_observation(observation_id)
                .await
                .map_err(ApiError::dependency)?
            else {
                continue;
            };
            let Some(host) = classification_observation_host(&observation) else {
                continue;
            };
            for rule_set in &rule_sets {
                if rule_set
                    .rules
                    .iter()
                    .any(|rule| classification_rule_matches(rule, host))
                {
                    matching_rule_set_ids.insert(rule_set.rule_set_id);
                    decisions.insert(rule_set.decision.key());
                }
            }
        }
        if decisions.len() > 1 {
            let rule_set_ids = matching_rule_set_ids.into_iter().collect::<Vec<_>>();
            state
                .postgres
                .record_classification_rule_conflict(*system_id, &rule_set_ids, Utc::now())
                .await
                .map_err(ApiError::dependency)?;
            continue;
        }
        let Some(rule_set) = rule_sets
            .iter()
            .find(|rule_set| matching_rule_set_ids.contains(&rule_set.rule_set_id))
        else {
            continue;
        };
        match state
            .postgres
            .apply_classification_rule_set_to_system(
                identity.installation_id,
                rule_set.rule_set_id,
                *system_id,
                Utc::now(),
            )
            .await
            .map_err(ApiError::from_store)?
        {
            ClassificationApplyOutcome::Applied
            | ClassificationApplyOutcome::Unchanged
            | ClassificationApplyOutcome::Conflict => {}
        }
    }
    Ok(())
}

async fn evaluate_imported_systems(
    state: &AppState,
    system_ids: &HashSet<uuid::Uuid>,
) -> Result<(), ApiError> {
    let evaluated_at = Utc::now();
    for system_id in system_ids {
        let links = state
            .postgres
            .list_system_evidence(*system_id)
            .await
            .map_err(ApiError::dependency)?;
        let mut source_ids = HashSet::new();
        for observation_id in links
            .iter()
            .flat_map(|link| link.observation_ids.iter().copied())
        {
            if let Some(observation) = state
                .observations
                .get_observation(observation_id)
                .await
                .map_err(ApiError::dependency)?
            {
                source_ids.insert(observation.connector.instance_id);
            }
        }
        let system = state
            .postgres
            .get_ai_system(*system_id)
            .await
            .map_err(ApiError::dependency)?
            .ok_or_else(|| ApiError::dependency_message("resolved_system_missing"))?;
        let source_count = u32::try_from(source_ids.len()).unwrap_or(u32::MAX);
        let findings = evaluate_baseline(&PolicyEvaluationInput {
            system: &system,
            evidence_source_count: source_count,
            evaluated_at,
        });
        state
            .postgres
            .replace_system_findings(
                &system,
                BASELINE_POLICY_ID,
                BASELINE_POLICY_VERSION,
                source_count,
                evaluated_at,
                &findings,
            )
            .await
            .map_err(ApiError::dependency)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn import_run_record(
    run_id: uuid::Uuid,
    started_at: DateTime<Utc>,
    cursor_before: String,
    outcome: &VendorImportOutcome,
    batch_id: uuid::Uuid,
    status: ConnectorRunStatus,
    accepted: u64,
    deduplicated: u64,
    error_code: Option<String>,
    redaction_digest: String,
) -> ConnectorRunRecord {
    let first_source_at = outcome
        .batch
        .observations
        .iter()
        .map(|observation| observation.observed_at)
        .min();
    let last_source_at = outcome
        .batch
        .observations
        .iter()
        .map(|observation| observation.observed_at)
        .max();
    ConnectorRunRecord {
        run_id,
        connector_instance_id: outcome.batch.receipt.connector_instance_id,
        installation_id: outcome.batch.receipt.installation_id,
        connector_type: outcome.batch.receipt.connector_type.clone(),
        status,
        started_at,
        completed_at: Utc::now(),
        cursor_before,
        cursor_after: outcome.batch.receipt.checkpoint.0.clone(),
        first_source_at,
        last_source_at,
        records_read: outcome.stats.records_read,
        accepted,
        ignored: outcome.stats.ignored,
        rejected: outcome.stats.rejected,
        deduplicated,
        batch_id: Some(batch_id),
        error_code,
        redaction_digest,
    }
}

fn import_preview_response(
    descriptor: &ConnectorDescriptor,
    outcome: &VendorImportOutcome,
) -> ImportPreviewResponse {
    ImportPreviewResponse {
        descriptor: ImportDescriptorResponse {
            connector_type: descriptor.connector_type.clone(),
            display_name: descriptor.display_name.clone(),
            source_vendor: descriptor.source_vendor.clone(),
            source_product: descriptor.source_product.clone(),
            transport: enum_name(descriptor.transport, "file"),
            required_permissions: descriptor.required_permissions.clone(),
            requested_fields: descriptor.requested_fields.clone(),
            prohibited_fields: descriptor.prohibited_fields.clone(),
            privacy_contract: descriptor.privacy_contract.clone(),
        },
        records_read: outcome.stats.records_read,
        accepted: outcome.stats.accepted,
        ignored: outcome.stats.ignored,
        rejected: outcome.stats.rejected,
        connector_instance_id: outcome.batch.receipt.connector_instance_id,
        canonical_digest: outcome.batch.receipt.canonical_digest.clone(),
        observation_count: outcome.batch.receipt.observation_count,
        redaction: ImportRedactionResponse {
            pseudonymization: outcome.redaction.pseudonymization.clone(),
            discarded_fields: outcome.redaction.discarded_fields.clone(),
            source_bytes_retained: outcome.redaction.source_bytes_retained,
        },
        samples: outcome
            .batch
            .observations
            .iter()
            .take(10)
            .map(|observation| ImportSampleResponse {
                observed_at: observation.observed_at,
                kind: enum_name(observation.kind, "unknown"),
                destination: event_destination(observation),
                actor: event_actor(observation),
                outcome: event_outcome(observation),
            })
            .collect(),
        writes_data: false,
        source_bytes_retained: false,
        content_retained: false,
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImportAdapterInput {
    DefenderStream,
    ServicenowAgents,
    N8nAgents,
    CopilotStudioAgents,
    LanggraphAgents,
    DifyAgents,
    OpenaiAgents,
    ClaudeAgents,
    GeminiAgents,
    Nextdns,
    NextdnsApi,
    CloudflareGateway,
    Zscaler,
    PaloAlto,
    AwsManagedAi,
    AwsManagedAiApi,
    AzureOpenai,
    AzureOpenaiApi,
    AzureAiFoundry,
    AzureAiFoundryApi,
    GcpVertexAi,
    GcpVertexAiApi,
    AwsCloudFlow,
    AwsNetworkMapping,
    AzureCloudFlow,
    AzureNetworkMapping,
    GcpCloudFlow,
    GcpNetworkMapping,
    AwsCloudFlowApi,
    AwsNetworkMappingApi,
    AzureCloudFlowApi,
    AzureNetworkMappingApi,
    GcpCloudFlowApi,
    GcpNetworkMappingApi,
    CloudflareCasb,
    CloudflareCasbApi,
    KubernetesApi,
    KubernetesApiPull,
    Litellm,
    LitellmApi,
    CloudflareAiGateway,
    CloudflareAiGatewayApi,
    CrowdstrikeEdr,
    Rapid7Edr,
    Netskope,
    MicrosoftDefenderApi,
    CatoNetworksApi,
    CloudflareZeroTrustGateway,
}

impl ImportAdapterInput {
    fn descriptor(self) -> ConnectorDescriptor {
        match self {
            Self::DefenderStream => tally_connectors::defender_stream_descriptor(),
            Self::ServicenowAgents => tally_connectors::managed_agents_descriptor("servicenow"),
            Self::N8nAgents => tally_connectors::managed_agents_descriptor("n8n"),
            Self::CopilotStudioAgents => {
                tally_connectors::managed_agents_descriptor("copilot_studio")
            }
            Self::LanggraphAgents => tally_connectors::managed_agents_descriptor("langgraph"),
            Self::DifyAgents => tally_connectors::managed_agents_descriptor("dify"),
            Self::OpenaiAgents => tally_connectors::managed_agents_descriptor("openai"),
            Self::ClaudeAgents => tally_connectors::managed_agents_descriptor("claude"),
            Self::GeminiAgents => tally_connectors::managed_agents_descriptor("gemini"),
            Self::Nextdns => nextdns_descriptor(),
            Self::NextdnsApi => nextdns_api_descriptor(),
            Self::CloudflareGateway => cloudflare_gateway_descriptor(),
            Self::Zscaler => zscaler_descriptor(),
            Self::PaloAlto => palo_alto_descriptor(),
            Self::AwsManagedAi => aws_managed_ai_descriptor(),
            Self::AwsManagedAiApi => aws_managed_ai_api_descriptor(),
            Self::AzureOpenai | Self::AzureAiFoundry => azure_managed_ai_descriptor(),
            Self::AzureOpenaiApi | Self::AzureAiFoundryApi => azure_managed_ai_api_descriptor(),
            Self::GcpVertexAi => gcp_vertex_ai_descriptor(),
            Self::GcpVertexAiApi => gcp_vertex_ai_api_descriptor(),
            Self::AwsCloudFlow => cloud_flow_descriptor(CloudFlowProvider::Aws),
            Self::AwsNetworkMapping => cloud_mapping_descriptor(CloudFlowProvider::Aws),
            Self::AzureCloudFlow => cloud_flow_descriptor(CloudFlowProvider::Azure),
            Self::AzureNetworkMapping => cloud_mapping_descriptor(CloudFlowProvider::Azure),
            Self::GcpCloudFlow => cloud_flow_descriptor(CloudFlowProvider::Gcp),
            Self::GcpNetworkMapping => cloud_mapping_descriptor(CloudFlowProvider::Gcp),
            Self::AwsCloudFlowApi => cloud_flow_api_descriptor(CloudFlowProvider::Aws),
            Self::AwsNetworkMappingApi => cloud_mapping_api_descriptor(CloudFlowProvider::Aws),
            Self::AzureCloudFlowApi => cloud_flow_api_descriptor(CloudFlowProvider::Azure),
            Self::AzureNetworkMappingApi => cloud_mapping_api_descriptor(CloudFlowProvider::Azure),
            Self::GcpCloudFlowApi => cloud_flow_api_descriptor(CloudFlowProvider::Gcp),
            Self::GcpNetworkMappingApi => cloud_mapping_api_descriptor(CloudFlowProvider::Gcp),
            Self::CloudflareCasb => cloudflare_casb_descriptor(),
            Self::CloudflareCasbApi => cloudflare_casb_api_descriptor(),
            Self::KubernetesApi => kubernetes_api_descriptor(),
            Self::KubernetesApiPull => kubernetes_api_pull_descriptor(),
            Self::Litellm => litellm_model_groups_descriptor(),
            Self::LitellmApi => litellm_model_groups_api_descriptor(),
            Self::CloudflareAiGateway => cloudflare_ai_gateway_descriptor(),
            Self::CloudflareAiGatewayApi => cloudflare_ai_gateway_api_descriptor(),
            Self::Rapid7Edr => tally_connectors::SecurityLogSource::Rapid7Edr.descriptor(),
            Self::Netskope => tally_connectors::SecurityLogSource::Netskope.descriptor(),
            Self::CrowdstrikeEdr => crowdstrike_edr_api_descriptor(),
            Self::MicrosoftDefenderApi => microsoft_defender_edr_api_descriptor(),
            Self::CatoNetworksApi => cato_networks_api_descriptor(),
            Self::CloudflareZeroTrustGateway => cloudflare_zero_trust_gateway_descriptor(),
        }
    }

    const fn is_managed_cloud(self) -> bool {
        matches!(
            self,
            Self::AwsManagedAi
                | Self::AwsManagedAiApi
                | Self::AzureOpenai
                | Self::AzureOpenaiApi
                | Self::AzureAiFoundry
                | Self::AzureAiFoundryApi
                | Self::GcpVertexAi
                | Self::GcpVertexAiApi
        )
    }

    const fn is_native_cloud_network(self) -> bool {
        matches!(
            self,
            Self::AwsCloudFlowApi
                | Self::AwsNetworkMappingApi
                | Self::AzureCloudFlowApi
                | Self::AzureNetworkMappingApi
                | Self::GcpCloudFlowApi
                | Self::GcpNetworkMappingApi
        )
    }

    const fn is_casb(self) -> bool {
        matches!(self, Self::CloudflareCasb | Self::CloudflareCasbApi)
    }

    const fn is_kubernetes(self) -> bool {
        matches!(self, Self::KubernetesApi | Self::KubernetesApiPull)
    }

    const fn cloud_transport(self) -> ManagedCloudTransport {
        match self {
            Self::AwsManagedAiApi
            | Self::AzureOpenaiApi
            | Self::AzureAiFoundryApi
            | Self::GcpVertexAiApi => ManagedCloudTransport::NativeApi,
            _ => ManagedCloudTransport::File,
        }
    }

    const fn is_native_cloud(self) -> bool {
        matches!(self.cloud_transport(), ManagedCloudTransport::NativeApi)
    }

    fn normalize_vendor(
        self,
        input: &[u8],
        config: &VendorImportConfig,
    ) -> Result<VendorImportOutcome, ApiError> {
        let outcome = match self {
            Self::DefenderStream => tally_connectors::import_defender_stream_json(input, config),
            Self::ServicenowAgents
            | Self::N8nAgents
            | Self::CopilotStudioAgents
            | Self::LanggraphAgents
            | Self::OpenaiAgents
            | Self::ClaudeAgents
            | Self::GeminiAgents
            | Self::DifyAgents => tally_connectors::import_managed_agents_json(input, config),
            Self::Nextdns => import_nextdns_csv(input, config),
            Self::NextdnsApi => import_nextdns_api_json(input, config),
            Self::CloudflareGateway => import_cloudflare_gateway_ndjson(input, config),
            Self::Zscaler => import_zscaler_ndjson(input, config),
            Self::PaloAlto => import_palo_alto_ndjson(input, config),
            Self::AwsCloudFlow => import_cloud_flow_json(input, CloudFlowProvider::Aws, config),
            Self::AwsNetworkMapping => {
                import_cloud_mapping_json(input, CloudFlowProvider::Aws, config)
            }
            Self::AzureCloudFlow => import_cloud_flow_json(input, CloudFlowProvider::Azure, config),
            Self::AzureNetworkMapping => {
                import_cloud_mapping_json(input, CloudFlowProvider::Azure, config)
            }
            Self::GcpCloudFlow => import_cloud_flow_json(input, CloudFlowProvider::Gcp, config),
            Self::GcpNetworkMapping => {
                import_cloud_mapping_json(input, CloudFlowProvider::Gcp, config)
            }
            Self::AwsCloudFlowApi => {
                import_cloud_flow_api_json(input, CloudFlowProvider::Aws, config)
            }
            Self::AwsNetworkMappingApi => {
                import_cloud_mapping_api_json(input, CloudFlowProvider::Aws, config)
            }
            Self::AzureCloudFlowApi => {
                import_cloud_flow_api_json(input, CloudFlowProvider::Azure, config)
            }
            Self::AzureNetworkMappingApi => {
                import_cloud_mapping_api_json(input, CloudFlowProvider::Azure, config)
            }
            Self::GcpCloudFlowApi => {
                import_cloud_flow_api_json(input, CloudFlowProvider::Gcp, config)
            }
            Self::GcpNetworkMappingApi => {
                import_cloud_mapping_api_json(input, CloudFlowProvider::Gcp, config)
            }
            Self::KubernetesApi => import_kubernetes_api_json(input, config),
            Self::KubernetesApiPull => import_kubernetes_api_pull_json(input, config),
            Self::Litellm => import_litellm_model_groups_json(input, config),
            Self::LitellmApi => import_litellm_model_groups_api_json(input, config),
            Self::CloudflareAiGateway => import_cloudflare_ai_gateway_json(input, config),
            Self::CloudflareAiGatewayApi => import_cloudflare_ai_gateway_api_json(input, config),
            Self::Rapid7Edr => tally_connectors::import_security_logs_json(
                input,
                tally_connectors::SecurityLogSource::Rapid7Edr,
                config,
            ),
            Self::Netskope => tally_connectors::import_security_logs_json(
                input,
                tally_connectors::SecurityLogSource::Netskope,
                config,
            ),
            Self::CrowdstrikeEdr => import_crowdstrike_edr_dns_json(input, config),
            Self::MicrosoftDefenderApi => import_microsoft_defender_json(input, config),
            Self::CatoNetworksApi => import_cato_networks_json(input, config),
            Self::CloudflareZeroTrustGateway => {
                import_cloudflare_zero_trust_gateway_ndjson(input, config)
            }
            Self::CloudflareCasb | Self::CloudflareCasbApi => {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "casb_scope_required",
                ));
            }
            Self::AwsManagedAi
            | Self::AwsManagedAiApi
            | Self::AzureOpenai
            | Self::AzureOpenaiApi
            | Self::AzureAiFoundry
            | Self::AzureAiFoundryApi
            | Self::GcpVertexAi
            | Self::GcpVertexAiApi => {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "vendor_adapter_invalid",
                ));
            }
        }
        .map_err(|_| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "import_invalid"))?;
        Ok(outcome)
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/coverage",
    responses((status = 200, body = CoverageResponse))
)]
async fn coverage(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<CoverageResponse>, ApiError> {
    const OBSERVATION_LIMIT: u32 = 100_000;
    let (connectors, jobs, systems, evidence_edges, observation_total, observations) = tokio::join!(
        state.postgres.list_connector_states(),
        state.postgres.list_connector_jobs(),
        state.postgres.list_ai_systems(200, 0),
        state.postgres.list_system_evidence_index(),
        state.observations.observation_count(),
        state.observations.list_observations(OBSERVATION_LIMIT),
    );
    let connectors = connectors.map_err(ApiError::dependency)?;
    let jobs = jobs.map_err(ApiError::dependency)?;
    let systems = systems.map_err(ApiError::dependency)?;
    let evidence_edges = evidence_edges.map_err(ApiError::dependency)?;
    let observation_total = observation_total.map_err(ApiError::dependency)?;
    let observations = observations.map_err(ApiError::dependency)?;
    Ok(Json(build_coverage(
        &connectors,
        &jobs,
        &systems,
        &evidence_edges,
        observation_total,
        &observations,
        OBSERVATION_LIMIT,
    )))
}

fn build_coverage(
    connectors: &[ConnectorStateView],
    jobs: &[ConnectorJobView],
    systems: &[AiSystemView],
    evidence_edges: &[SystemEvidenceEdge],
    observation_total: u64,
    observations: &[Observation],
    observation_limit: u32,
) -> CoverageResponse {
    let generated_at = Utc::now();
    let observation_sources = observations
        .iter()
        .map(|observation| {
            (
                observation.observation_id,
                observation.connector.instance_id,
            )
        })
        .collect::<HashMap<_, _>>();
    let mut sources_by_system = HashMap::<uuid::Uuid, HashSet<uuid::Uuid>>::new();
    for edge in evidence_edges {
        if let Some(source_id) = observation_sources.get(&edge.observation_id) {
            sources_by_system
                .entry(edge.system_id)
                .or_default()
                .insert(*source_id);
        }
    }
    let actor_count = observations
        .iter()
        .filter_map(|observation| {
            observation
                .actor
                .identity
                .as_ref()
                .map(|identity| identity.subject_key.clone())
                .or_else(|| observation.actor.device_key.clone())
        })
        .collect::<HashSet<_>>()
        .len();
    let first_observed_at = observations.iter().map(|item| item.observed_at).min();
    let last_observed_at = observations.iter().map(|item| item.observed_at).max();
    let health_counts = coverage_health_counts(connectors);
    let corroborated_systems = systems
        .iter()
        .filter(|system| {
            sources_by_system
                .get(&system.system_id)
                .is_some_and(|sources| sources.len() >= 2)
        })
        .count();
    let strong_evidence_systems = systems
        .iter()
        .filter(|system| system.evidence_quality == tally_core::EvidenceQuality::Strong)
        .count();
    let source_items = coverage_source_items(connectors, jobs, generated_at);
    let (
        freshness_slo_met_sources,
        freshness_slo_breached_sources,
        freshness_slo_error_sources,
        freshness_slo_unmeasured_sources,
    ) = coverage_freshness_counts(&source_items);
    let blind_spots = coverage_blind_spots(
        &source_items,
        observation_total,
        observations.len(),
        observation_limit,
    );
    CoverageResponse {
        status: CoverageStatus::Unscored,
        weighted_percent: None,
        scoring_reason: "No authoritative zone or population denominator is configured.".to_owned(),
        configured_sources: source_items.len(),
        healthy_sources: health_counts.0,
        delayed_sources: health_counts.1,
        error_sources: health_counts.2,
        never_run_sources: health_counts.3,
        freshness_slo_met_sources,
        freshness_slo_breached_sources,
        freshness_slo_error_sources,
        freshness_slo_unmeasured_sources,
        systems_total: systems.len(),
        corroborated_systems,
        strong_evidence_systems,
        pseudonymous_actors_observed: actor_count,
        observation_total,
        observation_window_truncated: observation_total
            > u64::try_from(observations.len()).unwrap_or(u64::MAX),
        first_observed_at,
        last_observed_at,
        sources: source_items,
        blind_spots,
    }
}

fn coverage_source_items(
    connectors: &[ConnectorStateView],
    jobs: &[ConnectorJobView],
    generated_at: DateTime<Utc>,
) -> Vec<CoverageSourceResponse> {
    let jobs_by_connector = jobs
        .iter()
        .map(|job| (job.connector_instance_id, job))
        .collect::<HashMap<_, _>>();
    connectors
        .iter()
        .map(|connector| {
            let freshness = freshness_slo(
                connector,
                jobs_by_connector
                    .get(&connector.connector_instance_id)
                    .copied(),
                generated_at,
            );
            CoverageSourceResponse {
                connector_instance_id: connector.connector_instance_id,
                display_name: connector.display_name.clone(),
                friendly_name: optional_friendly_name(&connector.friendly_name),
                connector_type: connector.connector_type.clone(),
                health: enum_name(connector.health, "never_run"),
                lag_seconds: connector.lag_seconds,
                last_source_at: connector.last_source_at,
                freshness_slo_status: freshness.status,
                freshness_slo_seconds: freshness.target_seconds,
                source_age_seconds: freshness.source_age_seconds,
                breach_seconds: freshness.breach_seconds,
                alertable: freshness.alertable,
                records_read_total: connector.records_read_total,
                accepted_total: connector.accepted_total,
            }
        })
        .collect()
}

fn coverage_freshness_counts(sources: &[CoverageSourceResponse]) -> (usize, usize, usize, usize) {
    sources.iter().fold((0, 0, 0, 0), |mut counts, source| {
        match source.freshness_slo_status {
            FreshnessSloStatus::Met => counts.0 += 1,
            FreshnessSloStatus::Breached => counts.1 += 1,
            FreshnessSloStatus::Error => counts.2 += 1,
            FreshnessSloStatus::Unmeasured | FreshnessSloStatus::Paused => counts.3 += 1,
        }
        counts
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FreshnessSloEvaluation {
    status: FreshnessSloStatus,
    target_seconds: Option<i64>,
    source_age_seconds: Option<i64>,
    breach_seconds: Option<i64>,
    alertable: bool,
}

fn freshness_slo(
    connector: &ConnectorStateView,
    job: Option<&ConnectorJobView>,
    now: DateTime<Utc>,
) -> FreshnessSloEvaluation {
    let source_age_seconds = connector
        .last_source_at
        .map(|source_at| (now - source_at).num_seconds().max(0));
    let Some(job) = job else {
        return FreshnessSloEvaluation {
            status: FreshnessSloStatus::Unmeasured,
            target_seconds: None,
            source_age_seconds,
            breach_seconds: None,
            alertable: false,
        };
    };
    let target_seconds = job
        .schedule_seconds
        .map(|seconds| seconds.saturating_mul(3).clamp(900, 86_400));
    if job.status == ConnectorJobStatus::Paused {
        return FreshnessSloEvaluation {
            status: FreshnessSloStatus::Paused,
            target_seconds,
            source_age_seconds,
            breach_seconds: None,
            alertable: false,
        };
    }
    if connector.health == ConnectorHealth::Error {
        return FreshnessSloEvaluation {
            status: FreshnessSloStatus::Error,
            target_seconds,
            source_age_seconds,
            breach_seconds: None,
            alertable: true,
        };
    }
    let Some((target_seconds, source_age_seconds)) = target_seconds.zip(source_age_seconds) else {
        return FreshnessSloEvaluation {
            status: FreshnessSloStatus::Unmeasured,
            target_seconds,
            source_age_seconds,
            breach_seconds: None,
            alertable: false,
        };
    };
    let breach_seconds = source_age_seconds.saturating_sub(target_seconds).max(0);
    FreshnessSloEvaluation {
        status: if breach_seconds == 0 {
            FreshnessSloStatus::Met
        } else {
            FreshnessSloStatus::Breached
        },
        target_seconds: Some(target_seconds),
        source_age_seconds: Some(source_age_seconds),
        breach_seconds: (breach_seconds > 0).then_some(breach_seconds),
        alertable: breach_seconds > 0,
    }
}

fn coverage_health_counts(connectors: &[ConnectorStateView]) -> (usize, usize, usize, usize) {
    (
        connectors
            .iter()
            .filter(|connector| connector.health == ConnectorHealth::Healthy)
            .count(),
        connectors
            .iter()
            .filter(|connector| connector.health == ConnectorHealth::Delayed)
            .count(),
        connectors
            .iter()
            .filter(|connector| connector.health == ConnectorHealth::Error)
            .count(),
        connectors
            .iter()
            .filter(|connector| connector.health == ConnectorHealth::NeverRun)
            .count(),
    )
}

fn coverage_blind_spots(
    sources: &[CoverageSourceResponse],
    observation_total: u64,
    observation_count: usize,
    observation_limit: u32,
) -> Vec<CoverageBlindSpot> {
    let mut blind_spots = vec![CoverageBlindSpot {
        code: "population_denominator_missing".to_owned(),
        title: "Population denominator is not configured".to_owned(),
        detail: "Tally will not invent a weighted percentage until network zones or an authoritative population source are configured.".to_owned(),
        severity: "warning".to_owned(),
    }];
    for source in sources {
        if source.freshness_slo_status == FreshnessSloStatus::Breached {
            blind_spots.push(CoverageBlindSpot {
                code: "freshness_slo_breached".to_owned(),
                title: format!("{} breached its freshness SLO", source.display_name),
                detail: format!(
                    "The newest source evidence is {} seconds old against a {}-second target. Tally exposes this state for a host to alert on but sends no alert itself.",
                    source.source_age_seconds.unwrap_or_default(),
                    source.freshness_slo_seconds.unwrap_or_default(),
                ),
                severity: "warning".to_owned(),
            });
        } else if source.freshness_slo_status == FreshnessSloStatus::Error {
            blind_spots.push(CoverageBlindSpot {
                code: "source_error".to_owned(),
                title: format!("{} is unavailable", source.display_name),
                detail:
                    "The last connector attempt failed; its covered population may be invisible."
                        .to_owned(),
                severity: "critical".to_owned(),
            });
        }
    }
    if observation_total > u64::try_from(observation_count).unwrap_or(u64::MAX) {
        blind_spots.push(CoverageBlindSpot {
            code: "observation_window_truncated".to_owned(),
            title: "Coverage evidence window is truncated".to_owned(),
            detail: format!("Coverage used the newest {observation_limit} observations."),
            severity: "warning".to_owned(),
        });
    }
    blind_spots
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct GovernanceFindingsResponse {
    unsanctioned: Vec<GovernanceFindingView>,
    authorization_queue: Vec<GovernanceFindingView>,
    sanctioned: Vec<GovernanceFindingView>,
}

#[utoipa::path(get, path = "/api/v1/tally/findings", responses((status = 200, body = GovernanceFindingsResponse)))]
async fn findings(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<GovernanceFindingsResponse>, ApiError> {
    let items = state
        .postgres
        .list_governance_findings(500)
        .await
        .map_err(ApiError::dependency)?;
    let mut response = GovernanceFindingsResponse {
        unsanctioned: Vec::new(),
        authorization_queue: Vec::new(),
        sanctioned: Vec::new(),
    };
    for item in items {
        match item.status {
            GovernanceFindingStatus::Unsanctioned => response.unsanctioned.push(item),
            GovernanceFindingStatus::AuthorizationQueue => {
                response.authorization_queue.push(item);
            }
            GovernanceFindingStatus::Sanctioned => response.sanctioned.push(item),
        }
    }
    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/audit",
    responses((status = 200, body = AuditResponse))
)]
async fn audit(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<AuditResponse>, ApiError> {
    let items = state
        .postgres
        .list_audit_events(500)
        .await
        .map_err(ApiError::dependency)?
        .into_iter()
        .map(|event| AuditEventResponse {
            audit_id: event.audit_id,
            at: event.at,
            actor: event.actor,
            action: event.action,
            entity_type: event.entity_type,
            entity_id: event.entity_id,
            detail: event.detail,
        })
        .collect();
    Ok(Json(AuditResponse { items }))
}

#[utoipa::path(get, path = "/api/v1/tally/data", responses((status = 200, body = DataInventory)))]
async fn data_inventory(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<DataInventory>, ApiError> {
    let mut inventory = state
        .postgres
        .data_inventory()
        .await
        .map_err(ApiError::dependency)?;
    inventory.ai_logs = state
        .observations
        .observation_count()
        .await
        .map_err(ApiError::dependency)?;
    inventory.inventory_entities = state
        .observations
        .estate_count()
        .await
        .map_err(ApiError::dependency)?;
    Ok(Json(inventory))
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct DeleteDataRequest {
    confirmation: String,
    scopes: Vec<String>,
    before: Option<DateTime<Utc>>,
}

#[utoipa::path(post, path = "/api/v1/tally/data/delete", request_body = DeleteDataRequest, responses((status = 200, body = DataInventory), (status = 409, body = ProblemDetails), (status = 422, body = ProblemDetails)))]
async fn delete_data(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(request): Json<DeleteDataRequest>,
) -> Result<Json<DataInventory>, ApiError> {
    const CONFIRMATION: &str = "DELETE SELECTED DATA";
    const ALLOWED_SCOPES: [&str; 9] = [
        "all",
        "ai_logs",
        "inventory",
        "findings",
        "connector_history",
        "connectors",
        "scanner_history",
        "audit_logs",
        "registry_sanctions",
    ];
    if request.confirmation != CONFIRMATION
        || request.scopes.is_empty()
        || request.scopes.len() > ALLOWED_SCOPES.len()
        || request
            .scopes
            .iter()
            .any(|scope| !ALLOWED_SCOPES.contains(&scope.as_str()))
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "data_delete_request_invalid",
        ));
    }
    let _guard = state.purge_lock.lock().await;
    let installation = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?
        .installation_id;
    let _sample_lock = sample_data::lock_workspace(&state, installation).await?;
    let all = request.scopes.iter().any(|s| s == "all");
    // Storage deletion precedes the control-plane acknowledgement. Failures remain retryable.
    state
        .observations
        .delete_selected(
            all || request.scopes.iter().any(|s| s == "ai_logs"),
            all || request.scopes.iter().any(|s| s == "inventory"),
            request.before.map(|t| t.timestamp_millis()),
        )
        .await
        .map_err(ApiError::dependency)?;
    if all
        || request
            .scopes
            .iter()
            .any(|s| s == "ai_logs" || s == "inventory")
    {
        state
            .pending_flows
            .delete_selected(true, false, request.before.map(|t| t.timestamp_millis()))
            .await
            .map_err(ApiError::dependency)?;
    }
    let mut inventory = state
        .postgres
        .delete_data(&request.scopes, request.before)
        .await
        .map_err(ApiError::from_store)?;
    inventory.ai_logs = state
        .observations
        .observation_count()
        .await
        .map_err(ApiError::dependency)?;
    inventory.inventory_entities = state
        .observations
        .estate_count()
        .await
        .map_err(ApiError::dependency)?;
    Ok(Json(inventory))
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/data/purge/preview",
    responses((status = 200, body = PurgePreviewResponse))
)]
async fn preview_purge(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<PurgePreviewResponse>, ApiError> {
    let counts = current_purge_counts(&state).await?;
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    Ok(Json(purge_preview_response(
        identity.installation_id,
        &counts,
    )?))
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/data/purge",
    request_body = PurgeCommitRequest,
    responses(
        (status = 200, body = PurgeCommitResponse),
        (status = 400, body = ProblemDetails),
        (status = 409, body = ProblemDetails),
        (status = 422, body = ProblemDetails)
    )
)]
#[allow(clippy::too_many_lines)] // Keep the cross-store purge and its durable receipt together.
async fn commit_purge(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PurgeCommitRequest>,
) -> Result<Json<PurgeCommitResponse>, ApiError> {
    const CONFIRMATION: &str = "DELETE TALLY DATA";
    if request.confirmation != CONFIRMATION {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "purge_confirmation_invalid",
        ));
    }
    let purge_id = parse_idempotency_key(&headers)?;
    let _guard = state.purge_lock.lock().await;
    let _registry_guard = state.registry.mutation_lock.lock().await;
    let _classification_guard = state.classification_lock.lock().await;
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    let receipt = state
        .postgres
        .get_purge_receipt(purge_id)
        .await
        .map_err(ApiError::dependency)?;
    let (preview_digest, counts) = if let Some(receipt) = receipt {
        if request.confirm_preview_digest != receipt.preview_digest {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "purge_idempotency_conflict",
            ));
        }
        if receipt.status == "completed" {
            let deleted = receipt
                .deleted_counts
                .ok_or_else(|| ApiError::dependency_message("purge_receipt_invalid"))?;
            state
                .registry
                .activate(Vec::new())
                .map_err(|_| ApiError::dependency_message("registry_reset_failed"))?;
            return Ok(Json(PurgeCommitResponse {
                purge_id,
                preview_digest: receipt.preview_digest,
                deleted: PurgeCountsResponse::from(&deleted),
                installation_identity_preserved: true,
                registry_artifact_preserved: true,
                content_retained: false,
            }));
        }
        (receipt.preview_digest, receipt.requested_counts)
    } else {
        let counts = current_purge_counts(&state).await?;
        let preview = purge_preview_response(identity.installation_id, &counts)?;
        if request.confirm_preview_digest != preview.preview_digest {
            return Err(ApiError::new(StatusCode::CONFLICT, "purge_preview_changed"));
        }
        state
            .postgres
            .begin_purge(
                identity.installation_id,
                purge_id,
                &preview.preview_digest,
                &counts,
                Utc::now(),
            )
            .await
            .map_err(ApiError::from_store)?;
        (preview.preview_digest, counts)
    };
    if state
        .observations
        .purge_installation(identity.installation_id)
        .await
        .is_err()
    {
        state
            .postgres
            .fail_purge(purge_id, "observations_purge_failed")
            .await
            .map_err(ApiError::dependency)?;
        return Err(ApiError::dependency_message("observations_purge_failed"));
    }
    state
        .pending_flows
        .purge_installation(identity.installation_id)
        .await
        .map_err(ApiError::dependency)?;
    let deleted = state
        .postgres
        .purge_installation_data(identity.installation_id, purge_id, &preview_digest, &counts)
        .await
        .map_err(ApiError::from_store)?;
    state
        .registry
        .activate(Vec::new())
        .map_err(|_| ApiError::dependency_message("registry_reset_failed"))?;
    Ok(Json(PurgeCommitResponse {
        purge_id,
        preview_digest,
        deleted: PurgeCountsResponse::from(&deleted),
        installation_identity_preserved: true,
        registry_artifact_preserved: true,
        content_retained: false,
    }))
}

async fn current_purge_counts(state: &AppState) -> Result<PurgeCounts, ApiError> {
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    let (counts, observations) = tokio::join!(
        state
            .postgres
            .purge_preview_counts(identity.installation_id),
        state
            .observations
            .installation_observation_count(identity.installation_id),
    );
    let mut counts = counts.map_err(ApiError::dependency)?;
    counts.observations = observations.map_err(ApiError::dependency)?;
    Ok(counts)
}

fn purge_preview_response(
    installation_id: uuid::Uuid,
    counts: &PurgeCounts,
) -> Result<PurgePreviewResponse, ApiError> {
    let canonical =
        serde_json::to_vec(&("purge-v1", installation_id, counts)).map_err(ApiError::dependency)?;
    Ok(PurgePreviewResponse {
        preview_digest: hex::encode(Sha256::digest(canonical)),
        counts: PurgeCountsResponse::from(counts),
        confirmation_phrase: "DELETE TALLY DATA",
        preserved: vec![
            "installation identity and pseudonymization key".to_owned(),
            "embedded registry artifact".to_owned(),
            "content-free purge receipts and one completion audit event".to_owned(),
        ],
        destructive: true,
        reversible: false,
        generated_at: Utc::now(),
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/scans/preview",
    request_body = ScanPreviewRequest,
    responses(
        (status = 200, body = ScanPreviewResponse),
        (status = 422, body = ProblemDetails)
    )
)]
async fn preview_scan(
    Json(request): Json<ScanPreviewRequest>,
) -> Result<Json<ScanPreviewResponse>, ApiError> {
    let (requested_targets, skipped, discovered_local_scope) = if request.targets.is_empty() {
        let discovery = discover_local_scope(request.max_hosts).map_err(|_| {
            ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "local_scope_unavailable")
        })?;
        if discovery.targets.is_empty() {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "no_safe_local_scope",
            ));
        }
        let skipped = discovery
            .skipped
            .into_iter()
            .map(|item| SkippedInterfaceResponse {
                name: item.name,
                address: item.address.to_string(),
                reason: item.reason,
            })
            .collect();
        (discovery.targets, skipped, true)
    } else {
        (request.targets.clone(), Vec::new(), false)
    };
    let ports = if request.ports.is_empty() {
        DEFAULT_PORTS.to_vec()
    } else {
        request.ports
    };
    let plan = ScanScope {
        targets: requested_targets.clone(),
        exclusions: request.exclusions,
        ports,
        max_hosts: request.max_hosts,
        allow_public: request.allow_public,
        authorization_acknowledged: request.public_target_authorization,
    }
    .plan()
    .map_err(|_| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "unsafe_scan_scope"))?;
    Ok(Json(ScanPreviewResponse {
        plan: ScanPlanResponse::from(&plan),
        requested_targets,
        skipped,
        discovered_local_scope,
        sends_network_traffic: false,
        content_retained: false,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/scans",
    request_body = ScanStartRequest,
    responses(
        (status = 202, body = ScanJobResponse),
        (status = 400, body = ProblemDetails),
        (status = 409, body = ProblemDetails),
        (status = 422, body = ProblemDetails)
    )
)]
async fn start_scan(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ScanStartRequest>,
) -> Result<(StatusCode, Json<ScanJobResponse>), ApiError> {
    if !request.authorized_to_scan {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "scan_authorization_required",
        ));
    }
    let plan = verify_scan_plan(&request.plan, &request.confirm_scope_digest)?;
    let policy = verify_scan_policy(request.execution_policy)?;
    let idempotency_key = parse_idempotency_key(&headers)?;
    let created_at = Utc::now();
    let scan_id = uuid::Uuid::now_v7();
    let request_fingerprint = format!(
        "{}:{}:{}",
        plan.scope_digest, policy.concurrency, policy.connect_timeout_millis
    );
    let (job, replayed) = state
        .postgres
        .create_scan_job(&ScanJobCreate {
            scan_id,
            idempotency_key,
            request_fingerprint,
            scope_digest: plan.scope_digest.clone(),
            plan: serde_json::to_value(&plan).map_err(ApiError::dependency)?,
            execution_policy: serde_json::to_value(policy).map_err(ApiError::dependency)?,
            created_at,
            planned_probes: plan.probe_count,
        })
        .await
        .map_err(ApiError::from_store)?;
    if !replayed {
        schedule_scan(state, job.scan_id, plan, policy).await;
    }
    Ok((StatusCode::ACCEPTED, Json(ScanJobResponse::from(job))))
}

async fn schedule_scan(
    state: AppState,
    scan_id: uuid::Uuid,
    plan: ScanPlan,
    policy: ScanExecutionPolicy,
) {
    let cancellation = ScanCancellation::default();
    state
        .scanner
        .cancellations
        .write()
        .await
        .insert(scan_id, cancellation.clone());
    tokio::spawn(async move {
        if !state
            .postgres
            .start_scan_job(scan_id)
            .await
            .unwrap_or(false)
        {
            state.scanner.cancellations.write().await.remove(&scan_id);
            return;
        }
        match execute_tcp_connect(&plan, policy, &cancellation).await {
            Ok(run) => {
                let open_port_count = run
                    .results
                    .iter()
                    .filter(|result| result.state == TcpProbeState::Open)
                    .count() as u64;
                let status = if run.status == ScanRunStatus::Completed {
                    ScanJobStatus::Completed
                } else {
                    ScanJobStatus::Cancelled
                };
                let evidence = if status == ScanJobStatus::Completed {
                    let registry = state.registry.snapshot();
                    let attempts = execute_http_fingerprints(&plan, &registry, &run, &cancellation)
                        .await
                        .ok();
                    let Some(attempts) = attempts else {
                        let _ = state
                            .postgres
                            .fail_scan_job(scan_id, "scan_fingerprint_failed")
                            .await;
                        state.scanner.cancellations.write().await.remove(&scan_id);
                        return;
                    };
                    let evidence = admit_scan_evidence(
                        &state,
                        scan_id,
                        run.started_at,
                        run.finished_at,
                        &attempts,
                    )
                    .await
                    .ok();
                    let Some(evidence) = evidence else {
                        let _ = state
                            .postgres
                            .fail_scan_job(scan_id, "scan_evidence_admission_failed")
                            .await;
                        state.scanner.cancellations.write().await.remove(&scan_id);
                        return;
                    };
                    evidence
                } else {
                    ScanEvidenceOutcome::default()
                };
                let results =
                    serde_json::to_value(&run.results).unwrap_or_else(|_| serde_json::json!([]));
                let _ = state
                    .postgres
                    .complete_scan_job(&ScanJobCompletion {
                        scan_id,
                        status,
                        finished_at: run.finished_at,
                        completed_probes: run.completed_probes,
                        open_port_count,
                        fingerprint_attempt_count: evidence.attempted,
                        fingerprint_match_count: evidence.matched,
                        resolved_system_count: evidence.resolved,
                        results,
                    })
                    .await;
            }
            Err(_) => {
                let _ = state
                    .postgres
                    .fail_scan_job(scan_id, "scan_execution_failed")
                    .await;
            }
        }
        state.scanner.cancellations.write().await.remove(&scan_id);
    });
}

#[derive(Debug, Default)]
struct ScanEvidenceOutcome {
    attempted: u64,
    matched: u64,
    resolved: u64,
}

#[allow(clippy::too_many_lines)]
async fn admit_scan_evidence(
    state: &AppState,
    scan_id: uuid::Uuid,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    attempts: &[HttpFingerprintAttempt],
) -> Result<ScanEvidenceOutcome, ApiError> {
    let attempted = attempts.len() as u64;
    let matched_attempts = attempts
        .iter()
        .filter(|attempt| attempt.outcome == HttpFingerprintOutcome::Matched)
        .collect::<Vec<_>>();
    let matched = matched_attempts.len() as u64;
    let identity = state
        .postgres
        .get_or_create_installation_identity()
        .await
        .map_err(ApiError::dependency)?;
    let connector_instance_id = uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        format!("godel-tally:{}:native-scanner", identity.installation_id).as_bytes(),
    );
    let descriptor = scanner_descriptor();
    state
        .postgres
        .register_connector(identity.installation_id, connector_instance_id, &descriptor)
        .await
        .map_err(ApiError::dependency)?;
    let cursor_before = state
        .postgres
        .connector_cursor(connector_instance_id)
        .await
        .map_err(ApiError::dependency)?
        .unwrap_or_default();
    let cursor_after = format!("scan:{scan_id}");
    let redaction_digest = hex::encode(Sha256::digest(descriptor.privacy_contract.as_bytes()));

    if matched_attempts.is_empty() {
        state
            .postgres
            .record_connector_run(&ConnectorRunRecord {
                run_id: uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, scan_id.as_bytes()),
                connector_instance_id,
                installation_id: identity.installation_id,
                connector_type: descriptor.connector_type,
                status: ConnectorRunStatus::Completed,
                started_at,
                completed_at: finished_at,
                cursor_before,
                cursor_after,
                first_source_at: None,
                last_source_at: None,
                records_read: attempted,
                accepted: 0,
                ignored: attempted,
                rejected: 0,
                deduplicated: 0,
                batch_id: None,
                error_code: None,
                redaction_digest,
            })
            .await
            .map_err(ApiError::dependency)?;
        return Ok(ScanEvidenceOutcome {
            attempted,
            matched,
            resolved: 0,
        });
    }

    let observations = matched_attempts
        .into_iter()
        .map(|attempt| {
            scanner_observation(
                identity.installation_id,
                connector_instance_id,
                scan_id,
                finished_at,
                attempt,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let batch = ObservationBatch::build(observations, Cursor(cursor_after.clone()))
        .map_err(ApiError::dependency)?;
    let usages = usages_from_observations(&batch.observations, &state.registry.snapshot())?;
    let admission = state
        .postgres
        .begin_ingestion(&batch.receipt)
        .await
        .map_err(ApiError::dependency)?;
    let (status, accepted, deduplicated, resolved) = match admission.disposition {
        BatchDisposition::Accepted | BatchDisposition::Retry => {
            if estate::append_ai(state, &batch.observations, &batch.receipt.canonical_digest)
                .await
                .is_err()
            {
                state
                    .postgres
                    .fail_ingestion(admission.batch_id, "observations_append_failed")
                    .await
                    .map_err(ApiError::dependency)?;
                return Err(ApiError::dependency_message("observations_append_failed"));
            }
            let resolved = match state
                .postgres
                .complete_ingestion_with_usage(admission.batch_id, &usages)
                .await
            {
                Ok(resolved) => resolved as u64,
                Err(error) => {
                    tracing::error!(
                        batch_id = %admission.batch_id,
                        connector_instance_id = %connector_instance_id,
                        error = %error,
                        "scanner finding batch persistence failed"
                    );
                    state
                        .postgres
                        .fail_ingestion(admission.batch_id, "finding_persist_failed")
                        .await
                        .map_err(ApiError::dependency)?;
                    return Err(ApiError::dependency_message("finding_persist_failed"));
                }
            };
            (ConnectorRunStatus::Completed, matched, 0, resolved)
        }
        BatchDisposition::Duplicate => (ConnectorRunStatus::Duplicate, 0, matched, 0),
        BatchDisposition::InProgress => {
            return Err(ApiError::dependency_message("scan_ingestion_in_progress"));
        }
    };
    state
        .postgres
        .record_connector_run(&ConnectorRunRecord {
            run_id: uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, scan_id.as_bytes()),
            connector_instance_id,
            installation_id: identity.installation_id,
            connector_type: descriptor.connector_type,
            status,
            started_at,
            completed_at: finished_at,
            cursor_before,
            cursor_after,
            first_source_at: Some(finished_at),
            last_source_at: Some(finished_at),
            records_read: attempted,
            accepted,
            ignored: attempted.saturating_sub(matched),
            rejected: 0,
            deduplicated,
            batch_id: Some(admission.batch_id),
            error_code: None,
            redaction_digest,
        })
        .await
        .map_err(ApiError::dependency)?;
    Ok(ScanEvidenceOutcome {
        attempted,
        matched,
        resolved,
    })
}

fn scanner_descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor {
        connector_type: "native_scanner".to_owned(),
        display_name: "Tally native scanner".to_owned(),
        implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
        source_vendor: "Godel Labs".to_owned(),
        source_product: "Gödel Tally".to_owned(),
        record_variants: vec!["registry_http_fingerprint".to_owned()],
        transport: ConnectorTransport::Scanner,
        required_permissions: vec!["operator_authorized_network_scope".to_owned()],
        requested_fields: vec![
            "destination_ip".to_owned(),
            "destination_port".to_owned(),
            "fingerprint_id".to_owned(),
            "transcript_digest".to_owned(),
        ],
        prohibited_fields: vec![
            "response_body".to_owned(),
            "request_body".to_owned(),
            "headers".to_owned(),
            "cookies".to_owned(),
            "credentials".to_owned(),
            "prompts".to_owned(),
            "model_output".to_owned(),
        ],
        cursor_semantics: "last completed scan receipt UUID".to_owned(),
        replay_capability: ReplayCapability::SourceManagedRetry,
        health_capabilities: vec!["last_scan".to_owned(), "matched_fingerprints".to_owned()],
        coverage_capabilities: vec!["network_runtime_evidence".to_owned()],
        privacy_contract: "Persist only a registry fingerprint identifier, endpoint metadata, timing, and transcript SHA-256; discard all response bytes and extracted values.".to_owned(),
    }
}

fn scanner_observation(
    installation_id: uuid::Uuid,
    connector_instance_id: uuid::Uuid,
    scan_id: uuid::Uuid,
    observed_at: DateTime<Utc>,
    attempt: &HttpFingerprintAttempt,
) -> Result<Observation, ApiError> {
    let transcript_digest = attempt
        .transcript_sha256
        .clone()
        .ok_or_else(|| ApiError::dependency_message("scanner_transcript_missing"))?;
    let observation_id = uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        format!(
            "godel-tally:scan:{scan_id}:{}:{}:{}:{transcript_digest}",
            attempt.address, attempt.port, attempt.fingerprint_id
        )
        .as_bytes(),
    );
    let mut observation = Observation::new(
        installation_id,
        observed_at,
        ConnectorRef {
            instance_id: connector_instance_id,
            connector_type: "native_scanner".to_owned(),
            implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
            source_lineage_id: Some(format!("scan:{scan_id}")),
        },
        ObservationKind::ScanFingerprint,
        EvidenceReceipt::ScannerTranscriptDigest {
            probe_id: observation_id,
            transcript_digest,
        },
    );
    observation.observation_id = observation_id;
    observation.received_at = observed_at;
    observation.destination.ip =
        Some(IpAddress::parse(&attempt.address.to_string()).map_err(ApiError::dependency)?);
    observation.destination.port = Some(attempt.port);
    observation.network.protocol = Some("http".to_owned());
    observation.network.duration_millis = Some(attempt.duration_millis);
    observation.service.scanner_fingerprint_id = Some(attempt.fingerprint_id.clone());
    observation.outcome.action = Some("fingerprint".to_owned());
    observation.outcome.result = Some("matched".to_owned());
    observation.outcome.response_code = attempt.status_code.map(|code| code.to_string());
    Ok(observation)
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/scans",
    responses((status = 200, body = ScanJobsResponse))
)]
async fn scans(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<ScanJobsResponse>, ApiError> {
    let items = state
        .postgres
        .list_scan_jobs(50)
        .await
        .map_err(ApiError::dependency)?
        .into_iter()
        .map(ScanJobResponse::from)
        .collect();
    Ok(Json(ScanJobsResponse { items }))
}

#[utoipa::path(
    get,
    path = "/api/v1/tally/scans/{scan_id}",
    params(("scan_id" = uuid::Uuid, Path, description = "Durable scan identifier")),
    responses(
        (status = 200, body = ScanJobResponse),
        (status = 404, body = ProblemDetails)
    )
)]
async fn scan(
    axum::extract::State(state): axum::extract::State<AppState>,
    Path(scan_id): Path<uuid::Uuid>,
) -> Result<Json<ScanJobResponse>, ApiError> {
    state
        .postgres
        .get_scan_job(scan_id)
        .await
        .map_err(ApiError::dependency)?
        .map(ScanJobResponse::from)
        .map(Json)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "scan_not_found"))
}

#[utoipa::path(
    post,
    path = "/api/v1/tally/scans/{scan_id}/cancel",
    params(("scan_id" = uuid::Uuid, Path, description = "Durable scan identifier")),
    responses(
        (status = 202, body = ScanJobResponse),
        (status = 404, body = ProblemDetails),
        (status = 409, body = ProblemDetails)
    )
)]
async fn cancel_scan(
    axum::extract::State(state): axum::extract::State<AppState>,
    Path(scan_id): Path<uuid::Uuid>,
) -> Result<(StatusCode, Json<ScanJobResponse>), ApiError> {
    let job = state
        .postgres
        .request_scan_cancellation(scan_id)
        .await
        .map_err(ApiError::from_store)?;
    if let Some(cancellation) = state.scanner.cancellations.read().await.get(&scan_id) {
        cancellation.cancel();
    }
    Ok((StatusCode::ACCEPTED, Json(ScanJobResponse::from(job))))
}

fn parse_idempotency_key(headers: &HeaderMap) -> Result<uuid::Uuid, ApiError> {
    headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "idempotency_key_required"))
}

fn verify_scan_plan(
    expected: &ScanPlanResponse,
    confirmed_digest: &str,
) -> Result<ScanPlan, ApiError> {
    if confirmed_digest != expected.scope_digest {
        return Err(ApiError::new(StatusCode::CONFLICT, "scope_digest_mismatch"));
    }
    let max_hosts = u32::try_from(expected.host_count)
        .ok()
        .filter(|count| (1..=HARD_MAX_HOSTS).contains(count))
        .ok_or_else(|| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "unsafe_scan_scope"))?;
    let actual = ScanScope {
        targets: expected.targets.clone(),
        exclusions: Vec::new(),
        ports: expected.ports.clone(),
        max_hosts,
        allow_public: expected.allow_public,
        authorization_acknowledged: expected.public_target_authorization,
    }
    .plan()
    .map_err(|_| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "unsafe_scan_scope"))?;
    if ScanPlanResponse::from(&actual) != *expected {
        return Err(ApiError::new(StatusCode::CONFLICT, "scan_plan_tampered"));
    }
    Ok(actual)
}

fn verify_scan_policy(input: ScanExecutionPolicyInput) -> Result<ScanExecutionPolicy, ApiError> {
    if input.concurrency == 0
        || input.concurrency > MAX_CONNECT_CONCURRENCY
        || !(50..=MAX_CONNECT_TIMEOUT_MILLIS).contains(&input.connect_timeout_millis)
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unsafe_scan_policy",
        ));
    }
    Ok(ScanExecutionPolicy {
        concurrency: input.concurrency,
        connect_timeout_millis: input.connect_timeout_millis,
    })
}

async fn metrics(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> ([(axum::http::HeaderName, &'static str); 1], String) {
    let started_at = state.started_at.timestamp();
    let uptime = Utc::now()
        .signed_duration_since(state.started_at)
        .num_seconds()
        .max(0);
    let body = format!(
        "# HELP tally_process_start_time_seconds Unix time when tallyd started.\n\
         # TYPE tally_process_start_time_seconds gauge\n\
         tally_process_start_time_seconds {started_at}\n\
         # HELP tally_process_uptime_seconds Seconds tallyd has been running.\n\
         # TYPE tally_process_uptime_seconds gauge\n\
         tally_process_uptime_seconds {uptime}\n\
         # HELP tally_build_info Static Tally build information.\n\
         # TYPE tally_build_info gauge\n\
         tally_build_info{{version=\"{}\"}} 1\n\
         # EOF\n",
        env!("CARGO_PKG_VERSION")
    );
    (
        [(
            CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )],
        body,
    )
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: HealthStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postgres: Option<DependencyHealth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observations: Option<DependencyHealth>,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DependencyHealth {
    pub healthy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<&'static str>,
}

impl DependencyHealth {
    fn from_result<T, E>(result: &Result<T, E>) -> Self {
        match result {
            Ok(_) => Self {
                healthy: true,
                error_code: None,
            },
            Err(_) => Self {
                healthy: false,
                error_code: Some("dependency_unavailable"),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct VersionResponse {
    pub product: &'static str,
    pub version: &'static str,
    pub api_version: &'static str,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OverviewResponse {
    pub state: OverviewState,
    pub systems: u64,
    pub new_systems: u64,
    pub unauthorized: u64,
    pub actors: u64,
    pub high_findings: u64,
    pub coverage_percent: Option<f32>,
    pub observations: u64,
    pub sources: u64,
    pub demo_observations: u64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AnalyticsResponse {
    pub activity_window: &'static str,
    pub window_start: Option<DateTime<Utc>>,
    pub observation_total: u64,
    pub loaded_observations: usize,
    pub observation_window_truncated: bool,
    pub system_total: u64,
    pub loaded_systems: usize,
    pub system_window_truncated: bool,
    pub first_observed_at: Option<DateTime<Utc>>,
    pub last_observed_at: Option<DateTime<Utc>>,
    pub service_rank: Vec<ServiceAdoptionResponse>,
    pub authorization: AuthorizationDistributionResponse,
    pub actors: Vec<ActorActivityResponse>,
    pub content_retained: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ServiceAdoptionResponse {
    pub system_id: uuid::Uuid,
    pub display_name: String,
    pub authorization: String,
    pub event_count: u64,
    pub unique_actor_count: usize,
    pub source_count: usize,
    pub first_observed_at: DateTime<Utc>,
    pub last_observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ActorActivityResponse {
    pub actor_key: String,
    pub event_count: u64,
    pub unresolved_event_count: u64,
    pub system_count: usize,
    pub destination_count: usize,
    pub sources: Vec<String>,
    pub first_observed_at: DateTime<Utc>,
    pub last_observed_at: DateTime<Utc>,
    pub systems: Vec<ActorSystemActivityResponse>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ActorSystemActivityResponse {
    pub system_id: uuid::Uuid,
    pub display_name: String,
    pub event_count: u64,
}

#[derive(Debug, Clone, Default, Serialize, ToSchema)]
pub struct AuthorizationDistributionResponse {
    pub discovered: u64,
    pub under_review: u64,
    pub authorized: u64,
    pub unauthorized: u64,
    pub retired: u64,
    pub total: u64,
}

impl AuthorizationDistributionResponse {
    fn from_systems(systems: &[AiSystemView]) -> Self {
        let mut distribution = Self::default();
        for system in systems {
            distribution.total = distribution.total.saturating_add(1);
            match system.authorization {
                AuthorizationStatus::Discovered => {
                    distribution.discovered = distribution.discovered.saturating_add(1);
                }
                AuthorizationStatus::UnderReview => {
                    distribution.under_review = distribution.under_review.saturating_add(1);
                }
                AuthorizationStatus::Authorized => {
                    distribution.authorized = distribution.authorized.saturating_add(1);
                }
                AuthorizationStatus::Unauthorized => {
                    distribution.unauthorized = distribution.unauthorized.saturating_add(1);
                }
                AuthorizationStatus::Retired => {
                    distribution.retired = distribution.retired.saturating_add(1);
                }
            }
        }
        distribution
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RegistryCatalogResponse {
    pub verification: RegistryVerificationResponse,
    pub schema_version: String,
    pub version: String,
    /// SHA-256 of the canonical JSON representation of the registry source.
    pub source_sha256: String,
    pub bundle_sha256: String,
    pub compressed_sha256: String,
    pub compiler_version: String,
    pub entry_count: usize,
    pub matcher_count: usize,
    pub fingerprint_count: usize,
    pub kind_counts: std::collections::BTreeMap<String, usize>,
    pub local_overlay_count: usize,
    pub content_retained: bool,
    pub entries: Vec<RegistryEntryResponse>,
    pub fingerprints: Vec<RegistryFingerprintResponse>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RegistryVerificationResponse {
    pub status: String,
    pub checks: Vec<String>,
    pub signature_verified: bool,
    pub signature_note: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RegistryEntryResponse {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub provider_ref: Option<String>,
    pub categories: Vec<String>,
    pub surfaces: Vec<String>,
    pub status: String,
    pub fact_count: usize,
    pub fact_names: Vec<String>,
    pub evidence_source_count: usize,
    pub latest_verified_at: Option<String>,
    pub local: bool,
    pub matchers: Vec<RegistryMatcherResponse>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LocalRegistryEntryKind {
    Service,
    Product,
    Runtime,
}

impl LocalRegistryEntryKind {
    const fn key(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Product => "product",
            Self::Runtime => "runtime",
        }
    }

    const fn registry_kind(self) -> RegistryEntryKind {
        match self {
            Self::Service => RegistryEntryKind::Service,
            Self::Product => RegistryEntryKind::Product,
            Self::Runtime => RegistryEntryKind::Runtime,
        }
    }

    const fn proof(self) -> ProofKind {
        match self {
            Self::Service => ProofKind::ServiceContact,
            Self::Product => ProofKind::ProductUse,
            Self::Runtime => ProofKind::RuntimeReachable,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LocalRegistryCategory {
    GenerativeAi,
    Assistant,
    DeveloperTool,
    ModelServing,
    AiInfrastructure,
    Productivity,
}

impl LocalRegistryCategory {
    const fn key(self) -> &'static str {
        match self {
            Self::GenerativeAi => "generative_ai",
            Self::Assistant => "assistant",
            Self::DeveloperTool => "developer_tool",
            Self::ModelServing => "model_serving",
            Self::AiInfrastructure => "ai_infrastructure",
            Self::Productivity => "productivity",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LocalRegistrySurface {
    WebApplication,
    ExternalApi,
    IdeExtension,
    LocalRuntime,
    NetworkService,
    SaasApplication,
}

impl LocalRegistrySurface {
    const fn key(self) -> &'static str {
        match self {
            Self::WebApplication => "web_application",
            Self::ExternalApi => "external_api",
            Self::IdeExtension => "ide_extension",
            Self::LocalRuntime => "local_runtime",
            Self::NetworkService => "network_service",
            Self::SaasApplication => "saas_application",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LocalHostRuleKind {
    Exact,
    Suffix,
}

impl LocalHostRuleKind {
    const fn key(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Suffix => "suffix",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalRegistryHostRule {
    pub kind: LocalHostRuleKind,
    pub host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalRegistryEntryRequest {
    pub name: String,
    pub kind: LocalRegistryEntryKind,
    pub categories: Vec<LocalRegistryCategory>,
    pub surface: LocalRegistrySurface,
    pub host_rules: Vec<LocalRegistryHostRule>,
    pub evidence_url: String,
    pub acknowledge_local_overlay: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LocalRegistryEntryResponse {
    pub overlay_id: String,
    pub overlay_sha256: String,
    pub replayed: bool,
    pub local: bool,
    pub content_retained: bool,
    pub effective_entry_count: usize,
    pub effective_matcher_count: usize,
    pub entry: RegistryEntryResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationDecision {
    Authorized,
    Unauthorized,
}

impl ClassificationDecision {
    const fn key(self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::Unauthorized => "unauthorized",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassificationHostRule {
    pub kind: LocalHostRuleKind,
    pub host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassificationRulePreviewRequest {
    pub decision: ClassificationDecision,
    pub rules: Vec<ClassificationHostRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassificationRuleCommitRequest {
    pub decision: ClassificationDecision,
    pub rules: Vec<ClassificationHostRule>,
    pub confirm_preview_digest: String,
    pub acknowledge_classification: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassificationRuleDeactivateRequest {
    pub acknowledge_deactivation: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClassificationSystemEffect {
    pub system_id: uuid::Uuid,
    pub display_name: String,
    pub current_authorization: String,
    pub target_authorization: String,
    pub current_revision: i64,
    pub matching_observations: u64,
    pub retired: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClassificationRulePreviewResponse {
    pub preview_digest: String,
    pub decision: ClassificationDecision,
    pub rules: Vec<ClassificationHostRule>,
    pub loaded_observations: usize,
    pub observation_total: u64,
    pub observation_window_truncated: bool,
    pub matched_observations: usize,
    pub unresolved_observations: u64,
    pub matched_systems: usize,
    pub systems: Vec<ClassificationSystemEffect>,
    pub content_retained: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClassificationRuleSetResponse {
    pub rule_set_id: uuid::Uuid,
    pub preview_digest: String,
    pub decision: ClassificationDecision,
    pub rules: Vec<ClassificationHostRule>,
    pub rules_sha256: String,
    pub matched_system_ids: Vec<uuid::Uuid>,
    pub changed_system_ids: Vec<uuid::Uuid>,
    pub matched_system_count: i32,
    pub changed_system_count: i32,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub active: bool,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub deactivated_by: Option<String>,
    pub content_retained: bool,
}

fn classification_rule_set_response(
    value: ClassificationRuleSetView,
) -> Result<ClassificationRuleSetResponse, ApiError> {
    let decision = match value.decision.as_str() {
        "authorized" => ClassificationDecision::Authorized,
        "unauthorized" => ClassificationDecision::Unauthorized,
        _ => {
            return Err(ApiError::dependency_message(
                "stored_classification_rules_invalid",
            ));
        }
    };
    let rules = serde_json::from_value::<Vec<ClassificationHostRule>>(value.rules.clone())
        .map_err(|_| ApiError::dependency_message("stored_classification_rules_invalid"))?;
    let digest = serde_json::to_vec(&value.rules)
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .map_err(ApiError::dependency)?;
    let lifecycle_valid = if value.active {
        value.deactivated_at.is_none() && value.deactivated_by.is_none()
    } else {
        value.deactivated_at.is_some() && value.deactivated_by.as_deref() == Some("local_operator")
    };
    if digest != value.rules_sha256
        || value.content_retained
        || value.created_by != "local_operator"
        || !lifecycle_valid
        || usize::try_from(value.matched_system_count).ok() != Some(value.matched_system_ids.len())
        || usize::try_from(value.changed_system_count).ok() != Some(value.changed_system_ids.len())
    {
        return Err(ApiError::dependency_message(
            "stored_classification_rules_invalid",
        ));
    }
    Ok(ClassificationRuleSetResponse {
        rule_set_id: value.rule_set_id,
        preview_digest: value.preview_digest,
        decision,
        rules,
        rules_sha256: value.rules_sha256,
        matched_system_ids: value.matched_system_ids,
        changed_system_ids: value.changed_system_ids,
        matched_system_count: value.matched_system_count,
        changed_system_count: value.changed_system_count,
        created_at: value.created_at,
        created_by: value.created_by,
        active: value.active,
        deactivated_at: value.deactivated_at,
        deactivated_by: value.deactivated_by,
        content_retained: false,
    })
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClassificationRuleSetsResponse {
    pub items: Vec<ClassificationRuleSetResponse>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClassificationRuleCommitResponse {
    pub replayed: bool,
    pub rule_set: ClassificationRuleSetResponse,
    pub content_retained: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClassificationRuleDeactivateResponse {
    pub replayed: bool,
    pub rule_set: ClassificationRuleSetResponse,
    pub existing_system_decisions_changed: bool,
    pub content_retained: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RegistryMatcherResponse {
    pub id: String,
    pub rule_type: String,
    pub value: String,
    pub proof: String,
    pub confidence_bps: u16,
    pub verified_at: String,
    pub evidence_count: usize,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RegistryFingerprintResponse {
    pub id: String,
    pub ports: Vec<u16>,
    pub method: String,
    pub probe_kind: Option<String>,
    pub path: String,
    pub assertion_count: usize,
    pub asserted_facts: Vec<String>,
    pub evidence_count: usize,
    pub verified_at: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DiscoveryEventsResponse {
    pub activity_window: &'static str,
    pub window_start: Option<DateTime<Utc>>,
    pub total: u64,
    pub page_size: usize,
    pub resolved_events: usize,
    pub unresolved_events: usize,
    pub unique_systems: usize,
    pub unique_actors: usize,
    pub next_cursor: Option<String>,
    pub content_retained: bool,
    pub items: Vec<DiscoveryEventResponse>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DiscoveryEventResponse {
    pub observation_id: uuid::Uuid,
    pub observed_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub kind: String,
    /// The connector instance recorded on the observation itself. Evidence is immutable, so this
    /// stays populated even after the connector that produced it is removed.
    pub connector_instance_id: uuid::Uuid,
    /// The same identifier, resolved against the connectors that still exist: null once the
    /// connector has been deleted. The three `connector_*` fields below go null with it.
    pub connector_id: Option<uuid::Uuid>,
    /// The operator's own label for the connector -- null when it was never set, or the
    /// connector is gone.
    pub connector_friendly_name: Option<String>,
    /// Catalog label for the connector type, null once the connector is gone.
    pub connector_display_name: Option<String>,
    /// The label to render: the friendly name when set, the catalog label otherwise, and null
    /// once the connector is gone. `source_type` is still there to fall back on.
    pub connector_label: Option<String>,
    pub source_type: String,
    pub demo: bool,
    pub destination: Option<String>,
    pub actor: Option<String>,
    pub outcome: Option<String>,
    pub receipt_type: String,
    pub receipt_digest: Option<String>,
    pub systems: Vec<EventSystemResponse>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EventSystemResponse {
    pub system_id: uuid::Uuid,
    pub display_name: String,
    pub surface: String,
    pub evidence_quality: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SystemsResponse {
    pub items: Vec<tally_core::AiSystemView>,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct IntegrationInventoryResponse {
    pub schema_version: String,
    pub items: Vec<InventoryContribution>,
    pub total: u64,
    pub relationships_may_be_truncated: bool,
    pub evidence_may_be_truncated: bool,
    pub content_retained: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationCapabilityManifestResponse {
    pub schema_version: String,
    pub product: String,
    pub product_version: String,
    pub api_version: String,
    pub integration_schema_version: String,
    pub supported_integration_schema_versions: Vec<String>,
    pub previous_compatible_tally_version: String,
    pub routes: Vec<IntegrationRouteCapability>,
    pub registry: IntegrationRegistryCapability,
    pub migrations: IntegrationMigrationCapability,
    pub deprecation: IntegrationDeprecationPolicy,
    pub content_retained: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationRouteCapability {
    pub capability: String,
    pub method: String,
    pub path: String,
    pub route_version: String,
    pub maximum_items: usize,
    pub deprecated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationRegistryCapability {
    pub schema_version: String,
    pub version: String,
    pub bundle_sha256: String,
    pub compressed_sha256: String,
    pub verification: String,
    pub local_overlay_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationMigrationCapability {
    pub postgres_head: i64,
    pub postgres_required_head: i64,
    pub observations_head: String,
    pub observations_required_head: String,
    pub compatible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationDeprecationPolicy {
    pub policy_version: String,
    pub minimum_notice_days: u16,
    pub previous_minor_fixture_required: bool,
    pub removal_requires_schema_major: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct IntegrationConnectorsResponse {
    pub schema_version: String,
    pub items: Vec<ConnectorContribution>,
    pub truncated: bool,
    pub content_retained: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct IntegrationFindingsResponse {
    pub schema_version: String,
    pub open: usize,
    pub items: Vec<FindingContribution>,
    pub evidence_may_be_truncated: bool,
    pub content_retained: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct IntegrationEvidenceLinksResponse {
    pub schema_version: String,
    pub items: Vec<EvidenceLinkContribution>,
    pub content_retained: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SystemEvidenceResponse {
    pub system_id: uuid::Uuid,
    pub claim_count: usize,
    pub observation_count: usize,
    pub independent_source_count: usize,
    pub registry_versions: Vec<String>,
    pub content_retained: bool,
    pub claims: Vec<EvidenceClaimResponse>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AttributionConflictsResponse {
    pub total: u64,
    pub items: Vec<AttributionConflict>,
    pub content_retained: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EntitiesResponse {
    pub total: u64,
    pub items: Vec<Entity>,
    pub content_retained: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RelationshipsResponse {
    pub total: u64,
    pub items: Vec<EntityRelationship>,
    pub content_retained: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct GraphNodeResponse {
    pub entity: Entity,
    pub depth: u8,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct GraphRelationshipResponse {
    pub relationship: EntityRelationship,
    pub evidence_count: u32,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SystemGraphResponse {
    pub root_entity_id: uuid::Uuid,
    pub requested_depth: u8,
    pub nodes: Vec<GraphNodeResponse>,
    pub relationships: Vec<GraphRelationshipResponse>,
    pub truncated: bool,
    pub content_retained: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EntityMergePreviewRequest {
    pub source_entity_id: uuid::Uuid,
    pub target_entity_id: uuid::Uuid,
    pub source_revision: i64,
    pub target_revision: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EntityMergeCommitRequest {
    pub source_entity_id: uuid::Uuid,
    pub target_entity_id: uuid::Uuid,
    pub source_revision: i64,
    pub target_revision: i64,
    pub confirm_preview_digest: String,
    pub acknowledge_evidence_preserved: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EntitySplitPreviewRequest {
    pub source_entity_id: uuid::Uuid,
    pub target_entity_id: uuid::Uuid,
    pub source_revision: i64,
    pub target_revision: i64,
    pub merge_event_id: uuid::Uuid,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EntitySplitCommitRequest {
    pub source_entity_id: uuid::Uuid,
    pub target_entity_id: uuid::Uuid,
    pub source_revision: i64,
    pub target_revision: i64,
    pub merge_event_id: uuid::Uuid,
    pub confirm_preview_digest: String,
    pub acknowledge_evidence_preserved: bool,
}

#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
pub struct EntityResolutionImpactResponse {
    pub key_count: u64,
    pub claim_count: u64,
    pub relationship_count: u64,
    pub finding_count: u64,
}

impl From<EntityResolutionImpact> for EntityResolutionImpactResponse {
    fn from(value: EntityResolutionImpact) -> Self {
        Self {
            key_count: value.key_count,
            claim_count: value.claim_count,
            relationship_count: value.relationship_count,
            finding_count: value.finding_count,
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EntityResolutionPreviewResponse {
    pub operation: String,
    pub source: Entity,
    pub target: Entity,
    pub merge_event_id: Option<uuid::Uuid>,
    pub impact: EntityResolutionImpactResponse,
    pub preview_digest: String,
    pub evidence_mutated: bool,
    pub content_retained: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EntityResolutionEventResponse {
    pub event_id: uuid::Uuid,
    pub operation: String,
    pub source_entity_id: uuid::Uuid,
    pub target_entity_id: uuid::Uuid,
    pub source_display_name: String,
    pub target_display_name: String,
    pub merge_event_id: Option<uuid::Uuid>,
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

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EntityResolutionEventsResponse {
    pub events: Vec<EntityResolutionEventResponse>,
    pub content_retained: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EntityResolutionCommitResponse {
    pub event: EntityResolutionEventResponse,
    pub canonical_entity_id: uuid::Uuid,
    pub replayed: bool,
    pub evidence_mutated: bool,
    pub content_retained: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EvidenceClaimResponse {
    pub claim: Claim,
    pub observations: Vec<Observation>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationReasonInput {
    SanctionedBusinessUse,
    KnownPersonalUse,
    NeedsOwnerReview,
    DuplicateOrFalsePositive,
    ServiceRetired,
}

impl From<AuthorizationReasonInput> for AuthorizationReason {
    fn from(value: AuthorizationReasonInput) -> Self {
        match value {
            AuthorizationReasonInput::SanctionedBusinessUse => Self::SanctionedBusinessUse,
            AuthorizationReasonInput::KnownPersonalUse => Self::KnownPersonalUse,
            AuthorizationReasonInput::NeedsOwnerReview => Self::NeedsOwnerReview,
            AuthorizationReasonInput::DuplicateOrFalsePositive => Self::DuplicateOrFalsePositive,
            AuthorizationReasonInput::ServiceRetired => Self::ServiceRetired,
        }
    }
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct AuthorizationRequestBody {
    pub to_status: AuthorizationStatus,
    pub reason_code: AuthorizationReasonInput,
    pub expected_revision: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuthorizationResponse {
    pub replayed: bool,
    pub transition_id: uuid::Uuid,
    pub authorization: AuthorizationStatus,
    pub revision: i64,
    pub findings: Vec<tally_core::RiskFinding>,
}

const DEFAULT_RESOLVE_LIMIT: u32 = 10_000;
const MAX_RESOLVE_LIMIT: u32 = 100_000;

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ResolveRequest {
    /// Maximum recent observations to process in one bounded pass.
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ResolveResponse {
    pub registry_version: String,
    pub observations_processed: u64,
    pub classified: u64,
    pub unknown_candidates: u64,
    pub insufficient_metadata: u64,
    pub resolved_systems: u64,
    pub content_retained: bool,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ScanPreviewRequest {
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub exclusions: Vec<String>,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default = "default_scan_max_hosts")]
    pub max_hosts: u32,
    #[serde(default)]
    pub allow_public: bool,
    #[serde(default)]
    pub public_target_authorization: bool,
}

const fn default_scan_max_hosts() -> u32 {
    DEFAULT_MAX_HOSTS
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct ScanPlanResponse {
    pub version: String,
    pub targets: Vec<String>,
    pub ports: Vec<u16>,
    pub host_count: u64,
    pub probe_count: u64,
    pub allow_public: bool,
    pub public_target_authorization: bool,
    pub scope_digest: String,
}

impl From<&ScanPlan> for ScanPlanResponse {
    fn from(value: &ScanPlan) -> Self {
        Self {
            version: value.version.clone(),
            targets: value.targets.iter().map(ToString::to_string).collect(),
            ports: value.ports.clone(),
            host_count: value.host_count,
            probe_count: value.probe_count,
            allow_public: value.allow_public,
            public_target_authorization: value.authorization_acknowledged,
            scope_digest: value.scope_digest.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SkippedInterfaceResponse {
    pub name: String,
    pub address: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ScanPreviewResponse {
    pub plan: ScanPlanResponse,
    pub requested_targets: Vec<String>,
    pub skipped: Vec<SkippedInterfaceResponse>,
    pub discovered_local_scope: bool,
    pub sends_network_traffic: bool,
    pub content_retained: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema)]
pub struct ScanExecutionPolicyInput {
    #[serde(default = "default_scan_concurrency")]
    pub concurrency: u16,
    #[serde(default = "default_scan_timeout")]
    pub connect_timeout_millis: u64,
}

impl Default for ScanExecutionPolicyInput {
    fn default() -> Self {
        Self {
            concurrency: default_scan_concurrency(),
            connect_timeout_millis: default_scan_timeout(),
        }
    }
}

const fn default_scan_concurrency() -> u16 {
    DEFAULT_CONNECT_CONCURRENCY
}

const fn default_scan_timeout() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_MILLIS
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ScanStartRequest {
    pub plan: ScanPlanResponse,
    pub confirm_scope_digest: String,
    pub authorized_to_scan: bool,
    #[serde(default)]
    pub execution_policy: ScanExecutionPolicyInput,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ScanJobsResponse {
    pub items: Vec<ScanJobResponse>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ScanJobResponse {
    pub scan_id: uuid::Uuid,
    pub scope_digest: String,
    pub plan: serde_json::Value,
    pub execution_policy: serde_json::Value,
    pub status: String,
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

impl From<ScanJobView> for ScanJobResponse {
    fn from(value: ScanJobView) -> Self {
        Self {
            scan_id: value.scan_id,
            scope_digest: value.scope_digest,
            plan: value.plan,
            execution_policy: value.execution_policy,
            status: enum_name(value.status, "failed"),
            authorized_by: value.authorized_by,
            authorization_acknowledged_at: value.authorization_acknowledged_at,
            created_at: value.created_at,
            started_at: value.started_at,
            finished_at: value.finished_at,
            planned_probes: value.planned_probes,
            completed_probes: value.completed_probes,
            open_port_count: value.open_port_count,
            fingerprint_attempt_count: value.fingerprint_attempt_count,
            fingerprint_match_count: value.fingerprint_match_count,
            resolved_system_count: value.resolved_system_count,
            results: value.results,
            error_code: value.error_code,
            content_retained: value.content_retained,
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ConnectorStatesResponse {
    pub items: Vec<ConnectorStateResponse>,
    pub jobs: Vec<ConnectorJobResponse>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ConnectorScheduleRequest {
    #[serde(default)]
    pub connector_instance_id: Option<uuid::Uuid>,
    /// The operator's own label for this instance -- "Production EKS", "Staging cluster" --
    /// which is what tells two connectors of the same type apart everywhere they are rendered.
    /// Omit the field to keep whatever name is already stored; send an empty string to clear it.
    #[serde(default)]
    pub friendly_name: Option<String>,
    pub interval_seconds: u32,
    #[serde(flatten)]
    pub source: ConnectorScheduleSourceInput,
    #[serde(default)]
    pub paused: bool,
    pub acknowledge_source_access: bool,
}

/// A connector source as the operator filled it in on the console form.
///
/// Every field here is a value the operator typed, not the name of an environment variable:
/// account identifiers, endpoints, and API tokens alike. The values that are secret or
/// free-form never reach `config_refs` — [`connector_schedule_source`] routes them into the
/// sealed credential bundle stored on the job row.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(tag = "source_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConnectorScheduleSourceInput {
    ManagedAgents {
        platform: String,
        base_url: String,
        #[serde(default)]
        app_id: Option<String>,
        /// `OpenAI` project, Claude workspace, or Gemini `projects/{project}/locations/{location}`.
        #[serde(default)]
        scope_id: Option<String>,
        #[serde(default)]
        api_key: String,
    },
    NextdnsApi {
        profile_id: String,
        #[serde(default)]
        api_key: String,
        #[schema(minimum = 60, maximum = 604_800)]
        initial_backfill_seconds: u32,
        #[serde(default = "default_initial_record_limit")]
        initial_record_limit: u32,
    },
    ManagedCloud {
        adapter: ImportAdapterInput,
        account_id: String,
        #[serde(default)]
        scope_id: Option<String>,
        #[serde(default)]
        workspace_resource: Option<String>,
        region: String,
        #[serde(default)]
        aws_access_key_id: Option<String>,
        #[serde(default)]
        aws_secret_access_key: Option<String>,
        #[serde(default)]
        azure_tenant_id: Option<String>,
        #[serde(default)]
        azure_client_id: Option<String>,
        #[serde(default)]
        azure_client_secret: Option<String>,
        #[serde(default)]
        gcp_service_account_json: Option<String>,
    },
    CloudNetwork {
        adapter: ImportAdapterInput,
        account_id: String,
        network_id: String,
        #[serde(default)]
        region: Option<String>,
        #[serde(default)]
        log_group: Option<String>,
        #[serde(default)]
        workspace_resource: Option<String>,
        #[serde(default)]
        aws_access_key_id: Option<String>,
        #[serde(default)]
        aws_secret_access_key: Option<String>,
        #[serde(default)]
        azure_tenant_id: Option<String>,
        #[serde(default)]
        azure_client_id: Option<String>,
        #[serde(default)]
        azure_client_secret: Option<String>,
        #[serde(default)]
        gcp_service_account_json: Option<String>,
        #[schema(minimum = 300, maximum = 3600)]
        initial_backfill_seconds: u32,
    },
    CasbApi {
        account_id: String,
        #[serde(default)]
        api_token: String,
    },
    KubernetesApi {
        api_url: String,
        #[serde(default)]
        bearer_token: String,
        #[serde(default)]
        ca_pem: Option<String>,
    },
    LitellmApi {
        base_url: String,
        #[serde(default)]
        api_key: String,
        #[serde(default = "default_initial_backfill_seconds")]
        #[schema(minimum = 60, maximum = 604_800)]
        initial_backfill_seconds: u32,
        #[serde(default = "default_initial_record_limit")]
        initial_record_limit: u32,
    },
    AiGatewayApi {
        account_id: String,
        #[serde(default)]
        api_token: String,
        #[serde(default = "default_initial_backfill_seconds")]
        #[schema(minimum = 60, maximum = 604_800)]
        initial_backfill_seconds: u32,
        #[serde(default = "default_initial_record_limit")]
        initial_record_limit: u32,
    },
    Rapid7Edr {
        region: String,
        log_id: String,
        #[serde(default)]
        api_key: String,
        #[serde(default = "default_initial_backfill_seconds")]
        #[schema(minimum = 60, maximum = 604_800)]
        initial_backfill_seconds: u32,
    },
    Netskope {
        tenant_url: String,
        event_type: String,
        #[serde(default)]
        api_token: String,
        #[serde(default = "default_initial_backfill_seconds")]
        #[schema(minimum = 60, maximum = 604_800)]
        initial_backfill_seconds: u32,
    },
    CrowdstrikeEdr {
        cloud: String,
        #[serde(default)]
        client_id: String,
        #[serde(default)]
        client_secret: String,
        #[serde(default = "default_initial_backfill_seconds")]
        #[schema(minimum = 60, maximum = 604_800)]
        initial_backfill_seconds: u32,
        #[serde(default = "default_initial_record_limit")]
        initial_record_limit: u32,
    },
    MicrosoftDefenderApi {
        tenant_id: String,
        #[serde(default)]
        client_id: String,
        #[serde(default)]
        client_secret: String,
        #[serde(default = "default_initial_backfill_seconds")]
        #[schema(minimum = 60, maximum = 604_800)]
        initial_backfill_seconds: u32,
        #[serde(default = "default_initial_record_limit")]
        initial_record_limit: u32,
    },
    CatoNetworksApi {
        account_id: String,
        #[serde(default)]
        api_key: String,
        #[serde(default = "default_cato_api_hostname")]
        api_hostname: String,
        #[serde(default = "default_initial_backfill_seconds")]
        #[schema(minimum = 60, maximum = 604_800)]
        initial_backfill_seconds: u32,
        #[serde(default = "default_initial_record_limit")]
        initial_record_limit: u32,
    },
    CloudflareZeroTrustGateway {
        account_id: String,
        #[serde(default)]
        api_token: String,
        #[serde(default = "default_gateway_window_seconds")]
        window_seconds: u32,
        #[serde(default)]
        endpoint_url: String,
        #[serde(default)]
        bucket: String,
        #[serde(default)]
        prefix: String,
        #[serde(default = "default_s3_region")]
        region: String,
        #[serde(default)]
        access_key_id: String,
        #[serde(default)]
        secret_access_key: String,
        #[serde(default = "default_s3_object_limit")]
        object_limit: u32,
    },
}

const fn default_initial_backfill_seconds() -> u32 {
    3_600
}

const fn default_initial_record_limit() -> u32 {
    1_000
}

fn default_cato_api_hostname() -> String {
    "api.catonetworks.com".to_owned()
}

fn default_s3_region() -> String {
    "auto".to_owned()
}

const fn default_s3_object_limit() -> u32 {
    32
}

const fn default_gateway_window_seconds() -> u32 {
    3_600
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ConnectorJobResponse {
    pub job_id: uuid::Uuid,
    pub connector_instance_id: uuid::Uuid,
    pub mode: String,
    pub status: String,
    pub schedule_seconds: Option<i64>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub leased: bool,
    pub lease_until: Option<DateTime<Utc>>,
    pub source_reference_kind: Option<String>,
    pub source_reference: Option<String>,
    pub backfill: Option<ConnectorBackfillCapabilityResponse>,
    pub privacy: ConnectorJobPrivacyResponse,
    pub attempt_count: i64,
    pub consecutive_failures: i64,
    pub last_started_at: Option<DateTime<Utc>>,
    pub last_finished_at: Option<DateTime<Utc>>,
    pub last_outcome: Option<String>,
    pub last_error_code: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ConnectorConfigurationResponse {
    pub fields: BTreeMap<String, String>,
    pub credential_reentry_required: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ConnectorBackfillCapabilityResponse {
    pub source_kind: String,
    pub minimum_lookback_seconds: u32,
    pub maximum_lookback_seconds: u32,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ConnectorJobPrivacyResponse {
    /// True once the operator's credentials are stored sealed under `TALLY_SECRET_KEY`.
    pub credentials_sealed: bool,
    /// Always false: Tally has no path that writes a credential to `PostgreSQL` in the clear.
    pub plaintext_secret_stored: bool,
    /// Always false: connectors keep metadata and digests, never source content.
    pub content_retained: bool,
}

/// Receipt for one on-demand run request. The run itself happens in the collector, which
/// claims the schedule on its next poll; this says the schedule is now due.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ConnectorSyncResponse {
    pub requested_at: DateTime<Utc>,
    pub job: ConnectorJobResponse,
    /// Always false: an on-demand run reads the same bounded window as a scheduled one.
    pub content_retained: bool,
}

/// Receipt for an on-demand run request across every registered schedule.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ConnectorSyncSweepResponse {
    pub requested_at: DateTime<Utc>,
    /// Schedules now due.
    pub triggered: u64,
    /// Attempts already in flight, left on their existing lease.
    pub skipped_leased: u64,
    /// Paused schedules; an on-demand request does not resume them.
    pub skipped_paused: u64,
    pub jobs: Vec<ConnectorJobResponse>,
    pub content_retained: bool,
}

impl ConnectorSyncSweepResponse {
    fn from_sweep(sweep: ConnectorSyncSweep, requested_at: DateTime<Utc>) -> Self {
        Self {
            requested_at,
            triggered: u64::try_from(sweep.triggered.len()).unwrap_or(u64::MAX),
            skipped_leased: sweep.skipped_leased,
            skipped_paused: sweep.skipped_paused,
            jobs: sweep
                .triggered
                .into_iter()
                .map(ConnectorJobResponse::from)
                .collect(),
            content_retained: false,
        }
    }
}

/// Receipt for a removed connector: its schedule, sealed credentials, run receipts, and
/// ingestion ledger rows are gone. Observations it contributed are evidence and remain.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ConnectorDeleteResponse {
    pub connector_instance_id: uuid::Uuid,
    pub connector_type: String,
    pub display_name: String,
    /// The operator's own label for the removed instance, or null when they never named it.
    pub friendly_name: Option<String>,
    pub job_id: Option<uuid::Uuid>,
    pub schedule_deleted: bool,
    pub runs_deleted: u64,
    pub ingestion_batches_deleted: u64,
    /// Always true: deleting a connector never deletes the evidence it already contributed.
    /// The purge path is the only route that deletes observations.
    pub evidence_retained: bool,
    pub deleted_at: DateTime<Utc>,
}

impl From<ConnectorDeletion> for ConnectorDeleteResponse {
    fn from(value: ConnectorDeletion) -> Self {
        Self {
            connector_instance_id: value.connector_instance_id,
            connector_type: value.connector_type,
            display_name: value.display_name,
            friendly_name: optional_friendly_name(&value.friendly_name),
            job_id: value.job_id,
            schedule_deleted: value.schedule_deleted,
            runs_deleted: value.runs_deleted,
            ingestion_batches_deleted: value.ingestion_batches_deleted,
            evidence_retained: true,
            deleted_at: value.deleted_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorBackfillPreviewRequest {
    pub lookback_seconds: u32,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ConnectorBackfillPreviewResponse {
    pub job_id: uuid::Uuid,
    pub connector_instance_id: uuid::Uuid,
    pub source_kind: String,
    pub job_status: String,
    pub lookback_seconds: u32,
    pub minimum_lookback_seconds: u32,
    pub maximum_lookback_seconds: u32,
    pub cursor_present: bool,
    pub job_updated_at: DateTime<Utc>,
    pub preview_digest: String,
    pub existing_evidence_mutated: bool,
    pub content_retained: bool,
}

impl From<ConnectorBackfillPreview> for ConnectorBackfillPreviewResponse {
    fn from(value: ConnectorBackfillPreview) -> Self {
        Self {
            job_id: value.job_id,
            connector_instance_id: value.connector_instance_id,
            source_kind: enum_name(value.source_kind, "cloud_flow_api"),
            job_status: enum_name(value.job_status, "paused"),
            lookback_seconds: value.lookback_seconds,
            minimum_lookback_seconds: value.minimum_lookback_seconds,
            maximum_lookback_seconds: value.maximum_lookback_seconds,
            cursor_present: value.cursor_present,
            job_updated_at: value.job_updated_at,
            preview_digest: value.preview_digest,
            existing_evidence_mutated: false,
            content_retained: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorBackfillCommitRequest {
    pub lookback_seconds: u32,
    pub confirm_preview_digest: String,
    pub acknowledge_existing_evidence_preserved: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[allow(clippy::struct_excessive_bools)] // Protocol facts are deliberately independent and explicit.
pub struct ConnectorBackfillCommitResponse {
    pub request_id: uuid::Uuid,
    pub job_id: uuid::Uuid,
    pub connector_instance_id: uuid::Uuid,
    pub source_kind: String,
    pub job_status: String,
    pub lookback_seconds: u32,
    pub cursor_was_present: bool,
    pub scheduled_now: bool,
    pub preview_digest: String,
    pub committed_at: DateTime<Utc>,
    pub replayed: bool,
    pub existing_evidence_mutated: bool,
    pub content_retained: bool,
}

impl ConnectorBackfillCommitResponse {
    fn from_receipt(value: ConnectorBackfillReceipt, replayed: bool) -> Self {
        Self {
            request_id: value.request_id,
            job_id: value.job_id,
            connector_instance_id: value.connector_instance_id,
            source_kind: enum_name(value.source_kind, "cloud_flow_api"),
            job_status: enum_name(value.job_status, "paused"),
            lookback_seconds: value.lookback_seconds,
            cursor_was_present: value.cursor_was_present,
            scheduled_now: value.scheduled_now,
            preview_digest: value.preview_digest,
            committed_at: value.committed_at,
            replayed,
            existing_evidence_mutated: false,
            content_retained: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportPreviewRequest {
    pub adapter: ImportAdapterInput,
    #[serde(default)]
    pub connector_instance_id: Option<uuid::Uuid>,
    #[serde(default)]
    pub friendly_name: Option<String>,
    #[serde(default)]
    pub source_lineage_id: Option<String>,
    pub checkpoint: String,
    /// Required for managed-cloud fixtures so preview and commit normalize to the same source time.
    #[serde(default)]
    pub observed_at: Option<DateTime<Utc>>,
    /// Raw scope identifiers are accepted only for managed-cloud normalization, pseudonymized in
    /// memory, and never returned or stored.
    #[serde(default)]
    pub cloud_scope: Option<ManagedCloudScopeInput>,
    /// Raw CASB account identifier is accepted only for in-memory installation-HMAC
    /// pseudonymization and is never returned or stored.
    #[serde(default)]
    pub casb_account_id: Option<String>,
    pub data: String,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagedCloudScopeInput {
    Aws {
        account_id: String,
        region: String,
    },
    Azure {
        subscription_id: String,
        account_resource_id: String,
        region: String,
    },
    Gcp {
        project_id: String,
        location: String,
    },
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportCommitRequest {
    #[serde(flatten)]
    pub preview: ImportPreviewRequest,
    pub confirm_canonical_digest: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ImportDescriptorResponse {
    pub connector_type: String,
    pub display_name: String,
    pub source_vendor: String,
    pub source_product: String,
    pub transport: String,
    pub required_permissions: Vec<String>,
    pub requested_fields: Vec<String>,
    pub prohibited_fields: Vec<String>,
    pub privacy_contract: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ImportRedactionResponse {
    pub pseudonymization: String,
    pub discarded_fields: Vec<String>,
    pub source_bytes_retained: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ImportSampleResponse {
    pub observed_at: DateTime<Utc>,
    pub kind: String,
    pub destination: Option<String>,
    pub actor: Option<String>,
    pub outcome: Option<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ImportPreviewResponse {
    pub descriptor: ImportDescriptorResponse,
    pub records_read: u64,
    pub accepted: u64,
    pub ignored: u64,
    pub rejected: u64,
    pub connector_instance_id: uuid::Uuid,
    pub canonical_digest: String,
    pub observation_count: u64,
    pub redaction: ImportRedactionResponse,
    pub samples: Vec<ImportSampleResponse>,
    pub writes_data: bool,
    pub source_bytes_retained: bool,
    pub content_retained: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ImportCommitResponse {
    pub run_id: uuid::Uuid,
    pub batch_id: uuid::Uuid,
    pub disposition: String,
    pub status: String,
    pub accepted: u64,
    pub deduplicated: u64,
    pub findings_updated: usize,
    pub canonical_digest: String,
    pub content_retained: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ConnectorStateResponse {
    /// Illustrative sample connector; it has no credentials or polling schedule.
    pub sample: bool,
    pub connector_instance_id: uuid::Uuid,
    pub connector_type: String,
    /// Catalog label for the connector type; identical across every instance of that type.
    pub display_name: String,
    /// The operator's own label for this instance, or null when they never named it.
    pub friendly_name: Option<String>,
    pub implementation_version: String,
    pub transport: String,
    pub health: String,
    pub cursor_value: String,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_poll_at: Option<DateTime<Utc>>,
    pub last_source_at: Option<DateTime<Utc>>,
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

#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Unscored,
    Partial,
    Complete,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CoverageResponse {
    pub status: CoverageStatus,
    pub weighted_percent: Option<f32>,
    pub scoring_reason: String,
    pub configured_sources: usize,
    pub healthy_sources: usize,
    pub delayed_sources: usize,
    pub error_sources: usize,
    pub never_run_sources: usize,
    pub freshness_slo_met_sources: usize,
    pub freshness_slo_breached_sources: usize,
    pub freshness_slo_error_sources: usize,
    pub freshness_slo_unmeasured_sources: usize,
    pub systems_total: usize,
    pub corroborated_systems: usize,
    pub strong_evidence_systems: usize,
    pub pseudonymous_actors_observed: usize,
    pub observation_total: u64,
    pub observation_window_truncated: bool,
    pub first_observed_at: Option<DateTime<Utc>>,
    pub last_observed_at: Option<DateTime<Utc>>,
    pub sources: Vec<CoverageSourceResponse>,
    pub blind_spots: Vec<CoverageBlindSpot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessSloStatus {
    Met,
    Breached,
    Unmeasured,
    Error,
    Paused,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CoverageSourceResponse {
    pub connector_instance_id: uuid::Uuid,
    pub display_name: String,
    /// The operator's own label for this instance, or null when they never named it.
    pub friendly_name: Option<String>,
    pub connector_type: String,
    pub health: String,
    pub lag_seconds: Option<i64>,
    pub last_source_at: Option<DateTime<Utc>>,
    pub freshness_slo_status: FreshnessSloStatus,
    pub freshness_slo_seconds: Option<i64>,
    pub source_age_seconds: Option<i64>,
    pub breach_seconds: Option<i64>,
    pub alertable: bool,
    pub records_read_total: i64,
    pub accepted_total: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CoverageBlindSpot {
    pub code: String,
    pub title: String,
    pub detail: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FindingsResponse {
    pub open: usize,
    pub items: Vec<FindingResponse>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FindingResponse {
    pub finding_id: uuid::Uuid,
    pub system_id: uuid::Uuid,
    pub system_name: String,
    pub policy_id: String,
    pub policy_version: String,
    pub title: String,
    pub severity: RiskSeverity,
    pub status: String,
    pub factor_codes: Vec<String>,
    pub factors: Vec<RiskFactorResponse>,
    pub system_revision: i64,
    pub evidence_source_count: i32,
    pub first_evaluated_at: DateTime<Utc>,
    pub last_evaluated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RiskFactorResponse {
    pub code: String,
    pub explanation: String,
    pub weight: i16,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuditResponse {
    pub items: Vec<AuditEventResponse>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuditEventResponse {
    pub audit_id: uuid::Uuid,
    pub at: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub entity_type: String,
    pub entity_id: String,
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PurgeCountsResponse {
    pub observations: u64,
    pub entities: u64,
    pub entity_keys: u64,
    pub relationships: u64,
    pub relationship_evidence: u64,
    pub attribution_checkpoints: u64,
    pub attribution_conflicts: u64,
    pub entity_resolution_events: u64,
    pub entity_resolution_aliases: u64,
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
    pub total_records: u64,
}

impl From<&PurgeCounts> for PurgeCountsResponse {
    fn from(value: &PurgeCounts) -> Self {
        let total_records = value
            .observations
            .saturating_add(value.entities)
            .saturating_add(value.entity_keys)
            .saturating_add(value.relationships)
            .saturating_add(value.relationship_evidence)
            .saturating_add(value.attribution_checkpoints)
            .saturating_add(value.attribution_conflicts)
            .saturating_add(value.entity_resolution_events)
            .saturating_add(value.entity_resolution_aliases)
            .saturating_add(value.connectors)
            .saturating_add(value.connector_runs)
            .saturating_add(value.connector_jobs)
            .saturating_add(value.connector_backfill_requests)
            .saturating_add(value.ingestion_batches)
            .saturating_add(value.systems)
            .saturating_add(value.findings)
            .saturating_add(value.claims)
            .saturating_add(value.evidence_links)
            .saturating_add(value.authorization_transitions)
            .saturating_add(value.mutation_receipts)
            .saturating_add(value.registry_overlays)
            .saturating_add(value.registry_mutation_receipts)
            .saturating_add(value.classification_rule_sets)
            .saturating_add(value.scans)
            .saturating_add(value.audit_events);
        Self {
            observations: value.observations,
            entities: value.entities,
            entity_keys: value.entity_keys,
            relationships: value.relationships,
            relationship_evidence: value.relationship_evidence,
            attribution_checkpoints: value.attribution_checkpoints,
            attribution_conflicts: value.attribution_conflicts,
            entity_resolution_events: value.entity_resolution_events,
            entity_resolution_aliases: value.entity_resolution_aliases,
            connectors: value.connectors,
            connector_runs: value.connector_runs,
            connector_jobs: value.connector_jobs,
            connector_backfill_requests: value.connector_backfill_requests,
            ingestion_batches: value.ingestion_batches,
            systems: value.systems,
            findings: value.findings,
            claims: value.claims,
            evidence_links: value.evidence_links,
            authorization_transitions: value.authorization_transitions,
            mutation_receipts: value.mutation_receipts,
            registry_overlays: value.registry_overlays,
            registry_mutation_receipts: value.registry_mutation_receipts,
            classification_rule_sets: value.classification_rule_sets,
            scans: value.scans,
            audit_events: value.audit_events,
            total_records,
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PurgePreviewResponse {
    pub preview_digest: String,
    pub counts: PurgeCountsResponse,
    pub confirmation_phrase: &'static str,
    pub preserved: Vec<String>,
    pub destructive: bool,
    pub reversible: bool,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PurgeCommitRequest {
    pub confirm_preview_digest: String,
    pub confirmation: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PurgeCommitResponse {
    pub purge_id: uuid::Uuid,
    pub preview_digest: String,
    pub deleted: PurgeCountsResponse,
    pub installation_identity_preserved: bool,
    pub registry_artifact_preserved: bool,
    pub content_retained: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub type_uri: String,
    pub title: String,
    pub status: u16,
    pub code: String,
}

impl From<tally_store_postgres::ConnectorStateView> for ConnectorStateResponse {
    fn from(value: tally_store_postgres::ConnectorStateView) -> Self {
        Self {
            sample: false,
            connector_instance_id: value.connector_instance_id,
            connector_type: value.connector_type,
            friendly_name: optional_friendly_name(&value.friendly_name),
            display_name: value.display_name,
            implementation_version: value.implementation_version,
            transport: enum_name(value.transport, "file"),
            health: enum_name(value.health, "never_run"),
            cursor_value: value.cursor_value,
            last_success_at: value.last_success_at,
            last_poll_at: value.last_poll_at,
            last_source_at: value.last_source_at,
            lag_seconds: value.lag_seconds,
            records_read_total: value.records_read_total,
            accepted_total: value.accepted_total,
            ignored_total: value.ignored_total,
            rejected_total: value.rejected_total,
            deduplicated_total: value.deduplicated_total,
            last_error_code: value.last_error_code,
            redaction_digest: value.redaction_digest,
            descriptor: value.descriptor,
        }
    }
}

impl From<ConnectorJobView> for ConnectorJobResponse {
    fn from(value: ConnectorJobView) -> Self {
        let backfill = connector_backfill_capability(&value.config_refs).map(|capability| {
            ConnectorBackfillCapabilityResponse {
                source_kind: enum_name(capability.source_kind, "cloud_flow_api"),
                minimum_lookback_seconds: capability.minimum_lookback_seconds,
                maximum_lookback_seconds: capability.maximum_lookback_seconds,
            }
        });
        let source_reference_kind = value
            .config_refs
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        // Operator-entered values live in the sealed bundle, so the console label is built
        // from what config_refs still carries in the clear: the adapter, the profile, and
        // the region. Never from a credential.
        let source_reference = ["adapter", "profile_id", "region", "api_hostname"]
            .into_iter()
            .filter_map(|key| {
                value
                    .config_refs
                    .get(key)
                    .and_then(serde_json::Value::as_str)
            })
            .collect::<Vec<_>>();
        let source_reference = (!source_reference.is_empty()).then(|| source_reference.join(" · "));
        Self {
            job_id: value.job_id,
            connector_instance_id: value.connector_instance_id,
            mode: enum_name(value.mode, "scheduled"),
            status: enum_name(value.status, "paused"),
            schedule_seconds: value.schedule_seconds,
            next_run_at: value.next_run_at,
            leased: value
                .lease_until
                .is_some_and(|lease_until| lease_until > Utc::now()),
            lease_until: value.lease_until,
            source_reference_kind,
            source_reference,
            backfill,
            privacy: ConnectorJobPrivacyResponse {
                credentials_sealed: value.credentials_stored,
                plaintext_secret_stored: false,
                content_retained: false,
            },
            attempt_count: value.attempt_count,
            consecutive_failures: value.consecutive_failures,
            last_started_at: value.last_started_at,
            last_finished_at: value.last_finished_at,
            last_outcome: value
                .last_outcome
                .map(|outcome| enum_name(outcome, "failed")),
            last_error_code: value.last_error_code,
            updated_at: value.updated_at,
        }
    }
}

fn enum_name(value: impl Serialize, fallback: &'static str) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| fallback.to_owned())
}

fn parse_etag_revision(value: &str) -> Option<i64> {
    let value = value.trim();
    if value.starts_with("W/") {
        return None;
    }
    value.trim_matches('"').parse().ok()
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
}

impl ApiError {
    const fn new(status: StatusCode, code: &'static str) -> Self {
        Self { status, code }
    }

    fn dependency<T: std::fmt::Display>(error: T) -> Self {
        // The response carries only the stable code, so the cause has to reach the log.
        tracing::error!(error = %error, "Tally dependency call failed");
        Self::dependency_message("dependency_unavailable")
    }

    const fn dependency_message(code: &'static str) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, code)
    }

    #[allow(clippy::too_many_lines)]
    fn from_store(error: PostgresStoreError) -> Self {
        match error {
            PostgresStoreError::InvalidRegistrySanction => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "registry_provider_domain_missing",
            ),
            PostgresStoreError::SystemNotFound => {
                Self::new(StatusCode::NOT_FOUND, "system_not_found")
            }
            PostgresStoreError::RevisionConflict { .. } => {
                Self::new(StatusCode::CONFLICT, "revision_conflict")
            }
            PostgresStoreError::IdempotencyConflict
            | PostgresStoreError::EntityResolutionIdempotencyConflict => {
                Self::new(StatusCode::CONFLICT, "idempotency_conflict")
            }
            PostgresStoreError::AuthorizationUnchanged => {
                Self::new(StatusCode::UNPROCESSABLE_ENTITY, "authorization_unchanged")
            }
            PostgresStoreError::InvalidAuthorizationTransition => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_authorization_transition",
            ),
            PostgresStoreError::InvalidAuthorizationReason => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_authorization_reason",
            ),
            PostgresStoreError::ScanNotFound => Self::new(StatusCode::NOT_FOUND, "scan_not_found"),
            PostgresStoreError::InvalidScanStatus => {
                Self::new(StatusCode::CONFLICT, "scan_not_cancellable")
            }
            PostgresStoreError::RegistryOverlayExists => {
                Self::new(StatusCode::CONFLICT, "registry_overlay_exists")
            }
            PostgresStoreError::UnsafeRegistryOverlay => {
                Self::new(StatusCode::UNPROCESSABLE_ENTITY, "registry_overlay_invalid")
            }
            PostgresStoreError::UnsafeClassificationRuleSet => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "classification_rule_set_invalid",
            ),
            PostgresStoreError::ClassificationPreviewChanged => {
                Self::new(StatusCode::CONFLICT, "classification_preview_changed")
            }
            PostgresStoreError::ClassificationRuleSetNotFound => {
                Self::new(StatusCode::NOT_FOUND, "classification_rule_set_not_found")
            }
            PostgresStoreError::ClassificationRuleSetInactive => {
                Self::new(StatusCode::CONFLICT, "classification_rule_set_inactive")
            }
            PostgresStoreError::ClassificationRuleConflict => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "classification_rule_conflict",
            ),
            PostgresStoreError::EntityResolutionEntityNotFound => {
                Self::new(StatusCode::NOT_FOUND, "entity_resolution_entity_not_found")
            }
            PostgresStoreError::EntityResolutionRevisionConflict { .. } => {
                Self::new(StatusCode::CONFLICT, "entity_resolution_revision_conflict")
            }
            PostgresStoreError::InvalidEntityResolution => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_entity_resolution",
            ),
            PostgresStoreError::EntityResolutionPreviewChanged => {
                Self::new(StatusCode::CONFLICT, "entity_resolution_preview_changed")
            }
            PostgresStoreError::ConnectorJobNotFound => {
                Self::new(StatusCode::NOT_FOUND, "connector_job_not_found")
            }
            PostgresStoreError::ConnectorJobLeased => {
                Self::new(StatusCode::CONFLICT, "connector_job_leased")
            }
            PostgresStoreError::ConnectorJobPaused => {
                Self::new(StatusCode::CONFLICT, "connector_job_paused")
            }
            PostgresStoreError::ConnectorNotFound => {
                Self::new(StatusCode::NOT_FOUND, "connector_not_found")
            }
            PostgresStoreError::ConnectorDeleteBlocked => {
                Self::new(StatusCode::CONFLICT, "connector_delete_blocked")
            }
            PostgresStoreError::ConnectorFriendlyNameInvalid => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "connector_friendly_name_invalid",
            ),
            PostgresStoreError::ConnectorBackfillPreviewChanged => {
                Self::new(StatusCode::CONFLICT, "connector_backfill_preview_changed")
            }
            PostgresStoreError::ConnectorBackfillIdempotencyConflict => Self::new(
                StatusCode::CONFLICT,
                "connector_backfill_idempotency_conflict",
            ),
            PostgresStoreError::ConnectorBackfillUnsupported => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "connector_backfill_unsupported",
            ),
            PostgresStoreError::ConnectorBackfillOutOfRange => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "connector_backfill_out_of_range",
            ),
            PostgresStoreError::UnsafeConnectorBackfill => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "connector_backfill_invalid",
            ),
            _ => Self::dependency(error),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let title = self.code.replace('_', " ");
        (
            self.status,
            Json(ProblemDetails {
                type_uri: format!("urn:godel-tally:problem:{}", self.code),
                title,
                status: self.status.as_u16(),
                code: self.code.to_owned(),
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OverviewState {
    Ready,
    NoSources,
    Stale,
}

#[derive(Debug, OpenApi)]
#[openapi(
    info(
        title = "Gödel Tally API",
        description = "AI provider and model governance API",
        version = "0.1.0-alpha.1"
    ),
    paths(
        estate::inventory,
        estate::activity,
        event_stream::event_stream,
        estate::activity_records,
        estate::review::update,
        live,
        ready,
        version,
        overview,
        registry_providers,
        registry_provider_domains,
        registry_models,
        registry_sanction,
        findings,
        connectors,
        connector_configuration,
        upsert_connector_schedule,
        sync_connector,
        sync_all_connectors,
        delete_connector,
        preview_import,
        commit_import,
        audit,
        data_inventory,
        data_preview::preview,
        sample_data::status,
        sample_data::add,
        sample_data::remove,
        delete_data,
        preview_scan,
        start_scan,
        scans,
        scan,
        cancel_scan
    ),
    components(schemas(
        HealthResponse,
        HealthStatus,
        DependencyHealth,
        VersionResponse,
        TallyOverviewSummary,
        RegistryProviderView,
        RegistryModelView,
        RegistrySanctionRequest,
        RegistrySanctionResponse,
        GovernanceFindingsResponse,
        GovernanceFindingView,
        GovernanceFindingStatus,
        tally_store_postgres::FindingDestinationView,
        tally_store_postgres::FindingEndpointView,
        tally_store_postgres::FindingUserView,
        tally_store_postgres::FindingConnectorView,
        ConnectorStatesResponse,
        ConnectorStateResponse,
        ConnectorScheduleRequest,
        ConnectorScheduleSourceInput,
        ConnectorJobResponse,
        ConnectorConfigurationResponse,
        ConnectorJobPrivacyResponse,
        ConnectorBackfillCapabilityResponse,
        ConnectorSyncResponse,
        ConnectorSyncSweepResponse,
        ConnectorDeleteResponse,
        ImportAdapterInput,
        ManagedCloudScopeInput,
        ImportPreviewRequest,
        ImportCommitRequest,
        ImportDescriptorResponse,
        ImportRedactionResponse,
        ImportSampleResponse,
        ImportPreviewResponse,
        ImportCommitResponse,
        AuditResponse,
        AuditEventResponse,
        DataInventory,
        data_preview::DataTarget,
        sample_data::SampleDataStatus,
        sample_data::RemoveSampleDataRequest,
        DeleteDataRequest,
        ScanPreviewRequest,
        ScanPreviewResponse,
        ScanPlanResponse,
        SkippedInterfaceResponse,
        ScanExecutionPolicyInput,
        ScanStartRequest,
        ScanJobsResponse,
        ScanJobResponse,
        ProblemDetails
    )),
    tags((name = "tally", description = "Gödel Tally v1 API"))
)]
pub struct ApiDoc;

pub fn openapi() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}

fn safe_managed_origin(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        (url.scheme() == "https"
            || (url.scheme() == "http"
                && url.host_str().is_some_and(|host| {
                    host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
                })))
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && matches!(url.path(), "" | "/")
    })
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, net::IpAddr};

    use tally_core::{BasisPoints, DigestAlgorithm, EvidenceQuality, Lifecycle, Surface};

    use super::*;

    fn governance_registry() -> RegistryBundle {
        let host_product =
            |id: &str, name: &str, provider_ref: &str, host: &str| -> RegistryEntry {
                let verified_at = "2026-08-26".parse().expect("date");
                let evidence_url = if host == "chatgpt.com" {
                    "https://help.openai.com/en/articles/12677804-what-is-chatgpt-faq"
                } else {
                    "https://api-docs.deepseek.com/news/news1210/"
                };
                RegistryEntry {
                    id: id.to_owned(),
                    kind: RegistryEntryKind::Product,
                    name: name.to_owned(),
                    provider_ref: Some(provider_ref.to_owned()),
                    categories: vec!["enterprise_application".to_owned()],
                    surfaces: vec!["browser_application".to_owned()],
                    facts: BTreeMap::new(),
                    matchers: vec![Matcher {
                        id: format!("host.{id}"),
                        rule: MatcherRule::HostExact {
                            value: host.to_owned(),
                        },
                        produces: MatchProduces {
                            entity_ref: id.to_owned(),
                            proof: ProofKind::ProductUse,
                        },
                        confidence_bps: 9_800,
                        verified_at,
                        evidence: vec![Evidence {
                            source_type: EvidenceType::VendorDocumentation,
                            url: evidence_url.to_owned(),
                            verified_at,
                            reviewer: "maintainer".to_owned(),
                        }],
                    }],
                    status: RegistryEntryStatus::Active,
                }
            };
        RegistryBundle {
            schema_version: REGISTRY_SCHEMA_VERSION.to_owned(),
            version: "test-v1".to_owned(),
            source_sha256: "0".repeat(64),
            fingerprints: Vec::new(),
            entries: vec![
                RegistryEntry {
                    id: "provider.openai".to_owned(),
                    kind: RegistryEntryKind::Provider,
                    name: "OpenAI".to_owned(),
                    provider_ref: None,
                    categories: vec!["direct_ai_provider".to_owned()],
                    surfaces: Vec::new(),
                    facts: BTreeMap::new(),
                    matchers: Vec::new(),
                    status: RegistryEntryStatus::Active,
                },
                RegistryEntry {
                    id: "svc.openai.api".to_owned(),
                    kind: RegistryEntryKind::Service,
                    name: "OpenAI API".to_owned(),
                    provider_ref: Some("provider.openai".to_owned()),
                    categories: vec!["llm_api".to_owned()],
                    surfaces: vec!["external_api".to_owned()],
                    facts: BTreeMap::new(),
                    matchers: Vec::new(),
                    status: RegistryEntryStatus::Active,
                },
                RegistryEntry {
                    id: "provider.deepseek".to_owned(),
                    kind: RegistryEntryKind::Provider,
                    name: "DeepSeek".to_owned(),
                    provider_ref: None,
                    categories: vec!["direct_ai_provider".to_owned()],
                    surfaces: Vec::new(),
                    facts: BTreeMap::new(),
                    matchers: Vec::new(),
                    status: RegistryEntryStatus::Active,
                },
                host_product(
                    "app.openai.chatgpt",
                    "ChatGPT",
                    "provider.openai",
                    "chatgpt.com",
                ),
                host_product(
                    "app.deepseek.chat",
                    "DeepSeek Chat",
                    "provider.deepseek",
                    "chat.deepseek.com",
                ),
            ],
        }
    }

    pub(super) fn usage_observation(kind: ObservationKind) -> Observation {
        let mut observation = Observation::new(
            uuid::Uuid::now_v7(),
            Utc::now(),
            ConnectorRef {
                instance_id: uuid::Uuid::now_v7(),
                connector_type: "fixture".to_owned(),
                implementation_version: "1".to_owned(),
                source_lineage_id: None,
            },
            kind,
            EvidenceReceipt::RecordDigest {
                algorithm: DigestAlgorithm::Sha256,
                digest: "ab".repeat(32),
            },
        );
        observation.service.vendor_application_id = Some("svc.openai.api".to_owned());
        observation.destination.host = Some(Hostname::parse("api.openai.com").expect("host"));
        observation.destination.ip = Some(IpAddress::parse("203.0.113.20").expect("IP"));
        observation.actor.hostname = Some("laptop-42".to_owned());
        observation.actor.source_ip = Some(IpAddress::parse("10.0.0.42").expect("IP"));
        observation
    }

    #[test]
    fn request_client_projection_reaches_finding_context() {
        let mut observation = usage_observation(ObservationKind::HttpMetadata);
        observation.actor.request_client = Some(tally_core::RequestClientObservation {
            name: Some(tally_core::RequestClientKind::LangChain),
            agent_id: Some("agent-42".to_owned()),
        });
        let usage = usage_from_observation(&observation, &governance_registry())
            .unwrap()
            .unwrap();
        assert_eq!(usage.request_client, observation.actor.request_client);
        assert_eq!(
            tally_store_postgres::FindingObservationContext::from(&usage).request_client,
            usage.request_client
        );
    }

    fn connector_import_config() -> VendorImportConfig {
        VendorImportConfig {
            installation_id: uuid::Uuid::parse_str("018f6cd4-4aaf-7bb4-a3b2-a7524ec43711")
                .expect("installation UUID"),
            connector_instance_id: uuid::Uuid::parse_str("018f6cd4-4aaf-7bb4-a3b2-a7524ec43741")
                .expect("connector UUID"),
            implementation_version: "test".to_owned(),
            source_lineage_id: Some("finding-attribution-test".to_owned()),
            received_at: "2026-08-13T10:05:00Z".parse().expect("received timestamp"),
            checkpoint: Cursor("finding-attribution-test".to_owned()),
            pseudonymization_key: PseudonymizationKey::new(&[7; 32]).expect("pseudonymization key"),
        }
    }

    fn assert_finding_attribution(
        observation: &Observation,
        registry: &RegistryBundle,
        destination_hostname: &str,
        source_hostname: Option<&str>,
        user_email: Option<&str>,
    ) {
        let usage = usage_from_observation(observation, registry)
            .expect("usage projection")
            .expect("finding-worthy usage");
        assert!(usage.destinations.iter().any(|destination| {
            destination.kind == "hostname" && destination.value == destination_hostname
        }));
        if let Some(source_hostname) = source_hostname {
            assert!(usage.endpoints.iter().any(|endpoint| {
                endpoint.kind == "hostname"
                    && endpoint.value == source_hostname
                    && endpoint.role == "source"
            }));
        }
        assert_eq!(
            usage
                .user_identity
                .as_ref()
                .and_then(|identity| identity.email.as_deref()),
            user_email
        );
    }

    #[test]
    fn governance_findings_separate_endpoints_from_remote_destinations() {
        let registry = governance_registry();
        let capability = usage_observation(ObservationKind::SaasCapability);
        assert!(
            usage_from_observation(&capability, &registry)
                .expect("capability projection")
                .is_none()
        );

        let usage =
            usage_from_observation(&usage_observation(ObservationKind::HttpMetadata), &registry)
                .expect("usage projection")
                .expect("finding-worthy usage");
        assert_eq!(usage.provider_key, "openai");
        assert_eq!(usage.provider_category, "direct_provider");
        assert_eq!(usage.destinations.len(), 2);
        assert_eq!(usage.endpoints.len(), 2);
        assert!(usage.destinations.iter().any(|destination| {
            destination.kind == "hostname" && destination.value == "api.openai.com"
        }));
        assert!(usage.endpoints.iter().any(|endpoint| {
            endpoint.kind == "hostname"
                && endpoint.value == "laptop-42"
                && endpoint.role == "source"
        }));

        let local_usage = usage_from_observation(
            &usage_observation(ObservationKind::ScanFingerprint),
            &registry,
        )
        .expect("local usage projection")
        .expect("finding-worthy local usage");
        assert_eq!(
            local_usage.destinations,
            [] as [tally_store_postgres::DestinationIdentity; 0]
        );
        assert!(local_usage.endpoints.iter().any(|endpoint| {
            endpoint.kind == "hostname"
                && endpoint.value == "api.openai.com"
                && endpoint.role == "local_service"
        }));
    }

    #[test]
    fn unique_cloud_flow_adds_private_source_context_to_managed_usage() {
        let registry = governance_registry();
        let installation_id = uuid::Uuid::now_v7();
        let invocation_time = Utc::now();
        let mut invocation = usage_observation(ObservationKind::CloudUsage);
        invocation.installation_id = installation_id;
        invocation.observed_at = invocation_time;
        invocation.cloud.provider = Some(tally_core::CloudProvider::Aws);
        invocation.cloud.provider_service = Some(CloudProviderService::AwsBedrock);
        invocation.cloud.usage_kind = Some(CloudUsageKind::Invocation);
        invocation.cloud.account_key = Some("p1_account".to_owned());
        invocation.cloud.region = Some("us-east-1".to_owned());
        invocation.service.ai_request = true;
        invocation.service.ai_request_evaluated = true;

        let mut flow = usage_observation(ObservationKind::NetworkFlow);
        flow.installation_id = installation_id;
        flow.observed_at = invocation_time - Duration::seconds(2);
        flow.connector.instance_id = uuid::Uuid::now_v7();
        flow.service.vendor_application_id = None;
        flow.cloud.provider = Some(tally_core::CloudProvider::Aws);
        flow.cloud.usage_kind = Some(CloudUsageKind::NetworkFlow);
        flow.cloud.account_key = Some("p1_account".to_owned());
        flow.cloud.region = Some("us-east-1".to_owned());
        flow.network.protocol = Some("tcp".to_owned());
        flow.network.destination_port = Some(443);
        flow.network.direction = Some(FlowDirection::Egress);
        flow.network.valid_until = Some(invocation_time + Duration::seconds(2));
        flow.outcome.action = Some("accepted".to_owned());
        flow.actor.hostname = Some("model-client-1".to_owned());
        flow.actor.source_ip = Some(IpAddress::parse("10.0.0.42").expect("source IP"));

        let correlated = correlate_cloud_flows(
            std::slice::from_ref(&flow),
            &[invocation, flow.clone()],
            &registry,
        )
        .expect("correlation");
        assert_eq!(correlated.len(), 1);
        assert_eq!(
            correlated[0].connector_instance_id,
            flow.connector.instance_id
        );
        assert_eq!(correlated[0].evidence_kind, FindingEvidenceKind::AiUsage);
        assert!(
            correlated[0].endpoints.iter().any(|endpoint| {
                endpoint.value == "model-client-1" && endpoint.role == "source"
            })
        );
        assert!(
            correlated[0]
                .endpoints
                .iter()
                .any(|endpoint| { endpoint.value == "10.0.0.42" && endpoint.role == "source" })
        );
    }

    #[test]
    fn aws_vpc_flow_start_skew_still_correlates_unique_invocation() {
        let registry = governance_registry();
        let installation_id = uuid::Uuid::now_v7();
        let invocation_time = Utc::now();
        let mut invocation = usage_observation(ObservationKind::CloudUsage);
        invocation.installation_id = installation_id;
        invocation.observed_at = invocation_time;
        invocation.cloud.provider = Some(tally_core::CloudProvider::Aws);
        invocation.cloud.provider_service = Some(CloudProviderService::AwsBedrock);
        invocation.cloud.usage_kind = Some(CloudUsageKind::Invocation);
        invocation.cloud.account_key = Some("p1_account".to_owned());
        invocation.cloud.region = Some("us-east-1".to_owned());
        invocation.service.ai_request = true;
        invocation.service.ai_request_evaluated = true;

        let mut flow = usage_observation(ObservationKind::NetworkFlow);
        flow.installation_id = installation_id;
        flow.observed_at = invocation_time + Duration::seconds(6);
        flow.connector.instance_id = uuid::Uuid::now_v7();
        flow.service.vendor_application_id = None;
        flow.cloud.provider = Some(tally_core::CloudProvider::Aws);
        flow.cloud.usage_kind = Some(CloudUsageKind::NetworkFlow);
        flow.cloud.account_key = Some("p1_account".to_owned());
        flow.cloud.region = Some("us-east-1".to_owned());
        flow.network.protocol = Some("tcp".to_owned());
        flow.network.destination_port = Some(443);
        flow.network.direction = Some(FlowDirection::Egress);
        flow.network.valid_until = Some(invocation_time + Duration::seconds(33));
        flow.outcome.action = Some("accepted".to_owned());
        flow.actor.hostname = Some("ip-172-31-87-51.ec2.internal".to_owned());
        flow.actor.source_ip = Some(IpAddress::parse("172.31.87.51").expect("source IP"));

        let correlated = correlate_cloud_flows(
            std::slice::from_ref(&flow),
            &[invocation, flow.clone()],
            &registry,
        )
        .expect("AWS aggregation-window correlation");

        assert_eq!(correlated.len(), 1);
        assert_eq!(
            correlated[0].connector_instance_id,
            flow.connector.instance_id
        );
        assert!(
            correlated[0]
                .endpoints
                .iter()
                .any(|endpoint| endpoint.value == "172.31.87.51" && endpoint.role == "source")
        );
    }

    #[test]
    fn aws_vpc_endpoint_invocation_excludes_concurrent_public_tls_flow() {
        let registry = governance_registry();
        let installation_id = uuid::Uuid::now_v7();
        let invocation_time = Utc::now();
        let mut invocation = usage_observation(ObservationKind::CloudUsage);
        invocation.installation_id = installation_id;
        invocation.observed_at = invocation_time;
        invocation.cloud.provider = Some(tally_core::CloudProvider::Aws);
        invocation.cloud.provider_service = Some(CloudProviderService::AwsBedrock);
        invocation.cloud.usage_kind = Some(CloudUsageKind::Invocation);
        invocation.cloud.account_key = Some("p1_account".to_owned());
        invocation.cloud.region = Some("us-east-1".to_owned());
        invocation.service.ai_request = true;
        invocation.service.ai_request_evaluated = true;
        invocation.destination.host = Some(
            Hostname::parse(
                "vpce-0123456789abcdef0-test.us-east-1a.bedrock-runtime.us-east-1.vpce.amazonaws.com",
            )
            .expect("VPC endpoint host"),
        );

        let mut private_flow = usage_observation(ObservationKind::NetworkFlow);
        private_flow.installation_id = installation_id;
        private_flow.observed_at = invocation_time;
        private_flow.connector.instance_id = uuid::Uuid::now_v7();
        private_flow.service.vendor_application_id = None;
        private_flow.cloud.provider = Some(tally_core::CloudProvider::Aws);
        private_flow.cloud.usage_kind = Some(CloudUsageKind::NetworkFlow);
        private_flow.cloud.account_key = Some("p1_account".to_owned());
        private_flow.cloud.region = Some("us-east-1".to_owned());
        private_flow.network.protocol = Some("tcp".to_owned());
        private_flow.network.destination_port = Some(443);
        private_flow.network.direction = Some(FlowDirection::Unknown);
        private_flow.network.valid_until = Some(invocation_time + Duration::seconds(30));
        private_flow.outcome.action = Some("accepted".to_owned());
        private_flow.destination.host = None;
        private_flow.destination.ip =
            Some(IpAddress::parse("10.242.0.11").expect("private endpoint IP"));
        private_flow.actor.source_ip = Some(IpAddress::parse("10.242.0.4").expect("source IP"));

        let mut public_flow = private_flow.clone();
        public_flow.observation_id = uuid::Uuid::now_v7();
        public_flow.destination.ip =
            Some(IpAddress::parse("13.217.79.129").expect("public destination IP"));

        let correlated = correlate_cloud_flows(
            std::slice::from_ref(&invocation),
            &[invocation.clone(), private_flow.clone(), public_flow],
            &registry,
        )
        .expect("VPC endpoint correlation");
        assert_eq!(correlated.len(), 1);
        assert_eq!(
            correlated[0].connector_instance_id,
            private_flow.connector.instance_id
        );
        assert!(
            correlated[0]
                .endpoints
                .iter()
                .any(|endpoint| endpoint.value == "10.242.0.4" && endpoint.role == "source")
        );
    }

    #[test]
    fn gcp_ingress_service_flow_correlates_with_vertex_invocation() {
        let registry = governance_registry();
        let flow_config = connector_import_config();
        let flow = import_cloud_flow_api_json(
            br#"{"provider":"gcp","account_id":"example-project","region":"global","network_id":"tally-e2e-flow-vpc-20260915","records":[{"window_start":"2026-09-15T17:20:37.512285382Z","window_end":"2026-09-15T17:20:38.267405435Z","source_ip":"198.51.100.4","destination_ip":"10.231.0.2","source_hostname":"aiplatform.googleapis.com","destination_hostname":"tally-e2e-flow-client-20260915","source_port":443,"destination_port":41624,"protocol":"tcp","packets":10,"bytes":2540,"direction":"ingress","decision":"accepted"}]}"#,
            CloudFlowProvider::Gcp,
            &flow_config,
        )
        .expect("GCP flow import")
        .batch
        .observations
        .into_iter()
        .next()
        .expect("flow observation");
        let managed_config = ManagedCloudImportConfig {
            installation_id: flow_config.installation_id,
            connector_instance_id: uuid::Uuid::now_v7(),
            implementation_version: "test".to_owned(),
            source_lineage_id: Some("gcp-vertex-test".to_owned()),
            observed_at: "2026-09-15T17:20:37.576975Z"
                .parse()
                .expect("observation time"),
            received_at: "2026-09-15T17:23:00Z".parse().expect("receive time"),
            checkpoint: Cursor("gcp-vertex-test".to_owned()),
            pseudonymization_key: flow_config.pseudonymization_key.clone(),
            scope: ManagedCloudScope::Gcp {
                project_id: "example-project".to_owned(),
                location: "us-central1".to_owned(),
                static_credentials: None,
            },
            transport: ManagedCloudTransport::NativeApi,
        };
        let invocation = import_gcp_vertex_ai_json(
            br#"{"endpoints":{"endpoints":[]},"models":{"models":[]},"invocations":[{"requestId":"request-1","modelId":"gemini-2.5-flash","principalEmail":"tally-e2e-invoker-20260915@example-project.iam.gserviceaccount.com","sourceIp":"192.0.2.198","destinationHost":"us-central1-aiplatform.googleapis.com","observedAt":"2026-09-15T17:20:37.576975Z"}]}"#,
            &managed_config,
        )
        .expect("Vertex invocation import")
        .batch
        .observations
        .into_iter()
        .next()
        .expect("invocation observation");
        let mut unlabeled_google_api_flow = flow.clone();
        unlabeled_google_api_flow.observation_id = uuid::Uuid::now_v7();
        unlabeled_google_api_flow.actor.hostname = None;

        let correlated = correlate_cloud_flows(
            std::slice::from_ref(&invocation),
            &[flow.clone(), unlabeled_google_api_flow, invocation.clone()],
            &registry,
        )
        .expect("correlation");
        assert_eq!(correlated.len(), 1);
        assert_eq!(
            correlated[0].connector_instance_id,
            flow.connector.instance_id
        );
        assert!(correlated[0].endpoints.iter().any(|endpoint| {
            endpoint.value == "tally-e2e-flow-client-20260915" && endpoint.role == "source"
        }));
        assert!(
            correlated[0]
                .endpoints
                .iter()
                .any(|endpoint| endpoint.value == "10.231.0.2" && endpoint.role == "source")
        );
    }

    #[test]
    fn ambiguous_cloud_flows_are_not_linked_to_managed_usage() {
        let registry = governance_registry();
        let installation_id = uuid::Uuid::now_v7();
        let invocation_time = Utc::now();
        let mut invocation = usage_observation(ObservationKind::CloudUsage);
        invocation.installation_id = installation_id;
        invocation.observed_at = invocation_time;
        invocation.cloud.provider = Some(tally_core::CloudProvider::Gcp);
        invocation.cloud.provider_service = Some(CloudProviderService::GcpVertexAi);
        invocation.cloud.usage_kind = Some(CloudUsageKind::Invocation);
        invocation.cloud.account_key = Some("p1_account".to_owned());
        invocation.cloud.region = Some("us-central1".to_owned());
        invocation.service.ai_request = true;

        let make_flow = || {
            let mut flow = usage_observation(ObservationKind::NetworkFlow);
            flow.installation_id = installation_id;
            flow.observation_id = uuid::Uuid::now_v7();
            flow.connector.instance_id = uuid::Uuid::now_v7();
            flow.observed_at = invocation_time;
            flow.service.vendor_application_id = None;
            flow.cloud.provider = Some(tally_core::CloudProvider::Gcp);
            flow.cloud.usage_kind = Some(CloudUsageKind::NetworkFlow);
            flow.cloud.account_key = Some("p1_account".to_owned());
            flow.cloud.region = Some("us-central1".to_owned());
            flow.network.protocol = Some("tcp".to_owned());
            flow.network.destination_port = Some(443);
            flow.network.direction = Some(FlowDirection::Egress);
            flow.network.valid_until = Some(invocation_time + Duration::seconds(1));
            flow.outcome.action = Some("accepted".to_owned());
            flow
        };
        let first = make_flow();
        let second = make_flow();
        assert_eq!(
            correlate_cloud_flows(
                std::slice::from_ref(&first),
                &[invocation, first.clone(), second],
                &registry,
            )
            .expect("correlation"),
            [] as [tally_store_postgres::ObservedUsage; 0]
        );
    }

    #[test]
    fn attribution_capable_connectors_project_users_and_hostnames_to_findings() {
        let registry = governance_registry();
        let config = connector_import_config();

        let nextdns = import_nextdns_api_json(
            br#"{"data":[{"timestamp":"2026-08-13T10:00:00Z","domain":"chatgpt.com","clientIp":"10.0.0.8","device":{"id":"device-1","name":"LAPTOP-40"}}]}"#,
            &config,
        )
        .expect("NextDNS import");
        assert_finding_attribution(
            &nextdns.batch.observations[0],
            &registry,
            "chatgpt.com",
            Some("laptop-40"),
            None,
        );

        let cloudflare = import_cloudflare_gateway_ndjson(
            br#"{"datetime":1788443425,"request_id":"00000000000000000000000000000002","user_id":"00000000-0000-4000-8000-000000000001","email":"person@example.com","device_id":"00000000-0000-4000-8000-000000000002","action":1,"action_name":"allow","http_host":"chat.z.ai","http_method":2,"http_method_name":"POST","url":"https://chat.z.ai/api/v2/chat/completions?discarded=true","source_ip":"198.51.100.8","source_internal_ip":"100.96.0.2","destination_ip":"203.0.113.34","destination_port":443}"#,
            &config,
        )
        .expect("Cloudflare import");
        assert_finding_attribution(
            &cloudflare.batch.observations[0],
            &registry,
            "chat.z.ai",
            None,
            Some("person@example.com"),
        );
        let cloudflare_usage = usage_from_observation(&cloudflare.batch.observations[0], &registry)
            .expect("Cloudflare usage projection")
            .expect("finding-worthy Cloudflare request");
        assert_eq!(
            cloudflare_usage
                .endpoints
                .iter()
                .filter(|endpoint| endpoint.kind == "ip_address")
                .map(|endpoint| endpoint.value.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["100.96.0.2", "198.51.100.8"])
        );
        assert!(
            cloudflare_usage
                .destinations
                .iter()
                .any(|endpoint| { endpoint.value == "chat.z.ai" && endpoint.port == Some(443) })
        );

        let zscaler = import_zscaler_ndjson(
            br#"{"time":1786615200,"recordid":"zs-1","login":"zscaler@example.com","eurl":"https://api.openai.com/v1/responses","devicehostname":"LAPTOP-42","cip":"10.0.0.10","action":"Allowed"}"#,
            &config,
        )
        .expect("Zscaler import");
        assert_finding_attribution(
            &zscaler.batch.observations[0],
            &registry,
            "api.openai.com",
            Some("laptop-42"),
            Some("zscaler@example.com"),
        );

        let palo_alto = import_palo_alto_ndjson(
            br#"{"TimeGenerated":"2026-08-13T10:00:03Z","SequenceNo":"pa-1","Type":"traffic","SourceAddress":"10.0.0.11","DestinationAddress":"203.0.113.11","DestinationDeviceHost":"CHATGPT.COM","SourceUser":"palo@example.com","SourceDeviceHost":"LAPTOP-43","Protocol":"tcp","Action":"allow"}"#,
            &config,
        )
        .expect("Palo Alto import");
        assert_finding_attribution(
            &palo_alto.batch.observations[0],
            &registry,
            "chatgpt.com",
            Some("laptop-43"),
            Some("palo@example.com"),
        );

        let ai_gateway = import_cloudflare_ai_gateway_json(
            br#"{"schema_version":"cloudflare_ai_gateway_projection_v1","account_ref":"0123456789abcdef0123456789abcdef","observed_at":"2026-08-13T10:01:00Z","gateways":[{"id":"production-gateway","providers":[],"usage":[{"id":"log-1","provider":"openai","model":"gpt-5","observed_at":"2026-08-13T10:00:04Z","email":"gateway@example.com","hostname":"LAPTOP-44"}]}]}"#,
            &config,
        )
        .expect("AI Gateway import");
        let usage_observation = ai_gateway
            .batch
            .observations
            .iter()
            .find(|observation| observation.kind == ObservationKind::HttpMetadata)
            .expect("AI Gateway usage observation");
        assert_finding_attribution(
            usage_observation,
            &registry,
            "gateway.ai.cloudflare.com",
            Some("laptop-44"),
            Some("gateway@example.com"),
        );
    }

    #[test]
    fn only_known_domains_or_verified_ai_http_requests_enter_governance() {
        let registry = governance_registry();
        for (host, provider_key) in [("chatgpt.com", "openai"), ("chat.deepseek.com", "deepseek")] {
            let mut observation = usage_observation(ObservationKind::DnsQuery);
            observation.service.vendor_application_id = None;
            observation.destination.host = Some(Hostname::parse(host).expect("known host"));
            let usage = usage_from_observation(&observation, &registry)
                .expect("known-domain projection")
                .expect("known domain is eligible");
            assert_eq!(usage.provider_key, provider_key);
            assert!(usage.provider_catalogued);
        }

        let mut regular_known_http = usage_observation(ObservationKind::HttpMetadata);
        regular_known_http.service.vendor_application_id = None;
        regular_known_http.destination.host =
            Some(Hostname::parse("chatgpt.com").expect("known host"));
        regular_known_http.service.ai_request_evaluated = true;
        assert!(
            usage_from_observation(&regular_known_http, &registry)
                .expect("checked regular HTTP projection")
                .is_none()
        );

        regular_known_http.service.ai_request_evaluated = false;
        assert!(
            usage_from_observation(&regular_known_http, &registry)
                .expect("domain-only projection")
                .is_some()
        );

        let mut ordinary_dns = usage_observation(ObservationKind::DnsQuery);
        ordinary_dns.service.vendor_application_id = None;
        ordinary_dns.destination.host =
            Some(Hostname::parse("notifications.example.com").expect("host"));
        assert!(
            usage_from_observation(&ordinary_dns, &registry)
                .expect("ordinary DNS projection")
                .is_none()
        );

        let mut ordinary_http = ordinary_dns.clone();
        ordinary_http.kind = ObservationKind::HttpMetadata;
        assert!(
            usage_from_observation(&ordinary_http, &registry)
                .expect("ordinary HTTP projection")
                .is_none()
        );

        ordinary_http.service.ai_request = true;
        let usage = usage_from_observation(&ordinary_http, &registry)
            .expect("AI HTTP projection")
            .expect("verified AI request");
        assert_eq!(
            usage.provider_key,
            "discovered.host.notifications.example.com"
        );
        assert!(!usage.provider_catalogued);
    }

    #[test]
    fn integration_capability_manifest_is_bounded_read_only_and_content_free() {
        let registry: RegistryManifest = serde_json::from_str(include_str!(
            "../../../registry-data/dist/tally-registry-2026.08.5.manifest.json"
        ))
        .expect("registry manifest");
        let manifest = build_integration_capability_manifest(
            &registry,
            2,
            POSTGRES_MIGRATION_HEAD,
            OBSERVATION_BUFFER_VERSION,
        );
        assert!(manifest.migrations.compatible);
        assert_eq!(manifest.routes.len(), 5);
        assert!(manifest.routes.iter().all(|route| {
            route.method == "GET"
                && route.path.starts_with("/api/v1/tally/integration/")
                && (1..=512).contains(&route.maximum_items)
                && !route.deprecated
        }));
        assert!(!manifest.content_retained);
        let encoded = serde_json::to_string(&manifest).expect("capability manifest JSON");
        for prohibited in [
            "credential_value",
            "cursor_value",
            "source_lineage_id",
            "identity_provider",
            "user_profile",
            "prompt",
            "response_body",
        ] {
            assert!(!encoded.contains(prohibited));
        }

        let mut paths = manifest
            .routes
            .iter()
            .map(|route| route.path.as_str())
            .collect::<Vec<_>>();
        paths.sort_unstable();
        paths.dedup();
        assert_eq!(paths.len(), 5);

        let incompatible = build_integration_capability_manifest(
            &registry,
            0,
            POSTGRES_MIGRATION_HEAD,
            "PRIVATE_MIGRATION_VALUE",
        );
        assert!(!incompatible.migrations.compatible);
        assert_eq!(incompatible.migrations.observations_head, "incompatible");
    }

    #[test]
    fn openapi_exposes_only_the_simplified_product_surface() {
        let document = serde_json::to_value(openapi()).expect("OpenAPI JSON");
        let paths = document["paths"].as_object().expect("OpenAPI paths");
        let expected = [
            "/api/v1/tally/estate",
            "/api/v1/tally/estate/activity",
            "/api/v1/tally/estate/activity/query",
            "/api/v1/tally/registry/estate-reviews",
            "/api/v1/tally/registry/provider-domains",
            "/api/v1/tally/audit",
            "/api/v1/tally/connectors",
            "/api/v1/tally/connectors/schedules",
            "/api/v1/tally/connectors/sync",
            "/api/v1/tally/connectors/{connector_instance_id}",
            "/api/v1/tally/connectors/{connector_instance_id}/configuration",
            "/api/v1/tally/connectors/{connector_instance_id}/sync",
            "/api/v1/tally/data",
            "/api/v1/tally/data/delete",
            "/api/v1/tally/data/preview",
            "/api/v1/tally/data/sample",
            "/api/v1/tally/data/sample/delete",
            "/api/v1/tally/findings",
            "/api/v1/tally/event-stream",
            "/api/v1/tally/health/live",
            "/api/v1/tally/health/ready",
            "/api/v1/tally/imports",
            "/api/v1/tally/imports/preview",
            "/api/v1/tally/overview",
            "/api/v1/tally/registry/sanctions",
            "/api/v1/tally/registry/models",
            "/api/v1/tally/registry/providers",
            "/api/v1/tally/scans",
            "/api/v1/tally/scans/preview",
            "/api/v1/tally/scans/{scan_id}",
            "/api/v1/tally/scans/{scan_id}/cancel",
            "/api/v1/tally/version",
        ];
        assert_eq!(paths.len(), expected.len());
        for path in expected {
            assert!(paths.contains_key(path), "missing {path}");
        }
        let encoded = serde_json::to_string(&document).expect("OpenAPI JSON string");
        assert!(encoded.contains("findings_updated"));
        assert!(!paths.contains_key("/api/v1/tally/registry/decisions"));
        assert!(!paths.contains_key("/api/v1/tally/estate/logs"));
        let sanction_schema = &document["components"]["schemas"]["RegistrySanctionRequest"];
        assert_eq!(
            sanction_schema["required"],
            serde_json::json!(["sanctioned"])
        );
        assert!(sanction_schema["properties"].get("enabled").is_none());
        let findings_schema = &document["components"]["schemas"]["GovernanceFindingsResponse"];
        assert!(findings_schema["properties"].get("unsanctioned").is_some());
        assert!(findings_schema["properties"].get("sanctioned").is_some());
        assert!(findings_schema["properties"].get("risks").is_none());
        assert!(findings_schema["properties"].get("inventory").is_none());
        let client_schema = &document["components"]["schemas"]["FindingClientView"];
        assert!(client_schema["properties"].get("name").is_some());
        assert!(client_schema["properties"].get("agent_id").is_some());
        assert!(client_schema["properties"].get("headers").is_none());
        assert!(client_schema["properties"].get("user_agent").is_none());
        let overview_schema = &document["components"]["schemas"]["TallyOverviewSummary"];
        assert!(overview_schema["properties"].get("unsanctioned").is_some());
        assert!(overview_schema["properties"].get("sanctioned").is_some());
        assert!(overview_schema["properties"].get("risks").is_none());
        assert!(overview_schema["properties"].get("inventory").is_none());
        for retired in ["/analytics", "/systems", "/coverage", "/reports", "/purge"] {
            assert!(
                !encoded.contains(retired),
                "retired route leaked: {retired}"
            );
        }
    }

    #[test]
    fn registry_sanction_request_rejects_the_legacy_enabled_field() {
        let request = serde_json::from_value::<RegistrySanctionRequest>(serde_json::json!({
            "provider_ids": [],
            "model_ids": [],
            "sanctioned": true
        }))
        .expect("sanction request");
        assert!(request.sanctioned);
        assert!(
            serde_json::from_value::<RegistrySanctionRequest>(serde_json::json!({
                "provider_ids": [],
                "model_ids": [],
                "enabled": true
            }))
            .is_err()
        );
    }

    fn safe_plan() -> ScanPlanResponse {
        let plan = ScanScope {
            targets: vec!["10.20.0.15".to_owned()],
            exclusions: Vec::new(),
            ports: vec![11_434],
            max_hosts: 1,
            allow_public: false,
            authorization_acknowledged: false,
        }
        .plan()
        .expect("safe plan");
        ScanPlanResponse::from(&plan)
    }

    #[test]
    fn scan_execution_requires_the_exact_reviewed_digest() {
        let plan = safe_plan();
        assert!(verify_scan_plan(&plan, &plan.scope_digest).is_ok());
        assert!(verify_scan_plan(&plan, &"0".repeat(64)).is_err());
    }

    #[test]
    fn tampered_scan_plan_is_rejected_even_with_its_original_digest() {
        let mut plan = safe_plan();
        let digest = plan.scope_digest.clone();
        plan.targets = vec!["10.20.0.16".to_owned()];
        assert!(verify_scan_plan(&plan, &digest).is_err());
    }

    #[test]
    fn scan_policy_refuses_excessive_concurrency_and_timeout() {
        assert!(
            verify_scan_policy(ScanExecutionPolicyInput {
                concurrency: MAX_CONNECT_CONCURRENCY + 1,
                connect_timeout_millis: DEFAULT_CONNECT_TIMEOUT_MILLIS,
            })
            .is_err()
        );
        assert!(
            verify_scan_policy(ScanExecutionPolicyInput {
                concurrency: DEFAULT_CONNECT_CONCURRENCY,
                connect_timeout_millis: MAX_CONNECT_TIMEOUT_MILLIS + 1,
            })
            .is_err()
        );
    }

    #[test]
    fn event_cursor_round_trips_and_rejects_malformed_values() {
        let observation_id = uuid::Uuid::now_v7();
        let value = format!("1735689600000:{observation_id}");
        assert_eq!(
            parse_event_cursor(&value).expect("valid cursor"),
            (1_735_689_600_000, observation_id)
        );

        for invalid in [
            "missing-separator",
            "not-a-time:0194f7b5-8000-7000-8000-000000000000",
            "-1:0194f7b5-8000-7000-8000-000000000000",
            "1735689600000:not-a-uuid",
        ] {
            let error = parse_event_cursor(invalid).expect_err("cursor must be rejected");
            assert_eq!(error.status, StatusCode::BAD_REQUEST);
            assert_eq!(error.code, "invalid_event_cursor");
        }
    }

    #[test]
    fn import_checkpoints_accept_only_bounded_machine_labels() {
        assert!(safe_import_checkpoint("browser-file:4096:1735689600000"));
        assert!(safe_import_checkpoint(&format!(
            "nd1:1786615200000:{}",
            "a".repeat(512)
        )));
        assert!(!safe_import_checkpoint(""));
        assert!(!safe_import_checkpoint("contains user@example.com"));
        assert!(!safe_import_checkpoint(&"a".repeat(2_049)));
        assert!(safe_import_source_lineage("nextdns_api:profile_1"));
        assert!(!safe_import_source_lineage("contains user@example.com"));
    }

    #[test]
    fn scanner_observation_discards_extracted_values_and_keeps_digest_proof() {
        let canary = "PROMPT_CANARY_MUST_NOT_SURVIVE";
        let attempt = HttpFingerprintAttempt {
            fingerprint_id: "fingerprint.ollama.version_v1".to_owned(),
            address: "127.0.0.1".parse::<IpAddr>().expect("IP"),
            port: 11_434,
            outcome: HttpFingerprintOutcome::Matched,
            duration_millis: 12,
            status_code: Some(200),
            content_type: Some("application/json".to_owned()),
            facts: BTreeMap::from([("version".to_owned(), canary.to_owned())]),
            matches: Vec::new(),
            transcript_sha256: Some("ab".repeat(32)),
        };
        let observation = scanner_observation(
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            uuid::Uuid::now_v7(),
            Utc::now(),
            &attempt,
        )
        .expect("scanner observation");
        let encoded = serde_json::to_string(&observation).expect("serialize observation");
        assert!(!encoded.contains(canary));
        assert!(encoded.contains("fingerprint.ollama.version_v1"));
        assert!(encoded.contains(&"ab".repeat(32)));
    }

    #[test]
    fn integration_evidence_link_is_digest_only_and_contract_valid() {
        let canary = "PRIVATE_SOURCE_VALUE_MUST_NOT_SURVIVE";
        let attempt = HttpFingerprintAttempt {
            fingerprint_id: "fingerprint.ollama.version_v1".to_owned(),
            address: "127.0.0.1".parse::<IpAddr>().expect("IP"),
            port: 11_434,
            outcome: HttpFingerprintOutcome::Matched,
            duration_millis: 12,
            status_code: Some(200),
            content_type: Some("application/json".to_owned()),
            facts: BTreeMap::from([("version".to_owned(), canary.to_owned())]),
            matches: Vec::new(),
            transcript_sha256: Some("ab".repeat(32)),
        };
        let observation = scanner_observation(
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            uuid::Uuid::now_v7(),
            Utc::now(),
            &attempt,
        )
        .expect("scanner observation");
        let link = evidence_link_contribution(&observation, "/api/v1/tally/events")
            .expect("valid evidence contribution");
        link.validate().expect("frozen integration contract");
        let encoded = serde_json::to_string(&link).expect("serialize contribution");
        assert!(!encoded.contains(canary));
        assert_eq!(link.receipt_sha256.len(), 64);
        assert_eq!(link.observation_id, observation.observation_id);
    }

    #[test]
    fn connector_contribution_drops_descriptor_and_credentials() {
        let now = Utc::now();
        let connector = ConnectorStateView {
            connector_instance_id: uuid::Uuid::now_v7(),
            connector_type: "aws_managed_ai_inventory_api_v1".to_owned(),
            display_name: "AWS managed AI inventory".to_owned(),
            friendly_name: "Production billing account".to_owned(),
            implementation_version: "1.0.0".to_owned(),
            transport: ConnectorTransport::Pull,
            health: ConnectorHealth::Healthy,
            cursor_value: "opaque-cursor".to_owned(),
            last_success_at: Some(now),
            last_poll_at: Some(now),
            last_source_at: Some(now),
            lag_seconds: Some(0),
            records_read_total: 10,
            accepted_total: 8,
            ignored_total: 1,
            rejected_total: 0,
            deduplicated_total: 1,
            last_error_code: None,
            redaction_digest: Some("ab".repeat(32)),
            descriptor: serde_json::json!({
                "credential": "DO_NOT_EXPORT",
                "account": "DO_NOT_EXPORT"
            }),
        };
        let contribution = connector_contribution(&connector, now).expect("valid contribution");
        contribution
            .validate()
            .expect("frozen integration contract");
        assert_eq!(
            contribution.source_family,
            ConnectorSourceFamily::ManagedCloud
        );
        assert_eq!(contribution.display_label, "Production billing account");
        let encoded = serde_json::to_string(&contribution).expect("serialize contribution");
        assert!(!encoded.contains("credential"));
        assert!(!encoded.contains("DO_NOT_EXPORT"));
        assert!(!encoded.contains("opaque-cursor"));
    }

    #[test]
    fn freshness_slo_is_schedule_derived_and_host_alertable() {
        let now: DateTime<Utc> = "2026-08-14T10:00:00Z".parse().expect("timestamp");
        let connector_instance_id = uuid::Uuid::now_v7();
        let mut connector = ConnectorStateView {
            connector_instance_id,
            connector_type: "aws_vpc_flow_api_v1".to_owned(),
            display_name: "AWS flow evidence".to_owned(),
            friendly_name: String::new(),
            implementation_version: "1".to_owned(),
            transport: ConnectorTransport::Pull,
            health: ConnectorHealth::Healthy,
            cursor_value: "opaque".to_owned(),
            last_success_at: Some(now),
            last_poll_at: Some(now),
            last_source_at: Some(now - Duration::minutes(10)),
            lag_seconds: Some(0),
            records_read_total: 1,
            accepted_total: 1,
            ignored_total: 0,
            rejected_total: 0,
            deduplicated_total: 0,
            last_error_code: None,
            redaction_digest: None,
            descriptor: serde_json::json!({}),
        };
        let mut job = ConnectorJobView {
            job_id: uuid::Uuid::now_v7(),
            connector_instance_id,
            mode: ConnectorJobMode::Scheduled,
            status: ConnectorJobStatus::Enabled,
            schedule_seconds: Some(300),
            next_run_at: Some(now),
            lease_owner: None,
            lease_until: None,
            config_refs: serde_json::json!({"kind": "cloud_network_api_v1"}),
            credentials_stored: true,
            attempt_count: 1,
            consecutive_failures: 0,
            last_started_at: Some(now),
            last_finished_at: Some(now),
            last_outcome: Some(ConnectorRunStatus::Completed),
            last_error_code: None,
            created_at: now,
            updated_at: now,
        };

        let met = freshness_slo(&connector, Some(&job), now);
        assert_eq!(met.target_seconds, Some(900));
        assert_eq!(met.source_age_seconds, Some(600));
        assert_eq!(met.status, FreshnessSloStatus::Met);
        assert!(!met.alertable);

        connector.last_source_at = Some(now - Duration::minutes(16));
        let breached = freshness_slo(&connector, Some(&job), now);
        assert_eq!(breached.status, FreshnessSloStatus::Breached);
        assert_eq!(breached.breach_seconds, Some(60));
        assert!(breached.alertable);

        job.status = ConnectorJobStatus::Paused;
        let paused = freshness_slo(&connector, Some(&job), now);
        assert_eq!(paused.status, FreshnessSloStatus::Paused);
        assert!(!paused.alertable);

        job.status = ConnectorJobStatus::Enabled;
        connector.health = ConnectorHealth::Error;
        let failed = freshness_slo(&connector, Some(&job), now);
        assert_eq!(failed.status, FreshnessSloStatus::Error);
        assert!(failed.alertable);
    }

    #[test]
    fn local_registry_entry_is_bounded_and_host_collision_safe() {
        let request = LocalRegistryEntryRequest {
            name: "Lab Assistant".to_owned(),
            kind: LocalRegistryEntryKind::Service,
            categories: vec![LocalRegistryCategory::Assistant],
            surface: LocalRegistrySurface::WebApplication,
            host_rules: vec![LocalRegistryHostRule {
                kind: LocalHostRuleKind::Suffix,
                host: "Assistant.Lab.Example.".to_owned(),
            }],
            evidence_url: "https://docs.lab.example/assistant".to_owned(),
            acknowledge_local_overlay: true,
        };
        let (overlay, entry_id) = build_local_registry_overlay(&request).expect("valid overlay");
        assert_eq!(entry_id, "local.service.lab-assistant");
        assert_eq!(overlay.additions[0].matchers.len(), 1);
        let MatcherRule::HostSuffix { value } = &overlay.additions[0].matchers[0].rule else {
            panic!("expected suffix matcher")
        };
        assert_eq!(value, "assistant.lab.example");
        assert!(local_registry_slug("<script>").is_some());
    }

    #[test]
    fn local_registry_entry_requires_explicit_acknowledgement_and_public_provenance() {
        let request = LocalRegistryEntryRequest {
            name: "Lab Assistant".to_owned(),
            kind: LocalRegistryEntryKind::Service,
            categories: vec![LocalRegistryCategory::Assistant],
            surface: LocalRegistrySurface::WebApplication,
            host_rules: vec![LocalRegistryHostRule {
                kind: LocalHostRuleKind::Exact,
                host: "assistant.lab.example".to_owned(),
            }],
            evidence_url: "file:///private/config".to_owned(),
            acknowledge_local_overlay: false,
        };
        let error = build_local_registry_overlay(&request).expect_err("unsafe request");
        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(error.code, "registry_entry_invalid");
    }

    #[test]
    fn classification_rules_are_canonical_and_label_safe() {
        let rules = normalize_classification_rules(&[
            ClassificationHostRule {
                kind: LocalHostRuleKind::Suffix,
                host: "Example.COM.".to_owned(),
            },
            ClassificationHostRule {
                kind: LocalHostRuleKind::Exact,
                host: "API.Example.com".to_owned(),
            },
        ])
        .expect("valid rules");
        assert_eq!(rules[0].kind, LocalHostRuleKind::Exact);
        assert_eq!(rules[0].host, "api.example.com");
        assert!(classification_rule_matches(&rules[1], "example.com"));
        assert!(classification_rule_matches(&rules[1], "api.example.com"));
        assert!(!classification_rule_matches(&rules[1], "notexample.com"));
    }

    #[test]
    fn classification_rules_reject_duplicates_and_opposite_overlap() {
        let duplicate = ClassificationHostRule {
            kind: LocalHostRuleKind::Exact,
            host: "api.example.com".to_owned(),
        };
        let error = normalize_classification_rules(&[duplicate.clone(), duplicate])
            .expect_err("duplicate must fail closed");
        assert_eq!(error.code, "classification_rules_invalid");

        let existing = ClassificationRuleSetView {
            rule_set_id: uuid::Uuid::now_v7(),
            installation_id: uuid::Uuid::now_v7(),
            preview_digest: "ab".repeat(32),
            decision: "unauthorized".to_owned(),
            rules: serde_json::json!([{"kind":"suffix","host":"example.com"}]),
            rules_sha256: "cd".repeat(32),
            matched_system_ids: Vec::new(),
            changed_system_ids: Vec::new(),
            matched_system_count: 0,
            changed_system_count: 0,
            created_at: Utc::now(),
            created_by: "local_operator".to_owned(),
            active: true,
            deactivated_at: None,
            deactivated_by: None,
            content_retained: false,
        };
        let error = reject_classification_conflicts(
            ClassificationDecision::Authorized,
            &[ClassificationHostRule {
                kind: LocalHostRuleKind::Exact,
                host: "api.example.com".to_owned(),
            }],
            &[existing],
        )
        .expect_err("opposite overlapping rule must fail closed");
        assert_eq!(error.code, "classification_rule_conflict");
    }

    #[test]
    fn classification_preview_digest_binds_revision_and_status() {
        let installation_id = uuid::Uuid::now_v7();
        let observation_id = uuid::Uuid::now_v7();
        let mut system = ClassificationSystemEffect {
            system_id: uuid::Uuid::now_v7(),
            display_name: "Example AI".to_owned(),
            current_authorization: "discovered".to_owned(),
            target_authorization: "authorized".to_owned(),
            current_revision: 1,
            matching_observations: 2,
            retired: false,
        };
        let rules = [ClassificationHostRule {
            kind: LocalHostRuleKind::Exact,
            host: "api.example.com".to_owned(),
        }];
        let first = classification_preview_digest(
            installation_id,
            ClassificationDecision::Authorized,
            &rules,
            &[observation_id],
            &[system.clone()],
        )
        .expect("digest");
        system.current_revision = 2;
        let revision_changed = classification_preview_digest(
            installation_id,
            ClassificationDecision::Authorized,
            &rules,
            &[observation_id],
            &[system.clone()],
        )
        .expect("digest");
        assert_ne!(first, revision_changed);
        system.current_authorization = "unauthorized".to_owned();
        let status_changed = classification_preview_digest(
            installation_id,
            ClassificationDecision::Authorized,
            &rules,
            &[observation_id],
            &[system],
        )
        .expect("digest");
        assert_ne!(revision_changed, status_changed);
    }

    #[test]
    fn purge_preview_digest_is_stable_and_count_bound() {
        let installation_id = uuid::Uuid::now_v7();
        let counts = PurgeCounts {
            observations: 7,
            systems: 2,
            connector_jobs: 1,
            authorization_transitions: 3,
            ..PurgeCounts::default()
        };
        let first = purge_preview_response(installation_id, &counts).expect("preview");
        let replay = purge_preview_response(installation_id, &counts).expect("replay");
        assert_eq!(first.preview_digest, replay.preview_digest);
        assert_eq!(first.counts.total_records, 13);

        let mut changed = counts;
        changed.observations += 1;
        let changed = purge_preview_response(installation_id, &changed).expect("changed preview");
        assert_ne!(first.preview_digest, changed.preview_digest);
    }

    #[test]
    fn analytics_separates_resolved_and_unresolved_actor_activity() {
        let installation_id = uuid::Uuid::now_v7();
        let system_id = uuid::Uuid::now_v7();
        let now = Utc::now();
        let connector = ConnectorRef {
            instance_id: uuid::Uuid::now_v7(),
            connector_type: "nextdns".to_owned(),
            implementation_version: "1".to_owned(),
            source_lineage_id: Some("fixture".to_owned()),
        };
        let receipt = EvidenceReceipt::RecordDigest {
            algorithm: DigestAlgorithm::Sha256,
            digest: "ab".repeat(32),
        };
        let mut resolved = Observation::new(
            installation_id,
            now,
            connector.clone(),
            ObservationKind::DnsQuery,
            receipt.clone(),
        );
        resolved.actor.device_key = Some("p1_fixture_actor".to_owned());
        let mut unresolved = Observation::new(
            installation_id,
            now,
            connector,
            ObservationKind::DnsQuery,
            receipt,
        );
        unresolved.actor.device_key = Some("p1_fixture_actor".to_owned());
        let system = AiSystemView {
            system_id,
            display_name: "Fixture AI".to_owned(),
            surface: Surface::ExternalApi,
            lifecycle: Lifecycle::Active,
            authorization: AuthorizationStatus::Authorized,
            first_seen: now,
            last_seen: now,
            evidence_quality: EvidenceQuality::Strong,
            confidence: BasisPoints::MAX,
            findings: Vec::new(),
            revision: 1,
        };
        let response = build_analytics(
            &[resolved.clone(), unresolved],
            2,
            &[system],
            1,
            &[SystemEvidenceEdge {
                system_id,
                observation_id: resolved.observation_id,
            }],
            ActivityWindow::Days7,
            Some((now - Duration::days(7)).timestamp_millis()),
        );
        assert_eq!(response.activity_window, "7d");
        assert_eq!(response.authorization.authorized, 1);
        assert_eq!(response.service_rank[0].event_count, 1);
        assert_eq!(response.service_rank[0].unique_actor_count, 1);
        assert_eq!(response.actors[0].event_count, 2);
        assert_eq!(response.actors[0].unresolved_event_count, 1);
        assert_eq!(response.actors[0].systems[0].system_id, system_id);
        assert!(!response.content_retained);
    }

    #[test]
    fn activity_windows_are_exact_and_default_to_seven_days() {
        let now = "2026-08-13T12:00:00Z".parse().expect("timestamp");
        assert_eq!(ActivityWindow::default(), ActivityWindow::Days7);
        assert_eq!(
            ActivityWindow::Hours24.since(now),
            Some(now - Duration::hours(24))
        );
        assert_eq!(
            ActivityWindow::Days30.since(now),
            Some(now - Duration::days(30))
        );
        assert_eq!(ActivityWindow::All.since(now), None);
        assert!(serde_json::from_str::<ActivityWindow>("\"90d\"").is_err());
    }

    #[test]
    fn connector_schedule_bounds_operator_entered_credentials() {
        assert!(safe_credential_value("/Users/operator/logs"));
        assert!(safe_credential_value("v1.0-Abc_123"));
        assert!(!safe_credential_value(""));
        assert!(!safe_credential_value(" leading-space"));
        assert!(!safe_credential_value("token\nX-Injected: 1"));
        assert!(safe_nextdns_profile_id("abc123"));
        assert!(!safe_nextdns_profile_id("profile/abc123"));
    }

    #[test]
    fn initial_backfill_accepts_seven_days_across_connector_schedules() {
        assert!(!valid_initial_backfill_seconds(59));
        assert!(valid_initial_backfill_seconds(60));
        assert!(valid_initial_backfill_seconds(604_800));
        assert!(!valid_initial_backfill_seconds(604_801));

        let schedules = [
            connector_nextdns_api_schedule("abc123", "nextdns-key", 604_800, 1_000),
            connector_ai_gateway_schedule("account-id", "api-token", 604_800, 1_000),
            connector_crowdstrike_edr_schedule(
                "us-1",
                "client-id",
                "client-secret",
                604_800,
                1_000,
            ),
            connector_microsoft_defender_schedule(
                "734a9822-652b-4efe-a23e-13afcb6e5578",
                "11111111-2222-4333-8444-555555555555",
                "client-secret",
                604_800,
                1_000,
            ),
            connector_cato_networks_schedule(
                "123456",
                "api-key",
                "api.catonetworks.com",
                604_800,
                1_000,
            ),
            connector_litellm_schedule(
                "https://litellm.internal.example:4000",
                "api-key",
                604_800,
                1_000,
            ),
        ];
        assert!(schedules.into_iter().all(|schedule| schedule.is_ok()));
    }

    /// Asserts the operator's typed values stay out of `config_refs`, which is the column an
    /// API response and the audit log both project.
    fn assert_config_refs_hide(refs: &serde_json::Value, secrets: &[&str]) {
        let serialized = serde_json::to_string(refs).expect("serialize");
        for secret in secrets {
            assert!(
                !serialized.contains(secret),
                "config_refs leaked {secret}: {serialized}"
            );
        }
    }

    #[test]
    fn managed_agent_schedules_scope_inventory_and_seal_credentials() {
        let source =
            |platform: &str, app_id: Option<&str>| ConnectorScheduleSourceInput::ManagedAgents {
                platform: platform.into(),
                base_url: "https://inventory.example.com".into(),
                api_key: "managed-key-canary".into(),
                app_id: app_id.map(str::to_owned),
                scope_id: None,
            };
        for platform in ["copilot_studio", "langgraph", "servicenow", "n8n"] {
            let plan = connector_schedule_source(&source(platform, None)).unwrap();
            assert_eq!(
                plan.descriptor.connector_type,
                format!("{platform}_agents_api_v1")
            );
            assert_eq!(plan.config_refs["platform"], platform);
            assert_eq!(plan.credentials["api_key"], "managed-key-canary");
            assert_config_refs_hide(
                &plan.config_refs,
                &["managed-key-canary", "inventory.example.com"],
            );
            assert!(
                connector_schedule_source(&source(
                    platform,
                    Some("00000000-0000-0000-0000-000000000001")
                ))
                .is_err()
            );
        }
        let first_id = "00000000-0000-0000-0000-000000000001";
        let second_id = "00000000-0000-0000-0000-000000000002";
        let first = connector_schedule_source(&source("dify", Some(first_id))).unwrap();
        let second = connector_schedule_source(&source("dify", Some(second_id))).unwrap();
        assert_eq!(first.credentials["app_id"], first_id);
        assert_ne!(first.identity_suffix, second.identity_suffix);
        assert_config_refs_hide(&first.config_refs, &["managed-key-canary", first_id]);
        let replay = connector_schedule_source(&source("dify", Some(first_id))).unwrap();
        assert_eq!(first.identity_suffix, replay.identity_suffix);
        assert!(connector_schedule_source(&source("dify", None)).is_err());
        assert!(connector_schedule_source(&source("dify", Some("not-an-app-id"))).is_err());
        assert!(connector_schedule_source(&source("unsupported", None)).is_err());
        let edited = connector_schedule_source_with_existing(
            &ConnectorScheduleSourceInput::ManagedAgents {
                platform: "dify".into(),
                base_url: "https://inventory.example.com".into(),
                api_key: String::new(),
                app_id: Some(first_id.into()),
                scope_id: None,
            },
            Some(&first.credentials),
        )
        .unwrap();
        assert_eq!(edited.credentials["api_key"], "managed-key-canary");
        assert_eq!(edited.identity_suffix, first.identity_suffix);
    }

    #[test]
    fn hosted_managed_agent_schedules_round_trip_scope_and_keep_keys_sealed() {
        for (platform, origin, scope) in [
            ("openai", "https://api.openai.com", "proj_test"),
            ("claude", "https://api.anthropic.com", "wrkspc_test"),
            (
                "gemini",
                "https://generativelanguage.googleapis.com",
                "projects/test/locations/global",
            ),
        ] {
            let source =
                |scope: Option<&str>, key: &str| ConnectorScheduleSourceInput::ManagedAgents {
                    platform: platform.into(),
                    base_url: origin.into(),
                    api_key: key.into(),
                    app_id: None,
                    scope_id: scope.map(str::to_owned),
                };
            let first =
                connector_schedule_source(&source(Some(scope), "managed-key-canary")).unwrap();
            assert_eq!(
                first.descriptor.connector_type,
                format!("{platform}_agents_api_v1")
            );
            assert_eq!(first.credentials["scope_id"], scope);
            let fields = connector_form_configuration(&first.config_refs, &first.credentials);
            assert_eq!(fields["scope_id"], scope);
            assert_eq!(fields["base_url"], origin);
            assert!(!fields.contains_key("api_key"));
            assert_config_refs_hide(&first.config_refs, &["managed-key-canary", scope]);
            let edited = connector_schedule_source_with_existing(
                &source(Some(scope), ""),
                Some(&first.credentials),
            )
            .unwrap();
            assert_eq!(edited.credentials, first.credentials);
            let rotated =
                connector_schedule_source(&source(Some(scope), "rotated-key-canary")).unwrap();
            assert_eq!(rotated.identity_suffix, first.identity_suffix);
            let unscoped = connector_schedule_source(&source(None, "managed-key-canary")).unwrap();
            let other = connector_schedule_source(&source(None, "different-project-key")).unwrap();
            assert_ne!(unscoped.identity_suffix, other.identity_suffix);
            assert!(connector_schedule_source(&source(Some("bad\r\nscope"), "key")).is_err());
        }
    }

    #[test]
    fn nextdns_schedule_seals_the_api_key_and_keeps_the_profile_visible() {
        let plan = connector_schedule_source(&ConnectorScheduleSourceInput::NextdnsApi {
            profile_id: "abc123".into(),
            api_key: "nextdns-key-canary".into(),
            initial_backfill_seconds: 3_600,
            initial_record_limit: 1_000,
        })
        .expect("valid schedule");
        assert_eq!(plan.descriptor.connector_type, "nextdns_logs_api_v1");
        assert_eq!(plan.identity_suffix.as_deref(), Some("abc123"));
        assert_eq!(plan.config_refs["kind"], "nextdns_api_v1");
        assert_eq!(plan.config_refs["profile_id"], "abc123");
        assert_eq!(
            plan.credentials.get("api_key").map(String::as_str),
            Some("nextdns-key-canary")
        );
        assert_config_refs_hide(&plan.config_refs, &["nextdns-key-canary"]);
        assert!(
            connector_schedule_source(&ConnectorScheduleSourceInput::NextdnsApi {
                profile_id: "profile/abc123".into(),
                api_key: "nextdns-key-canary".into(),
                initial_backfill_seconds: 3_600,
                initial_record_limit: 1_000,
            })
            .is_err()
        );
    }

    #[test]
    fn managed_cloud_schedule_seals_account_and_scope_identifiers() {
        let plan = connector_file_schedule(
            ImportAdapterInput::AzureAiFoundry,
            "/var/tally/azure-inventory",
            Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            Some("/subscriptions/aaaa/resourceGroups/rg"),
            Some("eastus2"),
        )
        .expect("valid managed-cloud schedule");
        assert_eq!(
            plan.descriptor.connector_type,
            "azure_managed_ai_inventory_file_v1"
        );
        assert_eq!(plan.config_refs["kind"], "file_env_v1");
        assert_eq!(plan.config_refs["region"], "eastus2");
        assert_eq!(
            plan.credentials.get("source_path").map(String::as_str),
            Some("/var/tally/azure-inventory")
        );
        assert_config_refs_hide(
            &plan.config_refs,
            &[
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "/subscriptions/",
                "/var/tally/azure-inventory",
            ],
        );

        // AWS managed-cloud takes no scope: a stray scope identifier is a contract error.
        assert!(
            connector_file_schedule(
                ImportAdapterInput::AwsManagedAi,
                "/var/tally/aws-inventory",
                Some("123456789012"),
                Some("scope-must-not-be-set"),
                Some("us-east-1"),
            )
            .is_err()
        );

        let plan = connector_schedule_source(&ConnectorScheduleSourceInput::ManagedCloud {
            adapter: ImportAdapterInput::AzureOpenaiApi,
            account_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
            scope_id: Some("/subscriptions/aaaa/resourceGroups/rg".into()),
            workspace_resource: None,
            region: "eastus2".into(),
            aws_access_key_id: None,
            aws_secret_access_key: None,
            azure_tenant_id: None,
            azure_client_id: None,
            azure_client_secret: None,
            gcp_service_account_json: None,
        })
        .expect("valid native cloud schedule");
        assert_eq!(
            plan.descriptor.connector_type,
            "azure_managed_ai_inventory_api_v1"
        );
        assert_eq!(plan.config_refs["kind"], "cloud_api_v1");
        assert_eq!(plan.config_refs["region"], "eastus2");
        assert!(
            plan.identity_suffix
                .is_some_and(|value| value.contains("azure_openai_api"))
        );
        assert_config_refs_hide(
            &plan.config_refs,
            &["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "/subscriptions/"],
        );

        // The native AWS adapter is not a file source, whatever else the request carries.
        assert!(
            connector_file_schedule(
                ImportAdapterInput::AwsManagedAiApi,
                "/var/tally/aws-inventory",
                Some("123456789012"),
                None,
                Some("us-east-1"),
            )
            .is_err()
        );
    }

    #[test]
    fn aws_native_cloud_schedule_supports_static_keys_or_vm_role() {
        let vm_role = ConnectorScheduleSourceInput::ManagedCloud {
            adapter: ImportAdapterInput::AwsManagedAiApi,
            account_id: "123456789012".into(),
            scope_id: None,
            workspace_resource: None,
            region: "us-east-1".into(),
            aws_access_key_id: None,
            aws_secret_access_key: None,
            azure_tenant_id: None,
            azure_client_id: None,
            azure_client_secret: None,
            gcp_service_account_json: None,
        };
        let vm_plan = connector_schedule_source(&vm_role).expect("VM role schedule");
        assert!(!vm_plan.credentials.contains_key("aws_access_key_id"));
        assert!(!vm_plan.credentials.contains_key("aws_secret_access_key"));

        let access_key_id = "AKIAIOSFODNN7EXAMPLE";
        let secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let static_key_plan =
            connector_schedule_source(&ConnectorScheduleSourceInput::ManagedCloud {
                adapter: ImportAdapterInput::AwsManagedAiApi,
                account_id: "123456789012".into(),
                scope_id: None,
                workspace_resource: None,
                region: "us-east-1".into(),
                aws_access_key_id: Some(access_key_id.into()),
                aws_secret_access_key: Some(secret_access_key.into()),
                azure_tenant_id: None,
                azure_client_id: None,
                azure_client_secret: None,
                gcp_service_account_json: None,
            })
            .expect("static key schedule");
        assert_eq!(
            static_key_plan
                .credentials
                .get("aws_access_key_id")
                .map(String::as_str),
            Some(access_key_id)
        );
        assert_eq!(
            static_key_plan
                .credentials
                .get("aws_secret_access_key")
                .map(String::as_str),
            Some(secret_access_key)
        );
        assert_config_refs_hide(
            &static_key_plan.config_refs,
            &[access_key_id, secret_access_key],
        );

        assert!(
            connector_schedule_source(&ConnectorScheduleSourceInput::ManagedCloud {
                adapter: ImportAdapterInput::AwsManagedAiApi,
                account_id: "123456789012".into(),
                scope_id: None,
                workspace_resource: None,
                region: "us-east-1".into(),
                aws_access_key_id: Some(access_key_id.into()),
                aws_secret_access_key: None,
                azure_tenant_id: None,
                azure_client_id: None,
                azure_client_secret: None,
                gcp_service_account_json: None,
            })
            .is_err()
        );
    }

    #[test]
    fn azure_and_gcp_native_cloud_schedules_support_static_or_collector_identity() {
        let azure_tenant_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let azure_client_id = "11111111-2222-3333-4444-555555555555";
        let azure_client_secret = "azure-client-secret-canary";
        let azure_plan = connector_schedule_source(&ConnectorScheduleSourceInput::ManagedCloud {
            adapter: ImportAdapterInput::AzureOpenaiApi,
            account_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
            scope_id: Some("/subscriptions/aaaa/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/tally".into()),
            workspace_resource: Some("/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/tally-logs".into()),
            region: "eastus2".into(),
            aws_access_key_id: None,
            aws_secret_access_key: None,
            azure_tenant_id: Some(azure_tenant_id.into()),
            azure_client_id: Some(azure_client_id.into()),
            azure_client_secret: Some(azure_client_secret.into()),
            gcp_service_account_json: None,
        })
        .expect("Azure service-principal schedule");
        assert_eq!(
            azure_plan
                .credentials
                .get("azure_client_secret")
                .map(String::as_str),
            Some(azure_client_secret)
        );
        assert!(
            azure_plan
                .credentials
                .get("workspace_resource")
                .is_some_and(|value| value.ends_with("/workspaces/tally-logs"))
        );
        assert_config_refs_hide(
            &azure_plan.config_refs,
            &[azure_tenant_id, azure_client_id, azure_client_secret],
        );
        assert!(
            connector_schedule_source(&ConnectorScheduleSourceInput::ManagedCloud {
                adapter: ImportAdapterInput::AzureOpenaiApi,
                account_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
                scope_id: Some("/subscriptions/aaaa/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/tally".into()),
                workspace_resource: None,
                region: "eastus2".into(),
                aws_access_key_id: None,
                aws_secret_access_key: None,
                azure_tenant_id: Some(azure_tenant_id.into()),
                azure_client_id: None,
                azure_client_secret: None,
                gcp_service_account_json: None,
            })
            .is_err()
        );

        let service_account_json =
            r#"{"type":"service_account","private_key":"gcp-private-key-canary"}"#;
        let gcp_plan = connector_schedule_source(&ConnectorScheduleSourceInput::ManagedCloud {
            adapter: ImportAdapterInput::GcpVertexAiApi,
            account_id: "tally-private-project".into(),
            scope_id: None,
            workspace_resource: None,
            region: "us-central1".into(),
            aws_access_key_id: None,
            aws_secret_access_key: None,
            azure_tenant_id: None,
            azure_client_id: None,
            azure_client_secret: None,
            gcp_service_account_json: Some(service_account_json.into()),
        })
        .expect("GCP service-account schedule");
        assert_eq!(
            gcp_plan
                .credentials
                .get("gcp_service_account_json")
                .map(String::as_str),
            Some(service_account_json)
        );
        assert_config_refs_hide(&gcp_plan.config_refs, &["gcp-private-key-canary"]);

        let gcp_collector_identity =
            connector_schedule_source(&ConnectorScheduleSourceInput::ManagedCloud {
                adapter: ImportAdapterInput::GcpVertexAiApi,
                account_id: "tally-private-project".into(),
                scope_id: None,
                workspace_resource: None,
                region: "us-central1".into(),
                aws_access_key_id: None,
                aws_secret_access_key: None,
                azure_tenant_id: None,
                azure_client_id: None,
                azure_client_secret: None,
                gcp_service_account_json: None,
            })
            .expect("GCP collector identity schedule");
        assert!(
            !gcp_collector_identity
                .credentials
                .contains_key("gcp_service_account_json")
        );
    }

    #[test]
    fn enterprise_file_schedules_are_bounded_and_seal_their_values() {
        let plan = connector_file_schedule(
            ImportAdapterInput::CloudflareCasb,
            "/var/tally/casb-snapshot",
            Some("raw-cloudflare-account-canary"),
            None,
            None,
        )
        .expect("valid CASB schedule");
        assert_eq!(
            plan.descriptor.connector_type,
            "cloudflare_casb_integrations_file_v1"
        );
        assert_eq!(
            plan.credentials.get("account_id").map(String::as_str),
            Some("raw-cloudflare-account-canary")
        );
        assert!(plan.identity_suffix.is_some());
        assert_config_refs_hide(&plan.config_refs, &["raw-cloudflare-account-canary"]);

        let plan = connector_file_schedule(
            ImportAdapterInput::KubernetesApi,
            "/var/tally/kubernetes-projection",
            None,
            None,
            None,
        )
        .expect("valid Kubernetes schedule");
        assert_eq!(
            plan.descriptor.connector_type,
            "kubernetes_api_discovery_file_v1"
        );
        assert_eq!(plan.config_refs["kind"], "file_env_v1");

        // CASB file imports must name the account the snapshot belongs to.
        assert!(
            connector_file_schedule(
                ImportAdapterInput::CloudflareCasb,
                "/var/tally/casb-snapshot",
                None,
                None,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn native_enterprise_schedules_seal_endpoints_and_tokens() {
        let plan = connector_schedule_source(&ConnectorScheduleSourceInput::CasbApi {
            account_id: "casb-account-canary".into(),
            api_token: "casb-token-canary".into(),
        })
        .expect("valid native CASB schedule");
        assert_eq!(
            plan.descriptor.connector_type,
            "cloudflare_casb_integrations_api_v1"
        );
        assert_eq!(plan.config_refs["kind"], "casb_api_v1");
        assert_config_refs_hide(
            &plan.config_refs,
            &["casb-account-canary", "casb-token-canary"],
        );

        let plan = connector_schedule_source(&ConnectorScheduleSourceInput::KubernetesApi {
            api_url: "https://cluster.internal.example:6443".into(),
            bearer_token: "bearer-token-canary".into(),
            ca_pem: Some(
                "-----BEGIN CERTIFICATE-----\nY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n".into(),
            ),
        })
        .expect("valid native Kubernetes schedule");
        assert_eq!(
            plan.descriptor.connector_type,
            "kubernetes_api_discovery_pull_v1"
        );
        assert_eq!(plan.config_refs["kind"], "kubernetes_api_v1");
        assert_eq!(plan.config_refs["auth_mode"], "explicit_bearer");
        assert_eq!(
            plan.credentials.get("ca_pem").map(String::as_str),
            Some("-----BEGIN CERTIFICATE-----\nY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n")
        );
        assert_config_refs_hide(
            &plan.config_refs,
            &[
                "https://cluster.internal.example:6443",
                "bearer-token-canary",
                "BEGIN CERTIFICATE",
            ],
        );

        let plan = connector_schedule_source(&ConnectorScheduleSourceInput::LitellmApi {
            base_url: "https://litellm.internal.example:4000".into(),
            api_key: "sk-litellm-key-canary".into(),
            initial_backfill_seconds: 3_600,
            initial_record_limit: 5_000,
        })
        .expect("valid native LiteLLM schedule");
        assert_eq!(
            plan.descriptor.connector_type,
            "litellm_model_groups_api_v1"
        );
        assert_eq!(plan.config_refs["kind"], "litellm_api_v1");
        assert_eq!(plan.config_refs["backfill_seconds"], "3600");
        assert_eq!(plan.config_refs["record_limit"], "5000");
        assert_config_refs_hide(
            &plan.config_refs,
            &[
                "https://litellm.internal.example:4000",
                "sk-litellm-key-canary",
            ],
        );

        let plan = connector_schedule_source(&ConnectorScheduleSourceInput::AiGatewayApi {
            account_id: "aigw-account-canary".into(),
            api_token: "aigw-token-canary".into(),
            initial_backfill_seconds: 3_600,
            initial_record_limit: 1_000,
        })
        .expect("valid native AI Gateway schedule");
        assert_eq!(
            plan.descriptor.connector_type,
            "cloudflare_ai_gateway_api_v1"
        );
        assert_eq!(plan.config_refs["kind"], "ai_gateway_api_v1");
        assert_config_refs_hide(
            &plan.config_refs,
            &["aigw-account-canary", "aigw-token-canary"],
        );

        // A newline in a credential would let the value forge an HTTP header downstream.
        assert!(
            connector_schedule_source(&ConnectorScheduleSourceInput::AiGatewayApi {
                account_id: "aigw-account-canary".into(),
                api_token: "token\nX-Injected: 1".into(),
                initial_backfill_seconds: 3_600,
                initial_record_limit: 1_000,
            })
            .is_err()
        );
    }

    #[test]
    fn security_logs_schedule_seals_credentials_and_round_trips_edits() {
        for mut input in [
            serde_json::json!({"source_kind":"rapid7_edr", "region":"us", "log_id":"00000000-0000-0000-0000-000000000001", "api_key":"secret-canary", "initial_backfill_seconds":3600}),
            serde_json::json!({"source_kind":"netskope", "tenant_url":"https://company.goskope.com/", "event_type":"page", "api_token":"secret-canary", "initial_backfill_seconds":3600}),
        ] {
            let source: ConnectorScheduleSourceInput =
                serde_json::from_value(input.clone()).unwrap();
            let plan = connector_schedule_source(&source).unwrap();
            assert_config_refs_hide(&plan.config_refs, &["secret-canary"]);
            let fields = connector_form_configuration(&plan.config_refs, &plan.credentials);
            assert!(!fields.values().any(|value| value == "secret-canary"));
            let secret = if input["source_kind"] == "netskope" {
                "api_token"
            } else {
                "api_key"
            };
            input[secret] = "".into();
            let edited = connector_schedule_source_with_existing(
                &serde_json::from_value(input.clone()).unwrap(),
                Some(&plan.credentials),
            )
            .unwrap();
            assert_eq!(edited.credentials, plan.credentials);
            assert_eq!(edited.identity_suffix, plan.identity_suffix);
            input[secret] = "rotated-canary".into();
            let rotated =
                connector_schedule_source(&serde_json::from_value(input.clone()).unwrap()).unwrap();
            assert_eq!(rotated.identity_suffix, plan.identity_suffix);
            input["initial_backfill_seconds"] = 604_801.into();
            assert!(connector_schedule_source(&serde_json::from_value(input).unwrap()).is_err());
        }
        for input in [
            serde_json::json!({"source_kind":"rapid7_edr", "region":"evil.test", "log_id":"00000000-0000-0000-0000-000000000001", "api_key":"secret"}),
            serde_json::json!({"source_kind":"rapid7_edr", "region":"us", "log_id":"../other", "api_key":"secret"}),
            serde_json::json!({"source_kind":"netskope", "tenant_url":"https://company.goskope.com.evil.test", "event_type":"page", "api_token":"secret"}),
            serde_json::json!({"source_kind":"netskope", "tenant_url":"https://company.goskope.com", "event_type":"../policy", "api_token":"secret"}),
        ] {
            assert!(connector_schedule_source(&serde_json::from_value(input).unwrap()).is_err());
        }
    }

    #[test]
    fn crowdstrike_edr_schedule_is_bounded_and_seals_oauth_credentials() {
        let plan = connector_schedule_source(&ConnectorScheduleSourceInput::CrowdstrikeEdr {
            cloud: "us-2".into(),
            client_id: "crowdstrike-client-canary".into(),
            client_secret: "crowdstrike-secret-canary".into(),
            initial_backfill_seconds: 3_600,
            initial_record_limit: 1_000,
        })
        .expect("valid CrowdStrike EDR schedule");
        assert_eq!(
            plan.descriptor.connector_type,
            "crowdstrike_edr_ngsiem_api_v1"
        );
        assert_eq!(plan.config_refs["kind"], "crowdstrike_edr_ngsiem_api_v1");
        assert_eq!(plan.config_refs["cloud"], "us-2");
        assert_config_refs_hide(
            &plan.config_refs,
            &["crowdstrike-client-canary", "crowdstrike-secret-canary"],
        );
        assert!(
            connector_schedule_source(&ConnectorScheduleSourceInput::CrowdstrikeEdr {
                cloud: "operator-supplied-url".into(),
                client_id: "client".into(),
                client_secret: "secret".into(),
                initial_backfill_seconds: 3_600,
                initial_record_limit: 1_000,
            })
            .is_err()
        );
    }

    #[test]
    fn defender_and_cato_schedules_are_bounded_and_seal_credentials() {
        let defender =
            connector_schedule_source(&ConnectorScheduleSourceInput::MicrosoftDefenderApi {
                tenant_id: "734a9822-652b-4efe-a23e-13afcb6e5578".into(),
                client_id: "11111111-2222-4333-8444-555555555555".into(),
                client_secret: "defender-secret-canary".into(),
                initial_backfill_seconds: 3_600,
                initial_record_limit: 1_000,
            })
            .expect("valid Defender schedule");
        assert_eq!(
            defender.descriptor.connector_type,
            "microsoft_defender_edr_api_v1"
        );
        assert_eq!(
            defender.config_refs["kind"],
            "microsoft_defender_graph_hunting_v1"
        );
        assert_config_refs_hide(
            &defender.config_refs,
            &[
                "734a9822-652b-4efe-a23e-13afcb6e5578",
                "11111111-2222-4333-8444-555555555555",
                "defender-secret-canary",
            ],
        );

        let cato = connector_schedule_source(&ConnectorScheduleSourceInput::CatoNetworksApi {
            account_id: "1234567".into(),
            api_key: "cato-key-canary".into(),
            api_hostname: "api.us1.catonetworks.com".into(),
            initial_backfill_seconds: 3_600,
            initial_record_limit: 1_000,
        })
        .expect("valid Cato schedule");
        assert_eq!(cato.descriptor.connector_type, "cato_networks_api_v1");
        assert_eq!(cato.config_refs["kind"], "cato_networks_events_feed_v1");
        assert_eq!(cato.config_refs["api_hostname"], "api.us1.catonetworks.com");
        assert_config_refs_hide(&cato.config_refs, &["1234567", "cato-key-canary"]);

        assert!(
            connector_schedule_source(&ConnectorScheduleSourceInput::CatoNetworksApi {
                account_id: "1234567".into(),
                api_key: "cato-key-canary".into(),
                api_hostname: "evil.example.com".into(),
                initial_backfill_seconds: 3_600,
                initial_record_limit: 1_000,
            })
            .is_err()
        );
    }

    #[test]
    fn cloudflare_gateway_defaults_to_http_and_dns_and_accepts_optional_s3() {
        let api_only =
            connector_schedule_source(&ConnectorScheduleSourceInput::CloudflareZeroTrustGateway {
                account_id: "0123456789abcdef0123456789abcdef".into(),
                api_token: "analytics-token-canary".into(),
                window_seconds: 3_600,
                endpoint_url: String::new(),
                bucket: String::new(),
                prefix: String::new(),
                region: "auto".into(),
                access_key_id: String::new(),
                secret_access_key: String::new(),
                object_limit: 32,
            })
            .expect("valid API-only Gateway schedule");
        assert_eq!(
            api_only.descriptor.connector_type,
            "cloudflare_zero_trust_gateway_v1"
        );
        assert_eq!(
            api_only.config_refs["kind"],
            "cloudflare_zero_trust_gateway_v1"
        );
        assert!(safe_import_source_lineage(
            api_only.config_refs["source_lineage_id"]
                .as_str()
                .expect("lineage")
        ));
        assert_eq!(api_only.config_refs["endpoint_url"], "");
        assert_eq!(
            api_only.credentials.get("api_token").map(String::as_str),
            Some("analytics-token-canary")
        );
        assert!(!api_only.credentials.contains_key("access_key_id"));

        let plan =
            connector_schedule_source(&ConnectorScheduleSourceInput::CloudflareZeroTrustGateway {
                account_id: "0123456789abcdef0123456789abcdef".into(),
                api_token: "analytics-token-canary".into(),
                window_seconds: 3_600,
                endpoint_url: "https://0123456789abcdef.r2.cloudflarestorage.com".into(),
                bucket: "gateway-http-logs".into(),
                prefix: "tally/".into(),
                region: "auto".into(),
                access_key_id: "r2-access-key-canary".into(),
                secret_access_key: "r2-secret-key-canary".into(),
                object_limit: 32,
            })
            .expect("valid Gateway schedule with HTTP Logpush");
        assert_eq!(
            plan.descriptor.connector_type,
            "cloudflare_zero_trust_gateway_v1"
        );
        assert_eq!(plan.config_refs["kind"], "cloudflare_zero_trust_gateway_v1");
        assert_eq!(plan.config_refs["bucket"], "gateway-http-logs");
        assert_config_refs_hide(
            &plan.config_refs,
            &[
                "0123456789abcdef0123456789abcdef",
                "analytics-token-canary",
                "r2-access-key-canary",
                "r2-secret-key-canary",
            ],
        );
        let fields = connector_form_configuration(&plan.config_refs, &plan.credentials);
        assert_eq!(
            fields.get("endpoint_url").map(String::as_str),
            Some("https://0123456789abcdef.r2.cloudflarestorage.com/")
        );
        assert!(!fields.contains_key("access_key_id"));
        assert!(!fields.contains_key("secret_access_key"));

        assert!(
            connector_cloudflare_zero_trust_gateway_schedule(
                "0123456789abcdef0123456789abcdef",
                "analytics-token-canary",
                3_600,
                "https://0123456789abcdef.r2.cloudflarestorage.com",
                "",
                "",
                "auto",
                Some("r2-access-key-canary"),
                Some("r2-secret-key-canary"),
                32,
            )
            .is_err()
        );
    }

    #[test]
    fn cloudflare_gateway_edit_retains_or_drops_optional_s3_secrets() {
        let existing_credentials = BTreeMap::from([
            (
                "account_id".to_owned(),
                "0123456789abcdef0123456789abcdef".to_owned(),
            ),
            ("api_token".to_owned(), "analytics-token-canary".to_owned()),
            (
                "access_key_id".to_owned(),
                "r2-access-key-canary".to_owned(),
            ),
            (
                "secret_access_key".to_owned(),
                "r2-secret-key-canary".to_owned(),
            ),
        ]);
        let edited = connector_schedule_source_with_existing(
            &ConnectorScheduleSourceInput::CloudflareZeroTrustGateway {
                account_id: "0123456789abcdef0123456789abcdef".into(),
                api_token: String::new(),
                window_seconds: 7_200,
                endpoint_url: "https://0123456789abcdef.r2.cloudflarestorage.com".into(),
                bucket: "gateway-http-logs".into(),
                prefix: "tally/".into(),
                region: "auto".into(),
                access_key_id: String::new(),
                secret_access_key: String::new(),
                object_limit: 64,
            },
            Some(&existing_credentials),
        )
        .expect("blank edit secrets retain the encrypted values");
        assert_eq!(edited.credentials, existing_credentials);

        let disabled = connector_schedule_source_with_existing(
            &ConnectorScheduleSourceInput::CloudflareZeroTrustGateway {
                account_id: "0123456789abcdef0123456789abcdef".into(),
                api_token: String::new(),
                window_seconds: 3_600,
                endpoint_url: String::new(),
                bucket: String::new(),
                prefix: String::new(),
                region: "auto".into(),
                access_key_id: String::new(),
                secret_access_key: String::new(),
                object_limit: 32,
            },
            Some(&existing_credentials),
        )
        .expect("clearing optional storage disables it");
        assert!(!disabled.credentials.contains_key("access_key_id"));
        assert!(!disabled.credentials.contains_key("secret_access_key"));
    }

    #[test]
    fn rotating_a_token_keeps_the_connector_instance_identity() {
        let first = connector_schedule_source(&ConnectorScheduleSourceInput::AiGatewayApi {
            account_id: "aigw-account-canary".into(),
            api_token: "aigw-token-original".into(),
            initial_backfill_seconds: 3_600,
            initial_record_limit: 1_000,
        })
        .expect("valid schedule");
        let rotated = connector_schedule_source(&ConnectorScheduleSourceInput::AiGatewayApi {
            account_id: "aigw-account-canary".into(),
            api_token: "aigw-token-rotated".into(),
            initial_backfill_seconds: 3_600,
            initial_record_limit: 1_000,
        })
        .expect("valid schedule");
        let other_account =
            connector_schedule_source(&ConnectorScheduleSourceInput::AiGatewayApi {
                account_id: "aigw-other-account".into(),
                api_token: "aigw-token-original".into(),
                initial_backfill_seconds: 3_600,
                initial_record_limit: 1_000,
            })
            .expect("valid schedule");
        assert_eq!(first.identity_suffix, rotated.identity_suffix);
        assert_ne!(first.identity_suffix, other_account.identity_suffix);
    }

    #[test]
    fn connector_edit_retains_blank_secrets_and_exposes_only_safe_fields() {
        let existing_credentials = credential_bundle([
            ("account_id", "aigw-account-canary"),
            ("api_token", "aigw-token-canary"),
        ]);
        let plan = connector_schedule_source_with_existing(
            &ConnectorScheduleSourceInput::AiGatewayApi {
                account_id: "aigw-account-canary".into(),
                api_token: String::new(),
                initial_backfill_seconds: 3_600,
                initial_record_limit: 1_000,
            },
            Some(&existing_credentials),
        )
        .expect("edit should retain the sealed token");
        assert_eq!(plan.credentials, existing_credentials);

        let fields = connector_form_configuration(&plan.config_refs, &plan.credentials);
        assert_eq!(
            fields.get("account_id"),
            Some(&"aigw-account-canary".to_owned())
        );
        assert!(!fields.contains_key("api_token"));

        let edr_credentials = credential_bundle([
            ("client_id", "crowdstrike-client-canary"),
            ("client_secret", "crowdstrike-secret-canary"),
        ]);
        let edr_plan = connector_schedule_source_with_existing(
            &ConnectorScheduleSourceInput::CrowdstrikeEdr {
                cloud: "eu-1".into(),
                client_id: String::new(),
                client_secret: String::new(),
                initial_backfill_seconds: 7_200,
                initial_record_limit: 2_000,
            },
            Some(&edr_credentials),
        )
        .expect("EDR edit should retain both sealed OAuth values");
        assert_eq!(edr_plan.credentials, edr_credentials);
        let fields = connector_form_configuration(&edr_plan.config_refs, &edr_plan.credentials);
        assert_eq!(fields.get("cloud"), Some(&"eu-1".to_owned()));
        assert_eq!(
            fields.get("initial_backfill_seconds"),
            Some(&"7200".to_owned())
        );
        assert!(!fields.contains_key("client_id"));
        assert!(!fields.contains_key("client_secret"));
    }

    #[test]
    fn cloud_network_schedule_seals_project_and_network_identifiers() {
        let service_account_json = r#"{"type":"service_account"}"#;
        let plan = connector_schedule_source(&ConnectorScheduleSourceInput::CloudNetwork {
            adapter: ImportAdapterInput::GcpCloudFlowApi,
            account_id: "tally-private-project".into(),
            network_id: "private-network".into(),
            region: None,
            log_group: None,
            workspace_resource: None,
            aws_access_key_id: None,
            aws_secret_access_key: None,
            azure_tenant_id: None,
            azure_client_id: None,
            azure_client_secret: None,
            gcp_service_account_json: Some(service_account_json.into()),
            initial_backfill_seconds: 3_600,
        })
        .expect("valid native network schedule");
        assert_eq!(plan.descriptor.connector_type, "gcp_vpc_flow_api_v1");
        assert_eq!(plan.config_refs["kind"], "cloud_network_api_v1");
        assert_eq!(plan.config_refs["region"], "global");
        assert_eq!(plan.config_refs["backfill_seconds"], "3600");
        assert!(
            plan.identity_suffix
                .is_some_and(|value| value.contains("gcp_cloud_flow_api"))
        );
        assert_eq!(
            plan.credentials
                .get("gcp_service_account_json")
                .map(String::as_str),
            Some(service_account_json)
        );
        assert_config_refs_hide(
            &plan.config_refs,
            &[
                "tally-private-project",
                "private-network",
                service_account_json,
            ],
        );

        // GCP flow logs are global; naming a region is a contract error.
        assert!(
            connector_schedule_source(&ConnectorScheduleSourceInput::CloudNetwork {
                adapter: ImportAdapterInput::GcpCloudFlowApi,
                account_id: "tally-private-project".into(),
                network_id: "private-network".into(),
                region: Some("us-central1".into()),
                log_group: None,
                workspace_resource: None,
                aws_access_key_id: None,
                aws_secret_access_key: None,
                azure_tenant_id: None,
                azure_client_id: None,
                azure_client_secret: None,
                gcp_service_account_json: None,
                initial_backfill_seconds: 3_600,
            })
            .is_err()
        );
    }

    #[test]
    fn aws_cloud_network_schedule_requires_region_and_log_group_by_role() {
        let access_key_id = "AKIAIOSFODNN7EXAMPLE";
        let secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let plan = connector_schedule_source(&ConnectorScheduleSourceInput::CloudNetwork {
            adapter: ImportAdapterInput::AwsCloudFlowApi,
            account_id: "123456789012".into(),
            network_id: "vpc-0abc".into(),
            region: Some("us-east-1".into()),
            log_group: Some("/aws/vpc/flowlogs".into()),
            workspace_resource: None,
            aws_access_key_id: Some(access_key_id.into()),
            aws_secret_access_key: Some(secret_access_key.into()),
            azure_tenant_id: None,
            azure_client_id: None,
            azure_client_secret: None,
            gcp_service_account_json: None,
            initial_backfill_seconds: 3_600,
        })
        .expect("valid AWS flow schedule");
        assert_eq!(plan.config_refs["region"], "us-east-1");
        assert_eq!(
            plan.credentials.get("log_group").map(String::as_str),
            Some("/aws/vpc/flowlogs")
        );
        assert_eq!(
            plan.credentials
                .get("aws_access_key_id")
                .map(String::as_str),
            Some(access_key_id)
        );
        assert_eq!(
            plan.credentials
                .get("aws_secret_access_key")
                .map(String::as_str),
            Some(secret_access_key)
        );
        assert_config_refs_hide(
            &plan.config_refs,
            &[
                "/aws/vpc/flowlogs",
                "vpc-0abc",
                access_key_id,
                secret_access_key,
            ],
        );
        assert!(
            connector_schedule_source(&ConnectorScheduleSourceInput::CloudNetwork {
                adapter: ImportAdapterInput::AwsNetworkMappingApi,
                account_id: "123456789012".into(),
                network_id: "vpc-0abc".into(),
                region: Some("us-east-1".into()),
                log_group: Some("/aws/vpc/flowlogs".into()),
                workspace_resource: None,
                aws_access_key_id: None,
                aws_secret_access_key: None,
                azure_tenant_id: None,
                azure_client_id: None,
                azure_client_secret: None,
                gcp_service_account_json: None,
                initial_backfill_seconds: 3_600,
            })
            .is_err()
        );
    }

    #[test]
    fn azure_cloud_network_schedule_requires_workspace_only_for_flow() {
        let tenant_id = "11111111-2222-3333-4444-555555555555";
        let client_id = "66666666-7777-8888-9999-aaaaaaaaaaaa";
        let client_secret = "azure-client-secret-fixture";
        let plan = connector_schedule_source(&ConnectorScheduleSourceInput::CloudNetwork {
            adapter: ImportAdapterInput::AzureCloudFlowApi,
            account_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
            network_id: "/subscriptions/aaaa/virtualNetworks/vnet".into(),
            region: Some("eastus2".into()),
            log_group: None,
            workspace_resource: Some("/subscriptions/aaaa/workspaces/logs".into()),
            aws_access_key_id: None,
            aws_secret_access_key: None,
            azure_tenant_id: Some(tenant_id.into()),
            azure_client_id: Some(client_id.into()),
            azure_client_secret: Some(client_secret.into()),
            gcp_service_account_json: None,
            initial_backfill_seconds: 3_600,
        })
        .expect("valid Azure flow schedule");
        assert_eq!(plan.config_refs["region"], "eastus2");
        assert_eq!(
            plan.credentials
                .get("workspace_resource")
                .map(String::as_str),
            Some("/subscriptions/aaaa/workspaces/logs")
        );
        assert_eq!(
            plan.credentials.get("azure_tenant_id").map(String::as_str),
            Some(tenant_id)
        );
        assert_eq!(
            plan.credentials.get("azure_client_id").map(String::as_str),
            Some(client_id)
        );
        assert_eq!(
            plan.credentials
                .get("azure_client_secret")
                .map(String::as_str),
            Some(client_secret)
        );
        assert_config_refs_hide(
            &plan.config_refs,
            &["/subscriptions/", tenant_id, client_id, client_secret],
        );
        assert!(
            connector_schedule_source(&ConnectorScheduleSourceInput::CloudNetwork {
                adapter: ImportAdapterInput::AzureNetworkMappingApi,
                account_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
                network_id: "/subscriptions/aaaa/virtualNetworks/vnet".into(),
                region: Some("eastus2".into()),
                log_group: None,
                workspace_resource: Some("/subscriptions/aaaa/workspaces/logs".into()),
                aws_access_key_id: None,
                aws_secret_access_key: None,
                azure_tenant_id: None,
                azure_client_id: None,
                azure_client_secret: None,
                gcp_service_account_json: None,
                initial_backfill_seconds: 3_600,
            })
            .is_err()
        );
    }

    #[test]
    fn sealed_credentials_round_trip_and_omit_an_empty_bundle() {
        let cipher = SecretCipher::from_hex(&"11".repeat(32)).expect("cipher");
        let bundle = credential_bundle([
            ("account_id", "aigw-account-canary"),
            ("api_token", "aigw-token-canary"),
        ]);
        let sealed = seal_connector_credentials(&cipher, &bundle)
            .expect("seal")
            .expect("bundle is not empty");
        assert!(sealed.is_well_formed());
        let plaintext = cipher
            .decrypt(&sealed.nonce, &sealed.ciphertext)
            .expect("decrypt");
        let restored: BTreeMap<String, String> =
            serde_json::from_str(&plaintext).expect("decode bundle");
        assert_eq!(restored, bundle);
        assert!(
            seal_connector_credentials(&cipher, &BTreeMap::new())
                .expect("seal")
                .is_none()
        );
    }

    #[test]
    fn flattened_schedule_contract_decodes_and_rejects_unknown_fields() {
        let valid = serde_json::json!({
            "source_kind": "cloudflare_zero_trust_gateway",
            "account_id": "0123456789abcdef0123456789abcdef",
            "api_token": "cf-token",
            "window_seconds": 3600,
            "endpoint_url": "https://0123456789abcdef.r2.cloudflarestorage.com",
            "bucket": "gateway-http-logs",
            "prefix": "tally/",
            "region": "auto",
            "access_key_id": "r2-access-key",
            "secret_access_key": "r2-secret-key",
            "object_limit": 32,
            "interval_seconds": 300,
            "paused": true,
            "acknowledge_source_access": true
        });
        assert!(serde_json::from_value::<ConnectorScheduleRequest>(valid.clone()).is_ok());
        let host_file = serde_json::json!({
            "source_kind": "file",
            "adapter": "zscaler",
            "source_path": "/var/log/zscaler",
            "interval_seconds": 300,
            "paused": true,
            "acknowledge_source_access": true
        });
        assert!(serde_json::from_value::<ConnectorScheduleRequest>(host_file).is_err());
        let native = serde_json::json!({
            "source_kind": "managed_cloud",
            "adapter": "gcp_vertex_ai_api",
            "account_id": "tally-private-project",
            "region": "us-central1",
            "interval_seconds": 300,
            "paused": true,
            "acknowledge_source_access": true
        });
        assert!(serde_json::from_value::<ConnectorScheduleRequest>(native).is_ok());
        let native_network = serde_json::json!({
            "source_kind": "cloud_network",
            "adapter": "gcp_network_mapping_api",
            "account_id": "tally-private-project",
            "network_id": "private-network",
            "initial_backfill_seconds": 3600,
            "interval_seconds": 300,
            "paused": true,
            "acknowledge_source_access": true
        });
        assert!(serde_json::from_value::<ConnectorScheduleRequest>(native_network).is_ok());
        let legacy_ai_gateway = serde_json::json!({
            "source_kind": "ai_gateway_api",
            "account_id": "cf-account",
            "api_token": "cf-token",
            "interval_seconds": 300,
            "paused": false,
            "acknowledge_source_access": true
        });
        let decoded = serde_json::from_value::<ConnectorScheduleRequest>(legacy_ai_gateway)
            .expect("legacy AI Gateway request");
        assert!(matches!(
            decoded.source,
            ConnectorScheduleSourceInput::AiGatewayApi {
                initial_backfill_seconds: 3_600,
                initial_record_limit: 1_000,
                ..
            }
        ));
        let mut unknown = valid;
        unknown
            .as_object_mut()
            .expect("object")
            .insert("credential".to_owned(), serde_json::json!("must-not-pass"));
        assert!(serde_json::from_value::<ConnectorScheduleRequest>(unknown).is_err());
    }

    #[test]
    fn friendly_name_rides_every_flattened_source_contract() {
        // The label sits on the outer schedule struct, so serde has to hand it to the outer
        // fields before the flattened source enum sees the rest. Cover one source of each
        // shape -- single-credential API, managed cloud, and the API-token enterprise pulls -- so
        // no variant loses the field to its deny_unknown_fields.
        for source in [
            serde_json::json!({
                "source_kind": "nextdns_api",
                "profile_id": "abc123",
                "api_key": "key",
                "initial_backfill_seconds": 3600,
                "initial_record_limit": 1000
            }),
            serde_json::json!({
                "source_kind": "managed_cloud",
                "adapter": "gcp_vertex_ai_api",
                "account_id": "tally-private-project",
                "region": "us-central1"
            }),
            serde_json::json!({
                "source_kind": "cloud_network",
                "adapter": "gcp_network_mapping_api",
                "account_id": "tally-private-project",
                "network_id": "private-network",
                "initial_backfill_seconds": 3600
            }),
            serde_json::json!({
                "source_kind": "kubernetes_api",
                "api_url": "https://cluster.internal.example:6443",
                "bearer_token": "token"
            }),
            serde_json::json!({
                "source_kind": "litellm_api",
                "base_url": "https://litellm.internal.example:4000",
                "api_key": "sk-fixture"
            }),
            serde_json::json!({
                "source_kind": "casb_api",
                "account_id": "cf-account",
                "api_token": "cf-token"
            }),
            serde_json::json!({
                "source_kind": "ai_gateway_api",
                "account_id": "cf-account",
                "api_token": "cf-token",
                "initial_backfill_seconds": 3600,
                "initial_record_limit": 1000
            }),
            serde_json::json!({
                "source_kind": "cloudflare_zero_trust_gateway",
                "account_id": "0123456789abcdef0123456789abcdef",
                "api_token": "cf-token",
                "window_seconds": 3600,
                "endpoint_url": "https://0123456789abcdef.r2.cloudflarestorage.com",
                "bucket": "gateway-http-logs",
                "prefix": "tally/",
                "region": "auto",
                "access_key_id": "r2-access-key",
                "secret_access_key": "r2-secret-key",
                "object_limit": 32
            }),
        ] {
            let mut body = source;
            let object = body.as_object_mut().expect("object");
            object.insert("interval_seconds".to_owned(), serde_json::json!(300));
            object.insert(
                "acknowledge_source_access".to_owned(),
                serde_json::json!(true),
            );
            object.insert(
                "friendly_name".to_owned(),
                serde_json::json!("Production cluster"),
            );
            let request = serde_json::from_value::<ConnectorScheduleRequest>(body.clone())
                .unwrap_or_else(|error| panic!("decode {body}: {error}"));
            assert_eq!(request.friendly_name.as_deref(), Some("Production cluster"));
            // Omitting it is what keeps a stored name from being erased by a later edit.
            body.as_object_mut()
                .expect("object")
                .remove("friendly_name");
            let request =
                serde_json::from_value::<ConnectorScheduleRequest>(body).expect("decode request");
            assert_eq!(request.friendly_name, None);
        }
    }

    #[test]
    fn connector_friendly_name_bounds_operator_input() {
        assert!(safe_connector_friendly_name("Production EKS · eu-west-1"));
        // Empty is the "unset" value, not a rejection: it clears a name an operator retired.
        assert!(safe_connector_friendly_name(""));
        assert!(!safe_connector_friendly_name(" leading space"));
        assert!(!safe_connector_friendly_name("two\nlines"));
        assert!(!safe_connector_friendly_name(&"n".repeat(121)));
        assert!(safe_connector_friendly_name(&"n".repeat(120)));
    }

    #[test]
    fn events_carry_the_connector_label_and_null_it_once_deleted() {
        let now = Utc::now();
        let live_instance = uuid::Uuid::now_v7();
        let named_instance = uuid::Uuid::now_v7();
        let deleted_instance = uuid::Uuid::now_v7();
        let receipt = EvidenceReceipt::RecordDigest {
            algorithm: DigestAlgorithm::Sha256,
            digest: "ab".repeat(32),
        };
        let observation = |instance_id: uuid::Uuid| {
            Observation::new(
                uuid::Uuid::now_v7(),
                now,
                ConnectorRef {
                    instance_id,
                    connector_type: "kubernetes_api_v1".to_owned(),
                    implementation_version: "1".to_owned(),
                    source_lineage_id: None,
                },
                ObservationKind::KubernetesResource,
                receipt.clone(),
            )
        };
        let connector_by_id = [
            ConnectorLabelView {
                connector_instance_id: live_instance,
                connector_type: "kubernetes_api_v1".to_owned(),
                display_name: "Kubernetes API discovery (native pull)".to_owned(),
                friendly_name: String::new(),
            },
            ConnectorLabelView {
                connector_instance_id: named_instance,
                connector_type: "kubernetes_api_v1".to_owned(),
                display_name: "Kubernetes API discovery (native pull)".to_owned(),
                friendly_name: "Production EKS".to_owned(),
            },
        ]
        .into_iter()
        .map(|connector| (connector.connector_instance_id, connector))
        .collect::<HashMap<_, _>>();
        let systems = HashMap::new();

        let unnamed = event_response(
            &observation(live_instance),
            None,
            &systems,
            &connector_by_id,
        );
        assert_eq!(unnamed.connector_id, Some(live_instance));
        assert_eq!(unnamed.connector_friendly_name, None);
        assert_eq!(
            unnamed.connector_label.as_deref(),
            Some("Kubernetes API discovery (native pull)")
        );

        let named = event_response(
            &observation(named_instance),
            None,
            &systems,
            &connector_by_id,
        );
        assert_eq!(named.connector_id, Some(named_instance));
        assert_eq!(
            named.connector_friendly_name.as_deref(),
            Some("Production EKS")
        );
        assert_eq!(named.connector_label.as_deref(), Some("Production EKS"));

        // The connector is gone; the evidence it produced is not, so the instance recorded on
        // the observation survives while every label resolved from the live table goes null.
        let orphaned = event_response(
            &observation(deleted_instance),
            None,
            &systems,
            &connector_by_id,
        );
        assert_eq!(orphaned.connector_instance_id, deleted_instance);
        assert_eq!(orphaned.connector_id, None);
        assert_eq!(orphaned.connector_friendly_name, None);
        assert_eq!(orphaned.connector_display_name, None);
        assert_eq!(orphaned.connector_label, None);
        assert_eq!(orphaned.source_type, "kubernetes_api_v1");
    }

    #[test]
    fn connector_instance_identity_is_stable_per_installation_and_type() {
        let installation = uuid::Uuid::now_v7();
        let first = default_connector_instance_id(installation, "nextdns_csv_v1");
        let replay = default_connector_instance_id(installation, "nextdns_csv_v1");
        let other = default_connector_instance_id(installation, "zscaler_zia_nss_web_v1");
        assert_eq!(first, replay);
        assert_ne!(first, other);
    }
}
