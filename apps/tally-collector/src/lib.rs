//! Reusable Tally connector runtime.
//!
//! The standalone binary and embedding products compile the same connector pull and normalization
//! code. An embedding worker can execute one leased due window against an in-process Tally router,
//! avoiding a second daemon and avoiding unauthenticated internal HTTP endpoints.

#![allow(dead_code)]

/// Leases and executes one bounded window of due connector jobs through an in-process Tally API.
///
/// The provider-facing pulls still use the hardened outbound HTTP client. Preview and commit are
/// dispatched through Tally's router in memory, so the exact same admission, deduplication, privacy,
/// and finding projection path is used by standalone Tally and by a host worker.
///
/// # Errors
///
/// Returns an error when jobs cannot be leased or completed, the registry cannot be refreshed, an
/// outbound client cannot be created, or durable connector state cannot be recorded.
pub async fn run_due_connector_jobs(
    state: &tally_api::AppState,
    lease_owner: Uuid,
    lease_seconds: u16,
) -> Result<usize> {
    let jobs = state
        .postgres
        .lease_due_connector_jobs(lease_owner, Utc::now(), lease_seconds, 4)
        .await
        .context("lease due Tally connector jobs")?;
    let count = jobs.len();
    if count == 0 {
        return Ok(0);
    }
    tally_api::refresh_registry_overlays(state)
        .await
        .context("refresh Tally registry before connector admission")?;
    let client = collector_http_client()?;
    let routes = tally_api::routes(state.clone());

    // All four leases start at claim time. Running the pulls serially can expire the last lease
    // before its provider request begins, particularly for Falcon's 30-second query polling.
    let mut running = tokio::task::JoinSet::new();
    for job in jobs {
        crate::pull_support::report_due_age(&job, Utc::now());
        let state = state.clone();
        let client = client.clone();
        let routes = routes.clone();
        running.spawn(async move {
            let execution = execute_scheduled_job_in_process(
                &state,
                &client,
                &routes,
                &job,
                Utc::now(),
                lease_seconds,
            );
            tokio::pin!(execution);
            let heartbeat_period = std::time::Duration::from_secs(u64::from(lease_seconds) / 4);
            let mut heartbeat = tokio::time::interval_at(
                tokio::time::Instant::now() + heartbeat_period,
                heartbeat_period,
            );
            let result = loop {
                tokio::select! {
                    result = &mut execution => break result?,
                    _ = heartbeat.tick() => {
                        state.postgres.renew_connector_job_lease(
                            job.job_id,
                            lease_owner,
                            Utc::now(),
                            lease_seconds,
                        ).await.context("renew Tally connector lease while pulling provider data")?;
                    }
                }
            };
            let (outcome, error_code) = match result {
                Ok(outcome) => (outcome, None),
                Err(code) => (ConnectorRunStatus::Failed, Some(code.to_owned())),
            };
            state
                .postgres
                .complete_connector_job(&ConnectorJobCompletion {
                    job_id: job.job_id,
                    lease_owner,
                    outcome,
                    error_code,
                    finished_at: Utc::now(),
                    catch_up: if outcome == ConnectorRunStatus::Completed {
                        crate::pull_support::needs_catch_up(&state.postgres, &job, Utc::now())
                            .await?
                    } else {
                        false
                    },
                })
                .await
                .context("complete Tally connector schedule attempt")?;
            Ok::<(), anyhow::Error>(())
        });
    }
    let mut first_error = None;
    while let Some(result) = running.join_next().await {
        if let Err(error) = result
            .context("Tally connector task panicked")
            .and_then(|value| value)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(count)
}

async fn execute_scheduled_job_in_process(
    state: &tally_api::AppState,
    client: &reqwest::Client,
    routes: &Router,
    job: &LeasedConnectorJob,
    started_at: DateTime<Utc>,
    lease_seconds: u16,
) -> Result<Result<ConnectorRunStatus, &'static str>> {
    let prepared =
        match prepare_scheduled_job(&state.postgres, &state.secret_cipher, client, job).await {
            Ok(value) => value,
            Err(code) => {
                record_job_failure(&state.postgres, job, started_at, code).await?;
                return Ok(Err(code));
            }
        };
    match prepared {
        PreparedJob::Source {
            descriptor,
            adapter,
            input,
            checkpoint,
            source_lineage_id,
            expected_canonical_digest,
            cloud,
            casb_account_id,
        } => {
            state
                .postgres
                .renew_connector_job_lease(job.job_id, job.lease_owner, Utc::now(), lease_seconds)
                .await
                .context("renew Tally connector job lease before admission")?;
            let result = commit_through_in_process_api(
                routes,
                &ApiImportSource {
                    adapter,
                    connector_instance_id: job.connector_instance_id,
                    source_lineage_id: &source_lineage_id,
                    checkpoint: &checkpoint,
                    input: &input,
                    expected_canonical_digest: &expected_canonical_digest,
                    cloud: cloud.as_ref(),
                    casb_account_id: casb_account_id.as_deref(),
                },
            )
            .await;
            drop(input);
            let Ok(receipt) = result else {
                record_job_failure(&state.postgres, job, started_at, "connector_commit_failed")
                    .await?;
                return Ok(Err("connector_commit_failed"));
            };
            if receipt.canonical_digest.len() != 64
                || receipt.content_retained
                || descriptor.connector_type != job.connector_type
            {
                record_job_failure(
                    &state.postgres,
                    job,
                    started_at,
                    "connector_receipt_invalid",
                )
                .await?;
                return Ok(Err("connector_receipt_invalid"));
            }
            if let Ok(status) = parse_run_status(&receipt.status) {
                Ok(Ok(status))
            } else {
                record_job_failure(
                    &state.postgres,
                    job,
                    started_at,
                    "connector_receipt_invalid",
                )
                .await?;
                Ok(Err("connector_receipt_invalid"))
            }
        }
        PreparedJob::EmptyPoll {
            descriptor,
            cursor_before,
            cursor_after,
        } => {
            record_empty_poll(
                &state.postgres,
                job,
                started_at,
                descriptor,
                cursor_before,
                cursor_after,
            )
            .await?;
            Ok(Ok(ConnectorRunStatus::Completed))
        }
    }
}

async fn commit_through_in_process_api(
    routes: &Router,
    source: &ApiImportSource<'_>,
) -> Result<CommitReceipt> {
    ensure!(
        safe_lineage_id(source.source_lineage_id),
        "unsafe source lineage ID"
    );
    let data = std::str::from_utf8(source.input).context("connector source must be UTF-8")?;
    let preview_request = ApiImportPreviewRequest {
        adapter: source.adapter.key(),
        connector_instance_id: source.connector_instance_id,
        source_lineage_id: source.source_lineage_id,
        checkpoint: source.checkpoint,
        observed_at: source.cloud.map(|cloud| cloud.observed_at),
        cloud_scope: source.cloud.map(CloudImportSource::api_scope),
        casb_account_id: source.casb_account_id,
        data,
    };
    let preview_response =
        in_process_json(routes, "/api/v1/tally/imports/preview", &preview_request).await?;
    ensure!(
        preview_response.status() == StatusCode::OK,
        "the in-process Tally preview rejected the connector batch"
    );
    let preview_body = axum::body::to_bytes(preview_response.into_body(), MAX_IMPORT_BYTES * 2)
        .await
        .context("read in-process Tally preview")?;
    let preview: ApiImportPreviewResponse =
        serde_json::from_slice(&preview_body).context("decode in-process Tally preview")?;
    ensure!(
        !preview.writes_data && !preview.source_bytes_retained && !preview.content_retained,
        "the in-process Tally preview violated the privacy contract"
    );
    ensure!(
        preview.canonical_digest == source.expected_canonical_digest,
        "the in-process Tally preview did not match the connector normalization"
    );

    let commit_request = ApiImportCommitRequest {
        preview: preview_request,
        confirm_canonical_digest: &preview.canonical_digest,
    };
    let commit_response = in_process_json(routes, "/api/v1/tally/imports", &commit_request).await?;
    ensure!(
        commit_response.status() == StatusCode::OK,
        "the in-process Tally API rejected the preview-bound commit"
    );
    let commit_body = axum::body::to_bytes(commit_response.into_body(), 1024 * 1024)
        .await
        .context("read in-process Tally commit receipt")?;
    let receipt: CommitReceipt =
        serde_json::from_slice(&commit_body).context("decode in-process Tally commit receipt")?;
    ensure!(
        receipt.canonical_digest == preview.canonical_digest && !receipt.content_retained,
        "the in-process Tally receipt violated the preview or privacy contract"
    );
    Ok(receipt)
}

async fn in_process_json<T: Serialize>(
    routes: &Router,
    uri: &'static str,
    value: &T,
) -> Result<axum::response::Response> {
    use tower::ServiceExt as _;

    let body = serde_json::to_vec(value).context("encode in-process Tally request")?;
    routes
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method(axum::http::Method::POST)
                .uri(uri)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body))
                .context("build in-process Tally request")?,
        )
        .await
        .context("dispatch in-process Tally request")
}

// Keep the standalone implementation as the single source for provider pulls and normalization.
// Rust item order is irrelevant, and placing the include last keeps its test module last as well.
include!("main.rs");
