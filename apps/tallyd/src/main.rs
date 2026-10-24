use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::Request,
    http::{HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tally_config::{LogFormat, SecretCipher, TallyConfig};
use tally_store_postgres::PostgresStore;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod auth;
#[cfg(test)]
mod auth_integration;
mod container;
mod email;
mod gate_rekey;
mod host;
mod runtime_control;
mod supervisor;
mod throttle;
mod ui;

fn main() -> Result<()> {
    // Outbound SDKs enable multiple rustls providers; select one explicitly for TLS serving.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let args: Vec<_> = std::env::args().skip(1).collect();
    // Drop container privileges before creating any runtime threads, then re-exec as PID 1.
    if args.first().is_some_and(|arg| arg == "container") {
        anyhow::ensure!(args.len() == 1, "container takes no arguments");
        return container::run();
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main(args))
}

async fn async_main(args: Vec<String>) -> Result<()> {
    if args.first().is_some_and(|arg| arg == "--version") {
        println!("tallyd {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "--help") {
        println!(
            "tallyd [--version | --check-ui | container | healthcheck | supervise | check-tls-host CERT HOST | collector <command> | rekey-for-gate]\nRun Tally API, UI, connector worker and Gate upgrades. Configuration: TALLY_* environment variables."
        );
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "--check-ui") {
        anyhow::ensure!(
            cfg!(feature = "embedded-ui"),
            "UI is not embedded; run make build"
        );
        println!("embedded UI is available");
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "rekey-for-gate") {
        return gate_rekey::run().await;
    }
    if args.first().is_some_and(|arg| arg == "healthcheck") {
        anyhow::ensure!(args.len() == 1, "healthcheck takes no arguments");
        return container::healthcheck().await;
    }
    if args.first().is_some_and(|arg| arg == "check-tls-host") {
        use rustls::pki_types::pem::PemObject;
        anyhow::ensure!(args.len() == 3, "usage: tallyd check-tls-host CERT HOST");
        let certificate = rustls::pki_types::CertificateDer::from_pem_file(&args[1])?;
        let name = rustls::pki_types::ServerName::try_from(args[2].clone())?;
        webpki::EndEntityCert::try_from(&certificate)?.verify_is_valid_for_subject_name(&name)?;
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "check-stopped") {
        anyhow::ensure!(args.len() == 2, "usage: tallyd check-stopped DATA_DIR");
        return supervisor::check_stopped(std::path::Path::new(&args[1]));
    }
    if runtime_control::marker("retired").is_file() {
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "supervise") {
        anyhow::ensure!(args.len() == 1, "supervise takes no arguments");
        return supervisor::run().await;
    }
    if args.first().is_some_and(|arg| arg == "collector") {
        return tally_collector::run_cli(
            std::iter::once("tally-collector".to_owned()).chain(args.into_iter().skip(1)),
        )
        .await;
    }
    anyhow::ensure!(args.is_empty(), "unknown argument; use --help");
    let config = TallyConfig::from_env().context("load Tally configuration")?;
    init_tracing(&config)?;

    run(config).await
}

async fn run(config: TallyConfig) -> Result<()> {
    let _ = tokio::fs::remove_file(runtime_control::marker("writers-drained")).await;
    info!(
        version = env!("CARGO_PKG_VERSION"),
        "starting Tally; connecting to PostgreSQL"
    );
    let postgres = Arc::new(
        PostgresStore::connect(config.postgres_url.expose())
            .await
            .context("connect to PostgreSQL")?,
    );
    info!("applying PostgreSQL migrations");
    postgres.migrate().await.context("migrate PostgreSQL")?;
    let recovered_scans = postgres
        .recover_interrupted_scans()
        .await
        .context("recover interrupted scan jobs")?;
    if recovered_scans > 0 {
        info!(recovered_scans, "marked interrupted scan jobs failed");
    }

    let secret_cipher = SecretCipher::from_env().context("load TALLY_SECRET_KEY")?;
    info!("loading Tally registry and runtime");
    let state = tally_api::state_from_store(postgres.clone(), secret_cipher.clone())
        .await
        .context("initialize Tally runtime")?;
    info!("connecting to ClickHouse and applying migrations");
    let state = tally_api::with_clickhouse(
        state,
        &clickhouse_url(
            &std::env::var("TALLY_CLICKHOUSE_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8124?user=tally&password=tally-local".into()),
            std::env::var("TALLY_CLICKHOUSE_PASSWORD")
                .ok()
                .filter(|value| !value.is_empty())
                .as_deref(),
        )?,
        &std::env::var("TALLY_CLICKHOUSE_DATABASE").unwrap_or_else(|_| "tally".into()),
        std::env::var("TALLY_AI_LOG_RETENTION_DAYS")
            .unwrap_or_else(|_| "90".into())
            .parse()
            .context("invalid AI log retention")?,
        true,
    )
    .await
    .context("initialize Tally AI log storage")?;

    info!("initializing authentication and upgrade services");
    let auth_state = init_auth(config.postgres_url.expose(), secret_cipher).await?;
    let host_service = tally_upgrade::prepare()
        .await
        .context("initialize upgrade host runtime")?;
    let host_bind: std::net::SocketAddr = tally_upgrade::setting("BIND")
        .unwrap_or_else(|_| "127.0.0.1:8789".into())
        .parse()?;
    anyhow::ensure!(
        host_bind.ip().is_loopback(),
        "Upgrade service listener must use loopback"
    );
    let host_listener = TcpListener::bind(host_bind)
        .await
        .context("bind Upgrade service listener")?;
    let host_routes = host::router(auth_state.clone(), &host_service);
    let collector_state = state.clone();
    let app = tally_api::router(state)
        .layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            auth::require_session,
        ))
        .layer(axum::middleware::from_fn(block_tally_writes_during_upgrade))
        .merge(
            auth::router(auth_state.clone())
                .layer(axum::middleware::from_fn(block_auth_changes_during_upgrade)),
        )
        .merge(host_routes)
        .fallback_service(ui::router(auth_state))
        .layer(tower_http::compression::CompressionLayer::new());
    let app = public_origin(app, config.http_bind)?;
    run_services(
        config,
        app,
        host_listener,
        host_service.router,
        collector_state,
    )
    .await
}

async fn init_auth(
    postgres_url: &str,
    secret_cipher: SecretCipher,
) -> Result<Arc<auth::AuthState>> {
    let auth_pool = sqlx::PgPool::connect(postgres_url)
        .await
        .context("connect standalone authentication database")?;
    let mut auth_migrator = sqlx::migrate!("./migrations");
    auth_migrator.dangerous_set_table_name("tally_auth_migrations");
    auth_migrator
        .run(&auth_pool)
        .await
        .context("migrate standalone authentication tables")?;
    Ok(Arc::new(auth::AuthState {
        pool: auth_pool,
        collector_import_token: secret_cipher.collector_import_token(),
        cipher: secret_cipher,
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("create email HTTP client")?,
        throttle: Arc::default(),
    }))
}

fn public_origin(app: Router, bind: std::net::SocketAddr) -> Result<Router> {
    // A direct public listener must not trust browser-supplied forwarded headers.
    // The configured public origin also works through the development proxy or a TLS ingress.
    let public_url = std::env::var("TALLY_URL").unwrap_or_else(|_| format!("http://{bind}"));
    public_origin_at(app, &public_url)
}

fn public_origin_at(app: Router, public_url: &str) -> Result<Router> {
    let public = url::Url::parse(public_url).context("invalid TALLY_URL")?;
    anyhow::ensure!(
        matches!(public.scheme(), "http" | "https")
            && public.origin().ascii_serialization() == public_url,
        "TALLY_URL must be an HTTP(S) origin without a path"
    );
    let public_host =
        HeaderValue::from_str(&public[url::Position::BeforeHost..url::Position::AfterPort])?;
    let public_proto = HeaderValue::from_str(public.scheme())?;
    // HSTS would pin every service on a shared name such as localhost to HTTPS, so it is
    // only sent for a real host name served over HTTPS.
    let hsts = public.scheme() == "https"
        && public.domain().is_some_and(|host| {
            !host.eq_ignore_ascii_case("localhost") && !host.ends_with(".localhost")
        });
    Ok(app
        .layer(axum::middleware::from_fn(
            move |request: Request, next: Next| async move {
                let mut response = next.run(request).await;
                add_security_headers(response.headers_mut(), hsts);
                response
            },
        ))
        .layer(axum::middleware::from_fn(
            move |mut request: Request, next: Next| {
                request
                    .headers_mut()
                    .insert("x-forwarded-host", public_host.clone());
                request
                    .headers_mut()
                    .insert("x-forwarded-proto", public_proto.clone());
                async move { next.run(request).await }
            },
        )))
}

/// The console is a static export served from this origin. Next.js inlines its bootstrap
/// scripts and React sets inline styles, so those need 'unsafe-inline'; everything else is
/// limited to this origin and the console can never be framed.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self' 'unsafe-inline'; \
    style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; \
    connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; \
    frame-ancestors 'none'";

fn add_security_headers(headers: &mut axum::http::HeaderMap, hsts: bool) {
    let defaults = [
        ("content-security-policy", CONTENT_SECURITY_POLICY),
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        ),
        ("cross-origin-opener-policy", "same-origin"),
    ];
    for (name, value) in defaults {
        if !headers.contains_key(name) {
            headers.insert(name, HeaderValue::from_static(value));
        }
    }
    if hsts && !headers.contains_key("strict-transport-security") {
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000"),
        );
    }
}

async fn run_services(
    config: TallyConfig,
    app: Router,
    host_listener: TcpListener,
    host_router: Router,
    collector_state: tally_api::AppState,
) -> Result<()> {
    let collector = async move {
        let owner = uuid::Uuid::now_v7();
        loop {
            if upgrade_read_only() {
                if runtime_control::writes_drained() {
                    tokio::fs::write(runtime_control::marker("writers-drained"), b"ready").await?;
                }
            } else {
                let _ = tokio::fs::remove_file(runtime_control::marker("writers-drained")).await;
                tally_collector::run_due_connector_jobs(&collector_state, owner, 300)
                    .await
                    .context("run connector jobs")?;
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        result = runtime_control::serve(config.http_bind, app) => result?,
        result = axum::serve(host_listener, host_router) => { result.context("serve upgrade host runtime")?; },
        result = collector => result?,
    }

    Ok(())
}

// Compose supplies the password separately so reserved URL characters remain valid credentials.
fn clickhouse_url(endpoint: &str, password: Option<&str>) -> Result<String> {
    let mut endpoint = url::Url::parse(endpoint).context("invalid ClickHouse URL")?;
    if let Some(password) = password {
        let pairs = endpoint
            .query_pairs()
            .filter(|(k, _)| k != "password")
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect::<Vec<_>>();
        endpoint
            .set_password(None)
            .map_err(|()| anyhow::anyhow!("invalid ClickHouse URL"))?;
        endpoint.set_query(None);
        endpoint
            .query_pairs_mut()
            .extend_pairs(pairs)
            .append_pair("password", password);
    }
    Ok(endpoint.into())
}

fn upgrade_read_only() -> bool {
    runtime_control::marker("read-only").is_file()
}

fn upgrade_paused_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"error":"Tally is read-only while Gate is staged. Complete or cancel the upgrade on the Upgrade page."})),
    ).into_response()
}

async fn block_tally_writes_during_upgrade(request: Request, next: Next) -> Response {
    let _write = (!tally_request_is_read_only(request.method(), request.uri().path()))
        .then(runtime_control::WriteGuard::new);
    let read_only = upgrade_read_only();
    if read_only && !tally_request_is_read_only(request.method(), request.uri().path()) {
        return upgrade_paused_response();
    }
    let mut response = next.run(request).await;
    if read_only {
        response.headers_mut().insert(
            "x-tally-upgrade-read-only",
            HeaderValue::from_static("true"),
        );
    }
    response
}

fn tally_request_is_read_only(method: &Method, path: &str) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
        || (*method == Method::POST && path == "/api/v1/tally/estate/activity/query")
}

async fn block_auth_changes_during_upgrade(request: Request, next: Next) -> Response {
    let _write = runtime_control::WriteGuard::new();
    if upgrade_read_only()
        && !matches!(
            *request.method(),
            Method::GET | Method::HEAD | Method::OPTIONS
        )
        && !matches!(
            request.uri().path(),
            "/api/v1/auth/login" | "/api/v1/auth/logout"
        )
    {
        return upgrade_paused_response();
    }
    next.run(request).await
}

fn init_tracing(config: &TallyConfig) -> Result<()> {
    let filter = EnvFilter::try_new(&config.log_filter).context("parse TALLY_LOG")?;
    match config.log_format {
        LogFormat::Pretty => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .try_init()
            .map_err(|error| anyhow::anyhow!("initialize tracing: {error}"))?,
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .try_init()
            .map_err(|error| anyhow::anyhow!("initialize tracing: {error}"))?,
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => (), _ = term.recv() => () }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    pub(crate) fn auth_state() -> std::sync::Arc<super::auth::AuthState> {
        let cipher = tally_config::SecretCipher::from_bytes([7; 32]);
        std::sync::Arc::new(super::auth::AuthState {
            pool: sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://localhost/unused")
                .unwrap(),
            collector_import_token: cipher.collector_import_token(),
            cipher,
            http: reqwest::Client::new(),
            throttle: std::sync::Arc::default(),
        })
    }

    #[tokio::test]
    async fn public_listener_ignores_forged_forwarding_headers() {
        use axum::{Router, body::Body, http::Request, routing::post};
        use tower::ServiceExt;
        let app = Router::new()
            .route("/mutation", post(|| async { "ok" }))
            .layer(axum::middleware::from_fn(super::auth::require_origin));
        let app = super::public_origin_at(app, "https://tally.example:8443").unwrap();
        for (origin, expected) in [
            ("https://attacker.example", 403),
            ("https://tally.example:8443", 200),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mutation")
                        .header("host", "tally.example:8443")
                        .header("origin", origin)
                        .header("x-forwarded-host", "attacker.example")
                        .header("x-forwarded-proto", "https")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), expected);
        }
    }

    #[test]
    fn estate_activity_remains_readable_during_upgrade_without_allowing_writes() {
        use axum::http::Method;
        assert!(super::tally_request_is_read_only(
            &Method::POST,
            "/api/v1/tally/estate/activity/query"
        ));
        for path in [
            "/api/v1/tally/registry/estate-reviews",
            "/api/v1/tally/connectors/schedules",
            "/api/v1/tally/estate/activity/query/extra",
        ] {
            assert!(!super::tally_request_is_read_only(&Method::POST, path));
        }
        assert!(!super::tally_request_is_read_only(
            &Method::DELETE,
            "/api/v1/tally/estate/activity/query"
        ));
    }

    #[test]
    fn clickhouse_password_is_encoded_as_a_single_credential() {
        let endpoint = super::clickhouse_url(
            "http://localhost:8124?user=tally&password=old",
            Some("a&b#c?d%+"),
        )
        .unwrap();
        let url = url::Url::parse(&endpoint).unwrap();
        let pairs = url.query_pairs().collect::<Vec<_>>();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[1].1, "a&b#c?d%+");
    }

    #[test]
    fn embedded_registry_passes_digest_and_invariant_verification() {
        let (bundle, manifest) =
            tally_api::embedded_registry().expect("verified embedded registry");
        assert_eq!(bundle.version, "2026.10.1");
        assert_eq!(bundle.entries.len(), manifest.entry_count);
        assert_eq!(bundle.fingerprints.len(), manifest.fingerprint_count);
        assert_eq!(
            bundle
                .entries
                .iter()
                .map(|entry| entry.matchers.len())
                .sum::<usize>(),
            manifest.matcher_count
        );
    }
}
