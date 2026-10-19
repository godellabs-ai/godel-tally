//! Host-local Tally-to-Gate upgrade execution and reviewed maintenance actions.
mod config;
mod origin;
pub use config::setting;
mod runner;
mod upgrade;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

type App = Arc<AppState>;
struct AppState {
    http: reqwest::Client,
    gate: PathBuf,
    dir: PathBuf,
    pair_code: String,
    sessions: Mutex<HashMap<String, Session>>,
    pair_attempts: AtomicUsize,
    execution_busy: AtomicBool,
    legacy_deployment: bool,
    host_upgrade_supported: bool,
}
struct Session {
    id: String,
    created: DateTime<Utc>,
    workspace: bool,
    plans: BTreeMap<String, runner::Plan>,
    cancels: HashMap<String, Arc<AtomicBool>>,
}
impl Session {
    fn valid(&self) -> bool {
        self.workspace || Utc::now() - self.created < chrono::Duration::hours(8)
    }
}

#[derive(Debug)]
struct ApiError(StatusCode, String);
impl ApiError {
    fn bad_request(s: &str) -> Self {
        Self(StatusCode::BAD_REQUEST, s.into())
    }
    fn conflict(s: &str) -> Self {
        Self(StatusCode::CONFLICT, s.into())
    }
    fn bad_gateway(s: &str) -> Self {
        Self(StatusCode::BAD_GATEWAY, s.into())
    }
    fn unauthorized() -> Self {
        Self(
            StatusCode::UNAUTHORIZED,
            "Reconnect to the local upgrade service.".into(),
        )
    }
    fn internal() -> Self {
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The local service could not complete this operation.".into(),
        )
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1}))).into_response()
    }
}
pub fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).expect("OS randomness");
    hex::encode(bytes)
}
fn secret_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}
fn token(headers: &HeaderMap) -> Result<String, ApiError> {
    headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .filter(|s| s.len() == 64)
        .map(str::to_owned)
        .ok_or_else(ApiError::unauthorized)
}
fn session<'a>(
    sessions: &'a mut HashMap<String, Session>,
    token: &str,
) -> Result<&'a mut Session, ApiError> {
    sessions
        .get_mut(token)
        .filter(|s| s.valid())
        .ok_or_else(ApiError::unauthorized)
}

pub async fn prepare() -> anyhow::Result<HostService> {
    prepare_runtime(false).await
}

async fn prepare_runtime(legacy_deployment: bool) -> anyhow::Result<HostService> {
    let dir = config::state_dir();
    let dir = std::env::current_dir()?.join(dir);
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let pair_code = random_token();
    let pair_path = dir.join("pairing-code");
    std::fs::write(&pair_path, &pair_code)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pair_path, std::fs::Permissions::from_mode(0o600))?;
    }
    let gate =
        PathBuf::from(setting("GATE_PATH").unwrap_or_else(|_| {
            format!("{}/godel-gate", std::env::var("HOME").unwrap_or_default())
        }));
    let app = Arc::new(AppState {
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(100))
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()?,
        gate,
        dir,
        pair_code,
        sessions: Mutex::new(HashMap::new()),
        pair_attempts: AtomicUsize::new(0),
        execution_busy: AtomicBool::new(false),
        legacy_deployment,
        host_upgrade_supported: setting("HOST_REQUIRED").as_deref() != Ok("1"),
    });
    let workspace_token = random_token();
    app.sessions.lock().await.insert(
        workspace_token.clone(),
        Session {
            id: random_token(),
            created: Utc::now(),
            workspace: true,
            plans: BTreeMap::new(),
            cancels: HashMap::new(),
        },
    );
    Ok(HostService {
        router: routes(app),
        workspace_token,
    })
}

/// Private host routes and an in-process workspace credential. Never expose these routes directly.
pub struct HostService {
    pub router: Router,
    pub workspace_token: String,
}

pub async fn run() -> anyhow::Result<()> {
    let service = prepare_runtime(true).await?;
    let bind = setting("BIND").unwrap_or_else(|_| "127.0.0.1:8789".into());
    let addr: std::net::SocketAddr = bind.parse()?;
    let docker_bridge = setting("DOCKER_BRIDGE_BIND").ok();
    anyhow::ensure!(
        addr.ip().is_loopback() || docker_bridge.as_deref() == Some(bind.as_str()),
        "The upgrade service must bind to loopback or the configured Docker bridge"
    );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, service.router).await?;
    Ok(())
}

fn routes(app: App) -> Router {
    Router::new()
        .route(
            "/health",
            get(|| async {
                Json(json!({"status":"ready","service":"tally_upgrade","version":"0.1.0"}))
            }),
        )
        .route("/pair", post(pair))
        .route("/actions", get(actions))
        .route("/actions/preview", post(preview_action))
        .route("/actions/{id}/execute", post(execute_action))
        .route("/actions/{id}/cancel", post(cancel_action))
        .route("/upgrade", get(upgrade::status))
        .route("/upgrade/preview", post(upgrade::preview))
        .route("/upgrade/prepare", post(upgrade::prepare))
        .route("/upgrade/cutover", post(upgrade::cutover))
        .route("/upgrade/cancel", post(upgrade::cancel))
        .route("/upgrade/reset", post(upgrade::reset))
        .route("/upgrade/cleanup", post(upgrade::cleanup))
        .layer(axum::middleware::from_fn(boundary))
        .with_state(app)
}
async fn boundary(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let allowed_host = host.starts_with("127.0.0.1:")
        || host.starts_with("localhost:")
        || host.starts_with("[::1]:")
        || setting("DOCKER_PROXY_HOST").is_ok_and(|trusted| trusted == host);
    if !allowed_host {
        return ApiError(StatusCode::FORBIDDEN, "Local host required.".into()).into_response();
    }
    if let Some(origin) = req.headers().get("origin").and_then(|v| v.to_str().ok()) {
        let allowed = setting("WEB_ORIGIN").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
        if !origin::web_origins(&allowed)
            .is_ok_and(|origins| origins.iter().any(|trusted| trusted == origin))
        {
            return ApiError(StatusCode::FORBIDDEN, "Untrusted browser origin.".into())
                .into_response();
        }
    }
    let mut response = next.run(req).await;
    response.headers_mut().insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairInput {
    code: String,
    #[serde(default)]
    workspace: bool,
}
async fn pair(
    State(app): State<App>,
    Json(input): Json<PairInput>,
) -> Result<Json<Value>, ApiError> {
    if !secret_eq(&input.code, &app.pair_code) {
        if app.pair_attempts.fetch_add(1, Ordering::Relaxed) > 20 {
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many pairing attempts. Restart the local service to reset pairing.".into(),
            ));
        }
        return Err(ApiError::unauthorized());
    }
    let mut sessions = app.sessions.lock().await;
    // Only the local console's server can bootstrap this shared workspace: it
    // must supply the private pairing secret, which never reaches the browser.
    if input.workspace
        && let Some((token, s)) = sessions.iter().find(|(_, s)| s.workspace)
    {
        return Ok(Json(
            json!({"token":token,"session_id":s.id,"workspace":true,"expires_in_seconds":null}),
        ));
    }
    sessions.retain(|_, s| s.valid());
    if sessions.len() >= 8 {
        return Err(ApiError::conflict(
            "Too many sessions. End an existing upgrade session first.",
        ));
    }
    let token = random_token();
    let id = random_token();
    let plans = std::fs::read_dir(&app.dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name().to_string_lossy().starts_with("action-")
                && e.path().extension().is_some_and(|x| x == "json")
        })
        .filter_map(|e| std::fs::read(e.path()).ok())
        .filter_map(|b| serde_json::from_slice::<runner::Plan>(&b).ok())
        .map(|mut p| {
            if p.status == "running" {
                p.status = "uncertain".into();
                p.output
                    .push_str("\nService restarted. Reconcile actual state before retrying.");
            }
            (p.id.clone(), p)
        })
        .collect();
    sessions.insert(
        token.clone(),
        Session {
            id: id.clone(),
            created: Utc::now(),
            workspace: input.workspace,
            plans,
            cancels: HashMap::new(),
        },
    );
    Ok(Json(
        json!({"token":token,"session_id":id,"workspace":input.workspace,
            "expires_in_seconds":if input.workspace {None} else {Some(28800)}}),
    ))
}
async fn actions(State(app): State<App>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let token = token(&headers)?;
    let mut sessions = app.sessions.lock().await;
    let s = session(&mut sessions, &token)?;
    Ok(Json(
        json!({"catalog":runner::catalog(&app.gate),"plans":s.plans.values().collect::<Vec<_>>(),"execution_busy":app.execution_busy.load(Ordering::SeqCst)}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewInput {
    action_id: String,
}
async fn preview_action(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<PreviewInput>,
) -> Result<Json<Value>, ApiError> {
    let token = token(&headers)?;
    {
        session(&mut *app.sessions.lock().await, &token)?;
    }
    let plan = runner::preview(&app.gate, &input.action_id)?;
    let value = json!(plan);
    session(&mut *app.sessions.lock().await, &token)?
        .plans
        .insert(plan.id.clone(), plan);
    Ok(Json(value))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecuteInput {
    digest: String,
    approved: bool,
}
async fn execute_action(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<ExecuteInput>,
) -> Result<Json<Value>, ApiError> {
    let token = token(&headers)?;
    if !input.approved {
        return Err(ApiError::bad_request(
            "Explicit action approval is required.",
        ));
    }
    let mut sessions = app.sessions.lock().await;
    let s = session(&mut sessions, &token)?;
    let plan = s
        .plans
        .get_mut(&id)
        .ok_or_else(|| ApiError::bad_request("Unknown reviewed action."))?;
    runner::validate(plan, &input.digest, &app.gate)?;
    if app
        .execution_busy
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(ApiError::conflict(
            "Another local action is running. Wait or cancel it first.",
        ));
    }
    plan.status = "running".into();
    if let Err(e) = runner::journal(&app.dir, plan) {
        plan.status = "awaiting_approval".into();
        app.execution_busy.store(false, Ordering::SeqCst);
        return Err(e);
    }
    let plan = plan.clone();
    let cancel = Arc::new(AtomicBool::new(false));
    s.cancels.insert(id.clone(), cancel.clone());
    drop(sessions);
    let task_app = app.clone();
    tokio::spawn(async move {
        let (status, code, output) = runner::execute(&plan, cancel).await;
        let mut final_plan = plan;
        final_plan.status = status;
        final_plan.exit_code = code;
        final_plan.output = output;
        final_plan.completed_at = Some(Utc::now());
        if runner::journal(&task_app.dir, &final_plan).is_err() {
            final_plan.status = "uncertain".into();
            final_plan
                .output
                .push_str("\nCould not persist final receipt. Verify actual state.");
        }
        let mut sessions = task_app.sessions.lock().await;
        if let Some(s) = sessions.get_mut(&token) {
            s.cancels.remove(&final_plan.id);
            s.plans.insert(final_plan.id.clone(), final_plan);
        }
        task_app.execution_busy.store(false, Ordering::SeqCst);
    });
    Ok(Json(json!({"id":id,"status":"running"})))
}
async fn cancel_action(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let token = token(&headers)?;
    let mut sessions = app.sessions.lock().await;
    let s = session(&mut sessions, &token)?;
    if let Some(cancel) = s.cancels.get(&id) {
        cancel.store(true, Ordering::SeqCst);
    } else if let Some(plan) = s.plans.get_mut(&id)
        && plan.status == "awaiting_approval"
    {
        plan.status = "cancelled".into();
    }
    Ok(Json(
        json!({"cancellation_requested":true,"rollback_performed":false}),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    fn app() -> App {
        Arc::new(AppState {
            http: reqwest::Client::new(),
            gate: PathBuf::from("/tmp/upgrade-test-missing-gate"),
            dir: PathBuf::from("/tmp/upgrade-test-missing-state"),
            pair_code: "test".into(),
            sessions: Mutex::new(HashMap::new()),
            pair_attempts: AtomicUsize::new(0),
            execution_busy: AtomicBool::new(false),
            legacy_deployment: true,
            host_upgrade_supported: true,
        })
    }
    async fn send(app: App, request: axum::http::Request<axum::body::Body>) -> (StatusCode, Value) {
        let response = routes(app).oneshot(request).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }
    #[tokio::test]
    async fn container_runtime_requires_host_for_docker_upgrade() {
        let mut app = app();
        Arc::get_mut(&mut app).unwrap().host_upgrade_supported = false;
        let bearer = "a".repeat(64);
        app.sessions.lock().await.insert(
            bearer.clone(),
            Session {
                id: "fixture".into(),
                created: Utc::now(),
                workspace: true,
                plans: BTreeMap::new(),
                cancels: HashMap::new(),
            },
        );
        let (status, _) = send(
            app,
            axum::http::Request::builder()
                .method("POST")
                .uri("/upgrade/reset")
                .header("host", "127.0.0.1:8789")
                .header("authorization", format!("Bearer {bearer}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn combined_host_supports_docker_gate_upgrade() {
        let mut app = app();
        Arc::get_mut(&mut app).unwrap().legacy_deployment = false;
        let bearer = "a".repeat(64);
        app.sessions.lock().await.insert(
            bearer.clone(),
            Session {
                id: "fixture".into(),
                created: Utc::now(),
                workspace: true,
                plans: BTreeMap::new(),
                cancels: HashMap::new(),
            },
        );
        let (code, body) = send(
            app,
            axum::http::Request::builder()
                .uri("/upgrade")
                .header("host", "127.0.0.1:8789")
                .header("authorization", format!("Bearer {bearer}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["status"], "not_started");
        assert_eq!(body["available"], true);
    }

    #[test]
    fn pairing_comparison_is_exact() {
        assert!(secret_eq("a", "a"));
        assert!(!secret_eq("a", "b"));
        assert!(!secret_eq("a", "aa"));
    }
    #[test]
    fn bearer_auth_is_required() {
        assert!(token(&HeaderMap::new()).is_err());
    }
    #[tokio::test]
    async fn untrusted_origin_cannot_pair() {
        let (status, _) = send(
            app(),
            axum::http::Request::builder()
                .method("POST")
                .uri("/pair")
                .header("host", "127.0.0.1:8789")
                .header("origin", "https://attacker.example")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"code":"test"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
}
