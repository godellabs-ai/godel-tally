//! Fixed, host-local Tally-to-Gate workflow. Registration secrets stay on this host.
use std::{
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::Ordering,
};

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::process::Command;

use crate::{ApiError, App, runner, session, token};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeInput {
    final_url: String,
    gate_dir: String,
    registration_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareInput {
    #[serde(flatten)]
    config: UpgradeInput,
    version: String,
    installer_sha256: String,
    digest: String,
    approved: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CutoverInput {
    final_url: String,
    tls_cert: String,
    tls_key: String,
    approved: bool,
}

#[derive(Deserialize)]
struct Latest {
    version: String,
    installer_sha256: String,
}

const HOST_UPGRADE_REQUIRED: &str = "Gate requires Docker on the host. For a fully containerized Tally installation, run the packaged upgrade workflow on that host with TALLY_RUNTIME_MODE=combined-compose; the application container does not control the Docker socket.";

fn require_host_upgrade(app: &App) -> Result<(), ApiError> {
    if !app.host_upgrade_supported {
        return Err(ApiError(
            StatusCode::NOT_IMPLEMENTED,
            HOST_UPGRADE_REQUIRED.into(),
        ));
    }
    Ok(())
}

async fn check_gate_host() -> Result<(), ApiError> {
    for args in [vec!["info"], vec!["compose", "version"]] {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            Command::new("docker")
                .args(args)
                .kill_on_drop(true)
                .output(),
        )
        .await;
        if !matches!(result, Ok(Ok(output)) if output.status.success()) {
            return Err(ApiError::bad_request(
                "Gate requires Docker and Docker Compose. Install and start Docker on the Tally host before reviewing this upgrade.",
            ));
        }
    }
    Ok(())
}

fn runtime_mode(app: &App) -> String {
    std::env::var("TALLY_RUNTIME_MODE").unwrap_or_else(|_| {
        if app.legacy_deployment {
            "legacy"
        } else {
            "combined"
        }
        .into()
    })
}

fn upgrade_command(app: &App) -> Command {
    let mut command = Command::new("bash");
    command
        .arg(root().join("scripts/upgrade-tally-to-gate.sh"))
        .env("TALLY_RUNTIME_MODE", runtime_mode(app))
        .env("TALLY_UPGRADE_TALLY_ROOT", root())
        .env("TALLY_UPGRADE_STATE_DIR", &app.dir)
        .current_dir(root());
    let maintenance = std::env::var_os("TALLY_MAINTENANCE_DIR").map_or_else(
        || {
            std::env::var_os("TALLY_DATA_DIR").map_or_else(
                || PathBuf::from(".local/tally-maintenance"),
                |dir| PathBuf::from(dir).join("maintenance"),
            )
        },
        PathBuf::from,
    );
    if let Ok(cwd) = std::env::current_dir() {
        command.env("TALLY_MAINTENANCE_DIR", cwd.join(maintenance));
    }
    if !app.legacy_deployment
        && let Ok(binary) = std::env::current_exe()
    {
        command.env("TALLY_BINARY", binary);
    }
    command
}

fn root() -> PathBuf {
    crate::setting("TALLY_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            if let Ok(binary) = std::env::current_exe()
                && let Some(dir) = binary.parent()
                && dir.join("scripts/upgrade-tally-to-gate.sh").is_file()
            {
                return dir.to_owned();
            }
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        })
}

fn job_dir(app: &App) -> PathBuf {
    app.dir.join("gate-upgrade")
}

fn tally_tls_path(env_name: &str) -> Option<String> {
    let configured = std::env::var(env_name).ok()?;
    let path = PathBuf::from(configured);
    let host_path = if path.is_absolute() {
        path
    } else {
        root().join(path)
    };
    host_path
        .is_file()
        .then(|| host_path.to_string_lossy().into_owned())
}

fn suggested_gate_dir() -> Option<String> {
    let tally_root = root().canonicalize().ok()?;
    Some(
        tally_root
            .parent()?
            .join("godel-gate")
            .to_string_lossy()
            .into_owned(),
    )
}

fn read_file(dir: &Path, name: &str) -> Option<String> {
    fs::read_to_string(dir.join(name))
        .ok()
        .map(|v| v.trim().to_owned())
}

fn log_tail(dir: &Path, name: &str, limit: u64) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = fs::File::open(dir.join(name)).ok()?;
    let length = file.metadata().ok()?.len();
    file.seek(SeekFrom::Start(length.saturating_sub(limit)))
        .ok()?;
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn progress_events(dir: &Path) -> Vec<Value> {
    log_tail(dir, "progress.log", 16_384)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let (at, message) = line.split_once('|')?;
            if at.len() != 20 || message.len() > 180 {
                return None;
            }
            Some(json!({"at": at, "message": message}))
        })
        .rev()
        .take(12)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

fn known_failure_reason(dir: &Path) -> Option<String> {
    if read_file(dir, "failure_code").as_deref() == Some("gate_migrations_before_tally") {
        return Some(
            "Gate migrations ran before the Tally database was imported. The staging order is fixed; retry can reuse the selected Gate directory."
                .to_owned(),
        );
    }
    if log_tail(dir, "prepare.log", 8192)
        .as_deref()
        .is_some_and(|tail| tail.contains("cannot decrypt connector job"))
    {
        return Some("Tally cannot decrypt a connector's stored credentials. Update that connector's credentials in Tally, then retry. No Gate cutover occurred.".to_owned());
    }
    if let Some(reason) = read_file(dir, "failure_reason") {
        return Some(reason);
    }
    use std::io::Read;
    let mut prefix = String::new();
    fs::File::open(dir.join("prepare.log"))
        .ok()?
        .take(256)
        .read_to_string(&mut prefix)
        .ok()?;
    prefix
        .lines()
        .any(|line| line == "ERROR: TLS certificate does not cover localhost")
        .then(|| "The previous attempt hit a LibreSSL hostname-check bug. The Tally certificate does cover localhost; this check is now fixed.".to_owned())
}

fn cutover_retryable(dir: &Path) -> bool {
    if read_file(dir, "status").as_deref() != Some("cutover_failed")
        || !dir.join("writers-paused").is_file()
        || dir.join("final_url").exists()
    {
        return false;
    }
    match read_file(dir, "cutover_stage").as_deref() {
        Some("preflight") => true,
        None => read_file(dir, "failure_reason")
            .is_some_and(|reason| reason.contains("row count differs")),
        _ => false,
    }
}

fn attempt_log(dir: &Path, status: &str) -> Option<Value> {
    let name = match status {
        "failed" => "prepare.log",
        "cutover_failed" => "cutover.log",
        _ => return None,
    };
    let path = dir.join(name);
    let content = runner::redact_output(&log_tail(dir, name, 32_768)?);
    if content.trim().is_empty() {
        return None;
    }
    Some(json!({
        "name": name,
        "content": content,
        "truncated": path.metadata().is_ok_and(|metadata| metadata.len() > 32_768),
    }))
}

fn retrying_failed_dir(app: &App, dir: &str) -> bool {
    let receipt = job_dir(app);
    read_file(&receipt, "status").as_deref() == Some("failed")
        && read_file(&receipt, "requested_gate_dir")
            .or_else(|| read_file(&receipt, "gate_dir"))
            .as_deref()
            == Some(dir)
}

fn final_console_url(value: &str) -> Result<url::Url, ApiError> {
    let url = url::Url::parse(value.trim())
        .map_err(|_| ApiError::bad_request("Use a valid HTTPS Gate Console URL."))?;
    if url.scheme() != "https"
        || url.host_str().is_none_or(|host| {
            !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        })
        || url.port() == Some(0)
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(ApiError::bad_request(
            "Gate's final URL must be an HTTPS hostname, with an optional port.",
        ));
    }
    Ok(url)
}

fn public_input(
    input: &UpgradeInput,
    retrying_same_dir: bool,
) -> Result<(String, String), ApiError> {
    let url = final_console_url(&input.final_url)?;
    let dir = Path::new(&input.gate_dir);
    if !dir.is_absolute() {
        return Err(ApiError::bad_request(
            "Enter an absolute Gate install directory path.",
        ));
    }
    if dir.exists()
        && (dir.is_file()
            || (!retrying_same_dir
                && fs::read_dir(dir)
                    .map_err(|_| ApiError::bad_request("Gate install directory is unreadable."))?
                    .next()
                    .is_some()))
    {
        return Err(ApiError::bad_request(
            "The Gate install directory must be fresh.",
        ));
    }
    // Gate's Console trims the pasted key and accepts it once it is at least 12 characters.
    let registration_key = input.registration_key.trim();
    if registration_key.len() < 12 || registration_key.len() > 256 {
        return Err(ApiError::bad_request(
            "Enter a valid product registration key.",
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| ApiError::bad_request("Gate hostname is missing."))?;
    let port = [8443, 9443, 10443, 11443, 12443]
        .into_iter()
        .find(|port| std::net::TcpListener::bind(("0.0.0.0", *port)).is_ok())
        .ok_or_else(|| ApiError::conflict("No Gate preview HTTPS port is available."))?;
    let temp = format!("https://{host}:{port}");
    Ok((url.origin().ascii_serialization(), temp))
}

fn digest(input: &UpgradeInput, version: &str, checksum: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"tally-gate-upgrade-v2\0");
    hasher.update(serde_json::to_vec(input).expect("upgrade input serializes"));
    hasher.update(version.as_bytes());
    hasher.update(checksum.as_bytes());
    hex::encode(hasher.finalize())
}

async fn check_source_credentials(app: &App) -> Result<(), ApiError> {
    let sql = "SELECT count(*) FROM connector_jobs WHERE secret_ciphertext IS NOT NULL AND last_error_code = 'connector_credentials_unsealable'";
    let mut command = if app.legacy_deployment {
        let mut command = Command::new("docker");
        command
            .arg("compose")
            .arg("-f")
            .arg(root().join("docker-compose.yml"))
            .args([
                "exec", "-T", "postgres", "psql", "-U", "tally", "-d", "tally", "-Atc", sql,
            ]);
        command
    } else {
        let mut command = Command::new("python3");
        command
            .arg(root().join("scripts/tally-source-db.py"))
            .args(["query", sql])
            .env("TALLY_RUNTIME_MODE", runtime_mode(app));
        command
    };
    let output = command.current_dir(root()).output().await
        .map_err(|_| ApiError::bad_gateway("Could not inspect Tally connector credential health. Check the PostgreSQL client tools on this host."))?;
    if !output.status.success() {
        return Err(ApiError::bad_gateway(
            "Could not inspect Tally connector credential health.",
        ));
    }
    let count = String::from_utf8(output.stdout)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .ok_or_else(|| ApiError::bad_gateway("Tally connector health response was invalid."))?;
    if count > 0 {
        return Err(ApiError::conflict(
            "Tally has connector credentials it cannot decrypt. Update the affected connector's credentials in Tally Connectors before retrying the Gate upgrade.",
        ));
    }
    Ok(())
}

fn registration_portal_url() -> String {
    crate::setting("REGISTRATION_API_URL")
        .unwrap_or_else(|_| "https://godel-gate.godel-labs.ai".into())
}

async fn validate_registration(
    client: &reqwest::Client,
    base: &str,
    key: &str,
) -> Result<Option<String>, ApiError> {
    // Require an active portal identity and a verifiable future key expiry before upgrading.
    // A successful identity check alone cannot establish the remaining license term.
    let key = key.trim();
    let url = format!("{}/api/v1/users/me", base.trim_end_matches('/'));
    let response = client
        .get(url)
        .header("x-godel-key", key)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|_| ApiError::bad_gateway("Could not reach the registration portal."))?;
    match response.status() {
        status if status.is_success() => {}
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            return Err(ApiError::bad_request(
                "Registration key is expired or deactivated. Upgrade is not possible. Contact support@godel-labs.ai to activate the key or extend the license.",
            ));
        }
        status => {
            return Err(ApiError::bad_gateway(&format!(
                "Registration portal could not validate the key (HTTP {status}).",
            )));
        }
    }
    let expiry_url = format!(
        "{}/api/v1/registration-keys/self",
        base.trim_end_matches('/')
    );
    let response = client
        .get(expiry_url)
        .header("x-godel-key", key)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|_| ApiError::bad_gateway("Could not verify registration key expiry."))?;
    if !response.status().is_success() {
        return Err(ApiError::bad_request(
            "Registration key is expired, deactivated, or unavailable. Upgrade is not possible. Contact support@godel-labs.ai to activate the key or extend the license.",
        ));
    }
    let body = response
        .json::<Value>()
        .await
        .map_err(|_| ApiError::bad_gateway("Invalid registration status response."))?;
    let expires_at = body
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok());
    let expiry = expires_at.filter(|at| at.with_timezone(&chrono::Utc) > chrono::Utc::now())
        .ok_or_else(|| ApiError::bad_request("Registration key expired or expiry could not be verified. Upgrade is not possible. Contact support@godel-labs.ai to extend the license."))?;
    let expires_at = Some(expiry.to_rfc3339());
    Ok(expires_at)
}

async fn latest(app: &App) -> Result<Latest, ApiError> {
    let base = crate::setting("GATE_DOWNLOAD_BASE")
        .unwrap_or_else(|_| "https://dl.godel-labs.ai/godel-gate/console".into());
    let response = app
        .http
        .get(format!(
            "{}/latest/manifest.json",
            base.trim_end_matches('/')
        ))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|_| ApiError::bad_gateway("Could not resolve the latest Gate release."))?;
    if !response.status().is_success() {
        return Err(ApiError::bad_gateway(
            "The latest Gate release is unavailable.",
        ));
    }
    let release: Latest = response
        .json()
        .await
        .map_err(|_| ApiError::bad_gateway("Latest Gate release manifest is invalid."))?;
    if release.version.split('.').count() != 3
        || !release
            .version
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'.')
        || release.installer_sha256.len() != 64
        || !release
            .installer_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err(ApiError::bad_gateway(
            "Latest Gate release manifest is invalid.",
        ));
    }
    Ok(release)
}

pub async fn status(State(app): State<App>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let bearer = token(&headers)?;
    session(&mut *app.sessions.lock().await, &bearer)?;
    let dir = job_dir(&app);
    let current_status = read_file(&dir, "status").unwrap_or_else(|| "not_started".into());
    Ok(Json(json!({
        "status": &current_status,
        "available": app.host_upgrade_supported,
        "requires_docker": true,
        "unavailable_reason": if app.host_upgrade_supported { None } else { Some(HOST_UPGRADE_REQUIRED) },
        "version": read_file(&dir, "version"),
        "temporary_url": read_file(&dir, "temp_url"),
        "final_url": read_file(&dir, "final_url"),
        "requested_final_url": read_file(&dir, "requested_final_url"),
        "requested_tls_cert": read_file(&dir, "requested_tls_cert").or_else(|| read_file(&dir, "tls_cert")),
        "requested_tls_key": read_file(&dir, "requested_tls_key").or_else(|| read_file(&dir, "tls_key")),
        "requested_gate_dir": read_file(&dir, "requested_gate_dir").or_else(|| read_file(&dir, "gate_dir")),
        "expires_at": read_file(&dir, "expires_at"),
        "verification": read_file(&dir, "verification.txt"),
        "migration_warning": read_file(&dir, "migration_warning"),
        "prepare_exit": read_file(&dir, "prepare-exit"),
        "cutover_exit": read_file(&dir, "cutover-exit"),
        "busy": app.execution_busy.load(Ordering::SeqCst),
        "failure_reason": known_failure_reason(&dir),
        "cutover_retryable": cutover_retryable(&dir),
        "cutover_stage": read_file(&dir, "cutover_stage"),
        "attempt_log": attempt_log(&dir, &current_status),
        "progress": progress_events(&dir),
        "suggested_tls_cert": tally_tls_path("TALLY_TLS_CERT_FILE"),
        "suggested_tls_key": tally_tls_path("TALLY_TLS_KEY_FILE"),
        "suggested_gate_dir": suggested_gate_dir(),
    })))
}

pub async fn preview(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<UpgradeInput>,
) -> Result<Json<Value>, ApiError> {
    let bearer = token(&headers)?;
    session(&mut *app.sessions.lock().await, &bearer)?;
    require_host_upgrade(&app)?;
    let (final_url, temporary_url) =
        public_input(&input, retrying_failed_dir(&app, &input.gate_dir))?;
    check_gate_host().await?;
    check_source_credentials(&app).await?;
    let expires_at = validate_registration(
        &app.http,
        &registration_portal_url(),
        &input.registration_key,
    )
    .await?;
    let release = latest(&app).await?;
    Ok(Json(json!({
        "final_url": final_url, "temporary_url": temporary_url,
        "version": release.version, "installer_sha256": release.installer_sha256,
        "expires_at": expires_at,
        "digest": digest(&input, &release.version, &release.installer_sha256),
        "effects": ["Use Docker to start Gate on an available preview HTTPS port with a self-signed certificate", "Pause Tally writers and save a database backup", "Copy Tally data, import Tally users, and re-encrypt connector credentials", "Open and explore Gate before entering production certificates or approving cutover"],
    })))
}

#[cfg(unix)]
fn write_private(path: &Path, value: &str) -> Result<(), ApiError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| ApiError::internal())?;
    file.write_all(value.as_bytes())
        .map_err(|_| ApiError::internal())
}

#[cfg(not(unix))]
fn write_private(_path: &Path, _value: &str) -> Result<(), ApiError> {
    Err(ApiError::bad_request(
        "Host-local Gate upgrade requires macOS or Linux.",
    ))
}

pub async fn prepare(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<PrepareInput>,
) -> Result<Json<Value>, ApiError> {
    let bearer = token(&headers)?;
    session(&mut *app.sessions.lock().await, &bearer)?;
    require_host_upgrade(&app)?;
    if !input.approved {
        return Err(ApiError::bad_request(
            "Review and approve the Gate installation first.",
        ));
    }
    let (_, temporary_url) = public_input(&input.config, false)?;
    check_gate_host().await?;
    check_source_credentials(&app).await?;
    if digest(&input.config, &input.version, &input.installer_sha256) != input.digest {
        return Err(ApiError::bad_request(
            "Upgrade details changed after review.",
        ));
    }
    let current = latest(&app).await?;
    if current.version != input.version || current.installer_sha256 != input.installer_sha256 {
        return Err(ApiError::bad_request(
            "The latest Gate release changed. Review it again.",
        ));
    }
    let expires_at = validate_registration(
        &app.http,
        &registration_portal_url(),
        &input.config.registration_key,
    )
    .await?;
    if app
        .execution_busy
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(ApiError::conflict("Another Upgrade action is running."));
    }
    let dir = job_dir(&app);
    if dir.join("status").exists() {
        app.execution_busy.store(false, Ordering::SeqCst);
        return Err(ApiError::conflict(
            "A Gate upgrade job already exists. Inspect its status first.",
        ));
    }
    if fs::create_dir_all(&dir).is_err() {
        app.execution_busy.store(false, Ordering::SeqCst);
        return Err(ApiError::internal());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    let key_path = dir.join("registration-key");
    if let Err(cause) = write_private(&key_path, input.config.registration_key.trim()) {
        app.execution_busy.store(false, Ordering::SeqCst);
        return Err(cause);
    }
    let _ = fs::write(dir.join("requested_final_url"), &input.config.final_url);
    let _ = fs::write(dir.join("requested_gate_dir"), &input.config.gate_dir);
    if let Some(expires_at) = expires_at {
        let _ = fs::write(dir.join("expires_at"), expires_at);
    }
    let task_app = app.clone();
    tokio::spawn(async move {
        let log = fs::File::create(dir.join("prepare.log"));
        let (stdout, stderr) = match log.and_then(|file| Ok((file.try_clone()?, file))) {
            Ok(pair) => pair,
            Err(_) => {
                let _ = fs::write(dir.join("status"), "failed");
                let _ = fs::remove_file(&key_path);
                task_app.execution_busy.store(false, Ordering::SeqCst);
                return;
            }
        };
        let result = upgrade_command(&task_app)
            .arg("prepare")
            .arg("--console-url")
            .arg(temporary_url)
            .arg("--registration-key-file")
            .arg(&key_path)
            .arg("--gate-dir")
            .arg(input.config.gate_dir)
            .arg("--release-version")
            .arg(input.version)
            .arg("--installer-sha256")
            .arg(input.installer_sha256)
            .env("TALLY_UPGRADE_STATE_DIR", &task_app.dir)
            .current_dir(root())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .status()
            .await;
        let _ = fs::remove_file(&key_path);
        if let Ok(status) = result {
            let _ = fs::write(
                dir.join("prepare-exit"),
                status.code().unwrap_or(-1).to_string(),
            );
            if !status.success() {
                let _ = fs::write(dir.join("status"), "failed");
            }
        } else {
            let _ = fs::write(dir.join("status"), "failed");
        }
        task_app.execution_busy.store(false, Ordering::SeqCst);
    });
    Ok(Json(json!({ "status": "starting" })))
}

fn cutover_url(dir: &Path, final_url: &str) -> Result<String, ApiError> {
    if read_file(dir, "status").as_deref() != Some("ready_for_cutover") && !cutover_retryable(dir) {
        return Err(ApiError::bad_request(
            "Gate must be verified or safely retryable before switching.",
        ));
    }
    Ok(final_console_url(final_url)?.origin().ascii_serialization())
}

pub async fn cutover(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<CutoverInput>,
) -> Result<Json<Value>, ApiError> {
    let bearer = token(&headers)?;
    session(&mut *app.sessions.lock().await, &bearer)?;
    require_host_upgrade(&app)?;
    if !input.approved {
        return Err(ApiError::bad_request("Cutover requires explicit approval."));
    }
    let dir = job_dir(&app);
    let final_url = cutover_url(&dir, &input.final_url)?;
    for path in [&input.tls_cert, &input.tls_key] {
        let path = Path::new(path);
        if !path.is_absolute() || !path.is_file() || fs::File::open(path).is_err() {
            return Err(ApiError::bad_request(
                "Enter readable absolute host paths for the production TLS full chain and private key.",
            ));
        }
    }
    if app
        .execution_busy
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(ApiError::conflict("Another Upgrade action is running."));
    }
    if fs::write(dir.join("requested_final_url"), &final_url).is_err() {
        app.execution_busy.store(false, Ordering::SeqCst);
        return Err(ApiError::internal());
    }
    let _ = fs::write(dir.join("requested_tls_cert"), &input.tls_cert);
    let _ = fs::write(dir.join("requested_tls_key"), &input.tls_key);
    let task_app = app.clone();
    tokio::spawn(async move {
        let log = fs::File::create(dir.join("cutover.log"));
        let (stdout, stderr) = match log.and_then(|file| Ok((file.try_clone()?, file))) {
            Ok(pair) => pair,
            Err(_) => {
                let _ = fs::write(dir.join("status"), "cutover_failed");
                task_app.execution_busy.store(false, Ordering::SeqCst);
                return;
            }
        };
        let result = upgrade_command(&task_app)
            .arg("cutover")
            .arg("--final-url")
            .arg(final_url)
            .arg("--tls-cert")
            .arg(input.tls_cert)
            .arg("--tls-key")
            .arg(input.tls_key)
            .env("TALLY_UPGRADE_STATE_DIR", &task_app.dir)
            .current_dir(root())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .status()
            .await;
        if let Ok(status) = result {
            let _ = fs::write(
                dir.join("cutover-exit"),
                status.code().unwrap_or(-1).to_string(),
            );
            if !status.success() {
                let _ = fs::write(dir.join("status"), "cutover_failed");
            }
        } else {
            let _ = fs::write(dir.join("status"), "cutover_failed");
        }
        task_app.execution_busy.store(false, Ordering::SeqCst);
    });
    Ok(Json(json!({ "status": "cutting_over" })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmInput {
    approved: bool,
}

pub async fn cancel(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<ConfirmInput>,
) -> Result<Json<Value>, ApiError> {
    let bearer = token(&headers)?;
    session(&mut *app.sessions.lock().await, &bearer)?;
    require_host_upgrade(&app)?;
    let dir = job_dir(&app);
    let cancellable = read_file(&dir, "status").as_deref() == Some("ready_for_cutover")
        || cutover_retryable(&dir);
    if !input.approved || !cancellable {
        return Err(ApiError::bad_request(
            "Only a prepared or safely retryable cutover can be cancelled.",
        ));
    }
    if app
        .execution_busy
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(ApiError::conflict("Another Upgrade action is running."));
    }
    let result = upgrade_command(&app)
        .arg("cancel")
        .env("TALLY_UPGRADE_STATE_DIR", &app.dir)
        .current_dir(root())
        .status()
        .await;
    app.execution_busy.store(false, Ordering::SeqCst);
    if !result.is_ok_and(|status| status.success()) {
        return Err(ApiError::internal());
    }
    Ok(Json(json!({ "status": "cancelled" })))
}

pub async fn reset(State(app): State<App>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let bearer = token(&headers)?;
    session(&mut *app.sessions.lock().await, &bearer)?;
    require_host_upgrade(&app)?;
    if !matches!(
        read_file(&job_dir(&app), "status").as_deref(),
        Some("failed" | "cancelled")
    ) {
        return Err(ApiError::bad_request(
            "Only a failed or cancelled upgrade can be reset.",
        ));
    }
    if app
        .execution_busy
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(ApiError::conflict("Another Upgrade action is running."));
    }
    let result = upgrade_command(&app)
        .arg("reset")
        .env("TALLY_UPGRADE_STATE_DIR", &app.dir)
        .current_dir(root())
        .status()
        .await;
    app.execution_busy.store(false, Ordering::SeqCst);
    if !result.is_ok_and(|status| status.success()) {
        return Err(ApiError::internal());
    }
    Ok(Json(json!({ "status": "not_started" })))
}

fn completed_upgrade(status: Option<&str>) -> bool {
    status == Some("gate_live")
}

pub async fn cleanup(State(app): State<App>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let bearer = token(&headers)?;
    session(&mut *app.sessions.lock().await, &bearer)?;
    require_host_upgrade(&app)?;
    let status = read_file(&job_dir(&app), "status").unwrap_or_else(|| "not_started".into());
    if !completed_upgrade(Some(&status)) {
        return Ok(Json(json!({ "cleaned": false, "status": status })));
    }
    if app
        .execution_busy
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(ApiError::conflict("Another Upgrade action is running."));
    }
    let result = upgrade_command(&app)
        .arg("cleanup")
        .env("TALLY_UPGRADE_STATE_DIR", &app.dir)
        .current_dir(root())
        .status()
        .await;
    app.execution_busy.store(false, Ordering::SeqCst);
    if !result.is_ok_and(|status| status.success()) {
        return Err(ApiError::bad_gateway(
            "Gate could not be confirmed healthy, so its upgrade recovery files were retained.",
        ));
    }
    Ok(Json(json!({ "cleaned": true, "status": "not_started" })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};

    #[test]
    fn cutover_accepts_an_updated_final_url_only_before_service_switching() {
        let dir = std::env::temp_dir().join(format!(
            "upgrade-cutover-url-test-{}",
            crate::random_token()
        ));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("status"), "ready_for_cutover").unwrap();
        fs::write(dir.join("requested_final_url"), "https://old.example.test").unwrap();
        let updated = "https://console.example.test:9443";
        assert_eq!(
            cutover_url(&dir, &format!(" {updated}/ ")).unwrap(),
            updated
        );
        for invalid in [
            "http://console.example.test",
            "console.example.test",
            "https://user:password@console.example.test",
            "https://console.example.test/path",
            "https://console.example.test?value=one",
            "https://console.example.test#fragment",
            "https://console.example.test:0",
            "https://[::1]",
        ] {
            assert!(
                cutover_url(&dir, invalid).is_err(),
                "accepted invalid final URL: {invalid}"
            );
        }
        fs::write(dir.join("status"), "copying").unwrap();
        assert!(cutover_url(&dir, updated).is_err());
        fs::write(dir.join("status"), "cutover_failed").unwrap();
        assert!(cutover_url(&dir, updated).is_err());
        fs::write(dir.join("writers-paused"), "").unwrap();
        fs::write(dir.join("cutover_stage"), "preflight").unwrap();
        assert_eq!(cutover_url(&dir, updated).unwrap(), updated);
        fs::write(dir.join("cutover_stage"), "switching").unwrap();
        assert!(cutover_url(&dir, updated).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn refuses_upgrade_when_expiry_cannot_be_verified() {
        let router = Router::new()
            .route(
                "/api/v1/users/me",
                get(|headers: HeaderMap| async move {
                    if headers
                        .get("x-godel-key")
                        .is_some_and(|value| value == "gg_valid_registration")
                    {
                        (StatusCode::OK, "{}")
                    } else {
                        (StatusCode::UNAUTHORIZED, "")
                    }
                }),
            )
            .route(
                "/api/v1/registration-keys/self",
                get(|| async { StatusCode::FORBIDDEN }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(axum::serve(listener, router).into_future());
        let accepted = validate_registration(
            &reqwest::Client::new(),
            &format!("http://{address}"),
            "  gg_valid_registration  ",
        )
        .await;
        assert!(accepted.is_err());
        server.abort();
    }

    #[tokio::test]
    async fn requires_an_active_key_with_a_future_expiry() {
        for (status, expiry, accepted) in [
            (StatusCode::OK, "2999-01-01T00:00:00Z", true),
            (StatusCode::OK, "2020-01-01T00:00:00Z", false),
            (StatusCode::UNAUTHORIZED, "2999-01-01T00:00:00Z", false),
        ] {
            let router = Router::new()
                .route("/api/v1/users/me", get(move || async move { status }))
                .route(
                    "/api/v1/registration-keys/self",
                    get(move || async move { Json(json!({"valid":true,"expires_at":expiry})) }),
                );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(axum::serve(listener, router).into_future());
            let result = validate_registration(
                &reqwest::Client::new(),
                &format!("http://{address}"),
                "gg_test",
            )
            .await;
            assert_eq!(result.is_ok(), accepted);
            server.abort();
        }
    }

    #[tokio::test]
    async fn portal_error_is_not_reported_as_key_rejection() {
        let router = Router::new().route(
            "/api/v1/users/me",
            get(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(axum::serve(listener, router).into_future());
        let error = validate_registration(
            &reqwest::Client::new(),
            &format!("http://{address}"),
            "gg_valid_registration",
        )
        .await
        .unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_GATEWAY);
        server.abort();
    }

    #[test]
    fn cleanup_is_limited_to_a_completed_upgrade() {
        assert!(completed_upgrade(Some("gate_live")));
        for status in [
            None,
            Some("not_started"),
            Some("preflight"),
            Some("ready_for_cutover"),
            Some("failed"),
            Some("cutover_failed"),
            Some("cancelled"),
        ] {
            assert!(!completed_upgrade(status));
        }
    }

    #[test]
    fn only_pre_switch_cutover_failures_are_retryable_and_logs_are_redacted() {
        let dir =
            std::env::temp_dir().join(format!("upgrade-upgrade-test-{}", crate::random_token()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("status"), "cutover_failed").unwrap();
        fs::write(dir.join("writers-paused"), "yes").unwrap();
        fs::write(
            dir.join("failure_reason"),
            "connector_runs row count differs",
        )
        .unwrap();
        fs::write(
            dir.join("cutover.log"),
            "Verified copied rows\nregistration key: private\nCutover stopped\n",
        )
        .unwrap();
        assert!(cutover_retryable(&dir));
        let log = attempt_log(&dir, "cutover_failed").unwrap();
        assert!(
            log["content"]
                .as_str()
                .unwrap()
                .contains("Verified copied rows")
        );
        assert!(
            log["content"]
                .as_str()
                .unwrap()
                .contains("[Sensitive output line redacted]")
        );
        assert!(!log["content"].as_str().unwrap().contains("private"));

        for stage in [
            "switching",
            "activating",
            "activation_failed",
            "recovery_failed",
            "retiring_tally",
        ] {
            fs::write(dir.join("cutover_stage"), stage).unwrap();
            assert!(!cutover_retryable(&dir), "unsafe retry allowed at {stage}");
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
