//! Standalone Tally IAM: password accounts, invitations, password resets and the
//! session check for the Tally API. Gate embeds `tally_api::routes` under its own IAM.
use std::sync::{Arc, OnceLock};

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use axum::{
    Json, Router,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use tally_config::SecretCipher;
use uuid::Uuid;

use crate::email;

#[derive(Clone)]
pub struct AuthState {
    pub pool: PgPool,
    pub collector_import_token: String,
    pub cipher: SecretCipher,
    pub http: reqwest::Client,
}

type ApiResult<T> = Result<T, (StatusCode, Json<serde_json::Value>)>;

fn error(status: StatusCode, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({ "error": message })))
}

fn request_origin(headers: &HeaderMap) -> ApiResult<String> {
    // The web proxy replaces forwarded headers after checking the browser's origin.
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "Missing request host"))?;
    let protocol = headers
        .get("x-forwarded-proto")
        .map(|value| value.to_str())
        .transpose()
        .map_err(|_| error(StatusCode::BAD_REQUEST, "Invalid request protocol"))?
        .unwrap_or("http");
    if !matches!(protocol, "http" | "https")
        || host.contains(['/', '\\', '?', '#', '@', ','])
        || host.chars().any(char::is_whitespace)
    {
        return Err(error(StatusCode::BAD_REQUEST, "Invalid request authority"));
    }
    let url = url::Url::parse(&format!("{protocol}://{host}"))
        .map_err(|_| error(StatusCode::BAD_REQUEST, "Invalid request authority"))?;
    Ok(url.origin().ascii_serialization())
}

fn valid_request_origin(headers: &HeaderMap) -> bool {
    request_origin(headers).is_ok_and(|expected| {
        headers
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            == Some(expected.as_str())
            && headers
                .get("sec-fetch-site")
                .and_then(|value| value.to_str().ok())
                != Some("cross-site")
    })
}

#[allow(clippy::needless_pass_by_value)] // Used directly as a map_err callback.
fn db_error(cause: sqlx::Error) -> (StatusCode, Json<serde_json::Value>) {
    tracing::error!(%cause, "standalone auth database operation failed");
    error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Authentication service unavailable",
    )
}

fn random_token() -> ApiResult<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| {
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Secure randomness unavailable",
        )
    })?;
    Ok(hex::encode(bytes))
}

fn token_hash(value: &str) -> Vec<u8> {
    Sha256::digest(value.as_bytes()).to_vec()
}

fn normalize_email(email: &str) -> ApiResult<String> {
    let email = email.trim().to_ascii_lowercase();
    if email.len() > 254 || email.len() < 5 || email.contains(char::is_whitespace) {
        return Err(error(StatusCode::BAD_REQUEST, "Invalid email address"));
    }
    let (local, domain) = email
        .split_once('@')
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "Invalid email address"))?;
    if local.is_empty()
        || domain.contains('@')
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return Err(error(StatusCode::BAD_REQUEST, "Invalid email address"));
    }
    Ok(email)
}

fn hash_password(password: &str) -> ApiResult<String> {
    if password.len() < 12 || password.len() > 1024 {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "Password must be 12 to 1024 characters",
        ));
    }
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Password hashing failed"))
}

async fn password_hash(password: String) -> ApiResult<String> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Password hashing failed"))?
}

async fn check_password(password: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&hash).is_ok_and(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
    })
    .await
    .unwrap_or(false)
}

#[derive(Debug, Serialize)]
pub(crate) struct UserView {
    pub(crate) id: Uuid,
    pub(crate) email: String,
    display_name: String,
    first_name: Option<String>,
    last_name: Option<String>,
    pub(crate) role: String,
}

fn validated_names<'a>(first_name: &'a str, last_name: &'a str) -> ApiResult<(&'a str, &'a str)> {
    let first = first_name.trim();
    let last = last_name.trim();
    if first.is_empty() || first.chars().count() > 100 {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "First name is required (up to 100 characters)",
        ));
    }
    if last.is_empty() || last.chars().count() > 100 {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "Last name is required (up to 100 characters)",
        ));
    }
    if first.chars().count() + last.chars().count() + 1 > 120 {
        return Err(error(StatusCode::BAD_REQUEST, "Full name is too long"));
    }
    Ok((first, last))
}

#[derive(Debug)]
struct UserRecord {
    view: UserView,
    password_hash: Option<String>,
    locked_until: Option<chrono::DateTime<Utc>>,
}

async fn load_user(pool: &PgPool, email: &str) -> ApiResult<Option<UserRecord>> {
    let row = sqlx::query("SELECT user_id, email, display_name, first_name, last_name, role, password_hash, failed_attempts, locked_until FROM tally_auth_users WHERE email = $1 AND disabled_at IS NULL")
        .bind(email)
        .fetch_optional(pool)
        .await
        .map_err(db_error)?;
    Ok(row.map(|row| UserRecord {
        view: UserView {
            id: row.get("user_id"),
            email: row.get("email"),
            display_name: row.get("display_name"),
            first_name: row.get("first_name"),
            last_name: row.get("last_name"),
            role: row.get("role"),
        },
        password_hash: row.get("password_hash"),
        locked_until: row.get("locked_until"),
    }))
}

/// Five consecutive failures lock the account for 15 minutes. Attempts during a lock
/// neither count nor extend it, and the count restarts once a lock has expired.
const RECORD_FAILED_ATTEMPT: &str = "UPDATE tally_auth_users SET
    failed_attempts = CASE
        WHEN locked_until > NOW() THEN failed_attempts
        WHEN locked_until IS NOT NULL THEN 1
        ELSE failed_attempts + 1 END,
    locked_until = CASE
        WHEN locked_until > NOW() THEN locked_until
        WHEN locked_until IS NULL AND failed_attempts + 1 >= 5 THEN NOW() + INTERVAL '15 minutes'
        ELSE NULL END
    WHERE user_id = $1";

fn session_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == "tally_session"
                && value.len() == 64
                && value.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| value.to_owned())
        })
}

pub(crate) async fn current_user(state: &AuthState, headers: &HeaderMap) -> ApiResult<UserView> {
    let token = session_from_headers(headers)
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "Sign in required"))?;
    let row = sqlx::query("SELECT u.user_id, u.email, u.display_name, u.first_name, u.last_name, u.role FROM tally_auth_sessions s JOIN tally_auth_users u ON u.user_id = s.user_id WHERE s.token_hash = $1 AND s.expires_at > NOW() AND u.disabled_at IS NULL")
        .bind(token_hash(&token))
        .fetch_optional(&state.pool)
        .await
        .map_err(db_error)?
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "Session expired"))?;
    Ok(UserView {
        id: row.get("user_id"),
        email: row.get("email"),
        display_name: row.get("display_name"),
        first_name: row.get("first_name"),
        last_name: row.get("last_name"),
        role: row.get("role"),
    })
}

async fn admin(state: &AuthState, headers: &HeaderMap) -> ApiResult<UserView> {
    let user = current_user(state, headers).await?;
    if user.role != "admin" {
        return Err(error(
            StatusCode::FORBIDDEN,
            "Administrator access required",
        ));
    }
    Ok(user)
}

fn set_session_cookie(response: &mut Response, token: &str) {
    let cookie =
        format!("tally_session={token}; Path=/; Max-Age=43200; HttpOnly; Secure; SameSite=Lax");
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("session cookie is ASCII"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

async fn issue_session(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user: UserView,
) -> ApiResult<Response> {
    sqlx::query("DELETE FROM tally_auth_sessions WHERE expires_at <= NOW()")
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
    let token = random_token()?;
    sqlx::query("INSERT INTO tally_auth_sessions (token_hash, user_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL '12 hours')")
        .bind(token_hash(&token))
        .bind(user.id)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
    let mut response = Json(serde_json::json!({ "user": user })).into_response();
    set_session_cookie(&mut response, &token);
    Ok(response)
}

#[derive(Deserialize)]
struct RegisterInput {
    email: String,
    first_name: String,
    last_name: String,
    password: String,
    invitation_token: Option<String>,
}

async fn status(State(state): State<Arc<AuthState>>) -> ApiResult<Json<serde_json::Value>> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tally_auth_users")
        .fetch_one(&state.pool)
        .await
        .map_err(db_error)?;
    let email_configured = password_reset_email(&state).await.is_some();
    Ok(Json(serde_json::json!({
        "first_user_registration_open": count == 0,
        "email_configured": email_configured,
    })))
}

/// Signing in or registering replaces any session this browser holds. A failed attempt
/// therefore leaves the browser signed out instead of in the previous account.
async fn end_presented_session(state: &AuthState, headers: &HeaderMap) -> ApiResult<bool> {
    let Some(token) = session_from_headers(headers) else {
        return Ok(false);
    };
    sqlx::query("DELETE FROM tally_auth_sessions WHERE token_hash = $1")
        .bind(token_hash(&token))
        .execute(&state.pool)
        .await
        .map_err(db_error)?;
    Ok(true)
}

fn clear_session_cookie(response: &mut Response) {
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "tally_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
        ),
    );
}

async fn replacing_session(
    state: &AuthState,
    headers: &HeaderMap,
    attempt: impl std::future::Future<Output = ApiResult<Response>>,
) -> Response {
    let ended = match end_presented_session(state, headers).await {
        Ok(ended) => ended,
        Err(e) => return e.into_response(),
    };
    match attempt.await {
        Ok(response) => response,
        Err(e) => {
            let mut response = e.into_response();
            if ended {
                clear_session_cookie(&mut response);
            }
            response
        }
    }
}

async fn register(
    State(state): State<Arc<AuthState>>,
    headers: HeaderMap,
    input: Result<Json<RegisterInput>, JsonRejection>,
) -> Response {
    replacing_session(&state, &headers, async {
        let Json(input) =
            input.map_err(|_| error(StatusCode::BAD_REQUEST, "Invalid registration request"))?;
        register_account(&state, input).await
    })
    .await
}

async fn register_account(state: &AuthState, input: RegisterInput) -> ApiResult<Response> {
    let email = normalize_email(&input.email)?;
    let (first_name, last_name) = validated_names(&input.first_name, &input.last_name)?;
    let name = format!("{first_name} {last_name}");
    let hashed = password_hash(input.password).await?;
    let mut tx = state.pool.begin().await.map_err(db_error)?;
    // Serialize first-user registration across API replicas. Only the first user is an admin.
    sqlx::query("SELECT pg_advisory_xact_lock(5190362026)")
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tally_auth_users")
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
    let role = if count == 0 {
        "admin"
    } else {
        let invite = input
            .invitation_token
            .as_deref()
            .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| error(StatusCode::FORBIDDEN, "An invitation is required"))?;
        let invited_email: Option<String> = sqlx::query_scalar("UPDATE tally_auth_invitations SET accepted_at = NOW() WHERE token_hash = $1 AND accepted_at IS NULL AND expires_at > NOW() RETURNING email")
            .bind(token_hash(invite)).fetch_optional(&mut *tx).await.map_err(db_error)?;
        if invited_email.as_deref() != Some(email.as_str()) {
            return Err(error(
                StatusCode::FORBIDDEN,
                "Invitation is invalid or expired",
            ));
        }
        "member"
    };
    let id = Uuid::new_v4();
    let inserted = sqlx::query("INSERT INTO tally_auth_users (user_id, email, display_name, first_name, last_name, password_hash, role) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (email) DO NOTHING")
        .bind(id).bind(&email).bind(&name).bind(first_name).bind(last_name).bind(hashed).bind(role)
        .execute(&mut *tx).await.map_err(db_error)?;
    if inserted.rows_affected() != 1 {
        return Err(error(StatusCode::CONFLICT, "Email already registered"));
    }
    let response = issue_session(
        &mut tx,
        UserView {
            id,
            email,
            display_name: name,
            first_name: Some(first_name.to_owned()),
            last_name: Some(last_name.to_owned()),
            role: role.to_owned(),
        },
    )
    .await?;
    tx.commit().await.map_err(db_error)?;
    Ok(response)
}

#[derive(Deserialize)]
struct LoginInput {
    email: String,
    password: String,
}

async fn login(
    State(state): State<Arc<AuthState>>,
    headers: HeaderMap,
    input: Result<Json<LoginInput>, JsonRejection>,
) -> Response {
    replacing_session(&state, &headers, async {
        let Json(input) =
            input.map_err(|_| error(StatusCode::BAD_REQUEST, "Invalid sign-in request"))?;
        sign_in(&state, input).await
    })
    .await
}

async fn sign_in(state: &AuthState, input: LoginInput) -> ApiResult<Response> {
    let email = normalize_email(&input.email)?;
    let user = load_user(&state.pool, &email).await?;
    let valid = if let Some(record) = &user {
        if record.locked_until.is_some_and(|until| until > Utc::now()) {
            false
        } else if let Some(hash) = &record.password_hash {
            check_password(input.password, hash.clone()).await
        } else {
            false
        }
    } else {
        // Keep unknown-email attempts expensive too.
        let _ = check_password(input.password, dummy_hash().to_owned()).await;
        false
    };
    if !valid {
        if let Some(record) = user {
            sqlx::query(RECORD_FAILED_ATTEMPT)
                .bind(record.view.id)
                .execute(&state.pool)
                .await
                .map_err(db_error)?;
        }
        return Err(error(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }
    let record = user.expect("valid password implies user exists");
    let mut tx = state.pool.begin().await.map_err(db_error)?;
    // Lock and recheck the credential before issuing the session. A concurrent reset
    // or account disable must not leave a new session authenticated with the old password.
    let updated = sqlx::query(
        "UPDATE tally_auth_users SET failed_attempts = 0, locked_until = NULL
         WHERE user_id = $1 AND password_hash = $2 AND disabled_at IS NULL
           AND (locked_until IS NULL OR locked_until <= NOW())",
    )
    .bind(record.view.id)
    .bind(record.password_hash)
    .execute(&mut *tx)
    .await
    .map_err(db_error)?;
    if updated.rows_affected() != 1 {
        return Err(error(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }
    let response = issue_session(&mut tx, record.view).await?;
    tx.commit().await.map_err(db_error)?;
    Ok(response)
}

// Generate a valid PHC string once so unknown accounts still pay the Argon2 verification cost.
fn dummy_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| {
        let salt = SaltString::encode_b64(b"tally-dummy-salt").expect("fixed salt is valid");
        Argon2::default()
            .hash_password(b"dummy-password", &salt)
            .expect("fixed dummy password hashes")
            .to_string()
    })
}

async fn me(
    State(state): State<Arc<AuthState>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(
        serde_json::json!({ "user": current_user(&state, &headers).await? }),
    ))
}

#[derive(Deserialize)]
struct ProfileInput {
    first_name: String,
    last_name: String,
}

async fn update_me(
    State(state): State<Arc<AuthState>>,
    headers: HeaderMap,
    Json(input): Json<ProfileInput>,
) -> ApiResult<Json<serde_json::Value>> {
    let actor = current_user(&state, &headers).await?;
    let (first_name, last_name) = validated_names(&input.first_name, &input.last_name)?;
    let display_name = format!("{first_name} {last_name}");
    sqlx::query("UPDATE tally_auth_users SET first_name = $2, last_name = $3, display_name = $4 WHERE user_id = $1")
        .bind(actor.id).bind(first_name).bind(last_name).bind(&display_name)
        .execute(&state.pool).await.map_err(db_error)?;
    Ok(Json(serde_json::json!({ "user": UserView {
        display_name,
        first_name: Some(first_name.to_owned()),
        last_name: Some(last_name.to_owned()),
        ..actor
    } })))
}

#[derive(Deserialize)]
struct ChangePasswordInput {
    current_password: String,
    new_password: String,
}

async fn change_password(
    State(state): State<Arc<AuthState>>,
    headers: HeaderMap,
    Json(input): Json<ChangePasswordInput>,
) -> ApiResult<StatusCode> {
    let actor = current_user(&state, &headers).await?;
    let row = sqlx::query("SELECT password_hash, locked_until FROM tally_auth_users WHERE user_id = $1 AND disabled_at IS NULL")
        .bind(actor.id).fetch_one(&state.pool).await.map_err(db_error)?;
    let old_hash: Option<String> = row.get("password_hash");
    let old_hash = old_hash.ok_or_else(|| {
        error(
            StatusCode::CONFLICT,
            "This account has no password yet. Set one with a password reset link.",
        )
    })?;
    let locked_until: Option<chrono::DateTime<Utc>> = row.get("locked_until");
    if locked_until.is_some_and(|until| until > Utc::now()) {
        return Err(error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many password attempts. Try again later",
        ));
    }
    if !check_password(input.current_password, old_hash.clone()).await {
        sqlx::query(RECORD_FAILED_ATTEMPT)
            .bind(actor.id)
            .execute(&state.pool)
            .await
            .map_err(db_error)?;
        return Err(error(
            StatusCode::UNAUTHORIZED,
            "Current password is incorrect",
        ));
    }
    if check_password(input.new_password.clone(), old_hash.clone()).await {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "Choose a different password",
        ));
    }
    let new_hash = password_hash(input.new_password).await?;
    let mut tx = state.pool.begin().await.map_err(db_error)?;
    let updated = sqlx::query("UPDATE tally_auth_users SET password_hash = $2, failed_attempts = 0, locked_until = NULL WHERE user_id = $1 AND password_hash = $3")
        .bind(actor.id).bind(new_hash).bind(old_hash).execute(&mut *tx).await.map_err(db_error)?;
    if updated.rows_affected() != 1 {
        return Err(error(
            StatusCode::CONFLICT,
            "Password changed in another session. Try again",
        ));
    }
    sqlx::query("DELETE FROM tally_auth_password_resets WHERE user_id = $1")
        .bind(actor.id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    let current_token = session_from_headers(&headers)
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "Sign in required"))?;
    sqlx::query("DELETE FROM tally_auth_sessions WHERE user_id = $1 AND token_hash <> $2")
        .bind(actor.id)
        .bind(token_hash(&current_token))
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ResetPasswordInput {
    token: String,
    new_password: String,
}

async fn confirm_password_reset(
    State(state): State<Arc<AuthState>>,
    Json(input): Json<ResetPasswordInput>,
) -> ApiResult<StatusCode> {
    if input.token.len() != 64 || !input.token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "Reset link is invalid or expired",
        ));
    }
    let new_hash = password_hash(input.new_password).await?;
    let mut tx = state.pool.begin().await.map_err(db_error)?;
    // All reset flows lock the user before changing tokens, avoiding lock-order
    // inversions with administrators issuing replacement links.
    let locked_user: Option<Uuid> = sqlx::query_scalar(
        "SELECT u.user_id FROM tally_auth_users u JOIN tally_auth_password_resets r
         ON r.user_id = u.user_id WHERE r.token_hash = $1 FOR UPDATE OF u",
    )
    .bind(token_hash(&input.token))
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_error)?;
    if locked_user.is_none() {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "Reset link is invalid or expired",
        ));
    }
    let user_id: Option<Uuid> = sqlx::query_scalar("UPDATE tally_auth_password_resets SET used_at = NOW() WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW() RETURNING user_id")
        .bind(token_hash(&input.token)).fetch_optional(&mut *tx).await.map_err(db_error)?;
    let user_id = user_id
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "Reset link is invalid or expired"))?;
    let updated = sqlx::query("UPDATE tally_auth_users SET password_hash = $2, failed_attempts = 0, locked_until = NULL WHERE user_id = $1 AND disabled_at IS NULL")
        .bind(user_id).bind(new_hash).execute(&mut *tx).await.map_err(db_error)?;
    if updated.rows_affected() != 1 {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "Reset link is invalid or expired",
        ));
    }
    sqlx::query("DELETE FROM tally_auth_sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    Ok(StatusCode::NO_CONTENT)
}

const RESET_SUBJECT: &str = "Reset your Gödel Tally password";

fn reset_body(link: &str) -> String {
    format!(
        "Hello,\n\nA password reset was requested for your Gödel Tally account.\n\n\
         Set a new password here within one hour:\n{link}\n\n\
         The link works once. If you did not request it, ignore this email; your password is unchanged."
    )
}

/// Delivery settings and the public URL for emailed links. Links never use the request's
/// Host header, which a client could forge to capture a victim's reset token.
async fn password_reset_email(state: &AuthState) -> Option<(email::EmailConfig, String)> {
    let public_url = email::public_url()?;
    Some((email::active(&state.pool, &state.cipher).await?, public_url))
}

/// Replaces any unused link, so only the newest one works.
async fn new_reset_token(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user: Uuid,
) -> ApiResult<(String, chrono::DateTime<Utc>)> {
    sqlx::query("DELETE FROM tally_auth_password_resets WHERE user_id = $1 AND used_at IS NULL")
        .bind(user)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
    let token = random_token()?;
    let expires_at = Utc::now() + Duration::hours(1);
    sqlx::query("INSERT INTO tally_auth_password_resets (token_hash, user_id, expires_at) VALUES ($1,$2,$3)")
        .bind(token_hash(&token)).bind(user).bind(expires_at)
        .execute(&mut **tx).await.map_err(db_error)?;
    Ok((token, expires_at))
}

#[derive(Deserialize)]
struct ResetRequestInput {
    email: String,
}

/// Forgot password. The response never reveals whether an account exists, and at most
/// one link per account is sent each minute.
async fn request_password_reset(
    State(state): State<Arc<AuthState>>,
    Json(input): Json<ResetRequestInput>,
) -> ApiResult<Json<serde_json::Value>> {
    let email = normalize_email(&input.email)?;
    let Some((config, public_url)) = password_reset_email(&state).await else {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Email is not set up for this Tally installation, so Tally cannot send reset links.",
        ));
    };
    let mut tx = state.pool.begin().await.map_err(db_error)?;
    let user: Option<Uuid> = sqlx::query_scalar(
        "SELECT u.user_id FROM tally_auth_users u
         WHERE u.email = $1 AND u.disabled_at IS NULL FOR UPDATE",
    )
    .bind(&email)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_error)?;
    if let Some(user) = user {
        // Check after acquiring the user lock so simultaneous requests cannot each
        // pass a stale snapshot and send different links.
        let recent: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM tally_auth_password_resets WHERE user_id = $1 AND created_at > NOW() - INTERVAL '1 minute')")
            .bind(user).fetch_one(&mut *tx).await.map_err(db_error)?;
        if recent {
            return Ok(Json(serde_json::json!({ "requested": true })));
        }
        let (token, _) = new_reset_token(&mut tx, user).await?;
        tx.commit().await.map_err(db_error)?;
        // Send after responding so timing does not reveal which addresses have accounts.
        let http = state.http.clone();
        tokio::spawn(async move {
            let link = format!("{public_url}/reset-password#token={token}");
            if let Err(cause) =
                email::send(&http, &config, &email, RESET_SUBJECT, &reset_body(&link)).await
            {
                tracing::warn!(
                    error = format!("{cause:#}"),
                    "could not send a password reset email"
                );
            }
        });
    }
    Ok(Json(serde_json::json!({ "requested": true })))
}

async fn email_settings(
    State(state): State<Arc<AuthState>>,
    headers: HeaderMap,
) -> ApiResult<Json<email::EmailView>> {
    admin(&state, &headers).await?;
    email::view(&state.pool, &state.cipher)
        .await
        .map(Json)
        .map_err(|cause| {
            tracing::error!(
                error = format!("{cause:#}"),
                "could not read the email configuration"
            );
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Email settings are unavailable",
            )
        })
}

async fn save_email_settings(
    State(state): State<Arc<AuthState>>,
    headers: HeaderMap,
    Json(input): Json<email::EmailInput>,
) -> ApiResult<Json<email::EmailView>> {
    let actor = admin(&state, &headers).await?;
    email::save(&state.pool, &state.cipher, input, actor.id)
        .await
        .map_err(|e| match e {
            email::SaveError::Invalid(message) => error(StatusCode::BAD_REQUEST, &message),
            email::SaveError::Internal(cause) => {
                tracing::error!(
                    error = format!("{cause:#}"),
                    "could not save the email configuration"
                );
                error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Email settings could not be saved",
                )
            }
        })?;
    email_settings(State(state), headers).await
}

#[derive(Deserialize)]
struct TestEmailInput {
    to: String,
}

async fn send_test_email(
    State(state): State<Arc<AuthState>>,
    headers: HeaderMap,
    Json(input): Json<TestEmailInput>,
) -> ApiResult<Json<serde_json::Value>> {
    admin(&state, &headers).await?;
    let to = normalize_email(&input.to)?;
    let config = email::active(&state.pool, &state.cipher)
        .await
        .ok_or_else(|| {
            error(
                StatusCode::CONFLICT,
                "Save and enable an email provider first",
            )
        })?;
    let body = "This is a test message from Gödel Tally. Your email delivery settings work.";
    match email::send(&state.http, &config, &to, "Gödel Tally email test", body).await {
        Ok(()) => Ok(Json(
            serde_json::json!({ "sent": true, "message": format!("Test email sent to {to}.") }),
        )),
        // Administrators need the provider's reason (credentials, sender verification, region).
        Err(cause) => Ok(Json(
            serde_json::json!({ "sent": false, "message": format!("{cause:#}") }),
        )),
    }
}

async fn logout(State(state): State<Arc<AuthState>>, headers: HeaderMap) -> ApiResult<Response> {
    if let Some(token) = session_from_headers(&headers) {
        sqlx::query("DELETE FROM tally_auth_sessions WHERE token_hash = $1")
            .bind(token_hash(&token))
            .execute(&state.pool)
            .await
            .map_err(db_error)?;
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "tally_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
        ),
    );
    Ok(response)
}

#[derive(Deserialize)]
struct InviteInput {
    email: String,
}

async fn invite(
    State(state): State<Arc<AuthState>>,
    headers: HeaderMap,
    Json(input): Json<InviteInput>,
) -> ApiResult<Json<serde_json::Value>> {
    let actor = admin(&state, &headers).await?;
    let email = normalize_email(&input.email)?;
    if load_user(&state.pool, &email).await?.is_some() {
        return Err(error(StatusCode::CONFLICT, "User already registered"));
    }
    let token = random_token()?;
    sqlx::query("INSERT INTO tally_auth_invitations (token_hash, email, invited_by, expires_at) VALUES ($1,$2,$3,NOW() + INTERVAL '7 days')")
        .bind(token_hash(&token)).bind(&email).bind(actor.id)
        .execute(&state.pool).await.map_err(db_error)?;
    Ok(Json(
        serde_json::json!({ "email": email, "invite_url": format!("{}/signin#invite={token}", request_origin(&headers)?), "expires_at": Utc::now() + Duration::days(7) }),
    ))
}

async fn users(
    State(state): State<Arc<AuthState>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    admin(&state, &headers).await?;
    let rows = sqlx::query("SELECT user_id, email, display_name, first_name, last_name, role, disabled_at, password_hash IS NOT NULL AS has_password FROM tally_auth_users ORDER BY created_at")
        .fetch_all(&state.pool).await.map_err(db_error)?;
    Ok(Json(
        serde_json::json!({ "users": rows.iter().map(|row| serde_json::json!({
        "id": row.get::<Uuid, _>("user_id"), "email": row.get::<String, _>("email"),
        "display_name": row.get::<String, _>("display_name"),
        "first_name": row.get::<Option<String>, _>("first_name"), "last_name": row.get::<Option<String>, _>("last_name"),
        "role": row.get::<String, _>("role"),
        "has_password": row.get::<bool, _>("has_password"),
        "disabled": row.get::<Option<chrono::DateTime<Utc>>, _>("disabled_at").is_some(),
    })).collect::<Vec<_>>() }),
    ))
}

#[derive(Deserialize)]
struct UserUpdate {
    disabled: bool,
}

async fn update_user_name(
    State(state): State<Arc<AuthState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<ProfileInput>,
) -> ApiResult<StatusCode> {
    admin(&state, &headers).await?;
    let (first_name, last_name) = validated_names(&input.first_name, &input.last_name)?;
    let display_name = format!("{first_name} {last_name}");
    let updated = sqlx::query("UPDATE tally_auth_users SET first_name = $2, last_name = $3, display_name = $4 WHERE user_id = $1")
        .bind(id).bind(first_name).bind(last_name).bind(display_name)
        .execute(&state.pool).await.map_err(db_error)?;
    if updated.rows_affected() != 1 {
        return Err(error(StatusCode::NOT_FOUND, "User not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn admin_reset_password(
    State(state): State<Arc<AuthState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    admin(&state, &headers).await?;
    let mut tx = state.pool.begin().await.map_err(db_error)?;
    let row = sqlx::query(
        "SELECT email, disabled_at FROM tally_auth_users WHERE user_id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_error)?
    .ok_or_else(|| error(StatusCode::NOT_FOUND, "User not found"))?;
    let email: String = row.get("email");
    let disabled_at: Option<chrono::DateTime<Utc>> = row.get("disabled_at");
    if disabled_at.is_some() {
        return Err(error(
            StatusCode::CONFLICT,
            "Enable this account before resetting its password",
        ));
    }
    let (token, expires_at) = new_reset_token(&mut tx, id).await?;
    tx.commit().await.map_err(db_error)?;
    let reset_url = format!(
        "{}/reset-password#token={token}",
        email::public_url().map_or_else(|| request_origin(&headers), Ok)?
    );
    let emailed = match password_reset_email(&state).await {
        Some((config, public_url)) => {
            let link = format!("{public_url}/reset-password#token={token}");
            email::send(
                &state.http,
                &config,
                &email,
                RESET_SUBJECT,
                &reset_body(&link),
            )
            .await
            .inspect_err(|cause| {
                tracing::warn!(
                    error = format!("{cause:#}"),
                    "could not email the reset link"
                );
            })
            .is_ok()
        }
        None => false,
    };
    Ok(Json(serde_json::json!({
        "reset_url": reset_url,
        "expires_at": expires_at,
        "emailed": emailed,
    })))
}

async fn update_user(
    State(state): State<Arc<AuthState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<UserUpdate>,
) -> ApiResult<StatusCode> {
    let actor = admin(&state, &headers).await?;
    if actor.id == id {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "Cannot disable your own account",
        ));
    }
    let updated = sqlx::query("UPDATE tally_auth_users SET disabled_at = CASE WHEN $2 THEN NOW() ELSE NULL END WHERE user_id = $1")
        .bind(id).bind(input.disabled).execute(&state.pool).await.map_err(db_error)?;
    if updated.rows_affected() == 0 {
        return Err(error(StatusCode::NOT_FOUND, "User not found"));
    }
    sqlx::query("DELETE FROM tally_auth_sessions WHERE user_id = $1")
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(db_error)?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn require_session(
    State(state): State<Arc<AuthState>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if matches!(
        path,
        "/api/v1/tally/health/live" | "/api/v1/tally/health/ready"
    ) {
        return next.run(request).await;
    }
    if collector_import_authorized(
        request.method(),
        path,
        request.headers(),
        &state.collector_import_token,
    ) {
        return next.run(request).await;
    }
    if !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) && !valid_request_origin(request.headers())
    {
        return error(StatusCode::FORBIDDEN, "Invalid request origin").into_response();
    }
    let mut response = match current_user(&state, request.headers()).await {
        Ok(user) if user.role != "admin" && admin_only(request.method(), path) => {
            error(StatusCode::FORBIDDEN, "Administrator access required").into_response()
        }
        Ok(_) => next.run(request).await,
        Err(e) => e.into_response(),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Tally API operations reserved for administrators: the Admin pages (audit logs and
/// data removal), connector credentials and configuration, bulk imports and backfills.
/// Members read the estate, run scans and syncs, and record governance decisions.
fn admin_only(method: &Method, path: &str) -> bool {
    let Some(route) = path.strip_prefix("/api/v1/tally/") else {
        return false;
    };
    matches!(
        route,
        "audit" | "data" | "data/delete" | "connectors/schedules"
    ) || route.starts_with("data/")
        || route.starts_with("imports")
        || (route.starts_with("connectors/jobs/") && route.contains("/backfill"))
        || (route.starts_with("connectors/")
            && (route.ends_with("/configuration") || *method == Method::DELETE))
}

fn collector_import_authorized(
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    expected_token: &str,
) -> bool {
    method == Method::POST
        && matches!(
            path,
            "/api/v1/tally/imports/preview" | "/api/v1/tally/imports"
        )
        && headers
            .get("x-tally-collector-token")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|provided| {
                subtle::ConstantTimeEq::ct_eq(provided.as_bytes(), expected_token.as_bytes()).into()
            })
}

pub(crate) async fn require_origin(request: axum::extract::Request, next: Next) -> Response {
    if !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) && !valid_request_origin(request.headers())
    {
        return error(StatusCode::FORBIDDEN, "Invalid request origin").into_response();
    }
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub fn router(state: Arc<AuthState>) -> Router {
    Router::new()
        .route("/api/v1/auth/status", get(status))
        .route("/api/v1/auth/register", post(register))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/me", get(me).post(update_me))
        .route("/api/v1/auth/me/password", post(change_password))
        .route(
            "/api/v1/auth/password-reset/request",
            post(request_password_reset),
        )
        .route(
            "/api/v1/auth/password-reset/confirm",
            post(confirm_password_reset),
        )
        .route(
            "/api/v1/auth/email",
            get(email_settings).post(save_email_settings),
        )
        .route("/api/v1/auth/email/test", post(send_test_email))
        .route("/api/v1/auth/users", get(users))
        .route("/api/v1/auth/users/{id}", post(update_user))
        .route("/api/v1/auth/users/{id}/name", post(update_user_name))
        .route(
            "/api/v1/auth/users/{id}/password-reset",
            post(admin_reset_password),
        )
        .route("/api/v1/auth/invitations", post(invite))
        .with_state(state)
        .layer(axum::middleware::from_fn(require_origin))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_origin_uses_the_proxied_domain_or_ip() {
        for host in [
            "tally.godel-labs.ai",
            "192.0.2.10",
            "localhost:8443",
            "[::1]:8443",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::HOST, HeaderValue::from_static("tallyd:8788"));
            headers.insert("x-forwarded-host", HeaderValue::from_str(host).unwrap());
            headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
            let origin = format!("https://{host}");
            headers.insert(header::ORIGIN, HeaderValue::from_str(&origin).unwrap());
            assert_eq!(request_origin(&headers).unwrap(), origin);
            assert!(valid_request_origin(&headers));
        }
    }

    #[test]
    fn request_origin_rejects_cross_origin_and_missing_origins() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("tally.godel-labs.ai"),
        );
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        for origin in [
            "https://attacker.example",
            "http://tally.godel-labs.ai",
            "https://tally.godel-labs.ai:8443",
            "null",
        ] {
            headers.insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
            assert!(!valid_request_origin(&headers));
        }
        headers.remove(header::ORIGIN);
        assert!(!valid_request_origin(&headers));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://tally.godel-labs.ai"),
        );
        headers.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        assert!(!valid_request_origin(&headers));
    }

    #[test]
    fn request_origin_validates_authorities_and_supports_direct_http() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("localhost:8788"));
        assert_eq!(request_origin(&headers).unwrap(), "http://localhost:8788");
        for host in [
            "example.com/path",
            "user@example.com",
            "example.com,attacker.example",
            "example.com?query",
            "example.com\\path",
        ] {
            headers.insert(header::HOST, HeaderValue::from_str(host).unwrap());
            assert!(request_origin(&headers).is_err());
        }
        headers.insert(header::HOST, HeaderValue::from_static("localhost:8788"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("ftp"));
        assert!(request_origin(&headers).is_err());
    }

    #[test]
    fn administrator_only_routes_cover_admin_pages_credentials_and_bulk_changes() {
        for (method, path) in [
            (Method::GET, "/api/v1/tally/audit"),
            (Method::GET, "/api/v1/tally/data"),
            (Method::POST, "/api/v1/tally/data/delete"),
            (Method::POST, "/api/v1/tally/data/preview"),
            (Method::GET, "/api/v1/tally/data/sample"),
            (Method::POST, "/api/v1/tally/data/sample"),
            (Method::POST, "/api/v1/tally/data/sample/delete"),
            (Method::POST, "/api/v1/tally/connectors/schedules"),
            (Method::GET, "/api/v1/tally/connectors/abc/configuration"),
            (Method::DELETE, "/api/v1/tally/connectors/abc"),
            (Method::POST, "/api/v1/tally/imports"),
            (Method::POST, "/api/v1/tally/imports/preview"),
            (Method::POST, "/api/v1/tally/connectors/jobs/abc/backfill"),
            (
                Method::POST,
                "/api/v1/tally/connectors/jobs/abc/backfill/preview",
            ),
        ] {
            assert!(admin_only(&method, path), "{method} {path}");
        }
        for (method, path) in [
            (Method::GET, "/api/v1/tally/overview"),
            (Method::GET, "/api/v1/tally/connectors"),
            (Method::POST, "/api/v1/tally/connectors/abc/sync"),
            (Method::POST, "/api/v1/tally/connectors/sync"),
            (Method::POST, "/api/v1/tally/scans"),
            (Method::POST, "/api/v1/tally/registry/sanctions"),
            (Method::POST, "/api/v1/tally/estate/activity/query"),
            (Method::GET, "/api/v1/tally/findings"),
        ] {
            assert!(!admin_only(&method, path), "{method} {path}");
        }
    }

    #[test]
    fn registration_requires_a_separate_last_name() {
        assert!(validated_names("Ada", "").is_err());
        assert!(validated_names("Ada", "  ").is_err());
        assert_eq!(
            validated_names(" Ada ", " van Rossum ").unwrap(),
            ("Ada", "van Rossum")
        );
    }

    #[test]
    fn collector_token_only_authorizes_import_posts() {
        let token = SecretCipher::from_hex(&"a".repeat(64))
            .expect("test key")
            .collector_import_token();
        let mut headers = HeaderMap::new();
        assert!(!collector_import_authorized(
            &Method::POST,
            "/api/v1/tally/imports",
            &headers,
            &token,
        ));
        headers.insert("x-tally-collector-token", HeaderValue::from_static("wrong"));
        assert!(!collector_import_authorized(
            &Method::POST,
            "/api/v1/tally/imports",
            &headers,
            &token,
        ));
        headers.insert(
            "x-tally-collector-token",
            HeaderValue::from_str(&token).expect("token header"),
        );
        for path in ["/api/v1/tally/imports/preview", "/api/v1/tally/imports"] {
            assert!(collector_import_authorized(
                &Method::POST,
                path,
                &headers,
                &token,
            ));
        }
        assert!(!collector_import_authorized(
            &Method::GET,
            "/api/v1/tally/imports",
            &headers,
            &token,
        ));
        assert!(!collector_import_authorized(
            &Method::POST,
            "/api/v1/tally/connectors/schedules",
            &headers,
            &token,
        ));
    }
}
