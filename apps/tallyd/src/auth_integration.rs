//! Run only against an empty disposable database:
//! ```sh
//! TALLY_AUTH_TEST_DATABASE_URL=postgres://... TALLY_URL=https://tally.example.test \
//! cargo test -p tallyd auth_integration -- --ignored
//! ```
use std::sync::Arc;

use reqwest::{Client, Response};
use serde_json::{Value, json};
use sqlx::PgPool;
use tally_config::SecretCipher;
use tally_store_postgres::PostgresStore;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::auth;

struct Api {
    base: String,
    http: Client,
}
impl Api {
    async fn call(&self, method: &str, path: &str, cookie: &str, body: Value) -> Response {
        self.http
            .request(method.parse().unwrap(), format!("{}{path}", self.base))
            .header("origin", &self.base)
            // Browsers may send unrelated cookies before the session in another field.
            .header("cookie", "unrelated=fixture")
            .header("cookie", cookie)
            .json(&body)
            .send()
            .await
            .unwrap()
    }
    async fn login(&self, email: &str, password: &str) -> String {
        cookie(
            self.call(
                "POST",
                "/api/v1/auth/login",
                "",
                json!({"email":email,"password":password}),
            )
            .await,
        )
    }
}
#[allow(clippy::needless_pass_by_value)] // Consume the response after reading its session header.
fn cookie(response: Response) -> String {
    assert_eq!(response.status(), 200);
    let value = response.headers()["set-cookie"].to_str().unwrap();
    assert!(value.contains("HttpOnly; Secure; SameSite=Lax"));
    value.split(';').next().unwrap().to_owned()
}
async fn body(response: Response) -> Value {
    assert_eq!(response.status(), 200);
    response.json().await.unwrap()
}

async fn smtp_sink() -> (
    u16,
    tokio::sync::mpsc::Receiver<String>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, receiver) = tokio::sync::mpsc::channel(16);
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let sender = sender.clone();
            tokio::spawn(async move {
                let (read, mut write) = stream.into_split();
                let mut lines = BufReader::new(read).lines();
                write
                    .write_all(b"220 localhost test SMTP\r\n")
                    .await
                    .unwrap();
                let mut data = false;
                let mut message = String::new();
                while let Some(line) = lines.next_line().await.unwrap() {
                    if data && line != "." {
                        message.push_str(&line);
                        message.push('\n');
                        continue;
                    }
                    let reply = if data {
                        data = false;
                        sender.send(message.clone()).await.unwrap();
                        "250 accepted\r\n"
                    } else if line.starts_with("EHLO") {
                        "250-localhost\r\n250 8BITMIME\r\n"
                    } else if line == "DATA" {
                        data = true;
                        "354 send message\r\n"
                    } else if line == "QUIT" {
                        "221 bye\r\n"
                    } else {
                        "250 OK\r\n"
                    };
                    write.write_all(reply.as_bytes()).await.unwrap();
                    if line == "QUIT" {
                        break;
                    }
                }
            });
        }
    });
    (port, receiver, task)
}

#[tokio::test]
#[ignore = "requires an empty disposable PostgreSQL database and TALLY_URL"]
#[allow(clippy::too_many_lines)]
async fn auth_integration() {
    let url = std::env::var("TALLY_AUTH_TEST_DATABASE_URL").unwrap();
    assert_eq!(
        crate::email::public_url().as_deref(),
        Some("https://tally.example.test")
    );
    let pool = PgPool::connect(&url).await.unwrap();
    let tables: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        tables, 0,
        "Use an empty disposable database, never an existing installation"
    );
    let store = Arc::new(PostgresStore::connect(&url).await.unwrap());
    store.migrate().await.unwrap();
    let mut migrations = sqlx::migrate!("./migrations");
    migrations.dangerous_set_table_name("tally_auth_migrations");
    migrations.run(&pool).await.unwrap();
    let state = Arc::new(auth::AuthState {
        pool: pool.clone(),
        cipher: SecretCipher::from_bytes([7; 32]),
        collector_import_token: "collector-fixture".into(),
        http: Client::new(),
    });
    let tally = tally_api::state_from_store(store.clone(), state.cipher.clone())
        .await
        .unwrap();
    let host = tally_upgrade::HostService {
        router: axum::Router::new().route(
            "/upgrade",
            axum::routing::get(|| async { axum::Json(json!({"status": "not_started"})) }),
        ),
        workspace_token: "a".repeat(64),
    };
    let app = tally_api::router(tally)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_session,
        ))
        .merge(auth::router(state.clone()))
        .merge(crate::host::router(state.clone(), &host));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = Api {
        base: format!("http://{}", listener.local_addr().unwrap()),
        http: Client::new(),
    };
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Every currently registered Tally API route rejects an anonymous request.
    // Derive paths from the actual route declarations so additions join this audit.
    for source in [include_str!("../../../crates/tally-api/src/lib.rs")] {
        for part in source.split(".route(").skip(1) {
            let Some(path) = part.split('"').nth(1) else {
                continue;
            };
            if !path.starts_with("/api/v1/tally/") || path.contains("/health/") {
                continue;
            }
            let mut path = path.to_owned();
            while let Some(start) = path.find('{') {
                let end = path[start..].find('}').unwrap() + start;
                path.replace_range(start..=end, "00000000-0000-0000-0000-000000000001");
            }
            // Select the declared method for each route.
            let method = if part.split(')').next().unwrap_or("").contains("get(") {
                "GET"
            } else {
                "POST"
            };
            let response = api.call(method, &path, "", json!({})).await;
            assert_eq!(response.status(), 401, "anonymous {method} {path}");
        }
    }
    assert_eq!(
        api.call("GET", "/api/v1/tally/health/live", "", json!({}))
            .await
            .status(),
        200
    );
    for path in ["me", "users", "email"] {
        assert_eq!(
            api.call("GET", &format!("/api/v1/auth/{path}"), "", json!({}))
                .await
                .status(),
            401
        );
    }
    for (path, input) in [
        (
            "/api/v1/auth/me",
            json!({"first_name":"Test","last_name":"User"}),
        ),
        (
            "/api/v1/auth/me/password",
            json!({"current_password":"old-password","new_password":"new-password-123"}),
        ),
        (
            "/api/v1/auth/invitations",
            json!({"email":"new@example.test"}),
        ),
        (
            "/api/v1/auth/email",
            json!({"provider":"smtp","enabled":true,"from_email":"a@example.test"}),
        ),
        ("/api/v1/auth/email/test", json!({"to":"a@example.test"})),
        (
            "/api/v1/auth/users/00000000-0000-0000-0000-000000000001",
            json!({"disabled":true}),
        ),
        (
            "/api/v1/auth/users/00000000-0000-0000-0000-000000000001/name",
            json!({"first_name":"Test","last_name":"User"}),
        ),
        (
            "/api/v1/auth/users/00000000-0000-0000-0000-000000000001/password-reset",
            json!({}),
        ),
    ] {
        assert_eq!(
            api.call("POST", path, "", input).await.status(),
            401,
            "anonymous {path}"
        );
    }
    let status = body(api.call("GET", "/api/v1/auth/status", "", json!({})).await).await;
    assert_eq!(status["first_user_registration_open"], true);
    assert_eq!(status["email_configured"], false);
    let registration = |email: &str| json!({"email":email,"first_name":"Test","last_name":"User","password":"initial-password-123"});
    // Only one concurrent first-user registration may become administrator.
    let (one, two) = tokio::join!(
        api.call(
            "POST",
            "/api/v1/auth/register",
            "",
            registration("admin@example.test")
        ),
        api.call(
            "POST",
            "/api/v1/auth/register",
            "",
            registration("other@example.test")
        )
    );
    let (_admin_email, admin_cookie) = if one.status() == 200 {
        assert_eq!(two.status(), 403);
        ("admin@example.test", cookie(one))
    } else {
        assert_eq!(one.status(), 403);
        ("other@example.test", cookie(two))
    };
    for path in ["sso", "sso/start", "sso/callback", "oidc"] {
        assert_eq!(
            api.call(
                "GET",
                &format!("/api/v1/auth/{path}"),
                &admin_cookie,
                json!({})
            )
            .await
            .status(),
            404
        );
    }
    let admin_me = body(
        api.call("GET", "/api/v1/auth/me", &admin_cookie, json!({}))
            .await,
    )
    .await;
    assert_eq!(admin_me["user"]["role"], "admin");
    let invitation = body(
        api.call(
            "POST",
            "/api/v1/auth/invitations",
            &admin_cookie,
            json!({"email":"member@example.test"}),
        )
        .await,
    )
    .await;
    let invite = invitation["invite_url"]
        .as_str()
        .unwrap()
        .split("#invite=")
        .nth(1)
        .unwrap();
    let mut member_registration = registration("member@example.test");
    member_registration["invitation_token"] = json!(invite);
    let member = cookie(
        api.call(
            "POST",
            "/api/v1/auth/register",
            "",
            member_registration.clone(),
        )
        .await,
    );
    assert_eq!(
        api.call("POST", "/api/v1/auth/register", "", member_registration)
            .await
            .status(),
        403
    );
    let member_me = body(api.call("GET", "/api/v1/auth/me", &member, json!({})).await).await;
    assert_eq!(member_me["user"]["role"], "member");
    let member_id = member_me["user"]["id"].as_str().unwrap();
    for (session, expected) in [("", 401), (&member, 403), (&admin_cookie, 200)] {
        assert_eq!(
            api.call("GET", "/api/upgrade/status", session, json!({}))
                .await
                .status()
                .as_u16(),
            expected
        );
    }
    assert_eq!(
        api.call("GET", "/api/v1/tally/overview", &member, json!({}))
            .await
            .status(),
        200
    );
    for path in [
        "/api/v1/auth/users",
        "/api/v1/auth/email",
        "/api/v1/tally/audit",
        "/api/v1/tally/data",
        "/api/v1/tally/connectors/00000000-0000-0000-0000-000000000001/configuration",
    ] {
        assert_eq!(
            api.call("GET", path, &member, json!({})).await.status(),
            403,
            "member {path}"
        );
    }
    assert_eq!(
        api.call(
            "POST",
            "/api/v1/auth/email",
            &member,
            json!({"provider":"resend","enabled":true,"from_email":"a@example.test"})
        )
        .await
        .status(),
        403
    );
    assert_eq!(
        api.http
            .post(format!("{}/api/v1/auth/logout", api.base))
            .header("cookie", &member)
            .header("origin", "https://attacker.example")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    // Malformed or unsuccessful sign-in cannot preserve a previous session.
    assert_eq!(
        api.call("POST", "/api/v1/auth/login", &member, json!({}))
            .await
            .status(),
        400
    );
    assert_eq!(
        api.call("GET", "/api/v1/tally/overview", &member, json!({}))
            .await
            .status(),
        401
    );
    let member = api
        .login("member@example.test", "initial-password-123")
        .await;
    assert_eq!(
        api.call(
            "POST",
            "/api/v1/auth/login",
            &member,
            json!({"email":"member@example.test","password":"incorrect"})
        )
        .await
        .status(),
        401
    );
    assert_eq!(
        api.call("GET", "/api/v1/tally/overview", &member, json!({}))
            .await
            .status(),
        401
    );
    for _ in 0..4 {
        assert_eq!(
            api.call(
                "POST",
                "/api/v1/auth/login",
                "",
                json!({"email":"member@example.test","password":"incorrect"})
            )
            .await
            .status(),
            401
        );
    }
    assert_eq!(
        api.call(
            "POST",
            "/api/v1/auth/login",
            "",
            json!({"email":"member@example.test","password":"initial-password-123"})
        )
        .await
        .status(),
        401
    );
    sqlx::query("UPDATE tally_auth_users SET locked_until = NOW() - INTERVAL '1 second' WHERE email = 'member@example.test'").execute(&pool).await.unwrap();
    let member = api
        .login("member@example.test", "initial-password-123")
        .await;

    let (smtp_port, mut mail, smtp_task) = smtp_sink().await;
    let smtp = json!({"provider":"smtp","enabled":true,"from_email":"tally@example.test","settings":{"host":"127.0.0.1","port":smtp_port.to_string(),"security":"none"}});
    body(
        api.call("POST", "/api/v1/auth/email", &admin_cookie, smtp.clone())
            .await,
    )
    .await;
    // Simultaneous requests send only one link, always using the configured URL.
    let (one, two) = tokio::join!(
        api.call(
            "POST",
            "/api/v1/auth/password-reset/request",
            "",
            json!({"email":"member@example.test"})
        ),
        api.call(
            "POST",
            "/api/v1/auth/password-reset/request",
            "",
            json!({"email":"member@example.test"})
        )
    );
    assert_eq!(body(one).await, body(two).await);
    let message = tokio::time::timeout(std::time::Duration::from_secs(5), mail.recv())
        .await
        .unwrap()
        .unwrap();
    let message = message.replace("=\n", "").replace("=3D", "=");
    let token = message
        .split("https://tally.example.test/reset-password#token=")
        .nth(1)
        .unwrap()
        .chars()
        .take(64)
        .collect::<String>();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), mail.recv())
            .await
            .is_err()
    );
    let reset = json!({"token":token,"new_password":"replacement-password-123"});
    assert_eq!(
        api.call(
            "POST",
            "/api/v1/auth/password-reset/confirm",
            "",
            reset.clone()
        )
        .await
        .status(),
        204
    );
    assert_eq!(
        api.call("POST", "/api/v1/auth/password-reset/confirm", "", reset)
            .await
            .status(),
        400
    );
    assert_eq!(
        api.call("GET", "/api/v1/auth/me", &member, json!({}))
            .await
            .status(),
        401
    );
    assert_eq!(
        api.call(
            "POST",
            "/api/v1/auth/login",
            "",
            json!({"email":"member@example.test","password":"initial-password-123"})
        )
        .await
        .status(),
        401
    );
    let member = api
        .login("member@example.test", "replacement-password-123")
        .await;
    // Disable saved email and verify that self-service reset requests stop.
    let mut disabled = smtp;
    disabled["enabled"] = json!(false);
    body(
        api.call("POST", "/api/v1/auth/email", &admin_cookie, disabled)
            .await,
    )
    .await;
    assert_eq!(
        api.call(
            "POST",
            "/api/v1/auth/password-reset/request",
            "",
            json!({"email":"member@example.test"})
        )
        .await
        .status(),
        503
    );
    let issued = body(
        api.call(
            "POST",
            &format!("/api/v1/auth/users/{member_id}/password-reset"),
            &admin_cookie,
            json!({}),
        )
        .await,
    )
    .await;
    let pending = issued["reset_url"]
        .as_str()
        .unwrap()
        .split("#token=")
        .nth(1)
        .unwrap();
    assert_eq!(api.call("POST", "/api/v1/auth/me/password", &member, json!({"current_password":"replacement-password-123","new_password":"changed-password-123"})).await.status(), 204);
    assert_eq!(
        api.call(
            "POST",
            "/api/v1/auth/password-reset/confirm",
            "",
            json!({"token":pending,"new_password":"unwanted-password-123"})
        )
        .await
        .status(),
        400
    );
    let config = json!({"provider":"resend","enabled":true,"from_email":"tally@example.test","secrets":{"api_key":"fixture-secret-never-send"}});
    let view = body(
        api.call("POST", "/api/v1/auth/email", &admin_cookie, config)
            .await,
    )
    .await;
    assert!(!view.to_string().contains("fixture-secret-never-send"));
    let encrypted: Vec<u8> = sqlx::query_scalar("SELECT secret_ciphertext FROM tally_email_config")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&encrypted).contains("fixture-secret-never-send"));
    assert_eq!(
        api.call(
            "POST",
            &format!("/api/v1/auth/users/{member_id}"),
            &admin_cookie,
            json!({"disabled":true})
        )
        .await
        .status(),
        204
    );
    assert_eq!(
        api.call("GET", "/api/v1/auth/me", &member, json!({}))
            .await
            .status(),
        401
    );
    assert_eq!(
        api.call("POST", "/api/v1/auth/logout", &admin_cookie, json!({}))
            .await
            .status(),
        204
    );
    assert_eq!(
        api.call("GET", "/api/v1/tally/overview", &admin_cookie, json!({}))
            .await
            .status(),
        401
    );
    server.abort();
    smtp_task.abort();
    pool.close().await;
}
