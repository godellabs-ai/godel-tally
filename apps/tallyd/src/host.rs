//! Administrator-only bridge to the in-process upgrade runtime.
use crate::auth;
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::any,
};
use std::sync::Arc;
use tower::ServiceExt;

#[derive(Clone)]
struct Host {
    auth: Arc<auth::AuthState>,
    routes: Router,
    token: String,
    origin: String,
}

pub fn router(auth: Arc<auth::AuthState>, service: &tally_upgrade::HostService) -> Router {
    Router::new()
        .route("/api/upgrade/{*path}", any(forward))
        .layer(axum::middleware::from_fn(auth::require_origin))
        .with_state(Host {
            auth,
            routes: service.router.clone(),
            token: service.workspace_token.clone(),
            origin: tally_upgrade::setting("WEB_ORIGIN")
                .unwrap_or_else(|_| "http://127.0.0.1:8080".into()),
        })
}

fn allowed(path: &str, method: &Method) -> bool {
    matches!(
        (method, path),
        (&Method::GET, "health" | "status")
            | (
                &Method::POST,
                "preview" | "prepare" | "cutover" | "cancel" | "reset" | "cleanup"
            )
    )
}

async fn forward(State(host): State<Host>, request: Request) -> Response {
    match auth::current_user(&host.auth, request.headers()).await {
        Ok(user) if user.role == "admin" => (),
        Ok(_) => return StatusCode::FORBIDDEN.into_response(),
        Err(error) => return error.into_response(),
    }
    let path = request.uri().path().trim_start_matches("/api/upgrade/");
    if !allowed(path, request.method()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if path == "health" {
        return Json(serde_json::json!({"ready": true})).into_response();
    }
    let target = if path == "status" {
        "/upgrade".to_owned()
    } else {
        format!("/upgrade/{path}")
    };
    let method = request.method().clone();
    let content_type = request.headers().get(header::CONTENT_TYPE).cloned();
    let Ok(body) = to_bytes(request.into_body(), 1_000_000).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let mut request = Request::builder()
        .method(method)
        .uri(target)
        .header(header::HOST, "127.0.0.1:8789")
        .header(header::ORIGIN, &host.origin)
        .header(header::AUTHORIZATION, format!("Bearer {}", host.token));
    if let Some(value) = content_type {
        request = request.header(header::CONTENT_TYPE, value);
    }
    host.routes
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn private_bearer_cannot_bypass_tally_session_or_csrf_checks() {
        let service = tally_upgrade::HostService {
            router: Router::new(),
            workspace_token: "a".repeat(64),
        };
        let app = router(crate::tests::auth_state(), &service);
        for (method, path, origin, status) in [
            ("GET", "/api/upgrade/status", "https://tally.example", 401),
            (
                "POST",
                "/api/upgrade/preview",
                "https://attacker.example",
                403,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("host", "tally.example")
                        .header("x-forwarded-proto", "https")
                        .header("origin", origin)
                        .header(
                            "authorization",
                            format!("Bearer {}", service.workspace_token),
                        )
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), status);
        }
    }

    #[test]
    fn exposes_only_upgrade_operations() {
        assert!(allowed("status", &Method::GET));
        for path in [
            "preview", "prepare", "cutover", "cancel", "reset", "cleanup",
        ] {
            assert!(allowed(path, &Method::POST));
            assert!(!allowed(path, &Method::GET));
        }
        for path in [
            "pair",
            "internal/context",
            "actions",
            "actions/preview",
            "status/anything",
        ] {
            assert!(!allowed(path, &Method::POST));
            assert!(!allowed(path, &Method::GET));
        }
    }
}
