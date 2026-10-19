//! The production console is compiled into tallyd; no filesystem or Node server is needed.
use axum::{
    body::Body,
    http::{Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};

include!(concat!(env!("OUT_DIR"), "/ui.rs"));

pub fn router(auth: std::sync::Arc<crate::auth::AuthState>) -> axum::Router {
    axum::Router::new()
        .fallback(serve_authenticated)
        .with_state(auth)
}

async fn serve_authenticated(
    axum::extract::State(auth): axum::extract::State<std::sync::Arc<crate::auth::AuthState>>,
    method: Method,
    uri: Uri,
    headers: axum::http::HeaderMap,
) -> Response {
    let public = matches!(
        uri.path(),
        "/signin" | "/forgot-password" | "/reset-password"
    );
    if !public
        && asset(uri.path()).is_some_and(|(_, mime)| mime.starts_with("text/html"))
        && let Err((status, body)) = crate::auth::current_user(&auth, &headers).await
    {
        return if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
            (
                [(header::CACHE_CONTROL, "no-store")],
                axum::response::Redirect::to("/signin"),
            )
                .into_response()
        } else {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::CACHE_CONTROL, "no-store")],
                body,
            )
                .into_response()
        };
    }
    serve(&method, &uri)
}

fn asset(path: &str) -> Option<(&'static [u8], &'static str)> {
    if path.starts_with("/api/") || path.split('/').any(|part| part == ".." || part == ".") {
        return None;
    }
    let path = path.trim_start_matches('/');
    let html = if path.is_empty() {
        "index.html".into()
    } else {
        format!("{}.html", path.trim_end_matches('/'))
    };
    ASSETS
        .iter()
        .find(|(name, _)| *name == path || *name == html)
        .map(|(name, bytes)| (*bytes, content_type(name)))
}

fn content_type(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        _ => "application/octet-stream",
    }
}

pub fn serve(method: &Method, uri: &Uri) -> Response {
    if *method != Method::GET && *method != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let Some((bytes, mime)) = asset(uri.path()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let cache = if uri.path().starts_with("/_next/static/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    Response::builder()
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, cache)
        .header("x-content-type-options", "nosniff")
        .header(header::CONTENT_LENGTH, bytes.len())
        .body(if *method == Method::HEAD {
            Body::empty()
        } else {
            Body::from(bytes)
        })
        .unwrap()
}

#[cfg(all(test, feature = "embedded-ui"))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn anonymous_pages_redirect_to_signin_and_assets_remain_public() {
        use tower::ServiceExt;
        let app = router(crate::tests::auth_state());
        for (path, status) in [
            ("/", 303),
            ("/settings", 303),
            ("/signin", 200),
            ("/favicon-dark.svg", 200),
            ("/api/missing", 404),
        ] {
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), status, "{path}");
            if status == 303 {
                assert_eq!(response.headers()[header::LOCATION], "/signin");
            }
        }
    }

    #[tokio::test]
    async fn serves_pages_and_assets_without_masking_missing_api_routes() {
        for path in [
            "/",
            "/signin",
            "/connectors/",
            "/reset-password",
            "/favicon-dark.svg",
        ] {
            assert_eq!(
                serve(&Method::GET, &path.parse().unwrap()).status(),
                StatusCode::OK,
                "{path}"
            );
        }
        for path in ["/api/missing", "/missing.js", "/../index.html"] {
            assert_eq!(
                serve(&Method::GET, &path.parse().unwrap()).status(),
                StatusCode::NOT_FOUND
            );
        }
        let head = serve(&Method::HEAD, &"/".parse().unwrap());
        assert!(
            axum::body::to_bytes(head.into_body(), 1)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            serve(&Method::POST, &"/".parse().unwrap()).status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        let script = ASSETS
            .iter()
            .find(|(path, _)| {
                path.starts_with("_next/static/")
                    && std::path::Path::new(path)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("js"))
            })
            .unwrap();
        let response = serve(&Method::GET, &format!("/{}", script.0).parse().unwrap());
        assert!(
            response.headers()[header::CACHE_CONTROL]
                .to_str()
                .unwrap()
                .contains("immutable")
        );
    }
}
