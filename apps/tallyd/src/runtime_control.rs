//! Host-local upgrade controls. These files are writable only by the Tally operator.
use anyhow::Result;
use axum::Router;
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

static WRITES: AtomicUsize = AtomicUsize::new(0);

pub struct WriteGuard;
impl WriteGuard {
    pub fn new() -> Self {
        WRITES.fetch_add(1, Ordering::SeqCst);
        Self
    }
}
impl Drop for WriteGuard {
    fn drop(&mut self) {
        WRITES.fetch_sub(1, Ordering::SeqCst);
    }
}
pub fn writes_drained() -> bool {
    WRITES.load(Ordering::SeqCst) == 0
}

pub fn marker(name: &str) -> PathBuf {
    std::env::var_os("TALLY_MAINTENANCE_DIR")
        .map_or_else(
            || {
                std::env::var_os("TALLY_DATA_DIR").map_or_else(
                    || PathBuf::from(".local/tally-maintenance"),
                    |dir| PathBuf::from(dir).join("maintenance"),
                )
            },
            PathBuf::from,
        )
        .join(name)
}

pub async fn serve(bind: SocketAddr, app: Router) -> Result<()> {
    let tls = match (
        std::env::var("TALLY_TLS_CERT_FILE").ok(),
        std::env::var("TALLY_TLS_KEY_FILE").ok(),
    ) {
        (Some(cert), Some(key)) => {
            Some(axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?)
        }
        (None, None) => None,
        _ => anyhow::bail!("set both TALLY_TLS_CERT_FILE and TALLY_TLS_KEY_FILE"),
    };
    serve_controlled(bind, app, tls, marker("")).await
}

async fn serve_controlled(
    bind: SocketAddr,
    app: Router,
    tls: Option<axum_server::tls_rustls::RustlsConfig>,
    control: PathBuf,
) -> Result<()> {
    loop {
        if control.join("retired").is_file() {
            return Ok(());
        }
        if control.join("http-paused").is_file() {
            tokio::select! {
                () = crate::shutdown_signal() => return Ok(()),
                () = tokio::time::sleep(Duration::from_millis(200)) => (),
            }
            continue;
        }
        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        let app = app.clone();
        let tls = tls.clone();
        let server = async move {
            tracing::info!(%bind, https = tls.is_some(), "starting Tally listener");
            if let Some(tls) = tls {
                axum_server::bind_rustls(bind, tls)
                    .handle(server_handle)
                    .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                    .await
            } else {
                axum_server::bind(bind)
                    .handle(server_handle)
                    .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                    .await
            }
        };
        tokio::pin!(server);
        let pause = async {
            loop {
                if control.join("http-paused").is_file() || control.join("retired").is_file() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        };
        let shutdown = tokio::select! {
            result = &mut server => { result?; return Ok(()); },
            () = pause => false,
            () = crate::shutdown_signal() => true,
        };
        handle.graceful_shutdown(Some(Duration::from_secs(5)));
        server.await?;
        if shutdown {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn ready(client: &reqwest::Client, url: &str) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if client
                    .get(url)
                    .header("connection", "close")
                    .send()
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn releases_and_restores_the_public_port_then_retires_cleanly() {
        let control =
            std::env::temp_dir().join(format!("tally-listener-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&control).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let bind = listener.local_addr().unwrap();
        drop(listener);
        let app = Router::new().route("/", axum::routing::get(|| async { "ready" }));
        let server = tokio::spawn(serve_controlled(bind, app, None, control.clone()));
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(200))
            .build()
            .unwrap();
        let url = format!("http://{bind}/");
        ready(&client, &url).await;
        std::fs::write(control.join("http-paused"), "").unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if std::net::TcpListener::bind(bind).is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            !server.is_finished(),
            "upgrade host work must survive the public port handoff"
        );
        std::fs::remove_file(control.join("http-paused")).unwrap();
        ready(&client, &url).await;
        std::fs::write(control.join("retired"), "").unwrap();
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        std::fs::remove_dir_all(control).unwrap();
    }
}
