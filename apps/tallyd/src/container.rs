//! Container bootstrap and readiness without a shell or external executables.
use anyhow::{Context, Result, ensure};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
#[cfg(any(target_os = "linux", test))]
use std::fs;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DATA: &str = "/data";

fn origin(value: &str) -> Result<(url::Url, String)> {
    let url = url::Url::parse(value).context("parse TALLY_URL")?;
    ensure!(
        url.scheme() == "https" && url.origin().ascii_serialization() == value,
        "TALLY_URL must be an HTTPS origin without a path"
    );
    let host = url.host_str().context("TALLY_URL has no hostname")?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    Ok((url, host))
}

#[cfg(any(target_os = "linux", test))]
fn validate_pair(cert: &Path, key: &Path, host: &str) -> Result<()> {
    use rustls::pki_types::PrivateKeyDer;
    use std::time::{SystemTime, UNIX_EPOCH};
    use x509_cert::der::Decode;
    let chain = CertificateDer::pem_file_iter(cert)
        .context("read TLS certificate")?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let leaf = chain.first().context("TLS certificate file is empty")?;
    let name = ServerName::try_from(host)?;
    webpki::EndEntityCert::try_from(leaf)?
        .verify_is_valid_for_subject_name(&name)
        .with_context(|| format!("Tally certificate does not cover {host}"))?;
    let parsed = x509_cert::Certificate::from_der(leaf)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    ensure!(
        now >= parsed
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            && now < parsed.tbs_certificate.validity.not_after.to_unix_duration(),
        "Tally certificate has expired or is not yet valid; check the certificate and system clock"
    );
    let key = PrivateKeyDer::from_pem_file(key).context("read unencrypted TLS private key")?;
    rustls::sign::CertifiedKey::from_der(
        chain,
        key,
        &rustls::crypto::aws_lc_rs::default_provider(),
    )
    .context("Tally certificate and key do not match")?;
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn prepare_tls(data: &Path, supplied: &Path, host: &str) -> Result<(PathBuf, PathBuf)> {
    let tls = data.join("tls");
    fs::create_dir_all(&tls)?;
    let source_cert = supplied.join("tally.crt");
    let source_key = supplied.join("tally.key");
    let staged = tls.join("supplied");
    if source_cert.try_exists()? || source_key.try_exists()? {
        validate_pair(&source_cert, &source_key, host).context(
            "invalid supplied TLS files; provide both /tls/tally.crt and /tls/tally.key",
        )?;
        fs::create_dir_all(&staged)?;
        let cert = staged.join("tally.crt");
        let key = staged.join("tally.key");
        write_private(&key, &fs::read(source_key)?)?;
        fs::write(&cert, fs::read(source_cert)?)?;
        eprintln!(
            "Using the supplied Tally TLS certificate: {}",
            cert.display()
        );
        return Ok((cert, key));
    }
    if staged.exists() {
        fs::remove_dir_all(staged)?;
    }
    let cert = tls.join("tally.crt");
    let key = tls.join("tally.key");
    if validate_pair(&cert, &key, host).is_err() {
        let mut params = rcgen::CertificateParams::new(vec![
            host.to_owned(),
            "localhost".into(),
            "127.0.0.1".into(),
            "::1".into(),
        ])?;
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3650);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let pair = rcgen::KeyPair::generate()?;
        let certificate = params.self_signed(&pair)?;
        write_private(&key, pair.serialize_pem().as_bytes())?;
        fs::write(&cert, certificate.pem())?;
        eprintln!(
            "Created Tally's local browser certificate in {}.",
            tls.display()
        );
    }
    validate_pair(&cert, &key, host)?;
    eprintln!(
        "Your browser will show a certificate warning because this certificate was created on your computer."
    );
    eprintln!("Check that you opened your Tally address before accepting the warning.");
    Ok((cert, key))
}

/// Runs before Tokio starts: stage root-readable keys, drop all groups/UID/GID, then exec.
#[cfg(target_os = "linux")]
pub fn run() -> Result<()> {
    use nix::unistd::{Gid, Uid, geteuid, setgid, setgroups, setuid};
    use std::os::unix::{fs::chown, process::CommandExt};
    let (_, host) =
        origin(&std::env::var("TALLY_URL").unwrap_or_else(|_| "https://localhost:2357".into()))?;
    let data = Path::new(DATA);
    let (cert, key) = prepare_tls(data, Path::new("/tls"), &host)?;
    if geteuid().is_root() {
        for path in [data, &data.join("tls"), cert.parent().unwrap(), &cert, &key] {
            chown(path, Some(65532), Some(65532)).context("set container data ownership")?;
        }
        setgroups(&[]).context("clear container supplementary groups")?;
        setgid(Gid::from_raw(65532)).context("drop container group")?;
        setuid(Uid::from_raw(65532)).context("drop container user")?;
    }
    let error = std::process::Command::new(std::env::current_exe()?)
        .env("TALLY_TLS_CERT_FILE", cert)
        .env("TALLY_TLS_KEY_FILE", key)
        .exec();
    Err(error).context("start Tally after preparing container TLS")
}

#[cfg(not(target_os = "linux"))]
pub fn run() -> Result<()> {
    anyhow::bail!("the container command requires Linux")
}

pub async fn healthcheck() -> Result<()> {
    let (url, host) =
        origin(&std::env::var("TALLY_URL").unwrap_or_else(|_| "https://localhost:2357".into()))?;
    let bind: SocketAddr = std::env::var("TALLY_HTTP_BIND")
        .unwrap_or_else(|_| "0.0.0.0:2357".into())
        .parse()
        .context("parse TALLY_HTTP_BIND")?;
    let ip = if bind.ip().is_unspecified() {
        if bind.is_ipv6() {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        }
    } else {
        bind.ip()
    };
    let cert = std::env::var_os("TALLY_TLS_CERT_FILE").map_or_else(
        || {
            let supplied = PathBuf::from(DATA).join("tls/supplied/tally.crt");
            if supplied.is_file() {
                supplied
            } else {
                PathBuf::from(DATA).join("tls/tally.crt")
            }
        },
        PathBuf::from,
    );
    probe(&url, &host, SocketAddr::new(ip, bind.port()), &cert).await
}

async fn probe(url: &url::Url, host: &str, address: SocketAddr, cert: &Path) -> Result<()> {
    // Connect directly: public DNS, published ports and HTTP(S)_PROXY cannot redirect this probe.
    // Preserve the public hostname for certificate verification, including public IP addresses.
    tokio::time::timeout(Duration::from_secs(8), async {
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_file_iter(cert).context("read readiness TLS certificate")? {
            roots.add(cert?)?;
        }
        let config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        let tcp = tokio::net::TcpStream::connect(address).await
            .with_context(|| format!("Tally is not listening at {address}; inspect docker compose logs tallyd for startup progress"))?;
        let mut stream = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(host.to_owned())?, tcp).await
            .context("readiness TLS verification failed")?;
        let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
        stream.write_all(format!("GET /api/v1/tally/health/ready HTTP/1.0\r\nHost: {authority}\r\nConnection: close\r\n\r\n").as_bytes()).await?;
        let mut response = String::new();
        stream.take(16 * 1024).read_to_string(&mut response).await?;
        let (headers, body) = response.split_once("\r\n\r\n").context("invalid readiness HTTP response")?;
        let status = headers.lines().next().context("missing readiness HTTP status")?;
        ensure!(status.split_whitespace().nth(1) == Some("200"), "Tally readiness failed: {status}: {body}");
        println!("{body}");
        Ok(())
    }).await.context("Tally readiness timed out after 8 seconds; inspect application and database logs")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("tally-tls-{}", uuid::Uuid::now_v7()));
            fs::create_dir_all(path.join("supplied")).unwrap();
            Self(path)
        }
        fn prepare(&self, host: &str) -> Result<(PathBuf, PathBuf)> {
            prepare_tls(&self.0.join("data"), &self.0.join("supplied"), host)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn reuses_existing_certificate_and_renews_for_a_new_hostname() {
        let f = Fixture::new();
        let (cert, key) = f.prepare("localhost").unwrap();
        let original = fs::read(&cert).unwrap();
        f.prepare("localhost").unwrap();
        assert_eq!(fs::read(&cert).unwrap(), original);
        f.prepare("tally.example.test").unwrap();
        assert_ne!(fs::read(&cert).unwrap(), original);
        validate_pair(&cert, &key, "tally.example.test").unwrap();
        validate_pair(&cert, &key, "::1").unwrap();
        assert_eq!(
            fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn validates_supplied_certificates_and_never_overwrites_them() {
        let f = Fixture::new();
        let (cert, key) = f.prepare("tally.example.test").unwrap();
        let supplied_cert = f.0.join("supplied/tally.crt");
        let supplied_key = f.0.join("supplied/tally.key");
        fs::copy(&cert, &supplied_cert).unwrap();
        assert!(f.prepare("tally.example.test").is_err());
        fs::copy(&key, &supplied_key).unwrap();
        let (staged, _) = f.prepare("tally.example.test").unwrap();
        assert!(staged.ends_with("tls/supplied/tally.crt"));
        assert!(f.prepare("wrong.example.test").is_err());
        fs::write(
            &supplied_key,
            rcgen::KeyPair::generate().unwrap().serialize_pem(),
        )
        .unwrap();
        assert!(f.prepare("tally.example.test").is_err());
        assert_eq!(fs::read(&supplied_cert).unwrap(), fs::read(&cert).unwrap());
        fs::remove_file(supplied_cert).unwrap();
        fs::remove_file(supplied_key).unwrap();
        assert_eq!(f.prepare("tally.example.test").unwrap().0, cert);
        assert!(!staged.exists());
    }

    #[test]
    fn rejects_expired_supplied_certificates() {
        let f = Fixture::new();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(2);
        params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        let key = rcgen::KeyPair::generate().unwrap();
        fs::write(
            f.0.join("supplied/tally.crt"),
            params.self_signed(&key).unwrap().pem(),
        )
        .unwrap();
        fs::write(f.0.join("supplied/tally.key"), key.serialize_pem()).unwrap();
        let error = f.prepare("localhost").unwrap_err();
        assert!(format!("{error:#}").contains("expired"));
    }

    #[tokio::test]
    async fn probe_uses_local_port_and_verifies_public_dns_or_ip_without_resolution() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        for host in ["unresolvable.invalid", "192.0.2.42", "::1"] {
            let f = Fixture::new();
            let (cert, key) = f.prepare(host).unwrap();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, key)
                .await
                .unwrap();
            let app = axum::Router::new().route(
                "/api/v1/tally/health/ready",
                axum::routing::get(|| async { "ready" }),
            );
            let server = tokio::spawn(async move {
                axum_server::from_tcp_rustls(listener, config)
                    .unwrap()
                    .serve(app.into_make_service())
                    .await
                    .unwrap();
            });
            let authority = if host.contains(':') {
                format!("[{host}]")
            } else {
                host.to_owned()
            };
            let (url, name) = origin(&format!("https://{authority}:9443")).unwrap();
            probe(&url, &name, address, &cert).await.unwrap();
            assert!(probe(&url, "wrong.invalid", address, &cert).await.is_err());
            server.abort();
        }
    }

    #[tokio::test]
    async fn probe_reports_connection_failure() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let f = Fixture::new();
        let (cert, _) = f.prepare("localhost").unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let (url, host) = origin("https://localhost:2357").unwrap();
        let error = probe(&url, &host, address, &cert).await.unwrap_err();
        assert!(error.to_string().contains("not listening"), "{error:#}");
    }

    #[tokio::test]
    async fn probe_reports_unhealthy_dependency_response() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let f = Fixture::new();
        let (cert, key) = f.prepare("localhost").unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, key)
            .await
            .unwrap();
        let app = axum::Router::new().route(
            "/api/v1/tally/health/ready",
            axum::routing::get(|| async {
                (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "postgres unavailable",
                )
            }),
        );
        let server = tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, config)
                .unwrap()
                .serve(app.into_make_service())
                .await
                .unwrap();
        });
        let (url, host) = origin("https://localhost:2357").unwrap();
        let error = probe(&url, &host, address, &cert).await.unwrap_err();
        assert!(error.to_string().contains("503"), "{error:#}");
        assert!(
            error.to_string().contains("postgres unavailable"),
            "{error:#}"
        );
        server.abort();
    }
}
