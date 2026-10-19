//! Trusted browser origins for the privileged loopback API.

fn validate_web_origin(web: &str) -> anyhow::Result<()> {
    let url = url::Url::parse(web)?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.host().is_some_and(|host| match host {
                url::Host::Domain(name) => name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
                _ => true,
            })
            && url.origin().ascii_serialization() == web,
        "Upgrade web origins must be HTTP or HTTPS origins"
    );
    Ok(())
}

pub(crate) fn web_origins(web: &str) -> anyhow::Result<Vec<String>> {
    validate_web_origin(web)?;
    Ok(if web == "http://127.0.0.1:8080" {
        vec![web.into(), "http://localhost:8080".into()]
    } else {
        vec![web.into()]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_origin_is_explicit_and_cannot_weaken_the_api_boundary() {
        assert_eq!(
            web_origins("http://127.0.0.1:18080").unwrap(),
            vec!["http://127.0.0.1:18080"]
        );
        assert_eq!(
            web_origins("http://127.0.0.1:8080").unwrap(),
            vec!["http://127.0.0.1:8080", "http://localhost:8080"]
        );
        assert_eq!(
            web_origins("https://localhost").unwrap(),
            vec!["https://localhost"]
        );
        for invalid in [
            "*",
            "https://*.example",
            "http://127.0.0.1:8080/other",
            "http://127.0.0.1:8080;evil",
            "http://user@localhost:8080",
            "https://localhost\n; frame-ancestors *",
        ] {
            assert!(web_origins(invalid).is_err(), "{invalid}");
        }
    }
}
