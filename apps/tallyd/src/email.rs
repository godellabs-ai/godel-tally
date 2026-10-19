//! Outbound email for standalone Tally: SMTP, AWS SES,
//! `SendGrid`, Mailgun, Postmark and Resend. An administrator configures delivery in
//! Settings; environment variables are the fallback. Provider credentials are encrypted
//! with `TALLY_SECRET_KEY` and never returned to a browser.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use tally_config::SecretCipher;
use uuid::Uuid;

pub(crate) const PROVIDERS: [&str; 6] =
    ["smtp", "ses", "sendgrid", "mailgun", "postmark", "resend"];

/// Non-secret and secret field names for each provider. Only these fields are stored.
fn fields(provider: &str) -> (&'static [&'static str], &'static [&'static str]) {
    match provider {
        "smtp" => (&["host", "port", "username", "security"], &["password"]),
        "ses" => (&["region"], &["access_key_id", "secret_access_key"]),
        "mailgun" => (&["domain", "region"], &["api_key"]),
        "postmark" => (&[], &["server_token"]),
        "sendgrid" | "resend" => (&[], &["api_key"]),
        _ => (&[], &[]),
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EmailConfig {
    pub(crate) provider: String,
    pub(crate) from_email: String,
    pub(crate) from_name: Option<String>,
    settings: BTreeMap<String, String>,
    secrets: BTreeMap<String, String>,
}

impl EmailConfig {
    fn setting(&self, name: &str) -> &str {
        self.settings.get(name).map_or("", String::as_str)
    }
    fn secret(&self, name: &str) -> &str {
        self.secrets.get(name).map_or("", String::as_str)
    }
    fn sender(&self) -> String {
        match &self.from_name {
            Some(name) => format!("{name} <{}>", self.from_email),
            None => self.from_email.clone(),
        }
    }
}

/// The admin-facing view: which fields are set, never their secret values.
#[derive(Serialize)]
pub(crate) struct EmailView {
    configured: bool,
    source: Option<&'static str>,
    enabled: bool,
    provider: String,
    from_email: String,
    from_name: Option<String>,
    settings: BTreeMap<String, String>,
    secrets_set: Vec<String>,
    public_url_configured: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EmailInput {
    provider: String,
    enabled: bool,
    from_email: String,
    from_name: Option<String>,
    #[serde(default)]
    settings: BTreeMap<String, String>,
    /// An omitted or empty secret keeps the saved value for the same provider.
    #[serde(default)]
    secrets: BTreeMap<String, String>,
}

/// The public console URL used in emailed links, from `TALLY_URL`.
pub(crate) fn public_url() -> Option<String> {
    let value = std::env::var("TALLY_URL").ok()?;
    let url = url::Url::parse(value.trim()).ok()?;
    (matches!(url.scheme(), "http" | "https") && url.host_str().is_some())
        .then(|| url.origin().ascii_serialization())
}

struct Stored {
    enabled: bool,
    config: EmailConfig,
}

async fn stored(pool: &PgPool, cipher: &SecretCipher) -> anyhow::Result<Option<Stored>> {
    let Some(row) = sqlx::query(
        "SELECT provider, enabled, from_email, from_name, settings, secret_nonce, secret_ciphertext
         FROM tally_email_config WHERE singleton",
    )
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };
    let settings: BTreeMap<String, String> =
        serde_json::from_value(row.get::<Value, _>("settings"))?;
    let secrets = match (
        row.get::<Option<Vec<u8>>, _>("secret_nonce"),
        row.get::<Option<Vec<u8>>, _>("secret_ciphertext"),
    ) {
        (Some(nonce), Some(ciphertext)) => {
            serde_json::from_str(&cipher.decrypt(&nonce, &ciphertext)?)?
        }
        _ => BTreeMap::new(),
    };
    Ok(Some(Stored {
        enabled: row.get("enabled"),
        config: EmailConfig {
            provider: row.get("provider"),
            from_email: row.get("from_email"),
            from_name: row.get("from_name"),
            settings,
            secrets,
        },
    }))
}

/// Delivery configured through Gate-compatible environment variables.
fn from_env() -> Option<EmailConfig> {
    let env = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
    let provider = env("EMAIL_PROVIDER")?.to_ascii_lowercase();
    if !PROVIDERS.contains(&provider.as_str())
        || !env("EMAIL_ENABLED").is_some_and(|v| v.eq_ignore_ascii_case("true"))
    {
        return None;
    }
    let from_email = [
        "EMAIL_FROM",
        "SMTP_FROM",
        "AWS_SES_FROM",
        "SENDGRID_FROM",
        "MAILGUN_FROM",
        "POSTMARK_FROM",
        "RESEND_FROM",
    ]
    .into_iter()
    .find_map(env)?;
    let mut settings = BTreeMap::new();
    let mut secrets = BTreeMap::new();
    let put = |map: &mut BTreeMap<String, String>, key: &str, var: &str| {
        if let Some(value) = env(var) {
            map.insert(key.to_owned(), value);
        }
    };
    match provider.as_str() {
        "smtp" => {
            put(&mut settings, "host", "SMTP_HOST");
            put(&mut settings, "port", "SMTP_PORT");
            put(&mut settings, "username", "SMTP_USER");
            put(&mut secrets, "password", "SMTP_PASSWORD");
            let tls = env("SMTP_TLS").is_none_or(|v| !v.eq_ignore_ascii_case("false"));
            settings.insert(
                "security".into(),
                if tls { "starttls" } else { "none" }.into(),
            );
        }
        "ses" => {
            put(&mut settings, "region", "AWS_SES_REGION");
            put(&mut secrets, "access_key_id", "AWS_SES_ACCESS_KEY_ID");
            put(
                &mut secrets,
                "secret_access_key",
                "AWS_SES_SECRET_ACCESS_KEY",
            );
        }
        "sendgrid" => put(&mut secrets, "api_key", "SENDGRID_API_KEY"),
        "mailgun" => {
            put(&mut settings, "domain", "MAILGUN_DOMAIN");
            put(&mut secrets, "api_key", "MAILGUN_API_KEY");
        }
        "postmark" => put(&mut secrets, "server_token", "POSTMARK_SERVER_TOKEN"),
        _ => put(&mut secrets, "api_key", "RESEND_API_KEY"),
    }
    merged(
        EmailInput {
            provider,
            enabled: true,
            from_email,
            from_name: env("EMAIL_FROM_NAME"),
            settings,
            secrets,
        },
        None,
    )
    .ok()
}

/// Saved settings take precedence, including an explicit disable. Environment is the initial fallback.
pub(crate) async fn active(pool: &PgPool, cipher: &SecretCipher) -> Option<EmailConfig> {
    match stored(pool, cipher).await {
        Ok(Some(stored)) if stored.enabled => Some(stored.config),
        Ok(Some(_)) => None,
        Ok(None) => from_env(),
        Err(cause) => {
            tracing::error!(%cause, "could not read the email configuration");
            None
        }
    }
}

pub(crate) async fn view(pool: &PgPool, cipher: &SecretCipher) -> anyhow::Result<EmailView> {
    let public_url_configured = public_url().is_some();
    let (source, enabled, config) = match stored(pool, cipher).await? {
        Some(stored) if stored.enabled => (Some("database"), true, Some(stored.config)),
        Some(stored) => (Some("database"), false, Some(stored.config)),
        None => match from_env() {
            Some(env) => (Some("environment"), true, Some(env)),
            None => (None, false, None),
        },
    };
    Ok(match config {
        Some(config) => EmailView {
            configured: enabled,
            source,
            enabled,
            secrets_set: config.secrets.keys().cloned().collect(),
            provider: config.provider,
            from_email: config.from_email,
            from_name: config.from_name,
            settings: config.settings,
            public_url_configured,
        },
        None => EmailView {
            configured: false,
            source: None,
            enabled: false,
            provider: "smtp".into(),
            from_email: String::new(),
            from_name: None,
            settings: BTreeMap::new(),
            secrets_set: vec![],
            public_url_configured,
        },
    })
}

fn valid_email(value: &str) -> bool {
    let value = value.trim();
    value.len() <= 254
        && !value.contains(char::is_whitespace)
        && value.parse::<lettre::Address>().is_ok()
        && value
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
}

/// Validate and merge an administrator's update into the saved configuration.
#[allow(clippy::too_many_lines)] // Keep provider validation together.
fn merged(input: EmailInput, previous: Option<&EmailConfig>) -> Result<EmailConfig, String> {
    let provider = input.provider.trim().to_ascii_lowercase();
    if !PROVIDERS.contains(&provider.as_str()) {
        return Err(format!("Choose one of: {}.", PROVIDERS.join(", ")));
    }
    if !valid_email(&input.from_email) {
        return Err("Enter a valid sender email address.".into());
    }
    let from_name = input
        .from_name
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty());
    if from_name
        .as_deref()
        .is_some_and(|name| name.len() > 120 || name.contains(['<', '>', '"', '\r', '\n']))
    {
        return Err("The sender name must be plain text up to 120 characters.".into());
    }
    let (setting_names, secret_names) = fields(&provider);
    let mut settings = BTreeMap::new();
    for (key, value) in input.settings {
        let value = value.trim().to_owned();
        if !setting_names.contains(&key.as_str()) {
            return Err(format!("Unknown {provider} setting: {key}."));
        }
        if value.len() > 512 || value.contains(['\r', '\n']) {
            return Err(format!("Invalid {key}."));
        }
        if !value.is_empty() {
            settings.insert(key, value);
        }
    }
    let same_provider = previous.filter(|p| p.provider == provider);
    let mut secrets = BTreeMap::new();
    for name in secret_names {
        let value = input
            .secrets
            .get(*name)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
            .or_else(|| same_provider.and_then(|p| p.secrets.get(*name).cloned()));
        if value
            .as_deref()
            .is_some_and(|v| v.len() > 4096 || v.contains(['\r', '\n']))
        {
            return Err(format!("Invalid {name}."));
        }
        if let Some(value) = value {
            secrets.insert((*name).to_owned(), value);
        }
    }
    if let Some(key) = input
        .secrets
        .keys()
        .find(|k| !secret_names.contains(&k.as_str()))
    {
        return Err(format!("Unknown {provider} credential: {key}."));
    }
    let required = |name: &str, label: &str, present: bool| {
        if present {
            Ok(())
        } else {
            Err(format!("{label} is required for {name}."))
        }
    };
    match provider.as_str() {
        "smtp" => {
            required("SMTP", "Host", settings.contains_key("host"))?;
            let port = settings.get("port").map_or("587", String::as_str);
            if !port.parse::<u16>().is_ok_and(|port| port > 0) {
                return Err("SMTP port must be a number from 1 to 65535.".into());
            }
            let security = settings.get("security").map_or("starttls", String::as_str);
            if !["starttls", "tls", "none"].contains(&security) {
                return Err("SMTP security must be starttls, tls or none.".into());
            }
            if settings.contains_key("username") != secrets.contains_key("password") {
                return Err("Enter both an SMTP username and password, or neither.".into());
            }
        }
        "ses" => {
            required("AWS SES", "Region", settings.contains_key("region"))?;
            if secrets.contains_key("access_key_id") != secrets.contains_key("secret_access_key") {
                return Err("Enter both AWS access keys, or leave both empty to use the host's AWS credentials.".into());
            }
        }
        "mailgun" => {
            required("Mailgun", "Domain", settings.contains_key("domain"))?;
            required("Mailgun", "API key", secrets.contains_key("api_key"))?;
            if settings
                .get("region")
                .is_some_and(|r| r != "us" && r != "eu")
            {
                return Err("Mailgun region must be us or eu.".into());
            }
        }
        "postmark" => required(
            "Postmark",
            "Server token",
            secrets.contains_key("server_token"),
        )?,
        _ => required(&provider, "API key", secrets.contains_key("api_key"))?,
    }
    Ok(EmailConfig {
        provider,
        from_email: input.from_email.trim().to_owned(),
        from_name,
        settings,
        secrets,
    })
}

pub(crate) async fn save(
    pool: &PgPool,
    cipher: &SecretCipher,
    input: EmailInput,
    user: Uuid,
) -> Result<(), SaveError> {
    let previous = stored(pool, cipher).await.map_err(SaveError::Internal)?;
    let enabled = input.enabled;
    let environment = if previous.is_none() { from_env() } else { None };
    let config = merged(
        input,
        previous
            .as_ref()
            .map(|s| &s.config)
            .or(environment.as_ref()),
    )
    .map_err(SaveError::Invalid)?;
    let (nonce, ciphertext) = if config.secrets.is_empty() {
        (None, None)
    } else {
        let (nonce, ciphertext) = cipher
            .encrypt(
                &serde_json::to_string(&config.secrets)
                    .map_err(|e| SaveError::Internal(e.into()))?,
            )
            .map_err(|e| SaveError::Internal(e.into()))?;
        (Some(nonce), Some(ciphertext))
    };
    sqlx::query(
        "INSERT INTO tally_email_config (singleton, provider, enabled, from_email, from_name, settings,
             secret_nonce, secret_ciphertext, updated_by, updated_at)
         VALUES (TRUE, $1, $2, $3, $4, $5, $6, $7, $8, NOW())
         ON CONFLICT (singleton) DO UPDATE SET provider = EXCLUDED.provider, enabled = EXCLUDED.enabled,
             from_email = EXCLUDED.from_email, from_name = EXCLUDED.from_name, settings = EXCLUDED.settings,
             secret_nonce = EXCLUDED.secret_nonce, secret_ciphertext = EXCLUDED.secret_ciphertext,
             updated_by = EXCLUDED.updated_by, updated_at = NOW()",
    )
    .bind(&config.provider)
    .bind(enabled)
    .bind(&config.from_email)
    .bind(&config.from_name)
    .bind(json!(config.settings))
    .bind(nonce)
    .bind(ciphertext)
    .bind(user)
    .execute(pool)
    .await
    .map_err(|e| SaveError::Internal(e.into()))?;
    Ok(())
}

pub(crate) enum SaveError {
    Invalid(String),
    Internal(anyhow::Error),
}

/// Send one plain-text message. Errors include the provider's reason for administrators.
pub(crate) async fn send(
    http: &reqwest::Client,
    config: &EmailConfig,
    to: &str,
    subject: &str,
    body: &str,
) -> anyhow::Result<()> {
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        deliver(http, config, to, subject, body),
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!("Email delivery timed out. Check the provider settings and try again.")
    })?
}

async fn deliver(
    http: &reqwest::Client,
    config: &EmailConfig,
    to: &str,
    subject: &str,
    body: &str,
) -> anyhow::Result<()> {
    let from = config.sender();
    let check = |response: reqwest::Response, provider: &'static str| async move {
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let detail: String = response
            .text()
            .await
            .unwrap_or_default()
            .chars()
            .take(300)
            .collect();
        anyhow::bail!("{provider} rejected the message (HTTP {status}): {detail}")
    };
    match config.provider.as_str() {
        "smtp" => smtp(config, &from, to, subject, body).await,
        "ses" => ses(config, &from, to, subject, body).await,
        "sendgrid" => {
            let response = http
                .post("https://api.sendgrid.com/v3/mail/send")
                .bearer_auth(config.secret("api_key"))
                .json(&json!({
                    "personalizations": [{"to": [{"email": to}]}],
                    "from": {"email": config.from_email, "name": config.from_name},
                    "subject": subject,
                    "content": [{"type": "text/plain", "value": body}],
                }))
                .send()
                .await?;
            check(response, "SendGrid").await
        }
        "mailgun" => {
            let host = if config.setting("region") == "eu" {
                "api.eu.mailgun.net"
            } else {
                "api.mailgun.net"
            };
            let response = http
                .post(format!(
                    "https://{host}/v3/{}/messages",
                    config.setting("domain")
                ))
                .basic_auth("api", Some(config.secret("api_key")))
                .form(&[
                    ("from", from.as_str()),
                    ("to", to),
                    ("subject", subject),
                    ("text", body),
                ])
                .send()
                .await?;
            check(response, "Mailgun").await
        }
        "postmark" => {
            let response = http
                .post("https://api.postmarkapp.com/email")
                .header("X-Postmark-Server-Token", config.secret("server_token"))
                .header("Accept", "application/json")
                .json(&json!({"From": from, "To": to, "Subject": subject, "TextBody": body, "MessageStream": "outbound"}))
                .send()
                .await?;
            check(response, "Postmark").await
        }
        "resend" => {
            let response = http
                .post("https://api.resend.com/emails")
                .bearer_auth(config.secret("api_key"))
                .json(&json!({"from": from, "to": [to], "subject": subject, "text": body}))
                .send()
                .await?;
            check(response, "Resend").await
        }
        other => anyhow::bail!("Unknown email provider: {other}"),
    }
}

async fn smtp(
    config: &EmailConfig,
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
) -> anyhow::Result<()> {
    use lettre::{
        AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::header::ContentType,
        transport::smtp::authentication::Credentials,
    };
    let message = Message::builder()
        .from(from.parse()?)
        .to(to.parse()?)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body.to_owned())?;
    let host = config.setting("host");
    let mut builder = match config.setting("security") {
        "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(host)?,
        "none" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
        _ => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)?,
    };
    if let Ok(port) = config.setting("port").parse() {
        builder = builder.port(port);
    }
    if !config.setting("username").is_empty() {
        builder = builder.credentials(Credentials::new(
            config.setting("username").to_owned(),
            config.secret("password").to_owned(),
        ));
    }
    builder
        .timeout(Some(std::time::Duration::from_secs(20)))
        .build()
        .send(message)
        .await?;
    Ok(())
}

async fn ses(
    config: &EmailConfig,
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
) -> anyhow::Result<()> {
    use aws_sdk_sesv2::{
        Client,
        config::{BehaviorVersion, Credentials, Region},
        types::{Body, Content, Destination, EmailContent, Message},
    };
    let region = Region::new(config.setting("region").to_owned());
    let sdk = if config.secret("access_key_id").is_empty() {
        // The host's AWS credential chain: environment, profile, or instance role.
        aws_sdk_sesv2::Config::new(
            &aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(region)
                .load()
                .await,
        )
    } else {
        aws_sdk_sesv2::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(region)
            .credentials_provider(Credentials::new(
                config.secret("access_key_id"),
                config.secret("secret_access_key"),
                None,
                None,
                "tally-email-settings",
            ))
            .build()
    };
    let content = |text: &str| Content::builder().data(text).charset("UTF-8").build();
    Client::from_conf(sdk)
        .send_email()
        .from_email_address(from)
        .destination(Destination::builder().to_addresses(to).build())
        .content(
            EmailContent::builder()
                .simple(
                    Message::builder()
                        .subject(content(subject)?)
                        .body(Body::builder().text(content(body)?).build())
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "AWS SES rejected the message: {}",
                aws_sdk_sesv2::error::DisplayErrorContext(error)
            )
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(value: Value) -> EmailInput {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn updates_validate_each_provider_and_keep_saved_secrets() {
        let first = merged(
            input(
                json!({"provider":"resend","enabled":true,"from_email":"tally@example.com",
                "secrets":{"api_key":"re_secret"}}),
            ),
            None,
        )
        .unwrap();
        // A blank secret keeps the saved key for the same provider only.
        let kept = merged(
            input(json!({"provider":"resend","enabled":true,"from_email":"tally@example.com","from_name":"Tally"})),
            Some(&first),
        )
        .unwrap();
        assert_eq!(kept.secret("api_key"), "re_secret");
        assert_eq!(kept.sender(), "Tally <tally@example.com>");
        assert!(
            merged(
                input(
                    json!({"provider":"sendgrid","enabled":true,"from_email":"tally@example.com"})
                ),
                Some(&first),
            )
            .unwrap_err()
            .contains("API key")
        );
        for bad in [
            json!({"provider":"carrier-pigeon","enabled":true,"from_email":"a@example.com"}),
            json!({"provider":"resend","enabled":true,"from_email":"not-an-email","secrets":{"api_key":"k"}}),
            json!({"provider":"resend","enabled":true,"from_email":"a@example.com","from_name":"Evil <x>","secrets":{"api_key":"k"}}),
            json!({"provider":"smtp","enabled":true,"from_email":"a@example.com","settings":{"port":"587"}}),
            json!({"provider":"smtp","enabled":true,"from_email":"a@example.com","settings":{"host":"smtp.example.com","port":"seventy"}}),
            json!({"provider":"smtp","enabled":true,"from_email":"a@example.com","settings":{"host":"smtp.example.com","port":"0"}}),
            json!({"provider":"smtp","enabled":true,"from_email":"a@example.com","settings":{"host":"smtp.example.com","username":"u"}}),
            json!({"provider":"ses","enabled":true,"from_email":"a@example.com","settings":{"region":"us-east-1"},"secrets":{"access_key_id":"AKIA"}}),
            json!({"provider":"resend","enabled":true,"from_email":"a@example.com","settings":{"host":"x"},"secrets":{"api_key":"k"}}),
            json!({"provider":"resend","enabled":true,"from_email":"a@example.com","secrets":{"api_key":"k\r\nBcc: x"}}),
        ] {
            assert!(merged(input(bad.clone()), None).is_err(), "{bad}");
        }
        // SES may rely on the host's AWS credentials.
        assert!(
            merged(
                input(json!({"provider":"ses","enabled":true,"from_email":"a@example.com","settings":{"region":"us-east-1"}})),
                None,
            )
            .is_ok()
        );
    }
}
