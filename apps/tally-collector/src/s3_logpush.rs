use std::{io::Read, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use aws_credential_types::Credentials;
use flate2::read::GzDecoder;
use reqwest::Url;
use tally_connectors::MAX_IMPORT_BYTES;
use tokio::io::AsyncReadExt;

use crate::pull_support::NativeEnterpriseSnapshot;

const CURSOR_PREFIX: &str = "cfs31:";
const BACKLOG_CURSOR_PREFIX: &str = "s3-backlog1:";
const MAX_OBJECT_KEY_BYTES: usize = 1_000;
const MAX_OBJECTS_PER_POLL: usize = 128;

#[derive(Debug)]
pub(crate) struct S3LogpushPullResult {
    pub(crate) snapshot: NativeEnterpriseSnapshot,
    pub(crate) cursor_after: String,
}

#[derive(Debug)]
pub(crate) struct S3LogpushPull<'a> {
    pub(crate) endpoint_url: &'a str,
    pub(crate) bucket: &'a str,
    pub(crate) prefix: &'a str,
    pub(crate) region: &'a str,
    pub(crate) access_key_id: &'a str,
    pub(crate) secret_access_key: &'a str,
    pub(crate) object_limit: usize,
    pub(crate) cursor_before: &'a str,
}

/// Reads a bounded, lexicographically ordered batch from a dedicated Cloudflare Logpush prefix.
/// Objects are never persisted; gzip expansion and the combined NDJSON projection are bounded.
pub(crate) async fn pull_gateway_http(request: &S3LogpushPull<'_>) -> Result<S3LogpushPullResult> {
    let endpoint = s3_endpoint(request.endpoint_url)?;
    validate_pull(request)?;
    let start_after = parse_cursor(request.cursor_before)?;
    let client = s3_client(request, &endpoint).await;
    let keys = list_object_keys(&client, request, start_after).await?;
    let mut backlog_hint = keys.len() == request.object_limit;
    let mut data = Vec::new();
    let mut cursor_after = request
        .cursor_before
        .strip_prefix(BACKLOG_CURSOR_PREFIX)
        .unwrap_or(request.cursor_before)
        .to_owned();
    for key in keys {
        validate_object_key(&key)?;
        if key.ends_with('/') {
            cursor_after = encode_cursor(&key);
            continue;
        }
        let decoded = read_logpush_object(&client, request.bucket, &key).await?;
        let Some(object_checkpoint) = logpush_object_checkpoint(&key, &decoded) else {
            continue;
        };
        let separator = usize::from(!data.is_empty() && !data.ends_with(b"\n"));
        if data
            .len()
            .saturating_add(separator)
            .saturating_add(decoded.len())
            .saturating_add(1)
            > MAX_IMPORT_BYTES
        {
            ensure!(
                !data.is_empty(),
                "Cloudflare Logpush object expands beyond the import limit"
            );
            backlog_hint = true;
            break;
        }
        if separator == 1 {
            data.push(b'\n');
        }
        data.extend_from_slice(&decoded);
        if !data.ends_with(b"\n") {
            data.push(b'\n');
        }
        cursor_after = object_checkpoint;
    }
    let record_count = data
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
        .count();
    if backlog_hint && !cursor_after.is_empty() {
        cursor_after = format!("{BACKLOG_CURSOR_PREFIX}{cursor_after}");
    }
    Ok(S3LogpushPullResult {
        snapshot: NativeEnterpriseSnapshot { data, record_count },
        cursor_after,
    })
}

async fn s3_client(request: &S3LogpushPull<'_>, endpoint: &Url) -> aws_sdk_s3::Client {
    let shared = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(request.region.to_owned()))
        .credentials_provider(Credentials::new(
            request.access_key_id.to_owned(),
            request.secret_access_key.to_owned(),
            None,
            None,
            "tally-cloudflare-logpush",
        ))
        .retry_config(aws_config::retry::RetryConfig::standard().with_max_attempts(3))
        .timeout_config(
            aws_config::timeout::TimeoutConfig::builder()
                .connect_timeout(Duration::from_secs(10))
                .operation_timeout(Duration::from_mins(1))
                .build(),
        )
        .endpoint_url(endpoint.as_str())
        .load()
        .await;
    let config = aws_sdk_s3::Config::from(&shared)
        .to_builder()
        .force_path_style(true)
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

async fn list_object_keys(
    client: &aws_sdk_s3::Client,
    request: &S3LogpushPull<'_>,
    start_after: Option<String>,
) -> Result<Vec<String>> {
    let output = client
        .list_objects_v2()
        .bucket(request.bucket)
        .prefix(request.prefix)
        .set_start_after(start_after.clone())
        .max_keys(i32::try_from(request.object_limit).unwrap_or(i32::MAX))
        .send()
        .await
        .context("Cloudflare Logpush destination listing failed")?;
    let mut keys = output
        .contents()
        .iter()
        .filter_map(|object| object.key())
        .filter(|key| start_after.as_deref().is_none_or(|cursor| *key > cursor))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    keys.sort();
    ensure!(
        keys.len() <= request.object_limit,
        "S3 listing exceeded the requested object limit"
    );
    Ok(keys)
}

async fn read_logpush_object(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
) -> Result<Vec<u8>> {
    let object = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .context("Cloudflare Logpush object read failed")?;
    if let Some(length) = object.content_length()
        && (length < 0 || usize::try_from(length).unwrap_or(usize::MAX) > MAX_IMPORT_BYTES)
    {
        bail!("Cloudflare Logpush object is too large");
    }
    let mut compressed = Vec::new();
    object
        .body
        .into_async_read()
        .take(u64::try_from(MAX_IMPORT_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut compressed)
        .await
        .context("Cloudflare Logpush object body read failed")?;
    ensure!(
        compressed.len() <= MAX_IMPORT_BYTES,
        "Cloudflare Logpush object is too large"
    );
    decode_logpush_object(compressed)
}

fn validate_pull(request: &S3LogpushPull<'_>) -> Result<()> {
    validate_bucket(request.bucket)?;
    validate_prefix(request.prefix)?;
    validate_region(request.region)?;
    validate_credential(request.access_key_id, "access key ID")?;
    validate_credential(request.secret_access_key, "secret access key")?;
    ensure!(
        (1..=MAX_OBJECTS_PER_POLL).contains(&request.object_limit),
        "S3 object limit must be between 1 and {MAX_OBJECTS_PER_POLL}"
    );
    Ok(())
}

fn decode_logpush_object(input: Vec<u8>) -> Result<Vec<u8>> {
    if !input.starts_with(&[0x1f, 0x8b]) {
        ensure!(
            input.len() <= MAX_IMPORT_BYTES,
            "Cloudflare Logpush object is too large"
        );
        return Ok(input);
    }
    let mut decoded = Vec::new();
    GzDecoder::new(input.as_slice())
        .take(u64::try_from(MAX_IMPORT_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut decoded)
        .context("Cloudflare Logpush gzip object is invalid")?;
    ensure!(
        decoded.len() <= MAX_IMPORT_BYTES,
        "Cloudflare Logpush object expands beyond the import limit"
    );
    Ok(decoded)
}

/// Cloudflare writes a one-field `content` document while validating a new Logpush destination.
/// It is destination setup metadata rather than a log event, so skip it without presenting it to
/// a dataset-specific normalizer or advancing the source watermark.
fn cloudflare_destination_validation_probe(input: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(input).is_ok_and(|value| {
        value.as_object().is_some_and(|object| {
            object.len() == 1
                && object
                    .get("content")
                    .and_then(serde_json::Value::as_str)
                    .is_some()
        })
    })
}

/// Validation objects can sort after timestamped log files in the same date prefix. They must not
/// move the monotonic source watermark or future log files could compare before the cursor.
fn logpush_object_checkpoint(key: &str, input: &[u8]) -> Option<String> {
    (!cloudflare_destination_validation_probe(input)).then(|| encode_cursor(key))
}

pub(crate) fn s3_endpoint(value: &str) -> Result<Url> {
    let mut url = Url::parse(value).context("invalid S3-compatible endpoint URL")?;
    ensure!(
        url.scheme() == "https",
        "S3-compatible endpoint must use HTTPS"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "S3-compatible endpoint cannot contain credentials"
    );
    ensure!(
        url.host_str().is_some(),
        "S3-compatible endpoint requires a host"
    );
    ensure!(
        matches!(url.path(), "" | "/") && url.query().is_none() && url.fragment().is_none(),
        "S3-compatible endpoint must be an origin without a path, query, or fragment"
    );
    url.set_path("/");
    Ok(url)
}

fn validate_bucket(value: &str) -> Result<()> {
    ensure!(
        (3..=255).contains(&value.len())
            && value.trim() == value
            && !value.chars().any(char::is_control)
            && !value.contains('/'),
        "invalid S3-compatible bucket"
    );
    Ok(())
}

fn validate_prefix(value: &str) -> Result<()> {
    ensure!(
        value.len() <= 1_024 && !value.chars().any(char::is_control),
        "invalid S3-compatible prefix"
    );
    Ok(())
}

fn validate_region(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 63
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "invalid S3-compatible region"
    );
    Ok(())
}

fn validate_credential(value: &str, label: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 4_096
            && value.trim() == value
            && !value.chars().any(char::is_control),
        "invalid S3-compatible {label}"
    );
    Ok(())
}

fn validate_object_key(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= MAX_OBJECT_KEY_BYTES
            && !value.chars().any(char::is_control),
        "invalid S3 object key"
    );
    Ok(())
}

fn encode_cursor(key: &str) -> String {
    format!("{CURSOR_PREFIX}{}", hex::encode(key))
}

fn parse_cursor(value: &str) -> Result<Option<String>> {
    let value = value.strip_prefix(BACKLOG_CURSOR_PREFIX).unwrap_or(value);
    if value.is_empty() {
        return Ok(None);
    }
    let encoded = value
        .strip_prefix(CURSOR_PREFIX)
        .context("invalid Cloudflare Logpush cursor")?;
    let key = String::from_utf8(hex::decode(encoded).context("invalid Cloudflare Logpush cursor")?)
        .context("invalid Cloudflare Logpush cursor")?;
    validate_object_key(&key)?;
    Ok(Some(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn endpoint_is_https_origin_without_embedded_credentials() {
        assert_eq!(
            s3_endpoint("https://0123456789abcdef.r2.cloudflarestorage.com")
                .expect("endpoint")
                .as_str(),
            "https://0123456789abcdef.r2.cloudflarestorage.com/"
        );
        assert!(s3_endpoint("http://object.example").is_err());
        assert!(s3_endpoint("https://user:secret@object.example").is_err());
        assert!(s3_endpoint("https://object.example/bucket").is_err());
    }

    #[test]
    fn cursor_round_trips_an_opaque_object_key() {
        let key = "tally-gateway-http/20260903/20260903T191900Z_abc.log.gz";
        assert_eq!(
            parse_cursor(&encode_cursor(key)).expect("cursor"),
            Some(key.into())
        );
        assert!(parse_cursor("cflog1:123").is_err());
        assert_eq!(
            parse_cursor(&format!("{BACKLOG_CURSOR_PREFIX}{}", encode_cursor(key)))
                .expect("backlogged cursor"),
            Some(key.into())
        );
    }

    #[test]
    fn gzip_expansion_is_bounded_and_plain_ndjson_is_supported() {
        let plain = br#"{"Datetime":1788443425,"RequestID":"request-1"}\n"#;
        assert_eq!(decode_logpush_object(plain.to_vec()).expect("plain"), plain);

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(plain).expect("compress");
        let compressed = encoder.finish().expect("finish gzip");
        assert_eq!(decode_logpush_object(compressed).expect("gzip"), plain);
    }

    #[test]
    fn cloudflare_destination_validation_probe_is_not_a_log_record() {
        assert!(cloudflare_destination_validation_probe(
            br#"{"content":"tests"}"#
        ));
        assert!(cloudflare_destination_validation_probe(
            b" \n {\"content\":\"tests\"} \n"
        ));
        assert!(cloudflare_destination_validation_probe(
            br#"{"content":"opaque destination challenge"}"#
        ));
        assert!(!cloudflare_destination_validation_probe(
            br#"{"Datetime":1788443425,"HTTPHost":"api.openai.com"}"#
        ));
        assert!(!cloudflare_destination_validation_probe(
            br#"{"content":"tests","Datetime":1788443425}"#
        ));
        assert_eq!(
            logpush_object_checkpoint("20260904/test.txt.gz", br#"{"content":"tests"}"#),
            None
        );
        assert_eq!(
            logpush_object_checkpoint(
                "20260904/20260904T193000Z.log.gz",
                br#"{"Datetime":1788443425,"HTTPHost":"api.openai.com"}"#
            ),
            Some(encode_cursor("20260904/20260904T193000Z.log.gz"))
        );
    }
}
