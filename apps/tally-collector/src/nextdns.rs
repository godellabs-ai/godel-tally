use chrono::{DateTime, Utc};
use reqwest::{StatusCode, Url, header::HeaderValue};
use tally_connectors::{MAX_IMPORT_BYTES, NextDnsApiPageMetadata};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NextDnsPullCursor {
    pub(crate) from_millis: i64,
    pub(crate) page_cursor: Option<String>,
}

pub(crate) async fn fetch_page(
    api_key: &str,
    client: &reqwest::Client,
    profile_id: &str,
    cursor: &NextDnsPullCursor,
    record_limit: u32,
) -> Result<Vec<u8>, &'static str> {
    if api_key.len() > 512 {
        return Err("secret_ref_invalid");
    }
    let mut api_key_header = HeaderValue::from_str(api_key).map_err(|_| "secret_ref_invalid")?;
    api_key_header.set_sensitive(true);
    let url = logs_url(profile_id, cursor, record_limit).map_err(|_| "nextdns_endpoint_invalid")?;
    let response = client
        .get(url)
        .header("X-Api-Key", api_key_header)
        .send()
        .await
        .map_err(|_| "nextdns_request_failed")?;
    if response.status() != StatusCode::OK {
        return Err(match response.status() {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => "nextdns_auth_failed",
            StatusCode::TOO_MANY_REQUESTS => "nextdns_rate_limited",
            _ => "nextdns_response_failed",
        });
    }
    if response
        .content_length()
        .is_some_and(|length| length > u64::try_from(MAX_IMPORT_BYTES).unwrap_or(u64::MAX))
    {
        return Err("source_size_invalid");
    }
    let input = response
        .bytes()
        .await
        .map_err(|_| "nextdns_response_failed")?
        .to_vec();
    if input.len() > MAX_IMPORT_BYTES {
        return Err("source_size_invalid");
    }
    Ok(input)
}

pub(crate) fn encode_cursor(cursor: &NextDnsPullCursor) -> String {
    format!(
        "nd1:{}:{}",
        cursor.from_millis,
        cursor.page_cursor.as_deref().unwrap_or("-")
    )
}

pub(crate) fn parse_cursor(value: &str) -> Option<NextDnsPullCursor> {
    let remainder = value.strip_prefix("nd1:")?;
    let (from_millis, page_cursor) = remainder.split_once(':')?;
    let from_millis = from_millis.parse::<i64>().ok().filter(|value| *value > 0)?;
    let page_cursor = match page_cursor {
        "-" => None,
        value
            if !value.is_empty()
                && value.len() <= 512
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')) =>
        {
            Some(value.to_owned())
        }
        _ => return None,
    };
    Some(NextDnsPullCursor {
        from_millis,
        page_cursor,
    })
}

pub(crate) fn next_cursor(
    current: &NextDnsPullCursor,
    page: &NextDnsApiPageMetadata,
    now: DateTime<Utc>,
    last_source_at: Option<DateTime<Utc>>,
) -> NextDnsPullCursor {
    // NextDNS can return a cursor even for an empty page. End pagination on any empty page;
    // first check for logs newer than the last committed timestamp, then move near real time.
    if page.record_count == 0 {
        let resume_from = last_source_at.map(|at| at.timestamp_millis().saturating_add(1));
        let from_millis = match resume_from {
            Some(resume_from) if current.from_millis < resume_from => resume_from,
            _ => (now - chrono::Duration::seconds(5)).timestamp_millis(),
        };
        return NextDnsPullCursor {
            from_millis: current.from_millis.max(from_millis),
            page_cursor: None,
        };
    }
    if let Some(cursor) = page
        .next_page_cursor
        .as_ref()
        .filter(|cursor| Some(*cursor) != current.page_cursor.as_ref())
    {
        return NextDnsPullCursor {
            from_millis: current.from_millis,
            page_cursor: Some(cursor.clone()),
        };
    }
    if let Some(last_observed_at) = page.last_observed_at {
        return NextDnsPullCursor {
            from_millis: current.from_millis.max(last_observed_at.timestamp_millis()),
            page_cursor: None,
        };
    }
    NextDnsPullCursor {
        from_millis: current
            .from_millis
            .max((now - chrono::Duration::seconds(5)).timestamp_millis()),
        page_cursor: None,
    }
}

fn logs_url(
    profile_id: &str,
    cursor: &NextDnsPullCursor,
    record_limit: u32,
) -> Result<Url, &'static str> {
    if !safe_profile_id(profile_id) || !(1..=1_000).contains(&record_limit) {
        return Err("unsafe profile ID");
    }
    let mut url = Url::parse(&format!(
        "https://api.nextdns.io/profiles/{profile_id}/logs"
    ))
    .map_err(|_| "invalid fixed endpoint")?;
    let mut query = url.query_pairs_mut();
    query
        .append_pair("from", &cursor.from_millis.to_string())
        .append_pair("sort", "asc")
        .append_pair("limit", &record_limit.to_string())
        .append_pair("raw", "0");
    if let Some(page_cursor) = &cursor.page_cursor {
        query.append_pair("cursor", page_cursor);
    }
    drop(query);
    Ok(url)
}

fn safe_profile_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trips_and_rejects_content() {
        let cursor = NextDnsPullCursor {
            from_millis: 1_786_615_200_000,
            page_cursor: Some("j2k3zl3b4v".into()),
        };
        assert_eq!(parse_cursor(&encode_cursor(&cursor)), Some(cursor));
        assert!(parse_cursor("nd1:1786615200000:user@example.com").is_none());
        assert!(parse_cursor("nd1:1786615200000:cursor/path").is_none());
    }

    #[test]
    fn request_is_fixed_bounded_and_replay_safe() {
        let url = logs_url(
            "abc123",
            &NextDnsPullCursor {
                from_millis: 1_786_615_200_000,
                page_cursor: Some("page_2".into()),
            },
            250,
        )
        .expect("URL");
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("api.nextdns.io"));
        assert_eq!(url.path(), "/profiles/abc123/logs");
        let query = url
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(query.get("sort").expect("sort"), "asc");
        assert_eq!(query.get("limit").expect("limit"), "250");
        assert_eq!(query.get("raw").expect("raw"), "0");
        assert_eq!(query.get("cursor").expect("cursor"), "page_2");
        assert!(!url.as_str().contains("api_key"));
    }

    #[test]
    fn repeated_empty_page_cursor_exits_pagination() {
        let now = DateTime::from_timestamp_millis(1_800_000_000_000).expect("time");
        let current = NextDnsPullCursor {
            from_millis: now.timestamp_millis() - 86_400_000,
            page_cursor: Some("same".into()),
        };
        let page = NextDnsApiPageMetadata {
            next_page_cursor: Some("same".into()),
            last_observed_at: None,
            record_count: 0,
        };
        assert_eq!(
            next_cursor(&current, &page, now, Some(now - chrono::Duration::hours(1))),
            NextDnsPullCursor {
                from_millis: now.timestamp_millis() - 3_600_000 + 1,
                page_cursor: None,
            }
        );
        let verification = NextDnsPullCursor {
            from_millis: now.timestamp_millis() - 3_600_000 + 1,
            page_cursor: None,
        };
        assert_eq!(
            next_cursor(
                &verification,
                &page,
                now,
                Some(now - chrono::Duration::hours(1))
            ),
            NextDnsPullCursor {
                from_millis: now.timestamp_millis() - 5_000,
                page_cursor: None,
            }
        );
        let advancing = NextDnsApiPageMetadata {
            next_page_cursor: Some("new".into()),
            last_observed_at: Some(now),
            record_count: 1,
        };
        assert_eq!(
            next_cursor(&current, &advancing, now, None)
                .page_cursor
                .as_deref(),
            Some("new")
        );
    }
}
