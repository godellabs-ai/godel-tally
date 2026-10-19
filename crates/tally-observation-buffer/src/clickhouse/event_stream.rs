use super::{ClickHouse, Count, Payload};
use crate::{
    ObservationBufferError,
    event_stream::{EventStreamFilter, EventStreamPage, SEARCH_PATHS, page_bounds},
};
use serde::de::DeserializeOwned;
use std::fmt::Write;

fn json_field(path: &[&str]) -> String {
    format!(
        "JSONExtractString(payload, {})",
        path.iter()
            .map(|key| format!("'{key}'"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

impl ClickHouse {
    pub async fn event_stream(
        &self,
        filter: &EventStreamFilter,
        page: u64,
        size: u16,
    ) -> Result<EventStreamPage, ObservationBufferError> {
        if filter.installation_id != self.installation_id {
            return Err(super::error("installation scope mismatch"));
        }
        // Values are bound as typed ClickHouse parameters, never interpolated into SQL.
        let mut store = self.clone();
        for (name, value) in [
            ("from", filter.from.to_string()),
            ("until", filter.until.to_string()),
            ("snapshot", filter.snapshot.to_string()),
            ("query", filter.query.clone()),
            ("kind", filter.kind.clone()),
            ("outcome", filter.outcome.clone()),
        ] {
            // HTTP String parameters use ClickHouse's escaped text format.
            let escaped = value
                .replace('\\', "\\\\")
                .replace('\t', "\\t")
                .replace('\n', "\\n")
                .replace('\r', "\\r")
                .replace('\0', "\\0");
            store
                .url
                .query_pairs_mut()
                .append_pair(&format!("param_{name}"), &escaped);
        }
        let mut predicate = format!(
            "{} AND observed_at >= {{from:Int64}} AND observed_at <= {{until:Int64}} AND received_at <= {{snapshot:Int64}} AND expires_at > now()",
            self.scope()
        );
        if let Some(id) = filter.connector_id {
            let _ = write!(predicate, " AND connector_id = toUUID('{id}')");
        }
        let authorization_data = filter.authorization.as_ref().map(|authorization| {
            let operator = if authorization.exclude {
                "NOT IN"
            } else {
                "IN"
            };
            let _ = write!(
                predicate,
                " AND observation_id {operator} (SELECT observation_id FROM event_authorization)"
            );
            let mut data = String::new();
            for id in &authorization.observation_ids {
                let _ = writeln!(data, "{id}");
            }
            data
        });
        if !filter.kind.is_empty() {
            predicate.push_str(" AND JSONExtractString(payload, 'kind') = {kind:String}");
        }
        if !filter.outcome.is_empty() {
            let terms = ["action", "result", "response_code"]
                .iter()
                .map(|key| {
                    format!(
                        "positionCaseInsensitiveUTF8({}, {{outcome:String}}) > 0",
                        json_field(&["outcome", key])
                    )
                })
                .collect::<Vec<_>>();
            let _ = write!(predicate, " AND ({})", terms.join(" OR "));
        }
        if !filter.query.is_empty() {
            let terms = SEARCH_PATHS
                .iter()
                .map(|path| json_field(path))
                .chain([
                    "arrayStringConcat(JSONExtract(payload, 'actor', 'additional_source_ips', 'Array(String)'), ' ')".into(),
                    "toString(observation_id)".into(),
                    "toString(connector_id)".into(),
                ])
                .map(|field| format!("positionCaseInsensitiveUTF8({field}, {{query:String}}) > 0"))
                .collect::<Vec<_>>();
            let _ = write!(predicate, " AND ({})", terms.join(" OR "));
        }
        let total = store
            .stream_rows::<Count>(
                &format!("SELECT count() AS count FROM tally_ai_events FINAL WHERE {predicate}"),
                authorization_data.as_deref(),
            )
            .await?
            .first()
            .map_or(0, |row| row.count);
        let (page, page_size, total_pages) = page_bounds(total, page, size);
        let offset = (page - 1) * u64::from(page_size);
        let direction = if filter.oldest_first { "ASC" } else { "DESC" };
        let rows = store.stream_rows::<Payload>(&format!("SELECT payload FROM tally_ai_events FINAL WHERE {predicate} ORDER BY observed_at {direction}, observation_id {direction} LIMIT {page_size} OFFSET {offset}"), authorization_data.as_deref()).await?;
        let items = rows
            .into_iter()
            .map(|row| serde_json::from_str(&row.payload).map_err(Into::into))
            .collect::<Result<Vec<_>, ObservationBufferError>>()?;
        Ok(EventStreamPage {
            items,
            total,
            page,
            page_size,
            total_pages,
        })
    }

    // External tables keep large ID sets out of the SQL AST and URL. The table is
    // request-local; no persisted copies of registry decisions can become stale.
    async fn stream_rows<T: DeserializeOwned>(
        &self,
        sql: &str,
        authorization_data: Option<&str>,
    ) -> Result<Vec<T>, ObservationBufferError> {
        let Some(data) = authorization_data else {
            return self.rows(sql).await;
        };
        let mut url = self.url.clone();
        url.query_pairs_mut()
            .append_pair("query", &format!("{sql} FORMAT JSONEachRow"))
            .append_pair("event_authorization_structure", "observation_id UUID")
            .append_pair("event_authorization_format", "TabSeparated");
        let form = reqwest::multipart::Form::new().part(
            "event_authorization",
            reqwest::multipart::Part::text(data.to_owned()).file_name("event_authorization.tsv"),
        );
        let response = self
            .client
            .post(url)
            .multipart(form)
            .send()
            .await
            .map_err(|_| super::error("ClickHouse request failed"))?;
        let body = Self::response_text(response).await?;
        body.lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).map_err(Into::into))
            .collect()
    }
}
