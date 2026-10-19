use crate::{JobCredentials, PreparedJob, VendorAdapter, litellm, pull_support};
use chrono::Utc;
use reqwest::{Client, RequestBuilder, Url};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tally_connectors::{Cursor, PseudonymizationKey, VendorImportConfig};
use tally_store_postgres::{LeasedConnectorJob, PostgresStore};

const COPILOT_FIELDS: &str = "botid,name,statecode,statuscode,modifiedon";

fn cursor_prefix(platform: &str, base: &Url, key: &str, scope: Option<&str>) -> String {
    if !matches!(platform, "openai" | "claude" | "gemini") {
        return "agents-v1:".into();
    }
    let mut digest = Sha256::new();
    for field in [platform, base.as_str(), key, scope.unwrap_or_default()] {
        digest.update(field.len().to_be_bytes());
        digest.update(field.as_bytes());
    }
    format!("agents-v2:{}:", hex::encode(digest.finalize()))
}

pub(crate) fn cursor_has_more(cursor: &str) -> bool {
    cursor
        .strip_prefix("agents-v1:")
        .or_else(|| {
            cursor
                .strip_prefix("agents-v2:")
                .and_then(|v| v.split_once(':').map(|(_, next)| next))
        })
        .is_some_and(|next| !next.is_empty())
}

fn adapter(platform: &str) -> Result<VendorAdapter, &'static str> {
    match platform {
        "servicenow" => Ok(VendorAdapter::ServicenowAgents),
        "n8n" => Ok(VendorAdapter::N8nAgents),
        "copilot_studio" => Ok(VendorAdapter::CopilotStudioAgents),
        "langgraph" => Ok(VendorAdapter::LanggraphAgents),
        "dify" => Ok(VendorAdapter::DifyAgents),
        "openai" => Ok(VendorAdapter::OpenaiAgents),
        "claude" => Ok(VendorAdapter::ClaudeAgents),
        "gemini" => Ok(VendorAdapter::GeminiAgents),
        _ => Err("connector_config_invalid"),
    }
}

pub(crate) async fn prepare(
    postgres: &PostgresStore,
    credentials: &JobCredentials,
    client: &Client,
    job: &LeasedConnectorJob,
) -> Result<PreparedJob, &'static str> {
    let platform = job
        .config_refs
        .get("platform")
        .and_then(Value::as_str)
        .ok_or("connector_config_invalid")?;
    let adapter = adapter(platform)?;
    let descriptor = adapter.descriptor();
    if descriptor.connector_type != job.connector_type {
        return Err("connector_type_mismatch");
    }
    let base = litellm::litellm_api_base(credentials.require("base_url")?)
        .map_err(|_| "connector_origin_invalid")?;
    let scope_id = credentials.get("scope_id");
    if !tally_connectors::managed_agents_scope_valid(platform, base.as_str(), scope_id) {
        return Err("connector_config_invalid");
    }
    let cursor_before = postgres
        .connector_cursor(job.connector_instance_id)
        .await
        .map_err(|_| "connector_cursor_unavailable")?
        .unwrap_or_default();
    let key = credentials.require("api_key")?;
    // A scope or credential edit must not replay a cursor from another project/workspace.
    let prefix = cursor_prefix(platform, &base, key, scope_id);
    let cursor = cursor_before.strip_prefix(&prefix).unwrap_or("");
    let app_id = if platform == "dify" {
        Some(credentials.require("app_id")?)
    } else {
        None
    };
    let page = read_page(client, platform, &base, key, cursor, app_id, scope_id).await?;
    let checkpoint = format!("{prefix}{}", page.next);
    if page.records.is_empty() {
        return Ok(PreparedJob::EmptyPoll {
            descriptor,
            cursor_before,
            cursor_after: checkpoint,
        });
    }
    let input = serde_json::to_vec(&json!({"platform":platform,"origin":base.origin().ascii_serialization(),"scope":scope_id,"observed_at":Utc::now(),"records":page.records})).map_err(|_| "source_serialization_failed")?;
    let identity = postgres
        .get_or_create_installation_identity()
        .await
        .map_err(|_| "installation_identity_unavailable")?;
    if identity.installation_id != job.installation_id {
        return Err("installation_identity_mismatch");
    }
    let source_lineage_id = format!("{platform}:agent_inventory");
    let outcome = adapter
        .normalize(
            &input,
            &VendorImportConfig {
                installation_id: job.installation_id,
                connector_instance_id: job.connector_instance_id,
                implementation_version: env!("CARGO_PKG_VERSION").into(),
                source_lineage_id: Some(source_lineage_id.clone()),
                received_at: Utc::now(),
                checkpoint: Cursor(checkpoint.clone()),
                pseudonymization_key: PseudonymizationKey::new(identity.pseudonymization_key())
                    .map_err(|_| "installation_key_invalid")?,
            },
        )
        .map_err(|_| "source_normalization_failed")?;
    Ok(PreparedJob::Source {
        descriptor,
        adapter,
        input,
        checkpoint,
        source_lineage_id,
        expected_canonical_digest: outcome.batch.receipt.canonical_digest,
        cloud: None,
        casb_account_id: None,
    })
}

struct Page {
    records: Vec<Value>,
    next: String,
}
fn offset(cursor: &str) -> Result<u64, &'static str> {
    if cursor.is_empty() {
        Ok(0)
    } else {
        cursor.parse().map_err(|_| "connector_cursor_invalid")
    }
}

fn copilot_url(base: &Url, cursor: &str) -> Result<Url, &'static str> {
    let mut initial = base
        .join("api/data/v9.2/bots")
        .map_err(|_| "connector_origin_invalid")?;
    initial
        .query_pairs_mut()
        .append_pair("$select", COPILOT_FIELDS)
        .append_pair("$orderby", "botid");
    if cursor.is_empty() {
        return Ok(initial);
    }
    let next = Url::parse(cursor).map_err(|_| "connector_cursor_invalid")?;
    if next.origin() != base.origin()
        || next.path() != initial.path()
        || !next.username().is_empty()
        || next.password().is_some()
        || next.fragment().is_some()
    {
        return Err("connector_cursor_invalid");
    }
    let fields = next
        .query_pairs()
        .filter(|(key, _)| key == "$select")
        .collect::<Vec<_>>();
    if fields.len() != 1
        || fields[0].1 != COPILOT_FIELDS
        || next
            .query_pairs()
            .any(|(key, _)| !["$select", "$orderby", "$skiptoken"].contains(&key.as_ref()))
    {
        return Err("connector_cursor_invalid");
    }
    Ok(next)
}

fn request(
    client: &Client,
    platform: &str,
    base: &Url,
    key: &str,
    cursor: &str,
    scope_id: Option<&str>,
) -> Result<RequestBuilder, &'static str> {
    let path = match platform {
        "n8n" => "api/v1/workflows",
        "servicenow" => "api/now/table/sn_aia_agent",
        "copilot_studio" => "api/data/v9.2/bots",
        "langgraph" => "assistants/search",
        "dify" => "v1/info",
        "openai" | "claude" => "v1/agents",
        "gemini" => "v1beta/agents",
        _ => return Err("connector_config_invalid"),
    };
    let mut url = base.join(path).map_err(|_| "connector_origin_invalid")?;
    match platform {
        "openai" => {
            url.query_pairs_mut().append_pair("limit", "100").append_pair("order", "asc");
            if !cursor.is_empty() { url.query_pairs_mut().append_pair("after", cursor); }
            let mut request = client.get(url).bearer_auth(key).header("OpenAI-Beta", "agents=v1");
            if let Some(project) = scope_id { request = request.header("OpenAI-Project", project); }
            Ok(request)
        }
        "claude" => {
            url.query_pairs_mut().append_pair("limit", "100").append_pair("include_archived", "true");
            if !cursor.is_empty() { url.query_pairs_mut().append_pair("page", cursor); }
            let mut request = client.get(url).header("x-api-key", key).header("anthropic-version", "2023-06-01").header("anthropic-beta", "managed-agents-2026-04-01");
            if let Some(workspace) = scope_id { request = request.header("anthropic-workspace-id", workspace); }
            Ok(request)
        }
        "gemini" => {
            url.query_pairs_mut().append_pair("page_size", "100");
            if !cursor.is_empty() { url.query_pairs_mut().append_pair("page_token", cursor); }
            if let Some(parent) = scope_id { url.query_pairs_mut().append_pair("parent", parent); }
            Ok(client.get(url).header("x-goog-api-key", key))
        }
        "n8n" => {
            url.query_pairs_mut().append_pair("limit", "100").append_pair("excludePinnedData", "true");
            if !cursor.is_empty() { url.query_pairs_mut().append_pair("cursor", cursor); }
            Ok(client.get(url).header("X-N8N-API-KEY", key))
        }
        "servicenow" => {
            url.query_pairs_mut().append_pair("sysparm_limit", "100").append_pair("sysparm_offset", &offset(cursor)?.to_string())
                .append_pair("sysparm_fields", "sys_id,name,active,sys_created_by,sys_updated_on")
                .append_pair("sysparm_query", "ORDERBYsys_id").append_pair("sysparm_display_value", "false").append_pair("sysparm_exclude_reference_link", "true");
            Ok(client.get(url).bearer_auth(key))
        }
        "copilot_studio" => Ok(client.get(copilot_url(base, cursor)?).bearer_auth(key).header("Prefer", "odata.maxpagesize=100").header("OData-Version", "4.0")),
        "langgraph" => Ok(client.post(url).header("X-Api-Key", key).json(&json!({"limit":100,"offset":offset(cursor)?,"sort_by":"assistant_id","sort_order":"asc","select":["assistant_id","name","graph_id"],"response_format":"array"}))),
        "dify" if cursor.is_empty() => Ok(client.get(url).bearer_auth(key)),
        _ => Err("connector_cursor_invalid"),
    }
}

async fn read_page(
    client: &Client,
    platform: &str,
    base: &Url,
    key: &str,
    cursor: &str,
    app_id: Option<&str>,
    scope_id: Option<&str>,
) -> Result<Page, &'static str> {
    if cursor.len() > 8192 {
        return Err("connector_cursor_invalid");
    }
    let response = request(client, platform, base, key, cursor, scope_id)?
        .send()
        .await
        .map_err(|_| "managed_agent_api_unreachable")?;
    let bytes = pull_support::bounded_response(response, "managed agent inventory")
        .await
        .map_err(|_| "managed_agent_read_failed")?;
    let response: Value =
        serde_json::from_slice(&bytes).map_err(|_| "managed_agent_response_invalid")?;
    parse_page(platform, base, cursor, &response, app_id)
}

fn parse_page(
    platform: &str,
    base: &Url,
    cursor: &str,
    response: &Value,
    app_id: Option<&str>,
) -> Result<Page, &'static str> {
    if platform == "dify" {
        let id = app_id
            .filter(|id| uuid::Uuid::parse_str(id).is_ok())
            .ok_or("connector_config_invalid")?;
        if response.get("name").and_then(Value::as_str).is_none()
            || response.get("mode").and_then(Value::as_str).is_none()
        {
            return Err("managed_agent_response_invalid");
        }
        return Ok(Page {
            records: vec![json!({"id":id,"name":response["name"],"mode":response["mode"]})],
            next: String::new(),
        });
    }
    let empty_agents = Vec::new();
    let records = match platform {
        "n8n" | "openai" | "claude" => response.get("data"),
        // Gemini omits the optional agents field for an empty inventory.
        "gemini" => response.get("agents"),
        "servicenow" => response.get("result"),
        "copilot_studio" => response.get("value"),
        "langgraph" => Some(response),
        _ => None,
    }
    .and_then(Value::as_array)
    .or_else(|| {
        (platform == "gemini"
            && response.is_object()
            && response.get("agents").is_none()
            && response.get("error").is_none())
        .then_some(&empty_agents)
    })
    .ok_or("managed_agent_response_invalid")?;
    if records.len() > 100 {
        return Err("managed_agent_page_exceeded");
    }
    let next = match platform {
        "openai" => match response.get("has_more").and_then(Value::as_bool) {
            Some(true) => {
                let next = next_link(response, "last_id")?;
                if next.is_empty()
                    || records
                        .last()
                        .and_then(|r| r.get("id"))
                        .and_then(Value::as_str)
                        != Some(next.as_str())
                {
                    return Err("connector_cursor_invalid");
                }
                next
            }
            Some(false) => String::new(),
            None => return Err("managed_agent_response_invalid"),
        },
        "claude" => next_link(response, "next_page")?,
        "gemini" => next_link(response, "next_page_token")?,
        "n8n" => next_link(response, "nextCursor")?,
        "copilot_studio" => {
            let next = next_link(response, "@odata.nextLink")?;
            if !next.is_empty() {
                copilot_url(base, &next)?;
            }
            next
        }
        _ if records.len() == 100 => offset(cursor)?
            .checked_add(100)
            .ok_or("connector_cursor_invalid")?
            .to_string(),
        _ => String::new(),
    };
    if next.len() > 8192 || (!cursor.is_empty() && cursor == next) {
        return Err("connector_cursor_invalid");
    }
    let records = records
        .iter()
        .map(|record| project_record(platform, record))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Page { records, next })
}

fn project_record(platform: &str, record: &Value) -> Result<Value, &'static str> {
    let fields: &[&str] = match platform {
        "servicenow" => &[
            "sys_id",
            "name",
            "active",
            "sys_created_by",
            "sys_updated_on",
        ],
        "copilot_studio" => &["botid", "name", "statecode", "statuscode", "modifiedon"],
        "langgraph" => &["assistant_id", "name", "graph_id"],
        "openai" => &["id", "name"],
        "claude" => &["id", "name", "archived_at"],
        "gemini" => &["id", "display_name"],
        _ => &["id", "name", "active"],
    };
    let mut projected = select(record, fields);
    if matches!(platform, "openai" | "claude" | "gemini") {
        if record
            .get("id")
            .and_then(Value::as_str)
            .is_none_or(|id| id.is_empty() || id.len() > 512 || id.chars().any(char::is_control))
        {
            return Err("managed_agent_response_invalid");
        }
        if let Value::Object(fields) = &mut projected {
            fields.retain(|_, value| {
                value.is_null()
                    || value
                        .as_str()
                        .is_some_and(|s| s.len() <= 512 && !s.chars().any(char::is_control))
            });
        }
        let model = match platform {
            "claude" => record.pointer("/model/id").or_else(|| record.get("model")),
            "gemini" => record.pointer("/agent_config/model"),
            _ => record.get("model"),
        };
        if let Some(model) = model.and_then(Value::as_str).filter(|model| {
            model.len() <= 128
                && model
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-:/".contains(&b))
        }) {
            projected["model"] = Value::String(model.into());
        }
    }
    if platform == "n8n" {
        let nodes = record
            .get("nodes")
            .and_then(Value::as_array)
            .ok_or("managed_agent_response_invalid")?;
        if nodes.len() > 2000 {
            return Err("managed_agent_page_exceeded");
        }
        projected["nodes"] = Value::Array(
            nodes
                .iter()
                .map(|node| {
                    let mut projected = select(node, &["id", "name", "type"]);
                    if let Some(model) = node
                        .pointer("/parameters/model")
                        .and_then(Value::as_str)
                        .filter(|v| {
                            v.len() <= 128
                                && v.bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b"._-:/".contains(&b))
                        })
                    {
                        projected["parameters"] = json!({"model":model});
                    }
                    projected
                })
                .collect(),
        );
    }
    Ok(projected)
}

fn select(record: &Value, fields: &[&str]) -> Value {
    Value::Object(
        fields
            .iter()
            .filter_map(|field| {
                record
                    .get(*field)
                    .map(|value| ((*field).into(), value.clone()))
            })
            .collect(),
    )
}
fn next_link(response: &Value, field: &str) -> Result<String, &'static str> {
    match response.get(field) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err("connector_cursor_invalid"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn hosted_cursors_restart_after_scope_or_credentials_change() {
        let base = Url::parse("https://api.openai.com/").unwrap();
        let first = cursor_prefix("openai", &base, "secret-one", Some("proj_one"));
        assert!(!first.contains("secret-one"));
        assert_ne!(
            first,
            cursor_prefix("openai", &base, "secret-two", Some("proj_one"))
        );
        assert_ne!(
            first,
            cursor_prefix("openai", &base, "secret-one", Some("proj_two"))
        );
        assert!(!cursor_has_more(&first));
        assert!(cursor_has_more(&format!("{first}agent_1")));
        assert!(cursor_has_more("agents-v1:100"));
        assert!(!cursor_has_more("agents-v1:"));
        assert!(!cursor_has_more("invalid"));
    }

    #[test]
    fn hosted_agent_pages_validate_cursors_and_strip_content() {
        let base = Url::parse("https://api.openai.com/").unwrap();
        for (platform, response, cursor) in [
            (
                "openai",
                json!({"data":[{"id":"a1","name":"Research","model":"gpt-5","instructions":"CONTENT_CANARY","tools":[{"headers":{"key":"CONTENT_CANARY"}}]}],"has_more":true,"last_id":"a1"}),
                "a1",
            ),
            (
                "claude",
                json!({"data":[{"id":"a1","name":"Research","model":{"id":"claude-sonnet-4-6","extra":"CONTENT_CANARY"},"system":"CONTENT_CANARY","archived_at":null}],"next_page":"page2"}),
                "page2",
            ),
            (
                "gemini",
                json!({"agents":[{"id":"research","display_name":"Research","agent_config":{"model":"gemini-2.5-pro","extra":"CONTENT_CANARY"},"system_instruction":"CONTENT_CANARY","base_environment":{"env":{"SECRET":"CONTENT_CANARY"}}}],"next_page_token":"page2"}),
                "page2",
            ),
        ] {
            let page = parse_page(platform, &base, "", &response, None).unwrap();
            assert_eq!(page.next, cursor);
            assert_eq!(page.records.len(), 1);
            assert!(page.records[0]["model"].is_string());
            assert!(!page.records[0].to_string().contains("CONTENT_CANARY"));
            assert!(parse_page(platform, &base, cursor, &response, None).is_err());
        }
        for response in [
            json!({"data":[],"has_more":true}),
            json!({"data":[],"has_more":"false"}),
            json!({"data":[{"name":"missing id"}],"has_more":false}),
        ] {
            assert!(parse_page("openai", &base, "", &response, None).is_err());
        }
        for platform in ["claude", "gemini"] {
            let (field, next) = if platform == "claude" {
                ("data", "next_page")
            } else {
                ("agents", "next_page_token")
            };
            assert!(parse_page(platform, &base, "", &json!({field:[], next:42}), None).is_err());
            assert!(
                parse_page(
                    platform,
                    &base,
                    "",
                    &json!({field:vec![json!({"id":"a"});101]}),
                    None
                )
                .is_err()
            );
        }
        assert_eq!(
            parse_page("gemini", &base, "", &json!({}), None)
                .unwrap()
                .records,
            Vec::<Value>::new()
        );
        assert!(parse_page("gemini", &base, "", &json!({"agents":null}), None).is_err());
        assert!(
            parse_page(
                "gemini",
                &base,
                "",
                &json!({"error":{"message":"CONTENT_CANARY"}}),
                None
            )
            .is_err()
        );
    }

    /// Runs the production HTTP request, page projection and normalizer against the checked-in
    /// Postman simulation. No provider credentials or database are required.
    #[tokio::test]
    #[ignore = "requires postman simulation run postman/simulations/managed-agents.sim.yaml --port 4917"]
    async fn hosted_agents_postman_simulation() {
        let origin = std::env::var("TALLY_MANAGED_AGENTS_SIM_URL").expect("simulation URL");
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        for (platform, scope, model) in [
            ("openai", "proj_test", "gpt-5"),
            ("claude", "wrkspc_test", "claude-sonnet-4-6"),
            ("gemini", "projects/test/locations/global", "gemini-2.5-pro"),
        ] {
            let base = Url::parse(&format!("{origin}/{platform}/")).unwrap();
            let first = read_page(
                &client,
                platform,
                &base,
                "fixture-key",
                "",
                None,
                Some(scope),
            )
            .await
            .unwrap();
            assert_eq!(first.records.len(), 1);
            assert_ne!(first.next, "");
            let second = read_page(
                &client,
                platform,
                &base,
                "fixture-key",
                &first.next,
                None,
                Some(scope),
            )
            .await
            .unwrap();
            assert_eq!(second.records.len(), 1);
            assert_eq!(second.next, "");
            let input = json!({"platform":platform,"origin":base.origin().ascii_serialization(),"scope":scope,"observed_at":"2026-10-16T00:00:00Z","records":[first.records[0],second.records[0]]});
            let outcome = adapter(platform)
                .unwrap()
                .normalize(
                    &serde_json::to_vec(&input).unwrap(),
                    &VendorImportConfig {
                        installation_id: uuid::Uuid::from_u128(1),
                        connector_instance_id: uuid::Uuid::from_u128(2),
                        implementation_version: "test".into(),
                        source_lineage_id: None,
                        received_at: Utc::now(),
                        checkpoint: Cursor("agents-v1:".into()),
                        pseudonymization_key: PseudonymizationKey::new(&[7; 32]).unwrap(),
                    },
                )
                .unwrap();
            assert_eq!(outcome.stats.accepted, 2);
            assert!(
                outcome
                    .batch
                    .observations
                    .iter()
                    .all(|o| o.agent.key.is_some()
                        && o.service.declared_model_id.as_deref() == Some(model))
            );
            assert!(
                !serde_json::to_string(&outcome)
                    .unwrap()
                    .contains("CONTENT_CANARY")
            );
            for key in [
                "fixture-401",
                "fixture-403",
                "fixture-429",
                "fixture-500",
                "fixture-invalid-json",
            ] {
                assert!(
                    read_page(&client, platform, &base, key, "", None, Some(scope))
                        .await
                        .is_err()
                );
            }
            let empty = read_page(
                &client,
                platform,
                &base,
                "fixture-empty",
                "",
                None,
                Some(scope),
            )
            .await
            .unwrap();
            assert!(empty.records.is_empty() && empty.next.is_empty());
        }
    }

    async fn server(pages: Vec<Value>) -> (Url, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let origin = base.origin().ascii_serialization();
        let handle = tokio::spawn(async move {
            let mut requests = Vec::new();
            for page in pages {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut data = Vec::new();
                loop {
                    let mut buffer = [0u8; 4096];
                    let n = stream.read(&mut buffer).await.unwrap();
                    assert!(n > 0);
                    data.extend_from_slice(&buffer[..n]);
                    let text = String::from_utf8_lossy(&data);
                    if let Some(end) = text.find("\r\n\r\n") {
                        let length = text[..end]
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|s| s.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if data.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                requests.push(String::from_utf8(data).unwrap());
                let body = page.to_string().replace("TEST_ORIGIN", &origin);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            requests
        });
        (base, handle)
    }

    #[tokio::test]
    async fn langgraph_search_is_read_only_paged_and_discards_configuration() {
        let full = (0..100).map(|i| json!({"assistant_id":i.to_string(),"name":"Agent","graph_id":"support","config":{"prompt":"CONTENT_CANARY"}})).collect::<Vec<_>>();
        let (base, handle) = server(vec![
            json!(full),
            json!([{"assistant_id":"last","name":"Last","config":"CONTENT_CANARY"}]),
        ])
        .await;
        let client = Client::new();
        let first = read_page(&client, "langgraph", &base, "fixture-key", "", None, None)
            .await
            .unwrap();
        assert_eq!(first.next, "100");
        assert!(
            !serde_json::to_string(&first.records)
                .unwrap()
                .contains("CONTENT_CANARY")
        );
        let second = read_page(
            &client,
            "langgraph",
            &base,
            "fixture-key",
            &first.next,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(second.next, "");
        assert_eq!(second.records.len(), 1);
        let requests = handle.await.unwrap();
        assert!(requests[0].starts_with("POST /assistants/search "));
        assert!(
            requests[0]
                .to_ascii_lowercase()
                .contains("x-api-key: fixture-key")
        );
        let body: Value =
            serde_json::from_str(requests[1].split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body["offset"], 100);
        assert_eq!(body["select"], json!(["assistant_id", "name", "graph_id"]));
    }

    #[tokio::test]
    async fn copilot_pages_resume_the_exact_scoped_next_link() {
        let next = format!(
            "TEST_ORIGIN/api/data/v9.2/bots?$select={COPILOT_FIELDS}&$orderby=botid&$skiptoken=page2"
        );
        let (base, handle)=server(vec![json!({"value":[{"botid":"b1","name":"Agent","configuration":"CONTENT_CANARY"}],"@odata.nextLink":next}),json!({"value":[{"botid":"b2","name":"Next","statecode":0}]})]).await;
        let client = Client::new();
        let first = read_page(
            &client,
            "copilot_studio",
            &base,
            "fixture-token",
            "",
            None,
            None,
        )
        .await
        .unwrap();
        assert!(!first.records[0].to_string().contains("CONTENT_CANARY"));
        let second = read_page(
            &client,
            "copilot_studio",
            &base,
            "fixture-token",
            &first.next,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(second.next, "");
        let requests = handle.await.unwrap();
        assert!(
            requests[0]
                .to_ascii_lowercase()
                .contains("prefer: odata.maxpagesize=100")
        );
        assert!(requests[1].contains("$skiptoken=page2"));
        assert!(
            requests[1]
                .to_ascii_lowercase()
                .contains("authorization: bearer fixture-token")
        );
    }

    #[test]
    fn copilot_cursors_cannot_escape_the_environment_or_expand_requested_fields() {
        let base = Url::parse("https://company.crm.dynamics.com/").unwrap();
        for next in [
            format!("https://attacker.example/api/data/v9.2/bots?$select={COPILOT_FIELDS}"),
            format!(
                "https://company.crm.dynamics.com/api/data/v9.2/accounts?$select={COPILOT_FIELDS}"
            ),
            "https://company.crm.dynamics.com/api/data/v9.2/bots?$select=configuration".into(),
        ] {
            assert!(copilot_url(&base, &next).is_err());
        }
    }

    #[tokio::test]
    async fn dify_reads_only_the_configured_apps_basic_metadata() {
        let (base, handle)=server(vec![json!({"name":"Helpdesk","mode":"agent-chat","description":"CONTENT_CANARY","tags":["CONTENT_CANARY"]})]).await;
        let id = "00000000-0000-0000-0000-000000000001";
        let page = read_page(
            &Client::new(),
            "dify",
            &base,
            "fixture-token",
            "",
            Some(id),
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            page.records[0],
            json!({"id":id,"name":"Helpdesk","mode":"agent-chat"})
        );
        assert_eq!(page.next, "");
        let requests = handle.await.unwrap();
        assert!(requests[0].starts_with("GET /v1/info "));
        assert!(
            requests[0]
                .to_ascii_lowercase()
                .contains("authorization: bearer fixture-token")
        );
    }

    #[test]
    fn malformed_or_repeating_pages_cannot_advance_the_cursor() {
        let base = Url::parse("https://n8n.example/").unwrap();
        assert!(
            parse_page(
                "n8n",
                &base,
                "page1",
                &json!({"data":[],"nextCursor":"page1"}),
                None
            )
            .is_err()
        );
        assert!(
            parse_page(
                "langgraph",
                &base,
                "",
                &json!({"error":"permission denied"}),
                None
            )
            .is_err()
        );
        assert!(
            parse_page(
                "copilot_studio",
                &base,
                "",
                &json!({"value":vec![json!({});101]}),
                None
            )
            .is_err()
        );
        assert!(
            parse_page(
                "dify",
                &base,
                "",
                &json!({"mode":"agent-chat"}),
                Some("not-a-uuid")
            )
            .is_err()
        );
    }
}
