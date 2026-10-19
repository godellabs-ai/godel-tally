//! Read-only Microsoft Purview Data Map and Information Protection client.
//! Purview does not guarantee content hashes. Only an explicitly configured SHA-256
//! attribute can be used as a hash identity; names and search keywords are never identities.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use url::Url;

type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub tenant_id: String,
    pub client_id: String,
    pub catalog_endpoint: String,
    #[serde(default)]
    pub collection: String,
    #[serde(default)]
    pub sha256_attribute: String,
    #[serde(default)]
    pub sensitivity_labels: bool,
}
impl Settings {
    /// Validate the configured account and attribute names.
    /// # Errors
    /// Returns a sanitized validation, authentication, or API error.
    pub fn validate(&self) -> Result<()> {
        uuid::Uuid::parse_str(&self.tenant_id).map_err(|_| "Tenant ID must be a UUID")?;
        uuid::Uuid::parse_str(&self.client_id).map_err(|_| "Client ID must be a UUID")?;
        let u = Url::parse(&self.catalog_endpoint).map_err(|_| "Invalid catalog endpoint")?;
        let host = u.host_str().unwrap_or_default();
        if u.scheme() != "https"
            || !host.ends_with(".purview.azure.com")
            || host.trim_end_matches(".purview.azure.com").is_empty()
            || u.port().is_some()
            || !u.username().is_empty()
            || u.password().is_some()
            || !matches!(u.path(), "" | "/")
            || u.query().is_some()
            || u.fragment().is_some()
        {
            return Err("Use an HTTPS account endpoint under purview.azure.com".into());
        }
        if !self
            .sha256_attribute
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
            || self.sha256_attribute.len() > 128
            || self.collection.len() > 256
        {
            return Err("Invalid collection or SHA-256 attribute".into());
        }
        Ok(())
    }
}

pub struct Client {
    http: reqwest::Client,
    settings: Settings,
    token: String,
    graph_token: Option<String>,
    sensitivity_selection: std::sync::OnceLock<String>,
}
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PurviewClient").finish_non_exhaustive()
    }
}
impl Client {
    /// Authenticate for the configured read-only APIs.
    /// # Errors
    /// Returns a sanitized validation, authentication, or API error.
    pub async fn connect(settings: Settings, secret: &str) -> Result<Self> {
        settings.validate()?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| "HTTP client unavailable")?;
        let token = Self::token(
            &http,
            &settings,
            secret,
            "https://purview.azure.net/.default",
        )
        .await?;
        let graph_token = if settings.sensitivity_labels {
            Some(
                Self::token(
                    &http,
                    &settings,
                    secret,
                    "https://graph.microsoft.com/.default",
                )
                .await?,
            )
        } else {
            None
        };
        Ok(Self {
            http,
            settings,
            token,
            graph_token,
            sensitivity_selection: std::sync::OnceLock::new(),
        })
    }
    async fn token(
        http: &reqwest::Client,
        s: &Settings,
        secret: &str,
        scope: &str,
    ) -> Result<String> {
        let value = response(
            http.post(format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                s.tenant_id
            ))
            .form(&[
                ("client_id", s.client_id.as_str()),
                ("client_secret", secret),
                ("grant_type", "client_credentials"),
                ("scope", scope),
            ])
            .send()
            .await,
        )
        .await?;
        value["access_token"]
            .as_str()
            .map(str::to_owned)
            .ok_or("Token response is missing access_token".into())
    }
    fn url(&self, path: &str) -> String {
        format!(
            "{}/datamap/api/{path}",
            self.settings.catalog_endpoint.trim_end_matches('/')
        )
    }
    /// Read classification definitions.
    /// # Errors
    /// Returns a sanitized validation, authentication, or API error.
    pub async fn classifications(&self) -> Result<Value> {
        response(
            self.http
                .get(self.url("tally/v2/types/typedefs"))
                .query(&[("api-version", "2023-09-01"), ("type", "classification")])
                .bearer_auth(&self.token)
                .send()
                .await,
        )
        .await
    }
    /// Fetch a bounded glossary or term page.
    /// # Errors
    /// Returns a sanitized request or protocol error.
    pub async fn glossary_page(&self, glossary: Option<&str>, offset: usize) -> Result<Value> {
        let path = if let Some(id) = glossary {
            uuid::Uuid::parse_str(id).map_err(|_| "Invalid glossary ID")?;
            format!("tally/v2/glossary/{id}/terms")
        } else {
            "tally/v2/glossary".into()
        };
        response(
            self.http
                .get(self.url(&path))
                .query(&[
                    ("api-version", "2023-09-01"),
                    ("limit", "100"),
                    ("offset", &offset.to_string()),
                    ("ignoreTermsAndCategories", "true"),
                ])
                .bearer_auth(&self.token)
                .send()
                .await,
        )
        .await
    }
    /// Read one bounded file search page.
    /// # Errors
    /// Returns a sanitized validation, authentication, or API error.
    pub async fn files(&self, continuation: Option<&str>) -> Result<Value> {
        let mut filter = vec![json!({"objectType":"Files"})];
        if !self.settings.collection.is_empty() {
            filter.push(json!({"collectionId":self.settings.collection}));
        }
        response(
            self.http
                .post(self.url("search/query"))
                .query(&[("api-version", "2023-09-01")])
                .bearer_auth(&self.token)
                .json(&json!({"filter":{"and":filter}, "limit":100,
                "continuationToken":continuation}))
                .send()
                .await,
        )
        .await
    }
    /// Read a bounded batch of exact assets and their classification assignments.
    /// # Errors
    /// Returns a sanitized validation, authentication, or API error.
    pub async fn entities(&self, ids: &[&str]) -> Result<Value> {
        if ids.is_empty() || ids.len() > 100 {
            return Err("Expected between 1 and 100 asset IDs".into());
        }
        let mut query = vec![
            ("api-version", "2023-09-01"),
            ("minExtInfo", "true"),
            ("ignoreRelationships", "false"),
        ];
        for id in ids {
            uuid::Uuid::parse_str(id).map_err(|_| "Invalid asset ID")?;
            query.push(("guid", *id));
        }
        response(
            self.http
                .get(self.url("tally/v2/entity/bulk"))
                .query(&query)
                .bearer_auth(&self.token)
                .send()
                .await,
        )
        .await
    }
    /// Read files together with classifications on their attached schemas and columns.
    /// Only containment edges are followed; lineage and neighboring datasets are excluded.
    /// # Errors
    /// Returns an error for incomplete responses or excessive schema size/depth.
    pub async fn file_entities(&self, ids: &[&str]) -> Result<Value> {
        let mut entities = BTreeMap::new();
        let mut pending: BTreeSet<String> = ids.iter().map(|id| (*id).to_owned()).collect();
        for depth in 0..=8 {
            if pending.is_empty() {
                break;
            }
            if depth == 8 || entities.len() + pending.len() > 10_000 {
                return Err("Purview file schema exceeds the traversal limit".into());
            }
            let names: Vec<_> = pending.iter().map(String::as_str).collect();
            for chunk in names.chunks(100) {
                let batch = self.entities(chunk).await?;
                let values = batch["entities"]
                    .as_array()
                    .ok_or("Missing Purview entities")?;
                let returned: BTreeSet<_> =
                    values.iter().filter_map(|e| e["guid"].as_str()).collect();
                if returned.len() != chunk.len() || chunk.iter().any(|id| !returned.contains(id)) {
                    return Err("Incomplete Purview file schema response".into());
                }
                for entity in values {
                    entities.insert(
                        entity["guid"]
                            .as_str()
                            .ok_or("Missing entity ID")?
                            .to_owned(),
                        entity.clone(),
                    );
                }
            }
            let mut next = BTreeSet::new();
            for id in &pending {
                for child in schema_references(&entities[id])? {
                    if !entities.contains_key(child) {
                        next.insert(child.to_owned());
                    }
                }
            }
            pending = next;
        }
        let files = ids
            .iter()
            .map(|id| merge_file_schema(id, &entities))
            .collect::<Result<Vec<_>>>()?;
        Ok(json!({"entities": files}))
    }
    async fn graphql(&self, query: String) -> Result<Value> {
        let result = response(
            self.http
                .post(self.url("graphql"))
                .bearer_auth(&self.token)
                .json(&json!({"query":query}))
                .send()
                .await,
        )
        .await?;
        if result.get("errors").is_some() {
            return Err(
                "Purview GraphQL sensitivity query failed; verify preview API access".into(),
            );
        }
        Ok(result)
    }
    /// The preview API is introspectable. Discover its sensitivity-label scalar fields rather
    /// than assuming the Tally free-form labels property contains MIP label assignments.
    /// # Errors
    /// Returns an error when schema discovery, authorization, or asset coverage is incomplete.
    pub async fn asset_sensitivity(&self, ids: &[&str]) -> Result<Value> {
        if ids.len() > 100 {
            return Err("Too many asset IDs".into());
        }
        for id in ids {
            uuid::Uuid::parse_str(id).map_err(|_| "Invalid asset ID")?;
        }
        let selection = if let Some(s) = self.sensitivity_selection.get() {
            s.clone()
        } else {
            let schema = self.graphql("{ __schema { types { name fields { name type { kind name ofType { kind name } } } } } }".into()).await?;
            let types = schema["data"]["__schema"]["types"]
                .as_array()
                .ok_or("Missing GraphQL schema")?;
            let field = types
                .iter()
                .flat_map(|t| t["fields"].as_array().into_iter().flatten())
                .find(|f| f["name"] == "sensitivityLabel")
                .ok_or("Purview sensitivityLabel field unavailable")?;
            let mut ty = &field["type"];
            if ty["kind"] == "NON_NULL" || ty["kind"] == "LIST" {
                ty = &ty["ofType"];
            }
            let s = if ty["kind"] == "SCALAR" {
                "sensitivityLabel".to_owned()
            } else {
                let object = types
                    .iter()
                    .find(|t| t["name"] == ty["name"])
                    .ok_or("Missing sensitivity-label type")?;
                let fields = object["fields"]
                    .as_array()
                    .ok_or("Missing sensitivity label fields")?;
                let id = ["labelId", "id", "guid"]
                    .into_iter()
                    .find(|name| {
                        fields.iter().any(|f| {
                            f["name"] == *name
                                && (f["type"]["kind"] == "SCALAR"
                                    || f["type"]["ofType"]["kind"] == "SCALAR")
                        })
                    })
                    .ok_or("Sensitivity label identifier unavailable")?;
                format!("sensitivityLabel {{ id: {id} }}")
            };
            let _ = self.sensitivity_selection.set(s.clone());
            s
        };
        let expected = ids;
        let ids = serde_json::to_string(ids).map_err(|_| "Invalid asset IDs")?;
        let result = self
            .graphql(format!(
                "{{ entities(where: {{ guid: {ids} }}) {{ guid {selection} }} }}"
            ))
            .await?;
        let entities = result["data"]["entities"]
            .as_array()
            .ok_or("Missing sensitivity asset assignments")?;
        let mut out = serde_json::Map::new();
        for entity in entities {
            if let Some(id) = entity["guid"].as_str() {
                let label = &entity["sensitivityLabel"];
                out.insert(
                    id.into(),
                    if label.is_string() {
                        json!({"id":label})
                    } else {
                        label.clone()
                    },
                );
            }
        }
        if out.len() != expected.len() || expected.iter().any(|id| !out.contains_key(*id)) {
            return Err("Incomplete sensitivity asset response".into());
        }
        Ok(Value::Object(out))
    }
    /// Read sensitivity definitions using an origin-checked continuation.
    /// # Errors
    /// Returns a sanitized validation, authentication, or API error.
    pub async fn sensitivity_page(&self, next: Option<&str>) -> Result<Value> {
        let url = next.unwrap_or(
            "https://graph.microsoft.com/v1.0/security/dataSecurityAndGovernance/sensitivityLabels",
        );
        let parsed = Url::parse(url).map_err(|_| "Invalid Graph continuation")?;
        if parsed.scheme() != "https"
            || parsed.host_str() != Some("graph.microsoft.com")
            || parsed.port().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || !parsed
                .path()
                .starts_with("/v1.0/security/dataSecurityAndGovernance/sensitivityLabels")
        {
            return Err("Invalid Graph continuation origin".into());
        }
        response(
            self.http
                .get(url)
                .bearer_auth(
                    self.graph_token
                        .as_deref()
                        .ok_or("Sensitivity label sync is disabled")?,
                )
                .send()
                .await,
        )
        .await
    }
}
fn schema_references(entity: &Value) -> Result<Vec<&str>> {
    if entity["status"] == "DELETED" {
        return Ok(vec![]);
    }
    let mut ids = Vec::new();
    for name in ["attachedSchema", "schema", "columns"] {
        let value = &entity["relationshipAttributes"][name];
        let references: Vec<_> = match value {
            Value::Array(items) => items.iter().collect(),
            Value::Object(_) => vec![value],
            Value::Null => vec![],
            _ => return Err("Invalid Purview schema relationship".into()),
        };
        for reference in references {
            if reference["entityStatus"] == "DELETED"
                || reference["relationshipStatus"] == "DELETED"
            {
                continue;
            }
            ids.push(
                reference["guid"]
                    .as_str()
                    .ok_or("Missing schema entity ID")?,
            );
        }
    }
    Ok(ids)
}

fn merge_file_schema(id: &str, entities: &BTreeMap<String, Value>) -> Result<Value> {
    let mut file = entities.get(id).ok_or("Missing file entity")?.clone();
    let mut pending = vec![id];
    let mut seen = BTreeSet::new();
    let mut classifications = Vec::new();
    let mut meanings = Vec::new();
    let mut relationships = Vec::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        let entity = entities
            .get(id)
            .ok_or("Incomplete Purview file schema response")?;
        if entity["status"] == "DELETED" {
            continue;
        }
        classifications.extend(
            entity["classifications"]
                .as_array()
                .into_iter()
                .flatten()
                .cloned(),
        );
        meanings.extend(entity["meanings"].as_array().into_iter().flatten().cloned());
        relationships.extend(
            entity["relationshipAttributes"]["meanings"]
                .as_array()
                .into_iter()
                .flatten()
                .cloned(),
        );
        pending.extend(schema_references(entity)?);
    }
    file["classifications"] = json!(classifications);
    file["meanings"] = json!(meanings);
    if !file["relationshipAttributes"].is_object() {
        file["relationshipAttributes"] = json!({});
    }
    file["relationshipAttributes"]["meanings"] = json!(relationships);
    Ok(file)
}

async fn response(
    response: std::result::Result<reqwest::Response, reqwest::Error>,
) -> Result<Value> {
    let mut response = response.map_err(|_| "Microsoft API request failed")?;
    if !response.status().is_success() {
        return Err(format!(
            "Microsoft API returned HTTP {}",
            response.status().as_u16()
        ));
    }
    if response
        .content_length()
        .is_some_and(|n| n > 16 * 1024 * 1024)
    {
        return Err("Microsoft response exceeds size limit".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Microsoft response could not be read")?
    {
        if bytes.len() + chunk.len() > 16 * 1024 * 1024 {
            return Err("Microsoft response exceeds size limit".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "Microsoft returned invalid JSON".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_labels_include_columns_and_terms_but_not_lineage_or_deleted_relations() {
        let entities = BTreeMap::from([
            (
                "file".into(),
                json!({"guid":"file", "relationshipAttributes": {
                    "attachedSchema":[{"guid":"schema"}], "sources":[{"guid":"unrelated"}],
                    "meanings":[{"guid":"project", "displayText":"Project Orchid"}]
                }}),
            ),
            (
                "schema".into(),
                json!({"guid":"schema", "relationshipAttributes": {
                    "columns":[{"guid":"column"},{"guid":"removed", "relationshipStatus":"DELETED"}]
                }}),
            ),
            (
                "column".into(),
                json!({"guid":"column", "classifications":[{"typeName":"EMAIL"}],
                    "relationshipAttributes":{"schema":{"guid":"schema"}}
                }),
            ),
        ]);
        let file = merge_file_schema("file", &entities).unwrap();
        assert_eq!(file["classifications"], json!([{"typeName":"EMAIL"}]));
        assert_eq!(
            file["relationshipAttributes"]["meanings"][0]["guid"],
            "project"
        );
        let mut incomplete = entities;
        incomplete.remove("column");
        assert!(merge_file_schema("file", &incomplete).is_err());
    }
    #[test]
    fn rejects_non_account_endpoints() {
        let mut s = Settings {
            tenant_id: uuid::Uuid::nil().to_string(),
            client_id: uuid::Uuid::nil().to_string(),
            catalog_endpoint: "https://example.purview.azure.com".into(),
            collection: String::new(),
            sha256_attribute: String::new(),
            sensitivity_labels: false,
        };
        assert!(s.validate().is_ok());
        for endpoint in [
            "http://example.purview.azure.com",
            "https://evil.test",
            "https://example.purview.azure.com@evil.test",
            "https://example.purview.azure.com/path",
        ] {
            s.catalog_endpoint = endpoint.into();
            assert!(s.validate().is_err());
        }
    }
}
