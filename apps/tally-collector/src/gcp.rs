use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use gcp_auth::TokenProvider;
use reqwest::{Response, Url, header};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tally_connectors::{GcpServiceAccountCredentials, MAX_IMPORT_BYTES};
use tally_core::Hostname;

use crate::{
    VendorAdapter,
    pull_support::{NativeCloudSnapshot, NativeNetworkPull, NativeNetworkSnapshot},
};

const GCP_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
const GCP_LOGGING_SCOPE: &str = "https://www.googleapis.com/auth/logging.read";
const GCP_COMPUTE_SCOPE: &str = "https://www.googleapis.com/auth/compute.readonly";
const MAX_PROVIDER_PAGES: usize = 100;
const MAX_PROVIDER_RESOURCES: usize = 10_000;
const MAX_PROVIDER_RECORDS: usize = 10_000;
const MAX_PAGE_BYTES: usize = 16 * 1_024 * 1_024;
const FLOW_INGESTION_DELAY_MINUTES: i64 = 5;
const FLOW_OVERLAP_MINUTES: i64 = 5;
const MAPPING_LOOKBACK_MINUTES: i64 = 10;
const MAPPING_FUTURE_MINUTES: i64 = 5;
const GCP_CURSOR_PREFIX: &str = "gcp-network-v1:";

pub(crate) async fn pull_inventory(
    client: &reqwest::Client,
    project_id: &str,
    location: &str,
    static_credentials: Option<&GcpServiceAccountCredentials>,
) -> Result<NativeCloudSnapshot> {
    inventory::pull_gcp(client, project_id, location, static_credentials).await
}

pub(crate) async fn pull_network(
    request: &NativeNetworkPull<'_>,
    client: &reqwest::Client,
) -> Result<NativeNetworkSnapshot> {
    ensure!(
        (300..=3_600).contains(&request.initial_lookback_seconds),
        "cloud-network lookback is invalid"
    );
    ensure!(
        request.region == "global",
        "Google Cloud network region must be global"
    );
    ensure!(
        request.log_group.is_none(),
        "Google Cloud does not accept an AWS log group"
    );
    ensure!(
        request.workspace_resource.is_none(),
        "Google Cloud does not accept an Azure workspace"
    );
    network::pull_gcp(request, client).await
}

mod inventory {
    use super::{
        Context, DateTime, Deserialize, DeserializeOwned, Duration, GCP_SCOPE,
        GcpServiceAccountCredentials, IpAddr, MAX_IMPORT_BYTES, MAX_PAGE_BYTES, MAX_PROVIDER_PAGES,
        MAX_PROVIDER_RESOURCES, NativeCloudSnapshot, Response, Result, Serialize, TokenProvider,
        Url, Utc, anyhow, ensure, header,
    };
    #[allow(clippy::too_many_lines)] // Keeps inventory and its bounded audit-log join together.
    pub(super) async fn pull_gcp(
        client: &reqwest::Client,
        project_id: &str,
        location: &str,
        static_credentials: Option<&GcpServiceAccountCredentials>,
    ) -> Result<NativeCloudSnapshot> {
        validate_gcp_scope(project_id, location)?;
        let token = if let Some(credentials) = static_credentials {
            gcp_auth::CustomServiceAccount::from_json(&credentials.json)
                .map_err(|_| anyhow!("Google Cloud service-account credential is invalid"))?
                .token(&[GCP_SCOPE])
                .await
                .map_err(|_| anyhow!("Google Cloud service-account authentication failed"))?
        } else {
            let provider = gcp_auth::provider().await.map_err(|_| {
                anyhow!("no usable Google Cloud application default credential was found")
            })?;
            provider
                .token(&[GCP_SCOPE])
                .await
                .map_err(|_| anyhow!("Google Cloud authentication failed"))?
        };

        let mut endpoints = Vec::new();
        let mut page_token = None;
        let mut exhausted = false;
        for _ in 0..MAX_PROVIDER_PAGES {
            let url = gcp_list_url(project_id, location, "endpoints", page_token.as_deref())?;
            let response = client
                .get(url)
                .header(header::ACCEPT, "application/json")
                .bearer_auth(token.as_str())
                .send()
                .await
                .map_err(|_| anyhow!("Google Vertex endpoint inventory request failed"))?;
            let page: GcpEndpointsPage =
                bounded_json(response, "Google Vertex endpoint inventory").await?;
            endpoints.extend(
                page.endpoints
                    .into_iter()
                    .map(|endpoint| endpoint.minimal(project_id, location))
                    .collect::<Result<Vec<_>>>()?,
            );
            enforce_resource_cap(endpoints.len(), "Google Vertex inventory")?;
            page_token = checked_provider_token(page.next_page_token.as_deref())?;
            if page_token.is_none() {
                exhausted = true;
                break;
            }
        }
        ensure!(
            exhausted,
            "Google Vertex endpoint inventory exceeded the page cap"
        );

        let mut models = Vec::new();
        page_token = None;
        exhausted = false;
        for _ in 0..MAX_PROVIDER_PAGES {
            let url = gcp_list_url(project_id, location, "models", page_token.as_deref())?;
            let response = client
                .get(url)
                .header(header::ACCEPT, "application/json")
                .bearer_auth(token.as_str())
                .send()
                .await
                .map_err(|_| anyhow!("Google Vertex model inventory request failed"))?;
            let page: GcpModelsPage =
                bounded_json(response, "Google Vertex model inventory").await?;
            models.extend(
                page.models
                    .into_iter()
                    .map(|model| model.minimal(project_id, location))
                    .collect::<Result<Vec<_>>>()?,
            );
            enforce_resource_cap(endpoints.len() + models.len(), "Google Vertex inventory")?;
            page_token = checked_provider_token(page.next_page_token.as_deref())?;
            if page_token.is_none() {
                exhausted = true;
                break;
            }
        }
        ensure!(
            exhausted,
            "Google Vertex model inventory exceeded the page cap"
        );
        let invocations = gcp_vertex_invocations(
            client,
            token.as_str(),
            project_id,
            location,
            Utc::now() - Duration::hours(1),
        )
        .await?;
        let record_count = endpoints.len()
            + endpoints
                .iter()
                .map(|endpoint| endpoint.deployed_models.len())
                .sum::<usize>()
            + models.len()
            + invocations.len();
        enforce_resource_cap(record_count, "Google Vertex inventory")?;
        serialize_snapshot(
            &GcpEnvelope {
                endpoints: GcpEndpoints { endpoints },
                models: GcpModels { models },
                invocations,
            },
            record_count,
        )
    }

    fn validate_gcp_scope(project_id: &str, location: &str) -> Result<()> {
        ensure!(
            (6..=30).contains(&project_id.len())
                && project_id
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && project_id
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_lowercase()),
            "Google Cloud project ID is invalid"
        );
        ensure!(
            !location.is_empty()
                && location.len() <= 63
                && location
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
            "Google Cloud location is invalid"
        );
        Ok(())
    }

    fn gcp_list_url(
        project_id: &str,
        location: &str,
        collection: &str,
        page_token: Option<&str>,
    ) -> Result<Url> {
        validate_gcp_scope(project_id, location)?;
        ensure!(
            matches!(collection, "endpoints" | "models"),
            "Google Cloud collection is invalid"
        );
        let mut url = Url::parse(&format!("https://{location}-aiplatform.googleapis.com/"))?;
        url.set_path(&format!(
            "/v1/projects/{project_id}/locations/{location}/{collection}"
        ));
        let mut query = url.query_pairs_mut();
        query.append_pair("pageSize", "100");
        if let Some(page_token) = page_token {
            let page_token = checked_provider_token(Some(page_token))?
                .ok_or_else(|| anyhow!("Google Cloud page token is invalid"))?;
            query.append_pair("pageToken", &page_token);
        }
        drop(query);
        Ok(url)
    }

    async fn gcp_vertex_invocations(
        client: &reqwest::Client,
        token: &str,
        project_id: &str,
        location: &str,
        window_start: DateTime<Utc>,
    ) -> Result<Vec<GcpInvocation>> {
        validate_gcp_scope(project_id, location)?;
        let mut invocations = Vec::new();
        let mut page_token = None;
        let mut exhausted = false;
        for _ in 0..MAX_PROVIDER_PAGES {
            let filter = format!(
                "logName=\"projects/{project_id}/logs/cloudaudit.googleapis.com%2Fdata_access\" AND protoPayload.serviceName=\"aiplatform.googleapis.com\" AND timestamp>=\"{}\"",
                window_start.to_rfc3339()
            );
            let response = client
                .post("https://logging.googleapis.com/v2/entries:list")
                .header(header::ACCEPT, "application/json")
                .bearer_auth(token)
                .json(&GcpAuditListRequest {
                    resource_names: vec![format!("projects/{project_id}")],
                    filter,
                    order_by: "timestamp asc",
                    page_size: 1_000,
                    page_token: page_token.as_deref(),
                })
                .send()
                .await
                .map_err(|_| anyhow!("Google Vertex invocation-log request failed"))?;
            let page: GcpAuditPage =
                bounded_json(response, "Google Vertex invocation logs").await?;
            invocations.extend(
                page.entries
                    .into_iter()
                    .filter_map(|entry| entry.minimal(project_id, location).transpose())
                    .collect::<Result<Vec<_>>>()?,
            );
            enforce_resource_cap(invocations.len(), "Google Vertex invocation logs")?;
            page_token = checked_provider_token(page.next_page_token.as_deref())?;
            if page_token.is_none() {
                exhausted = true;
                break;
            }
        }
        ensure!(
            exhausted,
            "Google Vertex invocation logs exceeded the page cap"
        );
        Ok(invocations)
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct GcpAuditListRequest<'a> {
        resource_names: Vec<String>,
        filter: String,
        order_by: &'static str,
        page_size: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        page_token: Option<&'a str>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct GcpAuditPage {
        #[serde(default)]
        entries: Vec<GcpAuditEntry>,
        #[serde(default)]
        next_page_token: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct GcpAuditEntry {
        insert_id: String,
        timestamp: DateTime<Utc>,
        proto_payload: GcpAuditPayload,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct GcpAuditPayload {
        method_name: String,
        resource_name: String,
        #[serde(default)]
        authentication_info: GcpAuditAuthentication,
        #[serde(default)]
        request_metadata: GcpAuditRequestMetadata,
        #[serde(default)]
        status: GcpAuditStatus,
    }

    #[derive(Default, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct GcpAuditAuthentication {
        #[serde(default)]
        principal_email: Option<String>,
    }

    #[derive(Default, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct GcpAuditRequestMetadata {
        #[serde(default)]
        caller_ip: Option<String>,
    }

    #[derive(Default, Deserialize)]
    struct GcpAuditStatus {
        #[serde(default)]
        code: Option<i64>,
    }

    impl GcpAuditEntry {
        fn minimal(self, project_id: &str, location: &str) -> Result<Option<GcpInvocation>> {
            if !matches!(
                self.proto_payload.method_name.as_str(),
                "google.cloud.aiplatform.v1.PredictionService.GenerateContent"
                    | "google.cloud.aiplatform.v1.PredictionService.StreamGenerateContent"
                    | "google.cloud.aiplatform.v1.PredictionService.Predict"
            ) || self.proto_payload.status.code.is_some_and(|code| code != 0)
            {
                return Ok(None);
            }
            let model_id =
                gcp_publisher_model(&self.proto_payload.resource_name, project_id, location)?;
            Ok(Some(GcpInvocation {
                request_id: self.insert_id,
                model_id,
                principal_email: self.proto_payload.authentication_info.principal_email,
                source_ip: self
                    .proto_payload
                    .request_metadata
                    .caller_ip
                    .filter(|value| value.parse::<IpAddr>().is_ok()),
                destination_host: format!("{location}-aiplatform.googleapis.com"),
                observed_at: self.timestamp,
            }))
        }
    }

    fn gcp_publisher_model(
        value: &str,
        project_id: &str,
        location: &str,
    ) -> Result<Option<String>> {
        let prefix = format!("projects/{project_id}/locations/{location}/publishers/");
        let Some(remainder) = value.strip_prefix(&prefix) else {
            return Ok(None);
        };
        let Some((publisher, model)) = remainder.split_once("/models/") else {
            return Ok(None);
        };
        ensure!(
            !publisher.is_empty()
                && publisher.len() <= 128
                && !model.is_empty()
                && model.len() <= 256
                && !model.contains('/')
                && publisher
                    .bytes()
                    .chain(model.bytes())
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')),
            "Google Vertex invocation resource was unsafe"
        );
        Ok(Some(model.to_owned()))
    }

    async fn bounded_json<T: DeserializeOwned>(
        mut response: Response,
        operation: &str,
    ) -> Result<T> {
        ensure!(response.status().is_success(), "{operation} request failed");
        let is_json = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                let value = value.to_ascii_lowercase();
                value.starts_with("application/json")
                    || value.starts_with("application/x-amz-json-1.1")
            });
        ensure!(is_json, "{operation} returned a non-JSON response");
        if let Some(length) = response.content_length() {
            ensure!(
                length <= u64::try_from(MAX_PAGE_BYTES).unwrap_or(u64::MAX),
                "{operation} response exceeded the page byte cap"
            );
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow!("{operation} response could not be read"))?
        {
            ensure!(
                bytes.len().saturating_add(chunk.len()) <= MAX_PAGE_BYTES,
                "{operation} response exceeded the page byte cap"
            );
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes)
            .with_context(|| format!("{operation} response shape changed"))
    }

    fn serialize_snapshot<T: Serialize>(
        value: &T,
        record_count: usize,
    ) -> Result<NativeCloudSnapshot> {
        let data =
            serde_json::to_vec(value).context("serialize minimal managed-cloud inventory")?;
        ensure!(
            !data.is_empty() && data.len() <= MAX_IMPORT_BYTES,
            "minimal managed-cloud inventory exceeded the import byte cap"
        );
        Ok(NativeCloudSnapshot { data, record_count })
    }

    fn enforce_resource_cap(count: usize, operation: &str) -> Result<()> {
        ensure!(
            count <= MAX_PROVIDER_RESOURCES,
            "{operation} exceeded the resource cap"
        );
        Ok(())
    }

    fn checked_provider_token(value: Option<&str>) -> Result<Option<String>> {
        value
            .map(|value| {
                ensure!(
                    !value.is_empty()
                        && value.len() <= 8_192
                        && !value.chars().any(char::is_control),
                    "provider pagination token was unsafe"
                );
                Ok(value.to_owned())
            })
            .transpose()
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct GcpEndpointsPage {
        #[serde(default)]
        endpoints: Vec<GcpEndpoint>,
        #[serde(default)]
        next_page_token: Option<String>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct GcpEndpoint {
        name: String,
        #[serde(default)]
        deployed_models: Vec<GcpDeployedModel>,
    }

    impl GcpEndpoint {
        fn minimal(mut self, project_id: &str, location: &str) -> Result<Self> {
            self.name = canonical_gcp_resource_name(&self.name, project_id, location, "endpoints")?;
            Ok(self)
        }
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct GcpDeployedModel {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct GcpModelsPage {
        #[serde(default)]
        models: Vec<GcpModel>,
        #[serde(default)]
        next_page_token: Option<String>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct GcpModel {
        name: String,
    }

    impl GcpModel {
        fn minimal(mut self, project_id: &str, location: &str) -> Result<Self> {
            self.name = canonical_gcp_resource_name(&self.name, project_id, location, "models")?;
            Ok(self)
        }
    }

    fn canonical_gcp_resource_name(
        value: &str,
        project_id: &str,
        location: &str,
        collection: &str,
    ) -> Result<String> {
        let segments = value.split('/').collect::<Vec<_>>();
        ensure!(
            segments.len() == 6
                && segments[0] == "projects"
                && (segments[1] == project_id
                    || (!segments[1].is_empty()
                        && segments[1].len() <= 30
                        && segments[1].bytes().all(|byte| byte.is_ascii_digit())))
                && segments[2] == "locations"
                && segments[3] == location
                && segments[4] == collection
                && !segments[5].is_empty()
                && segments[5].len() <= 128
                && segments[5]
                    .bytes()
                    .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') }),
            "Google Vertex resource escaped the configured project or location"
        );
        Ok(format!(
            "projects/{project_id}/locations/{location}/{collection}/{}",
            segments[5]
        ))
    }

    #[derive(Debug, Serialize)]
    struct GcpEnvelope {
        endpoints: GcpEndpoints,
        models: GcpModels,
        invocations: Vec<GcpInvocation>,
    }

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct GcpInvocation {
        request_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        model_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        principal_email: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        source_ip: Option<String>,
        destination_host: String,
        observed_at: DateTime<Utc>,
    }

    #[derive(Debug, Serialize)]
    struct GcpEndpoints {
        endpoints: Vec<GcpEndpoint>,
    }

    #[derive(Debug, Serialize)]
    struct GcpModels {
        models: Vec<GcpModel>,
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn gcp_urls_are_fixed_to_the_configured_vertex_origin() {
            let url = gcp_list_url(
                "tally-project-1",
                "us-central1",
                "endpoints",
                Some("opaque-token"),
            )
            .expect("GCP URL");
            assert_eq!(
                url.host_str(),
                Some("us-central1-aiplatform.googleapis.com")
            );
            assert_eq!(
                url.path(),
                "/v1/projects/tally-project-1/locations/us-central1/endpoints"
            );
            assert!(url.query().is_some_and(|query| query.contains("pageToken")));
            assert!(gcp_list_url("../../metadata", "us-central1", "models", None).is_err());
        }

        #[test]
        fn numeric_project_resource_names_are_canonicalized_to_the_scoped_project_id() {
            assert_eq!(
                canonical_gcp_resource_name(
                    "projects/312922624238/locations/us-central1/endpoints/endpoint-1",
                    "tally-project-1",
                    "us-central1",
                    "endpoints",
                )
                .expect("provider numeric project reference"),
                "projects/tally-project-1/locations/us-central1/endpoints/endpoint-1"
            );
            assert!(
                canonical_gcp_resource_name(
                    "projects/312922624238/locations/europe-west1/endpoints/endpoint-1",
                    "tally-project-1",
                    "us-central1",
                    "endpoints",
                )
                .is_err()
            );
            assert!(
                canonical_gcp_resource_name(
                    "projects/other-project/locations/us-central1/endpoints/endpoint-1",
                    "tally-project-1",
                    "us-central1",
                    "endpoints",
                )
                .is_err()
            );
        }

        #[test]
        fn vertex_audit_projection_retains_attribution_but_not_request_content() {
            let entry: GcpAuditEntry = serde_json::from_str(
                r#"{"insertId":"request-1","timestamp":"2026-09-04T16:12:34Z","protoPayload":{"methodName":"google.cloud.aiplatform.v1.PredictionService.GenerateContent","resourceName":"projects/example-project/locations/us-central1/publishers/google/models/gemini-2.5-flash","authenticationInfo":{"principalEmail":"person@example.com"},"requestMetadata":{"callerIp":"203.0.113.10"},"request":{"contents":[{"text":"PROMPT_CANARY"}]},"status":{}}}"#,
            )
            .expect("audit entry");
            let invocation = entry
                .minimal("example-project", "us-central1")
                .expect("safe projection")
                .expect("successful invocation");
            let serialized = serde_json::to_string(&invocation).expect("serialized projection");
            assert!(serialized.contains("person@example.com"));
            assert!(serialized.contains("203.0.113.10"));
            assert!(serialized.contains("gemini-2.5-flash"));
            assert!(!serialized.contains("PROMPT_CANARY"));
        }

        #[test]
        fn vertex_audit_projection_discards_google_internal_ip_sentinel() {
            let entry: GcpAuditEntry = serde_json::from_str(
                r#"{"insertId":"request-private","timestamp":"2026-09-21T17:43:29Z","protoPayload":{"methodName":"google.cloud.aiplatform.v1.PredictionService.GenerateContent","resourceName":"projects/example-project/locations/us-central1/publishers/google/models/gemini-2.5-flash-lite","authenticationInfo":{"principalEmail":"service-account@example-project.iam.gserviceaccount.com"},"requestMetadata":{"callerIp":"gce-internal-ip"},"status":{}}}"#,
            )
            .expect("audit entry");
            let invocation = entry
                .minimal("example-project", "us-central1")
                .expect("safe projection")
                .expect("successful invocation");

            assert_eq!(invocation.source_ip, None);
            assert_eq!(
                invocation.model_id.as_deref(),
                Some("gemini-2.5-flash-lite")
            );
            assert_eq!(
                invocation.principal_email.as_deref(),
                Some("service-account@example-project.iam.gserviceaccount.com")
            );
        }
    }
}

mod network {
    use super::{
        Context, DateTime, Deserialize, DeserializeOwned, Duration, FLOW_INGESTION_DELAY_MINUTES,
        FLOW_OVERLAP_MINUTES, GCP_COMPUTE_SCOPE, GCP_CURSOR_PREFIX, GCP_LOGGING_SCOPE, HashMap,
        HashSet, Hostname, IpAddr, MAPPING_FUTURE_MINUTES, MAPPING_LOOKBACK_MINUTES,
        MAX_IMPORT_BYTES, MAX_PAGE_BYTES, MAX_PROVIDER_PAGES, MAX_PROVIDER_RECORDS,
        NativeNetworkPull, NativeNetworkSnapshot, Response, Result, SecondsFormat, Serialize,
        TokenProvider, Url, Utc, VendorAdapter, anyhow, bail, ensure, header,
    };
    pub(super) async fn pull_gcp(
        request: &NativeNetworkPull<'_>,
        client: &reqwest::Client,
    ) -> Result<NativeNetworkSnapshot> {
        let project_id = request.account_id;
        let network_id = request.network_id;
        validate_gcp_scope(project_id, network_id)?;
        let scope = match request.adapter {
            VendorAdapter::GcpCloudFlowApi => GCP_LOGGING_SCOPE,
            VendorAdapter::GcpNetworkMappingApi => GCP_COMPUTE_SCOPE,
            _ => bail!("Google Cloud network adapter is unsupported"),
        };
        let token = if let Some(credentials) = request.credentials.gcp.as_ref() {
            gcp_auth::CustomServiceAccount::from_json(&credentials.json)
                .map_err(|_| anyhow!("Google Cloud service-account credential is invalid"))?
                .token(&[scope])
                .await
                .map_err(|_| anyhow!("Google Cloud service-account authentication failed"))?
        } else {
            let provider = gcp_auth::provider().await.map_err(|_| {
                anyhow!("no usable Google Cloud application default credential was found")
            })?;
            provider
                .token(&[scope])
                .await
                .map_err(|_| anyhow!("Google Cloud authentication failed"))?
        };
        match request.adapter {
            VendorAdapter::GcpCloudFlowApi => {
                pull_gcp_flows(
                    client,
                    token.as_str(),
                    project_id,
                    network_id,
                    request.cursor_before,
                    request.initial_lookback_seconds,
                    request.now,
                )
                .await
            }
            VendorAdapter::GcpNetworkMappingApi => {
                pull_gcp_mappings(client, token.as_str(), project_id, network_id, request.now).await
            }
            _ => bail!("Google Cloud network adapter is unsupported"),
        }
    }

    async fn pull_gcp_flows(
        client: &reqwest::Client,
        token: &str,
        project_id: &str,
        network_id: &str,
        cursor_before: &str,
        initial_lookback_seconds: u32,
        now: DateTime<Utc>,
    ) -> Result<NativeNetworkSnapshot> {
        let end = now - Duration::minutes(FLOW_INGESTION_DELAY_MINUTES);
        let start = if cursor_before.is_empty() {
            end - Duration::seconds(i64::from(initial_lookback_seconds))
        } else {
            parse_cursor(cursor_before, GCP_CURSOR_PREFIX, "Google Cloud")?
                - Duration::minutes(FLOW_OVERLAP_MINUTES)
        };
        let cursor_after = format!("{GCP_CURSOR_PREFIX}{}", end.timestamp_millis());
        if start >= end {
            return serialize_snapshot(
                &FlowEnvelope {
                    provider: "gcp",
                    account_id: project_id,
                    region: "global",
                    network_id,
                    ignored_records: 0,
                    records: Vec::new(),
                },
                0,
                cursor_after,
            );
        }

        let filter = gcp_flow_filter(project_id, network_id, start, end)?;
        let mut records = Vec::new();
        let mut page_token = None;
        let mut seen_tokens = HashSet::new();
        let mut exhausted = false;
        for _ in 0..MAX_PROVIDER_PAGES {
            let request = LoggingListRequest {
                resource_names: [format!("projects/{project_id}")],
                filter: &filter,
                order_by: "timestamp asc",
                page_size: 1_000,
                page_token: page_token.as_deref(),
            };
            let response = client
                .post(logging_entries_url()?)
                .header(header::ACCEPT, "application/json")
                .bearer_auth(token)
                .json(&request)
                .send()
                .await
                .map_err(|_| anyhow!("Google Cloud flow-log request failed"))?;
            let page: LoggingListResponse = bounded_json(response, "Google Cloud flow-log").await?;
            for entry in page.entries {
                records.push(entry.minimal(network_id)?);
                enforce_record_cap(records.len(), "Google Cloud flow-log")?;
            }
            page_token = checked_page_token(page.next_page_token.as_deref(), &mut seen_tokens)?;
            if page_token.is_none() {
                exhausted = true;
                break;
            }
        }
        ensure!(exhausted, "Google Cloud flow-log exceeded the page cap");
        let count = records.len();
        serialize_snapshot(
            &FlowEnvelope {
                provider: "gcp",
                account_id: project_id,
                region: "global",
                network_id,
                ignored_records: 0,
                records,
            },
            count,
            cursor_after,
        )
    }

    async fn pull_gcp_mappings(
        client: &reqwest::Client,
        token: &str,
        project_id: &str,
        network_id: &str,
        now: DateTime<Utc>,
    ) -> Result<NativeNetworkSnapshot> {
        let valid_from = now - Duration::minutes(MAPPING_LOOKBACK_MINUTES);
        let valid_until = now + Duration::minutes(MAPPING_FUTURE_MINUTES);
        let mut records = Vec::new();
        let mut page_token = None;
        let mut seen_tokens = HashSet::new();
        let mut exhausted = false;
        for _ in 0..MAX_PROVIDER_PAGES {
            let url = compute_instances_url(project_id, page_token.as_deref())?;
            let response = client
                .get(url)
                .header(header::ACCEPT, "application/json")
                .bearer_auth(token)
                .send()
                .await
                .map_err(|_| anyhow!("Google Cloud network mapping request failed"))?;
            let page: ComputeAggregatedResponse =
                bounded_json(response, "Google Cloud network mapping").await?;
            ensure!(
                page.unreachables.is_empty(),
                "Google Cloud network mapping was incomplete"
            );
            for scope in page.items.into_values() {
                for instance in scope.instances {
                    records.extend(instance.minimal_mappings(
                        project_id,
                        network_id,
                        valid_from,
                        valid_until,
                    )?);
                    enforce_record_cap(records.len(), "Google Cloud network mapping")?;
                }
            }
            page_token = checked_page_token(page.next_page_token.as_deref(), &mut seen_tokens)?;
            if page_token.is_none() {
                exhausted = true;
                break;
            }
        }
        ensure!(
            exhausted,
            "Google Cloud network mapping exceeded the page cap"
        );
        let count = records.len();
        serialize_snapshot(
            &MappingEnvelope {
                provider: "gcp",
                account_id: project_id,
                region: "global",
                network_id,
                records,
            },
            count,
            format!("{GCP_CURSOR_PREFIX}{}", now.timestamp_millis()),
        )
    }

    fn gcp_flow_filter(
        project_id: &str,
        network_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<String> {
        validate_gcp_scope(project_id, network_id)?;
        ensure!(start < end, "Google Cloud flow-log window is invalid");
        Ok(format!(
            "logName=\"projects/{project_id}/logs/compute.googleapis.com%2Fvpc_flows\" AND timestamp>=\"{}\" AND timestamp<\"{}\" AND (jsonPayload.src_vpc.vpc_name=\"{network_id}\" OR jsonPayload.dest_vpc.vpc_name=\"{network_id}\")",
            start.to_rfc3339_opts(SecondsFormat::Millis, true),
            end.to_rfc3339_opts(SecondsFormat::Millis, true)
        ))
    }

    fn logging_entries_url() -> Result<Url> {
        Url::parse("https://logging.googleapis.com/v2/entries:list")
            .context("build Google Logging URL")
    }

    fn compute_instances_url(project_id: &str, page_token: Option<&str>) -> Result<Url> {
        validate_project_id(project_id)?;
        let mut url = Url::parse("https://compute.googleapis.com/")?;
        url.set_path(&format!(
            "/compute/v1/projects/{project_id}/aggregated/instances"
        ));
        let mut query = url.query_pairs_mut();
        query
            .append_pair("maxResults", "500")
            .append_pair("returnPartialSuccess", "true");
        if let Some(page_token) = page_token {
            ensure!(
                safe_page_token(page_token),
                "provider pagination token was unsafe"
            );
            query.append_pair("pageToken", page_token);
        }
        drop(query);
        Ok(url)
    }

    fn validate_gcp_scope(project_id: &str, network_id: &str) -> Result<()> {
        validate_project_id(project_id)?;
        ensure!(
            (1..=63).contains(&network_id.len())
                && network_id
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_lowercase())
                && network_id
                    .bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && network_id
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
            "Google Cloud network ID is invalid"
        );
        Ok(())
    }

    fn validate_project_id(project_id: &str) -> Result<()> {
        ensure!(
            (6..=30).contains(&project_id.len())
                && project_id
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_lowercase())
                && project_id
                    .bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && project_id
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
            "Google Cloud project ID is invalid"
        );
        Ok(())
    }

    fn parse_cursor(value: &str, prefix: &str, provider: &str) -> Result<DateTime<Utc>> {
        let millis = value
            .strip_prefix(prefix)
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or_else(|| anyhow!("{provider} network cursor is invalid"))?;
        DateTime::from_timestamp_millis(millis)
            .ok_or_else(|| anyhow!("{provider} network cursor is invalid"))
    }

    async fn bounded_json<T: DeserializeOwned>(
        mut response: Response,
        operation: &str,
    ) -> Result<T> {
        ensure!(response.status().is_success(), "{operation} request failed");
        let is_json = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.to_ascii_lowercase().starts_with("application/json"));
        ensure!(is_json, "{operation} returned a non-JSON response");
        if let Some(length) = response.content_length() {
            ensure!(
                length <= u64::try_from(MAX_PAGE_BYTES).unwrap_or(u64::MAX),
                "{operation} response exceeded the page byte cap"
            );
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow!("{operation} response could not be read"))?
        {
            ensure!(
                bytes.len().saturating_add(chunk.len()) <= MAX_PAGE_BYTES,
                "{operation} response exceeded the page byte cap"
            );
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes)
            .with_context(|| format!("{operation} response shape changed"))
    }

    fn checked_page_token(
        value: Option<&str>,
        seen: &mut HashSet<String>,
    ) -> Result<Option<String>> {
        value
            .map(|value| {
                ensure!(
                    safe_page_token(value),
                    "provider pagination token was unsafe"
                );
                ensure!(
                    seen.insert(value.to_owned()),
                    "provider pagination token repeated"
                );
                Ok(value.to_owned())
            })
            .transpose()
    }

    fn safe_page_token(value: &str) -> bool {
        !value.is_empty() && value.len() <= 8_192 && !value.chars().any(char::is_control)
    }

    fn enforce_record_cap(count: usize, operation: &str) -> Result<()> {
        ensure!(
            count <= MAX_PROVIDER_RECORDS,
            "{operation} exceeded the record cap"
        );
        Ok(())
    }

    fn serialize_snapshot<T: Serialize>(
        value: &T,
        record_count: usize,
        cursor_after: String,
    ) -> Result<NativeNetworkSnapshot> {
        let data =
            serde_json::to_vec(value).context("serialize minimal cloud-network projection")?;
        ensure!(
            !data.is_empty() && data.len() <= MAX_IMPORT_BYTES,
            "minimal cloud-network projection exceeded the import byte cap"
        );
        Ok(NativeNetworkSnapshot {
            data,
            record_count,
            cursor_after,
        })
    }

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct LoggingListRequest<'a> {
        resource_names: [String; 1],
        filter: &'a str,
        order_by: &'static str,
        page_size: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        page_token: Option<&'a str>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct LoggingListResponse {
        #[serde(default)]
        entries: Vec<LoggingEntry>,
        #[serde(default)]
        next_page_token: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct LoggingEntry {
        json_payload: GcpFlowPayload,
    }

    impl LoggingEntry {
        fn minimal(self, network_id: &str) -> Result<FlowRecord> {
            ensure!(
                self.json_payload
                    .src_vpc
                    .as_ref()
                    .is_some_and(|vpc| vpc.vpc_name == network_id)
                    || self
                        .json_payload
                        .dest_vpc
                        .as_ref()
                        .is_some_and(|vpc| vpc.vpc_name == network_id),
                "Google Cloud flow-log escaped the configured network"
            );
            let protocol = match self.json_payload.connection.protocol {
                6 => "tcp",
                17 => "udp",
                1 | 58 => "icmp",
                _ => "other",
            };
            let source_port = bounded_port(self.json_payload.connection.src_port)?;
            let destination_port = bounded_port(self.json_payload.connection.dest_port)?;
            let (packets, bytes, decision) =
                match self.json_payload.disposition.as_deref() {
                    None => (
                        positive_counter(self.json_payload.packets_sent.ok_or_else(|| {
                            anyhow!("Google Cloud flow packet counter is missing")
                        })?)?,
                        byte_counter(self.json_payload.bytes_sent.ok_or_else(|| {
                            anyhow!("Google Cloud flow byte counter is missing")
                        })?)?,
                        "accepted",
                    ),
                    Some("DROPPED") => (
                        positive_counter(self.json_payload.packets_dropped.ok_or_else(|| {
                            anyhow!("Google Cloud dropped-flow packet counter is missing")
                        })?)?,
                        None, // Dropped bytes do not measure data sent to the destination.
                        "rejected",
                    ),
                    Some(_) => bail!("Google Cloud flow disposition was unsupported"),
                };
            let direction = match self.json_payload.reporter.as_str() {
                "SRC" | "SRC_GATEWAY" => "egress",
                "DEST" | "DEST_GATEWAY" => "ingress",
                _ => "unknown",
            };
            let source_hostname = self
                .json_payload
                .src_instance
                .as_ref()
                .and_then(|instance| normalized_hostname(&instance.vm_name))
                .or_else(|| {
                    self.json_payload
                        .src_google_service
                        .as_ref()
                        .and_then(|service| service.service_name.as_deref())
                        .and_then(normalized_hostname)
                });
            let destination_hostname = self
                .json_payload
                .dest_instance
                .as_ref()
                .and_then(|instance| normalized_hostname(&instance.vm_name))
                .or_else(|| {
                    self.json_payload
                        .dest_google_service
                        .as_ref()
                        .and_then(|service| service.service_name.as_deref())
                        .and_then(normalized_hostname)
                });
            Ok(FlowRecord {
                window_start: self.json_payload.start_time,
                window_end: self.json_payload.end_time,
                source_ip: self.json_payload.connection.src_ip,
                destination_ip: self.json_payload.connection.dest_ip,
                source_hostname,
                destination_hostname,
                source_port,
                destination_port,
                protocol,
                packets,
                bytes,
                direction,
                decision,
            })
        }
    }

    #[derive(Debug, Deserialize)]
    struct GcpFlowPayload {
        connection: GcpConnection,
        reporter: String,
        #[serde(default)]
        packets_sent: Option<serde_json::Value>,
        #[serde(default)]
        bytes_sent: Option<serde_json::Value>,
        #[serde(default)]
        packets_dropped: Option<serde_json::Value>,
        #[serde(default)]
        disposition: Option<String>,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        #[serde(default)]
        src_vpc: Option<GcpVpc>,
        #[serde(default)]
        dest_vpc: Option<GcpVpc>,
        #[serde(default)]
        src_instance: Option<GcpInstanceRef>,
        #[serde(default)]
        dest_instance: Option<GcpInstanceRef>,
        #[serde(default)]
        src_google_service: Option<GcpGoogleService>,
        #[serde(default)]
        dest_google_service: Option<GcpGoogleService>,
    }

    #[derive(Debug, Deserialize)]
    struct GcpInstanceRef {
        vm_name: String,
    }

    #[derive(Debug, Deserialize)]
    struct GcpGoogleService {
        #[serde(default)]
        service_name: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct GcpConnection {
        src_ip: String,
        dest_ip: String,
        #[serde(default)]
        src_port: Option<i64>,
        #[serde(default)]
        dest_port: Option<i64>,
        protocol: i64,
    }

    #[derive(Debug, Deserialize)]
    struct GcpVpc {
        vpc_name: String,
    }

    fn bounded_port(value: Option<i64>) -> Result<Option<u16>> {
        value
            .map(|value| {
                u16::try_from(value).map_err(|_| anyhow!("Google Cloud flow port is invalid"))
            })
            .transpose()
    }

    fn positive_counter(value: serde_json::Value) -> Result<Option<u64>> {
        let value = match value {
            serde_json::Value::Number(number) => number.as_u64(),
            serde_json::Value::String(value) => value.parse::<u64>().ok(),
            _ => None,
        }
        .ok_or_else(|| anyhow!("Google Cloud flow counter is invalid"))?;
        Ok((value > 0).then_some(value))
    }

    fn byte_counter(value: serde_json::Value) -> Result<Option<u64>> {
        let count = match value {
            serde_json::Value::Number(number) => number.as_u64(),
            serde_json::Value::String(value) => value.parse::<u64>().ok(),
            _ => None,
        }
        .ok_or_else(|| anyhow!("Google Cloud flow byte counter is invalid"))?;
        Ok(Some(count))
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ComputeAggregatedResponse {
        #[serde(default)]
        items: HashMap<String, ComputeScope>,
        #[serde(default)]
        next_page_token: Option<String>,
        #[serde(default)]
        unreachables: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    struct ComputeScope {
        #[serde(default)]
        instances: Vec<ComputeInstance>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ComputeInstance {
        name: String,
        #[serde(default)]
        hostname: Option<String>,
        self_link: String,
        #[serde(default)]
        network_interfaces: Vec<ComputeNetworkInterface>,
    }

    impl ComputeInstance {
        fn minimal_mappings(
            self,
            project_id: &str,
            network_id: &str,
            valid_from: DateTime<Utc>,
            valid_until: DateTime<Utc>,
        ) -> Result<Vec<MappingRecord>> {
            validate_instance_self_link(&self.self_link, project_id)?;
            let hostname = self
                .hostname
                .as_deref()
                .and_then(normalized_hostname)
                .or_else(|| normalized_hostname(&self.name));
            let expected_network = format!("/projects/{project_id}/global/networks/{network_id}");
            let mut records = Vec::new();
            for interface in self.network_interfaces {
                if !interface.network.ends_with(&expected_network) {
                    continue;
                }
                let interface_id = format!("{}#{}", self.self_link, interface.name);
                for private_ip in [interface.network_ip, interface.ipv6_address]
                    .into_iter()
                    .flatten()
                {
                    let Ok(address) = private_ip.parse::<IpAddr>() else {
                        bail!("Google Cloud network mapping address is invalid");
                    };
                    if !is_private(address) {
                        continue;
                    }
                    records.push(MappingRecord {
                        valid_from,
                        valid_until,
                        private_ip,
                        interface_id: interface_id.clone(),
                        resource_id: self.self_link.clone(),
                        resource_kind: "workload",
                        hostname: hostname.clone(),
                    });
                }
            }
            Ok(records)
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ComputeNetworkInterface {
        name: String,
        network: String,
        #[serde(default, rename = "networkIP")]
        network_ip: Option<String>,
        #[serde(default)]
        ipv6_address: Option<String>,
    }

    fn validate_instance_self_link(value: &str, project_id: &str) -> Result<()> {
        ensure!(
            value.len() <= 2_048 && !value.chars().any(char::is_control),
            "Google Cloud instance resource ID is invalid"
        );
        let url = Url::parse(value).context("Google Cloud instance resource ID is invalid")?;
        let prefix = format!("/compute/v1/projects/{project_id}/zones/");
        ensure!(
            url.scheme() == "https"
                && matches!(
                    url.host_str(),
                    Some("www.googleapis.com" | "compute.googleapis.com")
                )
                && url.port().is_none()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path().starts_with(&prefix)
                && url.path().contains("/instances/"),
            "Google Cloud instance resource ID is outside the configured project"
        );
        Ok(())
    }

    fn is_private(address: IpAddr) -> bool {
        match address {
            IpAddr::V4(address) => address.is_private(),
            IpAddr::V6(address) => (address.segments()[0] & 0xfe00) == 0xfc00,
        }
    }

    #[derive(Debug, Serialize)]
    struct FlowEnvelope<'a> {
        provider: &'a str,
        account_id: &'a str,
        region: &'a str,
        network_id: &'a str,
        ignored_records: u64,
        records: Vec<FlowRecord>,
    }

    #[derive(Debug, Serialize)]
    struct FlowRecord {
        window_start: DateTime<Utc>,
        window_end: DateTime<Utc>,
        source_ip: String,
        destination_ip: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        source_hostname: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        destination_hostname: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        source_port: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        destination_port: Option<u16>,
        protocol: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        packets: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        bytes: Option<u64>,
        direction: &'static str,
        decision: &'static str,
    }

    #[derive(Debug, Serialize)]
    struct MappingEnvelope<'a> {
        provider: &'a str,
        account_id: &'a str,
        region: &'a str,
        network_id: &'a str,
        records: Vec<MappingRecord>,
    }

    #[derive(Debug, Serialize)]
    struct MappingRecord {
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
        private_ip: String,
        interface_id: String,
        resource_id: String,
        resource_kind: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
    }

    fn normalized_hostname(value: &str) -> Option<String> {
        Hostname::parse(value)
            .ok()
            .map(|hostname| hostname.as_str().to_owned())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn google_origins_and_filters_are_fixed() {
            let start = "2026-08-13T10:00:00Z".parse().expect("start");
            let end = "2026-08-13T10:05:00Z".parse().expect("end");
            let filter =
                gcp_flow_filter("tally-project-1", "tally-vpc", start, end).expect("filter");
            assert!(filter.contains("compute.googleapis.com%2Fvpc_flows"));
            assert!(filter.contains("vpc_name=\"tally-vpc\""));
            assert!(gcp_flow_filter("tally-project-1", "x\" OR true", start, end).is_err());

            let logging = logging_entries_url().expect("logging URL");
            assert_eq!(logging.host_str(), Some("logging.googleapis.com"));
            let compute = compute_instances_url("tally-project-1", Some("opaque-token"))
                .expect("compute URL");
            assert_eq!(compute.host_str(), Some("compute.googleapis.com"));
            assert!(compute.query().is_some_and(|query| {
                query.contains("returnPartialSuccess=true") && query.contains("pageToken")
            }));
        }

        #[test]
        fn log_projection_keeps_only_the_strict_flow_contract() {
            let entry: LoggingEntry = serde_json::from_str(
            r#"{"jsonPayload":{"connection":{"src_ip":"10.0.0.4","dest_ip":"10.0.0.8","src_port":50000,"dest_port":443,"protocol":6},"reporter":"SRC","packets_sent":"2","bytes_sent":"128","start_time":"2026-08-13T10:00:00Z","end_time":"2026-08-13T10:00:30Z","src_vpc":{"vpc_name":"tally-vpc"},"src_instance":{"vm_name":"client-vm-1"},"dest_instance":{"vm_name":"model-vm-1"},"dest_google_service":{"service_name":"private.example"},"metadata":{"prompt":"CONTENT_CANARY"}}}"#,
        )
        .expect("log entry");
            let record = entry.minimal("tally-vpc").expect("minimal flow");
            let serialized = serde_json::to_string(&record).expect("serialized flow");
            assert!(!serialized.contains("CONTENT_CANARY"));
            assert!(!serialized.contains("private.example"));
            assert!(serialized.contains("client-vm-1"));
            assert!(serialized.contains("model-vm-1"));
            assert!(serialized.contains("10.0.0.4"));
            assert!(serialized.contains("\"direction\":\"egress\""));
        }

        #[test]
        fn google_service_name_is_retained_when_no_vm_hostname_exists() {
            let entry: LoggingEntry = serde_json::from_str(
                r#"{"jsonPayload":{"connection":{"src_ip":"10.0.0.4","dest_ip":"172.217.0.1","src_port":50000,"dest_port":443,"protocol":6},"reporter":"SRC","packets_sent":"2","bytes_sent":"128","start_time":"2026-08-13T10:00:00Z","end_time":"2026-08-13T10:00:30Z","src_vpc":{"vpc_name":"tally-vpc"},"src_instance":{"vm_name":"client-vm-1"},"dest_google_service":{"service_name":"aiplatform.googleapis.com"}}}"#,
            )
            .expect("log entry");
            let record = entry.minimal("tally-vpc").expect("minimal flow");
            assert_eq!(
                record.destination_hostname.as_deref(),
                Some("aiplatform.googleapis.com")
            );
        }

        #[test]
        fn dropped_flow_projection_uses_drop_counters_and_rejected_decision() {
            let entry: LoggingEntry = serde_json::from_str(
                r#"{"jsonPayload":{"connection":{"src_ip":"203.0.113.10","dest_ip":"10.0.0.8","src_port":47326,"dest_port":22,"protocol":6},"reporter":"DEST","packets_dropped":"1","bytes_dropped":"128","start_time":"2026-08-13T10:00:00Z","end_time":"2026-08-13T10:00:00Z","disposition":"DROPPED","drop_reason":"FIREWALL_DENY","dest_vpc":{"vpc_name":"tally-vpc"},"dest_instance":{"vm_name":"model-vm-1"}}}"#,
            )
            .expect("dropped log entry");
            let record = entry.minimal("tally-vpc").expect("minimal dropped flow");
            assert_eq!(record.packets, Some(1));
            assert_eq!(record.bytes, None);
            assert_eq!(record.decision, "rejected");
            let serialized = serde_json::to_string(&record).expect("serialized flow");
            assert!(!serialized.contains("FIREWALL_DENY"));
            assert!(serialized.contains("model-vm-1"));
        }
    }
}
