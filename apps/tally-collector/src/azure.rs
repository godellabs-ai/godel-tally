use std::{
    collections::{HashMap, HashSet},
    env,
    net::IpAddr,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use azure_core::credentials::{Secret, TokenCredential};
use azure_identity::{
    ClientSecretCredential, DeveloperToolsCredential, ManagedIdentityCredential,
    WorkloadIdentityCredential,
};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use reqwest::{Response, Url, header};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tally_connectors::{AzureServicePrincipalCredentials, MAX_IMPORT_BYTES};
use tally_core::Hostname;

use crate::{
    VendorAdapter,
    pull_support::{NativeCloudSnapshot, NativeNetworkPull, NativeNetworkSnapshot},
};

const AZURE_API_VERSION: &str = "2025-06-01";
const AZURE_SCOPE: &str = "https://management.azure.com/.default";
const AZURE_MANAGEMENT_SCOPE: &str = "https://management.azure.com/.default";
const AZURE_LOGS_SCOPE: &str = "https://api.loganalytics.io/.default";
const AZURE_NETWORK_API_VERSION: &str = "2025-05-01";
const AZURE_COMPUTE_API_VERSION: &str = "2026-03-01";
const AZURE_WORKSPACE_API_VERSION: &str = "2025-07-01";
const MAX_PROVIDER_PAGES: usize = 100;
const MAX_PROVIDER_RESOURCES: usize = 10_000;
const MAX_PROVIDER_RECORDS: usize = 10_000;
const MAX_PAGE_BYTES: usize = 16 * 1_024 * 1_024;
// Traffic Analytics is a second processing stage after VNet flow-log blobs. Keep the query
// watermark behind that stage so an empty poll cannot advance past records that have not reached
// NTANetAnalytics yet. The 10-minute analytics interval took more than 20 minutes in live testing.
const FLOW_INGESTION_DELAY_MINUTES: i64 = 30;
const FLOW_OVERLAP_MINUTES: i64 = 5;
const MAPPING_LOOKBACK_MINUTES: i64 = 10;
const MAPPING_FUTURE_MINUTES: i64 = 5;
const AZURE_CURSOR_PREFIX: &str = "azure-network-v1:";

pub(crate) async fn pull_inventory(
    client: &reqwest::Client,
    subscription_id: &str,
    account_resource_id: &str,
    workspace_resource: Option<&str>,
    static_credentials: Option<&AzureServicePrincipalCredentials>,
) -> Result<NativeCloudSnapshot> {
    inventory::pull_azure(
        client,
        subscription_id,
        account_resource_id,
        workspace_resource,
        static_credentials,
    )
    .await
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
        request.log_group.is_none(),
        "Azure does not accept an AWS log group"
    );
    network::pull_azure(request, client).await
}

mod inventory {
    use super::{
        AZURE_API_VERSION, AZURE_LOGS_SCOPE, AZURE_SCOPE, AZURE_WORKSPACE_API_VERSION,
        AzureServicePrincipalCredentials, ClientSecretCredential, Context, DateTime, Deserialize,
        DeserializeOwned, DeveloperToolsCredential, Duration, MAX_IMPORT_BYTES, MAX_PAGE_BYTES,
        MAX_PROVIDER_PAGES, MAX_PROVIDER_RECORDS, MAX_PROVIDER_RESOURCES,
        ManagedIdentityCredential, NativeCloudSnapshot, Response, Result, SecondsFormat, Secret,
        Serialize, TokenCredential, Url, Utc, WorkloadIdentityCredential, anyhow, ensure, env,
        header,
    };
    pub(super) async fn pull_azure(
        client: &reqwest::Client,
        subscription_id: &str,
        account_resource_id: &str,
        workspace_resource: Option<&str>,
        static_credentials: Option<&AzureServicePrincipalCredentials>,
    ) -> Result<NativeCloudSnapshot> {
        let mut next = azure_deployments_url(subscription_id, account_resource_id)?;
        let expected_path = next.path().to_ascii_lowercase();
        let credential =
            azure_access_token_with_credentials(AZURE_SCOPE, static_credentials).await?;
        let mut deployments = Vec::new();
        let mut exhausted = false;
        for _ in 0..MAX_PROVIDER_PAGES {
            let response = client
                .get(next.clone())
                .header(header::ACCEPT, "application/json")
                .bearer_auth(credential.token.secret())
                .send()
                .await
                .map_err(|_| anyhow!("Azure managed AI inventory request failed"))?;
            let page: AzurePage = bounded_json(response, "Azure managed AI inventory").await?;
            deployments.extend(page.value.into_iter().map(AzureDeployment::minimal));
            enforce_resource_cap(deployments.len(), "Azure managed AI inventory")?;
            let Some(next_link) = page.next_link else {
                exhausted = true;
                break;
            };
            next = validate_azure_next_link(&next_link, &expected_path)?;
        }
        ensure!(
            exhausted,
            "Azure managed AI inventory exceeded the page cap"
        );
        let invocations = match workspace_resource {
            Some(workspace) => {
                azure_openai_invocations(
                    client,
                    subscription_id,
                    account_resource_id,
                    workspace,
                    static_credentials,
                )
                .await?
            }
            None => Vec::new(),
        };
        let record_count = deployments.len().saturating_add(invocations.len());
        serialize_snapshot(
            &AzureEnvelope {
                value: deployments,
                invocations,
            },
            record_count,
        )
    }

    pub(super) async fn azure_access_token_with_credentials(
        scope: &str,
        static_credentials: Option<&AzureServicePrincipalCredentials>,
    ) -> Result<azure_core::credentials::AccessToken> {
        ensure!(
            matches!(
                scope,
                "https://management.azure.com/.default" | "https://api.loganalytics.io/.default"
            ),
            "Azure token scope is unsupported"
        );
        if let Some(credentials) = static_credentials {
            let credential = ClientSecretCredential::new(
                &credentials.tenant_id,
                credentials.client_id.clone(),
                Secret::new(credentials.client_secret.clone()),
                None,
            )
            .map_err(|_| anyhow!("Azure service-principal credential is invalid"))?;
            return credential
                .get_token(&[scope], None)
                .await
                .map_err(|_| anyhow!("Azure service-principal authentication failed"));
        }
        if let (Ok(tenant_id), Ok(client_id), Ok(client_secret)) = (
            env::var("AZURE_TENANT_ID"),
            env::var("AZURE_CLIENT_ID"),
            env::var("AZURE_CLIENT_SECRET"),
        ) {
            let credential = ClientSecretCredential::new(
                &tenant_id,
                client_id,
                Secret::new(client_secret),
                None,
            )
            .map_err(|_| anyhow!("Azure service-principal credential is invalid"))?;
            return credential
                .get_token(&[scope], None)
                .await
                .map_err(|_| anyhow!("Azure service-principal authentication failed"));
        }
        if env::var_os("AZURE_FEDERATED_TOKEN_FILE").is_some() {
            let credential = WorkloadIdentityCredential::new(None)
                .map_err(|_| anyhow!("Azure workload identity is invalid"))?;
            return credential
                .get_token(&[scope], None)
                .await
                .map_err(|_| anyhow!("Azure workload-identity authentication failed"));
        }
        if let Ok(credential) = DeveloperToolsCredential::new(None)
            && let Ok(token) = credential.get_token(&[scope], None).await
        {
            return Ok(token);
        }
        let credential = ManagedIdentityCredential::new(None)
            .map_err(|_| anyhow!("Azure managed identity is invalid"))?;
        credential
            .get_token(&[scope], None)
            .await
            .map_err(|_| anyhow!("no usable Azure token credential was found"))
    }

    fn azure_deployments_url(subscription_id: &str, account_resource_id: &str) -> Result<Url> {
        ensure!(
            !subscription_id.is_empty() && subscription_id.len() <= 128,
            "Azure subscription ID is invalid"
        );
        ensure!(
            account_resource_id.starts_with('/')
                && account_resource_id.len() <= 2_048
                && !account_resource_id.contains(['?', '#'])
                && !account_resource_id.chars().any(char::is_control),
            "Azure account resource ID is invalid"
        );
        let segments = account_resource_id
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>();
        ensure!(
            segments.len() == 8
                && segments[0].eq_ignore_ascii_case("subscriptions")
                && segments[1].eq_ignore_ascii_case(subscription_id)
                && segments[2].eq_ignore_ascii_case("resourceGroups")
                && segments[4].eq_ignore_ascii_case("providers")
                && segments[5].eq_ignore_ascii_case("Microsoft.CognitiveServices")
                && segments[6].eq_ignore_ascii_case("accounts"),
            "Azure account resource ID is outside the configured subscription"
        );
        let mut url = Url::parse("https://management.azure.com/")?;
        url.set_path(&format!(
            "{}/deployments",
            account_resource_id.trim_end_matches('/')
        ));
        url.query_pairs_mut()
            .append_pair("api-version", AZURE_API_VERSION);
        Ok(url)
    }

    fn validate_azure_next_link(value: &str, expected_path: &str) -> Result<Url> {
        ensure!(
            value.len() <= 16_384 && !value.chars().any(char::is_control),
            "Azure pagination link was unsafe"
        );
        let url = Url::parse(value).context("Azure pagination link was invalid")?;
        ensure!(
            url.scheme() == "https"
                && url.host_str() == Some("management.azure.com")
                && url.port().is_none()
                && url.username().is_empty()
                && url.password().is_none()
                && url.path().to_ascii_lowercase() == expected_path,
            "Azure pagination link left the configured account"
        );
        let pairs = url.query_pairs().collect::<Vec<_>>();
        ensure!(
            !pairs.is_empty()
                && pairs.len() <= 3
                && pairs.iter().all(|(key, value)| {
                    (key == "api-version" && value == AZURE_API_VERSION)
                        || ((key == "$skiptoken" || key == "$top")
                            && !value.is_empty()
                            && value.len() <= 8_192
                            && !value.chars().any(char::is_control))
                }),
            "Azure pagination query was unsafe"
        );
        Ok(url)
    }

    async fn azure_openai_invocations(
        client: &reqwest::Client,
        subscription_id: &str,
        account_resource_id: &str,
        workspace_resource: &str,
        static_credentials: Option<&AzureServicePrincipalCredentials>,
    ) -> Result<Vec<AzureInvocation>> {
        validate_azure_workspace_resource(workspace_resource, subscription_id)?;
        let management_token =
            azure_access_token_with_credentials(AZURE_SCOPE, static_credentials).await?;
        let workspace_response = client
            .get(azure_arm_url(
                workspace_resource,
                AZURE_WORKSPACE_API_VERSION,
            )?)
            .header(header::ACCEPT, "application/json")
            .bearer_auth(management_token.token.secret())
            .send()
            .await
            .map_err(|_| anyhow!("Azure Log Analytics workspace verification request failed"))?;
        let workspace: AzureInventoryWorkspace = bounded_json(
            workspace_response,
            "Azure Log Analytics workspace verification",
        )
        .await?;
        ensure!(
            workspace.id.eq_ignore_ascii_case(workspace_resource)
                && workspace
                    .properties
                    .provisioning_state
                    .eq_ignore_ascii_case("Succeeded"),
            "Azure Log Analytics workspace did not match the configured scope"
        );
        let workspace_id = workspace.properties.customer_id;
        uuid::Uuid::parse_str(&workspace_id)
            .map_err(|_| anyhow!("Azure Log Analytics workspace ID was invalid"))?;
        let account_name = account_resource_id
            .rsplit('/')
            .next()
            .filter(|name| safe_azure_path_segment(name))
            .ok_or_else(|| anyhow!("Azure managed AI account name was invalid"))?;
        let window_end = Utc::now();
        let window_start = window_end - Duration::hours(1);
        let query = azure_openai_usage_query(account_resource_id, window_start, window_end)?;
        let logs_token =
            azure_access_token_with_credentials(AZURE_LOGS_SCOPE, static_credentials).await?;
        let response = client
            .post(azure_logs_url(&workspace_id)?)
            .header(header::ACCEPT, "application/json")
            .bearer_auth(logs_token.token.secret())
            .json(&AzureInventoryLogsRequest {
                query: &query,
                timespan: format!(
                    "{}/{}",
                    window_start.to_rfc3339_opts(SecondsFormat::Millis, true),
                    window_end.to_rfc3339_opts(SecondsFormat::Millis, true)
                ),
            })
            .send()
            .await
            .map_err(|_| anyhow!("Azure OpenAI request-log query failed"))?;
        let result: AzureInventoryLogsResponse =
            bounded_json(response, "Azure OpenAI request logs").await?;
        ensure!(
            result.error.is_none() && result.tables.len() == 1,
            "Azure OpenAI request-log query was incomplete"
        );
        result
            .tables
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Azure OpenAI request-log query returned no table"))?
            .minimal_invocations(account_name)
    }

    fn azure_openai_usage_query(
        account_resource_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<String> {
        ensure!(start < end, "Azure OpenAI request-log window is invalid");
        ensure!(
            safe_azure_resource_id(account_resource_id),
            "Azure managed AI account resource ID was unsafe"
        );
        Ok(format!(
            "AzureDiagnostics\n| where TimeGenerated >= datetime({}) and TimeGenerated < datetime({})\n| where _ResourceId =~ \"{}\"\n| where Category == \"AzureOpenAIRequestUsage\" or (Category == \"RequestResponse\" and tostring(ResultSignature) startswith \"2\")\n| extend Props = parse_json(tostring(column_ifexists(\"properties_s\", \"{{}}\")))\n| extend RequestId = tostring(CorrelationId), Model = coalesce(tostring(Props.modelName), tostring(Props.modelDeploymentName), tostring(column_ifexists(\"modelName_s\", \"\")), tostring(column_ifexists(\"deploymentId_s\", \"\"))), Principal = coalesce(tostring(column_ifexists(\"identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn_s\", \"\")), tostring(column_ifexists(\"identity_claim_upn_s\", \"\")), tostring(column_ifexists(\"identity_claim_email_s\", \"\")), tostring(column_ifexists(\"Caller_s\", \"\")), tostring(column_ifexists(\"identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g\", \"\")), tostring(Props.callerObjectId), tostring(Props.objectId)), CallerIp = coalesce(tostring(column_ifexists(\"CallerIPAddress\", \"\")), tostring(column_ifexists(\"clientIp_s\", \"\")), tostring(column_ifexists(\"identity_claim_ipaddr_s\", \"\")), tostring(Props.clientIp))\n| where isnotempty(RequestId) and isnotempty(Model)\n| summarize TimeGenerated=min(TimeGenerated), Model=take_anyif(Model, isnotempty(Model)), Principal=take_anyif(Principal, isnotempty(Principal)), CallerIp=take_anyif(CallerIp, isnotempty(CallerIp)) by RequestId\n| project TimeGenerated, RequestId, Model, Principal, CallerIp\n| order by TimeGenerated asc\n| take 10001",
            start.to_rfc3339_opts(SecondsFormat::Millis, true),
            end.to_rfc3339_opts(SecondsFormat::Millis, true),
            account_resource_id
        ))
    }

    fn azure_arm_url(resource_id: &str, api_version: &str) -> Result<Url> {
        ensure!(
            safe_azure_resource_id(resource_id),
            "Azure resource ID was unsafe"
        );
        let mut url = Url::parse("https://management.azure.com/")?;
        url.set_path(resource_id);
        url.query_pairs_mut()
            .append_pair("api-version", api_version);
        Ok(url)
    }

    fn azure_logs_url(workspace_id: &str) -> Result<Url> {
        uuid::Uuid::parse_str(workspace_id)
            .map_err(|_| anyhow!("Azure Log Analytics workspace ID was invalid"))?;
        let mut url = Url::parse("https://api.loganalytics.azure.com/")?;
        url.set_path(&format!("/v1/workspaces/{workspace_id}/query"));
        Ok(url)
    }

    fn validate_azure_workspace_resource(value: &str, subscription_id: &str) -> Result<()> {
        ensure!(
            safe_azure_resource_id(value),
            "Azure Log Analytics workspace resource ID was unsafe"
        );
        let segments = value.split('/').collect::<Vec<_>>();
        ensure!(
            segments.len() == 9
                && segments[0].is_empty()
                && segments[1].eq_ignore_ascii_case("subscriptions")
                && segments[2].eq_ignore_ascii_case(subscription_id)
                && segments[3].eq_ignore_ascii_case("resourcegroups")
                && safe_azure_path_segment(segments[4])
                && segments[5].eq_ignore_ascii_case("providers")
                && segments[6].eq_ignore_ascii_case("microsoft.operationalinsights")
                && segments[7].eq_ignore_ascii_case("workspaces")
                && safe_azure_path_segment(segments[8]),
            "Azure Log Analytics workspace escaped the configured subscription"
        );
        Ok(())
    }

    fn safe_azure_resource_id(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 2_048
            && value.starts_with('/')
            && !value.ends_with('/')
            && !value.chars().any(char::is_control)
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'(' | b')')
            })
    }

    fn safe_azure_path_segment(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 260
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'(' | b')')
            })
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

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AzurePage {
        #[serde(default)]
        value: Vec<AzureDeployment>,
        #[serde(default)]
        next_link: Option<String>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct AzureDeployment {
        id: String,
        properties: AzureDeploymentProperties,
    }

    impl AzureDeployment {
        fn minimal(self) -> Self {
            self
        }
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct AzureDeploymentProperties {
        provisioning_state: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model: Option<AzureModel>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct AzureModel {
        name: String,
    }

    #[derive(Debug, Serialize)]
    struct AzureEnvelope {
        value: Vec<AzureDeployment>,
        invocations: Vec<AzureInvocation>,
    }

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct AzureInvocation {
        request_id: String,
        model_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        principal_email: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        principal: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        source_ip: Option<String>,
        destination_host: String,
        observed_at: DateTime<Utc>,
    }

    #[derive(Deserialize)]
    struct AzureInventoryWorkspace {
        id: String,
        properties: AzureInventoryWorkspaceProperties,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AzureInventoryWorkspaceProperties {
        customer_id: String,
        provisioning_state: String,
    }

    #[derive(Serialize)]
    struct AzureInventoryLogsRequest<'a> {
        query: &'a str,
        timespan: String,
    }

    #[derive(Deserialize)]
    struct AzureInventoryLogsResponse {
        #[serde(default)]
        tables: Vec<AzureInventoryLogsTable>,
        #[serde(default)]
        error: Option<serde_json::Value>,
    }

    #[derive(Deserialize)]
    struct AzureInventoryLogsTable {
        name: String,
        columns: Vec<AzureInventoryLogsColumn>,
        rows: Vec<Vec<serde_json::Value>>,
    }

    #[derive(Deserialize)]
    struct AzureInventoryLogsColumn {
        name: String,
        #[serde(rename = "type")]
        data_type: String,
    }

    impl AzureInventoryLogsTable {
        fn minimal_invocations(self, account_name: &str) -> Result<Vec<AzureInvocation>> {
            const COLUMNS: [(&str, &str); 5] = [
                ("TimeGenerated", "datetime"),
                ("RequestId", "string"),
                ("Model", "string"),
                ("Principal", "string"),
                ("CallerIp", "string"),
            ];
            ensure!(
                self.name == "PrimaryResult"
                    && self.columns.len() == COLUMNS.len()
                    && self.columns.iter().zip(COLUMNS).all(|(actual, expected)| {
                        actual.name == expected.0 && actual.data_type == expected.1
                    }),
                "Azure OpenAI request-log response schema changed"
            );
            ensure!(
                self.rows.len() <= MAX_PROVIDER_RECORDS,
                "Azure OpenAI request logs exceeded the record cap"
            );
            self.rows
                .into_iter()
                .map(|row| azure_invocation_row(&row, account_name))
                .collect()
        }
    }

    fn azure_invocation_row(
        row: &[serde_json::Value],
        account_name: &str,
    ) -> Result<AzureInvocation> {
        ensure!(row.len() == 5, "Azure OpenAI request-log row shape changed");
        let observed_at = azure_log_string(&row[0], "time")?
            .parse::<DateTime<Utc>>()
            .map_err(|_| anyhow!("Azure OpenAI request-log time was invalid"))?;
        let request_id = azure_log_string(&row[1], "request ID")?.to_owned();
        let model_id = azure_log_string(&row[2], "model")?.to_owned();
        let principal = azure_log_optional_string(&row[3], "principal")?;
        let (principal_email, principal) = match principal {
            Some(value) if value.contains('@') => (Some(value), None),
            value => (None, value),
        };
        // Azure may privacy-mask the final octet (for example, `203.0.113.***`). That value is
        // useful to an operator in the raw workspace but is not an IP address Tally can safely
        // join against flow evidence, so retain only exact addresses here.
        let source_ip = azure_log_optional_string(&row[4], "caller IP")?.and_then(|value| {
            value
                .parse::<std::net::IpAddr>()
                .ok()
                .map(|ip| ip.to_string())
        });
        Ok(AzureInvocation {
            request_id,
            model_id,
            principal_email,
            principal,
            source_ip,
            destination_host: format!("{account_name}.openai.azure.com"),
            observed_at,
        })
    }

    fn azure_log_string<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str> {
        value
            .as_str()
            .filter(|value| !value.is_empty() && value.len() <= 2_048)
            .ok_or_else(|| anyhow!("Azure OpenAI request-log {field} was invalid"))
    }

    fn azure_log_optional_string(value: &serde_json::Value, field: &str) -> Result<Option<String>> {
        if value.is_null() || value.as_str() == Some("") {
            return Ok(None);
        }
        azure_log_string(value, field).map(|value| Some(value.to_owned()))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn azure_next_link_cannot_leave_the_account_or_origin() {
            let account = "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/tally/providers/Microsoft.CognitiveServices/accounts/tally-ai";
            let url = azure_deployments_url("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", account)
                .expect("Azure URL");
            let expected_path = url.path().to_ascii_lowercase();
            let valid = format!(
                "https://management.azure.com{expected_path}?api-version={AZURE_API_VERSION}&%24skiptoken=opaque"
            );
            assert!(validate_azure_next_link(&valid, &expected_path).is_ok());
            assert!(
                validate_azure_next_link(
                    &valid.replace("management.azure.com", "example.com"),
                    &expected_path
                )
                .is_err()
            );
            assert!(
                validate_azure_next_link(
                    &valid.replace("/deployments", "/deployments/other"),
                    &expected_path
                )
                .is_err()
            );
        }

        #[test]
        fn provider_response_projection_drops_customer_controlled_fields() {
            let azure: AzurePage = serde_json::from_str(
            r#"{"value":[{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/a/deployments/d","name":"CONTENT_CANARY","tags":{"owner":"person@example.com"},"properties":{"provisioningState":"Succeeded","model":{"name":"gpt-4o","version":"private"},"raiPolicyName":"CONTENT_CANARY"}}]}"#,
        )
        .expect("Azure provider response");
            let serialized = serde_json::to_string(&AzureEnvelope {
                value: azure
                    .value
                    .into_iter()
                    .map(AzureDeployment::minimal)
                    .collect(),
                invocations: Vec::new(),
            })
            .expect("minimal Azure envelope");
            assert!(!serialized.contains("CONTENT_CANARY"));
            assert!(!serialized.contains("person@example.com"));
            assert!(!serialized.contains("private"));
            assert!(serialized.contains("gpt-4o"));
        }

        #[test]
        fn openai_log_projection_has_a_strict_attribution_schema() {
            let table = AzureInventoryLogsTable {
                name: "PrimaryResult".to_owned(),
                columns: [
                    ("TimeGenerated", "datetime"),
                    ("RequestId", "string"),
                    ("Model", "string"),
                    ("Principal", "string"),
                    ("CallerIp", "string"),
                ]
                .into_iter()
                .map(|(name, data_type)| AzureInventoryLogsColumn {
                    name: name.to_owned(),
                    data_type: data_type.to_owned(),
                })
                .collect(),
                rows: vec![vec![
                    serde_json::json!("2026-09-04T16:30:00Z"),
                    serde_json::json!("request-1"),
                    serde_json::json!("gpt-4.1-mini"),
                    serde_json::json!("person@example.com"),
                    serde_json::json!("203.0.113.10"),
                ]],
            };
            let invocations = table
                .minimal_invocations("tally-ai")
                .expect("strict request-log table");
            let serialized = serde_json::to_string(&invocations).expect("projection");
            assert!(serialized.contains("person@example.com"));
            assert!(serialized.contains("203.0.113.10"));
            assert!(serialized.contains("gpt-4.1-mini"));
            assert!(!serialized.contains("prompt"));
            assert!(!serialized.contains("response"));

            let masked = AzureInventoryLogsTable {
                name: "PrimaryResult".to_owned(),
                columns: [
                    ("TimeGenerated", "datetime"),
                    ("RequestId", "string"),
                    ("Model", "string"),
                    ("Principal", "string"),
                    ("CallerIp", "string"),
                ]
                .into_iter()
                .map(|(name, data_type)| AzureInventoryLogsColumn {
                    name: name.to_owned(),
                    data_type: data_type.to_owned(),
                })
                .collect(),
                rows: vec![vec![
                    serde_json::json!("2026-09-04T16:30:00Z"),
                    serde_json::json!("request-2"),
                    serde_json::json!("gpt-4.1-mini"),
                    serde_json::json!("ba0d50df-e4a7-4c60-a845-33c7be21d910"),
                    serde_json::json!("203.0.113.***"),
                ]],
            };
            let masked = masked
                .minimal_invocations("tally-ai")
                .expect("masked caller address");
            let serialized = serde_json::to_string(&masked).expect("masked projection");
            assert!(serialized.contains("ba0d50df-e4a7-4c60-a845-33c7be21d910"));
            assert!(!serialized.contains("203.0.113.***"));
        }
    }
}

mod network {
    use super::{
        AZURE_COMPUTE_API_VERSION, AZURE_CURSOR_PREFIX, AZURE_LOGS_SCOPE, AZURE_MANAGEMENT_SCOPE,
        AZURE_NETWORK_API_VERSION, AZURE_WORKSPACE_API_VERSION, Context, DateTime, Deserialize,
        DeserializeOwned, Duration, FLOW_INGESTION_DELAY_MINUTES, FLOW_OVERLAP_MINUTES, HashMap,
        HashSet, Hostname, IpAddr, MAPPING_FUTURE_MINUTES, MAPPING_LOOKBACK_MINUTES,
        MAX_IMPORT_BYTES, MAX_PAGE_BYTES, MAX_PROVIDER_PAGES, MAX_PROVIDER_RECORDS,
        NativeNetworkPull, NativeNetworkSnapshot, Response, Result, SecondsFormat, Serialize, Url,
        Utc, VendorAdapter, anyhow, bail, ensure, header,
    };
    pub(super) async fn pull_azure(
        request: &NativeNetworkPull<'_>,
        client: &reqwest::Client,
    ) -> Result<NativeNetworkSnapshot> {
        validate_azure_scope(request.account_id, request.network_id, request.region)?;
        let management_token = super::inventory::azure_access_token_with_credentials(
            AZURE_MANAGEMENT_SCOPE,
            request.credentials.azure.as_ref(),
        )
        .await?;
        verify_azure_vnet(
            client,
            management_token.token.secret(),
            request.account_id,
            request.network_id,
            request.region,
        )
        .await?;
        match request.adapter {
            VendorAdapter::AzureCloudFlowApi => {
                let workspace_resource = request
                    .workspace_resource
                    .ok_or_else(|| anyhow!("Azure flow workspace resource is required"))?;
                validate_azure_workspace_id(workspace_resource, request.account_id)?;
                let workspace_id = azure_workspace_customer_id(
                    client,
                    management_token.token.secret(),
                    request.account_id,
                    workspace_resource,
                )
                .await?;
                let logs_token = super::inventory::azure_access_token_with_credentials(
                    AZURE_LOGS_SCOPE,
                    request.credentials.azure.as_ref(),
                )
                .await?;
                pull_azure_flows(client, logs_token.token.secret(), request, &workspace_id).await
            }
            VendorAdapter::AzureNetworkMappingApi => {
                ensure!(
                    request.workspace_resource.is_none(),
                    "Azure mapping does not accept a workspace resource"
                );
                pull_azure_mappings(
                    client,
                    management_token.token.secret(),
                    request.account_id,
                    request.network_id,
                    request.region,
                    request.now,
                )
                .await
            }
            _ => bail!("Azure network adapter is unsupported"),
        }
    }

    async fn verify_azure_vnet(
        client: &reqwest::Client,
        token: &str,
        subscription_id: &str,
        network_id: &str,
        region: &str,
    ) -> Result<()> {
        let response = client
            .get(azure_arm_resource_url(
                network_id,
                AZURE_NETWORK_API_VERSION,
            )?)
            .header(header::ACCEPT, "application/json")
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| anyhow!("Azure virtual-network verification request failed"))?;
        let resource: AzureVirtualNetwork =
            bounded_json(response, "Azure virtual-network verification").await?;
        validate_azure_vnet_id(&resource.id, subscription_id)?;
        ensure!(
            resource.id.eq_ignore_ascii_case(network_id)
                && resource.location.eq_ignore_ascii_case(region)
                && resource
                    .properties
                    .provisioning_state
                    .eq_ignore_ascii_case("Succeeded"),
            "Azure virtual-network verification did not match the configured scope"
        );
        Ok(())
    }

    async fn azure_workspace_customer_id(
        client: &reqwest::Client,
        token: &str,
        subscription_id: &str,
        workspace_resource: &str,
    ) -> Result<String> {
        let response = client
            .get(azure_arm_resource_url(
                workspace_resource,
                AZURE_WORKSPACE_API_VERSION,
            )?)
            .header(header::ACCEPT, "application/json")
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| anyhow!("Azure Log Analytics workspace verification request failed"))?;
        let workspace: AzureWorkspace =
            bounded_json(response, "Azure Log Analytics workspace verification").await?;
        validate_azure_workspace_id(&workspace.id, subscription_id)?;
        ensure!(
            workspace.id.eq_ignore_ascii_case(workspace_resource)
                && workspace
                    .properties
                    .provisioning_state
                    .eq_ignore_ascii_case("Succeeded"),
            "Azure Log Analytics workspace did not match the configured scope"
        );
        let workspace_id = workspace.properties.customer_id;
        uuid::Uuid::parse_str(&workspace_id)
            .map_err(|_| anyhow!("Azure Log Analytics workspace ID was invalid"))?;
        Ok(workspace_id.to_ascii_lowercase())
    }

    async fn pull_azure_flows(
        client: &reqwest::Client,
        token: &str,
        request: &NativeNetworkPull<'_>,
        workspace_id: &str,
    ) -> Result<NativeNetworkSnapshot> {
        let end = request.now - Duration::minutes(FLOW_INGESTION_DELAY_MINUTES);
        let start = if request.cursor_before.is_empty() {
            end - Duration::seconds(i64::from(request.initial_lookback_seconds))
        } else {
            parse_cursor(request.cursor_before, AZURE_CURSOR_PREFIX, "Azure")?
                - Duration::minutes(FLOW_OVERLAP_MINUTES)
        };
        let cursor_after = format!("{AZURE_CURSOR_PREFIX}{}", end.timestamp_millis());
        if start >= end {
            return serialize_snapshot(
                &FlowEnvelope {
                    provider: "azure",
                    account_id: request.account_id,
                    region: request.region,
                    network_id: request.network_id,
                    ignored_records: 0,
                    records: Vec::new(),
                },
                0,
                cursor_after,
            );
        }
        let query = azure_flow_query(request.network_id, start, end)?;
        let query_request = AzureLogsQueryRequest {
            query: &query,
            timespan: format!(
                "{}/{}",
                start.to_rfc3339_opts(SecondsFormat::Millis, true),
                request.now.to_rfc3339_opts(SecondsFormat::Millis, true)
            ),
        };
        let response = client
            .post(azure_logs_query_url(workspace_id)?)
            .header(header::ACCEPT, "application/json")
            .bearer_auth(token)
            .json(&query_request)
            .send()
            .await
            .map_err(|_| anyhow!("Azure VNet flow-log query failed"))?;
        let result: AzureLogsQueryResponse = bounded_json(response, "Azure VNet flow-log").await?;
        ensure!(
            result.error.is_none() && result.tables.len() == 1,
            "Azure VNet flow-log query was incomplete"
        );
        let table = result
            .tables
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Azure VNet flow-log query returned no table"))?;
        let records = table.minimal_flows(request.network_id, workspace_id)?;
        enforce_record_cap(records.len(), "Azure VNet flow-log")?;
        let count = records.len();
        serialize_snapshot(
            &FlowEnvelope {
                provider: "azure",
                account_id: request.account_id,
                region: request.region,
                network_id: request.network_id,
                ignored_records: 0,
                records,
            },
            count,
            cursor_after,
        )
    }

    async fn pull_azure_mappings(
        client: &reqwest::Client,
        token: &str,
        subscription_id: &str,
        network_id: &str,
        region: &str,
        now: DateTime<Utc>,
    ) -> Result<NativeNetworkSnapshot> {
        let valid_from = now - Duration::minutes(MAPPING_LOOKBACK_MINUTES);
        let valid_until = now + Duration::minutes(MAPPING_FUTURE_MINUTES);
        let virtual_machine_hostnames =
            azure_virtual_machine_hostnames(client, token, subscription_id, region).await?;
        let mut records = Vec::new();
        let mut next = azure_network_interfaces_url(subscription_id)?;
        let expected_path = next.path().to_ascii_lowercase();
        let mut seen_links = HashSet::new();
        let mut exhausted = false;
        for _ in 0..MAX_PROVIDER_PAGES {
            let response = client
                .get(next.clone())
                .header(header::ACCEPT, "application/json")
                .bearer_auth(token)
                .send()
                .await
                .map_err(|_| anyhow!("Azure network mapping request failed"))?;
            let page: AzureNetworkInterfacePage =
                bounded_json(response, "Azure network mapping").await?;
            for interface in page.value {
                records.extend(interface.minimal_mappings(
                    subscription_id,
                    network_id,
                    region,
                    valid_from,
                    valid_until,
                    &virtual_machine_hostnames,
                )?);
                enforce_record_cap(records.len(), "Azure network mapping")?;
            }
            let Some(next_link) = page.next_link else {
                exhausted = true;
                break;
            };
            ensure!(
                seen_links.insert(next_link.clone()),
                "Azure network mapping pagination link repeated"
            );
            next = validate_azure_next_link(&next_link, &expected_path, AZURE_NETWORK_API_VERSION)?;
        }
        ensure!(exhausted, "Azure network mapping exceeded the page cap");
        let count = records.len();
        serialize_snapshot(
            &MappingEnvelope {
                provider: "azure",
                account_id: subscription_id,
                region,
                network_id,
                records,
            },
            count,
            format!("{AZURE_CURSOR_PREFIX}{}", now.timestamp_millis()),
        )
    }

    fn azure_flow_query(
        network_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<String> {
        ensure!(start < end, "Azure VNet flow-log window is invalid");
        ensure!(
            safe_azure_kql_literal(network_id),
            "Azure virtual-network resource ID was unsafe"
        );
        let target_resource_id = azure_traffic_analytics_target_id(network_id)?;
        Ok(format!(
            "NTANetAnalytics\n| where FlowStartTime >= datetime({}) and FlowStartTime < datetime({})\n| where SubType =~ \"FlowLog\" and TargetResourceType =~ \"VirtualNetwork\"\n| where TargetResourceId =~ \"{}\"\n| extend PublicEntries = split(iff(FlowDirection =~ \"Outbound\", tostring(DestPublicIps), tostring(SrcPublicIps)), \" \")\n| mv-expand PublicEntry = PublicEntries to typeof(string)\n| extend PublicIp = tostring(split(PublicEntry, \"|\")[0])\n| extend NormalizedSrcIp = iff(isempty(SrcIp), PublicIp, tostring(SrcIp)), NormalizedDestIp = iff(isempty(DestIp), PublicIp, tostring(DestIp))\n| where isnotempty(NormalizedSrcIp) and isnotempty(NormalizedDestIp)\n| project FlowStartTime, FlowEndTime, SrcIp=NormalizedSrcIp, DestIp=NormalizedDestIp, SrcPorts, DestPort, L4Protocol, PacketsSrcToDest, PacketsDestToSrc, BytesSrcToDest, BytesDestToSrc, FlowDirection, Action=FlowStatus, TargetResourceId, TargetResourceType, SubType, TenantId, SrcVm, DestVm, DestServiceTags\n| order by FlowStartTime asc\n| take 10001",
            start.to_rfc3339_opts(SecondsFormat::Millis, true),
            end.to_rfc3339_opts(SecondsFormat::Millis, true),
            target_resource_id
        ))
    }

    fn azure_traffic_analytics_target_id(network_id: &str) -> Result<String> {
        let segments = network_id.split('/').collect::<Vec<_>>();
        ensure!(
            segments.len() == 9
                && segments[0].is_empty()
                && segments[1].eq_ignore_ascii_case("subscriptions")
                && segments[3].eq_ignore_ascii_case("resourcegroups")
                && segments[5].eq_ignore_ascii_case("providers")
                && segments[6].eq_ignore_ascii_case("microsoft.network")
                && segments[7].eq_ignore_ascii_case("virtualnetworks"),
            "Azure virtual-network resource ID was invalid"
        );
        Ok(format!("{}/{}/{}", segments[2], segments[4], segments[8]))
    }

    fn azure_logs_query_url(workspace_id: &str) -> Result<Url> {
        uuid::Uuid::parse_str(workspace_id)
            .map_err(|_| anyhow!("Azure Log Analytics workspace ID was invalid"))?;
        let mut url = Url::parse("https://api.loganalytics.azure.com/")?;
        url.set_path(&format!("/v1/workspaces/{workspace_id}/query"));
        Ok(url)
    }

    fn azure_network_interfaces_url(subscription_id: &str) -> Result<Url> {
        validate_azure_subscription(subscription_id)?;
        let mut url = Url::parse("https://management.azure.com/")?;
        url.set_path(&format!(
            "/subscriptions/{subscription_id}/providers/Microsoft.Network/networkInterfaces"
        ));
        url.query_pairs_mut()
            .append_pair("api-version", AZURE_NETWORK_API_VERSION);
        Ok(url)
    }

    fn azure_virtual_machines_url(subscription_id: &str) -> Result<Url> {
        validate_azure_subscription(subscription_id)?;
        let mut url = Url::parse("https://management.azure.com/")?;
        url.set_path(&format!(
            "/subscriptions/{subscription_id}/providers/Microsoft.Compute/virtualMachines"
        ));
        url.query_pairs_mut()
            .append_pair("api-version", AZURE_COMPUTE_API_VERSION);
        Ok(url)
    }

    fn azure_arm_resource_url(resource_id: &str, api_version: &str) -> Result<Url> {
        ensure!(
            safe_azure_resource_id(resource_id),
            "Azure resource ID was unsafe"
        );
        let mut url = Url::parse("https://management.azure.com/")?;
        url.set_path(resource_id);
        url.query_pairs_mut()
            .append_pair("api-version", api_version);
        Ok(url)
    }

    fn validate_azure_next_link(
        value: &str,
        expected_path: &str,
        api_version: &str,
    ) -> Result<Url> {
        ensure!(
            !value.is_empty() && value.len() <= 16_384 && !value.chars().any(char::is_control),
            "Azure network mapping pagination link was unsafe"
        );
        let url = Url::parse(value).context("Azure network mapping pagination link was invalid")?;
        ensure!(
            url.scheme() == "https"
                && url.host_str() == Some("management.azure.com")
                && url.port().is_none()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
                && url.path().eq_ignore_ascii_case(expected_path)
                && url
                    .query_pairs()
                    .any(|(key, value)| { key == "api-version" && value == api_version }),
            "Azure network mapping pagination link escaped the configured endpoint"
        );
        Ok(url)
    }

    fn validate_azure_scope(subscription_id: &str, network_id: &str, region: &str) -> Result<()> {
        validate_azure_subscription(subscription_id)?;
        validate_azure_vnet_id(network_id, subscription_id)?;
        ensure!(
            (1..=63).contains(&region.len())
                && region
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_lowercase())
                && region
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
            "Azure region is invalid"
        );
        Ok(())
    }

    fn validate_azure_subscription(value: &str) -> Result<()> {
        let parsed = uuid::Uuid::parse_str(value)
            .map_err(|_| anyhow!("Azure subscription ID is invalid"))?;
        ensure!(
            parsed.to_string() == value.to_ascii_lowercase(),
            "Azure subscription ID must use canonical UUID syntax"
        );
        Ok(())
    }

    fn validate_azure_vnet_id(value: &str, subscription_id: &str) -> Result<()> {
        validate_azure_typed_resource_id(
            value,
            subscription_id,
            "microsoft.network",
            "virtualnetworks",
            "Azure virtual-network resource ID",
        )
    }

    fn validate_azure_workspace_id(value: &str, subscription_id: &str) -> Result<()> {
        validate_azure_typed_resource_id(
            value,
            subscription_id,
            "microsoft.operationalinsights",
            "workspaces",
            "Azure Log Analytics workspace resource ID",
        )
    }

    fn validate_azure_typed_resource_id(
        value: &str,
        subscription_id: &str,
        namespace: &str,
        resource_type: &str,
        field: &str,
    ) -> Result<()> {
        ensure!(safe_azure_resource_id(value), "{field} was unsafe");
        let segments = value.split('/').collect::<Vec<_>>();
        ensure!(
            segments.len() == 9
                && segments[0].is_empty()
                && segments[1].eq_ignore_ascii_case("subscriptions")
                && segments[2].eq_ignore_ascii_case(subscription_id)
                && segments[3].eq_ignore_ascii_case("resourcegroups")
                && safe_azure_path_segment(segments[4])
                && segments[5].eq_ignore_ascii_case("providers")
                && segments[6].eq_ignore_ascii_case(namespace)
                && segments[7].eq_ignore_ascii_case(resource_type)
                && safe_azure_path_segment(segments[8]),
            "{field} did not match the configured subscription"
        );
        Ok(())
    }

    fn validate_azure_nested_resource_id(
        value: &str,
        subscription_id: &str,
        namespace: &str,
        resource_type: &str,
        field: &str,
    ) -> Result<()> {
        ensure!(safe_azure_resource_id(value), "{field} was unsafe");
        let segments = value.split('/').collect::<Vec<_>>();
        ensure!(
            segments.len() >= 9
                && segments[0].is_empty()
                && segments[1].eq_ignore_ascii_case("subscriptions")
                && segments[2].eq_ignore_ascii_case(subscription_id)
                && segments[3].eq_ignore_ascii_case("resourcegroups")
                && safe_azure_path_segment(segments[4])
                && segments[5].eq_ignore_ascii_case("providers")
                && segments[6].eq_ignore_ascii_case(namespace)
                && segments[7].eq_ignore_ascii_case(resource_type)
                && segments[8..]
                    .iter()
                    .all(|segment| safe_azure_path_segment(segment)),
            "{field} did not match the configured subscription"
        );
        Ok(())
    }

    fn safe_azure_resource_id(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 2_048
            && value.starts_with('/')
            && !value.ends_with('/')
            && !value.chars().any(char::is_control)
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'(' | b')')
            })
    }

    fn safe_azure_path_segment(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 260
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'(' | b')')
            })
    }

    fn safe_azure_kql_literal(value: &str) -> bool {
        safe_azure_resource_id(value) && !value.contains(['"', '\'', '\\'])
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

    #[derive(Debug, Deserialize)]
    struct AzureVirtualNetwork {
        id: String,
        location: String,
        properties: AzureProvisioningProperties,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AzureProvisioningProperties {
        provisioning_state: String,
    }

    #[derive(Debug, Deserialize)]
    struct AzureWorkspace {
        id: String,
        properties: AzureWorkspaceProperties,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AzureWorkspaceProperties {
        customer_id: String,
        provisioning_state: String,
    }

    #[derive(Debug, Serialize)]
    struct AzureLogsQueryRequest<'a> {
        query: &'a str,
        timespan: String,
    }

    #[derive(Debug, Deserialize)]
    struct AzureLogsQueryResponse {
        #[serde(default)]
        tables: Vec<AzureLogsTable>,
        #[serde(default)]
        error: Option<serde_json::Value>,
    }

    #[derive(Debug, Deserialize)]
    struct AzureLogsTable {
        name: String,
        columns: Vec<AzureLogsColumn>,
        rows: Vec<Vec<serde_json::Value>>,
    }

    #[derive(Debug, Deserialize)]
    struct AzureLogsColumn {
        name: String,
        #[serde(rename = "type")]
        data_type: String,
    }

    impl AzureLogsTable {
        fn minimal_flows(self, network_id: &str, workspace_id: &str) -> Result<Vec<FlowRecord>> {
            const COLUMNS: [(&str, &str); 20] = [
                ("FlowStartTime", "datetime"),
                ("FlowEndTime", "datetime"),
                ("SrcIp", "string"),
                ("DestIp", "string"),
                ("SrcPorts", "string"),
                ("DestPort", "int"),
                ("L4Protocol", "string"),
                ("PacketsSrcToDest", "long"),
                ("PacketsDestToSrc", "long"),
                ("BytesSrcToDest", "long"),
                ("BytesDestToSrc", "long"),
                ("FlowDirection", "string"),
                ("Action", "string"),
                ("TargetResourceId", "string"),
                ("TargetResourceType", "string"),
                ("SubType", "string"),
                ("TenantId", "string"),
                ("SrcVm", "string"),
                ("DestVm", "string"),
                ("DestServiceTags", "string"),
            ];
            ensure!(
                self.name == "PrimaryResult"
                    && self.columns.len() == COLUMNS.len()
                    && self.columns.iter().zip(COLUMNS).all(|(actual, expected)| {
                        actual.name == expected.0 && actual.data_type == expected.1
                    }),
                "Azure VNet flow-log response schema changed"
            );
            ensure!(
                self.rows.len() <= MAX_PROVIDER_RECORDS,
                "Azure VNet flow-log exceeded the record cap"
            );
            self.rows
                .into_iter()
                .map(|row| azure_flow_record(&row, network_id, workspace_id))
                .collect()
        }
    }

    fn azure_flow_record(
        row: &[serde_json::Value],
        network_id: &str,
        workspace_id: &str,
    ) -> Result<FlowRecord> {
        ensure!(row.len() == 20, "Azure VNet flow-log row shape changed");
        let window_start = azure_datetime(&row[0], "start")?;
        let window_end = azure_datetime(&row[1], "end")?;
        ensure!(
            window_start <= window_end,
            "Azure VNet flow-log window was invalid"
        );
        let source_ip = azure_string(&row[2], "source address")?
            .parse::<IpAddr>()
            .map_err(|_| anyhow!("Azure VNet flow source address was invalid"))?;
        let destination_ip = azure_string(&row[3], "destination address")?
            .parse::<IpAddr>()
            .map_err(|_| anyhow!("Azure VNet flow destination address was invalid"))?;
        let source_port = azure_source_port(&row[4])?;
        let destination_port = azure_destination_port(&row[5])?;
        let protocol = match azure_string(&row[6], "protocol")?
            .to_ascii_uppercase()
            .as_str()
        {
            "T" | "TCP" => "tcp",
            "U" | "UDP" => "udp",
            _ => bail!("Azure VNet flow protocol was unsupported"),
        };
        let packets = azure_counter_sum(&row[7], &row[8], "packets")?;
        let bytes = azure_directional_bytes(&row[9])?;
        let bytes_received = azure_directional_bytes(&row[10])?;
        let direction = match azure_string(&row[11], "direction")?
            .to_ascii_lowercase()
            .as_str()
        {
            "inbound" | "ingress" => "ingress",
            "outbound" | "egress" => "egress",
            _ => bail!("Azure VNet flow direction was unsupported"),
        };
        let decision = match azure_string(&row[12], "action")?
            .to_ascii_lowercase()
            .as_str()
        {
            "allow" | "allowed" => "accepted",
            "deny" | "denied" => "rejected",
            _ => bail!("Azure VNet flow action was unsupported"),
        };
        ensure!(
            azure_string(&row[13], "target resource")?
                .eq_ignore_ascii_case(&azure_traffic_analytics_target_id(network_id)?)
                && azure_string(&row[14], "target resource type")?
                    .eq_ignore_ascii_case("VirtualNetwork")
                && azure_string(&row[15], "subtype")?.eq_ignore_ascii_case("FlowLog")
                && azure_string(&row[16], "workspace")?.eq_ignore_ascii_case(workspace_id),
            "Azure VNet flow-log escaped the configured scope"
        );
        Ok(FlowRecord {
            window_start,
            window_end,
            source_ip: source_ip.to_string(),
            destination_ip: destination_ip.to_string(),
            source_hostname: azure_vm_hostname(&row[17], "source VM")?,
            destination_hostname: azure_vm_hostname(&row[18], "destination VM")?
                .or_else(|| azure_destination_service_hostname(&row[19], destination_ip)),
            source_port,
            destination_port,
            protocol,
            packets,
            bytes,
            bytes_received,
            direction,
            decision,
        })
    }

    fn azure_string<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str> {
        value
            .as_str()
            .filter(|value| !value.is_empty() && value.len() <= 2_048)
            .ok_or_else(|| anyhow!("Azure VNet flow {field} was invalid"))
    }

    fn azure_datetime(value: &serde_json::Value, field: &str) -> Result<DateTime<Utc>> {
        azure_string(value, field)?
            .parse::<DateTime<Utc>>()
            .map_err(|_| anyhow!("Azure VNet flow {field} time was invalid"))
    }

    fn azure_source_port(value: &serde_json::Value) -> Result<Option<u16>> {
        if value.is_null() || value.as_str() == Some("") {
            return Ok(None);
        }
        let ports = azure_string(value, "source ports")?;
        if ports.contains('|') {
            return Ok(None);
        }
        ports
            .parse::<u16>()
            .map(Some)
            .map_err(|_| anyhow!("Azure VNet flow source port was invalid"))
    }

    fn azure_vm_hostname(value: &serde_json::Value, field: &str) -> Result<Option<String>> {
        if value.is_null() || value.as_str() == Some("") {
            return Ok(None);
        }
        let value = azure_string(value, field)?;
        let hostname = value.rsplit('/').next().unwrap_or(value);
        normalized_hostname(hostname)
            .map(Some)
            .ok_or_else(|| anyhow!("Azure VNet flow {field} was invalid"))
    }

    fn azure_destination_service_hostname(
        value: &serde_json::Value,
        destination_ip: IpAddr,
    ) -> Option<String> {
        let tags = value.as_str()?;
        let destination_ip = destination_ip.to_string();
        tags.split(" | ").find_map(|tag| {
            let (service, addresses) = tag.split_once('-')?;
            (service.eq_ignore_ascii_case("CognitiveServicesManagement")
                && addresses.split(',').any(|value| value == destination_ip))
            .then(|| "openai.azure.com".to_owned())
        })
    }

    fn azure_destination_port(value: &serde_json::Value) -> Result<Option<u16>> {
        if value.is_null() {
            return Ok(None);
        }
        value
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .map(Some)
            .ok_or_else(|| anyhow!("Azure VNet flow destination port was invalid"))
    }

    fn azure_directional_bytes(value: &serde_json::Value) -> Result<Option<u64>> {
        if value.is_null() {
            return Ok(None);
        }
        let count = azure_counter(value, "bytes")?;
        ensure!(
            count <= 1_000_000_000_000_000,
            "Azure VNet byte counter exceeded the bound"
        );
        Ok(Some(count))
    }

    fn azure_counter_sum(
        first: &serde_json::Value,
        second: &serde_json::Value,
        field: &str,
    ) -> Result<Option<u64>> {
        let first = azure_counter(first, field)?;
        let second = azure_counter(second, field)?;
        let total = first
            .checked_add(second)
            .ok_or_else(|| anyhow!("Azure VNet flow {field} counter overflowed"))?;
        ensure!(
            total <= 1_000_000_000_000_000,
            "Azure VNet flow {field} counter exceeded the bound"
        );
        Ok((total > 0).then_some(total))
    }

    fn azure_counter(value: &serde_json::Value, field: &str) -> Result<u64> {
        if value.is_null() {
            return Ok(0);
        }
        value
            .as_u64()
            .ok_or_else(|| anyhow!("Azure VNet flow {field} counter was invalid"))
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AzureNetworkInterfacePage {
        #[serde(default)]
        value: Vec<AzureNetworkInterface>,
        #[serde(default)]
        next_link: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AzureVirtualMachinePage {
        #[serde(default)]
        value: Vec<AzureVirtualMachine>,
        #[serde(default)]
        next_link: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct AzureVirtualMachine {
        id: String,
        location: String,
        properties: AzureVirtualMachineProperties,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AzureVirtualMachineProperties {
        #[serde(default)]
        os_profile: Option<AzureOsProfile>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AzureOsProfile {
        #[serde(default)]
        computer_name: Option<String>,
    }

    async fn azure_virtual_machine_hostnames(
        client: &reqwest::Client,
        token: &str,
        subscription_id: &str,
        region: &str,
    ) -> Result<HashMap<String, String>> {
        let mut hostnames = HashMap::new();
        let mut next = azure_virtual_machines_url(subscription_id)?;
        let expected_path = next.path().to_ascii_lowercase();
        let mut seen_links = HashSet::new();
        let mut exhausted = false;
        for _ in 0..MAX_PROVIDER_PAGES {
            let response = client
                .get(next.clone())
                .header(header::ACCEPT, "application/json")
                .bearer_auth(token)
                .send()
                .await
                .map_err(|_| anyhow!("Azure virtual-machine mapping request failed"))?;
            let page: AzureVirtualMachinePage =
                bounded_json(response, "Azure virtual-machine mapping").await?;
            for machine in page.value {
                validate_azure_typed_resource_id(
                    &machine.id,
                    subscription_id,
                    "microsoft.compute",
                    "virtualmachines",
                    "Azure virtual-machine resource ID",
                )?;
                if !machine.location.eq_ignore_ascii_case(region) {
                    continue;
                }
                let Some(hostname) = machine
                    .properties
                    .os_profile
                    .and_then(|profile| profile.computer_name)
                    .and_then(|value| normalized_hostname(&value))
                else {
                    continue;
                };
                ensure!(
                    hostnames
                        .insert(machine.id.to_ascii_lowercase(), hostname)
                        .is_none(),
                    "duplicate Azure virtual machine"
                );
                enforce_record_cap(hostnames.len(), "Azure virtual-machine mapping")?;
            }
            let Some(next_link) = page.next_link else {
                exhausted = true;
                break;
            };
            ensure!(
                seen_links.insert(next_link.clone()),
                "Azure virtual-machine pagination link repeated"
            );
            next = validate_azure_next_link(&next_link, &expected_path, AZURE_COMPUTE_API_VERSION)?;
        }
        ensure!(
            exhausted,
            "Azure virtual-machine mapping exceeded the page cap"
        );
        Ok(hostnames)
    }

    #[derive(Debug, Deserialize)]
    struct AzureNetworkInterface {
        id: String,
        location: String,
        properties: AzureNetworkInterfaceProperties,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AzureNetworkInterfaceProperties {
        #[serde(default)]
        virtual_machine: Option<AzureSubResource>,
        #[serde(default)]
        ip_configurations: Vec<AzureIpConfiguration>,
    }

    #[derive(Debug, Deserialize)]
    struct AzureSubResource {
        id: String,
    }

    #[derive(Debug, Deserialize)]
    struct AzureIpConfiguration {
        properties: AzureIpConfigurationProperties,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AzureIpConfigurationProperties {
        #[serde(default, rename = "privateIPAddress")]
        private_ip_address: Option<String>,
        #[serde(default)]
        subnet: Option<AzureSubResource>,
    }

    impl AzureNetworkInterface {
        fn minimal_mappings(
            self,
            subscription_id: &str,
            network_id: &str,
            region: &str,
            valid_from: DateTime<Utc>,
            valid_until: DateTime<Utc>,
            virtual_machine_hostnames: &HashMap<String, String>,
        ) -> Result<Vec<MappingRecord>> {
            validate_azure_typed_resource_id(
                &self.id,
                subscription_id,
                "microsoft.network",
                "networkinterfaces",
                "Azure network-interface resource ID",
            )?;
            let mut addresses = HashSet::new();
            for configuration in self.properties.ip_configurations {
                let Some(subnet) = configuration.properties.subnet else {
                    continue;
                };
                if !azure_subnet_belongs_to_network(&subnet.id, subscription_id, network_id)? {
                    continue;
                }
                ensure!(
                    self.location.eq_ignore_ascii_case(region),
                    "Azure network interface escaped the configured region"
                );
                if let Some(address) = configuration.properties.private_ip_address {
                    addresses.insert(address);
                }
            }
            let (resource_id, resource_kind, hostname) =
                if let Some(resource) = self.properties.virtual_machine {
                    let regular_vm = validate_azure_typed_resource_id(
                        &resource.id,
                        subscription_id,
                        "microsoft.compute",
                        "virtualmachines",
                        "Azure virtual-machine resource ID",
                    )
                    .is_ok();
                    ensure!(
                        regular_vm || azure_vmss_instance_id(&resource.id, subscription_id),
                        "Azure compute attachment did not match the configured subscription"
                    );
                    let resource_id = resource.id.to_ascii_lowercase();
                    let hostname = if regular_vm {
                        virtual_machine_hostnames.get(&resource_id).cloned()
                    } else {
                        None
                    };
                    (resource_id, "workload", hostname)
                } else {
                    (self.id.to_ascii_lowercase(), "network_interface", None)
                };
            let mut records = Vec::new();
            for private_ip in addresses {
                let address = private_ip
                    .parse::<IpAddr>()
                    .map_err(|_| anyhow!("Azure network mapping address was invalid"))?;
                if !is_private(address) {
                    continue;
                }
                records.push(MappingRecord {
                    valid_from,
                    valid_until,
                    private_ip,
                    interface_id: self.id.to_ascii_lowercase(),
                    resource_id: resource_id.clone(),
                    resource_kind,
                    hostname: hostname.clone(),
                });
            }
            Ok(records)
        }
    }

    fn azure_vmss_instance_id(value: &str, subscription_id: &str) -> bool {
        if !safe_azure_resource_id(value) {
            return false;
        }
        let segments = value.split('/').collect::<Vec<_>>();
        segments.len() == 11
            && segments[0].is_empty()
            && segments[1].eq_ignore_ascii_case("subscriptions")
            && segments[2].eq_ignore_ascii_case(subscription_id)
            && segments[3].eq_ignore_ascii_case("resourcegroups")
            && safe_azure_path_segment(segments[4])
            && segments[5].eq_ignore_ascii_case("providers")
            && segments[6].eq_ignore_ascii_case("microsoft.compute")
            && segments[7].eq_ignore_ascii_case("virtualmachinescalesets")
            && safe_azure_path_segment(segments[8])
            && segments[9].eq_ignore_ascii_case("virtualmachines")
            && safe_azure_path_segment(segments[10])
    }

    fn azure_subnet_belongs_to_network(
        value: &str,
        subscription_id: &str,
        network_id: &str,
    ) -> Result<bool> {
        validate_azure_nested_resource_id(
            value,
            subscription_id,
            "microsoft.network",
            "virtualnetworks",
            "Azure subnet resource ID",
        )?;
        let expected = format!("{}/subnets/", network_id.to_ascii_lowercase());
        Ok(value.to_ascii_lowercase().starts_with(&expected) && value.split('/').count() == 11)
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
        #[serde(skip_serializing_if = "Option::is_none")]
        bytes_received: Option<u64>,
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
        fn azure_directional_bytes_distinguish_unknown_from_measured_zero() {
            assert_eq!(
                azure_directional_bytes(&serde_json::Value::Null).expect("unknown"),
                None
            );
            assert_eq!(
                azure_directional_bytes(&serde_json::json!(0)).expect("zero"),
                Some(0)
            );
            assert!(azure_directional_bytes(&serde_json::json!(-1)).is_err());
        }

        #[test]
        fn azure_origins_scope_and_query_are_fixed() {
            assert_eq!(FLOW_INGESTION_DELAY_MINUTES, 30);
            let subscription = "11111111-2222-3333-4444-555555555555";
            let network = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/tally-rg/providers/Microsoft.Network/virtualNetworks/tally-vnet";
            let workspace = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/tally-rg/providers/Microsoft.OperationalInsights/workspaces/tally-logs";
            assert!(validate_azure_scope(subscription, network, "eastus2").is_ok());
            assert!(validate_azure_workspace_id(workspace, subscription).is_ok());
            assert!(
                validate_azure_scope(subscription, "https://example.com/vnet", "eastus2").is_err()
            );

            let start = "2026-08-13T10:00:00Z".parse().expect("start");
            let end = "2026-08-13T10:05:00Z".parse().expect("end");
            let query = azure_flow_query(network, start, end).expect("query");
            assert!(query.starts_with("NTANetAnalytics\n"));
            assert!(query.contains("TargetResourceType =~ \"VirtualNetwork\""));
            assert!(query.contains("11111111-2222-3333-4444-555555555555/tally-rg/tally-vnet"));
            assert!(query.contains("DestPublicIps"));
            assert!(query.contains("Action=FlowStatus"));
            assert!(query.ends_with("take 10001"));

            let logs =
                azure_logs_query_url("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("logs URL");
            assert_eq!(logs.host_str(), Some("api.loganalytics.azure.com"));
            let nics = azure_network_interfaces_url(subscription).expect("NIC URL");
            assert_eq!(nics.host_str(), Some("management.azure.com"));
            assert!(
                nics.query()
                    .is_some_and(|query| query.contains("2025-05-01"))
            );
            assert!(azure_vmss_instance_id(
                "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/workload-rg/providers/Microsoft.Compute/virtualMachineScaleSets/ai-workers/virtualMachines/3",
                subscription
            ));
            assert!(!azure_vmss_instance_id(
                "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/workload-rg/providers/Microsoft.Compute/virtualMachineScaleSets/ai-workers/virtualMachines/3",
                subscription
            ));
        }

        #[test]
        fn azure_log_projection_is_strict_and_minimal() {
            let network = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/tally-rg/providers/Microsoft.Network/virtualNetworks/tally-vnet";
            let workspace = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
            let table: AzureLogsTable = serde_json::from_value(serde_json::json!({
                "name": "PrimaryResult",
                "columns": [
                    {"name":"FlowStartTime","type":"datetime"},
                    {"name":"FlowEndTime","type":"datetime"},
                    {"name":"SrcIp","type":"string"},
                    {"name":"DestIp","type":"string"},
                    {"name":"SrcPorts","type":"string"},
                    {"name":"DestPort","type":"int"},
                    {"name":"L4Protocol","type":"string"},
                    {"name":"PacketsSrcToDest","type":"long"},
                    {"name":"PacketsDestToSrc","type":"long"},
                    {"name":"BytesSrcToDest","type":"long"},
                    {"name":"BytesDestToSrc","type":"long"},
                    {"name":"FlowDirection","type":"string"},
                    {"name":"Action","type":"string"},
                    {"name":"TargetResourceId","type":"string"},
                    {"name":"TargetResourceType","type":"string"},
                    {"name":"SubType","type":"string"},
                    {"name":"TenantId","type":"string"},
                    {"name":"SrcVm","type":"string"},
                    {"name":"DestVm","type":"string"},
                    {"name":"DestServiceTags","type":"string"}
                ],
                "rows": [[
                    "2026-08-13T10:00:00Z", "2026-08-13T10:05:00Z",
                    "10.0.0.4", "20.232.91.78", "", 443, "TCP",
                    2, 3, 128, 256, "Outbound", "Allowed",
                    "11111111-2222-3333-4444-555555555555/tally-rg/tally-vnet",
                    "VirtualNetwork", "FlowLog", workspace,
                    "tally-rg/tally-vm-1", "",
                    "Storage.EastUS-20.209.75.97 | CognitiveServicesManagement-20.232.91.78"
                ]],
                "statistics": {"CONTENT_CANARY": "person@example.com"}
            }))
            .expect("table");
            let records = table.minimal_flows(network, workspace).expect("flows");
            let serialized = serde_json::to_string(&records).expect("serialized flow");
            assert_eq!(records.len(), 1);
            assert!(!serialized.contains("CONTENT_CANARY"));
            assert!(!serialized.contains("person@example.com"));
            assert!(!serialized.contains("source_port"));
            assert!(serialized.contains("\"source_hostname\":\"tally-vm-1\""));
            assert!(serialized.contains("\"destination_hostname\":\"openai.azure.com\""));
            assert!(serialized.contains("\"packets\":5"));
            assert!(serialized.contains("\"bytes\":128"));
            assert!(serialized.contains("\"bytes_received\":256"));
            assert!(serialized.contains("\"direction\":\"egress\""));
        }

        #[test]
        fn azure_mapping_projection_drops_customer_controlled_fields() {
            let subscription = "11111111-2222-3333-4444-555555555555";
            let network = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/tally-rg/providers/Microsoft.Network/virtualNetworks/tally-vnet";
            let interface: AzureNetworkInterface = serde_json::from_value(serde_json::json!({
            "id": "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/workload-rg/providers/Microsoft.Network/networkInterfaces/nic-1",
            "location": "eastus2",
            "tags": {"owner": "person@example.com", "prompt": "CONTENT_CANARY"},
            "properties": {
                "virtualMachine": {"id": "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/workload-rg/providers/Microsoft.Compute/virtualMachines/vm-1"},
                "dnsSettings": {"internalDnsNameLabel": "CONTENT_CANARY"},
                "ipConfigurations": [{"properties": {
                    "privateIPAddress": "10.0.0.4",
                    "subnet": {"id": "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/tally-rg/providers/Microsoft.Network/virtualNetworks/tally-vnet/subnets/default"},
                    "publicIPAddress": {"properties": {"ipAddress": "203.0.113.8"}}
                }}]
            }
        }))
        .expect("interface");
            let virtual_machine_hostnames = HashMap::from([(
            "/subscriptions/11111111-2222-3333-4444-555555555555/resourcegroups/workload-rg/providers/microsoft.compute/virtualmachines/vm-1".to_owned(),
            "tally-vm-1.internal".to_owned(),
        )]);
            let records = interface
                .minimal_mappings(
                    subscription,
                    network,
                    "eastus2",
                    "2026-08-13T10:00:00Z".parse().expect("from"),
                    "2026-08-13T10:15:00Z".parse().expect("until"),
                    &virtual_machine_hostnames,
                )
                .expect("mappings");
            let serialized = serde_json::to_string(&records).expect("serialized mapping");
            assert_eq!(records.len(), 1);
            assert!(serialized.contains("10.0.0.4"));
            assert!(!serialized.contains("203.0.113.8"));
            assert!(!serialized.contains("CONTENT_CANARY"));
            assert!(!serialized.contains("person@example.com"));
            assert!(serialized.contains("tally-vm-1.internal"));
        }
    }
}
