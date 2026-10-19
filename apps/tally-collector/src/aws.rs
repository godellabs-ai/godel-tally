use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
    time::{Duration as StdDuration, SystemTime},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use aws_credential_types::{Credentials, provider::ProvideCredentials};
use aws_sigv4::{
    http_request::{SignableBody, SignableRequest, SigningSettings, sign},
    sign::v4,
};
use chrono::{DateTime, Duration, Utc};
use reqwest::{Response, header};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tally_connectors::{AwsStaticCredentials, MAX_IMPORT_BYTES};
use tally_core::Hostname;

use crate::{
    VendorAdapter,
    pull_support::{NativeCloudSnapshot, NativeNetworkPull, NativeNetworkSnapshot},
};

const MAX_PROVIDER_PAGES: usize = 100;
const MAX_PROVIDER_RESOURCES: usize = 10_000;
const MAX_PROVIDER_RECORDS: usize = 10_000;
const MAX_PAGE_BYTES: usize = 16 * 1_024 * 1_024;
const FLOW_INGESTION_DELAY_MINUTES: i64 = 5;
const FLOW_OVERLAP_MINUTES: i64 = 5;
const MAPPING_LOOKBACK_MINUTES: i64 = 10;
const MAPPING_FUTURE_MINUTES: i64 = 5;
const AWS_CURSOR_PREFIX: &str = "aws-network-v1:";
const AWS_EC2_API_VERSION: &str = "2016-11-15";
const AWS_DEFAULT_FLOW_FORMAT: &str = "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}";

struct SignedPost<'a> {
    endpoint: &'a str,
    region: &'a str,
    service: &'a str,
    content_type: &'a str,
    signed_headers: &'a [(&'a str, &'a str)],
    body: &'a [u8],
    operation: &'a str,
}

async fn signed_post(
    client: &reqwest::Client,
    shared: &aws_config::SdkConfig,
    post: &SignedPost<'_>,
) -> Result<Response> {
    let provider = shared
        .credentials_provider()
        .ok_or_else(|| anyhow!("AWS credential provider was unavailable"))?;
    let credentials = provider
        .provide_credentials()
        .await
        .map_err(|_| anyhow!("AWS credentials could not be loaded"))?;
    let identity = credentials.into();

    for attempt in 0_u32..3 {
        let signing_parameters = v4::SigningParams::builder()
            .identity(&identity)
            .region(post.region)
            .name(post.service)
            .time(SystemTime::now())
            .settings(SigningSettings::default())
            .build()
            .map_err(|_| anyhow!("{} request could not be signed", post.operation))?
            .into();
        let headers = std::iter::once((header::CONTENT_TYPE.as_str(), post.content_type))
            .chain(post.signed_headers.iter().copied());
        let signable = SignableRequest::new(
            "POST",
            post.endpoint,
            headers,
            SignableBody::Bytes(post.body),
        )
        .map_err(|_| anyhow!("{} request could not be signed", post.operation))?;
        let (instructions, _) = sign(signable, &signing_parameters)
            .map_err(|_| anyhow!("{} request could not be signed", post.operation))?
            .into_parts();
        let mut request = client
            .post(post.endpoint)
            .header(header::CONTENT_TYPE, post.content_type)
            .body(post.body.to_vec());
        for (name, value) in post.signed_headers {
            request = request.header(*name, *value);
        }
        let mut request = request
            .build()
            .map_err(|_| anyhow!("{} request could not be built", post.operation))?;
        for (name, value) in instructions.headers() {
            request.headers_mut().insert(
                header::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| anyhow!("{} signature was invalid", post.operation))?,
                header::HeaderValue::from_str(value)
                    .map_err(|_| anyhow!("{} signature was invalid", post.operation))?,
            );
        }
        let response = match client.execute(request).await {
            Ok(response) => response,
            Err(_) if attempt < 2 => {
                tokio::time::sleep(StdDuration::from_millis(100 * 2_u64.pow(attempt))).await;
                continue;
            }
            Err(_) => bail!("{} request failed", post.operation),
        };
        if attempt < 2
            && (response.status().is_server_error()
                || response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS)
        {
            tokio::time::sleep(StdDuration::from_millis(100 * 2_u64.pow(attempt))).await;
            continue;
        }
        return Ok(response);
    }
    bail!("{} request failed", post.operation)
}

pub(crate) async fn pull_inventory(
    client: &reqwest::Client,
    region: &str,
    static_credentials: Option<&AwsStaticCredentials>,
) -> Result<NativeCloudSnapshot> {
    inventory::pull_aws(client, region, static_credentials).await
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
        request.workspace_resource.is_none(),
        "AWS does not accept an Azure workspace"
    );
    network::pull_aws(request, client).await
}

mod inventory {
    use super::{
        AwsStaticCredentials, Context, Credentials, DateTime, Deserialize, DeserializeOwned,
        Duration, Hostname, MAX_IMPORT_BYTES, MAX_PAGE_BYTES, MAX_PROVIDER_PAGES,
        MAX_PROVIDER_RESOURCES, NativeCloudSnapshot, Response, Result, Serialize, SignedPost,
        StdDuration, Utc, anyhow, bail, ensure, header, signed_post,
    };
    pub(super) async fn pull_aws(
        client: &reqwest::Client,
        region: &str,
        static_credentials: Option<&AwsStaticCredentials>,
    ) -> Result<NativeCloudSnapshot> {
        validate_aws_region(region)?;
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_owned()))
            .retry_config(aws_config::retry::RetryConfig::standard().with_max_attempts(3))
            .timeout_config(
                aws_config::timeout::TimeoutConfig::builder()
                    .connect_timeout(StdDuration::from_secs(10))
                    .operation_timeout(StdDuration::from_secs(30))
                    .build(),
            );
        let shared = match static_credentials {
            Some(credentials) => {
                config
                    .credentials_provider(Credentials::new(
                        credentials.access_key_id.clone(),
                        credentials.secret_access_key.clone(),
                        credentials.session_token.clone(),
                        None,
                        "tally-static-connector-credentials",
                    ))
                    .load()
                    .await
            }
            None => config.load().await,
        };
        let bedrock = aws_sdk_bedrock::Client::from_conf(
            aws_sdk_bedrock::Config::from(&shared)
                .to_builder()
                .endpoint_url(format!("https://bedrock.{region}.amazonaws.com"))
                .build(),
        );
        let agents = aws_sdk_bedrockagent::Client::from_conf(
            aws_sdk_bedrockagent::Config::from(&shared)
                .to_builder()
                .endpoint_url(format!("https://bedrock-agent.{region}.amazonaws.com"))
                .build(),
        );
        let provisioned_models = aws_provisioned_models(&bedrock).await?;
        let agent_summaries = aws_agents(&agents, &bedrock).await?;
        let endpoints = aws_endpoints(client, &shared, region).await?;
        let models = aws_models(client, &shared, region).await?;
        let invocations =
            aws_invocations(client, &shared, region, Utc::now() - Duration::hours(1)).await?;

        let record_count = provisioned_models.len()
            + agent_summaries.len()
            + endpoints.len()
            + models.len()
            + invocations.len();
        enforce_resource_cap(record_count, "AWS managed AI inventory")?;
        serialize_snapshot(
            &AwsEnvelope {
                provisioned_model_throughputs: AwsProvisionedModels { provisioned_models },
                agents: AwsAgents { agent_summaries },
                sagemaker_endpoints: AwsEndpoints { endpoints },
                sagemaker_models: AwsModels { models },
                invocations,
            },
            record_count,
        )
    }

    async fn aws_provisioned_models(
        client: &aws_sdk_bedrock::Client,
    ) -> Result<Vec<AwsProvisionedModel>> {
        let mut models = Vec::new();
        let mut token = None;
        for _ in 0..MAX_PROVIDER_PAGES {
            let output = client
                .list_provisioned_model_throughputs()
                .max_results(1_000)
                .set_next_token(token.take())
                .send()
                .await
                .map_err(|_| anyhow!("AWS Bedrock provisioned inventory request failed"))?;
            models.extend(output.provisioned_model_summaries().iter().map(|summary| {
                AwsProvisionedModel {
                    provisioned_model_arn: summary.provisioned_model_arn().to_owned(),
                    foundation_model_arn: Some(summary.foundation_model_arn().to_owned()),
                    status: summary.status().as_str().to_owned(),
                }
            }));
            enforce_resource_cap(models.len(), "AWS Bedrock inventory")?;
            token = checked_provider_token(output.next_token())?;
            if token.is_none() {
                return Ok(models);
            }
        }
        bail!("AWS Bedrock inventory exceeded the page cap")
    }

    async fn aws_agents(
        client: &aws_sdk_bedrockagent::Client,
        bedrock: &aws_sdk_bedrock::Client,
    ) -> Result<Vec<AwsAgent>> {
        let mut agents = Vec::new();
        let mut token = None;
        for _ in 0..MAX_PROVIDER_PAGES {
            let output = client
                .list_agents()
                .max_results(1_000)
                .set_next_token(token.take())
                .send()
                .await
                .map_err(|_| anyhow!("AWS Bedrock Agent inventory request failed"))?;
            for summary in output.agent_summaries() {
                let agent_id = summary.agent_id().to_owned();
                let detail = client
                    .get_agent()
                    .agent_id(&agent_id)
                    .send()
                    .await
                    .map_err(|_| anyhow!("AWS Bedrock Agent detail request failed"))?;
                let configured_model = detail
                    .agent()
                    .and_then(|agent| agent.foundation_model())
                    .map(str::to_owned);
                let foundation_model = match configured_model {
                    Some(model) if is_aws_inference_profile_reference(&model) => bedrock
                        .get_inference_profile()
                        .inference_profile_identifier(model)
                        .send()
                        .await
                        .map_err(|_| {
                            anyhow!("AWS Bedrock inference profile detail request failed")
                        })?
                        .models()
                        .iter()
                        .filter_map(|model| model.model_arn())
                        .find_map(aws_foundation_model_from_arn)
                        .map(str::to_owned),
                    model => model,
                };
                agents.push(AwsAgent {
                    agent_id,
                    agent_name: summary.agent_name().to_owned(),
                    agent_status: summary.agent_status().as_str().to_owned(),
                    foundation_model,
                });
            }
            enforce_resource_cap(agents.len(), "AWS Agent inventory")?;
            token = checked_provider_token(output.next_token())?;
            if token.is_none() {
                return Ok(agents);
            }
        }
        bail!("AWS Agent inventory exceeded the page cap")
    }

    fn is_aws_inference_profile_reference(value: &str) -> bool {
        value.contains(":inference-profile/")
            || value.contains(":application-inference-profile/")
            || ["us.", "eu.", "apac.", "global."]
                .iter()
                .any(|prefix| value.starts_with(prefix))
            || (!value.contains('.')
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'))
    }

    fn aws_foundation_model_from_arn(value: &str) -> Option<&str> {
        value
            .split_once(":foundation-model/")
            .map(|(_, model)| model)
    }

    async fn aws_endpoints(
        client: &reqwest::Client,
        shared: &aws_config::SdkConfig,
        region: &str,
    ) -> Result<Vec<AwsEndpoint>> {
        let mut endpoints = Vec::new();
        let mut token = None;
        for _ in 0..MAX_PROVIDER_PAGES {
            let output: AwsEndpointPage = aws_sagemaker_list(
                client,
                shared,
                region,
                "SageMaker.ListEndpoints",
                token.take().as_deref(),
                "AWS SageMaker endpoint inventory",
            )
            .await?;
            endpoints.extend(output.endpoints.into_iter().filter_map(|summary| {
                Some(AwsEndpoint {
                    endpoint_arn: summary.endpoint_arn?,
                    endpoint_status: summary.endpoint_status?,
                })
            }));
            enforce_resource_cap(endpoints.len(), "AWS endpoint inventory")?;
            token = checked_provider_token(output.next_token.as_deref())?;
            if token.is_none() {
                return Ok(endpoints);
            }
        }
        bail!("AWS endpoint inventory exceeded the page cap")
    }

    async fn aws_models(
        client: &reqwest::Client,
        shared: &aws_config::SdkConfig,
        region: &str,
    ) -> Result<Vec<AwsModel>> {
        let mut models = Vec::new();
        let mut token = None;
        for _ in 0..MAX_PROVIDER_PAGES {
            let output: AwsModelPage = aws_sagemaker_list(
                client,
                shared,
                region,
                "SageMaker.ListModels",
                token.take().as_deref(),
                "AWS SageMaker model inventory",
            )
            .await?;
            models.extend(output.models.into_iter().filter_map(|summary| {
                Some(AwsModel {
                    model_arn: summary.model_arn?,
                })
            }));
            enforce_resource_cap(models.len(), "AWS model inventory")?;
            token = checked_provider_token(output.next_token.as_deref())?;
            if token.is_none() {
                return Ok(models);
            }
        }
        bail!("AWS model inventory exceeded the page cap")
    }

    async fn aws_sagemaker_list<T: DeserializeOwned>(
        client: &reqwest::Client,
        shared: &aws_config::SdkConfig,
        region: &str,
        target: &str,
        next_token: Option<&str>,
        operation: &str,
    ) -> Result<T> {
        let endpoint = format!("https://api.sagemaker.{region}.amazonaws.com/");
        let body = serde_json::to_vec(&AwsSageMakerListRequest {
            max_results: 100,
            next_token,
        })
        .context("serialize AWS SageMaker inventory request")?;
        let response = signed_post(
            client,
            shared,
            &SignedPost {
                endpoint: &endpoint,
                region,
                service: "sagemaker",
                content_type: "application/x-amz-json-1.1",
                signed_headers: &[("x-amz-target", target)],
                body: &body,
                operation,
            },
        )
        .await?;
        bounded_json(response, operation).await
    }

    async fn aws_invocations(
        client: &reqwest::Client,
        shared: &aws_config::SdkConfig,
        region: &str,
        window_start: DateTime<Utc>,
    ) -> Result<Vec<AwsInvocation>> {
        let mut invocations = Vec::new();
        for event_name in ["InvokeModel", "Converse"] {
            let mut next_token = None;
            let mut exhausted = false;
            for _ in 0..MAX_PROVIDER_PAGES {
                let endpoint = format!("https://cloudtrail.{region}.amazonaws.com/");
                let body = serde_json::to_vec(&AwsLookupEventsRequest {
                    lookup_attributes: [AwsLookupAttribute {
                        attribute_key: "EventName",
                        attribute_value: event_name,
                    }],
                    start_time: window_start.timestamp(),
                    max_results: 50,
                    next_token: next_token.as_deref(),
                })
                .context("serialize AWS CloudTrail lookup")?;
                let response = signed_post(
                    client,
                    shared,
                    &SignedPost {
                        endpoint: &endpoint,
                        region,
                        service: "cloudtrail",
                        content_type: "application/x-amz-json-1.1",
                        signed_headers: &[(
                            "x-amz-target",
                            "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents",
                        )],
                        body: &body,
                        operation: "AWS CloudTrail Bedrock invocation lookup",
                    },
                )
                .await?;
                let page: AwsLookupEventsResponse =
                    bounded_json(response, "AWS CloudTrail Bedrock invocation lookup").await?;
                invocations.extend(
                    page.events
                        .into_iter()
                        .filter_map(|event| event.minimal(region).transpose())
                        .collect::<Result<Vec<_>>>()?,
                );
                enforce_resource_cap(invocations.len(), "AWS Bedrock invocation logs")?;
                next_token = checked_provider_token(page.next_token.as_deref())?;
                if next_token.is_none() {
                    exhausted = true;
                    break;
                }
            }
            ensure!(
                exhausted,
                "AWS CloudTrail Bedrock invocation lookup exceeded the page cap"
            );
        }
        invocations.sort_by(|left, right| left.request_id.cmp(&right.request_id));
        invocations.dedup_by(|left, right| left.request_id == right.request_id);
        Ok(invocations)
    }

    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct AwsLookupEventsRequest<'a> {
        lookup_attributes: [AwsLookupAttribute<'a>; 1],
        start_time: i64,
        max_results: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        next_token: Option<&'a str>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct AwsLookupAttribute<'a> {
        attribute_key: &'static str,
        attribute_value: &'a str,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct AwsLookupEventsResponse {
        #[serde(default)]
        events: Vec<AwsLookupEvent>,
        #[serde(default)]
        next_token: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct AwsLookupEvent {
        cloud_trail_event: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AwsCloudTrailEvent {
        #[serde(rename = "eventID")]
        event_id: String,
        event_time: DateTime<Utc>,
        event_source: String,
        event_name: String,
        #[serde(rename = "sourceIPAddress")]
        source_ip_address: String,
        #[serde(default)]
        error_code: Option<String>,
        #[serde(default)]
        request_parameters: Option<AwsBedrockRequestParameters>,
        #[serde(default)]
        tls_details: Option<AwsTlsDetails>,
        user_identity: AwsCloudTrailIdentity,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AwsTlsDetails {
        #[serde(default)]
        client_provided_host_header: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AwsBedrockRequestParameters {
        model_id: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AwsCloudTrailIdentity {
        #[serde(default)]
        arn: Option<String>,
        #[serde(default)]
        user_name: Option<String>,
        #[serde(default)]
        #[serde(rename = "principalId")]
        principal_id: Option<String>,
    }

    impl AwsLookupEvent {
        fn minimal(self, region: &str) -> Result<Option<AwsInvocation>> {
            let event: AwsCloudTrailEvent = serde_json::from_str(&self.cloud_trail_event)
                .context("AWS CloudTrail event shape changed")?;
            if event.event_source != "bedrock.amazonaws.com"
                || !matches!(event.event_name.as_str(), "InvokeModel" | "Converse")
            {
                return Ok(None);
            }
            let destination_host = event
                .tls_details
                .and_then(|details| details.client_provided_host_header)
                .and_then(|value| {
                    Hostname::parse(&value)
                        .ok()
                        .map(|hostname| hostname.as_str().to_owned())
                })
                .unwrap_or_else(|| format!("bedrock-runtime.{region}.amazonaws.com"));
            Ok(Some(AwsInvocation {
                request_id: event.event_id,
                service: "bedrock",
                model_id: event
                    .request_parameters
                    .map(|parameters| parameters.model_id),
                principal: event
                    .user_identity
                    .arn
                    .or(event.user_identity.user_name)
                    .or(event.user_identity.principal_id),
                source_ip: Some(event.source_ip_address),
                destination_host,
                observed_at: event.event_time,
                result: if event.error_code.is_some() {
                    "failure"
                } else {
                    "success"
                },
            }))
        }
    }

    fn validate_aws_region(region: &str) -> Result<()> {
        ensure!(
            region.len() <= 32
                && (region.starts_with("af-")
                    || region.starts_with("ap-")
                    || region.starts_with("ca-")
                    || region.starts_with("eu-")
                    || region.starts_with("il-")
                    || region.starts_with("me-")
                    || region.starts_with("mx-")
                    || region.starts_with("sa-")
                    || region.starts_with("us-"))
                && region
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
            "AWS commercial region is invalid"
        );
        Ok(())
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

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct AwsEnvelope {
        provisioned_model_throughputs: AwsProvisionedModels,
        agents: AwsAgents,
        sagemaker_endpoints: AwsEndpoints,
        sagemaker_models: AwsModels,
        invocations: Vec<AwsInvocation>,
    }

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct AwsInvocation {
        request_id: String,
        service: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        model_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        principal: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        source_ip: Option<String>,
        destination_host: String,
        observed_at: DateTime<Utc>,
        result: &'static str,
    }

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct AwsProvisionedModels {
        #[serde(rename = "provisionedModelSummaries")]
        provisioned_models: Vec<AwsProvisionedModel>,
    }

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct AwsProvisionedModel {
        provisioned_model_arn: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        foundation_model_arn: Option<String>,
        status: String,
    }

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct AwsAgents {
        agent_summaries: Vec<AwsAgent>,
    }

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct AwsAgent {
        agent_id: String,
        agent_name: String,
        agent_status: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        foundation_model: Option<String>,
    }

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct AwsSageMakerListRequest<'a> {
        max_results: i32,
        #[serde(skip_serializing_if = "Option::is_none")]
        next_token: Option<&'a str>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct AwsEndpointPage {
        #[serde(default)]
        endpoints: Vec<AwsEndpointSummary>,
        next_token: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct AwsEndpointSummary {
        endpoint_arn: Option<String>,
        endpoint_status: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct AwsModelPage {
        #[serde(default)]
        models: Vec<AwsModelSummary>,
        next_token: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct AwsModelSummary {
        model_arn: Option<String>,
    }

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct AwsEndpoints {
        endpoints: Vec<AwsEndpoint>,
    }

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct AwsEndpoint {
        endpoint_arn: String,
        endpoint_status: String,
    }

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct AwsModels {
        models: Vec<AwsModel>,
    }

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct AwsModel {
        model_arn: String,
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn aws_agent_model_references_distinguish_models_and_profiles() {
            assert!(!is_aws_inference_profile_reference(
                "anthropic.claude-3-sonnet-20240229-v1:0"
            ));
            assert!(is_aws_inference_profile_reference(
                "us.anthropic.claude-3-sonnet-20240229-v1:0"
            ));
            assert!(is_aws_inference_profile_reference(
                "arn:aws:bedrock:us-east-1:111122223333:application-inference-profile/profile-id"
            ));
            assert_eq!(
                aws_foundation_model_from_arn(
                    "arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-3-sonnet-20240229-v1:0"
                ),
                Some("anthropic.claude-3-sonnet-20240229-v1:0")
            );
        }

        #[test]
        fn sagemaker_json_contract_is_minimal_and_pascal_case() {
            let request = serde_json::to_string(&AwsSageMakerListRequest {
                max_results: 100,
                next_token: Some("opaque-token"),
            })
            .expect("request");
            assert_eq!(request, r#"{"MaxResults":100,"NextToken":"opaque-token"}"#);

            let page: AwsEndpointPage = serde_json::from_str(
            r#"{"Endpoints":[{"EndpointArn":"arn:aws:sagemaker:us-east-1:111122223333:endpoint/tally","EndpointStatus":"InService","EndpointName":"CONTENT_CANARY"}],"NextToken":"next","CustomerControlled":"CONTENT_CANARY"}"#,
        )
        .expect("response");
            assert_eq!(page.endpoints.len(), 1);
            assert_eq!(
                page.endpoints[0].endpoint_status.as_deref(),
                Some("InService")
            );
            assert_eq!(page.next_token.as_deref(), Some("next"));
        }

        #[test]
        fn bedrock_cloudtrail_projection_keeps_attribution_and_drops_content() {
            let event = AwsLookupEvent {
                cloud_trail_event: serde_json::json!({
                    "eventID": "event-1",
                    "eventTime": "2026-09-04T16:22:28Z",
                    "eventSource": "bedrock.amazonaws.com",
                    "eventName": "InvokeModel",
                    "sourceIPAddress": "203.0.113.10",
                    "requestParameters": {
                        "modelId": "amazon.nova-micro-v1:0",
                        "body": "PROMPT_CANARY"
                    },
                    "userIdentity": {
                        "arn": "arn:aws:iam::111122223333:user/person",
                        "accessKeyId": "SECRET_ACCESS_KEY_CANARY"
                    },
                    "responseElements": {"body": "RESPONSE_CANARY"}
                })
                .to_string(),
            };
            let invocation = event
                .minimal("us-east-1")
                .expect("safe projection")
                .expect("successful invocation");
            let serialized = serde_json::to_string(&invocation).expect("serialized projection");
            assert!(serialized.contains("amazon.nova-micro-v1:0"));
            assert!(serialized.contains("203.0.113.10"));
            assert!(serialized.contains("arn:aws:iam::111122223333:user/person"));
            for discarded in [
                "PROMPT_CANARY",
                "RESPONSE_CANARY",
                "SECRET_ACCESS_KEY_CANARY",
            ] {
                assert!(!serialized.contains(discarded));
            }
            assert!(serialized.contains("\"result\":\"success\""));

            let denied = AwsLookupEvent {
                cloud_trail_event: serde_json::json!({
                    "eventID": "event-2",
                    "eventTime": "2026-09-04T16:23:28Z",
                    "eventSource": "bedrock.amazonaws.com",
                    "eventName": "Converse",
                    "sourceIPAddress": "203.0.113.10",
                    "errorCode": "ValidationException",
                    "errorMessage": "CONTENT_CANARY",
                    "requestParameters": null,
                    "tlsDetails": {
                        "clientProvidedHostHeader": "vpce-0123456789abcdef0-test.us-east-1a.bedrock-runtime.us-east-1.vpce.amazonaws.com",
                        "cipherSuite": "TLS_AES_128_GCM_SHA256"
                    },
                    "userIdentity": {"principalId": "principal-1"}
                })
                .to_string(),
            };
            let denied = denied
                .minimal("us-east-1")
                .expect("safe denied projection")
                .expect("denied invocation attempt");
            let serialized = serde_json::to_string(&denied).expect("serialized denied attempt");
            assert!(serialized.contains("\"result\":\"failure\""));
            assert!(serialized.contains("vpce-0123456789abcdef0-test.us-east-1a.bedrock-runtime.us-east-1.vpce.amazonaws.com"));
            assert!(!serialized.contains("modelId"));
            assert!(!serialized.contains("CONTENT_CANARY"));
            assert!(!serialized.contains("TLS_AES_128_GCM_SHA256"));
        }
    }
}

mod network {
    use super::{
        AWS_CURSOR_PREFIX, AWS_DEFAULT_FLOW_FORMAT, AWS_EC2_API_VERSION, BTreeMap, Context,
        Credentials, DateTime, Deserialize, DeserializeOwned, Duration,
        FLOW_INGESTION_DELAY_MINUTES, FLOW_OVERLAP_MINUTES, HashSet, Hostname, IpAddr,
        MAPPING_FUTURE_MINUTES, MAPPING_LOOKBACK_MINUTES, MAX_IMPORT_BYTES, MAX_PAGE_BYTES,
        MAX_PROVIDER_PAGES, MAX_PROVIDER_RECORDS, NativeNetworkPull, NativeNetworkSnapshot,
        Response, Result, Serialize, SignedPost, StdDuration, Utc, VendorAdapter, anyhow, bail,
        ensure, header, signed_post,
    };
    pub(super) async fn pull_aws(
        request: &NativeNetworkPull<'_>,
        client: &reqwest::Client,
    ) -> Result<NativeNetworkSnapshot> {
        validate_aws_scope(request.account_id, request.network_id, request.region)?;
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(request.region.to_owned()))
            .retry_config(aws_config::retry::RetryConfig::standard().with_max_attempts(3))
            .timeout_config(
                aws_config::timeout::TimeoutConfig::builder()
                    .connect_timeout(StdDuration::from_secs(10))
                    .operation_timeout(StdDuration::from_secs(30))
                    .build(),
            );
        let shared = if let Some(credentials) = request.credentials.aws.as_ref() {
            config
                .credentials_provider(Credentials::new(
                    credentials.access_key_id.clone(),
                    credentials.secret_access_key.clone(),
                    credentials.session_token.clone(),
                    None,
                    "tally-static-network-connector-credentials",
                ))
                .load()
                .await
        } else {
            config.load().await
        };
        verify_aws_account(&shared, request.account_id, request.region).await?;
        match request.adapter {
            VendorAdapter::AwsCloudFlowApi => {
                let log_group = request
                    .log_group
                    .ok_or_else(|| anyhow!("AWS flow-log group is required"))?;
                validate_aws_log_group(log_group)?;
                verify_aws_flow_log(
                    client,
                    &shared,
                    request.region,
                    request.network_id,
                    log_group,
                )
                .await?;
                let logs = aws_sdk_cloudwatchlogs::Client::from_conf(
                    aws_sdk_cloudwatchlogs::Config::from(&shared)
                        .to_builder()
                        .endpoint_url(format!("https://logs.{}.amazonaws.com", request.region))
                        .build(),
                );
                pull_aws_flows(&logs, request, log_group).await
            }
            VendorAdapter::AwsNetworkMappingApi => {
                ensure!(
                    request.log_group.is_none(),
                    "AWS mapping does not accept a log group"
                );
                pull_aws_mappings(
                    client,
                    &shared,
                    request.account_id,
                    request.network_id,
                    request.region,
                    request.now,
                )
                .await
            }
            _ => bail!("AWS network adapter is unsupported"),
        }
    }

    async fn verify_aws_account(
        shared: &aws_config::SdkConfig,
        account_id: &str,
        region: &str,
    ) -> Result<()> {
        let client = aws_sdk_sts::Client::from_conf(
            aws_sdk_sts::Config::from(shared)
                .to_builder()
                .endpoint_url(format!("https://sts.{region}.amazonaws.com"))
                .build(),
        );
        let output = client
            .get_caller_identity()
            .send()
            .await
            .map_err(|_| anyhow!("AWS caller-identity request failed"))?;
        ensure!(
            output.account() == Some(account_id),
            "AWS credential account did not match the configured account"
        );
        Ok(())
    }

    async fn aws_ec2_query<T: DeserializeOwned>(
        client: &reqwest::Client,
        shared: &aws_config::SdkConfig,
        region: &str,
        parameters: &[(&str, &str)],
        operation: &str,
    ) -> Result<T> {
        let endpoint = format!("https://ec2.{region}.amazonaws.com/");
        // `Serializer` contains a non-Sync callback reference in older `url` releases. Keep it in
        // a non-async scope so an embedding worker can require this future to be `Send`.
        let body = {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for (name, value) in parameters {
                serializer.append_pair(name, value);
            }
            serializer.finish()
        };
        let content_type = "application/x-www-form-urlencoded; charset=utf-8";
        let response = signed_post(
            client,
            shared,
            &SignedPost {
                endpoint: &endpoint,
                region,
                service: "ec2",
                content_type,
                signed_headers: &[],
                body: body.as_bytes(),
                operation,
            },
        )
        .await?;
        bounded_xml(response, operation).await
    }

    async fn verify_aws_flow_log(
        client: &reqwest::Client,
        shared: &aws_config::SdkConfig,
        region: &str,
        network_id: &str,
        log_group: &str,
    ) -> Result<()> {
        let output: AwsDescribeFlowLogsResponse = aws_ec2_query(
            client,
            shared,
            region,
            &[
                ("Action", "DescribeFlowLogs"),
                ("Version", AWS_EC2_API_VERSION),
                ("Filter.1.Name", "log-group-name"),
                ("Filter.1.Value.1", log_group),
                ("Filter.2.Name", "log-destination-type"),
                ("Filter.2.Value.1", "cloud-watch-logs"),
                ("MaxResults", "1000"),
            ],
            "AWS VPC flow-log configuration",
        )
        .await?;
        ensure!(
            output.next_token.is_none(),
            "AWS VPC flow-log configuration was ambiguous"
        );
        let flow_logs = output.flow_log_set.items;
        let valid = !flow_logs.is_empty()
            && flow_logs.iter().all(|flow_log| {
                flow_log.resource_id.as_deref() == Some(network_id)
                    && flow_log.log_group_name.as_deref() == Some(log_group)
                    && flow_log.log_destination_type.as_deref() == Some("cloud-watch-logs")
                    && flow_log.flow_log_status.as_deref() == Some("ACTIVE")
                    && flow_log.deliver_logs_status.as_deref() == Some("SUCCESS")
                    && flow_log.log_format.as_deref() == Some(AWS_DEFAULT_FLOW_FORMAT)
            });
        ensure!(
            valid,
            "AWS requires a dedicated active, healthy VPC-level CloudWatch log group in the default v2 format"
        );
        Ok(())
    }

    #[derive(Debug, Deserialize)]
    struct AwsDescribeFlowLogsResponse {
        #[serde(rename = "flowLogSet", default)]
        flow_log_set: AwsFlowLogSet,
        #[serde(rename = "nextToken")]
        next_token: Option<String>,
    }

    #[derive(Debug, Default, Deserialize)]
    struct AwsFlowLogSet {
        #[serde(rename = "item", default)]
        items: Vec<AwsFlowLog>,
    }

    #[derive(Debug, Deserialize)]
    struct AwsFlowLog {
        #[serde(rename = "resourceId")]
        resource_id: Option<String>,
        #[serde(rename = "logGroupName")]
        log_group_name: Option<String>,
        #[serde(rename = "logDestinationType")]
        log_destination_type: Option<String>,
        #[serde(rename = "flowLogStatus")]
        flow_log_status: Option<String>,
        #[serde(rename = "deliverLogsStatus")]
        deliver_logs_status: Option<String>,
        #[serde(rename = "logFormat")]
        log_format: Option<String>,
    }

    async fn pull_aws_flows(
        client: &aws_sdk_cloudwatchlogs::Client,
        request: &NativeNetworkPull<'_>,
        log_group: &str,
    ) -> Result<NativeNetworkSnapshot> {
        let end = request.now - Duration::minutes(FLOW_INGESTION_DELAY_MINUTES);
        let start = if request.cursor_before.is_empty() {
            end - Duration::seconds(i64::from(request.initial_lookback_seconds))
        } else {
            parse_cursor(request.cursor_before, AWS_CURSOR_PREFIX, "AWS")?
                - Duration::minutes(FLOW_OVERLAP_MINUTES)
        };
        let cursor_after = format!("{AWS_CURSOR_PREFIX}{}", end.timestamp_millis());
        if start >= end {
            return serialize_snapshot(
                &FlowEnvelope {
                    provider: "aws",
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

        let mut records = Vec::new();
        let mut ignored_records = 0_u64;
        let mut page_token = None;
        let mut seen_tokens = HashSet::new();
        let mut exhausted = false;
        for _ in 0..MAX_PROVIDER_PAGES {
            let output = client
                .filter_log_events()
                .log_group_name(log_group)
                .start_time(start.timestamp_millis())
                .end_time(end.timestamp_millis())
                .limit(10_000)
                .unmask(false)
                .set_next_token(page_token.take())
                .send()
                .await
                .map_err(|_| anyhow!("AWS VPC flow-log request failed"))?;
            for event in output.events() {
                let message = event
                    .message()
                    .ok_or_else(|| anyhow!("AWS VPC flow-log event had no message"))?;
                match parse_aws_flow_line(message, request.account_id)? {
                    Some(record) => records.push(record),
                    None => ignored_records = ignored_records.saturating_add(1),
                }
                let total = records
                    .len()
                    .saturating_add(usize::try_from(ignored_records).unwrap_or(usize::MAX));
                enforce_record_cap(total, "AWS VPC flow-log")?;
            }
            page_token = checked_page_token(output.next_token(), &mut seen_tokens)?;
            if page_token.is_none() {
                exhausted = true;
                break;
            }
        }
        ensure!(exhausted, "AWS VPC flow-log exceeded the page cap");
        let count = records
            .len()
            .saturating_add(usize::try_from(ignored_records).unwrap_or(usize::MAX));
        serialize_snapshot(
            &FlowEnvelope {
                provider: "aws",
                account_id: request.account_id,
                region: request.region,
                network_id: request.network_id,
                ignored_records,
                records,
            },
            count,
            cursor_after,
        )
    }

    fn parse_aws_flow_line(message: &str, account_id: &str) -> Result<Option<FlowRecord>> {
        ensure!(
            !message.is_empty() && message.len() <= 4_096 && !message.chars().any(char::is_control),
            "AWS VPC flow-log line was unsafe"
        );
        let fields = message.split_whitespace().collect::<Vec<_>>();
        ensure!(fields.len() == 14, "AWS VPC flow-log was not default v2");
        ensure!(fields[0] == "2", "AWS VPC flow-log version was unsupported");
        match fields[13] {
            "NODATA" | "SKIPDATA" => return Ok(None),
            "OK" => {}
            _ => bail!("AWS VPC flow-log status was unsupported"),
        }
        ensure!(
            fields[1] == account_id || fields[1] == "unknown",
            "AWS VPC flow-log escaped the configured account"
        );
        ensure!(
            fields[2] == "-" || valid_aws_id(fields[2], "eni-"),
            "AWS VPC flow-log interface ID was invalid"
        );
        let source_ip = fields[3]
            .parse::<IpAddr>()
            .map_err(|_| anyhow!("AWS VPC flow source address was invalid"))?;
        let destination_ip = fields[4]
            .parse::<IpAddr>()
            .map_err(|_| anyhow!("AWS VPC flow destination address was invalid"))?;
        let source_port = aws_port(fields[5])?;
        let destination_port = aws_port(fields[6])?;
        let protocol = match fields[7]
            .parse::<u16>()
            .map_err(|_| anyhow!("AWS VPC flow protocol was invalid"))?
        {
            6 => "tcp",
            17 => "udp",
            1 | 58 => "icmp",
            _ => "other",
        };
        let packets = positive_aws_counter(fields[8], "packets")?;
        let bytes = fields[9]
            .parse::<u64>()
            .context("AWS VPC flow byte counter was invalid")?;
        let window_start = aws_epoch(fields[10], "start")?;
        let window_end = aws_epoch(fields[11], "end")?;
        ensure!(
            window_start <= window_end,
            "AWS VPC flow window was invalid"
        );
        let decision = match fields[12] {
            "ACCEPT" => "accepted",
            "REJECT" => "rejected",
            _ => bail!("AWS VPC flow action was unsupported"),
        };
        Ok(Some(FlowRecord {
            window_start,
            window_end,
            source_ip: source_ip.to_string(),
            destination_ip: destination_ip.to_string(),
            source_hostname: None,
            destination_hostname: None,
            source_port,
            destination_port,
            protocol,
            packets: Some(packets),
            bytes: Some(bytes),
            direction: "unknown",
            decision,
        }))
    }

    fn aws_port(value: &str) -> Result<Option<u16>> {
        if value == "-" {
            return Ok(None);
        }
        value
            .parse::<u16>()
            .map(Some)
            .map_err(|_| anyhow!("AWS VPC flow port was invalid"))
    }

    fn positive_aws_counter(value: &str, field: &str) -> Result<u64> {
        let counter = value
            .parse::<u64>()
            .map_err(|_| anyhow!("AWS VPC flow {field} counter was invalid"))?;
        ensure!(counter > 0, "AWS VPC flow {field} counter was invalid");
        Ok(counter)
    }

    fn aws_epoch(value: &str, field: &str) -> Result<DateTime<Utc>> {
        let seconds = value
            .parse::<i64>()
            .map_err(|_| anyhow!("AWS VPC flow {field} time was invalid"))?;
        DateTime::from_timestamp(seconds, 0)
            .ok_or_else(|| anyhow!("AWS VPC flow {field} time was invalid"))
    }

    async fn pull_aws_mappings(
        client: &reqwest::Client,
        shared: &aws_config::SdkConfig,
        account_id: &str,
        network_id: &str,
        region: &str,
        now: DateTime<Utc>,
    ) -> Result<NativeNetworkSnapshot> {
        let valid_from = now - Duration::minutes(MAPPING_LOOKBACK_MINUTES);
        let valid_until = now + Duration::minutes(MAPPING_FUTURE_MINUTES);
        let mut records = Vec::new();
        let mut page_token = None;
        let mut seen_tokens = HashSet::new();
        let mut exhausted = false;
        for _ in 0..MAX_PROVIDER_PAGES {
            let mut parameters = vec![
                ("Action", "DescribeNetworkInterfaces"),
                ("Version", AWS_EC2_API_VERSION),
                ("Filter.1.Name", "vpc-id"),
                ("Filter.1.Value.1", network_id),
                ("IncludeManagedResources", "true"),
                ("MaxResults", "1000"),
            ];
            let token = page_token.take();
            if let Some(token) = token.as_deref() {
                parameters.push(("NextToken", token));
            }
            let output: AwsDescribeNetworkInterfacesResponse =
                aws_ec2_query(client, shared, region, &parameters, "AWS network mapping").await?;
            for interface in &output.network_interface_set.items {
                records.extend(aws_interface_mappings(
                    interface,
                    account_id,
                    network_id,
                    region,
                    valid_from,
                    valid_until,
                )?);
                enforce_record_cap(records.len(), "AWS network mapping")?;
            }
            page_token = checked_page_token(output.next_token.as_deref(), &mut seen_tokens)?;
            if page_token.is_none() {
                exhausted = true;
                break;
            }
        }
        ensure!(exhausted, "AWS network mapping exceeded the page cap");
        let count = records.len();
        serialize_snapshot(
            &MappingEnvelope {
                provider: "aws",
                account_id,
                region,
                network_id,
                records,
            },
            count,
            format!("{AWS_CURSOR_PREFIX}{}", now.timestamp_millis()),
        )
    }

    fn aws_interface_mappings(
        interface: &AwsNetworkInterface,
        account_id: &str,
        network_id: &str,
        region: &str,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<Vec<MappingRecord>> {
        ensure!(
            interface.vpc_id.as_deref() == Some(network_id),
            "AWS network interface escaped the configured VPC"
        );
        let interface_id = interface
            .network_interface_id
            .as_deref()
            .ok_or_else(|| anyhow!("AWS network interface had no ID"))?;
        ensure!(
            valid_aws_id(interface_id, "eni-"),
            "AWS network interface ID was invalid"
        );
        let (resource_id, resource_kind) = if let Some(instance_id) = interface
            .attachment
            .as_ref()
            .and_then(|attachment| attachment.instance_id.as_deref())
        {
            ensure!(
                valid_aws_id(instance_id, "i-"),
                "AWS instance ID was invalid"
            );
            (
                format!("arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"),
                "workload",
            )
        } else {
            (
                format!("arn:aws:ec2:{region}:{account_id}:network-interface/{interface_id}"),
                "network_interface",
            )
        };
        let interface_hostname = interface
            .private_dns_name
            .as_deref()
            .and_then(normalized_hostname);
        let mut addresses = BTreeMap::new();
        if let Some(address) = interface.private_ip_address.as_deref() {
            addresses.insert(address.to_owned(), interface_hostname.clone());
        }
        for address in &interface.private_ip_addresses_set.items {
            if let Some(value) = address.private_ip_address.as_deref() {
                addresses.insert(
                    value.to_owned(),
                    address
                        .private_dns_name
                        .as_deref()
                        .and_then(normalized_hostname)
                        .or_else(|| interface_hostname.clone()),
                );
            }
        }
        for address in &interface.ipv6_addresses_set.items {
            if let Some(value) = address.ipv6_address.as_deref() {
                addresses.insert(value.to_owned(), interface_hostname.clone());
            }
        }
        let mut records = Vec::new();
        for (private_ip, hostname) in addresses {
            let address = private_ip
                .parse::<IpAddr>()
                .map_err(|_| anyhow!("AWS network mapping address was invalid"))?;
            if !is_private(address) {
                continue;
            }
            records.push(MappingRecord {
                valid_from,
                valid_until,
                private_ip,
                interface_id: interface_id.to_owned(),
                resource_id: resource_id.clone(),
                resource_kind,
                hostname,
            });
        }
        Ok(records)
    }

    #[derive(Debug, Deserialize)]
    struct AwsDescribeNetworkInterfacesResponse {
        #[serde(rename = "networkInterfaceSet", default)]
        network_interface_set: AwsNetworkInterfaceSet,
        #[serde(rename = "nextToken")]
        next_token: Option<String>,
    }

    #[derive(Debug, Default, Deserialize)]
    struct AwsNetworkInterfaceSet {
        #[serde(rename = "item", default)]
        items: Vec<AwsNetworkInterface>,
    }

    #[derive(Debug, Deserialize)]
    struct AwsNetworkInterface {
        #[serde(rename = "vpcId")]
        vpc_id: Option<String>,
        #[serde(rename = "networkInterfaceId")]
        network_interface_id: Option<String>,
        #[serde(rename = "privateIpAddress")]
        private_ip_address: Option<String>,
        #[serde(rename = "privateDnsName")]
        private_dns_name: Option<String>,
        attachment: Option<AwsNetworkInterfaceAttachment>,
        #[serde(rename = "privateIpAddressesSet", default)]
        private_ip_addresses_set: AwsPrivateIpAddressSet,
        #[serde(rename = "ipv6AddressesSet", default)]
        ipv6_addresses_set: AwsIpv6AddressSet,
    }

    #[derive(Debug, Deserialize)]
    struct AwsNetworkInterfaceAttachment {
        #[serde(rename = "instanceId")]
        instance_id: Option<String>,
    }

    #[derive(Debug, Default, Deserialize)]
    struct AwsPrivateIpAddressSet {
        #[serde(rename = "item", default)]
        items: Vec<AwsPrivateIpAddress>,
    }

    #[derive(Debug, Deserialize)]
    struct AwsPrivateIpAddress {
        #[serde(rename = "privateIpAddress")]
        private_ip_address: Option<String>,
        #[serde(rename = "privateDnsName")]
        private_dns_name: Option<String>,
    }

    #[derive(Debug, Default, Deserialize)]
    struct AwsIpv6AddressSet {
        #[serde(rename = "item", default)]
        items: Vec<AwsIpv6Address>,
    }

    #[derive(Debug, Deserialize)]
    struct AwsIpv6Address {
        #[serde(rename = "ipv6Address")]
        ipv6_address: Option<String>,
    }

    fn validate_aws_scope(account_id: &str, network_id: &str, region: &str) -> Result<()> {
        ensure!(
            account_id.len() == 12 && account_id.bytes().all(|byte| byte.is_ascii_digit()),
            "AWS account ID is invalid"
        );
        ensure!(valid_aws_id(network_id, "vpc-"), "AWS VPC ID is invalid");
        ensure!(
            region.len() <= 32
                && (region.starts_with("af-")
                    || region.starts_with("ap-")
                    || region.starts_with("ca-")
                    || region.starts_with("eu-")
                    || region.starts_with("il-")
                    || region.starts_with("me-")
                    || region.starts_with("mx-")
                    || region.starts_with("sa-")
                    || region.starts_with("us-"))
                && region
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
            "AWS commercial region is invalid"
        );
        Ok(())
    }

    fn valid_aws_id(value: &str, prefix: &str) -> bool {
        value.strip_prefix(prefix).is_some_and(|suffix| {
            (8..=17).contains(&suffix.len())
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    }

    fn validate_aws_log_group(value: &str) -> Result<()> {
        ensure!(
            (1..=512).contains(&value.len())
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/' | b'#')
                }),
            "AWS CloudWatch log-group name is invalid"
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

    async fn bounded_xml<T: DeserializeOwned>(
        mut response: Response,
        operation: &str,
    ) -> Result<T> {
        ensure!(response.status().is_success(), "{operation} request failed");
        let is_xml = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                let value = value.to_ascii_lowercase();
                value.starts_with("application/xml") || value.starts_with("text/xml")
            });
        ensure!(is_xml, "{operation} returned a non-XML response");
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
        quick_xml::de::from_reader(bytes.as_slice())
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
        fn aws_mapping_retains_only_the_valid_private_hostname() {
            let interface = AwsNetworkInterface {
                vpc_id: Some("vpc-12345678".to_owned()),
                network_interface_id: Some("eni-12345678".to_owned()),
                private_ip_address: Some("10.0.0.4".to_owned()),
                private_dns_name: Some("IP-10-0-0-4.EC2.INTERNAL".to_owned()),
                attachment: Some(AwsNetworkInterfaceAttachment {
                    instance_id: Some("i-12345678".to_owned()),
                }),
                private_ip_addresses_set: AwsPrivateIpAddressSet::default(),
                ipv6_addresses_set: AwsIpv6AddressSet::default(),
            };
            let records = aws_interface_mappings(
                &interface,
                "111122223333",
                "vpc-12345678",
                "us-east-1",
                "2026-08-13T10:00:00Z".parse().expect("from"),
                "2026-08-13T10:15:00Z".parse().expect("until"),
            )
            .expect("mappings");
            assert_eq!(records.len(), 1);
            assert_eq!(
                records[0].hostname.as_deref(),
                Some("ip-10-0-0-4.ec2.internal")
            );
        }

        #[test]
        fn aws_ec2_query_xml_decodes_only_required_fields() {
            let flow_logs: AwsDescribeFlowLogsResponse = quick_xml::de::from_str(
                r#"<DescribeFlowLogsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
                <requestId>request-id</requestId>
                <flowLogSet><item>
                    <resourceId>vpc-12345678</resourceId>
                    <logGroupName>/aws/vpc/tally-flow</logGroupName>
                    <logDestinationType>cloud-watch-logs</logDestinationType>
                    <flowLogStatus>ACTIVE</flowLogStatus>
                    <deliverLogsStatus>SUCCESS</deliverLogsStatus>
                    <logFormat>${version} ${account-id}</logFormat>
                    <customerControlled>CONTENT_CANARY</customerControlled>
                </item></flowLogSet>
            </DescribeFlowLogsResponse>"#,
            )
            .expect("flow-log response");
            assert_eq!(flow_logs.flow_log_set.items.len(), 1);
            assert_eq!(
                flow_logs.flow_log_set.items[0].resource_id.as_deref(),
                Some("vpc-12345678")
            );
            assert!(flow_logs.next_token.is_none());

            let interfaces: AwsDescribeNetworkInterfacesResponse = quick_xml::de::from_str(
            r#"<DescribeNetworkInterfacesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
                <requestId>request-id</requestId>
                <networkInterfaceSet><item>
                    <networkInterfaceId>eni-12345678</networkInterfaceId>
                    <vpcId>vpc-12345678</vpcId>
                    <privateIpAddress>10.0.0.4</privateIpAddress>
                    <privateDnsName>ip-10-0-0-4.ec2.internal</privateDnsName>
                    <attachment><instanceId>i-12345678</instanceId></attachment>
                    <privateIpAddressesSet><item>
                        <privateIpAddress>10.0.0.5</privateIpAddress>
                        <privateDnsName>ip-10-0-0-5.ec2.internal</privateDnsName>
                    </item></privateIpAddressesSet>
                    <ipv6AddressesSet><item><ipv6Address>fd00::5</ipv6Address></item></ipv6AddressesSet>
                    <tagSet><item><key>prompt</key><value>CONTENT_CANARY</value></item></tagSet>
                </item></networkInterfaceSet>
                <nextToken>opaque-token</nextToken>
            </DescribeNetworkInterfacesResponse>"#,
        )
        .expect("network-interface response");
            let interface = &interfaces.network_interface_set.items[0];
            assert_eq!(
                interface.network_interface_id.as_deref(),
                Some("eni-12345678")
            );
            assert_eq!(interface.private_ip_addresses_set.items.len(), 1);
            assert_eq!(interface.ipv6_addresses_set.items.len(), 1);
            assert_eq!(interfaces.next_token.as_deref(), Some("opaque-token"));
        }

        #[test]
        fn aws_default_v2_flow_projection_is_strict_and_minimal() {
            let record = parse_aws_flow_line(
            "2 111122223333 eni-12345678 10.0.0.4 10.0.0.8 50000 443 6 2 128 1786615200 1786615260 ACCEPT OK",
            "111122223333",
        )
        .expect("valid line")
        .expect("flow record");
            let serialized = serde_json::to_string(&record).expect("serialized flow");
            assert!(serialized.contains("\"direction\":\"unknown\""));
            assert!(serialized.contains("\"decision\":\"accepted\""));
            assert!(!serialized.contains("eni-12345678"));
            let rejected = parse_aws_flow_line(
                "2 111122223333 eni-12345678 10.0.0.4 10.0.0.8 50000 443 6 2 128 1786615200 1786615260 REJECT OK",
                "111122223333",
            )
            .expect("valid rejected line")
            .expect("rejected flow record");
            assert!(
                serde_json::to_string(&rejected)
                    .expect("serialized rejected flow")
                    .contains("\"decision\":\"rejected\"")
            );
            assert!(
                parse_aws_flow_line(
                    "2 111122223333 eni-12345678 - - - - - - - 1786615200 1786615260 - NODATA",
                    "111122223333",
                )
                .expect("status line")
                .is_none()
            );
            assert!(
            parse_aws_flow_line(
                "2 999999999999 eni-12345678 10.0.0.4 10.0.0.8 50000 443 6 2 128 1786615200 1786615260 ACCEPT OK",
                "111122223333",
            )
            .is_err()
        );
            assert!(
            parse_aws_flow_line(
                "2 unknown - 10.0.0.4 10.0.0.8 50000 443 6 2 128 1786615200 1786615260 ACCEPT OK",
                "111122223333",
            )
            .expect("provider-owned interface")
            .is_some()
        );
        }

        #[test]
        fn aws_scope_and_log_group_validation_are_fail_closed() {
            assert!(validate_aws_scope("111122223333", "vpc-12345678", "us-east-1").is_ok());
            assert!(validate_aws_scope("111122223333", "vpc-unsafe/id", "us-east-1").is_err());
            assert!(validate_aws_scope("111122223333", "vpc-12345678", "cn-north-1").is_err());
            assert!(validate_aws_log_group("/aws/vpc/tally-flow").is_ok());
            assert!(validate_aws_log_group("unsafe group").is_err());
        }
    }
}
