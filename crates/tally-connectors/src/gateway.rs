//! AI gateway connectors: `LiteLLM` proxy and Cloudflare AI Gateway discovery.
//!
//! Gateways are chokepoints: one configured gateway routes to many providers, so a single
//! read-only snapshot maps an estate that endpoint scanning cannot see. Only bounded inventory
//! and identity metadata survives normalization; credentials, prompts, parameters, and source
//! bytes do not.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::IgnoredAny};
use sha2::{Digest, Sha256};
use tally_core::{
    CloudProvider, CloudProviderService, ConnectorRef, DigestAlgorithm, EvidenceReceipt, Hostname,
    IdentityAuthority, IdentityObservation, IdentitySubjectKind, IpAddress, Observation,
    ObservationKind, RequestClientObservation, SaasCapabilityState, SaasSanctionStatus,
};
use url::Url;

use crate::{
    ConnectorDescriptor, ConnectorTransport, ObservationBatch, ReplayCapability,
    VendorImportConfig, VendorImportError, VendorImportOutcome, VendorImportStats,
};

const LITELLM_CONNECTOR_TYPE: &str = "litellm_model_groups_file_v1";
const LITELLM_API_CONNECTOR_TYPE: &str = "litellm_model_groups_api_v1";
const AI_GATEWAY_CONNECTOR_TYPE: &str = "cloudflare_ai_gateway_file_v1";
const AI_GATEWAY_API_CONNECTOR_TYPE: &str = "cloudflare_ai_gateway_api_v1";
const AI_GATEWAY_ENDPOINT_HOST: &str = "gateway.ai.cloudflare.com";

pub const LITELLM_PROJECTION_SCHEMA_VERSION: &str = "litellm_model_groups_projection_v1";
pub const LITELLM_USAGE_PROJECTION_SCHEMA_VERSION: &str = "litellm_gateway_projection_v2";
pub const AI_GATEWAY_PROJECTION_SCHEMA_VERSION: &str = "cloudflare_ai_gateway_projection_v1";

/// The registry service entry proven by an existing Cloudflare AI Gateway.
pub const AI_GATEWAY_REGISTRY_ENTRY: &str = "svc.cloudflare.ai_gateway";

/// Maps a bounded `LiteLLM` provider token to a public registry service entry.
///
/// Unmapped providers are ignored rather than guessed; Tally never invents an AI-system claim
/// from a routing token it cannot tie to verified registry evidence.
#[must_use]
pub fn litellm_registry_entry_for_provider(provider: &str) -> Option<&'static str> {
    match provider {
        "openai" => Some("svc.openai.api"),
        "anthropic" => Some("svc.anthropic.api"),
        "gemini" => Some("svc.google.gemini_api"),
        "cohere" => Some("svc.cohere.api"),
        "deepseek" => Some("svc.deepseek.api"),
        "fireworks_ai" => Some("svc.fireworks.api"),
        "groq" => Some("svc.groq.api"),
        "mistral" | "mistral_ai" => Some("svc.mistral.api"),
        "openrouter" => Some("svc.openrouter.api"),
        "perplexity" => Some("svc.perplexity.api"),
        "replicate" => Some("svc.replicate.api"),
        "together_ai" => Some("svc.together.api"),
        "xai" => Some("svc.xai.api"),
        "ollama" | "ollama_chat" => Some("runtime.ollama"),
        _ => None,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LitellmModelGroupsProjection {
    schema_version: String,
    endpoint_ref: String,
    observed_at: DateTime<Utc>,
    model_groups: Vec<LitellmModelGroupRecord>,
    #[serde(default)]
    usage: Vec<LitellmUsageRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LitellmModelGroupRecord {
    model_group: String,
    providers: Vec<String>,
    #[serde(default, rename = "mode")]
    _mode: Option<IgnoredAny>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LitellmUsageRecord {
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    user_role: Option<tally_core::IdentityRole>,
    request_id: String,
    provider: String,
    #[serde(default)]
    model: Option<String>,
    observed_at: DateTime<Utc>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    requester_ip_address: Option<String>,
    #[serde(default)]
    destination_url: Option<String>,
    #[serde(default)]
    source_hostname: Option<String>,
    #[serde(default)]
    request_client: Option<RequestClientObservation>,
}

#[derive(Serialize)]
struct CanonicalLitellmUsage<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_role: Option<&'a tally_core::IdentityRole>,
    tenant_key: &'a str,
    request_key: &'a str,
    provider_id: &'a str,
    model: Option<&'a str>,
    user: Option<&'a str>,
    requester_ip_address: Option<&'a str>,
    destination_host: Option<&'a str>,
    destination_port: Option<u16>,
    observed_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_hostname: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_client: Option<&'a RequestClientObservation>,
}

#[derive(Serialize)]
struct CanonicalGatewayCapability<'a> {
    tenant_key: &'a str,
    application_key: &'a str,
    registry_entry_id: &'a str,
    capability_state: SaasCapabilityState,
    sanction_status: SaasSanctionStatus,
    observed_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_count: Option<u64>,
}

/// Maps a bounded Cloudflare AI Gateway provider token to a public registry service entry.
#[must_use]
pub fn ai_gateway_registry_entry_for_provider(provider: &str) -> Option<&'static str> {
    match provider {
        "openai" => Some("svc.openai.api"),
        "anthropic" => Some("svc.anthropic.api"),
        "google-ai-studio" => Some("svc.google.gemini_api"),
        "cohere" => Some("svc.cohere.api"),
        "deepseek" => Some("svc.deepseek.api"),
        "fireworks" | "fireworks-ai" => Some("svc.fireworks.api"),
        "groq" => Some("svc.groq.api"),
        "mistral-ai" => Some("svc.mistral.api"),
        "openrouter" => Some("svc.openrouter.api"),
        "perplexity" => Some("svc.perplexity.api"),
        "replicate" => Some("svc.replicate.api"),
        "together-ai" => Some("svc.together.api"),
        "xai" => Some("svc.xai.api"),
        _ => None,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AiGatewayProjection {
    schema_version: String,
    account_ref: String,
    observed_at: DateTime<Utc>,
    gateways: Vec<AiGatewayRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AiGatewayRecord {
    id: String,
    #[serde(default)]
    providers: Vec<AiGatewayProviderRecord>,
    #[serde(default)]
    usage: Vec<AiGatewayUsageRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AiGatewayProviderRecord {
    provider: String,
    request_count: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AiGatewayUsageRecord {
    #[serde(default)]
    request_size: Option<u64>,
    #[serde(default)]
    response_size: Option<u64>,
    id: String,
    provider: String,
    #[serde(default)]
    model: Option<String>,
    observed_at: DateTime<Utc>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
}

#[derive(Serialize)]
struct CanonicalGatewayUsage<'a> {
    tenant_key: &'a str,
    gateway_key: &'a str,
    request_key: &'a str,
    provider_id: &'a str,
    model: Option<&'a str>,
    email: Option<&'a str>,
    user_id: Option<&'a str>,
    hostname: Option<&'a str>,
    observed_at: DateTime<Utc>,
}

pub fn litellm_model_groups_descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor {
        connector_type: LITELLM_CONNECTOR_TYPE.to_owned(),
        display_name: "LiteLLM proxy model groups".to_owned(),
        implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
        source_vendor: "BerriAI".to_owned(),
        source_product: "LiteLLM proxy gateway".to_owned(),
        record_variants: vec![
            "model_group_provider_v1".to_owned(),
            "gateway_request_metadata_v1".to_owned(),
        ],
        transport: ConnectorTransport::File,
        required_permissions: vec![
            "LiteLLM key with read access to GET /model_group/info and GET /spend/logs/v2"
                .to_owned(),
        ],
        requested_fields: vec![
            "full endpoint reference for in-memory pseudonymization only".to_owned(),
            "validated proxy endpoint hostname or address".to_owned(),
            "model group name as the gateway's declared model reference".to_owned(),
            "bounded provider routing tokens".to_owned(),
            "request ID, provider/model, timestamp, assigned user, and requester IP from spend logs"
                .to_owned(),
            "upstream api_base reduced to destination hostname/address and port".to_owned(),
            "explicit source hostname and agent ID; allowlisted client/framework label derived transiently from user-agent metadata".to_owned(),
        ],
        prohibited_fields: vec![
            "api keys, credentials, api_base values, or master keys".to_owned(),
            "model parameters, pricing, token limits, and capability flags".to_owned(),
            "prompts, completions, spend, token counts, or usage content".to_owned(),
            "source response bytes".to_owned(),
            "raw headers, user-agent strings, request tags, and request bodies".to_owned(),
        ],
        cursor_semantics: "immutable model-group snapshot checkpoint".to_owned(),
        replay_capability: ReplayCapability::FileReplay,
        health_capabilities: vec![
            "endpoint reachability".to_owned(),
            "snapshot freshness".to_owned(),
        ],
        coverage_capabilities: vec![
            "LiteLLM gateway tenant boundary".to_owned(),
            "configured provider routing capability".to_owned(),
            "request-level provider/model usage with assigned-user and source-IP attribution"
                .to_owned(),
        ],
        privacy_contract: "The validated proxy endpoint and declared model group are retained for inventory. Spend logs retain only request identity, provider/model, assigned user, requester IP, timestamp, a sanitized upstream host/port, explicit source hostname and agent ID, and an allowlisted client/framework label. Prompts, responses, tokens, cost, keys, raw headers, user-agent strings, request tags, arbitrary metadata, and source bytes are discarded. Client hints are not proof of a discovered agent process.".to_owned(),
    }
}

pub fn litellm_model_groups_api_descriptor() -> ConnectorDescriptor {
    let mut descriptor = litellm_model_groups_descriptor();
    LITELLM_API_CONNECTOR_TYPE.clone_into(&mut descriptor.connector_type);
    "LiteLLM proxy model groups (native pull)".clone_into(&mut descriptor.display_name);
    descriptor.transport = ConnectorTransport::Pull;
    "complete bounded snapshot digest per poll; the source call is a single unpaginated read"
        .clone_into(&mut descriptor.cursor_semantics);
    descriptor.replay_capability = ReplayCapability::DurableCursor;
    descriptor
}

pub fn cloudflare_ai_gateway_descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor {
        connector_type: AI_GATEWAY_CONNECTOR_TYPE.to_owned(),
        display_name: "Cloudflare AI Gateway capabilities".to_owned(),
        implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
        source_vendor: "Cloudflare".to_owned(),
        source_product: "Cloudflare AI Gateway".to_owned(),
        record_variants: vec![
            "ai_gateway_v1".to_owned(),
            "ai_gateway_provider_count_v1".to_owned(),
            "ai_gateway_usage_v1".to_owned(),
        ],
        transport: ConnectorTransport::File,
        required_permissions: vec!["AI Gateway Read".to_owned()],
        requested_fields: vec![
            "account reference for in-memory pseudonymization".to_owned(),
            "gateway identifier for in-memory pseudonymization".to_owned(),
            "bounded provider and model identifiers from the metadata-only log list".to_owned(),
            "request_size and response_size from bounded log details; other detail fields discarded".to_owned(),
            "validated user email, Access subject, and endpoint hostname from explicitly named custom metadata keys".to_owned(),
        ],
        prohibited_fields: vec![
            "prompts, completions, request or response bodies, and log payloads".to_owned(),
            "unselected metadata, costs, token counts, timings, and raw log identifiers".to_owned(),
            "gateway settings, keys, and rate-limit or retry configuration".to_owned(),
            "source response bytes".to_owned(),
        ],
        cursor_semantics: "immutable gateway snapshot checkpoint".to_owned(),
        replay_capability: ReplayCapability::FileReplay,
        health_capabilities: vec![
            "account reachability".to_owned(),
            "snapshot freshness".to_owned(),
        ],
        coverage_capabilities: vec![
            "AI Gateway tenant boundary".to_owned(),
            "provider routing capability with bounded usage counts".to_owned(),
            "model usage with optional user and endpoint attribution".to_owned(),
        ],
        privacy_contract: "Account, gateway, and log identifiers are installation-HMAC pseudonymized; provider/model identifiers and validated email, Access subject, and hostname metadata are retained for findings; prompts, payloads, other metadata, settings, and source bytes are discarded.".to_owned(),
    }
}

pub fn cloudflare_ai_gateway_api_descriptor() -> ConnectorDescriptor {
    let mut descriptor = cloudflare_ai_gateway_descriptor();
    AI_GATEWAY_API_CONNECTOR_TYPE.clone_into(&mut descriptor.connector_type);
    "Cloudflare AI Gateway capabilities (native pull)".clone_into(&mut descriptor.display_name);
    descriptor.transport = ConnectorTransport::Pull;
    "complete bounded snapshot digest; gateway pagination and a bounded metadata-only log window are consumed within each poll"
        .clone_into(&mut descriptor.cursor_semantics);
    descriptor.replay_capability = ReplayCapability::DurableCursor;
    descriptor
}

/// Imports a strict Cloudflare AI Gateway projection and retains only capability metadata.
///
/// # Errors
///
/// Returns [`VendorImportError`] when the projection shape, identifiers, provider tokens, or the
/// admission batch fail closed.
pub fn import_cloudflare_ai_gateway_json(
    input: &[u8],
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    import_ai_gateway_with_type(input, config, AI_GATEWAY_CONNECTOR_TYPE)
}

/// Imports a native Cloudflare AI Gateway pull projection using the native connector identity.
///
/// # Errors
///
/// Returns [`VendorImportError`] under the same fail-closed conditions as
/// [`import_cloudflare_ai_gateway_json`].
pub fn import_cloudflare_ai_gateway_api_json(
    input: &[u8],
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    import_ai_gateway_with_type(input, config, AI_GATEWAY_API_CONNECTOR_TYPE)
}

#[allow(clippy::too_many_lines)] // One pass keeps gateway and usage bounds visibly coupled.
fn import_ai_gateway_with_type(
    input: &[u8],
    config: &VendorImportConfig,
    connector_type: &'static str,
) -> Result<VendorImportOutcome, VendorImportError> {
    validate_input(input)?;
    let projection: AiGatewayProjection =
        serde_json::from_slice(input).map_err(|_| VendorImportError::MalformedRecord { row: 1 })?;
    if projection.schema_version != AI_GATEWAY_PROJECTION_SCHEMA_VERSION {
        return Err(VendorImportError::InvalidField {
            row: 1,
            field: "schema_version",
        });
    }
    validate_identifier(&projection.account_ref, 1, "account_ref")?;
    if projection.gateways.is_empty() {
        return Err(VendorImportError::NoRecords);
    }
    if projection.gateways.len() > crate::MAX_BATCH_OBSERVATIONS {
        return Err(VendorImportError::InvalidField {
            row: 1,
            field: "record_count",
        });
    }
    let tenant_key = config
        .pseudonymization_key
        .pseudonym_exact("ai_gateway_account", &projection.account_ref);
    let mut observations = Vec::new();
    let mut records_read = 0_u64;
    for (index, gateway) in projection.gateways.into_iter().enumerate() {
        let row = index + 1;
        validate_identifier(&gateway.id, row, "gateway_id")?;
        if gateway.providers.len() > 64 || gateway.usage.len() > crate::MAX_BATCH_OBSERVATIONS {
            return Err(VendorImportError::InvalidField {
                row,
                field: "providers",
            });
        }
        // The gateway itself is a capability: this account routes AI traffic through a
        // Cloudflare AI Gateway, independent of which providers were observed.
        records_read = records_read.saturating_add(1);
        let gateway_key = config.pseudonymization_key.pseudonym_exact(
            "ai_gateway",
            &format!("{}:{}", projection.account_ref, gateway.id),
        );
        observations.push(gateway_capability_observation(
            config,
            connector_type,
            &tenant_key,
            gateway_key.clone(),
            AI_GATEWAY_REGISTRY_ENTRY,
            None,
            projection.observed_at,
        )?);
        for provider in &gateway.providers {
            records_read = records_read.saturating_add(1);
            validate_ai_gateway_provider_token(&provider.provider, row)?;
            let registry_entry_id = ai_gateway_registry_entry_for_provider(&provider.provider)
                .map_or_else(
                    || {
                        format!(
                            "discovered.provider.cloudflare-ai-gateway.{}",
                            provider.provider
                        )
                    },
                    str::to_owned,
                );
            let provider_key = config.pseudonymization_key.pseudonym_exact(
                "ai_gateway_provider",
                &format!(
                    "{}:{}:{}",
                    projection.account_ref, gateway.id, provider.provider
                ),
            );
            observations.push(gateway_capability_observation(
                config,
                connector_type,
                &tenant_key,
                provider_key,
                &registry_entry_id,
                Some(provider.request_count),
                projection.observed_at,
            )?);
        }
        for usage in &gateway.usage {
            records_read = records_read.saturating_add(1);
            observations.push(gateway_usage_observation(
                config,
                connector_type,
                &projection.account_ref,
                &tenant_key,
                &gateway.id,
                &gateway_key,
                usage,
                row,
            )?);
        }
    }
    finish_import(
        observations,
        records_read,
        connector_type,
        config,
        vec![
            "raw account and gateway identifiers".to_owned(),
            "unselected custom metadata and malformed optional actor fields".to_owned(),
            "prompts, payloads, costs, tokens, and timings".to_owned(),
            "gateway settings, keys, and source response bytes".to_owned(),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn gateway_usage_observation(
    config: &VendorImportConfig,
    connector_type: &'static str,
    account_ref: &str,
    tenant_key: &str,
    gateway_id: &str,
    gateway_key: &str,
    usage: &AiGatewayUsageRecord,
    row: usize,
) -> Result<Observation, VendorImportError> {
    validate_identifier(&usage.id, row, "usage_id")?;
    validate_ai_gateway_provider_token(&usage.provider, row)?;
    let model = usage
        .model
        .as_deref()
        .map(|value| validate_model_reference(value, row))
        .transpose()?;
    let email = usage
        .email
        .as_deref()
        .map(|value| {
            recognized_email(value).ok_or(VendorImportError::InvalidField {
                row,
                field: "email",
            })
        })
        .transpose()?;
    let user_id = usage
        .user_id
        .as_deref()
        .map(|value| validate_user_id(value, row))
        .transpose()?;
    let hostname = usage
        .hostname
        .as_deref()
        .map(Hostname::parse)
        .transpose()
        .map_err(|_| VendorImportError::InvalidField {
            row,
            field: "hostname",
        })?;
    let request_key = config.pseudonymization_key.pseudonym_exact(
        "ai_gateway_log",
        &format!("{account_ref}:{gateway_id}:{}", usage.id),
    );
    let provider_id = ai_gateway_registry_entry_for_provider(&usage.provider).map_or_else(
        || {
            format!(
                "discovered.provider.cloudflare-ai-gateway.{}",
                usage.provider
            )
        },
        str::to_owned,
    );
    let canonical = CanonicalGatewayUsage {
        tenant_key,
        gateway_key,
        request_key: &request_key,
        provider_id: &provider_id,
        model,
        email: email.as_deref(),
        user_id,
        hostname: hostname.as_ref().map(Hostname::as_str),
        observed_at: usage.observed_at,
    };
    let digest = canonical_digest(&canonical)?;
    let mut observation = base_observation(
        config,
        connector_type,
        ObservationKind::HttpMetadata,
        usage.observed_at,
        &digest,
    );
    observation.saas.tenant_key = Some(tenant_key.to_owned());
    observation.saas.application_key = Some(gateway_key.to_owned());
    observation.service.vendor_application_id = Some(provider_id);
    observation.service.declared_model_id = model.map(str::to_owned);
    observation.service.ai_request = true;
    observation.service.ai_request_evaluated = true;
    observation.destination.host =
        Some(Hostname::parse(AI_GATEWAY_ENDPOINT_HOST).map_err(|_| {
            VendorImportError::InvalidField {
                row,
                field: "gateway_endpoint",
            }
        })?);
    observation.network.request_count = Some(1);
    observation.network.bytes_sent = usage.request_size;
    observation.network.bytes_received = usage.response_size;
    observation.actor.hostname = hostname.map(|value| value.as_str().to_owned());
    let identity_subject = email.as_deref().or(user_id).map(str::to_owned);
    observation.actor.identity = identity_subject.map(|subject| IdentityObservation {
        subject_key: config
            .pseudonymization_key
            .pseudonym_exact("identity", &subject),
        email,
        source_subject: user_id.map(str::to_owned),
        source_subject_kind: user_id.map(|_| IdentitySubjectKind::SourceUserId),
        authority: Some(IdentityAuthority::SourceNative),
        directory_key: None,
        application_key: Some(gateway_key.to_owned()),
        display_label: None,
    });
    observation.outcome.action = Some("request_observed".to_owned());
    Ok(observation)
}

fn validate_model_reference(value: &str, row: usize) -> Result<&str, VendorImportError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(VendorImportError::InvalidField {
            row,
            field: "model",
        });
    }
    Ok(value)
}

fn validate_user_id(value: &str, row: usize) -> Result<&str, VendorImportError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(VendorImportError::InvalidField {
            row,
            field: "user_id",
        });
    }
    Ok(value)
}

fn recognized_email(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    let (local, domain) = value.split_once('@')?;
    if value.len() > 254
        || local.is_empty()
        || local.len() > 64
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
        || domain.contains('@')
        || Hostname::parse(domain).is_err()
    {
        return None;
    }
    Some(value)
}

#[allow(clippy::too_many_arguments)]
fn gateway_capability_observation(
    config: &VendorImportConfig,
    connector_type: &'static str,
    tenant_key: &str,
    application_key: String,
    registry_entry_id: &str,
    request_count: Option<u64>,
    observed_at: DateTime<Utc>,
) -> Result<Observation, VendorImportError> {
    let canonical = CanonicalGatewayCapability {
        tenant_key,
        application_key: &application_key,
        registry_entry_id,
        capability_state: SaasCapabilityState::Enabled,
        sanction_status: SaasSanctionStatus::Unknown,
        observed_at,
        request_count,
    };
    let digest = canonical_digest(&canonical)?;
    let mut observation = base_observation(
        config,
        connector_type,
        ObservationKind::SaasCapability,
        observed_at,
        &digest,
    );
    observation.saas.tenant_key = Some(tenant_key.to_owned());
    observation.saas.application_key = Some(application_key);
    observation.saas.capability_state = Some(SaasCapabilityState::Enabled);
    observation.saas.sanction_status = Some(SaasSanctionStatus::Unknown);
    observation.service.vendor_application_id = Some(registry_entry_id.to_owned());
    observation.network.request_count = request_count;
    observation.outcome.action = Some("capability_enabled".to_owned());
    Ok(observation)
}

fn validate_ai_gateway_provider_token(value: &str, row: usize) -> Result<(), VendorImportError> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
    {
        return Err(VendorImportError::InvalidField {
            row,
            field: "provider",
        });
    }
    Ok(())
}

/// Imports a strict `LiteLLM` model-group projection and retains only capability metadata.
///
/// # Errors
///
/// Returns [`VendorImportError`] when the projection shape, identifiers, provider tokens, or the
/// admission batch fail closed.
pub fn import_litellm_model_groups_json(
    input: &[u8],
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    import_litellm_with_type(input, config, LITELLM_CONNECTOR_TYPE)
}

/// Imports a native `LiteLLM` pull projection using the native connector identity.
///
/// # Errors
///
/// Returns [`VendorImportError`] under the same fail-closed conditions as
/// [`import_litellm_model_groups_json`].
pub fn import_litellm_model_groups_api_json(
    input: &[u8],
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    import_litellm_with_type(input, config, LITELLM_API_CONNECTOR_TYPE)
}

#[allow(clippy::too_many_lines)] // Keeps strict validation and projection in one fail-closed path.
fn import_litellm_with_type(
    input: &[u8],
    config: &VendorImportConfig,
    connector_type: &'static str,
) -> Result<VendorImportOutcome, VendorImportError> {
    validate_input(input)?;
    let projection: LitellmModelGroupsProjection =
        serde_json::from_slice(input).map_err(|_| VendorImportError::MalformedRecord { row: 1 })?;
    if projection.schema_version != LITELLM_PROJECTION_SCHEMA_VERSION
        && projection.schema_version != LITELLM_USAGE_PROJECTION_SCHEMA_VERSION
    {
        return Err(VendorImportError::InvalidField {
            row: 1,
            field: "schema_version",
        });
    }
    if projection.schema_version == LITELLM_PROJECTION_SCHEMA_VERSION
        && !projection.usage.is_empty()
    {
        return Err(VendorImportError::InvalidField {
            row: 1,
            field: "usage",
        });
    }
    validate_identifier(&projection.endpoint_ref, 1, "endpoint_ref")?;
    let endpoint = litellm_endpoint(&projection.endpoint_ref, 1)?;
    if projection.model_groups.is_empty() && projection.usage.is_empty() {
        return Err(VendorImportError::NoRecords);
    }
    if projection
        .model_groups
        .len()
        .saturating_add(projection.usage.len())
        > crate::MAX_BATCH_OBSERVATIONS
    {
        return Err(VendorImportError::InvalidField {
            row: 1,
            field: "record_count",
        });
    }
    let tenant_key = config
        .pseudonymization_key
        .pseudonym_exact("litellm_endpoint", &projection.endpoint_ref);
    let mut observations = Vec::new();
    let mut records_read = 0_u64;
    let model_group_count = projection.model_groups.len();
    for (index, record) in projection.model_groups.into_iter().enumerate() {
        let row = index + 1;
        let model_group = validate_model_reference(&record.model_group, row)?;
        if record.providers.len() > 64 {
            return Err(VendorImportError::InvalidField {
                row,
                field: "providers",
            });
        }
        for provider in &record.providers {
            records_read = records_read.saturating_add(1);
            validate_provider_token(provider, row)?;
            let registry_entry_id = litellm_registry_entry_for_provider(provider).map_or_else(
                || format!("discovered.provider.litellm.{provider}"),
                str::to_owned,
            );
            let application_key = config.pseudonymization_key.pseudonym_exact(
                "litellm_model_group",
                &format!("{}:{}:{provider}", projection.endpoint_ref, model_group),
            );
            let canonical = CanonicalGatewayCapability {
                tenant_key: &tenant_key,
                application_key: &application_key,
                registry_entry_id: &registry_entry_id,
                capability_state: SaasCapabilityState::Enabled,
                sanction_status: SaasSanctionStatus::Unknown,
                observed_at: projection.observed_at,
                request_count: None,
            };
            let digest = canonical_digest(&canonical)?;
            let mut observation = base_observation(
                config,
                connector_type,
                ObservationKind::SaasCapability,
                projection.observed_at,
                &digest,
            );
            observation.saas.tenant_key = Some(tenant_key.clone());
            observation.saas.application_key = Some(application_key);
            observation.saas.capability_state = Some(SaasCapabilityState::Enabled);
            observation.saas.sanction_status = Some(SaasSanctionStatus::Unknown);
            observation.service.vendor_application_id = Some(registry_entry_id);
            observation.service.declared_model_id = Some(model_group.to_owned());
            observation.destination.host.clone_from(&endpoint.hostname);
            observation.destination.ip.clone_from(&endpoint.address);
            observation.destination.port = endpoint.port;
            observation.outcome.action = Some("capability_enabled".to_owned());
            observations.push(observation);
        }
    }
    for (index, usage) in projection.usage.iter().enumerate() {
        let row = model_group_count + index + 1;
        records_read = records_read.saturating_add(1);
        observations.push(litellm_usage_observation(
            config,
            connector_type,
            &tenant_key,
            usage,
            row,
        )?);
    }
    finish_import(
        observations,
        records_read,
        connector_type,
        config,
        vec![
            "raw endpoint references beyond validated host/address and port".to_owned(),
            "credentials, api_base values, model parameters, pricing, and limits".to_owned(),
            "raw headers, user-agent strings, and request tags".to_owned(),
            "prompts, completions, spend, tokens, arbitrary metadata, and source response bytes"
                .to_owned(),
        ],
    )
}

#[allow(clippy::too_many_lines)] // Keep request normalization and its privacy boundary auditable together.
fn litellm_usage_observation(
    config: &VendorImportConfig,
    connector_type: &'static str,
    tenant_key: &str,
    usage: &LitellmUsageRecord,
    row: usize,
) -> Result<Observation, VendorImportError> {
    validate_identifier(&usage.request_id, row, "request_id")?;
    validate_provider_token(&usage.provider, row)?;
    let model = usage
        .model
        .as_deref()
        .map(|value| validate_model_reference(value, row))
        .transpose()?;
    let user = usage
        .user
        .as_deref()
        .map(|value| validate_user_id(value, row))
        .transpose()?;
    let normalized_email = user.and_then(recognized_email);
    let source_ip = usage
        .requester_ip_address
        .as_deref()
        .map(IpAddress::parse)
        .transpose()
        .map_err(|_| VendorImportError::InvalidField {
            row,
            field: "requester_ip_address",
        })?;
    let destination = usage
        .destination_url
        .as_deref()
        .map(|value| litellm_service_endpoint(value, row))
        .transpose()?;
    let source_hostname = usage
        .source_hostname
        .as_deref()
        .map(Hostname::parse)
        .transpose()
        .map_err(|_| VendorImportError::InvalidField {
            row,
            field: "source_hostname",
        })?;
    if usage.request_client.as_ref().is_some_and(|client| {
        (client.name.is_none() && client.agent_id.is_none())
            || client
                .agent_id
                .as_deref()
                .is_some_and(|id| !RequestClientObservation::valid_agent_id(id))
    }) {
        return Err(VendorImportError::InvalidField {
            row,
            field: "request_client",
        });
    }
    let provider_id = litellm_registry_entry_for_provider(&usage.provider).map_or_else(
        || format!("discovered.provider.litellm.{}", usage.provider),
        str::to_owned,
    );
    let request_key = config.pseudonymization_key.pseudonym_exact(
        "litellm_request",
        &format!("{tenant_key}:{}", usage.request_id),
    );
    if usage.device_id.as_deref().is_some_and(|v| {
        v.is_empty()
            || v.len() > 256
            || !v
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':'))
    }) {
        return Err(VendorImportError::InvalidField {
            row,
            field: "device_id",
        });
    }
    let canonical = CanonicalLitellmUsage {
        device_id: usage.device_id.as_deref(),
        user_role: usage.user_role.as_ref(),
        tenant_key,
        request_key: &request_key,
        provider_id: &provider_id,
        model,
        user: normalized_email.as_deref().or(user),
        requester_ip_address: source_ip.as_ref().map(IpAddress::as_str),
        destination_host: destination.as_ref().and_then(LitellmEndpoint::host),
        destination_port: destination.as_ref().and_then(|value| value.port),
        observed_at: usage.observed_at,
        source_hostname: source_hostname.as_ref().map(Hostname::as_str),
        request_client: usage.request_client.as_ref(),
    };
    let digest = canonical_digest(&canonical)?;
    // Client/hostname enrichment of an existing request must not count it again. Preserve the
    // pre-client observation identity; the receipt/batch digest still covers the enriched data.
    let identity_digest = canonical_digest(&CanonicalLitellmUsage {
        source_hostname: None,
        request_client: None,
        device_id: None,
        user_role: None,
        ..canonical
    })?;
    let mut observation = base_observation(
        config,
        connector_type,
        ObservationKind::HttpMetadata,
        usage.observed_at,
        &identity_digest,
    );
    observation.source = EvidenceReceipt::RecordDigest {
        algorithm: DigestAlgorithm::Sha256,
        digest,
    };
    observation.saas.tenant_key = Some(tenant_key.to_owned());
    observation.service.vendor_application_id = Some(provider_id);
    observation.service.source_category = Some("ai_gateway_usage".to_owned());
    observation.service.declared_model_id = model.map(str::to_owned);
    observation.service.ai_request = true;
    observation.service.ai_request_evaluated = true;
    // LiteLLM identifies Azure OpenAI with its provider-native `azure` routing token. Preserve
    // that managed-platform attribution so the gateway observation joins the same Azure finding
    // as native Azure diagnostics instead of inventing a separate `litellm.azure` provider.
    if usage.provider == "azure" {
        observation.cloud.provider = Some(CloudProvider::Azure);
        observation.cloud.provider_service = Some(CloudProviderService::AzureOpenai);
    }
    observation.inventory.device_key_kind = Some(tally_core::DeviceIdentifierKind::ClientSupplied);
    observation.actor.device_key = usage.device_id.as_ref().map(|id| {
        config
            .pseudonymization_key
            .pseudonym_exact("litellm_device", &format!("{tenant_key}:{id}"))
    });
    observation.inventory.user_role.clone_from(&usage.user_role);
    observation.actor.source_ip = source_ip;
    observation.actor.hostname = source_hostname.map(|host| host.as_str().to_owned());
    observation
        .actor
        .request_client
        .clone_from(&usage.request_client);
    if let Some(subject) = normalized_email.as_deref().or(user) {
        observation.actor.identity = Some(IdentityObservation {
            subject_key: config
                .pseudonymization_key
                .pseudonym_exact("identity", subject),
            email: normalized_email,
            source_subject: user.map(str::to_owned),
            source_subject_kind: user.map(|_| IdentitySubjectKind::SourceUserId),
            authority: Some(IdentityAuthority::SourceNative),
            directory_key: None,
            application_key: Some(tenant_key.to_owned()),
            display_label: None,
        });
    }
    if let Some(destination) = destination {
        observation.destination.host = destination.hostname;
        observation.destination.ip = destination.address;
        observation.destination.port = destination.port;
    }
    observation.network.request_count = Some(1);
    observation.outcome.action = Some("request_observed".to_owned());
    Ok(observation)
}

#[derive(Clone)]
struct LitellmEndpoint {
    hostname: Option<Hostname>,
    address: Option<IpAddress>,
    port: Option<u16>,
}

impl LitellmEndpoint {
    fn host(&self) -> Option<&str> {
        self.hostname
            .as_ref()
            .map(Hostname::as_str)
            .or_else(|| self.address.as_ref().map(IpAddress::as_str))
    }
}

fn litellm_service_endpoint(value: &str, row: usize) -> Result<LitellmEndpoint, VendorImportError> {
    let mut url = Url::parse(value).map_err(|_| VendorImportError::InvalidField {
        row,
        field: "destination_url",
    })?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(VendorImportError::InvalidField {
            row,
            field: "destination_url",
        });
    }
    url.set_path("/");
    // Upstream private runtimes commonly use HTTP. The collector never fetches this value; only
    // its validated host/address and effective port survive normalization.
    let host = url.host_str().ok_or(VendorImportError::InvalidField {
        row,
        field: "destination_url",
    })?;
    let (hostname, address) = match host.parse::<IpAddr>() {
        Ok(_) => (
            None,
            Some(
                IpAddress::parse(host).map_err(|_| VendorImportError::InvalidField {
                    row,
                    field: "destination_url",
                })?,
            ),
        ),
        Err(_) => (
            Some(
                Hostname::parse(host).map_err(|_| VendorImportError::InvalidField {
                    row,
                    field: "destination_url",
                })?,
            ),
            None,
        ),
    };
    Ok(LitellmEndpoint {
        hostname,
        address,
        port: url.port_or_known_default(),
    })
}

fn litellm_endpoint(value: &str, row: usize) -> Result<LitellmEndpoint, VendorImportError> {
    let url = Url::parse(value).map_err(|_| VendorImportError::InvalidField {
        row,
        field: "endpoint_ref",
    })?;
    let host = url.host_str().ok_or(VendorImportError::InvalidField {
        row,
        field: "endpoint_ref",
    })?;
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(VendorImportError::InvalidField {
            row,
            field: "endpoint_ref",
        });
    }
    let (hostname, address) = match host.parse::<IpAddr>() {
        Ok(_) => (
            None,
            Some(
                IpAddress::parse(host).map_err(|_| VendorImportError::InvalidField {
                    row,
                    field: "endpoint_ref",
                })?,
            ),
        ),
        Err(_) => (
            Some(
                Hostname::parse(host).map_err(|_| VendorImportError::InvalidField {
                    row,
                    field: "endpoint_ref",
                })?,
            ),
            None,
        ),
    };
    Ok(LitellmEndpoint {
        hostname,
        address,
        port: url.port(),
    })
}

fn base_observation(
    config: &VendorImportConfig,
    connector_type: &'static str,
    kind: ObservationKind,
    observed_at: DateTime<Utc>,
    digest: &str,
) -> Observation {
    let mut observation = Observation::new(
        config.installation_id,
        observed_at,
        ConnectorRef {
            instance_id: config.connector_instance_id,
            connector_type: connector_type.to_owned(),
            implementation_version: config.implementation_version.clone(),
            source_lineage_id: config.source_lineage_id.clone(),
        },
        kind,
        EvidenceReceipt::RecordDigest {
            algorithm: DigestAlgorithm::Sha256,
            digest: digest.to_owned(),
        },
    );
    observation.observation_id = uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        format!(
            "godel-tally:gateway-discovery:{}:{}:{digest}",
            config.connector_instance_id,
            config
                .source_lineage_id
                .as_deref()
                .unwrap_or("connector_default")
        )
        .as_bytes(),
    );
    observation.received_at = config.received_at;
    observation
}

fn finish_import(
    mut observations: Vec<Observation>,
    records_read: u64,
    connector_type: &'static str,
    config: &VendorImportConfig,
    discarded_fields: Vec<String>,
) -> Result<VendorImportOutcome, VendorImportError> {
    observations.sort_by_key(|observation| observation.observation_id);
    observations.dedup_by_key(|observation| observation.observation_id);
    let accepted = u64::try_from(observations.len()).unwrap_or(u64::MAX);
    if accepted == 0 {
        return Err(VendorImportError::NoRecords);
    }
    Ok(VendorImportOutcome {
        batch: ObservationBatch::build(observations, config.checkpoint.clone())?,
        stats: VendorImportStats {
            records_read,
            accepted,
            ignored: records_read.saturating_sub(accepted),
            rejected: 0,
        },
        redaction: crate::RedactionProof {
            connector_type: connector_type.to_owned(),
            pseudonymization: "hmac_sha256_installation_key_v1".to_owned(),
            discarded_fields,
            source_bytes_retained: false,
        },
    })
}

fn validate_input(input: &[u8]) -> Result<(), VendorImportError> {
    if input.is_empty() {
        return Err(VendorImportError::NoRecords);
    }
    if input.len() > crate::MAX_IMPORT_BYTES {
        return Err(VendorImportError::ImportTooLarge(input.len()));
    }
    Ok(())
}

fn validate_identifier(
    value: &str,
    row: usize,
    field: &'static str,
) -> Result<(), VendorImportError> {
    if value.is_empty() || value.len() > 2_048 || value.chars().any(char::is_control) {
        return Err(VendorImportError::InvalidField { row, field });
    }
    Ok(())
}

fn validate_provider_token(value: &str, row: usize) -> Result<(), VendorImportError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(VendorImportError::InvalidField {
            row,
            field: "provider",
        });
    }
    Ok(())
}

fn canonical_digest(value: &impl Serialize) -> Result<String, VendorImportError> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(value).map_err(|_| VendorImportError::Serialization)?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn litellm_client_attribution_enriches_replay_without_counting_another_request() {
        let mut input = serde_json::json!({
            "schema_version":"litellm_gateway_projection_v2", "endpoint_ref":"http://localhost:4000",
            "observed_at":"2026-10-06T08:00:00Z", "model_groups":[],
            "usage":[{"request_id":"request-1", "provider":"deepseek", "model":"deepseek-chat",
                "observed_at":"2026-10-06T07:48:04Z", "user":"aishu@acme.test",
                "requester_ip_address":"10.24.3.8", "destination_url":"https://api.deepseek.com/"}]
        });
        let before =
            import_litellm_model_groups_api_json(&serde_json::to_vec(&input).unwrap(), &config())
                .unwrap();
        input["usage"][0]["source_hostname"] = "aishu-laptop.local".into();
        input["usage"][0]["request_client"] =
            serde_json::json!({"name":"langchain", "agent_id":"agent-1"});
        let after =
            import_litellm_model_groups_api_json(&serde_json::to_vec(&input).unwrap(), &config())
                .unwrap();
        assert_eq!(
            before.batch.observations[0].observation_id,
            after.batch.observations[0].observation_id
        );
        assert_ne!(
            before.batch.observations[0].source,
            after.batch.observations[0].source
        );
        assert_eq!(
            after.batch.observations[0].actor.hostname.as_deref(),
            Some("aishu-laptop.local")
        );
        assert_eq!(
            after.batch.observations[0]
                .actor
                .request_client
                .as_ref()
                .unwrap()
                .agent_id
                .as_deref(),
            Some("agent-1")
        );
        input["usage"][0]["request_client"]["headers"] =
            serde_json::json!({"authorization":"secret"});
        assert!(
            import_litellm_model_groups_api_json(&serde_json::to_vec(&input).unwrap(), &config())
                .is_err()
        );
        input["usage"][0]["request_client"] = serde_json::json!({"name":"unknown-client"});
        assert!(
            import_litellm_model_groups_api_json(&serde_json::to_vec(&input).unwrap(), &config())
                .is_err()
        );
    }
    use crate::{Cursor, PseudonymizationKey};

    fn config() -> VendorImportConfig {
        VendorImportConfig {
            installation_id: uuid::Uuid::nil(),
            connector_instance_id: uuid::Uuid::new_v5(
                &uuid::Uuid::NAMESPACE_URL,
                b"gateway-fixture",
            ),
            implementation_version: "1".to_owned(),
            source_lineage_id: Some("gateway:fixture".to_owned()),
            received_at: "2026-08-18T09:00:00Z".parse().expect("time"),
            checkpoint: Cursor("fixture:1".to_owned()),
            pseudonymization_key: PseudonymizationKey::new(&[7_u8; 32]).expect("key"),
        }
    }

    #[test]
    fn litellm_fixture_is_capability_only_and_replay_safe() {
        let input = include_bytes!("../../../testdata/connectors/litellm/v1/input.json");
        let first = import_litellm_model_groups_json(input, &config()).expect("LiteLLM fixture");
        let replay = import_litellm_model_groups_json(input, &config()).expect("LiteLLM replay");
        assert_eq!(first.batch.receipt, replay.batch.receipt);
        // All safe provider/model pairs survive; unknown providers become authorization items.
        assert_eq!(first.stats.records_read, 4);
        assert_eq!(first.stats.accepted, 4);
        assert_eq!(first.stats.ignored, 0);
        assert!(first.batch.observations.iter().all(|observation| {
            observation.kind == ObservationKind::SaasCapability
                && observation.saas.tenant_key.is_some()
                && observation.saas.application_key.is_some()
        }));
        let entries = first
            .batch
            .observations
            .iter()
            .filter_map(|observation| observation.service.vendor_application_id.as_deref())
            .collect::<Vec<_>>();
        assert!(entries.contains(&"svc.openai.api"));
        assert!(entries.contains(&"svc.anthropic.api"));
        assert!(entries.contains(&"discovered.provider.litellm.bedrock"));
        assert!(first.batch.observations.iter().all(|observation| {
            observation
                .destination
                .host
                .as_ref()
                .is_some_and(|host| host.as_str() == "litellm.internal.example")
                && observation.destination.port == Some(4000)
                && observation.service.declared_model_id.is_some()
        }));
        let encoded = serde_json::to_string(&first).expect("serialize");
        assert!(!encoded.contains("sk-litellm-key-canary"));
    }

    #[test]
    fn litellm_shapes_fail_closed_on_unknown_or_unmappable_input() {
        // Unknown fields anywhere fail closed so content cannot ride along.
        let unknown_field = br#"{
            "schema_version":"litellm_model_groups_projection_v1",
            "endpoint_ref":"https://litellm.internal:4000",
            "observed_at":"2026-08-18T08:00:00Z",
            "model_groups":[{"model_group":"g","providers":["openai"],"api_key":"sk-secret"}]
        }"#;
        assert!(import_litellm_model_groups_json(unknown_field, &config()).is_err());

        // A safe provider missing from the catalog is preserved as an authorization candidate.
        let unmappable = br#"{
            "schema_version":"litellm_model_groups_projection_v1",
            "endpoint_ref":"https://litellm.internal:4000",
            "observed_at":"2026-08-18T08:00:00Z",
            "model_groups":[{"model_group":"g","providers":["bedrock"]}]
        }"#;
        let unmappable = import_litellm_model_groups_json(unmappable, &config())
            .expect("unknown provider is retained");
        assert_eq!(unmappable.stats.accepted, 1);
        assert_eq!(
            unmappable.batch.observations[0]
                .service
                .vendor_application_id
                .as_deref(),
            Some("discovered.provider.litellm.bedrock")
        );

        // Provider tokens are bounded; anything outside the grammar fails closed.
        let bad_token = br#"{
            "schema_version":"litellm_model_groups_projection_v1",
            "endpoint_ref":"https://litellm.internal:4000",
            "observed_at":"2026-08-18T08:00:00Z",
            "model_groups":[{"model_group":"g","providers":["OpenAI Secret"]}]
        }"#;
        assert!(import_litellm_model_groups_json(bad_token, &config()).is_err());
    }

    #[test]
    fn litellm_native_projection_allows_only_http_loopback() {
        let local = br#"{
            "schema_version":"litellm_model_groups_projection_v1",
            "endpoint_ref":"http://127.0.0.1:4000/",
            "observed_at":"2026-08-18T08:00:00Z",
            "model_groups":[{"model_group":"local","providers":["ollama"]}]
        }"#;
        let outcome = import_litellm_model_groups_api_json(local, &config())
            .expect("loopback development endpoint");
        assert_eq!(outcome.stats.accepted, 1);
        assert!(
            outcome.batch.observations[0]
                .destination
                .ip
                .as_ref()
                .is_some_and(|address| address.as_str() == "127.0.0.1")
        );
        assert_eq!(outcome.batch.observations[0].destination.port, Some(4000));

        let private = br#"{
            "schema_version":"litellm_model_groups_projection_v1",
            "endpoint_ref":"http://10.0.0.12:4000/",
            "observed_at":"2026-08-18T08:00:00Z",
            "model_groups":[{"model_group":"local","providers":["ollama"]}]
        }"#;
        assert!(import_litellm_model_groups_api_json(private, &config()).is_err());
    }

    #[test]
    fn litellm_usage_retains_only_request_attribution_and_upstream_location() {
        let input = br#"{
            "schema_version":"litellm_gateway_projection_v2",
            "endpoint_ref":"http://127.0.0.1:4000/",
            "observed_at":"2026-09-04T08:05:00Z",
            "model_groups":[{"model_group":"local-qwen","providers":["ollama"]}],
            "usage":[{
              "request_id":"chatcmpl-tally-e2e",
              "provider":"ollama",
              "model":"ollama/qwen2.5:0.5b",
              "observed_at":"2026-09-04T08:04:59Z",
              "user":"operator@example.com",
              "requester_ip_address":"172.31.77.25",
              "destination_url":"http://ollama:11434/"
            }]
        }"#;
        let outcome = import_litellm_model_groups_api_json(input, &config())
            .expect("request-level LiteLLM projection");
        assert_eq!(outcome.stats.records_read, 2);
        assert_eq!(outcome.stats.accepted, 2);
        let usage = outcome
            .batch
            .observations
            .iter()
            .find(|observation| observation.kind == ObservationKind::HttpMetadata)
            .expect("usage observation");
        assert_eq!(
            usage.service.vendor_application_id.as_deref(),
            Some("runtime.ollama")
        );
        assert_eq!(
            usage.service.declared_model_id.as_deref(),
            Some("ollama/qwen2.5:0.5b")
        );
        assert!(usage.service.ai_request && usage.service.ai_request_evaluated);
        assert_eq!(
            usage.actor.source_ip.as_ref().map(IpAddress::as_str),
            Some("172.31.77.25")
        );
        assert_eq!(
            usage
                .actor
                .identity
                .as_ref()
                .and_then(|identity| identity.email.as_deref()),
            Some("operator@example.com")
        );
        assert_eq!(
            usage.destination.host.as_ref().map(Hostname::as_str),
            Some("ollama")
        );
        assert_eq!(usage.destination.port, Some(11434));
    }

    #[test]
    fn litellm_usage_projection_rejects_content_fields() {
        let input = br#"{
            "schema_version":"litellm_gateway_projection_v2",
            "endpoint_ref":"http://127.0.0.1:4000/",
            "observed_at":"2026-09-04T08:05:00Z",
            "model_groups":[],
            "usage":[{
              "request_id":"chatcmpl-tally-e2e",
              "provider":"openai",
              "model":"openai/gpt-4o-mini",
              "observed_at":"2026-09-04T08:04:59Z",
              "prompt":"SECRET_PROMPT_CANARY"
            }]
        }"#;
        assert!(import_litellm_model_groups_api_json(input, &config()).is_err());
    }

    #[test]
    fn litellm_azure_usage_retains_managed_platform_attribution() {
        let input = br#"{
            "schema_version":"litellm_gateway_projection_v2",
            "endpoint_ref":"http://127.0.0.1:4000/",
            "observed_at":"2026-09-04T08:05:00Z",
            "model_groups":[],
            "usage":[{
              "request_id":"chatcmpl-azure-e2e",
              "provider":"azure",
              "model":"tally-gpt-4-1-mini",
              "observed_at":"2026-09-04T08:04:59Z",
              "user":"operator@example.com",
              "requester_ip_address":"172.31.77.25",
              "destination_url":"https://tally-ai.openai.azure.com/"
            }]
        }"#;
        let outcome = import_litellm_model_groups_api_json(input, &config())
            .expect("Azure request-level LiteLLM projection");
        let usage = outcome
            .batch
            .observations
            .iter()
            .find(|observation| observation.kind == ObservationKind::HttpMetadata)
            .expect("usage observation");
        assert_eq!(usage.cloud.provider, Some(CloudProvider::Azure));
        assert_eq!(
            usage.cloud.provider_service,
            Some(CloudProviderService::AzureOpenai)
        );
        assert_eq!(
            usage.service.vendor_application_id.as_deref(),
            Some("discovered.provider.litellm.azure")
        );
    }

    #[test]
    fn ai_gateway_fixture_is_capability_only_and_replay_safe() {
        assert_eq!(
            ai_gateway_registry_entry_for_provider("fireworks"),
            Some("svc.fireworks.api")
        );
        let input =
            include_bytes!("../../../testdata/connectors/cloudflare-ai-gateway/v1/input.json");
        let first =
            import_cloudflare_ai_gateway_json(input, &config()).expect("AI Gateway fixture");
        let replay =
            import_cloudflare_ai_gateway_json(input, &config()).expect("AI Gateway replay");
        assert_eq!(first.batch.receipt, replay.batch.receipt);
        // Fixture: two gateways plus three provider pairs; unknown providers are retained.
        assert_eq!(first.stats.records_read, 5);
        assert_eq!(first.stats.accepted, 5);
        assert_eq!(first.stats.ignored, 0);
        assert!(first.batch.observations.iter().all(|observation| {
            observation.kind == ObservationKind::SaasCapability
                && observation.saas.tenant_key.is_some()
                && observation.saas.application_key.is_some()
        }));
        let entries = first
            .batch
            .observations
            .iter()
            .filter_map(|observation| observation.service.vendor_application_id.as_deref())
            .collect::<Vec<_>>();
        assert_eq!(
            entries
                .iter()
                .filter(|entry| **entry == AI_GATEWAY_REGISTRY_ENTRY)
                .count(),
            2
        );
        assert!(entries.contains(&"svc.openai.api"));
        assert!(entries.contains(&"svc.anthropic.api"));
        assert!(entries.contains(&"discovered.provider.cloudflare-ai-gateway.workers-ai"));
        assert!(first.batch.observations.iter().any(|observation| {
            observation.service.vendor_application_id.as_deref() == Some("svc.openai.api")
                && observation.network.request_count == Some(42)
        }));
        let encoded = serde_json::to_string(&first).expect("serialize");
        for canary in ["aigw-account-canary", "AIGW_GATEWAY_NAME_CANARY"] {
            assert!(!encoded.contains(canary), "canary {canary} survived");
        }
    }

    #[test]
    fn ai_gateway_usage_retains_only_explicit_directional_byte_measurements() {
        let mut input = serde_json::json!({
            "schema_version":"cloudflare_ai_gateway_projection_v1",
            "account_ref":"0123456789abcdef0123456789abcdef", "observed_at":"2026-08-18T08:00:00Z",
            "gateways":[{"id":"gw","providers":[],"usage":[{
                "id":"log-1","provider":"openai","observed_at":"2026-08-18T07:59:00Z",
                "request_size":0,"response_size":4096
            }]}]
        });
        let outcome = import_cloudflare_ai_gateway_api_json(
            &serde_json::to_vec(&input).expect("fixture"),
            &config(),
        )
        .expect("usage");
        let usage = outcome
            .batch
            .observations
            .iter()
            .find(|observation| observation.kind == ObservationKind::HttpMetadata)
            .expect("request");
        assert_eq!(usage.network.bytes_sent, Some(0));
        assert_eq!(usage.network.bytes_received, Some(4096));
        let id = usage.observation_id;
        input["gateways"][0]["usage"][0]
            .as_object_mut()
            .expect("usage")
            .remove("request_size");
        let missing = import_cloudflare_ai_gateway_api_json(
            &serde_json::to_vec(&input).expect("fixture"),
            &config(),
        )
        .expect("usage");
        let usage = missing
            .batch
            .observations
            .iter()
            .find(|observation| observation.kind == ObservationKind::HttpMetadata)
            .expect("request");
        assert_eq!(usage.network.bytes_sent, None);
        assert_eq!(
            usage.observation_id, id,
            "enrichment must not create a second request"
        );
    }

    #[test]
    fn ai_gateway_shapes_fail_closed_on_unknown_or_unbounded_input() {
        // Unknown fields anywhere fail closed so payloads cannot ride along.
        let unknown_field = br#"{
            "schema_version":"cloudflare_ai_gateway_projection_v1",
            "account_ref":"0123456789abcdef0123456789abcdef",
            "observed_at":"2026-08-18T08:00:00Z",
            "gateways":[{"id":"gw","providers":[],"logs":[{"prompt":"ULTRA_SECRET_PROMPT_CANARY"}]}]
        }"#;
        let error = import_cloudflare_ai_gateway_json(unknown_field, &config())
            .expect_err("unknown fields fail closed");
        assert!(!error.to_string().contains("ULTRA_SECRET_PROMPT_CANARY"));

        // Provider tokens are bounded; anything outside the grammar fails closed.
        let bad_token = br#"{
            "schema_version":"cloudflare_ai_gateway_projection_v1",
            "account_ref":"0123456789abcdef0123456789abcdef",
            "observed_at":"2026-08-18T08:00:00Z",
            "gateways":[{"id":"gw","providers":[{"provider":"OpenAI Payload","request_count":1}]}]
        }"#;
        assert!(import_cloudflare_ai_gateway_json(bad_token, &config()).is_err());
    }

    #[test]
    fn ai_gateway_usage_retains_model_email_hostname_and_unknown_provider() {
        let input = br#"{
            "schema_version":"cloudflare_ai_gateway_projection_v1",
            "account_ref":"0123456789abcdef0123456789abcdef",
            "observed_at":"2026-08-18T08:00:00Z",
            "gateways":[{
              "id":"production-gateway",
              "providers":[],
              "usage":[{
                "id":"log-1",
                "provider":"private-proxy",
                "model":"llama3.2:3b",
                "observed_at":"2026-08-18T07:59:00Z",
                "email":"User@Example.com",
                "user_id":"access-subject-1",
                "hostname":"LAPTOP-42"
              }]
            }]
        }"#;
        let outcome = import_cloudflare_ai_gateway_json(input, &config()).expect("usage");
        assert_eq!(outcome.stats.records_read, 2);
        assert_eq!(outcome.stats.accepted, 2);
        let usage = outcome
            .batch
            .observations
            .iter()
            .find(|observation| observation.kind == ObservationKind::HttpMetadata)
            .expect("usage observation");
        assert_eq!(
            usage.service.vendor_application_id.as_deref(),
            Some("discovered.provider.cloudflare-ai-gateway.private-proxy")
        );
        assert_eq!(
            usage.service.declared_model_id.as_deref(),
            Some("llama3.2:3b")
        );
        assert_eq!(usage.actor.hostname.as_deref(), Some("laptop-42"));
        assert_eq!(
            usage.destination.host.as_ref().map(Hostname::as_str),
            Some(AI_GATEWAY_ENDPOINT_HOST)
        );
        assert_eq!(
            usage
                .actor
                .identity
                .as_ref()
                .and_then(|identity| identity.email.as_deref()),
            Some("user@example.com")
        );
        assert_eq!(
            usage
                .actor
                .identity
                .as_ref()
                .and_then(|identity| identity.source_subject.as_deref()),
            Some("access-subject-1")
        );
        let encoded = serde_json::to_string(&outcome).expect("serialize");
        assert!(!encoded.contains("log-1"));
        assert!(!encoded.contains("0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn native_litellm_transport_keeps_a_distinct_replay_identity() {
        let input = include_bytes!("../../../testdata/connectors/litellm/v1/input.json");
        let outcome =
            import_litellm_model_groups_api_json(input, &config()).expect("native projection");
        assert!(outcome.batch.observations.iter().all(|observation| {
            observation.connector.connector_type == "litellm_model_groups_api_v1"
        }));
        assert_eq!(
            litellm_model_groups_api_descriptor().transport,
            ConnectorTransport::Pull
        );

        let input =
            include_bytes!("../../../testdata/connectors/cloudflare-ai-gateway/v1/input.json");
        let outcome = import_cloudflare_ai_gateway_api_json(input, &config())
            .expect("native AI Gateway projection");
        assert!(outcome.batch.observations.iter().all(|observation| {
            observation.connector.connector_type == "cloudflare_ai_gateway_api_v1"
        }));
        assert_eq!(
            cloudflare_ai_gateway_api_descriptor().transport,
            ConnectorTransport::Pull
        );
    }
}
