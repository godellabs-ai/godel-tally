use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tally_core::{
    ConnectorRef, DigestAlgorithm, EvidenceReceipt, Hostname, IdentityAuthority,
    IdentityObservation, IdentitySubjectKind, IpAddress, Observation, ObservationKind,
};

use crate::{
    ConnectorDescriptor, ConnectorTransport, ObservationBatch, ReplayCapability,
    VendorImportConfig, VendorImportError, VendorImportOutcome, VendorImportStats,
};

const CONNECTOR_TYPE: &str = "microsoft_defender_edr_api_v1";
pub const MICROSOFT_DEFENDER_PROJECTION_SCHEMA_VERSION: &str = "microsoft_defender_projection_v1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DefenderProjection {
    schema_version: String,
    customer_ref: String,
    #[serde(rename = "observed_at")]
    _observed_at: DateTime<Utc>,
    events: Vec<DefenderEvent>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DefenderEvent {
    id: String,
    observed_at: DateTime<Utc>,
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    action_type: Option<String>,
    #[serde(default)]
    #[serde(rename = "file_name")]
    file_name: Option<String>,
    #[serde(default)]
    command_line: Option<String>,
    #[serde(default)]
    parent_file_name: Option<String>,
    #[serde(default)]
    parent_command_line: Option<String>,
    #[serde(default)]
    process_id: Option<String>,
    #[serde(default)]
    parent_process_id: Option<String>,
    #[serde(default)]
    event_table: Option<String>,
    #[serde(default)]
    directory_device_id: Option<String>,
    #[serde(default)]
    os_platform: Option<String>,
    #[serde(default)]
    process_started_at: Option<DateTime<Utc>>,
    #[serde(default)]
    process_unique_id: Option<String>,
    #[serde(default)]
    directory_object_id: Option<String>,
    #[serde(default)]
    source_ip: Option<String>,
    #[serde(default)]
    source_port: Option<u16>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    remote_url: Option<String>,
    #[serde(default)]
    remote_ip: Option<String>,
    #[serde(default)]
    remote_port: Option<u16>,
}

#[derive(Serialize)]
struct CanonicalDefenderUsage<'a> {
    tenant_key: &'a str,
    request_key: &'a str,
    device_key: Option<&'a str>,
    hostname: Option<&'a str>,
    user_id: Option<&'a str>,
    action_type: Option<&'a str>,
    destination_host: Option<&'a str>,
    destination_ip: Option<&'a str>,
    destination_port: Option<u16>,
    registry_entry_id: Option<&'a str>,
    observed_at: DateTime<Utc>,
}

#[must_use]
pub fn microsoft_defender_edr_api_descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor {
        connector_type: CONNECTOR_TYPE.to_owned(),
        display_name: "Microsoft Defender EDR".to_owned(),
        implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
        source_vendor: "Microsoft".to_owned(),
        source_product: "Defender for Endpoint".to_owned(),
        record_variants: vec!["DefenderEvent".to_owned()],
        transport: ConnectorTransport::Pull,
        required_permissions: vec![
            "Microsoft Graph application permission ThreatHunting.Read.All".to_owned(),
        ],
        requested_fields: vec![
            "event ID and timestamp".to_owned(),
            "device ID, hostname, user identity, and action type".to_owned(),
            "remote hostname, IP, and port".to_owned(),
            "local IP, process executable/PID/creation time and parent executable/PID".to_owned(),
        ],
        prohibited_fields: vec![
            "process command lines, payloads, file hashes, and arbitrary event fields".to_owned(),
        ],
        cursor_semantics: "timestamp watermark; replay is idempotent".to_owned(),
        replay_capability: ReplayCapability::OverlapWindow,
        health_capabilities: vec!["API reachability".to_owned()],
        coverage_capabilities: vec!["endpoint events".to_owned()],
        privacy_contract: "Retains the source-native user or email, endpoint hostname, pseudonymous device key, and destination network metadata required to locate Shadow AI usage. Bounded process basenames, PIDs and creation times are retained; raw command lines and content are discarded.".to_owned(),
    }
}

/// Converts a bounded Defender projection into normalized Tally observations.
///
/// # Errors
///
/// Returns [`VendorImportError`] when the projection is empty, oversized, malformed, uses an
/// unsupported schema version, contains an invalid field, or cannot build a canonical batch.
#[allow(clippy::too_many_lines)] // Keep the field validation and privacy projection linear.
pub fn import_microsoft_defender_json(
    input: &[u8],
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    if input.is_empty() {
        return Err(VendorImportError::NoRecords);
    }
    if input.len() > crate::MAX_IMPORT_BYTES {
        return Err(VendorImportError::ImportTooLarge(input.len()));
    }
    let projection: DefenderProjection =
        serde_json::from_slice(input).map_err(|_| VendorImportError::MalformedRecord { row: 1 })?;
    if projection.schema_version != MICROSOFT_DEFENDER_PROJECTION_SCHEMA_VERSION {
        return Err(VendorImportError::InvalidField {
            row: 1,
            field: "schema_version",
        });
    }
    if projection.events.is_empty() {
        return Err(VendorImportError::NoRecords);
    }

    let tenant_key = config
        .pseudonymization_key
        .pseudonym_exact("microsoft_customer", &projection.customer_ref);

    let mut observations = Vec::new();
    let records_read = u64::try_from(projection.events.len()).unwrap_or(u64::MAX);

    for (index, event) in projection.events.into_iter().enumerate() {
        let row = index.saturating_add(1);
        validate_text(&event.id, row, "id", 512)?;
        let device_key = event.device_id.as_deref().map(|id| {
            config
                .pseudonymization_key
                .pseudonym_exact("defender_device", id)
        });
        let request_key = config.pseudonymization_key.pseudonym_exact(
            "defender_event",
            &format!("{}:{}", projection.customer_ref, event.id),
        );
        let hostname = optional_text(event.hostname.as_deref(), row, "hostname", 512)?;
        let user_id = optional_text(event.user_id.as_deref(), row, "user_id", 512)?;
        let action_type = optional_text(event.action_type.as_deref(), row, "action_type", 256)?;
        let destination_host = event
            .remote_url
            .as_deref()
            .map(|value| destination_hostname(value, row))
            .transpose()?;
        let destination_ip = event
            .remote_ip
            .as_deref()
            .map(IpAddress::parse)
            .transpose()
            .map_err(|_| VendorImportError::InvalidField {
                row,
                field: "remote_ip",
            })?;
        let registry_entry_id = destination_host
            .as_ref()
            .and_then(|host| crate::crowdstrike::registry_entry_for_label(host.as_str()));

        let canonical = CanonicalDefenderUsage {
            tenant_key: &tenant_key,
            request_key: &request_key,
            device_key: device_key.as_deref(),
            hostname,
            user_id,
            action_type,
            destination_host: destination_host.as_ref().map(Hostname::as_str),
            destination_ip: destination_ip.as_ref().map(IpAddress::as_str),
            destination_port: event.remote_port,
            registry_entry_id,
            observed_at: event.observed_at,
        };
        let bytes = serde_json::to_vec(&canonical).map_err(|_| VendorImportError::Serialization)?;
        let digest = hex::encode(Sha256::digest(bytes));

        let mut observation = Observation::new(
            config.installation_id,
            event.observed_at,
            ConnectorRef {
                instance_id: config.connector_instance_id,
                connector_type: CONNECTOR_TYPE.to_owned(),
                implementation_version: config.implementation_version.clone(),
                source_lineage_id: config.source_lineage_id.clone(),
            },
            ObservationKind::HttpMetadata,
            EvidenceReceipt::RecordDigest {
                algorithm: DigestAlgorithm::Sha256,
                digest: digest.clone(),
            },
        );
        observation.observation_id = uuid::Uuid::new_v5(
            &uuid::Uuid::NAMESPACE_URL,
            format!(
                "godel-tally:defender:{}:{}:{digest}",
                config.connector_instance_id,
                config
                    .source_lineage_id
                    .as_deref()
                    .unwrap_or("connector_default")
            )
            .as_bytes(),
        );
        observation.received_at = config.received_at;
        observation.saas.tenant_key = Some(tenant_key.clone());
        observation.actor.device_key = device_key;
        observation.inventory.device_key_kind =
            Some(tally_core::DeviceIdentifierKind::SourceNative);
        observation.actor.hostname = hostname.map(str::to_owned);
        observation.actor.identity = user_id.map(|subject| IdentityObservation {
            subject_key: config.pseudonymization_key.pseudonym_exact(
                "identity",
                &if crate::crowdstrike::recognized_email(subject).is_some() {
                    subject.to_ascii_lowercase()
                } else {
                    format!(
                        "{}:{subject}",
                        observation
                            .actor
                            .device_key
                            .as_deref()
                            .unwrap_or(&request_key)
                    )
                },
            ),
            email: crate::crowdstrike::recognized_email(subject),
            source_subject: Some(subject.to_owned()),
            source_subject_kind: Some(IdentitySubjectKind::UserName),
            authority: Some(IdentityAuthority::SourceNative),
            directory_key: None,
            application_key: None,
            display_label: None,
        });
        observation.destination.host = destination_host;
        observation.destination.ip = destination_ip;
        observation.destination.port = event.remote_port;
        observation.network.destination_port = event.remote_port;
        observation.network.source_port = event.source_port;
        observation.network.protocol = event
            .protocol
            .as_deref()
            .map(str::to_ascii_lowercase)
            .filter(|v| ["tcp", "udp", "icmp", "icmpv6"].contains(&v.as_str()));
        observation.service.vendor_application_id = registry_entry_id.map(str::to_owned);
        observation.service.source_category = Some("microsoft_defender_device_network".to_owned());
        observation.outcome.action = action_type.map(str::to_owned);

        enrich_agent(&mut observation, &event, config);
        observation.process = tally_core::ProcessObservation {
            executable: event
                .file_name
                .as_deref()
                .and_then(tally_core::ProcessObservation::executable_basename),
            pid: observation.agent.process_id.clone(),
            unique_id: event
                .process_unique_id
                .as_deref()
                .filter(|v| {
                    !v.is_empty()
                        && !v.bytes().all(|b| b == b'0')
                        && v.len() <= 128
                        && v.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':'))
                })
                .map(str::to_owned),
            started_at: event.process_started_at,
            parent_executable: event
                .parent_file_name
                .as_deref()
                .and_then(tally_core::ProcessObservation::executable_basename),
            parent_pid: observation.agent.parent_process_id.clone(),
            parent_unique_id: None,
        };
        observation.inventory.user_role = Some(tally_core::IdentityRole::ProcessAccount);
        if let Some(id) = event
            .directory_device_id
            .as_deref()
            .and_then(|v| uuid::Uuid::parse_str(v).ok())
            .filter(|v| !v.is_nil())
        {
            observation
                .inventory
                .identifiers
                .push(tally_core::InventoryIdentifier {
                    kind: "entra_device_id".into(),
                    value: id.to_string(),
                });
            observation.inventory.directory_tenant_key = Some(
                config
                    .pseudonymization_key
                    .pseudonym_exact("directory_tenant", &projection.customer_ref),
            );
        }
        if let Some(id) = observation.agent.directory_object_id.clone() {
            if let Some(identity) = observation.actor.identity.as_mut() {
                identity.directory_key = Some(id);
            }
            observation.inventory.directory_tenant_key = Some(
                config
                    .pseudonymization_key
                    .pseudonym_exact("directory_tenant", &projection.customer_ref),
            );
        }
        observation.inventory.os = event
            .os_platform
            .as_deref()
            .filter(|v| v.len() <= 128 && !v.chars().any(char::is_control))
            .map(str::to_owned);
        if event.event_table.as_deref() == Some("DeviceInfo") {
            observation.kind = ObservationKind::NetworkMapping;
            observation.service.source_category = Some("microsoft_defender_device_info".into());
            observation.inventory.user_role = None;
        }

        // Receipts describe projected evidence. Keep the observation identity above unchanged
        // when process metadata is enriched, so replay cannot add another usage count.
        if !observation.agent.is_empty()
            || !observation.process.is_empty()
            || !observation.inventory.is_empty()
        {
            let normalized = serde_json::to_vec(&(
                &digest,
                &observation.agent,
                &observation.process,
                &observation.inventory,
                &observation.actor,
                &observation.network,
            ))
            .map_err(|_| VendorImportError::Serialization)?;
            let digest = hex::encode(Sha256::digest(normalized));
            observation.source = EvidenceReceipt::RecordDigest {
                algorithm: DigestAlgorithm::Sha256,
                digest,
            };
        }
        observations.push(observation);
    }

    observations.sort_by_key(|obs| obs.observation_id);
    observations.dedup_by_key(|obs| obs.observation_id);
    let accepted = u64::try_from(observations.len()).unwrap_or(u64::MAX);

    Ok(VendorImportOutcome {
        batch: ObservationBatch::build(observations, config.checkpoint.clone())?,
        stats: VendorImportStats {
            records_read,
            accepted,
            ignored: records_read.saturating_sub(accepted),
            rejected: 0,
        },
        redaction: crate::RedactionProof {
            connector_type: CONNECTOR_TYPE.to_owned(),
            pseudonymization: "hmac_sha256_installation_key_v1".to_owned(),
            discarded_fields: vec![
                "process command lines, file metadata, hashes, payloads, and arbitrary hunting columns".to_owned(),
                "raw Microsoft Graph response bytes and source event IDs".to_owned(),
            ],
            source_bytes_retained: false,
        },
    })
}

fn validate_text(
    value: &str,
    row: usize,
    field: &'static str,
    max_len: usize,
) -> Result<(), VendorImportError> {
    if value.trim().is_empty()
        || value.trim() != value
        || value.len() > max_len
        || value.chars().any(char::is_control)
    {
        return Err(VendorImportError::InvalidField { row, field });
    }
    Ok(())
}

fn optional_text<'a>(
    value: Option<&'a str>,
    row: usize,
    field: &'static str,
    max_len: usize,
) -> Result<Option<&'a str>, VendorImportError> {
    value
        .map(|value| {
            validate_text(value, row, field, max_len)?;
            Ok(value)
        })
        .transpose()
}

fn destination_hostname(value: &str, row: usize) -> Result<Hostname, VendorImportError> {
    validate_text(value, row, "remote_url", 2_048)?;
    if let Ok(url) = url::Url::parse(value) {
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(VendorImportError::InvalidField {
                row,
                field: "remote_url",
            });
        }
        return url
            .host_str()
            .ok_or(VendorImportError::InvalidField {
                row,
                field: "remote_url",
            })
            .and_then(|host| {
                Hostname::parse(host).map_err(|_| VendorImportError::InvalidField {
                    row,
                    field: "remote_url",
                })
            });
    }
    Hostname::parse(value).map_err(|_| VendorImportError::InvalidField {
        row,
        field: "remote_url",
    })
}

fn enrich_agent(o: &mut Observation, event: &DefenderEvent, config: &VendorImportConfig) {
    let table = event
        .event_table
        .as_deref()
        .unwrap_or("DeviceNetworkEvents");
    let file = event.file_name.as_deref().unwrap_or_default();
    let command = event.command_line.as_deref().unwrap_or_default();
    let signature = crate::agent_signatures::identify(file, command);
    let device = event
        .device_id
        .as_deref()
        .or(event.hostname.as_deref())
        .unwrap_or("unknown-device");
    let key = |name: &str| {
        config
            .pseudonymization_key
            .pseudonym_exact("endpoint_agent", &format!("{device}:{name}"))
    };
    if let Some((kind, name)) = signature {
        o.agent.key = Some(key(&name));
        o.agent.name = Some(name);
        o.agent.kind = Some(kind.into());
        o.agent.platform = Some("endpoint".into());
        o.agent.state = Some("observed".into());
    }
    if table == "DeviceFileEvents"
        && [
            "mcp.json",
            "claude_desktop_config.json",
            "mcp_settings.json",
        ]
        .contains(&file)
    {
        o.agent.key = Some(key(file));
        o.agent.name = Some(file.into());
        o.agent.kind = Some("mcp_config".into());
        o.agent.config_file = Some(file.into());
        o.agent.state = Some("declared".into());
    }
    if table == "DeviceProcessEvents"
        && o.agent.key.is_some()
        && let Some(("agent", name)) = crate::agent_signatures::identify(
            event.parent_file_name.as_deref().unwrap_or_default(),
            event.parent_command_line.as_deref().unwrap_or_default(),
        )
    {
        o.agent.parent_key = Some(key(&name));
        o.agent.parent_name = Some(name);
    }
    o.agent.process_id = event
        .process_id
        .as_deref()
        .filter(|s| s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()))
        .map(str::to_owned);
    o.agent.parent_process_id = event
        .parent_process_id
        .as_deref()
        .filter(|s| s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()))
        .map(str::to_owned);
    o.agent.directory_object_id = event
        .directory_object_id
        .as_deref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .map(|id| {
            config
                .pseudonymization_key
                .pseudonym_exact("entra_object", &id.to_string())
        });
    o.agent.attribution_confidence = Some(
        if o.actor.identity.is_some() {
            "confirmed"
        } else {
            "unattributed"
        }
        .into(),
    );
    o.agent.attribution_basis = Some(
        if o.actor.identity.is_some() {
            "Defender event reports the process OS account directly"
        } else {
            "No OS account was supplied by Defender"
        }
        .into(),
    );
    o.agent.identity_kind = Some("os_account".into());
    o.actor.source_ip = event
        .source_ip
        .as_deref()
        .and_then(|s| s.parse::<std::net::IpAddr>().ok())
        .filter(|ip| !ip.is_unspecified())
        .and_then(|ip| IpAddress::parse(&ip.to_string()).ok());
    o.service.source_category = Some(format!("defender:{table}"));
}

#[must_use]
pub fn defender_stream_descriptor() -> ConnectorDescriptor {
    let mut descriptor = microsoft_defender_edr_api_descriptor();
    descriptor.connector_type = "microsoft_defender_stream_v1".into();
    descriptor.display_name = "Microsoft Defender event stream".into();
    descriptor.transport = ConnectorTransport::Stream;
    descriptor.required_permissions =
        vec!["Azure Event Hubs Data Receiver; Defender streaming export enabled".into()];
    descriptor.record_variants = [
        "DeviceProcessEvents",
        "DeviceNetworkEvents",
        "DeviceFileEvents",
        "DeviceInfo",
        "DeviceLogonEvents",
    ]
    .map(str::to_owned)
    .to_vec();
    descriptor.requested_fields.push("Process filename/command line and parent, OS account, device identity, MCP config basename".into());
    descriptor.prohibited_fields =
        vec!["stored raw command lines, tokens, prompts, file contents".into()];
    descriptor.privacy_contract = "Command lines are inspected transiently for recognized signatures. Bounded executable basenames, scoped native process IDs, process start and parent metadata are retained when supplied. No full paths, arbitrary arguments or file contents are stored.".into();
    descriptor.cursor_semantics =
        "Event Hubs partition checkpoint advances only after Tally acknowledges the batch".into();
    descriptor.replay_capability = ReplayCapability::SourceManagedRetry;
    descriptor
}

/// Normalize Defender Streaming API envelopes delivered by the Event Hubs receiver.
/// # Errors
/// Returns an error for invalid envelopes or oversized batches; command lines never leave memory.
#[allow(clippy::too_many_lines)]
pub fn import_defender_stream_json(
    input: &[u8],
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    if input.len() > crate::MAX_IMPORT_BYTES {
        return Err(VendorImportError::ImportTooLarge(input.len()));
    }
    let value: serde_json::Value =
        serde_json::from_slice(input).map_err(|_| VendorImportError::MalformedRecord { row: 1 })?;
    let records = value
        .get("records")
        .and_then(serde_json::Value::as_array)
        .or_else(|| value.as_array())
        .cloned()
        .unwrap_or_else(|| vec![value]);
    if records.len() > crate::MAX_BATCH_OBSERVATIONS {
        return Err(VendorImportError::ImportTooLarge(input.len()));
    }
    let mut events = Vec::new();
    for (index, record) in records.iter().enumerate() {
        let row = index + 1;
        let Some(props) = record.get("properties") else {
            return Err(VendorImportError::MalformedRecord { row });
        };
        let get = |key: &str| {
            props.get(key).and_then(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .or_else(|| v.as_u64().map(|v| v.to_string()))
            })
        };
        let table = record
            .get("category")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim_start_matches("AdvancedHunting-");
        let observed_at = get("Timestamp")
            .or_else(|| {
                record
                    .get("time")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .and_then(|t| DateTime::parse_from_rfc3339(&t).ok())
            .map(|t| t.with_timezone(&Utc))
            .ok_or(VendorImportError::InvalidField {
                row,
                field: "Timestamp",
            })?;
        let network = table == "DeviceNetworkEvents";
        let account = |prefix: &str| {
            get(&format!("{prefix}AccountUpn"))
                .filter(|v| !v.is_empty())
                .or_else(|| {
                    let name = get(&format!("{prefix}AccountName")).filter(|v| !v.is_empty())?;
                    let domain = get(&format!("{prefix}AccountDomain"))
                        .filter(|v| !v.is_empty())
                        .or_else(|| get("DeviceName"))
                        .or_else(|| get("DeviceId"));
                    Some(domain.map_or_else(|| name.clone(), |domain| format!("{domain}\\{name}")))
                })
        };
        let user = if network {
            account("InitiatingProcess").or_else(|| account(""))
        } else {
            account("").or_else(|| account("InitiatingProcess"))
        };
        events.push(DefenderEvent {
            id: format!(
                "{}:{}:{}:{}",
                get("DeviceId").unwrap_or_default(),
                get("ReportId").unwrap_or_default(),
                table,
                observed_at
            ),
            observed_at,
            device_id: get("DeviceId"),
            hostname: get("DeviceName"),
            user_id: user,
            action_type: get("ActionType"),
            file_name: if network {
                get("InitiatingProcessFileName")
            } else {
                get("FileName")
            },
            command_line: if network {
                get("InitiatingProcessCommandLine")
            } else {
                get("ProcessCommandLine")
            },
            parent_file_name: if network {
                get("InitiatingProcessParentFileName")
            } else {
                get("InitiatingProcessFileName")
            },
            parent_command_line: if network {
                None
            } else {
                get("InitiatingProcessCommandLine")
            },
            process_id: if network {
                get("InitiatingProcessId")
            } else {
                get("ProcessId")
            },
            parent_process_id: if network {
                get("InitiatingProcessParentId")
            } else {
                get("InitiatingProcessId")
            },
            process_started_at: get(if network {
                "InitiatingProcessCreationTime"
            } else {
                "ProcessCreationTime"
            })
            .and_then(|v| v.parse().ok()),
            process_unique_id: get(if network {
                "InitiatingProcessUniqueId"
            } else {
                "ProcessUniqueId"
            }),
            directory_device_id: get("AadDeviceId"),
            os_platform: get("OSPlatform"),
            event_table: Some(table.into()),
            directory_object_id: get("AccountObjectId")
                .or_else(|| get("InitiatingProcessAccountObjectId")),
            source_ip: get("LocalIP"),
            source_port: get("LocalPort").and_then(|v| v.parse().ok()),
            protocol: get("Protocol"),
            remote_url: get("RemoteUrl"),
            remote_ip: get("RemoteIP"),
            remote_port: props
                .get("RemotePort")
                .and_then(serde_json::Value::as_u64)
                .and_then(|v| u16::try_from(v).ok()),
        });
    }
    let projection = DefenderProjection {
        schema_version: MICROSOFT_DEFENDER_PROJECTION_SCHEMA_VERSION.into(),
        customer_ref: config
            .source_lineage_id
            .clone()
            .unwrap_or_else(|| config.connector_instance_id.to_string()),
        _observed_at: config.received_at,
        events,
    };
    let mut outcome = import_microsoft_defender_json(
        &serde_json::to_vec(&projection).map_err(|_| VendorImportError::Serialization)?,
        config,
    )?;
    for observation in &mut outcome.batch.observations {
        observation.connector.connector_type = "microsoft_defender_stream_v1".into();
    }
    outcome.batch = ObservationBatch::build(outcome.batch.observations, config.checkpoint.clone())?;
    outcome.redaction.connector_type = "microsoft_defender_stream_v1".into();
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cursor, PseudonymizationKey};
    use uuid::Uuid;

    fn config() -> VendorImportConfig {
        VendorImportConfig {
            installation_id: Uuid::from_u128(1),
            connector_instance_id: Uuid::from_u128(2),
            implementation_version: "test".to_owned(),
            source_lineage_id: Some("defender:edr".to_owned()),
            received_at: "2026-09-07T10:01:00Z".parse().expect("timestamp"),
            checkpoint: Cursor("defender:123".to_owned()),
            pseudonymization_key: PseudonymizationKey::new(&[7_u8; 32]).expect("key"),
        }
    }

    #[test]
    fn macos_process_names_survive_but_placeholder_ids_and_addresses_do_not() {
        for (unique, ip, expected_ip) in [
            ("0", "0.0.0.0", None),
            ("000", "::", None),
            ("123", "192.168.0.42", Some("192.168.0.42")),
        ] {
            let input = serde_json::json!({"records":[{"category":"AdvancedHunting-DeviceNetworkEvents","properties":{
                "Timestamp":"2026-10-24T12:44:00Z", "ReportId":123,
                "DeviceId":"device1", "DeviceName":"macbook", "RemoteUrl":"https://chat.z.ai",
                "InitiatingProcessFileName":"microsoft edge helper", "InitiatingProcessParentFileName":"Microsoft Edge",
                "InitiatingProcessId":42, "InitiatingProcessUniqueId":unique,
                "InitiatingProcessCreationTime":"2026-10-24T12:43:00Z", "LocalIP":ip,
                "InitiatingProcessAccountUpn":"", "InitiatingProcessAccountName":"ramanan",
                "InitiatingProcessCommandLine":"must-not-persist --secret canary"
            }}]});
            let result =
                import_defender_stream_json(&serde_json::to_vec(&input).unwrap(), &config())
                    .unwrap();
            let o = &result.batch.observations[0];
            assert_eq!(
                o.process.executable.as_deref(),
                Some("microsoft edge helper")
            );
            assert_eq!(
                o.process.parent_executable.as_deref(),
                Some("Microsoft Edge")
            );
            assert_eq!(o.process.pid.as_deref(), Some("42"));
            assert!(o.process.started_at.is_some());
            assert_eq!(
                o.process.unique_id.as_deref(),
                (unique == "123").then_some("123")
            );
            assert_eq!(
                o.actor.source_ip.as_ref().map(IpAddress::as_str),
                expected_ip
            );
            assert_eq!(
                o.actor.identity.as_ref().unwrap().source_subject.as_deref(),
                Some("macbook\\ramanan")
            );
            assert_eq!(
                o.service.vendor_application_id.as_deref(),
                Some("app.zai.chat")
            );
            assert!(!serde_json::to_string(o).unwrap().contains("canary"));
        }
    }

    #[test]
    fn adding_process_context_preserves_the_source_observation_identity() {
        let input = serde_json::json!({"records":[{"category":"AdvancedHunting-DeviceNetworkEvents","properties":{"Timestamp":"2026-10-07T00:00:00Z","ReportId":12,"DeviceId":"device1","DeviceName":"workstation.example.com","RemoteUrl":"api.openai.com"}}]});
        let first =
            import_defender_stream_json(&serde_json::to_vec(&input).unwrap(), &config()).unwrap();
        let mut enriched = input;
        enriched["records"][0]["properties"]["InitiatingProcessFileName"] =
            serde_json::json!("curl");
        let second =
            import_defender_stream_json(&serde_json::to_vec(&enriched).unwrap(), &config())
                .unwrap();
        assert_eq!(
            first.batch.observations[0].observation_id,
            second.batch.observations[0].observation_id
        );
        assert_eq!(
            second.batch.observations[0].process.executable.as_deref(),
            Some("curl")
        );
    }

    #[test]
    fn stream_preserves_parent_child_identity_and_discards_arguments() {
        let input = serde_json::json!({"records":[{"category":"AdvancedHunting-DeviceProcessEvents","properties":{"Timestamp":"2026-10-07T00:00:00Z","ReportId":12,"DeviceId":"device1","DeviceName":"workstation.example.com","AccountUpn":"user@example.com","AccountObjectId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","FileName":"node","ProcessCommandLine":"npx @modelcontextprotocol/server-filesystem --token secret-token-canary /private/project","InitiatingProcessFileName":"claude","ProcessId":42,"InitiatingProcessId":40}}]});
        let result =
            import_defender_stream_json(&serde_json::to_vec(&input).unwrap(), &config()).unwrap();
        let agent = &result.batch.observations[0].agent;
        assert_eq!(agent.kind.as_deref(), Some("mcp_server"));
        assert_eq!(agent.parent_name.as_deref(), Some("Claude Code"));
        assert_eq!(agent.process_id.as_deref(), Some("42"));
        assert_eq!(agent.attribution_confidence.as_deref(), Some("confirmed"));
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(!encoded.contains("secret-token-canary"));
        assert!(!encoded.contains("/private/project"));
        let replay =
            import_defender_stream_json(&serde_json::to_vec(&input).unwrap(), &config()).unwrap();
        assert_eq!(
            result.batch.receipt.canonical_digest,
            replay.batch.receipt.canonical_digest
        );
    }

    #[test]
    fn streaming_accounts_preserve_domain_and_network_process_owner() {
        let record = |domain: &str| serde_json::json!({"category":"AdvancedHunting-DeviceNetworkEvents","properties":{"Timestamp":"2026-10-07T00:00:00Z","ReportId":domain,"DeviceId":"device1","DeviceName":"workstation.example.com","AccountName":"wrong-owner","InitiatingProcessAccountName":"alex","InitiatingProcessAccountDomain":domain,"InitiatingProcessFileName":"claude","RemoteUrl":"api.anthropic.com","RemotePort":443}});
        let data = serde_json::json!({"records":[record("FIRST"),record("SECOND")]});
        let result =
            import_defender_stream_json(&serde_json::to_vec(&data).unwrap(), &config()).unwrap();
        let identities = result
            .batch
            .observations
            .iter()
            .map(|o| o.actor.identity.as_ref().unwrap())
            .collect::<Vec<_>>();
        assert_ne!(identities[0].subject_key, identities[1].subject_key);
        assert!(
            identities
                .iter()
                .all(|i| i.source_subject.as_deref().unwrap().ends_with("\\alex"))
        );
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("wrong-owner")
        );
    }

    #[test]
    fn normalizes_defender_events() {
        let input = br#"{
            "schema_version":"microsoft_defender_projection_v1",
            "customer_ref":"tenant-1",
            "observed_at":"2026-09-07T10:01:00Z",
            "events":[{
                "id":"evt-1",
                "observed_at":"2026-09-07T10:00:00Z",
                "device_id":"dev-1",
                "hostname":"laptop-17.example.com",
                "user_id":"analyst@example.com",
                "action_type":"NetworkConnection",
                "file_name":"malware.exe",
                "remote_url":"https://api.openai.com/v1/chat/completions",
                "remote_ip":"192.168.1.1",
                "remote_port":443
            }]
        }"#;
        let outcome = import_microsoft_defender_json(input, &config()).expect("import");
        assert_eq!(outcome.stats.records_read, 1);
        assert_eq!(outcome.stats.accepted, 1);
        let observation = &outcome.batch.observations[0];
        assert_eq!(observation.kind, ObservationKind::HttpMetadata);
        assert_eq!(
            observation.outcome.action.as_deref(),
            Some("NetworkConnection")
        );
        assert_eq!(
            observation.actor.hostname.as_deref(),
            Some("laptop-17.example.com")
        );
        assert_eq!(
            observation
                .actor
                .identity
                .as_ref()
                .and_then(|identity| identity.email.as_deref()),
            Some("analyst@example.com")
        );
        assert_eq!(
            observation.destination.host.as_ref().map(Hostname::as_str),
            Some("api.openai.com")
        );
        assert_eq!(observation.destination.port, Some(443));
        assert_eq!(
            observation.service.vendor_application_id.as_deref(),
            Some("svc.openai.api")
        );
        let serialized = serde_json::to_string(&outcome.batch).expect("serialize");
        assert!(!serialized.contains("evt-1"));
        assert_eq!(
            observation.process.executable.as_deref(),
            Some("malware.exe")
        );
        assert!(observation.agent.key.is_none());
    }
}
