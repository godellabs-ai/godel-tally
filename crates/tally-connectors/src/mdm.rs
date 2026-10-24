//! Read-only device inventory projections. No management commands or device secrets.
use crate::{
    ConnectorDescriptor, ConnectorTransport, ObservationBatch, RedactionProof, ReplayCapability,
    VendorImportConfig, VendorImportError, VendorImportOutcome, VendorImportStats,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tally_core::{
    ConnectorRef, DigestAlgorithm, EvidenceReceipt, Hostname, IdentityAuthority,
    IdentityObservation, IdentityRole, IdentitySubjectKind, InventoryIdentifier, IpAddress,
    Observation, ObservationKind,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MdmProvider {
    Iru,
    Addigy,
    Intune,
    Jamf,
}
impl MdmProvider {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Iru => "iru",
            Self::Addigy => "addigy",
            Self::Intune => "intune",
            Self::Jamf => "jamf",
        }
    }
    pub const fn connector_type(self) -> &'static str {
        match self {
            Self::Iru => "iru_inventory_v1",
            Self::Addigy => "addigy_inventory_v1",
            Self::Intune => "intune_inventory_v1",
            Self::Jamf => "jamf_inventory_v1",
        }
    }
    pub fn descriptor(self) -> ConnectorDescriptor {
        ConnectorDescriptor {connector_type:self.connector_type().into(),display_name:format!("{} device inventory",self.name()),implementation_version:env!("CARGO_PKG_VERSION").into(),source_vendor:self.name().into(),source_product:"Read-only MDM inventory".into(),record_variants:vec!["mdm_inventory_v1".into()],transport:ConnectorTransport::Pull,
            required_permissions:vec![match self {Self::Iru=>"Devices list/detail and user assignment read",Self::Addigy=>"Read device inventory and facts",Self::Intune=>"DeviceManagementManagedDevices.Read.All application permission; active Intune license",Self::Jamf=>"Jamf Platform API devices:read; v4 computer inventory"}.into()],
            requested_fields:vec!["scoped device IDs, hostname, OS, serial, reported addresses and source timestamps".into(),"source user IDs and explicit assignment/logged-in roles".into()],prohibited_fields:vec!["device secrets, recovery keys, management commands, installed software lists and unrelated facts".into()],cursor_semantics:"Complete bounded paginated snapshots; partial failures never retire unseen devices".into(),replay_capability:ReplayCapability::OverlapWindow,health_capabilities:vec!["source reachability, pagination and sync freshness".into()],coverage_capabilities:vec!["device and user inventory; no AI usage".into()],privacy_contract:"Only bounded inventory identifiers, addresses and typed user relationships survive projection. Ownership is not request attribution; snapshot addresses have no implied historical validity.".into()}
    }
}

pub fn valid_mdm_origin(provider: MdmProvider, value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.port().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    let host = url.host_str().unwrap_or("");
    match provider {
        MdmProvider::Iru => [".api.kandji.io", ".api.eu.kandji.io"]
            .iter()
            .any(|suffix| {
                host.strip_suffix(suffix)
                    .is_some_and(|s| !s.is_empty() && !s.contains('.'))
            }),
        MdmProvider::Addigy => host == "api.addigy.com",
        MdmProvider::Intune => host == "graph.microsoft.com",
        MdmProvider::Jamf => host
            .strip_suffix(".api.jamfcloud.com")
            .is_some_and(|s| !s.is_empty() && !s.contains('.')),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryUser {
    pub id: String,
    pub label: Option<String>,
    pub email: Option<String>,
    pub role: IdentityRole,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSnapshot {
    pub id: String,
    pub hostname: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    pub os: Option<String>,
    pub observed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub identifiers: Vec<InventoryIdentifier>,
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub users: Vec<InventoryUser>,
    #[serde(default)]
    pub retired: bool,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MdmSnapshot {
    pub provider: MdmProvider,
    pub tenant: String,
    pub observed_at: DateTime<Utc>,
    pub devices: Vec<DeviceSnapshot>,
}

fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

/// Imports a complete, bounded read-only inventory snapshot.
///
/// # Errors
/// Returns an error for malformed, oversized or invalid inventory metadata.
#[allow(clippy::too_many_lines)] // Keep the bounded source projection together.
pub fn import_mdm_json(
    input: &[u8],
    provider: MdmProvider,
    config: &VendorImportConfig,
) -> Result<VendorImportOutcome, VendorImportError> {
    if input.len() > crate::MAX_IMPORT_BYTES {
        return Err(VendorImportError::ImportTooLarge(input.len()));
    }
    let snapshot: MdmSnapshot =
        serde_json::from_slice(input).map_err(|_| VendorImportError::MalformedRecord { row: 1 })?;
    if snapshot.provider != provider
        || !bounded(&snapshot.tenant, 512)
        || snapshot.devices.len() > crate::MAX_BATCH_OBSERVATIONS
    {
        return Err(VendorImportError::InvalidField {
            row: 1,
            field: "inventory_scope",
        });
    }
    let mut observations = Vec::new();
    for (index, device) in snapshot.devices.iter().enumerate() {
        let row = index + 1;
        if !bounded(&device.id, 512)
            || device.identifiers.len() > 32
            || device.addresses.len() > 32
            || device.users.len() > 32
            || device
                .display_name
                .as_ref()
                .is_some_and(|v| !bounded(v, 256))
            || device.os.as_ref().is_some_and(|v| !bounded(v, 128))
            || device
                .observed_at
                .is_some_and(|at| at > snapshot.observed_at + chrono::Duration::minutes(5))
        {
            return Err(VendorImportError::InvalidField {
                row,
                field: "device_inventory",
            });
        }
        for id in &device.identifiers {
            if !bounded(&id.kind, 64) || !bounded(&id.value, 256) {
                return Err(VendorImportError::InvalidField {
                    row,
                    field: "device_identifier",
                });
            }
        }
        let hostname = device
            .hostname
            .as_deref()
            .map(Hostname::parse)
            .transpose()
            .map_err(|_| VendorImportError::InvalidField {
                row,
                field: "hostname",
            })?;
        let addresses = device
            .addresses
            .iter()
            .map(|v| {
                IpAddress::parse(v).map_err(|_| VendorImportError::InvalidField {
                    row,
                    field: "address",
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        for user in device
            .users
            .iter()
            .map(Some)
            .chain(device.users.is_empty().then_some(None))
        {
            if user.is_some_and(|u| {
                !bounded(&u.id, 512)
                    || u.label.as_ref().is_some_and(|v| !bounded(v, 256))
                    || u.email.as_ref().is_some_and(|v| !bounded(v, 254))
            }) {
                return Err(VendorImportError::InvalidField {
                    row,
                    field: "inventory_user",
                });
            }
            let canonical = serde_json::to_vec(&(
                provider,
                &snapshot.tenant,
                snapshot.observed_at,
                device,
                user,
            ))
            .map_err(|_| VendorImportError::Serialization)?;
            let digest = hex::encode(Sha256::digest(canonical));
            let mut o = Observation::new(
                config.installation_id,
                snapshot.observed_at,
                ConnectorRef {
                    instance_id: config.connector_instance_id,
                    connector_type: provider.connector_type().into(),
                    implementation_version: config.implementation_version.clone(),
                    source_lineage_id: config.source_lineage_id.clone(),
                },
                ObservationKind::NetworkMapping,
                EvidenceReceipt::RecordDigest {
                    algorithm: DigestAlgorithm::Sha256,
                    digest: digest.clone(),
                },
            );
            o.observation_id = uuid::Uuid::new_v5(&config.connector_instance_id, digest.as_bytes());
            o.received_at = config.received_at;
            o.saas.tenant_key = Some(config.pseudonymization_key.pseudonym_exact(
                "mdm_tenant",
                &format!("{}:{}", provider.name(), snapshot.tenant),
            ));
            o.actor.device_key = Some(config.pseudonymization_key.pseudonym_exact(
                "mdm_device",
                &format!("{}:{}:{}", provider.name(), snapshot.tenant, device.id),
            ));
            o.actor.hostname = hostname.as_ref().map(|v| v.as_str().to_owned());
            o.inventory.device_key_kind = Some(tally_core::DeviceIdentifierKind::SourceNative);
            o.actor.additional_source_ips.clone_from(&addresses);
            o.inventory.addresses = addresses
                .iter()
                .map(|ip| tally_core::AddressObservation {
                    address: ip.clone(),
                    role: if provider == MdmProvider::Addigy {
                        tally_core::AddressRole::LocalInterface
                    } else {
                        tally_core::AddressRole::Unknown
                    },
                    valid_from: snapshot.observed_at,
                    valid_until: None,
                    network_key: None,
                })
                .collect();
            if provider == MdmProvider::Intune {
                let mut digest = Sha256::new();
                digest.update(b"godel-tally:microsoft-defender-tenant:v1\0");
                digest.update(snapshot.tenant.as_bytes());
                let reference = format!("md1_{}", hex::encode(digest.finalize()));
                o.inventory.directory_tenant_key = Some(
                    config
                        .pseudonymization_key
                        .pseudonym_exact("directory_tenant", &reference),
                );
            }
            o.inventory.snapshot_at = Some(snapshot.observed_at);
            o.inventory.reported_at = device.observed_at;
            o.inventory.identifiers.clone_from(&device.identifiers);
            o.inventory.os.clone_from(&device.os);
            o.inventory.display_name.clone_from(&device.display_name);
            o.inventory.retired = device.retired;
            if let Some(user) = user {
                o.inventory.user_role = Some(user.role.clone());
                o.actor.identity = Some(IdentityObservation {
                    subject_key: config.pseudonymization_key.pseudonym_exact(
                        "mdm_user",
                        &format!("{}:{}:{}", provider.name(), snapshot.tenant, user.id),
                    ),
                    email: user
                        .email
                        .as_deref()
                        .and_then(crate::crowdstrike::recognized_email),
                    source_subject: Some(user.id.clone()),
                    source_subject_kind: Some(IdentitySubjectKind::SourceUserId),
                    authority: Some(IdentityAuthority::SourceNative),
                    directory_key: if provider == MdmProvider::Intune {
                        uuid::Uuid::parse_str(&user.id)
                            .ok()
                            .filter(|id| !id.is_nil())
                            .map(|id| {
                                config
                                    .pseudonymization_key
                                    .pseudonym_exact("entra_object", &id.to_string())
                            })
                    } else {
                        None
                    },
                    application_key: None,
                    display_label: user.label.clone(),
                });
            }
            observations.push(o);
        }
    }
    let accepted = observations.len() as u64;
    Ok(VendorImportOutcome {
        batch: ObservationBatch::build(observations, config.checkpoint.clone())?,
        stats: VendorImportStats {
            records_read: snapshot.devices.len() as u64,
            accepted,
            ignored: 0,
            rejected: 0,
        },
        redaction: RedactionProof {
            connector_type: provider.connector_type().into(),
            pseudonymization: "hmac_sha256_installation_key_v1".into(),
            discarded_fields: vec!["all unselected device facts and raw source bytes".into()],
            source_bytes_retained: false,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_provider_keeps_inventory_separate_from_requests_and_replay() {
        use crate::{Cursor, PseudonymizationKey};
        use uuid::Uuid;
        let config = VendorImportConfig {
            installation_id: Uuid::from_u128(1),
            connector_instance_id: Uuid::from_u128(2),
            implementation_version: "test".into(),
            source_lineage_id: Some("fixture-inventory".into()),
            received_at: "2026-10-20T00:00:01Z".parse().unwrap(),
            checkpoint: Cursor("snapshot-1".into()),
            pseudonymization_key: PseudonymizationKey::new(&[7; 32]).unwrap(),
        };
        for provider in [
            MdmProvider::Iru,
            MdmProvider::Addigy,
            MdmProvider::Intune,
            MdmProvider::Jamf,
        ] {
            let mut input = serde_json::json!({"provider":provider,"tenant":"tenant-1","observed_at":"2026-10-20T00:00:00Z","devices":[{"id":"device-1","hostname":"mac.example.test","display_name":"Alice’s MacBook","os":"macOS","observed_at":null,"addresses":["fd00::7"],"users":[{"id":"user-1","label":"Alice","email":"alice@example.test","role":"assigned_owner"}]}]});
            let first =
                import_mdm_json(&serde_json::to_vec(&input).unwrap(), provider, &config).unwrap();
            let replay =
                import_mdm_json(&serde_json::to_vec(&input).unwrap(), provider, &config).unwrap();
            let observation = &first.batch.observations[0];
            assert_eq!(
                observation.observation_id,
                replay.batch.observations[0].observation_id
            );
            assert_eq!(observation.kind, ObservationKind::NetworkMapping);
            assert!(!observation.service.ai_request);
            assert!(observation.service.declared_model_id.is_none());
            assert!(observation.process.is_empty());
            assert!(observation.inventory.reported_at.is_none());
            assert_eq!(
                observation.inventory.user_role,
                Some(IdentityRole::AssignedOwner)
            );
            input["observed_at"] = serde_json::json!("2026-10-20T01:00:00Z");
            let later =
                import_mdm_json(&serde_json::to_vec(&input).unwrap(), provider, &config).unwrap();
            assert_ne!(
                observation.observation_id,
                later.batch.observations[0].observation_id
            );
        }
    }

    #[test]
    fn origins_are_provider_scoped() {
        assert!(valid_mdm_origin(
            MdmProvider::Iru,
            "https://tenant.api.eu.kandji.io"
        ));
        assert!(!valid_mdm_origin(
            MdmProvider::Iru,
            "https://api.kandji.io.evil.test"
        ));
        assert!(!valid_mdm_origin(
            MdmProvider::Intune,
            "https://graph.microsoft.com@evil.test"
        ));
        assert!(!valid_mdm_origin(
            MdmProvider::Jamf,
            "http://us.api.jamfcloud.com"
        ));
    }
}
