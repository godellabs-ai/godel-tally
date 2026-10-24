//! Read-only inventory clients. A complete snapshot is admitted only after all pages succeed.
use crate::{JobCredentials, PreparedJob, VendorAdapter};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use tally_connectors::{
    DeviceSnapshot, InventoryUser, MdmProvider, MdmSnapshot, PseudonymizationKey,
    VendorImportConfig,
};
use tally_core::{IdentityRole, InventoryIdentifier};
use tally_store_postgres::{LeasedConnectorJob, PostgresStore};

pub(crate) async fn prepare(
    store: &PostgresStore,
    credentials: &JobCredentials,
    client: &reqwest::Client,
    job: &LeasedConnectorJob,
) -> Result<PreparedJob, &'static str> {
    prepare_inner(store, credentials, client, job)
        .await
        .map_err(|error| {
            let status = error
                .downcast_ref::<reqwest::Error>()
                .and_then(reqwest::Error::status);
            let detail = error.to_string();
            let code = match status {
                Some(reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN) => {
                    "mdm_access_denied"
                }
                Some(reqwest::StatusCode::TOO_MANY_REQUESTS) => "mdm_rate_limited",
                _ if detail.contains("pagination")
                    || detail.contains("page")
                    || detail.contains("snapshot size") =>
                {
                    "mdm_incomplete_snapshot"
                }
                _ => "mdm_inventory_sync_failed",
            };
            eprintln!("{code}: {error:#}");
            code
        })
}

async fn read_json(
    client: &reqwest::Client,
    url: reqwest::Url,
    token: &str,
    addigy: Option<Value>,
    jamf_tenant: Option<&str>,
) -> Result<Value> {
    for attempt in 0..3 {
        let mut authorization = reqwest::header::HeaderValue::from_str(token)?;
        authorization.set_sensitive(true);
        let request = if let Some(body) = &addigy {
            client
                .post(url.clone())
                .header("x-api-key", authorization)
                .json(body)
        } else {
            client.get(url.clone()).bearer_auth(token)
        };
        let request = if let Some(tenant) = jamf_tenant {
            request.header("X-Tenant-Id", tenant)
        } else {
            request
        };
        let response = request.send().await?;
        if (response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
            || response.status().is_server_error())
            && attempt < 2
        {
            let delay = response
                .headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok())
                .and_then(|h| h.parse::<u64>().ok())
                .unwrap_or(2_u64.pow(attempt + 1))
                .clamp(1, 30);
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            continue;
        }
        let bytes =
            crate::pull_support::bounded_response(response.error_for_status()?, "MDM inventory")
                .await?;
        return Ok(serde_json::from_slice(&bytes)?);
    }
    anyhow::bail!("inventory retry budget exhausted")
}

#[allow(clippy::too_many_lines)] // Keep the bounded provider acquisition/projection contract together.
async fn prepare_inner(
    store: &PostgresStore,
    credentials: &JobCredentials,
    client: &reqwest::Client,
    job: &LeasedConnectorJob,
) -> Result<PreparedJob> {
    let provider: MdmProvider = serde_json::from_value(
        job.config_refs
            .get("provider")
            .context("inventory provider")?
            .clone(),
    )?;
    ensure!(
        job.connector_type == provider.connector_type(),
        "inventory connector mismatch"
    );
    let origin = credentials
        .require("base_url")
        .map_err(|_| anyhow::anyhow!("inventory origin missing"))?;
    ensure!(
        tally_connectors::valid_mdm_origin(provider, origin),
        "invalid inventory origin"
    );
    let tenant = credentials
        .require("tenant_id")
        .map_err(|_| anyhow::anyhow!("inventory tenant missing"))?;
    ensure!(
        tenant
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
        "invalid tenant"
    );
    let token = if provider == MdmProvider::Intune {
        uuid::Uuid::parse_str(tenant)?;
        let response = client
            .post(format!(
                "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
            ))
            .form(&[
                ("grant_type", "client_credentials"),
                ("scope", "https://graph.microsoft.com/.default"),
                (
                    "client_id",
                    credentials
                        .require("client_id")
                        .map_err(|_| anyhow::anyhow!("client ID missing"))?,
                ),
                (
                    "client_secret",
                    credentials
                        .require("client_secret")
                        .map_err(|_| anyhow::anyhow!("client secret missing"))?,
                ),
            ])
            .send()
            .await?
            .error_for_status()?;
        let bytes = crate::pull_support::bounded_response(response, "Intune token").await?;
        let value: Value = serde_json::from_slice(&bytes)?;
        value["access_token"]
            .as_str()
            .context("access token missing")?
            .to_owned()
    } else {
        credentials
            .require("api_token")
            .map_err(|_| anyhow::anyhow!("inventory token missing"))?
            .to_owned()
    };
    let now = Utc::now();
    let devices = fetch_inventory(provider, origin, &token, tenant, client, now).await?;
    let checkpoint = format!("mdm-v1:{}", now.timestamp_millis());
    let descriptor = provider.descriptor();
    if devices.is_empty() {
        let before = store
            .connector_cursor(job.connector_instance_id)
            .await?
            .unwrap_or_default();
        return Ok(PreparedJob::EmptyPoll {
            descriptor,
            cursor_before: before,
            cursor_after: checkpoint,
        });
    }
    let input = serde_json::to_vec(&MdmSnapshot {
        provider,
        tenant: tenant.into(),
        observed_at: now,
        devices,
    })?;
    let identity = store.get_or_create_installation_identity().await?;
    let lineage = format!("mdm:{}", provider.name());
    let config = VendorImportConfig {
        installation_id: identity.installation_id,
        connector_instance_id: job.connector_instance_id,
        source_lineage_id: Some(lineage.clone()),
        implementation_version: env!("CARGO_PKG_VERSION").into(),
        received_at: now,
        checkpoint: tally_connectors::Cursor(checkpoint.clone()),
        pseudonymization_key: PseudonymizationKey::new(identity.pseudonymization_key())?,
    };
    let normalized = tally_connectors::import_mdm_json(&input, provider, &config)?;
    let adapter = match provider {
        MdmProvider::Iru => VendorAdapter::IruInventory,
        MdmProvider::Addigy => VendorAdapter::AddigyInventory,
        MdmProvider::Intune => VendorAdapter::IntuneInventory,
        MdmProvider::Jamf => VendorAdapter::JamfInventory,
    };
    Ok(PreparedJob::Source {
        descriptor,
        adapter,
        input,
        checkpoint,
        source_lineage_id: lineage,
        expected_canonical_digest: normalized.batch.receipt.canonical_digest,
        cloud: None,
        casb_account_id: None,
    })
}

#[allow(clippy::too_many_lines)] // Keep the bounded provider acquisition/projection contract together.
async fn fetch_inventory(
    provider: MdmProvider,
    origin: &str,
    token: &str,
    tenant: &str,
    client: &reqwest::Client,
    now: DateTime<Utc>,
) -> Result<Vec<DeviceSnapshot>> {
    let base = reqwest::Url::parse(origin)?;
    let mut devices = Vec::new();
    let mut next: Option<String> = None;
    let mut finished = false;
    let mut seen_urls = std::collections::BTreeSet::new();
    let mut seen_devices = std::collections::BTreeSet::new();
    for page in 0..100_usize {
        let mut url = if let Some(next) = next.take() {
            reqwest::Url::parse(&next)?
        } else {
            base.join(match provider {
                MdmProvider::Iru => "/api/v1/devices",
                MdmProvider::Addigy => "/api/v2/devices",
                MdmProvider::Intune => "/v1.0/deviceManagement/managedDevices",
                MdmProvider::Jamf => "/pro/v4/computers-inventory",
            })?
        };
        ensure!(
            url.origin() == base.origin(),
            "cross-origin inventory pagination rejected"
        );
        if provider == MdmProvider::Addigy {
            url.set_path(&format!("/api/v2/o/{tenant}/devices"));
        }
        ensure!(
            url.username().is_empty() && url.password().is_none() && url.fragment().is_none(),
            "invalid inventory continuation"
        );
        if provider == MdmProvider::Intune {
            ensure!(
                url.path() == "/v1.0/deviceManagement/managedDevices",
                "inventory continuation changed dataset"
            );
        }
        let body = match provider {
            MdmProvider::Iru => {
                url.query_pairs_mut()
                    .append_pair("limit", "100")
                    .append_pair("offset", &(page * 100).to_string());
                None
            }
            MdmProvider::Addigy => Some(
                json!({"page":page+1,"per_page":100,"desired_fact_identifiers":["device_name","host_name","os_version","serial_number","local_ip","current_user","identity_users","last_online","mac_uuid"],"query":{"filters":[]}}),
            ),
            MdmProvider::Intune => {
                if page == 0 {
                    url.query_pairs_mut().append_pair("$top","100").append_pair("$select","id,deviceName,azureADDeviceId,operatingSystem,osVersion,serialNumber,lastSyncDateTime,userId,userPrincipalName,userDisplayName");
                }
                None
            }
            MdmProvider::Jamf => {
                url.query_pairs_mut()
                    .append_pair("page", &page.to_string())
                    .append_pair("page-size", "100")
                    .append_pair("section", "GENERAL")
                    .append_pair("section", "HARDWARE")
                    .append_pair("section", "OPERATING_SYSTEM")
                    .append_pair("section", "USER_AND_LOCATION");
                None
            }
        };
        ensure!(
            seen_urls.insert(format!(
                "{}:{}",
                url.as_str(),
                body.as_ref().map_or_else(String::new, Value::to_string)
            )),
            "inventory pagination cursor repeated"
        );
        let value = read_json(
            client,
            url,
            token,
            body,
            (provider == MdmProvider::Jamf).then_some(tenant),
        )
        .await?;
        let rows = value
            .as_array()
            .or_else(|| {
                value
                    .get(match provider {
                        MdmProvider::Addigy => "items",
                        MdmProvider::Intune => "value",
                        _ => "results",
                    })
                    .and_then(Value::as_array)
            })
            .context("inventory page has no device array")?;
        for row in rows {
            if provider == MdmProvider::Addigy {
                ensure!(
                    row["orgid"].as_str() == Some(tenant),
                    "Addigy response organization differs from configured scope"
                );
            }
            let mut device = project_device(provider, row, now)?;
            ensure!(
                seen_devices.insert(device.id.clone()),
                "inventory device repeated across pages; retry the complete snapshot"
            );
            if provider == MdmProvider::Iru {
                ensure!(
                    device
                        .id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                    "invalid device ID"
                );
                tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                let detail = read_json(
                    client,
                    base.join(&format!("/api/v1/devices/{}/details", device.id))?,
                    token,
                    None,
                    None,
                )
                .await?;
                append_addresses(
                    &mut device,
                    &detail,
                    &[
                        "/network/local_ip",
                        "/network/ip_address",
                        "/general/ip_address",
                    ],
                );
            }
            devices.push(device);
            ensure!(
                devices.len() <= 5_000,
                "inventory exceeds supported snapshot size"
            );
        }
        let more = match provider {
            MdmProvider::Intune => {
                next = value
                    .get("@odata.nextLink")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                next.is_some()
            }
            MdmProvider::Addigy => {
                let pages = value
                    .pointer("/metadata/page_count")
                    .and_then(Value::as_u64)
                    .context("Addigy page count missing")?;
                page + 1 < usize::try_from(pages)?
            }
            MdmProvider::Jamf => {
                let total = value
                    .get("totalCount")
                    .and_then(Value::as_u64)
                    .context("Jamf total count missing")?;
                devices.len() < usize::try_from(total)?
            }
            MdmProvider::Iru => rows.len() == 100,
        };
        if !more {
            finished = true;
            break;
        }
        ensure!(!rows.is_empty(), "empty inventory page with continuation");
    }
    ensure!(
        finished,
        "inventory pagination budget exhausted; no partial snapshot admitted"
    );
    Ok(devices)
}

fn text(value: &Value, paths: &[&str]) -> Option<String> {
    paths
        .iter()
        .find_map(|p| {
            value.pointer(p).and_then(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .or_else(|| v.as_u64().map(|v| v.to_string()))
            })
        })
        .filter(|v| !v.is_empty() && v.len() <= 512 && !v.chars().any(char::is_control))
}
fn append_addresses(device: &mut DeviceSnapshot, value: &Value, paths: &[&str]) {
    for path in paths {
        if let Some(ip) = text(value, &[path]).and_then(|v| tally_core::IpAddress::parse(&v).ok()) {
            device.addresses.push(ip.as_str().to_owned());
        }
    }
    device.addresses.sort();
    device.addresses.dedup();
}

#[allow(clippy::too_many_lines)] // Explicit field/role allowlists for all supported inventory providers.
fn project_device(
    provider: MdmProvider,
    row: &Value,
    _now: DateTime<Utc>,
) -> Result<DeviceSnapshot> {
    let id = text(row, &["/id", "/device_id", "/agentid"]).context("device ID missing")?;
    let hostname = text(
        row,
        &[
            "/deviceName",
            "/device_name",
            "/general/name",
            "/facts/host_name/value",
            "/facts/device_name/value",
        ],
    )
    .and_then(|s| tally_core::Hostname::parse(&s).ok())
    .map(|v| v.as_str().to_owned());
    let observed_at = text(
        row,
        &[
            "/lastSyncDateTime",
            "/last_check_in",
            "/general/reportDate",
            "/general/lastCheckIn",
            "/facts/last_online/value",
            "/agent_audit_date",
            "/audit_date",
        ],
    )
    .and_then(|v| v.parse().ok());
    let os = text(
        row,
        &[
            "/operatingSystem/name",
            "/operatingSystem",
            "/os_version",
            "/facts/os_version/value",
        ],
    );
    let mut identifiers = Vec::new();
    for (kind, paths) in [
        (
            "serial",
            vec![
                "/serialNumber",
                "/serial_number",
                "/hardware/serialNumber",
                "/facts/serial_number/value",
            ],
        ),
        ("entra_device_id", vec!["/azureADDeviceId"]),
        (
            "hardware_uuid",
            vec!["/udid", "/hardware/udid", "/facts/mac_uuid/value"],
        ),
    ] {
        if let Some(value) = text(row, &paths) {
            identifiers.push(InventoryIdentifier {
                kind: kind.into(),
                value,
            });
        }
    }
    let mut users = Vec::new();
    let (user_id, email, label, role) = match provider {
        MdmProvider::Iru => (
            text(row, &["/user/id", "/assigned_user/id"]),
            text(row, &["/user/email", "/assigned_user/email"]),
            text(row, &["/user/name", "/assigned_user/name"]),
            IdentityRole::AssignedOwner,
        ),
        MdmProvider::Intune => (
            text(row, &["/userId"]),
            text(row, &["/userPrincipalName"]),
            text(row, &["/userDisplayName"]),
            IdentityRole::AssociatedUser,
        ),
        MdmProvider::Addigy => (
            text(row, &["/facts/current_user/value"]),
            None,
            text(row, &["/facts/current_user/value"]),
            IdentityRole::LastLoggedIn,
        ),
        MdmProvider::Jamf => (
            text(row, &["/userAndLocation/username"]),
            text(row, &["/userAndLocation/email"]),
            text(row, &["/userAndLocation/realname"]),
            IdentityRole::AssignedOwner,
        ),
    };
    if let Some(id) = if provider == MdmProvider::Addigy {
        user_id.map(|user| format!("device:{id}:account:{user}"))
    } else if provider == MdmProvider::Jamf {
        email
            .clone()
            .or_else(|| user_id.map(|user| format!("device:{id}:assigned:{user}")))
    } else {
        user_id.or_else(|| email.clone())
    } {
        users.push(InventoryUser {
            id,
            label,
            email,
            role,
        });
    }
    if provider == MdmProvider::Addigy
        && let Some(accounts) = row
            .pointer("/facts/identity_users/value")
            .and_then(Value::as_array)
    {
        ensure!(
            accounts.len() <= 32,
            "too many identity accounts on one device"
        );
        for account in accounts {
            if let Some(name) = account
                .as_str()
                .filter(|v| !v.is_empty() && v.len() <= 256 && !v.chars().any(char::is_control))
            {
                users.push(InventoryUser {
                    id: format!("device:{id}:idp-account:{name}"),
                    label: Some(name.into()),
                    email: None,
                    role: IdentityRole::AssociatedUser,
                });
            }
        }
    }
    if provider == MdmProvider::Jamf
        && let Some(name) = text(row, &["/general/lastLoggedInUsernameBinary"])
    {
        users.push(InventoryUser {
            id: format!("device:{id}:login:{name}"),
            label: Some(name),
            email: None,
            role: IdentityRole::LastLoggedIn,
        });
    }
    let mut device = DeviceSnapshot {
        id,
        hostname,
        display_name: text(
            row,
            &[
                "/deviceName",
                "/device_name",
                "/general/name",
                "/facts/device_name/value",
            ],
        ),
        os,
        observed_at,
        identifiers,
        addresses: Vec::new(),
        users,
        retired: false,
    };
    append_addresses(
        &mut device,
        row,
        &[
            "/general/lastReportedIp",
            "/general/lastReportedIpV4",
            "/general/lastReportedIpV6",
            "/general/lastIpAddress",
            "/ip_address",
            "/facts/local_ip/value",
        ],
    );
    Ok(device)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn intune_inventory_does_not_invent_an_ip_or_primary_user() {
        let d=project_device(MdmProvider::Intune,&json!({"id":"d1","deviceName":"workstation","userId":"u1","userPrincipalName":"user@example.test","lastSyncDateTime":"2026-10-01T12:00:00Z"}),Utc::now()).unwrap();
        assert_eq!(d.addresses, Vec::<String>::new());
        assert_eq!(d.users[0].role, IdentityRole::AssociatedUser);
        assert_eq!(
            d.observed_at,
            Some("2026-10-01T12:00:00Z".parse::<DateTime<Utc>>().unwrap())
        );
    }
    #[test]
    fn addigy_reads_fact_values_and_never_retains_unrelated_facts() {
        let d=project_device(MdmProvider::Addigy,&json!({"agentid":"a1","facts":{"host_name":{"value":"mac.example.test"},"local_ip":{"value":"10.0.0.8"},"current_user":{"value":"alex"},"recovery_key":{"value":"SECRET-CANARY"}}}),Utc::now()).unwrap();
        assert_eq!(d.addresses, ["10.0.0.8"]);
        assert!(!serde_json::to_string(&d).unwrap().contains("SECRET-CANARY"));
        assert_eq!(d.users[0].role, IdentityRole::LastLoggedIn);
    }

    #[tokio::test]
    async fn addigy_acquisition_uses_read_only_search_and_complete_pagination() {
        use axum::{Json, Router, extract::Path, http::HeaderMap, routing::post};
        let server=Router::new().route("/api/v2/o/{org}/devices",post(|Path(org):Path<String>,headers:HeaderMap,Json(body):Json<Value>|async move{
            assert_eq!(org,"test-org");assert_eq!(headers["x-api-key"],"fixture-read-token");
            assert!(body["desired_fact_identifiers"].as_array().unwrap().contains(&json!("current_user")));
            let page=body["page"].as_u64().unwrap();
            Json(json!({"items":[{"agentid":format!("device-{page}"),"orgid":"test-org","facts":{"host_name":{"value":format!("host-{page}.example.test")},"current_user":{"value":"alex"}}}],"metadata":{"page_count":2}}))
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, server).await.unwrap();
        });
        let devices = fetch_inventory(
            MdmProvider::Addigy,
            &format!("http://{address}"),
            "fixture-read-token",
            "test-org",
            &reqwest::Client::new(),
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[1].hostname.as_deref(), Some("host-2.example.test"));
        task.abort();
    }

    #[tokio::test]
    async fn intune_continuations_cannot_leak_credentials_to_another_origin_or_dataset() {
        use axum::{Json, Router, routing::get};
        let server = Router::new().route(
            "/v1.0/deviceManagement/managedDevices",
            get(|| async {
                Json(json!({"value":[],"@odata.nextLink":"https://attacker.example/steal"}))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, server).await.unwrap();
        });
        let error = fetch_inventory(
            MdmProvider::Intune,
            &format!("http://{address}"),
            "fixture-token",
            "tenant",
            &reqwest::Client::new(),
            Utc::now(),
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("empty inventory page")
                || error.to_string().contains("cross-origin")
        );
        task.abort();
    }

    #[tokio::test]
    async fn iru_reads_device_details_without_any_management_actions() {
        use axum::{Json, Router, routing::get};
        let server=Router::new().route("/api/v1/devices",get(||async{Json(json!([{"device_id":"device-1","device_name":"mac.example.test","user":{"id":"owner-1","email":"owner@example.test"}}]))}))
            .route("/api/v1/devices/device-1/details",get(||async{Json(json!({"network":{"local_ip":"10.0.0.8"},"recovery_key":"SECRET-CANARY"}))}));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, server).await.unwrap();
        });
        let devices = fetch_inventory(
            MdmProvider::Iru,
            &format!("http://{address}"),
            "fixture-token",
            "tenant",
            &reqwest::Client::new(),
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(devices[0].addresses, ["10.0.0.8"]);
        assert_eq!(devices[0].users[0].role, IdentityRole::AssignedOwner);
        assert!(
            !serde_json::to_string(&devices)
                .unwrap()
                .contains("SECRET-CANARY")
        );
        task.abort();
    }

    #[tokio::test]
    async fn jamf_requests_inventory_sections_and_keeps_pages_separate() {
        use axum::{Json, Router, extract::Query, routing::get};
        let server=Router::new().route("/pro/v4/computers-inventory",get(|Query(query):Query<Vec<(String,String)>>|async move{
            assert!(query.iter().any(|v|v==&("section".into(),"HARDWARE".into())));
            let page=query.iter().find(|(k,_)|k=="page").unwrap().1.clone();
            Json(json!({"results":[{"id":format!("device-{page}"),"general":{"name":format!("mac-{page}")},"hardware":{"serialNumber":format!("serial-{page}")}}],"totalCount":2}))
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, server).await.unwrap();
        });
        let devices = fetch_inventory(
            MdmProvider::Jamf,
            &format!("http://{address}"),
            "fixture-token",
            "tenant",
            &reqwest::Client::new(),
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[1].identifiers[0].value, "serial-1");
        task.abort();
    }
}
