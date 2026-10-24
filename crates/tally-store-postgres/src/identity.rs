//! Installation-scoped, immutable source facts and reversible operator corrections.
use crate::{PostgresStore, PostgresStoreError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tally_core::{ActivityAttribution, IdentityRole, Observation};
use uuid::Uuid;

type DeviceFactRow = (
    Uuid,
    Uuid,
    Uuid,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    bool,
    Value,
);
type InventoryRow = (Uuid, String, DateTime<Utc>, DateTime<Utc>, Value);

fn process_key(process: &tally_core::ProcessObservation) -> Option<String> {
    process
        .unique_id
        .as_ref()
        .map(|v| format!("native:{v}"))
        .or_else(|| {
            process
                .pid
                .as_ref()
                .zip(process.started_at)
                .map(|(pid, start)| format!("pid:{pid}:{}", start.timestamp_millis()))
        })
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IdentityRecord {
    pub entity_id: Uuid,
    pub entity_kind: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub facts: Vec<Value>,
}

pub fn identity_ids(o: &Observation) -> (Option<Uuid>, Option<Uuid>, String) {
    let scope = o
        .saas
        .tenant_key
        .as_deref()
        .or(o.cloud.account_key.as_deref())
        .unwrap_or("source")
        .to_owned();
    let id = |kind: &str, key: &str| {
        Uuid::new_v5(
            &o.installation_id,
            format!(
                "identity:v1:{}:{scope}:{kind}:{key}",
                o.connector.instance_id
            )
            .as_bytes(),
        )
    };
    let directory_device = o
        .inventory
        .directory_tenant_key
        .as_ref()
        .and_then(|tenant| {
            o.inventory
                .identifiers
                .iter()
                .find(|i| i.kind == "entra_device_id")
                .and_then(|i| Uuid::parse_str(&i.value).ok())
                .filter(|id| !id.is_nil())
                .map(|device| {
                    Uuid::new_v5(
                        &o.installation_id,
                        format!("directory-device:v1:{tenant}:{device}").as_bytes(),
                    )
                })
        });
    let stable = matches!(
        o.inventory.device_key_kind,
        Some(
            tally_core::DeviceIdentifierKind::SourceNative
                | tally_core::DeviceIdentifierKind::ClientSupplied
        )
    );
    let device = directory_device
        .or_else(|| {
            if stable {
                o.actor.device_key.as_deref().map(|v| id("device", v))
            } else {
                None
            }
        })
        .or_else(|| {
            (o.actor.device_key.is_some()
                || o.actor.hostname.is_some()
                || o.actor.source_ip.is_some()
                || !o.actor.additional_source_ips.is_empty())
            .then(|| {
                Uuid::new_v5(
                    &o.installation_id,
                    format!(
                        "unresolved-device:v1:{}:{}",
                        o.connector.instance_id, o.observation_id
                    )
                    .as_bytes(),
                )
            })
        });
    let user = o.actor.identity.as_ref().map(|identity| {
        o.inventory
            .directory_tenant_key
            .as_ref()
            .zip(identity.directory_key.as_ref())
            .map_or_else(
                || id("user", &identity.subject_key),
                |(tenant, key)| {
                    Uuid::new_v5(
                        &o.installation_id,
                        format!("directory-user:v1:{tenant}:{key}").as_bytes(),
                    )
                },
            )
    });
    (device, user, scope)
}

impl PostgresStore {
    /// Records absence only after a complete snapshot; source facts from other connectors survive.
    ///
    /// # Errors
    /// Returns an error if source validation or the database operation fails.
    pub async fn complete_inventory_snapshot(
        &self,
        installation: Uuid,
        connector: Uuid,
        at: DateTime<Utc>,
        seen: &[String],
    ) -> Result<(), PostgresStoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(installation.to_string())
            .execute(&mut *tx)
            .await?;
        Self::inventory_presence_in_transaction(&mut tx, installation, connector, at, seen).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn inventory_presence_in_transaction(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        installation: Uuid,
        connector: Uuid,
        at: DateTime<Utc>,
        seen: &[String],
    ) -> Result<(), PostgresStoreError> {
        let changed=sqlx::query("INSERT INTO inventory_sync_status(installation_id,connector_instance_id,completed_at,device_count) VALUES($1,$2,$3,$4) ON CONFLICT(installation_id,connector_instance_id) DO UPDATE SET completed_at=EXCLUDED.completed_at,device_count=EXCLUDED.device_count WHERE inventory_sync_status.completed_at<EXCLUDED.completed_at")
            .bind(installation).bind(connector).bind(at).bind(i64::try_from(seen.len()).unwrap_or(i64::MAX)).execute(&mut **tx).await?.rows_affected();
        if changed == 0 {
            return Ok(());
        }
        sqlx::query("INSERT INTO inventory_presence_events(installation_id,connector_instance_id,device_key,observed_at,present) SELECT installation_id,connector_instance_id,device_key,$3,false FROM inventory_source_presence WHERE installation_id=$1 AND connector_instance_id=$2 AND last_snapshot_at<$3 AND retired_at IS NULL AND NOT(device_key=ANY($4)) ON CONFLICT DO NOTHING")
            .bind(installation).bind(connector).bind(at).bind(seen).execute(&mut **tx).await?;
        sqlx::query("UPDATE inventory_source_presence SET retired_at=COALESCE(retired_at,$3),last_snapshot_at=$3 WHERE installation_id=$1 AND connector_instance_id=$2 AND last_snapshot_at<$3 AND NOT(device_key=ANY($4))")
            .bind(installation).bind(connector).bind(at).bind(seen).execute(&mut **tx).await?;
        for key in seen {
            sqlx::query("INSERT INTO inventory_presence_events(installation_id,connector_instance_id,device_key,observed_at,present) SELECT $1,$2,$3,$4,true WHERE NOT EXISTS(SELECT 1 FROM inventory_source_presence WHERE installation_id=$1 AND connector_instance_id=$2 AND device_key=$3 AND (retired_at IS NULL OR last_snapshot_at>=$4)) ON CONFLICT DO NOTHING")
                .bind(installation).bind(connector).bind(key).bind(at).execute(&mut **tx).await?;
            sqlx::query("INSERT INTO inventory_source_presence(installation_id,connector_instance_id,device_key,last_snapshot_at) VALUES($1,$2,$3,$4) ON CONFLICT(installation_id,connector_instance_id,device_key) DO UPDATE SET last_snapshot_at=EXCLUDED.last_snapshot_at,retired_at=NULL WHERE inventory_source_presence.last_snapshot_at<EXCLUDED.last_snapshot_at")
                .bind(installation).bind(connector).bind(key).bind(at).execute(&mut **tx).await?;
        }
        sqlx::query("INSERT INTO identity_replay_jobs(installation_id) VALUES($1) ON CONFLICT(installation_id) DO UPDATE SET requested_generation=identity_replay_jobs.requested_generation+1,updated_at=now()")
            .bind(installation).execute(&mut **tx).await?;
        Ok(())
    }
    /// Historical identity snapshots expire separately from the latest durable inventory fact.
    ///
    /// # Errors
    /// Returns an error if source validation or the database operation fails.
    pub async fn maintain_identity_history(
        &self,
        installation: Uuid,
        history_days: u16,
        activity_days: u16,
    ) -> Result<(), PostgresStoreError> {
        let history = Utc::now() - chrono::Duration::days(i64::from(history_days.max(1)));
        let activity = Utc::now() - chrono::Duration::days(i64::from(activity_days.max(1)));
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM identity_facts WHERE fact_id IN (SELECT f.fact_id FROM identity_facts f WHERE f.installation_id=$1 AND f.last_seen<$2 AND EXISTS(SELECT 1 FROM identity_facts newer WHERE newer.installation_id=f.installation_id AND newer.entity_id=f.entity_id AND newer.connector_instance_id=f.connector_instance_id AND newer.observed_at>f.observed_at) ORDER BY f.observed_at LIMIT 1000)")
            .bind(installation).bind(history).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM identity_links WHERE ctid IN(SELECT ctid FROM identity_links WHERE installation_id=$1 AND valid_until<$2 LIMIT 1000)")
            .bind(installation).bind(history).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM finding_activity WHERE (finding_id,observation_id) IN(SELECT finding_id,observation_id FROM finding_activity WHERE installation_id=$1 AND observed_at<$2 ORDER BY observed_at LIMIT 1000)")
            .bind(installation).bind(activity).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM endpoint_process_facts WHERE (installation_id,connector_instance_id,observation_id) IN(SELECT installation_id,connector_instance_id,observation_id FROM endpoint_process_facts WHERE installation_id=$1 AND observed_at<$2 ORDER BY observed_at LIMIT 1000)").bind(installation).bind(activity).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM identity_enrichments e WHERE installation_id=$1 AND NOT EXISTS(SELECT 1 FROM finding_activity a WHERE a.installation_id=e.installation_id AND a.observation_id=e.observation_id)")
            .bind(installation).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    ///
    /// # Errors
    /// Returns an error if source validation or the database operation fails.
    pub async fn identity_inventory_count(
        &self,
        installation: Uuid,
        before: Option<DateTime<Utc>>,
    ) -> Result<u64, PostgresStoreError> {
        let (count,):(i64,)=sqlx::query_as("SELECT count(DISTINCT entity_id) FROM identity_facts WHERE installation_id=$1 AND ($2::timestamptz IS NULL OR last_seen<$2)").bind(installation).bind(before).fetch_one(&self.pool).await?;
        Ok(u64::try_from(count).unwrap_or(0))
    }
    /// Resolves only bounded event-time source facts. Derived results never overwrite the event.
    ///
    /// # Errors
    /// Returns an error if source validation or the database operation fails.
    pub async fn activity_identity_context(
        &self,
        installation: Uuid,
        activity: &ActivityAttribution,
    ) -> Result<Value, PostgresStoreError> {
        use tally_resolve::identity::{DeviceEvidence, resolve_device};
        let scope = activity
            .source_scope
            .clone()
            .unwrap_or_else(|| "source".into());
        let rows:Vec<DeviceFactRow> = sqlx::query_as(
            "SELECT COALESCE(c.target_id,alias.entity_id,f.entity_id),f.connector_instance_id,f.observation_id,f.observed_at,f.valid_until,NOT f.retired AND s.connector_instance_id IS NOT NULL AND COALESCE(j.status='enabled',true) AND COALESCE((SELECT p.present FROM inventory_presence_events p WHERE p.installation_id=f.installation_id AND p.connector_instance_id=f.connector_instance_id AND p.device_key=f.attributes->>'device_key' AND p.observed_at<=$3 ORDER BY p.observed_at DESC LIMIT 1),true),f.attributes FROM identity_facts f LEFT JOIN LATERAL (SELECT min(a.entity_id::text)::uuid AS entity_id FROM identity_device_aliases a WHERE a.installation_id=f.installation_id AND a.connector_instance_id=f.connector_instance_id AND a.source_scope=f.source_scope AND a.device_key=f.attributes->>'device_key' AND a.valid_from<=$3 AND (a.valid_until IS NULL OR a.valid_until>$3) HAVING count(DISTINCT a.entity_id)=1) alias ON true LEFT JOIN identity_corrections c ON c.installation_id=f.installation_id AND c.subject_id=COALESCE(alias.entity_id,f.entity_id) AND c.undone_at IS NULL LEFT JOIN connector_states s ON s.installation_id=f.installation_id AND s.connector_instance_id=f.connector_instance_id LEFT JOIN connector_jobs j ON j.connector_instance_id=f.connector_instance_id WHERE f.installation_id=$1 AND f.entity_kind='device' AND f.source_scope=$2 AND f.observed_at<=$3 AND ((f.connector_instance_id=$4 AND $5::text IS NOT NULL AND f.attributes->>'device_key'=$5) OR ($6::text IS NOT NULL AND f.attributes->>'network_key'=$6 AND f.valid_until>=$3)) ORDER BY f.observed_at DESC LIMIT 500")
            .bind(installation).bind(&scope).bind(activity.observed_at).bind(activity.connector.instance_id).bind(&activity.actor.device_key).bind(&activity.network.network_key).fetch_all(&self.pool).await?;
        let candidates = rows
            .into_iter()
            .map(
                |(
                    entity_id,
                    connector_id,
                    observation_id,
                    observed_at,
                    valid_until,
                    active,
                    attributes,
                )| DeviceEvidence {
                    installation_id: installation,
                    entity_id,
                    connector_id,
                    observation_id,
                    observed_at,
                    valid_until,
                    active,
                    source_scope: scope.clone(),
                    network_key: attributes["network_key"].as_str().map(str::to_owned),
                    device_key: attributes["device_key"].as_str().map(str::to_owned),
                    hostname: attributes["hostname"].as_str().map(str::to_owned),
                    addresses: serde_json::from_value(attributes["addresses"].clone())
                        .unwrap_or_default(),
                },
            )
            .collect::<Vec<_>>();
        let mut addresses = activity.actor.additional_source_ips.clone();
        addresses.extend(activity.actor.source_ip.clone());
        let event = DeviceEvidence {
            installation_id: installation,
            entity_id: Uuid::nil(),
            connector_id: activity.connector.instance_id,
            observation_id: activity.observation_id,
            source_scope: scope,
            network_key: activity.network.network_key.clone(),
            device_key: if matches!(
                activity.device_key_kind,
                Some(
                    tally_core::DeviceIdentifierKind::SourceNative
                        | tally_core::DeviceIdentifierKind::ClientSupplied
                )
            ) {
                activity.actor.device_key.clone()
            } else {
                None
            },
            hostname: activity.actor.hostname.clone(),
            addresses,
            observed_at: activity.observed_at,
            valid_until: None,
            active: true,
        };
        let resolution = resolve_device(&event, &candidates);
        let mut process_context = Value::Null;
        if activity.process.executable.is_none()
            && let (Some(key), Some(device)) = (
                process_key(&activity.process),
                activity.actor.device_key.as_ref(),
            )
        {
            let process_rows:Vec<(Value,Uuid,DateTime<Utc>)>=sqlx::query_as("SELECT context,observation_id,observed_at FROM endpoint_process_facts WHERE installation_id=$1 AND connector_instance_id=$2 AND source_scope=$3 AND device_key=$4 AND process_key=$5 AND observed_at<=$6 AND EXISTS(SELECT 1 FROM connector_states s LEFT JOIN connector_jobs j ON j.connector_instance_id=s.connector_instance_id WHERE s.installation_id=endpoint_process_facts.installation_id AND s.connector_instance_id=endpoint_process_facts.connector_instance_id AND COALESCE(j.status='enabled',true)) ORDER BY observed_at DESC LIMIT 100")
                    .bind(installation).bind(activity.connector.instance_id).bind(&event.source_scope).bind(device).bind(key).bind(activity.observed_at).fetch_all(&self.pool).await?;
            if let Some((context, observation, time)) = process_rows.first() {
                let conflict = process_rows
                    .iter()
                    .any(|(other, _, _)| other["process"] != context["process"]);
                process_context = json!({"status":if conflict{"ambiguous"}else{"correlated"},"process":if conflict{Value::Null}else{context["process"].clone()},"process_account":if conflict{Value::Null}else{context["identity"].clone()},"observation_id":observation,"observed_at":time,"reason":"Same installation, connector, source scope, device and native process ID (or PID with exact start time). No model or request actor is inferred."});
            }
        }
        let relationships: Vec<(Value,)> = if let Some(device) = resolution.device_id {
            sqlx::query_as("SELECT DISTINCT ON(l.connector_instance_id,l.user_id,l.role) jsonb_build_object('user_id',l.user_id,'role',l.role,'status','candidate','valid_from',l.valid_from,'valid_until',l.valid_until,'observation_id',l.observation_id,'connector_instance_id',l.connector_instance_id) FROM identity_links l LEFT JOIN identity_corrections c ON c.installation_id=l.installation_id AND c.subject_id=l.device_id AND c.undone_at IS NULL WHERE l.installation_id=$1 AND EXISTS(SELECT 1 FROM connector_states state LEFT JOIN connector_jobs job ON job.connector_instance_id=state.connector_instance_id WHERE state.installation_id=l.installation_id AND state.connector_instance_id=l.connector_instance_id AND COALESCE(job.status='enabled',true)) AND NOT EXISTS(SELECT 1 FROM identity_facts fact WHERE fact.installation_id=l.installation_id AND fact.connector_instance_id=l.connector_instance_id AND fact.observation_id=l.observation_id AND fact.entity_kind='device' AND (SELECT presence.present FROM inventory_presence_events presence WHERE presence.installation_id=fact.installation_id AND presence.connector_instance_id=fact.connector_instance_id AND presence.device_key=fact.attributes->>'device_key' AND presence.observed_at<=$3 ORDER BY presence.observed_at DESC LIMIT 1)=false) AND COALESCE(c.target_id,l.device_id)=$2 AND l.valid_from<=$3 AND (l.valid_until IS NULL OR l.valid_until>=$3) AND l.role NOT IN ('request_actor','process_account') ORDER BY l.connector_instance_id,l.user_id,l.role,l.valid_from DESC LIMIT 50")
                .bind(installation).bind(device).bind(activity.observed_at).fetch_all(&self.pool).await?
        } else {
            Vec::new()
        };
        Ok(
            json!({"device":resolution,"process":process_context,"related_users":relationships.into_iter().map(|v|v.0).collect::<Vec<_>>(),"request_actor_inferred":false}),
        )
    }

    /// Re-enrich a bounded page, keeping a durable generation and cursor across restarts.
    ///
    /// # Errors
    /// Returns an error if source validation or the database operation fails.
    pub async fn process_identity_replay(&self) -> Result<u64, PostgresStoreError> {
        let mut tx = self.pool.begin().await?;
        let job:Option<(Uuid,i64,i64,i64,Uuid)>=sqlx::query_as("SELECT installation_id,requested_generation,scan_generation,completed_generation,last_observation_id FROM identity_replay_jobs WHERE requested_generation>completed_generation ORDER BY updated_at LIMIT 1 FOR UPDATE SKIP LOCKED").fetch_optional(&mut *tx).await?;
        let Some((
            installation,
            requested_generation,
            scan_generation,
            completed_generation,
            previous,
        )) = job
        else {
            return Ok(0);
        };
        let generation = if scan_generation > completed_generation {
            scan_generation
        } else {
            requested_generation
        };
        let after = if scan_generation > completed_generation {
            previous
        } else {
            Uuid::nil()
        };
        let rows:Vec<(Uuid,Value)>=sqlx::query_as("SELECT DISTINCT ON(observation_id) observation_id,context FROM finding_activity WHERE installation_id=$1 AND observation_id>$2 ORDER BY observation_id LIMIT 50").bind(installation).bind(after).fetch_all(&mut *tx).await?;
        for (observation, context) in &rows {
            let activity: ActivityAttribution = serde_json::from_value(context.clone())?;
            let enriched = self
                .activity_identity_context(installation, &activity)
                .await?;
            sqlx::query("INSERT INTO identity_enrichments(installation_id,observation_id,rule_version,context) VALUES($1,$2,$3,$4) ON CONFLICT(installation_id,observation_id) DO UPDATE SET rule_version=EXCLUDED.rule_version,context=EXCLUDED.context,updated_at=now()")
                .bind(installation).bind(observation).bind(tally_resolve::identity::IDENTITY_RULE_VERSION).bind(enriched).execute(&mut *tx).await?;
        }
        let finished = rows.len() < 50;
        sqlx::query("UPDATE identity_replay_jobs SET scan_generation=$2,completed_generation=CASE WHEN $3 THEN $2 ELSE completed_generation END,last_observation_id=$4,processed_count=processed_count+$5,updated_at=now() WHERE installation_id=$1")
            .bind(installation).bind(generation).bind(finished).bind(rows.last().map_or(after,|r|r.0)).bind(i64::try_from(rows.len()).unwrap_or(50)).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(rows.len() as u64)
    }

    ///
    /// # Errors
    /// Returns an error if source validation or the database operation fails.
    pub async fn identity_replay_status(
        &self,
        installation: Uuid,
    ) -> Result<Value, PostgresStoreError> {
        let row: Option<(Value,)> = sqlx::query_as(
            "SELECT to_jsonb(j) FROM identity_replay_jobs j WHERE installation_id=$1",
        )
        .bind(installation)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map_or(Value::Null, |r| r.0))
    }

    /// Persist identity facts before AI admission. Replaying a source event is a no-op.
    ///
    /// # Errors
    /// Returns an error if source validation or the database operation fails.
    #[allow(clippy::too_many_lines)] // Source facts, aliases and complete-snapshot presence commit atomically.
    pub async fn record_identity_observations(
        &self,
        observations: &[Observation],
    ) -> Result<(), PostgresStoreError> {
        let mut tx = self.pool.begin().await?;
        let installations = observations
            .iter()
            .map(|o| o.installation_id)
            .collect::<std::collections::BTreeSet<_>>();
        for installation in installations {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                .bind(installation.to_string())
                .execute(&mut *tx)
                .await?;
        }
        let mut changed = std::collections::BTreeSet::new();
        for o in observations {
            let (device, user, scope) = identity_ids(o);
            if o.process.executable.is_some()
                && let (Some(key), Some(device_key)) =
                    (process_key(&o.process), o.actor.device_key.as_ref())
            {
                let written=sqlx::query("INSERT INTO endpoint_process_facts(installation_id,connector_instance_id,source_scope,device_key,process_key,observation_id,observed_at,context) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING")
                        .bind(o.installation_id).bind(o.connector.instance_id).bind(&scope).bind(device_key).bind(key).bind(o.observation_id).bind(o.observed_at).bind(json!({"process":o.process,"identity":o.actor.identity,"source":o.source})).execute(&mut *tx).await?.rows_affected();
                if written > 0 {
                    changed.insert(o.installation_id);
                }
            }
            if let (Some(entity), Some(key), Some(_)) = (
                device,
                o.actor.device_key.as_ref(),
                o.inventory.directory_tenant_key.as_ref(),
            ) && o.inventory.identifiers.iter().any(|i| {
                i.kind == "entra_device_id"
                    && Uuid::parse_str(&i.value).is_ok_and(|id| !id.is_nil())
            }) {
                sqlx::query("UPDATE identity_device_aliases SET valid_until=LEAST(COALESCE(valid_until,$6),$6) WHERE installation_id=$1 AND connector_instance_id=$2 AND source_scope=$3 AND device_key=$4 AND entity_id<>$5 AND valid_from<$6")
                        .bind(o.installation_id).bind(o.connector.instance_id).bind(&scope).bind(key).bind(entity).bind(o.observed_at).execute(&mut *tx).await?;
                sqlx::query("INSERT INTO identity_device_aliases(installation_id,connector_instance_id,source_scope,device_key,entity_id,valid_from,valid_until,observation_id) SELECT $1,$2,$3,$4,$5,$6,(SELECT min(valid_from) FROM identity_device_aliases WHERE installation_id=$1 AND connector_instance_id=$2 AND source_scope=$3 AND device_key=$4 AND entity_id<>$5 AND valid_from>$6),$7 ON CONFLICT DO NOTHING")
                        .bind(o.installation_id).bind(o.connector.instance_id).bind(&scope).bind(key).bind(entity).bind(o.observed_at).bind(o.observation_id).execute(&mut *tx).await?;
            }
            let mut expiry = o.inventory.valid_until.or(o.network.valid_until);
            if o.inventory.snapshot_at.is_some() {
                let latest: Option<DateTime<Utc>> = sqlx::query_scalar("SELECT completed_at FROM inventory_sync_status WHERE installation_id=$1 AND connector_instance_id=$2 AND completed_at>$3")
                    .bind(o.installation_id).bind(o.connector.instance_id).bind(o.observed_at).fetch_optional(&mut *tx).await?;
                if let Some(next_snapshot) = latest {
                    expiry = Some(expiry.map_or(next_snapshot, |end| end.min(next_snapshot)));
                }
            }
            if expiry.is_some_and(|v| v < o.observed_at) {
                return Err(PostgresStoreError::InvalidEntityResolution);
            }
            let mut addresses = o.actor.additional_source_ips.clone();
            addresses.extend(o.actor.source_ip.clone());
            addresses.sort_by(|a, b| a.as_str().cmp(b.as_str()));
            addresses.dedup();
            let role = o
                .inventory
                .user_role
                .clone()
                .unwrap_or(if o.cloud.provider.is_some() {
                    IdentityRole::CloudPrincipal
                } else {
                    IdentityRole::AssociatedUser
                });
            for (entity, kind, attributes) in [
                (
                    device,
                    "device",
                    json!({"hostname": o.actor.hostname, "device_key": o.actor.device_key,"device_key_kind":o.inventory.device_key_kind,"identity_status":if o.actor.device_key.is_some()&&matches!(o.inventory.device_key_kind,Some(tally_core::DeviceIdentifierKind::SourceNative|tally_core::DeviceIdentifierKind::ClientSupplied)){"source_identified"}else{"provisional"},
                    "addresses": addresses, "address_facts":o.inventory.addresses, "network_key": o.network.network_key,
                    "reported_at":o.inventory.reported_at,"identifiers": o.inventory.identifiers, "directory_tenant_key":o.inventory.directory_tenant_key,"os": o.inventory.os,"display_name":o.inventory.display_name,
                    "associated_user":o.actor.identity,"role":role,"source": o.source, "connector_type": o.connector.connector_type}),
                ),
                (
                    user,
                    "user",
                    json!({"identity": o.actor.identity, "role": role,"device_id":device,
                    "source": o.source, "connector_type": o.connector.connector_type}),
                ),
            ] {
                let Some(entity) = entity else {
                    continue;
                };
                let fact = Uuid::new_v5(&entity, o.observation_id.as_bytes());
                let affected=sqlx::query("INSERT INTO identity_facts (fact_id, installation_id, entity_id, entity_kind, connector_instance_id, source_scope, observation_id, observed_at, received_at, last_seen, valid_until, retired, attributes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$8,$10,$11,$12) ON CONFLICT (fact_id) DO UPDATE SET last_seen=GREATEST(identity_facts.last_seen,EXCLUDED.last_seen) WHERE identity_facts.last_seen<EXCLUDED.last_seen")
                    .bind(fact).bind(o.installation_id).bind(entity).bind(kind).bind(o.connector.instance_id)
                    .bind(&scope).bind(o.observation_id).bind(o.observed_at).bind(o.received_at)
                    .bind(expiry).bind(o.inventory.retired).bind(attributes).execute(&mut *tx).await?.rows_affected();
                if affected > 0 {
                    changed.insert(o.installation_id);
                }
            }
            if let (Some(device), Some(user)) = (device, user) {
                let next_relationship: Option<DateTime<Utc>> = sqlx::query_scalar("SELECT min(valid_from) FROM identity_links WHERE installation_id=$1 AND connector_instance_id=$2 AND device_id=$3 AND role=$4 AND valid_from>$5")
                    .bind(o.installation_id).bind(o.connector.instance_id).bind(device).bind(serde_json::to_value(&role)?.as_str().unwrap_or("associated_user")).bind(o.observed_at).fetch_one(&mut *tx).await?;
                let link_expiry = next_relationship.map_or(expiry, |next| {
                    Some(expiry.map_or(next, |end| end.min(next)))
                });
                sqlx::query("INSERT INTO identity_links (installation_id, device_id, user_id, role, observation_id, connector_instance_id, valid_from, valid_until) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING")
                    .bind(o.installation_id).bind(device).bind(user).bind(serde_json::to_value(role)?.as_str().unwrap_or("request_actor"))
                    .bind(o.observation_id).bind(o.connector.instance_id).bind(o.observed_at).bind(link_expiry).execute(&mut *tx).await?;
            }
        }
        // Replace relationships only from the complete snapshot's membership set. Several
        // users of one role may be present; processing one row must not expire its peers.
        let mut memberships = std::collections::BTreeMap::<
            (Uuid, Uuid, Uuid, DateTime<Utc>, &str),
            std::collections::BTreeSet<Uuid>,
        >::new();
        for o in observations {
            let (Some(at), Some(device)) = (o.inventory.snapshot_at, identity_ids(o).0) else {
                continue;
            };
            for role in [
                "assigned_owner",
                "primary_user",
                "last_logged_in",
                "associated_user",
            ] {
                let members = memberships
                    .entry((o.installation_id, o.connector.instance_id, device, at, role))
                    .or_default();
                if o.inventory.user_role.as_ref().is_some_and(|r| {
                    serde_json::to_value(r)
                        .ok()
                        .as_ref()
                        .and_then(Value::as_str)
                        == Some(role)
                }) && let Some(user) = identity_ids(o).1
                {
                    members.insert(user);
                }
            }
        }
        for ((installation, connector, device, at, role), members) in memberships {
            sqlx::query("UPDATE identity_links SET valid_until=LEAST(COALESCE(valid_until,$5),$5) WHERE installation_id=$1 AND connector_instance_id=$2 AND device_id=$3 AND role=$4 AND valid_from<$5 AND NOT(user_id=ANY($6))")
                .bind(installation).bind(connector).bind(device).bind(role).bind(at).bind(members.into_iter().collect::<Vec<_>>()).execute(&mut *tx).await?;
        }
        for installation in changed {
            sqlx::query("INSERT INTO identity_replay_jobs(installation_id) VALUES ($1) ON CONFLICT(installation_id) DO UPDATE SET requested_generation=identity_replay_jobs.requested_generation+1,updated_at=now()")
                .bind(installation).execute(&mut *tx).await?;
        }
        let mut snapshots = std::collections::BTreeMap::<
            (Uuid, Uuid, DateTime<Utc>),
            std::collections::BTreeSet<String>,
        >::new();
        for o in observations {
            if let (Some(at), Some(key)) = (o.inventory.snapshot_at, o.actor.device_key.as_ref()) {
                snapshots
                    .entry((o.installation_id, o.connector.instance_id, at))
                    .or_default()
                    .insert(key.clone());
            }
        }
        for ((installation, connector, at), keys) in snapshots {
            Self::inventory_presence_in_transaction(
                &mut tx,
                installation,
                connector,
                at,
                &keys.into_iter().collect::<Vec<_>>(),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    ///
    /// # Errors
    /// Returns an error if source validation or the database operation fails.
    pub async fn identity_inventory(
        &self,
        installation: Uuid,
        kind: &str,
        query: &str,
        after: Uuid,
        limit: i64,
    ) -> Result<Vec<IdentityRecord>, PostgresStoreError> {
        let rows: Vec<InventoryRow> = sqlx::query_as(
            "WITH scoped AS (SELECT f.*, p.retired_at AS source_retired_at,p.last_snapshot_at AS source_last_refresh,COALESCE(c.target_id,alias.entity_id,f.entity_id) AS canonical_id FROM identity_facts f LEFT JOIN inventory_source_presence p ON p.installation_id=f.installation_id AND p.connector_instance_id=f.connector_instance_id AND p.device_key=f.attributes->>'device_key' LEFT JOIN LATERAL (SELECT min(a.entity_id::text)::uuid AS entity_id FROM identity_device_aliases a WHERE a.installation_id=f.installation_id AND a.connector_instance_id=f.connector_instance_id AND a.source_scope=f.source_scope AND a.device_key=f.attributes->>'device_key' AND a.valid_from<=now() AND (a.valid_until IS NULL OR a.valid_until>now()) HAVING count(DISTINCT a.entity_id)=1) alias ON true LEFT JOIN identity_corrections c ON c.installation_id=f.installation_id AND c.subject_id=COALESCE(alias.entity_id,f.entity_id) AND c.undone_at IS NULL WHERE f.installation_id=$1 AND f.entity_kind=$2), selected AS (SELECT canonical_id FROM scoped WHERE canonical_id>$4 GROUP BY canonical_id HAVING $3='' OR canonical_id::text=$3 OR bool_or(strpos(lower(attributes::text),lower($3))>0) ORDER BY canonical_id LIMIT $5) SELECT canonical_id, min(entity_kind), min(entity_first_seen), max(entity_last_seen), jsonb_agg(jsonb_build_object('fact_id',fact_id,'source_entity_id',entity_id,'connector_instance_id',connector_instance_id,'source_scope',source_scope,'observation_id',observation_id,'observed_at',observed_at,'received_at',received_at,'last_seen',last_seen,'valid_until',valid_until,'retired',retired,'source_retired_at',source_retired_at,'source_last_refresh',source_last_refresh,'attributes',attributes) ORDER BY observed_at DESC) FROM (SELECT scoped.*,row_number() OVER(PARTITION BY canonical_id ORDER BY observed_at DESC,fact_id) AS fact_rank,min(observed_at) OVER(PARTITION BY canonical_id) AS entity_first_seen,max(last_seen) OVER(PARTITION BY canonical_id) AS entity_last_seen FROM scoped JOIN selected USING(canonical_id)) ranked WHERE fact_rank<=100 GROUP BY canonical_id ORDER BY canonical_id")
            .bind(installation).bind(kind).bind(query).bind(after).bind(limit.clamp(1,201)).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|(entity_id, entity_kind, first_seen, last_seen, facts)| {
                Ok(IdentityRecord {
                    entity_id,
                    entity_kind,
                    first_seen,
                    last_seen,
                    facts: serde_json::from_value(facts)?,
                })
            })
            .collect()
    }

    ///
    /// # Errors
    /// Returns an error if source validation or the database operation fails.
    pub async fn finding_activity(
        &self,
        installation: Uuid,
        finding: Uuid,
        before: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
    ) -> Result<Vec<ActivityAttribution>, PostgresStoreError> {
        self.filtered_finding_activity(installation, finding, before, limit, None)
            .await
    }

    /// Reads source-associated activity, optionally restricted to one observation.
    /// # Errors
    /// Returns an error if reading or decoding stored activity fails.
    pub async fn filtered_finding_activity(
        &self,
        installation: Uuid,
        finding: Uuid,
        before: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
        observation: Option<Uuid>,
    ) -> Result<Vec<ActivityAttribution>, PostgresStoreError> {
        let rows: Vec<(Value,)> = sqlx::query_as("SELECT a.context FROM finding_activity a JOIN findings f USING(finding_id) WHERE f.installation_id=$1 AND a.installation_id=$1 AND a.finding_id=$2 AND ($6::uuid IS NULL OR a.observation_id=$6) AND ($3::timestamptz IS NULL OR (a.observed_at,a.observation_id)<($3,$4)) ORDER BY a.observed_at DESC,a.observation_id DESC LIMIT $5")
            .bind(installation).bind(finding).bind(before.map(|v| v.0)).bind(before.map(|v| v.1)).bind(limit.clamp(1,201)).bind(observation).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|(v,)| serde_json::from_value(v).map_err(Into::into))
            .collect()
    }

    /// Corrections are explicit, source facts remain intact, and chains/cycles are rejected.
    ///
    /// # Errors
    /// Returns an error if source validation or the database operation fails.
    pub async fn correct_identity(
        &self,
        installation: Uuid,
        subject: Uuid,
        target: Uuid,
        reason: &str,
    ) -> Result<Uuid, PostgresStoreError> {
        if subject == target
            || reason.trim().is_empty()
            || reason.len() > 512
            || reason.chars().any(char::is_control)
        {
            return Err(PostgresStoreError::InvalidEntityResolution);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(installation.to_string())
            .execute(&mut *tx)
            .await?;
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM identity_facts a JOIN identity_facts b ON a.entity_kind=b.entity_kind AND a.installation_id=b.installation_id WHERE a.installation_id=$1 AND a.entity_id=$2 AND b.entity_id=$3) AND NOT EXISTS(SELECT 1 FROM identity_corrections WHERE installation_id=$1 AND undone_at IS NULL AND (subject_id IN ($2,$3) OR target_id=$2))")
            .bind(installation).bind(subject).bind(target).fetch_one(&mut *tx).await?;
        if !valid {
            return Err(PostgresStoreError::InvalidEntityResolution);
        }
        let id = Uuid::now_v7();
        sqlx::query("INSERT INTO identity_corrections(correction_id,installation_id,subject_id,target_id,actor,reason) VALUES ($1,$2,$3,$4,$5,$6)")
            .bind(id).bind(installation).bind(subject).bind(target).bind(crate::audit_actor()).bind(reason.trim()).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO identity_replay_jobs(installation_id) VALUES($1) ON CONFLICT(installation_id) DO UPDATE SET requested_generation=identity_replay_jobs.requested_generation+1,updated_at=now()")
            .bind(installation).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO audit_log(audit_id,actor,action,entity_type,entity_id,detail) VALUES($1,$2,'inventory.identity.merged','identity',$3,$4)").bind(id).bind(crate::audit_actor()).bind(subject.to_string()).bind(json!({"target_id":target,"reason":reason,"correction_id":id})).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(id)
    }

    ///
    /// # Errors
    /// Returns an error if source validation or the database operation fails.
    pub async fn undo_identity_correction(
        &self,
        installation: Uuid,
        id: Uuid,
    ) -> Result<bool, PostgresStoreError> {
        let mut tx = self.pool.begin().await?;
        let undone=sqlx::query("UPDATE identity_corrections SET undone_at=now() WHERE installation_id=$1 AND correction_id=$2 AND undone_at IS NULL")
            .bind(installation).bind(id).execute(&mut *tx).await?.rows_affected()>0;
        if undone {
            sqlx::query("INSERT INTO identity_replay_jobs(installation_id) VALUES($1) ON CONFLICT(installation_id) DO UPDATE SET requested_generation=identity_replay_jobs.requested_generation+1,updated_at=now()")
            .bind(installation).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO audit_log(audit_id,actor,action,entity_type,entity_id,detail) VALUES($1,$2,'inventory.identity.merge_undone','identity',$3,$4)").bind(Uuid::now_v7()).bind(crate::audit_actor()).bind(id.to_string()).bind(json!({"correction_id":id})).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(undone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_core::{ConnectorRef, DigestAlgorithm, EvidenceReceipt, ObservationKind};
    fn observation() -> Observation {
        Observation::new(
            Uuid::now_v7(),
            Utc::now(),
            ConnectorRef {
                instance_id: Uuid::now_v7(),
                connector_type: "edr".into(),
                implementation_version: "1".into(),
                source_lineage_id: None,
            },
            ObservationKind::DnsQuery,
            EvidenceReceipt::RecordDigest {
                algorithm: DigestAlgorithm::Sha256,
                digest: "a".repeat(64),
            },
        )
    }
    #[test]
    fn identity_keys_are_scoped_and_hostnames_remain_provisional() {
        let mut o = observation();
        o.actor.hostname = Some("shared".into());
        let provisional = identity_ids(&o).0;
        assert!(provisional.is_some());
        o.observation_id = Uuid::now_v7();
        assert_ne!(provisional, identity_ids(&o).0);
        o.actor.device_key = Some("device-1".into());
        o.inventory.device_key_kind = Some(tally_core::DeviceIdentifierKind::SourceNative);
        let first = identity_ids(&o).0;
        o.installation_id = Uuid::now_v7();
        assert_ne!(first, identity_ids(&o).0);
        o.connector.instance_id = Uuid::now_v7();
        assert_ne!(first, identity_ids(&o).0);
    }
}
