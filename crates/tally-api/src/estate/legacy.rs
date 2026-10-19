//! Metadata-only recovery of the attribution that Tally retained before AI log storage.
//! A finding aggregates events: its people and devices must not be paired as if they were one event.
use chrono::{DateTime, Utc};
use serde::Deserialize;
use tally_observation_buffer::{
    ObservationBuffer,
    estate::{EstateDetail, EstateRecord},
};
use tally_store_postgres::{
    FindingDestinationView, FindingEndpointView, FindingUserView, FindingWorkloadView,
};
use uuid::Uuid;

#[derive(Deserialize)]
struct Finding {
    #[serde(rename = "finding_id")]
    id: Uuid,
    provider_key: String,
    provider_name: String,
    model_key: Option<String>,
    model_name: Option<String>,
    model_owner: Option<String>,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    hosts: Vec<FindingEndpointView>,
    users: Vec<FindingUserView>,
    destinations: Vec<FindingDestinationView>,
    workloads: Vec<FindingWorkloadView>,
    evidence_sources: Vec<String>,
}

const QUERY: &str = r"
    SELECT jsonb_build_object(
        'finding_id', f.finding_id, 'provider_key', p.key, 'provider_name', p.name,
        'model_key', m.key, 'model_name', m.name, 'model_owner', owner.name,
        'first_seen', f.first_used_at, 'last_seen', f.last_used_at,
        'hosts', COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'endpoint_host_id', h.endpoint_host_id, 'kind', h.kind, 'value', h.value,
            'role', fh.role, 'port', NULLIF(fh.port,0), 'first_seen', fh.first_seen, 'last_seen', fh.last_seen))
            FROM finding_hosts fh JOIN endpoint_hosts h USING(endpoint_host_id) WHERE fh.finding_id=f.finding_id), '[]'),
        'users', COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'endpoint_user_id', u.endpoint_user_id, 'kind', u.kind, 'value', u.value, 'email', u.email,
            'first_seen', fu.first_seen, 'last_seen', fu.last_seen))
            FROM finding_users fu JOIN endpoint_users u USING(endpoint_user_id) WHERE fu.finding_id=f.finding_id), '[]'),
        'destinations', COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'destination_host_id', d.destination_host_id, 'kind', d.kind, 'value', d.value,
            'port', NULLIF(fd.port,0), 'first_seen', fd.first_seen, 'last_seen', fd.last_seen))
            FROM finding_destinations fd JOIN destination_hosts d USING(destination_host_id) WHERE fd.finding_id=f.finding_id), '[]'),
        'workloads', COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'namespace_name', fw.namespace_name, 'workload_name', fw.workload_name,
            'workload_kind', fw.workload_kind, 'runtime_image', NULLIF(fw.runtime_image,''),
            'first_seen', fw.first_seen, 'last_seen', fw.last_seen))
            FROM finding_workloads fw WHERE fw.finding_id=f.finding_id), '[]'),
        'evidence_sources', COALESCE((SELECT jsonb_agg(DISTINCT COALESCE(NULLIF(c.friendly_name,''),c.display_name))
            FROM finding_connectors fc JOIN connector_states c USING(connector_instance_id)
            WHERE fc.finding_id=f.finding_id AND c.installation_id=f.installation_id), '[]')
    )
    FROM findings f JOIN ai_providers p USING(provider_id) LEFT JOIN ai_models m USING(model_id)
    LEFT JOIN ai_providers owner ON owner.provider_id=m.owner_provider_id
    WHERE f.installation_id=$1 AND f.finding_id>$2 ORDER BY f.finding_id LIMIT 200
";

pub(super) async fn bootstrap(
    connection: &mut sqlx::PgConnection,
    store: &ObservationBuffer,
    installation: Uuid,
) -> anyhow::Result<()> {
    if !store.bootstrap_needed().await? {
        return Ok(());
    }
    let mut after = Uuid::nil();
    loop {
        let rows = sqlx::query_scalar::<_, serde_json::Value>(QUERY)
            .bind(installation)
            .bind(after)
            .fetch_all(&mut *connection)
            .await?;
        if rows.is_empty() {
            break;
        }
        let mut records = Vec::new();
        for row in rows {
            let finding: Finding = serde_json::from_value(row)?;
            after = finding.id;
            records.extend(project(installation, &finding));
        }
        store.write_inventory(&records).await?;
    }
    store.finish_bootstrap().await?;
    Ok(())
}

fn project(installation: Uuid, finding: &Finding) -> Vec<EstateRecord> {
    let registry = if finding.provider_key.contains('.') {
        finding.provider_key.clone()
    } else {
        format!("provider.{}", finding.provider_key)
    };
    let base = EstateDetail {
        registry_entry_id: Some(registry.clone()), confidence: "historical".into(),
        basis: "Preserved historical finding attribution. Original events were not retained; users and devices are associated with this finding, not paired as one request.".into(),
        connector_type: "legacy_findings".into(), observation_id: finding.id,
        evidence_sources: Some(finding.evidence_sources.clone()),
        ..Default::default()
    };
    let mut graph = Projection {
        installation,
        base,
        records: Vec::new(),
    };
    let times = (finding.first_seen, finding.last_seen);
    let provider = graph.node(
        "provider",
        &registry,
        &finding.provider_name,
        graph.base.clone(),
        times,
    );
    let model = finding.model_key.as_deref().map(|key| {
        let mut detail = graph.base.clone();
        detail.model = Some(key.to_owned());
        detail.model_owner.clone_from(&finding.model_owner);
        let model = graph.node(
            "model",
            &format!("{registry}:{key}"),
            finding.model_name.as_deref().unwrap_or(key),
            detail,
            times,
        );
        // Preserve the identity of the v1 provider/model relationship.
        graph.edge(model, provider, "provided by", times, Uuid::nil());
        model
    });
    let target = model.unwrap_or(provider);
    graph.hosts(&finding.hosts, target, finding.id);
    graph.users(&finding.users, target, finding.id);
    graph.destinations(&finding.destinations, provider, model, finding.id);
    graph.workloads(&finding.workloads, target, finding.id);
    graph.records
}

struct Projection {
    installation: Uuid,
    base: EstateDetail,
    records: Vec<EstateRecord>,
}
impl Projection {
    fn hosts(&mut self, hosts: &[FindingEndpointView], target: Uuid, evidence: Uuid) {
        for host in hosts {
            let mut detail = self.base.clone();
            let key = if host.kind == "hostname" {
                detail.hostname = Some(host.value.clone());
                host.value.to_lowercase()
            } else {
                detail.source_ip = Some(host.value.clone());
                format!("source-ip:{}", host.value)
            };
            detail.port = host.port;
            detail.state = Some(
                if host.kind == "ip_address" {
                    "source address"
                } else {
                    "historically observed"
                }
                .into(),
            );
            let device = self.node(
                "device",
                &key,
                &host.value,
                detail,
                (host.first_seen, host.last_seen),
            );
            self.edge(
                device,
                target,
                if host.role == "local_service" {
                    "historical local service"
                } else {
                    "historical usage"
                },
                (host.first_seen, host.last_seen),
                evidence,
            );
        }
    }
    fn users(&mut self, users: &[FindingUserView], target: Uuid, evidence: Uuid) {
        for user in users {
            let mut detail = self.base.clone();
            detail.registry_entry_id = None;
            detail.identity_kind = Some(user.kind.clone());
            let identity = self.node(
                "identity",
                &format!("legacy-user:{}", user.endpoint_user_id),
                user.email.as_deref().unwrap_or(&user.value),
                detail,
                (user.first_seen, user.last_seen),
            );
            self.edge(
                identity,
                target,
                "historical usage",
                (user.first_seen, user.last_seen),
                evidence,
            );
        }
    }
    fn destinations(
        &mut self,
        destinations: &[FindingDestinationView],
        provider: Uuid,
        model: Option<Uuid>,
        evidence: Uuid,
    ) {
        for destination in destinations {
            let mut detail = self.base.clone();
            detail.port = destination.port;
            if destination.kind == "hostname" {
                detail.hostname = Some(destination.value.clone());
            }
            let endpoint = self.node(
                "endpoint",
                &destination.value,
                &destination.value,
                detail,
                (destination.first_seen, destination.last_seen),
            );
            self.edge(
                endpoint,
                provider,
                "provided by",
                (destination.first_seen, destination.last_seen),
                evidence,
            );
            if let Some(model) = model {
                self.edge(
                    endpoint,
                    model,
                    "historically associated with",
                    (destination.first_seen, destination.last_seen),
                    evidence,
                );
            }
        }
    }
    fn workloads(&mut self, workloads: &[FindingWorkloadView], target: Uuid, evidence: Uuid) {
        for workload in workloads {
            let mut detail = self.base.clone();
            detail.namespace = Some(workload.namespace_name.clone());
            detail.workload_kind = Some(workload.workload_kind.clone());
            detail.runtime_image.clone_from(&workload.runtime_image);
            detail.platform = Some("kubernetes".into());
            let key = format!(
                "legacy-workload:{}:{}:{}",
                workload.namespace_name, workload.workload_kind, workload.workload_name
            );
            let id = self.node(
                "workload",
                &key,
                &workload.workload_name,
                detail,
                (workload.first_seen, workload.last_seen),
            );
            self.edge(
                id,
                target,
                "historical usage",
                (workload.first_seen, workload.last_seen),
                evidence,
            );
        }
    }

    fn node(
        &mut self,
        kind: &str,
        key: &str,
        name: &str,
        mut detail: EstateDetail,
        times: (DateTime<Utc>, DateTime<Utc>),
    ) -> Uuid {
        let id = Uuid::new_v5(
            &self.installation,
            format!("estate:{kind}:{key}").as_bytes(),
        );
        kind.clone_into(&mut detail.kind);
        name.clone_into(&mut detail.name);
        self.push(id, "node", detail, times);
        id
    }
    fn edge(
        &mut self,
        source: Uuid,
        target: Uuid,
        kind: &str,
        times: (DateTime<Utc>, DateTime<Utc>),
        evidence: Uuid,
    ) {
        let id = Uuid::new_v5(
            &self.installation,
            format!("estate:{source}:{target}:{kind}:{evidence}").as_bytes(),
        );
        let mut detail = self.base.clone();
        kind.clone_into(&mut detail.kind);
        kind.clone_into(&mut detail.name);
        detail.source = Some(source);
        detail.target = Some(target);
        self.push(id, "edge", detail, times);
    }
    fn push(
        &mut self,
        id: Uuid,
        record_type: &str,
        detail: EstateDetail,
        times: (DateTime<Utc>, DateTime<Utc>),
    ) {
        self.records.push(EstateRecord {
            id,
            record_type: record_type.to_owned(),
            first_seen: times.0.timestamp_millis(),
            last_seen: times.1.timestamp_millis(),
            detail,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn finding_fixture() -> Finding {
        let id = Uuid::now_v7();
        let first = Utc::now() - chrono::Duration::days(10);
        let last = Utc::now();
        Finding {
            id,
            provider_key: "openai".into(),
            provider_name: "OpenAI".into(),
            model_key: Some("gpt-5".into()),
            model_name: Some("GPT-5".into()),
            model_owner: Some("OpenAI".into()),
            first_seen: first,
            last_seen: last,
            hosts: vec![FindingEndpointView {
                endpoint_host_id: Uuid::now_v7(),
                kind: "hostname".into(),
                value: "dev-laptop".into(),
                role: "source".into(),
                port: None,
                first_seen: first,
                last_seen: last,
            }],
            users: vec![FindingUserView {
                endpoint_user_id: Uuid::now_v7(),
                kind: "email".into(),
                value: "alex@example.com".into(),
                email: Some("alex@example.com".into()),
                first_seen: first,
                last_seen: last,
            }],
            destinations: vec![FindingDestinationView {
                destination_host_id: Uuid::now_v7(),
                kind: "hostname".into(),
                value: "api.openai.com".into(),
                port: Some(443),
                first_seen: first,
                last_seen: last,
            }],
            workloads: vec![FindingWorkloadView {
                namespace_name: "engineering".into(),
                workload_name: "inference".into(),
                workload_kind: "deployment".into(),
                runtime_image: Some("vllm/vllm-openai:v1".into()),
                first_seen: first,
                last_seen: last,
            }],
            evidence_sources: vec!["Endpoint connector".into()],
        }
    }

    #[test]
    fn historical_attribution_survives_without_inventing_request_pairs_or_logs() {
        let finding = finding_fixture();
        let id = finding.id;
        let first = finding.first_seen;
        let last = finding.last_seen;
        let records = project(id, &finding);
        let repeated = project(id, &finding);
        assert_eq!(
            records.iter().map(|r| r.id).collect::<Vec<_>>(),
            repeated.iter().map(|r| r.id).collect::<Vec<_>>()
        );
        for kind in [
            "identity", "device", "model", "provider", "endpoint", "workload",
        ] {
            assert!(
                records
                    .iter()
                    .any(|r| r.record_type == "node" && r.detail.kind == kind),
                "missing {kind}"
            );
        }
        assert!(
            records
                .iter()
                .all(|r| r.first_seen == first.timestamp_millis()
                    && r.last_seen == last.timestamp_millis()
                    && r.detail.confidence == "historical")
        );
        let person = records
            .iter()
            .find(|r| r.detail.kind == "identity")
            .unwrap()
            .id;
        let device = records
            .iter()
            .find(|r| r.detail.kind == "device")
            .unwrap()
            .id;
        assert!(
            !records
                .iter()
                .any(|r| r.detail.source == Some(person) && r.detail.target == Some(device)),
            "aggregated findings cannot prove user/device co-occurrence"
        );
        assert_eq!(
            records
                .iter()
                .find(|r| r.detail.kind == "workload")
                .unwrap()
                .detail
                .namespace
                .as_deref(),
            Some("engineering")
        );
        assert_eq!(
            records
                .iter()
                .find(|r| r.detail.kind == "model")
                .unwrap()
                .detail
                .model
                .as_deref(),
            Some("gpt-5")
        );
        assert_ne!(
            project(Uuid::now_v7(), &finding)[0].id,
            records[0].id,
            "installation-scoped identities"
        );
    }
}
