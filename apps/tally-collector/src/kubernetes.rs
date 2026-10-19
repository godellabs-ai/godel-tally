use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use reqwest::{Certificate, Response, Url, header::HeaderValue, redirect::Policy};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tally_connectors::{MAX_BATCH_OBSERVATIONS, MAX_IMPORT_BYTES};
use tally_core::WorkloadKind;

const MAX_PAGES: usize = 100;
const KUBERNETES_PAGE_SIZE: usize = 500;
const MAX_PAGE_BYTES: usize = 16 * 1_024 * 1_024;

#[derive(Debug)]
pub(crate) struct NativeEnterpriseSnapshot {
    pub data: Vec<u8>,
    pub record_count: usize,
}

#[derive(Deserialize)]
struct KubernetesList<T> {
    #[serde(default)]
    metadata: KubernetesListMetadata,
    items: Vec<T>,
}

#[derive(Default, Deserialize)]
struct KubernetesListMetadata {
    #[serde(default, rename = "continue")]
    continuation: String,
}

#[derive(Deserialize)]
struct KubernetesNamespace {
    metadata: KubernetesObjectMetadata,
}

#[derive(Deserialize)]
struct KubernetesObjectMetadata {
    name: String,
    uid: String,
    #[serde(default)]
    namespace: Option<String>,
}

#[derive(Deserialize)]
struct KubernetesWorkload {
    metadata: KubernetesObjectMetadata,
    spec: KubernetesWorkloadSpec,
}

#[derive(Deserialize)]
struct KubernetesWorkloadSpec {
    template: KubernetesPodTemplate,
}

#[derive(Deserialize)]
struct KubernetesCronJob {
    metadata: KubernetesObjectMetadata,
    spec: KubernetesCronJobSpec,
}

#[derive(Deserialize)]
struct KubernetesCronJobSpec {
    #[serde(rename = "jobTemplate")]
    job_template: KubernetesCronJobTemplate,
}

#[derive(Deserialize)]
struct KubernetesCronJobTemplate {
    spec: KubernetesWorkloadSpec,
}

#[derive(Deserialize)]
struct KubernetesPodTemplate {
    spec: KubernetesPodSpec,
}

#[derive(Deserialize)]
struct KubernetesPodSpec {
    containers: Vec<KubernetesContainer>,
    #[serde(default, rename = "nodeName")]
    node_name: Option<String>,
}

#[derive(Deserialize)]
struct KubernetesPod {
    metadata: KubernetesObjectMetadata,
    spec: KubernetesPodSpec,
}

#[derive(Deserialize)]
struct KubernetesContainer {
    image: String,
}

#[derive(Deserialize)]
struct KubernetesService {
    metadata: KubernetesObjectMetadata,
    spec: KubernetesServiceSpec,
}

#[derive(Deserialize)]
struct KubernetesServiceSpec {
    #[serde(default, rename = "clusterIP")]
    cluster_ip: Option<String>,
}

#[derive(Serialize)]
struct KubernetesProjection {
    schema_version: &'static str,
    cluster_uid: String,
    observed_at: DateTime<Utc>,
    resources: Vec<KubernetesProjectionResource>,
}

#[derive(Serialize)]
struct KubernetesProjectionResource {
    uid: String,
    namespace_uid: String,
    namespace_name: String,
    workload_name: String,
    kind: WorkloadKind,
    images: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
}

pub(crate) fn kubernetes_api_base(value: &str) -> Result<Url> {
    let mut url = Url::parse(value).context("invalid Kubernetes API URL reference")?;
    ensure!(url.scheme() == "https", "Kubernetes API must use HTTPS");
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "Kubernetes API URL cannot contain credentials"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "Kubernetes API URL cannot contain query or fragment data"
    );
    ensure!(
        url.host_str().is_some(),
        "Kubernetes API URL requires a host"
    );
    ensure!(
        matches!(url.path(), "" | "/"),
        "Kubernetes API URL cannot contain a path"
    );
    url.set_path("/");
    Ok(url)
}

pub(crate) fn kubernetes_in_cluster_api_base(host: &str, port: &str) -> Result<Url> {
    let port = port
        .parse::<u16>()
        .context("invalid Kubernetes service port")?;
    ensure!(port > 0, "invalid Kubernetes service port");
    let host = host.trim();
    ensure!(
        !host.is_empty() && !host.chars().any(char::is_control),
        "invalid Kubernetes service host"
    );
    let authority = match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(address)) => format!("[{address}]"),
        Ok(std::net::IpAddr::V4(address)) => address.to_string(),
        Err(_) => tally_core::Hostname::parse(host)
            .map_err(|_| anyhow::anyhow!("invalid Kubernetes service host"))?
            .as_str()
            .to_owned(),
    };
    kubernetes_api_base(&format!("https://{authority}:{port}"))
}

pub(crate) fn kubernetes_client(ca_pem: Option<&[u8]>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(45))
        .user_agent(concat!(
            "godel-tally-kubernetes/",
            env!("CARGO_PKG_VERSION")
        ));
    if let Some(ca_pem) = ca_pem {
        ensure!(
            !ca_pem.is_empty() && ca_pem.len() <= 1_048_576,
            "invalid Kubernetes CA reference"
        );
        builder = builder.add_root_certificate(
            Certificate::from_pem(ca_pem).context("invalid Kubernetes CA reference")?,
        );
    }
    builder.build().context("build bounded Kubernetes client")
}

#[allow(clippy::too_many_lines)] // Sequential list calls make the read-only RBAC surface auditable.
pub(crate) async fn pull_kubernetes(
    api_base: &Url,
    bearer_token: &str,
    client: &reqwest::Client,
) -> Result<NativeEnterpriseSnapshot> {
    ensure!(
        !bearer_token.is_empty() && bearer_token.len() <= 16_384,
        "invalid Kubernetes token reference"
    );
    let mut authorization = HeaderValue::from_str(&format!("Bearer {bearer_token}"))
        .context("invalid Kubernetes token reference")?;
    authorization.set_sensitive(true);
    let namespaces: Vec<KubernetesNamespace> =
        kubernetes_list(client, api_base, "api/v1/namespaces", &authorization).await?;
    let (namespace_uids, cluster_uid) = kubernetes_namespace_uids(namespaces)?;
    let observed_at = Utc::now();
    let mut resources = Vec::new();
    for (path, kind) in [
        ("apis/apps/v1/deployments", WorkloadKind::Deployment),
        ("apis/apps/v1/statefulsets", WorkloadKind::StatefulSet),
        ("apis/apps/v1/daemonsets", WorkloadKind::DaemonSet),
        ("apis/batch/v1/jobs", WorkloadKind::Job),
    ] {
        let workloads: Vec<KubernetesWorkload> =
            kubernetes_list(client, api_base, path, &authorization).await?;
        for workload in workloads {
            let namespace_name = workload
                .metadata
                .namespace
                .as_deref()
                .context("Kubernetes workload namespace is unavailable")?
                .to_owned();
            let namespace_uid = namespace_uids
                .get(&namespace_name)
                .context("Kubernetes workload namespace is unknown")?
                .clone();
            ensure!(
                resources.len() < MAX_BATCH_OBSERVATIONS,
                "Kubernetes resource cap exceeded"
            );
            resources.push(KubernetesProjectionResource {
                uid: workload.metadata.uid,
                namespace_uid,
                namespace_name,
                workload_name: workload.metadata.name,
                kind,
                images: workload
                    .spec
                    .template
                    .spec
                    .containers
                    .into_iter()
                    .map(|container| container.image)
                    .collect(),
                service_ip: None,
                hostname: None,
            });
        }
    }
    let cron_jobs: Vec<KubernetesCronJob> =
        kubernetes_list(client, api_base, "apis/batch/v1/cronjobs", &authorization).await?;
    for cron_job in cron_jobs {
        let namespace_name = cron_job
            .metadata
            .namespace
            .as_deref()
            .context("Kubernetes CronJob namespace is unavailable")?
            .to_owned();
        let namespace_uid = namespace_uids
            .get(&namespace_name)
            .context("Kubernetes CronJob namespace is unknown")?
            .clone();
        ensure!(
            resources.len() < MAX_BATCH_OBSERVATIONS,
            "Kubernetes resource cap exceeded"
        );
        resources.push(KubernetesProjectionResource {
            uid: cron_job.metadata.uid,
            namespace_uid,
            namespace_name,
            workload_name: cron_job.metadata.name,
            kind: WorkloadKind::CronJob,
            images: cron_job
                .spec
                .job_template
                .spec
                .template
                .spec
                .containers
                .into_iter()
                .map(|container| container.image)
                .collect(),
            service_ip: None,
            hostname: None,
        });
    }
    let pods: Vec<KubernetesPod> =
        kubernetes_list(client, api_base, "api/v1/pods", &authorization).await?;
    for pod in pods {
        let namespace_name = pod
            .metadata
            .namespace
            .as_deref()
            .context("Kubernetes pod namespace is unavailable")?
            .to_owned();
        let namespace_uid = namespace_uids
            .get(&namespace_name)
            .context("Kubernetes pod namespace is unknown")?
            .clone();
        ensure!(
            resources.len() < MAX_BATCH_OBSERVATIONS,
            "Kubernetes resource cap exceeded"
        );
        resources.push(KubernetesProjectionResource {
            uid: pod.metadata.uid,
            namespace_uid,
            namespace_name,
            workload_name: pod.metadata.name,
            kind: WorkloadKind::Pod,
            images: pod
                .spec
                .containers
                .into_iter()
                .map(|container| container.image)
                .collect(),
            service_ip: None,
            hostname: pod
                .spec
                .node_name
                .and_then(|value| normalized_hostname(&value)),
        });
    }
    let services: Vec<KubernetesService> =
        kubernetes_list(client, api_base, "api/v1/services", &authorization).await?;
    for service in services {
        let namespace_name = service
            .metadata
            .namespace
            .as_deref()
            .context("Kubernetes service namespace is unavailable")?
            .to_owned();
        let namespace_uid = namespace_uids
            .get(&namespace_name)
            .context("Kubernetes service namespace is unknown")?
            .clone();
        ensure!(
            resources.len() < MAX_BATCH_OBSERVATIONS,
            "Kubernetes resource cap exceeded"
        );
        resources.push(KubernetesProjectionResource {
            uid: service.metadata.uid,
            namespace_uid,
            namespace_name,
            workload_name: service.metadata.name,
            kind: WorkloadKind::Service,
            images: Vec::new(),
            service_ip: service
                .spec
                .cluster_ip
                .filter(|value| !value.is_empty() && value != "None"),
            hostname: None,
        });
    }
    ensure!(
        resources.len() <= MAX_BATCH_OBSERVATIONS,
        "Kubernetes resource cap exceeded"
    );
    resources.sort_by(|left, right| {
        left.namespace_uid
            .cmp(&right.namespace_uid)
            .then_with(|| left.uid.cmp(&right.uid))
    });
    let record_count = resources.len();
    let data = serde_json::to_vec(&KubernetesProjection {
        schema_version: "kubernetes_api_discovery_projection_v1",
        cluster_uid,
        observed_at,
        resources,
    })?;
    ensure!(
        data.len() <= MAX_IMPORT_BYTES,
        "Kubernetes projection is too large"
    );
    Ok(NativeEnterpriseSnapshot { data, record_count })
}

fn normalized_hostname(value: &str) -> Option<String> {
    tally_core::Hostname::parse(value)
        .ok()
        .map(|hostname| hostname.as_str().to_owned())
}

fn kubernetes_namespace_uids(
    namespaces: Vec<KubernetesNamespace>,
) -> Result<(BTreeMap<String, String>, String)> {
    let mut namespace_uids = BTreeMap::new();
    for namespace in namespaces {
        ensure!(
            namespace_uids
                .insert(namespace.metadata.name, namespace.metadata.uid)
                .is_none(),
            "duplicate Kubernetes namespace"
        );
    }
    let cluster_uid = namespace_uids
        .get("kube-system")
        .context("Kubernetes kube-system namespace is unavailable")?
        .clone();
    Ok((namespace_uids, cluster_uid))
}

async fn kubernetes_list<T: DeserializeOwned>(
    client: &reqwest::Client,
    api_base: &Url,
    path: &str,
    authorization: &HeaderValue,
) -> Result<Vec<T>> {
    let mut items = Vec::new();
    let mut continuation: Option<String> = None;
    for page in 1..=MAX_PAGES {
        let mut url = api_base.join(path).context("build Kubernetes API URL")?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("limit", &KUBERNETES_PAGE_SIZE.to_string());
            if let Some(token) = &continuation {
                query.append_pair("continue", token);
            }
        }
        let response = client
            .get(url)
            .header(reqwest::header::AUTHORIZATION, authorization.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .context("Kubernetes API request failed")?;
        let bytes = bounded_response(response, "Kubernetes API").await?;
        let list: KubernetesList<T> =
            serde_json::from_slice(&bytes).context("invalid Kubernetes API response")?;
        items.extend(list.items);
        ensure!(
            items.len() <= MAX_BATCH_OBSERVATIONS,
            "Kubernetes resource cap exceeded"
        );
        if list.metadata.continuation.is_empty() {
            return Ok(items);
        }
        ensure!(
            list.metadata.continuation.len() <= 4_096
                && !list.metadata.continuation.chars().any(char::is_control),
            "invalid Kubernetes continuation token"
        );
        continuation = Some(list.metadata.continuation);
        ensure!(page < MAX_PAGES, "Kubernetes page cap exceeded");
    }
    bail!("Kubernetes page cap exceeded")
}

pub(crate) async fn bounded_response(mut response: Response, source: &str) -> Result<Vec<u8>> {
    let status = response.status();
    ensure!(
        status.is_success(),
        "{source} request was unsuccessful (HTTP {status})"
    );
    if response
        .content_length()
        .is_some_and(|length| length > u64::try_from(MAX_PAGE_BYTES).unwrap_or(u64::MAX))
    {
        bail!("{source} response is too large");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("read bounded provider response")?
    {
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= MAX_PAGE_BYTES,
            "{source} response is too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kubernetes_origin_is_explicit_https_and_content_free() {
        let url = kubernetes_api_base("https://10.0.0.5:6443").expect("URL");
        assert_eq!(url.as_str(), "https://10.0.0.5:6443/");
        assert!(kubernetes_api_base("http://10.0.0.5:8080").is_err());
        assert!(kubernetes_api_base("https://user:secret@cluster.example").is_err());
        assert!(kubernetes_api_base("https://cluster.example/api/v1/secrets").is_err());
        assert_eq!(
            kubernetes_in_cluster_api_base("10.96.0.1", "443")
                .expect("in-cluster URL")
                .as_str(),
            "https://10.96.0.1/"
        );
        assert_eq!(
            kubernetes_in_cluster_api_base("fd00::1", "6443")
                .expect("in-cluster IPv6 URL")
                .as_str(),
            "https://[fd00::1]:6443/"
        );
        assert!(kubernetes_in_cluster_api_base("host/path", "443").is_err());
    }

    #[test]
    fn kubernetes_projection_drops_unrequested_metadata() {
        let workloads: KubernetesList<KubernetesWorkload> = serde_json::from_slice(br#"{
          "metadata":{"continue":""},
          "items":[{
            "metadata":{"name":"WORKLOAD_NAME_CANARY","uid":"uid-1","namespace":"ai","labels":{"owner":"LABEL_CANARY"}},
            "spec":{"template":{"spec":{"containers":[{"image":"docker.io/ollama/ollama:1","env":[{"name":"SECRET","value":"CONTENT_CANARY"}]}]}}}
          }]
        }"#).expect("Kubernetes response");
        let workload = workloads.items.into_iter().next().expect("workload");
        assert_eq!(workload.metadata.uid, "uid-1");
        assert_eq!(workload.spec.template.spec.containers.len(), 1);
        let debug = workload.metadata.uid.clone();
        assert!(!debug.contains("CANARY"));
    }
}
