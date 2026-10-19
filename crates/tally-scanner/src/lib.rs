//! Safe, deterministic planning for the agentless network scanner.
//!
//! Planning is intentionally separate from probing. A caller cannot reach the probe engine until
//! every target has been parsed, classified, excluded, capped, and recorded in a stable receipt.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use chrono::{DateTime, Utc};
use if_addrs::IfAddr;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tally_registry_lib::{
    FingerprintAssertion, HttpFingerprint, MatchHit, RegistryBundle, RegistryError, SafeHttpMethod,
    SafeProbeRequest,
};
use thiserror::Error;
use tokio::{net::TcpStream, sync::watch, task::JoinSet, time::Instant};

pub const SCAN_PLAN_VERSION: &str = "1.0.0-alpha.1";
pub const DEFAULT_MAX_HOSTS: u32 = 1_024;
pub const HARD_MAX_HOSTS: u32 = 65_536;
pub const DEFAULT_CONNECT_CONCURRENCY: u16 = 64;
pub const MAX_CONNECT_CONCURRENCY: u16 = 256;
pub const DEFAULT_CONNECT_TIMEOUT_MILLIS: u64 = 1_500;
pub const MAX_CONNECT_TIMEOUT_MILLIS: u64 = 10_000;
pub const DEFAULT_PORTS: &[u16] = &[
    80, 443, 3_000, 4_000, 7_860, 8_000, 8_001, 8_002, 8_080, 8_081, 11_434,
];

/// Ports supported by Phase 1's benign runtime fingerprints.
pub const SAFE_PORTS: &[u16] = DEFAULT_PORTS;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalScopeDiscovery {
    /// Eligible directly connected networks, in stable order.
    pub targets: Vec<String>,
    /// Interfaces excluded from automatic scope and the reason why.
    pub skipped: Vec<SkippedInterface>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedInterface {
    pub name: String,
    pub address: IpAddr,
    pub reason: String,
}

#[derive(Debug, Error)]
pub enum LocalScopeError {
    #[error("enumerate local network interfaces")]
    Enumerate(#[source] std::io::Error),
    #[error("local scope host cap {0} is outside the safe supported range 1..={HARD_MAX_HOSTS}")]
    UnsafeHostCap(u32),
    #[error("interface {name} returned invalid network {address}/{prefix}")]
    InvalidInterfaceNetwork {
        name: String,
        address: IpAddr,
        prefix: u8,
    },
}

/// Enumerates directly connected private networks for the default scanner preview.
///
/// Loopback, link-local, public, tunnel/VPN, container-bridge, and overly broad networks are
/// reported as skipped and never silently enter the target list.
///
/// # Errors
///
/// Returns [`LocalScopeError`] if interface enumeration fails, the cap is unsafe, or the operating
/// system supplies an invalid address/prefix pair.
pub fn discover_local_scope(max_hosts: u32) -> Result<LocalScopeDiscovery, LocalScopeError> {
    if max_hosts == 0 || max_hosts > HARD_MAX_HOSTS {
        return Err(LocalScopeError::UnsafeHostCap(max_hosts));
    }

    let interfaces = if_addrs::get_if_addrs().map_err(LocalScopeError::Enumerate)?;
    let mut targets = BTreeSet::new();
    let mut skipped = Vec::new();

    for interface in interfaces {
        let (address, prefix) = match interface.addr {
            IfAddr::V4(details) => (IpAddr::V4(details.ip), details.prefixlen),
            IfAddr::V6(details) => (IpAddr::V6(details.ip), details.prefixlen),
        };
        let network =
            IpNet::new(address, prefix).map_err(|_| LocalScopeError::InvalidInterfaceNetwork {
                name: interface.name.clone(),
                address,
                prefix,
            })?;

        match local_candidate(&interface.name, address, network, max_hosts) {
            Ok(candidate) => {
                targets.insert(candidate);
            }
            Err(reason) => skipped.push(SkippedInterface {
                name: interface.name,
                address,
                reason: reason.to_owned(),
            }),
        }
    }

    skipped.sort_by(|left, right| (&left.name, left.address).cmp(&(&right.name, right.address)));
    Ok(LocalScopeDiscovery {
        targets: targets.into_iter().collect(),
        skipped,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanScope {
    /// Exact IP addresses or CIDRs. DNS names are deliberately excluded from scope planning.
    pub targets: Vec<String>,
    pub exclusions: Vec<String>,
    pub ports: Vec<u16>,
    pub max_hosts: u32,
    pub allow_public: bool,
    /// Required in addition to `allow_public` before a public address can enter a plan.
    #[serde(default)]
    pub authorization_acknowledged: bool,
}

impl ScanScope {
    /// Validates the requested scope and returns the exact immutable plan a probe engine may use.
    ///
    /// # Errors
    ///
    /// Returns [`ScanScopeError`] when a target is ambiguous or unsafe, public authorization is
    /// incomplete, a port is outside the fingerprint allowlist, or the expanded scope exceeds its
    /// host cap.
    pub fn plan(&self) -> Result<ScanPlan, ScanScopeError> {
        if self.targets.is_empty() {
            return Err(ScanScopeError::NoTargets);
        }
        if self.max_hosts == 0 || self.max_hosts > HARD_MAX_HOSTS {
            return Err(ScanScopeError::UnsafeHostCap(self.max_hosts));
        }

        let ports = normalize_ports(&self.ports)?;
        let target_nets = parse_nets(&self.targets, InputKind::Target)?;
        let exclusion_nets = parse_nets(&self.exclusions, InputKind::Exclusion)?;
        let mut targets = BTreeSet::new();

        for network in target_nets {
            for address in network.hosts() {
                if exclusion_nets
                    .iter()
                    .any(|excluded| excluded.contains(&address))
                {
                    continue;
                }

                match classify(address) {
                    AddressClass::Public if !self.allow_public => {
                        return Err(ScanScopeError::PublicTargetRequiresOptIn(address));
                    }
                    AddressClass::Public if !self.authorization_acknowledged => {
                        return Err(ScanScopeError::PublicAuthorizationRequired(address));
                    }
                    AddressClass::Private | AddressClass::Public => {}
                    AddressClass::Forbidden(reason) => {
                        return Err(ScanScopeError::ForbiddenTarget { address, reason });
                    }
                }

                targets.insert(address);
                if targets.len() > self.max_hosts as usize {
                    return Err(ScanScopeError::HostCapExceeded {
                        cap: self.max_hosts,
                    });
                }
            }
        }

        if targets.is_empty() {
            return Err(ScanScopeError::NoTargetsAfterExclusions);
        }

        let targets = targets.into_iter().collect::<Vec<_>>();
        let host_count = u64::try_from(targets.len()).unwrap_or(u64::MAX);
        let probe_count = host_count.saturating_mul(u64::try_from(ports.len()).unwrap_or(u64::MAX));
        let scope_digest = scope_digest(
            &targets,
            &ports,
            self.allow_public,
            self.authorization_acknowledged,
        );

        Ok(ScanPlan {
            version: SCAN_PLAN_VERSION.to_owned(),
            targets,
            ports,
            host_count,
            probe_count,
            allow_public: self.allow_public,
            authorization_acknowledged: self.authorization_acknowledged,
            scope_digest,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanPlan {
    pub version: String,
    pub targets: Vec<IpAddr>,
    pub ports: Vec<u16>,
    pub host_count: u64,
    pub probe_count: u64,
    pub allow_public: bool,
    pub authorization_acknowledged: bool,
    /// SHA-256 of the canonical plan fields. This is an identifier, not a signature.
    pub scope_digest: String,
}

impl ScanPlan {
    /// Revalidates a serialized plan before any network operation.
    ///
    /// # Errors
    ///
    /// Returns [`ScanExecutionError::InvalidPlan`] when fields or the digest were altered after
    /// planning.
    pub fn validate_integrity(&self) -> Result<(), ScanExecutionError> {
        if self.version != SCAN_PLAN_VERSION {
            return Err(ScanExecutionError::InvalidPlan("unsupported plan version"));
        }
        if self.targets.is_empty() || self.targets.len() > HARD_MAX_HOSTS as usize {
            return Err(ScanExecutionError::InvalidPlan("unsafe host count"));
        }
        if self.host_count != self.targets.len() as u64 {
            return Err(ScanExecutionError::InvalidPlan("host count mismatch"));
        }
        if self.ports.is_empty()
            || self.ports.iter().any(|port| !SAFE_PORTS.contains(port))
            || !strictly_sorted(&self.ports)
            || !strictly_sorted(&self.targets)
        {
            return Err(ScanExecutionError::InvalidPlan(
                "targets or ports are not canonical",
            ));
        }
        for target in &self.targets {
            match classify(*target) {
                AddressClass::Private => {}
                AddressClass::Public if self.allow_public && self.authorization_acknowledged => {}
                AddressClass::Public => {
                    return Err(ScanExecutionError::InvalidPlan(
                        "public target lacks authorization",
                    ));
                }
                AddressClass::Forbidden(_) => {
                    return Err(ScanExecutionError::InvalidPlan("forbidden target"));
                }
            }
        }
        let expected_probes = self.host_count.saturating_mul(self.ports.len() as u64);
        if self.probe_count != expected_probes {
            return Err(ScanExecutionError::InvalidPlan("probe count mismatch"));
        }
        if self.scope_digest
            != scope_digest(
                &self.targets,
                &self.ports,
                self.allow_public,
                self.authorization_acknowledged,
            )
        {
            return Err(ScanExecutionError::InvalidPlan("scope digest mismatch"));
        }
        Ok(())
    }
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanExecutionPolicy {
    pub concurrency: u16,
    pub connect_timeout_millis: u64,
}

impl Default for ScanExecutionPolicy {
    fn default() -> Self {
        Self {
            concurrency: DEFAULT_CONNECT_CONCURRENCY,
            connect_timeout_millis: DEFAULT_CONNECT_TIMEOUT_MILLIS,
        }
    }
}

impl ScanExecutionPolicy {
    fn validate(self) -> Result<Self, ScanExecutionError> {
        if self.concurrency == 0 || self.concurrency > MAX_CONNECT_CONCURRENCY {
            return Err(ScanExecutionError::UnsafeConcurrency(self.concurrency));
        }
        if !(50..=MAX_CONNECT_TIMEOUT_MILLIS).contains(&self.connect_timeout_millis) {
            return Err(ScanExecutionError::UnsafeTimeout(
                self.connect_timeout_millis,
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone)]
pub struct ScanCancellation {
    sender: watch::Sender<bool>,
}

impl Default for ScanCancellation {
    fn default() -> Self {
        let (sender, _) = watch::channel(false);
        Self { sender }
    }
}

impl ScanCancellation {
    pub fn cancel(&self) {
        self.sender.send_replace(true);
    }

    pub fn is_cancelled(&self) -> bool {
        *self.sender.borrow()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpScanRun {
    pub scope_digest: String,
    pub status: ScanRunStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub planned_probes: u64,
    pub completed_probes: u64,
    pub results: Vec<TcpProbeResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanRunStatus {
    Completed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpProbeResult {
    pub address: IpAddr,
    pub port: u16,
    pub state: TcpProbeState,
    pub duration_millis: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpProbeState {
    Open,
    Closed,
    TimedOut,
    Unreachable,
    Cancelled,
    Error,
}

/// Executes bounded TCP-connect discovery for an immutable, revalidated scope plan.
///
/// No raw sockets, payloads, authentication, banners, response bytes, or third-party scanners are
/// used. Each result is limited to address, port, reachability class, and elapsed milliseconds.
///
/// # Errors
///
/// Returns [`ScanExecutionError`] before any connection attempt when the plan or policy is unsafe,
/// and if an internal probe task fails unexpectedly.
pub async fn execute_tcp_connect(
    plan: &ScanPlan,
    policy: ScanExecutionPolicy,
    cancellation: &ScanCancellation,
) -> Result<TcpScanRun, ScanExecutionError> {
    plan.validate_integrity()?;
    let policy = policy.validate()?;
    let started_at = Utc::now();
    let sockets = plan
        .targets
        .iter()
        .flat_map(|address| {
            plan.ports
                .iter()
                .map(move |port| SocketAddr::new(*address, *port))
        })
        .collect::<Vec<_>>();
    let mut next = 0_usize;
    let mut tasks = JoinSet::new();
    let mut results = Vec::with_capacity(sockets.len());

    schedule_probes(&mut tasks, &sockets, &mut next, policy, cancellation);
    while let Some(joined) = tasks.join_next().await {
        results.push(joined.map_err(|_| ScanExecutionError::ProbeTaskFailed)?);
        schedule_probes(&mut tasks, &sockets, &mut next, policy, cancellation);
    }
    results.sort_by_key(|result| (result.address, result.port));
    let completed_probes = results.len() as u64;

    Ok(TcpScanRun {
        scope_digest: plan.scope_digest.clone(),
        status: if cancellation.is_cancelled() {
            ScanRunStatus::Cancelled
        } else {
            ScanRunStatus::Completed
        },
        started_at,
        finished_at: Utc::now(),
        planned_probes: plan.probe_count,
        completed_probes,
        results,
    })
}

fn schedule_probes(
    tasks: &mut JoinSet<TcpProbeResult>,
    sockets: &[SocketAddr],
    next: &mut usize,
    policy: ScanExecutionPolicy,
    cancellation: &ScanCancellation,
) {
    while tasks.len() < policy.concurrency as usize
        && *next < sockets.len()
        && !cancellation.is_cancelled()
    {
        let socket = sockets[*next];
        *next += 1;
        let receiver = cancellation.sender.subscribe();
        tasks.spawn(probe(socket, policy.connect_timeout_millis, receiver));
    }
}

async fn probe(
    socket: SocketAddr,
    timeout_millis: u64,
    mut cancellation: watch::Receiver<bool>,
) -> TcpProbeResult {
    let started = Instant::now();
    let state = if *cancellation.borrow() {
        TcpProbeState::Cancelled
    } else {
        tokio::select! {
            biased;
            changed = cancellation.changed() => {
                if changed.is_ok() && *cancellation.borrow() {
                    TcpProbeState::Cancelled
                } else {
                    TcpProbeState::Error
                }
            }
            connected = tokio::time::timeout(
                Duration::from_millis(timeout_millis),
                TcpStream::connect(socket),
            ) => classify_connect_result(connected),
        }
    };
    TcpProbeResult {
        address: socket.ip(),
        port: socket.port(),
        state,
        duration_millis: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn classify_connect_result(
    result: Result<Result<TcpStream, std::io::Error>, tokio::time::error::Elapsed>,
) -> TcpProbeState {
    match result {
        Ok(Ok(_)) => TcpProbeState::Open,
        Err(_) => TcpProbeState::TimedOut,
        Ok(Err(error)) => match error.kind() {
            std::io::ErrorKind::ConnectionRefused => TcpProbeState::Closed,
            std::io::ErrorKind::AddrNotAvailable
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::NetworkUnreachable => TcpProbeState::Unreachable,
            std::io::ErrorKind::TimedOut => TcpProbeState::TimedOut,
            _ => TcpProbeState::Error,
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ScanExecutionError {
    #[error("scan plan is invalid: {0}")]
    InvalidPlan(&'static str),
    #[error("scan concurrency {0} is outside the safe supported range")]
    UnsafeConcurrency(u16),
    #[error("scan timeout {0}ms is outside the safe supported range")]
    UnsafeTimeout(u64),
    #[error("an internal probe task failed")]
    ProbeTaskFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpFingerprintAttempt {
    pub fingerprint_id: String,
    pub address: IpAddr,
    pub port: u16,
    pub outcome: HttpFingerprintOutcome,
    pub duration_millis: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facts: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<MatchHit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcript_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpFingerprintOutcome {
    Matched,
    NoMatch,
    UnexpectedStatus,
    UnexpectedContentType,
    ResponseTooLarge,
    TimedOut,
    RequestFailed,
    Cancelled,
}

/// Runs registry-signed benign HTTP fingerprints only against open ports in a completed TCP run.
///
/// Redirects are disabled. Registry-enumerated `GET`/`HEAD`/`OPTIONS` requests and compiled benign
/// protocol-metadata `POST` probes are possible; arbitrary request bodies are not. Each response is
/// size/time bounded. Bodies exist only long enough to evaluate declared assertions; returned data
/// contains safe extracted facts and a transcript digest, never bytes.
///
/// # Errors
///
/// Returns [`FingerprintExecutionError`] before requests when the scope receipt, TCP run, or
/// registry is invalid.
pub async fn execute_http_fingerprints(
    plan: &ScanPlan,
    registry: &RegistryBundle,
    tcp_run: &TcpScanRun,
    cancellation: &ScanCancellation,
) -> Result<Vec<HttpFingerprintAttempt>, FingerprintExecutionError> {
    plan.validate_integrity()?;
    registry.validate()?;
    if tcp_run.scope_digest != plan.scope_digest || tcp_run.status != ScanRunStatus::Completed {
        return Err(FingerprintExecutionError::InvalidTcpRun);
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Godel-Tally/0.1 (+https://github.com/godellabs-ai/godel-tally)")
        .build()
        .map_err(|_| FingerprintExecutionError::ClientBuild)?;
    let mut attempts = Vec::new();

    for open in tcp_run
        .results
        .iter()
        .filter(|result| result.state == TcpProbeState::Open)
    {
        for fingerprint in registry
            .fingerprints
            .iter()
            .filter(|fingerprint| fingerprint.ports.contains(&open.port))
        {
            attempts.push(
                execute_http_fingerprint(
                    &client,
                    registry,
                    fingerprint,
                    open.address,
                    open.port,
                    cancellation,
                )
                .await,
            );
            if cancellation.is_cancelled() {
                return Ok(attempts);
            }
        }
    }
    attempts.sort_by(|left, right| {
        (left.address, left.port, &left.fingerprint_id).cmp(&(
            right.address,
            right.port,
            &right.fingerprint_id,
        ))
    });
    Ok(attempts)
}

async fn execute_http_fingerprint(
    client: &reqwest::Client,
    registry: &RegistryBundle,
    fingerprint: &HttpFingerprint,
    address: IpAddr,
    port: u16,
    cancellation: &ScanCancellation,
) -> HttpFingerprintAttempt {
    let started = Instant::now();
    let mut receiver = cancellation.sender.subscribe();
    let socket = SocketAddr::new(address, port);
    let request = fetch_fingerprint(client, fingerprint, socket);
    let response = if *receiver.borrow() {
        FingerprintResponse::Cancelled
    } else {
        tokio::select! {
            biased;
            changed = receiver.changed() => {
                if changed.is_ok() && *receiver.borrow() {
                    FingerprintResponse::Cancelled
                } else {
                    FingerprintResponse::RequestFailed
                }
            }
            result = tokio::time::timeout(
                Duration::from_millis(fingerprint.timeout_millis), request
            ) => match result {
                Ok(response) => response,
                Err(_) => FingerprintResponse::TimedOut,
            }
        }
    };
    let mut attempt = HttpFingerprintAttempt {
        fingerprint_id: fingerprint.id.clone(),
        address,
        port,
        outcome: HttpFingerprintOutcome::RequestFailed,
        duration_millis: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        status_code: None,
        content_type: None,
        facts: BTreeMap::new(),
        matches: Vec::new(),
        transcript_sha256: None,
    };

    match response {
        FingerprintResponse::Received {
            status_code,
            content_type,
            body,
            transcript_sha256,
        } => {
            attempt.status_code = Some(status_code);
            attempt.content_type = content_type;
            attempt.transcript_sha256 = Some(transcript_sha256);
            if !(200..300).contains(&status_code) {
                attempt.outcome = HttpFingerprintOutcome::UnexpectedStatus;
            } else if let Some(facts) = evaluate_assertions(fingerprint, &body) {
                attempt.outcome = HttpFingerprintOutcome::Matched;
                attempt.facts = facts;
                attempt.matches = registry.match_fingerprint(&fingerprint.id);
            } else {
                attempt.outcome = HttpFingerprintOutcome::NoMatch;
            }
        }
        FingerprintResponse::UnexpectedContentType {
            status_code,
            content_type,
            transcript_sha256,
        } => {
            attempt.outcome = HttpFingerprintOutcome::UnexpectedContentType;
            attempt.status_code = Some(status_code);
            attempt.content_type = content_type;
            attempt.transcript_sha256 = Some(transcript_sha256);
        }
        FingerprintResponse::ResponseTooLarge {
            status_code,
            content_type,
            transcript_sha256,
        } => {
            attempt.outcome = HttpFingerprintOutcome::ResponseTooLarge;
            attempt.status_code = Some(status_code);
            attempt.content_type = content_type;
            attempt.transcript_sha256 = Some(transcript_sha256);
        }
        FingerprintResponse::TimedOut => attempt.outcome = HttpFingerprintOutcome::TimedOut,
        FingerprintResponse::RequestFailed => {
            attempt.outcome = HttpFingerprintOutcome::RequestFailed;
        }
        FingerprintResponse::Cancelled => attempt.outcome = HttpFingerprintOutcome::Cancelled,
    }
    attempt.duration_millis = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    attempt
}

#[derive(Debug)]
enum FingerprintResponse {
    Received {
        status_code: u16,
        content_type: Option<String>,
        body: Vec<u8>,
        transcript_sha256: String,
    },
    UnexpectedContentType {
        status_code: u16,
        content_type: Option<String>,
        transcript_sha256: String,
    },
    ResponseTooLarge {
        status_code: u16,
        content_type: Option<String>,
        transcript_sha256: String,
    },
    TimedOut,
    RequestFailed,
    Cancelled,
}

async fn fetch_fingerprint(
    client: &reqwest::Client,
    fingerprint: &HttpFingerprint,
    socket: SocketAddr,
) -> FingerprintResponse {
    let method = match fingerprint.method {
        SafeHttpMethod::Get => reqwest::Method::GET,
        SafeHttpMethod::Head => reqwest::Method::HEAD,
        SafeHttpMethod::Options => reqwest::Method::OPTIONS,
        SafeHttpMethod::Post => reqwest::Method::POST,
    };
    let url = format!("http://{socket}{}", fingerprint.path);
    let mut request = client.request(method, url).header(
        reqwest::header::ACCEPT,
        fingerprint.accepted_content_types.join(", "),
    );
    if let Some(probe) = fingerprint.request {
        request = apply_safe_probe(request, probe);
    }
    let Ok(mut response) = request.send().await else {
        return FingerprintResponse::RequestFailed;
    };
    let status_code = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        });
    let mut transcript = Sha256::new();
    transcript.update(status_code.to_be_bytes());
    if let Some(content_type) = &content_type {
        transcript.update((content_type.len() as u64).to_be_bytes());
        transcript.update(content_type.as_bytes());
    }
    if !content_type.as_ref().is_some_and(|actual| {
        fingerprint
            .accepted_content_types
            .iter()
            .any(|accepted| actual == accepted)
    }) {
        return FingerprintResponse::UnexpectedContentType {
            status_code,
            content_type,
            transcript_sha256: hex::encode(transcript.finalize()),
        };
    }
    if response
        .content_length()
        .is_some_and(|length| length > u64::from(fingerprint.max_response_bytes))
    {
        return FingerprintResponse::ResponseTooLarge {
            status_code,
            content_type,
            transcript_sha256: hex::encode(transcript.finalize()),
        };
    }

    let mut body = Vec::new();
    loop {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(_) => return FingerprintResponse::RequestFailed,
        };
        if body.len().saturating_add(chunk.len()) > fingerprint.max_response_bytes as usize {
            return FingerprintResponse::ResponseTooLarge {
                status_code,
                content_type,
                transcript_sha256: hex::encode(transcript.finalize()),
            };
        }
        transcript.update(&chunk);
        body.extend_from_slice(&chunk);
    }
    FingerprintResponse::Received {
        status_code,
        content_type,
        body,
        transcript_sha256: hex::encode(transcript.finalize()),
    }
}

fn apply_safe_probe(
    request: reqwest::RequestBuilder,
    probe: SafeProbeRequest,
) -> reqwest::RequestBuilder {
    match probe {
        SafeProbeRequest::McpServerDiscover20260728 => request
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "server/discover")
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "godel-tally-discovery",
                "method": "server/discover",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities": {},
                        "io.modelcontextprotocol/clientInfo": {
                            "name": "godel-tally",
                            "version": env!("CARGO_PKG_VERSION")
                        }
                    }
                }
            })),
    }
}

fn evaluate_assertions(
    fingerprint: &HttpFingerprint,
    body: &[u8],
) -> Option<BTreeMap<String, String>> {
    let document = parse_json_response(body)?;
    let mut facts = BTreeMap::new();
    for assertion in &fingerprint.assertions {
        match assertion {
            FingerprintAssertion::JsonStringPresent { field, fact } => {
                let value = json_path(&document, field)?.as_str()?;
                if !safe_extracted_fact(value) {
                    return None;
                }
                facts.insert(fact.clone(), value.to_owned());
            }
            FingerprintAssertion::JsonStringEquals { field, value } => {
                if json_path(&document, field)?.as_str()? != value {
                    return None;
                }
            }
            FingerprintAssertion::JsonArrayPresent { field, count_fact } => {
                let values = json_path(&document, field)?.as_array()?;
                facts.insert(count_fact.clone(), values.len().to_string());
            }
        }
    }
    Some(facts)
}

fn parse_json_response(body: &[u8]) -> Option<serde_json::Value> {
    serde_json::from_slice(body).ok().or_else(|| {
        std::str::from_utf8(body)
            .ok()?
            .lines()
            .filter_map(|line| line.strip_prefix("data:").map(str::trim))
            .find_map(|data| serde_json::from_str(data).ok())
    })
}

fn json_path<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    path.split('.')
        .try_fold(value, |current, segment| current.as_object()?.get(segment))
}

fn safe_extracted_fact(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+' | b'/')
        })
}

#[derive(Debug, Error)]
pub enum FingerprintExecutionError {
    #[error(transparent)]
    InvalidPlan(#[from] ScanExecutionError),
    #[error("scanner registry is invalid: {0}")]
    Registry(#[from] RegistryError),
    #[error("TCP scan run does not belong to this completed scope")]
    InvalidTcpRun,
    #[error("build the safe HTTP client")]
    ClientBuild,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputKind {
    Target,
    Exclusion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressClass {
    Private,
    Public,
    Forbidden(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ScanScopeError {
    #[error("scan scope contains no targets")]
    NoTargets,
    #[error("scan scope contains no targets after exclusions")]
    NoTargetsAfterExclusions,
    #[error("scan host cap {0} is outside the safe supported range 1..={HARD_MAX_HOSTS}")]
    UnsafeHostCap(u32),
    #[error("invalid {kind} '{value}'; only exact IP addresses and CIDRs are accepted")]
    InvalidNetwork { kind: &'static str, value: String },
    #[error("scan port {0} has no approved Phase 1 fingerprint")]
    UnsafePort(u16),
    #[error("public target {0} requires --allow-public")]
    PublicTargetRequiresOptIn(IpAddr),
    #[error("public target {0} requires an explicit authorization acknowledgement")]
    PublicAuthorizationRequired(IpAddr),
    #[error("target {address} is forbidden: {reason}")]
    ForbiddenTarget {
        address: IpAddr,
        reason: &'static str,
    },
    #[error("expanded scan scope exceeds the configured host cap of {cap}")]
    HostCapExceeded { cap: u32 },
}

fn parse_nets(values: &[String], kind: InputKind) -> Result<Vec<IpNet>, ScanScopeError> {
    values
        .iter()
        .map(|value| {
            value
                .parse::<IpNet>()
                .or_else(|_| value.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| ScanScopeError::InvalidNetwork {
                    kind: match kind {
                        InputKind::Target => "target",
                        InputKind::Exclusion => "exclusion",
                    },
                    value: value.clone(),
                })
        })
        .collect()
}

fn normalize_ports(requested: &[u16]) -> Result<Vec<u16>, ScanScopeError> {
    let ports = if requested.is_empty() {
        DEFAULT_PORTS.iter().copied().collect::<BTreeSet<_>>()
    } else {
        requested.iter().copied().collect::<BTreeSet<_>>()
    };

    for port in &ports {
        if !SAFE_PORTS.contains(port) {
            return Err(ScanScopeError::UnsafePort(*port));
        }
    }
    Ok(ports.into_iter().collect())
}

fn local_candidate(
    interface_name: &str,
    address: IpAddr,
    network: IpNet,
    max_hosts: u32,
) -> Result<String, &'static str> {
    if excluded_interface_name(interface_name) {
        return Err("tunnel, virtual, or container interface");
    }
    if address.is_loopback() {
        return Err("loopback interface");
    }
    if matches!(classify(address), AddressClass::Forbidden(_)) {
        return Err("link-local, multicast, or unspecified interface address");
    }
    if !matches!(classify(address), AddressClass::Private) {
        return Err("public interface address");
    }

    let expansion = network.hosts().take(max_hosts as usize + 1).count();
    if expansion > max_hosts as usize {
        return Err("connected network exceeds the automatic host cap");
    }
    Ok(network.trunc().to_string())
}

fn excluded_interface_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "lo",
        "utun",
        "tun",
        "tap",
        "wg",
        "docker",
        "br-",
        "bridge",
        "veth",
        "virbr",
        "vmnet",
        "vboxnet",
        "colima",
        "tailscale",
        "zt",
        "awdl",
        "llw",
        "p2p",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

fn classify(address: IpAddr) -> AddressClass {
    match address {
        IpAddr::V4(address) => classify_v4(address),
        IpAddr::V6(address) => classify_v6(address),
    }
}

fn classify_v4(address: Ipv4Addr) -> AddressClass {
    if address.is_unspecified() {
        AddressClass::Forbidden("unspecified address")
    } else if address.is_broadcast() {
        AddressClass::Forbidden("limited broadcast address")
    } else if address.is_link_local() {
        AddressClass::Forbidden("link-local and cloud metadata range")
    } else if address.is_multicast() {
        AddressClass::Forbidden("multicast address")
    } else if address.is_private() || address.is_loopback() {
        AddressClass::Private
    } else {
        AddressClass::Public
    }
}

fn classify_v6(address: Ipv6Addr) -> AddressClass {
    if address.is_unspecified() {
        AddressClass::Forbidden("unspecified address")
    } else if address.is_unicast_link_local() {
        AddressClass::Forbidden("link-local address")
    } else if address.is_multicast() {
        AddressClass::Forbidden("multicast address")
    } else if address.is_unique_local() || address.is_loopback() {
        AddressClass::Private
    } else {
        AddressClass::Public
    }
}

fn scope_digest(
    targets: &[IpAddr],
    ports: &[u16],
    allow_public: bool,
    authorization_acknowledged: bool,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SCAN_PLAN_VERSION.as_bytes());
    hasher.update([u8::from(allow_public)]);
    hasher.update([u8::from(authorization_acknowledged)]);
    for target in targets {
        hasher.update(target.to_string().as_bytes());
        hasher.update([0]);
    }
    for port in ports {
        hasher.update(port.to_be_bytes());
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    use chrono::NaiveDate;
    use tally_registry_lib::{
        Evidence, EvidenceType, MatchProduces, Matcher, MatcherRule, ProofKind,
        REGISTRY_SCHEMA_VERSION, RegistryEntry, RegistryEntryKind, RegistryEntryStatus,
        RegistrySource,
    };

    use super::*;

    fn scope(targets: &[&str]) -> ScanScope {
        ScanScope {
            targets: targets.iter().map(ToString::to_string).collect(),
            exclusions: Vec::new(),
            ports: vec![11_434, 443, 11_434],
            max_hosts: DEFAULT_MAX_HOSTS,
            allow_public: false,
            authorization_acknowledged: false,
        }
    }

    #[test]
    fn empty_scope_is_rejected() {
        assert_eq!(scope(&[]).plan(), Err(ScanScopeError::NoTargets));
    }

    #[test]
    fn private_and_loopback_targets_are_planned_deterministically() {
        let plan = scope(&["10.0.0.2", "127.0.0.1", "10.0.0.0/30"])
            .plan()
            .expect("safe plan");
        assert_eq!(
            plan.targets,
            ["10.0.0.1", "10.0.0.2", "127.0.0.1"]
                .map(|value| value.parse::<IpAddr>().expect("valid test IP"))
        );
        assert_eq!(plan.ports, vec![443, 11_434]);
        assert_eq!(plan.host_count, 3);
        assert_eq!(plan.probe_count, 6);

        let reversed = scope(&["10.0.0.0/30", "127.0.0.1", "10.0.0.2"])
            .plan()
            .expect("safe plan");
        assert_eq!(plan.scope_digest, reversed.scope_digest);
    }

    #[test]
    fn exclusions_apply_before_the_host_cap() {
        let mut request = scope(&["10.0.0.0/29"]);
        request.exclusions = vec!["10.0.0.2/31".into(), "10.0.0.6".into()];
        request.max_hosts = 3;
        let plan = request.plan().expect("exclusions reduce scope to cap");
        assert_eq!(
            plan.targets,
            ["10.0.0.1", "10.0.0.4", "10.0.0.5"]
                .map(|value| value.parse::<IpAddr>().expect("valid test IP"))
        );
    }

    #[test]
    fn cap_is_enforced_before_a_large_network_can_expand() {
        let mut request = scope(&["10.0.0.0/8"]);
        request.max_hosts = 4;
        assert_eq!(
            request.plan(),
            Err(ScanScopeError::HostCapExceeded { cap: 4 })
        );
    }

    #[test]
    fn public_scope_requires_both_controls() {
        let mut request = scope(&["8.8.8.8"]);
        assert_eq!(
            request.plan(),
            Err(ScanScopeError::PublicTargetRequiresOptIn(
                "8.8.8.8".parse().expect("valid test IP")
            ))
        );

        request.allow_public = true;
        assert_eq!(
            request.plan(),
            Err(ScanScopeError::PublicAuthorizationRequired(
                "8.8.8.8".parse().expect("valid test IP")
            ))
        );

        request.authorization_acknowledged = true;
        assert!(request.plan().is_ok());
    }

    #[test]
    fn metadata_link_local_and_multicast_targets_are_always_forbidden() {
        for target in ["169.254.169.254", "fe80::1", "224.0.0.1", "ff02::1"] {
            let mut request = scope(&[target]);
            request.allow_public = true;
            request.authorization_acknowledged = true;
            assert!(matches!(
                request.plan(),
                Err(ScanScopeError::ForbiddenTarget { .. })
            ));
        }
    }

    #[test]
    fn ipv6_unique_local_targets_are_private() {
        let plan = scope(&["fd00::1", "fd00::/126"])
            .plan()
            .expect("ULA is private");
        assert_eq!(plan.host_count, 4);
    }

    #[test]
    fn non_allowlisted_ports_are_rejected() {
        let mut request = scope(&["10.0.0.1"]);
        request.ports = vec![22];
        assert_eq!(request.plan(), Err(ScanScopeError::UnsafePort(22)));
    }

    #[test]
    fn names_are_rejected_to_avoid_dns_rebinding() {
        assert!(matches!(
            scope(&["ollama.internal"]).plan(),
            Err(ScanScopeError::InvalidNetwork { .. })
        ));
    }

    #[test]
    fn default_discovery_accepts_only_bounded_physical_private_networks() {
        let private = IpNet::new("192.168.50.9".parse().expect("IP"), 24).expect("network");
        assert_eq!(
            local_candidate(
                "en0",
                "192.168.50.9".parse().expect("IP"),
                private,
                DEFAULT_MAX_HOSTS
            ),
            Ok("192.168.50.0/24".into())
        );

        assert_eq!(
            local_candidate(
                "utun4",
                "10.10.0.2".parse().expect("IP"),
                "10.10.0.0/24".parse().expect("network"),
                DEFAULT_MAX_HOSTS
            ),
            Err("tunnel, virtual, or container interface")
        );
        assert_eq!(
            local_candidate(
                "en0",
                "10.10.0.2".parse().expect("IP"),
                "10.0.0.0/8".parse().expect("network"),
                DEFAULT_MAX_HOSTS
            ),
            Err("connected network exceeds the automatic host cap")
        );
    }

    #[test]
    fn tampered_plan_is_rejected_before_execution() {
        let mut plan = scope(&["10.0.0.1"]).plan().expect("safe plan");
        plan.probe_count += 1;
        assert_eq!(
            plan.validate_integrity(),
            Err(ScanExecutionError::InvalidPlan("probe count mismatch"))
        );
    }

    #[tokio::test]
    async fn pre_cancelled_run_sends_no_probes() {
        let plan = scope(&["127.0.0.1"]).plan().expect("safe plan");
        let cancellation = ScanCancellation::default();
        cancellation.cancel();
        let run = execute_tcp_connect(&plan, ScanExecutionPolicy::default(), &cancellation)
            .await
            .expect("cancelled run");
        assert_eq!(run.status, ScanRunStatus::Cancelled);
        assert_eq!(run.completed_probes, 0);
        assert_eq!(run.results, [] as [TcpProbeResult; 0]);
    }

    #[tokio::test]
    async fn unsafe_execution_policy_fails_before_probing() {
        let plan = scope(&["127.0.0.1"]).plan().expect("safe plan");
        let error = execute_tcp_connect(
            &plan,
            ScanExecutionPolicy {
                concurrency: MAX_CONNECT_CONCURRENCY + 1,
                connect_timeout_millis: DEFAULT_CONNECT_TIMEOUT_MILLIS,
            },
            &ScanCancellation::default(),
        )
        .await
        .expect_err("unsafe policy");
        assert_eq!(
            error,
            ScanExecutionError::UnsafeConcurrency(MAX_CONNECT_CONCURRENCY + 1)
        );
    }

    #[tokio::test]
    #[ignore = "requires permission to bind a loopback fixture server"]
    async fn http_fingerprint_extracts_only_declared_safe_facts() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let port = listener.local_addr().expect("fixture address").port();
        let canary = "PROMPT_CONTENT_MUST_NOT_SURVIVE";
        let body = format!(r#"{{"version":"0.11.7","prompt":"{canary}"}}"#);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let fixture = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept fixture request");
            let mut request = [0_u8; 1_024];
            let _ = stream.read(&mut request).expect("read fixture request");
            stream
                .write_all(response.as_bytes())
                .expect("write fixture response");
        });
        let registry = fingerprint_registry(port);
        let attempt = execute_http_fingerprint(
            &reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("client"),
            &registry,
            &registry.fingerprints[0],
            "127.0.0.1".parse().expect("IP"),
            port,
            &ScanCancellation::default(),
        )
        .await;
        fixture.join().expect("fixture server");

        assert_eq!(attempt.outcome, HttpFingerprintOutcome::Matched);
        assert_eq!(
            attempt.facts.get("version").map(String::as_str),
            Some("0.11.7")
        );
        assert_eq!(attempt.matches[0].entry_id, "runtime.ollama");
        let serialized = serde_json::to_string(&attempt).expect("serialize attempt");
        assert!(!serialized.contains(canary));
        assert!(attempt.transcript_sha256.is_some());
    }

    #[tokio::test]
    #[ignore = "requires permission to bind loopback fixture servers"]
    async fn openai_compatible_and_triton_fingerprints_match_live_http_without_model_names() {
        let canary = "MODEL_NAME_MUST_NOT_SURVIVE";
        let generic = exercise_runtime_fixture(
            openai_models_fingerprint,
            &format!(r#"{{"object":"list","data":[{{"id":"{canary}"}}]}}"#),
            "runtime.openai_compatible_api",
        )
        .await;
        assert_eq!(
            generic.facts.get("model_count").map(String::as_str),
            Some("1")
        );
        assert!(
            !serde_json::to_string(&generic)
                .expect("serialize")
                .contains(canary)
        );

        let triton = exercise_runtime_fixture(
            triton_fingerprint,
            &format!(r#"{{"name":"triton","version":"2.60.0","extensions":["classification"],"models":["{canary}"]}}"#),
            "runtime.triton",
        )
        .await;
        assert_eq!(
            triton.facts.get("version").map(String::as_str),
            Some("2.60.0")
        );
        assert!(
            !serde_json::to_string(&triton)
                .expect("serialize")
                .contains(canary)
        );
    }

    #[test]
    fn mcp_sse_probe_extracts_only_nested_declared_facts() {
        let fingerprint = mcp_fingerprint(3_000);
        let canary = "MCP_INSTRUCTIONS_MUST_NOT_SURVIVE";
        let body = format!(
            "event: message\ndata: {{\"jsonrpc\":\"2.0\",\"result\":{{\"supportedVersions\":[\"2026-07-28\",\"2025-11-25\"],\"instructions\":\"{canary}\"}}}}\n\n"
        );
        let facts = evaluate_assertions(&fingerprint, body.as_bytes()).expect("MCP match");
        assert_eq!(
            facts.get("protocol_version_count").map(String::as_str),
            Some("2")
        );
        assert!(
            !serde_json::to_string(&facts)
                .expect("serialize facts")
                .contains(canary)
        );
    }

    #[test]
    fn openai_models_shape_resolves_generically_not_as_vllm() {
        // The bug this guards against: LiteLLM (and every other OpenAI-compatible
        // server) returns the exact `{"object":"list","data":[...]}` document that the
        // old vLLM fingerprint asserted, so LiteLLM deployments were labeled vLLM.
        let litellm_models_body = r#"{"object":"list","data":[{"id":"xai/grok-2-1212","object":"model","created":1677610602,"owned_by":"openai"}]}"#;

        // The generic fingerprint still matches the shared shape...
        let generic = openai_models_fingerprint(8_000);
        let facts =
            evaluate_assertions(&generic, litellm_models_body.as_bytes()).expect("generic match");
        assert_eq!(facts.get("model_count").map(String::as_str), Some("1"));

        // ...but the distinctive vLLM fingerprint refuses it: /version's document
        // is absent from a model listing.
        let vllm = vllm_version_fingerprint(8_000);
        assert!(evaluate_assertions(&vllm, litellm_models_body.as_bytes()).is_none());

        // And the distinctive vLLM body never satisfies the generic listing shape.
        let vllm_version_body = r#"{"version":"0.10.0"}"#;
        assert!(evaluate_assertions(&generic, vllm_version_body.as_bytes()).is_none());
        let vllm_facts =
            evaluate_assertions(&vllm, vllm_version_body.as_bytes()).expect("vLLM match");
        assert_eq!(
            vllm_facts.get("version").map(String::as_str),
            Some("0.10.0")
        );
    }

    #[test]
    fn litellm_readiness_probe_extracts_only_bounded_states() {
        let fingerprint = litellm_readiness_fingerprint(4_000);

        // Documented public readiness body when a database is configured.
        let facts = evaluate_assertions(&fingerprint, br#"{"status":"healthy","db":"connected"}"#)
            .expect("LiteLLM readiness match");
        assert_eq!(
            facts.get("readiness_status").map(String::as_str),
            Some("healthy")
        );
        // Only the bounded readiness token is extracted; the database state is not a fact.
        assert_eq!(facts.len(), 1);

        // Regression guard for a shadow-AI blind spot: LiteLLM reports `db: "Not connected"`
        // when no database is configured, which is both the simplest deployment and the most
        // likely to be unregistered. Asserting `db` made every such proxy undetectable because
        // the value cannot pass the safe-fact filter, so `db` is deliberately not asserted.
        let database_less = evaluate_assertions(
            &fingerprint,
            br#"{"status":"healthy","db":"Not connected"}"#,
        )
        .expect("database-less LiteLLM must still be detected");
        assert_eq!(
            database_less.get("readiness_status").map(String::as_str),
            Some("healthy")
        );

        // An unhealthy proxy is still a discovered proxy.
        assert!(evaluate_assertions(&fingerprint, br#"{"status":"unhealthy"}"#).is_some());

        // Neighboring runtimes never satisfy the readiness shape: neither a vLLM version
        // document nor an OpenAI model listing carries a `status` string.
        assert!(evaluate_assertions(&fingerprint, br#"{"version":"0.10.0"}"#).is_none());
        assert!(evaluate_assertions(&fingerprint, br#"{"object":"list","data":[]}"#).is_none());

        // A LiteLLM readiness body never satisfies the vLLM or generic fingerprints.
        let readiness_body = br#"{"status":"healthy","db":"connected"}"#;
        assert!(evaluate_assertions(&vllm_version_fingerprint(8_000), readiness_body).is_none());
        assert!(evaluate_assertions(&openai_models_fingerprint(8_000), readiness_body).is_none());
    }

    #[test]
    fn triton_probe_extracts_only_declared_metadata() {
        let fingerprint = triton_fingerprint(8_000);
        let canary = "TRITON_MODEL_NAME_MUST_NOT_SURVIVE";
        let body = format!(
            r#"{{"name":"triton","version":"2.60.0","extensions":["classification","model_repository"],"models":["{canary}"]}}"#
        );
        let facts = evaluate_assertions(&fingerprint, body.as_bytes()).expect("Triton match");
        assert_eq!(facts.get("version").map(String::as_str), Some("2.60.0"));
        assert_eq!(facts.get("extension_count").map(String::as_str), Some("2"));
        assert!(
            !serde_json::to_string(&facts)
                .expect("serialize facts")
                .contains(canary)
        );
    }

    #[tokio::test]
    #[ignore = "requires permission to bind a loopback fixture server"]
    async fn mcp_fingerprint_uses_only_server_discovery_and_discards_instructions() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let port = listener.local_addr().expect("fixture address").port();
        let canary = "MCP_SERVER_INSTRUCTIONS_MUST_NOT_SURVIVE";
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":"godel-tally-discovery","result":{{"supportedVersions":["2026-07-28"],"capabilities":{{}},"instructions":"{canary}"}}}}"#
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let fixture = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept fixture request");
            let mut request = [0_u8; 4_096];
            let bytes = stream.read(&mut request).expect("read fixture request");
            stream
                .write_all(response.as_bytes())
                .expect("write fixture response");
            String::from_utf8_lossy(&request[..bytes]).into_owned()
        });
        let registry = mcp_fingerprint_registry(port);
        let attempt = execute_http_fingerprint(
            &reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("client"),
            &registry,
            &registry.fingerprints[0],
            "127.0.0.1".parse().expect("IP"),
            port,
            &ScanCancellation::default(),
        )
        .await;
        let request = fixture.join().expect("fixture server");

        assert!(request.starts_with("POST /mcp HTTP/1.1"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("mcp-method: server/discover")
        );
        assert!(request.contains("\"method\":\"server/discover\""));
        assert!(!request.contains("tools/call"));
        assert_eq!(attempt.outcome, HttpFingerprintOutcome::Matched);
        assert_eq!(attempt.matches[0].entry_id, "runtime.mcp_streamable_http");
        let serialized = serde_json::to_string(&attempt).expect("serialize attempt");
        assert!(!serialized.contains(canary));
    }

    fn fingerprint_registry(port: u16) -> RegistryBundle {
        let date = NaiveDate::from_ymd_opt(2026, 8, 13).expect("date");
        let evidence = Evidence {
            source_type: EvidenceType::VendorDocumentation,
            url: "https://docs.ollama.com/api/version".into(),
            verified_at: date,
            reviewer: "test".into(),
        };
        RegistrySource {
            schema_version: REGISTRY_SCHEMA_VERSION.into(),
            version: "fixture".into(),
            fingerprints: vec![HttpFingerprint {
                id: "fingerprint.ollama.version_v1".into(),
                ports: vec![port],
                method: SafeHttpMethod::Get,
                request: None,
                path: "/api/version".into(),
                accepted_content_types: vec!["application/json".into()],
                max_response_bytes: 4_096,
                timeout_millis: 1_500,
                assertions: vec![FingerprintAssertion::JsonStringPresent {
                    field: "version".into(),
                    fact: "version".into(),
                }],
                verified_at: date,
                evidence: vec![evidence.clone()],
            }],
            entries: vec![RegistryEntry {
                id: "runtime.ollama".into(),
                kind: RegistryEntryKind::Runtime,
                name: "Ollama".into(),
                provider_ref: None,
                categories: vec!["runtime".into()],
                surfaces: vec!["self_hosted_api".into()],
                facts: BTreeMap::new(),
                matchers: vec![Matcher {
                    id: "scanner.version".into(),
                    rule: MatcherRule::ScannerFingerprint {
                        fingerprint_ref: "fingerprint.ollama.version_v1".into(),
                    },
                    produces: MatchProduces {
                        entity_ref: "runtime.ollama".into(),
                        proof: ProofKind::RuntimeReachable,
                    },
                    confidence_bps: 9_800,
                    verified_at: date,
                    evidence: vec![evidence],
                }],
                status: RegistryEntryStatus::Active,
            }],
        }
        .compile("fixture")
        .expect("compile fixture registry")
        .bundle
    }

    fn mcp_fingerprint(port: u16) -> HttpFingerprint {
        let date = NaiveDate::from_ymd_opt(2026, 8, 13).expect("date");
        HttpFingerprint {
            id: "fingerprint.mcp.server_discover_20260728".into(),
            ports: vec![port],
            method: SafeHttpMethod::Post,
            request: Some(SafeProbeRequest::McpServerDiscover20260728),
            path: "/mcp".into(),
            accepted_content_types: vec!["application/json".into(), "text/event-stream".into()],
            max_response_bytes: 16_384,
            timeout_millis: 1_500,
            assertions: vec![
                FingerprintAssertion::JsonStringEquals {
                    field: "jsonrpc".into(),
                    value: "2.0".into(),
                },
                FingerprintAssertion::JsonArrayPresent {
                    field: "result.supportedVersions".into(),
                    count_fact: "protocol_version_count".into(),
                },
            ],
            verified_at: date,
            evidence: vec![Evidence {
                source_type: EvidenceType::StandardsBody,
                url: "https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http".into(),
                verified_at: date,
                reviewer: "test".into(),
            }],
        }
    }

    fn triton_fingerprint(port: u16) -> HttpFingerprint {
        let date = NaiveDate::from_ymd_opt(2026, 8, 13).expect("date");
        HttpFingerprint {
            id: "fingerprint.triton.server_metadata_v2".into(),
            ports: vec![port],
            method: SafeHttpMethod::Get,
            request: None,
            path: "/v2".into(),
            accepted_content_types: vec!["application/json".into()],
            max_response_bytes: 16_384,
            timeout_millis: 1_500,
            assertions: vec![
                FingerprintAssertion::JsonStringEquals {
                    field: "name".into(),
                    value: "triton".into(),
                },
                FingerprintAssertion::JsonStringPresent {
                    field: "version".into(),
                    fact: "version".into(),
                },
                FingerprintAssertion::JsonArrayPresent {
                    field: "extensions".into(),
                    count_fact: "extension_count".into(),
                },
            ],
            verified_at: date,
            evidence: vec![Evidence {
                source_type: EvidenceType::VendorDocumentation,
                url: "https://docs.nvidia.com/deeplearning/triton-inference-server/user-guide/docs/customization_guide/inference_protocols.html".into(),
                verified_at: date,
                reviewer: "test".into(),
            }],
        }
    }

    fn openai_models_fingerprint(port: u16) -> HttpFingerprint {
        let date = NaiveDate::from_ymd_opt(2026, 8, 18).expect("date");
        HttpFingerprint {
            id: "fingerprint.openai_compatible.models_v1".into(),
            ports: vec![port],
            method: SafeHttpMethod::Get,
            request: None,
            path: "/v1/models".into(),
            accepted_content_types: vec!["application/json".into()],
            max_response_bytes: 65_536,
            timeout_millis: 1_500,
            assertions: vec![
                FingerprintAssertion::JsonStringEquals {
                    field: "object".into(),
                    value: "list".into(),
                },
                FingerprintAssertion::JsonArrayPresent {
                    field: "data".into(),
                    count_fact: "model_count".into(),
                },
            ],
            verified_at: date,
            evidence: vec![Evidence {
                source_type: EvidenceType::VendorDocumentation,
                url: "https://platform.openai.com/docs/api-reference/models".into(),
                verified_at: date,
                reviewer: "test".into(),
            }],
        }
    }

    fn vllm_version_fingerprint(port: u16) -> HttpFingerprint {
        let date = NaiveDate::from_ymd_opt(2026, 8, 18).expect("date");
        HttpFingerprint {
            id: "fingerprint.vllm.version_v1".into(),
            ports: vec![port],
            method: SafeHttpMethod::Get,
            request: None,
            path: "/version".into(),
            accepted_content_types: vec!["application/json".into()],
            max_response_bytes: 4_096,
            timeout_millis: 1_500,
            assertions: vec![FingerprintAssertion::JsonStringPresent {
                field: "version".into(),
                fact: "version".into(),
            }],
            verified_at: date,
            evidence: vec![Evidence {
                source_type: EvidenceType::VendorDocumentation,
                url: "https://docs.vllm.ai/en/stable/serving/online_serving/".into(),
                verified_at: date,
                reviewer: "test".into(),
            }],
        }
    }

    fn litellm_readiness_fingerprint(port: u16) -> HttpFingerprint {
        let date = NaiveDate::from_ymd_opt(2026, 8, 18).expect("date");
        HttpFingerprint {
            id: "fingerprint.litellm.health_readiness_v1".into(),
            ports: vec![port],
            method: SafeHttpMethod::Get,
            request: None,
            path: "/health/readiness".into(),
            accepted_content_types: vec!["application/json".into()],
            max_response_bytes: 4_096,
            timeout_millis: 1_500,
            assertions: vec![FingerprintAssertion::JsonStringPresent {
                field: "status".into(),
                fact: "readiness_status".into(),
            }],
            verified_at: date,
            evidence: vec![Evidence {
                source_type: EvidenceType::VendorDocumentation,
                url: "https://docs.litellm.ai/docs/proxy/health".into(),
                verified_at: date,
                reviewer: "test".into(),
            }],
        }
    }

    async fn exercise_runtime_fixture(
        fingerprint_factory: fn(u16) -> HttpFingerprint,
        body: &str,
        entry_id: &str,
    ) -> HttpFingerprintAttempt {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let port = listener.local_addr().expect("fixture address").port();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let fixture = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept fixture request");
            let mut request = [0_u8; 1_024];
            let _ = stream.read(&mut request).expect("read fixture request");
            stream
                .write_all(response.as_bytes())
                .expect("write fixture response");
        });
        let fingerprint = fingerprint_factory(port);
        let registry = single_runtime_fingerprint_registry(fingerprint, entry_id);
        let attempt = execute_http_fingerprint(
            &reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("client"),
            &registry,
            &registry.fingerprints[0],
            "127.0.0.1".parse().expect("IP"),
            port,
            &ScanCancellation::default(),
        )
        .await;
        fixture.join().expect("fixture server");
        assert_eq!(attempt.outcome, HttpFingerprintOutcome::Matched);
        assert_eq!(attempt.matches[0].entry_id, entry_id);
        attempt
    }

    fn single_runtime_fingerprint_registry(
        fingerprint: HttpFingerprint,
        entry_id: &str,
    ) -> RegistryBundle {
        let evidence = fingerprint.evidence[0].clone();
        let fingerprint_id = fingerprint.id.clone();
        RegistrySource {
            schema_version: REGISTRY_SCHEMA_VERSION.into(),
            version: "fixture".into(),
            fingerprints: vec![fingerprint],
            entries: vec![RegistryEntry {
                id: entry_id.into(),
                kind: RegistryEntryKind::Runtime,
                name: entry_id.into(),
                provider_ref: None,
                categories: vec!["model_runtime".into()],
                surfaces: vec!["self_hosted_api".into()],
                facts: BTreeMap::new(),
                matchers: vec![Matcher {
                    id: "scanner.fixture".into(),
                    rule: MatcherRule::ScannerFingerprint {
                        fingerprint_ref: fingerprint_id,
                    },
                    produces: MatchProduces {
                        entity_ref: entry_id.into(),
                        proof: ProofKind::RuntimeReachable,
                    },
                    confidence_bps: 9_500,
                    verified_at: evidence.verified_at,
                    evidence: vec![evidence],
                }],
                status: RegistryEntryStatus::Active,
            }],
        }
        .compile("fixture")
        .expect("compile runtime fixture registry")
        .bundle
    }

    fn mcp_fingerprint_registry(port: u16) -> RegistryBundle {
        let fingerprint = mcp_fingerprint(port);
        let evidence = fingerprint.evidence[0].clone();
        RegistrySource {
            schema_version: REGISTRY_SCHEMA_VERSION.into(),
            version: "fixture".into(),
            fingerprints: vec![fingerprint],
            entries: vec![RegistryEntry {
                id: "runtime.mcp_streamable_http".into(),
                kind: RegistryEntryKind::Runtime,
                name: "MCP Streamable HTTP Server".into(),
                provider_ref: None,
                categories: vec!["agent_protocol".into()],
                surfaces: vec!["self_hosted_api".into()],
                facts: BTreeMap::new(),
                matchers: vec![Matcher {
                    id: "scanner.server_discover".into(),
                    rule: MatcherRule::ScannerFingerprint {
                        fingerprint_ref: "fingerprint.mcp.server_discover_20260728".into(),
                    },
                    produces: MatchProduces {
                        entity_ref: "runtime.mcp_streamable_http".into(),
                        proof: ProofKind::RuntimeReachable,
                    },
                    confidence_bps: 9_700,
                    verified_at: evidence.verified_at,
                    evidence: vec![evidence],
                }],
                status: RegistryEntryStatus::Experimental,
            }],
        }
        .compile("fixture")
        .expect("compile MCP fixture registry")
        .bundle
    }
}
