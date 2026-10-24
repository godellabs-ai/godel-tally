use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sigstore_verify::{
    VerificationPolicy,
    trust_root::{SIGSTORE_PRODUCTION_TRUSTED_ROOT, TrustedRoot},
    types::Bundle as SigstoreBundle,
    verify as verify_sigstore,
};
use tally_core::{
    ConnectorContribution, EvidenceLinkContribution, FindingContribution, Hostname,
    IntegrationContractBundle, InventoryContribution, Observation, ReportSectionContribution,
    SignedHostRequestContext,
};
use tally_registry_lib::{
    RegistryBundle, RegistryManifest, RegistryOverlay, RegistrySource, RegistrySourceDocument,
    apply_overlays, verify_artifact,
};
use url::Url;
use uuid::Uuid;

const RELEASE_IDENTITY: &str = "https://github.com/godellabs-ai/godel-tally/.github/workflows/release-registry.yml@refs/heads/main";
const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";

#[derive(Debug, Parser)]
#[command(
    name = "tally-registry",
    version,
    about = "Build, verify, and inspect Tally registry artifacts"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate or verify checked-in `OpenAPI` and JSON Schema artifacts.
    Schemas {
        #[arg(long, default_value = ".")]
        output: PathBuf,
        #[arg(long)]
        check: bool,
    },
    /// Parse, canonicalize, and validate YAML registry source.
    Lint {
        #[arg(long, default_value = "registry-data/source")]
        source: PathBuf,
    },
    /// Compile YAML source into deterministic JSON.zst and manifest artifacts.
    Build {
        #[arg(long, default_value = "registry-data/source")]
        source: PathBuf,
        #[arg(long, default_value = "registry-data/dist")]
        output: PathBuf,
    },
    /// Verify artifact digests, structure, and manifest consistency offline.
    Verify {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Verify a project release, including its pinned Sigstore workflow identity.
    VerifyRelease {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        sigstore: PathBuf,
    },
    /// Verify and atomically activate a signed release after checking local overlays.
    ActivateRelease {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        sigstore: PathBuf,
        #[arg(long)]
        overlay: Vec<PathBuf>,
        #[arg(long, default_value = "data/registry")]
        state_dir: PathBuf,
    },
    /// Roll back to an already retained and re-verified signed release.
    Rollback {
        #[arg(long)]
        version: String,
        #[arg(long)]
        overlay: Vec<PathBuf>,
        #[arg(long, default_value = "data/registry")]
        state_dir: PathBuf,
    },
    /// Work with scrubbed, local-only registry candidates.
    Candidate {
        #[command(subcommand)]
        command: CandidateCommand,
    },
    /// Show non-sensitive metadata from a verified registry bundle.
    Inspect {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Exercise host matching without performing any network access.
    MatchHost {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        host: String,
    },
}

#[derive(Debug, Subcommand)]
enum CandidateCommand {
    /// Export one bounded unknown public-host candidate; never submits it.
    Export {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        acknowledge_manual_contribution: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Schemas { output, check } => schemas(&output, check),
        Command::Lint { source } => lint(&source),
        Command::Build { source, output } => build(&source, &output),
        Command::Verify { bundle, manifest } => {
            let bundle = load_verified(&bundle, &manifest)?;
            println!(
                "verified registry {} ({} entries)",
                bundle.version,
                bundle.entries.len()
            );
            Ok(())
        }
        Command::VerifyRelease {
            bundle,
            manifest,
            sigstore,
        } => verify_release(&bundle, &manifest, &sigstore),
        Command::ActivateRelease {
            bundle,
            manifest,
            sigstore,
            overlay,
            state_dir,
        } => activate_release(&bundle, &manifest, &sigstore, &overlay, &state_dir),
        Command::Rollback {
            version,
            overlay,
            state_dir,
        } => rollback_release(&version, &overlay, &state_dir),
        Command::Candidate { command } => candidate(command),
        Command::Inspect { bundle, manifest } => inspect(&bundle, &manifest),
        Command::MatchHost {
            bundle,
            manifest,
            host,
        } => match_host(&bundle, &manifest, &host),
    }
}

fn verify_release(bundle_path: &Path, manifest_path: &Path, sigstore_path: &Path) -> Result<()> {
    let (bundle, _) = load_verified_release(bundle_path, manifest_path, sigstore_path)?;
    println!(
        "verified signed registry {} from {}",
        bundle.version, RELEASE_IDENTITY
    );
    Ok(())
}

fn load_verified_release(
    bundle_path: &Path,
    manifest_path: &Path,
    sigstore_path: &Path,
) -> Result<(RegistryBundle, RegistryManifest)> {
    let compressed =
        read_bounded_regular_file(bundle_path, 128 * 1024 * 1024, "compressed registry bundle")?;
    let manifest = read_manifest(manifest_path)?;
    let bundle = verify_artifact(&compressed, &manifest).context("verify registry artifact")?;

    let sigstore_json = String::from_utf8(read_bounded_regular_file(
        sigstore_path,
        8 * 1024 * 1024,
        "Sigstore bundle",
    )?)
    .context("Sigstore bundle is not UTF-8")?;
    verify_sigstore_bytes(&compressed, &sigstore_json)?;

    Ok((bundle, manifest))
}

fn verify_sigstore_bytes(compressed: &[u8], sigstore_json: &str) -> Result<()> {
    let sigstore_bundle =
        SigstoreBundle::from_json(sigstore_json).context("parse Sigstore bundle")?;
    let trust_root = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT)
        .context("parse embedded Sigstore production trust root")?;
    let policy = VerificationPolicy::default()
        .require_identity(RELEASE_IDENTITY)
        .require_issuer(GITHUB_ACTIONS_ISSUER);
    verify_sigstore(compressed, &sigstore_bundle, &policy, &trust_root)
        .context("verify Sigstore release identity and transparency evidence")?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveRegistryPointer {
    schema_version: String,
    registry_version: String,
    source_sha256: String,
    #[serde(default)]
    bundle_sha256: Option<String>,
    compressed_sha256: String,
    release_identity: String,
    overlay_ids: Vec<String>,
    relative_path: String,
    #[serde(default)]
    activated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    transition_id: Option<Uuid>,
    #[serde(default)]
    reprocessing_required: bool,
    #[serde(default)]
    content_retained: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RegistryTransitionKind {
    Activation,
    Rollback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RegistryTransitionReceipt {
    schema_version: &'static str,
    transition_id: Uuid,
    operation: RegistryTransitionKind,
    from_version: Option<String>,
    from_compressed_sha256: Option<String>,
    to_version: String,
    to_bundle_sha256: String,
    to_compressed_sha256: String,
    overlay_ids: Vec<String>,
    transitioned_at: DateTime<Utc>,
    release_identity: &'static str,
    reprocessing_required: bool,
    content_retained: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateExportInput {
    schema_version: String,
    host: String,
    proposed_service_name: String,
    observation_count: u32,
    independent_source_count: u8,
    first_observed_at: DateTime<Utc>,
    last_observed_at: DateTime<Utc>,
    observation_kinds: Vec<String>,
    evidence_urls: Vec<String>,
    public_service_endpoint: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CandidateProposalSeed<'a> {
    schema_version: &'static str,
    registry_version: &'a str,
    registry_compressed_sha256: &'a str,
    proposed_service_name: &'a str,
    matcher: CandidateHostMatcher<'a>,
    aggregate: CandidateAggregate<'a>,
    proof_limit: &'static str,
    non_claims: [&'static str; 7],
    evidence_urls: &'a [String],
    manual_submission_required: bool,
    content_retained: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CandidateProposal<'a> {
    proposal_id: String,
    #[serde(flatten)]
    seed: CandidateProposalSeed<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
struct CandidateHostMatcher<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    value: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CandidateAggregate<'a> {
    observation_count: u32,
    independent_source_count: u8,
    first_observed_at: DateTime<Utc>,
    last_observed_at: DateTime<Utc>,
    observation_kinds: &'a [String],
}

fn activate_release(
    bundle_path: &Path,
    manifest_path: &Path,
    sigstore_path: &Path,
    overlay_paths: &[PathBuf],
    state_dir: &Path,
) -> Result<()> {
    let (bundle, manifest) = load_verified_release(bundle_path, manifest_path, sigstore_path)?;
    let overlays = overlay_paths
        .iter()
        .map(|path| read_overlay(path))
        .collect::<Result<Vec<_>>>()?;
    apply_overlays(&bundle, &overlays).context("validate local overlay compatibility")?;

    ensure_safe_registry_version(&bundle.version)?;
    fs::create_dir_all(state_dir)
        .with_context(|| format!("create registry state directory {}", state_dir.display()))?;
    ensure_directory(state_dir)?;
    let versions = state_dir.join("versions");
    fs::create_dir_all(&versions)
        .with_context(|| format!("create registry state directory {}", versions.display()))?;
    ensure_directory(&versions)?;
    let final_dir = versions.join(&bundle.version);
    if final_dir.exists() {
        ensure_directory(&final_dir)?;
        let (_, stored_manifest) = load_verified_release(
            &final_dir.join("registry.json.zst"),
            &final_dir.join("manifest.json"),
            &final_dir.join("sigstore.json"),
        )
        .context("re-verify retained signed release")?;
        if stored_manifest != manifest {
            bail!("retained registry version differs from the verified input")
        }
    } else {
        let staging = versions.join(format!(".staging-{}-{}", bundle.version, Uuid::now_v7()));
        fs::create_dir(&staging)
            .with_context(|| format!("create registry staging directory {}", staging.display()))?;
        copy_artifact(bundle_path, &staging.join("registry.json.zst"))?;
        copy_artifact(manifest_path, &staging.join("manifest.json"))?;
        copy_artifact(sigstore_path, &staging.join("sigstore.json"))?;
        fs::rename(&staging, &final_dir).with_context(|| {
            format!(
                "atomically activate registry directory {}",
                final_dir.display()
            )
        })?;
        load_verified_release(
            &final_dir.join("registry.json.zst"),
            &final_dir.join("manifest.json"),
            &final_dir.join("sigstore.json"),
        )
        .context("re-verify staged signed release")?;
    }
    transition_registry(
        state_dir,
        &manifest,
        &overlays,
        RegistryTransitionKind::Activation,
    )
}

fn rollback_release(version: &str, overlay_paths: &[PathBuf], state_dir: &Path) -> Result<()> {
    ensure_safe_registry_version(version)?;
    ensure_directory(state_dir).context("registry state directory is unavailable")?;
    if read_active_pointer(&state_dir.join("active.json"))?.is_none() {
        bail!("cannot roll back before a signed registry release has been activated")
    }
    let release_dir = state_dir.join("versions").join(version);
    ensure_directory(&release_dir).context("rollback target is not a retained release")?;
    let (bundle, manifest) = load_verified_release(
        &release_dir.join("registry.json.zst"),
        &release_dir.join("manifest.json"),
        &release_dir.join("sigstore.json"),
    )
    .context("re-verify rollback target and pinned signing identity")?;
    if bundle.version != version || manifest.registry_version != version {
        bail!("retained rollback release does not match its version directory")
    }
    let overlays = overlay_paths
        .iter()
        .map(|path| read_overlay(path))
        .collect::<Result<Vec<_>>>()?;
    apply_overlays(&bundle, &overlays).context("validate rollback overlay compatibility")?;
    transition_registry(
        state_dir,
        &manifest,
        &overlays,
        RegistryTransitionKind::Rollback,
    )
}

fn transition_registry(
    state_dir: &Path,
    manifest: &RegistryManifest,
    overlays: &[RegistryOverlay],
    operation: RegistryTransitionKind,
) -> Result<()> {
    fs::create_dir_all(state_dir)
        .with_context(|| format!("create registry state directory {}", state_dir.display()))?;
    ensure_directory(state_dir)?;
    let active_path = state_dir.join("active.json");
    let previous = read_active_pointer(&active_path)?;
    let mut overlay_ids = overlays
        .iter()
        .map(|overlay| overlay.id.clone())
        .collect::<Vec<_>>();
    overlay_ids.sort();
    overlay_ids.dedup();
    if previous.as_ref().is_some_and(|active| {
        active.registry_version == manifest.registry_version
            && active.compressed_sha256 == manifest.compressed_sha256
            && active.overlay_ids == overlay_ids
    }) {
        println!(
            "registry {} is already active with the same overlay set",
            manifest.registry_version
        );
        return Ok(());
    }
    let transitioned_at = Utc::now();
    let transition_id = Uuid::now_v7();
    let pointer = ActiveRegistryPointer {
        schema_version: manifest.schema_version.clone(),
        registry_version: manifest.registry_version.clone(),
        source_sha256: manifest.source_sha256.clone(),
        bundle_sha256: Some(manifest.bundle_sha256.clone()),
        compressed_sha256: manifest.compressed_sha256.clone(),
        release_identity: RELEASE_IDENTITY.to_owned(),
        overlay_ids: overlay_ids.clone(),
        relative_path: format!("versions/{}", manifest.registry_version),
        activated_at: Some(transitioned_at),
        transition_id: Some(transition_id),
        reprocessing_required: true,
        content_retained: false,
    };
    validate_active_pointer(&pointer)?;
    let receipt = RegistryTransitionReceipt {
        schema_version: "1",
        transition_id,
        operation,
        from_version: previous
            .as_ref()
            .map(|value| value.registry_version.clone()),
        from_compressed_sha256: previous
            .as_ref()
            .map(|value| value.compressed_sha256.clone()),
        to_version: manifest.registry_version.clone(),
        to_bundle_sha256: manifest.bundle_sha256.clone(),
        to_compressed_sha256: manifest.compressed_sha256.clone(),
        overlay_ids,
        transitioned_at,
        release_identity: RELEASE_IDENTITY,
        reprocessing_required: true,
        content_retained: false,
    };
    let receipts = state_dir.join("receipts");
    fs::create_dir_all(&receipts)
        .with_context(|| format!("create registry receipt directory {}", receipts.display()))?;
    ensure_directory(&receipts)?;
    let receipt_json = with_newline(serde_json::to_string_pretty(&receipt)?);
    let receipt_path = receipts.join(format!("{transition_id}.json"));
    let prepared_receipt = receipts.join(format!(".prepared-{transition_id}.json"));
    write_new(&prepared_receipt, receipt_json.as_bytes())?;
    let pointer_json = with_newline(serde_json::to_string_pretty(&pointer)?);
    if let Err(error) = write_atomic(&active_path, pointer_json.as_bytes()) {
        let _ = fs::remove_file(&prepared_receipt);
        return Err(error);
    }
    fs::rename(&prepared_receipt, &receipt_path).with_context(|| {
        format!(
            "publish registry transition receipt {}",
            receipt_path.display()
        )
    })?;
    let retained_versions = retained_version_count(&state_dir.join("versions"))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "active",
            "operation": operation,
            "transition_id": transition_id,
            "from_version": receipt.from_version,
            "to_version": receipt.to_version,
            "overlay_count": receipt.overlay_ids.len(),
            "retained_versions": retained_versions,
            "reprocessing_required": true,
            "content_retained": false,
        }))?
    );
    Ok(())
}

fn read_active_pointer(path: &Path) -> Result<Option<ActiveRegistryPointer>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect active pointer {}", path.display()));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 64 * 1024 {
        bail!("active registry pointer must be a bounded regular file")
    }
    let pointer: ActiveRegistryPointer = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("read active pointer {}", path.display()))?,
    )
    .with_context(|| format!("parse active pointer {}", path.display()))?;
    validate_active_pointer(&pointer)?;
    Ok(Some(pointer))
}

fn validate_active_pointer(pointer: &ActiveRegistryPointer) -> Result<()> {
    ensure_safe_registry_version(&pointer.registry_version)?;
    if pointer.release_identity != RELEASE_IDENTITY
        || pointer.relative_path != format!("versions/{}", pointer.registry_version)
        || pointer.content_retained
    {
        bail!("active registry pointer contract is invalid")
    }
    Ok(())
}

fn ensure_safe_registry_version(version: &str) -> Result<()> {
    if version.is_empty()
        || version.len() > 64
        || !version
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !version
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        bail!("registry version is unsafe for local state")
    }
    Ok(())
}

fn ensure_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect registry directory {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("registry state path must be a real directory")
    }
    Ok(())
}

fn retained_version_count(path: &Path) -> Result<usize> {
    Ok(fs::read_dir(path)
        .with_context(|| format!("list retained registry versions {}", path.display()))?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter(|entry| !entry.file_name().to_string_lossy().starts_with('.'))
        .count())
}

fn candidate(command: CandidateCommand) -> Result<()> {
    match command {
        CandidateCommand::Export {
            input,
            output,
            bundle,
            manifest,
            acknowledge_manual_contribution,
        } => export_candidate(
            &input,
            &output,
            &bundle,
            &manifest,
            acknowledge_manual_contribution,
        ),
    }
}

fn export_candidate(
    input_path: &Path,
    output_path: &Path,
    bundle_path: &Path,
    manifest_path: &Path,
    acknowledge_manual_contribution: bool,
) -> Result<()> {
    if !acknowledge_manual_contribution {
        bail!(
            "candidate export requires --acknowledge-manual-contribution; Tally never submits candidates"
        )
    }
    let input_bytes = read_bounded_regular_file(input_path, 64 * 1024, "candidate input")?;
    let mut input: CandidateExportInput = serde_json::from_slice(&input_bytes)
        .with_context(|| format!("parse candidate input {}", input_path.display()))?;
    let host = validate_candidate_input(&mut input)?;
    let manifest = read_manifest(manifest_path)?;
    let bundle = load_verified_with_manifest(bundle_path, &manifest)?;
    if !bundle.match_host(host.as_str())?.is_empty() {
        bail!(
            "candidate host already matches the verified registry; export is only for unknown hosts"
        )
    }

    let seed = CandidateProposalSeed {
        schema_version: "1",
        registry_version: &manifest.registry_version,
        registry_compressed_sha256: &manifest.compressed_sha256,
        proposed_service_name: &input.proposed_service_name,
        matcher: CandidateHostMatcher {
            kind: "host_exact",
            value: host.as_str(),
        },
        aggregate: CandidateAggregate {
            observation_count: input.observation_count,
            independent_source_count: input.independent_source_count,
            first_observed_at: input.first_observed_at,
            last_observed_at: input.last_observed_at,
            observation_kinds: &input.observation_kinds,
        },
        proof_limit: "service_contact_only",
        non_claims: [
            "service_ownership",
            "product_use",
            "authorization",
            "identity",
            "prompt_or_response_content",
            "model_invocation",
            "data_transfer",
        ],
        evidence_urls: &input.evidence_urls,
        manual_submission_required: true,
        content_retained: false,
    };
    let seed_json = serde_json::to_vec(&seed)?;
    let proposal_id = format!(
        "tally-candidate-{}",
        &hex::encode(Sha256::digest(&seed_json))[..24]
    );
    let proposal = CandidateProposal { proposal_id, seed };
    let output_json = with_newline(serde_json::to_string_pretty(&proposal)?);
    write_new(output_path, output_json.as_bytes())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "exported",
            "proposal_id": proposal.proposal_id,
            "registry_version": manifest.registry_version,
            "observation_count": input.observation_count,
            "independent_source_count": input.independent_source_count,
            "manual_submission_required": true,
            "content_retained": false,
        }))?
    );
    Ok(())
}

fn validate_candidate_input(input: &mut CandidateExportInput) -> Result<Hostname> {
    if input.schema_version != "1" {
        bail!("candidate input schema_version must be 1")
    }
    if !input.public_service_endpoint {
        bail!("candidate host must be acknowledged as a public service endpoint")
    }
    input.proposed_service_name = input.proposed_service_name.trim().to_owned();
    if input.proposed_service_name.is_empty()
        || input.proposed_service_name.len() > 120
        || input.proposed_service_name.chars().any(char::is_control)
    {
        bail!("proposed_service_name must be 1..120 non-control characters")
    }
    let host = Hostname::parse(&input.host).context("candidate host is not a valid hostname")?;
    validate_public_candidate_host(host.as_str())?;
    if !(1..=1_000_000).contains(&input.observation_count) {
        bail!("observation_count must be between 1 and 1000000")
    }
    if !(1..=32).contains(&input.independent_source_count)
        || u32::from(input.independent_source_count) > input.observation_count
    {
        bail!("independent_source_count must be between 1 and 32 and not exceed observation_count")
    }
    if input.first_observed_at > input.last_observed_at {
        bail!("candidate observation window is reversed")
    }
    let window = input.last_observed_at - input.first_observed_at;
    if window > chrono::Duration::days(365) {
        bail!("candidate observation window must not exceed 365 days")
    }
    if !(1..=8).contains(&input.observation_kinds.len()) {
        bail!("observation_kinds must contain between 1 and 8 values")
    }
    input.observation_kinds.sort();
    input.observation_kinds.dedup();
    let allowed_kinds = [
        "cloud_resource",
        "cloud_usage",
        "dns_query",
        "http_metadata",
        "kubernetes_resource",
        "network_flow",
        "network_mapping",
        "registry_pull",
        "saas_capability",
        "scan_fingerprint",
    ];
    if input
        .observation_kinds
        .iter()
        .any(|kind| allowed_kinds.binary_search(&kind.as_str()).is_err())
    {
        bail!("candidate input contains an unsupported observation kind")
    }
    if !(1..=8).contains(&input.evidence_urls.len()) {
        bail!("evidence_urls must contain between 1 and 8 values")
    }
    for value in &input.evidence_urls {
        validate_public_evidence_url(value)?;
    }
    input.evidence_urls.sort();
    input.evidence_urls.dedup();
    Ok(host)
}

fn validate_public_candidate_host(host: &str) -> Result<()> {
    const PRIVATE_SUFFIXES: [&str; 9] = [
        ".home",
        ".internal",
        ".invalid",
        ".lan",
        ".local",
        ".localhost",
        ".test",
        ".example",
        ".onion",
    ];
    if host.parse::<IpAddr>().is_ok() || !host.contains('.') {
        bail!("candidate host must be a public multi-label DNS hostname, not an IP or local name")
    }
    if PRIVATE_SUFFIXES.iter().any(|suffix| host.ends_with(suffix)) {
        bail!("candidate host uses a private, reserved, or non-public suffix")
    }
    Ok(())
}

fn validate_public_evidence_url(value: &str) -> Result<()> {
    if value.len() > 2048 || value.chars().any(char::is_control) {
        bail!("evidence URL is too long or contains control characters")
    }
    let url = Url::parse(value).context("evidence URL is invalid")?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("evidence URLs must be HTTPS and contain no credentials, query, or fragment")
    }
    let host = url.host_str().context("evidence URL has no host")?;
    let normalized = Hostname::parse(host).context("evidence URL host is invalid")?;
    validate_public_candidate_host(normalized.as_str())
}

fn read_bounded_regular_file(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{label} must be a regular file, not a symlink")
    }
    if metadata.len() > limit {
        bail!("{label} exceeds the {limit}-byte limit")
    }
    fs::read(path).with_context(|| format!("read {label}"))
}

fn copy_artifact(source: &Path, destination: &Path) -> Result<()> {
    let bytes = read_bounded_regular_file(source, 128 * 1024 * 1024, "release artifact")?;
    write_new(destination, &bytes)
        .with_context(|| format!("stage artifact {}", destination.display()))?;
    Ok(())
}

fn read_overlay(path: &Path) -> Result<RegistryOverlay> {
    let contents = String::from_utf8(read_bounded_regular_file(
        path,
        4 * 1024 * 1024,
        "registry overlay",
    )?)
    .context("registry overlay is not UTF-8")?;
    serde_saphyr::from_str(&contents)
        .with_context(|| format!("parse registry overlay {}", path.display()))
}

fn schemas(root: &Path, check: bool) -> Result<()> {
    let specs = root.join("specs");
    let openapi = with_newline(serde_json::to_string_pretty(&tally_api::openapi())?);
    let observation = with_newline(serde_json::to_string_pretty(&schemars::schema_for!(
        Observation
    ))?);
    let registry = with_newline(serde_json::to_string_pretty(&schemars::schema_for!(
        RegistryBundle
    ))?);
    let overlay = with_newline(serde_json::to_string_pretty(&schemars::schema_for!(
        RegistryOverlay
    ))?);
    let integration_bundle = with_newline(serde_json::to_string_pretty(&schemars::schema_for!(
        IntegrationContractBundle
    ))?);
    let inventory_contribution = with_newline(serde_json::to_string_pretty(
        &schemars::schema_for!(InventoryContribution),
    )?);
    let connector_contribution = with_newline(serde_json::to_string_pretty(
        &schemars::schema_for!(ConnectorContribution),
    )?);
    let finding_contribution = with_newline(serde_json::to_string_pretty(&schemars::schema_for!(
        FindingContribution
    ))?);
    let evidence_link_contribution = with_newline(serde_json::to_string_pretty(
        &schemars::schema_for!(EvidenceLinkContribution),
    )?);
    let report_section_contribution = with_newline(serde_json::to_string_pretty(
        &schemars::schema_for!(ReportSectionContribution),
    )?);
    let signed_host_request_context = with_newline(serde_json::to_string_pretty(
        &schemars::schema_for!(SignedHostRequestContext),
    )?);
    write_or_check(&specs.join("openapi.json"), &openapi, check)?;
    write_or_check(&specs.join("observation.schema.json"), &observation, check)?;
    write_or_check(&specs.join("registry.schema.json"), &registry, check)?;
    write_or_check(&specs.join("registry-overlay.schema.json"), &overlay, check)?;
    write_or_check(
        &specs.join("integration-contracts.schema.json"),
        &integration_bundle,
        check,
    )?;
    write_or_check(
        &specs.join("inventory-contribution.schema.json"),
        &inventory_contribution,
        check,
    )?;
    write_or_check(
        &specs.join("connector-contribution.schema.json"),
        &connector_contribution,
        check,
    )?;
    write_or_check(
        &specs.join("finding-contribution.schema.json"),
        &finding_contribution,
        check,
    )?;
    write_or_check(
        &specs.join("evidence-link-contribution.schema.json"),
        &evidence_link_contribution,
        check,
    )?;
    write_or_check(
        &specs.join("report-section-contribution.schema.json"),
        &report_section_contribution,
        check,
    )?;
    write_or_check(
        &specs.join("signed-host-request-context.schema.json"),
        &signed_host_request_context,
        check,
    )?;
    println!(
        "schema artifacts are {}",
        if check { "current" } else { "generated" }
    );
    Ok(())
}

fn lint(source: &Path) -> Result<()> {
    let source = read_source(source)?;
    let compiled = source.compile("registry.json.zst")?;
    println!(
        "registry {} is valid: {} entries, {} matchers, {} fingerprints",
        compiled.bundle.version,
        compiled.manifest.entry_count,
        compiled.manifest.matcher_count,
        compiled.manifest.fingerprint_count
    );
    Ok(())
}

fn build(source: &Path, output: &Path) -> Result<()> {
    let source = read_source(source)?;
    let bundle_name = format!("tally-registry-{}.json.zst", source.version);
    let manifest_name = format!("tally-registry-{}.manifest.json", source.version);
    let compiled = source.compile(&bundle_name)?;
    fs::create_dir_all(output)
        .with_context(|| format!("create output directory {}", output.display()))?;
    write_atomic(&output.join(&bundle_name), &compiled.compressed)?;
    let manifest = with_newline(serde_json::to_string_pretty(&compiled.manifest)?);
    write_atomic(&output.join(&manifest_name), manifest.as_bytes())?;
    println!(
        "built {} and {} ({} entries, {} matchers, {} fingerprints)",
        bundle_name,
        manifest_name,
        compiled.manifest.entry_count,
        compiled.manifest.matcher_count,
        compiled.manifest.fingerprint_count
    );
    Ok(())
}

fn inspect(bundle_path: &Path, manifest_path: &Path) -> Result<()> {
    let manifest = read_manifest(manifest_path)?;
    let bundle = load_verified_with_manifest(bundle_path, &manifest)?;
    println!("version: {}", bundle.version);
    println!("schema: {}", bundle.schema_version);
    println!("source sha256: {}", bundle.source_sha256);
    println!("entries: {}", manifest.entry_count);
    println!("matchers: {}", manifest.matcher_count);
    println!("fingerprints: {}", manifest.fingerprint_count);
    println!("bundle sha256: {}", manifest.bundle_sha256);
    println!("compressed sha256: {}", manifest.compressed_sha256);
    Ok(())
}

fn match_host(bundle_path: &Path, manifest_path: &Path, host: &str) -> Result<()> {
    let bundle = load_verified(bundle_path, manifest_path)?;
    let hits = bundle.match_host(host)?;
    if hits.is_empty() {
        println!("unknown host: {host}");
    } else {
        for hit in hits {
            println!(
                "{} via {} ({} bps, {:?})",
                hit.entry_id, hit.matcher_id, hit.confidence_bps, hit.proof
            );
        }
    }
    Ok(())
}

fn read_source(path: &Path) -> Result<RegistrySource> {
    let paths = source_paths(path)?;
    if paths.is_empty() {
        bail!("no .yaml or .yml source files found at {}", path.display());
    }

    let mut schema_version = None;
    let mut version = None;
    let mut fingerprints = Vec::new();
    let mut entries = Vec::new();
    for source_path in paths {
        let contents = fs::read_to_string(&source_path)
            .with_context(|| format!("read registry source {}", source_path.display()))?;
        let document: RegistrySourceDocument = serde_saphyr::from_str(&contents)
            .with_context(|| format!("parse registry source {}", source_path.display()))?;
        merge_metadata(
            &mut schema_version,
            document.schema_version,
            "schema_version",
            &source_path,
        )?;
        merge_metadata(&mut version, document.version, "version", &source_path)?;
        fingerprints.extend(document.fingerprints);
        entries.extend(document.entries);
    }

    Ok(RegistrySource {
        schema_version: schema_version.context("registry source is missing schema_version")?,
        version: version.context("registry source is missing version")?,
        fingerprints,
        entries,
    })
}

fn source_paths(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_owned()]);
    }
    let mut paths = fs::read_dir(path)
        .with_context(|| format!("read registry source directory {}", path.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.retain(|path| {
        path.extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|extension| matches!(extension, "yaml" | "yml"))
    });
    paths.sort();
    Ok(paths)
}

fn merge_metadata(
    destination: &mut Option<String>,
    value: Option<String>,
    field: &str,
    path: &Path,
) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    if let Some(existing) = destination {
        if existing != &value {
            bail!(
                "conflicting {field} in {}: expected {existing}, found {value}",
                path.display()
            );
        }
    } else {
        *destination = Some(value);
    }
    Ok(())
}

fn load_verified(bundle_path: &Path, manifest_path: &Path) -> Result<RegistryBundle> {
    let manifest = read_manifest(manifest_path)?;
    load_verified_with_manifest(bundle_path, &manifest)
}

fn load_verified_with_manifest(
    bundle_path: &Path,
    manifest: &RegistryManifest,
) -> Result<RegistryBundle> {
    let compressed =
        read_bounded_regular_file(bundle_path, 128 * 1024 * 1024, "compressed registry bundle")?;
    verify_artifact(&compressed, manifest).context("verify registry artifact")
}

fn read_manifest(path: &Path) -> Result<RegistryManifest> {
    let bytes = read_bounded_regular_file(path, 1024 * 1024, "registry manifest")?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse manifest {}", path.display()))
}

fn write_or_check(path: &Path, expected: &str, check: bool) -> Result<()> {
    if check {
        let actual = fs::read_to_string(path)
            .with_context(|| format!("read checked schema {}", path.display()))?;
        if actual != expected {
            bail!("{} is stale; run make schemas", path.display());
        }
    } else {
        let parent = path.parent().context("schema path has no parent")?;
        fs::create_dir_all(parent)
            .with_context(|| format!("create schema directory {}", parent.display()))?;
        write_atomic(path, expected.as_bytes())?;
    }
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("output path has no parent")?;
    let file_name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .context("output file name is not UTF-8")?;
    let temporary = parent.join(format!(".{file_name}.tmp-{}", Uuid::now_v7()));
    write_new(&temporary, bytes)
        .with_context(|| format!("write temporary artifact {}", temporary.display()))?;
    fs::rename(&temporary, path)
        .with_context(|| format!("activate artifact {}", path.display()))?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create new file {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write file {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync file {}", path.display()))?;
    Ok(())
}

fn with_newline(mut value: String) -> String {
    value.push('\n');
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checked_release(version: &str) -> (PathBuf, PathBuf) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../registry-data/dist");
        (
            root.join(format!("tally-registry-{version}.json.zst")),
            root.join(format!("tally-registry-{version}.manifest.json")),
        )
    }

    fn candidate_input(host: &str) -> serde_json::Value {
        serde_json::json!({
            "schema_version": "1",
            "host": host,
            "proposed_service_name": "Unlisted AI service",
            "observation_count": 18,
            "independent_source_count": 2,
            "first_observed_at": "2026-08-01T00:00:00Z",
            "last_observed_at": "2026-08-02T00:00:00Z",
            "observation_kinds": ["network_flow", "dns_query"],
            "evidence_urls": ["https://www.rfc-editor.org/rfc/rfc9110"],
            "public_service_endpoint": true
        })
    }

    fn manifest(version: &str, digest: &str) -> RegistryManifest {
        RegistryManifest {
            schema_version: "1".to_owned(),
            registry_version: version.to_owned(),
            source_sha256: format!("{digest:0<64}"),
            bundle_file: format!("tally-registry-{version}.json.zst"),
            bundle_sha256: format!("bundle-{digest}"),
            compressed_sha256: format!("compressed-{digest}"),
            entry_count: 1,
            matcher_count: 1,
            fingerprint_count: 0,
            compiler_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    #[test]
    fn conflicting_source_metadata_is_rejected() {
        let mut destination = Some("1".to_owned());
        let error = merge_metadata(
            &mut destination,
            Some("2".to_owned()),
            "schema_version",
            Path::new("second.yaml"),
        )
        .expect_err("must reject conflict");
        assert!(error.to_string().contains("conflicting schema_version"));
    }

    #[test]
    fn malformed_sigstore_bundle_is_rejected_before_trust_evaluation() {
        let error = verify_sigstore_bytes(b"registry", "not-json")
            .expect_err("malformed bundle must be rejected");
        assert!(error.to_string().contains("parse Sigstore bundle"));
    }

    #[test]
    fn release_identity_is_pinned_to_the_main_release_workflow() {
        assert_eq!(
            RELEASE_IDENTITY,
            "https://github.com/godellabs-ai/godel-tally/.github/workflows/release-registry.yml@refs/heads/main"
        );
        assert_eq!(
            GITHUB_ACTIONS_ISSUER,
            "https://token.actions.githubusercontent.com"
        );
    }

    #[test]
    fn corrupted_checked_artifact_is_rejected() {
        let (bundle_path, manifest_path) = checked_release("2026.10.1");
        let mut compressed = fs::read(bundle_path).expect("checked bundle");
        let midpoint = compressed.len() / 2;
        compressed[midpoint] ^= 0x01;
        let manifest = read_manifest(&manifest_path).expect("checked manifest");
        let error = verify_artifact(&compressed, &manifest).expect_err("corruption must fail");
        assert!(error.to_string().contains("compressed SHA-256 digest"));
    }

    #[test]
    fn candidate_export_is_deterministic_bounded_and_content_free() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let input_path = temporary.path().join("input.json");
        let first_output = temporary.path().join("first.json");
        let second_output = temporary.path().join("second.json");
        fs::write(
            &input_path,
            serde_json::to_vec(&candidate_input("candidate.godel-tally.org"))
                .expect("candidate JSON"),
        )
        .expect("candidate fixture");
        let (bundle, manifest) = checked_release("2026.10.1");

        export_candidate(&input_path, &first_output, &bundle, &manifest, true)
            .expect("first export");
        export_candidate(&input_path, &second_output, &bundle, &manifest, true)
            .expect("second export");
        let first = fs::read_to_string(&first_output).expect("first proposal");
        let second = fs::read_to_string(&second_output).expect("second proposal");
        assert_eq!(first, second);

        let proposal: serde_json::Value = serde_json::from_str(&first).expect("proposal JSON");
        assert_eq!(proposal["matcher"]["type"], "host_exact");
        assert_eq!(proposal["proof_limit"], "service_contact_only");
        assert_eq!(proposal["manual_submission_required"], true);
        assert_eq!(proposal["content_retained"], false);
        assert_eq!(proposal["aggregate"]["observation_count"], 18);
        for prohibited in [
            "actor",
            "device",
            "source_ip",
            "identity",
            "cursor",
            "prompt",
            "response",
            "request_path",
            "query_string",
        ] {
            assert!(
                !proposal
                    .as_object()
                    .expect("object")
                    .contains_key(prohibited)
            );
        }
    }

    #[test]
    fn candidate_export_rejects_known_or_private_hosts_and_requires_acknowledgement() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let input_path = temporary.path().join("input.json");
        let output_path = temporary.path().join("proposal.json");
        let (bundle, manifest) = checked_release("2026.10.1");

        fs::write(
            &input_path,
            serde_json::to_vec(&candidate_input("api.openai.com")).expect("candidate JSON"),
        )
        .expect("known fixture");
        let error = export_candidate(&input_path, &output_path, &bundle, &manifest, true)
            .expect_err("known host must fail");
        assert!(error.to_string().contains("already matches"));
        assert!(!output_path.exists());

        fs::write(
            &input_path,
            serde_json::to_vec(&candidate_input("runtime.internal")).expect("candidate JSON"),
        )
        .expect("private fixture");
        let error = export_candidate(&input_path, &output_path, &bundle, &manifest, true)
            .expect_err("private host must fail");
        assert!(
            error
                .to_string()
                .contains("private, reserved, or non-public")
        );
        assert!(!output_path.exists());

        let error = export_candidate(&input_path, &output_path, &bundle, &manifest, false)
            .expect_err("acknowledgement is mandatory");
        assert!(error.to_string().contains("never submits candidates"));
    }

    #[test]
    fn registry_transitions_keep_versions_and_write_content_free_receipts() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let state = temporary.path();
        let versions = state.join("versions");
        fs::create_dir_all(versions.join("fixture-a")).expect("first retained release");
        fs::create_dir_all(versions.join("fixture-b")).expect("second retained release");
        let first = manifest("fixture-a", "one");
        let second = manifest("fixture-b", "two");

        transition_registry(state, &second, &[], RegistryTransitionKind::Activation)
            .expect("activation transition");
        transition_registry(state, &first, &[], RegistryTransitionKind::Rollback)
            .expect("rollback transition");
        transition_registry(state, &first, &[], RegistryTransitionKind::Rollback)
            .expect("identical rollback is a no-op");

        assert!(versions.join("fixture-a").is_dir());
        assert!(versions.join("fixture-b").is_dir());
        assert_eq!(retained_version_count(&versions).expect("version count"), 2);
        let active = read_active_pointer(&state.join("active.json"))
            .expect("active pointer")
            .expect("active release");
        assert_eq!(active.registry_version, "fixture-a");
        assert!(active.reprocessing_required);
        assert!(!active.content_retained);
        let receipts = fs::read_dir(state.join("receipts"))
            .expect("receipts")
            .count();
        assert_eq!(receipts, 2);
        for entry in fs::read_dir(state.join("receipts")).expect("receipts") {
            let receipt =
                fs::read_to_string(entry.expect("receipt entry").path()).expect("receipt JSON");
            assert!(receipt.contains("\"content_retained\": false"));
            assert!(!receipt.contains("observation"));
            assert!(!receipt.contains("hostname"));
        }
    }

    #[test]
    fn unsafe_registry_versions_and_active_paths_are_rejected() {
        for version in ["", "../outside", "nested/version", "."] {
            assert!(ensure_safe_registry_version(version).is_err());
        }
        let pointer = ActiveRegistryPointer {
            schema_version: "1".to_owned(),
            registry_version: "fixture-b".to_owned(),
            source_sha256: "0".repeat(64),
            bundle_sha256: Some("bundle".to_owned()),
            compressed_sha256: "compressed".to_owned(),
            release_identity: RELEASE_IDENTITY.to_owned(),
            overlay_ids: vec![],
            relative_path: "../outside".to_owned(),
            activated_at: None,
            transition_id: None,
            reprocessing_required: true,
            content_retained: false,
        };
        assert!(validate_active_pointer(&pointer).is_err());
    }
}
