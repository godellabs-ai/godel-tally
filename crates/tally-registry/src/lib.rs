//! Versioned registry source, compiled-bundle, overlay, and matching contracts.

use std::collections::{BTreeMap, BTreeSet};

use chrono::NaiveDate;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const REGISTRY_SCHEMA_VERSION: &str = "1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistrySource {
    pub schema_version: String,
    pub version: String,
    #[serde(default)]
    pub fingerprints: Vec<HttpFingerprint>,
    pub entries: Vec<RegistryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistrySourceDocument {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default)]
    pub fingerprints: Vec<HttpFingerprint>,
    #[serde(default)]
    pub entries: Vec<RegistryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistryBundle {
    pub schema_version: String,
    pub version: String,
    /// SHA-256 of the canonical JSON representation of the registry source.
    pub source_sha256: String,
    #[serde(default)]
    pub fingerprints: Vec<HttpFingerprint>,
    pub entries: Vec<RegistryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HttpFingerprint {
    pub id: String,
    pub ports: Vec<u16>,
    pub method: SafeHttpMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<SafeProbeRequest>,
    pub path: String,
    pub accepted_content_types: Vec<String>,
    pub max_response_bytes: u32,
    pub timeout_millis: u64,
    pub assertions: Vec<FingerprintAssertion>,
    pub verified_at: NaiveDate,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SafeHttpMethod {
    Get,
    Head,
    Options,
    Post,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SafeProbeRequest {
    McpServerDiscover20260728,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FingerprintAssertion {
    JsonStringPresent { field: String, fact: String },
    JsonStringEquals { field: String, value: String },
    JsonArrayPresent { field: String, count_fact: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistryEntry {
    pub id: String,
    pub kind: RegistryEntryKind,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_ref: Option<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub surfaces: Vec<String>,
    #[serde(default)]
    pub facts: BTreeMap<String, RegistryFact>,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    pub status: RegistryEntryStatus,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RegistryEntryKind {
    Provider,
    Service,
    Product,
    ModelFamily,
    ModelHub,
    Runtime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RegistryEntryStatus {
    Active,
    Deprecated,
    Experimental,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistryFact {
    pub value: serde_json::Value,
    pub confidence_bps: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applies_when: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recheck_after: Option<NaiveDate>,
    pub sources: Vec<Evidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub source_type: EvidenceType,
    pub url: String,
    pub verified_at: NaiveDate,
    pub reviewer: String,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    VendorDocumentation,
    VendorApplication,
    StandardsBody,
    ProjectResearch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Matcher {
    pub id: String,
    #[serde(flatten)]
    pub rule: MatcherRule,
    pub produces: MatchProduces,
    pub confidence_bps: u16,
    pub verified_at: NaiveDate,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MatcherRule {
    HostExact { value: String },
    HostSuffix { value: String },
    ModelPattern { value: String },
    VendorAppId { vendor: String, value: String },
    ScannerFingerprint { fingerprint_ref: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MatchProduces {
    pub entity_ref: String,
    pub proof: ProofKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProofKind {
    ServiceContact,
    ProductUse,
    ModelReference,
    RuntimeReachable,
    ArtifactProvisioning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistryManifest {
    pub schema_version: String,
    pub registry_version: String,
    /// SHA-256 of the canonical JSON representation of the registry source.
    pub source_sha256: String,
    pub bundle_file: String,
    pub bundle_sha256: String,
    pub compressed_sha256: String,
    pub entry_count: usize,
    pub matcher_count: usize,
    pub fingerprint_count: usize,
    pub compiler_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledRegistry {
    pub bundle: RegistryBundle,
    pub json: Vec<u8>,
    pub compressed: Vec<u8>,
    pub manifest: RegistryManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistryOverlay {
    pub schema_version: String,
    pub id: String,
    /// Installation-local entries appended to the signed base without modifying its bytes.
    #[serde(default)]
    pub additions: Vec<RegistryEntry>,
    #[serde(default)]
    pub entries: Vec<RegistryEntryOverride>,
    #[serde(default)]
    pub disabled_matchers: Vec<MatcherRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistryEntryOverride {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub categories: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surfaces: Option<Vec<String>>,
    #[serde(default)]
    pub facts: BTreeMap<String, RegistryFact>,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MatcherRef {
    pub entry_id: String,
    pub matcher_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MatchHit {
    pub entry_id: String,
    pub matcher_id: String,
    pub confidence_bps: u16,
    pub proof: ProofKind,
}

impl RegistrySource {
    /// Builds a canonical, deterministic registry artifact.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] when source invariants fail or compression fails.
    pub fn compile(
        mut self,
        bundle_file: impl Into<String>,
    ) -> Result<CompiledRegistry, RegistryError> {
        canonicalize_entries(&mut self.entries);
        canonicalize_fingerprints(&mut self.fingerprints);
        let source_sha256 = sha256_hex(&serde_json::to_vec(&self)?);
        let bundle_file = bundle_file.into();
        let bundle = RegistryBundle {
            schema_version: self.schema_version,
            version: self.version,
            source_sha256: source_sha256.clone(),
            fingerprints: self.fingerprints,
            entries: self.entries,
        };
        bundle.validate()?;

        let json = serde_json::to_vec(&bundle)?;
        let compressed = zstd::stream::encode_all(json.as_slice(), 19)
            .map_err(|error| RegistryError::Compression(error.to_string()))?;
        let matcher_count = bundle
            .entries
            .iter()
            .map(|entry| entry.matchers.len())
            .sum();
        let manifest = RegistryManifest {
            schema_version: bundle.schema_version.clone(),
            registry_version: bundle.version.clone(),
            source_sha256,
            bundle_file,
            bundle_sha256: sha256_hex(&json),
            compressed_sha256: sha256_hex(&compressed),
            entry_count: bundle.entries.len(),
            matcher_count,
            fingerprint_count: bundle.fingerprints.len(),
            compiler_version: env!("CARGO_PKG_VERSION").to_owned(),
        };

        Ok(CompiledRegistry {
            bundle,
            json,
            compressed,
            manifest,
        })
    }
}

impl RegistryBundle {
    /// Checks bundle-level, entry, provenance, and collision invariants.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] for any unsafe or ambiguous registry state.
    pub fn validate(&self) -> Result<(), RegistryError> {
        if self.schema_version != REGISTRY_SCHEMA_VERSION || self.version.trim().is_empty() {
            return Err(RegistryError::MissingVersion);
        }
        if !is_sha256_hex(&self.source_sha256) {
            return Err(RegistryError::InvalidSourceSha256);
        }

        let fingerprint_ids = validate_fingerprints(&self.fingerprints)?;

        let mut ids = BTreeSet::new();
        for entry in &self.entries {
            validate_identifier(&entry.id, "entry")?;
            if !ids.insert(entry.id.clone()) {
                return Err(RegistryError::DuplicateId(entry.id.clone()));
            }
            if entry.name.trim().is_empty() {
                return Err(RegistryError::MissingName(entry.id.clone()));
            }
        }

        let entries_by_id: BTreeMap<_, _> = self
            .entries
            .iter()
            .map(|entry| (entry.id.as_str(), entry))
            .collect();
        let mut matcher_keys = BTreeMap::new();
        let mut host_scopes = Vec::new();
        for entry in &self.entries {
            validate_provider_reference(entry, &entries_by_id)?;

            ensure_unique(&entry.categories, &entry.id, "category")?;
            ensure_unique(&entry.surfaces, &entry.id, "surface")?;
            for (name, fact) in &entry.facts {
                validate_identifier(name, "fact")?;
                validate_confidence(fact.confidence_bps, &format!("{}.facts.{name}", entry.id))?;
                validate_evidence(&fact.sources, &format!("{}.facts.{name}", entry.id))?;
            }

            let mut matcher_ids = BTreeSet::new();
            for matcher in &entry.matchers {
                validate_identifier(&matcher.id, "matcher")?;
                if !matcher_ids.insert(matcher.id.clone()) {
                    return Err(RegistryError::DuplicateMatcherId {
                        entry: entry.id.clone(),
                        matcher: matcher.id.clone(),
                    });
                }
                validate_confidence(
                    matcher.confidence_bps,
                    &format!("{}.matchers.{}", entry.id, matcher.id),
                )?;
                validate_evidence(
                    &matcher.evidence,
                    &format!("{}.matchers.{}", entry.id, matcher.id),
                )?;
                if matcher
                    .evidence
                    .iter()
                    .all(|source| source.verified_at != matcher.verified_at)
                {
                    return Err(RegistryError::UnlinkedVerificationDate {
                        entry: entry.id.clone(),
                        matcher: matcher.id.clone(),
                    });
                }
                if !entries_by_id.contains_key(matcher.produces.entity_ref.as_str()) {
                    return Err(RegistryError::UnknownReference {
                        owner: format!("{}.matchers.{}", entry.id, matcher.id),
                        target: matcher.produces.entity_ref.clone(),
                    });
                }
                let key = matcher.rule.collision_key()?;
                if let Some(scope) = host_scope_for_rule(&matcher.rule)? {
                    host_scopes.push((entry.id.clone(), scope));
                }
                if let MatcherRule::ScannerFingerprint { fingerprint_ref } = &matcher.rule
                    && !fingerprint_ids.contains(fingerprint_ref.as_str())
                {
                    return Err(RegistryError::UnknownFingerprintReference {
                        owner: format!("{}.matchers.{}", entry.id, matcher.id),
                        target: fingerprint_ref.clone(),
                    });
                }
                if let Some(previous) = matcher_keys.insert(key.clone(), entry.id.as_str()) {
                    return Err(RegistryError::MatcherCollision {
                        key,
                        first: previous.to_owned(),
                        second: entry.id.clone(),
                    });
                }
            }
        }
        validate_host_scope_ownership(&host_scopes)?;
        Ok(())
    }

    /// Returns deterministic host matches in strongest-first order.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] when the input is not a valid normalized DNS host.
    pub fn match_host(&self, host: &str) -> Result<Vec<MatchHit>, RegistryError> {
        let host = normalize_host(host)?;
        let mut hits = Vec::new();
        for entry in &self.entries {
            for matcher in &entry.matchers {
                let matches = match &matcher.rule {
                    MatcherRule::HostExact { value } => host == normalize_host(value)?,
                    MatcherRule::HostSuffix { value } => {
                        let suffix = normalize_host(value)?;
                        host == suffix || host.ends_with(&format!(".{suffix}"))
                    }
                    _ => false,
                };
                if matches {
                    hits.push(MatchHit {
                        entry_id: entry.id.clone(),
                        matcher_id: matcher.id.clone(),
                        confidence_bps: matcher.confidence_bps,
                        proof: matcher.produces.proof,
                    });
                }
            }
        }
        hits.sort_by(|left, right| {
            right
                .confidence_bps
                .cmp(&left.confidence_bps)
                .then_with(|| left.entry_id.cmp(&right.entry_id))
                .then_with(|| left.matcher_id.cmp(&right.matcher_id))
        });
        Ok(hits)
    }

    pub fn fingerprint(&self, id: &str) -> Option<&HttpFingerprint> {
        self.fingerprints
            .iter()
            .find(|fingerprint| fingerprint.id == id)
    }

    pub fn match_fingerprint(&self, fingerprint_id: &str) -> Vec<MatchHit> {
        let mut hits = self
            .entries
            .iter()
            .flat_map(|entry| {
                entry
                    .matchers
                    .iter()
                    .filter(|matcher| {
                        matches!(
                            &matcher.rule,
                            MatcherRule::ScannerFingerprint { fingerprint_ref }
                                if fingerprint_ref == fingerprint_id
                        )
                    })
                    .map(|matcher| MatchHit {
                        entry_id: entry.id.clone(),
                        matcher_id: matcher.id.clone(),
                        confidence_bps: matcher.confidence_bps,
                        proof: matcher.produces.proof,
                    })
            })
            .collect::<Vec<_>>();
        hits.sort_by(|left, right| {
            right
                .confidence_bps
                .cmp(&left.confidence_bps)
                .then_with(|| left.entry_id.cmp(&right.entry_id))
                .then_with(|| left.matcher_id.cmp(&right.matcher_id))
        });
        hits
    }
}

impl MatcherRule {
    fn collision_key(&self) -> Result<String, RegistryError> {
        match self {
            Self::HostExact { value } => Ok(format!("host_exact:{}", normalize_host(value)?)),
            Self::HostSuffix { value } => Ok(format!("host_suffix:{}", normalize_host(value)?)),
            Self::ModelPattern { value } => Ok(format!("model_pattern:{value}")),
            Self::VendorAppId { vendor, value } => Ok(format!(
                "vendor_app_id:{}:{value}",
                vendor.trim().to_ascii_lowercase()
            )),
            Self::ScannerFingerprint { fingerprint_ref } => {
                Ok(format!("scanner_fingerprint:{fingerprint_ref}"))
            }
        }
    }
}

#[derive(Debug)]
enum HostScope {
    Exact(String),
    Suffix(String),
}

impl HostScope {
    fn value(&self) -> &str {
        match self {
            Self::Exact(value) | Self::Suffix(value) => value,
        }
    }
}

fn host_scopes_overlap(first: &HostScope, second: &HostScope) -> bool {
    match (first, second) {
        (HostScope::Exact(first), HostScope::Exact(second)) => first == second,
        (HostScope::Exact(exact), HostScope::Suffix(suffix))
        | (HostScope::Suffix(suffix), HostScope::Exact(exact)) => {
            exact == suffix || exact.ends_with(&format!(".{suffix}"))
        }
        (HostScope::Suffix(first), HostScope::Suffix(second)) => {
            first == second
                || first.ends_with(&format!(".{second}"))
                || second.ends_with(&format!(".{first}"))
        }
    }
}

fn host_scope_for_rule(rule: &MatcherRule) -> Result<Option<HostScope>, RegistryError> {
    match rule {
        MatcherRule::HostExact { value } => Ok(Some(HostScope::Exact(normalize_host(value)?))),
        MatcherRule::HostSuffix { value } => Ok(Some(HostScope::Suffix(normalize_host(value)?))),
        _ => Ok(None),
    }
}

fn validate_provider_reference(
    entry: &RegistryEntry,
    entries_by_id: &BTreeMap<&str, &RegistryEntry>,
) -> Result<(), RegistryError> {
    let Some(provider_ref) = &entry.provider_ref else {
        return Ok(());
    };
    let provider = entries_by_id.get(provider_ref.as_str()).ok_or_else(|| {
        RegistryError::UnknownReference {
            owner: entry.id.clone(),
            target: provider_ref.clone(),
        }
    })?;
    if provider.kind != RegistryEntryKind::Provider {
        return Err(RegistryError::InvalidProviderReference {
            owner: entry.id.clone(),
            target: provider_ref.clone(),
        });
    }
    Ok(())
}

fn validate_host_scope_ownership(scopes: &[(String, HostScope)]) -> Result<(), RegistryError> {
    for (index, (first_entry, first_scope)) in scopes.iter().enumerate() {
        for (second_entry, second_scope) in &scopes[index + 1..] {
            if first_entry != second_entry && host_scopes_overlap(first_scope, second_scope) {
                return Err(RegistryError::MatcherCollision {
                    key: format!(
                        "host_overlap:{}:{}",
                        first_scope.value(),
                        second_scope.value()
                    ),
                    first: first_entry.clone(),
                    second: second_entry.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Applies installation overlays without changing the signed base bundle.
///
/// # Errors
///
/// Returns [`RegistryError`] when overlays conflict or reference unknown entries.
pub fn apply_overlays(
    base: &RegistryBundle,
    overlays: &[RegistryOverlay],
) -> Result<RegistryBundle, RegistryError> {
    base.validate()?;
    let mut effective = base.clone();
    let mut assignments = BTreeSet::new();
    let mut disabled = BTreeSet::new();

    for overlay in overlays {
        if overlay.schema_version != REGISTRY_SCHEMA_VERSION || overlay.id.trim().is_empty() {
            return Err(RegistryError::InvalidOverlay(overlay.id.clone()));
        }
        for addition in &overlay.additions {
            claim_overlay_assignment(&mut assignments, &format!("add:{}", addition.id))?;
            if effective
                .entries
                .iter()
                .any(|entry| entry.id == addition.id)
            {
                return Err(RegistryError::DuplicateId(addition.id.clone()));
            }
            effective.entries.push(addition.clone());
        }
        for matcher_ref in &overlay.disabled_matchers {
            let key = format!(
                "disable:{}:{}",
                matcher_ref.entry_id, matcher_ref.matcher_id
            );
            claim_overlay_assignment(&mut assignments, &key)?;
            disabled.insert(matcher_ref.clone());
        }
        for patch in &overlay.entries {
            let entry = effective
                .entries
                .iter_mut()
                .find(|entry| entry.id == patch.id)
                .ok_or_else(|| RegistryError::UnknownReference {
                    owner: format!("overlay.{}", overlay.id),
                    target: patch.id.clone(),
                })?;
            if let Some(name) = &patch.name {
                claim_overlay_assignment(&mut assignments, &format!("{}.name", patch.id))?;
                entry.name.clone_from(name);
            }
            if let Some(categories) = &patch.categories {
                claim_overlay_assignment(&mut assignments, &format!("{}.categories", patch.id))?;
                entry.categories.clone_from(categories);
            }
            if let Some(surfaces) = &patch.surfaces {
                claim_overlay_assignment(&mut assignments, &format!("{}.surfaces", patch.id))?;
                entry.surfaces.clone_from(surfaces);
            }
            for (name, fact) in &patch.facts {
                claim_overlay_assignment(&mut assignments, &format!("{}.facts.{name}", patch.id))?;
                entry.facts.insert(name.clone(), fact.clone());
            }
            for matcher in &patch.matchers {
                claim_overlay_assignment(
                    &mut assignments,
                    &format!("{}.matchers.{}", patch.id, matcher.id),
                )?;
                if let Some(existing) = entry
                    .matchers
                    .iter_mut()
                    .find(|existing| existing.id == matcher.id)
                {
                    existing.clone_from(matcher);
                } else {
                    entry.matchers.push(matcher.clone());
                }
            }
        }
    }

    for entry in &mut effective.entries {
        entry.matchers.retain(|matcher| {
            !disabled.contains(&MatcherRef {
                entry_id: entry.id.clone(),
                matcher_id: matcher.id.clone(),
            })
        });
    }
    canonicalize_entries(&mut effective.entries);
    effective.validate()?;
    Ok(effective)
}

/// Verifies artifact digests and manifest-to-bundle consistency before loading.
///
/// Signature verification is a separate release-identity gate; this function validates the
/// deterministic artifact itself and is also used after signature verification.
///
/// # Errors
///
/// Returns [`RegistryError`] when bytes are corrupt or disagree with the manifest.
pub fn verify_artifact(
    compressed: &[u8],
    manifest: &RegistryManifest,
) -> Result<RegistryBundle, RegistryError> {
    if sha256_hex(compressed) != manifest.compressed_sha256 {
        return Err(RegistryError::ManifestMismatch(
            "compressed SHA-256 digest".to_owned(),
        ));
    }
    let json = zstd::stream::decode_all(compressed)
        .map_err(|error| RegistryError::Compression(error.to_string()))?;
    if sha256_hex(&json) != manifest.bundle_sha256 {
        return Err(RegistryError::ManifestMismatch(
            "bundle SHA-256 digest".to_owned(),
        ));
    }
    let bundle: RegistryBundle = serde_json::from_slice(&json)?;
    bundle.validate()?;
    let matcher_count: usize = bundle
        .entries
        .iter()
        .map(|entry| entry.matchers.len())
        .sum();
    if bundle.schema_version != manifest.schema_version
        || bundle.version != manifest.registry_version
        || bundle.source_sha256 != manifest.source_sha256
        || bundle.entries.len() != manifest.entry_count
        || matcher_count != manifest.matcher_count
        || bundle.fingerprints.len() != manifest.fingerprint_count
    {
        return Err(RegistryError::ManifestMismatch(
            "bundle metadata or counts".to_owned(),
        ));
    }
    Ok(bundle)
}

fn claim_overlay_assignment(
    assignments: &mut BTreeSet<String>,
    key: &str,
) -> Result<(), RegistryError> {
    if assignments.insert(key.to_owned()) {
        Ok(())
    } else {
        Err(RegistryError::OverlayConflict(key.to_owned()))
    }
}

fn canonicalize_entries(entries: &mut [RegistryEntry]) {
    for entry in entries.iter_mut() {
        entry.categories.sort();
        entry.categories.dedup();
        entry.surfaces.sort();
        entry.surfaces.dedup();
        for fact in entry.facts.values_mut() {
            fact.sources.sort();
            fact.sources.dedup();
        }
        for matcher in &mut entry.matchers {
            matcher.evidence.sort();
            matcher.evidence.dedup();
        }
        entry.matchers.sort_by(|left, right| left.id.cmp(&right.id));
    }
    entries.sort_by(|left, right| left.id.cmp(&right.id));
}

fn canonicalize_fingerprints(fingerprints: &mut [HttpFingerprint]) {
    for fingerprint in fingerprints.iter_mut() {
        fingerprint.ports.sort_unstable();
        fingerprint.ports.dedup();
        fingerprint.accepted_content_types.sort();
        fingerprint.accepted_content_types.dedup();
        fingerprint
            .assertions
            .sort_by_key(fingerprint_assertion_key);
        fingerprint.evidence.sort();
        fingerprint.evidence.dedup();
    }
    fingerprints.sort_by(|left, right| left.id.cmp(&right.id));
}

fn fingerprint_assertion_key(assertion: &FingerprintAssertion) -> String {
    match assertion {
        FingerprintAssertion::JsonStringPresent { field, fact } => {
            format!("json_string_present:{field}:{fact}")
        }
        FingerprintAssertion::JsonStringEquals { field, value } => {
            format!("json_string_equals:{field}:{value}")
        }
        FingerprintAssertion::JsonArrayPresent { field, count_fact } => {
            format!("json_array_present:{field}:{count_fact}")
        }
    }
}

fn validate_fingerprint(fingerprint: &HttpFingerprint) -> Result<(), RegistryError> {
    validate_identifier(&fingerprint.id, "fingerprint")?;
    if fingerprint.ports.is_empty()
        || fingerprint.ports.contains(&0)
        || !strictly_sorted(&fingerprint.ports)
    {
        return Err(RegistryError::InvalidFingerprint {
            fingerprint: fingerprint.id.clone(),
            reason: "ports must be unique, sorted, and nonzero",
        });
    }
    if fingerprint.path.is_empty()
        || fingerprint.path.len() > 128
        || !fingerprint.path.starts_with('/')
        || fingerprint.path.contains(['?', '#'])
        || !fingerprint.path.is_ascii()
    {
        return Err(RegistryError::InvalidFingerprint {
            fingerprint: fingerprint.id.clone(),
            reason: "path must be a bounded static ASCII path without query or fragment",
        });
    }
    if matches!(fingerprint.method, SafeHttpMethod::Post) != fingerprint.request.is_some() {
        return Err(RegistryError::InvalidFingerprint {
            fingerprint: fingerprint.id.clone(),
            reason: "POST requires one compiled safe probe and other methods forbid request bodies",
        });
    }
    if fingerprint.accepted_content_types.is_empty()
        || fingerprint.accepted_content_types.iter().any(|value| {
            value.is_empty()
                || value.len() > 64
                || value != &value.to_ascii_lowercase()
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'+' | b'-'))
        })
    {
        return Err(RegistryError::InvalidFingerprint {
            fingerprint: fingerprint.id.clone(),
            reason: "content types must be bounded media types",
        });
    }
    if !(1..=65_536).contains(&fingerprint.max_response_bytes)
        || !(50..=5_000).contains(&fingerprint.timeout_millis)
        || fingerprint.assertions.is_empty()
    {
        return Err(RegistryError::InvalidFingerprint {
            fingerprint: fingerprint.id.clone(),
            reason: "response cap, timeout, or assertions are unsafe",
        });
    }
    for assertion in &fingerprint.assertions {
        let (field, fact) = match assertion {
            FingerprintAssertion::JsonStringPresent { field, fact } => (field, Some(fact)),
            FingerprintAssertion::JsonStringEquals { field, value } => {
                if value.is_empty() || value.len() > 64 {
                    return Err(RegistryError::InvalidFingerprint {
                        fingerprint: fingerprint.id.clone(),
                        reason: "assertion value is unsafe",
                    });
                }
                (field, None)
            }
            FingerprintAssertion::JsonArrayPresent { field, count_fact } => {
                (field, Some(count_fact))
            }
        };
        validate_json_path(field)?;
        if let Some(fact) = fact {
            validate_identifier(fact, "fingerprint fact")?;
        }
    }
    validate_evidence(
        &fingerprint.evidence,
        &format!("fingerprint.{}", fingerprint.id),
    )?;
    if fingerprint
        .evidence
        .iter()
        .all(|source| source.verified_at != fingerprint.verified_at)
    {
        return Err(RegistryError::InvalidFingerprint {
            fingerprint: fingerprint.id.clone(),
            reason: "verified_at must correspond to one evidence source",
        });
    }
    Ok(())
}

fn validate_json_path(value: &str) -> Result<(), RegistryError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        });
    if valid {
        Ok(())
    } else {
        Err(RegistryError::InvalidIdentifier {
            kind: "fingerprint field".to_owned(),
            value: value.to_owned(),
        })
    }
}

fn validate_fingerprints(
    fingerprints: &[HttpFingerprint],
) -> Result<BTreeSet<&str>, RegistryError> {
    let mut ids = BTreeSet::new();
    for fingerprint in fingerprints {
        validate_fingerprint(fingerprint)?;
        if !ids.insert(fingerprint.id.as_str()) {
            return Err(RegistryError::DuplicateFingerprintId(
                fingerprint.id.clone(),
            ));
        }
    }
    Ok(ids)
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn validate_identifier(value: &str, kind: &str) -> Result<(), RegistryError> {
    let valid = !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
        && !value.starts_with(['.', '-', '_'])
        && !value.ends_with(['.', '-', '_']);
    if valid {
        Ok(())
    } else {
        Err(RegistryError::InvalidIdentifier {
            kind: kind.to_owned(),
            value: value.to_owned(),
        })
    }
}

fn validate_confidence(value: u16, owner: &str) -> Result<(), RegistryError> {
    if (1..=10_000).contains(&value) {
        Ok(())
    } else {
        Err(RegistryError::InvalidConfidence(owner.to_owned()))
    }
}

fn validate_evidence(evidence: &[Evidence], owner: &str) -> Result<(), RegistryError> {
    if evidence.is_empty() {
        return Err(RegistryError::MissingEvidence(owner.to_owned()));
    }
    for source in evidence {
        if !source.url.starts_with("https://")
            || source.url.contains(char::is_whitespace)
            || source.reviewer.trim().is_empty()
        {
            return Err(RegistryError::InvalidEvidence {
                owner: owner.to_owned(),
                url: source.url.clone(),
            });
        }
    }
    Ok(())
}

fn ensure_unique(values: &[String], owner: &str, kind: &str) -> Result<(), RegistryError> {
    let mut unique = BTreeSet::new();
    for value in values {
        validate_identifier(value, kind)?;
        if !unique.insert(value) {
            return Err(RegistryError::DuplicateValue {
                owner: owner.to_owned(),
                kind: kind.to_owned(),
                value: value.clone(),
            });
        }
    }
    Ok(())
}

fn normalize_host(value: &str) -> Result<String, RegistryError> {
    let normalized = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = normalized.len() <= 253
        && normalized.contains('.')
        && !normalized.contains('*')
        && normalized.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if valid {
        Ok(normalized)
    } else {
        Err(RegistryError::InvalidHost(value.to_owned()))
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error(
        "registry schema version must be {REGISTRY_SCHEMA_VERSION} and bundle version is required"
    )]
    MissingVersion,
    #[error("registry source SHA-256 must be 64 lowercase hexadecimal characters")]
    InvalidSourceSha256,
    #[error("registry contains duplicate id {0}")]
    DuplicateId(String),
    #[error("registry entry {0} has no display name")]
    MissingName(String),
    #[error("registry contains duplicate fingerprint id {0}")]
    DuplicateFingerprintId(String),
    #[error("fingerprint {fingerprint} is invalid: {reason}")]
    InvalidFingerprint {
        fingerprint: String,
        reason: &'static str,
    },
    #[error("{owner} references unknown scanner fingerprint {target}")]
    UnknownFingerprintReference { owner: String, target: String },
    #[error("invalid {kind} identifier {value}")]
    InvalidIdentifier { kind: String, value: String },
    #[error("{owner} contains duplicate {kind} {value}")]
    DuplicateValue {
        owner: String,
        kind: String,
        value: String,
    },
    #[error("entry {entry} contains duplicate matcher id {matcher}")]
    DuplicateMatcherId { entry: String, matcher: String },
    #[error("matcher key {key} is claimed by both {first} and {second}")]
    MatcherCollision {
        key: String,
        first: String,
        second: String,
    },
    #[error("{0} has invalid confidence; expected 1..=10000 basis points")]
    InvalidConfidence(String),
    #[error("{0} requires at least one evidence source")]
    MissingEvidence(String),
    #[error("{owner} has invalid evidence URL or reviewer: {url}")]
    InvalidEvidence { owner: String, url: String },
    #[error("matcher {entry}.{matcher} verified_at must correspond to one evidence source")]
    UnlinkedVerificationDate { entry: String, matcher: String },
    #[error("{owner} references unknown registry entity {target}")]
    UnknownReference { owner: String, target: String },
    #[error("{owner} provider_ref {target} is not a provider")]
    InvalidProviderReference { owner: String, target: String },
    #[error("invalid DNS host {0}")]
    InvalidHost(String),
    #[error("invalid registry overlay {0}")]
    InvalidOverlay(String),
    #[error("multiple overlays assign {0} at the same precedence")]
    OverlayConflict(String),
    #[error("serialize registry: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("compress registry: {0}")]
    Compression(String),
    #[error("registry manifest mismatch: {0}")]
    ManifestMismatch(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 8, 13).expect("valid fixture date")
    }

    fn evidence(url: &str) -> Evidence {
        Evidence {
            source_type: EvidenceType::VendorDocumentation,
            url: url.to_owned(),
            verified_at: date(),
            reviewer: "godel-tally-maintainers".to_owned(),
        }
    }

    fn entry(id: &str, host: &str) -> RegistryEntry {
        RegistryEntry {
            id: id.to_owned(),
            kind: RegistryEntryKind::Service,
            name: id.to_owned(),
            provider_ref: None,
            categories: vec!["llm_api".to_owned()],
            surfaces: vec!["external_api".to_owned()],
            facts: BTreeMap::new(),
            matchers: vec![Matcher {
                id: "host.api".to_owned(),
                rule: MatcherRule::HostExact {
                    value: host.to_owned(),
                },
                produces: MatchProduces {
                    entity_ref: id.to_owned(),
                    proof: ProofKind::ServiceContact,
                },
                confidence_bps: 9_500,
                verified_at: date(),
                evidence: vec![evidence("https://vendor.example/docs")],
            }],
            status: RegistryEntryStatus::Active,
        }
    }

    fn source(entries: Vec<RegistryEntry>) -> RegistrySource {
        RegistrySource {
            schema_version: REGISTRY_SCHEMA_VERSION.to_owned(),
            version: "test-version".to_owned(),
            fingerprints: Vec::new(),
            entries,
        }
    }

    fn fingerprint(method: SafeHttpMethod, request: Option<SafeProbeRequest>) -> HttpFingerprint {
        HttpFingerprint {
            id: "fingerprint.test.metadata".to_owned(),
            ports: vec![3_000],
            method,
            request,
            path: "/metadata".to_owned(),
            accepted_content_types: vec!["application/json".to_owned()],
            max_response_bytes: 4_096,
            timeout_millis: 1_500,
            assertions: vec![FingerprintAssertion::JsonArrayPresent {
                field: "result.supportedVersions".to_owned(),
                count_fact: "version_count".to_owned(),
            }],
            verified_at: date(),
            evidence: vec![evidence("https://vendor.example/protocol")],
        }
    }

    #[test]
    fn compilation_is_order_independent() {
        let first = source(vec![
            entry("svc.openai.api", "api.openai.com"),
            entry("svc.anthropic.api", "api.anthropic.com"),
        ])
        .compile("tally-registry-test.json.zst")
        .expect("compile first source");
        let second = source(vec![
            entry("svc.anthropic.api", "api.anthropic.com"),
            entry("svc.openai.api", "api.openai.com"),
        ])
        .compile("tally-registry-test.json.zst")
        .expect("compile reordered source");

        assert_eq!(first.json, second.json);
        assert_eq!(first.compressed, second.compressed);
        assert_eq!(first.manifest, second.manifest);
        assert!(is_sha256_hex(&first.bundle.source_sha256));
    }

    #[test]
    fn source_digest_changes_with_canonical_source_content() {
        let first = source(vec![entry("svc.one", "api.example.com")])
            .compile("registry.json.zst")
            .expect("compile first source");
        let mut changed = entry("svc.one", "api.example.com");
        changed.name = "Changed display name".to_owned();
        let second = source(vec![changed])
            .compile("registry.json.zst")
            .expect("compile changed source");

        assert_ne!(first.bundle.source_sha256, second.bundle.source_sha256);
    }

    #[test]
    fn suffix_matching_respects_dns_label_boundaries() {
        let mut github = entry("svc.github.copilot", "copilot-proxy.githubusercontent.com");
        github.matchers[0].rule = MatcherRule::HostSuffix {
            value: "githubcopilot.com".to_owned(),
        };
        let bundle = source(vec![github])
            .compile("registry.json.zst")
            .expect("compile")
            .bundle;

        assert_eq!(
            bundle
                .match_host("api.business.githubcopilot.com")
                .expect("valid host")
                .len(),
            1
        );
        assert_eq!(
            bundle
                .match_host("evilgithubcopilot.com")
                .expect("valid host"),
            [] as [MatchHit; 0]
        );
    }

    #[test]
    fn colliding_matchers_fail_closed() {
        let error = source(vec![
            entry("svc.one", "api.example.com"),
            entry("svc.two", "API.EXAMPLE.COM."),
        ])
        .compile("registry.json.zst")
        .expect_err("collision must fail");

        assert!(matches!(error, RegistryError::MatcherCollision { .. }));
    }

    #[test]
    fn disable_rule_wins_over_overlay_matcher_override() {
        let base = source(vec![entry("svc.one", "api.example.com")])
            .compile("registry.json.zst")
            .expect("compile")
            .bundle;
        let overlay = RegistryOverlay {
            schema_version: REGISTRY_SCHEMA_VERSION.to_owned(),
            id: "lab".to_owned(),
            additions: Vec::new(),
            entries: vec![RegistryEntryOverride {
                id: "svc.one".to_owned(),
                name: Some("Private display name".to_owned()),
                categories: None,
                surfaces: None,
                facts: BTreeMap::new(),
                matchers: Vec::new(),
            }],
            disabled_matchers: vec![MatcherRef {
                entry_id: "svc.one".to_owned(),
                matcher_id: "host.api".to_owned(),
            }],
        };

        let effective = apply_overlays(&base, &[overlay]).expect("apply overlay");
        assert_eq!(effective.entries[0].name, "Private display name");
        assert_eq!(effective.entries[0].matchers, [] as [Matcher; 0]);
    }

    #[test]
    fn same_precedence_overlay_conflicts_fail() {
        let base = source(vec![entry("svc.one", "api.example.com")])
            .compile("registry.json.zst")
            .expect("compile")
            .bundle;
        let overlay = |id: &str, name: &str| RegistryOverlay {
            schema_version: REGISTRY_SCHEMA_VERSION.to_owned(),
            id: id.to_owned(),
            additions: Vec::new(),
            entries: vec![RegistryEntryOverride {
                id: "svc.one".to_owned(),
                name: Some(name.to_owned()),
                categories: None,
                surfaces: None,
                facts: BTreeMap::new(),
                matchers: Vec::new(),
            }],
            disabled_matchers: Vec::new(),
        };

        let error = apply_overlays(
            &base,
            &[overlay("first", "First"), overlay("second", "Second")],
        )
        .expect_err("conflict must fail");
        assert!(matches!(error, RegistryError::OverlayConflict(_)));
    }

    #[test]
    fn local_addition_is_validated_and_matches_without_mutating_base() {
        let base = source(vec![entry("svc.one", "api.example.com")])
            .compile("registry.json.zst")
            .expect("compile")
            .bundle;
        let local = entry("local.service.lab", "ai.lab.example");
        let overlay = RegistryOverlay {
            schema_version: REGISTRY_SCHEMA_VERSION.to_owned(),
            id: "local.service.lab".to_owned(),
            additions: vec![local],
            entries: Vec::new(),
            disabled_matchers: Vec::new(),
        };

        let effective = apply_overlays(&base, &[overlay]).expect("apply addition");
        assert_eq!(base.entries.len(), 1);
        assert_eq!(effective.entries.len(), 2);
        assert_eq!(
            effective.match_host("ai.lab.example").expect("valid host")[0].entry_id,
            "local.service.lab"
        );
    }

    #[test]
    fn local_suffix_cannot_shadow_a_signed_exact_host() {
        let base = source(vec![entry("svc.one", "api.example.com")])
            .compile("registry.json.zst")
            .expect("compile")
            .bundle;
        let mut local = entry("local.service.shadow", "example.com");
        local.matchers[0].rule = MatcherRule::HostSuffix {
            value: "example.com".to_owned(),
        };
        let overlay = RegistryOverlay {
            schema_version: REGISTRY_SCHEMA_VERSION.to_owned(),
            id: "local.service.shadow".to_owned(),
            additions: vec![local],
            entries: Vec::new(),
            disabled_matchers: Vec::new(),
        };

        let error = apply_overlays(&base, &[overlay]).expect_err("overlap must fail closed");
        assert!(matches!(error, RegistryError::MatcherCollision { .. }));
    }

    #[test]
    fn verification_rejects_corrupt_compressed_artifact() {
        let compiled = source(vec![entry("svc.one", "api.example.com")])
            .compile("registry.json.zst")
            .expect("compile");
        let mut corrupt = compiled.compressed;
        corrupt[0] ^= 1;

        let error = verify_artifact(&corrupt, &compiled.manifest).expect_err("reject corruption");
        assert!(matches!(error, RegistryError::ManifestMismatch(_)));
    }

    #[test]
    fn post_fingerprint_requires_a_compiled_safe_probe() {
        let error = validate_fingerprint(&fingerprint(SafeHttpMethod::Post, None))
            .expect_err("arbitrary POST bodies must be impossible");
        assert!(matches!(error, RegistryError::InvalidFingerprint { .. }));
    }

    #[test]
    fn non_post_fingerprint_forbids_a_request_body() {
        let error = validate_fingerprint(&fingerprint(
            SafeHttpMethod::Get,
            Some(SafeProbeRequest::McpServerDiscover20260728),
        ))
        .expect_err("GET request bodies must be impossible");
        assert!(matches!(error, RegistryError::InvalidFingerprint { .. }));
    }

    #[test]
    fn bounded_nested_json_paths_are_validated() {
        validate_fingerprint(&fingerprint(
            SafeHttpMethod::Post,
            Some(SafeProbeRequest::McpServerDiscover20260728),
        ))
        .expect("declared nested response fields are allowed");

        let mut invalid = fingerprint(
            SafeHttpMethod::Post,
            Some(SafeProbeRequest::McpServerDiscover20260728),
        );
        invalid.assertions = vec![FingerprintAssertion::JsonArrayPresent {
            field: "result..supportedVersions".to_owned(),
            count_fact: "version_count".to_owned(),
        }];
        assert!(matches!(
            validate_fingerprint(&invalid),
            Err(RegistryError::InvalidIdentifier { .. })
        ));
    }
}
