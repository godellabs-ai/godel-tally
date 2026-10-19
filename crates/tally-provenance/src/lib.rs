//! Canonical evidence digests.

use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Serializes a value and returns its SHA-256 digest as lowercase hexadecimal.
///
/// # Errors
///
/// Returns [`ProvenanceError`] when the value cannot be serialized as JSON.
pub fn sha256_json(value: &impl Serialize) -> Result<String, ProvenanceError> {
    let canonical = serde_json::to_vec(value)?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

#[derive(Debug, Error)]
pub enum ProvenanceError {
    #[error("cannot serialize provenance value: {0}")]
    Json(#[from] serde_json::Error),
}
