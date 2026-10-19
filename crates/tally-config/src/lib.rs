//! Typed process configuration. Secret values redact themselves from `Debug` output.

use std::{env, fmt, net::SocketAddr, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct TallyConfig {
    pub http_bind: SocketAddr,
    pub postgres_url: SecretString,
    pub log_filter: String,
    pub log_format: LogFormat,
}

impl TallyConfig {
    /// Loads Tally configuration from environment variables and safe local defaults.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when a configured address or enum value is invalid.
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            http_bind: parse_env("TALLY_HTTP_BIND", "127.0.0.1:8788")?,
            postgres_url: SecretString::new(read_env(
                "TALLY_POSTGRES_URL",
                "postgres://tally:tally@127.0.0.1:5433/tally",
            )),
            log_filter: read_env("TALLY_LOG", "tally=info,tower_http=info"),
            log_format: parse_env("TALLY_LOG_FORMAT", "pretty")?,
        })
    }
}

fn read_env(name: &'static str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn parse_env<T>(name: &'static str, default: &str) -> Result<T, ConfigError>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    let value = read_env(name, default);
    value.parse::<T>().map_err(|error| ConfigError::Invalid {
        name,
        reason: error.to_string(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    Pretty,
    Json,
}

impl FromStr for LogFormat {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "pretty" => Ok(Self::Pretty),
            "json" => Ok(Self::Json),
            _ => Err("expected pretty or json"),
        }
    }
}

#[derive(Clone)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid {name}: {reason}")]
    Invalid { name: &'static str, reason: String },
    #[error("secret cipher unavailable: {0}")]
    SecretCipher(String),
}

/// Authenticated encryption used to protect connector credentials at rest in `PostgreSQL`.
///
/// The 32-byte key is read from `TALLY_SECRET_KEY` as 64 lowercase hexadecimal characters and
/// redacts itself from `Debug` output. Rotating the key requires re-entering stored credentials.
#[derive(Clone)]
pub struct SecretCipher {
    key: chacha20poly1305::Key,
}

impl SecretCipher {
    /// Loads the credential-encryption key from `TALLY_SECRET_KEY`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::SecretCipher`] when the variable is missing or malformed.
    pub fn from_env() -> Result<Self, ConfigError> {
        let value = env::var("TALLY_SECRET_KEY").map_err(|_| {
            ConfigError::SecretCipher("TALLY_SECRET_KEY must be a 64-character hex key".to_owned())
        })?;
        Self::from_hex(&value)
    }

    /// Builds a cipher from a 64-character lowercase hexadecimal key.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::SecretCipher`] when the key is not exactly 32 bytes of hex.
    pub fn from_hex(value: &str) -> Result<Self, ConfigError> {
        let bytes = hex::decode(value).map_err(|error| {
            ConfigError::SecretCipher(format!("TALLY_SECRET_KEY is not valid hex: {error}"))
        })?;
        let key: [u8; 32] = bytes.try_into().map_err(|_| {
            ConfigError::SecretCipher("TALLY_SECRET_KEY must decode to exactly 32 bytes".to_owned())
        })?;
        Ok(Self::from_bytes(key))
    }

    /// Builds a cipher from already-derived 256-bit key material.
    ///
    /// Host products use this constructor to domain-separate an existing installation secret
    /// without making Tally depend on the host's configuration model.
    #[must_use]
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self {
            key: chacha20poly1305::Key::from(key),
        }
    }

    /// Derives Tally credential-encryption key material from a host installation secret.
    ///
    /// Domain separation prevents Tally ciphertext from reusing the host secret directly or
    /// colliding with keys the host derives for its own purposes.
    #[must_use]
    pub fn from_host_secret(secret: &[u8]) -> Self {
        use sha2::{Digest as _, Sha256};

        let mut digest = Sha256::new();
        digest.update(b"godel-tally/host-credential-encryption/v1\0");
        digest.update(secret);
        Self::from_bytes(digest.finalize().into())
    }

    /// Derives the standalone collector's import-only API credential.
    #[must_use]
    pub fn collector_import_token(&self) -> String {
        use sha2::{Digest as _, Sha256};

        let mut digest = Sha256::new();
        digest.update(b"tally/collector-import/v1\0");
        digest.update(self.key.as_slice());
        hex::encode(digest.finalize())
    }

    /// Encrypts a plaintext credential, returning the random nonce and the authenticated
    /// ciphertext as separate byte vectors for durable storage.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::SecretCipher`] when secure randomness is unavailable.
    pub fn encrypt(&self, plaintext: &str) -> Result<(Vec<u8>, Vec<u8>), ConfigError> {
        use chacha20poly1305::{KeyInit, aead::Aead};

        let mut nonce_bytes = [0_u8; 12];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|error| ConfigError::SecretCipher(error.to_string()))?;
        let nonce = chacha20poly1305::Nonce::from(nonce_bytes);
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(&self.key);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| ConfigError::SecretCipher("encryption failed".to_owned()))?;
        Ok((nonce_bytes.to_vec(), ciphertext))
    }

    /// Decrypts a nonce/ciphertext pair produced by [`SecretCipher::encrypt`].
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::SecretCipher`] when the inputs are malformed or the tag does not
    /// authenticate, which indicates a wrong key or tampered ciphertext.
    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<String, ConfigError> {
        use chacha20poly1305::{KeyInit, aead::Aead};

        let nonce_bytes: [u8; 12] = nonce.try_into().map_err(|_| {
            ConfigError::SecretCipher("stored credential nonce has an invalid length".to_owned())
        })?;
        let nonce = chacha20poly1305::Nonce::from(nonce_bytes);
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(&self.key);
        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| ConfigError::SecretCipher("decryption failed".to_owned()))?;
        String::from_utf8(plaintext)
            .map_err(|_| ConfigError::SecretCipher("decrypted value is not UTF-8".to_owned()))
    }
}

impl fmt::Debug for SecretCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretCipher([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let secret = SecretString::new("do-not-print-me");
        let debug = format!("{secret:?}");
        assert!(!debug.contains("do-not-print-me"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn host_secret_derivation_is_stable_and_domain_separated() {
        let tally = SecretCipher::from_host_secret(b"installation-secret");
        let tally_again = SecretCipher::from_host_secret(b"installation-secret");
        let other = SecretCipher::from_host_secret(b"other-installation-secret");

        let (nonce, ciphertext) = tally.encrypt("credential").expect("seal credential");
        assert_eq!(
            tally_again
                .decrypt(&nonce, &ciphertext)
                .expect("open with same host secret"),
            "credential"
        );
        assert!(other.decrypt(&nonce, &ciphertext).is_err());
    }
}
