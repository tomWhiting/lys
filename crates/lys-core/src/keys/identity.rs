//! Ed25519 identity keypair — the cryptographic root of trust.
//!
//! **Invariant:** the signing key (private seed) NEVER appears in `Debug`
//! output, log lines, or error messages. The custom `Debug` impl redacts it
//! unconditionally; key-management errors carry only operational context, not
//! key material.
//!
//! Identities are obtained via [`Ed25519Identity::load_or_generate`]
//! (file-backed) or [`Ed25519Identity::from_env`] (env-var-backed, for
//! containers and CI). The two paths are independent — neither calls the
//! other.
//!
//! **Concurrency invariant:** when multiple callers — threads in one process
//! or separate processes — race `load_or_generate` on the same missing path,
//! exactly one generated seed is ever persisted and every caller returns the
//! identity for that persisted seed. Each generator writes its candidate
//! seed to a uniquely named temp file (pid + per-process counter) and
//! publishes it with a no-clobber `hard_link`; the first publisher wins, and
//! losers discard their candidate seed and load the winner's file. The key
//! file at a given path therefore never changes once created.
//!
//! Sealed payload transport uses X25519 key agreement, but the long-term keys
//! here are Ed25519. [`Ed25519Identity::x25519_static_secret`] and
//! [`Ed25519Identity::x25519_public_key`] derive the X25519 keypair from the
//! Ed25519 signing key via the standard clamped-scalar conversion, so one
//! keypair serves both signing and key agreement.

use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::Signer;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{TrustError, TrustResult};

/// Name of the environment variable read by [`Ed25519Identity::from_env`].
const KEY_ENV_VAR: &str = "LYS_IDENTITY_KEY";

/// Ed25519 identity keypair.
///
/// This is the cryptographic root of trust for the consuming domain. The
/// signing key never appears in `Debug` output. Obtain one via
/// [`Self::load_or_generate`] (file-backed) or [`Self::from_env`]
/// (env-var-backed).
pub struct Ed25519Identity {
    signing_key: ed25519_dalek::SigningKey,
    verifying_key: ed25519_dalek::VerifyingKey,
}

impl fmt::Debug for Ed25519Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Identity")
            .field("signing_key", &"[REDACTED]")
            .field("verifying_key", &self.public_key_bytes_hex())
            .finish()
    }
}

impl Ed25519Identity {
    /// Returns the 32-byte Ed25519 verifying (public) key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Signs a message with the identity's Ed25519 signing key.
    ///
    /// Returns the 64-byte detached signature. Ed25519 deterministic signing
    /// is infallible in dalek 2.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Verifies an Ed25519 signature against a public key using **strict**
    /// verification (`verify_strict`).
    ///
    /// Static method (no `&self`) so callers can verify against any public
    /// key without holding an [`Ed25519Identity`] instance.
    ///
    /// Strict verification rejects signature malleability (non-canonical
    /// scalar and group-element encodings) and small-order/torsion public
    /// keys and `R` components, which plain `verify` accepts. This crate is
    /// an audit trust foundation: non-repudiation requires that a given
    /// (message, public key) pair has a unique valid signature and that weak
    /// keys — for which signatures can be forged for arbitrary messages —
    /// are categorically rejected.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::InvalidSignature`] if the signature is not
    /// exactly 64 bytes, the public key is not a valid Ed25519 point, the
    /// public key or the signature's `R` component is a small-order point,
    /// or the signature does not strictly verify against the message.
    pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> TrustResult<()> {
        let sig_bytes: &[u8; 64] = signature
            .try_into()
            .map_err(|_err| TrustError::InvalidSignature)?;
        let signature = ed25519_dalek::Signature::from_bytes(sig_bytes);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(public_key)
            .map_err(|_err| TrustError::InvalidSignature)?;
        vk.verify_strict(message, &signature)
            .map_err(|_err| TrustError::InvalidSignature)
    }

    /// Derives the X25519 static secret from the Ed25519 signing key.
    ///
    /// Uses the standard Ed25519-to-X25519 clamped-scalar conversion
    /// (`to_scalar_bytes`), so the same Ed25519 identity always yields the
    /// same X25519 secret. Used as the long-term key for sealed payload key
    /// agreement.
    pub fn x25519_static_secret(&self) -> x25519_dalek::StaticSecret {
        x25519_dalek::StaticSecret::from(self.signing_key.to_scalar_bytes())
    }

    /// Returns the Montgomery-form X25519 public key derived from this
    /// identity, matching the public key of [`Self::x25519_static_secret`].
    pub fn x25519_public_key(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.x25519_static_secret()).to_bytes()
    }

    /// Loads or generates the identity from a file.
    ///
    /// File format: raw 32-byte Ed25519 seed (not base64, not PEM). On Unix,
    /// generated files are mode `0600`. Existing files with looser
    /// permissions emit a `tracing::warn!` but still load (an operator may
    /// have a legitimate reason).
    ///
    /// Safe under concurrency: racing callers (threads or processes) on the
    /// same missing path all return the identity of the single seed that
    /// wins the atomic no-clobber publish — no caller ever holds an identity
    /// that differs from the persisted file. See the module docs for the
    /// mechanism.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::KeyManagement`] if the existing file cannot be
    /// read, its length is not exactly 32 bytes, the path has no filename
    /// component, or the parent directory or file cannot be written.
    pub fn load_or_generate(path: &Path) -> TrustResult<Self> {
        if path.exists() {
            load_existing(path)
        } else {
            generate_and_persist(path)
        }
    }

    /// Loads the identity from the `LYS_IDENTITY_KEY` environment variable.
    ///
    /// The value is a base64-encoded 32-byte seed. Both standard and
    /// URL-safe-no-pad base64 encodings are accepted, and surrounding
    /// whitespace is trimmed. Independent of [`Self::load_or_generate`].
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::KeyManagement`] if the variable is unset,
    /// contains invalid base64, or decodes to a length other than 32 bytes.
    pub fn from_env() -> TrustResult<Self> {
        let raw = std::env::var(KEY_ENV_VAR).map_err(|_err| TrustError::KeyManagement {
            reason: format!("environment variable {KEY_ENV_VAR} not set"),
        })?;
        let trimmed = raw.trim();
        let decoded = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(trimmed.trim_end_matches('='))
                .or_else(|_err| STANDARD.decode(trimmed))
                .map_err(|_err| TrustError::KeyManagement {
                    reason: format!("environment variable {KEY_ENV_VAR} contains invalid base64"),
                })?,
        );
        let n = decoded.len();
        if n != 32 {
            return Err(TrustError::KeyManagement {
                reason: format!(
                    "environment variable {KEY_ENV_VAR} decoded to {n} bytes, expected 32"
                ),
            });
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&decoded);
        Ok(Self::from_seed(&seed))
    }

    /// Constructs an identity from a raw 32-byte seed.
    ///
    /// Takes the seed wrapped in [`Zeroizing`] so every caller's copy is
    /// guaranteed to be overwritten when it goes out of scope; only the
    /// [`SigningKey`]'s own internal copy survives.
    ///
    /// Private to the crate; tests in the same module use it to build
    /// deterministic identities. Not part of the public API, so no
    /// constructor accepting private key material is exposed to consumers.
    ///
    /// [`SigningKey`]: ed25519_dalek::SigningKey
    fn from_seed(seed: &Zeroizing<[u8; 32]>) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Lowercase hex encoding of the verifying key, for `Debug` output.
    fn public_key_bytes_hex(&self) -> String {
        crate::hex_lower(&self.verifying_key.to_bytes())
    }
}

#[cfg(unix)]
fn warn_if_loose_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mode = match std::fs::metadata(path) {
        Ok(m) => m.permissions().mode(),
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "could not stat identity key file to check permissions"
            );
            return;
        }
    };
    if mode & 0o077 != 0 {
        tracing::warn!(
            path = %path.display(),
            mode = format!("{:o}", mode & 0o777),
            "identity key file has loose permissions; expected 0600"
        );
    }
}

#[cfg(not(unix))]
fn warn_if_loose_permissions(_path: &Path) {}

/// Loads an identity from an existing key file (raw 32-byte seed).
///
/// Warns (but still loads) on loose Unix permissions. Shared by
/// [`Ed25519Identity::load_or_generate`] and the lost-publish-race path of
/// [`generate_and_persist`].
fn load_existing(path: &Path) -> TrustResult<Ed25519Identity> {
    warn_if_loose_permissions(path);
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|e| TrustError::KeyManagement {
        reason: format!("failed to read identity key: {e}"),
    })?);
    if bytes.len() != 32 {
        return Err(TrustError::KeyManagement {
            reason: format!(
                "identity key file has invalid length: expected 32 bytes, got {}",
                bytes.len()
            ),
        });
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&bytes);
    Ok(Ed25519Identity::from_seed(&seed))
}

/// Monotonic per-process counter mixed into temp key-file names so
/// concurrent generators within the same process never share a temp path.
/// The process id in the name covers cross-process uniqueness.
static TMP_NAME_COUNTER: AtomicU64 = AtomicU64::new(0);

fn generate_and_persist(path: &Path) -> TrustResult<Ed25519Identity> {
    let file_name = path.file_name().ok_or_else(|| TrustError::KeyManagement {
        reason: format!(
            "identity key path has no filename component: {}",
            path.display()
        ),
    })?;
    let parent = path.parent().unwrap_or_else(|| Path::new(""));

    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(&mut *seed);

    if !parent.as_os_str().is_empty() {
        std::fs::create_dir_all(parent).map_err(|e| TrustError::KeyManagement {
            reason: format!("failed to write identity key: {e}"),
        })?;
    }

    // The tmp suffix embeds the process id (cross-process uniqueness) and a
    // per-process counter (same-process uniqueness), so concurrent
    // generators never clobber each other's in-flight tmp file.
    let unique = TMP_NAME_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(format!(".{}.{unique}.tmp", std::process::id()));
    let tmp_path = if parent.as_os_str().is_empty() {
        std::path::PathBuf::from(tmp_name)
    } else {
        parent.join(tmp_name)
    };

    if let Err(e) = write_identity_file(&tmp_path, &seed) {
        remove_tmp_file(&tmp_path);
        return Err(e);
    }

    // Publish with a no-clobber `hard_link` rather than `rename`: linking
    // fails with `AlreadyExists` if the destination exists, so the first
    // generator to publish wins permanently and the key file never changes
    // once created. A `rename` here would let a later generator overwrite
    // the winner, leaving the earlier caller holding an identity whose seed
    // is no longer the one on disk.
    match std::fs::hard_link(&tmp_path, path) {
        Ok(()) => {
            remove_tmp_file(&tmp_path);
            tracing::info!(
                path = %path.display(),
                "generated and persisted identity key"
            );
            Ok(Ed25519Identity::from_seed(&seed))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Lost the publish race: a concurrent generator persisted its
            // key first. First writer wins — discard our candidate seed and
            // load the persisted one so we return the identity that is
            // actually on disk.
            remove_tmp_file(&tmp_path);
            tracing::info!(
                path = %path.display(),
                "identity key was persisted concurrently; loading the persisted key"
            );
            load_existing(path)
        }
        Err(e) => {
            remove_tmp_file(&tmp_path);
            Err(TrustError::KeyManagement {
                reason: format!("failed to write identity key: {e}"),
            })
        }
    }
}

/// Best-effort removal of an in-flight tmp key file after a failed write or
/// rename. A missing file is fine (the failure may have preceded creation);
/// any other removal error is logged so the orphaned file — which may contain
/// key material — is never silently left behind.
fn remove_tmp_file(tmp_path: &Path) {
    if let Err(e) = std::fs::remove_file(tmp_path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(
            path = %tmp_path.display(),
            error = %e,
            "failed to remove temporary identity key file after write failure"
        );
    }
}

#[cfg(unix)]
fn write_identity_file(path: &Path, seed: &[u8; 32]) -> TrustResult<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| TrustError::KeyManagement {
            reason: format!("failed to write identity key: {e}"),
        })?;
    file.write_all(seed)
        .map_err(|e| TrustError::KeyManagement {
            reason: format!("failed to write identity key: {e}"),
        })?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
        TrustError::KeyManagement {
            reason: format!("failed to write identity key: {e}"),
        }
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn write_identity_file(path: &Path, seed: &[u8; 32]) -> TrustResult<()> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| TrustError::KeyManagement {
            reason: format!("failed to write identity key: {e}"),
        })?;
    file.write_all(seed)
        .map_err(|e| TrustError::KeyManagement {
            reason: format!("failed to write identity key: {e}"),
        })?;
    Ok(())
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;
