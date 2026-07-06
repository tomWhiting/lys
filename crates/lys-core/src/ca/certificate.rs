//! [`IssuedCertificate`] — the result of a certificate-authority issuance.
//!
//! Holds the signed X.509 DER, the subject's freshly generated Ed25519
//! keypair, a SHA-256 fingerprint of the DER, the expiry instant, and the
//! issuer's public key. The subject signing key is private material: the
//! manual [`fmt::Debug`] impl redacts it unconditionally and the type never
//! derives `Debug` (which would expose key internals).

use std::fmt;

use chrono::{DateTime, Utc};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::{TrustError, TrustResult};
use crate::hex_lower;

/// A certificate issued by a [`crate::ca::CertificateAuthority`].
///
/// The subject keypair is generated during issuance and travels with the
/// certificate so the holder can prove possession of the subject identity.
/// The signing half is private — guard it accordingly; it is redacted from
/// `Debug` output.
pub struct IssuedCertificate {
    /// The signed certificate in DER encoding.
    pub der_bytes: Vec<u8>,
    /// The subject's Ed25519 signing (private) key. **Sensitive material** —
    /// redacted from `Debug`.
    pub subject_signing_key: SigningKey,
    /// The subject's Ed25519 verifying (public) key, matching
    /// [`Self::subject_signing_key`].
    pub subject_verifying_key: VerifyingKey,
    /// SHA-256 fingerprint of [`Self::der_bytes`].
    pub fingerprint: [u8; 32],
    /// Instant after which the certificate is no longer valid.
    pub expires_at: DateTime<Utc>,
    /// The 32-byte Ed25519 public key of the issuing authority.
    pub issuer_public_key: [u8; 32],
}

impl IssuedCertificate {
    /// Builds an [`IssuedCertificate`] from signed DER and the subject keypair.
    ///
    /// Computes the SHA-256 fingerprint over `der_bytes`, converts the rcgen
    /// Ed25519 subject keypair into dalek signing/verifying keys via its
    /// PKCS#8 serialization, and validates that the raw public key is exactly
    /// 32 bytes and consistent with the recovered signing key.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::CertificateGeneration`] if the subject public key
    /// is not 32 bytes, the PKCS#8 private key cannot be decoded into a dalek
    /// signing key, or the recovered public key does not match the keypair.
    pub fn from_der_and_keypair(
        der_bytes: Vec<u8>,
        subject_keypair: &rcgen::KeyPair,
        expires_at: DateTime<Utc>,
        issuer_public_key: [u8; 32],
    ) -> TrustResult<Self> {
        let raw_public = subject_keypair.public_key_raw();
        if raw_public.len() != 32 {
            return Err(TrustError::CertificateGeneration {
                reason: format!(
                    "subject public key must be 32 bytes for Ed25519, got {}",
                    raw_public.len()
                ),
            });
        }

        let pkcs8 = subject_keypair.serialize_der();
        let subject_signing_key =
            SigningKey::from_pkcs8_der(&pkcs8).map_err(|e| TrustError::CertificateGeneration {
                reason: format!("failed to load subject signing key from PKCS#8: {e}"),
            })?;
        let subject_verifying_key = subject_signing_key.verifying_key();

        if subject_verifying_key.to_bytes().as_slice() != raw_public {
            return Err(TrustError::CertificateGeneration {
                reason: "subject keypair public and private halves do not match".to_string(),
            });
        }

        let fingerprint: [u8; 32] = Sha256::digest(&der_bytes).into();

        Ok(Self {
            der_bytes,
            subject_signing_key,
            subject_verifying_key,
            fingerprint,
            expires_at,
            issuer_public_key,
        })
    }
}

impl fmt::Debug for IssuedCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedCertificate")
            .field("der_bytes_len", &self.der_bytes.len())
            .field("subject_signing_key", &"[REDACTED]")
            .field(
                "subject_verifying_key",
                &hex_lower(&self.subject_verifying_key.to_bytes()),
            )
            .field("fingerprint", &hex_lower(&self.fingerprint))
            .field("expires_at", &self.expires_at)
            .field("issuer_public_key", &hex_lower(&self.issuer_public_key))
            .finish()
    }
}

#[cfg(test)]
#[path = "certificate_tests.rs"]
mod tests;
