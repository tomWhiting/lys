//! [`CertificateAuthority`] — Ed25519-rooted X.509 issuance and chain
//! verification.
//!
//! The authority wraps an [`Ed25519Identity`] and issues short-lived X.509
//! certificates for arbitrary subjects. All certificates use Ed25519
//! exclusively: the subject keypair is generated with `PKCS_ED25519` and the
//! certificate is signed by the authority's Ed25519 key, surfaced to rcgen
//! through a [`RemoteKeyPair`] adapter so the authority's private seed is
//! never exposed.
//!
//! Chain verification is performed directly with `ed25519-dalek`:
//! x509-parser is used only to parse the certificate and recover its
//! to-be-signed bytes and signature. x509-parser's own `verify_signature` is
//! never called — it cannot verify Ed25519.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Timelike, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CustomExtension, DistinguishedName, DnType,
    IsCa, KeyPair, PKCS_ED25519, RemoteKeyPair, SignatureAlgorithm,
};
use time::OffsetDateTime;
use x509_parser::oid_registry::OID_SIG_ED25519;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::ca::certificate::IssuedCertificate;
use crate::error::{TrustError, TrustResult};
use crate::hex_lower;
use crate::keys::Ed25519Identity;

/// Issues X.509 certificates signed by an Ed25519 root identity.
#[derive(Debug)]
pub struct CertificateAuthority {
    identity: Arc<Ed25519Identity>,
}

impl CertificateAuthority {
    /// Wraps an [`Ed25519Identity`] as a certificate authority.
    pub fn new(identity: Ed25519Identity) -> Self {
        Self {
            identity: Arc::new(identity),
        }
    }

    /// Returns the authority's 32-byte Ed25519 public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.identity.public_key_bytes()
    }

    /// Issues a certificate for `subject`, valid for `ttl` from now, carrying
    /// the supplied non-critical custom extensions.
    ///
    /// A fresh Ed25519 subject keypair is generated for the certificate. The
    /// certificate is signed by this authority's Ed25519 key; the issuer
    /// distinguished name is derived from the authority's public key so the
    /// issued certificate's issuer field is tied to this authority.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::CertificateGeneration`] if `subject` is empty,
    /// `ttl` is zero or out of representable range, subject key generation
    /// fails, or rcgen cannot build or sign the certificate.
    pub fn issue_certificate(
        &self,
        subject: &str,
        ttl: Duration,
        extensions: Vec<CustomExtension>,
    ) -> TrustResult<IssuedCertificate> {
        if subject.trim().is_empty() {
            return Err(TrustError::CertificateGeneration {
                reason: "certificate subject must not be empty".to_string(),
            });
        }
        if ttl.is_zero() {
            return Err(TrustError::CertificateGeneration {
                reason: "certificate TTL must be positive".to_string(),
            });
        }

        let issuer_key = self.issuer_key_pair()?;
        let issuer_cert = self.issuer_certificate(&issuer_key)?;

        let subject_key = KeyPair::generate_for(&PKCS_ED25519).map_err(|e| {
            TrustError::CertificateGeneration {
                reason: format!("failed to generate Ed25519 subject keypair: {e}"),
            }
        })?;

        let issued_at = Utc::now();
        let ttl =
            chrono::Duration::from_std(ttl).map_err(|e| TrustError::CertificateGeneration {
                reason: format!("certificate TTL is out of representable range: {e}"),
            })?;
        let expires_at =
            issued_at
                .checked_add_signed(ttl)
                .ok_or_else(|| TrustError::CertificateGeneration {
                    reason: "certificate expiry overflowed the supported date range".to_string(),
                })?;
        // The DER `notAfter` is encoded at whole-second granularity (see
        // `to_offset_date_time`), so truncate the reported expiry to the same
        // instant — otherwise `expires_at` could run up to a second past the
        // certificate's actual validity.
        let expires_at =
            expires_at
                .with_nanosecond(0)
                .ok_or_else(|| TrustError::CertificateGeneration {
                    reason: "certificate expiry could not be truncated to whole seconds"
                        .to_string(),
                })?;

        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|e| {
            TrustError::CertificateGeneration {
                reason: format!("failed to build certificate parameters: {e}"),
            }
        })?;
        params.distinguished_name = distinguished_name(subject);
        params.is_ca = IsCa::ExplicitNoCa;
        params.not_before = to_offset_date_time(issued_at)?;
        params.not_after = to_offset_date_time(expires_at)?;
        params.custom_extensions = extensions;

        let certificate = params
            .signed_by(&subject_key, &issuer_cert, &issuer_key)
            .map_err(|e| TrustError::CertificateGeneration {
                reason: format!("failed to sign certificate: {e}"),
            })?;

        IssuedCertificate::from_der_and_keypair(
            certificate.der().to_vec(),
            &subject_key,
            expires_at,
            self.identity.public_key_bytes(),
        )
    }

    /// Verifies that `cert_der` was issued by this authority and is within
    /// its validity window at the current time.
    ///
    /// Convenience over the free [`verify_certificate_chain`] using this
    /// authority's public key as the expected issuer. The validity window is
    /// evaluated against `Utc::now()`; use the free
    /// [`verify_certificate_chain_at`] to verify at an explicit instant.
    ///
    /// # Errors
    ///
    /// See [`verify_certificate_chain`].
    pub fn verify_certificate_chain(&self, cert_der: &[u8]) -> TrustResult<()> {
        verify_certificate_chain(cert_der, &self.identity.public_key_bytes())
    }

    /// Builds an rcgen [`KeyPair`] backed by this authority's identity through
    /// a [`RemoteKeyPair`] adapter, so the private seed is never serialised.
    fn issuer_key_pair(&self) -> TrustResult<KeyPair> {
        let remote = IdentitySigner::new(Arc::clone(&self.identity));
        KeyPair::from_remote(Box::new(remote)).map_err(|e| TrustError::CertificateGeneration {
            reason: format!("failed to construct issuer key from identity: {e}"),
        })
    }

    /// Builds the self-signed in-memory issuer certificate whose subject DN is
    /// derived from this authority's public key.
    fn issuer_certificate(&self, issuer_key: &KeyPair) -> TrustResult<Certificate> {
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|e| {
            TrustError::CertificateGeneration {
                reason: format!("failed to build issuer parameters: {e}"),
            }
        })?;
        let common_name = hex_lower(&self.identity.public_key_bytes());
        params.distinguished_name = distinguished_name(&common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .self_signed(issuer_key)
            .map_err(|e| TrustError::CertificateGeneration {
                reason: format!("failed to build issuer certificate: {e}"),
            })
    }
}

/// Verifies a certificate's Ed25519 signature against an expected issuer key
/// and checks the validity window at the current time (`Utc::now()`).
///
/// Thin wrapper over [`verify_certificate_chain_at`]; see it for the full
/// list of checks.
///
/// # Errors
///
/// See [`verify_certificate_chain_at`].
pub fn verify_certificate_chain(cert_der: &[u8], issuer_public_key: &[u8; 32]) -> TrustResult<()> {
    verify_certificate_chain_at(cert_der, issuer_public_key, Utc::now())
}

/// Verifies a certificate's Ed25519 signature against an expected issuer key
/// and checks that `at` falls within the certificate's validity window.
///
/// Parses `cert_der`, rejects self-signed certificates (issuer equal to
/// subject), confirms the signature algorithm is Ed25519, recovers the
/// to-be-signed DER and 64-byte signature, verifies the signature with
/// `ed25519-dalek` **strict** verification, and finally rejects the
/// certificate if `at` lies outside its `notBefore`/`notAfter` window
/// (boundaries inclusive, per X.509). x509-parser's `verify_signature` is
/// deliberately not used — it cannot verify Ed25519.
///
/// Strict verification (`verify_strict`) rejects signature malleability and
/// small-order/torsion issuer keys, which plain `verify` accepts. This crate
/// is an audit trust foundation: non-repudiation requires that a certificate
/// has a unique valid signature under the issuer key, and weak keys — for
/// which signatures can be forged for arbitrary payloads — must be
/// categorically rejected.
///
/// The self-signed rejection compares the raw subject and issuer DN bytes.
/// That is a heuristic defence-in-depth screen, not a security boundary —
/// the Ed25519 signature check against the caller-supplied issuer key is the
/// real boundary. The heuristic has a known false positive: a certificate
/// legitimately issued by the authority for a caller-chosen subject equal to
/// the authority's hex-pubkey common name is rejected here even though its
/// signature would verify.
///
/// # Errors
///
/// Returns [`TrustError::CertificateParsing`] if `cert_der` cannot be parsed,
/// and [`TrustError::CertificateVerification`] if the certificate is
/// self-signed, is not Ed25519-signed, carries a malformed signature or
/// issuer key, the signature does not strictly verify, or `at` is outside
/// the validity window (the reason distinguishes `expired` from
/// `not yet valid` and names the violated boundary instant).
pub fn verify_certificate_chain_at(
    cert_der: &[u8],
    issuer_public_key: &[u8; 32],
    at: DateTime<Utc>,
) -> TrustResult<()> {
    let (_, certificate) =
        X509Certificate::from_der(cert_der).map_err(|e| TrustError::CertificateParsing {
            reason: format!("failed to parse certificate DER: {e:?}"),
        })?;

    // Heuristic screen only — see the rustdoc above. The signature check
    // below is the actual security boundary.
    if certificate.subject().as_raw() == certificate.issuer().as_raw() {
        return Err(TrustError::CertificateVerification {
            reason: "self-signed certificate rejected (issuer equals subject)".to_string(),
        });
    }

    if certificate.signature_algorithm.algorithm != OID_SIG_ED25519 {
        return Err(TrustError::CertificateVerification {
            reason: "certificate signature algorithm is not Ed25519".to_string(),
        });
    }

    let tbs = certificate.tbs_certificate.as_ref();
    let signature_bytes: &[u8] = &certificate.signature_value.data;
    let signature_array: &[u8; 64] =
        signature_bytes
            .try_into()
            .map_err(|_err| TrustError::CertificateVerification {
                reason: format!(
                    "certificate signature must be 64 bytes for Ed25519, got {}",
                    signature_bytes.len()
                ),
            })?;
    let signature = Signature::from_bytes(signature_array);

    let verifying_key = VerifyingKey::from_bytes(issuer_public_key).map_err(|_err| {
        TrustError::CertificateVerification {
            reason: "issuer public key is not a valid Ed25519 point".to_string(),
        }
    })?;

    verifying_key
        .verify_strict(tbs, &signature)
        .map_err(|_err| TrustError::CertificateVerification {
            reason: "certificate signature did not verify against the issuer public key"
                .to_string(),
        })?;

    check_validity_window(&certificate, at)
}

/// Rejects `at` instants outside the certificate's `notBefore`/`notAfter`
/// window (boundaries inclusive, per X.509 semantics).
fn check_validity_window(certificate: &X509Certificate<'_>, at: DateTime<Utc>) -> TrustResult<()> {
    let validity = certificate.validity();
    let not_before = datetime_from_asn1_timestamp(validity.not_before.timestamp(), "notBefore")?;
    let not_after = datetime_from_asn1_timestamp(validity.not_after.timestamp(), "notAfter")?;

    if at < not_before {
        return Err(TrustError::CertificateVerification {
            reason: format!(
                "certificate not yet valid: notBefore is {not_before}, checked at {at}"
            ),
        });
    }
    if at > not_after {
        return Err(TrustError::CertificateVerification {
            reason: format!("certificate expired: notAfter was {not_after}, checked at {at}"),
        });
    }
    Ok(())
}

/// Converts an ASN.1 validity timestamp (seconds since the Unix epoch) into a
/// chrono UTC instant.
fn datetime_from_asn1_timestamp(timestamp: i64, field: &str) -> TrustResult<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp(timestamp, 0).ok_or_else(|| TrustError::CertificateParsing {
        reason: format!(
            "certificate {field} timestamp {timestamp} is outside the representable date range"
        ),
    })
}

/// rcgen [`RemoteKeyPair`] adapter over an [`Ed25519Identity`].
///
/// Exposes the identity's public key and `sign` operation to rcgen without
/// revealing the private seed. Held behind an [`Arc`] so it satisfies rcgen's
/// `'static` boxed-trait requirement while sharing the authority's identity.
struct IdentitySigner {
    identity: Arc<Ed25519Identity>,
    public_key: Vec<u8>,
}

impl IdentitySigner {
    fn new(identity: Arc<Ed25519Identity>) -> Self {
        let public_key = identity.public_key_bytes().to_vec();
        Self {
            identity,
            public_key,
        }
    }
}

impl RemoteKeyPair for IdentitySigner {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(self.identity.sign(msg).to_vec())
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ED25519
    }
}

/// Builds a distinguished name carrying a single common-name component.
fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn
}

/// Converts a chrono UTC instant into the `time` type rcgen's validity fields
/// require, preserving second-granularity.
fn to_offset_date_time(instant: DateTime<Utc>) -> TrustResult<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(instant.timestamp()).map_err(|e| {
        TrustError::CertificateGeneration {
            reason: format!("certificate validity instant is out of range: {e}"),
        }
    })
}

#[cfg(test)]
#[path = "authority_tests.rs"]
mod tests;
