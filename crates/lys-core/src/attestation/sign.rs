//! Sign and verify [`Attestation`] envelopes over arbitrary payload bytes.
//!
//! [`sign_attestation`] hashes the payload with SHA-256, captures the current
//! unix-millisecond timestamp, and signs a domain-separated preimage with the
//! supplied [`Ed25519Identity`]:
//!
//! ```text
//! preimage = ATTESTATION_DOMAIN_V1 || timestamp.to_le_bytes() || payload_hash
//! ```
//!
//! [`verify_attestation`] recomputes the digest of the candidate payload,
//! compares it against `attestation.payload_hash`, reconstructs the preimage
//! from the attestation's own timestamp and payload hash, and verifies the
//! Ed25519 signature against `attestation.signer_public_key`. Any mismatch —
//! wrong payload, tampered signature, tampered timestamp, or wrong signer
//! key — collapses to [`TrustError::InvalidSignature`].
//!
//! Verification is v1-only: the domain-separated preimage above is the sole
//! accepted signing scheme. A signature over anything else — including a
//! bare 32-byte payload hash with no domain tag or timestamp — is rejected.
//! There is no fallback path.
//!
//! Two properties fall out of the preimage construction:
//!
//! - **The timestamp is authenticated.** Because the signature covers the
//!   little-endian timestamp bytes, an adversary cannot alter `timestamp`
//!   after signing without invalidating the signature.
//! - **Domain separation.** The `ATTESTATION_DOMAIN_V1` prefix ensures an
//!   attestation signature can never be confused with a signature produced
//!   in any other lys-core signing context, nor with a raw
//!   [`Ed25519Identity::sign`] over attacker-chosen bytes. The raw
//!   `Ed25519Identity::sign` primitive itself stays unprefixed by necessity:
//!   the CA path signs exact X.509 TBS bytes through it, and those bytes must
//!   not be altered. Any raw-sign caller whose message could start with the
//!   domain tag would need its own separation; within this crate no such
//!   caller exists.
//!
//! The signed quantity embeds the 32-byte hash, not the raw payload. This
//! keeps the signing input fixed-size and uniform regardless of payload
//! length. Consumers that need to attest to large payloads pass the bytes
//! once and let `sign_attestation` produce the canonical hash.

use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::attestation::envelope::Attestation;
use crate::error::{TrustError, TrustResult};
use crate::keys::identity::Ed25519Identity;

/// Domain-separation tag prepended to every attestation signing preimage.
///
/// Versioned so a future preimage change can rotate the tag without
/// ambiguity. Prevents cross-protocol confusion between attestation
/// signatures and signatures produced by other lys-core contexts
/// (or raw [`Ed25519Identity::sign`] calls such as the CA's X.509 TBS
/// signing).
const ATTESTATION_DOMAIN_V1: &[u8] = b"lys/attestation/v1";

/// Length of the signing preimage: domain tag + 8-byte timestamp + 32-byte
/// payload hash.
const PREIMAGE_LEN: usize = ATTESTATION_DOMAIN_V1.len() + 8 + 32;

/// Hash `payload` with SHA-256, capture the current timestamp, sign the
/// domain-separated preimage with `signing_key`, and package the result as
/// an [`Attestation`].
///
/// The signature covers `ATTESTATION_DOMAIN_V1 || timestamp.to_le_bytes()
/// || payload_hash`, so both the digest and the timestamp are authenticated.
/// The returned envelope carries the SHA-256 digest, the Ed25519 detached
/// signature over that preimage, the signer's public key, and the
/// unix-millisecond timestamp that was signed. The original payload bytes
/// are not stored on the envelope.
///
/// `sign_attestation` is infallible: `Utc::now().timestamp_millis()` is
/// total over the representable date range and Ed25519 deterministic
/// signing has no failure mode in dalek 2.
pub fn sign_attestation(payload: &[u8], signing_key: &Ed25519Identity) -> Attestation {
    let payload_hash = sha256_digest(payload);
    let timestamp = Utc::now().timestamp_millis();
    let preimage = signing_preimage(timestamp, &payload_hash);
    let signature = signing_key.sign(&preimage);
    let signer_public_key = signing_key.public_key_bytes();
    Attestation {
        payload_hash,
        signature,
        signer_public_key,
        timestamp,
    }
}

/// Verify that `attestation` is a valid signature over `payload` and the
/// attestation's own timestamp by `attestation.signer_public_key`.
///
/// The check is two-step: the SHA-256 digest of `payload` must equal
/// `attestation.payload_hash`, and the Ed25519 signature must verify against
/// the embedded public key over the reconstructed preimage
/// `ATTESTATION_DOMAIN_V1 || attestation.timestamp.to_le_bytes() ||
/// attestation.payload_hash`. Because the preimage is rebuilt from the
/// attestation's own timestamp field, a tampered timestamp fails signature
/// verification. All failures collapse to [`TrustError::InvalidSignature`]
/// so callers cannot distinguish them by error variant — a tampered payload,
/// a tampered timestamp, and a forged signature all look the same to the
/// verifier, which is the desired property.
///
/// Verification is v1-only: only signatures over the domain-separated v1
/// preimage are accepted. A signature over the bare payload hash (no domain
/// tag, no timestamp) is rejected like any other invalid signature.
///
/// # Errors
///
/// Returns [`TrustError::InvalidSignature`] if the recomputed payload hash
/// does not match `attestation.payload_hash`, if the public key is not a
/// valid Ed25519 point, or if the signature does not verify over the v1
/// preimage (covering tampered signature bytes and tampered timestamps
/// alike).
pub fn verify_attestation(attestation: &Attestation, payload: &[u8]) -> TrustResult<()> {
    let recomputed = sha256_digest(payload);
    if recomputed != attestation.payload_hash {
        return Err(TrustError::InvalidSignature);
    }
    let preimage = signing_preimage(attestation.timestamp, &attestation.payload_hash);
    Ed25519Identity::verify(
        &attestation.signer_public_key,
        &preimage,
        &attestation.signature,
    )
}

/// Build the domain-separated signing preimage:
/// `ATTESTATION_DOMAIN_V1 || timestamp.to_le_bytes() || payload_hash`.
///
/// Shared by [`sign_attestation`] and [`verify_attestation`] so the two
/// sides can never drift apart.
fn signing_preimage(timestamp: i64, payload_hash: &[u8; 32]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(PREIMAGE_LEN);
    preimage.extend_from_slice(ATTESTATION_DOMAIN_V1);
    preimage.extend_from_slice(&timestamp.to_le_bytes());
    preimage.extend_from_slice(payload_hash);
    preimage
}

/// SHA-256 digest of `bytes` as a fixed-size 32-byte array.
fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn identity() -> Ed25519Identity {
        let dir = tempdir().unwrap();
        Ed25519Identity::load_or_generate(&dir.path().join("id.key")).unwrap()
    }

    #[test]
    fn sign_attestation_populates_envelope_fields() {
        let id = identity();
        let payload = b"execution receipt v1";
        let att = sign_attestation(payload, &id);

        let expected = sha256_digest(payload);
        assert_eq!(att.payload_hash, expected);
        assert_eq!(att.signer_public_key, id.public_key_bytes());
        assert_eq!(att.signature.len(), 64);
        assert!(
            att.timestamp > 0,
            "timestamp should be a positive unix-millisecond value, got {}",
            att.timestamp
        );
    }

    #[test]
    fn verify_attestation_accepts_valid_signature() {
        let id = identity();
        let payload = b"audit entry payload";
        let att = sign_attestation(payload, &id);
        verify_attestation(&att, payload).unwrap();
    }

    #[test]
    fn verify_attestation_rejects_tampered_payload() {
        let id = identity();
        let payload = b"original";
        let att = sign_attestation(payload, &id);
        let tampered = b"originaL";
        let err = verify_attestation(&att, tampered).unwrap_err();
        assert!(matches!(err, TrustError::InvalidSignature));
    }

    #[test]
    fn verify_attestation_rejects_tampered_signature() {
        let id = identity();
        let payload = b"payload";
        let mut att = sign_attestation(payload, &id);
        att.signature[0] ^= 0x01;
        let err = verify_attestation(&att, payload).unwrap_err();
        assert!(matches!(err, TrustError::InvalidSignature));
    }

    #[test]
    fn verify_attestation_rejects_tampered_timestamp() {
        let id = identity();
        let payload = b"timestamped payload";
        let mut att = sign_attestation(payload, &id);
        // The timestamp is part of the signed preimage — shifting it by one
        // millisecond must invalidate the signature.
        att.timestamp += 1;
        let err = verify_attestation(&att, payload).unwrap_err();
        assert!(matches!(err, TrustError::InvalidSignature));
    }

    #[test]
    fn verify_attestation_rejects_wrong_signer_key() {
        let id_a = identity();
        let id_b = identity();
        let payload = b"payload";
        let mut att = sign_attestation(payload, &id_a);
        // Swap in a different (valid) public key — the signature was produced
        // by id_a, so verification against id_b must fail.
        att.signer_public_key = id_b.public_key_bytes();
        let err = verify_attestation(&att, payload).unwrap_err();
        assert!(matches!(err, TrustError::InvalidSignature));
    }

    #[test]
    fn attestation_signature_differs_from_raw_sign_over_hash() {
        // Domain separation: an attestation signature is never the same as a
        // raw Ed25519 signature over the bare payload hash, so the two
        // signing contexts cannot be confused.
        let id = identity();
        let payload = b"domain separated";
        let att = sign_attestation(payload, &id);
        let raw = id.sign(&att.payload_hash);
        assert_ne!(att.signature, raw);
    }

    #[test]
    fn bare_hash_signed_attestation_is_rejected() {
        // v1-only verification: an envelope whose signature covers only the
        // bare 32-byte payload hash (no domain tag, no timestamp) must be
        // rejected — there is no fallback to any pre-domain-separation
        // scheme in lys-core.
        let id = identity();
        let payload = b"bare hash signed";
        let payload_hash = sha256_digest(payload);
        let att = Attestation {
            payload_hash,
            signature: id.sign(&payload_hash),
            signer_public_key: id.public_key_bytes(),
            timestamp: 1_700_000_000_000,
        };
        let err = verify_attestation(&att, payload).unwrap_err();
        assert!(matches!(err, TrustError::InvalidSignature));
    }

    #[test]
    fn attestation_round_trips_through_serde_postcard() {
        let id = identity();
        let payload = b"persisted attestation";
        let att = sign_attestation(payload, &id);
        let bytes = postcard::to_allocvec(&att).unwrap();
        let restored: Attestation = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored, att);
        verify_attestation(&restored, payload).unwrap();
    }

    #[test]
    fn empty_payload_signs_and_verifies() {
        let id = identity();
        let att = sign_attestation(&[], &id);
        verify_attestation(&att, &[]).unwrap();
        // The empty-string SHA-256 digest is well-known.
        let expected: [u8; 32] = sha256_digest(&[]);
        assert_eq!(att.payload_hash, expected);
    }
}
