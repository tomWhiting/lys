//! Authenticated sealed envelope: composition of [`super::seal`] with a
//! sender [`Attestation`] over the context-tagged sealed envelope bytes.
//!
//! [`sign_and_seal`] seals the payload for the recipient first, then signs
//! an attestation over `SEALED_ENVELOPE_CONTEXT_V1 || ephemeral_public_key
//! || ciphertext || nonce` with the sender's Ed25519 identity. The returned
//! tuple is the sealed envelope and the attestation that proves the envelope
//! came from that specific sender.
//!
//! The context prefix exists because attestations are a generic primitive:
//! without it, an attestation a sender legitimately produced over some other
//! payload that happened to equal a sealed envelope's canonical bytes could
//! be replayed as an envelope attestation (and vice versa). Prefixing the
//! attested message with a construction-specific tag binds the attestation
//! to *this* composition, so a signature only ever means "this sender sealed
//! this envelope" — never anything a generic attestation could be confused
//! with.
//!
//! [`open_and_verify`] inverts the composition: it checks that the
//! attestation's embedded signer key matches the expected sender public key,
//! verifies the signature against the context-tagged sealed-envelope bytes,
//! and only then unseals. Failure of either attestation step short-circuits with
//! [`TrustError::AttestationFailed`] — the recipient never decrypts a
//! payload it cannot bind to a sender, which closes the substitution
//! oracle that bare [`super::seal`] necessarily leaves open.
//!
//! The standalone [`super::seal`] and [`super::open`] primitives remain
//! available for broadcast or anonymous use cases. Authenticated sealing is
//! a strict superset, not a replacement.

use x25519_dalek::StaticSecret;

use crate::attestation::envelope::Attestation;
use crate::attestation::sign::{sign_attestation, verify_attestation};
use crate::error::{TrustError, TrustResult};
use crate::keys::identity::Ed25519Identity;
use crate::seal::sealed_envelope::{SealedEnvelope, open, seal};

/// Context tag prefixed to the sealed-envelope bytes before attestation.
///
/// Binds the sender's attestation to the authenticated-seal composition
/// specifically. A generic [`sign_attestation`] over arbitrary bytes that
/// happen to match an envelope's canonical encoding cannot be replayed as
/// an envelope attestation, because it lacks this prefix; likewise an
/// envelope attestation cannot be presented as an attestation over some
/// other payload. Versioned so a future change to the attested message can
/// rotate the tag unambiguously.
const SEALED_ENVELOPE_CONTEXT_V1: &[u8] = b"lys/sealed-envelope/v1";

/// Build the attested message for `envelope`:
/// `SEALED_ENVELOPE_CONTEXT_V1 || ephemeral_public_key || ciphertext ||
/// nonce`.
///
/// Shared by [`sign_and_seal`] and [`open_and_verify`] so signer and
/// verifier can never drift apart.
fn contextualized_envelope_bytes(envelope: &SealedEnvelope) -> Vec<u8> {
    let envelope_bytes = envelope.attestation_bytes();
    let mut message = Vec::with_capacity(SEALED_ENVELOPE_CONTEXT_V1.len() + envelope_bytes.len());
    message.extend_from_slice(SEALED_ENVELOPE_CONTEXT_V1);
    message.extend_from_slice(&envelope_bytes);
    message
}

/// Seal `payload` for the recipient's X25519 public key and sign the
/// resulting envelope with `sender_identity`, returning the pair.
///
/// The attestation covers `SEALED_ENVELOPE_CONTEXT_V1 ||
/// ephemeral_public_key || ciphertext || nonce` — a construction-specific
/// context tag followed by every byte that travels with the envelope.
/// Signing the canonical sealed-envelope bytes (rather than the plaintext)
/// means the sender commits to the exact ciphertext the recipient receives;
/// an adversary cannot replay or substitute parts of the envelope without
/// invalidating the signature. The context tag prevents a generic
/// attestation the sender produced elsewhere from being confused with an
/// envelope attestation (see the module docs).
///
/// # Errors
///
/// Returns whatever [`seal`] returns ([`TrustError::Seal`] on a low-order
/// recipient public key, AES-GCM failure, or HKDF failure).
/// [`sign_attestation`] is itself infallible (see the attestation module
/// docs), so the only error path is through `seal`.
pub fn sign_and_seal(
    payload: &[u8],
    sender_identity: &Ed25519Identity,
    recipient_x25519_public_key: &[u8; 32],
) -> TrustResult<(SealedEnvelope, Attestation)> {
    let envelope = seal(payload, recipient_x25519_public_key)?;
    let attestation = sign_attestation(&contextualized_envelope_bytes(&envelope), sender_identity);
    Ok((envelope, attestation))
}

/// Verify that `attestation` was produced by `sender_public_key` over
/// `envelope` and, only on success, unseal the envelope with
/// `recipient_x25519_secret`.
///
/// Verification is two gates in strict order:
///
/// 1. The attestation's embedded signer public key must equal
///    `sender_public_key`. This rejects forgeries where an adversary signs a
///    valid sealed envelope with their own key and hopes the recipient
///    accepts it.
/// 2. The attestation signature must verify against the context-tagged
///    sealed-envelope bytes (`SEALED_ENVELOPE_CONTEXT_V1 || canonical
///    envelope bytes`), so only attestations produced for this composition
///    are accepted — a generic attestation over the bare envelope bytes is
///    rejected.
///
/// Either failure returns [`TrustError::AttestationFailed`] *before* the
/// AES-GCM cipher is touched, so the recipient is not an unsealing oracle
/// for envelopes whose sender cannot be verified.
///
/// # Errors
///
/// - [`TrustError::AttestationFailed`] if the embedded signer key does not
///   match `sender_public_key`, or the signature does not verify against
///   the context-tagged sealed-envelope bytes.
/// - [`TrustError::UnsealFailed`] if the attestation verifies but the
///   ciphertext or nonce fail AES-GCM authentication (tampering after
///   signing is structurally impossible since the signature covers
///   nonce + ciphertext + ephemeral key, but the unseal error is still
///   reported for completeness).
pub fn open_and_verify(
    envelope: &SealedEnvelope,
    attestation: &Attestation,
    sender_public_key: &[u8; 32],
    recipient_x25519_secret: &StaticSecret,
) -> TrustResult<Vec<u8>> {
    if attestation.signer_public_key != *sender_public_key {
        return Err(TrustError::AttestationFailed);
    }
    verify_attestation(attestation, &contextualized_envelope_bytes(envelope))
        .map_err(|_err| TrustError::AttestationFailed)?;
    open(envelope, recipient_x25519_secret)
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
    fn sign_and_seal_returns_envelope_and_attestation() {
        let sender = identity();
        let recipient = identity();
        let payload = b"authenticated credential bundle";
        let (env, att) = sign_and_seal(payload, &sender, &recipient.x25519_public_key()).unwrap();
        assert_eq!(att.signer_public_key, sender.public_key_bytes());
        assert_eq!(env.ciphertext.len(), payload.len() + 16);
    }

    #[test]
    fn open_and_verify_returns_payload_for_correct_sender() {
        let sender = identity();
        let recipient = identity();
        let payload = b"audit-bound payload";
        let (env, att) = sign_and_seal(payload, &sender, &recipient.x25519_public_key()).unwrap();
        let opened = open_and_verify(
            &env,
            &att,
            &sender.public_key_bytes(),
            &recipient.x25519_static_secret(),
        )
        .unwrap();
        assert_eq!(opened.as_slice(), payload);
    }

    #[test]
    fn wrong_sender_public_key_returns_attestation_failed_without_unsealing() {
        let sender = identity();
        let imposter = identity();
        let recipient = identity();
        let (env, att) =
            sign_and_seal(b"payload", &sender, &recipient.x25519_public_key()).unwrap();
        let err = open_and_verify(
            &env,
            &att,
            &imposter.public_key_bytes(),
            &recipient.x25519_static_secret(),
        )
        .unwrap_err();
        assert!(matches!(err, TrustError::AttestationFailed));
    }

    #[test]
    fn tampered_attestation_signature_returns_attestation_failed() {
        let sender = identity();
        let recipient = identity();
        let (env, mut att) =
            sign_and_seal(b"payload", &sender, &recipient.x25519_public_key()).unwrap();
        att.signature[0] ^= 0x01;
        let err = open_and_verify(
            &env,
            &att,
            &sender.public_key_bytes(),
            &recipient.x25519_static_secret(),
        )
        .unwrap_err();
        assert!(matches!(err, TrustError::AttestationFailed));
    }

    #[test]
    fn forged_signer_key_in_attestation_returns_attestation_failed() {
        let sender = identity();
        let imposter = identity();
        let recipient = identity();
        let (env, mut att) =
            sign_and_seal(b"payload", &sender, &recipient.x25519_public_key()).unwrap();
        // Adversary swaps in their own public key claiming the signature is
        // theirs. The two-step gate must reject this — first the explicit
        // key comparison would pass (we now ask to verify against the
        // imposter's key), but the signature was produced by `sender` over
        // the original hash, so verification against `imposter` fails.
        att.signer_public_key = imposter.public_key_bytes();
        let err = open_and_verify(
            &env,
            &att,
            &imposter.public_key_bytes(),
            &recipient.x25519_static_secret(),
        )
        .unwrap_err();
        assert!(matches!(err, TrustError::AttestationFailed));
    }

    #[test]
    fn tampered_envelope_after_signing_returns_attestation_failed() {
        let sender = identity();
        let recipient = identity();
        let (mut env, att) =
            sign_and_seal(b"payload", &sender, &recipient.x25519_public_key()).unwrap();
        env.ciphertext[0] ^= 0x01;
        let err = open_and_verify(
            &env,
            &att,
            &sender.public_key_bytes(),
            &recipient.x25519_static_secret(),
        )
        .unwrap_err();
        // The attestation covers the envelope bytes, so a post-signing
        // tamper is rejected at the attestation gate, not the AES-GCM gate.
        assert!(matches!(err, TrustError::AttestationFailed));
    }

    #[test]
    fn generic_attestation_over_bare_envelope_bytes_is_rejected() {
        // Context binding: an attestation the sender produced with the
        // generic primitive over the envelope's canonical bytes (no context
        // tag) must not be accepted by the authenticated composition.
        let sender = identity();
        let recipient = identity();
        let (env, _att) =
            sign_and_seal(b"payload", &sender, &recipient.x25519_public_key()).unwrap();
        let generic = crate::attestation::sign::sign_attestation(&env.attestation_bytes(), &sender);
        let err = open_and_verify(
            &env,
            &generic,
            &sender.public_key_bytes(),
            &recipient.x25519_static_secret(),
        )
        .unwrap_err();
        assert!(matches!(err, TrustError::AttestationFailed));
    }

    #[test]
    fn standalone_seal_and_open_still_work() {
        // The composed API is a strict superset; the standalone primitives
        // must remain functional and unrelated — `seal`/`open` are not
        // replaced by the authenticated composition.
        let recipient = identity();
        let env = seal(b"anonymous", &recipient.x25519_public_key()).unwrap();
        let opened = open(&env, &recipient.x25519_static_secret()).unwrap();
        assert_eq!(opened.as_slice(), b"anonymous");
    }
}
