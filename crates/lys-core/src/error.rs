//! [`TrustError`] and the crate-wide [`TrustResult`] alias.
//!
//! Every fallible public API on the trust primitives returns
//! `TrustResult<T>`. Each variant names a distinct trust operation, and every
//! `Display` string carries the operation name so callers can surface a
//! precise diagnostic without parsing free-form text. Variants that carry a
//! dynamic cause use a `reason: String` field; signature verification has a
//! dedicated parameterless variant so callers can match it structurally
//! rather than by string.

/// Errors returned from the trust primitives.
///
/// Variants are grouped by operation: certificate lifecycle (generation,
/// parsing, verification, revocation), the Merkle transparency log, sealed
/// payload transport (seal/unseal), key management, signing, and the
/// dedicated signature-verification failure.
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    /// Generating a certificate failed.
    #[error("certificate generation failed: {reason}")]
    CertificateGeneration {
        /// Human-readable cause of the generation failure.
        reason: String,
    },

    /// Parsing a certificate or extracting one of its fields failed.
    #[error("certificate parsing failed: {reason}")]
    CertificateParsing {
        /// Human-readable cause of the parsing failure.
        reason: String,
    },

    /// Verifying a certificate chain failed.
    #[error("certificate verification failed: {reason}")]
    CertificateVerification {
        /// Human-readable cause of the verification failure.
        reason: String,
    },

    /// A certificate revocation operation failed.
    ///
    /// Reserved for consumer-side operations: revocation tracking is
    /// explicitly a consumer concern (a design non-goal for this crate), so
    /// this crate never constructs the variant itself. It exists so
    /// consumers implementing revocation stores can surface failures through
    /// the shared [`TrustError`] type.
    #[error("certificate revocation failed: {reason}")]
    CertificateRevocation {
        /// Human-readable cause of the revocation failure.
        reason: String,
    },

    /// A Merkle transparency-log operation failed.
    #[error("merkle tree operation failed: {reason}")]
    MerkleTree {
        /// Human-readable cause of the Merkle operation failure.
        reason: String,
    },

    /// Sealing a payload for a recipient failed.
    #[error("seal failed: {reason}")]
    Seal {
        /// Human-readable cause of the seal failure.
        reason: String,
    },

    /// Unsealing failed — deliberately omits the cause so callers cannot
    /// distinguish wrong-key from tampered-ciphertext (non-oracle).
    #[error("unseal failed")]
    UnsealFailed,

    /// Attestation verification failed — the sender's public key did not
    /// match, or the signature over the sealed payload was invalid.
    #[error("attestation verification failed")]
    AttestationFailed,

    /// A key-management operation failed: file I/O, environment loading,
    /// base64 decoding, or key-material length validation.
    #[error("key management failed: {reason}")]
    KeyManagement {
        /// Human-readable cause of the key-management failure.
        reason: String,
    },

    /// Producing a signature failed.
    ///
    /// Reserved for consumer-side signing pipelines. This crate's own
    /// Ed25519 signing is infallible (dalek 2 deterministic signing), so the
    /// crate never constructs the variant itself; consumers whose signing
    /// paths can fail (HSMs, remote signers, key lookups) surface those
    /// failures through it.
    #[error("signing failed: {reason}")]
    Signing {
        /// Human-readable cause of the signing failure.
        reason: String,
    },

    /// A signature failed verification, or the supplied signature or public
    /// key bytes were structurally invalid.
    #[error("invalid signature")]
    InvalidSignature,

    /// Building or encoding a checkpoint or signed note failed (invalid
    /// origin or key name, malformed body).
    #[error("checkpoint encoding failed: {reason}")]
    CheckpointEncoding {
        /// Human-readable cause of the encoding failure.
        reason: String,
    },

    /// Parsing a checkpoint body failed. Used on already-verified body text
    /// and operator-supplied text; artifact verification collapses it
    /// (non-oracle).
    #[error("checkpoint parsing failed: {reason}")]
    CheckpointParsing {
        /// Human-readable cause of the parsing failure.
        reason: String,
    },

    /// A note verifier key string was malformed or internally inconsistent.
    /// Trusted operator input — carries an actionable reason.
    #[error("invalid note verifier key: {reason}")]
    VerifierKey {
        /// Human-readable cause of the verifier-key failure.
        reason: String,
    },

    /// A signed note failed verification — deliberately omits the cause so
    /// callers cannot distinguish malformed envelope, unknown key, or bad
    /// signature (non-oracle).
    #[error("note verification failed")]
    NoteVerification,

    /// Building a log proof artifact failed (tree too large for JSON-safe
    /// integers, size/index invariant violations at build time).
    #[error("log artifact encoding failed: {reason}")]
    LogArtifactEncoding {
        /// Human-readable cause of the encoding failure.
        reason: String,
    },

    /// A log proof artifact failed verification — deliberately omits the
    /// cause (non-oracle): bad checkpoint signature, size mismatch, root
    /// mismatch, malformed hashes, and kind confusion are indistinguishable.
    #[error("log artifact verification failed")]
    LogArtifactVerification,
}

/// Convenience alias for `Result<T, TrustError>`.
pub type TrustResult<T> = std::result::Result<T, TrustError>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn display_certificate_generation() {
        let err = TrustError::CertificateGeneration {
            reason: "rcgen rejected params".to_string(),
        };
        let display = err.to_string();
        assert!(
            display.contains("certificate generation failed"),
            "got: {display}"
        );
        assert!(display.contains("rcgen rejected params"), "got: {display}");
    }

    #[test]
    fn display_certificate_parsing() {
        let err = TrustError::CertificateParsing {
            reason: "malformed DER".to_string(),
        };
        let display = err.to_string();
        assert!(
            display.contains("certificate parsing failed"),
            "got: {display}"
        );
        assert!(display.contains("malformed DER"), "got: {display}");
    }

    #[test]
    fn display_certificate_verification() {
        let err = TrustError::CertificateVerification {
            reason: "issuer mismatch".to_string(),
        };
        let display = err.to_string();
        assert!(
            display.contains("certificate verification failed"),
            "got: {display}"
        );
        assert!(display.contains("issuer mismatch"), "got: {display}");
    }

    #[test]
    fn display_certificate_revocation() {
        let err = TrustError::CertificateRevocation {
            reason: "unknown fingerprint".to_string(),
        };
        let display = err.to_string();
        assert!(
            display.contains("certificate revocation failed"),
            "got: {display}"
        );
        assert!(display.contains("unknown fingerprint"), "got: {display}");
    }

    #[test]
    fn display_merkle_tree() {
        let err = TrustError::MerkleTree {
            reason: "index out of range".to_string(),
        };
        let display = err.to_string();
        assert!(
            display.contains("merkle tree operation failed"),
            "got: {display}"
        );
        assert!(display.contains("index out of range"), "got: {display}");
    }

    #[test]
    fn display_seal() {
        let err = TrustError::Seal {
            reason: "HKDF expand failed".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("seal failed"), "got: {display}");
        assert!(display.contains("HKDF expand failed"), "got: {display}");
    }

    #[test]
    fn display_key_management() {
        let err = TrustError::KeyManagement {
            reason: "identity key file has invalid length".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("key management failed"), "got: {display}");
        assert!(
            display.contains("identity key file has invalid length"),
            "got: {display}"
        );
    }

    #[test]
    fn display_signing() {
        let err = TrustError::Signing {
            reason: "no signing key configured".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("signing failed"), "got: {display}");
        assert!(
            display.contains("no signing key configured"),
            "got: {display}"
        );
    }

    #[test]
    fn display_unseal_failed() {
        let err = TrustError::UnsealFailed;
        let display = err.to_string();
        assert!(display.contains("unseal failed"), "got: {display}");
    }

    #[test]
    fn display_attestation_failed() {
        let err = TrustError::AttestationFailed;
        let display = err.to_string();
        assert!(
            display.contains("attestation verification failed"),
            "got: {display}"
        );
    }

    #[test]
    fn display_invalid_signature() {
        let err = TrustError::InvalidSignature;
        let display = err.to_string();
        assert!(display.contains("invalid signature"), "got: {display}");
    }

    #[test]
    fn display_checkpoint_encoding() {
        let err = TrustError::CheckpointEncoding {
            reason: "origin contains '+'".to_string(),
        };
        let display = err.to_string();
        assert!(
            display.contains("checkpoint encoding failed"),
            "got: {display}"
        );
        assert!(display.contains("origin contains '+'"), "got: {display}");
    }

    #[test]
    fn display_checkpoint_parsing() {
        let err = TrustError::CheckpointParsing {
            reason: "tree size has a leading zero".to_string(),
        };
        let display = err.to_string();
        assert!(
            display.contains("checkpoint parsing failed"),
            "got: {display}"
        );
        assert!(
            display.contains("tree size has a leading zero"),
            "got: {display}"
        );
    }

    #[test]
    fn display_verifier_key() {
        let err = TrustError::VerifierKey {
            reason: "declared key ID does not match".to_string(),
        };
        let display = err.to_string();
        assert!(
            display.contains("invalid note verifier key"),
            "got: {display}"
        );
        assert!(
            display.contains("declared key ID does not match"),
            "got: {display}"
        );
    }

    /// Non-oracle: the note-verification failure string is a single generic
    /// message that never distinguishes a malformed envelope from an unknown
    /// key from a bad signature.
    #[test]
    fn note_verification_display_is_single_and_generic() {
        let display = TrustError::NoteVerification.to_string();
        assert_eq!(display, "note verification failed");
        for oracle_word in ["signature", "key", "envelope", "structure", "base64"] {
            assert!(
                !display.contains(oracle_word),
                "non-oracle message must not mention {oracle_word}: {display}"
            );
        }
    }

    #[test]
    fn display_log_artifact_encoding() {
        let err = TrustError::LogArtifactEncoding {
            reason: "tree size exceeds the JSON-safe bound".to_string(),
        };
        let display = err.to_string();
        assert!(
            display.contains("log artifact encoding failed"),
            "got: {display}"
        );
        assert!(
            display.contains("tree size exceeds the JSON-safe bound"),
            "got: {display}"
        );
    }

    /// Non-oracle: the artifact-verification failure string is a single
    /// generic message that never distinguishes checkpoint, size, root,
    /// hash, or kind failures.
    #[test]
    fn log_artifact_verification_display_is_single_and_generic() {
        let display = TrustError::LogArtifactVerification.to_string();
        assert_eq!(display, "log artifact verification failed");
        for oracle_word in ["signature", "checkpoint", "root", "size", "hash", "format"] {
            assert!(
                !display.contains(oracle_word),
                "non-oracle message must not mention {oracle_word}: {display}"
            );
        }
    }

    #[test]
    fn trust_result_alias_accepts_ok_and_err() {
        let ok: TrustResult<u8> = Ok(7);
        let err: TrustResult<u8> = Err(TrustError::InvalidSignature);
        assert!(ok.is_ok());
        assert!(err.is_err());
    }
}
