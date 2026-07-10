//! Self-contained transparency-log proof artifacts (the `lys` D2 wire
//! contract): JSON objects carrying an RFC 6962 proof plus the relevant
//! signed checkpoint(s) embedded verbatim.
//!
//! # Invariants
//!
//! - Artifact shapes are FROZEN wire contracts identified by their `format`
//!   strings ([`INCLUSION_PROOF_FORMAT`], [`CONSISTENCY_PROOF_FORMAT`]);
//!   evolving one means a new `v2` format string, never a mutation.
//!   Unknown fields are rejected (`deny_unknown_fields`).
//! - Redundancy is checked, not trusted: every size an artifact declares is
//!   compared against the size inside its embedded, signature-verified
//!   checkpoint, and the proof recomputes the root(s) against the
//!   checkpoint root(s). No artifact field is believed on its own.
//! - Builders SELF-VERIFY every artifact before returning it — a broken
//!   artifact is never silently emitted.
//! - Tree sizes at or beyond 2^53 ([`MAX_JSON_TREE_SIZE`]) are refused on
//!   emission and rejected on verification (JSON number precision bound).
//! - Verification of untrusted artifacts is non-oracle: every failure —
//!   kind confusion, size mismatch, malformed hashes, bad checkpoint, root
//!   mismatch — collapses to the single
//!   [`TrustError::LogArtifactVerification`] value.
//!
//! [`TrustError::LogArtifactVerification`]: crate::error::TrustError::LogArtifactVerification

pub mod artifact;
pub mod build;
pub mod verify;

pub use artifact::{
    CONSISTENCY_PROOF_FORMAT, ConsistencyProofArtifact, INCLUSION_PROOF_FORMAT,
    InclusionProofArtifact, MAX_JSON_TREE_SIZE,
};
pub use build::{build_consistency_artifact, build_inclusion_artifact};
pub use verify::{verify_consistency_artifact, verify_inclusion_artifact};
