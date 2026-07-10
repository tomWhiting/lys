//! Verification of untrusted D2 proof artifacts — the cross-check engine
//! a third party runs.
//!
//! # Invariants
//!
//! - Every listed check is MANDATORY and every failure collapses to the
//!   single non-oracle [`TrustError::LogArtifactVerification`] value: kind
//!   confusion, size guards, malformed hashes, checkpoint signature
//!   failures, origin-binding failures, redundancy mismatches, and root
//!   recomputation failures are indistinguishable to the caller.
//! - Redundancy is checked, not trusted: declared sizes must equal the
//!   sizes inside the signature-verified embedded checkpoint(s), and the
//!   proof recomputes the root(s) against the checkpoint root(s).
//! - Defensive caps bound hostile-input work: at most 64 inclusion-path
//!   nodes / 128 consistency nodes (both far beyond any tree below the
//!   2^53 guard, so no legitimate artifact is ever touched).
//!
//! [`TrustError::LogArtifactVerification`]: crate::error::TrustError::LogArtifactVerification

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::checkpoint::{CheckpointBody, NoteVerifierKey, verify_checkpoint};
use crate::error::{TrustError, TrustResult};
use crate::merkle::{ConsistencyProof, InclusionProof, verify_consistency, verify_inclusion_raw};

use super::artifact::{
    CONSISTENCY_PROOF_FORMAT, ConsistencyProofArtifact, INCLUSION_PROOF_FORMAT,
    InclusionProofArtifact, MAX_JSON_TREE_SIZE,
};

/// Defensive cap on inclusion-path nodes: an inclusion path in a tree
/// below the 2^53 guard has at most 53 nodes.
const MAX_INCLUSION_HASHES: usize = 64;

/// Defensive cap on consistency-proof nodes: a consistency proof between
/// trees below the 2^53 guard has at most ~2×53 nodes.
const MAX_CONSISTENCY_HASHES: usize = 128;

/// Verifies an untrusted inclusion artifact against the verifier key and
/// the RAW leaf bytes held by the caller; returns the verified checkpoint
/// body (origin, tree size, root) on success.
///
/// Checks, in order: `format` kind binding; `tree_size` below 2^53;
/// `leaf_index < tree_size`; hash count cap and exact 32-byte canonical
/// base64 nodes; embedded-checkpoint signature and origin binding;
/// `checkpoint tree size == artifact tree_size` (redundancy checked, not
/// trusted); and RFC 6962 root recomputation from the leaf bytes and path
/// against the checkpoint root.
///
/// # Errors
///
/// Returns [`TrustError::LogArtifactVerification`] on every failure
/// (non-oracle).
pub fn verify_inclusion_artifact(
    artifact: &InclusionProofArtifact,
    leaf_bytes: &[u8],
    verifier: &NoteVerifierKey,
) -> TrustResult<CheckpointBody> {
    if artifact.format != INCLUSION_PROOF_FORMAT {
        return Err(TrustError::LogArtifactVerification);
    }
    if artifact.tree_size >= MAX_JSON_TREE_SIZE {
        return Err(TrustError::LogArtifactVerification);
    }
    if artifact.leaf_index >= artifact.tree_size {
        return Err(TrustError::LogArtifactVerification);
    }
    if artifact.hashes.len() > MAX_INCLUSION_HASHES {
        return Err(TrustError::LogArtifactVerification);
    }
    let proof_bytes = decode_hashes(&artifact.hashes)?;
    let body = verify_checkpoint(artifact.checkpoint.as_bytes(), verifier)
        .map_err(|_err| TrustError::LogArtifactVerification)?;
    if body.tree_size() != artifact.tree_size {
        return Err(TrustError::LogArtifactVerification);
    }
    let proof = InclusionProof::try_from_bytes(proof_bytes)
        .map_err(|_err| TrustError::LogArtifactVerification)?;
    verify_inclusion_raw(&body.to_root(), leaf_bytes, artifact.leaf_index, &proof)
        .map_err(|_err| TrustError::LogArtifactVerification)?;
    Ok(body)
}

/// Verifies an untrusted consistency artifact against the verifier key;
/// returns the two verified checkpoint bodies `(old, new)` on success.
///
/// Checks, in order: `format` kind binding;
/// `1 <= tree_size_1 < tree_size_2 < 2^53`; hash count cap and exact
/// 32-byte canonical base64 nodes; BOTH embedded checkpoints
/// signature-verified under the SAME verifier (each origin equals the
/// verifier name, so the two origins are equal — origin substitution
/// dead); both checkpoint tree sizes equal to the declared sizes; and
/// RFC 6962 consistency recomputation of BOTH roots against the checkpoint
/// roots.
///
/// # Errors
///
/// Returns [`TrustError::LogArtifactVerification`] on every failure
/// (non-oracle).
pub fn verify_consistency_artifact(
    artifact: &ConsistencyProofArtifact,
    verifier: &NoteVerifierKey,
) -> TrustResult<(CheckpointBody, CheckpointBody)> {
    if artifact.format != CONSISTENCY_PROOF_FORMAT {
        return Err(TrustError::LogArtifactVerification);
    }
    if artifact.tree_size_1 == 0
        || artifact.tree_size_1 >= artifact.tree_size_2
        || artifact.tree_size_2 >= MAX_JSON_TREE_SIZE
    {
        return Err(TrustError::LogArtifactVerification);
    }
    if artifact.hashes.len() > MAX_CONSISTENCY_HASHES {
        return Err(TrustError::LogArtifactVerification);
    }
    let proof_bytes = decode_hashes(&artifact.hashes)?;
    let body_1 = verify_checkpoint(artifact.checkpoint_1.as_bytes(), verifier)
        .map_err(|_err| TrustError::LogArtifactVerification)?;
    let body_2 = verify_checkpoint(artifact.checkpoint_2.as_bytes(), verifier)
        .map_err(|_err| TrustError::LogArtifactVerification)?;
    if body_1.tree_size() != artifact.tree_size_1 || body_2.tree_size() != artifact.tree_size_2 {
        return Err(TrustError::LogArtifactVerification);
    }
    let proof = ConsistencyProof::try_from_bytes(proof_bytes)
        .map_err(|_err| TrustError::LogArtifactVerification)?;
    verify_consistency(&body_1.to_root(), &body_2.to_root(), &proof)
        .map_err(|_err| TrustError::LogArtifactVerification)?;
    Ok((body_1, body_2))
}

/// Decodes artifact hash entries — each must be canonical standard base64
/// with padding decoding to exactly 32 bytes — and concatenates them into
/// the RFC 6962 proof byte form. Any violation is
/// [`TrustError::LogArtifactVerification`].
fn decode_hashes(hashes: &[String]) -> TrustResult<Vec<u8>> {
    let mut proof_bytes = Vec::with_capacity(hashes.len() * 32);
    for entry in hashes {
        let decoded = STANDARD
            .decode(entry)
            .map_err(|_err| TrustError::LogArtifactVerification)?;
        if decoded.len() != 32 {
            return Err(TrustError::LogArtifactVerification);
        }
        proof_bytes.extend_from_slice(&decoded);
    }
    Ok(proof_bytes)
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
