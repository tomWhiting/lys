//! Building D2 proof artifacts from a raw-leaf tree and a signing identity.
//!
//! # Invariants
//!
//! - Checkpoints are signed under the origin as the note key name (the
//!   origin-binding rule enforced by verification).
//! - Every builder SELF-VERIFIES the assembled artifact with the exact
//!   verification path a third party runs before returning it — a broken
//!   artifact is never silently emitted.
//! - The 2^53 JSON-safety guard runs before any proof work.
//! - Consistency artifacts require `1 <= old_size < new_size` strictly:
//!   equal-size "consistency" is vacuous (compare checkpoints directly)
//!   and RFC 6962 defines no proof from an empty tree.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::checkpoint::{CheckpointBody, NoteVerifierKey, sign_note};
use crate::error::{TrustError, TrustResult};
use crate::keys::Ed25519Identity;
use crate::merkle::{AppendOnlyTree, RawLeaf};

use super::artifact::{
    CONSISTENCY_PROOF_FORMAT, ConsistencyProofArtifact, INCLUSION_PROOF_FORMAT,
    InclusionProofArtifact, check_json_safe_tree_size,
};
use super::verify::{verify_consistency_artifact, verify_inclusion_artifact};

/// Builds a self-contained inclusion artifact for the leaf at `leaf_index`.
///
/// Guards the JSON-safe tree size, builds the RFC 6962 inclusion proof,
/// chunks its byte form into 32-byte nodes (base64-encoded per D2), signs
/// the checkpoint under the origin as the note key name, and SELF-VERIFIES
/// the assembled artifact before returning — which is why the leaf bytes
/// are a parameter.
///
/// # Errors
///
/// Returns [`TrustError::LogArtifactEncoding`] if the tree size is at or
/// beyond 2^53 or self-verification fails, [`TrustError::MerkleTree`] if
/// `leaf_index` is out of range (actionable operator input), and
/// [`TrustError::CheckpointEncoding`] if the origin is invalid.
pub fn build_inclusion_artifact(
    tree: &AppendOnlyTree<RawLeaf>,
    leaf_bytes: &[u8],
    origin: &str,
    identity: &Ed25519Identity,
    leaf_index: u64,
) -> TrustResult<InclusionProofArtifact> {
    let root = tree.root();
    check_json_safe_tree_size(root.num_leaves())?;
    let proof = tree.prove_inclusion(leaf_index)?;
    let hashes = chunk_proof_bytes(proof.as_bytes())?;
    let body = CheckpointBody::from_root(origin, &root)?;
    let checkpoint = sign_note(&body.encode(), origin, identity)?;
    let artifact = InclusionProofArtifact {
        format: INCLUSION_PROOF_FORMAT.to_string(),
        tree_size: root.num_leaves(),
        leaf_index,
        hashes,
        checkpoint,
    };
    let verifier = self_verifier(origin, identity)?;
    verify_inclusion_artifact(&artifact, leaf_bytes, &verifier).map_err(|_err| {
        TrustError::LogArtifactEncoding {
            reason: "self-verification of freshly built inclusion artifact failed \
                     (the supplied leaf bytes do not match the leaf at the given index, \
                     or the tree is internally inconsistent)"
                .to_string(),
        }
    })?;
    Ok(artifact)
}

/// Builds a self-contained consistency artifact from the old tree to the
/// new tree.
///
/// Requires `1 <= old_size < new_size` strictly and `new_size` below the
/// 2^53 JSON-safe bound. `checkpoint_1` signs the old tree's root,
/// `checkpoint_2` the new tree's root, both under the origin as the note
/// key name. SELF-VERIFIES before returning.
///
/// # Errors
///
/// Returns [`TrustError::LogArtifactEncoding`] on a size-invariant
/// violation, the 2^53 guard, or failed self-verification (the old tree
/// not being a prefix of the new tree surfaces here), and
/// [`TrustError::CheckpointEncoding`] if the origin is invalid.
pub fn build_consistency_artifact(
    old_tree: &AppendOnlyTree<RawLeaf>,
    new_tree: &AppendOnlyTree<RawLeaf>,
    origin: &str,
    identity: &Ed25519Identity,
) -> TrustResult<ConsistencyProofArtifact> {
    let old_size = old_tree.len();
    let new_size = new_tree.len();
    check_json_safe_tree_size(new_size)?;
    if old_size == 0 {
        return Err(TrustError::LogArtifactEncoding {
            reason: "consistency artifact requires the old tree size to be at least 1; \
                     RFC 6962 has no consistency proof from an empty tree"
                .to_string(),
        });
    }
    if old_size >= new_size {
        return Err(TrustError::LogArtifactEncoding {
            reason: format!(
                "consistency artifact requires old size strictly below new size: \
                 old={old_size}, new={new_size}"
            ),
        });
    }
    let proof = new_tree.prove_consistency(old_size, new_size)?;
    let hashes = chunk_proof_bytes(proof.as_bytes())?;
    let body_1 = CheckpointBody::from_root(origin, &old_tree.root())?;
    let body_2 = CheckpointBody::from_root(origin, &new_tree.root())?;
    let checkpoint_1 = sign_note(&body_1.encode(), origin, identity)?;
    let checkpoint_2 = sign_note(&body_2.encode(), origin, identity)?;
    let artifact = ConsistencyProofArtifact {
        format: CONSISTENCY_PROOF_FORMAT.to_string(),
        tree_size_1: old_size,
        tree_size_2: new_size,
        hashes,
        checkpoint_1,
        checkpoint_2,
    };
    let verifier = self_verifier(origin, identity)?;
    verify_consistency_artifact(&artifact, &verifier).map_err(|_err| {
        TrustError::LogArtifactEncoding {
            reason: "self-verification of freshly built consistency artifact failed \
                     (the old tree is not a prefix of the new tree)"
                .to_string(),
        }
    })?;
    Ok(artifact)
}

/// Builds the verifier used for build-time self-verification from the same
/// origin and identity the artifact was signed with.
fn self_verifier(origin: &str, identity: &Ed25519Identity) -> TrustResult<NoteVerifierKey> {
    NoteVerifierKey::new(origin, identity.public_key_bytes()).map_err(|e| {
        TrustError::LogArtifactEncoding {
            reason: format!("could not build self-verification key: {e}"),
        }
    })
}

/// Chunks an RFC 6962 proof byte form into exact 32-byte nodes, each
/// standard-base64-with-padding encoded per D2.
///
/// A remainder cannot happen (ct-merkle proofs are whole digests) but is
/// checked anyway — no silent emission of a malformed artifact.
fn chunk_proof_bytes(proof_bytes: &[u8]) -> TrustResult<Vec<String>> {
    let chunks = proof_bytes.chunks_exact(32);
    if !chunks.remainder().is_empty() {
        return Err(TrustError::LogArtifactEncoding {
            reason: format!(
                "proof byte length {} is not a multiple of the 32-byte digest size",
                proof_bytes.len()
            ),
        });
    }
    Ok(chunks.map(|chunk| STANDARD.encode(chunk)).collect())
}

#[cfg(test)]
#[path = "build_tests.rs"]
mod tests;
