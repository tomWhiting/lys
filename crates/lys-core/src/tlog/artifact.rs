//! Serde shapes of the D2 proof artifacts and the shared JSON-safety guard.
//!
//! # Invariants
//!
//! - Field declaration order below IS the serialization order and matches
//!   the D2 wire contract exactly. The shapes are FROZEN once artifacts are
//!   emitted; a `v2` gets a new `format` string, never field changes here.
//! - `deny_unknown_fields`: unknown fields in a v1 artifact are not valid
//!   v1 — there is no field smuggling into a frozen shape. Duplicate JSON
//!   keys are likewise rejected (serde-derive behavior, pinned by test).
//! - This crate performs no JSON (de)serialization itself; the types only
//!   derive `Serialize`/`Deserialize` (mirroring the `Attestation`
//!   precedent) and the consumer chooses the codec.

use serde::{Deserialize, Serialize};

use crate::error::{TrustError, TrustResult};

/// `format` value of every inclusion-proof artifact. FROZEN.
pub const INCLUSION_PROOF_FORMAT: &str = "lys/log-inclusion-proof/v1";

/// `format` value of every consistency-proof artifact. FROZEN.
pub const CONSISTENCY_PROOF_FORMAT: &str = "lys/log-consistency-proof/v1";

/// Exclusive JSON-safe bound: artifacts with any tree size at or beyond
/// 2^53 are refused on emission AND rejected on verification (JSON number
/// precision boundary — a documented D2 contract, not a surprise).
pub const MAX_JSON_TREE_SIZE: u64 = 1 << 53; // 9_007_199_254_740_992

/// Self-contained inclusion-proof artifact
/// (`lys/log-inclusion-proof/v1`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InclusionProofArtifact {
    /// Artifact kind marker; must equal [`INCLUSION_PROOF_FORMAT`].
    pub format: String,
    /// Size of the tree the proof was generated against.
    pub tree_size: u64,
    /// Zero-based index of the proven leaf.
    pub leaf_index: u64,
    /// RFC 6962 inclusion-path nodes: standard base64 WITH padding,
    /// 32 bytes each.
    pub hashes: Vec<String>,
    /// The full signed-note text, VERBATIM, including its trailing newline.
    pub checkpoint: String,
}

/// Self-contained consistency-proof artifact
/// (`lys/log-consistency-proof/v1`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsistencyProofArtifact {
    /// Artifact kind marker; must equal [`CONSISTENCY_PROOF_FORMAT`].
    pub format: String,
    /// Size of the OLD tree; strictly less than `tree_size_2` and at
    /// least 1.
    pub tree_size_1: u64,
    /// Size of the NEW tree.
    pub tree_size_2: u64,
    /// RFC 6962 consistency-proof nodes: standard base64 WITH padding,
    /// 32 bytes each.
    pub hashes: Vec<String>,
    /// Signed note for the OLD tree, verbatim, including trailing newline.
    pub checkpoint_1: String,
    /// Signed note for the NEW tree, verbatim, including trailing newline.
    pub checkpoint_2: String,
}

/// The 2^53 refusal guard, shared by build and verify (verify wraps the
/// error into its non-oracle collapse).
///
/// # Errors
///
/// Returns [`TrustError::LogArtifactEncoding`] if `tree_size` is at or
/// beyond [`MAX_JSON_TREE_SIZE`].
pub(crate) fn check_json_safe_tree_size(tree_size: u64) -> TrustResult<()> {
    if tree_size >= MAX_JSON_TREE_SIZE {
        return Err(TrustError::LogArtifactEncoding {
            reason: format!(
                "tree size {tree_size} is at or beyond the JSON-safe bound 2^53 \
                 ({MAX_JSON_TREE_SIZE})"
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
#[path = "artifact_tests.rs"]
mod tests;
