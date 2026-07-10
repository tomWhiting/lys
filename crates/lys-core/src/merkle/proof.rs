//! Wrapper types for Merkle root hashes and proofs, and the public
//! verification helpers.
//!
//! [`RootHash`], [`InclusionProof`], and [`ConsistencyProof`] hide the
//! `ct_merkle` generics behind public types parameterised only on SHA-256.
//! Consumers persist proofs by calling [`InclusionProof::as_bytes`] /
//! [`ConsistencyProof::as_bytes`] and reconstitute them later via
//! `try_from_bytes`, with malformed-byte failures mapped to
//! [`TrustError::MerkleTree`].
//!
//! [`verify_inclusion`] re-serializes the candidate leaf with the same
//! `postcard` helper used by [`super::tree::AppendOnlyTree::append`], so
//! verification observes the exact bytes that were originally hashed.
//! [`verify_consistency`] verifies on the new root and compares against the
//! supplied old root.
//!
//! External verification requires no tree access at all: a log publishes
//! `(root bytes, leaf count)` via [`RootHash::to_parts`] plus proof bytes,
//! and a third party reconstructs the root with [`RootHash::from_parts`],
//! rebuilds the proofs with `try_from_bytes`, and runs the verification
//! helpers against only those published primitives.

use ct_merkle::{ConsistencyProof as CtConsistencyProof, InclusionProof as CtInclusionProof};
use serde::Serialize;
use sha2::Sha256;

use crate::error::{TrustError, TrustResult};
use crate::merkle::leaf::serialize_leaf;

/// Root hash of an [`AppendOnlyTree`] at a particular size.
///
/// Wraps `ct_merkle::RootHash<Sha256>`, which carries both the 32-byte
/// SHA-256 Merkle Tree Hash and the number of leaves. The leaf count is part
/// of the root because ct-merkle's verifier uses it to size proofs — a bare
/// 32-byte hash without the count cannot drive verification.
///
/// [`AppendOnlyTree`]: super::tree::AppendOnlyTree
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootHash {
    inner: ct_merkle::RootHash<Sha256>,
}

impl RootHash {
    /// Wraps a ct-merkle root hash. Internal constructor used by the tree.
    pub(crate) fn from_inner(inner: ct_merkle::RootHash<Sha256>) -> Self {
        Self { inner }
    }

    /// Reconstructs a root hash from its published parts: the 32-byte
    /// SHA-256 Merkle Tree Hash and the leaf count at which that root was
    /// computed.
    ///
    /// This is the entry point for **external verifiers**. A transparency
    /// log publishes `(root bytes, leaf count)` — obtained from
    /// [`Self::to_parts`] — alongside proof bytes; a third party that holds
    /// only those published primitives reconstructs the root with this
    /// constructor and then verifies proofs via [`verify_inclusion`] /
    /// [`verify_consistency`] without ever having access to the tree
    /// itself.
    ///
    /// No validation is possible at construction time — a root hash is an
    /// opaque commitment. Supplying bytes or a leaf count that do not match
    /// the tree that produced the proofs causes verification to fail, which
    /// is exercised by this module's tests.
    pub fn from_parts(root_hash: [u8; 32], num_leaves: u64) -> Self {
        let digest = sha2::digest::Output::<Sha256>::from(root_hash);
        Self {
            inner: ct_merkle::RootHash::new(digest, num_leaves),
        }
    }

    /// Returns the published parts of this root: the 32-byte SHA-256 Merkle
    /// Tree Hash and the leaf count at which it was computed.
    ///
    /// The returned pair is exactly what [`Self::from_parts`] accepts, so a
    /// log operator publishes these two values and an external verifier
    /// reconstructs an equal `RootHash` from them.
    pub fn to_parts(&self) -> ([u8; 32], u64) {
        ((*self.inner.as_bytes()).into(), self.inner.num_leaves())
    }

    /// Returns the 32-byte SHA-256 Merkle Tree Hash.
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes().as_slice()
    }

    /// Returns the number of leaves in the tree at the time this root was
    /// computed.
    pub fn num_leaves(&self) -> u64 {
        self.inner.num_leaves()
    }
}

/// Inclusion proof for a single leaf at a known index.
///
/// Produced by [`super::tree::AppendOnlyTree::prove_inclusion`] and verified
/// by [`verify_inclusion`].
///
/// `PartialEq`/`Eq` are intentionally not implemented: ct-merkle's
/// `InclusionProof<H>` derives them with a `H: Eq` bound that `Sha256` does
/// not satisfy. Equality testing of proofs is done by comparing the raw
/// bytes via [`Self::as_bytes`].
#[derive(Clone, Debug)]
pub struct InclusionProof {
    inner: CtInclusionProof<Sha256>,
}

impl InclusionProof {
    /// Wraps a ct-merkle inclusion proof. Internal constructor used by the
    /// tree.
    pub(crate) fn from_inner(inner: CtInclusionProof<Sha256>) -> Self {
        Self { inner }
    }

    /// Returns a reference to the wrapped ct-merkle inclusion proof.
    pub(crate) fn as_inner(&self) -> &CtInclusionProof<Sha256> {
        &self.inner
    }

    /// Returns the RFC 6962 `PATH(m, D[n])` byte encoding of the proof.
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    /// Reconstructs an inclusion proof from its byte encoding.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::MerkleTree`] if `bytes.len()` is not a multiple
    /// of the SHA-256 digest size, i.e. the input is not a concatenated
    /// sequence of valid hash digests.
    pub fn try_from_bytes(bytes: Vec<u8>) -> TrustResult<Self> {
        CtInclusionProof::<Sha256>::try_from_bytes(bytes)
            .map(|inner| Self { inner })
            .map_err(|e| TrustError::MerkleTree {
                reason: format!("inclusion proof bytes are malformed: {e}"),
            })
    }
}

/// Consistency proof showing that one tree is a prefix of another.
///
/// Produced by [`super::tree::AppendOnlyTree::prove_consistency`] and
/// verified by [`verify_consistency`].
#[derive(Clone, Debug)]
pub struct ConsistencyProof {
    inner: CtConsistencyProof<Sha256>,
}

impl ConsistencyProof {
    /// Wraps a ct-merkle consistency proof. Internal constructor used by the
    /// tree.
    pub(crate) fn from_inner(inner: CtConsistencyProof<Sha256>) -> Self {
        Self { inner }
    }

    /// Returns a reference to the wrapped ct-merkle consistency proof.
    pub(crate) fn as_inner(&self) -> &CtConsistencyProof<Sha256> {
        &self.inner
    }

    /// Returns the RFC 6962 `PROOF(m, D[n])` byte encoding of the proof.
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    /// Reconstructs a consistency proof from its byte encoding.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::MerkleTree`] if `bytes.len()` is not a multiple
    /// of the SHA-256 digest size.
    pub fn try_from_bytes(bytes: Vec<u8>) -> TrustResult<Self> {
        CtConsistencyProof::<Sha256>::try_from_bytes(bytes)
            .map(|inner| Self { inner })
            .map_err(|e| TrustError::MerkleTree {
                reason: format!("consistency proof bytes are malformed: {e}"),
            })
    }
}

/// Verifies that `leaf` was at position `index` in the tree whose root is
/// `root_hash`.
///
/// `leaf` is serialized via the same `postcard` helper used by
/// [`super::tree::AppendOnlyTree::append`], so the verifier hashes the same
/// bytes that were originally inserted. A mismatched root, a tampered leaf,
/// or an out-of-range index all fail verification.
///
/// # Errors
///
/// Returns [`TrustError::MerkleTree`] if:
/// - serializing `leaf` fails, or
/// - ct-merkle reports that the proof does not verify against `root_hash` for
///   the given `index` (including index-out-of-range, empty-tree root,
///   incorrect-hash, or malformed-proof cases).
pub fn verify_inclusion<L: Serialize>(
    root_hash: &RootHash,
    leaf: &L,
    index: u64,
    proof: &InclusionProof,
) -> TrustResult<()> {
    let serialized = serialize_leaf(leaf)?;
    root_hash
        .inner
        .verify_inclusion(&serialized, index, proof.as_inner())
        .map_err(|e| TrustError::MerkleTree {
            reason: format!("inclusion proof verification failed: {e}"),
        })
}

/// Verifies inclusion of RAW leaf bytes (hashed as `SHA-256(0x00 ‖ bytes)`
/// per RFC 6962), the counterpart of [`verify_inclusion`] for
/// [`AppendOnlyTree<RawLeaf>`](super::tree::RawLeaf).
///
/// The bytes are hashed exactly as supplied — no postcard, no length
/// prefix — so a third party holding only the raw leaf file recomputes the
/// leaf hash with any SHA-256 tool and drives this verification from the
/// published `(root bytes, leaf count)` and proof bytes alone.
///
/// # Errors
///
/// Returns [`TrustError::MerkleTree`] if ct-merkle reports that the proof
/// does not verify against `root_hash` for the given `index` (including
/// index-out-of-range, empty-tree root, incorrect-hash, or malformed-proof
/// cases).
pub fn verify_inclusion_raw(
    root_hash: &RootHash,
    leaf_bytes: &[u8],
    index: u64,
    proof: &InclusionProof,
) -> TrustResult<()> {
    root_hash
        .inner
        .verify_inclusion(&leaf_bytes, index, proof.as_inner())
        .map_err(|e| TrustError::MerkleTree {
            reason: format!("inclusion proof verification failed: {e}"),
        })
}

/// Verifies that the tree described by `old_root` is a prefix of the tree
/// described by `new_root`.
///
/// # Errors
///
/// Returns [`TrustError::MerkleTree`] if ct-merkle rejects the proof — for
/// example because the old tree is empty, the old tree is larger than the
/// new tree, the proof bytes are the wrong length, or the recomputed root
/// hashes do not match (which is what happens when leaves between the two
/// trees have been reordered or modified).
pub fn verify_consistency(
    old_root: &RootHash,
    new_root: &RootHash,
    proof: &ConsistencyProof,
) -> TrustResult<()> {
    new_root
        .inner
        .verify_consistency(&old_root.inner, proof.as_inner())
        .map_err(|e| TrustError::MerkleTree {
            reason: format!("consistency proof verification failed: {e}"),
        })
}

#[cfg(test)]
#[path = "proof_tests.rs"]
mod tests;
