//! [`AppendOnlyTree`] — the append-only Merkle log over a SHA-256
//! `ct_merkle::MemoryBackedTree`.
//!
//! Only [`AppendOnlyTree::append`] mutates the tree. There is no API that
//! deletes, replaces, reorders, or otherwise touches past leaves; the type
//! exists precisely to make the append-only invariant a property of the
//! public surface, not just of the underlying RFC 6962 construction.
//!
//! ct-merkle's `prove_inclusion` and `prove_consistency` panic on
//! out-of-range arguments. The wrapper methods pre-check the arguments and
//! return [`TrustError::MerkleTree`] instead, keeping the no-panic invariant
//! of this crate intact.
//!
//! The tree is generic over the leaf type `L: Serialize`. Leaves are
//! converted to a deterministic byte representation via `serialize_leaf`
//! before being pushed into the underlying ct-merkle tree, so the original
//! `L` is not stored on the tree and the trust crate stays domain-agnostic.
//!
//! The [`RawLeaf`] marker selects the parallel raw-byte encoding:
//! `AppendOnlyTree<RawLeaf>` hashes leaf bytes verbatim
//! (`SHA-256(0x00 ‖ bytes)` per RFC 6962) via [`AppendOnlyTree::append_raw`]
//! and never gains the postcard methods, so the two leaf encodings cannot
//! be mixed in one tree.

use std::fmt;
use std::marker::PhantomData;

use ct_merkle::mem_backed_tree::MemoryBackedTree;
use serde::Serialize;
use sha2::Sha256;

use crate::error::{TrustError, TrustResult};
use crate::merkle::leaf::{SerializedLeaf, serialize_leaf};
use crate::merkle::proof::{ConsistencyProof, InclusionProof, RootHash};

/// Append-only Merkle transparency log over any `L: Serialize` leaf.
///
/// Each [`Self::append`] serializes the leaf with `postcard` and pushes the
/// resulting bytes into a `ct_merkle::MemoryBackedTree<Sha256, _>`. The
/// original `L` is not stored; the tree retains the serialized bytes plus
/// the internal Merkle nodes.
///
/// The empty tree's root is RFC 6962's deterministic zero-leaf root —
/// `SHA-256("")` paired with `num_leaves = 0`. After `n` appends, [`Self::root`]
/// returns the SHA-256 Merkle Tree Hash of the `n` leaves with `num_leaves =
/// n`. Two trees built from the same `Serialize` sequence in the same order
/// produce the same root.
///
/// # The leaf encoding is a FROZEN WIRE CONTRACT
///
/// Leaves are hashed via their `postcard` encoding, which is derived
/// entirely from `L`'s shape: fields, field declaration order, and enum
/// variant declaration order. Once leaves of `L` exist in a persisted or
/// published tree, that shape must **never** change — reordering or adding
/// fields, or reordering enum variants, silently alters the bytes of
/// historical leaves, so every previously published root and proof stops
/// verifying with no error and no version signal. Schema evolution
/// requires a new versioned leaf type or an explicitly versioned envelope.
/// When long-lived verifiability matters, prefer a leaf type that pins the
/// payload as pre-encoded bytes (e.g. a struct holding `Vec<u8>`) so the
/// hashed bytes are under explicit consumer control. See the
/// [`leaf`](super::leaf) module docs for the full contract.
pub struct AppendOnlyTree<L> {
    inner: MemoryBackedTree<Sha256, SerializedLeaf>,
    // `fn(L)` is the standard "leaf-type tag" marker — it tracks `L` in the
    // type signature without imposing variance constraints on the wrapper
    // and without requiring `L: Debug`/`Clone` on the wrapper's derives.
    _marker: PhantomData<fn(L)>,
}

impl<L> AppendOnlyTree<L> {
    /// Builds a new empty tree.
    ///
    /// The empty tree's [`Self::root`] is the deterministic zero-leaf root
    /// (`SHA-256("")` with `num_leaves = 0`) defined by RFC 6962 and
    /// implemented by ct-merkle.
    pub fn new() -> Self {
        Self {
            inner: MemoryBackedTree::new(),
            _marker: PhantomData,
        }
    }

    /// Returns the number of leaves in the tree.
    pub fn len(&self) -> u64 {
        self.inner.len()
    }

    /// Returns `true` if no leaves have been appended.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the current root hash, capturing both the SHA-256 Merkle Tree
    /// Hash and the current leaf count.
    pub fn root(&self) -> RootHash {
        RootHash::from_inner(self.inner.root())
    }

    /// Builds an inclusion proof for the leaf at `leaf_index`.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::MerkleTree`] if `leaf_index` is greater than or
    /// equal to the current tree length, or if the index does not fit in a
    /// `usize` on this target. Both conditions are pre-checked so the
    /// underlying ct-merkle call (which would otherwise panic) is never made
    /// with an invalid argument.
    pub fn prove_inclusion(&self, leaf_index: u64) -> TrustResult<InclusionProof> {
        let len = self.inner.len();
        if leaf_index >= len {
            return Err(TrustError::MerkleTree {
                reason: format!(
                    "inclusion proof requested for leaf index {leaf_index} but tree has {len} leaves"
                ),
            });
        }
        let idx = usize::try_from(leaf_index).map_err(|_err| TrustError::MerkleTree {
            reason: format!("inclusion proof leaf index {leaf_index} does not fit in usize"),
        })?;
        Ok(InclusionProof::from_inner(self.inner.prove_inclusion(idx)))
    }

    /// Builds a consistency proof showing that the tree of size `old_size` is
    /// a prefix of the current tree (which must be exactly `new_size` leaves).
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::MerkleTree`] if `new_size` does not equal the
    /// current tree length, `old_size` is zero, `old_size` exceeds `new_size`,
    /// or the resulting `num_additions` does not fit in a `usize`. These
    /// checks ensure the underlying ct-merkle call (which would otherwise
    /// panic when `num_additions >= self.len()`) is never made with an
    /// invalid argument.
    pub fn prove_consistency(&self, old_size: u64, new_size: u64) -> TrustResult<ConsistencyProof> {
        let len = self.inner.len();
        if new_size != len {
            return Err(TrustError::MerkleTree {
                reason: format!(
                    "consistency proof requires new_size to equal current tree length: \
                     new_size={new_size}, current_len={len}"
                ),
            });
        }
        if old_size == 0 {
            return Err(TrustError::MerkleTree {
                reason: "consistency proof requires old_size > 0; \
                         RFC 6962 has no consistency proof from an empty tree"
                    .to_string(),
            });
        }
        if old_size > new_size {
            return Err(TrustError::MerkleTree {
                reason: format!(
                    "consistency proof old_size must be <= new_size: \
                     old_size={old_size}, new_size={new_size}"
                ),
            });
        }
        // old_size > 0 and old_size <= new_size = self.len(), so this never
        // wraps around.
        let num_additions = new_size - old_size;
        let num_additions_usize =
            usize::try_from(num_additions).map_err(|_err| TrustError::MerkleTree {
                reason: format!(
                    "consistency proof num_additions {num_additions} does not fit in usize"
                ),
            })?;
        Ok(ConsistencyProof::from_inner(
            self.inner.prove_consistency(num_additions_usize),
        ))
    }
}

/// Type-level marker for trees whose leaves are raw bytes hashed verbatim
/// (leaf hash = `SHA-256(0x00 ‖ bytes)` per RFC 6962).
///
/// Uninhabited: never a value, and it deliberately does NOT implement
/// `Serialize`, so the postcard methods ([`AppendOnlyTree::append`],
/// [`AppendOnlyTree::reconstruct_from_leaves`]) do not exist on
/// `AppendOnlyTree<RawLeaf>` — the two leaf encodings cannot be mixed in
/// one tree even by accident.
///
/// **Invariant:** for every leaf appended via
/// [`AppendOnlyTree::append_raw`],
/// `leaf_hash = SHA-256(0x00 ‖ leaf-bytes)`; a third party reproduces it
/// with `(printf '\x00'; cat leaf-file) | shasum -a 256`.
pub enum RawLeaf {}

impl AppendOnlyTree<RawLeaf> {
    /// Appends raw bytes verbatim and returns the new tree size.
    ///
    /// The bytes are hashed exactly as supplied — no postcard, no length
    /// prefix — so the RFC 6962 leaf hash is `SHA-256(0x00 ‖ leaf_bytes)`
    /// (see [`raw_leaf_hash`](super::leaf::raw_leaf_hash)). Infallible:
    /// there is no serialization step to fail.
    pub fn append_raw(&mut self, leaf_bytes: &[u8]) -> u64 {
        self.inner
            .push(SerializedLeaf::from_raw_bytes(leaf_bytes.to_vec()));
        self.inner.len()
    }

    /// Rebuilds a raw-leaf tree from leaves in their original append order.
    ///
    /// The reconstruction path for restart and prefix rebuilds, mirroring
    /// [`AppendOnlyTree::reconstruct_from_leaves`] for the raw encoding.
    /// Because it reuses [`Self::append_raw`], the rebuilt tree reproduces
    /// the original root bit-for-bit.
    pub fn reconstruct_from_raw_leaves<I>(leaves: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let mut tree = Self::new();
        for leaf in leaves {
            tree.append_raw(leaf.as_ref());
        }
        tree
    }
}

impl<L: Serialize> AppendOnlyTree<L> {
    /// Appends `leaf` to the tree and returns the new tree size.
    ///
    /// The leaf is serialized via `postcard` before being hashed into the
    /// tree. The first append returns `1`, the next `2`, and so on.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::MerkleTree`] if the leaf cannot be serialized.
    /// No other failure modes exist at this scale of tree (ct-merkle's
    /// internal limits are well beyond practical use).
    pub fn append(&mut self, leaf: L) -> TrustResult<u64> {
        let serialized = serialize_leaf(&leaf)?;
        self.inner.push(serialized);
        Ok(self.inner.len())
    }

    /// Rebuilds a tree from a sequence of leaves in their original append
    /// order.
    ///
    /// This is the mechanism for reconstructing in-memory tree state from
    /// persistent storage on restart. Because reconstruction reuses
    /// [`Self::append`], it goes through the same serialization path and
    /// therefore reproduces the original root hash bit-for-bit.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::MerkleTree`] if any leaf fails to serialize.
    pub fn reconstruct_from_leaves(leaves: Vec<L>) -> TrustResult<Self> {
        let mut tree = Self::new();
        for leaf in leaves {
            tree.append(leaf)?;
        }
        Ok(tree)
    }
}

impl<L> Default for AppendOnlyTree<L> {
    fn default() -> Self {
        Self::new()
    }
}

impl<L> fmt::Debug for AppendOnlyTree<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppendOnlyTree")
            .field("num_leaves", &self.inner.len())
            .finish()
    }
}

#[cfg(test)]
#[path = "tree_tests.rs"]
mod tests;
