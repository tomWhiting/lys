//! Append-only Merkle transparency-log operations.
//!
//! [`AppendOnlyTree`] wraps an RFC 6962-compliant SHA-256 Merkle tree from
//! `ct-merkle` behind an append-only public surface. Leaves of any
//! `Serialize` type are deterministically serialized to bytes before they are
//! hashed into the tree, so this crate stays domain-agnostic — the consumer
//! decides what a leaf means.
//!
//! The only mutating operation is [`AppendOnlyTree::append`]. There is no
//! `remove`, no `replace`, no mutable access to past leaves, and no API that
//! exposes ct-merkle's panicking methods. Out-of-range indices and other
//! invariant violations become [`TrustError::MerkleTree`] values.
//!
//! Proofs are produced and verified through wrapper types that hide the
//! ct-merkle generics:
//! [`RootHash`], [`InclusionProof`], and [`ConsistencyProof`]. The two
//! verification helpers [`verify_inclusion`] and [`verify_consistency`] live
//! at the module root. External verifiers reconstruct a published root via
//! [`RootHash::from_parts`] and proofs via `try_from_bytes`, needing no
//! access to the tree itself.
//!
//! **Frozen wire contract:** a leaf type's `postcard` encoding is fixed
//! forever once leaves are in a persisted or published tree. Fields, field
//! order, and enum variant order of the leaf type must never change —
//! doing so silently invalidates every historical root and proof. Schema
//! evolution requires a new versioned leaf type or an explicitly versioned
//! envelope; consumers needing long-lived verifiability should pin leaves
//! as pre-encoded byte payloads. See the [`leaf`] module docs for details.
//!
//! **Raw-leaf invariant (alongside, not replacing, the postcard contract):**
//! trees typed `AppendOnlyTree<RawLeaf>` hash leaf bytes verbatim, so every
//! leaf hash is exactly RFC 6962's `SHA-256(0x00 ‖ leaf-bytes)` — a third
//! party holding only the raw leaf file recomputes it with standard tooling
//! (`(printf '\x00'; cat leaf-file) | shasum -a 256`). [`raw_leaf_hash`]
//! computes that hash without a tree, and [`verify_inclusion_raw`] is the
//! matching verification helper. The [`RawLeaf`] marker is uninhabited and
//! non-`Serialize`, so the two leaf encodings cannot be mixed in one tree.
//!
//! [`TrustError::MerkleTree`]: crate::error::TrustError::MerkleTree

pub mod leaf;
pub mod proof;
pub mod tree;

pub use leaf::raw_leaf_hash;
pub use proof::{
    ConsistencyProof, InclusionProof, RootHash, verify_consistency, verify_inclusion,
    verify_inclusion_raw,
};
pub use tree::{AppendOnlyTree, RawLeaf};
