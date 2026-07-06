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
//! [`TrustError::MerkleTree`]: crate::error::TrustError::MerkleTree

pub mod leaf;
pub mod proof;
pub mod tree;

pub use proof::{ConsistencyProof, InclusionProof, RootHash, verify_consistency, verify_inclusion};
pub use tree::AppendOnlyTree;
