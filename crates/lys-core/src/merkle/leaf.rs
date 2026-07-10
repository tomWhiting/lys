//! Deterministic serialization of arbitrary `Serialize` leaves into bytes the
//! Merkle tree can hash.
//!
//! ct-merkle's `MemoryBackedTree` requires leaves to implement
//! `ct_merkle::HashableLeaf`. A blanket impl is provided for any
//! `T: AsRef<[u8]>`, so `SerializedLeaf` satisfies the bound by exposing
//! its bytes through [`AsRef`]. The tree never sees the original `L` —
//! `serialize_leaf` is the single conversion point for `Serialize` leaves,
//! and [`SerializedLeaf::from_raw_bytes`] is the single entry point for the
//! raw-leaf path (see below).
//!
//! Serialization is performed with `postcard`, a compact and deterministic
//! binary format. Two consumers serializing the same value with the same
//! schema therefore produce byte-identical input to the hash function, which
//! is what makes [`AppendOnlyTree::root`] stable across runs.
//!
//! # The postcard encoding is a FROZEN WIRE CONTRACT
//!
//! Postcard is a non-self-describing format: it writes no field names, no
//! tags, and no schema information. The encoded bytes are determined
//! entirely by the leaf type's **shape** — its fields, their declaration
//! order, and (for enums) the declaration order of variants. Consequently,
//! once leaves of a type have been hashed into a persisted or published
//! tree, that type's shape is frozen forever:
//!
//! - **Never** add, remove, rename-with-retype, or reorder fields.
//! - **Never** reorder, insert, or remove enum variants.
//! - **Never** change a field's type, even to a layout-compatible one.
//!
//! Any such change silently changes the serialized bytes of historical
//! leaf values. There is no error and no version mismatch — every
//! previously published root and proof simply stops verifying, which for a
//! transparency log is indistinguishable from tampering. Schema evolution
//! requires a **new versioned leaf type** or an **explicitly versioned
//! envelope**; it must never be done by editing an existing leaf type in
//! place.
//!
//! Consumers who need long-lived verifiability are strongly encouraged to
//! pin leaves as pre-encoded byte payloads — e.g. a leaf struct holding a
//! `Vec<u8>` the consumer encodes and versions itself — so the bytes that
//! enter the tree are under the consumer's explicit control rather than
//! derived from a Rust type's shape.
//!
//! # The raw-leaf path (transparency-log invariant)
//!
//! `postcard` prefixes byte-sequence leaves with a length varint, so the
//! bytes a `Serialize` tree hashes are **not** the consumer's bytes — a
//! third party holding only the raw leaf cannot recompute the leaf hash
//! with standard tooling. [`SerializedLeaf::from_raw_bytes`] wraps bytes
//! verbatim (no postcard, no length prefix), so a tree fed through it
//! hashes exactly `SHA-256(0x00 ‖ bytes)` per RFC 6962. **Invariant:** for
//! every raw leaf, `leaf_hash = SHA-256(0x00 ‖ leaf-bytes)`; reproduce with
//! `(printf '\x00'; cat leaf-file) | shasum -a 256`. The postcard contract
//! above is untouched — the two paths never mix in one tree (see
//! [`RawLeaf`](super::tree::RawLeaf)).
//!
//! Failures (e.g. a `Serialize` impl that returns an error) are mapped to
//! [`TrustError::MerkleTree`], not panics.
//!
//! [`AppendOnlyTree::root`]: super::tree::AppendOnlyTree::root
//! [`TrustError::MerkleTree`]: crate::error::TrustError::MerkleTree

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{TrustError, TrustResult};

/// Byte representation of a Merkle leaf.
///
/// Implements [`AsRef<[u8]>`] so that ct-merkle's blanket
/// `impl<T: AsRef<[u8]>> HashableLeaf for T` applies and the tree can hash
/// the wrapped bytes directly. The inner buffer is intentionally private:
/// callers outside this module work in terms of the original `L` and the
/// [`serialize_leaf`] helper.
pub(crate) struct SerializedLeaf(Vec<u8>);

impl SerializedLeaf {
    /// Wraps bytes VERBATIM — no postcard, no length prefix. The tree then
    /// hashes exactly `SHA-256(0x00 ‖ bytes)` per RFC 6962. This is the
    /// transparency-log invariant path: a third party holding only the raw
    /// leaf bytes recomputes the leaf hash with any SHA-256 tool.
    pub(crate) fn from_raw_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Read-only access to the serialized bytes, used by tests in this crate
    /// to assert content stability.
    #[cfg(test)]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for SerializedLeaf {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Serializes a leaf into the canonical byte representation used by the
/// Merkle tree.
///
/// The postcard encoding of `L` is a **frozen wire contract** (see the
/// module docs): the bytes produced here depend on `L`'s fields, field
/// order, and enum variant order, and those must never change once leaves
/// of `L` are part of a persisted or published tree. Evolving the schema
/// means introducing a new versioned leaf type, not editing `L`.
///
/// # Errors
///
/// Returns [`TrustError::MerkleTree`] if `postcard` rejects the value — for
/// example, a custom `Serialize` impl that fails or a type postcard cannot
/// represent (such as a non-`'static` map with non-string keys when a schema
/// constraint is violated).
pub(crate) fn serialize_leaf<L: Serialize>(leaf: &L) -> TrustResult<SerializedLeaf> {
    postcard::to_allocvec(leaf)
        .map(SerializedLeaf)
        .map_err(|e| TrustError::MerkleTree {
            reason: format!("failed to serialize leaf for Merkle tree: {e}"),
        })
}

/// RFC 6962 leaf hash of raw bytes: `SHA-256(0x00 ‖ leaf_bytes)`.
///
/// Public so consumers (and the CLI) can display and compare leaf hashes
/// without a tree. **Invariant:** this is exactly the hash the raw-leaf
/// tree ([`RawLeaf`](super::tree::RawLeaf)) computes for a leaf, and it is
/// reproducible by any stranger with standard tooling:
/// `(printf '\x00'; cat leaf-file) | shasum -a 256`.
pub fn raw_leaf_hash(leaf_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(leaf_bytes);
    hasher.finalize().into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Sample {
        id: u32,
        label: String,
    }

    #[test]
    fn serialize_leaf_is_deterministic_for_identical_inputs() {
        let a = Sample {
            id: 7,
            label: "alpha".to_string(),
        };
        let b = Sample {
            id: 7,
            label: "alpha".to_string(),
        };
        let bytes_a = serialize_leaf(&a).unwrap();
        let bytes_b = serialize_leaf(&b).unwrap();
        assert_eq!(bytes_a.as_bytes(), bytes_b.as_bytes());
    }

    #[test]
    fn serialize_leaf_differs_between_distinct_inputs() {
        let a = Sample {
            id: 7,
            label: "alpha".to_string(),
        };
        let c = Sample {
            id: 8,
            label: "alpha".to_string(),
        };
        let bytes_a = serialize_leaf(&a).unwrap();
        let bytes_c = serialize_leaf(&c).unwrap();
        assert_ne!(bytes_a.as_bytes(), bytes_c.as_bytes());
    }

    #[test]
    fn serialized_leaf_exposes_bytes_through_as_ref() {
        let leaf = serialize_leaf(&123u64).unwrap();
        let as_ref: &[u8] = leaf.as_ref();
        assert_eq!(as_ref, leaf.as_bytes());
    }
}
