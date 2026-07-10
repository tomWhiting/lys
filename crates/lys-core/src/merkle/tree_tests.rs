#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::merkle::leaf::raw_leaf_hash;
use crate::merkle::proof::{verify_consistency, verify_inclusion, verify_inclusion_raw};

#[test]
fn append_returns_incrementing_sizes_starting_at_one() {
    let mut tree = AppendOnlyTree::<u64>::new();

    assert_eq!(tree.append(10).unwrap(), 1);
    assert_eq!(tree.append(20).unwrap(), 2);
    assert_eq!(tree.append(30).unwrap(), 3);
    assert_eq!(tree.len(), 3);
}

#[test]
fn empty_tree_is_empty_and_has_deterministic_root() {
    let tree = AppendOnlyTree::<u64>::new();
    let default_tree = AppendOnlyTree::<u64>::default();

    assert!(tree.is_empty());
    assert_eq!(tree.root(), default_tree.root());
    assert_eq!(tree.root().num_leaves(), 0);
}

#[test]
fn identical_ordered_leaves_produce_identical_roots() {
    let leaves = vec!["alpha", "beta", "gamma"];
    let mut a = AppendOnlyTree::<&str>::new();
    let mut b = AppendOnlyTree::<&str>::new();

    for leaf in &leaves {
        a.append(*leaf).unwrap();
        b.append(*leaf).unwrap();
    }

    assert_eq!(a.root(), b.root());
}

#[test]
fn inclusion_proof_verifies_against_current_root() {
    let leaves = vec!["alpha", "beta", "gamma", "delta"];
    let mut tree = AppendOnlyTree::<&str>::new();
    for leaf in &leaves {
        tree.append(*leaf).unwrap();
    }
    let root = tree.root();

    for (index, leaf) in leaves.iter().enumerate() {
        let proof = tree.prove_inclusion(index as u64).unwrap();
        verify_inclusion(&root, leaf, index as u64, &proof).unwrap();
    }
}

#[test]
fn inclusion_proof_out_of_range_returns_trust_error() {
    let mut tree = AppendOnlyTree::<u64>::new();
    tree.append(1).unwrap();

    let err = tree.prove_inclusion(1).unwrap_err();
    assert!(matches!(err, TrustError::MerkleTree { .. }));
}

#[test]
fn inclusion_proof_for_empty_tree_returns_trust_error() {
    let tree = AppendOnlyTree::<u64>::new();

    let err = tree.prove_inclusion(0).unwrap_err();
    assert!(matches!(err, TrustError::MerkleTree { .. }));
}

#[test]
fn inclusion_proof_fails_against_different_root() {
    let mut tree = AppendOnlyTree::<u64>::new();
    tree.append(1).unwrap();
    tree.append(2).unwrap();
    let proof = tree.prove_inclusion(0).unwrap();

    let mut other = AppendOnlyTree::<u64>::new();
    other.append(1).unwrap();
    other.append(3).unwrap();

    assert!(verify_inclusion(&other.root(), &1, 0, &proof).is_err());
}

#[test]
fn inclusion_proof_fails_for_tampered_leaf() {
    let mut tree = AppendOnlyTree::<u64>::new();
    tree.append(1).unwrap();
    tree.append(2).unwrap();
    let root = tree.root();
    let proof = tree.prove_inclusion(1).unwrap();

    assert!(verify_inclusion(&root, &99, 1, &proof).is_err());
}

#[test]
fn consistency_proof_verifies_from_n_to_n_plus_m() {
    let mut tree = AppendOnlyTree::<u64>::new();
    tree.append(1).unwrap();
    tree.append(2).unwrap();
    let old_root = tree.root();
    tree.append(3).unwrap();
    tree.append(4).unwrap();
    tree.append(5).unwrap();
    let new_root = tree.root();

    let proof = tree.prove_consistency(2, 5).unwrap();
    verify_consistency(&old_root, &new_root, &proof).unwrap();
}

#[test]
fn consistency_proof_fails_against_wrong_old_root() {
    let mut tree = AppendOnlyTree::<u64>::new();
    tree.append(1).unwrap();
    tree.append(2).unwrap();
    tree.append(3).unwrap();
    let new_root = tree.root();
    let proof = tree.prove_consistency(2, 3).unwrap();

    let mut wrong_old = AppendOnlyTree::<u64>::new();
    wrong_old.append(1).unwrap();
    wrong_old.append(99).unwrap();

    assert!(verify_consistency(&wrong_old.root(), &new_root, &proof).is_err());
}

#[test]
fn consistency_proof_detects_reordered_or_modified_leaves() {
    let mut original = AppendOnlyTree::<u64>::new();
    original.append(1).unwrap();
    original.append(2).unwrap();
    let old_root = original.root();

    let mut tampered = AppendOnlyTree::<u64>::new();
    tampered.append(2).unwrap();
    tampered.append(1).unwrap();
    tampered.append(3).unwrap();
    let tampered_root = tampered.root();
    let tampered_proof = tampered.prove_consistency(2, 3).unwrap();

    assert!(verify_consistency(&old_root, &tampered_root, &tampered_proof).is_err());
}

#[test]
fn consistency_proof_rejects_invalid_size_ranges() {
    let mut tree = AppendOnlyTree::<u64>::new();
    tree.append(1).unwrap();
    tree.append(2).unwrap();

    assert!(tree.prove_consistency(0, 2).is_err());
    assert!(tree.prove_consistency(3, 2).is_err());
    assert!(tree.prove_consistency(1, 3).is_err());
}

#[test]
fn reconstruct_from_leaves_reproduces_root_for_ten_leaves() {
    let leaves: Vec<u64> = (0..10).collect();
    let mut original = AppendOnlyTree::<u64>::new();
    for leaf in &leaves {
        original.append(*leaf).unwrap();
    }
    let original_root = original.root();

    let reconstructed = AppendOnlyTree::<u64>::reconstruct_from_leaves(leaves).unwrap();

    assert_eq!(original_root, reconstructed.root());
}

#[test]
fn inclusion_proof_verifies_against_reconstructed_root() {
    let leaves: Vec<u64> = (0..10).collect();
    let mut original = AppendOnlyTree::<u64>::new();
    for leaf in &leaves {
        original.append(*leaf).unwrap();
    }
    let proof = original.prove_inclusion(7).unwrap();

    let reconstructed = AppendOnlyTree::<u64>::reconstruct_from_leaves(leaves).unwrap();

    verify_inclusion(&reconstructed.root(), &7u64, 7, &proof).unwrap();
}

#[test]
fn consistency_proof_between_equal_size_trees_verifies() {
    let leaves: Vec<u64> = (0..10).collect();
    let mut original = AppendOnlyTree::<u64>::new();
    for leaf in &leaves {
        original.append(*leaf).unwrap();
    }
    let reconstructed = AppendOnlyTree::<u64>::reconstruct_from_leaves(leaves).unwrap();

    let proof = original.prove_consistency(10, 10).unwrap();

    verify_consistency(&original.root(), &reconstructed.root(), &proof).unwrap();
}

// --- Raw-leaf path (transparency-log invariant) ---

/// Golden RFC 6962 leaf hash of the raw bytes `leaf-0`:
/// `SHA-256(0x00 ‖ "leaf-0")`, reproducible with standard tooling via
/// `(printf '\x00'; printf 'leaf-0') | shasum -a 256`.
const GOLDEN_RAW_LEAF_HASH_HEX: &str =
    "305df59f9590c3c9ac63d2b2743c388e3792449078cebf7fb3dbe6471643b2b7";

/// Sentinel: the hash the FROZEN postcard path would produce for the same
/// bytes (`SHA-256(0x00 ‖ 0x06 ‖ "leaf-0")`, with postcard's length varint).
/// The raw path must never equal it — a regression that reintroduces
/// postcard into the raw path is caught here.
const POSTCARD_DIVERGENCE_SENTINEL_HEX: &str =
    "a905673a4e120c687374d7e844af1048212cb9800d1726a7380b62447ccf1a4f";

/// Golden root of the raw-leaf tree over `leaf-0`, `leaf-1`, `leaf-2`.
const GOLDEN_ROOT_3_HEX: &str = "cf763a041c81ceef1578a6083f75c61bef2e0014f2a3e683a97fcfca5be7f19a";

/// Golden root of the 2-leaf prefix (`leaf-0`, `leaf-1`).
const GOLDEN_ROOT_2_HEX: &str = "60a53eed0de87a90c8e59427c59c46253c33a76a09502a51801300927b7e6bdc";

/// The RFC 6962 empty-tree root: `SHA-256("")`.
const EMPTY_ROOT_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn golden_raw_tree() -> AppendOnlyTree<RawLeaf> {
    let mut tree = AppendOnlyTree::<RawLeaf>::new();
    tree.append_raw(b"leaf-0");
    tree.append_raw(b"leaf-1");
    tree.append_raw(b"leaf-2");
    tree
}

#[test]
fn append_raw_returns_incrementing_sizes_starting_at_one() {
    let mut tree = AppendOnlyTree::<RawLeaf>::new();

    assert_eq!(tree.append_raw(b"leaf-0"), 1);
    assert_eq!(tree.append_raw(b"leaf-1"), 2);
    assert_eq!(tree.append_raw(b"leaf-2"), 3);
    assert_eq!(tree.len(), 3);
}

#[test]
fn raw_tree_root_equals_directly_built_ct_merkle_tree() {
    // Proves there is no intermediate encoding: the raw tree's root equals
    // the root of a ct-merkle tree fed the same bytes directly.
    let tree = golden_raw_tree();

    let mut direct: ct_merkle::mem_backed_tree::MemoryBackedTree<sha2::Sha256, Vec<u8>> =
        ct_merkle::mem_backed_tree::MemoryBackedTree::new();
    direct.push(b"leaf-0".to_vec());
    direct.push(b"leaf-1".to_vec());
    direct.push(b"leaf-2".to_vec());

    let (root_bytes, count) = tree.root().to_parts();
    assert_eq!(root_bytes.as_slice(), direct.root().as_bytes().as_slice());
    assert_eq!(count, 3);
}

#[test]
fn raw_leaf_hash_matches_golden_vector_and_one_leaf_tree_root() {
    let hash = raw_leaf_hash(b"leaf-0");
    assert_eq!(crate::hex_lower(&hash), GOLDEN_RAW_LEAF_HASH_HEX);

    // A 1-leaf tree's root IS the leaf hash.
    let mut tree = AppendOnlyTree::<RawLeaf>::new();
    tree.append_raw(b"leaf-0");
    let (root_bytes, count) = tree.root().to_parts();
    assert_eq!(root_bytes, hash);
    assert_eq!(count, 1);
}

#[test]
fn raw_leaf_hash_diverges_from_postcard_sentinel() {
    let hash = raw_leaf_hash(b"leaf-0");
    assert_ne!(
        crate::hex_lower(&hash),
        POSTCARD_DIVERGENCE_SENTINEL_HEX,
        "raw path must not hash a postcard length prefix"
    );
}

#[test]
fn raw_tree_roots_match_golden_vectors() {
    let tree = golden_raw_tree();
    let (root3, count3) = tree.root().to_parts();
    assert_eq!(crate::hex_lower(&root3), GOLDEN_ROOT_3_HEX);
    assert_eq!(count3, 3);

    let prefix = AppendOnlyTree::<RawLeaf>::reconstruct_from_raw_leaves([b"leaf-0", b"leaf-1"]);
    let (root2, count2) = prefix.root().to_parts();
    assert_eq!(crate::hex_lower(&root2), GOLDEN_ROOT_2_HEX);
    assert_eq!(count2, 2);
}

#[test]
fn empty_raw_tree_root_is_sha256_of_empty_string() {
    let tree = AppendOnlyTree::<RawLeaf>::new();
    let (root, count) = tree.root().to_parts();
    assert_eq!(crate::hex_lower(&root), EMPTY_ROOT_HEX);
    assert_eq!(count, 0);
}

#[test]
fn reconstruct_from_raw_leaves_reproduces_root() {
    let original = golden_raw_tree();
    let rebuilt = AppendOnlyTree::<RawLeaf>::reconstruct_from_raw_leaves([
        b"leaf-0".as_slice(),
        b"leaf-1".as_slice(),
        b"leaf-2".as_slice(),
    ]);
    assert_eq!(original.root(), rebuilt.root());
}

#[test]
fn empty_leaf_bytes_are_a_valid_raw_leaf() {
    let mut tree = AppendOnlyTree::<RawLeaf>::new();
    assert_eq!(tree.append_raw(b""), 1);

    // The empty leaf's hash is SHA-256(0x00) and equals the 1-leaf root.
    let (root, _count) = tree.root().to_parts();
    assert_eq!(root, raw_leaf_hash(b""));

    let proof = tree.prove_inclusion(0).unwrap();
    verify_inclusion_raw(&tree.root(), b"", 0, &proof).unwrap();
}

#[test]
fn raw_tree_inclusion_and_consistency_proofs_verify() {
    let tree = golden_raw_tree();
    let root = tree.root();

    for (index, leaf) in [b"leaf-0", b"leaf-1", b"leaf-2"].iter().enumerate() {
        let proof = tree.prove_inclusion(index as u64).unwrap();
        verify_inclusion_raw(&root, *leaf, index as u64, &proof).unwrap();
    }

    let prefix = AppendOnlyTree::<RawLeaf>::reconstruct_from_raw_leaves([b"leaf-0", b"leaf-1"]);
    let proof = tree.prove_consistency(2, 3).unwrap();
    verify_consistency(&prefix.root(), &root, &proof).unwrap();
}
