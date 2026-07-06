#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::merkle::proof::{verify_consistency, verify_inclusion};

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
