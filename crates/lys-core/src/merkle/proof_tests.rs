#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::merkle::tree::AppendOnlyTree;

#[test]
fn inclusion_proof_byte_roundtrip_verifies() {
    let mut tree = AppendOnlyTree::<u64>::new();
    tree.append(10).unwrap();
    tree.append(20).unwrap();
    tree.append(30).unwrap();

    let root = tree.root();
    let proof = tree.prove_inclusion(1).unwrap();
    let decoded = InclusionProof::try_from_bytes(proof.as_bytes().to_vec()).unwrap();

    verify_inclusion(&root, &20u64, 1, &decoded).unwrap();
}

#[test]
fn malformed_inclusion_proof_bytes_return_trust_error() {
    let err = InclusionProof::try_from_bytes(vec![1, 2, 3]).unwrap_err();
    assert!(matches!(err, TrustError::MerkleTree { .. }));
}

#[test]
fn consistency_proof_byte_roundtrip_verifies() {
    let mut tree = AppendOnlyTree::<u64>::new();
    tree.append(1).unwrap();
    tree.append(2).unwrap();
    let old_root = tree.root();
    tree.append(3).unwrap();
    tree.append(4).unwrap();
    let new_root = tree.root();

    let proof = tree.prove_consistency(2, 4).unwrap();
    let decoded = ConsistencyProof::try_from_bytes(proof.as_bytes().to_vec()).unwrap();

    verify_consistency(&old_root, &new_root, &decoded).unwrap();
}

#[test]
fn malformed_consistency_proof_bytes_return_trust_error() {
    let err = ConsistencyProof::try_from_bytes(vec![1, 2, 3]).unwrap_err();
    assert!(matches!(err, TrustError::MerkleTree { .. }));
}

#[test]
fn root_hash_parts_roundtrip_preserves_equality_and_accessors() {
    let mut tree = AppendOnlyTree::<u64>::new();
    tree.append(1).unwrap();
    tree.append(2).unwrap();
    tree.append(3).unwrap();
    let root = tree.root();

    let (bytes, count) = root.to_parts();
    let rebuilt = RootHash::from_parts(bytes, count);

    assert_eq!(rebuilt, root);
    assert_eq!(bytes.as_slice(), root.as_bytes());
    assert_eq!(count, root.num_leaves());
    assert_eq!(count, 3);
}

/// The defining transparency-log property: a third party holding ONLY the
/// published primitives — root bytes, leaf count, and serialized proof
/// bytes — verifies inclusion and consistency without any access to the
/// tree that produced them.
#[test]
fn external_verifier_verifies_proofs_from_published_primitives_only() {
    // --- Log operator side: build the tree, publish primitives. ---
    let mut tree = AppendOnlyTree::<u64>::new();
    tree.append(10).unwrap();
    tree.append(20).unwrap();
    let (published_old_bytes, published_old_count) = tree.root().to_parts();
    tree.append(30).unwrap();
    tree.append(40).unwrap();
    let (published_new_bytes, published_new_count) = tree.root().to_parts();
    let published_inclusion_bytes = tree.prove_inclusion(2).unwrap().as_bytes().to_vec();
    let published_consistency_bytes = tree.prove_consistency(2, 4).unwrap().as_bytes().to_vec();
    // The external verifier has no tree access.
    drop(tree);

    // --- External verifier side: published primitives only. ---
    let old_root = RootHash::from_parts(published_old_bytes, published_old_count);
    let new_root = RootHash::from_parts(published_new_bytes, published_new_count);
    let inclusion = InclusionProof::try_from_bytes(published_inclusion_bytes).unwrap();
    let consistency = ConsistencyProof::try_from_bytes(published_consistency_bytes).unwrap();

    verify_inclusion(&new_root, &30u64, 2, &inclusion).unwrap();
    verify_consistency(&old_root, &new_root, &consistency).unwrap();
}

#[test]
fn from_parts_with_wrong_leaf_count_fails_verification() {
    let mut tree = AppendOnlyTree::<u64>::new();
    tree.append(10).unwrap();
    tree.append(20).unwrap();
    let (old_bytes, old_count) = tree.root().to_parts();
    tree.append(30).unwrap();
    tree.append(40).unwrap();
    let (new_bytes, new_count) = tree.root().to_parts();
    let inclusion = tree.prove_inclusion(2).unwrap();
    let consistency = tree.prove_consistency(2, 4).unwrap();

    // Correct bytes, wrong leaf count: both proof kinds must be rejected.
    let miscounted_new = RootHash::from_parts(new_bytes, new_count + 1);
    assert!(verify_inclusion(&miscounted_new, &30u64, 2, &inclusion).is_err());

    let good_old = RootHash::from_parts(old_bytes, old_count);
    assert!(verify_consistency(&good_old, &miscounted_new, &consistency).is_err());

    let miscounted_old = RootHash::from_parts(old_bytes, old_count + 1);
    let good_new = RootHash::from_parts(new_bytes, new_count);
    assert!(verify_consistency(&miscounted_old, &good_new, &consistency).is_err());
}

// --- Raw-leaf verification (transparency-log invariant) ---

use crate::merkle::leaf::raw_leaf_hash;
use crate::merkle::tree::RawLeaf;

fn raw_tree(leaves: &[&[u8]]) -> AppendOnlyTree<RawLeaf> {
    let mut tree = AppendOnlyTree::<RawLeaf>::new();
    for leaf in leaves {
        tree.append_raw(leaf);
    }
    tree
}

#[test]
fn verify_inclusion_raw_accepts_correct_leaf_and_rejects_tampering() {
    let tree = raw_tree(&[b"leaf-0", b"leaf-1", b"leaf-2"]);
    let root = tree.root();
    let proof = tree.prove_inclusion(1).unwrap();

    // Accept: right bytes, right index, right root.
    verify_inclusion_raw(&root, b"leaf-1", 1, &proof).unwrap();

    // Reject: wrong bytes.
    assert!(verify_inclusion_raw(&root, b"leaf-x", 1, &proof).is_err());

    // Reject: wrong index.
    assert!(verify_inclusion_raw(&root, b"leaf-1", 0, &proof).is_err());
    assert!(verify_inclusion_raw(&root, b"leaf-1", 2, &proof).is_err());

    // Reject: wrong root.
    let other = raw_tree(&[b"leaf-0", b"leaf-x", b"leaf-2"]);
    assert!(verify_inclusion_raw(&other.root(), b"leaf-1", 1, &proof).is_err());
}

#[test]
fn verify_inclusion_raw_rejects_postcard_encoding_of_true_leaf() {
    // Sentinel for the leaf-hash transparency invariant: the postcard
    // encoding of the true leaf (length varint 0x06 then the bytes) must
    // NOT verify where the raw bytes do.
    let tree = raw_tree(&[b"leaf-0", b"leaf-1", b"leaf-2"]);
    let root = tree.root();
    let proof = tree.prove_inclusion(0).unwrap();

    verify_inclusion_raw(&root, b"leaf-0", 0, &proof).unwrap();
    assert!(verify_inclusion_raw(&root, b"\x06leaf-0", 0, &proof).is_err());
}

#[test]
fn interior_node_preimage_does_not_verify_as_a_leaf() {
    // RFC 6962 prefix confusion (0x00 leaf vs 0x01 node domain
    // separation): a crafted "leaf" whose bytes are the concatenated child
    // hashes must not verify at any position implying the interior node.
    let tree = raw_tree(&[b"leaf-0", b"leaf-1"]);
    let (root2_bytes, _count) = tree.root().to_parts();

    let mut forged_leaf = Vec::with_capacity(64);
    forged_leaf.extend_from_slice(&raw_leaf_hash(b"leaf-0"));
    forged_leaf.extend_from_slice(&raw_leaf_hash(b"leaf-1"));

    // If domain separation were broken, the 2-leaf root would equal the
    // "1-leaf tree" root over the forged leaf (empty inclusion path).
    let empty_proof = InclusionProof::try_from_bytes(Vec::new()).unwrap();
    let root_as_single = RootHash::from_parts(root2_bytes, 1);
    assert!(verify_inclusion_raw(&root_as_single, &forged_leaf, 0, &empty_proof).is_err());

    // Nor does the forged leaf verify anywhere in the real 2-leaf tree.
    let root = tree.root();
    for index in 0..2 {
        let proof = tree.prove_inclusion(index).unwrap();
        assert!(verify_inclusion_raw(&root, &forged_leaf, index, &proof).is_err());
    }

    // And the true node hash differs from hashing the forged leaf as a
    // leaf: SHA-256(0x01 ‖ h0 ‖ h1) != SHA-256(0x00 ‖ h0 ‖ h1).
    assert_ne!(root2_bytes, raw_leaf_hash(&forged_leaf));
}

#[test]
fn from_parts_with_wrong_root_bytes_fails_verification() {
    let mut tree = AppendOnlyTree::<u64>::new();
    tree.append(10).unwrap();
    tree.append(20).unwrap();
    let (old_bytes, old_count) = tree.root().to_parts();
    tree.append(30).unwrap();
    tree.append(40).unwrap();
    let (new_bytes, new_count) = tree.root().to_parts();
    let inclusion = tree.prove_inclusion(2).unwrap();
    let consistency = tree.prove_consistency(2, 4).unwrap();

    // Correct leaf count, corrupted hash bytes: both proof kinds must be
    // rejected.
    let mut corrupted_new_bytes = new_bytes;
    corrupted_new_bytes[0] ^= 0xff;
    let corrupted_new = RootHash::from_parts(corrupted_new_bytes, new_count);
    assert!(verify_inclusion(&corrupted_new, &30u64, 2, &inclusion).is_err());

    let good_old = RootHash::from_parts(old_bytes, old_count);
    assert!(verify_consistency(&good_old, &corrupted_new, &consistency).is_err());

    let mut corrupted_old_bytes = old_bytes;
    corrupted_old_bytes[31] ^= 0x01;
    let corrupted_old = RootHash::from_parts(corrupted_old_bytes, old_count);
    let good_new = RootHash::from_parts(new_bytes, new_count);
    assert!(verify_consistency(&corrupted_old, &good_new, &consistency).is_err());
}
