#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::*;
use crate::checkpoint::{NoteVerifierKey, sign_note};
use crate::error::TrustError;
use crate::keys::Ed25519Identity;
use crate::merkle::{AppendOnlyTree, RawLeaf};
use crate::tlog::build::{build_consistency_artifact, build_inclusion_artifact};

const GOLDEN_SEED: &[u8; 32] = b"lys-go-conformance-test-seed-01!";
const GOLDEN_ORIGIN: &str = "example.com/lys/test";

fn golden_identity() -> (tempfile::TempDir, Ed25519Identity) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("golden.key");
    std::fs::write(&path, GOLDEN_SEED).unwrap();
    let identity = Ed25519Identity::load(&path).unwrap();
    (dir, identity)
}

fn golden_tree() -> AppendOnlyTree<RawLeaf> {
    AppendOnlyTree::<RawLeaf>::reconstruct_from_raw_leaves([b"leaf-0", b"leaf-1", b"leaf-2"])
}

fn golden_verifier() -> NoteVerifierKey {
    let (_dir, identity) = golden_identity();
    NoteVerifierKey::new(GOLDEN_ORIGIN, identity.public_key_bytes()).unwrap()
}

fn golden_inclusion() -> InclusionProofArtifact {
    let (_dir, identity) = golden_identity();
    build_inclusion_artifact(&golden_tree(), b"leaf-1", GOLDEN_ORIGIN, &identity, 1).unwrap()
}

fn golden_consistency() -> ConsistencyProofArtifact {
    let (_dir, identity) = golden_identity();
    let prefix = AppendOnlyTree::<RawLeaf>::reconstruct_from_raw_leaves([b"leaf-0", b"leaf-1"]);
    build_consistency_artifact(&prefix, &golden_tree(), GOLDEN_ORIGIN, &identity).unwrap()
}

/// Signs a checkpoint note for the golden log at the given prefix size.
fn checkpoint_for_size(size: usize) -> String {
    let (_dir, identity) = golden_identity();
    let leaves: Vec<&[u8]> = [b"leaf-0".as_slice(), b"leaf-1", b"leaf-2"][..size].to_vec();
    let tree = AppendOnlyTree::<RawLeaf>::reconstruct_from_raw_leaves(leaves);
    let body = crate::checkpoint::CheckpointBody::from_root(GOLDEN_ORIGIN, &tree.root()).unwrap();
    sign_note(&body.encode(), GOLDEN_ORIGIN, &identity).unwrap()
}

fn assert_inclusion_rejected(artifact: &InclusionProofArtifact, leaf: &[u8], label: &str) {
    let err = verify_inclusion_artifact(artifact, leaf, &golden_verifier()).unwrap_err();
    assert!(
        matches!(err, TrustError::LogArtifactVerification),
        "tamper {label} must collapse to LogArtifactVerification"
    );
}

fn assert_consistency_rejected(artifact: &ConsistencyProofArtifact, label: &str) {
    let err = verify_consistency_artifact(artifact, &golden_verifier()).unwrap_err();
    assert!(
        matches!(err, TrustError::LogArtifactVerification),
        "tamper {label} must collapse to LogArtifactVerification"
    );
}

// --- Positive paths ---

#[test]
fn valid_inclusion_artifact_verifies_and_returns_checkpoint_body() {
    let body =
        verify_inclusion_artifact(&golden_inclusion(), b"leaf-1", &golden_verifier()).unwrap();
    assert_eq!(body.origin(), GOLDEN_ORIGIN);
    assert_eq!(body.tree_size(), 3);
}

#[test]
fn valid_consistency_artifact_verifies_and_returns_both_bodies() {
    let (body_1, body_2) =
        verify_consistency_artifact(&golden_consistency(), &golden_verifier()).unwrap();
    assert_eq!(body_1.origin(), GOLDEN_ORIGIN);
    assert_eq!(body_2.origin(), GOLDEN_ORIGIN);
    assert_eq!(body_1.tree_size(), 2);
    assert_eq!(body_2.tree_size(), 3);
}

#[test]
fn empty_hashes_are_legal_for_a_single_leaf_tree() {
    let (_dir, identity) = golden_identity();
    let mut tree = AppendOnlyTree::<RawLeaf>::new();
    tree.append_raw(b"only-leaf");
    let artifact =
        build_inclusion_artifact(&tree, b"only-leaf", GOLDEN_ORIGIN, &identity, 0).unwrap();
    assert!(artifact.hashes.is_empty());

    let body = verify_inclusion_artifact(&artifact, b"only-leaf", &golden_verifier()).unwrap();
    assert_eq!(body.tree_size(), 1);
}

#[test]
fn artifacts_survive_json_round_trip() {
    let inclusion = golden_inclusion();
    let json = serde_json::to_string_pretty(&inclusion).unwrap();
    let parsed: InclusionProofArtifact = serde_json::from_str(&json).unwrap();
    verify_inclusion_artifact(&parsed, b"leaf-1", &golden_verifier()).unwrap();

    let consistency = golden_consistency();
    let json = serde_json::to_string_pretty(&consistency).unwrap();
    let parsed: ConsistencyProofArtifact = serde_json::from_str(&json).unwrap();
    verify_consistency_artifact(&parsed, &golden_verifier()).unwrap();
}

// --- Inclusion tampers (§6.4, lys-core half) ---

#[test]
fn inclusion_rejects_kind_confusion() {
    let mut artifact = golden_inclusion();
    artifact.format = CONSISTENCY_PROOF_FORMAT.to_string();
    assert_inclusion_rejected(&artifact, b"leaf-1", "format swapped to consistency");

    let mut artifact = golden_inclusion();
    artifact.format = "lys/log-inclusion-proof/v2".to_string();
    assert_inclusion_rejected(&artifact, b"leaf-1", "unknown format version");
}

#[test]
fn inclusion_rejects_size_and_index_tampers() {
    let mut artifact = golden_inclusion();
    artifact.tree_size = 4;
    assert_inclusion_rejected(&artifact, b"leaf-1", "tree_size off by one (up)");

    let mut artifact = golden_inclusion();
    artifact.tree_size = 2;
    assert_inclusion_rejected(&artifact, b"leaf-1", "tree_size off by one (down)");

    let mut artifact = golden_inclusion();
    artifact.leaf_index = 0;
    assert_inclusion_rejected(&artifact, b"leaf-1", "leaf_index off by one");

    let mut artifact = golden_inclusion();
    artifact.leaf_index = artifact.tree_size;
    assert_inclusion_rejected(&artifact, b"leaf-1", "leaf_index == tree_size");
}

#[test]
fn inclusion_rejects_json_unsafe_tree_size_before_checkpoint_work() {
    // §6.5 verify-side: handcrafted artifact at exactly 2^53.
    let mut artifact = golden_inclusion();
    artifact.tree_size = MAX_JSON_TREE_SIZE;
    artifact.leaf_index = 1;
    assert_inclusion_rejected(&artifact, b"leaf-1", "tree_size at 2^53");
}

#[test]
fn inclusion_rejects_hash_tampers() {
    // Bit-flipped node.
    let mut artifact = golden_inclusion();
    let mut node = STANDARD.decode(&artifact.hashes[0]).unwrap();
    node[0] ^= 0x01;
    artifact.hashes[0] = STANDARD.encode(&node);
    assert_inclusion_rejected(&artifact, b"leaf-1", "bit-flipped hash");

    // Wrong-length nodes (31 and 33 bytes).
    for len in [31usize, 33] {
        let mut artifact = golden_inclusion();
        artifact.hashes[0] = STANDARD.encode(vec![0u8; len]);
        assert_inclusion_rejected(&artifact, b"leaf-1", "wrong-length hash");
    }

    // Non-canonical base64 (unpadded).
    let mut artifact = golden_inclusion();
    artifact.hashes[0] = artifact.hashes[0].trim_end_matches('=').to_string();
    assert_inclusion_rejected(&artifact, b"leaf-1", "unpadded base64 hash");

    // Extra hash appended.
    let mut artifact = golden_inclusion();
    let extra = artifact.hashes[0].clone();
    artifact.hashes.push(extra);
    assert_inclusion_rejected(&artifact, b"leaf-1", "extra hash");

    // Hash removed.
    let mut artifact = golden_inclusion();
    artifact.hashes.pop();
    assert_inclusion_rejected(&artifact, b"leaf-1", "hash removed");

    // Above the 64-entry cap.
    let mut artifact = golden_inclusion();
    let filler = STANDARD.encode([0u8; 32]);
    artifact.hashes = vec![filler; 65];
    assert_inclusion_rejected(&artifact, b"leaf-1", "65 hashes (cap)");
}

#[test]
fn inclusion_rejects_rechunked_hash_entries() {
    // The per-entry 32-byte rule in isolation: these re-chunks decode to a
    // concatenation BYTE-IDENTICAL to the honest proof, so the downstream
    // multiple-of-32 and root-recomputation checks would accept them — only
    // the per-entry rule (WIRE-FORMATS §3.1/§3.3: each entry is one 32-byte
    // node) rejects.
    let honest = golden_inclusion();
    assert_eq!(honest.hashes.len(), 2, "golden path must have two nodes");
    let node_0 = STANDARD.decode(&honest.hashes[0]).unwrap();
    let node_1 = STANDARD.decode(&honest.hashes[1]).unwrap();
    let concat: Vec<u8> = [node_0.as_slice(), node_1.as_slice()].concat();

    // Both nodes re-chunked into ONE 64-byte entry.
    let mut artifact = golden_inclusion();
    artifact.hashes = vec![STANDARD.encode(&concat)];
    assert_inclusion_rejected(&artifact, b"leaf-1", "one 64-byte entry");

    // The same 64 bytes re-split at 16/48.
    let mut artifact = golden_inclusion();
    artifact.hashes = vec![
        STANDARD.encode(&concat[..16]),
        STANDARD.encode(&concat[16..]),
    ];
    assert_inclusion_rejected(&artifact, b"leaf-1", "16-byte + 48-byte split");
}

#[test]
fn consistency_rejects_rechunked_hash_entries() {
    // Same per-entry rule, consistency side: the honest nodes re-chunked
    // into 16-byte entries decode to a byte-identical concatenation (still
    // a multiple of 32), so only the per-entry 32-byte rule rejects.
    let honest = golden_consistency();
    assert!(!honest.hashes.is_empty(), "golden proof must have nodes");
    let concat: Vec<u8> = honest
        .hashes
        .iter()
        .flat_map(|entry| STANDARD.decode(entry).unwrap())
        .collect();

    let mut artifact = golden_consistency();
    artifact.hashes = concat
        .chunks(16)
        .map(|chunk| STANDARD.encode(chunk))
        .collect();
    assert_consistency_rejected(&artifact, "nodes re-chunked into 16-byte entries");
}

#[test]
fn inclusion_rejects_checkpoint_substitution_and_tampers() {
    // Same log, different size: signature valid, tree_size cross-check
    // fails (redundancy checked, not trusted).
    let mut artifact = golden_inclusion();
    artifact.checkpoint = checkpoint_for_size(2);
    assert_inclusion_rejected(&artifact, b"leaf-1", "checkpoint of different size");

    // Doctored checkpoint text (signature breaks).
    let mut artifact = golden_inclusion();
    artifact.checkpoint = artifact.checkpoint.replacen("z3Y6", "z3Y7", 1);
    assert_inclusion_rejected(&artifact, b"leaf-1", "doctored checkpoint root");

    // Checkpoint validly re-signed under a different origin/keyname by the
    // same key: candidate filtering + origin binding kill it.
    let (_dir, identity) = golden_identity();
    let foreign_body = "other.example/log\n3\nz3Y6BByBzu8VeKYIP3XGG+8uABTyo+aDqX/Pylvn8Zo=\n";
    let mut artifact = golden_inclusion();
    artifact.checkpoint = sign_note(foreign_body, "other.example/log", &identity).unwrap();
    assert_inclusion_rejected(&artifact, b"leaf-1", "checkpoint from different origin");
}

#[test]
fn inclusion_rejects_wrong_leaf_bytes() {
    let artifact = golden_inclusion();
    assert_inclusion_rejected(&artifact, b"leaf-0", "wrong leaf bytes");
    assert_inclusion_rejected(&artifact, b"", "empty leaf bytes");
    // The postcard encoding of the true leaf (§2 sentinel).
    assert_inclusion_rejected(&artifact, b"\x06leaf-1", "postcard-encoded leaf bytes");
}

#[test]
fn inclusion_rejects_wrong_verifier_key() {
    // A different identity's verifier key under the same name: the key ID
    // differs, so no signature candidate matches.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("other.key");
    std::fs::write(&path, b"a-completely-different-seed-32b!").unwrap();
    let other = Ed25519Identity::load(&path).unwrap();
    let other_verifier = NoteVerifierKey::new(GOLDEN_ORIGIN, other.public_key_bytes()).unwrap();

    let err =
        verify_inclusion_artifact(&golden_inclusion(), b"leaf-1", &other_verifier).unwrap_err();
    assert!(matches!(err, TrustError::LogArtifactVerification));
}

// --- Consistency tampers ---

#[test]
fn consistency_rejects_kind_confusion() {
    let mut artifact = golden_consistency();
    artifact.format = INCLUSION_PROOF_FORMAT.to_string();
    assert_consistency_rejected(&artifact, "format swapped to inclusion");
}

#[test]
fn consistency_rejects_size_invariant_violations() {
    // Equal sizes (R8 strict inequality).
    let mut artifact = golden_consistency();
    artifact.tree_size_1 = artifact.tree_size_2;
    assert_consistency_rejected(&artifact, "tree_size_1 == tree_size_2");

    // Zero old size.
    let mut artifact = golden_consistency();
    artifact.tree_size_1 = 0;
    assert_consistency_rejected(&artifact, "tree_size_1 = 0");

    // Off-by-one sizes.
    let mut artifact = golden_consistency();
    artifact.tree_size_1 = 1;
    assert_consistency_rejected(&artifact, "tree_size_1 off by one");

    let mut artifact = golden_consistency();
    artifact.tree_size_2 = 4;
    assert_consistency_rejected(&artifact, "tree_size_2 off by one");

    // §6.5 verify-side: tree_size_2 at exactly 2^53.
    let mut artifact = golden_consistency();
    artifact.tree_size_2 = MAX_JSON_TREE_SIZE;
    assert_consistency_rejected(&artifact, "tree_size_2 at 2^53");
}

#[test]
fn consistency_rejects_checkpoint_swaps_and_substitution() {
    // Old and new checkpoints exchanged.
    let mut artifact = golden_consistency();
    std::mem::swap(&mut artifact.checkpoint_1, &mut artifact.checkpoint_2);
    assert_consistency_rejected(&artifact, "checkpoints swapped");

    // checkpoint_2 replaced by a same-key note for a different origin.
    let (_dir, identity) = golden_identity();
    let foreign_body = "other.example/log\n3\nz3Y6BByBzu8VeKYIP3XGG+8uABTyo+aDqX/Pylvn8Zo=\n";
    let mut artifact = golden_consistency();
    artifact.checkpoint_2 = sign_note(foreign_body, "other.example/log", &identity).unwrap();
    assert_consistency_rejected(&artifact, "checkpoint_2 from different origin");

    // checkpoint_1 replaced by the same log at a different size.
    let mut artifact = golden_consistency();
    artifact.checkpoint_1 = checkpoint_for_size(1);
    assert_consistency_rejected(&artifact, "checkpoint_1 of different size");
}

#[test]
fn consistency_rejects_hash_tampers() {
    // Bit-flipped node.
    let mut artifact = golden_consistency();
    let mut node = STANDARD.decode(&artifact.hashes[0]).unwrap();
    node[31] ^= 0x80;
    artifact.hashes[0] = STANDARD.encode(&node);
    assert_consistency_rejected(&artifact, "bit-flipped hash");

    // Empty proof where a nonempty one is required (old < new strictly
    // implies a nonempty consistency proof; ct-merkle rejects via root
    // recomputation / proof-length mismatch).
    let mut artifact = golden_consistency();
    artifact.hashes.clear();
    assert_consistency_rejected(&artifact, "empty hashes");

    // Above the 128-entry cap.
    let mut artifact = golden_consistency();
    let filler = STANDARD.encode([0u8; 32]);
    artifact.hashes = vec![filler; 129];
    assert_consistency_rejected(&artifact, "129 hashes (cap)");
}

// --- Non-oracle discipline ---

#[test]
fn different_tamper_classes_yield_identical_error_displays() {
    // The strongest non-oracle assertion available at the library level:
    // the Display of the collapse error is byte-identical across tamper
    // classes (it carries no fields at all).
    let mut kind_confused = golden_inclusion();
    kind_confused.format = CONSISTENCY_PROOF_FORMAT.to_string();
    let err_a =
        verify_inclusion_artifact(&kind_confused, b"leaf-1", &golden_verifier()).unwrap_err();

    let err_b = verify_inclusion_artifact(&golden_inclusion(), b"wrong-leaf", &golden_verifier())
        .unwrap_err();

    let mut doctored = golden_inclusion();
    doctored.checkpoint = doctored.checkpoint.replacen("z3Y6", "z3Y7", 1);
    let err_c = verify_inclusion_artifact(&doctored, b"leaf-1", &golden_verifier()).unwrap_err();

    assert_eq!(err_a.to_string(), err_b.to_string());
    assert_eq!(err_b.to_string(), err_c.to_string());
    assert_eq!(err_a.to_string(), "log artifact verification failed");
}
