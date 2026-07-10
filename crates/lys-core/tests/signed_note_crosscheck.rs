//! Second-implementation conformance for D1/D6: cross-check the `lys`
//! signed-note implementation against Cloudflare's independently written
//! [`signed_note`] crate (`c2sp.org/signed-note` in Rust).
//!
//! # Why this exists
//!
//! The primary conformance gate (`go_conformance.rs`) round-trips against
//! the Go `sumdb/note` reference — the format author's implementation. This
//! file adds a SECOND independent implementation, so the evidence reads:
//! byte-identical to the reference AND accepted by a third party's
//! independently authored verifier. Strength comes from independence of
//! authorship; these are the two independent codebases that exist.
//!
//! Pure Rust, no toolchain requirement, runs unconditionally — no skip path.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use lys_core::Ed25519Identity;
use lys_core::checkpoint::{NoteVerifierKey, key_id, sign_note, verify_note};
use signed_note::{Note, StandardSigner, StandardVerifier, VerifierList};

/// Same golden inputs as `go_conformance.rs`, so all three implementations
/// (lys, Go reference, Cloudflare crate) are pinned against one vector.
const GOLDEN_SEED: &[u8; 32] = b"lys-go-conformance-test-seed-01!";
const GOLDEN_NAME: &str = "example.com/lys/test";
const GOLDEN_BODY: &str = "example.com/lys/test\n3\nz3Y6BByBzu8VeKYIP3XGG+8uABTyo+aDqX/Pylvn8Zo=\n";

fn golden_identity() -> (tempfile::TempDir, Ed25519Identity) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("golden.key");
    std::fs::write(&path, GOLDEN_SEED).unwrap();
    let identity = Ed25519Identity::load(&path).unwrap();
    (dir, identity)
}

/// The Cloudflare crate's signer-key text form for the golden identity:
/// `PRIVATE+KEY+<name>+<hex8 key id>+<base64(0x01 ‖ seed)>`.
fn golden_cloudflare_signer_key(identity: &Ed25519Identity) -> String {
    let id = key_id(GOLDEN_NAME, &identity.public_key_bytes()).unwrap();
    let mut blob = vec![0x01u8];
    blob.extend_from_slice(GOLDEN_SEED);
    format!(
        "PRIVATE+KEY+{GOLDEN_NAME}+{}+{}",
        hex_of(&id),
        STANDARD.encode(&blob)
    )
}

fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = s.write_fmt(format_args!("{b:02x}"));
    }
    s
}

#[test]
fn key_id_matches_cloudflare_derivation() {
    let (_dir, identity) = golden_identity();
    let lys_id = key_id(GOLDEN_NAME, &identity.public_key_bytes()).unwrap();

    let mut alg_pubkey = vec![0x01u8];
    alg_pubkey.extend_from_slice(&identity.public_key_bytes());
    let cloudflare_id = signed_note::key_id(GOLDEN_NAME, &alg_pubkey);

    assert_eq!(u32::from_be_bytes(lys_id), cloudflare_id);
}

#[test]
fn verifier_key_spec_parses_in_cloudflare_verifier() {
    let (_dir, identity) = golden_identity();
    let spec = NoteVerifierKey::new(GOLDEN_NAME, identity.public_key_bytes())
        .unwrap()
        .to_spec();
    let verifier = StandardVerifier::new(&spec).expect("lys verifier-key spec rejected");
    assert_eq!(signed_note::Verifier::name(&verifier), GOLDEN_NAME);
}

#[test]
fn lys_signed_note_verifies_under_cloudflare_implementation() {
    let (_dir, identity) = golden_identity();
    let note_text = sign_note(GOLDEN_BODY, GOLDEN_NAME, &identity).unwrap();

    let spec = NoteVerifierKey::new(GOLDEN_NAME, identity.public_key_bytes())
        .unwrap()
        .to_spec();
    let cf_verifier = StandardVerifier::new(&spec).unwrap();
    let known = VerifierList::new(vec![Box::new(cf_verifier)]);

    let note = Note::from_bytes(note_text.as_bytes()).expect("Cloudflare parser rejected the note");
    let (accepted_sigs, unknown_sigs) = note
        .verify(&known)
        .expect("Cloudflare verifier rejected the lys-signed note");
    assert_eq!(accepted_sigs.len(), 1);
    assert!(unknown_sigs.is_empty());
    assert_eq!(note.text(), GOLDEN_BODY.as_bytes());
}

#[test]
fn cloudflare_signed_note_verifies_under_lys_and_is_byte_identical() {
    let (_dir, identity) = golden_identity();

    let signer = StandardSigner::new(&golden_cloudflare_signer_key(&identity))
        .expect("Cloudflare signer rejected the lys seed material");
    let mut note = Note::new(GOLDEN_BODY.as_bytes(), &[]).unwrap();
    note.add_sigs(&[&signer]).unwrap();
    let cloudflare_note = note.to_bytes();

    let verifier = NoteVerifierKey::new(GOLDEN_NAME, identity.public_key_bytes()).unwrap();
    let body =
        verify_note(&cloudflare_note, &verifier).expect("lys rejected the Cloudflare-signed note");
    assert_eq!(body, GOLDEN_BODY);

    // Deterministic Ed25519 over identical note text: the two independent
    // implementations must emit the identical artifact, byte for byte.
    let lys_note = sign_note(GOLDEN_BODY, GOLDEN_NAME, &identity).unwrap();
    assert_eq!(
        cloudflare_note,
        lys_note.as_bytes(),
        "lys and Cloudflare signed_note notes must be byte-identical"
    );
}

#[test]
fn tampered_note_is_rejected_by_both_implementations() {
    let (_dir, identity) = golden_identity();
    let note_text = sign_note(GOLDEN_BODY, GOLDEN_NAME, &identity).unwrap();
    let tampered = note_text.replacen("\n3\n", "\n4\n", 1);

    let verifier = NoteVerifierKey::new(GOLDEN_NAME, identity.public_key_bytes()).unwrap();
    assert!(verify_note(tampered.as_bytes(), &verifier).is_err());

    let spec = NoteVerifierKey::new(GOLDEN_NAME, identity.public_key_bytes())
        .unwrap()
        .to_spec();
    let cf_verifier = StandardVerifier::new(&spec).unwrap();
    let verifiers = VerifierList::new(vec![Box::new(cf_verifier)]);
    let parsed = Note::from_bytes(tampered.as_bytes()).expect("structurally the note still parses");
    assert!(
        parsed.verify(&verifiers).is_err(),
        "Cloudflare implementation accepted a tampered note"
    );
}
