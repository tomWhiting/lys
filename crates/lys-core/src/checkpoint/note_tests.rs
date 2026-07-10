#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

use super::*;
use crate::error::TrustError;
use crate::keys::Ed25519Identity;

/// Fixed test seed: the 32 ASCII bytes `"lys-go-conformance-test-seed-01!"`.
const GOLDEN_SEED: &[u8; 32] = b"lys-go-conformance-test-seed-01!";

const GOLDEN_NAME: &str = "example.com/lys/test";

/// Golden checkpoint body (size-3 raw-leaf tree), byte-exact.
const GOLDEN_BODY: &str = "example.com/lys/test\n3\nz3Y6BByBzu8VeKYIP3XGG+8uABTyo+aDqX/Pylvn8Zo=\n";

/// Golden signature blob: base64(key ID ‖ Ed25519 signature over the body
/// including its trailing newline). Byte-identical to Go `note.Sign`
/// output for the same inputs (verified during design).
const GOLDEN_SIG_BLOB_B64: &str =
    "UlgM2S4MVZwL9PUGADbPhidG6yKCC0hCE+sx7iXFboC6/rex00vtEy4d33ODa1g0afYmx36opQUAXnwdUl9E7eE28QU=";

/// Golden Ed25519 signature (hex) over the golden body.
const GOLDEN_SIG_HEX: &str = "2e0c559c0bf4f5060036cf862746eb22820b484213eb31ee25c56e80bafeb7b1d34bed132e1ddf73836b583469f626c77ea8a505005e7c1d525f44ede136f105";

const GOLDEN_KEY_ID: [u8; 4] = [0x52, 0x58, 0x0c, 0xd9];

fn golden_note() -> String {
    format!("{GOLDEN_BODY}\n\u{2014} {GOLDEN_NAME} {GOLDEN_SIG_BLOB_B64}\n")
}

fn golden_identity() -> (tempfile::TempDir, Ed25519Identity) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("golden.key");
    std::fs::write(&path, GOLDEN_SEED).unwrap();
    let identity = Ed25519Identity::load(&path).unwrap();
    (dir, identity)
}

fn golden_verifier() -> NoteVerifierKey {
    let (_dir, identity) = golden_identity();
    NoteVerifierKey::new(GOLDEN_NAME, identity.public_key_bytes()).unwrap()
}

// --- Golden vectors ---

#[test]
fn sign_note_emits_exact_golden_bytes() {
    let (_dir, identity) = golden_identity();
    let note = sign_note(GOLDEN_BODY, GOLDEN_NAME, &identity).unwrap();
    assert_eq!(note, golden_note());
}

#[test]
fn signature_line_prefix_is_exact_em_dash_bytes() {
    // Assert on the raw note bytes, not via string contains: the four
    // bytes after the blank line must be E2 80 94 20 (U+2014, space).
    let note = golden_note();
    let bytes = note.as_bytes();
    let sig_line_start = GOLDEN_BODY.len() + 1;
    assert_eq!(
        &bytes[sig_line_start..sig_line_start + 4],
        &[0xe2, 0x80, 0x94, 0x20]
    );
}

#[test]
fn key_id_matches_golden_and_hand_computed_sha256() {
    let (_dir, identity) = golden_identity();
    let pubkey = identity.public_key_bytes();
    assert_eq!(
        crate::hex_lower(&pubkey),
        "0cfd0fd81b16accbc5230cf45cba9d4b937d827c6c8dbd44a144e5aba571b9e2"
    );

    let id = key_id(GOLDEN_NAME, &pubkey).unwrap();
    assert_eq!(id, GOLDEN_KEY_ID);

    // Recompute SHA-256(name ‖ 0x0A ‖ 0x01 ‖ pubkey) by hand.
    let mut hasher = Sha256::new();
    hasher.update(GOLDEN_NAME.as_bytes());
    hasher.update([0x0a]);
    hasher.update([0x01]);
    hasher.update(pubkey);
    let digest = hasher.finalize();
    assert_eq!(&digest[..4], &id);
}

#[test]
fn key_id_rejects_invalid_name() {
    let (_dir, identity) = golden_identity();
    let err = key_id("bad name", &identity.public_key_bytes()).unwrap_err();
    assert!(matches!(err, TrustError::VerifierKey { .. }));
}

#[test]
fn signature_covers_body_including_trailing_newline_golden_hex() {
    let (_dir, identity) = golden_identity();
    let signature = identity.sign(GOLDEN_BODY.as_bytes());
    assert_eq!(crate::hex_lower(&signature), GOLDEN_SIG_HEX);

    // The golden blob is exactly key ID ‖ that signature.
    let blob = STANDARD.decode(GOLDEN_SIG_BLOB_B64).unwrap();
    assert_eq!(&blob[..4], &GOLDEN_KEY_ID);
    assert_eq!(&blob[4..], &signature);
}

#[test]
fn verify_note_accepts_golden_and_returns_body() {
    let body = verify_note(golden_note().as_bytes(), &golden_verifier()).unwrap();
    assert_eq!(body, GOLDEN_BODY);
}

#[test]
fn verify_checkpoint_accepts_golden_and_parses_body() {
    let body = verify_checkpoint(golden_note().as_bytes(), &golden_verifier()).unwrap();
    assert_eq!(body.origin(), GOLDEN_NAME);
    assert_eq!(body.tree_size(), 3);
    let (root, count) = body.to_root().to_parts();
    assert_eq!(
        crate::hex_lower(&root),
        "cf763a041c81ceef1578a6083f75c61bef2e0014f2a3e683a97fcfca5be7f19a"
    );
    assert_eq!(count, 3);
}

#[test]
fn sign_then_verify_round_trips_for_other_bodies() {
    let (_dir, identity) = golden_identity();
    let verifier = golden_verifier();
    for body in [
        "example.com/lys/test\n0\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n",
        "example.com/lys/test\n1\nMF31n5WQw8msY9KydDw4jjeSRJB4zr9/s9vmRxZDsrc=\n",
    ] {
        let note = sign_note(body, GOLDEN_NAME, &identity).unwrap();
        assert_eq!(verify_note(note.as_bytes(), &verifier).unwrap(), body);
    }
}

// --- sign_note preconditions ---

#[test]
fn sign_note_rejects_invalid_bodies_and_names() {
    let (_dir, identity) = golden_identity();
    // (a) of the trailing-newline boundary: body lacking the trailing
    // newline is refused at signing time.
    let no_newline = GOLDEN_BODY.trim_end_matches('\n');
    for (body, name) in [
        ("", GOLDEN_NAME),
        (no_newline, GOLDEN_NAME),
        ("body\nwith\n\nblank line\n", GOLDEN_NAME),
        ("body\rwith carriage return\n", GOLDEN_NAME),
        ("body\twith tab\n", GOLDEN_NAME),
        (GOLDEN_BODY, "bad name"),
        (GOLDEN_BODY, "bad+name"),
        (GOLDEN_BODY, ""),
    ] {
        let err = sign_note(body, name, &identity).unwrap_err();
        assert!(
            matches!(err, TrustError::CheckpointEncoding { .. }),
            "body: {body:?}, name: {name:?}"
        );
    }
}

// --- Trailing-newline boundary, both directions ---

#[test]
fn signature_over_body_without_trailing_newline_is_rejected() {
    // (b): construct a signature over the body WITHOUT its trailing
    // newline, splice it into an otherwise-valid note. Verification signs
    // the body WITH the newline, so this must fail.
    let (_dir, identity) = golden_identity();
    let body_without_newline = GOLDEN_BODY.trim_end_matches('\n');
    let signature = identity.sign(body_without_newline.as_bytes());
    let mut blob = GOLDEN_KEY_ID.to_vec();
    blob.extend_from_slice(&signature);
    let spliced = format!(
        "{GOLDEN_BODY}\n\u{2014} {GOLDEN_NAME} {}\n",
        STANDARD.encode(&blob)
    );
    let err = verify_note(spliced.as_bytes(), &golden_verifier()).unwrap_err();
    assert!(matches!(err, TrustError::NoteVerification));
}

#[test]
fn golden_note_with_body_final_newline_removed_is_rejected() {
    // (c): flipping the body's final '\n' off the golden note collapses
    // the blank-line separator; the note must be rejected.
    let tampered = golden_note().replacen("=\n\n", "=\n", 1);
    let err = verify_note(tampered.as_bytes(), &golden_verifier()).unwrap_err();
    assert!(matches!(err, TrustError::NoteVerification));
}

// --- Envelope tampers: every failure collapses to NoteVerification ---

fn assert_rejected(note_bytes: &[u8], label: &str) {
    let err = verify_note(note_bytes, &golden_verifier()).unwrap_err();
    assert!(
        matches!(err, TrustError::NoteVerification),
        "tamper {label} must collapse to NoteVerification"
    );
}

#[test]
fn dash_lookalikes_are_rejected() {
    let note = golden_note();
    assert_rejected(
        note.replacen('\u{2014}', "\u{2013}", 1).as_bytes(),
        "en dash U+2013",
    );
    assert_rejected(
        note.replacen('\u{2014}', "\u{2015}", 1).as_bytes(),
        "horizontal bar U+2015",
    );
    assert_rejected(
        note.replacen('\u{2014}', "--", 1).as_bytes(),
        "double hyphen",
    );
    assert_rejected(
        note.replacen("\u{2014} ", "\u{2014}", 1).as_bytes(),
        "em dash without following space",
    );
}

#[test]
fn structural_tampers_are_rejected() {
    let note = golden_note();
    assert_rejected(b"", "empty note");
    assert_rejected(GOLDEN_BODY.as_bytes(), "body with no signature block");
    assert_rejected(
        note.replacen("\n\n", "\n", 1).as_bytes(),
        "missing blank line",
    );
    assert_rejected(
        format!("{GOLDEN_BODY}\n").as_bytes(),
        "blank line but empty signature block",
    );
    assert_rejected(
        note.trim_end_matches('\n').to_string().as_bytes(),
        "signature block not newline-terminated",
    );
}

#[test]
fn control_characters_and_invalid_utf8_are_rejected() {
    let note = golden_note();
    assert_rejected(
        note.replacen("test\n3", "test\r\n3", 1).as_bytes(),
        "carriage return in body",
    );
    let mut invalid_utf8 = note.into_bytes();
    invalid_utf8[0] = 0xff;
    assert_rejected(&invalid_utf8, "invalid UTF-8 byte");
}

#[test]
fn oversized_note_is_rejected() {
    let mut oversized = golden_note().into_bytes();
    oversized.extend(std::iter::repeat_n(b'a', 1024 * 1024));
    assert_rejected(&oversized, "note above the 1 MiB cap");
}

/// Hand-signs an otherwise-valid golden-key note whose body is a single
/// `'a'`-line of exactly `body_len` bytes (including its trailing `'\n'`),
/// bypassing `sign_note`'s own size cap so verify-side behavior can be
/// tested in isolation.
fn hand_signed_note_with_body_len(body_len: usize) -> String {
    let (_dir, identity) = golden_identity();
    let mut body = "a".repeat(body_len - 1);
    body.push('\n');
    let signature = identity.sign(body.as_bytes());
    let mut blob = GOLDEN_KEY_ID.to_vec();
    blob.extend_from_slice(&signature);
    format!(
        "{body}\n\u{2014} {GOLDEN_NAME} {}\n",
        STANDARD.encode(&blob)
    )
}

/// Envelope overhead around the body for a single golden-key signature
/// line: blank-line `'\n'` (1) + em dash (3) + space (1) + name (20) +
/// space (1) + base64 of 68 blob bytes (92) + trailing `'\n'` (1).
const GOLDEN_NOTE_OVERHEAD: usize = 1 + 3 + 1 + GOLDEN_NAME.len() + 1 + 92 + 1;

#[test]
fn size_cap_boundary_is_exact_for_otherwise_valid_notes() {
    // Isolates the 1 MiB cap: both notes are fully valid except for size,
    // so the one-byte-over rejection can come only from the cap itself.
    let at_cap = hand_signed_note_with_body_len(MAX_NOTE_BYTES - GOLDEN_NOTE_OVERHEAD);
    assert_eq!(at_cap.len(), MAX_NOTE_BYTES);
    let body = verify_note(at_cap.as_bytes(), &golden_verifier()).unwrap();
    assert_eq!(body.len(), MAX_NOTE_BYTES - GOLDEN_NOTE_OVERHEAD);

    let one_over = hand_signed_note_with_body_len(MAX_NOTE_BYTES - GOLDEN_NOTE_OVERHEAD + 1);
    assert_eq!(one_over.len(), MAX_NOTE_BYTES + 1);
    assert_rejected(
        one_over.as_bytes(),
        "otherwise-valid note one byte above the 1 MiB cap",
    );
}

#[test]
fn sign_note_refuses_bodies_that_would_exceed_the_cap() {
    // The emitted-note-re-verifies invariant, both sides of the boundary:
    // a body whose note lands exactly on the cap signs AND re-verifies;
    // one byte more and sign_note refuses instead of emitting a note that
    // verify_note would reject.
    let (_dir, identity) = golden_identity();
    let verifier = golden_verifier();

    let mut at_cap_body = "a".repeat(MAX_NOTE_BYTES - GOLDEN_NOTE_OVERHEAD - 1);
    at_cap_body.push('\n');
    let note = sign_note(&at_cap_body, GOLDEN_NAME, &identity).unwrap();
    assert_eq!(note.len(), MAX_NOTE_BYTES);
    assert_eq!(
        verify_note(note.as_bytes(), &verifier).unwrap(),
        at_cap_body
    );

    let mut over_body = "a".repeat(MAX_NOTE_BYTES - GOLDEN_NOTE_OVERHEAD);
    over_body.push('\n');
    let err = sign_note(&over_body, GOLDEN_NAME, &identity).unwrap_err();
    assert!(matches!(err, TrustError::CheckpointEncoding { .. }));
}

#[test]
fn malformed_signature_blobs_are_rejected() {
    let blob = STANDARD.decode(GOLDEN_SIG_BLOB_B64).unwrap();

    // Blob decoding to fewer than 5 bytes: structurally malformed line.
    let short = STANDARD.encode(&blob[..4]);
    assert_rejected(
        golden_note()
            .replacen(GOLDEN_SIG_BLOB_B64, &short, 1)
            .as_bytes(),
        "blob shorter than 5 bytes",
    );

    // Altered key ID: no candidate matches the verifier.
    let mut altered_id = blob.clone();
    altered_id[0] ^= 0xff;
    assert_rejected(
        golden_note()
            .replacen(GOLDEN_SIG_BLOB_B64, &STANDARD.encode(&altered_id), 1)
            .as_bytes(),
        "altered key ID",
    );

    // 63- and 65-byte signatures: candidate matches but never verifies.
    let sixty_three = STANDARD.encode(&blob[..4 + 63]);
    let mut long = blob.clone();
    long.push(0x00);
    let sixty_five = STANDARD.encode(&long);
    for (bad, label) in [(sixty_three, "63-byte"), (sixty_five, "65-byte")] {
        assert_rejected(
            golden_note()
                .replacen(GOLDEN_SIG_BLOB_B64, &bad, 1)
                .as_bytes(),
            label,
        );
    }

    // Bit-flipped signature body: full Ed25519 verification fails.
    let mut flipped = blob;
    flipped[10] ^= 0x01;
    assert_rejected(
        golden_note()
            .replacen(GOLDEN_SIG_BLOB_B64, &STANDARD.encode(&flipped), 1)
            .as_bytes(),
        "bit-flipped signature",
    );
}

#[test]
fn non_canonical_base64_signature_blobs_are_rejected() {
    // Unpadded re-encoding (padding stripped).
    let unpadded = GOLDEN_SIG_BLOB_B64.trim_end_matches('=');
    assert_rejected(
        golden_note()
            .replacen(GOLDEN_SIG_BLOB_B64, unpadded, 1)
            .as_bytes(),
        "unpadded base64",
    );

    // Non-canonical trailing bits in the final data character
    // ('U' -> 'V' sets a trailing bit that must be zero).
    let non_canonical = GOLDEN_SIG_BLOB_B64.replacen("8QU=", "8QV=", 1);
    assert_rejected(
        golden_note()
            .replacen(GOLDEN_SIG_BLOB_B64, &non_canonical, 1)
            .as_bytes(),
        "non-canonical trailing bits",
    );
}

#[test]
fn any_malformed_signature_line_rejects_the_whole_note() {
    // Go parity: a malformed second line rejects the note even though the
    // first line alone would verify.
    let note = golden_note();
    assert_rejected(
        format!("{note}garbage line\n").as_bytes(),
        "malformed second line",
    );
    assert_rejected(
        format!("{note}\u{2014} {GOLDEN_NAME} not*base64\n").as_bytes(),
        "second line with invalid base64",
    );
    assert_rejected(
        format!("{note}\u{2014} bad+name {GOLDEN_SIG_BLOB_B64}\n").as_bytes(),
        "second line with invalid name",
    );
}

#[test]
fn one_hundred_one_signature_lines_are_rejected_and_one_hundred_accepted() {
    let sig_line = format!("\u{2014} {GOLDEN_NAME} {GOLDEN_SIG_BLOB_B64}\n");

    let hundred = format!("{GOLDEN_BODY}\n{}", sig_line.repeat(100));
    let body = verify_note(hundred.as_bytes(), &golden_verifier()).unwrap();
    assert_eq!(body, GOLDEN_BODY);

    let hundred_one = format!("{GOLDEN_BODY}\n{}", sig_line.repeat(101));
    assert_rejected(hundred_one.as_bytes(), "101 signature lines");
}

// --- Candidate semantics ---

#[test]
fn signature_under_different_name_is_filtered_not_accepted() {
    // Origin-confusion half 1: the same key signing under a different
    // keyname is filtered out (different name AND different key ID).
    let (_dir, identity) = golden_identity();
    let note = sign_note(GOLDEN_BODY, "other.example/log", &identity).unwrap();
    assert_rejected(note.as_bytes(), "signature under a different keyname");
}

#[test]
fn matching_key_id_alone_is_never_authentication() {
    // A candidate whose (name, key ID) match but whose signature is
    // garbage must not be accepted: key IDs are filters, the full Ed25519
    // check decides — and its failure rejects the whole note.
    let mut blob = GOLDEN_KEY_ID.to_vec();
    blob.extend_from_slice(&[0u8; 64]);
    let forged = format!(
        "{GOLDEN_BODY}\n\u{2014} {GOLDEN_NAME} {}\n",
        STANDARD.encode(&blob)
    );
    assert_rejected(forged.as_bytes(), "matching key ID with garbage signature");
}

#[test]
fn failed_known_key_signature_rejects_despite_later_valid_line() {
    // Go parity (note.Open returns InvalidSignatureError; C2SP: a failed
    // known-key signature rejects the whole note): a garbage candidate
    // matching the verifier's (name, key ID) rejects even though a fully
    // valid signature line follows it.
    let mut garbage_blob = GOLDEN_KEY_ID.to_vec();
    garbage_blob.extend_from_slice(&[0u8; 64]);
    let note = format!(
        "{GOLDEN_BODY}\n\u{2014} {GOLDEN_NAME} {}\n\u{2014} {GOLDEN_NAME} {GOLDEN_SIG_BLOB_B64}\n",
        STANDARD.encode(&garbage_blob)
    );
    assert_rejected(
        note.as_bytes(),
        "failed known-key signature before a valid line",
    );
}

#[test]
fn duplicate_lines_after_a_verifying_first_candidate_are_skipped() {
    // Go parity (the `seen` map): once the first matching candidate
    // verifies, later lines by the same signer — even garbage ones — are
    // skipped and the note is accepted.
    let mut garbage_blob = GOLDEN_KEY_ID.to_vec();
    garbage_blob.extend_from_slice(&[0u8; 64]);
    let note = format!(
        "{GOLDEN_BODY}\n\u{2014} {GOLDEN_NAME} {GOLDEN_SIG_BLOB_B64}\n\u{2014} {GOLDEN_NAME} {}\n",
        STANDARD.encode(&garbage_blob)
    );
    let body = verify_note(note.as_bytes(), &golden_verifier()).unwrap();
    assert_eq!(body, GOLDEN_BODY);
}

#[test]
fn golden_signature_spliced_onto_different_body_is_rejected() {
    let other_body = "example.com/lys/test\n2\nYKU+7Q3oepDI5ZQnxZxGJTwzp2oJUCpRgBMAknt+a9w=\n";
    let spliced = format!("{other_body}\n\u{2014} {GOLDEN_NAME} {GOLDEN_SIG_BLOB_B64}\n");
    assert_rejected(spliced.as_bytes(), "golden signature over a different body");
}

// --- Extension lines and smuggling ---

#[test]
fn resigned_extension_line_is_tolerated_by_checkpoint_verification() {
    // A timestamp-like fourth line WITH a re-signed note is accepted as an
    // extension line by design; the parsed body ignores it.
    let (_dir, identity) = golden_identity();
    let body_with_extension = format!("{GOLDEN_BODY}1234567890\n");
    let note = sign_note(&body_with_extension, GOLDEN_NAME, &identity).unwrap();
    let body = verify_checkpoint(note.as_bytes(), &golden_verifier()).unwrap();
    assert_eq!(body.tree_size(), 3);
    assert_eq!(body.encode(), GOLDEN_BODY);
}

#[test]
fn unsigned_extension_line_breaks_the_signature() {
    // The same fourth line inserted WITHOUT re-signing: the signature no
    // longer covers the body text and the note is rejected.
    let tampered = golden_note().replacen("=\n\n", "=\n1234567890\n\n", 1);
    assert_rejected(tampered.as_bytes(), "unsigned extension line");
}

#[test]
fn em_dash_line_inside_body_stays_signed_content() {
    // Signature-line smuggling: a body line that LOOKS like a signature
    // line remains part of the signed body (split happens at the LAST
    // blank line), and the note still verifies with the line intact.
    let (_dir, identity) = golden_identity();
    let smuggled = format!("{GOLDEN_BODY}\u{2014} {GOLDEN_NAME} {GOLDEN_SIG_BLOB_B64}\n");
    let note = sign_note(&smuggled, GOLDEN_NAME, &identity).unwrap();
    let body = verify_note(note.as_bytes(), &golden_verifier()).unwrap();
    assert_eq!(body, smuggled, "smuggled line must remain in the body");
}

#[test]
fn verify_note_splits_at_the_last_blank_line() {
    // Go parity for the split point: Go note.Sign requires only a trailing
    // newline, so a Go-signed note may carry a body CONTAINING a blank
    // line, and Go note.Open splits at bytes.LastIndex("\n\n"). lys
    // sign_note refuses such bodies, so hand-sign one here: verify_note
    // must split at the LAST blank line and return the body intact.
    let (_dir, identity) = golden_identity();
    let blank_line_body = "A\n\nB\n";
    let signature = identity.sign(blank_line_body.as_bytes());
    let mut blob = GOLDEN_KEY_ID.to_vec();
    blob.extend_from_slice(&signature);
    let note = format!(
        "{blank_line_body}\n\u{2014} {GOLDEN_NAME} {}\n",
        STANDARD.encode(&blob)
    );
    let body = verify_note(note.as_bytes(), &golden_verifier()).unwrap();
    assert_eq!(
        body, blank_line_body,
        "the body's own blank line must stay inside the signed body"
    );
}

// --- verify_checkpoint binding and parse collapse ---

#[test]
fn checkpoint_origin_must_equal_verifier_name() {
    // Origin-confusion half 2: an honest key, a validly signed note, but
    // the body's origin differs from the verifier's name (R1 binding).
    let (_dir, identity) = golden_identity();
    let foreign_body = "other.example/log\n3\nz3Y6BByBzu8VeKYIP3XGG+8uABTyo+aDqX/Pylvn8Zo=\n";
    let note = sign_note(foreign_body, GOLDEN_NAME, &identity).unwrap();

    // The note itself verifies (signed under the golden keyname)...
    verify_note(note.as_bytes(), &golden_verifier()).unwrap();
    // ...but checkpoint verification enforces origin == verifier name.
    let err = verify_checkpoint(note.as_bytes(), &golden_verifier()).unwrap_err();
    assert!(matches!(err, TrustError::NoteVerification));
}

#[test]
fn unparseable_body_collapses_to_note_verification() {
    let (_dir, identity) = golden_identity();
    // Valid note, but the body is not a checkpoint (one line only).
    let note = sign_note("not-a-checkpoint\n", GOLDEN_NAME, &identity).unwrap();
    let err = verify_checkpoint(note.as_bytes(), &golden_verifier()).unwrap_err();
    assert!(matches!(err, TrustError::NoteVerification));
}

#[test]
fn tree_size_tamper_in_checkpoint_note_is_rejected() {
    // Splice a different tree size into the golden note without
    // re-signing: signature breaks.
    let tampered = golden_note().replacen("\n3\n", "\n4\n", 1);
    assert_rejected(tampered.as_bytes(), "tree-size line tamper");

    // Leading-zero tree size WITH a valid re-sign: rejected by the strict
    // body parse inside verify_checkpoint.
    let (_dir, identity) = golden_identity();
    let leading_zero_body = GOLDEN_BODY.replacen("\n3\n", "\n03\n", 1);
    let note = sign_note(&leading_zero_body, GOLDEN_NAME, &identity).unwrap();
    let err = verify_checkpoint(note.as_bytes(), &golden_verifier()).unwrap_err();
    assert!(matches!(err, TrustError::NoteVerification));
}

#[test]
fn root_hash_tamper_in_checkpoint_note_is_rejected() {
    let tampered = golden_note().replacen("z3Y6", "z3Y7", 1);
    assert_rejected(tampered.as_bytes(), "root-hash line tamper");
}
