#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::error::TrustError;

/// Golden fixed test key: Ed25519 public key of the seed
/// `"lys-go-conformance-test-seed-01!"` (cross-checked against Go
/// `sumdb/note` during design).
const GOLDEN_PUBKEY: [u8; 32] = [
    0x0c, 0xfd, 0x0f, 0xd8, 0x1b, 0x16, 0xac, 0xcb, 0xc5, 0x23, 0x0c, 0xf4, 0x5c, 0xba, 0x9d, 0x4b,
    0x93, 0x7d, 0x82, 0x7c, 0x6c, 0x8d, 0xbd, 0x44, 0xa1, 0x44, 0xe5, 0xab, 0xa5, 0x71, 0xb9, 0xe2,
];

const GOLDEN_NAME: &str = "example.com/lys/test";

const GOLDEN_SPEC: &str =
    "example.com/lys/test+52580cd9+AQz9D9gbFqzLxSMM9Fy6nUuTfYJ8bI29RKFE5aulcbni";

const GOLDEN_KEY_ID: [u8; 4] = [0x52, 0x58, 0x0c, 0xd9];

#[test]
fn new_computes_golden_key_id_and_spec() {
    let key = NoteVerifierKey::new(GOLDEN_NAME, GOLDEN_PUBKEY).unwrap();
    assert_eq!(key.name(), GOLDEN_NAME);
    assert_eq!(key.key_id(), GOLDEN_KEY_ID);
    assert_eq!(key.public_key(), GOLDEN_PUBKEY);
    assert_eq!(key.to_spec(), GOLDEN_SPEC);
}

#[test]
fn from_spec_parses_golden_and_round_trips() {
    let key = NoteVerifierKey::from_spec(GOLDEN_SPEC).unwrap();
    assert_eq!(key.name(), GOLDEN_NAME);
    assert_eq!(key.key_id(), GOLDEN_KEY_ID);
    assert_eq!(key.public_key(), GOLDEN_PUBKEY);
    assert_eq!(key.to_spec(), GOLDEN_SPEC);
    assert_eq!(
        key,
        NoteVerifierKey::new(GOLDEN_NAME, GOLDEN_PUBKEY).unwrap()
    );
}

#[test]
fn from_spec_accepts_uppercase_hex_key_id_and_emits_lowercase() {
    let uppercase = GOLDEN_SPEC.replace("52580cd9", "52580CD9");
    let key = NoteVerifierKey::from_spec(&uppercase).unwrap();
    assert_eq!(key.key_id(), GOLDEN_KEY_ID);
    assert_eq!(key.to_spec(), GOLDEN_SPEC, "emission must be lowercase hex");
}

#[test]
fn from_spec_rejects_missing_parts() {
    for spec in ["", "name-only", "name+52580cd9", "+52580cd9+AQAB"] {
        let err = NoteVerifierKey::from_spec(spec).unwrap_err();
        assert!(
            matches!(err, TrustError::VerifierKey { .. }),
            "spec: {spec}"
        );
    }
}

#[test]
fn from_spec_rejects_invalid_names() {
    for bad_name in ["has space", "has\ttab", "has\u{a0}nbsp"] {
        let spec = GOLDEN_SPEC.replacen(GOLDEN_NAME, bad_name, 1);
        let err = NoteVerifierKey::from_spec(&spec).unwrap_err();
        assert!(
            matches!(err, TrustError::VerifierKey { .. }),
            "name: {bad_name:?}"
        );
    }
}

#[test]
fn from_spec_rejects_bad_key_id_lengths_and_non_hex() {
    for bad_id in ["52580cd", "52580cd99", "52580cdX", "5258 cd9", ""] {
        let spec = GOLDEN_SPEC.replacen("52580cd9", bad_id, 1);
        let err = NoteVerifierKey::from_spec(&spec).unwrap_err();
        assert!(
            matches!(err, TrustError::VerifierKey { .. }),
            "id: {bad_id:?}"
        );
    }
}

#[test]
fn from_spec_rejects_mismatched_declared_key_id() {
    let spec = GOLDEN_SPEC.replacen("52580cd9", "deadbeef", 1);
    let err = NoteVerifierKey::from_spec(&spec).unwrap_err();
    assert!(matches!(err, TrustError::VerifierKey { .. }));
}

#[test]
fn from_spec_rejects_wrong_key_blob_length() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    // 32 bytes (missing algorithm byte) and 34 bytes (one extra).
    let short = STANDARD.encode(GOLDEN_PUBKEY);
    let mut long_bytes = vec![0x01];
    long_bytes.extend_from_slice(&GOLDEN_PUBKEY);
    long_bytes.push(0x00);
    let long = STANDARD.encode(&long_bytes);
    for blob in [short.as_str(), long.as_str()] {
        let spec = format!("{GOLDEN_NAME}+52580cd9+{blob}");
        let err = NoteVerifierKey::from_spec(&spec).unwrap_err();
        assert!(matches!(err, TrustError::VerifierKey { .. }));
    }
}

#[test]
fn from_spec_rejects_wrong_algorithm_byte() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let mut blob_bytes = vec![0x02];
    blob_bytes.extend_from_slice(&GOLDEN_PUBKEY);
    let spec = format!("{GOLDEN_NAME}+52580cd9+{}", STANDARD.encode(&blob_bytes));
    let err = NoteVerifierKey::from_spec(&spec).unwrap_err();
    assert!(matches!(err, TrustError::VerifierKey { .. }));
}

#[test]
fn from_spec_rejects_non_canonical_base64_blob() {
    // "AAA" is a length-invalid unpadded fragment: strict standard base64
    // with required canonical padding must reject it.
    let spec = format!("{GOLDEN_NAME}+52580cd9+AAA");
    let err = NoteVerifierKey::from_spec(&spec).unwrap_err();
    assert!(matches!(err, TrustError::VerifierKey { .. }));
}

#[test]
fn validate_note_name_accepts_valid_and_rejects_invalid() {
    validate_note_name("example.com/lys/test").unwrap();
    validate_note_name("a").unwrap();
    validate_note_name("log.example.org").unwrap();

    for bad in [
        "",
        "has space",
        "has\ttab",
        "has\nnewline",
        "has+plus",
        "nbsp\u{a0}name",
        "ideographic\u{3000}space",
    ] {
        let err = validate_note_name(bad).unwrap_err();
        assert!(
            matches!(err, TrustError::VerifierKey { .. }),
            "name: {bad:?}"
        );
    }
}
