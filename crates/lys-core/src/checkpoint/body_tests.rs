#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::error::TrustError;
use crate::merkle::{AppendOnlyTree, RawLeaf};

const GOLDEN_ORIGIN: &str = "example.com/lys/test";

/// Golden root of the raw-leaf tree over `leaf-0`, `leaf-1`, `leaf-2`.
const GOLDEN_ROOT_3: [u8; 32] = [
    0xcf, 0x76, 0x3a, 0x04, 0x1c, 0x81, 0xce, 0xef, 0x15, 0x78, 0xa6, 0x08, 0x3f, 0x75, 0xc6, 0x1b,
    0xef, 0x2e, 0x00, 0x14, 0xf2, 0xa3, 0xe6, 0x83, 0xa9, 0x7f, 0xcf, 0xca, 0x5b, 0xe7, 0xf1, 0x9a,
];

/// Golden checkpoint body for the size-3 tree, byte-exact.
const GOLDEN_BODY: &str = "example.com/lys/test\n3\nz3Y6BByBzu8VeKYIP3XGG+8uABTyo+aDqX/Pylvn8Zo=\n";

fn golden_body() -> CheckpointBody {
    CheckpointBody::new(GOLDEN_ORIGIN, 3, GOLDEN_ROOT_3).unwrap()
}

#[test]
fn encode_matches_golden_bytes() {
    assert_eq!(golden_body().encode(), GOLDEN_BODY);
}

#[test]
fn from_root_matches_direct_construction() {
    let mut tree = AppendOnlyTree::<RawLeaf>::new();
    tree.append_raw(b"leaf-0");
    tree.append_raw(b"leaf-1");
    tree.append_raw(b"leaf-2");

    let body = CheckpointBody::from_root(GOLDEN_ORIGIN, &tree.root()).unwrap();
    assert_eq!(body, golden_body());
    assert_eq!(body.encode(), GOLDEN_BODY);
}

#[test]
fn parse_round_trips_byte_exactly() {
    let parsed = CheckpointBody::parse(GOLDEN_BODY).unwrap();
    assert_eq!(parsed.origin(), GOLDEN_ORIGIN);
    assert_eq!(parsed.tree_size(), 3);
    assert_eq!(parsed.root_hash(), GOLDEN_ROOT_3);
    assert_eq!(parsed.encode(), GOLDEN_BODY);
    assert_eq!(parsed, golden_body());
}

#[test]
fn to_root_bridges_into_merkle_root() {
    let root = golden_body().to_root();
    let (bytes, count) = root.to_parts();
    assert_eq!(bytes, GOLDEN_ROOT_3);
    assert_eq!(count, 3);
}

#[test]
fn tree_size_zero_is_valid() {
    let body = CheckpointBody::new(GOLDEN_ORIGIN, 0, [0u8; 32]).unwrap();
    let encoded = body.encode();
    let parsed = CheckpointBody::parse(&encoded).unwrap();
    assert_eq!(parsed.tree_size(), 0);
}

#[test]
fn parse_tolerates_and_discards_extension_lines() {
    let with_extension = format!("{GOLDEN_BODY}extension data\nanother extension\n");
    let parsed = CheckpointBody::parse(&with_extension).unwrap();
    assert_eq!(parsed, golden_body());
    assert_eq!(
        parsed.encode(),
        GOLDEN_BODY,
        "extensions are never re-emitted"
    );
}

#[test]
fn new_rejects_invalid_origin() {
    for bad in ["", "has space", "has+plus", "has\ttab"] {
        let err = CheckpointBody::new(bad, 1, [0u8; 32]).unwrap_err();
        assert!(
            matches!(err, TrustError::CheckpointEncoding { .. }),
            "origin: {bad:?}"
        );
    }
}

#[test]
fn parse_rejects_missing_trailing_newline() {
    let truncated = GOLDEN_BODY.trim_end_matches('\n');
    let err = CheckpointBody::parse(truncated).unwrap_err();
    assert!(matches!(err, TrustError::CheckpointParsing { .. }));
}

#[test]
fn parse_rejects_fewer_than_three_lines() {
    for text in ["", "\n", "origin\n", "origin\n3\n"] {
        let err = CheckpointBody::parse(text).unwrap_err();
        assert!(
            matches!(err, TrustError::CheckpointParsing { .. }),
            "text: {text:?}"
        );
    }
}

#[test]
fn parse_rejects_empty_lines_anywhere() {
    // A blank extension line and a blank line among the three core lines.
    for text in [
        format!("{GOLDEN_BODY}\n"),
        format!("{GOLDEN_BODY}ext\n\nmore\n"),
        "example.com/lys/test\n\n3\nz3Y6BByBzu8VeKYIP3XGG+8uABTyo+aDqX/Pylvn8Zo=\n".to_string(),
    ] {
        let err = CheckpointBody::parse(&text).unwrap_err();
        assert!(
            matches!(err, TrustError::CheckpointParsing { .. }),
            "text: {text:?}"
        );
    }
}

#[test]
fn parse_rejects_invalid_origins() {
    for bad in ["bad origin", "bad+origin"] {
        let text = GOLDEN_BODY.replacen(GOLDEN_ORIGIN, bad, 1);
        let err = CheckpointBody::parse(&text).unwrap_err();
        assert!(
            matches!(err, TrustError::CheckpointParsing { .. }),
            "origin: {bad:?}"
        );
    }
}

#[test]
fn parse_rejects_non_canonical_tree_sizes() {
    // Leading zero, sign, whitespace, non-digit, float, overflow.
    for bad_size in [
        "03",
        "00",
        "+3",
        "-3",
        " 3",
        "3 ",
        "3.0",
        "three",
        "18446744073709551616",
    ] {
        let text = GOLDEN_BODY.replacen("\n3\n", &format!("\n{bad_size}\n"), 1);
        let err = CheckpointBody::parse(&text).unwrap_err();
        assert!(
            matches!(err, TrustError::CheckpointParsing { .. }),
            "size: {bad_size:?}"
        );
    }
}

#[test]
fn parse_rejects_malformed_root_lines() {
    const GOLDEN_ROOT_B64: &str = "z3Y6BByBzu8VeKYIP3XGG+8uABTyo+aDqX/Pylvn8Zo=";
    let too_short = &GOLDEN_ROOT_B64[..43];
    let too_long = format!("{GOLDEN_ROOT_B64}A");
    let bad_char = GOLDEN_ROOT_B64.replacen('z', "!", 1);
    // Non-canonical trailing bits: the final data character before '=' has
    // its low bits set ('o' -> 'p'), which RequireCanonical rejects.
    let non_canonical = GOLDEN_ROOT_B64.replacen("Zo=", "Zp=", 1);
    // Unpadded re-encoding of the same 32 bytes (43 chars, '=' stripped).
    let unpadded = GOLDEN_ROOT_B64.trim_end_matches('=');

    for bad_root in [
        too_short,
        too_long.as_str(),
        bad_char.as_str(),
        non_canonical.as_str(),
        unpadded,
    ] {
        let text = GOLDEN_BODY.replacen(GOLDEN_ROOT_B64, bad_root, 1);
        let err = CheckpointBody::parse(&text).unwrap_err();
        assert!(
            matches!(err, TrustError::CheckpointParsing { .. }),
            "root: {bad_root:?}"
        );
    }
}
