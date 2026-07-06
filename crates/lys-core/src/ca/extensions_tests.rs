#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use super::*;
use crate::ca::authority::CertificateAuthority;
use crate::keys::Ed25519Identity;

/// A custom extension OID under [`LYS_OID_ARC`] used for these tests.
const TEST_EXT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 58888, 7];

fn test_authority() -> CertificateAuthority {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca.key");
    let identity = Ed25519Identity::load_or_generate(&path).unwrap();
    CertificateAuthority::new(identity)
}

#[test]
fn encoded_extension_is_non_critical() {
    let extension = encode_extension(TEST_EXT_OID, b"opaque payload".to_vec());
    assert!(!extension.criticality(), "extension must be non-critical");
}

#[test]
fn encode_accepts_slice_and_vec_payloads() {
    let from_vec = encode_extension(TEST_EXT_OID, vec![1u8, 2, 3]);
    let from_slice = encode_extension(TEST_EXT_OID, &[1u8, 2, 3][..]);
    assert!(!from_vec.criticality());
    assert!(!from_slice.criticality());
}

#[test]
fn extension_encode_decode_round_trips() {
    let payload = b"capability-claim-bytes".to_vec();
    let extensions = vec![encode_extension(TEST_EXT_OID, payload.clone())];

    let ca = test_authority();
    let issued = ca
        .issue_certificate(
            "subject-with-extension",
            Duration::from_hours(1),
            extensions,
        )
        .unwrap();

    let extracted = decode_extension(&issued.der_bytes, TEST_EXT_OID).unwrap();
    assert_eq!(extracted, Some(payload));
}

#[test]
fn decode_returns_none_for_absent_extension() {
    let ca = test_authority();
    let issued = ca
        .issue_certificate("subject-no-extension", Duration::from_hours(1), vec![])
        .unwrap();

    let extracted = decode_extension(&issued.der_bytes, TEST_EXT_OID).unwrap();
    assert_eq!(extracted, None);
}

#[test]
fn decode_rejects_malformed_certificate() {
    let result = decode_extension(b"not a certificate", TEST_EXT_OID);
    assert!(matches!(
        result,
        Err(crate::error::TrustError::CertificateParsing { .. })
    ));
}
