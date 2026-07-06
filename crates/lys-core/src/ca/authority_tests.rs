#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use x509_parser::prelude::{FromDer, X509Certificate};

use super::*;
use crate::error::TrustError;
use crate::keys::Ed25519Identity;

fn test_identity() -> Ed25519Identity {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca.key");
    Ed25519Identity::load_or_generate(&path).unwrap()
}

fn test_authority() -> CertificateAuthority {
    CertificateAuthority::new(test_identity())
}

#[test]
fn issue_certificate_returns_non_empty_parseable_der() {
    let ca = test_authority();
    let issued = ca
        .issue_certificate("agent-001", Duration::from_hours(1), vec![])
        .unwrap();

    assert!(!issued.der_bytes.is_empty());
    let (_, parsed) = X509Certificate::from_der(&issued.der_bytes)
        .expect("issued certificate must parse as valid DER");
    assert_eq!(issued.issuer_public_key, ca.public_key_bytes());
    // Leaf subject differs from the CA-derived issuer.
    assert_ne!(parsed.subject().as_raw(), parsed.issuer().as_raw());
}

#[test]
fn issuer_common_name_matches_ca_public_key_hex() {
    let ca = test_authority();
    let issued = ca
        .issue_certificate("agent-002", Duration::from_hours(1), vec![])
        .unwrap();

    let (_, parsed) = X509Certificate::from_der(&issued.der_bytes).unwrap();
    let issuer_cn = parsed
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .expect("issuer must carry a common name");

    let expected_hex = crate::hex_lower(&ca.public_key_bytes());
    assert_eq!(issuer_cn, expected_hex);
}

#[test]
fn empty_subject_is_rejected() {
    let ca = test_authority();
    let result = ca.issue_certificate("   ", Duration::from_hours(1), vec![]);
    assert!(matches!(
        result,
        Err(TrustError::CertificateGeneration { .. })
    ));
}

#[test]
fn zero_ttl_is_rejected() {
    let ca = test_authority();
    let result = ca.issue_certificate("agent-003", Duration::ZERO, vec![]);
    assert!(matches!(
        result,
        Err(TrustError::CertificateGeneration { .. })
    ));
}

#[test]
fn legitimately_issued_certificate_verifies() {
    let ca = test_authority();
    let issued = ca
        .issue_certificate("agent-004", Duration::from_hours(1), vec![])
        .unwrap();

    // Free function with explicit issuer key.
    verify_certificate_chain(&issued.der_bytes, &ca.public_key_bytes()).unwrap();
    // Convenience method.
    ca.verify_certificate_chain(&issued.der_bytes).unwrap();
}

#[test]
fn certificate_from_other_ca_fails_verification() {
    let ca_a = test_authority();
    let ca_b = test_authority();
    let issued = ca_a
        .issue_certificate("agent-005", Duration::from_hours(1), vec![])
        .unwrap();

    let result = verify_certificate_chain(&issued.der_bytes, &ca_b.public_key_bytes());
    assert!(matches!(
        result,
        Err(TrustError::CertificateVerification { .. })
    ));
    // And the wrong CA's convenience method rejects it too.
    assert!(ca_b.verify_certificate_chain(&issued.der_bytes).is_err());
}

#[test]
fn self_signed_certificate_is_rejected() {
    // A self-signed Ed25519 certificate: issuer equals subject.
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let params = CertificateParams::new(Vec::<String>::new()).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let der = cert.der().to_vec();

    let result = verify_certificate_chain(&der, &[0u8; 32]);
    assert!(matches!(
        result,
        Err(TrustError::CertificateVerification { .. })
    ));
}

#[test]
fn malformed_der_fails_to_parse() {
    let result = verify_certificate_chain(b"not a certificate", &[0u8; 32]);
    assert!(matches!(result, Err(TrustError::CertificateParsing { .. })));
}

// ─── validity window (verify_certificate_chain_at) ────────────────

#[test]
fn expired_certificate_is_rejected_at_future_instant() {
    let ca = test_authority();
    let issued = ca
        .issue_certificate("agent-006", Duration::from_mins(1), vec![])
        .unwrap();

    let future = chrono::Utc::now() + chrono::Duration::hours(2);
    let err =
        verify_certificate_chain_at(&issued.der_bytes, &ca.public_key_bytes(), future).unwrap_err();
    assert!(matches!(err, TrustError::CertificateVerification { .. }));
    let msg = err.to_string();
    assert!(msg.contains("expired"), "got: {msg}");
    assert!(msg.contains("notAfter"), "got: {msg}");
    assert!(!msg.contains("not yet valid"), "got: {msg}");
}

#[test]
fn not_yet_valid_certificate_is_rejected_at_past_instant() {
    let ca = test_authority();
    let issued = ca
        .issue_certificate("agent-007", Duration::from_hours(1), vec![])
        .unwrap();

    let past = chrono::Utc::now() - chrono::Duration::hours(2);
    let err =
        verify_certificate_chain_at(&issued.der_bytes, &ca.public_key_bytes(), past).unwrap_err();
    assert!(matches!(err, TrustError::CertificateVerification { .. }));
    let msg = err.to_string();
    assert!(msg.contains("not yet valid"), "got: {msg}");
    assert!(msg.contains("notBefore"), "got: {msg}");
}

#[test]
fn certificate_verifies_at_explicit_instant_inside_window() {
    let ca = test_authority();
    let issued = ca
        .issue_certificate("agent-008", Duration::from_hours(1), vec![])
        .unwrap();

    let mid_window = chrono::Utc::now() + chrono::Duration::minutes(30);
    verify_certificate_chain_at(&issued.der_bytes, &ca.public_key_bytes(), mid_window).unwrap();
}

#[test]
fn validity_boundaries_are_inclusive() {
    let ca = test_authority();
    let issued = ca
        .issue_certificate("agent-009", Duration::from_hours(1), vec![])
        .unwrap();

    // expires_at is truncated to the exact DER notAfter instant, so
    // verification exactly at the boundary must still pass (X.509 validity
    // is inclusive), and one second past it must fail.
    verify_certificate_chain_at(&issued.der_bytes, &ca.public_key_bytes(), issued.expires_at)
        .unwrap();
    let err = verify_certificate_chain_at(
        &issued.der_bytes,
        &ca.public_key_bytes(),
        issued.expires_at + chrono::Duration::seconds(1),
    )
    .unwrap_err();
    assert!(err.to_string().contains("expired"), "got: {err}");
}

// ─── expires_at / DER notAfter agreement ──────────────────────────

#[test]
fn expires_at_is_whole_seconds_and_matches_der_not_after() {
    let ca = test_authority();
    let issued = ca
        .issue_certificate("agent-010", Duration::from_hours(1), vec![])
        .unwrap();

    assert_eq!(
        issued.expires_at.timestamp_subsec_nanos(),
        0,
        "expires_at must be truncated to whole-second precision"
    );

    let (_, parsed) = X509Certificate::from_der(&issued.der_bytes).unwrap();
    assert_eq!(
        issued.expires_at.timestamp(),
        parsed.validity().not_after.timestamp(),
        "expires_at must be the same instant encoded in the DER notAfter"
    );
}

// ─── strict verification (weak issuer keys) ───────────────────────

#[test]
fn small_order_issuer_key_forgery_is_rejected() {
    use ed25519_dalek::Verifier;

    // Take a legitimately issued certificate and replace its trailing
    // 64-byte signature with the small-order forgery (R = basepoint, s = 1).
    // Against the identity-point issuer key ([1, 0, ..., 0], order 1) the
    // non-strict equation s·B = R + k·A reduces to B = R, so the forged
    // signature passes NON-strict verification for any tbs bytes. Strict
    // verification rejects the weak key outright.
    let ca = test_authority();
    let issued = ca
        .issue_certificate("agent-011", Duration::from_hours(1), vec![])
        .unwrap();

    let mut der = issued.der_bytes;
    let sig_offset = der.len() - 64;
    let basepoint: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];
    der[sig_offset..sig_offset + 32].copy_from_slice(&basepoint);
    der[sig_offset + 32..].copy_from_slice(&{
        let mut s = [0u8; 32];
        s[0] = 1; // s = 1, little-endian
        s
    });

    let mut weak_issuer = [0u8; 32];
    weak_issuer[0] = 1; // Edwards identity point encoding

    // Sanity: dalek's non-strict verify accepts the forgery over the tbs —
    // this is exactly the hole verify_strict closes.
    let (_, parsed) = X509Certificate::from_der(&der).unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&weak_issuer).unwrap();
    let forged_sig = ed25519_dalek::Signature::from_bytes(
        der[sig_offset..].try_into().expect("64-byte signature"),
    );
    vk.verify(parsed.tbs_certificate.as_ref(), &forged_sig)
        .expect("non-strict verify accepts the small-order forgery");

    // Chain verification with strict checking must reject it.
    let result = verify_certificate_chain(&der, &weak_issuer);
    assert!(matches!(
        result,
        Err(TrustError::CertificateVerification { .. })
    ));
}
