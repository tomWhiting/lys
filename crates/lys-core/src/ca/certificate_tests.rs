#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, Verifier};
use rcgen::{KeyPair, PKCS_ED25519};
use sha2::{Digest, Sha256};

use super::*;

fn subject_keypair() -> KeyPair {
    KeyPair::generate_for(&PKCS_ED25519).unwrap()
}

#[test]
fn from_der_and_keypair_populates_all_fields() {
    let keypair = subject_keypair();
    let der = b"example certificate der bytes".to_vec();
    let expires_at = Utc::now() + Duration::hours(1);
    let issuer_key = [9u8; 32];

    let issued =
        IssuedCertificate::from_der_and_keypair(der.clone(), &keypair, expires_at, issuer_key)
            .unwrap();

    assert_eq!(issued.der_bytes, der);
    assert_eq!(issued.expires_at, expires_at);
    assert_eq!(issued.issuer_public_key, issuer_key);
    assert_eq!(
        issued.subject_verifying_key.to_bytes().as_slice(),
        keypair.public_key_raw()
    );
}

#[test]
fn fingerprint_equals_sha256_of_der() {
    let keypair = subject_keypair();
    let der = b"the quick brown fox".to_vec();
    let expected: [u8; 32] = Sha256::digest(&der).into();

    let issued =
        IssuedCertificate::from_der_and_keypair(der, &keypair, Utc::now(), [0u8; 32]).unwrap();

    assert_eq!(issued.fingerprint, expected);
}

#[test]
fn rcgen_keypair_round_trips_into_dalek_signing_and_verifying_keys() {
    let keypair = subject_keypair();
    let issued =
        IssuedCertificate::from_der_and_keypair(b"der".to_vec(), &keypair, Utc::now(), [0u8; 32])
            .unwrap();

    let message = b"attestation payload";
    let signature = issued.subject_signing_key.sign(message);
    issued
        .subject_verifying_key
        .verify(message, &signature)
        .expect("subject keypair must sign and verify consistently");
}

#[test]
fn debug_redacts_subject_signing_key() {
    let keypair = subject_keypair();
    let issued =
        IssuedCertificate::from_der_and_keypair(b"der".to_vec(), &keypair, Utc::now(), [7u8; 32])
            .unwrap();

    let rendered = format!("{issued:?}");
    assert!(rendered.contains("[REDACTED]"), "got: {rendered}");
    assert!(
        !rendered.contains("SigningKey"),
        "dalek SigningKey debug leaked: {rendered}"
    );
}

#[test]
fn debug_includes_non_sensitive_fields() {
    let keypair = subject_keypair();
    let issued = IssuedCertificate::from_der_and_keypair(
        b"der-bytes".to_vec(),
        &keypair,
        Utc::now(),
        [0xab; 32],
    )
    .unwrap();

    let rendered = format!("{issued:?}");
    // issuer public key hex (0xab repeated) must surface for diagnostics.
    assert!(rendered.contains("abab"), "got: {rendered}");
    assert!(rendered.contains("der_bytes_len"), "got: {rendered}");
}
