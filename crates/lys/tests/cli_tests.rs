//! End-to-end integration tests for the `lys` binary.
//!
//! Each subcommand is exercised through a real process spawn of the compiled
//! binary (`CARGO_BIN_EXE_lys`), asserting on exit codes, stdout/stderr
//! content, and on-disk side effects. The attest/verify tests additionally
//! cross-check the CLI's JSON envelope against `lys-core` directly.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::{Command, Output};

use base64::Engine;
use lys_core::Ed25519Identity;
use lys_core::attestation::{Attestation, verify_attestation};
use lys_core::ca::{
    CertificateAuthority, decode_extension, encode_extension, verify_certificate_chain,
};
use lys_core::seal::{SealedEnvelope, open_and_verify};

/// Spawn the compiled `lys` binary with the given arguments.
fn run_lys(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lys"))
        .args(args)
        .output()
        .expect("failed to spawn lys binary")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout was not UTF-8")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr was not UTF-8")
}

/// Extract the value following `label` on the matching stdout line.
fn field(stdout: &str, label: &str) -> String {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(label))
        .unwrap_or_else(|| panic!("no line starting with {label:?} in output:\n{stdout}"))
        .trim()
        .to_string()
}

/// Lowercase hex encoding, mirroring the CLI's output format.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = s.write_fmt(format_args!("{b:02x}"));
    }
    s
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("tempdir path was not UTF-8")
}

// ---------------------------------------------------------------- key generate

#[test]
fn key_generate_creates_key_file_and_prints_public_hex_only() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("agent.key");

    let output = run_lys(&["key", "generate", "--out", path_str(&key_path)]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr_of(&output));

    let stdout = stdout_of(&output);
    assert!(stdout.contains("generated new identity key"), "{stdout}");
    let pub_hex = field(&stdout, "public key (ed25519):");
    assert_eq!(pub_hex.len(), 64, "expected 32-byte hex, got: {pub_hex}");
    assert!(pub_hex.chars().all(|c| c.is_ascii_hexdigit()));

    // The key file holds exactly the 32-byte seed, and no encoding of that
    // seed ever appears in the command output.
    let seed = std::fs::read(&key_path).unwrap();
    assert_eq!(seed.len(), 32);
    let seed_hex = hex_lower(&seed);
    assert!(
        !stdout.contains(&seed_hex),
        "private seed leaked into stdout"
    );
    assert!(
        !stderr_of(&output).contains(&seed_hex),
        "private seed leaked into stderr"
    );

    // The printed hex is the real public key for the persisted seed.
    let identity = Ed25519Identity::load_or_generate(&key_path).unwrap();
    assert_eq!(pub_hex, hex_lower(&identity.public_key_bytes()));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "key file mode was {:o}", mode & 0o777);
    }
}

#[test]
fn key_generate_is_idempotent_and_reports_existing_key() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("agent.key");

    let first = run_lys(&["key", "generate", "--out", path_str(&key_path)]);
    assert_eq!(first.status.code(), Some(0), "{}", stderr_of(&first));
    let first_pub = field(&stdout_of(&first), "public key (ed25519):");
    let seed_before = std::fs::read(&key_path).unwrap();

    let second = run_lys(&["key", "generate", "--out", path_str(&key_path)]);
    assert_eq!(second.status.code(), Some(0), "{}", stderr_of(&second));
    let second_stdout = stdout_of(&second);
    assert!(
        second_stdout.contains("loaded existing identity key"),
        "{second_stdout}"
    );
    assert_eq!(field(&second_stdout, "public key (ed25519):"), first_pub);
    assert_eq!(
        std::fs::read(&key_path).unwrap(),
        seed_before,
        "second generate must not rewrite the key file"
    );
}

// ---------------------------------------------------------------- key inspect

#[test]
fn key_inspect_prints_ed25519_and_derived_x25519_public_keys() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("agent.key");
    let generate = run_lys(&["key", "generate", "--out", path_str(&key_path)]);
    assert_eq!(generate.status.code(), Some(0), "{}", stderr_of(&generate));
    let generated_pub = field(&stdout_of(&generate), "public key (ed25519):");

    let output = run_lys(&["key", "inspect", "--key", path_str(&key_path)]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr_of(&output));
    let stdout = stdout_of(&output);

    assert_eq!(field(&stdout, "public key (ed25519):"), generated_pub);

    let identity = Ed25519Identity::load_or_generate(&key_path).unwrap();
    assert_eq!(
        field(&stdout, "public key (x25519):"),
        hex_lower(&identity.x25519_public_key())
    );

    let seed_hex = hex_lower(&std::fs::read(&key_path).unwrap());
    assert!(
        !stdout.contains(&seed_hex),
        "private seed leaked into stdout"
    );
}

#[test]
fn key_inspect_missing_file_fails_without_creating_one() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("absent.key");

    let output = run_lys(&["key", "inspect", "--key", path_str(&key_path)]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("identity key file not found"),
        "stderr: {stderr}"
    );
    assert!(
        !key_path.exists(),
        "inspect must never create a key file as a side effect"
    );
}

// --------------------------------------------------------------------- attest

#[test]
fn attest_writes_json_envelope_that_lys_core_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("agent.key");
    let payload_path = dir.path().join("payload.bin");
    let out_path = dir.path().join("attestation.json");
    let payload: &[u8] = b"execution receipt: task 42 completed";

    let generate = run_lys(&["key", "generate", "--out", path_str(&key_path)]);
    assert_eq!(generate.status.code(), Some(0), "{}", stderr_of(&generate));
    std::fs::write(&payload_path, payload).unwrap();

    let output = run_lys(&[
        "attest",
        "--key",
        path_str(&key_path),
        "--payload",
        path_str(&payload_path),
        "--out",
        path_str(&out_path),
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr_of(&output));
    let stdout = stdout_of(&output);

    // The written envelope is valid JSON in the lys-core wire shape and
    // verifies against the payload through the library directly.
    let json = std::fs::read_to_string(&out_path).unwrap();
    let attestation: Attestation = serde_json::from_str(&json).unwrap();
    verify_attestation(&attestation, payload).unwrap();

    // Printed metadata matches the envelope on disk.
    let identity = Ed25519Identity::load_or_generate(&key_path).unwrap();
    assert_eq!(attestation.signer_public_key, identity.public_key_bytes());
    assert_eq!(
        field(&stdout, "payload hash (sha256):"),
        hex_lower(&attestation.payload_hash)
    );
    assert_eq!(
        field(&stdout, "signer public key (ed25519):"),
        hex_lower(&attestation.signer_public_key)
    );
    assert_eq!(
        field(&stdout, "signed at (unix ms):"),
        attestation.timestamp.to_string()
    );

    let seed_hex = hex_lower(&std::fs::read(&key_path).unwrap());
    assert!(
        !json.contains(&seed_hex),
        "private seed leaked into envelope"
    );
    assert!(
        !stdout.contains(&seed_hex),
        "private seed leaked into stdout"
    );
}

#[test]
fn attest_with_missing_key_fails_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let payload_path = dir.path().join("payload.bin");
    let out_path = dir.path().join("attestation.json");
    std::fs::write(&payload_path, b"payload").unwrap();

    let output = run_lys(&[
        "attest",
        "--key",
        path_str(&dir.path().join("absent.key")),
        "--payload",
        path_str(&payload_path),
        "--out",
        path_str(&out_path),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("identity key file not found"),
        "stderr: {stderr}"
    );
    assert!(
        !out_path.exists(),
        "no attestation may be written on failure"
    );
    assert!(
        !dir.path().join("absent.key").exists(),
        "attest must never create a key file as a side effect"
    );
}

// --------------------------------------------------------------------- verify

/// Run the full generate → attest pipeline, returning the attestation path.
fn attest_fixture(dir: &Path, payload: &[u8]) -> std::path::PathBuf {
    let key_path = dir.join("agent.key");
    let payload_path = dir.join("payload.bin");
    let out_path = dir.join("attestation.json");

    let generate = run_lys(&["key", "generate", "--out", path_str(&key_path)]);
    assert_eq!(generate.status.code(), Some(0), "{}", stderr_of(&generate));
    std::fs::write(&payload_path, payload).unwrap();
    let attest = run_lys(&[
        "attest",
        "--key",
        path_str(&key_path),
        "--payload",
        path_str(&payload_path),
        "--out",
        path_str(&out_path),
    ]);
    assert_eq!(attest.status.code(), Some(0), "{}", stderr_of(&attest));
    out_path
}

#[test]
fn verify_accepts_valid_attestation_with_exit_zero() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = attest_fixture(dir.path(), b"audit entry payload");

    let output = run_lys(&[
        "verify",
        "--attestation",
        path_str(&out_path),
        "--payload",
        path_str(&dir.path().join("payload.bin")),
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr_of(&output));
    let stdout = stdout_of(&output);
    assert!(stdout.contains("attestation verified"), "{stdout}");
    assert_eq!(field(&stdout, "signer public key (ed25519):").len(), 64);
}

#[test]
fn verify_rejects_tampered_payload_with_exit_one() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = attest_fixture(dir.path(), b"original payload");
    let payload_path = dir.path().join("payload.bin");
    std::fs::write(&payload_path, b"tampered payload").unwrap();

    let output = run_lys(&[
        "verify",
        "--attestation",
        path_str(&out_path),
        "--payload",
        path_str(&payload_path),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("attestation verification failed"),
        "stderr: {stderr}"
    );
    let stdout = stdout_of(&output);
    assert!(
        !stdout.contains("attestation verified"),
        "must not claim success: {stdout}"
    );
}

#[test]
fn verify_rejects_tampered_timestamp_with_exit_one() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = attest_fixture(dir.path(), b"timestamped payload");

    // Shift the (authenticated) timestamp by one millisecond in the JSON.
    let json = std::fs::read_to_string(&out_path).unwrap();
    let mut envelope: serde_json::Value = serde_json::from_str(&json).unwrap();
    let timestamp = envelope["timestamp"].as_i64().unwrap();
    envelope["timestamp"] = serde_json::Value::from(timestamp + 1);
    std::fs::write(&out_path, serde_json::to_string(&envelope).unwrap()).unwrap();

    let output = run_lys(&[
        "verify",
        "--attestation",
        path_str(&out_path),
        "--payload",
        path_str(&dir.path().join("payload.bin")),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr_of(&output).contains("attestation verification failed"),
        "stderr: {}",
        stderr_of(&output)
    );
}

// ------------------------------------------------------------------- ca issue

/// Capability claims used across the CA tests.
const CLAIMS_JSON: &str = r#"{"capabilities":["deploy","sign"],"scope":"ci"}"#;

/// The OID the CLI documents for capability-claims extensions
/// (`LYS_OID_ARC` + `1`).
const CLAIMS_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 58888, 1];

/// Strip PEM framing and base64-decode the certificate body.
fn der_from_pem(pem_text: &str) -> Vec<u8> {
    let body: String = pem_text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .expect("PEM body was not valid base64")
}

/// Generate an issuer key and issue a certificate with the standard claims,
/// returning the cert path and the issuer public key hex.
fn ca_issue_fixture(dir: &Path, validity_days: &str) -> (std::path::PathBuf, String) {
    let key_path = dir.join("issuer.key");
    let claims_path = dir.join("claims.json");
    let cert_path = dir.join("subject.pem");

    let generate = run_lys(&["key", "generate", "--out", path_str(&key_path)]);
    assert_eq!(generate.status.code(), Some(0), "{}", stderr_of(&generate));
    let issuer_pub = field(&stdout_of(&generate), "public key (ed25519):");
    std::fs::write(&claims_path, CLAIMS_JSON).unwrap();

    let issue = run_lys(&[
        "ca",
        "issue",
        "--key",
        path_str(&key_path),
        "--subject",
        "agent-under-test",
        "--claims",
        path_str(&claims_path),
        "--validity-days",
        validity_days,
        "--out",
        path_str(&cert_path),
    ]);
    assert_eq!(issue.status.code(), Some(0), "{}", stderr_of(&issue));
    (cert_path, issuer_pub)
}

#[test]
fn ca_issue_writes_pem_certificate_that_lys_core_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("issuer.key");
    let claims_path = dir.path().join("claims.json");
    let cert_path = dir.path().join("subject.pem");

    let generate = run_lys(&["key", "generate", "--out", path_str(&key_path)]);
    assert_eq!(generate.status.code(), Some(0), "{}", stderr_of(&generate));
    std::fs::write(&claims_path, CLAIMS_JSON).unwrap();

    let output = run_lys(&[
        "ca",
        "issue",
        "--key",
        path_str(&key_path),
        "--subject",
        "agent-under-test",
        "--claims",
        path_str(&claims_path),
        "--validity-days",
        "1",
        "--out",
        path_str(&cert_path),
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr_of(&output));
    let stdout = stdout_of(&output);

    // The written file is PEM whose DER verifies through lys-core directly
    // against the issuer key, and carries the claims byte-for-byte under the
    // documented OID.
    let pem_text = std::fs::read_to_string(&cert_path).unwrap();
    assert!(pem_text.starts_with("-----BEGIN CERTIFICATE-----"));
    let der = der_from_pem(&pem_text);
    let identity = Ed25519Identity::load_or_generate(&key_path).unwrap();
    verify_certificate_chain(&der, &identity.public_key_bytes()).unwrap();
    assert_eq!(
        decode_extension(&der, CLAIMS_OID).unwrap(),
        Some(CLAIMS_JSON.as_bytes().to_vec())
    );

    // Printed metadata is public-only and consistent with the issuer key.
    assert_eq!(
        field(&stdout, "issuer public key (ed25519):"),
        hex_lower(&identity.public_key_bytes())
    );
    assert_eq!(field(&stdout, "subject public key (ed25519):").len(), 64);
    assert_eq!(field(&stdout, "fingerprint (sha256):").len(), 64);

    // The issuer seed never leaks, and no subject key file is minted — the
    // only files in the directory are the ones this test created plus the
    // certificate.
    let seed_hex = hex_lower(&std::fs::read(&key_path).unwrap());
    assert!(
        !stdout.contains(&seed_hex),
        "private seed leaked into stdout"
    );
    assert!(
        !pem_text.contains(&seed_hex),
        "private seed leaked into certificate"
    );
    let mut entries: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    assert_eq!(
        entries,
        vec!["claims.json", "issuer.key", "subject.pem"],
        "ca issue must not create extra files (e.g. a subject key)"
    );
}

#[test]
fn ca_issue_with_missing_key_fails_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("absent.key");
    let cert_path = dir.path().join("subject.pem");

    let output = run_lys(&[
        "ca",
        "issue",
        "--key",
        path_str(&key_path),
        "--subject",
        "agent-under-test",
        "--validity-days",
        "1",
        "--out",
        path_str(&cert_path),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("identity key file not found"),
        "stderr: {stderr}"
    );
    assert!(
        !cert_path.exists(),
        "no certificate may be written on failure"
    );
    assert!(
        !key_path.exists(),
        "ca issue must never create a key file as a side effect"
    );
}

#[test]
fn ca_issue_rejects_malformed_claims_json_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("issuer.key");
    let claims_path = dir.path().join("claims.json");
    let cert_path = dir.path().join("subject.pem");

    let generate = run_lys(&["key", "generate", "--out", path_str(&key_path)]);
    assert_eq!(generate.status.code(), Some(0), "{}", stderr_of(&generate));
    std::fs::write(&claims_path, b"{ not json ]").unwrap();

    let output = run_lys(&[
        "ca",
        "issue",
        "--key",
        path_str(&key_path),
        "--subject",
        "agent-under-test",
        "--claims",
        path_str(&claims_path),
        "--validity-days",
        "1",
        "--out",
        path_str(&cert_path),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("capability claims JSON"),
        "stderr: {stderr}"
    );
    assert!(
        !cert_path.exists(),
        "no certificate may be written on failure"
    );
}

// ------------------------------------------------------------------ ca verify

#[test]
fn ca_verify_accepts_valid_certificate_with_exit_zero() {
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, issuer_pub) = ca_issue_fixture(dir.path(), "1");

    let output = run_lys(&[
        "ca",
        "verify",
        "--cert",
        path_str(&cert_path),
        "--issuer-public-key",
        &issuer_pub,
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr_of(&output));
    let stdout = stdout_of(&output);
    assert!(stdout.contains("certificate verified"), "{stdout}");
    assert_eq!(field(&stdout, "issuer public key (ed25519):"), issuer_pub);
    assert_eq!(field(&stdout, "capability claims:"), CLAIMS_JSON);
}

#[test]
fn ca_verify_accepts_explicit_instant_inside_the_window() {
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, issuer_pub) = ca_issue_fixture(dir.path(), "2");
    let inside = (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339();

    let output = run_lys(&[
        "ca",
        "verify",
        "--cert",
        path_str(&cert_path),
        "--issuer-public-key",
        &issuer_pub,
        "--at",
        &inside,
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr_of(&output));
    assert!(
        stdout_of(&output).contains("certificate verified"),
        "{}",
        stdout_of(&output)
    );
}

#[test]
fn ca_verify_failures_collapse_to_one_generic_message() {
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, issuer_pub) = ca_issue_fixture(dir.path(), "1");

    // A different (untrusted) issuer key.
    let other_key = dir.path().join("other.key");
    let generate = run_lys(&["key", "generate", "--out", path_str(&other_key)]);
    assert_eq!(generate.status.code(), Some(0), "{}", stderr_of(&generate));
    let wrong_pub = field(&stdout_of(&generate), "public key (ed25519):");

    let before_window = "2000-01-01T00:00:00Z".to_string();
    let after_window = (chrono::Utc::now() + chrono::Duration::days(400)).to_rfc3339();

    let cases: Vec<Vec<&str>> = vec![
        // Wrong issuer key at a valid instant.
        vec![
            "ca",
            "verify",
            "--cert",
            path_str(&cert_path),
            "--issuer-public-key",
            &wrong_pub,
        ],
        // Right issuer key, before the validity window.
        vec![
            "ca",
            "verify",
            "--cert",
            path_str(&cert_path),
            "--issuer-public-key",
            &issuer_pub,
            "--at",
            &before_window,
        ],
        // Right issuer key, after the validity window.
        vec![
            "ca",
            "verify",
            "--cert",
            path_str(&cert_path),
            "--issuer-public-key",
            &issuer_pub,
            "--at",
            &after_window,
        ],
    ];

    let mut messages = Vec::new();
    for args in &cases {
        let output = run_lys(args);
        assert_eq!(output.status.code(), Some(1), "args: {args:?}");
        let stderr = stderr_of(&output);
        assert!(
            stderr.contains("certificate verification failed"),
            "stderr: {stderr}"
        );
        assert!(
            !stdout_of(&output).contains("certificate verified"),
            "must not claim success"
        );
        messages.push(stderr);
    }
    // Non-oracle: wrong key, not-yet-valid, and expired must all be
    // indistinguishable from the caller's side.
    assert_eq!(messages[0], messages[1]);
    assert_eq!(messages[1], messages[2]);
}

#[test]
fn ca_verify_rejects_malformed_at_timestamp() {
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, issuer_pub) = ca_issue_fixture(dir.path(), "1");

    let output = run_lys(&[
        "ca",
        "verify",
        "--cert",
        path_str(&cert_path),
        "--issuer-public-key",
        &issuer_pub,
        "--at",
        "yesterday at noon",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(stderr.contains("invalid timestamp"), "stderr: {stderr}");
    assert!(stderr.contains("RFC 3339"), "stderr: {stderr}");
}

#[test]
fn ca_verify_rejects_invalid_issuer_public_key_hex() {
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, _) = ca_issue_fixture(dir.path(), "1");

    for bad in ["zz", "abc123", &"ab".repeat(33)] {
        let output = run_lys(&[
            "ca",
            "verify",
            "--cert",
            path_str(&cert_path),
            "--issuer-public-key",
            bad,
        ]);
        assert_eq!(output.status.code(), Some(1), "input: {bad}");
        assert!(
            stderr_of(&output).contains("invalid issuer public key"),
            "stderr: {}",
            stderr_of(&output)
        );
    }
}

#[test]
fn ca_verify_rejects_non_pem_certificate_file() {
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("bogus.pem");
    std::fs::write(&cert_path, b"this is not a certificate").unwrap();

    let output = run_lys(&[
        "ca",
        "verify",
        "--cert",
        path_str(&cert_path),
        "--issuer-public-key",
        &"ab".repeat(32),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("failed to parse PEM certificate"),
        "stderr: {stderr}"
    );
}

#[test]
fn ca_verify_echoes_control_character_claims_as_hex_never_raw() {
    // `lys ca issue` only embeds valid JSON, but `ca verify` must handle
    // certificates from ANY issuer under the trusted key. Issue one directly
    // through lys-core with raw terminal escape bytes in the claims
    // extension and confirm the CLI hex-encodes rather than replays them.
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("issuer.key");
    let cert_path = dir.path().join("hostile-claims.pem");

    let generate = run_lys(&["key", "generate", "--out", path_str(&key_path)]);
    assert_eq!(generate.status.code(), Some(0), "{}", stderr_of(&generate));
    let issuer_pub = field(&stdout_of(&generate), "public key (ed25519):");

    let identity = lys_core::Ed25519Identity::load(&key_path).unwrap();
    let authority = CertificateAuthority::new(identity);
    let hostile_claims = b"claims \x1b[2K\x1b[1A certificate verified (spoofed)".to_vec();
    let issued = authority
        .issue_certificate(
            "escape-artist",
            std::time::Duration::from_secs(86_400),
            vec![encode_extension(CLAIMS_OID, hostile_claims)],
        )
        .unwrap();

    let body = base64::engine::general_purpose::STANDARD.encode(&issued.der_bytes);
    let mut pem_text = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in body.as_bytes().chunks(64) {
        pem_text.push_str(std::str::from_utf8(chunk).unwrap());
        pem_text.push('\n');
    }
    pem_text.push_str("-----END CERTIFICATE-----\n");
    std::fs::write(&cert_path, pem_text).unwrap();

    let output = run_lys(&[
        "ca",
        "verify",
        "--cert",
        path_str(&cert_path),
        "--issuer-public-key",
        &issuer_pub,
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr_of(&output));
    let stdout = stdout_of(&output);
    assert!(
        !stdout.contains('\u{1b}'),
        "raw escape byte replayed to the terminal: {stdout:?}"
    );
    assert!(
        stdout.contains("capability claims (hex):"),
        "control-character claims must fall back to hex: {stdout}"
    );
}

// ----------------------------------------------------------------- seal / open

/// Everything `seal_fixture` produces, so tests can pick what they need.
struct SealFixture {
    sender_key: std::path::PathBuf,
    recipient_key: std::path::PathBuf,
    payload_path: std::path::PathBuf,
    envelope_path: std::path::PathBuf,
    attestation_path: std::path::PathBuf,
    sender_pub: String,
    recipient_x25519_pub: String,
}

/// Generate sender and recipient keys, then run `lys seal` end to end.
fn seal_fixture(dir: &Path, payload: &[u8]) -> SealFixture {
    let sender_key = dir.join("sender.key");
    let recipient_key = dir.join("recipient.key");
    let payload_path = dir.join("payload.bin");
    let envelope_path = dir.join("envelope.json");
    let attestation_path = dir.join("seal-attestation.json");

    let generate_sender = run_lys(&["key", "generate", "--out", path_str(&sender_key)]);
    assert_eq!(
        generate_sender.status.code(),
        Some(0),
        "{}",
        stderr_of(&generate_sender)
    );
    let sender_pub = field(&stdout_of(&generate_sender), "public key (ed25519):");

    let generate_recipient = run_lys(&["key", "generate", "--out", path_str(&recipient_key)]);
    assert_eq!(
        generate_recipient.status.code(),
        Some(0),
        "{}",
        stderr_of(&generate_recipient)
    );
    let inspect = run_lys(&["key", "inspect", "--key", path_str(&recipient_key)]);
    assert_eq!(inspect.status.code(), Some(0), "{}", stderr_of(&inspect));
    let recipient_x25519_pub = field(&stdout_of(&inspect), "public key (x25519):");

    std::fs::write(&payload_path, payload).unwrap();
    let seal = run_lys(&[
        "seal",
        "--key",
        path_str(&sender_key),
        "--recipient-public-key",
        &recipient_x25519_pub,
        "--payload",
        path_str(&payload_path),
        "--out",
        path_str(&envelope_path),
        "--attestation-out",
        path_str(&attestation_path),
    ]);
    assert_eq!(seal.status.code(), Some(0), "{}", stderr_of(&seal));

    SealFixture {
        sender_key,
        recipient_key,
        payload_path,
        envelope_path,
        attestation_path,
        sender_pub,
        recipient_x25519_pub,
    }
}

#[test]
fn seal_writes_envelope_and_attestation_that_lys_core_opens() {
    let dir = tempfile::tempdir().unwrap();
    let payload: &[u8] = b"credential bundle: api token hunter2";
    let fixture = seal_fixture(dir.path(), payload);

    // Both files are the exact lys-core wire shapes, and the pair opens
    // through the library directly with the recipient's key.
    let envelope_json = std::fs::read_to_string(&fixture.envelope_path).unwrap();
    let envelope: SealedEnvelope = serde_json::from_str(&envelope_json).unwrap();
    let attestation_json = std::fs::read_to_string(&fixture.attestation_path).unwrap();
    let attestation: Attestation = serde_json::from_str(&attestation_json).unwrap();

    let sender = Ed25519Identity::load_or_generate(&fixture.sender_key).unwrap();
    let recipient = Ed25519Identity::load_or_generate(&fixture.recipient_key).unwrap();
    assert_eq!(attestation.signer_public_key, sender.public_key_bytes());
    let opened = open_and_verify(
        &envelope,
        &attestation,
        &sender.public_key_bytes(),
        &recipient.x25519_static_secret(),
    )
    .unwrap();
    assert_eq!(opened.as_slice(), payload);

    // The ciphertext is not the plaintext, and neither the plaintext nor
    // either private seed appears in any output.
    assert_ne!(envelope.ciphertext.as_slice(), payload);
    let seal_output = run_lys(&[
        "seal",
        "--key",
        path_str(&fixture.sender_key),
        "--recipient-public-key",
        &fixture.recipient_x25519_pub,
        "--payload",
        path_str(&fixture.payload_path),
        "--out",
        path_str(&fixture.envelope_path),
        "--attestation-out",
        path_str(&fixture.attestation_path),
    ]);
    assert_eq!(seal_output.status.code(), Some(0));
    let stdout = stdout_of(&seal_output);
    assert!(
        !stdout.contains("hunter2"),
        "plaintext leaked into stdout: {stdout}"
    );
    for key_path in [&fixture.sender_key, &fixture.recipient_key] {
        let seed_hex = hex_lower(&std::fs::read(key_path).unwrap());
        assert!(
            !stdout.contains(&seed_hex),
            "private seed leaked into stdout"
        );
        assert!(
            !envelope_json.contains(&seed_hex),
            "private seed leaked into envelope"
        );
    }
    assert_eq!(field(&stdout, "sender public key (ed25519):").len(), 64);
    assert_eq!(
        field(&stdout, "recipient public key (x25519):"),
        fixture.recipient_x25519_pub
    );
}

#[test]
fn seal_with_missing_key_fails_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let payload_path = dir.path().join("payload.bin");
    let envelope_path = dir.path().join("envelope.json");
    let attestation_path = dir.path().join("seal-attestation.json");
    std::fs::write(&payload_path, b"payload").unwrap();

    let output = run_lys(&[
        "seal",
        "--key",
        path_str(&dir.path().join("absent.key")),
        "--recipient-public-key",
        &"ab".repeat(32),
        "--payload",
        path_str(&payload_path),
        "--out",
        path_str(&envelope_path),
        "--attestation-out",
        path_str(&attestation_path),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("identity key file not found"),
        "stderr: {stderr}"
    );
    assert!(!envelope_path.exists(), "no envelope on failure");
    assert!(!attestation_path.exists(), "no attestation on failure");
    assert!(
        !dir.path().join("absent.key").exists(),
        "seal must never create a key file as a side effect"
    );
}

#[test]
fn seal_rejects_invalid_recipient_public_key_hex() {
    let dir = tempfile::tempdir().unwrap();
    let sender_key = dir.path().join("sender.key");
    let payload_path = dir.path().join("payload.bin");
    let envelope_path = dir.path().join("envelope.json");
    let attestation_path = dir.path().join("seal-attestation.json");

    let generate = run_lys(&["key", "generate", "--out", path_str(&sender_key)]);
    assert_eq!(generate.status.code(), Some(0), "{}", stderr_of(&generate));
    std::fs::write(&payload_path, b"payload").unwrap();

    for bad in ["zz", "abc123", &"ab".repeat(33)] {
        let output = run_lys(&[
            "seal",
            "--key",
            path_str(&sender_key),
            "--recipient-public-key",
            bad,
            "--payload",
            path_str(&payload_path),
            "--out",
            path_str(&envelope_path),
            "--attestation-out",
            path_str(&attestation_path),
        ]);
        assert_eq!(output.status.code(), Some(1), "input: {bad}");
        assert!(
            stderr_of(&output).contains("invalid recipient public key"),
            "stderr: {}",
            stderr_of(&output)
        );
        assert!(!envelope_path.exists(), "no envelope on failure");
    }
}

#[test]
fn seal_attestation_write_failure_leaves_no_partial_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let sender_key = dir.path().join("sender.key");
    let recipient_key = dir.path().join("recipient.key");
    let payload_path = dir.path().join("payload.bin");
    let envelope_path = dir.path().join("envelope.json");
    // Unwritable attestation destination: parent directory does not exist.
    let attestation_path = dir.path().join("no-such-dir").join("attestation.json");

    let generate_sender = run_lys(&["key", "generate", "--out", path_str(&sender_key)]);
    assert_eq!(
        generate_sender.status.code(),
        Some(0),
        "{}",
        stderr_of(&generate_sender)
    );
    let generate_recipient = run_lys(&["key", "generate", "--out", path_str(&recipient_key)]);
    assert_eq!(
        generate_recipient.status.code(),
        Some(0),
        "{}",
        stderr_of(&generate_recipient)
    );
    let inspect = run_lys(&["key", "inspect", "--key", path_str(&recipient_key)]);
    assert_eq!(inspect.status.code(), Some(0), "{}", stderr_of(&inspect));
    let recipient_x25519_pub = field(&stdout_of(&inspect), "public key (x25519):");
    std::fs::write(&payload_path, b"payload").unwrap();

    let output = run_lys(&[
        "seal",
        "--key",
        path_str(&sender_key),
        "--recipient-public-key",
        &recipient_x25519_pub,
        "--payload",
        path_str(&payload_path),
        "--out",
        path_str(&envelope_path),
        "--attestation-out",
        path_str(&attestation_path),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr_of(&output).contains("seal attestation file"),
        "stderr: {}",
        stderr_of(&output)
    );
    // The envelope written before the attestation failure must be cleaned
    // up: an envelope without its attestation is unopenable, and failed
    // commands leave no partial outputs.
    assert!(
        !envelope_path.exists(),
        "orphaned envelope left behind after attestation write failure"
    );
}

#[cfg(unix)]
#[test]
fn open_writes_plaintext_owner_readable_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let fixture = seal_fixture(dir.path(), b"confidential payload");
    let out_path = dir.path().join("opened.bin");

    let output = run_lys(&[
        "open",
        "--key",
        path_str(&fixture.recipient_key),
        "--sender-public-key",
        &fixture.sender_pub,
        "--envelope",
        path_str(&fixture.envelope_path),
        "--attestation",
        path_str(&fixture.attestation_path),
        "--out",
        path_str(&out_path),
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr_of(&output));

    let mode = std::fs::metadata(&out_path).unwrap().permissions().mode();
    assert_eq!(
        mode & 0o777,
        0o600,
        "recovered plaintext must be owner-readable only"
    );
}

#[test]
fn open_recovers_payload_without_printing_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let payload: &[u8] = b"sealed secret: hunter2";
    let fixture = seal_fixture(dir.path(), payload);
    let out_path = dir.path().join("opened.bin");

    let output = run_lys(&[
        "open",
        "--key",
        path_str(&fixture.recipient_key),
        "--sender-public-key",
        &fixture.sender_pub,
        "--envelope",
        path_str(&fixture.envelope_path),
        "--attestation",
        path_str(&fixture.attestation_path),
        "--out",
        path_str(&out_path),
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr_of(&output));

    // Exact plaintext recovered on disk; stdout carries only metadata.
    assert_eq!(std::fs::read(&out_path).unwrap(), payload);
    let stdout = stdout_of(&output);
    assert!(stdout.contains("sealed envelope opened"), "{stdout}");
    assert!(
        !stdout.contains("hunter2"),
        "plaintext leaked into stdout: {stdout}"
    );
    assert_eq!(
        field(&stdout, "sender public key (ed25519):"),
        fixture.sender_pub
    );
    assert_eq!(field(&stdout, "payload bytes:"), payload.len().to_string());
    let seed_hex = hex_lower(&std::fs::read(&fixture.recipient_key).unwrap());
    assert!(
        !stdout.contains(&seed_hex),
        "private seed leaked into stdout"
    );
}

#[test]
fn open_failures_collapse_to_one_generic_message() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = seal_fixture(dir.path(), b"non-oracle payload");
    let out_path = dir.path().join("opened.bin");

    // An unrelated identity: wrong recipient key, and wrong expected sender.
    let other_key = dir.path().join("other.key");
    let generate = run_lys(&["key", "generate", "--out", path_str(&other_key)]);
    assert_eq!(generate.status.code(), Some(0), "{}", stderr_of(&generate));
    let other_pub = field(&stdout_of(&generate), "public key (ed25519):");

    // A tampered envelope: flip one ciphertext byte, keeping the JSON shape.
    let tampered_envelope = dir.path().join("tampered-envelope.json");
    let mut envelope: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&fixture.envelope_path).unwrap()).unwrap();
    let byte = envelope["ciphertext"][0].as_u64().unwrap();
    envelope["ciphertext"][0] = serde_json::Value::from(byte ^ 0x01);
    std::fs::write(
        &tampered_envelope,
        serde_json::to_string(&envelope).unwrap(),
    )
    .unwrap();

    // A tampered attestation: flip one signature byte, keeping the shape.
    let tampered_attestation = dir.path().join("tampered-attestation.json");
    let mut attestation: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&fixture.attestation_path).unwrap()).unwrap();
    let sig_byte = attestation["signature"][0].as_u64().unwrap();
    attestation["signature"][0] = serde_json::Value::from(sig_byte ^ 0x01);
    std::fs::write(
        &tampered_attestation,
        serde_json::to_string(&attestation).unwrap(),
    )
    .unwrap();

    let cases: Vec<Vec<&str>> = vec![
        // Wrong recipient key (decryption would fail).
        vec![
            "open",
            "--key",
            path_str(&other_key),
            "--sender-public-key",
            &fixture.sender_pub,
            "--envelope",
            path_str(&fixture.envelope_path),
            "--attestation",
            path_str(&fixture.attestation_path),
            "--out",
            path_str(&out_path),
        ],
        // Wrong expected sender (attestation binding fails).
        vec![
            "open",
            "--key",
            path_str(&fixture.recipient_key),
            "--sender-public-key",
            &other_pub,
            "--envelope",
            path_str(&fixture.envelope_path),
            "--attestation",
            path_str(&fixture.attestation_path),
            "--out",
            path_str(&out_path),
        ],
        // Tampered ciphertext (signature over envelope bytes fails).
        vec![
            "open",
            "--key",
            path_str(&fixture.recipient_key),
            "--sender-public-key",
            &fixture.sender_pub,
            "--envelope",
            path_str(&tampered_envelope),
            "--attestation",
            path_str(&fixture.attestation_path),
            "--out",
            path_str(&out_path),
        ],
        // Tampered attestation signature.
        vec![
            "open",
            "--key",
            path_str(&fixture.recipient_key),
            "--sender-public-key",
            &fixture.sender_pub,
            "--envelope",
            path_str(&fixture.envelope_path),
            "--attestation",
            path_str(&tampered_attestation),
            "--out",
            path_str(&out_path),
        ],
    ];

    let mut messages = Vec::new();
    for args in &cases {
        let output = run_lys(args);
        assert_eq!(output.status.code(), Some(1), "args: {args:?}");
        let stderr = stderr_of(&output);
        assert!(
            stderr.contains("sealed envelope open failed"),
            "stderr: {stderr}"
        );
        assert!(
            !stdout_of(&output).contains("sealed envelope opened"),
            "must not claim success"
        );
        assert!(!out_path.exists(), "no plaintext may be written on failure");
        messages.push(stderr);
    }
    // Non-oracle: wrong recipient key, wrong sender, tampered envelope, and
    // tampered attestation must all be indistinguishable to the caller.
    for message in &messages[1..] {
        assert_eq!(&messages[0], message);
    }
}

#[test]
fn open_with_missing_key_fails_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = seal_fixture(dir.path(), b"payload");
    let out_path = dir.path().join("opened.bin");
    let absent_key = dir.path().join("absent.key");

    let output = run_lys(&[
        "open",
        "--key",
        path_str(&absent_key),
        "--sender-public-key",
        &fixture.sender_pub,
        "--envelope",
        path_str(&fixture.envelope_path),
        "--attestation",
        path_str(&fixture.attestation_path),
        "--out",
        path_str(&out_path),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("identity key file not found"),
        "stderr: {stderr}"
    );
    assert!(!out_path.exists(), "no plaintext may be written on failure");
    assert!(
        !absent_key.exists(),
        "open must never create a key file as a side effect"
    );
}

#[test]
fn open_rejects_malformed_envelope_json() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = seal_fixture(dir.path(), b"payload");
    let out_path = dir.path().join("opened.bin");
    let bogus_envelope = dir.path().join("bogus.json");
    std::fs::write(&bogus_envelope, b"{ not json ]").unwrap();

    let output = run_lys(&[
        "open",
        "--key",
        path_str(&fixture.recipient_key),
        "--sender-public-key",
        &fixture.sender_pub,
        "--envelope",
        path_str(&bogus_envelope),
        "--attestation",
        path_str(&fixture.attestation_path),
        "--out",
        path_str(&out_path),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("failed to parse sealed envelope JSON"),
        "stderr: {stderr}"
    );
    assert!(!out_path.exists(), "no plaintext may be written on failure");
}

#[test]
fn verify_rejects_malformed_attestation_json_with_exit_one() {
    let dir = tempfile::tempdir().unwrap();
    let attestation_path = dir.path().join("attestation.json");
    let payload_path = dir.path().join("payload.bin");
    std::fs::write(&attestation_path, b"{ not json ]").unwrap();
    std::fs::write(&payload_path, b"payload").unwrap();

    let output = run_lys(&[
        "verify",
        "--attestation",
        path_str(&attestation_path),
        "--payload",
        path_str(&payload_path),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("failed to parse attestation JSON"),
        "stderr: {stderr}"
    );
}

// ------------------------------------------------- key inspect --note-name

/// Golden test seed from the design (32 ASCII bytes), shared with the
/// lys-core golden vectors and the Go conformance gate.
const GOLDEN_SEED: &[u8; 32] = b"lys-go-conformance-test-seed-01!";

/// Golden verifier key text form for (example.com/lys/test, golden pubkey).
const GOLDEN_VERIFIER_SPEC: &str =
    "example.com/lys/test+52580cd9+AQz9D9gbFqzLxSMM9Fy6nUuTfYJ8bI29RKFE5aulcbni";

#[test]
fn key_inspect_note_name_prints_golden_verifier_key() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("golden.key");
    std::fs::write(&key_path, GOLDEN_SEED).unwrap();

    let output = run_lys(&[
        "key",
        "inspect",
        "--key",
        path_str(&key_path),
        "--note-name",
        "example.com/lys/test",
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr_of(&output));
    let stdout = stdout_of(&output);
    let spec = field(&stdout, "verifier key (signed-note):");
    assert_eq!(spec, GOLDEN_VERIFIER_SPEC);

    // Cross-check against the library's own derivation.
    let identity = Ed25519Identity::load_or_generate(&key_path).unwrap();
    let expected = lys_core::checkpoint::NoteVerifierKey::new(
        "example.com/lys/test",
        identity.public_key_bytes(),
    )
    .unwrap();
    assert_eq!(spec, expected.to_spec());

    // Still never prints private material.
    let seed_hex = hex_lower(GOLDEN_SEED);
    assert!(!stdout.contains(&seed_hex), "private seed leaked");
}

#[test]
fn key_inspect_without_note_name_prints_no_verifier_line() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("golden.key");
    std::fs::write(&key_path, GOLDEN_SEED).unwrap();

    let output = run_lys(&["key", "inspect", "--key", path_str(&key_path)]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr_of(&output));
    assert!(
        !stdout_of(&output).contains("verifier key"),
        "no verifier line without --note-name: {}",
        stdout_of(&output)
    );
}

#[test]
fn key_inspect_note_name_rejects_invalid_names() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("golden.key");
    std::fs::write(&key_path, GOLDEN_SEED).unwrap();

    for bad in ["has space", "has+plus", ""] {
        let output = run_lys(&[
            "key",
            "inspect",
            "--key",
            path_str(&key_path),
            "--note-name",
            bad,
        ]);
        assert_eq!(output.status.code(), Some(1), "name {bad:?} was accepted");
        let stderr = stderr_of(&output);
        assert!(stderr.contains("invalid note verifier key"), "{stderr}");
    }
}
