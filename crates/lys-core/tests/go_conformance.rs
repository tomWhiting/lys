//! D6 conformance gate: round-trip the `lys` signed-note implementation
//! against the Go `sumdb/note` reference implementation.
//!
//! # Environment contract
//!
//! The Go scaffold in `tests/go-conformance/` is fully vendored
//! (`go mod vendor`, pinned `golang.org/x/mod v0.22.0`); every invocation
//! runs with `GOFLAGS=-mod=vendor GOPROXY=off GOTOOLCHAIN=local` and a
//! throwaway `GOCACHE`, so the gate needs zero network. The toolchain is
//! located via `LYS_GO_BIN`, then `/usr/local/go/bin/go`, then `go` on
//! `PATH`. If none is found, the Go round-trip tests print a skip notice
//! and return — but a toolchain that is present and BROKEN is a hard test
//! failure, deliberately.
//!
//! The pure-Rust golden assertions in this file run unconditionally, so a
//! Go-less environment never reduces byte-exact coverage (the primary
//! copies of these vectors live in the always-run unit tests as well).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use lys_core::Ed25519Identity;
use lys_core::checkpoint::{NoteVerifierKey, sign_note, verify_note};

/// Fixed test seed: the 32 ASCII bytes `"lys-go-conformance-test-seed-01!"`.
const GOLDEN_SEED: &[u8; 32] = b"lys-go-conformance-test-seed-01!";

/// Hex form of the seed, handed to the Go tool's `sign` mode.
const GOLDEN_SEED_HEX: &str = "6c79732d676f2d636f6e666f726d616e63652d746573742d736565642d303121";

const GOLDEN_NAME: &str = "example.com/lys/test";

const GOLDEN_BODY: &str = "example.com/lys/test\n3\nz3Y6BByBzu8VeKYIP3XGG+8uABTyo+aDqX/Pylvn8Zo=\n";

/// First 4 bytes of `SHA-256(name ‖ 0x0A ‖ 0x01 ‖ pubkey)` for the golden
/// name and key.
const GOLDEN_KEY_ID: [u8; 4] = [0x52, 0x58, 0x0c, 0xd9];

const GOLDEN_VERIFIER_SPEC: &str =
    "example.com/lys/test+52580cd9+AQz9D9gbFqzLxSMM9Fy6nUuTfYJ8bI29RKFE5aulcbni";

/// The complete golden note, byte-identical to Go `note.Sign` output for
/// the same body/name/seed (Ed25519 is deterministic).
const GOLDEN_NOTE: &str = "example.com/lys/test\n3\nz3Y6BByBzu8VeKYIP3XGG+8uABTyo+aDqX/Pylvn8Zo=\n\n\u{2014} example.com/lys/test UlgM2S4MVZwL9PUGADbPhidG6yKCC0hCE+sx7iXFboC6/rex00vtEy4d33ODa1g0afYmx36opQUAXnwdUl9E7eE28QU=\n";

fn golden_identity() -> (tempfile::TempDir, Ed25519Identity) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("golden.key");
    std::fs::write(&path, GOLDEN_SEED).unwrap();
    let identity = Ed25519Identity::load(&path).unwrap();
    (dir, identity)
}

fn golden_verifier() -> NoteVerifierKey {
    NoteVerifierKey::from_spec(GOLDEN_VERIFIER_SPEC).unwrap()
}

/// Pure-Rust golden assertions — run unconditionally, Go or no Go, so the
/// gate file alone is self-evidently covered even when the round-trip
/// skips.
#[test]
fn golden_vectors_pure_rust() {
    let (_dir, identity) = golden_identity();

    let note = sign_note(GOLDEN_BODY, GOLDEN_NAME, &identity).unwrap();
    assert_eq!(note, GOLDEN_NOTE);

    let verifier = golden_verifier();
    assert_eq!(verifier.to_spec(), GOLDEN_VERIFIER_SPEC);
    assert_eq!(
        verifier,
        NoteVerifierKey::new(GOLDEN_NAME, identity.public_key_bytes()).unwrap()
    );

    let body = verify_note(GOLDEN_NOTE.as_bytes(), &verifier).unwrap();
    assert_eq!(body, GOLDEN_BODY);

    // Negative control: one flipped body byte rejects.
    let tampered = GOLDEN_NOTE.replacen("\n3\n", "\n4\n", 1);
    assert!(verify_note(tampered.as_bytes(), &verifier).is_err());
}

/// Locates the Go toolchain: `LYS_GO_BIN` override, then the pinned
/// absolute path, then `go` on PATH. `None` means "skip the round-trip".
fn find_go() -> Option<PathBuf> {
    if let Ok(overridden) = std::env::var("LYS_GO_BIN") {
        return Some(PathBuf::from(overridden));
    }
    let pinned = Path::new("/usr/local/go/bin/go");
    if pinned.exists() {
        return Some(pinned.to_path_buf());
    }
    let on_path = Command::new("go")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match on_path {
        Ok(status) if status.success() => Some(PathBuf::from("go")),
        _ => None,
    }
}

/// Runs the vendored Go tool hermetically with `input` on stdin; returns
/// `(exit_success, stdout_bytes)`. Any spawn failure with a PRESENT
/// toolchain is a hard panic — the environment contract is documented in
/// the file header.
fn run_go_tool(go: &Path, gocache: &Path, args: &[&str], input: &[u8]) -> (bool, Vec<u8>) {
    let scaffold_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/go-conformance");
    let mut child = Command::new(go)
        .arg("run")
        .arg(".")
        .args(args)
        .current_dir(&scaffold_dir)
        .env("GOFLAGS", "-mod=vendor")
        .env("GOPROXY", "off")
        .env("GOTOOLCHAIN", "local")
        .env("GOCACHE", gocache)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("failed to spawn the Go toolchain (present but broken is a hard failure)");
    child
        .stdin
        .take()
        .expect("child stdin is piped")
        .write_all(input)
        .expect("failed to write to the Go tool's stdin");
    let output = child
        .wait_with_output()
        .expect("failed to wait for the Go tool");
    (output.status.success(), output.stdout)
}

#[test]
fn go_conformance_round_trips() {
    let Some(go) = find_go() else {
        // The skip is for developer machines only. CI sets LYS_REQUIRE_GO,
        // so a missing toolchain there is a hard failure — the D6 gate can
        // never silently degrade to "passed" where it matters.
        assert!(
            std::env::var_os("LYS_REQUIRE_GO").is_none(),
            "LYS_REQUIRE_GO is set but no Go toolchain was found — \
             the Go conformance gate must not skip in this environment"
        );
        eprintln!("skipping Go conformance round-trip: no Go toolchain found");
        return;
    };
    let gocache_dir = tempfile::tempdir().unwrap();
    let gocache = gocache_dir.path().join("gocache");

    let (_dir, identity) = golden_identity();
    let verifier = golden_verifier();
    let rust_note = sign_note(GOLDEN_BODY, GOLDEN_NAME, &identity).unwrap();

    // Round-trip A (Rust -> Go): Go's reference verifier accepts the
    // Rust-built note under the Rust-built verifier-key string.
    let (ok, stdout) = run_go_tool(
        &go,
        &gocache,
        &["verify", GOLDEN_VERIFIER_SPEC],
        rust_note.as_bytes(),
    );
    assert!(ok, "Go note.Open rejected the Rust-built note");
    assert_eq!(
        stdout,
        GOLDEN_BODY.as_bytes(),
        "Go returned a different body"
    );

    // Round-trip B (Go -> Rust): the Go-built note verifies under the
    // Rust verifier, returning the same body.
    let (ok, go_note) = run_go_tool(
        &go,
        &gocache,
        &["sign", GOLDEN_NAME, GOLDEN_SEED_HEX],
        GOLDEN_BODY.as_bytes(),
    );
    assert!(ok, "Go note.Sign failed");
    let body = verify_note(&go_note, &verifier).unwrap();
    assert_eq!(body, GOLDEN_BODY);

    // Byte-identity: deterministic Ed25519 makes the two notes exact.
    assert_eq!(
        go_note,
        rust_note.as_bytes(),
        "Go and Rust notes must be byte-identical"
    );

    // Negative parity: one flipped body byte, rejected by BOTH.
    let tampered = rust_note.replacen("\n3\n", "\n4\n", 1);
    let (ok, _stdout) = run_go_tool(
        &go,
        &gocache,
        &["verify", GOLDEN_VERIFIER_SPEC],
        tampered.as_bytes(),
    );
    assert!(!ok, "Go accepted a tampered note");
    assert!(verify_note(tampered.as_bytes(), &verifier).is_err());

    // Split-point parity: Go note.Sign requires only a trailing newline,
    // so it will sign a body CONTAINING a blank line; both note.Open and
    // verify_note must split at the LAST "\n\n" and return that body
    // intact.
    let blank_line_body = "A\n\nB\n";
    let (ok, blank_note) = run_go_tool(
        &go,
        &gocache,
        &["sign", GOLDEN_NAME, GOLDEN_SEED_HEX],
        blank_line_body.as_bytes(),
    );
    assert!(ok, "Go note.Sign failed on a blank-line body");
    let (ok, go_body) = run_go_tool(
        &go,
        &gocache,
        &["verify", GOLDEN_VERIFIER_SPEC],
        &blank_note,
    );
    assert!(ok, "Go note.Open rejected its own blank-line-body note");
    assert_eq!(go_body, blank_line_body.as_bytes());
    let body = verify_note(&blank_note, &verifier).unwrap();
    assert_eq!(
        body, blank_line_body,
        "verify_note must split at the LAST blank line, exactly like Go"
    );

    // Failed-known-key parity: a garbage signature under the golden
    // (name, key ID) followed by the valid line is rejected by BOTH — Go
    // returns InvalidSignatureError for the first matching candidate and
    // never reaches the valid line; lys mirrors that hard reject.
    let mut garbage_blob = GOLDEN_KEY_ID.to_vec();
    garbage_blob.extend_from_slice(&[0u8; 64]);
    let garbage_line = format!(
        "\u{2014} {GOLDEN_NAME} {}\n",
        STANDARD.encode(&garbage_blob)
    );
    let valid_sig_line = &GOLDEN_NOTE[GOLDEN_BODY.len() + 1..];
    let poisoned = format!("{GOLDEN_BODY}\n{garbage_line}{valid_sig_line}");
    let (ok, _stdout) = run_go_tool(
        &go,
        &gocache,
        &["verify", GOLDEN_VERIFIER_SPEC],
        poisoned.as_bytes(),
    );
    assert!(
        !ok,
        "Go accepted a note with a failed known-key signature line"
    );
    assert!(
        verify_note(poisoned.as_bytes(), &verifier).is_err(),
        "lys must reject a failed known-key signature line, exactly like Go"
    );
}
