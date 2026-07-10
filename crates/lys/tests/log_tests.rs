//! End-to-end integration tests for the `lys log` command family.
//!
//! Every test drives the compiled binary through real process spawns
//! (`CARGO_BIN_EXE_lys`). The centrepiece is the third-party path: proofs
//! produced in one directory verify in a fresh directory holding ONLY the
//! artifacts, the proven leaf, and the verifier key string — never the log.
//! The tamper matrices assert the non-oracle discipline: every tamper class
//! within one artifact class produces the identical exit code AND stderr.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use lys_core::merkle::raw_leaf_hash;

/// Golden test seed from the design (32 ASCII bytes), shared with the
/// lys-core golden vectors and the Go conformance gate.
const GOLDEN_SEED: &[u8; 32] = b"lys-go-conformance-test-seed-01!";

/// Golden origin / note key name.
const GOLDEN_ORIGIN: &str = "example.com/lys/test";

/// Golden verifier key text form for (`GOLDEN_ORIGIN`, golden seed's pubkey).
const GOLDEN_VERIFIER_SPEC: &str =
    "example.com/lys/test+52580cd9+AQz9D9gbFqzLxSMM9Fy6nUuTfYJ8bI29RKFE5aulcbni";

/// Golden signed note over the size-3 checkpoint body (byte-identical to Go
/// `note.Sign` output; the primary copy is pinned in the lys-core tests).
const GOLDEN_NOTE: &str = "example.com/lys/test\n3\nz3Y6BByBzu8VeKYIP3XGG+8uABTyo+aDqX/Pylvn8Zo=\n\n\u{2014} example.com/lys/test UlgM2S4MVZwL9PUGADbPhidG6yKCC0hCE+sx7iXFboC6/rex00vtEy4d33ODa1g0afYmx36opQUAXnwdUl9E7eE28QU=\n";

/// Golden RFC 6962 leaf hash of the raw bytes `leaf-0`.
const GOLDEN_LEAF0_HASH: &str = "305df59f9590c3c9ac63d2b2743c388e3792449078cebf7fb3dbe6471643b2b7";

/// Golden root at size 3 over leaves `leaf-0`, `leaf-1`, `leaf-2`.
const GOLDEN_ROOT3_HEX: &str = "cf763a041c81ceef1578a6083f75c61bef2e0014f2a3e683a97fcfca5be7f19a";

/// The empty tree's root: SHA-256 of the empty string.
const EMPTY_ROOT_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Exact stderr of a failed `lys log verify inclusion` (crypto class).
const INCLUSION_FAIL_STDERR: &str =
    "error: inclusion proof verification failed: invalid artifact, checkpoint, or leaf\n";

/// Exact stderr of a failed `lys log verify consistency` (crypto class).
const CONSISTENCY_FAIL_STDERR: &str =
    "error: consistency proof verification failed: invalid artifact or checkpoints\n";

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

fn assert_success(output: &Output) {
    assert_eq!(output.status.code(), Some(0), "{}", stderr_of(output));
}

/// A fully built log: key, three leaves, checkpoint, and both artifacts.
struct ProvenLog {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    key: PathBuf,
    leaf_files: Vec<PathBuf>,
    verifier: String,
    checkpoint_file: PathBuf,
    checkpoint_stdout: String,
    append_stdouts: Vec<String>,
    inclusion_artifact: PathBuf,
    consistency_artifact: PathBuf,
    /// Every stdout/stderr captured while building, for leak checks.
    transcripts: Vec<String>,
}

/// Builds a log with three leaves and produces a checkpoint, an inclusion
/// artifact for leaf 1, and a consistency artifact from size 2 to 3.
///
/// `seed`: `Some(bytes)` writes that exact key file (golden vectors);
/// `None` runs `lys key generate`.
fn build_proven_log(origin: &str, seed: Option<&[u8; 32]>) -> ProvenLog {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("log");
    let key = tmp.path().join("operator.key");
    let mut transcripts = Vec::new();
    if let Some(bytes) = seed {
        std::fs::write(&key, bytes).unwrap();
    } else {
        let generate = run_lys(&["key", "generate", "--out", path_str(&key)]);
        assert_success(&generate);
        transcripts.push(stdout_of(&generate));
        transcripts.push(stderr_of(&generate));
    }
    let init = run_lys(&["log", "init", "--dir", path_str(&dir), "--origin", origin]);
    assert_success(&init);
    transcripts.push(stdout_of(&init));
    transcripts.push(stderr_of(&init));
    let mut leaf_files = Vec::new();
    let mut append_stdouts = Vec::new();
    for i in 0..3u32 {
        let leaf = tmp.path().join(format!("leaf-{i}.bin"));
        std::fs::write(&leaf, format!("leaf-{i}")).unwrap();
        let append = run_lys(&[
            "log",
            "append",
            "--dir",
            path_str(&dir),
            "--leaf",
            path_str(&leaf),
        ]);
        assert_success(&append);
        append_stdouts.push(stdout_of(&append));
        transcripts.push(stdout_of(&append));
        transcripts.push(stderr_of(&append));
        leaf_files.push(leaf);
    }
    let checkpoint_file = tmp.path().join("checkpoint.note");
    let checkpoint = run_lys(&[
        "log",
        "checkpoint",
        "--dir",
        path_str(&dir),
        "--key",
        path_str(&key),
        "--out",
        path_str(&checkpoint_file),
    ]);
    assert_success(&checkpoint);
    let checkpoint_stdout = stdout_of(&checkpoint);
    let verifier = field(&checkpoint_stdout, "verifier key (signed-note):");
    transcripts.push(stdout_of(&checkpoint));
    transcripts.push(stderr_of(&checkpoint));
    let inclusion_artifact = tmp.path().join("inclusion.json");
    let prove_inclusion = run_lys(&[
        "log",
        "prove",
        "inclusion",
        "--dir",
        path_str(&dir),
        "--key",
        path_str(&key),
        "--leaf-index",
        "1",
        "--out",
        path_str(&inclusion_artifact),
    ]);
    assert_success(&prove_inclusion);
    transcripts.push(stdout_of(&prove_inclusion));
    transcripts.push(stderr_of(&prove_inclusion));
    let consistency_artifact = tmp.path().join("consistency.json");
    let prove_consistency = run_lys(&[
        "log",
        "prove",
        "consistency",
        "--dir",
        path_str(&dir),
        "--key",
        path_str(&key),
        "--old-size",
        "2",
        "--out",
        path_str(&consistency_artifact),
    ]);
    assert_success(&prove_consistency);
    transcripts.push(stdout_of(&prove_consistency));
    transcripts.push(stderr_of(&prove_consistency));
    ProvenLog {
        _tmp: tmp,
        dir,
        key,
        leaf_files,
        verifier,
        checkpoint_file,
        checkpoint_stdout,
        append_stdouts,
        inclusion_artifact,
        consistency_artifact,
        transcripts,
    }
}

/// Writes `value` as JSON to a fresh file under `dir` and returns the path.
fn write_json(dir: &Path, name: &str, value: &serde_json::Value) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_string_pretty(value).unwrap()).unwrap();
    path
}

fn load_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

// ------------------------------------------------------------------ log init

#[test]
fn log_init_pins_origin_and_prints_empty_root() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("log");
    let output = run_lys(&[
        "log",
        "init",
        "--dir",
        path_str(&dir),
        "--origin",
        "example.com/lys/init-test",
    ]);
    assert_success(&output);
    let stdout = stdout_of(&output);
    assert_eq!(field(&stdout, "origin:"), "example.com/lys/init-test");
    assert_eq!(field(&stdout, "tree size:"), "0");
    assert_eq!(field(&stdout, "root hash (sha256):"), EMPTY_ROOT_HEX);

    // Re-init is refused: the origin is pinned exactly once.
    let again = run_lys(&[
        "log",
        "init",
        "--dir",
        path_str(&dir),
        "--origin",
        "example.com/lys/other",
    ]);
    assert_eq!(again.status.code(), Some(1));
    let stderr = stderr_of(&again);
    assert!(stderr.contains("log directory invalid"), "{stderr}");
    assert!(stderr.contains("already initialized"), "{stderr}");
}

#[test]
fn log_init_rejects_invalid_origins() {
    let tmp = tempfile::tempdir().unwrap();
    for (bad, tag) in [("has space", "space"), ("has+plus", "plus"), ("", "empty")] {
        let dir = tmp.path().join(format!("log-{tag}"));
        let output = run_lys(&["log", "init", "--dir", path_str(&dir), "--origin", bad]);
        assert_eq!(output.status.code(), Some(1), "origin {bad:?} was accepted");
        assert!(
            !dir.join("log.json").exists(),
            "invalid origin {bad:?} must not initialize a log"
        );
    }
}

// ------------------------------------------------------------ log checkpoint

#[test]
fn log_checkpoint_with_missing_key_fails_and_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("log");
    let init = run_lys(&[
        "log",
        "init",
        "--dir",
        path_str(&dir),
        "--origin",
        "example.com/lys/ckpt-fail",
    ]);
    assert_success(&init);

    let missing_key = tmp.path().join("no-such.key");
    let out = tmp.path().join("checkpoint.txt");
    let output = run_lys(&[
        "log",
        "checkpoint",
        "--dir",
        path_str(&dir),
        "--key",
        path_str(&missing_key),
        "--out",
        path_str(&out),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(stderr.contains("identity key file not found"), "{stderr}");
    assert!(stderr.contains("lys key generate"), "{stderr}");
    assert!(!out.exists(), "no checkpoint on failure");
    assert!(
        !missing_key.exists(),
        "checkpoint must never mint key material"
    );
}

#[test]
fn log_checkpoint_on_uninitialized_dir_fails_and_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let key = tmp.path().join("signer.key");
    let generate = run_lys(&["key", "generate", "--out", path_str(&key)]);
    assert_success(&generate);

    let out = tmp.path().join("checkpoint.txt");
    let output = run_lys(&[
        "log",
        "checkpoint",
        "--dir",
        path_str(&tmp.path().join("never-initialized")),
        "--key",
        path_str(&key),
        "--out",
        path_str(&out),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(stderr.contains("log init"), "remedy missing: {stderr}");
    assert!(!out.exists(), "no checkpoint on failure");
}

// ------------------------------------------------------- golden design vectors

#[test]
fn golden_log_reproduces_design_vectors_byte_for_byte() {
    let log = build_proven_log(GOLDEN_ORIGIN, Some(GOLDEN_SEED));

    // Leaf 0's printed hash is the golden RFC 6962 raw-leaf hash,
    // reproducible with `(printf '\x00'; cat leaf-file) | shasum -a 256`.
    assert_eq!(
        field(&log.append_stdouts[0], "leaf hash (sha256, rfc6962):"),
        GOLDEN_LEAF0_HASH
    );
    assert_eq!(hex_lower(&raw_leaf_hash(b"leaf-0")), GOLDEN_LEAF0_HASH);

    // The size-3 root and the verifier key match the design vectors.
    assert_eq!(
        field(&log.append_stdouts[2], "root hash (sha256):"),
        GOLDEN_ROOT3_HEX
    );
    let checkpoint_stdout = &log.checkpoint_stdout;
    assert_eq!(
        field(checkpoint_stdout, "root hash (sha256):"),
        GOLDEN_ROOT3_HEX
    );
    assert_eq!(field(checkpoint_stdout, "tree size:"), "3");
    assert_eq!(field(checkpoint_stdout, "origin:"), GOLDEN_ORIGIN);
    assert_eq!(log.verifier, GOLDEN_VERIFIER_SPEC);

    // The checkpoint note file is the golden note, byte for byte, and the
    // signature-line prefix is the exact em-dash bytes E2 80 94 20.
    let note_bytes = std::fs::read(&log.checkpoint_file).unwrap();
    assert_eq!(note_bytes, GOLDEN_NOTE.as_bytes());
    assert!(
        note_bytes.windows(4).any(|w| w == [0xe2, 0x80, 0x94, 0x20]),
        "note must contain the em-dash-space signature prefix bytes"
    );
}

// ---------------------------------------------------- third-party verification

#[test]
fn e2e_third_party_verifies_with_only_artifacts_leaf_and_verifier_key() {
    let log = build_proven_log("example.com/lys/e2e", None);
    let seed_hex = hex_lower(&std::fs::read(&log.key).unwrap());

    // "Process B": a fresh directory holding ONLY the two artifacts and the
    // one proven leaf file. No log directory, no key.
    let third_party = tempfile::tempdir().unwrap();
    let inclusion = third_party.path().join("inclusion.json");
    let consistency = third_party.path().join("consistency.json");
    let leaf = third_party.path().join("leaf-1.bin");
    std::fs::copy(&log.inclusion_artifact, &inclusion).unwrap();
    std::fs::copy(&log.consistency_artifact, &consistency).unwrap();
    std::fs::copy(&log.leaf_files[1], &leaf).unwrap();
    let entries_before = std::fs::read_dir(third_party.path()).unwrap().count();
    assert_eq!(
        entries_before, 3,
        "third-party dir must hold exactly 3 files"
    );

    let verify_inclusion = run_lys(&[
        "log",
        "verify",
        "inclusion",
        "--artifact",
        path_str(&inclusion),
        "--leaf",
        path_str(&leaf),
        "--verifier-key",
        &log.verifier,
    ]);
    assert_success(&verify_inclusion);
    let stdout = stdout_of(&verify_inclusion);
    assert!(stdout.contains("inclusion verified"), "{stdout}");
    assert_eq!(field(&stdout, "origin:"), "example.com/lys/e2e");
    assert_eq!(field(&stdout, "tree size:"), "3");
    assert_eq!(field(&stdout, "leaf index:"), "1");
    assert_eq!(
        field(&stdout, "root hash (sha256):"),
        field(&log.checkpoint_stdout, "root hash (sha256):"),
        "verified root must match the checkpointed root"
    );

    let verify_consistency = run_lys(&[
        "log",
        "verify",
        "consistency",
        "--artifact",
        path_str(&consistency),
        "--verifier-key",
        &log.verifier,
    ]);
    assert_success(&verify_consistency);
    let stdout = stdout_of(&verify_consistency);
    assert!(stdout.contains("consistency verified"), "{stdout}");
    assert_eq!(field(&stdout, "origin:"), "example.com/lys/e2e");
    assert_eq!(field(&stdout, "old tree size:"), "2");
    assert_eq!(field(&stdout, "new tree size:"), "3");

    // The third-party directory gained nothing: still exactly 3 files, no
    // log directory materialized.
    let entries_after: Vec<_> = std::fs::read_dir(third_party.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(entries_after.len(), 3, "verify must not create files");

    // The verify subcommands accept no --dir flag at all (clap exit 2).
    let with_dir = run_lys(&[
        "log",
        "verify",
        "inclusion",
        "--artifact",
        path_str(&inclusion),
        "--leaf",
        path_str(&leaf),
        "--verifier-key",
        &log.verifier,
        "--dir",
        path_str(&log.dir),
    ]);
    assert_eq!(with_dir.status.code(), Some(2), "--dir must be rejected");
    let with_dir_consistency = run_lys(&[
        "log",
        "verify",
        "consistency",
        "--artifact",
        path_str(&consistency),
        "--verifier-key",
        &log.verifier,
        "--dir",
        path_str(&log.dir),
    ]);
    assert_eq!(with_dir_consistency.status.code(), Some(2));

    // No private key material in any output from either side.
    for transcript in log
        .transcripts
        .iter()
        .map(String::as_str)
        .chain([stdout.as_str()])
    {
        assert!(
            !transcript.contains(&seed_hex),
            "private seed leaked into output"
        );
    }
}

// ------------------------------------------------------------- append behavior

#[test]
fn log_append_to_uninitialized_dir_names_remedy() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("no-log");
    let leaf = tmp.path().join("leaf.bin");
    std::fs::write(&leaf, b"data").unwrap();
    let output = run_lys(&[
        "log",
        "append",
        "--dir",
        path_str(&dir),
        "--leaf",
        path_str(&leaf),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(stderr.contains("log directory not initialized"), "{stderr}");
    assert!(stderr.contains("lys log init"), "{stderr}");
}

#[test]
fn empty_leaf_appends_proves_and_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("log");
    let key = tmp.path().join("operator.key");
    std::fs::write(&key, GOLDEN_SEED).unwrap();
    assert_success(&run_lys(&[
        "log",
        "init",
        "--dir",
        path_str(&dir),
        "--origin",
        "example.com/lys/empty-leaf",
    ]));
    let leaf = tmp.path().join("empty.bin");
    std::fs::write(&leaf, b"").unwrap();
    let append = run_lys(&[
        "log",
        "append",
        "--dir",
        path_str(&dir),
        "--leaf",
        path_str(&leaf),
    ]);
    assert_success(&append);
    assert_eq!(
        field(&stdout_of(&append), "leaf hash (sha256, rfc6962):"),
        hex_lower(&raw_leaf_hash(b"")),
        "empty leaf hash must be SHA-256 of the single 0x00 prefix byte"
    );
    let artifact = tmp.path().join("inclusion.json");
    let prove = run_lys(&[
        "log",
        "prove",
        "inclusion",
        "--dir",
        path_str(&dir),
        "--key",
        path_str(&key),
        "--leaf-index",
        "0",
        "--out",
        path_str(&artifact),
    ]);
    assert_success(&prove);
    // A size-1 tree has an EMPTY inclusion path — legal and verifiable.
    let value = load_json(&artifact);
    assert_eq!(value["hashes"].as_array().unwrap().len(), 0);
    let checkpoint = tmp.path().join("cp.note");
    let checkpoint_out = run_lys(&[
        "log",
        "checkpoint",
        "--dir",
        path_str(&dir),
        "--key",
        path_str(&key),
        "--out",
        path_str(&checkpoint),
    ]);
    assert_success(&checkpoint_out);
    let verifier = field(&stdout_of(&checkpoint_out), "verifier key (signed-note):");
    let verify = run_lys(&[
        "log",
        "verify",
        "inclusion",
        "--artifact",
        path_str(&artifact),
        "--leaf",
        path_str(&leaf),
        "--verifier-key",
        &verifier,
    ]);
    assert_success(&verify);
}

// ------------------------------------------------- crash recovery / corruption

#[test]
fn interrupted_append_is_recovered_with_a_notice() {
    let log = build_proven_log("example.com/lys/recovery", None);
    // Roll state.json back one append: exactly the crash window between the
    // leaf write and the state write.
    let state_path = log.dir.join("state.json");
    let stale = serde_json::json!({
        "tree_size": 2,
        "root_hash": STANDARD.encode(prefix_root_of(&log, 2)),
    });
    std::fs::write(&state_path, serde_json::to_string_pretty(&stale).unwrap()).unwrap();

    let leaf = log.dir.join("../next-leaf.bin");
    std::fs::write(&leaf, b"leaf-3").unwrap();
    let append = run_lys(&[
        "log",
        "append",
        "--dir",
        path_str(&log.dir),
        "--leaf",
        path_str(&leaf),
    ]);
    assert_success(&append);
    let stderr = stderr_of(&append);
    assert!(
        stderr.contains("recovered interrupted append: state advanced to 3"),
        "{stderr}"
    );
    assert_eq!(field(&stdout_of(&append), "tree size:"), "4");
}

/// Recomputes the root over the first `n` golden-style leaves of a log by
/// reading its leaf files directly (test-side cross-check only).
fn prefix_root_of(log: &ProvenLog, n: usize) -> [u8; 32] {
    let mut leaves = Vec::new();
    for i in 0..n {
        leaves.push(std::fs::read(log.dir.join("leaves").join(format!("{i:020}"))).unwrap());
    }
    let tree =
        lys_core::merkle::AppendOnlyTree::<lys_core::merkle::RawLeaf>::reconstruct_from_raw_leaves(
            &leaves,
        );
    let (root, _size) = tree.root().to_parts();
    root
}

#[test]
fn corrupted_log_directories_are_refused() {
    // Modified leaf byte.
    let log = build_proven_log("example.com/lys/corrupt-a", None);
    std::fs::write(log.dir.join("leaves").join(format!("{:020}", 0)), b"leaf-X").unwrap();
    let leaf = log.dir.join("../again.bin");
    std::fs::write(&leaf, b"more").unwrap();
    let output = run_lys(&[
        "log",
        "append",
        "--dir",
        path_str(&log.dir),
        "--leaf",
        path_str(&leaf),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr_of(&output).contains("log directory invalid"),
        "{}",
        stderr_of(&output)
    );

    // Gap: a missing middle leaf.
    let log = build_proven_log("example.com/lys/corrupt-b", None);
    std::fs::remove_file(log.dir.join("leaves").join(format!("{:020}", 1))).unwrap();
    let output = run_lys(&[
        "log",
        "append",
        "--dir",
        path_str(&log.dir),
        "--leaf",
        path_str(&leaf),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr_of(&output).contains("log directory invalid"),
        "{}",
        stderr_of(&output)
    );

    // Extra non-dot entry in leaves/.
    let log = build_proven_log("example.com/lys/corrupt-c", None);
    std::fs::write(log.dir.join("leaves").join("stray.txt"), b"junk").unwrap();
    let output = run_lys(&[
        "log",
        "append",
        "--dir",
        path_str(&log.dir),
        "--leaf",
        path_str(&leaf),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr_of(&output).contains("log directory invalid"),
        "{}",
        stderr_of(&output)
    );

    // Dotfiles (e.g. .DS_Store) are ignored, not corruption.
    let log = build_proven_log("example.com/lys/corrupt-d", None);
    std::fs::write(log.dir.join("leaves").join(".DS_Store"), b"junk").unwrap();
    let output = run_lys(&[
        "log",
        "append",
        "--dir",
        path_str(&log.dir),
        "--leaf",
        path_str(&leaf),
    ]);
    assert_success(&output);
}

// ------------------------------------------------------------- prove edge cases

#[test]
fn prove_inclusion_out_of_range_index_is_actionable() {
    let log = build_proven_log("example.com/lys/range", None);
    let out = log.dir.join("../oob.json");
    let output = run_lys(&[
        "log",
        "prove",
        "inclusion",
        "--dir",
        path_str(&log.dir),
        "--key",
        path_str(&log.key),
        "--leaf-index",
        "3",
        "--out",
        path_str(&out),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(stderr.contains("leaf index 3"), "{stderr}");
    assert!(stderr.contains("3 leaves"), "{stderr}");
}

#[test]
fn prove_consistency_enforces_strict_size_rules() {
    let log = build_proven_log("example.com/lys/sizes", None);
    let out = log.dir.join("../c.json");
    // old_size == current size: vacuous, refused with an actionable message.
    let equal = run_lys(&[
        "log",
        "prove",
        "consistency",
        "--dir",
        path_str(&log.dir),
        "--key",
        path_str(&log.key),
        "--old-size",
        "3",
        "--out",
        path_str(&out),
    ]);
    assert_eq!(equal.status.code(), Some(1));
    assert!(
        stderr_of(&equal).contains("strictly below"),
        "{}",
        stderr_of(&equal)
    );
    // old_size == 0: rejected by clap's range parser (exit 2).
    let zero = run_lys(&[
        "log",
        "prove",
        "consistency",
        "--dir",
        path_str(&log.dir),
        "--key",
        path_str(&log.key),
        "--old-size",
        "0",
        "--out",
        path_str(&out),
    ]);
    assert_eq!(zero.status.code(), Some(2));
}

// -------------------------------------------------- tamper matrix — inclusion

/// Runs `lys log verify inclusion` against a mutated artifact and returns
/// `(exit code, stderr)`.
fn verify_inclusion_raw_output(
    artifact: &Path,
    leaf: &Path,
    verifier: &str,
) -> (Option<i32>, String) {
    let output = run_lys(&[
        "log",
        "verify",
        "inclusion",
        "--artifact",
        path_str(artifact),
        "--leaf",
        path_str(leaf),
        "--verifier-key",
        verifier,
    ]);
    (output.status.code(), stderr_of(&output))
}

#[test]
fn verify_inclusion_rejects_every_tamper_class_with_one_identical_message() {
    let log = build_proven_log("example.com/lys/tamper-i", None);
    let tmp = tempfile::tempdir().unwrap();
    let original = load_json(&log.inclusion_artifact);
    let consistency = load_json(&log.consistency_artifact);
    let leaf1 = &log.leaf_files[1];

    let mut tampers: Vec<(&str, serde_json::Value)> = Vec::new();

    let mut v = original.clone();
    v["tree_size"] = serde_json::json!(4);
    tampers.push(("tree_size off by one", v));

    let mut v = original.clone();
    v["leaf_index"] = serde_json::json!(2);
    tampers.push(("leaf_index off by one", v));

    let mut v = original.clone();
    v["leaf_index"] = serde_json::json!(3);
    tampers.push(("leaf_index == tree_size", v));

    let mut v = original.clone();
    let entry = v["hashes"][0].as_str().unwrap().to_string();
    let flipped = if entry.starts_with('M') {
        entry.replacen('M', "N", 1)
    } else {
        format!("M{}", &entry[1..])
    };
    v["hashes"][0] = serde_json::json!(flipped);
    tampers.push(("hash entry bit-flipped", v));

    let mut v = original.clone();
    v["hashes"][0] = serde_json::json!(STANDARD.encode([0u8; 31]));
    tampers.push(("hash entry decodes to 31 bytes", v));

    let mut v = original.clone();
    v["hashes"][0] = serde_json::json!("AAA");
    tampers.push(("hash entry unpadded base64", v));

    let mut v = original.clone();
    let extra = v["hashes"][0].clone();
    v["hashes"].as_array_mut().unwrap().push(extra);
    tampers.push(("extra hash appended", v));

    let mut v = original.clone();
    v["hashes"].as_array_mut().unwrap().remove(0);
    tampers.push(("hash removed", v));

    let mut v = original.clone();
    v["checkpoint"] = consistency["checkpoint_1"].clone();
    tampers.push(("checkpoint swapped for same-log size-2 checkpoint", v));

    let mut v = original;
    v["format"] = serde_json::json!("lys/log-consistency-proof/v1");
    tampers.push(("format swapped to the other kind", v));

    let mut stderrs = Vec::new();
    for (index, (label, value)) in tampers.iter().enumerate() {
        let path = write_json(tmp.path(), &format!("tamper-{index}.json"), value);
        let (code, stderr) = verify_inclusion_raw_output(&path, leaf1, &log.verifier);
        assert_eq!(code, Some(1), "tamper {label:?} did not fail");
        assert_eq!(
            stderr, INCLUSION_FAIL_STDERR,
            "tamper {label:?} leaked detail"
        );
        stderrs.push(stderr);
    }
    // Wrong leaf bytes: same class, same message.
    let (code, stderr) =
        verify_inclusion_raw_output(&log.inclusion_artifact, &log.leaf_files[0], &log.verifier);
    assert_eq!(code, Some(1));
    assert_eq!(stderr, INCLUSION_FAIL_STDERR);
    stderrs.push(stderr);
    // Wrong (but well-formed) verifier key: same class, same message.
    let other = build_proven_log("example.com/lys/tamper-i", None);
    let (code, stderr) =
        verify_inclusion_raw_output(&log.inclusion_artifact, leaf1, &other.verifier);
    assert_eq!(code, Some(1));
    assert_eq!(stderr, INCLUSION_FAIL_STDERR);
    stderrs.push(stderr);
    // The strongest non-oracle assertion: all failures are byte-identical.
    assert!(
        stderrs.windows(2).all(|w| w[0] == w[1]),
        "tamper classes must be indistinguishable"
    );
}

#[test]
fn verify_inclusion_shape_errors_are_actionable_json_parse_failures() {
    let log = build_proven_log("example.com/lys/shape-i", None);
    let tmp = tempfile::tempdir().unwrap();
    let leaf1 = &log.leaf_files[1];

    // Unknown extra field: not valid v1 (deny_unknown_fields).
    let mut v = load_json(&log.inclusion_artifact);
    v["timestamp"] = serde_json::json!(123);
    let path = write_json(tmp.path(), "unknown-field.json", &v);
    let (code, stderr) = verify_inclusion_raw_output(&path, leaf1, &log.verifier);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("failed to parse inclusion proof artifact JSON"),
        "{stderr}"
    );

    // Duplicate JSON key: rejected by serde.
    let text = std::fs::read_to_string(&log.inclusion_artifact).unwrap();
    let duplicated = text.replacen(
        "\"tree_size\": 3,",
        "\"tree_size\": 3,\n  \"tree_size\": 9,",
        1,
    );
    assert_ne!(text, duplicated, "fixture must contain the expected field");
    let dup_path = tmp.path().join("duplicate-key.json");
    std::fs::write(&dup_path, duplicated).unwrap();
    let (code, stderr) = verify_inclusion_raw_output(&dup_path, leaf1, &log.verifier);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("failed to parse inclusion proof artifact JSON"),
        "{stderr}"
    );

    // Kind confusion at the shape level: a consistency artifact is not
    // shaped like an inclusion artifact.
    let (code, stderr) =
        verify_inclusion_raw_output(&log.consistency_artifact, leaf1, &log.verifier);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("failed to parse inclusion proof artifact JSON"),
        "{stderr}"
    );

    // Malformed verifier key string: trusted operator input, actionable.
    let (code, stderr) = verify_inclusion_raw_output(&log.inclusion_artifact, leaf1, "not-a-key");
    assert_eq!(code, Some(1));
    assert!(stderr.contains("invalid note verifier key"), "{stderr}");
}

// ------------------------------------------------ tamper matrix — consistency

/// Runs `lys log verify consistency` and returns `(exit code, stderr)`.
fn verify_consistency_raw_output(artifact: &Path, verifier: &str) -> (Option<i32>, String) {
    let output = run_lys(&[
        "log",
        "verify",
        "consistency",
        "--artifact",
        path_str(artifact),
        "--verifier-key",
        verifier,
    ]);
    (output.status.code(), stderr_of(&output))
}

#[test]
fn verify_consistency_rejects_every_tamper_class_with_one_identical_message() {
    let log = build_proven_log("example.com/lys/tamper-c", None);
    // A second log, same operator key file copied, DIFFERENT origin: its
    // checkpoints are signed by the same key but must never verify here.
    let other_origin = {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("log");
        assert_success(&run_lys(&[
            "log",
            "init",
            "--dir",
            path_str(&dir),
            "--origin",
            "example.com/lys/other-origin",
        ]));
        for leaf in &log.leaf_files {
            assert_success(&run_lys(&[
                "log",
                "append",
                "--dir",
                path_str(&dir),
                "--leaf",
                path_str(leaf),
            ]));
        }
        let note = tmp.path().join("cp.note");
        assert_success(&run_lys(&[
            "log",
            "checkpoint",
            "--dir",
            path_str(&dir),
            "--key",
            path_str(&log.key),
            "--out",
            path_str(&note),
        ]));
        std::fs::read_to_string(&note).unwrap()
    };

    let tmp = tempfile::tempdir().unwrap();
    let original = load_json(&log.consistency_artifact);

    let mut tampers: Vec<(&str, serde_json::Value)> = Vec::new();

    let mut v = original.clone();
    v["tree_size_1"] = serde_json::json!(1);
    tampers.push(("tree_size_1 off by one", v));

    let mut v = original.clone();
    v["tree_size_2"] = serde_json::json!(4);
    tampers.push(("tree_size_2 off by one", v));

    let mut v = original.clone();
    v["tree_size_1"] = serde_json::json!(3);
    tampers.push(("tree_size_1 == tree_size_2", v));

    let mut v = original.clone();
    v["tree_size_1"] = serde_json::json!(0);
    tampers.push(("tree_size_1 == 0", v));

    let mut v = original.clone();
    let cp1 = v["checkpoint_1"].clone();
    v["checkpoint_1"] = v["checkpoint_2"].clone();
    v["checkpoint_2"] = cp1;
    tampers.push(("checkpoints exchanged", v));

    let mut v = original.clone();
    let entry = v["hashes"][0].as_str().unwrap().to_string();
    let flipped = if entry.starts_with('/') {
        entry.replacen('/', "A", 1)
    } else {
        format!("/{}", &entry[1..])
    };
    v["hashes"][0] = serde_json::json!(flipped);
    tampers.push(("hash entry bit-flipped", v));

    let mut v = original.clone();
    v["checkpoint_2"] = serde_json::json!(other_origin);
    tampers.push(("checkpoint_2 from a different origin, same key", v));

    let mut v = original;
    v["format"] = serde_json::json!("lys/log-inclusion-proof/v1");
    tampers.push(("format swapped to the other kind", v));

    let mut stderrs = Vec::new();
    for (index, (label, value)) in tampers.iter().enumerate() {
        let path = write_json(tmp.path(), &format!("tamper-{index}.json"), value);
        let (code, stderr) = verify_consistency_raw_output(&path, &log.verifier);
        assert_eq!(code, Some(1), "tamper {label:?} did not fail");
        assert_eq!(
            stderr, CONSISTENCY_FAIL_STDERR,
            "tamper {label:?} leaked detail"
        );
        stderrs.push(stderr);
    }
    assert!(
        stderrs.windows(2).all(|w| w[0] == w[1]),
        "tamper classes must be indistinguishable"
    );

    // Kind confusion at the shape level for the consistency verifier.
    let (code, stderr) = verify_consistency_raw_output(&log.inclusion_artifact, &log.verifier);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("failed to parse consistency proof artifact JSON"),
        "{stderr}"
    );
}
