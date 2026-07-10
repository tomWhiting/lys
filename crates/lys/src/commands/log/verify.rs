//! `lys log verify` — third-party verification of proof artifacts.
//!
//! Structurally honest by construction: these subcommands take no log
//! directory at all — verification runs from the artifact file, the
//! verifier key string, and (for inclusion) the leaf file alone.
//!
//! Failure discipline: JSON shape errors and a malformed verifier key
//! string are pre-crypto and actionable; every cryptographic or structural
//! verification failure collapses to one generic message per artifact
//! class ([`CliError::LogInclusionVerificationFailed`] /
//! [`CliError::LogConsistencyVerificationFailed`]) so different tamper
//! classes are indistinguishable from the output. Artifact files are
//! capped at 16 MiB before reading (defensive; real artifacts are a few
//! kilobytes).

use std::path::Path;

use lys_core::checkpoint::NoteVerifierKey;
use lys_core::tlog::{
    ConsistencyProofArtifact, InclusionProofArtifact, verify_consistency_artifact,
    verify_inclusion_artifact,
};

use crate::commands::error::{CliError, CliResult};
use crate::commands::files::read_file;
use crate::commands::hex::hex_lower;

/// Defensive cap on artifact file size (16 MiB). Real artifacts are a few
/// kilobytes; the cap bounds hostile-input memory without ever touching a
/// legitimate artifact.
const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;

/// `lys log verify inclusion --artifact <file> --leaf <file>
/// --verifier-key <string>`.
///
/// # Errors
///
/// Returns [`CliError::Io`] if a file cannot be read or exceeds the 16 MiB
/// cap, [`CliError::JsonParse`] if the artifact is not shaped like an
/// inclusion-proof artifact (pre-crypto, actionable), [`CliError::Trust`]
/// if the verifier key string is malformed (trusted operator input), and
/// [`CliError::LogInclusionVerificationFailed`] — one generic message —
/// for every verification failure.
pub fn inclusion(artifact_path: &Path, leaf: &Path, verifier_key: &str) -> CliResult<()> {
    let artifact_bytes = read_artifact_file(artifact_path)?;
    let artifact: InclusionProofArtifact =
        serde_json::from_slice(&artifact_bytes).map_err(|source| CliError::JsonParse {
            what: "inclusion proof artifact",
            path: artifact_path.to_path_buf(),
            source,
        })?;
    let leaf_bytes = read_file(leaf, "leaf file")?;
    let verifier = NoteVerifierKey::from_spec(verifier_key)?;
    let body = verify_inclusion_artifact(&artifact, &leaf_bytes, &verifier)
        .map_err(|_err| CliError::LogInclusionVerificationFailed)?;
    println!("inclusion verified");
    println!("origin: {}", body.origin());
    println!("tree size: {}", body.tree_size());
    println!("leaf index: {}", artifact.leaf_index);
    println!("root hash (sha256): {}", hex_lower(&body.root_hash()));
    Ok(())
}

/// `lys log verify consistency --artifact <file> --verifier-key <string>`.
///
/// # Errors
///
/// Returns [`CliError::Io`] if the artifact cannot be read or exceeds the
/// 16 MiB cap, [`CliError::JsonParse`] if it is not shaped like a
/// consistency-proof artifact (pre-crypto, actionable), [`CliError::Trust`]
/// if the verifier key string is malformed (trusted operator input), and
/// [`CliError::LogConsistencyVerificationFailed`] — one generic message —
/// for every verification failure.
pub fn consistency(artifact_path: &Path, verifier_key: &str) -> CliResult<()> {
    let artifact_bytes = read_artifact_file(artifact_path)?;
    let artifact: ConsistencyProofArtifact =
        serde_json::from_slice(&artifact_bytes).map_err(|source| CliError::JsonParse {
            what: "consistency proof artifact",
            path: artifact_path.to_path_buf(),
            source,
        })?;
    let verifier = NoteVerifierKey::from_spec(verifier_key)?;
    let (body_1, body_2) = verify_consistency_artifact(&artifact, &verifier)
        .map_err(|_err| CliError::LogConsistencyVerificationFailed)?;
    println!("consistency verified");
    println!("origin: {}", body_2.origin());
    println!("old tree size: {}", body_1.tree_size());
    println!("new tree size: {}", body_2.tree_size());
    println!("old root hash (sha256): {}", hex_lower(&body_1.root_hash()));
    println!("new root hash (sha256): {}", hex_lower(&body_2.root_hash()));
    Ok(())
}

/// Reads an artifact file after checking it against the 16 MiB cap.
fn read_artifact_file(path: &Path) -> CliResult<Vec<u8>> {
    let metadata = std::fs::metadata(path).map_err(|source| CliError::Io {
        context: format!("failed to read artifact file {}", path.display()),
        source,
    })?;
    if metadata.len() > MAX_ARTIFACT_BYTES {
        return Err(CliError::Io {
            context: format!("refusing to read artifact file {}", path.display()),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "file is {} bytes, above the {MAX_ARTIFACT_BYTES}-byte artifact cap",
                    metadata.len()
                ),
            ),
        });
    }
    read_file(path, "artifact file")
}
