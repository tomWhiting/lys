//! `lys log prove` — build self-contained, signed JSON proof artifacts.
//!
//! Both subcommands sign their embedded checkpoints inline with the
//! operator's key (the log operator holds the key in every real
//! deployment); the library self-verifies every artifact before it is
//! returned, so a broken artifact is never written. The JSON bytes are
//! pretty-printed with a trailing newline — cosmetic only, since the
//! artifact carries no signature over its own JSON bytes; all integrity
//! flows through the embedded notes and root recomputation.

use std::path::Path;

use lys_core::TrustError;
use lys_core::tlog::{build_consistency_artifact, build_inclusion_artifact};
use serde::Serialize;

use crate::commands::error::{CliError, CliResult};
use crate::commands::files::write_file;
use crate::commands::hex::hex_lower;
use crate::commands::key::load_identity;
use crate::commands::log::store::LogStore;

/// `lys log prove inclusion --dir <log-dir> --key <keyfile>
/// --leaf-index <n> --out <file>`.
///
/// # Errors
///
/// Returns [`CliError::LogDirMissing`] / [`CliError::LogDirInvalid`] for
/// log-directory problems, [`CliError::KeyFileMissing`] if the key file
/// does not exist, [`CliError::Trust`] with the actionable
/// `TrustError::MerkleTree` message for an out-of-range index (operator
/// input, not an oracle concern), and [`CliError::Io`] /
/// [`CliError::JsonSerialize`] on output failures.
///
/// [`CliError::LogDirMissing`]: crate::commands::error::CliError::LogDirMissing
/// [`CliError::LogDirInvalid`]: crate::commands::error::CliError::LogDirInvalid
/// [`CliError::KeyFileMissing`]: crate::commands::error::CliError::KeyFileMissing
/// [`CliError::Trust`]: crate::commands::error::CliError::Trust
/// [`CliError::Io`]: crate::commands::error::CliError::Io
/// [`CliError::JsonSerialize`]: crate::commands::error::CliError::JsonSerialize
pub fn inclusion(dir: &Path, key: &Path, leaf_index: u64, out: &Path) -> CliResult<()> {
    let store = LogStore::open(dir)?;
    let identity = load_identity(key)?;
    let leaf_bytes = store.leaf_bytes(leaf_index).ok_or_else(|| {
        CliError::Trust(TrustError::MerkleTree {
            reason: format!(
                "inclusion proof requested for leaf index {leaf_index} but tree has {} leaves",
                store.tree().len()
            ),
        })
    })?;
    let artifact = build_inclusion_artifact(
        store.tree(),
        leaf_bytes,
        store.origin(),
        &identity,
        leaf_index,
    )?;
    write_artifact(out, &artifact, "inclusion proof artifact")?;
    let (root, tree_size) = store.tree().root().to_parts();
    println!("leaf index: {leaf_index}");
    println!("tree size: {tree_size}");
    println!("root hash (sha256): {}", hex_lower(&root));
    println!("artifact written: {}", out.display());
    Ok(())
}

/// `lys log prove consistency --dir <log-dir> --key <keyfile>
/// --old-size <n> --out <file>`.
///
/// Requires `1 <= old_size < current tree size` strictly (clap enforces the
/// lower bound; the library enforces the strict upper bound with an
/// actionable message).
///
/// # Errors
///
/// As [`inclusion`], with `TrustError::LogArtifactEncoding` for size-rule
/// violations.
pub fn consistency(dir: &Path, key: &Path, old_size: u64, out: &Path) -> CliResult<()> {
    let store = LogStore::open(dir)?;
    let identity = load_identity(key)?;
    let new_size = store.tree().len();
    if old_size >= new_size {
        return Err(CliError::Trust(TrustError::LogArtifactEncoding {
            reason: format!(
                "consistency artifact requires old size strictly below the current tree size: \
                 old={old_size}, current={new_size}"
            ),
        }));
    }
    let old_tree = store.prefix_tree(old_size)?;
    let artifact = build_consistency_artifact(&old_tree, store.tree(), store.origin(), &identity)?;
    write_artifact(out, &artifact, "consistency proof artifact")?;
    let (old_root, _old) = old_tree.root().to_parts();
    let (new_root, _new) = store.tree().root().to_parts();
    println!("old tree size: {old_size}");
    println!("new tree size: {new_size}");
    println!("old root hash (sha256): {}", hex_lower(&old_root));
    println!("new root hash (sha256): {}", hex_lower(&new_root));
    println!("artifact written: {}", out.display());
    Ok(())
}

/// Writes an artifact as pretty JSON with a trailing newline (the emit-side
/// convention shared with `lys attest`).
fn write_artifact<T: Serialize>(out: &Path, artifact: &T, what: &'static str) -> CliResult<()> {
    let mut json = serde_json::to_string_pretty(artifact)
        .map_err(|source| CliError::JsonSerialize { what, source })?;
    json.push('\n');
    write_file(out, json.as_bytes(), what)
}
