//! `lys log append` — append a leaf file's raw bytes to the log.
//!
//! The transparency invariant: the appended bytes are hashed verbatim, so
//! `leaf_hash = SHA-256(0x00 ‖ file-bytes)` per RFC 6962, reproducible by
//! any third party with `(printf '\x00'; cat leaf-file) | shasum -a 256`.
//! Appending never requires the signing key, and the origin is store state
//! — never a per-invocation flag.

use std::path::Path;

use crate::commands::error::CliResult;
use crate::commands::files::read_file;
use crate::commands::hex::hex_lower;
use crate::commands::log::store::LogStore;

/// `lys log append --dir <log-dir> --leaf <file>`.
///
/// # Errors
///
/// Returns [`CliError::LogDirMissing`] if the directory is not an
/// initialized log (with the `lys log init` remedy),
/// [`CliError::LogDirInvalid`] if the directory fails its integrity check,
/// and [`CliError::Io`] if the leaf file cannot be read or written.
///
/// [`CliError::LogDirMissing`]: crate::commands::error::CliError::LogDirMissing
/// [`CliError::LogDirInvalid`]: crate::commands::error::CliError::LogDirInvalid
/// [`CliError::Io`]: crate::commands::error::CliError::Io
pub fn run(dir: &Path, leaf: &Path) -> CliResult<()> {
    let mut store = LogStore::open(dir)?;
    let leaf_bytes = read_file(leaf, "leaf file")?;
    let (index, leaf_hash) = store.append(&leaf_bytes)?;
    let (root, tree_size) = store.tree().root().to_parts();
    println!("leaf index: {index}");
    println!("leaf hash (sha256, rfc6962): {}", hex_lower(&leaf_hash));
    println!("tree size: {tree_size}");
    println!("root hash (sha256): {}", hex_lower(&root));
    Ok(())
}
