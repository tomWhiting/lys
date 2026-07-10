//! `lys log init` — create a log directory and pin its origin.
//!
//! The origin is the log's identity and the signed-note key name its
//! checkpoints are signed under; it is set exactly once, here. Re-running
//! init on an existing log directory is refused — a per-invocation origin
//! is exactly the two-logs-one-origin confusion the origin binding exists
//! to kill.

use std::path::Path;

use lys_core::merkle::{AppendOnlyTree, RawLeaf};

use crate::commands::error::CliResult;
use crate::commands::hex::hex_lower;
use crate::commands::log::store::LogStore;

/// `lys log init --dir <log-dir> --origin <origin>`.
///
/// # Errors
///
/// Returns [`CliError::Trust`] if the origin is invalid (actionable —
/// trusted operator input), [`CliError::LogDirInvalid`] if the directory is
/// already initialized, and [`CliError::Io`] on filesystem failures.
///
/// [`CliError::Trust`]: crate::commands::error::CliError::Trust
/// [`CliError::LogDirInvalid`]: crate::commands::error::CliError::LogDirInvalid
/// [`CliError::Io`]: crate::commands::error::CliError::Io
pub fn run(dir: &Path, origin: &str) -> CliResult<()> {
    LogStore::init(dir, origin)?;
    let (empty_root, tree_size) = AppendOnlyTree::<RawLeaf>::new().root().to_parts();
    println!("initialized log directory: {}", dir.display());
    println!("origin: {origin}");
    println!("tree size: {tree_size}");
    println!("root hash (sha256): {}", hex_lower(&empty_root));
    Ok(())
}
