//! `lys log checkpoint` — sign a C2SP signed-note checkpoint over the
//! log's current root.
//!
//! Checkpointing is a distinct signing act, separate from appending: the
//! identity key is loaded via the load-only path (never minted here), the
//! note is signed under the origin as the key name (the origin binding
//! third-party verifiers enforce), and the verifier key string is printed
//! so the operator can hand the trust anchor to a third party in the same
//! breath.

use std::path::Path;

use lys_core::checkpoint::{CheckpointBody, NoteVerifierKey, sign_note};

use crate::commands::error::CliResult;
use crate::commands::files::write_file;
use crate::commands::hex::hex_lower;
use crate::commands::key::load_identity;
use crate::commands::log::store::LogStore;

/// `lys log checkpoint --dir <log-dir> --key <keyfile> --out <file>`.
///
/// # Errors
///
/// Returns [`CliError::LogDirMissing`] / [`CliError::LogDirInvalid`] if the
/// log directory is absent or fails its integrity check,
/// [`CliError::KeyFileMissing`] if the key file does not exist,
/// [`CliError::Trust`] if signing fails, and [`CliError::Io`] if the note
/// cannot be written.
///
/// [`CliError::LogDirMissing`]: crate::commands::error::CliError::LogDirMissing
/// [`CliError::LogDirInvalid`]: crate::commands::error::CliError::LogDirInvalid
/// [`CliError::KeyFileMissing`]: crate::commands::error::CliError::KeyFileMissing
/// [`CliError::Trust`]: crate::commands::error::CliError::Trust
/// [`CliError::Io`]: crate::commands::error::CliError::Io
pub fn run(dir: &Path, key: &Path, out: &Path) -> CliResult<()> {
    let store = LogStore::open(dir)?;
    let identity = load_identity(key)?;
    let body = CheckpointBody::from_root(store.origin(), &store.tree().root())?;
    let note = sign_note(&body.encode(), store.origin(), &identity)?;
    write_file(out, note.as_bytes(), "checkpoint note file")?;
    let verifier = NoteVerifierKey::new(store.origin(), identity.public_key_bytes())?;
    println!("origin: {}", body.origin());
    println!("tree size: {}", body.tree_size());
    println!("root hash (sha256): {}", hex_lower(&body.root_hash()));
    println!("checkpoint written: {}", out.display());
    println!("verifier key (signed-note): {}", verifier.to_spec());
    Ok(())
}
