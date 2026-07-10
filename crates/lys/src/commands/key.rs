//! `lys key` subcommands: generate and inspect identity key files.
//!
//! Output discipline: only public material is ever printed — the Ed25519
//! verifying key and the derived X25519 public key, both as lowercase hex.
//! The 32-byte seed never leaves the key file.

use std::path::Path;

use lys_core::Ed25519Identity;
use lys_core::checkpoint::NoteVerifierKey;

use crate::commands::error::{CliError, CliResult};
use crate::commands::hex::hex_lower;

/// `lys key generate --out <path>`.
///
/// Generates a new Ed25519 identity key at `out` via
/// [`Ed25519Identity::load_or_generate`], which is safe under concurrent
/// callers and loads (rather than clobbers) an existing key file. Reports
/// which of the two happened, then prints the public key.
///
/// # Errors
///
/// Returns [`CliError::Trust`] if the key file cannot be created or an
/// existing file at `out` is not a valid 32-byte seed.
pub fn generate(out: &Path) -> CliResult<()> {
    // Existence is checked before the call purely to report accurately
    // whether a key was generated or loaded; `load_or_generate` itself is
    // race-safe regardless.
    let existed = out.exists();
    let identity = Ed25519Identity::load_or_generate(out).map_err(CliError::from)?;
    if existed {
        println!("loaded existing identity key: {}", out.display());
    } else {
        println!("generated new identity key: {}", out.display());
    }
    println!(
        "public key (ed25519): {}",
        hex_lower(&identity.public_key_bytes())
    );
    Ok(())
}

/// `lys key inspect --key <path> [--note-name <name>]`.
///
/// Loads an existing identity key file and prints the Ed25519 public key
/// and the derived X25519 public key (used for sealed payload key
/// agreement), both as lowercase hex. When `note_name` is given, also
/// prints the signed-note verifier key line for that name — the name must
/// equal the log origin this key signs checkpoints for, because `lys`
/// verifiers enforce `checkpoint origin == verifier-key name`. Without a
/// name there is nothing truthful to print, so the line is omitted.
///
/// # Errors
///
/// Returns [`CliError::KeyFileMissing`] if the file does not exist,
/// [`CliError::Trust`] if it cannot be read or is not a valid 32-byte seed,
/// or if `note_name` violates the signed-note key-name rules (non-empty,
/// no whitespace, no `'+'`).
pub fn inspect(key: &Path, note_name: Option<&str>) -> CliResult<()> {
    let identity = load_identity(key)?;
    println!("identity key: {}", key.display());
    println!(
        "public key (ed25519): {}",
        hex_lower(&identity.public_key_bytes())
    );
    println!(
        "public key (x25519): {}",
        hex_lower(&identity.x25519_public_key())
    );
    if let Some(name) = note_name {
        let verifier =
            NoteVerifierKey::new(name, identity.public_key_bytes()).map_err(CliError::from)?;
        println!("verifier key (signed-note): {}", verifier.to_spec());
    }
    Ok(())
}

/// Load an identity from an existing key file, refusing to generate one.
///
/// Consuming subcommands (`key inspect`, `attest`, `ca issue`, `seal`,
/// `open`) go through [`Ed25519Identity::load`], which can never mint key
/// material — signing with a key the operator never created is the failure
/// this guard exists to prevent, and the load-only constructor closes it
/// with no check-then-act window. The existence pre-check remains solely to
/// produce the friendlier [`CliError::KeyFileMissing`] message with its
/// `lys key generate` remedy.
///
/// # Errors
///
/// Returns [`CliError::KeyFileMissing`] if `key` does not exist, or
/// [`CliError::Trust`] if the file cannot be read or is invalid.
pub fn load_identity(key: &Path) -> CliResult<Ed25519Identity> {
    if !key.exists() {
        return Err(CliError::KeyFileMissing {
            path: key.to_path_buf(),
        });
    }
    Ed25519Identity::load(key).map_err(CliError::from)
}
