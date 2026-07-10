//! `lys attest` — sign an attestation over a payload file.
//!
//! Reads the payload, signs it with the identity at `--key` via
//! [`lys_core::attestation::sign_attestation`], and writes the resulting
//! envelope to `--out` as pretty-printed JSON (the exact serde shape of
//! [`lys_core::attestation::Attestation`], which `lys verify` reads back).

use std::path::Path;

use lys_core::attestation::sign_attestation;

use crate::commands::error::{CliError, CliResult};
use crate::commands::files::{read_file, write_file};
use crate::commands::hex::hex_lower;
use crate::commands::key::load_identity;

/// `lys attest --key <path> --payload <file> --out <file>`.
///
/// # Errors
///
/// Returns [`CliError::KeyFileMissing`] if the key file does not exist,
/// [`CliError::Trust`] if it is invalid, [`CliError::Io`] if the payload
/// cannot be read or the envelope cannot be written, and
/// [`CliError::JsonSerialize`] if the envelope cannot be encoded.
pub fn run(key: &Path, payload: &Path, out: &Path) -> CliResult<()> {
    let identity = load_identity(key)?;
    let payload_bytes = read_file(payload, "payload file")?;
    let attestation = sign_attestation(&payload_bytes, &identity);
    let mut json =
        serde_json::to_string_pretty(&attestation).map_err(|source| CliError::JsonSerialize {
            what: "attestation",
            source,
        })?;
    json.push('\n');
    write_file(out, json.as_bytes(), "attestation file")?;
    println!("attested payload: {}", payload.display());
    println!(
        "payload hash (sha256): {}",
        hex_lower(&attestation.payload_hash)
    );
    println!(
        "signer public key (ed25519): {}",
        hex_lower(&attestation.signer_public_key)
    );
    println!("signed at (unix ms): {}", attestation.timestamp);
    println!("attestation written: {}", out.display());
    Ok(())
}
