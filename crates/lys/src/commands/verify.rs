//! `lys verify` — verify a JSON attestation envelope against a payload.
//!
//! Parses the envelope written by `lys attest`, re-reads the candidate
//! payload, and delegates to [`lys_core::attestation::verify_attestation`].
//! Success prints the verified envelope details and exits 0; any
//! verification failure — tampered payload, tampered timestamp, forged
//! signature, wrong signer key — exits 1 with a single indistinguishable
//! message, matching the library's deliberate non-oracle behaviour.

use std::path::Path;

use lys_core::TrustError;
use lys_core::attestation::{Attestation, verify_attestation};

use crate::commands::error::{CliError, CliResult};
use crate::commands::files::read_file;
use crate::commands::hex::hex_lower;

/// `lys verify --attestation <file> --payload <file>`.
///
/// # Errors
///
/// Returns [`CliError::Io`] if either file cannot be read,
/// [`CliError::JsonParse`] if the attestation file is not a valid envelope,
/// [`CliError::VerificationFailed`] if the attestation does not verify
/// against the payload, and [`CliError::Trust`] for any other library
/// failure.
pub fn run(attestation_path: &Path, payload_path: &Path) -> CliResult<()> {
    let envelope_bytes = read_file(attestation_path, "attestation file")?;
    let attestation: Attestation =
        serde_json::from_slice(&envelope_bytes).map_err(|source| CliError::JsonParse {
            what: "attestation",
            path: attestation_path.to_path_buf(),
            source,
        })?;
    let payload = read_file(payload_path, "payload file")?;
    match verify_attestation(&attestation, &payload) {
        Ok(()) => {
            println!("attestation verified");
            println!(
                "signer public key (ed25519): {}",
                hex_lower(&attestation.signer_public_key)
            );
            println!(
                "payload hash (sha256): {}",
                hex_lower(&attestation.payload_hash)
            );
            println!("signed at (unix ms): {}", attestation.timestamp);
            Ok(())
        }
        Err(TrustError::InvalidSignature) => Err(CliError::VerificationFailed),
        Err(other) => Err(CliError::Trust(other)),
    }
}
