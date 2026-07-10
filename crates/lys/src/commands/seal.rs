//! `lys seal` and `lys open` — authenticated sealed payload transport.
//!
//! Sealing wraps [`lys_core::seal::sign_and_seal`]: the payload is encrypted
//! to the recipient's X25519 public key (X25519 ephemeral key agreement,
//! HKDF-SHA256, AES-256-GCM) and the resulting envelope is signed with the
//! sender's Ed25519 identity, binding the ciphertext to the sender. Opening
//! wraps [`lys_core::seal::open_and_verify`]: the sender attestation is
//! verified against the expected sender public key *before* any decryption
//! is attempted.
//!
//! The CLI deliberately surfaces only the authenticated composition, not the
//! bare [`lys_core::seal::seal`] / [`lys_core::seal::open`] primitives. A
//! bare open would let anyone with an envelope use the recipient's CLI as an
//! unsealing oracle for envelopes of unverifiable origin, and a bare seal
//! produces a ciphertext no third party can attribute — the opposite of what
//! this tool exists for. The bare primitives remain available to library
//! consumers with broadcast or anonymous use cases.
//!
//! On-disk formats are the exact `serde_json` wire shapes of the `lys-core`
//! types: `--out` receives the [`SealedEnvelope`] and `--attestation-out`
//! receives the [`Attestation`], as two separate files mirroring the
//! library's two-value return. Keeping them separate means each file is a
//! pure `lys-core` wire type with no CLI-invented framing.
//!
//! Invariants: both key-consuming commands refuse a missing key file — only
//! `lys key generate` creates key material. Plaintext is never written to
//! stdout; `lys open` writes it to `--out` only, created owner-readable
//! (mode `0600` on Unix), and prints only public metadata. A failed `seal`
//! leaves no partial outputs: if the attestation cannot be written, the
//! already-written envelope is removed. Open failures are non-oracle: wrong
//! recipient key, forged or mismatched sender attestation, and tampered
//! envelope fields all collapse to the one generic [`CliError::OpenFailed`]
//! message.

use std::path::Path;

use lys_core::attestation::Attestation;
use lys_core::seal::{SealedEnvelope, open_and_verify, sign_and_seal};

use crate::commands::error::{CliError, CliResult};
use crate::commands::files::{read_file, write_file, write_file_private};
use crate::commands::hex::{hex_lower, parse_hex_32};
use crate::commands::key::load_identity;

/// `lys seal --key <path> --recipient-public-key <hex> --payload <file>
/// --out <file> --attestation-out <file>`.
///
/// # Errors
///
/// Returns [`CliError::KeyFileMissing`] if the sender key file does not
/// exist, [`CliError::InvalidRecipientPublicKey`] if the recipient key is
/// not 64 hex characters, [`CliError::Io`] if the payload cannot be read or
/// either output cannot be written, [`CliError::Trust`] if the library
/// rejects the seal (e.g. a low-order recipient key), and
/// [`CliError::JsonSerialize`] if either wire type cannot be encoded.
pub fn seal(
    key: &Path,
    recipient_public_key: &str,
    payload: &Path,
    out: &Path,
    attestation_out: &Path,
) -> CliResult<()> {
    let identity = load_identity(key)?;
    let recipient =
        parse_hex_32(recipient_public_key).ok_or(CliError::InvalidRecipientPublicKey)?;
    let payload_bytes = read_file(payload, "payload file")?;

    let (envelope, attestation) = sign_and_seal(&payload_bytes, &identity, &recipient)?;

    // Both files carry the exact serde_json wire shape of the lys-core type
    // — no CLI-invented framing — with a trailing newline for POSIX tools.
    let mut envelope_json =
        serde_json::to_string_pretty(&envelope).map_err(|source| CliError::JsonSerialize {
            what: "sealed envelope",
            source,
        })?;
    envelope_json.push('\n');
    let mut attestation_json =
        serde_json::to_string_pretty(&attestation).map_err(|source| CliError::JsonSerialize {
            what: "seal attestation",
            source,
        })?;
    attestation_json.push('\n');
    write_file(out, envelope_json.as_bytes(), "sealed envelope file")?;
    if let Err(error) = write_file(
        attestation_out,
        attestation_json.as_bytes(),
        "seal attestation file",
    ) {
        // Failed commands leave no partial outputs: an envelope without its
        // attestation is unopenable by `lys open`, so remove it rather than
        // strand it. Best-effort — the write failure is what surfaces.
        if let Err(cleanup) = std::fs::remove_file(out) {
            eprintln!(
                "warning: failed to remove partial sealed envelope {}: {cleanup}",
                out.display()
            );
        }
        return Err(error);
    }

    println!("sealed payload: {}", payload.display());
    println!("recipient public key (x25519): {}", hex_lower(&recipient));
    println!(
        "sender public key (ed25519): {}",
        hex_lower(&attestation.signer_public_key)
    );
    println!("sealed envelope written: {}", out.display());
    println!("seal attestation written: {}", attestation_out.display());
    Ok(())
}

/// `lys open --key <path> --sender-public-key <hex> --envelope <file>
/// --attestation <file> --out <file>`.
///
/// The recovered plaintext goes to `--out` only; stdout carries public
/// metadata exclusively.
///
/// # Errors
///
/// Returns [`CliError::KeyFileMissing`] if the recipient key file does not
/// exist, [`CliError::InvalidSenderPublicKey`] if the sender key is not 64
/// hex characters, [`CliError::Io`] if an input cannot be read or the
/// plaintext cannot be written, [`CliError::JsonParse`] if either input file
/// is not the expected wire type, and [`CliError::OpenFailed`] — the single
/// non-oracle message — if the attestation or the envelope fails any
/// cryptographic check.
pub fn open(
    key: &Path,
    sender_public_key: &str,
    envelope: &Path,
    attestation: &Path,
    out: &Path,
) -> CliResult<()> {
    let identity = load_identity(key)?;
    let sender = parse_hex_32(sender_public_key).ok_or(CliError::InvalidSenderPublicKey)?;

    let envelope_bytes = read_file(envelope, "sealed envelope file")?;
    let sealed: SealedEnvelope =
        serde_json::from_slice(&envelope_bytes).map_err(|source| CliError::JsonParse {
            what: "sealed envelope",
            path: envelope.to_path_buf(),
            source,
        })?;
    let attestation_bytes = read_file(attestation, "seal attestation file")?;
    let seal_attestation: Attestation =
        serde_json::from_slice(&attestation_bytes).map_err(|source| CliError::JsonParse {
            what: "seal attestation",
            path: attestation.to_path_buf(),
            source,
        })?;

    // Non-oracle by design: every cryptographic rejection — mismatched or
    // forged sender attestation, tampered envelope fields, wrong recipient
    // key — collapses to the one indistinguishable message. The library
    // already refuses to decrypt before the attestation verifies.
    let plaintext = open_and_verify(
        &sealed,
        &seal_attestation,
        &sender,
        &identity.x25519_static_secret(),
    )
    .map_err(|_err| CliError::OpenFailed)?;

    // The payload was confidential enough to be sealed; the recovered
    // plaintext lands owner-readable only (0600 on Unix), not umask-default.
    write_file_private(out, &plaintext, "opened payload file")?;

    println!("sealed envelope opened");
    println!("sender public key (ed25519): {}", hex_lower(&sender));
    println!("payload bytes: {}", plaintext.len());
    println!("payload written: {}", out.display());
    Ok(())
}
