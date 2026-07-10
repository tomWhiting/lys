//! [`CheckpointBody`] — the C2SP tlog-checkpoint body, byte-exact.
//!
//! # Invariants
//!
//! - [`CheckpointBody::encode`] emits exactly three newline-terminated
//!   lines: origin, tree size in strict ASCII decimal (no leading zeros,
//!   no sign), and the standard-base64-with-padding encoding of the
//!   32-byte RFC 6962 root hash. No extension lines are ever emitted.
//! - [`CheckpointBody::parse`] is strict on those three lines and tolerates
//!   (discards) non-empty extension lines after them, per the C2SP spec.
//!   Empty lines are malformed — a body can never contain a blank line,
//!   which is what keeps the signed-note envelope split unambiguous.
//! - The origin is validated against the note key-name rules at
//!   construction: origins double as note key names (the checkpoint is
//!   signed under its origin), so an origin that cannot be a key name is
//!   rejected before anything is signed under it.
//! - encode/parse round-trip byte-exactly.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::error::{TrustError, TrustResult};
use crate::merkle::RootHash;

use super::verifier_key::validate_note_name;

/// C2SP tlog-checkpoint body: origin, tree size, and RFC 6962 root hash.
///
/// The origin is validated against note-name rules at construction — the
/// origin doubles as the signing key name, so `lys`-emitted checkpoints
/// sign under the origin and verifiers enforce the binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointBody {
    origin: String,
    tree_size: u64,
    root_hash: [u8; 32],
}

impl CheckpointBody {
    /// Builds a checkpoint body, validating the origin against the note
    /// key-name rules.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::CheckpointEncoding`] if the origin is empty,
    /// contains whitespace, or contains `'+'`.
    pub fn new(origin: &str, tree_size: u64, root_hash: [u8; 32]) -> TrustResult<Self> {
        validate_note_name(origin).map_err(|e| TrustError::CheckpointEncoding {
            reason: format!("invalid checkpoint origin: {e}"),
        })?;
        Ok(Self {
            origin: origin.to_string(),
            tree_size,
            root_hash,
        })
    }

    /// Convenience constructor from the existing merkle root type via
    /// [`RootHash::to_parts`].
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::CheckpointEncoding`] if the origin is invalid
    /// (see [`Self::new`]).
    pub fn from_root(origin: &str, root: &RootHash) -> TrustResult<Self> {
        let (root_hash, tree_size) = root.to_parts();
        Self::new(origin, tree_size, root_hash)
    }

    /// Encodes the body as exactly
    /// `"{origin}\n{tree_size}\n{base64_std_padded(root_hash)}\n"`.
    pub fn encode(&self) -> String {
        format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.tree_size,
            STANDARD.encode(self.root_hash)
        )
    }

    /// Strict parse of a body (typically one returned by `verify_note`).
    ///
    /// Line 1: a valid origin per the note key-name rules. Line 2: ASCII
    /// decimal `u64`, no leading zeros unless the value is `"0"`, no sign,
    /// no whitespace. Line 3: exactly 44 base64 characters decoding
    /// canonically to 32 bytes. Extension lines (non-empty lines after
    /// line 3) are tolerated and discarded, per the C2SP spec; an empty
    /// line anywhere is malformed (bodies cannot contain blank lines — see
    /// [`super::note::sign_note`]).
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::CheckpointParsing`] on any violation,
    /// including a body that does not end with `'\n'`.
    pub fn parse(text: &str) -> TrustResult<Self> {
        let Some(without_final_newline) = text.strip_suffix('\n') else {
            return Err(TrustError::CheckpointParsing {
                reason: "checkpoint body must end with a newline".to_string(),
            });
        };
        let lines: Vec<&str> = without_final_newline.split('\n').collect();
        if lines.len() < 3 {
            return Err(TrustError::CheckpointParsing {
                reason: format!(
                    "checkpoint body must have at least 3 lines, got {}",
                    lines.len()
                ),
            });
        }
        if lines.iter().any(|line| line.is_empty()) {
            return Err(TrustError::CheckpointParsing {
                reason: "checkpoint body must not contain empty lines".to_string(),
            });
        }
        let origin = lines[0];
        validate_note_name(origin).map_err(|e| TrustError::CheckpointParsing {
            reason: format!("invalid checkpoint origin: {e}"),
        })?;
        let tree_size = parse_tree_size(lines[1])?;
        let root_hash = parse_root_line(lines[2])?;
        // Lines beyond the third are extension lines: tolerated, discarded.
        Ok(Self {
            origin: origin.to_string(),
            tree_size,
            root_hash,
        })
    }

    /// The log's origin (its unique identity, and the note key name).
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The tree size this checkpoint commits to.
    pub fn tree_size(&self) -> u64 {
        self.tree_size
    }

    /// The 32-byte RFC 6962 root hash this checkpoint commits to.
    pub fn root_hash(&self) -> [u8; 32] {
        self.root_hash
    }

    /// Bridges into the existing merkle verification helpers:
    /// `RootHash::from_parts(self.root_hash, self.tree_size)`.
    pub fn to_root(&self) -> RootHash {
        RootHash::from_parts(self.root_hash, self.tree_size)
    }
}

/// Parses a strict ASCII-decimal `u64` tree size: digits only, no sign, no
/// whitespace, and no leading zeros unless the value is exactly `"0"`.
fn parse_tree_size(line: &str) -> TrustResult<u64> {
    if line.is_empty() || !line.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TrustError::CheckpointParsing {
            reason: "tree size must be ASCII decimal digits only".to_string(),
        });
    }
    if line.len() > 1 && line.starts_with('0') {
        return Err(TrustError::CheckpointParsing {
            reason: "tree size must not have leading zeros".to_string(),
        });
    }
    line.parse::<u64>()
        .map_err(|e| TrustError::CheckpointParsing {
            reason: format!("tree size does not fit in u64: {e}"),
        })
}

/// Parses the root-hash line: exactly 44 standard-base64 characters
/// decoding canonically to 32 bytes.
fn parse_root_line(line: &str) -> TrustResult<[u8; 32]> {
    if line.len() != 44 {
        return Err(TrustError::CheckpointParsing {
            reason: format!(
                "root hash line must be exactly 44 base64 characters, got {}",
                line.len()
            ),
        });
    }
    let decoded = STANDARD
        .decode(line)
        .map_err(|e| TrustError::CheckpointParsing {
            reason: format!("root hash line is not canonical standard base64: {e}"),
        })?;
    let root: [u8; 32] =
        decoded
            .as_slice()
            .try_into()
            .map_err(|_err| TrustError::CheckpointParsing {
                reason: format!("root hash must decode to 32 bytes, got {}", decoded.len()),
            })?;
    Ok(root)
}

#[cfg(test)]
#[path = "body_tests.rs"]
mod tests;
