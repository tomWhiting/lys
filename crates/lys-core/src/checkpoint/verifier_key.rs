//! [`NoteVerifierKey`] — the signed-note verifier-key text form, and the
//! key-name validity rules shared with checkpoint origins.
//!
//! # Invariants
//!
//! - A key name (and therefore a checkpoint origin) is non-empty, contains
//!   no Unicode whitespace, and contains no `'+'` — exactly the Go
//!   `isValidName` rules (UTF-8 validity is given by `&str`; Go's
//!   `unicode.IsSpace` and Rust's `char::is_whitespace` both test the
//!   Unicode `White_Space` property).
//! - The text form is `<name>+<8 lowercase hex chars of key ID>+<standard
//!   base64 with padding of (0x01 ‖ 32-byte pubkey)>`. Parsing accepts
//!   upper- or lowercase hex (like Go's `ParseUint`); emission is lowercase
//!   (like Go's `%08x`).
//! - A parsed key is internally consistent: the declared key ID always
//!   equals the key ID recomputed from `(name, pubkey)` (Go `NewVerifier`
//!   validates identically).
//! - Only public material is held; `Debug` is safe to derive.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::error::{TrustError, TrustResult};

/// Validates a signed-note key name / checkpoint origin.
///
/// Rules (Go `isValidName`): non-empty, no Unicode whitespace, no `'+'`.
/// (UTF-8 validity is given by `&str`.)
pub(crate) fn validate_note_name(name: &str) -> TrustResult<()> {
    if name.is_empty() {
        return Err(TrustError::VerifierKey {
            reason: "key name must not be empty".to_string(),
        });
    }
    if name.chars().any(char::is_whitespace) {
        return Err(TrustError::VerifierKey {
            reason: "key name must not contain whitespace".to_string(),
        });
    }
    if name.contains('+') {
        return Err(TrustError::VerifierKey {
            reason: "key name must not contain '+'".to_string(),
        });
    }
    Ok(())
}

/// A parsed note verifier key: `<name>+<hex keyid>+<base64(0x01 ‖ pubkey)>`.
///
/// Holds only public material. Constructed either from its parts via
/// [`Self::new`] (which computes the key ID) or from the text form via
/// [`Self::from_spec`] (which validates the declared key ID against the
/// recomputed one).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteVerifierKey {
    name: String,
    key_id: [u8; 4],
    public_key: [u8; 32],
}

impl NoteVerifierKey {
    /// Builds a verifier key from a name and public key, computing the
    /// key ID per the signed-note rule
    /// `SHA-256(name ‖ 0x0A ‖ 0x01 ‖ pubkey)[..4]`.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::VerifierKey`] if `name` violates the key-name
    /// rules.
    pub fn new(name: &str, public_key: [u8; 32]) -> TrustResult<Self> {
        let key_id = super::note::key_id(name, &public_key)?;
        Ok(Self {
            name: name.to_string(),
            key_id,
            public_key,
        })
    }

    /// Parses the text form `<name>+<hex keyid>+<base64(0x01 ‖ pubkey)>`.
    ///
    /// Splits at the first two `'+'` characters (the base64 part may itself
    /// contain `'+'`), then validates: name rules, exactly 8 hex chars of
    /// key ID (upper- or lowercase, like Go), base64 decoding to exactly
    /// 33 bytes, first byte `0x01` (the Ed25519 algorithm byte), and the
    /// declared key ID equal to the one recomputed from `(name, pubkey)` —
    /// Go `NewVerifier` validates identically.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::VerifierKey`] with a specific reason on any
    /// violation — this is TRUSTED operator input, diagnostics are safe.
    pub fn from_spec(spec: &str) -> TrustResult<Self> {
        let mut parts = spec.splitn(3, '+');
        let (Some(name), Some(hex_id), Some(key_b64)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(TrustError::VerifierKey {
                reason: "expected <name>+<hex keyid>+<base64 key>".to_string(),
            });
        };
        validate_note_name(name)?;
        let declared_id = parse_key_id_hex(hex_id)?;
        let key_bytes = STANDARD
            .decode(key_b64)
            .map_err(|e| TrustError::VerifierKey {
                reason: format!("key part is not canonical standard base64: {e}"),
            })?;
        let (Some((&alg, public_key_slice)), 33) = (key_bytes.split_first(), key_bytes.len())
        else {
            return Err(TrustError::VerifierKey {
                reason: format!(
                    "key part must decode to 33 bytes (algorithm byte + 32-byte public key), \
                     got {}",
                    key_bytes.len()
                ),
            });
        };
        if alg != 0x01 {
            return Err(TrustError::VerifierKey {
                reason: format!("unsupported algorithm byte {alg:#04x}, expected 0x01 (Ed25519)"),
            });
        }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(public_key_slice);
        let computed_id = super::note::key_id(name, &public_key)?;
        if declared_id != computed_id {
            return Err(TrustError::VerifierKey {
                reason: "declared key ID does not match the key ID computed from \
                         the name and public key"
                    .to_string(),
            });
        }
        Ok(Self {
            name: name.to_string(),
            key_id: computed_id,
            public_key,
        })
    }

    /// Emits the text form with a lowercase-hex key ID (Go emits `%08x`).
    pub fn to_spec(&self) -> String {
        let mut key_bytes = Vec::with_capacity(33);
        key_bytes.push(0x01);
        key_bytes.extend_from_slice(&self.public_key);
        format!(
            "{}+{}+{}",
            self.name,
            crate::hex_lower(&self.key_id),
            STANDARD.encode(&key_bytes)
        )
    }

    /// The key name (equal to the checkpoint origin this key verifies).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The 4-byte key ID.
    pub fn key_id(&self) -> [u8; 4] {
        self.key_id
    }

    /// The 32-byte Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
}

/// Parses exactly 8 hex characters (either case) into a big-endian 4-byte
/// key ID, mirroring Go's `strconv.ParseUint(…, 16, 32)` acceptance.
fn parse_key_id_hex(hex_id: &str) -> TrustResult<[u8; 4]> {
    if hex_id.len() != 8 || !hex_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(TrustError::VerifierKey {
            reason: "key ID must be exactly 8 hex characters".to_string(),
        });
    }
    let value = u32::from_str_radix(hex_id, 16).map_err(|e| TrustError::VerifierKey {
        reason: format!("key ID is not valid hex: {e}"),
    })?;
    Ok(value.to_be_bytes())
}

#[cfg(test)]
#[path = "verifier_key_tests.rs"]
mod tests;
