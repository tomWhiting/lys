//! C2SP tlog-checkpoint bodies and the signed-note envelope (the
//! `lys` D1 wire contract), byte-for-byte compatible with the Go
//! `sumdb/note` reference implementation.
//!
//! # Invariants
//!
//! - The encode/parse pair round-trips byte-exactly: parsing a body emitted
//!   by [`CheckpointBody::encode`] reproduces the value, and re-encoding a
//!   parsed body reproduces the exact bytes.
//! - A note that [`sign_note`] emits always re-verifies under
//!   [`verify_note`] (and under Go `note.Open`): the signing preconditions
//!   forbid every body shape the parser would reject, and the 1 MiB note
//!   size cap is enforced at signing time as well as at verification time.
//! - Checkpoint origins double as note key names, and [`verify_checkpoint`]
//!   **enforces** `checkpoint origin == verifier-key name`, so a key that
//!   signs two logs can never have a checkpoint for one accepted by a
//!   verifier configured for the other.
//! - Verification of untrusted notes is non-oracle: every failure mode —
//!   size, UTF-8, structure, unknown key, bad signature — collapses to the
//!   single [`TrustError::NoteVerification`] value.
//! - Private key material never appears in any output or error of this
//!   module; notes and verifier keys carry only public material.
//!
//! [`TrustError::NoteVerification`]: crate::error::TrustError::NoteVerification

pub mod body;
pub mod note;
pub mod verifier_key;

pub use body::CheckpointBody;
pub use note::{key_id, sign_note, verify_checkpoint, verify_note};
pub use verifier_key::NoteVerifierKey;
