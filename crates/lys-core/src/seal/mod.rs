//! Sealed payload transport: X25519 key agreement plus AES-256-GCM
//! encryption.
//!
//! [`seal`] and [`open`] are the standalone primitives — any caller who
//! knows the recipient's X25519 public key can seal, no sender identity is
//! bound. [`sign_and_seal`] and [`open_and_verify`] in
//! [`authenticated`] compose the sealed envelope with an
//! [`crate::attestation::Attestation`] over the sealed bytes for the cases
//! that need sender-identity binding (credential dispatch, audit
//! provenance). The two forms coexist by design.

pub mod authenticated;
pub mod sealed_envelope;

pub use authenticated::{open_and_verify, sign_and_seal};
pub use sealed_envelope::{SealedEnvelope, open, seal};
