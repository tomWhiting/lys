//! `lys-core` — domain-agnostic cryptographic trust primitives.
//!
//! A focused library of trust primitives: certificate authority operations,
//! Merkle transparency-log operations, signed attestations, sealed payload
//! transport, and Ed25519 key management. Consumers compose domain meaning
//! on top — this crate knows nothing about any higher-level concepts.
//!
//! The foundation laid here is [`TrustError`], [`TrustResult`], and
//! [`Ed25519Identity`]. The [`ca`], [`merkle`], [`attestation`], and [`seal`]
//! modules are implemented on top of these primitives.
//!
//! ```
//! use lys_core::TrustResult;
//!
//! fn fallible_op() -> TrustResult<()> {
//!     Ok(())
//! }
//!
//! assert!(fallible_op().is_ok());
//! ```

// Library code contains no unsafe whatsoever. Test builds relax `forbid` to
// the workspace-level `deny` because the env-backed tests must call
// `std::env::set_var` (unsafe in edition 2024) under `#[allow(unsafe_code)]`,
// which a crate-level `forbid` would reject outright.
#![cfg_attr(not(test), forbid(unsafe_code))]

pub mod attestation;
pub mod ca;
pub mod error;
pub mod keys;
pub mod merkle;
pub mod seal;

pub use error::{TrustError, TrustResult};
pub use keys::Ed25519Identity;

/// Lowercase hex encoding of a byte slice.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Deliberate discard: `fmt::Write` for `String` is infallible —
        // writing to an in-memory String can never return an error.
        let _ = s.write_fmt(format_args!("{b:02x}"));
    }
    s
}
