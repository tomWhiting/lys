//! Signed attestations: Ed25519 detached signatures over a domain-separated
//! preimage binding the SHA-256 hash of any byte payload together with the
//! signing timestamp, plus a serializable envelope ([`Attestation`]) that
//! carries the hash, the signature, the signer's public key, and the unix
//! millisecond timestamp. Both the hash and the timestamp are authenticated;
//! the domain tag prevents cross-protocol signature confusion (see
//! [`sign`]).
//!
//! Domain meaning (execution receipt, audit entry, dispatch attestation) is
//! applied by consumers; the trust crate only provides the sign/verify and
//! the envelope shape.

pub mod envelope;
pub mod sign;

pub use envelope::Attestation;
pub use sign::{sign_attestation, verify_attestation};
