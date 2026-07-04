//! `lys-core` — domain-agnostic cryptographic trust primitives.
//!
//! A focused library of trust primitives: certificate-authority operations,
//! Merkle transparency-log operations, signed attestations, sealed payload
//! transport, and Ed25519 key management. Consumers (an agent runtime, a
//! workflow engine, an anchoring service) compose domain meaning on top — this
//! crate knows nothing about agents, sessions, workspaces, or any higher-level
//! concept.
//!
//! # Status
//!
//! This crate is being extracted, unchanged in behaviour, from the hardened
//! `meridian-trust` crate. See `docs/ROADMAP.md` in the repository root for the
//! extraction plan and the module inventory that will land here:
//!
//! - `keys` — [`Ed25519Identity`]: file/env-backed keypair with strict
//!   verification, Debug redaction, and Ed25519→X25519 derivation.
//! - `ca` — certificate authority: Ed25519-rooted X.509 issuance, custom
//!   extensions, and validity-window-enforcing chain verification.
//! - `merkle` — `AppendOnlyTree`: RFC 6962 transparency log with inclusion and
//!   consistency proofs verifiable by external parties from published roots.
//! - `attestation` — domain-separated, timestamp-authenticated signed
//!   statements over arbitrary payloads.
//! - `seal` — X25519 + AES-256-GCM sealed envelopes, standalone and
//!   sender-authenticated.
//!
//! [`Ed25519Identity`]: https://docs.rs/lys-core

#![forbid(unsafe_code)]
