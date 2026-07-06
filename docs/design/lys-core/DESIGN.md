---
type: design
cluster: lys-core
title: "Lys Core — Trust Primitives and CLI Surface"
---

# Lys Core — Trust Primitives and CLI Surface

## Intention

When this cluster is done, the hardened trust primitives live in this repository as `lys-core` — a standalone, domain-agnostic library with zero Meridian lineage — and the `lys` binary gives operators and auditors a command-line face over every primitive. An agent runtime signs session events with it. An auditor verifies a challenged log with it, offline, from nothing but a published root and proof bytes. A future anchoring service consumes its roots and attestations. Nothing in the crate knows what an agent, session, or workspace is; domain meaning is applied by consumers.

The crate arrives only in its hardened form. Phase 0 (the adversarial review and fix pass on `meridian-trust`) is done; this cluster is the extraction (phase 1) plus the CLI surface (phase 2). Behaviour is ported unchanged except for three deliberate breaks made at the last free moment: the wire-format tags are renamed to lys-owned strings, the legacy pre-domain-separation attestation fallback is stripped, and the identity env var and OID constant take lys names.

## Problem

The primitives exist today as `crates/meridian-trust` inside the Meridian workspace — hardened, adversarially reviewed, ~137 tests, with a live consumer. But they are unusable as the foundation of an open trust project in that shape:

- The wire-format tags (`meridian-trust/attestation/v1`, `meridian-trust-sealed-envelope/v1`) are baked into every signature produced. Once anything durable is signed under a tag, that tag is frozen forever. The extraction is the last moment these strings can change.
- The attestation verifier carries a dual-verify legacy fallback that exists only so Meridian's already-persisted attestations keep verifying. Lys must not inherit that caveat: v1 is domain-separated only.
- The custom-extension OID constant, the identity env var, and the crate naming all carry Meridian identity into what must be a vendor-neutral library.
- There is no operator or auditor surface. The library's defining promise — third parties verify without the operator's cooperation — has no tool a third party can actually run.

Consumers are waiting on the extracted form: the Norn agent runtime (the primary consumer — signing persistence sink, cert-at-spawn, MCP-boundary verification), the future `lys-anchor` transparency service, and haematite commit attestation.

## Solution

### D1: Domain-agnostic boundary

The founding rule carries over unchanged: `lys-core` knows no domain concepts. No agents, sessions, workspaces, peers, contracts, or members — and no Meridian references of any kind. It provides:

- Ed25519 key management with X25519 derivation
- A Certificate Authority that issues X.509 certificates for any subject
- An RFC 6962 Merkle transparency log over any serializable leaf
- Domain-separated signed attestations over any byte payload
- Sealed envelopes for any byte payload, standalone or sender-authenticated

Consumers compose meaning on top: Norn defines what an "agent certificate" or "session event leaf" is; the trust crate doesn't know or care. If a type references a domain concept, it does not belong in this crate.

### D2: Key management (`lys_core::keys`)

`Ed25519Identity` is the single long-term key type. Ported hardened behaviour:

- `load_or_generate(path)` — loads a 32-byte seed file or generates one. Generation is race-free: the seed is written to a unique temp file (pid + per-process counter in the name) and published with a no-clobber `hard_link` — the first generator to publish wins permanently; a loser detects `AlreadyExists`, discards its candidate seed, and loads the persisted key. The key file on disk never changes once created.
- Unix key files are created mode `0o600`; loading a file with loose permissions warns but does not fail.
- `from_env()` — loads a base64-encoded 32-byte seed from **`LYS_IDENTITY_KEY`** (renamed from the Meridian variable). Missing or malformed values are `KeyManagement` errors, never panics.
- All seed material — generated, file-read, or base64-decoded — lives in `Zeroizing` buffers.
- `sign(message)` → `[u8; 64]`; `verify(public_key, message, signature)` uses `verify_strict` (malleability/torsion-safe) everywhere. No non-strict verification exists anywhere in the crate.
- `Debug` output redacts the signing key; redaction is tested, not assumed.
- `x25519_static_secret()` / `x25519_public_key()` derive the Montgomery-form X25519 keys from the Ed25519 identity via the standard clamped-scalar conversion, so one long-term key serves both signing and credential unsealing.

### D3: Certificate Authority (`lys_core::ca`)

Ed25519-rooted X.509 issuance and verification:

- `CertificateAuthority` wraps an `Ed25519Identity`; `issue_certificate(subject, ttl, extensions)` produces an `IssuedCertificate` (DER bytes, subject keypair, SHA-256 fingerprint, expiry, issuer public key; Debug-redacted).
- rcgen signing goes through a `RemoteKeyPair` adapter so the CA's private seed is never serialised into rcgen's key-pair representation. `PKCS_ED25519` throughout.
- `verify_certificate_chain(cert_der, issuer_public_key)` extracts the TBS bytes with `x509-parser` and verifies the signature with `ed25519-dalek::verify_strict` (x509-parser cannot verify Ed25519). The validity window is enforced in-crate: expired and not-yet-valid certificates are rejected, and `verify_certificate_chain_at(cert_der, issuer_public_key, instant)` verifies at an explicit instant for auditing historical records. Self-signed certificates are rejected.
- Capability claims travel as opaque DER in custom extensions under **`LYS_OID_ARC`** (`1.3.6.1.4.1.58888`). The payload is opaque to the crate; the consumer defines claim semantics — the cert *is* the permission object. The arc keeps the placeholder PEN 58888 for now, with a documented note that a real IANA Private Enterprise Number must be registered before public issuance.

Revocation tracking is deliberately absent (never built in the source crate; a first-class revocation story is an open product question — see repo DESIGN.md §Open questions).

### D4: Merkle transparency log (`lys_core::merkle`)

`AppendOnlyTree<L: Serialize>` provides RFC 6962 semantics over SHA-256, backed by `ct-merkle` behind a deliberately backing-agnostic API:

- `append(leaf)` is the only mutation — the API exposes no delete or modify. Every argument is pre-checked so the underlying library cannot panic; out-of-range indices and invalid size pairs return `MerkleTree` errors.
- Inclusion proofs (`prove_inclusion` / `verify_inclusion`) and consistency proofs (`prove_consistency` / `verify_consistency`), with byte round-tripping (`as_bytes` / `try_from_bytes`) on both proof types.
- `RootHash::from_parts(root_hash, num_leaves)` / `to_parts()` — the external-verifier constructor. A third party holding only a published root and proof bytes can verify inclusion and consistency with no access to the tree. The external-verifier round trip is the defining test of the layer.
- `reconstruct_from_leaves(leaves)` rebuilds an identical tree from a persisted leaf sequence — the crash-recovery path for consumers persisting leaves externally.
- Leaf serialization is a **frozen wire contract**: leaves are canonical bytes; schema evolution means a new versioned leaf type, never a mutated one. This rule is documented at the module level.

### D5: Signed attestations (`lys_core::attestation`) — v1-only, domain-separated

Signed statements binding a key to a payload. The signed preimage is complete and domain-separated:

```
preimage = b"lys/attestation/v1" || timestamp.to_le_bytes() || payload_hash
```

- The timestamp is authenticated — inside the signature, not alongside it. Tampering with either payload or timestamp fails verification.
- The domain tag makes attestation signatures structurally non-interchangeable with any other lys signing context (sealed-envelope binding, raw CA certificate signing).
- **The legacy fallback is stripped.** The source crate's dual-verify shim (accepting pre-domain-separation signatures over the bare payload hash) exists only for Meridian's persisted history and does not port. `verify_attestation` accepts the v1 preimage and nothing else.
- Envelope: `Attestation { payload_hash: [u8; 32], signature: [u8; 64], signer_public_key: [u8; 32], timestamp: i64 }`, serde-serializable.

### D6: Sealed envelopes (`lys_core::seal`)

X25519 ephemeral key agreement + HKDF-SHA256 + AES-256-GCM, the standard sealed-box construction with the keys bound into the KDF:

- `seal(payload, recipient_public_key)` → `SealedEnvelope { ephemeral_public_key, ciphertext, nonce }`. Fresh ephemeral keypair per seal — forward secrecy per envelope.
- HKDF info binds the domain tag and both public keys: `b"lys/sealed-envelope/v1" || ephemeral_public_key || recipient_public_key` (tag renamed from the Meridian string).
- Contributory-behaviour enforcement on **both** seal and open: a low-order public key producing a non-contributory shared secret is rejected before any key material is derived.
- Every unseal failure — wrong key, tampered ciphertext, tampered nonce — collapses to the single undifferentiated `TrustError::UnsealFailed` through one failure arbiter (AES-GCM tag verification). No oracle, no timing split, no early return.
- `sign_and_seal(payload, sender_identity, recipient_x25519_public_key)` / `open_and_verify(...)` compose attestation over the sealed bytes for sender-identity binding. The attestation covers every wire byte of the envelope (`attestation_bytes()`), and verification gates **before** the cipher is ever touched — a forged sender is rejected without decrypting anything.

### D7: Wire formats are forever

The domain tags (`lys/attestation/v1`, `lys/sealed-envelope/v1`), the attestation preimage layout, the HKDF info layout, and leaf encodings are versioned wire contracts, frozen the moment anything durable is signed under them. Evolving one means a new `v2` constant and code path, never a mutation of `v1`. The extraction renames the Meridian tags precisely because it is the last moment nothing has been signed under the lys names.

### D8: CLI surface (`lys` binary)

The auditor's and operator's tool — a thin clap surface over `lys-core`. Logic lives in the library; the binary parses arguments and formats output (`anyhow` at the top level only). Subcommands:

- `lys key` — generate and inspect identities (public key, fingerprint). **Never prints private key material** under any flag or format.
- `lys ca issue` — issue a certificate with a capability-claim extension payload, signed by an issuer identity.
- `lys ca verify` — verify a certificate chain against an issuer public key, with an optional explicit verification instant (the `verify_certificate_chain_at` path).
- `lys attest` / `lys verify` — sign and verify attestations over a file or stdin.
- `lys seal` / `lys open` — sealed-envelope transport of a payload file.
- `lys log append` / `lys log prove` / `lys log verify` — transparency-log operations over a persisted leaf sequence, including the third-party path: `lys log verify` proves an inclusion or consistency claim from **only** a published root and proof bytes, with no access to the original tree.

The phase proof: a log produced by one process is verified end-to-end by the CLI in another process that never sees the original tree.

## Goals

1. `lys-core` compiles standalone in this repository with zero Meridian dependencies and zero Meridian references, behaviour-identical to the hardened source crate except the deliberate breaks (D5 legacy strip, D7 tag renames, `LYS_IDENTITY_KEY`, `LYS_OID_ARC`).
2. All hardening commitments hold in the ported code: `verify_strict` everywhere, validity-window enforcement with an `_at` variant, `RootHash::from_parts` external verification, authenticated timestamps with domain separation, contributory-DH rejection, seed zeroization, single-arbiter unsealing, race-free key generation.
3. Attestation verification is v1-only: no legacy code path exists in the crate.
4. An external verifier round-trips: inclusion and consistency proofs verify from published root parts and proof bytes alone.
5. The `lys` CLI covers every primitive, and a log produced in one process verifies end-to-end via the CLI in another with no access to the original tree.
6. `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --workspace` all pass clean.

## Non-Goals

- **Domain-specific semantics.** No agent, session, or claim vocabulary in the crate. Canonical agent claim schemas are phase 5.
- **Storage traits.** In-memory operations only; persistence is the consumer's concern. The CLI persists leaf sequences as files, using `reconstruct_from_leaves` — that is CLI policy, not a library trait.
- **Network operations.** `lys-core` is a pure library; the CLI is local-only. Transport belongs to `lys-anchor` (phase 4).
- **Anchoring, receipts, SCITT/COSE.** The notary layer is `lys-anchor`; nothing in this cluster emits or verifies COSE receipts.
- **Revocation infrastructure.** No CRLs, no OCSP, no revocation flag. Consumer-side today; a first-class answer is an open product question.
- **MCP surface.** `lys-mcp` is a later phase.
- **Zero-knowledge proofs.** Selective disclosure via salted-hash leaves + inclusion proofs is the v1 privacy story; ZK is a research direction.

## Structure

```
crates/lys-core/
├── Cargo.toml
└── src/
    ├── lib.rs                    — pub mod + re-exports, hex_lower helper (D1)
    ├── error.rs                  — TrustError enum, TrustResult<T> (D1)
    ├── keys/
    │   ├── mod.rs                — pub mod / pub use only
    │   ├── identity.rs           — Ed25519Identity: load_or_generate, from_env, sign,
    │   │                           verify_strict, X25519 derivation, redaction (D2)
    │   └── identity_tests.rs
    ├── ca/
    │   ├── mod.rs                — pub mod / pub use only
    │   ├── authority.rs          — CertificateAuthority: issue, verify chain, _at variant (D3)
    │   ├── certificate.rs        — IssuedCertificate, Debug redaction (D3)
    │   ├── extensions.rs         — LYS_OID_ARC, encode/decode extension (D3)
    │   └── *_tests.rs
    ├── merkle/
    │   ├── mod.rs                — pub mod / pub use only
    │   ├── tree.rs               — AppendOnlyTree<L>: append, root, proofs, reconstruct (D4)
    │   ├── proof.rs              — RootHash from_parts/to_parts, Inclusion/ConsistencyProof,
    │   │                           verify_inclusion, verify_consistency (D4)
    │   ├── leaf.rs               — leaf hashing, frozen-wire-contract docs (D4)
    │   └── *_tests.rs
    ├── attestation/
    │   ├── mod.rs                — pub mod / pub use only
    │   ├── sign.rs               — sign_attestation, verify_attestation, v1 preimage (D5)
    │   ├── envelope.rs           — Attestation envelope type (D5)
    │   └── *_tests.rs
    └── seal/
        ├── mod.rs                — pub mod / pub use only
        ├── sealed_envelope.rs    — seal/open, HKDF binding, contributory checks,
        │                           single failure arbiter (D6)
        ├── authenticated.rs      — sign_and_seal / open_and_verify (D6)
        └── *_tests.rs

crates/lys/
├── Cargo.toml
└── src/
    ├── main.rs                   — thin entry: parse args, dispatch, format errors (D8)
    └── commands/
        ├── mod.rs                — pub mod only
        ├── key.rs                — lys key (D8)
        ├── ca.rs                 — lys ca issue / verify (D8)
        ├── attest.rs             — lys attest / verify (D8)
        ├── seal.rs               — lys seal / open (D8)
        └── log.rs                — lys log append / prove / verify (D8)
```

## Constraints

- **No domain types and no Meridian references.** If it names an agent, session, workspace, peer, contract, or anything Meridian, it doesn't belong here.
- **No storage traits, no network.** Pure library crate; CLI is local file I/O only.
- **`unsafe_code` forbidden.** All dependencies pure Rust.
- **No `unwrap` / `expect` / `panic` / `todo` in library code.** Tests opt out per-module.
- **Private key material never in `Debug`, logs, error messages, or CLI output.** Redaction tested, not assumed. Seed buffers are `Zeroizing`.
- **Wire formats are frozen.** Tags, preimage layouts, and leaf encodings version forward (`v2`), never mutate.
- **No file over 500 lines of code.** `mod.rs` carries only `pub mod` / `pub use` / module docs; tests live in sibling `*_tests.rs` files.
- **Every public item documented**; module-level `//!` docs state invariants.
- **Cryptographic changes require an adversarial review before landing.** This cluster ports hardened behaviour unchanged; any deviation beyond the four deliberate breaks (tag renames, legacy strip, env var, OID constant) is out of bounds.
