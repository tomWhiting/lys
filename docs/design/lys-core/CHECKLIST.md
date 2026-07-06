# Lys-Core — Checklist

## Crate Setup

- [ ] **C1** — Root Cargo.toml declares workspace members `crates/lys-core` and `crates/lys`
- [ ] **C2** — lys-core Cargo.toml declares ed25519-dalek, x25519-dalek, aes-gcm, rcgen, ct-merkle, x509-parser, sha2, hkdf, rand, serde, thiserror, zeroize, base64, chrono, tracing dependencies
- [ ] **C3** — lys-core lib.rs declares public modules: keys, ca, merkle, attestation, seal, error — and the crate-internal `hex_lower` helper
- [ ] **C4** — lib.rs carries `#![forbid(unsafe_code)]`
- [ ] **C5** — TrustError enum defined with thiserror: CertificateGeneration, CertificateParsing, CertificateVerification, CertificateRevocation, MerkleTree, Seal, UnsealFailed, AttestationFailed, KeyManagement, Signing, InvalidSignature — with `TrustResult<T>` alias
- [ ] **C6** — No Meridian reference anywhere in lys-core or lys sources: `grep -ri meridian crates/` returns nothing

## Key Management

- [ ] **C7** — Ed25519Identity struct holds SigningKey + VerifyingKey; Debug output contains '[REDACTED]' for the signing key (test exists)
- [ ] **C8** — Ed25519Identity::load_or_generate(path) loads a 32-byte seed file or generates and persists one; malformed-length files return KeyManagement errors
- [ ] **C9** — Key generation is race-free: seed written to a unique temp file (pid + per-process counter in the name), published via no-clobber `hard_link`; on `AlreadyExists` the loser discards its candidate seed and loads the persisted key (first-writer-wins; concurrent-generation test exists)
- [ ] **C10** — On Unix the key file is created mode 0o600; loading a key file with loose permissions emits a warning but still loads
- [ ] **C11** — Ed25519Identity::from_env() reads a base64-encoded 32-byte seed from the `LYS_IDENTITY_KEY` environment variable; missing variable, invalid base64, and wrong decoded length each return KeyManagement errors
- [ ] **C12** — All seed material in loading, generation, and decode paths is held in `Zeroizing` buffers
- [ ] **C13** — Ed25519Identity::sign(message) returns [u8; 64]
- [ ] **C14** — Ed25519Identity::verify(public_key, message, signature) uses ed25519-dalek `verify_strict`; no call to non-strict `verify` exists anywhere in the crate
- [ ] **C15** — Ed25519Identity::x25519_public_key() returns the Montgomery-form [u8; 32] and x25519_static_secret() returns the clamped-scalar StaticSecret; Diffie-Hellman between two identities' derived keys agrees from both sides (test exists)

## Certificate Authority

- [ ] **C16** — CertificateAuthority::new(identity) wraps Ed25519Identity and exposes public_key_bytes()
- [ ] **C17** — issue_certificate(subject, ttl, extensions) returns IssuedCertificate holding DER bytes, subject keypair, SHA-256 fingerprint ([u8; 32] of DER), expiry, and issuer public key
- [ ] **C18** — rcgen signing goes through a RemoteKeyPair adapter with PKCS_ED25519 so the CA private seed is never serialised into rcgen's keypair representation
- [ ] **C19** — IssuedCertificate Debug output redacts private key material (test exists)
- [ ] **C20** — verify_certificate_chain(cert_der, issuer_public_key) extracts TBS bytes with x509-parser and verifies the signature with ed25519-dalek `verify_strict`
- [ ] **C21** — Chain verification enforces the validity window: expired certificates and not-yet-valid certificates are both rejected (tests exist for each)
- [ ] **C22** — verify_certificate_chain_at(cert_der, issuer_public_key, instant) verifies at an explicit instant; a cert expired now but valid at the given instant passes
- [ ] **C23** — Self-signed certificates are rejected by verify_certificate_chain
- [ ] **C24** — `LYS_OID_ARC` constant equals [1, 3, 6, 1, 4, 1, 58888] with a doc comment stating the PEN is a placeholder pending IANA Private Enterprise Number registration
- [ ] **C25** — encode_extension / decode_extension round-trip an arbitrary DER payload under LYS_OID_ARC; decode of a cert without the extension returns Ok(None)
- [ ] **C26** — Round-trip test: rcgen-generated Ed25519 keypair is loadable as ed25519-dalek SigningKey/VerifyingKey

## Merkle Transparency Log

- [ ] **C27** — AppendOnlyTree<L> generic over leaf type L: Serialize; append(leaf) returns the new tree size
- [ ] **C28** — No delete or modify operation exists on the tree — append-only enforced by API
- [ ] **C29** — root() returns the current RootHash; the empty tree produces a deterministic empty root hash
- [ ] **C30** — prove_inclusion(leaf_index) pre-checks bounds and returns TrustError::MerkleTree on out-of-range index — no panic path into the backing library
- [ ] **C31** — prove_consistency(old_size, new_size) pre-checks the size pair (old ≤ new, new ≤ len, old ≥ 1) and returns TrustError::MerkleTree on violation
- [ ] **C32** — verify_inclusion(root_hash, leaf, index, proof) and verify_consistency(old_root, new_root, proof) return Result; tampered proofs and mismatched roots fail
- [ ] **C33** — RootHash::from_parts(root_hash, num_leaves) and to_parts() round-trip; from_parts requires no tree access
- [ ] **C34** — InclusionProof and ConsistencyProof round-trip through as_bytes() / try_from_bytes()
- [ ] **C35** — External-verifier round-trip test exists: a verifier holding only published root parts and proof bytes (never the tree) verifies inclusion and consistency
- [ ] **C36** — reconstruct_from_leaves(leaves) rebuilds a tree with a root hash identical to the original (test exists)
- [ ] **C37** — merkle module docs state the frozen-wire-contract rule: leaf encodings are canonical bytes, evolved only by introducing a new versioned leaf type

## Signed Attestations

- [ ] **C38** — sign_attestation(payload, signing_key) signs the preimage `b"lys/attestation/v1" || timestamp.to_le_bytes() || payload_hash` — domain tag constant equals the lys string, not any meridian string
- [ ] **C39** — Attestation { payload_hash: [u8; 32], signature: [u8; 64], signer_public_key: [u8; 32], timestamp: i64 } is serde Serialize/Deserialize
- [ ] **C40** — verify_attestation(attestation, payload) recomputes the v1 preimage and verifies with `verify_strict`
- [ ] **C41** — No legacy fallback exists: verification never attempts a signature check over the bare payload hash, and a signature over the bare payload hash fails verify_attestation (test exists)
- [ ] **C42** — Tampered payload fails verify_attestation
- [ ] **C43** — Tampered timestamp fails verify_attestation — the timestamp is inside the signed preimage (test exists)

## Sealed Envelope

- [ ] **C44** — seal(payload, recipient_public_key) returns SealedEnvelope { ephemeral_public_key, ciphertext, nonce } using a fresh ephemeral X25519 keypair per call (two seals of the same payload to the same recipient differ)
- [ ] **C45** — HKDF-SHA256 info input is `b"lys/sealed-envelope/v1" || ephemeral_public_key || recipient_public_key` — domain tag constant equals the lys string
- [ ] **C46** — Both seal and open reject non-contributory Diffie-Hellman: a low-order public key fails via `was_contributory` before any key derivation (test exists)
- [ ] **C47** — Seal/open roundtrip succeeds: sealed with the recipient's X25519 public key, opened with the recipient's static secret
- [ ] **C48** — Wrong private key, tampered ciphertext, and tampered nonce all return exactly TrustError::UnsealFailed — a single undifferentiated failure through the AES-GCM arbiter, with no early return distinguishing causes
- [ ] **C49** — SealedEnvelope::attestation_bytes() covers every wire byte of the envelope (ephemeral key, nonce, ciphertext)
- [ ] **C50** — sign_and_seal(payload, sender_identity, recipient_x25519_public_key) returns (SealedEnvelope, Attestation) where the attestation signs attestation_bytes()
- [ ] **C51** — open_and_verify verifies the attestation before any decryption: an invalid sender signature is rejected without the cipher being touched, and a valid signature over a tampered envelope also fails (tests exist)

## CLI Surface

- [ ] **C52** — `lys` binary crate exists; main.rs is a thin entry (parse, dispatch, format errors); anyhow appears only in the CLI crate
- [ ] **C53** — `lys key` generates an identity at a path and inspects one (public key, fingerprint); no subcommand, flag, or output format prints private key material (test asserts output contains no seed bytes in any encoding)
- [ ] **C54** — `lys ca issue` issues a certificate signed by an issuer identity file, embedding a caller-supplied capability-claim payload as a LYS_OID_ARC extension, and writes the DER out
- [ ] **C55** — `lys ca verify` verifies a certificate against an issuer public key, and accepts an explicit verification instant flag routing to verify_certificate_chain_at
- [ ] **C56** — `lys attest` signs a file or stdin and emits a serialized Attestation; `lys verify` checks an attestation against a payload and reports success/failure via exit code
- [ ] **C57** — `lys seal` seals a payload file for a recipient public key; `lys open` opens it with the recipient identity; the pair round-trips
- [ ] **C58** — `lys log append` appends leaves to a persisted leaf sequence and prints the new root; `lys log prove` emits inclusion or consistency proof bytes plus root parts
- [ ] **C59** — `lys log verify` verifies an inclusion or consistency proof from only a published root (bytes + leaf count) and proof bytes — no access to the leaf sequence or tree required
- [ ] **C60** — Cross-process CLI test exists: a log produced by one process is verified end-to-end by the CLI in another process with no access to the original tree

## Integration Verification

- [ ] **C61** — cargo fmt --check passes clean
- [ ] **C62** — cargo clippy --all-targets -- -D warnings passes clean
- [ ] **C63** — cargo test --workspace passes green
- [ ] **C64** — No file exceeds 500 lines of code; every mod.rs carries only pub mod / pub use / module docs; tests live in sibling *_tests.rs files
- [ ] **C65** — lys-core builds standalone with zero meridian-* dependencies in its Cargo.toml and Cargo.lock
