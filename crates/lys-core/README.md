# lys-core

Domain-agnostic cryptographic trust primitives for AI agents.

- **Identity** — Ed25519 keypairs and X.509 capability certificates (strict verification, validity-window enforcement).
- **Transparency** — RFC 6962 append-only Merkle logs with C2SP signed-note checkpoints and self-contained inclusion/consistency proof artifacts, third-party-verifiable from a verifier key string alone.
- **Attestation** — tagged `COSE_Sign1` (RFC 9052) statements over any payload's SHA-256 hash, Ed25519-signed with deterministic CBOR and a canonical-encoding-strict verifier; verifiable with any off-the-shelf COSE library.
- **Sealed transport** — X25519 + HKDF-SHA256 + AES-256-GCM envelopes, standalone or sender-authenticated.

The library knows nothing about agents, sessions, or workspaces — consumers apply domain meaning. Every artifact it emits verifies with standard, non-vendor tooling; wire formats are versioned contracts that freeze at 0.1.0. Part of the [lys](https://github.com/tomWhiting/lys) project; see the repository for vision, design, roadmap, and the byte-exact wire-format contracts.

Licensed under Apache-2.0.
