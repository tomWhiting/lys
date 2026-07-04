# lys-core

Domain-agnostic cryptographic trust primitives for AI agents.

- **Identity** — Ed25519 keypairs and X.509 capability certificates (strict verification, validity-window enforcement).
- **Transparency** — RFC 6962 append-only Merkle logs with inclusion and consistency proofs verifiable from a published root.
- **Attestation** — domain-separated, timestamp-authenticated signed statements over any payload.
- **Sealed transport** — X25519 + AES-256-GCM envelopes, standalone or sender-authenticated.

The library knows nothing about agents, sessions, or workspaces — consumers apply domain meaning. Part of the [lys](https://github.com/tomWhiting/lys) project; see the repository for vision, design, and roadmap.

Licensed under Apache-2.0.
