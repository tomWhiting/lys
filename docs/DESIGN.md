# Lys — Design

> Status: pre-extraction. The core primitives live today as `meridian-trust` inside the Meridian workspace, undergoing a security-hardening pass (see [Hardening baseline](#hardening-baseline)). This document records the design as it will stand in this repository.

## Origin

Lys is the extraction and elevation of `crates/meridian-trust` — a domain-agnostic cryptographic primitives crate (certificate authority, Merkle transparency log, signed attestations, sealed envelopes, Ed25519 key management) built for the Meridian exchange and proven against ~110 tests with a live consumer (workspace audit, dispatch verification, execution receipts).

The founding rule carries over unchanged: **the core crate knows no domain concepts.** No peers, contracts, workspaces, agents, or sessions in the primitive layer. Domain meaning is applied by consumers. What changes in lys is scope: around that core, lys adds the layers that turn primitives into a trust system — canonical schemas for agent claims, an anchoring service, and verification tooling.

## Architecture

Six layers, composable but separable:

### 1. Identity (`lys-core::keys`, `lys-core::ca`)

- `Ed25519Identity`: file- or env-backed keypair, strict verification, Debug-redacted, with X25519 derivation (clamped-scalar conversion) so one long-term key serves both signing and credential unsealing.
- `CertificateAuthority`: Ed25519-rooted X.509 issuance via rcgen with a `RemoteKeyPair` adapter (the private seed never serialises). Chain verification extracts TBS bytes with x509-parser and verifies with ed25519-dalek (`verify_strict`), enforcing the validity window. Capability claims travel as opaque DER in custom extensions under the lys OID arc — the cert *is* the permission object; consumers define claim semantics.
- **Open item:** register a real IANA Private Enterprise Number (the current arc uses placeholder PEN 58888).

### 2. Tamper-evident log (`lys-core::merkle`)

- `AppendOnlyTree<L>`: RFC 6962 semantics over SHA-256. Append is the only mutation; the API exposes no delete/modify and pre-checks every argument so the underlying library cannot panic.
- Inclusion and consistency proofs with byte round-tripping, and — critically — `RootHash::from_parts(bytes, leaf_count)` so a third party holding only a published root and a proof can verify. The external-verifier round trip is the defining test of the layer.
- Leaf serialization is a **frozen wire contract**: leaves are canonical bytes; schema evolution means a new versioned leaf type, never a mutated one.

### 3. Attestation (`lys-core::attestation`)

Signed statements binding an agent key to an action or artifact. The signed preimage is domain-separated and complete: `domain-tag || timestamp || payload-hash` — the timestamp is authenticated, and signatures from different lys contexts (attestation, sealed-envelope binding, raw CA signing) are structurally non-interchangeable. Envelope: `{ payload_hash, signature, signer_public_key, timestamp }`, serde-serializable.

### 4. Sealed transport (`lys-core::seal`)

X25519 ephemeral key agreement + HKDF-SHA256 (info binds the domain tag and both public keys) + AES-256-GCM. Fresh ephemeral per seal — forward secrecy per envelope; contributory-behaviour checks reject low-order points; every unseal failure collapses to a single undifferentiated error through a single failure arbiter (no oracle, no timing split). `sign_and_seal` / `open_and_verify` compose attestation over the sealed bytes for sender-identity binding — verification gates before the cipher is ever touched.

### 5. Anchoring (`lys-anchor` — new, service)

The layer that makes history *externally* fixed. Instances periodically submit log roots; the service maintains its own transparency log of anchored roots and returns receipts.

- **Alignment: SCITT (RFC 9943/9942).** Anchored statements are COSE-signed; receipts are COSE receipts verifiable with standard tooling. This is the QLDB lesson operationalised — verification must outlive the vendor.
- **Storage ambition: tile-backed** (the format CT itself converged on; Tessera-compatible), so the log can be served as static assets and witnessed externally.
- Privacy invariant: the service sees roots and signer identities, never contents. Salted-hash leaves for anything sensitive even at the metadata level.
- Deployment shapes: hosted shared ledger (the product), self-hosted for enterprises, and — for minimal-trust operation — counter-anchoring the service's own root to public infrastructure (OpenTimestamps-style).

### 6. Verification (`lys-verify` — new, CLI + library)

The auditor's tool: given published roots, receipts, and proofs, answer "is this history intact?" without contacting the operator. Verifies cert chains to instance CAs, inclusion/consistency against anchored roots, attestation signatures, and — where the runtime supports it — drives deterministic replay as the strongest check. Must be independently implementable from the wire formats alone.

## Primitive decisions

| Layer | Choice | Rationale |
|---|---|---|
| Signatures | Ed25519, `verify_strict` | Universal; strict mode excludes malleability/torsion — non-repudiation grade |
| Trust-layer hash | SHA-256 | The verification world's lingua franca (RFC 6962, SCITT, COSE, HSMs, FIPS, auditors) |
| Storage hash (haematite) | BLAKE3 | Internal, performance-sensitive, never externally verified — different job |
| Receipts | COSE (SCITT profile) | Standard tooling verifies; no lys lock-in |
| Envelope crypto | X25519 + HKDF-SHA256 + AES-256-GCM | Standard sealed-box construction, keys bound into KDF |
| Log format | RFC 6962 semantics now; tile-compatible target | Tiles are where CT, Rekor v2, and Tessera all landed |

The governing principle: **in trust infrastructure, boring wins.** The product is verifiability by strangers, and strangers verify what they already speak. "Better" primitives (faster hashes, novel signatures) buy performance that doesn't matter here at the cost of the interop that does. The two hash worlds meet cleanly: a haematite BLAKE3 root logged by lys is just 32 attested bytes.

Rust throughout; `unsafe_code = "deny"`; no unwrap/expect/panic in library code; private key material never in Debug output or logs (redaction-tested). The current Merkle backing (`ct-merkle`) is RFC 6962-correct but unaudited — the wrapper API is deliberately backing-agnostic so it can be re-implemented over audited primitives (`sha2` is RustCrypto-audited) or replaced with a tile-native implementation without breaking consumers.

## Hardening baseline

An adversarial review (July 2026) of `meridian-trust` produced the punch list below — all being fixed **before extraction**. Lys inherits the crate only in its hardened form; these are recorded here as design commitments:

| # | Finding | Commitment |
|---|---|---|
| H1 | Chain verification ignored the validity window | Expiry/not-before enforced in-crate, with an `_at(instant)` variant |
| H2 | Non-strict Ed25519 verification | `verify_strict` everywhere |
| H3 | No public `RootHash` constructor — external verifiers couldn't verify | `from_parts` + external-verifier round-trip test |
| M1 | Attestation timestamp not covered by signature | Timestamp in the signed preimage |
| M2 | No domain separation across signing contexts | Context tags in every lys-controlled preimage |
| M3 | No low-order-point rejection in key agreement | `was_contributory` enforced on seal and open |
| M4 | Seed buffers not zeroized in key-loading paths | `Zeroizing` on all seed material |
| M5 | Timing-distinguishable unseal failure | Single failure arbiter (AES-GCM), no early return |
| M6 | Schema-fragile leaf serialization | Frozen-wire-contract rule, documented and enforced by convention |

Sound and carried forward unchanged: the Ed25519→X25519 derivation, the authenticated-seal composition (attestation covers every wire byte; verification gates before decryption), Merkle panic-safety, per-seal nonce derivation, and redaction discipline.

## Integration: Norn is the primary consumer

The original crate was built inside Meridian, but Meridian is not lys's real customer. **Norn — the Ablative agent runtime — is.** Meridian consumes Norn as a library, so wherever Meridian needs trust it inherits it transitively; and as the stack's second generation lands (everything as library + CLI + MCP surface, composed rather than monolithic), Meridian becomes an in-house means-to-an-end rather than the consumer lys is designed around. Design for Norn first.

**Norn (agent runtime) — the primary consumer and the payoff.** Every persisted session event flows through one chokepoint: `EventStore::append` → the `PersistenceSink` trait. A lys signing sink decorates the existing JSONL sink — sign each event, maintain the session Merkle root — and `checkpoint()` is the natural anchoring moment. Zero core-loop changes. Norn's own design (norn-runtime D12) already anticipates this: `CallerContext.agent_cert_fingerprint`, cert-signed cross-boundary tool actions. Agent spawn is the cert-issuance moment; the MCP server/client boundary (currently carrying no caller attestation) is the agent-to-agent trust surface. Norn as headless JSON-RPC, each agent attachable at its own position, nothing happening in darkness — lys is the layer that makes "nothing in darkness" cryptographically true rather than merely observable.

**Aion (durable workflows) — the strongest claim.** Norn agents run as Aion workflows that survive power loss and replay deterministically from an immutable event history. That upgrades "the log is untampered" to "the log is re-derivable": signed event chain + deterministic replay is a stronger guarantee than any TEE attestation, in software alone. This is the claim no competitor with a runtime they don't own can make.

**Haematite (storage) — the durable home.** Session logs and anchored roots persist in haematite's `EventStore` (ordered, append-only leaves), and Norn sessions become portable — an agent's history moves across nodes and clusters instead of being locked in a folder. Lys supplies exactly what haematite structurally lacks: signatures over commits, and hash-chained commit lineage (its commit log is currently a flat timestamped list). A haematite root anchored through lys makes a whole database state attestable.

**Meridian (exchange) — reference consumer, not target.** The exchange already consumes the hardened crate (certificate auth, transparency log, receipts, sealed dispatch) and serves as the reference implementation of a lys-trusted domain and the migration test for the extraction — but it is not the audience the API is shaped for.

## Non-goals

- **No authorization engine.** Policy, consent, and permission evaluation belong to the runtime and IdP. Lys certifies claims and proves conduct; it does not decide.
- **No storage traits in the core crate.** In-memory operations; persistence is the consumer's concern (the anchor service has its own storage).
- **No network in the core crate.** `lys-core` stays a pure library; transport lives in `lys-anchor`.
- **No zero-knowledge proofs in v1.** Salted-hash leaves + selective disclosure of individual entries with inclusion proofs deliver the "verify without revealing" property at a fraction of the complexity. ZK over policy compliance is a research direction, not a launch dependency.
- **No observability/analytics.** Lys is evidence, not dashboards.

## Open questions

1. **The ledger's trust model.** Own hosted SCITT-compatible service with standard receipts (the Sigstore playbook — leaning this way), pure self-host, or anchoring into third-party infrastructure? Likely all three shapes eventually; which ships first is a product decision.
2. **Key management and revocation.** Instance-CA key custody, rotation, compromise recovery, and the revocation story (deliberately consumer-side today — a real product needs a first-class answer). The one part of the original design (D2 revocation tracking) never built.
3. **Self-attestation honesty.** A signed log proves nobody tampered *after* signing, not that the runtime wrote the truth. The mitigations are anchoring frequency (bounds the window) and deterministic replay (re-derive the truth). This limit gets stated plainly in every audience-facing claim.
4. **Ecosystem posture.** Nono (Luke Hinds / Sigstore lineage) is the closest open-source architecture; EQTY Lab the closest commercial ambition. Receipt-level compatibility with the SCITT/Sigstore world may matter more than any feature. Decide early whether lys engages that community or builds parallel.
5. **Claim schemas.** The canonical vocabulary for agent sessions, actions, capabilities, and delegation chains — the thing that makes an agent transparency service *agent-native* rather than generic. This is the standards-shaped moat; design it in the open.

## Roadmap

The phase-by-phase plan, with proof points, lives in [ROADMAP.md](ROADMAP.md). In brief: Phase 0 (harden the primitives) is **done**; Phase 1 extracts them to `lys-core`; Phase 2 gives the `lys` CLI surface; Phase 3 — the payoff — is the Norn signing sink, producing signed, Merkle-rooted, replayable session logs; Phase 4 adds the `lys-anchor` transparency service; Phases 5–6 cover SCITT interop, agent claim schemas, haematite commit attestation, and agent-to-agent verified dispatch.

The Norn integration is the demo nobody else can give: an agent session that is signed, anchored, and — because the runtime is deterministic — re-runnable. Prove it on Norn first *because* we own the runtime; generalise to "anyone's agents via MCP" from a position of working evidence.
