# Lys — Roadmap

> This is the working plan: what gets built, in what order, and how each phase proves itself. It complements [VISION.md](VISION.md) (why) and [DESIGN.md](DESIGN.md) (architecture). Nothing here is cutting-edge — every primitive is well-understood. The value is execution and assembly, not invention.

## Guiding shape

Every phase produces something demonstrable, and later phases depend only on earlier ones. The library (`lys-core`) leads; surfaces (CLI, MCP, service) follow; the runtime integration is the payoff. We do **not** implement ahead of the plan or fan out an ultracode blitz — this is measured, reviewed, crypto-grade work.

## Phase 0 — Harden the primitives ✅ DONE

The source crate (`meridian-trust`) passed an adversarial security review and a full hardening pass: strict Ed25519 verification, certificate validity-window enforcement, externally-reconstructable Merkle roots, timestamp-authenticated attestations with domain separation, low-order-point rejection, seed zeroization, single-arbiter unsealing, frozen-wire-contract leaf docs. 137 tests, workspace green, adversarially re-verified. Landed on `meridian@main` (commit `f4bff9f1c`).

**lys inherits the crate only in its hardened form.** The findings and their fixes are recorded as design commitments in [DESIGN.md](DESIGN.md#hardening-baseline).

## Phase 1 — Extract to `lys-core`

Move the hardened crate into this repository as `lys-core`, cleaned of its Meridian lineage.

- Port the five modules (`keys`, `ca`, `merkle`, `attestation`, `seal`) plus `error` and the `hex_lower` helper, unchanged in behaviour.
- **Strip the legacy attestation fallback.** The dual-verify shim exists only so Meridian's already-persisted attestations keep verifying. lys v1 is domain-separated only — no legacy path, no caveat.
- **Rename the wire-format tags** `meridian-trust/*` → `lys/attestation/v1`, `lys/sealed-envelope/v1`. These strings are baked into every signature forever; the extraction is the last free moment to change them.
- Rename the custom-extension constant to a lys-owned OID arc; keep the placeholder PEN for now, with a note to register a real IANA Private Enterprise Number.
- Wire the pedantic lint set (already in the workspace `Cargo.toml`), pass `fmt` / `clippy -D warnings` / `test` clean.
- **Reserve the crates.io name** by publishing `lys` `0.0.1` (placeholder), then `lys-core` `0.0.1` once the port compiles.

**Proof:** `cargo test -p lys-core` green in the new repo; the crate builds standalone with zero Meridian dependencies.

## Phase 2 — `lys` CLI surface

The library gets a command-line face — the auditor's and operator's tool.

- `lys key` — generate / inspect identities (never prints private material).
- `lys ca issue` / `lys ca verify` — issue certs with capability-claim extensions; verify a chain against an issuer key at a given instant.
- `lys attest` / `lys verify` — sign and verify attestations over a file or stdin.
- `lys seal` / `lys open` — sealed-envelope transport.
- `lys log append` / `lys log prove` / `lys log verify` — transparency-log operations, including verifying an inclusion or consistency proof from **only** a published root + proof bytes (the third-party path).

**Proof:** a session log produced by one process is verified end-to-end by the CLI in another, with no access to the original tree.

## Phase 3 — Norn integration (the payoff)

Norn is the primary consumer (see [DESIGN.md](DESIGN.md#integration-norn-is-the-primary-consumer)). This is the demo nobody else can give.

- A signing `PersistenceSink` decorator: every session event flows through Norn's single append chokepoint, gets signed with the agent's key, and extends a per-session Merkle root. Zero core-loop changes.
- Certificate issuance at agent spawn; capability claims carried in the cert.
- `checkpoint()` becomes the anchoring hook (anchors land in phase 4).
- Because Norn agents run as deterministic Aion workflows, the signed log is not just tamper-evident but **re-runnable** — a stronger guarantee than any TEE attestation, in software alone.

**Proof:** a Norn session that is signed, Merkle-rooted, independently verifiable offline, and replayable.

## Phase 4 — `lys-anchor` (the notary)

The transparency-ledger service that makes history externally fixed.

- Instances submit log roots periodically; the service maintains its own append-only log of anchored roots and returns receipts.
- **SCITT-aligned** (RFC 9943/9942): COSE-signed statements, COSE receipts verifiable with standard tooling. Tile-backed storage (Tessera-compatible) is the target so the log can be served as static assets and externally witnessed.
- Privacy invariant: the service sees roots and signer identities, never contents.
- Optional counter-anchoring of the service's own root to public infrastructure (OpenTimestamps-style) for minimal-trust operation.

**Proof:** tampering with a session log between two anchor points is detected by the verifier.

## Phase 5 — Standards interop + agent claim schemas

- Canonical COSE/SCITT claim schemas for agent sessions, actions, capabilities, and delegation chains — the thing that makes this *agent-native* rather than a generic log. This is the standards-shaped moat; design it in the open.
- Confirm receipts verify with non-lys (standard SCITT) tooling.

## Phase 6 — Ecosystem reach

- Agent-to-agent verified dispatch: cert exchange over the MCP boundary, so a counterparty agent's capabilities and history are checkable before trust is extended.
- Haematite commit attestation: sign and anchor content-addressed database roots, giving haematite the commit-lineage integrity it structurally lacks.

## Open decisions (see DESIGN.md §Open questions)

1. Ledger trust model — hosted SCITT service (leaning), self-host, or third-party anchoring.
2. Key management, rotation, and revocation — needs a first-class answer for a product.
3. Self-attestation honesty — anchoring frequency + deterministic replay are the mitigations; stated plainly in every claim.
4. Ecosystem posture toward Nono (Sigstore lineage) and the SCITT community — interop over competition.

## How we build it

Tom wants to run this work through the Ablative agent stack — Norn as the runtime, Aion for durable orchestration — rather than (or alongside) the usual ultracode workflows. That is itself a proof point: the stack building the layer that makes the stack trustworthy. The coordination pattern is the same fan-out/gate/adversarial-review shape used for Phase 0, adapted to dispatch through Norn. Phases 1–2 are the natural first candidates: well-scoped, crypto-grade, and a clean test of the runtime on real infrastructure work.
