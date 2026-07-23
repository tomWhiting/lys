# lys — Repository Review

**Date:** 2026-07-23
**Scope:** full repository — architecture, code quality, correctness, and drift between design docs and implementation.
**Method:** six parallel review dimensions (identity/CA, attestation, seal, merkle/tlog/checkpoint, CLI + coding standards, docs drift), each finding adversarially verified by an independent pass before inclusion; direct hand-verification of every doc-drift claim and all gate results. One finding was refuted during verification and is recorded at the bottom for transparency.

---

## Verdict

**The cryptographic core is sound. No exploitable defect, forgery path, malleability, oracle, or verification bypass was found in any module.** The hardening baseline (H1–H3, M1–M6) is implemented and — with two narrow exceptions noted below — pinned by genuinely adversarial tests. The implementation matches the ratified wire contracts in WIRE-FORMATS.md byte-for-byte.

The real issues are operational and documentary: **the repo currently fails its own clippy gate on Rust 1.95**, and the older design documents (docs/DESIGN.md, docs/design/lys-core/DESIGN.md, CHECKLIST.md) have drifted materially behind the shipped code — including one byte-level error that would mislead an independent implementer.

**Gates as of this review:** `cargo fmt --check` ✅ clean · `cargo clippy --all-targets -- -D warnings` ❌ **fails** (see F1) · `cargo test --workspace` ✅ 295 passed, 0 failed, 0 ignored.

---

## Strengths (verified, not just claimed)

- **Attestation (`lys/attestation/v2`)** — the canonical-strictness gate is byte-complete: `from_cose_bytes` re-encodes all parsed fields and requires byte-identity with the full input, so every malleation class (non-shortest heads, reordered/duplicate keys, indefinite lengths, tag stripping, unprotected-header smuggling, trailing garbage) is rejected by construction. The `kid` is signature-covered and verification rebuilds the `Sig_structure` from the artifact's own fields with `verify_strict`. Timestamp handling is correct across the full `i64` range. The go-cose conformance suite pins the strictness delta where lys rejects artifacts vanilla COSE accepts.
- **Merkle / tlog / checkpoint** — the verification engine never trusts an artifact-declared value: roots are reconstructed exclusively from the signature-verified embedded checkpoint, declared sizes are checked against signed sizes, the 2^53 guard is enforced on both emit and verify, and every failure collapses to a single non-oracle error. Builders self-verify through the third-party path before returning. The signed-note layer mirrors Go `note.Open` faithfully (last-`\n\n` split, first-matching-candidate semantics, 100-line/1 MiB caps, U+2014 prefix, key-ID formula). Reviewers attempted forged proofs, index off-by-ones, direction confusion, and origin substitution — all closed.
- **Seal** — nonce is derived from the same HKDF expansion as the key (fresh ephemeral ⇒ fresh nonce), the HKDF info binds the domain tag and both public keys, low-order points are rejected on both seal and open (tested with the all-zero and order-8 points), AES-GCM is the single failure arbiter, and the authenticated composition covers every wire byte behind a versioned context tag with verification gated before decryption. M3/M5 hold.
- **Identity / CA** — H1 and H2 are pinned by real attack-construction tests: both `identity_tests.rs` and `authority_tests.rs` build the concrete small-order forgery (R = basepoint, s = 1), prove dalek's non-strict `verify` accepts it, then prove lys rejects it. Debug redaction is manual and tested on both `Ed25519Identity` and `IssuedCertificate`. The `RemoteKeyPair` adapter keeps the CA seed off rcgen's serialization path; chain verification recovers TBS bytes and verifies with dalek strict rather than x509-parser. The `load_or_generate` no-clobber race design is pinned by an 8-thread race test.
- **CLI** — genuinely thin (cli.rs is pure clap; logic in lys-core). Non-oracle failure messages are tested. Key-consuming commands are load-only; `log init` refuses re-init; the log store uses O_EXCL leaf writes and atomic tmp+rename state, with full rebuild + tamper/gap/root checks on every open — there is no path to a wrong-but-signed checkpoint from store corruption. `lys log verify` takes only artifact + leaf + verifier key.
- **Conformance discipline** — round-trips against three independent implementations (Go `sumdb/note`, `veraison/go-cose`, Cloudflare `signed_note`), with CI's `LYS_REQUIRE_GO=1` turning developer-machine skips into hard failures. cargo-deny runs on every change.
- **Standards compliance** — zero `unwrap`/`expect`/`panic`/`todo`/`unreachable` outside test modules in both crates; no `#[ignore]`; no `anyhow` in the library; no file over 500 lines of code; `mod.rs` files are declarations only; README worked examples were re-verified command-by-command against the CLI and match exactly, including the two verbatim non-oracle error strings and the 191–199-byte artifact window.

---

## Findings

All findings below survived adversarial verification. None is critical or high.

### F1 · Clippy gate fails on Rust 1.95 — the repo cannot pass its own commit gate *(medium, tooling)*

`cargo clippy --all-targets -- -D warnings` fails with 4 × the new 1.95 lint `decimal_bitwise_operands` in `crates/lys-core/src/attestation/encoding.rs:83` and `:86` (`major_bits | 26`, `major_bits | 27`, plus two more). CLAUDE.md's "gates before any commit" rule is currently unsatisfiable on an up-to-date stable toolchain, and `.github/workflows/ci.yml` uses unpinned `dtolnay/rust-toolchain@stable`, so CI fails the same way. Fix is mechanical (hex literals); alternatively pin the toolchain — but per the project's own rules, `#[allow]` would be a bypass, not a fix.

### F2 · HKDF info tag documented with a slash, coded with a hyphen *(medium, docs-drift on a frozen contract value)*

`docs/design/lys-core/DESIGN.md:95` and `CHECKLIST.md:66` (C45) state the sealed-envelope HKDF info tag as `lys/sealed-envelope/v1`. The actual constant is `lys-sealed-envelope/v1` (`sealed_envelope.rs:57`). The docs conflate it with the separate attestation context tag `SEALED_ENVELOPE_CONTEXT_V1` (which genuinely is the slash form, `authenticated.rs:50`). The authoritative WIRE-FORMATS.md §1 is correct; the code matches the ratified contract. But an independent implementer working from lys-core/DESIGN.md would derive the wrong key and produce undecryptable envelopes — the worst kind of doc error for a project whose product is independent implementability.

### F3 · `checkpoint/` and `tlog/` modules absent from every architecture doc *(medium, docs-drift)*

`lib.rs` declares eight modules including `checkpoint` and `tlog` — which carry the whole of README Example 1 (C2SP checkpoints, JSON proof artifacts). But docs/DESIGN.md §2 describes the log layer as `lys-core::merkle` only; lys-core/DESIGN.md's structure diagram omits both directories; CHECKLIST.md C3 lists six modules; root CLAUDE.md lists five. A large fraction of shipped, ratified functionality is invisible in the architecture documentation.

### F4 · lys-core/DESIGN.md D8 + CHECKLIST C58/C59 describe the pre-ratification log-verify interface *(medium, docs-drift)*

They spec `lys log verify` as taking "only a published root (bytes + leaf count) and proof bytes." The shipped, D1/D2-ratified interface takes a self-contained JSON `--artifact`, `--verifier-key`, and `--leaf`. C38–C43 were annotated as amended by D4, but C58/C59 were never annotated as superseded by D1/D2, so the stale interface reads as current spec.

### F5 · DESIGN.md architecture layer 6 (`lys-verify`) contradicts the shipped CLI; header status stale *(medium, docs-drift)*

docs/DESIGN.md:44 lists "Verification (`lys-verify` — new, CLI + library)" as a planned crate, but verification shipped inside the `lys` binary in Phase 2 (`lys verify`, `lys ca verify`, `lys log verify`), which ROADMAP marks DONE — and DESIGN.md's own roadmap summary (line 111) agrees. The doc's header also still reads "Status: pre-extraction" although extraction is complete. The whole document needs a post-Phase-2 revision pass (subsumes F3 for this file).

### F6 · Frozen JSON envelope shape only partially pinned by tests *(low, test-gap)*

WIRE-FORMATS.md freezes `lys/sealed-envelope/v1` as "JSON (serde shape of `SealedEnvelope`)". The `ciphertext` field name and encoding are pinned incidentally (`cli_tests.rs:1173` indexes `envelope["ciphertext"][0]` on a real CLI-written envelope), but `ephemeral_public_key` and `nonce` are unguarded — a stray `#[serde(rename)]` would silently break every historical envelope with all tests green. The postcard round-trip test in `sealed_envelope.rs:426` cannot catch renames (positional format). A single JSON snapshot test pinning all three field names/encodings would close this.

### F7 · `lys open` writes recovered plaintext into a pre-existing file keeping its old permissions *(low, hardening)*

`write_file_private` (`files.rs:37`) sets mode 0600 only at creation; a pre-existing output file is truncated and receives decrypted plaintext while keeping its prior (possibly world-readable) permissions. lys-core's own key-write path force-tightens with `set_permissions(0600)` (`identity.rs:394`); the plaintext path has no equivalent, and the inline comment at `seal.rs:164–165` overstates the guarantee as unconditional. The behavior is documented as intentional at `files.rs:34–36`, but its "matches lys-core" justification points at the load/warn path rather than the true analog (the force-tightening write path).

### F8 · Derived X25519 secret scalar not zeroized — narrow M4 gap *(low, crypto hygiene)*

`identity.rs:115` passes `self.signing_key.to_scalar_bytes()` (the raw X25519 private scalar, SHA-512(seed)[..32]) by value into `StaticSecret::from`; the bare `[u8; 32]` temporary is dropped un-wiped, unlike every other seed buffer in the file. Also notable: M4 ("Zeroizing on all seed material") is the one hardening claim with no pinning test, so it rests entirely on this structural discipline.

### F9 · Doc attributes clamping to `to_scalar_bytes`, which returns the *unclamped* scalar *(low, docs-drift)*

`identity.rs:110–111` describes the derivation as "the standard Ed25519-to-X25519 clamped-scalar conversion (`to_scalar_bytes`)". dalek's `to_scalar_bytes` explicitly returns an unreduced, unclamped scalar; clamping happens downstream in x25519-dalek at public-key/DH time. The end-to-end conversion is correct and tested; the attribution is wrong.

### F10 · `decode_extension` returns unauthenticated capability payloads with no rustdoc warning *(low, api-design)*

`extensions.rs:55` parses and returns the capability-claim payload with no signature or issuer check, and the extension is non-critical. The payload is only trustworthy after `verify_certificate_chain`, but the rustdoc (`extensions.rs:43–54`) never says so — a real footgun given DESIGN.md's "the cert *is* the permission object" framing.

### F11 · notBefore boundary inclusivity unpinned by any test *(low, test-gap)*

`check_validity_window` treats both boundaries as inclusive, but `validity_boundaries_are_inclusive` (`authority_tests.rs:174`) exercises only the notAfter edge; the notBefore test uses a coarse −2 h instant. A regression flipping notBefore to exclusive would pass the suite.

### F12 · Inline test modules deviate from the sibling `*_tests.rs` convention *(low, standards)*

CLAUDE.md mandates tests in sibling `*_tests.rs` files. Most modules comply via `#[path]`, but `merkle/leaf.rs`, `seal/sealed_envelope.rs`, `seal/authenticated.rs`, `error.rs`, and six CLI files (`files.rs`, `ca.rs`, `pem.rs`, `error.rs`, `hex.rs`, `log/store.rs`) define tests inline. No correctness impact; pure convention drift.

### F13 · CHECKLIST.md never reconciled — all 65 items unchecked despite Phases 1–2 DONE *(low, docs-drift)*

Every item C1–C65 remains `[ ]` while ROADMAP marks both phases complete and the corresponding code exists. Combined with F4's superseded items, the checklist can no longer be relied on as a status record. Related staleness: the lys-core/DESIGN.md structure diagram shows `commands/log.rs` (actual: a `log/` directory of six files plus a separate `cli.rs`) and the D8 subcommand list omits `lys log init` and `lys log checkpoint`.

---

## Refuted during verification (recorded for transparency)

- **"files.rs doc misstates lys-core key-file permission behavior"** — refuted. lys-core's handling of *existing* key files is exactly warn-don't-tighten (`warn_if_loose_permissions`, `identity.rs:249–255`); the force-tighten at `identity.rs:394` applies only to files lys-core itself is writing. The doc's cited precedent is accurate.
- The original form of F6 claimed "zero regression protection" for the JSON envelope shape; verification found the `ciphertext` field is in fact pinned by `cli_tests.rs`, and the finding was narrowed accordingly.

---

## Recommendations, in order

1. **Fix F1 now** (hex literals in `encoding.rs`) — the commit gate and CI are red on current stable; nothing else can land cleanly until this does. Consider pinning the CI toolchain version so new lints arrive on your schedule, not stable's.
2. **Fix F2 in the two design docs** — it is a one-character error that defeats independent implementation, which is the project's entire value proposition.
3. **Run a post-Phase-2 revision pass over docs/DESIGN.md, lys-core/DESIGN.md, and CHECKLIST.md** (F3, F4, F5, F13): add `checkpoint`/`tlog` to the architecture, mark superseded checklist items the way C38–C43 already are, update the header status, and either commit to `lys-verify` as future scope or fold it into the CLI story. WIRE-FORMATS.md needs nothing — it is accurate throughout and is the model the others should follow.
4. **Add the small tests**: a JSON snapshot for `SealedEnvelope` (F6) and a notBefore-boundary case (F11). Both are minutes of work protecting frozen-contract and hardening claims.
5. F7–F10, F12 at leisure — none is urgent.

---

*Review conducted by Claude (Fable 5) with Opus subagent reviewers; every included finding was independently re-verified against the code, and severity reflects the verified — not the claimed — impact.*
