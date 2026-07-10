# lys-anchor — Phase 4 design strawman

> **STRAWMAN for the design session — nothing here is decided, ratified, or scheduled for building; the operator's gate (no anchor building before the session) stands.** This document exists to be shot at. Every section ends in a DECISION POINT; §8 consolidates them. Evidence base: a 2026-07 survey of the C2SP specs, Tessera, Rekor v2, RFC 9942/9943, SCRAPI, tuf-on-ci, and the signed-time landscape — load-bearing citations inline. Wire-format context: [WIRE-FORMATS.md](../WIRE-FORMATS.md) (D1–D6); roadmap context: [ROADMAP.md](../../ROADMAP.md) Phase 4.

The one rule governs here with full force: an anchor's entire value is that strangers can verify it. Everything below is composed from primitives lys already owns (Ed25519, SHA-256, RFC 6962, C2SP signed notes, COSE_Sign1) plus formats the transparency ecosystem has already converged on. Nothing on the trust path introduces a third-party dependency.

---

## 1. The hydra, formalized

**An anchor IS a lys instance.** `lys-anchor` is not a new kind of thing; it is a lys transparency log (the frozen raw-leaf path — WIRE-FORMATS §1) plus a write endpoint, whose leaves are:

- **(a) submitted checkpoints** — the full C2SP signed-note text of a client's checkpoint, bytes verbatim. This leaf is self-authenticating: it carries its own origin, size, root, and signature, so any auditor replaying the anchor's log can re-verify every leaf against the submitter's key without contacting anyone.
- **(b) the anchor's own operational events** — key rotations, verifier-key-manifest updates, cert issuance (§3) — as `lys/attestation/v2` COSE artifacts or DER certificates, bytes verbatim.

A pleasant property, to be pinned by test if we keep it: the three leaf kinds are byte-0 disjoint (a signed note begins with an ASCII origin line, a tagged COSE_Sign1 begins `0xD2`, a DER certificate begins `0x30`), so a leaf is classifiable without external metadata.

Because an anchor is a lys instance, it composes upward: a child anchor relates to its parent exactly as any lys client relates to an anchor. That recursion is the hydra. The research identified **two distinct upward edges with different guarantees** ([tlog-witness](https://github.com/C2SP/C2SP/blob/main/tlog-witness.md); RFC 9943 registration):

**Edge 1 — parent witnesses + cosigns the child (C2SP tlog-witness).** The child POSTs `add-checkpoint`: its previous size, an RFC 6962 consistency proof, and the new checkpoint. The parent verifies the signature against the child key it trusts for that origin, verifies the consistency proof against the last checkpoint it cosigned, persists the new checkpoint *before responding* (the spec's atomicity requirement — otherwise a rollback attack deletes verified leaves), and returns a [cosignature v1](https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md) note line the child folds into its published checkpoint. State: one checkpoint per child. Storage growth: none. Authentication: none needed — the checkpoint signature is the credential (the spec is explicit: "There is no authentication of requests beyond the validation of the signature on the checkpoint"). Guarantee: **continuous append-only-ness** — a forking or rewinding child is detected at the next heartbeat (409 on size mismatch, 422 on root mismatch).

**Edge 2 — child submits its checkpoint as a leaf to the parent's log (SCITT-style registration).** The parent's log grows by one leaf; the child receives an RFC 9942 receipt (§2). Guarantee: a **durable, ordered, independently provable record** that "child root R existed at parent-index N" — a portable artifact the child can hand to a stranger years later, even if the parent is gone.

These are not alternatives. Cosigning is the cheap real-time fork detector; leaf submission is the periodic durable notarization that yields the receipt Phase 4 promises. They compose cleanly: the parent cosigns every child checkpoint and periodically ingests one as a leaf.

**Two-level verification, end to end, for a stranger.** Alice holds one disputed session event and wants to know it happened and history wasn't rewritten. She needs: the leaf bytes, a `lys/log-inclusion-proof/v1` artifact (D2), the child's verifier key, the parent's verifier key, and the parent's receipt over the child checkpoint. Then, with no lys tooling required:

1. Leaf hash: `SHA-256(0x00 ‖ leaf-bytes)` — one line of shell (WIRE-FORMATS §1).
2. Run the RFC 6962 inclusion proof to the root in the embedded child checkpoint; verify the checkpoint's note signature against the child key (Go `sumdb/note`, Cloudflare `signed_note`, or 20 lines of Ed25519).
3. Verify the parent's cosignature line on that same checkpoint (freshness: "as of time T, the largest consistent tree I've seen for this origin has this root").
4. Take the child-checkpoint bytes as a leaf of the *parent's* log: verify the parent's RFC 9942 receipt with any COSE library (§2) — durable ordering.
5. If the parent is the root anchor, check its counter-anchor (§7) — the recursion terminates on public infrastructure, not on the parent trusting itself.

Every step uses a format with independent implementations. No step contacts the operator.

> **DECISION POINT 1 — the upward edge.**
> **Question:** which parent–child mechanism does the hydra standardize on?
> **Options:** (a) cosigning only — cheapest, real-time, but no durable receipt and the guarantee evaporates if the child's published checkpoint is lost; (b) leaf submission only — durable receipts, but fork detection is only as fine-grained as the submission cadence, and the parent's log grows per heartbeat if you tighten it; (c) both, composed — cosign every checkpoint, submit a leaf periodically (e.g. hourly/daily, plus on demand).
> **Recommendation: (c).** The two guarantees are different and both are wanted; the marginal cost of the second edge is small because the witness code is in scope anyway (every anchor is also a witness for its children), and (c) is the only option under which "receipt" and "near-real-time fork detection" are both true claims.

---

## 2. Receipts

D3 ratified the direction: RFC 9942 COSE receipts, at the anchor phase, additive alongside the D2 JSON artifacts, never replacing them. Proposed contents (confirmed against [draft-ietf-cose-merkle-tree-proofs](https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/), the published form of RFC 9942):

- **Form:** COSE_Sign1 `[protected, unprotected, payload, signature]`.
- **Protected header:** `1: -8` (EdDSA — the deployed-practice code point; see below), `395: 1` (`vds = RFC9162_SHA256` — the *same* RFC 6962 SHA-256 tree lys already speaks, so this is a re-encoding of identical semantics, not a new proof system; WIRE-FORMATS §3.4). Plus a content-type or issuer identifier for domain separation — byte-exact spec to be written and ratified per D3.
- **Unprotected header:** `396` (`vdp`), a map keyed by proof type: inclusion `-1`, CBOR `[tree-size, leaf-index, inclusion-path: [+bstr]]`; consistency `-2`, `[size-1, size-2, consistency-path]`.
- **Payload: detached (`nil`).** The signed statement is the anchor's Merkle root at `tree-size`; the verifier *recomputes* it from the leaf and the proof rather than reading it from the receipt. What the anchor's signature asserts, in words: "the leaf that hashes to this path's base was included at index N in my tree of size S, whose root I vouch for."
- **The leaf being proven** is the child's checkpoint bytes (§1 edge 2) — so verifying the receipt simultaneously verifies *which* child root was notarized, because the checkpoint is self-describing.

**Chaining upward.** A full provenance chain for a stranger is a bundle: `(leaf bytes, D2 inclusion proof + child checkpoint, parent receipt over child-checkpoint bytes, [grandparent receipt over parent-checkpoint bytes, …], root counter-anchor proof)`. Each link verifies independently with standard tooling; the bundle format itself (a JSON container carrying the artifacts verbatim, in the D2 self-contained-file spirit) is a new versioned artifact to specify — it contains frozen artifacts but is itself just packaging.

**Algorithm identifier, stated honestly.** [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html) deprecates polymorphic `-8` in favour of fully-specified `Ed25519 = -19`, but deployed tooling has not caught up — go-cose still implements only `-8` ([veraison/go-cose#224](https://github.com/veraison/go-cose/issues/224)). A receipt a stranger can't verify with an off-the-shelf library is worthless, so receipts issue under `-8` today, matching D4, with a documented migration trigger (go-cose and pycose shipping `-19`) and the WIRE-FORMATS note that `-19` is a v3 matter.

**Ecosystem honesty.** The SCITT service world is thinner than the RFC's polish suggests: [scitt.io/implementations](https://scitt.io/implementations.html) lists essentially one service (DataTrails, Preview, tracking [SCRAPI](https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/) draft 10); Microsoft's contribution is a [receipt profile](https://datatracker.ietf.org/doc/draft-ietf-scitt-receipts-ccf-profile/), not a public service. There is no interop corpus to conform against yet. That argues for shipping the receipt *format* (it's fully specified and the tree is one we already implement) while treating full SCRAPI API conformance as Phase 5.

**Day one vs later.** Day one: inclusion receipts (`-1`) over submitted checkpoints, plus the existing D2 JSON proofs served in parallel (an anchor that can't emit the artifact a 15-line script verifies has regressed). Later: consistency receipts (`-2`), SCRAPI surface, `-19` migration.

> **DECISION POINT 2 — receipt scope at launch.**
> **Question:** what does the anchor emit on day one?
> **Options:** (a) D2 JSON proofs only, defer COSE receipts until an interop corpus exists; (b) inclusion COSE receipts + D2 JSON in parallel; (c) full RFC 9942 (inclusion + consistency) + SCRAPI from the start.
> **Recommendation: (b).** D3 already ratified the direction and the format is a re-encoding of a tree we've conformance-tested; waiting (a) buys nothing since the RFC is final, while (c) front-loads API surface with no counterparty to interop against. Alg `-8`, detached payload, byte-exact spec ratified before anything durable is signed.

---

## 3. Cert-issuance transparency

The identity thesis (VISION: "issue a capability-scoped agent certificate, then prove the agent's logged actions stayed within those capabilities") gets its CT moment here: **certificate issuance is itself an anchored event from day one.** This is the same move Certificate Transparency made when trusting CAs stopped being enough — the anchor's CA (and any registered instance CA) cannot issue quietly.

**Leaf schema sketch.** The CT-shaped default: the leaf is the issued certificate's **DER bytes verbatim** on the raw-leaf path — `SHA-256(0x00 ‖ cert-DER)`. No new format to freeze; any x509 tooling reads the leaf; the leaf hash doubles as a cert fingerprint convention. For deployments whose capability claims are sensitive at the metadata level, the alternative is a versioned CBOR issuance record `{format, SHA-256(cert DER), issuer key, subject key, salted-hash(claims), unix-ms}` — the salted-hash-leaves pattern DESIGN.md §5 already names. Both can coexist (they're different leaf *contents*, not different tree encodings), but the default should be the transparent one: an issuance log of hashes only is a CT log that can't be monitored.

**What "who is this agent?" looks like.** At issuance, the CA logs the cert and hands the agent its inclusion proof alongside the cert — the SCT analogy: the agent carries proof its birth certificate is on the public record. A counterparty verifying an agent then checks: (1) cert chain to the operator's CA (existing `lys ca verify`); (2) inclusion proof of the cert leaf against an anchored, witnessed checkpoint; (3) optionally, the anchor log for *other* certs under the same CA key — the monitor's question, "what else has this operator's key issued?" Honesty about lookups: tile logs are static assets with no query API; deployed CT answers "look up by identity" with monitors (crt.sh), not the log itself. Day one, the issuing CA retains leaf indices and serves proofs; third-party monitoring is an ecosystem role the tile format deliberately makes cheap, not an anchor endpoint.

> **DECISION POINT 3 — issuance-leaf format and default posture.**
> **Question:** what do issuance leaves contain, and is issuance logging on by default?
> **Options:** (a) DER cert verbatim, mandatory for the anchor's own CA, opt-in for instance CAs; (b) salted-hash CBOR record everywhere — maximal privacy, but the log degrades to "something was issued" and can't be monitored; (c) both defined day one — DER default, salted-hash record as the documented sensitive-claims escape hatch.
> **Recommendation: (c), with (a)'s mandatory-for-the-anchor's-own-CA rule.** The anchor must hold itself to the standard it offers others; instance CAs choose their disclosure level, but the choice is itself visible (the leaf kind is distinguishable).

---

## 4. Key lifecycle

**The anchor's own keys.** Distinct roles, distinct keys — note-signing (checkpoints), receipt-signing (COSE), cosigning (witness role; note its key-ID type byte is `0x04`, not `0x01` — [tlog-cosignature](https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md) vs [signed-note](https://github.com/C2SP/C2SP/blob/main/signed-note.md)) — so one compromise doesn't burn every artifact class. Online keys live in KMS/HSM for the hosted product, file-backed `Ed25519Identity` for the smallest self-host (§6).

**Root of trust, sized for a small honest team.** The reference ceremony is [tuf-on-ci / Sigstore root-signing](https://github.com/sigstore/root-signing): signing events are GitHub PRs, keyholders sign with hardware/KMS keys, CI drives staged publication — no air-gapped bunker. The TUF minimum-ceremony numbers ([TUF docs](https://theupdateframework.io/docs/metadata/), [Rugged guidance](https://rugged.works/background/ceremonies/key-rotation/)): **3–5 offline root keys, threshold 2, never a single key, rotate ~annually** — the rotation doubling as the drill that proves the team still knows where the keys are. The root keys sign one small artifact: a **verifier-key manifest** (the anchor's origin, current note/receipt/cosign public keys in the note verifier-key text form of WIRE-FORMATS §2.2.5, validity window). Expiration dates on the manifest mean stale trust is rejected automatically. The manifest is itself logged as an operational-event leaf (§1b) — rotations are on the record.

**Log-key rotation without a flag day.** The note format was designed for this ([tlog-checkpoint](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md): checkpoints MAY carry multiple signatures; verifiers ignore unknown keys, rejecting only when a *known* key fails): an **overlap window** where every checkpoint is signed by both outgoing and incoming keys, relying parties update their key list, then the old key retires. The coarser alternative deployed practice also uses: shard the log — Rekor v2 and static-CT temporally shard roughly every 6 months ([Rekor v2 GA](https://blog.sigstore.dev/rekor-v2-ga/)), which bounds log size and rolls keys as a side effect.

**No CRL/OCSP — deliberately.** The CRL/OCSP graveyard is where PKI for long-lived certs goes to die; the modern answer (Fulcio/SPIFFE lineage) is **short-lived credentials + a transparency log**. That is exactly the lys shape:

- **Agent certs are short-lived** (minutes-to-days, set by the operator at spawn). Revocation is mostly moot: a compromised agent cert expires before any revocation signal could propagate, and the issuance log (§3) is the permanent record of what existed and when. What "revoking an agent" actually means is: stop re-issuing.
- **The residual story is operator/CA keys** — the long-lived ones. Recovery is **rotate-and-re-anchor**: issue the successor key, log the rotation event (a signed statement naming old key, new key, and effective instant), re-issue live agent certs under it, and let verifiers use the log to answer "was this cert issued while its CA key was considered good?" — the transparency log is the audit record of which key was live when, which is more than a CRL ever honestly delivered.
- **Client key custody guidance** (docs, not mechanism): operator CA keys offline or in KMS, never on the box that runs agents; agent keys are ephemeral session material, `Zeroizing` end to end (already the lys-core discipline).

> **DECISION POINT 4 — ceremony weight and rotation mechanism.**
> **Question:** how heavy is the anchor's root-of-trust ceremony, and how do log keys rotate?
> **Options:** (a) no offline root — the online note key is the root of trust (honest for a hobbyist self-host, unacceptable for the hosted product); (b) 2-of-3 offline root keys signing an expiring verifier-key manifest, tuf-on-ci-style PR ceremony, annual rotation drill; log keys rotate via the multi-signature overlap window; (c) full TUF repository with delegations, plus 6-month log sharding.
> **Recommendation: (b) for the hosted anchor, with (a) explicitly documented as the self-host floor.** (c) is ceremony beyond what a small honest team will actually execute, and an unexecuted ceremony is worse than a modest one performed on schedule. Sharding stays available as an operational tool, not a mandate.

---

## 5. Signed time

D1 already took the position: no timestamp line in the checkpoint; signed time over a root is **an attestation over the checkpoint bytes** — a composition of two frozen artifacts, not a format change (WIRE-FORMATS §2.1). The evidence pack's survey confirms that as the right default:

| Option | Trust & cost | Role |
|---|---|---|
| **lys attestation over checkpoint bytes** (WIRE-FORMATS §2.1/§4.2) | No new dependency, self-hostable, reuses a frozen format. Time is **self-attested** — as trustworthy as the anchor's clock and key, stated plainly. | **Primary.** |
| Self-run TSA — [sigstore/timestamp-authority](https://github.com/sigstore/timestamp-authority) (RFC 3161/5816, KMS-backed keys, NTP-drift monitored) | Hostable, matches the no-third-party ruling; still self-attested time, now with RFC 3161 interop. | **Reserve**, if external parties demand RFC 3161 receipts. |
| Public TSAs — free ([FreeTSA](https://www.freetsa.org/index_en.php), [rfc3161.ai.moda](https://gist.github.com/Manouchehri/fd754e402d98430243455713efada710)) or commercial (DigiCert, Sectigo) | Zero-ops but a third-party trust dependency — violates the never-third-party-dependent ruling if load-bearing. | Corroboration only, never load-bearing. |
| [Roughtime](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/) (draft-19, Experimental; Cloudflare endpoint) | Not an RFC, sparse tooling, ~1 s granularity. | Sanity oracle at most. Not a receipt primitive. |
| [OpenTimestamps](https://opentimestamps.org/) | Trustless (verification rests on Bitcoin PoW alone), free, coarse (hours), eventually consistent. | The **counter-anchor** for the root of the hydra (§7) — not a per-checkpoint timestamp. |

The honest statement that accompanies the primary: within the hydra, "when" is attested by the anchor itself, cross-checked by witness cosignatures (each cosignature carries the witness's own `time` assertion — a free second clock from every witness), and bounded below by the counter-anchor. Nobody is told a timestamp is more than it is.

> **DECISION POINT 5 — signed time.**
> **Question:** what carries "when" in anchor artifacts?
> **Options:** (a) attestation-over-checkpoint as the only mechanism, witness cosignature times as corroboration; (b) also stand up a self-run RFC 3161 TSA day one; (c) lean on a public TSA.
> **Recommendation: (a), with (b) held in reserve** behind a documented trigger (a concrete external-interop demand for RFC 3161). (c) is ruled out as load-bearing by the operator's existing no-third-party ruling.

---

## 6. Operational shape

**Read path: static assets, no application server.** The log is served as [tlog-tiles](https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md) — the format CT (Sunlight/static-ct), Rekor v2, and Tessera all converged on. Tessera's cloud backends demonstrate the economics: data is written to object storage and "served directly by the cloud provider" ([tessera](https://github.com/transparency-dev/tessera)); its POSIX backend writes the exact tile files, servable by any HTTP file server — the self-host story. The static-asset thesis ([You Should Run a CT Log](https://words.filippo.io/run-sunlight/), Cloudflare's [Azul](https://blog.cloudflare.com/azul-certificate-transparency-log/)) is what makes "we host AND others self-host" economically real. One honesty note on the word "Tessera-compatible": Tessera is Go, and lys is pure Rust by policy — **the tile *format* is the contract, not the library.** The write path is our Rust implementation (Cloudflare's `tlog_tiles` crate exists but is young at 0.2.0; the backing-agnostic wrapper posture in DESIGN.md §Primitive-decisions anticipated exactly this replacement).

**Write path: two small endpoints, per the two edges of §1.**
- `POST <prefix>/add-checkpoint` — the C2SP witness endpoint, implemented to spec (specific error semantics: 404 unknown origin, 403 untrusted signature, 409 size mismatch returning the witness's latest size, 422 bad proof; persist-before-respond).
- `POST /v1/submit` — leaf submission (a checkpoint to notarize; an issuance cert per §3), returning the receipt (§2). Rekor v2's single-endpoint shape ([GA post](https://blog.sigstore.dev/rekor-v2-ga/)) with in-memory batching as the throughput mechanism.

**Auth/spam model.** The deployed options: cert-gated cryptographic eligibility (CT: "logs must refuse certificates without a valid chain to a known root" — [Chrome CT policy](https://googlechrome.github.io/CertificateTransparency/log_policy.html)); pool-size rate limiting ([Sunlight](https://github.com/FiloSottile/sunlight): at most poolsize/period submissions); self-authenticating requests (tlog-witness: no API keys, the checkpoint signature is the credential); or generic API keys. The clean lys analogue of CT's gate: **accept a submission only if its note signature verifies against a key holding a lys certificate chaining to a CA the anchor recognizes** (or an allowlisted child-anchor key). Self-authenticating, no API-key infrastructure, privacy-neutral by construction (the anchor sees a signer identity and 32 bytes of root, never contents — the Phase 4 privacy invariant), and it is literally RFC 9943 registration-policy semantics ("MUST check the attributes required by a Registration Policy are present"). Sunlight-style pool-size limits and Tessera-style best-effort dedup sit behind it as backpressure, not as trust mechanisms.

**Packaging.** Hosted: object storage + CDN reads, KMS keys, the §4(b) ceremony. Self-host: a single `lys-anchor` binary over a POSIX directory. NAT'd self-hosters expose their witness role through an [https-bastion](https://github.com/C2SP/C2SP/blob/main/https-bastion.md) reverse tunnel (witness dials out over TLS 1.3 with an Ed25519 client cert; reachable at `https://<bastion>/<sha256(witness-pubkey)>/…`).

**The smallest honest deployment**, spelled out because it is the credibility test: one binary, one POSIX directory of tiles behind nginx/caddy, one file-backed identity, a checkpoint cadence, at least one *external* witness cosigning (another lys anchor — see §7), and a periodic counter-anchor. That is a complete anchor: submission gate, static verifiable log, receipts, upward edge. If that isn't cheap to run, the federation story is fiction.

> **DECISION POINT 6 — write-path gate and day-one backend.**
> **Question:** what admits a submission, and what storage ships first?
> **Options (gate):** (a) cert-gated as above; (b) open + rate-limited; (c) API keys. **Options (backend):** (x) POSIX tiles first, object storage second; (y) object storage first.
> **Recommendation: (a) + (x).** (a) is the only gate that is simultaneously spam-resistant, key-less, and privacy-preserving — and it makes the anchor *consume* lys identity, closing the product loop. POSIX-first keeps the self-host and hosted paths byte-identical (same tiles), with object storage as a deployment detail rather than a fork.

---

## 7. Out of scope / later

Named now so their absence reads as sequencing, not oversight:

- **Public witness-network participation.** The ecosystem is green: the public network is ~15 [Armored Witness](https://github.com/transparency-dev/armored-witness) devices ([Can I Get A Witness](https://blog.transparency.dev/can-i-get-a-witness-network)), and Rekor v2 shipped GA with witnessing off ("we wait for the launch of a public witness network" — [GA post](https://blog.sigstore.dev/rekor-v2-ga/)). So "externally witnessed" by *that* network is aspirational in mid-2026. The strategic bet, stated plainly: a recursive federation where **every lys anchor is also a witness for its children** grows the witness diversity the ecosystem lacks instead of waiting on it. Registering lys anchors into the public network is a later, additive step.
- **Counter-anchoring the root to public infrastructure.** [OpenTimestamps](https://opentimestamps.org/) is the honest terminator for the top of the hydra — the root anchor's self-attestation bottoms out on Bitcoin proof-of-work rather than on trusting itself, with no institutional dependency. Coarse (hours) and eventually consistent, which is fine for a terminator and wrong for a heartbeat. The *mechanism* is trivial (stamp the checkpoint bytes); the design cost is deciding cadence and how the OTS proof rides in the verification bundle (§2). Lean: design the bundle slot day one, ship the cron as a fast-follow.
- **Post-quantum.** The cosignature spec already admits ML-DSA-44, but Ed25519 + SHA-256 is the frozen lys lineup and the interop world's floor. PQ is a tracked v2/v3 wire matter (new versioned artifacts, per the wire-formats-are-forever rule), not a Phase 4 deliverable.
- **SCRAPI conformance and claim schemas** — Phase 5, as roadmapped.

> **DECISION POINT 7 — the deferral list.**
> **Question:** does the operator ratify these four as consciously deferred, and the counter-anchor as designed-for-day-one / shipped-as-fast-follow?
> **Recommendation: yes as written.** The one I'd resist deferring further is the counter-anchor bundle slot: retrofitting a slot into a ratified bundle format is a v2, so the *format* accommodation is cheap now and expensive later.

---

## 8. Open questions for Tom — consolidated decision points

The session's ammunition, numbered, each with my lean. Everything here is shootable.

1. **Upward edge (DP1).** Cosign-only, leaf-submit-only, or both composed? **Lean: both** — cosign every child checkpoint (real-time fork detection), periodic leaf submission for the durable receipt. They answer different questions; Phase 4's promises need both.
2. **Receipt launch scope (DP2).** **Lean: inclusion COSE receipts (alg `-8`, `vds=1`, detached payload) + D2 JSON proofs in parallel**; consistency receipts and SCRAPI later; `-19` behind a documented tooling trigger. Byte-exact receipt spec written and ratified before anything durable is signed — D3's own condition.
3. **Verification bundle.** A new versioned container carrying leaf + proof + checkpoints + receipt chain + counter-anchor proof verbatim. **Lean: specify it in this design round** — it's the artifact a stranger actually receives, and it needs the counter-anchor slot from day one (DP7).
4. **Issuance transparency (DP3).** **Lean: DER-verbatim cert leaves, mandatory for the anchor's own CA; salted-hash CBOR record defined as the sensitive-claims opt-out for instance CAs.** The anchor holds itself to the standard it sells.
5. **"Who is this agent" lookup.** Tile logs don't do queries; CT solved this with monitors. **Lean: issuing CA hands the agent its inclusion proof at issuance (SCT analogy); no lookup endpoint on the anchor; monitoring is an ecosystem role the tile format keeps cheap.** Worth an explicit yes/no since it shapes product expectations.
6. **Ceremony weight (DP4).** **Lean: 2-of-3 offline root signing an expiring verifier-key manifest, tuf-on-ci-style PR ceremony, annual rotation-as-drill** for the hosted anchor; single-key floor documented for self-host; log-key rotation via the multi-signature overlap window; no CRL/OCSP — rotate-and-re-anchor, with the log as the record of which key was live when.
7. **Agent revocation posture.** **Lean: ratify "short-lived agent certs + issuance transparency" as the revocation story**, with the residual mechanism (CA-key rotation events as logged, signed statements) specified in this design round. This closes DESIGN.md open question 2.
8. **Signed time (DP5).** **Lean: attestation-over-checkpoint-bytes as primary** (already D1's direction), witness-cosignature times as free corroboration, self-run sigstore TSA in reserve behind a concrete interop trigger, public TSAs and Roughtime never load-bearing.
9. **Write-path gate (DP6a).** **Lean: cert-gated self-authenticating submission** — a checkpoint gets in iff its note signature chains to a lys-recognized CA or an allowlisted child-anchor key. No API keys. Doubles as the RFC 9943 registration policy.
10. **Storage day one (DP6b).** **Lean: POSIX tlog-tiles first**, object storage as a deployment variant of the same bytes; Rust tile writer (format is the contract — Tessera is the shape, not a dependency; Go is off the table by the pure-Rust rule).
11. **Deferrals (DP7).** **Lean: ratify** — public witness network participation, PQ, SCRAPI to later phases; OpenTimestamps counter-anchor designed-for now (bundle slot), cron as fast-follow.
12. **Origin naming.** Anchors need an origin-naming convention (D1 made `--origin` mandatory precisely because collisions are a security defect). **Lean: schema-less URL under a domain the operator controls, e.g. `anchor.lys.dev/prod-01`; child anchors under their own domains** — the note ecosystem's convention, nothing invented.
