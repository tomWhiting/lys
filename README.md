# lys

**Cryptographic trust infrastructure for AI agents.** Identity, tamper-evident history, and verifiable provenance — the accountability layer that lets an agent prove its work to someone who has no reason to trust it.

*Lys* is Danish and Norwegian for **light**.

## The one rule

This is trust infrastructure. Its entire value is that **strangers can verify it** — without lys, without the operator's cooperation, and without trusting the vendor. Every design decision serves that, which is why every primitive is deliberately boring:

- **SHA-256** for every hash.
- **Ed25519** for every signature.
- **RFC 6962** Merkle trees for tamper-evident logs, with roots published as [C2SP checkpoints](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md) in signed-note envelopes — the same artifact Tessera, Rekor v2, and the transparency-log witness network speak.
- **COSE_Sign1 (RFC 9052)** for attestations — verifiable with any off-the-shelf COSE library.
- **X.509** for capability certificates, **X25519 + HKDF-SHA256 + AES-256-GCM** for sealed transport.

A receipt nobody can verify with standard tooling is worthless. Verification must outlive the vendor.

## What exists today

- **Identity** — Ed25519 keypairs; each doubles as a signed-note verifier key and derives an X25519 key for sealed transport.
- **Capability certificates** — Ed25519-signed X.509 certificates with JSON capability claims embedded as an extension: identity and permission as one presentable object.
- **Attestations** — compact (under 200 bytes) COSE_Sign1 statements binding a signer to a payload hash and timestamp, with canonical-encoding-strict verification.
- **Sealed transport** — authenticated envelopes so a credential travels to exactly one recipient, from a provable sender, without the infrastructure in between being able to read it.
- **Transparency logs** — RFC 6962 append-only Merkle logs over raw file bytes, C2SP signed-note checkpoints, and self-contained inclusion/consistency proof artifacts a third party verifies offline.

All of it is a library (`lys-core`, domain-agnostic — no concept of agents anywhere in it) plus a thin CLI (`lys`).

**Maturity:** pre-1.0. The wire formats above are implemented and conformance-tested against independent implementations (Go `sumdb/note`, `veraison/go-cose`, Cloudflare's `signed_note`), and they **freeze at 0.1.0** — from then on, evolving a format means a new version alongside, never a mutation of the shipped one. Until 0.1.0, treat formats as settling. See [docs/design/WIRE-FORMATS.md](docs/design/WIRE-FORMATS.md) for the byte-exact contracts and the decision log.

## Install

```console
$ cargo install lys        # the CLI
$ cargo add lys-core       # the library
```

## Example 1 — a tamper-evident audit log for anything

Nothing about lys is agent-specific. Here is a build pipeline that keeps a tamper-evident record of release events, then hands an auditor proof that a specific event happened — without giving the auditor the log, the other events, or anything to trust but a public key.

**On the CI machine** — one signing key, one log, pinned to an origin:

```console
$ lys key generate --out ci-signing.key
generated new identity key: ci-signing.key
public key (ed25519): d551ce5e413c930d65ff105bbd74a9a991bcb56c28e20159b8e65e9168260cfb

$ lys log init --dir release-log --origin ci.example.com/releases
initialized log directory: release-log
origin: ci.example.com/releases
tree size: 0
root hash (sha256): e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

(Key-dependent values — public keys, hashes, signatures, timestamps — will differ in your run. Shapes won't.)

Append events as they happen. A leaf is any file; its raw bytes are what get logged. Appending needs no key:

```console
$ lys log append --dir release-log --leaf event-001.json
leaf index: 0
leaf hash (sha256, rfc6962): 8bc2d611b16ca56b984594b3a077735a86521f879501ba4431ba9d9c00d66b81
tree size: 1
root hash (sha256): 8bc2d611b16ca56b984594b3a077735a86521f879501ba4431ba9d9c00d66b81

$ lys log append --dir release-log --leaf event-002.json
leaf index: 1
leaf hash (sha256, rfc6962): 28e569baaa8bed97a57dfb4e132ace2646a6f90bb2d09132c7b43b6074c4e48e
tree size: 2
root hash (sha256): 1cf2e05361ff3c0300755537027891566d96b87712cb79206db89d10b01c71b6

$ lys log append --dir release-log --leaf event-003.json
leaf index: 2
leaf hash (sha256, rfc6962): 78716e235bd2da8de246c35dc5fb1cac71b4e0fdd541f2d4530887893d5064a5
tree size: 3
root hash (sha256): 83c59810973c077111dae6b9ac63a7e7de57de7d7d6a6b75c00f22bb6c8cfd65
```

Checkpoint the log — a C2SP signed note over the current root. This also prints the **verifier key string**, the one thing a third party needs to trust:

```console
$ lys log checkpoint --dir release-log --key ci-signing.key --out checkpoint
origin: ci.example.com/releases
tree size: 3
root hash (sha256): 83c59810973c077111dae6b9ac63a7e7de57de7d7d6a6b75c00f22bb6c8cfd65
checkpoint written: checkpoint
verifier key (signed-note): ci.example.com/releases+195aa55f+AdVRzl5BPJMNZf8QW710qamRvLVsKOIBWbjmXpFoJgz7

$ cat checkpoint
ci.example.com/releases
3
g8WYEJc8B3ER2ua5rGOn595X3n19amt1wA8iu2yM/WU=

— ci.example.com/releases GVqlX/xwGfEf3FDmN/XsuAZ12+Znb3Xmh1fQb1CnlMyrc9EecKDzOB/kqPlliSAArKNuoM71FDuk4EUCdI7YIDMP5Qg=
```

Now someone challenges event 1. Build a self-contained proof artifact for it — JSON carrying the RFC 6962 proof and a signed checkpoint, verbatim:

```console
$ lys log prove inclusion --dir release-log --key ci-signing.key --leaf-index 1 --out event-002.proof.json
leaf index: 1
tree size: 3
root hash (sha256): 83c59810973c077111dae6b9ac63a7e7de57de7d7d6a6b75c00f22bb6c8cfd65
artifact written: event-002.proof.json
```

**On the auditor's machine.** This is the point of everything above. The auditor has a clean directory containing exactly two files — the disputed event and the proof artifact — plus the verifier key string, received out of band. No log directory, no access to the CI machine, no other events disclosed:

```console
$ ls
event-002.json  event-002.proof.json

$ lys log verify inclusion --artifact event-002.proof.json --leaf event-002.json \
    --verifier-key 'ci.example.com/releases+195aa55f+AdVRzl5BPJMNZf8QW710qamRvLVsKOIBWbjmXpFoJgz7'
inclusion verified
origin: ci.example.com/releases
tree size: 3
leaf index: 1
root hash (sha256): 83c59810973c077111dae6b9ac63a7e7de57de7d7d6a6b75c00f22bb6c8cfd65
```

Exit code 0. Change one byte of the leaf and it fails closed:

```console
$ sed 's/412/413/' event-002.json > tampered.json
$ lys log verify inclusion --artifact event-002.proof.json --leaf tampered.json \
    --verifier-key 'ci.example.com/releases+195aa55f+AdVRzl5BPJMNZf8QW710qamRvLVsKOIBWbjmXpFoJgz7'
error: inclusion proof verification failed: invalid artifact, checkpoint, or leaf
```

Exit code 1.

The auditor doesn't even need lys to check the leaf hash. Leaves are hashed per RFC 6962 — `SHA-256(0x00 || file-bytes)` — so any machine with `shasum` reproduces it:

```console
$ (printf '\x00'; cat event-002.json) | shasum -a 256
28e569baaa8bed97a57dfb4e132ace2646a6f90bb2d09132c7b43b6074c4e48e  -
```

The same hash `lys log append` printed for leaf index 1.

Finally, sign the release artifact itself. `lys attest` writes a COSE_Sign1 statement over the payload's hash — 199 bytes in this run, never carrying the payload:

```console
$ lys attest --key ci-signing.key --payload myapp-1.4.2.tar.gz --out myapp-1.4.2.tar.gz.cose
attested payload: myapp-1.4.2.tar.gz
payload hash (sha256): 3f849cfd62ffe088a42756c21fbf5ba5f0b8655f32f30398ac20dad521c97ba0
signer public key (ed25519): d551ce5e413c930d65ff105bbd74a9a991bcb56c28e20159b8e65e9168260cfb
signed at (unix ms): 1783709501291
attestation written: myapp-1.4.2.tar.gz.cose (COSE_Sign1, application/cose)

$ lys verify --attestation myapp-1.4.2.tar.gz.cose --payload myapp-1.4.2.tar.gz
attestation verified
signer public key (ed25519): d551ce5e413c930d65ff105bbd74a9a991bcb56c28e20159b8e65e9168260cfb
payload hash (sha256): 3f849cfd62ffe088a42756c21fbf5ba5f0b8655f32f30398ac20dad521c97ba0
signed at (unix ms): 1783709501291
```

Append `myapp-1.4.2.tar.gz.cose` to the log as a leaf and the attestation itself is now in tamper-evident history.

## Example 2 — trust infrastructure for AI agents

The same primitives, applied to the problem lys was built for: agents that can prove who they are, what they were allowed to do, and what they actually did.

**Birth certificate.** An orchestrator issues an agent a capability certificate — identity and permission as one object. Claims are plain JSON:

```console
$ lys key generate --out orchestrator.key
generated new identity key: orchestrator.key
public key (ed25519): 06550cfda45fbe5df579a921b52cdd378827e76dcd09569c4eb556e149c9f276

$ cat capabilities.json
{
  "capabilities": ["repo:read", "ci:dispatch", "artifact:sign"],
  "delegated_by": "tom@example.com",
  "max_budget_usd": 50
}

$ lys ca issue --key orchestrator.key --subject agent-noor --claims capabilities.json \
    --validity-days 7 --out agent-noor.pem
issued certificate for subject: agent-noor
subject public key (ed25519): 45d014ed38a175291a39360767fed3cc99d2a042b4fe4dd6ea4bb3da6a92774c
issuer public key (ed25519): 06550cfda45fbe5df579a921b52cdd378827e76dcd09569c4eb556e149c9f276
fingerprint (sha256): 59fc3cdee97c771e63e54b4ad4c7745a30d9a6b9814506ccd1a7d32d2cfe244e
expires at (rfc3339): 2026-07-17T18:51:56+00:00
capability claims embedded from: capabilities.json
certificate written: agent-noor.pem
```

Any counterparty holding the issuer's public key verifies the certificate and reads the claims — "should I trust this agent?" becomes a query:

```console
$ lys ca verify --cert agent-noor.pem \
    --issuer-public-key 06550cfda45fbe5df579a921b52cdd378827e76dcd09569c4eb556e149c9f276
certificate verified
issuer public key (ed25519): 06550cfda45fbe5df579a921b52cdd378827e76dcd09569c4eb556e149c9f276
checked at (rfc3339): 2026-07-10T18:52:08.432205+00:00
capability claims: {
  "capabilities": ["repo:read", "ci:dispatch", "artifact:sign"],
  "delegated_by": "tom@example.com",
  "max_budget_usd": 50
}
```

**Flight recorder.** Each agent session gets its own log — every message, tool call, and result appended as it happens, checkpointed under the agent's own key. Exactly the machinery from Example 1, with a per-session origin:

```console
$ lys key generate --out agent.key
generated new identity key: agent.key
public key (ed25519): aeb552a9cf067a8c61e756c00b11c05f82df8119e7c2a36dde25113f63fda5a2

$ lys log init --dir session-log --origin agents.example.com/agent-noor/session-0001
initialized log directory: session-log
origin: agents.example.com/agent-noor/session-0001
tree size: 0
root hash (sha256): e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

$ lys log append --dir session-log --leaf tool-call-001.json
leaf index: 0
leaf hash (sha256, rfc6962): 1c96b0231afa7d6f654185d034c5eca12ed0c25b0f658b46a0c5444bf3bcce32
tree size: 1
root hash (sha256): 1c96b0231afa7d6f654185d034c5eca12ed0c25b0f658b46a0c5444bf3bcce32

$ lys log checkpoint --dir session-log --key agent.key --out session.checkpoint
origin: agents.example.com/agent-noor/session-0001
tree size: 1
root hash (sha256): 1c96b0231afa7d6f654185d034c5eca12ed0c25b0f658b46a0c5444bf3bcce32
checkpoint written: session.checkpoint
verifier key (signed-note): agents.example.com/agent-noor/session-0001+26c74c25+Aa61UqnPBnqMYedWwAsRwF+C34EZ58Kjbd4lET9j/aWi
```

A disputed session answers with an inclusion proof for the one challenged entry — the rest of the session stays private, exactly as in Example 1.

**Sealed credential hand-off.** The status quo for giving an agent a credential is pasting a secret into a context window. Instead: seal it to the agent's key, signed by the sender, opaque to everything in between. Each lys identity derives an X25519 key; `lys key inspect` prints it:

```console
$ lys key inspect --key agent.key
identity key: agent.key
public key (ed25519): aeb552a9cf067a8c61e756c00b11c05f82df8119e7c2a36dde25113f63fda5a2
public key (x25519): 186883fcca79f84abc8f121e686ab4d89b5018d432754ae7177423644832d538
```

The orchestrator seals to that key. Two files come out — the envelope and a COSE attestation binding the sender to the sealed bytes:

```console
$ lys seal --key orchestrator.key \
    --recipient-public-key 186883fcca79f84abc8f121e686ab4d89b5018d432754ae7177423644832d538 \
    --payload credential.env --out credential.sealed.json --attestation-out credential.sealed.cose
sealed payload: credential.env
recipient public key (x25519): 186883fcca79f84abc8f121e686ab4d89b5018d432754ae7177423644832d538
sender public key (ed25519): 06550cfda45fbe5df579a921b52cdd378827e76dcd09569c4eb556e149c9f276
sealed envelope written: credential.sealed.json
seal attestation written: credential.sealed.cose (COSE_Sign1, application/cose)
```

The agent opens it, naming the sender it expects. The attestation is verified before anything is decrypted; the plaintext goes to a file (mode 0600 on Unix), never to stdout:

```console
$ lys open --key agent.key \
    --sender-public-key 06550cfda45fbe5df579a921b52cdd378827e76dcd09569c4eb556e149c9f276 \
    --envelope credential.sealed.json --attestation credential.sealed.cose --out received.env
sealed envelope opened
sender public key (ed25519): 06550cfda45fbe5df579a921b52cdd378827e76dcd09569c4eb556e149c9f276
payload bytes: 53
payload written: received.env
```

Name the wrong sender and it fails closed, exit code 1:

```console
$ lys open --key agent.key \
    --sender-public-key aeb552a9cf067a8c61e756c00b11c05f82df8119e7c2a36dde25113f63fda5a2 \
    --envelope credential.sealed.json --attestation credential.sealed.cose --out nope.env
error: sealed envelope open failed: invalid attestation or undecryptable envelope
```

## Verify without lys

Nobody should have to trust lys to verify a lys artifact.

- **Leaf hashes** reproduce with coreutils: `(printf '\x00'; cat leaf-file) | shasum -a 256` — RFC 6962, raw file bytes, no framing.
- **Checkpoints** are standard C2SP signed notes: any signed-note verifier checks them, including Go's `golang.org/x/mod/sumdb/note` and Cloudflare's Rust `signed_note` crate. lys's output is conformance-tested byte-identical against both.
- **Attestations** are tagged COSE_Sign1: any COSE library verifies them (conformance-tested against `veraison/go-cose`). lys's own verifier is stricter — canonical-encoding-strict — so lys accepts a subset of what vanilla COSE accepts, never a superset.
- **Proof artifacts** are self-contained JSON around the standard RFC 6962 proof triple; the shape is hand-checkable with a short script and any RFC 6962 verifier.

Byte-exact contracts, rationale, and rejected alternatives: [docs/design/WIRE-FORMATS.md](docs/design/WIRE-FORMATS.md).

## Learn more

- [docs/VISION.md](docs/VISION.md) — why this exists: trust in AI work is social today, and needs to be structural.
- [docs/DESIGN.md](docs/DESIGN.md) — architecture, primitive decisions, integration map.
- [docs/ROADMAP.md](docs/ROADMAP.md) — the plan, phase by phase, and where things stand.
- [LICENSE](LICENSE) — Apache-2.0.
