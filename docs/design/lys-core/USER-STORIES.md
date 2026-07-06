# Lys-Core — User Stories

## Norn Agent Runtime — Signing Session History (primary consumer)

**S1.** As the Norn runtime, I want a signing `PersistenceSink` decorator to attest each session event with the agent's Ed25519 identity so that every persisted event carries a verifiable, timestamp-authenticated signature without any core-loop change.

**S2.** As the Norn runtime, I want to append each event's hash to a per-session `AppendOnlyTree` so that the session history becomes tamper-evident from the first event.

**S3.** As the Norn runtime, I want to export the session root via `RootHash::to_parts()` at every `checkpoint()` so that the 32-byte root can later be anchored externally without revealing session contents.

**S4.** As the Norn runtime, I want to issue an X.509 certificate at agent spawn with capability claims embedded as a `LYS_OID_ARC` extension so that the agent's identity and permissions are one presentable object.

**S5.** As the Norn runtime, I want to verify a counterparty's certificate chain at the MCP boundary — at the dispatch instant, via `verify_certificate_chain_at` — so that cross-agent tool calls are gated on legitimate, unexpired, capability-scoped identity.

**S6.** As the Norn runtime, I want spawned agents to load their identity from `LYS_IDENTITY_KEY` so that key material reaches an agent process through its environment without touching shared disk.

**S7.** As the Norn runtime, I want `reconstruct_from_leaves` to rebuild a session tree from the persisted event sequence after a crash so that the recovered tree's root matches the last checkpointed root exactly.

**S8.** As the Norn runtime, I want concurrent agent processes calling `load_or_generate` on the same key path to converge on one persisted key so that a spawn race never leaves an agent holding an identity that differs from the key on disk.

## Lys CLI Operator and Auditor

**S9.** As an operator, I want `lys key` to generate and inspect identities without ever printing private material so that key handling over a shoulder-surfable terminal is safe by construction.

**S10.** As an operator, I want `lys ca issue` to mint certificates with capability-claim extensions from my instance CA key so that I can provision agent identities from the command line.

**S11.** As an auditor, I want `lys ca verify` with an explicit instant so that I can check whether a certificate was valid at the time a disputed action occurred, not just at the time of my audit.

**S12.** As an operator, I want `lys attest` to sign a file or stdin so that I can hand a third party a detached, self-contained attestation over any artifact.

**S13.** As an auditor, I want `lys verify` to check an attestation with only the payload and the signer's public key so that verification requires nothing from the party who produced the record.

**S14.** As an auditor, I want `lys log verify` to prove inclusion from only a published root and proof bytes so that I can confirm a challenged entry was logged without the operator's cooperation and without seeing any other entry.

**S15.** As an auditor, I want `lys log verify` to check consistency between two published roots so that I can detect any rewrite of history between two points in time.

**S16.** As an operator, I want `lys seal` and `lys open` so that I can move a credential file to a specific recipient with per-envelope forward secrecy instead of pasting secrets into a chat.

## Lys-Anchor Service (future notary)

**S17.** As the anchor service, I want to reconstruct submitted roots via `RootHash::from_parts` so that I can verify consistency proofs between an instance's successive submissions while seeing only roots, never contents.

**S18.** As the anchor service, I want to verify the submitter's v1 domain-separated attestation over each submitted root so that only the holder of the registered instance key can extend that instance's anchored history.

**S19.** As the anchor service, I want to append anchored roots to my own `AppendOnlyTree` and serve inclusion proofs so that my receipt for an anchoring event is itself independently verifiable.

**S20.** As the anchor service, I want the wire tags and preimage layouts frozen at `v1` so that a receipt issued today still verifies against signatures produced years from now.

## Haematite Commit Attestation

**S21.** As haematite, I want to attest a BLAKE3 commit root — 32 opaque bytes signed with the instance identity — so that a whole database state becomes attestable without lys knowing anything about haematite's hash world.

**S22.** As haematite, I want to append commit attestations to an append-only log so that my flat timestamped commit list gains the hash-chained lineage it structurally lacks.

**S23.** As haematite, I want inclusion proofs over the commit log so that any party can verify a historical commit belongs to the canonical lineage without replaying the database.
