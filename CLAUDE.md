# CLAUDE.md — lys

## What this is

`lys` is cryptographic trust infrastructure for AI agents: identity, tamper-evident history, verifiable provenance. It is the extraction and elevation of the hardened `meridian-trust` crate into a standalone, open-source project.

Read [docs/VISION.md](docs/VISION.md) for why this exists, [docs/DESIGN.md](docs/DESIGN.md) for the architecture, and [docs/ROADMAP.md](docs/ROADMAP.md) for the plan and current phase.

## Crates

- **`lys-core`** — the library. All trust logic lives here: `keys`, `ca`, `merkle`, `attestation`, `seal`. Domain-agnostic — no concept of agents, sessions, or workspaces. This is what consumers depend on and what gets published to crates.io.
- **`lys`** — the CLI binary. Thin surface over `lys-core`. The "everything is a library + CLI + MCP surface" principle: logic lives in the library, the binary only parses arguments and formats output.

Future crates (later phases): `lys-anchor` (transparency-ledger service), `lys-mcp` (MCP server surface).

## The one rule that governs everything

**This is trust infrastructure. Its entire value is that strangers can verify it.** Every design decision serves verifiability-by-third-parties, not cleverness, not performance for its own sake. When choosing between a "better" primitive and the boring interoperable one, choose boring — the verification world speaks SHA-256, Ed25519, and RFC 6962, and a receipt nobody can verify with standard tooling is worthless. Verification must outlive the vendor.

## Coding standards

Non-negotiable, enforced by CI (`clippy --all-targets -- -D warnings`):

- **No `unwrap` / `expect` / `panic` / `todo` / `unimplemented` / `unreachable` in library code.** Tests opt out per-module with `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`.
- **No silent failures.** Every error handled or propagated with operation-specific context. `thiserror` for the library error type; the CLI may use `anyhow` at the top level only.
- **Private key material never appears in `Debug`, logs, or error messages.** Redaction is tested, not assumed. Seed buffers are `Zeroizing`.
- **No file over 500 lines** of code (excluding tests/comments/whitespace). `mod.rs` carries only `pub mod` / `pub use` / module docs. Logic goes in named files; tests in sibling `*_tests.rs` files.
- **`unsafe_code = "deny"`.** All dependencies pure Rust.
- **Every public item documented** (`missing_docs = "warn"` under `-D warnings`). Module-level `//!` docs state invariants, not just descriptions.
- **Cryptographic changes require an adversarial review** before landing. Not a light-model pass — construct actual attacks (forgeries, malleability, cross-protocol confusion, timing oracles) and prove they fail. See the meridian-trust hardening in `docs/ROADMAP.md` for the standard.

Silencing a lint with `#[allow]`, an `#[ignore]`d test, a `_`-prefixed unused variable, or `#[cfg(any())]` is a bypass, not a fix. Fix the code.

## Wire formats are forever

Once a signature is produced or a leaf is logged under a format, that format is frozen — changing it breaks every historical verification. Domain-separation tags (`lys/attestation/v1`, `lys/sealed-envelope/v1`) and leaf encodings are versioned wire contracts. Evolving one means a new `v2`, never a mutation of `v1`. This is why the extraction renames the tags *before* anything durable is signed under them.

## Gates before any commit

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

All three clean. No exceptions.
