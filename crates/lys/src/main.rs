//! `lys` — command-line surface for the lys trust primitives.
//!
//! This binary is the CLI surface over [`lys_core`]. Subcommands (key
//! management, certificate issuance and verification, attestation, sealed
//! transport, and transparency-log inspection/verification) will be wired in as
//! the corresponding `lys-core` modules land. See `docs/ROADMAP.md`.

use std::process::ExitCode;

/// Entry point. Currently a placeholder that reports the crate version; real
/// subcommands land in roadmap phase 2 (see `docs/ROADMAP.md`).
fn main() -> ExitCode {
    println!(
        "lys {} — trust infrastructure for AI agents",
        env!("CARGO_PKG_VERSION")
    );
    println!("CLI surface under construction; see docs/ROADMAP.md");
    ExitCode::SUCCESS
}
