//! `lys` — command-line surface for the lys trust primitives.
//!
//! This binary is a thin surface over [`lys_core`]: it parses arguments,
//! dispatches to the subcommand implementations in [`commands`], and maps
//! their results to process exit codes. All logic lives in the library and
//! the per-subcommand modules — this file stays parse-and-dispatch only.
//!
//! Exit codes: `0` on success, `1` on any operational or verification
//! failure (with a diagnostic on stderr), `2` for argument-parsing errors
//! (clap's convention).

mod cli;
mod commands;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{
    CaCommand, Cli, Command, KeyCommand, LogCommand, LogProveCommand, LogVerifyCommand,
};

/// Entry point: parse arguments, dispatch, and translate the outcome into an
/// exit code. Every failure path prints a diagnostic to stderr.
fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Key(key_command) => match key_command {
            KeyCommand::Generate { out } => commands::key::generate(&out),
            KeyCommand::Inspect { key, note_name } => {
                commands::key::inspect(&key, note_name.as_deref())
            }
        },
        Command::Log(log_command) => match log_command {
            LogCommand::Init { dir, origin } => commands::log::init::run(&dir, &origin),
            LogCommand::Append { dir, leaf } => commands::log::append::run(&dir, &leaf),
            LogCommand::Checkpoint { dir, key, out } => {
                commands::log::checkpoint::run(&dir, &key, &out)
            }
            LogCommand::Prove(prove_command) => match prove_command {
                LogProveCommand::Inclusion {
                    dir,
                    key,
                    leaf_index,
                    out,
                } => commands::log::prove::inclusion(&dir, &key, leaf_index, &out),
                LogProveCommand::Consistency {
                    dir,
                    key,
                    old_size,
                    out,
                } => commands::log::prove::consistency(&dir, &key, old_size, &out),
            },
            LogCommand::Verify(verify_command) => match verify_command {
                LogVerifyCommand::Inclusion {
                    artifact,
                    leaf,
                    verifier_key,
                } => commands::log::verify::inclusion(&artifact, &leaf, &verifier_key),
                LogVerifyCommand::Consistency {
                    artifact,
                    verifier_key,
                } => commands::log::verify::consistency(&artifact, &verifier_key),
            },
        },
        Command::Ca(ca_command) => match ca_command {
            CaCommand::Issue {
                key,
                subject,
                claims,
                validity_days,
                out,
            } => commands::ca::issue(&key, &subject, claims.as_deref(), validity_days, &out),
            CaCommand::Verify {
                cert,
                issuer_public_key,
                at,
            } => commands::ca::verify(&cert, &issuer_public_key, at.as_deref()),
        },
        Command::Attest { key, payload, out } => commands::attest::run(&key, &payload, &out),
        Command::Verify {
            attestation,
            payload,
        } => commands::verify::run(&attestation, &payload),
        Command::Seal {
            key,
            recipient_public_key,
            payload,
            out,
            attestation_out,
        } => commands::seal::seal(
            &key,
            &recipient_public_key,
            &payload,
            &out,
            &attestation_out,
        ),
        Command::Open {
            key,
            sender_public_key,
            envelope,
            attestation,
            out,
        } => commands::seal::open(&key, &sender_public_key, &envelope, &attestation, &out),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
