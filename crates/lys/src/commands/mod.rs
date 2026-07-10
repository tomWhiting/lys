//! Subcommand implementations for the `lys` CLI.
//!
//! Each named module implements one subcommand family; shared plumbing lives
//! in [`error`], [`files`], and [`hex`]. Per the repo standards, this file
//! carries declarations only.

pub mod attest;
pub mod ca;
pub mod error;
pub mod files;
pub mod hex;
pub mod key;
pub mod log;
pub mod pem;
pub mod seal;
pub mod verify;
