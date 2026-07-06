//! Certificate authority operations: Ed25519-rooted X.509 issuance, custom
//! extension transport, and chain verification.

pub mod authority;
pub mod certificate;
pub mod extensions;

pub use authority::{CertificateAuthority, verify_certificate_chain, verify_certificate_chain_at};
pub use certificate::IssuedCertificate;
pub use extensions::{CustomExtension, LYS_OID_ARC, decode_extension, encode_extension};
