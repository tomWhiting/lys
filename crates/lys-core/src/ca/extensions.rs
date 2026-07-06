//! Custom X.509 extension transport.
//!
//! These helpers encode and extract opaque DER payloads carried in custom
//! certificate extensions. The crate owns only the extension *structure* —
//! encoding bytes into an extension and reading them back out by OID. It does
//! not interpret the payload: the meaning of the bytes is the consumer's
//! concern.
//!
//! Extensions are created non-critical so that generic X.509 parsers, which
//! do not recognise the custom OID, still accept certificates that carry them.

use x509_parser::oid_registry::Oid;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::error::{TrustError, TrustResult};

/// The rcgen extension type produced by [`encode_extension`] and consumed by
/// [`crate::ca::CertificateAuthority::issue_certificate`].
pub use rcgen::CustomExtension;

/// Private-enterprise OID arc reserved for lys custom extensions.
///
/// Rooted at the IANA Private Enterprise Numbers arc (`1.3.6.1.4.1`). The
/// final component is a stable placeholder used only to namespace opaque
/// extension payloads within lys; it is not yet an officially registered
/// Private Enterprise Number, pending an IANA registration. Consumers append
/// their own sub-components to this arc to distinguish individual extension
/// kinds.
pub const LYS_OID_ARC: &[u64] = &[1, 3, 6, 1, 4, 1, 58888];

/// Encodes an opaque DER payload into a non-critical custom X.509 extension.
///
/// The returned extension carries `payload_bytes` verbatim under `oid`. The
/// payload is treated as opaque transport — no structure is imposed on or
/// read from it here. Criticality is set to `false` so parsers that do not
/// recognise `oid` will not reject the certificate.
pub fn encode_extension(oid: &[u64], payload_bytes: impl Into<Vec<u8>>) -> CustomExtension {
    let mut extension = CustomExtension::from_oid_content(oid, payload_bytes.into());
    extension.set_criticality(false);
    extension
}

/// Extracts the opaque payload of a custom extension identified by `oid`.
///
/// Parses `cert_der`, then looks up the extension by OID, rejecting
/// certificates that carry the same OID more than once. Returns the raw
/// extension value bytes unchanged, or `None` when the certificate does not
/// carry an extension with that OID.
///
/// # Errors
///
/// Returns [`TrustError::CertificateParsing`] if `cert_der` is not a valid
/// certificate, `oid` is not a well-formed object identifier, or the
/// certificate carries the OID more than once.
pub fn decode_extension(cert_der: &[u8], oid: &[u64]) -> TrustResult<Option<Vec<u8>>> {
    let (_, certificate) =
        X509Certificate::from_der(cert_der).map_err(|e| TrustError::CertificateParsing {
            reason: format!("failed to parse certificate DER: {e:?}"),
        })?;

    let target = Oid::from(oid).map_err(|_err| TrustError::CertificateParsing {
        reason: "extension lookup OID is not a well-formed object identifier".to_string(),
    })?;

    match certificate.tbs_certificate.get_extension_unique(&target) {
        Ok(Some(extension)) => Ok(Some(extension.value.to_vec())),
        Ok(None) => Ok(None),
        Err(e) => Err(TrustError::CertificateParsing {
            reason: format!("duplicate or malformed extension for OID lookup: {e}"),
        }),
    }
}

#[cfg(test)]
#[path = "extensions_tests.rs"]
mod tests;
