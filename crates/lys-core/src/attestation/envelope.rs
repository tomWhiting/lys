//! [`Attestation`] — the on-the-wire envelope produced by
//! [`super::sign::sign_attestation`].
//!
//! The envelope is exactly the four fields fixed by the design: the SHA-256
//! hash of the attested payload, a 64-byte Ed25519 detached signature, the
//! signer's 32-byte Ed25519 verifying key, and a unix-millisecond timestamp
//! captured at signing time. The signature covers the domain-separated
//! preimage `ATTESTATION_DOMAIN_V1 || timestamp.to_le_bytes() ||
//! payload_hash` (see [`super::sign`]), so both the hash and the timestamp
//! are authenticated. Nothing else travels — the original payload bytes are
//! the consumer's concern, not this crate's, which keeps the attestation
//! domain-agnostic.
//!
//! The envelope deliberately carries no scheme-version field: its wire shape
//! is fixed by the design, and scheme versioning lives in the
//! domain-separation tag inside the signed preimage rather than in the
//! envelope itself. [`super::sign::verify_attestation`] accepts the v1
//! preimage only — see the `sign` module docs.
//!
//! `serde` is implemented manually so the field shapes — `[u8; 32]`,
//! `[u8; 64]`, `[u8; 32]`, `i64` — remain exactly what the design calls
//! for. Stock `serde` derives only generate impls for arrays up to
//! length 32, so the 64-byte signature needs a dedicated serializer that
//! ferries it as a `serde_bytes`-style byte sequence.

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Ed25519-signed attestation over a payload's SHA-256 hash.
///
/// Constructed by [`super::sign::sign_attestation`] and consumed by
/// [`super::sign::verify_attestation`]. The struct is intentionally a plain
/// record with public fields — the trust crate provides the primitive;
/// consumers wrap it with their domain meaning (execution receipt, audit
/// entry, etc.).
///
/// The signature covers the domain-separated preimage
/// `ATTESTATION_DOMAIN_V1 || timestamp.to_le_bytes() || payload_hash`, not
/// the raw payload bytes. Signing a fixed-size preimage keeps the signed
/// quantity small and uniform regardless of payload size, authenticates the
/// timestamp, and separates attestation signatures from every other signing
/// context in the crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    /// SHA-256 digest of the attested payload bytes.
    pub payload_hash: [u8; 32],

    /// Ed25519 detached signature over the domain-separated preimage
    /// `ATTESTATION_DOMAIN_V1 || timestamp.to_le_bytes() || payload_hash`.
    pub signature: [u8; 64],

    /// Ed25519 verifying key of the signer that produced `signature`.
    pub signer_public_key: [u8; 32],

    /// Unix-millisecond timestamp captured when the attestation was signed.
    ///
    /// Authenticated: the timestamp is part of the signed preimage, so it
    /// cannot be altered after signing without invalidating `signature`.
    /// Stored as `i64` (matching `chrono::DateTime::timestamp_millis`) so
    /// pre-epoch timestamps remain representable; the trust crate makes no
    /// monotonicity or freshness guarantees — those are the consumer's
    /// responsibility.
    pub timestamp: i64,
}

// `serde` only provides derives for arrays up to length 32, but the design
// fixes `signature: [u8; 64]`. The Serialize / Deserialize impls below ferry
// the signature through a `Bytes64` helper that serialises as a byte buffer
// in self-describing formats (e.g. JSON) and as a 64-byte sequence in
// compact formats (e.g. postcard). All other fields use stock serde.

const FIELD_NAMES: &[&str] = &[
    "payload_hash",
    "signature",
    "signer_public_key",
    "timestamp",
];

impl Serialize for Attestation {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Attestation", 4)?;
        state.serialize_field("payload_hash", &self.payload_hash)?;
        state.serialize_field("signature", &Bytes64Ref(&self.signature))?;
        state.serialize_field("signer_public_key", &self.signer_public_key)?;
        state.serialize_field("timestamp", &self.timestamp)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Attestation {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_struct("Attestation", FIELD_NAMES, AttestationVisitor)
    }
}

struct AttestationVisitor;

impl<'de> Visitor<'de> for AttestationVisitor {
    type Value = Attestation;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an Attestation struct with four fields")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let payload_hash: [u8; 32] = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let signature: Bytes64 = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
        let signer_public_key: [u8; 32] = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(2, &self))?;
        let timestamp: i64 = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(3, &self))?;
        Ok(Attestation {
            payload_hash,
            signature: signature.0,
            signer_public_key,
            timestamp,
        })
    }

    fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut payload_hash: Option<[u8; 32]> = None;
        let mut signature: Option<Bytes64> = None;
        let mut signer_public_key: Option<[u8; 32]> = None;
        let mut timestamp: Option<i64> = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "payload_hash" => {
                    if payload_hash.is_some() {
                        return Err(de::Error::duplicate_field("payload_hash"));
                    }
                    payload_hash = Some(map.next_value()?);
                }
                "signature" => {
                    if signature.is_some() {
                        return Err(de::Error::duplicate_field("signature"));
                    }
                    signature = Some(map.next_value()?);
                }
                "signer_public_key" => {
                    if signer_public_key.is_some() {
                        return Err(de::Error::duplicate_field("signer_public_key"));
                    }
                    signer_public_key = Some(map.next_value()?);
                }
                "timestamp" => {
                    if timestamp.is_some() {
                        return Err(de::Error::duplicate_field("timestamp"));
                    }
                    timestamp = Some(map.next_value()?);
                }
                other => return Err(de::Error::unknown_field(other, FIELD_NAMES)),
            }
        }
        Ok(Attestation {
            payload_hash: payload_hash.ok_or_else(|| de::Error::missing_field("payload_hash"))?,
            signature: signature
                .ok_or_else(|| de::Error::missing_field("signature"))?
                .0,
            signer_public_key: signer_public_key
                .ok_or_else(|| de::Error::missing_field("signer_public_key"))?,
            timestamp: timestamp.ok_or_else(|| de::Error::missing_field("timestamp"))?,
        })
    }
}

/// Newtype that serializes a `[u8; 64]` as a byte sequence regardless of
/// format. Stock serde derives only cover arrays up to length 32.
struct Bytes64([u8; 64]);

/// Borrowed counterpart of [`Bytes64`] used on the serialize side to avoid
/// copying the 64-byte signature.
struct Bytes64Ref<'a>(&'a [u8; 64]);

impl Serialize for Bytes64Ref<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Tuple serializer with a fixed length matches what stock serde
        // derives do for shorter arrays — postcard treats this as 64
        // ordered bytes, JSON treats it as a 64-element array.
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(64)?;
        for byte in self.0 {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }
}

impl<'de> Deserialize<'de> for Bytes64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct B64Visitor;

        impl<'de> Visitor<'de> for B64Visitor {
            type Value = Bytes64;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a 64-byte sequence")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; 64];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(Bytes64(out))
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                if v.len() != 64 {
                    return Err(de::Error::invalid_length(v.len(), &self));
                }
                let mut out = [0u8; 64];
                out.copy_from_slice(v);
                Ok(Bytes64(out))
            }

            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                self.visit_bytes(&v)
            }
        }

        deserializer.deserialize_tuple(64, B64Visitor)
    }
}
