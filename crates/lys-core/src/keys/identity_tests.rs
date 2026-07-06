#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

/// The single environment variable read by [`Ed25519Identity::from_env`].
/// Every env-backed test mutates this and so must run serially.
const TEST_ENV_VAR: &str = "LYS_IDENTITY_KEY";

fn identity_from_seed(seed: [u8; 32]) -> Ed25519Identity {
    Ed25519Identity::from_seed(&Zeroizing::new(seed))
}

// ─── Debug redaction ──────────────────────────────────────────────

#[test]
fn debug_redacts_signing_key() {
    let seed = [7u8; 32];
    let id = identity_from_seed(seed);
    let dbg = format!("{id:?}");
    assert!(dbg.contains("[REDACTED]"), "got: {dbg}");
    assert!(
        !dbg.contains("07, 07, 07"),
        "raw seed bytes leaked in debug (hex): {dbg}"
    );
    assert!(
        !dbg.contains("7, 7, 7, 7"),
        "raw seed bytes leaked in debug (decimal array): {dbg}"
    );
    assert!(
        !dbg.contains("SigningKey("),
        "default SigningKey tuple debug leaked: {dbg}"
    );
    assert!(
        !dbg.contains("SigningKey {"),
        "default SigningKey struct debug leaked: {dbg}"
    );
}

#[test]
fn debug_includes_verifying_key_hex() {
    let seed = [7u8; 32];
    let id = identity_from_seed(seed);
    let dbg = format!("{id:?}");
    let expected_hex = id.public_key_bytes_hex();
    assert!(
        dbg.contains(&expected_hex),
        "verifying key hex missing from debug: {dbg}"
    );
}

// ─── public_key_bytes accessor ────────────────────────────────────

#[test]
fn public_key_bytes_returns_32_bytes() {
    let id = identity_from_seed([1u8; 32]);
    let bytes = id.public_key_bytes();
    assert_eq!(bytes.len(), 32);
}

#[test]
fn public_key_bytes_round_trips_through_verifying_key() {
    let id = identity_from_seed([2u8; 32]);
    let bytes = id.public_key_bytes();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&bytes).unwrap();
    assert_eq!(vk.to_bytes(), bytes);
}

#[test]
fn public_key_bytes_stable_across_calls() {
    let id = identity_from_seed([3u8; 32]);
    assert_eq!(id.public_key_bytes(), id.public_key_bytes());
}

// ─── sign ─────────────────────────────────────────────────────────

#[test]
fn sign_produces_64_byte_signature() {
    let id = identity_from_seed([4u8; 32]);
    let sig = id.sign(b"hello");
    assert_eq!(sig.len(), 64);
}

#[test]
fn sign_then_verify_roundtrip() {
    let id = identity_from_seed([5u8; 32]);
    let msg = b"hello world";
    let sig = id.sign(msg);
    Ed25519Identity::verify(&id.public_key_bytes(), msg, &sig).unwrap();
}

#[test]
fn sign_different_messages_yields_different_signatures() {
    let id = identity_from_seed([6u8; 32]);
    let sig_a = id.sign(b"message A");
    let sig_b = id.sign(b"message B");
    assert_ne!(sig_a, sig_b);
}

#[test]
fn sign_empty_message() {
    let id = identity_from_seed([8u8; 32]);
    let sig = id.sign(b"");
    assert_eq!(sig.len(), 64);
    Ed25519Identity::verify(&id.public_key_bytes(), b"", &sig).unwrap();
}

// ─── verify ───────────────────────────────────────────────────────

#[test]
fn verify_rejects_tampered_message() {
    let id = identity_from_seed([10u8; 32]);
    let sig = id.sign(b"original");
    let result = Ed25519Identity::verify(&id.public_key_bytes(), b"tampered", &sig);
    assert!(matches!(result, Err(TrustError::InvalidSignature)));
}

#[test]
fn verify_rejects_wrong_public_key() {
    let id_a = identity_from_seed([11u8; 32]);
    let id_b = identity_from_seed([12u8; 32]);
    let sig = id_a.sign(b"msg");
    let result = Ed25519Identity::verify(&id_b.public_key_bytes(), b"msg", &sig);
    assert!(matches!(result, Err(TrustError::InvalidSignature)));
}

#[test]
fn verify_rejects_short_signature() {
    let id = identity_from_seed([13u8; 32]);
    let result = Ed25519Identity::verify(&id.public_key_bytes(), b"msg", &[0u8; 32]);
    assert!(matches!(result, Err(TrustError::InvalidSignature)));
}

#[test]
fn verify_rejects_long_signature() {
    let id = identity_from_seed([14u8; 32]);
    let result = Ed25519Identity::verify(&id.public_key_bytes(), b"msg", &[0u8; 128]);
    assert!(matches!(result, Err(TrustError::InvalidSignature)));
}

#[test]
fn verify_rejects_empty_signature() {
    let id = identity_from_seed([15u8; 32]);
    let result = Ed25519Identity::verify(&id.public_key_bytes(), b"msg", &[]);
    assert!(matches!(result, Err(TrustError::InvalidSignature)));
}

#[test]
fn verify_rejects_malformed_public_key() {
    let id = identity_from_seed([16u8; 32]);
    let sig = id.sign(b"msg");
    let result = Ed25519Identity::verify(&[0xff; 32], b"msg", &sig);
    assert!(matches!(result, Err(TrustError::InvalidSignature)));
}

#[test]
fn verify_rejects_small_order_public_key() {
    // [0u8; 32] encodes the point with y = 0, which lies on the curve and
    // has order 4. dalek's `VerifyingKey::from_bytes` accepts it (it is a
    // valid point encoding), so the strict-verification weak-key check is
    // the layer that must reject it.
    let weak_pk = [0u8; 32];
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&weak_pk)
        .expect("y=0 small-order point is a valid encoding dalek accepts");
    assert!(vk.is_weak(), "y=0 point must be classified as weak");

    let id = identity_from_seed([17u8; 32]);
    let sig = id.sign(b"msg");
    let result = Ed25519Identity::verify(&weak_pk, b"msg", &sig);
    assert!(matches!(result, Err(TrustError::InvalidSignature)));
}

#[test]
fn verify_rejects_identity_point_forgery_that_passes_non_strict() {
    use ed25519_dalek::Verifier;

    // The Edwards identity point (order 1) encodes as y = 1: [1, 0, ..., 0].
    // For a public key A equal to the identity, k·A is the identity for any
    // hash scalar k, so the verification equation s·B = R + k·A reduces to
    // s·B = R. The forged signature (R = basepoint, s = 1) therefore passes
    // NON-strict verification for ANY message — total forgery. Strict
    // verification rejects the small-order public key outright, which is why
    // Ed25519Identity::verify uses verify_strict.
    let mut weak_pk = [0u8; 32];
    weak_pk[0] = 1;

    // Compressed Ed25519 basepoint.
    let basepoint: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];
    let mut forged_sig = [0u8; 64];
    forged_sig[..32].copy_from_slice(&basepoint);
    forged_sig[32] = 1; // s = 1, little-endian

    // Sanity: the forgery really does pass dalek's non-strict verify, for
    // two unrelated messages. This is the exact hole verify_strict closes.
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&weak_pk).unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&forged_sig);
    vk.verify(b"any message at all", &sig)
        .expect("non-strict verify accepts the small-order forgery");
    vk.verify(b"a completely different message", &sig)
        .expect("non-strict verify accepts the forgery for every message");

    // Our verify must reject it.
    let result = Ed25519Identity::verify(&weak_pk, b"any message at all", &forged_sig);
    assert!(matches!(result, Err(TrustError::InvalidSignature)));
}

// ─── load_or_generate ─────────────────────────────────────────────

#[test]
fn load_or_generate_creates_file_when_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.key");
    assert!(!path.exists());

    let id = Ed25519Identity::load_or_generate(&path).unwrap();
    assert!(path.exists());

    let contents = std::fs::read(&path).unwrap();
    assert_eq!(contents.len(), 32, "file must be exactly 32 bytes");

    let _ = id.public_key_bytes();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "generated key file must be 0600");
    }
}

#[test]
fn load_or_generate_loads_existing_valid_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.key");
    let seed = [5u8; 32];
    std::fs::write(&path, seed).unwrap();
    #[cfg(unix)]
    chmod(&path, 0o600);

    let id = Ed25519Identity::load_or_generate(&path).unwrap();
    let expected_pk = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    assert_eq!(id.public_key_bytes(), expected_pk);
}

#[test]
fn load_or_generate_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.key");

    let id1 = Ed25519Identity::load_or_generate(&path).unwrap();
    let id2 = Ed25519Identity::load_or_generate(&path).unwrap();
    assert_eq!(id1.public_key_bytes(), id2.public_key_bytes());
}

#[test]
fn load_or_generate_rejects_wrong_length() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.key");
    std::fs::write(&path, [0u8; 16]).unwrap();
    #[cfg(unix)]
    chmod(&path, 0o600);

    let err = Ed25519Identity::load_or_generate(&path).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("invalid length"), "got: {msg}");
    assert!(msg.contains("expected 32 bytes, got 16"), "got: {msg}");
}

#[test]
fn load_or_generate_rejects_oversized() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.key");
    std::fs::write(&path, [0u8; 64]).unwrap();
    #[cfg(unix)]
    chmod(&path, 0o600);

    let err = Ed25519Identity::load_or_generate(&path).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("invalid length"), "got: {msg}");
    assert!(msg.contains("got 64"), "got: {msg}");
}

#[cfg(unix)]
#[test]
fn load_or_generate_warns_but_loads_on_loose_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.key");
    let seed = [9u8; 32];
    std::fs::write(&path, seed).unwrap();
    chmod(&path, 0o644);

    let id = Ed25519Identity::load_or_generate(&path).unwrap();
    let expected_pk = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    assert_eq!(id.public_key_bytes(), expected_pk);
}

#[test]
fn load_or_generate_creates_parent_dir() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested").join("deep").join("identity.key");
    assert!(!path.parent().unwrap().exists());

    let _id = Ed25519Identity::load_or_generate(&path).unwrap();
    assert!(path.exists());
    assert!(path.parent().unwrap().exists());
}

#[test]
fn load_or_generate_rejects_no_filename_path() {
    let err = Ed25519Identity::load_or_generate(Path::new("")).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("no filename component"), "got: {msg}");
}

#[test]
fn load_or_generate_concurrent_threads_agree_on_persisted_seed() {
    // The concurrency invariant: racing generators in the same process must
    // all return the identity of the single seed that ends up on disk. No
    // caller may hold an identity that diverges from the persisted file, and
    // no tmp files may be left behind.
    const THREADS: usize = 8;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.key");

    let barrier = std::sync::Barrier::new(THREADS);
    let public_keys: Vec<[u8; 32]> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    Ed25519Identity::load_or_generate(&path)
                        .expect("concurrent load_or_generate must succeed")
                        .public_key_bytes()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("thread panicked"))
            .collect()
    });

    // Every thread must agree with the seed that was actually persisted.
    let persisted = std::fs::read(&path).unwrap();
    assert_eq!(persisted.len(), 32);
    let mut persisted_seed = [0u8; 32];
    persisted_seed.copy_from_slice(&persisted);
    let expected_pk = ed25519_dalek::SigningKey::from_bytes(&persisted_seed)
        .verifying_key()
        .to_bytes();
    for (i, pk) in public_keys.iter().enumerate() {
        assert_eq!(
            *pk, expected_pk,
            "thread {i} returned an identity that diverges from the persisted seed"
        );
    }

    // No temp files may survive the race.
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| *name != *"identity.key")
        .collect();
    assert!(
        leftovers.is_empty(),
        "tmp files left behind after concurrent generation: {leftovers:?}"
    );
}

#[test]
fn generate_and_persist_lost_race_loads_winner_seed() {
    // Deterministic replay of the publish race: the key file appears after
    // the `path.exists()` check in load_or_generate but before the
    // no-clobber publish. Calling the private generate_and_persist with the
    // file already present exercises exactly that window — the caller must
    // get the WINNER's identity back, and the file must not be clobbered.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.key");
    let winner_seed = [42u8; 32];
    std::fs::write(&path, winner_seed).unwrap();
    #[cfg(unix)]
    chmod(&path, 0o600);

    let id = generate_and_persist(&path).unwrap();
    let expected_pk = ed25519_dalek::SigningKey::from_bytes(&winner_seed)
        .verifying_key()
        .to_bytes();
    assert_eq!(
        id.public_key_bytes(),
        expected_pk,
        "loser of the publish race must return the persisted (winner) identity"
    );

    // The winner's file must be untouched and no tmp files left behind.
    assert_eq!(std::fs::read(&path).unwrap(), winner_seed);
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| *name != *"identity.key")
        .collect();
    assert!(
        leftovers.is_empty(),
        "tmp files left behind after lost publish race: {leftovers:?}"
    );
}

#[test]
fn generate_and_persist_lost_race_surfaces_invalid_winner_file() {
    // If the concurrently persisted file is corrupt (wrong length), the
    // losing generator must surface that loudly instead of silently
    // returning its own unpersisted identity.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.key");
    std::fs::write(&path, [7u8; 16]).unwrap();
    #[cfg(unix)]
    chmod(&path, 0o600);

    let err = generate_and_persist(&path).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("invalid length"), "got: {msg}");
    assert!(msg.contains("expected 32 bytes, got 16"), "got: {msg}");
}

// ─── from_env ─────────────────────────────────────────────────────

#[test]
#[serial_test::serial]
#[allow(unsafe_code)]
fn from_env_loads_valid_base64_standard() {
    let seed = [9u8; 32];
    let encoded = STANDARD.encode(seed);
    // SAFETY: env mutation serialised via #[serial]; cleaned up by the guard.
    unsafe { std::env::set_var(TEST_ENV_VAR, &encoded) };
    let _guard = EnvCleanup;

    let id = Ed25519Identity::from_env().unwrap();
    let expected_pk = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    assert_eq!(id.public_key_bytes(), expected_pk);

    let sig = id.sign(b"test");
    Ed25519Identity::verify(&id.public_key_bytes(), b"test", &sig).unwrap();
}

#[test]
#[serial_test::serial]
#[allow(unsafe_code)]
fn from_env_loads_valid_base64_urlsafe() {
    let seed = [3u8; 32];
    let encoded = URL_SAFE_NO_PAD.encode(seed);
    // SAFETY: env mutation serialised via #[serial]; cleaned up by the guard.
    unsafe { std::env::set_var(TEST_ENV_VAR, &encoded) };
    let _guard = EnvCleanup;

    let id = Ed25519Identity::from_env().unwrap();
    let expected_pk = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    assert_eq!(id.public_key_bytes(), expected_pk);
}

#[test]
#[serial_test::serial]
#[allow(unsafe_code)]
fn from_env_missing_var_returns_key_management_error() {
    // SAFETY: env mutation serialised via #[serial].
    unsafe { std::env::remove_var(TEST_ENV_VAR) };

    let err = Ed25519Identity::from_env().unwrap_err();
    assert!(matches!(err, TrustError::KeyManagement { .. }));
    let msg = err.to_string();
    assert!(msg.contains(TEST_ENV_VAR), "got: {msg}");
    assert!(msg.contains("not set"), "got: {msg}");
}

#[test]
#[serial_test::serial]
#[allow(unsafe_code)]
fn from_env_invalid_base64_returns_key_management_error() {
    // SAFETY: env mutation serialised via #[serial]; cleaned up by the guard.
    unsafe { std::env::set_var(TEST_ENV_VAR, "not-base64!!!@@") };
    let _guard = EnvCleanup;

    let err = Ed25519Identity::from_env().unwrap_err();
    assert!(matches!(err, TrustError::KeyManagement { .. }));
    let msg = err.to_string();
    assert!(msg.contains("invalid base64"), "got: {msg}");
}

#[test]
#[serial_test::serial]
#[allow(unsafe_code)]
fn from_env_wrong_length_decoded_returns_key_management_error() {
    let encoded = STANDARD.encode([1u8; 16]);
    // SAFETY: env mutation serialised via #[serial]; cleaned up by the guard.
    unsafe { std::env::set_var(TEST_ENV_VAR, &encoded) };
    let _guard = EnvCleanup;

    let err = Ed25519Identity::from_env().unwrap_err();
    assert!(matches!(err, TrustError::KeyManagement { .. }));
    let msg = err.to_string();
    assert!(
        msg.contains("decoded to 16 bytes, expected 32"),
        "got: {msg}"
    );
}

// ─── X25519 derivation ────────────────────────────────────────────

#[test]
fn x25519_public_key_matches_derived_static_secret() {
    let id = identity_from_seed([21u8; 32]);
    let secret = id.x25519_static_secret();
    let expected = x25519_dalek::PublicKey::from(&secret).to_bytes();
    assert_eq!(id.x25519_public_key(), expected);
}

#[test]
fn x25519_public_key_is_deterministic() {
    let id = identity_from_seed([22u8; 32]);
    assert_eq!(id.x25519_public_key(), id.x25519_public_key());
}

#[test]
fn different_identities_produce_different_x25519_public_keys() {
    let id_a = identity_from_seed([23u8; 32]);
    let id_b = identity_from_seed([24u8; 32]);
    assert_ne!(id_a.x25519_public_key(), id_b.x25519_public_key());
}

#[test]
fn x25519_static_secret_agrees_across_identities() {
    // Diffie–Hellman sanity: two identities derive the same shared secret
    // from each other's X25519 public keys.
    let id_a = identity_from_seed([25u8; 32]);
    let id_b = identity_from_seed([26u8; 32]);

    let a_secret = id_a.x25519_static_secret();
    let b_secret = id_b.x25519_static_secret();

    let b_public = x25519_dalek::PublicKey::from(id_b.x25519_public_key());
    let a_public = x25519_dalek::PublicKey::from(id_a.x25519_public_key());

    let shared_ab = a_secret.diffie_hellman(&b_public);
    let shared_ba = b_secret.diffie_hellman(&a_public);
    assert_eq!(shared_ab.as_bytes(), shared_ba.as_bytes());
}

// ─── IO failure paths ─────────────────────────────────────────────

#[cfg(unix)]
#[test]
fn load_or_generate_read_permission_denied() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.key");
    std::fs::write(&path, [1u8; 32]).unwrap();
    chmod(&path, 0o000);

    let err = Ed25519Identity::load_or_generate(&path).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("failed to read"), "got: {msg}");

    chmod(&path, 0o600);
}

#[cfg(unix)]
#[test]
fn load_or_generate_write_permission_denied() {
    let dir = tempfile::tempdir().unwrap();
    let restricted = dir.path().join("noaccess");
    std::fs::create_dir(&restricted).unwrap();
    chmod(&restricted, 0o000);

    let path = restricted.join("identity.key");
    let err = Ed25519Identity::load_or_generate(&path).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("failed to write"), "got: {msg}");

    chmod(&restricted, 0o755);

    // The failed generation must not leave an orphaned tmp key file behind.
    let leftovers: Vec<_> = std::fs::read_dir(&restricted)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(
        leftovers.is_empty(),
        "orphaned files left after failed key generation: {leftovers:?}"
    );
}

// ─── test helpers ─────────────────────────────────────────────────

#[cfg(unix)]
fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(mode);
    std::fs::set_permissions(path, perms).unwrap();
}

/// Removes [`TEST_ENV_VAR`] on drop so env-backed tests leave no residue.
#[allow(unsafe_code)]
struct EnvCleanup;

#[allow(unsafe_code)]
impl Drop for EnvCleanup {
    fn drop(&mut self) {
        // SAFETY: env mutation serialised via #[serial].
        unsafe { std::env::remove_var(TEST_ENV_VAR) };
    }
}
