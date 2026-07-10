//! [`LogStore`] — the on-disk log directory behind the `lys log` commands.
//!
//! This layout is local state for the `lys` CLI, NOT a wire contract. It
//! may change between lys versions without a version dance; nothing durable
//! is signed under it. The wire contracts are the checkpoint note and the
//! proof artifacts. The pinned root in `state.json` is an integrity
//! convenience for detecting local bit-rot or tampering of the directory;
//! the *cryptographic* tamper-evidence of the log is carried by emitted
//! checkpoints and artifacts.
//!
//! # Layout and invariants
//!
//! - `log.json` — immutable identity (`format`, `origin`); written once by
//!   init, never rewritten. The origin is pinned here and is never taken
//!   per-invocation.
//! - `leaves/<20-digit zero-padded index>` — one file per leaf, raw bytes
//!   verbatim. The leaf file IS the RFC 6962 preimage:
//!   `(printf '\x00'; cat leaf-file) | shasum -a 256` IS the leaf hash.
//!   Existing leaf files are never rewritten; new leaves are created with
//!   `O_EXCL`, so a racing append loses loudly instead of corrupting.
//! - `state.json` — `tree_size` plus the base64 pinned root; rewritten
//!   atomically (tmp file + rename) after every append.
//!
//! Every open runs the full integrity routine: enumerate and validate
//! `leaves/`, rebuild the tree, and compare against the pinned state. The
//! single tolerated divergence is crash recovery — exactly one extra
//! contiguous leaf whose prefix root matches the pinned root — which is
//! repaired deterministically with a stderr notice, never silently. The
//! store is single-writer; leaves are retained in memory for prefix
//! rebuilds, which is fine at CLI scale.

use std::io::Write;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use lys_core::checkpoint::CheckpointBody;
use lys_core::merkle::{AppendOnlyTree, RawLeaf, RootHash, raw_leaf_hash};
use serde::{Deserialize, Serialize};

use crate::commands::error::{CliError, CliResult};
use crate::commands::files::{read_file, write_file};

/// Detection marker in `log.json`. A local-state version tag, not a wire
/// contract.
const LOG_DIR_FORMAT: &str = "lys/log-dir/v1";

/// Width of a leaf filename: `u64::MAX` has 20 decimal digits.
const LEAF_NAME_WIDTH: usize = 20;

/// `log.json` — the log directory's immutable identity.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogConfig {
    /// Always [`LOG_DIR_FORMAT`]; a detection marker only.
    format: String,
    /// The log's origin, pinned at init.
    origin: String,
}

/// `state.json` — the pinned `(tree_size, root)` after the last append.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogState {
    /// Number of leaves the pinned root covers.
    tree_size: u64,
    /// Standard base64 (with padding) of the 32-byte RFC 6962 root hash.
    root_hash: String,
}

/// An open, integrity-verified log directory.
pub struct LogStore {
    dir: PathBuf,
    origin: String,
    leaves: Vec<Vec<u8>>,
    tree: AppendOnlyTree<RawLeaf>,
}

impl std::fmt::Debug for LogStore {
    /// Summarizes the store without dumping leaf contents (they are public
    /// log content, but arbitrarily large).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogStore")
            .field("dir", &self.dir)
            .field("origin", &self.origin)
            .field("num_leaves", &self.leaves.len())
            .finish_non_exhaustive()
    }
}

impl LogStore {
    /// Creates and initializes a new log directory at `dir` with the given
    /// origin. Refuses to re-initialize an existing log directory.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::LogDirInvalid`] if `log.json` already exists,
    /// [`CliError::Trust`] if the origin violates the checkpoint-origin
    /// rules, and [`CliError::Io`] on filesystem failures.
    pub fn init(dir: &Path, origin: &str) -> CliResult<()> {
        // Validate the origin exactly as checkpoint construction will: the
        // origin doubles as the signed-note key name.
        let empty_root = AppendOnlyTree::<RawLeaf>::new().root();
        CheckpointBody::from_root(origin, &empty_root).map_err(CliError::from)?;
        let config_path = dir.join("log.json");
        if config_path.exists() {
            return Err(CliError::LogDirInvalid {
                path: dir.to_path_buf(),
                reason: "already initialized (log.json exists); the origin is pinned at init \
                         and a log directory is never re-initialized"
                    .to_string(),
            });
        }
        std::fs::create_dir_all(dir.join("leaves")).map_err(|source| CliError::Io {
            context: format!("failed to create log directory {}", dir.display()),
            source,
        })?;
        let config = LogConfig {
            format: LOG_DIR_FORMAT.to_string(),
            origin: origin.to_string(),
        };
        write_file(
            &config_path,
            state_json_bytes(&config, "log config")?.as_slice(),
            "log config file",
        )?;
        write_state(dir, &empty_root)?;
        Ok(())
    }

    /// Opens and integrity-verifies the log directory at `dir` (see the
    /// module docs for the routine and the single tolerated crash-recovery
    /// divergence).
    ///
    /// # Errors
    ///
    /// Returns [`CliError::LogDirMissing`] if the directory is not an
    /// initialized log, [`CliError::LogDirInvalid`] with the specific
    /// discrepancy on any integrity failure, and [`CliError::Io`] on
    /// filesystem failures.
    pub fn open(dir: &Path) -> CliResult<Self> {
        let config_path = dir.join("log.json");
        if !config_path.exists() {
            return Err(CliError::LogDirMissing {
                path: dir.to_path_buf(),
            });
        }
        let config: LogConfig = parse_state_file(dir, &config_path, "log.json")?;
        if config.format != LOG_DIR_FORMAT {
            return Err(CliError::LogDirInvalid {
                path: dir.to_path_buf(),
                reason: format!(
                    "log.json format is {:?}, expected {LOG_DIR_FORMAT:?}",
                    config.format
                ),
            });
        }
        let state_path = dir.join("state.json");
        let state: LogState = parse_state_file(dir, &state_path, "state.json")?;
        let pinned_root = decode_pinned_root(dir, &state.root_hash)?;
        let leaves = read_leaves(dir)?;
        let tree = AppendOnlyTree::<RawLeaf>::reconstruct_from_raw_leaves(&leaves);
        let mut store = Self {
            dir: dir.to_path_buf(),
            origin: config.origin,
            leaves,
            tree,
        };
        store.check_against_state(state.tree_size, pinned_root)?;
        Ok(store)
    }

    /// Compares the rebuilt tree against the pinned state, applying the
    /// single tolerated crash-recovery divergence (module docs).
    fn check_against_state(&mut self, pinned_size: u64, pinned_root: [u8; 32]) -> CliResult<()> {
        let (rebuilt_root, rebuilt_size) = self.tree.root().to_parts();
        if rebuilt_size == pinned_size && rebuilt_root == pinned_root {
            return Ok(());
        }
        // Crash recovery: exactly one extra contiguous leaf AND the rebuilt
        // root over the pinned-size prefix equals the pinned root means the
        // previous append crashed between the leaf write and the state
        // write. Repair the state, notify on stderr, continue.
        if rebuilt_size == pinned_size + 1 {
            let prefix = self.prefix_tree(pinned_size)?;
            let (prefix_root, _prefix_size) = prefix.root().to_parts();
            if prefix_root == pinned_root {
                write_state(&self.dir, &self.tree.root())?;
                eprintln!("recovered interrupted append: state advanced to {rebuilt_size}");
                return Ok(());
            }
        }
        Err(CliError::LogDirInvalid {
            path: self.dir.clone(),
            reason: format!(
                "leaves rebuild to tree size {rebuilt_size} with root {}, but state.json pins \
                 tree size {pinned_size} with root {}",
                STANDARD.encode(rebuilt_root),
                STANDARD.encode(pinned_root)
            ),
        })
    }

    /// Appends raw leaf bytes: writes the leaf file with `O_EXCL`, extends
    /// the in-memory tree, and atomically rewrites `state.json`. Returns
    /// the new leaf's index and its RFC 6962 leaf hash.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Io`] if the leaf file cannot be created (an
    /// existing file at the next index — e.g. a racing append — surfaces
    /// here rather than being clobbered) or the state cannot be rewritten.
    pub fn append(&mut self, leaf_bytes: &[u8]) -> CliResult<(u64, [u8; 32])> {
        let index = self.tree.len();
        let leaf_path = self
            .dir
            .join("leaves")
            .join(format!("{index:0LEAF_NAME_WIDTH$}"));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&leaf_path)
            .map_err(|source| CliError::Io {
                context: format!("failed to create leaf file {}", leaf_path.display()),
                source,
            })?;
        file.write_all(leaf_bytes).map_err(|source| CliError::Io {
            context: format!("failed to write leaf file {}", leaf_path.display()),
            source,
        })?;
        self.tree.append_raw(leaf_bytes);
        self.leaves.push(leaf_bytes.to_vec());
        write_state(&self.dir, &self.tree.root())?;
        Ok((index, raw_leaf_hash(leaf_bytes)))
    }

    /// The log's origin, pinned at init.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The current in-memory tree (rebuilt and verified at open).
    pub fn tree(&self) -> &AppendOnlyTree<RawLeaf> {
        &self.tree
    }

    /// The raw bytes of the leaf at `index`, if it exists.
    pub fn leaf_bytes(&self, index: u64) -> Option<&[u8]> {
        usize::try_from(index)
            .ok()
            .and_then(|i| self.leaves.get(i))
            .map(Vec::as_slice)
    }

    /// Rebuilds the tree over the first `old_size` leaves (the prefix a
    /// consistency proof starts from).
    ///
    /// # Errors
    ///
    /// Returns [`CliError::LogDirInvalid`] if `old_size` exceeds the
    /// current tree size.
    pub fn prefix_tree(&self, old_size: u64) -> CliResult<AppendOnlyTree<RawLeaf>> {
        let count = usize::try_from(old_size)
            .ok()
            .filter(|&n| n <= self.leaves.len())
            .ok_or_else(|| CliError::LogDirInvalid {
                path: self.dir.clone(),
                reason: format!(
                    "prefix of size {old_size} requested but the log has {} leaves",
                    self.leaves.len()
                ),
            })?;
        Ok(AppendOnlyTree::<RawLeaf>::reconstruct_from_raw_leaves(
            &self.leaves[..count],
        ))
    }
}

/// Serializes a local-state struct as pretty JSON with a trailing newline.
fn state_json_bytes<T: Serialize>(value: &T, what: &'static str) -> CliResult<Vec<u8>> {
    let mut json = serde_json::to_string_pretty(value)
        .map_err(|source| CliError::JsonSerialize { what, source })?;
    json.push('\n');
    Ok(json.into_bytes())
}

/// Parses a local-state JSON file, mapping failures to an actionable
/// [`CliError::LogDirInvalid`] (local trusted state, not an oracle concern).
fn parse_state_file<T: serde::de::DeserializeOwned>(
    dir: &Path,
    path: &Path,
    what: &str,
) -> CliResult<T> {
    let bytes = read_file(path, what)?;
    serde_json::from_slice(&bytes).map_err(|e| CliError::LogDirInvalid {
        path: dir.to_path_buf(),
        reason: format!("{what} is malformed: {e}"),
    })
}

/// Decodes the pinned root from `state.json`: canonical standard base64 of
/// exactly 32 bytes.
fn decode_pinned_root(dir: &Path, root_b64: &str) -> CliResult<[u8; 32]> {
    STANDARD
        .decode(root_b64)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| CliError::LogDirInvalid {
            path: dir.to_path_buf(),
            reason: "state.json root_hash is not standard base64 of exactly 32 bytes".to_string(),
        })
}

/// Atomically rewrites `state.json` for the given root: write to
/// `state.json.tmp` in the same directory, then rename (atomic on POSIX).
fn write_state(dir: &Path, root: &RootHash) -> CliResult<()> {
    let (root_hash, tree_size) = root.to_parts();
    let state = LogState {
        tree_size,
        root_hash: STANDARD.encode(root_hash),
    };
    let tmp_path = dir.join("state.json.tmp");
    write_file(
        &tmp_path,
        state_json_bytes(&state, "log state")?.as_slice(),
        "log state file",
    )?;
    let state_path = dir.join("state.json");
    std::fs::rename(&tmp_path, &state_path).map_err(|source| CliError::Io {
        context: format!(
            "failed to atomically replace log state file {}",
            state_path.display()
        ),
        source,
    })
}

/// Enumerates and validates `leaves/`, returning leaf bytes in index order.
///
/// Directory entries beginning with `.` are ignored (they can never be leaf
/// names, which are exactly 20 digits, so ignoring them cannot mask a
/// missing or extra leaf); any other unexpected entry is a corruption
/// error. The index set must be exactly `0..n`, contiguous.
fn read_leaves(dir: &Path) -> CliResult<Vec<Vec<u8>>> {
    let leaves_dir = dir.join("leaves");
    let entries = std::fs::read_dir(&leaves_dir).map_err(|source| CliError::Io {
        context: format!("failed to read leaves directory {}", leaves_dir.display()),
        source,
    })?;
    let mut indices: Vec<u64> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| CliError::Io {
            context: format!("failed to read leaves directory {}", leaves_dir.display()),
            source,
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(invalid_leaf_entry(dir, &name.to_string_lossy()));
        };
        if name.starts_with('.') {
            continue;
        }
        if name.len() != LEAF_NAME_WIDTH || !name.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid_leaf_entry(dir, name));
        }
        let Ok(index) = name.parse::<u64>() else {
            return Err(invalid_leaf_entry(dir, name));
        };
        if !entry.path().is_file() {
            return Err(invalid_leaf_entry(dir, name));
        }
        indices.push(index);
    }
    indices.sort_unstable();
    for (expected, &index) in (0u64..).zip(indices.iter()) {
        if index != expected {
            return Err(CliError::LogDirInvalid {
                path: dir.to_path_buf(),
                reason: format!(
                    "leaves are not contiguous: expected leaf index {expected}, found {index}"
                ),
            });
        }
    }
    let mut leaves = Vec::with_capacity(indices.len());
    for index in indices {
        let leaf_path = leaves_dir.join(format!("{index:0LEAF_NAME_WIDTH$}"));
        leaves.push(read_file(&leaf_path, "leaf file")?);
    }
    Ok(leaves)
}

/// Builds the corruption error for an unexpected `leaves/` entry.
fn invalid_leaf_entry(dir: &Path, name: &str) -> CliError {
    CliError::LogDirInvalid {
        path: dir.to_path_buf(),
        reason: format!(
            "unexpected entry {name:?} in leaves/: leaf names are exactly {LEAF_NAME_WIDTH} \
             decimal digits"
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn init_store(dir: &Path) -> LogStore {
        LogStore::init(dir, "example.com/lys/store-test").unwrap();
        LogStore::open(dir).unwrap()
    }

    #[test]
    fn init_creates_layout_and_open_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("log");
        let store = init_store(&dir);
        assert_eq!(store.origin(), "example.com/lys/store-test");
        assert_eq!(store.tree().len(), 0);
        assert!(dir.join("log.json").is_file());
        assert!(dir.join("state.json").is_file());
        assert!(dir.join("leaves").is_dir());
    }

    #[test]
    fn init_refuses_to_reinitialize() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("log");
        init_store(&dir);
        let err = LogStore::init(&dir, "example.com/other").unwrap_err();
        assert!(matches!(err, CliError::LogDirInvalid { .. }), "{err}");
        assert!(err.to_string().contains("already initialized"), "{err}");
    }

    #[test]
    fn init_rejects_invalid_origin() {
        let tmp = tempfile::tempdir().unwrap();
        for bad in ["", "has space", "has+plus"] {
            let dir = tmp.path().join(format!("log-{}", bad.len()));
            let err = LogStore::init(&dir, bad).unwrap_err();
            assert!(matches!(err, CliError::Trust(_)), "{bad:?}: {err}");
        }
    }

    #[test]
    fn open_missing_dir_is_log_dir_missing_with_remedy() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("nope");
        let err = LogStore::open(&dir).unwrap_err();
        assert!(matches!(err, CliError::LogDirMissing { .. }), "{err}");
        assert!(err.to_string().contains("lys log init"), "{err}");
    }

    #[test]
    fn append_reopen_reproduces_root_and_golden_leaf_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("log");
        let mut store = init_store(&dir);
        let (index0, hash0) = store.append(b"leaf-0").unwrap();
        let (index1, _hash1) = store.append(b"leaf-1").unwrap();
        assert_eq!((index0, index1), (0, 1));
        // Golden vector: SHA-256(0x00 || "leaf-0").
        assert_eq!(
            crate::commands::hex::hex_lower(&hash0),
            "305df59f9590c3c9ac63d2b2743c388e3792449078cebf7fb3dbe6471643b2b7"
        );
        assert_eq!(hash0, raw_leaf_hash(b"leaf-0"));
        let root_before = store.tree().root();
        let reopened = LogStore::open(&dir).unwrap();
        assert_eq!(reopened.tree().root(), root_before);
        assert_eq!(reopened.leaf_bytes(0), Some(b"leaf-0".as_slice()));
        assert_eq!(reopened.leaf_bytes(1), Some(b"leaf-1".as_slice()));
        assert_eq!(reopened.leaf_bytes(2), None);
    }

    #[test]
    fn leaf_files_hold_raw_bytes_verbatim() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("log");
        let mut store = init_store(&dir);
        store.append(b"raw \x00 bytes").unwrap();
        let on_disk = std::fs::read(dir.join("leaves").join("0".repeat(20))).unwrap();
        assert_eq!(on_disk, b"raw \x00 bytes");
    }

    #[test]
    fn empty_leaf_is_legal() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("log");
        let mut store = init_store(&dir);
        let (_index, hash) = store.append(b"").unwrap();
        assert_eq!(hash, raw_leaf_hash(b""));
        assert_eq!(LogStore::open(&dir).unwrap().tree().len(), 1);
    }

    #[test]
    fn tampered_leaf_byte_is_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("log");
        let mut store = init_store(&dir);
        store.append(b"leaf-0").unwrap();
        std::fs::write(dir.join("leaves").join("0".repeat(20)), b"leaf-X").unwrap();
        let err = LogStore::open(&dir).unwrap_err();
        assert!(matches!(err, CliError::LogDirInvalid { .. }), "{err}");
    }

    #[test]
    fn leaf_gap_is_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("log");
        let mut store = init_store(&dir);
        store.append(b"leaf-0").unwrap();
        store.append(b"leaf-1").unwrap();
        store.append(b"leaf-2").unwrap();
        std::fs::remove_file(dir.join("leaves").join(format!("{:020}", 1))).unwrap();
        let err = LogStore::open(&dir).unwrap_err();
        assert!(err.to_string().contains("not contiguous"), "{err}");
    }

    #[test]
    fn unexpected_leaves_entry_is_detected_but_dotfiles_are_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("log");
        let mut store = init_store(&dir);
        store.append(b"leaf-0").unwrap();
        std::fs::write(dir.join("leaves").join(".DS_Store"), b"junk").unwrap();
        assert!(LogStore::open(&dir).is_ok(), "dotfiles must be ignored");
        std::fs::write(dir.join("leaves").join("stray.txt"), b"junk").unwrap();
        let err = LogStore::open(&dir).unwrap_err();
        assert!(err.to_string().contains("unexpected entry"), "{err}");
    }

    #[test]
    fn tampered_state_root_is_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("log");
        let mut store = init_store(&dir);
        store.append(b"leaf-0").unwrap();
        let state = std::fs::read_to_string(dir.join("state.json")).unwrap();
        let tampered = state.replacen("\"tree_size\": 1", "\"tree_size\": 2", 1);
        assert_ne!(state, tampered);
        std::fs::write(dir.join("state.json"), tampered).unwrap();
        let err = LogStore::open(&dir).unwrap_err();
        assert!(matches!(err, CliError::LogDirInvalid { .. }), "{err}");
    }

    #[test]
    fn malformed_state_json_is_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("log");
        init_store(&dir);
        std::fs::write(dir.join("state.json"), "{\"tree_size\": 0}").unwrap();
        let err = LogStore::open(&dir).unwrap_err();
        assert!(err.to_string().contains("state.json is malformed"), "{err}");
    }

    #[test]
    fn crash_recovery_repairs_one_extra_contiguous_leaf() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("log");
        let mut store = init_store(&dir);
        store.append(b"leaf-0").unwrap();
        let state_after_one = std::fs::read(dir.join("state.json")).unwrap();
        store.append(b"leaf-1").unwrap();
        // Simulate a crash between the leaf write and the state write.
        std::fs::write(dir.join("state.json"), &state_after_one).unwrap();
        let recovered = LogStore::open(&dir).unwrap();
        assert_eq!(recovered.tree().len(), 2);
        // The state file was repaired on disk.
        let reread = LogStore::open(&dir).unwrap();
        assert_eq!(reread.tree().len(), 2);
    }

    #[test]
    fn crash_recovery_does_not_mask_a_tampered_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("log");
        let mut store = init_store(&dir);
        store.append(b"leaf-0").unwrap();
        let state_after_one = std::fs::read(dir.join("state.json")).unwrap();
        store.append(b"leaf-1").unwrap();
        // Stale state AND a tampered pinned prefix: must NOT recover.
        std::fs::write(dir.join("leaves").join("0".repeat(20)), b"leaf-X").unwrap();
        std::fs::write(dir.join("state.json"), &state_after_one).unwrap();
        let err = LogStore::open(&dir).unwrap_err();
        assert!(matches!(err, CliError::LogDirInvalid { .. }), "{err}");
    }

    #[test]
    fn prefix_tree_matches_directly_built_tree_and_bounds_checked() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("log");
        let mut store = init_store(&dir);
        store.append(b"leaf-0").unwrap();
        store.append(b"leaf-1").unwrap();
        store.append(b"leaf-2").unwrap();
        let prefix = store.prefix_tree(2).unwrap();
        let direct = AppendOnlyTree::<RawLeaf>::reconstruct_from_raw_leaves([b"leaf-0", b"leaf-1"]);
        assert_eq!(prefix.root(), direct.root());
        assert!(store.prefix_tree(4).is_err());
    }
}
