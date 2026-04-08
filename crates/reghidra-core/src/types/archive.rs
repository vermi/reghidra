//! On-disk (de)serialization for [`TypeArchive`].
//!
//! The wire format is postcard — a compact, self-describing-enough binary
//! encoding that's deterministic across runs (important for the CI drift
//! check that diffs regenerated archives against checked-in ones). We do
//! a manual version check on load so that stale archives from an older
//! Reghidra release produce a clear error rather than silently
//! deserializing into a struct whose field meanings have shifted.

use super::{TypeArchive, ARCHIVE_VERSION};
use std::fmt;

/// Errors produced by [`TypeArchive::load_from_bytes`] and
/// [`TypeArchive::to_bytes`].
#[derive(Debug)]
pub enum ArchiveError {
    /// Postcard couldn't decode the bytes. Usually means the archive was
    /// truncated, corrupted, or produced by a format so old that even the
    /// outer envelope has diverged. We wrap the raw message rather than
    /// re-exporting postcard's error type so consumers don't need to
    /// depend on postcard directly.
    Decode(String),
    /// Postcard couldn't encode the archive. Should be impossible in
    /// practice — the archive's fields are all owned, `Serialize`-clean
    /// types — but we surface it as a recoverable error anyway to avoid
    /// panicking inside the loader.
    Encode(String),
    /// The archive was decoded successfully but its `version` field is
    /// newer than the current [`ARCHIVE_VERSION`]. This is the expected
    /// failure mode when a user runs an older Reghidra against a newer
    /// shipped archive, which shouldn't happen in practice (archives
    /// ship with the binary) but we check anyway as a forward-compat
    /// safety net.
    UnsupportedVersion(u32),
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(m) => write!(f, "failed to decode type archive: {m}"),
            Self::Encode(m) => write!(f, "failed to encode type archive: {m}"),
            Self::UnsupportedVersion(v) => write!(
                f,
                "type archive format version {v} is newer than supported version {ARCHIVE_VERSION}"
            ),
        }
    }
}

impl std::error::Error for ArchiveError {}

impl TypeArchive {
    /// Decode an archive from its on-disk postcard representation. Validates
    /// the version field before returning — a future-versioned archive is
    /// rejected with [`ArchiveError::UnsupportedVersion`] so callers can
    /// distinguish "corrupted data" from "stale binary, grab a newer
    /// Reghidra release".
    pub fn load_from_bytes(bytes: &[u8]) -> Result<Self, ArchiveError> {
        let archive: TypeArchive = postcard::from_bytes(bytes)
            .map_err(|e| ArchiveError::Decode(e.to_string()))?;
        if archive.version > ARCHIVE_VERSION {
            return Err(ArchiveError::UnsupportedVersion(archive.version));
        }
        Ok(archive)
    }

    /// Encode the archive to its on-disk postcard representation. Used by
    /// the `tools/typegen` crate at archive generation time and by the
    /// roundtrip tests; not called during normal Reghidra execution.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ArchiveError> {
        postcard::to_allocvec(self).map_err(|e| ArchiveError::Encode(e.to_string()))
    }
}
