//! One item (file, folder, link) inside an archive.

use serde::{Deserialize, Serialize};

/// What kind of item an entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    Hardlink,
    /// Device nodes, FIFOs, sockets: listed but never created on extraction.
    Special,
}

/// Metadata of one archive member, independent of the archive format.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    /// Position of the entry in the archive (stable id used for selection).
    pub index: usize,
    /// Normalised path: `/`-separated, no leading `/`, no `.` parts, no
    /// trailing `/`. May still contain `..` parts; see [`Entry::unsafe_path`].
    pub path: String,
    /// The stored path contained `..` parts or was absolute.
    pub unsafe_path: bool,
    pub kind: EntryKind,
    /// Uncompressed size in bytes (0 when unknown, see `size_known`).
    pub size: u64,
    pub size_known: bool,
    /// Bytes this entry occupies in the archive, if the format tells.
    pub packed_size: Option<u64>,
    /// Modification time, seconds since the Unix epoch (UTC).
    pub mtime: Option<i64>,
    pub mtime_nanos: u32,
    /// Unix permission bits (`0o7777` mask), if stored.
    pub mode: Option<u32>,
    pub crc32: Option<u32>,
    pub encrypted: bool,
    /// Human readable compression method, e.g. `LZMA2:24` or `Deflate`.
    pub method: Option<String>,
    /// Target of a symbolic or hard link.
    pub link_target: Option<String>,
    pub comment: Option<String>,
    /// Solid block number (7z folder), when the format has blocks.
    pub block: Option<u32>,
}

impl Entry {
    pub fn new(index: usize, path: String, kind: EntryKind) -> Self {
        Entry {
            index,
            path,
            unsafe_path: false,
            kind,
            size: 0,
            size_known: true,
            packed_size: None,
            mtime: None,
            mtime_nanos: 0,
            mode: None,
            crc32: None,
            encrypted: false,
            method: None,
            link_target: None,
            comment: None,
            block: None,
        }
    }

    /// Last path component.
    pub fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    pub fn is_dir(&self) -> bool {
        self.kind == EntryKind::Dir
    }

    pub fn is_file(&self) -> bool {
        self.kind == EntryKind::File
    }
}
