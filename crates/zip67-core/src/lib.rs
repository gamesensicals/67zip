//! 67zip archive engine.
//!
//! Everything in this crate is safe Rust: `unsafe` is forbidden. Archive data
//! is treated as hostile: every size, offset and count read from a file is
//! checked before it is used, and extraction can never write outside the
//! chosen destination folder.

#![forbid(unsafe_code)]

pub mod archive;
pub mod bench;
pub mod cipher;
pub mod codecs;
pub mod crc;
pub mod create;
pub mod detect;
pub mod entry;
pub mod error;
pub mod extract;
pub mod formats;
pub mod hash;
pub mod io;
pub mod limits;
pub mod password;
pub mod progress;
pub mod shred;
pub mod source;
pub mod split;
pub mod update;
pub mod util;

pub use archive::{open, ArchiveInfo, ArchiveReader, EntryVisitor, OpenOptions};
pub use detect::{ArchiveType, Compression, Container};
pub use entry::{Entry, EntryKind};
pub use error::{Error, Result};
pub use limits::Limits;
pub use password::Password;
pub use progress::Progress;

/// Version of the engine (same as the crate version).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
