//! RAR archives, reading only: RAR5 (WinRAR 5 and later) and RAR 1.5-4.x
//! headers, RAR5 and RAR 2.9 decompression (LZ, PPMd, filters), solid and
//! multi-volume archives, AES encryption, CRC-32 and BLAKE2sp checks.
//!
//! Everything here is written from the published format descriptions and
//! the behaviour of the reference decoder; no RAR code is included. The
//! PPMd model is vendored from the public-domain-licensed `ppmd-rust`.

mod bits;
mod blake2sp;
mod crypto;
mod huffman;
mod ppmd;
mod rar4;
mod rar5;
mod reader;
mod unpack;
mod unpack3;
mod unpack5;
mod window;

use std::collections::HashMap;
use std::sync::Arc;

use zeroize::Zeroizing;

pub use reader::RarReader;

use crate::password::Password;

/// True when `head` starts with a RAR signature (any version).
pub fn is_rar(head: &[u8]) -> bool {
    head.starts_with(b"Rar!\x1a\x07")
}

/// Offset of a RAR signature inside a self-extracting program.
pub fn find_sfx_signature(head: &[u8]) -> Option<usize> {
    if !(head.starts_with(b"MZ") || head.starts_with(b"\x7fELF")) {
        return None;
    }
    head.windows(8).position(|w| w == rar5::SIGNATURE || &w[..7] == rar4::SIGNATURE)
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Version {
    V5 { alg: u8 },
    V3 { unp_ver: u8 },
}

impl Default for Version {
    fn default() -> Self {
        Version::V5 { alg: 0 }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Crypt {
    V5 { lg2: u8, salt: [u8; 16], iv: [u8; 16], check: Option<[u8; 8]>, mac: bool },
    V3 { salt: Option<[u8; 8]> },
    Unknown(String),
}

#[derive(Clone, Debug, Default)]
pub(crate) enum Link {
    #[default]
    None,
    Symlink(String),
    Hardlink(String),
    /// A copy of an earlier file's content (RAR5 "file copy").
    Copy(String),
    /// RAR 4 Unix symlink: the target is the file's data.
    InData,
}

/// One file or service header as stored in one volume.
#[derive(Clone, Debug, Default)]
pub(crate) struct FileRec {
    pub name: String,
    pub dir: bool,
    pub size: u64,
    pub size_known: bool,
    pub mtime: Option<(i64, u32)>,
    pub attr: u64,
    pub unix: bool,
    pub crc: Option<u32>,
    pub blake2: Option<[u8; 32]>,
    pub method: u8,
    pub dict: u64,
    pub version: Version,
    pub solid: bool,
    pub crypt: Option<Crypt>,
    pub link: Link,
    pub split_before: bool,
    pub split_after: bool,
    pub data_offset: u64,
    pub data_len: u64,
    /// The volume ends inside this file's data.
    pub truncated: bool,
}

/// What one volume's headers say.
#[derive(Debug, Default)]
pub(crate) struct VolumeHeaders {
    pub files: Vec<FileRec>,
    pub comment: Option<FileRec>,
    pub volume: bool,
    pub solid: bool,
    pub locked: bool,
    pub volume_number: Option<u64>,
    pub encrypted_headers: bool,
    /// The end header says another volume follows.
    pub more_volumes: bool,
    pub ended: bool,
    pub truncated: bool,
    pub warnings: Vec<String>,
}

/// Derived keys, so solid and multi-file archives run the slow key
/// derivation once per salt.
/// RAR 2.9 AES-128 key and IV.
type Keys3 = (Zeroizing<[u8; 16]>, [u8; 16]);

#[derive(Default)]
pub(crate) struct KeyCache {
    v5: HashMap<([u8; 16], u8), Arc<crypto::Keys5>>,
    v3: HashMap<Option<[u8; 8]>, Keys3>,
}

impl KeyCache {
    pub fn rar5(&mut self, pw: &Password, salt: &[u8; 16], lg2: u8) -> Arc<crypto::Keys5> {
        self.v5.entry((*salt, lg2)).or_insert_with(|| Arc::new(crypto::derive5(pw, salt, lg2))).clone()
    }
    pub fn rar3(&mut self, pw: &Password, salt: Option<&[u8; 8]>) -> Keys3 {
        self.v3.entry(salt.copied()).or_insert_with(|| crypto::derive3(pw, salt)).clone()
    }
}
